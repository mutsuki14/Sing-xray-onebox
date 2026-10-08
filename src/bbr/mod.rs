//! TCP BBR and BBRv3 kernel management (`onebox bbr`).
//!
//! - [`status`]: read-only report (no root, no network, no writes);
//! - [`enable`]: the running kernel's `bbr` + a default qdisc, runtime and
//!   persisted, as one sysctl transaction;
//! - [`release`]: byJoey/Actions-bbr-v3 tags, manifests and trust rules;
//! - [`preflight`]: install eligibility, one check per line;
//! - [`install`]: preview, then download/verify/install with `--apply`.
//!
//! Grammar (v2, plus `menu` in the usage text): `bbr` | `bbr menu` (menu
//! when interactive, else status) | `status` | `enable [fq|fq_codel|fq_pie|cake]`
//! | `releases [--max]` | `install [latest|TAG] [--max] [--apply]`.
//! Locks: `ONEBOX_BBR_DIR/lock` (v2 path) for enable and install --apply.
//!
//! Changes from v2:
//! - one typed [`Action`] with `requires_root()`/`mutates()` decides the
//!   root policy for the CLI and the menu alike: `bbr`, `bbr menu`,
//!   `status`, `releases` and an install preview need no root; `enable` and
//!   `install --apply` do (v2 required root for `menu` and previews and
//!   accepted `info|list|preview` that the parser rejected, I-8.1#1/#2);
//! - the menu builds actions directly instead of re-parsing strings, and a
//!   failed item prints `[错误] …` and returns to the menu (I-8.1#6);
//! - `bbr install --dry-run` is the preview.

pub mod enable;
pub mod install;
pub mod net;
pub mod preflight;
pub mod release;
pub mod status;

pub use install::InstallRequest;

use crate::cli::args::{ArgSpec, CommandSpec, Group, Matches, OptSpec, Root};
use crate::ctx::Ctx;
use crate::error::{Error, Result};
use crate::sys::fs::ensure_dir;
use crate::sys::lock::FileLock;
use crate::ui::out;
use net::{CurlFetcher, Fetcher};
use release::Arch;

pub const REPO: &str = "byJoey/Actions-bbr-v3";
pub const CC: &str = "net.ipv4.tcp_congestion_control";
pub const QDISC: &str = "net.core.default_qdisc";
pub const AVAILABLE: &str = "net.ipv4.tcp_available_congestion_control";
pub const USAGE: &str = "用法: onebox bbr [menu|status|enable [fq|fq_codel|fq_pie|cake]|releases [--max]|install [latest|TAG] [--max] [--apply]]";
const ROOT_REQUIRED: &str = "此操作需要 root 权限";
const LOCK_BUSY: &str = "另一个 BBR 操作正在进行；稍后重试";

/// Default qdiscs `enable` accepts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Queue {
    Fq,
    FqCodel,
    FqPie,
    Cake,
}

impl Queue {
    pub const ALL: [Queue; 4] = [Queue::Fq, Queue::FqCodel, Queue::FqPie, Queue::Cake];

    pub fn id(self) -> &'static str {
        match self {
            Queue::Fq => "fq",
            Queue::FqCodel => "fq_codel",
            Queue::FqPie => "fq_pie",
            Queue::Cake => "cake",
        }
    }

    pub fn parse(s: &str) -> Result<Queue> {
        Queue::ALL
            .into_iter()
            .find(|q| q.id() == s)
            .ok_or_else(|| Error::msg("队列应为 fq / fq_codel / fq_pie / cake"))
    }
}

/// One `bbr` operation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Action {
    /// The interactive menu; status when there is no terminal.
    Menu,
    Status,
    Enable(Queue),
    Releases {
        max: bool,
    },
    Install(InstallRequest),
}

impl Action {
    /// Root is needed only for actions that change the system; menu items
    /// are checked one by one when chosen.
    pub fn requires_root(&self) -> bool {
        self.mutates()
    }

    pub fn mutates(&self) -> bool {
        match self {
            Action::Enable(_) => true,
            Action::Install(req) => req.apply,
            Action::Menu | Action::Status | Action::Releases { .. } => false,
        }
    }
}

fn usage() -> Error {
    Error::msg(USAGE)
}

/// Parse the words after `bbr` (v2 grammar).
pub fn parse(args: &[String]) -> Result<Action> {
    let Some((first, rest)) = args.split_first() else {
        return Ok(Action::Menu);
    };
    match (first.as_str(), rest) {
        ("menu", []) => Ok(Action::Menu),
        ("status", []) => Ok(Action::Status),
        ("enable", []) => Ok(Action::Enable(Queue::Fq)),
        ("enable", [queue]) => Queue::parse(queue).map(Action::Enable),
        ("releases", []) => Ok(Action::Releases { max: false }),
        ("releases", [flag]) if flag == "--max" => Ok(Action::Releases { max: true }),
        ("install", rest) => parse_install(rest).map(Action::Install),
        _ => Err(usage()),
    }
}

/// `install` tokens in any order; duplicates, unknown flags and a second
/// positional are rejected.
fn parse_install(tokens: &[String]) -> Result<InstallRequest> {
    let (mut desired, mut max, mut apply) = (None, false, false);
    for item in tokens {
        match item.as_str() {
            "--max" if !max => max = true,
            "--apply" if !apply => apply = true,
            value if !value.starts_with('-') && desired.is_none() => {
                desired = Some(value.to_string())
            }
            _ => {
                return Err(Error::msg(format!(
                    "重复或无效的 BBR 参数: {item}\n{USAGE}"
                )))
            }
        }
    }
    Ok(InstallRequest {
        desired: desired.unwrap_or_else(|| "latest".into()),
        max,
        apply,
    })
}

/// The action for a parsed `onebox bbr …` command line.
pub fn from_matches(m: &Matches) -> Result<Action> {
    match m.path.get(1).copied() {
        None | Some("menu") => Ok(Action::Menu),
        Some("status") => Ok(Action::Status),
        Some("enable") => Queue::parse(m.positional(0).unwrap_or("fq")).map(Action::Enable),
        Some("releases") => Ok(Action::Releases { max: m.flag("max") }),
        Some("install") => {
            if m.dry_run && m.flag("apply") {
                return Err(Error::msg("--dry-run 与 --apply 不能同时使用"));
            }
            Ok(Action::Install(InstallRequest {
                desired: m.positional(0).unwrap_or("latest").to_string(),
                max: m.flag("max"),
                apply: m.flag("apply"),
            }))
        }
        Some(_) => Err(usage()),
    }
}

fn root_for(m: &Matches) -> bool {
    from_matches(m).is_ok_and(|a| a.requires_root())
}

fn handle(ctx: &Ctx, m: &Matches) -> Result<()> {
    run(ctx, from_matches(m)?)
}

const MAX_FLAG: OptSpec = OptSpec::flag("max", "BBRv3 Max 实验版");

/// The `bbr` command tree for the registry.
pub const COMMAND: CommandSpec = CommandSpec::new("bbr", Group::Feature, "TCP BBR 与 BBRv3 内核")
    .usage(&[
        "bbr [menu]",
        "bbr status",
        "bbr enable [fq|fq_codel|fq_pie|cake]",
        "bbr releases [--max]",
        "bbr install [latest|标签] [--max] [--apply]",
    ])
    .subcommands(&[
        CommandSpec::new("menu", Group::Feature, "交互菜单（无终端时显示状态）")
            .root(Root::NotRequired)
            .handler(handle),
        CommandSpec::new("status", Group::Feature, "拥塞控制、队列与已安装内核状态")
            .root(Root::NotRequired)
            .handler(handle),
        CommandSpec::new(
            "enable",
            Group::Feature,
            "启用当前内核的 BBR 并设置默认队列",
        )
        .args(&[ArgSpec::optional(
            "队列",
            "fq（默认）/ fq_codel / fq_pie / cake",
        )])
        .root(Root::Required)
        .handler(handle),
        CommandSpec::new("releases", Group::Feature, "列出可安装的 BBRv3 Release")
            .options(&[MAX_FLAG])
            .root(Root::NotRequired)
            .handler(handle),
        CommandSpec::new(
            "install",
            Group::Feature,
            "预览或安装 BBRv3 内核（不会自动重启）",
        )
        .args(&[ArgSpec::optional(
            "标签",
            "完整 Release 标签或 latest（默认）",
        )])
        .options(&[MAX_FLAG, OptSpec::flag("apply", "执行安装（默认只预览）")])
        .root(Root::Custom(root_for))
        .dry_run()
        .handler(handle),
    ])
    .root(Root::NotRequired)
    .handler(handle);

/// Run `action` with the production fetcher and the real effective uid.
pub fn run(ctx: &Ctx, action: Action) -> Result<()> {
    let fetcher = CurlFetcher::from_env();
    Session {
        ctx,
        fetcher: &fetcher,
        is_root: crate::sys::process::is_root(),
    }
    .run(action)
}

/// Everything an action needs; tests inject the fetcher and root status.
pub struct Session<'a> {
    pub ctx: &'a Ctx,
    pub fetcher: &'a dyn Fetcher,
    pub is_root: bool,
}

impl Session<'_> {
    pub fn run(&self, action: Action) -> Result<()> {
        if action.requires_root() && !self.is_root {
            return Err(Error::msg(ROOT_REQUIRED));
        }
        match action {
            Action::Menu if self.ctx.ui.interactive() => self.menu(),
            Action::Menu | Action::Status => self.status(),
            Action::Enable(queue) => enable::enable(self.ctx, queue),
            Action::Releases { max } => self.releases(max),
            Action::Install(req) => install::install(self, &req),
        }
    }

    fn status(&self) -> Result<()> {
        let report = status::collect(self.ctx);
        out::data(&status::render(&report))?;
        for notice in status::conflict_notices(&report.conflicts) {
            out::warn(notice);
        }
        Ok(())
    }

    fn releases(&self, max: bool) -> Result<()> {
        let arch = Arch::detect(self.ctx)?;
        let mut fetch = |url: &str| self.fetcher.json(self.ctx, url);
        for tag in release::release_tags(arch, max, &mut fetch)? {
            out::data(&tag)?;
        }
        Ok(())
    }

    /// The interactive menu; a failed item is reported and the menu shown
    /// again, cancellation (EOF) leaves.
    fn menu(&self) -> Result<()> {
        let items: Vec<String> = [
            "状态与实际网卡队列",
            "启用当前内核 BBR，选择默认队列",
            "查看 BBRv3 标准版 Release",
            "安装/更新标准版（先预览，确认后执行）",
            "查看 BBRv3 Max 实验版 Release",
            "安装/更新 Max 实验版（先预览，确认后执行）",
        ]
        .map(String::from)
        .to_vec();
        loop {
            let Some(choice) = self.ctx.ui.select("TCP BBR 管理", &items, 0, true)? else {
                return Ok(());
            };
            let Some(action) = self.menu_action(choice)? else {
                continue;
            };
            if let Err(e) = self.run(action) {
                if e.is_cancelled() {
                    return Err(e);
                }
                out::error(e);
            }
        }
    }

    /// The action of menu item `choice` (0-based); `None` = back.
    fn menu_action(&self, choice: usize) -> Result<Option<Action>> {
        let ui = &self.ctx.ui;
        let install = |max| -> Result<Option<Action>> {
            let desired = ui.input("完整 Release 标签或 latest", "latest")?;
            Ok(Some(Action::Install(InstallRequest {
                desired,
                max,
                apply: true,
            })))
        };
        match choice {
            0 => Ok(Some(Action::Status)),
            1 => {
                let queues: Vec<String> = ["fq（默认）", "fq_codel", "fq_pie", "cake"]
                    .map(String::from)
                    .to_vec();
                let picked = ui.select("默认队列", &queues, 0, true)?;
                Ok(picked
                    .and_then(|i| Queue::ALL.get(i).copied())
                    .map(Action::Enable))
            }
            2 => Ok(Some(Action::Releases { max: false })),
            3 => install(false),
            4 => Ok(Some(Action::Releases { max: true })),
            5 => install(true),
            _ => Ok(None),
        }
    }
}

/// The BBR lock `ONEBOX_BBR_DIR/lock` (dir 0700, file 0600, non-blocking),
/// shared by enable and kernel installs (v2-compatible path).
pub(crate) fn lock(ctx: &Ctx) -> Result<FileLock> {
    ensure_dir(&ctx.paths.bbr_dir, 0o700)?;
    FileLock::acquire(&ctx.paths.bbr_dir.join("lock"), LOCK_BUSY)
}

#[cfg(test)]
mod fixture;
#[cfg(test)]
mod tests;
