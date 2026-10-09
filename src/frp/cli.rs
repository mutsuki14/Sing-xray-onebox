//! `onebox frps …`: the command tree (spec H §2.2–2.7), the typed
//! [`Action`]s it maps to, their handlers and the interactive menu (G41).
//!
//! Bare `frps` (and `frps menu`) opens the menu with a terminal and shows
//! the status without one (v2). Root is needed only for actions that
//! change the host; previews (`plan`, `install --dry-run`), `info`,
//! `client` and `log` need none (reading the 0600 state still does).
//!
//! Changes from v2:
//! - `frps --help` shows this command's help and `--dry-run` works where
//!   the FRP help promised it (H-8.1#3, handled by the CLI framework);
//!   `logs` is accepted (H-8.1#21) and `export` is an alias of `client`;
//! - Cloudflare credentials are looked up (or asked for) before the
//!   confirmation and written only by the transaction (H-8.1#1); declining
//!   the confirmation changes nothing;
//! - the menu is a numbered list with `0) 返回`; a failed item prints
//!   `[错误] …`, a cancelled one `[提示] 操作已取消`, and the menu stays
//!   (v2 printed the bare error); Ctrl+D at the menu prompt itself exits
//!   with 130 (ARCH G5); root is checked before an item asks anything;
//! - `update` to the version already running changes nothing.

use super::draft::{self, normalize_version, Draft, Flags};
use super::export::{self, ExportRequest};
use super::journal;
use super::lifecycle::{self, Change, ServiceAction, CRON_LOCK_WAIT};
use super::model::{self, FrpState, WebTls};
use super::render::summary;
use super::runtime::Runtime;
use super::wizard;
use crate::cert::cloudflare::{self, CfCredentials};
use crate::cli::args::{ArgSpec, CommandSpec, Group, Matches, OptSpec, Root};
use crate::ctx::Ctx;
use crate::error::{Error, Result};
use crate::host::os::ROOT_REQUIRED;
use crate::host::service::{FRPS, FRP_WEB};
use crate::ui::{out, BACK};
use std::path::{Path, PathBuf};

/// v2's `frps help` text (H §2.3).
pub const HELP: &str = "onebox frps [plan|install|configure|info|status|start|stop|restart|update [版本]|renew|rotate-token|client [新目录]|log|uninstall]\n配置参数：--mode web|tcp --domain 控制域名 --web-domain 应用域名 / --subdomain-host 泛域名根\n--port 7000 --http-port 7080 --https-port 443 --redirect-port 80 --allow-ports 20000-20100\n--tls http|cf|custom --cert 完整链 --key 私钥 --version 0.71.0|latest --dry-run";
pub const PREVIEW: &str = "以上仅为预览，未联网、未修改配置。实际安装会验证 DNS 和端口。";
const CONFIRM_DEPLOY: &str = "确认部署上述 FRP 配置？已有连接将短暂中断";
const CONFIRM_UPDATE: &str = "确认更新 FRP？连接将短暂中断";
const CONFIRM_ROTATE: &str = "轮换 token 会使所有旧客户端失效，确认继续？";
const CONFIRM_UNINSTALL: &str = "卸载 FRP、独立配置与证书？已导出配置将失效";
const NOT_INSTALLED_INFO: &str = "尚未安装 FRP；运行 onebox frps install";
const LOG_LINES: usize = 80;

/// One `frps` operation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Action {
    /// The menu with a terminal, else [`Action::Info`].
    Menu,
    Info,
    /// `plan` (preview only) or `install|configure` (`dry_run` previews).
    Configure {
        flags: Flags,
        dry_run: bool,
        plan: bool,
    },
    Client(ExportRequest),
    Service(ServiceAction),
    Log,
    /// To a version, or `latest` without one.
    Update(Option<String>),
    Renew {
        cron: bool,
    },
    RotateToken,
    Uninstall,
    Help,
    NetApply,
}

impl Action {
    /// Root is needed by actions that change the host.
    pub fn requires_root(&self) -> bool {
        match self {
            Action::Menu | Action::Info | Action::Client(_) | Action::Log | Action::Help => false,
            Action::Configure { dry_run, plan, .. } => !(*dry_run || *plan),
            Action::Service(_)
            | Action::Update(_)
            | Action::Renew { .. }
            | Action::RotateToken
            | Action::Uninstall
            | Action::NetApply => true,
        }
    }
}

/// The action of a parsed `onebox frps …` command line.
pub fn from_matches(m: &Matches, cwd: &Path) -> Result<Action> {
    let configure = |plan: bool| -> Result<Action> {
        Ok(Action::Configure {
            flags: Flags::from_matches(m, cwd)?,
            dry_run: plan || m.dry_run,
            plan,
        })
    };
    Ok(match m.path.get(1).copied() {
        None | Some("menu") => Action::Menu,
        Some("info") => Action::Info,
        Some("plan") => configure(true)?,
        Some("install") => configure(false)?,
        Some("client") => Action::Client(ExportRequest::from_matches(m)?),
        Some("start") => Action::Service(ServiceAction::Start),
        Some("stop") => Action::Service(ServiceAction::Stop),
        Some("restart") => Action::Service(ServiceAction::Restart),
        Some("log") => Action::Log,
        Some("update") => Action::Update(m.positional(0).map(normalize_version)),
        Some("renew") => Action::Renew {
            cron: m.flag("cron"),
        },
        Some("rotate-token") => Action::RotateToken,
        Some("uninstall") => Action::Uninstall,
        Some("help") => Action::Help,
        Some("net-apply") => Action::NetApply,
        Some(other) => bail!("未知 FRP 操作: {other}"),
    })
}

fn root_for(m: &Matches) -> bool {
    from_matches(m, Path::new("/")).is_ok_and(|a| a.requires_root())
}

fn current_dir() -> Result<PathBuf> {
    std::env::current_dir().map_err(|e| Error::msg(format!("无法读取当前目录: {e}")))
}

fn handle(ctx: &Ctx, m: &Matches) -> Result<()> {
    let cwd = current_dir()?;
    run(ctx, from_matches(m, &cwd)?)
}

/// Run `action` with the production runtime.
pub fn run(ctx: &Ctx, action: Action) -> Result<()> {
    Session {
        rt: Runtime::system(ctx),
        cwd: current_dir()?,
        is_root: crate::sys::process::is_root(),
    }
    .run(action)
}

/// The `frps` tree for the registry (`cli_spec()`).
pub fn cli_spec() -> &'static CommandSpec {
    &COMMAND
}

const fn option(long: &'static str, value: &'static str, help: &'static str) -> OptSpec {
    OptSpec::value(long, value, help).repeated()
}

const CONFIG_OPTIONS: &[OptSpec] = &[
    option("mode", "web|tcp", "web = HTTPS 网站（默认），tcp = TCP / UDP 转发"),
    option("domain", "域名", "控制域名：frpc 连接并校验证书的名字"),
    option("port", "端口", "控制端口（默认 7000）"),
    option("http-port", "端口", "web：frps 内部 HTTP 端口（默认 7080，仅本机）"),
    option("https-port", "端口", "web：公开 HTTPS 端口（默认 443）"),
    option("redirect-port", "端口", "web：HTTP 跳转端口（默认 80，0 关闭）"),
    option("web-domain", "域名", "web：应用域名（单域名）"),
    option("subdomain-host", "域名", "web：泛域名根（*.根）"),
    option("allow-ports", "起始-结束", "tcp：允许转发端口范围（默认 20000-20100）"),
    option("tls", "http|cf|custom", "web：网站证书方式"),
    option("cert", "路径", "web：自备证书完整链（--tls custom）"),
    option("key", "路径", "web：自备证书未加密私钥（--tls custom）"),
    option("version", "版本", "frp 版本，如 0.71.0 或 latest"),
];

const EXPORT_OPTIONS: &[OptSpec] = &[
    OptSpec::value("type", "http|tcp|udp", "代理类型（web 模式为 http）"),
    OptSpec::value("local-port", "端口", "内网服务端口（默认 8080）"),
    OptSpec::value("remote-port", "端口", "tcp/udp：公网转发端口（默认范围起点）"),
    OptSpec::value("subdomain", "标签", "泛域名部署的子域标签（默认 www）"),
];

const fn sub(name: &'static str, summary: &'static str, root: Root) -> CommandSpec {
    CommandSpec::new(name, Group::Feature, summary)
        .root(root)
        .handler(handle)
}

pub static COMMAND: CommandSpec = CommandSpec::new("frps", Group::Feature, "独立 FRP 服务端")
    .usage(&[
        "frps [menu]",
        "frps info|status",
        "frps plan [配置参数]",
        "frps install|configure [配置参数] [--dry-run]",
        "frps client [新目录] [--type http|tcp|udp] [--local-port N] [--remote-port N] [--subdomain 标签]",
        "frps start|stop|restart",
        "frps update [版本]",
        "frps renew [--cron]",
        "frps rotate-token",
        "frps log",
        "frps uninstall",
    ])
    .subcommands(&[
        sub("menu", "交互菜单（无终端时显示状态）", Root::NotRequired),
        sub("info", "配置摘要与服务状态", Root::NotRequired).aliases(&["status"]),
        sub("plan", "预览配置（不联网、不修改系统）", Root::NotRequired)
            .options(CONFIG_OPTIONS)
            .dry_run(),
        sub(
            "install",
            "安装或修改 FRP 服务端；无参数时进入向导",
            Root::Custom(root_for),
        )
        .aliases(&["configure"])
        .options(CONFIG_OPTIONS)
        .dry_run(),
        sub("client", "导出客户端配置目录（frpc.toml、ca.pem、README）", Root::NotRequired)
            .aliases(&["export"])
            .args(&[ArgSpec::optional(
                "新目录",
                "导出目录，必须不存在；省略时交互填写",
            )])
            .options(EXPORT_OPTIONS),
        sub("start", "启动 FRP 服务", Root::Required),
        sub("stop", "停止 FRP 服务（防火墙规则与自启保留）", Root::Required),
        sub("restart", "重启 FRP 服务", Root::Required),
        sub("update", "更新 frps 到指定版本或 latest", Root::Required).args(&[
            ArgSpec::optional("版本", "如 0.72.0；默认 latest"),
        ]),
        sub("renew", "检查并续期控制证书与网站证书", Root::Required).options(&[
            OptSpec::flag("cron", "计划任务调用：只续期到期的网站证书"),
        ]),
        sub("rotate-token", "轮换 token（所有旧客户端失效）", Root::Required),
        sub("log", "最近的 frps 与网站日志", Root::NotRequired).aliases(&["logs"]),
        sub("uninstall", "卸载 FRP、独立配置与证书", Root::Required),
        sub("help", "v2 用法摘要", Root::NotRequired).hidden(),
        CommandSpec::new("net-apply", Group::Hidden, "开机恢复 FRP 防火墙规则")
            .root(Root::Required)
            .handler(handle),
    ])
    .root(Root::NotRequired)
    .handler(handle);

/// Everything an action needs; tests inject the runtime and root status.
pub struct Session<'a> {
    pub rt: Runtime<'a>,
    /// Resolves relative paths (`--cert`, export directories).
    pub cwd: PathBuf,
    pub is_root: bool,
}

impl Session<'_> {
    fn ctx(&self) -> &Ctx {
        self.rt.ctx
    }

    pub fn run(&self, action: Action) -> Result<()> {
        ensure!(!action.requires_root() || self.is_root, "{ROOT_REQUIRED}");
        match action {
            Action::Menu if self.ctx().ui.interactive() => self.menu(),
            Action::Menu | Action::Info => self.info(),
            Action::Configure {
                flags,
                dry_run,
                plan,
            } => self.configure(&flags, dry_run, plan),
            Action::Client(req) => {
                let state = lifecycle::installed_state(&self.rt)?;
                let ctx = self.ctx();
                export::export(ctx.ui.as_ref(), &ctx.paths, &state, &req, &self.cwd).map(drop)
            }
            Action::Service(service) => {
                let lock = self.rt.lock()?;
                lifecycle::service(&self.rt, &lock, service)
            }
            Action::Log => self.logs(),
            Action::Update(version) => self.update(version),
            Action::Renew { cron } => {
                let lock = if cron {
                    self.rt.lock_waiting(CRON_LOCK_WAIT)?
                } else {
                    self.rt.lock()?
                };
                lifecycle::renew(&self.rt, &lock, cron)
            }
            Action::RotateToken => self.rotate_token(),
            Action::Uninstall => self.uninstall(),
            Action::Help => out::data(HELP),
            Action::NetApply => lifecycle::net_apply(self.ctx()),
        }
    }

    /// `info`/`status`: the summary and the service states (stdout).
    fn info(&self) -> Result<()> {
        let paths = &self.ctx().paths;
        if !model::installed(paths) {
            return out::data(NOT_INSTALLED_INFO);
        }
        let state = lifecycle::installed_state(&self.rt)?;
        out::data(&summary(&state))?;
        let services = self.rt.services();
        let running = |name: &str| {
            if services.running(name) {
                "运行中"
            } else {
                "已停止"
            }
        };
        out::data(&format!("frps: {}", running(FRPS)))?;
        if state.is_web() {
            out::data(&format!("网站: {}", running(FRP_WEB)))?;
        }
        if journal::exists(paths) {
            out::warn(journal::PENDING);
        }
        Ok(())
    }

    fn configure(&self, flags: &Flags, dry_run: bool, plan: bool) -> Result<()> {
        let ctx = self.ctx();
        let previous = model::load(&ctx.paths)?;
        let mut draft = match &previous {
            Some(state) => {
                for warning in state.warnings() {
                    out::warn(warning);
                }
                Draft::of(state)
            }
            None => Draft::fresh(crate::sys::net::ipv6_available(&ctx.paths.system_root)),
        };
        flags.apply(&mut draft);
        for option in flags.ignored(draft.mode) {
            out::warn(format!("{option} 不适用于 {} 模式，已忽略", draft.mode.id()));
        }
        let wizard = !dry_run && flags.is_empty() && ctx.ui.interactive();
        let state = if wizard {
            wizard::run(ctx.ui.as_ref(), draft, previous.as_ref(), &self.cwd)?
        } else {
            draft::finish(&draft, previous.as_ref())?
        };
        out::data(&summary(&state))?;
        if dry_run || plan {
            out::info(PREVIEW);
            return Ok(());
        }
        let cloudflare = self.cloudflare(&state)?;
        if !ctx.ui.confirm(CONFIRM_DEPLOY, false)? {
            return Ok(());
        }
        let reason = if previous.is_some() { "配置" } else { "安装" };
        lifecycle::apply(
            &self.rt,
            state,
            Change {
                cloudflare,
                reason,
                ..Change::default()
            },
        )
    }

    /// Credentials for a Cloudflare website certificate: stored or from
    /// the environment, else asked for (never written here).
    fn cloudflare(&self, state: &FrpState) -> Result<Option<CfCredentials>> {
        let cf = state.web().is_some_and(|w| w.tls == WebTls::Cloudflare);
        if !cf {
            return Ok(None);
        }
        let ctx = self.ctx();
        let dir = ctx.paths.frp_root.join("web-tls");
        if let Some(found) = cloudflare::lookup_with(ctx, &dir, self.rt.env)? {
            return Ok(Some(found));
        }
        ensure!(ctx.ui.interactive(), "{}", cloudflare::MISSING);
        cloudflare::prompt(ctx.ui.as_ref()).map(Some)
    }

    fn update(&self, version: Option<String>) -> Result<()> {
        let current = lifecycle::installed_state(&self.rt)?;
        let mut draft = Draft::of(&current);
        draft.version = version.unwrap_or_else(|| "latest".to_owned());
        let state = draft::finish(&draft, Some(&current))?;
        out::data(&summary(&state))?;
        let cloudflare = self.cloudflare(&state)?;
        if !self.ctx().ui.confirm(CONFIRM_UPDATE, false)? {
            return Ok(());
        }
        lifecycle::apply(
            &self.rt,
            state,
            Change {
                cloudflare,
                reason: "更新",
                skip_unchanged: true,
                ..Change::default()
            },
        )
    }

    fn rotate_token(&self) -> Result<()> {
        let state = lifecycle::installed_state(&self.rt)?;
        out::data(&summary(&state))?;
        let cloudflare = self.cloudflare(&state)?;
        if !self.ctx().ui.confirm(CONFIRM_ROTATE, false)? {
            return Ok(());
        }
        lifecycle::apply(
            &self.rt,
            state,
            Change {
                rotate: true,
                cloudflare,
                reason: "轮换 token",
                ..Change::default()
            },
        )
    }

    fn uninstall(&self) -> Result<()> {
        ensure!(
            model::installed(&self.ctx().paths),
            "{}",
            model::NOT_INSTALLED
        );
        if !self.ctx().ui.confirm(CONFIRM_UNINSTALL, false)? {
            return Ok(());
        }
        let lock = self.rt.lock()?;
        lifecycle::uninstall(&self.rt, &lock)
    }

    /// The last lines of each FRP service's log.
    fn logs(&self) -> Result<()> {
        let services = self.rt.services();
        let mut shown = false;
        for name in [FRPS, FRP_WEB] {
            if name == FRP_WEB && !services.exists(name) {
                continue;
            }
            match services.logs(name, LOG_LINES) {
                Ok(text) => {
                    out::data(&format!("==> {name} <=="))?;
                    out::data(text.trim_end())?;
                    shown = true;
                }
                Err(e) => out::warn(format!("{name}: {e}")),
            }
        }
        if !shown {
            out::info("暂无 FRP 日志");
        }
        Ok(())
    }

    /// The interactive menu (G41; module docs for the rules).
    fn menu(&self) -> Result<()> {
        let items: Vec<String> = MENU.iter().map(|(_, label)| label.to_string()).collect();
        loop {
            let title = format!("FRP 服务端\n{}", self.headline());
            let Some(choice) = self.ctx().ui.select(&title, &items, BACK, true)? else {
                return Ok(());
            };
            let Some((item, _)) = MENU.get(choice) else {
                continue;
            };
            let action = item.action();
            let outcome = if action.requires_root() && !self.is_root {
                Err(Error::msg(ROOT_REQUIRED))
            } else {
                self.run(action)
            };
            match outcome {
                Ok(()) => {}
                Err(e) if e.is_cancelled() => out::info("操作已取消"),
                Err(e) => out::error(e),
            }
        }
    }

    /// `web · frp.example.com:7000 · frps 运行中` (or why there is none).
    fn headline(&self) -> String {
        let paths = &self.ctx().paths;
        if !model::installed(paths) {
            return "未安装".to_owned();
        }
        match model::load(paths) {
            Ok(Some(state)) => {
                let mode = if state.is_web() { "web" } else { "tcp" };
                let running = if self.rt.services().running(FRPS) {
                    "运行中"
                } else {
                    "已停止"
                };
                format!(
                    "{mode} · {}:{} · frps {running}",
                    state.domain, state.bind_port
                )
            }
            Ok(None) => "未安装".to_owned(),
            Err(e) => format!("状态无法读取: {e}"),
        }
    }
}

/// One menu entry (v2 order).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MenuItem {
    Configure,
    Info,
    Client,
    Start,
    Stop,
    Restart,
    Update,
    Renew,
    RotateToken,
    Log,
    Uninstall,
}

impl MenuItem {
    fn action(self) -> Action {
        match self {
            MenuItem::Configure => Action::Configure {
                flags: Flags::default(),
                dry_run: false,
                plan: false,
            },
            MenuItem::Info => Action::Info,
            MenuItem::Client => Action::Client(ExportRequest::default()),
            MenuItem::Start => Action::Service(ServiceAction::Start),
            MenuItem::Stop => Action::Service(ServiceAction::Stop),
            MenuItem::Restart => Action::Service(ServiceAction::Restart),
            MenuItem::Update => Action::Update(None),
            MenuItem::Renew => Action::Renew { cron: false },
            MenuItem::RotateToken => Action::RotateToken,
            MenuItem::Log => Action::Log,
            MenuItem::Uninstall => Action::Uninstall,
        }
    }
}

const MENU: [(MenuItem, &str); 11] = [
    (MenuItem::Configure, "安装/配置"),
    (MenuItem::Info, "状态"),
    (MenuItem::Client, "导出客户端"),
    (MenuItem::Start, "启动"),
    (MenuItem::Stop, "停止"),
    (MenuItem::Restart, "重启"),
    (MenuItem::Update, "更新"),
    (MenuItem::Renew, "续期"),
    (MenuItem::RotateToken, "轮换 token"),
    (MenuItem::Log, "日志"),
    (MenuItem::Uninstall, "卸载"),
];

#[cfg(test)]
mod tests;
