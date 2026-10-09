//! The interactive menu (`onebox` without arguments, ARCH §6.1).
//!
//! The header (version, cores, node address, protocol count, core state)
//! heads the main menu; every submenu shows its current values first and
//! ends with `0) 返回`. Node features call the command modules' functions
//! directly; the features of the independent modules (subscription, FRP,
//! updates, backups, doctor) and the link tools run fixed command lines
//! through the registry — never words the user typed.
//!
//! What an action's result does (G5): success and ordinary errors (`[错误]
//! …`) return to the same menu; `Exit{2}` (warnings-only result) prints
//! `[警告] …` and continues; a cancellation inside the action (EOF or
//! Ctrl+C at one of its questions — the menu's prompter turns the signal
//! into a cancellation, see [`interrupt`]) prints `[提示]` and continues;
//! `Exit{0}` (a finished self-update) and `Exit{75}` end the process, so
//! the replaced program never keeps running; EOF (or Ctrl+C) at a menu
//! prompt itself — the main menu's or any submenu's, including the FRP and
//! BBR menus the commands show ([`Menu::command_menu`]) — leaves with 130.
//! Under `-y` the menu picks `0) 退出` at once.
//!
//! Typed values reach dispatched command lines only after `--`, so an
//! answer such as `-y` or `--help` is data, never an option.
//!
//! Changes from v2 (spec B §2.9, B-9.1#11/#25): eleven grouped entries
//! instead of 28; no menu item dispatches typed text as a command (v2 item
//! 24); prompts default to the current values (v2's site title default
//! was the literal `山间手记`); a not-installed host gets its own menu with
//! restore and recovery when they apply (G29); `Exit{2}` and cancelled
//! actions no longer end the menu.

mod feature;
pub mod interrupt;
mod node;
mod perf;

use crate::cli::commands::install::{self, InstallArgs};
use crate::cli::registry;
use crate::cli::session::{with_system, Session};
use crate::cli::wizard::steps;
use crate::ctx::Ctx;
use crate::domain::config::NodeConfig;
use crate::error::{Error, Result};
use crate::state::Loaded;
use crate::ui::menu::{choose, Entry};
use crate::VERSION;
use std::cell::Cell;
use std::sync::Arc;

/// Runs fixed command lines (the registry in production).
pub trait Dispatcher {
    fn dispatch(&self, session: &Session, argv: &[&str]) -> Result<()>;
}

/// The command registry with the session's root fact.
pub struct Registry;

impl Dispatcher for Registry {
    fn dispatch(&self, session: &Session, argv: &[&str]) -> Result<()> {
        registry::dispatch(registry::COMMANDS, session.ctx, argv, session.is_root)
    }
}

/// `onebox` without arguments. Without a terminal (and without `-y`) the
/// command overview is printed instead, as a menu could not be answered.
/// Questions asked from the menu (its own and its actions') are cancelled
/// by Ctrl+C ([`interrupt::Interruptible`]).
pub fn run(ctx: &Ctx) -> Result<()> {
    if let Some(help) = unanswerable(ctx.ui.as_ref()) {
        return crate::ui::out::data(&help);
    }
    let ctx = Ctx {
        ui: Arc::new(interrupt::Interruptible::new(ctx.ui.clone())),
        ..ctx.clone()
    };
    with_system(&ctx, |session| Menu::new(session, &Registry).main())
}

/// The command overview to print instead of a menu nobody can answer
/// (no terminal and no `-y`); `None` when the menu runs.
pub fn unanswerable(ui: &dyn crate::ui::Prompter) -> Option<String> {
    (!ui.interactive() && !ui.assume_yes())
        .then(|| crate::cli::help::global_help(registry::COMMANDS))
}

pub struct Menu<'a> {
    pub session: &'a Session<'a>,
    pub dispatcher: &'a dyn Dispatcher,
    /// Set when a menu prompt was cancelled: every loop unwinds (G5).
    left: Cell<bool>,
}

/// An entry of the main menu.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Main {
    Info,
    Protocols,
    Connection,
    Subscription,
    Site,
    Services,
    Performance,
    Backups,
    Frp,
    Update,
    Reinstall,
    // Not installed.
    Install,
    Preview,
    Bbr,
    UpdateProgram,
    Restore,
    Recover,
}

impl Main {
    fn entry(self) -> Entry {
        let (label, hint) = match self {
            Main::Info => ("节点信息与分享", "查看节点、导出客户端配置、二维码"),
            Main::Protocols => ("协议管理", "添加 / 删除协议、修改端口"),
            Main::Connection => ("连接与伪装", "连接地址、REALITY 目标、ShadowTLS、TLS 证书"),
            Main::Subscription => ("远程订阅", ""),
            Main::Site => ("自有域名网站", ""),
            Main::Services => ("服务", "状态、启动/停止/重启、日志"),
            Main::Performance => ("性能与诊断", "调优、体检、链路测试、BBR"),
            Main::Backups => ("备份与恢复", "快照、恢复、故障恢复、重新生成配置"),
            Main::Frp => ("FRP 服务端", ""),
            Main::Update => ("更新", "程序、内核、更新渠道"),
            Main::Reinstall => ("重装 / 卸载", ""),
            Main::Install => ("安装", ""),
            Main::Preview => ("安装预演", ""),
            Main::Bbr => ("BBR", ""),
            Main::UpdateProgram => ("更新程序", ""),
            Main::Restore => ("恢复快照", ""),
            Main::Recover => ("故障恢复", ""),
        };
        Entry::with_hint(label, hint)
    }
}

/// The installed node's main menu, in ARCH §6.1 order.
pub const INSTALLED: [Main; 11] = [
    Main::Info,
    Main::Protocols,
    Main::Connection,
    Main::Subscription,
    Main::Site,
    Main::Services,
    Main::Performance,
    Main::Backups,
    Main::Frp,
    Main::Update,
    Main::Reinstall,
];

impl<'a> Menu<'a> {
    pub fn new(session: &'a Session<'a>, dispatcher: &'a dyn Dispatcher) -> Menu<'a> {
        Menu {
            session,
            dispatcher,
            left: Cell::new(false),
        }
    }

    /// The main loop.
    pub fn main(&self) -> Result<()> {
        loop {
            let (heading, entries) = self.main_view();
            let labels: Vec<Entry> = entries.iter().map(|e| e.entry()).collect();
            let answer = choose(self.session.ui(), &heading, &labels, "退出");
            let Some(index) = self.menu_answer(answer)? else {
                return Ok(());
            };
            if let Some(entry) = entries.get(index) {
                self.after(self.main_action(*entry))?;
            }
        }
    }

    /// An answer at a menu prompt; a cancellation there leaves the whole
    /// menu (exit 130), unlike one inside an action.
    fn menu_answer<T>(&self, answer: Result<T>) -> Result<T> {
        answer.inspect_err(|e| {
            if e.is_cancelled() {
                self.left.set(true);
            }
        })
    }

    /// After an action: unwind when a (nested) menu prompt was cancelled,
    /// else the [`outcome`](Menu::outcome) rules.
    fn after(&self, result: Result<()>) -> Result<()> {
        if self.left.get() {
            return result.and(Err(Error::Cancelled));
        }
        self.outcome(result)
    }

    /// Header and entries for the current state of the host.
    fn main_view(&self) -> (String, Vec<Main>) {
        match self.session.load_optional() {
            Ok(Some(loaded)) => (
                header(self.session, Some(&loaded.config)),
                INSTALLED.to_vec(),
            ),
            Ok(None) => (header(self.session, None), self.not_installed()),
            Err(e) => (
                format!("{}\n[错误] {}", header(self.session, None), e.report_text()),
                self.not_installed(),
            ),
        }
    }

    /// `1) 安装 2) 安装预演 3) FRP 4) BBR 5) 更新程序`, plus restore and
    /// recovery when they apply (G29).
    pub fn not_installed(&self) -> Vec<Main> {
        let mut entries = vec![
            Main::Install,
            Main::Preview,
            Main::Frp,
            Main::Bbr,
            Main::UpdateProgram,
        ];
        let paths = &self.session.ctx.paths;
        if has_backups(&paths.backups()) {
            entries.push(Main::Restore);
        }
        // A journal that cannot even be read needs recovery too.
        let pending = match crate::apply::journal::pending(paths) {
            Ok(pending) => pending.any(),
            Err(_) => true,
        };
        if pending {
            entries.push(Main::Recover);
        }
        entries
    }

    fn main_action(&self, entry: Main) -> Result<()> {
        match entry {
            Main::Info => self.info_menu(),
            Main::Protocols => self.protocol_menu(),
            Main::Connection => self.connection_menu(),
            Main::Subscription => self.subscription_menu(),
            Main::Site => self.site_menu(),
            Main::Services => self.service_menu(),
            Main::Performance => self.performance_menu(),
            Main::Backups => self.backup_menu(),
            Main::Frp => self.command_menu(&["frps"]),
            Main::Update => self.update_menu(),
            Main::Reinstall => self.reinstall_menu(),
            Main::Install => install::install(self.session, &InstallArgs::default()),
            Main::Preview => self.preview(),
            Main::Bbr => self.command_menu(&["bbr"]),
            Main::UpdateProgram => self.dispatch(&["update-script"]),
            Main::Restore => self.restore(),
            Main::Recover => self.dispatch(&["recover"]),
        }
    }

    /// A submenu: `heading` (current values) is rebuilt every round.
    pub fn submenu(
        &self,
        heading: &dyn Fn() -> String,
        entries: &[Entry],
        act: &dyn Fn(usize) -> Result<()>,
    ) -> Result<()> {
        loop {
            let answer = choose(self.session.ui(), &heading(), entries, "返回");
            let Some(index) = self.menu_answer(answer)? else {
                return Ok(());
            };
            self.after(act(index))?;
        }
    }

    /// What the menu does after an action (module docs, G5).
    pub fn outcome(&self, result: Result<()>) -> Result<()> {
        match result {
            Ok(()) => Ok(()),
            // Exit 0, or 75 (the program was replaced while recovering a
            // self-update), ends the menu even when wrapped in context.
            Err(e) if matches!(crate::update::exit_within(&e), Some(0 | 75)) => Err(e),
            Err(Error::Exit { code: 2, message }) => {
                self.session.warn(message);
                Ok(())
            }
            Err(e) if e.is_cancelled() => {
                self.session.info(e.report_text());
                Ok(())
            }
            Err(e) => {
                self.session.error(e.report_text());
                Ok(())
            }
        }
    }

    pub fn dispatch(&self, argv: &[&str]) -> Result<()> {
        self.dispatcher.dispatch(self.session, argv)
    }

    /// A command whose own interactive menu runs as a submenu (`frps`,
    /// `bbr`). Such a menu keeps its items' errors and cancellations to
    /// itself and returns a cancellation only from its own prompt, so that
    /// one leaves the whole menu (exit 130) like a cancellation at a native
    /// submenu's prompt.
    fn command_menu(&self, argv: &[&str]) -> Result<()> {
        self.menu_answer(self.dispatch(argv))
    }

    /// The loaded node for a submenu action.
    pub fn loaded(&self) -> Result<Loaded> {
        self.session.load()
    }

    /// Preview an install of a chosen combination.
    fn preview(&self) -> Result<()> {
        let mut args = InstallArgs::default();
        steps::protocols(self.session.ui(), &mut args)?;
        install::preview(self.session, &args)
    }

    /// List the backups, then restore one (`latest` by default).
    fn restore(&self) -> Result<()> {
        self.dispatch(&["backups"])?;
        let id = self
            .session
            .ui()
            .input_with("备份 ID 或 latest", "latest", &|id: &str| {
                backup_id(id).map(str::to_owned)
            })?;
        self.dispatch(&["restore", "--", &id])
    }
}

/// A backup id (`{seconds}-{8 hex}`, v1 forms included) or `latest`.
pub fn backup_id(id: &str) -> Result<&str> {
    let ok = id == "latest"
        || (!id.is_empty()
            && id.len() <= 64
            && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-'));
    if ok {
        Ok(id)
    } else {
        Err(Error::msg("备份 ID 无效"))
    }
}

/// Whether `dir` holds at least one backup (a directory with a manifest).
pub fn has_backups(dir: &std::path::Path) -> bool {
    std::fs::read_dir(dir).is_ok_and(|entries| {
        entries.flatten().any(|e| {
            !e.file_name().to_string_lossy().starts_with('.')
                && e.path().join("manifest.json").is_file()
        })
    })
}

/// The two header lines (ARCH §6.1).
pub fn header(session: &Session, cfg: Option<&NodeConfig>) -> String {
    let Some(cfg) = cfg else {
        return format!("Onebox {VERSION}\n尚未安装节点");
    };
    let mut first = vec![format!("Onebox {VERSION}")];
    for core in cfg.cores() {
        let version = cfg.versions.installed(core).unwrap_or("未知版本");
        first.push(format!("{} {version}", core.title()));
    }
    let running = cfg
        .cores()
        .into_iter()
        .filter(|c| session.live.running(c.service()))
        .count();
    let state = match running {
        0 => "内核已停止",
        n if n == cfg.cores().len() => "内核运行中",
        _ => "部分内核已停止",
    };
    format!(
        "{}\n节点 {} · {} 个协议 · {state}",
        first.join(" · "),
        cfg.server.addr,
        cfg.inbounds.len()
    )
}

#[cfg(test)]
mod tests;
