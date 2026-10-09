//! Service commands: `start|stop|restart|status` (the proxy cores),
//! `log|logs [内核]`, `service NAME [操作]`, the boot entry `net-apply`
//! (aliases `hop-apply`, `boot`) and `hop-clear`.
//!
//! Locks (G33): changing a service takes the configuration lock of the
//! scope it belongs to (node: `ROOT/.apply.lock`, FRP: the FRP lock), so a
//! start cannot interleave with an apply; `start` waits up to five minutes
//! for it because concurrent `@reboot` lines (no-init autostart) start
//! services while `net-apply` may hold it. A service whose own start takes
//! that lock (`onebox-network`, `onebox-frps`) is started without it.
//! `status` and `log` take no lock and need no root.
//!
//! Changes from v2 (spec B §2.4, §2.8, E §2.1, E-8.1#10/#11): `reload` is
//! refused with a hint (units define no reload); service changes are
//! serialized with configuration changes; `start` waits until the service
//! runs and says so; `hop-clear` takes the node lock and reports rules it
//! could not remove.

use crate::cli::args::{ArgSpec, CommandSpec, Group, Matches, Root};
use crate::cli::session::{with_system, Session};
use crate::ctx::Ctx;
use crate::domain::protocol::Core;
use crate::error::{Error, Result};
use crate::host::service::{validate_name, Scope, ServiceDef, WAIT_RUNNING};
use crate::sys::lock::{FileLock, BUSY_MESSAGE};
use std::time::Duration;

const FRP_BUSY: &str = "另一个 FRP 操作正在进行；稍后重试";
const START_WAIT: Duration = Duration::from_secs(300);
const LOG_LINES: usize = 200;

/// A service operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    Start,
    Stop,
    Restart,
    Enable,
    Disable,
    Remove,
    Status,
    Log,
}

impl Action {
    pub fn parse(word: &str) -> Result<Action> {
        Ok(match word {
            "start" => Action::Start,
            "stop" => Action::Stop,
            "restart" => Action::Restart,
            "enable" => Action::Enable,
            "disable" => Action::Disable,
            "remove" => Action::Remove,
            "status" => Action::Status,
            "log" | "logs" => Action::Log,
            "reload" => bail!("不支持 reload，请使用 restart"),
            _ => bail!("未知服务操作"),
        })
    }

    /// Read-only actions need neither root nor a lock.
    pub fn read_only(self) -> bool {
        matches!(self, Action::Status | Action::Log)
    }

    fn done(self) -> &'static str {
        match self {
            Action::Start => "已启动",
            Action::Stop => "已停止",
            Action::Restart => "已重启",
            Action::Enable => "已设为开机启动",
            Action::Disable => "已取消开机启动",
            Action::Remove => "已删除",
            Action::Status | Action::Log => "",
        }
    }
}

const fn core_action(name: &'static str, summary: &'static str) -> CommandSpec {
    CommandSpec::new(name, Group::Service, summary).handler(cores_command)
}

pub const START: CommandSpec = core_action("start", "启动代理内核");
pub const STOP: CommandSpec = core_action("stop", "停止代理内核");
pub const RESTART: CommandSpec = core_action("restart", "重启代理内核");
pub const STATUS: CommandSpec = core_action("status", "代理内核运行状态").root(Root::NotRequired);

pub const LOG: CommandSpec = CommandSpec::new("log", Group::Service, "代理内核日志（最近 200 行）")
    .aliases(&["logs"])
    .args(&[ArgSpec::optional("内核", "singbox（默认）/ xray")])
    .root(Root::NotRequired)
    .handler(log_command);

pub const SERVICE: CommandSpec =
    CommandSpec::new("service", Group::Service, "单独控制某个 Onebox 服务")
        .usage(&["service 服务名 [start|stop|restart|enable|disable|remove|status|log]"])
        .args(&[
            ArgSpec::optional("服务名", "onebox-…，如 onebox-site"),
            ArgSpec::optional("操作", "默认 status"),
        ])
        .root(Root::Custom(service_needs_root))
        .handler(service_command);

pub const NET_APPLY: CommandSpec = CommandSpec::new(
    "net-apply",
    Group::Hidden,
    "开机恢复防火墙规则与端口跳跃（onebox-network 调用）",
)
.aliases(&["hop-apply", "boot"])
.handler(net_apply_command);

pub const HOP_CLEAR: CommandSpec =
    CommandSpec::new("hop-clear", Group::Hidden, "清除 Hysteria2 端口跳跃规则")
        .handler(hop_clear_command);

fn service_needs_root(m: &Matches) -> bool {
    m.positional(1)
        .map_or(Ok(Action::Status), Action::parse)
        .is_ok_and(|a| !a.read_only())
}

fn cores_command(ctx: &Ctx, m: &Matches) -> Result<()> {
    let action = Action::parse(m.path.first().copied().unwrap_or("status"))?;
    with_system(ctx, |s| cores(s, action))
}

/// `start|stop|restart|status` for every core the node uses.
pub fn cores(session: &Session, action: Action) -> Result<()> {
    let loaded = session.load()?;
    let services = session.services();
    if action == Action::Status {
        let lines: Vec<String> = loaded
            .config
            .cores()
            .into_iter()
            .map(|core| {
                let state = if session.live.running(core.service()) {
                    "运行中"
                } else {
                    "已停止"
                };
                format!("{core}: {state}")
            })
            .collect();
        return session.data(&lines.join("\n"));
    }
    session.require_root()?;
    let _lock = node_lock(session, action)?;
    for core in loaded.config.cores() {
        act(session, &services, core.service(), action)?;
        session.ok(format!("{} {}", core.title(), action.done()));
    }
    Ok(())
}

fn node_lock(session: &Session, action: Action) -> Result<FileLock> {
    lock(session, Scope::Node, action)
}

fn lock(session: &Session, scope: Scope, action: Action) -> Result<FileLock> {
    let path = scope.lock_path(&session.ctx.paths);
    let busy = match scope {
        Scope::Node => BUSY_MESSAGE,
        Scope::Frp => FRP_BUSY,
    };
    if action == Action::Start {
        FileLock::acquire_waiting(&path, busy, START_WAIT, Duration::from_secs(1))
    } else {
        FileLock::acquire(&path, busy)
    }
}

/// Run one mutating action on `name`.
fn act(
    session: &Session,
    services: &crate::host::service::Services,
    name: &str,
    action: Action,
) -> Result<()> {
    match action {
        Action::Start => {
            services.start(name)?;
            services.wait_running(name, WAIT_RUNNING)
        }
        Action::Restart => {
            services.restart(name)?;
            services.wait_running(name, WAIT_RUNNING)
        }
        Action::Stop => services.stop(name),
        Action::Enable => services.enable(name),
        Action::Disable => services.disable(name),
        Action::Remove => services.remove(name),
        Action::Status => session.data(&services.status_line(name)),
        Action::Log => session.data(&services.logs(name, LOG_LINES)?),
    }
}

fn log_command(ctx: &Ctx, m: &Matches) -> Result<()> {
    let core = m.positional(0).map_or(Ok(Core::Singbox), str::parse)?;
    with_system(ctx, |s| log(s, core))
}

/// `log [内核]`: the last 200 lines of a core's log.
pub fn log(session: &Session, core: Core) -> Result<()> {
    let services = session.services();
    session.data(&services.logs(core.service(), LOG_LINES)?)
}

fn service_command(ctx: &Ctx, m: &Matches) -> Result<()> {
    let name = m.positional(0).ok_or_else(|| Error::msg("缺少服务名称"))?;
    let action = m.positional(1).map_or(Ok(Action::Status), Action::parse)?;
    with_system(ctx, |s| service(s, name, action))
}

/// `service NAME ACTION` with the lock rules of the module docs.
pub fn service(session: &Session, name: &str, action: Action) -> Result<()> {
    validate_name(name)?;
    let services = session.services();
    if action.read_only() {
        return act(session, &services, name, action);
    }
    session.require_root()?;
    let def = ServiceDef::skeleton(&session.ctx.paths, name);
    let starts_itself =
        matches!(action, Action::Start | Action::Restart) && def.takes_lock() == Some(def.scope());
    let _lock = if starts_itself {
        None
    } else {
        Some(lock(session, def.scope(), action)?)
    };
    act(session, &services, name, action)?;
    session.ok(format!("{name} {}", action.done()));
    Ok(())
}

fn net_apply_command(ctx: &Ctx, _m: &Matches) -> Result<()> {
    with_system(ctx, |s| s.engine.boot(s.ctx))
}

fn hop_clear_command(ctx: &Ctx, _m: &Matches) -> Result<()> {
    with_system(ctx, hop_clear)
}

/// `hop-clear`: remove every recorded port-hopping rule (node lock held).
pub fn hop_clear(session: &Session) -> Result<()> {
    session.require_root()?;
    let _lock = FileLock::acquire(&session.ctx.paths.lock(), BUSY_MESSAGE)?;
    let report = crate::host::hop::clear(session.ctx)?;
    ensure!(
        report.failed.is_empty(),
        "部分端口跳跃规则未清理（已保留记录）: {}",
        report.failed.join("; ")
    );
    session.ok(format!("已清除端口跳跃规则 {} 条", report.removed.len()));
    Ok(())
}

#[cfg(test)]
mod tests;
