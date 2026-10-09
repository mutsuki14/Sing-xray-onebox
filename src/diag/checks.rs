//! The check list (what runs, in which order) and the checks that read no
//! more than a file or two: node state, pending journals, the installed
//! program, the firewall and hop ledgers, the FRP state.

use super::survey::{FrpFound, NodeState, Survey};
use super::{node, tls, Check, CheckFn, CheckStatus, Diagnosis, Doctor};
use crate::apply::journal::{self, Pending, PhaseInfo};
use crate::ctx::Ctx;
use crate::domain::config::PortRange;
use crate::domain::version::Semver;
use crate::domain::{NodeConfig, Protocol};
use crate::error::{Error, Result};
use crate::host::firewall::{ledger_path, Ledger};
use crate::host::hop::{self, Hop};
use crate::paths::Paths;
use crate::state::Origin;
use crate::sys::exec::Cmd;
use crate::sys::fs::TempDir;
use crate::sys::lock::{FileLock, BUSY_MESSAGE};
use std::time::Duration;

pub const STATE: &str = "节点配置";
pub const MIGRATION: &str = "配置迁移";
pub const JOURNAL: &str = "未完成事务";
pub const PROGRAM: &str = "管理程序";
pub const FIREWALL: &str = "防火墙台账";
pub const HOPS: &str = "端口跳跃";
pub const FRP: &str = "FRP 服务端";
const VERSION_TIMEOUT: Duration = Duration::from_secs(15);

/// Prefix of a failure downgraded while a configuration operation runs.
pub const TRANSIENT: &str = "配置操作进行中，可能是暂时的: ";

/// Checks recorded in order, each handed to the sink as it is added.
struct Run<'s> {
    checks: Vec<Check>,
    sink: &'s mut dyn FnMut(&Check),
    /// A configuration operation runs: failures become warnings.
    transient: bool,
}

impl Run<'_> {
    fn push(&mut self, check: Check) {
        let check = if self.transient {
            downgrade(check)
        } else {
            check
        };
        (self.sink)(&check);
        self.checks.push(check);
    }

    fn extend(&mut self, checks: impl IntoIterator<Item = Check>) {
        for check in checks {
            self.push(check);
        }
    }
}

/// A failure seen while an operation stops services and swaps files on
/// purpose is reported as a warning (doctor must not exit 1 for it).
pub fn downgrade(check: Check) -> Check {
    if check.is_fail() {
        Check::warn(check.name, format!("{TRANSIENT}{}", check.detail))
    } else {
        check
    }
}

/// See [`Doctor::diagnose`].
pub(super) fn diagnose(
    doctor: &Doctor,
    extra: &[CheckFn],
    sink: &mut dyn FnMut(&Check),
) -> Result<Diagnosis> {
    let ctx = doctor.ctx;
    let survey = Survey::gather(ctx);
    let running = operation_running(&ctx.paths);
    // Decided before anything is printed: an interrupted first install
    // leaves a journal but no state, and must still be diagnosed.
    let journal = journal_check(&ctx.paths, running);
    let nothing = !survey.node.present() && !survey.frp.installed();
    if nothing && journal.status == CheckStatus::Pass {
        return Err(Error::NotInstalled);
    }
    let mut run = Run {
        checks: Vec::new(),
        sink,
        transient: false,
    };
    run.extend(state_checks(&survey.node));
    run.push(journal);
    run.transient = running;
    run.push(program_check(ctx));
    if let Some(cfg) = survey.config() {
        node_checks(doctor, cfg, &mut run);
    }
    if survey.node.present() {
        run.extend(ledger_checks(ctx, survey.config()));
    }
    run.extend(frp_check(&survey.frp));
    for provider in extra {
        run.extend(provider(doctor, survey.config()));
    }
    Ok(Diagnosis {
        survey,
        checks: run.checks,
        operation_running: running,
    })
}

/// Everything that needs the loaded configuration.
fn node_checks(doctor: &Doctor, cfg: &NodeConfig, run: &mut Run) {
    // sing-box checks need a working directory; a private one keeps the
    // diagnosis from creating `RUN/check` (G42). Removed on drop.
    let temp = TempDir::new("doctor").map_err(|e| e.to_string());
    let workdir = temp.as_ref().map(TempDir::path).map_err(String::as_str);
    run.extend(node::core_checks(doctor.ctx, cfg, workdir));
    run.extend(node::service_checks(&doctor.services(), cfg));
    run.extend(tls::certificate_checks(doctor, cfg));
    run.extend(tls::nginx_checks(doctor.ctx, cfg));
    run.extend(tls::renewal_check(doctor, cfg));
}

/// `节点配置`: loaded (protocol summary), still in v2 shape (with the
/// migration notes), unusable, or not installed.
pub fn state_checks(node: &NodeState) -> Vec<Check> {
    match node {
        NodeState::Absent => vec![Check::pass(STATE, "未安装代理节点")],
        NodeState::Invalid(message) => vec![Check::fail(STATE, message.clone())],
        NodeState::Loaded(loaded) => {
            let summary = protocol_summary(&loaded.config);
            match &loaded.origin {
                Origin::V3 => vec![Check::pass(STATE, summary)],
                Origin::V2 { warnings, .. } => {
                    let mut checks = vec![Check::warn(
                        STATE,
                        format!("{summary}；仍是 2.x 格式，执行 onebox regen 完成升级"),
                    )];
                    checks.extend(warnings.iter().map(|w| Check::warn(MIGRATION, w.clone())));
                    checks
                }
            }
        }
    }
}

/// `3 个协议：vless-reality、hysteria2、tuic`.
pub fn protocol_summary(cfg: &NodeConfig) -> String {
    let ids: Vec<&str> = cfg.protocols().map(Protocol::id).collect();
    if ids.is_empty() {
        return "没有协议".to_owned();
    }
    format!("{} 个协议：{}", ids.len(), ids.join("、"))
}

/// `未完成事务`: none, a pending config or self-update journal (a failure:
/// changes are blocked until `recover`), or an unreadable one (D-8.1#28).
/// While `running` (see [`operation_running`]) a journal — even one caught
/// half-written — is that operation's, not something to recover.
pub fn journal_check(paths: &Paths, running: bool) -> Check {
    journal_verdict(journal::pending(paths), running)
}

/// Whether a configuration operation (an apply, a recovery, a self-update)
/// runs right now: a node or self-update journal exists and another
/// process holds the node lock. Doctor runs without the lock, so the lock
/// is probed only while a journal exists, on an existing lock file
/// (nothing is created), and released at once.
pub fn operation_running(paths: &Paths) -> bool {
    let journal = [paths.transaction(), paths.self_update_journal()]
        .iter()
        .any(|p| std::fs::symlink_metadata(p).is_ok());
    journal && node_lock_held(paths)
}

fn node_lock_held(paths: &Paths) -> bool {
    let lock = paths.lock();
    let exists = std::fs::symlink_metadata(&lock).is_ok_and(|m| m.is_file());
    exists && matches!(FileLock::acquire(&lock, BUSY_MESSAGE), Err(Error::Busy(_)))
}

/// The verdict on what [`journal::pending`] found; `running` = an operation
/// holds the node lock.
pub fn journal_verdict(pending: Result<Pending>, running: bool) -> Check {
    let busy = |what: &str| {
        Check::warn(
            JOURNAL,
            format!("另一个配置操作正在进行（{what}）；完成后重新执行 onebox doctor"),
        )
    };
    match pending {
        Err(_) if running => busy("事务记录正在更新"),
        Err(e) => Check::fail(JOURNAL, format!("事务记录无法读取: {e}")),
        Ok(pending) if !pending.any() => Check::pass(JOURNAL, "无"),
        Ok(pending) => {
            let what = pending_parts(pending.config.as_ref(), pending.program);
            if running {
                busy(&what)
            } else {
                Check::fail(
                    JOURNAL,
                    format!("有未完成事务（{what}）；执行 onebox recover"),
                )
            }
        }
    }
}

/// `配置变更「添加协议」停在启动内核阶段，程序自更新`.
pub fn pending_parts(config: Option<&PhaseInfo>, program: bool) -> String {
    let mut parts = Vec::new();
    if let Some(info) = config {
        let reason = info
            .reason
            .as_deref()
            .map(|r| format!("「{r}」"))
            .unwrap_or_default();
        parts.push(format!("配置变更{reason}停在{}阶段", info.phase.label()));
    }
    if program {
        parts.push("程序自更新".to_owned());
    }
    parts.join("，")
}

/// `管理程序`: `EXE` (which every unit and cron line runs) exists, runs,
/// and is this version.
pub fn program_check(ctx: &Ctx) -> Check {
    let exe = &ctx.paths.executable;
    let shown = exe.display();
    if !exe.is_file() {
        return Check::fail(
            PROGRAM,
            format!("{shown} 不存在；服务与定时任务依赖它，执行 onebox regen 安装"),
        );
    }
    let cmd = Cmd::new(exe.to_string_lossy())
        .arg("version")
        .timeout(VERSION_TIMEOUT);
    match ctx.run(&cmd) {
        Ok(out) if out.ok() => {
            let installed = out.stdout.lines().next().unwrap_or("").trim();
            version_check(&shown.to_string(), installed, crate::VERSION)
        }
        Ok(out) => Check::fail(PROGRAM, format!("{shown} 无法运行（退出码 {}）", out.code)),
        Err(e) => Check::fail(PROGRAM, format!("{shown} 无法运行: {e}")),
    }
}

/// Compare the installed program's version with the running one.
pub fn version_check(exe: &str, installed: &str, running: &str) -> Check {
    if installed == running {
        return Check::pass(PROGRAM, format!("{exe}（{installed}）"));
    }
    let newer = Semver::parse(installed)
        .zip(Semver::parse(running))
        .is_some_and(|(i, r)| i > r);
    if newer {
        Check::warn(
            PROGRAM,
            format!("{exe} 是更新的 {installed}，本次运行的是 {running}；请直接运行 {exe}"),
        )
    } else {
        Check::warn(
            PROGRAM,
            format!("{exe} 是 {installed}，本次运行的是 {running}；执行 onebox regen 安装当前程序"),
        )
    }
}

/// `防火墙台账` and `端口跳跃`: the ledgers can be read (an unreadable one
/// blocks every apply), no temporary ACME rule was left behind, and the
/// recorded hops match the configuration.
pub fn ledger_checks(ctx: &Ctx, cfg: Option<&NodeConfig>) -> Vec<Check> {
    let load = |owner: &str| Ledger::load(&ledger_path(&ctx.paths, owner), owner);
    let mut checks = vec![firewall_check(load("proxy"), load("acme"))];
    checks.extend(hop_check(hop::recorded(ctx), cfg));
    checks
}

pub fn firewall_check(proxy: Result<Ledger>, acme: Result<Ledger>) -> Check {
    match (proxy, acme) {
        (Err(e), _) | (_, Err(e)) => Check::fail(FIREWALL, e.to_string()),
        (Ok(_), Ok(acme)) if !acme.entries.is_empty() => Check::warn(
            FIREWALL,
            format!(
                "临时证书验证规则仍在（{} 条）；执行 onebox regen 清理",
                acme.entries.len()
            ),
        ),
        (Ok(proxy), Ok(_)) => Check::pass(
            FIREWALL,
            format!("已记录 {} 条端口规则", proxy.entries.len()),
        ),
    }
}

/// The hop the configuration asks for: (range, Hysteria2 port).
fn wanted_hop(cfg: &NodeConfig) -> Option<(PortRange, u16)> {
    let port = cfg.inbound(Protocol::Hysteria2)?.port;
    cfg.hy2.hop.map(|range| (range, port))
}

/// `None` when nothing is configured or recorded (or the configuration is
/// unknown and the ledger reads fine).
pub fn hop_check(recorded: Result<Vec<Hop>>, cfg: Option<&NodeConfig>) -> Option<Check> {
    let hops = match recorded {
        Ok(hops) => hops,
        Err(e) => return Some(Check::fail(HOPS, e.to_string())),
    };
    let cfg = cfg?;
    match wanted_hop(cfg) {
        None if hops.is_empty() => None,
        None => Some(Check::warn(
            HOPS,
            format!(
                "配置未启用端口跳跃，但仍记录 {} 条规则；执行 onebox hop-clear",
                hops.len()
            ),
        )),
        Some((range, port)) => {
            let active = hops
                .iter()
                .any(|h| h.start == range.start && h.end == range.end && h.target == port);
            Some(if active {
                Check::pass(HOPS, format!("UDP {range} → {port}"))
            } else {
                Check::warn(
                    HOPS,
                    format!("UDP {range} → {port} 的规则未记录；执行 onebox hop-apply"),
                )
            })
        }
    }
}

/// `FRP 服务端`: the state of an installed FRP can be read.
pub fn frp_check(frp: &FrpFound) -> Option<Check> {
    match frp {
        FrpFound::Absent => None,
        FrpFound::Invalid(message) => Some(Check::fail(FRP, message.clone())),
        FrpFound::Loaded(state) => {
            let mode = if state.is_web() {
                "网站模式"
            } else {
                "TCP 模式"
            };
            let warnings = state.warnings();
            Some(if warnings.is_empty() {
                Check::pass(FRP, format!("状态正常（{mode}，frp {}）", state.version))
            } else {
                Check::warn(FRP, format!("{mode}；{}", warnings.join("；")))
            })
        }
    }
}

#[cfg(test)]
mod tests;
