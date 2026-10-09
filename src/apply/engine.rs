//! One apply, start to end (ARCH §4, spec B §4.1):
//!
//! 1. recover leftovers (node journal, then the self-update journal);
//! 2. compare-and-swap: the caller's `state.json` hash must still be the
//!    current one, before any side effect;
//! 3. cancellation handlers for INT/TERM/HUP (honored between stages);
//! 4. defaults, `NodeConfig::validate`, `PortPlan::validate` with FRP's
//!    reservations, replacement and cron preconditions;
//! 5. runtime snapshot (running / enabled services, the node's crontab);
//! 6. journal begun (snapshot of every owned path);
//! 7. the stages; on failure a rollback, unless the journal already says
//!    `committed`.
//!
//! Errors keep the v2 wording: `配置未应用，已恢复原状态: {e}`,
//! `配置失败: {e}；恢复未完成: {r}；事务日志保留于 {dir}，请执行 recover`,
//! `配置已提交，但事务清理失败: {e}；请执行 recover 清理`. A cancellation keeps
//! exit code 130 through all of them (B-9.1#16).
//!
//! Changes from v2: preconditions that need no side effect (replacements,
//! the cron daemon for ACME renewals) fail before the journal exists; a
//! pending signal fails before anything starts; whatever error an apply
//! ends with while a signal is pending becomes a cancellation (exit 130)
//! and the signal is cleared (`recover::settle_signal`), so the next
//! operation of an interactive session is not cancelled by it; a
//! `state.json` that exists but cannot be read no longer blocks a
//! reinstall; crash leftovers are swept before the journal snapshot, so
//! they are neither copied into it nor restored.

use super::features::Features;
use super::journal::{self, Journal, Phase};
use super::recover::{self, keep_cancellation};
use super::request::{ApplyRequest, Intents};
use super::stages::{self, Run};
use super::{rollback, transaction};
use crate::ctx::Ctx;
use crate::domain::ports::PortPlan;
use crate::domain::NodeConfig;
use crate::error::{Error, Result};
use crate::host::service::Services;
use crate::state::StateStore;
use crate::sys::lock::FileLock;
use crate::sys::signal::{self, SignalScope};
use crate::ui::out;

/// [`crate::apply::apply_locked`] with explicit feature hooks.
pub fn apply_with(
    ctx: &Ctx,
    lock: &FileLock,
    req: ApplyRequest,
    features: &dyn Features,
) -> Result<()> {
    recover::settle_signal(run(ctx, lock, req, features))
}

fn run(ctx: &Ctx, lock: &FileLock, req: ApplyRequest, features: &dyn Features) -> Result<()> {
    recover::recover_all(ctx, lock)?;
    if StateStore::current_hash(ctx)? != req.expected {
        return Err(Error::Conflict);
    }
    let _signals = SignalScope::install()?;
    signal::check()?;
    let ApplyRequest {
        mut config,
        intents,
        reason,
        ..
    } = req;
    let services = Services::detect(ctx);
    preflight(ctx, &services, &mut config, &intents)?;
    let old = old_config(ctx)?;
    let runtime = transaction::runtime_state(ctx, &services)?;
    stages::sweep_leftovers(&ctx.paths);
    let journal = transaction::begin(ctx, reason, old.clone(), runtime)?;
    let mut run = Run::new(ctx, features, services, journal, config, old, intents);
    if let Err(error) = stages::run_all(&mut run) {
        return Err(failed(ctx, lock, &mut run.journal, error));
    }
    transaction::finish(&ctx.paths).map_err(|e| {
        Error::msg(format!(
            "配置已提交，但事务清理失败: {e}；请执行 recover 清理"
        ))
    })?;
    out::ok(format!("{reason}完成"));
    Ok(())
}

/// Step 4: everything that can be refused without touching the host.
fn preflight(
    ctx: &Ctx,
    services: &Services,
    config: &mut NodeConfig,
    intents: &Intents,
) -> Result<()> {
    if config.installed_at == 0 {
        config.installed_at = crate::sys::time::now();
    }
    config.validate()?;
    let frp = super::frp_reservations(&ctx.paths)?;
    PortPlan::of(config, &frp).validate()?;
    stages::check_replacements(config, &intents.replace_cores)?;
    stages::cron_precheck(ctx, config, services.init())
}

/// The running generation's configuration. A state.json that exists but
/// cannot be read (corrupt, or a v2 state the migration rejects) does not
/// block the apply — the request's hash matched those very bytes, so this
/// is a reinstall or restore over them: the snapshot keeps the file for a
/// rollback, which then skips re-applying old network rules with a
/// warning. A v1 installation (no state.json) is still refused.
fn old_config(ctx: &Ctx) -> Result<Option<NodeConfig>> {
    match StateStore::load(ctx) {
        Ok(loaded) => Ok(loaded.map(|loaded| loaded.config)),
        Err(e) if std::fs::symlink_metadata(ctx.paths.state()).is_ok() => {
            out::warn(format!(
                "现有 state.json 无法读取（{}），按全新配置应用；失败时将恢复原文件",
                e.report_text()
            ));
            Ok(None)
        }
        Err(e) => Err(e),
    }
}

/// The error of a failed apply after the rollback it triggers.
fn failed(ctx: &Ctx, lock: &FileLock, journal: &mut Journal, error: Error) -> Error {
    let dir = journal::dir(&ctx.paths);
    // Without the generic "操作已取消" tail of a wrapped cancellation.
    let cause = error.report_text();
    let result = if *journal.phase() == Phase::Committed {
        let message = format!("配置已提交，但事务清理失败: {cause}；请执行 recover 清理");
        keep_cancellation(error, message)
    } else {
        out::warn(format!("{cause}；正在恢复原配置…"));
        match rollback::rollback(ctx, lock, journal) {
            Ok(()) => error.wrap("配置未应用，已恢复原状态"),
            Err(recovery) => {
                let message = format!(
                    "配置失败: {cause}；恢复未完成: {}；事务日志保留于 {}，请执行 recover",
                    recovery.report_text(),
                    dir.display()
                );
                keep_cancellation(error, message)
            }
        }
    };
    result
}
