//! FRP transactions (spec H §5.3): journal + snapshot → mutate → commit,
//! or roll back on any error or signal — immediately, or after a crash by
//! the next FRP command or `onebox recover` (G24).
//!
//! Rollback order: validate the journal (nothing changes when it is
//! corrupt) → stop and disable both FRP services, clear the `frp`
//! firewall owner → restore the snapshot (trees that did not exist are
//! removed entirely) → reload systemd → restore the FRP crontab lines →
//! for a restored installation re-open its firewall ports, re-enable and
//! restart what was enabled/running before → `rolled-back` → remove the
//! journal. Signals are blocked while it runs.
//!
//! Changes from v2:
//! - the transaction is journaled outside the trees it snapshots and is
//!   recovered after a crash (v2's backup was only used by the process that
//!   made it);
//! - a failed cleanup after a successful change is a warning, never a
//!   failure of the change (H-8.1#14);
//! - existing units are adopted only together with their spec in
//!   `FRP_ROOT/services` (v2 accepted every unit once the directory
//!   existed, H-8.1#9);
//! - a rolled-back fresh install leaves no FRP directory behind, so the
//!   next install is not refused as "not managed";
//! - a cancellation keeps exit code 130 through the rollback message.

use super::journal::{self, Before, Journal, Phase, SERVICES};
use super::model::{self, MANAGED_FILE};
use super::runtime::Runtime;
use crate::error::{Error, Result};
use crate::host::cron::{self, Scope};
use crate::host::firewall;
use crate::host::init::InitSystem;
use crate::host::service::{script_file, unit_file, ServiceDef};
use crate::sys::fs::remove_tree_if_exists;
use crate::sys::lock::FileLock;
use crate::sys::signal::{self, BlockSignals};
use crate::ui::out;
use std::path::PathBuf;

/// Suffix of an error whose change was rolled back (v2 wording).
pub const ROLLED_BACK: &str = "；已恢复旧 FRP 配置与服务状态";

/// An open FRP transaction; end it with [`Txn::commit`] or [`Txn::abort`].
pub struct Txn<'r, 'a> {
    rt: &'r Runtime<'a>,
    lock: &'r FileLock,
    journal: Journal,
}

/// Refuse directories and units Onebox does not manage (H §5.3 steps
/// 1–2): an FRP tree without `.managed`, or a unit file without the spec
/// v2/v3 wrote next to it.
pub fn refuse_adoption(rt: &Runtime) -> Result<()> {
    let paths = rt.paths();
    for dir in [&paths.frp_root, &paths.frp_bin, &paths.frp_web] {
        let managed = std::fs::symlink_metadata(dir.join(MANAGED_FILE)).is_ok_and(|m| m.is_file());
        ensure!(
            !dir.exists() || managed,
            "拒绝接管非本程序管理的目录: {}",
            dir.display()
        );
    }
    for name in SERVICES {
        let spec = ServiceDef::skeleton(paths, name).spec_path();
        for unit in [unit_file(paths, name), script_file(paths, name)] {
            let foreign = std::fs::symlink_metadata(&unit).is_ok() && !spec.is_file();
            ensure!(!foreign, "拒绝接管现有服务: {}", unit.display());
        }
    }
    Ok(())
}

/// The services' state before a change.
fn before(rt: &Runtime) -> Result<Before> {
    let services = rt.services();
    let mut state = Before {
        cron: cron::snapshot(rt.ctx, Scope::Frp)?,
        ..Before::default()
    };
    for name in SERVICES {
        if services.running(name) {
            state.active.push(name.to_owned());
        }
        if services.enabled(name).unwrap_or(false) {
            state.enabled.push(name.to_owned());
        }
    }
    Ok(state)
}

impl<'r, 'a> Txn<'r, 'a> {
    /// Snapshot `targets` and open the journal (`reason` for messages).
    pub fn begin(
        rt: &'r Runtime<'a>,
        lock: &'r FileLock,
        reason: &str,
        targets: &[PathBuf],
    ) -> Result<Txn<'r, 'a>> {
        refuse_adoption(rt)?;
        let journal = journal::create(rt.paths(), reason, before(rt)?, targets)?;
        Ok(Txn { rt, lock, journal })
    }

    /// Enter `phase`, honouring a pending cancellation first.
    pub fn phase(&mut self, phase: Phase) -> Result<()> {
        signal::check()?;
        self.journal.set_phase(self.rt.paths(), phase)
    }

    /// Finish successfully. A failed cleanup only warns once the journal
    /// says `committed`; without that record a later recovery would roll
    /// the change back, so then it is an error.
    pub fn commit(mut self) -> Result<()> {
        let paths = self.rt.paths();
        let recorded = self.journal.set_phase(paths, Phase::Committed);
        match (recorded, journal::remove(paths)) {
            (_, Ok(())) => Ok(()),
            (Ok(()), Err(e)) => {
                out::warn(format!(
                    "FRP 配置已提交，但事务清理失败: {e}；请执行 onebox recover 清理"
                ));
                Ok(())
            }
            (Err(e), Err(_)) => {
                Err(e.wrap("FRP 配置已提交，但事务清理失败；请执行 onebox recover"))
            }
        }
    }

    /// Roll back after `error` and return the error to report.
    pub fn abort(mut self, error: Error) -> Error {
        let _blocked = BlockSignals::new();
        match rollback(self.rt, self.lock, &mut self.journal) {
            Ok(()) => decorate(error, ROLLED_BACK),
            Err(recovery) => decorate(
                error,
                &format!(
                    "；恢复未完成: {recovery}。事务日志保留于 {}，请执行 onebox recover",
                    journal::dir(self.rt.paths()).display()
                ),
            ),
        }
    }
}

/// `{error}{suffix}`; a cancellation stays one (exit 130).
pub fn decorate(error: Error, suffix: &str) -> Error {
    if error.is_cancelled() {
        Error::Cancelled.wrap(format!("{}{suffix}", error.report_text()))
    } else {
        Error::msg(format!("{error}{suffix}"))
    }
}

/// Undo the change `journal` records (module docs for the order).
pub fn rollback(rt: &Runtime, lock: &FileLock, journal: &mut Journal) -> Result<()> {
    let paths = rt.paths();
    journal.validate(paths)?;
    let services = rt.services();
    journal.set_phase(paths, Phase::RollbackStop)?;
    for name in SERVICES.iter().rev() {
        services.stop(name)?;
    }
    firewall::clear_owner(rt.ctx, "frp")?;
    for name in SERVICES {
        let _ = services.disable(name);
    }
    journal.set_phase(paths, Phase::RollbackFiles)?;
    crate::apply::snapshot::restore(
        &journal.snapshot,
        &journal::files_dir(paths),
        &journal::allowlist(paths),
    )?;
    for entry in journal.snapshot.entries.iter().filter(|e| !e.present) {
        remove_tree_if_exists(&entry.target)?;
    }
    services.daemon_reload()?;
    journal.set_phase(paths, Phase::RollbackServices)?;
    cron::restore(rt.ctx, &journal.cron, Scope::Frp)?;
    restore_services(rt, lock, journal)?;
    journal.set_phase(paths, Phase::RolledBack)?;
    journal::remove(paths)
}

/// Firewall and services of the restored installation (nothing when the
/// change was a first install).
fn restore_services(rt: &Runtime, lock: &FileLock, journal: &Journal) -> Result<()> {
    let paths = rt.paths();
    if !model::installed(paths) {
        return Ok(());
    }
    match model::load(paths) {
        Ok(Some(state)) => {
            firewall::reconcile_owner(rt.ctx, "frp", &state.firewall_ports())?;
        }
        Ok(None) => {}
        Err(e) => out::warn(format!("恢复的 FRP 状态无法读取，未恢复防火墙规则: {e}")),
    }
    let services = rt.services();
    for name in SERVICES {
        let name_owned = name.to_owned();
        // Without an init system the restored crontab already holds the
        // autostart lines exactly as they were.
        if rt.init != InitSystem::None && journal.enabled.contains(&name_owned) {
            services.enable(name)?;
        }
        if journal.active.contains(&name_owned) {
            rt.start(lock, name)?;
        }
    }
    Ok(())
}

/// Finish an interrupted transaction: a committed or rolled-back journal
/// is removed, any other one rolled back. Returns whether a rollback ran.
pub fn recover_locked(rt: &Runtime, lock: &FileLock) -> Result<bool> {
    let paths = rt.paths();
    let Some(mut journal) = journal::load(paths)? else {
        return Ok(false);
    };
    if journal.phase.is_finished() {
        journal::remove(paths)?;
        return Ok(false);
    }
    let _blocked = BlockSignals::new();
    out::info(format!("回滚未完成的 FRP 事务（{}）…", journal.reason));
    rollback(rt, lock, &mut journal).map_err(|e| {
        e.wrap(format!(
            "FRP 事务恢复未完成；事务日志保留于 {}",
            journal::dir(paths).display()
        ))
    })?;
    out::ok("已恢复未完成的 FRP 事务");
    Ok(true)
}

#[cfg(test)]
mod tests;
