//! The FRP transaction journal (G24), so an FRP change interrupted by a
//! crash, a reboot or a kill is rolled back by the next FRP command or by
//! `onebox recover`.
//!
//! Layout, next to the FRP lock (`/etc/.onebox-frp.lock`):
//! ```text
//! /etc/.onebox-frp-journal/      0700, published by renaming a staged directory
//!   journal.json                 0600: phase, reason, services and FRP crontab lines before the change
//!   files/                       snapshot of the FRP trees and unit files (apply::snapshot)
//! ```
//! The journal lives outside the trees it snapshots, so uninstalling or
//! restoring `FRP_ROOT` never touches it.
//!
//! Changes from v2: v2 kept a backup directory with a random name only
//! for the lifetime of the process (a crash left it behind and nothing
//! used it); the snapshot's targets are recorded and validated against the
//! FRP paths before anything is restored.

use crate::apply::snapshot::{self, Allowlist, Snapshot, TargetRule};
use crate::error::{Context, Error, Result};
use crate::host::cron::{self, CronSnapshot, Scope};
use crate::host::service::{script_file, unit_file, FRPS, FRP_WEB};
use crate::paths::Paths;
use crate::sys::fs::{
    atomic_write, ensure_dir, fsync_dir, read_bounded, remove_tree_if_exists, sweep_stale,
};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::time::Duration;

pub const VERSION: u8 = 1;
pub const DIR_NAME: &str = ".onebox-frp-journal";
/// Staging directories (`{DIR_NAME}-{hex}`) left by a crash are removed.
const STAGE_PREFIX: &str = ".onebox-frp-journal-";
pub const JOURNAL_FILE: &str = "journal.json";
pub const FILES_DIR: &str = "files";
const MAX_BYTES: u64 = 4 * 1024 * 1024;
/// Refusal of operations that must wait for the recovery.
pub const PENDING: &str = "FRP 存在未完成事务，请先执行 onebox recover";
/// A finished journal whose removal failed: harmless, only cleanup left.
pub const CLEANUP: &str = "待清理；执行 onebox recover";
/// The FRP services, in start order.
pub const SERVICES: [&str; 2] = [FRPS, FRP_WEB];

/// Where an FRP transaction is.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub enum Phase {
    Prepared,
    StopServices,
    WriteFiles,
    ConfigureServices,
    ApplyNetwork,
    ApplyWebsite,
    StartServices,
    HealthCheck,
    RenewCertificates,
    Teardown,
    /// The FRP crontab lines are rewritten.
    WriteCron,
    /// Everything is deployed and verified; only the commit record and the
    /// cleanup are left, so recovery keeps the change (see
    /// [`Phase::is_finished`]).
    Finalize,
    Committed,
    RollbackStop,
    RollbackFiles,
    RollbackServices,
    RolledBack,
    /// A phase a newer version wrote: unfinished, rolled back.
    Other(String),
}

impl Phase {
    const KNOWN: [Phase; 17] = [
        Phase::Prepared,
        Phase::StopServices,
        Phase::WriteFiles,
        Phase::ConfigureServices,
        Phase::ApplyNetwork,
        Phase::ApplyWebsite,
        Phase::StartServices,
        Phase::HealthCheck,
        Phase::RenewCertificates,
        Phase::Teardown,
        Phase::WriteCron,
        Phase::Finalize,
        Phase::Committed,
        Phase::RollbackStop,
        Phase::RollbackFiles,
        Phase::RollbackServices,
        Phase::RolledBack,
    ];

    pub fn id(&self) -> &str {
        match self {
            Phase::Prepared => "prepared",
            Phase::StopServices => "stop-services",
            Phase::WriteFiles => "write-files",
            Phase::ConfigureServices => "configure-services",
            Phase::ApplyNetwork => "apply-network",
            Phase::ApplyWebsite => "apply-website",
            Phase::StartServices => "start-services",
            Phase::HealthCheck => "health-check",
            Phase::RenewCertificates => "renew-certificates",
            Phase::Teardown => "teardown",
            Phase::WriteCron => "write-cron",
            Phase::Finalize => "finalize",
            Phase::Committed => "committed",
            Phase::RollbackStop => "rollback-stop",
            Phase::RollbackFiles => "rollback-files",
            Phase::RollbackServices => "rollback-services",
            Phase::RolledBack => "rolled-back",
            Phase::Other(name) => name,
        }
    }

    /// Only cleanup is left: nothing to roll back. `finalize` counts: a
    /// transaction records it only after its last step succeeded
    /// ([`crate::frp::txn::Txn::run`]), so a commit record that could not
    /// be written (full disk) never makes recovery undo a deployed change.
    pub fn is_finished(&self) -> bool {
        matches!(self, Phase::Finalize | Phase::Committed | Phase::RolledBack)
    }
}

impl TryFrom<String> for Phase {
    type Error = Error;
    fn try_from(name: String) -> Result<Phase> {
        if let Some(known) = Phase::KNOWN.iter().find(|p| p.id() == name) {
            return Ok(known.clone());
        }
        let kebab = !name.is_empty()
            && name.len() <= 64
            && name
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
        ensure!(kebab, "FRP 事务阶段无效");
        Ok(Phase::Other(name))
    }
}

impl From<Phase> for String {
    fn from(phase: Phase) -> String {
        phase.id().to_owned()
    }
}

/// `journal.json`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Journal {
    pub version: u8,
    /// What the change was (`安装`, `续期`, `卸载`, …).
    pub reason: String,
    pub phase: Phase,
    /// FRP services running before the change.
    pub active: Vec<String>,
    /// FRP services enabled at boot before the change.
    pub enabled: Vec<String>,
    /// The FRP crontab lines before the change, with their positions.
    pub cron: CronSnapshot,
    pub snapshot: Snapshot,
}

/// `{parent of FRP_ROOT}/.onebox-frp-journal`.
pub fn dir(paths: &Paths) -> PathBuf {
    paths.frp_lock().with_file_name(DIR_NAME)
}

pub fn files_dir(paths: &Paths) -> PathBuf {
    dir(paths).join(FILES_DIR)
}

/// The FRP unit files and init scripts.
fn unit_targets(paths: &Paths) -> Vec<PathBuf> {
    SERVICES
        .iter()
        .flat_map(|name| [unit_file(paths, name), script_file(paths, name)])
        .collect()
}

/// What an apply or uninstall snapshots: the three FRP trees and the
/// unit files. Logs, runtime records and the manager executable are not
/// part of FRP's transaction (the node owns the executable).
pub fn targets(paths: &Paths) -> Vec<PathBuf> {
    let mut targets = vec![
        paths.frp_root.clone(),
        paths.frp_bin.clone(),
        paths.frp_web.clone(),
    ];
    targets.extend(unit_targets(paths));
    targets
}

/// What a journal may restore: any of [`targets`] (renewals snapshot fewer),
/// never a system directory.
pub fn allowlist(paths: &Paths) -> Allowlist {
    let roots = [&paths.frp_root, &paths.frp_bin, &paths.frp_web];
    let list = targets(paths)
        .into_iter()
        .fold(Allowlist::default(), |list, t| {
            list.with_rule(TargetRule::Exact(t))
        });
    roots
        .into_iter()
        .fold(list, |list, root| list.guard_root(root.clone()))
        .keep_apart(
            paths.frp_root.clone(),
            paths.frp_web.clone(),
            "FRP 数据目录不能相同或互相包含",
        )
        .keep_apart(
            paths.frp_root.clone(),
            paths.frp_bin.clone(),
            "FRP 数据目录不能相同或互相包含",
        )
        .keep_apart(
            paths.frp_bin.clone(),
            paths.frp_web.clone(),
            "FRP 数据目录不能相同或互相包含",
        )
}

fn present(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(false),
        Err(e) => Err(Error::io(path, e)),
    }
}

/// Whether a journal directory exists (it may be corrupt).
pub fn exists(paths: &Paths) -> bool {
    present(&dir(paths)).unwrap_or(true)
}

/// What a leftover journal means for the user (`None` without one): the
/// [`PENDING`] refusal, or the cleanup notice for a finished journal.
pub fn notice(paths: &Paths) -> Option<String> {
    if !exists(paths) {
        return None;
    }
    Some(match load(paths) {
        Ok(None) => return None,
        Ok(Some(j)) if j.phase.is_finished() => format!("FRP 事务日志{CLEANUP}"),
        _ => PENDING.to_owned(),
    })
}

/// The pending journal (`None` without one). A journal directory without a
/// readable, valid journal is an error.
pub fn load(paths: &Paths) -> Result<Option<Journal>> {
    let dir = dir(paths);
    match fs::symlink_metadata(&dir) {
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(Error::io(&dir, e)),
        Ok(m) if m.file_type().is_symlink() || !m.is_dir() => {
            bail!("FRP 事务目录无效: {}", dir.display())
        }
        Ok(_) => {}
    }
    let bytes = read_bounded(&dir.join(JOURNAL_FILE), MAX_BYTES)
        .with_context(|| format!("FRP 事务日志不完整: {}", dir.display()))?;
    let journal: Journal = serde_json::from_slice(&bytes).context("FRP 事务日志无效")?;
    ensure!(journal.version == VERSION, "不支持的 FRP 事务日志版本");
    journal.check_services()?;
    Ok(Some(journal))
}

impl Journal {
    /// Everything a rollback relies on, before it changes anything: known
    /// services, FRP-owned crontab lines of a known shape and an intact
    /// snapshot of FRP paths only.
    pub fn validate(&self, paths: &Paths) -> Result<()> {
        self.check_services()?;
        cron::check_snapshot(paths, &self.cron, Scope::Frp)?;
        snapshot::validate(&self.snapshot, &files_dir(paths), &allowlist(paths))
    }

    fn check_services(&self) -> Result<()> {
        let known = self
            .active
            .iter()
            .chain(&self.enabled)
            .all(|s| SERVICES.contains(&s.as_str()));
        ensure!(known, "FRP 事务日志含未知服务");
        Ok(())
    }

    /// Durably move to `phase` (in memory only after it was written).
    pub fn set_phase(&mut self, paths: &Paths, phase: Phase) -> Result<()> {
        let mut next = self.clone();
        next.phase = phase;
        write_in(&dir(paths), &next)?;
        *self = next;
        Ok(())
    }
}

fn write_in(dir: &Path, journal: &Journal) -> Result<()> {
    atomic_write(
        &dir.join(JOURNAL_FILE),
        &serde_json::to_vec_pretty(journal)?,
        0o600,
    )
}

/// What a new journal records besides its snapshot.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Before {
    pub active: Vec<String>,
    pub enabled: Vec<String>,
    pub cron: CronSnapshot,
}

/// Snapshot `targets` and publish a new journal in phase `prepared`
/// (staged, then renamed into place). Refused while a journal exists.
pub fn create(paths: &Paths, reason: &str, before: Before, targets: &[PathBuf]) -> Result<Journal> {
    let final_dir = dir(paths);
    ensure!(!present(&final_dir)?, "{PENDING}");
    let parent = final_dir
        .parent()
        .ok_or_else(|| Error::msg("FRP 事务目录无父目录"))?
        .to_path_buf();
    ensure_dir_exists(&parent)?;
    // Staging leftovers of a crash (the caller holds the FRP lock).
    sweep_stale(&parent, STAGE_PREFIX, Duration::ZERO)?;
    let stage = parent.join(format!("{STAGE_PREFIX}{}", crate::sys::rand::hex(8)?));
    ensure_dir(&stage, 0o700)?;
    let result = (|| -> Result<Journal> {
        let snapshot = snapshot::take(targets, &stage.join(FILES_DIR), &allowlist(paths))?;
        let journal = Journal {
            version: VERSION,
            reason: reason.to_owned(),
            phase: Phase::Prepared,
            active: before.active,
            enabled: before.enabled,
            cron: before.cron,
            snapshot,
        };
        write_in(&stage, &journal)?;
        fs::rename(&stage, &final_dir).map_err(|e| Error::io(&final_dir, e))?;
        fsync_dir(&parent).map_err(|e| Error::io(&parent, e))?;
        Ok(journal)
    })();
    if result.is_err() {
        let _ = remove_tree_if_exists(&stage);
    }
    result
}

/// The parent of the journal (the lock's directory) must exist.
fn ensure_dir_exists(parent: &Path) -> Result<()> {
    ensure!(parent.is_dir(), "目录不存在: {}", parent.display());
    Ok(())
}

/// Remove the journal directory (after commit or rollback).
pub fn remove(paths: &Paths) -> Result<()> {
    let dir = dir(paths);
    remove_tree_if_exists(&dir)?;
    if let Some(parent) = dir.parent() {
        fsync_dir(parent).map_err(|e| Error::io(parent, e))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests;
