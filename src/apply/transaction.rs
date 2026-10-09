//! Creating and removing the node journal directory, and the runtime facts
//! a journal records (which services run / start at boot, the node's
//! crontab lines).
//!
//! A journal is published atomically: everything (the snapshot of every
//! owned path and `journal.json` in phase `prepared`) is written into a
//! private staging directory `ROOT/.transaction-new-<24 hex>`, which is
//! fsynced and renamed to `ROOT/.transaction`. A crash leaves either no
//! journal or a complete one; staging leftovers are swept under the lock.
//!
//! Changes from v2: stale staging directories are removed before a new
//! journal is begun (E-8.1#16); the journal is version 2 with the reason,
//! the typed old configuration and positioned cron lines.

use super::journal::{self, Journal, LEGACY_NETWORK_SERVICES, SERVICES};
use super::snapshot::{self, node_allowlist, node_targets};
use crate::ctx::Ctx;
use crate::domain::NodeConfig;
use crate::error::{Error, Result};
use crate::host::cron::{self, CronSnapshot, Scope};
use crate::host::service::Services;
use crate::paths::Paths;
use crate::sys::fs::{ensure_dir, fsync_dir, remove_tree_if_exists, sweep_stale};
use std::fs;
use std::io::ErrorKind;
use std::time::Duration;

/// Name prefix of journal staging directories in `ROOT`.
pub const STAGE_PREFIX: &str = ".transaction-new-";
pub const PENDING_JOURNAL: &str = "检测到未完成事务，请先恢复";

/// Services and crontab lines as they were before a change.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RuntimeState {
    pub active: Vec<String>,
    pub enabled: Vec<String>,
    pub cron: CronSnapshot,
}

/// Read which node services (and v1 network units) run and start at boot,
/// and the node's crontab lines (spec B §4.5). Changes nothing.
pub fn runtime_state(ctx: &Ctx, services: &Services) -> Result<RuntimeState> {
    let cron = cron::snapshot(ctx, Scope::Node)?;
    let mut state = RuntimeState {
        cron,
        ..RuntimeState::default()
    };
    for name in SERVICES.iter().chain(LEGACY_NETWORK_SERVICES.iter()) {
        if services.running(name) {
            state.active.push((*name).to_owned());
        }
        if services.enabled(name)? {
            state.enabled.push((*name).to_owned());
        }
    }
    Ok(state)
}

/// Remove journal staging directories left by a crash. The caller holds the
/// node lock, so every one of them is stale.
pub fn sweep_stages(paths: &Paths) -> Result<()> {
    sweep_stale(&paths.root, STAGE_PREFIX, Duration::ZERO).map(drop)
}

/// Snapshot every owned path and publish a v3 journal in phase `prepared`.
/// A pending journal is refused; nothing is left behind on failure.
pub fn begin(
    ctx: &Ctx,
    reason: &str,
    old: Option<NodeConfig>,
    runtime: RuntimeState,
) -> Result<Journal> {
    let paths = &ctx.paths;
    let dir = journal::dir(paths);
    match fs::symlink_metadata(&dir) {
        Err(e) if e.kind() == ErrorKind::NotFound => {}
        Ok(_) => bail!("{PENDING_JOURNAL}"),
        Err(e) => return Err(Error::io(&dir, e)),
    }
    ensure_dir(&paths.root, 0o700)?;
    sweep_stages(paths)?;
    let stage = paths
        .root
        .join(format!("{STAGE_PREFIX}{}", crate::sys::rand::hex(12)?));
    let result = stage_journal(ctx, &stage, reason, old, runtime);
    match result {
        Ok(journal) => Ok(journal),
        Err(e) => {
            let _ = remove_tree_if_exists(&stage);
            Err(e)
        }
    }
}

fn stage_journal(
    ctx: &Ctx,
    stage: &std::path::Path,
    reason: &str,
    old: Option<NodeConfig>,
    runtime: RuntimeState,
) -> Result<Journal> {
    let paths = &ctx.paths;
    ensure_dir(stage, 0o700)?;
    let files = stage.join(journal::FILES_DIR);
    let snapshot = snapshot::take(&node_targets(paths), &files, &node_allowlist(paths))?;
    let journal = Journal::new(
        reason,
        old,
        runtime.active,
        runtime.enabled,
        runtime.cron,
        snapshot,
    );
    journal::write_in(stage, &journal)?;
    fsync_dir(stage).map_err(|e| Error::io(stage, e))?;
    let dir = journal::dir(paths);
    fs::rename(stage, &dir).map_err(|e| Error::io(&dir, e))?;
    fsync_dir(&paths.root).map_err(|e| Error::io(&paths.root, e))?;
    Ok(journal)
}

/// Remove the journal directory (after `committed` or `rolled-back`) and
/// make the removal durable.
pub fn finish(paths: &Paths) -> Result<()> {
    remove_tree_if_exists(&journal::dir(paths))?;
    fsync_dir(&paths.root).map_err(|e| Error::io(&paths.root, e))
}
