//! Restoring a backup through the apply engine (spec E §5.7, G22).
//!
//! Under one node lock: recover leftovers, resolve and validate the backup
//! (its configuration: v3 as stored, v2 migrated with the backup's own
//! subscription settings), take a `before-restore` safety backup when a
//! node is installed (rotation spares the backup being restored), then
//! apply the backup's configuration with `Intents.restore_backup` so its
//! files are placed inside the transaction (prepare-state) and everything
//! is rolled back together on failure. Never prompts: the CLI confirms
//! first ([`preview`]).
//!
//! Changes from v2: one lock for the whole restore (v2 validated without
//! it and took it three times); `latest` is the newest restorable backup by
//! creation time; the resolved id (not `latest`) is what the transaction
//! re-validates, so the safety backup cannot be mistaken for it; a v2
//! backup's subscription devices are migrated with it; a `state.json` that
//! exists but cannot be loaded no longer refuses the restore (the safety
//! copy keeps it as it is, the engine applies over it).

use super::archive::{self, Validated};
use super::store::{self, BEFORE_RESTORE};
use crate::apply::{self, ApplyRequest, Features, SystemFeatures};
use crate::ctx::Ctx;
use crate::error::Result;
use crate::paths::Paths;
use crate::state::StateStore;
use crate::sys::lock::FileLock;
use crate::ui::out;

/// Progress label of a restore.
pub const REASON: &str = "恢复备份";
pub const RESTORED: &str = "备份已恢复";

/// Resolve `id` (`latest` = newest restorable backup) and validate it
/// without changing anything; returns the concrete id.
pub fn preview(paths: &Paths, id: &str) -> Result<(String, Validated)> {
    let id = resolve(paths, id)?;
    let dir = archive::backup_dir(paths, &id)?;
    let validated = archive::validate(paths, &id, &dir)?;
    Ok((id, validated))
}

/// `latest` → the newest restorable id; anything else as given.
pub fn resolve(paths: &Paths, id: &str) -> Result<String> {
    if id == "latest" {
        store::latest(paths)
    } else {
        Ok(id.to_owned())
    }
}

/// Restore backup `id` (or `latest`). Prints [`RESTORED`] on stdout.
pub fn restore(ctx: &Ctx, id: &str) -> Result<()> {
    let lock = apply::node_lock(ctx)?;
    restore_locked(ctx, &lock, id)
}

/// [`restore`] under a lock the caller holds.
pub fn restore_locked(ctx: &Ctx, lock: &FileLock, id: &str) -> Result<()> {
    restore_with(ctx, lock, id, &SystemFeatures)
}

/// [`restore_locked`] with explicit apply feature hooks.
pub fn restore_with(ctx: &Ctx, lock: &FileLock, id: &str, features: &dyn Features) -> Result<()> {
    apply::recover_locked(ctx, lock)?;
    let (id, validated) = preview(&ctx.paths, id)?;
    for warning in &validated.warnings {
        out::warn(warning);
    }
    if StateStore::installed(ctx) {
        let safety = store::create_kept(ctx, lock, BEFORE_RESTORE, Some(&id))?;
        out::info(format!("当前配置已备份为 {safety}"));
    }
    let mut req = ApplyRequest::new(validated.config, StateStore::current_hash(ctx)?, REASON);
    req.intents.restore_backup = Some(id);
    req.intents.migrated_devices = validated.devices;
    apply::engine::apply_with(ctx, lock, req, features)?;
    out::data(RESTORED)
}
