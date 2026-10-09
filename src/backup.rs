//! User backups (schema 2, compatible with v2 in both directions of the
//! format) and their restore through the apply engine.
//!
//! - [`archive`]: the format, validation and the in-transaction placement of
//!   a backup's files (a leaf the apply engine calls);
//! - [`store`]: create (under the node lock), list and rotate (keep 5);
//! - [`restore`]: restore through `apply` with `Intents.restore_backup`;
//! - [`cli`]: `backup [标签]`, `backups`, `restore [ID|latest]`, `recover`.
//!
//! Nothing here prompts (G12); the restore confirmation is the CLI's.
//!
//! Changes from v2 (details in each module): ordering, `latest` and
//! rotation by creation time instead of by name (E-8.1#1); v2 backups are
//! migrated with their own subscription devices (G22); v1 backups get a
//! clear message; directories that are not backups are never rotated away;
//! explicit per-component restore policy; one lock for a whole restore.

pub mod archive;
pub mod cli;
pub mod restore;
pub mod store;

pub use restore::{preview, restore, restore_locked, restore_with};
pub use store::{create_locked, list, BackupInfo, BackupKind};

use crate::ctx::Ctx;
use crate::error::Result;

/// `onebox backup [LABEL]`: take the node lock and back up; returns the id.
pub fn create(ctx: &Ctx, label: &str) -> Result<String> {
    let lock = crate::apply::node_lock(ctx)?;
    create_locked(ctx, &lock, label)
}

#[cfg(test)]
mod tests;
