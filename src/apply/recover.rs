//! Recovery of interrupted operations under the node lock: first the node
//! journal (finish a committed or rolled-back one, roll back anything
//! else), then the self-update journal (G3). Every apply, `recover`, boot
//! and backup runs this first.
//!
//! Both journal versions are recovered: version 2 (v3) validates its
//! snapshot against the owned-root patterns of its recorded targets,
//! version 1 (written by v2.x) against v2's fixed allowlist, and its old
//! state is migrated with `state::v2` when its rules are re-applied.
//!
//! Changes from v2: the outcome is reported (`[完成] …`), and the
//! self-update journal is not consulted at all under a lock inherited from
//! the updating parent (the parent owns it).

use super::journal::{self, Journal};
use super::{program_journal, rollback, transaction};
use crate::ctx::Ctx;
use crate::error::{Error, Result};
use crate::sys::lock::FileLock;
use crate::ui::out;

/// What [`recover_journal`] found.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Recovery {
    /// No node journal.
    Nothing,
    /// A committed or rolled-back journal was cleaned up.
    Finished,
    /// An unfinished change was rolled back.
    RolledBack,
}

/// Recover the node journal, then the self-update journal (which refuses
/// to run while a node journal is pending, so the order matters).
pub fn recover_all(ctx: &Ctx, lock: &FileLock) -> Result<Recovery> {
    lock.verify(&ctx.paths.lock())?;
    let outcome = recover_journal(ctx, lock)?;
    program_journal::recover_program_locked(ctx, lock)?;
    Ok(outcome)
}

/// The node journal alone (the caller verified the lock).
pub fn recover_journal(ctx: &Ctx, lock: &FileLock) -> Result<Recovery> {
    let paths = &ctx.paths;
    let Some(mut journal) = journal::load(paths)? else {
        return Ok(Recovery::Nothing);
    };
    if journal.phase().is_finished() {
        transaction::finish(paths)?;
        return Ok(Recovery::Finished);
    }
    let what = describe(&journal);
    rollback::rollback(ctx, lock, &mut journal).map_err(|e| {
        let message = format!(
            "未完成事务恢复失败；日志保留于 {}: {e}",
            journal::dir(paths).display()
        );
        keep_cancellation(e, message)
    })?;
    out::ok(format!("已回滚未完成的配置事务{what}"));
    Ok(Recovery::RolledBack)
}

/// `（{reason}，中断于 {phase}）` for the completion notice.
fn describe(journal: &Journal) -> String {
    let phase = journal.phase().id().to_owned();
    match journal.reason() {
        Some(reason) => format!("（{reason}，中断于 {phase}）"),
        None => format!("（中断于 {phase}）"),
    }
}

/// `message` as the error, keeping exit code 130 when `cause` was a
/// cancellation.
pub fn keep_cancellation(cause: Error, message: String) -> Error {
    if cause.is_cancelled() {
        Error::Cancelled.wrap(message)
    } else {
        Error::Msg(message)
    }
}
