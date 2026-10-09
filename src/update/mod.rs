//! Self-update of the manager (journal compatible with v2) and proxy core
//! updates (spec G §1.2, §2.8–2.11, §5.2–5.4).
//!
//! - [`channel`]: the update channel (`stable` / `testing`) and the saved
//!   preference `ROOT/update-channel`;
//! - [`release`]: the manager's GitHub release for a channel, its asset for
//!   this CPU and the version report printed before anything happens;
//! - [`selfupdate`]: `update-script` / `update-check` — verified download,
//!   the journaled replacement of `EXE` (`apply::program_journal`), the
//!   child `regen` under the inherited node lock, and recovery on failure;
//! - [`cores`]: `onebox update [CORE] [VERSION] [--force]` — only the cores
//!   the configuration uses, pin and downgrade policy, verified staging,
//!   then one apply transaction that swaps the binaries;
//! - [`cli`]: the four command specs and their handlers.
//!
//! Locks (G §5.4): the update lock `RUN/update.lock`, then the node lock
//! `ROOT/.apply.lock`, then `apply::recover_locked` before anything else.
//!
//! Every external effect goes through an [`Updater`]: the context, the
//! environment lookup (`GH_PROXY`, offline core overrides) and the apply
//! [`Engine`]. [`self_update`] and [`update_cores`] wire the production
//! pieces; tests inject fakes.

pub mod channel;
pub mod cli;
pub mod cores;
pub mod release;
pub mod selfupdate;

#[cfg(test)]
mod testing;

pub use channel::Channel;
pub use cli::COMMANDS;
pub use cores::CoreSelection;

use crate::apply::program_journal::ProgramPhase;
use crate::apply::{self, ApplyRequest};
use crate::ctx::Ctx;
use crate::error::Result;
use crate::host::os::{process_env, require_root, EnvLookup};
use crate::sys::lock::FileLock;

/// Contention message of the update lock (v2 wording).
pub const UPDATE_BUSY: &str = "另一个更新正在进行";

/// The apply-engine entry points the updaters need. Production uses
/// [`ApplyEngine`]; tests substitute a recording fake.
pub trait Engine {
    /// Finish or roll back leftover node and self-update journals.
    fn recover(&self, ctx: &Ctx, lock: &FileLock) -> Result<()>;
    /// Apply `req` while the caller holds the node lock.
    fn apply(&self, ctx: &Ctx, lock: &FileLock, req: ApplyRequest) -> Result<()>;
}

/// [`Engine`] backed by `apply::recover_locked` / `apply::apply_locked`.
#[derive(Clone, Copy, Debug, Default)]
pub struct ApplyEngine;

impl Engine for ApplyEngine {
    fn recover(&self, ctx: &Ctx, lock: &FileLock) -> Result<()> {
        apply::recover_locked(ctx, lock)
    }

    fn apply(&self, ctx: &Ctx, lock: &FileLock, req: ApplyRequest) -> Result<()> {
        apply::apply_locked(ctx, lock, req)
    }
}

/// Everything an update touches besides the filesystem layout in `ctx`.
#[derive(Clone, Copy)]
pub struct Updater<'a> {
    pub ctx: &'a Ctx,
    /// `GH_PROXY`, `GH_TOKEN`, `ONEBOX_SINGBOX_BIN` / `ONEBOX_XRAY_BIN`.
    pub env: EnvLookup<'a>,
    pub engine: &'a dyn Engine,
    /// Called after each self-update journal phase became durable. A no-op
    /// in production; tests use it to observe the phases or to simulate a
    /// crash right after one.
    pub on_phase: &'a dyn Fn(ProgramPhase),
}

fn ignore_phase(_: ProgramPhase) {}

impl<'a> Updater<'a> {
    /// The production wiring: process environment, the real apply engine.
    pub fn system(ctx: &'a Ctx) -> Updater<'a> {
        Updater {
            ctx,
            env: &process_env,
            engine: &ApplyEngine,
            on_phase: &ignore_phase,
        }
    }
}

/// `update-script` (`check_only = false`, root) and `update-check`
/// (`check_only = true`, no root). `channel` overrides the saved channel
/// for this run only. A completed replacement returns
/// `Err(Error::Exit { code: 0, .. })` so that every caller — the interactive
/// menu included — ends the process instead of continuing in the replaced
/// image; identical content returns `Ok(())`.
pub fn self_update(ctx: &Ctx, channel: Option<Channel>, check_only: bool) -> Result<()> {
    if !check_only {
        require_root()?;
    }
    Updater::system(ctx).self_update(channel, check_only)
}

/// `onebox update [CORE] [VERSION] [--force]` (root): update the selected
/// cores the configuration uses. `version` is an exact version or
/// `latest`; `None` means the recommended version (bare `update` / `all`
/// keeps pinned versions).
pub fn update_cores(
    ctx: &Ctx,
    which: CoreSelection,
    version: Option<&str>,
    force: bool,
) -> Result<()> {
    require_root()?;
    Updater::system(ctx).update_cores(which, version, force)
}
