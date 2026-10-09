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
//! A core update releases the node lock while it looks releases up, asks
//! and downloads (see [`cores`]).
//!
//! Every external effect goes through an [`Updater`]: the context, the
//! environment lookup (`GH_PROXY`, offline core overrides), the apply
//! [`Engine`] and the warning sink. [`self_update`] and [`update_cores`]
//! wire the production pieces; tests inject fakes.
//!
//! For other work packages: [`sweep_orphans`] removes work directories of
//! killed self-updates (they may hold a copy of the node's keys); callers
//! holding the node lock after `apply::recover_locked` — the CLI's
//! `recover` / `net-apply` handlers — should call it.

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
use crate::error::{Error, Result};
use crate::host::os::{process_env, require_root, EnvLookup};
use crate::paths::Paths;
use crate::sys::lock::FileLock;
use crate::ui::out;

/// Contention message of the update lock (v2 wording).
pub const UPDATE_BUSY: &str = "另一个更新正在进行";

/// The apply-engine entry points the updaters need. Production uses
/// [`ApplyEngine`]; tests substitute a recording fake.
pub trait Engine {
    /// Finish or roll back leftover node and self-update journals.
    ///
    /// Contract: an `Error::Exit` (notably code 75, "recovered, but this
    /// process is the replaced manager") is returned as is, never inside
    /// `Error::Context` — `Error::wrap` / `Context::context` already keep
    /// it intact, and [`ApplyEngine`] unwraps a hand-built wrapper. The
    /// updaters still look through context ([`exit_within`]).
    fn recover(&self, ctx: &Ctx, lock: &FileLock) -> Result<()>;
    /// Apply `req` while the caller holds the node lock.
    fn apply(&self, ctx: &Ctx, lock: &FileLock, req: ApplyRequest) -> Result<()>;
}

/// [`Engine`] backed by `apply::recover_locked` / `apply::apply_locked`.
#[derive(Clone, Copy, Debug, Default)]
pub struct ApplyEngine;

impl Engine for ApplyEngine {
    fn recover(&self, ctx: &Ctx, lock: &FileLock) -> Result<()> {
        apply::recover_locked(ctx, lock).map_err(unwrap_exit)
    }

    fn apply(&self, ctx: &Ctx, lock: &FileLock, req: ApplyRequest) -> Result<()> {
        apply::apply_locked(ctx, lock, req)
    }
}

/// The exit code of an `Error::Exit` at `error` or anywhere in its
/// context chain.
pub fn exit_within(error: &Error) -> Option<i32> {
    match error {
        Error::Exit { code, .. } => Some(*code),
        Error::Context { source, .. } => exit_within(source),
        _ => None,
    }
}

/// The innermost `Error::Exit` when `error` wraps one (its exit code must
/// survive), else `error` unchanged.
pub fn unwrap_exit(error: Error) -> Error {
    match error {
        Error::Context { source, message } => match unwrap_exit(*source) {
            exit @ Error::Exit { .. } => exit,
            source => Error::Context {
                message,
                source: Box::new(source),
            },
        },
        other => other,
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
    /// Every warning the updaters print (`[警告] …` on stderr in
    /// production); tests record them.
    pub warn: &'a dyn Fn(&str),
}

fn ignore_phase(_: ProgramPhase) {}

fn print_warning(message: &str) {
    out::warn(message);
}

impl<'a> Updater<'a> {
    /// The production wiring: process environment, the real apply engine.
    pub fn system(ctx: &'a Ctx) -> Updater<'a> {
        Updater {
            ctx,
            env: &process_env,
            engine: &ApplyEngine,
            on_phase: &ignore_phase,
            warn: &print_warning,
        }
    }
}

/// The saved update channel (`stable` when none was saved).
pub fn channel(paths: &Paths) -> Result<Channel> {
    channel::saved(paths)
}

/// Save the update channel preference (`ROOT/update-channel`, 0600).
pub fn set_channel(paths: &Paths, channel: Channel) -> Result<()> {
    channel::save(paths, channel)
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

/// Remove work directories `dirname(EXE)/.onebox-update-*` that no
/// self-update journal refers to: left by an updater killed before its
/// journal existed, they may hold a copy of the node's configuration and
/// private keys (0700, root only). `lock` is the node lock the caller holds
/// after `apply::recover_locked`. Every updater (v2 and v3) creates and
/// uses its work directory while holding the node lock and the update lock,
/// so nothing is touched under an inherited lock (a self-update child: the
/// parent's directory is in use), while any journal — or an unreadable one
/// — exists, or while another process holds the update lock. Best effort.
pub fn sweep_orphans(paths: &Paths, lock: &FileLock) {
    if lock.is_inherited() || lock.verify(&paths.lock()).is_err() {
        return;
    }
    if let Ok(_update) = FileLock::acquire(&paths.update_lock(), UPDATE_BUSY) {
        selfupdate::sweep_unreferenced(paths);
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exit_codes_are_found_through_context() {
        let stale = || Error::exit(75, "stale");
        let wrapped = Error::Context {
            message: "外层".into(),
            source: Box::new(Error::Context {
                message: "内层".into(),
                source: Box::new(stale()),
            }),
        };
        assert_eq!(exit_within(&wrapped), Some(75));
        assert_eq!(exit_within(&stale()), Some(75));
        assert_eq!(exit_within(&Error::msg("x").wrap("y")), None);
        let unwrapped = unwrap_exit(wrapped);
        assert!(matches!(unwrapped, Error::Exit { code: 75, .. }));
        assert_eq!(unwrapped.exit_code(), 75);
        // Anything else keeps its chain.
        let plain = unwrap_exit(Error::msg("内层").wrap("外层"));
        assert_eq!(plain.to_string(), "外层: 内层");
        assert!(unwrap_exit(Error::Cancelled.wrap("取消")).is_cancelled());
    }
}
