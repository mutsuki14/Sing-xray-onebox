//! What every command handler works with: the context, the apply engine,
//! live host facts and whether we run as root. All of it is injectable, so
//! handlers and menus are tested end to end without root, network or the
//! real transaction engine (tests use `testing::Recorder` and
//! `testing::FakeLive`).
//!
//! The shared rules of node mutations live here too:
//! - every `ApplyRequest` is built from the loaded state with
//!   `ApplyRequest::from_loaded` (v2-migrated devices ride along, G23) and
//!   the v2 migration warnings are printed once per session;
//! - Cloudflare credentials are resolved before the engine runs (G8,
//!   `cert::cloudflare::resolve_for_apply`): the engine never prompts, so a
//!   missing token is asked for here when interactive and is an error
//!   under `-y`.
//!
//! Changes from v2: reading the state as a non-root user explains that root
//! is needed instead of showing a raw permission error; a self-update child
//! (the `regen` v2.0.1's `update-script` runs) repeats its warnings — the
//! once-only migration notes among them — on stdout, the only output that
//! parent shows.

use crate::apply::{self, ApplyRequest};
use crate::cert::cloudflare;
use crate::ctx::Ctx;
use crate::domain::config::NodeConfig;
use crate::domain::plan::PlanEnv;
use crate::domain::ports::{PortProbe, Reservation};
use crate::domain::protocol::Transport;
use crate::error::{Error, Result};
use crate::host::init::{self, InitSystem};
use crate::host::service::Services;
use crate::paths::Paths;
use crate::state::{Loaded, Origin, StateStore};
use crate::sys::lock::FileLock;
use crate::sys::rand::{OsRandom, Random};
use crate::ui::out::{self, Level};
use crate::ui::Prompter;
use std::net::IpAddr;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};

/// Message for commands that need root.
pub const ROOT_REQUIRED: &str = "此操作需要 root 权限";

/// The transaction engine as the CLI uses it.
pub trait Engine: Send + Sync {
    fn apply(&self, ctx: &Ctx, req: ApplyRequest) -> Result<()>;
    fn apply_locked(&self, ctx: &Ctx, lock: &FileLock, req: ApplyRequest) -> Result<()>;
    fn recover(&self, ctx: &Ctx) -> Result<()>;
    fn recover_locked(&self, ctx: &Ctx, lock: &FileLock) -> Result<()>;
    fn boot(&self, ctx: &Ctx) -> Result<()>;
}

/// The real engine (`crate::apply`).
pub struct SystemEngine;

impl Engine for SystemEngine {
    fn apply(&self, ctx: &Ctx, req: ApplyRequest) -> Result<()> {
        apply::apply(ctx, req)
    }
    fn apply_locked(&self, ctx: &Ctx, lock: &FileLock, req: ApplyRequest) -> Result<()> {
        apply::apply_locked(ctx, lock, req)
    }
    fn recover(&self, ctx: &Ctx) -> Result<()> {
        apply::recover(ctx)
    }
    fn recover_locked(&self, ctx: &Ctx, lock: &FileLock) -> Result<()> {
        apply::recover_locked(ctx, lock)
    }
    fn boot(&self, ctx: &Ctx) -> Result<()> {
        apply::boot(ctx)
    }
}

/// Live facts about the host.
pub trait Live {
    /// IPv6 sockets work (listen address `::`, IPv6 subscriptions).
    fn ipv6(&self) -> bool;
    /// A socket holds `port` (`Transport::Tcp` or `Transport::Udp`).
    fn in_use(&self, port: u16, transport: Transport) -> bool;
    /// Ports reserved by the independent FRP server.
    fn frp(&self) -> Result<Vec<Reservation>>;
    /// The public address seen from the internet (`None` when unknown).
    fn public_ip(&self, v6: bool) -> Option<IpAddr>;
    /// Unix seconds.
    fn now(&self) -> u64;
    /// Randomness for credentials.
    fn rng(&self) -> Box<dyn Random>;
    fn init(&self) -> InitSystem;
    fn running(&self, service: &str) -> bool;
    /// [`Live::running`] for a status report: a service definition that
    /// exists but cannot be read or parsed (no init system) is an error,
    /// never "stopped".
    fn running_checked(&self, service: &str) -> Result<bool>;
}

/// The real host, read through the context (paths under `system_root`).
pub struct SystemLive<'a> {
    pub ctx: &'a Ctx,
}

impl Live for SystemLive<'_> {
    fn ipv6(&self) -> bool {
        crate::sys::net::ipv6_available(&self.ctx.paths.system_root)
    }
    fn in_use(&self, port: u16, transport: Transport) -> bool {
        crate::sys::net::listening(&self.ctx.paths.system_root, port, transport.tcp())
    }
    fn frp(&self) -> Result<Vec<Reservation>> {
        crate::frp::model::reservations(&self.ctx.paths)
    }
    fn public_ip(&self, v6: bool) -> Option<IpAddr> {
        crate::sys::net::detect_public_ip(self.ctx, v6)
    }
    fn now(&self) -> u64 {
        crate::sys::time::now()
    }
    fn rng(&self) -> Box<dyn Random> {
        Box::new(OsRandom)
    }
    fn init(&self) -> InitSystem {
        init::detect(self.ctx)
    }
    fn running(&self, service: &str) -> bool {
        Services::detect(self.ctx).running(service)
    }
    fn running_checked(&self, service: &str) -> Result<bool> {
        Services::detect(self.ctx).running_checked(service)
    }
}

/// [`Live`] as the planners' port probe.
pub struct LiveProbe<'a>(pub &'a dyn Live);

impl PortProbe for LiveProbe<'_> {
    fn in_use(&self, port: u16, transport: Transport) -> bool {
        self.0.in_use(port, transport)
    }
}

/// Facts a planner needs, gathered once per command.
pub struct Facts {
    pub ipv6: bool,
    pub frp: Vec<Reservation>,
    pub now: u64,
}

impl Facts {
    /// The planner environment over these facts.
    pub fn env<'a>(
        &'a self,
        probe: &'a dyn PortProbe,
        previous: Option<&'a NodeConfig>,
    ) -> PlanEnv<'a> {
        PlanEnv {
            ipv6: self.ipv6,
            probe,
            frp: &self.frp,
            previous,
            now: self.now,
        }
    }
}

/// Where a handler's output goes: command results to stdout, status lines
/// (`[完成]`/`[提示]`/`[警告]`/`[错误]`) to stderr. Tests capture both.
pub trait Printer: Send + Sync {
    fn data(&self, text: &str) -> Result<()>;
    fn status(&self, level: Level, text: &str);
}

/// The terminal (`ui::out`).
pub struct StdPrinter;

impl Printer for StdPrinter {
    fn data(&self, text: &str) -> Result<()> {
        out::data(text)
    }
    fn status(&self, level: Level, text: &str) {
        out::status(level, text);
    }
}

pub struct Session<'a> {
    pub ctx: &'a Ctx,
    pub engine: &'a dyn Engine,
    pub live: &'a dyn Live,
    pub is_root: bool,
    printer: &'a dyn Printer,
    warned: AtomicBool,
    /// Warnings are repeated on stdout (a self-update child, see
    /// [`Session::echoing_warnings`]).
    echo_warnings: bool,
}

impl<'a> Session<'a> {
    pub fn new(
        ctx: &'a Ctx,
        engine: &'a dyn Engine,
        live: &'a dyn Live,
        is_root: bool,
    ) -> Session<'a> {
        Session {
            ctx,
            engine,
            live,
            is_root,
            printer: &StdPrinter,
            warned: AtomicBool::new(false),
            echo_warnings: false,
        }
    }

    /// The same session printing through `printer` (tests).
    pub fn with_printer(mut self, printer: &'a dyn Printer) -> Session<'a> {
        self.printer = printer;
        self
    }

    /// The same session repeating every warning on stdout as `[警告] …`.
    /// For a self-update child (a parent offered its lock): v2.0.1's
    /// `update-script` shows only the child's stdout, so the once-only
    /// migration notes on stderr would never reach the user. A v3 parent
    /// collects the stderr copies and drops these lines from the stdout it
    /// shows (`update::selfupdate::child_report`).
    pub fn echoing_warnings(mut self, echo: bool) -> Session<'a> {
        self.echo_warnings = echo;
        self
    }

    /// A command result on stdout (one trailing newline).
    pub fn data(&self, text: &str) -> Result<()> {
        self.printer.data(text.trim_end_matches('\n'))
    }

    pub fn ok(&self, text: impl std::fmt::Display) {
        self.printer.status(Level::Ok, &text.to_string());
    }

    pub fn info(&self, text: impl std::fmt::Display) {
        self.printer.status(Level::Info, &text.to_string());
    }

    pub fn warn(&self, text: impl std::fmt::Display) {
        let text = text.to_string();
        self.printer.status(Level::Warn, &text);
        if self.echo_warnings {
            // Best effort: a parent that went away is not this command's error.
            let _ = self.data(&format!("{} {text}", Level::Warn.tag()));
        }
    }

    pub fn error(&self, text: impl std::fmt::Display) {
        self.printer.status(Level::Error, &text.to_string());
    }

    pub fn ui(&self) -> &dyn Prompter {
        self.ctx.ui.as_ref()
    }

    pub fn require_root(&self) -> Result<()> {
        if self.is_root {
            Ok(())
        } else {
            Err(Error::msg(ROOT_REQUIRED))
        }
    }

    pub fn services(&self) -> Services<'_> {
        Services::new(self.ctx, self.live.init())
    }

    /// A node is installed when its state file (or a v1 `onebox.conf`) is
    /// present — or cannot even be looked at: a non-root user gets EACCES
    /// inside the 0700 ROOT, which means "installed, needs root", not a
    /// fresh host (a preview would otherwise plan against no node).
    pub fn installed(&self) -> bool {
        installed_with(&self.ctx.paths, &|path| {
            std::fs::symlink_metadata(path).map(|_| ())
        })
    }

    /// The installed configuration (`NotInstalled` otherwise). Migration
    /// warnings of a v2 state are printed the first time only.
    pub fn load(&self) -> Result<Loaded> {
        let loaded = StateStore::load_required(self.ctx).map_err(explain_permission)?;
        self.warn_migration(&loaded);
        Ok(loaded)
    }

    /// Like [`Session::load`] but `None` when not installed.
    pub fn load_optional(&self) -> Result<Option<Loaded>> {
        let loaded = StateStore::load(self.ctx).map_err(explain_permission)?;
        if let Some(loaded) = &loaded {
            self.warn_migration(loaded);
        }
        Ok(loaded)
    }

    fn warn_migration(&self, loaded: &Loaded) {
        if let Origin::V2 { warnings, .. } = &loaded.origin {
            if !self.warned.swap(true, Ordering::SeqCst) {
                for warning in warnings {
                    self.warn(warning);
                }
            }
        }
    }

    pub fn facts(&self) -> Result<Facts> {
        Ok(Facts {
            ipv6: self.live.ipv6(),
            frp: self.live.frp()?,
            now: self.live.now(),
        })
    }

    /// Resolve Cloudflare credentials for `req` (G8), then run the engine.
    pub fn apply(&self, mut req: ApplyRequest) -> Result<()> {
        if req.intents.cloudflare.is_none() {
            req.intents.cloudflare =
                cloudflare::resolve_for_apply(self.ctx, self.ui(), &req.config, req.intents.renew)?;
        }
        self.engine.apply(self.ctx, req)
    }
}

/// [`Session::installed`] over a `stat` of each state file.
fn installed_with(paths: &Paths, stat: &dyn Fn(&Path) -> std::io::Result<()>) -> bool {
    [paths.state(), paths.legacy_v1_state()]
        .iter()
        .any(|path| match stat(path) {
            Ok(()) => true,
            Err(e) => e.kind() == std::io::ErrorKind::PermissionDenied,
        })
}

/// `ApplyRequest::from_loaded` for a modification of `loaded`.
pub fn request(loaded: &Loaded, config: NodeConfig, reason: &'static str) -> ApplyRequest {
    ApplyRequest::from_loaded(loaded, config, reason)
}

/// A permission error on the state file means "run as root".
fn explain_permission(e: Error) -> Error {
    match &e {
        Error::Io { source, .. } if source.kind() == std::io::ErrorKind::PermissionDenied => {
            Error::msg(ROOT_REQUIRED)
        }
        _ => e,
    }
}

/// Run `f` with the production session. In a self-update child (a parent
/// offered its lock; read before the lock is adopted, which consumes the
/// offer) warnings are repeated on stdout.
pub fn with_system<T>(ctx: &Ctx, f: impl FnOnce(&Session) -> Result<T>) -> Result<T> {
    let live = SystemLive { ctx };
    let session = Session::new(ctx, &SystemEngine, &live, crate::sys::process::is_root())
        .echoing_warnings(crate::sys::lock::inherited_lock_offered());
    f(&session)
}

#[cfg(test)]
pub(crate) mod testing;

#[cfg(test)]
mod tests;
