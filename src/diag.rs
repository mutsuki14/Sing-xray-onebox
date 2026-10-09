//! Diagnostics: `onebox doctor` (data-driven health checks) and
//! `onebox support` (a redacted JSON report for bug reports).
//!
//! A diagnosis is a list of [`Check`]s. Which checks run follows from what
//! is installed and configured ([`survey`]): the node state, pending
//! journals and the installed program always; per used core its binary,
//! version and configuration; the services the configuration needs; the
//! certificates in effect (proxy, site, standalone subscription); the site's
//! nginx configuration; the renewal cron line when a certificate needs it;
//! the firewall and hop ledgers; the FRP state when FRP is installed; then
//! the checks of feature modules registered in [`registry::EXTRA_CHECKS`]
//! (or passed to [`doctor_with`] / [`support_with`]).
//!
//! Every check is read-only: nothing is started, repaired, created under
//! the run root or written (support writes only its report file). Checks
//! never abort the diagnosis: a failing probe becomes a `[失败]` or
//! `[警告]` line.
//!
//! Changes from v2:
//! - checks cover the site, subscription and FRP, service autostart, the
//!   renewal cron line, the firewall/hop ledgers and the installed program,
//!   not only the cores, two certificates and the journal (D-8.1#32);
//! - an expired certificate is a failure, one expiring within 7 days a
//!   warning (v2 warned for both); a missing `openssl` is a warning line,
//!   not an abort (D-8.1#27);
//! - a pending or corrupt journal is a `[失败]` line and counts as a
//!   problem (v2 printed `[警告]` but counted it, or aborted on a corrupt
//!   journal, D-8.1#28/#29); one helper (`apply::journal::pending`) decides;
//! - core configurations are checked in a private temp directory, never in
//!   `RUN/check` (D-8.1#30, G42);
//! - lines are `[通过]/[警告]/[失败] {name}: {detail}` followed by a summary;
//!   the exit status counts failures only;
//! - `support` names its file `support-{unix}-{random}.json` (v2 failed
//!   when run twice in a second, D-8.1#31), ends it with a newline, adds the
//!   check results, and redacts IP addresses, domain names and credentials
//!   from every free-form text; failing host probes (`uname`) no longer
//!   abort it.

mod checks;
mod cli;
mod node;
mod redact;
pub mod registry;
mod report;
mod support;
mod survey;
mod tls;

#[cfg(test)]
pub(crate) mod fixture;
#[cfg(test)]
mod realcore;

pub use cli::{COMMANDS, DOCTOR, SUPPORT};
pub use redact::Redactor;
pub use registry::EXTRA_CHECKS;
pub use report::{format_check, summary_line, Tally, DOCTOR_HINT};
pub use support::{
    CertModes, CoreRow, Features, HostInfo, ProtocolRow, SupportReport, SUPPORT_NOTE,
    SUPPORT_SCHEMA,
};
pub use survey::{NodeState, Survey};

use crate::ctx::Ctx;
use crate::domain::NodeConfig;
use crate::error::Result;
use crate::host::init::{self, InitSystem};
use crate::host::service::Services;
use serde::Serialize;
use std::path::PathBuf;

/// Outcome of one doctor check.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum CheckStatus {
    /// Nothing to do.
    Pass,
    /// Worth a look; does not fail the diagnosis.
    Warn,
    /// Needs fixing; `doctor` exits non-zero.
    Fail,
}

impl CheckStatus {
    /// `[通过]` / `[警告]` / `[失败]`.
    pub fn tag(self) -> &'static str {
        match self {
            CheckStatus::Pass => "[通过]",
            CheckStatus::Warn => "[警告]",
            CheckStatus::Fail => "[失败]",
        }
    }
}

/// One line of `onebox doctor` output.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Check {
    /// What was checked, e.g. `sing-box 配置`, `服务 onebox-site`.
    pub name: String,
    pub status: CheckStatus,
    /// The finding (may span lines, e.g. a core's own error output).
    pub detail: String,
}

impl Check {
    pub fn new(name: impl Into<String>, status: CheckStatus, detail: impl Into<String>) -> Self {
        Check {
            name: name.into(),
            status,
            detail: detail.into(),
        }
    }

    pub fn pass(name: impl Into<String>, detail: impl Into<String>) -> Self {
        Check::new(name, CheckStatus::Pass, detail)
    }

    pub fn warn(name: impl Into<String>, detail: impl Into<String>) -> Self {
        Check::new(name, CheckStatus::Warn, detail)
    }

    pub fn fail(name: impl Into<String>, detail: impl Into<String>) -> Self {
        Check::new(name, CheckStatus::Fail, detail)
    }

    pub fn is_fail(&self) -> bool {
        self.status == CheckStatus::Fail
    }
}

/// A provider of extra checks (feature modules such as the subscription
/// or FRP). It gets the node configuration when one could be loaded and
/// must not fail: problems are reported as checks.
pub type CheckFn = fn(&Ctx, Option<&NodeConfig>) -> Vec<Check>;

/// The external facts of a diagnosis; tests build one with fixed values.
pub struct Doctor<'a> {
    pub ctx: &'a Ctx,
    /// The init system services are queried through.
    pub init: InitSystem,
    /// Unix seconds certificate expiry is measured against.
    pub now: u64,
}

impl<'a> Doctor<'a> {
    /// The running host: detected init system, current time.
    pub fn system(ctx: &'a Ctx) -> Doctor<'a> {
        Doctor {
            ctx,
            init: init::detect(ctx),
            now: crate::sys::time::now(),
        }
    }

    /// Service operations for [`Doctor::init`].
    pub fn services(&self) -> Services<'a> {
        Services::new(self.ctx, self.init)
    }

    /// Run every applicable check (see the module docs), handing each one
    /// to `sink` as soon as it is known. `Err(NotInstalled)` when there is
    /// nothing to diagnose: no node state, no FRP and no pending journal.
    pub fn diagnose(&self, extra: &[CheckFn], sink: &mut dyn FnMut(&Check)) -> Result<Diagnosis> {
        checks::diagnose(self, extra, sink)
    }
}

/// What a diagnosis found.
#[derive(Debug)]
pub struct Diagnosis {
    pub survey: Survey,
    pub checks: Vec<Check>,
}

impl Diagnosis {
    pub fn tally(&self) -> Tally {
        Tally::of(&self.checks)
    }
}

/// `onebox doctor` with the registered extra checks.
pub fn doctor(ctx: &Ctx) -> Result<()> {
    doctor_with(ctx, EXTRA_CHECKS)
}

/// `onebox doctor` with explicit extra check providers: prints every check
/// as it completes, then the summary and v2's closing hint, on stdout.
/// `Err("体检发现 {n} 个需要处理的问题")` iff a check failed.
pub fn doctor_with(ctx: &Ctx, extra: &[CheckFn]) -> Result<()> {
    report::run_doctor(&Doctor::system(ctx), extra)
}

/// `onebox support` with the registered extra checks; returns the path of
/// the new report `ROOT/support-{unix}-{hex}.json` (0600).
pub fn support(ctx: &Ctx) -> Result<PathBuf> {
    support_with(ctx, EXTRA_CHECKS)
}

/// [`support`] with explicit extra check providers.
pub fn support_with(ctx: &Ctx, extra: &[CheckFn]) -> Result<PathBuf> {
    support::write_support(&Doctor::system(ctx), extra)
}

#[cfg(test)]
mod tests;
