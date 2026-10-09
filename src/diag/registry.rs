//! Extra doctor checks contributed by feature modules.
//!
//! The built-in checks cover what every node has (state, journals, cores,
//! services, certificates, nginx configurations, renewal cron, ledgers,
//! FRP state). Feature modules add deeper checks as [`CheckFn`] providers
//! that run after the built-in checks, in list order, for `doctor` and
//! `support` alike.
//!
//! Feature modules return [`super::Check`], so they depend on `diag`;
//! listing them here would make `diag` depend on them in turn (a module
//! cycle, ARCH §2). Their list therefore lives in the CLI
//! (`cli::commands::diagnose::PROVIDERS`: the subscription and FRP
//! checks), whose `doctor` / `support` handlers pass it through
//! [`super::doctor_with`] / [`super::support_command_with`]; the specs
//! stay [`super::DOCTOR`] / [`super::SUPPORT`] with the handlers swapped.
//!
//! [`EXTRA_CHECKS`] — what [`super::doctor`] / [`super::support`] run —
//! stays empty: `diag` never imports a feature module.

use super::CheckFn;

/// Providers run by [`super::doctor`] and [`super::support`]; empty (see
/// the module docs).
pub static EXTRA_CHECKS: &[CheckFn] = &[];
