//! Extra doctor checks contributed by feature modules.
//!
//! The built-in checks cover what every node has (state, journals, cores,
//! services, certificates, site nginx, renewal cron, ledgers, FRP state).
//! Feature modules add their own deeper checks as [`CheckFn`] providers;
//! this list is where they are registered (the CLI work package wires the
//! subscription and FRP modules in, e.g.
//! `|ctx, cfg| cfg.map(|c| crate::subscription::checks(ctx, c)).unwrap_or_default()`
//! and `|ctx, _| crate::frp::checks(ctx)`). Providers run after the
//! built-in checks, in list order, for `doctor` and `support` alike.
//! Callers that need another list use `doctor_with` / `support_with`.

use super::CheckFn;

/// Providers run by [`super::doctor`] and [`super::support`].
pub static EXTRA_CHECKS: &[CheckFn] = &[];
