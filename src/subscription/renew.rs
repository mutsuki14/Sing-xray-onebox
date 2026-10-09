//! `subscription renew [--cron]` (also v2's `cert-renew subscription`):
//! renew the certificate the subscription URL is served with, without an
//! apply (ARCH §11, G9). ip mode has nothing to renew; site mode renews
//! the website certificate (it serves the URLs); standalone renews
//! `subscription/tls`. Only the affected nginx is restarted. A manual run
//! forces the renewal; `--cron` renews only what is due and is silent
//! otherwise.
//!
//! Changes from v2: no full apply (v2 restarted every core for a
//! renewal, G-8.1#9); a renewal failure is an error under `--cron` too
//! instead of being hidden (G-8.1#18).

use super::endpoint::IP_RENEW;
use crate::cert::{renew_all, CertScope, CertScopes, CfCredentials, RenewOptions};
use crate::ctx::Ctx;
use crate::domain::config::SubscriptionMode;
use crate::domain::NodeConfig;
use crate::error::{Error, Result};
use crate::sys::lock::FileLock;
use crate::ui::out;

/// The renewal options of a subscription renewal.
pub fn options(scheduled: bool) -> RenewOptions {
    RenewOptions {
        targets: CertScopes::only(CertScope::Subscription),
        scheduled,
        force: !scheduled,
    }
}

/// Renew under the node lock (module docs). `cf` serves DNS-01 targets
/// without stored credentials (resolved by the caller, never prompted).
pub fn renew(
    ctx: &Ctx,
    lock: &FileLock,
    cfg: &NodeConfig,
    scheduled: bool,
    cf: Option<&CfCredentials>,
) -> Result<()> {
    let Some(sub) = &cfg.subscription else {
        return Ok(());
    };
    if matches!(sub.mode, SubscriptionMode::Ip { .. }) {
        return out::data(IP_RENEW);
    }
    let report = renew_all(ctx, lock, cfg, &options(scheduled), cf)?;
    match report.failed.first() {
        Some((scope, error)) => Err(Error::msg(format!("{}续期失败: {error}", scope.label()))),
        None => Ok(()),
    }
}

#[cfg(test)]
mod tests;
