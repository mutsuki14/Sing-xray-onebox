//! `onebox net-apply` (alias `boot`, run by the `onebox-network` oneshot at
//! boot, spec B §4.6): recover leftovers, then bring the network rules back.
//!
//! When the node blocks egress to its own addresses and the host's global
//! addresses changed since the saved generation, the server configs must
//! carry the new list, so a full apply runs (it refreshes the addresses
//! again inside the transaction). Otherwise only the firewall rules and hops
//! are rebuilt: no unit, crontab line or state is written.
//!
//! Changes from v2:
//! - nothing is started here — without an init system each enabled service
//!   has its own `@reboot … service NAME start` line (G18);
//! - the comparison is on the sorted address list, not on JSON text;
//! - the node lock is waited for (up to [`LOCK_WAIT`], like `--cron`
//!   renewals): without an init system every `@reboot` line runs at the
//!   same moment, and a renewal or self-update may hold the lock at boot —
//!   losing that race would leave the host without its firewall rules and
//!   hops until the next boot (they do not survive a reboot);
//! - an address refresh that fails still restores the rules of the saved
//!   configuration (its server configs carry the saved address list), and
//!   then reports the failure.

use super::engine;
use super::features::Features;
use super::network;
use super::recover;
use super::request::ApplyRequest;
use crate::ctx::Ctx;
use crate::error::{Error, Result};
use crate::paths::Paths;
use crate::state::StateStore;
use crate::sys::lock::{inherited_lock_offered, FileLock, BUSY_MESSAGE};
use crate::sys::net;
use std::time::Duration;

/// Reason shown when a boot regenerates the node.
pub const REFRESH_REASON: &str = "更新本机地址";
/// How long boot waits for the node lock (the `--cron` retry policy).
pub const LOCK_WAIT: Duration = Duration::from_secs(600);
/// How often boot retries the node lock meanwhile.
pub const LOCK_POLL: Duration = Duration::from_millis(200);

/// [`crate::apply::boot`] with explicit feature hooks.
pub fn boot_with(ctx: &Ctx, features: &dyn Features) -> Result<()> {
    let lock = boot_lock(&ctx.paths, LOCK_WAIT)?;
    recover::settle_signal(boot_locked(ctx, &lock, features))
}

/// The lock inherited from a self-update parent, else the node lock,
/// waiting up to `wait` while another operation holds it.
pub fn boot_lock(paths: &Paths, wait: Duration) -> Result<FileLock> {
    if inherited_lock_offered() {
        return FileLock::from_inherited(&paths.lock());
    }
    FileLock::acquire_waiting(&paths.lock(), BUSY_MESSAGE, wait, LOCK_POLL)
}

/// [`boot_with`] under a lock the caller holds.
pub fn boot_locked(ctx: &Ctx, lock: &FileLock, features: &dyn Features) -> Result<()> {
    recover::recover_all(ctx, lock)?;
    let loaded = StateStore::load_required(ctx)?;
    if loaded.config.routing.block_private {
        match net::own_global_cidrs(ctx) {
            Ok(current) if current != loaded.config.routing.own_cidrs => {
                let mut config = loaded.config.clone();
                config.routing.own_cidrs = current;
                let req = ApplyRequest::from_loaded(&loaded, config, REFRESH_REASON);
                return engine::apply_with(ctx, lock, req, features);
            }
            Ok(_) => {}
            Err(e) => {
                return Err(match network::apply_rules(ctx, &loaded.config) {
                    Ok(()) => e.wrap("已按保存的配置恢复防火墙规则，但无法读取本机地址"),
                    Err(rules) => Error::msg(format!(
                        "无法读取本机地址: {}；恢复防火墙规则失败: {}",
                        e.report_text(),
                        rules.report_text()
                    )),
                });
            }
        }
    }
    network::apply_rules(ctx, &loaded.config)
}
