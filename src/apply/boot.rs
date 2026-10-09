//! `onebox net-apply` (alias `boot`, run by the `onebox-network` oneshot at
//! boot, spec B §4.6): recover leftovers, then bring the network rules back.
//!
//! When the node blocks egress to its own addresses and the host's global
//! addresses changed since the saved generation, the server configs must
//! carry the new list, so a full apply runs (it refreshes the addresses
//! again inside the transaction). Otherwise only the firewall rules and hops
//! are rebuilt: no unit, crontab line or state is written.
//!
//! Changes from v2: nothing is started here — without an init system each
//! enabled service has its own `@reboot … service NAME start` line (G18);
//! the comparison is on the sorted address list, not on JSON text.

use super::engine;
use super::features::Features;
use super::network;
use super::recover;
use super::request::ApplyRequest;
use crate::ctx::Ctx;
use crate::error::Result;
use crate::state::StateStore;
use crate::sys::lock::{FileLock, BUSY_MESSAGE};
use crate::sys::net;

/// Reason shown when a boot regenerates the node.
pub const REFRESH_REASON: &str = "更新本机地址";

/// [`crate::apply::boot`] with explicit feature hooks.
pub fn boot_with(ctx: &Ctx, features: &dyn Features) -> Result<()> {
    let lock = FileLock::acquire_or_inherit(&ctx.paths.lock(), BUSY_MESSAGE)?;
    recover::recover_all(ctx, &lock)?;
    let loaded = StateStore::load_required(ctx)?;
    if loaded.config.routing.block_private {
        let current = net::own_global_cidrs(ctx)?;
        if current != loaded.config.routing.own_cidrs {
            let mut config = loaded.config.clone();
            config.routing.own_cidrs = current;
            let req = ApplyRequest::from_loaded(&loaded, config, REFRESH_REASON);
            return engine::apply_with(ctx, &lock, req, features);
        }
    }
    network::apply_rules(ctx, &loaded.config)
}
