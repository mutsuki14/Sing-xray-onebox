//! Public API of the apply engine: the request types and the entry points,
//! which take the node lock and hand over to the engine with the production
//! feature hooks.
//!
//! Changes from v2: one-shot requests are typed [`Intents`] instead of
//! transient state keys (`RESTORE_PENDING_ID`, `CERT_RENEW_PROXY`,
//! `SITE_CONTENT_PENDING_TEXT`, …), and the compare-and-swap hash is a field
//! of the request instead of `__EXPECTED_STATE_HASH`; every entry point
//! adopts a lock inherited from a self-update parent.

use super::features::SystemFeatures;
use crate::cert::cloudflare::CfCredentials;
use crate::cert::CertScopes;
use crate::ctx::Ctx;
use crate::domain::config::Device;
use crate::domain::{Core, NodeConfig};
use crate::error::Result;
use crate::site::SiteContent;
use crate::state::{Loaded, Origin, StateHash, StateStore};
use crate::sys::lock::{FileLock, BUSY_MESSAGE};
use std::path::PathBuf;

/// One-shot requests carried by an apply; never persisted in state.json.
#[derive(Clone, Debug, Default)]
pub struct Intents {
    /// Force renewal of these certificates.
    pub renew: CertScopes,
    /// Place this backup's files inside the transaction (prepare-state).
    /// A concrete id: `backup::restore` resolves `latest` before it takes
    /// its safety backup, which would otherwise be the newest.
    pub restore_backup: Option<String>,
    pub site_content: Option<SiteContent>,
    /// Verified core binaries to swap in (`onebox update`).
    pub replace_cores: Vec<(Core, PathBuf)>,
    /// Devices migrated from v2 `subscription/settings.json`, written to
    /// `subscription/devices.json` by the transaction.
    pub migrated_devices: Option<Vec<Device>>,
    /// Cloudflare credentials resolved by the caller (apply never prompts);
    /// persisted into each Cloudflare certificate directory it issues for.
    pub cloudflare: Option<CfCredentials>,
    /// Delete subscription devices and the published snapshot (reinstall).
    pub clear_devices: bool,
}

/// A request to make `config` the running generation.
#[derive(Clone, Debug)]
pub struct ApplyRequest {
    pub config: NodeConfig,
    /// Hash of the state.json the caller started from (compare-and-swap).
    pub expected: StateHash,
    pub intents: Intents,
    /// Short Chinese label for progress output, e.g. "添加协议".
    pub reason: &'static str,
}

impl ApplyRequest {
    pub fn new(config: NodeConfig, expected: StateHash, reason: &'static str) -> Self {
        ApplyRequest {
            config,
            expected,
            intents: Intents::default(),
            reason,
        }
    }

    /// A modification of a loaded configuration. For a configuration just
    /// migrated from v2 the migrated subscription devices ride along, so the
    /// first v3 mutation (whatever it is) persists them.
    pub fn from_loaded(loaded: &Loaded, config: NodeConfig, reason: &'static str) -> Self {
        let mut req = ApplyRequest::new(config, loaded.hash.clone(), reason);
        if let Origin::V2 { devices, .. } = &loaded.origin {
            req.intents.migrated_devices = devices.clone();
        }
        req
    }

    /// A fresh install (or reinstall) over whatever state.json exists now.
    pub fn install(ctx: &Ctx, config: NodeConfig, reason: &'static str) -> Result<Self> {
        Ok(ApplyRequest::new(
            config,
            StateStore::current_hash(ctx)?,
            reason,
        ))
    }
}

/// Take the node lock (or the lock inherited from a self-update parent) and
/// apply `req` transactionally. Never prompts.
pub fn apply(ctx: &Ctx, req: ApplyRequest) -> Result<()> {
    let lock = node_lock(ctx)?;
    apply_locked(ctx, &lock, req)
}

/// [`apply`] with a lock the caller already holds.
pub fn apply_locked(ctx: &Ctx, lock: &FileLock, req: ApplyRequest) -> Result<()> {
    super::engine::apply_with(ctx, lock, req, &SystemFeatures)
}

/// Finish or roll back a leftover node journal, then a leftover self-update
/// journal (skipped under an inherited lock).
pub fn recover(ctx: &Ctx) -> Result<()> {
    let lock = node_lock(ctx)?;
    recover_locked(ctx, &lock)
}

pub fn recover_locked(ctx: &Ctx, lock: &FileLock) -> Result<()> {
    super::recover::recover_all(ctx, lock).map(drop)
}

/// `onebox net-apply` at boot: recover, refresh own IPs, re-apply firewall
/// rules and hops (full apply only when own IPs changed). Starts nothing.
pub fn boot(ctx: &Ctx) -> Result<()> {
    super::boot::boot_with(ctx, &SystemFeatures)
}

/// The node lock: inherited from a self-update parent when one is offered,
/// else taken without waiting.
pub fn node_lock(ctx: &Ctx) -> Result<FileLock> {
    FileLock::acquire_or_inherit(&ctx.paths.lock(), BUSY_MESSAGE)
}
