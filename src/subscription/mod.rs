//! Remote subscription: client configurations published as per-device URLs
//! (`/sub/<token>/<format>`), spec G §1.1–§3.7, §5.1.
//!
//! - Endpoint settings live in `NodeConfig.subscription` (ip / site /
//!   standalone, port); devices in `subscription/devices.json`
//!   ([`devices`]; v2's `settings.json` is read until then).
//! - [`snapshot`]: `subscription/published.json`, every supported remote
//!   format, written atomically by the publish stage.
//! - [`server`] + [`http`]: the worker `onebox subscription serve` — TCP
//!   in ip mode, a unix socket behind nginx otherwise.
//! - [`frontend`]: the `/sub/` location for the site and the standalone
//!   `onebox-subscription-web` nginx.
//! - [`lifecycle`]: the apply hooks (prepare, certificates, services,
//!   publish) re-exported below with the signatures the apply engine uses.
//! - [`endpoint`]: URLs and texts; [`request`] + [`cli`]: the commands;
//!   [`renew`]: certificate renewal without an apply; [`checks`]: doctor.
//!
//! Changes from v2 (details in each module): ip mode is served by the
//! worker directly on TCP, without nginx; the worker is restarted when the
//! program or its listener changes; disabling removes units, nginx config
//! and the credential-bearing snapshot; tokens are printed with URLs for
//! every supported format even without a snapshot; renewals never run a
//! full apply; standalone nginx temp files live under the persistent
//! `subscription/` directory.

pub mod checks;
pub mod cli;
pub mod devices;
pub mod endpoint;
pub mod frontend;
pub mod http;
pub mod lifecycle;
pub mod renew;
pub mod request;
pub mod server;
pub mod snapshot;

#[cfg(test)]
mod e2e;
#[cfg(test)]
pub(crate) mod testing;

pub use checks::checks;
pub use cli::{info, SUBSCRIPTION};
pub use devices::{DeviceStore, NewDevice};
pub use endpoint::{endpoint, singbox_import_link, urls, SubscriptionInfo};
pub use frontend::{install_web_conf, render_web_conf};
pub use renew::renew;
pub use server::serve;

use crate::cert::cloudflare::CfCredentials;
use crate::cert::Engine;
use crate::ctx::Ctx;
use crate::domain::config::Device;
use crate::domain::NodeConfig;
use crate::error::Result;
use crate::paths::Paths;
use crate::render::NodeSpec;
use crate::site::SiteSubscription;

/// Worker service (unix socket or, in ip mode, TCP).
pub const SERVICE: &str = crate::host::service::SUBSCRIPTION;
/// Dedicated nginx for the standalone HTTPS endpoint.
pub const WEB_SERVICE: &str = crate::host::service::SUBSCRIPTION_WEB;

/// prepare-state: write migrated v2 devices, or clear devices and the
/// published snapshot on reinstall; ensure directories.
pub fn prepare(ctx: &Ctx, cfg: &NodeConfig, migrated: Option<&[Device]>, clear: bool) -> Result<()> {
    lifecycle::prepare(&Engine::system(ctx), cfg, migrated, clear)
}

/// prepare-certificates: the standalone endpoint's certificate (no-op in ip
/// and site mode). Returns whether the deployed pair changed. Never prompts.
pub fn prepare_certificates(
    ctx: &Ctx,
    cfg: &NodeConfig,
    force: bool,
    cf: Option<&CfCredentials>,
) -> Result<bool> {
    lifecycle::prepare_certificates(&Engine::system(ctx), cfg, force, cf)
}

/// The `/sub/` location block for the site nginx when the subscription is
/// served through the site (`SubscriptionMode::Site`), else `None`.
pub fn site_location(paths: &Paths, cfg: &NodeConfig) -> Option<SiteSubscription> {
    frontend::site_location(paths, cfg)
}

/// configure-services: write/remove the worker and web units for the mode.
pub fn configure_services(ctx: &Ctx, cfg: &NodeConfig) -> Result<()> {
    lifecycle::configure_services(&Engine::system(ctx), cfg)
}

/// publish-subscription: write the snapshot, then start/restart the worker
/// and web service as needed (executable identity or listener changed).
pub fn publish(ctx: &Ctx, cfg: &NodeConfig, spec: &NodeSpec) -> Result<()> {
    lifecycle::publish(&Engine::system(ctx), cfg, spec)
}
