//! Remote subscription: endpoint settings (in NodeConfig), devices
//! (`subscription/devices.json`), the published snapshot, the HTTP worker and
//! the nginx front-end. The hook bodies below are implemented by WP-C2; the
//! apply engine (WP-C1) calls them with these exact signatures.

use crate::cert::cloudflare::CfCredentials;
use crate::ctx::Ctx;
use crate::domain::config::Device;
use crate::domain::NodeConfig;
use crate::error::Result;
use crate::paths::Paths;
use crate::render::NodeSpec;
use crate::site::SiteSubscription;
use std::path::Path;

/// Worker service (unix socket or, in ip mode, TCP).
pub const SERVICE: &str = "onebox-subscription";
/// Dedicated nginx for the standalone HTTPS endpoint.
pub const WEB_SERVICE: &str = "onebox-subscription-web";

/// prepare-state: write migrated v2 devices, or clear devices and the
/// published snapshot on reinstall; ensure directories.
pub fn prepare(
    _ctx: &Ctx,
    _cfg: &NodeConfig,
    _migrated: Option<&[Device]>,
    _clear: bool,
) -> Result<()> {
    todo!("WP-C2")
}

/// prepare-certificates: the standalone endpoint's certificate (no-op in ip
/// and site mode). Returns whether the deployed pair changed. Never prompts.
pub fn prepare_certificates(
    _ctx: &Ctx,
    _cfg: &NodeConfig,
    _force: bool,
    _cf: Option<&CfCredentials>,
) -> Result<bool> {
    todo!("WP-C2")
}

/// The `/sub/` location block for the site nginx when the subscription is
/// served through the site (`SubscriptionMode::Site`), else `None`.
pub fn site_location(_paths: &Paths, _cfg: &NodeConfig) -> Option<SiteSubscription> {
    todo!("WP-C2")
}

/// check-configurations: the standalone nginx config to stage and
/// `nginx -t`; `None` in ip and site mode or when disabled.
pub fn render_web_conf(_ctx: &Ctx, _cfg: &NodeConfig) -> Result<Option<String>> {
    todo!("WP-C2")
}

/// Install a web config that passed `nginx -t` (later stage).
pub fn install_web_conf(_ctx: &Ctx, _tested: &Path) -> Result<()> {
    todo!("WP-C2")
}

/// configure-services: write/remove the worker and web units for the mode.
pub fn configure_services(_ctx: &Ctx, _cfg: &NodeConfig) -> Result<()> {
    todo!("WP-C2")
}

/// publish-subscription: write the snapshot, then start/restart the worker
/// and web service as needed (executable identity or listener changed).
pub fn publish(_ctx: &Ctx, _cfg: &NodeConfig, _spec: &NodeSpec) -> Result<()> {
    todo!("WP-C2")
}
