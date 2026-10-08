//! Init system detection (systemd / OpenRC / none) with the ONEBOX_INIT override.
//!
//! Minimal placeholder used by the service layer until the full module lands;
//! it keeps v2's detection order (`ONEBOX_INIT`, `/run/systemd/system`,
//! `/run/openrc` or `openrc-run`, else none), read under `system_root`.

use crate::ctx::Ctx;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum InitSystem {
    Systemd,
    Openrc,
    /// No init integration: Onebox supervises daemons itself.
    None,
}

/// Detect the init system of the host.
pub fn detect(ctx: &Ctx) -> InitSystem {
    match std::env::var("ONEBOX_INIT").as_deref() {
        Ok("systemd") => return InitSystem::Systemd,
        Ok("openrc") => return InitSystem::Openrc,
        Ok("none") => return InitSystem::None,
        _ => {}
    }
    if ctx.paths.system("/run/systemd/system").is_dir() {
        InitSystem::Systemd
    } else if ctx.paths.system("/run/openrc").exists() || ctx.has("openrc-run") {
        InitSystem::Openrc
    } else {
        InitSystem::None
    }
}
