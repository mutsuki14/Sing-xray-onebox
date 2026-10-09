//! The subscription's part of a node apply (called by `apply::stages`
//! through the hooks in `subscription`): prepare-state, prepare-
//! certificates, configure-services and publish-subscription. None of them
//! prompts.
//!
//! - [`prepare`]: write migrated v2 devices (never over an existing
//!   `devices.json`, which is newer), or clear devices, snapshot and
//!   listener record on reinstall; re-check the IPv6 family and the
//!   socket path.
//! - [`prepare_certificates`] (standalone only): install nginx, then the
//!   endpoint certificate in `subscription/tls`. HTTP-01 is answered by the
//!   standalone nginx's port-80 server over the ACME webroot; when acme.sh
//!   will run ([`crate::cert::web_needs_acme`]) and no running instance
//!   serves that webroot yet, a bootstrap config (port 80 only) is started
//!   first.
//! - [`configure_services`]: write or remove `onebox-subscription` and
//!   `onebox-subscription-web` for the mode (both removed when off; the web
//!   service and its config only exist in standalone mode).
//! - [`publish`]: render and atomically write the snapshot, record the
//!   listener, install the tested standalone config, then start the worker
//!   — or restart it when its executable (`/proc/PID/exe` versus `EXE`)
//!   or its listener changed (self-update, mode or port change; G6/G13) —
//!   and wait until it listens; start the web service in standalone mode.
//!   Off: remove both services, the snapshot and the listener record.
//!
//! Changes from v2: the worker is restarted after self-updates and
//! listener changes (G-8.1#8); disabling removes the units, the nginx
//! config and the snapshot with its credentials (G-8.1#12); the snapshot
//! and settings are not restored by hand on failure — the apply's journal
//! rolls the whole directory back.

use super::devices::DeviceStore;
use super::frontend::{self, WebPhase};
use super::server::{self, Listener};
use super::{snapshot, SERVICE, WEB_SERVICE};
use crate::cert::hooks::{prepare_web_with, web_needs_acme_with};
use crate::cert::{CertDir, CfCredentials, Engine, WebCertTarget};
use crate::domain::config::{Device, NodeConfig, SubscriptionMode};
use crate::domain::plan::check_subscription_family;
use crate::error::{Error, Result};
use crate::host::nginx;
use crate::host::service::{ServiceDef, Services, WAIT_RUNNING};
use crate::paths::Paths;
use crate::render::NodeSpec;
use crate::site::NginxFacts;
use crate::sys::fs::{atomic_write, ensure_dir, remove_file_if_exists};
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::time::{Duration, Instant};

pub const PORT80_BUSY: &str = "HTTP-01 的 TCP 80 已被占用，请改用 cf/custom";
pub const ACME_FOREIGN: &str = "订阅 ACME 目录含未托管内容";
const OWNED_MARKER: &str = ".onebox-owned";
/// How long a (re)started worker gets to accept connections.
const LISTEN_WAIT: Duration = Duration::from_secs(3);

/// prepare-state (module docs).
pub fn prepare(
    engine: &Engine,
    cfg: &NodeConfig,
    migrated: Option<&[Device]>,
    clear: bool,
) -> Result<()> {
    let paths = &engine.ctx.paths;
    if clear {
        clear_all(paths)?;
    } else if let Some(devices) = migrated {
        if std::fs::symlink_metadata(paths.devices()).is_err() {
            DeviceStore::write(paths, devices)?;
        }
    }
    let Some(listener) = Listener::of(cfg) else {
        return Ok(());
    };
    check_subscription_family(cfg, ipv6(paths))?;
    if listener == Listener::Unix {
        frontend::check_socket_path(paths)?;
    }
    Ok(())
}

/// Reinstall: devices (v3 and v2 lists), snapshot and listener record.
fn clear_all(paths: &Paths) -> Result<()> {
    for file in [
        paths.devices(),
        paths.subscription_v2_settings(),
        paths.published(),
        server::listener_file(paths),
    ] {
        remove_file_if_exists(&file)?;
    }
    Ok(())
}

fn ipv6(paths: &Paths) -> bool {
    crate::sys::net::ipv6_available(&paths.system_root)
}

/// prepare-certificates (module docs). Returns whether the deployed pair
/// changed.
pub fn prepare_certificates(
    engine: &Engine,
    cfg: &NodeConfig,
    force: bool,
    cf: Option<&CfCredentials>,
) -> Result<bool> {
    let Some((domain, cert, http01, _)) = frontend::standalone(cfg) else {
        return Ok(false);
    };
    let ctx = engine.ctx;
    nginx::ensure_installed_with(ctx, engine.env, crate::host::os::is_root())?;
    let paths = &ctx.paths;
    let target = WebCertTarget {
        dir: CertDir::subscription(paths).path().to_path_buf(),
        domains: vec![domain.to_owned()],
        cert,
        webroot: http01.then(|| paths.subscription_acme()),
    };
    if http01 {
        prepare_acme_root(&paths.subscription_acme())?;
        let services = engine.services();
        let served = services.running(WEB_SERVICE) && frontend::installed_serves_acme(paths);
        if !served && web_needs_acme_with(engine, &target, force) {
            bootstrap(engine, cfg)?;
        }
    }
    prepare_web_with(engine, target, force, cf)
}

/// The ACME webroot: absent, empty or Onebox-owned; its three directories
/// 0755 (nginx workers read the challenges) and the ownership marker.
pub fn prepare_acme_root(root: &Path) -> Result<()> {
    let marker = root.join(OWNED_MARKER);
    if let Ok(mut entries) = std::fs::read_dir(root) {
        let foreign = entries.next().is_some() && std::fs::symlink_metadata(&marker).is_err();
        ensure!(!foreign, "{ACME_FOREIGN}");
    }
    let challenge = root.join(".well-known/acme-challenge");
    for dir in [root.to_path_buf(), root.join(".well-known"), challenge] {
        ensure_dir(&dir, 0o755)?;
    }
    atomic_write(&marker, b"onebox\n", 0o600)
}

/// Start the standalone nginx with the port-80-only config.
fn bootstrap(engine: &Engine, cfg: &NodeConfig) -> Result<()> {
    let ctx = engine.ctx;
    let paths = &ctx.paths;
    ensure!(!crate::sys::net::listening(&paths.system_root, 80, true), "{PORT80_BUSY}");
    let facts = NginxFacts::detect(ctx)?;
    let text = frontend::render_for(paths, cfg, &facts, WebPhase::Bootstrap)?
        .ok_or_else(|| Error::msg("订阅未使用独立 HTTPS 入口"))?;
    frontend::install_web_conf(ctx, &frontend::test_conf(ctx, &text)?)?;
    let bin = nginx::binary_with(ctx, engine.env)?;
    let services = engine.services();
    services.write(&ServiceDef::subscription_web(paths, &bin))?;
    services.restart(WEB_SERVICE)?;
    services.wait_running(WEB_SERVICE, WAIT_RUNNING)
}

/// configure-services (module docs).
pub fn configure_services(engine: &Engine, cfg: &NodeConfig) -> Result<()> {
    let ctx = engine.ctx;
    let paths = &ctx.paths;
    let services = engine.services();
    let Some(sub) = &cfg.subscription else {
        services.remove(WEB_SERVICE)?;
        frontend::remove_conf(paths)?;
        return services.remove(SERVICE);
    };
    let worker = ServiceDef::subscription(paths);
    if matches!(sub.mode, SubscriptionMode::Standalone { .. }) {
        let bin = nginx::binary_with(ctx, engine.env)?;
        return services.write_all(&[worker, ServiceDef::subscription_web(paths, &bin)]);
    }
    services.remove(WEB_SERVICE)?;
    frontend::remove_conf(paths)?;
    services.write(&worker)
}

/// publish-subscription (module docs).
pub fn publish(engine: &Engine, cfg: &NodeConfig, spec: &NodeSpec) -> Result<()> {
    let ctx = engine.ctx;
    let paths = &ctx.paths;
    let services = engine.services();
    let Some(listener) = Listener::of(cfg) else {
        return unpublish(&services, paths);
    };
    check_subscription_family(cfg, ipv6(paths))?;
    let published = snapshot::render(spec)?;
    snapshot::write(paths, &published)?;
    let previous = server::recorded(paths).ok().flatten();
    server::record(paths, listener)?;
    let standalone = frontend::standalone(cfg).is_some();
    if standalone {
        let text = frontend::render_web_conf(ctx, cfg)?
            .ok_or_else(|| Error::msg("订阅未使用独立 HTTPS 入口"))?;
        frontend::install_text(ctx, &text)?;
    } else {
        services.remove(WEB_SERVICE)?;
        frontend::remove_conf(paths)?;
    }
    if !services.exists(SERVICE) {
        services.write(&ServiceDef::subscription(paths))?;
    }
    let restart = previous != Some(listener) || !worker_is_current(&services, paths);
    run_worker(&services, paths, listener, restart)?;
    if standalone {
        start_web(engine, &services)?;
    }
    Ok(())
}

/// Subscription off: no services, no snapshot (its credentials included).
fn unpublish(services: &Services, paths: &Paths) -> Result<()> {
    services.remove(WEB_SERVICE)?;
    services.remove(SERVICE)?;
    frontend::remove_conf(paths)?;
    snapshot::remove(paths)?;
    server::forget(paths)
}

/// Start the worker (or restart it when `restart` and it runs), enable it,
/// and wait until it accepts connections on `listener`.
fn run_worker(services: &Services, paths: &Paths, listener: Listener, restart: bool) -> Result<()> {
    if !services.running(SERVICE) {
        services.start(SERVICE)?;
    } else if restart {
        services.restart(SERVICE)?;
    }
    services.enable(SERVICE)?;
    services.wait_running(SERVICE, WAIT_RUNNING)?;
    wait_listening(paths, listener, LISTEN_WAIT)
}

/// The standalone nginx after the apply stopped it: restart, enable, wait.
fn start_web(engine: &Engine, services: &Services) -> Result<()> {
    if !services.exists(WEB_SERVICE) {
        let bin = nginx::binary_with(engine.ctx, engine.env)?;
        services.write(&ServiceDef::subscription_web(&engine.ctx.paths, &bin))?;
    }
    services.restart(WEB_SERVICE)?;
    services.enable(WEB_SERVICE)?;
    services.wait_running(WEB_SERVICE, WAIT_RUNNING)
}

/// Whether the running worker executes the installed `EXE` (same device
/// and inode as `/proc/PID/exe`). A self-update replaces `EXE` with a new
/// file, so an old worker then points at the old, unlinked inode.
pub fn worker_is_current(services: &Services, paths: &Paths) -> bool {
    match services.main_pid(SERVICE) {
        Ok(Some(pid)) => same_file(&paths.system(&format!("/proc/{pid}/exe")), &paths.executable),
        _ => false,
    }
}

fn same_file(a: &Path, b: &Path) -> bool {
    match (std::fs::metadata(a), std::fs::metadata(b)) {
        (Ok(x), Ok(y)) => x.dev() == y.dev() && x.ino() == y.ino(),
        _ => false,
    }
}

/// Poll until the worker accepts connections on `listener`: the TCP port
/// is in LISTEN state, or the socket accepts a connection.
pub fn wait_listening(paths: &Paths, listener: Listener, timeout: Duration) -> Result<()> {
    let deadline = Instant::now() + timeout;
    loop {
        if listening(paths, listener) {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(Error::msg(format!(
                "{SERVICE} 未能在 {listener} 上开始监听，请查看 onebox service {SERVICE} log"
            )));
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn listening(paths: &Paths, listener: Listener) -> bool {
    match listener {
        Listener::Tcp { port } => crate::sys::net::listening(&paths.system_root, port, true),
        Listener::Unix => {
            std::os::unix::net::UnixStream::connect(paths.subscription_socket()).is_ok()
        }
    }
}

#[cfg(test)]
mod tests;
