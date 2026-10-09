//! nginx in front of the worker's unix socket (spec G §3.5): the `/sub/`
//! location (shared by the site and the standalone instance) and the
//! standalone `onebox-subscription-web` configuration
//! (`ROOT/subscription/nginx.conf`, prefix `ROOT/subscription`).
//!
//! The standalone config has a TLS server on the configured port and, for
//! HTTP-01 certificates, a port-80 server for the ACME webroot. Its
//! bootstrap variant is that port-80 server alone (before the certificate
//! exists).
//!
//! Staging (K7): the apply engine renders the full config with
//! [`render_web_conf`] in check-configurations, stages and `nginx -t`-tests
//! it inside its journal directory, and installs exactly that file with
//! [`install_web_conf`] before the publish stage, which only checks that it
//! is there. The one other staged file is the prepare-certificates
//! bootstrap's `nginx.conf.new` ([`test_conf`]), installed the same way.
//!
//! Changes from v2:
//! - temp paths (and the pid file) live under the persistent
//!   `ROOT/subscription` instead of `/run/onebox/nginx-subscription`, which
//!   vanished at reboot (G19);
//! - the port-80 server answers for any `Host` (`server_name _`): it also
//!   serves the proxy certificate's HTTP-01 challenges (ARCH §10);
//! - ip mode has no nginx: the worker listens on TCP itself (G13);
//! - the worker's `Cache-Control`/`Referrer-Policy`/`X-Content-Type-Options`
//!   headers are hidden behind nginx's own (v2 sent each twice, G-8.1#19);
//! - nginx ≥ 1.25.1 gets `listen … ssl;` + `http2 on;` (G-8.1#20).

use crate::ctx::Ctx;
use crate::domain::config::{NodeConfig, SubscriptionMode, WebCert};
use crate::error::{Error, Result};
use crate::host::nginx::{self, Worker};
use crate::paths::Paths;
use crate::site::nginx_conf::{quote_path, temp_paths};
use crate::site::{NginxFacts, SiteSubscription};
use crate::sys::fs::{atomic_write, read_bounded, remove_file_if_exists};
use crate::sys::text::valid_domain;
use std::path::{Path, PathBuf};

/// Longest unix socket path the worker binds (`sun_path` is 108 bytes).
pub const SOCKET_PATH_MAX: usize = 100;
const CONF_MAX: u64 = 1024 * 1024;
/// The acme location of the port-80 server, without the root (to detect it
/// in an installed config).
const ACME_LOCATION: &str = "location ^~ /.well-known/acme-challenge/ { root ";

/// Which standalone config to render.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WebPhase {
    /// Only the port-80 ACME server (HTTP-01 before the certificate exists).
    Bootstrap,
    Full,
}

/// Inputs of the standalone renderer.
#[derive(Clone, Debug)]
pub struct WebConf<'a> {
    pub worker: &'a Worker,
    pub http2_directive: bool,
    pub ipv6: bool,
    /// `ROOT/subscription`: prefix, pid, temp paths, `tls/`.
    pub sub_dir: &'a Path,
    pub acme_root: &'a Path,
    pub domain: &'a str,
    pub port: u16,
    /// Render the port-80 HTTP-01 server.
    pub http01: bool,
    pub location: &'a str,
    pub phase: WebPhase,
}

/// The `/sub/` location proxying to the worker socket (v2 text plus the
/// header hiding, see the module docs). Refuses socket paths nginx cannot
/// take inside `proxy_pass "…"`.
pub fn location_block(paths: &Paths) -> Result<String> {
    let socket = paths.subscription_socket();
    let socket = socket
        .to_str()
        .ok_or_else(|| Error::msg("订阅 socket 路径含不支持的字符"))?;
    let uri = format!("http://unix:{socket}:");
    let unsafe_char = |c: char| matches!(c, '"' | '$' | '\\') || c.is_control();
    ensure!(!uri.contains(unsafe_char), "订阅 socket 路径含不支持的字符");
    Ok(format!(
        r#"location ^~ /sub/ {{
        access_log off; error_log /dev/null crit;
        limit_except GET {{ deny all; }}
        proxy_pass "{uri}";
        proxy_http_version 1.1; proxy_set_header Connection "";
        proxy_buffering off; proxy_request_buffering off; proxy_cache off;
        proxy_hide_header Cache-Control; proxy_hide_header Referrer-Policy; proxy_hide_header X-Content-Type-Options;
        proxy_connect_timeout 3s; proxy_read_timeout 10s;
        add_header Cache-Control "private, no-store" always;
        add_header Referrer-Policy "no-referrer" always;
        add_header X-Content-Type-Options "nosniff" always;
    }}"#
    ))
}

/// The socket path is usable by both the worker and nginx.
pub fn check_socket_path(paths: &Paths) -> Result<()> {
    let socket = paths.subscription_socket();
    let len = socket.as_os_str().len();
    ensure!(len <= SOCKET_PATH_MAX, "订阅 Unix socket 路径过长");
    location_block(paths).map(|_| ())
}

/// The location block for the site nginx in site mode, else `None`. The
/// socket path was validated by the prepare stage
/// ([`check_socket_path`]); an unusable path yields `None` here.
pub fn site_location(paths: &Paths, cfg: &NodeConfig) -> Option<SiteSubscription> {
    let site_mode = matches!(
        cfg.subscription.as_ref().map(|s| &s.mode),
        Some(SubscriptionMode::Site)
    );
    if !site_mode || cfg.site_active().is_none() {
        return None;
    }
    location_block(paths)
        .ok()
        .map(|location_block| SiteSubscription { location_block })
}

/// The standalone settings of `cfg`, if that is its mode.
pub fn standalone(cfg: &NodeConfig) -> Option<(&str, &WebCert, bool, u16)> {
    let sub = cfg.subscription.as_ref()?;
    match &sub.mode {
        SubscriptionMode::Standalone {
            domain,
            cert,
            http01_port80,
        } => Some((domain.as_str(), cert, *http01_port80, sub.port)),
        _ => None,
    }
}

/// Render the standalone config.
pub fn render(c: &WebConf) -> Result<String> {
    ensure!(valid_domain(c.domain), "订阅域名无效");
    ensure!(c.port != 0, "订阅端口无效");
    let mut out = header(c)?;
    if c.http01 {
        out.push_str(&acme_server(c)?);
    }
    if c.phase == WebPhase::Full {
        out.push_str(&tls_server(c)?);
    }
    out.push_str("}\n");
    Ok(out)
}

fn header(c: &WebConf) -> Result<String> {
    Ok(format!(
        "user {};\nworker_processes 1;\npid {};\nerror_log /dev/null crit;\n\
         events {{ worker_connections 256; }}\nhttp {{ {}\n\
         access_log off; server_tokens off; default_type text/plain; client_max_body_size 1k; keepalive_timeout 10;\n",
        c.worker,
        quote_path(&c.sub_dir.join("nginx.pid"))?,
        temp_paths(c.sub_dir)?,
    ))
}

fn acme_server(c: &WebConf) -> Result<String> {
    let listen6 = if c.ipv6 { "listen [::]:80;" } else { "" };
    Ok(format!(
        "server {{ listen 80; {listen6} server_name _;\n\
         {ACME_LOCATION}{}; try_files $uri =404; }}\n\
         location / {{ return 404; }}\n}}\n",
        quote_path(c.acme_root)?,
    ))
}

fn tls_server(c: &WebConf) -> Result<String> {
    let listen = ssl_listen(&c.port.to_string(), c);
    let listen6 = if c.ipv6 {
        ssl_listen(&format!("[::]:{}", c.port), c)
    } else {
        String::new()
    };
    let http2 = if c.http2_directive { "http2 on; " } else { "" };
    let tls = c.sub_dir.join("tls");
    Ok(format!(
        "server {{ {listen} {listen6} {http2}server_name {};\n\
         ssl_certificate {}; ssl_certificate_key {}; ssl_protocols TLSv1.2 TLSv1.3;\n\
         {}\nlocation / {{ return 404; }}\n}}\n",
        c.domain,
        quote_path(&tls.join("cert.pem"))?,
        quote_path(&tls.join("key.pem"))?,
        c.location,
    ))
}

/// `listen ADDR ssl http2;` (old nginx) or `listen ADDR ssl;` (new).
fn ssl_listen(addr: &str, c: &WebConf) -> String {
    if c.http2_directive {
        format!("listen {addr} ssl;")
    } else {
        format!("listen {addr} ssl http2;")
    }
}

/// The standalone config of `cfg` for `phase` with explicit nginx facts;
/// `None` unless the subscription is standalone.
pub fn render_for(
    paths: &Paths,
    cfg: &NodeConfig,
    facts: &NginxFacts,
    phase: WebPhase,
) -> Result<Option<String>> {
    let Some((domain, _, http01, port)) = standalone(cfg) else {
        return Ok(None);
    };
    let location = location_block(paths)?;
    let sub_dir = paths.subscription();
    let acme_root = paths.subscription_acme();
    render(&WebConf {
        worker: &facts.worker,
        http2_directive: facts.http2_directive,
        ipv6: facts.ipv6,
        sub_dir: &sub_dir,
        acme_root: &acme_root,
        domain,
        port,
        http01,
        location: &location,
        phase,
    })
    .map(Some)
}

/// check-configurations: the full standalone config (`None` in ip and site
/// mode or when the subscription is off). Detects the nginx facts.
pub fn render_web_conf(ctx: &Ctx, cfg: &NodeConfig) -> Result<Option<String>> {
    if standalone(cfg).is_none() {
        return Ok(None);
    }
    render_for(&ctx.paths, cfg, &NginxFacts::detect(ctx)?, WebPhase::Full)
}

/// `ROOT/subscription/nginx.conf`, the file `onebox-subscription-web` runs.
pub fn conf_file(paths: &Paths) -> PathBuf {
    paths.subscription().join("nginx.conf")
}

/// Whether a standalone config is installed (a regular file, not a link).
pub fn conf_installed(paths: &Paths) -> bool {
    std::fs::symlink_metadata(conf_file(paths)).is_ok_and(|m| m.is_file())
}

/// Where the prepare-certificates bootstrap stages its config (the apply
/// engine stages the full config in its journal directory instead).
pub fn staged_conf(paths: &Paths) -> PathBuf {
    paths.subscription().join("nginx.conf.new")
}

/// Write `text` as [`staged_conf`] (0600) and `nginx -t` it; the staged
/// file is removed when the test fails.
pub fn test_conf(ctx: &Ctx, text: &str) -> Result<PathBuf> {
    let staged = staged_conf(&ctx.paths);
    crate::sys::fs::ensure_dir(&ctx.paths.subscription(), 0o700)?;
    atomic_write(&staged, text.as_bytes(), 0o600)?;
    if let Err(e) = nginx::test(ctx, &ctx.paths.subscription(), &staged) {
        let _ = remove_file_if_exists(&staged);
        return Err(e);
    }
    Ok(staged)
}

/// Copy a tested config to `nginx.conf` (atomic, 0600). The bootstrap's
/// [`staged_conf`] is removed afterwards; the engine's staged copy lives in
/// its journal directory and goes away with it.
pub fn install_web_conf(ctx: &Ctx, tested: &Path) -> Result<()> {
    let bytes = read_bounded(tested, CONF_MAX)?;
    atomic_write(&conf_file(&ctx.paths), &bytes, 0o600)?;
    if tested == staged_conf(&ctx.paths) {
        remove_file_if_exists(tested)?;
    }
    Ok(())
}

/// Remove the standalone config and its staged copy (ip and site mode).
pub fn remove_conf(paths: &Paths) -> Result<()> {
    remove_file_if_exists(&staged_conf(paths))?;
    remove_file_if_exists(&conf_file(paths))?;
    Ok(())
}

/// Whether the installed config has the port-80 server for the ACME
/// webroot (so a running instance already answers HTTP-01).
pub fn installed_serves_acme(paths: &Paths) -> bool {
    let Ok(acme) = quote_path(&paths.subscription_acme()) else {
        return false;
    };
    let needle = format!("{ACME_LOCATION}{acme};");
    read_bounded(&conf_file(paths), CONF_MAX)
        .is_ok_and(|b| String::from_utf8_lossy(&b).contains(&needle))
}

#[cfg(test)]
mod tests;
