//! Pure renderer of the site's `nginx.conf` (F §3.7), byte-compatible with
//! v2's three variants:
//! - **bootstrap**: only the port-80 server (ACME webroot, everything else
//!   `404`), so HTTP-01 can run before the certificate exists;
//! - **deferred**: port 80 redirects to HTTPS, plus the TLS 1.3-only
//!   internal listener `127.0.0.1:{internal_port}` (the REALITY target);
//! - **full**: deferred plus the public TCP 443 front-end when the HTTPS
//!   entrance is on and no REALITY inbound already holds TCP 443.
//!
//! IPv6 adds `listen [::]:80;` / `listen [::]:443 …;`. A subscription
//! served through the site inserts its `location` block into both TLS
//! servers and switches the error log to `/dev/null crit` (tokens are in
//! URLs and must never reach a log, G20).
//!
//! Changes from v2:
//! - temp paths live under the persistent site directory
//!   (`ROOT/site/{client_body,proxy,fastcgi,uwsgi,scgi}_temp`, created by
//!   the nginx master itself) instead of `/run/onebox/nginx-site`, which
//!   vanished at reboot and broke startup (F-8.1#2). Workers never write
//!   them: static files read no request body and every proxied location
//!   turns buffering off;
//! - nginx ≥ 1.25.1 gets `listen … ssl;` + `http2 on;` instead of the
//!   deprecated `listen … ssl http2` (F-8.1#23); older nginx keeps v2's
//!   bytes exactly;
//! - the domain is re-validated before it is interpolated.

use crate::error::{Error, Result};
use crate::host::nginx::Worker;
use crate::sys::text::valid_domain;
use std::path::Path;

/// Which configuration variant to render (see the module docs).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SitePhase {
    Bootstrap,
    Deferred,
    Full,
}

/// Every input of the renderer.
#[derive(Clone, Debug)]
pub struct SiteConf<'a> {
    pub worker: &'a Worker,
    pub domain: &'a str,
    pub internal_port: u16,
    /// Public HTTPS port the port-80 redirect points to.
    pub public_port: u16,
    pub ipv6: bool,
    /// nginx ≥ 1.25.1: `http2 on;` style.
    pub http2_directive: bool,
    /// `ROOT/site`: pid, error log, temp paths, certificate.
    pub site_dir: &'a Path,
    pub site_root: &'a Path,
    pub phase: SitePhase,
    /// CA bundle for the public front-end; the front-end is rendered only
    /// in the full phase and only when this is `Some`.
    pub frontend_ca: Option<&'a Path>,
    /// The subscription's `location` block (without trailing newline).
    pub subscription: Option<&'a str>,
}

/// nginx-quoted path: `"…"` with `\`, `"`, `$` escaped; control characters
/// are refused (v2 `quote_path`).
pub fn quote_path(path: &Path) -> Result<String> {
    let text = path
        .to_str()
        .ok_or_else(|| Error::msg("路径不是有效的 UTF-8"))?;
    if text.chars().any(char::is_control) {
        return Err(Error::msg("路径含控制字符"));
    }
    Ok(format!(
        "\"{}\"",
        text.replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('$', "\\$")
    ))
}

/// The five temp-path directives (one per line, each ending in `\n`).
pub fn temp_paths(dir: &Path) -> Result<String> {
    let mut lines = String::new();
    for kind in ["client_body", "proxy", "fastcgi", "uwsgi", "scgi"] {
        let path = quote_path(&dir.join(format!("{kind}_temp")))?;
        lines.push_str(&format!("{kind}_temp_path {path};\n"));
    }
    Ok(lines)
}

/// Render `nginx.conf`.
pub fn render(c: &SiteConf) -> Result<String> {
    if !valid_domain(c.domain) {
        return Err(Error::msg("网站域名无效"));
    }
    let mut out = header(c)?;
    out.push_str(&http80(c)?);
    if c.phase != SitePhase::Bootstrap {
        out.push_str(&internal(c)?);
        if let Some(ca) = c.frontend_ca.filter(|_| c.phase == SitePhase::Full) {
            out.push_str(&frontend(c, ca)?);
        }
    }
    out.push_str("}\n");
    Ok(out)
}

fn header(c: &SiteConf) -> Result<String> {
    let error_log = match c.subscription {
        Some(_) => "/dev/null crit".to_owned(),
        None => format!("{} warn", quote_path(&c.site_dir.join("error.log"))?),
    };
    Ok(format!(
        "user {};\nworker_processes 1;\npid {};\nerror_log {error_log};\n\
         events {{ worker_connections 512; }}\nhttp {{\n{}\n\
         access_log off; server_tokens off; charset utf-8; default_type application/octet-stream;\n\
         types {{ text/html html htm; text/css css; application/javascript js; image/png png; \
         image/jpeg jpg jpeg; image/svg+xml svg; text/plain txt; }}\n\
         sendfile on; keepalive_timeout 20; client_max_body_size 1m;\n",
        c.worker,
        quote_path(&c.site_dir.join("nginx.pid"))?,
        temp_paths(c.site_dir)?,
    ))
}

fn http80(c: &SiteConf) -> Result<String> {
    let listen6 = if c.ipv6 { "listen [::]:80;" } else { "" };
    let fallback = match c.phase {
        SitePhase::Bootstrap => "return 404;".to_owned(),
        _ => {
            let suffix = match c.public_port {
                443 => String::new(),
                port => format!(":{port}"),
            };
            format!("return 301 https://{}{suffix}$request_uri;", c.domain)
        }
    };
    Ok(format!(
        "server {{ listen 80; {listen6} server_name {};\n\
         location ^~ /.well-known/acme-challenge/ {{ root {}; default_type text/plain; try_files $uri =404; }}\n\
         location / {{ {fallback} }}\n}}\n",
        c.domain,
        quote_path(c.site_root)?,
    ))
}

/// `listen ADDR ssl http2;` (old nginx) or `listen ADDR ssl;` (new).
fn ssl_listen(addr: &str, c: &SiteConf) -> String {
    if c.http2_directive {
        format!("listen {addr} ssl;")
    } else {
        format!("listen {addr} ssl http2;")
    }
}

/// `http2 on; ` before `server_name` for new nginx.
fn http2_on(c: &SiteConf) -> &'static str {
    if c.http2_directive {
        "http2 on; "
    } else {
        ""
    }
}

fn certificate(c: &SiteConf) -> Result<String> {
    Ok(format!(
        "ssl_certificate {}; ssl_certificate_key {};",
        quote_path(&c.site_dir.join("cert.pem"))?,
        quote_path(&c.site_dir.join("key.pem"))?,
    ))
}

fn internal(c: &SiteConf) -> Result<String> {
    let listen = ssl_listen(&format!("127.0.0.1:{}", c.internal_port), c);
    Ok(format!(
        "server {{ {listen} {}server_name {};\n\
         {} ssl_protocols TLSv1.3; ssl_ecdh_curve X25519:prime256v1;\n\
         absolute_redirect off; root {}; index index.html;\n\
         add_header X-Content-Type-Options nosniff always; add_header Referrer-Policy no-referrer always;\n\
         {}\nlocation ~ /\\. {{ deny all; }}\nlocation / {{ try_files $uri $uri/ =404; }}\n}}\n",
        http2_on(c),
        c.domain,
        certificate(c)?,
        quote_path(c.site_root)?,
        c.subscription.unwrap_or(""),
    ))
}

fn frontend(c: &SiteConf, ca: &Path) -> Result<String> {
    let listen = ssl_listen("443", c);
    let listen6 = if c.ipv6 {
        ssl_listen("[::]:443", c)
    } else {
        String::new()
    };
    let domain = c.domain;
    Ok(format!(
        "server {{ {listen} {listen6} {}server_name {domain};\n\
         {} ssl_protocols TLSv1.2 TLSv1.3;\n{}\n\
         location / {{ proxy_pass https://127.0.0.1:{}; proxy_ssl_server_name on; \
         proxy_ssl_name {domain}; proxy_ssl_verify on; proxy_ssl_trusted_certificate {}; \
         proxy_ssl_verify_depth 5; proxy_set_header Host {domain}; proxy_set_header Connection \"\"; \
         proxy_http_version 1.1; proxy_buffering off; proxy_request_buffering off; }}\n}}\n",
        http2_on(c),
        certificate(c)?,
        c.subscription.unwrap_or(""),
        c.internal_port,
        quote_path(ca)?,
    ))
}

#[cfg(test)]
mod tests;
