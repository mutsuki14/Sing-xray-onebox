//! What other modules call: the apply engine's certificate stage
//! ([`prepare_proxy`], [`prepare_web`]), FRP ([`issue_domains`],
//! [`renew_dir`]), `cert info` / `doctor` ([`status`]) and the finalize
//! stage's cron decision ([`renew_needed`]).
//!
//! None of these prompt: Cloudflare credentials come in as
//! `Option<&CfCredentials>` (resolved by the CLI) or from what is stored for
//! the directory. The apply engine opens the temporary `acme` firewall owner
//! itself around certificate work (G21).

use super::engine::{Engine, RenewKind};
use super::method::{CertSpec, Challenge, MethodId, Source};
use super::openssl::{self, Trust};
use super::store::{self, CertDir, CertStatus, Metadata};
use super::{CfCredentials, PUBLIC_REQUIRED};
use crate::ctx::Ctx;
use crate::domain::config::{AcmeMethod, NodeConfig, ProxyCertMode, SubscriptionMode, WebCert};
use crate::domain::defaults::RENEWAL_WINDOW_SECS;
use crate::domain::ports::{proxy_http01_responder, Http01Responder};
use crate::error::{Error, Result};
use crate::host::service::{SITE, SUBSCRIPTION_WEB};
use crate::paths::Paths;
use std::path::{Path, PathBuf};

/// A public web endpoint's certificate (site, standalone subscription).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WebCertTarget<'a> {
    /// Certificate directory (`ROOT/site`, `ROOT/subscription/tls`).
    pub dir: PathBuf,
    pub domains: Vec<String>,
    pub cert: &'a WebCert,
    /// HTTP-01 webroot served by a running Onebox nginx; `None` = the
    /// built-in responder (tokens in `<dir>/acme/http01`).
    pub webroot: Option<PathBuf>,
}

/// Whether the node needs the renewal cron line (finalize, G17).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum RenewNeed {
    /// Self-signed only (or no certificate): nothing to schedule.
    None,
    /// A custom certificate: renewal redeploys refreshed sources.
    Recommended,
    /// An ACME certificate expires without renewal.
    Required,
}

/// The ACME webroot of the standalone subscription's port-80 server
/// (v2 `subscription::acme_root`: a sibling of the site root).
pub fn subscription_acme_root(paths: &Paths) -> PathBuf {
    paths.site_root.with_file_name("onebox-subscription-acme")
}

/// Proxy certificate stage: bring `ROOT/tls` to the configured mode
/// (self-signed: generate when missing, renamed or invalid; ACME: issue
/// when missing or renamed, renew when due or forced; custom: validate and
/// deploy the sources), then record public trust on `cfg`. Returns whether
/// the deployed pair changed.
pub fn prepare_proxy(
    ctx: &Ctx,
    cfg: &mut NodeConfig,
    force_renew: bool,
    cf: Option<&CfCredentials>,
) -> Result<bool> {
    prepare_proxy_with(&Engine::system(ctx), cfg, force_renew, cf)
}

/// [`prepare_proxy`] with an explicit engine.
pub fn prepare_proxy_with(
    engine: &Engine,
    cfg: &mut NodeConfig,
    force_renew: bool,
    cf: Option<&CfCredentials>,
) -> Result<bool> {
    let dir = CertDir::proxy(&engine.ctx.paths);
    let Some(spec) = proxy_spec(engine, cfg, &dir) else {
        return Ok(false);
    };
    let changed = engine.ensure(&dir, &spec, force_renew, cf)?;
    let trusted = openssl::publicly_trusted(engine.ctx, &dir.cert(), &dir.key(), spec.primary());
    if let Some(tls) = cfg.tls.as_mut() {
        tls.record_trust(trusted);
    }
    Ok(changed)
}

/// What `ROOT/tls` must hold for `cfg` (`None` without a proxy certificate).
pub fn proxy_spec(engine: &Engine, cfg: &NodeConfig, dir: &CertDir) -> Option<CertSpec> {
    let tls = cfg.tls.as_ref().filter(|_| cfg.needs_cert())?;
    let name = tls.mode.server_name().to_owned();
    let (source, trust) = match &tls.mode {
        ProxyCertMode::SelfSigned { .. } => (Source::SelfSigned, Trust::Pinned),
        ProxyCertMode::Acme { method, .. } => {
            let challenge = match method {
                AcmeMethod::Http01 => proxy_challenge(engine, cfg, dir),
                AcmeMethod::Cloudflare => Challenge::Cloudflare,
            };
            (Source::Acme(challenge), Trust::Public)
        }
        ProxyCertMode::Custom { cert, key, .. } => (
            Source::Custom {
                cert: cert.clone(),
                key: key.clone(),
            },
            Trust::Pinned,
        ),
    };
    Some(CertSpec {
        domains: vec![name],
        source,
        trust,
    })
}

/// Who answers the proxy's HTTP-01 challenge (`proxy_http01_responder`):
/// the Onebox nginx owning port 80 when it runs, else the built-in
/// responder serving that nginx's webroot (or the directory's own).
fn proxy_challenge(engine: &Engine, cfg: &NodeConfig, dir: &CertDir) -> Challenge {
    let paths = &engine.ctx.paths;
    match proxy_http01_responder(cfg) {
        Some(Http01Responder::Site) => served_by(engine, SITE, paths.site_root.clone()),
        Some(Http01Responder::Subscription) => {
            served_by(engine, SUBSCRIPTION_WEB, subscription_acme_root(paths))
        }
        _ => Challenge::Responder(dir.responder_webroot()),
    }
}

/// `webroot` through `service`'s nginx while it runs, else the responder.
pub fn served_by(engine: &Engine, service: &str, webroot: PathBuf) -> Challenge {
    if engine.services().running(service) {
        Challenge::Webroot(webroot)
    } else {
        Challenge::Responder(webroot)
    }
}

/// A web endpoint's spec: `http01` answers HTTP-01 challenges, custom pairs
/// must verify with `custom_trust`.
pub fn web_spec(
    domains: &[String],
    cert: &WebCert,
    http01: Challenge,
    custom_trust: Trust,
) -> CertSpec {
    let (source, trust) = match cert {
        WebCert::Http01 => (Source::Acme(http01), Trust::Public),
        WebCert::Cloudflare => (Source::Acme(Challenge::Cloudflare), Trust::Public),
        WebCert::Custom { cert, key } => (
            Source::Custom {
                cert: cert.clone(),
                key: key.clone(),
            },
            custom_trust,
        ),
    };
    CertSpec {
        domains: domains.to_vec(),
        source,
        trust,
    }
}

/// `webroot` through an nginx, or the responder with the directory's own.
fn http01_challenge(dir: &CertDir, webroot: Option<&Path>) -> Challenge {
    match webroot {
        Some(w) => Challenge::Webroot(w.to_path_buf()),
        None => Challenge::Responder(dir.responder_webroot()),
    }
}

/// Site / standalone subscription certificate stage (publicly trusted
/// certificates only). Returns whether the deployed pair changed.
pub fn prepare_web(
    ctx: &Ctx,
    target: WebCertTarget,
    force_renew: bool,
    cf: Option<&CfCredentials>,
) -> Result<bool> {
    prepare_web_with(&Engine::system(ctx), target, force_renew, cf)
}

/// [`prepare_web`] with an explicit engine.
pub fn prepare_web_with(
    engine: &Engine,
    target: WebCertTarget,
    force_renew: bool,
    cf: Option<&CfCredentials>,
) -> Result<bool> {
    let dir = CertDir::new(&target.dir);
    let http01 = http01_challenge(&dir, target.webroot.as_deref());
    let spec = web_spec(&target.domains, target.cert, http01, Trust::Public);
    engine
        .ensure(&dir, &spec, force_renew, cf)
        .map_err(|e| explain_untrusted(engine, &spec, e))
}

/// A custom web pair that is fine except for public trust gets the
/// "needs a real certificate" message (self-signed or private CA).
fn explain_untrusted(engine: &Engine, spec: &CertSpec, error: Error) -> Error {
    let Source::Custom { cert, key } = &spec.source else {
        return error;
    };
    let pinned_ok = openssl::validate_pair(engine.ctx, cert, key, spec.primary(), Trust::Pinned);
    let public_ok = openssl::publicly_trusted(engine.ctx, cert, key, spec.primary());
    if pinned_ok.is_ok() && !public_ok {
        error.wrap(PUBLIC_REQUIRED)
    } else {
        error
    }
}

/// The deployed web pair of `target` is publicly valid for 30 more days
/// (no ACME call would be needed): the site starts a bootstrap nginx for
/// HTTP-01 only when this is false.
pub fn web_cert_ready(ctx: &Ctx, target: &WebCertTarget) -> bool {
    store::valid_for(
        ctx,
        &CertDir::new(&target.dir),
        &target.domains,
        Trust::Public,
        RENEWAL_WINDOW_SECS,
    )
}

/// FRP web certificate: issue or deploy for `domains` (≤ 32, wildcards via
/// DNS or custom) unless the deployed pair already matches. Custom pairs
/// may use a private CA (v2 parity). Returns whether the pair changed.
pub fn issue_domains(
    ctx: &Ctx,
    dir: &Path,
    domains: &[String],
    cert: &WebCert,
    webroot: Option<&Path>,
    cf: Option<&CfCredentials>,
) -> Result<bool> {
    let engine = Engine::system(ctx);
    let cert_dir = CertDir::new(dir);
    let http01 = http01_challenge(&cert_dir, webroot);
    let spec = web_spec(domains, cert, http01, Trust::Pinned);
    engine.ensure(&cert_dir, &spec, false, cf)
}

/// Renew the certificate recorded in `dir`'s metadata (FRP): only when
/// due unless `force`. Returns whether the deployed pair changed.
pub fn renew_dir(ctx: &Ctx, dir: &Path, force: bool, cf: Option<&CfCredentials>) -> Result<bool> {
    renew_dir_with(&Engine::system(ctx), dir, force, cf)
}

/// [`renew_dir`] with an explicit engine.
pub fn renew_dir_with(
    engine: &Engine,
    dir: &Path,
    force: bool,
    cf: Option<&CfCredentials>,
) -> Result<bool> {
    let cert_dir = CertDir::new(dir);
    let metadata = cert_dir
        .metadata()?
        .ok_or_else(|| Error::msg(format!("证书尚未签发: {}", dir.display())))?;
    let spec = spec_from_metadata(&cert_dir, &metadata)?;
    if !force && !engine.due(&cert_dir, &spec)? {
        return Ok(false);
    }
    let kind = if force {
        RenewKind::Forced
    } else {
        RenewKind::Scheduled
    };
    engine.renew(&cert_dir, &spec, kind, cf)
}

/// The spec a directory's recorded metadata describes.
pub fn spec_from_metadata(dir: &CertDir, m: &Metadata) -> Result<CertSpec> {
    let missing = |text: &str| Error::msg(text.to_owned());
    let (source, trust) = match m.method {
        MethodId::SelfSigned => (Source::SelfSigned, Trust::Pinned),
        MethodId::Http => {
            let webroot = m
                .webroot
                .clone()
                .ok_or_else(|| missing("HTTP 验证缺少网站目录"))?;
            (Source::Acme(Challenge::Webroot(webroot)), Trust::Public)
        }
        MethodId::Standalone => {
            let webroot = m.webroot.clone().unwrap_or_else(|| dir.responder_webroot());
            (Source::Acme(Challenge::Responder(webroot)), Trust::Public)
        }
        MethodId::Cloudflare => (Source::Acme(Challenge::Cloudflare), Trust::Public),
        MethodId::Custom => (
            Source::Custom {
                cert: m
                    .source_cert
                    .clone()
                    .ok_or_else(|| missing("未记录外部证书路径"))?,
                key: m
                    .source_key
                    .clone()
                    .ok_or_else(|| missing("未记录外部私钥路径"))?,
            },
            Trust::Pinned,
        ),
    };
    Ok(CertSpec {
        domains: m.domains.clone(),
        source,
        trust,
    })
}

/// `cert info` / `doctor` facts of a directory (`None`: no certificate).
pub fn status(ctx: &Ctx, dir: &Path) -> Result<Option<CertStatus>> {
    store::status(ctx, &CertDir::new(dir))
}

/// Whether the configuration needs scheduled renewals: ACME anywhere →
/// required, a custom certificate → recommended, else none.
pub fn renew_needed(cfg: &NodeConfig) -> RenewNeed {
    let web = |cert: &WebCert| match cert {
        WebCert::Http01 | WebCert::Cloudflare => RenewNeed::Required,
        WebCert::Custom { .. } => RenewNeed::Recommended,
    };
    let proxy = cfg
        .tls
        .as_ref()
        .filter(|_| cfg.needs_cert())
        .map_or(RenewNeed::None, |t| match t.mode {
            ProxyCertMode::SelfSigned { .. } => RenewNeed::None,
            ProxyCertMode::Acme { .. } => RenewNeed::Required,
            ProxyCertMode::Custom { .. } => RenewNeed::Recommended,
        });
    let site = cfg.site_active().map_or(RenewNeed::None, |s| web(&s.cert));
    let subscription = match cfg.subscription.as_ref().map(|s| &s.mode) {
        Some(SubscriptionMode::Standalone { cert, .. }) => web(cert),
        _ => RenewNeed::None,
    };
    proxy.max(site).max(subscription)
}

#[cfg(test)]
mod tests;
