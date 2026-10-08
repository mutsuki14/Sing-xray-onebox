//! Own-domain REALITY website: a private nginx instance (`onebox-site`)
//! that is the REALITY handshake target on `127.0.0.1:{internal_port}`
//! (TLS 1.3 only), serves TCP 80 for HTTP-01 and the HTTPS redirect, and
//! optionally the public TCP 443 front-end; homepage templates and content
//! publishing ([`content`]); the config renderer ([`nginx_conf`]).
//!
//! Hooks for the apply engine (none of them prompts):
//! - [`prepare`] (prepare-certificates): directories and markers, content
//!   intent or default homepage, nginx installation, the service
//!   definition, a bootstrap config + start when HTTP-01 needs port 80
//!   before the certificate exists, then the site certificate;
//! - [`check`] (check-configurations): render the full config to the staged
//!   file `ROOT/site/nginx.conf.new` and `nginx -t` it (K7);
//! - [`apply`] (apply-website): install the tested file, write the unit,
//!   restart, enable, wait until running; or [`disable`] when the site is
//!   off (content and certificates stay).
//!
//! Changes from v2: nginx temp paths and pid are under the persistent
//! `ROOT/site` (F-8.1#2); the config is tested before any service stops and
//! later stages only install the tested bytes (K7); the site's error log is
//! off while it serves subscription URLs (G20); the CA bundle for the 443
//! front-end comes from [`ca_bundle`] (G35); content backups are pruned and
//! keep the generated-homepage marker (F-8.1#20).

pub mod content;
pub mod nginx_conf;
pub mod templates;

pub use content::{ContentBackup, ContentStore};
pub use nginx_conf::{quote_path, SiteConf, SitePhase};

use crate::cert::hooks::{prepare_web_with, web_cert_ready};
use crate::cert::{CertDir, CertStatus, CfCredentials, Engine, WebCertTarget};
use crate::ctx::Ctx;
use crate::domain::config::{NodeConfig, SiteConfig, WebCert};
use crate::error::{Error, Result};
use crate::host::nginx::{self, Worker};
use crate::host::os::EnvLookup;
use crate::host::service::{ServiceDef, WAIT_RUNNING};
use crate::paths::Paths;
use crate::sys::fs::{atomic_write, read_bounded, remove_file_if_exists};
use std::path::{Path, PathBuf};

/// The site's service name.
pub use crate::host::service::SITE as SERVICE;
/// System CA bundles, in lookup order (after `$SSL_CERT_FILE`).
pub const CA_BUNDLES: [&str; 4] = [
    "/etc/ssl/certs/ca-certificates.crt",
    "/etc/pki/tls/certs/ca-bundle.crt",
    "/etc/ssl/ca-bundle.pem",
    "/etc/ssl/cert.pem",
];
const CONF_MAX: u64 = 1024 * 1024;

/// A content change requested for this apply (`apply::Intents`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SiteContent {
    /// Publish the homepage rendered from the site settings.
    Template,
    /// Publish a local directory.
    Import(PathBuf),
    /// Restore a content backup by id, or `latest`.
    Restore(String),
}

/// The subscription's nginx `location` block when it is served through
/// the site (built by the subscription module).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SiteSubscription {
    pub location_block: String,
}

/// What [`prepare`] did.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SitePrepared {
    pub cert_changed: bool,
    /// Backup id of the replaced content (also recorded in the config).
    pub content_backup: Option<String>,
    /// A bootstrap nginx was started for HTTP-01.
    pub bootstrapped: bool,
}

/// nginx facts the renderer needs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NginxFacts {
    pub worker: Worker,
    pub http2_directive: bool,
    pub ipv6: bool,
}

impl NginxFacts {
    pub fn detect(ctx: &Ctx) -> Result<NginxFacts> {
        Ok(NginxFacts {
            worker: nginx::worker(ctx)?,
            http2_directive: nginx::version(ctx)?.supports_http2_directive(),
            ipv6: crate::sys::net::ipv6_available(&ctx.paths.system_root),
        })
    }
}

/// `ROOT/site/nginx.conf`, the file `onebox-site` runs with.
pub fn conf_file(paths: &Paths) -> PathBuf {
    paths.site().join("nginx.conf")
}

/// The staged, tested config of the current apply.
pub fn staged_conf(paths: &Paths) -> PathBuf {
    paths.site().join("nginx.conf.new")
}

/// The CA bundle the 443 front-end verifies its upstream with:
/// `$SSL_CERT_FILE` when it is a file, else the first distro bundle.
pub fn ca_bundle(paths: &Paths) -> Result<PathBuf> {
    ca_bundle_with(paths, &crate::host::os::process_env)
}

/// [`ca_bundle`] with an injected environment.
pub fn ca_bundle_with(paths: &Paths, env: EnvLookup) -> Result<PathBuf> {
    if let Some(file) = env("SSL_CERT_FILE").map(PathBuf::from) {
        if file.is_absolute() && file.is_file() {
            return Ok(file);
        }
    }
    CA_BUNDLES
        .iter()
        .find(|p| paths.system(p).is_file())
        .map(PathBuf::from)
        .ok_or_else(|| Error::msg("缺少系统 CA 证书包"))
}

fn active(cfg: &NodeConfig) -> Result<&SiteConfig> {
    cfg.site_active().ok_or_else(|| Error::msg("网站未启用"))
}

/// Whether the full config has the public 443 front-end.
pub fn uses_frontend(cfg: &NodeConfig) -> bool {
    cfg.site_active().is_some_and(|s| s.https_entry) && !cfg.reality_on_443()
}

/// Render the site config for `phase` (detects nginx facts and, for the
/// front-end, the CA bundle).
pub fn render_conf(
    ctx: &Ctx,
    cfg: &NodeConfig,
    sub: Option<&SiteSubscription>,
    phase: SitePhase,
) -> Result<String> {
    active(cfg)?;
    let facts = NginxFacts::detect(ctx)?;
    let ca = match phase == SitePhase::Full && uses_frontend(cfg) {
        true => Some(ca_bundle(&ctx.paths)?),
        false => None,
    };
    render_conf_with(&ctx.paths, cfg, sub, phase, &facts, ca.as_deref())
}

/// Pure [`render_conf`].
pub fn render_conf_with(
    paths: &Paths,
    cfg: &NodeConfig,
    sub: Option<&SiteSubscription>,
    phase: SitePhase,
    facts: &NginxFacts,
    ca: Option<&Path>,
) -> Result<String> {
    let site = active(cfg)?;
    let site_dir = paths.site();
    nginx_conf::render(&SiteConf {
        worker: &facts.worker,
        domain: &site.domain,
        internal_port: site.internal_port,
        public_port: cfg.site_public_port(),
        ipv6: facts.ipv6,
        http2_directive: facts.http2_directive,
        site_dir: &site_dir,
        site_root: &paths.site_root,
        phase,
        frontend_ca: ca.filter(|_| uses_frontend(cfg)),
        subscription: sub.map(|s| s.location_block.as_str()),
    })
}

/// Write `text` to the staged file (0600) and `nginx -t` it; the staged
/// file is removed when the test fails.
pub fn test_conf(ctx: &Ctx, text: &str) -> Result<PathBuf> {
    let staged = staged_conf(&ctx.paths);
    atomic_write(&staged, text.as_bytes(), 0o600)?;
    if let Err(e) = nginx::test(ctx, &ctx.paths.site(), &staged) {
        let _ = remove_file_if_exists(&staged);
        return Err(e);
    }
    Ok(staged)
}

/// Install a tested config as `ROOT/site/nginx.conf` (the staged file is
/// consumed).
pub fn install_conf(ctx: &Ctx, tested: &Path) -> Result<()> {
    let bytes = read_bounded(tested, CONF_MAX)?;
    atomic_write(&conf_file(&ctx.paths), &bytes, 0o600)?;
    if tested == staged_conf(&ctx.paths) {
        remove_file_if_exists(tested)?;
    }
    Ok(())
}

/// check-configurations: render the full config and test it as the staged
/// file. `None` when the site is off.
pub fn check(
    ctx: &Ctx,
    cfg: &NodeConfig,
    sub: Option<&SiteSubscription>,
) -> Result<Option<PathBuf>> {
    if cfg.site_active().is_none() {
        return Ok(None);
    }
    let text = render_conf(ctx, cfg, sub, SitePhase::Full)?;
    test_conf(ctx, &text).map(Some)
}

/// prepare-certificates (module docs). Records a content backup id in
/// `cfg.site.last_content_backup`.
pub fn prepare(
    ctx: &Ctx,
    cfg: &mut NodeConfig,
    content: Option<&SiteContent>,
    force_cert: bool,
    cf: Option<&CfCredentials>,
) -> Result<SitePrepared> {
    prepare_with(&Engine::system(ctx), cfg, content, force_cert, cf)
}

/// [`prepare`] with an explicit engine.
pub fn prepare_with(
    engine: &Engine,
    cfg: &mut NodeConfig,
    content: Option<&SiteContent>,
    force_cert: bool,
    cf: Option<&CfCredentials>,
) -> Result<SitePrepared> {
    let Some(site) = cfg.site_active().cloned() else {
        return Ok(SitePrepared::default());
    };
    let paths = &engine.ctx.paths;
    let store = ContentStore::new(paths);
    store.prepare()?;
    let content_backup = publish(&store, &site, content)?;
    if let (Some(id), Some(s)) = (&content_backup, cfg.site.as_mut()) {
        s.last_content_backup = Some(id.clone());
    }
    let bin = nginx::ensure_installed_with(engine.ctx, engine.env, crate::host::os::is_root())?;
    let services = engine.services();
    services.write(&ServiceDef::site(paths, &bin))?;
    let target = WebCertTarget {
        dir: paths.site(),
        domains: vec![site.domain.clone()],
        cert: &site.cert,
        webroot: Some(paths.site_root.clone()),
    };
    let needs_port80 = site.cert == WebCert::Http01
        && !services.running(SERVICE)
        && (force_cert || !web_cert_ready(engine.ctx, &target));
    if needs_port80 {
        bootstrap(engine, cfg)?;
    }
    let cert_changed = prepare_web_with(engine, target, force_cert, cf)?;
    Ok(SitePrepared {
        cert_changed,
        content_backup,
        bootstrapped: needs_port80,
    })
}

/// Apply the content intent, or make sure a homepage exists.
fn publish(
    store: &ContentStore,
    site: &SiteConfig,
    content: Option<&SiteContent>,
) -> Result<Option<String>> {
    let homepage = templates::homepage(site);
    Ok(match content {
        None => {
            store.ensure_default(&homepage)?;
            None
        }
        Some(SiteContent::Template) => Some(store.publish_template(&homepage)?),
        Some(SiteContent::Import(dir)) => Some(store.import(dir)?),
        Some(SiteContent::Restore(which)) => Some(store.restore(which)?),
    })
}

/// Start nginx with the port-80-only config so HTTP-01 can be answered
/// before the certificate exists.
fn bootstrap(engine: &Engine, cfg: &NodeConfig) -> Result<()> {
    let ctx = engine.ctx;
    if crate::sys::net::listening(&ctx.paths.system_root, crate::cert::http01::HTTP_PORT, true) {
        return Err(Error::msg(crate::cert::http01::PORT_BUSY));
    }
    let text = render_conf(ctx, cfg, None, SitePhase::Bootstrap)?;
    install_conf(ctx, &test_conf(ctx, &text)?)?;
    let services = engine.services();
    services.restart(SERVICE)?;
    services.wait_running(SERVICE, WAIT_RUNNING)
}

/// apply-website: install the tested full config (testing it now if the
/// staged file is missing or stale), write the unit, restart, enable and
/// wait. Turns the site off when it is not active.
pub fn apply(ctx: &Ctx, cfg: &NodeConfig, sub: Option<&SiteSubscription>) -> Result<()> {
    apply_with(&Engine::system(ctx), cfg, sub)
}

/// [`apply`] with an explicit engine.
pub fn apply_with(engine: &Engine, cfg: &NodeConfig, sub: Option<&SiteSubscription>) -> Result<()> {
    if cfg.site_active().is_none() {
        return disable_with(engine);
    }
    let ctx = engine.ctx;
    let text = render_conf(ctx, cfg, sub, SitePhase::Full)?;
    let staged = staged_conf(&ctx.paths);
    let tested = read_bounded(&staged, CONF_MAX).is_ok_and(|b| b == text.as_bytes());
    let tested = if tested {
        staged
    } else {
        test_conf(ctx, &text)?
    };
    install_conf(ctx, &tested)?;
    let bin = nginx::binary_with(ctx, engine.env)?;
    let services = engine.services();
    services.write(&ServiceDef::site(&ctx.paths, &bin))?;
    services.restart(SERVICE)?;
    services.enable(SERVICE)?;
    services.wait_running(SERVICE, WAIT_RUNNING)
}

/// Stop and remove `onebox-site`; content, certificates and the config
/// stay for a later re-enable.
pub fn disable(ctx: &Ctx) -> Result<()> {
    disable_with(&Engine::system(ctx))
}

/// [`disable`] with an explicit engine.
pub fn disable_with(engine: &Engine) -> Result<()> {
    let _ = remove_file_if_exists(&staged_conf(&engine.ctx.paths));
    engine.services().remove(SERVICE)
}

/// `site info`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SiteInfo {
    /// Configured and effective (a REALITY inbound exists).
    pub enabled: bool,
    pub site: Option<SiteConfig>,
    pub public_port: u16,
    pub frontend: bool,
    pub url: Option<String>,
    pub content_dir: PathBuf,
    pub config_dir: PathBuf,
    pub running: bool,
    pub generated: bool,
    pub backups: usize,
    pub cert: Option<CertStatus>,
}

impl SiteInfo {
    /// Human-readable lines (Chinese).
    pub fn lines(&self) -> Vec<String> {
        let state = if self.enabled { "开启" } else { "关闭" };
        let Some(site) = &self.site else {
            return vec![
                format!("网站: {state}"),
                format!("内容: {}", self.content_dir.display()),
            ];
        };
        let mut lines = vec![
            format!(
                "网站: {state}；域名: {}；内部端口: {}；公网端口: {}",
                site.domain, site.internal_port, self.public_port
            ),
            format!(
                "服务: {}",
                if self.running {
                    "运行中"
                } else {
                    "已停止"
                }
            ),
        ];
        if let Some(url) = &self.url {
            lines.push(format!("地址: {url}"));
        }
        let entry = match (site.https_entry, self.frontend) {
            (true, true) => "开启（nginx 监听 TCP 443）",
            (true, false) => "开启（由 REALITY 的 TCP 443 转发）",
            (false, _) => "关闭",
        };
        lines.push(format!("HTTPS 443 入口: {entry}"));
        let kind = if self.generated {
            "模板主页"
        } else {
            "自定义内容"
        };
        lines.push(format!(
            "内容: {}（{kind}，模板 {} / 主题 {}；备份 {} 个）",
            self.content_dir.display(),
            site.template,
            site.theme,
            self.backups
        ));
        match &self.cert {
            Some(cert) => lines.extend(cert.lines().into_iter().map(|l| format!("证书 {l}"))),
            None => lines.push("证书: 未配置".to_owned()),
        }
        lines
    }
}

/// Gather [`SiteInfo`] (reads files and service state, never changes them).
pub fn info(ctx: &Ctx, cfg: &NodeConfig) -> Result<SiteInfo> {
    info_with(&Engine::system(ctx), cfg)
}

/// [`info`] with an explicit engine.
pub fn info_with(engine: &Engine, cfg: &NodeConfig) -> Result<SiteInfo> {
    let paths = &engine.ctx.paths;
    let store = ContentStore::new(paths);
    let public_port = cfg.site_public_port();
    let url = cfg.site_active().map(|s| match public_port {
        443 => format!("https://{}/", s.domain),
        port => format!("https://{}:{port}/", s.domain),
    });
    Ok(SiteInfo {
        enabled: cfg.site_active().is_some(),
        site: cfg.site.clone(),
        public_port,
        frontend: uses_frontend(cfg),
        url,
        content_dir: paths.site_root.clone(),
        config_dir: paths.site(),
        running: engine.services().running(SERVICE),
        generated: store.is_generated()?,
        backups: store.backups()?.len(),
        cert: crate::cert::store::status(engine.ctx, &CertDir::site(paths))?,
    })
}

#[cfg(test)]
mod tests;
