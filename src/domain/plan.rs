//! Pure planners: typed requests in, a new validated `NodeConfig` out.
//!
//! The CLI flags and the interactive wizard both feed these functions; they
//! never prompt, read files or run programs. Live state they need (IPv6
//! availability, listening sockets, FRP reservations, the previous
//! generation, the clock) arrives through [`PlanEnv`]. Every planner returns
//! a configuration that passes `NodeConfig::validate` and `PortPlan::validate`
//! (planners without an environment check port conflicts without FRP; the
//! apply engine re-checks with FRP).
//!
//! Changes from v2 (spec B §9.1): auto-allocation avoids hop ranges, ACME
//! port 80 and every other reserved listener (#5); `add` recomputes
//! `vmess_tls` and picks a certificate when one becomes necessary (#9);
//! address changes never leave stale other-family addresses (#8); changing the
//! ShadowTLS SNI clears an explicit handshake target (#3); Hysteria2 tuning is
//! validated once as integer Mbps and switching away from `measured` clears
//! stale bandwidth (#20, C-8.1 #1).
//!
//! Settings exist only while they are in effect (a deliberate change from
//! v2, which kept `TLS_MODE`/`DOMAIN`/`ACME_METHOD` and the
//! `REALITY_SITE_*`/`SITE_*` keys dormant and reused them): the proxy
//! certificate is dropped with the last protocol that needs one, and the
//! website with `disable_site` or the last REALITY inbound, so adding them
//! back starts from the defaults (self-signed; `山间手记`, minimal/forest)
//! unless the request says otherwise. `tls` and `site` are present iff in
//! use (`NodeConfig::validate`), so a configuration never carries settings
//! that look active but are not. Website content and its backups live on
//! disk and are untouched; `vmess_host` is kept because it is only a
//! client-side header, and the REALITY keys are kept (v2 parity, K12) so a
//! re-added REALITY inbound keeps the public key clients already have.
//!
//! Contract with the apply engine: a custom proxy certificate's
//! `ProxyTls::pinned` is provisional ([`PROVISIONAL_CUSTOM_PIN`]) until the
//! prepare-certificates stage records the trust check of the deployed pair
//! (`ProxyTls::record_trust`); the apply persists that result with the rest
//! of the configuration. Self-signed and ACME pins follow from the mode.

mod install;
mod node;
mod site;

pub use install::{install, InstallRequest, ProtocolChoice};
pub use node::{
    add, remove, reset_credentials, set_address, set_hy2, set_port, set_proxy_cert,
    set_reality_target, set_shadowtls_sni, set_vmess_host, tune_hy2, tune_reset, tune_resource,
    AddOptions,
};
pub use site::{
    default_subscription_address, disable_site, disable_subscription, enable_site,
    enable_subscription, site_description, site_https, site_template, site_theme, site_title,
    SubscriptionChoice,
};

use super::config::*;
use super::defaults;
use super::ports::{Owner, PortPlan, PortProbe, Reservation};
use super::protocol::Protocol;
use super::validate::{valid_domain, valid_label};
use crate::error::Result;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;

/// Live facts a planner may consult.
pub struct PlanEnv<'a> {
    /// IPv6 sockets work on this host (listen address `::`).
    pub ipv6: bool,
    pub probe: &'a dyn PortProbe,
    pub frp: &'a [Reservation],
    /// The configuration currently applied (its sockets are not foreign).
    /// Modification planners fall back to the configuration they modify.
    pub previous: Option<&'a NodeConfig>,
    /// Unix seconds (`installed_at`).
    pub now: u64,
}

impl PlanEnv<'static> {
    /// No live sockets, no FRP, no previous generation (dry runs, tests).
    pub fn offline(ipv6: bool, now: u64) -> Self {
        PlanEnv {
            ipv6,
            probe: &super::ports::NoProbe,
            frp: &[],
            previous: None,
            now,
        }
    }
}

impl PlanEnv<'_> {
    fn previous_plan(&self, fallback: &NodeConfig) -> PortPlan {
        PortPlan::of(self.previous.unwrap_or(fallback), self.frp)
    }
}

/// REALITY handshake target selection (install wizard step 2, `onebox sni`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum RealityChoice {
    /// Keep the current target (the Microsoft default on a fresh install).
    #[default]
    Default,
    Microsoft,
    Apple,
    /// Another external site: SNI `name`, target `name:443`.
    Custom(String),
    /// Explicit handshake target; the SNI is unchanged and the own site is
    /// switched off (its target would be overridden otherwise).
    Dest(HostPort),
    OwnSite(OwnSite),
}

/// Own-domain website as the REALITY target.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OwnSite {
    pub domain: String,
    /// `None` keeps the current title (default `山间手记`).
    pub title: Option<String>,
    pub https_entry: bool,
    pub cert: WebCert,
}

/// Proxy certificate selection (`--tls self|acme|http|cf|custom`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProxyCertChoice {
    SelfSigned,
    Acme {
        domain: String,
        method: AcmeMethod,
    },
    Custom {
        domain: String,
        cert: PathBuf,
        key: PathBuf,
    },
}

/// Validate structure and port conflicts with the environment's FRP view.
fn finish(next: NodeConfig, env: &PlanEnv) -> Result<NodeConfig> {
    next.validate()?;
    PortPlan::of(&next, env.frp).validate()?;
    Ok(next)
}

/// Validate structure and port conflicts among the node's own listeners.
fn finish_local(next: NodeConfig) -> Result<NodeConfig> {
    next.validate()?;
    PortPlan::of(&next, &[]).validate()?;
    Ok(next)
}

/// Trimmed, lower-cased DNS name or `message`.
pub fn normalize_domain(input: &str, message: &str) -> Result<String> {
    let domain = input.trim().to_ascii_lowercase();
    ensure!(valid_domain(&domain), "{message}");
    Ok(domain)
}

fn normalize_label(input: &str, message: &str) -> Result<String> {
    let label = input.trim();
    ensure!(valid_label(label), "{message}");
    Ok(label.to_owned())
}

const NODE_NAME_ERROR: &str = "节点名称不能为空或超过 128 个字符，且不能包含控制字符";
const SITE_TITLE_ERROR: &str = "网站标题不能为空或超过 128 个字符，且不能包含控制字符";
const SITE_REQUIRES_REALITY: &str = "自建站需要 REALITY 协议及有效域名";
const NO_CERT_NEEDED: &str = "当前协议无需代理 TLS 证书，自建站证书请使用 site 管理";
const SUBSCRIPTION_USES_SITE: &str = "请先关闭订阅或将订阅切换为独立 HTTPS 站点";

/// Public address plus detected families; the address's own family always
/// wins and the other family comes only from fresh detection (no stale data).
fn server_addr(
    addr: Option<Host>,
    ipv4: Option<Ipv4Addr>,
    ipv6: Option<Ipv6Addr>,
) -> Result<ServerAddr> {
    let detected = ipv4.map(IpAddr::V4).or(ipv6.map(IpAddr::V6)).map(Host::Ip);
    let addr = match addr.or(detected) {
        Some(Host::Ip(ip)) => Host::Ip(ip.to_canonical()),
        Some(host) => host,
        None => bail!("无法检测公网地址，请使用 --addr 指定"),
    };
    let (mut ipv4, mut ipv6) = (ipv4, ipv6);
    match addr {
        Host::Ip(IpAddr::V4(v4)) => ipv4 = Some(v4),
        Host::Ip(IpAddr::V6(v6)) => ipv6 = Some(v6),
        Host::Domain(_) => {}
    }
    Ok(ServerAddr {
        addr,
        ipv4,
        ipv6,
        ipv4_warp: false,
        ipv6_warp: false,
    })
}

/// Point REALITY at `choice`. `Default` keeps the current target.
fn apply_reality(cfg: &mut NodeConfig, choice: &RealityChoice) -> Result<()> {
    match choice {
        RealityChoice::Default => {}
        RealityChoice::Microsoft => external_target(cfg, defaults::REALITY_SNI),
        RealityChoice::Apple => external_target(cfg, defaults::REALITY_APPLE_SNI),
        RealityChoice::Custom(name) => {
            let sni = normalize_domain(name, "REALITY SNI 域名无效")?;
            external_target(cfg, &sni);
        }
        RealityChoice::Dest(dest) => {
            cfg.site = None;
            cfg.reality.dest = dest.clone();
        }
        RealityChoice::OwnSite(site) => own_site(cfg, site)?,
    }
    Ok(())
}

fn external_target(cfg: &mut NodeConfig, sni: &str) {
    cfg.site = None;
    cfg.reality.sni = sni.to_owned();
    cfg.reality.dest = defaults::handshake_dest(sni);
}

/// Enable (or re-target) the own site, keeping the internal port, content
/// settings and title of an existing site.
fn own_site(cfg: &mut NodeConfig, request: &OwnSite) -> Result<()> {
    ensure!(cfg.any_reality(), "{SITE_REQUIRES_REALITY}");
    let domain = normalize_domain(&request.domain, SITE_REQUIRES_REALITY)?;
    let cert = web_cert(&request.cert)?;
    let existing = cfg.site.take();
    let title = match &request.title {
        Some(title) => normalize_label(title, SITE_TITLE_ERROR)?,
        None => existing
            .as_ref()
            .map_or_else(|| defaults::SITE_TITLE.to_owned(), |s| s.title.clone()),
    };
    let site = match existing {
        Some(old) => SiteConfig {
            domain,
            https_entry: request.https_entry,
            title,
            cert,
            ..old
        },
        None => SiteConfig {
            domain,
            internal_port: defaults::SITE_INTERNAL_PORT,
            https_entry: request.https_entry,
            title,
            template: defaults::SITE_TEMPLATE,
            theme: defaults::SITE_THEME,
            description: String::new(),
            cert,
            last_content_backup: None,
        },
    };
    cfg.reality.sni = site.domain.clone();
    cfg.reality.dest = defaults::site_dest(site.internal_port);
    cfg.site = Some(site);
    Ok(())
}

/// A site-mode subscription follows the site: block changes that would
/// remove it or silently change its domain (v2 `validate_site_endpoint`).
fn check_site_subscription(old: &NodeConfig, next: &NodeConfig) -> Result<()> {
    let uses_site = matches!(
        old.subscription.as_ref().map(|s| &s.mode),
        Some(SubscriptionMode::Site)
    );
    if !uses_site {
        return Ok(());
    }
    let (Some(before), Some(after)) = (old.site_active(), next.site_active()) else {
        bail!("{SUBSCRIPTION_USES_SITE}");
    };
    ensure!(
        before.domain == after.domain,
        "远程订阅正在复用自建站；更换网站域名前请先关闭订阅，或改用独立 HTTPS 订阅"
    );
    Ok(())
}

fn web_cert(cert: &WebCert) -> Result<WebCert> {
    if let WebCert::Custom { cert, key } = cert {
        ensure!(
            cert.is_absolute() && key.is_absolute(),
            "证书路径必须为绝对路径"
        );
    }
    Ok(cert.clone())
}

fn proxy_tls(choice: &ProxyCertChoice, current: Option<&ProxyTls>) -> Result<ProxyTls> {
    let mode = match choice {
        ProxyCertChoice::SelfSigned => {
            let sni = match current.map(|t| &t.mode) {
                Some(ProxyCertMode::SelfSigned { sni }) => sni.clone(),
                _ => defaults::TLS_SNI.to_owned(),
            };
            ProxyCertMode::SelfSigned { sni }
        }
        ProxyCertChoice::Acme { domain, method } => ProxyCertMode::Acme {
            domain: normalize_domain(domain, "证书域名无效")?,
            method: *method,
        },
        ProxyCertChoice::Custom { domain, cert, key } => {
            ensure!(
                cert.is_absolute() && key.is_absolute(),
                "证书路径必须为绝对路径"
            );
            ProxyCertMode::Custom {
                domain: normalize_domain(domain, "证书域名无效")?,
                cert: cert.clone(),
                key: key.clone(),
            }
        }
    };
    let pinned = match current {
        // The same custom pair again: keep the trust the certificate stage
        // recorded for it.
        Some(cur) if cur.mode == mode && mode.implied_pin().is_none() => cur.pinned,
        _ => mode.implied_pin().unwrap_or(PROVISIONAL_CUSTOM_PIN),
    };
    Ok(ProxyTls { mode, pinned })
}

/// Apply an optional certificate choice, then restore the TLS invariants.
///
/// `vmess_tls` is (re)decided when the certificate changes or VMess-WS is
/// newly added (`vmess_added`): TLS exactly with a real domain certificate
/// (v2 rule). Otherwise the stored decision is kept, as v2 pinned it, so an
/// unrelated change never flips VMess between TLS and plain. A certificate
/// exists iff some inbound needs one; a newly needed one is self-signed.
fn settle_tls(
    cfg: &mut NodeConfig,
    choice: Option<&ProxyCertChoice>,
    vmess_added: bool,
) -> Result<()> {
    if let Some(choice) = choice {
        cfg.tls = Some(proxy_tls(choice, cfg.tls.as_ref())?);
    }
    let has_vmess = cfg.has(Protocol::VmessWs);
    if choice.is_some() || vmess_added {
        cfg.vmess_tls = has_vmess && cfg.tls.as_ref().is_some_and(|t| t.mode.is_domain_cert());
    }
    cfg.vmess_tls &= has_vmess;
    if !cfg.needs_cert() {
        cfg.tls = None;
    } else if cfg.tls.is_none() {
        cfg.tls = Some(proxy_tls(&ProxyCertChoice::SelfSigned, None)?);
    }
    Ok(())
}

/// Check a user-chosen inbound port against the plan and live sockets.
fn check_explicit_port(
    cfg: &NodeConfig,
    protocol: Protocol,
    port: u16,
    env: &PlanEnv,
    previous: &PortPlan,
) -> Result<()> {
    ensure!(port != 0, "端口不能为 0");
    let plan = PortPlan::of(cfg, env.frp);
    let owner = Owner::Inbound(protocol);
    let free = plan.is_free(
        port,
        protocol.transport(),
        &owner,
        env.probe,
        Some(previous),
    );
    ensure!(free, "{protocol} 端口不可用: {port}");
    Ok(())
}

/// Allocate every inbound still at port 0, in configuration order.
fn allocate_missing(cfg: &mut NodeConfig, env: &PlanEnv, previous: &PortPlan) -> Result<()> {
    for i in 0..cfg.inbounds.len() {
        let Inbound {
            protocol,
            port,
            core,
        } = cfg.inbounds[i];
        if port == 0 {
            let plan = PortPlan::of(cfg, env.frp);
            cfg.inbounds[i].port = plan.allocate(protocol, core, env.probe, Some(previous))?;
        }
    }
    Ok(())
}

/// Keep the guard port when it is still free, otherwise allocate a new one.
fn ensure_guard(cfg: &mut NodeConfig, env: &PlanEnv, previous: &PortPlan) -> Result<()> {
    let plan = PortPlan::of(cfg, env.frp);
    let port = cfg.reality.guard_port;
    let owner = Owner::RealityGuard;
    let tcp = super::protocol::Transport::Tcp;
    if port == 0 || !plan.is_free(port, tcp, &owner, env.probe, Some(previous)) {
        cfg.reality.guard_port = plan.allocate_guard(env.probe, Some(previous))?;
    }
    Ok(())
}

/// Optional plain VMess-WS `Host` header; empty means none.
fn vmess_host(value: Option<&str>) -> Result<Option<String>> {
    match value.map(str::trim).filter(|v| !v.is_empty()) {
        Some(host) => normalize_domain(host, "VMess Host 域名无效").map(Some),
        None => Ok(None),
    }
}

/// Optional core version pin: `latest` / empty mean "no pin".
fn version_pin(value: Option<&str>) -> Result<Option<String>> {
    let Some(value) = value
        .map(str::trim)
        .filter(|v| !v.is_empty() && *v != "latest")
    else {
        return Ok(None);
    };
    ensure!(
        super::validate::valid_version(value),
        "内核版本无效: {value}"
    );
    Ok(Some(value.to_owned()))
}

#[cfg(test)]
mod tests;
