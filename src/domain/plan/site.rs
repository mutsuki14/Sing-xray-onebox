//! Planners for the own-domain website and the remote subscription endpoint
//! (spec F §2.1, G §2.3).
//!
//! Changes from v2: an ip-mode subscription on an IPv6 address is refused
//! while planning when the host cannot listen on IPv6 (v2 found out only
//! when rendering the nginx config, G32); [`check_subscription_family`] is
//! that rule, also for the apply/publish stages. Without IPv6 the default
//! address prefers a detected IPv4 address over an IPv6 connection address.

use super::*;
use crate::domain::protocol::Transport;
use crate::domain::validate::{check_subscription_ip, valid_text};

/// `site enable DOMAIN [--tls http|cf|custom]`: the site becomes the REALITY
/// target with the HTTPS entrance on (v2 behavior).
pub fn enable_site(
    cfg: &NodeConfig,
    domain: &str,
    cert: WebCert,
    env: &PlanEnv,
) -> Result<NodeConfig> {
    ensure!(
        cfg.any_reality(),
        "自建 REALITY 网站需要先开启 REALITY 协议；独立订阅请用 subscription enable"
    );
    let request = OwnSite {
        domain: domain.to_owned(),
        title: None,
        https_entry: true,
        cert,
    };
    super::set_reality_target(cfg, &RealityChoice::OwnSite(request), env)
}

/// Turn the site off; REALITY goes back to the default external target.
/// The site settings (title, template, theme, description, certificate
/// method) go with it; a later `enable_site` starts from the defaults
/// (change from v2, which kept the `SITE_*` keys; see the `plan` module).
pub fn disable_site(cfg: &NodeConfig) -> Result<NodeConfig> {
    ensure!(cfg.site.is_some(), "网站未启用");
    let mut next = cfg.clone();
    external_target(&mut next, defaults::REALITY_SNI);
    check_site_subscription(cfg, &next)?;
    finish_local(next)
}

pub fn site_https(cfg: &NodeConfig, on: bool) -> Result<NodeConfig> {
    edit_site(cfg, |site| {
        site.https_entry = on;
        Ok(())
    })
}

pub fn site_title(cfg: &NodeConfig, title: &str) -> Result<NodeConfig> {
    let title = normalize_label(title, SITE_TITLE_ERROR)?;
    edit_site(cfg, |site| {
        site.title = title;
        Ok(())
    })
}

pub fn site_template(cfg: &NodeConfig, template: SiteTemplate) -> Result<NodeConfig> {
    edit_site(cfg, |site| {
        site.template = template;
        Ok(())
    })
}

pub fn site_theme(cfg: &NodeConfig, theme: SiteTheme) -> Result<NodeConfig> {
    edit_site(cfg, |site| {
        site.theme = theme;
        Ok(())
    })
}

pub fn site_description(cfg: &NodeConfig, text: &str) -> Result<NodeConfig> {
    let text = text.trim();
    ensure!(valid_text(text), "网站描述不能包含控制字符");
    edit_site(cfg, |site| {
        site.description = text.to_owned();
        Ok(())
    })
}

fn edit_site(
    cfg: &NodeConfig,
    edit: impl FnOnce(&mut SiteConfig) -> Result<()>,
) -> Result<NodeConfig> {
    let mut next = cfg.clone();
    let site = next.site.as_mut().ok_or("请先启用网站")?;
    edit(site)?;
    finish_local(next)
}

/// Subscription endpoint request (`subscription enable --mode …`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SubscriptionChoice {
    /// Plain HTTP on an IP literal; `None` uses the node's own IP.
    Ip {
        address: Option<IpAddr>,
    },
    /// Reuse the active site's domain, certificate and public port.
    Site,
    Standalone {
        domain: String,
        cert: WebCert,
    },
}

/// Enable (or reconfigure) the subscription endpoint. `port` defaults to
/// 8448 for ip/standalone and is ignored in site mode (the site's public
/// port is used, v2 behavior).
pub fn enable_subscription(
    cfg: &NodeConfig,
    choice: &SubscriptionChoice,
    port: Option<u16>,
    env: &PlanEnv,
) -> Result<NodeConfig> {
    let default_port = port.unwrap_or(defaults::SUBSCRIPTION_PORT);
    let (mode, port) = match choice {
        SubscriptionChoice::Ip { address } => {
            let address = address
                .or_else(|| listenable_default_address(cfg, env.ipv6))
                .ok_or("没有可用的服务器 IP，请用 --address 指定 IPv4 或 IPv6 地址")?
                .to_canonical();
            check_subscription_ip(&address)?;
            (SubscriptionMode::Ip { address }, default_port)
        }
        SubscriptionChoice::Site => {
            ensure!(
                cfg.site_active().is_some(),
                "没有可复用的自建站，请使用 --mode ip --address IP，或 --mode standalone --domain 域名 --tls cf|http|custom"
            );
            (SubscriptionMode::Site, cfg.site_public_port())
        }
        SubscriptionChoice::Standalone { domain, cert } => {
            let mode = SubscriptionMode::Standalone {
                domain: normalize_domain(domain, "订阅域名无效")?,
                cert: web_cert(cert)?,
                http01_port80: *cert == WebCert::Http01,
            };
            (mode, default_port)
        }
    };
    ensure!(port != 0, "订阅端口无效");
    let site_mode = mode == SubscriptionMode::Site;
    let mut next = cfg.clone();
    next.subscription = Some(SubscriptionConfig { mode, port });
    check_subscription_family(&next, env.ipv6)?;
    let next = finish(next, env)?;
    if !site_mode {
        let previous = env.previous_plan(cfg);
        let plan = PortPlan::of(&next, env.frp);
        let owner = Owner::SubscriptionPort;
        let free = plan.is_free(port, Transport::Tcp, &owner, env.probe, Some(&previous));
        ensure!(free, "订阅端口 {port} 已被占用");
    }
    Ok(next)
}

pub fn disable_subscription(cfg: &NodeConfig) -> Result<NodeConfig> {
    let mut next = cfg.clone();
    next.subscription = None;
    finish_local(next)
}

/// v2 `validate_listener_family` (G32): an ip-mode subscription on an IPv6
/// address needs IPv6 sockets (`ipv6` = `sys::net::ipv6_available`).
/// Other modes listen behind nginx and are not affected.
///
/// v2 re-ran this on every subscription render, i.e. on every apply. Here
/// planning checks it, and the apply/publish stages call it again with the
/// probed value: a host can lose IPv6 after the subscription was enabled,
/// and migrated v2 settings were never planned. Without it the worker
/// would fail late with a raw bind error.
pub fn check_subscription_family(cfg: &NodeConfig, ipv6: bool) -> Result<()> {
    if let Some(SubscriptionConfig {
        mode: SubscriptionMode::Ip { address },
        ..
    }) = &cfg.subscription
    {
        ensure!(
            ipv6 || address.to_canonical().is_ipv4(),
            "订阅地址为 IPv6，但当前系统无法监听 IPv6；请启用 IPv6 或使用 IPv4 地址"
        );
    }
    Ok(())
}

/// First usable IP among the connection address and the detected addresses
/// (v2 `default_address`), canonical form.
pub fn default_subscription_address(cfg: &NodeConfig) -> Option<IpAddr> {
    let server = &cfg.server;
    [
        server.addr.ip(),
        server.ipv4.map(IpAddr::V4),
        server.ipv6.map(IpAddr::V6),
    ]
    .into_iter()
    .flatten()
    .map(|ip| ip.to_canonical())
    .find(|ip| check_subscription_ip(ip).is_ok())
}

/// [`default_subscription_address`], but without IPv6 sockets an IPv4
/// candidate wins over an earlier IPv6 one (the worker could not listen on
/// the IPv6 address). Falls back to the plain default, which the caller
/// then rejects with the IPv6 message.
fn listenable_default_address(cfg: &NodeConfig, ipv6: bool) -> Option<IpAddr> {
    let first = default_subscription_address(cfg)?;
    if ipv6 || first.is_ipv4() {
        return Some(first);
    }
    let server = &cfg.server;
    [server.addr.ip(), server.ipv4.map(IpAddr::V4)]
        .into_iter()
        .flatten()
        .map(|ip| ip.to_canonical())
        .find(|ip| ip.is_ipv4() && check_subscription_ip(ip).is_ok())
        .or(Some(first))
}

#[cfg(test)]
mod tests;
