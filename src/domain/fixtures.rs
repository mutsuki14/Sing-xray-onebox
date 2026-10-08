//! Deterministic configurations shared by the domain and state unit tests.

use super::config::*;
use super::protocol::{Core, Protocol};
use super::{credentials, defaults};
use crate::sys::rand::SeqRandom;
use std::net::{IpAddr, Ipv4Addr};

pub(crate) const ADDR: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 10);

/// A valid node with the given inbounds, deterministic credentials, the
/// default REALITY target (guard 18000) and a self-signed certificate when
/// one is needed.
pub(crate) fn config(inbounds: &[(Protocol, u16, Core)]) -> NodeConfig {
    let mut rng = SeqRandom(1);
    let mut creds = credentials::generate(&mut rng, defaults::SS_METHOD).unwrap();
    let inbounds: Vec<Inbound> = inbounds
        .iter()
        .map(|&(protocol, port, core)| Inbound {
            protocol,
            port,
            core,
        })
        .collect();
    if inbounds.iter().any(|i| i.protocol.reality()) {
        creds.reality = Some(credentials::reality_keys(&mut rng).unwrap());
    }
    let mut cfg = NodeConfig {
        schema: SCHEMA,
        node_name: defaults::NODE_NAME.into(),
        server: ServerAddr {
            addr: Host::Ip(IpAddr::V4(ADDR)),
            ipv4: Some(ADDR),
            ipv6: None,
            ipv4_warp: false,
            ipv6_warp: false,
        },
        listen: defaults::listen(true),
        inbounds,
        creds,
        reality: defaults::reality_target(18000),
        shadowtls: defaults::shadowtls(),
        site: None,
        tls: None,
        vmess_tls: false,
        vmess_host: None,
        hy2: Hy2Settings::default(),
        resource_profile: ResourceProfile::Balanced,
        routing: Routing::default(),
        subscription: None,
        versions: CoreVersions::default(),
        installed_at: 1_700_000_000,
    };
    if cfg.needs_cert() {
        cfg.tls = Some(self_signed());
    }
    cfg
}

pub(crate) fn self_signed() -> ProxyTls {
    ProxyTls {
        mode: ProxyCertMode::SelfSigned {
            sni: defaults::TLS_SNI.into(),
        },
        pinned: true,
    }
}

/// Enable the own-domain site on `cfg` (internal port 10443, HTTP-01 cert).
pub(crate) fn with_site(mut cfg: NodeConfig, domain: &str, https_entry: bool) -> NodeConfig {
    cfg.site = Some(SiteConfig {
        domain: domain.into(),
        internal_port: defaults::SITE_INTERNAL_PORT,
        https_entry,
        title: defaults::SITE_TITLE.into(),
        template: defaults::SITE_TEMPLATE,
        theme: defaults::SITE_THEME,
        description: String::new(),
        cert: WebCert::Http01,
        last_content_backup: None,
    });
    cfg.reality.sni = domain.into();
    cfg.reality.dest = defaults::site_dest(defaults::SITE_INTERNAL_PORT);
    cfg
}

pub(crate) fn standalone_subscription(
    domain: &str,
    port: u16,
    cert: WebCert,
) -> SubscriptionConfig {
    let http01_port80 = cert == WebCert::Http01;
    SubscriptionConfig {
        mode: SubscriptionMode::Standalone {
            domain: domain.into(),
            cert,
            http01_port80,
        },
        port,
    }
}

pub(crate) fn ip_subscription(port: u16) -> SubscriptionConfig {
    SubscriptionConfig {
        mode: SubscriptionMode::Ip {
            address: IpAddr::V4(ADDR),
        },
        port,
    }
}
