//! Every default constant, decided once.
//!
//! Changes from v2: v2 defaulted the same settings differently per module
//! (site internal port 10443 / 8443 / 8444 / 0, subscription port 8448 / 443,
//! `REALITY_SITE_HTTPS` absent = off / on, Xray vs sing-box listen fallback).
//! Every consumer now reads the values below.

use super::config::{Host, HostPort, RealityTarget, ShadowTls, SiteTemplate, SiteTheme};
use super::protocol::Protocol;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::ops::RangeInclusive;

/// Node label prefix (`{node_name}-{protocol title}`).
pub const NODE_NAME: &str = "onebox";

/// REALITY handshake target used when the user picks no other.
pub const REALITY_SNI: &str = "www.microsoft.com";
/// Alternative offered by the install wizard ("Apple").
pub const REALITY_APPLE_SNI: &str = "www.apple.com";
/// External REALITY/ShadowTLS handshake targets are always reached on 443.
pub const HANDSHAKE_PORT: u16 = 443;

pub const SHADOWTLS_SNI: &str = "www.microsoft.com";
/// CN/SAN of the self-signed proxy certificate.
pub const TLS_SNI: &str = "www.bing.com";
pub const SS_METHOD: &str = "2022-blake3-aes-128-gcm";
/// ShadowTLS wraps a fixed-method Shadowsocks inbound (v2 behavior).
pub const SHADOWTLS_SS_METHOD: &str = "2022-blake3-aes-128-gcm";
/// Shadowsocks-2022 methods the cores accept.
pub const SS_METHODS: [&str; 3] = [
    "2022-blake3-aes-128-gcm",
    "2022-blake3-aes-256-gcm",
    "2022-blake3-chacha20-poly1305",
];

/// Loopback HTTPS port of the own-domain website (the REALITY target).
pub const SITE_INTERNAL_PORT: u16 = 10443;
/// The internal port must not be a privileged port (v2 rule).
pub const SITE_INTERNAL_PORT_MIN: u16 = 1024;
pub const SITE_TITLE: &str = "山间手记";
pub const SITE_DESCRIPTION: &str = "给思考一点空间，给日常一些留白。";
pub const SITE_TEMPLATE: SiteTemplate = SiteTemplate::Minimal;
pub const SITE_THEME: SiteTheme = SiteTheme::Forest;

/// Port of the IP and standalone subscription endpoints.
pub const SUBSCRIPTION_PORT: u16 = 8448;

/// Plain HTTP (site redirect, HTTP-01 challenges) and HTTPS entry ports.
pub const HTTP_PORT: u16 = 80;
pub const HTTPS_PORT: u16 = 443;

/// Local TCP ports searched for the Xray REALITY guard (dokodemo) inbound.
pub const GUARD_PORTS: RangeInclusive<u16> = 18000..=19999;

/// Preferred ports per protocol family, tried in order before [`FALLBACK_PORTS`].
pub const SHADOWSOCKS_PORTS: [u16; 3] = [8388, 8389, 8390];
pub const VMESS_WS_PORTS: [u16; 3] = [8080, 2082, 8880];
pub const COMMON_PORTS: [u16; 7] = [443, 8443, 2053, 2083, 2087, 2096, 9443];
pub const FALLBACK_PORTS: RangeInclusive<u16> = 20000..=20999;

/// Hysteria2 hop ranges must stay out of the privileged range.
pub const HOP_MIN_START: u16 = 1024;
/// Hysteria2 bandwidth limits (integer Mbps).
pub const HY2_MBPS: RangeInclusive<u32> = 1..=10_000;

/// Client-side local ports used by the generated client configurations.
pub const SINGBOX_MIXED_PORT: u16 = 2080;
pub const CLASH_API_PORT: u16 = 9090;
pub const MIHOMO_MIXED_PORT: u16 = 7890;
pub const MIHOMO_DNS_PORT: u16 = 1053;
pub const XRAY_SOCKS_PORT: u16 = 10808;
pub const XRAY_HTTP_PORT: u16 = 10809;

/// Tested / fallback upstream versions.
pub const XRAY_TESTED_VERSION: &str = "26.3.27";
pub const SINGBOX_FALLBACK_VERSION: &str = "1.14.2";
pub const FRP_VERSION: &str = "0.71.0";
pub const ACME_SH_VERSION: &str = "3.1.6";

/// Certificates are renewed when they expire within this window.
pub const RENEWAL_WINDOW_DAYS: u64 = 30;
pub const RENEWAL_WINDOW_SECS: u64 = RENEWAL_WINDOW_DAYS * 24 * 60 * 60;
/// `doctor` warns about certificates expiring within this many days.
pub const CERT_WARNING_DAYS: u64 = 7;
pub const NODE_RENEW_CRON: &str = "17 4 * * *";
pub const FRP_RENEW_CRON: &str = "17 3 * * *";

/// Size cap for `state.json` and other small JSON state files.
pub const STATE_MAX_BYTES: u64 = 1024 * 1024;

pub const BLOCK_PRIVATE: bool = true;
pub const BLOCK_BT: bool = true;

/// Auto-assignment candidates for `protocol` (before [`FALLBACK_PORTS`]).
pub fn port_candidates(protocol: Protocol) -> &'static [u16] {
    match protocol {
        Protocol::Shadowsocks => &SHADOWSOCKS_PORTS,
        Protocol::VmessWs => &VMESS_WS_PORTS,
        _ => &COMMON_PORTS,
    }
}

/// One listen address for both cores: dual-stack `::` when IPv6 sockets work.
pub fn listen(ipv6: bool) -> IpAddr {
    if ipv6 {
        IpAddr::V6(Ipv6Addr::UNSPECIFIED)
    } else {
        IpAddr::V4(Ipv4Addr::UNSPECIFIED)
    }
}

/// `{domain}:443` as a handshake target. `domain` must already be validated.
pub fn handshake_dest(domain: &str) -> HostPort {
    HostPort {
        host: Host::Domain(domain.to_owned()),
        port: HANDSHAKE_PORT,
    }
}

/// `127.0.0.1:{port}`: the REALITY target while the own site is active.
pub fn site_dest(port: u16) -> HostPort {
    HostPort {
        host: Host::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        port,
    }
}

/// Default REALITY target (Microsoft) with the given guard port.
pub fn reality_target(guard_port: u16) -> RealityTarget {
    RealityTarget {
        sni: REALITY_SNI.to_owned(),
        dest: handshake_dest(REALITY_SNI),
        guard_port,
    }
}

pub fn shadowtls() -> ShadowTls {
    ShadowTls {
        sni: SHADOWTLS_SNI.to_owned(),
        dest: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn candidates_follow_protocol_family() {
        assert_eq!(port_candidates(Protocol::Shadowsocks), &[8388, 8389, 8390]);
        assert_eq!(port_candidates(Protocol::VmessWs), &[8080, 2082, 8880]);
        assert_eq!(port_candidates(Protocol::Tuic)[0], 443);
        assert_eq!(port_candidates(Protocol::VlessReality).len(), 7);
    }

    #[test]
    fn targets_render_as_v2_strings() {
        assert_eq!(
            reality_target(18000).dest.to_string(),
            "www.microsoft.com:443"
        );
        assert_eq!(site_dest(10443).to_string(), "127.0.0.1:10443");
        assert_eq!(listen(true).to_string(), "::");
        assert_eq!(listen(false).to_string(), "0.0.0.0");
        assert_eq!(shadowtls().effective_dest(), "www.microsoft.com:443");
    }

    #[test]
    fn ranges_do_not_overlap() {
        assert!(GUARD_PORTS.end() < FALLBACK_PORTS.start());
        assert!(COMMON_PORTS.iter().all(|p| !GUARD_PORTS.contains(p)));
        assert_eq!(RENEWAL_WINDOW_SECS, 2_592_000);
    }
}
