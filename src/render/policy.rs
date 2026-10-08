//! Routing and DNS policy shared by every renderer: constants (private
//! ranges, DNS servers, rule-set URLs, local client ports, TUN addresses)
//! and the ordered rule lists of each target schema.
//!
//! Every list is built front to back in its final order; nothing is
//! inserted at an index afterwards, so a rule's position is visible here.
//!
//! Changes from v2: one place for the constants v2 repeated per renderer
//! (ALPN lists, uTLS fingerprint, WebSocket early data, masquerade URL);
//! the rule lists are identical to v2.
//!
//! Kept from v2 (C-8.1 #11): the client policies still differ by target
//! (Xray and mihomo block ads, sing-box does not) so existing clients keep
//! their behavior.

use super::spec::{DirectTargets, Families, NodeSpec};
use crate::domain::defaults;
use crate::domain::protocol::{Core, Protocol};
use serde_json::{json, Value};

/// Private, special-purpose and documentation ranges: blocked as server
/// egress targets, sent direct by clients. Declared order is the client
/// order; servers use the sorted union with the node's own addresses.
pub const PRIVATE_CIDRS: [&str; 18] = [
    "0.0.0.0/8",
    "10.0.0.0/8",
    "100.64.0.0/10",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "172.16.0.0/12",
    "192.0.0.0/24",
    "192.0.2.0/24",
    "192.88.99.0/24",
    "192.168.0.0/16",
    "198.18.0.0/15",
    "198.51.100.0/24",
    "203.0.113.0/24",
    "224.0.0.0/3",
    "::/127",
    "fc00::/7",
    "fe80::/10",
    "ff00::/8",
];

/// uTLS / REALITY client fingerprint.
pub const FINGERPRINT: &str = "chrome";
/// WebSocket early data (sing-box and mihomo).
pub const WS_EARLY_DATA: u32 = 2048;
pub const WS_EARLY_DATA_HEADER: &str = "Sec-WebSocket-Protocol";
/// Site a Hysteria2 server without obfuscation impersonates.
pub const MASQUERADE_URL: &str = "https://www.bing.com";
/// Abstract socket between the Xray Vision fallback and the shared XHTTP
/// inbound (a constant: v2's `XR_XHTTP_SOCK` override was never settable,
/// C-8.1 #8).
pub const XHTTP_SOCKET: &str = "@onebox-xhttp";
/// Loopback address of local-only listeners (ShadowTLS backend, REALITY
/// guard, client proxy ports).
pub const LOOPBACK: &str = "127.0.0.1";
/// Name every client-side Onebox user carries on the server.
pub const USER_NAME: &str = "onebox";
/// Hysteria2 port-hopping intervals per client schema.
pub const SINGBOX_HOP_INTERVAL: &str = "30s";
pub const XRAY_HOP_INTERVAL: &str = "25-35";
pub const MIHOMO_HOP_INTERVAL: u32 = 30;
/// UDP-over-TCP version of the ShadowTLS Shadowsocks client.
pub const UOT_VERSION: u32 = 2;

/// Latency test target of `urltest` / `url-test` groups.
pub const URL_TEST: &str = "https://www.gstatic.com/generate_204";
pub const SINGBOX_URL_TEST_INTERVAL: &str = "3m";
pub const MIHOMO_URL_TEST_INTERVAL: u32 = 300;
pub const URL_TEST_TOLERANCE: u32 = 50;

/// sing-box TUN interface addresses.
pub const TUN_ADDRESSES: [&str; 2] = ["172.19.0.1/30", "fdfe:dcba:9876::1/126"];

/// Domestic plain DNS server used for direct lookups.
pub const DNS_DIRECT: &str = "223.5.5.5";
/// Remote DoH server reached through the proxy (sing-box).
pub const DNS_REMOTE: &str = "1.1.1.1";
pub const DNS_REMOTE_TLS_NAME: &str = "cloudflare-dns.com";
/// Remote DoH URL (Xray).
pub const XRAY_DOH: &str = "https://1.1.1.1/dns-query";

/// sing-box remote rule sets `(tag, url)`.
pub const SINGBOX_RULE_SETS: [(&str, &str); 2] = [
    (
        "geosite-cn",
        "https://testingcf.jsdelivr.net/gh/SagerNet/sing-geosite@rule-set/geosite-cn.srs",
    ),
    (
        "geoip-cn",
        "https://testingcf.jsdelivr.net/gh/SagerNet/sing-geoip@rule-set/geoip-cn.srs",
    ),
];

/// mihomo geodata downloads `(kind, url)`.
pub const MIHOMO_GEOX: [(&str, &str); 4] = [
    (
        "geoip",
        "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/geoip.dat",
    ),
    (
        "geosite",
        "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/geosite.dat",
    ),
    (
        "mmdb",
        "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/country.mmdb",
    ),
    (
        "asn",
        "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/GeoLite2-ASN.mmdb",
    ),
];

/// mihomo proxy group names (shown in client UIs).
pub const MIHOMO_SELECT: &str = "节点选择";
pub const MIHOMO_AUTO: &str = "自动选择";

/// Domestic DoH servers (mihomo).
pub const DOH_CN: [&str; 2] = [
    "https://dns.alidns.com/dns-query",
    "https://doh.pub/dns-query",
];
/// Foreign DoH servers reached through the select group (mihomo).
pub const DOH_GLOBAL: [&str; 2] = [
    "https://dns.cloudflare.com/dns-query#节点选择",
    "https://dns.google/dns-query#节点选择",
];
pub const MIHOMO_BOOTSTRAP_DNS: [&str; 2] = ["223.5.5.5", "119.29.29.29"];
pub const MIHOMO_FAKE_IP_RANGE: &str = "198.18.0.1/16";
pub const MIHOMO_FAKE_IP_FILTER: [&str; 14] = [
    "geosite:private",
    "geosite:connectivity-check",
    "+.lan",
    "+.local",
    "+.home.arpa",
    "time.*.com",
    "ntp.*.com",
    "+.pool.ntp.org",
    "+.stun.*.*",
    "+.stun.*.*.*",
    "+.srv.nintendo.net",
    "+.stun.playstation.net",
    "xbox.*.microsoft.com",
    "+.xboxlive.com",
];
/// mihomo rules after the direct bypass rules.
pub const MIHOMO_RULES: [&str; 7] = [
    "GEOSITE,private,DIRECT",
    "GEOIP,private,DIRECT,no-resolve",
    "GEOSITE,category-ads-all,REJECT",
    "GEOSITE,cn,DIRECT",
    "GEOSITE,geolocation-!cn,节点选择",
    "GEOIP,CN,DIRECT",
    "MATCH,节点选择",
];

/// `host:port` of the local clash API / mihomo controller.
pub fn controller() -> String {
    format!("{LOOPBACK}:{}", defaults::CLASH_API_PORT)
}

/// ALPN of a certificate (non-REALITY) TLS protocol; empty for AnyTLS and
/// for protocols without certificate TLS.
pub fn cert_alpn(protocol: Protocol) -> &'static [&'static str] {
    match protocol {
        Protocol::VlessWs | Protocol::VmessWs => &["http/1.1"],
        Protocol::Trojan => &["h2", "http/1.1"],
        Protocol::Hysteria2 | Protocol::Tuic => &["h3"],
        _ => &[],
    }
}

/// sing-box clients use uTLS except on QUIC protocols.
pub fn singbox_utls(protocol: Protocol) -> bool {
    !matches!(protocol, Protocol::Hysteria2 | Protocol::Tuic)
}

/// sing-box domain strategy for the server's outbound address families.
pub fn singbox_strategy(families: Families) -> &'static str {
    match families {
        Families::V4Only => "ipv4_only",
        Families::V6Only => "ipv6_only",
        Families::Dual => "prefer_ipv4",
    }
}

/// Xray freedom domain strategy for the server's address families.
pub fn xray_strategy(families: Families) -> &'static str {
    match families {
        Families::V4Only => "UseIPv4",
        Families::V6Only => "UseIPv6",
        Families::Dual => "UseIPv4v6",
    }
}

/// sing-box server route rules: sniff, then BitTorrent and egress to
/// private / own addresses rejected (domains resolved first so the address
/// check sees the real target).
pub fn singbox_server_rules(spec: &NodeSpec) -> Vec<Value> {
    let routing = &spec.routing;
    let mut rules = vec![json!({"action": "sniff"})];
    if routing.block_bt {
        rules.push(json!({"protocol": "bittorrent", "action": "reject"}));
    }
    if routing.block_private {
        let strategy = singbox_strategy(routing.families);
        rules.push(json!({"action": "resolve", "strategy": strategy}));
        rules.push(json!({"ip_is_private": true, "action": "reject"}));
        rules.push(json!({"ip_cidr": routing.blocked_cidrs, "action": "reject"}));
    }
    rules
}

/// Tag of the Xray REALITY guard inbound and its outbounds.
pub const XRAY_GUARD_TAG: &str = "reality-dest-in";
pub const XRAY_SITE_TAG: &str = "reality-site";

/// Xray server routing rules: the REALITY guard (only the exact SNI is
/// forwarded, everything else black-holed), BitTorrent, private egress.
pub fn xray_server_rules(spec: &NodeSpec) -> Vec<Value> {
    let mut rules = Vec::new();
    if let Some(reality) = spec.reality.as_ref().filter(|_| spec.uses_xray_reality()) {
        let target = if spec.site.is_some() {
            XRAY_SITE_TAG
        } else {
            "direct"
        };
        rules.push(json!({"type": "field", "inboundTag": [XRAY_GUARD_TAG],
            "domain": [format!("full:{}", reality.sni)], "outboundTag": target}));
        rules
            .push(json!({"type": "field", "inboundTag": [XRAY_GUARD_TAG], "outboundTag": "block"}));
    }
    if spec.routing.block_bt {
        rules.push(json!({"type": "field", "protocol": ["bittorrent"], "outboundTag": "block"}));
    }
    if spec.routing.block_private {
        rules.push(
            json!({"type": "field", "ip": spec.routing.blocked_cidrs, "outboundTag": "block"}),
        );
    }
    rules
}

/// sing-box client DNS rules: own endpoints resolved directly ahead of the
/// clash modes, so subscription refresh works even in Global mode.
pub fn singbox_client_dns_rules(direct: &DirectTargets) -> Vec<Value> {
    let mut rules = Vec::new();
    if !direct.domains.is_empty() {
        rules.push(json!({"domain": direct.domains, "server": "dns-direct"}));
    }
    rules.push(json!({"clash_mode": "Direct", "server": "dns-direct"}));
    rules.push(json!({"clash_mode": "Global", "server": "dns-remote"}));
    rules.push(json!({"rule_set": "geosite-cn", "server": "dns-direct"}));
    rules
}

/// sing-box client route rules (own endpoints direct before Global mode).
pub fn singbox_client_route_rules(direct: &DirectTargets) -> Vec<Value> {
    let mut rules = vec![
        json!({"action": "sniff"}),
        json!({"protocol": "dns", "action": "hijack-dns"}),
    ];
    if !direct.cidrs.is_empty() {
        rules.push(json!({"ip_cidr": direct.cidrs, "outbound": "direct"}));
    }
    if !direct.domains.is_empty() {
        rules.push(json!({"domain": direct.domains, "outbound": "direct"}));
    }
    rules.extend([
        json!({"ip_is_private": true, "outbound": "direct"}),
        json!({"clash_mode": "Direct", "outbound": "direct"}),
        json!({"clash_mode": "Global", "outbound": "proxy"}),
        json!({"rule_set": ["geosite-cn", "geoip-cn"], "outbound": "direct"}),
    ]);
    rules
}

pub fn singbox_rule_sets() -> Vec<Value> {
    SINGBOX_RULE_SETS
        .iter()
        .map(|(tag, url)| {
            json!({"type": "remote", "tag": tag, "format": "binary", "url": url,
                "download_detour": "direct"})
        })
        .collect()
}

fn full_domains(direct: &DirectTargets) -> Vec<String> {
    direct.domains.iter().map(|d| format!("full:{d}")).collect()
}

/// Xray client DNS servers (own endpoints first, via the domestic server).
pub fn xray_client_dns_servers(direct: &DirectTargets) -> Vec<Value> {
    let mut servers = Vec::new();
    if !direct.domains.is_empty() {
        servers.push(
            json!({"address": DNS_DIRECT, "domains": full_domains(direct),
            "skipFallback": true}),
        );
    }
    servers.push(json!(XRAY_DOH));
    servers.push(json!({"address": DNS_DIRECT, "domains": ["geosite:cn"],
        "expectIPs": ["geoip:cn"], "skipFallback": true}));
    servers
}

/// Xray client routing rules: own endpoints, the DNS server, private
/// ranges (declared order), ads blocked, mainland China direct.
pub fn xray_client_rules(direct: &DirectTargets) -> Vec<Value> {
    let mut rules = Vec::new();
    if !direct.cidrs.is_empty() {
        rules.push(json!({"type": "field", "ip": direct.cidrs, "outboundTag": "direct"}));
    }
    if !direct.domains.is_empty() {
        rules.push(
            json!({"type": "field", "domain": full_domains(direct), "outboundTag": "direct"}),
        );
    }
    rules.extend([
        json!({"type": "field", "ip": [DNS_DIRECT], "outboundTag": "direct"}),
        json!({"type": "field", "ip": PRIVATE_CIDRS, "outboundTag": "direct"}),
        json!({"type": "field", "domain": ["geosite:category-ads-all"], "outboundTag": "block"}),
        json!({"type": "field", "domain": ["geosite:cn"], "outboundTag": "direct"}),
        json!({"type": "field", "ip": ["geoip:cn"], "outboundTag": "direct"}),
    ]);
    rules
}

/// mihomo rules: own domains and addresses direct (IP rules never resolve),
/// then the fixed list.
pub fn mihomo_rules(direct: &DirectTargets) -> Vec<String> {
    let domains = direct.domains.iter().map(|d| format!("DOMAIN,{d},DIRECT"));
    let cidrs = direct.cidrs.iter().map(|cidr| {
        let kind = if cidr.contains(':') {
            "IP-CIDR6"
        } else {
            "IP-CIDR"
        };
        format!("{kind},{cidr},DIRECT,no-resolve")
    });
    domains
        .chain(cidrs)
        .chain(MIHOMO_RULES.iter().map(|r| r.to_string()))
        .collect()
}

/// mihomo `dns` section: fake-ip with own domains excluded from fake IPs
/// and resolved by domestic DoH.
pub fn mihomo_dns(direct: &DirectTargets) -> Value {
    let mut filter: Vec<String> = MIHOMO_FAKE_IP_FILTER
        .iter()
        .map(|s| s.to_string())
        .collect();
    filter.extend(direct.domains.iter().cloned());
    let mut policy = serde_json::Map::new();
    policy.insert("geosite:cn".into(), json!(DOH_CN));
    policy.insert("geosite:geolocation-!cn".into(), json!(DOH_GLOBAL));
    for domain in &direct.domains {
        policy.insert(domain.clone(), json!(DOH_CN));
    }
    json!({
        "enable": true, "ipv6": true,
        "listen": format!("{LOOPBACK}:{}", defaults::MIHOMO_DNS_PORT),
        "enhanced-mode": "fake-ip", "fake-ip-range": MIHOMO_FAKE_IP_RANGE,
        "fake-ip-filter": filter,
        "default-nameserver": MIHOMO_BOOTSTRAP_DNS,
        "nameserver": DOH_CN, "proxy-server-nameserver": DOH_CN,
        "nameserver-policy": policy,
    })
}

/// The client core a probe or a client document uses for `protocol` when
/// the server runs it on `server_core`: Xray clients for Xray-hosted
/// protocols Xray clients support, sing-box otherwise.
pub fn client_core(protocol: Protocol, server_core: Core) -> Core {
    let xray = crate::domain::ClientFormat::Xray.supports(protocol);
    if xray && server_core == Core::Xray {
        Core::Xray
    } else {
        Core::Singbox
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn direct(domains: &[&str], cidrs: &[&str]) -> DirectTargets {
        DirectTargets {
            domains: domains.iter().map(|s| s.to_string()).collect(),
            cidrs: cidrs.iter().map(|s| s.to_string()).collect(),
        }
    }

    #[test]
    fn strategies_follow_address_families() {
        let table = [
            (Families::V4Only, "ipv4_only", "UseIPv4"),
            (Families::V6Only, "ipv6_only", "UseIPv6"),
            (Families::Dual, "prefer_ipv4", "UseIPv4v6"),
        ];
        for (families, singbox, xray) in table {
            assert_eq!(singbox_strategy(families), singbox);
            assert_eq!(xray_strategy(families), xray);
        }
    }

    #[test]
    fn alpn_and_utls_per_protocol() {
        assert_eq!(cert_alpn(Protocol::Trojan), ["h2", "http/1.1"]);
        assert_eq!(cert_alpn(Protocol::VmessWs), ["http/1.1"]);
        assert_eq!(cert_alpn(Protocol::Tuic), ["h3"]);
        assert!(cert_alpn(Protocol::Anytls).is_empty());
        assert!(!singbox_utls(Protocol::Hysteria2));
        assert!(singbox_utls(Protocol::Anytls));
    }

    #[test]
    fn direct_rules_precede_global_mode_in_v2_order() {
        let d = direct(&["sub.example.com"], &["203.0.113.9/32"]);
        let route = singbox_client_route_rules(&d);
        assert_eq!(
            route[2],
            json!({"ip_cidr": ["203.0.113.9/32"], "outbound": "direct"})
        );
        assert_eq!(route[3]["domain"], json!(["sub.example.com"]));
        assert_eq!(route[4]["ip_is_private"], json!(true));
        assert_eq!(route.len(), 8);
        let dns = singbox_client_dns_rules(&d);
        assert_eq!(dns[0]["server"], "dns-direct");
        assert_eq!(dns.len(), 4);
        let xray = xray_client_rules(&d);
        assert_eq!(xray[0]["ip"], json!(["203.0.113.9/32"]));
        assert_eq!(xray[1]["domain"], json!(["full:sub.example.com"]));
        assert_eq!(
            xray_client_dns_servers(&d)[0]["domains"],
            json!(["full:sub.example.com"])
        );
    }

    #[test]
    fn empty_direct_targets_add_no_rules() {
        let d = direct(&[], &[]);
        assert_eq!(singbox_client_route_rules(&d).len(), 6);
        assert_eq!(singbox_client_dns_rules(&d).len(), 3);
        assert_eq!(xray_client_rules(&d).len(), 5);
        assert_eq!(xray_client_dns_servers(&d)[0], json!(XRAY_DOH));
        assert_eq!(mihomo_rules(&d), MIHOMO_RULES.map(String::from).to_vec());
    }

    #[test]
    fn mihomo_rules_and_dns_bypass_own_endpoints() {
        let d = direct(&["a.example.com"], &["192.0.2.1/32", "2001:db8::1/128"]);
        let rules = mihomo_rules(&d);
        assert_eq!(rules[0], "DOMAIN,a.example.com,DIRECT");
        assert_eq!(rules[1], "IP-CIDR,192.0.2.1/32,DIRECT,no-resolve");
        assert_eq!(rules[2], "IP-CIDR6,2001:db8::1/128,DIRECT,no-resolve");
        assert_eq!(rules[3], MIHOMO_RULES[0]);
        let dns = mihomo_dns(&d);
        assert_eq!(dns["nameserver-policy"]["a.example.com"], json!(DOH_CN));
        assert_eq!(dns["fake-ip-filter"][14], "a.example.com");
        assert_eq!(dns["listen"], "127.0.0.1:1053");
    }

    #[test]
    fn client_core_matches_server_core_when_xray_can_serve() {
        assert_eq!(client_core(Protocol::VlessXhttp, Core::Xray), Core::Xray);
        assert_eq!(client_core(Protocol::Trojan, Core::Xray), Core::Xray);
        assert_eq!(client_core(Protocol::Trojan, Core::Singbox), Core::Singbox);
        assert_eq!(client_core(Protocol::Tuic, Core::Xray), Core::Singbox);
        assert_eq!(controller(), "127.0.0.1:9090");
    }
}
