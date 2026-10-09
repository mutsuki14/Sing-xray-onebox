use super::*;
use crate::domain::config::ProxyTls;
use crate::domain::{fixtures, Core, Protocol};
use crate::frp::model::{BindAddr, Mode, WebSettings};

#[test]
fn ip_literals_are_replaced() {
    let r = Redactor::new();
    let cases = [
        (
            "dial tcp 203.0.113.10:443: refused",
            "dial tcp <ip>:443: refused",
        ),
        (
            "listen [2001:db8::1]:8443 failed",
            "listen [<ip>]:8443 failed",
        ),
        (
            "own 198.51.100.7/32 and 2001:db8::5/128",
            "own <ip>/32 and <ip>/128",
        ),
        ("bound to ::ffff:192.0.2.1.", "bound to <ip>."),
        ("address fe80::1: no route", "address <ip>: no route"),
        ("连接 192.0.2.44 失败", "连接 <ip> 失败"),
        // Not addresses: versions, times, identifiers, ports.
        ("sing-box 1.14.2", "sing-box 1.14.2"),
        ("at 18:19:13 GMT", "at 18:19:13 GMT"),
        ("crate::diag::checks", "crate::diag::checks"),
        ("port 8443/udp", "port 8443/udp"),
        ("v1.2.3.4", "v1.2.3.4"),
    ];
    for (text, want) in cases {
        assert_eq!(r.redact(text), want, "{text}");
    }
}

#[test]
fn domain_names_are_replaced_but_file_names_kept() {
    let r = Redactor::new();
    let cases = [
        (
            "certificate for blog.example.org expired",
            "certificate for <domain> expired",
        ),
        (
            "https://sub.example.org:8448/sub/x",
            "https://<domain>:8448/sub/x",
        ),
        (
            "/etc/letsencrypt/live/example.com/fullchain.pem",
            "/etc/letsencrypt/live/<domain>/fullchain.pem",
        ),
        ("域名example.net无效。", "域名<domain>无效。"),
        ("mail admin@example.com.", "mail admin@<domain>."),
        (
            "open /etc/onebox/sing-box.json: denied",
            "open /etc/onebox/sing-box.json: denied",
        ),
        ("nginx.conf test failed", "nginx.conf test failed"),
        ("run acme.sh --cron", "run acme.sh --cron"),
        ("onebox-xray.service failed", "onebox-xray.service failed"),
        ("e.g. 3.x or v2.0.1", "e.g. 3.x or v2.0.1"),
        ("plain words stay", "plain words stay"),
    ];
    for (text, want) in cases {
        assert_eq!(r.redact(text), want, "{text}");
    }
}

#[test]
fn looks_like_domain_rules() {
    for yes in [
        "example.com",
        "a.b.example.co",
        "xn--fiqs8s.cn",
        "WWW.Example.ORG",
    ] {
        assert!(looks_like_domain(yes), "{yes}");
    }
    for no in [
        "example",
        "1.14.2",
        "sing-box.json",
        "a.b",
        "-x.com",
        "x-.com",
        "example.c0m",
        "",
        "..",
        "under_score.com",
    ] {
        assert!(!looks_like_domain(no), "{no}");
    }
}

#[test]
fn known_values_are_replaced_longest_first() {
    let mut r = Redactor::new();
    r.add("example.org", DOMAIN);
    r.add("deep.sub.example.org", DOMAIN);
    r.add("s3cret-value-123", SECRET);
    r.add("abc", SECRET);
    assert_eq!(
        r.redact("deep.sub.example.org / example.org / s3cret-value-123 / abc"),
        "<domain> / <domain> / <secret> / abc",
        "values shorter than 4 characters are not known values"
    );
    let mut dup = r.clone();
    dup.add("example.org", SECRET);
    assert_eq!(
        dup.redact("example.org"),
        "<domain>",
        "first placeholder wins"
    );
}

#[test]
fn every_node_and_frp_value_is_known() {
    let mut cfg = fixtures::with_site(
        fixtures::config(&[
            (Protocol::VlessReality, 443, Core::Singbox),
            (Protocol::Trojan, 8443, Core::Xray),
        ]),
        "blog.example.org",
        false,
    );
    cfg.server.addr = "node.example.net".parse().unwrap();
    cfg.server.ipv6 = Some("2001:db8::10".parse().unwrap());
    cfg.routing.own_cidrs = vec!["198.51.100.20/32".into()];
    cfg.tls = Some(ProxyTls {
        mode: crate::domain::config::ProxyCertMode::Custom {
            domain: "proxy.example.net".into(),
            cert: "/srv/keys/node-cert.pem".into(),
            key: "/srv/keys/node-key.pem".into(),
        },
        pinned: true,
    });
    cfg.subscription = Some(fixtures::standalone_subscription(
        "feed.example.io",
        8448,
        crate::domain::config::WebCert::Cloudflare,
    ));
    let frp = FrpState::new(
        "frp.example.dev".into(),
        "f00d".repeat(16),
        BindAddr::AnyV4,
        Mode::Web(WebSettings::new(
            AppDomain::Wildcard {
                root: "apps.example.dev".into(),
            },
            WebTls::Custom {
                cert: "/srv/frp/c.pem".into(),
                key: "/srv/frp/k.pem".into(),
            },
        )),
    );
    let r = Redactor::for_node(Some(&cfg), Some(&frp));
    let c = &cfg.creds;
    let keys = c.reality.clone().unwrap();
    let sensitive = [
        c.uuid.clone(),
        c.password.clone(),
        c.ss_password.clone(),
        c.hy2_obfs_password.clone(),
        c.shadowtls_password.clone(),
        c.shadowtls_ss_password.clone(),
        c.clash_secret.clone(),
        c.ws_path.clone(),
        c.xhttp_path.clone(),
        c.grpc_service.clone(),
        keys.private_key,
        keys.public_key,
        keys.short_id,
        "node.example.net".into(),
        "203.0.113.10".into(),
        "2001:db8::10".into(),
        "198.51.100.20".into(),
        "blog.example.org".into(),
        "proxy.example.net".into(),
        "/srv/keys/node-key.pem".into(),
        "feed.example.io".into(),
        "frp.example.dev".into(),
        "apps.example.dev".into(),
        "f00d".repeat(16),
        "/srv/frp/k.pem".into(),
        cfg.reality.sni.clone(),
        cfg.shadowtls.sni.clone(),
    ];
    let text = sensitive.join(" | ");
    let redacted = r.redact(&text);
    for value in &sensitive {
        assert!(
            !redacted.contains(value.as_str()),
            "{value} leaked: {redacted}"
        );
    }
    assert!(!contains_ip(&redacted), "{redacted}");
    assert!(redacted.contains(SECRET) && redacted.contains(DOMAIN) && redacted.contains(IP));
}

#[test]
fn contains_ip_detects_literals() {
    assert!(contains_ip("x 203.0.113.1 y"));
    assert!(contains_ip("[2001:db8::1]:443"));
    assert!(!contains_ip("<ip>:443 and 1.14.2 at 18:19:13"));
}
