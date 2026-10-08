//! v2 states that v2 itself ran with must migrate (the in-place upgrade
//! cannot be blocked by server-side values), and leftovers that broke v2
//! clients are normalized.

use super::fields::v2_endpoint;
use super::fixtures::*;
use super::*;
use crate::domain::config::*;
use crate::domain::defaults;
use crate::domain::plan::{self, AddOptions, PlanEnv};
use crate::domain::Protocol::*;
use crate::sys::rand::SeqRandom;

/// Preset 4's site, then v2 `del vless-reality`: only
/// `REALITY_SITE_ENABLED` was cleared (spec B §3.5).
fn after_v2_del() -> BTreeMap<String, String> {
    with(
        preset1(),
        &[
            ("PROTOCOLS", "hysteria2 tuic"),
            ("REALITY_SITE_ENABLED", "0"),
            ("REALITY_SITE_DOMAIN", "www.example.com"),
            ("REALITY_SITE_PORT", "8443"),
            ("REALITY_SNI", "www.example.com"),
            ("REALITY_DEST", "127.0.0.1:8443"),
        ],
    )
}

#[test]
fn stale_site_target_left_by_v2_del_is_reset() {
    let m = run(&after_v2_del()).unwrap();
    assert!(m.config.site.is_none());
    assert_eq!(m.config.reality, defaults::reality_target(18000));
    assert_eq!(
        m.warnings,
        ["v2 REALITY 目标仍指向已停用的自建站 127.0.0.1:8443，已改为默认目标 www.microsoft.com:443"]
    );
    // Re-adding REALITY afterwards handshakes with the default target.
    let env = PlanEnv::offline(true, 0);
    let opts = AddOptions::default();
    let next = plan::add(&m.config, VlessReality, &opts, &env, &mut SeqRandom(3)).unwrap();
    assert_eq!(next.reality.sni, "www.microsoft.com");
    assert_eq!(next.reality.dest.to_string(), "www.microsoft.com:443");
    assert!(next.site.is_none());

    // v2 `del` then v2 `add vless-reality -y` kept the broken target.
    let readded = with(
        after_v2_del(),
        &[("PROTOCOLS", "vless-reality hysteria2 tuic")],
    );
    let m = run(&readded).unwrap();
    assert!(m.config.site.is_none());
    assert_eq!(m.config.reality.dest.to_string(), "www.microsoft.com:443");
    assert_eq!(m.warnings.len(), 1);
    assert!(m.warnings[0].ends_with("；请更新客户端"));

    // A site flag without REALITY: not migrated, target reset as well.
    let flagged = with(after_v2_del(), &[("REALITY_SITE_ENABLED", "1")]);
    let m = run(&flagged).unwrap();
    assert_eq!(m.config.reality.sni, "www.microsoft.com");
    assert_eq!(m.warnings.len(), 2);

    // Loopback targets that are not the old site (local test servers) stay.
    for extra in [("REALITY_SNI", "reality.test"), ("REALITY_SITE_DOMAIN", "")] {
        let kept = run(&with(after_v2_del(), &[extra])).unwrap();
        assert_eq!(kept.config.reality.dest.to_string(), "127.0.0.1:8443");
        assert!(kept.warnings.is_empty());
    }
}

fn relative_proxy_cert() -> BTreeMap<String, String> {
    with(
        preset1(),
        &[
            ("PROTOCOLS", "trojan"),
            ("PORT_trojan", "443"),
            ("TLS_MODE", "custom"),
            ("DOMAIN", "proxy.example.com"),
            ("CUSTOM_CERT", "fullchain.pem"),
            ("CUSTOM_KEY", "/root/privkey.pem"),
            ("CERT_PINNED", "0"),
        ],
    )
}

#[test]
fn relative_custom_sources_use_the_deployed_copies() {
    // v2 stored `--cert fullchain.pem` verbatim (resolved against the cwd).
    let m = run(&relative_proxy_cert()).unwrap();
    let Some(ProxyCertMode::Custom { cert, key, .. }) = m.config.tls.map(|t| t.mode) else {
        panic!("custom expected");
    };
    assert_eq!(cert.to_str(), Some("/etc/onebox/tls/cert.pem"));
    assert_eq!(key.to_str(), Some("/etc/onebox/tls/key.pem"));
    assert_eq!(
        m.warnings,
        ["v2 代理自备证书路径 CUSTOM_CERT=\"fullchain.pem\" CUSTOM_KEY=\"/root/privkey.pem\" 缺失或不是绝对路径，已改用已部署的 /etc/onebox/tls/cert.pem 和 /etc/onebox/tls/key.pem"]
    );

    let site = with(
        preset1(),
        &[
            ("REALITY_SITE_ENABLED", "1"),
            ("REALITY_SITE_DOMAIN", "www.example.com"),
            ("SITE_ACME_METHOD", "custom"),
            ("SITE_CUSTOM_CERT", "site/fullchain.pem"),
            ("SITE_CUSTOM_KEY", "/srv/site.key"),
        ],
    );
    let m = run(&site).unwrap();
    assert_eq!(
        m.config.site.unwrap().cert,
        WebCert::Custom {
            cert: "/etc/onebox/site/cert.pem".into(),
            key: "/etc/onebox/site/key.pem".into()
        }
    );
    assert_eq!(m.warnings.len(), 1);

    let mut sub = settings("standalone", "sub.example.com", 8448, "custom");
    sub["custom_cert"] = serde_json::json!("sub.pem");
    sub["custom_key"] = serde_json::json!("sub.key");
    let m = migrate_with(&preset1(), Some(&sub)).unwrap();
    let Some(SubscriptionMode::Standalone { cert, .. }) = m.config.subscription.map(|s| s.mode)
    else {
        panic!("standalone expected");
    };
    assert_eq!(
        cert,
        WebCert::Custom {
            cert: "/etc/onebox/subscription/tls/cert.pem".into(),
            key: "/etc/onebox/subscription/tls/key.pem".into()
        }
    );
    assert!(m.warnings[0].starts_with("v2 订阅自备证书路径 custom_cert=\"sub.pem\""));

    // The deployment directories follow ONEBOX_DIR.
    let paths = crate::paths::Paths::isolated(std::path::Path::new("/t"));
    let deployed = DeployedCerts::of(&paths);
    assert_eq!(deployed.site.to_str(), Some("/t/etc/site"));
    assert_eq!(
        deployed.subscription.to_str(),
        Some("/t/etc/subscription/tls")
    );
}

#[test]
fn v2_endpoint_rule() {
    let parse = |raw: &str| v2_endpoint(raw).map(|d| d.to_string());
    let cases = [
        ("www.microsoft.com:443", Some("www.microsoft.com:443")),
        ("2001:db8::1:443", Some("[2001:db8::1]:443")),
        ("[2001:db8::1]:443", Some("[2001:db8::1]:443")),
        ("[::ffff:127.0.0.1]:8443", Some("127.0.0.1:8443")),
        ("localhost:8443", Some("localhost:8443")),
        ("My_Host.lan:443", Some("my_host.lan:443")),
        (" 127.0.0.1:24443 ", Some("127.0.0.1:24443")),
        ("nohost", None),
        (":443", None),
        ("host:0", None),
        ("host:http", None),
        ("bad host:443", None),
    ];
    for (raw, want) in cases {
        assert_eq!(parse(raw).as_deref(), want, "{raw}");
    }
}

#[test]
fn handshake_targets_v2_ran_with_migrate() {
    let reality = |raw: &str| {
        let m = run(&with(preset1(), &[("REALITY_DEST", raw)])).unwrap();
        (m.config.reality.dest.to_string(), m.warnings)
    };
    assert_eq!(
        reality("2001:db8::1:443"),
        ("[2001:db8::1]:443".into(), vec![])
    );
    assert_eq!(reality("localhost:8443"), ("localhost:8443".into(), vec![]));
    // A value v2 could not render either falls back with a warning.
    assert_eq!(
        reality("nohost"),
        (
            "www.microsoft.com:443".into(),
            vec!["v2 字段 REALITY_DEST 无效，已改为 www.microsoft.com:443: nohost".to_owned()]
        )
    );

    let st = with(
        preset1(),
        &[
            ("PROTOCOLS", "shadowtls"),
            ("PORT_shadowtls", "443"),
            ("SHADOWTLS_SNI", "a.example.com"),
        ],
    );
    let shadowtls = |raw: &str| {
        let m = run(&with(st.clone(), &[("SHADOWTLS_DEST", raw)])).unwrap();
        (m.config.shadowtls.effective_dest(), m.warnings.len())
    };
    assert_eq!(
        shadowtls("2001:db8::2:8443"),
        ("[2001:db8::2]:8443".into(), 0)
    );
    assert_eq!(shadowtls("relay_1:8443"), ("relay_1:8443".into(), 0));
    assert_eq!(
        shadowtls("[a.example.com]:443"),
        ("a.example.com:443".into(), 0)
    );
    assert_eq!(shadowtls("x:y"), ("a.example.com:443".into(), 1));

    // What was migrated is saved and loaded again unchanged.
    let m = run(&with(preset1(), &[("REALITY_DEST", "localhost:8443")])).unwrap();
    let json = serde_json::to_value(&m.config).unwrap();
    assert_eq!(
        serde_json::from_value::<NodeConfig>(json).unwrap(),
        m.config
    );
}

#[test]
fn plain_vmess_keeps_its_host_header() {
    // Preset 5 behind a CDN: SERVER_ADDR is a CDN IP, clients send
    // `Host: DOMAIN`, the certificate stays self-signed for VLESS-WS.
    let cdn = with(
        preset1(),
        &[
            ("PROTOCOLS", "vless-ws vmess-ws"),
            ("PORT_vless_ws", "443"),
            ("PORT_vmess_ws", "8080"),
            ("TLS_MODE", "self"),
            ("DOMAIN", "CDN.Example.com"),
            ("VMESS_TLS", "0"),
        ],
    );
    let m = run(&cdn).unwrap();
    assert!(m.warnings.is_empty());
    assert!(!m.config.vmess_tls);
    assert_eq!(m.config.vmess_host.as_deref(), Some("cdn.example.com"));
    assert_eq!(
        m.config.tls.as_ref().map(|t| t.mode.server_name()),
        Some("www.bing.com")
    );
    // A DOMAIN that is no domain cannot be a Host header any more.
    let m = run(&with(cdn.clone(), &[("DOMAIN", "203.0.113.9")])).unwrap();
    assert_eq!(m.config.vmess_host, None);
    assert_eq!(
        m.warnings,
        ["v2 字段 DOMAIN 不是有效域名，VMess-WS 不再发送该 Host 头: 203.0.113.9"]
    );
    // Without VMess-WS, DOMAIN only names the certificate.
    let m = run(&with(cdn, &[("PROTOCOLS", "vless-ws")])).unwrap();
    assert_eq!(m.config.vmess_host, None);
}
