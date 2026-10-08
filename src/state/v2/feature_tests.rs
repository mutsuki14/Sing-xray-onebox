//! Migration of the website, routing, guard, subscription and file shape.

use super::fixtures::*;
use super::*;
use crate::domain::config::*;
use crate::domain::{Core, Protocol};
use std::net::IpAddr;

#[test]
fn site_port_derivation_and_https_default() {
    let site = with(
        preset1(),
        &[
            ("REALITY_SITE_ENABLED", "1"),
            ("REALITY_SITE_DOMAIN", "www.example.com"),
        ],
    );
    let port = |extra: &[(&str, &str)]| {
        let m = run(&with(site.clone(), extra)).unwrap();
        let s = m.config.site.clone().unwrap();
        (
            s.internal_port,
            s.https_entry,
            m.config.reality.dest.to_string(),
        )
    };
    assert_eq!(
        port(&[
            ("REALITY_DEST", "127.0.0.1:8443"),
            ("REALITY_SITE_PORT", "9000")
        ]),
        (8443, true, "127.0.0.1:8443".into())
    );
    assert_eq!(
        port(&[("REALITY_SITE_PORT", "9000")]),
        (9000, true, "127.0.0.1:9000".into())
    );
    assert_eq!(port(&[]), (10443, true, "127.0.0.1:10443".into()));
    assert!(!port(&[("REALITY_SITE_HTTPS", "0")]).1);
    assert!(port(&[("REALITY_SITE_HTTPS", "1")]).1);

    let m = run(&with(site.clone(), &[("SITE_ACME_METHOD", "standalone")])).unwrap();
    assert_eq!(m.config.site.unwrap().cert, WebCert::Http01);
    let custom = with(
        site.clone(),
        &[
            ("SITE_ACME_METHOD", "custom"),
            ("SITE_CUSTOM_CERT", "/srv/site.pem"),
            ("SITE_CUSTOM_KEY", "/srv/site.key"),
        ],
    );
    let m = run(&custom).unwrap();
    assert_eq!(
        m.config.site.unwrap().cert,
        WebCert::Custom {
            cert: "/srv/site.pem".into(),
            key: "/srv/site.key".into()
        }
    );
    // A missing source falls back to the deployed site pair.
    let m = run(&with(custom, &[("SITE_CUSTOM_KEY", "")])).unwrap();
    assert_eq!(
        m.config.site.unwrap().cert,
        WebCert::Custom {
            cert: "/etc/onebox/site/cert.pem".into(),
            key: "/etc/onebox/site/key.pem".into()
        }
    );
    assert_eq!(m.warnings.len(), 1);
    assert_eq!(
        err(&with(site.clone(), &[("SITE_ACME_METHOD", "self")])),
        "v2 字段 SITE_ACME_METHOD 无效: self"
    );
    assert_eq!(
        err(&with(site.clone(), &[("REALITY_SITE_DOMAIN", "")])),
        "v2 字段 REALITY_SITE_DOMAIN 无效: "
    );
    // Without REALITY the site was inactive in v2.
    let inactive = with(
        site,
        &[("PROTOCOLS", "hysteria2 tuic"), ("SITE_TEMPLATE", "bogus")],
    );
    let m = run(&inactive).unwrap();
    assert!(m.config.site.is_none());
    assert_eq!(m.warnings, ["v2 网站已随 REALITY 协议停用，网站设置未迁移"]);
}

#[test]
fn shadowtls_default_target_is_dropped() {
    let st = with(
        preset1(),
        &[("PROTOCOLS", "shadowtls"), ("PORT_shadowtls", "443")],
    );
    let m = run(&with(
        st.clone(),
        &[
            ("SHADOWTLS_SNI", "a.example.com"),
            ("SHADOWTLS_DEST", "a.example.com:443"),
        ],
    ))
    .unwrap();
    assert_eq!(m.config.shadowtls.dest, None);
    let m = run(&with(
        st,
        &[
            ("SHADOWTLS_SNI", "a.example.com"),
            ("SHADOWTLS_DEST", "a.example.com:8443"),
        ],
    ))
    .unwrap();
    assert_eq!(m.config.shadowtls.effective_dest(), "a.example.com:8443");
}

#[test]
fn routing_and_misc_keys() {
    let cidrs = |raw: &str| {
        let m = run(&with(preset1(), &[("OWN_IP_CIDRS", raw)])).unwrap();
        (m.config.routing.own_cidrs, m.warnings)
    };
    assert_eq!(
        cidrs("[\"9.9.9.9/32\",\"2001:db8::1/128\"]").0,
        ["9.9.9.9/32", "2001:db8::1/128"]
    );
    assert_eq!(cidrs("\"9.9.9.9/32\"").0, ["9.9.9.9/32"]);
    assert_eq!(
        cidrs("9.9.9.9/32, 8.8.8.8/32").0,
        ["9.9.9.9/32", "8.8.8.8/32"]
    );
    let (good, warnings) = cidrs("[\"9.9.9.9/32\",\"nope\",\"9.9.9.9/32\"]");
    assert_eq!(good, ["9.9.9.9/32"]);
    assert_eq!(warnings, ["OWN_IP_CIDRS 含无效条目，已忽略: nope"]);

    let m = run(&with(
        preset1(),
        &[
            ("BLOCK_PRIVATE", "0"),
            ("BLOCK_BT", "true"),
            ("SERVER_IPV4_WARP", "1"),
            ("NODE_NAME", "东京-01"),
            ("CERT_RENEW_PROXY", "1"),
            ("RESTORE_PENDING_ID", "x"),
            ("SITE_CONTENT_PENDING_TEXT", "<html>"),
            ("SUBSCRIPTION_SETTINGS_PENDING", "{}"),
            ("SUBSCRIPTION_SETTINGS_EXPECTED", "absent"),
            ("__EXPECTED_STATE_HASH", "abc"),
            ("XR_XHTTP_SOCK", "@x"),
            ("PORT_shadowtls", "1"),
            ("FOO", "1"),
            ("PORT_bogus", "1"),
        ],
    ))
    .unwrap();
    assert!(!m.config.routing.block_private);
    assert!(m.config.routing.block_bt, "only \"0\" disables");
    assert!(m.config.server.ipv4_warp);
    assert_eq!(m.config.node_name, "东京-01");
    assert_eq!(m.warnings, ["已忽略未知的 v2 字段: FOO, PORT_bogus"]);

    let m = run(&with(
        preset1(),
        &[("LISTEN_ADDR", ""), ("INSTALLED_AT", "soon")],
    ))
    .unwrap();
    assert_eq!(m.config.listen.to_string(), "0.0.0.0");
    assert_eq!(m.config.installed_at, 0);
    assert_eq!(m.warnings.len(), 2);
}

#[test]
fn guard_is_allocated_when_missing() {
    let xray = with(
        preset1(),
        &[
            ("CORE_vless_reality", "xray"),
            ("REALITY_GUARD_PORT", ""),
            ("PORT_vless_reality", "18000"),
        ],
    );
    let m = run(&xray).unwrap();
    assert_eq!(m.config.reality.guard_port, 18001);
    assert_eq!(m.warnings, ["v2 状态缺少 REALITY_GUARD_PORT，已分配 18001"]);
    let singbox = run(&with(preset1(), &[("REALITY_GUARD_PORT", "")])).unwrap();
    assert_eq!(singbox.config.reality.guard_port, 18000);
    assert!(singbox.warnings.is_empty());
}

#[test]
fn subscription_settings() {
    let ip = settings("ip", "203.0.113.10", 8448, "none");
    let m = migrate_with(&preset1(), Some(&ip)).unwrap();
    assert_eq!(
        m.config.subscription,
        Some(SubscriptionConfig {
            mode: SubscriptionMode::Ip {
                address: "203.0.113.10".parse::<IpAddr>().unwrap()
            },
            port: 8448
        })
    );
    assert_eq!(m.devices.as_ref().map(Vec::len), Some(2));

    let mut disabled = ip.clone();
    disabled["enabled"] = serde_json::json!(false);
    let m = migrate_with(&preset1(), Some(&disabled)).unwrap();
    assert_eq!(m.config.subscription, None);
    assert_eq!(
        m.devices.map(|d| d.len()),
        Some(2),
        "devices survive a disabled subscription"
    );

    let site_values = with(
        preset1(),
        &[
            ("REALITY_SITE_ENABLED", "1"),
            ("REALITY_SITE_DOMAIN", "www.example.com"),
        ],
    );
    let site = settings("site", "www.example.com", 443, "cf");
    let m = migrate_with(&site_values, Some(&site)).unwrap();
    assert_eq!(
        m.config.subscription,
        Some(SubscriptionConfig {
            mode: SubscriptionMode::Site,
            port: 443
        })
    );
    let m = migrate_with(&preset1(), Some(&site)).unwrap();
    assert_eq!(m.config.subscription, None);
    assert_eq!(
        m.warnings,
        ["v2 订阅复用的网站未启用，订阅已关闭（设备保留）"]
    );

    let http = settings("standalone", "Sub.Example.com", 8443, "http");
    let m = migrate_with(&preset1(), Some(&http)).unwrap();
    assert_eq!(
        m.config.subscription.unwrap().mode,
        SubscriptionMode::Standalone {
            domain: "sub.example.com".into(),
            cert: WebCert::Http01,
            http01_port80: true
        }
    );
    let mut custom = settings("standalone", "sub.example.com", 8443, "custom");
    let m = migrate_with(&preset1(), Some(&custom)).unwrap();
    assert!(
        matches!(
            m.config.subscription.unwrap().mode,
            SubscriptionMode::Standalone {
                cert: WebCert::Custom { ref cert, .. },
                ..
            } if cert.to_str() == Some("/etc/onebox/subscription/tls/cert.pem")
        ),
        "missing sources fall back to the deployed pair"
    );
    custom["custom_cert"] = serde_json::json!("/srv/sub.pem");
    custom["custom_key"] = serde_json::json!("/srv/sub.key");
    let m = migrate_with(&preset1(), Some(&custom)).unwrap();
    assert!(matches!(
        m.config.subscription.unwrap().mode,
        SubscriptionMode::Standalone {
            cert: WebCert::Custom { .. },
            ..
        }
    ));

    let cases = [
        (
            settings("ip", "sub.example.com", 8448, "none"),
            "v2 订阅地址无效: sub.example.com",
        ),
        (settings("cdn", "x", 1, "cf"), "v2 订阅托管模式无效: cdn"),
        (
            settings("standalone", "bad", 1, "cf"),
            "v2 订阅域名无效: bad",
        ),
        (
            settings("standalone", "a.example.com", 1, "self"),
            "v2 订阅证书方式无效: self",
        ),
    ];
    for (s, want) in cases {
        let e = migrate_with(&preset1(), Some(&s)).unwrap_err();
        assert_eq!(e.to_string(), want);
    }
    let broken = serde_json::json!({"enabled": "yes"});
    let e = migrate_with(&preset1(), Some(&broken)).unwrap_err();
    assert!(e.to_string().starts_with("v2 订阅设置无效"));
}

#[test]
fn values_file_shape() {
    let values = v2_values_from_json(&file(&preset1())).unwrap();
    assert_eq!(values, preset1());
    assert_eq!(v2_values_from_json(b"{}").unwrap(), BTreeMap::new());
    assert_eq!(
        v2_values_from_json(br#"{"values":{"PORT_tuic":443}}"#)
            .unwrap_err()
            .to_string(),
        "v2 状态值必须为字符串: PORT_tuic"
    );
    assert!(v2_values_from_json(b"[]").is_err());
    assert!(v2_values_from_json(b"{\"values\":[]}").is_err());
    assert!(v2_values_from_json(b"not json").is_err());
    assert_eq!(err(&BTreeMap::new()), "状态缺少协议列表");
}

/// The state shape v2's `tests/native_e2e.py` wrote for its protocol × core
/// matrix (single protocol, loopback targets, custom or self-signed TLS).
fn e2e_state(protocol: Protocol, core: Core, ca: bool) -> BTreeMap<String, String> {
    let (private, public) = reality_pair();
    let key = protocol.id().replace('-', "_");
    let flag = |on: bool| if on { "1" } else { "0" };
    let mut values = map(&[
        ("SERVER_ADDR", "127.0.0.1"),
        ("SERVER_IPV4", "127.0.0.1"),
        ("SERVER_IPV6", ""),
        ("LISTEN_ADDR", "127.0.0.1"),
        ("NODE_NAME", "native-e2e"),
        ("UUID", UUID),
        (
            "PASSWORD",
            "0123456789abcdef0123456789abcdef0123456789abcdef",
        ),
        ("SS_METHOD", "2022-blake3-aes-128-gcm"),
        ("SS_PASSWORD", SS_KEY_16),
        ("SHADOWTLS_PASSWORD", PASSWORD),
        ("SHADOWTLS_SS_PASSWORD", SS_KEY_16),
        ("REALITY_SHORT_ID", "0011223344556677"),
        ("REALITY_SNI", "reality.test"),
        ("REALITY_DEST", "127.0.0.1:24443"),
        ("SHADOWTLS_SNI", "reality.test"),
        ("SHADOWTLS_DEST", "127.0.0.1:24443"),
        ("REALITY_GUARD_PORT", "24001"),
        ("REALITY_SITE_ENABLED", "0"),
        ("REALITY_SITE_HTTPS", "0"),
        ("WS_PATH", "/native-ws"),
        ("VMESS_PATH", "/native-vmess"),
        ("XHTTP_PATH", "/native-xhttp"),
        ("GRPC_SERVICE", "native-grpc"),
        ("VMESS_TLS", flag(ca)),
        ("HY2_OBFS", flag(ca)),
        ("HY2_OBFS_PASSWORD", PASSWORD),
        ("HY2_PROFILE", "auto"),
        ("RESOURCE_PROFILE", "balanced"),
        ("TLS_MODE", if ca { "custom" } else { "self" }),
        ("TLS_SNI", "onebox.test"),
        ("DOMAIN", "onebox.test"),
        ("CERT_PINNED", flag(!ca)),
        ("CERT_FILE", "/tmp/pki/onebox.test.pem"),
        ("KEY_FILE", "/tmp/pki/onebox.test.key"),
        ("BLOCK_PRIVATE", "0"),
        ("BLOCK_BT", "1"),
        ("SB_VERSION", "latest"),
        ("XR_VERSION", "latest"),
        ("PROTOCOLS", protocol.id()),
    ]);
    values.insert(format!("PORT_{key}"), "24100".into());
    values.insert(format!("CORE_{key}"), core.id().into());
    values.insert("REALITY_PRIVATE_KEY".into(), private);
    values.insert("REALITY_PUBLIC_KEY".into(), public);
    values
}

#[test]
fn every_v2_e2e_matrix_state_migrates() {
    for protocol in crate::domain::Protocol::ALL {
        for &core in protocol.cores() {
            for ca in [false, true] {
                let m = run(&e2e_state(protocol, core, ca))
                    .unwrap_or_else(|e| panic!("{protocol}/{core}/{ca}: {e}"));
                let c = &m.config;
                assert_eq!(c.listen.to_string(), "127.0.0.1");
                assert_eq!(c.reality.dest.to_string(), "127.0.0.1:24443");
                assert_eq!(
                    c.shadowtls.effective_dest(),
                    "127.0.0.1:24443",
                    "explicit ShadowTLS target kept"
                );
                assert!(!c.routing.block_private);
                if protocol == Protocol::Hysteria2 && core == Core::Xray {
                    assert_eq!(c.hy2.profile, None, "Xray cannot apply tuning");
                } else if protocol == Protocol::Hysteria2 {
                    assert_eq!(c.hy2.profile, Some(Hy2Profile::Auto));
                }
                match &c.tls {
                    Some(ProxyTls {
                        mode: ProxyCertMode::Custom { cert, .. },
                        pinned,
                    }) => {
                        assert!(ca && !pinned);
                        assert_eq!(cert.to_str(), Some("/tmp/pki/onebox.test.pem"));
                    }
                    Some(ProxyTls {
                        mode: ProxyCertMode::SelfSigned { sni },
                        pinned,
                    }) => assert!(!ca && *pinned && sni == "onebox.test"),
                    Some(other) => panic!("unexpected {other:?}"),
                    None => assert!(!c.needs_cert()),
                }
                assert_eq!(c.vmess_tls, ca && protocol == Protocol::VmessWs);
            }
        }
    }
}

#[test]
fn core_pins_survive_only_when_they_match_the_installed_core() {
    // (installed SB_VERSION, SB_VERSION_WANT, migrated pin, warning)
    let cases: [(&str, &str, Option<&str>, Option<&str>); 12] = [
        ("1.12.0", "1.12.0", Some("1.12.0"), None),
        ("1.12.0", "v1.12.0", Some("1.12.0"), None),
        ("", "1.12.0", Some("1.12.0"), None),
        ("1.14.2", "latest", None, None),
        ("1.14.2", "", None, None),
        (
            "1.14.2",
            "1.12.0",
            None,
            Some("v2 固定的 sing-box 版本 1.12.0 与已安装 1.14.2 不一致，已取消固定"),
        ),
        (
            "v1.14.2",
            "v1.12.0",
            None,
            Some("v2 固定的 sing-box 版本 1.12.0 与已安装 v1.14.2 不一致，已取消固定"),
        ),
        // v2 stored `--singbox-version` as given: pins host::cores could
        // never resolve are dropped even with nothing recorded as installed.
        (
            "",
            "beta",
            None,
            Some("v2 固定的 sing-box 版本 beta 无效，已取消固定"),
        ),
        (
            "",
            "1.12.0+x",
            None,
            Some("v2 固定的 sing-box 版本 1.12.0+x 无效，已取消固定"),
        ),
        (
            "",
            "LATEST",
            None,
            Some("v2 固定的 sing-box 版本 LATEST 无效，已取消固定"),
        ),
        (
            "1.14.2",
            "v_1",
            None,
            Some("v2 固定的 sing-box 版本 _1 无效，已取消固定"),
        ),
        ("", "v", None, None),
    ];
    for (installed, wanted, pin, warning) in cases {
        let values = with(
            preset1(),
            &[("SB_VERSION", installed), ("SB_VERSION_WANT", wanted)],
        );
        let m = run(&values).unwrap();
        let case = format!("installed {installed:?}, wanted {wanted:?}");
        assert_eq!(m.config.versions.singbox_pin.as_deref(), pin, "{case}");
        let installed = (!installed.is_empty()).then_some(installed);
        assert_eq!(m.config.versions.singbox.as_deref(), installed, "{case}");
        let want: Vec<&str> = warning.into_iter().collect();
        assert_eq!(m.warnings, want, "{case}");
    }
}

#[test]
fn xray_pin_is_checked_against_the_xray_version() {
    let values = with(
        preset1(),
        &[
            ("XR_VERSION", "26.3.27"),
            ("XR_VERSION_WANT", "25.1.1"),
            ("SB_VERSION_WANT", "1.12.0"),
        ],
    );
    let m = run(&values).unwrap();
    let v = &m.config.versions;
    assert_eq!(v.xray_pin, None);
    assert_eq!(v.singbox_pin.as_deref(), Some("1.12.0"), "sing-box matches");
    assert_eq!(
        m.warnings,
        ["v2 固定的 Xray 版本 25.1.1 与已安装 26.3.27 不一致，已取消固定"]
    );
}
