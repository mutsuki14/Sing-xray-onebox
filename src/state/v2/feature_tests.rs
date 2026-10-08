//! Migration of the website, routing, guard, subscription and file shape.

use super::fixtures::*;
use super::*;
use crate::domain::config::*;
use crate::sys::rand::SeqRandom;
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
    assert_eq!(
        err(&with(custom, &[("SITE_CUSTOM_KEY", "")])),
        "v2 状态缺少 SITE_CUSTOM_KEY"
    );
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
    let m = migrate(&preset1(), Some(&ip), &mut SeqRandom(1)).unwrap();
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
    let m = migrate(&preset1(), Some(&disabled), &mut SeqRandom(1)).unwrap();
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
    let m = migrate(&site_values, Some(&site), &mut SeqRandom(1)).unwrap();
    assert_eq!(
        m.config.subscription,
        Some(SubscriptionConfig {
            mode: SubscriptionMode::Site,
            port: 443
        })
    );
    let m = migrate(&preset1(), Some(&site), &mut SeqRandom(1)).unwrap();
    assert_eq!(m.config.subscription, None);
    assert_eq!(
        m.warnings,
        ["v2 订阅复用的网站未启用，订阅已关闭（设备保留）"]
    );

    let http = settings("standalone", "Sub.Example.com", 8443, "http");
    let m = migrate(&preset1(), Some(&http), &mut SeqRandom(1)).unwrap();
    assert_eq!(
        m.config.subscription.unwrap().mode,
        SubscriptionMode::Standalone {
            domain: "sub.example.com".into(),
            cert: WebCert::Http01,
            http01_port80: true
        }
    );
    let mut custom = settings("standalone", "sub.example.com", 8443, "custom");
    let e = migrate(&preset1(), Some(&custom), &mut SeqRandom(1)).unwrap_err();
    assert_eq!(e.to_string(), "v2 订阅自备证书缺少 custom_cert/custom_key");
    custom["custom_cert"] = serde_json::json!("/srv/sub.pem");
    custom["custom_key"] = serde_json::json!("/srv/sub.key");
    let m = migrate(&preset1(), Some(&custom), &mut SeqRandom(1)).unwrap();
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
        let e = migrate(&preset1(), Some(&s), &mut SeqRandom(1)).unwrap_err();
        assert_eq!(e.to_string(), want);
    }
    let broken = serde_json::json!({"enabled": "yes"});
    let e = migrate(&preset1(), Some(&broken), &mut SeqRandom(1)).unwrap_err();
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
