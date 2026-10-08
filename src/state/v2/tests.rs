use super::fixtures::*;
use super::*;
use crate::domain::config::*;
use crate::domain::protocol::{Core, Protocol};
use crate::sys::rand::SeqRandom;
use std::net::IpAddr;
use Core::{Singbox as SB, Xray as XR};
use Protocol::*;

fn run(values: &BTreeMap<String, String>) -> Result<Migrated> {
    migrate(values, None, &mut SeqRandom(42))
}

fn with(mut values: BTreeMap<String, String>, pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
    for (k, v) in pairs {
        if v.is_empty() {
            values.remove(*k);
        } else {
            values.insert(k.to_string(), v.to_string());
        }
    }
    values
}

fn err(values: &BTreeMap<String, String>) -> String {
    run(values).unwrap_err().to_string()
}

fn layout(cfg: &NodeConfig) -> Vec<(Protocol, u16, Core)> {
    cfg.inbounds
        .iter()
        .map(|i| (i.protocol, i.port, i.core))
        .collect()
}

#[test]
fn preset1_self_signed_field_by_field() {
    let m = run(&preset1()).unwrap();
    let c = &m.config;
    assert_eq!(m.warnings, Vec::<String>::new());
    assert_eq!(m.devices, None);
    assert_eq!(c.schema, 3);
    assert_eq!(
        layout(c),
        [
            (VlessReality, 443, SB),
            (Hysteria2, 443, SB),
            (Tuic, 8443, SB)
        ]
    );
    assert_eq!(c.node_name, "onebox");
    assert_eq!(c.server.addr.to_string(), "203.0.113.10");
    assert_eq!(c.server.ipv4, Some("203.0.113.10".parse().unwrap()));
    assert_eq!(c.server.ipv6, None);
    assert_eq!(c.listen.to_string(), "::");
    let (private, public) = reality_pair();
    assert_eq!(c.creds.uuid, UUID);
    assert_eq!(c.creds.password, PASSWORD);
    assert_eq!(c.creds.ss_password, SS_KEY_16);
    assert_eq!(c.creds.clash_secret, CLASH);
    assert_eq!(c.creds.grpc_service, "a1b2c3d4e5f6");
    assert_eq!(c.creds.xhttp_path, "/a1b2c3d4e5f9");
    let keys = c.creds.reality.as_ref().unwrap();
    assert_eq!((&keys.private_key, &keys.public_key), (&private, &public));
    assert_eq!(keys.short_id, "0123456789abcdef");
    assert_eq!(c.reality.sni, "www.microsoft.com");
    assert_eq!(c.reality.dest.to_string(), "www.microsoft.com:443");
    assert_eq!(c.reality.guard_port, 18000);
    assert_eq!(c.shadowtls, crate::domain::defaults::shadowtls());
    assert_eq!(
        c.tls,
        Some(ProxyTls {
            mode: ProxyCertMode::SelfSigned {
                sni: "www.bing.com".into()
            },
            pinned: true
        })
    );
    assert!(!c.vmess_tls);
    assert_eq!(c.hy2, Hy2Settings::default());
    assert_eq!(c.resource_profile, ResourceProfile::Balanced);
    assert_eq!(c.routing.own_cidrs, ["203.0.113.10/32"]);
    assert!(c.routing.block_private && c.routing.block_bt);
    assert_eq!(c.versions.singbox.as_deref(), Some("1.12.0"));
    assert_eq!(c.versions.singbox_pin, None);
    assert_eq!(c.installed_at, 1_791_000_000);
    assert!(c.site.is_none() && c.subscription.is_none());
}

fn preset4_site() -> BTreeMap<String, String> {
    with(
        preset1(),
        &[
            (
                "PROTOCOLS",
                "vless-reality vless-grpc trojan shadowsocks hysteria2 tuic anytls shadowtls vmess-ws",
            ),
            ("PORT_vless_grpc", "8443"),
            ("PORT_trojan", "2053"),
            ("PORT_shadowsocks", "8388"),
            ("PORT_anytls", "2083"),
            ("PORT_shadowtls", "2087"),
            ("PORT_vmess_ws", "8080"),
            ("REALITY_SITE_ENABLED", "1"),
            ("REALITY_SITE_DOMAIN", "www.example.com"),
            ("REALITY_SITE_PORT", "10443"),
            ("REALITY_DEST", "127.0.0.1:10443"),
            ("REALITY_SNI", "www.example.com"),
            ("REALITY_SITE_TITLE", "我的小站"),
            ("SITE_TEMPLATE", "docs"),
            ("SITE_THEME", "ocean"),
            ("SITE_DESCRIPTION", "记录与分享"),
            ("SITE_ACME_METHOD", "cf"),
            ("SITE_LAST_CONTENT_BACKUP", "20260101-010101"),
            ("TLS_MODE", "acme"),
            ("ACME_METHOD", "standalone"),
            ("DOMAIN", "Proxy.Example.com"),
            ("CERT_PINNED", "0"),
            ("SHADOWTLS_DEST", "old.example.com:443"),
            ("SUBSCRIPTION_ENABLED", "1"),
            ("SUBSCRIPTION_MODE", "standalone"),
            ("SUBSCRIPTION_DOMAIN", "sub.example.com"),
            ("SUBSCRIPTION_PORT", "8448"),
            ("SUBSCRIPTION_HTTP", "0"),
        ],
    )
}

#[test]
fn preset4_site_and_standalone_subscription() {
    let mut settings = settings("standalone", "sub.example.com", 8448, "cf");
    settings["devices"]
        .as_array_mut()
        .unwrap()
        .push(serde_json::json!({"id": "XYZ", "name": "bad", "hash": "00", "created": 1}));
    let m = migrate(&preset4_site(), Some(&settings), &mut SeqRandom(1)).unwrap();
    let c = &m.config;
    assert_eq!(c.inbounds.len(), 9);
    assert_eq!(
        c.inbounds[8],
        Inbound {
            protocol: VmessWs,
            port: 8080,
            core: SB
        }
    );
    let site = c.site_active().unwrap();
    assert_eq!(
        site,
        &SiteConfig {
            domain: "www.example.com".into(),
            internal_port: 10443,
            https_entry: true,
            title: "我的小站".into(),
            template: SiteTemplate::Docs,
            theme: SiteTheme::Ocean,
            description: "记录与分享".into(),
            cert: WebCert::Cloudflare,
            last_content_backup: Some("20260101-010101".into()),
        }
    );
    assert_eq!(c.reality.dest.to_string(), "127.0.0.1:10443");
    assert_eq!(
        c.tls,
        Some(ProxyTls {
            mode: ProxyCertMode::Acme {
                domain: "proxy.example.com".into(),
                method: AcmeMethod::Http01
            },
            pinned: false
        })
    );
    assert!(
        c.vmess_tls,
        "empty VMESS_TLS with acme is pinned to TLS (v2 upgrade())"
    );
    assert_eq!(
        c.shadowtls
            .dest
            .as_ref()
            .map(ToString::to_string)
            .as_deref(),
        Some("old.example.com:443"),
        "the target v2 actually used is preserved"
    );
    assert_eq!(
        c.subscription,
        Some(SubscriptionConfig {
            mode: SubscriptionMode::Standalone {
                domain: "sub.example.com".into(),
                cert: WebCert::Cloudflare,
                http01_port80: false
            },
            port: 8448
        })
    );
    let devices = m.devices.unwrap();
    assert_eq!(devices.len(), 2);
    assert_eq!(devices[1].name, "手机");
    assert_eq!(m.warnings, ["v2 订阅设备数据无效，已忽略: \"XYZ\""]);
    crate::domain::ports::PortPlan::of(c, &[])
        .validate()
        .unwrap();
}

#[test]
fn preset2_xray_shared_port_and_stale_family() {
    let values = with(
        preset1(),
        &[
            ("PROTOCOLS", "vless-reality vless-xhttp shadowsocks"),
            ("CORE_vless_reality", "xray"),
            ("CORE_vless_xhttp", "xray"),
            ("CORE_shadowsocks", "xray"),
            ("PORT_vless_xhttp", "443"),
            ("PORT_shadowsocks", "8388"),
            ("TLS_MODE", ""),
            ("SERVER_ADDR", "2001:db8::10"),
            ("SERVER_IPV6", "2001:db8::99"),
            ("SERVER_IPV4", "198.51.100.1"),
            ("XR_VERSION", "26.3.27"),
            ("XR_VERSION_WANT", "latest"),
            ("SB_VERSION_WANT", "1.12.0"),
        ],
    );
    let m = run(&values).unwrap();
    let c = &m.config;
    assert_eq!(
        layout(c),
        [
            (VlessReality, 443, XR),
            (VlessXhttp, 443, XR),
            (Shadowsocks, 8388, XR)
        ]
    );
    assert!(c.uses_guard());
    assert!(c.tls.is_none());
    assert_eq!(c.server.ipv6, Some("2001:db8::10".parse().unwrap()));
    assert_eq!(c.server.ipv4, Some("198.51.100.1".parse().unwrap()));
    assert_eq!(
        m.warnings,
        ["SERVER_IPV6=2001:db8::99 与连接地址不一致，已改为 2001:db8::10"]
    );
    assert_eq!(c.versions.xray.as_deref(), Some("26.3.27"));
    assert_eq!(c.versions.xray_pin, None);
    assert_eq!(c.versions.singbox_pin.as_deref(), Some("1.12.0"));
    crate::domain::ports::PortPlan::of(c, &[])
        .validate()
        .unwrap();
}

fn custom_cert() -> BTreeMap<String, String> {
    with(
        preset1(),
        &[
            ("PROTOCOLS", "trojan vmess-ws"),
            ("PORT_trojan", "443"),
            ("PORT_vmess_ws", "8080"),
            ("TLS_MODE", "custom"),
            ("DOMAIN", "proxy.example.com"),
            ("CUSTOM_CERT", "/root/fullchain.pem"),
            ("CUSTOM_KEY", "/root/privkey.pem"),
            ("CERT_PINNED", "1"),
            ("VMESS_TLS", "0"),
        ],
    )
}

#[test]
fn custom_certificate() {
    let m = run(&custom_cert()).unwrap();
    let c = &m.config;
    assert!(
        c.creds.reality.is_none(),
        "keys only exist with a REALITY inbound"
    );
    assert_eq!(
        c.tls,
        Some(ProxyTls {
            mode: ProxyCertMode::Custom {
                domain: "proxy.example.com".into(),
                cert: "/root/fullchain.pem".into(),
                key: "/root/privkey.pem".into()
            },
            pinned: true
        })
    );
    assert!(!c.vmess_tls, "an explicit VMESS_TLS=0 stays");
    assert!(m.warnings[0].contains("DOMAIN=proxy.example.com"));

    let upgraded = run(&with(custom_cert(), &[("VMESS_TLS", "")])).unwrap();
    assert!(upgraded.config.vmess_tls);

    let fallback = run(&with(
        custom_cert(),
        &[("CUSTOM_CERT", ""), ("CUSTOM_KEY", "")],
    ))
    .unwrap();
    let Some(ProxyTls {
        mode: ProxyCertMode::Custom { cert, key, .. },
        ..
    }) = &fallback.config.tls
    else {
        panic!("custom expected");
    };
    assert_eq!(cert.to_str(), Some("/etc/onebox/tls/cert.pem"));
    assert_eq!(key.to_str(), Some("/etc/onebox/tls/key.pem"));
    assert!(fallback
        .warnings
        .iter()
        .any(|w| w.contains("已使用已部署的文件")));

    let missing = with(
        custom_cert(),
        &[("CUSTOM_CERT", ""), ("CERT_FILE", ""), ("VMESS_TLS", "")],
    );
    assert_eq!(err(&missing), "v2 状态缺少 CUSTOM_CERT");
    assert_eq!(
        err(&with(custom_cert(), &[("TLS_MODE", "magic")])),
        "v2 字段 TLS_MODE 无效: magic"
    );
}

#[test]
fn hysteria2_tuning() {
    let base = with(preset1(), &[("HY2_OBFS", "1"), ("HY2_PROFILE", "measured")]);
    let ok = run(&with(
        base.clone(),
        &[("HY2_UP_MBPS", "100"), ("HY2_DOWN_MBPS", "500")],
    ))
    .unwrap();
    assert_eq!(
        ok.config.hy2,
        Hy2Settings {
            obfs: true,
            hop: None,
            profile: Some(Hy2Profile::Measured),
            up_mbps: Some(100),
            down_mbps: Some(500)
        }
    );
    let float = run(&with(
        base.clone(),
        &[("HY2_UP_MBPS", "100"), ("HY2_DOWN_MBPS", "20.5")],
    ))
    .unwrap();
    assert_eq!(float.config.hy2.profile, None);
    assert_eq!(float.config.hy2.up_mbps, None);
    assert_eq!(
        float.warnings,
        [
            "HY2_DOWN_MBPS 不是 1–10000 的整数，已忽略: 20.5",
            "Hysteria2 measured 档位缺少有效带宽，已取消调优"
        ]
    );
    let big = run(&with(
        base,
        &[("HY2_UP_MBPS", "20000"), ("HY2_DOWN_MBPS", "5")],
    ))
    .unwrap();
    assert_eq!(big.config.hy2.profile, None);

    let stale = with(
        preset1(),
        &[
            ("HY2_PROFILE", "auto"),
            ("HY2_UP_MBPS", "100"),
            ("RESOURCE_PROFILE", "low-memory"),
        ],
    );
    let m = run(&stale).unwrap();
    assert_eq!(m.config.hy2.profile, Some(Hy2Profile::Auto));
    assert_eq!(
        m.config.hy2.up_mbps, None,
        "stale bandwidth outside measured is dropped"
    );
    assert_eq!(m.config.resource_profile, ResourceProfile::LowMemory);

    let xray = with(
        preset1(),
        &[
            ("CORE_hysteria2", "xray"),
            ("HY2_PROFILE", "conservative"),
            ("RESOURCE_PROFILE", "throughput"),
        ],
    );
    let m = run(&xray).unwrap();
    assert_eq!(m.config.hy2.profile, None);
    assert_eq!(m.config.resource_profile, ResourceProfile::Balanced);
    assert_eq!(m.warnings.len(), 1);

    let unknown = run(&with(
        preset1(),
        &[("RESOURCE_PROFILE", "huge"), ("HY2_PROFILE", "fast")],
    ))
    .unwrap();
    assert_eq!(unknown.config.resource_profile, ResourceProfile::Balanced);
    assert_eq!(unknown.warnings.len(), 2);
}

#[test]
fn hop_ranges() {
    let ok = run(&with(preset1(), &[("HY2_HOP", "20000-30000")])).unwrap();
    assert_eq!(
        ok.config.hy2.hop,
        Some(PortRange {
            start: 20000,
            end: 30000
        })
    );
    for bad in ["100-200", "abc", "30000-20000", "20000-20000"] {
        let m = run(&with(preset1(), &[("HY2_HOP", bad)])).unwrap();
        assert_eq!(m.config.hy2.hop, None, "{bad}");
        assert_eq!(m.warnings, [format!("v2 字段 HY2_HOP 无效，已忽略: {bad}")]);
    }
}

#[test]
fn protocol_errors() {
    let cases = [
        (with(preset1(), &[("PORT_tuic", "")]), "tuic 端口无效"),
        (with(preset1(), &[("PORT_tuic", "0")]), "tuic 端口无效"),
        (with(preset1(), &[("PORT_tuic", "70000")]), "tuic 端口无效"),
        (
            with(preset1(), &[("PROTOCOLS", "vless-reality vless")]),
            "未知协议: vless",
        ),
        (with(preset1(), &[("PROTOCOLS", "tuic tuic")]), "协议重复"),
        (with(preset1(), &[("PROTOCOLS", " ")]), "状态缺少协议列表"),
        (
            with(preset1(), &[("CORE_tuic", "xray")]),
            "tuic 不支持 xray",
        ),
        (
            with(preset1(), &[("CORE_tuic", "clash")]),
            "未知内核: clash",
        ),
        (with(preset1(), &[("UUID", "nope")]), "v2 字段 UUID 无效"),
        (
            with(preset1(), &[("REALITY_PRIVATE_KEY", "bad")]),
            "v2 字段 REALITY_PRIVATE_KEY 无效",
        ),
        (
            with(preset1(), &[("REALITY_SHORT_ID", "xyz")]),
            "v2 字段 REALITY_SHORT_ID 无效",
        ),
        (
            with(preset1(), &[("REALITY_DEST", "nohost")]),
            "v2 字段 REALITY_DEST 无效: nohost",
        ),
        (
            with(preset1(), &[("SERVER_ADDR", "bad host")]),
            "v2 字段 SERVER_ADDR 无效: bad host",
        ),
        (
            with(preset1(), &[("LISTEN_ADDR", "any")]),
            "v2 字段 LISTEN_ADDR 无效: any",
        ),
        (
            with(preset1(), &[("REALITY_SNI", "1.2.3.4")]),
            "v2 字段 REALITY_SNI 无效: 1.2.3.4",
        ),
    ];
    for (values, want) in cases {
        assert_eq!(err(&values), want);
    }
}

#[test]
fn missing_credentials_are_generated() {
    // Unused credentials (v1-era states) are generated silently.
    let m = run(&with(
        preset1(),
        &[("SHADOWTLS_SS_PASSWORD", ""), ("XHTTP_PATH", "")],
    ))
    .unwrap();
    assert!(m.warnings.is_empty());
    assert_eq!(m.config.creds.xhttp_path.len(), 13);
    // Used ones are generated with a warning.
    let m = run(&with(preset1(), &[("PASSWORD", ""), ("CLASH_SECRET", "")])).unwrap();
    assert_eq!(m.config.creds.password.len(), 40);
    assert_eq!(m.warnings.len(), 2);
    // Invalid but unused: regenerated with a warning.
    let m = run(&with(preset1(), &[("SS_PASSWORD", "short")])).unwrap();
    assert_eq!(m.warnings, ["v2 字段 SS_PASSWORD 无效，已重新生成"]);
    let used = with(
        preset1(),
        &[
            ("PROTOCOLS", "shadowsocks"),
            ("PORT_shadowsocks", "8388"),
            ("SS_PASSWORD", "short"),
        ],
    );
    assert_eq!(err(&used), "v2 字段 SS_PASSWORD 无效");
    // REALITY keys: derived public key, generated keys.
    let (_, public) = reality_pair();
    let m = run(&with(preset1(), &[("REALITY_PUBLIC_KEY", "wrong")])).unwrap();
    assert_eq!(m.config.creds.reality.unwrap().public_key, public);
    assert_eq!(m.warnings.len(), 1);
    let m = run(&with(
        preset1(),
        &[("REALITY_PRIVATE_KEY", ""), ("REALITY_SHORT_ID", "")],
    ))
    .unwrap();
    assert!(m.config.creds.reality.is_some());
    assert_eq!(m.warnings.len(), 1);
}

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
