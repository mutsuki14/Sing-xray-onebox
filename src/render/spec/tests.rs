use super::*;
use crate::domain::fixtures::{ip_subscription, standalone_subscription, ADDR};
use crate::render::fixtures::{config, material, paths, spec, with_site};
use crate::sys::fs::TempDir;
use std::net::Ipv6Addr;
use Core::{Singbox as SB, Xray as XR};
use Protocol::*;

#[test]
fn new_validates_the_configuration() {
    let mut cfg = config(&[(Trojan, 443, SB)]);
    cfg.creds.uuid = "not-a-uuid".into();
    let err = NodeSpec::new(&cfg, &paths(), None).unwrap_err();
    assert_eq!(err.to_string(), "UUID 格式无效");
}

#[test]
fn inbounds_keep_order_cores_and_labels() {
    let mut cfg = config(&[(Trojan, 443, XR), (Tuic, 8443, SB)]);
    cfg.node_name = "香港 #1".into();
    let s = spec(&cfg);
    let labels: Vec<&str> = s.inbounds.iter().map(|i| i.label.as_str()).collect();
    assert_eq!(labels, ["香港 #1-Trojan-TLS", "香港 #1-TUIC-v5"]);
    assert_eq!(s.inbound(Tuic).unwrap().core, SB);
    assert_eq!(s.on_core(XR).count(), 1);
    assert_eq!(
        s.require(Anytls).unwrap_err().to_string(),
        "未启用协议 anytls"
    );
}

#[test]
fn reality_keys_live_only_in_the_reality_spec() {
    let cfg = config(&[(VlessReality, 443, XR)]);
    let s = spec(&cfg);
    let keys = cfg.creds.reality.clone().unwrap();
    let r = s.reality().unwrap();
    assert_eq!(r.private_key, keys.private_key);
    assert_eq!(r.dest.to_string(), "www.microsoft.com:443");
    assert_eq!(r.guard_port, 18000);
    assert!(s.creds.reality.is_none());
    assert!(spec(&config(&[(Trojan, 443, SB)])).reality.is_none());
}

#[test]
fn shadowtls_target_defaults_to_sni_443() {
    let mut cfg = config(&[(Shadowtls, 443, SB)]);
    assert_eq!(
        spec(&cfg).shadowtls.dest.to_string(),
        "www.microsoft.com:443"
    );
    cfg.shadowtls.dest = Some("[2001:db8::9]:8443".parse().unwrap());
    let s = spec(&cfg);
    assert_eq!(s.shadowtls.dest.host.to_string(), "2001:db8::9");
    assert_eq!(s.shadowtls.dest.port, 8443);
}

#[test]
fn certificate_trust_follows_pinning_and_material() {
    let cfg = config(&[(Trojan, 443, SB)]);
    let tls = spec(&cfg).tls.unwrap();
    assert_eq!(tls.server_name, "www.bing.com");
    assert_eq!(tls.cert_path, "/onebox-test/etc/tls/cert.pem");
    assert_eq!(tls.key_path, "/onebox-test/etc/tls/key.pem");
    assert_eq!(
        tls.pin().unwrap().unwrap().leaf_pin(),
        material("selfsigned").leaf_pin()
    );

    let unloaded = NodeSpec::new(&cfg, &paths(), None).unwrap().tls.unwrap();
    assert_eq!(unloaded.trust, CertTrust::PinnedUnloaded);
    assert!(unloaded.pinned());
    let err = unloaded.pin().unwrap_err().to_string();
    assert_eq!(err, "固定证书的客户端配置缺少证书指纹");

    let mut acme = cfg.clone();
    acme.tls = Some(ProxyTls {
        mode: ProxyCertMode::Acme {
            domain: "proxy.example.com".into(),
            method: AcmeMethod::Http01,
        },
        pinned: false,
    });
    let public = spec(&acme).tls.unwrap();
    assert_eq!(public.trust, CertTrust::Public);
    assert_eq!(public.server_name, "proxy.example.com");
    assert!(public.pin().unwrap().is_none());
    assert!(spec(&config(&[(Shadowsocks, 8388, SB)])).tls.is_none());
}

#[test]
fn vmess_host_header_by_tls_mode() {
    let mut plain = config(&[(VmessWs, 8080, SB)]);
    assert_eq!(
        spec(&plain).vmess,
        VmessSpec {
            tls: false,
            ws_host: None
        }
    );
    plain.vmess_host = Some("cdn.example.com".into());
    let s = spec(&plain);
    assert_eq!(s.vmess.ws_host.as_deref(), Some("cdn.example.com"));
    assert!(s.tls.is_none());

    let mut tls = plain.clone();
    tls.vmess_tls = true;
    tls.tls = Some(crate::domain::fixtures::self_signed());
    let s = spec(&tls);
    assert!(s.vmess.tls);
    assert_eq!(s.vmess.ws_host.as_deref(), Some("www.bing.com"));
}

#[test]
fn hysteria2_tuning_is_resolved_once() {
    let mut cfg = config(&[(Hysteria2, 443, SB)]);
    let s = spec(&cfg);
    assert_eq!(s.hy2.obfs_password, None);
    assert_eq!(
        (s.hy2.profile, s.hy2.bandwidth, s.hy2.windows),
        (None, None, None)
    );
    cfg.hy2 = Hy2Settings {
        obfs: true,
        hop: Some("30000-30100".parse().unwrap()),
        profile: Some(Hy2Profile::Measured),
        up_mbps: Some(50),
        down_mbps: Some(200),
    };
    cfg.resource_profile = ResourceProfile::LowMemory;
    let s = spec(&cfg);
    assert_eq!(
        s.hy2.obfs_password.as_ref(),
        Some(&cfg.creds.hy2_obfs_password)
    );
    assert_eq!(s.hy2.hop.unwrap().to_string(), "30000-30100");
    assert_eq!(
        s.hy2.bandwidth,
        Some(Bandwidth {
            up_mbps: 50,
            down_mbps: 200
        })
    );
    assert_eq!(s.hy2.windows.unwrap().max_streams, 64);
}

#[test]
fn resource_profiles_map_to_v2_windows() {
    let table = [
        (ResourceProfile::Balanced, None),
        (ResourceProfile::LowMemory, Some((2_097_152, 5_242_880, 64))),
        (
            ResourceProfile::Throughput,
            Some((16_777_216, 41_943_040, 1024)),
        ),
    ];
    for (profile, expected) in table {
        let got = Hy2Windows::of(profile).map(|w| (w.stream, w.connection, w.max_streams));
        assert_eq!(got, expected, "{profile}");
    }
}

#[test]
fn blocked_cidrs_are_private_ranges_plus_own_addresses_sorted() {
    let mut cfg = config(&[(Trojan, 443, SB)]);
    let v6: Ipv6Addr = "2001:db8::7".parse().unwrap();
    cfg.server.ipv6 = Some(v6);
    cfg.routing.own_cidrs = vec!["9.9.9.9/32".into(), "203.0.113.10/32".into()];
    let s = spec(&cfg);
    let cidrs = &s.routing.blocked_cidrs;
    assert_eq!(cidrs.len(), 18 + 3);
    assert!(cidrs.windows(2).all(|w| w[0] < w[1]), "sorted and unique");
    for c in [
        "203.0.113.10/32",
        "2001:db8::7/128",
        "9.9.9.9/32",
        "100.64.0.0/10",
    ] {
        assert!(cidrs.contains(&c.to_string()), "{c}");
    }
    let pos = |c: &str| cidrs.iter().position(|x| x == c).unwrap();
    assert!(
        pos("192.168.0.0/16") < pos("192.88.99.0/24"),
        "v2 string order"
    );
    assert!(!cidrs.contains(&"64:ff9b::/96".to_string()));
    assert_eq!(s.routing.families, Families::Dual);
}

#[test]
fn warp_addresses_are_not_blocked_but_the_public_address_always_is() {
    let mut cfg = config(&[(Trojan, 443, SB)]);
    cfg.server.ipv4_warp = true;
    let s = spec(&cfg);
    // The public address is the WARP-flagged IPv4: still blocked (v2 rule).
    assert!(s.routing.blocked_cidrs.contains(&format!("{ADDR}/32")));
    cfg.server.addr = Host::Domain("proxy.example.com".into());
    let s = spec(&cfg);
    assert!(!s.routing.blocked_cidrs.contains(&format!("{ADDR}/32")));
    assert_eq!(s.routing.blocked_cidrs.len(), 18);
}

#[test]
fn address_families_choose_the_strategy() {
    let v6: Ipv6Addr = "2001:db8::1".parse().unwrap();
    let mut cfg = config(&[(Trojan, 443, SB)]);
    cfg.server.addr = Host::Domain("proxy.example.com".into());
    let table = [
        (Some(ADDR), None, Families::V4Only),
        (None, Some(v6), Families::V6Only),
        (Some(ADDR), Some(v6), Families::Dual),
        (None, None, Families::Dual),
    ];
    for (v4, v6, families) in table {
        cfg.server.ipv4 = v4;
        cfg.server.ipv6 = v6;
        assert_eq!(spec(&cfg).routing.families, families);
    }
}

#[test]
fn direct_targets_collect_subscription_and_site_endpoints() {
    let base = config(&[(VlessReality, 443, XR)]);
    assert_eq!(spec(&base).direct, DirectTargets::default());

    let mut ip = base.clone();
    ip.subscription = Some(ip_subscription(8448));
    assert_eq!(spec(&ip).direct.cidrs, ["203.0.113.10/32"]);

    let mut standalone = with_site(base.clone(), "site.example.com", true);
    standalone.subscription = Some(standalone_subscription(
        "sub.example.com",
        8448,
        WebCert::Cloudflare,
    ));
    let s = spec(&standalone);
    assert_eq!(s.direct.domains, ["site.example.com", "sub.example.com"]);
    assert!(s.direct.cidrs.is_empty());

    let mut site = with_site(base, "site.example.com", true);
    site.subscription = Some(SubscriptionConfig {
        mode: SubscriptionMode::Site,
        port: 443,
    });
    let s = spec(&site);
    assert_eq!(s.direct.domains, ["site.example.com"]);
    assert_eq!(
        s.site,
        Some(SiteSpec {
            domain: "site.example.com".into(),
            internal_port: 10443,
            https_entry: true
        })
    );
}

#[test]
fn local_view_prefers_a_specific_listen_address() {
    let mut cfg = config(&[(Trojan, 443, SB)]);
    let s = spec(&cfg);
    assert_eq!(s.local().server_host(), "127.0.0.1");
    assert_eq!(s.server_host(), "203.0.113.10");
    cfg.listen = "2001:db8::5".parse().unwrap();
    let local = spec(&cfg).local();
    assert_eq!(local.server_host(), "2001:db8::5");
    assert_eq!(local.uri_host(), "[2001:db8::5]");
    assert_eq!(local.inbounds, spec(&cfg).inbounds);
}

#[test]
fn xhttp_sharing_needs_both_on_xray_and_one_port() {
    let table = [
        (vec![(VlessReality, 443, XR), (VlessXhttp, 443, XR)], true),
        (vec![(VlessReality, 443, XR), (VlessXhttp, 8443, XR)], false),
        (vec![(VlessReality, 443, SB), (VlessXhttp, 8443, XR)], false),
        (vec![(VlessXhttp, 443, XR)], false),
    ];
    for (inbounds, shared) in table {
        let s = spec(&config(&inbounds));
        assert_eq!(s.xhttp_shared(), shared, "{inbounds:?}");
        assert!(s.uses_xray_reality());
    }
    assert!(!spec(&config(&[(VlessReality, 443, SB)])).uses_xray_reality());
}

#[test]
fn formats_and_omissions_follow_the_capability_table() {
    let s = spec(&config(&[(AnytlsReality, 443, SB)]));
    assert_eq!(
        s.formats(),
        [ClientFormat::Singbox, ClientFormat::SingboxNoTun]
    );
    assert_eq!(s.omitted(ClientFormat::Mihomo), [AnytlsReality]);
    let s = spec(&config(&[(Shadowtls, 443, SB), (Trojan, 8443, SB)]));
    assert_eq!(s.for_format(ClientFormat::Links).len(), 1);
    assert_eq!(s.formats().len(), 7);
    assert_eq!(s.shadowtls_label().unwrap(), "onebox-ShadowTLS-v3");
}

#[test]
fn load_reads_the_deployed_certificate_only_when_pinned() {
    let dir = TempDir::new("spec-load").unwrap();
    let paths = Paths::isolated(dir.path());
    let cfg = config(&[(Trojan, 443, SB)]);
    let err = NodeSpec::load(&cfg, &paths).unwrap_err().to_string();
    assert!(err.contains("cert.pem"), "{err}");
    std::fs::create_dir_all(paths.tls()).unwrap();
    let (cert, _) = crate::render::fixtures::cert_pair("selfsigned");
    std::fs::copy(cert, paths.tls().join(CERT_FILE)).unwrap();
    let s = NodeSpec::load(&cfg, &paths).unwrap();
    assert!(matches!(s.tls.unwrap().trust, CertTrust::Pinned(_)));
    // Nothing to pin: no certificate read at all.
    let plain = config(&[(Shadowsocks, 8388, SB)]);
    assert!(NodeSpec::load(&plain, &Paths::isolated(Path::new("/nonexistent"))).is_ok());
}
