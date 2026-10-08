use super::*;
use crate::domain::fixtures::{config, with_site};
use crate::domain::protocol::Core::Singbox as SB;
use Protocol::*;

#[test]
fn server_address_resolution() {
    let v4: Ipv4Addr = "198.51.100.7".parse().unwrap();
    let v6: Ipv6Addr = "2001:db8::7".parse().unwrap();
    // Detected IPv4 wins without --addr, then IPv6.
    let s = server_addr(None, Some(v4), Some(v6)).unwrap();
    assert_eq!(s.addr, Host::Ip(IpAddr::V4(v4)));
    assert_eq!((s.ipv4, s.ipv6), (Some(v4), Some(v6)));
    let s = server_addr(None, None, Some(v6)).unwrap();
    assert_eq!(s.addr.to_string(), "2001:db8::7");
    assert_eq!(
        server_addr(None, None, None).unwrap_err().to_string(),
        "无法检测公网地址，请使用 --addr 指定"
    );
    // The address's own family overrides detection.
    let other: Ipv4Addr = "203.0.113.99".parse().unwrap();
    let s = server_addr(Some(Host::Ip(IpAddr::V4(other))), Some(v4), None).unwrap();
    assert_eq!(s.ipv4, Some(other));
    // Mapped IPv6 literals are stored as IPv4.
    let mapped: Host = "::ffff:203.0.113.99".parse().unwrap();
    let s = server_addr(Some(mapped), None, None).unwrap();
    assert_eq!(s.addr, Host::Ip(IpAddr::V4(other)));
    assert_eq!(s.ipv4, Some(other));
    // Domains keep only detected families.
    let s = server_addr(Some("proxy.example.com".parse().unwrap()), None, Some(v6)).unwrap();
    assert_eq!((s.ipv4, s.ipv6), (None, Some(v6)));
}

#[test]
fn reality_choices() {
    let base = config(&[(VlessReality, 443, SB)]);
    let run = |choice: RealityChoice| {
        let mut cfg = base.clone();
        apply_reality(&mut cfg, &choice).map(|_| cfg)
    };
    let apple = run(RealityChoice::Apple).unwrap();
    assert_eq!(apple.reality.sni, "www.apple.com");
    assert_eq!(apple.reality.dest.to_string(), "www.apple.com:443");
    let custom = run(RealityChoice::Custom(" WWW.Example.COM ".into())).unwrap();
    assert_eq!(custom.reality.dest.to_string(), "www.example.com:443");
    assert_eq!(
        run(RealityChoice::Custom("1.2.3.4".into()))
            .unwrap_err()
            .to_string(),
        "REALITY SNI 域名无效"
    );
    let dest = run(RealityChoice::Dest("[2001:db8::9]:8443".parse().unwrap())).unwrap();
    assert_eq!(dest.reality.sni, "www.microsoft.com");
    assert_eq!(dest.reality.dest.to_string(), "[2001:db8::9]:8443");
    assert_eq!(run(RealityChoice::Default).unwrap(), base);

    let site = run(RealityChoice::OwnSite(OwnSite {
        domain: "Blog.Example.com".into(),
        title: None,
        https_entry: false,
        cert: WebCert::Cloudflare,
    }))
    .unwrap();
    let s = site.site.as_ref().unwrap();
    assert_eq!(s.domain, "blog.example.com");
    assert_eq!((s.internal_port, s.https_entry), (10443, false));
    assert_eq!(s.title, "山间手记");
    assert_eq!(site.reality.sni, "blog.example.com");
    assert_eq!(site.reality.dest.to_string(), "127.0.0.1:10443");
    // Re-targeting keeps the internal port and content settings.
    let mut moved = with_site(base.clone(), "old.example.com", true);
    if let Some(s) = moved.site.as_mut() {
        s.internal_port = 12000;
        s.description = "保留".into();
    }
    apply_reality(
        &mut moved,
        &RealityChoice::OwnSite(OwnSite {
            domain: "new.example.com".into(),
            title: Some(" 新标题 ".into()),
            https_entry: true,
            cert: WebCert::Http01,
        }),
    )
    .unwrap();
    let s = moved.site.as_ref().unwrap();
    assert_eq!((s.internal_port, s.title.as_str()), (12000, "新标题"));
    assert_eq!(s.description, "保留");
    assert_eq!(moved.reality.dest.to_string(), "127.0.0.1:12000");
    // External targets switch the site off.
    apply_reality(&mut moved, &RealityChoice::Microsoft).unwrap();
    assert!(moved.site.is_none());

    let no_reality = config(&[(Trojan, 443, SB)]);
    let mut c = no_reality.clone();
    let err = apply_reality(
        &mut c,
        &RealityChoice::OwnSite(OwnSite {
            domain: "a.example.com".into(),
            title: None,
            https_entry: true,
            cert: WebCert::Http01,
        }),
    )
    .unwrap_err();
    assert_eq!(err.to_string(), "自建站需要 REALITY 协议及有效域名");
}

#[test]
fn tls_settlement() {
    let acme = ProxyCertChoice::Acme {
        domain: "Proxy.Example.com".into(),
        method: AcmeMethod::Cloudflare,
    };
    // VMess-WS uses TLS with a domain certificate only.
    let mut cfg = config(&[(VmessWs, 8080, SB)]);
    assert!(cfg.tls.is_none());
    settle_tls(&mut cfg, Some(&acme), false).unwrap();
    assert!(cfg.vmess_tls);
    let tls = cfg.tls.clone().unwrap();
    assert!(!tls.pinned);
    assert_eq!(tls.mode.server_name(), "proxy.example.com");
    settle_tls(&mut cfg, Some(&ProxyCertChoice::SelfSigned), false).unwrap();
    assert!(!cfg.vmess_tls);
    assert!(cfg.tls.is_none(), "plain VMess needs no certificate");

    // A newly needed certificate defaults to self-signed (pinned).
    let mut cfg = config(&[(VlessReality, 443, SB)]);
    cfg.inbounds.push(Inbound {
        protocol: Tuic,
        port: 443,
        core: SB,
    });
    settle_tls(&mut cfg, None, false).unwrap();
    let tls = cfg.tls.clone().unwrap();
    assert!(tls.pinned);
    assert_eq!(tls.mode.server_name(), "www.bing.com");

    let custom = ProxyCertChoice::Custom {
        domain: "proxy.example.com".into(),
        cert: "cert.pem".into(),
        key: "/etc/key.pem".into(),
    };
    assert_eq!(
        settle_tls(&mut cfg, Some(&custom), false)
            .unwrap_err()
            .to_string(),
        "证书路径必须为绝对路径"
    );
    let bad = ProxyCertChoice::Acme {
        domain: "bad".into(),
        method: AcmeMethod::Http01,
    };
    assert_eq!(
        settle_tls(&mut cfg, Some(&bad), false)
            .unwrap_err()
            .to_string(),
        "证书域名无效"
    );
}

#[test]
fn version_pins() {
    assert_eq!(version_pin(None).unwrap(), None);
    assert_eq!(version_pin(Some("latest")).unwrap(), None);
    assert_eq!(version_pin(Some(" ")).unwrap(), None);
    assert_eq!(version_pin(Some("1.12.0")).unwrap(), Some("1.12.0".into()));
    // Only versions host::cores can download become pins (v2 stored
    // `--singbox-version beta` and failed later).
    for bad in ["1.0;x", "beta", "LATEST", "1.12.0+x"] {
        assert_eq!(
            version_pin(Some(bad)).unwrap_err().to_string(),
            format!("内核版本无效: {bad}")
        );
    }
}

#[test]
fn domain_normalization() {
    assert_eq!(
        normalize_domain(" A.Example.COM ", "x").unwrap(),
        "a.example.com"
    );
    assert_eq!(
        normalize_domain("a..b", "坏域名").unwrap_err().to_string(),
        "坏域名"
    );
}
