use super::*;

/// Matches with option values (`("port", "a=1")` may repeat) and flags.
pub(crate) fn matches(values: &[(&'static str, &str)], flags: &[&'static str]) -> Matches {
    let mut m = Matches::default();
    for (key, value) in values {
        m.values.entry(key).or_default().push(value.to_string());
    }
    m.flags = flags.to_vec();
    m
}

#[test]
fn port_values() {
    assert_eq!(port("8443").unwrap(), 8443);
    assert_eq!(port(" 443 ").unwrap(), 443);
    assert_eq!(port("0").unwrap_err().to_string(), "端口不能为 0");
    assert_eq!(port("x").unwrap_err().to_string(), "端口无效: x");
    assert_eq!(port("70000").unwrap_err().to_string(), "端口无效: 70000");
}

#[test]
fn port_maps() {
    let m = matches(&[("port", "trojan=8443"), ("port", "tuic=2053")], &[]);
    assert_eq!(
        ports(&m).unwrap(),
        [(Protocol::Trojan, 8443), (Protocol::Tuic, 2053)]
    );
    for (value, message) in [
        ("trojan", "--port 格式为 协议=端口"),
        ("trojan=0", "端口不能为 0"),
        ("trojan=x", "端口无效: x"),
        ("vless=443", "未知协议: vless"),
    ] {
        let m = matches(&[("port", value)], &[]);
        assert_eq!(ports(&m).unwrap_err().to_string(), message, "{value}");
    }
    let dup = matches(&[("port", "trojan=1"), ("port", "trojan=2")], &[]);
    assert_eq!(ports(&dup).unwrap_err().to_string(), "重复指定协议端口");
}

#[test]
fn presets_protocols_cores_and_hosts() {
    assert_eq!(preset(&matches(&[("preset", "3")], &[])).unwrap(), Some(3));
    assert_eq!(
        preset(&matches(&[("preset", "x")], &[]))
            .unwrap_err()
            .to_string(),
        "预设应为 1–7，7 为自定义协议组合"
    );
    assert_eq!(preset(&Matches::default()).unwrap(), None);
    let list = protocols(&matches(&[("protocols", "tuic vless-reality")], &[]))
        .unwrap()
        .unwrap();
    assert_eq!(list, [Protocol::VlessReality, Protocol::Tuic]);
    assert_eq!(
        core(&matches(&[("core", "sing-box")], &[]), "core").unwrap(),
        Some(Core::Singbox)
    );
    assert!(core(&matches(&[("core", "clash")], &[]), "core").is_err());
    assert_eq!(host("[2001:db8::1]").unwrap().to_string(), "2001:db8::1");
    assert_eq!(
        host("Proxy.Example.com").unwrap().to_string(),
        "proxy.example.com"
    );
    assert_eq!(
        host("bad host").unwrap_err().to_string(),
        "服务器地址应为 IP 或域名"
    );
    assert!(on_off("on", "x").unwrap() && !on_off("off", "x").unwrap());
    assert_eq!(
        on_off("yes", "--site-https").unwrap_err().to_string(),
        "--site-https 应为 on/off"
    );
    assert_eq!(
        hop(&matches(&[("hy2-hop", "20000-30000")], &[]))
            .unwrap()
            .unwrap()
            .to_string(),
        "20000-30000"
    );
    let m = matches(&[("singbox-version", "1.12.0")], &[]);
    assert_eq!(
        version_pin(&m, "singbox-version", Some("1.0.0".into())),
        Some("1.12.0".into())
    );
    assert_eq!(
        version_pin(&Matches::default(), "x", Some("1.0.0".into())),
        Some("1.0.0".into())
    );
    assert!(any(&m, &["singbox-version"]) && !any(&m, &["tls"]));
}

#[test]
fn proxy_certificate_choices() {
    let parse = |values: &[(&'static str, &str)]| cert_args(&matches(values, &[]), None);
    assert_eq!(parse(&[]).unwrap(), CertArgs::default());
    assert_eq!(
        parse(&[("domain", "cdn.example.com")]).unwrap().vmess_host,
        Some("cdn.example.com".into())
    );
    let self_signed = parse(&[("tls", "self"), ("domain", "cdn.example.com")]).unwrap();
    assert_eq!(self_signed.choice, Some(ProxyCertChoice::SelfSigned));
    assert_eq!(self_signed.vmess_host, Some("cdn.example.com".into()));
    for method in ["acme", "http"] {
        assert_eq!(
            parse(&[("tls", method), ("domain", "v.example.com")])
                .unwrap()
                .choice,
            Some(ProxyCertChoice::Acme {
                domain: "v.example.com".into(),
                method: AcmeMethod::Http01
            })
        );
    }
    let cf = parse(&[("tls", "cf"), ("domain", "v.example.com")]).unwrap();
    assert!(matches!(
        cf.choice,
        Some(ProxyCertChoice::Acme {
            method: AcmeMethod::Cloudflare,
            ..
        })
    ));
    let custom = parse(&[
        ("tls", "custom"),
        ("domain", "v.example.com"),
        ("cert", "/root/full.pem"),
        ("key", "key.pem"),
    ])
    .unwrap();
    let Some(ProxyCertChoice::Custom { cert, key, .. }) = custom.choice else {
        panic!("custom expected");
    };
    assert_eq!(cert, PathBuf::from("/root/full.pem"));
    assert!(key.is_absolute() && key.ends_with("key.pem"));
    for (values, message) in [
        (&[("tls", "acme")][..], "--tls acme 需要 --domain 域名"),
        (&[("tls", "bogus")], "--tls 应为 self/acme/cf/custom"),
        (
            &[("tls", "custom"), ("domain", "a.example.com")],
            "自备证书需要 --cert 和 --key",
        ),
        (&[("cert", "/x")], "--cert/--key 需要 --tls custom"),
        (
            &[("tls", "self"), ("key", "/x")],
            "--cert/--key 需要 --tls custom",
        ),
    ] {
        assert_eq!(
            parse(values).unwrap_err().to_string(),
            message,
            "{values:?}"
        );
    }
    let kept = cert_args(&matches(&[("tls", "cf")], &[]), Some("old.example.com")).unwrap();
    assert_eq!(
        kept.choice,
        Some(ProxyCertChoice::Acme {
            domain: "old.example.com".into(),
            method: AcmeMethod::Cloudflare
        })
    );
}

#[test]
fn web_certificates() {
    assert_eq!(web_cert(&Matches::default()).unwrap(), WebCert::Http01);
    assert_eq!(
        web_cert(&matches(&[("tls", "cf")], &[])).unwrap(),
        WebCert::Cloudflare
    );
    assert_eq!(
        web_cert(&matches(&[("tls", "self")], &[]))
            .unwrap_err()
            .to_string(),
        crate::cert::PUBLIC_REQUIRED
    );
    assert_eq!(
        web_cert(&matches(&[("tls", "custom"), ("cert", "/a")], &[]))
            .unwrap_err()
            .to_string(),
        "自备证书需要 --cert 和 --key"
    );
    assert!(matches!(
        web_cert_from(Some("custom"), Some("/a"), Some("/b")).unwrap(),
        WebCert::Custom { .. }
    ));
    assert_eq!(
        web_cert_from(Some("dns"), None, None)
            .unwrap_err()
            .to_string(),
        "--tls 应为 http/cf/custom"
    );
}

#[test]
fn handshake_options() {
    let parse =
        |values: &[(&'static str, &str)]| reality_args(&matches(values, &[]), WebCert::Http01);
    assert!(parse(&[]).unwrap().is_empty());
    let sni = parse(&[("sni", "www.apple.com")]).unwrap();
    assert_eq!(sni.choice, RealityChoice::Custom("www.apple.com".into()));
    assert_eq!(sni.shadowtls_sni, Some("www.apple.com".into()));
    let both = parse(&[
        ("sni", "www.apple.com"),
        ("reality-dest", "198.51.100.7:443"),
    ])
    .unwrap();
    assert_eq!(both.dest_after_sni.unwrap().to_string(), "198.51.100.7:443");
    let dest = parse(&[("reality-dest", "[2001:db8::7]:8443")]).unwrap();
    assert!(matches!(dest.choice, RealityChoice::Dest(_)));
    let site = parse(&[
        ("reality-site", "www.example.com"),
        ("site-title", "我的手记"),
        ("site-https", "off"),
    ])
    .unwrap();
    let RealityChoice::OwnSite(own) = site.choice else {
        panic!("own site expected");
    };
    assert_eq!(own.title.as_deref(), Some("我的手记"));
    assert!(!own.https_entry);
    assert_eq!(own.cert, WebCert::Http01);
    assert_eq!(
        parse(&[("site-https", "on")]).unwrap().site_https,
        Some(true)
    );
    for (values, message) in [
        (
            &[("reality-site", "a.example.com"), ("sni", "b.example.com")][..],
            "--reality-site 不能与 --sni/--reality-dest 同时指定",
        ),
        (
            &[("site-title", "x")],
            "--site-title 需要与 --reality-site 一起使用",
        ),
        (&[("reality-dest", "nope")], "握手目标格式为 主机:端口"),
        (&[("reality-dest", "a.example.com:0")], "握手目标无效"),
        (&[("site-https", "maybe")], "--site-https 应为 on/off"),
    ] {
        assert_eq!(
            parse(values).unwrap_err().to_string(),
            message,
            "{values:?}"
        );
    }
}
