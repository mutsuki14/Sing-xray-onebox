use super::*;
use crate::frp::model::{AppDomain, WebTls};
use std::collections::BTreeMap;

const TOKEN: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

/// Matches with the given `--long value` options (each may repeat).
fn matches(options: &[(&'static str, &str)]) -> Matches {
    let mut values: BTreeMap<&'static str, Vec<String>> = BTreeMap::new();
    for (long, value) in options {
        values.entry(long).or_default().push(value.to_string());
    }
    Matches {
        path: vec!["frps", "install"],
        values,
        ..Matches::default()
    }
}

fn flags(options: &[(&'static str, &str)]) -> Result<Flags> {
    Flags::from_matches(&matches(options), Path::new("/root"))
}

fn web_draft() -> Draft {
    let mut d = Draft::fresh(true);
    d.domain = "frp.example.com".into();
    d.web_domain = "app.example.com".into();
    d
}

#[test]
fn fresh_drafts_have_v2_defaults() {
    let d = Draft::fresh(true);
    assert_eq!(d.mode, ModeKind::Web);
    assert_eq!(d.bind_addr, BindAddr::AnyV6);
    assert_eq!(Draft::fresh(false).bind_addr, BindAddr::AnyV4);
    assert_eq!(
        (d.bind_port, d.http_port, d.https_port, d.redirect_port),
        (7000, 7080, 443, 80)
    );
    assert_eq!(d.range, DEFAULT_RANGE);
    assert_eq!((d.tls, d.version.as_str()), (TlsKind::Http01, "0.71.0"));
    let err = finish(&d, None).unwrap_err();
    assert_eq!(err.to_string(), "请设置有效的 FRP 控制域名");
}

#[test]
fn draft_round_trips_through_the_state() {
    let mut d = web_draft();
    d.token = TOKEN.into();
    let state = finish(&d, None).unwrap();
    assert_eq!(Draft::of(&state), {
        let mut expected = d.clone();
        expected.bind_addr = BindAddr::AnyV6;
        expected
    });
    let mut tcp = d.clone();
    tcp.mode = ModeKind::Tcp;
    tcp.range = PortRange {
        start: 30000,
        end: 30010,
    };
    let state = finish(&tcp, None).unwrap();
    assert_eq!(state.range(), Some(tcp.range));
    let back = Draft::of(&state);
    assert_eq!((back.mode, back.range), (ModeKind::Tcp, tcp.range));
    // The web fields of a tcp state are the defaults again.
    assert_eq!(back.web_domain, "");

    let mut custom = web_draft();
    custom.subdomain_host = "apps.example.com".into();
    custom.web_domain.clear();
    custom.tls = TlsKind::Custom;
    custom.cert = "/c.pem".into();
    custom.key = "/k.pem".into();
    let web = finish(&custom, None).unwrap();
    let settings = web.web().unwrap();
    assert_eq!(
        settings.app,
        AppDomain::Wildcard {
            root: "apps.example.com".into()
        }
    );
    assert_eq!(
        settings.tls,
        WebTls::Custom {
            cert: "/c.pem".into(),
            key: "/k.pem".into()
        }
    );
    assert_eq!(Draft::of(&web), custom);
}

#[test]
fn both_application_names_are_refused() {
    let mut d = web_draft();
    d.subdomain_host = "apps.example.com".into();
    assert_eq!(
        d.build().unwrap_err().to_string(),
        "应用域名与泛域名根不能并用"
    );
    // tcp mode ignores the web fields entirely.
    d.mode = ModeKind::Tcp;
    assert!(d.build().is_ok());
}

#[test]
fn changes_keep_the_token_requirement() {
    let mut d = web_draft();
    d.token = TOKEN.into();
    let installed = finish(&d, None).unwrap();
    let mut changed = Draft::of(&installed);
    changed.bind_port = 7001;
    assert_eq!(finish(&changed, Some(&installed)).unwrap().bind_port, 7001);
    changed.token.clear();
    assert!(finish(&changed, Some(&installed)).is_err());
    // A new domain must be a DNS name (H-8.1#15).
    let mut ip = Draft::of(&installed);
    ip.domain = "192.0.2.1".into();
    let err = finish(&ip, Some(&installed)).unwrap_err().to_string();
    assert!(err.contains("不能是 IP 地址"), "{err}");
}

#[test]
fn options_parse_with_v2_messages() {
    let f = flags(&[
        ("mode", "tcp"),
        ("domain", "FRP.Example.COM"),
        ("port", "7001"),
        ("allow-ports", "30000-30100"),
        ("version", "v0.72.0"),
    ])
    .unwrap();
    assert_eq!(f.mode, Some(ModeKind::Tcp));
    assert_eq!(f.domain.as_deref(), Some("frp.example.com"));
    assert_eq!(f.bind_port, Some(7001));
    assert_eq!(
        f.range,
        Some(PortRange {
            start: 30000,
            end: 30100
        })
    );
    assert_eq!(f.version.as_deref(), Some("0.72.0"));
    for (options, message) in [
        (&[("mode", "udp")][..], "FRP 模式应为 web 或 tcp"),
        (&[("tls", "dns")], "网站证书方式应为 http、cf 或 custom"),
        (&[("port", "70000")], "--port 的值无效: 70000"),
        (&[("https-port", "x")], "--https-port 的值无效: x"),
        (
            &[("allow-ports", "20000")],
            "--allow-ports 格式为 20000-20100",
        ),
        (
            &[("allow-ports", "a-b")],
            "--allow-ports 格式为 20000-20100",
        ),
        (
            &[
                ("web-domain", "a.example.com"),
                ("subdomain-host", "example.com"),
            ],
            "--web-domain 与 --subdomain-host 不能同时使用",
        ),
        (&[("cert", "../c.pem")], "证书路径不能包含 ..: ../c.pem"),
    ] {
        assert_eq!(
            flags(options).unwrap_err().to_string(),
            message,
            "{options:?}"
        );
    }
}

#[test]
fn repeated_options_take_the_last_value() {
    let f = flags(&[
        ("web-domain", "a.example.com"),
        ("web-domain", "b.example.com"),
    ])
    .unwrap();
    assert_eq!(f.web_domain.as_deref(), Some("b.example.com"));
}

#[test]
fn applying_flags_sets_fields_and_switches_names() {
    let mut d = web_draft();
    flags(&[("subdomain-host", "Apps.Example.com"), ("tls", "cf")])
        .unwrap()
        .apply(&mut d);
    assert_eq!(
        (d.web_domain.as_str(), d.subdomain_host.as_str()),
        ("", "apps.example.com")
    );
    assert_eq!(d.tls, TlsKind::Cloudflare);
    flags(&[("web-domain", "x.example.com")])
        .unwrap()
        .apply(&mut d);
    assert_eq!(
        (d.web_domain.as_str(), d.subdomain_host.as_str()),
        ("x.example.com", "")
    );
    let custom = flags(&[("tls", "custom"), ("cert", "c.pem"), ("key", "/etc/k.pem")]).unwrap();
    custom.apply(&mut d);
    assert_eq!(d.cert, "/root/c.pem");
    assert_eq!(d.key, "/etc/k.pem");
    let ports = flags(&[
        ("port", "7100"),
        ("http-port", "7180"),
        ("https-port", "8443"),
        ("redirect-port", "0"),
    ])
    .unwrap();
    ports.apply(&mut d);
    assert_eq!(
        (d.bind_port, d.http_port, d.https_port, d.redirect_port),
        (7100, 7180, 8443, 0)
    );
    assert!(Flags::default().is_empty() && !ports.is_empty());
}

#[test]
fn options_of_the_other_mode_are_reported() {
    let f = flags(&[
        ("allow-ports", "1-2"),
        ("tls", "cf"),
        ("https-port", "8443"),
    ])
    .unwrap();
    assert_eq!(f.ignored(ModeKind::Web), ["--allow-ports"]);
    assert_eq!(f.ignored(ModeKind::Tcp), ["--https-port", "--tls"]);
    assert!(Flags::default().ignored(ModeKind::Tcp).is_empty());
}

#[test]
fn mode_and_tls_ids() {
    for mode in [ModeKind::Web, ModeKind::Tcp] {
        assert_eq!(ModeKind::parse(mode.id()).unwrap(), mode);
    }
    assert_eq!(normalize_version("latest"), "latest");
    assert_eq!(
        absolute_path("x/y.pem", Path::new("/srv")).unwrap(),
        "/srv/x/y.pem"
    );
}
