use super::*;
use crate::domain::config::SubscriptionMode;
use crate::domain::plan::{enable_subscription, PlanEnv};
use crate::subscription::testing::{reality, site};

fn matches(options: &[(&'static str, &str)]) -> Matches {
    let mut m = Matches::default();
    for (key, value) in options {
        m.values.entry(*key).or_default().push(value.to_string());
    }
    m
}

fn request(options: &[(&'static str, &str)]) -> Result<EnableRequest> {
    EnableRequest::from_matches(&matches(options))
}

fn choice(options: &[(&'static str, &str)], cfg: &NodeConfig) -> Result<(SubscriptionChoice, Option<u16>)> {
    request(options)?.choice(cfg)
}

fn err(result: Result<impl std::fmt::Debug>) -> String {
    result.unwrap_err().to_string()
}

#[test]
fn option_values_are_checked_like_v2() {
    assert_eq!(
        err(request(&[("address", "192.0.2.1"), ("ip", "192.0.2.2")])),
        "订阅参数重复: --address"
    );
    assert_eq!(err(request(&[("domain", " ")])), "订阅参数缺少值: --domain");
    assert_eq!(err(request(&[("ip", "")])), "订阅参数缺少值: --ip");
    let r = request(&[("ip", " 192.0.2.1 "), ("name", "手机")]).unwrap();
    assert_eq!(r.address.as_deref(), Some("192.0.2.1"), "--ip is --address");
    assert_eq!(r.name.as_deref(), Some("手机"));
}

#[test]
fn mode_is_inferred_in_v2_order() {
    let plain = reality();
    let with_site = site();
    let cases: [(&[(&'static str, &str)], &NodeConfig, Mode); 6] = [
        (&[], &plain, Mode::Ip),
        (&[], &with_site, Mode::Site),
        (&[("address", "192.0.2.1")], &with_site, Mode::Ip),
        (&[("domain", "sub.example.com")], &with_site, Mode::Standalone),
        (&[("mode", "standalone")], &plain, Mode::Standalone),
        (&[("mode", "site")], &plain, Mode::Site),
    ];
    for (options, cfg, want) in cases {
        assert_eq!(request(options).unwrap().mode(cfg).unwrap(), want, "{options:?}");
    }
    assert_eq!(err(request(&[("mode", "cdn")]).unwrap().mode(&plain)), BAD_MODE);
    for mode in ["site", "standalone"] {
        let r = request(&[("mode", mode), ("address", "192.0.2.1")]).unwrap();
        assert_eq!(err(r.mode(&with_site)), ADDRESS_NOT_IP);
    }
}

#[test]
fn ip_mode_takes_only_an_address_and_a_port() {
    let cfg = reality();
    assert_eq!(
        choice(&[], &cfg).unwrap(),
        (SubscriptionChoice::Ip { address: None }, None)
    );
    assert_eq!(
        choice(&[("address", "2001:db8::7"), ("port", "9000")], &cfg).unwrap(),
        (
            SubscriptionChoice::Ip {
                address: Some("2001:db8::7".parse().unwrap())
            },
            Some(9000)
        )
    );
    for flag in ["domain", "tls", "cert", "key"] {
        let options = [("mode", "ip"), (flag, "x")];
        assert_eq!(err(choice(&options, &cfg)), IP_NO_CERT, "{flag}");
    }
    for bad in ["[::1]", "fe80::1%eth0", "192.0.2.1:80", "example.com", "192.0.2.1/x", "http://192.0.2.1"] {
        assert_eq!(err(choice(&[("address", bad)], &cfg)), BAD_ADDRESS, "{bad}");
    }
    for bad in ["0", "65536", "port", "-1"] {
        assert_eq!(err(choice(&[("port", bad)], &cfg)), BAD_PORT, "{bad}");
    }
}

#[test]
fn standalone_needs_a_domain_and_a_complete_certificate_choice() {
    let cfg = reality();
    let standalone = |options: &[(&'static str, &str)]| {
        let mut all = vec![("mode", "standalone")];
        all.extend_from_slice(options);
        choice(&all, &cfg)
    };
    assert_eq!(err(standalone(&[])), NEEDS_DOMAIN);
    let domain = ("domain", "sub.example.com");
    let cert_of = |options: &[(&'static str, &str)]| match standalone(options).unwrap().0 {
        SubscriptionChoice::Standalone { cert, .. } => cert,
        other => panic!("{other:?}"),
    };
    assert_eq!(cert_of(&[domain]), WebCert::Cloudflare, "cf by default");
    assert_eq!(cert_of(&[domain, ("tls", "http")]), WebCert::Http01);
    assert_eq!(
        cert_of(&[domain, ("tls", "custom"), ("cert", "/c.pem"), ("key", "/k.pem")]),
        WebCert::Custom {
            cert: "/c.pem".into(),
            key: "/k.pem".into()
        }
    );
    assert_eq!(err(standalone(&[domain, ("tls", "custom"), ("cert", "/c")])), CUSTOM_PATHS);
    assert_eq!(err(standalone(&[domain, ("key", "/k")])), PATHS_NOT_CUSTOM);
    assert_eq!(err(standalone(&[domain, ("tls", "self")])), BAD_METHOD);
    assert_eq!(standalone(&[domain, ("port", "443")]).unwrap().1, Some(443));
}

#[test]
fn site_mode_ignores_and_names_endpoint_options() {
    let cfg = site();
    let r = request(&[("mode", "site"), ("port", "9000"), ("tls", "http")]).unwrap();
    assert_eq!(r.choice(&cfg).unwrap(), (SubscriptionChoice::Site, None));
    assert_eq!(r.ignored_in_site_mode(), ["--port", "--tls"]);
    assert!(request(&[]).unwrap().ignored_in_site_mode().is_empty());
}

#[test]
fn planner_finishes_the_v2_address_rules() {
    let cfg = reality();
    let env = PlanEnv::offline(true, 1);
    let plan = |address: &str| {
        let (choice, port) = choice(&[("address", address)], &cfg)?;
        enable_subscription(&cfg, &choice, port, &env)
    };
    for bad in ["0.0.0.0", "::", "224.0.0.1", "ff02::1", "::ffff:0.0.0.0"] {
        assert_eq!(err(plan(bad)), "订阅地址不能是未指定地址或组播地址", "{bad}");
    }
    let mapped = plan("::ffff:192.0.2.5").unwrap();
    let sub = mapped.subscription.unwrap();
    assert_eq!(
        sub.mode,
        SubscriptionMode::Ip {
            address: "192.0.2.5".parse().unwrap()
        }
    );
    assert_eq!(sub.port, 8448);
    let no_v6 = PlanEnv::offline(false, 1);
    let (choice, port) = choice(&[("address", "2001:db8::7")], &cfg).unwrap();
    assert_eq!(
        err(enable_subscription(&cfg, &choice, port, &no_v6)),
        "订阅地址为 IPv6，但当前系统无法监听 IPv6；请启用 IPv6 或使用 IPv4 地址"
    );
}
