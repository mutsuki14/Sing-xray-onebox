use super::*;
use crate::domain::fixtures::{config, with_site, ADDR};
use crate::domain::ports::FnProbe;
use crate::domain::protocol::Core::{Singbox as SB, Xray as XR};
use Protocol::*;

fn env() -> PlanEnv<'static> {
    PlanEnv::offline(true, 0)
}

fn reality() -> NodeConfig {
    config(&[(VlessReality, 443, XR), (Tuic, 443, SB)])
}

fn site() -> NodeConfig {
    with_site(reality(), "www.example.com", true)
}

#[test]
fn settings_do_not_outlive_the_site() {
    // Documented change from v2: disabled sites keep no dormant settings.
    let mut custom = site_title(&site(), "我的站").unwrap();
    custom = site_theme(&custom, SiteTheme::Ocean).unwrap();
    let off = disable_site(&custom).unwrap();
    assert!(off.site.is_none());
    let on = enable_site(&off, "www.example.com", WebCert::Http01, &env()).unwrap();
    let s = on.site.unwrap();
    assert_eq!((s.title.as_str(), s.theme), ("山间手记", SiteTheme::Forest));
    // Re-targeting an active site keeps them.
    let moved = enable_site(&custom, "new.example.com", WebCert::Http01, &env()).unwrap();
    let s = moved.site.unwrap();
    assert_eq!((s.title.as_str(), s.theme), ("我的站", SiteTheme::Ocean));
}

#[test]
fn enable_and_disable() {
    let trojan = config(&[(Trojan, 443, SB)]);
    let e = enable_site(&trojan, "www.example.com", WebCert::Http01, &env()).unwrap_err();
    assert_eq!(
        e.to_string(),
        "自建 REALITY 网站需要先开启 REALITY 协议；独立订阅请用 subscription enable"
    );
    let e = enable_site(&reality(), "localhost", WebCert::Http01, &env()).unwrap_err();
    assert_eq!(e.to_string(), "自建站需要 REALITY 协议及有效域名");
    let on = enable_site(&reality(), "WWW.Example.com", WebCert::Cloudflare, &env()).unwrap();
    let s = on.site_active().unwrap();
    assert_eq!(
        (s.domain.as_str(), s.https_entry),
        ("www.example.com", true)
    );
    assert_eq!(s.cert, WebCert::Cloudflare);
    assert_eq!(on.reality.dest.to_string(), "127.0.0.1:10443");

    let off = disable_site(&on).unwrap();
    assert!(off.site.is_none());
    assert_eq!(off.reality.sni, "www.microsoft.com");
    assert_eq!(disable_site(&off).unwrap_err().to_string(), "网站未启用");
    let mut sub = on.clone();
    sub.subscription = Some(SubscriptionConfig {
        mode: SubscriptionMode::Site,
        port: 443,
    });
    assert_eq!(
        disable_site(&sub).unwrap_err().to_string(),
        "请先关闭订阅或将订阅切换为独立 HTTPS 站点"
    );
}

#[test]
fn site_settings() {
    assert_eq!(
        site_https(&reality(), false).unwrap_err().to_string(),
        "请先启用网站"
    );
    let off = site_https(&site(), false).unwrap();
    assert!(!off.site.as_ref().unwrap().https_entry);
    // The HTTPS front-end cannot coexist with a non-REALITY proxy on TCP 443.
    let mut trojan = with_site(
        config(&[(VlessReality, 8443, SB), (Trojan, 443, SB)]),
        "www.example.com",
        false,
    );
    assert_eq!(
        site_https(&trojan, true).unwrap_err().to_string(),
        "TCP 443 被非 REALITY 协议占用"
    );
    trojan = site_title(&trojan, " 新的标题 ").unwrap();
    assert_eq!(trojan.site.as_ref().unwrap().title, "新的标题");
    assert!(site_title(&trojan, "")
        .unwrap_err()
        .to_string()
        .starts_with("网站标题不能为空"));
    let t = site_template(&trojan, SiteTemplate::Docs).unwrap();
    let t = site_theme(&t, SiteTheme::Ocean).unwrap();
    let t = site_description(&t, "记录生活").unwrap();
    let s = t.site.as_ref().unwrap();
    assert_eq!(
        (s.template, s.theme),
        (SiteTemplate::Docs, SiteTheme::Ocean)
    );
    assert_eq!(s.description, "记录生活");
    assert_eq!(
        site_description(&t, "a\u{0}b").unwrap_err().to_string(),
        "网站描述不能包含控制字符"
    );
}

#[test]
fn subscription_modes() {
    // IP mode defaults to the node address and port 8448.
    let ip = enable_subscription(
        &reality(),
        &SubscriptionChoice::Ip { address: None },
        None,
        &env(),
    )
    .unwrap();
    let sub = ip.subscription.clone().unwrap();
    assert_eq!(sub.port, 8448);
    assert_eq!(
        sub.mode,
        SubscriptionMode::Ip {
            address: IpAddr::V4(ADDR)
        }
    );
    let mapped = SubscriptionChoice::Ip {
        address: Some("::ffff:192.0.2.5".parse().unwrap()),
    };
    let next = enable_subscription(&reality(), &mapped, Some(9000), &env()).unwrap();
    assert_eq!(
        next.subscription.unwrap(),
        SubscriptionConfig {
            mode: SubscriptionMode::Ip {
                address: "192.0.2.5".parse().unwrap()
            },
            port: 9000
        }
    );
    let unspecified = SubscriptionChoice::Ip {
        address: Some("0.0.0.0".parse().unwrap()),
    };
    assert_eq!(
        enable_subscription(&reality(), &unspecified, None, &env())
            .unwrap_err()
            .to_string(),
        "订阅地址不能是未指定地址或组播地址"
    );
    let mut domain_only = reality();
    domain_only.server = ServerAddr {
        addr: "proxy.example.com".parse().unwrap(),
        ipv4: None,
        ipv6: None,
        ipv4_warp: false,
        ipv6_warp: false,
    };
    assert_eq!(
        enable_subscription(
            &domain_only,
            &SubscriptionChoice::Ip { address: None },
            None,
            &env()
        )
        .unwrap_err()
        .to_string(),
        "没有可用的服务器 IP，请用 --address 指定 IPv4 或 IPv6 地址"
    );

    // Site mode reuses the site's public port.
    assert!(
        enable_subscription(&reality(), &SubscriptionChoice::Site, None, &env())
            .unwrap_err()
            .to_string()
            .starts_with("没有可复用的自建站")
    );
    let mut no_entry = site_https(&site(), false).unwrap();
    no_entry = enable_subscription(&no_entry, &SubscriptionChoice::Site, Some(1), &env()).unwrap();
    assert_eq!(no_entry.subscription.as_ref().unwrap().port, 443);

    // Standalone.
    let standalone = SubscriptionChoice::Standalone {
        domain: "Sub.Example.com".into(),
        cert: WebCert::Http01,
    };
    let next = enable_subscription(&reality(), &standalone, None, &env()).unwrap();
    assert_eq!(
        next.subscription.as_ref().unwrap().mode,
        SubscriptionMode::Standalone {
            domain: "sub.example.com".into(),
            cert: WebCert::Http01,
            http01_port80: true,
        }
    );
    let bad = SubscriptionChoice::Standalone {
        domain: "sub".into(),
        cert: WebCert::Cloudflare,
    };
    assert_eq!(
        enable_subscription(&reality(), &bad, None, &env())
            .unwrap_err()
            .to_string(),
        "订阅域名无效"
    );
    // Next to the site, HTTP-01 is refused (two nginx instances on port 80).
    assert_eq!(
        enable_subscription(&site(), &standalone, None, &env())
            .unwrap_err()
            .to_string(),
        "订阅端口与自建站冲突：请复用网站，或为独立站选择其他端口和 DNS 验证"
    );
    let off = disable_subscription(&next).unwrap();
    assert!(off.subscription.is_none());
}

#[test]
fn subscription_ports() {
    let ip = SubscriptionChoice::Ip { address: None };
    assert_eq!(
        enable_subscription(&reality(), &ip, Some(0), &env())
            .unwrap_err()
            .to_string(),
        "订阅端口无效"
    );
    assert_eq!(
        enable_subscription(&reality(), &ip, Some(443), &env())
            .unwrap_err()
            .to_string(),
        "订阅或验证端口与代理端口冲突"
    );
    let busy = FnProbe(|p, _| p == 8448);
    let probing = PlanEnv {
        probe: &busy,
        ..env()
    };
    assert_eq!(
        enable_subscription(&reality(), &ip, None, &probing)
            .unwrap_err()
            .to_string(),
        "订阅端口 8448 已被占用"
    );
    // Re-enabling on the port the endpoint already holds is fine.
    let current = enable_subscription(&reality(), &ip, None, &env()).unwrap();
    let again = enable_subscription(&current, &ip, None, &probing).unwrap();
    assert_eq!(again, current);
}

#[test]
fn ipv6_subscription_address_needs_ipv6_sockets() {
    const NO_V6: &str = "订阅地址为 IPv6，但当前系统无法监听 IPv6；请启用 IPv6 或使用 IPv4 地址";
    let no_v6 = PlanEnv::offline(false, 0);
    let v6 = SubscriptionChoice::Ip {
        address: Some("2001:db8::7".parse().unwrap()),
    };
    let e = enable_subscription(&reality(), &v6, None, &no_v6).unwrap_err();
    assert_eq!(e.to_string(), NO_V6);
    let ok = enable_subscription(&reality(), &v6, None, &env()).unwrap();
    assert!(matches!(
        ok.subscription.unwrap().mode,
        SubscriptionMode::Ip { address } if address.is_ipv6()
    ));
    // An IPv4-mapped address is IPv4 after canonicalization.
    let mapped = SubscriptionChoice::Ip {
        address: Some("::ffff:192.0.2.5".parse().unwrap()),
    };
    enable_subscription(&reality(), &mapped, None, &no_v6).unwrap();

    // The default prefers a detected IPv4 when IPv6 cannot listen ...
    let mut dual = reality();
    dual.server.addr = Host::Ip("2001:db8::10".parse().unwrap());
    dual.server.ipv6 = Some("2001:db8::10".parse().unwrap());
    let auto = SubscriptionChoice::Ip { address: None };
    let next = enable_subscription(&dual, &auto, None, &no_v6).unwrap();
    assert_eq!(
        next.subscription.unwrap().mode,
        SubscriptionMode::Ip {
            address: IpAddr::V4(ADDR)
        }
    );
    // ... keeps the IPv6 connection address when it can ...
    let next = enable_subscription(&dual, &auto, None, &env()).unwrap();
    assert_eq!(
        next.subscription.unwrap().mode,
        SubscriptionMode::Ip {
            address: "2001:db8::10".parse().unwrap()
        }
    );
    // ... and refuses an IPv6-only node without IPv6 sockets.
    dual.server.ipv4 = None;
    let e = enable_subscription(&dual, &auto, None, &no_v6).unwrap_err();
    assert_eq!(e.to_string(), NO_V6);
}

#[test]
fn default_address_order() {
    let mut cfg = reality();
    assert_eq!(default_subscription_address(&cfg), Some(IpAddr::V4(ADDR)));
    cfg.server = ServerAddr {
        addr: "proxy.example.com".parse().unwrap(),
        ipv4: Some("224.0.0.1".parse().unwrap()),
        ipv6: Some("2001:0db8::7".parse().unwrap()),
        ipv4_warp: false,
        ipv6_warp: false,
    };
    assert_eq!(
        default_subscription_address(&cfg),
        Some("2001:db8::7".parse().unwrap()),
        "multicast addresses are skipped (spec G example)"
    );
}
