use super::*;
use crate::domain::config::{PortRange, ProxyTls, WebCert};
use crate::domain::fixtures::{self, config, with_site};
use Core::{Singbox as SB, Xray as XR};
use Protocol::*;

fn preset1() -> NodeConfig {
    config(&[
        (VlessReality, 443, SB),
        (Hysteria2, 443, SB),
        (Tuic, 8443, SB),
    ])
}

fn acme(cfg: &mut NodeConfig, method: AcmeMethod) {
    cfg.tls = Some(ProxyTls {
        mode: ProxyCertMode::Acme {
            domain: "proxy.example.com".into(),
            method,
        },
        pinned: false,
    });
}

fn hop(start: u16, end: u16) -> Option<PortRange> {
    Some(PortRange { start, end })
}

fn frp(start: u16, end: u16, transport: Transport) -> Reservation {
    Reservation {
        start,
        end,
        transport,
        label: "test".into(),
    }
}

fn check(cfg: &NodeConfig, frp: &[Reservation]) -> std::result::Result<(), String> {
    PortPlan::of(cfg, frp).validate().map_err(|e| e.to_string())
}

#[test]
fn conflict_matrix() {
    type Case = (
        &'static str,
        NodeConfig,
        Vec<Reservation>,
        Option<&'static str>,
    );
    let mut cases: Vec<Case> = vec![
        ("preset 1 default layout", preset1(), vec![], None),
        (
            "two TCP inbounds on one port",
            config(&[(VlessReality, 443, SB), (Trojan, 443, SB)]),
            vec![],
            Some("协议重复使用 443/tcp"),
        ),
        (
            "Vision and XHTTP share 443 on Xray",
            config(&[(VlessReality, 443, XR), (VlessXhttp, 443, XR)]),
            vec![],
            None,
        ),
        (
            "Vision on sing-box cannot share with XHTTP",
            config(&[(VlessReality, 443, SB), (VlessXhttp, 443, XR)]),
            vec![],
            Some("协议重复使用 443/tcp"),
        ),
        (
            "shadowsocks occupies UDP too",
            config(&[(Shadowsocks, 8388, SB), (Tuic, 8388, SB)]),
            vec![],
            Some("协议重复使用 8388/udp"),
        ),
        (
            "TCP and UDP are independent",
            config(&[(Trojan, 8443, SB), (Tuic, 8443, SB)]),
            vec![],
            None,
        ),
        (
            "FRP reservation on an inbound",
            preset1(),
            vec![frp(400, 500, Transport::Tcp)],
            Some("端口 443/tcp 已保留给 FRP"),
        ),
        (
            "FRP UDP range does not block TCP",
            config(&[(VlessReality, 443, SB)]),
            vec![frp(400, 500, Transport::Udp)],
            None,
        ),
    ];

    let mut hop_cfg = preset1();
    hop_cfg.hy2.hop = hop(8000, 9000);
    cases.push((
        "hop range covers the TUIC port",
        hop_cfg.clone(),
        vec![],
        Some("Hysteria2 跳跃范围与 tuic UDP 端口冲突"),
    ));
    hop_cfg.hy2.hop = hop(400, 9000);
    cases.push((
        "hop below 1024",
        hop_cfg.clone(),
        vec![],
        Some("跳跃端口范围无效"),
    ));
    hop_cfg.hy2.hop = hop(20000, 20000);
    cases.push((
        "hop not increasing",
        hop_cfg.clone(),
        vec![],
        Some("跳跃端口范围无效"),
    ));
    hop_cfg.hy2.hop = hop(20000, 30000);
    cases.push((
        "FRP blocks the hop range",
        hop_cfg.clone(),
        vec![frp(25000, 25000, Transport::Both)],
        Some("端口 25000/udp 已保留给 FRP"),
    ));
    let mut own_port = config(&[(Hysteria2, 20500, SB)]);
    own_port.hy2.hop = hop(20000, 30000);
    cases.push(("hop may cover the Hysteria2 port", own_port, vec![], None));
    let mut no_hy2 = config(&[(Trojan, 443, SB)]);
    no_hy2.hy2.hop = hop(10, 5);
    cases.push(("hop ignored without Hysteria2", no_hy2, vec![], None));

    let mut acme_cfg = config(&[(Trojan, 443, SB), (VmessWs, 80, SB)]);
    acme(&mut acme_cfg, AcmeMethod::Http01);
    cases.push((
        "HTTP-01 reserves TCP 80",
        acme_cfg.clone(),
        vec![],
        Some("HTTP-01 验证需要保留 TCP 80，不能同时用于代理入站"),
    ));
    acme(&mut acme_cfg, AcmeMethod::Cloudflare);
    cases.push(("DNS validation leaves 80 free", acme_cfg, vec![], None));

    let site = with_site(
        config(&[(VlessReality, 443, XR), (Trojan, 8443, SB)]),
        "www.example.com",
        true,
    );
    cases.push(("site with REALITY on 443", site.clone(), vec![], None));
    let mut on443 = with_site(
        config(&[(VlessReality, 8443, SB), (Trojan, 443, SB)]),
        "www.example.com",
        true,
    );
    cases.push((
        "HTTPS entrance blocks non-REALITY 443",
        on443.clone(),
        vec![],
        Some("TCP 443 被非 REALITY 协议占用"),
    ));
    if let Some(s) = on443.site.as_mut() {
        s.https_entry = false;
    }
    cases.push(("without the entrance 443 is free", on443, vec![], None));
    cases.push((
        "site needs 80",
        with_site(
            config(&[(VlessReality, 443, SB), (VmessWs, 80, SB)]),
            "www.example.com",
            false,
        ),
        vec![],
        Some("网站端口与代理协议冲突"),
    ));
    cases.push((
        "site internal port",
        with_site(
            config(&[(VlessReality, 443, SB), (Anytls, 10443, SB)]),
            "www.example.com",
            false,
        ),
        vec![],
        Some("网站端口与代理协议冲突"),
    ));
    cases.push((
        "FRP blocks the site internal port",
        site.clone(),
        vec![frp(10443, 10443, Transport::Tcp)],
        Some("端口 10443/tcp 已保留给 FRP"),
    ));
    let mut acme_site = site.clone();
    acme(&mut acme_site, AcmeMethod::Http01);
    cases.push(("HTTP-01 shares the site's port 80", acme_site, vec![], None));

    let mut guard = config(&[(VlessReality, 443, XR)]);
    guard.reality.guard_port = 443;
    cases.push((
        "guard on a proxy port",
        guard.clone(),
        vec![],
        Some("REALITY guard 端口缺失或与代理冲突"),
    ));
    guard.reality.guard_port = 0;
    cases.push((
        "guard missing",
        guard.clone(),
        vec![],
        Some("REALITY guard 端口缺失或与代理冲突"),
    ));
    let mut sb_guard = config(&[(VlessReality, 443, SB)]);
    sb_guard.reality.guard_port = 0;
    cases.push(("no guard without Xray REALITY", sb_guard, vec![], None));
    let mut site_guard = site.clone();
    site_guard.reality.guard_port = 10443;
    cases.push((
        "guard on the site port",
        site_guard,
        vec![],
        Some("REALITY guard 端口与网站监听冲突"),
    ));
    let mut sub_guard = config(&[(VlessReality, 443, XR)]);
    sub_guard.subscription = Some(fixtures::ip_subscription(18000));
    cases.push((
        "guard on the subscription port",
        sub_guard,
        vec![],
        Some("REALITY guard 端口与订阅监听冲突"),
    ));
    cases.push((
        "FRP blocks the guard",
        config(&[(VlessReality, 443, XR)]),
        vec![frp(18000, 18000, Transport::Tcp)],
        Some("端口 18000/tcp 已保留给 FRP"),
    ));

    let mut sub = config(&[(VlessReality, 443, SB), (Trojan, 8448, SB)]);
    sub.subscription = Some(fixtures::standalone_subscription(
        "sub.example.com",
        8448,
        WebCert::Cloudflare,
    ));
    cases.push((
        "subscription on a proxy port",
        sub,
        vec![],
        Some("订阅或验证端口与代理端口冲突"),
    ));
    let mut sub_site = site.clone();
    sub_site.subscription = Some(fixtures::standalone_subscription(
        "sub.example.com",
        8448,
        WebCert::Http01,
    ));
    cases.push((
        "standalone HTTP-01 next to the site",
        sub_site,
        vec![],
        Some("订阅端口与自建站冲突：请复用网站，或为独立站选择其他端口和 DNS 验证"),
    ));
    let mut sub80 = config(&[(VlessReality, 443, SB)]);
    sub80.subscription = Some(fixtures::standalone_subscription(
        "sub.example.com",
        80,
        WebCert::Http01,
    ));
    cases.push((
        "HTTPS subscription on 80",
        sub80,
        vec![],
        Some("HTTPS 订阅端口不能与 HTTP-01 验证端口 80 相同"),
    ));
    let mut ip80 = config(&[(VlessReality, 443, SB), (VmessWs, 80, SB)]);
    ip80.subscription = Some(fixtures::ip_subscription(8448));
    cases.push(("IP subscription has no HTTP-01", ip80.clone(), vec![], None));
    ip80.subscription = Some(fixtures::standalone_subscription(
        "sub.example.com",
        8448,
        WebCert::Http01,
    ));
    cases.push((
        "standalone HTTP-01 reserves 80",
        ip80,
        vec![],
        Some("HTTP-01 验证需要保留 TCP 80，不能同时用于代理入站"),
    ));

    for (name, cfg, reservations, want) in cases {
        let got = check(&cfg, &reservations);
        match want {
            None => assert_eq!(got, Ok(()), "{name}"),
            Some(msg) => assert_eq!(got, Err(msg.to_owned()), "{name}"),
        }
    }
}

#[test]
fn https_front_end_only_without_reality_on_443() {
    let owners = |cfg: &NodeConfig| -> Vec<Owner> {
        PortPlan::of(cfg, &[])
            .listeners()
            .iter()
            .map(|l| l.owner.clone())
            .collect()
    };
    let on443 = with_site(config(&[(VlessReality, 443, SB)]), "www.example.com", true);
    assert!(!owners(&on443).contains(&Owner::SiteHttps443));
    let elsewhere = with_site(config(&[(VlessReality, 8443, SB)]), "www.example.com", true);
    assert!(owners(&elsewhere).contains(&Owner::SiteHttps443));
    assert_eq!(elsewhere.site_public_port(), 443);
    let mut no_entry = elsewhere.clone();
    if let Some(s) = no_entry.site.as_mut() {
        s.https_entry = false;
    }
    assert_eq!(no_entry.site_public_port(), 8443);
}

#[test]
fn allocation_avoids_every_reserved_listener() {
    let none = &NoProbe;
    // UDP 443 is taken by Hysteria2: TUIC moves to the next candidate.
    let mut cfg = config(&[(VlessReality, 443, SB), (Hysteria2, 443, SB), (Tuic, 0, SB)]);
    assert_eq!(
        PortPlan::of(&cfg, &[])
            .allocate(Tuic, SB, none, None)
            .unwrap(),
        8443
    );
    // The hop range covers every remaining candidate (v2 picked 2053 and failed later).
    cfg.hy2.hop = hop(2000, 9999);
    assert_eq!(
        PortPlan::of(&cfg, &[])
            .allocate(Tuic, SB, none, None)
            .unwrap(),
        20000
    );
    // FRP reservations are skipped as well.
    let reserved = [frp(20000, 20005, Transport::Both)];
    assert_eq!(
        PortPlan::of(&cfg, &reserved)
            .allocate(Tuic, SB, none, None)
            .unwrap(),
        20006
    );

    // The site's HTTPS entrance keeps 443 for REALITY only.
    let site = with_site(
        config(&[(VlessReality, 0, SB), (Trojan, 0, SB)]),
        "www.example.com",
        true,
    );
    let plan = PortPlan::of(&site, &[]);
    assert_eq!(plan.allocate(Trojan, SB, none, None).unwrap(), 8443);
    assert_eq!(plan.allocate(VlessReality, SB, none, None).unwrap(), 443);
    assert!(!plan.is_free(80, Transport::Tcp, &Owner::Inbound(VmessWs), none, None));
    assert!(!plan.is_free(10443, Transport::Tcp, &Owner::Inbound(Anytls), none, None));

    // ACME HTTP-01 and the subscription endpoint.
    let mut misc = config(&[(Trojan, 443, SB)]);
    acme(&mut misc, AcmeMethod::Http01);
    misc.subscription = Some(fixtures::ip_subscription(8448));
    let plan = PortPlan::of(&misc, &[]);
    assert!(!plan.is_free(80, Transport::Tcp, &Owner::Inbound(VmessWs), none, None));
    assert!(!plan.is_free(8448, Transport::Tcp, &Owner::Inbound(Anytls), none, None));
    assert!(plan.is_free(8448, Transport::Udp, &Owner::Inbound(Tuic), none, None));
    assert!(!plan.is_free(0, Transport::Udp, &Owner::Inbound(Tuic), none, None));

    // XHTTP may join Vision on Xray only.
    let xray = PortPlan::of(&config(&[(VlessReality, 443, XR)]), &[]);
    assert_eq!(xray.allocate(VlessXhttp, XR, none, None).unwrap(), 443);
    let singbox = PortPlan::of(&config(&[(VlessReality, 443, SB)]), &[]);
    assert_eq!(singbox.allocate(VlessXhttp, XR, none, None).unwrap(), 8443);
}

#[test]
fn guard_allocation() {
    let none = &NoProbe;
    let mut cfg = config(&[(VlessReality, 18000, XR)]);
    cfg.reality.guard_port = 0;
    assert_eq!(
        PortPlan::of(&cfg, &[]).allocate_guard(none, None).unwrap(),
        18001
    );
    let tcp = [frp(18001, 18010, Transport::Tcp)];
    assert_eq!(
        PortPlan::of(&cfg, &tcp).allocate_guard(none, None).unwrap(),
        18011
    );
    let udp = [frp(18001, 19999, Transport::Udp)];
    assert_eq!(
        PortPlan::of(&cfg, &udp).allocate_guard(none, None).unwrap(),
        18001
    );
    let busy = FnProbe(|_, _| true);
    assert_eq!(
        PortPlan::of(&cfg, &[])
            .allocate_guard(&busy, None)
            .unwrap_err()
            .to_string(),
        "没有空闲的 REALITY guard 端口"
    );
}

#[test]
fn probe_and_previous_generation() {
    let busy443 = FnProbe(|port, t| port == 443 && t == Transport::Tcp);
    let empty = config(&[(VlessReality, 0, SB)]);
    let plan = PortPlan::of(&empty, &[]);
    assert_eq!(
        plan.allocate(VlessReality, SB, &busy443, None).unwrap(),
        8443
    );
    assert_eq!(plan.allocate(Hysteria2, SB, &busy443, None).unwrap(), 443);

    // Held by the same owner in the previous generation: not foreign.
    let prev = PortPlan::of(&config(&[(VlessReality, 443, SB)]), &[]);
    assert_eq!(
        plan.allocate(VlessReality, SB, &busy443, Some(&prev))
            .unwrap(),
        443
    );
    // Another core inbound is stopped by the apply as well (v2 semantics).
    let prev_trojan = PortPlan::of(&config(&[(Trojan, 443, SB)]), &[]);
    assert_eq!(
        plan.allocate(VlessReality, SB, &busy443, Some(&prev_trojan))
            .unwrap(),
        443
    );
    // The IP subscription worker keeps running: its port stays foreign.
    let mut sub = config(&[(Trojan, 8443, SB)]);
    sub.subscription = Some(fixtures::ip_subscription(443));
    let prev_sub = PortPlan::of(&sub, &[]);
    assert_eq!(
        plan.allocate(VlessReality, SB, &busy443, Some(&prev_sub))
            .unwrap(),
        8443
    );
    // UDP probing is independent.
    let busy_udp = FnProbe(|port, t| port == 443 && t == Transport::Udp);
    assert_eq!(
        plan.allocate(Shadowsocks, SB, &busy_udp, None).unwrap(),
        8388
    );
    assert!(!plan.is_free(
        443,
        Transport::Both,
        &Owner::Inbound(Shadowsocks),
        &busy_udp,
        None
    ));

    let all = FnProbe(|_, _| true);
    assert_eq!(
        plan.allocate(Trojan, SB, &all, None)
            .unwrap_err()
            .to_string(),
        "未找到空闲端口"
    );
}

#[test]
fn listeners_without_sockets_never_excuse_probed_ports() {
    let plan = PortPlan::of(&config(&[(VlessReality, 443, SB)]), &[]);
    // The previous generation hopped 20000–30000 (an nft REDIRECT, no socket).
    let mut hopped = config(&[(Hysteria2, 25000, SB)]);
    hopped.hy2.hop = hop(20000, 30000);
    let prev = PortPlan::of(&hopped, &[]);
    let foreign = FnProbe(|port, t| port == 20005 && t == Transport::Udp);
    let tuic = Owner::Inbound(Tuic);
    assert!(!plan.is_free(20005, Transport::Udp, &tuic, &foreign, Some(&prev)));
    // Auto-allocation skips a foreign socket inside the old range as well.
    let busy = FnProbe(|port, t| {
        t == Transport::Udp && (defaults::COMMON_PORTS.contains(&port) || port == 20000)
    });
    assert_eq!(plan.allocate(Tuic, SB, &busy, Some(&prev)).unwrap(), 20001);
    // The Hysteria2 socket itself is still ours.
    let own = FnProbe(|port, _| port == 25000);
    let hy2 = Owner::Inbound(Hysteria2);
    assert!(plan.is_free(25000, Transport::Udp, &hy2, &own, Some(&prev)));

    // The proxy's HTTP-01 responder runs only during issuance.
    let mut issued = config(&[(Trojan, 443, SB)]);
    acme(&mut issued, AcmeMethod::Http01);
    let prev = PortPlan::of(&issued, &[]);
    let busy80 = FnProbe(|port, t| port == 80 && t == Transport::Tcp);
    let vmess = Owner::Inbound(VmessWs);
    assert!(!plan.is_free(80, Transport::Tcp, &vmess, &busy80, Some(&prev)));
    // The site's nginx holds 80 and is stopped by the apply: not foreign.
    let prev = PortPlan::of(&with_site(preset1(), "www.example.com", false), &[]);
    assert!(plan.is_free(80, Transport::Tcp, &vmess, &busy80, Some(&prev)));
}

#[test]
fn firewall_ports_are_public_and_merged() {
    let p1 = PortPlan::of(&preset1(), &[]);
    assert_eq!(
        p1.firewall_ports(),
        [
            (443, 443, Transport::Tcp),
            (443, 443, Transport::Udp),
            (8443, 8443, Transport::Udp)
        ]
    );

    let mut cfg = config(&[
        (VlessReality, 443, XR),
        (Trojan, 444, SB),
        (Shadowsocks, 8388, SB),
        (Hysteria2, 19999, SB),
    ]);
    cfg.hy2.hop = hop(20000, 30000);
    acme(&mut cfg, AcmeMethod::Http01);
    let cfg = with_site(cfg, "www.example.com", true);
    let reserved = [frp(7000, 7000, Transport::Tcp)];
    assert_eq!(
        PortPlan::of(&cfg, &reserved).firewall_ports(),
        [
            (80, 80, Transport::Tcp),
            (443, 444, Transport::Tcp),
            (8388, 8388, Transport::Tcp),
            (8388, 8388, Transport::Udp),
            (19999, 30000, Transport::Udp),
        ],
        "internal site port, guard and FRP stay closed; ACME and site share 80"
    );
}

#[test]
fn merge_ranges() {
    assert_eq!(merge(vec![]), vec![]);
    assert_eq!(merge(vec![(5, 6), (1, 2), (3, 4)]), vec![(1, 6)]);
    assert_eq!(merge(vec![(5, 6), (1, 3)]), vec![(1, 3), (5, 6)]);
    assert_eq!(
        merge(vec![(1, 10), (2, 3), (12, 12)]),
        vec![(1, 10), (12, 12)]
    );
    assert_eq!(
        merge(vec![(65535, 65535), (65534, 65535)]),
        vec![(65534, 65535)]
    );
}

#[test]
fn owner_labels() {
    assert_eq!(Owner::Inbound(Tuic).label(), "TUIC-v5");
    assert_eq!(Owner::Frp("web".into()).label(), "FRP web");
    assert_eq!(
        conflict_message(&Owner::SiteInternal, &Owner::Hy2Hop, 9, true),
        "端口 9/udp 冲突: 网站内部 HTTPS 与 Hysteria2 端口跳跃"
    );
}
