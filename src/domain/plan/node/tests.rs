use super::*;
use crate::domain::fixtures::{config, with_site};
use crate::domain::ports::FnProbe;
use crate::domain::protocol::Transport;
use crate::sys::rand::SeqRandom;
use Core::{Singbox as SB, Xray as XR};
use Protocol::*;

fn env() -> PlanEnv<'static> {
    PlanEnv::offline(true, 0)
}

#[test]
fn vmess_tls_decision_is_pinned_across_unrelated_changes() {
    // A v2 state with VMESS_TLS=1 and a self-signed certificate.
    let mut pinned = config(&[(Trojan, 443, SB), (VmessWs, 8080, SB)]);
    pinned.vmess_tls = true;
    pinned.validate().unwrap();
    let next = remove(&pinned, Trojan).unwrap();
    assert!(
        next.vmess_tls,
        "removing another protocol keeps the decision"
    );
    assert!(next.tls.as_ref().unwrap().pinned);
    let next = add_default(&pinned, Tuic).unwrap();
    assert!(next.vmess_tls, "adding another protocol keeps the decision");
    // Changing the certificate re-decides it (Trojan keeps needing one).
    let next = set_proxy_cert(&pinned, &ProxyCertChoice::SelfSigned).unwrap();
    assert!(!next.vmess_tls);
}

fn preset1() -> NodeConfig {
    config(&[
        (VlessReality, 443, SB),
        (Hysteria2, 443, SB),
        (Tuic, 8443, SB),
    ])
}

fn acme_trojan() -> NodeConfig {
    let mut cfg = config(&[(Trojan, 443, SB)]);
    cfg.tls = Some(ProxyTls {
        mode: ProxyCertMode::Acme {
            domain: "proxy.example.com".into(),
            method: AcmeMethod::Cloudflare,
        },
        pinned: false,
    });
    cfg
}

fn add_default(cfg: &NodeConfig, p: Protocol) -> Result<NodeConfig> {
    add(cfg, p, &AddOptions::default(), &env(), &mut SeqRandom(50))
}

#[test]
fn add_assigns_core_port_and_certificate() {
    let reality = config(&[(VlessReality, 443, XR)]);
    assert_eq!(
        add_default(&reality, VlessReality).unwrap_err().to_string(),
        "协议已存在"
    );
    let next = add_default(&reality, Tuic).unwrap();
    let tuic = next.inbound(Tuic).unwrap();
    assert_eq!(
        (tuic.port, tuic.core),
        (443, SB),
        "TUIC is sing-box only; UDP 443 is free"
    );
    assert!(
        next.tls.as_ref().unwrap().pinned,
        "a needed certificate defaults to self-signed"
    );
    let next = add_default(&reality, Shadowsocks).unwrap();
    assert_eq!(
        next.inbound(Shadowsocks).unwrap().core,
        XR,
        "first inbound's core is preferred"
    );
    let next = add_default(&reality, Hysteria2).unwrap();
    assert_eq!(next.core_of(Hysteria2), Some(SB));
    let next = add(
        &reality,
        Hysteria2,
        &opts_core(XR),
        &env(),
        &mut SeqRandom(1),
    )
    .unwrap();
    assert_eq!(
        next.core_of(Hysteria2),
        Some(SB),
        "--core does not move Hysteria2 off sing-box (v2 and install rule)"
    );
    let opts = AddOptions {
        hy2_core: Some(XR),
        ..AddOptions::default()
    };
    let next = add(&reality, Hysteria2, &opts, &env(), &mut SeqRandom(1)).unwrap();
    assert_eq!(next.core_of(Hysteria2), Some(XR), "--hy2-core does");
    let next = add_default(&reality, VlessXhttp).unwrap();
    assert_eq!(
        next.inbound(VlessXhttp).unwrap().port,
        443,
        "XHTTP joins Vision on Xray"
    );
}

#[test]
fn add_hysteria2_options() {
    let reality = config(&[(VlessReality, 443, SB), (Tuic, 8443, SB)]);
    let hop = PortRange {
        start: 20000,
        end: 30000,
    };
    let opts = AddOptions {
        hy2_obfs: true,
        hy2_hop: Some(hop),
        ..AddOptions::default()
    };
    let next = add(&reality, Hysteria2, &opts, &env(), &mut SeqRandom(1)).unwrap();
    assert!(next.hy2.obfs);
    assert_eq!(next.hy2.hop, Some(hop));
    assert_eq!(next.inbound(Hysteria2).unwrap().port, 443);
    // Without options the stored settings stay as they are.
    let next = add_default(&reality, Hysteria2).unwrap();
    assert_eq!(next.hy2, Hy2Settings::default());

    // Hysteria2 options need Hysteria2.
    let only = |opts: AddOptions| {
        add(&reality, Trojan, &opts, &env(), &mut SeqRandom(1))
            .unwrap_err()
            .to_string()
    };
    for opts in [
        AddOptions {
            hy2_obfs: true,
            ..AddOptions::default()
        },
        AddOptions {
            hy2_hop: Some(hop),
            ..AddOptions::default()
        },
        AddOptions {
            hy2_core: Some(SB),
            ..AddOptions::default()
        },
    ] {
        assert_eq!(only(opts), "未选择 hysteria2");
    }
    // The hop range must not cover another UDP inbound (TUIC on 8443).
    let opts = AddOptions {
        hy2_hop: Some(PortRange {
            start: 8000,
            end: 9000,
        }),
        ..AddOptions::default()
    };
    let e = add(&reality, Hysteria2, &opts, &env(), &mut SeqRandom(1)).unwrap_err();
    assert_eq!(e.to_string(), "Hysteria2 跳跃范围与 tuic UDP 端口冲突");
    let opts = AddOptions {
        hy2_hop: Some(PortRange {
            start: 100,
            end: 200,
        }),
        ..AddOptions::default()
    };
    let e = add(&reality, Hysteria2, &opts, &env(), &mut SeqRandom(1)).unwrap_err();
    assert_eq!(e.to_string(), "跳跃端口范围无效");
}

#[test]
fn hysteria2_options_after_install() {
    let p1 = preset1();
    let hop = PortRange {
        start: 20000,
        end: 30000,
    };
    let next = set_hy2(&p1, true, Some(hop), &env()).unwrap();
    assert!(next.hy2.obfs);
    assert_eq!(next.hy2.hop, Some(hop));
    let off = set_hy2(&next, false, None, &env()).unwrap();
    assert_eq!(off.hy2, Hy2Settings::default());
    let e = set_hy2(&config(&[(Tuic, 443, SB)]), true, None, &env()).unwrap_err();
    assert_eq!(e.to_string(), "未启用 Hysteria2");
    // Checked against other UDP listeners and FRP reservations.
    let e = set_hy2(
        &p1,
        false,
        Some(PortRange {
            start: 8000,
            end: 9000,
        }),
        &env(),
    )
    .unwrap_err();
    assert_eq!(e.to_string(), "Hysteria2 跳跃范围与 tuic UDP 端口冲突");
    let reserved = [crate::domain::ports::Reservation {
        start: 25000,
        end: 25010,
        transport: Transport::Udp,
        label: "game".into(),
    }];
    let with_frp = PlanEnv {
        frp: &reserved,
        ..env()
    };
    let e = set_hy2(&p1, false, Some(hop), &with_frp).unwrap_err();
    assert_eq!(e.to_string(), "端口 25000/udp 已保留给 FRP");
}

#[test]
fn vmess_host_header() {
    let cdn = config(&[(VlessWs, 443, SB), (VmessWs, 8080, SB)]);
    let next = set_vmess_host(&cdn, Some(" CDN.Example.com ")).unwrap();
    assert_eq!(next.vmess_host.as_deref(), Some("cdn.example.com"));
    assert_eq!(set_vmess_host(&next, Some("")).unwrap().vmess_host, None);
    assert_eq!(set_vmess_host(&next, None).unwrap().vmess_host, None);
    assert_eq!(
        set_vmess_host(&cdn, Some("1.2.3.4"))
            .unwrap_err()
            .to_string(),
        "VMess Host 域名无效"
    );
    // `add vmess-ws --domain …` sets it too.
    let opts = AddOptions {
        vmess_host: Some("cdn.example.com".into()),
        ..AddOptions::default()
    };
    let base = config(&[(VlessWs, 443, SB)]);
    let next = add(&base, VmessWs, &opts, &env(), &mut SeqRandom(1)).unwrap();
    assert_eq!(next.vmess_host.as_deref(), Some("cdn.example.com"));
    assert!(
        !next.vmess_tls,
        "self-signed: plain VMess sends the Host header"
    );
    // Removing VMess keeps it (v2 kept DOMAIN).
    let next = remove(&next, VmessWs).unwrap();
    assert_eq!(next.vmess_host.as_deref(), Some("cdn.example.com"));
}

#[test]
fn add_recomputes_vmess_tls() {
    // v2 skipped this on `add` (B-9.1 #9).
    let next = add_default(&acme_trojan(), VmessWs).unwrap();
    assert!(next.vmess_tls);
    assert_eq!(next.inbound(VmessWs).unwrap().port, 8080);
    let next = add_default(&config(&[(Trojan, 443, SB)]), VmessWs).unwrap();
    assert!(!next.vmess_tls, "self-signed keeps VMess plain");
}

#[test]
fn add_first_reality_generates_keys_and_target() {
    let cdn = config(&[(VlessWs, 443, SB), (VmessWs, 8080, SB)]);
    assert!(cdn.creds.reality.is_none());
    let opts = AddOptions {
        core: Some(XR),
        reality: RealityChoice::OwnSite(OwnSite {
            domain: "www.example.com".into(),
            title: None,
            https_entry: false,
            cert: WebCert::Http01,
        }),
        ..AddOptions::default()
    };
    let next = add(&cdn, VlessReality, &opts, &env(), &mut SeqRandom(5)).unwrap();
    assert!(next.creds.reality.is_some());
    assert_eq!(next.inbound(VlessReality).unwrap().port, 8443);
    assert_eq!(next.reality.dest.to_string(), "127.0.0.1:10443");
    assert!(next.uses_guard());

    // The guard moves when its port has been taken in the meantime.
    let mut taken = config(&[(Trojan, 18000, SB)]);
    taken.reality.guard_port = 18000;
    let next = add(
        &taken,
        VlessReality,
        &opts_core(XR),
        &env(),
        &mut SeqRandom(5),
    )
    .unwrap();
    assert_eq!(next.reality.guard_port, 18001);
}

#[test]
fn first_reality_never_inherits_a_dead_loopback_target() {
    // A target left on a removed site (or a v2 leftover): no site, loopback.
    let mut stale = config(&[(Trojan, 443, SB)]);
    stale.reality.sni = "www.example.com".into();
    stale.reality.dest = crate::domain::defaults::site_dest(8443);
    let next = add_default(&stale, VlessReality).unwrap();
    assert_eq!(next.reality.sni, "www.microsoft.com");
    assert_eq!(next.reality.dest.to_string(), "www.microsoft.com:443");
    // An explicit choice still wins, including an explicit loopback target.
    let opts = AddOptions {
        reality: RealityChoice::Dest("127.0.0.1:24443".parse().unwrap()),
        ..AddOptions::default()
    };
    let next = add(&stale, VlessReality, &opts, &env(), &mut SeqRandom(5)).unwrap();
    assert_eq!(next.reality.dest.to_string(), "127.0.0.1:24443");
    // Later REALITY inbounds keep whatever the first one uses.
    let next = add_default(&next, VlessGrpc).unwrap();
    assert_eq!(next.reality.dest.to_string(), "127.0.0.1:24443");
    // External targets are kept for the first inbound too.
    let mut apple = config(&[(Trojan, 443, SB)]);
    apple.reality = crate::domain::defaults::reality_target(18000);
    apple.reality.sni = "www.apple.com".into();
    apple.reality.dest = "www.apple.com:443".parse().unwrap();
    let next = add_default(&apple, VlessReality).unwrap();
    assert_eq!(next.reality.sni, "www.apple.com");
}

fn opts_core(core: Core) -> AddOptions {
    AddOptions {
        core: Some(core),
        ..AddOptions::default()
    }
}

#[test]
fn add_explicit_port_and_certificate_errors() {
    let busy = FnProbe(|p, t| p == 9443 && t == Transport::Tcp);
    let probing = PlanEnv {
        probe: &busy,
        ..env()
    };
    let opts = AddOptions {
        port: Some(9443),
        ..AddOptions::default()
    };
    let e = add(&preset1(), Anytls, &opts, &probing, &mut SeqRandom(1)).unwrap_err();
    assert_eq!(e.to_string(), "anytls 端口不可用: 9443");
    let opts = AddOptions {
        cert: Some(ProxyCertChoice::SelfSigned),
        ..AddOptions::default()
    };
    let reality = config(&[(VlessReality, 443, SB)]);
    let e = add(&reality, Shadowsocks, &opts, &env(), &mut SeqRandom(1)).unwrap_err();
    assert_eq!(
        e.to_string(),
        "当前协议无需代理 TLS 证书，自建站证书请使用 site 管理"
    );
}

#[test]
fn foreign_socket_in_a_dropped_hop_range_is_busy() {
    let mut hopped = preset1();
    hopped.hy2.hop = Some(PortRange {
        start: 20000,
        end: 30000,
    });
    let mut unhopped = hopped.clone();
    unhopped.hy2.hop = None;
    let foreign = FnProbe(|p, t| p == 20005 && t == Transport::Udp);
    let probing = PlanEnv {
        probe: &foreign,
        previous: Some(&hopped),
        ..env()
    };
    let opts = AddOptions {
        port: Some(20005),
        ..AddOptions::default()
    };
    let tcp = add(&unhopped, Anytls, &opts, &probing, &mut SeqRandom(1)).unwrap();
    assert_eq!(tcp.inbound(Anytls).unwrap().port, 20005, "AnyTLS is TCP");
    let e = add(&unhopped, Shadowsocks, &opts, &probing, &mut SeqRandom(1)).unwrap_err();
    assert_eq!(e.to_string(), "shadowsocks 端口不可用: 20005");
}

#[test]
fn remove_rules() {
    let p1 = preset1();
    assert_eq!(remove(&p1, Trojan).unwrap_err().to_string(), "协议未启用");
    let single = config(&[(VlessReality, 443, SB)]);
    assert_eq!(
        remove(&single, VlessReality).unwrap_err().to_string(),
        "至少保留一个协议；全部删除请使用 uninstall"
    );
    // Dropping the last certificate protocol drops the certificate.
    let next = remove(&remove(&p1, Tuic).unwrap(), Hysteria2).unwrap();
    assert!(next.tls.is_none());
    // Dropping the last REALITY inbound drops site, keys and site target.
    let site = with_site(p1.clone(), "www.example.com", true);
    let next = remove(&site, VlessReality).unwrap();
    assert!(next.site.is_none() && next.creds.reality.is_none());
    assert_eq!(next.reality.dest.to_string(), "www.microsoft.com:443");
    // Removing VMess clears vmess_tls.
    let mut vm = add_default(&acme_trojan(), VmessWs).unwrap();
    vm = remove(&vm, VmessWs).unwrap();
    assert!(!vm.vmess_tls);
    // A site-mode subscription keeps the site alive.
    let mut sub = site.clone();
    sub.subscription = Some(SubscriptionConfig {
        mode: SubscriptionMode::Site,
        port: 443,
    });
    assert_eq!(
        remove(&sub, VlessReality).unwrap_err().to_string(),
        "请先关闭订阅或将订阅切换为独立 HTTPS 站点"
    );
}

#[test]
fn port_changes() {
    let p1 = preset1();
    let next = set_port(&p1, Tuic, 9443, &env()).unwrap();
    assert_eq!(next.inbound(Tuic).unwrap().port, 9443);
    assert_eq!(
        set_port(&p1, Trojan, 1, &env()).unwrap_err().to_string(),
        "协议未启用"
    );
    for port in [0, 443] {
        let e = set_port(&p1, Tuic, port, &env()).unwrap_err();
        assert_eq!(e.to_string(), "端口无效或被占用");
    }
    let busy = FnProbe(|p, _| p == 9443 || p == 443);
    let probing = PlanEnv {
        probe: &busy,
        ..env()
    };
    let e = set_port(&p1, Tuic, 9443, &probing).unwrap_err();
    assert_eq!(e.to_string(), "端口无效或被占用");
    // Moving onto a port the node itself holds in another family is fine.
    let next = set_port(&p1, Tuic, 443, &probing);
    assert!(next.is_err(), "UDP 443 is Hysteria2's");
    let next = set_port(&p1, VlessReality, 443, &probing).unwrap();
    assert_eq!(next, p1, "its own socket is not foreign");
}

#[test]
fn address_changes_leave_no_stale_family() {
    let mut p1 = preset1();
    p1.server.ipv4_warp = true;
    let v6: Ipv6Addr = "2001:db8::5".parse().unwrap();
    let next = set_address(
        &p1,
        "proxy.example.com".parse().unwrap(),
        None,
        None,
        Some(v6),
    )
    .unwrap();
    assert_eq!(next.server.addr.to_string(), "proxy.example.com");
    assert_eq!((next.server.ipv4, next.server.ipv6), (None, Some(v6)));
    assert!(!next.server.ipv4_warp);
    let same: Host = "203.0.113.10".parse().unwrap();
    let next = set_address(&p1, same, Some("香港"), None, None).unwrap();
    assert!(
        next.server.ipv4_warp,
        "unchanged address keeps its WARP flag"
    );
    assert_eq!(next.node_name, "香港");
    let e = set_address(&p1, "203.0.113.10".parse().unwrap(), Some(""), None, None).unwrap_err();
    assert!(e.to_string().starts_with("节点名称不能为空"));
}

#[test]
fn credential_reset() {
    let p1 = preset1();
    let next = reset_credentials(&p1, &mut SeqRandom(77)).unwrap();
    assert_ne!(next.creds.uuid, p1.creds.uuid);
    assert_ne!(next.creds.reality, p1.creds.reality);
    assert_eq!(next.creds.ws_path, p1.creds.ws_path);
    assert_eq!(next.reality.guard_port, p1.reality.guard_port);
}

#[test]
fn reality_target_changes() {
    let trojan = config(&[(Trojan, 443, SB)]);
    let e = set_reality_target(&trojan, &RealityChoice::Apple, &env()).unwrap_err();
    assert_eq!(e.to_string(), "没有启用 REALITY 协议");
    let p1 = preset1();
    let next = set_reality_target(&p1, &RealityChoice::Apple, &env()).unwrap();
    assert_eq!(next.reality.sni, "www.apple.com");

    let mut site = with_site(p1.clone(), "www.example.com", true);
    let reserved = [crate::domain::ports::Reservation {
        start: 80,
        end: 80,
        transport: Transport::Tcp,
        label: "web".into(),
    }];
    let with_frp = PlanEnv {
        frp: &reserved,
        ..env()
    };
    let own = RealityChoice::OwnSite(OwnSite {
        domain: "www.example.com".into(),
        title: None,
        https_entry: true,
        cert: WebCert::Http01,
    });
    let e = set_reality_target(&p1, &own, &with_frp).unwrap_err();
    assert_eq!(e.to_string(), "端口 80/tcp 已保留给 FRP");

    site.subscription = Some(SubscriptionConfig {
        mode: SubscriptionMode::Site,
        port: 443,
    });
    let e = set_reality_target(&site, &RealityChoice::Microsoft, &env()).unwrap_err();
    assert_eq!(e.to_string(), "请先关闭订阅或将订阅切换为独立 HTTPS 站点");
    let moved = RealityChoice::OwnSite(OwnSite {
        domain: "new.example.com".into(),
        title: None,
        https_entry: true,
        cert: WebCert::Http01,
    });
    let e = set_reality_target(&site, &moved, &env()).unwrap_err();
    assert!(e.to_string().starts_with("远程订阅正在复用自建站"));
    // Same domain, other certificate: allowed.
    set_reality_target(&site, &own, &env()).unwrap();
}

#[test]
fn shadowtls_sni_clears_explicit_target() {
    let mut cfg = config(&[(Shadowtls, 443, SB)]);
    cfg.shadowtls.dest = Some("old.example.com:443".parse().unwrap());
    let next = set_shadowtls_sni(&cfg, "New.Example.com").unwrap();
    assert_eq!(next.shadowtls.sni, "new.example.com");
    assert_eq!(next.shadowtls.effective_dest(), "new.example.com:443");
    assert_eq!(
        set_shadowtls_sni(&cfg, "bad").unwrap_err().to_string(),
        "ShadowTLS SNI 域名无效"
    );
    assert_eq!(
        set_shadowtls_sni(&preset1(), "a.example.com")
            .unwrap_err()
            .to_string(),
        "未启用 ShadowTLS"
    );
}

#[test]
fn hysteria2_tuning() {
    let p1 = preset1();
    let e = tune_hy2(&config(&[(Trojan, 443, SB)]), Hy2Profile::Auto, None, None).unwrap_err();
    assert_eq!(e.to_string(), "未启用 Hysteria2");
    let mut xray = p1.clone();
    xray.inbounds[1].core = XR;
    let e = tune_hy2(&xray, Hy2Profile::Auto, None, None).unwrap_err();
    assert_eq!(
        e.to_string(),
        "Xray 承载的 Hysteria2 不支持带宽调优，请改用 sing-box 承载"
    );

    let e = tune_hy2(&p1, Hy2Profile::Measured, Some(100), None).unwrap_err();
    assert_eq!(e.to_string(), "measured 需要 --up 和 --down");
    let measured = tune_hy2(&p1, Hy2Profile::Measured, Some(100), Some(500)).unwrap();
    assert_eq!(
        (measured.hy2.up_mbps, measured.hy2.down_mbps),
        (Some(100), Some(500))
    );
    let adjusted = tune_hy2(&measured, Hy2Profile::Measured, None, Some(800)).unwrap();
    assert_eq!(
        (adjusted.hy2.up_mbps, adjusted.hy2.down_mbps),
        (Some(100), Some(800))
    );
    let auto = tune_hy2(&adjusted, Hy2Profile::Auto, None, None).unwrap();
    assert_eq!(auto.hy2.profile, Some(Hy2Profile::Auto));
    assert_eq!((auto.hy2.up_mbps, auto.hy2.down_mbps), (None, None));
    let e = tune_hy2(&auto, Hy2Profile::Measured, Some(10), None).unwrap_err();
    assert_eq!(
        e.to_string(),
        "measured 需要 --up 和 --down",
        "no stale values after auto"
    );
    let e = tune_hy2(&p1, Hy2Profile::Conservative, Some(10), None).unwrap_err();
    assert_eq!(e.to_string(), "--up/--down 仅用于 measured 档位");
    for bad in [0, 10_001] {
        let e = tune_hy2(&p1, Hy2Profile::Measured, Some(bad), Some(10)).unwrap_err();
        assert_eq!(e.to_string(), "带宽值无效（应为 1–10000 的整数 Mbps）");
    }
}

#[test]
fn resource_tuning_and_reset() {
    let p1 = preset1();
    let low = tune_resource(&p1, ResourceProfile::LowMemory).unwrap();
    assert_eq!(low.resource_profile, ResourceProfile::LowMemory);
    let mut xray = p1.clone();
    xray.inbounds[1].core = XR;
    let e = tune_resource(&xray, ResourceProfile::Throughput).unwrap_err();
    assert_eq!(
        e.to_string(),
        "Xray 承载的 Hysteria2 不支持资源调优，请改用 sing-box 承载"
    );
    let tuned = tune_hy2(&low, Hy2Profile::Measured, Some(1), Some(2)).unwrap();
    let reset = tune_reset(&tuned).unwrap();
    assert_eq!(reset.hy2, Hy2Settings::default());
    assert_eq!(reset.resource_profile, ResourceProfile::Balanced);
}

#[test]
fn proxy_certificate_changes() {
    let reality = config(&[(VlessReality, 443, SB)]);
    let e = set_proxy_cert(&reality, &ProxyCertChoice::SelfSigned).unwrap_err();
    assert_eq!(
        e.to_string(),
        "当前协议无需代理 TLS 证书，自建站证书请使用 site 管理"
    );
    let plain_vmess = config(&[(VmessWs, 8080, SB)]);
    let acme = ProxyCertChoice::Acme {
        domain: "cdn.example.com".into(),
        method: AcmeMethod::Http01,
    };
    let next = set_proxy_cert(&plain_vmess, &acme).unwrap();
    assert!(next.vmess_tls && next.needs_cert());
    let e = set_proxy_cert(&next, &ProxyCertChoice::SelfSigned).unwrap_err();
    assert_eq!(
        e.to_string(),
        "当前协议无需代理 TLS 证书，自建站证书请使用 site 管理",
        "self-signed turns VMess back to plain, which needs no certificate"
    );
    // HTTP-01 conflicts with a proxy on TCP 80.
    let on80 = config(&[(Trojan, 443, SB), (VmessWs, 80, SB)]);
    let e = set_proxy_cert(&on80, &acme).unwrap_err();
    assert_eq!(
        e.to_string(),
        "HTTP-01 验证需要保留 TCP 80，不能同时用于代理入站"
    );
    let custom = ProxyCertChoice::Custom {
        domain: "proxy.example.com".into(),
        cert: "/etc/ssl/proxy.pem".into(),
        key: "/etc/ssl/proxy.key".into(),
    };
    let next = set_proxy_cert(&on80, &custom).unwrap();
    assert!(next.vmess_tls);
    assert!(!next.tls.unwrap().pinned);
}
