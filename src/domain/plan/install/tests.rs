use super::*;
use crate::domain::ports::{FnProbe, NoProbe};
use crate::domain::protocol::Transport;
use crate::sys::rand::SeqRandom;
use Core::{Singbox as SB, Xray as XR};
use Protocol::*;

const NOW: u64 = 1_790_000_000;
const ADDR: &str = "203.0.113.10";

fn request(protocols: ProtocolChoice) -> InstallRequest {
    InstallRequest {
        protocols,
        addr: Some(ADDR.parse().unwrap()),
        ..InstallRequest::default()
    }
}

fn plan(req: &InstallRequest) -> Result<NodeConfig> {
    install(req, &PlanEnv::offline(true, NOW), &mut SeqRandom(9))
}

type Layout = Vec<(Protocol, u16, Core)>;

fn layout(cfg: &NodeConfig) -> Layout {
    cfg.inbounds
        .iter()
        .map(|i| (i.protocol, i.port, i.core))
        .collect()
}

fn err(req: &InstallRequest) -> String {
    plan(req).unwrap_err().to_string()
}

#[test]
fn every_preset_installs_with_v2_layouts() {
    let cases: [(u32, Layout, bool); 6] = [
        (
            1,
            vec![
                (VlessReality, 443, SB),
                (Hysteria2, 443, SB),
                (Tuic, 8443, SB),
            ],
            true,
        ),
        (
            2,
            vec![
                (VlessReality, 443, XR),
                (VlessXhttp, 443, XR),
                (Shadowsocks, 8388, XR),
            ],
            false,
        ),
        (
            3,
            vec![
                (VlessReality, 443, XR),
                (VlessXhttp, 443, XR),
                (Hysteria2, 443, SB),
                (Tuic, 8443, SB),
                (Anytls, 8443, SB),
            ],
            true,
        ),
        (
            4,
            vec![
                (VlessReality, 443, SB),
                (VlessGrpc, 8443, SB),
                (Trojan, 2053, SB),
                (Shadowsocks, 8388, SB),
                (Hysteria2, 443, SB),
                (Tuic, 8443, SB),
                (Anytls, 2083, SB),
                (Shadowtls, 2087, SB),
                (VmessWs, 8080, SB),
            ],
            true,
        ),
        (5, vec![(VlessWs, 443, SB), (VmessWs, 8080, SB)], true),
        (6, vec![(VlessReality, 443, XR)], false),
    ];
    for (n, want, needs_cert) in cases {
        let cfg = plan(&request(ProtocolChoice::Preset(n))).unwrap();
        assert_eq!(layout(&cfg), want, "preset {n}");
        assert_eq!(cfg.tls.is_some(), needs_cert, "preset {n}");
        assert_eq!(cfg.creds.reality.is_some(), cfg.any_reality(), "preset {n}");
        assert_eq!(cfg.reality.guard_port, 18000, "preset {n}");
        assert!(!cfg.vmess_tls);
        assert_eq!(cfg.installed_at, NOW);
        assert_eq!(cfg.listen.to_string(), "::");
        assert_eq!(cfg.reality.dest.to_string(), "www.microsoft.com:443");
        assert_eq!(cfg.server.ipv4, Some(ADDR.parse().unwrap()));
        assert!(cfg.site.is_none() && cfg.subscription.is_none());
        PortPlan::of(&cfg, &[]).validate().unwrap();
    }
}

#[test]
fn installs_are_deterministic_for_a_seed() {
    let req = request(ProtocolChoice::Preset(1));
    assert_eq!(plan(&req).unwrap(), plan(&req).unwrap());
    let ipv4_only = install(&req, &PlanEnv::offline(false, NOW), &mut SeqRandom(9)).unwrap();
    assert_eq!(ipv4_only.listen.to_string(), "0.0.0.0");
}

#[test]
fn protocol_selection() {
    assert_eq!(
        err(&request(ProtocolChoice::Preset(7))),
        "自定义预设需要 --protocols"
    );
    assert!(err(&request(ProtocolChoice::Preset(0))).contains("1–7"));
    assert_eq!(
        err(&request(ProtocolChoice::List(vec![]))),
        "至少选择一种协议"
    );
    let list = ProtocolChoice::List(vec![Tuic, VlessReality, Tuic, Shadowsocks]);
    let cfg = plan(&request(list.clone())).unwrap();
    assert_eq!(
        layout(&cfg),
        [
            (VlessReality, 443, SB),
            (Shadowsocks, 8388, SB),
            (Tuic, 443, SB)
        ]
    );
    let mut xray = request(list);
    xray.core = Some(XR);
    let cfg = plan(&xray).unwrap();
    assert_eq!(
        layout(&cfg),
        [
            (VlessReality, 443, XR),
            (Shadowsocks, 8388, XR),
            (Tuic, 443, SB)
        ]
    );
}

#[test]
fn explicit_ports() {
    let mut req = request(ProtocolChoice::Preset(1));
    req.ports = vec![(Tuic, 9443), (VlessReality, 8443)];
    let cfg = plan(&req).unwrap();
    assert_eq!(
        layout(&cfg),
        [
            (VlessReality, 8443, SB),
            (Hysteria2, 443, SB),
            (Tuic, 9443, SB)
        ]
    );
    // Explicit ports win over automatic ones.
    req.ports = vec![(Tuic, 443)];
    let cfg = plan(&req).unwrap();
    assert_eq!(
        layout(&cfg),
        [
            (VlessReality, 443, SB),
            (Hysteria2, 8443, SB),
            (Tuic, 443, SB)
        ]
    );

    let cases = [
        (vec![(Trojan, 443)], "未选择协议: trojan"),
        (vec![(Tuic, 1), (Tuic, 2)], "重复指定协议端口"),
        (vec![(Tuic, 0)], "端口不能为 0"),
        (vec![(Tuic, 443), (Hysteria2, 443)], "tuic 端口不可用: 443"),
        (
            vec![(VlessReality, 18000)],
            "vless-reality 端口不可用: 18000",
        ),
    ];
    for (ports, want) in cases {
        let mut req = request(ProtocolChoice::Preset(1));
        req.ports = ports;
        if want.contains("18000") {
            // An explicit port inside the guard range is fine on its own…
            assert!(plan(&req).is_ok());
            // …but not when it is already listening.
            let busy = FnProbe(|p, _| p == 18000);
            let env = PlanEnv {
                probe: &busy,
                ..PlanEnv::offline(true, NOW)
            };
            let e = install(&req, &env, &mut SeqRandom(9)).unwrap_err();
            assert_eq!(e.to_string(), want);
        } else {
            assert_eq!(err(&req), want);
        }
    }

    // The guard moves away from an explicit Xray port in its range.
    let mut req = request(ProtocolChoice::Preset(6));
    req.ports = vec![(VlessReality, 18000)];
    assert_eq!(plan(&req).unwrap().reality.guard_port, 18001);
}

#[test]
fn addresses_and_names() {
    let v4 = "198.51.100.7".parse().unwrap();
    let v6 = "2001:db8::7".parse().unwrap();
    let mut req = request(ProtocolChoice::Preset(6));
    req.addr = None;
    req.detected_ipv4 = Some(v4);
    req.detected_ipv6 = Some(v6);
    let cfg = plan(&req).unwrap();
    assert_eq!(cfg.server.addr.to_string(), "198.51.100.7");
    assert_eq!(cfg.server.ipv6, Some(v6));
    req.detected_ipv4 = None;
    req.detected_ipv6 = None;
    assert_eq!(err(&req), "无法检测公网地址，请使用 --addr 指定");

    let mut req = request(ProtocolChoice::Preset(6));
    req.node_name = Some(" 东京 ".into());
    let cfg = plan(&req).unwrap();
    assert_eq!(cfg.node_label(VlessReality), "东京-VLESS-Reality-Vision");
    req.node_name = Some("a\u{7}".into());
    assert!(err(&req).starts_with("节点名称不能为空"));
}

#[test]
fn reality_target_and_site() {
    let mut req = request(ProtocolChoice::Preset(1));
    req.reality = RealityChoice::OwnSite(OwnSite {
        domain: "www.example.com".into(),
        title: Some("我的站".into()),
        https_entry: true,
        cert: WebCert::Http01,
    });
    let cfg = plan(&req).unwrap();
    let site = cfg.site_active().unwrap();
    assert_eq!(
        (site.domain.as_str(), site.title.as_str()),
        ("www.example.com", "我的站")
    );
    assert_eq!(cfg.reality.dest.to_string(), "127.0.0.1:10443");
    assert_eq!(cfg.site_public_port(), 443);

    let mut no_reality = request(ProtocolChoice::Preset(5));
    no_reality.reality = req.reality.clone();
    assert_eq!(err(&no_reality), "自建站需要 REALITY 协议及有效域名");

    let mut sni = request(ProtocolChoice::Preset(4));
    sni.reality = RealityChoice::Custom("cdn.example.com".into());
    sni.shadowtls_sni = Some("cdn.example.com".into());
    let cfg = plan(&sni).unwrap();
    assert_eq!(cfg.reality.dest.to_string(), "cdn.example.com:443");
    assert_eq!(cfg.shadowtls.effective_dest(), "cdn.example.com:443");
    sni.shadowtls_sni = Some("x".into());
    assert_eq!(err(&sni), "ShadowTLS SNI 域名无效");
}

#[test]
fn certificates() {
    let acme = ProxyCertChoice::Acme {
        domain: "cdn.example.com".into(),
        method: AcmeMethod::Http01,
    };
    let mut req = request(ProtocolChoice::Preset(5));
    req.cert = Some(acme.clone());
    let cfg = plan(&req).unwrap();
    assert!(cfg.vmess_tls, "acme/custom certificates put VMess on TLS");
    assert!(PortPlan::of(&cfg, &[])
        .listeners()
        .iter()
        .any(|l| l.owner == Owner::AcmeHttp80));
    // Ignored when nothing needs a certificate (v2 parity).
    let mut reality_only = request(ProtocolChoice::Preset(6));
    reality_only.cert = Some(acme);
    assert!(plan(&reality_only).unwrap().tls.is_none());

    // CDN fronting: self-signed VLESS-WS, plain VMess with a Host header.
    let mut cdn = request(ProtocolChoice::Preset(5));
    cdn.vmess_host = Some("CDN.Example.com".into());
    let cfg = plan(&cdn).unwrap();
    assert!(!cfg.vmess_tls);
    assert_eq!(cfg.vmess_host.as_deref(), Some("cdn.example.com"));
    assert_eq!(cfg.tls.unwrap().mode.server_name(), "www.bing.com");
    cdn.vmess_host = Some("bad".into());
    assert_eq!(err(&cdn), "VMess Host 域名无效");
}

#[test]
fn hysteria2_options() {
    let mut req = request(ProtocolChoice::Preset(6));
    req.hy2_obfs = true;
    assert_eq!(err(&req), "未选择 hysteria2");
    let mut req = request(ProtocolChoice::Preset(1));
    req.hy2_core = Some(XR);
    req.hy2_obfs = true;
    req.hy2_hop = Some(PortRange {
        start: 8000,
        end: 9000,
    });
    let cfg = plan(&req).unwrap();
    assert_eq!(cfg.core_of(Hysteria2), Some(XR));
    assert!(cfg.hy2.obfs);
    // TUIC avoids 8443 inside the hop range (v2 picked it and failed later).
    assert_eq!(cfg.inbound(Tuic).unwrap().port, 2053);
    req.hy2_hop = Some(PortRange {
        start: 100,
        end: 9000,
    });
    assert_eq!(err(&req), "跳跃端口范围无效");
}

#[test]
fn version_pins_and_reinstall() {
    let mut req = request(ProtocolChoice::Preset(3));
    req.singbox_version = Some("latest".into());
    req.xray_version = Some("26.3.27".into());
    let cfg = plan(&req).unwrap();
    assert_eq!(cfg.versions.singbox_pin, None);
    assert_eq!(cfg.versions.xray_pin.as_deref(), Some("26.3.27"));

    // Reinstall: our own sockets are not foreign, FRP still blocks.
    let previous = plan(&request(ProtocolChoice::Preset(1))).unwrap();
    let busy = FnProbe(|p, t| p == 443 && t == Transport::Tcp);
    let reserved = [crate::domain::ports::Reservation {
        start: 8443,
        end: 8443,
        transport: Transport::Udp,
        label: "game".into(),
    }];
    let env = PlanEnv {
        ipv6: true,
        probe: &busy,
        frp: &reserved,
        previous: Some(&previous),
        now: NOW,
    };
    let cfg = install(&request(ProtocolChoice::Preset(1)), &env, &mut SeqRandom(3)).unwrap();
    assert_eq!(
        layout(&cfg),
        [
            (VlessReality, 443, SB),
            (Hysteria2, 443, SB),
            (Tuic, 2053, SB)
        ]
    );
    assert_ne!(
        cfg.creds.uuid, previous.creds.uuid,
        "reinstall means new credentials"
    );
    let fresh = PlanEnv {
        probe: &busy,
        ..PlanEnv::offline(true, NOW)
    };
    let cfg = install(
        &request(ProtocolChoice::Preset(1)),
        &fresh,
        &mut SeqRandom(3),
    )
    .unwrap();
    assert_eq!(cfg.inbound(VlessReality).unwrap().port, 8443);
    let _ = NoProbe;
}
