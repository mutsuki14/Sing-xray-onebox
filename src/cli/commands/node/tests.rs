use super::*;
use crate::cli::args::{parse, Globals};
use crate::cli::session::testing::{Bench, Call};
use crate::domain::config::{ProxyCertMode, WebCert};
use crate::domain::fixtures::{config, with_site};
use crate::domain::protocol::Core::{Singbox as SB, Xray as XR};
use crate::domain::protocol::Transport;
use Protocol::*;

static SPECS: [CommandSpec; 1] = [ADD];

fn reality_node() -> NodeConfig {
    config(&[(VlessReality, 443, XR)])
}

fn port_of(cfg: &NodeConfig, p: Protocol) -> u16 {
    cfg.inbound(p).unwrap().port
}

/// `add` options from a command line, against `cfg` (its site).
fn add_args(cfg: &NodeConfig, line: &str) -> AddArgs {
    let argv: Vec<String> = line.split_whitespace().map(String::from).collect();
    let parsed = parse(&SPECS, &argv, Globals::default()).unwrap_or_else(|e| panic!("{e}"));
    AddArgs::from_matches(&parsed.matches, cfg.site.as_ref()).unwrap()
}

#[test]
fn add_sni_moves_shadowtls_and_touches_reality_only_where_present() {
    let trojan = config(&[(Trojan, 443, SB)]);
    let line = "add shadowtls --sni www.apple.com";
    // (node, REALITY SNI afterwards)
    for (cfg, reality_sni) in [
        (reality_node(), "www.apple.com"),
        (trojan.clone(), trojan.reality.sni.as_str()),
    ] {
        let bench = Bench::installed(&cfg);
        bench.unattended();
        let args = add_args(&cfg, line);
        let (req, _) = plan_add(&bench.session(), Some(Shadowtls), &args)
            .unwrap()
            .unwrap();
        assert_eq!(req.config.shadowtls.sni, "www.apple.com", "{cfg:?}");
        assert_eq!(req.config.shadowtls.dest, None);
        assert_eq!(req.config.reality.sni, reality_sni);
        if !cfg.any_reality() {
            assert_eq!(req.config.reality, cfg.reality, "no dormant REALITY target");
        }
    }
    // Neither handshake on the resulting node: refused, not stored.
    let bench = Bench::installed(&trojan);
    bench.unattended();
    let args = add_args(&trojan, "add tuic --sni www.apple.com");
    let err = plan_add(&bench.session(), Some(Tuic), &args).unwrap_err();
    assert_eq!(err.to_string(), NO_HANDSHAKE);
}

#[test]
fn add_without_a_protocol_is_refused_unattended() {
    let bench = Bench::installed(&reality_node());
    bench.unattended();
    let err = plan_add(&bench.session(), None, &AddArgs::default()).unwrap_err();
    assert_eq!(err.to_string(), ADD_NEEDS_PROTOCOL);
    assert!(bench.ui.prompts().is_empty(), "nothing is picked");
    assert!(bench.engine.calls().is_empty());
}

#[test]
fn add_reality_site_keeps_the_site_certificate_and_entrance() {
    let mut cfg = with_site(reality_node(), "www.example.com", false);
    if let Some(site) = cfg.site.as_mut() {
        site.cert = WebCert::Cloudflare;
    }
    let bench = Bench::installed(&cfg);
    bench.unattended();
    // (command line, HTTPS entrance afterwards)
    for (line, https) in [
        ("add tuic --reality-site new.example.com", false),
        (
            "add tuic --reality-site new.example.com --site-https on",
            true,
        ),
    ] {
        let args = add_args(&cfg, line);
        let (req, _) = plan_add(&bench.session(), Some(Tuic), &args)
            .unwrap()
            .unwrap();
        let site = req.config.site.unwrap();
        assert_eq!(site.domain, "new.example.com", "{line}");
        assert_eq!(site.cert, WebCert::Cloudflare, "{line}");
        assert_eq!(site.https_entry, https, "{line}");
    }
}

#[test]
fn add_unattended_allocates_and_creates_a_certificate() {
    let bench = Bench::installed(&reality_node());
    bench.unattended();
    let (req, added) = plan_add(&bench.session(), Some(Tuic), &AddArgs::default())
        .unwrap()
        .unwrap();
    assert_eq!(added, Tuic);
    assert_eq!(req.reason, "添加协议");
    assert_eq!(port_of(&req.config, Tuic), 443, "443/udp is free");
    assert!(matches!(
        req.config.tls.unwrap().mode,
        ProxyCertMode::SelfSigned { .. }
    ));
    assert!(bench.ui.prompts().is_empty());
}

#[test]
fn add_interactive_menu_certificate_and_port() {
    let bench = Bench::installed(&reality_node());
    bench.live.occupy(8443, Transport::Tcp);
    // Back from the menu first.
    bench.answers(&["0"]);
    assert!(plan_add(&bench.session(), None, &AddArgs::default())
        .unwrap()
        .is_none());
    let menu = bench.ui.menus()[0].clone();
    assert!(
        menu.starts_with("选择要添加的协议\n   1) VLESS-XHTTP-Reality"),
        "{menu}"
    );
    assert!(
        !menu.contains("VLESS-Reality-Vision"),
        "enabled ones are not offered"
    );
    assert!(menu.contains("(仅 sing-box 完整配置)"));
    // Trojan (5th candidate): certificate menu, then the port re-asked.
    bench.answers(&["5", "", "443", "8443", "2053"]);
    let (req, _) = plan_add(&bench.session(), None, &AddArgs::default())
        .unwrap()
        .unwrap();
    assert_eq!(port_of(&req.config, Trojan), 2053);
    assert_eq!(
        bench.ui.errors(),
        ["trojan 端口不可用: 443", "trojan 端口不可用: 8443"]
    );
    let prompts = bench.ui.prompts();
    assert!(prompts
        .iter()
        .any(|p| p.starts_with("Trojan-TLS 需要 TLS 证书")));
}

#[test]
fn add_errors() {
    let bench = Bench::installed(&reality_node());
    bench.unattended();
    let session = bench.session();
    let err = plan_add(&session, Some(VlessReality), &AddArgs::default()).unwrap_err();
    assert_eq!(err.to_string(), "协议已存在");
    let wrong = AddArgs {
        port: Some("trojan=2053".into()),
        ..AddArgs::default()
    };
    let err = plan_add(&session, Some(Tuic), &wrong).unwrap_err();
    assert_eq!(err.to_string(), "未选择协议: trojan");
    let named = AddArgs {
        port: Some("tuic=2053".into()),
        ..AddArgs::default()
    };
    let (req, _) = plan_add(&session, Some(Tuic), &named).unwrap().unwrap();
    assert_eq!(port_of(&req.config, Tuic), 2053);
    let https = AddArgs {
        reality: RealityArgs {
            site_https: Some(true),
            ..RealityArgs::default()
        },
        ..AddArgs::default()
    };
    let err = plan_add(&session, Some(Tuic), &https).unwrap_err();
    assert_eq!(err.to_string(), "--site-https 需要先启用自建站");
    assert!(bench.engine.calls().is_empty());
}

#[test]
fn first_reality_inbound_asks_for_a_target() {
    let bench = Bench::installed(&config(&[(Trojan, 443, SB)]));
    bench.answers(&["2", ""]);
    let (req, _) = plan_add(&bench.session(), Some(VlessReality), &AddArgs::default())
        .unwrap()
        .unwrap();
    assert_eq!(req.config.reality.sni, "www.apple.com");
    assert!(req.config.creds.reality.is_some());
    assert_eq!(bench.ui.prompts()[0], "选择 REALITY 伪装目标");
}

#[test]
fn add_prints_the_v2_tail_and_the_anytls_reality_hint() {
    let bench = Bench::installed(&reality_node());
    bench.unattended();
    add(&bench.session(), Some(AnytlsReality), &AddArgs::default()).unwrap();
    assert_eq!(bench.engine.calls(), [Call::Apply]);
    assert_eq!(bench.output(), format!("{UPDATED}\n{ANYTLS_REALITY_HINT}"));
    let bench = Bench::installed(&config(&[(AnytlsReality, 443, SB)]));
    bench.unattended();
    add(&bench.session(), Some(Tuic), &AddArgs::default()).unwrap();
    assert_eq!(
        bench.output(),
        UPDATED,
        "the hint is for the added protocol only"
    );
}

#[test]
fn delete_rules() {
    let bench = Bench::installed(&reality_node());
    bench.unattended();
    let err = plan_del(&bench.session(), None).unwrap_err();
    assert_eq!(
        err.to_string(),
        "至少保留一个协议；全部删除请使用 uninstall"
    );
    let err = plan_del(&bench.session(), Some(VlessReality)).unwrap_err();
    assert_eq!(
        err.to_string(),
        "至少保留一个协议；全部删除请使用 uninstall"
    );
    let err = plan_del(&bench.session(), Some(Tuic)).unwrap_err();
    assert_eq!(err.to_string(), "协议未启用");
    let bench = Bench::installed(&config(&[(VlessReality, 443, XR), (Tuic, 443, SB)]));
    // Enter at the menu deletes nothing.
    bench.answers(&[""]);
    assert!(plan_del(&bench.session(), None).unwrap().is_none());
    bench.answers(&["2"]);
    let req = plan_del(&bench.session(), None).unwrap().unwrap();
    assert_eq!(req.reason, "删除协议");
    assert!(!req.config.has(Tuic));
    assert!(req.config.tls.is_none(), "the certificate goes with TUIC");
    assert_eq!(
        bench.ui.menus()[0],
        "选择要删除的协议\n  1) VLESS-Reality-Vision\n  2) TUIC-v5\n  0) 返回"
    );
    // Unattended without a protocol: refused, never the first one.
    bench.unattended();
    let err = plan_del(&bench.session(), None).unwrap_err();
    assert_eq!(err.to_string(), DEL_NEEDS_PROTOCOL);
    let req = plan_del(&bench.session(), Some(VlessReality))
        .unwrap()
        .unwrap();
    assert!(!req.config.has(VlessReality));
}

#[test]
fn port_changes() {
    let bench = Bench::installed(&config(&[(VlessReality, 443, XR), (Tuic, 443, SB)]));
    bench.unattended();
    let session = bench.session();
    assert!(plan_port(&session, Some(Tuic), Some(443))
        .unwrap()
        .is_none());
    assert_eq!(bench.notes(), ["[提示] 端口未变化"]);
    let req = plan_port(&session, Some(Tuic), Some(8443))
        .unwrap()
        .unwrap();
    assert_eq!(req.reason, "修改端口");
    assert_eq!(port_of(&req.config, Tuic), 8443);
    bench.live.occupy(9443, Transport::Udp);
    let err = plan_port(&session, Some(Tuic), Some(9443)).unwrap_err();
    assert_eq!(err.to_string(), "端口无效或被占用");
    // -y without a port keeps the current one.
    assert!(plan_port(&session, Some(VlessReality), None)
        .unwrap()
        .is_none());
}

#[test]
fn port_interactive_reasks() {
    let bench = Bench::installed(&config(&[(VlessReality, 443, XR), (Tuic, 8443, SB)]));
    bench.answers(&["2", "x", "0", "2083"]);
    let req = plan_port(&bench.session(), None, None).unwrap().unwrap();
    assert_eq!(port_of(&req.config, Tuic), 2083);
    assert_eq!(bench.ui.errors(), ["端口无效: x", "端口不能为 0"]);
    assert!(bench.ui.prompts().contains(&"TUIC-v5 端口".to_owned()));
}

#[test]
fn reset_regen_and_run() {
    let cfg = reality_node();
    let bench = Bench::installed(&cfg);
    bench.answers(&[""]);
    assert!(
        plan_reset(&bench.session()).unwrap().is_none(),
        "default is no"
    );
    bench.unattended();
    let req = plan_reset(&bench.session()).unwrap().unwrap();
    assert_eq!(req.reason, "重置凭据");
    assert_ne!(req.config.creds.uuid, cfg.creds.uuid);
    assert_eq!(req.config.reality.guard_port, cfg.reality.guard_port);
    let req = plan_regen(&bench.session()).unwrap();
    assert_eq!(req.reason, "重新生成配置");
    assert_eq!(req.config, cfg);
    run(&bench.session(), Some(req)).unwrap();
    assert_eq!(bench.output(), UPDATED);
    run(&bench.session(), None).unwrap();
    assert_eq!(bench.engine.calls(), [Call::Apply]);
}

#[test]
fn commands_need_an_installed_node() {
    let bench = Bench::new();
    let session = bench.session();
    for err in [
        plan_add(&session, Some(Tuic), &AddArgs::default()).map(|_| ()),
        plan_del(&session, Some(Tuic)).map(|_| ()),
        plan_port(&session, Some(Tuic), Some(1)).map(|_| ()),
        plan_reset(&session).map(|_| ()),
        plan_regen(&session).map(|_| ()),
    ] {
        assert_eq!(
            err.unwrap_err().to_string(),
            "尚未安装 Onebox，请先执行 onebox install"
        );
    }
}
