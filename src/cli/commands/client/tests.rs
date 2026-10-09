use super::*;
use crate::cli::session::testing::Bench;
use crate::domain::fixtures::config;
use crate::domain::protocol::Core::{Singbox as SB, Xray as XR};
use crate::ui::NO_TERMINAL;
use Protocol::*;

fn words(list: &[&str]) -> Vec<String> {
    list.iter().map(|s| s.to_string()).collect()
}

#[test]
fn export_names() {
    assert_eq!(Export::parse("qr").unwrap(), Export::Qr);
    assert_eq!(
        Export::parse("clash").unwrap(),
        Export::Format(ClientFormat::Mihomo)
    );
    assert_eq!(
        Export::parse("sub").unwrap(),
        Export::Format(ClientFormat::Base64)
    );
    assert_eq!(
        Export::parse("json").unwrap_err().to_string(),
        "未知客户端格式: json"
    );
}

#[test]
fn links_have_exactly_one_trailing_newline() {
    let bench = Bench::installed(&config(&[(VlessReality, 443, XR)]));
    client(&bench.session(), Some(Export::Format(ClientFormat::Links))).unwrap();
    let out = bench.output();
    assert!(out.starts_with("vless://"), "{out}");
    assert!(!out.ends_with('\n'), "the printer adds the single newline");
    assert!(bench.notes().is_empty());
}

#[test]
fn format_menu_offers_supported_formats_with_mihomo_default() {
    let bench = Bench::installed(&config(&[(VlessReality, 443, XR)]));
    bench.answers(&[""]);
    client(&bench.session(), None).unwrap();
    let menu = &bench.ui.menus()[0];
    assert!(
        menu.starts_with("选择客户端配置格式\n  1) mihomo  mihomo / Clash Meta 完整配置"),
        "{menu}"
    );
    assert!(menu.contains("  7) sub  Base64 订阅"));
    assert!(menu.contains("  8) qr  终端二维码"));
    assert!(bench.output().contains("proxies:"), "mihomo YAML");
    // AnyTLS-REALITY only: sing-box formats, sing-box first.
    let bench = Bench::installed(&config(&[(AnytlsReality, 443, SB)]));
    bench.unattended();
    client(&bench.session(), None).unwrap();
    assert!(bench.ui.menus()[0].starts_with("选择客户端配置格式\n  1) singbox  "));
    assert!(bench.output().starts_with('{'));
}

#[test]
fn format_menu_needs_a_terminal() {
    let bench = Bench::installed(&config(&[(VlessReality, 443, XR)]));
    bench.ui.set_interactive(false);
    let err = client(&bench.session(), None).unwrap_err();
    assert_eq!(err.to_string(), NO_TERMINAL);
    bench.ui.set_interactive(true);
    bench.answers(&["0"]);
    client(&bench.session(), None).unwrap();
    assert!(bench.output().is_empty(), "back prints nothing");
}

#[test]
fn anytls_reality_notice_for_non_sing_box_formats() {
    let bench = Bench::installed(&config(&[
        (VlessReality, 443, SB),
        (AnytlsReality, 8443, SB),
    ]));
    client(&bench.session(), Some(Export::Format(ClientFormat::Links))).unwrap();
    assert_eq!(bench.notes(), [format!("[提示] {ANYTLS_REALITY_NOTICE}")]);
    client(
        &bench.session(),
        Some(Export::Format(ClientFormat::SingboxNoTun)),
    )
    .unwrap();
    assert_eq!(bench.notes().len(), 1, "no notice for sing-box");
}

#[test]
fn qr_codes_follow_each_link() {
    let bench = Bench::installed(&config(&[(VlessReality, 443, XR), (Shadowsocks, 8388, XR)]));
    client(&bench.session(), Some(Export::Qr)).unwrap();
    let out = bench.output();
    let links: Vec<&str> = out
        .lines()
        .filter(|l| l.starts_with("vless://") || l.starts_with("ss://"))
        .collect();
    assert_eq!(links.len(), 2, "{out}");
    assert!(out.contains('█'));
    let bench = Bench::installed(&config(&[(AnytlsReality, 443, SB)]));
    let err = client(&bench.session(), Some(Export::Qr)).unwrap_err();
    assert_eq!(err.to_string(), NO_LINKS);
}

#[test]
fn render_targets() {
    use RenderTarget::*;
    for (argv, expected) in [
        (&[][..], Server(Core::Singbox)),
        (&["server"], Server(Core::Singbox)),
        (&["server", "xray"], Server(Core::Xray)),
        (&["server", "sing-box"], Server(Core::Singbox)),
        (&["inbound", "trojan"], Inbound(Trojan)),
        (&["outbound", "tuic"], Outbound(Tuic, Core::Singbox)),
        (
            &["outbound", "vless-reality", "xray"],
            Outbound(VlessReality, Core::Xray),
        ),
        (&["probe"], Probe),
    ] {
        assert_eq!(render_target(&words(argv)).unwrap(), expected, "{argv:?}");
    }
    for (argv, message) in [
        (&["inbound"][..], "需要协议"),
        (&["outbound"], "需要协议"),
        (&["config"], RENDER_USAGE),
        (&["probe", "x"], RENDER_USAGE),
        (&["server", "clash"], "未知内核: clash"),
        (&["inbound", "vless"], "未知协议: vless"),
    ] {
        assert_eq!(
            render_target(&words(argv)).unwrap_err().to_string(),
            message,
            "{argv:?}"
        );
    }
}

#[test]
fn render_prints_pretty_json_without_writing() {
    let bench = Bench::installed(&config(&[(VlessReality, 443, XR), (Hysteria2, 443, SB)]));
    std::fs::remove_dir_all(bench.ctx.paths.tls()).ok();
    render_out(&bench.session(), RenderTarget::Server(Core::Xray)).unwrap();
    let doc: serde_json::Value = serde_json::from_str(&bench.output()).unwrap();
    assert!(doc["inbounds"].is_array());
    let bench = Bench::installed(&config(&[(VlessReality, 443, XR)]));
    render_out(&bench.session(), RenderTarget::Probe).unwrap();
    let doc: serde_json::Value = serde_json::from_str(&bench.output()).unwrap();
    assert_eq!(doc["schema"], serde_json::json!(1));
    let err = render_out(&bench.session(), RenderTarget::Server(Core::Singbox)).unwrap_err();
    assert!(err.to_string().contains("singbox"), "{err}");
}
