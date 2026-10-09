use super::*;
use crate::cli::args::{parse, Globals};
use crate::cli::session::testing::{Bench, Call};
use crate::domain::config::{HostPort, ProxyCertMode};
use crate::domain::fixtures::config;
use crate::domain::protocol::Transport;
use std::collections::BTreeMap;

static SPECS: [CommandSpec; 2] = [INSTALL, PLAN];

fn matches(line: &str) -> Matches {
    let argv: Vec<String> = line.split_whitespace().map(String::from).collect();
    parse(&SPECS, &argv, Globals::default())
        .unwrap_or_else(|e| panic!("{line}: {e}"))
        .matches
}

fn no_env(_: &str) -> Option<String> {
    None
}

fn args(line: &str) -> Result<InstallArgs> {
    InstallArgs::from_matches(&matches(line), &no_env)
}

fn prerequisites(bench: &Bench) {
    for (program, _) in PREREQUISITES {
        bench.exec.provide(program);
    }
}

#[test]
fn option_parsing() {
    let a = args("install --preset 2 --addr 198.51.100.7 --name hk --port vless-reality=8443 --hy2-obfs --no-bbr --force").unwrap();
    assert_eq!(a.protocols, Some(ProtocolChoice::Preset(2)));
    assert_eq!(a.addr.unwrap().to_string(), "198.51.100.7");
    assert_eq!(a.name.as_deref(), Some("hk"));
    assert_eq!(a.ports, [(Protocol::VlessReality, 8443)]);
    assert!(a.hy2_obfs && a.no_bbr && a.force && !a.json);
    let custom = args("install --preset 7 --protocols trojan,tuic").unwrap();
    assert_eq!(
        custom.protocols,
        Some(ProtocolChoice::List(vec![Protocol::Trojan, Protocol::Tuic]))
    );
    assert!(args("plan --json").unwrap().json);
    assert!(args("install --dry-run --json").unwrap().json);
    for (line, message) in [
        (
            "install --preset 2 --protocols trojan",
            "--preset 与 --protocols 只能二选一（--preset 7 可配合 --protocols）",
        ),
        ("install --preset 9", "预设应为 1–7，7 为自定义协议组合"),
        ("install --json", "--json 仅用于 plan 或 install --dry-run"),
        ("install --site-https off", "--site-https 需要先启用自建站"),
        ("install --addr bad_host!", "服务器地址应为 IP 或域名"),
        ("install --core clash", "未知内核: clash"),
    ] {
        assert_eq!(args(line).unwrap_err().to_string(), message, "{line}");
    }
}

#[test]
fn version_pins_default_to_the_v2_environment() {
    let env = |key: &str| match key {
        "ONEBOX_SINGBOX_VERSION" => Some("1.12.0".to_owned()),
        _ => None,
    };
    let a = InstallArgs::from_matches(&matches("install --xray-version 25.1.1"), &env).unwrap();
    assert_eq!(a.singbox_version.as_deref(), Some("1.12.0"));
    assert_eq!(a.xray_version.as_deref(), Some("25.1.1"));
    let a = InstallArgs::from_matches(&matches("install --singbox-version latest"), &env).unwrap();
    assert_eq!(a.singbox_version.as_deref(), Some("latest"));
}

#[test]
fn per_command_options_are_enforced() {
    let argv = |l: &str| l.split_whitespace().map(String::from).collect::<Vec<_>>();
    let err = parse(&SPECS, &argv("install --apply"), Globals::default()).unwrap_err();
    assert_eq!(
        err.to_string(),
        "install 不支持选项 --apply；请执行 onebox install --help"
    );
    let inv = parse(&SPECS, &argv("install --dry-run"), Globals::default()).unwrap();
    assert!(
        !inv.spec.root.required(&inv.matches),
        "preview needs no root"
    );
    let inv = parse(&SPECS, &argv("install -y"), Globals::default()).unwrap();
    assert!(inv.spec.root.required(&inv.matches));
    let inv = parse(&SPECS, &argv("plan --preset 1"), Globals::default()).unwrap();
    assert!(!inv.spec.root.required(&inv.matches));
}

#[test]
fn preview_text_matches_v2() {
    let mut cfg = config(&[
        (Protocol::VlessReality, 443, Core::Singbox),
        (Protocol::Hysteria2, 443, Core::Singbox),
        (Protocol::Shadowsocks, 8388, Core::Xray),
    ]);
    let text = preview_text(&cfg, Path::new("/etc/onebox"), false).unwrap();
    assert_eq!(
        text,
        "只读安装预演（未写文件、下载内核或申请证书）\n\
         vless-reality | singbox | 443/tcp\n\
         hysteria2 | singbox | 443/udp\n\
         shadowsocks | xray | 8388/both\n\
         配置目录: /etc/onebox"
    );
    cfg = crate::domain::fixtures::with_site(cfg, "www.example.com", true);
    let text = preview_text(&cfg, Path::new("/etc/onebox"), false).unwrap();
    assert!(text.ends_with("网站: www.example.com，申请正式证书，HTTPS 443: true"));
    let json = preview_text(&cfg, Path::new("/etc/onebox"), true).unwrap();
    let doc: BTreeMap<String, serde_json::Value> = serde_json::from_str(&json).unwrap();
    assert_eq!(
        doc.keys().collect::<Vec<_>>(),
        ["directory", "dry_run", "protocols", "site"]
    );
    assert!(json.starts_with("{\n  \"directory\": \"/etc/onebox\",\n  \"dry_run\": true,"));
    assert!(json.contains(
        "{\n      \"core\": \"xray\",\n      \"network\": \"both\",\n      \"port\": 8388,\n      \"protocol\": \"shadowsocks\"\n    }"
    ));
    assert_eq!(doc["site"], serde_json::json!(true));
}

#[test]
fn preview_needs_no_root_and_writes_nothing() {
    let mut bench = Bench::new();
    bench.is_root = false;
    bench.live.occupy(443, Transport::Tcp);
    let a = args("plan --preset 1").unwrap();
    preview(&bench.session(), &a).unwrap();
    assert!(bench.output().starts_with(
        "只读安装预演（未写文件、下载内核或申请证书）\nvless-reality | singbox | 8443/tcp\n"
    ));
    assert!(
        !bench.ctx.paths.root.exists(),
        "ONEBOX_DIR is never created"
    );
    assert!(bench.engine.calls().is_empty());
    assert!(bench.ui.prompts().is_empty(), "previews never prompt");
    assert!(bench.exec.history().is_empty(), "no detection, no packages");
}

#[test]
fn preview_of_an_installed_node_needs_root() {
    let mut bench = Bench::installed(&config(&[(Protocol::VlessReality, 443, Core::Xray)]));
    bench.is_root = false;
    let err = preview(&bench.session(), &args("plan").unwrap()).unwrap_err();
    assert_eq!(err.to_string(), "此操作需要 root 权限");
    bench.is_root = true;
    preview(&bench.session(), &args("plan --preset 6").unwrap()).unwrap();
}

#[test]
fn preview_allocates_around_live_ports() {
    let bench = Bench::new();
    bench.live.occupy(443, Transport::Tcp);
    let a = args("plan --preset 1").unwrap();
    let cfg = plan_node(
        &bench.session(),
        &a.request(Detected::default()),
        None,
        None,
    );
    // The preview address is only applied by `preview`; the bare request
    // has none and the planner refuses it.
    assert!(cfg.is_err());
    let req = a.request(Detected {
        addr: Some(Host::Ip(IpAddr::V4(PREVIEW_ADDR))),
        ..Detected::default()
    });
    let cfg = plan_node(&bench.session(), &req, None, None).unwrap();
    let ports: Vec<u16> = cfg.inbounds.iter().map(|i| i.port).collect();
    assert_eq!(ports, [8443, 443, 8443], "443/tcp is taken");
}

#[test]
fn unattended_install_applies_a_planned_node() {
    let bench = Bench::new();
    bench.unattended();
    prerequisites(&bench);
    install(&bench.session(), &args("install --preset 1").unwrap()).unwrap();
    let req = bench.engine.single();
    assert_eq!(req.reason, "安装");
    assert!(req.expected.is_absent());
    assert!(!req.intents.clear_devices);
    let ports: Vec<(Protocol, u16)> = req
        .config
        .inbounds
        .iter()
        .map(|i| (i.protocol, i.port))
        .collect();
    assert_eq!(
        ports,
        [
            (Protocol::VlessReality, 443),
            (Protocol::Hysteria2, 443),
            (Protocol::Tuic, 8443)
        ]
    );
    assert_eq!(req.config.server.addr.to_string(), "203.0.113.10");
    assert!(matches!(
        req.config.tls.as_ref().unwrap().mode,
        ProxyCertMode::SelfSigned { .. }
    ));
    assert!(bench.ui.prompts().is_empty(), "no BBR offer under -y");
    let output = bench.output();
    assert!(
        output.starts_with("Onebox 3.0.0  地址: 203.0.113.10\n"),
        "{output}"
    );
    assert!(
        output.contains("\n下一步:\n  onebox client mihomo"),
        "{output}"
    );
}

#[test]
fn unattended_install_without_an_address_fails() {
    let mut bench = Bench::new();
    bench.live.ipv4 = None;
    bench.unattended();
    prerequisites(&bench);
    let err = install(&bench.session(), &args("install").unwrap()).unwrap_err();
    assert_eq!(err.to_string(), "无法检测公网地址，请使用 --addr 指定");
    install(
        &bench.session(),
        &args("install --addr 2001:db8::5").unwrap(),
    )
    .unwrap();
    assert_eq!(
        bench.engine.single().config.server.addr.to_string(),
        "2001:db8::5"
    );
}

#[test]
fn reinstall_rules() {
    let bench = Bench::installed(&config(&[(Protocol::VlessReality, 443, Core::Xray)]));
    prerequisites(&bench);
    // Interactive: declined → nothing happens.
    bench.answers(&["n"]);
    install(&bench.session(), &args("install --preset 6").unwrap()).unwrap();
    assert!(bench.engine.calls().is_empty());
    assert_eq!(bench.ui.prompts(), [REINSTALL_PROMPT]);
    // -y without --force is refused.
    bench.unattended();
    let err = install(&bench.session(), &args("install --preset 6").unwrap()).unwrap_err();
    assert_eq!(err.to_string(), REINSTALL_REFUSED);
    assert!(bench.engine.calls().is_empty());
    // -y --force reinstalls and clears subscription devices.
    install(
        &bench.session(),
        &args("install --preset 6 --force").unwrap(),
    )
    .unwrap();
    let req = bench.engine.single();
    assert!(req.intents.clear_devices);
    assert!(!req.expected.is_absent());
}

#[test]
fn install_requires_root_and_prerequisites() {
    let mut bench = Bench::new();
    bench.is_root = false;
    let err = install(&bench.session(), &args("install").unwrap()).unwrap_err();
    assert_eq!(err.to_string(), "此操作需要 root 权限");
    bench.is_root = true;
    bench.unattended();
    // `curl` missing and no package manager: the install stops early.
    bench.exec.provide("openssl");
    let err = install(&bench.session(), &args("install").unwrap()).unwrap_err();
    assert!(err.to_string().contains("curl"), "{err}");
    assert!(bench.engine.calls().is_empty());
}

#[test]
fn sni_then_explicit_destination() {
    let bench = Bench::new();
    bench.unattended();
    prerequisites(&bench);
    let a = args("install --preset 6 --sni www.apple.com --reality-dest 198.51.100.7:443").unwrap();
    install(&bench.session(), &a).unwrap();
    let cfg = bench.engine.single().config;
    assert_eq!(cfg.reality.sni, "www.apple.com");
    assert_eq!(
        cfg.reality.dest,
        "198.51.100.7:443".parse::<HostPort>().unwrap()
    );
}

#[test]
fn failed_apply_surfaces_the_engine_error() {
    let bench = Bench::new();
    bench.unattended();
    prerequisites(&bench);
    bench.engine.fail_with("配置未应用，已恢复原状态: 测试");
    let err = install(&bench.session(), &args("install --preset 6").unwrap()).unwrap_err();
    assert_eq!(err.to_string(), "配置未应用，已恢复原状态: 测试");
    assert_eq!(bench.engine.calls(), [Call::Apply]);
}

#[test]
fn interactive_install_offers_bbr_after_success() {
    let bench = Bench::new();
    prerequisites(&bench);
    // Wizard with flags deciding everything but ports/summary, then BBR "n".
    bench.answers(&["", "", "n"]);
    let a = args("install --preset 6 --sni www.apple.com --addr 198.51.100.7").unwrap();
    install(&bench.session(), &a).unwrap();
    assert_eq!(bench.engine.calls(), [Call::Apply]);
    let prompts = bench.ui.prompts();
    assert_eq!(prompts.last().map(String::as_str), Some(BBR_PROMPT));
}
