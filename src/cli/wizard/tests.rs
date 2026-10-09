use super::*;
use crate::cli::args::{parse, Globals, Matches};
use crate::cli::commands::install::{INSTALL, PLAN};
use crate::cli::session::testing::Bench;
use crate::domain::config::{AcmeMethod, ProxyCertMode, WebCert};
use crate::domain::protocol::{Core, Protocol, Transport};

fn args(line: &str) -> InstallArgs {
    let argv: Vec<String> = line.split_whitespace().map(String::from).collect();
    let specs = [INSTALL, PLAN];
    let m: Matches = parse(&specs, &argv, Globals::default()).unwrap().matches;
    InstallArgs::from_matches(&m, &|_: &str| None).unwrap()
}

fn wizard(bench: &Bench, line: &str, answers: &[&str]) -> Option<NodeConfig> {
    bench.answers(answers);
    let result = run(&bench.session(), &args(line), None).unwrap();
    assert_eq!(
        bench.ui.remaining(),
        0,
        "unused answers: {:?}",
        bench.ui.prompts()
    );
    result
}

fn has_prompt(bench: &Bench, needle: &str) -> bool {
    bench.ui.prompts().iter().any(|p| p.contains(needle))
}

#[test]
fn recommended_preset_with_defaults() {
    let bench = Bench::new();
    // preset (Enter = 1), target (Microsoft), certificate (self-signed),
    // address (detected), custom ports (no), summary (yes).
    let cfg = wizard(&bench, "install", &["", "", "", "", "", ""]).unwrap();
    let prompts = bench.ui.prompts();
    assert!(
        prompts[0].starts_with("步骤 1/5 · 协议组合\n"),
        "{prompts:?}"
    );
    assert!(prompts[1].starts_with("步骤 2/5 · 伪装目标\n"));
    assert!(prompts[2].starts_with("步骤 3/5 · 证书\nHysteria2、TUIC-v5 需要 TLS 证书"));
    assert!(prompts[3]
        .starts_with("步骤 4/5 · 连接地址与端口\n检测到公网 IPv4 203.0.113.10 · IPv6 未检测到\n"));
    assert!(prompts[4].starts_with(
        "自动分配的端口: VLESS-Reality-Vision 443/tcp、Hysteria2 443/udp、TUIC-v5 8443/udp"
    ));
    assert!(prompts[5].starts_with("步骤 5/5 · 确认\n"));
    assert!(prompts[5].ends_with("连接地址: 203.0.113.10\nREALITY 目标: www.microsoft.com（www.microsoft.com:443）\n证书: 自签证书（www.bing.com）\n确认安装？"));
    let menu = &bench.ui.menus()[0];
    assert!(
        menu.contains("  1) Reality + Hysteria2 + TUIC（推荐，无需域名）"),
        "{menu}"
    );
    assert!(menu.contains("  7) 自定义：从 12 种协议中自由组合"));
    assert_eq!(cfg.inbounds.len(), 3);
    assert_eq!(cfg.server.addr.to_string(), "203.0.113.10");
}

#[test]
fn custom_selection_core_target_ports_and_reask() {
    let bench = Bench::new();
    let cfg = wizard(
        &bench,
        "install",
        &[
            "7",            // custom
            "1 7",          // VLESS-Reality + Shadowsocks
            "2",            // Xray preferred
            "2",            // Apple
            "bad host!",    // address re-asked
            "198.51.100.5", // address
            "y",            // custom ports
            "0",            // invalid
            "9443",         // reality
            "9443",         // shadowsocks: taken by reality on TCP
            "8389",         // shadowsocks
            "y",            // summary
        ],
    )
    .unwrap();
    assert!(!has_prompt(&bench, "步骤 3/5"), "no certificate needed");
    assert_eq!(
        bench.ui.errors(),
        [
            "服务器地址应为 IP 或域名",
            "端口不能为 0",
            "Shadowsocks-2022 端口不可用: 9443"
        ]
    );
    let summary: Vec<(Protocol, Core, u16)> = cfg
        .inbounds
        .iter()
        .map(|i| (i.protocol, i.core, i.port))
        .collect();
    assert_eq!(
        summary,
        [
            (Protocol::VlessReality, Core::Xray, 9443),
            (Protocol::Shadowsocks, Core::Xray, 8389)
        ]
    );
    assert_eq!(cfg.reality.sni, "www.apple.com");
    assert_eq!(cfg.server.addr.to_string(), "198.51.100.5");
}

#[test]
fn own_site_target_and_decline() {
    let bench = Bench::new();
    let declined = wizard(
        &bench,
        "install",
        &[
            "6",               // REALITY only
            "4",               // own site
            "not a domain",    // re-asked
            "www.example.com", // domain
            "",                // title default
            "n",               // no HTTPS entrance
            "2",               // Cloudflare
            "",                // address
            "",                // ports
            "n",               // decline
        ],
    );
    assert!(declined.is_none());
    assert_eq!(bench.ui.errors(), ["网站域名无效"]);
    assert!(has_prompt(&bench, "网站证书（公网网站必须使用正式证书）"));
    let summary = bench.ui.prompts().last().cloned().unwrap();
    assert!(
        summary.contains("REALITY 目标: 自有网站 www.example.com（HTTPS 443 入口关闭）"),
        "{summary}"
    );
}

#[test]
fn own_site_configuration() {
    let bench = Bench::new();
    let cfg = wizard(
        &bench,
        "install --preset 6",
        &["4", "www.example.com", "我的手记", "", "", "", "", ""],
    )
    .unwrap();
    let site = cfg.site.unwrap();
    assert_eq!(site.domain, "www.example.com");
    assert_eq!(site.title, "我的手记");
    assert!(site.https_entry);
    assert_eq!(site.cert, WebCert::Http01);
    assert!(!has_prompt(&bench, "步骤 1/5"), "the preset was given");
}

#[test]
fn certificate_choices() {
    let bench = Bench::new();
    let cfg = wizard(
        &bench,
        "install --preset 5",
        &["3", "V.Example.com", "", "", ""],
    )
    .unwrap();
    assert!(!has_prompt(&bench, "步骤 2/5"), "no REALITY protocol");
    assert_eq!(
        cfg.tls.unwrap().mode,
        ProxyCertMode::Acme {
            domain: "v.example.com".into(),
            method: AcmeMethod::Cloudflare
        }
    );
    assert!(cfg.vmess_tls, "VMess uses TLS with a domain certificate");
}

#[test]
fn self_signed_vmess_gets_an_optional_host() {
    let bench = Bench::new();
    let cfg = wizard(
        &bench,
        "install --preset 5",
        &["", "bad host!", "cdn.example.com", "", "", ""],
    )
    .unwrap();
    assert_eq!(bench.ui.errors(), ["VMess Host 域名无效"]);
    assert_eq!(cfg.vmess_host.as_deref(), Some("cdn.example.com"));
    assert!(!cfg.vmess_tls);
    let summary = bench.ui.prompts().last().cloned().unwrap();
    assert!(
        summary.contains("VMess-WS Host: cdn.example.com"),
        "{summary}"
    );
}

#[test]
fn custom_certificate_files_must_exist() {
    let bench = Bench::new();
    let cert = bench.dir.join("full.pem");
    let key = bench.dir.join("key.pem");
    std::fs::write(&cert, "CERT").unwrap();
    std::fs::write(&key, "KEY").unwrap();
    let missing = bench.dir.join("missing.pem");
    let cfg = wizard(
        &bench,
        "install --protocols trojan",
        &[
            "4",
            "proxy.example.com",
            missing.to_str().unwrap(),
            cert.to_str().unwrap(),
            key.to_str().unwrap(),
            "",
            "",
            "",
        ],
    )
    .unwrap();
    assert_eq!(
        bench.ui.errors(),
        [format!("文件不存在: {}", missing.display())]
    );
    let ProxyCertMode::Custom {
        cert: c, key: k, ..
    } = cfg.tls.unwrap().mode
    else {
        panic!("custom certificate expected");
    };
    assert_eq!((c, k), (cert, key));
}

#[test]
fn command_line_options_skip_their_steps() {
    let bench = Bench::new();
    bench.live.occupy(443, Transport::Udp);
    let cfg = wizard(
        &bench,
        "install --preset 1 --sni www.apple.com --tls self --addr 198.51.100.9",
        &["", ""],
    )
    .unwrap();
    let prompts = bench.ui.prompts();
    assert_eq!(prompts.len(), 2, "{prompts:?}");
    assert!(
        prompts[0].starts_with("自动分配的端口: VLESS-Reality-Vision 443/tcp、Hysteria2 8443/udp")
    );
    assert_eq!(
        cfg.shadowtls.sni, "www.apple.com",
        "--sni moves ShadowTLS too (v2)"
    );
    assert_eq!(cfg.reality.sni, "www.apple.com");
}

#[test]
fn eof_cancels_the_wizard() {
    let bench = Bench::new();
    bench.answers(&["1"]);
    let err = run(&bench.session(), &args("install"), None).unwrap_err();
    assert!(err.is_cancelled());
}

#[test]
fn undetected_address_must_be_typed() {
    let mut bench = Bench::new();
    bench.live.ipv4 = None;
    let cfg = wizard(
        &bench,
        "install --preset 6 --sni www.apple.com",
        &["", "vpn.example.com", "", ""],
    )
    .unwrap();
    assert_eq!(bench.ui.errors(), ["无法检测公网地址，请输入 IP 或域名"]);
    assert!(has_prompt(
        &bench,
        "检测到公网 IPv4 未检测到 · IPv6 未检测到"
    ));
    assert_eq!(cfg.server.addr.to_string(), "vpn.example.com");
}
