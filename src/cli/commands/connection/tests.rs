use super::*;
use crate::cli::session::testing::Bench;
use crate::domain::config::HostPort;
use crate::domain::fixtures::config;
use crate::domain::protocol::Core::{Singbox as SB, Xray as XR};
use std::net::IpAddr;
use Protocol::*;

fn args(addr: Option<&str>, name: Option<&str>) -> AddrArgs {
    AddrArgs {
        addr: addr.map(|a| opt::host(a).unwrap()),
        name: name.map(str::to_owned),
    }
}

#[test]
fn address_changes_detect_the_other_family_fresh() {
    let mut cfg = config(&[(VlessReality, 443, XR)]);
    cfg.server.ipv6 = Some("2001:db8::99".parse().unwrap());
    let mut bench = Bench::installed(&cfg);
    bench.live.ipv6_addr = Some("2001:db8::1".parse::<IpAddr>().unwrap());
    bench.unattended();
    let req = plan_addr(&bench.session(), &args(Some("vpn.example.com"), None))
        .unwrap()
        .unwrap();
    assert_eq!(req.reason, "修改连接地址");
    let server = &req.config.server;
    assert_eq!(server.addr.to_string(), "vpn.example.com");
    assert_eq!(server.ipv4.unwrap().to_string(), "203.0.113.10");
    assert_eq!(
        server.ipv6.unwrap().to_string(),
        "2001:db8::1",
        "stale IPv6 replaced"
    );
}

#[test]
fn name_only_keeps_the_address() {
    let bench = Bench::installed(&config(&[(VlessReality, 443, XR)]));
    bench.unattended();
    let req = plan_addr(&bench.session(), &args(None, Some("hk-1")))
        .unwrap()
        .unwrap();
    assert_eq!(req.config.node_name, "hk-1");
    assert_eq!(req.config.server, config(&[(VlessReality, 443, XR)]).server);
    // Nothing given under -y: nothing to do.
    assert!(plan_addr(&bench.session(), &AddrArgs::default())
        .unwrap()
        .is_none());
    assert_eq!(bench.notes(), ["[提示] 配置未变化"]);
}

#[test]
fn interactive_address_reasks_invalid_answers() {
    let bench = Bench::installed(&config(&[(VlessReality, 443, XR)]));
    bench.answers(&["bad host!", "198.51.100.20", "新节点"]);
    let req = plan_addr(&bench.session(), &AddrArgs::default())
        .unwrap()
        .unwrap();
    assert_eq!(bench.ui.errors(), ["服务器地址应为 IP 或域名"]);
    assert_eq!(req.config.server.addr.to_string(), "198.51.100.20");
    assert_eq!(req.config.node_name, "新节点");
    assert_eq!(
        bench.ui.prompts(),
        ["连接 IP 或域名", "连接 IP 或域名", "节点名称"]
    );
}

#[test]
fn sni_requires_reality_or_shadowtls() {
    let bench = Bench::installed(&config(&[(Trojan, 443, SB)]));
    let err = plan_sni(&bench.session(), &RealityArgs::default()).unwrap_err();
    assert_eq!(err.to_string(), "没有启用 REALITY 或 ShadowTLS");
}

#[test]
fn sni_options_move_both_handshakes() {
    let bench = Bench::installed(&config(&[(VlessReality, 443, XR), (Shadowtls, 8443, SB)]));
    let sni = RealityArgs {
        choice: RealityChoice::Custom("www.apple.com".into()),
        shadowtls_sni: Some("www.apple.com".into()),
        ..RealityArgs::default()
    };
    let req = plan_sni(&bench.session(), &sni).unwrap().unwrap();
    assert_eq!(req.reason, "更换伪装目标");
    assert_eq!(req.config.reality.sni, "www.apple.com");
    assert_eq!(req.config.shadowtls.sni, "www.apple.com");
    // ShadowTLS only: --sni moves just its handshake.
    let bench = Bench::installed(&config(&[(Shadowtls, 443, SB)]));
    let req = plan_sni(&bench.session(), &sni).unwrap().unwrap();
    assert_eq!(req.config.shadowtls.sni, "www.apple.com");
    // --reality-dest keeps the SNI.
    let bench = Bench::installed(&config(&[(VlessReality, 443, XR)]));
    let dest = RealityArgs {
        choice: RealityChoice::Dest("198.51.100.7:443".parse::<HostPort>().unwrap()),
        ..RealityArgs::default()
    };
    let req = plan_sni(&bench.session(), &dest).unwrap().unwrap();
    assert_eq!(req.config.reality.sni, "www.microsoft.com");
    assert_eq!(req.config.reality.dest.to_string(), "198.51.100.7:443");
}

#[test]
fn sni_interactive() {
    let bench = Bench::installed(&config(&[(VlessReality, 443, XR), (Shadowtls, 8443, SB)]));
    bench.answers(&["3", "bad!", "addons.mozilla.org", ""]);
    let req = plan_sni(&bench.session(), &RealityArgs::default())
        .unwrap()
        .unwrap();
    assert_eq!(req.config.reality.sni, "addons.mozilla.org");
    assert_eq!(
        req.config.shadowtls.sni, "www.microsoft.com",
        "Enter keeps it"
    );
    assert_eq!(bench.ui.errors(), ["域名无效"]);
    assert!(bench.ui.prompts()[0]
        .starts_with("当前 REALITY 目标: www.microsoft.com（www.microsoft.com:443）"));
    // Unattended without options changes nothing.
    bench.unattended();
    assert!(plan_sni(&bench.session(), &RealityArgs::default())
        .unwrap()
        .is_none());
}

#[test]
fn site_https_toggle_needs_a_site() {
    let bench = Bench::installed(&config(&[(VlessReality, 443, XR)]));
    let https = RealityArgs {
        site_https: Some(false),
        ..RealityArgs::default()
    };
    let err = plan_sni(&bench.session(), &https).unwrap_err();
    assert_eq!(err.to_string(), "--site-https 需要先启用自建站");
    let site = crate::domain::fixtures::with_site(
        config(&[(VlessReality, 443, XR)]),
        "www.example.com",
        true,
    );
    let bench = Bench::installed(&site);
    let req = plan_sni(&bench.session(), &https).unwrap().unwrap();
    assert!(!req.config.site.unwrap().https_entry);
}
