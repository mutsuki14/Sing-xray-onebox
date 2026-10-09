use super::*;
use crate::cli::session::testing::Bench;
use crate::domain::fixtures::{config, ip_subscription};
use crate::domain::protocol::Core::{Singbox as SB, Xray as XR};
use Protocol::*;

#[test]
fn clients_follow_the_capability_table() {
    assert_eq!(clients(VlessReality), "singbox, xray, mihomo, link");
    assert_eq!(clients(VlessXhttp), "xray, mihomo, link");
    assert_eq!(clients(Shadowtls), "singbox, mihomo");
    assert_eq!(clients(AnytlsReality), "singbox");
    assert_eq!(clients(Tuic), "singbox, mihomo, link");
}

#[test]
fn card_snapshot() {
    let mut cfg = config(&[
        (VlessReality, 443, XR),
        (Hysteria2, 443, SB),
        (Shadowsocks, 8388, XR),
    ]);
    cfg.versions.xray = Some("26.3.27".into());
    cfg.hy2.obfs = true;
    let cores = [
        CoreState {
            core: SB,
            version: None,
            running: false,
        },
        CoreState {
            core: XR,
            version: Some("26.3.27".into()),
            running: true,
        },
    ];
    let keys = cfg.creds.reality.clone().unwrap();
    let c = &cfg.creds;
    let expected = format!(
        "Onebox {VERSION}  地址: 203.0.113.10
节点: onebox · IPv4 203.0.113.10 · IPv6 无
内核: sing-box 版本未知（已停止） · Xray 26.3.27（运行中）

协议                  内核     传输  端口  客户端
--------------------  -------  ----  ----  ---------------------------
VLESS-Reality-Vision  xray     tcp   443   singbox, xray, mihomo, link
Hysteria2             singbox  udp   443   singbox, xray, mihomo, link
Shadowsocks-2022      xray     both  8388  singbox, xray, mihomo, link

REALITY SNI: www.microsoft.com  公钥: {}  ShortID: {}
REALITY 目标: www.microsoft.com:443
TLS: 自签证书 www.bing.com，客户端固定证书指纹
UUID: {}
密码: {}
SS-2022 密钥: {}（2022-blake3-aes-128-gcm）
Hysteria2 混淆密码: {}
控制面板密钥: {}
配置目录: /etc/onebox/client
导出: onebox client singbox | mihomo | links
订阅: onebox subscription info",
        keys.public_key,
        keys.short_id,
        c.uuid,
        c.password,
        c.ss_password,
        c.hy2_obfs_password,
        c.clash_secret
    );
    assert_eq!(render(&cfg, &cores, "/etc/onebox/client"), expected);
}

#[test]
fn card_mentions_anytls_reality_shadowtls_and_sites() {
    let mut cfg = config(&[(AnytlsReality, 443, SB), (Shadowtls, 8443, SB)]);
    cfg = crate::domain::fixtures::with_site(cfg, "www.example.com", true);
    let text = render(&cfg, &[], "/c");
    assert!(text.contains("AnyTLS-REALITY 请使用 sing-box 完整配置或远程配置订阅。"));
    assert!(text.contains("REALITY 目标: 自有网站 www.example.com（127.0.0.1:10443）"));
    assert!(text.contains("ShadowTLS 握手: www.microsoft.com（www.microsoft.com:443）"));
    assert!(text.contains(&format!("ShadowTLS 密码: {}", cfg.creds.shadowtls_password)));
    assert!(!text.contains("TLS: "), "no proxy certificate here");
}

#[test]
fn next_steps_depend_on_formats_and_subscription() {
    let cfg = config(&[(AnytlsReality, 443, SB)]);
    let text = next_steps(&cfg);
    assert!(!text.contains("onebox client mihomo"), "{text}");
    assert!(!text.contains("onebox qr"));
    assert!(text.contains("onebox client singbox"));
    assert!(text.contains("onebox subscription enable"));
    let mut cfg = config(&[(VlessReality, 443, XR)]);
    cfg.subscription = Some(ip_subscription(8448));
    let text = next_steps(&cfg);
    assert!(
        text.starts_with("下一步:\n  onebox client mihomo "),
        "{text}"
    );
    assert!(text.contains("onebox subscription info"));
    assert!(
        text.ends_with("  onebox                    打开管理菜单"),
        "{text}"
    );
}

#[test]
fn info_reads_the_installed_node() {
    let bench = Bench::new();
    let err = show(&bench.session()).unwrap_err();
    assert_eq!(err.to_string(), "尚未安装 Onebox，请先执行 onebox install");
    let bench = Bench::installed(&config(&[(VlessReality, 443, XR)]));
    bench.live.set_running("onebox-xray");
    show(&bench.session()).unwrap();
    let out = bench.output();
    assert!(out.contains("内核: Xray 版本未知（运行中）"), "{out}");
    assert!(out.contains(&format!(
        "配置目录: {}",
        bench.ctx.paths.clients().display()
    )));
}
