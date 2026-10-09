use super::*;
use crate::domain::config::{SubscriptionConfig, WebCert};
use crate::domain::fixtures::config;
use crate::domain::protocol::{Core, Protocol};
use crate::subscription::testing::{
    device, ip, reality, site, standalone, with_subscription, TOKEN,
};

fn ip_at(address: &str, port: u16) -> NodeConfig {
    with_subscription(
        reality(),
        SubscriptionConfig {
            mode: SubscriptionMode::Ip {
                address: address.parse().unwrap(),
            },
            port,
        },
    )
}

#[test]
fn endpoints_use_scheme_default_ports_and_brackets() {
    let cases = [
        (ip_at("192.0.2.5", 80), "http://192.0.2.5"),
        (ip_at("192.0.2.5", 443), "http://192.0.2.5:443"),
        (ip_at("2001:db8::7", 8448), "http://[2001:db8::7]:8448"),
        (ip_at("::1", 80), "http://[::1]"),
        (ip_at("::ffff:192.0.2.5", 80), "http://192.0.2.5"),
        (
            standalone(WebCert::Cloudflare, 443),
            "https://sub.example.com",
        ),
        (
            standalone(WebCert::Http01, 80),
            "https://sub.example.com:80",
        ),
        (
            standalone(WebCert::Cloudflare, 8448),
            "https://sub.example.com:8448",
        ),
        (site(), "https://www.example.com"),
    ];
    for (cfg, want) in cases {
        assert_eq!(endpoint(&cfg).as_deref(), Some(want));
    }
    assert_eq!(endpoint(&reality()), None);
    let mut no_site = site();
    no_site.site = None;
    assert_eq!(endpoint(&no_site), None, "site mode needs the site");
}

#[test]
fn urls_cover_every_supported_format_without_a_snapshot() {
    let cfg = ip(8448);
    let urls = urls(&cfg, TOKEN);
    let want: Vec<String> = [
        "base64",
        "mihomo",
        "provider",
        "singbox",
        "singbox-notun",
        "xray",
    ]
    .iter()
    .map(|f| format!("http://203.0.113.10:8448/sub/{TOKEN}/{f}"))
    .collect();
    assert_eq!(
        urls.iter().map(|(_, u)| u.clone()).collect::<Vec<_>>(),
        want
    );
    assert!(super::urls(&reality(), TOKEN).is_empty());
    let xhttp = with_subscription(
        config(&[(Protocol::VlessXhttp, 443, Core::Xray)]),
        crate::domain::fixtures::ip_subscription(8448),
    );
    let ids: Vec<&str> = super::urls(&xhttp, TOKEN)
        .iter()
        .map(|(f, _)| f.id())
        .collect();
    assert_eq!(ids, ["base64", "mihomo", "provider", "xray"]);
}

#[test]
fn import_link_percent_encodes_the_url() {
    assert_eq!(
        singbox_import_link("http://[::1]:8448/sub/ab/singbox"),
        "sing-box://import-remote-profile?url=http%3A%2F%2F%5B%3A%3A1%5D%3A8448%2Fsub%2Fab%2Fsingbox#onebox"
    );
}

#[test]
fn url_block_shows_id_token_urls_import_link_and_notice() {
    let cfg = ip(8448);
    let new = NewDevice {
        id: "00000000000000aa".into(),
        name: "手机".into(),
        token: TOKEN.into(),
    };
    let lines = url_block(&cfg, &new, true);
    let base = format!("http://203.0.113.10:8448/sub/{TOKEN}");
    assert_eq!(lines[0], "设备 ID: 00000000000000aa");
    assert_eq!(lines[1], format!("令牌: {TOKEN}"));
    assert_eq!(lines[2], format!("base64: {base}/base64"));
    assert_eq!(lines[7], format!("xray: {base}/xray"));
    assert_eq!(
        lines[8],
        format!(
            "sing-box 导入: {}",
            singbox_import_link(&format!("{base}/singbox"))
        )
    );
    assert_eq!(lines.last().map(String::as_str), Some(TOKEN_NOTICE));
    assert_eq!(lines.len(), 10);
    let reset = url_block(&cfg, &new, false);
    assert_eq!(reset[0], format!("令牌: {TOKEN}"), "reset prints no id");
    let xhttp = with_subscription(
        config(&[(Protocol::VlessXhttp, 443, Core::Xray)]),
        crate::domain::fixtures::ip_subscription(8448),
    );
    assert!(!url_block(&xhttp, &new, true)
        .iter()
        .any(|l| l.starts_with("sing-box 导入")));
}

#[test]
fn plaintext_warning_only_for_ip_mode() {
    assert_eq!(warnings(&ip(8448)), [PLAINTEXT_WARNING]);
    assert!(plaintext(&ip(8448)));
    for cfg in [site(), standalone(WebCert::Http01, 8448), reality()] {
        assert!(warnings(&cfg).is_empty());
    }
}

#[test]
fn enable_message_tells_whether_urls_changed() {
    let cfg = ip(8448);
    assert_eq!(
        enabled_message(Some("http://203.0.113.10:8448"), &cfg),
        UNCHANGED
    );
    for old in [None, Some("https://www.example.com")] {
        assert_eq!(
            enabled_message(old, &cfg),
            "订阅已启用；地址、端口或传输协议已改变，请把客户端已有订阅 URL 的入口改为 http://203.0.113.10:8448，保留 /sub/ 后的令牌和格式；若已遗失旧 URL，可执行 subscription reset 设备ID 获取新链接。"
        );
    }
}

#[test]
fn info_lines_follow_v2_layout() {
    let devices = vec![
        device("00000000000000aa", "手机", TOKEN),
        device("00000000000000bb", "laptop", TOKEN),
    ];
    let on = SubscriptionInfo::of(&ip(8448), devices.clone());
    assert_eq!(on.mode, Some("ip"));
    assert!(on.plaintext);
    assert_eq!(
        on.lines(),
        [
            "订阅: 启用；托管: ip；地址: http://203.0.113.10:8448",
            "00000000000000aa  手机  创建于 2025-10-09 08:53:20 UTC",
            "00000000000000bb  laptop  创建于 2025-10-09 08:53:20 UTC",
            FORMATS_LINE,
        ]
    );
    let off = SubscriptionInfo::of(&reality(), devices);
    assert_eq!(off.lines()[0], "订阅: 关闭");
    assert_eq!(
        off.lines().len(),
        4,
        "devices survive a disabled subscription"
    );
    let site_info = SubscriptionInfo::of(&site(), Vec::new());
    assert_eq!(
        site_info.lines(),
        [
            "订阅: 启用；托管: site；地址: https://www.example.com",
            FORMATS_LINE
        ]
    );
}
