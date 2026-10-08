use super::*;
use crate::domain::config::{AcmeMethod, Host, ProxyCertMode, ProxyTls};
use crate::domain::protocol::Core;
use crate::render::fixtures::{all_protocols, config, paths, spec, spec_with};
use serde_json::Value;
use Core::{Singbox as SB, Xray as XR};
use Protocol::*;

fn link_of(spec: &NodeSpec, p: Protocol) -> String {
    link(spec, spec.require(p).unwrap()).unwrap()
}

/// The node of `all_protocols()` with an IPv6 address and nasty values.
fn nasty() -> NodeSpec {
    let mut cfg = all_protocols();
    let v6 = "2001:db8::42".parse().unwrap();
    cfg.server.addr = Host::Ip(std::net::IpAddr::V6(v6));
    cfg.server.ipv6 = Some(v6);
    cfg.node_name = "节点's #1".into();
    cfg.creds.password = "pass:@#&?/中文".into();
    cfg.hy2.obfs = true;
    cfg.creds.hy2_obfs_password = "obfs&+password".into();
    cfg.hy2.hop = Some("25000-26000".parse().unwrap());
    spec(&cfg)
}

#[test]
fn uris_bracket_ipv6_and_percent_encode_everything() {
    let s = nasty();
    for ib in s.for_format(ClientFormat::Links) {
        let uri = link(&s, ib).unwrap();
        assert!(!uri.contains('节'), "{uri}");
        if ib.protocol != VmessWs {
            assert!(uri.ends_with(&url_encode(&ib.label)), "{uri}");
            assert!(uri.contains("@[2001:db8::42]:"), "{uri}");
        }
    }
    let trojan = link_of(&s, Trojan);
    assert!(
        trojan.starts_with("trojan://pass%3A%40%23%26%3F%2F%E4%B8%AD%E6%96%87@"),
        "{trojan}"
    );
    assert!(
        trojan.ends_with("#%E8%8A%82%E7%82%B9%27s%20%231-Trojan-TLS"),
        "{trojan}"
    );
}

#[test]
fn reality_links_use_the_v2_templates() {
    let s = spec_with(&[
        (VlessReality, 443, XR),
        (VlessXhttp, 8443, XR),
        (VlessGrpc, 2053, SB),
    ]);
    let r = s.reality().unwrap();
    let common = format!(
        "security=reality&sni=www.microsoft.com&fp=chrome&pbk={}&sid={}",
        url_encode(&r.public_key),
        r.short_id
    );
    let uuid = &s.creds.uuid;
    assert_eq!(
        link_of(&s, VlessReality),
        format!("vless://{uuid}@203.0.113.10:443?encryption=none&flow=xtls-rprx-vision&{common}&type=tcp&headerType=none#onebox-VLESS-Reality-Vision")
    );
    assert_eq!(
        link_of(&s, VlessXhttp),
        format!(
            "vless://{uuid}@203.0.113.10:8443?encryption=none&{common}&type=xhttp&path={}&mode=auto#onebox-VLESS-XHTTP-Reality",
            url_encode(&s.creds.xhttp_path)
        )
    );
    assert!(link_of(&s, VlessGrpc).contains(&format!(
        "&type=grpc&serviceName={}&mode=gun#",
        s.creds.grpc_service
    )));
}

#[test]
fn pinned_links_carry_pins_per_client_convention() {
    let s = nasty();
    let pin = s
        .tls
        .as_ref()
        .unwrap()
        .pinned_material()
        .unwrap()
        .unwrap()
        .pin()
        .to_owned();
    let ws = link_of(&s, VlessWs);
    assert!(
        ws.contains(&format!(
            "alpn=http%2F1.1&allowInsecure=1&insecure=1&pcs={pin}&type=ws&host=www.bing.com&path="
        )),
        "{ws}"
    );
    assert!(
        link_of(&s, Trojan).contains(&format!("&allowInsecure=1&insecure=1&pcs={pin}&type=tcp"))
    );
    let hy2 = link_of(&s, Hysteria2);
    assert!(hy2.contains(&format!(
        "/?sni=www.bing.com&alpn=h3&insecure=1&pinSHA256={pin}&obfs=salamander&obfs-password=obfs%26%2Bpassword&mport=25000-26000#"
    )), "{hy2}");
    let tuic = link_of(&s, Tuic);
    assert!(
        tuic.contains("&udp_relay_mode=native&allow_insecure=1&insecure=1#"),
        "{tuic}"
    );
    assert!(link_of(&s, Anytls).contains(&format!("/?sni=www.bing.com&insecure=1&hpkp={pin}#")));
}

#[test]
fn publicly_trusted_links_have_no_trust_overrides() {
    let mut cfg = config(&[
        (VlessWs, 1, SB),
        (Trojan, 2, SB),
        (Hysteria2, 3, SB),
        (Tuic, 4, SB),
        (Anytls, 5, SB),
    ]);
    cfg.tls = Some(ProxyTls {
        mode: ProxyCertMode::Acme {
            domain: "proxy.example.com".into(),
            method: AcmeMethod::Cloudflare,
        },
        pinned: false,
    });
    let s = NodeSpec::new(&cfg, &paths(), None).unwrap();
    for ib in &s.inbounds {
        let uri = link(&s, ib).unwrap();
        assert!(!uri.contains("insecure") && !uri.contains("pcs="), "{uri}");
        assert!(uri.contains("sni=proxy.example.com"), "{uri}");
    }
}

fn vmess_json(uri: &str) -> Value {
    let payload = uri.strip_prefix("vmess://").unwrap();
    serde_json::from_slice(&STANDARD.decode(payload).unwrap()).unwrap()
}

#[test]
fn vmess_links_are_base64_json_with_raw_values() {
    let s = nasty();
    let uri = link_of(&s, VmessWs);
    let decoded = STANDARD
        .decode(uri.strip_prefix("vmess://").unwrap())
        .unwrap();
    let text = String::from_utf8(decoded).unwrap();
    assert!(
        text.starts_with("{\"add\":\"2001:db8::42\",\"aid\":\"0\","),
        "sorted keys: {text}"
    );
    let v = vmess_json(&uri);
    let pin = s
        .tls
        .as_ref()
        .unwrap()
        .pinned_material()
        .unwrap()
        .unwrap()
        .pin()
        .to_owned();
    let port = s.require(VmessWs).unwrap().port.to_string();
    assert_eq!(v["port"], port.as_str());
    assert_eq!(v["ps"], "节点's #1-VMess-WS");
    assert_eq!(v["path"], s.creds.vmess_path.as_str());
    assert_eq!(v["tls"], "");
    assert_eq!(v["host"], "");
    assert!(v.get("pcs").is_none());

    let mut cfg = all_protocols();
    cfg.vmess_tls = true;
    let tls = vmess_json(&link_of(&spec(&cfg), VmessWs));
    assert_eq!(
        (tls["tls"].clone(), tls["sni"].clone()),
        ("tls".into(), "www.bing.com".into())
    );
    assert_eq!(
        (tls["alpn"].clone(), tls["fp"].clone()),
        ("http/1.1".into(), "chrome".into())
    );
    assert_eq!(tls["host"], "www.bing.com");
    assert_eq!(
        (tls["insecure"].clone(), tls["pcs"].clone()),
        ("1".into(), pin.into())
    );
    let mut plain = config(&[(VmessWs, 8080, SB)]);
    plain.vmess_host = Some("cdn.example.com".into());
    let v = vmess_json(&link_of(&spec(&plain), VmessWs));
    assert_eq!(
        (v["host"].clone(), v["sni"].clone()),
        ("cdn.example.com".into(), "".into())
    );
}

#[test]
fn shadowsocks_userinfo_is_unpadded_base64url() {
    let mut cfg = config(&[(Shadowsocks, 8388, SB)]);
    cfg.creds.ss_password = "c3Nwc3Nwc3Nwc3Nwc3M/Pw==".into();
    let uri = link_of(&spec(&cfg), Shadowsocks);
    let auth = uri
        .strip_prefix("ss://")
        .unwrap()
        .split('@')
        .next()
        .unwrap();
    assert!(!auth.contains(['+', '/', '=']), "{auth}");
    let decoded = URL_SAFE_NO_PAD.decode(auth).unwrap();
    assert_eq!(decoded, b"2022-blake3-aes-128-gcm:c3Nwc3Nwc3Nwc3Nwc3M/Pw==");
    assert!(uri.ends_with("@203.0.113.10:8388#onebox-Shadowsocks-2022"));
}

#[test]
fn links_text_and_subscription_encoding() {
    let s = spec_with(&[
        (Trojan, 443, SB),
        (Shadowtls, 8443, SB),
        (Shadowsocks, 8388, SB),
    ]);
    let text = links_text(&s).unwrap();
    assert_eq!(text.lines().count(), 2);
    assert!(text.ends_with('\n') && !text.ends_with("\n\n"));
    let sub = subscription(&s).unwrap();
    assert!(sub.ends_with('\n') && sub.lines().count() == 1);
    assert_eq!(STANDARD.decode(sub.trim_end()).unwrap(), text.as_bytes());
}

#[test]
fn unsupported_protocols_and_formats_are_errors() {
    let s = spec_with(&[(Shadowtls, 443, SB), (AnytlsReality, 8443, SB)]);
    for p in [Shadowtls, AnytlsReality] {
        let err = link(&s, s.require(p).unwrap()).unwrap_err();
        assert_eq!(err.to_string(), format!("{p} 不支持通用分享链接"));
    }
    let links = links_text(&s).unwrap_err().to_string();
    assert!(
        links.contains("links") && links.contains("singbox"),
        "{links}"
    );
    // v2 named `links` for the Base64 export (C-8.1 #17).
    let sub = subscription(&s).unwrap_err().to_string();
    assert!(sub.contains("base64") && !sub.contains("links"), "{sub}");
}
