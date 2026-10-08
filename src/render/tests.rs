use super::fixtures::{all_protocols, spec, spec_with};
use super::*;
use Core::{Singbox as SB, Xray as XR};
use Protocol::*;

#[test]
fn every_export_ends_in_exactly_one_newline() {
    let s = spec(&all_protocols());
    for format in ClientFormat::ALL {
        let text = client(&s, format).unwrap();
        assert!(text.ends_with('\n') && !text.ends_with("\n\n"), "{format}");
    }
    for core in Core::ALL {
        let text = server_text(&s, core).unwrap();
        assert!(
            text.ends_with('}'),
            "server configs have no trailing newline"
        );
    }
}

#[test]
fn json_exports_parse_and_yaml_exports_are_not_json() {
    let s = spec(&all_protocols());
    for format in [
        ClientFormat::Singbox,
        ClientFormat::SingboxNoTun,
        ClientFormat::Xray,
    ] {
        serde_json::from_str::<Value>(&client(&s, format).unwrap()).unwrap();
    }
    let yaml = client(&s, ClientFormat::Mihomo).unwrap();
    assert!(yaml.starts_with("allow-lan: false\n"), "{yaml}");
    assert_eq!(
        yaml::reader::parse(&yaml).unwrap(),
        mihomo::config(&s).unwrap()
    );
}

#[test]
fn dispatchers_use_the_configured_core() {
    let s = spec_with(&[(Trojan, 443, XR), (Tuic, 8443, SB)]);
    assert_eq!(inbound(&s, Trojan).unwrap()["protocol"], "trojan");
    assert_eq!(inbound(&s, Tuic).unwrap()["type"], "tuic");
    assert_eq!(outbound(&s, Trojan, SB).unwrap()["type"], "trojan");
    assert_eq!(outbound(&s, Trojan, XR).unwrap()["protocol"], "trojan");
    let err = outbound(&s, Tuic, XR).unwrap_err().to_string();
    assert_eq!(err, "xray 客户端不支持 tuic");
    let err = inbound(&s, Anytls).unwrap_err().to_string();
    assert_eq!(err, "未启用协议 anytls");
    assert!(server(&s, XR).is_ok() && server(&s, SB).is_ok());
}

#[test]
fn a_format_without_nodes_names_itself_and_the_usable_formats() {
    let s = spec_with(&[(AnytlsReality, 443, SB)]);
    let table = [
        (ClientFormat::Links, "links"),
        (ClientFormat::Base64, "base64"),
        (ClientFormat::Mihomo, "mihomo"),
        (ClientFormat::Provider, "provider"),
        (ClientFormat::Xray, "xray"),
    ];
    for (format, id) in table {
        let err = client(&s, format).unwrap_err().to_string();
        assert_eq!(
            err,
            format!("当前协议组合没有支持 {id} 格式的节点，请改用 singbox / singbox-notun")
        );
    }
}

#[test]
fn server_secrets_never_reach_client_exports() {
    let s = spec(&all_protocols());
    let private_key = &s.reality().unwrap().private_key;
    let mut exports: Vec<String> = ClientFormat::ALL
        .iter()
        .map(|f| client(&s, *f).unwrap())
        .collect();
    exports.push(probe::bundle(&s, false).unwrap().to_json().unwrap());
    for text in exports {
        assert!(!text.contains(private_key.as_str()));
        assert!(!text.contains("PRIVATE KEY"));
        assert!(!text.contains("key.pem"));
    }
    let server = server_text(&s, SB).unwrap();
    assert!(server.contains(private_key.as_str()));
}
