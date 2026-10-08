use super::*;
use crate::render::fixtures::{all_protocols, config, spec, spec_with, with_site};
use serde_json::json;
use Core::{Singbox as SB, Xray as XR};
use Protocol::*;

fn entry_of(bundle: &ProbeBundle, p: Protocol) -> &ProbeEntry {
    bundle.entries.iter().find(|e| e.id == p.id()).unwrap()
}

#[test]
fn entries_use_the_client_core_matching_the_server() {
    let s = spec_with(&[
        (Trojan, 1, XR),
        (Tuic, 2, SB),
        (VlessXhttp, 3, XR),
        (Shadowsocks, 4, SB),
    ]);
    let b = bundle(&s, false).unwrap();
    let table = [
        (Trojan, Core::Xray, Transport::Tcp, "proxy"),
        (Tuic, Core::Singbox, Transport::Udp, "onebox-TUIC-v5"),
        (VlessXhttp, Core::Xray, Transport::Tcp, "proxy"),
        (
            Shadowsocks,
            Core::Singbox,
            Transport::Both,
            "onebox-Shadowsocks-2022",
        ),
    ];
    for (p, core, transport, tag) in table {
        let e = entry_of(&b, p);
        assert_eq!(
            (e.core, e.transport, e.tag.as_str()),
            (core, transport, tag),
            "{p}"
        );
        assert_eq!(e.outbounds[0]["tag"], tag);
        assert!(e.reality.is_none() || p.reality());
    }
    assert_eq!(b.schema, 1);
    let text = b.to_json().unwrap();
    assert!(text.starts_with("{\n  \"entries\": [") && !text.ends_with('\n'));
}

#[test]
fn shadowtls_entries_carry_the_detour_pair() {
    let b = bundle(&spec_with(&[(Shadowtls, 443, SB)]), false).unwrap();
    let e = &b.entries[0];
    assert_eq!(e.outbounds.len(), 2);
    assert_eq!(e.outbounds[0]["detour"], e.outbounds[1]["tag"]);
    assert_eq!(e.outbounds[1]["type"], "shadowtls");
}

#[test]
fn reality_reference_follows_the_site_entrance() {
    let base = config(&[(VlessReality, 443, XR)]);
    let plain = bundle(&spec(&base), false).unwrap();
    let meta = plain.entries[0].reality.clone().unwrap();
    assert_eq!(
        meta,
        RealityProbe {
            host: "203.0.113.10".into(),
            port: 443,
            sni: "www.microsoft.com".into(),
            reference_host: "www.microsoft.com".into(),
            reference_port: 443,
        }
    );
    let https = spec(&with_site(base.clone(), "site.example.com", true));
    let meta = bundle(&https, false).unwrap().entries[0]
        .reality
        .clone()
        .unwrap();
    assert_eq!(
        (meta.reference_host.as_str(), meta.reference_port),
        ("203.0.113.10", 443)
    );
    assert_eq!(meta.sni, "site.example.com");
    let closed = spec(&with_site(base, "site.example.com", false));
    let meta = bundle(&closed, false).unwrap().entries[0]
        .reality
        .clone()
        .unwrap();
    assert_eq!((meta.reference_host.as_str(), meta.reference_port), ("", 0));
    // From the server itself the loopback site is the reference.
    let local = bundle(&closed, true).unwrap().entries[0]
        .reality
        .clone()
        .unwrap();
    assert_eq!(
        (local.host.as_str(), local.reference_host.as_str()),
        ("127.0.0.1", "127.0.0.1")
    );
    assert_eq!(local.reference_port, 10443);
}

#[test]
fn local_bundles_connect_to_the_listen_address() {
    let mut cfg = config(&[(Trojan, 443, XR), (Anytls, 8443, SB)]);
    let b = bundle(&spec(&cfg), true).unwrap();
    assert_eq!(
        entry_of(&b, Trojan).outbounds[0]["settings"]["servers"][0]["address"],
        "127.0.0.1"
    );
    assert_eq!(entry_of(&b, Anytls).outbounds[0]["server"], "127.0.0.1");
    cfg.listen = "10.0.0.5".parse().unwrap();
    let b = bundle(&spec(&cfg), true).unwrap();
    assert_eq!(entry_of(&b, Anytls).outbounds[0]["server"], "10.0.0.5");
}

#[test]
fn bundles_roundtrip_with_unknown_keys() {
    let b = bundle(&spec(&all_protocols()), false).unwrap();
    assert_eq!(b.entries.len(), 12);
    let mut value = b.to_value().unwrap();
    value["entries"][0]["note"] = json!("kept");
    let parsed = ProbeBundle::parse(serde_json::to_string(&value).unwrap().as_bytes()).unwrap();
    assert_eq!(parsed.entries[0].extra["note"], "kept");
    assert_eq!(parsed.to_value().unwrap(), value);
    assert!(!b
        .to_json()
        .unwrap()
        .contains(&spec(&all_protocols()).reality().unwrap().private_key));
}

fn valid() -> Value {
    json!({"schema": 1, "entries": [{"id": "vless-reality", "core": "singbox", "transport": "tcp",
        "tag": "a", "outbounds": [{"type": "vless", "tag": "a"}],
        "reality": {"host": "h", "port": 443, "sni": "s", "reference_host": "", "reference_port": 0}}]})
}

#[test]
fn validation_keeps_every_v2_rule_and_message() {
    assert!(ProbeBundle::from_value(valid()).is_ok());
    let entry = |f: &dyn Fn(&mut Value)| {
        let mut v = valid();
        f(&mut v["entries"][0]);
        v
    };
    let many: Vec<Value> = (0..33)
        .map(|i| {
            let mut e = valid()["entries"][0].clone();
            e["id"] = json!(format!("n{i}"));
            e
        })
        .collect();
    let cases: Vec<(Value, &str)> = vec![
        (
            json!({"schema": true, "entries": []}),
            "探测配置 schema 无效",
        ),
        (json!({"schema": "1"}), "探测配置 schema 无效"),
        (json!({"schema": 1}), "探测配置缺少 entries"),
        (
            json!({"schema": 1, "entries": []}),
            "配置需要 1 至 32 个入口",
        ),
        (
            json!({"schema": 1, "entries": many}),
            "配置需要 1 至 32 个入口",
        ),
        (entry(&|e| e["id"] = json!(7)), "入口 ID 无效"),
        (entry(&|e| e["id"] = json!("bad id")), "入口 ID 无效或重复"),
        (
            entry(&|e| e["id"] = json!("x".repeat(81))),
            "入口 ID 无效或重复",
        ),
        (entry(&|e| e["core"] = json!("clash")), "入口类型无效"),
        (entry(&|e| e["transport"] = json!("quic")), "入口类型无效"),
        (entry(&|e| e["outbounds"] = json!([])), "入口出站无效"),
        (entry(&|e| e["outbounds"] = json!({})), "入口出站无效"),
        (
            entry(&|e| e["outbounds"] = json!([{"type": "direct", "tag": "a"}])),
            "出站包含未支持的协议；不允许 direct/block",
        ),
        (
            entry(&|e| e["outbounds"] = json!([{"type": "vless"}])),
            "出站标签无效",
        ),
        (
            entry(&|e| {
                e["outbounds"] =
                    json!([{"type": "vless", "tag": "a"}, {"type": "shadowtls", "tag": "a"}])
            }),
            "出站标签无效或重复",
        ),
        (entry(&|e| e["tag"] = json!("b")), "出站标签不匹配"),
        (
            entry(&|e| e["reality"]["sni"] = json!("")),
            "REALITY 元数据无效",
        ),
        (
            entry(&|e| e["reality"]["port"] = json!(70000)),
            "REALITY 端口无效",
        ),
        (
            entry(&|e| e["reality"]["reference_port"] = json!("x")),
            "探测配置无效",
        ),
    ];
    for (value, message) in cases {
        let err = ProbeBundle::from_value(value.clone())
            .unwrap_err()
            .to_string();
        assert!(err.starts_with(message), "{value}: {err}");
    }
    let mut dup = valid();
    let first = dup["entries"][0].clone();
    dup["entries"].as_array_mut().unwrap().push(first);
    assert_eq!(
        ProbeBundle::from_value(dup).unwrap_err().to_string(),
        "入口 ID 无效或重复"
    );
    let mut xray = valid();
    xray["entries"][0]["core"] = json!("xray");
    assert!(
        ProbeBundle::from_value(xray.clone()).is_err(),
        "Xray uses `protocol`"
    );
    xray["entries"][0]["outbounds"] = json!([{"protocol": "hysteria", "tag": "a"}]);
    assert!(ProbeBundle::from_value(xray).is_ok());
}

#[test]
fn parse_enforces_size_and_json() {
    let big = vec![b' '; MAX_BYTES + 1];
    assert_eq!(
        ProbeBundle::parse(&big).unwrap_err().to_string(),
        "探测配置超过 2 MiB"
    );
    assert_eq!(
        ProbeBundle::parse(b"{").unwrap_err().to_string(),
        "探测配置不是有效 JSON"
    );
    let text = serde_json::to_vec(&valid()).unwrap();
    let b = ProbeBundle::parse(&text).unwrap();
    assert_eq!(b.entries[0].reality.as_ref().unwrap().reference_port, 0);
    b.validate().unwrap();
}
