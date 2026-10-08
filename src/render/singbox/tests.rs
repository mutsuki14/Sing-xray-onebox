use super::*;
use crate::domain::config::{Hy2Profile, ResourceProfile};
use crate::render::fixtures::{all_protocols, config, spec, spec_with};
use serde_json::json;
use Core::{Singbox as SB, Xray as XR};
use Protocol::*;

fn first_inbound(spec: &NodeSpec, p: Protocol) -> Value {
    inbound(spec, spec.require(p).unwrap()).unwrap()
}

fn client_outbound(spec: &NodeSpec, p: Protocol) -> Value {
    outbound(spec, spec.require(p).unwrap()).unwrap()
}

#[test]
fn server_lists_inbounds_with_the_shadowtls_backend_and_v2_route() {
    let s = spec_with(&[
        (Shadowtls, 443, SB),
        (Trojan, 8443, SB),
        (VlessXhttp, 2053, XR),
    ]);
    let doc = server(&s).unwrap();
    let tags: Vec<&str> = doc["inbounds"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| i["tag"].as_str().unwrap())
        .collect();
    assert_eq!(tags, ["shadowtls-in", "shadowtls-ss-in", "trojan-in"]);
    let backend = &doc["inbounds"][1];
    assert_eq!(backend["listen"], "127.0.0.1");
    assert_eq!(backend["network"], "tcp");
    assert!(backend.get("listen_port").is_none());
    let rules = doc["route"]["rules"].as_array().unwrap();
    assert_eq!(rules[0], json!({"action": "sniff"}));
    assert_eq!(
        rules[1],
        json!({"protocol": "bittorrent", "action": "reject"})
    );
    assert_eq!(
        rules[2],
        json!({"action": "resolve", "strategy": "ipv4_only"})
    );
    assert_eq!(rules[3], json!({"ip_is_private": true, "action": "reject"}));
    assert!(rules[4]["ip_cidr"]
        .as_array()
        .unwrap()
        .contains(&json!("203.0.113.10/32")));
    assert_eq!(
        doc["route"]["default_domain_resolver"]["strategy"],
        "ipv4_only"
    );
    assert_eq!(
        doc["dns"],
        json!({"servers": [{"type": "local", "tag": "local"}]})
    );
}

#[test]
fn egress_rules_follow_the_block_switches() {
    let mut cfg = config(&[(Trojan, 443, SB)]);
    cfg.routing.block_private = false;
    let rules = server(&spec(&cfg)).unwrap()["route"]["rules"].clone();
    assert_eq!(rules.as_array().unwrap().len(), 2);
    cfg.routing.block_bt = false;
    let rules = server(&spec(&cfg)).unwrap()["route"]["rules"].clone();
    assert_eq!(rules, json!([{"action": "sniff"}]));
}

#[test]
fn server_without_singbox_inbounds_is_an_error() {
    let s = spec_with(&[(VlessXhttp, 443, XR)]);
    assert_eq!(
        server(&s).unwrap_err().to_string(),
        "没有分配给 singbox 的协议"
    );
}

#[test]
fn reality_inbounds_handshake_directly_with_the_target() {
    let mut cfg = config(&[(VlessReality, 443, SB), (AnytlsReality, 8443, SB)]);
    cfg.reality.dest = "[2001:db8::9]:443".parse().unwrap();
    let s = spec(&cfg);
    let v = first_inbound(&s, VlessReality);
    assert_eq!(v["users"][0]["flow"], "xtls-rprx-vision");
    let reality = &v["tls"]["reality"];
    assert_eq!(
        reality["handshake"],
        json!({"server": "2001:db8::9", "server_port": 443})
    );
    assert_eq!(reality["short_id"], json!([s.reality().unwrap().short_id]));
    let any = first_inbound(&s, AnytlsReality);
    assert_eq!(any["type"], "anytls");
    assert!(any["tls"].get("certificate_path").is_none());
}

#[test]
fn certificate_inbounds_reference_the_deployed_pair_with_v2_alpn() {
    let s = spec_with(&[
        (VlessWs, 1, SB),
        (Trojan, 2, SB),
        (Tuic, 3, SB),
        (Anytls, 4, SB),
    ]);
    let table = [
        (VlessWs, Some(json!(["http/1.1"]))),
        (Trojan, Some(json!(["h2", "http/1.1"]))),
        (Tuic, Some(json!(["h3"]))),
        (Anytls, None),
    ];
    for (p, alpn) in table {
        let tls = first_inbound(&s, p)["tls"].clone();
        assert_eq!(
            tls["certificate_path"], "/onebox-test/etc/tls/cert.pem",
            "{p}"
        );
        assert_eq!(tls["key_path"], "/onebox-test/etc/tls/key.pem");
        assert_eq!(tls.get("alpn").cloned(), alpn, "{p}");
    }
    let tuic = first_inbound(&s, Tuic);
    assert_eq!(tuic["users"][0]["uuid"], json!(s.creds.uuid));
    assert_eq!(tuic["congestion_control"], "bbr");
    let ws = first_inbound(&s, VlessWs)["transport"].clone();
    assert!(ws.get("headers").is_none());
    assert_eq!(ws["max_early_data"], 2048);
}

#[test]
fn hysteria2_obfuscation_replaces_the_masquerade() {
    let mut cfg = config(&[(Hysteria2, 443, SB)]);
    let v = first_inbound(&spec(&cfg), Hysteria2);
    assert_eq!(v["masquerade"]["url"], "https://www.bing.com");
    assert!(v.get("obfs").is_none());
    cfg.hy2.obfs = true;
    let v = first_inbound(&spec(&cfg), Hysteria2);
    assert!(v.get("masquerade").is_none());
    assert_eq!(v["obfs"]["type"], "salamander");
}

#[test]
fn measured_bandwidth_is_swapped_to_the_server_perspective() {
    let mut cfg = config(&[(Hysteria2, 443, SB)]);
    cfg.hy2.profile = Some(Hy2Profile::Measured);
    cfg.hy2.up_mbps = Some(50);
    cfg.hy2.down_mbps = Some(200);
    cfg.resource_profile = ResourceProfile::LowMemory;
    let s = spec(&cfg);
    let server_side = first_inbound(&s, Hysteria2);
    assert_eq!(
        (
            server_side["up_mbps"].clone(),
            server_side["down_mbps"].clone()
        ),
        (json!(200), json!(50))
    );
    assert_eq!(server_side["max_concurrent_streams"], 64);
    assert!(server_side.get("ignore_client_bandwidth").is_none());
    let client_side = client_outbound(&s, Hysteria2);
    assert_eq!(
        (
            client_side["up_mbps"].clone(),
            client_side["down_mbps"].clone()
        ),
        (json!(50), json!(200))
    );
    assert_eq!(client_side["stream_receive_window"], 2_097_152);
    assert!(client_side.get("max_concurrent_streams").is_none());
}

#[test]
fn congestion_profiles_on_both_sides() {
    let mut cfg = config(&[(Hysteria2, 443, SB)]);
    let table = [
        (Hy2Profile::Auto, json!(true), Value::Null, Value::Null),
        (
            Hy2Profile::Conservative,
            json!(true),
            json!("conservative"),
            json!("conservative"),
        ),
    ];
    for (profile, ignore, server_bbr, client_bbr) in table {
        cfg.hy2.profile = Some(profile);
        let s = spec(&cfg);
        let inb = first_inbound(&s, Hysteria2);
        let out = client_outbound(&s, Hysteria2);
        assert_eq!(inb["ignore_client_bandwidth"], ignore, "{profile}");
        assert_eq!(
            inb.get("bbr_profile").cloned().unwrap_or(Value::Null),
            server_bbr
        );
        assert_eq!(
            out.get("bbr_profile").cloned().unwrap_or(Value::Null),
            client_bbr
        );
        assert!(out.get("up_mbps").is_none());
    }
}

#[test]
fn pinned_clients_embed_the_chain_and_never_go_insecure() {
    let s = spec(&all_protocols());
    let doc = client(&s, false).unwrap();
    let text = doc.to_string();
    assert!(!text.contains("insecure"));
    assert!(!text.contains("PRIVATE KEY"));
    assert!(!text.contains(&s.reality().unwrap().private_key));
    assert!(!text.contains("key_path"));
    let trojan = client_outbound(&s, Trojan);
    let pems = trojan["tls"]["certificate"].as_array().unwrap();
    assert_eq!(pems.len(), 1);
    assert!(pems[0]
        .as_str()
        .unwrap()
        .starts_with("-----BEGIN CERTIFICATE-----\n"));
    assert_eq!(trojan["tls"]["utls"]["fingerprint"], "chrome");
    let hy2 = client_outbound(&s, Hysteria2);
    assert!(hy2["tls"].get("utls").is_none());
    assert_eq!(hy2["tls"]["alpn"], json!(["h3"]));
}

#[test]
fn unloaded_pin_fails_client_outbounds_but_not_the_server() {
    let cfg = config(&[(Trojan, 443, SB)]);
    let s = NodeSpec::new(&cfg, &crate::render::fixtures::paths(), None).unwrap();
    assert!(server(&s).is_ok());
    let err = outbound(&s, s.require(Trojan).unwrap()).unwrap_err();
    assert_eq!(err.to_string(), "固定证书的客户端配置缺少证书指纹");
}

#[test]
fn client_outbounds_carry_transport_details() {
    let mut cfg = all_protocols();
    cfg.hy2.obfs = true;
    cfg.hy2.hop = Some("30000-30100".parse().unwrap());
    let s = spec(&cfg);
    let ws = client_outbound(&s, VlessWs);
    assert_eq!(ws["transport"]["headers"], json!({"Host": "www.bing.com"}));
    let hy2 = client_outbound(&s, Hysteria2);
    assert_eq!(hy2["server_ports"], json!(["30000:30100"]));
    assert_eq!(hy2["hop_interval"], "30s");
    assert_eq!(hy2["obfs"]["password"], json!(s.creds.hy2_obfs_password));
    let tuic = client_outbound(&s, Tuic);
    assert_eq!(tuic["udp_relay_mode"], "native");
    assert_eq!(tuic["zero_rtt_handshake"], false);
    let grpc = client_outbound(&s, VlessGrpc);
    assert_eq!(
        grpc["transport"]["service_name"],
        json!(s.creds.grpc_service)
    );
    assert_eq!(
        grpc["tls"]["reality"]["short_id"],
        json!(s.reality().unwrap().short_id)
    );
    let err = outbound(&s, s.require(VlessXhttp).unwrap()).unwrap_err();
    assert_eq!(err.to_string(), "singbox 客户端不支持 vless-xhttp");
}

#[test]
fn plain_vmess_sends_the_configured_host() {
    let mut cfg = config(&[(VmessWs, 8080, SB)]);
    cfg.vmess_host = Some("cdn.example.com".into());
    let s = spec(&cfg);
    let out = client_outbound(&s, VmessWs);
    assert!(out.get("tls").is_none());
    assert_eq!(out["transport"]["headers"]["Host"], "cdn.example.com");
    let inb = first_inbound(&s, VmessWs);
    assert!(inb.get("tls").is_none());
    assert!(inb["transport"].get("headers").is_none());
    assert_eq!(inb["users"][0]["alterId"], 0);
}

#[test]
fn shadowtls_clients_ship_exactly_one_detour() {
    let s = spec_with(&[(Shadowtls, 443, SB)]);
    let doc = client(&s, true).unwrap();
    let outbounds = doc["outbounds"].as_array().unwrap();
    let tags: Vec<&str> = outbounds
        .iter()
        .map(|o| o["tag"].as_str().unwrap())
        .collect();
    assert_eq!(
        tags,
        [
            "proxy",
            "auto",
            "onebox-ShadowTLS-v3",
            "onebox-ShadowTLS-v3-tls",
            "direct"
        ]
    );
    assert_eq!(outbounds[2]["detour"], "onebox-ShadowTLS-v3-tls");
    assert_eq!(
        outbounds[2]["udp_over_tcp"],
        json!({"enabled": true, "version": 2})
    );
    assert_eq!(outbounds[3]["type"], "shadowtls");
    assert_eq!(outbounds[3]["tls"]["server_name"], "www.microsoft.com");
}

#[test]
fn client_documents_with_and_without_tun() {
    let s = spec_with(&[
        (VlessReality, 443, SB),
        (VlessXhttp, 8443, XR),
        (Trojan, 2053, SB),
    ]);
    let tun = client(&s, true).unwrap();
    assert_eq!(tun["inbounds"][0]["type"], "tun");
    assert_eq!(tun["inbounds"][0]["address"], json!(policy::TUN_ADDRESSES));
    assert_eq!(tun["inbounds"][1]["listen_port"], 2080);
    let plain = client(&s, false).unwrap();
    assert_eq!(plain["inbounds"].as_array().unwrap().len(), 1);
    assert_eq!(
        plain["outbounds"][0]["outbounds"],
        json!([
            "auto",
            "onebox-VLESS-Reality-Vision",
            "onebox-Trojan-TLS",
            "direct"
        ])
    );
    assert_eq!(plain["outbounds"][1]["interval"], "3m");
    let api = &plain["experimental"]["clash_api"];
    assert_eq!(api["external_controller"], "127.0.0.1:9090");
    assert_eq!(api["secret"], json!(s.creds.clash_secret));
    assert_eq!(plain["route"]["rule_set"][0]["tag"], "geosite-cn");
    assert_eq!(plain["dns"]["final"], "dns-remote");
    let only_xhttp = spec_with(&[(VlessXhttp, 443, XR)]);
    let err = client(&only_xhttp, true).unwrap_err().to_string();
    assert!(err.contains("singbox"), "{err}");
}
