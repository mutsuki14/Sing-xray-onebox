use super::*;
use crate::domain::protocol::Protocol;
use crate::render::fixtures::{config, paths, spec, spec_with, with_site};
use serde_json::json;
use Core::{Singbox as SB, Xray as XR};
use Protocol::*;

fn find<'a>(list: &'a Value, key: &str, value: &str) -> &'a Value {
    list.as_array()
        .unwrap()
        .iter()
        .find(|v| v[key] == value)
        .unwrap_or_else(|| panic!("no {key}={value}"))
}

#[test]
fn shared_port_has_one_reality_terminator_and_a_socket_fallback() {
    let s = spec_with(&[(VlessReality, 443, XR), (VlessXhttp, 443, XR)]);
    let doc = server(&s).unwrap();
    let vision = find(&doc["inbounds"], "tag", "vless-reality-in");
    assert_eq!(
        vision["settings"]["fallbacks"],
        json!([{"dest": "@onebox-xhttp", "xver": 1}])
    );
    assert_eq!(vision["streamSettings"]["network"], "raw");
    assert_eq!(
        vision["streamSettings"]["realitySettings"]["target"],
        "127.0.0.1:18000"
    );
    let xhttp = find(&doc["inbounds"], "tag", "vless-xhttp-in");
    assert_eq!(xhttp["listen"], "@onebox-xhttp");
    assert!(xhttp.get("port").is_none());
    let stream = &xhttp["streamSettings"];
    assert!(stream.get("realitySettings").is_none() && stream.get("security").is_none());
    assert_eq!(stream["sockopt"]["acceptProxyProtocol"], true);
    assert_eq!(stream["xhttpSettings"]["mode"], "auto");
}

#[test]
fn separate_xhttp_port_terminates_reality_itself() {
    let s = spec_with(&[(VlessReality, 443, XR), (VlessXhttp, 8443, XR)]);
    let doc = server(&s).unwrap();
    assert!(
        find(&doc["inbounds"], "tag", "vless-reality-in")["settings"]
            .get("fallbacks")
            .is_none()
    );
    let xhttp = find(&doc["inbounds"], "tag", "vless-xhttp-in");
    assert_eq!(xhttp["port"], 8443);
    assert_eq!(xhttp["streamSettings"]["security"], "reality");
    assert_eq!(xhttp["streamSettings"]["network"], "xhttp");
}

#[test]
fn guard_forwards_only_the_exact_sni_and_blackholes_the_rest() {
    let s = spec_with(&[(VlessGrpc, 443, XR)]);
    let doc = server(&s).unwrap();
    let guard = find(&doc["inbounds"], "tag", "reality-dest-in");
    assert_eq!(guard["listen"], "127.0.0.1");
    assert_eq!(guard["port"], 18000);
    assert_eq!(
        guard["settings"],
        json!({"address": "www.microsoft.com", "port": 443, "network": "tcp"})
    );
    let rules = doc["routing"]["rules"].as_array().unwrap();
    assert_eq!(rules[0]["domain"], json!(["full:www.microsoft.com"]));
    assert_eq!(rules[0]["outboundTag"], "direct");
    assert_eq!(
        rules[1],
        json!({"type": "field", "inboundTag": ["reality-dest-in"], "outboundTag": "block"})
    );
    assert_eq!(rules[2]["protocol"], json!(["bittorrent"]));
    assert_eq!(rules[3]["outboundTag"], "block");
    assert_eq!(doc["routing"]["domainStrategy"], "IPIfNonMatch");
    let tags: Vec<&str> = doc["outbounds"]
        .as_array()
        .unwrap()
        .iter()
        .map(|o| o["tag"].as_str().unwrap())
        .collect();
    assert_eq!(tags, ["direct", "block"]);
    // sing-box REALITY needs no guard.
    let doc = server(&spec_with(&[(VlessReality, 443, SB), (Trojan, 8443, XR)])).unwrap();
    assert_eq!(doc["inbounds"].as_array().unwrap().len(), 1);
}

#[test]
fn own_site_guard_redirects_to_the_loopback_site_only() {
    let cfg = with_site(
        config(&[(VlessReality, 443, XR)]),
        "site.example.com",
        false,
    );
    let doc = server(&spec(&cfg)).unwrap();
    let guard = find(&doc["inbounds"], "tag", "reality-dest-in");
    assert_eq!(guard["settings"]["address"], "127.0.0.1");
    assert_eq!(guard["settings"]["port"], 10443);
    let site = find(&doc["outbounds"], "tag", "reality-site");
    assert_eq!(site["settings"]["redirect"], "127.0.0.1:10443");
    assert_eq!(
        site["settings"]["finalRules"],
        json!([{"action": "allow", "network": "tcp", "ip": ["127.0.0.1/32"], "port": "10443"},
            {"action": "block"}])
    );
    assert_eq!(doc["routing"]["rules"][0]["outboundTag"], "reality-site");
    assert_eq!(
        doc["routing"]["rules"][0]["domain"],
        json!(["full:site.example.com"])
    );
}

#[test]
fn private_egress_switch_changes_strategy_and_freedom_rules() {
    let mut cfg = config(&[(Trojan, 443, XR)]);
    cfg.routing.block_private = false;
    cfg.routing.block_bt = false;
    let doc = server(&spec(&cfg)).unwrap();
    assert_eq!(doc["routing"]["domainStrategy"], "AsIs");
    assert_eq!(doc["routing"]["rules"], json!([]));
    let direct = find(&doc["outbounds"], "tag", "direct");
    assert_eq!(
        direct["settings"],
        json!({"finalRules": [{"action": "allow"}]})
    );
    assert_eq!(
        direct["streamSettings"]["sockopt"]["domainStrategy"],
        "UseIPv4"
    );
    cfg.routing.block_private = true;
    let doc = server(&spec(&cfg)).unwrap();
    assert!(find(&doc["outbounds"], "tag", "direct")
        .get("settings")
        .is_none());
}

#[test]
fn hysteria2_server_masquerades_only_without_obfuscation() {
    let mut cfg = config(&[(Hysteria2, 443, XR)]);
    let s = spec(&cfg);
    let v = inbound(&s, s.require(Hysteria2).unwrap()).unwrap();
    let stream = &v["streamSettings"];
    assert_eq!(
        stream["hysteriaSettings"]["masquerade"]["rewriteHost"],
        true
    );
    assert!(stream.get("finalmask").is_none());
    assert_eq!(v["settings"]["clients"][0]["auth"], json!(s.creds.password));
    cfg.hy2.obfs = true;
    let s = spec(&cfg);
    let v = inbound(&s, s.require(Hysteria2).unwrap()).unwrap();
    let stream = &v["streamSettings"];
    assert_eq!(stream["hysteriaSettings"], json!({"version": 2}));
    assert_eq!(stream["finalmask"]["udp"][0]["type"], "salamander");
    assert_eq!(stream["tlsSettings"]["alpn"], json!(["h3"]));
}

#[test]
fn inbound_shapes_per_protocol() {
    let s = spec_with(&[
        (VlessWs, 1, XR),
        (VmessWs, 2, XR),
        (Trojan, 3, XR),
        (Shadowsocks, 4, XR),
    ]);
    let get = |p| inbound(&s, s.require(p).unwrap()).unwrap();
    let ws = get(VlessWs);
    assert_eq!(
        ws["streamSettings"]["wsSettings"],
        json!({"path": s.creds.ws_path})
    );
    assert_eq!(
        ws["streamSettings"]["tlsSettings"]["certificates"][0]["keyFile"],
        "/onebox-test/etc/tls/key.pem"
    );
    let vmess = get(VmessWs);
    assert_eq!(vmess["streamSettings"]["security"], "none");
    assert!(vmess["settings"].get("decryption").is_none());
    assert_eq!(
        get(Trojan)["streamSettings"]["tlsSettings"]["alpn"],
        json!(["h2", "http/1.1"])
    );
    let ss = get(Shadowsocks);
    assert!(ss.get("streamSettings").is_none());
    assert_eq!(ss["settings"]["network"], "tcp,udp");
    assert_eq!(
        ss["sniffing"]["destOverride"],
        json!(["http", "tls", "quic"])
    );
    assert_eq!(ss["listen"], "::");
    let err = server(&spec_with(&[(Tuic, 1, SB)]))
        .unwrap_err()
        .to_string();
    assert_eq!(err, "没有分配给 xray 的协议");
}

#[test]
fn client_uses_the_first_node_as_proxy() {
    let s = spec_with(&[
        (Tuic, 1, SB),
        (VlessGrpc, 2, XR),
        (Hysteria2, 3, SB),
        (Shadowsocks, 4, SB),
    ]);
    let doc = client(&s).unwrap();
    let tags: Vec<&str> = doc["outbounds"]
        .as_array()
        .unwrap()
        .iter()
        .map(|o| o["tag"].as_str().unwrap())
        .collect();
    assert_eq!(
        tags,
        ["proxy", "hysteria2", "shadowsocks", "direct", "block"]
    );
    assert_eq!(doc["inbounds"][0]["port"], 10808);
    assert_eq!(doc["inbounds"][1]["port"], 10809);
    assert_eq!(
        doc["routing"]["rules"][1]["ip"],
        json!(policy::PRIVATE_CIDRS)
    );
    assert_eq!(doc["dns"]["queryStrategy"], "UseIP");
}

#[test]
fn client_outbounds_pin_by_leaf_hash() {
    let mut cfg = config(&[(VlessWs, 1, XR), (VmessWs, 2, XR), (Hysteria2, 3, XR)]);
    cfg.vmess_tls = true;
    cfg.hy2.obfs = true;
    cfg.hy2.hop = Some("40000-40100".parse().unwrap());
    let s = spec(&cfg);
    let pin = s
        .tls
        .as_ref()
        .unwrap()
        .pinned_material()
        .unwrap()
        .unwrap()
        .pin()
        .to_owned();
    for p in [VlessWs, VmessWs, Hysteria2] {
        let v = outbound(&s, s.require(p).unwrap()).unwrap();
        let tls = &v["streamSettings"]["tlsSettings"];
        assert_eq!(tls["pinnedPeerCertSha256"], json!(pin), "{p}");
        assert_eq!(tls["fingerprint"], "chrome");
    }
    let vmess = outbound(&s, s.require(VmessWs).unwrap()).unwrap();
    assert_eq!(
        vmess["settings"]["vnext"][0]["users"][0],
        json!({"id": s.creds.uuid, "security": "auto"})
    );
    assert_eq!(
        vmess["streamSettings"]["wsSettings"]["host"],
        "www.bing.com"
    );
    let hy2 = outbound(&s, s.require(Hysteria2).unwrap()).unwrap();
    let mask = &hy2["streamSettings"]["finalmask"];
    assert_eq!(
        mask["udp"][0]["settings"]["password"],
        json!(s.creds.hy2_obfs_password)
    );
    assert_eq!(
        mask["quicParams"]["udpHop"],
        json!({"ports": "40000-40100", "interval": "25-35"})
    );
    assert_eq!(
        hy2["settings"],
        json!({"version": 2, "address": "203.0.113.10", "port": 3})
    );
}

#[test]
fn plain_clients_have_no_tls_and_no_empty_finalmask() {
    let mut cfg = config(&[(VmessWs, 8080, XR), (Hysteria2, 443, XR)]);
    cfg.tls = None;
    cfg.inbounds.retain(|i| i.protocol == VmessWs);
    cfg.vmess_host = Some("cdn.example.com".into());
    let s = NodeSpec::new(&cfg, &paths(), None).unwrap();
    let vmess = outbound(&s, s.require(VmessWs).unwrap()).unwrap();
    assert_eq!(
        vmess["streamSettings"],
        json!({"security": "none", "network": "ws",
            "wsSettings": {"path": s.creds.vmess_path, "host": "cdn.example.com"}})
    );
    let hy2 = spec_with(&[(Hysteria2, 443, XR)]);
    let v = outbound(&hy2, hy2.require(Hysteria2).unwrap()).unwrap();
    assert!(v["streamSettings"].get("finalmask").is_none());
}

#[test]
fn reality_client_settings_and_unsupported_protocols() {
    let s = spec_with(&[(VlessReality, 443, XR), (Anytls, 8443, SB)]);
    let v = outbound(&s, s.require(VlessReality).unwrap()).unwrap();
    let user = &v["settings"]["vnext"][0]["users"][0];
    assert_eq!(user["flow"], "xtls-rprx-vision");
    assert_eq!(user["encryption"], "none");
    let reality = &v["streamSettings"]["realitySettings"];
    assert_eq!(reality["spiderX"], "/");
    assert_eq!(reality["publicKey"], json!(s.reality().unwrap().public_key));
    assert!(!v.to_string().contains(&s.reality().unwrap().private_key));
    let err = outbound(&s, s.require(Anytls).unwrap()).unwrap_err();
    assert_eq!(err.to_string(), "xray 客户端不支持 anytls");
}
