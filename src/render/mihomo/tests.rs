use super::*;
use crate::domain::config::ResourceProfile;
use crate::domain::protocol::Core;
use crate::render::fixtures::{
    all_protocols, config as node, ip_subscription, spec, spec_with, with_site,
};
use crate::render::yaml::{reader, to_yaml};
use Core::{Singbox as SB, Xray as XR};
use Protocol::*;

fn proxy_of(spec: &NodeSpec, p: Protocol) -> Value {
    proxy(spec, spec.require(p).unwrap()).unwrap()
}

#[test]
fn provider_is_only_the_proxy_list_without_anytls_reality() {
    let s = spec(&all_protocols());
    let doc = provider(&s).unwrap();
    let map = doc.as_object().unwrap();
    assert_eq!(map.len(), 1);
    let proxies = doc["proxies"].as_array().unwrap();
    assert_eq!(proxies.len(), 11);
    assert!(proxies.iter().all(|p| p["name"] != "onebox-AnyTLS-REALITY"));
    let text = to_yaml(&doc);
    assert!(text.starts_with("proxies:\n  - "), "{text}");
    assert_eq!(reader::parse(&text).unwrap(), doc);
}

#[test]
fn reality_proxies_advertise_mlkem_and_keep_transport_options() {
    let s = spec_with(&[
        (VlessReality, 1, XR),
        (VlessXhttp, 2, XR),
        (VlessGrpc, 3, SB),
    ]);
    let vision = proxy_of(&s, VlessReality);
    assert_eq!(vision["network"], "tcp");
    assert_eq!(vision["flow"], "xtls-rprx-vision");
    assert_eq!(vision["reality-opts"]["support-x25519mlkem768"], true);
    assert_eq!(vision["servername"], "www.microsoft.com");
    assert_eq!(
        proxy_of(&s, VlessXhttp)["xhttp-opts"],
        json!({"path": s.creds.xhttp_path, "mode": "auto"})
    );
    assert_eq!(
        proxy_of(&s, VlessGrpc)["grpc-opts"]["grpc-service-name"],
        json!(s.creds.grpc_service)
    );
}

#[test]
fn pinned_certificates_use_the_leaf_fingerprint() {
    let s = spec(&all_protocols());
    let pin = s
        .tls
        .as_ref()
        .unwrap()
        .pin()
        .unwrap()
        .unwrap()
        .leaf_pin()
        .to_owned();
    let table = [
        (VlessWs, "servername"),
        (Trojan, "sni"),
        (Hysteria2, "sni"),
        (Tuic, "sni"),
        (Anytls, "sni"),
    ];
    for (p, key) in table {
        let v = proxy_of(&s, p);
        assert_eq!(v[key], "www.bing.com", "{p}");
        assert_eq!(v["fingerprint"], json!(pin), "{p}");
        assert_eq!(v["skip-cert-verify"], true, "{p}");
    }
    let text = to_yaml(&config(&s).unwrap());
    assert!(!text.contains("PRIVATE KEY") && !text.contains(&s.reality().unwrap().private_key));
}

#[test]
fn plain_vmess_has_no_tls_options() {
    let mut cfg = node(&[(VmessWs, 8080, SB)]);
    let v = proxy_of(&spec(&cfg), VmessWs);
    assert_eq!(v["tls"], false);
    for key in [
        "alpn",
        "servername",
        "client-fingerprint",
        "fingerprint",
        "skip-cert-verify",
    ] {
        assert!(v.get(key).is_none(), "{key}");
    }
    assert!(v["ws-opts"].get("headers").is_none());
    cfg.vmess_host = Some("cdn.example.com".into());
    let v = proxy_of(&spec(&cfg), VmessWs);
    assert_eq!(v["ws-opts"]["headers"], json!({"Host": "cdn.example.com"}));
    assert_eq!(v["ws-opts"]["max-early-data"], 2048);
}

#[test]
fn hysteria2_tuning_hop_and_obfs_use_the_client_direction() {
    let mut cfg = node(&[(Hysteria2, 443, SB)]);
    cfg.hy2.obfs = true;
    cfg.hy2.hop = Some("25000-26000".parse().unwrap());
    cfg.hy2.profile = Some(Hy2Profile::Measured);
    cfg.hy2.up_mbps = Some(50);
    cfg.hy2.down_mbps = Some(300);
    cfg.resource_profile = ResourceProfile::LowMemory;
    let v = proxy_of(&spec(&cfg), Hysteria2);
    assert_eq!(
        (v["up"].clone(), v["down"].clone()),
        (json!(50), json!(300))
    );
    assert_eq!(v["ports"], "25000-26000");
    assert_eq!(v["hop-interval"], 30);
    assert_eq!(v["obfs"], "salamander");
    assert_eq!(v["initial-stream-receive-window"], 2_097_152);
    assert_eq!(v["max-connection-receive-window"], 5_242_880);
    assert!(v.get("udp").is_none() && v.get("client-fingerprint").is_none());
    cfg.hy2.profile = Some(Hy2Profile::Conservative);
    cfg.hy2.up_mbps = None;
    cfg.hy2.down_mbps = None;
    let v = proxy_of(&spec(&cfg), Hysteria2);
    assert_eq!(v["bbr-profile"], "conservative");
    assert!(v.get("up").is_none());
}

#[test]
fn shadowtls_uses_the_plugin_with_udp_over_tcp() {
    let s = spec_with(&[(Shadowtls, 443, SB)]);
    let v = proxy_of(&s, Shadowtls);
    assert_eq!(v["type"], "ss");
    assert_eq!(v["plugin"], "shadow-tls");
    assert_eq!(
        v["plugin-opts"],
        json!({"host": "www.microsoft.com", "password": s.creds.shadowtls_password, "version": 3})
    );
    assert_eq!(v["udp-over-tcp-version"], 2);
}

#[test]
fn full_config_keeps_controller_local_and_groups_complete() {
    let s = spec(&all_protocols());
    let doc = config(&s).unwrap();
    assert_eq!(doc["allow-lan"], false);
    assert_eq!(doc["mixed-port"], 7890);
    assert_eq!(doc["external-controller"], "127.0.0.1:9090");
    assert_eq!(doc["secret"], json!(s.creds.clash_secret));
    assert_ne!(doc["secret"], json!(s.creds.uuid));
    assert_eq!(
        doc["proxy-groups"][0]["proxies"].as_array().unwrap().len(),
        13
    );
    assert_eq!(
        doc["proxy-groups"][1]["proxies"].as_array().unwrap().len(),
        11
    );
    assert_eq!(doc["dns"]["listen"], "127.0.0.1:1053");
    assert_eq!(doc["rules"][0], "GEOSITE,private,DIRECT");
    assert_eq!(doc["geox-url"]["mmdb"], policy::MIHOMO_GEOX[2].1);
    let text = to_yaml(&doc);
    assert!(text.contains("  - name: \"节点选择\"\n"), "{text}");
    assert_eq!(reader::parse(&text).unwrap(), doc);
}

#[test]
fn own_endpoints_bypass_the_tunnel() {
    let mut cfg = with_site(node(&[(VlessReality, 443, XR)]), "site.example.com", true);
    cfg.subscription = Some(ip_subscription(8448));
    let doc = config(&spec(&cfg)).unwrap();
    assert_eq!(doc["rules"][0], "DOMAIN,site.example.com,DIRECT");
    assert_eq!(doc["rules"][1], "IP-CIDR,203.0.113.10/32,DIRECT,no-resolve");
    assert_eq!(doc["rules"][2], "GEOSITE,private,DIRECT");
    assert_eq!(
        doc["dns"]["nameserver-policy"]["site.example.com"],
        json!(policy::DOH_CN)
    );
    assert!(doc["dns"]["nameserver-policy"]
        .get("203.0.113.10")
        .is_none());
    assert_eq!(
        doc["dns"]["fake-ip-filter"]
            .as_array()
            .unwrap()
            .last()
            .unwrap(),
        "site.example.com"
    );
}

#[test]
fn anytls_reality_only_cannot_be_exported() {
    let s = spec_with(&[(AnytlsReality, 443, SB)]);
    for (err, id) in [
        (config(&s).unwrap_err(), "mihomo"),
        (provider(&s).unwrap_err(), "provider"),
    ] {
        let text = err.to_string();
        assert!(text.contains(id) && text.contains("singbox"), "{text}");
    }
    let err = proxy(&s, s.require(AnytlsReality).unwrap()).unwrap_err();
    assert_eq!(err.to_string(), "anytls-reality 不支持 mihomo");
}
