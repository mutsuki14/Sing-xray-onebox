//! Share formats are rendered directly from state; JSON is also valid YAML.
use super::{certificate_pin, direct_domains, hy2_windows, pinned, tls_name};
use crate::{
    context::Context,
    model::{Protocol, State},
    util::url_encode,
    Result,
};
use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine,
};
use serde_json::{json, Value};

fn required_pin(ctx: &Context, s: &State) -> Result<String> {
    certificate_pin(ctx, s)?
        .filter(|v| !v.is_empty())
        .ok_or_else(|| "固定证书的客户端配置缺少证书指纹".into())
}

fn uri_host(s: &State) -> Result<String> {
    let host = s.get("SERVER_ADDR");
    if host.is_empty()
        || host
            .chars()
            .any(|c| c.is_whitespace() || matches!(c, '/' | '?' | '#' | '@'))
    {
        return Err("服务器地址无效".into());
    }
    let host = host
        .strip_prefix('[')
        .and_then(|v| v.strip_suffix(']'))
        .unwrap_or(host);
    if host.contains(':') {
        let address = host.split('%').next().unwrap_or(host);
        address
            .parse::<std::net::Ipv6Addr>()
            .map_err(|_| "服务器 IPv6 地址无效")?;
        Ok(format!("[{}]", host.replace('%', "%25")))
    } else if host.contains(['[', ']']) {
        Err("服务器地址括号无效".into())
    } else {
        Ok(host.to_string())
    }
}

fn insecure_query(ctx: &Context, s: &State) -> Result<String> {
    if !pinned(s) {
        return Ok(String::new());
    }
    Ok(format!(
        "&allowInsecure=1&insecure=1&pcs={}",
        required_pin(ctx, s)?
    ))
}

/// URI families supported by common clients. AnyTLS-REALITY must use JSON.
pub(super) fn link(ctx: &Context, s: &State, p: Protocol) -> Result<String> {
    if !p.supports("link") {
        return Err(format!("{p} 不支持通用分享链接").into());
    }
    let host = uri_host(s)?;
    let port = s.port(p);
    if port == 0 {
        return Err("分享链接端口无效".into());
    }
    let name = url_encode(&s.node_name(p));
    let uuid = url_encode(s.get("UUID"));
    let password = url_encode(s.get("PASSWORD"));
    let sni = url_encode(tls_name(s));
    let reality = format!(
        "security=reality&sni={}&fp=chrome&pbk={}&sid={}",
        url_encode(s.get("REALITY_SNI")),
        url_encode(s.get("REALITY_PUBLIC_KEY")),
        url_encode(s.get("REALITY_SHORT_ID"))
    );
    let result = match p {
        Protocol::VlessReality => format!("vless://{uuid}@{host}:{port}?encryption=none&flow=xtls-rprx-vision&{reality}&type=tcp&headerType=none#{name}"),
        Protocol::VlessXhttp => format!("vless://{uuid}@{host}:{port}?encryption=none&{reality}&type=xhttp&path={}&mode=auto#{name}", url_encode(s.get("XHTTP_PATH"))),
        Protocol::VlessGrpc => format!("vless://{uuid}@{host}:{port}?encryption=none&{reality}&type=grpc&serviceName={}&mode=gun#{name}", url_encode(s.get("GRPC_SERVICE"))),
        Protocol::VlessWs => format!("vless://{uuid}@{host}:{port}?encryption=none&security=tls&sni={sni}&fp=chrome&alpn=http%2F1.1{}&type=ws&host={sni}&path={}#{name}", insecure_query(ctx, s)?, url_encode(s.get("WS_PATH"))),
        Protocol::VmessWs => {
            let tls = s.vmess_tls();
            let mut config = json!({
                "v":"2", "ps":s.node_name(p), "add":s.get("SERVER_ADDR"),
                "port":port.to_string(), "id":s.get("UUID"), "aid":"0", "scy":"auto",
                "net":"ws", "type":"none", "host":if tls {tls_name(s)} else {s.get("DOMAIN")},
                "path":s.get("VMESS_PATH"), "tls":if tls {"tls"} else {""},
                "sni":if tls {tls_name(s)} else {""}, "alpn":if tls {"http/1.1"} else {""},
                "fp":if tls {"chrome"} else {""}
            });
            if tls && pinned(s) {
                config["insecure"] = json!("1");
                config["pcs"] = json!(required_pin(ctx, s)?);
            }
            format!("vmess://{}", STANDARD.encode(serde_json::to_vec(&config)?))
        }
        Protocol::Trojan => format!("trojan://{password}@{host}:{port}?security=tls&sni={sni}&fp=chrome&alpn=h2%2Chttp%2F1.1{}&type=tcp&headerType=none#{name}", insecure_query(ctx, s)?),
        Protocol::Shadowsocks => {
            let auth = URL_SAFE_NO_PAD.encode(format!("{}:{}", s.get_or("SS_METHOD", "2022-blake3-aes-128-gcm"), s.get("SS_PASSWORD")));
            format!("ss://{auth}@{host}:{port}#{name}")
        }
        Protocol::Hysteria2 => {
            let mut query = format!("sni={sni}&alpn=h3");
            if pinned(s) { query.push_str(&format!("&insecure=1&pinSHA256={}", required_pin(ctx, s)?)); }
            if s.flag("HY2_OBFS") { query.push_str(&format!("&obfs=salamander&obfs-password={}", url_encode(s.get("HY2_OBFS_PASSWORD")))); }
            if !s.get("HY2_HOP").is_empty() { query.push_str(&format!("&mport={}", url_encode(s.get("HY2_HOP")))); }
            format!("hysteria2://{password}@{host}:{port}/?{query}#{name}")
        }
        Protocol::Tuic => {
            // TUIC's common URI has no portable certificate-pin field.
            let trust = if pinned(s) {"&allow_insecure=1&insecure=1"} else {""};
            format!("tuic://{uuid}:{password}@{host}:{port}?sni={sni}&alpn=h3&congestion_control=bbr&udp_relay_mode=native{trust}#{name}")
        }
        Protocol::Anytls => {
            let trust = if pinned(s) { format!("&insecure=1&hpkp={}", required_pin(ctx, s)?) } else { String::new() };
            format!("anytls://{password}@{host}:{port}/?sni={sni}{trust}#{name}")
        }
        Protocol::Shadowtls | Protocol::AnytlsReality => unreachable!("unsupported protocols were rejected"),
    };
    Ok(result)
}

fn reality(out: &mut Value, s: &State) {
    out["tls"] = json!(true);
    out["servername"] = json!(s.get("REALITY_SNI"));
    out["client-fingerprint"] = json!("chrome");
    out["reality-opts"] = json!({"public-key":s.get("REALITY_PUBLIC_KEY"), "short-id":s.get("REALITY_SHORT_ID"), "support-x25519mlkem768":true});
}

fn tls(ctx: &Context, out: &mut Value, s: &State, key: &str) -> Result<()> {
    out[key] = json!(tls_name(s));
    if pinned(s) {
        out["skip-cert-verify"] = json!(true);
        out["fingerprint"] = json!(required_pin(ctx, s)?);
    }
    Ok(())
}

fn websocket(path: &str, host: &str) -> Value {
    let mut out = json!({"path":path, "max-early-data":2048, "early-data-header-name":"Sec-WebSocket-Protocol"});
    if !host.is_empty() {
        out["headers"] = json!({"Host":host});
    }
    out
}

fn bandwidth(s: &State, key: &str) -> Result<u64> {
    s.get(key)
        .parse::<u64>()
        .ok()
        .filter(|n| (1..=10000).contains(n))
        .ok_or_else(|| format!("{key} 必须为 1..10000 的整数 Mbps").into())
}

fn proxy(ctx: &Context, s: &State, p: Protocol) -> Result<Value> {
    if !p.supports("mihomo") {
        return Err(format!("{p} 不支持 mihomo").into());
    }
    let mut out = json!({"name":s.node_name(p), "server":s.get("SERVER_ADDR"), "port":s.port(p)});
    match p {
        Protocol::VlessReality | Protocol::VlessXhttp | Protocol::VlessGrpc | Protocol::VlessWs => {
            out["type"] = json!("vless");
            out["uuid"] = json!(s.get("UUID"));
            out["udp"] = json!(true);
            match p {
                Protocol::VlessReality => {
                    out["network"] = json!("tcp");
                    out["flow"] = json!("xtls-rprx-vision");
                    reality(&mut out, s);
                }
                Protocol::VlessXhttp => {
                    out["network"] = json!("xhttp");
                    reality(&mut out, s);
                    out["xhttp-opts"] = json!({"path":s.get("XHTTP_PATH"), "mode":"auto"});
                }
                Protocol::VlessGrpc => {
                    out["network"] = json!("grpc");
                    reality(&mut out, s);
                    out["grpc-opts"] = json!({"grpc-service-name":s.get("GRPC_SERVICE")});
                }
                Protocol::VlessWs => {
                    out["network"] = json!("ws");
                    out["tls"] = json!(true);
                    out["client-fingerprint"] = json!("chrome");
                    out["alpn"] = json!(["http/1.1"]);
                    tls(ctx, &mut out, s, "servername")?;
                    out["ws-opts"] = websocket(s.get("WS_PATH"), tls_name(s));
                }
                _ => unreachable!(),
            }
        }
        Protocol::VmessWs => {
            out["type"] = json!("vmess");
            out["uuid"] = json!(s.get("UUID"));
            out["alterId"] = json!(0);
            out["cipher"] = json!("auto");
            out["network"] = json!("ws");
            out["udp"] = json!(true);
            out["tls"] = json!(s.vmess_tls());
            if s.vmess_tls() {
                out["client-fingerprint"] = json!("chrome");
                out["alpn"] = json!(["http/1.1"]);
                tls(ctx, &mut out, s, "servername")?;
            }
            out["ws-opts"] = websocket(
                s.get("VMESS_PATH"),
                if s.vmess_tls() {
                    tls_name(s)
                } else {
                    s.get("DOMAIN")
                },
            );
        }
        Protocol::Trojan | Protocol::Anytls => {
            out["type"] = json!(p.as_str());
            out["password"] = json!(s.get("PASSWORD"));
            out["udp"] = json!(true);
            out["client-fingerprint"] = json!("chrome");
            if p == Protocol::Trojan {
                out["alpn"] = json!(["h2", "http/1.1"]);
            }
            tls(ctx, &mut out, s, "sni")?;
        }
        Protocol::Shadowsocks => {
            out["type"] = json!("ss");
            out["cipher"] = json!(s.get_or("SS_METHOD", "2022-blake3-aes-128-gcm"));
            out["password"] = json!(s.get("SS_PASSWORD"));
            out["udp"] = json!(true);
        }
        Protocol::Hysteria2 => {
            out["type"] = json!("hysteria2");
            out["password"] = json!(s.get("PASSWORD"));
            out["alpn"] = json!(["h3"]);
            if !s.get("HY2_HOP").is_empty() {
                out["ports"] = json!(s.get("HY2_HOP"));
                out["hop-interval"] = json!(30);
            }
            if s.flag("HY2_OBFS") {
                out["obfs"] = json!("salamander");
                out["obfs-password"] = json!(s.get("HY2_OBFS_PASSWORD"));
            }
            match s.get("HY2_PROFILE") {
                "conservative" => out["bbr-profile"] = json!("conservative"),
                "measured" => {
                    out["up"] = json!(bandwidth(s, "HY2_UP_MBPS")?);
                    out["down"] = json!(bandwidth(s, "HY2_DOWN_MBPS")?);
                }
                "" | "auto" => {}
                _ => return Err("未知 Hysteria2 调优配置".into()),
            }
            if let Some((stream, connection, _)) = hy2_windows(s) {
                out["initial-stream-receive-window"] = json!(stream);
                out["max-stream-receive-window"] = json!(stream);
                out["initial-connection-receive-window"] = json!(connection);
                out["max-connection-receive-window"] = json!(connection);
            }
            tls(ctx, &mut out, s, "sni")?;
        }
        Protocol::Tuic => {
            out["type"] = json!("tuic");
            out["uuid"] = json!(s.get("UUID"));
            out["password"] = json!(s.get("PASSWORD"));
            out["alpn"] = json!(["h3"]);
            out["congestion-controller"] = json!("bbr");
            out["udp-relay-mode"] = json!("native");
            tls(ctx, &mut out, s, "sni")?;
        }
        Protocol::Shadowtls => {
            out["type"] = json!("ss");
            out["cipher"] = json!("2022-blake3-aes-128-gcm");
            out["password"] = json!(s.get("SHADOWTLS_SS_PASSWORD"));
            out["udp"] = json!(true);
            out["udp-over-tcp"] = json!(true);
            out["udp-over-tcp-version"] = json!(2);
            out["client-fingerprint"] = json!("chrome");
            out["plugin"] = json!("shadow-tls");
            out["plugin-opts"] = json!({"host":s.get("SHADOWTLS_SNI"), "password":s.get("SHADOWTLS_PASSWORD"), "version":3});
        }
        Protocol::AnytlsReality => unreachable!("unsupported protocols were rejected"),
    }
    Ok(out)
}

pub(super) fn mihomo(ctx: &Context, s: &State, provider: bool) -> Result<String> {
    let protocols: Vec<_> = s
        .protocols()
        .into_iter()
        .filter(|p| p.supports("mihomo"))
        .collect();
    if protocols.is_empty() {
        return Err("没有可导出到 mihomo 的协议；AnyTLS-REALITY 需要 sing-box JSON".into());
    }
    let proxies = protocols
        .iter()
        .map(|p| proxy(ctx, s, *p))
        .collect::<Result<Vec<_>>>()?;
    let mut document = json!({"proxies":proxies});
    if !provider {
        let names: Vec<_> = protocols.iter().map(|p| s.node_name(*p)).collect();
        let mut choices = vec!["自动选择".to_owned()];
        choices.extend(names.clone());
        choices.push("DIRECT".to_owned());
        document = json!({
            "mixed-port":7890, "allow-lan":false, "mode":"rule", "log-level":"info", "ipv6":true,
            "unified-delay":true, "tcp-concurrent":true,
            "profile":{"store-selected":true, "store-fake-ip":true},
            "geodata-mode":true, "geo-auto-update":true, "geo-update-interval":24,
            "geox-url":{
                "geoip":"https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/geoip.dat",
                "geosite":"https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/geosite.dat",
                "mmdb":"https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/country.mmdb",
                "asn":"https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/GeoLite2-ASN.mmdb"
            },
            "sniffer":{"enable":true, "sniff":{"HTTP":{"ports":[80,"8080-8880"], "override-destination":true},
                "TLS":{"ports":[443,8443]}, "QUIC":{"ports":[443,8443]}}, "skip-domain":["Mijia Cloud","+.push.apple.com"]},
            "tun":{"enable":false, "stack":"mixed", "auto-route":true, "auto-detect-interface":true, "dns-hijack":["any:53"]},
            "dns":{
                "enable":true, "ipv6":true, "listen":"127.0.0.1:1053", "enhanced-mode":"fake-ip", "fake-ip-range":"198.18.0.1/16",
                "fake-ip-filter":["geosite:private","geosite:connectivity-check","+.lan","+.local","+.home.arpa","time.*.com","ntp.*.com","+.pool.ntp.org","+.stun.*.*","+.stun.*.*.*","+.srv.nintendo.net","+.stun.playstation.net","xbox.*.microsoft.com","+.xboxlive.com"],
                "default-nameserver":["223.5.5.5","119.29.29.29"],
                "nameserver":["https://dns.alidns.com/dns-query","https://doh.pub/dns-query"],
                "proxy-server-nameserver":["https://dns.alidns.com/dns-query","https://doh.pub/dns-query"],
                "nameserver-policy":{"geosite:cn":["https://dns.alidns.com/dns-query","https://doh.pub/dns-query"],
                    "geosite:geolocation-!cn":["https://dns.cloudflare.com/dns-query#节点选择","https://dns.google/dns-query#节点选择"]}
            },
            "proxies":proxies,
            "proxy-groups":[{"name":"节点选择", "type":"select", "proxies":choices},
                {"name":"自动选择", "type":"url-test", "url":"https://www.gstatic.com/generate_204", "interval":300, "tolerance":50, "proxies":names}],
            "rules":["GEOSITE,private,DIRECT","GEOIP,private,DIRECT,no-resolve","GEOSITE,category-ads-all,REJECT","GEOSITE,cn,DIRECT","GEOSITE,geolocation-!cn,节点选择","GEOIP,CN,DIRECT","MATCH,节点选择"]
        });
        // Never expose an unauthenticated controller when importing incomplete legacy state.
        if !s.get("CLASH_SECRET").is_empty() {
            document["external-controller"] = json!("127.0.0.1:9090");
            document["secret"] = json!(s.get("CLASH_SECRET"));
        }
        let domains = direct_domains(s);
        let mut rules: Vec<Value> = domains
            .iter()
            .map(|domain| json!(format!("DOMAIN,{domain},DIRECT")))
            .collect();
        rules.extend(document["rules"].as_array().unwrap().iter().cloned());
        document["rules"] = json!(rules);
        for domain in domains {
            document["dns"]["nameserver-policy"][&domain] = json!([
                "https://dns.alidns.com/dns-query",
                "https://doh.pub/dns-query"
            ]);
            document["dns"]["fake-ip-filter"]
                .as_array_mut()
                .unwrap()
                .push(json!(domain));
        }
    }
    Ok(format!("{}\n", serde_json::to_string_pretty(&document)?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::PROTOCOLS;

    fn state() -> State {
        let mut s = State::default();
        for (key, value) in [
            ("PROTOCOLS", "vless-reality vless-xhttp vless-grpc vless-ws vmess-ws trojan shadowsocks hysteria2 tuic anytls shadowtls anytls-reality"),
            ("SERVER_ADDR", "2001:db8::42"), ("NODE_NAME", "节点's #1"),
            ("UUID", "11111111-2222-4333-8444-555555555555"), ("PASSWORD", "pass:@#&?/中文"),
            ("TLS_MODE", "acme"), ("DOMAIN", "proxy.example.com"), ("TLS_SNI", "fallback.example.com"),
            ("REALITY_SNI", "reality.example.com"), ("REALITY_PUBLIC_KEY", "Abc-DEF_ghi"), ("REALITY_SHORT_ID", "0123"),
            ("SS_METHOD", "2022-blake3-aes-128-gcm"), ("SS_PASSWORD", "base64+/=="),
            ("SHADOWTLS_SS_PASSWORD", "otherbase64+/=="), ("SHADOWTLS_PASSWORD", "shadow:@&"), ("SHADOWTLS_SNI", "www.example.org"),
            ("WS_PATH", "/ws?foo=bar&ed=2048"), ("VMESS_PATH", "/vmess'\\\""), ("XHTTP_PATH", "/x?key=1&more=2"),
            ("GRPC_SERVICE", "service/name?tag=1"), ("CLASH_SECRET", "secret&quote'\""), ("VMESS_TLS", "1")
        ] { s.set(key, value); }
        for (i, p) in PROTOCOLS.iter().enumerate() {
            s.set_port(*p, 24000 + i as u16);
        }
        s
    }

    #[test]
    fn uri_support_and_escaping() {
        let s = state();
        let ctx = Context::default();
        for p in PROTOCOLS {
            let result = link(&ctx, &s, p);
            assert_eq!(result.is_ok(), p.supports("link"), "{p}");
            if let Ok(uri) = result {
                if p != Protocol::VmessWs {
                    assert!(uri.contains("@[2001:db8::42]:"), "{p}: {uri}");
                    assert!(uri.ends_with(&url_encode(&s.node_name(p))), "{p}");
                    assert!(!uri.contains("中文"), "{p}");
                }
            }
        }
        let trojan = link(&ctx, &s, Protocol::Trojan).unwrap();
        assert!(trojan.starts_with("trojan://pass%3A%40%23%26%3F%2F%E4%B8%AD%E6%96%87@"));
        assert!(link(&ctx, &s, Protocol::VlessWs)
            .unwrap()
            .contains("path=%2Fws%3Ffoo%3Dbar%26ed%3D2048"));
        assert!(link(&ctx, &s, Protocol::VlessXhttp)
            .unwrap()
            .contains("&mode=auto#"));
        assert!(link(&ctx, &s, Protocol::VlessGrpc)
            .unwrap()
            .contains("serviceName=service%2Fname%3Ftag%3D1"));
    }

    #[test]
    fn base64_links_preserve_exact_credentials() {
        let s = state();
        let ctx = Context::default();
        let vmess = link(&ctx, &s, Protocol::VmessWs).unwrap();
        let decoded: Value = serde_json::from_slice(
            &STANDARD
                .decode(vmess.strip_prefix("vmess://").unwrap())
                .unwrap(),
        )
        .unwrap();
        assert_eq!(decoded["port"], "24004");
        assert_eq!(decoded["aid"], "0");
        assert_eq!(decoded["ps"], s.node_name(Protocol::VmessWs));
        assert_eq!(decoded["path"], s.get("VMESS_PATH"));
        assert_eq!(decoded["sni"], s.get("DOMAIN"));
        assert_eq!(decoded["alpn"], "http/1.1");
        let ss = link(&ctx, &s, Protocol::Shadowsocks).unwrap();
        let auth = ss.strip_prefix("ss://").unwrap().split('@').next().unwrap();
        assert!(!auth.contains(['+', '/', '=']));
        assert_eq!(
            String::from_utf8(URL_SAFE_NO_PAD.decode(auth).unwrap()).unwrap(),
            "2022-blake3-aes-128-gcm:base64+/=="
        );
    }

    #[test]
    fn provider_filters_anytls_reality_and_preserves_nested_fields() {
        let s = state();
        let ctx = Context::default();
        let doc: Value = serde_json::from_str(&mihomo(&ctx, &s, true).unwrap()).unwrap();
        assert_eq!(doc.as_object().unwrap().len(), 1);
        let proxies = doc["proxies"].as_array().unwrap();
        assert_eq!(proxies.len(), 11);
        assert!(!proxies
            .iter()
            .any(|p| p["name"] == s.node_name(Protocol::AnytlsReality)));
        assert_eq!(proxies[0]["reality-opts"]["support-x25519mlkem768"], true);
        assert_eq!(proxies[1]["xhttp-opts"]["path"], s.get("XHTTP_PATH"));
        assert_eq!(proxies[1]["xhttp-opts"]["mode"], "auto");
        assert_eq!(
            proxies[2]["grpc-opts"]["grpc-service-name"],
            s.get("GRPC_SERVICE")
        );
        assert_eq!(proxies[3]["ws-opts"]["max-early-data"], 2048);
        assert_eq!(proxies[3]["ws-opts"]["headers"]["Host"], s.get("DOMAIN"));
        assert_eq!(proxies[5]["password"], s.get("PASSWORD"));
        assert_eq!(
            proxies[10]["plugin-opts"]["password"],
            s.get("SHADOWTLS_PASSWORD")
        );
        assert_eq!(proxies[10]["udp-over-tcp-version"], 2);
    }

    #[test]
    fn vmess_plaintext_has_no_tls_options() {
        let mut s = state();
        s.set("VMESS_TLS", "0");
        s.set("TLS_MODE", "self");
        s.set("DOMAIN", "");
        let ctx = Context::default();
        let out = proxy(&ctx, &s, Protocol::VmessWs).unwrap();
        assert_eq!(out["tls"], false);
        for key in [
            "alpn",
            "servername",
            "client-fingerprint",
            "fingerprint",
            "skip-cert-verify",
        ] {
            assert!(out.get(key).is_none());
        }
        assert!(out["ws-opts"].get("headers").is_none());
        let link = link(&ctx, &s, Protocol::VmessWs).unwrap();
        let decoded: Value = serde_json::from_slice(
            &STANDARD
                .decode(link.strip_prefix("vmess://").unwrap())
                .unwrap(),
        )
        .unwrap();
        assert_eq!(decoded["tls"], "");
        assert_eq!(decoded["alpn"], "");
        assert!(decoded.get("pcs").is_none());
    }

    #[test]
    fn hysteria_tuning_and_hopping_use_client_direction() {
        let mut s = state();
        let ctx = Context::default();
        s.set("HY2_PROFILE", "measured");
        s.set("HY2_UP_MBPS", "50");
        s.set("HY2_DOWN_MBPS", "300");
        s.set("RESOURCE_PROFILE", "low-memory");
        s.set("HY2_OBFS", "1");
        s.set("HY2_OBFS_PASSWORD", "obfs&+password");
        s.set("HY2_HOP", "25000-26000");
        let out = proxy(&ctx, &s, Protocol::Hysteria2).unwrap();
        assert_eq!(out["up"], 50);
        assert_eq!(out["down"], 300);
        assert_eq!(out["initial-stream-receive-window"], 2097152);
        assert_eq!(out["max-connection-receive-window"], 5242880);
        assert_eq!(out["ports"], "25000-26000");
        assert_eq!(out["hop-interval"], 30);
        assert_eq!(out["obfs-password"], "obfs&+password");
        let uri = link(&ctx, &s, Protocol::Hysteria2).unwrap();
        assert!(uri.contains("obfs-password=obfs%26%2Bpassword"));
        assert!(uri.contains("mport=25000-26000"));
        s.set("HY2_PROFILE", "conservative");
        let out = proxy(&ctx, &s, Protocol::Hysteria2).unwrap();
        assert_eq!(out["bbr-profile"], "conservative");
        assert!(out.get("up").is_none());
        s.set("HY2_PROFILE", "measured");
        s.set("HY2_UP_MBPS", "0");
        assert!(proxy(&ctx, &s, Protocol::Hysteria2).is_err());
    }

    #[test]
    fn full_config_keeps_controller_local_and_secret_independent_of_uuid() {
        let mut s = state();
        let ctx = Context::default();
        let out: Value = serde_json::from_str(&mihomo(&ctx, &s, false).unwrap()).unwrap();
        assert_eq!(out["allow-lan"], false);
        assert_eq!(out["external-controller"], "127.0.0.1:9090");
        assert_eq!(out["secret"], s.get("CLASH_SECRET"));
        assert_ne!(out["secret"], s.get("UUID"));
        assert_eq!(
            out["proxy-groups"][0]["proxies"].as_array().unwrap().len(),
            13
        );
        assert_eq!(
            out["proxy-groups"][1]["proxies"].as_array().unwrap().len(),
            11
        );
        assert_eq!(out["dns"]["listen"], "127.0.0.1:1053");
        s.set("CLASH_SECRET", "");
        let out: Value = serde_json::from_str(&mihomo(&ctx, &s, false).unwrap()).unwrap();
        assert!(out.get("external-controller").is_none());
        assert!(out.get("secret").is_none());
        s.set("PROTOCOLS", "anytls-reality");
        assert!(mihomo(&ctx, &s, false).is_err());
        assert!(mihomo(&ctx, &s, true).is_err());
    }

    #[test]
    fn pinned_certificates_are_carried_by_supported_formats() {
        use crate::{context::Paths, util};
        let root =
            std::env::temp_dir().join(format!("onebox-share-pin-{}", util::random_hex(8).unwrap()));
        let ctx = Context {
            paths: Paths::isolated(&root),
            ..Context::default()
        };
        let mut s = state();
        s.set("TLS_MODE", "custom");
        s.set("CERT_PINNED", "1");
        let der = [0x30_u8, 3, 2, 1, 1];
        let pin = util::sha256(&der);
        std::fs::create_dir_all(ctx.paths.tls()).unwrap();
        std::fs::write(ctx.paths.tls().join("cert.pem"), "-----BEGIN CERTIFICATE-----\nMAMCAQE=\n-----END CERTIFICATE-----\n-----BEGIN PRIVATE KEY-----\nnot-a-client-secret\n-----END PRIVATE KEY-----\n").unwrap();
        for p in [
            Protocol::VlessWs,
            Protocol::VmessWs,
            Protocol::Trojan,
            Protocol::Hysteria2,
            Protocol::Tuic,
            Protocol::Anytls,
        ] {
            let out = proxy(&ctx, &s, p).unwrap();
            assert_eq!(out["fingerprint"], pin, "{p}");
            assert_eq!(out["skip-cert-verify"], true, "{p}");
            assert!(!out.to_string().contains("not-a-client-secret"));
        }
        for (p, parameter) in [
            (Protocol::VlessWs, "pcs"),
            (Protocol::Trojan, "pcs"),
            (Protocol::Hysteria2, "pinSHA256"),
            (Protocol::Anytls, "hpkp"),
        ] {
            let uri = link(&ctx, &s, p).unwrap();
            assert!(uri.contains(&format!("&{parameter}={pin}")), "{p}");
        }
        let uri = link(&ctx, &s, Protocol::VmessWs).unwrap();
        let vmess: Value = serde_json::from_slice(
            &STANDARD
                .decode(uri.strip_prefix("vmess://").unwrap())
                .unwrap(),
        )
        .unwrap();
        assert_eq!(vmess["pcs"], pin);
        assert_eq!(vmess["insecure"], "1");
        std::fs::remove_file(ctx.paths.tls().join("cert.pem")).unwrap();
        assert!(proxy(&ctx, &s, Protocol::Trojan).is_err());
        assert!(link(&ctx, &s, Protocol::Trojan).is_err());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn own_site_and_subscription_domains_do_not_need_the_tunnel() {
        let mut s = state();
        let ctx = Context::default();
        s.set("SUBSCRIPTION_DOMAIN", "subscribe.example.com");
        s.set("REALITY_SITE_DOMAIN", "site.example.com");
        let document: Value = serde_json::from_str(&mihomo(&ctx, &s, false).unwrap()).unwrap();
        let rules = document["rules"].as_array().unwrap();
        for domain in ["subscribe.example.com", "site.example.com"] {
            let rule = json!(format!("DOMAIN,{domain},DIRECT"));
            assert!(rules[..2].contains(&rule));
            assert_eq!(
                document["dns"]["nameserver-policy"][domain],
                json!([
                    "https://dns.alidns.com/dns-query",
                    "https://doh.pub/dns-query"
                ])
            );
            assert!(document["dns"]["fake-ip-filter"]
                .as_array()
                .unwrap()
                .contains(&json!(domain)));
        }
        let provider: Value = serde_json::from_str(&mihomo(&ctx, &s, true).unwrap()).unwrap();
        assert_eq!(provider.as_object().unwrap().len(), 1);
        s.set("SUBSCRIPTION_DOMAIN", "invalid,REJECT");
        s.set("REALITY_SITE_DOMAIN", "invalid-domain");
        let document: Value = serde_json::from_str(&mihomo(&ctx, &s, false).unwrap()).unwrap();
        assert_eq!(document["rules"][0], "GEOSITE,private,DIRECT");
    }

    #[test]
    fn host_brackets_and_invalid_addresses() {
        let mut s = state();
        s.set("SERVER_ADDR", "[2001:db8::1]");
        assert_eq!(uri_host(&s).unwrap(), "[2001:db8::1]");
        s.set("SERVER_ADDR", "fe80::1%eth0");
        assert_eq!(uri_host(&s).unwrap(), "[fe80::1%25eth0]");
        for host in [
            "",
            "host.example/x",
            "host.example#fragment",
            "user@host.example",
            "host example",
            "host.example:443",
            "[host.example",
        ] {
            s.set("SERVER_ADDR", host);
            assert!(uri_host(&s).is_err(), "{host}");
        }
    }
}
