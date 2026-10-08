//! Native, deterministic proxy configuration rendering. No shell templates are
//! evaluated; credential strings are always serialized by serde_json.
use crate::{
    context::Context,
    model::{Core, Protocol, State},
    util, Result,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use serde_json::{json, Value};
use std::{
    collections::BTreeSet,
    fs,
    net::IpAddr,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};

mod share;

const PRIVATE_CIDRS: &[&str] = &[
    "0.0.0.0/8",
    "10.0.0.0/8",
    "100.64.0.0/10",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "172.16.0.0/12",
    "192.0.0.0/24",
    "192.0.2.0/24",
    "192.88.99.0/24",
    "192.168.0.0/16",
    "198.18.0.0/15",
    "198.51.100.0/24",
    "203.0.113.0/24",
    "224.0.0.0/3",
    "::/127",
    "fc00::/7",
    "fe80::/10",
    "ff00::/8",
];

pub(super) fn tls_name(s: &State) -> &str {
    if matches!(s.get("TLS_MODE"), "acme" | "custom") {
        s.get_or("DOMAIN", s.get("TLS_SNI"))
    } else {
        s.get("TLS_SNI")
    }
}
pub(super) fn pinned(s: &State) -> bool {
    s.get("TLS_MODE") == "self" || s.flag("CERT_PINNED")
}
fn cert_path(ctx: &Context, s: &State) -> PathBuf {
    if s.get("CERT_FILE").is_empty() {
        ctx.paths.tls().join("cert.pem")
    } else {
        s.get("CERT_FILE").into()
    }
}
fn key_path(ctx: &Context, s: &State) -> PathBuf {
    if s.get("KEY_FILE").is_empty() {
        ctx.paths.tls().join("key.pem")
    } else {
        s.get("KEY_FILE").into()
    }
}

/// Extract certificates only: a mistakenly concatenated private key must never
/// appear in a client configuration. Each block is checked as base64 DER.
fn certificates(ctx: &Context, s: &State) -> Result<Vec<(String, Vec<u8>)>> {
    let pem = fs::read_to_string(cert_path(ctx, s))?;
    let mut result = Vec::new();
    let begin = "-----BEGIN CERTIFICATE-----";
    let end = "-----END CERTIFICATE-----";
    let mut remaining = pem.as_str();
    while let Some(start) = remaining.find(begin) {
        remaining = &remaining[start + begin.len()..];
        let finish = remaining.find(end).ok_or("TLS 证书 PEM 缺少结束标记")?;
        let encoded: String = remaining[..finish]
            .chars()
            .filter(|c| !c.is_ascii_whitespace())
            .collect();
        let der = STANDARD.decode(&encoded)?;
        if der.is_empty() || der[0] != 0x30 {
            return Err("TLS 证书不是有效 DER 序列".into());
        }
        result.push((
            format!(
                "{begin}\n{}\n{end}\n",
                encoded
                    .as_bytes()
                    .chunks(64)
                    .map(|chunk| std::str::from_utf8(chunk).unwrap_or(""))
                    .collect::<Vec<_>>()
                    .join("\n")
            ),
            der,
        ));
        remaining = &remaining[finish + end.len()..];
    }
    if result.is_empty() {
        return Err("TLS 证书文件未包含 CERTIFICATE，拒绝导出未验证配置".into());
    }
    Ok(result)
}
pub(super) fn certificate_pin(ctx: &Context, s: &State) -> Result<Option<String>> {
    if !pinned(s) {
        return Ok(None);
    }
    let certs = certificates(ctx, s)?;
    Ok(Some(util::sha256(&certs[0].1)))
}
pub(super) fn hy2_congestion(s: &State) -> Option<&str> {
    if s.get("HY2_PROFILE") == "conservative" {
        Some("conservative")
    } else {
        None
    }
}
pub(super) fn hy2_windows(s: &State) -> Option<(u64, u64, u64)> {
    match s.get("RESOURCE_PROFILE") {
        "low-memory" => Some((2_097_152, 5_242_880, 64)),
        "throughput" => Some((16_777_216, 41_943_040, 1024)),
        _ => None,
    }
}
fn apply_hy2(v: &mut Value, s: &State, server: bool) -> Result<()> {
    match s.get("HY2_PROFILE") {
        "auto" | "conservative" => {
            if server {
                v["ignore_client_bandwidth"] = json!(true);
            }
            if let Some(profile) = hy2_congestion(s) {
                v["bbr_profile"] = json!(profile);
            }
        }
        "measured" => {
            let up = bandwidth(s, "HY2_UP_MBPS")?;
            let down = bandwidth(s, "HY2_DOWN_MBPS")?;
            v["up_mbps"] = json!(if server { down } else { up });
            v["down_mbps"] = json!(if server { up } else { down });
        }
        "" => (),
        _ => return Err("未知 Hysteria2 调优配置".into()),
    }
    if let Some((stream, connection, concurrent)) = hy2_windows(s) {
        v["stream_receive_window"] = json!(stream);
        v["connection_receive_window"] = json!(connection);
        if server {
            v["max_concurrent_streams"] = json!(concurrent);
        }
    }
    Ok(())
}
fn bandwidth(s: &State, key: &str) -> Result<u64> {
    let n = s.get(key).parse::<u64>()?;
    if !(1..=10_000).contains(&n) {
        return Err(format!("{key} 必须为 1..10000 Mbps").into());
    }
    Ok(n)
}
fn endpoint(raw: &str) -> Result<(String, u16)> {
    let (host, port) = raw.rsplit_once(':').ok_or("REALITY 握手目标必须含端口")?;
    let host = host.trim_start_matches('[').trim_end_matches(']');
    let port: u16 = port.parse()?;
    if host.is_empty() || port == 0 {
        return Err("握手目标地址或端口无效".into());
    }
    Ok((host.to_owned(), port))
}
fn sb_reality_server(s: &State) -> Result<Value> {
    let (host, port) = endpoint(s.get("REALITY_DEST"))?;
    Ok(
        json!({"enabled":true,"server_name":s.get("REALITY_SNI"),"reality":{
        "enabled":true,"handshake":{"server":host,"server_port":port},
        "private_key":s.get("REALITY_PRIVATE_KEY"),"short_id":[s.get("REALITY_SHORT_ID")]}}),
    )
}
fn sb_reality_client(s: &State) -> Value {
    json!({"enabled":true,"server_name":s.get("REALITY_SNI"),"utls":{"enabled":true,"fingerprint":"chrome"},
        "reality":{"enabled":true,"public_key":s.get("REALITY_PUBLIC_KEY"),"short_id":s.get("REALITY_SHORT_ID")}})
}
fn sb_cert_server(ctx: &Context, s: &State, alpn: &[&str]) -> Result<Value> {
    let mut v = json!({"enabled":true,"server_name":tls_name(s),
        "certificate_path":util::path_str(&cert_path(ctx,s))?,"key_path":util::path_str(&key_path(ctx,s))?});
    if !alpn.is_empty() {
        v["alpn"] = json!(alpn);
    }
    Ok(v)
}
fn sb_cert_client(ctx: &Context, s: &State, alpn: &[&str], utls: bool) -> Result<Value> {
    let mut v = json!({"enabled":true,"server_name":tls_name(s)});
    if pinned(s) {
        v["certificate"] = json!(certificates(ctx, s)?
            .into_iter()
            .map(|(pem, _)| pem)
            .collect::<Vec<_>>());
    }
    if !alpn.is_empty() {
        v["alpn"] = json!(alpn);
    }
    if utls {
        v["utls"] = json!({"enabled":true,"fingerprint":"chrome"});
    }
    Ok(v)
}

/// A protocol's primary listener. ShadowTLS additionally needs its internal SS
/// listener; `server` adds it without exposing another public socket.
pub fn inbound(ctx: &Context, s: &State, p: Protocol) -> Result<Value> {
    if !p.cores().contains(&s.core(p)) {
        return Err(format!("{p} 不支持 {} 服务端", s.core(p)).into());
    }
    match s.core(p) {
        Core::Singbox => sb_inbound(ctx, s, p),
        Core::Xray => xr_inbound(ctx, s, p),
    }
}
fn sb_inbound(ctx: &Context, s: &State, p: Protocol) -> Result<Value> {
    use Protocol::*;
    if !p.cores().contains(&Core::Singbox) {
        return Err("sing-box 不支持该入站".into());
    }
    let mut v = json!({"tag":format!("{p}-in"),"listen":s.get_or("LISTEN_ADDR","::"),"listen_port":s.port(p)});
    match p {
        VlessReality | VlessGrpc | VlessWs => {
            v["type"] = json!("vless");
            v["users"] = json!([{"name":"onebox","uuid":s.get("UUID")}]);
            if p == VlessReality {
                v["users"][0]["flow"] = json!("xtls-rprx-vision");
            }
            v["tls"] = if p.reality() {
                sb_reality_server(s)?
            } else {
                sb_cert_server(ctx, s, &["http/1.1"])?
            };
            if p == VlessGrpc {
                v["transport"] = json!({"type":"grpc","service_name":s.get("GRPC_SERVICE")});
            }
            if p == VlessWs {
                v["transport"] = ws_transport(s.get("WS_PATH"), None);
            }
        }
        VmessWs => {
            v["type"] = json!("vmess");
            v["users"] = json!([{"name":"onebox","uuid":s.get("UUID"),"alterId":0}]);
            if s.vmess_tls() {
                v["tls"] = sb_cert_server(ctx, s, &["http/1.1"])?;
            }
            v["transport"] = ws_transport(s.get("VMESS_PATH"), None);
        }
        Trojan | Hysteria2 | Tuic | Anytls | AnytlsReality => {
            v["type"] = json!(match p {
                Trojan => "trojan",
                Hysteria2 => "hysteria2",
                Tuic => "tuic",
                _ => "anytls",
            });
            v["users"] = json!([{"name":"onebox","password":s.get("PASSWORD")}]);
            v["tls"] = if p == AnytlsReality {
                sb_reality_server(s)?
            } else {
                sb_cert_server(
                    ctx,
                    s,
                    match p {
                        Trojan => &["h2", "http/1.1"],
                        Hysteria2 | Tuic => &["h3"],
                        _ => &[],
                    },
                )?
            };
            if p == Tuic {
                v["users"][0]["uuid"] = json!(s.get("UUID"));
                v["congestion_control"] = json!("bbr");
            }
            if p == Hysteria2 {
                if s.flag("HY2_OBFS") {
                    v["obfs"] = json!({"type":"salamander","password":s.get("HY2_OBFS_PASSWORD")});
                } else {
                    v["masquerade"] =
                        json!({"type":"proxy","url":"https://www.bing.com","rewrite_host":true});
                }
                apply_hy2(&mut v, s, true)?;
            }
        }
        Shadowsocks => {
            v["type"] = json!("shadowsocks");
            v["method"] = json!(s.get_or("SS_METHOD", "2022-blake3-aes-128-gcm"));
            v["password"] = json!(s.get("SS_PASSWORD"));
        }
        Shadowtls => {
            let dest = if s.get("SHADOWTLS_DEST").is_empty() {
                format!("{}:443", s.get("SHADOWTLS_SNI"))
            } else {
                s.get("SHADOWTLS_DEST").to_owned()
            };
            let (host, port) = endpoint(&dest)?;
            v["type"] = json!("shadowtls");
            v["version"] = json!(3);
            v["users"] = json!([{"name":"onebox","password":s.get("SHADOWTLS_PASSWORD")}]);
            v["handshake"] = json!({"server":host,"server_port":port});
            v["strict_mode"] = json!(true);
            v["detour"] = json!("shadowtls-ss-in");
        }
        VlessXhttp => unreachable!(),
    }
    Ok(v)
}
fn ws_transport(path: &str, host: Option<&str>) -> Value {
    let mut v = json!({"type":"ws","path":path,"max_early_data":2048,"early_data_header_name":"Sec-WebSocket-Protocol"});
    if let Some(host) = host.filter(|h| !h.is_empty()) {
        v["headers"] = json!({"Host":host});
    }
    v
}
fn xhttp_shared(s: &State) -> bool {
    s.enabled(Protocol::VlessReality)
        && s.enabled(Protocol::VlessXhttp)
        && s.core(Protocol::VlessReality) == Core::Xray
        && s.core(Protocol::VlessXhttp) == Core::Xray
        && s.port(Protocol::VlessReality) == s.port(Protocol::VlessXhttp)
}
fn xr_has_reality(s: &State) -> bool {
    s.protocols()
        .into_iter()
        .any(|p| p.reality() && s.core(p) == Core::Xray)
}
fn guard_port(s: &State) -> Result<u16> {
    let port = s.number("REALITY_GUARD_PORT", 0);
    if port == 0 {
        return Err("Xray REALITY 缺少有效防偷跑端口 REALITY_GUARD_PORT".into());
    }
    Ok(port)
}
fn xr_reality(s: &State, server: bool) -> Result<Value> {
    if server {
        Ok(
            json!({"security":"reality","realitySettings":{"target":format!("127.0.0.1:{}",guard_port(s)?),
            "serverNames":[s.get("REALITY_SNI")],"privateKey":s.get("REALITY_PRIVATE_KEY"),"shortIds":[s.get("REALITY_SHORT_ID")]}}),
        )
    } else {
        Ok(
            json!({"security":"reality","realitySettings":{"serverName":s.get("REALITY_SNI"),
            "fingerprint":"chrome","publicKey":s.get("REALITY_PUBLIC_KEY"),"shortId":s.get("REALITY_SHORT_ID"),"spiderX":"/"}}),
        )
    }
}
fn xr_cert(ctx: &Context, s: &State, server: bool, alpn: &[&str]) -> Result<Value> {
    let mut tls = json!({"serverName":tls_name(s),"alpn":alpn});
    if server {
        tls["certificates"] = json!([{"certificateFile":util::path_str(&cert_path(ctx,s))?,"keyFile":util::path_str(&key_path(ctx,s))?}]);
    } else {
        tls["fingerprint"] = json!("chrome");
        if let Some(pin) = certificate_pin(ctx, s)? {
            tls["pinnedPeerCertSha256"] = json!(pin);
        }
    }
    Ok(json!({"security":"tls","tlsSettings":tls}))
}
fn xr_sniffing() -> Value {
    json!({"enabled":true,"destOverride":["http","tls","quic"],"routeOnly":true})
}
fn xr_inbound(ctx: &Context, s: &State, p: Protocol) -> Result<Value> {
    use Protocol::*;
    if !p.cores().contains(&Core::Xray) {
        return Err(format!("Xray 不支持 {p}").into());
    }
    let mut v = json!({"tag":format!("{p}-in"),"listen":s.get_or("LISTEN_ADDR","0.0.0.0"),"port":s.port(p),"sniffing":xr_sniffing()});
    let mut stream = json!({"network":"raw","security":"none"});
    match p {
        VlessReality | VlessXhttp | VlessGrpc | VlessWs => {
            v["protocol"] = json!("vless");
            v["settings"] =
                json!({"clients":[{"id":s.get("UUID"),"email":"onebox"}],"decryption":"none"});
            stream = if p.reality() {
                xr_reality(s, true)?
            } else {
                xr_cert(ctx, s, true, &["http/1.1"])?
            };
            stream["network"] = json!("raw");
            match p {
                VlessReality => {
                    v["settings"]["clients"][0]["flow"] = json!("xtls-rprx-vision");
                    if xhttp_shared(s) {
                        v["settings"]["fallbacks"] =
                            json!([{"dest":s.get_or("XR_XHTTP_SOCK","@onebox-xhttp"),"xver":1}]);
                    }
                }
                VlessXhttp => {
                    if xhttp_shared(s) {
                        v["listen"] = json!(s.get_or("XR_XHTTP_SOCK", "@onebox-xhttp"));
                        v.as_object_mut().unwrap().remove("port");
                        stream = json!({"sockopt":{"acceptProxyProtocol":true}});
                    }
                    stream["network"] = json!("xhttp");
                    stream["xhttpSettings"] = json!({"path":s.get("XHTTP_PATH"),"mode":"auto"});
                }
                VlessGrpc => {
                    stream["network"] = json!("grpc");
                    stream["grpcSettings"] = json!({"serviceName":s.get("GRPC_SERVICE")});
                }
                VlessWs => {
                    stream["network"] = json!("ws");
                    stream["wsSettings"] = json!({"path":s.get("WS_PATH")});
                }
                _ => unreachable!(),
            }
        }
        VmessWs => {
            v["protocol"] = json!("vmess");
            v["settings"] = json!({"clients":[{"id":s.get("UUID"),"email":"onebox"}]});
            if s.vmess_tls() {
                stream = xr_cert(ctx, s, true, &["http/1.1"])?;
            }
            stream["network"] = json!("ws");
            stream["wsSettings"] = json!({"path":s.get("VMESS_PATH")});
        }
        Trojan => {
            v["protocol"] = json!("trojan");
            v["settings"] = json!({"clients":[{"password":s.get("PASSWORD"),"email":"onebox"}]});
            stream = xr_cert(ctx, s, true, &["h2", "http/1.1"])?;
            stream["network"] = json!("raw");
        }
        Shadowsocks => {
            v["protocol"] = json!("shadowsocks");
            v["settings"] = json!({"method":s.get_or("SS_METHOD","2022-blake3-aes-128-gcm"),"password":s.get("SS_PASSWORD"),"network":"tcp,udp"});
        }
        Hysteria2 => {
            v["protocol"] = json!("hysteria");
            v["settings"] =
                json!({"version":2,"clients":[{"auth":s.get("PASSWORD"),"email":"onebox"}]});
            stream = xr_cert(ctx, s, true, &["h3"])?;
            stream["network"] = json!("hysteria");
            stream["hysteriaSettings"] = json!({"version":2,"masquerade":{"type":"proxy","url":"https://www.bing.com","rewriteHost":true}});
            if s.flag("HY2_OBFS") {
                stream["finalmask"] = json!({"udp":[{"type":"salamander","settings":{"password":s.get("HY2_OBFS_PASSWORD")}}]});
            }
        }
        _ => unreachable!(),
    }
    if p != Shadowsocks {
        v["streamSettings"] = stream;
    }
    Ok(v)
}

fn cidrs(s: &State) -> Vec<String> {
    let mut all: BTreeSet<String> = PRIVATE_CIDRS.iter().map(|x| x.to_string()).collect();
    for (key, warp) in [
        ("SERVER_IPV4", "SERVER_IPV4_WARP"),
        ("SERVER_IPV6", "SERVER_IPV6_WARP"),
        ("SERVER_ADDR", ""),
    ] {
        if s.flag(warp) {
            continue;
        }
        if let Ok(ip) = s.get(key).parse::<IpAddr>() {
            all.insert(format!("{ip}/{}", if ip.is_ipv4() { 32 } else { 128 }));
        }
    }
    let stored = s.get("OWN_IP_CIDRS");
    let wrapped = if stored.trim_start().starts_with('[') {
        stored.to_owned()
    } else {
        format!("[{stored}]")
    };
    if let Ok(values) = serde_json::from_str::<Vec<String>>(&wrapped) {
        for value in values {
            if valid_cidr(&value) {
                all.insert(value);
            }
        }
    }
    all.into_iter().collect()
}
fn valid_cidr(value: &str) -> bool {
    value
        .split_once('/')
        .and_then(|(ip, n)| Some((ip.parse::<IpAddr>().ok()?, n.parse::<u8>().ok()?)))
        .map(|(ip, n)| n <= if ip.is_ipv4() { 32 } else { 128 })
        .unwrap_or(false)
}
fn sb_strategy(s: &State) -> &'static str {
    match (
        s.get("SERVER_IPV4").is_empty(),
        s.get("SERVER_IPV6").is_empty(),
    ) {
        (false, true) => "ipv4_only",
        (true, false) => "ipv6_only",
        _ => "prefer_ipv4",
    }
}
fn xr_strategy(s: &State) -> &'static str {
    match (
        s.get("SERVER_IPV4").is_empty(),
        s.get("SERVER_IPV6").is_empty(),
    ) {
        (false, true) => "UseIPv4",
        (true, false) => "UseIPv6",
        _ => "UseIPv4v6",
    }
}
pub fn server(ctx: &Context, s: &State, core: Core) -> Result<Value> {
    s.validate()?;
    let mut ins = Vec::new();
    for p in s.protocols().into_iter().filter(|p| s.core(*p) == core) {
        ins.push(inbound(ctx, s, p)?);
        if p == Protocol::Shadowtls {
            ins.push(json!({"type":"shadowsocks","tag":"shadowtls-ss-in","listen":"127.0.0.1","network":"tcp",
                "method":"2022-blake3-aes-128-gcm","password":s.get("SHADOWTLS_SS_PASSWORD")}));
        }
    }
    if ins.is_empty() {
        return Err(format!("没有分配给 {core} 的协议").into());
    }
    if core == Core::Singbox {
        let mut rules = vec![json!({"action":"sniff"})];
        if s.get("BLOCK_BT") != "0" {
            rules.push(json!({"protocol":"bittorrent","action":"reject"}));
        }
        if s.get("BLOCK_PRIVATE") != "0" {
            rules.push(json!({"action":"resolve","strategy":sb_strategy(s)}));
            rules.push(json!({"ip_is_private":true,"action":"reject"}));
            rules.push(json!({"ip_cidr":cidrs(s),"action":"reject"}));
        }
        return Ok(
            json!({"log":{"level":"warn","timestamp":true},"dns":{"servers":[{"type":"local","tag":"local"}]},
            "inbounds":ins,"outbounds":[{"type":"direct","tag":"direct"}],"route":{"rules":rules,
                "default_domain_resolver":{"server":"local","strategy":sb_strategy(s)},"final":"direct"}}),
        );
    }
    let mut rules = Vec::new();
    let mut direct = json!({"tag":"direct","protocol":"freedom","streamSettings":{"sockopt":{"domainStrategy":xr_strategy(s)}}});
    if s.get("BLOCK_PRIVATE") == "0" {
        direct["settings"] = json!({"finalRules":[{"action":"allow"}]});
    }
    let mut outs = vec![direct];
    if xr_has_reality(s) {
        let (host, port) = endpoint(s.get("REALITY_DEST"))?;
        ins.push(json!({"tag":"reality-dest-in","listen":"127.0.0.1","port":guard_port(s)?,"protocol":"dokodemo-door",
            "settings":{"address":host,"port":port,"network":"tcp"},"sniffing":{"enabled":true,"destOverride":["tls"],"routeOnly":true}}));
        let target = if s.site_enabled() {
            "reality-site"
        } else {
            "direct"
        };
        if s.site_enabled() {
            let port = s.number("REALITY_SITE_PORT", 0);
            if port == 0 {
                return Err("自建站缺少 HTTPS 内部端口".into());
            }
            outs.push(json!({"tag":"reality-site","protocol":"freedom","settings":{"redirect":format!("127.0.0.1:{port}"),
                "finalRules":[{"action":"allow","network":"tcp","ip":["127.0.0.1/32"],"port":port.to_string()},{"action":"block"}]}}));
        }
        rules.push(json!({"type":"field","inboundTag":["reality-dest-in"],"domain":[format!("full:{}",s.get("REALITY_SNI"))],"outboundTag":target}));
        rules.push(json!({"type":"field","inboundTag":["reality-dest-in"],"outboundTag":"block"}));
    }
    if s.get("BLOCK_BT") != "0" {
        rules.push(json!({"type":"field","protocol":["bittorrent"],"outboundTag":"block"}));
    }
    if s.get("BLOCK_PRIVATE") != "0" {
        rules.push(json!({"type":"field","ip":cidrs(s),"outboundTag":"block"}));
    }
    outs.push(json!({"tag":"block","protocol":"blackhole"}));
    Ok(
        json!({"log":{"loglevel":"warning","access":"none"},"inbounds":ins,"outbounds":outs,
        "routing":{"domainStrategy":if s.get("BLOCK_PRIVATE")=="0"{"AsIs"}else{"IPIfNonMatch"},"rules":rules}}),
    )
}

/// Primary outbound. Complete client and probe bundles also include the
/// ShadowTLS transport outbound referenced by this protocol's SS detour.
pub fn outbound(ctx: &Context, s: &State, p: Protocol, core: Core) -> Result<Value> {
    if !p.supports(core.as_str()) {
        return Err(format!("{core} 客户端不支持 {p}").into());
    }
    match core {
        Core::Singbox => sb_outbound(ctx, s, p),
        Core::Xray => xr_outbound(ctx, s, p),
    }
}
fn sb_outbound(ctx: &Context, s: &State, p: Protocol) -> Result<Value> {
    use Protocol::*;
    let mut v = json!({"tag":s.node_name(p),"server":s.get("SERVER_ADDR"),"server_port":s.port(p)});
    match p {
        VlessReality | VlessGrpc | VlessWs => {
            v["type"] = json!("vless");
            v["uuid"] = json!(s.get("UUID"));
            v["tls"] = if p.reality() {
                sb_reality_client(s)
            } else {
                sb_cert_client(ctx, s, &["http/1.1"], true)?
            };
            if p == VlessReality {
                v["flow"] = json!("xtls-rprx-vision");
            }
            if p == VlessGrpc {
                v["transport"] = json!({"type":"grpc","service_name":s.get("GRPC_SERVICE")});
            }
            if p == VlessWs {
                v["transport"] = ws_transport(s.get("WS_PATH"), Some(tls_name(s)));
            }
        }
        VmessWs => {
            v["type"] = json!("vmess");
            v["uuid"] = json!(s.get("UUID"));
            v["security"] = json!("auto");
            v["alter_id"] = json!(0);
            if s.vmess_tls() {
                v["tls"] = sb_cert_client(ctx, s, &["http/1.1"], true)?;
            }
            v["transport"] = ws_transport(
                s.get("VMESS_PATH"),
                Some(if s.vmess_tls() {
                    tls_name(s)
                } else {
                    s.get("DOMAIN")
                }),
            );
        }
        Trojan | Hysteria2 | Tuic | Anytls | AnytlsReality => {
            v["type"] = json!(match p {
                Trojan => "trojan",
                Hysteria2 => "hysteria2",
                Tuic => "tuic",
                _ => "anytls",
            });
            v["password"] = json!(s.get("PASSWORD"));
            v["tls"] = if p == AnytlsReality {
                sb_reality_client(s)
            } else {
                sb_cert_client(
                    ctx,
                    s,
                    match p {
                        Trojan => &["h2", "http/1.1"],
                        Hysteria2 | Tuic => &["h3"],
                        _ => &[],
                    },
                    !matches!(p, Hysteria2 | Tuic),
                )?
            };
            if p == Tuic {
                v["uuid"] = json!(s.get("UUID"));
                v["congestion_control"] = json!("bbr");
                v["udp_relay_mode"] = json!("native");
                v["zero_rtt_handshake"] = json!(false);
            }
            if p == Hysteria2 {
                if s.flag("HY2_OBFS") {
                    v["obfs"] = json!({"type":"salamander","password":s.get("HY2_OBFS_PASSWORD")});
                }
                if !s.get("HY2_HOP").is_empty() {
                    v["server_ports"] = json!([s.get("HY2_HOP").replace('-', ":")]);
                    v["hop_interval"] = json!("30s");
                }
                apply_hy2(&mut v, s, false)?;
            }
        }
        Shadowsocks => {
            v["type"] = json!("shadowsocks");
            v["method"] = json!(s.get_or("SS_METHOD", "2022-blake3-aes-128-gcm"));
            v["password"] = json!(s.get("SS_PASSWORD"));
        }
        Shadowtls => {
            v = json!({"type":"shadowsocks","tag":s.node_name(p),"method":"2022-blake3-aes-128-gcm","password":s.get("SHADOWTLS_SS_PASSWORD"),
                "udp_over_tcp":{"enabled":true,"version":2},"detour":format!("{}-tls",s.node_name(p))});
        }
        VlessXhttp => return Err("sing-box 客户端不支持 XHTTP".into()),
    }
    Ok(v)
}
fn shadow_transport(s: &State) -> Value {
    json!({"type":"shadowtls","tag":format!("{}-tls",s.node_name(Protocol::Shadowtls)),"server":s.get("SERVER_ADDR"),"server_port":s.port(Protocol::Shadowtls),
        "version":3,"password":s.get("SHADOWTLS_PASSWORD"),"tls":{"enabled":true,"server_name":s.get("SHADOWTLS_SNI"),"utls":{"enabled":true,"fingerprint":"chrome"}}})
}
fn xr_outbound(ctx: &Context, s: &State, p: Protocol) -> Result<Value> {
    use Protocol::*;
    let mut v = json!({"tag":s.node_name(p)});
    let mut stream = json!({"network":"raw","security":"none"});
    match p {
        VlessReality | VlessXhttp | VlessGrpc | VlessWs | VmessWs => {
            let mut user = json!({"id":s.get("UUID")});
            if p == VmessWs {
                user["security"] = json!("auto");
            } else {
                user["encryption"] = json!("none");
            }
            if p == VlessReality {
                user["flow"] = json!("xtls-rprx-vision");
            }
            v["protocol"] = json!(if p == VmessWs { "vmess" } else { "vless" });
            v["settings"] =
                json!({"vnext":[{"address":s.get("SERVER_ADDR"),"port":s.port(p),"users":[user]}]});
            if p.reality() {
                stream = xr_reality(s, false)?;
            } else if p != VmessWs || s.vmess_tls() {
                stream = xr_cert(ctx, s, false, &["http/1.1"])?;
            }
            stream["network"] = json!("raw");
            match p {
                VlessXhttp => {
                    stream["network"] = json!("xhttp");
                    stream["xhttpSettings"] = json!({"path":s.get("XHTTP_PATH"),"mode":"auto"});
                }
                VlessGrpc => {
                    stream["network"] = json!("grpc");
                    stream["grpcSettings"] = json!({"serviceName":s.get("GRPC_SERVICE")});
                }
                VlessWs | VmessWs => {
                    stream["network"] = json!("ws");
                    stream["wsSettings"] =
                        json!({"path":if p==VlessWs{s.get("WS_PATH")}else{s.get("VMESS_PATH")}});
                    let host = if p == VlessWs || s.vmess_tls() {
                        tls_name(s)
                    } else {
                        s.get("DOMAIN")
                    };
                    if !host.is_empty() {
                        stream["wsSettings"]["host"] = json!(host);
                    }
                }
                _ => (),
            }
        }
        Trojan | Shadowsocks => {
            v["protocol"] = json!(if p == Trojan { "trojan" } else { "shadowsocks" });
            let mut node = json!({"address":s.get("SERVER_ADDR"),"port":s.port(p),"password":if p==Trojan{s.get("PASSWORD")}else{s.get("SS_PASSWORD")}});
            if p == Shadowsocks {
                node["method"] = json!(s.get_or("SS_METHOD", "2022-blake3-aes-128-gcm"));
            } else {
                stream = xr_cert(ctx, s, false, &["h2", "http/1.1"])?;
                stream["network"] = json!("raw");
            }
            v["settings"] = json!({"servers":[node]});
        }
        Hysteria2 => {
            v["protocol"] = json!("hysteria");
            v["settings"] = json!({"version":2,"address":s.get("SERVER_ADDR"),"port":s.port(p)});
            stream = xr_cert(ctx, s, false, &["h3"])?;
            stream["network"] = json!("hysteria");
            stream["hysteriaSettings"] = json!({"version":2,"auth":s.get("PASSWORD")});
            let mut mask = json!({});
            if s.flag("HY2_OBFS") {
                mask["udp"] = json!([{"type":"salamander","settings":{"password":s.get("HY2_OBFS_PASSWORD")}}]);
            }
            if !s.get("HY2_HOP").is_empty() {
                mask["quicParams"] =
                    json!({"udpHop":{"ports":s.get("HY2_HOP"),"interval":"25-35"}});
            }
            if !mask.as_object().unwrap().is_empty() {
                stream["finalmask"] = mask;
            }
        }
        _ => return Err(format!("Xray 客户端不支持 {p}").into()),
    }
    if p != Shadowsocks {
        v["streamSettings"] = stream;
    }
    Ok(v)
}

fn client_protocols(s: &State, format: &str) -> Result<Vec<Protocol>> {
    let protocols: Vec<_> = s
        .protocols()
        .into_iter()
        .filter(|p| p.supports(format))
        .collect();
    if protocols.is_empty() {
        return Err(format!("当前协议组合没有 {format} 支持的节点").into());
    }
    Ok(protocols)
}
pub(super) fn direct_domains(s: &State) -> Vec<String> {
    [s.get("SUBSCRIPTION_DOMAIN"), s.get("REALITY_SITE_DOMAIN")]
        .into_iter()
        .filter(|d| util::valid_domain(d))
        .map(|d| d.to_lowercase())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}
fn sb_client(ctx: &Context, s: &State, tun: bool) -> Result<Value> {
    let protocols = client_protocols(s, "singbox")?;
    let names: Vec<_> = protocols.iter().map(|p| s.node_name(*p)).collect();
    let mut selection = vec!["auto".to_owned()];
    selection.extend(names.clone());
    selection.push("direct".into());
    let mut outs = vec![
        json!({"type":"selector","tag":"proxy","outbounds":selection,"default":"auto"}),
        json!({"type":"urltest","tag":"auto","outbounds":names,"url":"https://www.gstatic.com/generate_204","interval":"3m","tolerance":50}),
    ];
    for p in protocols {
        outs.push(outbound(ctx, s, p, Core::Singbox)?);
        if p == Protocol::Shadowtls {
            outs.push(shadow_transport(s));
        }
    }
    outs.push(json!({"type":"direct","tag":"direct"}));
    let mut ins = Vec::new();
    if tun {
        ins.push(json!({"type":"tun","tag":"tun-in","address":["172.19.0.1/30","fdfe:dcba:9876::1/126"],"auto_route":true,"strict_route":true,"stack":"mixed"}));
    }
    ins.push(json!({"type":"mixed","tag":"mixed-in","listen":"127.0.0.1","listen_port":2080}));
    let mut config = json!({"log":{"level":"info","timestamp":true},"dns":{
        "servers":[{"type":"https","tag":"dns-remote","server":"1.1.1.1","tls":{"server_name":"cloudflare-dns.com"},"detour":"proxy"},
            {"type":"udp","tag":"dns-direct","server":"223.5.5.5"}],
        "rules":[{"clash_mode":"Direct","server":"dns-direct"},{"clash_mode":"Global","server":"dns-remote"},{"rule_set":"geosite-cn","server":"dns-direct"}],
        "final":"dns-remote","strategy":"prefer_ipv4"},"inbounds":ins,"outbounds":outs,
        "route":{"rules":[{"action":"sniff"},{"protocol":"dns","action":"hijack-dns"},{"ip_is_private":true,"outbound":"direct"},
            {"clash_mode":"Direct","outbound":"direct"},{"clash_mode":"Global","outbound":"proxy"},{"rule_set":["geosite-cn","geoip-cn"],"outbound":"direct"}],
            "rule_set":[{"type":"remote","tag":"geosite-cn","format":"binary","url":"https://testingcf.jsdelivr.net/gh/SagerNet/sing-geosite@rule-set/geosite-cn.srs","download_detour":"direct"},
                {"type":"remote","tag":"geoip-cn","format":"binary","url":"https://testingcf.jsdelivr.net/gh/SagerNet/sing-geoip@rule-set/geoip-cn.srs","download_detour":"direct"}],
            "final":"proxy","auto_detect_interface":true,"default_domain_resolver":"dns-direct"},
        "experimental":{"cache_file":{"enabled":true},"clash_api":{"external_controller":"127.0.0.1:9090","secret":s.get("CLASH_SECRET"),"default_mode":"Rule"}}});
    let domains = direct_domains(s);
    if !domains.is_empty() {
        config["dns"]["rules"]
            .as_array_mut()
            .unwrap()
            .insert(0, json!({"domain":domains,"server":"dns-direct"}));
        config["route"]["rules"]
            .as_array_mut()
            .unwrap()
            .insert(2, json!({"domain":domains,"outbound":"direct"}));
    }
    if s.get("CLASH_SECRET").is_empty() {
        config["experimental"]
            .as_object_mut()
            .unwrap()
            .remove("clash_api");
    }
    Ok(config)
}
fn xr_client(ctx: &Context, s: &State) -> Result<Value> {
    let protocols = client_protocols(s, "xray")?;
    let mut outs = Vec::new();
    for (i, p) in protocols.into_iter().enumerate() {
        let mut v = outbound(ctx, s, p, Core::Xray)?;
        v["tag"] = json!(if i == 0 {
            "proxy".to_owned()
        } else {
            p.to_string()
        });
        outs.push(v);
    }
    outs.push(json!({"tag":"direct","protocol":"freedom"}));
    outs.push(json!({"tag":"block","protocol":"blackhole"}));
    let mut config = json!({"log":{"loglevel":"warning"},"dns":{"servers":["https://1.1.1.1/dns-query",
        {"address":"223.5.5.5","domains":["geosite:cn"],"expectIPs":["geoip:cn"],"skipFallback":true}],"queryStrategy":"UseIP"},
        "inbounds":[{"tag":"socks-in","listen":"127.0.0.1","port":10808,"protocol":"socks","settings":{"udp":true},"sniffing":xr_sniffing()},
            {"tag":"http-in","listen":"127.0.0.1","port":10809,"protocol":"http","sniffing":{"enabled":true,"destOverride":["http","tls"],"routeOnly":true}}],
        "outbounds":outs,"routing":{"domainStrategy":"IPIfNonMatch","rules":[
            {"type":"field","ip":["223.5.5.5"],"outboundTag":"direct"},{"type":"field","ip":PRIVATE_CIDRS,"outboundTag":"direct"},
            {"type":"field","domain":["geosite:category-ads-all"],"outboundTag":"block"},
            {"type":"field","domain":["geosite:cn"],"outboundTag":"direct"},{"type":"field","ip":["geoip:cn"],"outboundTag":"direct"}]}});
    let domains: Vec<_> = direct_domains(s)
        .into_iter()
        .map(|d| format!("full:{d}"))
        .collect();
    if !domains.is_empty() {
        config["dns"]["servers"].as_array_mut().unwrap().insert(
            0,
            json!({"address":"223.5.5.5","domains":domains,"skipFallback":true}),
        );
        config["routing"]["rules"].as_array_mut().unwrap().insert(
            0,
            json!({"type":"field","domain":domains,"outboundTag":"direct"}),
        );
    }
    Ok(config)
}
pub fn link(ctx: &Context, s: &State, p: Protocol) -> Result<String> {
    share::link(ctx, s, p)
}
pub fn provider(ctx: &Context, s: &State) -> Result<String> {
    share::mihomo(ctx, s, true)
}
pub fn client(ctx: &Context, s: &State, format: &str) -> Result<String> {
    match format {
        "links" | "link" => {
            let links = client_protocols(s, "links")?
                .into_iter()
                .map(|p| share::link(ctx, s, p))
                .collect::<Result<Vec<_>>>()?;
            Ok(format!("{}\n", links.join("\n")))
        }
        "sub" | "base64" => Ok(format!("{}\n", STANDARD.encode(client(ctx, s, "links")?))),
        "mihomo" | "clash" => share::mihomo(ctx, s, false),
        "provider" => provider(ctx, s),
        "singbox" | "sing-box" => Ok(format!(
            "{}\n",
            serde_json::to_string_pretty(&sb_client(ctx, s, true)?)?
        )),
        "singbox-notun" | "sing-box-notun" => Ok(format!(
            "{}\n",
            serde_json::to_string_pretty(&sb_client(ctx, s, false)?)?
        )),
        "xray" => Ok(format!(
            "{}\n",
            serde_json::to_string_pretty(&xr_client(ctx, s)?)?
        )),
        _ => Err(format!("未知客户端格式: {format}").into()),
    }
}
pub fn probe_bundle(ctx: &Context, s: &State, local: bool) -> Result<Value> {
    let mut state = s.clone();
    if local {
        state.set("SERVER_ADDR", "127.0.0.1");
    }
    let mut entries = Vec::new();
    for p in state.protocols() {
        let core =
            if p.supports("xray") && (p == Protocol::VlessXhttp || state.core(p) == Core::Xray) {
                Core::Xray
            } else {
                Core::Singbox
            };
        let tag = if core == Core::Xray {
            "proxy".to_owned()
        } else {
            state.node_name(p)
        };
        let mut primary = outbound(ctx, &state, p, core)?;
        primary["tag"] = json!(tag);
        let mut outs = vec![primary];
        if p == Protocol::Shadowtls {
            outs.push(shadow_transport(&state));
        }
        let mut entry = json!({"id":p.as_str(),"core":core.as_str(),"transport":p.network(),"tag":tag,"outbounds":outs});
        if p.reality() {
            let (mut host, mut port) = endpoint(state.get("REALITY_DEST"))?;
            if state.site_enabled() && !local {
                if state.flag("REALITY_SITE_HTTPS") {
                    host = state.get("SERVER_ADDR").into();
                    port = 443;
                } else {
                    host.clear();
                    port = 0;
                }
            }
            entry["reality"] = json!({"host":state.get("SERVER_ADDR"),"port":state.port(p),"sni":state.get("REALITY_SNI"),"reference_host":host,"reference_port":port});
        }
        entries.push(entry);
    }
    if entries.is_empty() {
        return Err("没有可导出的节点".into());
    }
    Ok(json!({"schema":1,"entries":entries}))
}

/// Render every file before publishing any. The staged directory replaces the
/// previous complete directory atomically with renameat2(RENAME_EXCHANGE) on
/// Linux, so readers never observe a mix of credentials or half-written files.
pub fn write_clients(ctx: &Context, s: &State) -> Result<()> {
    let target = ctx.paths.clients();
    util::safe_path(&target)?;
    fs::create_dir_all(&ctx.paths.root)?;
    let stage = ctx
        .paths
        .root
        .join(format!(".client-new-{}", util::random_hex(12)?));
    fs::create_dir(&stage)?;
    fs::set_permissions(&stage, fs::Permissions::from_mode(0o700))?;
    let result = (|| -> Result<()> {
        for (format, name) in [
            ("links", "links.txt"),
            ("sub", "sub.txt"),
            ("mihomo", "mihomo.yaml"),
            ("provider", "provider.yaml"),
            ("singbox", "sing-box.json"),
            ("singbox-notun", "sing-box-notun.json"),
            ("xray", "xray.json"),
        ] {
            if s.protocols().iter().any(|p| p.supports(format)) {
                util::atomic_write(&stage.join(name), client(ctx, s, format)?.as_bytes(), 0o600)?;
            }
        }
        util::atomic_write(
            &stage.join("probe.json"),
            serde_json::to_string_pretty(&probe_bundle(ctx, s, false)?)?.as_bytes(),
            0o600,
        )?;
        if target.exists() {
            if !target.is_dir() {
                return Err("客户端目录路径不是目录".into());
            }
            exchange_directories(&stage, &target)?;
        } else {
            fs::rename(&stage, &target)?;
        }
        fs::File::open(&ctx.paths.root)?.sync_all()?;
        Ok(())
    })();
    if stage.exists() {
        let _ = fs::remove_dir_all(&stage);
    }
    result
}
#[cfg(target_os = "linux")]
fn exchange_directories(left: &Path, right: &Path) -> Result<()> {
    use std::{ffi::CString, os::unix::ffi::OsStrExt};
    let left = CString::new(left.as_os_str().as_bytes())?;
    let right = CString::new(right.as_os_str().as_bytes())?;
    let rc = unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            libc::AT_FDCWD,
            left.as_ptr(),
            libc::AT_FDCWD,
            right.as_ptr(),
            libc::RENAME_EXCHANGE,
        )
    };
    if rc != 0 {
        return Err(format!(
            "无法原子替换客户端目录，原目录保持不变: {}",
            std::io::Error::last_os_error()
        )
        .into());
    }
    Ok(())
}
#[cfg(not(target_os = "linux"))]
fn exchange_directories(_left: &Path, _right: &Path) -> Result<()> {
    Err("原子客户端目录替换需要 Linux renameat2".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::Paths;
    fn fixture(protocols: &[Protocol]) -> (Context, State, PathBuf) {
        let root = std::env::temp_dir().join(format!(
            "onebox-render-test-{}",
            util::random_hex(8).unwrap()
        ));
        let ctx = Context {
            paths: Paths::isolated(&root),
            ..Context::default()
        };
        let mut s = State::default();
        s.set(
            "PROTOCOLS",
            protocols
                .iter()
                .map(|p| p.as_str())
                .collect::<Vec<_>>()
                .join(" "),
        );
        for (i, p) in protocols.iter().enumerate() {
            s.set_core(*p, p.cores()[0]);
            s.set_port(*p, 10_000 + i as u16);
        }
        for (k, v) in [
            ("UUID", "11111111-2222-4333-8444-555555555555"),
            ("PASSWORD", "a'\"&\n秘密"),
            ("SERVER_ADDR", "2001:db8::7"),
            ("REALITY_PRIVATE_KEY", "private-key-never-export"),
            ("REALITY_PUBLIC_KEY", "public-key"),
            ("REALITY_SHORT_ID", "0123456789abcdef"),
            ("REALITY_DEST", "[2001:db8::9]:443"),
            ("REALITY_SNI", "www.example.com"),
            ("TLS_MODE", "acme"),
            ("DOMAIN", "cert.example.com"),
            ("TLS_SNI", "fallback.example.com"),
            ("REALITY_GUARD_PORT", "10999"),
            ("NODE_NAME", "O'Reilly \"节点\""),
            ("SS_METHOD", "2022-blake3-aes-128-gcm"),
            ("SS_PASSWORD", "base64-password"),
            ("SHADOWTLS_PASSWORD", "shadow-secret"),
            ("SHADOWTLS_SS_PASSWORD", "shadow-ss-secret"),
            ("SHADOWTLS_SNI", "www.example.com"),
            ("SHADOWTLS_DEST", "www.example.com:443"),
            ("WS_PATH", "/ws?one=1&two=2"),
            ("VMESS_PATH", "/vmess"),
            ("XHTTP_PATH", "/xhttp"),
            ("GRPC_SERVICE", "grpc-service"),
            ("VMESS_TLS", "1"),
        ] {
            s.set(k, v);
        }
        (ctx, s, root)
    }
    #[test]
    fn all_protocols_keep_supported_core_and_client_boundaries() {
        for p in crate::model::PROTOCOLS {
            let (ctx, mut s, _) = fixture(&[p]);
            for core in [Core::Singbox, Core::Xray] {
                s.set_core(p, core);
                assert_eq!(
                    inbound(&ctx, &s, p).is_ok(),
                    p.cores().contains(&core),
                    "{p} {core} inbound"
                );
                assert_eq!(
                    outbound(&ctx, &s, p, core).is_ok(),
                    p.supports(core.as_str()),
                    "{p} {core} outbound"
                );
            }
        }
    }
    #[test]
    fn anytls_reality_has_no_certificate_or_fallback_export() {
        let (ctx, s, _) = fixture(&[Protocol::AnytlsReality]);
        let i = inbound(&ctx, &s, Protocol::AnytlsReality).unwrap();
        assert_eq!(i["type"], "anytls");
        assert_eq!(i["tls"]["reality"]["handshake"]["server"], "2001:db8::9");
        assert!(i["tls"].get("certificate_path").is_none());
        let o = outbound(&ctx, &s, Protocol::AnytlsReality, Core::Singbox).unwrap();
        assert_eq!(o["password"], s.get("PASSWORD"));
        assert_eq!(o["tls"]["utls"]["enabled"], true);
        assert!(!serde_json::to_string(&o)
            .unwrap()
            .contains("private-key-never-export"));
        for f in ["links", "base64", "provider", "mihomo", "xray"] {
            assert!(client(&ctx, &s, f).is_err(), "{f}");
        }
    }
    #[test]
    fn xhttp_shared_socket_has_one_reality_terminator_and_guard() {
        let (ctx, mut s, _) = fixture(&[Protocol::VlessReality, Protocol::VlessXhttp]);
        for p in s.protocols() {
            s.set_core(p, Core::Xray);
            s.set_port(p, 443);
        }
        let v = server(&ctx, &s, Core::Xray).unwrap();
        assert_eq!(v["inbounds"][0]["settings"]["fallbacks"][0]["xver"], 1);
        assert_eq!(v["inbounds"][1]["listen"], "@onebox-xhttp");
        assert!(v["inbounds"][1].get("port").is_none());
        assert!(v["inbounds"][1]["streamSettings"]
            .get("realitySettings")
            .is_none());
        assert_eq!(v["routing"]["rules"][1]["outboundTag"], "block");
        s.set("REALITY_GUARD_PORT", "");
        assert!(server(&ctx, &s, Core::Xray).is_err());
    }
    #[test]
    fn private_guard_resolves_domains_and_blocks_metadata_and_own_ip() {
        let (ctx, mut s, _) = fixture(&[Protocol::AnytlsReality]);
        s.set("SERVER_IPV4", "8.8.4.4");
        s.set("OWN_IP_CIDRS", "\"9.9.9.9/32\"");
        let v = server(&ctx, &s, Core::Singbox).unwrap();
        let rules = v["route"]["rules"].as_array().unwrap();
        assert_eq!(rules[2]["action"], "resolve");
        let ips = rules[4]["ip_cidr"].as_array().unwrap();
        for ip in ["100.64.0.0/10", "8.8.4.4/32", "9.9.9.9/32"] {
            assert!(ips.contains(&json!(ip)));
        }
        assert!(!ips.contains(&json!("64:ff9b::/96")));
    }
    #[test]
    fn shadowtls_complete_bundles_include_only_one_private_detour() {
        let (ctx, s, _) = fixture(&[Protocol::Shadowtls]);
        let v = server(&ctx, &s, Core::Singbox).unwrap();
        assert_eq!(v["inbounds"].as_array().unwrap().len(), 2);
        assert_eq!(v["inbounds"][1]["listen"], "127.0.0.1");
        assert!(v["inbounds"][1].get("listen_port").is_none());
        let b = probe_bundle(&ctx, &s, false).unwrap();
        assert_eq!(b["entries"][0]["outbounds"].as_array().unwrap().len(), 2);
        assert_eq!(
            b["entries"][0]["outbounds"][0]["detour"],
            b["entries"][0]["outbounds"][1]["tag"]
        );
    }
    #[test]
    fn measured_hysteria_bandwidth_swaps_server_perspective() {
        let (ctx, mut s, _) = fixture(&[Protocol::Hysteria2]);
        s.set("HY2_PROFILE", "measured");
        s.set("HY2_UP_MBPS", "50");
        s.set("HY2_DOWN_MBPS", "200");
        s.set("RESOURCE_PROFILE", "low-memory");
        let i = inbound(&ctx, &s, Protocol::Hysteria2).unwrap();
        let o = outbound(&ctx, &s, Protocol::Hysteria2, Core::Singbox).unwrap();
        assert_eq!(i["up_mbps"], 200);
        assert_eq!(o["up_mbps"], 50);
        assert_eq!(i["max_concurrent_streams"], 64);
        assert!(o.get("max_concurrent_streams").is_none());
    }
    #[test]
    fn subscription_refresh_uses_direct_routing_and_dns() {
        let (ctx, mut s, _) = fixture(&[Protocol::Trojan]);
        s.set("SUBSCRIPTION_DOMAIN", "updates.example.com");
        s.set("REALITY_SITE_DOMAIN", "site.example.com");
        let sb = sb_client(&ctx, &s, false).unwrap();
        let xr = xr_client(&ctx, &s).unwrap();
        assert_eq!(sb["dns"]["rules"][0]["server"], "dns-direct");
        assert_eq!(sb["route"]["rules"][2]["outbound"], "direct");
        assert!(sb["route"]["rules"][2]["domain"]
            .as_array()
            .unwrap()
            .contains(&json!("updates.example.com")));
        assert_eq!(xr["routing"]["rules"][0]["outboundTag"], "direct");
        assert!(xr["dns"]["servers"][0]["domains"]
            .as_array()
            .unwrap()
            .contains(&json!("full:updates.example.com")));
        assert!(sb["experimental"].get("clash_api").is_none());
    }
    #[test]
    fn pinned_certificate_exports_cannot_leak_concatenated_private_key() {
        let (ctx, mut s, root) = fixture(&[Protocol::Trojan]);
        fs::create_dir_all(ctx.paths.tls()).unwrap();
        s.set("TLS_MODE", "self");
        fs::write(ctx.paths.tls().join("cert.pem"),"-----BEGIN CERTIFICATE-----\nMAMCAQE=\n-----END CERTIFICATE-----\n-----BEGIN PRIVATE KEY-----\nsecret-private\n-----END PRIVATE KEY-----\n").unwrap();
        let o = outbound(&ctx, &s, Protocol::Trojan, Core::Singbox).unwrap();
        let text = serde_json::to_string(&o).unwrap();
        assert!(!text.contains("secret-private"));
        assert!(!text.contains("insecure"));
        let x = outbound(&ctx, &s, Protocol::Trojan, Core::Xray).unwrap();
        assert_eq!(
            x["streamSettings"]["tlsSettings"]["pinnedPeerCertSha256"],
            util::sha256(&[0x30, 3, 2, 1, 1])
        );
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn client_publish_removes_unsupported_files_and_preserves_old_on_error() {
        let (ctx, mut s, root) = fixture(&[Protocol::Trojan]);
        write_clients(&ctx, &s).unwrap();
        assert!(ctx.paths.clients().join("xray.json").exists());
        s.set("PROTOCOLS", "anytls-reality");
        s.set_core(Protocol::AnytlsReality, Core::Singbox);
        s.set_port(Protocol::AnytlsReality, 443);
        write_clients(&ctx, &s).unwrap();
        for file in [
            "links.txt",
            "sub.txt",
            "xray.json",
            "mihomo.yaml",
            "provider.yaml",
        ] {
            assert!(!ctx.paths.clients().join(file).exists(), "{file}");
        }
        let before = fs::read(ctx.paths.clients().join("sing-box.json")).unwrap();
        s.set("PROTOCOLS", "trojan");
        s.set("TLS_MODE", "self");
        assert!(write_clients(&ctx, &s).is_err());
        assert_eq!(
            fs::read(ctx.paths.clients().join("sing-box.json")).unwrap(),
            before
        );
        assert_eq!(
            fs::metadata(ctx.paths.clients().join("sing-box.json"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        fs::remove_dir_all(root).unwrap();
    }
}
