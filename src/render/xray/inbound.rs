//! Xray server inbounds, one per protocol, and the REALITY guard.

use super::sniffing;
use crate::domain::protocol::Protocol;
use crate::error::Result;
use crate::render::json::ObjectExt;
use crate::render::policy::{self, cert_alpn, USER_NAME};
use crate::render::spec::{InboundSpec, NodeSpec, RealitySpec, TlsSpec};
use serde_json::{json, Value};

/// The public inbound of `ib` (tag `{protocol}-in`). A shared XHTTP inbound
/// listens on the abstract fallback socket instead of a port.
pub fn inbound(spec: &NodeSpec, ib: &InboundSpec) -> Result<Value> {
    let p = ib.protocol;
    let mut v = json!({"tag": format!("{p}-in"), "listen": spec.listen.to_string(),
        "port": ib.port, "sniffing": sniffing()});
    v.merge(protocol_fields(spec, p)?);
    if p == Protocol::VlessXhttp && spec.xhttp_shared() {
        v.set("listen", policy::XHTTP_SOCKET);
        v.remove_key("port");
    }
    Ok(v)
}

/// `protocol`, `settings` and (except Shadowsocks) `streamSettings`.
fn protocol_fields(spec: &NodeSpec, p: Protocol) -> Result<Value> {
    use Protocol::*;
    let creds = &spec.creds;
    Ok(match p {
        VlessReality => json!({"protocol": "vless", "settings": vision_settings(spec),
            "streamSettings": with_network(reality(spec)?, "raw")}),
        VlessXhttp => json!({"protocol": "vless", "settings": vless(spec),
            "streamSettings": xhttp_stream(spec)?}),
        VlessGrpc => {
            let mut stream = with_network(reality(spec)?, "grpc");
            stream.set("grpcSettings", json!({"serviceName": creds.grpc_service}));
            json!({"protocol": "vless", "settings": vless(spec), "streamSettings": stream})
        }
        VlessWs => json!({"protocol": "vless", "settings": vless(spec),
            "streamSettings": ws_stream(certificate(spec.tls()?, p), &creds.ws_path)}),
        VmessWs => json!({"protocol": "vmess", "settings": {"clients": clients(spec)},
            "streamSettings": vmess_stream(spec)?}),
        Trojan => json!({"protocol": "trojan",
            "settings": {"clients": [{"password": creds.password, "email": USER_NAME}]},
            "streamSettings": with_network(certificate(spec.tls()?, p), "raw")}),
        Shadowsocks => json!({"protocol": "shadowsocks", "settings": {"method": creds.ss_method,
            "password": creds.ss_password, "network": "tcp,udp"}}),
        Hysteria2 => json!({"protocol": "hysteria",
            "settings": {"version": 2, "clients": [{"auth": creds.password, "email": USER_NAME}]},
            "streamSettings": hysteria2_stream(spec)?}),
        Tuic | Anytls | Shadowtls | AnytlsReality => bail!("{p} 不支持 xray 服务端"),
    })
}

fn clients(spec: &NodeSpec) -> Value {
    json!([{"id": spec.creds.uuid, "email": USER_NAME}])
}

fn vless(spec: &NodeSpec) -> Value {
    json!({"clients": clients(spec), "decryption": "none"})
}

/// VMess over WebSocket, with certificate TLS when enabled.
fn vmess_stream(spec: &NodeSpec) -> Result<Value> {
    let security = if spec.vmess.tls {
        certificate(spec.tls()?, Protocol::VmessWs)
    } else {
        json!({"security": "none"})
    };
    Ok(ws_stream(security, &spec.creds.vmess_path))
}

/// Vision clients; with a shared port, non-Vision traffic falls back to the
/// XHTTP inbound over the abstract socket with PROXY protocol v1.
fn vision_settings(spec: &NodeSpec) -> Value {
    let mut v = json!({"clients": [{"id": spec.creds.uuid, "email": USER_NAME,
        "flow": "xtls-rprx-vision"}], "decryption": "none"});
    if spec.xhttp_shared() {
        v.set(
            "fallbacks",
            json!([{"dest": policy::XHTTP_SOCKET, "xver": 1}]),
        );
    }
    v
}

/// XHTTP behind the shared Vision port carries no REALITY of its own (Vision
/// already terminated it) and accepts the PROXY header of the fallback.
fn xhttp_stream(spec: &NodeSpec) -> Result<Value> {
    let mut stream = if spec.xhttp_shared() {
        json!({"sockopt": {"acceptProxyProtocol": true}, "network": "xhttp"})
    } else {
        with_network(reality(spec)?, "xhttp")
    };
    stream.set(
        "xhttpSettings",
        json!({"path": spec.creds.xhttp_path, "mode": "auto"}),
    );
    Ok(stream)
}

fn ws_stream(security: Value, path: &str) -> Value {
    let mut stream = with_network(security, "ws");
    stream.set("wsSettings", json!({"path": path}));
    stream
}

/// Hysteria2 over QUIC: Salamander via `finalmask` or, without
/// obfuscation, a masquerade site (C-8.1 #3: never both).
fn hysteria2_stream(spec: &NodeSpec) -> Result<Value> {
    let mut stream = with_network(certificate(spec.tls()?, Protocol::Hysteria2), "hysteria");
    let mut settings = json!({"version": 2});
    match &spec.hy2.obfs_password {
        Some(password) => stream.set(
            "finalmask",
            json!({"udp": [{"type": "salamander", "settings": {"password": password}}]}),
        ),
        None => settings.set(
            "masquerade",
            json!({"type": "proxy", "url": policy::MASQUERADE_URL, "rewriteHost": true}),
        ),
    }
    stream.set("hysteriaSettings", settings);
    Ok(stream)
}

fn with_network(mut stream: Value, network: &str) -> Value {
    stream.set("network", network);
    stream
}

/// REALITY terminated against the local guard, never the target itself.
fn reality(spec: &NodeSpec) -> Result<Value> {
    let r = spec.reality()?;
    Ok(json!({"security": "reality", "realitySettings": {
        "target": format!("{}:{}", policy::LOOPBACK, r.guard_port),
        "serverNames": [r.sni], "privateKey": r.private_key, "shortIds": [r.short_id]}}))
}

fn certificate(tls: &TlsSpec, p: Protocol) -> Value {
    json!({"security": "tls", "tlsSettings": {"serverName": tls.server_name,
        "alpn": cert_alpn(p),
        "certificates": [{"certificateFile": tls.cert_path, "keyFile": tls.key_path}]}})
}

/// Loopback dokodemo inbound REALITY handshakes go through (see module docs).
pub fn guard_inbound(r: &RealitySpec) -> Value {
    json!({"tag": policy::XRAY_GUARD_TAG, "listen": policy::LOOPBACK, "port": r.guard_port,
        "protocol": "dokodemo-door",
        "settings": {"address": r.dest.host.to_string(), "port": r.dest.port, "network": "tcp"},
        "sniffing": {"enabled": true, "destOverride": ["tls"], "routeOnly": true}})
}
