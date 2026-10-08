//! Xray client outbounds, one per protocol (tag = node label; the client
//! document retags them).

use crate::domain::protocol::Protocol;
use crate::error::Result;
use crate::render::json::ObjectExt;
use crate::render::policy::{self, cert_alpn};
use crate::render::spec::{InboundSpec, NodeSpec, TlsSpec};
use serde_json::{json, Value};

/// The client outbound of `ib`.
pub fn outbound(spec: &NodeSpec, ib: &InboundSpec) -> Result<Value> {
    use Protocol::*;
    let p = ib.protocol;
    let mut v = json!({"tag": ib.label});
    let creds = &spec.creds;
    let address = spec.server_host();
    match p {
        VlessReality | VlessXhttp | VlessGrpc | VlessWs | VmessWs => {
            let kind = if p == VmessWs { "vmess" } else { "vless" };
            v.set("protocol", kind);
            v.set(
                "settings",
                json!({"vnext": [{"address": address, "port": ib.port, "users": [user(spec, p)]}]}),
            );
            v.set("streamSettings", vnext_stream(spec, p)?);
        }
        Trojan => {
            v.set("protocol", "trojan");
            v.set(
                "settings",
                json!({"servers": [{"address": address, "port": ib.port,
                    "password": creds.password}]}),
            );
            let mut stream = certificate(spec.tls()?, p)?;
            stream.set("network", "raw");
            v.set("streamSettings", stream);
        }
        Shadowsocks => {
            v.set("protocol", "shadowsocks");
            v.set(
                "settings",
                json!({"servers": [{"address": address, "port": ib.port,
                    "password": creds.ss_password, "method": creds.ss_method}]}),
            );
        }
        Hysteria2 => {
            v.set("protocol", "hysteria");
            v.set(
                "settings",
                json!({"version": 2, "address": address, "port": ib.port}),
            );
            v.set("streamSettings", hysteria2_stream(spec)?);
        }
        Tuic | Anytls | Shadowtls | AnytlsReality => bail!("xray 客户端不支持 {p}"),
    }
    Ok(v)
}

/// VLESS users carry `encryption: none` (+ Vision flow); VMess `security: auto`.
fn user(spec: &NodeSpec, p: Protocol) -> Value {
    let mut user = json!({"id": spec.creds.uuid});
    match p {
        Protocol::VmessWs => user.set("security", "auto"),
        Protocol::VlessReality => {
            user.set("encryption", "none");
            user.set("flow", "xtls-rprx-vision");
        }
        _ => user.set("encryption", "none"),
    }
    user
}

fn vnext_stream(spec: &NodeSpec, p: Protocol) -> Result<Value> {
    use Protocol::*;
    let creds = &spec.creds;
    let mut stream = if p.reality() {
        reality(spec)?
    } else if p != VmessWs || spec.vmess.tls {
        certificate(spec.tls()?, p)?
    } else {
        json!({"security": "none"})
    };
    match p {
        VlessXhttp => {
            stream.set("network", "xhttp");
            stream.set(
                "xhttpSettings",
                json!({"path": creds.xhttp_path, "mode": "auto"}),
            );
        }
        VlessGrpc => {
            stream.set("network", "grpc");
            stream.set("grpcSettings", json!({"serviceName": creds.grpc_service}));
        }
        VlessWs | VmessWs => {
            let (path, host) = if p == VlessWs {
                (&creds.ws_path, Some(spec.tls()?.server_name.as_str()))
            } else {
                (&creds.vmess_path, spec.vmess.ws_host.as_deref())
            };
            let mut ws = json!({"path": path});
            if let Some(host) = host.filter(|h| !h.is_empty()) {
                ws.set("host", host);
            }
            stream.set("network", "ws");
            stream.set("wsSettings", ws);
        }
        _ => stream.set("network", "raw"),
    }
    Ok(stream)
}

/// Hysteria2 over QUIC; `finalmask` only when obfuscation or hopping is on.
fn hysteria2_stream(spec: &NodeSpec) -> Result<Value> {
    let mut stream = certificate(spec.tls()?, Protocol::Hysteria2)?;
    stream.set("network", "hysteria");
    stream.set(
        "hysteriaSettings",
        json!({"version": 2, "auth": spec.creds.password}),
    );
    let mut mask = json!({});
    if let Some(password) = &spec.hy2.obfs_password {
        mask.set(
            "udp",
            json!([{"type": "salamander", "settings": {"password": password}}]),
        );
    }
    if let Some(hop) = spec.hy2.hop {
        mask.set(
            "quicParams",
            json!({"udpHop": {"ports": hop.to_string(), "interval": policy::XRAY_HOP_INTERVAL}}),
        );
    }
    if mask.as_object().is_some_and(|m| !m.is_empty()) {
        stream.set("finalmask", mask);
    }
    Ok(stream)
}

fn reality(spec: &NodeSpec) -> Result<Value> {
    let r = spec.reality()?;
    Ok(
        json!({"security": "reality", "realitySettings": {"serverName": r.sni,
        "fingerprint": policy::FINGERPRINT, "publicKey": r.public_key, "shortId": r.short_id,
        "spiderX": "/"}}),
    )
}

/// Certificate TLS of a client; a pinned certificate is verified by the
/// leaf SHA-256 (Xray has no embedded-chain option).
fn certificate(tls: &TlsSpec, p: Protocol) -> Result<Value> {
    let mut settings = json!({"serverName": tls.server_name, "alpn": cert_alpn(p),
        "fingerprint": policy::FINGERPRINT});
    if let Some(material) = tls.pin()? {
        settings.set("pinnedPeerCertSha256", material.leaf_pin());
    }
    Ok(json!({"security": "tls", "tlsSettings": settings}))
}
