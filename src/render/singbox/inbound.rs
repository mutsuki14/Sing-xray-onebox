//! sing-box server inbounds, one per protocol.

use super::{grpc_transport, ws_transport};
use crate::domain::config::Hy2Profile;
use crate::domain::defaults;
use crate::domain::protocol::Protocol;
use crate::error::Result;
use crate::render::json::ObjectExt;
use crate::render::policy::{self, cert_alpn, USER_NAME};
use crate::render::spec::{Hy2Spec, InboundSpec, NodeSpec, RealitySpec, TlsSpec};
use serde_json::{json, Value};

/// Tag of the loopback Shadowsocks inbound behind ShadowTLS.
pub const SHADOWTLS_BACKEND_TAG: &str = "shadowtls-ss-in";

/// The public inbound of `ib` (tag `{protocol}-in`).
pub fn inbound(spec: &NodeSpec, ib: &InboundSpec) -> Result<Value> {
    let p = ib.protocol;
    let mut v = json!({"tag": format!("{p}-in"), "listen": spec.listen.to_string(),
        "listen_port": ib.port});
    v.merge(protocol_fields(spec, p)?);
    Ok(v)
}

fn protocol_fields(spec: &NodeSpec, p: Protocol) -> Result<Value> {
    use Protocol::*;
    let creds = &spec.creds;
    Ok(match p {
        VlessReality => json!({"type": "vless",
            "users": [{"name": USER_NAME, "uuid": creds.uuid, "flow": "xtls-rprx-vision"}],
            "tls": reality(spec.reality()?)}),
        VlessGrpc => json!({"type": "vless", "users": [uuid_user(spec)],
            "tls": reality(spec.reality()?), "transport": grpc_transport(spec)}),
        VlessWs => json!({"type": "vless", "users": [uuid_user(spec)],
            "tls": certificate(spec.tls()?, cert_alpn(p)),
            "transport": ws_transport(&creds.ws_path, None)}),
        VmessWs => vmess(spec)?,
        Trojan | Anytls => json!({"type": p.id(), "users": [password_user(spec)],
            "tls": certificate(spec.tls()?, cert_alpn(p))}),
        AnytlsReality => json!({"type": "anytls", "users": [password_user(spec)],
            "tls": reality(spec.reality()?)}),
        Hysteria2 => hysteria2(spec)?,
        Tuic => json!({"type": "tuic",
            "users": [{"name": USER_NAME, "password": creds.password, "uuid": creds.uuid}],
            "tls": certificate(spec.tls()?, cert_alpn(p)), "congestion_control": "bbr"}),
        Shadowsocks => json!({"type": "shadowsocks", "method": creds.ss_method,
            "password": creds.ss_password}),
        Shadowtls => json!({"type": "shadowtls", "version": 3,
            "users": [{"name": USER_NAME, "password": creds.shadowtls_password}],
            "handshake": {"server": spec.shadowtls.dest.host.to_string(),
                "server_port": spec.shadowtls.dest.port},
            "strict_mode": true, "detour": SHADOWTLS_BACKEND_TAG}),
        VlessXhttp => bail!("{p} 不支持 singbox 服务端"),
    })
}

/// Loopback, TCP-only Shadowsocks inbound ShadowTLS forwards to (no public port).
pub fn shadowtls_backend(spec: &NodeSpec) -> Value {
    json!({"type": "shadowsocks", "tag": SHADOWTLS_BACKEND_TAG, "listen": policy::LOOPBACK,
        "network": "tcp", "method": defaults::SHADOWTLS_SS_METHOD,
        "password": spec.creds.shadowtls_ss_password})
}

fn uuid_user(spec: &NodeSpec) -> Value {
    json!({"name": USER_NAME, "uuid": spec.creds.uuid})
}

fn password_user(spec: &NodeSpec) -> Value {
    json!({"name": USER_NAME, "password": spec.creds.password})
}

fn vmess(spec: &NodeSpec) -> Result<Value> {
    let mut v = json!({"type": "vmess",
        "users": [{"name": USER_NAME, "uuid": spec.creds.uuid, "alterId": 0}],
        "transport": ws_transport(&spec.creds.vmess_path, None)});
    if spec.vmess.tls {
        v.set(
            "tls",
            certificate(spec.tls()?, cert_alpn(Protocol::VmessWs)),
        );
    }
    Ok(v)
}

/// Salamander obfuscation or, without it, a masquerade site; then tuning.
fn hysteria2(spec: &NodeSpec) -> Result<Value> {
    let mut v = json!({"type": "hysteria2", "users": [password_user(spec)],
        "tls": certificate(spec.tls()?, cert_alpn(Protocol::Hysteria2))});
    match &spec.hy2.obfs_password {
        Some(password) => v.set("obfs", json!({"type": "salamander", "password": password})),
        None => v.set(
            "masquerade",
            json!({"type": "proxy", "url": policy::MASQUERADE_URL, "rewrite_host": true}),
        ),
    }
    server_tuning(&spec.hy2, &mut v);
    Ok(v)
}

/// Server side of the Hysteria2 tuning: `auto`/`conservative` ignore the
/// client's bandwidth hint; measured bandwidth is swapped to the server's
/// perspective (its upload is the client's download).
fn server_tuning(hy2: &Hy2Spec, v: &mut Value) {
    match hy2.profile {
        Some(Hy2Profile::Auto) => v.set("ignore_client_bandwidth", true),
        Some(Hy2Profile::Conservative) => {
            v.set("ignore_client_bandwidth", true);
            v.set("bbr_profile", "conservative");
        }
        Some(Hy2Profile::Measured) => {
            if let Some(bw) = hy2.bandwidth {
                v.set("up_mbps", bw.down_mbps);
                v.set("down_mbps", bw.up_mbps);
            }
        }
        None => {}
    }
    if let Some(w) = hy2.windows {
        v.set("stream_receive_window", w.stream);
        v.set("connection_receive_window", w.connection);
        v.set("max_concurrent_streams", w.max_streams);
    }
}

fn reality(r: &RealitySpec) -> Value {
    json!({"enabled": true, "server_name": r.sni, "reality": {"enabled": true,
        "handshake": {"server": r.dest.host.to_string(), "server_port": r.dest.port},
        "private_key": r.private_key, "short_id": [r.short_id]}})
}

fn certificate(tls: &TlsSpec, alpn: &[&str]) -> Value {
    let mut v = json!({"enabled": true, "server_name": tls.server_name,
        "certificate_path": tls.cert_path, "key_path": tls.key_path});
    if !alpn.is_empty() {
        v.set("alpn", json!(alpn));
    }
    v
}
