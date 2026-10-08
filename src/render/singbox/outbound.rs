//! sing-box client outbounds, one per protocol (tag = node label).

use super::{grpc_transport, utls, ws_transport};
use crate::domain::config::Hy2Profile;
use crate::domain::defaults;
use crate::domain::protocol::Protocol;
use crate::error::Result;
use crate::render::json::ObjectExt;
use crate::render::policy::{self, cert_alpn, singbox_utls};
use crate::render::spec::{Hy2Spec, InboundSpec, NodeSpec, RealitySpec, TlsSpec};
use serde_json::{json, Value};

/// The primary client outbound of `ib`. ShadowTLS clients additionally need
/// [`shadowtls_transport`], which this outbound detours through.
pub fn outbound(spec: &NodeSpec, ib: &InboundSpec) -> Result<Value> {
    let p = ib.protocol;
    if p == Protocol::Shadowtls {
        return Ok(shadowtls_client(spec, &ib.label));
    }
    let mut v = json!({"tag": ib.label, "server": spec.server_host(), "server_port": ib.port});
    v.merge(protocol_fields(spec, p)?);
    Ok(v)
}

fn protocol_fields(spec: &NodeSpec, p: Protocol) -> Result<Value> {
    use Protocol::*;
    let creds = &spec.creds;
    Ok(match p {
        VlessReality => json!({"type": "vless", "uuid": creds.uuid, "flow": "xtls-rprx-vision",
            "tls": reality(spec.reality()?)}),
        VlessGrpc => json!({"type": "vless", "uuid": creds.uuid, "tls": reality(spec.reality()?),
            "transport": grpc_transport(spec)}),
        VlessWs => {
            let tls = spec.tls()?;
            json!({"type": "vless", "uuid": creds.uuid, "tls": certificate(tls, p)?,
                "transport": ws_transport(&creds.ws_path, Some(&tls.server_name))})
        }
        VmessWs => vmess(spec)?,
        Trojan | Anytls => json!({"type": p.id(), "password": creds.password,
            "tls": certificate(spec.tls()?, p)?}),
        AnytlsReality => json!({"type": "anytls", "password": creds.password,
            "tls": reality(spec.reality()?)}),
        Hysteria2 => hysteria2(spec)?,
        Tuic => json!({"type": "tuic", "password": creds.password, "uuid": creds.uuid,
            "tls": certificate(spec.tls()?, p)?, "congestion_control": "bbr",
            "udp_relay_mode": "native", "zero_rtt_handshake": false}),
        Shadowsocks => json!({"type": "shadowsocks", "method": creds.ss_method,
            "password": creds.ss_password}),
        Shadowtls | VlessXhttp => bail!("singbox 客户端不支持 {p}"),
    })
}

/// ShadowTLS clients: a Shadowsocks outbound (UDP over TCP) detoured
/// through the ShadowTLS transport `{label}-tls`.
fn shadowtls_client(spec: &NodeSpec, label: &str) -> Value {
    json!({"type": "shadowsocks", "tag": label, "method": defaults::SHADOWTLS_SS_METHOD,
        "password": spec.creds.shadowtls_ss_password,
        "udp_over_tcp": {"enabled": true, "version": policy::UOT_VERSION},
        "detour": format!("{label}-tls")})
}

/// The ShadowTLS v3 transport outbound every complete bundle ships with the
/// Shadowsocks outbound (exactly one detour).
pub fn shadowtls_transport(spec: &NodeSpec) -> Result<Value> {
    let ib = spec.require(Protocol::Shadowtls)?;
    Ok(
        json!({"type": "shadowtls", "tag": format!("{}-tls", ib.label),
        "server": spec.server_host(), "server_port": ib.port, "version": 3,
        "password": spec.creds.shadowtls_password,
        "tls": {"enabled": true, "server_name": spec.shadowtls.sni, "utls": utls()}}),
    )
}

fn vmess(spec: &NodeSpec) -> Result<Value> {
    let mut v = json!({"type": "vmess", "uuid": spec.creds.uuid, "security": "auto",
        "alter_id": 0,
        "transport": ws_transport(&spec.creds.vmess_path, spec.vmess.ws_host.as_deref())});
    if spec.vmess.tls {
        v.set("tls", certificate(spec.tls()?, Protocol::VmessWs)?);
    }
    Ok(v)
}

fn hysteria2(spec: &NodeSpec) -> Result<Value> {
    let mut v = json!({"type": "hysteria2", "password": spec.creds.password,
        "tls": certificate(spec.tls()?, Protocol::Hysteria2)?});
    if let Some(password) = &spec.hy2.obfs_password {
        v.set("obfs", json!({"type": "salamander", "password": password}));
    }
    if let Some(hop) = spec.hy2.hop {
        v.set(
            "server_ports",
            json!([format!("{}:{}", hop.start, hop.end)]),
        );
        v.set("hop_interval", policy::SINGBOX_HOP_INTERVAL);
    }
    client_tuning(&spec.hy2, &mut v);
    Ok(v)
}

/// Client side of the Hysteria2 tuning (client perspective bandwidth).
fn client_tuning(hy2: &Hy2Spec, v: &mut Value) {
    match hy2.profile {
        Some(Hy2Profile::Conservative) => v.set("bbr_profile", "conservative"),
        Some(Hy2Profile::Measured) => {
            if let Some(bw) = hy2.bandwidth {
                v.set("up_mbps", bw.up_mbps);
                v.set("down_mbps", bw.down_mbps);
            }
        }
        Some(Hy2Profile::Auto) | None => {}
    }
    if let Some(w) = hy2.windows {
        v.set("stream_receive_window", w.stream);
        v.set("connection_receive_window", w.connection);
    }
}

fn reality(r: &RealitySpec) -> Value {
    json!({"enabled": true, "server_name": r.sni, "utls": utls(),
        "reality": {"enabled": true, "public_key": r.public_key, "short_id": r.short_id}})
}

/// Certificate TLS of a client: the whole pinned chain is embedded (sing-box
/// then trusts exactly it); never `insecure`.
fn certificate(tls: &TlsSpec, p: Protocol) -> Result<Value> {
    let mut v = json!({"enabled": true, "server_name": tls.server_name});
    if let Some(material) = tls.pinned_material()? {
        v.set("certificate", json!(material.pems()));
    }
    let alpn = cert_alpn(p);
    if !alpn.is_empty() {
        v.set("alpn", json!(alpn));
    }
    if singbox_utls(p) {
        v.set("utls", utls());
    }
    Ok(v)
}
