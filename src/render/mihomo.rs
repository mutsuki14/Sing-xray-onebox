//! mihomo (Clash Meta) full configuration and proxy-provider, as a JSON
//! value with the v2 structure; [`super::yaml`] turns it into YAML text.
//!
//! Schema: mihomo ≥ 1.19.3 (`xhttp-opts` ≥ 1.19.22, `bbr-profile` ≥ 1.19.32);
//! REALITY proxies advertise X25519MLKEM768 support for Xray ≥ 26.4 servers.
//!
//! Changes from v2: `mihomo.yaml` / `provider.yaml` are real block-style
//! YAML (v2 wrote pretty JSON, which mihomo also accepted); the structure is
//! identical.

use super::json::ObjectExt;
use super::policy::{self, cert_alpn};
use super::spec::{InboundSpec, NodeSpec, TlsSpec};
use crate::domain::config::Hy2Profile;
use crate::domain::defaults;
use crate::domain::protocol::{ClientFormat, Protocol};
use crate::error::Result;
use serde_json::{json, Value};

/// One proxy entry.
pub fn proxy(spec: &NodeSpec, ib: &InboundSpec) -> Result<Value> {
    use Protocol::*;
    let p = ib.protocol;
    let creds = &spec.creds;
    let mut v = json!({"name": ib.label, "server": spec.server_host(), "port": ib.port});
    match p {
        VlessReality | VlessXhttp | VlessGrpc => {
            v.merge(json!({"type": "vless", "uuid": creds.uuid, "udp": true}));
            v.merge(reality(spec)?);
            v.merge(match p {
                VlessReality => json!({"network": "tcp", "flow": "xtls-rprx-vision"}),
                VlessXhttp => json!({"network": "xhttp",
                    "xhttp-opts": {"path": creds.xhttp_path, "mode": "auto"}}),
                _ => json!({"network": "grpc",
                    "grpc-opts": {"grpc-service-name": creds.grpc_service}}),
            });
        }
        VlessWs => {
            let tls = spec.tls()?;
            v.merge(
                json!({"type": "vless", "uuid": creds.uuid, "udp": true, "network": "ws",
                "tls": true, "client-fingerprint": policy::FINGERPRINT, "alpn": cert_alpn(p),
                "ws-opts": websocket(&creds.ws_path, Some(&tls.server_name))}),
            );
            v.merge(certificate(tls, "servername")?);
        }
        VmessWs => v.merge(vmess(spec)?),
        Trojan | Anytls => {
            v.merge(
                json!({"type": p.id(), "password": creds.password, "udp": true,
                "client-fingerprint": policy::FINGERPRINT}),
            );
            if p == Trojan {
                v.set("alpn", json!(cert_alpn(p)));
            }
            v.merge(certificate(spec.tls()?, "sni")?);
        }
        Shadowsocks => v.merge(json!({"type": "ss", "cipher": creds.ss_method,
            "password": creds.ss_password, "udp": true})),
        Hysteria2 => v.merge(hysteria2(spec)?),
        Tuic => {
            v.merge(
                json!({"type": "tuic", "uuid": creds.uuid, "password": creds.password,
                "alpn": cert_alpn(p), "congestion-controller": "bbr",
                "udp-relay-mode": "native"}),
            );
            v.merge(certificate(spec.tls()?, "sni")?);
        }
        Shadowtls => v.merge(
            json!({"type": "ss", "cipher": defaults::SHADOWTLS_SS_METHOD,
            "password": creds.shadowtls_ss_password, "udp": true, "udp-over-tcp": true,
            "udp-over-tcp-version": policy::UOT_VERSION,
            "client-fingerprint": policy::FINGERPRINT, "plugin": "shadow-tls",
            "plugin-opts": {"host": spec.shadowtls.sni, "password": creds.shadowtls_password,
                "version": 3}}),
        ),
        AnytlsReality => bail!("{p} 不支持 mihomo"),
    }
    Ok(v)
}

fn vmess(spec: &NodeSpec) -> Result<Value> {
    let mut v = json!({"type": "vmess", "uuid": spec.creds.uuid, "alterId": 0,
        "cipher": "auto", "network": "ws", "udp": true, "tls": spec.vmess.tls,
        "ws-opts": websocket(&spec.creds.vmess_path, spec.vmess.ws_host.as_deref())});
    if spec.vmess.tls {
        v.set("client-fingerprint", policy::FINGERPRINT);
        v.set("alpn", json!(cert_alpn(Protocol::VmessWs)));
        v.merge(certificate(spec.tls()?, "servername")?);
    }
    Ok(v)
}

fn hysteria2(spec: &NodeSpec) -> Result<Value> {
    let hy2 = &spec.hy2;
    let mut v = json!({"type": "hysteria2", "password": spec.creds.password,
        "alpn": cert_alpn(Protocol::Hysteria2)});
    if let Some(hop) = hy2.hop {
        v.set("ports", hop.to_string());
        v.set("hop-interval", policy::MIHOMO_HOP_INTERVAL);
    }
    if let Some(password) = &hy2.obfs_password {
        v.set("obfs", "salamander");
        v.set("obfs-password", password.as_str());
    }
    match (hy2.profile, hy2.bandwidth) {
        (Some(Hy2Profile::Conservative), _) => v.set("bbr-profile", "conservative"),
        (Some(Hy2Profile::Measured), Some(bw)) => {
            v.set("up", bw.up_mbps);
            v.set("down", bw.down_mbps);
        }
        _ => {}
    }
    if let Some(w) = hy2.windows {
        v.set("initial-stream-receive-window", w.stream);
        v.set("max-stream-receive-window", w.stream);
        v.set("initial-connection-receive-window", w.connection);
        v.set("max-connection-receive-window", w.connection);
    }
    v.merge(certificate(spec.tls()?, "sni")?);
    Ok(v)
}

fn reality(spec: &NodeSpec) -> Result<Value> {
    let r = spec.reality()?;
    Ok(
        json!({"tls": true, "servername": r.sni, "client-fingerprint": policy::FINGERPRINT,
        "reality-opts": {"public-key": r.public_key, "short-id": r.short_id,
            "support-x25519mlkem768": true}}),
    )
}

/// Certificate name under `key`; a pinned certificate is verified by its
/// leaf fingerprint (`skip-cert-verify` only disables CA verification).
fn certificate(tls: &TlsSpec, key: &str) -> Result<Value> {
    let mut v = json!({});
    v.set(key, tls.server_name.as_str());
    if let Some(material) = tls.pinned_material()? {
        v.set("skip-cert-verify", true);
        v.set("fingerprint", material.pin());
    }
    Ok(v)
}

fn websocket(path: &str, host: Option<&str>) -> Value {
    let mut v = json!({"path": path, "max-early-data": policy::WS_EARLY_DATA,
        "early-data-header-name": policy::WS_EARLY_DATA_HEADER});
    if let Some(host) = host.filter(|h| !h.is_empty()) {
        v.set("headers", json!({"Host": host}));
    }
    v
}

/// Proxies and their names; `format` names the export in the "no node" error.
fn proxies(spec: &NodeSpec, format: ClientFormat) -> Result<(Vec<Value>, Vec<String>)> {
    let nodes = super::nodes_for(spec, format)?;
    let proxies = nodes
        .iter()
        .map(|ib| proxy(spec, ib))
        .collect::<Result<Vec<_>>>()?;
    Ok((proxies, nodes.iter().map(|n| n.label.clone()).collect()))
}

/// Proxy-provider document: exactly `{"proxies": [...]}`.
pub fn provider(spec: &NodeSpec) -> Result<Value> {
    Ok(json!({"proxies": proxies(spec, ClientFormat::Provider)?.0}))
}

/// Full mihomo configuration: rule mode with a select group over an
/// url-test group, fake-ip DNS, local mixed port; the controller only on
/// loopback and only with a secret.
pub fn config(spec: &NodeSpec) -> Result<Value> {
    let (proxies, names) = proxies(spec, ClientFormat::Mihomo)?;
    let mut choices = vec![policy::MIHOMO_AUTO.to_owned()];
    choices.extend(names.iter().cloned());
    choices.push("DIRECT".to_owned());
    let geox: serde_json::Map<String, Value> = policy::MIHOMO_GEOX
        .iter()
        .map(|(kind, url)| (kind.to_string(), json!(url)))
        .collect();
    let mut doc = json!({
        "mixed-port": defaults::MIHOMO_MIXED_PORT, "allow-lan": false, "mode": "rule",
        "log-level": "info", "ipv6": true, "unified-delay": true, "tcp-concurrent": true,
        "profile": {"store-selected": true, "store-fake-ip": true},
        "geodata-mode": true, "geo-auto-update": true, "geo-update-interval": 24,
        "geox-url": geox,
        "sniffer": {"enable": true, "sniff": {
                "HTTP": {"ports": [80, "8080-8880"], "override-destination": true},
                "TLS": {"ports": [443, 8443]}, "QUIC": {"ports": [443, 8443]}},
            "skip-domain": ["Mijia Cloud", "+.push.apple.com"]},
        "tun": {"enable": false, "stack": "mixed", "auto-route": true,
            "auto-detect-interface": true, "dns-hijack": ["any:53"]},
        "dns": policy::mihomo_dns(&spec.direct),
        "proxies": proxies,
        "proxy-groups": [
            {"name": policy::MIHOMO_SELECT, "type": "select", "proxies": choices},
            {"name": policy::MIHOMO_AUTO, "type": "url-test", "url": policy::URL_TEST,
                "interval": policy::MIHOMO_URL_TEST_INTERVAL,
                "tolerance": policy::URL_TEST_TOLERANCE, "proxies": names},
        ],
        "rules": policy::mihomo_rules(&spec.direct),
    });
    if !spec.creds.clash_secret.is_empty() {
        doc.set("external-controller", policy::controller());
        doc.set("secret", spec.creds.clash_secret.as_str());
    }
    Ok(doc)
}

#[cfg(test)]
mod tests;
