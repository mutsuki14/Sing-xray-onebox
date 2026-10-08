//! Share links (one URI per protocol, v2 templates) and the Base64
//! subscription.
//!
//! Encoding: every interpolated value is percent-encoded byte-wise except
//! the RFC 3986 unreserved set (`sys::text::url_encode`); IPv6 hosts are
//! bracketed. VMess links carry base64 of compact JSON with sorted keys and
//! raw (not percent-encoded) values.
//!
//! Kept from v2, documented trade-offs:
//! - C-8.1 #4: with a pinned certificate, VLESS-WS/Trojan links add
//!   `allowInsecure=1&insecure=1` next to the pin (`pcs`) for clients that
//!   only understand the insecure flag, and TUIC links (no portable pin
//!   field) carry `allow_insecure=1&insecure=1` only;
//! - C-8.1 #19: Shadowsocks-2022 user info is base64url without padding
//!   (SIP002 suggests percent-encoding for 2022 ciphers; most clients
//!   accept both).
//!
//! Changes from v2: the server address is typed, so v2's address checks
//! (whitespace, `/?#@`, brackets) cannot fail here.

use super::json::ObjectExt;
use super::policy;
use super::spec::{InboundSpec, NodeSpec, TlsSpec};
use crate::domain::protocol::{ClientFormat, Protocol};
use crate::error::Result;
use crate::sys::text::url_encode;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use serde_json::json;

/// Share link of one enabled protocol.
pub fn link(spec: &NodeSpec, ib: &InboundSpec) -> Result<String> {
    let p = ib.protocol;
    ensure!(ClientFormat::Links.supports(p), "{p} 不支持通用分享链接");
    if p == Protocol::VmessWs {
        return vmess(spec, ib);
    }
    let (scheme, user, query) = uri_parts(spec, p)?;
    let host = spec.uri_host();
    let name = url_encode(&ib.label);
    Ok(format!(
        "{scheme}://{user}@{host}:{}{query}#{name}",
        ib.port
    ))
}

/// Scheme, user info and query (with its `?` or `/?`) of a URI link.
fn uri_parts(spec: &NodeSpec, p: Protocol) -> Result<(&'static str, String, String)> {
    use Protocol::*;
    let uuid = url_encode(&spec.creds.uuid);
    let password = url_encode(&spec.creds.password);
    Ok(match p {
        VlessReality => (
            "vless",
            uuid,
            format!(
                "?encryption=none&flow=xtls-rprx-vision&{}&type=tcp&headerType=none",
                reality_query(spec)?
            ),
        ),
        VlessXhttp => (
            "vless",
            uuid,
            format!(
                "?encryption=none&{}&type=xhttp&path={}&mode=auto",
                reality_query(spec)?,
                url_encode(&spec.creds.xhttp_path)
            ),
        ),
        VlessGrpc => (
            "vless",
            uuid,
            format!(
                "?encryption=none&{}&type=grpc&serviceName={}&mode=gun",
                reality_query(spec)?,
                url_encode(&spec.creds.grpc_service)
            ),
        ),
        VlessWs => ("vless", uuid, vless_ws_query(spec)?),
        Trojan => ("trojan", password, trojan_query(spec)?),
        Shadowsocks => ("ss", shadowsocks_user(spec), String::new()),
        Hysteria2 => ("hysteria2", password, hysteria2_query(spec)?),
        Tuic => ("tuic", format!("{uuid}:{password}"), tuic_query(spec)?),
        Anytls => ("anytls", password, anytls_query(spec)?),
        VmessWs | Shadowtls | AnytlsReality => bail!("{p} 不支持通用分享链接"),
    })
}

fn vless_ws_query(spec: &NodeSpec) -> Result<String> {
    let tls = spec.tls()?;
    let sni = url_encode(&tls.server_name);
    Ok(format!(
        "?encryption=none&security=tls&sni={sni}&fp=chrome&alpn=http%2F1.1{}&type=ws&host={sni}&path={}",
        pin_query(tls)?,
        url_encode(&spec.creds.ws_path)
    ))
}

fn trojan_query(spec: &NodeSpec) -> Result<String> {
    let tls = spec.tls()?;
    Ok(format!(
        "?security=tls&sni={}&fp=chrome&alpn=h2%2Chttp%2F1.1{}&type=tcp&headerType=none",
        url_encode(&tls.server_name),
        pin_query(tls)?
    ))
}

/// SIP002 user info: base64url (no padding) of `method:password`.
fn shadowsocks_user(spec: &NodeSpec) -> String {
    let creds = &spec.creds;
    URL_SAFE_NO_PAD.encode(format!("{}:{}", creds.ss_method, creds.ss_password))
}

/// TUIC URIs have no portable pin field: a pinned certificate can only be
/// expressed as "skip verification" (kept from v2, see module docs).
fn tuic_query(spec: &NodeSpec) -> Result<String> {
    let tls = spec.tls()?;
    let trust = if tls.pinned() {
        "&allow_insecure=1&insecure=1"
    } else {
        ""
    };
    Ok(format!(
        "?sni={}&alpn=h3&congestion_control=bbr&udp_relay_mode=native{trust}",
        url_encode(&tls.server_name)
    ))
}

fn anytls_query(spec: &NodeSpec) -> Result<String> {
    let tls = spec.tls()?;
    let trust = match tls.pin()? {
        Some(m) => format!("&insecure=1&hpkp={}", m.leaf_pin()),
        None => String::new(),
    };
    Ok(format!("/?sni={}{trust}", url_encode(&tls.server_name)))
}

fn reality_query(spec: &NodeSpec) -> Result<String> {
    let r = spec.reality()?;
    Ok(format!(
        "security=reality&sni={}&fp=chrome&pbk={}&sid={}",
        url_encode(&r.sni),
        url_encode(&r.public_key),
        url_encode(&r.short_id)
    ))
}

/// Pin parameters of VLESS-WS / Trojan links (empty when publicly trusted).
fn pin_query(tls: &TlsSpec) -> Result<String> {
    Ok(match tls.pin()? {
        Some(m) => format!("&allowInsecure=1&insecure=1&pcs={}", m.leaf_pin()),
        None => String::new(),
    })
}

fn hysteria2_query(spec: &NodeSpec) -> Result<String> {
    let tls = spec.tls()?;
    let mut query = format!("/?sni={}&alpn=h3", url_encode(&tls.server_name));
    if let Some(m) = tls.pin()? {
        query.push_str(&format!("&insecure=1&pinSHA256={}", m.leaf_pin()));
    }
    if let Some(password) = &spec.hy2.obfs_password {
        query.push_str(&format!(
            "&obfs=salamander&obfs-password={}",
            url_encode(password)
        ));
    }
    if let Some(hop) = spec.hy2.hop {
        query.push_str(&format!("&mport={}", url_encode(&hop.to_string())));
    }
    Ok(query)
}

/// `vmess://` + base64 (standard, padded) of compact JSON, keys sorted.
fn vmess(spec: &NodeSpec, ib: &InboundSpec) -> Result<String> {
    let tls = if spec.vmess.tls {
        Some(spec.tls()?)
    } else {
        None
    };
    // Plain VMess leaves every TLS field empty (v2 shape).
    let (security, sni, alpn, fp) = match tls {
        Some(tls) => (
            "tls",
            tls.server_name.as_str(),
            "http/1.1",
            policy::FINGERPRINT,
        ),
        None => ("", "", "", ""),
    };
    let mut config = json!({
        "v": "2", "ps": ib.label, "add": spec.server_host(), "port": ib.port.to_string(),
        "id": spec.creds.uuid, "aid": "0", "scy": "auto", "net": "ws", "type": "none",
        "host": spec.vmess.ws_host.as_deref().unwrap_or(""), "path": spec.creds.vmess_path,
        "tls": security, "sni": sni, "alpn": alpn, "fp": fp,
    });
    if let Some(material) = tls.map(TlsSpec::pin).transpose()?.flatten() {
        config.set("insecure", "1");
        config.set("pcs", material.leaf_pin());
    }
    Ok(format!(
        "vmess://{}",
        STANDARD.encode(serde_json::to_vec(&config)?)
    ))
}

/// One link per supported protocol, each line ending in `"\n"`. `format`
/// only names the export in the "no supported node" error.
fn lines(spec: &NodeSpec, format: ClientFormat) -> Result<String> {
    let links = super::nodes_for(spec, format)?
        .into_iter()
        .map(|ib| link(spec, ib))
        .collect::<Result<Vec<_>>>()?;
    Ok(format!("{}\n", links.join("\n")))
}

/// Links of every supported protocol, one per line, ending in `"\n"`.
pub fn links_text(spec: &NodeSpec) -> Result<String> {
    lines(spec, ClientFormat::Links)
}

/// Base64 subscription: standard base64 of the links text (including its
/// final newline) plus `"\n"`.
pub fn subscription(spec: &NodeSpec) -> Result<String> {
    Ok(format!(
        "{}\n",
        STANDARD.encode(lines(spec, ClientFormat::Base64)?)
    ))
}

#[cfg(test)]
mod tests;
