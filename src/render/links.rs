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
    use Protocol::*;
    let p = ib.protocol;
    ensure!(ClientFormat::Links.supports(p), "{p} 不支持通用分享链接");
    let at = format!("{}:{}", spec.uri_host(), ib.port);
    let name = url_encode(&ib.label);
    let uuid = url_encode(&spec.creds.uuid);
    let password = url_encode(&spec.creds.password);
    Ok(match p {
        VlessReality => format!(
            "vless://{uuid}@{at}?encryption=none&flow=xtls-rprx-vision&{}&type=tcp&headerType=none#{name}",
            reality_query(spec)?
        ),
        VlessXhttp => format!(
            "vless://{uuid}@{at}?encryption=none&{}&type=xhttp&path={}&mode=auto#{name}",
            reality_query(spec)?,
            url_encode(&spec.creds.xhttp_path)
        ),
        VlessGrpc => format!(
            "vless://{uuid}@{at}?encryption=none&{}&type=grpc&serviceName={}&mode=gun#{name}",
            reality_query(spec)?,
            url_encode(&spec.creds.grpc_service)
        ),
        VlessWs => {
            let tls = spec.tls()?;
            let sni = url_encode(&tls.server_name);
            format!(
                "vless://{uuid}@{at}?encryption=none&security=tls&sni={sni}&fp=chrome&alpn=http%2F1.1{}&type=ws&host={sni}&path={}#{name}",
                pin_query(tls)?,
                url_encode(&spec.creds.ws_path)
            )
        }
        VmessWs => vmess(spec, ib)?,
        Trojan => {
            let tls = spec.tls()?;
            format!(
                "trojan://{password}@{at}?security=tls&sni={}&fp=chrome&alpn=h2%2Chttp%2F1.1{}&type=tcp&headerType=none#{name}",
                url_encode(&tls.server_name),
                pin_query(tls)?
            )
        }
        Shadowsocks => {
            let creds = &spec.creds;
            let auth = URL_SAFE_NO_PAD.encode(format!("{}:{}", creds.ss_method, creds.ss_password));
            format!("ss://{auth}@{at}#{name}")
        }
        Hysteria2 => format!("hysteria2://{password}@{at}/?{}#{name}", hysteria2_query(spec)?),
        Tuic => {
            let tls = spec.tls()?;
            let trust = if tls.pinned() {
                "&allow_insecure=1&insecure=1"
            } else {
                ""
            };
            format!(
                "tuic://{uuid}:{password}@{at}?sni={}&alpn=h3&congestion_control=bbr&udp_relay_mode=native{trust}#{name}",
                url_encode(&tls.server_name)
            )
        }
        Anytls => {
            let tls = spec.tls()?;
            let trust = match tls.pin()? {
                Some(m) => format!("&insecure=1&hpkp={}", m.leaf_pin()),
                None => String::new(),
            };
            format!(
                "anytls://{password}@{at}/?sni={}{trust}#{name}",
                url_encode(&tls.server_name)
            )
        }
        Shadowtls | AnytlsReality => bail!("{p} 不支持通用分享链接"),
    })
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
    let mut query = format!("sni={}&alpn=h3", url_encode(&tls.server_name));
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
        Some(tls) => ("tls", tls.server_name.as_str(), "http/1.1", policy::FINGERPRINT),
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
    Ok(format!("vmess://{}", STANDARD.encode(serde_json::to_vec(&config)?)))
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
