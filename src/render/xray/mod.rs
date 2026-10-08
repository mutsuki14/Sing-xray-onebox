//! Xray documents: the server configuration (with the REALITY guard) and
//! the client configuration.
//!
//! Schema: Xray 26.x (tested 26.3.27): `raw` network, `realitySettings.target`,
//! `xhttp`, `hysteria` v2 with `finalmask`, `pinnedPeerCertSha256`, freedom
//! `finalRules`.
//!
//! The REALITY guard: Xray REALITY inbounds never handshake with the target
//! directly. Their `target` is a loopback dokodemo inbound that forwards only
//! the exact REALITY SNI (to the own site or the configured target) and
//! black-holes every other probe, so the node cannot be used as a free relay.
//!
//! Changes from v2:
//! - an Xray Hysteria2 server masquerades only without obfuscation, like
//!   sing-box (v2 always set the masquerade, C-8.1 #3);
//! - the XHTTP fallback socket is a constant (C-8.1 #8);
//! - the own site's loopback port comes from one setting (v2 rendered the
//!   dokodemo target from `REALITY_DEST` and the redirect from
//!   `REALITY_SITE_PORT`, which could disagree).
//!
//! Kept from v2 (C-8.1 #10): the client document routes through its first
//! outbound only (`proxy`); the others carry their protocol id as tag.

mod inbound;
mod outbound;

pub use inbound::{guard_inbound, inbound};
pub use outbound::outbound;

use super::json::ObjectExt;
use super::policy;
use super::spec::NodeSpec;
use crate::domain::defaults;
use crate::domain::protocol::{ClientFormat, Core};
use crate::error::Result;
use serde_json::{json, Value};

/// Xray server configuration for every inbound it hosts, plus the guard.
pub fn server(spec: &NodeSpec) -> Result<Value> {
    let mut inbounds = spec
        .on_core(Core::Xray)
        .map(|ib| inbound(spec, ib))
        .collect::<Result<Vec<_>>>()?;
    ensure!(!inbounds.is_empty(), "没有分配给 xray 的协议");
    let mut outbounds = vec![direct_outbound(spec)];
    if spec.uses_xray_reality() {
        inbounds.push(guard_inbound(spec.reality()?));
        if let Some(site) = &spec.site {
            outbounds.push(site_outbound(site.internal_port));
        }
    }
    outbounds.push(json!({"tag": "block", "protocol": "blackhole"}));
    let strategy = if spec.routing.block_private {
        "IPIfNonMatch"
    } else {
        "AsIs"
    };
    Ok(json!({
        "log": {"loglevel": "warning", "access": "none"},
        "inbounds": inbounds,
        "outbounds": outbounds,
        "routing": {"domainStrategy": strategy, "rules": policy::xray_server_rules(spec)},
    }))
}

/// Egress. Without the private-address block, Xray 26's built-in denial of
/// private destinations is lifted explicitly.
fn direct_outbound(spec: &NodeSpec) -> Value {
    let strategy = policy::xray_strategy(spec.routing.families);
    let mut v = json!({"tag": "direct", "protocol": "freedom",
        "streamSettings": {"sockopt": {"domainStrategy": strategy}}});
    if !spec.routing.block_private {
        v.set("settings", json!({"finalRules": [{"action": "allow"}]}));
    }
    v
}

/// Guard target for the own site: only TCP to the site's loopback port.
fn site_outbound(port: u16) -> Value {
    json!({"tag": policy::XRAY_SITE_TAG, "protocol": "freedom", "settings": {
        "redirect": format!("{}:{port}", policy::LOOPBACK),
        "finalRules": [
            {"action": "allow", "network": "tcp", "ip": [format!("{}/32", policy::LOOPBACK)],
                "port": port.to_string()},
            {"action": "block"},
        ]}})
}

/// Xray client: local SOCKS and HTTP ports, the first supported node as
/// `proxy`.
pub fn client(spec: &NodeSpec) -> Result<Value> {
    let nodes = super::nodes_for(spec, ClientFormat::Xray)?;
    let mut outbounds = Vec::new();
    for (i, node) in nodes.iter().enumerate() {
        let mut v = outbound(spec, node)?;
        let tag = if i == 0 { "proxy" } else { node.protocol.id() };
        v.set("tag", tag);
        outbounds.push(v);
    }
    outbounds.push(json!({"tag": "direct", "protocol": "freedom"}));
    outbounds.push(json!({"tag": "block", "protocol": "blackhole"}));
    Ok(json!({
        "log": {"loglevel": "warning"},
        "dns": {"servers": policy::xray_client_dns_servers(&spec.direct), "queryStrategy": "UseIP"},
        "inbounds": [
            {"tag": "socks-in", "listen": policy::LOOPBACK, "port": defaults::XRAY_SOCKS_PORT,
                "protocol": "socks", "settings": {"udp": true}, "sniffing": sniffing()},
            {"tag": "http-in", "listen": policy::LOOPBACK, "port": defaults::XRAY_HTTP_PORT,
                "protocol": "http",
                "sniffing": {"enabled": true, "destOverride": ["http", "tls"], "routeOnly": true}},
        ],
        "outbounds": outbounds,
        "routing": {"domainStrategy": "IPIfNonMatch",
            "rules": policy::xray_client_rules(&spec.direct)},
    }))
}

/// Route-only sniffing of HTTP, TLS and QUIC.
pub(super) fn sniffing() -> Value {
    json!({"enabled": true, "destOverride": ["http", "tls", "quic"], "routeOnly": true})
}

#[cfg(test)]
mod tests;
