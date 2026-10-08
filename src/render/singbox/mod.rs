//! sing-box documents: the server configuration and the full client
//! configurations (TUN and mixed-port only), built from the per-protocol
//! inbounds and outbounds of the submodules.
//!
//! Schema: sing-box ≥ 1.12 (typed DNS servers, rule actions,
//! `default_domain_resolver`); Hysteria2 tuning keys need ≥ 1.14 and are
//! emitted only when tuning is configured.
//!
//! Changes from v2: none in the output. The clash API is always present
//! because `NodeConfig::validate` guarantees a controller secret (v2 dropped
//! it for legacy states without one).

mod inbound;
mod outbound;

pub use inbound::{inbound, shadowtls_backend};
pub use outbound::{outbound, shadowtls_transport};

use super::json::ObjectExt;
use super::policy;
use super::spec::NodeSpec;
use crate::domain::defaults;
use crate::domain::protocol::{ClientFormat, Core, Protocol};
use crate::error::Result;
use serde_json::{json, Value};

/// sing-box server configuration for every inbound it hosts.
pub fn server(spec: &NodeSpec) -> Result<Value> {
    let mut inbounds = Vec::new();
    for ib in spec.on_core(Core::Singbox) {
        inbounds.push(inbound(spec, ib)?);
        if ib.protocol == Protocol::Shadowtls {
            inbounds.push(shadowtls_backend(spec));
        }
    }
    ensure!(!inbounds.is_empty(), "没有分配给 singbox 的协议");
    let strategy = policy::singbox_strategy(spec.routing.families);
    Ok(json!({
        "log": {"level": "warn", "timestamp": true},
        "dns": {"servers": [{"type": "local", "tag": "local"}]},
        "inbounds": inbounds,
        "outbounds": [{"type": "direct", "tag": "direct"}],
        "route": {
            "rules": policy::singbox_server_rules(spec),
            "default_domain_resolver": {"server": "local", "strategy": strategy},
            "final": "direct",
        },
    }))
}

/// Full sing-box client: `proxy` selector over an `auto` url-test of every
/// node, a local mixed port, and the TUN inbound when `tun`.
pub fn client(spec: &NodeSpec, tun: bool) -> Result<Value> {
    let format = if tun {
        ClientFormat::Singbox
    } else {
        ClientFormat::SingboxNoTun
    };
    let nodes = super::nodes_for(spec, format)?;
    let names: Vec<&str> = nodes.iter().map(|n| n.label.as_str()).collect();
    let mut selection = vec!["auto"];
    selection.extend(&names);
    selection.push("direct");
    let mut outbounds = vec![
        json!({"type": "selector", "tag": "proxy", "outbounds": selection, "default": "auto"}),
        json!({"type": "urltest", "tag": "auto", "outbounds": names, "url": policy::URL_TEST,
            "interval": policy::SINGBOX_URL_TEST_INTERVAL, "tolerance": policy::URL_TEST_TOLERANCE}),
    ];
    for node in &nodes {
        outbounds.push(outbound(spec, node)?);
        if node.protocol == Protocol::Shadowtls {
            outbounds.push(shadowtls_transport(spec)?);
        }
    }
    outbounds.push(json!({"type": "direct", "tag": "direct"}));
    let mut doc = json!({
        "log": {"level": "info", "timestamp": true},
        "dns": client_dns(spec),
        "inbounds": client_inbounds(tun),
        "outbounds": outbounds,
        "route": {
            "rules": policy::singbox_client_route_rules(&spec.direct),
            "rule_set": policy::singbox_rule_sets(),
            "final": "proxy",
            "auto_detect_interface": true,
            "default_domain_resolver": "dns-direct",
        },
    });
    doc.set("experimental", experimental(spec));
    Ok(doc)
}

fn client_dns(spec: &NodeSpec) -> Value {
    json!({
        "servers": [
            {"type": "https", "tag": "dns-remote", "server": policy::DNS_REMOTE,
                "tls": {"server_name": policy::DNS_REMOTE_TLS_NAME}, "detour": "proxy"},
            {"type": "udp", "tag": "dns-direct", "server": policy::DNS_DIRECT},
        ],
        "rules": policy::singbox_client_dns_rules(&spec.direct),
        "final": "dns-remote",
        "strategy": "prefer_ipv4",
    })
}

fn client_inbounds(tun: bool) -> Vec<Value> {
    let mut inbounds = Vec::new();
    if tun {
        inbounds.push(
            json!({"type": "tun", "tag": "tun-in", "address": policy::TUN_ADDRESSES,
            "auto_route": true, "strict_route": true, "stack": "mixed"}),
        );
    }
    inbounds.push(
        json!({"type": "mixed", "tag": "mixed-in", "listen": policy::LOOPBACK,
        "listen_port": defaults::SINGBOX_MIXED_PORT}),
    );
    inbounds
}

/// Cache file plus the local clash API; the controller is only ever
/// exposed with a secret, on loopback.
fn experimental(spec: &NodeSpec) -> Value {
    let mut v = json!({"cache_file": {"enabled": true}});
    if !spec.creds.clash_secret.is_empty() {
        v.set(
            "clash_api",
            json!({"external_controller": policy::controller(),
                "secret": spec.creds.clash_secret, "default_mode": "Rule"}),
        );
    }
    v
}

/// `utls` object shared by every uTLS-capable client outbound.
pub(super) fn utls() -> Value {
    json!({"enabled": true, "fingerprint": policy::FINGERPRINT})
}

/// sing-box WebSocket transport; clients add the `Host` header.
pub(super) fn ws_transport(path: &str, host: Option<&str>) -> Value {
    let mut v = json!({"type": "ws", "path": path, "max_early_data": policy::WS_EARLY_DATA,
        "early_data_header_name": policy::WS_EARLY_DATA_HEADER});
    if let Some(host) = host.filter(|h| !h.is_empty()) {
        v.set("headers", json!({"Host": host}));
    }
    v
}

pub(super) fn grpc_transport(spec: &NodeSpec) -> Value {
    json!({"type": "grpc", "service_name": spec.creds.grpc_service})
}

#[cfg(test)]
mod tests;
