//! Pure renderers for server configs, client configs, share links,
//! subscriptions and probe bundles.
//!
//! Input is a [`NodeSpec`] (validated `NodeConfig` + certificate material);
//! output is a `serde_json::Value` or text. The only I/O in this module tree
//! is loading the certificate PEM ([`TlsMaterial::load`],
//! [`NodeSpec::load`]) and the atomic client-directory publish
//! ([`publish::write_clients`]).
//!
//! Output formats are byte-compatible with v2.0.1 (golden tests in
//! `tests/golden/`): JSON objects serialize with sorted keys; client exports
//! end in exactly one `"\n"`; server configs and `probe.json` have none.
//!
//! Changes from v2 (details in each module):
//! - one validated input type instead of string lookups (C-8.1 #1, #5, #6,
//!   #9, #12, #20: no panics, no late parse errors);
//! - certificate read once per render (#13);
//! - Xray Hysteria2 masquerade only without obfuscation (#3);
//! - `mihomo.yaml` / `provider.yaml` are real YAML (v2 wrote pretty JSON);
//! - a format without supported nodes names itself and the usable formats
//!   (#17: v2 said `links` for `base64`);
//! - client publication sweeps leftovers and reports cleanup failures (#15);
//! - the probe's loopback view honors a specific listen address (#21);
//! - plain VMess-WS sends `vmess_host` as `Host` (ARCH §10).

pub mod links;
pub mod mihomo;
pub mod policy;
pub mod probe;
pub mod publish;
pub mod singbox;
pub mod spec;
pub mod tls;
pub mod xray;
pub mod yaml;

mod json;

#[cfg(test)]
pub(crate) mod fixtures;
#[cfg(test)]
mod golden;

pub use json::{pretty, pretty_line};
pub use probe::ProbeBundle;
pub use publish::{write_clients, Published};
pub use spec::{InboundSpec, NodeSpec};
pub use tls::TlsMaterial;

use crate::domain::protocol::{ClientFormat, Core, Protocol};
use crate::error::{Error, Result};
use serde_json::Value;

/// Server configuration of `core` (every inbound it hosts).
pub fn server(spec: &NodeSpec, core: Core) -> Result<Value> {
    match core {
        Core::Singbox => singbox::server(spec),
        Core::Xray => xray::server(spec),
    }
}

/// Server configuration file text (pretty JSON, no trailing newline).
pub fn server_text(spec: &NodeSpec, core: Core) -> Result<String> {
    pretty(&server(spec, core)?)
}

/// The public inbound of an enabled protocol, on the core that hosts it.
pub fn inbound(spec: &NodeSpec, protocol: Protocol) -> Result<Value> {
    let ib = spec.require(protocol)?;
    match ib.core {
        Core::Singbox => singbox::inbound(spec, ib),
        Core::Xray => xray::inbound(spec, ib),
    }
}

/// The primary client outbound of an enabled protocol for a `core` client.
pub fn outbound(spec: &NodeSpec, protocol: Protocol, core: Core) -> Result<Value> {
    let ib = spec.require(protocol)?;
    let format = client_format(core);
    ensure!(format.supports(protocol), "{core} 客户端不支持 {protocol}");
    match core {
        Core::Singbox => singbox::outbound(spec, ib),
        Core::Xray => xray::outbound(spec, ib),
    }
}

/// The full client document format of a client core.
fn client_format(core: Core) -> ClientFormat {
    match core {
        Core::Singbox => ClientFormat::Singbox,
        Core::Xray => ClientFormat::Xray,
    }
}

/// Exact text of a client export (ends in one `"\n"`).
pub fn client(spec: &NodeSpec, format: ClientFormat) -> Result<String> {
    match format {
        ClientFormat::Links => links::links_text(spec),
        ClientFormat::Base64 => links::subscription(spec),
        ClientFormat::Mihomo => Ok(yaml::to_yaml(&mihomo::config(spec)?)),
        ClientFormat::Provider => Ok(yaml::to_yaml(&mihomo::provider(spec)?)),
        ClientFormat::Singbox => pretty_line(&singbox::client(spec, true)?),
        ClientFormat::SingboxNoTun => pretty_line(&singbox::client(spec, false)?),
        ClientFormat::Xray => pretty_line(&xray::client(spec)?),
    }
}

/// Inbounds `format` can carry; none is an error naming the usable formats.
pub(crate) fn nodes_for(spec: &NodeSpec, format: ClientFormat) -> Result<Vec<&InboundSpec>> {
    let nodes = spec.for_format(format);
    if !nodes.is_empty() {
        return Ok(nodes);
    }
    let usable: Vec<&str> = spec.formats().iter().map(|f| f.id()).collect();
    Err(Error::msg(format!(
        "当前协议组合没有支持 {} 格式的节点，请改用 {}",
        format.id(),
        usable.join(" / ")
    )))
}

#[cfg(test)]
mod tests;
