//! Probe bundle (schema 1): the client outbounds `probe`, `bench`,
//! `failover` and `reality-check` start local client cores with. The typed
//! structs are shared with `linktools`, which loads ([`ProbeBundle::load`]),
//! merges ([`ProbeBundle::merge`]) and exports ([`bundle`]) through them.
//!
//! JSON shape (keys sorted on output, identical to v2):
//! `{"schema":1,"entries":[{"id","core","transport","tag","outbounds":[…],"reality"?:{…}}]}`.
//! Unknown entry keys survive load → export (v2 passed entries through).
//!
//! Changes from v2:
//! - bundles are typed and validated on export too, with v2's rules and
//!   messages (v2 validated only on load);
//! - the loopback view connects to the listen address when it is a specific
//!   address (C-8.1 #21);
//! - the client core is chosen by one rule, `policy::client_core` (C-8.1 #18);
//! - a `reality.reference_*` of the wrong type is rejected on load
//!   (`REALITY 元数据无效`) instead of failing later at use; unknown keys inside
//!   `reality` are not kept;
//! - a bundle file must be a regular file (v2 followed symlinks and read
//!   FIFOs); the size cap still bounds the read itself, as in v2;
//! - a merge is checked against the size cap too, so it always loads again.

use super::spec::{InboundSpec, NodeSpec};
use super::{json, policy, singbox, xray};
use crate::domain::protocol::{Core, Protocol, Transport};
use crate::error::{Error, Result};
use crate::sys::fs::read_bounded;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::path::Path;

pub const SCHEMA: u32 = 1;
/// Largest bundle file accepted (and produced).
pub const MAX_BYTES: usize = 2 * 1024 * 1024;
pub const MAX_ENTRIES: usize = 32;
pub const MAX_ID_BYTES: usize = 80;
/// Outbound kinds a bundle may contain per client core (never direct/block).
pub const SINGBOX_KINDS: [&str; 8] = [
    "vless",
    "vmess",
    "trojan",
    "shadowsocks",
    "hysteria2",
    "tuic",
    "anytls",
    "shadowtls",
];
pub const XRAY_KINDS: [&str; 5] = ["vless", "vmess", "trojan", "shadowsocks", "hysteria"];
const TOO_LARGE: &str = "探测配置超过 2 MiB";

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ProbeBundle {
    pub schema: u32,
    pub entries: Vec<ProbeEntry>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ProbeEntry {
    /// `[A-Za-z0-9_.-]{1,80}`, unique; the protocol id (merges prefix it).
    pub id: String,
    pub core: Core,
    pub transport: Transport,
    /// Tag of the primary outbound (`outbounds[0]`).
    pub tag: String,
    /// The primary client outbound plus, for ShadowTLS, its transport.
    pub outbounds: Vec<Value>,
    /// REALITY endpoints, for REALITY protocols only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reality: Option<RealityProbe>,
    /// Keys this version does not know (kept on load → export).
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RealityProbe {
    pub host: String,
    pub port: u16,
    pub sni: String,
    /// Site the REALITY fallback must look like; `("", 0)` when there is
    /// nothing public to compare with (own site without HTTPS entry).
    #[serde(default)]
    pub reference_host: String,
    #[serde(default)]
    pub reference_port: u16,
}

impl ProbeBundle {
    /// Read and parse a bundle file. At most [`MAX_BYTES`] are read, so an
    /// oversized file is refused without loading it.
    pub fn load(path: &Path) -> Result<ProbeBundle> {
        let limit = MAX_BYTES as u64;
        let bytes = read_bounded(path, limit).map_err(|e| {
            let oversized =
                fs::symlink_metadata(path).is_ok_and(|m| m.is_file() && m.len() > limit);
            if oversized {
                Error::msg(TOO_LARGE)
            } else {
                e
            }
        })?;
        Self::parse(&bytes)
    }

    /// `probe merge`: the entries of every input in order, each id prefixed
    /// with `n{i}-` (`i` = 1-based input position, as v2) so equal protocol
    /// ids of different servers stay distinct; the result is validated like
    /// any bundle (1–32 entries, id length, size cap).
    pub fn merge(inputs: &[ProbeBundle]) -> Result<ProbeBundle> {
        let entries = inputs
            .iter()
            .enumerate()
            .flat_map(|(i, input)| {
                input.entries.iter().map(move |e| ProbeEntry {
                    id: format!("n{}-{}", i + 1, e.id),
                    ..e.clone()
                })
            })
            .collect();
        let merged = ProbeBundle {
            schema: SCHEMA,
            entries,
        };
        merged.validate()?;
        Ok(merged)
    }

    /// Parse a bundle file's bytes (size cap, JSON, v2 validation rules).
    pub fn parse(bytes: &[u8]) -> Result<ProbeBundle> {
        ensure!(bytes.len() <= MAX_BYTES, "{TOO_LARGE}");
        let value: Value =
            serde_json::from_slice(bytes).map_err(|_| Error::msg("探测配置不是有效 JSON"))?;
        Self::from_value(value)
    }

    /// Validate an untyped bundle with v2's rules and messages, then type it.
    pub fn from_value(value: Value) -> Result<ProbeBundle> {
        check(&value)?;
        // `check` accepted every typed field except `reality.reference_*`,
        // so a typing failure can only come from those.
        serde_json::from_value(value).map_err(|_| Error::msg("REALITY 元数据无效"))
    }

    /// v2's load rules applied to this bundle, plus the size cap of its
    /// pretty serialization (so every exported bundle loads again).
    pub fn validate(&self) -> Result<()> {
        check(&self.to_value()?)?;
        ensure!(self.to_json()?.len() <= MAX_BYTES, "{TOO_LARGE}");
        Ok(())
    }

    pub fn to_value(&self) -> Result<Value> {
        Ok(serde_json::to_value(self)?)
    }

    /// Pretty JSON with sorted keys and no trailing newline (`probe.json`).
    pub fn to_json(&self) -> Result<String> {
        json::pretty(&self.to_value()?)
    }
}

/// The bundle of every enabled protocol. `local` targets the node from the
/// server itself (see [`NodeSpec::local`]).
pub fn bundle(spec: &NodeSpec, local: bool) -> Result<ProbeBundle> {
    let local_spec;
    let view = if local {
        local_spec = spec.local();
        &local_spec
    } else {
        spec
    };
    let entries = view
        .inbounds
        .iter()
        .map(|ib| entry(view, ib, local))
        .collect::<Result<Vec<_>>>()?;
    ensure!(!entries.is_empty(), "没有可导出的节点");
    let bundle = ProbeBundle {
        schema: SCHEMA,
        entries,
    };
    bundle.validate()?;
    Ok(bundle)
}

fn entry(spec: &NodeSpec, ib: &InboundSpec, local: bool) -> Result<ProbeEntry> {
    let p = ib.protocol;
    let core = policy::client_core(p, ib.core);
    let (mut primary, tag) = match core {
        Core::Xray => (xray::outbound(spec, ib)?, "proxy".to_owned()),
        Core::Singbox => (singbox::outbound(spec, ib)?, ib.label.clone()),
    };
    json::ObjectExt::set(&mut primary, "tag", tag.as_str());
    let mut outbounds = vec![primary];
    if p == Protocol::Shadowtls {
        outbounds.push(singbox::shadowtls_transport(spec)?);
    }
    Ok(ProbeEntry {
        id: p.id().to_owned(),
        core,
        transport: p.transport(),
        tag,
        outbounds,
        reality: reality(spec, ib, local)?,
        extra: BTreeMap::new(),
    })
}

/// REALITY metadata: the node endpoint and the reference site the fallback
/// should match (the own site's public HTTPS entrance, or nothing to
/// compare without one; the handshake target otherwise and when local).
fn reality(spec: &NodeSpec, ib: &InboundSpec, local: bool) -> Result<Option<RealityProbe>> {
    if !ib.protocol.reality() {
        return Ok(None);
    }
    let r = spec.reality()?;
    let (reference_host, reference_port) = match spec.site.as_ref().filter(|_| !local) {
        Some(site) if site.https_entry => (spec.server_host(), crate::domain::defaults::HTTPS_PORT),
        Some(_) => (String::new(), 0),
        None => (r.dest.host.to_string(), r.dest.port),
    };
    Ok(Some(RealityProbe {
        host: spec.server_host(),
        port: ib.port,
        sni: r.sni.clone(),
        reference_host,
        reference_port,
    }))
}

/// v2 `validate_bundle`, rule for rule and message for message.
fn check(value: &Value) -> Result<()> {
    ensure!(
        value.get("schema").and_then(Value::as_u64) == Some(u64::from(SCHEMA)),
        "探测配置 schema 无效"
    );
    let entries = value
        .get("entries")
        .and_then(Value::as_array)
        .ok_or_else(|| Error::msg("探测配置缺少 entries"))?;
    ensure!(
        (1..=MAX_ENTRIES).contains(&entries.len()),
        "配置需要 1 至 32 个入口"
    );
    let mut ids = HashSet::new();
    for entry in entries {
        let id = entry
            .get("id")
            .and_then(Value::as_str)
            .ok_or_else(|| Error::msg("入口 ID 无效"))?;
        ensure!(valid_id(id) && ids.insert(id), "入口 ID 无效或重复");
        check_entry(entry)?;
    }
    Ok(())
}

fn valid_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= MAX_ID_BYTES
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b))
}

fn check_entry(entry: &Value) -> Result<()> {
    let core = entry.get("core").and_then(Value::as_str).unwrap_or("");
    let transport = entry.get("transport").and_then(Value::as_str);
    ensure!(
        matches!(core, "singbox" | "xray") && matches!(transport, Some("tcp" | "udp" | "both")),
        "入口类型无效"
    );
    let outbounds = entry
        .get("outbounds")
        .and_then(Value::as_array)
        .filter(|o| (1..=2).contains(&o.len()))
        .ok_or_else(|| Error::msg("入口出站无效"))?;
    let (kind_key, kinds): (&str, &[&str]) = if core == "singbox" {
        ("type", &SINGBOX_KINDS)
    } else {
        ("protocol", &XRAY_KINDS)
    };
    let mut tags = HashSet::new();
    for outbound in outbounds {
        let kind = outbound.get(kind_key).and_then(Value::as_str).unwrap_or("");
        ensure!(
            kinds.contains(&kind),
            "出站包含未支持的协议；不允许 direct/block"
        );
        let tag = outbound
            .get("tag")
            .and_then(Value::as_str)
            .ok_or_else(|| Error::msg("出站标签无效"))?;
        ensure!(!tag.is_empty() && tags.insert(tag), "出站标签无效或重复");
    }
    let primary = outbounds.first().and_then(|o| o.get("tag"));
    ensure!(
        entry.get("tag").and_then(Value::as_str).is_some() && entry.get("tag") == primary,
        "出站标签不匹配"
    );
    if let Some(meta) = entry.get("reality") {
        check_reality(meta)?;
    }
    Ok(())
}

fn check_reality(meta: &Value) -> Result<()> {
    for key in ["host", "sni"] {
        let present = meta
            .get(key)
            .and_then(Value::as_str)
            .is_some_and(|s| !s.is_empty());
        ensure!(present, "REALITY 元数据无效");
    }
    ensure!(
        matches!(meta.get("port").and_then(Value::as_u64), Some(1..=65535)),
        "REALITY 端口无效"
    );
    Ok(())
}

#[cfg(test)]
mod tests;
