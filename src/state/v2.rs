//! v2 state migration: `{"values":{KEY:"string"}}` (+ v2
//! `subscription/settings.json`) → `NodeConfig` schema 3.
//!
//! Every key of spec A §3.4 is read with the semantics v2 actually used.
//! Policy for questionable values:
//! - a value clients depend on (credentials, keys, ports, targets) that is
//!   present but invalid is an error — guessing would silently break clients;
//! - a missing credential is generated (with a warning when an enabled
//!   protocol uses it, because those clients must be updated);
//! - a value v2 never applied (stale tuning, an invalid hop range on a node
//!   without Hysteria2, unknown keys) is dropped with a warning.
//!
//! Decisions on v2 inconsistencies (spec A §8.1 #2):
//! - site internal port: the port in `REALITY_DEST` (`127.0.0.1:N`) while the
//!   site is enabled (that is what v2 rendered), else `REALITY_SITE_PORT`,
//!   else 10443;
//! - `REALITY_SITE_HTTPS` absent/empty with the site enabled = on: v2
//!   `site::prepare` wrote `1` into an empty value on the first apply and the
//!   workflow port checks treated absent as on;
//! - `SHADOWTLS_DEST` is dropped when it equals `{SHADOWTLS_SNI}:443` (the
//!   v3 default) and kept otherwise, so the handshake target v2 used is
//!   preserved exactly;
//! - `ACME_METHOD` `standalone`, `http` and empty all mean HTTP-01;
//! - `*_VERSION_WANT=latest` means no pin.

mod features;
mod fields;

use crate::domain::config::{Device, NodeConfig, SCHEMA};
use crate::domain::ports::{NoProbe, PortPlan};
use crate::error::{Context, Result};
use crate::sys::rand::Random;
use serde_json::Value;
use std::collections::BTreeMap;

/// Result of a v2 migration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Migrated {
    pub config: NodeConfig,
    /// Subscription devices from v2 `settings.json` (`None` without the file).
    pub devices: Option<Vec<Device>>,
    /// Chinese notes about generated, normalized or dropped values.
    pub warnings: Vec<String>,
}

/// Parse the v2 file shape `{"values":{…}}`; every value must be a string.
/// A missing `values` member yields an empty map (migration then reports
/// the missing protocol list, as v2 did).
pub fn v2_values_from_json(bytes: &[u8]) -> Result<BTreeMap<String, String>> {
    let doc: Value = serde_json::from_slice(bytes).context("v2 state.json 无效")?;
    let root = doc.as_object().ok_or("v2 state.json 必须是 JSON 对象")?;
    let Some(values) = root.get("values") else {
        return Ok(BTreeMap::new());
    };
    let values = values
        .as_object()
        .ok_or("v2 state.json 的 values 必须是对象")?;
    values
        .iter()
        .map(|(k, v)| match v {
            Value::String(s) => Ok((k.clone(), s.clone())),
            _ => Err(crate::Error::msg(format!("v2 状态值必须为字符串: {k}"))),
        })
        .collect()
}

/// Convert v2 values (and the v2 subscription settings, when the file
/// exists) into a validated schema-3 configuration. `rng` fills credentials
/// v2 never generated (v1-era states).
pub fn migrate(
    values: &BTreeMap<String, String>,
    subscription_settings: Option<&Value>,
    rng: &mut dyn Random,
) -> Result<Migrated> {
    let mut v = fields::V2::new(values);
    let inbounds = v.inbounds()?;
    let creds = v.credentials(&inbounds, rng)?;
    let mut config = NodeConfig {
        schema: SCHEMA,
        node_name: v.node_name(),
        server: v.server()?,
        listen: v.listen()?,
        inbounds,
        creds,
        reality: v.reality_target()?,
        shadowtls: v.shadowtls()?,
        site: None,
        tls: None,
        vmess_tls: false,
        hy2: Default::default(),
        resource_profile: Default::default(),
        routing: v.routing(),
        subscription: None,
        versions: v.versions(),
        installed_at: v.installed_at(),
    };
    v.site(&mut config)?;
    v.tls(&mut config)?;
    v.tuning(&mut config);
    assign_guard(&mut v, &mut config)?;
    let (subscription, devices) = match subscription_settings {
        Some(settings) => {
            let (sub, devices) = v.subscription(&config, settings)?;
            (sub, Some(devices))
        }
        None => (None, None),
    };
    config.subscription = subscription;
    v.report_unknown_keys();
    config.validate().context("v2 状态迁移失败")?;
    Ok(Migrated {
        config,
        devices,
        warnings: v.into_warnings(),
    })
}

/// v2 always stored a guard port; allocate one deterministically when a
/// v1-era state lacks it (no live probe: migration is pure).
fn assign_guard(v: &mut fields::V2, config: &mut NodeConfig) -> Result<()> {
    if config.reality.guard_port != 0 {
        return Ok(());
    }
    let port = PortPlan::of(config, &[]).allocate_guard(&NoProbe, None)?;
    config.reality.guard_port = port;
    if config.uses_guard() {
        v.warn(format!("v2 状态缺少 REALITY_GUARD_PORT，已分配 {port}"));
    }
    Ok(())
}

#[cfg(test)]
mod tests;
