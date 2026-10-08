//! v2 `subscription/settings.json` (spec G §3.2) → endpoint settings and
//! devices. The `SUBSCRIPTION_*` mirror keys in `state.json` are ignored.

use super::features::deployed_pair;
use super::fields::V2;
use crate::domain::config::*;
use crate::domain::validate::{valid_domain, valid_text};
use crate::error::{Error, Result};
use serde::Deserialize;
use serde_json::Value;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

/// v2 `subscription/settings.json` (spec G §3.2). Fields default leniently;
/// the values are validated below.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct Settings {
    enabled: bool,
    mode: String,
    domain: String,
    port: u16,
    method: String,
    custom_cert: Option<PathBuf>,
    custom_key: Option<PathBuf>,
    devices: Vec<Device>,
}

impl V2<'_> {
    /// v2 `settings.json` → endpoint settings (only when enabled) and the
    /// device list (always, so tokens survive a later re-enable).
    pub(super) fn subscription(
        &mut self,
        cfg: &NodeConfig,
        settings: &Value,
    ) -> Result<(Option<SubscriptionConfig>, Vec<Device>)> {
        let s = Settings::deserialize(settings)
            .map_err(|e| Error::msg(format!("v2 订阅设置无效: {e}")))?;
        let devices = self.devices(&s.devices);
        if !s.enabled {
            return Ok((None, devices));
        }
        let mode = match s.mode.as_str() {
            "ip" => SubscriptionMode::Ip {
                address: s
                    .domain
                    .trim()
                    .parse::<IpAddr>()
                    .map_err(|_| Error::msg(format!("v2 订阅地址无效: {}", s.domain)))?
                    .to_canonical(),
            },
            "site" if cfg.site_active().is_none() => {
                self.warn("v2 订阅复用的网站未启用，订阅已关闭（设备保留）");
                return Ok((None, devices));
            }
            "site" => SubscriptionMode::Site,
            "standalone" => self.standalone(&s)?,
            other => bail!("v2 订阅托管模式无效: {other}"),
        };
        let port = if mode == SubscriptionMode::Site {
            cfg.site_public_port()
        } else {
            s.port
        };
        Ok((Some(SubscriptionConfig { mode, port }), devices))
    }

    fn devices(&mut self, list: &[Device]) -> Vec<Device> {
        let mut out: Vec<Device> = Vec::new();
        for device in list {
            let duplicate = out.iter().any(|d| d.id == device.id);
            if valid_device(device) && !duplicate {
                out.push(device.clone());
            } else {
                self.warn(format!("v2 订阅设备数据无效，已忽略: {:?}", device.id));
            }
        }
        out
    }

    fn standalone(&mut self, s: &Settings) -> Result<SubscriptionMode> {
        let domain = s.domain.trim().to_ascii_lowercase();
        ensure!(valid_domain(&domain), "v2 订阅域名无效: {}", s.domain);
        let cert = match s.method.as_str() {
            "cf" => WebCert::Cloudflare,
            "http" => WebCert::Http01,
            "custom" => {
                let sources = [
                    ("custom_cert", path_text(s.custom_cert.as_deref())),
                    ("custom_key", path_text(s.custom_key.as_deref())),
                ];
                let deployed = deployed_pair(&self.deployed.subscription);
                let (cert, key) = self.source_pair("订阅", sources, deployed);
                WebCert::Custom { cert, key }
            }
            other => bail!("v2 订阅证书方式无效: {other}"),
        };
        Ok(SubscriptionMode::Standalone {
            domain,
            http01_port80: cert == WebCert::Http01,
            cert,
        })
    }
}

fn path_text(path: Option<&Path>) -> Option<&str> {
    path.and_then(Path::to_str)
        .map(str::trim)
        .filter(|p| !p.is_empty())
}

/// v2 `validate_settings` device rules.
fn valid_device(d: &Device) -> bool {
    let lower_hex = |s: &str, n: usize| {
        s.len() == n
            && s.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    };
    lower_hex(&d.id, 16)
        && lower_hex(&d.hash, 64)
        && !d.name.is_empty()
        && d.name.len() <= 80
        && valid_text(&d.name)
}
