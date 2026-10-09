//! `subscription enable` options → a typed planner request (spec G §2.3).
//!
//! Mode when `--mode` is absent: an enabled subscription keeps its mode
//! (options of another mode are refused, [`OTHER_MODE`]); otherwise
//! `--address`/`--ip` → ip; `--domain` → standalone; an active own-domain
//! site → site; else ip. Per mode:
//! - ip: no `--domain/--tls/--cert/--key`; the address defaults to the
//!   node's own IP; port 8448 unless `--port`;
//! - site: the site's domain, certificate and public port;
//! - standalone: `--domain` required; `--tls cf` (default) | `http` |
//!   `custom` (with `--cert` and `--key`); port 8448 unless `--port`.
//!
//! What an enabled subscription already has is kept where an option is
//! omitted: the ip address, the standalone domain and certificate method
//! (and either path of a custom pair), and the port of an ip or
//! standalone endpoint (a site-mode endpoint's port is the site's, so it
//! is not carried over).
//!
//! Unknown, repeated and value-less options are rejected by the command
//! parser (`subscription enable 不支持选项 …`, `重复选项: …`,
//! `--port 需要参数`); the v2 texts below cover what it cannot see.
//!
//! Changes from v2: an invalid port is `订阅端口无效` instead of a raw
//! parse error; `--cert/--key` without `--tls custom` and `--tls custom`
//! without both paths are refused (v2 stored them and failed later);
//! options site mode ignores are named in a notice (v2 dropped them
//! silently); re-running `enable` on an enabled subscription changes only
//! what is given (v2 re-inferred the mode and reset omitted options, so
//! `enable --port 9443` could turn an HTTPS endpoint into plain HTTP).

use crate::cli::args::Matches;
use crate::domain::config::{NodeConfig, SubscriptionMode, WebCert};
use crate::domain::plan::SubscriptionChoice;
use crate::error::{Error, Result};
use std::net::IpAddr;
use std::path::PathBuf;

pub const BAD_MODE: &str = "订阅托管模式无效，请选择 ip/site/standalone";
pub const ADDRESS_NOT_IP: &str = "--address/--ip 仅用于 --mode ip";
pub const IP_NO_CERT: &str =
    "IP 订阅不使用域名或证书，请移除 --domain/--tls/--cert/--key，或选择 --mode standalone";
pub const NEEDS_DOMAIN: &str = "独立 HTTPS 订阅需要 --domain";
pub const BAD_ADDRESS: &str =
    "订阅地址必须是 IPv4 或 IPv6 字面地址，不能含域名、端口、路径或 zone ID";
pub const BAD_METHOD: &str = "订阅证书方式无效";
pub const BAD_PORT: &str = "订阅端口无效";
pub const CUSTOM_PATHS: &str = "--tls custom 需要同时提供 --cert 和 --key";
pub const PATHS_NOT_CUSTOM: &str = "--cert/--key 仅用于 --tls custom";
/// Options of another mode for an enabled subscription without `--mode`
/// (the end of `订阅当前为 MODE 模式，FLAGS 不适用；…`).
pub const OTHER_MODE: &str = "更换订阅模式请指定 --mode";

/// Hosting mode of an enable request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    Ip,
    Site,
    Standalone,
}

impl Mode {
    fn of(mode: &SubscriptionMode) -> Mode {
        match mode {
            SubscriptionMode::Ip { .. } => Mode::Ip,
            SubscriptionMode::Site => Mode::Site,
            SubscriptionMode::Standalone { .. } => Mode::Standalone,
        }
    }

    /// The `--mode` value.
    pub fn id(self) -> &'static str {
        match self {
            Mode::Ip => "ip",
            Mode::Site => "site",
            Mode::Standalone => "standalone",
        }
    }
}

/// The raw options of `subscription enable` (trimmed; never empty).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct EnableRequest {
    pub mode: Option<String>,
    /// `--address` or its alias `--ip`.
    pub address: Option<String>,
    pub domain: Option<String>,
    pub port: Option<String>,
    pub tls: Option<String>,
    pub cert: Option<String>,
    pub key: Option<String>,
    /// Name of the first device (only used when there is none).
    pub name: Option<String>,
}

impl EnableRequest {
    /// From parsed options (the option names of `subscription enable`).
    pub fn from_matches(m: &Matches) -> Result<EnableRequest> {
        ensure!(
            m.value("address").is_none() || m.value("ip").is_none(),
            "订阅参数重复: --address"
        );
        let get = |long: &str| -> Result<Option<String>> {
            match m.value(long).map(str::trim) {
                Some("") => Err(Error::msg(format!("订阅参数缺少值: --{long}"))),
                value => Ok(value.map(str::to_owned)),
            }
        };
        Ok(EnableRequest {
            mode: get("mode")?,
            address: get("address")?.or(get("ip")?),
            domain: get("domain")?,
            port: get("port")?,
            tls: get("tls")?,
            cert: get("cert")?,
            key: get("key")?,
            name: get("name")?,
        })
    }

    /// The requested, kept or inferred mode (module docs).
    pub fn mode(&self, cfg: &NodeConfig) -> Result<Mode> {
        let enabled = cfg.subscription.as_ref().map(|s| Mode::of(&s.mode));
        let mode = match (self.mode.as_deref(), enabled) {
            (Some("ip"), _) => Mode::Ip,
            (Some("site"), _) => Mode::Site,
            (Some("standalone"), _) => Mode::Standalone,
            (Some(_), _) => return Err(Error::msg(BAD_MODE)),
            (None, Some(kept)) => {
                self.check_kept(kept)?;
                kept
            }
            (None, None) if self.address.is_some() => Mode::Ip,
            (None, None) if self.domain.is_some() => Mode::Standalone,
            (None, None) if cfg.site_active().is_some() => Mode::Site,
            (None, None) => Mode::Ip,
        };
        ensure!(
            mode == Mode::Ip || self.address.is_none(),
            "{ADDRESS_NOT_IP}"
        );
        Ok(mode)
    }

    /// Without `--mode` an enabled subscription keeps its mode: an option
    /// only another mode uses would silently mean nothing, so it is refused.
    fn check_kept(&self, kept: Mode) -> Result<()> {
        let foreign: Vec<&str> = [
            ("--address", &self.address, kept != Mode::Ip),
            ("--domain", &self.domain, kept != Mode::Standalone),
            ("--port", &self.port, kept == Mode::Site),
            ("--tls", &self.tls, kept != Mode::Standalone),
            ("--cert", &self.cert, kept != Mode::Standalone),
            ("--key", &self.key, kept != Mode::Standalone),
        ]
        .into_iter()
        .filter(|(_, value, foreign)| *foreign && value.is_some())
        .map(|(flag, _, _)| flag)
        .collect();
        ensure!(
            foreign.is_empty(),
            "订阅当前为 {} 模式，{} 不适用；{OTHER_MODE}",
            kept.id(),
            foreign.join(" ")
        );
        Ok(())
    }

    /// The planner request and the port (`None` = default): omitted
    /// options keep what an enabled subscription has (module docs).
    pub fn choice(&self, cfg: &NodeConfig) -> Result<(SubscriptionChoice, Option<u16>)> {
        let current = cfg.subscription.as_ref();
        let kept_port = current
            .filter(|s| s.mode != SubscriptionMode::Site)
            .map(|s| s.port);
        let port = match self.port.as_deref() {
            Some(port) => Some(parse_port(port)?),
            None => kept_port,
        };
        Ok(match self.mode(cfg)? {
            Mode::Ip => {
                let certificate_options = [&self.domain, &self.tls, &self.cert, &self.key];
                ensure!(
                    certificate_options.iter().all(|o| o.is_none()),
                    "{IP_NO_CERT}"
                );
                let address = match (self.address.as_deref(), current.map(|s| &s.mode)) {
                    (Some(address), _) => Some(parse_address(address)?),
                    (None, Some(SubscriptionMode::Ip { address })) => Some(*address),
                    (None, _) => None,
                };
                (SubscriptionChoice::Ip { address }, port)
            }
            Mode::Site => (SubscriptionChoice::Site, None),
            Mode::Standalone => {
                let (domain, cert) = match current.map(|s| &s.mode) {
                    Some(SubscriptionMode::Standalone { domain, cert, .. }) => {
                        (Some(domain), Some(cert))
                    }
                    _ => (None, None),
                };
                let domain = self
                    .domain
                    .clone()
                    .or_else(|| domain.cloned())
                    .ok_or_else(|| Error::msg(NEEDS_DOMAIN))?;
                let cert = self.web_cert(cert)?;
                (SubscriptionChoice::Standalone { domain, cert }, port)
            }
        })
    }

    /// `--tls`/`--cert`/`--key` over the `current` certificate of an
    /// enabled standalone subscription: its method stays without `--tls`,
    /// and a custom pair keeps the path that is not given.
    fn web_cert(&self, current: Option<&WebCert>) -> Result<WebCert> {
        let current_method = match current {
            None | Some(WebCert::Cloudflare) => "cf",
            Some(WebCert::Http01) => "http",
            Some(WebCert::Custom { .. }) => "custom",
        };
        let method = self.tls.as_deref().unwrap_or(current_method);
        ensure!(
            method == "custom" || (self.cert.is_none() && self.key.is_none()),
            "{PATHS_NOT_CUSTOM}"
        );
        Ok(match method {
            "cf" => WebCert::Cloudflare,
            "http" => WebCert::Http01,
            "custom" => {
                let (current_cert, current_key) = match current {
                    Some(WebCert::Custom { cert, key }) => (Some(cert), Some(key)),
                    _ => (None, None),
                };
                let given = |path: &Option<String>| path.as_deref().map(PathBuf::from);
                let cert = given(&self.cert).or_else(|| current_cert.cloned());
                let key = given(&self.key).or_else(|| current_key.cloned());
                match (cert, key) {
                    (Some(cert), Some(key)) => WebCert::Custom { cert, key },
                    _ => return Err(Error::msg(CUSTOM_PATHS)),
                }
            }
            _ => return Err(Error::msg(BAD_METHOD)),
        })
    }

    /// Options site mode does not use (for a notice).
    pub fn ignored_in_site_mode(&self) -> Vec<&'static str> {
        [
            ("--domain", &self.domain),
            ("--port", &self.port),
            ("--tls", &self.tls),
            ("--cert", &self.cert),
            ("--key", &self.key),
        ]
        .into_iter()
        .filter(|(_, value)| value.is_some())
        .map(|(flag, _)| flag)
        .collect()
    }
}

/// An IP literal: no brackets, port, path, zone id or whitespace.
pub fn parse_address(value: &str) -> Result<IpAddr> {
    value.parse().map_err(|_| Error::msg(BAD_ADDRESS))
}

/// 1–65535.
pub fn parse_port(value: &str) -> Result<u16> {
    value
        .parse::<u16>()
        .ok()
        .filter(|p| *p != 0)
        .ok_or_else(|| Error::msg(BAD_PORT))
}

#[cfg(test)]
mod tests;
