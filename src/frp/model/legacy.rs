//! The two older FRP state formats, read as input only: v2's `state.json`
//! (16 required fields, unknown fields refused) and v1's `state.conf`
//! (`FRPS_*=value` lines, data only — never sourced, no quotes, comments
//! or `export`). Both convert into the typed [`FrpState`]; the token is
//! preserved, never rotated.

use super::{AppDomain, BindAddr, FrpState, Mode, WebSettings, WebTls, SCHEMA};
use crate::domain::config::PortRange;
use crate::error::{Error, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// v2 `frp::Config` (`state.json` without `schema`), field order as v2.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct V2Config {
    pub mode: String,
    pub domain: String,
    pub bind_addr: String,
    pub bind_port: u16,
    pub http_port: u16,
    pub https_port: u16,
    pub redirect_port: u16,
    pub web_domain: String,
    pub subdomain_host: String,
    pub range_start: u16,
    pub range_end: u16,
    pub token: String,
    pub tls_method: String,
    pub cert_input: String,
    pub key_input: String,
    pub version: String,
}

/// The 16 keys of v1 `state.conf`, in v1 write order (`FRPS_BIND_PORT` is
/// v2's `bind_port`, and so on).
pub const STATE_CONF_KEYS: [&str; 16] = [
    "FRPS_MODE",
    "FRPS_DOMAIN",
    "FRPS_BIND_ADDR",
    "FRPS_BIND_PORT",
    "FRPS_HTTP_PORT",
    "FRPS_HTTPS_PORT",
    "FRPS_REDIRECT_PORT",
    "FRPS_WEB_DOMAIN",
    "FRPS_SUBDOMAIN_HOST",
    "FRPS_RANGE_START",
    "FRPS_RANGE_END",
    "FRPS_TOKEN",
    "FRPS_TLS_METHOD",
    "FRPS_CERT_INPUT",
    "FRPS_KEY_INPUT",
    "FRPS_VERSION",
];

impl V2Config {
    /// The typed state (validated). Web-only fields are dropped in tcp
    /// mode, where v2 ignored them too; domains are lower-cased.
    pub fn into_state(self) -> Result<FrpState> {
        let texts = [
            &self.mode,
            &self.domain,
            &self.bind_addr,
            &self.web_domain,
            &self.subdomain_host,
            &self.token,
            &self.tls_method,
            &self.cert_input,
            &self.key_input,
            &self.version,
        ];
        ensure!(
            !texts.iter().any(|t| t.chars().any(char::is_control)),
            "FRP 参数不能含控制字符"
        );
        let mode = match self.mode.as_str() {
            "web" => Mode::Web(self.web_settings()?),
            "tcp" => Mode::Tcp,
            _ => bail!("FRP 模式应为 web 或 tcp"),
        };
        let bind_addr =
            BindAddr::parse(&self.bind_addr).ok_or_else(|| Error::msg("FRP 监听地址无效"))?;
        let state = FrpState {
            schema: SCHEMA,
            domain: self.domain.to_ascii_lowercase(),
            bind_addr,
            bind_port: self.bind_port,
            range: PortRange {
                start: self.range_start,
                end: self.range_end,
            },
            token: self.token,
            version: self.version,
            mode,
        };
        state.validate()?;
        Ok(state)
    }

    fn web_settings(&self) -> Result<WebSettings> {
        let app = match (self.web_domain.as_str(), self.subdomain_host.as_str()) {
            (domain, "") => AppDomain::Single {
                domain: domain.to_ascii_lowercase(),
            },
            ("", root) => AppDomain::Wildcard {
                root: root.to_ascii_lowercase(),
            },
            _ => bail!("应用域名与泛域名根不能并用"),
        };
        let tls = match self.tls_method.as_str() {
            "http" => WebTls::Http01,
            "cf" => WebTls::Cloudflare,
            "custom" => WebTls::Custom {
                cert: self.cert_input.clone(),
                key: self.key_input.clone(),
            },
            _ => bail!("网站证书方式应为 http、cf 或 custom"),
        };
        Ok(WebSettings {
            http_port: self.http_port,
            https_port: self.https_port,
            redirect_port: self.redirect_port,
            app,
            tls,
        })
    }

    /// The v2 shape of `state` (tcp mode gets v2's defaults for the web
    /// fields), e.g. for comparisons with v2 output.
    pub fn from_state(state: &FrpState) -> V2Config {
        let web = state.web().cloned().unwrap_or_else(|| {
            WebSettings::new(
                AppDomain::Single {
                    domain: String::new(),
                },
                WebTls::Http01,
            )
        });
        let (web_domain, subdomain_host) = match &web.app {
            AppDomain::Single { domain } => (domain.clone(), String::new()),
            AppDomain::Wildcard { root } => (String::new(), root.clone()),
        };
        let (cert_input, key_input) = match &web.tls {
            WebTls::Custom { cert, key } => (cert.clone(), key.clone()),
            _ => (String::new(), String::new()),
        };
        V2Config {
            mode: if state.is_web() { "web" } else { "tcp" }.to_owned(),
            domain: state.domain.clone(),
            bind_addr: state.bind_addr.as_str().to_owned(),
            bind_port: state.bind_port,
            http_port: web.http_port,
            https_port: web.https_port,
            redirect_port: web.redirect_port,
            web_domain,
            subdomain_host,
            range_start: state.range.start,
            range_end: state.range.end,
            token: state.token.clone(),
            tls_method: web.tls.v2_id().to_owned(),
            cert_input,
            key_input,
            version: state.version.clone(),
        }
    }
}

/// Parse v1 `state.conf` strictly (spec H §3.4): empty lines are skipped,
/// every other line is `KEY=VALUE` with one of the 16 keys, each exactly
/// once, values without control characters; ports are decimal.
pub fn parse_state_conf(text: &str) -> Result<FrpState> {
    let mut values: BTreeMap<&str, &str> = BTreeMap::new();
    for line in text.lines().filter(|l| !l.is_empty()) {
        let (key, value) = line
            .split_once('=')
            .ok_or_else(|| Error::msg("旧 FRP 状态格式无效"))?;
        ensure!(STATE_CONF_KEYS.contains(&key), "旧 FRP 状态含未知键");
        ensure!(
            !value.chars().any(char::is_control),
            "旧 FRP 状态 {key} 含控制字符"
        );
        ensure!(
            values.insert(key, value).is_none(),
            "旧 FRP 状态含重复键 {key}"
        );
    }
    if let Some(missing) = STATE_CONF_KEYS.iter().find(|k| !values.contains_key(*k)) {
        bail!("旧 FRP 状态缺少 {missing}");
    }
    let text = |key: &str| values.get(key).copied().unwrap_or_default().to_owned();
    let port = |key: &str| -> Result<u16> {
        values
            .get(key)
            .and_then(|v| v.parse().ok())
            .ok_or_else(|| Error::msg(format!("旧 FRP 状态 {key} 不是有效端口")))
    };
    V2Config {
        mode: text("FRPS_MODE"),
        domain: text("FRPS_DOMAIN"),
        bind_addr: text("FRPS_BIND_ADDR"),
        bind_port: port("FRPS_BIND_PORT")?,
        http_port: port("FRPS_HTTP_PORT")?,
        https_port: port("FRPS_HTTPS_PORT")?,
        redirect_port: port("FRPS_REDIRECT_PORT")?,
        web_domain: text("FRPS_WEB_DOMAIN"),
        subdomain_host: text("FRPS_SUBDOMAIN_HOST"),
        range_start: port("FRPS_RANGE_START")?,
        range_end: port("FRPS_RANGE_END")?,
        token: text("FRPS_TOKEN"),
        tls_method: text("FRPS_TLS_METHOD"),
        cert_input: text("FRPS_CERT_INPUT"),
        key_input: text("FRPS_KEY_INPUT"),
        version: text("FRPS_VERSION"),
    }
    .into_state()
}
