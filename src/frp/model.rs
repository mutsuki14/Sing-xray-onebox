//! FRP server state: the typed model, its validation, and its files
//! (spec H §3.1–3.4). A leaf module (domain, sys, paths, error only) so the
//! node side can read FRP's port reservations without depending on the FRP
//! manager.
//!
//! Files under `FRP_ROOT` (`/etc/onebox-frp`):
//! - `.managed` — FRP is installed (with a state file) only when it exists;
//! - `state.json` — schema 2 (written by v3) or the v2 shape (16 required
//!   fields, unknown fields refused), both read;
//! - `state.conf` — the v1 `FRPS_*=value` file, still read (strictly, as
//!   data) when `state.json` is absent: v2-managed hosts installed by v1 may
//!   have no other state (G10). It is never written or removed; the next
//!   FRP change writes `state.json`.
//!
//! Changes from v2:
//! - typed model: `Mode::{Web, Tcp}`, `AppDomain::{Single, Wildcard}`,
//!   `WebTls::{Http01, Cloudflare, Custom}`, `BindAddr` (H-8.2), persisted
//!   with `schema: 2`; web-only settings exist only in web mode;
//! - web mode has no forwarding range at all (H-8.1#8): the range belongs
//!   to `Mode::Tcp`, so web mode neither reserves nor opens one. Its frps
//!   `allowPorts` ([`PortLayout::allow_ports`], which the renderer must
//!   emit in both modes: an empty `allowPorts` allows every port) is the
//!   bind port alone, which frps holds itself and which is reserved for
//!   UDP too, so clients cannot open TCP/UDP proxies (v2 let them bind
//!   127.0.0.1:20000–20100 there, inside the node's fallback port pool).
//!   Reading a v2 web state drops its range; [`V2Config::from_state`]
//!   writes v2's default;
//! - new domains must be DNS names (H-8.1#15: frpc cannot verify a
//!   certificate for an IP literal). Stored states keep v2's rule, so an IP
//!   literal v2 accepted is still read and kept while it is unchanged, with
//!   a notice from [`FrpState::warnings`] (ARCH §10: lenient migration);
//!   only a changed domain is refused ([`FrpState::validate_change`],
//!   enforced by [`save`]). Domains from v2/v1 files are lower-cased;
//! - [`reservations`] reads the port fields alone ([`PortLayout`]), so a
//!   problem elsewhere in the FRP state cannot stop node port planning;
//! - precise messages instead of shared ones (H-8.1#16): an invalid
//!   wildcard root, unknown vs duplicate vs control-character keys in
//!   `state.conf`, and Chinese text instead of raw integer-parse errors;
//! - symlinked state files are refused instead of followed.

mod files;
mod legacy;
mod ports;

pub use files::{
    installed, legacy_state_path, load, managed_path, parse_ports_json, parse_state_json,
    reservations, save, state_path,
};
pub use legacy::{parse_state_conf, V2Config, STATE_CONF_KEYS};
pub use ports::{PortLayout, MAX_RANGE_PORTS};

use crate::domain::config::PortRange;
use crate::domain::defaults::FRP_VERSION;
use crate::domain::ports::Reservation;
use crate::domain::protocol::Transport;
use crate::error::{Error, Result};
use crate::sys::text::{valid_domain, valid_label};
use serde::{Deserialize, Serialize};
use std::fmt;

/// `schema` of the state written by v3.
pub const SCHEMA: u32 = 2;
pub const STATE_FILE: &str = "state.json";
pub const LEGACY_STATE_FILE: &str = "state.conf";
pub const MANAGED_FILE: &str = ".managed";
/// Largest state file accepted, either format (v2).
pub const MAX_STATE_BYTES: u64 = 64 * 1024;
pub const NOT_INSTALLED: &str = "尚未安装托管 FRP；运行 onebox frps install";
pub const DEFAULT_BIND_PORT: u16 = 7000;
pub const DEFAULT_HTTP_PORT: u16 = 7080;
pub const DEFAULT_HTTPS_PORT: u16 = 443;
pub const DEFAULT_REDIRECT_PORT: u16 = 80;
pub const DEFAULT_RANGE: PortRange = PortRange {
    start: 20000,
    end: 20100,
};
/// Longest wildcard root (`*.{root}` must stay a valid name).
pub const WILDCARD_ROOT_MAX: usize = 238;
const OLDEST_VERSION: (u32, u32, u32) = (0, 71, 0);

/// Where frps listens for clients.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub enum BindAddr {
    /// `0.0.0.0`
    AnyV4,
    /// `::`
    AnyV6,
    /// `127.0.0.1`
    LoopbackV4,
    /// `::1`
    LoopbackV6,
}

impl BindAddr {
    pub const ALL: [BindAddr; 4] = [
        BindAddr::AnyV4,
        BindAddr::AnyV6,
        BindAddr::LoopbackV4,
        BindAddr::LoopbackV6,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            BindAddr::AnyV4 => "0.0.0.0",
            BindAddr::AnyV6 => "::",
            BindAddr::LoopbackV4 => "127.0.0.1",
            BindAddr::LoopbackV6 => "::1",
        }
    }

    pub fn parse(value: &str) -> Option<BindAddr> {
        BindAddr::ALL.into_iter().find(|a| a.as_str() == value)
    }

    /// The default: every address, IPv6 included when the host has it.
    pub fn default_for(ipv6: bool) -> BindAddr {
        if ipv6 {
            BindAddr::AnyV6
        } else {
            BindAddr::AnyV4
        }
    }
}

impl fmt::Display for BindAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl TryFrom<String> for BindAddr {
    type Error = Error;
    fn try_from(value: String) -> Result<BindAddr> {
        BindAddr::parse(&value).ok_or_else(|| Error::msg("FRP 监听地址无效"))
    }
}

impl From<BindAddr> for String {
    fn from(addr: BindAddr) -> String {
        addr.as_str().to_owned()
    }
}

/// The public application name(s) of web mode.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum AppDomain {
    /// One application domain (`customDomains`).
    Single { domain: String },
    /// `*.{root}` (frps `subDomainHost`); the bare root is not routed.
    Wildcard { root: String },
}

impl AppDomain {
    /// The names the website certificate must cover.
    pub fn cert_domains(&self) -> Vec<String> {
        match self {
            AppDomain::Single { domain } => vec![domain.clone()],
            AppDomain::Wildcard { root } => vec![root.clone(), format!("*.{root}")],
        }
    }

    pub fn is_wildcard(&self) -> bool {
        matches!(self, AppDomain::Wildcard { .. })
    }
}

/// How the web-mode certificate is obtained.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum WebTls {
    /// ACME HTTP-01 through the managed nginx on TCP 80.
    Http01,
    /// ACME DNS-01 through Cloudflare.
    Cloudflare,
    /// A certificate pair supplied by the administrator.
    Custom { cert: String, key: String },
}

impl WebTls {
    /// The v2 `tls_method` spelling (`http`, `cf`, `custom`).
    pub fn v2_id(&self) -> &'static str {
        match self {
            WebTls::Http01 => "http",
            WebTls::Cloudflare => "cf",
            WebTls::Custom { .. } => "custom",
        }
    }
}

/// Web mode: nginx terminates HTTPS and proxies to the frps vhost port,
/// which listens on loopback.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WebSettings {
    /// frps `vhostHTTPPort` (loopback only).
    pub http_port: u16,
    pub https_port: u16,
    /// HTTP → HTTPS redirect (and HTTP-01) port; 0 disables it.
    pub redirect_port: u16,
    pub app: AppDomain,
    pub tls: WebTls,
}

impl WebSettings {
    /// Default ports for `app` and `tls`.
    pub fn new(app: AppDomain, tls: WebTls) -> WebSettings {
        WebSettings {
            http_port: DEFAULT_HTTP_PORT,
            https_port: DEFAULT_HTTPS_PORT,
            redirect_port: DEFAULT_REDIRECT_PORT,
            app,
            tls,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum Mode {
    /// HTTP applications behind nginx. There is no forwarding range and
    /// clients must not open TCP/UDP proxies: frps `allowPorts` is
    /// [`PortLayout::allow_ports`] (the bind port alone), never empty.
    Web(WebSettings),
    /// Public TCP/UDP forwarding inside `range` (frps `allowPorts`).
    Tcp { range: PortRange },
}

impl Mode {
    /// Tcp mode with the default range.
    pub fn tcp() -> Mode {
        Mode::Tcp {
            range: DEFAULT_RANGE,
        }
    }
}

/// Which name a domain field holds (for messages).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum NameField {
    Control,
    App,
    WildcardRoot,
}

impl NameField {
    fn label(self) -> &'static str {
        match self {
            NameField::Control => "FRP 控制域名",
            NameField::App => "FRP 应用域名",
            NameField::WildcardRoot => "FRP 泛域名根",
        }
    }
}

/// The domain rule of stored states: v2's `util::valid_domain` (in lower
/// case), which also accepted IP literals and all-digit suffixes.
fn stored_domain(name: &str) -> bool {
    name.len() <= 253
        && name.contains('.')
        && !name.ends_with('.')
        && name.split('.').all(valid_label)
}

/// The FRP server configuration (`state.json`, schema 2).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FrpState {
    pub schema: u32,
    /// The control domain clients connect to (and the control certificate
    /// name).
    pub domain: String,
    pub bind_addr: BindAddr,
    pub bind_port: u16,
    /// 64 lowercase hex; also authenticates heartbeats and work connections.
    pub token: String,
    /// `latest` or a concrete `0.x.y` (≥ 0.71.0); concrete after an apply.
    pub version: String,
    pub mode: Mode,
}

impl FrpState {
    /// A state with the default bind port and frp version.
    pub fn new(domain: String, token: String, bind_addr: BindAddr, mode: Mode) -> FrpState {
        FrpState {
            schema: SCHEMA,
            domain,
            bind_addr,
            bind_port: DEFAULT_BIND_PORT,
            token,
            version: FRP_VERSION.to_owned(),
            mode,
        }
    }

    pub fn web(&self) -> Option<&WebSettings> {
        match &self.mode {
            Mode::Web(web) => Some(web),
            Mode::Tcp { .. } => None,
        }
    }

    pub fn is_web(&self) -> bool {
        self.web().is_some()
    }

    /// The forwarding range (tcp mode only).
    pub fn range(&self) -> Option<PortRange> {
        match self.mode {
            Mode::Tcp { range } => Some(range),
            Mode::Web(_) => None,
        }
    }

    pub fn ports(&self) -> PortLayout {
        match &self.mode {
            Mode::Web(web) => PortLayout::Web {
                bind_port: self.bind_port,
                http_port: web.http_port,
                https_port: web.https_port,
                redirect_port: web.redirect_port,
            },
            Mode::Tcp { range } => PortLayout::Tcp {
                bind_port: self.bind_port,
                range: *range,
            },
        }
    }

    /// See [`PortLayout::listeners`].
    pub fn listeners(&self) -> Vec<u16> {
        self.ports().listeners()
    }

    /// See [`PortLayout::reservations`].
    pub fn reservations(&self) -> Vec<Reservation> {
        self.ports().reservations()
    }

    /// See [`PortLayout::firewall_ports`].
    pub fn firewall_ports(&self) -> Vec<(u16, u16, Transport)> {
        self.ports().firewall_ports()
    }

    /// See [`PortLayout::allow_ports`] (what the renderer emits as frps
    /// `allowPorts`).
    pub fn allow_ports(&self) -> Vec<(u16, u16)> {
        self.ports().allow_ports()
    }

    /// The invariants of a stored state (load, save, render), token
    /// required. Domains follow v2's rule, so a state v2 accepted stays
    /// readable; new input goes through [`FrpState::validate_change`].
    pub fn validate(&self) -> Result<()> {
        self.check(true)
    }

    /// Settings entered before the first install (the token is generated
    /// later): every domain must be a DNS name.
    pub fn validate_draft(&self) -> Result<()> {
        self.check(false)?;
        self.check_new_names(None)
    }

    /// A state about to replace `previous` (flags, wizard, [`save`]): the
    /// stored invariants, and every domain that is not the same field with
    /// the same value in `previous` must be a DNS name — an IP literal v2
    /// accepted is kept only while it is unchanged.
    pub fn validate_change(&self, previous: Option<&FrpState>) -> Result<()> {
        self.check(true)?;
        self.check_new_names(previous)
    }

    /// Notices about settings v2 accepted that cannot work (IP literals as
    /// names), for FRP commands to print.
    pub fn warnings(&self) -> Vec<String> {
        self.names()
            .into_iter()
            .filter(|(_, name)| !valid_domain(name))
            .map(|(field, name)| {
                let effect = match field {
                    NameField::Control => "，frpc 无法校验服务端证书",
                    NameField::App | NameField::WildcardRoot => "",
                };
                format!(
                    "{} {name} 不是有效域名（v2 曾允许 IP 地址）{effect}；请通过 onebox frps 重新配置为域名",
                    field.label()
                )
            })
            .collect()
    }

    /// Every domain field with its value.
    fn names(&self) -> Vec<(NameField, &str)> {
        let mut names = vec![(NameField::Control, self.domain.as_str())];
        match self.web().map(|w| &w.app) {
            Some(AppDomain::Single { domain }) => names.push((NameField::App, domain)),
            Some(AppDomain::Wildcard { root }) => names.push((NameField::WildcardRoot, root)),
            None => {}
        }
        names
    }

    fn check_new_names(&self, previous: Option<&FrpState>) -> Result<()> {
        let kept = previous.map(FrpState::names).unwrap_or_default();
        for (field, name) in self.names() {
            if !kept.contains(&(field, name)) {
                ensure!(
                    valid_domain(name),
                    "{}必须是域名，不能是 IP 地址: {name}",
                    field.label()
                );
            }
        }
        Ok(())
    }

    fn check(&self, credentials: bool) -> Result<()> {
        ensure!(
            self.schema == SCHEMA,
            "FRP 状态 schema 无效: {}",
            self.schema
        );
        self.check_text()?;
        ensure!(stored_domain(&self.domain), "请设置有效的 FRP 控制域名");
        check_version(&self.version)?;
        if credentials || !self.token.is_empty() {
            ensure!(
                valid_token(&self.token),
                "FRP token 必须为 64 位小写十六进制值"
            );
        }
        self.ports().check()?;
        match &self.mode {
            Mode::Web(web) => check_web(web),
            Mode::Tcp { .. } => Ok(()),
        }
    }

    fn check_text(&self) -> Result<()> {
        let mut texts = vec![self.domain.as_str(), &self.token, &self.version];
        if let Some(web) = self.web() {
            match &web.app {
                AppDomain::Single { domain } => texts.push(domain),
                AppDomain::Wildcard { root } => texts.push(root),
            }
            if let WebTls::Custom { cert, key } = &web.tls {
                texts.extend([cert.as_str(), key.as_str()]);
            }
        }
        ensure!(
            !texts.iter().any(|t| t.chars().any(char::is_control)),
            "FRP 参数不能含控制字符"
        );
        Ok(())
    }
}

fn check_web(web: &WebSettings) -> Result<()> {
    match &web.app {
        AppDomain::Single { domain } => ensure!(stored_domain(domain), "请设置有效应用域名"),
        AppDomain::Wildcard { root } => ensure!(
            stored_domain(root) && root.len() <= WILDCARD_ROOT_MAX,
            "请设置有效的泛域名根（不超过 {WILDCARD_ROOT_MAX} 个字符）"
        ),
    }
    match &web.tls {
        WebTls::Http01 => ensure!(
            !web.app.is_wildcard() && web.redirect_port == 80,
            "HTTP-01 要求 TCP 80 且不支持泛域名；泛域名请选择 cf 或 custom"
        ),
        WebTls::Custom { cert, key } => ensure!(
            !cert.is_empty() && !key.is_empty(),
            "自备证书需要 --cert 与 --key"
        ),
        WebTls::Cloudflare => {}
    }
    Ok(())
}

fn valid_token(token: &str) -> bool {
    token.len() == 64
        && token
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// `latest`, or `0.x.y` not older than 0.71.0.
pub fn check_version(version: &str) -> Result<()> {
    if version == "latest" {
        return Ok(());
    }
    let parts: Option<Vec<u32>> = version.split('.').map(|p| p.parse().ok()).collect();
    let ok =
        parts.is_some_and(|p| p.len() == 3 && p[0] == 0 && (p[0], p[1], p[2]) >= OLDEST_VERSION);
    ensure!(ok, "FRP 版本须为 0.71.0 或更新的稳定版本");
    Ok(())
}

#[cfg(test)]
mod tests;
