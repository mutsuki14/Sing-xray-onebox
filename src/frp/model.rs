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
//! - web mode no longer reserves the forwarding range (H-8.1#8): only tcp
//!   mode exposes it publicly;
//! - IP literals are no longer accepted as domains (H-8.1#15) and domains
//!   from v2/v1 files are lower-cased;
//! - precise messages instead of shared ones (H-8.1#16): an invalid
//!   wildcard root, unknown vs duplicate vs control-character keys in
//!   `state.conf`, and Chinese text instead of raw integer-parse errors;
//! - symlinked state files are refused instead of followed.

mod legacy;

pub use legacy::{parse_state_conf, V2Config, STATE_CONF_KEYS};

use crate::domain::config::PortRange;
use crate::domain::defaults::FRP_VERSION;
use crate::domain::ports::Reservation;
use crate::domain::protocol::Transport;
use crate::error::{Context, Error, Result};
use crate::paths::Paths;
use crate::sys::fs::{atomic_write, read_bounded};
use crate::sys::text::valid_domain;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeSet;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

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
/// A forwarding range spans at most this many ports.
pub const MAX_RANGE_PORTS: u32 = 1000;
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
    Web(WebSettings),
    /// Public TCP/UDP forwarding inside the range.
    Tcp,
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
    /// Remote ports clients may open (frps `allowPorts`, both modes).
    pub range: PortRange,
    /// 64 lowercase hex; also authenticates heartbeats and work connections.
    pub token: String,
    /// `latest` or a concrete `0.x.y` (≥ 0.71.0); concrete after an apply.
    pub version: String,
    pub mode: Mode,
}

impl FrpState {
    /// A state with the default ports, range and frp version.
    pub fn new(domain: String, token: String, bind_addr: BindAddr, mode: Mode) -> FrpState {
        FrpState {
            schema: SCHEMA,
            domain,
            bind_addr,
            bind_port: DEFAULT_BIND_PORT,
            range: DEFAULT_RANGE,
            token,
            version: FRP_VERSION.to_owned(),
            mode,
        }
    }

    pub fn web(&self) -> Option<&WebSettings> {
        match &self.mode {
            Mode::Web(web) => Some(web),
            Mode::Tcp => None,
        }
    }

    pub fn is_web(&self) -> bool {
        self.web().is_some()
    }

    /// Ports frps or the web nginx listen on outside the range: the bind
    /// port, plus the vhost, HTTPS and (when enabled) redirect ports in
    /// web mode.
    pub fn listeners(&self) -> Vec<u16> {
        let mut ports = vec![self.bind_port];
        if let Some(web) = self.web() {
            ports.extend([web.http_port, web.https_port, web.redirect_port]);
            ports.retain(|p| *p != 0);
        }
        ports
    }

    /// Ports other Onebox components must leave to FRP — also while FRP is
    /// stopped. The range only in tcp mode, where it is public (H-8.1#8).
    pub fn reservations(&self) -> Vec<Reservation> {
        let reserve = |port: u16, label: &str| Reservation {
            start: port,
            end: port,
            transport: Transport::Tcp,
            label: label.to_owned(),
        };
        let mut out = vec![reserve(self.bind_port, "控制端口")];
        match &self.mode {
            Mode::Web(web) => {
                out.push(reserve(web.http_port, "HTTP 端口"));
                out.push(reserve(web.https_port, "HTTPS 端口"));
                if web.redirect_port != 0 {
                    out.push(reserve(web.redirect_port, "HTTP 跳转端口"));
                }
            }
            Mode::Tcp => out.push(Reservation {
                start: self.range.start,
                end: self.range.end,
                transport: Transport::Both,
                label: "转发端口".to_owned(),
            }),
        }
        out
    }

    /// What the FRP firewall owner opens: the bind port; in web mode HTTPS
    /// and the redirect port (the vhost port stays on loopback); in tcp mode
    /// the whole range for TCP and UDP.
    pub fn firewall_ports(&self) -> Vec<(u16, u16, Transport)> {
        let mut out = vec![(self.bind_port, self.bind_port, Transport::Tcp)];
        match &self.mode {
            Mode::Web(web) => {
                out.push((web.https_port, web.https_port, Transport::Tcp));
                if web.redirect_port != 0 {
                    out.push((web.redirect_port, web.redirect_port, Transport::Tcp));
                }
            }
            Mode::Tcp => out.push((self.range.start, self.range.end, Transport::Both)),
        }
        out
    }

    /// Full validation, token required (load, save, render).
    pub fn validate(&self) -> Result<()> {
        self.check(true)
    }

    /// Validation of settings before the first install (the token is
    /// generated later).
    pub fn validate_draft(&self) -> Result<()> {
        self.check(false)
    }

    fn check(&self, credentials: bool) -> Result<()> {
        ensure!(
            self.schema == SCHEMA,
            "FRP 状态 schema 无效: {}",
            self.schema
        );
        self.check_text()?;
        ensure!(valid_domain(&self.domain), "请设置有效的 FRP 控制域名");
        check_version(&self.version)?;
        if credentials || !self.token.is_empty() {
            ensure!(
                valid_token(&self.token),
                "FRP token 必须为 64 位小写十六进制值"
            );
        }
        self.check_ports()?;
        match &self.mode {
            Mode::Web(web) => check_web(web),
            Mode::Tcp => Ok(()),
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

    fn check_ports(&self) -> Result<()> {
        let range = self.range;
        let web_ports_ok = self
            .web()
            .is_none_or(|w| w.http_port != 0 && w.https_port != 0);
        ensure!(
            self.bind_port != 0
                && web_ports_ok
                && range.start != 0
                && range.start <= range.end
                && u32::from(range.end - range.start) < MAX_RANGE_PORTS,
            "FRP 端口无效，转发范围必须为 1 至 1000 个端口"
        );
        let mut seen = BTreeSet::new();
        let clash = self
            .listeners()
            .into_iter()
            .any(|p| !seen.insert(p) || range.contains(p));
        ensure!(!clash, "FRP 监听端口重复或落在转发范围内");
        Ok(())
    }
}

fn check_web(web: &WebSettings) -> Result<()> {
    match &web.app {
        AppDomain::Single { domain } => ensure!(valid_domain(domain), "请设置有效应用域名"),
        AppDomain::Wildcard { root } => ensure!(
            valid_domain(root) && root.len() <= WILDCARD_ROOT_MAX,
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

pub fn state_path(paths: &Paths) -> PathBuf {
    paths.frp_root.join(STATE_FILE)
}

pub fn legacy_state_path(paths: &Paths) -> PathBuf {
    paths.frp_root.join(LEGACY_STATE_FILE)
}

pub fn managed_path(paths: &Paths) -> PathBuf {
    paths.frp_root.join(MANAGED_FILE)
}

/// Present without following a final symlink (a symlinked state file
/// counts as present so that `load` reports it instead of ignoring it).
fn present(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok()
}

/// FRP is installed: `.managed` is a regular file and a state file exists.
pub fn installed(paths: &Paths) -> bool {
    let managed = fs::symlink_metadata(managed_path(paths)).is_ok_and(|m| m.is_file());
    managed && (present(&state_path(paths)) || present(&legacy_state_path(paths)))
}

fn read_state_file(path: &Path) -> Result<Vec<u8>> {
    let meta = fs::symlink_metadata(path).map_err(|e| Error::io(path, e))?;
    ensure!(meta.len() <= MAX_STATE_BYTES, "FRP 状态文件异常大");
    read_bounded(path, MAX_STATE_BYTES)
}

/// The installed FRP state (`None` when FRP is not installed): `state.json`
/// (schema 2 or the v2 shape), else the v1 `state.conf`; validated.
pub fn load(paths: &Paths) -> Result<Option<FrpState>> {
    if !installed(paths) {
        return Ok(None);
    }
    let json = state_path(paths);
    let path = if present(&json) {
        json
    } else {
        legacy_state_path(paths)
    };
    let parsed = read_state_file(&path).and_then(|bytes| {
        if path == state_path(paths) {
            parse_state_json(&bytes)
        } else {
            let text = String::from_utf8(bytes).map_err(|_| Error::msg("旧 FRP 状态不是 UTF-8"))?;
            parse_state_conf(&text)
        }
    });
    let state = parsed.with_context(|| format!("FRP 状态 {} 无效", path.display()))?;
    Ok(Some(state))
}

/// Parse `state.json`: schema 2, or the v2 shape (no `schema` member).
pub fn parse_state_json(bytes: &[u8]) -> Result<FrpState> {
    let doc: Value = serde_json::from_slice(bytes)?;
    let state = match doc.get("schema") {
        None => serde_json::from_value::<V2Config>(doc)?.into_state()?,
        Some(schema) => match schema.as_u64() {
            Some(2) => serde_json::from_value::<FrpState>(doc)?,
            Some(n) if n > 2 => {
                bail!("FRP 配置由更新版本的 Onebox 写入（schema {n}），请先更新程序")
            }
            _ => bail!("FRP 状态 schema 无效"),
        },
    };
    state.validate()?;
    Ok(state)
}

/// Validate, then write `state.json` (schema 2, pretty JSON + newline,
/// 0600) atomically. `state.conf` is left untouched.
pub fn save(paths: &Paths, state: &FrpState) -> Result<()> {
    state.validate()?;
    let mut text = serde_json::to_string_pretty(state)?;
    text.push('\n');
    atomic_write(&state_path(paths), text.as_bytes(), 0o600)
}

/// The ports FRP reserves (empty when FRP is not installed). A state that
/// cannot be read is an error naming FRP: other components must not take
/// ports FRP may own.
pub fn reservations(paths: &Paths) -> Result<Vec<Reservation>> {
    Ok(load(paths)?.map(|s| s.reservations()).unwrap_or_default())
}

#[cfg(test)]
mod tests;
