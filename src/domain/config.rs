//! The typed node configuration persisted as `ROOT/state.json` (schema 3).
//!
//! Replaces v2's stringly-typed `{"values":{KEY:"string"}}` bag. Transient
//! requests (renewals, restores, content publishes) never live here; they are
//! carried by `apply::Intents`. Subscription *devices* live in
//! `subscription/devices.json` because they change without a full apply.

use super::protocol::{Core, Protocol};
use crate::error::{Error, Result};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;
use std::str::FromStr;

pub const SCHEMA: u32 = 3;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeConfig {
    pub schema: u32,
    pub node_name: String,
    pub server: ServerAddr,
    /// Listen address for every inbound (one default for both cores).
    pub listen: IpAddr,
    /// Enabled inbounds in display order (preset order or insertion order).
    pub inbounds: Vec<Inbound>,
    pub creds: Credentials,
    pub reality: RealityTarget,
    pub shadowtls: ShadowTls,
    /// Own-domain website; only effective while a REALITY inbound exists.
    #[serde(default)]
    pub site: Option<SiteConfig>,
    /// Proxy certificate; required iff [`NodeConfig::needs_cert`].
    #[serde(default)]
    pub tls: Option<ProxyTls>,
    #[serde(default)]
    pub vmess_tls: bool,
    #[serde(default)]
    pub hy2: Hy2Settings,
    #[serde(default)]
    pub resource_profile: ResourceProfile,
    #[serde(default)]
    pub routing: Routing,
    #[serde(default)]
    pub subscription: Option<SubscriptionConfig>,
    #[serde(default)]
    pub versions: CoreVersions,
    #[serde(default)]
    pub installed_at: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Inbound {
    pub protocol: Protocol,
    pub port: u16,
    pub core: Core,
}

/// Public address clients connect to, plus detected address families.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerAddr {
    pub addr: Host,
    #[serde(default)]
    pub ipv4: Option<Ipv4Addr>,
    #[serde(default)]
    pub ipv6: Option<Ipv6Addr>,
    /// Legacy WARP flags: the address is not excluded as an own IP.
    #[serde(default)]
    pub ipv4_warp: bool,
    #[serde(default)]
    pub ipv6_warp: bool,
}

/// An IP literal or a DNS name (validated, lower-case).
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub enum Host {
    Ip(IpAddr),
    Domain(String),
}

impl Host {
    /// Host as used inside URLs and `host:port` strings (IPv6 bracketed).
    pub fn url_host(&self) -> String {
        match self {
            Host::Ip(IpAddr::V6(v6)) => format!("[{v6}]"),
            Host::Ip(ip) => ip.to_string(),
            Host::Domain(d) => d.clone(),
        }
    }
    pub fn ip(&self) -> Option<IpAddr> {
        match self {
            Host::Ip(ip) => Some(*ip),
            Host::Domain(_) => None,
        }
    }
}

impl fmt::Display for Host {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Host::Ip(ip) => write!(f, "{ip}"),
            Host::Domain(d) => f.write_str(d),
        }
    }
}

impl FromStr for Host {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self> {
        let trimmed = s.trim();
        let unbracketed = trimmed
            .strip_prefix('[')
            .and_then(|t| t.strip_suffix(']'))
            .unwrap_or(trimmed);
        if let Ok(ip) = unbracketed.parse::<IpAddr>() {
            return Ok(Host::Ip(ip));
        }
        let lower = trimmed.to_ascii_lowercase();
        if crate::sys::text::valid_domain(&lower) {
            Ok(Host::Domain(lower))
        } else {
            Err(Error::Msg(format!("地址应为 IP 或域名: {s}")))
        }
    }
}

impl TryFrom<String> for Host {
    type Error = Error;
    fn try_from(s: String) -> Result<Self> {
        s.parse()
    }
}

impl From<Host> for String {
    fn from(h: Host) -> String {
        h.to_string()
    }
}

/// `host:port` where host is a domain or IP (IPv6 bracketed in text form).
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct HostPort {
    pub host: Host,
    pub port: u16,
}

impl fmt::Display for HostPort {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.host.url_host(), self.port)
    }
}

impl FromStr for HostPort {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self> {
        let invalid = || Error::Msg(format!("目标格式应为 主机:端口: {s}"));
        let (host, port) = if let Some(rest) = s.strip_prefix('[') {
            let (h, p) = rest.split_once("]:").ok_or_else(invalid)?;
            (h, p)
        } else {
            let (h, p) = s.rsplit_once(':').ok_or_else(invalid)?;
            if h.contains(':') {
                return Err(invalid());
            }
            (h, p)
        };
        let port: u16 = port.parse().map_err(|_| invalid())?;
        if port == 0 || host.is_empty() {
            return Err(invalid());
        }
        Ok(HostPort {
            host: host.parse()?,
            port,
        })
    }
}

impl TryFrom<String> for HostPort {
    type Error = Error;
    fn try_from(s: String) -> Result<Self> {
        s.parse()
    }
}

impl From<HostPort> for String {
    fn from(h: HostPort) -> String {
        h.to_string()
    }
}

/// Generated secrets. Formats are identical to v2 (see `domain::credentials`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Credentials {
    pub uuid: String,
    pub password: String,
    pub ss_method: String,
    pub ss_password: String,
    pub hy2_obfs_password: String,
    pub shadowtls_password: String,
    pub shadowtls_ss_password: String,
    pub clash_secret: String,
    /// Present iff a REALITY inbound has ever been configured.
    #[serde(default)]
    pub reality: Option<RealityKeys>,
    pub ws_path: String,
    pub vmess_path: String,
    pub xhttp_path: String,
    pub grpc_service: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RealityKeys {
    /// X25519 keys, base64url without padding (43 chars).
    pub private_key: String,
    pub public_key: String,
    /// 16 lowercase hex.
    pub short_id: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RealityTarget {
    pub sni: String,
    /// Handshake target; `127.0.0.1:{site.internal_port}` while the site is active.
    pub dest: HostPort,
    /// Local dokodemo "guard" port used by Xray REALITY (18000–19999).
    pub guard_port: u16,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShadowTls {
    pub sni: String,
    /// Explicit handshake target; `None` means `{sni}:443`. Changing `sni`
    /// clears it so the two cannot drift apart (v2 bug).
    #[serde(default)]
    pub dest: Option<HostPort>,
}

impl ShadowTls {
    pub fn effective_dest(&self) -> String {
        match &self.dest {
            Some(d) => d.to_string(),
            None => format!("{}:443", self.sni),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SiteConfig {
    pub domain: String,
    /// Loopback HTTPS port nginx listens on (REALITY handshake target).
    pub internal_port: u16,
    /// Public HTTPS entrance on TCP 443.
    pub https_entry: bool,
    pub title: String,
    #[serde(default)]
    pub template: SiteTemplate,
    #[serde(default)]
    pub theme: SiteTheme,
    #[serde(default)]
    pub description: String,
    pub cert: WebCert,
    #[serde(default)]
    pub last_content_backup: Option<String>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SiteTemplate {
    #[default]
    Minimal,
    Profile,
    Docs,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SiteTheme {
    #[default]
    Forest,
    Ocean,
    Slate,
}

/// Certificates for public web endpoints (site, subscription, FRP web).
/// Never self-signed: browsers and subscription clients must trust them.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum WebCert {
    Http01,
    Cloudflare,
    Custom { cert: PathBuf, key: PathBuf },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProxyTls {
    pub mode: ProxyCertMode,
    /// Not publicly trusted: clients pin the leaf SHA-256.
    #[serde(default)]
    pub pinned: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum ProxyCertMode {
    SelfSigned {
        sni: String,
    },
    Acme {
        domain: String,
        method: AcmeMethod,
    },
    Custom {
        domain: String,
        cert: PathBuf,
        key: PathBuf,
    },
}

impl ProxyCertMode {
    /// Name clients put in SNI / verify against.
    pub fn server_name(&self) -> &str {
        match self {
            ProxyCertMode::SelfSigned { sni } => sni,
            ProxyCertMode::Acme { domain, .. } | ProxyCertMode::Custom { domain, .. } => domain,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AcmeMethod {
    Http01,
    Cloudflare,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Hy2Settings {
    #[serde(default)]
    pub obfs: bool,
    #[serde(default)]
    pub hop: Option<PortRange>,
    #[serde(default)]
    pub profile: Option<Hy2Profile>,
    /// Integer Mbps, 1..=10000 (validated once; v2 accepted floats it could not render).
    #[serde(default)]
    pub up_mbps: Option<u32>,
    #[serde(default)]
    pub down_mbps: Option<u32>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Hy2Profile {
    Auto,
    Conservative,
    Measured,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ResourceProfile {
    #[default]
    Balanced,
    LowMemory,
    Throughput,
}

/// Inclusive port range `start-end`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct PortRange {
    pub start: u16,
    pub end: u16,
}

impl PortRange {
    pub fn contains(&self, port: u16) -> bool {
        (self.start..=self.end).contains(&port)
    }
}

impl fmt::Display for PortRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}-{}", self.start, self.end)
    }
}

impl FromStr for PortRange {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self> {
        let invalid = || Error::Msg(format!("端口范围格式应为 起始-结束: {s}"));
        let (a, b) = s.trim().split_once('-').ok_or_else(invalid)?;
        let start: u16 = a.trim().parse().map_err(|_| invalid())?;
        let end: u16 = b.trim().parse().map_err(|_| invalid())?;
        if start == 0 || start > end {
            return Err(invalid());
        }
        Ok(PortRange { start, end })
    }
}

impl TryFrom<String> for PortRange {
    type Error = Error;
    fn try_from(s: String) -> Result<Self> {
        s.parse()
    }
}

impl From<PortRange> for String {
    fn from(r: PortRange) -> String {
        r.to_string()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Routing {
    #[serde(default = "yes")]
    pub block_private: bool,
    #[serde(default = "yes")]
    pub block_bt: bool,
    /// The host's own global addresses as `ip/32` / `ip/128`, refreshed on
    /// every apply and at boot; blocked as egress targets with private ranges.
    #[serde(default)]
    pub own_cidrs: Vec<String>,
}

fn yes() -> bool {
    true
}

impl Default for Routing {
    fn default() -> Self {
        Routing {
            block_private: true,
            block_bt: true,
            own_cidrs: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubscriptionConfig {
    pub mode: SubscriptionMode,
    pub port: u16,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum SubscriptionMode {
    /// Plain HTTP on an IP literal; served directly by the worker over TCP.
    Ip { address: IpAddr },
    /// Shares the managed site's domain, certificate and public port.
    Site,
    /// Dedicated HTTPS endpoint behind a private nginx.
    Standalone {
        domain: String,
        cert: WebCert,
        http01_port80: bool,
    },
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoreVersions {
    /// Installed versions (recorded after download / version probe).
    #[serde(default)]
    pub singbox: Option<String>,
    #[serde(default)]
    pub xray: Option<String>,
    /// User pins (`--singbox-version`, `--xray-version`, `update <core> <ver>`).
    #[serde(default)]
    pub singbox_pin: Option<String>,
    #[serde(default)]
    pub xray_pin: Option<String>,
}

impl CoreVersions {
    pub fn installed(&self, core: Core) -> Option<&str> {
        match core {
            Core::Singbox => self.singbox.as_deref(),
            Core::Xray => self.xray.as_deref(),
        }
    }
    pub fn pin(&self, core: Core) -> Option<&str> {
        match core {
            Core::Singbox => self.singbox_pin.as_deref(),
            Core::Xray => self.xray_pin.as_deref(),
        }
    }
}

impl NodeConfig {
    pub fn protocols(&self) -> impl Iterator<Item = Protocol> + '_ {
        self.inbounds.iter().map(|i| i.protocol)
    }
    pub fn inbound(&self, protocol: Protocol) -> Option<&Inbound> {
        self.inbounds.iter().find(|i| i.protocol == protocol)
    }
    pub fn has(&self, protocol: Protocol) -> bool {
        self.inbound(protocol).is_some()
    }
    pub fn any_reality(&self) -> bool {
        self.protocols().any(Protocol::reality)
    }
    pub fn uses(&self, core: Core) -> bool {
        self.inbounds.iter().any(|i| i.core == core)
    }
    pub fn cores(&self) -> Vec<Core> {
        Core::ALL.into_iter().filter(|c| self.uses(*c)).collect()
    }
    /// The website is served only while a REALITY inbound exists.
    pub fn site_active(&self) -> Option<&SiteConfig> {
        self.site.as_ref().filter(|_| self.any_reality())
    }
    pub fn needs_cert(&self) -> bool {
        self.protocols()
            .any(|p| p.certificate() || (p == Protocol::VmessWs && self.vmess_tls))
    }
    /// `{node_name}-{title}` (client-side node label).
    pub fn node_label(&self, protocol: Protocol) -> String {
        format!("{}-{}", self.node_name, protocol.title())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_parsing() {
        assert_eq!(
            "203.0.113.5".parse::<Host>().unwrap().url_host(),
            "203.0.113.5"
        );
        assert_eq!(
            "[2001:db8::1]".parse::<Host>().unwrap().url_host(),
            "[2001:db8::1]"
        );
        assert_eq!(
            "WWW.Example.COM".parse::<Host>().unwrap().to_string(),
            "www.example.com"
        );
        assert!("bad host".parse::<Host>().is_err());
    }

    #[test]
    fn host_port_parsing() {
        let hp: HostPort = "www.microsoft.com:443".parse().unwrap();
        assert_eq!(hp.to_string(), "www.microsoft.com:443");
        let v6: HostPort = "[2001:db8::1]:8443".parse().unwrap();
        assert_eq!(v6.to_string(), "[2001:db8::1]:8443");
        assert!("2001:db8::1:443".parse::<HostPort>().is_err());
        assert!("example.com:0".parse::<HostPort>().is_err());
        assert!("example.com".parse::<HostPort>().is_err());
    }

    #[test]
    fn port_range_parsing() {
        let r: PortRange = "20000-30000".parse().unwrap();
        assert!(r.contains(25000) && !r.contains(19999));
        assert!("3000-2000".parse::<PortRange>().is_err());
        assert_eq!(
            serde_json::to_value(r).unwrap(),
            serde_json::json!("20000-30000")
        );
    }

    #[test]
    fn tagged_enums_serialize_readably() {
        let mode = ProxyCertMode::Acme {
            domain: "a.example.com".into(),
            method: AcmeMethod::Cloudflare,
        };
        assert_eq!(
            serde_json::to_value(&mode).unwrap(),
            serde_json::json!({"type": "acme", "domain": "a.example.com", "method": "cloudflare"})
        );
        let sub = SubscriptionMode::Ip {
            address: "203.0.113.5".parse().unwrap(),
        };
        assert_eq!(
            serde_json::to_value(&sub).unwrap(),
            serde_json::json!({"type": "ip", "address": "203.0.113.5"})
        );
    }
}
