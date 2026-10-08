//! `NodeSpec`: the validated, resolved view of a `NodeConfig` every
//! renderer reads. All configuration errors surface in [`NodeSpec::new`];
//! renderers only combine the resolved values.
//!
//! Changes from v2:
//! - the configuration is validated once here (`NodeConfig::validate`)
//!   instead of each renderer re-checking stringly-typed values with its own
//!   messages (C-8.1 #1, #5, #6); handshake targets, ports and bandwidths
//!   are typed, so parse failures are impossible (#9, #12);
//! - certificate material is loaded once per render and shared (#13);
//! - plain VMess-WS clients send `NodeConfig::vmess_host` as `Host`
//!   (ARCH §10; v2 used `DOMAIN`);
//! - certificate paths are always `ROOT/tls/{cert,key}.pem` (v2's
//!   `CERT_FILE`/`KEY_FILE` always held those paths after a deployment);
//! - the probe's loopback view uses a specific listen address when the node
//!   binds one (C-8.1 #21), see [`NodeSpec::local`].

use super::policy::PRIVATE_CIDRS;
use super::tls::TlsMaterial;
use crate::domain::config::*;
use crate::domain::defaults;
use crate::domain::protocol::{ClientFormat, Core, Protocol};
use crate::error::{Error, Result};
use crate::paths::Paths;
use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr};
use std::path::Path;

/// Resolved values for rendering one node.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NodeSpec {
    /// Address clients connect to (`127.0.0.1` / the listen address in the
    /// probe's loopback view).
    pub server: Host,
    /// Listen address of every public inbound.
    pub listen: IpAddr,
    /// Enabled inbounds in configuration order.
    pub inbounds: Vec<InboundSpec>,
    pub creds: Credentials,
    pub reality: Option<RealitySpec>,
    pub shadowtls: ShadowTlsSpec,
    /// Certificate TLS; present iff a certificate protocol is enabled.
    pub tls: Option<TlsSpec>,
    pub vmess: VmessSpec,
    pub hy2: Hy2Spec,
    pub routing: RoutingSpec,
    /// The own-domain website while it is active.
    pub site: Option<SiteSpec>,
    /// Own endpoints clients reach without the tunnel.
    pub direct: DirectTargets,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InboundSpec {
    pub protocol: Protocol,
    pub port: u16,
    pub core: Core,
    /// Client-side node name `{node_name}-{title}`.
    pub label: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RealitySpec {
    pub sni: String,
    /// Handshake target (sing-box directly, Xray through the guard).
    pub dest: HostPort,
    /// Local Xray guard (dokodemo) port.
    pub guard_port: u16,
    pub private_key: String,
    pub public_key: String,
    pub short_id: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShadowTlsSpec {
    pub sni: String,
    /// Effective handshake target (`{sni}:443` unless configured).
    pub dest: HostPort,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TlsSpec {
    /// Certificate name: SNI clients send and verify.
    pub server_name: String,
    /// Deployed certificate and key (`ROOT/tls/cert.pem`, `ROOT/tls/key.pem`).
    pub cert_path: String,
    pub key_path: String,
    pub trust: CertTrust,
}

/// How clients verify the proxy certificate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CertTrust {
    /// Publicly trusted: ordinary verification.
    Public,
    /// Not publicly trusted: clients pin the deployed certificate.
    Pinned(TlsMaterial),
    /// Pinned, but the certificate was not loaded (server-only renders such
    /// as an install preview). Client formats that need the pin fail.
    PinnedUnloaded,
}

impl TlsSpec {
    /// The pinned material; `None` for publicly trusted certificates.
    pub fn pinned_material(&self) -> Result<Option<&TlsMaterial>> {
        match &self.trust {
            CertTrust::Public => Ok(None),
            CertTrust::Pinned(material) => Ok(Some(material)),
            CertTrust::PinnedUnloaded => Err(Error::msg("固定证书的客户端配置缺少证书指纹")),
        }
    }

    pub fn pinned(&self) -> bool {
        !matches!(self.trust, CertTrust::Public)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VmessSpec {
    /// VMess-WS runs over certificate TLS.
    pub tls: bool,
    /// `Host` header VMess-WS clients send: the certificate name with TLS,
    /// `vmess_host` (CDN fronting) without; `None` sends no header.
    pub ws_host: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Hy2Spec {
    /// Salamander obfuscation password when obfuscation is on.
    pub obfs_password: Option<String>,
    /// UDP port-hopping range.
    pub hop: Option<PortRange>,
    /// Congestion profile (`None` = untuned).
    pub profile: Option<Hy2Profile>,
    /// Measured bandwidth (client perspective), present iff `Measured`.
    pub bandwidth: Option<Bandwidth>,
    /// QUIC receive windows from the resource profile.
    pub windows: Option<Hy2Windows>,
}

/// Client-perspective bandwidth in Mbps (validated 1..=10000).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Bandwidth {
    pub up_mbps: u32,
    pub down_mbps: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Hy2Windows {
    pub stream: u64,
    pub connection: u64,
    /// Server-side concurrent stream limit.
    pub max_streams: u64,
}

impl Hy2Windows {
    /// QUIC windows of a resource profile (v2 values); balanced = defaults.
    pub fn of(profile: ResourceProfile) -> Option<Hy2Windows> {
        match profile {
            ResourceProfile::Balanced => None,
            ResourceProfile::LowMemory => Some(Hy2Windows {
                stream: 2_097_152,
                connection: 5_242_880,
                max_streams: 64,
            }),
            ResourceProfile::Throughput => Some(Hy2Windows {
                stream: 16_777_216,
                connection: 41_943_040,
                max_streams: 1024,
            }),
        }
    }
}

/// Address families the server has (domain strategy of the egress).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Families {
    V4Only,
    V6Only,
    /// Both, or neither detected (v2 treated "none" like "both").
    Dual,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RoutingSpec {
    pub block_private: bool,
    pub block_bt: bool,
    /// Egress targets the servers reject: private ranges plus the node's own
    /// addresses, as a sorted, de-duplicated list of strings (v2 order).
    pub blocked_cidrs: Vec<String>,
    pub families: Families,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SiteSpec {
    pub domain: String,
    pub internal_port: u16,
    pub https_entry: bool,
}

/// Own endpoints (subscription host, website domain) that full client
/// configurations route directly, ahead of the Global mode.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DirectTargets {
    /// Sorted lower-case domains.
    pub domains: Vec<String>,
    /// Sorted `ip/32` / `ip/128` strings.
    pub cidrs: Vec<String>,
}

impl NodeSpec {
    /// Validate `cfg` and resolve it. `tls` is the deployed proxy certificate;
    /// it is only consulted when clients pin it.
    pub fn new(cfg: &NodeConfig, paths: &Paths, tls: Option<&TlsMaterial>) -> Result<NodeSpec> {
        cfg.validate()?;
        let inbounds = cfg
            .inbounds
            .iter()
            .map(|i| InboundSpec {
                protocol: i.protocol,
                port: i.port,
                core: i.core,
                label: cfg.node_label(i.protocol),
            })
            .collect();
        let tls_spec = tls_spec(cfg, paths, tls)?;
        Ok(NodeSpec {
            server: cfg.server.addr.clone(),
            listen: cfg.listen,
            inbounds,
            creds: Credentials {
                reality: None,
                ..cfg.creds.clone()
            },
            reality: reality_spec(cfg)?,
            shadowtls: ShadowTlsSpec {
                sni: cfg.shadowtls.sni.clone(),
                dest: cfg
                    .shadowtls
                    .dest
                    .clone()
                    .unwrap_or_else(|| defaults::handshake_dest(&cfg.shadowtls.sni)),
            },
            vmess: vmess_spec(cfg, tls_spec.as_ref()),
            tls: tls_spec,
            hy2: hy2_spec(cfg),
            routing: routing_spec(cfg),
            site: cfg.site_active().map(|s| SiteSpec {
                domain: s.domain.clone(),
                internal_port: s.internal_port,
                https_entry: s.https_entry,
            }),
            direct: direct_targets(cfg),
        })
    }

    /// [`NodeSpec::new`] with the deployed certificate (`ROOT/tls/cert.pem`)
    /// loaded when clients pin it.
    pub fn load(cfg: &NodeConfig, paths: &Paths) -> Result<NodeSpec> {
        let pinned = cfg.needs_cert() && cfg.tls.as_ref().is_some_and(|t| t.pinned);
        let material = if pinned {
            Some(TlsMaterial::deployed(paths)?)
        } else {
            None
        };
        Self::new(cfg, paths, material.as_ref())
    }

    /// The same node as seen from the server itself (probe `--local`,
    /// server-local REALITY check): clients connect to the listen address
    /// when it is a specific one, else to `127.0.0.1`.
    pub fn local(&self) -> NodeSpec {
        let host = if self.listen.is_unspecified() {
            IpAddr::V4(Ipv4Addr::LOCALHOST)
        } else {
            self.listen
        };
        NodeSpec {
            server: Host::Ip(host),
            ..self.clone()
        }
    }

    /// Server address as JSON configurations carry it (IPv6 unbracketed).
    pub fn server_host(&self) -> String {
        self.server.to_string()
    }

    /// Server address inside URIs (IPv6 bracketed).
    pub fn uri_host(&self) -> String {
        self.server.url_host()
    }

    pub fn inbound(&self, protocol: Protocol) -> Option<&InboundSpec> {
        self.inbounds.iter().find(|i| i.protocol == protocol)
    }

    /// The enabled inbound of `protocol`, or a Chinese error.
    pub fn require(&self, protocol: Protocol) -> Result<&InboundSpec> {
        self.inbound(protocol)
            .ok_or_else(|| Error::msg(format!("未启用协议 {protocol}")))
    }

    /// Inbounds served by `core`, in configuration order.
    pub fn on_core(&self, core: Core) -> impl Iterator<Item = &InboundSpec> + '_ {
        self.inbounds.iter().filter(move |i| i.core == core)
    }

    /// Inbounds a client format can carry, in configuration order.
    pub fn for_format(&self, format: ClientFormat) -> Vec<&InboundSpec> {
        self.inbounds
            .iter()
            .filter(|i| format.supports(i.protocol))
            .collect()
    }

    /// Enabled protocols a format leaves out (for "not included" notices).
    pub fn omitted(&self, format: ClientFormat) -> Vec<Protocol> {
        self.inbounds
            .iter()
            .map(|i| i.protocol)
            .filter(|p| !format.supports(*p))
            .collect()
    }

    /// Client formats with at least one node, in `ClientFormat::ALL` order.
    pub fn formats(&self) -> Vec<ClientFormat> {
        ClientFormat::ALL
            .into_iter()
            .filter(|f| !self.for_format(*f).is_empty())
            .collect()
    }

    /// Xray hosts a REALITY inbound, so it needs the local guard.
    pub fn uses_xray_reality(&self) -> bool {
        self.on_core(Core::Xray).any(|i| i.protocol.reality())
    }

    /// Xray Vision and XHTTP share one TCP port: Vision terminates REALITY
    /// and falls back to XHTTP over the abstract socket.
    pub fn xhttp_shared(&self) -> bool {
        let xray_port = |p| {
            self.inbound(p)
                .filter(|i| i.core == Core::Xray)
                .map(|i| i.port)
        };
        match (
            xray_port(Protocol::VlessReality),
            xray_port(Protocol::VlessXhttp),
        ) {
            (Some(a), Some(b)) => a == b,
            _ => false,
        }
    }

    /// REALITY settings; present whenever a REALITY inbound is enabled.
    pub fn reality(&self) -> Result<&RealitySpec> {
        self.reality
            .as_ref()
            .ok_or_else(|| Error::msg("缺少 REALITY 密钥"))
    }

    /// Certificate TLS; present whenever a certificate protocol is enabled.
    pub fn tls(&self) -> Result<&TlsSpec> {
        self.tls
            .as_ref()
            .ok_or_else(|| Error::msg("当前协议需要代理 TLS 证书"))
    }

    /// Label of the ShadowTLS inbound (its transport outbound is `{label}-tls`).
    pub fn shadowtls_label(&self) -> Result<&str> {
        Ok(&self.require(Protocol::Shadowtls)?.label)
    }
}

/// File names of the deployed proxy certificate pair inside `ROOT/tls`.
pub const CERT_FILE: &str = "cert.pem";
pub const KEY_FILE: &str = "key.pem";

fn utf8(path: &Path) -> Result<String> {
    path.to_str()
        .map(str::to_owned)
        .ok_or_else(|| Error::msg(format!("路径不是 UTF-8: {}", path.display())))
}

fn tls_spec(cfg: &NodeConfig, paths: &Paths, tls: Option<&TlsMaterial>) -> Result<Option<TlsSpec>> {
    let Some(proxy) = cfg.tls.as_ref().filter(|_| cfg.needs_cert()) else {
        return Ok(None);
    };
    let trust = match (proxy.pinned, tls) {
        (false, _) => CertTrust::Public,
        (true, Some(material)) => CertTrust::Pinned(material.clone()),
        (true, None) => CertTrust::PinnedUnloaded,
    };
    let dir = paths.tls();
    Ok(Some(TlsSpec {
        server_name: proxy.mode.server_name().to_owned(),
        cert_path: utf8(&dir.join(CERT_FILE))?,
        key_path: utf8(&dir.join(KEY_FILE))?,
        trust,
    }))
}

fn reality_spec(cfg: &NodeConfig) -> Result<Option<RealitySpec>> {
    if !cfg.any_reality() {
        return Ok(None);
    }
    let keys = cfg
        .creds
        .reality
        .as_ref()
        .ok_or_else(|| Error::msg("缺少 REALITY 密钥"))?;
    Ok(Some(RealitySpec {
        sni: cfg.reality.sni.clone(),
        dest: cfg.reality.dest.clone(),
        guard_port: cfg.reality.guard_port,
        private_key: keys.private_key.clone(),
        public_key: keys.public_key.clone(),
        short_id: keys.short_id.clone(),
    }))
}

fn vmess_spec(cfg: &NodeConfig, tls: Option<&TlsSpec>) -> VmessSpec {
    let tls = tls.filter(|_| cfg.vmess_tls);
    VmessSpec {
        tls: tls.is_some(),
        ws_host: match tls {
            Some(tls) => Some(tls.server_name.clone()),
            None => cfg.vmess_host.clone(),
        },
    }
}

fn hy2_spec(cfg: &NodeConfig) -> Hy2Spec {
    let hy2 = &cfg.hy2;
    let bandwidth = match (hy2.profile, hy2.up_mbps, hy2.down_mbps) {
        (Some(Hy2Profile::Measured), Some(up_mbps), Some(down_mbps)) => {
            Some(Bandwidth { up_mbps, down_mbps })
        }
        _ => None,
    };
    Hy2Spec {
        obfs_password: hy2.obfs.then(|| cfg.creds.hy2_obfs_password.clone()),
        hop: hy2.hop,
        profile: hy2.profile,
        bandwidth,
        windows: Hy2Windows::of(cfg.resource_profile),
    }
}

fn host_cidr(ip: IpAddr) -> String {
    let prefix = if ip.is_ipv4() { 32 } else { 128 };
    format!("{ip}/{prefix}")
}

/// Private ranges ∪ detected addresses (unless behind WARP) ∪ the public
/// address ∪ refreshed own addresses, sorted as strings (v2 `cidrs`).
fn routing_spec(cfg: &NodeConfig) -> RoutingSpec {
    let server = &cfg.server;
    let mut cidrs: BTreeSet<String> = PRIVATE_CIDRS.iter().map(|c| c.to_string()).collect();
    let v4 = server.ipv4.filter(|_| !server.ipv4_warp).map(IpAddr::V4);
    let v6 = server.ipv6.filter(|_| !server.ipv6_warp).map(IpAddr::V6);
    cidrs.extend(
        [v4, v6, server.addr.ip()]
            .into_iter()
            .flatten()
            .map(host_cidr),
    );
    cidrs.extend(cfg.routing.own_cidrs.iter().cloned());
    let families = match (server.ipv4.is_some(), server.ipv6.is_some()) {
        (true, false) => Families::V4Only,
        (false, true) => Families::V6Only,
        _ => Families::Dual,
    };
    RoutingSpec {
        block_private: cfg.routing.block_private,
        block_bt: cfg.routing.block_bt,
        blocked_cidrs: cidrs.into_iter().collect(),
        families,
    }
}

/// Subscription endpoint host and website domain.
fn direct_targets(cfg: &NodeConfig) -> DirectTargets {
    let site = cfg.site_active().map(|s| Host::Domain(s.domain.clone()));
    let subscription = cfg.subscription.as_ref().and_then(|sub| match &sub.mode {
        SubscriptionMode::Ip { address } => Some(Host::Ip(*address)),
        SubscriptionMode::Site => site.clone(),
        SubscriptionMode::Standalone { domain, .. } => Some(Host::Domain(domain.clone())),
    });
    let mut domains = BTreeSet::new();
    let mut cidrs = BTreeSet::new();
    for host in [subscription, site].into_iter().flatten() {
        match host {
            Host::Ip(ip) => cidrs.insert(host_cidr(ip)),
            Host::Domain(domain) => domains.insert(domain),
        };
    }
    DirectTargets {
        domains: domains.into_iter().collect(),
        cidrs: cidrs.into_iter().collect(),
    }
}

#[cfg(test)]
mod tests;
