//! Install planner: every v2 install option (spec B §2.5, §3.3) as typed input.

use super::*;
use crate::domain::credentials;
use crate::domain::presets::{self, Selection};
use crate::domain::protocol::Core;
use crate::sys::rand::Random;

/// Which protocols to install.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProtocolChoice {
    /// Preset number 1–6 (7 = custom requires an explicit list).
    Preset(u32),
    /// Explicit list (`--protocols`, custom menu); stored in canonical order.
    List(Vec<Protocol>),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InstallRequest {
    pub protocols: ProtocolChoice,
    /// `--core`: preferred core (default: the preset's, sing-box for lists).
    pub core: Option<Core>,
    /// `--addr`; `None` uses the detected IPv4, else the detected IPv6.
    pub addr: Option<Host>,
    pub detected_ipv4: Option<Ipv4Addr>,
    pub detected_ipv6: Option<Ipv6Addr>,
    pub node_name: Option<String>,
    /// `--port proto=N` in argument order.
    pub ports: Vec<(Protocol, u16)>,
    pub reality: RealityChoice,
    /// `--sni` also moves the ShadowTLS handshake (v2 parity).
    pub shadowtls_sni: Option<String>,
    /// `None` uses a self-signed certificate when one is needed. A choice is
    /// ignored when no selected protocol needs a certificate (v2 parity).
    pub cert: Option<ProxyCertChoice>,
    /// `Host` header of plain VMess-WS clients (v2 `--domain` without a
    /// domain certificate; CDN fronting).
    pub vmess_host: Option<String>,
    pub hy2_obfs: bool,
    pub hy2_hop: Option<PortRange>,
    pub hy2_core: Option<Core>,
    /// `--singbox-version` / `--xray-version` (`latest` = no pin).
    pub singbox_version: Option<String>,
    pub xray_version: Option<String>,
}

impl Default for InstallRequest {
    fn default() -> Self {
        InstallRequest {
            protocols: ProtocolChoice::Preset(u32::from(presets::DEFAULT)),
            core: None,
            addr: None,
            detected_ipv4: None,
            detected_ipv6: None,
            node_name: None,
            ports: Vec::new(),
            reality: RealityChoice::Default,
            shadowtls_sni: None,
            cert: None,
            vmess_host: None,
            hy2_obfs: false,
            hy2_hop: None,
            hy2_core: None,
            singbox_version: None,
            xray_version: None,
        }
    }
}

/// Build a complete new node: defaults applied, credentials generated, the
/// guard and every port allocated, `installed_at = env.now`. A previous
/// installation (`env.previous`) only exempts its sockets from the probe;
/// nothing else is carried over (reinstall means new credentials).
pub fn install(req: &InstallRequest, env: &PlanEnv, rng: &mut dyn Random) -> Result<NodeConfig> {
    let (list, preferred) = resolve_protocols(&req.protocols)?;
    let core = req.core.unwrap_or(preferred);
    check_hy2_options(req, &list)?;
    let mut inbounds: Vec<Inbound> = list
        .iter()
        .map(|&protocol| {
            let over = req.hy2_core.filter(|_| protocol == Protocol::Hysteria2);
            Inbound {
                protocol,
                port: 0,
                core: presets::assign_core(protocol, core, over),
            }
        })
        .collect();
    apply_explicit_ports(&mut inbounds, &req.ports)?;
    let mut cfg = skeleton(req, env, inbounds, rng)?;
    apply_reality(&mut cfg, &req.reality)?;
    if let Some(sni) = &req.shadowtls_sni {
        cfg.shadowtls.sni = normalize_domain(sni, "ShadowTLS SNI 域名无效")?;
        cfg.shadowtls.dest = None;
    }
    settle_tls(&mut cfg, req.cert.as_ref(), true)?;
    cfg.vmess_host = vmess_host(req.vmess_host.as_deref())?;
    assign_ports(&mut cfg, &req.ports, env)?;
    finish(cfg, env)
}

fn resolve_protocols(choice: &ProtocolChoice) -> Result<(Vec<Protocol>, Core)> {
    match choice {
        ProtocolChoice::Preset(n) => match presets::select(*n)? {
            Selection::Preset(p) => Ok((p.protocols.to_vec(), p.core)),
            Selection::Custom => bail!("自定义预设需要 --protocols"),
        },
        ProtocolChoice::List(list) => {
            let list = presets::canonical(list);
            ensure!(!list.is_empty(), "至少选择一种协议");
            Ok((list, presets::CUSTOM_CORE))
        }
    }
}

fn check_hy2_options(req: &InstallRequest, list: &[Protocol]) -> Result<()> {
    let wants_hy2 = req.hy2_core.is_some() || req.hy2_obfs || req.hy2_hop.is_some();
    ensure!(
        !wants_hy2 || list.contains(&Protocol::Hysteria2),
        "未选择 hysteria2"
    );
    Ok(())
}

fn apply_explicit_ports(inbounds: &mut [Inbound], ports: &[(Protocol, u16)]) -> Result<()> {
    for (i, &(protocol, port)) in ports.iter().enumerate() {
        ensure!(port != 0, "端口不能为 0");
        ensure!(
            !ports[..i].iter().any(|(p, _)| *p == protocol),
            "重复指定协议端口"
        );
        let inbound = inbounds
            .iter_mut()
            .find(|x| x.protocol == protocol)
            .ok_or_else(|| crate::Error::msg(format!("未选择协议: {protocol}")))?;
        inbound.port = port;
    }
    Ok(())
}

/// Defaults, address, credentials and pins; ports still unallocated.
fn skeleton(
    req: &InstallRequest,
    env: &PlanEnv,
    inbounds: Vec<Inbound>,
    rng: &mut dyn Random,
) -> Result<NodeConfig> {
    let node_name = match &req.node_name {
        Some(name) => normalize_label(name, NODE_NAME_ERROR)?,
        None => defaults::NODE_NAME.to_owned(),
    };
    let mut creds = credentials::generate(rng, defaults::SS_METHOD)?;
    if inbounds.iter().any(|i| i.protocol.reality()) {
        creds.reality = Some(credentials::reality_keys(rng)?);
    }
    Ok(NodeConfig {
        schema: SCHEMA,
        node_name,
        server: server_addr(req.addr.clone(), req.detected_ipv4, req.detected_ipv6)?,
        listen: defaults::listen(env.ipv6),
        inbounds,
        creds,
        reality: defaults::reality_target(0),
        shadowtls: defaults::shadowtls(),
        site: None,
        tls: None,
        vmess_tls: false,
        vmess_host: None,
        hy2: Hy2Settings {
            obfs: req.hy2_obfs,
            hop: req.hy2_hop,
            ..Hy2Settings::default()
        },
        resource_profile: ResourceProfile::default(),
        routing: Routing::default(),
        subscription: None,
        versions: CoreVersions {
            singbox_pin: version_pin(req.singbox_version.as_deref())?,
            xray_pin: version_pin(req.xray_version.as_deref())?,
            ..CoreVersions::default()
        },
        installed_at: env.now,
    })
}

/// Explicit ports first (each must be free), then the guard (always assigned,
/// v2 parity, so adding an Xray REALITY inbound later keeps it stable), then
/// automatic ports in storage order.
fn assign_ports(cfg: &mut NodeConfig, explicit: &[(Protocol, u16)], env: &PlanEnv) -> Result<()> {
    let previous = env
        .previous
        .map(|p| PortPlan::of(p, env.frp))
        .unwrap_or_default();
    for &(protocol, port) in explicit {
        check_explicit_port(cfg, protocol, port, env, &previous)?;
    }
    ensure_guard(cfg, env, &previous)?;
    allocate_missing(cfg, env, &previous)
}

#[cfg(test)]
mod tests;
