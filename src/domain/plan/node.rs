//! Planners for an installed node: protocols, ports, address, credentials,
//! handshake targets, Hysteria2/resource tuning and the proxy certificate.

use super::*;
use crate::domain::credentials;
use crate::domain::presets;
use crate::domain::protocol::Core;
use crate::sys::rand::Random;

/// Options of `onebox add PROTO` (the v2 `apply_options` that `add` ran,
/// spec B §3.4 step 7).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AddOptions {
    /// `--core`: preferred core (default: the core of the first inbound).
    /// Hysteria2 follows the install rule and stays on sing-box; only
    /// `hy2_core` moves it (v2 parity).
    pub core: Option<Core>,
    pub port: Option<u16>,
    /// Applied when not `Default` (typically chosen for the first REALITY inbound).
    pub reality: RealityChoice,
    /// Certificate to use; a self-signed one is created when the new
    /// protocol needs a certificate and none exists.
    pub cert: Option<ProxyCertChoice>,
    /// `--hy2-obfs`: Salamander obfuscation on (Hysteria2 only).
    pub hy2_obfs: bool,
    /// `--hy2-hop A-B`: UDP port hopping range (Hysteria2 only).
    pub hy2_hop: Option<PortRange>,
    /// `--hy2-core`: core for Hysteria2 (Hysteria2 only).
    pub hy2_core: Option<Core>,
    /// `--domain` as the plain VMess-WS `Host` header ([`NodeConfig::vmess_host`]).
    pub vmess_host: Option<String>,
}

pub fn add(
    cfg: &NodeConfig,
    protocol: Protocol,
    opts: &AddOptions,
    env: &PlanEnv,
    rng: &mut dyn Random,
) -> Result<NodeConfig> {
    ensure!(!cfg.has(protocol), "协议已存在");
    let hy2 = protocol == Protocol::Hysteria2;
    let hy2_options = opts.hy2_obfs || opts.hy2_hop.is_some() || opts.hy2_core.is_some();
    ensure!(hy2 || !hy2_options, "未选择 hysteria2");
    let preferred = opts
        .core
        .or_else(|| cfg.inbounds.first().map(|i| i.core))
        .unwrap_or(presets::CUSTOM_CORE);
    let mut next = cfg.clone();
    next.inbounds.push(Inbound {
        protocol,
        port: opts.port.unwrap_or(0),
        core: presets::assign_core(protocol, preferred, opts.hy2_core),
    });
    if hy2 {
        next.hy2.obfs |= opts.hy2_obfs;
        next.hy2.hop = opts.hy2_hop.or(next.hy2.hop);
    }
    if opts.vmess_host.is_some() {
        next.vmess_host = vmess_host(opts.vmess_host.as_deref())?;
    }
    let first_reality = protocol.reality() && !cfg.any_reality();
    if first_reality && next.creds.reality.is_none() {
        next.creds.reality = Some(credentials::reality_keys(rng)?);
    }
    let choice = first_reality_choice(cfg, &opts.reality, first_reality);
    apply_reality(&mut next, choice)?;
    check_site_subscription(cfg, &next)?;
    settle_tls(&mut next, opts.cert.as_ref(), protocol == Protocol::VmessWs)?;
    ensure!(
        opts.cert.is_none() || next.tls.is_some(),
        "{NO_CERT_NEEDED}"
    );
    let previous = env.previous_plan(cfg);
    if let Some(port) = opts.port {
        check_explicit_port(&next, protocol, port, env, &previous)?;
    }
    if next.uses_guard() {
        ensure_guard(&mut next, env, &previous)?;
    }
    allocate_missing(&mut next, env, &previous)?;
    finish(next, env)
}

/// The target for an added REALITY inbound. `Default` keeps the current
/// target, except that the first REALITY inbound never inherits a loopback
/// target with no site behind it (a site removed with the last REALITY
/// inbound, or a v2 leftover): it falls back to the Microsoft default.
fn first_reality_choice<'a>(
    cfg: &NodeConfig,
    choice: &'a RealityChoice,
    first_reality: bool,
) -> &'a RealityChoice {
    let loopback = cfg
        .reality
        .dest
        .host
        .ip()
        .is_some_and(|ip| ip.is_loopback());
    match choice {
        RealityChoice::Default if first_reality && loopback && cfg.site.is_none() => {
            &RealityChoice::Microsoft
        }
        other => other,
    }
}

/// Remove an inbound. Dropping the last REALITY inbound also drops the own
/// site, the REALITY keys and the site-specific handshake target.
pub fn remove(cfg: &NodeConfig, protocol: Protocol) -> Result<NodeConfig> {
    ensure!(cfg.has(protocol), "协议未启用");
    ensure!(
        cfg.inbounds.len() > 1,
        "至少保留一个协议；全部删除请使用 uninstall"
    );
    let mut next = cfg.clone();
    next.inbounds.retain(|i| i.protocol != protocol);
    if !next.any_reality() {
        if next.site.is_some() {
            external_target(&mut next, defaults::REALITY_SNI);
        }
        next.creds.reality = None;
        check_site_subscription(cfg, &next)?;
    }
    settle_tls(&mut next, None, false)?;
    finish_local(next)
}

pub fn set_port(
    cfg: &NodeConfig,
    protocol: Protocol,
    port: u16,
    env: &PlanEnv,
) -> Result<NodeConfig> {
    ensure!(cfg.has(protocol), "协议未启用");
    let mut next = cfg.clone();
    if let Some(inbound) = next.inbound_mut(protocol) {
        inbound.port = port;
    }
    let previous = env.previous_plan(cfg);
    let plan = PortPlan::of(&next, env.frp);
    let owner = Owner::Inbound(protocol);
    let free = plan.is_free(
        port,
        protocol.transport(),
        &owner,
        env.probe,
        Some(&previous),
    );
    ensure!(free, "端口无效或被占用");
    finish(next, env)
}

/// New public address (and optionally node name). The other address family
/// comes only from `ipv4`/`ipv6` (fresh detection), never from stale state.
pub fn set_address(
    cfg: &NodeConfig,
    addr: Host,
    node_name: Option<&str>,
    ipv4: Option<Ipv4Addr>,
    ipv6: Option<Ipv6Addr>,
) -> Result<NodeConfig> {
    let mut next = cfg.clone();
    let mut server = server_addr(Some(addr), ipv4, ipv6)?;
    // Legacy WARP flags describe a specific address; keep them only for it.
    server.ipv4_warp = cfg.server.ipv4_warp && server.ipv4 == cfg.server.ipv4;
    server.ipv6_warp = cfg.server.ipv6_warp && server.ipv6 == cfg.server.ipv6;
    next.server = server;
    if let Some(name) = node_name {
        next.node_name = normalize_label(name, NODE_NAME_ERROR)?;
    }
    finish_local(next)
}

pub fn reset_credentials(cfg: &NodeConfig, rng: &mut dyn Random) -> Result<NodeConfig> {
    let mut next = cfg.clone();
    credentials::reset(&mut next.creds, rng)?;
    finish_local(next)
}

pub fn set_reality_target(
    cfg: &NodeConfig,
    choice: &RealityChoice,
    env: &PlanEnv,
) -> Result<NodeConfig> {
    ensure!(cfg.any_reality(), "没有启用 REALITY 协议");
    let mut next = cfg.clone();
    apply_reality(&mut next, choice)?;
    check_site_subscription(cfg, &next)?;
    finish(next, env)
}

/// New ShadowTLS handshake name; an explicit target is cleared so SNI and
/// target cannot drift apart (v2 bug B-9.1 #3).
pub fn set_shadowtls_sni(cfg: &NodeConfig, sni: &str) -> Result<NodeConfig> {
    ensure!(cfg.has(Protocol::Shadowtls), "未启用 ShadowTLS");
    let mut next = cfg.clone();
    next.shadowtls.sni = normalize_domain(sni, "ShadowTLS SNI 域名无效")?;
    next.shadowtls.dest = None;
    finish_local(next)
}

/// Hysteria2 profile. `measured` needs both bandwidths (a value not given
/// keeps the current `measured` value); other profiles clear them.
pub fn tune_hy2(
    cfg: &NodeConfig,
    profile: Hy2Profile,
    up: Option<u32>,
    down: Option<u32>,
) -> Result<NodeConfig> {
    let core = cfg.core_of(Protocol::Hysteria2).ok_or("未启用 Hysteria2")?;
    ensure!(
        core == Core::Singbox,
        "Xray 承载的 Hysteria2 不支持带宽调优，请改用 sing-box 承载"
    );
    for mbps in [up, down].into_iter().flatten() {
        ensure!(
            defaults::HY2_MBPS.contains(&mbps),
            "带宽值无效（应为 1–10000 的整数 Mbps）"
        );
    }
    let mut next = cfg.clone();
    if profile == Hy2Profile::Measured {
        next.hy2.up_mbps = up.or(cfg.hy2.up_mbps);
        next.hy2.down_mbps = down.or(cfg.hy2.down_mbps);
        ensure!(
            next.hy2.up_mbps.is_some() && next.hy2.down_mbps.is_some(),
            "measured 需要 --up 和 --down"
        );
    } else {
        ensure!(
            up.is_none() && down.is_none(),
            "--up/--down 仅用于 measured 档位"
        );
        next.hy2.up_mbps = None;
        next.hy2.down_mbps = None;
    }
    next.hy2.profile = Some(profile);
    finish_local(next)
}

/// Hysteria2 obfuscation and port hopping after install (v2 could set them
/// only while adding Hysteria2, so changing them meant a reinstall with new
/// credentials). `hop: None` turns hopping off. The range is checked against
/// every other UDP listener and FRP.
pub fn set_hy2(
    cfg: &NodeConfig,
    obfs: bool,
    hop: Option<PortRange>,
    env: &PlanEnv,
) -> Result<NodeConfig> {
    ensure!(cfg.has(Protocol::Hysteria2), "未启用 Hysteria2");
    let mut next = cfg.clone();
    next.hy2.obfs = obfs;
    next.hy2.hop = hop;
    finish(next, env)
}

/// Plain VMess-WS `Host` header; `None` or blank sends none.
pub fn set_vmess_host(cfg: &NodeConfig, host: Option<&str>) -> Result<NodeConfig> {
    let mut next = cfg.clone();
    next.vmess_host = vmess_host(host)?;
    finish_local(next)
}

pub fn tune_resource(cfg: &NodeConfig, profile: ResourceProfile) -> Result<NodeConfig> {
    let mut next = cfg.clone();
    next.resource_profile = profile;
    finish_local(next)
}

/// Back to untuned Hysteria2 and the balanced resource profile.
pub fn tune_reset(cfg: &NodeConfig) -> Result<NodeConfig> {
    let mut next = cfg.clone();
    next.hy2.profile = None;
    next.hy2.up_mbps = None;
    next.hy2.down_mbps = None;
    next.resource_profile = ResourceProfile::Balanced;
    finish_local(next)
}

/// Replace the proxy certificate (`cert set`); `vmess_tls` follows the
/// certificate kind.
pub fn set_proxy_cert(cfg: &NodeConfig, choice: &ProxyCertChoice) -> Result<NodeConfig> {
    let mut next = cfg.clone();
    settle_tls(&mut next, Some(choice), false)?;
    ensure!(next.tls.is_some(), "{NO_CERT_NEEDED}");
    finish_local(next)
}

#[cfg(test)]
mod tests;
