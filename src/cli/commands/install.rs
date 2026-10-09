//! `install` (interactive wizard or unattended) and `plan` /
//! `install --dry-run` (read-only preview).
//!
//! Flow of a real install: root → reinstall confirmation (`--force` under
//! `-y`, G30: subscription devices are cleared) → prerequisites `openssl`,
//! `curl`, `iproute2` (G14) → the wizard when interactive, else the options
//! with defaults and address detection → apply (credentials for Cloudflare
//! resolved first) → optional BBR offer (interactive only, never fatal) →
//! node information card with next steps.
//!
//! A preview never prompts, detects addresses, writes, downloads or needs
//! root on a host without a node; it probes live ports and FRP like the
//! real install.
//!
//! Changes from v2 (spec B §3.1–§3.3, B-9.1#7/#10/#21): `-y` over an
//! installed node needs `--force` (v2 silently regenerated every
//! credential); reinstall clears subscription devices; `--preset N` with
//! `--protocols` is refused unless `N` is 7; `--site-https`/`--site-title`
//! without `--reality-site` are errors; the version pins default to
//! `ONEBOX_SINGBOX_VERSION` / `ONEBOX_XRAY_VERSION` (G34); `--json`
//! outside a preview is an error instead of being ignored.

use super::info;
use crate::apply::ApplyRequest;
use crate::bbr::{self, Action, Queue};
use crate::cli::args::{CommandSpec, Group, Matches, OptSpec, Root};
use crate::cli::options::{self as opt, CertArgs, RealityArgs};
use crate::cli::session::{with_system, LiveProbe, Session};
use crate::ctx::Ctx;
use crate::domain::config::{Host, NodeConfig, PortRange};
use crate::domain::plan::{self, InstallRequest, ProtocolChoice, RealityChoice};
use crate::domain::presets;
use crate::domain::protocol::{Core, Protocol};
use crate::error::{Error, Result};
use crate::host::os::{process_env, EnvLookup};
use crate::ui::confirm_danger;
use serde_json::json;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;

pub const REINSTALL_PROMPT: &str = "重新安装会生成新凭据并清除订阅设备，继续？";
pub const REINSTALL_REFUSED: &str =
    "已安装 Onebox；无人值守重装会生成新凭据，请追加 --force，或使用 onebox regen 保留现有凭据";
const BBR_PROMPT: &str = "启用系统自带 BBR?";
const PREVIEW_HEADER: &str = "只读安装预演（未写文件、下载内核或申请证书）";
/// Commands an install needs, with their packages (G14).
pub const PREREQUISITES: [(&str, &str); 3] =
    [("openssl", "openssl"), ("curl", "curl"), ("ip", "iproute2")];
/// Connection address of a preview without `--addr` (never shown).
const PREVIEW_ADDR: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);

const OPTIONS: &[OptSpec] = &[
    opt::PRESET,
    opt::PROTOCOLS,
    opt::CORE,
    opt::ADDR,
    opt::NAME,
    opt::PORTS,
    opt::SNI,
    opt::REALITY_DEST,
    opt::REALITY_SITE,
    opt::SITE_TITLE,
    opt::SITE_HTTPS,
    opt::TLS,
    opt::DOMAIN,
    opt::CERT,
    opt::KEY,
    opt::HY2_HOP,
    opt::HY2_OBFS,
    opt::HY2_CORE,
    opt::SINGBOX_VERSION,
    opt::XRAY_VERSION,
    opt::NO_BBR,
    opt::FORCE,
    opt::JSON,
];

pub const INSTALL: CommandSpec = CommandSpec::new(
    "install",
    Group::Node,
    "安装节点（交互向导，或 -y 无人值守）",
)
.usage(&[
    "install [选项]",
    "install --preset 1 -y",
    "install --dry-run [选项] [--json]",
])
.options(OPTIONS)
.dry_run()
.root(Root::Custom(install_needs_root))
.handler(install_command);

pub const PLAN: CommandSpec = CommandSpec::new(
    "plan",
    Group::Node,
    "只读安装预演（不写文件、不联网、不申请证书）",
)
.usage(&["plan [安装选项] [--json]"])
.options(OPTIONS)
.dry_run()
.root(Root::NotRequired)
.handler(plan_command);

/// A preview needs root only to read an installed node (checked later).
fn install_needs_root(m: &Matches) -> bool {
    !m.dry_run
}

fn install_command(ctx: &Ctx, m: &Matches) -> Result<()> {
    with_system(ctx, |s| {
        let args = InstallArgs::from_matches(m, &process_env)?;
        if m.dry_run {
            return preview(s, &args);
        }
        install(s, &args)
    })
}

fn plan_command(ctx: &Ctx, m: &Matches) -> Result<()> {
    with_system(ctx, |s| {
        preview(s, &InstallArgs::from_matches(m, &process_env)?)
    })
}

/// The install options as typed values; `None` / empty = not given (the
/// wizard asks, unattended installs use the defaults).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct InstallArgs {
    pub protocols: Option<ProtocolChoice>,
    pub core: Option<Core>,
    pub addr: Option<Host>,
    pub name: Option<String>,
    pub ports: Vec<(Protocol, u16)>,
    pub reality: RealityArgs,
    pub cert: CertArgs,
    pub hy2_obfs: bool,
    pub hy2_hop: Option<PortRange>,
    pub hy2_core: Option<Core>,
    pub singbox_version: Option<String>,
    pub xray_version: Option<String>,
    pub no_bbr: bool,
    pub force: bool,
    pub json: bool,
}

impl InstallArgs {
    pub fn from_matches(m: &Matches, env: EnvLookup) -> Result<InstallArgs> {
        ensure!(
            !m.flag("json") || m.dry_run || m.path.first() == Some(&"plan"),
            "--json 仅用于 plan 或 install --dry-run"
        );
        let reality = opt::reality_args(m, None)?;
        ensure!(
            reality.site_https.is_none(),
            "--site-https 需要先启用自建站"
        );
        Ok(InstallArgs {
            protocols: protocol_choice(opt::preset(m)?, opt::protocols(m)?)?,
            core: opt::core(m, "core")?,
            addr: m.value("addr").map(opt::host).transpose()?,
            name: m.value("name").map(str::to_owned),
            ports: opt::ports(m)?,
            reality,
            cert: opt::cert_args(m, None)?,
            hy2_obfs: m.flag("hy2-obfs"),
            hy2_hop: opt::hop(m)?,
            hy2_core: opt::core(m, "hy2-core")?,
            singbox_version: opt::version_pin(m, "singbox-version", env("ONEBOX_SINGBOX_VERSION")),
            xray_version: opt::version_pin(m, "xray-version", env("ONEBOX_XRAY_VERSION")),
            no_bbr: m.flag("no-bbr"),
            force: m.flag("force"),
            json: m.flag("json"),
        })
    }

    /// The planner request for these options, with `addr` as the
    /// connection address when no `--addr` was given.
    pub fn request(&self, detected: Detected) -> InstallRequest {
        InstallRequest {
            protocols: self
                .protocols
                .clone()
                .unwrap_or(ProtocolChoice::Preset(u32::from(presets::DEFAULT))),
            core: self.core,
            addr: self.addr.clone().or(detected.addr),
            detected_ipv4: detected.ipv4,
            detected_ipv6: detected.ipv6,
            node_name: self.name.clone(),
            ports: self.ports.clone(),
            reality: self.reality.choice.clone(),
            shadowtls_sni: self.reality.shadowtls_sni.clone(),
            cert: self.cert.choice.clone(),
            vmess_host: self.cert.vmess_host.clone(),
            hy2_obfs: self.hy2_obfs,
            hy2_hop: self.hy2_hop,
            hy2_core: self.hy2_core,
            singbox_version: self.singbox_version.clone(),
            xray_version: self.xray_version.clone(),
        }
    }
}

/// `--preset` / `--protocols` (7 = custom pairs with an explicit list).
fn protocol_choice(
    preset: Option<u32>,
    list: Option<Vec<Protocol>>,
) -> Result<Option<ProtocolChoice>> {
    if let Some(n) = preset {
        presets::select(n)?;
    }
    let custom = u32::from(presets::CUSTOM);
    match (preset, list) {
        (Some(n), Some(_)) if n != custom => {
            bail!("--preset 与 --protocols 只能二选一（--preset 7 可配合 --protocols）")
        }
        (_, Some(list)) => Ok(Some(ProtocolChoice::List(list))),
        (Some(n), None) => Ok(Some(ProtocolChoice::Preset(n))),
        (None, None) => Ok(None),
    }
}

/// Addresses found by detection (or chosen in the wizard).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Detected {
    pub addr: Option<Host>,
    pub ipv4: Option<Ipv4Addr>,
    pub ipv6: Option<Ipv6Addr>,
}

impl Detected {
    /// Ask the internet for the public IPv4 and IPv6 (v2 used ipify).
    pub fn detect(session: &Session) -> Detected {
        let ipv4 = match session.live.public_ip(false) {
            Some(IpAddr::V4(v4)) => Some(v4),
            _ => None,
        };
        let ipv6 = match session.live.public_ip(true) {
            Some(IpAddr::V6(v6)) => Some(v6),
            _ => None,
        };
        Detected {
            addr: None,
            ipv4,
            ipv6,
        }
    }

    /// The default connection address: IPv4 first.
    pub fn default_host(&self) -> Option<Host> {
        self.ipv4
            .map(IpAddr::V4)
            .or(self.ipv6.map(IpAddr::V6))
            .map(Host::Ip)
    }
}

/// Plan a complete node for `req` against the live host. `previous` is the
/// node being replaced (its sockets are not foreign).
pub fn plan_node(
    session: &Session,
    req: &InstallRequest,
    dest_after_sni: Option<&crate::domain::config::HostPort>,
    previous: Option<&NodeConfig>,
) -> Result<NodeConfig> {
    let facts = session.facts()?;
    let probe = LiveProbe(session.live);
    let env = facts.env(&probe, previous);
    let cfg = plan::install(req, &env, session.live.rng().as_mut())?;
    match dest_after_sni {
        Some(dest) => plan::set_reality_target(&cfg, &RealityChoice::Dest(dest.clone()), &env),
        None => Ok(cfg),
    }
}

/// `plan` / `install --dry-run`.
pub fn preview(session: &Session, args: &InstallArgs) -> Result<()> {
    let previous = if session.installed() {
        session.require_root()?;
        session.load_optional()?.map(|l| l.config)
    } else {
        None
    };
    let detected = Detected {
        addr: Some(Host::Ip(IpAddr::V4(PREVIEW_ADDR))),
        ..Detected::default()
    };
    let req = args.request(detected);
    let cfg = plan_node(
        session,
        &req,
        args.reality.dest_after_sni.as_ref(),
        previous.as_ref(),
    )?;
    session.data(&preview_text(&cfg, &session.ctx.paths.root, args.json)?)
}

/// The preview output (v2 text, or `--json` with sorted keys).
pub fn preview_text(cfg: &NodeConfig, root: &Path, json: bool) -> Result<String> {
    if json {
        let protocols: Vec<serde_json::Value> = cfg
            .inbounds
            .iter()
            .map(|i| {
                json!({
                    "core": i.core.id(),
                    "network": i.protocol.transport().id(),
                    "port": i.port,
                    "protocol": i.protocol.id(),
                })
            })
            .collect();
        let doc = json!({
            "directory": root,
            "dry_run": true,
            "protocols": protocols,
            "site": cfg.site_active().is_some(),
        });
        return Ok(serde_json::to_string_pretty(&doc)?);
    }
    let mut lines = vec![PREVIEW_HEADER.to_owned()];
    lines.extend(cfg.inbounds.iter().map(|i| {
        format!(
            "{} | {} | {}/{}",
            i.protocol,
            i.core,
            i.port,
            i.protocol.transport().id()
        )
    }));
    lines.push(format!("配置目录: {}", root.display()));
    if let Some(site) = cfg.site_active() {
        lines.push(format!(
            "网站: {}，申请正式证书，HTTPS 443: {}",
            site.domain, site.https_entry
        ));
    }
    Ok(lines.join("\n"))
}

/// A real install (see the module docs).
pub fn install(session: &Session, args: &InstallArgs) -> Result<()> {
    session.require_root()?;
    let previous = session.load_optional()?;
    if previous.is_some()
        && !confirm_danger(
            session.ui(),
            REINSTALL_PROMPT,
            args.force,
            REINSTALL_REFUSED,
        )?
    {
        return Ok(());
    }
    crate::host::pkg::ensure_all(session.ctx, &PREREQUISITES)?;
    let previous = previous.map(|l| l.config);
    let planned = if session.ui().interactive() {
        crate::cli::wizard::run(session, args, previous.as_ref())?
    } else {
        Some(unattended(session, args, previous.as_ref())?)
    };
    let Some(cfg) = planned else {
        session.info("已取消安装");
        return Ok(());
    };
    let mut req = ApplyRequest::install(session.ctx, cfg.clone(), "安装")?;
    req.intents.clear_devices = previous.is_some();
    session.apply(req)?;
    offer_bbr(session, args);
    let installed = session.load_optional()?.map_or(cfg, |l| l.config);
    session.data(&info::card(session, &installed))?;
    session.data(&info::next_steps(&installed))
}

/// The configuration of an unattended install: options plus defaults, the
/// detected address unless `--addr` was given.
pub fn unattended(
    session: &Session,
    args: &InstallArgs,
    previous: Option<&NodeConfig>,
) -> Result<NodeConfig> {
    let detected = Detected::detect(session);
    if args.addr.is_none() && detected.default_host().is_none() {
        return Err(Error::msg("无法检测公网地址，请使用 --addr 指定"));
    }
    let req = args.request(detected);
    plan_node(
        session,
        &req,
        args.reality.dest_after_sni.as_ref(),
        previous,
    )
}

/// The optional BBR step after a successful install (interactive only).
fn offer_bbr(session: &Session, args: &InstallArgs) {
    let ui = session.ui();
    if args.no_bbr || !ui.interactive() {
        return;
    }
    match ui.confirm(BBR_PROMPT, true) {
        Ok(true) => {
            if let Err(e) = bbr::run(session.ctx, Action::Enable(Queue::Fq)) {
                session.warn(format!("代理安装成功；可选 BBR 设置失败: {e}"));
            }
        }
        Ok(false) => {}
        Err(e) => session.warn(format!("代理安装成功；可选 BBR 设置失败: {e}")),
    }
}

#[cfg(test)]
mod tests;
