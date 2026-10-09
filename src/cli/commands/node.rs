//! Protocol commands of an installed node: `add`, `del|remove`, `port`,
//! `reset` and `regen`.
//!
//! Each command has a `plan_*` function that loads the node, asks what the
//! command line did not say (interactive only) and returns the
//! `ApplyRequest` (`None` = nothing to do), and a thin handler that applies
//! it and prints the v2 tail `配置已更新`.
//!
//! Changes from v2 (spec B §3.4–§3.10, B-9.1#4/#6/#9/#19): the added
//! protocol's port is checked like any explicit port; a protocol that needs
//! a certificate asks for one interactively (v2 silently used a
//! self-signed one); the AnyTLS-REALITY hint follows only the addition of
//! AnyTLS-REALITY itself; selections are numbered menus of the relevant
//! protocols with `0) 返回`; `add --port` takes `端口` or v2's
//! `协议=端口`; `port` without a port under `-y` keeps the current one and
//! changes nothing; `del` never deletes by default: Enter at its menu goes
//! back, and without a terminal (or under `-y`) the protocol must be named
//! (v2 deleted the first protocol).

use crate::apply::ApplyRequest;
use crate::cli::args::{ArgSpec, CommandSpec, Group, Matches, OptSpec};
use crate::cli::options::{self as opt, CertArgs, RealityArgs};
use crate::cli::session::{request, with_system, LiveProbe, Session};
use crate::cli::wizard::steps;
use crate::ctx::Ctx;
use crate::domain::config::{NodeConfig, PortRange, WebCert};
use crate::domain::plan::{self, AddOptions, RealityChoice};
use crate::domain::protocol::{Core, Protocol};
use crate::error::Result;
use crate::state::Loaded;
use crate::ui;

/// The v2 tail after a node change (scripts grep it).
pub const UPDATED: &str = "配置已更新";
/// `del` without a protocol where nobody can choose one.
pub const DEL_NEEDS_PROTOCOL: &str = "请指定要删除的协议，例如 onebox del tuic";
const ANYTLS_REALITY_HINT: &str =
    "AnyTLS-REALITY: onebox client singbox，或使用 sing-box 远程配置订阅";

const ADD_PORT: OptSpec = OptSpec::value(
    "port",
    "端口",
    "新协议的端口（也接受 协议=端口）；默认自动分配",
);

pub const ADD: CommandSpec = CommandSpec::new(
    "add",
    Group::Node,
    "添加协议（自动分配端口，需要时准备证书）",
)
.usage(&["add [协议] [选项]"])
.args(&[ArgSpec::optional("协议", "协议名；省略时交互选择")])
.options(&[
    opt::CORE,
    ADD_PORT,
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
])
.handler(add_command);

pub const DEL: CommandSpec = CommandSpec::new("del", Group::Node, "删除协议（至少保留一个）")
    .aliases(&["remove"])
    .args(&[ArgSpec::optional("协议", "协议名；省略时交互选择")])
    .handler(del_command);

pub const PORT: CommandSpec = CommandSpec::new("port", Group::Node, "修改协议端口")
    .usage(&["port [协议] [端口]"])
    .args(&[
        ArgSpec::optional("协议", "协议名；省略时交互选择"),
        ArgSpec::optional("端口", "新端口；省略时交互输入"),
    ])
    .handler(port_command);

pub const RESET: CommandSpec = CommandSpec::new(
    "reset",
    Group::Node,
    "重置全部 UUID、密码与密钥（客户端需重新导入）",
)
.handler(reset_command);

pub const REGEN: CommandSpec = CommandSpec::new(
    "regen",
    Group::Maintain,
    "按当前状态重新生成并应用全部配置（凭据不变；也用于从 v2 迁移）",
)
.handler(regen_command);

/// The options of `add` after the protocol.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AddArgs {
    pub core: Option<Core>,
    /// `N` or `协议=N` (checked against the added protocol).
    pub port: Option<String>,
    pub reality: RealityArgs,
    pub cert: CertArgs,
    pub hy2_obfs: bool,
    pub hy2_hop: Option<PortRange>,
    pub hy2_core: Option<Core>,
}

impl AddArgs {
    pub fn from_matches(m: &Matches) -> Result<AddArgs> {
        Ok(AddArgs {
            core: opt::core(m, "core")?,
            port: m.value("port").map(str::to_owned),
            reality: opt::reality_args(m, WebCert::Http01)?,
            cert: opt::cert_args(m, None)?,
            hy2_obfs: m.flag("hy2-obfs"),
            hy2_hop: opt::hop(m)?,
            hy2_core: opt::core(m, "hy2-core")?,
        })
    }

    /// The port for `protocol` (`协议=端口` must name it).
    fn port_for(&self, protocol: Protocol) -> Result<Option<u16>> {
        let Some(text) = self.port.as_deref() else {
            return Ok(None);
        };
        let number = match text.split_once('=') {
            Some((named, number)) => {
                let named: Protocol = named.trim().parse()?;
                ensure!(named == protocol, "未选择协议: {named}");
                number
            }
            None => text,
        };
        opt::port(number).map(Some)
    }
}

fn add_command(ctx: &Ctx, m: &Matches) -> Result<()> {
    let protocol = m.positional(0).map(str::parse).transpose()?;
    let args = AddArgs::from_matches(m)?;
    with_system(ctx, |s| add(s, protocol, &args))
}

/// `add`: plan, apply, v2 tail.
pub fn add(session: &Session, protocol: Option<Protocol>, args: &AddArgs) -> Result<()> {
    let Some((req, added)) = plan_add(session, protocol, args)? else {
        return Ok(());
    };
    session.apply(req)?;
    session.data(UPDATED)?;
    if added == Protocol::AnytlsReality {
        session.data(ANYTLS_REALITY_HINT)?;
    }
    Ok(())
}

/// The request adding a protocol (`None`: the user went back).
pub fn plan_add(
    session: &Session,
    protocol: Option<Protocol>,
    args: &AddArgs,
) -> Result<Option<(ApplyRequest, Protocol)>> {
    let loaded = session.load()?;
    let cfg = &loaded.config;
    let protocol = match protocol {
        Some(p) => p,
        None => match choose_new(session, cfg)? {
            Some(p) => p,
            None => return Ok(None),
        },
    };
    ensure!(!cfg.has(protocol), "协议已存在");
    let mut opts = add_options(session, cfg, protocol, args)?;
    let facts = session.facts()?;
    let probe = LiveProbe(session.live);
    let env = facts.env(&probe, Some(cfg));
    let plan_with =
        |opts: &AddOptions| plan::add(cfg, protocol, opts, &env, session.live.rng().as_mut());
    let mut next = plan_with(&opts)?;
    if opts.port.is_none() && session.ui().interactive() {
        let auto = next.inbound(protocol).map_or(0, |i| i.port);
        let port = ask_port(session, protocol, auto, &|port| {
            let mut trial = opts.clone();
            trial.port = Some(port);
            plan_with(&trial).map(|_| ())
        })?;
        if port != auto {
            opts.port = Some(port);
            next = plan_with(&opts)?;
        }
    }
    next = handshake_extras(&next, &args.reality, &env)?;
    Ok(Some((request(&loaded, next, "添加协议"), protocol)))
}

/// `--reality-dest` after `--sni`, and `--site-https` for an existing site.
fn handshake_extras(
    cfg: &NodeConfig,
    reality: &RealityArgs,
    env: &plan::PlanEnv,
) -> Result<NodeConfig> {
    let mut next = cfg.clone();
    if let Some(dest) = &reality.dest_after_sni {
        next = plan::set_reality_target(&next, &RealityChoice::Dest(dest.clone()), env)?;
    }
    if let Some(on) = reality.site_https {
        ensure!(next.site.is_some(), "--site-https 需要先启用自建站");
        next = plan::site_https(&next, on)?;
    }
    Ok(next)
}

/// Turn `add` options into the planner's, asking for the REALITY target of
/// the first REALITY inbound and for a certificate a new protocol needs
/// (interactive only, when the command line did not decide).
fn add_options(
    session: &Session,
    cfg: &NodeConfig,
    protocol: Protocol,
    args: &AddArgs,
) -> Result<AddOptions> {
    let ui = session.ui();
    let mut reality = args.reality.choice.clone();
    if protocol.reality() && !cfg.any_reality() && args.reality.is_empty() && ui.interactive() {
        reality = steps::reality_menu(ui, "选择 REALITY 伪装目标")?;
    }
    let mut cert = args.cert.choice.clone();
    let needs_new_cert = protocol.certificate() && cfg.tls.is_none();
    if needs_new_cert && cert.is_none() && ui.interactive() {
        let title = format!("{} 需要 TLS 证书；没有域名时选自签即可", protocol.title());
        cert = Some(steps::cert_menu(ui, &title)?);
    }
    Ok(AddOptions {
        core: args.core,
        port: args.port_for(protocol)?,
        reality,
        cert,
        hy2_obfs: args.hy2_obfs,
        hy2_hop: args.hy2_hop,
        hy2_core: args.hy2_core,
        vmess_host: args.cert.vmess_host.clone(),
    })
}

/// Pick a protocol that is not enabled yet.
fn choose_new(session: &Session, cfg: &NodeConfig) -> Result<Option<Protocol>> {
    let candidates: Vec<Protocol> = Protocol::ALL.into_iter().filter(|p| !cfg.has(*p)).collect();
    ensure!(!candidates.is_empty(), "已启用全部协议");
    pick(session, "选择要添加的协议", &candidates)
}

/// A numbered choice among `protocols` (`None` = back), Enter = the first.
pub fn pick(session: &Session, title: &str, protocols: &[Protocol]) -> Result<Option<Protocol>> {
    pick_with_default(session, title, protocols, 0)
}

/// [`pick`] with `default` (an index, or [`ui::BACK`]).
fn pick_with_default(
    session: &Session,
    title: &str,
    protocols: &[Protocol],
    default: usize,
) -> Result<Option<Protocol>> {
    let items: Vec<String> = protocols.iter().map(|p| protocol_item(*p)).collect();
    let choice = session.ui().select(title, &items, default, true)?;
    Ok(choice.and_then(|i| protocols.get(i).copied()))
}

fn protocol_item(protocol: Protocol) -> String {
    match protocol {
        Protocol::AnytlsReality => format!("{} (仅 sing-box 完整配置)", protocol.title()),
        _ => protocol.title().to_owned(),
    }
}

/// An enabled protocol: the argument, or a menu of the enabled ones.
fn enabled(
    session: &Session,
    cfg: &NodeConfig,
    given: Option<Protocol>,
    title: &str,
) -> Result<Option<Protocol>> {
    match given {
        Some(p) => {
            ensure!(cfg.has(p), "协议未启用");
            Ok(Some(p))
        }
        None => {
            let list: Vec<Protocol> = cfg.protocols().collect();
            pick(session, title, &list)
        }
    }
}

/// Ask for a port (default `current`) until `check` accepts it.
fn ask_port(
    session: &Session,
    protocol: Protocol,
    current: u16,
    check: &dyn Fn(u16) -> Result<()>,
) -> Result<u16> {
    let validate = |answer: &str| -> Result<String> {
        let port = opt::port(answer)?;
        check(port).map(|()| port.to_string())
    };
    let prompt = format!("{} 端口", protocol.title());
    let answer = session
        .ui()
        .input_with(&prompt, &current.to_string(), &validate)?;
    opt::port(&answer)
}

fn del_command(ctx: &Ctx, m: &Matches) -> Result<()> {
    let protocol = m.positional(0).map(str::parse).transpose()?;
    with_system(ctx, |s| run(s, plan_del(s, protocol)?))
}

/// The request removing a protocol (`None`: back).
pub fn plan_del(session: &Session, protocol: Option<Protocol>) -> Result<Option<ApplyRequest>> {
    let loaded = session.load()?;
    let cfg = &loaded.config;
    ensure!(
        protocol.is_some() || cfg.inbounds.len() > 1,
        "至少保留一个协议；全部删除请使用 uninstall"
    );
    let protocol = match protocol {
        Some(p) => {
            ensure!(cfg.has(p), "协议未启用");
            Some(p)
        }
        // Destructive: nothing is picked for the user.
        None => {
            ensure!(session.ui().interactive(), "{DEL_NEEDS_PROTOCOL}");
            let list: Vec<Protocol> = cfg.protocols().collect();
            pick_with_default(session, "选择要删除的协议", &list, ui::BACK)?
        }
    };
    let Some(protocol) = protocol else {
        return Ok(None);
    };
    let next = plan::remove(cfg, protocol)?;
    Ok(Some(request(&loaded, next, "删除协议")))
}

fn port_command(ctx: &Ctx, m: &Matches) -> Result<()> {
    let protocol = m.positional(0).map(str::parse).transpose()?;
    let port = m.positional(1).map(opt::port).transpose()?;
    with_system(ctx, |s| run(s, plan_port(s, protocol, port)?))
}

/// The request changing a port (`None`: back, or unchanged).
pub fn plan_port(
    session: &Session,
    protocol: Option<Protocol>,
    port: Option<u16>,
) -> Result<Option<ApplyRequest>> {
    let loaded = session.load()?;
    let cfg = &loaded.config;
    let Some(protocol) = enabled(session, cfg, protocol, "选择要修改端口的协议")? else {
        return Ok(None);
    };
    let current = cfg.inbound(protocol).map_or(0, |i| i.port);
    let facts = session.facts()?;
    let probe = LiveProbe(session.live);
    let env = facts.env(&probe, Some(cfg));
    let port = match port {
        Some(port) => port,
        None => ask_port(session, protocol, current, &|p| {
            plan::set_port(cfg, protocol, p, &env).map(|_| ())
        })?,
    };
    if port == current {
        session.info("端口未变化");
        return Ok(None);
    }
    let next = plan::set_port(cfg, protocol, port, &env)?;
    Ok(Some(request(&loaded, next, "修改端口")))
}

fn reset_command(ctx: &Ctx, _m: &Matches) -> Result<()> {
    with_system(ctx, |s| run(s, plan_reset(s)?))
}

/// The request rotating every credential (`None`: declined).
pub fn plan_reset(session: &Session) -> Result<Option<ApplyRequest>> {
    let loaded = session.load()?;
    let prompt = "重置全部节点凭据？客户端需要更新配置或订阅";
    if !session.ui().confirm(prompt, false)? {
        return Ok(None);
    }
    let next = plan::reset_credentials(&loaded.config, session.live.rng().as_mut())?;
    Ok(Some(request(&loaded, next, "重置凭据")))
}

fn regen_command(ctx: &Ctx, _m: &Matches) -> Result<()> {
    with_system(ctx, |s| run(s, Some(plan_regen(s)?)))
}

/// The request re-applying the configuration unchanged (also the v2 → v3
/// migration path: devices from v2 ride along).
pub fn plan_regen(session: &Session) -> Result<ApplyRequest> {
    let loaded: Loaded = session.load()?;
    Ok(request(&loaded, loaded.config.clone(), "重新生成配置"))
}

/// Apply `req` (if any) and print the v2 tail.
pub fn run(session: &Session, req: Option<ApplyRequest>) -> Result<()> {
    let Some(req) = req else {
        return Ok(());
    };
    session.apply(req)?;
    session.data(UPDATED)
}

#[cfg(test)]
mod tests;
