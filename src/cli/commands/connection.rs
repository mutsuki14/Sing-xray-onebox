//! Connection commands: `addr` (client address and node name) and `sni`
//! (REALITY target and ShadowTLS handshake).
//!
//! Changes from v2 (spec B §3.7, §3.9, B-9.1#3/#4/#8): `addr` takes only
//! `--addr`/`--name` and `sni` only the handshake options (v2 accepted
//! every option, e.g. `addr --port`, bypassing the port checks); a new
//! address is checked and the other address family comes from fresh
//! detection, never from the old state; the interactive ShadowTLS change
//! also resets an explicit handshake target; `sni` without options under
//! `-y`, or answers that change nothing, apply nothing.

use crate::apply::ApplyRequest;
use crate::cli::args::{CommandSpec, Group, Matches};
use crate::cli::commands::install::Detected;
use crate::cli::commands::node::run;
use crate::cli::options::{self as opt, RealityArgs};
use crate::cli::session::{request, with_system, LiveProbe, Session};
use crate::cli::wizard::steps;
use crate::ctx::Ctx;
use crate::domain::config::{Host, NodeConfig, WebCert};
use crate::domain::plan::{self, RealityChoice};
use crate::domain::protocol::Protocol;
use crate::error::{Error, Result};

pub const ADDR: CommandSpec = CommandSpec::new("addr", Group::Node, "修改客户端连接地址与节点名称")
    .usage(&["addr [--addr IP或域名] [--name 名称]"])
    .options(&[opt::ADDR, opt::NAME])
    .handler(addr_command);

pub const SNI: CommandSpec = CommandSpec::new(
    "sni",
    Group::Node,
    "更换 REALITY / ShadowTLS 伪装目标（凭据不变）",
)
.usage(&[
    "sni",
    "sni --sni 域名",
    "sni --reality-dest 主机:端口",
    "sni --reality-site 域名 [--site-title 标题] [--site-https on|off]",
])
.options(&[
    opt::SNI,
    opt::REALITY_DEST,
    opt::REALITY_SITE,
    opt::SITE_TITLE,
    opt::SITE_HTTPS,
])
.handler(sni_command);

/// What `addr` should set; `None` = ask (interactive) or keep.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AddrArgs {
    pub addr: Option<Host>,
    pub name: Option<String>,
}

fn addr_command(ctx: &Ctx, m: &Matches) -> Result<()> {
    let args = AddrArgs {
        addr: m.value("addr").map(opt::host).transpose()?,
        name: m.value("name").map(str::to_owned),
    };
    with_system(ctx, |s| run(s, plan_addr(s, &args)?))
}

/// The request changing the address and/or name (`None`: unchanged).
pub fn plan_addr(session: &Session, args: &AddrArgs) -> Result<Option<ApplyRequest>> {
    let loaded = session.load()?;
    let cfg = &loaded.config;
    let ui = session.ui();
    let asked = args.addr.is_none() && args.name.is_none() && ui.interactive();
    let (addr, name) = if asked {
        let check = |answer: &str| -> Result<String> {
            if answer.is_empty() {
                return Ok(String::new());
            }
            opt::host(answer).map(|h| h.to_string())
        };
        let addr = ui.input_with("连接 IP 或域名", &cfg.server.addr.to_string(), &check)?;
        let name = ui.input("节点名称", &cfg.node_name)?;
        let addr = (!addr.is_empty()).then(|| opt::host(&addr)).transpose()?;
        (addr, Some(name))
    } else {
        (args.addr.clone(), args.name.clone())
    };
    // A new address takes the other family from fresh detection.
    let next = if addr.is_some() {
        let detected = Detected::detect(session);
        let host = match addr {
            Some(host) => host,
            None => detected
                .default_host()
                .ok_or_else(|| Error::msg("无法检测公网地址，请使用 --addr 指定"))?,
        };
        plan::set_address(cfg, host, name.as_deref(), detected.ipv4, detected.ipv6)?
    } else {
        let server = &cfg.server;
        plan::set_address(
            cfg,
            server.addr.clone(),
            name.as_deref(),
            server.ipv4,
            server.ipv6,
        )?
    };
    if next == *cfg {
        session.info("配置未变化");
        return Ok(None);
    }
    Ok(Some(request(&loaded, next, "修改连接地址")))
}

fn sni_command(ctx: &Ctx, m: &Matches) -> Result<()> {
    with_system(ctx, |s| {
        let loaded = s.load()?;
        let site_cert = loaded
            .config
            .site
            .as_ref()
            .map_or(WebCert::Http01, |site| site.cert.clone());
        let args = opt::reality_args(m, site_cert)?;
        run(s, plan_sni(s, &args)?)
    })
}

/// The request changing the handshake targets (`None`: unchanged).
pub fn plan_sni(session: &Session, args: &RealityArgs) -> Result<Option<ApplyRequest>> {
    let loaded = session.load()?;
    let cfg = &loaded.config;
    let reality = cfg.any_reality();
    let shadowtls = cfg.has(Protocol::Shadowtls);
    ensure!(reality || shadowtls, "没有启用 REALITY 或 ShadowTLS");
    let facts = session.facts()?;
    let probe = LiveProbe(session.live);
    let env = facts.env(&probe, Some(cfg));
    let next = if args.is_empty() {
        ask_targets(session, cfg, &env)?
    } else {
        apply_targets(cfg, args, &env)?
    };
    if next == *cfg {
        session.info("配置未变化");
        return Ok(None);
    }
    Ok(Some(request(&loaded, next, "更换伪装目标")))
}

/// The command-line handshake options on `cfg`.
fn apply_targets(cfg: &NodeConfig, args: &RealityArgs, env: &plan::PlanEnv) -> Result<NodeConfig> {
    let mut next = cfg.clone();
    if args.choice != RealityChoice::Default && (cfg.any_reality() || args.shadowtls_sni.is_none())
    {
        next = plan::set_reality_target(&next, &args.choice, env)?;
    }
    if let Some(sni) = args
        .shadowtls_sni
        .as_deref()
        .filter(|_| cfg.has(Protocol::Shadowtls))
    {
        next = plan::set_shadowtls_sni(&next, sni)?;
    }
    if let Some(dest) = &args.dest_after_sni {
        next = plan::set_reality_target(&next, &RealityChoice::Dest(dest.clone()), env)?;
    }
    if let Some(on) = args.site_https {
        ensure!(next.site.is_some(), "--site-https 需要先启用自建站");
        next = plan::site_https(&next, on)?;
    }
    Ok(next)
}

/// The interactive change (REALITY menu, then the ShadowTLS name).
fn ask_targets(session: &Session, cfg: &NodeConfig, env: &plan::PlanEnv) -> Result<NodeConfig> {
    let ui = session.ui();
    if !ui.interactive() {
        return Ok(cfg.clone());
    }
    let mut next = cfg.clone();
    if cfg.any_reality() {
        let title = format!(
            "当前 REALITY 目标: {}（{}）\n选择新的伪装目标",
            cfg.reality.sni, cfg.reality.dest
        );
        let choice = steps::reality_menu(ui, &title)?;
        next = plan::set_reality_target(&next, &choice, env)?;
    }
    if cfg.has(Protocol::Shadowtls) {
        let sni = ui.input_with(
            "ShadowTLS 握手域名",
            &cfg.shadowtls.sni,
            &|answer: &str| plan::normalize_domain(answer, "域名无效"),
        )?;
        if sni != cfg.shadowtls.sni {
            next = plan::set_shadowtls_sni(&next, &sni)?;
        }
    }
    Ok(next)
}

#[cfg(test)]
mod tests;
