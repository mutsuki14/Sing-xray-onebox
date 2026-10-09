//! `tune status | hy2 [MODE] [--up N --down N] [--obfs on|off]
//! [--hop 起-止|off] | resource MODE | reset`, each a preview unless
//! `--apply` is given. Every form needs root, previews and `status`
//! included: they read the node state in the root-only ROOT.
//!
//! Changes from v2 (spec B §3.12, B-9.1#20, C-8.1#1): options are parsed by
//! name, so `tune hy2 --apply` reports the missing mode instead of reading
//! `--apply` as one; bandwidths are integer Mbps 1–10000 (what the
//! renderers can use) and `measured` with a value missing keeps the stored
//! one only while the profile already is `measured`; switching to another
//! profile clears stale bandwidths; Xray-hosted Hysteria2 is refused at
//! planning time; `tune hy2 --obfs/--hop` changes Salamander obfuscation
//! and port hopping after install (v2 needed a reinstall with new
//! credentials), checked against every other UDP listener and FRP, and
//! says that clients must re-import; `status` and previews are declared
//! root-only (they failed for non-root users anyway).

use crate::cli::args::{ArgSpec, CommandSpec, Group, Matches, OptSpec};
use crate::cli::options as opt;
use crate::cli::session::{request, with_system, LiveProbe, Session};
use crate::ctx::Ctx;
use crate::domain::config::{Hy2Profile, NodeConfig, PortRange, ResourceProfile};
use crate::domain::plan::{self, PlanEnv};
use crate::error::{Error, Result};

const APPLY: OptSpec = OptSpec::flag("apply", "应用（默认只预览）");
const UP: OptSpec = OptSpec::value("up", "Mbps", "客户端上传带宽（measured）");
const DOWN: OptSpec = OptSpec::value("down", "Mbps", "客户端下载带宽（measured）");
const OBFS: OptSpec = OptSpec::value("obfs", "on|off", "Salamander 混淆（客户端需重新导入）");
const HOP: OptSpec = OptSpec::value(
    "hop",
    "起-止|off",
    "UDP 端口跳跃范围（起始 ≥ 1024），off 关闭（客户端需重新导入）",
);
const BAD_BANDWIDTH: &str = "带宽值无效（应为 1–10000 的整数 Mbps）";
const NEEDS_HY2_CHANGE: &str = "需要 auto/conservative/measured，或 --obfs / --hop";
/// After an applied obfuscation or hopping change.
pub const REIMPORT: &str = "Hysteria2 混淆或端口跳跃已更改，客户端需要重新导入配置或刷新订阅";

pub const TUNE: CommandSpec =
    CommandSpec::new("tune", Group::Node, "Hysteria2 与资源调优（默认只预览）")
        .usage(&[
            "tune [status]",
            "tune hy2 auto|conservative|measured [--up N --down N] [--apply]",
            "tune hy2 [档位] [--obfs on|off] [--hop 起-止|off] [--apply]",
            "tune resource balanced|low-memory|throughput [--apply]",
            "tune reset [--apply]",
        ])
        .subcommands(&[
            CommandSpec::new("status", Group::Node, "当前调优设置").handler(tune_command),
            CommandSpec::new(
                "hy2",
                Group::Node,
                "Hysteria2 拥塞与带宽档位、混淆与端口跳跃",
            )
            .args(&[ArgSpec::optional(
                "档位",
                "auto / conservative / measured（只改 --obfs/--hop 时可省略）",
            )])
            .options(&[UP, DOWN, OBFS, HOP, APPLY])
            .handler(tune_command),
            CommandSpec::new("resource", Group::Node, "QUIC 接收窗口与并发流档位")
                .args(&[ArgSpec::optional(
                    "档位",
                    "balanced / low-memory / throughput",
                )])
                .options(&[APPLY])
                .handler(tune_command),
            CommandSpec::new("reset", Group::Node, "恢复默认调优")
                .options(&[APPLY])
                .handler(tune_command),
        ])
        .handler(tune_command);

/// One tuning change.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tune {
    Hy2 {
        /// `None`: only `obfs` / `hop` change.
        profile: Option<Hy2Profile>,
        up: Option<u32>,
        down: Option<u32>,
        /// `--obfs on|off` (`None` keeps the current setting).
        obfs: Option<bool>,
        /// `--hop 起-止|off`: `Some(None)` turns hopping off.
        hop: Option<Option<PortRange>>,
    },
    Resource(ResourceProfile),
    Reset,
}

impl Tune {
    /// A Hysteria2 profile change alone.
    pub fn hy2(profile: Hy2Profile, up: Option<u32>, down: Option<u32>) -> Tune {
        Tune::Hy2 {
            profile: Some(profile),
            up,
            down,
            obfs: None,
            hop: None,
        }
    }

    /// An obfuscation / port hopping change alone.
    pub fn hy2_transport(obfs: Option<bool>, hop: Option<Option<PortRange>>) -> Tune {
        Tune::Hy2 {
            profile: None,
            up: None,
            down: None,
            obfs,
            hop,
        }
    }

    /// Whether the change touches obfuscation or port hopping.
    pub fn transport(&self) -> bool {
        matches!(self, Tune::Hy2 { obfs, hop, .. } if obfs.is_some() || hop.is_some())
    }
}

/// A parsed `tune` command line: `None` = status.
pub fn parse(m: &Matches) -> Result<Option<Tune>> {
    match m.path.get(1).copied() {
        None | Some("status") => Ok(None),
        Some("hy2") => {
            let obfs = m
                .value("obfs")
                .map(|v| opt::on_off(v, "--obfs"))
                .transpose()?;
            let hop = m.value("hop").map(hop).transpose()?;
            let profile = match m.positional(0) {
                Some(profile) => Some(profile.parse()?),
                None if obfs.is_some() || hop.is_some() => None,
                None => bail!("{NEEDS_HY2_CHANGE}"),
            };
            let (up, down) = (bandwidth(m.value("up"))?, bandwidth(m.value("down"))?);
            ensure!(
                profile.is_some() || (up.is_none() && down.is_none()),
                "--up/--down 仅用于 measured 档位"
            );
            Ok(Some(Tune::Hy2 {
                profile,
                up,
                down,
                obfs,
                hop,
            }))
        }
        Some("resource") => {
            let profile = m
                .positional(0)
                .ok_or_else(|| Error::msg("需要 balanced/low-memory/throughput"))?
                .parse()?;
            Ok(Some(Tune::Resource(profile)))
        }
        Some("reset") => Ok(Some(Tune::Reset)),
        Some(_) => Err(Error::msg("用法: tune status|hy2|resource|reset")),
    }
}

/// Integer Mbps (range checked by the planner).
pub fn bandwidth(value: Option<&str>) -> Result<Option<u32>> {
    value
        .map(|v| {
            v.trim()
                .parse::<u32>()
                .map_err(|_| Error::msg(BAD_BANDWIDTH))
        })
        .transpose()
}

/// `起-止` or `off` (hopping off).
pub fn hop(value: &str) -> Result<Option<PortRange>> {
    match value.trim() {
        "off" => Ok(None),
        range => range.parse().map(Some),
    }
}

fn tune_command(ctx: &Ctx, m: &Matches) -> Result<()> {
    let change = parse(m)?;
    with_system(ctx, |s| match change {
        None => status(s),
        Some(change) => tune(s, change, m.flag("apply")),
    })
}

/// `tune status`: v2's four `KEY=value` lines (root: the node state).
pub fn status(session: &Session) -> Result<()> {
    session.require_root()?;
    session.data(&status_text(&session.load()?.config))
}

pub fn status_text(cfg: &NodeConfig) -> String {
    let number = |v: Option<u32>| v.map(|n| n.to_string()).unwrap_or_default();
    [
        format!(
            "HY2_PROFILE={}",
            cfg.hy2.profile.map(|p| p.id()).unwrap_or_default()
        ),
        format!("HY2_UP_MBPS={}", number(cfg.hy2.up_mbps)),
        format!("HY2_DOWN_MBPS={}", number(cfg.hy2.down_mbps)),
        format!("RESOURCE_PROFILE={}", cfg.resource_profile.id()),
    ]
    .join("\n")
}

/// The tuned configuration (`env`: the live ports and FRP reservations a
/// hopping range must avoid).
pub fn plan_tune(cfg: &NodeConfig, change: Tune, env: &PlanEnv) -> Result<NodeConfig> {
    match change {
        Tune::Hy2 {
            profile,
            up,
            down,
            obfs,
            hop,
        } => {
            let mut next = match profile {
                Some(profile) => plan::tune_hy2(cfg, profile, up, down)?,
                None => cfg.clone(),
            };
            if obfs.is_some() || hop.is_some() {
                let obfs = obfs.unwrap_or(next.hy2.obfs);
                let hop = hop.unwrap_or(next.hy2.hop);
                next = plan::set_hy2(&next, obfs, hop, env)?;
            }
            Ok(next)
        }
        Tune::Resource(profile) => plan::tune_resource(cfg, profile),
        Tune::Reset => plan::tune_reset(cfg),
    }
}

/// [`plan_tune`] against the session's live facts.
pub fn plan_live(session: &Session, cfg: &NodeConfig, change: Tune) -> Result<NodeConfig> {
    let facts = session.facts()?;
    let probe = LiveProbe(session.live);
    let env = facts.env(&probe, Some(cfg));
    plan_tune(cfg, change, &env)
}

/// `调优预览: HY2={} up={} down={} resource={}` (v2 line).
pub fn preview_line(cfg: &NodeConfig) -> String {
    let number = |v: Option<u32>| v.map(|n| n.to_string()).unwrap_or_default();
    format!(
        "调优预览: HY2={} up={} down={} resource={}",
        cfg.hy2.profile.map(|p| p.id()).unwrap_or_default(),
        number(cfg.hy2.up_mbps),
        number(cfg.hy2.down_mbps),
        cfg.resource_profile.id()
    )
}

/// The preview of `change` planned as `next`: v2's line, plus obfuscation
/// and hopping when the change touches them.
pub fn preview_text(next: &NodeConfig, change: Tune) -> String {
    let mut lines = vec![preview_line(next)];
    if change.transport() {
        let hop = next
            .hy2
            .hop
            .map_or_else(|| "off".to_owned(), |r| r.to_string());
        let obfs = if next.hy2.obfs { "on" } else { "off" };
        lines.push(format!("Hysteria2 混淆={obfs} 端口跳跃={hop}"));
    }
    lines.join("\n")
}

/// Whether clients must re-import after `cfg` became `next`.
pub fn needs_reimport(cfg: &NodeConfig, next: &NodeConfig) -> bool {
    cfg.hy2.obfs != next.hy2.obfs || cfg.hy2.hop != next.hy2.hop
}

/// Preview `change`; with `apply`, run it (root either way: the node
/// state is root-only).
pub fn tune(session: &Session, change: Tune, apply: bool) -> Result<()> {
    session.require_root()?;
    let loaded = session.load()?;
    let next = plan_live(session, &loaded.config, change)?;
    session.data(&preview_text(&next, change))?;
    if !apply {
        return session.data("添加 --apply 才会应用");
    }
    let reimport = needs_reimport(&loaded.config, &next);
    session.apply(request(&loaded, next, "调优"))?;
    if reimport {
        session.info(REIMPORT);
    }
    Ok(())
}

#[cfg(test)]
mod tests;
