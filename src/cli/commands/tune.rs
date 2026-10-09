//! `tune status | hy2 MODE [--up N --down N] | resource MODE | reset`,
//! each a preview unless `--apply` is given (root only then).
//!
//! Changes from v2 (spec B §3.12, B-9.1#20, C-8.1#1): options are parsed by
//! name, so `tune hy2 --apply` reports the missing mode instead of reading
//! `--apply` as one; bandwidths are integer Mbps 1–10000 (what the
//! renderers can use) and `measured` with a value missing keeps the stored
//! one only while the profile already is `measured`; switching to another
//! profile clears stale bandwidths; Xray-hosted Hysteria2 is refused at
//! planning time.

use crate::cli::args::{ArgSpec, CommandSpec, Group, Matches, OptSpec, Root};
use crate::cli::session::{request, with_system, Session};
use crate::ctx::Ctx;
use crate::domain::config::{Hy2Profile, NodeConfig, ResourceProfile};
use crate::domain::plan;
use crate::error::{Error, Result};

const APPLY: OptSpec = OptSpec::flag("apply", "应用（默认只预览，不需要 root）");
const UP: OptSpec = OptSpec::value("up", "Mbps", "客户端上传带宽（measured）");
const DOWN: OptSpec = OptSpec::value("down", "Mbps", "客户端下载带宽（measured）");
const BAD_BANDWIDTH: &str = "带宽值无效（应为 1–10000 的整数 Mbps）";

fn apply_flag(m: &Matches) -> bool {
    m.flag("apply")
}

pub const TUNE: CommandSpec =
    CommandSpec::new("tune", Group::Node, "Hysteria2 与资源调优（默认只预览）")
        .usage(&[
            "tune [status]",
            "tune hy2 auto|conservative|measured [--up N --down N] [--apply]",
            "tune resource balanced|low-memory|throughput [--apply]",
            "tune reset [--apply]",
        ])
        .subcommands(&[
            CommandSpec::new("status", Group::Node, "当前调优设置")
                .root(Root::NotRequired)
                .handler(tune_command),
            CommandSpec::new("hy2", Group::Node, "Hysteria2 拥塞与带宽档位")
                .args(&[ArgSpec::optional("档位", "auto / conservative / measured")])
                .options(&[UP, DOWN, APPLY])
                .root(Root::Custom(apply_flag))
                .handler(tune_command),
            CommandSpec::new("resource", Group::Node, "QUIC 接收窗口与并发流档位")
                .args(&[ArgSpec::optional(
                    "档位",
                    "balanced / low-memory / throughput",
                )])
                .options(&[APPLY])
                .root(Root::Custom(apply_flag))
                .handler(tune_command),
            CommandSpec::new("reset", Group::Node, "恢复默认调优")
                .options(&[APPLY])
                .root(Root::Custom(apply_flag))
                .handler(tune_command),
        ])
        .root(Root::NotRequired)
        .handler(tune_command);

/// One tuning change.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tune {
    Hy2 {
        profile: Hy2Profile,
        up: Option<u32>,
        down: Option<u32>,
    },
    Resource(ResourceProfile),
    Reset,
}

/// A parsed `tune` command line: `None` = status.
pub fn parse(m: &Matches) -> Result<Option<Tune>> {
    match m.path.get(1).copied() {
        None | Some("status") => Ok(None),
        Some("hy2") => {
            let profile = m
                .positional(0)
                .ok_or_else(|| Error::msg("需要 auto/conservative/measured"))?
                .parse()?;
            Ok(Some(Tune::Hy2 {
                profile,
                up: bandwidth(m.value("up"))?,
                down: bandwidth(m.value("down"))?,
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

fn tune_command(ctx: &Ctx, m: &Matches) -> Result<()> {
    let change = parse(m)?;
    with_system(ctx, |s| match change {
        None => status(s),
        Some(change) => tune(s, change, m.flag("apply")),
    })
}

/// `tune status`: v2's four `KEY=value` lines.
pub fn status(session: &Session) -> Result<()> {
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

/// The tuned configuration.
pub fn plan_tune(cfg: &NodeConfig, change: Tune) -> Result<NodeConfig> {
    match change {
        Tune::Hy2 { profile, up, down } => plan::tune_hy2(cfg, profile, up, down),
        Tune::Resource(profile) => plan::tune_resource(cfg, profile),
        Tune::Reset => plan::tune_reset(cfg),
    }
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

/// Preview `change`; with `apply`, run it (root only).
pub fn tune(session: &Session, change: Tune, apply: bool) -> Result<()> {
    let loaded = session.load()?;
    let next = plan_tune(&loaded.config, change)?;
    session.data(&preview_line(&next))?;
    if !apply {
        return session.data("添加 --apply 才会应用");
    }
    session.require_root()?;
    session.apply(request(&loaded, next, "调优"))
}

#[cfg(test)]
mod tests;
