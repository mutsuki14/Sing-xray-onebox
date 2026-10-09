//! Checks before (and at the start of) an FRP change: path layout
//! (H §5.7), DNS of the FRP names (H §4.2) and port conflicts with the
//! proxy node and with live sockets (H §4.5).
//!
//! Changes from v2:
//! - the node's ports come from its one port authority,
//!   `PortPlan::of(node, &[])` (G24, H-8.1#7): subscription, REALITY guard,
//!   HTTP-01 and the hop range are included and the site's internal port
//!   is the configured one (v2 assumed 8444); the node state is read without
//!   the node lock, and the node re-checks FRP's reservations under its own
//!   lock, so a race fails safe;
//! - live sockets are read from `/proc/net/{tcp,tcp6,udp,udp6}` (no `ss`);
//! - the configured roots may sit below distro symlinks (`/var/run`): only
//!   their spelling, their nesting and their scope are checked here, the
//!   snapshot refuses symlinks inside the owned trees;
//! - public addresses are detected with the shared `sys::net` probe.

use super::model::FrpState;
use crate::ctx::Ctx;
use crate::domain::ports::{Listener, PortPlan, Reservation};
use crate::error::Result;
use crate::paths::Paths;
use crate::state::StateStore;
use crate::sys::exec::Cmd;
use crate::sys::net::{detect_public_ip, listening, parse_ip_addresses, table_has_port};
use std::collections::BTreeSet;
use std::net::IpAddr;
use std::path::{Component, Path};
use std::time::Duration;

const LOOKUP_TIMEOUT: Duration = Duration::from_secs(15);
/// Directories FRP may never own as a whole (v2 `path_safe`).
const BROAD: [&str; 9] = [
    "/",
    "/etc",
    "/opt",
    "/var",
    "/var/lib",
    "/var/log",
    "/run",
    "/usr",
    "/usr/local",
];

/// A dedicated absolute path of `[A-Za-z0-9/_.-]` without `..`, not a
/// system directory.
fn path_safe(path: &Path) -> Result<()> {
    let s = path.to_string_lossy();
    let ok = path.is_absolute()
        && !path.components().any(|c| c == Component::ParentDir)
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"/_-.".contains(&b))
        && path.parent().is_some()
        && !BROAD.contains(&s.trim_end_matches('/'));
    ensure!(ok, "FRP 路径必须为专用绝对目录且不能含空格: {s}");
    Ok(())
}

fn nested(a: &Path, b: &Path) -> bool {
    a.starts_with(b) || b.starts_with(a)
}

/// The FRP roots are dedicated, distinct, not nested in each other and
/// apart from the node's directories; the executable path is plain.
pub fn check_paths(paths: &Paths) -> Result<()> {
    let roots = [
        &paths.frp_root,
        &paths.frp_bin,
        &paths.frp_web,
        &paths.frp_log,
        &paths.frp_run,
    ];
    let node = [
        &paths.root,
        &paths.bin,
        &paths.log,
        &paths.run,
        &paths.site_root,
        &paths.systemd,
        &paths.initd,
    ];
    for (i, path) in roots.iter().enumerate() {
        path_safe(path)?;
        let clash = roots
            .iter()
            .enumerate()
            .any(|(j, other)| i != j && nested(path, other));
        ensure!(!clash, "FRP 数据目录不能相同或互相包含");
        ensure!(
            !node.iter().any(|other| nested(path, other)),
            "FRP 路径不能与代理、网站或服务目录重叠"
        );
    }
    path_safe(&paths.executable)
}

/// IPv4-mapped IPv6 addresses count as the IPv4 address.
fn normalize(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
        v4 => v4,
    }
}

/// Every address of the host's interfaces (`ip -j address show`); a
/// failure leaves the set empty (public detection still runs).
fn own_addresses(ctx: &Ctx) -> BTreeSet<IpAddr> {
    let cmd = Cmd::new("ip")
        .args(["-j", "address", "show"])
        .timeout(LOOKUP_TIMEOUT);
    let Ok(out) = ctx.check(&cmd) else {
        return BTreeSet::new();
    };
    parse_ip_addresses(&out)
        .unwrap_or_default()
        .iter()
        .filter_map(|cidr| cidr.split('/').next()?.parse().ok())
        .map(normalize)
        .collect()
}

/// The first column of `getent ahosts|ahostsv6|hosts NAME` (both
/// families explicitly: `ahosts` alone can hide stale AAAA records).
fn resolve(ctx: &Ctx, name: &str) -> BTreeSet<IpAddr> {
    let mut ips = BTreeSet::new();
    for database in ["ahosts", "ahostsv6", "hosts"] {
        let cmd = Cmd::new("getent")
            .args([database, name])
            .timeout(LOOKUP_TIMEOUT);
        let Ok(out) = ctx.run(&cmd) else { continue };
        if !out.ok() {
            continue;
        }
        ips.extend(
            out.stdout
                .lines()
                .filter_map(|l| l.split_whitespace().next()?.parse::<IpAddr>().ok())
                .map(normalize),
        );
    }
    ips
}

/// The names FRP serves: the control domain and, in web mode, the
/// application domain or a random name below the wildcard root.
fn names(state: &FrpState) -> Result<Vec<String>> {
    let mut names = vec![state.domain.clone()];
    if let Some(web) = state.web() {
        names.push(match &web.app {
            crate::frp::model::AppDomain::Single { domain } => domain.clone(),
            crate::frp::model::AppDomain::Wildcard { root } => {
                format!("onebox-{}.{root}", crate::sys::rand::hex(4)?)
            }
        });
    }
    Ok(names)
}

/// Every A/AAAA record of the FRP names must point at this host (H §4.2).
pub fn check_dns(ctx: &Ctx, state: &FrpState) -> Result<()> {
    let mut own = own_addresses(ctx);
    let mut discovered = false;
    for name in names(state)? {
        let ips = resolve(ctx, &name);
        ensure!(!ips.is_empty(), "无法解析 {name}，请先添加 DNS 记录");
        if !discovered && ips.iter().any(|ip| !own.contains(ip)) {
            own.extend(
                [false, true]
                    .into_iter()
                    .filter_map(|v6| detect_public_ip(ctx, v6))
                    .map(normalize),
            );
            discovered = true;
        }
        if let Some(ip) = ips.iter().find(|ip| !own.contains(ip)) {
            bail!("FRP 域名 {name} 的 {ip} 不属于本机；检查全部 A/AAAA 并关闭 CDN 代理");
        }
    }
    Ok(())
}

fn overlaps(r: &Reservation, l: &Listener) -> bool {
    r.start <= l.end && l.start <= r.end && r.transport.overlaps(l.transport)
}

/// FRP's reservations against every listener of the installed node.
pub fn check_node_ports(ctx: &Ctx, state: &FrpState) -> Result<()> {
    let Some(loaded) = StateStore::load(ctx)? else {
        return Ok(());
    };
    let plan = PortPlan::of(&loaded.config, &[]);
    for r in state.reservations() {
        if let Some(l) = plan.listeners().iter().find(|l| overlaps(&r, l)) {
            bail!(
                "FRP {}-{}/{} 与已有代理或网站 {}-{}/{} 冲突",
                r.start,
                r.end,
                r.transport.id(),
                l.start,
                l.end,
                l.transport.id()
            );
        }
    }
    Ok(())
}

/// The socket tables of one protocol (`None` when none is readable).
fn tables(system_root: &Path, tcp: bool) -> Option<Vec<String>> {
    let names: [&str; 2] = if tcp {
        ["proc/net/tcp", "proc/net/tcp6"]
    } else {
        ["proc/net/udp", "proc/net/udp6"]
    };
    let texts: Vec<String> = names
        .iter()
        .filter_map(|n| std::fs::read_to_string(system_root.join(n)).ok())
        .collect();
    (!texts.is_empty()).then_some(texts)
}

/// No other process listens on a reserved port (run after FRP's own
/// services stopped). TCP counts LISTEN sockets, UDP any bound socket.
pub fn check_live_ports(system_root: &Path, state: &FrpState) -> Result<()> {
    for (tcp, name) in [(true, "tcp"), (false, "udp")] {
        let tables = tables(system_root, tcp);
        let busy = |port: u16| match &tables {
            Some(texts) => texts.iter().any(|t| table_has_port(t, port, tcp)),
            None => listening(system_root, port, tcp),
        };
        for r in state.reservations() {
            let covered = if tcp {
                r.transport.tcp()
            } else {
                r.transport.udp()
            };
            if !covered {
                continue;
            }
            if let Some(port) = (r.start..=r.end).find(|p| busy(*p)) {
                bail!("FRP 端口 {port}/{name} 已被其他进程占用");
            }
        }
    }
    Ok(())
}

/// Both port checks.
pub fn check_ports(ctx: &Ctx, state: &FrpState) -> Result<()> {
    check_node_ports(ctx, state)?;
    check_live_ports(&ctx.paths.system_root, state)
}

#[cfg(test)]
mod tests;
