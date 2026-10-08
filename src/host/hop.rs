//! Hysteria2 UDP port hopping: packets to any port of a UDP range addressed
//! to this host are redirected to the Hysteria2 port, through an own nft
//! table (preferred) or iptables `nat PREROUTING` REDIRECT rules. What was
//! installed is recorded in `ROOT/hop-v2.json` (compact JSON array, 0600,
//! v2-compatible) so it can be removed exactly:
//!
//! `[{"backend":"nft","start":20000,"end":40000,"target":443,"token":"onebox_hop_<16hex>"}]`
//!
//! nft: one entry; the token is the table name in each family (`ip`, plus
//! `ip6` with IPv6). iptables: one entry per binary with its own comment
//! token `onebox-hop-<16hex>`. The firewall ledger separately opens the
//! range as UDP (`PortPlan::firewall_ports`).
//!
//! Changes from v2:
//! - the nft script is valid nft syntax (v2's one-line `… } }` form is
//!   rejected by nft 1.0.x with "syntax error, unexpected '}'", so hopping
//!   never worked through nft);
//! - when nft is present but cannot load the table (e.g. no `fib` support),
//!   iptables is used instead of failing;
//! - hop changes take their own lock (`hop-v2.lock`), so `hop-clear` cannot
//!   race an apply (E-8.1#20, F-8.1#16);
//! - a recorded rule whose program vanished counts as removed;
//! - a change installs the new rules before removing the old ones and
//!   undoes a partial install (e.g. ip6tables failing after iptables), so a
//!   failed change no longer leaves the host without hopping or with an
//!   unreported IPv4-only hop;
//! - an old rule that cannot be removed stays recorded with a warning and
//!   is retried by the next change; only an old rule that would redirect
//!   some of the new ports elsewhere fails the change. `clear` attempts
//!   every recorded rule and reports the ones it could not remove, so a
//!   broken nft no longer blocks rollback, recover and boot forever;
//! - records are validated when the ledger is read, before anything runs.

use crate::ctx::Ctx;
use crate::domain::config::PortRange;
use crate::error::{Context, Error, Result};
use crate::host::firewall::{lock_waiting, safe_word};
use crate::sys::exec::Cmd;
use crate::sys::fs::{atomic_write, read_bounded, remove_file_if_exists, write_new_exclusive};
use crate::sys::lock::FileLock;
use crate::sys::net::ipv6_available;
use crate::ui::out;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::time::Duration;

const LEDGER: &str = "hop-v2.json";
const MAX_LEDGER_BYTES: u64 = 1 << 20;
const LOCK_WAIT: Duration = Duration::from_secs(30);
const LOCK_BUSY: &str = "另一个端口跳跃操作正在进行；稍后重试";

/// One installed redirect (field order = v2 serialization order).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Hop {
    /// `nft`, `iptables` or `ip6tables`.
    pub backend: String,
    pub start: u16,
    pub end: u16,
    pub target: u16,
    pub token: String,
}

/// `ROOT/hop-v2.json`.
pub fn ledger_path(ctx: &Ctx) -> PathBuf {
    ctx.paths.root.join(LEDGER)
}

/// What [`clear`] did. Failed removals were printed as warnings; their
/// records are kept for the next attempt.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Report {
    /// `"{backend} {start}-{end}/udp → {target}"` per hop.
    pub removed: Vec<String>,
    pub failed: Vec<String>,
}

impl Hop {
    fn describe(&self) -> String {
        format!(
            "{} {}-{}/udp → {}",
            self.backend, self.start, self.end, self.target
        )
    }

    /// IP families the hop redirects (an nft table may exist in both).
    fn families(&self) -> &'static [&'static str] {
        match self.backend.as_str() {
            "iptables" => &["ip"],
            "ip6tables" => &["ip6"],
            _ => &["ip", "ip6"],
        }
    }

    /// Whether a leftover `self` can send some of `new`'s ports to another
    /// target (both are NAT redirects at the same hook; the first wins).
    fn shadows(&self, new: &Hop) -> bool {
        self.target != new.target
            && self.start <= new.end
            && new.start <= self.end
            && self.families().iter().any(|f| new.families().contains(f))
    }
}

/// The recorded hops (empty when nothing is recorded).
pub fn recorded(ctx: &Ctx) -> Result<Vec<Hop>> {
    load(&ledger_path(ctx))
}

/// Replace any previous hopping with `range` → `target`. The new rules are
/// installed and recorded before the previous ones are removed, so a
/// failed change leaves the working hopping in place.
pub fn apply(ctx: &Ctx, range: PortRange, target: u16) -> Result<()> {
    if range.start < 1024 || range.start >= range.end || target == 0 {
        return Err(Error::msg("跳跃范围必须为1024以上递增端口"));
    }
    let path = ledger_path(ctx);
    let _lock = lock(&path)?;
    let mut hops = load(&path)?;
    let previous = hops.len();
    install(ctx, &path, &mut hops, range, target)?;
    retire(ctx, &path, hops, previous)
}

/// Install the new hops after the `previous` ones already in `hops`,
/// recording each at once. On failure everything installed here is taken
/// out again and the ledger is restored.
fn install(
    ctx: &Ctx,
    path: &Path,
    hops: &mut Vec<Hop>,
    range: PortRange,
    target: u16,
) -> Result<()> {
    let binaries = iptables_binaries(ctx);
    let mut nft_error = None;
    if ctx.has("nft") {
        match load_nft(ctx, range, target) {
            Ok(hop) => return record(ctx, path, hops, hop),
            Err(e) if binaries.is_empty() => return Err(e),
            Err(e) => {
                out::warn(format!("nft 无法加载端口跳跃规则，改用 iptables: {e}"));
                nft_error = Some(e);
            }
        }
    }
    if binaries.is_empty() {
        return Err(Error::msg("端口跳跃需要 nft 或 iptables/ip6tables"));
    }
    let previous = hops.len();
    for binary in binaries {
        let hop = Hop {
            backend: binary.into(),
            start: range.start,
            end: range.end,
            target,
            token: format!("onebox-hop-{}", crate::sys::rand::hex(8)?),
        };
        let added = ctx
            .check(&iptables_cmd(&hop, "-A"))
            .and_then(|_| record(ctx, path, hops, hop));
        if let Err(e) = added {
            undo(ctx, path, hops, previous);
            return Err(match &nft_error {
                Some(nft) => Error::msg(format!("{e}（nft: {nft}）")),
                None => e,
            });
        }
    }
    Ok(())
}

/// Append an installed hop and save at once; if saving fails the hop is
/// taken out again so nothing unrecorded stays behind.
fn record(ctx: &Ctx, path: &Path, hops: &mut Vec<Hop>, hop: Hop) -> Result<()> {
    hops.push(hop);
    let Err(error) = save(path, hops) else {
        return Ok(());
    };
    let Some(hop) = hops.pop() else {
        return Err(error);
    };
    match remove(ctx, &hop) {
        Ok(()) => Err(error),
        Err(cleanup) => Err(Error::msg(format!(
            "跳跃记录保存失败: {error}；新规则清理失败: {cleanup}"
        ))),
    }
}

/// Take out the hops installed after index `keep` and record only the rest.
fn undo(ctx: &Ctx, path: &Path, hops: &mut Vec<Hop>, keep: usize) {
    while hops.len() > keep {
        let Some(hop) = hops.pop() else { break };
        if let Err(e) = remove(ctx, &hop) {
            out::warn(format!("未能撤销新的端口跳跃规则 {}: {e}", hop.token));
            hops.push(hop);
            break;
        }
    }
    if let Err(e) = save(path, hops) {
        out::warn(format!("端口跳跃记录保存失败: {e}"));
    }
}

/// Remove the first `count` (previous) hops now that the new ones work. A
/// hop that cannot be removed stays recorded (retried by the next change)
/// with a warning; the change fails only when such a leftover shadows a new
/// hop.
fn retire(ctx: &Ctx, path: &Path, mut hops: Vec<Hop>, count: usize) -> Result<()> {
    let fresh = hops.split_off(count);
    let mut kept = Vec::new();
    let mut shadowing = Vec::new();
    for (i, old) in hops.iter().enumerate() {
        match remove(ctx, old) {
            Ok(()) => {}
            Err(e) if fresh.iter().any(|new| old.shadows(new)) => {
                shadowing.push(format!("{}: {e}", old.describe()));
                kept.push(old.clone());
            }
            Err(e) => {
                out::warn(format!(
                    "旧端口跳跃规则清理失败，已保留记录，下次应用时重试: {}: {e}",
                    old.describe()
                ));
                kept.push(old.clone());
            }
        }
        save(
            path,
            &[kept.as_slice(), &hops[i + 1..], fresh.as_slice()].concat(),
        )?;
    }
    if shadowing.is_empty() {
        return Ok(());
    }
    Err(Error::msg(format!(
        "新的端口跳跃规则已生效，但与其冲突的旧规则清理失败（已保留记录）: {}",
        shadowing.join("; ")
    )))
}

/// Remove every recorded hop, each attempted even when another fails. The
/// ledger is rewritten after each removal; failures stay recorded, are
/// printed as warnings and listed in the report. Errors are only ledger and
/// lock problems.
pub fn clear(ctx: &Ctx) -> Result<Report> {
    let path = ledger_path(ctx);
    let _lock = lock(&path)?;
    let mut report = Report::default();
    if !path.exists() {
        return Ok(report);
    }
    let hops = load(&path)?;
    let mut kept = Vec::new();
    for (i, hop) in hops.iter().enumerate() {
        match remove(ctx, hop) {
            Ok(()) => report.removed.push(hop.describe()),
            Err(e) => {
                let message = format!("{}: {e}", hop.describe());
                out::warn(format!("未能删除端口跳跃规则（已保留记录）: {message}"));
                report.failed.push(message);
                kept.push(hop.clone());
            }
        }
        save(&path, &[kept.as_slice(), &hops[i + 1..]].concat())?;
    }
    Ok(report)
}

/// iptables binaries usable for hops: iptables, plus ip6tables with IPv6.
fn iptables_binaries(ctx: &Ctx) -> Vec<&'static str> {
    ["iptables", "ip6tables"]
        .into_iter()
        .filter(|b| ctx.has(b) && (*b == "iptables" || ipv6_available(&ctx.paths.system_root)))
        .collect()
}

/// The nft table, one block per family; multi-line because nft requires a
/// separator between a chain's closing brace and the table's.
pub fn nft_script(families: &[&str], token: &str, range: PortRange, target: u16) -> String {
    families
        .iter()
        .map(|family| {
            format!(
                "table {family} {token} {{\n\tchain prerouting {{\n\t\ttype nat hook prerouting priority -100; policy accept;\n\t\tfib daddr type local udp dport {}-{} redirect to :{target}\n\t}}\n}}\n",
                range.start, range.end
            )
        })
        .collect()
}

/// Load the hop table with `nft -f` (atomic: all families or nothing).
fn load_nft(ctx: &Ctx, range: PortRange, target: u16) -> Result<Hop> {
    let token = format!("onebox_hop_{}", crate::sys::rand::hex(8)?);
    let families: &[&str] = if ipv6_available(&ctx.paths.system_root) {
        &["ip", "ip6"]
    } else {
        &["ip"]
    };
    let script = nft_script(families, &token, range, target);
    // A private file under ROOT (TEMP_PREFIX, so a crash leftover is swept).
    let file = ctx.paths.root.join(format!(
        "{}nft-hop-{}",
        crate::sys::fs::TEMP_PREFIX,
        crate::sys::rand::hex(8)?
    ));
    if !ctx.paths.root.is_dir() {
        crate::sys::fs::ensure_dir(&ctx.paths.root, 0o700)?;
    }
    write_new_exclusive(&file, script.as_bytes(), 0o600)?;
    let result = ctx.check(&Cmd::new("nft").arg("-f").arg(file.to_string_lossy()));
    let _ = remove_file_if_exists(&file);
    result?;
    Ok(Hop {
        backend: "nft".into(),
        start: range.start,
        end: range.end,
        target,
        token,
    })
}

/// The only place iptables hop argv is built (`-A`, `-C` or `-D`).
fn iptables_cmd(hop: &Hop, op: &str) -> Cmd {
    Cmd::new(hop.backend.as_str()).args([
        "-w".to_string(),
        "5".into(),
        "-t".into(),
        "nat".into(),
        op.into(),
        "PREROUTING".into(),
        "-p".into(),
        "udp".into(),
        "--dport".into(),
        format!("{}:{}", hop.start, hop.end),
        "-m".into(),
        "addrtype".into(),
        "--dst-type".into(),
        "LOCAL".into(),
        "-m".into(),
        "comment".into(),
        "--comment".into(),
        hop.token.clone(),
        "-j".into(),
        "REDIRECT".into(),
        "--to-ports".into(),
        hop.target.to_string(),
    ])
}

/// Remove one recorded hop; absent rules and vanished programs are fine.
fn remove(ctx: &Ctx, hop: &Hop) -> Result<()> {
    match hop.backend.as_str() {
        "nft" => remove_nft(ctx, &hop.token),
        "iptables" | "ip6tables" => {
            if !ctx.has(&hop.backend) {
                return Ok(());
            }
            let check = ctx.run(&iptables_cmd(hop, "-C"))?;
            match check.code {
                1 => Ok(()),
                0 => ctx.check(&iptables_cmd(hop, "-D")).map(drop),
                _ => Err(match check.stderr.trim() {
                    "" => Error::msg("无法读取跳跃规则"),
                    detail => Error::msg(format!("无法读取跳跃规则: {detail}")),
                }),
            }
        }
        _ => Err(Error::msg("未知端口跳跃记录类型")),
    }
}

fn remove_nft(ctx: &Ctx, token: &str) -> Result<()> {
    if !ctx.has("nft") {
        return Ok(());
    }
    let listing = ctx.check(&Cmd::new("nft").args(["-j", "list", "tables"]))?;
    let doc: serde_json::Value = serde_json::from_str(&listing)?;
    let tables = doc["nftables"]
        .as_array()
        .ok_or_else(|| Error::msg("nft tables格式错误"))?;
    for family in ["ip", "ip6", "inet"] {
        let present = tables.iter().any(|row| {
            row["table"]["family"] == family && row["table"]["name"].as_str() == Some(token)
        });
        if present {
            ctx.check(&Cmd::new("nft").args(["delete", "table", family, token]))?;
        }
    }
    Ok(())
}

/// Read and validate the ledger (its values end up in command arguments).
fn load(path: &Path) -> Result<Vec<Hop>> {
    let hops: Vec<Hop> = match read_bounded(path, MAX_LEDGER_BYTES) {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .with_context(|| format!("端口跳跃记录无效: {}", path.display()))?,
        Err(Error::Io { source, .. }) if source.kind() == std::io::ErrorKind::NotFound => {
            return Ok(Vec::new())
        }
        Err(e) => return Err(e),
    };
    for hop in &hops {
        validate(hop).with_context(|| format!("端口跳跃记录无效: {}", path.display()))?;
    }
    Ok(hops)
}

fn validate(hop: &Hop) -> Result<()> {
    if !matches!(hop.backend.as_str(), "nft" | "iptables" | "ip6tables") {
        return Err(Error::msg("未知端口跳跃记录类型"));
    }
    if !safe_word(&hop.token) {
        return Err(Error::msg("跳跃表名称无效"));
    }
    if hop.start == 0 || hop.start > hop.end || hop.target == 0 {
        return Err(Error::msg("跳跃端口无效"));
    }
    Ok(())
}

/// Compact JSON like v2; `[]` once everything is cleared.
fn save(path: &Path, hops: &[Hop]) -> Result<()> {
    atomic_write(path, &serde_json::to_vec(hops)?, 0o600)
}

fn lock(ledger: &Path) -> Result<FileLock> {
    lock_waiting(&ledger.with_extension("lock"), LOCK_BUSY, LOCK_WAIT)
}

#[cfg(test)]
mod tests;
