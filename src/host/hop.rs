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
//!   unreported IPv4-only hop.

use crate::ctx::Ctx;
use crate::domain::config::PortRange;
use crate::error::{Error, Result};
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

/// Remove the first `count` (previous) hops now that the new ones work.
fn retire(ctx: &Ctx, path: &Path, mut hops: Vec<Hop>, count: usize) -> Result<()> {
    for _ in 0..count {
        let Some(old) = hops.first() else { break };
        remove(ctx, old).map_err(|e| {
            Error::msg(format!(
                "新的端口跳跃规则已生效，但旧规则清理失败（已保留记录）: {e}"
            ))
        })?;
        hops.remove(0);
        save(path, &hops)?;
    }
    Ok(())
}

/// Remove every recorded hop. Hops are removed in order and the ledger is
/// rewritten after each one; the first failure stops, leaving the rest
/// recorded.
pub fn clear(ctx: &Ctx) -> Result<()> {
    let path = ledger_path(ctx);
    let _lock = lock(&path)?;
    clear_locked(ctx, &path)
}

fn clear_locked(ctx: &Ctx, path: &Path) -> Result<()> {
    if !path.exists() {
        return Ok(());
    }
    let mut hops = load(path)?;
    while let Some(first) = hops.first() {
        remove(ctx, first)?;
        hops.remove(0);
        save(path, &hops)?;
    }
    Ok(())
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
                _ => Err(Error::msg("无法读取跳跃规则")),
            }
        }
        _ => Err(Error::msg("未知端口跳跃记录类型")),
    }
}

fn remove_nft(ctx: &Ctx, token: &str) -> Result<()> {
    if !safe_word(token) {
        return Err(Error::msg("跳跃表名称无效"));
    }
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

fn load(path: &Path) -> Result<Vec<Hop>> {
    match read_bounded(path, MAX_LEDGER_BYTES) {
        Ok(bytes) => Ok(serde_json::from_slice(&bytes)?),
        Err(Error::Io { source, .. }) if source.kind() == std::io::ErrorKind::NotFound => {
            Ok(Vec::new())
        }
        Err(e) => Err(e),
    }
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
