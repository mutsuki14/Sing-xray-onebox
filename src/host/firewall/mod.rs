//! Managed host firewall: allow rules owned by Onebox, grouped by owner
//! (`proxy`, `acme`, `frp`, …), recorded in a durable per-owner ledger and
//! reconciled against the public ports an owner needs.
//!
//! Ownership is proven only by the ledger plus a random per-rule token
//! `onebox-{owner}-{16 hex}`: it is the rule comment for iptables, ufw and
//! nft; firewalld has no comments, so there a rule is ours only when the
//! port was absent from the zone before Onebox added it. Rules an
//! administrator created are never adopted and never removed.
//!
//! Backend selection ([`detect`], first match wins):
//! 1. ufw, only while `ufw status` reports `Status: active`;
//! 2. firewalld, while running: every active zone, runtime and permanent;
//! 3. native nft input chains (family ip/ip6/inet) that can block a port
//!    (`policy drop`, or an unconditional drop/reject rule), plus
//!    iptables/ip6tables for the families whose `filter INPUT` chain belongs
//!    to iptables-nft;
//! 4. iptables / ip6tables, inserting at `INPUT` position 1 so a trailing
//!    `REJECT` (Oracle Cloud images) cannot win.
//!
//! No rule is persisted with `iptables-save`/`netfilter-persistent`: the
//! `onebox-network` boot oneshot re-applies the ledger owners.
//!
//! Changes from v2:
//! - iptables-nft compatibility chains (`ip|ip6 filter INPUT`) are never
//!   edited with raw nft rules; they are managed through iptables, while
//!   native nft chains still get nft rules (v2 E-8.1#14 / F-8.1#14);
//! - a rule whose backend program vanished counts as gone (E-8.1#13);
//! - rules left on a backend that is no longer selected are removed too,
//!   and a failed removal of a stale rule no longer aborts the whole apply:
//!   the rule stays in the ledger, a warning is printed and the next
//!   reconcile retries (F-8.1#13);
//! - an nft chain that no longer exists counts as "rule gone"; iptables-nft's
//!   `nat`/`mangle`/`raw`/`security` INPUT chains and non-filter chains are
//!   never edited;
//! - v2 inserted an accept at the head of every native filter input chain,
//!   including security chains whose drops are all conditional (crowdsec's
//!   `crowdsec-chain`, fail2ban's `f2b-chain`), where it only let blocked
//!   sources bypass them; v3 edits only chains that can block a port, and
//!   reconcile removes the rules v2 left in the others;
//! - an input chain whose name nft cannot be given safely (LXD/Incus
//!   `inet lxd in.lxdbr0`) is skipped, with a warning when it can block,
//!   instead of failing every apply;
//! - ufw specs held by an administrator rule are no longer re-commented
//!   (ufw merges identical rules, so v2 adopted and later deleted them);
//! - firewalld/ufw ports wanted by two owners (`proxy` and `acme` on TCP
//!   80) stay open until neither records them (v2 closed TCP 80 after the
//!   first HTTP-01 issuance on firewalld hosts);
//! - the owner name `v2` is reserved (its ledger file is `proxy`'s);
//! - a failing `nft list ruleset` (kernel without nf_tables) falls back to
//!   iptables instead of failing the apply;
//! - the ledger lock waits at most 30 seconds instead of forever.
//!
//! One-shot v1 cleanup (`firewall.list`, `onebox` comments) is not part of
//! v3: v1 installations must upgrade through v2.0.1 first.

mod firewalld;
mod iptables;
mod ledger;
mod nft;
mod reconcile;
mod siblings;
mod ufw;

pub use firewalld::Firewalld;
pub use iptables::Iptables;
pub use ledger::{ledger_path, Entry, Ledger};
pub use nft::Nft;
pub use reconcile::{clear, clear_owner, reconcile, reconcile_owner, Report};
pub use ufw::Ufw;

use crate::ctx::Ctx;
use crate::domain::protocol::Transport;
use crate::error::{Error, Result};
use crate::sys::exec::Output;
use crate::sys::lock::FileLock;
use std::path::Path;
use std::time::{Duration, Instant};

/// Layer-4 protocol of one rule (a rule never covers both).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Proto {
    Tcp,
    Udp,
}

impl Proto {
    pub fn id(self) -> &'static str {
        match self {
            Proto::Tcp => "tcp",
            Proto::Udp => "udp",
        }
    }

    pub fn is_udp(self) -> bool {
        self == Proto::Udp
    }

    /// The protocols a listener transport needs (TCP first).
    pub fn of(transport: Transport) -> &'static [Proto] {
        match transport {
            Transport::Tcp => &[Proto::Tcp],
            Transport::Udp => &[Proto::Udp],
            Transport::Both => &[Proto::Tcp, Proto::Udp],
        }
    }
}

/// One owned allow rule: an inclusive port range of one protocol, tagged
/// with the ownership token.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rule {
    pub owner: String,
    pub proto: Proto,
    pub start: u16,
    pub end: u16,
    pub token: String,
}

impl Rule {
    /// `start` alone, or `start{sep}end` for a real range.
    pub fn span(&self, sep: &str) -> String {
        if self.end > self.start {
            format!("{}{sep}{}", self.start, self.end)
        } else {
            self.start.to_string()
        }
    }

    /// The range key used to match desired ports.
    pub fn range(&self) -> PortSpan {
        PortSpan {
            start: self.start,
            end: self.end,
            proto: self.proto,
        }
    }
}

/// An inclusive port range of one protocol.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PortSpan {
    pub start: u16,
    pub end: u16,
    pub proto: Proto,
}

/// A firewall implementation. Every backend builds its argv in exactly one
/// place; `Ctx::exec` runs it, so tests use `FakeExec`.
pub trait Backend {
    /// The ledger `backend` value (`ufw`, `firewalld`, `nft`, `iptables`,
    /// `ip6tables`).
    fn name(&self) -> &'static str;
    /// The program whose absence means every rule of this backend is gone.
    fn program(&self) -> &'static str;
    /// Active instances of this backend on the host (empty when inactive).
    fn detect(ctx: &Ctx) -> Result<Vec<Self>>
    where
        Self: Sized;
    /// Add `rule`. `Ok(false)`: an equal administrator rule already exists
    /// (firewalld), nothing was added and nothing may be recorded.
    fn create(&self, ctx: &Ctx, rule: &Rule) -> Result<bool>;
    /// Whether `rule` is live, always queried from the firewall itself.
    fn exists(&self, ctx: &Ctx, rule: &Rule) -> Result<bool>;
    /// Remove `rule`; an absent rule is fine.
    fn remove(&self, ctx: &Ctx, rule: &Rule) -> Result<()>;
}

/// Where a rule lives: one backend instance (zone, chain or binary).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Location {
    Ufw(Ufw),
    Firewalld(Firewalld),
    Nft(Nft),
    Iptables(Iptables),
}

impl Location {
    pub fn backend(&self) -> &dyn Backend {
        match self {
            Location::Ufw(b) => b,
            Location::Firewalld(b) => b,
            Location::Nft(b) => b,
            Location::Iptables(b) => b,
        }
    }

    /// Place for user-facing messages, e.g. `firewalld public（永久）`.
    pub fn describe(&self) -> String {
        match self {
            Location::Ufw(_) => "ufw".into(),
            Location::Firewalld(f) if f.permanent => format!("firewalld {}（永久）", f.zone),
            Location::Firewalld(f) => format!("firewalld {}（运行时）", f.zone),
            Location::Nft(n) => format!("nft {} {} {}", n.family, n.table, n.chain),
            Location::Iptables(i) => i.binary().into(),
        }
    }
}

/// The backend instances to manage on this host (see module docs for the
/// order). An empty list means no managed firewall: nothing is created.
pub fn detect(ctx: &Ctx) -> Result<Vec<Location>> {
    if let Some(ufw) = Ufw::detect(ctx)?.pop() {
        return Ok(vec![Location::Ufw(ufw)]);
    }
    let zones = Firewalld::detect(ctx)?;
    if !zones.is_empty() {
        return Ok(zones.into_iter().map(Location::Firewalld).collect());
    }
    let scan = nft::scan(ctx)?;
    if scan.native.is_empty() {
        return Ok(Iptables::detect(ctx)?
            .into_iter()
            .map(Location::Iptables)
            .collect());
    }
    let compat = iptables::detect_families(ctx, scan.compat_v4, scan.compat_v6)?;
    Ok(scan
        .native
        .into_iter()
        .map(Location::Nft)
        .chain(compat.into_iter().map(Location::Iptables))
        .collect())
}

/// Owner names become file names and tokens: `[A-Za-z0-9-]{1,31}`, and
/// never `v2`, whose `firewall-v2.json` is the `proxy` ledger.
pub fn validate_owner(owner: &str) -> Result<()> {
    let ok = !owner.is_empty()
        && owner.len() < 32
        && owner != "v2"
        && owner
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-');
    if ok {
        Ok(())
    } else {
        Err(Error::msg("防火墙所有者名称无效"))
    }
}

/// A fresh ownership token `onebox-{owner}-{16 hex}`.
pub fn new_token(owner: &str) -> Result<String> {
    Ok(format!("onebox-{owner}-{}", crate::sys::rand::hex(8)?))
}

/// Identifiers interpolated into nft/firewalld arguments: `[A-Za-z0-9_-]+`.
pub fn safe_word(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

/// Normalize desired ports: expand `Transport::Both`, then merge
/// overlapping or adjacent ranges per protocol (never across protocols),
/// TCP ranges first, each ascending. Port 0 and reversed ranges are errors.
pub fn spans(desired: &[(u16, u16, Transport)]) -> Result<Vec<PortSpan>> {
    let mut out = Vec::new();
    for proto in [Proto::Tcp, Proto::Udp] {
        let mut ranges = Vec::new();
        for &(start, end, transport) in desired {
            if start == 0 || end == 0 {
                return Err(Error::msg("防火墙端口不能为0"));
            }
            if start > end {
                return Err(Error::msg(format!("防火墙端口范围无效: {start}-{end}")));
            }
            if Proto::of(transport).contains(&proto) {
                ranges.push((start, end));
            }
        }
        ranges.sort_unstable();
        let mut merged: Vec<(u16, u16)> = Vec::new();
        for (start, end) in ranges {
            match merged.last_mut() {
                Some(last) if u32::from(start) <= u32::from(last.1) + 1 => {
                    last.1 = last.1.max(end);
                }
                _ => merged.push((start, end)),
            }
        }
        out.extend(
            merged
                .into_iter()
                .map(|(start, end)| PortSpan { start, end, proto }),
        );
    }
    Ok(out)
}

/// Take the lock file `path`, waiting up to `wait` while another process
/// holds it (ledger mutations are short); then `Error::Busy(busy)`.
pub(crate) fn lock_waiting(path: &Path, busy: &str, wait: Duration) -> Result<FileLock> {
    let deadline = Instant::now() + wait;
    loop {
        match FileLock::acquire(path, busy) {
            Err(Error::Busy(_)) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(100))
            }
            other => return other,
        }
    }
}

/// `{message}` or `{message}: {stderr}` for a failed probe.
fn failure(message: &str, out: &Output) -> Error {
    let detail = out.stderr.trim();
    if detail.is_empty() {
        Error::msg(message)
    } else {
        Error::msg(format!("{message}: {detail}"))
    }
}

#[cfg(test)]
mod tests;
