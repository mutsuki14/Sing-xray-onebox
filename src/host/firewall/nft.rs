//! Native nftables input chains: rules tagged with a comment token.
//!
//! Only chains that can actually block a port get an Onebox rule: a
//! `type filter hook input` base chain with `policy drop`, or one holding
//! an unconditional `drop`/`reject` rule. In nftables an `accept` ends only
//! the chain it is in, so inserting one at the head of a chain whose drops
//! are all conditional (crowdsec's `ip saddr @crowdsec-blacklists drop`,
//! fail2ban's `f2b-chain`) would not open anything — it would only let
//! blocklisted sources skip that chain.
//!
//! Names Onebox cannot pass to nft safely (`[A-Za-z0-9_-]` only) are
//! skipped instead of failing the scan: LXD/Incus create `inet lxd
//! in.lxdbr0`. A skipped chain that can block is reported once per scan.

use super::{failure, safe_word, Backend, Rule};
use crate::ctx::Ctx;
use crate::error::{Error, Result};
use crate::sys::exec::{Cmd, Output};
use crate::sys::text::sanitize_input;
use crate::ui::out;
use serde_json::Value;
use std::collections::BTreeSet;

/// One base chain hooked on `input`.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Nft {
    pub family: String,
    pub table: String,
    pub chain: String,
}

/// What `nft -j list ruleset` revealed about input base chains.
#[derive(Debug, Default, PartialEq, Eq)]
pub(super) struct Scan {
    /// Chains Onebox edits with nft: they can block, and their names are safe.
    pub native: Vec<Nft>,
    /// Chains that can block but whose table or chain name cannot be
    /// managed safely: left alone (the port may stay blocked there).
    pub skipped: Vec<Nft>,
    /// `ip filter INPUT` / `ip6 filter INPUT` exist: tables owned by
    /// iptables-nft, managed through iptables / ip6tables instead.
    pub compat_v4: bool,
    pub compat_v6: bool,
}

/// An `INPUT` chain of one of iptables-nft's tables. Editing those with raw
/// nft makes iptables report the table as incompatible; only `filter INPUT`
/// (where `iptables -I INPUT` goes) decides whether a packet is accepted.
fn iptables_table(family: &str, table: &str, chain: &str) -> bool {
    matches!(family, "ip" | "ip6")
        && matches!(table, "filter" | "nat" | "mangle" | "raw" | "security")
        && chain == "INPUT"
}

/// A `type filter hook input` base chain of family ip/ip6/inet, with
/// whether its policy drops. Other chains are `None`.
fn input_chain(chain: &Value) -> Result<Option<(Nft, bool)>> {
    if chain["hook"] != "input" || chain["type"].as_str().is_some_and(|t| t != "filter") {
        return Ok(None);
    }
    let family = chain["family"]
        .as_str()
        .ok_or_else(|| Error::msg("缺少 nft family"))?;
    if !matches!(family, "ip" | "ip6" | "inet") {
        return Ok(None);
    }
    let field = |name: &str, missing: &str| {
        chain[name]
            .as_str()
            .map(String::from)
            .ok_or_else(|| Error::msg(missing.to_string()))
    };
    let found = Nft {
        family: family.into(),
        table: field("table", "缺少 nft table")?,
        chain: field("name", "缺少 nft chain")?,
    };
    Ok(Some((found, chain["policy"] == "drop")))
}

/// A rule without any match that ends in `drop` or `reject` (counters and
/// log statements allowed): every packet reaching it is refused.
fn unconditional_block(rule: &Value) -> bool {
    let Some(exprs) = rule["expr"].as_array() else {
        return false;
    };
    let mut refuses = false;
    for expr in exprs {
        match statement(expr) {
            Some("drop" | "reject") => refuses = true,
            Some("counter" | "log") => {}
            _ => return false,
        }
    }
    refuses
}

/// The only key of a one-key JSON object (`{"drop": null}` → `drop`).
fn statement(expr: &Value) -> Option<&str> {
    expr.as_object()
        .filter(|o| o.len() == 1)
        .and_then(|o| o.keys().next())
        .map(String::as_str)
}

/// `(family, table, chain)` of every chain holding an unconditional block.
fn blocking_rules(entries: &[Value]) -> BTreeSet<(String, String, String)> {
    entries
        .iter()
        .map(|e| &e["rule"])
        .filter(|rule| unconditional_block(rule))
        .filter_map(|rule| {
            let text = |name: &str| rule[name].as_str().map(String::from);
            Some((text("family")?, text("table")?, text("chain")?))
        })
        .collect()
}

/// Classify the input base chains of a `nft -j list ruleset` document.
/// Only `type filter` chains can accept or drop; nat/route chains are
/// ignored, and so are filter chains that cannot block (module docs).
pub(super) fn parse_ruleset(doc: &Value) -> Result<Scan> {
    let entries = doc["nftables"]
        .as_array()
        .ok_or_else(|| Error::msg("nft ruleset 格式无效"))?;
    let blocking = blocking_rules(entries);
    let mut scan = Scan::default();
    for chain in entries.iter().map(|e| &e["chain"]) {
        let Some((found, policy_drop)) = input_chain(chain)? else {
            continue;
        };
        if iptables_table(&found.family, &found.table, &found.chain) {
            let filter = found.table == "filter";
            scan.compat_v4 |= filter && found.family == "ip";
            scan.compat_v6 |= filter && found.family == "ip6";
            continue;
        }
        let key = (
            found.family.clone(),
            found.table.clone(),
            found.chain.clone(),
        );
        if !policy_drop && !blocking.contains(&key) {
            continue;
        }
        let list = if safe_word(&found.table) && safe_word(&found.chain) {
            &mut scan.native
        } else {
            &mut scan.skipped
        };
        if !list.contains(&found) {
            list.push(found);
        }
    }
    Ok(scan)
}

/// The warning for a blocking chain Onebox cannot edit.
pub(super) fn skipped_notice(chain: &Nft) -> String {
    format!(
        "nft 链 {} {} {} 名称无法安全管理，已跳过；该链会拦截未放行的流量，Onebox 端口可能无法访问，请手动放行",
        chain.family,
        sanitize_input(&chain.table),
        sanitize_input(&chain.chain)
    )
}

/// Input chains on this host. Without nft, or when the ruleset cannot be
/// listed (kernel without nf_tables), there are none.
pub(super) fn scan(ctx: &Ctx) -> Result<Scan> {
    if !ctx.has("nft") {
        return Ok(Scan::default());
    }
    let out = ctx.run(&Cmd::new("nft").args(["-j", "list", "ruleset"]))?;
    if !out.ok() {
        return Ok(Scan::default());
    }
    let scan = parse_ruleset(&serde_json::from_str(&out.stdout)?)?;
    for chain in &scan.skipped {
        out::warn(skipped_notice(chain));
    }
    Ok(scan)
}

/// One rule of a chain listing.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct ChainRule {
    pub handle: Option<u64>,
    pub comment: Option<String>,
}

impl ChainRule {
    fn tagged(&self, token: &str) -> bool {
        self.comment.as_deref() == Some(token)
    }
}

/// Every rule in a `nft -j [-a] list chain` document.
pub(super) fn chain_rules(doc: &Value) -> Result<Vec<ChainRule>> {
    let rows = doc["nftables"]
        .as_array()
        .ok_or_else(|| Error::msg("nft chain 格式无效"))?;
    Ok(rows
        .iter()
        .map(|row| &row["rule"])
        .filter(|rule| rule.is_object())
        .map(|rule| ChainRule {
            handle: rule["handle"].as_u64(),
            comment: rule["comment"].as_str().map(String::from),
        })
        .collect())
}

/// A chain listing that failed because the chain (or its table) is gone.
fn chain_missing(out: &Output) -> bool {
    !out.ok() && out.stderr.contains("No such file or directory")
}

impl Nft {
    /// The only place nft rule argv is built. The comment element contains
    /// literal double quotes because nft parses its joined argv.
    fn insert_cmd(&self, rule: &Rule) -> Cmd {
        Cmd::new("nft").args([
            "insert",
            "rule",
            self.family.as_str(),
            self.table.as_str(),
            self.chain.as_str(),
            rule.proto.id(),
            "dport",
            rule.span("-").as_str(),
            "accept",
            "comment",
            format!("\"{}\"", rule.token).as_str(),
        ])
    }

    fn list_cmd(&self, handles: bool) -> Cmd {
        let flags: &[&str] = if handles { &["-j", "-a"] } else { &["-j"] };
        Cmd::new("nft").args(flags.iter().copied()).args([
            "list",
            "chain",
            &self.family,
            &self.table,
            &self.chain,
        ])
    }

    fn delete_cmd(&self, handle: u64) -> Cmd {
        Cmd::new("nft").args([
            "delete",
            "rule",
            self.family.as_str(),
            self.table.as_str(),
            self.chain.as_str(),
            "handle",
            handle.to_string().as_str(),
        ])
    }

    /// Rules of this chain, or `None` when the chain no longer exists.
    fn rules(&self, ctx: &Ctx, handles: bool) -> Result<Option<Vec<ChainRule>>> {
        let out = ctx.run(&self.list_cmd(handles))?;
        if chain_missing(&out) {
            return Ok(None);
        }
        if !out.ok() {
            return Err(failure("无法读取 nft 规则", &out));
        }
        chain_rules(&serde_json::from_str(&out.stdout)?).map(Some)
    }
}

impl Backend for Nft {
    fn name(&self) -> &'static str {
        "nft"
    }

    fn program(&self) -> &'static str {
        "nft"
    }

    fn detect(ctx: &Ctx) -> Result<Vec<Self>> {
        Ok(scan(ctx)?.native)
    }

    fn create(&self, ctx: &Ctx, rule: &Rule) -> Result<bool> {
        ctx.check(&self.insert_cmd(rule))?;
        Ok(true)
    }

    fn exists(&self, ctx: &Ctx, rule: &Rule) -> Result<bool> {
        Ok(self
            .rules(ctx, false)?
            .is_some_and(|rules| rules.iter().any(|r| r.tagged(&rule.token))))
    }

    fn remove(&self, ctx: &Ctx, rule: &Rule) -> Result<()> {
        let Some(rules) = self.rules(ctx, true)? else {
            return Ok(());
        };
        for listed in rules.iter().filter(|r| r.tagged(&rule.token)) {
            let handle = listed.handle.ok_or_else(|| Error::msg("nft handle 无效"))?;
            ctx.check(&self.delete_cmd(handle))?;
        }
        Ok(())
    }
}
