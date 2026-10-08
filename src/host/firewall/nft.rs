//! Native nftables input chains: rules tagged with a comment token.

use super::{failure, safe_word, Backend, Rule};
use crate::ctx::Ctx;
use crate::error::{Error, Result};
use crate::sys::exec::{Cmd, Output};
use serde_json::Value;

/// One base chain hooked on `input`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Nft {
    pub family: String,
    pub table: String,
    pub chain: String,
}

/// What `nft -j list ruleset` revealed about input base chains.
#[derive(Debug, Default, PartialEq, Eq)]
pub(super) struct Scan {
    /// Chains Onebox may edit with nft.
    pub native: Vec<Nft>,
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

/// Classify the input base chains of a `nft -j list ruleset` document.
/// Only `type filter` chains can accept or drop; nat/route chains are
/// ignored.
pub(super) fn parse_ruleset(doc: &Value) -> Result<Scan> {
    let entries = doc["nftables"]
        .as_array()
        .ok_or_else(|| Error::msg("nft ruleset 格式无效"))?;
    let mut scan = Scan::default();
    for chain in entries.iter().map(|e| &e["chain"]) {
        if chain["hook"] != "input" || chain["type"].as_str().is_some_and(|t| t != "filter") {
            continue;
        }
        let family = chain["family"]
            .as_str()
            .ok_or_else(|| Error::msg("缺少 nft family"))?;
        if !matches!(family, "ip" | "ip6" | "inet") {
            continue;
        }
        let table = chain["table"]
            .as_str()
            .ok_or_else(|| Error::msg("缺少 nft table"))?;
        let name = chain["name"]
            .as_str()
            .ok_or_else(|| Error::msg("缺少 nft chain"))?;
        if !safe_word(table) || !safe_word(name) {
            return Err(Error::msg("nft 表或链名无法安全管理"));
        }
        if iptables_table(family, table, name) {
            let filter = table == "filter";
            scan.compat_v4 |= filter && family == "ip";
            scan.compat_v6 |= filter && family == "ip6";
            continue;
        }
        let found = Nft {
            family: family.into(),
            table: table.into(),
            chain: name.into(),
        };
        if !scan.native.contains(&found) {
            scan.native.push(found);
        }
    }
    Ok(scan)
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
    parse_ruleset(&serde_json::from_str(&out.stdout)?)
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
