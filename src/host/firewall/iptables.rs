//! iptables / ip6tables `INPUT` rules with a comment token.

use super::{failure, Backend, Rule};
use crate::ctx::Ctx;
use crate::error::Result;
use crate::sys::exec::Cmd;
use crate::sys::net::ipv6_available;

/// One of the two binaries; rules go to the `filter` table's `INPUT` chain.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Iptables {
    pub v6: bool,
}

#[derive(Clone, Copy)]
enum Op {
    /// `-I INPUT 1`: ahead of trailing REJECT rules (Oracle Cloud images).
    Insert,
    Check,
    Delete,
}

impl Iptables {
    pub fn binary(self) -> &'static str {
        if self.v6 {
            "ip6tables"
        } else {
            "iptables"
        }
    }

    /// `-S INPUT`: succeeds when this binary can read its `INPUT` chain.
    fn list_cmd(self) -> Cmd {
        Cmd::new(self.binary()).args(["-w", "5", "-S", "INPUT"])
    }

    /// The only place iptables rule argv is built.
    fn cmd(self, op: Op, rule: &Rule) -> Cmd {
        let head: &[&str] = match op {
            Op::Insert => &["-w", "5", "-I", "INPUT", "1"],
            Op::Check => &["-w", "5", "-C", "INPUT"],
            Op::Delete => &["-w", "5", "-D", "INPUT"],
        };
        Cmd::new(self.binary()).args(head.iter().copied()).args([
            "-p",
            rule.proto.id(),
            "--dport",
            rule.span(":").as_str(),
            "-m",
            "comment",
            "--comment",
            rule.token.as_str(),
            "-j",
            "ACCEPT",
        ])
    }
}

/// Who manages an `ip|ip6 filter INPUT` chain listed by nft.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum FilterOwner {
    /// iptables-nft: the binary is the nf_tables variant and lists the
    /// chain, so rules go through iptables.
    Iptables,
    /// A native nft chain; the binary is absent or iptables-legacy, whose
    /// tables are separate from nft's.
    Nft,
    /// A native nft chain iptables-nft refuses to list (`incompatible, use
    /// 'nft' tool`, e.g. after `iptables-restore-translate`): rules go
    /// through nft and this binary cannot manage anything.
    NftOnly,
}

/// Ask `backend` whether the nft `filter INPUT` chain of its family is its
/// own: only iptables-nft (`-V` says `nf_tables`) that lists it owns it.
pub(super) fn filter_input_owner(ctx: &Ctx, backend: Iptables) -> Result<FilterOwner> {
    if !ctx.has(backend.binary()) {
        return Ok(FilterOwner::Nft);
    }
    let version = ctx.run(&Cmd::new(backend.binary()).arg("-V"))?;
    if !version.ok() || !version.stdout.contains("nf_tables") {
        return Ok(FilterOwner::Nft);
    }
    Ok(if ctx.run(&backend.list_cmd())?.ok() {
        FilterOwner::Iptables
    } else {
        FilterOwner::NftOnly
    })
}

/// Usable binaries among `wanted` (ip6tables only with IPv6 enabled); each
/// must answer `-S INPUT`, otherwise the firewall state is unknown.
pub(super) fn detect_families(ctx: &Ctx, v4: bool, v6: bool) -> Result<Vec<Iptables>> {
    let mut found = Vec::new();
    for backend in [Iptables { v6: false }, Iptables { v6: true }] {
        let wanted = if backend.v6 { v6 } else { v4 };
        if !wanted
            || !ctx.has(backend.binary())
            || (backend.v6 && !ipv6_available(&ctx.paths.system_root))
        {
            continue;
        }
        ctx.check(&backend.list_cmd())?;
        found.push(backend);
    }
    Ok(found)
}

impl Backend for Iptables {
    fn name(&self) -> &'static str {
        self.binary()
    }

    fn program(&self) -> &'static str {
        self.binary()
    }

    fn detect(ctx: &Ctx) -> Result<Vec<Self>> {
        detect_families(ctx, true, true)
    }

    fn create(&self, ctx: &Ctx, rule: &Rule) -> Result<bool> {
        ctx.check(&self.cmd(Op::Insert, rule))?;
        Ok(true)
    }

    /// `-C`: 0 present, 1 absent, anything else is an error.
    fn exists(&self, ctx: &Ctx, rule: &Rule) -> Result<bool> {
        let out = ctx.run(&self.cmd(Op::Check, rule))?;
        match out.code {
            0 => Ok(true),
            1 => Ok(false),
            _ => Err(failure("无法检查 iptables 规则", &out)),
        }
    }

    fn remove(&self, ctx: &Ctx, rule: &Rule) -> Result<()> {
        let out = ctx.run(&self.cmd(Op::Check, rule))?;
        match out.code {
            1 => Ok(()),
            0 => ctx.check(&self.cmd(Op::Delete, rule)).map(drop),
            _ => Err(failure("无法检查已有 iptables 规则", &out)),
        }
    }
}
