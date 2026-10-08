//! iptables / ip6tables `INPUT` rules with a comment token.

use super::{failure, ipv6_enabled, Backend, Rule};
use crate::ctx::Ctx;
use crate::error::Result;
use crate::sys::exec::Cmd;

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

/// Usable binaries among `wanted` (ip6tables only with IPv6 enabled); each
/// must answer `-S INPUT`, otherwise the firewall state is unknown.
pub(super) fn detect_families(ctx: &Ctx, v4: bool, v6: bool) -> Result<Vec<Iptables>> {
    let mut found = Vec::new();
    for backend in [Iptables { v6: false }, Iptables { v6: true }] {
        let wanted = if backend.v6 { v6 } else { v4 };
        if !wanted || !ctx.has(backend.binary()) || (backend.v6 && !ipv6_enabled(&ctx.paths)) {
            continue;
        }
        ctx.check(&Cmd::new(backend.binary()).args(["-w", "5", "-S", "INPUT"]))?;
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
