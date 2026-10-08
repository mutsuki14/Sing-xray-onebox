//! ufw rules with a comment token (managed only while ufw is active).

use super::{Backend, Rule};
use crate::ctx::Ctx;
use crate::error::Result;
use crate::sys::exec::Cmd;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Ufw;

/// Rule numbers of `ufw status numbered` lines carrying `token`, highest
/// first (deleting from the end keeps the remaining numbers valid).
pub(super) fn numbered_matches(status: &str, token: &str) -> Vec<u32> {
    let mut numbers: Vec<u32> = status
        .lines()
        .filter(|line| carries(line, token))
        .filter_map(|line| {
            let (number, _) = line.trim().strip_prefix('[')?.split_once(']')?;
            number.trim().parse().ok()
        })
        .collect();
    numbers.sort_unstable_by(|a, b| b.cmp(a));
    numbers.dedup();
    numbers
}

/// Whether a status line carries the token as a whole word (the comment
/// follows `# `).
fn carries(line: &str, token: &str) -> bool {
    line.split_whitespace().any(|word| word == token)
}

fn status_numbered(ctx: &Ctx) -> Result<String> {
    ctx.check(&Cmd::new("ufw").args(["status", "numbered"]))
}

impl Backend for Ufw {
    fn name(&self) -> &'static str {
        "ufw"
    }

    fn program(&self) -> &'static str {
        "ufw"
    }

    /// Only an active ufw filters traffic; an installed but inactive ufw is
    /// left alone (rules added there would silently do nothing).
    fn detect(ctx: &Ctx) -> Result<Vec<Self>> {
        if !ctx.has("ufw") {
            return Ok(Vec::new());
        }
        let out = ctx.run(&Cmd::new("ufw").arg("status"))?;
        let active = out.ok() && out.stdout.lines().any(|l| l.trim() == "Status: active");
        Ok(if active { vec![Ufw] } else { Vec::new() })
    }

    /// `ufw allow P[:E]/proto comment TOKEN`.
    fn create(&self, ctx: &Ctx, rule: &Rule) -> Result<bool> {
        let port = format!("{}/{}", rule.span(":"), rule.proto.id());
        ctx.check(&Cmd::new("ufw").args(["allow", &port, "comment", &rule.token]))?;
        Ok(true)
    }

    fn exists(&self, ctx: &Ctx, rule: &Rule) -> Result<bool> {
        Ok(status_numbered(ctx)?
            .lines()
            .any(|line| carries(line, &rule.token)))
    }

    /// Delete every numbered rule carrying the token (IPv4 and IPv6 copies).
    fn remove(&self, ctx: &Ctx, rule: &Rule) -> Result<()> {
        for number in numbered_matches(&status_numbered(ctx)?, &rule.token) {
            ctx.check(&Cmd::new("ufw").args(["--force", "delete", &number.to_string()]))?;
        }
        Ok(())
    }
}
