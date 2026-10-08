//! ufw rules with a comment token (managed only while ufw is active).
//!
//! ufw keeps one rule per spec: `ufw allow 443/tcp comment X` on a spec that
//! already exists replaces that rule's comment (and action) instead of
//! adding a rule. So a spec already held by a rule without an Onebox token
//! belongs to the administrator: it is not touched, not recorded and never
//! removed (v2 silently re-commented such rules and deleted them later). A
//! spec held by another Onebox owner is taken over (the comment moves to
//! us); when we stop wanting it while that owner still records it, the
//! comment is handed back instead of deleting the rule (`siblings`).

use super::{Backend, Rule};
use crate::ctx::Ctx;
use crate::error::{Error, Result};
use crate::sys::exec::Cmd;
use crate::ui::out;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Ufw;

/// One line of `ufw status numbered`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Listed<'a> {
    pub number: u32,
    /// `443/tcp`, `20000:40000/udp`, `22` …
    pub to: &'a str,
    /// `ALLOW`, `DENY`, `LIMIT`, `REJECT`.
    pub action: &'a str,
    pub from: &'a str,
    pub comment: Option<&'a str>,
}

/// `[ 2] 443/tcp (v6)   ALLOW IN    Anywhere (v6)   # comment`.
pub(super) fn parse_line(line: &str) -> Option<Listed<'_>> {
    let (number, rest) = line.trim().strip_prefix('[')?.split_once(']')?;
    let (rule, comment) = match rest.split_once(" # ") {
        Some((rule, comment)) => (rule, Some(comment.trim())),
        None => (rest, None),
    };
    let words: Vec<&str> = rule.split_whitespace().filter(|w| *w != "(v6)").collect();
    Some(Listed {
        number: number.trim().parse().ok()?,
        to: words.first()?,
        action: words.get(1)?,
        from: words.last()?,
        comment,
    })
}

/// Rule numbers carrying `token`, highest first (deleting from the end
/// keeps the remaining numbers valid).
pub(super) fn numbered_matches(status: &str, token: &str) -> Vec<u32> {
    let mut numbers: Vec<u32> = status
        .lines()
        .filter_map(parse_line)
        .filter(|l| l.comment == Some(token))
        .map(|l| l.number)
        .collect();
    numbers.sort_unstable_by(|a, b| b.cmp(a));
    numbers.dedup();
    numbers
}

/// A rule for `spec` from anywhere that no Onebox owner created.
pub(super) fn foreign_rule<'a>(status: &'a str, spec: &str) -> Option<Listed<'a>> {
    status.lines().filter_map(parse_line).find(|l| {
        l.to == spec && l.from == "Anywhere" && !l.comment.is_some_and(|c| c.starts_with("onebox-"))
    })
}

fn status_numbered(ctx: &Ctx) -> Result<String> {
    ctx.check(&Cmd::new("ufw").args(["status", "numbered"]))
}

/// Give the rule carrying `rule.token` to another owner by replacing its
/// comment with `token` (ufw updates the existing rule in place).
pub(super) fn recomment(ctx: &Ctx, rule: &Rule, token: &str) -> Result<()> {
    if numbered_matches(&status_numbered(ctx)?, &rule.token).is_empty() {
        return Ok(());
    }
    ctx.check(&Cmd::new("ufw").args(["allow", &spec(rule), "comment", token]))?;
    Ok(())
}

fn spec(rule: &Rule) -> String {
    format!("{}/{}", rule.span(":"), rule.proto.id())
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

    /// `ufw allow P[:E]/proto comment TOKEN`, unless an administrator rule
    /// already covers the spec.
    fn create(&self, ctx: &Ctx, rule: &Rule) -> Result<bool> {
        let spec = spec(rule);
        let status = status_numbered(ctx)?;
        if let Some(admin) = foreign_rule(&status, &spec) {
            if admin.action != "ALLOW" {
                out::warn(format!(
                    "ufw 已有管理员规则 {spec} {}，Onebox 不修改它；该端口可能无法访问",
                    admin.action
                ));
            }
            return Ok(false);
        }
        ctx.check(&Cmd::new("ufw").args(["allow", &spec, "comment", &rule.token]))?;
        Ok(true)
    }

    fn exists(&self, ctx: &Ctx, rule: &Rule) -> Result<bool> {
        Ok(!numbered_matches(&status_numbered(ctx)?, &rule.token).is_empty())
    }

    /// Delete every numbered rule carrying the token (IPv4 and IPv6 copies).
    /// An inactive ufw lists no rules although they persist in its
    /// configuration, so nothing can be confirmed removed: the rule stays
    /// recorded until ufw is active again.
    fn remove(&self, ctx: &Ctx, rule: &Rule) -> Result<()> {
        let status = status_numbered(ctx)?;
        if status.lines().any(|l| l.trim() == "Status: inactive") {
            return Err(Error::msg(
                "ufw 未启用，暂时无法删除其中的规则（启用 ufw 后会自动清理）",
            ));
        }
        for number in numbered_matches(&status, &rule.token) {
            ctx.check(&Cmd::new("ufw").args(["--force", "delete", &number.to_string()]))?;
        }
        Ok(())
    }
}
