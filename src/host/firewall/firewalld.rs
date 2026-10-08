//! firewalld ports, per zone, runtime and permanent configuration.
//!
//! firewalld rules carry no comment: the token lives only in the ledger, and
//! a port that already exists in a zone belongs to the administrator (it is
//! never recorded, so never removed).

use super::{failure, safe_word, Backend, Rule};
use crate::ctx::Ctx;
use crate::error::{Error, Result};
use crate::sys::exec::Cmd;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Firewalld {
    pub zone: String,
    pub permanent: bool,
}

impl Firewalld {
    /// The only place firewalld argv is built:
    /// `firewall-cmd --zone=Z --{action}-port=P[-E]/proto [--permanent]`.
    fn cmd(&self, action: &str, rule: &Rule) -> Cmd {
        let cmd = Cmd::new("firewall-cmd").args([
            format!("--zone={}", self.zone),
            format!("--{action}-port={}/{}", rule.span("-"), rule.proto.id()),
        ]);
        if self.permanent {
            cmd.arg("--permanent")
        } else {
            cmd
        }
    }
}

/// Zone names from `firewall-cmd --get-active-zones`: the first word of
/// every non-indented, non-empty line (`public (default)` → `public`).
pub(super) fn parse_active_zones(text: &str) -> Vec<String> {
    let mut zones: Vec<String> = Vec::new();
    for line in text.lines() {
        if line.starts_with(char::is_whitespace) {
            continue;
        }
        if let Some(zone) = line.split_whitespace().next() {
            if !zones.iter().any(|z| z == zone) {
                zones.push(zone.to_string());
            }
        }
    }
    zones
}

impl Backend for Firewalld {
    fn name(&self) -> &'static str {
        "firewalld"
    }

    fn program(&self) -> &'static str {
        "firewall-cmd"
    }

    /// Every active zone (default zone when none is active), each with a
    /// runtime and a permanent instance; only while firewalld is running.
    fn detect(ctx: &Ctx) -> Result<Vec<Self>> {
        if !ctx.has("firewall-cmd") {
            return Ok(Vec::new());
        }
        let state = ctx.run(&Cmd::new("firewall-cmd").arg("--state"))?;
        if !state.ok() || state.stdout.trim() != "running" {
            return Ok(Vec::new());
        }
        let active = ctx.check(&Cmd::new("firewall-cmd").arg("--get-active-zones"))?;
        let mut zones = parse_active_zones(&active);
        if zones.is_empty() {
            let default = ctx.check(&Cmd::new("firewall-cmd").arg("--get-default-zone"))?;
            zones.push(default.trim().to_string());
        }
        let mut found = Vec::new();
        for zone in zones {
            if !safe_word(&zone) {
                return Err(Error::msg("firewalld zone 无效"));
            }
            for permanent in [false, true] {
                found.push(Firewalld {
                    zone: zone.clone(),
                    permanent,
                });
            }
        }
        Ok(found)
    }

    fn create(&self, ctx: &Ctx, rule: &Rule) -> Result<bool> {
        let query = ctx.run(&self.cmd("query", rule))?;
        if query.ok() {
            return Ok(false);
        }
        if query.code != 1 {
            return Err(failure("firewalld 查询失败，未变更规则", &query));
        }
        ctx.check(&self.cmd("add", rule))?;
        Ok(true)
    }

    fn exists(&self, ctx: &Ctx, rule: &Rule) -> Result<bool> {
        let query = ctx.run(&self.cmd("query", rule))?;
        match query.code {
            0 => Ok(true),
            1 => Ok(false),
            _ => Err(failure("无法检查 firewalld 规则", &query)),
        }
    }

    fn remove(&self, ctx: &Ctx, rule: &Rule) -> Result<()> {
        let query = ctx.run(&self.cmd("query", rule))?;
        match query.code {
            1 => Ok(()),
            0 => ctx.check(&self.cmd("remove", rule)).map(drop),
            _ => Err(failure("无法检查已有 firewalld 规则", &query)),
        }
    }
}
