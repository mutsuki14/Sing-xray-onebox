//! firewalld ports, per zone, runtime and permanent configuration.
//!
//! firewalld rules carry no comment: the token lives only in the ledger, and
//! a port that already exists in a zone belongs to the administrator (it is
//! never recorded, so never removed).
//!
//! firewalld ≥ 0.9 keeps non-overlapping entries: `--add-port` merges a
//! range into the entries it overlaps, `--query-port` matches a port inside
//! a larger entry, and `--remove-port` cuts a sub-range out of the entry
//! holding it. Older versions keep every added range as its own entry and
//! match exactly. Removal ([`Firewalld::release`]) therefore reads the
//! zone's entries (`--list-ports`) and works for both.

use super::{failure, safe_word, Backend, PortSpan, Proto, Rule};
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
    /// `firewall-cmd --zone=Z --{action}-port=P[-E]/proto [--permanent]`,
    /// or `--list-ports` without `span`.
    fn cmd(&self, action: &str, span: Option<PortSpan>) -> Cmd {
        let operation = match span {
            Some(span) => format!("--{action}-port={}/{}", span.text("-"), span.proto.id()),
            None => format!("--{action}-ports"),
        };
        let cmd = Cmd::new("firewall-cmd").args([format!("--zone={}", self.zone), operation]);
        if self.permanent {
            cmd.arg("--permanent")
        } else {
            cmd
        }
    }

    fn rule_cmd(&self, action: &str, rule: &Rule) -> Cmd {
        self.cmd(action, Some(rule.range()))
    }

    /// The zone's port entries of `proto` (`--list-ports`).
    fn entries(&self, ctx: &Ctx, proto: Proto) -> Result<Vec<PortSpan>> {
        let out = ctx.run(&self.cmd("list", None))?;
        if !out.ok() {
            return Err(failure("无法读取 firewalld 端口", &out));
        }
        Ok(parse_ports(&out.stdout)
            .into_iter()
            .filter(|e| e.proto == proto)
            .collect())
    }

    /// Take `rule`'s ports out of the zone while `others` (the spans other
    /// Onebox records hold here) stay open, and never cut into an entry an
    /// administrator range absorbed:
    /// - another record of exactly this span: nothing to do;
    /// - our span is an entry of its own: remove it; when it absorbed
    ///   another record's ports (merging firewalld) remove only the ports
    ///   no other record needs;
    /// - our span sits inside a larger entry (merged with other ranges):
    ///   remove the ports no other record needs, but only when every port
    ///   of that entry is Onebox's; otherwise leave the entry alone;
    /// - no entry holds it: it is gone.
    pub fn release(&self, ctx: &Ctx, rule: &Rule, others: &[PortSpan]) -> Result<()> {
        let span = rule.range();
        if others.contains(&span) {
            return Ok(());
        }
        let entries = self.entries(ctx, span.proto)?;
        let pieces = if entries.contains(&span) {
            let absorbed = others
                .iter()
                .any(|o| o.overlaps(&span) && !entries.contains(o));
            if !absorbed {
                return ctx.check(&self.rule_cmd("remove", rule)).map(drop);
            }
            span.uncovered(others)
        } else {
            let Some(entry) = entries.iter().find(|e| e.contains(&span)) else {
                return Ok(());
            };
            let mut onebox = others.to_vec();
            onebox.push(span);
            if !entry.uncovered(&onebox).is_empty() {
                return Ok(());
            }
            span.uncovered(others)
        };
        for piece in pieces {
            ctx.check(&self.cmd("remove", Some(piece)))?;
        }
        Ok(())
    }
}

/// `80/tcp 443/tcp 20000-40000/udp` (the `--list-ports` format); entries
/// that are not numeric ranges are ignored.
pub(super) fn parse_ports(text: &str) -> Vec<PortSpan> {
    text.split_whitespace()
        .filter_map(|word| {
            let (ports, proto) = word.split_once('/')?;
            let proto = match proto {
                "tcp" => Proto::Tcp,
                "udp" => Proto::Udp,
                _ => return None,
            };
            let (start, end) = ports.split_once('-').unwrap_or((ports, ports));
            let (start, end) = (start.parse().ok()?, end.parse().ok()?);
            (start <= end).then_some(PortSpan { start, end, proto })
        })
        .collect()
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
        let query = ctx.run(&self.rule_cmd("query", rule))?;
        if query.ok() {
            return Ok(false);
        }
        if query.code != 1 {
            return Err(failure("firewalld 查询失败，未变更规则", &query));
        }
        ctx.check(&self.rule_cmd("add", rule))?;
        Ok(true)
    }

    fn exists(&self, ctx: &Ctx, rule: &Rule) -> Result<bool> {
        let query = ctx.run(&self.rule_cmd("query", rule))?;
        match query.code {
            0 => Ok(true),
            1 => Ok(false),
            _ => Err(failure("无法检查 firewalld 规则", &query)),
        }
    }

    /// [`Firewalld::release`] with no other Onebox record.
    fn remove(&self, ctx: &Ctx, rule: &Rule) -> Result<()> {
        self.release(ctx, rule, &[])
    }
}
