//! Reconcile an owner's ledger with the ports it needs, and clear owners.
//!
//! Invariants:
//! - the ledger lock is held for the whole operation;
//! - a created rule is recorded immediately; if recording fails the rule is
//!   removed again, so the firewall never holds an unrecorded Onebox rule;
//! - existence is always queried from the live firewall, never assumed from
//!   the ledger;
//! - only ledger rules are ever removed, by their token: rules an
//!   administrator created are never touched (a recorded firewalld/ufw port
//!   that an administrator rule replaced is forgotten, not removed);
//! - a port that is one shared object (firewalld, ufw) stays open while
//!   another Onebox owner still records it (`siblings`);
//! - a rule whose backend program is gone counts as gone.

use super::ledger::{lock, LOCK_WAIT};
use super::siblings::Siblings;
use super::{
    detect, ledger_path, new_token, spans, validate_owner, Entry, Ledger, Location, PortSpan, Rule,
};
use crate::ctx::Ctx;
use crate::domain::protocol::Transport;
use crate::error::{Error, Result};
use crate::ui::out;
use std::collections::BTreeSet;
use std::path::Path;

/// What a reconcile changed. Failed removals were already printed as
/// warnings; their rules stay recorded and are retried next time.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Report {
    /// `"{location} {span}/{proto}"` of rules added (new or re-created).
    pub created: Vec<String>,
    pub removed: Vec<String>,
    pub failed: Vec<String>,
}

/// [`reconcile`] at the owner's v2 ledger location.
pub fn reconcile_owner(
    ctx: &Ctx,
    owner: &str,
    desired: &[(u16, u16, Transport)],
) -> Result<Report> {
    validate_owner(owner)?;
    reconcile(ctx, &ledger_path(&ctx.paths, owner), owner, desired)
}

/// Make the firewall allow exactly `desired` for `owner`: contiguous ports
/// are merged per protocol, missing rules are created on every detected
/// backend instance (a recorded rule that vanished is re-created with its
/// token), and every other recorded rule of the owner is removed.
pub fn reconcile(
    ctx: &Ctx,
    ledger: &Path,
    owner: &str,
    desired: &[(u16, u16, Transport)],
) -> Result<Report> {
    validate_owner(owner)?;
    let wanted = spans(desired)?;
    let _lock = lock(ledger, LOCK_WAIT)?;
    let mut run = Run {
        ctx,
        owner,
        ledger: Ledger::load(ledger, owner)?,
        siblings: Siblings::load(ctx, ledger),
        keep: BTreeSet::new(),
        report: Report::default(),
    };
    let locations = detect(ctx)?;
    for span in &wanted {
        for location in &locations {
            run.ensure(*span, location)?;
        }
    }
    run.prune()?;
    run.ledger.save()?;
    Ok(run.report)
}

/// State of one reconcile pass. `keep` holds the tokens of recorded rules
/// that match a wanted span at a detected location; everything else in the
/// ledger is stale.
struct Run<'a> {
    ctx: &'a Ctx,
    owner: &'a str,
    ledger: Ledger,
    siblings: Siblings,
    keep: BTreeSet<String>,
    report: Report,
}

impl Run<'_> {
    /// Make sure `span` is allowed at `location`, reusing a recorded rule.
    fn ensure(&mut self, span: PortSpan, location: &Location) -> Result<()> {
        let recorded = self.ledger.entries.iter().find(|e| {
            e.rule.range() == span && e.location == *location && !self.keep.contains(&e.rule.token)
        });
        match recorded.cloned() {
            Some(entry) => self.refresh(entry),
            None => self.add(span, location),
        }
    }

    /// A recorded rule: re-create it when it vanished.
    fn refresh(&mut self, entry: Entry) -> Result<()> {
        let backend = entry.location.backend();
        let token = entry.rule.token.clone();
        if backend.exists(self.ctx, &entry.rule)? {
            self.keep.insert(token);
        } else if backend.create(self.ctx, &entry.rule)? {
            self.keep.insert(token);
            self.report.created.push(describe(&entry));
        } else if self.shared(&entry) {
            self.keep.insert(token);
        } else {
            // An administrator rule now covers the port: it is theirs.
            self.ledger.remove_token(&token);
            self.ledger.save()?;
        }
        Ok(())
    }

    /// A span without a record at `location`: create and record it.
    fn add(&mut self, span: PortSpan, location: &Location) -> Result<()> {
        let entry = Entry {
            location: location.clone(),
            rule: Rule {
                owner: self.owner.to_string(),
                proto: span.proto,
                start: span.start,
                end: span.end,
                token: new_token(self.owner)?,
            },
        };
        if location.backend().create(self.ctx, &entry.rule)? {
            self.record(&entry)?;
            self.report.created.push(describe(&entry));
        } else if self.shared(&entry) {
            // Already open for another owner: record our interest only.
            self.ledger.entries.push(entry.clone());
            self.ledger.save()?;
        } else {
            return Ok(());
        }
        self.keep.insert(entry.rule.token);
        Ok(())
    }

    fn shared(&self, entry: &Entry) -> bool {
        self.siblings
            .holder(&entry.location, entry.rule.range())
            .is_some()
    }

    /// Append a freshly created rule and save at once; when saving fails the
    /// rule is taken out of the firewall again.
    fn record(&mut self, entry: &Entry) -> Result<()> {
        self.ledger.entries.push(entry.clone());
        let Err(error) = self.ledger.save() else {
            return Ok(());
        };
        self.ledger.entries.pop();
        match entry.location.backend().remove(self.ctx, &entry.rule) {
            Ok(()) => Err(error),
            Err(cleanup) => Err(Error::msg(format!(
                "台账保存失败: {error}；新规则清理失败: {cleanup}"
            ))),
        }
    }

    /// Remove every recorded rule not kept. A failure keeps the rule
    /// recorded (retried next time) and is reported as a warning: one
    /// unreachable backend must not block every later apply.
    fn prune(&mut self) -> Result<()> {
        let stale: Vec<Entry> = self
            .ledger
            .entries
            .iter()
            .filter(|e| !self.keep.contains(&e.rule.token))
            .cloned()
            .collect();
        for entry in stale {
            match remove_entry(self.ctx, &self.siblings, &entry) {
                Ok(()) => {
                    self.ledger.remove_token(&entry.rule.token);
                    self.ledger.save()?;
                    self.report.removed.push(describe(&entry));
                }
                Err(e) => {
                    let message = format!("{}: {e}", describe(&entry));
                    out::warn(format!(
                        "未能删除旧防火墙规则（已保留台账，下次应用时重试）: {message}"
                    ));
                    self.report.failed.push(message);
                }
            }
        }
        Ok(())
    }
}

/// Remove a recorded rule. A backend whose program disappeared took its
/// rules with it; a port another owner still records stays open.
fn remove_entry(ctx: &Ctx, siblings: &Siblings, entry: &Entry) -> Result<()> {
    let backend = entry.location.backend();
    if !ctx.has(backend.program()) {
        return Ok(());
    }
    match siblings.holder(&entry.location, entry.rule.range()) {
        Some(holder) => Siblings::hand_over(ctx, entry, holder),
        None => backend.remove(ctx, &entry.rule),
    }
}

fn describe(entry: &Entry) -> String {
    format!(
        "{} {}/{}",
        entry.location.describe(),
        entry.rule.span("-"),
        entry.rule.proto.id()
    )
}

/// [`clear`] at the owner's v2 ledger location.
pub fn clear_owner(ctx: &Ctx, owner: &str) -> Result<()> {
    validate_owner(owner)?;
    clear(ctx, &ledger_path(&ctx.paths, owner), owner)
}

/// Remove every rule recorded for `owner`. Removed rules leave the ledger
/// one by one; rules that could not be removed stay recorded and the error
/// lists them.
pub fn clear(ctx: &Ctx, ledger: &Path, owner: &str) -> Result<()> {
    validate_owner(owner)?;
    let _lock = lock(ledger, LOCK_WAIT)?;
    let mut ledger = Ledger::load(ledger, owner)?;
    let siblings = Siblings::load(ctx, ledger.path());
    let mut failed = Vec::new();
    for entry in ledger.entries.clone() {
        match remove_entry(ctx, &siblings, &entry) {
            Ok(()) => {
                ledger.remove_token(&entry.rule.token);
                ledger.save()?;
            }
            Err(e) => failed.push(e.to_string()),
        }
    }
    if failed.is_empty() {
        Ok(())
    } else {
        Err(Error::msg(format!(
            "部分规则未清理，已保留台账: {}",
            failed.join("; ")
        )))
    }
}

#[cfg(test)]
mod shared_tests;
#[cfg(test)]
mod tests;
