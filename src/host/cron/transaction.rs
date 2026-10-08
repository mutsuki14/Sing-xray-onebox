//! Transaction support: snapshots of the owned lines of a [`Scope`] with
//! their positions, and restoring them (see the parent module docs).

use super::{available, Crontab, Form, Line, Scope, Tag};
use crate::ctx::Ctx;
use crate::error::{Error, Result};
use serde::{Deserialize, Serialize};

pub(super) const NOT_OWNED: &str = "事务记录的 crontab 行不属于 Onebox，拒绝恢复";
pub(super) const UNKNOWN_SHAPE: &str = "事务记录的 crontab 行不是 Onebox 写入的格式，拒绝恢复";
pub(super) const BAD_ANCHORS: &str = "事务记录的 crontab 位置无效，拒绝恢复";

impl Crontab {
    /// The owned lines of `scope` with their positions, for a transaction
    /// journal.
    pub fn snapshot(&self, scope: Scope) -> CronSnapshot {
        let mut lines = Vec::new();
        let mut anchors = Vec::new();
        let mut others = 0;
        for line in &self.lines {
            if in_scope(line, scope) {
                lines.push(line.text.clone());
                anchors.push(others);
            } else {
                others += 1;
            }
        }
        CronSnapshot {
            available: true,
            lines,
            anchors: Some(anchors),
        }
    }

    /// Put the owned lines of `scope` back to a [`snapshot`]. With anchors
    /// (v3 journals) every line returns to its position among the lines
    /// outside the scope, so `restore(snapshot())` changes nothing and a
    /// rollback reinstalls the original text; without them (v2 journals)
    /// each group returns to the position of its current first line and a
    /// group that already has exactly these lines stays as it is. Groups
    /// absent from the snapshot are removed; lines outside the scope are
    /// untouched. Every line must be owned within `scope` and have a known
    /// shape (checked before anything changes); a retired renewal job (no
    /// exact shape) is kept only while the crontab still has it, never
    /// reinstalled.
    ///
    /// [`snapshot`]: Crontab::snapshot
    pub fn restore(&mut self, snapshot: &CronSnapshot, scope: Scope) -> Result<()> {
        let wanted = self.restorable(snapshot, scope)?;
        if snapshot.anchors.is_some() {
            self.restore_anchored(wanted, scope);
        } else {
            self.restore_groups(wanted.into_iter().map(|(_, l)| l).collect(), scope);
        }
        Ok(())
    }

    /// The snapshot's lines (with anchors, 0 without) after validation.
    fn restorable(&self, snapshot: &CronSnapshot, scope: Scope) -> Result<Vec<(usize, Line)>> {
        if let Some(anchors) = &snapshot.anchors {
            let ordered = anchors.windows(2).all(|w| w[0] <= w[1]);
            if anchors.len() != snapshot.lines.len() || !ordered {
                return Err(Error::msg(BAD_ANCHORS));
            }
        }
        let mut present: Vec<&str> = self
            .lines
            .iter()
            .filter(|l| in_scope(l, scope))
            .map(|l| l.text.as_str())
            .collect();
        let mut wanted = Vec::with_capacity(snapshot.lines.len());
        for (index, text) in snapshot.lines.iter().enumerate() {
            let (tag, form) = self
                .ownership
                .classify_form(text)
                .filter(|(t, _)| scope.covers(t) && !text.contains(['\n', '\0']))
                .ok_or_else(|| Error::msg(NOT_OWNED))?;
            if form == Form::Retired {
                match present.iter().position(|p| p == text) {
                    Some(at) => _ = present.remove(at),
                    None => continue,
                }
            } else if !self.ownership.restorable(text, &tag, form) {
                return Err(Error::msg(UNKNOWN_SHAPE));
            }
            let anchor = snapshot.anchors.as_ref().map_or(0, |a| a[index]);
            let line = Line {
                text: text.clone(),
                tag: Some(tag),
            };
            wanted.push((anchor, line));
        }
        Ok(wanted)
    }

    /// Line `i` of the snapshot goes before the `anchor`-th line outside
    /// the scope (after the last one when there are fewer).
    fn restore_anchored(&mut self, wanted: Vec<(usize, Line)>, scope: Scope) {
        let others: Vec<Line> = std::mem::take(&mut self.lines)
            .into_iter()
            .filter(|l| !in_scope(l, scope))
            .collect();
        let mut wanted = wanted.into_iter().peekable();
        for (index, other) in others.into_iter().enumerate() {
            while let Some((_, line)) = wanted.next_if(|(anchor, _)| *anchor <= index) {
                self.lines.push(line);
            }
            self.lines.push(other);
        }
        self.lines.extend(wanted.map(|(_, line)| line));
    }

    fn restore_groups(&mut self, wanted: Vec<Line>, scope: Scope) {
        let mut groups: Vec<(Tag, Vec<Line>)> = Vec::new();
        for line in wanted {
            let Some(tag) = line.tag.clone() else {
                continue;
            };
            match groups.iter_mut().find(|(t, _)| *t == tag) {
                Some((_, group)) => group.push(line),
                None => groups.push((tag, vec![line])),
            }
        }
        self.lines.retain(|l| {
            !l.tag
                .as_ref()
                .is_some_and(|t| scope.covers(t) && !groups.iter().any(|(g, _)| g == t))
        });
        for (tag, group) in groups {
            let current = self.lines.iter().filter(|l| l.tag.as_ref() == Some(&tag));
            let same = current
                .map(|l| l.text.as_str())
                .eq(group.iter().map(|l| l.text.as_str()));
            if !same {
                self.splice_group(&tag, group);
            }
        }
    }
}

/// Whether `line` is owned within `scope`.
fn in_scope(line: &Line, scope: Scope) -> bool {
    line.tag.as_ref().is_some_and(|t| scope.covers(t))
}

/// The owned lines of a transaction scope, with whether cron was available
/// (v2 journals: `cron_lines` + `cron_available`, no anchors).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CronSnapshot {
    pub available: bool,
    pub lines: Vec<String>,
    /// For each line, how many lines outside the scope preceded it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub anchors: Option<Vec<usize>>,
}

/// Snapshot the owned lines of `scope` (no `crontab` program: nothing).
pub fn snapshot(ctx: &Ctx, scope: Scope) -> Result<CronSnapshot> {
    if !available(ctx) {
        return Ok(CronSnapshot::default());
    }
    Ok(Crontab::read(ctx)?.snapshot(scope))
}

/// Restore a [`snapshot`]; foreign lines and other scopes are untouched.
pub fn restore(ctx: &Ctx, snapshot: &CronSnapshot, scope: Scope) -> Result<()> {
    if !available(ctx) {
        if snapshot.available && !snapshot.lines.is_empty() {
            return Err(Error::msg("恢复续期任务需要 crontab"));
        }
        return Ok(());
    }
    Crontab::edit(ctx, |tab| tab.restore(snapshot, scope))
}

#[cfg(test)]
mod tests;
