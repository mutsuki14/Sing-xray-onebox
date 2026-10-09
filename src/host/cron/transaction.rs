//! Transaction support: snapshots of the owned lines of a [`Scope`] with
//! their positions, and restoring them (see the parent module docs).

use super::{available, Crontab, Form, Line, Ownership, Scope, Tag};
use crate::ctx::Ctx;
use crate::error::{Error, Result};
use crate::paths::Paths;
use crate::ui::out;
use serde::{Deserialize, Serialize};

pub(super) const NOT_REINSTALLED: &str = "事务记录的 crontab 行已被手工修改或不是 Onebox 写入的格式，未重新安装；重新应用配置即可重建所需的定时任务";
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
    /// untouched. Only a line owned within `scope` with a shape some Onebox
    /// version writes is reinstalled. Any other is kept only while the
    /// crontab still has it: a retired renewal job (no exact shape), an
    /// owned line edited by hand, a line this version no longer owns (a
    /// comment). Such lines never fail the restore — a journal cannot
    /// smuggle a job in, and refusing would leave the transaction's every
    /// later rollback refused. Returns how many of them are gone (never
    /// reinstalled), retired jobs aside, for the caller's warning.
    ///
    /// [`snapshot`]: Crontab::snapshot
    pub fn restore(&mut self, snapshot: &CronSnapshot, scope: Scope) -> Result<usize> {
        let (wanted, dropped) = self.restorable(snapshot, scope)?;
        if snapshot.anchors.is_some() {
            self.restore_anchored(wanted, scope);
        } else {
            self.restore_groups(wanted.into_iter().map(|(_, l)| l).collect(), scope);
        }
        Ok(dropped)
    }

    /// The snapshot's lines to put back (with anchors, 0 without) after
    /// validation, and how many unrestorable lines are gone.
    fn restorable(
        &self,
        snapshot: &CronSnapshot,
        scope: Scope,
    ) -> Result<(Vec<(usize, Line)>, usize)> {
        let checked = check_lines(&self.ownership, snapshot, scope)?;
        let mut present: Vec<&str> = self
            .lines
            .iter()
            .filter(|l| in_scope(l, scope))
            .map(|l| l.text.as_str())
            .collect();
        let mut wanted = Vec::with_capacity(snapshot.lines.len());
        let mut dropped = 0;
        for (index, (text, kind)) in snapshot.lines.iter().zip(checked).enumerate() {
            let tag = match kind {
                Restorable::Exact(tag) => tag,
                Restorable::WhilePresent(tag, form) => {
                    match present.iter().position(|p| p == text) {
                        Some(at) => _ = present.remove(at),
                        None => {
                            dropped += usize::from(form != Form::Retired);
                            continue;
                        }
                    }
                    tag
                }
                Restorable::Foreign => {
                    // Left to the crontab, which keeps it if it has it.
                    dropped += usize::from(!self.lines.iter().any(|l| l.text == *text));
                    continue;
                }
            };
            let anchor = snapshot.anchors.as_ref().map_or(0, |a| a[index]);
            let line = Line {
                text: text.clone(),
                tag: Some(tag),
            };
            wanted.push((anchor, line));
        }
        Ok((wanted, dropped))
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

/// Everything [`Crontab::restore`] requires of `snapshot` that does not
/// depend on the current crontab: well-formed anchors. Lines are not
/// refused — one that cannot be reinstalled is only kept while the crontab
/// has it. Pure, so a journal can be checked before a rollback changes
/// anything.
pub fn check_snapshot(paths: &Paths, snapshot: &CronSnapshot, scope: Scope) -> Result<()> {
    check_lines(&Ownership::of(paths), snapshot, scope).map(drop)
}

/// How a journal line is restored.
#[derive(Debug, PartialEq, Eq)]
enum Restorable {
    /// Owned within the scope, with a shape some Onebox version writes:
    /// reinstalled at its position.
    Exact(Tag),
    /// Owned within the scope without such a shape (a retired renewal job,
    /// a line edited by hand): kept only while the crontab still has it.
    WhilePresent(Tag, Form),
    /// Not (or no longer) owned within the scope — a comment, a line of
    /// another scope, several lines: left to the crontab.
    Foreign,
}

/// [`check_snapshot`], returning how each line is restored.
fn check_lines(
    ownership: &Ownership,
    snapshot: &CronSnapshot,
    scope: Scope,
) -> Result<Vec<Restorable>> {
    if let Some(anchors) = &snapshot.anchors {
        let ordered = anchors.windows(2).all(|w| w[0] <= w[1]);
        if anchors.len() != snapshot.lines.len() || !ordered {
            return Err(Error::msg(BAD_ANCHORS));
        }
    }
    let kinds = snapshot.lines.iter().map(|text| {
        let owned = ownership
            .classify_form(text)
            .filter(|(t, _)| scope.covers(t) && !text.contains(['\n', '\0']));
        match owned {
            None => Restorable::Foreign,
            Some((tag, form)) if ownership.restorable(text, &tag, form) => Restorable::Exact(tag),
            Some((tag, form)) => Restorable::WhilePresent(tag, form),
        }
    });
    Ok(kinds.collect())
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
/// Journal lines that could not be reinstalled are reported as a warning.
pub fn restore(ctx: &Ctx, snapshot: &CronSnapshot, scope: Scope) -> Result<()> {
    if !available(ctx) {
        if snapshot.available && !snapshot.lines.is_empty() {
            return Err(Error::msg("恢复续期任务需要 crontab"));
        }
        return Ok(());
    }
    let dropped = Crontab::edit(ctx, |tab| tab.restore(snapshot, scope))?;
    if dropped > 0 {
        out::warn(format!("{NOT_REINSTALLED}（{dropped} 行）"));
    }
    Ok(())
}

#[cfg(test)]
mod tests;
