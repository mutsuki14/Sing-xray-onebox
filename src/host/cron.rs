//! The only crontab editor: owned lines by marker, PATH-prefixed commands,
//! `%` escaping, v2/v1 marker migration.
//!
//! Onebox owns a crontab line when it ends with ` # onebox:{tag}` (v3), or
//! carries a marker of an older version, which maps to the v3 tag that
//! replaces it:
//!
//! | older line | tag |
//! |---|---|
//! | `… # onebox-native-cert-proxy\|site\|subscription` (v2, three lines) | `renew` |
//! | `…/tls/acme/acme.sh … --cron`, `…/site/acme/acme.sh … --cron`, `EXE … cert-renew T --cron` (retired forms v2 removed) | `renew` |
//! | `… # onebox-rust:{service}` (v2 no-init autostart) | `boot:{service}` |
//! | `… # onebox-frps-renew` / `… # onebox-frps-boot` (v2 FRP) | `frp-renew` / `frp-boot` |
//! | the exact v1 line `@reboot EXE net-apply >/dev/null 2>&1; EXE start >/dev/null 2>&1` | `legacy-boot` |
//!
//! A *group* is every line with one tag; [`Crontab::replace`] swaps a
//! group in place (at the position of its first line) and every other line
//! keeps its text and order. Transactions snapshot the owned lines of their
//! [`Scope`] and put them back group by group.
//!
//! Changes from v2:
//! - one reader with one rule for "no crontab yet" (v2 had four, E-8.1#9);
//! - lines keep their position: v2 appended re-installed lines at the end
//!   and reordered the crontab on rollback (B-9.1#23);
//! - jobs run with `PATH=/usr/local/sbin:…:/bin` and the service variables
//!   (F-8.1#1: Debian cron's `PATH=/usr/bin:/bin` hid nginx and the
//!   firewall tools) and log to a file instead of `/dev/null`;
//! - `%` is escaped in every generated line (E-8.1#8);
//! - markers are matched after trimming trailing blanks/CR everywhere
//!   (H-8.1#11) and the crontab always ends with a newline;
//! - journal lines are validated before they are reinstalled (E-8.1#17).

mod line;
mod scheduler;
#[cfg(test)]
pub(crate) mod testing;

pub use line::line;
pub use scheduler::{ensure_available, scheduler_running, NOT_RUNNING};

use crate::ctx::Ctx;
use crate::error::{Error, Result};
use crate::host::service::{validate_name, FRPS, FRP_WEB};
use crate::paths::Paths;
use crate::sys::exec::{Cmd, Output};
use crate::sys::fs::{remove_file_if_exists, write_new_exclusive, TEMP_PREFIX};
use crate::sys::text::quote_shell;
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::time::Duration;

/// Suffix introducing the tag of a v3 line.
pub const MARKER: &str = " # onebox:";
const CRONTAB_TIMEOUT: Duration = Duration::from_secs(30);
const TAG_MAX: usize = 96;

/// The ownership tag of a crontab line (`renew`, `boot:onebox-xray`, …).
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Tag(String);

impl Tag {
    /// A tag of `[A-Za-z0-9:._-]`, at most 96 characters.
    pub fn new(tag: &str) -> Result<Tag> {
        let ok = !tag.is_empty()
            && tag.len() <= TAG_MAX
            && tag
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b":._-".contains(&b));
        if ok {
            Ok(Tag(tag.to_owned()))
        } else {
            Err(Error::msg(format!("crontab 标记无效: {tag}")))
        }
    }

    /// Node certificate renewal (one line for proxy, site and subscription).
    pub fn renew() -> Tag {
        Tag("renew".into())
    }

    pub fn frp_renew() -> Tag {
        Tag("frp-renew".into())
    }

    pub fn frp_boot() -> Tag {
        Tag("frp-boot".into())
    }

    /// The v1 combined boot line (only ever removed or restored).
    pub fn legacy_boot() -> Tag {
        Tag("legacy-boot".into())
    }

    /// Autostart of `service` without an init system.
    pub fn boot(service: &str) -> Result<Tag> {
        validate_name(service)?;
        Tag::new(&format!("boot:{service}"))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for Tag {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Which owned lines an independent transaction covers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scope {
    /// The proxy node: renewal, autostart of its services, the v1 line.
    Node,
    /// The FRP server manager.
    Frp,
}

impl Scope {
    pub fn covers(self, tag: &Tag) -> bool {
        let frp = matches!(tag.as_str(), "frp-renew" | "frp-boot")
            || [FRPS, FRP_WEB]
                .iter()
                .any(|s| tag.as_str() == format!("boot:{s}"));
        frp == (self == Scope::Frp)
    }
}

/// What decides ownership besides markers: the executable path (v1 line,
/// retired `cert-renew` jobs) and the acme.sh copies whose own cron jobs
/// v2 retired.
#[derive(Clone, Debug)]
struct Ownership {
    exe: String,
    acme_scripts: [String; 2],
}

impl Ownership {
    fn of(paths: &Paths) -> Ownership {
        let script = |dir: &Path| dir.join("acme/acme.sh").to_string_lossy().into_owned();
        Ownership {
            exe: paths.executable.to_string_lossy().into_owned(),
            acme_scripts: [script(&paths.tls()), script(&paths.site())],
        }
    }

    /// The tag owning `line`, if Onebox owns it.
    fn classify(&self, line: &str) -> Option<Tag> {
        let trimmed = line.trim_end_matches([' ', '\t', '\r']);
        if let Some((_, tag)) = trimmed.rsplit_once(MARKER) {
            if let Ok(tag) = Tag::new(tag) {
                return Some(tag);
            }
        }
        if let Some((_, service)) = trimmed.rsplit_once("# onebox-rust:") {
            return Tag::boot(service.trim()).ok();
        }
        let v2_markers = [
            ("# onebox-native-cert-proxy", Tag::renew()),
            ("# onebox-native-cert-site", Tag::renew()),
            ("# onebox-native-cert-subscription", Tag::renew()),
            ("# onebox-frps-renew", Tag::frp_renew()),
            ("# onebox-frps-boot", Tag::frp_boot()),
        ];
        if let Some((_, tag)) = v2_markers.into_iter().find(|(m, _)| trimmed.ends_with(m)) {
            return Some(tag);
        }
        if self.is_v1_boot(line) {
            return Some(Tag::legacy_boot());
        }
        self.is_retired_renew(trimmed).then(Tag::renew)
    }

    /// The exact v1 boot line, with the executable bare (when it is a plain
    /// shell word) or single-quoted, each occurrence independently. Extra
    /// commands, comments or redirections make it foreign.
    fn is_v1_boot(&self, line: &str) -> bool {
        if self.exe.chars().any(char::is_control) || line.contains(['\n', '\0']) {
            return false;
        }
        let quoted = quote_shell(&self.exe);
        let mut forms = vec![quoted.as_str()];
        if self
            .exe
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"/._-+:,@%=".contains(&c))
        {
            forms.push(self.exe.as_str());
        }
        let line = line.trim_matches([' ', '\t', '\r']);
        forms.iter().any(|first| {
            forms.iter().any(|second| {
                line == format!(
                    "@reboot {first} net-apply >/dev/null 2>&1; {second} start >/dev/null 2>&1"
                )
            })
        })
    }

    /// Renewal jobs older versions installed without a marker.
    fn is_retired_renew(&self, line: &str) -> bool {
        let acme = self.acme_scripts.iter().any(|s| line.contains(s.as_str()))
            && line.split_whitespace().any(|w| w == "--cron");
        let v1 = line.contains(self.exe.as_str())
            && ["proxy", "site", "subscription"]
                .iter()
                .any(|t| line.contains(&format!("cert-renew {t} --cron")));
        acme || v1
    }
}

#[derive(Clone, Debug)]
struct Line {
    text: String,
    tag: Option<Tag>,
}

/// A parsed crontab. Foreign lines are kept byte for byte (a trailing CR
/// included); rendering always ends with a newline.
#[derive(Clone, Debug)]
pub struct Crontab {
    lines: Vec<Line>,
    ownership: Ownership,
    original: String,
}

impl Crontab {
    pub fn parse(paths: &Paths, text: &str) -> Crontab {
        let ownership = Ownership::of(paths);
        let lines = text
            .split_terminator('\n')
            .map(|l| Line {
                text: l.to_owned(),
                tag: ownership.classify(l),
            })
            .collect();
        Crontab {
            lines,
            ownership,
            original: text.to_owned(),
        }
    }

    /// The current user's crontab (`crontab -l`); none yet reads as empty.
    pub fn read(ctx: &Ctx) -> Result<Crontab> {
        let out = ctx.run(&Cmd::new("crontab").arg("-l").timeout(CRONTAB_TIMEOUT))?;
        Ok(Crontab::parse(&ctx.paths, &listing(&out)?))
    }

    /// The crontab text to install.
    pub fn text(&self) -> String {
        self.lines.iter().map(|l| format!("{}\n", l.text)).collect()
    }

    pub fn is_modified(&self) -> bool {
        self.text() != self.original
    }

    /// Owned lines with their tags, in order.
    pub fn owned(&self) -> impl Iterator<Item = (&Tag, &str)> {
        self.lines
            .iter()
            .filter_map(|l| Some((l.tag.as_ref()?, l.text.as_str())))
    }

    /// Owned lines whose tag starts with `tag_prefix` (`""` = all owned).
    pub fn lines_for(&self, tag_prefix: &str) -> Vec<&str> {
        self.owned()
            .filter(|(tag, _)| tag.as_str().starts_with(tag_prefix))
            .map(|(_, text)| text)
            .collect()
    }

    pub fn has(&self, tag: &Tag) -> bool {
        self.owned().any(|(t, _)| t == tag)
    }

    /// Make `new_lines` the whole group of `tag`, at the position of the
    /// group's first line (appended when the group is new). Each new line
    /// must be a single line owned by exactly `tag`. Returns whether the
    /// crontab changed.
    pub fn replace(&mut self, tag: &Tag, new_lines: &[String]) -> Result<bool> {
        let mut fresh = Vec::with_capacity(new_lines.len());
        for text in new_lines {
            let owner = self.ownership.classify(text);
            if text.contains(['\n', '\0']) || owner.as_ref() != Some(tag) {
                return Err(Error::msg(format!("crontab 行与托管标记 {tag} 不符")));
            }
            fresh.push(Line {
                text: text.clone(),
                tag: owner,
            });
        }
        let before = self.text();
        let position = self
            .lines
            .iter()
            .position(|l| l.tag.as_ref() == Some(tag))
            .unwrap_or(self.lines.len());
        self.lines.retain(|l| l.tag.as_ref() != Some(tag));
        let position = position.min(self.lines.len());
        self.lines.splice(position..position, fresh);
        Ok(self.text() != before)
    }

    /// Remove the group of `tag`; returns whether a line was removed.
    pub fn remove(&mut self, tag: &Tag) -> bool {
        let before = self.lines.len();
        self.lines.retain(|l| l.tag.as_ref() != Some(tag));
        self.lines.len() != before
    }

    /// Remove every owned line of `scope` (uninstall).
    pub fn remove_scope(&mut self, scope: Scope) -> bool {
        let before = self.lines.len();
        self.lines
            .retain(|l| !l.tag.as_ref().is_some_and(|t| scope.covers(t)));
        self.lines.len() != before
    }

    /// The owned lines of `scope`, for a transaction journal.
    pub fn snapshot(&self, scope: Scope) -> Vec<String> {
        self.owned()
            .filter(|(tag, _)| scope.covers(tag))
            .map(|(_, text)| text.to_owned())
            .collect()
    }

    /// Put the owned lines of `scope` back to `lines` (a [`snapshot`]):
    /// each group returns to its position, groups absent from the snapshot
    /// are removed, foreign lines are untouched. Lines that are not owned
    /// within `scope` are refused before anything changes.
    ///
    /// [`snapshot`]: Crontab::snapshot
    pub fn restore(&mut self, lines: &[String], scope: Scope) -> Result<()> {
        let mut groups: Vec<(Tag, Vec<String>)> = Vec::new();
        for text in lines {
            let tag = self
                .ownership
                .classify(text)
                .filter(|t| scope.covers(t) && !text.contains(['\n', '\0']))
                .ok_or_else(|| Error::msg("事务记录的 crontab 行不属于 Onebox，拒绝恢复"))?;
            match groups.iter_mut().find(|(t, _)| *t == tag) {
                Some((_, group)) => group.push(text.clone()),
                None => groups.push((tag, vec![text.clone()])),
            }
        }
        let stale: Vec<Tag> = self
            .owned()
            .map(|(t, _)| t.clone())
            .filter(|t| scope.covers(t) && !groups.iter().any(|(g, _)| g == t))
            .collect();
        for tag in &stale {
            self.remove(tag);
        }
        for (tag, group) in &groups {
            self.replace(tag, group)?;
        }
        Ok(())
    }

    /// Install this text as the crontab (`crontab FILE` with a private
    /// temp file in the run directory).
    pub fn install(&self, ctx: &Ctx) -> Result<()> {
        let run = &ctx.paths.run;
        crate::host::service::prepare_dir(run)?;
        let temp = run.join(format!(
            "{TEMP_PREFIX}crontab-{}",
            crate::sys::rand::hex(12)?
        ));
        write_new_exclusive(&temp, self.text().as_bytes(), 0o600)?;
        let cmd = Cmd::new("crontab")
            .arg(temp.to_string_lossy())
            .timeout(CRONTAB_TIMEOUT);
        let result = ctx.check(&cmd);
        let cleanup = remove_file_if_exists(&temp);
        result?;
        cleanup.map(|_| ())
    }

    /// [`install`](Crontab::install) when the text changed; returns whether
    /// it did.
    pub fn save(&self, ctx: &Ctx) -> Result<bool> {
        if !self.is_modified() {
            return Ok(false);
        }
        self.install(ctx)?;
        Ok(true)
    }
}

/// `crontab -l` output → text. Exit 1 with no output and a "no crontab"
/// message (cronie, vixie, BSD, busybox `can't open … No such file`) or no
/// message at all means "none yet"; any other failure is an error, so a
/// crontab that could not be read is never overwritten.
fn listing(out: &Output) -> Result<String> {
    if out.ok() {
        return Ok(out.stdout.clone());
    }
    let stderr = out.stderr.trim();
    let lower = stderr.to_lowercase();
    let absent = stderr.is_empty()
        || lower.contains("no crontab for")
        || lower.contains("no such file or directory");
    if out.code == 1 && out.stdout.trim().is_empty() && absent {
        return Ok(String::new());
    }
    Err(Error::msg(format!(
        "无法读取当前 crontab ({}): {stderr}",
        out.code
    )))
}

/// Whether a `crontab` program is available.
pub fn available(ctx: &Ctx) -> bool {
    ctx.has("crontab")
}

/// The owned lines of a transaction scope, with whether cron was available.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CronSnapshot {
    pub available: bool,
    pub lines: Vec<String>,
}

/// Snapshot the owned lines of `scope` (no `crontab` program: nothing).
pub fn snapshot(ctx: &Ctx, scope: Scope) -> Result<CronSnapshot> {
    if !available(ctx) {
        return Ok(CronSnapshot::default());
    }
    Ok(CronSnapshot {
        available: true,
        lines: Crontab::read(ctx)?.snapshot(scope),
    })
}

/// Restore a [`snapshot`]; foreign lines and other scopes are untouched.
pub fn restore(ctx: &Ctx, snapshot: &CronSnapshot, scope: Scope) -> Result<()> {
    if !available(ctx) {
        if snapshot.available && !snapshot.lines.is_empty() {
            return Err(Error::msg("恢复续期任务需要 crontab"));
        }
        return Ok(());
    }
    let mut tab = Crontab::read(ctx)?;
    tab.restore(&snapshot.lines, scope)?;
    tab.save(ctx).map(|_| ())
}

#[cfg(test)]
mod tests;
