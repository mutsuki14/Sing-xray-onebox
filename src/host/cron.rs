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
//! [`Scope`] with their positions and put each line back where it was, so a
//! rollback reinstalls the original crontab byte for byte; a journal line
//! is reinstalled only when it has the exact shape some Onebox version
//! writes (`shape.rs`); any other is only kept while it is still there.
//!
//! Every change goes through [`Crontab::edit`], which holds the crontab
//! lock (`RUN/crontab.lock`) from `crontab -l` to `crontab FILE`: node and
//! FRP operations run under different configuration locks and must not
//! drop each other's lines. It is the innermost lock (taken after the
//! node/FRP locks, never held while taking another).
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
//! - journal lines are validated against the exact shapes before they are
//!   reinstalled (E-8.1#17); retired renewal jobs are never reinstalled;
//!   neither is a journal line of no known shape (a job edited by hand) or
//!   one no longer owned, but such a line is kept while the crontab still
//!   has it instead of failing the whole restore (which made every later
//!   rollback of that transaction refuse);
//! - comment lines are never owned, even when they end with a marker (a
//!   job commented out to disable it); leading blanks, which cron ignores,
//!   are ignored when a line's shape is checked;
//! - concurrent edits are serialized by the crontab lock.

mod line;
mod scheduler;
mod shape;
#[cfg(test)]
pub(crate) mod testing;
mod transaction;

pub use crate::host::service::Scope;
pub use line::line;
pub use scheduler::{ensure_scheduler, ensure_scheduler_as, scheduler_active, NOT_RUNNING};
pub use transaction::{check_snapshot, restore, snapshot, CronSnapshot};

use crate::ctx::Ctx;
use crate::error::{Error, Result};
use crate::host::service::{prepare_dir, validate_name, FRPS, FRP_WEB};
use crate::paths::Paths;
use crate::sys::exec::{Cmd, Output};
use crate::sys::fs::{remove_file_if_exists, write_new_exclusive, TEMP_PREFIX};
use crate::sys::lock::FileLock;
use crate::sys::text::quote_shell;
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::time::Duration;

/// Suffix introducing the tag of a v3 line.
pub const MARKER: &str = " # onebox:";
const CRONTAB_TIMEOUT: Duration = Duration::from_secs(30);
const TAG_MAX: usize = 96;
/// How long an edit waits for a concurrent one.
const EDIT_LOCK_WAIT: Duration = Duration::from_secs(30);
const EDIT_BUSY: &str = "另一个操作正在修改 crontab；稍后重试";

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

impl Scope {
    /// Whether a line of `tag` belongs to this scope: FRP owns `frp-renew`,
    /// `frp-boot` and the autostart of its two services; the node owns the
    /// rest (renewal, autostart of its services, the v1 line).
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
        self.classify_form(line).map(|(tag, _)| tag)
    }

    /// The owning tag and the form (version) of an owned line.
    fn classify_form(&self, line: &str) -> Option<(Tag, Form)> {
        let trimmed = line.trim_end_matches([' ', '\t', '\r']);
        // A comment is no job, whatever it ends with: a job an administrator
        // disabled by commenting it out is theirs, never replaced, removed
        // or journaled as Onebox's.
        if trimmed.trim_start_matches([' ', '\t']).starts_with('#') {
            return None;
        }
        if let Some((_, tag)) = trimmed.rsplit_once(MARKER) {
            if let Ok(tag) = Tag::new(tag) {
                return Some((tag, Form::V3));
            }
        }
        if let Some((_, service)) = trimmed.rsplit_once("# onebox-rust:") {
            return Tag::boot(service.trim()).ok().map(|t| (t, Form::V2Boot));
        }
        for target in ["proxy", "site", "subscription"] {
            if trimmed.ends_with(&format!("# onebox-native-cert-{target}")) {
                return Some((Tag::renew(), Form::V2Cert(target)));
            }
        }
        for (marker, tag) in [
            ("# onebox-frps-renew", Tag::frp_renew()),
            ("# onebox-frps-boot", Tag::frp_boot()),
        ] {
            if trimmed.ends_with(marker) {
                return Some((tag, Form::V2Frp));
            }
        }
        if self.is_v1_boot(line) {
            return Some((Tag::legacy_boot(), Form::V1Boot));
        }
        self.is_retired_renew(trimmed)
            .then(|| (Tag::renew(), Form::Retired))
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

/// Which version wrote an owned line (decides its exact shape).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Form {
    V3,
    /// `# onebox-rust:{service}`.
    V2Boot,
    /// `# onebox-native-cert-{target}`.
    V2Cert(&'static str),
    /// `# onebox-frps-renew` / `# onebox-frps-boot`.
    V2Frp,
    /// The exact v1 `@reboot` line.
    V1Boot,
    /// Renewal jobs older versions installed without a marker.
    Retired,
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
    /// For queries; changes go through [`edit`](Crontab::edit).
    pub fn read(ctx: &Ctx) -> Result<Crontab> {
        let out = ctx.run(&Cmd::new("crontab").arg("-l").timeout(CRONTAB_TIMEOUT))?;
        Ok(Crontab::parse(&ctx.paths, &listing(&out)?))
    }

    /// Read the crontab, apply `change` and install the result when its
    /// text changed, all under the crontab lock (see the module docs).
    /// Nothing is installed when `change` fails.
    pub fn edit<T>(ctx: &Ctx, change: impl FnOnce(&mut Crontab) -> Result<T>) -> Result<T> {
        prepare_dir(&ctx.paths.run)?;
        let path = ctx.paths.run.join("crontab.lock");
        let _lock = FileLock::acquire_waiting(
            &path,
            EDIT_BUSY,
            EDIT_LOCK_WAIT,
            Duration::from_millis(100),
        )?;
        let mut tab = Crontab::read(ctx)?;
        let value = change(&mut tab)?;
        tab.save(ctx)?;
        Ok(value)
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
    /// must be a single line owned by exactly `tag` (build it with
    /// [`line()`]). Returns whether the crontab changed.
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
        self.splice_group(tag, fresh);
        Ok(self.text() != before)
    }

    /// Put `fresh` where the group of `tag` starts (or at the end).
    fn splice_group(&mut self, tag: &Tag, fresh: Vec<Line>) {
        let position = self
            .lines
            .iter()
            .position(|l| l.tag.as_ref() == Some(tag))
            .unwrap_or(self.lines.len());
        self.lines.retain(|l| l.tag.as_ref() != Some(tag));
        let position = position.min(self.lines.len());
        self.lines.splice(position..position, fresh);
    }

    /// Remove the group of `tag`; returns whether a line was removed.
    pub fn remove(&mut self, tag: &Tag) -> bool {
        let before = self.lines.len();
        self.lines.retain(|l| l.tag.as_ref() != Some(tag));
        self.lines.len() != before
    }

    /// Remove the lines of `scope` written in v3's own form
    /// (` # onebox:{tag}`) and keep those older versions wrote: run before a
    /// restored 2.x manager regenerates, which does not recognize v3 lines
    /// and would neither remove nor replace them. Returns whether a line
    /// was removed.
    pub fn remove_v3_lines(&mut self, scope: Scope) -> bool {
        let ownership = &self.ownership;
        let before = self.lines.len();
        self.lines.retain(|l| {
            !matches!(
                ownership.classify_form(&l.text),
                Some((tag, Form::V3)) if scope.covers(&tag)
            )
        });
        self.lines.len() != before
    }

    /// Remove every owned line of `scope` (uninstall).
    pub fn remove_scope(&mut self, scope: Scope) -> bool {
        let before = self.lines.len();
        self.lines
            .retain(|l| !l.tag.as_ref().is_some_and(|t| scope.covers(t)));
        self.lines.len() != before
    }

    /// Install this text as the crontab (`crontab FILE` with a private
    /// temp file in the run directory). Writers use [`edit`](Crontab::edit).
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

#[cfg(test)]
mod tests;
