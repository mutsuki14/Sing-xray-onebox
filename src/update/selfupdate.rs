//! `update-script` / `update-check`: replace the manager with the channel's
//! release, crash-safely (spec G §2.9, §5.2).
//!
//! Flow: resolve the channel → release metadata and this CPU's asset →
//! print the version report → refuse a stable downgrade → (`update-check`
//! stops here) → update lock, node lock, `apply::recover_locked` → refuse
//! an installed node whose manager is missing, an unsupported installed or
//! target version → sweep orphaned work dirs → work dir
//! `dirname(EXE)/.onebox-update-<24hex>` →
//! download `new` (size and SHA-256 from the API digest or `SHA256SUMS`),
//! ELF check → identical bytes: done → probe `new version` (no downgrade,
//! stable: equals the tag) → copy `EXE` to `old`, snapshot the node into
//! `config/` → block INT/TERM/HUP → journal `prepared` → `replacing` →
//! `EXE` ← `new` → `replaced` → child `EXE regen` with the node lock on
//! fd 198 (output captured: shown in full on failure; on success its
//! stdout and warnings are repeated) → `committed` → remove the journal and
//! the work dir → `程序已更新到 {v}` and `Error::Exit { code: 0 }` (the
//! process must end: continuing in the old image would let the next
//! apply's self-install copy it back, G §5.2).
//!
//! A failure after the journal was written is handed to
//! `apply::recover_locked` (the child's node journal first, then the
//! program journal restores the old manager and the snapshot). The journal
//! format and its recovery live in `apply::program_journal`; this module
//! only writes it.
//!
//! Signals: from just before the work directory is created until the
//! outcome is known, INT/TERM/HUP only set the cancel flag (`SignalScope`;
//! a timed child such as curl gets them forwarded), and from just
//! before the journal is written until the swap's outcome (recovery
//! included) they are blocked as well. A signal never kills the updater
//! half way or before it reported what happened: before the journal it
//! cancels at the next safe point (the work directory is removed); later
//! the outcome stands, and a failure is reported as a cancellation (exit
//! 130) with the same message. Ctrl+C during the child `regen` reaches the
//! child (same process group, default dispositions), whose failure is
//! recovered.
//!
//! The subscription worker (G-8.1#8): the child `regen` is a full apply;
//! its publish stage restarts `onebox-subscription` when the worker's
//! executable identity changed (COMPLETENESS G13, owned by the
//! subscription module), which is what makes the worker run the new
//! manager after an update. This module relies on that and does not
//! restart it again.
//!
//! Changes from v2:
//! - the asset is verified by the API digest **or** the release's
//!   `SHA256SUMS` fetched directly from github.com (G-8.1#6, G26), through
//!   the shared `host::fetch` chain (its size/digest messages);
//! - updates to a 2.x manager, and from an installed 2.x manager, are
//!   refused before anything is downloaded (`program_journal::
//!   supported_target` / `supported_installed`: the two could never finish
//!   a v3 journal);
//! - an installed node without its manager, a symlinked or oversized
//!   manager, and an oversized asset are refused before the download;
//! - signals are blocked before the journal is written (v2 blocked them
//!   right after) and one that arrived meanwhile no longer kills the
//!   process when they are unblocked (it is reported as a cancellation);
//! - the child `regen` output is captured: shown in full when it fails;
//!   after a success its stdout is echoed (as v2 did) and its warning lines
//!   are repeated;
//! - a recovery that succeeded in a stale process reports success with
//!   exit code 75 instead of `恢复需要重试` (G-8.1#6);
//! - the work directory is kept (with `更新工作目录保留供恢复`) only while a
//!   journal still needs it; otherwise it is removed — it may hold a copy
//!   of the node's private keys (v2 kept it after early failures and
//!   announced it even after it was deleted, G-8.1#6); work directories of
//!   killed updates that no journal refers to are swept by the next update
//!   (and by [`super::sweep_orphans`] callers);
//! - `update-script` installs a missing curl (as every mutating download
//!   does); `update-check` never installs anything.

use super::channel::{self, Channel};
use super::release::{self, SelfRelease, CHECKSUMS};
use super::{exit_within, Updater, UPDATE_BUSY};
use crate::apply::program_journal::{
    self as journal, ProgramJournal, ProgramPhase, CONFIG_DIR, NEW_FILE, OLD_FILE,
    PROGRAM_MAX_BYTES, WORK_PREFIX,
};
use crate::apply::snapshot::{self, node_allowlist, node_targets};
use crate::error::{Context, Error, Result, EXIT_STALE_PROCESS};
use crate::host::fetch::{self, is_elf};
use crate::paths::Paths;
use crate::state::StateStore;
use crate::sys::exec::{Cmd, Output};
use crate::sys::fs::{copy_file, remove_tree_if_exists, sha256_file, sweep_stale};
use crate::sys::lock::{FileLock, BUSY_MESSAGE};
use crate::sys::signal::{self, BlockSignals, SignalScope};
use crate::ui::out;
use crate::{Ctx, REPOSITORY};
use std::fs;
use std::io::{ErrorKind, Read};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::time::Duration;

pub const CHECK_ONLY: &str = "仅检查，未下载或替换程序";
pub const ALREADY_CURRENT: &str = "已是当前发布的最新内容";
/// The message of the `Exit { code: 0 }` a completed update returns.
pub const DONE: &str = "程序更新已完成；请重新执行 onebox 以使用新版本";
pub const MANAGER_MISSING: &str = "已有配置但管理程序缺失，请先重新安装原程序再更新";
pub const NEWER_INSTALLED: &str = "已安装版本更高，拒绝降级";
pub const DOWNLOADED_OLDER: &str = "下载程序版本低于已安装版本，拒绝降级";
pub const TAG_MISMATCH: &str = "发布标签与程序版本不一致";
pub const NOT_ELF: &str = "发布文件不是 Linux ELF 程序";
pub const REGENERATING: &str = "正在由新版本重新生成配置（可能需要几分钟）…";
const VERSION_TIMEOUT: Duration = Duration::from_secs(15);

/// What the replacement learned about the host before downloading.
struct Preflight {
    /// A node configuration exists (`state.json` or a v1 `onebox.conf`).
    installed: bool,
    /// `EXE` exists (a regular file within the size cap).
    exe_present: bool,
    /// The installed manager's version (or this program's without `EXE`).
    version: String,
}

impl Updater<'_> {
    /// `update-script` (`check_only = false`) / `update-check` (`true`);
    /// see the module docs. Root is the caller's business.
    pub fn self_update(&self, explicit: Option<Channel>, check_only: bool) -> Result<()> {
        let paths = &self.ctx.paths;
        let channel = channel::for_run(explicit, check_only, || channel::load(paths), self.warn)?;
        if !check_only {
            // The replacement changes the host anyway: a missing curl is
            // installed (a check only reports that it is missing).
            fetch::ensure_curl(self.ctx)?;
        }
        let found = release::lookup(self.ctx, self.env, channel)?;
        let installed = installed_version(self.ctx)?;
        for line in release::report_lines(channel, &installed, &found.remote, &found.release.body) {
            out::data(&line)?;
        }
        if channel == Channel::Stable {
            release::refuse_older(&found.remote, &installed, NEWER_INSTALLED)?;
        }
        if check_only {
            return out::data(CHECK_ONLY);
        }
        self.replace(&found)
    }

    /// The mutation path, under the update and node locks.
    fn replace(&self, found: &SelfRelease) -> Result<()> {
        let paths = &self.ctx.paths;
        let _update = FileLock::acquire(&paths.update_lock(), UPDATE_BUSY)?;
        let lock = FileLock::acquire(&paths.lock(), BUSY_MESSAGE)?;
        self.engine.recover(self.ctx, &lock)?;
        let pre = preflight(self.ctx, found)?;
        sweep_unreferenced(paths);
        // Held until the outcome is reported: see the module docs.
        let signals = Interruptions::watch()?;
        let (name, work) = journal::create_work_dir(paths)?;
        let outcome = self.replace_in(found, &pre, &lock, &name, &work, &signals);
        settle_work_dir(paths, &name, &work, self.warn);
        signals.settle(outcome)
    }

    fn replace_in(
        &self,
        found: &SelfRelease,
        pre: &Preflight,
        lock: &FileLock,
        name: &str,
        work: &Path,
        signals: &Interruptions,
    ) -> Result<()> {
        let paths = &self.ctx.paths;
        let new = work.join(NEW_FILE);
        self.download(found, &new)?;
        signals.check()?;
        if pre.exe_present && sha256_file(&paths.executable)? == sha256_file(&new)? {
            return out::data(ALREADY_CURRENT);
        }
        set_mode(&new, 0o755)?;
        let version = probe_version(self.ctx, &new).context("无法识别下载程序的版本")?;
        check_new_version(found, &version, &pre.version)?;
        let mut record = record(paths, pre, name, work, &new)?;
        signals.check()?;
        // Blocked before the journal exists, so no signal can stop the
        // process between "journal written" and a consistent swap; the
        // child regen starts with an empty mask (sys::exec) and can still
        // be interrupted from the terminal. Dropped only after the outcome
        // (recovery included) is known; what arrived meanwhile then lands
        // in the cancel flag (`signals`), it does not kill the process.
        let _blocked = BlockSignals::new()?;
        journal::write(paths, &record)?;
        (self.on_phase)(ProgramPhase::Prepared);
        match self.swap(&mut record, &new, lock, pre.installed) {
            Ok(child) => {
                // Best effort: the update is complete whatever stdout does.
                if !child.stdout.is_empty() {
                    let _ = out::data(&child.stdout);
                }
                let _ = out::data(&format!("程序已更新到 {version}"));
                child.warnings.iter().for_each(|w| (self.warn)(w));
                Err(Error::exit(0, DONE))
            }
            Err(error) => {
                let recovery = if record.phase == ProgramPhase::Committed {
                    None
                } else {
                    Some(self.engine.recover(self.ctx, lock))
                };
                Err(failure(error, recovery, work))
            }
        }
    }

    /// Download and verify the asset into `dest`.
    fn download(&self, found: &SelfRelease, dest: &Path) -> Result<()> {
        let asset = &found.asset;
        ensure!(
            asset.size <= PROGRAM_MAX_BYTES,
            "发布文件超出自更新大小限制: {}",
            asset.name
        );
        out::info(format!("正在下载 {}…", asset.name));
        let sums = |name: &str| name == CHECKSUMS;
        fetch::download_asset_with(
            self.ctx,
            self.env,
            REPOSITORY,
            &found.release,
            asset,
            dest,
            &sums,
        )?;
        check_elf(dest)
    }

    /// Journal `replacing` → new `EXE` → `replaced` → child regen →
    /// `committed` → cleanup. `record.phase` is always the durable phase.
    /// Returns what the child said that is still worth showing.
    fn swap(
        &self,
        record: &mut ProgramJournal,
        new: &Path,
        lock: &FileLock,
        installed: bool,
    ) -> Result<ChildReport> {
        let paths = &self.ctx.paths;
        self.advance(record, ProgramPhase::Replacing)?;
        copy_file(new, &paths.executable, 0o755)?;
        self.advance(record, ProgramPhase::Replaced)?;
        let child = if installed {
            regenerate(self.ctx, lock)?
        } else {
            ChildReport::default()
        };
        self.advance(record, ProgramPhase::Committed)?;
        record.finish(paths)?;
        Ok(child)
    }

    fn advance(&self, record: &mut ProgramJournal, phase: ProgramPhase) -> Result<()> {
        record.set_phase(&self.ctx.paths, phase)?;
        (self.on_phase)(phase);
        Ok(())
    }
}

/// The checks that need the locks (and nothing downloaded yet).
fn preflight(ctx: &Ctx, found: &SelfRelease) -> Result<Preflight> {
    let exe_present = exe_present(&ctx.paths.executable)?;
    let installed = StateStore::installed(ctx);
    ensure!(!installed || exe_present, "{MANAGER_MISSING}");
    // Re-read under the lock: another update may have finished meanwhile.
    let version = installed_version(ctx)?;
    journal::supported_installed(&version)?;
    if found.channel == Channel::Stable {
        journal::supported_target(&found.remote)?;
    }
    Ok(Preflight {
        installed,
        exe_present,
        version,
    })
}

/// Whether `EXE` exists. It must then be a regular file (it is replaced by
/// rename and backed up byte for byte) within the journal's size cap.
fn exe_present(exe: &Path) -> Result<bool> {
    let meta = match fs::symlink_metadata(exe) {
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(Error::io(exe, e)),
        Ok(meta) => meta,
    };
    ensure!(
        !meta.file_type().is_symlink(),
        "{} 是符号链接，无法安全替换；请改为普通文件后重试",
        exe.display()
    );
    ensure!(meta.is_file(), "程序路径不是普通文件: {}", exe.display());
    ensure!(
        meta.len() <= PROGRAM_MAX_BYTES,
        "当前程序超出自更新大小限制"
    );
    Ok(true)
}

/// The installed manager's `version` (v2: `EXE version` when `EXE` is a
/// file, else this program's version).
pub fn installed_version(ctx: &Ctx) -> Result<String> {
    let exe = &ctx.paths.executable;
    if fs::metadata(exe).is_ok_and(|m| m.is_file()) {
        probe_version(ctx, exe).context("无法识别已安装程序的版本")
    } else {
        Ok(crate::VERSION.to_owned())
    }
}

fn probe_version(ctx: &Ctx, program: &Path) -> Result<String> {
    let cmd = Cmd::new(program.to_string_lossy())
        .arg("version")
        .timeout(VERSION_TIMEOUT);
    release::reported_version(&ctx.check(&cmd)?)
}

/// The probed version of the download: a 3.x manager, not older than the
/// installed one, and on stable exactly the release's tag.
fn check_new_version(found: &SelfRelease, new: &str, installed: &str) -> Result<()> {
    journal::supported_target(new)?;
    release::refuse_older(new, installed, DOWNLOADED_OLDER)?;
    if let Some(tagged) = found.version() {
        ensure!(release::parse(new)? == tagged, "{TAG_MISMATCH}");
    }
    Ok(())
}

/// ELF magic plus a minimal header (v2 rule and message).
fn check_elf(path: &Path) -> Result<()> {
    let mut head = Vec::with_capacity(20);
    fs::File::open(path)
        .and_then(|file| file.take(20).read_to_end(&mut head))
        .map_err(|e| Error::io(path, e))?;
    ensure!(is_elf(&head), "{NOT_ELF}");
    Ok(())
}

fn set_mode(path: &Path, mode: u32) -> Result<()> {
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).map_err(|e| Error::io(path, e))
}

/// The journal for this replacement (phase `prepared`, not yet written):
/// `old` is a copy of `EXE` when there is one, `config/` a snapshot of the
/// node when one is installed.
fn record(
    paths: &Paths,
    pre: &Preflight,
    name: &str,
    work: &Path,
    new: &Path,
) -> Result<ProgramJournal> {
    let old_sha256 = if pre.exe_present {
        let old = work.join(OLD_FILE);
        copy_file(&paths.executable, &old, 0o700)?;
        Some(sha256_file(&old)?)
    } else {
        None
    };
    let snapshot = if pre.installed {
        let taken = snapshot::take(
            &node_targets(paths),
            &work.join(CONFIG_DIR),
            &node_allowlist(paths),
        )
        .context("备份当前配置失败")?;
        Some(taken)
    } else {
        None
    };
    Ok(ProgramJournal::new(
        name.to_owned(),
        old_sha256,
        sha256_file(new)?,
        snapshot,
    ))
}

/// Run the new manager's `regen` with the node lock on fd 198 (its
/// recovery then leaves our journal alone, and it rolls back its own
/// configuration journal on failure). stdin is null; its output is shown
/// in full when it fails, else summarized by [`child_report`].
fn regenerate(ctx: &Ctx, lock: &FileLock) -> Result<ChildReport> {
    let exe = ctx
        .paths
        .executable
        .to_str()
        .ok_or_else(|| Error::msg("程序路径不是 UTF-8"))?;
    out::info(REGENERATING);
    let cmd = ctx
        .paths
        .service_env()
        .into_iter()
        .fold(Cmd::new(exe).arg("regen"), |cmd, (k, v)| cmd.env(k, v))
        .inherit_lock(lock.raw_fd());
    let output = ctx.run(&cmd).context("无法运行新版本程序")?;
    if output.ok() {
        return Ok(child_report(&output));
    }
    if let Some(text) = child_output(&output) {
        out::line(text);
    }
    bail!("新版本重新生成配置失败（退出码 {}）", output.code)
}

/// What a successful child `regen` printed that the user should still see.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ChildReport {
    /// Its stdout, trimmed (v2 echoed it).
    pub stdout: String,
    /// Its `[警告]` lines from stderr, without the tag (pin, migration or
    /// certificate notices); progress lines are dropped.
    pub warnings: Vec<String>,
}

/// Summarize a successful child's output.
pub fn child_report(output: &Output) -> ChildReport {
    ChildReport {
        stdout: output.stdout.trim().to_owned(),
        warnings: output.stderr.lines().filter_map(warning_text).collect(),
    }
}

/// The text of a `[警告] …` line (colors and control characters removed).
fn warning_text(line: &str) -> Option<String> {
    let plain = strip_sgr(line);
    let text = plain.trim_start().strip_prefix(out::Level::Warn.tag())?;
    let text: String = text.chars().filter(|c| !c.is_control()).collect();
    let text = text.trim();
    (!text.is_empty()).then(|| text.to_owned())
}

/// `line` without ANSI SGR sequences (`ESC [ … m`).
fn strip_sgr(line: &str) -> String {
    let mut plain = String::with_capacity(line.len());
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' && chars.peek() == Some(&'[') {
            for c in chars.by_ref() {
                if c == 'm' {
                    break;
                }
            }
        } else {
            plain.push(c);
        }
    }
    plain
}

/// The child's captured stdout and stderr, trimmed; `None` when silent.
pub fn child_output(output: &Output) -> Option<String> {
    let parts: Vec<&str> = [output.stdout.trim(), output.stderr.trim()]
        .into_iter()
        .filter(|part| !part.is_empty())
        .collect();
    (!parts.is_empty()).then(|| parts.join("\n"))
}

/// The error of a failed swap (G §5.2): `recovery` is `None` once the
/// update was committed (only the cleanup failed), else the result of
/// `apply::recover_locked`. A recovery that ended with exit code 75 —
/// even one wrapped in context — succeeded in a stale process.
pub fn failure(error: Error, recovery: Option<Result<()>>, work: &Path) -> Error {
    match recovery {
        None => Error::msg(format!(
            "程序更新已提交，但恢复记录清理失败: {error}；请执行 recover 完成清理"
        )),
        Some(Ok(())) => Error::msg(format!("更新失败，已恢复原程序: {error}")),
        // Recovered, but this process is not the restored manager.
        Some(Err(e)) if exit_within(&e) == Some(EXIT_STALE_PROCESS) => Error::exit(
            EXIT_STALE_PROCESS,
            format!("更新失败，已恢复原程序: {error}；请重新执行命令以使用恢复后的程序"),
        ),
        Some(Err(recovery)) => Error::msg(format!(
            "更新失败: {error}；恢复需要重试: {recovery}；备份: {}",
            work.display()
        )),
    }
}

/// Cancellation signals during a replacement (see the module docs): the
/// recording handlers are installed for as long as this lives, and the
/// receive counter tells whether a signal arrived since [`watch`].
///
/// [`watch`]: Interruptions::watch
struct Interruptions {
    start: signal::Received,
    _scope: SignalScope,
}

impl Interruptions {
    fn watch() -> Result<Interruptions> {
        let start = signal::received();
        let scope = SignalScope::install()?;
        Ok(Interruptions {
            start,
            _scope: scope,
        })
    }

    /// The signal received since [`watch`](Interruptions::watch), if any.
    fn received(&self) -> Option<i32> {
        let now = signal::received();
        (now.count != self.start.count && now.last != 0).then_some(now.last)
    }

    /// A safe point before the journal exists: cancel when a signal came.
    fn check(&self) -> Result<()> {
        match self.received() {
            None => Ok(()),
            Some(sig) => Err(Error::Cancelled.wrap(format!("操作被信号 {sig} 中断"))),
        }
    }

    /// The reported outcome once the replacement is over: a failure while
    /// a signal arrived is a cancellation (exit 130, same message); a
    /// completed update and exit codes (0 done, 75 stale process) stand.
    /// The signal is consumed.
    fn settle(self, outcome: Result<()>) -> Result<()> {
        if self.received().is_none() {
            return outcome;
        }
        signal::clear();
        match outcome {
            Err(e) if !e.is_cancelled() && exit_within(&e).is_none() => {
                Err(Error::Cancelled.wrap(e.to_string()))
            }
            other => other,
        }
    }
}

/// `更新工作目录保留供恢复: {dir}`.
pub fn retention_notice(work: &Path) -> String {
    format!("更新工作目录保留供恢复: {}", work.display())
}

/// Remove work directories of earlier updates that no journal refers to
/// (a process killed before its journal was written). The caller holds the
/// update lock and the node lock (not inherited) after recovery, so no
/// updater — v2 or v3, both hold both locks while their work directory
/// exists — is using one; while any journal (or an unreadable one) is
/// present nothing is touched. Best effort.
pub(super) fn sweep_unreferenced(paths: &Paths) {
    if !matches!(journal::load(paths), Ok(None)) {
        return;
    }
    if let Some(dir) = paths.executable.parent() {
        let _ = sweep_stale(dir, WORK_PREFIX, Duration::ZERO);
    }
}

/// Keep the work directory only while the journal refers to it (recovery
/// needs it; say where it is); otherwise remove it.
fn settle_work_dir(paths: &Paths, name: &str, work: &Path, warn: &dyn Fn(&str)) {
    let needed = match journal::load(paths) {
        Ok(Some(record)) => record.work == name,
        Ok(None) => false,
        // Unreadable: keep everything for a manual look.
        Err(_) => true,
    };
    if !needed {
        let _ = remove_tree_if_exists(work);
    } else if work.exists() {
        warn(&retention_notice(work));
    }
}

#[cfg(test)]
mod tests;
