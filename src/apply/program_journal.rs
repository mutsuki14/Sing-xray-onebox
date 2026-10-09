//! The self-update journal `ROOT/.self-update.json` and the recovery of an
//! interrupted manager replacement (spec G §3.8, §5.2).
//!
//! The updater (`update`) writes the journal through [`write()`] /
//! [`ProgramJournal::set_phase`]; every node recovery calls
//! [`recover_program_locked`] after the configuration journal has been
//! handled (the child's configuration snapshot may contain the new manager,
//! so the order matters).
//!
//! Format (v2 field names, unknown fields refused, pretty JSON, 0600):
//! `{"version","work","phase","old_existed","old_sha256","new_sha256","snapshot"}`
//! where `work` is `.onebox-update-<24 hex>` under the executable's
//! directory, holding `old` (the previous manager) and `config/` (a
//! [`Snapshot`] of the node, present iff a node was installed).
//!
//! Recovery (G §5.2): verify the lock; nothing to do under a lock inherited
//! from the updating parent; refuse while a node journal is pending;
//! validate everything before changing anything; `committed` only cleans
//! up; otherwise mark `recovering`, stop the node services, clear the hops
//! and the proxy firewall rules (any rule left behind stops the recovery
//! there, so the pre-update ledgers are never restored over a live rule),
//! put the old manager back, restore the configuration snapshot (and, for
//! a 2.x manager, drop the node's v3 crontab lines), let the restored
//! manager `regen` under our lock, remove the journal, and report exit
//! code 75 when this process is not the restored binary.
//!
//! Changes from v2:
//! - v3 writes `version: 2` (same fields): version-1 journals were written
//!   by v2 and their snapshots are validated against v2's fixed allowlist,
//!   version-2 snapshots against their recorded targets (owned-root
//!   patterns), so a v3.x journal survives allowlist changes in v3.y. v2
//!   refuses a version-2 journal without touching anything (it would also
//!   have refused its snapshot, which has v3-only targets);
//! - a child holding the parent's inherited lock does not read the journal
//!   at all (v2 validated it first, so any validation difference between the
//!   versions would have failed the upgrade);
//! - a snapshot without an old manager is refused before anything changes
//!   (v2 restored the snapshot first, then failed);
//! - every hop and proxy rule is attempted before a leftover stops the
//!   recovery (v2 stopped at the first hop it could not remove);
//! - before a restored 2.x manager regenerates (version-1 journals), the
//!   node's v3-form crontab lines are removed (2.x would keep a `renew` job
//!   it has no command for and duplicate autostarts);
//! - files are hashed while streaming (v2 read up to 128 MiB into memory);
//! - the restored manager's `regen` output streams to the terminal and the
//!   completion notice goes to stderr;
//! - an unreadable running image counts as "not the restored binary" (exit
//!   75) instead of failing the finished recovery.

use crate::apply::snapshot::{self, node_allowlist, v2_node_allowlist, Allowlist, Snapshot};
use crate::ctx::Ctx;
use crate::error::{Context, Error, Result};
use crate::host::cron::{self, Crontab, Scope};
use crate::host::service::{self as svc, Services};
use crate::host::{firewall, hop};
use crate::paths::Paths;
use crate::sys::exec::Cmd;
use crate::sys::fs::{
    atomic_write, check_owned, copy_file, ensure_dir, fsync_dir, read_bounded,
    remove_file_if_exists, remove_tree_if_exists, sha256_file,
};
use crate::sys::lock::FileLock;
use crate::sys::rand::to_hex;
use crate::ui::out;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::{ErrorKind, Read};
use std::path::{Path, PathBuf};

/// Largest journal accepted (v2).
pub const JOURNAL_MAX_BYTES: u64 = 8 * 1024 * 1024;
/// Largest manager binary accepted for `old` and the current executable.
pub const PROGRAM_MAX_BYTES: u64 = 128 * 1024 * 1024;
/// Name prefix of the work directory next to the executable.
pub const WORK_PREFIX: &str = ".onebox-update-";
/// Version written by v2.
pub const V2_VERSION: u8 = 1;
/// Version written by v3.
pub const VERSION: u8 = 2;
/// The previous manager inside the work directory.
pub const OLD_FILE: &str = "old";
/// The downloaded manager inside the work directory (updater only).
pub const NEW_FILE: &str = "new";
/// The configuration snapshot inside the work directory.
pub const CONFIG_DIR: &str = "config";
pub const RECOVERED: &str = "已恢复中断前的管理程序与配置";
pub const STALE_PROCESS: &str =
    "自更新恢复已完成；当前进程仍是被替换版本，请重新执行命令以使用恢复后的程序";
const INVALID: &str = "自更新恢复记录无效";
/// Recovery stopped because owned network rules could not be removed (v2).
pub const RULES_LEFT: &str = "部分规则未清理，已保留台账";
/// Refusal while a node journal is pending (v2 wording; shared with
/// `apply::journal`).
pub const PENDING_MESSAGE: &str = "存在未完成事务，请先 recover";
/// The running process image (follows the kernel's magic link, so it is the
/// mapped binary even after the file was replaced).
const RUNNING_IMAGE: &str = "/proc/self/exe";
/// v2 stop order during recovery (`onebox-network` is never stopped: it
/// may be the boot oneshot running this recovery).
const STOP_ORDER: [&str; 5] = [
    svc::SING_BOX,
    svc::XRAY,
    svc::SUBSCRIPTION_WEB,
    svc::SITE,
    svc::SUBSCRIPTION,
];

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProgramPhase {
    /// Journal written, executable not touched yet.
    Prepared,
    /// The new executable is being moved into place.
    Replacing,
    /// The new executable is in place; the child `regen` may run.
    Replaced,
    /// Done; only cleanup remains.
    Committed,
    /// A recovery started (re-running it is safe).
    Recovering,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProgramJournal {
    pub version: u8,
    /// `.onebox-update-<24 hex>`, relative to the executable's directory.
    pub work: String,
    pub phase: ProgramPhase,
    /// Whether the executable existed before the replacement.
    pub old_existed: bool,
    /// SHA-256 of `work/old`; empty iff `!old_existed`.
    pub old_sha256: String,
    pub new_sha256: String,
    /// The node snapshot in `work/config`, `None` when nothing was installed.
    pub snapshot: Option<Snapshot>,
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit())
}

/// v2's `semver`: leading `v`s stripped, everything from the first `-`
/// dropped (`3.0.1-rc1` is `3.0.1`), exactly three numeric fields.
pub fn semver(version: &str) -> Result<(u64, u64, u64)> {
    let main = version
        .trim_start_matches('v')
        .split('-')
        .next()
        .unwrap_or("");
    let fields: Option<Vec<u64>> = main.split('.').map(|f| f.parse().ok()).collect();
    match fields.as_deref() {
        Some(&[major, minor, patch]) => Ok((major, minor, patch)),
        _ => bail!("版本需要 major.minor.patch"),
    }
}

/// Refuse to self-update to `version` (the downloaded manager's `version`
/// output) unless it is 3.x or newer. A 2.x child `regen` validates the
/// journal before it looks at the inherited lock and refuses version 2, so
/// such an update could only fail and be rolled back. The updater calls
/// this before anything is downloaded (with the release tag) and again with
/// the probed version, before anything is replaced.
pub fn supported_target(version: &str) -> Result<()> {
    let (major, ..) = semver(version)?;
    ensure!(
        major >= 3,
        "不支持自更新到 {version}：2.x 及更早版本无法处理 3.x 的自更新恢复记录"
    );
    Ok(())
}

/// Refuse to record `version` (the installed manager's `version` output)
/// as the `old` manager unless it is 3.x or newer: recovery runs the
/// restored manager's `regen` while the journal exists, and a 2.x manager
/// refuses version 2, so the recovery could never finish. A 2.x manager
/// updates itself (its own journal is version 1).
pub fn supported_installed(version: &str) -> Result<()> {
    let (major, ..) = semver(version)?;
    ensure!(
        major >= 3,
        "已安装的管理程序为 {version}，请先执行 onebox update-script 由它升级到 3.x"
    );
    Ok(())
}

impl ProgramJournal {
    /// A v3 journal in phase `prepared`.
    ///
    /// Both managers must be 3.x or newer (the updater checks with
    /// [`supported_installed`] and [`supported_target`]): recovery runs the
    /// restored `old` manager's `regen` while this journal still exists, and
    /// the update itself runs the `new` manager's `regen` under the
    /// inherited lock; a 2.x manager validates the journal first in both
    /// cases and refuses version 2 (and v3-only snapshot targets), so the
    /// update would always fail and its recovery could never finish.
    pub fn new(
        work: String,
        old_sha256: Option<String>,
        new_sha256: String,
        snapshot: Option<Snapshot>,
    ) -> ProgramJournal {
        ProgramJournal {
            version: VERSION,
            work,
            phase: ProgramPhase::Prepared,
            old_existed: old_sha256.is_some(),
            old_sha256: old_sha256.unwrap_or_default(),
            new_sha256,
            snapshot,
        }
    }

    /// `dirname(EXE)/work`, after checking the name and that the directory
    /// is not a symlink.
    pub fn work_dir(&self, paths: &Paths) -> Result<PathBuf> {
        let token = self
            .work
            .strip_prefix(WORK_PREFIX)
            .ok_or_else(|| Error::msg("更新工作目录前缀无效"))?;
        ensure!(
            token.len() == 24 && token.bytes().all(|b| b.is_ascii_hexdigit()),
            "更新工作目录无效"
        );
        let parent = exe_dir(paths)?;
        let dir = parent.join(&self.work);
        check_owned(parent, &dir)?;
        Ok(dir)
    }

    /// The allowlist the snapshot is validated against: v2's for journals
    /// v2 wrote, the owned-root patterns for v3's.
    pub fn allowlist(&self, paths: &Paths) -> Allowlist {
        if self.version == V2_VERSION {
            v2_node_allowlist(paths)
        } else {
            node_allowlist(paths)
        }
    }

    /// Everything recovery relies on, checked before it changes anything
    /// (G §5.2 step 2). Returns the work directory.
    pub fn validate(&self, paths: &Paths) -> Result<PathBuf> {
        let digests_ok = valid_digest(&self.new_sha256)
            && if self.old_existed {
                valid_digest(&self.old_sha256)
            } else {
                self.old_sha256.is_empty()
            };
        ensure!(
            matches!(self.version, V2_VERSION | VERSION) && digests_ok,
            "{INVALID}"
        );
        let work = self.work_dir(paths)?;
        if self.old_existed {
            self.check_old(&work)?;
        }
        if let Some(snapshot) = &self.snapshot {
            ensure!(self.old_existed, "已安装配置缺少可恢复的旧管理程序");
            snapshot::validate(snapshot, &work.join(CONFIG_DIR), &self.allowlist(paths))?;
        }
        self.check_current(paths)?;
        Ok(work)
    }

    fn check_old(&self, work: &Path) -> Result<()> {
        let old = work.join(OLD_FILE);
        check_owned(work, &old)?;
        let size = fs::symlink_metadata(&old)
            .map_err(|e| Error::io(&old, e))?
            .len();
        let matches =
            size <= PROGRAM_MAX_BYTES && sha256_file(&old)?.eq_ignore_ascii_case(&self.old_sha256);
        ensure!(matches, "自更新旧程序备份 SHA256 不匹配，未更改当前程序");
        Ok(())
    }

    /// The executable, when present, is the old or the new manager.
    fn check_current(&self, paths: &Paths) -> Result<()> {
        let exe = &paths.executable;
        check_owned(exe_dir(paths)?, exe)?;
        let meta = match fs::symlink_metadata(exe) {
            Ok(meta) => meta,
            Err(e) if e.kind() == ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(Error::io(exe, e)),
        };
        ensure!(
            meta.len() <= PROGRAM_MAX_BYTES,
            "当前程序超出自更新大小限制"
        );
        let hash = sha256_file(exe)?;
        let known = hash.eq_ignore_ascii_case(&self.new_sha256)
            || (self.old_existed && hash.eq_ignore_ascii_case(&self.old_sha256));
        ensure!(
            known,
            "当前程序已被其他操作替换，拒绝覆盖；请检查自更新记录"
        );
        Ok(())
    }

    /// Durably move to `phase` (the in-memory phase changes only after the
    /// journal was written).
    pub fn set_phase(&mut self, paths: &Paths, phase: ProgramPhase) -> Result<()> {
        let next = ProgramJournal {
            phase,
            ..self.clone()
        };
        write(paths, &next)?;
        *self = next;
        Ok(())
    }

    /// Remove the journal (durably), then the work directory; a failure to
    /// remove the latter is only a warning.
    pub fn finish(&self, paths: &Paths) -> Result<()> {
        let work = self.work_dir(paths)?;
        remove_file_if_exists(&journal_path(paths))?;
        fsync_dir(&paths.root).map_err(|e| Error::io(&paths.root, e))?;
        if let Err(e) = remove_tree_if_exists(&work) {
            out::warn(format!(
                "自更新已完成，临时文件清理失败 {}: {e}",
                work.display()
            ));
        }
        Ok(())
    }
}

fn exe_dir(paths: &Paths) -> Result<&Path> {
    paths
        .executable
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .ok_or_else(|| Error::msg("程序没有父目录"))
}

/// `ROOT/.self-update.json`.
pub fn journal_path(paths: &Paths) -> PathBuf {
    paths.self_update_journal()
}

/// The journal, `None` when there is none. Oversized, unreadable or
/// malformed journals are errors (never "no journal").
pub fn load(paths: &Paths) -> Result<Option<ProgramJournal>> {
    let path = journal_path(paths);
    let meta = match fs::symlink_metadata(&path) {
        Ok(meta) => meta,
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(Error::io(&path, e)),
    };
    ensure!(meta.len() <= JOURNAL_MAX_BYTES, "自更新恢复记录异常大");
    let bytes = read_bounded(&path, JOURNAL_MAX_BYTES)?;
    let journal = serde_json::from_slice(&bytes).context(INVALID)?;
    Ok(Some(journal))
}

/// Atomically write the journal (pretty JSON, 0600).
pub fn write(paths: &Paths, journal: &ProgramJournal) -> Result<()> {
    let json = serde_json::to_vec_pretty(journal)?;
    atomic_write(&journal_path(paths), &json, 0o600)
}

/// Create a fresh work directory `dirname(EXE)/.onebox-update-<24 hex>`
/// (0700, its directory entry made durable) for the updater; returns the
/// name to record in the journal and the path.
pub fn create_work_dir(paths: &Paths) -> Result<(String, PathBuf)> {
    let parent = exe_dir(paths)?;
    let name = format!("{WORK_PREFIX}{}", crate::sys::rand::hex(12)?);
    let dir = parent.join(&name);
    ensure!(!dir.exists(), "更新工作目录已存在: {}", dir.display());
    ensure_dir(&dir, 0o700)?;
    fsync_dir(parent).map_err(|e| Error::io(parent, e))?;
    Ok((name, dir))
}

/// Recover an interrupted self-update (G §5.2). The caller holds the node
/// lock and has already recovered the configuration journal: a pending
/// `ROOT/.transaction` is refused with [`PENDING_MESSAGE`] before anything
/// changes. May return `Error::Exit { code: 75 }` after a successful
/// recovery when this process is not the restored manager.
pub fn recover_program_locked(ctx: &Ctx, lock: &FileLock) -> Result<()> {
    recover_with(ctx, lock, Path::new(RUNNING_IMAGE))
}

/// [`recover_program_locked`] with the running image to compare (tests).
fn recover_with(ctx: &Ctx, lock: &FileLock, running_image: &Path) -> Result<()> {
    lock.verify(&ctx.paths.lock())?;
    if lock.is_inherited() {
        // The updating parent owns the journal and recovers it itself.
        return Ok(());
    }
    let Some(mut journal) = load(&ctx.paths)? else {
        return Ok(());
    };
    // The node journal must be rolled back first: the child's snapshot may
    // hold the new manager, so a later rollback would put it back over the
    // restored one and the program journal would be gone.
    match fs::symlink_metadata(ctx.paths.transaction()) {
        Err(e) if e.kind() == ErrorKind::NotFound => {}
        _ => bail!("{PENDING_MESSAGE}"),
    }
    let work = journal.validate(&ctx.paths)?;
    if journal.phase == ProgramPhase::Committed {
        let exe = &ctx.paths.executable;
        let committed =
            is_regular(exe) && sha256_file(exe)?.eq_ignore_ascii_case(&journal.new_sha256);
        ensure!(committed, "已提交的自更新程序不匹配，保留恢复记录");
        return journal.finish(&ctx.paths);
    }
    journal.set_phase(&ctx.paths, ProgramPhase::Recovering)?;
    if journal.snapshot.is_some() {
        stop_services(ctx)?;
        clear_network(ctx)?;
    }
    restore_program(&ctx.paths, &journal, &work)?;
    if let Some(snapshot) = &journal.snapshot {
        let allow = journal.allowlist(&ctx.paths);
        snapshot::restore(snapshot, &work.join(CONFIG_DIR), &allow)?;
        if journal.version == V2_VERSION {
            retire_v3_cron(ctx)?;
        }
        regenerate(ctx, lock)?;
    }
    journal.finish(&ctx.paths)?;
    out::ok(RECOVERED);
    if journal.old_existed && !image_matches(running_image, &journal.old_sha256) {
        return Err(Error::exit(crate::error::EXIT_STALE_PROCESS, STALE_PROCESS));
    }
    Ok(())
}

fn is_regular(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok_and(|m| m.is_file())
}

fn stop_services(ctx: &Ctx) -> Result<()> {
    let services = Services::detect(ctx);
    for name in STOP_ORDER {
        if services.exists(name) {
            services.stop(name)?;
        }
    }
    Ok(())
}

/// The hop redirects, then the proxy firewall rules (v2 `clear_rules`:
/// both attempted, in this order). Any rule left behind fails the recovery
/// before anything is restored: restoring the snapshot would put back the
/// pre-update ledgers and orphan the rule (an open port or a UDP redirect
/// no later clear could find), so the journal stays `recovering` for a
/// retry.
fn clear_network(ctx: &Ctx) -> Result<()> {
    let mut failed = Vec::new();
    match hop::clear(ctx) {
        Ok(report) => failed.extend(report.failed),
        Err(e) => failed.push(e.to_string()),
    }
    match firewall::clear_owner(ctx, "proxy") {
        Ok(report) => failed.extend(report.failed),
        Err(e) => failed.push(e.to_string()),
    }
    ensure!(failed.is_empty(), "{RULES_LEFT}: {}", failed.join("; "));
    Ok(())
}

/// Put the previous manager back, or remove the executable when there was
/// none before the update.
fn restore_program(paths: &Paths, journal: &ProgramJournal, work: &Path) -> Result<()> {
    let exe = &paths.executable;
    if journal.old_existed {
        copy_file(&work.join(OLD_FILE), exe, 0o755)?;
    } else if remove_file_if_exists(exe)? {
        let dir = exe_dir(paths)?;
        fsync_dir(dir).map_err(|e| Error::io(dir, e))?;
    }
    Ok(())
}

/// Before a restored 2.x manager regenerates (version-1 journals): remove
/// the node's v3-form crontab lines (`renew`, `boot:onebox-*`) a v3 child
/// regen may have installed. The crontab is in no snapshot, and 2.x
/// neither recognizes nor replaces `# onebox:` lines, so a daily job
/// calling a command 2.x lacks and duplicate autostarts next to its own
/// `# onebox-rust:` lines would stay. Lines in older forms are kept for the
/// restored regen to manage.
fn retire_v3_cron(ctx: &Ctx) -> Result<()> {
    if !cron::available(ctx) {
        return Ok(());
    }
    Crontab::edit(ctx, |tab| Ok(tab.remove_v3_lines(Scope::Node)))
        .map(drop)
        .context("恢复前清理 3.x 计划任务失败")
}

/// Run the restored manager's `regen` with our lock on fd 198, so its
/// self-install cannot overwrite it with this (newer) process image.
fn regenerate(ctx: &Ctx, lock: &FileLock) -> Result<()> {
    let exe = ctx
        .paths
        .executable
        .to_str()
        .ok_or_else(|| Error::msg("程序路径不是 UTF-8"))?;
    let cmd = ctx
        .paths
        .service_env()
        .into_iter()
        .fold(Cmd::new(exe).arg("regen"), |cmd, (k, v)| cmd.env(k, v))
        .inherit_lock(lock.raw_fd())
        .stream();
    ctx.check(&cmd)
        .map(drop)
        .context("恢复后的管理程序重新生成配置失败")
}

/// Whether the file behind `image` (symlinks followed) has `sha256`.
fn image_matches(image: &Path, sha256: &str) -> bool {
    let digest = || -> std::io::Result<String> {
        let mut file = fs::File::open(image)?;
        let mut hasher = Sha256::new();
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            match file.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => hasher.update(&buf[..n]),
                Err(e) if e.kind() == ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
        Ok(to_hex(&hasher.finalize()))
    };
    digest().is_ok_and(|hash| hash.eq_ignore_ascii_case(sha256))
}

#[cfg(test)]
mod tests;
