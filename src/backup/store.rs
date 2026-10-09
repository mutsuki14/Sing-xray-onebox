//! Creating, listing and rotating backups under `ROOT/backups`.
//!
//! Order is by creation time, never by name (E-8.1#1): schema-2 backups by
//! their manifest's `created`, v1 backups by the timestamp in their id
//! (`YYYYMMDDTHHMMSSZ-XXXXXX`), anything else by a leading `{unix}-` in the
//! id, else as the oldest; ties by the manifest's modification time, then
//! by id. `latest` is the newest backup that can be restored. Rotation
//! keeps the [`KEEP`] newest recognizable backups (plus the new one and the
//! one being restored); directories that are not backups are listed but
//! never deleted. The safety copy a restore keeps of an unreadable
//! `state.json` is labelled as such ([`unreadable_label`]), is never
//! `latest`, and rotates nothing away: it only replaces the previous such
//! copy (otherwise every failed restore over a corrupt state pushed out one
//! good backup).
//!
//! Changes from v2: creation time instead of lexicographic ids for order,
//! `latest` and rotation (E-8.1#1: v1 ids `2026…` outranked every Unix-time
//! id, so rotation could delete the `before-restore` copy); unknown
//! directories are never rotated away; rotation renames a backup to a
//! `.new-*` stage before deleting it (v2 deleted in place, so an interrupted
//! deletion could leave an unrecognizable directory holding credentials
//! that nothing removed); stale `.new-*` stages are removed by the next
//! backup or apply; `state.json` is stored as it is on disk (no internal
//! keys, E-8.1#18) and counts against the 64 MiB budget.

use super::archive::{self, clean_label, copy_private, inventory, Budget, Kind, Manifest, Part};
use crate::ctx::Ctx;
use crate::error::{Error, Result};
use crate::paths::Paths;
use crate::state::StateStore;
use crate::sys::fs::{
    atomic_write, ensure_dir, fsync_dir, read_bounded, remove_tree_if_exists, sweep_stale,
};
use crate::sys::lock::FileLock;
use crate::ui::out;
use std::fs;
use std::io::ErrorKind;
use std::path::Path;
use std::time::Duration;

/// Backups kept by rotation (v2).
pub const KEEP: usize = 5;
/// Label of the safety copy taken before a restore.
pub const BEFORE_RESTORE: &str = "before-restore";
/// Label shown for directories without a readable label.
pub const LEGACY_LABEL: &str = "旧版本备份";
/// Prefix of a backup being written (renamed to its id when complete) or
/// deleted (renamed from its id first).
pub const STAGE_PREFIX: &str = ".new-";

/// One entry of `onebox backups`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BackupInfo {
    pub id: String,
    pub label: String,
    /// Unix seconds of creation, when known.
    pub created: Option<u64>,
    pub kind: BackupKind,
}

/// What `restore` can do with a backup.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BackupKind {
    /// Schema 2: restorable.
    Current,
    /// Schema 2, but its `state.json` cannot be loaded (the safety copy of
    /// an unreadable state): listed and rotated, never `latest`.
    Unrestorable,
    /// Written by v1: listed, not restorable.
    V1,
    /// Not recognizable as a backup.
    Unknown,
}

/// Every directory under `ROOT/backups` with a valid id, newest first.
pub fn list(paths: &Paths) -> Result<Vec<BackupInfo>> {
    let dir = paths.backups();
    let entries = match fs::read_dir(&dir) {
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(Error::io(&dir, e)),
        Ok(entries) => entries,
    };
    let mut found = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|e| Error::io(&dir, e))?;
        let is_dir = entry.file_type().is_ok_and(|t| t.is_dir());
        let Some(id) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        if is_dir && archive::id_valid(&id) {
            let path = dir.join(&id);
            let written = fs::symlink_metadata(path.join(archive::MANIFEST))
                .and_then(|m| m.modified())
                .ok();
            found.push((info(paths, &path, id), written));
        }
    }
    // Backups of the same second (a safety copy right before a restore)
    // are told apart by when their manifest was written.
    found.sort_by(|(a, wa), (b, wb)| (b.created, wb, &b.id).cmp(&(a.created, wa, &a.id)));
    Ok(found.into_iter().map(|(info, _)| info).collect())
}

fn info(paths: &Paths, dir: &Path, id: String) -> BackupInfo {
    let (kind, label, created) = match archive::kind(dir) {
        Kind::Current(m) if archive::state_restorable(paths, dir) => {
            (BackupKind::Current, m.label, Some(m.created))
        }
        Kind::Current(m) => (BackupKind::Unrestorable, m.label, Some(m.created)),
        Kind::V1 => (BackupKind::V1, label_file(dir), v1_created(&id)),
        Kind::Unknown => (BackupKind::Unknown, label_file(dir), unix_prefix(&id)),
    };
    BackupInfo {
        id,
        label,
        created,
        kind,
    }
}

/// The trimmed `label` file of a v1 backup, else [`LEGACY_LABEL`].
fn label_file(dir: &Path) -> String {
    read_bounded(&dir.join("label"), 4096)
        .ok()
        .map(|b| clean_label(String::from_utf8_lossy(&b).trim()))
        .filter(|l| !l.is_empty())
        .unwrap_or_else(|| LEGACY_LABEL.to_owned())
}

/// `{unix}-…` ids (v2/v3) → the seconds.
fn unix_prefix(id: &str) -> Option<u64> {
    id.split_once('-').and_then(|(secs, _)| secs.parse().ok())
}

/// v1 ids `YYYYMMDDTHHMMSSZ-XXXXXX` → Unix seconds.
pub fn v1_created(id: &str) -> Option<u64> {
    let stamp = id.split_once('-')?.0;
    let (date, time) = stamp.strip_suffix('Z')?.split_once('T')?;
    if date.len() != 8
        || time.len() != 6
        || !(date.to_owned() + time).bytes().all(|b| b.is_ascii_digit())
    {
        return None;
    }
    let num = |s: &str| s.parse::<u32>().ok();
    let (year, month, day) = (num(&date[..4])?, num(&date[4..6])?, num(&date[6..])?);
    let (h, m, s) = (num(&time[..2])?, num(&time[2..4])?, num(&time[4..])?);
    let valid = (1..=12).contains(&month) && (1..=31).contains(&day) && h < 24 && m < 60 && s < 61;
    if !valid {
        return None;
    }
    let days = days_from_civil(i64::from(year), month, day);
    let secs = days * 86_400 + i64::from(h * 3600 + m * 60 + s);
    u64::try_from(secs).ok()
}

/// Days since 1970-01-01 of a proleptic Gregorian date (Howard Hinnant's
/// `days_from_civil`, the inverse of `sys::time::civil_from_days`).
pub fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let m = i64::from(month);
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + i64::from(day) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// The newest restorable backup's id (`latest`).
pub fn latest(paths: &Paths) -> Result<String> {
    list(paths)?
        .into_iter()
        .find(|b| b.kind == BackupKind::Current)
        .map(|b| b.id)
        .ok_or_else(|| Error::msg("没有备份"))
}

/// Back up the node under the held node lock (`backup`, `uninstall`): the
/// state as stored, then tls, site, site root, subscription and clients.
/// Refused while a recovery is due, and when the state cannot be loaded
/// (such a backup could not be restored). Returns the new id.
pub fn create_locked(ctx: &Ctx, lock: &FileLock, label: &str) -> Result<String> {
    create(ctx, lock, label, None, false)
}

/// The safety copy a restore takes first: [`create_locked`], except that a
/// `state.json` that exists but cannot be loaded (corrupt, or a v2 state
/// the migration rejects) is kept as it is, with a warning, instead of
/// refusing the restore — restoring a backup is the natural way out of
/// such a state, and the engine applies over it (`engine::old_config`).
/// Such a copy is labelled [`unreadable_label`] and rotates nothing away:
/// it only replaces the previous copy of that label, so restores that fail
/// over a corrupt state cannot push out the good backups one by one.
/// Rotation also spares `keep` (the backup the restore is about to use).
pub fn create_kept(ctx: &Ctx, lock: &FileLock, label: &str, keep: Option<&str>) -> Result<String> {
    create(ctx, lock, label, keep, true)
}

/// The label of a safety copy whose `state.json` could not be loaded.
pub fn unreadable_label(label: &str) -> String {
    clean_label(&format!("{label}（state.json 无法读取，不能恢复）"))
}

fn create(
    ctx: &Ctx,
    lock: &FileLock,
    label: &str,
    keep: Option<&str>,
    unreadable_ok: bool,
) -> Result<String> {
    let paths = &ctx.paths;
    lock.verify(&paths.lock())?;
    crate::apply::journal::pending(paths)?.refuse()?;
    let unreadable = match StateStore::load_required(ctx) {
        Ok(_) => false,
        Err(e) if unreadable_ok && fs::symlink_metadata(paths.state()).is_ok() => {
            out::warn(format!(
                "现有 state.json 无法读取（{}），安全备份按原样保存该文件（该备份不能直接恢复）",
                e.report_text()
            ));
            true
        }
        Err(e) => return Err(e),
    };
    let label = if unreadable {
        unreadable_label(label)
    } else {
        label.to_owned()
    };
    let state = read_bounded(&paths.state(), crate::domain::defaults::STATE_MAX_BYTES)?;
    let root = paths.backups();
    crate::sys::fs::check_owned(&paths.root, &root)?;
    ensure_dir(&root, 0o700)?;
    sweep_stages(&root);
    let created = crate::sys::time::now();
    let id = format!("{created}-{}", crate::sys::rand::hex(4)?);
    let stage = root.join(format!("{STAGE_PREFIX}{id}"));
    let result = write_backup(paths, &stage, &state, &label, created)
        .and_then(|()| fs::rename(&stage, root.join(&id)).map_err(|e| Error::io(&stage, e)))
        .and_then(|()| fsync_dir(&root).map_err(|e| Error::io(&root, e)));
    if let Err(e) = result {
        let _ = remove_tree_if_exists(&stage);
        return Err(e);
    }
    if unreadable {
        replace_unreadable(paths, &id, &label)?;
    } else {
        prune(paths, &id, keep)?;
    }
    Ok(id)
}

/// Fill the staging directory: state, components, manifest.
fn write_backup(
    paths: &Paths,
    stage: &Path,
    state: &[u8],
    label: &str,
    created: u64,
) -> Result<()> {
    ensure_dir(stage, 0o700)?;
    let mut budget = Budget::BACKUP;
    budget.take(state.len() as u64)?;
    atomic_write(&stage.join(archive::STATE_FILE), state, 0o600)?;
    for part in Part::ALL {
        let source = part.live(paths);
        if fs::symlink_metadata(&source).is_ok() {
            copy_private(&source, &stage.join(part.name()), &mut budget)?;
        }
    }
    let manifest = Manifest {
        schema: archive::SCHEMA,
        label: clean_label(label),
        created,
        files: inventory(stage)?,
    };
    atomic_write(
        &stage.join(archive::MANIFEST),
        &serde_json::to_vec_pretty(&manifest)?,
        0o600,
    )?;
    fsync_dir(stage).map_err(|e| Error::io(stage, e))
}

/// Keep the [`KEEP`] newest recognizable backups, `new` and `keep`.
fn prune(paths: &Paths, new: &str, keep: Option<&str>) -> Result<()> {
    let root = paths.backups();
    let recognized = list(paths)?
        .into_iter()
        .filter(|b| b.kind != BackupKind::Unknown);
    for old in recognized.skip(KEEP) {
        if old.id != new && Some(old.id.as_str()) != keep {
            remove_backup(&root, &old.id)?;
        }
    }
    Ok(())
}

/// Delete backup `id` without ever leaving a half-deleted one under its id:
/// it is renamed to a stage name first, then the stage is deleted. A
/// deletion stopped part-way (a crash, an I/O error) leaves only a stage,
/// which the next backup or apply sweeps; in place, a directory that lost
/// its manifest first became an unknown entry that rotation never removed,
/// with the state's credentials and the TLS key still inside.
fn remove_backup(root: &Path, id: &str) -> Result<()> {
    let dir = root.join(id);
    let stage = root.join(format!("{STAGE_PREFIX}{id}"));
    remove_tree_if_exists(&stage)?;
    match fs::rename(&dir, &stage) {
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(Error::io(&dir, e)),
        Ok(()) => {}
    }
    fsync_dir(root).map_err(|e| Error::io(root, e))?;
    remove_tree_if_exists(&stage).map(drop)
}

/// Remove the stages a killed backup or an interrupted [`remove_backup`]
/// left (the node lock is held, so none is in use). Failures only warn.
fn sweep_stages(root: &Path) {
    if let Err(e) = sweep_stale(root, STAGE_PREFIX, Duration::ZERO) {
        out::warn(format!(
            "清理残留的备份临时目录失败 {}: {}",
            root.display(),
            e.report_text()
        ));
    }
}

/// After an unrestorable safety copy `new` (labelled `label`): remove the
/// earlier unrestorable copies of the same label, nothing else. Restorable
/// backups are left to the next ordinary rotation, where the copy counts
/// like any recognizable backup (so it ages out).
fn replace_unreadable(paths: &Paths, new: &str, label: &str) -> Result<()> {
    let root = paths.backups();
    for old in list(paths)? {
        if old.id != new && old.kind == BackupKind::Unrestorable && old.label == label {
            remove_backup(&root, &old.id)?;
        }
    }
    Ok(())
}
