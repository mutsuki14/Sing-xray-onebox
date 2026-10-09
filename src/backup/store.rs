//! Creating, listing and rotating backups under `ROOT/backups`.
//!
//! Order is by creation time, never by name (E-8.1#1): schema-2 backups by
//! their manifest's `created`, v1 backups by the timestamp in their id
//! (`YYYYMMDDTHHMMSSZ-XXXXXX`), anything else by a leading `{unix}-` in the
//! id, else as the oldest; ties by id. `latest` is the newest backup that
//! can be restored. Rotation keeps the [`KEEP`] newest recognizable backups
//! (plus the new one and the one being restored); directories that are not
//! backups are listed but never deleted.

use super::archive::{self, clean_label, copy_private, inventory, Budget, Kind, Manifest, Part};
use crate::ctx::Ctx;
use crate::error::{Error, Result};
use crate::paths::Paths;
use crate::state::StateStore;
use crate::sys::fs::{atomic_write, ensure_dir, fsync_dir, read_bounded, remove_tree_if_exists};
use crate::sys::lock::FileLock;
use std::fs;
use std::io::ErrorKind;
use std::path::Path;

/// Backups kept by rotation (v2).
pub const KEEP: usize = 5;
/// Label of the safety copy taken before a restore.
pub const BEFORE_RESTORE: &str = "before-restore";
/// Label shown for directories without a readable label.
pub const LEGACY_LABEL: &str = "旧版本备份";
/// Prefix of a backup being written (renamed to its id when complete).
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
            found.push(info(&dir.join(&id), id));
        }
    }
    sort_newest_first(&mut found);
    Ok(found)
}

fn info(dir: &Path, id: String) -> BackupInfo {
    let (kind, label, created) = match archive::kind(dir) {
        Kind::Current(m) => (BackupKind::Current, m.label, Some(m.created)),
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

/// Newest first: by creation time (unknown = oldest), then by id.
pub fn sort_newest_first(backups: &mut [BackupInfo]) {
    backups.sort_by(|a, b| (b.created, &b.id).cmp(&(a.created, &a.id)));
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
    if date.len() != 8 || time.len() != 6 || !(date.to_owned() + time).bytes().all(|b| b.is_ascii_digit()) {
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

/// Back up the node under the held node lock (`uninstall`, `restore`): the
/// state as stored, then tls, site, site root, subscription and clients.
/// Refused while a recovery is due. Returns the new id.
pub fn create_locked(ctx: &Ctx, lock: &FileLock, label: &str) -> Result<String> {
    create_kept(ctx, lock, label, None)
}

/// [`create_locked`]; rotation also spares `keep` (the backup a restore is
/// about to use).
pub fn create_kept(ctx: &Ctx, lock: &FileLock, label: &str, keep: Option<&str>) -> Result<String> {
    let paths = &ctx.paths;
    lock.verify(&paths.lock())?;
    crate::apply::journal::pending(paths)?.refuse()?;
    StateStore::load_required(ctx)?;
    let state = read_bounded(&paths.state(), crate::domain::defaults::STATE_MAX_BYTES)?;
    let root = paths.backups();
    crate::sys::fs::check_owned(&paths.root, &root)?;
    ensure_dir(&root, 0o700)?;
    let created = crate::sys::time::now();
    let id = format!("{created}-{}", crate::sys::rand::hex(4)?);
    let stage = root.join(format!("{STAGE_PREFIX}{id}"));
    let result = write_backup(paths, &stage, &state, label, created)
        .and_then(|()| fs::rename(&stage, root.join(&id)).map_err(|e| Error::io(&stage, e)))
        .and_then(|()| fsync_dir(&root).map_err(|e| Error::io(&root, e)));
    if let Err(e) = result {
        let _ = remove_tree_if_exists(&stage);
        return Err(e);
    }
    prune(paths, &id, keep)?;
    Ok(id)
}

/// Fill the staging directory: state, components, manifest.
fn write_backup(paths: &Paths, stage: &Path, state: &[u8], label: &str, created: u64) -> Result<()> {
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
            remove_tree_if_exists(&root.join(&old.id))?;
        }
    }
    Ok(())
}
