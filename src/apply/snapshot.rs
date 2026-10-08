//! Bounded snapshots of Onebox-owned paths, used by the node journal, the
//! self-update journal, backups and FRP. The JSON shape
//! (`{"entries":[{"target","present","slot","sha256"}]}`), the slot names
//! (`item-{i}`), the skip rule and the tree digest are identical to v2, so
//! journals written by v2 are validated and restored by v3.
//!
//! A snapshot is taken into a new private directory: every present target is
//! copied (modes kept, symlinks and special files refused) into `item-{i}`
//! and digested; absent targets are recorded as absent. Restoring first
//! validates everything — allowlist, slots, digests — and only then
//! replaces each target, deleting the ones that were absent, so a corrupt
//! snapshot never changes a live file and a restore can be repeated.
//!
//! Changes from v2:
//! - the allowlist is explicit ([`Allowlist`]): v2 journals are checked
//!   against v2's fixed list plus a *pattern* for retired acme.sh
//!   deployments (E-8.1#5: v2 recomputed those from `$ACME_HOME`, which the
//!   boot service did not carry, so `net-apply` refused the journal), v3
//!   journals against owned-root patterns of their recorded targets;
//! - symlink checks start below the configured roots, so distributions with
//!   a symlinked `/etc/init.d` work (E-8.1#6);
//! - copies and digests stream file contents (E-8.1#22) and the 2 GiB cap
//!   is enforced while copying;
//! - the ACME-code skip rule looks at the path below the snapshotted target
//!   (plus the target's own name), so taking and restoring a slot apply the
//!   same rule wherever the journal directory lives;
//! - slot names must be `item-{n}` and unique;
//! - [`take`] checks its targets against the allowlist the snapshot will be
//!   validated with (v2 ran `safe_roots` first; a snapshot that can never be
//!   restored is refused before anything is copied) and refuses a non-empty
//!   destination, so leftovers are never restored;
//! - a regular file restored over a regular file is replaced atomically
//!   (v2 deleted it first, so a crash could leave the manager missing).

mod allowlist;
mod digest;

pub use allowlist::{
    acme_homes, node_allowlist, subscription_acme_dir, v2_fixed_targets, v2_node_allowlist,
    v2_node_allowlist_with, Allowlist, TargetRule, DEFAULT_ACME_HOME,
};
pub use digest::{digest_tree, MAX_FILE_BYTES};

use crate::error::{Context, Error, Result};
use crate::paths::Paths;
use crate::sys::fs::{
    atomic_write, check_owned, copy_file, copy_tree, ensure_dir, remove_tree_contents, CopyLimits,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::ffi::OsStr;
use std::fs;
use std::io::ErrorKind;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::{Path, PathBuf};

/// Total size cap of one snapshot (v2).
pub const MAX_BYTES: u64 = 2 * 1024 * 1024 * 1024;
/// The snapshot description written next to the slots.
pub const SNAPSHOT_FILE: &str = "snapshot.json";
const TOO_LARGE: &str = "快照超过 2 GiB，请先清理托管目录";
/// Never copied, restored or deleted, anywhere in a tree (v2 `skip`).
const ALWAYS_SKIPPED: [&str; 7] = [
    "backups",
    "content-backups",
    ".transaction",
    ".apply.lock",
    "nginx.pid",
    "error.log",
    "access.log",
];
/// acme.sh code below an `acme` directory: kept live, never rolled back
/// (account and certificate data next to it are snapshotted).
const ACME_CODE: [&str; 5] = ["acme.sh", "dnsapi", "deploy", "notify", ".git"];

/// One snapshotted target (v2 field names).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotEntry {
    pub target: PathBuf,
    pub present: bool,
    /// Directory entry under the snapshot directory (`item-{i}`).
    pub slot: String,
    /// [`digest_tree`] of the slot; empty when absent.
    pub sha256: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Snapshot {
    pub entries: Vec<SnapshotEntry>,
}

impl Snapshot {
    /// The recorded targets, in slot order.
    pub fn targets(&self) -> impl Iterator<Item = &Path> {
        self.entries.iter().map(|e| e.target.as_path())
    }

    pub fn entry(&self, target: &Path) -> Option<&SnapshotEntry> {
        self.entries.iter().find(|e| e.target == target)
    }
}

/// The v2 skip rule for `rel`, a path inside a snapshotted tree that starts
/// with the target's own name (`tls/acme/acme.sh`).
pub fn skipped(rel: &Path) -> bool {
    let name = rel.file_name().and_then(OsStr::to_str).unwrap_or("");
    if ALWAYS_SKIPPED.contains(&name) {
        return true;
    }
    if rel.components().any(|c| c.as_os_str() == "acme") {
        return ACME_CODE.contains(&name)
            || name.ends_with(".sh")
            || name.starts_with(".download-");
    }
    false
}

/// A skip predicate for a tree rooted at `root` holding the content of a
/// target named `name` (the target itself, or its slot).
fn skip_below<'a>(root: &'a Path, name: &'a OsStr) -> impl Fn(&Path) -> bool + 'a {
    move |path: &Path| {
        let below = path.strip_prefix(root).unwrap_or(path);
        skipped(&Path::new(name).join(below))
    }
}

fn target_name(target: &Path) -> &OsStr {
    target.file_name().unwrap_or(target.as_os_str())
}

/// Whether `path` exists, without following a final symlink.
fn present(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(false),
        Err(e) => Err(Error::io(path, e)),
    }
}

/// What [`validate`] will require of a snapshot of `targets`, checked
/// before anything is copied: the allowlist's scope is sane, every target
/// is accepted once and has no symlink below its owned root, and every
/// required target is included. Whatever `take` accepts, `validate` accepts.
fn check_targets(targets: &[PathBuf], allow: &Allowlist) -> Result<()> {
    allow.check_scope()?;
    let mut seen = BTreeSet::new();
    for target in targets {
        let root = allow
            .owned_root(target)
            .filter(|_| seen.insert(target.as_path()))
            .ok_or_else(|| Error::msg(format!("快照路径范围不合法: {}", target.display())))?;
        check_owned(&root, target)?;
    }
    allow.check_complete(&seen)
}

/// Create `dest` (0700, its parent must exist), or accept an existing empty
/// real directory: leftovers of an earlier attempt must never be digested
/// into a new snapshot and restored later.
fn prepare_dest(dest: &Path) -> Result<()> {
    let not_empty = || Error::msg(format!("快照目录必须为空: {}", dest.display()));
    match fs::DirBuilder::new().mode(0o700).create(dest) {
        Ok(()) => {}
        Err(e) if e.kind() == ErrorKind::AlreadyExists => {
            let meta = fs::symlink_metadata(dest).map_err(|e| Error::io(dest, e))?;
            if !meta.is_dir() {
                return Err(not_empty());
            }
            let mut entries = fs::read_dir(dest).map_err(|e| Error::io(dest, e))?;
            if entries.next().is_some() {
                return Err(not_empty());
            }
        }
        Err(e) => return Err(Error::io(dest, e)),
    }
    ensure_dir(dest, 0o700)
}

/// Snapshot `targets` into `dest`: `dest/item-{i}` for every present
/// target, `dest/snapshot.json` (0600) describing them. `targets` must
/// satisfy `allow` (the allowlist the snapshot will be validated against)
/// and `dest` must be absent or empty; both are checked before anything is
/// written. Fails on symlinks or special files in a target and when all
/// copies together exceed [`MAX_BYTES`]; the caller removes `dest` on error.
pub fn take(targets: &[PathBuf], dest: &Path, allow: &Allowlist) -> Result<Snapshot> {
    take_within(targets, dest, allow, MAX_BYTES)
}

/// [`take`] with a total size budget of `max_bytes`.
fn take_within(
    targets: &[PathBuf],
    dest: &Path,
    allow: &Allowlist,
    max_bytes: u64,
) -> Result<Snapshot> {
    check_targets(targets, allow)?;
    prepare_dest(dest)?;
    let mut used = 0u64;
    let mut entries = Vec::with_capacity(targets.len());
    for (i, target) in targets.iter().enumerate() {
        let slot = format!("item-{i}");
        let present = present(target)?;
        let mut sha256 = String::new();
        if present {
            let saved = dest.join(&slot);
            let limits =
                CopyLimits::new(max_bytes.saturating_sub(used), usize::MAX).message(TOO_LARGE);
            let skip = skip_below(target, target_name(target));
            let stats = copy_tree(target, &saved, &skip, &limits)
                .with_context(|| format!("快照 {} 失败", target.display()))?;
            used += stats.bytes;
            sha256 = digest_tree(&saved)?;
        }
        entries.push(SnapshotEntry {
            target: target.clone(),
            present,
            slot,
            sha256,
        });
    }
    let snapshot = Snapshot { entries };
    let json = serde_json::to_vec_pretty(&snapshot)?;
    atomic_write(&dest.join(SNAPSHOT_FILE), &json, 0o600)?;
    Ok(snapshot)
}

/// `item-{n}`: the only slot names v2 and v3 write.
fn valid_slot(slot: &str) -> bool {
    slot.strip_prefix("item-")
        .is_some_and(|n| !n.is_empty() && n.len() <= 6 && n.bytes().all(|b| b.is_ascii_digit()))
}

fn check_source(src: &Path) -> Result<()> {
    let meta = fs::symlink_metadata(src).map_err(|e| Error::io(src, e))?;
    ensure!(
        meta.is_dir() && !meta.file_type().is_symlink(),
        "快照目录无效: {}",
        src.display()
    );
    Ok(())
}

/// Check `snapshot` (slots under `src`) before anything is restored: every
/// target accepted by `allow` and unique, no symlink below its owned root,
/// slots well-formed and unique, every present slot matching its digest
/// (which also refuses symlinks and special files inside it), and every
/// required target present in the snapshot.
pub fn validate(snapshot: &Snapshot, src: &Path, allow: &Allowlist) -> Result<()> {
    allow.check_scope()?;
    check_source(src)?;
    let mut targets = BTreeSet::new();
    let mut slots = BTreeSet::new();
    for entry in &snapshot.entries {
        let root = allow
            .owned_root(&entry.target)
            .filter(|_| targets.insert(entry.target.as_path()))
            .filter(|_| valid_slot(&entry.slot) && slots.insert(entry.slot.as_str()))
            .ok_or_else(|| Error::msg("快照路径范围不合法"))?;
        check_owned(&root, &entry.target)?;
        if entry.present {
            let saved = src.join(&entry.slot);
            let intact = present(&saved)? && digest_tree(&saved)? == entry.sha256;
            ensure!(intact, "快照文件缺失或校验失败: {}", entry.slot);
        }
    }
    allow.check_complete(&targets)
}

/// [`validate`], then put every target back as it was when `snapshot` was
/// taken (absent targets are deleted; skipped names are left alone). Every
/// entry is attempted; failures are reported together. Idempotent.
pub fn restore(snapshot: &Snapshot, src: &Path, allow: &Allowlist) -> Result<()> {
    validate(snapshot, src, allow)?;
    let errors: Vec<String> = snapshot
        .entries
        .iter()
        .filter_map(|entry| {
            restore_entry(entry, src)
                .err()
                .map(|e| format!("{}: {e}", entry.target.display()))
        })
        .collect();
    ensure!(errors.is_empty(), "文件恢复不完整: {}", errors.join("; "));
    Ok(())
}

fn is_regular(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok_and(|m| m.is_file())
}

fn restore_entry(entry: &SnapshotEntry, src: &Path) -> Result<()> {
    let target = &entry.target;
    let saved = src.join(&entry.slot);
    let name = target_name(target);
    if entry.present && is_regular(&saved) && is_regular(target) {
        let mode = fs::symlink_metadata(&saved)
            .map_err(|e| Error::io(&saved, e))?
            .permissions()
            .mode()
            & 0o777;
        copy_file(&saved, target, mode)?;
        return Ok(());
    }
    remove_tree_contents(target, &skip_below(target, name))?;
    if entry.present {
        let limits = CopyLimits::new(MAX_BYTES, usize::MAX).message(TOO_LARGE);
        copy_tree(&saved, target, &skip_below(&saved, name), &limits)?;
    }
    Ok(())
}

/// The v3 node snapshot targets: v2's fixed targets in v2 slot order, then
/// the paths v3 added (`state.v2.json`, the original v2 state kept by the
/// first v3 save). `subscription/devices.json` and the per-certificate
/// `acme/onebox-dns.json` live inside snapshotted directories.
pub fn node_targets(paths: &Paths) -> Vec<PathBuf> {
    let mut targets = v2_fixed_targets(paths);
    targets.push(paths.state_v2_backup());
    targets
}

#[cfg(test)]
mod tests;
