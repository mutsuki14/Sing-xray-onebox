//! The on-disk backup format (schema 2, shared with v2) and the restore of a
//! backup's files inside a transaction. A leaf module (domain, state, sys,
//! paths, error), so the apply engine's prepare-state stage can place a
//! backup's files without depending on the backup commands above it.
//!
//! Layout of `ROOT/backups/<id>/` (id `{unix}-{8 hex}`):
//! `state.json` (0600; the node's state.json as stored), `tls/`, `site/`,
//! `public/` (site root), `subscription/`, `client/` copies (dirs 0700,
//! files 0600) and `manifest.json`:
//! `{"schema":2,"label","created","files":{"rel/path":"<sha256>"}}` listing
//! every file except the top-level `manifest.json` / `manifest`.
//!
//! Restore policy per component (explicit, E-8.1#19):
//!
//! | component | in the backup | absent from the backup |
//! |---|---|---|
//! | `tls` → `ROOT/tls` | replaced | kept (re-validated by the certificate stage) |
//! | `site` → `ROOT/site` | replaced (content backups kept) | kept |
//! | `public` → site root | replaced, made world-readable | kept |
//! | `subscription` → `ROOT/subscription` | replaced | removed (no device survives) |
//! | `client` | never restored: clients are regenerated | — |
//!
//! In every component the [`ignored`] entries are neither copied nor
//! replaced nor removed: pid and log files, nested backups, acme.sh code
//! and the subscription worker's `listener.json` (runtime state that
//! describes the running worker, not the configuration).
//!
//! Changes from v2:
//! - the 64 MiB budget counts `state.json` too (E-8.1#19);
//! - hard links, symlinks and special files are refused when backing up
//!   *and* when validating (v2 checked hard links only in some places);
//! - a backup written by v1 (format 1) gets a clear message instead of
//!   being restored through a dropped parser;
//! - `state.json` is no longer polluted with internal keys (E-8.1#18);
//! - only the site root (outside `ROOT`, possibly holding an
//!   administrator's site) needs the ownership marker to be overwritten;
//!   `ROOT/site` belongs to Onebox anyway (v2 refused it without a marker);
//! - the listener record is new in v3 and never part of a backup (a copy an
//!   earlier v3 backup holds is not restored).

use crate::ctx::Ctx;
use crate::domain::config::{Device, NodeConfig};
use crate::domain::validate::check_schema;
use crate::error::{Context, Error, Result};
use crate::paths::Paths;
use crate::state::v2::{self as statev2, DeployedCerts};
use crate::sys::fs::{atomic_write, check_owned, copy_file, ensure_dir, read_bounded, sha256_file};
use crate::sys::rand::OsRandom;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::fs;
use std::io::ErrorKind;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

/// Manifest schema written by v2 and v3.
pub const SCHEMA: u8 = 2;
pub const MANIFEST: &str = "manifest.json";
/// v1's NUL-separated manifest (excluded from inventories like v2 did).
pub const V1_MANIFEST: &str = "manifest";
pub const STATE_FILE: &str = "state.json";
/// Files (state.json included) and bytes a backup may hold (v2).
pub const MAX_FILES: usize = 4096;
pub const MAX_BYTES: u64 = 64 * 1024 * 1024;
/// Longest label kept (characters).
pub const LABEL_MAX: usize = 120;
/// The web roots' ownership marker (also written by the site module).
pub const OWNED_MARKER: &str = ".onebox-site-owned";
const TOO_LARGE: &str = "备份超过 4096 文件或 64 MiB 限制";
const MANIFEST_MAX: u64 = 16 * 1024 * 1024;
const STATE_MAX: u64 = 1024 * 1024;
const SETTINGS_MAX: u64 = 1024 * 1024;

/// `manifest.json` (field order as v2 wrote it).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    pub schema: u8,
    pub label: String,
    pub created: u64,
    pub files: BTreeMap<String, String>,
}

/// The copied components, in backup order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Part {
    Tls,
    Site,
    Public,
    Subscription,
    Client,
}

impl Part {
    pub const ALL: [Part; 5] = [
        Part::Tls,
        Part::Site,
        Part::Public,
        Part::Subscription,
        Part::Client,
    ];

    /// Directory name inside a backup.
    pub fn name(self) -> &'static str {
        match self {
            Part::Tls => "tls",
            Part::Site => "site",
            Part::Public => "public",
            Part::Subscription => "subscription",
            Part::Client => "client",
        }
    }

    /// The live path it is copied from and restored to.
    pub fn live(self, paths: &Paths) -> PathBuf {
        match self {
            Part::Tls => paths.tls(),
            Part::Site => paths.site(),
            Part::Public => paths.site_root.clone(),
            Part::Subscription => paths.subscription(),
            Part::Client => paths.clients(),
        }
    }
}

/// `[A-Za-z0-9_-]{1,99}` (v2).
pub fn id_valid(id: &str) -> bool {
    !id.is_empty()
        && id.len() < 100
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b))
}

/// Never backed up, restored over or removed (v2 `ignored`): user backups,
/// content backups, pid and log files, acme.sh code, and the subscription
/// worker's listener record.
pub fn ignored(path: &Path) -> bool {
    let name = path.file_name().and_then(OsStr::to_str).unwrap_or("");
    let always = matches!(
        name,
        "backups" | "content-backups" | "nginx.pid" | "access.log" | "error.log"
    );
    let acme_code = path.components().any(|c| c.as_os_str() == "acme")
        && (name.ends_with(".sh") || matches!(name, "dnsapi" | "deploy" | "notify" | ".git"));
    always || acme_code || is_listener_record(path)
}

/// `subscription/listener.json` (`subscription::server::listener_file`):
/// which listener the *running* worker uses, so runtime state like a pid
/// file. Restoring a backup's copy over it made publish-subscription
/// believe the worker already listened where the backup's configuration
/// wants and skip the restart, so a backup taken before a subscription
/// port or mode change could not be restored while the worker ran.
fn is_listener_record(path: &Path) -> bool {
    path.file_name() == Some(OsStr::new("listener.json"))
        && path
            .parent()
            .and_then(Path::file_name)
            .is_some_and(|dir| dir == "subscription")
}

/// What a copy may still add.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Budget {
    pub files: usize,
    pub bytes: u64,
}

impl Budget {
    pub const BACKUP: Budget = Budget {
        files: MAX_FILES,
        bytes: MAX_BYTES,
    };
    pub const UNLIMITED: Budget = Budget {
        files: usize::MAX,
        bytes: u64::MAX,
    };

    /// Take one file of `size` bytes, or fail with v2's limit message.
    pub fn take(&mut self, size: u64) -> Result<()> {
        ensure!(self.files > 0 && size <= self.bytes, "{TOO_LARGE}");
        self.files -= 1;
        self.bytes -= size;
        Ok(())
    }
}

/// A plain file or directory that is not a hard link (`refusal` otherwise).
fn plain_entry(path: &Path, refusal: &str) -> Result<fs::Metadata> {
    let meta = fs::symlink_metadata(path).map_err(|e| Error::io(path, e))?;
    let plain = meta.is_dir() || (meta.is_file() && meta.nlink() == 1);
    ensure!(plain && !meta.file_type().is_symlink(), "{refusal}");
    Ok(meta)
}

/// Copy `src` to `dst` with private modes (dirs 0700, files 0600), skipping
/// [`ignored`] names, refusing links and special files, within `budget`.
pub fn copy_private(src: &Path, dst: &Path, budget: &mut Budget) -> Result<()> {
    let meta = plain_entry(src, "备份拒绝链接或特殊文件")?;
    if meta.is_file() {
        budget.take(meta.len())?;
        copy_file(src, dst, 0o600)?;
        return Ok(());
    }
    ensure_dir(dst, 0o700)?;
    for entry in sorted_children(src)? {
        if !ignored(&entry) {
            let name = entry.file_name().unwrap_or_default();
            copy_private(&entry, &dst.join(name), budget)?;
        }
    }
    Ok(())
}

/// The entries of `dir`, sorted by name (deterministic copies and errors).
fn sorted_children(dir: &Path) -> Result<Vec<PathBuf>> {
    let mut children = Vec::new();
    for entry in fs::read_dir(dir).map_err(|e| Error::io(dir, e))? {
        children.push(entry.map_err(|e| Error::io(dir, e))?.path());
    }
    children.sort();
    Ok(children)
}

/// SHA-256 of every file below `root` except the top-level manifests,
/// keyed by relative UTF-8 path.
pub fn inventory(root: &Path) -> Result<BTreeMap<String, String>> {
    let mut files = BTreeMap::new();
    walk_inventory(root, root, &mut files)?;
    Ok(files)
}

fn walk_inventory(root: &Path, path: &Path, out: &mut BTreeMap<String, String>) -> Result<()> {
    let meta = plain_entry(path, "备份包含不安全的文件类型")?;
    if meta.is_dir() {
        for child in sorted_children(path)? {
            walk_inventory(root, &child, out)?;
        }
        return Ok(());
    }
    let rel = path
        .strip_prefix(root)
        .ok()
        .and_then(Path::to_str)
        .ok_or_else(|| Error::msg("备份文件名不是UTF-8"))?;
    if rel != MANIFEST && rel != V1_MANIFEST {
        out.insert(rel.to_owned(), sha256_file(path)?);
    }
    Ok(())
}

/// The manifest label for `label`: control characters removed, at most
/// [`LABEL_MAX`] characters.
pub fn clean_label(label: &str) -> String {
    label
        .chars()
        .filter(|c| !c.is_control())
        .take(LABEL_MAX)
        .collect()
}

/// What kind of directory a backup id names.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Kind {
    /// Schema 2 (v2 or v3) with its manifest.
    Current(Manifest),
    /// Written by v1 (`format` = 1).
    V1,
    /// Neither (unreadable manifest, foreign directory).
    Unknown,
}

/// Classify the backup directory `dir` (read-only, never fails).
pub fn kind(dir: &Path) -> Kind {
    let manifest = dir.join(MANIFEST);
    if fs::symlink_metadata(&manifest).is_ok() {
        return read_bounded(&manifest, MANIFEST_MAX)
            .ok()
            .and_then(|b| serde_json::from_slice::<Manifest>(&b).ok())
            .map_or(Kind::Unknown, Kind::Current);
    }
    let v1 = read_bounded(&dir.join("format"), 64)
        .ok()
        .is_some_and(|b| String::from_utf8_lossy(&b).trim() == "1");
    if v1 {
        Kind::V1
    } else {
        Kind::Unknown
    }
}

/// Message for a v1 backup (format 1 is no longer read).
pub fn v1_refusal(id: &str) -> String {
    format!(
        "备份 {id} 由 Onebox 1.x 创建（旧格式），3.x 不能恢复；如需使用，请先安装 2.0.1 恢复该备份后再升级到 3.x"
    )
}

/// The configuration a validated backup restores, with the devices of a
/// v2 backup (its `subscription/settings.json`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Validated {
    pub manifest: Manifest,
    pub config: NodeConfig,
    /// `Some` for v2 backups that had subscription settings.
    pub devices: Option<Vec<Device>>,
    /// Notes of a v2 migration.
    pub warnings: Vec<String>,
}

/// `ROOT/backups/{id}` after checking the id and that it is a real
/// directory inside the configuration root.
pub fn backup_dir(paths: &Paths, id: &str) -> Result<PathBuf> {
    ensure!(id_valid(id), "备份 ID 无效");
    let dir = paths.backups().join(id);
    check_owned(&paths.root, &dir)?;
    let is_dir = fs::symlink_metadata(&dir).is_ok_and(|m| m.is_dir());
    ensure!(is_dir, "备份不存在");
    Ok(dir)
}

/// Full validation of the backup in `dir`: format, manifest = inventory,
/// and a configuration that migrates (v2) or validates (v3).
pub fn validate(paths: &Paths, id: &str, dir: &Path) -> Result<Validated> {
    let manifest = match kind(dir) {
        Kind::Current(manifest) => manifest,
        Kind::V1 => bail!("{}", v1_refusal(id)),
        Kind::Unknown => bail!("未知旧备份格式"),
    };
    ensure!(
        manifest.schema == SCHEMA && manifest.files == inventory(dir)?,
        "备份完整性校验失败"
    );
    let bytes = read_bounded(&dir.join(STATE_FILE), STATE_MAX).context("备份缺少 state.json")?;
    let (config, devices, warnings) = parse_state(paths, dir, &bytes)?;
    Ok(Validated {
        manifest,
        config,
        devices,
        warnings,
    })
}

/// Whether the backup in `dir` holds a `state.json` [`validate`] accepts
/// (a v3 configuration that validates, or a v2 state that migrates); its
/// files are not hashed. The safety copy a restore keeps of an unreadable
/// `state.json` fails this, so `latest` never picks it.
pub fn state_restorable(paths: &Paths, dir: &Path) -> bool {
    read_bounded(&dir.join(STATE_FILE), STATE_MAX)
        .is_ok_and(|bytes| parse_state(paths, dir, &bytes).is_ok())
}

type Parsed = (NodeConfig, Option<Vec<Device>>, Vec<String>);

/// A v3 state, or a v2 `{"values"}` state migrated with the backup's own
/// subscription settings (G22). Certificate copies are recorded at their
/// live locations, where the restore puts the backup's.
fn parse_state(paths: &Paths, dir: &Path, bytes: &[u8]) -> Result<Parsed> {
    let doc: Value = serde_json::from_slice(bytes).context("备份中的 state.json 无效")?;
    if doc.get("values").is_some() {
        let values = statev2::v2_values_from_json(bytes)?;
        let settings = read_settings(&dir.join("subscription/settings.json"))?;
        let migrated = statev2::migrate(
            &values,
            settings.as_ref(),
            &DeployedCerts::of(paths),
            &mut OsRandom,
        )
        .context("备份中的 v2 配置无法迁移")?;
        return Ok((migrated.config, migrated.devices, migrated.warnings));
    }
    let schema = doc
        .get("schema")
        .and_then(Value::as_u64)
        .and_then(|n| u32::try_from(n).ok())
        .ok_or_else(|| Error::msg("备份中的 state.json 格式无法识别"))?;
    check_schema(schema)?;
    let config: NodeConfig = serde_json::from_value(doc).context("备份中的 state.json 无效")?;
    config.validate().context("备份中的配置校验失败")?;
    Ok((config, None, Vec::new()))
}

fn read_settings(path: &Path) -> Result<Option<Value>> {
    match read_bounded(path, SETTINGS_MAX) {
        Ok(bytes) => Ok(Some(
            serde_json::from_slice(&bytes).context("备份中的订阅设置无效")?,
        )),
        Err(Error::Io { source, .. }) if source.kind() == ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

/// prepare-state with `Intents.restore_backup`: re-validate the backup
/// (TOCTOU) and put its files in place per the component policy. The
/// journal's snapshot already holds every target, so a failure here (or
/// later) is rolled back completely.
pub fn restore_files(ctx: &Ctx, id: &str) -> Result<()> {
    let paths = &ctx.paths;
    let dir = backup_dir(paths, id)?;
    validate(paths, id, &dir)?;
    for part in [Part::Tls, Part::Site, Part::Public, Part::Subscription] {
        restore_part(paths, part, &dir.join(part.name()))
            .with_context(|| format!("恢复 {} 失败", part.name()))?;
    }
    Ok(())
}

fn exists(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok()
}

fn restore_part(paths: &Paths, part: Part, source: &Path) -> Result<()> {
    let target = part.live(paths);
    if !exists(source) {
        if part == Part::Subscription && exists(&target) {
            remove_assets(&target)?;
        }
        return Ok(());
    }
    let web = matches!(part, Part::Site | Part::Public);
    if exists(&target) {
        if part == Part::Public {
            check_web_target(&target)?;
        }
        remove_assets(&target)?;
    }
    let mut unlimited = Budget::UNLIMITED;
    copy_private(source, &target, &mut unlimited)?;
    if part == Part::Public {
        public_permissions(&target)?;
    }
    if web {
        atomic_write(&target.join(OWNED_MARKER), b"onebox\n", 0o600)?;
    }
    Ok(())
}

/// A web directory is overwritten only when Onebox owns it (marker) or it
/// is empty.
fn check_web_target(target: &Path) -> Result<()> {
    let meta = fs::symlink_metadata(target).map_err(|e| Error::io(target, e))?;
    ensure!(!meta.file_type().is_symlink(), "恢复目标包含符号链接");
    let empty = meta.is_dir() && sorted_children(target)?.is_empty();
    ensure!(
        empty || target.join(OWNED_MARKER).is_file(),
        "拒绝覆盖非托管网站目录"
    );
    Ok(())
}

/// Remove `path` except [`ignored`] entries; directories only once empty
/// (v2 `remove_assets`).
pub fn remove_assets(path: &Path) -> Result<()> {
    let meta = fs::symlink_metadata(path).map_err(|e| Error::io(path, e))?;
    ensure!(!meta.file_type().is_symlink(), "恢复目标包含符号链接");
    if meta.is_file() {
        return fs::remove_file(path).map_err(|e| Error::io(path, e));
    }
    ensure!(meta.is_dir(), "恢复目标包含特殊文件");
    for child in sorted_children(path)? {
        if !ignored(&child) {
            remove_assets(&child)?;
        }
    }
    if sorted_children(path)?.is_empty() {
        fs::remove_dir(path).map_err(|e| Error::io(path, e))?;
    }
    Ok(())
}

/// The restored site root is world-readable: dirs 0755, files 0644.
fn public_permissions(path: &Path) -> Result<()> {
    let meta = fs::symlink_metadata(path).map_err(|e| Error::io(path, e))?;
    ensure!(
        !meta.file_type().is_symlink() && (meta.is_dir() || meta.is_file()),
        "网站恢复包含链接或特殊文件"
    );
    let mode = if meta.is_dir() { 0o755 } else { 0o644 };
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).map_err(|e| Error::io(path, e))?;
    if meta.is_dir() {
        for child in sorted_children(path)? {
            public_permissions(&child)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
