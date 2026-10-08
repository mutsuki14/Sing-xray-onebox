//! Persistence of `NodeConfig` as `ROOT/state.json` (schema 3) with
//! compare-and-swap hashes. Reads v3 directly, migrates v2
//! `{"values":{…}}` (plus v2 `subscription/settings.json`) on load, and
//! recognizes v1 (`onebox.conf` only) to explain the upgrade path.
//!
//! Changes from v2: an explicit schema number; loads validate the whole
//! configuration; a missing state is `Error::NotInstalled` instead of a raw
//! I/O error (A-8.1 #12); `installed()` and `load()` agree on symlinks
//! (A-8.1 #13: both refuse them); v1 is no longer parsed (dropped by design);
//! the original v2 file is kept as `state.v2.json` on the first save. That
//! backup is taken by `save` itself whenever the file it replaces is in v2
//! shape, so no caller can lose it by passing the wrong origin.

pub mod v2;

use crate::ctx::Ctx;
use crate::domain::config::{Device, NodeConfig};
use crate::domain::defaults::STATE_MAX_BYTES;
use crate::domain::validate::check_schema;
use crate::error::{Context, Error, Result};
use crate::paths::Paths;
use crate::sys::fs::{atomic_write, read_bounded, sha256_hex};
use crate::sys::rand::{OsRandom, Random};
use serde_json::Value;
use std::fmt;
use std::fs;
use std::io::ErrorKind;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::Path;

/// Printed when only a v1 `onebox.conf` exists.
pub const V1_MESSAGE: &str = "检测到 Onebox 1.x 配置（onebox.conf）。3.x 只能从 2.x 升级：请先执行 curl -fsSL https://raw.githubusercontent.com/mutsuki14/Sing-xray-onebox/v2.0.1/onebox.sh -o onebox-v2.sh && sh onebox-v2.sh regen，再更新到 3.x。";

const STATE_MODE: u32 = 0o600;
const ROOT_MODE: u32 = 0o700;

/// SHA-256 hex of the `state.json` bytes, or `absent`. Compared under the
/// node lock before an apply writes anything (optimistic concurrency).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct StateHash(String);

impl StateHash {
    pub fn absent() -> Self {
        StateHash("absent".to_owned())
    }
    pub fn of(bytes: &[u8]) -> Self {
        StateHash(sha256_hex(bytes))
    }
    pub fn is_absent(&self) -> bool {
        self.0 == "absent"
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for StateHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Where a loaded configuration came from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Origin {
    V3,
    /// Migrated from v2 on this load; nothing has been written yet.
    V2 {
        /// Devices from v2 `subscription/settings.json` (to be written to
        /// `subscription/devices.json` by the apply), `None` without the file.
        devices: Option<Vec<Device>>,
        /// Chinese notes about generated, normalized or dropped values.
        warnings: Vec<String>,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Loaded {
    pub config: NodeConfig,
    pub hash: StateHash,
    pub origin: Origin,
}

/// Stateless facade over the node's `state.json`.
pub struct StateStore;

impl StateStore {
    /// `Ok(None)` when not installed; v1-only installs are an error.
    pub fn load(ctx: &Ctx) -> Result<Option<Loaded>> {
        Self::load_from(&ctx.paths, &mut OsRandom)
    }

    pub fn load_required(ctx: &Ctx) -> Result<Loaded> {
        Self::load(ctx)?.ok_or(Error::NotInstalled)
    }

    pub fn current_hash(ctx: &Ctx) -> Result<StateHash> {
        Self::current_hash_at(&ctx.paths)
    }

    /// `state.json` (or a v1 `onebox.conf`) exists. Symlinks count as present
    /// so a tampered layout is reported by `load` instead of being reinstalled over.
    pub fn installed(ctx: &Ctx) -> bool {
        Self::installed_at(&ctx.paths)
    }

    pub fn save(ctx: &Ctx, cfg: &NodeConfig) -> Result<()> {
        Self::save_to(&ctx.paths, cfg)
    }

    /// [`StateStore::load`] on explicit paths; `rng` fills credentials a
    /// v1-era v2 state never had.
    pub fn load_from(paths: &Paths, rng: &mut dyn Random) -> Result<Option<Loaded>> {
        let state = paths.state();
        let Some(bytes) = read_state(&state)? else {
            ensure!(!exists(&paths.legacy_v1_state()), "{V1_MESSAGE}");
            return Ok(None);
        };
        let hash = StateHash::of(&bytes);
        let doc: Value = serde_json::from_slice(&bytes).context("state.json 无效")?;
        let (config, origin) = match detect(&doc)? {
            Format::V2 => migrate_v2(paths, &bytes, rng)?,
            Format::V3(schema) => (parse_v3(schema, doc)?, Origin::V3),
        };
        Ok(Some(Loaded {
            config,
            hash,
            origin,
        }))
    }

    pub fn current_hash_at(paths: &Paths) -> Result<StateHash> {
        Ok(read_state(&paths.state())?.map_or_else(StateHash::absent, |b| StateHash::of(&b)))
    }

    pub fn installed_at(paths: &Paths) -> bool {
        exists(&paths.state()) || exists(&paths.legacy_v1_state())
    }

    /// Validate, then write pretty JSON + newline (0600) atomically; the root
    /// directory is forced to 0700. When the file being replaced is a v2
    /// state, its exact bytes are first kept as `state.v2.json` (0600, never
    /// overwritten). The caller holds the node lock and has checked the CAS
    /// hash, so those bytes are the ones the migration started from.
    pub fn save_to(paths: &Paths, cfg: &NodeConfig) -> Result<()> {
        cfg.validate()?;
        prepare_root(&paths.root)?;
        keep_v2_original(paths)?;
        let mut text = serde_json::to_string_pretty(cfg)?;
        text.push('\n');
        atomic_write(&paths.state(), text.as_bytes(), STATE_MODE)
    }
}

/// `Ok(None)` when the file does not exist; symlinks, non-files and files
/// over 1 MiB are refused.
fn read_state(path: &Path) -> Result<Option<Vec<u8>>> {
    match fs::symlink_metadata(path) {
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(None),
        Err(e) => Err(Error::io(path, e)),
        Ok(_) => read_bounded(path, STATE_MAX_BYTES).map(Some),
    }
}

/// Copy a v2-shaped `state.json` to `state.v2.json` unless a copy exists.
fn keep_v2_original(paths: &Paths) -> Result<()> {
    let backup = paths.state_v2_backup();
    if exists(&backup) {
        return Ok(());
    }
    let Some(bytes) = read_state(&paths.state())? else {
        return Ok(());
    };
    let is_v2 = serde_json::from_slice::<Value>(&bytes)
        .ok()
        .is_some_and(|doc| matches!(detect(&doc), Ok(Format::V2)));
    if is_v2 {
        atomic_write(&backup, &bytes, STATE_MODE)?;
    }
    Ok(())
}

fn exists(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok()
}

enum Format {
    /// `{"values":{…}}`
    V2,
    /// `{"schema":N,…}`
    V3(u32),
}

fn detect(doc: &Value) -> Result<Format> {
    let object = doc.as_object().ok_or("state.json 格式无法识别")?;
    if object.contains_key("values") {
        return Ok(Format::V2);
    }
    let schema = object.get("schema").ok_or("state.json 格式无法识别")?;
    schema
        .as_u64()
        .and_then(|n| u32::try_from(n).ok())
        .map(Format::V3)
        .ok_or_else(|| "state.json 的 schema 无效".into())
}

fn parse_v3(schema: u32, doc: Value) -> Result<NodeConfig> {
    check_schema(schema)?;
    let config: NodeConfig = serde_json::from_value(doc).context("state.json 无效")?;
    config.validate().context("state.json 校验失败")?;
    Ok(config)
}

fn migrate_v2(
    paths: &Paths,
    original: &[u8],
    rng: &mut dyn Random,
) -> Result<(NodeConfig, Origin)> {
    let values = v2::v2_values_from_json(original)?;
    let settings_path = paths.subscription().join("settings.json");
    let settings = match read_state(&settings_path)? {
        Some(bytes) => Some(
            serde_json::from_slice::<Value>(&bytes).context("v2 订阅设置 settings.json 无效")?,
        ),
        None => None,
    };
    let migrated = v2::migrate(&values, settings.as_ref(), rng)?;
    let origin = Origin::V2 {
        devices: migrated.devices,
        warnings: migrated.warnings,
    };
    Ok((migrated.config, origin))
}

/// Create the root (0700) or tighten an existing one; refuse a symlinked root.
fn prepare_root(root: &Path) -> Result<()> {
    match fs::symlink_metadata(root) {
        Ok(meta) if meta.file_type().is_symlink() => {
            bail!("不允许符号链接: {}", root.display())
        }
        Ok(meta) => ensure!(meta.is_dir(), "配置目录不是目录: {}", root.display()),
        Err(e) if e.kind() == ErrorKind::NotFound => fs::DirBuilder::new()
            .recursive(true)
            .mode(ROOT_MODE)
            .create(root)
            .map_err(|e| Error::io(root, e))?,
        Err(e) => return Err(Error::io(root, e)),
    }
    fs::set_permissions(root, fs::Permissions::from_mode(ROOT_MODE)).map_err(|e| Error::io(root, e))
}

#[cfg(test)]
mod tests;
