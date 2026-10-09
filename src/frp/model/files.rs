//! The FRP state files: which format is read, the installed rule, loading,
//! saving and the reservations read by the node side.

use super::legacy::{self, parse_state_conf, V2Config};
use super::ports::{PortLayout, StoredPorts};
use super::{FrpState, LEGACY_STATE_FILE, MANAGED_FILE, MAX_STATE_BYTES, SCHEMA, STATE_FILE};
use crate::domain::ports::Reservation;
use crate::error::{Context, Error, Result};
use crate::paths::Paths;
use crate::sys::fs::{atomic_write, read_bounded};
use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};

pub fn state_path(paths: &Paths) -> PathBuf {
    paths.frp_root.join(STATE_FILE)
}

pub fn legacy_state_path(paths: &Paths) -> PathBuf {
    paths.frp_root.join(LEGACY_STATE_FILE)
}

pub fn managed_path(paths: &Paths) -> PathBuf {
    paths.frp_root.join(MANAGED_FILE)
}

/// Present without following a final symlink (a symlinked state file
/// counts as present so that `load` reports it instead of ignoring it).
fn present(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok()
}

/// FRP is installed: `.managed` is a regular file and a state file exists.
pub fn installed(paths: &Paths) -> bool {
    let managed = fs::symlink_metadata(managed_path(paths)).is_ok_and(|m| m.is_file());
    managed && (present(&state_path(paths)) || present(&legacy_state_path(paths)))
}

fn read_state_file(path: &Path) -> Result<Vec<u8>> {
    let meta = fs::symlink_metadata(path).map_err(|e| Error::io(path, e))?;
    ensure!(meta.len() <= MAX_STATE_BYTES, "FRP 状态文件异常大");
    read_bounded(path, MAX_STATE_BYTES)
}

/// The two state formats on disk.
enum Format {
    /// `state.json`: schema 2 or the v2 shape.
    Json,
    /// v1 `state.conf`.
    Conf,
}

/// Parse the state file of an installed FRP (`None` when FRP is not
/// installed) with `parse`: `state.json` when present, else `state.conf`.
/// Errors name the file.
fn read_installed<T>(
    paths: &Paths,
    parse: impl FnOnce(&[u8], Format) -> Result<T>,
) -> Result<Option<T>> {
    if !installed(paths) {
        return Ok(None);
    }
    let json = state_path(paths);
    let (path, format) = if present(&json) {
        (json, Format::Json)
    } else {
        (legacy_state_path(paths), Format::Conf)
    };
    let parsed = read_state_file(&path).and_then(|bytes| parse(&bytes, format));
    parsed
        .with_context(|| format!("FRP 状态 {} 无效", path.display()))
        .map(Some)
}

fn conf_text(bytes: &[u8]) -> Result<&str> {
    std::str::from_utf8(bytes).map_err(|_| Error::msg("旧 FRP 状态不是 UTF-8"))
}

/// The installed FRP state (`None` when FRP is not installed): `state.json`
/// (schema 2 or the v2 shape), else the v1 `state.conf`; validated.
pub fn load(paths: &Paths) -> Result<Option<FrpState>> {
    read_installed(paths, |bytes, format| match format {
        Format::Json => parse_state_json(bytes),
        Format::Conf => parse_state_conf(conf_text(bytes)?),
    })
}

/// `None` for the v2 shape (no `schema` member), else the supported schema.
fn schema_of(doc: &Value) -> Result<Option<u32>> {
    match doc.get("schema").map(Value::as_u64) {
        None => Ok(None),
        Some(Some(2)) => Ok(Some(SCHEMA)),
        Some(Some(n)) if n > 2 => {
            bail!("FRP 配置由更新版本的 Onebox 写入（schema {n}），请先更新程序")
        }
        Some(_) => bail!("FRP 状态 schema 无效"),
    }
}

/// Parse `state.json`: schema 2, or the v2 shape (no `schema` member).
pub fn parse_state_json(bytes: &[u8]) -> Result<FrpState> {
    let doc: Value = serde_json::from_slice(bytes)?;
    let state = match schema_of(&doc)? {
        None => serde_json::from_value::<V2Config>(doc)?.into_state()?,
        Some(_) => serde_json::from_value::<FrpState>(doc)?,
    };
    state.validate()?;
    Ok(state)
}

/// Only the port fields of `state.json` (either shape), checked.
pub fn parse_ports_json(bytes: &[u8]) -> Result<PortLayout> {
    let doc: Value = serde_json::from_slice(bytes)?;
    let layout = match schema_of(&doc)? {
        None => serde_json::from_value::<V2Config>(doc)?.ports()?,
        Some(_) => serde_json::from_value::<StoredPorts>(doc)?.into(),
    };
    layout.check()?;
    Ok(layout)
}

/// Write `state.json` (schema 2, pretty JSON + newline, 0600) atomically
/// after [`FrpState::validate_change`] against the installed state (a
/// state that cannot be read counts as none). `state.conf` is left
/// untouched.
pub fn save(paths: &Paths, state: &FrpState) -> Result<()> {
    let previous = load(paths).ok().flatten();
    state.validate_change(previous.as_ref())?;
    let mut text = serde_json::to_string_pretty(state)?;
    text.push('\n');
    atomic_write(&state_path(paths), text.as_bytes(), 0o600)
}

/// The ports FRP reserves (empty when FRP is not installed), read from the
/// port fields alone. A state whose ports cannot be read is an error naming
/// FRP: other components must not take ports FRP may own.
pub fn reservations(paths: &Paths) -> Result<Vec<Reservation>> {
    let layout = read_installed(paths, |bytes, format| match format {
        Format::Json => parse_ports_json(bytes),
        Format::Conf => legacy::parse_conf_ports(conf_text(bytes)?),
    })?;
    Ok(layout.map(|l| l.reservations()).unwrap_or_default())
}
