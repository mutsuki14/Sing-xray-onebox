//! The published client snapshot `ROOT/subscription/published.json`: every
//! remote client format the configuration supports, rendered at once and
//! switched in one atomic rename, so the worker always serves one complete
//! generation (v2 shape `{"generation","formats"}`, compact JSON, sorted
//! keys, 0600; v2 workers read v3 snapshots and the reverse).
//!
//! Only client documents are published — never server configurations,
//! keys, `probe.json` or any file named by a request.
//!
//! Changes from v2: a snapshot is removed when the subscription is
//! disabled or the node is reinstalled (v2 left full credentials on disk,
//! G-8.1#12); reads are size-bounded.

use crate::domain::protocol::ClientFormat;
use crate::domain::NodeConfig;
use crate::error::{Context, Error, Result};
use crate::paths::Paths;
use crate::render::NodeSpec;
use crate::sys::fs::{atomic_write, read_bounded, remove_file_if_exists};
use crate::sys::rand::{OsRandom, Random};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Largest body of one format (v2 limit).
pub const MAX_BODY_BYTES: usize = 8 * 1024 * 1024;
/// Largest `published.json` read (six bodies, JSON-escaped).
pub const MAX_FILE_BYTES: u64 = 128 * 1024 * 1024;
pub const NOTHING: &str = "没有可发布的客户端配置";
pub const TOO_LARGE: &str = "客户端配置过大";

/// `published.json`. `generation` (24 lowercase hex) is random per publish
/// and only tells generations apart.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Published {
    pub generation: String,
    pub formats: BTreeMap<String, String>,
}

impl Published {
    /// The body of `format`, if published.
    pub fn body(&self, format: ClientFormat) -> Option<&str> {
        self.formats.get(format.id()).map(String::as_str)
    }

    /// Published formats in `ClientFormat::REMOTE` order.
    pub fn published_formats(&self) -> Vec<ClientFormat> {
        ClientFormat::REMOTE
            .into_iter()
            .filter(|f| self.formats.contains_key(f.id()))
            .collect()
    }
}

/// Remote formats with at least one enabled protocol, in v2 order. URLs
/// and the snapshot are both derived from this, never from the file.
pub fn supported_formats(cfg: &NodeConfig) -> Vec<ClientFormat> {
    ClientFormat::REMOTE
        .into_iter()
        .filter(|f| cfg.protocols().any(|p| f.supports(p)))
        .collect()
}

/// Render every supported remote format of `spec` (nothing is written).
pub fn render(spec: &NodeSpec) -> Result<Published> {
    render_with(spec, &mut OsRandom)
}

/// [`render`] with injected randomness for the generation id.
pub fn render_with(spec: &NodeSpec, rng: &mut dyn Random) -> Result<Published> {
    let mut formats = BTreeMap::new();
    for format in ClientFormat::REMOTE {
        if spec.for_format(format).is_empty() {
            continue;
        }
        let body = crate::render::client(spec, format)?;
        check_body(format, &body)?;
        formats.insert(format.id().to_owned(), body);
    }
    ensure!(!formats.is_empty(), "{NOTHING}");
    Ok(Published {
        generation: rng.hex(12)?,
        formats,
    })
}

/// A body must be non-blank and at most 8 MiB (v2 rules).
pub fn check_body(format: ClientFormat, body: &str) -> Result<()> {
    ensure!(!body.trim().is_empty(), "{format} 客户端配置为空");
    ensure!(body.len() <= MAX_BODY_BYTES, "{TOO_LARGE}");
    Ok(())
}

/// Atomically replace `published.json`.
pub fn write(paths: &Paths, snapshot: &Published) -> Result<()> {
    crate::sys::fs::ensure_dir(&paths.subscription(), 0o700)?;
    atomic_write(&paths.published(), &serde_json::to_vec(snapshot)?, 0o600)
}

/// The current snapshot; `None` when none is published.
pub fn load(paths: &Paths) -> Result<Option<Published>> {
    let path = paths.published();
    match std::fs::symlink_metadata(&path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(Error::io(&path, e)),
        Ok(_) => {}
    }
    let bytes = read_bounded(&path, MAX_FILE_BYTES)?;
    serde_json::from_slice(&bytes)
        .map(Some)
        .context("订阅快照 published.json 无效")
}

/// Delete `published.json` (disable, reinstall). Returns whether it existed.
pub fn remove(paths: &Paths) -> Result<bool> {
    remove_file_if_exists(&paths.published())
}

#[cfg(test)]
mod tests;
