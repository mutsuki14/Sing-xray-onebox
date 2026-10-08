//! Probe bundle I/O for the link tools: `probe export|list|merge`, entry
//! selection (`--entries`, the failover pair) and the private output files.
//! The bundle type, its validation and the 2 MiB cap live in
//! [`crate::render::probe`], shared with the client publication.
//!
//! Changes from v2:
//! - `probe merge` needs at least two inputs (README: "合并多份"; v2
//!   accepted one, D-8.1#16), and an id that the `n<i>-` prefix pushes
//!   over 80 characters is named in a clear error instead of the generic
//!   `入口 ID 无效或重复`;
//! - `--entries` ids are trimmed (`a, b` works, D-8.1#12);
//! - outputs are written through `sys::fs::write_new_exclusive`: still
//!   O_EXCL + O_NOFOLLOW + 0600, but a failed write no longer leaves a
//!   partial file behind.

use crate::ctx::Ctx;
use crate::domain::protocol::Transport;
use crate::error::{Error, Result};
use crate::render::probe::{self, ProbeBundle, ProbeEntry, MAX_ID_BYTES};
use crate::render::NodeSpec;
use crate::state::StateStore;
use crate::sys::fs::write_new_exclusive;
use serde_json::Value;
use std::collections::HashSet;
use std::path::Path;

/// Mode of every file the tools create for the user (bundles, reports).
pub const PRIVATE_MODE: u32 = 0o600;

/// Read a bundle file (regular file, ≤ 2 MiB, v2 validation rules).
pub fn load(path: &Path) -> Result<ProbeBundle> {
    ProbeBundle::load(path)
}

/// The installed node's bundle. `local` targets the node from the server
/// itself (server-local REALITY check): loopback address, handshake target
/// as the reference.
pub fn from_node(ctx: &Ctx, local: bool) -> Result<ProbeBundle> {
    let loaded = StateStore::load_required(ctx)?;
    let spec = NodeSpec::load(&loaded.config, &ctx.paths)?;
    probe::bundle(&spec, local)
}

/// `probe merge`: every input's entries in order, ids prefixed `n<i>-`.
pub fn merge(inputs: &[ProbeBundle]) -> Result<ProbeBundle> {
    ensure!(inputs.len() >= 2, "probe merge 至少需要两份探测配置");
    for (i, input) in inputs.iter().enumerate() {
        for entry in &input.entries {
            let id = merged_id(i, &entry.id);
            ensure!(
                id.len() <= MAX_ID_BYTES,
                "合并后的入口 ID 超过 {MAX_ID_BYTES} 个字符: {id}"
            );
        }
    }
    ProbeBundle::merge(inputs)
}

/// The id `ProbeBundle::merge` gives entry `id` of input `index` (0-based).
fn merged_id(index: usize, id: &str) -> String {
    format!("n{}-{id}", index + 1)
}

/// `probe list`: `id<TAB>transport<TAB>core` per entry, no header (v2).
pub fn list_lines(bundle: &ProbeBundle) -> Vec<String> {
    bundle
        .entries
        .iter()
        .map(|e| format!("{}\t{}\t{}", e.id, e.transport.id(), e.core.id()))
        .collect()
}

/// Pretty JSON + `"\n"` (v2 `private_json`).
pub fn json_text(value: &Value) -> Result<String> {
    let mut text = crate::render::pretty(value)?;
    text.push('\n');
    Ok(text)
}

/// Create `path` (must not exist, symlinks refused) with mode 0600.
pub fn write_private(path: &Path, text: &str) -> Result<()> {
    write_new_exclusive(path, text.as_bytes(), PRIVATE_MODE)
}

/// Write a bundle as `probe export` / `probe merge` do.
pub fn write_bundle(path: &Path, bundle: &ProbeBundle) -> Result<()> {
    write_private(path, &json_text(&bundle.to_value()?)?)
}

/// Default entry choice when `--entries` is absent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Selection {
    /// Every entry in bundle order (bench, reality-check).
    All,
    /// The first TCP-capable entry, then the first UDP-only one; the first
    /// entry when neither exists (failover's TCP + QUIC pair).
    Pair,
}

/// The entries to run, in priority order. Explicit ids must exist and be
/// unique; they are trimmed (an empty id is unknown).
pub fn select<'a>(
    bundle: &'a ProbeBundle,
    explicit: Option<&[String]>,
    default: Selection,
) -> Result<Vec<&'a ProbeEntry>> {
    let entries = &bundle.entries;
    if let Some(ids) = explicit {
        let mut seen = HashSet::new();
        return ids
            .iter()
            .map(|raw| {
                let id = raw.trim();
                ensure!(seen.insert(id), "--entries 包含重复的 ID");
                entries
                    .iter()
                    .find(|e| e.id == id)
                    .ok_or_else(|| Error::msg("--entries 包含未知 ID（先执行 probe list）"))
            })
            .collect();
    }
    match default {
        Selection::All => Ok(entries.iter().collect()),
        Selection::Pair => {
            let tcp = entries.iter().find(|e| e.transport.tcp());
            let udp = entries.iter().find(|e| e.transport == Transport::Udp);
            let pair: Vec<&ProbeEntry> = tcp.into_iter().chain(udp).collect();
            Ok(if pair.is_empty() {
                entries.iter().take(1).collect()
            } else {
                pair
            })
        }
    }
}

/// Split a `--entries` value into ids (empty pieces kept: they are errors).
pub fn split_ids(value: &str) -> Vec<String> {
    value.split(',').map(str::to_owned).collect()
}

#[cfg(test)]
mod tests;
