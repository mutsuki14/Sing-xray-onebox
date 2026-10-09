//! The tree digest recorded for every snapshot slot. Its byte layout is a
//! compatibility contract: journals written by v2 carry these digests and
//! v3 must reproduce them exactly (spec E §5.6).
//!
//! Depth-first from the slot with relative path `""`, children sorted by
//! raw file name; for every node the hash input receives
//! `u64 BE len(rel)`, `rel` (UTF-8), `u32 BE (mode & 0o777)`, then for a
//! file `b'f'` + the 64 lowercase hex digits of its SHA-256, for a
//! directory `b'd'` followed by its children. The digest is the lowercase
//! hex SHA-256 of that input.
//!
//! Changes from v2: the input is hashed while walking and files are hashed
//! in a streaming fashion (v2 read every file, up to 2 GiB each, into
//! memory and buffered the whole manifest; E-8.1#22). The digest is the
//! same.

use crate::error::{Error, Result};
use crate::sys::fs::sha256_file;
use crate::sys::rand::to_hex;
use sha2::{Digest, Sha256};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

/// Largest single file a digest accepts (v2 limit).
pub const MAX_FILE_BYTES: u64 = 2 * 1024 * 1024 * 1024;

/// The v2-compatible digest of the tree (or single file) at `path`.
/// Symlinks and special files anywhere are refused.
pub fn digest_tree(path: &Path) -> Result<String> {
    let mut hasher = Sha256::new();
    walk(path, Path::new(""), &mut hasher)?;
    Ok(to_hex(&hasher.finalize()))
}

fn walk(path: &Path, rel: &Path, hasher: &mut Sha256) -> Result<()> {
    let meta = fs::symlink_metadata(path).map_err(|e| Error::io(path, e))?;
    if meta.file_type().is_symlink() || (!meta.is_file() && !meta.is_dir()) {
        return Err(Error::msg("快照摘要拒绝符号链接或特殊文件"));
    }
    let name = rel
        .to_str()
        .ok_or_else(|| Error::msg(format!("路径不是 UTF-8: {}", path.display())))?;
    hasher.update((name.len() as u64).to_be_bytes());
    hasher.update(name.as_bytes());
    hasher.update((meta.permissions().mode() & 0o777).to_be_bytes());
    if meta.is_file() {
        if meta.len() > MAX_FILE_BYTES {
            return Err(Error::msg("快照单文件超过2GiB"));
        }
        hasher.update(b"f");
        hasher.update(sha256_file(path)?.as_bytes());
        return Ok(());
    }
    hasher.update(b"d");
    let mut names = fs::read_dir(path)
        .map_err(|e| Error::io(path, e))?
        .map(|entry| entry.map(|e| e.file_name()))
        .collect::<std::io::Result<Vec<_>>>()
        .map_err(|e| Error::io(path, e))?;
    names.sort();
    for child in names {
        walk(&path.join(&child), &rel.join(&child), hasher)?;
    }
    Ok(())
}
