//! Atomic publication of the client directory (`ROOT/client`).
//!
//! Everything is rendered in memory first; only then is a private stage
//! directory written and swapped with the live one in a single
//! `renameat2(RENAME_EXCHANGE)`, so readers never see a mix of old and new
//! credentials or a half-written file, and a render error leaves the old
//! directory byte-identical. The swapped-out old directory is removed.
//!
//! Resulting layout: directory 0700, files 0600; formats the current
//! protocols do not support disappear (the directory is replaced as a whole,
//! including files a user put there).
//!
//! Changes from v2: stale stage directories left by crashed runs are swept
//! first, and a failed cleanup is reported as a warning (v2 ignored it and
//! could leave the previous credentials behind, C-8.1 #15); nothing touches
//! the disk when rendering fails.

use super::spec::NodeSpec;
use super::{client, probe};
use crate::error::{Error, Result};
use crate::paths::Paths;
use crate::sys::fs::{
    fsync_dir, remove_tree_if_exists, rename_exchange, sweep_stale, write_new_exclusive,
};
use std::fs;
use std::io::ErrorKind;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::Path;
use std::time::Duration;

const DIR_MODE: u32 = 0o700;
const FILE_MODE: u32 = 0o600;
/// Name of the probe bundle inside the client directory.
pub const PROBE_FILE: &str = "probe.json";

/// Outcome of a successful publication.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Published {
    /// Non-fatal problems for the caller to show (`ui::out::warn`).
    pub warnings: Vec<String>,
}

/// Render every client file of `spec`: each supported format (v2 order and
/// file names) plus `probe.json` (pretty JSON without trailing newline).
pub fn client_files(spec: &NodeSpec) -> Result<Vec<(String, Vec<u8>)>> {
    let mut files = Vec::new();
    for format in spec.formats() {
        files.push((
            format.file_name().to_owned(),
            client(spec, format)?.into_bytes(),
        ));
    }
    let probe = probe::bundle(spec, false)?.to_json()?;
    files.push((PROBE_FILE.to_owned(), probe.into_bytes()));
    Ok(files)
}

/// Render and atomically publish `ROOT/client`. The caller holds the node lock.
pub fn write_clients(paths: &Paths, spec: &NodeSpec) -> Result<Published> {
    replace_dir(&paths.clients(), &client_files(spec)?)
}

/// Replace directory `target` with exactly `files` (`(name, bytes)`, plain
/// file names) atomically. Callers serialize publications of one target.
pub fn replace_dir(target: &Path, files: &[(String, Vec<u8>)]) -> Result<Published> {
    let (parent, name) = split(target)?;
    check_names(files)?;
    check_target(target)?;
    ensure_parent(parent)?;
    let prefix = format!(".{name}-new-");
    let mut published = Published::default();
    // The node lock makes every existing stage directory a crash leftover.
    if let Err(e) = sweep_stale(parent, &prefix, Duration::ZERO) {
        published
            .warnings
            .push(format!("清理残留的临时目录失败: {e}"));
    }
    let stage = parent.join(format!("{prefix}{}", crate::sys::rand::hex(12)?));
    let result = fill_and_swap(&stage, target, parent, files);
    let cleanup = remove_tree_if_exists(&stage);
    match (result, cleanup) {
        (Ok(()), Ok(_)) => Ok(published),
        (Ok(()), Err(e)) => {
            published.warnings.push(format!(
                "旧目录 {} 清理失败（含旧凭据，请手动删除）: {e}",
                stage.display()
            ));
            Ok(published)
        }
        (Err(e), Ok(_)) => Err(e),
        (Err(e), Err(c)) => Err(Error::msg(format!(
            "{e}；临时目录 {} 清理失败: {c}",
            stage.display()
        ))),
    }
}

fn split(target: &Path) -> Result<(&Path, &str)> {
    let parent = target.parent().filter(|p| !p.as_os_str().is_empty());
    let name = target.file_name().and_then(|n| n.to_str());
    match (parent, name) {
        (Some(parent), Some(name)) => Ok((parent, name)),
        _ => Err(Error::msg(format!("发布目录无效: {}", target.display()))),
    }
}

fn check_names(files: &[(String, Vec<u8>)]) -> Result<()> {
    for (i, (name, _)) in files.iter().enumerate() {
        let plain = !name.is_empty() && name != "." && name != ".." && !name.contains(['/', '\0']);
        ensure!(plain, "发布文件名无效: {name:?}");
        ensure!(
            !files[..i].iter().any(|(other, _)| other == name),
            "发布文件名重复: {name}"
        );
    }
    Ok(())
}

/// The live directory must be a real directory (or absent).
fn check_target(target: &Path) -> Result<()> {
    match fs::symlink_metadata(target) {
        Ok(m) if m.file_type().is_symlink() => {
            bail!("不允许符号链接: {}", target.display())
        }
        Ok(m) if !m.is_dir() => bail!("客户端目录路径不是目录: {}", target.display()),
        Ok(_) => Ok(()),
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(()),
        Err(e) => Err(Error::io(target, e)),
    }
}

fn ensure_parent(parent: &Path) -> Result<()> {
    if parent.is_dir() {
        return Ok(());
    }
    fs::DirBuilder::new()
        .recursive(true)
        .mode(DIR_MODE)
        .create(parent)
        .map_err(|e| Error::io(parent, e))
}

fn fill_and_swap(
    stage: &Path,
    target: &Path,
    parent: &Path,
    files: &[(String, Vec<u8>)],
) -> Result<()> {
    fs::DirBuilder::new()
        .mode(DIR_MODE)
        .create(stage)
        .map_err(|e| Error::io(stage, e))?;
    fs::set_permissions(stage, fs::Permissions::from_mode(DIR_MODE))
        .map_err(|e| Error::io(stage, e))?;
    for (name, bytes) in files {
        write_new_exclusive(&stage.join(name), bytes, FILE_MODE)?;
    }
    swap(stage, target)?;
    fsync_dir(parent).map_err(|e| Error::io(parent, e))
}

/// Exchange when the target exists (the old tree lands in `stage`), plain
/// rename otherwise.
fn swap(stage: &Path, target: &Path) -> Result<()> {
    let exists = fs::symlink_metadata(target).is_ok();
    let result = if exists {
        rename_exchange(stage, target)
    } else {
        fs::rename(stage, target)
    };
    result.map_err(|e| {
        Error::msg(format!(
            "无法原子替换客户端目录，原目录保持不变: {}",
            Error::io(target, e)
        ))
    })
}

#[cfg(test)]
mod tests;
