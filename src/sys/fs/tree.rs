//! Tree operations: budgeted recursive copy and skip-aware removal (the
//! primitives behind snapshots, backups and site content imports).

use super::{
    atomic_write_with, ensure_dir, fsync_dir, not_found, open_regular, symlink_error, MODE_MASK,
};
use crate::error::{Error, Result};
use std::fs;
use std::io::{self, Read};
use std::os::unix::fs::PermissionsExt;
use std::path::{Component, Path, PathBuf};

/// Budget for [`copy_tree`], checked before each entry is created so a huge
/// or hostile tree is rejected without filling the destination disk.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CopyLimits {
    /// Total bytes of all copied files.
    pub max_bytes: u64,
    /// Files and directories below the root.
    pub max_entries: usize,
    /// Error text when a limit is exceeded; `None` → `复制内容超过上限: {path}`.
    pub message: Option<&'static str>,
}

impl CopyLimits {
    pub const UNLIMITED: CopyLimits = CopyLimits::new(u64::MAX, usize::MAX);

    pub const fn new(max_bytes: u64, max_entries: usize) -> CopyLimits {
        CopyLimits {
            max_bytes,
            max_entries,
            message: None,
        }
    }

    /// Use a caller-specific message (e.g. v2's `备份超过 4096 文件或 64 MiB 限制`).
    pub const fn message(mut self, message: &'static str) -> CopyLimits {
        self.message = Some(message);
        self
    }

    fn exceeded(&self, path: &Path) -> Error {
        match self.message {
            Some(message) => Error::msg(message),
            None => Error::msg(format!("复制内容超过上限: {}", path.display())),
        }
    }
}

/// What [`copy_tree`] copied.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CopyStats {
    pub bytes: u64,
    /// Files and directories created below the root.
    pub entries: usize,
}

/// Recursively copy `src` to `dst`, streaming file contents and preserving
/// permission bits. `skip(path)` is called with each entry's source path and
/// excludes it (and its subtree). Symlinks and special files anywhere in the
/// tree are refused, and so is a `dst` inside `src` unless it lies in a
/// skipped subtree (a snapshot staged in `ROOT/.transaction`). `limits` is
/// enforced while copying; on any error `dst` may be partially populated and
/// the caller removes it.
pub fn copy_tree(
    src: &Path,
    dst: &Path,
    skip: &dyn Fn(&Path) -> bool,
    limits: &CopyLimits,
) -> Result<CopyStats> {
    check_not_nested(src, dst, skip)?;
    let mut copy = TreeCopy {
        skip,
        limits,
        stats: CopyStats::default(),
    };
    copy.entry(src, dst, true)?;
    Ok(copy.stats)
}

struct TreeCopy<'a> {
    skip: &'a dyn Fn(&Path) -> bool,
    limits: &'a CopyLimits,
    stats: CopyStats,
}

impl TreeCopy<'_> {
    fn entry(&mut self, src: &Path, dst: &Path, root: bool) -> Result<()> {
        let meta = fs::symlink_metadata(src).map_err(|e| Error::io(src, e))?;
        let mode = meta.permissions().mode() & MODE_MASK;
        if meta.file_type().is_symlink() {
            return Err(symlink_error(src));
        }
        if !meta.is_file() && !meta.is_dir() {
            return Err(Error::msg(format!("不支持的特殊文件: {}", src.display())));
        }
        if !root {
            if self.stats.entries >= self.limits.max_entries {
                return Err(self.limits.exceeded(src));
            }
            self.stats.entries += 1;
        }
        if meta.is_file() {
            let remaining = self.limits.max_bytes.saturating_sub(self.stats.bytes);
            if meta.len() > remaining {
                return Err(self.limits.exceeded(src));
            }
            let copied = copy_file_limited(src, dst, mode, remaining)?
                .ok_or_else(|| self.limits.exceeded(src))?;
            self.stats.bytes += copied;
            return Ok(());
        }
        // Fill the directory while it is private and writable; its real mode
        // (possibly read-only) is applied once the children are in place.
        ensure_dir(dst, 0o700)?;
        let mut entries = fs::read_dir(src)
            .map_err(|e| Error::io(src, e))?
            .map(|entry| entry.map(|e| e.file_name()))
            .collect::<io::Result<Vec<_>>>()
            .map_err(|e| Error::io(src, e))?;
        entries.sort();
        for name in entries {
            let child = src.join(&name);
            if !(self.skip)(&child) {
                self.entry(&child, &dst.join(&name), false)?;
            }
        }
        ensure_dir(dst, mode)?;
        fsync_dir(dst).map_err(|e| Error::io(dst, e))
    }
}

/// [`copy_file`] that stops at `max` bytes even if the source grows while it
/// is copied: `Ok(None)` (and no `dst` written) when it is larger.
pub(super) fn copy_file_limited(
    src: &Path,
    dst: &Path,
    mode: u32,
    max: u64,
) -> Result<Option<u64>> {
    let (source, _) = open_regular(src)?;
    let mut copied = 0;
    let mut too_large = false;
    let result = atomic_write_with(dst, mode, |file| {
        copied = io::copy(&mut source.take(max.saturating_add(1)), file)?;
        too_large = copied > max;
        if too_large {
            return Err(io::Error::other("source exceeds the copy limit"));
        }
        Ok(())
    });
    match result {
        Err(_) if too_large => Ok(None),
        Err(e) => Err(e),
        Ok(()) => Ok(Some(copied)),
    }
}

/// Refuse a destination inside the source tree (the copy would recurse into
/// its own output) unless the copy never enters it because a component
/// between `src` and `dst` is skipped. Compared after resolving symlinks in
/// the existing part of both paths.
fn check_not_nested(src: &Path, dst: &Path, skip: &dyn Fn(&Path) -> bool) -> Result<()> {
    let src_real = fs::canonicalize(src).map_err(|e| Error::io(src, e))?;
    let dst_real = resolve_existing(dst)?;
    let Ok(rel) = dst_real.strip_prefix(&src_real) else {
        return Ok(());
    };
    let mut walked = src.to_path_buf();
    for component in rel.components() {
        walked.push(component);
        if skip(&walked) {
            return Ok(());
        }
    }
    Err(Error::msg(format!(
        "复制目标不能位于源目录内: {}",
        dst.display()
    )))
}

/// `path` made absolute, with its longest existing prefix canonicalized and
/// the not-yet-existing rest appended lexically (`.` dropped, `..` popped).
fn resolve_existing(path: &Path) -> Result<PathBuf> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    let components: Vec<Component> = absolute.components().collect();
    for split in (1..=components.len()).rev() {
        let prefix: PathBuf = components[..split].iter().collect();
        match fs::canonicalize(&prefix) {
            Ok(mut resolved) => {
                for component in &components[split..] {
                    match component {
                        Component::ParentDir => {
                            resolved.pop();
                        }
                        Component::CurDir => {}
                        other => resolved.push(other),
                    }
                }
                return Ok(resolved);
            }
            Err(e) if not_found(&e) || e.raw_os_error() == Some(libc::ENOTDIR) => {}
            Err(e) => return Err(Error::io(&prefix, e)),
        }
    }
    Ok(absolute)
}

/// Remove `path` (a file or a directory tree) except the entries for which
/// `skip(entry)` is true; a directory is removed only once it is empty, so
/// directories holding skipped entries stay. Symlinks and special files are
/// refused anywhere in the removed part, checked before anything is deleted.
/// A missing `path` is fine. (Restoring a snapshot clears exactly what the
/// snapshot covers this way; v2 `remove_included`.)
pub fn remove_tree_contents(path: &Path, skip: &dyn Fn(&Path) -> bool) -> Result<()> {
    match fs::symlink_metadata(path) {
        Err(e) if not_found(&e) => return Ok(()),
        Err(e) => return Err(Error::io(path, e)),
        Ok(_) => {}
    }
    walk_removable(path, skip, &mut |_, _| Ok(()))?;
    walk_removable(path, skip, &mut |entry, is_dir| {
        let result = if !is_dir {
            fs::remove_file(entry)
        } else if fs::read_dir(entry)
            .map_err(|e| Error::io(entry, e))?
            .next()
            .is_none()
        {
            fs::remove_dir(entry)
        } else {
            return Ok(());
        };
        match result {
            Err(e) if !not_found(&e) => Err(Error::io(entry, e)),
            _ => Ok(()),
        }
    })
}

/// Post-order walk over the non-skipped entries of `path`, refusing
/// symlinks and special files; `visit(entry, is_dir)` runs after children.
fn walk_removable(
    path: &Path,
    skip: &dyn Fn(&Path) -> bool,
    visit: &mut dyn FnMut(&Path, bool) -> Result<()>,
) -> Result<()> {
    let meta = match fs::symlink_metadata(path) {
        Err(e) if not_found(&e) => return Ok(()),
        Err(e) => return Err(Error::io(path, e)),
        Ok(m) => m,
    };
    if meta.file_type().is_symlink() {
        return Err(symlink_error(path));
    }
    if meta.is_dir() {
        for entry in fs::read_dir(path).map_err(|e| Error::io(path, e))? {
            let child = entry.map_err(|e| Error::io(path, e))?.path();
            if !skip(&child) {
                walk_removable(&child, skip, visit)?;
            }
        }
    } else if !meta.is_file() {
        return Err(Error::msg(format!("不支持的特殊文件: {}", path.display())));
    }
    visit(path, meta.is_dir())
}
