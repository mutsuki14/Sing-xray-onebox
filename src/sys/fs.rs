//! Filesystem primitives: atomic writes, exclusive creates, bounded reads,
//! owned-tree symlink safety, budgeted tree copy, skip-aware tree removal,
//! stale temp sweeping.
//!
//! Changes from v2: missing parents are created 0700 instead of with the
//! umask (A-8.1#20); temp files carry a common prefix so crashes can be
//! swept; copies stream instead of reading whole files (E-8.1#22); the
//! symlink rule applies only below Onebox-owned roots, so distributions
//! where `/etc/init.d` or `/var/run` are symlinks keep working (E-8.1#6);
//! tree copies enforce their size budget while copying (v2 checked after
//! reading whole files) and count directories too.

use crate::error::{Error, Result};
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};
use std::time::{Duration, SystemTime};

mod exchange;
mod tree;

pub use exchange::rename_exchange;
pub use tree::{copy_tree, remove_tree_contents, CopyLimits, CopyStats};

/// Name prefix of every temp file created by [`atomic_write`] and
/// [`copy_file`]; [`sweep_stale`] with this prefix removes crash leftovers.
pub const TEMP_PREFIX: &str = ".onebox-tmp-";

/// Permission bits preserved by copies (setuid/setgid/sticky are dropped).
const MODE_MASK: u32 = 0o777;

fn not_found(e: &io::Error) -> bool {
    e.kind() == io::ErrorKind::NotFound
}

fn symlink_error(path: &Path) -> Error {
    Error::msg(format!("不允许符号链接: {}", path.display()))
}

fn parent_of(path: &Path) -> Result<&Path> {
    path.parent()
        .filter(|p| !p.as_os_str().is_empty())
        .ok_or_else(|| Error::msg(format!("路径没有父目录: {}", path.display())))
}

/// Create `dir` and its missing ancestors with mode 0700; existing
/// directories are left untouched.
fn create_parents(dir: &Path) -> Result<()> {
    if dir.exists() {
        return Ok(());
    }
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
        .map_err(|e| Error::io(dir, e))
}

fn temp_sibling(path: &Path) -> Result<PathBuf> {
    let parent = parent_of(path)?;
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    // Keep the temp name well below NAME_MAX (255) whatever the target name.
    let short: String = name.chars().take(64).collect();
    Ok(parent.join(format!(
        "{TEMP_PREFIX}{short}-{}",
        crate::sys::rand::hex(12)?
    )))
}

/// Atomically replace `path` with whatever `fill` writes: temp file in the
/// same directory (create_new, O_NOFOLLOW), fsync, exact chmod, rename,
/// fsync the directory. On error the temp file is removed and the old
/// content stays intact.
fn atomic_write_with(
    path: &Path,
    mode: u32,
    fill: impl FnOnce(&mut File) -> io::Result<()>,
) -> Result<()> {
    let parent = parent_of(path)?;
    create_parents(parent)?;
    let temp = temp_sibling(path)?;
    let result = (|| -> io::Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&temp)?;
        fill(&mut file)?;
        file.sync_all()?;
        // fchmod: the create mode was filtered by the umask.
        file.set_permissions(fs::Permissions::from_mode(mode))?;
        fs::rename(&temp, path)?;
        fsync_dir(parent)
    })();
    if let Err(e) = result {
        let _ = fs::remove_file(&temp);
        return Err(Error::io(path, e));
    }
    Ok(())
}

/// Replace `path` atomically with `bytes` (see [`atomic_write_with`]).
/// Missing parents are created with mode 0700.
pub fn atomic_write(path: &Path, bytes: &[u8], mode: u32) -> Result<()> {
    atomic_write_with(path, mode, |file| file.write_all(bytes))
}

/// Create a new file that must not exist yet (O_EXCL also refuses a
/// symlink at `path`). For files the user asked us to write, where silently
/// replacing something would be wrong. The parent must exist.
pub fn write_new_exclusive(path: &Path, bytes: &[u8], mode: u32) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|e| match e.kind() {
            io::ErrorKind::AlreadyExists => Error::msg(format!("目标已存在: {}", path.display())),
            _ => Error::io(path, e),
        })?;
    let result = (|| -> io::Result<()> {
        file.write_all(bytes)?;
        file.sync_all()?;
        file.set_permissions(fs::Permissions::from_mode(mode))?;
        match path.parent().filter(|p| !p.as_os_str().is_empty()) {
            Some(parent) => fsync_dir(parent),
            None => Ok(()),
        }
    })();
    if let Err(e) = result {
        drop(file);
        let _ = fs::remove_file(path);
        return Err(Error::io(path, e));
    }
    Ok(())
}

/// Make sure `path` is a real directory with exactly `mode`. Missing
/// ancestors are created 0700; a symlink or non-directory is refused. The
/// chmod goes through an O_NOFOLLOW descriptor so it cannot be redirected.
pub fn ensure_dir(path: &Path, mode: u32) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(m) if m.file_type().is_symlink() => return Err(symlink_error(path)),
        Ok(m) if !m.is_dir() => {
            return Err(Error::msg(format!("不是目录: {}", path.display())));
        }
        Ok(_) => {}
        Err(e) if not_found(&e) => {
            if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
                create_parents(parent)?;
            }
            match fs::DirBuilder::new().mode(mode).create(path) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(Error::io(path, e)),
            }
        }
        Err(e) => return Err(Error::io(path, e)),
    }
    let dir = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|e| match e.raw_os_error() {
            Some(libc::ELOOP) => symlink_error(path),
            Some(libc::ENOTDIR) => Error::msg(format!("不是目录: {}", path.display())),
            _ => Error::io(path, e),
        })?;
    dir.set_permissions(fs::Permissions::from_mode(mode))
        .map_err(|e| Error::io(path, e))
}

/// fsync a directory so a rename inside it is durable.
pub fn fsync_dir(dir: &Path) -> std::io::Result<()> {
    File::open(dir)?.sync_all()
}

fn invalid_file(path: &Path) -> Error {
    Error::msg(format!("文件类型或大小无效: {}", path.display()))
}

/// Open a regular file for reading without following a final symlink.
fn open_regular(path: &Path) -> Result<(File, fs::Metadata)> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)
        .map_err(|e| match e.raw_os_error() {
            Some(libc::ELOOP) => symlink_error(path),
            _ => Error::io(path, e),
        })?;
    let meta = file.metadata().map_err(|e| Error::io(path, e))?;
    if !meta.is_file() {
        return Err(invalid_file(path));
    }
    Ok((file, meta))
}

/// Read a regular, non-symlink file of at most `max` bytes.
pub fn read_bounded(path: &Path, max: u64) -> Result<Vec<u8>> {
    let (file, meta) = open_regular(path)?;
    if meta.len() > max {
        return Err(invalid_file(path));
    }
    let mut buf = Vec::with_capacity(meta.len() as usize);
    file.take(max + 1)
        .read_to_end(&mut buf)
        .map_err(|e| Error::io(path, e))?;
    if buf.len() as u64 > max {
        return Err(invalid_file(path));
    }
    Ok(buf)
}

/// [`read_bounded`] for UTF-8 text.
pub fn read_to_string_bounded(path: &Path, max: u64) -> Result<String> {
    String::from_utf8(read_bounded(path, max)?)
        .map_err(|_| Error::msg(format!("文件不是有效的 UTF-8: {}", path.display())))
}

/// True when `path` itself is a symlink (dangling links included).
pub fn is_symlink(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_symlink())
}

/// Remove a file or symlink (never what it points to). Returns whether
/// something was removed; a directory is refused.
pub fn remove_file_if_exists(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Err(e) if not_found(&e) => Ok(false),
        Err(e) => Err(Error::io(path, e)),
        Ok(m) if m.is_dir() => Err(Error::msg(format!("不是文件: {}", path.display()))),
        Ok(_) => match fs::remove_file(path) {
            Ok(()) => Ok(true),
            Err(e) if not_found(&e) => Ok(false),
            Err(e) => Err(Error::io(path, e)),
        },
    }
}

/// Remove a directory tree or a single file. A symlink as the root is
/// refused (the caller named a managed path, so a link there is suspicious);
/// symlinks inside the tree are removed as links, never followed.
pub fn remove_tree_if_exists(path: &Path) -> Result<bool> {
    let meta = match fs::symlink_metadata(path) {
        Err(e) if not_found(&e) => return Ok(false),
        Err(e) => return Err(Error::io(path, e)),
        Ok(m) => m,
    };
    if meta.file_type().is_symlink() {
        return Err(symlink_error(path));
    }
    let result = if meta.is_dir() {
        fs::remove_dir_all(path)
    } else {
        fs::remove_file(path)
    };
    match result {
        Ok(()) => Ok(true),
        Err(e) if not_found(&e) => Ok(false),
        Err(e) => Err(Error::io(path, e)),
    }
}

/// Copy a regular, non-symlink file to `dst` atomically with exactly `mode`.
pub fn copy_file(src: &Path, dst: &Path, mode: u32) -> Result<u64> {
    let (mut source, _) = open_regular(src)?;
    let mut copied = 0;
    atomic_write_with(dst, mode, |file| {
        copied = io::copy(&mut source, file)?;
        Ok(())
    })?;
    Ok(copied)
}

/// Remove entries of `dir` whose name starts with `prefix` and whose mtime
/// is at least `min_age` old (crash leftovers: temp files, staging dirs).
/// A missing `dir` is fine. Returns how many entries were removed.
pub fn sweep_stale(dir: &Path, prefix: &str, min_age: Duration) -> Result<usize> {
    // An empty prefix would match (and delete) everything in `dir`.
    if prefix.is_empty() {
        return Err(Error::msg("清理前缀不能为空"));
    }
    let entries = match fs::read_dir(dir) {
        Err(e) if not_found(&e) => return Ok(0),
        Err(e) => return Err(Error::io(dir, e)),
        Ok(entries) => entries,
    };
    let now = SystemTime::now();
    let mut removed = 0;
    for entry in entries {
        let entry = entry.map_err(|e| Error::io(dir, e))?;
        if !entry.file_name().as_bytes().starts_with(prefix.as_bytes()) {
            continue;
        }
        let path = entry.path();
        let meta = match fs::symlink_metadata(&path) {
            Err(e) if not_found(&e) => continue,
            Err(e) => return Err(Error::io(&path, e)),
            Ok(m) => m,
        };
        // A future mtime (clock jump) means "not stale": never guess.
        let age = meta
            .modified()
            .ok()
            .and_then(|t| now.duration_since(t).ok());
        if age.is_none_or(|age| age < min_age) {
            continue;
        }
        let result = if meta.is_dir() {
            fs::remove_dir_all(&path)
        } else {
            fs::remove_file(&path)
        };
        match result {
            Ok(()) => removed += 1,
            Err(e) if not_found(&e) => {}
            Err(e) => return Err(Error::io(&path, e)),
        }
    }
    Ok(removed)
}

/// Lowercase hex SHA-256 of `bytes`.
pub fn sha256_hex(bytes: &[u8]) -> String {
    crate::sys::rand::to_hex(&Sha256::digest(bytes))
}

/// Streaming lowercase hex SHA-256 of a regular, non-symlink file.
pub fn sha256_file(path: &Path) -> Result<String> {
    let (mut file, _) = open_regular(path)?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = match file.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(Error::io(path, e)),
        };
        hasher.update(&buf[..n]);
    }
    Ok(crate::sys::rand::to_hex(&hasher.finalize()))
}

/// Path-safety rule for Onebox-owned trees: `path` must lie under
/// `owned_root` (lexically, without `..`), and no existing component below
/// `owned_root` may be a symlink. `owned_root` itself and its ancestors are
/// trusted as configured (they may be distro symlinks such as `/var/run`).
/// Non-existent tails are fine (they are about to be created).
pub fn check_owned(owned_root: &Path, path: &Path) -> Result<()> {
    let rel = path.strip_prefix(owned_root).map_err(|_| {
        Error::msg(format!(
            "路径不在托管目录 {} 内: {}",
            owned_root.display(),
            path.display()
        ))
    })?;
    if !rel.components().all(|c| matches!(c, Component::Normal(_))) {
        return Err(Error::msg(format!(
            "路径不能包含 .. 或特殊组件: {}",
            path.display()
        )));
    }
    let mut current = owned_root.to_path_buf();
    for component in rel.components() {
        current.push(component);
        match fs::symlink_metadata(&current) {
            Ok(m) if m.file_type().is_symlink() => return Err(symlink_error(&current)),
            Ok(_) => {}
            Err(e) if not_found(&e) => return Ok(()),
            Err(e) => return Err(Error::io(&current, e)),
        }
    }
    Ok(())
}

/// A private (0700) temporary directory removed on drop. Used for staging
/// and by tests.
#[derive(Debug)]
pub struct TempDir {
    path: PathBuf,
}

impl TempDir {
    /// Create `{std::env::temp_dir()}/onebox-{label}-{random}`.
    pub fn new(label: &str) -> Result<TempDir> {
        Self::new_in(&std::env::temp_dir(), label)
    }

    /// Create `{parent}/onebox-{label}-{random}`; `parent` must exist.
    pub fn new_in(parent: &Path, label: &str) -> Result<TempDir> {
        let path = parent.join(format!("onebox-{label}-{}", crate::sys::rand::hex(8)?));
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .map_err(|e| Error::io(&path, e))?;
        Ok(TempDir { path })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// `self.path().join(rel)`.
    pub fn join(&self, rel: impl AsRef<Path>) -> PathBuf {
        self.path.join(rel)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

#[cfg(test)]
mod tests;
