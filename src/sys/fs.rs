//! Filesystem primitives: atomic writes, exclusive creates, bounded reads,
//! owned-tree symlink safety, tree copy/remove, stale temp sweeping.
//!
//! Changes from v2: missing parents are created 0700 instead of with the
//! umask (A-8.1#20); temp files carry a common prefix so crashes can be
//! swept; copies stream instead of reading whole files (E-8.1#22); the
//! symlink rule applies only below Onebox-owned roots, so distributions
//! where `/etc/init.d` or `/var/run` are symlinks keep working (E-8.1#6).

use crate::error::{Error, Result};
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};
use std::time::{Duration, SystemTime};

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

/// Recursively copy `src` to `dst`, streaming file contents and preserving
/// permission bits. `skip(path)` is called with each entry's source path and
/// excludes it (and its subtree). Symlinks and special files anywhere in the
/// tree are refused. Returns the number of file bytes copied.
pub fn copy_tree(src: &Path, dst: &Path, skip: &dyn Fn(&Path) -> bool) -> Result<u64> {
    let mut total = 0u64;
    copy_entry(src, dst, skip, &mut total)?;
    Ok(total)
}

fn copy_entry(src: &Path, dst: &Path, skip: &dyn Fn(&Path) -> bool, total: &mut u64) -> Result<()> {
    let meta = fs::symlink_metadata(src).map_err(|e| Error::io(src, e))?;
    let mode = meta.permissions().mode() & MODE_MASK;
    if meta.file_type().is_symlink() {
        return Err(symlink_error(src));
    }
    if meta.is_file() {
        *total = total.saturating_add(copy_file(src, dst, mode)?);
        return Ok(());
    }
    if !meta.is_dir() {
        return Err(Error::msg(format!("不支持的特殊文件: {}", src.display())));
    }
    ensure_dir(dst, mode)?;
    let mut entries = fs::read_dir(src)
        .map_err(|e| Error::io(src, e))?
        .map(|entry| entry.map(|e| e.file_name()))
        .collect::<io::Result<Vec<_>>>()
        .map_err(|e| Error::io(src, e))?;
    entries.sort();
    for name in entries {
        let child = src.join(&name);
        if !skip(&child) {
            copy_entry(&child, &dst.join(&name), skip, total)?;
        }
    }
    fsync_dir(dst).map_err(|e| Error::io(dst, e))
}

/// Remove entries of `dir` whose name starts with `prefix` and whose mtime
/// is at least `min_age` old (crash leftovers: temp files, staging dirs).
/// A missing `dir` is fine. Returns how many entries were removed.
pub fn sweep_stale(dir: &Path, prefix: &str, min_age: Duration) -> Result<usize> {
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
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    fn mode_of(path: &Path) -> u32 {
        fs::symlink_metadata(path).unwrap().permissions().mode() & 0o7777
    }

    fn tmp() -> TempDir {
        TempDir::new("fs-test").unwrap()
    }

    #[test]
    fn atomic_write_and_bounded_read() {
        let dir = tmp();
        let file = dir.join("a/b/state.json");
        atomic_write(&file, b"{}", 0o600).unwrap();
        atomic_write(&file, b"{\"x\":1}", 0o600).unwrap();
        assert_eq!(read_bounded(&file, 100).unwrap(), b"{\"x\":1}");
        assert!(read_bounded(&file, 3).is_err());
        assert_eq!(mode_of(&file), 0o600);
        assert_eq!(mode_of(&dir.join("a")), 0o700);
        let link = dir.join("link");
        symlink(&file, &link).unwrap();
        assert!(read_bounded(&link, 100).is_err());
        assert!(read_bounded(dir.path(), 100).is_err());
        // No temp files survive.
        let names: Vec<_> = fs::read_dir(dir.join("a/b")).unwrap().collect();
        assert_eq!(names.len(), 1);
    }

    #[test]
    fn atomic_write_sets_exact_mode_despite_umask() {
        let dir = tmp();
        let file = dir.join("x");
        atomic_write(&file, b"1", 0o644).unwrap();
        assert_eq!(mode_of(&file), 0o644);
        atomic_write(&file, b"2", 0o600).unwrap();
        assert_eq!(mode_of(&file), 0o600);
    }

    #[test]
    fn atomic_write_replaces_a_symlink_instead_of_following_it() {
        let dir = tmp();
        let victim = dir.join("victim");
        fs::write(&victim, b"keep").unwrap();
        let link = dir.join("link");
        symlink(&victim, &link).unwrap();
        atomic_write(&link, b"new", 0o600).unwrap();
        assert_eq!(fs::read(&victim).unwrap(), b"keep");
        assert!(!is_symlink(&link));
        assert_eq!(fs::read(&link).unwrap(), b"new");
    }

    #[test]
    fn atomic_write_failure_keeps_old_content() {
        let dir = tmp();
        let target = dir.join("dir-target");
        fs::create_dir(&target).unwrap();
        fs::write(target.join("inner"), b"x").unwrap();
        // rename(file, non-empty dir) fails; the directory must be untouched.
        assert!(atomic_write(&target, b"data", 0o600).is_err());
        assert!(target.join("inner").exists());
        let leftovers = fs::read_dir(dir.path())
            .unwrap()
            .filter(|e| {
                e.as_ref()
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .starts_with(TEMP_PREFIX)
            })
            .count();
        assert_eq!(leftovers, 0);
    }

    #[test]
    fn exclusive_write() {
        let dir = tmp();
        let file = dir.join("out.yaml");
        write_new_exclusive(&file, b"a", 0o640).unwrap();
        assert_eq!(mode_of(&file), 0o640);
        let err = write_new_exclusive(&file, b"b", 0o600).unwrap_err();
        assert_eq!(err.to_string(), format!("目标已存在: {}", file.display()));
        assert_eq!(fs::read(&file).unwrap(), b"a");
        let link = dir.join("dangling");
        symlink(dir.join("nowhere"), &link).unwrap();
        assert!(write_new_exclusive(&link, b"x", 0o600).is_err());
        assert!(!dir.join("nowhere").exists());
    }

    #[test]
    fn ensure_dir_modes_and_refusals() {
        let dir = tmp();
        let deep = dir.join("p/q/r");
        ensure_dir(&deep, 0o750).unwrap();
        assert_eq!(mode_of(&deep), 0o750);
        assert_eq!(mode_of(&dir.join("p")), 0o700);
        ensure_dir(&deep, 0o711).unwrap();
        assert_eq!(mode_of(&deep), 0o711);
        let link = dir.join("link");
        symlink(&deep, &link).unwrap();
        assert!(ensure_dir(&link, 0o700)
            .unwrap_err()
            .to_string()
            .contains("不允许符号链接"));
        let file = dir.join("file");
        fs::write(&file, b"").unwrap();
        assert!(ensure_dir(&file, 0o700)
            .unwrap_err()
            .to_string()
            .contains("不是目录"));
    }

    #[test]
    fn string_reads() {
        let dir = tmp();
        let file = dir.join("t");
        fs::write(&file, "节点").unwrap();
        assert_eq!(read_to_string_bounded(&file, 10).unwrap(), "节点");
        fs::write(&file, [0xff, 0xfe]).unwrap();
        assert!(read_to_string_bounded(&file, 10)
            .unwrap_err()
            .to_string()
            .contains("UTF-8"));
    }

    #[test]
    fn removals() {
        let dir = tmp();
        let file = dir.join("f");
        fs::write(&file, b"").unwrap();
        assert!(remove_file_if_exists(&file).unwrap());
        assert!(!remove_file_if_exists(&file).unwrap());
        assert!(remove_file_if_exists(dir.path()).is_err());

        let tree = dir.join("tree");
        fs::create_dir_all(tree.join("a/b")).unwrap();
        fs::write(tree.join("a/b/c"), b"").unwrap();
        let outside = dir.join("outside");
        fs::create_dir(&outside).unwrap();
        fs::write(outside.join("keep"), b"").unwrap();
        symlink(&outside, tree.join("a/link")).unwrap();
        assert!(remove_tree_if_exists(&tree).unwrap());
        assert!(!tree.exists());
        assert!(
            outside.join("keep").exists(),
            "links inside are not followed"
        );
        assert!(!remove_tree_if_exists(&tree).unwrap());

        let root_link = dir.join("root-link");
        symlink(&outside, &root_link).unwrap();
        assert!(remove_tree_if_exists(&root_link).is_err());
        assert!(outside.join("keep").exists());
    }

    #[test]
    fn file_copy() {
        let dir = tmp();
        let src = dir.join("src");
        fs::write(&src, b"payload").unwrap();
        let dst = dir.join("new/dst");
        assert_eq!(copy_file(&src, &dst, 0o640).unwrap(), 7);
        assert_eq!(fs::read(&dst).unwrap(), b"payload");
        assert_eq!(mode_of(&dst), 0o640);
        let link = dir.join("link");
        symlink(&src, &link).unwrap();
        assert!(copy_file(&link, &dir.join("x"), 0o600).is_err());
    }

    #[test]
    fn tree_copy_preserves_modes_and_skips() {
        let dir = tmp();
        let src = dir.join("src");
        fs::create_dir_all(src.join("sub/deeper")).unwrap();
        fs::write(src.join("a"), b"12345").unwrap();
        fs::set_permissions(src.join("a"), fs::Permissions::from_mode(0o640)).unwrap();
        fs::write(src.join("sub/b"), b"xy").unwrap();
        fs::set_permissions(src.join("sub/b"), fs::Permissions::from_mode(0o755)).unwrap();
        fs::write(src.join("sub/skip.me"), b"no").unwrap();
        fs::set_permissions(src.join("sub"), fs::Permissions::from_mode(0o750)).unwrap();
        let dst = dir.join("dst");
        let skip = |p: &Path| p.extension().is_some_and(|e| e == "me");
        assert_eq!(copy_tree(&src, &dst, &skip).unwrap(), 7);
        assert_eq!(fs::read(dst.join("a")).unwrap(), b"12345");
        assert_eq!(mode_of(&dst.join("a")), 0o640);
        assert_eq!(mode_of(&dst.join("sub/b")), 0o755);
        assert_eq!(mode_of(&dst.join("sub")), 0o750);
        assert!(dst.join("sub/deeper").is_dir());
        assert!(!dst.join("sub/skip.me").exists());
    }

    #[test]
    fn tree_copy_refuses_symlinks_and_special_files() {
        let dir = tmp();
        let src = dir.join("src");
        fs::create_dir(&src).unwrap();
        symlink("/etc/passwd", src.join("evil")).unwrap();
        let err = copy_tree(&src, &dir.join("dst"), &|_| false).unwrap_err();
        assert!(err.to_string().contains("不允许符号链接"), "{err}");
        // Whitelisting by skip works.
        copy_tree(&src, &dir.join("dst2"), &|p| p.ends_with("evil")).unwrap();

        let fifo_dir = dir.join("fifo");
        fs::create_dir(&fifo_dir).unwrap();
        let fifo = fifo_dir.join("pipe");
        let c = std::ffi::CString::new(fifo.as_os_str().as_bytes()).unwrap();
        // SAFETY: valid NUL-terminated path; mkfifo has no other preconditions.
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
        let err = copy_tree(&fifo_dir, &dir.join("dst3"), &|_| false).unwrap_err();
        assert!(err.to_string().contains("特殊文件"), "{err}");
    }

    #[test]
    fn stale_sweep() {
        let dir = tmp();
        fs::write(dir.join(format!("{TEMP_PREFIX}a")), b"").unwrap();
        fs::create_dir(dir.join(format!("{TEMP_PREFIX}dir"))).unwrap();
        fs::write(dir.join("keep"), b"").unwrap();
        assert_eq!(
            sweep_stale(dir.path(), TEMP_PREFIX, Duration::from_secs(3600)).unwrap(),
            0,
            "fresh entries are kept"
        );
        assert_eq!(
            sweep_stale(dir.path(), TEMP_PREFIX, Duration::ZERO).unwrap(),
            2
        );
        assert!(dir.join("keep").exists());
        assert_eq!(
            sweep_stale(&dir.join("missing"), TEMP_PREFIX, Duration::ZERO).unwrap(),
            0
        );
    }

    #[test]
    fn hashing() {
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        let dir = tmp();
        let file = dir.join("big");
        let data = vec![7u8; 200_000];
        fs::write(&file, &data).unwrap();
        assert_eq!(sha256_file(&file).unwrap(), sha256_hex(&data));
        let link = dir.join("link");
        symlink(&file, &link).unwrap();
        assert!(sha256_file(&link).is_err());
    }

    #[test]
    fn owned_path_rule() {
        let dir = tmp();
        // The owned root's ancestors may be symlinks (e.g. /var/run → /run).
        let real = dir.join("real");
        fs::create_dir(&real).unwrap();
        let alias = dir.join("alias");
        symlink(&real, &alias).unwrap();
        let root = alias.join("onebox");
        fs::create_dir(&root).unwrap();
        check_owned(&root, &root).unwrap();
        check_owned(&root, &root.join("state.json")).unwrap();
        check_owned(&root, &root.join("not/yet/created")).unwrap();

        fs::create_dir(root.join("tls")).unwrap();
        symlink("/etc", root.join("tls/link")).unwrap();
        let err = check_owned(&root, &root.join("tls/link/passwd")).unwrap_err();
        assert!(err.to_string().contains("不允许符号链接"), "{err}");
        assert!(check_owned(&root, &root.join("tls/link")).is_err());

        assert!(check_owned(&root, &dir.join("elsewhere")).is_err());
        assert!(check_owned(&root, &root.join("a/../../x")).is_err());
    }

    #[test]
    fn temp_dir_is_private_and_removed() {
        let path = {
            let t = TempDir::new("probe").unwrap();
            assert_eq!(mode_of(t.path()), 0o700);
            t.path().to_path_buf()
        };
        assert!(!path.exists());
    }
}
