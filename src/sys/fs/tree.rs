//! Tree operations: budgeted recursive copy and skip-aware removal (the
//! primitives behind snapshots, backups and site content imports).
//!
//! [`copy_tree`] walks its source with descriptors: every entry is opened
//! relative to its parent directory's descriptor with `O_NOFOLLOW`, so a
//! directory swapped for a symlink while it is being copied (an import
//! source writable by another local user) cannot redirect the rest of the
//! walk outside the tree. The root itself is opened by path, where
//! `O_NOFOLLOW` covers only the last component; a caller whose source path
//! has ancestors another user controls pins the root first with
//! [`open_dir_nofollow`] (no symlink anywhere in the path) and copies from
//! that descriptor with [`copy_tree_at`].

use super::{atomic_write_with, ensure_dir, fsync_dir, not_found, symlink_error, MODE_MASK};
use crate::error::{Error, Result};
use std::ffi::{CStr, CString, OsStr, OsString};
use std::fs::{self, File};
use std::io::{self, Read};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
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
    /// Whether files with more than one hard link are copied. An untrusted
    /// source (`site import`) may link a file only root can read.
    pub hard_links: bool,
}

impl CopyLimits {
    pub const UNLIMITED: CopyLimits = CopyLimits::new(u64::MAX, usize::MAX);

    pub const fn new(max_bytes: u64, max_entries: usize) -> CopyLimits {
        CopyLimits {
            max_bytes,
            max_entries,
            message: None,
            hard_links: true,
        }
    }

    /// Use a caller-specific message (e.g. v2's `备份超过 4096 文件或 64 MiB 限制`).
    pub const fn message(mut self, message: &'static str) -> CopyLimits {
        self.message = Some(message);
        self
    }

    /// Refuse files with more than one hard link (`不允许硬链接: {path}`).
    pub const fn refuse_hard_links(mut self) -> CopyLimits {
        self.hard_links = false;
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
/// tree are refused (hard links too when `limits` says so), and so is a
/// `dst` inside `src` unless it lies in a skipped subtree (a snapshot staged
/// in `ROOT/.transaction`). The source is read through descriptors (module
/// docs): `src` itself is opened by path without following a final symlink,
/// everything below it relative to its parent. `limits` is enforced while
/// copying; on any error `dst` may be partially populated and the caller
/// removes it.
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
    copy.entry(None, src.as_os_str(), src, dst, true)?;
    Ok(copy.stats)
}

/// [`copy_tree`] from the directory `root` was opened on (by
/// [`open_dir_nofollow`]), whatever its path `src` names by now; `src` only
/// serves `skip`, the nesting check and messages.
pub fn copy_tree_at(
    root: &File,
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
    copy.entry(Some(root), OsStr::new("."), src, dst, true)?;
    Ok(copy.stats)
}

/// Open the directory at the absolute `path` one component at a time from
/// `/`, each relative to its parent's descriptor with `O_NOFOLLOW`: a
/// symlink anywhere in the path is refused (`不允许符号链接: {where}`), not
/// only as its last component, which is all `O_NOFOLLOW` on a whole path
/// covers. The `O_PATH` descriptor stays on the directory the path named
/// while it was opened, whatever is renamed or swapped later; `path`
/// should be canonical (a `..` component is refused).
pub fn open_dir_nofollow(path: &Path) -> Result<File> {
    if !path.is_absolute() {
        return Err(Error::msg(format!("需要绝对路径: {}", path.display())));
    }
    let mut walked = PathBuf::new();
    let mut dir: Option<File> = None;
    for component in path.components() {
        let name = match component {
            Component::RootDir => OsStr::new("/"),
            Component::Normal(name) => name,
            _ => return Err(Error::msg(format!("需要规范路径: {}", path.display()))),
        };
        walked.push(name);
        let next = open_at(dir.as_ref(), name, libc::O_PATH).map_err(|e| Error::io(&walked, e))?;
        let meta = next.metadata().map_err(|e| Error::io(&walked, e))?;
        if meta.file_type().is_symlink() {
            return Err(symlink_error(&walked));
        }
        if !meta.is_dir() {
            return Err(Error::msg(format!("不是目录: {}", walked.display())));
        }
        dir = Some(next);
    }
    dir.ok_or_else(|| Error::msg(format!("需要绝对路径: {}", path.display())))
}

struct TreeCopy<'a> {
    skip: &'a dyn Fn(&Path) -> bool,
    limits: &'a CopyLimits,
    stats: CopyStats,
}

impl TreeCopy<'_> {
    /// Copy the entry `name` of the open directory `parent` (`None`: `name`
    /// is the root's path) to `dst`; `src` is its path, for `skip` and errors.
    fn entry(
        &mut self,
        parent: Option<&File>,
        name: &OsStr,
        src: &Path,
        dst: &Path,
        root: bool,
    ) -> Result<()> {
        // Inspect through an O_PATH descriptor first: it opens neither
        // devices nor FIFOs, and with O_NOFOLLOW it pins a symlink itself.
        let meta = open_at(parent, name, libc::O_PATH)
            .and_then(|probe| probe.metadata())
            .map_err(|e| Error::io(src, e))?;
        let mode = meta.permissions().mode() & MODE_MASK;
        if meta.file_type().is_symlink() {
            return Err(symlink_error(src));
        }
        if !meta.is_file() && !meta.is_dir() {
            return Err(Error::msg(format!("不支持的特殊文件: {}", src.display())));
        }
        if meta.is_file() && meta.nlink() > 1 && !self.limits.hard_links {
            return Err(Error::msg(format!("不允许硬链接: {}", src.display())));
        }
        if !root {
            if self.stats.entries >= self.limits.max_entries {
                return Err(self.limits.exceeded(src));
            }
            self.stats.entries += 1;
        }
        let kind = if meta.is_dir() { libc::O_DIRECTORY } else { 0 };
        let source =
            open_at(parent, name, libc::O_RDONLY | libc::O_NONBLOCK | kind).map_err(|e| match e
                .raw_os_error()
            {
                Some(libc::ELOOP) => symlink_error(src),
                _ => Error::io(src, e),
            })?;
        // Swapped between the two opens: refuse rather than guess.
        let opened = source.metadata().map_err(|e| Error::io(src, e))?;
        if (opened.dev(), opened.ino()) != (meta.dev(), meta.ino()) {
            return Err(Error::msg(format!(
                "复制期间源内容被替换: {}",
                src.display()
            )));
        }
        if meta.is_file() {
            let remaining = self.limits.max_bytes.saturating_sub(self.stats.bytes);
            if opened.len() > remaining {
                return Err(self.limits.exceeded(src));
            }
            let copied = copy_file_limited(source, dst, mode, remaining)?
                .ok_or_else(|| self.limits.exceeded(src))?;
            self.stats.bytes += copied;
            return Ok(());
        }
        // Fill the directory while it is private and writable; its real mode
        // (possibly read-only) is applied once the children are in place.
        ensure_dir(dst, 0o700)?;
        let mut entries = list_dir(&source).map_err(|e| Error::io(src, e))?;
        entries.sort();
        for name in entries {
            let child = src.join(&name);
            if !(self.skip)(&child) {
                self.entry(Some(&source), &name, &child, &dst.join(&name), false)?;
            }
        }
        ensure_dir(dst, mode)?;
        fsync_dir(dst).map_err(|e| Error::io(dst, e))
    }
}

/// `openat(parent, name, flags | O_NOFOLLOW | O_CLOEXEC | O_NOCTTY)`;
/// without a parent, `name` is a path (relative to the working directory).
fn open_at(parent: Option<&File>, name: &OsStr, flags: libc::c_int) -> io::Result<File> {
    let name = CString::new(name.as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "路径包含 NUL 字符"))?;
    let dir = parent.map_or(libc::AT_FDCWD, |p| p.as_raw_fd());
    let flags = flags | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NOCTTY;
    // SAFETY: `name` is a live NUL-terminated string and `dir` is AT_FDCWD
    // or a descriptor that `parent` keeps open for the duration of the call.
    let fd = unsafe { libc::openat(dir, name.as_ptr(), flags) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `fd` is a fresh descriptor owned by nobody else.
    Ok(unsafe { File::from_raw_fd(fd) })
}

/// The names in the open directory `dir`, without `.` and `..`.
fn list_dir(dir: &File) -> io::Result<Vec<OsString>> {
    // fdopendir takes over the descriptor it is given: hand it a duplicate
    // so `dir` stays usable for the openat calls on its children.
    // SAFETY: F_DUPFD_CLOEXEC on a descriptor that `dir` keeps open.
    let fd = unsafe { libc::fcntl(dir.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `fd` is our own fresh duplicate.
    let stream = unsafe { libc::fdopendir(fd) };
    if stream.is_null() {
        let error = io::Error::last_os_error();
        // SAFETY: fdopendir failed, so `fd` is still ours to close.
        unsafe { libc::close(fd) };
        return Err(error);
    }
    let mut names = Vec::new();
    let result = loop {
        // readdir reports both the end and an error as NULL; only errno
        // tells them apart, so clear it first.
        // SAFETY: errno is thread-local, and `stream` is a live DIR* used
        // only by this loop.
        let entry = unsafe {
            *libc::__errno_location() = 0;
            libc::readdir(stream)
        };
        if entry.is_null() {
            let error = io::Error::last_os_error();
            break match error.raw_os_error() {
                Some(0) => Ok(()),
                _ => Err(error),
            };
        }
        // SAFETY: `entry` points into `stream` until the next readdir call,
        // and d_name is NUL-terminated; the name is copied out right here.
        let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes();
        if name != b"." && name != b".." {
            names.push(OsStr::from_bytes(name).to_owned());
        }
    };
    // SAFETY: `stream` is live and closed exactly once, with its descriptor.
    unsafe { libc::closedir(stream) };
    result.map(|()| names)
}

/// Stream `source` into `dst` (atomically, with `mode`), stopping at `max`
/// bytes even if the source grows while it is copied: `Ok(None)` (and no
/// `dst` written) when it is larger.
pub(super) fn copy_file_limited(
    source: File,
    dst: &Path,
    mode: u32,
    max: u64,
) -> Result<Option<u64>> {
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
