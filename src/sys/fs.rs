//! Filesystem primitives: atomic writes, exclusive creates, bounded reads,
//! owned-tree symlink safety, tree copy/remove, stale temp sweeping.

use crate::error::{Error, Result};
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;

/// Replace `path` atomically: temp file in the same directory (create_new),
/// write, fsync, exact chmod, rename, fsync the directory. The temp file is
/// removed on error and the old content stays intact. Missing parents are
/// created with mode 0700.
pub fn atomic_write(path: &Path, bytes: &[u8], mode: u32) -> Result<()> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .ok_or_else(|| Error::msg(format!("路径没有父目录: {}", path.display())))?;
    if !parent.exists() {
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(parent)
            .map_err(|e| Error::io(parent, e))?;
    }
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let temp = parent.join(format!(".{name}.onebox-{}", crate::sys::rand::hex(12)?));
    let result = (|| -> std::io::Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&temp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        fs::set_permissions(&temp, fs::Permissions::from_mode(mode))?;
        fs::rename(&temp, path)?;
        fsync_dir(parent)
    })();
    if let Err(e) = result {
        let _ = fs::remove_file(&temp);
        return Err(Error::io(path, e));
    }
    Ok(())
}

/// fsync a directory so a rename inside it is durable.
pub fn fsync_dir(dir: &Path) -> std::io::Result<()> {
    File::open(dir)?.sync_all()
}

/// Read a regular, non-symlink file of at most `max` bytes.
pub fn read_bounded(path: &Path, max: u64) -> Result<Vec<u8>> {
    let meta = fs::symlink_metadata(path).map_err(|e| Error::io(path, e))?;
    if !meta.file_type().is_file() || meta.len() > max {
        return Err(Error::msg(format!(
            "文件类型或大小无效: {}",
            path.display()
        )));
    }
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|e| Error::io(path, e))?;
    let mut buf = Vec::with_capacity(meta.len() as usize);
    Read::by_ref(&mut file)
        .take(max + 1)
        .read_to_end(&mut buf)
        .map_err(|e| Error::io(path, e))?;
    if buf.len() as u64 > max {
        return Err(Error::msg(format!(
            "文件类型或大小无效: {}",
            path.display()
        )));
    }
    Ok(buf)
}

/// Lowercase hex SHA-256 of `bytes`.
pub fn sha256_hex(bytes: &[u8]) -> String {
    crate::sys::rand::to_hex(&Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn atomic_write_and_bounded_read() {
        let dir =
            std::env::temp_dir().join(format!("onebox-fs-{}", crate::sys::rand::hex(6).unwrap()));
        let file = dir.join("a/b/state.json");
        atomic_write(&file, b"{}", 0o600).unwrap();
        atomic_write(&file, b"{\"x\":1}", 0o600).unwrap();
        assert_eq!(read_bounded(&file, 100).unwrap(), b"{\"x\":1}");
        assert!(read_bounded(&file, 3).is_err());
        assert_eq!(
            fs::metadata(&file).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            fs::metadata(dir.join("a")).unwrap().permissions().mode() & 0o777,
            0o700
        );
        let link = dir.join("link");
        std::os::unix::fs::symlink(&file, &link).unwrap();
        assert!(read_bounded(&link, 100).is_err());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn sha256_of_empty() {
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }
}
