//! Atomic exchange of two paths (`renameat2(RENAME_EXCHANGE)`), used to
//! replace a whole directory so readers never see a mix of old and new files.

use std::ffi::CString;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

fn c_path(path: &Path) -> io::Result<CString> {
    CString::new(path.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "路径包含 NUL 字符"))
}

/// Atomically swap `a` and `b` (both must exist; any file types). Fails with
/// the kernel's error (e.g. `EINVAL` on filesystems without support) and
/// then leaves both paths untouched.
pub fn rename_exchange(a: &Path, b: &Path) -> io::Result<()> {
    let a = c_path(a)?;
    let b = c_path(b)?;
    // SAFETY: both pointers come from live, NUL-terminated CStrings that
    // outlive the call; renameat2 only reads them. glibc and musl differ in
    // exposing a renameat2 wrapper, the raw syscall is available on both.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            libc::AT_FDCWD,
            a.as_ptr(),
            libc::AT_FDCWD,
            b.as_ptr(),
            libc::RENAME_EXCHANGE,
        )
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sys::fs::TempDir;
    use std::fs;

    #[test]
    fn swaps_directories_atomically() {
        let dir = TempDir::new("exchange").unwrap();
        let (a, b) = (dir.join("a"), dir.join("b"));
        fs::create_dir(&a).unwrap();
        fs::create_dir(&b).unwrap();
        fs::write(a.join("old"), "1").unwrap();
        fs::write(b.join("new"), "2").unwrap();
        rename_exchange(&a, &b).unwrap();
        assert!(a.join("new").exists() && b.join("old").exists());
        assert!(!a.join("old").exists());
    }

    #[test]
    fn missing_paths_fail_without_changes() {
        let dir = TempDir::new("exchange").unwrap();
        let a = dir.join("a");
        fs::create_dir(&a).unwrap();
        let err = rename_exchange(&a, &dir.join("missing")).unwrap_err();
        assert_eq!(err.raw_os_error(), Some(libc::ENOENT));
        assert!(a.is_dir());
        assert!(rename_exchange(Path::new("a\0b"), &a).is_err());
    }
}
