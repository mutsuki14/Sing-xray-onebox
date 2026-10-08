//! flock-based mutation locks and the inherited lock-fd (198) protocol.
//!
//! A lock is held by an open file description with `flock(LOCK_EX)`. It is
//! released only by closing the descriptor (drop) — never with `LOCK_UN`,
//! which would also release a parent's lock when the description was
//! inherited across exec during self-update (spec A §4.2).
//!
//! Handoff protocol (compatible with v2 parents and children):
//! 1. the parent holds the lock and runs the child with the description on
//!    fd 198 and `ONEBOX_INHERITED_LOCK_FD=198` (see `Cmd::inherit_lock`);
//! 2. the child duplicates fd 198 to a private CLOEXEC descriptor, checks it
//!    refers to the expected lock file (dev/ino), re-flocks it (succeeds on
//!    the shared description), closes 198 and removes the variable so
//!    grandchildren never see it.
//!
//! Changes from v2: one lock type for every lock file (node, update, FRP,
//! BBR) with a caller-supplied contention message; fd 198 is a named
//! constant (A-8.1#18); `from_inherited` never touches fd 198 unless the
//! variable is exactly `198`.

use crate::error::{Error, Result};
use crate::sys::exec::{INHERITED_LOCK_ENV, INHERITED_LOCK_FD};
use std::fs::{File, OpenOptions};
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

/// Default contention message for the node lock.
pub const BUSY_MESSAGE: &str = "另一个配置操作正在进行；稍后重试";

#[derive(Debug)]
pub struct FileLock {
    file: File,
    path: PathBuf,
    inherited: bool,
}

/// True when a parent offered its lock through the environment.
pub fn inherited_lock_offered() -> bool {
    std::env::var_os(INHERITED_LOCK_ENV).is_some()
}

fn flock_exclusive(fd: RawFd) -> io::Result<()> {
    // SAFETY: flock on a descriptor we own; no memory is involved.
    if unsafe { libc::flock(fd, libc::LOCK_EX | libc::LOCK_NB) } == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

impl FileLock {
    /// Take the lock without blocking. Contention → `Error::Busy(busy_message)`.
    /// The file is created 0600 (missing parents 0700), never truncated and
    /// never opened through a symlink.
    pub fn acquire(path: &Path, busy_message: &str) -> Result<FileLock> {
        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            if !parent.exists() {
                std::fs::DirBuilder::new()
                    .recursive(true)
                    .mode(0o700)
                    .create(parent)
                    .map_err(|e| Error::io(parent, e))?;
            }
        }
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)
            .map_err(|e| match e.raw_os_error() {
                Some(libc::ELOOP) => Error::msg(format!("不允许符号链接: {}", path.display())),
                _ => Error::io(path, e),
            })?;
        match flock_exclusive(file.as_raw_fd()) {
            Ok(()) => Ok(FileLock {
                file,
                path: path.to_path_buf(),
                inherited: false,
            }),
            Err(e) if e.raw_os_error() == Some(libc::EWOULDBLOCK) => {
                Err(Error::Busy(busy_message.to_owned()))
            }
            Err(e) => Err(Error::io(path, e)),
        }
    }

    /// [`acquire`](FileLock::acquire), retrying every `poll` for up to
    /// `wait` while another holder has it (short critical sections such as
    /// one crontab edit or one service start).
    pub fn acquire_waiting(
        path: &Path,
        busy_message: &str,
        wait: std::time::Duration,
        poll: std::time::Duration,
    ) -> Result<FileLock> {
        let deadline = std::time::Instant::now() + wait;
        loop {
            match Self::acquire(path, busy_message) {
                Err(Error::Busy(_)) if std::time::Instant::now() < deadline => {
                    std::thread::sleep(poll);
                }
                other => return other,
            }
        }
    }

    /// Adopt the lock a parent passed on fd 198 (see module docs).
    pub fn from_inherited(expected_path: &Path) -> Result<FileLock> {
        if std::env::var(INHERITED_LOCK_ENV).ok().as_deref() != Some("198") {
            return Err(Error::msg("继承锁描述符无效"));
        }
        // SAFETY: F_DUPFD_CLOEXEC on a possibly invalid fd only returns EBADF.
        let duplicate = unsafe { libc::fcntl(INHERITED_LOCK_FD, libc::F_DUPFD_CLOEXEC, 3) };
        if duplicate < 0 {
            return Err(Error::msg("继承锁描述符无效"));
        }
        // SAFETY: `duplicate` is a fresh descriptor owned by nobody else.
        let file = unsafe { File::from_raw_fd(duplicate) };
        let mismatch = || Error::msg("继承锁与当前实例不匹配");
        let held = file.metadata().map_err(|_| mismatch())?;
        let expected = std::fs::symlink_metadata(expected_path).map_err(|_| mismatch())?;
        if !held.is_file()
            || !expected.is_file()
            || held.dev() != expected.dev()
            || held.ino() != expected.ino()
        {
            return Err(mismatch());
        }
        flock_exclusive(file.as_raw_fd()).map_err(|_| Error::msg("继承锁无法获得独占权限"))?;
        // Only a verified descriptor is consumed; our copy is CLOEXEC so
        // later children (cores, systemctl) cannot keep the lock alive.
        // SAFETY: closing the inherited descriptor number, which we verified.
        unsafe {
            libc::close(INHERITED_LOCK_FD);
        }
        std::env::remove_var(INHERITED_LOCK_ENV);
        Ok(FileLock {
            file,
            path: expected_path.to_path_buf(),
            inherited: true,
        })
    }

    /// Adopt an inherited lock when one is offered, else acquire normally.
    pub fn acquire_or_inherit(path: &Path, busy_message: &str) -> Result<FileLock> {
        if inherited_lock_offered() {
            Self::from_inherited(path)
        } else {
            Self::acquire(path, busy_message)
        }
    }

    /// Whether this lock was handed over by a parent process.
    pub fn is_inherited(&self) -> bool {
        self.inherited
    }

    /// The descriptor to pass to a child with `Cmd::inherit_lock`.
    pub fn raw_fd(&self) -> RawFd {
        self.file.as_raw_fd()
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Check that `path` still names the file this lock holds (it was not
    /// deleted or replaced behind our back).
    pub fn verify(&self, path: &Path) -> Result<()> {
        let foreign = || Error::msg("配置锁不属于当前实例");
        let actual = std::fs::symlink_metadata(path).map_err(|_| foreign())?;
        let held = self.file.metadata().map_err(|_| foreign())?;
        if !actual.is_file() || held.dev() != actual.dev() || held.ino() != actual.ino() {
            return Err(foreign());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sys::exec::{Cmd, Exec, SystemExec};
    use crate::sys::fs::TempDir;

    const CHILD_MARKER: &str = "ONEBOX_LOCK_TEST_PATH";
    const ISOLATED: &str = "ONEBOX_LOCK_TEST_ISOLATED";

    #[test]
    fn contention_and_release() {
        let dir = TempDir::new("lock").unwrap();
        let path = dir.join("state/.apply.lock");
        let first = FileLock::acquire(&path, BUSY_MESSAGE).unwrap();
        assert!(!first.is_inherited());
        assert_eq!(first.path(), path);
        match FileLock::acquire(&path, "忙") {
            Err(Error::Busy(m)) => assert_eq!(m, "忙"),
            other => panic!("expected Busy, got {other:?}"),
        }
        first.verify(&path).unwrap();
        drop(first);
        let again = FileLock::acquire(&path, BUSY_MESSAGE).unwrap();
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        // A replaced lock file is detected.
        std::fs::remove_file(&path).unwrap();
        std::fs::write(&path, "").unwrap();
        assert_eq!(
            again.verify(&path).unwrap_err().to_string(),
            "配置锁不属于当前实例"
        );
    }

    #[test]
    fn waiting_acquire_gets_a_released_lock_or_reports_busy() {
        use std::time::Duration;
        let dir = TempDir::new("lock-wait").unwrap();
        let path = dir.join("x.lock");
        let held = FileLock::acquire(&path, BUSY_MESSAGE).unwrap();
        let short = Duration::from_millis(30);
        let err =
            FileLock::acquire_waiting(&path, "忙", short, Duration::from_millis(5)).unwrap_err();
        assert!(matches!(err, Error::Busy(ref m) if m == "忙"), "{err}");
        let release = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(30));
            drop(held);
        });
        FileLock::acquire_waiting(
            &path,
            "忙",
            Duration::from_secs(5),
            Duration::from_millis(5),
        )
        .unwrap();
        release.join().unwrap();
    }

    #[test]
    fn refuses_symlinked_lock_file() {
        let dir = TempDir::new("lock-link").unwrap();
        let target = dir.join("target");
        std::fs::write(&target, "").unwrap();
        let link = dir.join(".apply.lock");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let err = FileLock::acquire(&link, BUSY_MESSAGE).unwrap_err();
        assert!(err.to_string().contains("不允许符号链接"), "{err}");
    }

    /// Runs only inside the child spawned by `child_inherits_and_parent_keeps_lock`.
    #[test]
    fn inherited_lock_child() {
        let Some(path) = std::env::var_os(CHILD_MARKER) else {
            return;
        };
        let path = PathBuf::from(path);
        assert_eq!(
            std::env::var(INHERITED_LOCK_ENV).ok().as_deref(),
            Some("198")
        );
        let lock = FileLock::acquire_or_inherit(&path, BUSY_MESSAGE).unwrap();
        assert!(lock.is_inherited());
        assert!(lock.raw_fd() >= 3 && lock.raw_fd() != INHERITED_LOCK_FD);
        assert!(std::env::var_os(INHERITED_LOCK_ENV).is_none());
        // SAFETY: querying flags of a descriptor number.
        assert_eq!(unsafe { libc::fcntl(INHERITED_LOCK_FD, libc::F_GETFD) }, -1);
        lock.verify(&path).unwrap();
        assert!(matches!(
            FileLock::acquire(&path, BUSY_MESSAGE),
            Err(Error::Busy(_))
        ));
        drop(lock);
        println!("inherited lock verified");
    }

    /// Only the dedicated child process may adopt fd 198: an absent or wrong
    /// variable is rejected before any descriptor is touched.
    #[test]
    fn inheritance_requires_exact_variable() {
        if inherited_lock_offered() {
            return; // running inside the handoff child
        }
        let err = FileLock::from_inherited(Path::new("/nonexistent")).unwrap_err();
        assert_eq!(err.to_string(), "继承锁描述符无效");
    }

    #[test]
    fn child_inherits_and_parent_keeps_lock() {
        // Re-run in an otherwise idle test process: concurrent tests forking
        // children could briefly hold a copy of our descriptor between fork
        // and exec, which would make the post-drop re-acquire flaky.
        if std::env::var(ISOLATED).ok().as_deref() != Some("1") {
            if std::env::var_os(CHILD_MARKER).is_some() {
                return;
            }
            let exe = std::env::current_exe().unwrap();
            let out = SystemExec
                .run(
                    &Cmd::new(exe.to_str().unwrap())
                        .args([
                            "--exact",
                            "sys::lock::tests::child_inherits_and_parent_keeps_lock",
                            "--nocapture",
                            "--test-threads=1",
                        ])
                        .env(ISOLATED, "1"),
                )
                .unwrap();
            assert!(out.ok(), "{}\n{}", out.stdout, out.stderr);
            assert!(out.stdout.contains("1 passed"), "{}", out.stdout);
            return;
        }
        let dir = TempDir::new("lock-handoff").unwrap();
        let path = dir.join(".apply.lock");
        let lock = FileLock::acquire(&path, BUSY_MESSAGE).unwrap();
        let exe = std::env::current_exe().unwrap();
        let out = SystemExec
            .run(
                &Cmd::new(exe.to_str().unwrap())
                    .args([
                        "--exact",
                        "sys::lock::tests::inherited_lock_child",
                        "--nocapture",
                        "--test-threads=1",
                    ])
                    .env(CHILD_MARKER, path.to_str().unwrap())
                    .inherit_lock(lock.raw_fd()),
            )
            .unwrap();
        assert!(out.ok(), "{}\n{}", out.stdout, out.stderr);
        assert!(
            out.stdout.contains("inherited lock verified"),
            "{}",
            out.stdout
        );
        assert!(
            matches!(FileLock::acquire(&path, BUSY_MESSAGE), Err(Error::Busy(_))),
            "the child must not unlock the parent's open file description"
        );
        drop(lock);
        FileLock::acquire(&path, BUSY_MESSAGE).unwrap();
    }

    #[test]
    fn mismatched_inherited_file_is_rejected() {
        if std::env::var(ISOLATED).ok().as_deref() != Some("mismatch") {
            if inherited_lock_offered() {
                return;
            }
            let dir = TempDir::new("lock-mismatch").unwrap();
            let held = FileLock::acquire(&dir.join("other.lock"), BUSY_MESSAGE).unwrap();
            std::fs::write(dir.join("expected.lock"), "").unwrap();
            let exe = std::env::current_exe().unwrap();
            let out = SystemExec
                .run(
                    &Cmd::new(exe.to_str().unwrap())
                        .args([
                            "--exact",
                            "sys::lock::tests::mismatched_inherited_file_is_rejected",
                            "--nocapture",
                            "--test-threads=1",
                        ])
                        .env(ISOLATED, "mismatch")
                        .env(CHILD_MARKER, dir.join("expected.lock").to_str().unwrap())
                        .inherit_lock(held.raw_fd()),
                )
                .unwrap();
            assert!(out.ok(), "{}\n{}", out.stdout, out.stderr);
            assert!(out.stdout.contains("mismatch rejected"), "{}", out.stdout);
            return;
        }
        let expected = PathBuf::from(std::env::var_os(CHILD_MARKER).unwrap());
        let err = FileLock::from_inherited(&expected).unwrap_err();
        assert_eq!(err.to_string(), "继承锁与当前实例不匹配");
        println!("mismatch rejected");
    }
}
