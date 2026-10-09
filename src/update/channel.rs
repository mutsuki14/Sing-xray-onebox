//! The self-update channel (spec G §2.8–2.9).
//!
//! `stable` follows the newest regular release (`/releases/latest`, never a
//! draft or prerelease); `testing` follows the release tagged `testing`
//! (a prerelease, published only by the maintainer). The channel used for
//! a run is the explicit argument, else the saved preference
//! `ROOT/update-channel` (`"{ch}\n"`, 0600, trimmed when read), else
//! `stable`. `update-script testing` is one-shot; `update-channel testing`
//! saves the preference.
//!
//! Changes from v2:
//! - the preference file is read with a size cap and must be a regular
//!   file (v2 refused symlinks only);
//! - printing the channel and `update-check` need no root (G-8.1#16). On an
//!   installed node `ROOT` is 0700, so a non-root user cannot read the
//!   preference ([`Saved::NeedsRoot`]): `update-check` then checks stable
//!   with a warning ([`CHECK_AS_STABLE`]), `update-channel` says that
//!   reading it needs root ([`READ_NEEDS_ROOT`]) — never a silent "stable".

use crate::error::{Error, Result};
use crate::host::fetch::Which;
use crate::paths::Paths;
use crate::sys::fs::{atomic_write, read_bounded};
use std::fmt;
use std::io::ErrorKind;
use std::path::Path;
use std::str::FromStr;

/// Error for anything but `stable` / `testing` (argument or file; v2).
pub const INVALID: &str = "更新渠道仅支持 stable/testing";
/// `update-channel` (or the menu) run by a user who may not read the
/// saved preference.
pub const READ_NEEDS_ROOT: &str = "读取已保存的更新渠道需要 root：sudo onebox update-channel";
/// Warning of an `update-check` that may not read the saved preference.
pub const CHECK_AS_STABLE: &str =
    "无法读取已保存的更新渠道（需要 root），按 stable 检查；可执行 onebox update-check testing";
/// Prefix of every other failure to read the preference.
const READ_FAILED: &str = "读取更新渠道失败";
/// The release tag the testing channel follows.
pub const TESTING_TAG: &str = "testing";
/// Largest preference file accepted (it holds one word).
const MAX_FILE_BYTES: u64 = 4096;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Channel {
    #[default]
    Stable,
    Testing,
}

impl Channel {
    pub fn id(self) -> &'static str {
        match self {
            Channel::Stable => "stable",
            Channel::Testing => "testing",
        }
    }

    /// Which release of the repository this channel installs.
    pub fn which(self) -> Which {
        match self {
            Channel::Stable => Which::Latest,
            Channel::Testing => Which::Tag(TESTING_TAG.to_owned()),
        }
    }
}

impl fmt::Display for Channel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.id())
    }
}

impl FromStr for Channel {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self> {
        match s {
            "stable" => Ok(Channel::Stable),
            "testing" => Ok(Channel::Testing),
            _ => Err(Error::msg(INVALID)),
        }
    }
}

/// What the saved preference says, as far as this user may know.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Saved {
    /// The saved channel (`stable` when none was saved).
    Channel(Channel),
    /// This user may not read the preference (a non-root user on an
    /// installed node, whose `ROOT` is 0700): only root knows it.
    NeedsRoot,
}

/// Read the preference.
pub fn load(paths: &Paths) -> Result<Saved> {
    interpret(read(&paths.update_channel()))
}

/// The preference file's bytes, `None` when there is none.
fn read(path: &Path) -> Result<Option<Vec<u8>>> {
    match std::fs::symlink_metadata(path) {
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(None),
        Err(e) => Err(Error::io(path, e)),
        Ok(_) => read_bounded(path, MAX_FILE_BYTES).map(Some),
    }
}

/// What a read of the preference file means: no file → stable; a denied
/// read → [`Saved::NeedsRoot`]; anything else unreadable or invalid is an
/// error.
pub fn interpret(read: Result<Option<Vec<u8>>>) -> Result<Saved> {
    match read {
        Ok(None) => Ok(Saved::Channel(Channel::Stable)),
        Ok(Some(bytes)) => std::str::from_utf8(&bytes)
            .map_err(|_| Error::msg(INVALID))?
            .trim()
            .parse()
            .map(Saved::Channel),
        Err(e) if permission_denied(&e) => Ok(Saved::NeedsRoot),
        Err(e) => Err(e.wrap(READ_FAILED)),
    }
}

/// An `EACCES` from the filesystem, possibly under context.
fn permission_denied(error: &Error) -> bool {
    match error {
        Error::Io { source, .. } => source.kind() == ErrorKind::PermissionDenied,
        Error::Context { source, .. } => permission_denied(source),
        _ => false,
    }
}

/// The saved preference, `stable` when none was saved; a user who may not
/// read it gets [`READ_NEEDS_ROOT`].
pub fn saved(paths: &Paths) -> Result<Channel> {
    known(load(paths)?)
}

/// The channel of a [`Saved`] reading, or [`READ_NEEDS_ROOT`].
pub fn known(saved: Saved) -> Result<Channel> {
    match saved {
        Saved::Channel(channel) => Ok(channel),
        Saved::NeedsRoot => Err(Error::msg(READ_NEEDS_ROOT)),
    }
}

/// The channel for this run: `explicit`, else the saved preference.
pub fn resolve(paths: &Paths, explicit: Option<Channel>) -> Result<Channel> {
    match explicit {
        Some(channel) => Ok(channel),
        None => saved(paths),
    }
}

/// The channel of an `update-script` / `update-check` run: `explicit`
/// (the preference is then not read at all), else what `load` returns. A
/// check — it needs no root — that may not read the preference checks
/// stable after [`CHECK_AS_STABLE`]; a replacement runs as root, so a
/// denied read there is an error.
pub fn for_run(
    explicit: Option<Channel>,
    check_only: bool,
    load: impl FnOnce() -> Result<Saved>,
    warn: &dyn Fn(&str),
) -> Result<Channel> {
    if let Some(channel) = explicit {
        return Ok(channel);
    }
    match load()? {
        Saved::Channel(channel) => Ok(channel),
        Saved::NeedsRoot if check_only => {
            warn(CHECK_AS_STABLE);
            Ok(Channel::Stable)
        }
        Saved::NeedsRoot => Err(Error::msg(format!("{READ_FAILED}: 权限不足"))),
    }
}

/// Save the preference (`"{ch}\n"`, 0600).
pub fn save(paths: &Paths, channel: Channel) -> Result<()> {
    let text = format!("{channel}\n");
    atomic_write(&paths.update_channel(), text.as_bytes(), 0o600)
}

/// `当前更新渠道: {ch}` (printed by `update-channel`).
pub fn describe(channel: Channel) -> String {
    format!("当前更新渠道: {channel}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sys::fs::TempDir;
    use std::os::unix::fs::PermissionsExt;

    fn layout() -> (TempDir, Paths) {
        let dir = TempDir::new("update-channel").unwrap();
        let paths = Paths::isolated(dir.path());
        (dir, paths)
    }

    #[test]
    fn parses_exactly_the_two_channels() {
        assert_eq!("stable".parse::<Channel>().unwrap(), Channel::Stable);
        assert_eq!("testing".parse::<Channel>().unwrap(), Channel::Testing);
        for bad in ["", "Stable", " testing", "beta", "main"] {
            assert_eq!(bad.parse::<Channel>().unwrap_err().to_string(), INVALID);
        }
        assert_eq!(Channel::Stable.which(), Which::Latest);
        assert_eq!(Channel::Testing.which(), Which::Tag("testing".into()));
        assert_eq!(describe(Channel::Testing), "当前更新渠道: testing");
    }

    #[test]
    fn explicit_wins_then_file_then_stable() {
        let (_dir, paths) = layout();
        assert_eq!(resolve(&paths, None).unwrap(), Channel::Stable);
        save(&paths, Channel::Testing).unwrap();
        let path = paths.update_channel();
        assert_eq!(std::fs::read(&path).unwrap(), b"testing\n");
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
        assert_eq!(resolve(&paths, None).unwrap(), Channel::Testing);
        assert_eq!(
            resolve(&paths, Some(Channel::Stable)).unwrap(),
            Channel::Stable
        );
        // v2 trimmed the file content.
        std::fs::write(&path, "  stable \n\n").unwrap();
        assert_eq!(saved(&paths).unwrap(), Channel::Stable);
    }

    #[test]
    fn bad_preference_files_are_errors() {
        let (_dir, paths) = layout();
        let path = paths.update_channel();
        std::fs::create_dir_all(&paths.root).unwrap();
        for bad in [&b"nightly\n"[..], b"", b"\xff\xfe"] {
            std::fs::write(&path, bad).unwrap();
            assert_eq!(saved(&paths).unwrap_err().to_string(), INVALID);
        }
        // An explicit channel does not need the file at all.
        assert_eq!(
            resolve(&paths, Some(Channel::Testing)).unwrap(),
            Channel::Testing
        );
        std::fs::write(&path, "x".repeat(5000)).unwrap();
        assert!(saved(&paths)
            .unwrap_err()
            .to_string()
            .starts_with("读取更新渠道失败"));
        std::fs::remove_file(&path).unwrap();
        let target = paths.root.join("elsewhere");
        std::fs::write(&target, "testing").unwrap();
        std::os::unix::fs::symlink(&target, &path).unwrap();
        let err = saved(&paths).unwrap_err().to_string();
        assert!(err.contains("不允许符号链接"), "{err}");
    }

    fn denied() -> Error {
        Error::io(
            "/etc/onebox/update-channel",
            std::io::Error::from(ErrorKind::PermissionDenied),
        )
    }

    #[test]
    fn a_denied_read_means_only_root_knows() {
        // A non-root user on an installed node: stat inside the 0700 ROOT
        // (or the open of the 0600 file) fails with EACCES.
        assert_eq!(interpret(Err(denied())).unwrap(), Saved::NeedsRoot);
        let wrapped = Err(denied().wrap("打开失败"));
        assert_eq!(interpret(wrapped).unwrap(), Saved::NeedsRoot);
        assert_eq!(
            known(Saved::NeedsRoot).unwrap_err().to_string(),
            READ_NEEDS_ROOT
        );
        assert_eq!(
            known(Saved::Channel(Channel::Testing)).unwrap(),
            Channel::Testing
        );
        // Other failures stay errors.
        let other = Error::io(
            "/etc/onebox/update-channel",
            std::io::Error::from(ErrorKind::InvalidData),
        );
        let err = interpret(Err(other)).unwrap_err().to_string();
        assert!(err.starts_with("读取更新渠道失败: "), "{err}");
        assert_eq!(
            interpret(Ok(None)).unwrap(),
            Saved::Channel(Channel::Stable)
        );
        assert_eq!(
            interpret(Ok(Some(b"testing\n".to_vec()))).unwrap(),
            Saved::Channel(Channel::Testing)
        );
    }

    #[test]
    fn a_check_without_root_checks_stable_with_a_warning() {
        let warnings = std::cell::RefCell::new(Vec::new());
        let warn = |m: &str| warnings.borrow_mut().push(m.to_owned());
        let denied = || Ok(Saved::NeedsRoot);
        assert_eq!(for_run(None, true, denied, &warn).unwrap(), Channel::Stable);
        assert_eq!(*warnings.borrow(), [CHECK_AS_STABLE]);
        // A replacement (root) that may not read it fails.
        let err = for_run(None, false, denied, &warn).unwrap_err();
        assert_eq!(err.to_string(), "读取更新渠道失败: 权限不足");
        // An explicit channel never reads the preference.
        let unread = || -> Result<Saved> { panic!("read the preference") };
        assert_eq!(
            for_run(Some(Channel::Testing), true, unread, &warn).unwrap(),
            Channel::Testing
        );
        let saved = || Ok(Saved::Channel(Channel::Testing));
        assert_eq!(for_run(None, true, saved, &warn).unwrap(), Channel::Testing);
        assert_eq!(warnings.borrow().len(), 1, "no further warnings");
        let failing = || Err(Error::msg(INVALID));
        assert_eq!(
            for_run(None, true, failing, &warn).unwrap_err().to_string(),
            INVALID
        );
    }
}
