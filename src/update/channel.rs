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
//! - printing the channel needs no root (G-8.1#16); a preference the
//!   current user cannot read is reported as such instead of "stable".

use crate::error::{Context, Error, Result};
use crate::host::fetch::Which;
use crate::paths::Paths;
use crate::sys::fs::{atomic_write, read_bounded};
use std::fmt;
use std::io::ErrorKind;
use std::str::FromStr;

/// Error for anything but `stable` / `testing` (argument or file; v2).
pub const INVALID: &str = "更新渠道仅支持 stable/testing";
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

/// The saved preference, `stable` when none was saved.
pub fn saved(paths: &Paths) -> Result<Channel> {
    let path = paths.update_channel();
    match std::fs::symlink_metadata(&path) {
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(Channel::Stable),
        Err(e) => return Err(Error::io(&path, e)).context("读取更新渠道失败"),
        Ok(_) => {}
    }
    let bytes = read_bounded(&path, MAX_FILE_BYTES).context("读取更新渠道失败")?;
    std::str::from_utf8(&bytes)
        .map_err(|_| Error::msg(INVALID))?
        .trim()
        .parse()
}

/// The channel for this run: `explicit`, else the saved preference.
pub fn resolve(paths: &Paths, explicit: Option<Channel>) -> Result<Channel> {
    match explicit {
        Some(channel) => Ok(channel),
        None => saved(paths),
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
}
