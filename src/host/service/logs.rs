//! Log files of services without journald: lookup in v2 order and an
//! in-process `tail` (v2 shelled out to `tail -n 200 --`).

use crate::error::{Error, Result};
use std::fs::{self, OpenOptions};
use std::io::{Read, Seek, SeekFrom};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

/// At most this many trailing bytes are read, so a huge log costs nothing.
const TAIL_WINDOW: u64 = 1024 * 1024;

/// The first candidate that is a regular file itself (not a symlink).
pub(super) fn find(candidates: &[PathBuf]) -> Option<PathBuf> {
    candidates
        .iter()
        .find(|p| fs::symlink_metadata(p).is_ok_and(|m| m.file_type().is_file()))
        .cloned()
}

/// The last `lines` lines of `path` (lossy UTF-8, line endings kept).
pub(super) fn tail(path: &Path, lines: usize) -> Result<String> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)
        .map_err(|e| Error::io(path, e))?;
    let len = file.metadata().map_err(|e| Error::io(path, e))?.len();
    let start = len.saturating_sub(TAIL_WINDOW);
    file.seek(SeekFrom::Start(start))
        .map_err(|e| Error::io(path, e))?;
    let mut bytes = Vec::new();
    file.take(TAIL_WINDOW)
        .read_to_end(&mut bytes)
        .map_err(|e| Error::io(path, e))?;
    let text = String::from_utf8_lossy(&bytes);
    // A window starting mid-file begins with a partial line: drop it.
    let text = match (start > 0, text.find('\n')) {
        (true, Some(index)) => &text[index + 1..],
        _ => &text[..],
    };
    Ok(last_lines(text, lines).to_owned())
}

/// The suffix of `text` holding its last `count` lines.
pub(super) fn last_lines(text: &str, count: usize) -> &str {
    if count == 0 {
        return "";
    }
    // Skip the final newline so it does not count as an empty last line.
    let body = text.strip_suffix('\n').unwrap_or(text);
    let mut seen = 0;
    for (index, byte) in body.bytes().enumerate().rev() {
        if byte == b'\n' {
            seen += 1;
            if seen == count {
                return &text[index + 1..];
            }
        }
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sys::fs::TempDir;

    #[test]
    fn last_lines_counts_from_the_end() {
        for (text, count, want) in [
            ("a\nb\nc\n", 2, "b\nc\n"),
            ("a\nb\nc", 2, "b\nc"),
            ("a\nb\nc\n", 5, "a\nb\nc\n"),
            ("a\nb\nc\n", 0, ""),
            ("", 3, ""),
            ("\n\n", 1, "\n"),
        ] {
            assert_eq!(last_lines(text, count), want, "{text:?} {count}");
        }
    }

    #[test]
    fn tail_reads_only_the_end_and_refuses_links() {
        let dir = TempDir::new("logs").unwrap();
        let log = dir.join("big.log");
        let line = "x".repeat(99) + "\n";
        let mut content = line.repeat(20_000);
        content.push_str("last one\n");
        fs::write(&log, &content).unwrap();
        assert_eq!(tail(&log, 2).unwrap(), format!("{line}last one\n"));
        let all = tail(&log, usize::MAX).unwrap();
        assert!(all.len() as u64 <= TAIL_WINDOW && all.starts_with('x'));
        let link = dir.join("link.log");
        std::os::unix::fs::symlink(&log, &link).unwrap();
        assert!(tail(&link, 1).is_err());
        assert_eq!(
            find(&[link.clone(), dir.join("none"), log.clone()]),
            Some(log)
        );
        assert_eq!(find(&[link]), None);
    }
}
