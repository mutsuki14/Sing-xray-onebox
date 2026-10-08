//! No-echo secret input on /dev/tty with termios restore on every path.
//!
//! Byte handling (spec B §2.10, kept from v2): EOF, Ctrl+C (3) and Ctrl+D (4)
//! cancel; CR/LF finish; backspace (8/127) removes one whole UTF-8
//! character; other bytes ≥ 32 are appended up to 4096 bytes; remaining
//! control bytes are ignored. The terminal is in no-echo, non-canonical,
//! no-signal mode only while reading, so Ctrl+C is seen as a byte and the
//! settings are restored before cancellation propagates.

use crate::error::{Error, Result};
use crate::sys::tty::NoEchoGuard;
use std::fs::OpenOptions;
use std::io::{self, Read, Write};
use std::os::fd::AsRawFd;

/// Longest accepted secret in bytes.
pub const MAX_SECRET: usize = 4096;

/// Outcome of feeding one byte.
#[derive(Debug, PartialEq, Eq)]
pub enum Step {
    More,
    Done(String),
    Cancelled,
    TooLong,
    InvalidUtf8,
}

/// The byte-level state machine behind [`read_secret`].
#[derive(Default)]
pub struct SecretBuffer {
    bytes: Vec<u8>,
}

impl SecretBuffer {
    pub fn feed(&mut self, byte: u8) -> Step {
        match byte {
            3 | 4 => Step::Cancelled,
            b'\r' | b'\n' => match String::from_utf8(std::mem::take(&mut self.bytes)) {
                Ok(s) => Step::Done(s),
                Err(_) => Step::InvalidUtf8,
            },
            8 | 127 => {
                self.bytes.pop();
                // Drop the rest of a multi-byte character.
                while !self.bytes.is_empty() && std::str::from_utf8(&self.bytes).is_err() {
                    self.bytes.pop();
                }
                Step::More
            }
            b if b >= 32 => {
                if self.bytes.len() >= MAX_SECRET {
                    return Step::TooLong;
                }
                self.bytes.push(b);
                Step::More
            }
            _ => Step::More,
        }
    }
}

impl Drop for SecretBuffer {
    fn drop(&mut self) {
        // Best effort: do not leave a half-typed secret in freed memory.
        self.bytes.fill(0);
    }
}

/// Read a secret from the controlling terminal without echo.
pub fn read_secret(prompt: &str) -> Result<String> {
    let mut tty = OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .map_err(|_| Error::msg("无法读取控制终端，请通过环境变量提供凭据"))?;
    // The prompt is written before switching modes (v2 order).
    write!(tty, "{prompt}（输入不回显，Ctrl+C 取消）: ")?;
    tty.flush()?;
    let guard = NoEchoGuard::enter(tty.as_raw_fd())?;
    let result = read_loop(&mut tty);
    drop(guard);
    // The newline that echo would have produced.
    let _ = writeln!(tty);
    result
}

fn read_loop(tty: &mut impl Read) -> Result<String> {
    let mut buffer = SecretBuffer::default();
    loop {
        let mut byte = [0u8];
        match tty.read(&mut byte) {
            Ok(0) => return Err(Error::Cancelled),
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {
                crate::sys::signal::check()?;
                continue;
            }
            Err(e) => return Err(e.into()),
        }
        match buffer.feed(byte[0]) {
            Step::More => {}
            Step::Done(secret) => return Ok(secret),
            Step::Cancelled => return Err(Error::Cancelled),
            Step::TooLong => return Err(Error::msg("凭据过长")),
            Step::InvalidUtf8 => return Err(Error::msg("凭据不是有效的 UTF-8")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn feed_all(input: &[u8]) -> Step {
        let mut buffer = SecretBuffer::default();
        for &b in input {
            let step = buffer.feed(b);
            if step != Step::More {
                return step;
            }
        }
        Step::More
    }

    #[test]
    fn byte_table() {
        for (input, expected) in [
            (&b"token\n"[..], Step::Done("token".into())),
            (b"tok\ren", Step::Done("tok".into())),
            (b"ab\x7fc\n", Step::Done("ac".into())),
            (b"ab\x08\x08\x08c\n", Step::Done("c".into())),
            (b"a\x01\x1bb\n", Step::Done("ab".into())),
            (b"abc\x03", Step::Cancelled),
            (b"\x04", Step::Cancelled),
            (b"\n", Step::Done(String::new())),
            (b"\xff\n", Step::InvalidUtf8),
        ] {
            assert_eq!(feed_all(input), expected, "{input:?}");
        }
    }

    #[test]
    fn backspace_removes_whole_utf8_character() {
        let mut input = "密钥".as_bytes().to_vec();
        input.push(127);
        input.push(b'\n');
        assert_eq!(feed_all(&input), Step::Done("密".into()));
    }

    #[test]
    fn length_cap() {
        let mut input = vec![b'x'; MAX_SECRET];
        assert_eq!(feed_all(&input), Step::More);
        input.push(b'y');
        assert_eq!(feed_all(&input), Step::TooLong);
    }

    #[test]
    fn read_loop_handles_eof_and_completion() {
        let mut ok = io::Cursor::new(b"pw\n".to_vec());
        assert_eq!(read_loop(&mut ok).unwrap(), "pw");
        let mut eof = io::Cursor::new(b"pw".to_vec());
        assert!(read_loop(&mut eof).unwrap_err().is_cancelled());
        let mut long = io::Cursor::new(vec![b'z'; MAX_SECRET + 1]);
        assert_eq!(read_loop(&mut long).unwrap_err().to_string(), "凭据过长");
    }
}
