//! Terminal primitives: TTY detection and a no-echo raw mode guard used by
//! secret prompts. The guard restores the saved termios on every exit path.

use crate::error::{Error, Result};
use std::io;
use std::os::fd::RawFd;

/// True when `fd` refers to a terminal.
pub fn is_terminal(fd: RawFd) -> bool {
    // SAFETY: isatty only inspects the descriptor.
    unsafe { libc::isatty(fd) == 1 }
}

/// While alive, the terminal on `fd` neither echoes nor generates signals
/// and delivers input byte by byte (ICANON, ECHO, ECHONL, ISIG cleared;
/// VMIN=1, VTIME=0). Ctrl+C therefore arrives as byte 3, so the caller can
/// cancel after the terminal settings are restored.
pub struct NoEchoGuard {
    fd: RawFd,
    saved: libc::termios,
}

impl NoEchoGuard {
    pub fn enter(fd: RawFd) -> Result<NoEchoGuard> {
        // SAFETY: termios is plain data filled by tcgetattr before use.
        let saved = unsafe {
            let mut saved: libc::termios = std::mem::zeroed();
            if libc::tcgetattr(fd, &mut saved) != 0 {
                return Err(term_error());
            }
            saved
        };
        let mut hidden = saved;
        hidden.c_lflag &= !(libc::ECHO | libc::ECHONL | libc::ICANON | libc::ISIG);
        hidden.c_cc[libc::VMIN] = 1;
        hidden.c_cc[libc::VTIME] = 0;
        // SAFETY: applying a termios derived from the one the kernel returned.
        if unsafe { libc::tcsetattr(fd, libc::TCSANOW, &hidden) } != 0 {
            return Err(term_error());
        }
        Ok(NoEchoGuard { fd, saved })
    }
}

fn term_error() -> Error {
    Error::msg(format!("无法设置终端模式: {}", io::Error::last_os_error()))
}

impl Drop for NoEchoGuard {
    fn drop(&mut self) {
        // SAFETY: restoring the settings saved in `enter` on the same fd.
        unsafe {
            libc::tcsetattr(self.fd, libc::TCSANOW, &self.saved);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn non_terminals_are_detected() {
        let file = std::fs::File::open("/dev/null").unwrap();
        use std::os::fd::AsRawFd;
        assert!(!is_terminal(file.as_raw_fd()));
        assert!(NoEchoGuard::enter(file.as_raw_fd()).is_err());
    }
}
