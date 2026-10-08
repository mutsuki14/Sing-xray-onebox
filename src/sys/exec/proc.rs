//! Process plumbing shared by [`SystemExec`](super::SystemExec): the
//! pre-exec setup, output captures and a started child ([`Proc`]).
//!
//! Children in their own process group or session are watched with
//! `waitid(WNOWAIT)`: the exited leader stays a zombie until its output is
//! drained, so its pid — and therefore the process-group id — cannot be
//! reused while we may still signal the group.

use super::{Cmd, Output, Stdin, INHERITED_LOCK_FD};
use crate::error::{Error, Result};
use std::io::{self, Read, Write};
use std::os::fd::RawFd;
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::PathBuf;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::{mpsc, Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

pub(super) const POLL_INTERVAL: Duration = Duration::from_millis(50);
/// How long to wait for output pipes to close once the leader is gone; a
/// daemon in another session could keep them open forever.
pub(super) const DRAIN_GRACE: Duration = Duration::from_secs(1);

/// What the child does between fork and exec. Everything here must be
/// async-signal-safe: plain syscalls, no allocation, no locks.
#[derive(Clone, Copy)]
pub(super) struct ChildSetup {
    /// Own process group so a timeout can kill the whole tree.
    pub(super) new_group: bool,
    /// Own session (supervised children and detached daemons).
    pub(super) new_session: bool,
    /// Descriptor to expose as [`INHERITED_LOCK_FD`] without CLOEXEC.
    pub(super) lock_fd: Option<RawFd>,
    /// Open-files limit to raise to ([`Cmd::nofile_limit`]).
    pub(super) nofile: Option<u64>,
}

impl ChildSetup {
    pub(super) fn install(self, command: &mut Command) {
        // SAFETY: the closure only performs async-signal-safe syscalls
        // (pthread_sigmask, setpgid, setsid, dup2, fcntl, getrlimit,
        // setrlimit) and constructs io::Error from raw errno values, which
        // does not allocate.
        unsafe {
            command.pre_exec(move || self.apply());
        }
    }

    fn apply(self) -> io::Result<()> {
        reset_signal_mask()?;
        if let Some(limit) = self.nofile {
            raise_nofile(limit);
        }
        // SAFETY: plain syscalls on our own process / valid descriptor numbers.
        unsafe {
            if self.new_group && libc::setpgid(0, 0) != 0 {
                return Err(io::Error::last_os_error());
            }
            if self.new_session && libc::setsid() < 0 {
                return Err(io::Error::last_os_error());
            }
            if let Some(fd) = self.lock_fd {
                if fd != INHERITED_LOCK_FD && libc::dup2(fd, INHERITED_LOCK_FD) < 0 {
                    return Err(io::Error::last_os_error());
                }
                let flags = libc::fcntl(INHERITED_LOCK_FD, libc::F_GETFD);
                if flags < 0
                    || libc::fcntl(INHERITED_LOCK_FD, libc::F_SETFD, flags & !libc::FD_CLOEXEC) < 0
                {
                    return Err(io::Error::last_os_error());
                }
            }
        }
        Ok(())
    }

    fn own_group(self) -> bool {
        self.new_group || self.new_session
    }
}

/// Best effort, like systemd's `setrlimit_closest`: `limit` for both soft
/// and hard limits when the hard limit may be raised, else the soft limit
/// up to the current hard limit. A soft limit already at `limit` or above
/// is left alone.
fn raise_nofile(limit: u64) {
    let limit = libc::rlim_t::from(limit);
    // SAFETY: getrlimit/setrlimit read and write a plain struct we own.
    unsafe {
        let mut current: libc::rlimit = std::mem::zeroed();
        if libc::getrlimit(libc::RLIMIT_NOFILE, &mut current) != 0 || current.rlim_cur >= limit {
            return;
        }
        let wanted = libc::rlimit {
            rlim_cur: limit,
            rlim_max: limit.max(current.rlim_max),
        };
        if libc::setrlimit(libc::RLIMIT_NOFILE, &wanted) == 0 {
            return;
        }
        let closest = libc::rlimit {
            rlim_cur: limit.min(current.rlim_max),
            rlim_max: current.rlim_max,
        };
        libc::setrlimit(libc::RLIMIT_NOFILE, &closest);
    }
}

/// Unblock every signal: parents block INT/TERM/HUP during critical
/// sections and the mask survives exec, which would make daemons unkillable.
fn reset_signal_mask() -> io::Result<()> {
    // SAFETY: sigset_t is plain data initialised by sigemptyset before use.
    unsafe {
        let mut mask: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut mask);
        let rc = libc::pthread_sigmask(libc::SIG_SETMASK, &mask, std::ptr::null_mut());
        if rc != 0 {
            return Err(io::Error::from_raw_os_error(rc));
        }
    }
    Ok(())
}

/// The child reports a failed `chdir` with the same errno as a failed exec,
/// so check the working directory before blaming the program.
pub(super) fn spawn_error(cmd: &Cmd, e: &io::Error) -> Error {
    if let Some(dir) = &cmd.cwd {
        match std::fs::metadata(dir) {
            Err(err) if err.kind() == io::ErrorKind::NotFound => {
                return Error::msg(format!("工作目录不存在: {}", dir.display()));
            }
            Ok(meta) if !meta.is_dir() => {
                return Error::msg(format!("工作目录不是目录: {}", dir.display()));
            }
            _ => {}
        }
    }
    let program = &cmd.program;
    match e.kind() {
        io::ErrorKind::NotFound => Error::msg(format!("未找到程序 {program}")),
        io::ErrorKind::PermissionDenied => Error::msg(format!("无法执行 {program}: 权限不足")),
        _ => Error::msg(format!("无法执行 {program}: {e}")),
    }
}

pub(super) fn exit_code(status: ExitStatus) -> i32 {
    status
        .code()
        .unwrap_or_else(|| 128 + status.signal().unwrap_or(0))
}

/// Write stdin from a thread so a child that fills its stdout pipe before
/// reading all input cannot deadlock us. Write errors (EPIPE when the child
/// exits early) are irrelevant: the exit status tells the story.
fn feed_stdin(child: &mut Child, bytes: Vec<u8>) {
    if let Some(mut pipe) = child.stdin.take() {
        std::thread::spawn(move || {
            let _ = pipe.write_all(&bytes);
        });
    }
}

/// A pipe drained by a background thread into a shared buffer, so a caller
/// that stops waiting still gets what arrived so far.
#[derive(Default)]
struct Capture {
    data: Arc<Mutex<Vec<u8>>>,
    done: Option<mpsc::Receiver<()>>,
}

impl Capture {
    /// `limit` keeps only the last `limit` bytes.
    fn start<R: Read + Send + 'static>(pipe: Option<R>, limit: Option<usize>) -> Capture {
        let Some(mut pipe) = pipe else {
            return Capture::default();
        };
        let data = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&data);
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let mut chunk = vec![0u8; 64 * 1024];
            loop {
                match pipe.read(&mut chunk) {
                    Ok(0) => break,
                    Ok(n) => append(&sink, &chunk[..n], limit),
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                    Err(_) => break,
                }
            }
            let _ = tx.send(());
        });
        Capture {
            data,
            done: Some(rx),
        }
    }

    /// Wait for end of file until `deadline` (forever when `None`); true
    /// once the pipe is fully drained.
    fn wait(&mut self, deadline: Option<Instant>) -> bool {
        let Some(rx) = &self.done else {
            return true;
        };
        let finished = match deadline {
            None => {
                let _ = rx.recv();
                true
            }
            Some(deadline) => !matches!(
                rx.recv_timeout(deadline.saturating_duration_since(Instant::now())),
                Err(mpsc::RecvTimeoutError::Timeout)
            ),
        };
        if finished {
            self.done = None;
        }
        finished
    }

    /// The text captured so far (lossy UTF-8).
    fn take(&mut self) -> String {
        let bytes = std::mem::take(&mut *self.data.lock().unwrap_or_else(PoisonError::into_inner));
        String::from_utf8_lossy(&bytes).into_owned()
    }
}

fn append(sink: &Mutex<Vec<u8>>, bytes: &[u8], limit: Option<usize>) {
    let mut buf = sink.lock().unwrap_or_else(PoisonError::into_inner);
    buf.extend_from_slice(bytes);
    if let Some(limit) = limit {
        // Trim lazily (at twice the limit) to avoid a memmove per chunk;
        // `Proc::finish` cuts the final text to exactly `limit`.
        if buf.len() > limit.saturating_mul(2) {
            let excess = buf.len() - limit;
            buf.drain(..excess);
        }
    }
}

/// A started child with its output captures.
pub(super) struct Proc {
    child: Child,
    pub(super) pid: libc::pid_t,
    /// Leader of its own process group (pgid == pid).
    own_group: bool,
    stdout: Capture,
    stderr: Capture,
    limit: Option<usize>,
    reaped: bool,
}

impl Proc {
    pub(super) fn start(
        cmd: &Cmd,
        mut command: Command,
        setup: ChildSetup,
        limit: Option<usize>,
    ) -> Result<Proc> {
        command.stdin(match cmd.stdin {
            Stdin::Null => Stdio::null(),
            Stdin::Inherit => Stdio::inherit(),
            Stdin::Bytes(_) => Stdio::piped(),
        });
        if cmd.stream {
            command.stdout(Stdio::inherit()).stderr(Stdio::inherit());
        } else {
            command.stdout(Stdio::piped()).stderr(Stdio::piped());
        }
        setup.install(&mut command);
        let mut child = command.spawn().map_err(|e| spawn_error(cmd, &e))?;
        if let Stdin::Bytes(bytes) = &cmd.stdin {
            feed_stdin(&mut child, bytes.clone());
        }
        let stdout = Capture::start(child.stdout.take(), limit);
        let stderr = Capture::start(child.stderr.take(), limit);
        Ok(Proc {
            pid: child.id() as libc::pid_t,
            child,
            own_group: setup.own_group(),
            stdout,
            stderr,
            limit,
            reaped: false,
        })
    }

    /// Plain wait: no time limit, output read to end of file.
    pub(super) fn wait_untimed(mut self, cmd: &Cmd) -> Result<Output> {
        let status = self
            .child
            .wait()
            .map_err(|e| Error::io(PathBuf::from(&cmd.program), e))?;
        self.reaped = true;
        self.stdout.wait(None);
        self.stderr.wait(None);
        Ok(Output {
            code: exit_code(status),
            stdout: self.stdout.take(),
            stderr: self.stderr.take(),
        })
    }

    /// Whether the child has exited, without reaping it (see module docs).
    pub(super) fn exited(&self) -> io::Result<bool> {
        loop {
            // SAFETY: siginfo_t is plain data that waitid fills in; it is
            // zeroed first so `si_pid` stays 0 when nothing has exited.
            let (rc, pid) = unsafe {
                let mut info: libc::siginfo_t = std::mem::zeroed();
                let rc = libc::waitid(
                    libc::P_PID,
                    self.pid as libc::id_t,
                    &mut info,
                    libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
                );
                (rc, info.si_pid())
            };
            if rc == 0 {
                return Ok(pid != 0);
            }
            let err = io::Error::last_os_error();
            if err.kind() != io::ErrorKind::Interrupted {
                return Err(err);
            }
        }
    }

    /// Poll until the child exits or `limit` passes; true when it exited.
    pub(super) fn wait_exit(&self, limit: Duration) -> io::Result<bool> {
        let deadline = Instant::now() + limit;
        loop {
            if self.exited()? {
                return Ok(true);
            }
            let now = Instant::now();
            if now >= deadline {
                return Ok(false);
            }
            std::thread::sleep(POLL_INTERVAL.min(deadline - now));
        }
    }

    pub(super) fn signal_group(&self, sig: libc::c_int) {
        if self.own_group && !self.reaped {
            // SAFETY: kill(2) on the group the child leads; the leader is not
            // reaped yet, so the id cannot have been reused.
            unsafe {
                libc::kill(-self.pid, sig);
            }
        }
    }

    /// Once the leader has exited (or been killed): wait up to `drain` for
    /// the output pipes to close; if members of its group still hold them,
    /// kill the group and wait briefly again; then reap the leader.
    pub(super) fn finish(&mut self, drain: Duration) -> io::Result<(ExitStatus, String, String)> {
        if !self.drain(drain) {
            self.signal_group(libc::SIGKILL);
            self.drain(DRAIN_GRACE);
        }
        let status = self.child.wait()?;
        self.reaped = true;
        let (mut stdout, mut stderr) = (self.stdout.take(), self.stderr.take());
        if let Some(limit) = self.limit {
            stdout = tail(stdout, limit);
            stderr = tail(stderr, limit);
        }
        Ok((status, stdout, stderr))
    }

    fn drain(&mut self, limit: Duration) -> bool {
        let deadline = Some(Instant::now() + limit);
        // Both waits run even when the first one gives up.
        self.stdout.wait(deadline) & self.stderr.wait(deadline)
    }
}

impl Drop for Proc {
    fn drop(&mut self) {
        // Only reached on error paths: never leave a running group behind.
        if !self.reaped && self.own_group {
            self.signal_group(libc::SIGKILL);
            let _ = self.child.wait();
        }
    }
}

/// The last `limit` bytes of `text`, cut at a character boundary.
fn tail(text: String, limit: usize) -> String {
    if text.len() <= limit {
        return text;
    }
    let mut start = text.len() - limit;
    while !text.is_char_boundary(start) {
        start += 1;
    }
    text[start..].to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tail_cuts_at_character_boundaries() {
        assert_eq!(tail("abc".into(), 5), "abc");
        assert_eq!(tail("abcdef".into(), 3), "def");
        // "节" occupies bytes 1..4; a cut at byte 3 moves forward to 4.
        assert_eq!(tail("a节点".into(), 4), "点");
    }
}
