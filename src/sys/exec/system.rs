//! [`SystemExec`]: the real [`Exec`] on top of `std::process`: timed runs,
//! supervised children and detached daemons.

use super::proc::{exit_code, spawn_error, ChildSetup, Proc, DRAIN_GRACE, POLL_INTERVAL};
use super::{
    check_detached, check_spawn, which_in, Cmd, Exec, Output, RunningChild, INHERITED_LOCK_ENV,
    INHERITED_LOCK_FD, SAFE_PATH, TIMEOUT_EXIT,
};
use crate::error::{Error, Result};
use crate::sys::signal;
use std::io;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};
/// After forwarding a cancellation signal to a timed child's group, how long
/// it may clean up before the group is killed.
const CANCEL_GRACE: Duration = Duration::from_secs(2);
/// SIGTERM → SIGKILL grace for a dropped supervised child (spec D).
const DROP_GRACE: Duration = Duration::from_millis(500);
/// Output kept per stream of a supervised child (the tail).
const SPAWN_CAPTURE_LIMIT: usize = 1 << 20;

/// The real implementation.
pub struct SystemExec;

impl Exec for SystemExec {
    fn run(&self, cmd: &Cmd) -> Result<Output> {
        let lock_fd = match cmd.inherit_lock_fd {
            Some(fd) if fd < 0 => return Err(Error::msg("配置锁描述符无效")),
            other => other,
        };
        let setup = ChildSetup {
            new_group: cmd.timeout.is_some() || shielded(cmd),
            new_session: false,
            lock_fd,
            nofile: cmd.nofile,
        };
        match cmd.timeout {
            None => Proc::start(cmd, base_command(cmd), setup, None)?.wait_untimed(cmd),
            Some(limit) => run_timed(cmd, setup, limit),
        }
    }

    fn spawn(&self, cmd: &Cmd) -> Result<Box<dyn RunningChild>> {
        check_spawn(cmd)?;
        let setup = ChildSetup {
            new_group: false,
            new_session: true,
            lock_fd: None,
            nofile: cmd.nofile,
        };
        let proc = Proc::start(cmd, base_command(cmd), setup, Some(SPAWN_CAPTURE_LIMIT))?;
        Ok(Box::new(SystemChild {
            pid: proc.pid as u32,
            proc: Some(proc),
            deadline: cmd.timeout.map(|t| Instant::now() + t),
            timeout: cmd.timeout,
            result: None,
        }))
    }

    fn spawn_detached(&self, cmd: &Cmd, log: &Path) -> Result<u32> {
        check_detached(cmd)?;
        let log_file = open_log(log)?;
        let stderr = log_file.try_clone().map_err(|e| Error::io(log, e))?;
        let mut command = base_command(cmd);
        if !cmd.env.iter().any(|(k, _)| k == "PATH") {
            command.env("PATH", SAFE_PATH);
        }
        if cmd.cwd.is_none() {
            // Do not keep the admin's working directory (or its mount) busy.
            command.current_dir("/");
        }
        command
            .stdin(Stdio::null())
            .stdout(Stdio::from(log_file))
            .stderr(Stdio::from(stderr));
        let setup = ChildSetup {
            new_group: false,
            new_session: true,
            lock_fd: None,
            nofile: cmd.nofile,
        };
        setup.install(&mut command);
        // The Child handle is dropped without waiting: the daemon lives on in
        // its own session; the init system or our supervisor tracks its PID.
        let child = command.spawn().map_err(|e| spawn_error(cmd, &e))?;
        Ok(child.id())
    }

    fn which(&self, program: &str) -> Option<PathBuf> {
        let path = std::env::var_os("PATH").unwrap_or_default();
        which_in(program, &path)
    }
}

/// Whether an untimed child gets its own process group because the caller
/// blocks the cancellation signals ([`Cmd::foreground`]). In our group it
/// would still receive the terminal's Ctrl+C and the hang-up of a dropped
/// SSH session with its mask reset — a firewall command of a rollback
/// killed half-way, the rest of its rules skipped. A child reading the
/// terminal stays in the foreground group (in another one it would stop).
fn shielded(cmd: &Cmd) -> bool {
    !cmd.foreground && cmd.stdin != super::Stdin::Inherit && signal::cancel_blocked()
}

/// The PATH the child will see: its own `PATH` entry, else ours unless the
/// environment is cleared.
fn child_path(cmd: &Cmd) -> std::ffi::OsString {
    match cmd.env.iter().rev().find(|(k, _)| k == "PATH") {
        Some((_, v)) => v.into(),
        None if cmd.clear_env => std::ffi::OsString::new(),
        None => std::env::var_os("PATH").unwrap_or_default(),
    }
}

fn base_command(cmd: &Cmd) -> Command {
    // Bare names are resolved like `which` (PATH, then SAFE_PATH) so a
    // program that `which` reports as present can also be run under cron's
    // minimal PATH. argv[0] stays the name the caller used.
    let resolved = (!cmd.program.contains('/'))
        .then(|| which_in(&cmd.program, &child_path(cmd)))
        .flatten();
    let mut command = match &resolved {
        Some(path) => {
            let mut c = Command::new(path);
            c.arg0(&cmd.program);
            c
        }
        None => Command::new(&cmd.program),
    };
    command.args(&cmd.args);
    if cmd.clear_env {
        command.env_clear();
    }
    command.envs(cmd.env.iter().map(|(k, v)| (k, v)));
    if cmd.inherit_lock_fd.is_some() {
        command.env(INHERITED_LOCK_ENV, INHERITED_LOCK_FD.to_string());
    }
    if let Some(dir) = &cmd.cwd {
        command.current_dir(dir);
    }
    command
}

pub(super) fn format_secs(d: Duration) -> String {
    if d.subsec_millis() == 0 {
        d.as_secs().to_string()
    } else {
        format!("{:.1}", d.as_secs_f64())
    }
}

fn timeout_message(limit: Duration) -> String {
    format!("命令超时（{} 秒）", format_secs(limit))
}

enum Outcome {
    Exited,
    TimedOut,
    Cancelled(i32),
}

/// A command with a timeout: it runs in its own process group, which is
/// killed at the deadline. Output still held open by the group at the
/// deadline does not extend the run. New cancellation signals are forwarded
/// to the group; without a `SignalScope` owner the run then fails with
/// `Error::Cancelled` (the user pressed Ctrl+C), with one the output is
/// returned and the owner cancels at its next safe point.
fn run_timed(cmd: &Cmd, setup: ChildSetup, limit: Duration) -> Result<Output> {
    // Handlers first: a Ctrl+C right after the spawn must not kill us and
    // orphan the child's group.
    let scope = signal::WaitScope::acquire()?;
    let start = signal::received();
    let mut proc = Proc::start(cmd, base_command(cmd), setup, None)?;
    let deadline = Instant::now() + limit;
    let io_error = |e| Error::io(PathBuf::from(&cmd.program), e);
    let outcome = watch(&proc, deadline, start).map_err(io_error)?;
    let drain = match outcome {
        Outcome::Exited => deadline
            .saturating_duration_since(Instant::now())
            .max(DRAIN_GRACE),
        _ => DRAIN_GRACE,
    };
    let (status, stdout, stderr) = proc.finish(drain).map_err(io_error)?;
    match outcome {
        Outcome::TimedOut => Ok(Output {
            code: TIMEOUT_EXIT,
            stdout,
            stderr: timeout_message(limit),
        }),
        Outcome::Cancelled(sig) if !scope.owned() => {
            signal::clear();
            Err(Error::Cancelled.wrap(format!("{} 被信号 {sig} 中断", cmd.program_name())))
        }
        Outcome::Exited | Outcome::Cancelled(_) => Ok(Output {
            code: exit_code(status),
            stdout,
            stderr,
        }),
    }
}

/// Wait for a timed child until it exits, the deadline passes (group killed)
/// or a new cancellation signal arrives (forwarded; the group is killed if
/// it does not exit within [`CANCEL_GRACE`]).
fn watch(proc: &Proc, deadline: Instant, start: signal::Received) -> io::Result<Outcome> {
    loop {
        if proc.exited()? {
            return Ok(Outcome::Exited);
        }
        let now = Instant::now();
        if now >= deadline {
            proc.signal_group(libc::SIGKILL);
            return Ok(Outcome::TimedOut);
        }
        let seen = signal::received();
        if seen.count != start.count && seen.last != 0 {
            proc.signal_group(seen.last);
            if !proc.wait_exit(CANCEL_GRACE)? {
                proc.signal_group(libc::SIGKILL);
            }
            return Ok(Outcome::Cancelled(seen.last));
        }
        std::thread::sleep(POLL_INTERVAL.min(deadline - now));
    }
}

/// [`RunningChild`] over a [`Proc`] in its own session.
struct SystemChild {
    pid: u32,
    /// `None` once reaped.
    proc: Option<Proc>,
    deadline: Option<Instant>,
    timeout: Option<Duration>,
    result: Option<Output>,
}

impl SystemChild {
    /// Reap the (exited or killed) child and cache its output.
    fn complete(&mut self, timed_out: bool) -> Result<Output> {
        let Some(mut proc) = self.proc.take() else {
            return self
                .result
                .clone()
                .ok_or_else(|| Error::msg("子进程已结束，结果不可用"));
        };
        let program = PathBuf::from(format!("pid {}", self.pid));
        let (status, stdout, stderr) = proc
            .finish(DRAIN_GRACE)
            .map_err(|e| Error::io(program, e))?;
        let output = match (timed_out, self.timeout) {
            (true, Some(limit)) => Output {
                code: TIMEOUT_EXIT,
                stdout,
                stderr: timeout_message(limit),
            },
            _ => Output {
                code: exit_code(status),
                stdout,
                stderr,
            },
        };
        self.result = Some(output.clone());
        Ok(output)
    }
}

impl RunningChild for SystemChild {
    fn pid(&self) -> u32 {
        self.pid
    }

    fn try_wait(&mut self) -> Result<Option<Output>> {
        let Some(proc) = &self.proc else {
            return self.complete(false).map(Some);
        };
        if proc.exited()? {
            return self.complete(false).map(Some);
        }
        if self.deadline.is_some_and(|d| Instant::now() >= d) {
            proc.signal_group(libc::SIGKILL);
            return self.complete(true).map(Some);
        }
        Ok(None)
    }

    fn wait_timeout(&mut self, limit: Duration) -> Result<Option<Output>> {
        let until = Instant::now() + limit;
        loop {
            if let Some(output) = self.try_wait()? {
                return Ok(Some(output));
            }
            let now = Instant::now();
            if now >= until {
                return Ok(None);
            }
            std::thread::sleep(POLL_INTERVAL.min(until - now));
        }
    }

    fn kill_group(&mut self, signal: i32) -> Result<()> {
        if let Some(proc) = &self.proc {
            proc.signal_group(signal);
        }
        Ok(())
    }

    fn terminate(&mut self, grace: Duration) -> Result<Output> {
        if let Some(output) = self.try_wait()? {
            return Ok(output);
        }
        self.kill_group(libc::SIGTERM)?;
        if let Some(output) = self.wait_timeout(grace)? {
            return Ok(output);
        }
        self.kill_group(libc::SIGKILL)?;
        self.complete(false)
    }
}

impl Drop for SystemChild {
    fn drop(&mut self) {
        if self.proc.is_some() {
            let _ = self.terminate(DROP_GRACE);
        }
    }
}

/// Open (create) a daemon log: parent created 0700 when missing, the file
/// itself 0600, append-only, never through a symlink.
fn open_log(log: &Path) -> Result<std::fs::File> {
    if let Some(parent) = log.parent().filter(|p| !p.as_os_str().is_empty()) {
        if !parent.exists() {
            std::fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(parent)
                .map_err(|e| Error::io(parent, e))?;
        }
    }
    std::fs::OpenOptions::new()
        .append(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(log)
        .map_err(|e| match e.raw_os_error() {
            Some(libc::ELOOP) => Error::msg(format!("不允许符号链接: {}", log.display())),
            _ => Error::io(log, e),
        })
}
