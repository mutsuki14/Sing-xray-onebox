//! Process execution behind a trait so every module can be tested with
//! [`FakeExec`].
//!
//! Rules (fixes v2 E-8.1#3): children always start with an empty signal mask;
//! detached daemons must be built with [`Cmd::daemon_env`] (cleared
//! environment, fixed PATH, only the explicitly passed variables), so
//! admin-shell secrets such as `CF_Token` never leak into long-running
//! services — both [`SystemExec`] and [`FakeExec`] refuse a daemon without it.
//!
//! Changes from v2: spawn failures name the program (`未找到程序 nginx`
//! instead of a bare `No such file or directory`) or the missing working
//! directory; signal deaths report 128 + signal instead of a flat 128;
//! commands may carry a timeout that bounds the whole run (including output
//! held open by background grandchildren) and then terminates the whole
//! process group (SIGTERM, SIGKILL after a grace);
//! supervised children ([`Exec::spawn`]) run in their own session and are
//! killed with their group when dropped; `which` also searches [`SAFE_PATH`]
//! because cron and sudo often run us without the sbin directories; while
//! the caller blocks the cancellation signals, untimed children run in
//! their own process group too ([`Cmd::foreground`] opts out), so the
//! terminal's signals cannot kill them in the middle of a section that
//! must not be interrupted.

mod fake;
mod proc;
mod system;

pub use fake::{FakeExec, FakeLife, Rule, FAKE_PID_BASE};
pub use system::SystemExec;

use crate::error::{Error, Result};
use std::os::fd::RawFd;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// The fd number used to hand the node lock to a child (`regen` during
/// self-update). Compatible with v2.
pub const INHERITED_LOCK_FD: RawFd = 198;
pub const INHERITED_LOCK_ENV: &str = "ONEBOX_INHERITED_LOCK_FD";
/// PATH given to daemons, cron jobs and cleared-environment children.
pub const SAFE_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";
/// Exit code reported when a command exceeded its timeout (like timeout(1)).
pub const TIMEOUT_EXIT: i32 = 124;
/// Error for a detached daemon started without [`Cmd::daemon_env`].
pub const DAEMON_ENV_REQUIRED: &str = "后台进程必须使用隔离环境（Cmd::daemon_env）";

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum Stdin {
    #[default]
    Null,
    Inherit,
    Bytes(Vec<u8>),
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Cmd {
    pub program: String,
    pub args: Vec<String>,
    pub env: Vec<(String, String)>,
    pub clear_env: bool,
    pub stdin: Stdin,
    pub timeout: Option<Duration>,
    pub inherit_lock_fd: Option<RawFd>,
    /// Inherit stdout/stderr (long installs show progress) instead of capturing.
    pub stream: bool,
    pub cwd: Option<PathBuf>,
    /// Raise the child's open-files soft limit to this value (and its hard
    /// limit when allowed); see [`Cmd::nofile_limit`].
    pub nofile: Option<u64>,
    /// Keep an untimed child in our process group even while the caller
    /// blocks the cancellation signals; see [`Cmd::foreground`].
    pub foreground: bool,
}

impl Cmd {
    pub fn new(program: impl Into<String>) -> Self {
        Cmd {
            program: program.into(),
            ..Cmd::default()
        }
    }
    pub fn arg(mut self, arg: impl Into<String>) -> Self {
        self.args.push(arg.into());
        self
    }
    pub fn args<I, S>(mut self, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.args.extend(args.into_iter().map(Into::into));
        self
    }
    pub fn env(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.env.push((key.into(), value.into()));
        self
    }
    /// Untranslated messages for a command whose output is parsed
    /// (`Status: active`, strerror texts): `LC_ALL=C` and an empty
    /// `LANGUAGE`, which gettext — Python's even ahead of `LC_ALL` — would
    /// otherwise follow (`LANG=zh_CN.UTF-8` from an SSH client).
    pub fn c_locale(self) -> Self {
        self.env("LC_ALL", "C").env("LANGUAGE", "")
    }
    /// Whether [`Cmd::c_locale`] was applied (test assertions).
    #[cfg(test)]
    pub fn is_c_locale(&self) -> bool {
        let has = |key: &str, value: &str| self.env.iter().any(|(k, v)| k == key && v == value);
        has("LC_ALL", "C") && has("LANGUAGE", "")
    }
    /// Start from an empty environment (only `env` entries are passed).
    pub fn clear_env(mut self) -> Self {
        self.clear_env = true;
        self
    }
    /// Cleared environment with `PATH=SAFE_PATH` plus `vars`.
    pub fn daemon_env(mut self, vars: &[(String, String)]) -> Self {
        self.clear_env = true;
        self.env.push(("PATH".into(), SAFE_PATH.into()));
        self.env.extend(vars.iter().cloned());
        self
    }
    pub fn stdin_bytes(mut self, bytes: impl Into<Vec<u8>>) -> Self {
        self.stdin = Stdin::Bytes(bytes.into());
        self
    }
    pub fn stdin_inherit(mut self) -> Self {
        self.stdin = Stdin::Inherit;
        self
    }
    /// Bound the whole run by `timeout`: when it expires the command's
    /// process group gets SIGTERM, is killed after a short grace (5 s) for
    /// cleaning up, and the output has code 124; when the command exits in
    /// time but background processes it left in its group still hold its
    /// output pipes at the deadline, they are killed. Timed commands run in
    /// their own process group, so they must not read from the terminal; a
    /// terminal Ctrl+C is forwarded to them.
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }
    pub fn stream(mut self) -> Self {
        self.stream = true;
        self
    }
    pub fn cwd(mut self, dir: impl Into<PathBuf>) -> Self {
        self.cwd = Some(dir.into());
        self
    }
    pub fn inherit_lock(mut self, fd: RawFd) -> Self {
        self.inherit_lock_fd = Some(fd);
        self
    }
    /// Give the child at least `limit` open files where the host allows
    /// it: like systemd's `LimitNOFILE`, the hard limit is raised when we
    /// may (CAP_SYS_RESOURCE), else the soft limit goes up to the current
    /// hard limit (unprivileged containers). A higher soft limit is kept.
    /// Never fails the spawn.
    pub fn nofile_limit(mut self, limit: u64) -> Self {
        self.nofile = Some(limit);
        self
    }
    /// While the calling thread blocks INT/TERM/HUP (a critical section
    /// under [`BlockSignals`](crate::sys::signal::BlockSignals)), untimed
    /// children run in their own process group, so a terminal Ctrl+C or a
    /// hang-up cannot kill a firewall command half-way through a rollback
    /// either. This keeps the child in our (the terminal's) group instead:
    /// for a child that handles cancellation itself and should still be
    /// interruptible from the terminal (the self-update child `regen`).
    pub fn foreground(mut self) -> Self {
        self.foreground = true;
        self
    }
    /// Program file name for messages (`/usr/bin/nginx` → `nginx`).
    pub fn program_name(&self) -> String {
        Path::new(&self.program)
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| self.program.clone())
    }
    /// Human-readable command line (for logs and test assertions; never
    /// contains secrets because secrets are passed via env or stdin).
    pub fn display(&self) -> String {
        std::iter::once(self.program.as_str())
            .chain(self.args.iter().map(String::as_str))
            .collect::<Vec<_>>()
            .join(" ")
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Output {
    /// Exit status, or 128 + signal number when killed, or 124 on timeout.
    pub code: i32,
    pub stdout: String,
    pub stderr: String,
}

impl Output {
    pub fn ok(&self) -> bool {
        self.code == 0
    }
    pub fn success(stdout: impl Into<String>) -> Self {
        Output {
            code: 0,
            stdout: stdout.into(),
            stderr: String::new(),
        }
    }
    pub fn failure(code: i32, stderr: impl Into<String>) -> Self {
        Output {
            code,
            stdout: String::new(),
            stderr: stderr.into(),
        }
    }
}

pub trait Exec: Send + Sync {
    /// Run to completion. Errors only when the program cannot be started,
    /// or when a cancellation signal interrupted a timed command while no
    /// `SignalScope` owner was active (`Error::Cancelled`, exit 130).
    fn run(&self, cmd: &Cmd) -> Result<Output>;
    /// Start a supervised child in its own session (so its whole process
    /// group can be signalled) and return a handle to poll, wait for and
    /// kill it. Output is captured (the last 1 MiB per stream) unless
    /// `cmd.stream`. Dropping the handle terminates and reaps the group.
    /// The child does not see the terminal's Ctrl+C: callers that wait for
    /// it hold a `SignalScope` and kill it when cancelled.
    fn spawn(&self, cmd: &Cmd) -> Result<Box<dyn RunningChild>>;
    /// Start a detached daemon (`setsid`, cwd `/` unless set, stdin null,
    /// stdout+stderr appended to `log` opened with O_NOFOLLOW, mode 0600).
    /// `cmd` must use [`Cmd::daemon_env`]. Returns the PID.
    fn spawn_detached(&self, cmd: &Cmd, log: &Path) -> Result<u32>;
    /// Resolve a program name through PATH (absolute names are checked as-is).
    fn which(&self, program: &str) -> Option<PathBuf>;
}

/// A child started by [`Exec::spawn`]. Results are cached: once an
/// [`Output`] was returned, later calls return the same one. A `timeout` on
/// the `Cmd` is enforced whenever the child is polled (code 124).
pub trait RunningChild: Send {
    fn pid(&self) -> u32;
    /// The output if the child has exited (it is then reaped), else `None`.
    fn try_wait(&mut self) -> Result<Option<Output>>;
    /// Like `try_wait`, waiting up to `limit` for the child to exit.
    fn wait_timeout(&mut self, limit: Duration) -> Result<Option<Output>>;
    /// Send `signal` to the child's whole process group (no-op once reaped).
    fn kill_group(&mut self, signal: i32) -> Result<()>;
    /// SIGTERM the group, wait up to `grace`, then SIGKILL it; reap.
    fn terminate(&mut self, grace: Duration) -> Result<Output>;
}

/// Preconditions of [`Exec::spawn_detached`], shared by every implementation
/// so tests with [`FakeExec`] catch the same mistakes as production.
pub fn check_detached(cmd: &Cmd) -> Result<()> {
    if cmd.inherit_lock_fd.is_some() {
        return Err(Error::msg("后台进程不能继承配置锁"));
    }
    if !cmd.clear_env {
        return Err(Error::msg(DAEMON_ENV_REQUIRED));
    }
    Ok(())
}

/// Preconditions of [`Exec::spawn`].
pub fn check_spawn(cmd: &Cmd) -> Result<()> {
    if cmd.inherit_lock_fd.is_some() {
        return Err(Error::msg("子进程不能继承配置锁"));
    }
    Ok(())
}

/// `which` against an explicit PATH value, then [`SAFE_PATH`]. Relative
/// PATH entries are ignored (they would depend on the current directory).
pub fn which_in(program: &str, path_var: &std::ffi::OsStr) -> Option<PathBuf> {
    if program.is_empty() {
        return None;
    }
    if program.contains('/') {
        let candidate = Path::new(program);
        return (candidate.is_absolute() && is_executable(candidate))
            .then(|| candidate.to_path_buf());
    }
    std::env::split_paths(path_var)
        .chain(std::env::split_paths(SAFE_PATH))
        .filter(|dir| dir.is_absolute())
        .map(|dir| dir.join(program))
        .find(|candidate| is_executable(candidate))
}

fn is_executable(path: &Path) -> bool {
    std::fs::metadata(path).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
}

#[cfg(test)]
mod tests;
