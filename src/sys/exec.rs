//! Process execution behind a trait so every module can be tested with
//! [`FakeExec`].
//!
//! Rules (fixes v2 E-8.1#3): children always start with an empty signal mask;
//! commands built with [`Cmd::daemon_env`] get a cleared environment, a fixed
//! PATH and only the explicitly passed variables, so admin-shell secrets such
//! as `CF_Token` never leak into long-running services.

use crate::error::Result;
use std::os::fd::RawFd;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Duration;

/// The fd number used to hand the node lock to a child (`regen` during
/// self-update). Compatible with v2.
pub const INHERITED_LOCK_FD: RawFd = 198;
pub const INHERITED_LOCK_ENV: &str = "ONEBOX_INHERITED_LOCK_FD";
/// PATH given to daemons, cron jobs and cleared-environment children.
pub const SAFE_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

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
    /// Run to completion. Errors only when the program cannot be started.
    fn run(&self, cmd: &Cmd) -> Result<Output>;
    /// Start a detached daemon (`setsid`, stdin null, stdout+stderr appended to
    /// `log` opened with O_NOFOLLOW, mode 0600). Returns the PID.
    fn spawn_detached(&self, cmd: &Cmd, log: &Path) -> Result<u32>;
    /// Resolve a program name through PATH (absolute names are checked as-is).
    fn which(&self, program: &str) -> Option<PathBuf>;
}

/// The real implementation.
pub struct SystemExec;

impl Exec for SystemExec {
    fn run(&self, _cmd: &Cmd) -> Result<Output> {
        todo!("WP-A1: std::process::Command with pre_exec signal-mask reset, env policy, stdin, timeout, lock fd 198")
    }
    fn spawn_detached(&self, _cmd: &Cmd, _log: &Path) -> Result<u32> {
        todo!("WP-A1")
    }
    fn which(&self, _program: &str) -> Option<PathBuf> {
        todo!("WP-A1")
    }
}

/// Scripted fake for tests: first matching rule wins; unmatched commands fail
/// with exit 127 so tests notice unexpected calls. Records every command.
#[derive(Default)]
pub struct FakeExec {
    pub rules: Mutex<Vec<Rule>>,
    pub calls: Mutex<Vec<Cmd>>,
    pub programs: Mutex<Vec<String>>,
}

pub struct Rule {
    pub matcher: Box<dyn Fn(&Cmd) -> bool + Send + Sync>,
    #[allow(clippy::type_complexity)]
    pub respond: Box<dyn Fn(&Cmd) -> Result<Output> + Send + Sync>,
}

impl FakeExec {
    pub fn new() -> Self {
        FakeExec::default()
    }
    /// Respond to `program` whose args start with `prefix`.
    pub fn on(&self, _program: &str, _prefix: &[&str], _output: Output) -> &Self {
        todo!("WP-A1")
    }
    pub fn on_fn(
        &self,
        _matcher: impl Fn(&Cmd) -> bool + Send + Sync + 'static,
        _respond: impl Fn(&Cmd) -> Result<Output> + Send + Sync + 'static,
    ) -> &Self {
        todo!("WP-A1")
    }
    /// Make `which(program)` succeed.
    pub fn provide(&self, _program: &str) -> &Self {
        todo!("WP-A1")
    }
    /// Command lines recorded so far (`Cmd::display`).
    pub fn history(&self) -> Vec<String> {
        todo!("WP-A1")
    }
}

impl Exec for FakeExec {
    fn run(&self, _cmd: &Cmd) -> Result<Output> {
        todo!("WP-A1")
    }
    fn spawn_detached(&self, _cmd: &Cmd, _log: &Path) -> Result<u32> {
        todo!("WP-A1")
    }
    fn which(&self, _program: &str) -> Option<PathBuf> {
        todo!("WP-A1")
    }
}
