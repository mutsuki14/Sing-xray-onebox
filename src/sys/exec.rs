//! Process execution behind a trait so every module can be tested with
//! [`FakeExec`].
//!
//! Rules (fixes v2 E-8.1#3): children always start with an empty signal mask;
//! commands built with [`Cmd::daemon_env`] get a cleared environment, a fixed
//! PATH and only the explicitly passed variables, so admin-shell secrets such
//! as `CF_Token` never leak into long-running services.
//!
//! Changes from v2: spawn failures name the program (`未找到程序 nginx`
//! instead of a bare `No such file or directory`); signal deaths report
//! 128 + signal instead of a flat 128; commands may carry a timeout, which
//! kills the whole process group; `which` also searches [`SAFE_PATH`]
//! because cron and sudo often run us without the sbin directories.

use crate::error::{Error, Result};
use std::io::{self, Read, Write};
use std::os::fd::RawFd;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{mpsc, Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

/// The fd number used to hand the node lock to a child (`regen` during
/// self-update). Compatible with v2.
pub const INHERITED_LOCK_FD: RawFd = 198;
pub const INHERITED_LOCK_ENV: &str = "ONEBOX_INHERITED_LOCK_FD";
/// PATH given to daemons, cron jobs and cleared-environment children.
pub const SAFE_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";
/// Exit code reported when a command exceeded its timeout (like timeout(1)).
pub const TIMEOUT_EXIT: i32 = 124;

const POLL_INTERVAL: Duration = Duration::from_millis(50);
/// After killing a timed-out group, how long to wait for its pipes to close
/// (a daemon in another session could keep them open forever).
const DRAIN_GRACE: Duration = Duration::from_secs(1);

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
    fn run(&self, cmd: &Cmd) -> Result<Output> {
        let lock_fd = match cmd.inherit_lock_fd {
            Some(fd) if fd < 0 => return Err(Error::msg("配置锁描述符无效")),
            other => other,
        };
        let mut command = base_command(cmd);
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
        let setup = ChildSetup {
            new_group: cmd.timeout.is_some(),
            new_session: false,
            lock_fd,
        };
        setup.install(&mut command);
        let mut child = command.spawn().map_err(|e| spawn_error(&cmd.program, &e))?;
        if let Stdin::Bytes(bytes) = &cmd.stdin {
            feed_stdin(&mut child, bytes.clone());
        }
        let stdout = Capture::start(child.stdout.take());
        let stderr = Capture::start(child.stderr.take());
        let waited = wait_child(&mut child, cmd.timeout)
            .map_err(|e| Error::io(PathBuf::from(&cmd.program), e))?;
        Ok(match (waited, cmd.timeout) {
            (Some(status), _) => Output {
                code: exit_code(status),
                stdout: stdout.collect(None),
                stderr: stderr.collect(None),
            },
            (None, limit) => Output {
                code: TIMEOUT_EXIT,
                stdout: stdout.collect(Some(DRAIN_GRACE)),
                stderr: format!("命令超时（{} 秒）", format_secs(limit.unwrap_or_default())),
            },
        })
    }

    fn spawn_detached(&self, cmd: &Cmd, log: &Path) -> Result<u32> {
        if cmd.inherit_lock_fd.is_some() {
            return Err(Error::msg("后台进程不能继承配置锁"));
        }
        let log_file = open_log(log)?;
        let stderr = log_file.try_clone().map_err(|e| Error::io(log, e))?;
        let mut command = base_command(cmd);
        command
            .stdin(Stdio::null())
            .stdout(Stdio::from(log_file))
            .stderr(Stdio::from(stderr));
        let setup = ChildSetup {
            new_group: false,
            new_session: true,
            lock_fd: None,
        };
        setup.install(&mut command);
        // The Child handle is dropped without waiting: the daemon lives on in
        // its own session; the init system or our supervisor tracks its PID.
        let child = command.spawn().map_err(|e| spawn_error(&cmd.program, &e))?;
        Ok(child.id())
    }

    fn which(&self, program: &str) -> Option<PathBuf> {
        let path = std::env::var_os("PATH").unwrap_or_default();
        which_in(program, &path)
    }
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

fn base_command(cmd: &Cmd) -> Command {
    let mut command = Command::new(&cmd.program);
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

/// What the child does between fork and exec. Everything here must be
/// async-signal-safe: plain syscalls, no allocation, no locks.
#[derive(Clone, Copy)]
struct ChildSetup {
    /// Own process group so a timeout can kill the whole tree.
    new_group: bool,
    /// Own session (detached daemons).
    new_session: bool,
    /// Descriptor to expose as [`INHERITED_LOCK_FD`] without CLOEXEC.
    lock_fd: Option<RawFd>,
}

impl ChildSetup {
    fn install(self, command: &mut Command) {
        // SAFETY: the closure only performs async-signal-safe syscalls
        // (pthread_sigmask, setpgid, setsid, dup2, fcntl) and constructs
        // io::Error from raw errno values, which does not allocate.
        unsafe {
            command.pre_exec(move || self.apply());
        }
    }

    fn apply(self) -> io::Result<()> {
        reset_signal_mask()?;
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

fn spawn_error(program: &str, e: &io::Error) -> Error {
    match e.kind() {
        io::ErrorKind::NotFound => Error::msg(format!("未找到程序 {program}")),
        io::ErrorKind::PermissionDenied => Error::msg(format!("无法执行 {program}: 权限不足")),
        _ => Error::msg(format!("无法执行 {program}: {e}")),
    }
}

fn exit_code(status: ExitStatus) -> i32 {
    status
        .code()
        .unwrap_or_else(|| 128 + status.signal().unwrap_or(0))
}

fn format_secs(d: Duration) -> String {
    if d.subsec_millis() == 0 {
        d.as_secs().to_string()
    } else {
        format!("{:.1}", d.as_secs_f64())
    }
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

/// A pipe drained by a background thread.
struct Capture(Option<mpsc::Receiver<Vec<u8>>>);

impl Capture {
    fn start<R: Read + Send + 'static>(pipe: Option<R>) -> Capture {
        Capture(pipe.map(|mut pipe| {
            let (tx, rx) = mpsc::channel();
            std::thread::spawn(move || {
                let mut buf = Vec::new();
                let _ = pipe.read_to_end(&mut buf);
                let _ = tx.send(buf);
            });
            rx
        }))
    }

    /// The captured text (lossy UTF-8); `limit` bounds the wait for EOF.
    fn collect(self, limit: Option<Duration>) -> String {
        let Some(rx) = self.0 else {
            return String::new();
        };
        let bytes = match limit {
            None => rx.recv().unwrap_or_default(),
            Some(limit) => rx.recv_timeout(limit).unwrap_or_default(),
        };
        String::from_utf8_lossy(&bytes).into_owned()
    }
}

/// Wait for the child. `Ok(None)` means the timeout expired and the child's
/// process group was killed and reaped. A signal that arrives while waiting
/// (recorded by `sys::signal`) is forwarded once to the child's group, which
/// otherwise would not see a terminal Ctrl+C.
fn wait_child(child: &mut Child, timeout: Option<Duration>) -> io::Result<Option<ExitStatus>> {
    let Some(limit) = timeout else {
        return child.wait().map(Some);
    };
    let deadline = Instant::now() + limit;
    let pgid = child.id() as libc::pid_t;
    let signal_at_start = crate::sys::signal::pending();
    let mut forwarded = false;
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(Some(status));
        }
        let now = Instant::now();
        if now >= deadline {
            kill_group(pgid, libc::SIGKILL);
            child.wait()?;
            return Ok(None);
        }
        if let Some(sig) = crate::sys::signal::pending() {
            if !forwarded && Some(sig) != signal_at_start {
                kill_group(pgid, sig);
                forwarded = true;
            }
        }
        std::thread::sleep(POLL_INTERVAL.min(deadline - now));
    }
}

fn kill_group(pgid: libc::pid_t, sig: libc::c_int) {
    // SAFETY: kill(2) with a negative pid targets the process group the child
    // created in pre_exec; it is not reaped yet, so the id cannot be reused.
    unsafe {
        libc::kill(-pgid, sig);
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

type Matcher = Box<dyn Fn(&Cmd) -> bool + Send + Sync>;
type Responder = Box<dyn Fn(&Cmd) -> Result<Output> + Send + Sync>;

/// One scripted response of a [`FakeExec`].
pub struct Rule {
    pub matcher: Matcher,
    pub respond: Responder,
}

/// Scripted fake for tests: rules are tried in insertion order and the first
/// match answers; unmatched commands fail with exit 127 so tests notice
/// unexpected calls. Records every command.
#[derive(Default)]
pub struct FakeExec {
    rules: Mutex<Vec<Arc<Rule>>>,
    calls: Mutex<Vec<Cmd>>,
    spawned: Mutex<Vec<(Cmd, PathBuf)>>,
    programs: Mutex<Vec<String>>,
    spawn_count: AtomicU32,
}

/// First fake PID handed out by [`FakeExec::spawn_detached`].
pub const FAKE_PID_BASE: u32 = 40_000;

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    // A panicking test thread must not poison the fake for other assertions.
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

fn program_matches(cmd: &Cmd, program: &str) -> bool {
    cmd.program == program || cmd.program_name() == program
}

impl FakeExec {
    pub fn new() -> Self {
        FakeExec::default()
    }

    /// Respond to `program` (exact string or file name) whose args start with `prefix`.
    pub fn on(&self, program: &str, prefix: &[&str], output: Output) -> &Self {
        let program = program.to_owned();
        let prefix: Vec<String> = prefix.iter().map(|s| s.to_string()).collect();
        self.on_fn(
            move |cmd| program_matches(cmd, &program) && cmd.args.starts_with(&prefix),
            move |_| Ok(output.clone()),
        )
    }

    /// Respond with a closure to commands accepted by `matcher`.
    pub fn on_fn(
        &self,
        matcher: impl Fn(&Cmd) -> bool + Send + Sync + 'static,
        respond: impl Fn(&Cmd) -> Result<Output> + Send + Sync + 'static,
    ) -> &Self {
        lock(&self.rules).push(Arc::new(Rule {
            matcher: Box::new(matcher),
            respond: Box::new(respond),
        }));
        self
    }

    /// Make `which(program)` succeed.
    pub fn provide(&self, program: &str) -> &Self {
        lock(&self.programs).push(program.to_owned());
        self
    }

    /// Command lines recorded so far (`Cmd::display`), including detached spawns.
    pub fn history(&self) -> Vec<String> {
        lock(&self.calls).iter().map(Cmd::display).collect()
    }

    /// Every command recorded so far, in order.
    pub fn calls(&self) -> Vec<Cmd> {
        lock(&self.calls).clone()
    }

    /// Detached spawns with their log paths.
    pub fn spawned(&self) -> Vec<(Cmd, PathBuf)> {
        lock(&self.spawned).clone()
    }

    /// Forget recorded calls (rules and provided programs stay).
    pub fn clear_history(&self) {
        lock(&self.calls).clear();
        lock(&self.spawned).clear();
    }
}

impl Exec for FakeExec {
    fn run(&self, cmd: &Cmd) -> Result<Output> {
        lock(&self.calls).push(cmd.clone());
        // Release the rules lock before responding so responders may add rules.
        let rule = lock(&self.rules)
            .iter()
            .find(|rule| (rule.matcher)(cmd))
            .cloned();
        match rule {
            Some(rule) => (rule.respond)(cmd),
            None => Ok(Output::failure(
                127,
                format!("fake: unexpected command: {}", cmd.display()),
            )),
        }
    }

    fn spawn_detached(&self, cmd: &Cmd, log: &Path) -> Result<u32> {
        lock(&self.calls).push(cmd.clone());
        lock(&self.spawned).push((cmd.clone(), log.to_path_buf()));
        Ok(FAKE_PID_BASE + self.spawn_count.fetch_add(1, Ordering::SeqCst))
    }

    fn which(&self, program: &str) -> Option<PathBuf> {
        let name = Path::new(program)
            .file_name()?
            .to_string_lossy()
            .into_owned();
        if !lock(&self.programs)
            .iter()
            .any(|p| *p == name || p == program)
        {
            return None;
        }
        Some(if program.starts_with('/') {
            PathBuf::from(program)
        } else {
            PathBuf::from(format!("/usr/bin/{name}"))
        })
    }
}

#[cfg(test)]
mod tests;
