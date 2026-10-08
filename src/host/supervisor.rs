//! Built-in daemon supervision for hosts without an init system: PID
//! identity records and detached spawning.
//!
//! A service's process is recorded in `{run_dir}/{name}.pid` (0600) as
//! `{"pid":N,"start":T}` with `T` = field 22 of `/proc/N/stat`. A record is
//! trusted only while the process with that PID still has that start time
//! (so a reused PID never matches), is not a zombie, runs the service's
//! program and has the service's command line ([`identity`]). PID files
//! written by others — nginx's own `pid` file, v1 FRP — are consulted after
//! the record, adopted into a record when found live, and removed on stop.
//!
//! Start and stop of one service are serialized by `{run_dir}/{name}.lock`,
//! so a boot-time `@reboot` start racing a manual one cannot spawn twice.
//!
//! Changes from v2:
//! - every nginx service is recognized by its master-process title, the
//!   subscription front included (E-8.1#2: it was never seen as running);
//! - daemons start with a cleared environment plus the fixed PATH and the
//!   service variables (E-8.1#3: admin-shell secrets leaked into them);
//! - check-then-spawn holds a per-service lock (E-8.1#20);
//! - liveness comes from `/proc` alone (no `kill(pid, 0)`), and stopping is
//!   SIGTERM, then SIGKILL after a grace period, ESRCH meaning "gone";
//! - a oneshot (the network restore) runs its own command synchronously
//!   instead of calling back into the workflow.

#[cfg(test)]
pub(crate) mod fixture;
pub mod identity;

use crate::ctx::Ctx;
use crate::error::{Error, Result};
use crate::host::service::{prepare_dir, ServiceDef, ServiceKind};
use crate::sys::exec::Cmd;
use crate::sys::fs::{atomic_write, read_to_string_bounded, remove_file_if_exists};
use crate::sys::lock::FileLock;
use identity::{command_matches, executable_matches, process_argv, process_start};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Largest PID file accepted.
const PID_FILE_MAX: u64 = 4096;
/// How long a pre-start command or a oneshot may run.
const COMMAND_TIMEOUT: Duration = Duration::from_secs(300);
pub const STOP_FAILED: &str = "后台服务未能退出，已保留 PID 记录";
pub const SPAWN_EXITED: &str = "启动的后台进程已退出";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PidRecord {
    pub pid: u32,
    pub start: u64,
}

/// A verified process of a service and the PID file naming it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Found {
    pub record: PidRecord,
    pub path: PathBuf,
    /// Found through a PID file the supervisor did not write.
    pub legacy: bool,
}

/// Sends signals to processes (faked in tests).
pub trait Signaller: Send + Sync {
    /// `Ok(false)` when the process no longer exists.
    fn signal(&self, pid: u32, signal: i32) -> Result<bool>;
}

pub struct SystemSignaller;

impl Signaller for SystemSignaller {
    fn signal(&self, pid: u32, signal: i32) -> Result<bool> {
        crate::sys::process::send_signal(pid, signal)
            .map_err(|e| Error::msg(format!("无法向进程 {pid} 发送信号: {e}")))
    }
}

/// Timing of stops and of waiting for the per-service lock.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StopPolicy {
    /// After SIGTERM, before SIGKILL.
    pub term_grace: Duration,
    /// After SIGKILL, before giving up.
    pub kill_grace: Duration,
    pub poll: Duration,
    /// How long a start/stop waits for a concurrent one on the same service.
    pub lock_wait: Duration,
}

impl Default for StopPolicy {
    fn default() -> Self {
        StopPolicy {
            term_grace: Duration::from_secs(5),
            kill_grace: Duration::from_secs(5),
            poll: Duration::from_millis(100),
            lock_wait: Duration::from_secs(15),
        }
    }
}

#[derive(Clone)]
pub struct Supervisor<'a> {
    ctx: &'a Ctx,
    signals: Arc<dyn Signaller>,
    policy: StopPolicy,
}

impl<'a> Supervisor<'a> {
    pub fn new(ctx: &'a Ctx) -> Self {
        Self::with(ctx, Arc::new(SystemSignaller), StopPolicy::default())
    }

    pub fn with(ctx: &'a Ctx, signals: Arc<dyn Signaller>, policy: StopPolicy) -> Self {
        Supervisor {
            ctx,
            signals,
            policy,
        }
    }

    fn system_root(&self) -> &Path {
        &self.ctx.paths.system_root
    }

    /// The live process of `def`: its record first, then legacy PID files.
    pub fn find(&self, def: &ServiceDef) -> Option<Found> {
        pid_files(def).into_iter().find_map(|(path, legacy)| {
            let record = self.verified(def, &path)?;
            Some(Found {
                record,
                path,
                legacy,
            })
        })
    }

    pub fn running(&self, def: &ServiceDef) -> bool {
        self.find(def).is_some()
    }

    /// Whether `record` is a live process of `def` (see the module docs).
    pub fn identifies(&self, def: &ServiceDef, record: &PidRecord) -> bool {
        let root = self.system_root();
        record.pid >= 2
            && process_start(root, record.pid) == Some(record.start)
            && executable_matches(root, record.pid, &def.program)
            && process_argv(root, record.pid).is_some_and(|argv| command_matches(def, &argv))
    }

    /// The record in `path` if it names a live process of `def`. Bare
    /// integers (older writers) take the start time from `/proc`.
    fn verified(&self, def: &ServiceDef, path: &Path) -> Option<PidRecord> {
        let text = read_to_string_bounded(path, PID_FILE_MAX).ok()?;
        let record = parse_record(&text, |pid| process_start(self.system_root(), pid))?;
        self.identifies(def, &record).then_some(record)
    }

    /// Start `def` unless it already runs. `env` is the service environment
    /// (the daemon gets nothing else besides the fixed PATH).
    pub fn start(&self, def: &ServiceDef, env: &[(String, String)]) -> Result<()> {
        let _lock = self.lock(def)?;
        self.start_locked(def, env)
    }

    pub fn stop(&self, def: &ServiceDef) -> Result<()> {
        let _lock = self.lock(def)?;
        self.stop_locked(def)
    }

    pub fn restart(&self, def: &ServiceDef, env: &[(String, String)]) -> Result<()> {
        let _lock = self.lock(def)?;
        self.stop_locked(def)?;
        self.start_locked(def, env)
    }

    fn start_locked(&self, def: &ServiceDef, env: &[(String, String)]) -> Result<()> {
        def.validate()?;
        if let Some(found) = self.find(def) {
            return self.adopt(def, &found);
        }
        if let Some(pre) = &def.pre_start {
            self.run_to_completion(pre, env)?;
        }
        if def.kind == ServiceKind::Oneshot {
            let argv: Vec<String> = std::iter::once(def.program.to_string_lossy().into_owned())
                .chain(def.args.iter().cloned())
                .collect();
            return self.run_to_completion(&argv, env);
        }
        self.spawn(def, env)
    }

    fn spawn(&self, def: &ServiceDef, env: &[(String, String)]) -> Result<()> {
        prepare_dir(&def.run_dir)?;
        prepare_dir(&def.log_dir)?;
        let cmd = Cmd::new(def.program.to_string_lossy())
            .args(&def.args)
            .daemon_env(env);
        let pid = self.ctx.exec.spawn_detached(&cmd, &def.log_file())?;
        let start =
            process_start(self.system_root(), pid).ok_or_else(|| Error::msg(SPAWN_EXITED))?;
        let record = PidRecord { pid, start };
        if let Err(error) = write_record(&def.pid_file(), &record) {
            // An unrecorded daemon could never be stopped: do not leave it.
            let _ = self.terminate(&record);
            return Err(error);
        }
        Ok(())
    }

    /// A process found through a legacy PID file becomes our own record;
    /// the legacy file has then been read for the last time.
    fn adopt(&self, def: &ServiceDef, found: &Found) -> Result<()> {
        if found.legacy {
            write_record(&def.pid_file(), &found.record)?;
            remove_file_if_exists(&found.path)?;
        }
        Ok(())
    }

    /// Terminate every verified process of `def` and remove its PID files.
    /// A process that survives SIGKILL keeps its file (and fails the stop).
    fn stop_locked(&self, def: &ServiceDef) -> Result<()> {
        for (path, _) in pid_files(def) {
            if let Some(record) = self.verified(def, &path) {
                self.terminate(&record)?;
            }
            remove_file_if_exists(&path)?;
        }
        Ok(())
    }

    /// SIGTERM, wait, SIGKILL, wait. "Gone" = the start time no longer
    /// matches (exited, zombie, or PID reused).
    fn terminate(&self, record: &PidRecord) -> Result<()> {
        let steps = [
            (libc::SIGTERM, self.policy.term_grace),
            (libc::SIGKILL, self.policy.kill_grace),
        ];
        for (signal, grace) in steps {
            if self.gone(record) || !self.signals.signal(record.pid, signal)? {
                return Ok(());
            }
            if self.wait_gone(record, grace) {
                return Ok(());
            }
        }
        Err(Error::msg(STOP_FAILED))
    }

    fn gone(&self, record: &PidRecord) -> bool {
        process_start(self.system_root(), record.pid) != Some(record.start)
    }

    fn wait_gone(&self, record: &PidRecord, grace: Duration) -> bool {
        let deadline = Instant::now() + grace;
        loop {
            if self.gone(record) {
                return true;
            }
            if Instant::now() >= deadline {
                return false;
            }
            std::thread::sleep(self.policy.poll);
        }
    }

    /// Run a helper command (pre-start, oneshot) with the service
    /// environment; a non-zero exit is an error.
    fn run_to_completion(&self, argv: &[String], env: &[(String, String)]) -> Result<()> {
        let (program, args) = argv
            .split_first()
            .ok_or_else(|| Error::msg("服务命令为空"))?;
        let cmd = Cmd::new(program)
            .args(args)
            .daemon_env(env)
            .timeout(COMMAND_TIMEOUT);
        self.ctx.check(&cmd).map(|_| ())
    }

    /// The per-service lock, waiting up to `lock_wait` for a concurrent
    /// start/stop of the same service to finish.
    fn lock(&self, def: &ServiceDef) -> Result<FileLock> {
        prepare_dir(&def.run_dir)?;
        let path = def.run_dir.join(format!("{}.lock", def.name));
        let busy = format!("服务 {} 正由另一个操作启动或停止；稍后重试", def.name);
        let deadline = Instant::now() + self.policy.lock_wait;
        loop {
            match FileLock::acquire(&path, &busy) {
                Err(Error::Busy(_)) if Instant::now() < deadline => {
                    std::thread::sleep(self.policy.poll);
                }
                other => return other,
            }
        }
    }
}

/// The supervisor's record first, then the legacy files (flagged).
fn pid_files(def: &ServiceDef) -> Vec<(PathBuf, bool)> {
    std::iter::once((def.pid_file(), false))
        .chain(def.legacy_pid_files.iter().map(|p| (p.clone(), true)))
        .collect()
}

/// `{"pid":N,"start":T}`, or a bare PID whose start time `start_of` reads.
pub fn parse_record(text: &str, start_of: impl Fn(u32) -> Option<u64>) -> Option<PidRecord> {
    if let Ok(record) = serde_json::from_str::<PidRecord>(text) {
        return (record.pid >= 2).then_some(record);
    }
    let pid: u32 = text.trim().parse().ok()?;
    if pid < 2 {
        return None;
    }
    Some(PidRecord {
        pid,
        start: start_of(pid)?,
    })
}

fn write_record(path: &Path, record: &PidRecord) -> Result<()> {
    atomic_write(path, &serde_json::to_vec(record)?, 0o600)
}

#[cfg(test)]
mod tests;
