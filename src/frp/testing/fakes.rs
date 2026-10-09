//! The programs and process facts of the fake host: systemd and OpenRC
//! service managers over shared unit states, a crontab, frps, and — for
//! hosts without an init system — detached spawns that appear under the
//! fake `/proc` and signals that end them.

use super::host::Units;
use crate::error::Result;
use crate::host::supervisor::fixture::FakeProc;
use crate::host::supervisor::Signaller;
use crate::sys::exec::{Cmd, Exec, FakeExec, Output, RunningChild};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

pub fn guard<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// `systemctl` over `units`.
pub fn systemctl(units: &Mutex<Units>, args: &[String]) -> Output {
    let mut u = guard(units);
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let ok = Output::success("");
    match args.as_slice() {
        ["is-active", "--quiet", name] if u.running.contains(*name) => ok,
        ["is-active", ..] => Output::failure(3, ""),
        ["is-enabled", name] if u.enabled.contains(*name) => Output::success("enabled\n"),
        ["is-enabled", _] => Output::failure(1, "disabled\n"),
        ["start" | "restart", name] => u.start(name),
        ["stop", name] => u.stop(name),
        ["enable", "--now", _] | ["daemon-reload"] => ok,
        ["enable", name] => {
            u.enabled.insert(name.to_string());
            ok
        }
        ["disable", name] => {
            u.enabled.remove(*name);
            ok
        }
        _ => Output::failure(1, "unexpected systemctl call"),
    }
}

/// `rc-service NAME start|stop|restart|status` over `units`.
pub fn rc_service(units: &Mutex<Units>, args: &[String]) -> Output {
    let mut u = guard(units);
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    match args.as_slice() {
        [name, "start" | "restart"] => u.start(name),
        [name, "stop"] => u.stop(name),
        [name, "status"] if u.running.contains(*name) => Output::success(" * status: started\n"),
        [_, "status"] => Output::failure(3, " * status: stopped\n"),
        _ => Output::failure(1, "unexpected rc-service call"),
    }
}

/// `rc-update add|del NAME default` and `rc-update show default`.
pub fn rc_update(units: &Mutex<Units>, args: &[String]) -> Output {
    let mut u = guard(units);
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    match args.as_slice() {
        ["add", name, "default"] => {
            u.enabled.insert(name.to_string());
            Output::success("")
        }
        ["del", name, "default"] => {
            u.enabled.remove(*name);
            Output::success("")
        }
        ["show", "default"] => Output::success(
            u.enabled
                .iter()
                .map(|name| format!(" {name} | default\n"))
                .collect::<String>(),
        ),
        _ => Output::failure(1, "unexpected rc-update call"),
    }
}

impl Units {
    fn start(&mut self, name: &str) -> Output {
        if self.broken.contains(name) {
            return Output::failure(1, format!("Job for {name} failed"));
        }
        self.running.insert(name.to_owned());
        Output::success("")
    }

    fn stop(&mut self, name: &str) -> Output {
        if self.stuck.contains(name) {
            return Output::failure(1, format!("Job for {name} timed out"));
        }
        self.running.remove(name);
        Output::success("")
    }
}

/// `crontab -l` / `crontab FILE` over one table (`None`: no crontab yet).
pub fn crontab_cmd(crontab: &Mutex<Option<String>>, args: &[String]) -> Result<Output> {
    let mut tab = guard(crontab);
    Ok(match args.first().map(String::as_str) {
        Some("-l") => match tab.as_ref() {
            Some(text) => Output::success(text.clone()),
            None => Output::failure(1, "no crontab for root"),
        },
        Some(file) => {
            *tab = Some(std::fs::read_to_string(file)?);
            Output::success("")
        }
        None => Output::failure(1, "usage"),
    })
}

/// A fake frps: `-v` prints the version its file carries (see
/// [`super::fake_frps`]); `verify` accepts any configuration.
pub fn frps_cmd(program: &str, args: &[String]) -> Output {
    match args.first().map(String::as_str) {
        Some("-v") => match std::fs::read(program) {
            Ok(bytes) => {
                let text = String::from_utf8_lossy(&bytes).into_owned();
                let version = text.rsplit(' ').next().unwrap_or("").to_owned();
                Output::success(format!("{version}\n"))
            }
            Err(_) => Output::failure(127, "not found"),
        },
        Some("verify") => Output::success("frps: the configuration file is syntax ok\n"),
        _ => Output::failure(2, "unexpected frps call"),
    }
}

/// How `/proc/PID/exe` names `program` (what the supervisor's identity
/// check expects: the canonical path, or the canonical directory plus the
/// file name for a program that does not exist on this machine).
fn exe_link(program: &Path) -> PathBuf {
    std::fs::canonicalize(program)
        .ok()
        .or_else(|| {
            let parent = program.parent()?.canonicalize().ok()?;
            Some(parent.join(program.file_name()?))
        })
        .unwrap_or_else(|| program.to_path_buf())
}

/// The fake exec of the host: everything goes to the [`FakeExec`]; a
/// detached spawn (a daemon the supervisor starts) also appears under the
/// fake `/proc` with its executable and command line.
pub struct HostExec {
    pub fake: Arc<FakeExec>,
    pub system_root: PathBuf,
    pub clock: AtomicU64,
}

impl Exec for HostExec {
    fn run(&self, cmd: &Cmd) -> Result<Output> {
        self.fake.run(cmd)
    }

    fn spawn(&self, cmd: &Cmd) -> Result<Box<dyn RunningChild>> {
        self.fake.spawn(cmd)
    }

    fn spawn_detached(&self, cmd: &Cmd, log: &Path) -> Result<u32> {
        let pid = self.fake.spawn_detached(cmd, log)?;
        let argv: Vec<&str> = std::iter::once(cmd.program.as_str())
            .chain(cmd.args.iter().map(String::as_str))
            .collect();
        let start = 1000 + self.clock.fetch_add(1, Ordering::SeqCst);
        FakeProc::new(&self.system_root).add(pid, start, &exe_link(Path::new(&cmd.program)), &argv);
        Ok(pid)
    }

    fn which(&self, program: &str) -> Option<PathBuf> {
        self.fake.which(program)
    }
}

/// Signals against the fake `/proc`: every delivered signal ends the
/// process (never a real `kill`).
pub struct FakeSignals {
    pub system_root: PathBuf,
}

impl Signaller for FakeSignals {
    fn signal(&self, pid: u32, _signal: i32) -> Result<bool> {
        let procs = FakeProc::new(&self.system_root);
        if !procs.exists(pid) {
            return Ok(false);
        }
        procs.remove(pid);
        Ok(true)
    }
}
