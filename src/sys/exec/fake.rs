//! [`FakeExec`]: the scripted `Exec` used by unit tests across the crate.

use super::{check_detached, check_spawn, Cmd, Exec, Output, RunningChild};
use crate::error::Result;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

type Matcher = Box<dyn Fn(&Cmd) -> bool + Send + Sync>;
type Responder = Box<dyn Fn(&Cmd) -> Result<Output> + Send + Sync>;
type SignalLog = Arc<Mutex<Vec<(u32, i32)>>>;

/// One scripted response of a [`FakeExec`].
pub struct Rule {
    pub matcher: Matcher,
    pub respond: Responder,
}

/// How a child started with [`FakeExec::spawn`](Exec::spawn) behaves.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FakeLife {
    /// Exits with its scripted output as soon as it is polled.
    Exits,
    /// Runs until signalled (`kill_group`, `terminate`, drop); then exits
    /// with code 128 + signal and the scripted stdout/stderr.
    UntilKilled,
}

struct SpawnRule {
    program: String,
    prefix: Vec<String>,
    life: FakeLife,
    output: Output,
}

/// Scripted fake for tests: rules are tried in insertion order and the first
/// match answers; unmatched commands fail with exit 127 so tests notice
/// unexpected calls. Records every command. Enforces the same
/// preconditions as `SystemExec` (e.g. daemons need `Cmd::daemon_env`).
#[derive(Default)]
pub struct FakeExec {
    rules: Mutex<Vec<Arc<Rule>>>,
    spawn_rules: Mutex<Vec<Arc<SpawnRule>>>,
    calls: Mutex<Vec<Cmd>>,
    spawned: Mutex<Vec<(Cmd, PathBuf)>>,
    programs: Mutex<Vec<String>>,
    signals: SignalLog,
    spawn_count: AtomicU32,
}

/// First fake PID handed out by `spawn` / `spawn_detached`.
pub const FAKE_PID_BASE: u32 = 40_000;

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    // A panicking test thread must not poison the fake for other assertions.
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

fn program_matches(cmd: &Cmd, program: &str) -> bool {
    cmd.program == program || cmd.program_name() == program
}

fn unexpected(cmd: &Cmd) -> Output {
    Output::failure(127, format!("fake: unexpected command: {}", cmd.display()))
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

    /// Script children started with `spawn` (matched like [`FakeExec::on`]).
    /// Unmatched spawns fall back to the `on` rules with [`FakeLife::Exits`].
    pub fn on_spawn(
        &self,
        program: &str,
        prefix: &[&str],
        life: FakeLife,
        output: Output,
    ) -> &Self {
        lock(&self.spawn_rules).push(Arc::new(SpawnRule {
            program: program.to_owned(),
            prefix: prefix.iter().map(|s| s.to_string()).collect(),
            life,
            output,
        }));
        self
    }

    /// Make `which(program)` succeed.
    pub fn provide(&self, program: &str) -> &Self {
        lock(&self.programs).push(program.to_owned());
        self
    }

    /// Command lines recorded so far (`Cmd::display`), including spawns.
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

    /// `(pid, signal)` sent to spawned children, in order (drops included).
    pub fn signals(&self) -> Vec<(u32, i32)> {
        lock(&self.signals).clone()
    }

    /// Forget recorded calls (rules and provided programs stay).
    pub fn clear_history(&self) {
        lock(&self.calls).clear();
        lock(&self.spawned).clear();
        lock(&self.signals).clear();
    }

    fn next_pid(&self) -> u32 {
        FAKE_PID_BASE + self.spawn_count.fetch_add(1, Ordering::SeqCst)
    }

    /// How a spawned `cmd` behaves: spawn rules, then run rules, else 127.
    fn script(&self, cmd: &Cmd) -> Result<(FakeLife, Output)> {
        let spawn_rule = lock(&self.spawn_rules)
            .iter()
            .find(|r| program_matches(cmd, &r.program) && cmd.args.starts_with(&r.prefix))
            .cloned();
        if let Some(rule) = spawn_rule {
            return Ok((rule.life, rule.output.clone()));
        }
        let rule = lock(&self.rules)
            .iter()
            .find(|rule| (rule.matcher)(cmd))
            .cloned();
        Ok(match rule {
            Some(rule) => (FakeLife::Exits, (rule.respond)(cmd)?),
            None => (FakeLife::Exits, unexpected(cmd)),
        })
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
            None => Ok(unexpected(cmd)),
        }
    }

    fn spawn(&self, cmd: &Cmd) -> Result<Box<dyn RunningChild>> {
        check_spawn(cmd)?;
        lock(&self.calls).push(cmd.clone());
        let (life, output) = self.script(cmd)?;
        Ok(Box::new(FakeChild {
            pid: self.next_pid(),
            life,
            output,
            result: None,
            signals: Arc::clone(&self.signals),
        }))
    }

    fn spawn_detached(&self, cmd: &Cmd, log: &Path) -> Result<u32> {
        check_detached(cmd)?;
        lock(&self.calls).push(cmd.clone());
        lock(&self.spawned).push((cmd.clone(), log.to_path_buf()));
        Ok(self.next_pid())
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

/// A scripted [`RunningChild`]; time does not pass (waits return at once).
struct FakeChild {
    pid: u32,
    life: FakeLife,
    output: Output,
    result: Option<Output>,
    signals: SignalLog,
}

impl RunningChild for FakeChild {
    fn pid(&self) -> u32 {
        self.pid
    }

    fn try_wait(&mut self) -> Result<Option<Output>> {
        if self.result.is_none() && self.life == FakeLife::Exits {
            self.result = Some(self.output.clone());
        }
        Ok(self.result.clone())
    }

    fn wait_timeout(&mut self, _limit: Duration) -> Result<Option<Output>> {
        self.try_wait()
    }

    fn kill_group(&mut self, signal: i32) -> Result<()> {
        if self.result.is_some() {
            return Ok(());
        }
        lock(&self.signals).push((self.pid, signal));
        if signal != 0 {
            self.result = Some(Output {
                code: 128 + signal,
                ..self.output.clone()
            });
        }
        Ok(())
    }

    fn terminate(&mut self, _grace: Duration) -> Result<Output> {
        if let Some(output) = self.try_wait()? {
            return Ok(output);
        }
        self.kill_group(libc::SIGTERM)?;
        Ok(self.result.clone().unwrap_or_default())
    }
}

impl Drop for FakeChild {
    fn drop(&mut self) {
        if self.result.is_none() && self.life == FakeLife::UntilKilled {
            let _ = self.kill_group(libc::SIGTERM);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::Error;
    use crate::sys::exec::DAEMON_ENV_REQUIRED;

    #[test]
    fn rules_match_in_order() {
        let fake = FakeExec::new();
        fake.on("systemctl", &["is-active"], Output::success("active\n"))
            .on("systemctl", &[], Output::failure(5, "generic"))
            .on("/usr/sbin/nginx", &["-t"], Output::success("syntax ok"));
        let active = fake
            .run(&Cmd::new("systemctl").args(["is-active", "onebox-xray"]))
            .unwrap();
        assert_eq!(active.stdout, "active\n");
        let other = fake.run(&Cmd::new("/bin/systemctl").arg("stop")).unwrap();
        assert_eq!(other.code, 5, "matched by file name");
        assert!(fake
            .run(&Cmd::new("/usr/sbin/nginx").arg("-t"))
            .unwrap()
            .ok());
        let miss = fake.run(&Cmd::new("nginx").arg("-t")).unwrap();
        assert_eq!(miss.code, 127, "rule program is a path; bare name differs");
        assert_eq!(miss.stderr, "fake: unexpected command: nginx -t");
        assert_eq!(
            fake.history(),
            [
                "systemctl is-active onebox-xray",
                "/bin/systemctl stop",
                "/usr/sbin/nginx -t",
                "nginx -t"
            ]
        );
    }

    #[test]
    fn closures_detached_spawns_and_which() {
        let fake = FakeExec::new();
        fake.on_fn(
            |cmd| cmd.program == "curl",
            |cmd| Ok(Output::success(cmd.args.join(","))),
        )
        .on_fn(
            |cmd| cmd.program == "boom",
            |_| Err(Error::msg("未找到程序 boom")),
        );
        assert_eq!(
            fake.run(&Cmd::new("curl").args(["-4", "x"]))
                .unwrap()
                .stdout,
            "-4,x"
        );
        assert!(fake.run(&Cmd::new("boom")).is_err());
        let log = Path::new("/tmp/x.log");
        let daemon = Cmd::new("frps").daemon_env(&[]);
        let first = fake.spawn_detached(&daemon, log).unwrap();
        let second = fake.spawn_detached(&daemon, log).unwrap();
        assert_eq!((first, second), (FAKE_PID_BASE, FAKE_PID_BASE + 1));
        assert_eq!(fake.spawned().len(), 2);
        assert_eq!(fake.calls().len(), 4);
        fake.provide("nft");
        assert_eq!(fake.which("nft"), Some(PathBuf::from("/usr/bin/nft")));
        assert_eq!(
            fake.which("/usr/sbin/nft"),
            Some(PathBuf::from("/usr/sbin/nft"))
        );
        assert_eq!(fake.which("ufw"), None);
        fake.clear_history();
        assert!(fake.history().is_empty());
    }

    #[test]
    fn detached_spawns_enforce_the_daemon_rules() {
        let fake = FakeExec::new();
        let log = Path::new("/tmp/x.log");
        let err = fake.spawn_detached(&Cmd::new("frps"), log).unwrap_err();
        assert_eq!(err.to_string(), DAEMON_ENV_REQUIRED);
        let locked = Cmd::new("frps").daemon_env(&[]).inherit_lock(3);
        assert!(fake.spawn_detached(&locked, log).is_err());
        assert!(fake.history().is_empty(), "refused spawns are not recorded");
    }

    #[test]
    fn scripted_supervised_children() {
        let fake = FakeExec::new();
        fake.on_spawn(
            "sing-box",
            &["run"],
            FakeLife::UntilKilled,
            Output::failure(0, "log line"),
        )
        .on("sing-box", &["check"], Output::failure(1, "bad config"));

        let mut core = fake
            .spawn(&Cmd::new("/opt/onebox/bin/sing-box").args(["run", "-c", "x"]))
            .unwrap();
        assert_eq!(core.try_wait().unwrap(), None);
        assert_eq!(core.wait_timeout(Duration::from_secs(1)).unwrap(), None);
        core.kill_group(0).unwrap();
        assert_eq!(core.try_wait().unwrap(), None, "signal 0 only probes");
        let out = core.terminate(Duration::from_millis(500)).unwrap();
        assert_eq!((out.code, out.stderr.as_str()), (143, "log line"));
        let pid = core.pid();
        assert_eq!(fake.signals(), [(pid, 0), (pid, libc::SIGTERM)]);

        // Without a spawn rule the run rules answer and the child exits.
        let mut check = fake.spawn(&Cmd::new("sing-box").arg("check")).unwrap();
        assert_eq!(check.try_wait().unwrap().unwrap().code, 1);
        let mut other = fake.spawn(&Cmd::new("xray")).unwrap();
        assert_eq!(other.try_wait().unwrap().unwrap().code, 127);

        // Dropping a running child terminates it.
        let dropped = fake.spawn(&Cmd::new("sing-box").arg("run")).unwrap();
        let dropped_pid = dropped.pid();
        drop(dropped);
        assert_eq!(fake.signals().last(), Some(&(dropped_pid, libc::SIGTERM)));
        assert!(fake
            .spawn(&Cmd::new("sing-box").arg("run").inherit_lock(3))
            .is_err());
        assert_eq!(fake.history().len(), 4);
    }
}
