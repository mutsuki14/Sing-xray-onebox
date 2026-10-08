//! [`FakeExec`]: the scripted `Exec` used by unit tests across the crate.

use super::{Cmd, Exec, Output};
use crate::error::Result;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

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
