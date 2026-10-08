//! INT/TERM/HUP while apt/dpkg installs the kernel (`run_protected`).

use super::*;
use crate::sys::exec::{Exec, RunningChild};
use std::sync::{Arc, Mutex};

/// An `Exec` whose spawned child keeps running for a few polls and raises
/// SIGINT on the listed polls (a Ctrl+C or SSH hangup while dpkg works).
struct SlowExec {
    polls: usize,
    raise_on: Vec<usize>,
    spawned: Mutex<Vec<Cmd>>,
    signals: Arc<Mutex<Vec<i32>>>,
}

struct SlowChild {
    poll: usize,
    polls: usize,
    raise_on: Vec<usize>,
    signals: Arc<Mutex<Vec<i32>>>,
}

impl Exec for SlowExec {
    fn run(&self, cmd: &Cmd) -> Result<Output> {
        Ok(Output::failure(
            127,
            format!("unexpected: {}", cmd.display()),
        ))
    }

    fn spawn(&self, cmd: &Cmd) -> Result<Box<dyn RunningChild>> {
        self.spawned.lock().unwrap().push(cmd.clone());
        Ok(Box::new(SlowChild {
            poll: 0,
            polls: self.polls,
            raise_on: self.raise_on.clone(),
            signals: Arc::clone(&self.signals),
        }))
    }

    fn spawn_detached(&self, _cmd: &Cmd, _log: &Path) -> Result<u32> {
        Err(Error::msg("unexpected detached spawn"))
    }

    fn which(&self, _program: &str) -> Option<PathBuf> {
        None
    }
}

impl RunningChild for SlowChild {
    fn pid(&self) -> u32 {
        41_000
    }

    fn try_wait(&mut self) -> Result<Option<Output>> {
        Ok((self.poll >= self.polls).then(|| Output::success("dpkg finished\n")))
    }

    fn wait_timeout(&mut self, _limit: Duration) -> Result<Option<Output>> {
        if let Some(out) = self.try_wait()? {
            return Ok(Some(out));
        }
        self.poll += 1;
        if self.raise_on.contains(&self.poll) {
            // SAFETY: raising a signal whose recording handler the code
            // under test installed (SignalScope) before spawning.
            unsafe {
                libc::raise(libc::SIGINT);
            }
        }
        Ok(None)
    }

    fn kill_group(&mut self, signal: i32) -> Result<()> {
        self.signals.lock().unwrap().push(signal);
        Ok(())
    }

    fn terminate(&mut self, _grace: Duration) -> Result<Output> {
        self.signals.lock().unwrap().push(libc::SIGTERM);
        Ok(Output::failure(143, ""))
    }
}

#[test]
fn signals_during_apt_only_print_a_notice() {
    let _g = signals();
    crate::sys::signal::clear();
    let f = Fixture::new();
    let exec = Arc::new(SlowExec {
        polls: 5,
        raise_on: vec![1, 3],
        spawned: Mutex::new(Vec::new()),
        signals: Arc::new(Mutex::new(Vec::new())),
    });
    let ctx = Ctx {
        paths: f.ctx.paths.clone(),
        exec: exec.clone(),
        ui: f.ctx.ui.clone(),
    };
    let mut notices = Vec::new();
    let cmd = Cmd::new("apt-get").args(["install", "-y"]);
    let out = run_protected_with(&ctx, cmd, Duration::ZERO, &mut |m| {
        notices.push(m.to_string())
    })
    .unwrap();
    assert_eq!(out.stdout, "dpkg finished\n", "the child's own result");
    assert!(exec.signals.lock().unwrap().is_empty(), "never signalled");
    assert_eq!(notices, [INSTALL_NOTICE], "warned once for two signals");
    assert_eq!(crate::sys::signal::pending(), None);
    assert!(
        crate::sys::signal::check().is_ok(),
        "nothing left to cancel"
    );
    let spawned = exec.spawned.lock().unwrap();
    assert!(spawned[0].stream, "apt output is streamed");
}

/// The same through the real `SystemExec` and a real child (`sleep 1`).
#[test]
#[ignore]
fn real_child_survives_a_signal_during_install() {
    let _g = signals();
    crate::sys::signal::clear();
    let dir = crate::sys::fs::TempDir::new("bbr-real").unwrap();
    let ctx = Ctx {
        paths: crate::paths::Paths::isolated(dir.path()),
        exec: Arc::new(crate::sys::exec::SystemExec),
        ui: Arc::new(crate::ui::ScriptedPrompter::new(Vec::<String>::new())),
    };
    let sender = std::thread::spawn(|| {
        std::thread::sleep(Duration::from_millis(300));
        // SAFETY: a process-directed SIGINT; the code under test has its
        // recording handler installed for the whole second `sleep` runs.
        unsafe {
            libc::kill(libc::getpid(), libc::SIGINT);
        }
    });
    let started = std::time::Instant::now();
    let mut notices = 0;
    let out = run_protected_with(
        &ctx,
        Cmd::new("sleep").arg("1"),
        Duration::from_millis(50),
        &mut |_| notices += 1,
    )
    .unwrap();
    sender.join().unwrap();
    assert_eq!(out.code, 0, "sleep ran to completion");
    assert!(started.elapsed() >= Duration::from_secs(1));
    assert_eq!(notices, 1);
    assert_eq!(crate::sys::signal::pending(), None);
}
