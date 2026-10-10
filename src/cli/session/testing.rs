//! Test doubles for [`Session`]: an engine that records requests and a
//! host with scripted facts.

use super::{Engine, Live, Printer, Session};
use crate::apply::ApplyRequest;
use crate::ctx::Ctx;
use crate::domain::config::NodeConfig;
use crate::domain::ports::Reservation;
use crate::domain::protocol::Transport;
use crate::error::{Error, Result};
use crate::host::init::InitSystem;
use crate::state::StateStore;
use crate::sys::exec::FakeExec;
use crate::sys::fs::TempDir;
use crate::sys::lock::FileLock;
use crate::sys::rand::{Random, SeqRandom};
use crate::ui::out::Level;
use crate::ui::ScriptedPrompter;
use std::net::IpAddr;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

/// What the recording engine was asked to do.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Call {
    Apply,
    ApplyLocked,
    Recover,
    RecoverLocked,
    Boot,
}

/// Records every call; `fail` makes the next calls fail with that message,
/// `fail_applies` only the applies (recovery still succeeds).
#[derive(Default)]
pub struct Recorder {
    requests: Mutex<Vec<ApplyRequest>>,
    calls: Mutex<Vec<Call>>,
    fail: Mutex<Option<String>>,
    fail_applies: Mutex<Option<String>>,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

impl Recorder {
    pub fn requests(&self) -> Vec<ApplyRequest> {
        lock(&self.requests).clone()
    }

    /// The only request; panics unless exactly one was made.
    pub fn single(&self) -> ApplyRequest {
        let requests = self.requests();
        assert_eq!(requests.len(), 1, "expected one apply: {requests:?}");
        requests.into_iter().next().unwrap()
    }

    pub fn calls(&self) -> Vec<Call> {
        lock(&self.calls).clone()
    }

    pub fn fail_with(&self, message: &str) {
        *lock(&self.fail) = Some(message.to_owned());
    }

    /// Make the next applies (not recoveries) fail with `message`.
    pub fn fail_applies_with(&self, message: &str) {
        *lock(&self.fail_applies) = Some(message.to_owned());
    }

    fn record(&self, call: Call, req: Option<ApplyRequest>) -> Result<()> {
        let apply = req.is_some();
        lock(&self.calls).push(call);
        if let Some(req) = req {
            lock(&self.requests).push(req);
        }
        let fail_applies = lock(&self.fail_applies).clone().filter(|_| apply);
        match lock(&self.fail).clone().or(fail_applies) {
            Some(message) => Err(Error::msg(message)),
            None => Ok(()),
        }
    }
}

impl Engine for Recorder {
    fn apply(&self, _ctx: &Ctx, req: ApplyRequest) -> Result<()> {
        self.record(Call::Apply, Some(req))
    }
    fn apply_locked(&self, _ctx: &Ctx, _lock: &FileLock, req: ApplyRequest) -> Result<()> {
        self.record(Call::ApplyLocked, Some(req))
    }
    fn recover(&self, _ctx: &Ctx) -> Result<()> {
        self.record(Call::Recover, None)
    }
    fn recover_locked(&self, _ctx: &Ctx, _lock: &FileLock) -> Result<()> {
        self.record(Call::RecoverLocked, None)
    }
    fn boot(&self, _ctx: &Ctx) -> Result<()> {
        self.record(Call::Boot, None)
    }
}

/// Scripted host facts (IPv6 on, nothing listening, no FRP, systemd).
pub struct FakeLive {
    pub init: InitSystem,
    pub ipv6: bool,
    pub busy: Mutex<Vec<(u16, Transport)>>,
    pub frp: Vec<Reservation>,
    pub ipv4: Option<IpAddr>,
    pub ipv6_addr: Option<IpAddr>,
    pub now: u64,
    pub running: Mutex<Vec<String>>,
    /// Services whose definition exists but cannot be read.
    pub unreadable: Mutex<Vec<String>>,
}

impl Default for FakeLive {
    fn default() -> Self {
        FakeLive {
            init: InitSystem::Systemd,
            ipv6: true,
            busy: Mutex::new(Vec::new()),
            frp: Vec::new(),
            ipv4: Some("203.0.113.10".parse().unwrap()),
            ipv6_addr: None,
            now: 1_700_000_000,
            running: Mutex::new(Vec::new()),
            unreadable: Mutex::new(Vec::new()),
        }
    }
}

impl FakeLive {
    pub fn occupy(&self, port: u16, transport: Transport) {
        lock(&self.busy).push((port, transport));
    }
    pub fn set_running(&self, service: &str) {
        lock(&self.running).push(service.to_owned());
    }
    /// `service`'s definition exists but is damaged (as a truncated no-init
    /// spec): it reads as stopped, and a status report fails.
    pub fn set_unreadable(&self, service: &str) {
        lock(&self.unreadable).push(service.to_owned());
    }
}

impl Live for FakeLive {
    fn ipv6(&self) -> bool {
        self.ipv6
    }
    fn in_use(&self, port: u16, transport: Transport) -> bool {
        lock(&self.busy)
            .iter()
            .any(|(p, t)| *p == port && t.overlaps(transport))
    }
    fn frp(&self) -> Result<Vec<Reservation>> {
        Ok(self.frp.clone())
    }
    fn public_ip(&self, v6: bool) -> Option<IpAddr> {
        if v6 {
            self.ipv6_addr
        } else {
            self.ipv4
        }
    }
    fn now(&self) -> u64 {
        self.now
    }
    fn rng(&self) -> Box<dyn Random> {
        Box::new(SeqRandom(7))
    }
    fn init(&self) -> InitSystem {
        self.init
    }
    fn running(&self, service: &str) -> bool {
        lock(&self.running).iter().any(|s| s == service)
    }
    fn running_checked(&self, service: &str) -> Result<bool> {
        if lock(&self.unreadable).iter().any(|s| s == service) {
            return Err(Error::msg("JSON 无效: EOF while parsing a string"));
        }
        Ok(self.running(service))
    }
}

/// Captured output: data lines (stdout) and status lines (`[完成] …`).
#[derive(Default)]
pub struct Capture {
    data: Mutex<Vec<String>>,
    notes: Mutex<Vec<String>>,
}

impl Printer for Capture {
    fn data(&self, text: &str) -> Result<()> {
        lock(&self.data).push(text.to_owned());
        Ok(())
    }
    fn status(&self, level: Level, text: &str) {
        lock(&self.notes).push(format!("{} {text}", level.tag()));
    }
}

/// Everything a handler test needs; build a [`Session`] with [`Bench::session`].
pub struct Bench {
    pub dir: TempDir,
    pub ctx: Ctx,
    pub exec: Arc<FakeExec>,
    pub ui: Arc<ScriptedPrompter>,
    pub engine: Recorder,
    pub live: FakeLive,
    pub is_root: bool,
    pub printed: Capture,
}

impl Bench {
    pub fn new() -> Bench {
        let dir = TempDir::new("cli-test").unwrap();
        let (ctx, exec, ui) = Ctx::test(dir.path());
        Bench {
            dir,
            ctx,
            exec,
            ui,
            engine: Recorder::default(),
            live: FakeLive::default(),
            is_root: true,
            printed: Capture::default(),
        }
    }

    /// A bench with `cfg` saved as the installed state.
    pub fn installed(cfg: &NodeConfig) -> Bench {
        let bench = Bench::new();
        StateStore::save_to(&bench.ctx.paths, cfg).unwrap();
        bench
    }

    pub fn session(&self) -> Session<'_> {
        Session::new(&self.ctx, &self.engine, &self.live, self.is_root).with_printer(&self.printed)
    }

    /// Everything printed on stdout so far, joined by newlines.
    pub fn output(&self) -> String {
        lock(&self.printed.data).join("\n")
    }

    /// Status lines printed so far (`[完成] …`, `[警告] …`).
    pub fn notes(&self) -> Vec<String> {
        lock(&self.printed.notes).clone()
    }

    /// Answer the next questions in order.
    pub fn answers(&self, answers: &[&str]) -> &Self {
        self.ui.extend(answers.iter().copied());
        self
    }

    pub fn unattended(&self) -> &Self {
        self.ui.set_assume_yes(true);
        self
    }

    pub fn state(&self) -> NodeConfig {
        StateStore::load_from(&self.ctx.paths, &mut SeqRandom(1))
            .unwrap()
            .unwrap()
            .config
    }
}
