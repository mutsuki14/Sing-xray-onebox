//! Test host for the apply engine and backups: an isolated layout with a
//! fake systemd, crontab, iptables, `ip` and core binaries behind one
//! [`FakeExec`], fake feature hooks with failure / crash / cancellation
//! injection, and a byte-level picture of everything an apply may touch.

use super::features::{Checkpoint, Features};
use super::request::ApplyRequest;
use crate::cert::CfCredentials;
use crate::ctx::Ctx;
use crate::domain::config::Device;
use crate::domain::fixtures;
use crate::domain::protocol::{Core, Protocol};
use crate::domain::NodeConfig;
use crate::error::{Error, Result};
use crate::host::cron::testing::{fake_crontab, text, CronState};
use crate::paths::Paths;
use crate::render::NodeSpec;
use crate::site::{SiteContent, SitePrepared, SiteSubscription};
use crate::state::StateStore;
use crate::sys::exec::{Cmd, FakeExec, Output};
use crate::sys::fs::TempDir;
use crate::sys::lock::{FileLock, BUSY_MESSAGE};
use crate::sys::signal;
use crate::ui::ScriptedPrompter;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

pub const MANAGER: &[u8] = b"\x7fELF onebox manager under test";
pub const OLD_MANAGER: &[u8] = b"\x7fELF onebox manager installed before";
pub const SING_BOX: &[u8] = b"\x7fELF sing-box binary";
pub const XRAY: &[u8] = b"\x7fELF xray binary";
pub const IPS: &str = r#"[{"addr_info":[{"local":"203.0.113.10"}]}]"#;
pub const NEW_IPS: &str = r#"[{"addr_info":[{"local":"203.0.113.10"},{"local":"198.51.100.7"}]}]"#;

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// One fake systemd unit's state.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Unit {
    pub active: bool,
    pub enabled: bool,
}

pub type Units = Arc<Mutex<BTreeMap<String, Unit>>>;

/// What a test may inject into the fake feature hooks.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Fault {
    /// Return an error at the checkpoint.
    Fail(Checkpoint),
    /// Panic at the checkpoint: the process "crashed", the journal stays.
    Crash(Checkpoint),
    /// Raise SIGINT at the checkpoint (honored at the next stage).
    Interrupt(Checkpoint),
}

/// Fake feature hooks: record every call, leave small marks on disk so
/// rollbacks can be checked, fail / crash / interrupt where asked.
#[derive(Default)]
pub struct FakeFeatures {
    pub calls: Mutex<Vec<String>>,
    pub fault: Mutex<Option<Fault>>,
}

impl FakeFeatures {
    pub fn calls(&self) -> Vec<String> {
        lock(&self.calls).clone()
    }

    pub fn inject(&self, fault: Fault) {
        *lock(&self.fault) = Some(fault);
    }

    pub fn clear(&self) {
        *lock(&self.fault) = None;
        lock(&self.calls).clear();
    }

    fn record(&self, call: impl Into<String>) {
        lock(&self.calls).push(call.into());
    }
}

impl Features for FakeFeatures {
    fn install_self(&self, ctx: &Ctx) -> Result<bool> {
        self.record("install_self");
        let exe = &ctx.paths.executable;
        if fs::read(exe).ok().as_deref() == Some(MANAGER) {
            return Ok(false);
        }
        crate::sys::fs::atomic_write(exe, MANAGER, 0o755)?;
        Ok(true)
    }

    fn prepare_subscription(
        &self,
        ctx: &Ctx,
        _cfg: &NodeConfig,
        migrated: Option<&[Device]>,
        clear: bool,
    ) -> Result<()> {
        self.record(format!(
            "prepare_subscription migrated={} clear={clear}",
            migrated.map_or(0, <[Device]>::len)
        ));
        let paths = &ctx.paths;
        if clear {
            let _ = fs::remove_file(paths.devices());
            let _ = fs::remove_file(paths.published());
        }
        if let Some(devices) = migrated {
            let json = serde_json::to_vec_pretty(devices)?;
            crate::sys::fs::atomic_write(&paths.devices(), &json, 0o600)?;
        }
        Ok(())
    }

    fn subscription_certificates(
        &self,
        _ctx: &Ctx,
        _cfg: &NodeConfig,
        force: bool,
        _cf: Option<&CfCredentials>,
    ) -> Result<bool> {
        self.record(format!("subscription_certificates force={force}"));
        Ok(false)
    }

    fn site_prepare(
        &self,
        ctx: &Ctx,
        cfg: &mut NodeConfig,
        content: Option<&SiteContent>,
        force: bool,
        _cf: Option<&CfCredentials>,
    ) -> Result<SitePrepared> {
        self.record(format!("site_prepare content={content:?} force={force}"));
        if cfg.site_active().is_some() {
            let index = ctx.paths.site_root.join("index.html");
            crate::sys::fs::atomic_write(&index, b"<h1>new site</h1>", 0o644)?;
        }
        Ok(SitePrepared::default())
    }

    fn proxy_certificate(
        &self,
        _ctx: &Ctx,
        cfg: &mut NodeConfig,
        force: bool,
        _cf: Option<&CfCredentials>,
    ) -> Result<bool> {
        self.record(format!("proxy_certificate force={force}"));
        if cfg.needs_cert() {
            return Err(Error::msg("fake: no certificates in these tests"));
        }
        Ok(false)
    }

    fn site_location(&self, _paths: &Paths, _cfg: &NodeConfig) -> Option<SiteSubscription> {
        None
    }

    fn site_check(
        &self,
        ctx: &Ctx,
        _cfg: &NodeConfig,
        _sub: Option<&SiteSubscription>,
    ) -> Result<Option<PathBuf>> {
        self.record("site_check");
        let staged = crate::site::staged_conf(&ctx.paths);
        crate::sys::fs::atomic_write(&staged, b"# tested", 0o600)?;
        Ok(Some(staged))
    }

    fn subscription_web_conf(&self, _ctx: &Ctx, _cfg: &NodeConfig) -> Result<Option<String>> {
        Ok(None)
    }

    fn nginx_test(&self, _ctx: &Ctx, _prefix: &Path, _conf: &Path) -> Result<()> {
        self.record("nginx_test");
        Ok(())
    }

    fn subscription_services(&self, _ctx: &Ctx, _cfg: &NodeConfig) -> Result<()> {
        self.record("subscription_services");
        Ok(())
    }

    fn site_apply(
        &self,
        ctx: &Ctx,
        _cfg: &NodeConfig,
        _sub: Option<&SiteSubscription>,
    ) -> Result<()> {
        self.record("site_apply");
        crate::site::install_conf(ctx, &crate::site::staged_conf(&ctx.paths))
    }

    fn site_disable(&self, _ctx: &Ctx) -> Result<()> {
        self.record("site_disable");
        Ok(())
    }

    fn install_web_conf(&self, _ctx: &Ctx, _tested: &Path) -> Result<()> {
        self.record("install_web_conf");
        Ok(())
    }

    fn publish_subscription(&self, ctx: &Ctx, cfg: &NodeConfig, _spec: &NodeSpec) -> Result<()> {
        self.record("publish_subscription");
        let published = ctx.paths.published();
        if cfg.subscription.is_some() {
            let body = format!("{{\"generation\":{}}}", cfg.installed_at);
            crate::sys::fs::atomic_write(&published, body.as_bytes(), 0o600)?;
        }
        Ok(())
    }

    fn checkpoint(&self, point: &Checkpoint) -> Result<()> {
        let fault = lock(&self.fault).clone();
        match fault {
            Some(Fault::Fail(at)) if at == *point => {
                Err(Error::msg(format!("注入故障: {point:?}")))
            }
            Some(Fault::Crash(at)) if at == *point => panic!("simulated crash at {point:?}"),
            Some(Fault::Interrupt(at)) if at == *point => {
                // SAFETY: raising a signal for which the apply's scope has a
                // recording handler installed (the test holds TEST_LOCK).
                unsafe {
                    libc::raise(libc::SIGINT);
                }
                Ok(())
            }
            _ => Ok(()),
        }
    }
}

/// The isolated host.
pub struct Host {
    pub ctx: Ctx,
    pub exec: Arc<FakeExec>,
    pub ui: Arc<ScriptedPrompter>,
    pub units: Units,
    pub faults: Faults,
    pub cron: CronState,
    pub iptables: Arc<Mutex<BTreeSet<String>>>,
    pub ips: Arc<Mutex<String>>,
    pub features: FakeFeatures,
    pub lock: FileLock,
    pub dir: TempDir,
    _signals: MutexGuard<'static, ()>,
}

impl Host {
    /// A systemd host with both core binaries and the old manager in place.
    pub fn new() -> Host {
        let dir = TempDir::new("apply-host").unwrap();
        let paths = Paths::isolated(dir.path());
        Host::build(dir, paths, true)
    }

    /// A host over an existing layout at `paths` (v2 fixtures, a child
    /// process working on its parent's host): nothing is added to it, and
    /// a lock offered by a parent is adopted instead of taken.
    pub fn with_paths(dir: TempDir, paths: Paths) -> Host {
        Host::build(dir, paths, false)
    }

    fn build(dir: TempDir, paths: Paths, seed: bool) -> Host {
        let (mut ctx, exec, ui) = Ctx::test(dir.path());
        ctx.paths = paths;
        let guard = signal::TEST_LOCK
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        signal::clear();
        let paths = &ctx.paths;
        fs::create_dir_all(paths.system("/run/systemd/system")).unwrap();
        if seed {
            for d in [&paths.systemd, &paths.initd, &paths.bin, &paths.log] {
                fs::create_dir_all(d).unwrap();
            }
        }
        let faults = fault_rule(&exec);
        let units = fake_systemd(&exec);
        let cron = fake_crontab(&exec, None);
        let iptables = fake_iptables(&exec);
        let ips = fake_ip(&exec);
        fake_cores(&exec, paths, seed);
        if seed {
            crate::apply::testing::file(&paths.executable, 0o755, OLD_MANAGER);
        }
        let lock = if crate::sys::lock::inherited_lock_offered() {
            FileLock::from_inherited(&paths.lock()).unwrap()
        } else {
            FileLock::acquire(&paths.lock(), BUSY_MESSAGE).unwrap()
        };
        Host {
            ctx,
            exec,
            ui,
            units,
            faults,
            cron,
            iptables,
            ips,
            features: FakeFeatures::default(),
            lock,
            dir,
            _signals: guard,
        }
    }

    pub fn paths(&self) -> &Paths {
        &self.ctx.paths
    }

    /// Make the next command whose line contains `needle` fail.
    pub fn fail_command(&self, needle: &str) {
        self.push_fault(needle, true);
    }

    /// Make every command whose line contains `needle` fail.
    pub fn fail_always(&self, needle: &str) {
        self.push_fault(needle, false);
    }

    fn push_fault(&self, needle: &str, once: bool) {
        lock(&self.faults).push(CommandFault {
            needle: needle.to_owned(),
            once,
        });
    }

    pub fn clear_faults(&self) {
        lock(&self.faults).clear();
        self.features.clear();
    }

    pub fn apply(&self, req: ApplyRequest) -> Result<()> {
        super::engine::apply_with(&self.ctx, &self.lock, req, &self.features)
    }

    /// Install `cfg` over whatever is there (must succeed).
    pub fn install(&self, cfg: NodeConfig) {
        let req = ApplyRequest::install(&self.ctx, cfg, "安装").unwrap();
        self.apply(req).unwrap();
    }

    /// A modification of the installed configuration.
    pub fn change(&self, cfg: NodeConfig, reason: &'static str) -> ApplyRequest {
        let loaded = StateStore::load_required(&self.ctx).unwrap();
        ApplyRequest::from_loaded(&loaded, cfg, reason)
    }

    pub fn installed(&self) -> NodeConfig {
        StateStore::load_required(&self.ctx).unwrap().config
    }

    pub fn unit(&self, name: &str) -> Unit {
        lock(&self.units).get(name).copied().unwrap_or_default()
    }

    pub fn set_unit(&self, name: &str, unit: Unit) {
        lock(&self.units).insert(name.to_owned(), unit);
    }

    pub fn crontab(&self) -> String {
        text(&self.cron)
    }

    pub fn set_crontab(&self, content: &str) {
        *lock(&self.cron) = Some(content.to_owned());
    }

    pub fn set_ips(&self, json: &str) {
        *lock(&self.ips) = json.to_owned();
    }

    /// Command lines run so far.
    pub fn history(&self) -> Vec<String> {
        self.exec.history()
    }

    /// Everything an apply may change, for byte-level comparisons.
    pub fn world(&self) -> World {
        let mut units = lock(&self.units).clone();
        units.retain(|_, u| *u != Unit::default());
        World {
            files: tree(self.dir.path()),
            units,
            cron: self.crontab(),
            iptables: lock(&self.iptables).clone(),
        }
    }
}

/// Files (relative path → mode and content; directories as `None`
/// content), service states, crontab text and live iptables rules.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct World {
    pub files: BTreeMap<String, (u32, Option<Vec<u8>>)>,
    pub units: BTreeMap<String, Unit>,
    pub cron: String,
    pub iptables: BTreeSet<String>,
}

impl World {
    /// Files that differ from `other`.
    pub fn file_diff(&self, other: &World) -> Vec<String> {
        let keys: BTreeSet<&String> = self.files.keys().chain(other.files.keys()).collect();
        keys.into_iter()
            .filter(|key| self.files.get(*key) != other.files.get(*key))
            .cloned()
            .collect()
    }

    /// Everything that differs from `other` (readable assertion messages).
    pub fn diff(&self, other: &World) -> Vec<String> {
        let mut out = self.file_diff(other);
        if self.units != other.units {
            out.push(format!("units {:?} != {:?}", self.units, other.units));
        }
        if self.cron != other.cron {
            out.push(format!("cron {:?} != {:?}", self.cron, other.cron));
        }
        if self.iptables != other.iptables {
            out.push(format!(
                "iptables {:?} != {:?}",
                self.iptables, other.iptables
            ));
        }
        out
    }

    /// The same picture without paths starting with any of `prefixes`.
    pub fn without(mut self, prefixes: &[&str]) -> World {
        self.files
            .retain(|k, _| !prefixes.iter().any(|p| k.starts_with(p)));
        self
    }
}

/// Everything below `root` except the run directory, the fake system root
/// and lock files (created on first use, never part of a generation).
fn tree(root: &Path) -> BTreeMap<String, (u32, Option<Vec<u8>>)> {
    let mut out = BTreeMap::new();
    walk(root, root, &mut out);
    out
}

fn walk(root: &Path, path: &Path, out: &mut BTreeMap<String, (u32, Option<Vec<u8>>)>) {
    let mut entries: Vec<PathBuf> = fs::read_dir(path)
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    entries.sort();
    for entry in entries {
        let rel = entry
            .strip_prefix(root)
            .unwrap()
            .to_string_lossy()
            .into_owned();
        if rel == "run" || rel == "system" || rel.ends_with(".lock") {
            continue;
        }
        let meta = fs::symlink_metadata(&entry).unwrap();
        let mode = meta.permissions().mode() & 0o7777;
        if meta.is_dir() {
            out.insert(rel, (mode, None));
            walk(root, &entry, out);
        } else {
            out.insert(rel, (mode, Some(fs::read(&entry).unwrap())));
        }
    }
}

/// One injected command failure: a needle of the command line, and
/// whether it fires only once.
#[derive(Clone, Debug)]
pub struct CommandFault {
    pub needle: String,
    pub once: bool,
}

pub type Faults = Arc<Mutex<Vec<CommandFault>>>;

/// The first rule: commands containing an injected needle fail (one-shot
/// faults are consumed by their first match).
fn fault_rule(exec: &FakeExec) -> Faults {
    let faults: Faults = Arc::default();
    let shared = faults.clone();
    exec.on_fn(
        move |cmd| {
            let line = cmd.display();
            let mut faults = lock(&shared);
            match faults.iter().position(|f| line.contains(f.needle.as_str())) {
                Some(i) => {
                    if faults[i].once {
                        faults.remove(i);
                    }
                    true
                }
                None => false,
            }
        },
        |cmd| {
            Ok(Output::failure(
                1,
                format!("injected failure: {}", cmd.display()),
            ))
        },
    );
    faults
}

/// `systemctl` over an in-memory unit table (a cron daemon runs).
fn fake_systemd(exec: &FakeExec) -> Units {
    let running = Unit {
        active: true,
        enabled: true,
    };
    let units: Units = Arc::new(Mutex::new(BTreeMap::from([("cron".to_owned(), running)])));
    let shared = units.clone();
    exec.on_fn(
        |cmd| cmd.program == "systemctl",
        move |cmd| Ok(systemctl(&shared, &cmd.args)),
    );
    units
}

fn systemctl(units: &Units, args: &[String]) -> Output {
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let mut table = lock(units);
    let mut set = |name: &str, f: &dyn Fn(&mut Unit)| {
        f(table.entry(name.to_owned()).or_default());
        Output::success("")
    };
    match args.as_slice() {
        ["daemon-reload"] => Output::success(""),
        ["is-active", "--quiet", name] => match table.get(*name) {
            Some(u) if u.active => Output::success(""),
            _ => Output::failure(3, ""),
        },
        ["is-enabled", name] => match table.get(*name) {
            Some(u) if u.enabled => Output::success("enabled\n"),
            _ => Output::failure(1, "disabled\n"),
        },
        ["start" | "restart", name] => set(name, &|u| u.active = true),
        ["stop", name] => set(name, &|u| u.active = false),
        ["enable", name] => set(name, &|u| u.enabled = true),
        ["disable", name] => set(name, &|u| u.enabled = false),
        other => Output::failure(1, format!("fake systemctl: {other:?}")),
    }
}

/// `iptables` (filter and nat) over an in-memory rule set; `ip6tables` is
/// absent (the fake system has no IPv6).
fn fake_iptables(exec: &FakeExec) -> Arc<Mutex<BTreeSet<String>>> {
    let rules: Arc<Mutex<BTreeSet<String>>> = Arc::default();
    exec.provide("iptables");
    let shared = rules.clone();
    exec.on_fn(
        |cmd| cmd.program == "iptables",
        move |cmd| Ok(iptables(&shared, &cmd.args)),
    );
    rules
}

fn iptables(rules: &Mutex<BTreeSet<String>>, args: &[String]) -> Output {
    let mut a: Vec<&str> = args.iter().map(String::as_str).collect();
    if a.starts_with(&["-w", "5"]) {
        a.drain(..2);
    }
    let table = if a.first() == Some(&"-t") {
        let t = a[1];
        a.drain(..2);
        t
    } else {
        "filter"
    };
    let Some((op, rest)) = a.split_first() else {
        return Output::failure(2, "fake iptables: no operation");
    };
    let Some((chain, mut spec)) = rest.split_first() else {
        return Output::success("");
    };
    if *op == "-I" && spec.first().is_some_and(|w| w.parse::<u32>().is_ok()) {
        spec = &spec[1..];
    }
    let key = format!("{table} {chain} {}", spec.join(" "));
    let mut set = lock(rules);
    match *op {
        "-S" => Output::success(format!("-P {chain} ACCEPT\n")),
        "-I" | "-A" => {
            set.insert(key);
            Output::success("")
        }
        "-C" if set.contains(&key) => Output::success(""),
        "-C" => Output::failure(1, "Bad rule (does a matching rule exist in that chain?)."),
        "-D" if set.remove(&key) => Output::success(""),
        _ => Output::failure(1, "fake iptables: no such rule"),
    }
}

fn fake_ip(exec: &FakeExec) -> Arc<Mutex<String>> {
    let ips = Arc::new(Mutex::new(IPS.to_owned()));
    let shared = ips.clone();
    exec.on_fn(
        |cmd| cmd.program == "ip",
        move |_| Ok(Output::success(lock(&shared).clone())),
    );
    ips
}

/// Core binaries (installed when `seed`) answering `version` and config
/// checks.
fn fake_cores(exec: &FakeExec, paths: &Paths, seed: bool) {
    for (core, bytes) in [(Core::Singbox, SING_BOX), (Core::Xray, XRAY)] {
        if seed {
            crate::apply::testing::file(&paths.core_bin(core), 0o755, bytes);
        }
    }
    exec.on(
        "sing-box",
        &["version"],
        Output::success("sing-box version 1.14.2\n"),
    )
    .on("sing-box", &["check"], Output::success(""))
    .on(
        "xray",
        &["version"],
        Output::success("Xray 26.3.27 (Xray, Penetrates Everything.) 0 (go1.24 linux/amd64)\n"),
    )
    .on(
        "xray",
        &["run", "-test"],
        Output::success("Configuration OK."),
    );
}

/// A REALITY node on sing-box plus Shadowsocks on Xray (both cores, no
/// certificate).
pub fn two_cores() -> NodeConfig {
    fixtures::config(&[
        (Protocol::VlessReality, 443, Core::Singbox),
        (Protocol::Shadowsocks, 8388, Core::Xray),
    ])
}

/// The same node on sing-box only, on another port.
pub fn singbox_only() -> NodeConfig {
    fixtures::config(&[(Protocol::VlessReality, 8443, Core::Singbox)])
}

/// Whether `cmd` was run (exact command line).
pub fn ran(history: &[String], line: &str) -> bool {
    history.iter().any(|h| h == line)
}

/// A command line for assertions (`systemctl start onebox-xray`).
pub fn line(program: &str, args: &[&str]) -> String {
    Cmd::new(program).args(args.iter().copied()).display()
}
