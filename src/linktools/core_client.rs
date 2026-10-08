//! Temporary client cores: a native sing-box or Xray started for one bundle
//! entry with a random-credential SOCKS5 inbound on a free loopback port
//! (spec D §3.3, §4.3). Every measurement goes through such a core; there
//! is never a direct fallback.
//!
//! Lifecycle: binary lookup → private 0700 work dir → port reservation →
//! config (0600) → `check` (15 s) → `run` in its own session → readiness
//! (SOCKS login within 8 s) → … → terminate (group SIGTERM, 500 ms grace,
//! SIGKILL, reap) → work dir removed.
//!
//! Binary lookup order (documented, D-8.1#21): `--singbox`/`--xray`, then
//! `ONEBOX_BIN_DIR` (`/opt/onebox/bin`, the node's own cores), then `PATH`;
//! only executable regular files qualify.
//!
//! Changes from v2:
//! - one kill routine (`RunningChild::terminate`) for drop and failover
//!   shutdown; v2's `terminate()` SIGKILLed the leader without grace and
//!   duplicated the drop logic (D-8.1#10);
//! - a core that exits during startup while its reserved port is taken by
//!   another process is restarted on a new port (up to 3 attempts, the
//!   reservation race of D-8.1#11);
//! - a cancellation during startup is `Error::Cancelled`, not
//!   `客户端内核启动超时` (D-8.1#9);
//! - candidates must be executable (D-8.1#21);
//! - check and start failures carry the core's last message with every
//!   credential of the entry redacted (D-8.1#8; still `未打印凭据`) and the
//!   exit code;
//! - RSS comes from `/proc/<pid>/status` (`VmRSS`, no page-size lookup) and
//!   CPU time uses the fixed Linux `USER_HZ` of 100 (what musl's `sysconf`
//!   returns too), so no `unsafe` is needed here.

use super::cancel::CancelToken;
use super::socks::{self, SocksEndpoint, USERNAME};
use crate::ctx::Ctx;
use crate::domain::protocol::Core;
use crate::error::{Error, Result};
use crate::render::probe::ProbeEntry;
use crate::sys::exec::{Cmd, Output, RunningChild};
use crate::sys::fs::TempDir;
use crate::sys::text::sanitize_input;
use serde_json::{json, Value};
use std::fs;
use std::net::{Ipv4Addr, TcpListener};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

/// Bytes of credential: 24 random bytes = 48 lowercase hex characters.
const TOKEN_BYTES: usize = 24;
const CONFIG_FILE: &str = "config.json";
const START_ATTEMPTS: usize = 3;
/// SIGTERM → SIGKILL grace when a core is stopped (v2 drop: 500 ms).
pub const STOP_GRACE: Duration = Duration::from_millis(500);
/// Linux USER_HZ: the unit of `/proc/<pid>/stat` CPU times.
const CLOCK_TICKS: f64 = 100.0;
/// Longest core message kept in an error.
const DETAIL_CHARS: usize = 200;

/// Startup timing (v2 constants; tests shorten them).
#[derive(Clone, Copy, Debug)]
pub struct Timing {
    pub check: Duration,
    pub ready: Duration,
    pub poll: Duration,
    pub login: Duration,
}

impl Default for Timing {
    fn default() -> Timing {
        Timing {
            check: Duration::from_secs(15),
            ready: Duration::from_secs(8),
            poll: Duration::from_millis(50),
            login: Duration::from_millis(300),
        }
    }
}

/// Client binaries given on the command line (`--singbox`, `--xray`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CoreBinaries {
    pub singbox: Option<PathBuf>,
    pub xray: Option<PathBuf>,
}

impl CoreBinaries {
    pub fn explicit(&self, core: Core) -> Option<&Path> {
        match core {
            Core::Singbox => self.singbox.as_deref(),
            Core::Xray => self.xray.as_deref(),
        }
    }
}

fn executable_file(path: &Path) -> bool {
    fs::metadata(path).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
}

/// Find the client binary of `core` (lookup order in the module docs).
pub fn locate(ctx: &Ctx, core: Core, explicit: Option<&Path>) -> Result<PathBuf> {
    if let Some(path) = explicit {
        let real = fs::canonicalize(path)
            .map_err(|_| Error::msg(format!("客户端内核不存在: {}", core.id())))?;
        ensure!(
            executable_file(&real),
            "客户端内核不可执行: {}",
            path.display()
        );
        return Ok(real);
    }
    let own = ctx.paths.core_bin(core);
    if executable_file(&own) {
        return Ok(own);
    }
    match ctx.exec.which(core.binary()) {
        Some(found) => Ok(fs::canonicalize(&found).unwrap_or(found)),
        None => bail!("缺少客户端内核: {}", core.id()),
    }
}

/// The temporary client configuration (spec D §3.3, exact).
pub fn client_config(entry: &ProbeEntry, port: u16, token: &str) -> Value {
    match entry.core {
        Core::Singbox => json!({
            "log": {"disabled": true},
            "dns": {"servers": [{"type": "local", "tag": "local"}]},
            "inbounds": [{"type": "socks", "listen": "127.0.0.1", "listen_port": port,
                "users": [{"username": USERNAME, "password": token}]}],
            "outbounds": entry.outbounds,
            "route": {"final": entry.tag, "default_domain_resolver": "local"},
        }),
        Core::Xray => json!({
            "log": {"loglevel": "none"},
            "inbounds": [{"protocol": "socks", "listen": "127.0.0.1", "port": port,
                "settings": {"auth": "password", "accounts": [{"user": USERNAME, "pass": token}],
                    "udp": true}}],
            "outbounds": entry.outbounds,
        }),
    }
}

fn path_arg(path: &Path) -> Result<String> {
    path.to_str()
        .map(str::to_owned)
        .ok_or_else(|| Error::msg(format!("路径必须是 UTF-8: {}", path.display())))
}

/// `sing-box check -c CFG -D WORK` / `xray run -test -c CFG`, in `work`.
pub fn check_command(core: Core, binary: &Path, work: &Path) -> Result<Cmd> {
    let config = path_arg(&work.join(CONFIG_FILE))?;
    let cmd = Cmd::new(path_arg(binary)?).cwd(work);
    Ok(match core {
        Core::Singbox => cmd.args(["check", "-c", &config, "-D", &path_arg(work)?]),
        Core::Xray => cmd.args(["run", "-test", "-c", &config]),
    })
}

/// `sing-box run -c CFG -D WORK` / `xray run -c CFG`, in `work`.
pub fn run_command(core: Core, binary: &Path, work: &Path) -> Result<Cmd> {
    let config = path_arg(&work.join(CONFIG_FILE))?;
    let cmd = Cmd::new(path_arg(binary)?)
        .cwd(work)
        .args(["run", "-c", &config]);
    Ok(match core {
        Core::Singbox => cmd.args(["-D", &path_arg(work)?]),
        Core::Xray => cmd,
    })
}

/// Whether an outbound key holds a credential (UUIDs, passwords, REALITY
/// keys and short IDs, obfuscation and auth secrets) in either core's
/// schema; other values (types, tags, names) stay readable in messages.
fn secret_key(key: &str) -> bool {
    let key = key.to_ascii_lowercase();
    key == "id"
        || [
            "uuid", "pass", "key", "short", "auth", "psk", "token", "secret",
        ]
        .iter()
        .any(|part| key.contains(part))
}

/// Every credential of the entry (plus the SOCKS token), so core messages
/// can be shown without them.
fn secrets(entry: &ProbeEntry, token: &str) -> Vec<String> {
    fn collect(value: &Value, out: &mut Vec<String>) {
        match value {
            Value::String(s) if !s.is_empty() => out.push(s.clone()),
            Value::Array(items) => items.iter().for_each(|v| collect(v, out)),
            Value::Object(map) => map.values().for_each(|v| collect(v, out)),
            _ => {}
        }
    }
    fn walk(value: &Value, out: &mut Vec<String>) {
        match value {
            Value::Array(items) => items.iter().for_each(|v| walk(v, out)),
            Value::Object(map) => {
                for (key, v) in map {
                    if secret_key(key) {
                        collect(v, out);
                    } else {
                        walk(v, out);
                    }
                }
            }
            _ => {}
        }
    }
    let mut out = vec![token.to_owned()];
    entry.outbounds.iter().for_each(|o| walk(o, &mut out));
    // Longest first, so a secret containing another is replaced whole.
    out.sort_by_key(|s| std::cmp::Reverse(s.len()));
    out
}

/// The core's last message line, sanitized, without any of `secrets`.
pub fn redacted_detail(output: &Output, secrets: &[String]) -> String {
    let last = |text: &str| {
        text.lines()
            .rev()
            .map(str::trim)
            .find(|l| !l.is_empty())
            .map(str::to_owned)
    };
    let mut line = last(&output.stderr)
        .or_else(|| last(&output.stdout))
        .unwrap_or_default();
    for secret in secrets {
        line = line.replace(secret.as_str(), "***");
    }
    sanitize_input(&line).chars().take(DETAIL_CHARS).collect()
}

fn with_detail(message: String, detail: &str) -> Error {
    if detail.is_empty() {
        Error::msg(message)
    } else {
        Error::msg(format!("{message}: {detail}"))
    }
}

/// CPU seconds (user + system) from `/proc/<pid>/stat`.
pub fn parse_cpu_seconds(stat: &str) -> Option<f64> {
    let (_, tail) = stat.rsplit_once(')')?;
    let fields: Vec<&str> = tail.split_whitespace().collect();
    let ticks = |i: usize| fields.get(i).and_then(|s| s.parse::<u64>().ok());
    Some((ticks(11)? + ticks(12)?) as f64 / CLOCK_TICKS)
}

/// Resident set size in bytes from `/proc/<pid>/status`.
pub fn parse_rss_bytes(status: &str) -> Option<u64> {
    let line = status.lines().find(|l| l.starts_with("VmRSS:"))?;
    let mut parts = line["VmRSS:".len()..].split_whitespace();
    let kib = parts.next()?.parse::<u64>().ok()?;
    (parts.next() == Some("kB")).then_some(kib * 1024)
}

/// Client-core resource usage; `None` when unavailable.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct Resources {
    pub cpu_seconds: Option<f64>,
    pub rss_bytes: Option<u64>,
}

fn resources_of(pid: u32) -> Resources {
    let read = |name: &str| fs::read_to_string(format!("/proc/{pid}/{name}")).ok();
    Resources {
        cpu_seconds: read("stat").as_deref().and_then(parse_cpu_seconds),
        rss_bytes: read("status").as_deref().and_then(parse_rss_bytes),
    }
}

/// A running client proxy as the drivers use it (real: [`ClientCore`]).
pub trait Proxy: Send + Sync {
    fn endpoint(&self) -> &SocksEndpoint;
    fn resources(&self) -> Resources;
    /// The exit code once the process has exited.
    fn exited(&self) -> Option<i32>;
    /// Stop the process group and reap it (idempotent).
    fn terminate(&self);
}

/// Starts proxies for bundle entries (real: [`CoreLauncher`]).
pub trait Launcher: Sync {
    fn launch(&self, entry: &ProbeEntry) -> Result<Box<dyn Proxy>>;
}

/// The production launcher.
pub struct CoreLauncher<'a> {
    pub ctx: &'a Ctx,
    pub binaries: &'a CoreBinaries,
    pub cancel: &'a CancelToken,
    pub timing: Timing,
}

impl Launcher for CoreLauncher<'_> {
    fn launch(&self, entry: &ProbeEntry) -> Result<Box<dyn Proxy>> {
        let binary = locate(self.ctx, entry.core, self.binaries.explicit(entry.core))?;
        let core = ClientCore::start(self.ctx, entry, &binary, self.cancel, self.timing)?;
        Ok(Box::new(core))
    }
}

/// A started, ready client core. Field order matters: the process is
/// stopped before the work dir holding its config is removed.
pub struct ClientCore {
    child: Mutex<Box<dyn RunningChild>>,
    endpoint: SocksEndpoint,
    _work: TempDir,
}

/// Why one start attempt failed.
enum Attempt {
    /// The core exited during startup while another process held its port.
    PortRace,
    Failed(Error),
}

impl From<Error> for Attempt {
    fn from(e: Error) -> Attempt {
        Attempt::Failed(e)
    }
}

impl From<std::io::Error> for Attempt {
    fn from(e: std::io::Error) -> Attempt {
        Attempt::Failed(e.into())
    }
}

impl ClientCore {
    pub fn start(
        ctx: &Ctx,
        entry: &ProbeEntry,
        binary: &Path,
        cancel: &CancelToken,
        timing: Timing,
    ) -> Result<ClientCore> {
        for _ in 1..START_ATTEMPTS {
            match Self::attempt(ctx, entry, binary, cancel, timing) {
                Ok(core) => return Ok(core),
                Err(Attempt::PortRace) => continue,
                Err(Attempt::Failed(e)) => return Err(e),
            }
        }
        match Self::attempt(ctx, entry, binary, cancel, timing) {
            Ok(core) => Ok(core),
            Err(Attempt::PortRace) => bail!("客户端内核启动失败：本机端口被占用"),
            Err(Attempt::Failed(e)) => Err(e),
        }
    }

    fn attempt(
        ctx: &Ctx,
        entry: &ProbeEntry,
        binary: &Path,
        cancel: &CancelToken,
        timing: Timing,
    ) -> std::result::Result<ClientCore, Attempt> {
        let work = TempDir::new("client")?;
        let reserve = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        let port = reserve.local_addr()?.port();
        let token = crate::sys::rand::hex(TOKEN_BYTES)?;
        let secrets = secrets(entry, &token);
        let config = super::bundle::json_text(&client_config(entry, port, &token))?;
        super::bundle::write_private(&work.join(CONFIG_FILE), &config)?;

        let check =
            ctx.run(&check_command(entry.core, binary, work.path())?.timeout(timing.check))?;
        if cancel.is_cancelled() {
            return Err(Error::Cancelled.into());
        }
        if !check.ok() {
            let message = format!(
                "客户端配置校验失败（检查内核版本；未打印凭据；退出码 {}）",
                check.code
            );
            return Err(with_detail(message, &redacted_detail(&check, &secrets)).into());
        }
        // The port stays reserved until just before the core binds it.
        drop(reserve);
        let mut child = ctx
            .exec
            .spawn(&run_command(entry.core, binary, work.path())?)?;
        let endpoint = SocksEndpoint { port, token };
        match wait_ready(child.as_mut(), &endpoint, cancel, timing) {
            Ok(()) => Ok(ClientCore {
                child: Mutex::new(child),
                endpoint,
                _work: work,
            }),
            Err(Startup::Exited(_)) if port_taken(port) => Err(Attempt::PortRace),
            Err(Startup::Exited(output)) => {
                let message = format!("客户端内核启动失败（退出码 {}）", output.code);
                Err(with_detail(message, &redacted_detail(&output, &secrets)).into())
            }
            Err(Startup::Failed(e)) => Err(e.into()),
        }
    }

    fn child(&self) -> MutexGuard<'_, Box<dyn RunningChild>> {
        self.child.lock().unwrap_or_else(PoisonError::into_inner)
    }

    pub fn pid(&self) -> u32 {
        self.child().pid()
    }
}

impl Proxy for ClientCore {
    fn endpoint(&self) -> &SocksEndpoint {
        &self.endpoint
    }

    fn resources(&self) -> Resources {
        let mut child = self.child();
        match child.try_wait() {
            // Only a live (unreaped) pid is ours to read.
            Ok(None) => resources_of(child.pid()),
            _ => Resources::default(),
        }
    }

    fn exited(&self) -> Option<i32> {
        match self.child().try_wait() {
            Ok(Some(output)) => Some(output.code),
            Ok(None) => None,
            Err(_) => Some(-1),
        }
    }

    fn terminate(&self) {
        let _ = self.child().terminate(STOP_GRACE);
    }
}

/// Is `port` bound by someone else (after our core exited)?
fn port_taken(port: u16) -> bool {
    TcpListener::bind((Ipv4Addr::LOCALHOST, port)).is_err()
}

/// Why a started core did not become ready.
enum Startup {
    Exited(Output),
    Failed(Error),
}

/// Poll until the SOCKS login works, the core exits, the deadline passes
/// or the run is cancelled.
fn wait_ready(
    child: &mut dyn RunningChild,
    endpoint: &SocksEndpoint,
    cancel: &CancelToken,
    timing: Timing,
) -> std::result::Result<(), Startup> {
    let deadline = Instant::now() + timing.ready;
    loop {
        match child.try_wait() {
            Ok(Some(output)) => return Err(Startup::Exited(output)),
            Ok(None) => {}
            Err(e) => return Err(Startup::Failed(e)),
        }
        if socks::dial(endpoint, timing.login).is_ok() {
            return Ok(());
        }
        if cancel.is_cancelled() {
            return Err(Startup::Failed(Error::Cancelled));
        }
        if Instant::now() >= deadline {
            return Err(Startup::Failed(Error::msg("客户端内核启动超时")));
        }
        std::thread::sleep(timing.poll);
    }
}

#[cfg(test)]
mod tests;
