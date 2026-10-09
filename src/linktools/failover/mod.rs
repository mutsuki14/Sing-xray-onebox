//! `failover`: 2–8 client cores behind one local SOCKS5 CONNECT listener
//! on `127.0.0.1:<port>`; every round checks each core's health URL and
//! [`FailoverPolicy`] picks the highest-priority healthy entry for new
//! connections (spec D §2.5). Events are JSON lines on stdout.
//!
//! Exit: Ctrl+C / SIGTERM is the normal way to stop the service and exits
//! 0 (deliberate, kept from v2 and now documented, D-8.1#2) — also while
//! the cores are still starting; a listener failure exits 1.
//!
//! Changes from v2: see [`server`], [`relay`], [`revive`] (dead cores are
//! restarted) and [`threads`]; the listener is bound before the first core
//! starts (v2 bound it after all of them, so a busy `--port` failed only
//! after up to 8 × 23 s of startup, and a core's random port could take a
//! `--port` in the ephemeral range); Ctrl+C during startup is the same
//! normal stop as later (it surfaced as the EOF message `输入结束，操作已取消`,
//! exit 130); without `--entries` the entry pair is the first TCP-capable
//! plus the first UDP-only entry (v2).

pub mod policy;
pub mod relay;
pub mod revive;
pub mod server;
pub mod threads;

pub use policy::FailoverPolicy;
pub use revive::ProxySlot;

use super::bundle::{self, Selection};
use super::cancel::{CancelToken, SignalCancel};
use super::core_client::{CoreLauncher, Launcher, Timing};
use super::http_probe::{safe_measure, HttpRequest, Route};
use super::options::FailoverOptions;
use crate::ctx::Ctx;
use crate::error::{Error, Result};
use crate::render::probe::ProbeEntry;
use crate::ui::out;
use std::ops::RangeInclusive;
use std::time::Duration;

/// How many entries a failover group may have.
pub const ENTRY_RANGE: RangeInclusive<usize> = 2..=8;
const COUNT_ERROR: &str =
    "回退需要 2 至 8 个入口；使用 --entries 指定顺序，或 probe merge 合并服务器配置";

/// `onebox failover`.
pub fn run(ctx: &Ctx, opts: &FailoverOptions) -> Result<()> {
    let path = opts
        .common
        .bundle
        .as_deref()
        .ok_or_else(|| Error::msg("onebox failover 需要 probe.json 配置文件"))?;
    let bundle = bundle::load(path)?;
    let entries = bundle::select(&bundle, opts.common.entries.as_deref(), Selection::Pair)?;
    ensure!(ENTRY_RANGE.contains(&entries.len()), "{COUNT_ERROR}");
    let signals = SignalCancel::install()?;
    let cancel = signals.token();
    let launcher = CoreLauncher {
        ctx,
        binaries: &opts.common.binaries,
        cancel,
        timing: Timing::default(),
    };
    let mut emit = |line: &str| out::data(line);
    failover(ctx, &launcher, &entries, opts, cancel, &mut emit)
}

/// Bind the listener, start every entry's core (in order; a failure stops
/// the cores already started), then serve until cancelled.
pub fn failover(
    ctx: &Ctx,
    launcher: &dyn Launcher,
    entries: &[&ProbeEntry],
    opts: &FailoverOptions,
    cancel: &CancelToken,
    emit: &mut dyn FnMut(&str) -> Result<()>,
) -> Result<()> {
    ensure!(ENTRY_RANGE.contains(&entries.len()), "{COUNT_ERROR}");
    let listener = server::bind(opts.port)?;
    let started = entries
        .iter()
        .map(|entry| launcher.launch(entry).map(ProxySlot::new))
        .collect::<Result<Vec<ProxySlot>>>();
    let proxies = match started {
        Ok(proxies) => proxies,
        // Ctrl+C while the cores start: the normal stop, as while serving.
        Err(e) if e.is_cancelled() || cancel.is_cancelled() => return Ok(()),
        Err(e) => return Err(e),
    };
    let ids: Vec<String> = entries.iter().map(|e| e.id.clone()).collect();
    let health = |i: usize| {
        let Some(slot) = proxies.get(i) else {
            return false;
        };
        let endpoint = slot.get().endpoint().clone();
        let req = HttpRequest {
            url: &opts.common.url,
            route: Route::Proxy(&endpoint),
            timeout_secs: opts.common.timeout,
            ca: opts.common.ca.as_deref(),
            range: 0,
            upload: 0,
        };
        safe_measure(ctx, &req, cancel).ok()
    };
    let restart = |i: usize| match entries.get(i) {
        Some(entry) => launcher.launch(entry),
        None => Err(Error::msg("入口不存在")),
    };
    let svc = server::Service {
        ids: &ids,
        proxies: &proxies,
        health: &health,
        restart: &restart,
        listener: &listener,
        interval: Duration::from_secs(opts.interval),
        upstream_timeout: Duration::from_secs(opts.common.timeout),
        max_clients: server::MAX_CLIENTS,
        idle: relay::IDLE,
        spawner: &threads::OsThreads,
    };
    let policy = FailoverPolicy::new(ids.len(), opts.failures, opts.recoveries, opts.cooldown);
    server::serve(&svc, policy, cancel, emit)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::protocol::{Core, Transport};
    use crate::linktools::testutil::{curl_ok, entry, proxy_port, FakeLauncher};
    use crate::sys::fs::TempDir;
    use std::sync::{Arc, Mutex};

    #[test]
    fn entry_count_is_checked_before_any_core_starts() {
        let dir = TempDir::new("linktools-test").unwrap();
        let (ctx, _, _) = Ctx::test(dir.path());
        let one = entry("a", Core::Singbox, Transport::Tcp);
        let launcher = FakeLauncher::new(45000);
        let err = failover(
            &ctx,
            &launcher,
            &[&one],
            &FailoverOptions::default(),
            &CancelToken::manual(),
            &mut |_| Ok(()),
        )
        .unwrap_err();
        assert_eq!(err.to_string(), COUNT_ERROR);
        assert!(launcher.launched().is_empty());

        let path = dir.join("probe.json");
        let all_tcp = crate::linktools::testutil::bundle(vec![
            entry("a", Core::Singbox, Transport::Tcp),
            entry("b", Core::Singbox, Transport::Tcp),
        ]);
        bundle::write_bundle(&path, &all_tcp).unwrap();
        let opts = FailoverOptions {
            common: crate::linktools::options::Common {
                bundle: Some(path),
                ..Default::default()
            },
            ..FailoverOptions::default()
        };
        assert_eq!(run(&ctx, &opts).unwrap_err().to_string(), COUNT_ERROR);
        let err = run(&ctx, &FailoverOptions::default()).unwrap_err();
        assert_eq!(err.to_string(), "onebox failover 需要 probe.json 配置文件");
    }

    #[test]
    fn a_core_that_fails_to_start_aborts_the_group() {
        let dir = TempDir::new("linktools-test").unwrap();
        let (ctx, _, _) = Ctx::test(dir.path());
        let a = entry("a", Core::Singbox, Transport::Tcp);
        let b = entry("b", Core::Xray, Transport::Udp);
        let mut launcher = FakeLauncher::new(45100);
        launcher.fail = vec!["b".into()];
        let err = failover(
            &ctx,
            &launcher,
            &[&a, &b],
            &FailoverOptions::default(),
            &CancelToken::manual(),
            &mut |_| Ok(()),
        )
        .unwrap_err();
        assert_eq!(err.to_string(), "缺少客户端内核: xray");
    }

    #[test]
    fn a_busy_port_fails_before_any_core_starts() {
        let dir = TempDir::new("linktools-test").unwrap();
        let (ctx, _, _) = Ctx::test(dir.path());
        let busy = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = busy.local_addr().unwrap().port();
        let a = entry("a", Core::Singbox, Transport::Tcp);
        let b = entry("b", Core::Xray, Transport::Udp);
        let launcher = FakeLauncher::new(45300);
        let opts = FailoverOptions {
            port,
            ..FailoverOptions::default()
        };
        let err = failover(
            &ctx,
            &launcher,
            &[&a, &b],
            &opts,
            &CancelToken::manual(),
            &mut |_| Ok(()),
        )
        .unwrap_err();
        assert!(
            err.to_string()
                .starts_with(&format!("无法监听本机 SOCKS5 端口: 127.0.0.1:{port}")),
            "{err}"
        );
        assert!(launcher.launched().is_empty(), "no core was started");
    }

    #[test]
    fn ctrl_c_during_startup_is_the_normal_stop() {
        let dir = TempDir::new("linktools-test").unwrap();
        let (ctx, exec, _) = Ctx::test(dir.path());
        let a = entry("a", Core::Singbox, Transport::Tcp);
        let b = entry("b", Core::Xray, Transport::Udp);
        let cancel = CancelToken::manual();
        let mut launcher = FakeLauncher::new(45400);
        launcher.interrupted = vec!["b".into()];
        launcher.cancel_on_launch = Some(cancel.clone());
        let events = Mutex::new(Vec::new());
        let mut emit = |line: &str| {
            events.lock().unwrap().push(line.to_owned());
            Ok(())
        };
        let opts = FailoverOptions {
            port: 0,
            ..FailoverOptions::default()
        };
        failover(&ctx, &launcher, &[&a, &b], &opts, &cancel, &mut emit).unwrap();
        assert_eq!(launcher.launched(), [("a".to_string(), 45400)]);
        assert!(events.lock().unwrap().is_empty(), "never served");
        assert!(exec.calls().is_empty(), "no health check");
    }

    #[test]
    fn health_rounds_probe_each_core_through_its_proxy() {
        let dir = TempDir::new("linktools-test").unwrap();
        let (ctx, exec, _) = Ctx::test(dir.path());
        // Entry a's proxy answers 503: unhealthy; b is healthy.
        exec.on_fn(
            |cmd| proxy_port(cmd) == Some(45200),
            |_| Ok(curl_ok(503, 0.1, 0)),
        )
        .on_fn(|cmd| cmd.program == "curl", |_| Ok(curl_ok(204, 0.1, 0)));
        let a = entry("a", Core::Singbox, Transport::Tcp);
        let b = entry("b", Core::Singbox, Transport::Udp);
        let launcher = FakeLauncher::new(45200);
        let port = std::net::TcpListener::bind(("127.0.0.1", 0))
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let opts = FailoverOptions {
            port,
            ..FailoverOptions::default()
        };
        let cancel = CancelToken::manual();
        let events = Arc::new(Mutex::new(Vec::new()));
        let seen = events.clone();
        let stopper = cancel.clone();
        let mut emit = move |line: &str| {
            seen.lock().unwrap().push(line.to_owned());
            if line.contains("ready") {
                stopper.cancel();
            }
            Ok(())
        };
        failover(&ctx, &launcher, &[&a, &b], &opts, &cancel, &mut emit).unwrap();
        assert_eq!(
            *events.lock().unwrap(),
            [
                r#"{"event":"switch","from":null,"to":"b"}"#.to_string(),
                format!(
                    r#"{{"entries":["a","b"],"event":"ready","socks":"127.0.0.1:{port}","tcp_only":true}}"#
                )
            ]
        );
        let mut ports: Vec<u16> = exec.calls().iter().filter_map(proxy_port).collect();
        ports.sort_unstable();
        assert_eq!(ports, [45200, 45201]);
    }
}
