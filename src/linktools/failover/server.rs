//! The failover service: an unauthenticated SOCKS5 CONNECT listener on
//! `127.0.0.1:<port>` that routes each new connection through the
//! currently active client core, plus the health rounds that drive
//! [`FailoverPolicy`] (spec D §2.5).
//!
//! Threads (all scoped, so shutdown joins everything): the caller runs the
//! monitor (health rounds, events on stdout), one acceptor, one health
//! round at a time (one request per core in parallel), and per connection
//! a handler plus its relay helper (at most `max_clients` connections).
//!
//! Changes from v2:
//! - a connection over the limit gets `05 FF` (no acceptable method)
//!   before it is closed instead of a silent close (D-8.1#22);
//! - transient accept errors (EMFILE, ECONNABORTED…) back off and retry
//!   instead of stopping the service; other accept errors still stop it
//!   (exit 1) through the run's own cancel token (D-8.1#24);
//! - a core that exits is reported once on stderr (its entry then fails
//!   every round and is never routed to);
//! - a panicking health check fails only its own entry (v2: the round).

use super::policy::FailoverPolicy;
use super::relay;
use crate::error::{Error, Result};
use crate::linktools::cancel::CancelToken;
use crate::linktools::core_client::Proxy;
use crate::linktools::socks::{self, Handshake, SocksEndpoint, REPLY_HOST_UNREACHABLE};
use crate::ui::out;
use serde_json::{json, Value};
use std::io::{self, Write};
use std::net::{Ipv4Addr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{mpsc, Mutex, PoisonError};
use std::thread::Scope;
use std::time::{Duration, Instant};

/// v2's limit of concurrent SOCKS clients.
pub const MAX_CLIENTS: usize = 128;
/// Read/write timeout of a client during the SOCKS handshake (v2).
pub const CLIENT_TIMEOUT: Duration = Duration::from_secs(5);
const ACCEPT_IDLE: Duration = Duration::from_millis(20);
const ACCEPT_BACKOFF: Duration = Duration::from_millis(100);
const MONITOR_TICK: Duration = Duration::from_millis(100);
const NONE: usize = usize::MAX;

/// The active entry, read once per new connection.
#[derive(Debug)]
pub struct Active(AtomicUsize);

impl Default for Active {
    fn default() -> Active {
        Active(AtomicUsize::new(NONE))
    }
}

impl Active {
    pub fn get(&self) -> Option<usize> {
        match self.0.load(Ordering::SeqCst) {
            NONE => None,
            i => Some(i),
        }
    }

    pub fn set(&self, index: Option<usize>) {
        self.0.store(index.unwrap_or(NONE), Ordering::SeqCst);
    }
}

/// Live-connection counter with a hard maximum.
#[derive(Debug)]
pub struct Slots {
    live: AtomicUsize,
    max: usize,
}

/// One taken slot; released on drop.
pub struct Slot<'a>(&'a Slots);

impl Slots {
    pub fn new(max: usize) -> Slots {
        Slots {
            live: AtomicUsize::new(0),
            max,
        }
    }

    pub fn try_take(&self) -> Option<Slot<'_>> {
        self.live
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| {
                (n < self.max).then_some(n + 1)
            })
            .ok()
            .map(|_| Slot(self))
    }

    pub fn live(&self) -> usize {
        self.live.load(Ordering::SeqCst)
    }
}

impl Drop for Slot<'_> {
    fn drop(&mut self) {
        self.0.live.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Serve one client: handshake, route through the active entry's core
/// (looked up after the request, so policy switches affect new
/// connections only), reply, relay.
pub fn handle_client(
    mut stream: TcpStream,
    route: &dyn Fn() -> Option<SocksEndpoint>,
    upstream_timeout: Duration,
    cancel: &CancelToken,
    idle: Duration,
) -> Result<()> {
    stream.set_nonblocking(false)?;
    stream.set_read_timeout(Some(CLIENT_TIMEOUT))?;
    stream.set_write_timeout(Some(CLIENT_TIMEOUT))?;
    let target = match socks::accept_handshake(&mut stream)? {
        Handshake::Connect(target) => target,
        Handshake::Refused => return Ok(()),
    };
    let upstream = route()
        .ok_or_else(|| Error::msg("无健康入口"))
        .and_then(|endpoint| socks::connect(&endpoint, &target, upstream_timeout));
    match upstream {
        Ok(upstream) => {
            stream.write_all(&socks::REPLY_SUCCEEDED)?;
            relay::relay(stream, upstream, cancel, idle)
        }
        Err(e) => {
            let _ = stream.write_all(&REPLY_HOST_UNREACHABLE);
            Err(e)
        }
    }
}

/// Best-effort refusal of a connection over the limit, without blocking
/// the acceptor: the client reads it as its method selection.
pub fn reject(stream: TcpStream) {
    let _ = stream.set_nonblocking(true);
    let _ = (&stream).write(&socks::NO_ACCEPTABLE_METHODS);
}

/// `{"event":"switch","from":…,"to":…}` (ids or null).
pub fn switch_event(ids: &[String], from: Option<usize>, to: Option<usize>) -> Value {
    let id = |i: Option<usize>| i.and_then(|i| ids.get(i)).cloned();
    json!({"event": "switch", "from": id(from), "to": id(to)})
}

/// `{"entries":[…],"event":"ready","socks":"127.0.0.1:<port>","tcp_only":true}`.
pub fn ready_event(ids: &[String], port: u16) -> Value {
    json!({"entries": ids, "event": "ready", "socks": format!("127.0.0.1:{port}"),
        "tcp_only": true})
}

/// Everything the service needs.
pub struct Service<'a> {
    /// Entry ids in priority order (event payloads).
    pub ids: &'a [String],
    /// One running proxy per entry, same order.
    pub proxies: &'a [Box<dyn Proxy>],
    /// One health check through proxy `i`.
    pub health: &'a (dyn Fn(usize) -> bool + Sync),
    pub port: u16,
    /// Pause between the end of a round and the next one.
    pub interval: Duration,
    /// Timeout of the upstream SOCKS connect (`--timeout`).
    pub upstream_timeout: Duration,
    pub max_clients: usize,
    /// Relay idle reaper.
    pub idle: Duration,
}

/// Run until `cancel` is tripped. Events go to `emit` as JSON lines; the
/// first round prints its switch (null → first entry) before `ready`.
/// `Ok` for a user stop, the error for a listener failure.
pub fn serve(
    svc: &Service,
    policy: FailoverPolicy,
    cancel: &CancelToken,
    emit: &mut dyn FnMut(&str) -> Result<()>,
) -> Result<()> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, svc.port))
        .map_err(|e| Error::io(format!("127.0.0.1:{}", svc.port), e).wrap("无法监听本机 SOCKS5 端口"))?;
    listener.set_nonblocking(true)?;
    let active = Active::default();
    let slots = Slots::new(svc.max_clients);
    let failure = Mutex::new(None);
    std::thread::scope(|scope| {
        scope.spawn(|| accept_loop(scope, &listener, svc, &active, &slots, cancel, &failure));
        if let Err(e) = monitor(scope, svc, policy, &active, cancel, emit) {
            record(&failure, e);
            cancel.cancel();
        }
        // Stopping the cores closes every upstream, which wakes the relays.
        for proxy in svc.proxies {
            proxy.terminate();
        }
    });
    match failure.into_inner().unwrap_or_else(PoisonError::into_inner) {
        Some(e) => Err(e),
        None => Ok(()),
    }
}

fn record(failure: &Mutex<Option<Error>>, e: Error) {
    let mut slot = failure.lock().unwrap_or_else(PoisonError::into_inner);
    slot.get_or_insert(e);
}

/// Accept until cancelled; each client gets a scoped handler thread.
fn accept_loop<'scope>(
    scope: &'scope Scope<'scope, '_>,
    listener: &'scope TcpListener,
    svc: &'scope Service,
    active: &'scope Active,
    slots: &'scope Slots,
    cancel: &'scope CancelToken,
    failure: &'scope Mutex<Option<Error>>,
) {
    let route = move || {
        active
            .get()
            .and_then(|i| svc.proxies.get(i))
            .map(|p| p.endpoint().clone())
    };
    while !cancel.is_cancelled() {
        match listener.accept() {
            Ok((stream, _)) => match slots.try_take() {
                Some(slot) => {
                    scope.spawn(move || {
                        let _slot = slot;
                        let timeout = svc.upstream_timeout;
                        let _ = handle_client(stream, &route, timeout, cancel, svc.idle);
                    });
                }
                None => reject(stream),
            },
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => std::thread::sleep(ACCEPT_IDLE),
            Err(e) if transient(&e) => std::thread::sleep(ACCEPT_BACKOFF),
            Err(e) => {
                record(failure, Error::from(e).wrap("本机 SOCKS5 监听失败"));
                cancel.cancel();
            }
        }
    }
}

/// Accept errors that say nothing about the listener itself.
fn transient(e: &io::Error) -> bool {
    matches!(e.kind(), io::ErrorKind::Interrupted | io::ErrorKind::ConnectionAborted)
        || matches!(
            e.raw_os_error(),
            Some(libc::EMFILE | libc::ENFILE | libc::ENOBUFS | libc::ENOMEM | libc::EPROTO)
        )
}

/// Health rounds and events until cancelled.
fn monitor<'scope>(
    scope: &'scope Scope<'scope, '_>,
    svc: &'scope Service,
    mut policy: FailoverPolicy,
    active: &Active,
    cancel: &CancelToken,
    emit: &mut dyn FnMut(&str) -> Result<()>,
) -> Result<()> {
    let (tx, rx) = mpsc::channel();
    let clock = Instant::now();
    let mut next_round = Instant::now();
    let mut running = false;
    let mut ready = false;
    let mut reported = vec![false; svc.proxies.len()];
    while !cancel.is_cancelled() {
        if !running && Instant::now() >= next_round {
            running = true;
            let tx = tx.clone();
            scope.spawn(move || {
                let _ = tx.send(round(svc));
            });
        }
        let health = match rx.recv_timeout(MONITOR_TICK) {
            Ok(health) => health,
            Err(_) => continue,
        };
        running = false;
        let old = policy.active();
        let new = policy.update(&health, clock.elapsed().as_secs_f64());
        active.set(new);
        if old != new {
            emit(&switch_event(svc.ids, old, new).to_string())?;
        }
        if !ready {
            emit(&ready_event(svc.ids, svc.port).to_string())?;
            ready = true;
        }
        report_exits(svc, &mut reported);
        next_round = Instant::now() + svc.interval;
    }
    Ok(())
}

/// One health check per proxy, in parallel.
fn round(svc: &Service) -> Vec<bool> {
    std::thread::scope(|scope| {
        let checks: Vec<_> = (0..svc.proxies.len())
            .map(|i| scope.spawn(move || (svc.health)(i)))
            .collect();
        checks
            .into_iter()
            .map(|check| check.join().unwrap_or(false))
            .collect()
    })
}

/// Tell once that a core has exited (its entry stays unhealthy).
fn report_exits(svc: &Service, reported: &mut [bool]) {
    for (i, proxy) in svc.proxies.iter().enumerate() {
        let Some(code) = proxy.exited() else {
            continue;
        };
        if !reported[i] {
            reported[i] = true;
            let id = svc.ids.get(i).map_or("?", String::as_str);
            out::warn(format!(
                "入口 {id} 的客户端内核已退出（退出码 {code}），该入口不再可用"
            ));
        }
    }
}

#[cfg(test)]
mod tests;
