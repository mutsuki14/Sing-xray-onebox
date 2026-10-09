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
//! - a core that exits is reported and restarted (see [`super::revive`]);
//! - a panicking health check fails only its own entry (v2: the round);
//! - the listener is bound by the caller before any core starts ([`bind`]);
//! - a thread the OS refuses (pids limit) costs one client (`05 FF`) or
//!   slows one round (the check runs on the round's thread); it never
//!   panics the service (see [`super::threads`]).

use super::policy::FailoverPolicy;
use super::relay;
use super::revive::{revive, Backoff, ProxySlot};
use super::threads::{spawn_with, Spawner, Task};
use crate::error::{Error, Result};
use crate::linktools::cancel::CancelToken;
use crate::linktools::core_client::Proxy;
use crate::linktools::socks::{self, Handshake, SocksEndpoint, REPLY_HOST_UNREACHABLE};
use serde_json::{json, Value};
use std::io::{self, Write};
use std::net::{Ipv4Addr, TcpListener, TcpStream};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
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

/// The client side of one connection: how long the upstream connect may
/// take, the relay's idle reaper, the run's token and the thread source.
#[derive(Clone, Copy)]
pub struct ClientPolicy<'a> {
    pub upstream_timeout: Duration,
    pub idle: Duration,
    pub cancel: &'a CancelToken,
    pub spawner: &'a dyn Spawner,
}

/// Serve one client: handshake, route through the active entry's core
/// (looked up after the request, so policy switches affect new
/// connections only), reply, relay.
pub fn handle_client(
    mut stream: TcpStream,
    route: &dyn Fn() -> Option<SocksEndpoint>,
    policy: ClientPolicy,
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
        .and_then(|endpoint| socks::connect(&endpoint, &target, policy.upstream_timeout));
    match upstream {
        Ok(upstream) => {
            stream.write_all(&socks::REPLY_SUCCEEDED)?;
            relay::relay(stream, upstream, policy.cancel, policy.idle, policy.spawner)
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
    /// The current proxy of each entry, same order.
    pub proxies: &'a [ProxySlot],
    /// One health check through the current proxy of entry `i`.
    pub health: &'a (dyn Fn(usize) -> bool + Sync),
    /// Start a fresh proxy for entry `i` (after its core died).
    pub restart: &'a (dyn Fn(usize) -> Result<Box<dyn Proxy>> + Sync),
    /// The local SOCKS5 listener from [`bind`].
    pub listener: &'a TcpListener,
    /// Pause between the end of a round and the next one.
    pub interval: Duration,
    /// Timeout of the upstream SOCKS connect (`--timeout`).
    pub upstream_timeout: Duration,
    pub max_clients: usize,
    /// Relay idle reaper.
    pub idle: Duration,
    /// Starts every helper thread (real: `threads::OsThreads`).
    pub spawner: &'a dyn Spawner,
}

/// Bind the local SOCKS5 listener on `127.0.0.1:<port>` (non-blocking, for
/// the acceptor). `failover` binds it before starting any core, so a busy
/// port fails at once and no temporary core's random port can take it.
pub fn bind(port: u16) -> Result<TcpListener> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, port))
        .map_err(|e| Error::io(format!("127.0.0.1:{port}"), e).wrap("无法监听本机 SOCKS5 端口"))?;
    listener.set_nonblocking(true)?;
    Ok(listener)
}

fn thread_error(e: io::Error) -> Error {
    Error::msg(format!("无法创建线程: {e}"))
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
    let port = svc.listener.local_addr()?.port();
    let active = Active::default();
    let slots = Slots::new(svc.max_clients);
    let failure = Mutex::new(None);
    let shared = (&active, &slots, &failure);
    std::thread::scope(|scope| {
        let (active, slots, failure) = shared;
        let acceptor: Task =
            Box::new(move || accept_loop(scope, svc, active, slots, cancel, failure));
        let outcome = match svc.spawner.spawn(scope, "onebox-accept", acceptor) {
            Ok(_) => monitor(scope, svc, port, policy, active, cancel, emit),
            Err(e) => Err(thread_error(e)),
        };
        if let Err(e) = outcome {
            record(failure, e);
            cancel.cancel();
        }
        // Stopping the cores closes every upstream, which wakes the relays.
        for slot in svc.proxies {
            slot.get().terminate();
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

/// Accept until cancelled; each client gets a scoped handler thread (a
/// client whose thread the OS refuses is rejected like one over the limit).
fn accept_loop<'scope>(
    scope: &'scope Scope<'scope, '_>,
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
            .map(|slot| slot.get().endpoint().clone())
    };
    let policy = ClientPolicy {
        upstream_timeout: svc.upstream_timeout,
        idle: svc.idle,
        cancel,
        spawner: svc.spawner,
    };
    while !cancel.is_cancelled() {
        match svc.listener.accept() {
            Ok((stream, _)) => match slots.try_take() {
                Some(slot) => {
                    let work = move |(stream, _slot): (TcpStream, Slot<'scope>)| {
                        let _ = handle_client(stream, &route, policy);
                    };
                    let item = (stream, slot);
                    if let Err((_, (stream, _slot))) =
                        spawn_with(svc.spawner, scope, "onebox-client", item, work)
                    {
                        reject(stream);
                    }
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
    matches!(
        e.kind(),
        io::ErrorKind::Interrupted | io::ErrorKind::ConnectionAborted
    ) || matches!(
        e.raw_os_error(),
        Some(libc::EMFILE | libc::ENFILE | libc::ENOBUFS | libc::ENOMEM | libc::EPROTO)
    )
}

/// Health rounds and events until cancelled. A round whose thread the OS
/// refuses runs on the monitor's own thread (it waits for it anyway).
fn monitor<'scope>(
    scope: &'scope Scope<'scope, '_>,
    svc: &'scope Service,
    port: u16,
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
    let mut rounds = 0u64;
    let mut backoff = vec![Backoff::default(); svc.proxies.len()];
    while !cancel.is_cancelled() {
        if !running && Instant::now() >= next_round {
            running = true;
            let sender = tx.clone();
            let task: Task = Box::new(move || {
                let _ = sender.send(round(svc));
            });
            if svc.spawner.spawn(scope, "onebox-round", task).is_err() {
                let _ = tx.send(round(svc));
            }
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
            emit(&ready_event(svc.ids, port).to_string())?;
            ready = true;
        }
        revive(
            svc.ids,
            svc.proxies,
            &mut backoff,
            rounds,
            svc.restart,
            cancel,
        );
        rounds += 1;
        next_round = Instant::now() + svc.interval;
    }
    Ok(())
}

/// One health check per proxy, in parallel. A check whose thread the OS
/// refuses runs on the round's own thread: a slower round, not a false
/// verdict about the entry. A panicking check fails only its entry.
fn round(svc: &Service) -> Vec<bool> {
    let results: Vec<AtomicBool> = svc.proxies.iter().map(|_| AtomicBool::new(false)).collect();
    std::thread::scope(|scope| {
        let mut checks = Vec::new();
        for (i, result) in results.iter().enumerate() {
            let task: Task = Box::new(move || result.store((svc.health)(i), Ordering::SeqCst));
            match svc.spawner.spawn(scope, "onebox-check", task) {
                Ok(check) => checks.push(check),
                Err(_) => {
                    let healthy = catch_unwind(AssertUnwindSafe(|| (svc.health)(i)));
                    result.store(healthy.unwrap_or(false), Ordering::SeqCst);
                }
            }
        }
        for check in checks {
            // A panicked check left its result false.
            let _ = check.join();
        }
    });
    results.into_iter().map(AtomicBool::into_inner).collect()
}

#[cfg(test)]
mod tests;
