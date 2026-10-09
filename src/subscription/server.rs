//! `onebox subscription serve`: the subscription worker.
//!
//! Listener (G13): ip mode → TCP on the configured port on every address
//! (`[::]` dual-stack, plus `0.0.0.0` when IPv6 sockets are v6-only;
//! `0.0.0.0` alone without IPv6); site and standalone mode → the unix
//! socket `RUN/subscription.sock` behind nginx (0660, group of the nginx
//! worker; a stale socket is replaced, a live one or a non-socket refused).
//! The listener comes from `ROOT/subscription/listener.json`, which the
//! publish stage writes before it (re)starts the worker — the worker must
//! follow the generation being published, whose `state.json` is written
//! only when the apply finalizes. Without that file the node configuration
//! decides; a configuration still in v2 format means v2's layout (socket
//! behind nginx, also in ip mode), so a v3 worker started on v2 data
//! during an upgrade serves it the way v2 did (G6).
//!
//! The worker is read-only: it never writes configuration, and reads
//! devices and the snapshot per request (`http`). Connections go to a
//! bounded pool, stamped with their accept time: behind nginx (unix
//! socket) 4 threads and 16 queued, as in v2; on TCP, where clients
//! connect directly, 16 threads and 64 queued. When the queue is full a
//! new connection is closed at once. Every exchange has whole-phase
//! deadlines counted from `accept` ([`http::Limits`]), so slow clients
//! release their thread within seconds and stale queued connections are
//! dropped without waiting. Nothing is logged per request (tokens are in
//! URLs).
//!
//! Changes from v2: TCP listener in ip mode (no nginx); deadlines per
//! exchange instead of per read; failed `accept` calls back off instead of
//! spinning; the socket group is the nginx worker account Onebox renders
//! into its configs, recorded in `listener.json` by the publish stage
//! ([`Record`]).

use super::http::{self, Conn, Limits};
use crate::ctx::Ctx;
use crate::domain::config::{NodeConfig, SubscriptionMode};
use crate::error::{Context, Error, Result};
use crate::paths::Paths;
use crate::state::StateStore;
use crate::sys::exec::Cmd;
use crate::sys::fs::{atomic_write, read_bounded, remove_file_if_exists};
use crate::sys::rand::OsRandom;
use serde::{Deserialize, Serialize};
use std::io::{self, ErrorKind};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener};
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{sync_channel, Receiver, SyncSender, TrySendError};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

pub const ALREADY_RUNNING: &str = "订阅服务已在运行";
pub const SOCKET_OCCUPIED: &str = "订阅 socket 路径被其他文件占用";
pub const NOT_ENABLED: &str = "订阅未启用";
const ACCEPT_BACKOFF: Duration = Duration::from_millis(100);
const LISTENER_MAX: u64 = 4096;

/// What the worker listens on.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum Listener {
    /// Plain HTTP on every address (ip mode).
    Tcp { port: u16 },
    /// `RUN/subscription.sock` behind nginx (site, standalone).
    Unix,
}

impl Listener {
    /// The listener `cfg` needs; `None` when the subscription is off.
    pub fn of(cfg: &NodeConfig) -> Option<Listener> {
        let sub = cfg.subscription.as_ref()?;
        Some(match sub.mode {
            SubscriptionMode::Ip { .. } => Listener::Tcp { port: sub.port },
            SubscriptionMode::Site | SubscriptionMode::Standalone { .. } => Listener::Unix,
        })
    }
}

impl std::fmt::Display for Listener {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Listener::Tcp { port } => write!(f, "TCP {port}"),
            Listener::Unix => f.write_str("unix socket"),
        }
    }
}

/// `ROOT/subscription/listener.json`.
pub fn listener_file(paths: &Paths) -> PathBuf {
    paths.subscription().join("listener.json")
}

/// `listener.json`: the listener and, for the unix socket, the group of
/// the nginx worker account the apply rendered into the nginx
/// configurations. The worker takes the socket group from here: a daemon's
/// environment has no `ONEBOX_NGINX_BIN`, so resolving the account itself
/// could read another nginx's `user` and lock the real workers out.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Record {
    #[serde(flatten)]
    pub listener: Listener,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
}

/// The listener recorded by the last publish (`None` without the file).
pub fn recorded(paths: &Paths) -> Result<Option<Listener>> {
    Ok(read_record(paths)?.map(|r| r.listener))
}

/// The whole record of the last publish (`None` without the file).
pub fn read_record(paths: &Paths) -> Result<Option<Record>> {
    let path = listener_file(paths);
    match std::fs::symlink_metadata(&path) {
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(Error::io(&path, e)),
        Ok(_) => {}
    }
    let bytes = read_bounded(&path, LISTENER_MAX)?;
    serde_json::from_slice(&bytes)
        .map(Some)
        .context("订阅监听记录 listener.json 无效")
}

/// Record what the next worker start uses (0600, atomic).
pub fn record(paths: &Paths, record: &Record) -> Result<()> {
    crate::sys::fs::ensure_dir(&paths.subscription(), 0o700)?;
    let mut text = serde_json::to_string(record)?;
    text.push('\n');
    atomic_write(&listener_file(paths), text.as_bytes(), 0o600)
}

/// The group the unix socket belongs to: the recorded one, else (no
/// record yet, or one written before groups were recorded) the nginx
/// worker account resolved here.
fn socket_group(ctx: &Ctx) -> Result<String> {
    match read_record(&ctx.paths)?.and_then(|r| r.group) {
        Some(group) => Ok(group),
        None => Ok(crate::host::nginx::worker(ctx)?.group),
    }
}

/// Forget the recorded listener (subscription off).
pub fn forget(paths: &Paths) -> Result<()> {
    remove_file_if_exists(&listener_file(paths)).map(|_| ())
}

/// The worker's listener (module docs): the record, else the
/// configuration (read-only; v2 data means the v2 socket layout).
pub fn resolve(paths: &Paths) -> Result<Listener> {
    if let Some(listener) = recorded(paths)? {
        return Ok(listener);
    }
    if v2_state(paths) {
        return Ok(Listener::Unix);
    }
    let loaded = StateStore::load_from(paths, &mut OsRandom)?.ok_or(Error::NotInstalled)?;
    Listener::of(&loaded.config).ok_or_else(|| Error::msg(NOT_ENABLED))
}

/// `state.json` is v2's `{"values":{…}}` document. Checked without
/// migrating it: the v2 layout needs nothing from the values, so a v3
/// worker started on v2 data never depends on the migration succeeding.
fn v2_state(paths: &Paths) -> bool {
    read_bounded(&paths.state(), crate::domain::defaults::STATE_MAX_BYTES)
        .ok()
        .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok())
        .is_some_and(|doc| doc.get("values").is_some())
}

/// A listening socket the accept loop takes connections from.
pub trait Acceptor: Send {
    fn accept_conn(&self) -> io::Result<Box<dyn Conn>>;
}

impl Acceptor for TcpListener {
    fn accept_conn(&self) -> io::Result<Box<dyn Conn>> {
        Ok(Box::new(self.accept()?.0))
    }
}

impl Acceptor for UnixListener {
    fn accept_conn(&self) -> io::Result<Box<dyn Conn>> {
        Ok(Box::new(self.accept()?.0))
    }
}

/// Bind the TCP listeners for `port` (family rules in the module docs).
pub fn bind_tcp(port: u16, system_root: &Path) -> Result<Vec<TcpListener>> {
    let failed = |e: io::Error| Error::msg(format!("订阅端口 {port} 无法监听: {e}"));
    let v4 = SocketAddr::from((Ipv4Addr::UNSPECIFIED, port));
    if !crate::sys::net::ipv6_available(system_root) {
        return Ok(vec![TcpListener::bind(v4).map_err(failed)?]);
    }
    let v6 = TcpListener::bind(SocketAddr::from((Ipv6Addr::UNSPECIFIED, port))).map_err(failed)?;
    let v6only = std::fs::read_to_string(system_root.join("proc/sys/net/ipv6/bindv6only"))
        .is_ok_and(|s| s.trim() == "1");
    if !v6only {
        return Ok(vec![v6]);
    }
    let bound = v6.local_addr().map_or(port, |a| a.port());
    let v4 = SocketAddr::from((Ipv4Addr::UNSPECIFIED, bound));
    Ok(vec![v6, TcpListener::bind(v4).map_err(failed)?])
}

/// Bind `RUN/subscription.sock`: 0660, owned by root and the group of the
/// nginx worker (`gid`).
pub fn bind_unix(paths: &Paths, gid: u32) -> Result<UnixListener> {
    crate::sys::fs::ensure_dir(&paths.run, 0o755)?;
    super::frontend::check_socket_path(paths)?;
    let socket = paths.subscription_socket();
    clear_stale(&socket)?;
    let listener = UnixListener::bind(&socket).map_err(|e| Error::io(&socket, e))?;
    std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o660))
        .map_err(|e| Error::io(&socket, e))?;
    let uid = crate::sys::process::effective_uid();
    std::os::unix::fs::chown(&socket, Some(uid), Some(gid)).map_err(|e| Error::io(&socket, e))?;
    Ok(listener)
}

/// A socket nobody answers on is removed; a live worker or any other file
/// at the path is an error (v2 rules).
fn clear_stale(socket: &Path) -> Result<()> {
    let Ok(meta) = std::fs::symlink_metadata(socket) else {
        return Ok(());
    };
    ensure!(meta.file_type().is_socket(), "{SOCKET_OCCUPIED}");
    ensure!(UnixStream::connect(socket).is_err(), "{ALREADY_RUNNING}");
    remove_file_if_exists(socket).map(|_| ())
}

/// The numeric id of group `name`: `getent group`, else `/etc/group`
/// under the system root.
pub fn group_id(ctx: &Ctx, name: &str) -> Result<u32> {
    let cmd = Cmd::new("getent")
        .args(["group", name])
        .timeout(Duration::from_secs(10));
    let from_getent = ctx
        .run(&cmd)
        .ok()
        .filter(|o| o.ok())
        .and_then(|o| parse_group(&o.stdout, name));
    if let Some(gid) = from_getent {
        return Ok(gid);
    }
    let file = std::fs::read_to_string(ctx.paths.system("/etc/group")).unwrap_or_default();
    parse_group(&file, name).ok_or_else(|| Error::msg(format!("找不到用户组 {name}")))
}

/// The gid of `name` in `group(5)` lines (`name:x:gid:members`).
pub fn parse_group(text: &str, name: &str) -> Option<u32> {
    text.lines().find_map(|line| {
        let mut fields = line.split(':');
        (fields.next()? == name).then_some(())?;
        fields.nth(1)?.trim().parse().ok()
    })
}

/// Pool and exchange sizes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PoolSize {
    pub workers: usize,
    pub queue: usize,
}

impl Default for PoolSize {
    /// v2's pool, for the unix socket: nginx forwards complete requests.
    fn default() -> Self {
        PoolSize {
            workers: 4,
            queue: 16,
        }
    }
}

impl PoolSize {
    /// The pool for `listener`: on TCP clients connect directly, so more
    /// threads keep a few slow ones from occupying all of them until their
    /// deadlines expire.
    pub fn for_listener(listener: Listener) -> PoolSize {
        match listener {
            Listener::Tcp { .. } => PoolSize {
                workers: 16,
                queue: 64,
            },
            Listener::Unix => PoolSize::default(),
        }
    }
}

/// A queued connection and when it was accepted (its deadlines count from
/// then).
type Accepted = (Box<dyn Conn>, Instant);

/// A fixed set of threads serving queued connections. Idle threads block
/// on the queue; nothing polls.
pub struct Pool {
    tx: SyncSender<Accepted>,
}

impl Pool {
    pub fn start(paths: &Paths, size: PoolSize, limits: Limits) -> Result<Pool> {
        let (tx, rx) = sync_channel::<Accepted>(size.queue);
        let rx = Arc::new(Mutex::new(rx));
        for index in 0..size.workers.max(1) {
            let (rx, paths) = (Arc::clone(&rx), paths.clone());
            std::thread::Builder::new()
                .name(format!("subscription-{index}"))
                .spawn(move || work(&rx, &paths, limits))
                .map_err(|e| Error::msg(format!("无法启动订阅工作线程: {e}")))?;
        }
        Ok(Pool { tx })
    }

    /// Queue a connection accepted just now; `false` when the queue is
    /// full (the connection is dropped, i.e. closed without a response).
    pub fn submit(&self, conn: Box<dyn Conn>) -> bool {
        match self.tx.try_send((conn, Instant::now())) {
            Ok(()) => true,
            Err(TrySendError::Full(_) | TrySendError::Disconnected(_)) => false,
        }
    }
}

fn work(rx: &Mutex<Receiver<Accepted>>, paths: &Paths, limits: Limits) {
    loop {
        // The lock is held only while waiting for the next connection.
        let next = rx.lock().unwrap_or_else(PoisonError::into_inner).recv();
        match next {
            Ok((mut conn, accepted)) => http::handle(conn.as_mut(), paths, limits, accepted),
            Err(_) => return,
        }
    }
}

/// Accept forever; a failing `accept` (e.g. out of descriptors) backs off
/// instead of spinning.
pub fn accept_loop(acceptor: &dyn Acceptor, pool: &Pool) -> ! {
    loop {
        match acceptor.accept_conn() {
            Ok(conn) => {
                pool.submit(conn);
            }
            Err(e) if e.kind() == ErrorKind::Interrupted => {}
            Err(_) => std::thread::sleep(ACCEPT_BACKOFF),
        }
    }
}

/// Serve `acceptors` forever (one accept thread each; the last runs on
/// the calling thread).
pub fn run(
    paths: &Paths,
    mut acceptors: Vec<Box<dyn Acceptor>>,
    size: PoolSize,
    limits: Limits,
) -> Result<()> {
    let last = acceptors
        .pop()
        .ok_or_else(|| Error::msg("订阅服务没有可用的监听"))?;
    let pool = Arc::new(Pool::start(paths, size, limits)?);
    for acceptor in acceptors {
        let pool = Arc::clone(&pool);
        std::thread::Builder::new()
            .name("subscription-accept".into())
            .spawn(move || accept_loop(acceptor.as_ref(), &pool))
            .map_err(|e| Error::msg(format!("无法启动订阅监听线程: {e}")))?;
    }
    accept_loop(last.as_ref(), &pool)
}

/// The hidden `subscription serve` command (module docs).
pub fn serve(ctx: &Ctx) -> Result<()> {
    let listener = resolve(&ctx.paths)?;
    let acceptors: Vec<Box<dyn Acceptor>> = match listener {
        Listener::Tcp { port } => bind_tcp(port, &ctx.paths.system_root)?
            .into_iter()
            .map(|l| Box::new(l) as Box<dyn Acceptor>)
            .collect(),
        Listener::Unix => {
            let group = socket_group(ctx)?;
            let gid = group_id(ctx, &group)?;
            vec![Box::new(bind_unix(&ctx.paths, gid)?)]
        }
    };
    crate::ui::out::info(format!("订阅服务已启动（{listener}）"));
    let size = PoolSize::for_listener(listener);
    run(&ctx.paths, acceptors, size, Limits::default())
}

#[cfg(test)]
mod tests;
