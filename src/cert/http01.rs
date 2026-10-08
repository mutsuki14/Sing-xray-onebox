//! Built-in HTTP-01 challenge responder.
//!
//! Serves exactly `GET`/`HEAD /.well-known/acme-challenge/<token>` from a
//! webroot (the files acme.sh `--webroot` writes) on TCP 80 while one
//! acme.sh call runs; every other request gets `404`. It binds `[::]`
//! (dual-stack) when the host has IPv6, plus `0.0.0.0` when IPv6 sockets
//! are v6-only (`net.ipv6.bindv6only=1`); without IPv6 only `0.0.0.0`.
//!
//! Bounds: requests are parsed with `httparse` from at most 8 KiB of
//! headers, sockets have 5 s read/write timeouts, at most 32 connections
//! are served at once (more are closed immediately), tokens are
//! `[A-Za-z0-9_-]{1,255}` and challenge files at most 16 KiB regular files
//! (no symlinks). [`Responder::stop`] (or drop) ends the accept loops and
//! waits briefly for open connections.
//!
//! Changes from v2: replaces acme.sh `--standalone`, which needed `socat`
//! (never installed) and could not bind while an nginx held TCP 80
//! (F-8.1#4/#5).

use crate::error::{Error, Result};
use crate::sys::fs::read_bounded;
use std::io::{ErrorKind, Read, Write};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

/// The port ACME servers connect to.
pub const HTTP_PORT: u16 = 80;
/// Error when the responder cannot bind (v2 text).
pub const PORT_BUSY: &str = "HTTP-01 需要 TCP 80；请选择 DNS 验证或释放端口";
const CHALLENGE_PREFIX: &str = "/.well-known/acme-challenge/";
const MAX_HEADER_BYTES: usize = 8 * 1024;
const MAX_CONNECTIONS: usize = 32;
const MAX_TOKEN_FILE: u64 = 16 * 1024;
const IO_TIMEOUT: Duration = Duration::from_secs(5);
const POLL: Duration = Duration::from_millis(20);
const STOP_GRACE: Duration = Duration::from_secs(2);

/// A running responder; stops when dropped.
pub struct Responder {
    port: u16,
    stop: Arc<AtomicBool>,
    active: Arc<AtomicUsize>,
    threads: Vec<JoinHandle<()>>,
}

impl Responder {
    /// Bind `port` (0 = any free port, for tests) and serve `webroot`.
    /// `system_root` locates `/proc` for the IPv6 facts.
    pub fn start(webroot: &Path, port: u16, system_root: &Path) -> Result<Responder> {
        let listeners = bind(port, system_root)?;
        let port = listeners
            .first()
            .and_then(|l| l.local_addr().ok())
            .map_or(port, |a| a.port());
        let stop = Arc::new(AtomicBool::new(false));
        let active = Arc::new(AtomicUsize::new(0));
        let mut threads = Vec::new();
        for listener in listeners {
            listener.set_nonblocking(true).map_err(|e| Error::io(webroot, e))?;
            let server = Server {
                webroot: webroot.to_path_buf(),
                stop: stop.clone(),
                active: active.clone(),
            };
            threads.push(std::thread::spawn(move || server.accept_loop(listener)));
        }
        Ok(Responder {
            port,
            stop,
            active,
            threads,
        })
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    /// Stop accepting, wait up to 2 s for open connections, join threads.
    pub fn stop(mut self) {
        self.shutdown();
    }

    fn shutdown(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        for thread in self.threads.drain(..) {
            let _ = thread.join();
        }
        let deadline = Instant::now() + STOP_GRACE;
        while self.active.load(Ordering::SeqCst) > 0 && Instant::now() < deadline {
            std::thread::sleep(POLL);
        }
    }
}

impl Drop for Responder {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// The listening sockets (see the module docs for the family rules).
fn bind(port: u16, system_root: &Path) -> Result<Vec<TcpListener>> {
    let busy = |e: std::io::Error| {
        if e.kind() == ErrorKind::AddrInUse || e.kind() == ErrorKind::PermissionDenied {
            Error::msg(PORT_BUSY)
        } else {
            Error::msg(format!("{PORT_BUSY}: {e}"))
        }
    };
    let v4 = SocketAddr::from((Ipv4Addr::UNSPECIFIED, port));
    if !crate::sys::net::ipv6_available(system_root) {
        return Ok(vec![TcpListener::bind(v4).map_err(busy)?]);
    }
    let v6 = TcpListener::bind(SocketAddr::from((Ipv6Addr::UNSPECIFIED, port))).map_err(busy)?;
    let bound = v6.local_addr().map_or(port, |a| a.port());
    let v6only = std::fs::read_to_string(system_root.join("proc/sys/net/ipv6/bindv6only"))
        .is_ok_and(|s| s.trim() == "1");
    if !v6only {
        return Ok(vec![v6]);
    }
    let v4 = TcpListener::bind(SocketAddr::from((Ipv4Addr::UNSPECIFIED, bound))).map_err(busy)?;
    Ok(vec![v6, v4])
}

struct Server {
    webroot: PathBuf,
    stop: Arc<AtomicBool>,
    active: Arc<AtomicUsize>,
}

impl Server {
    fn accept_loop(self, listener: TcpListener) {
        let server = Arc::new(self);
        while !server.stop.load(Ordering::SeqCst) {
            match listener.accept() {
                Ok((stream, _)) => server.dispatch(stream),
                Err(_) => std::thread::sleep(POLL),
            }
        }
    }

    /// Serve on a thread, or drop the connection when at capacity.
    fn dispatch(self: &Arc<Self>, stream: TcpStream) {
        if self.active.fetch_add(1, Ordering::SeqCst) >= MAX_CONNECTIONS {
            self.active.fetch_sub(1, Ordering::SeqCst);
            return;
        }
        let server = Arc::clone(self);
        let spawned = std::thread::Builder::new().spawn(move || {
            let _ = server.serve(stream);
            server.active.fetch_sub(1, Ordering::SeqCst);
        });
        if spawned.is_err() {
            self.active.fetch_sub(1, Ordering::SeqCst);
        }
    }

    fn serve(&self, mut stream: TcpStream) -> std::io::Result<()> {
        stream.set_nonblocking(false)?;
        stream.set_read_timeout(Some(IO_TIMEOUT))?;
        stream.set_write_timeout(Some(IO_TIMEOUT))?;
        let Some((method, path)) = read_request(&mut stream)? else {
            return Ok(());
        };
        let response = respond(&self.webroot, &method, &path);
        stream.write_all(&response)?;
        stream.flush()
    }
}

/// Read until the header block is complete; `None` for malformed input.
fn read_request(stream: &mut TcpStream) -> std::io::Result<Option<(String, String)>> {
    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];
    loop {
        let n = stream.read(&mut chunk)?;
        if n == 0 {
            return Ok(None);
        }
        buf.extend_from_slice(&chunk[..n]);
        let mut headers = [httparse::EMPTY_HEADER; 32];
        let mut request = httparse::Request::new(&mut headers);
        match request.parse(&buf) {
            Ok(httparse::Status::Complete(_)) => {
                let method = request.method.unwrap_or_default().to_owned();
                let path = request.path.unwrap_or_default().to_owned();
                return Ok(Some((method, path)));
            }
            Ok(httparse::Status::Partial) if buf.len() < MAX_HEADER_BYTES => {}
            _ => return Ok(None),
        }
    }
}

/// The full HTTP response for one request (pure; unit-tested).
pub fn respond(webroot: &Path, method: &str, path: &str) -> Vec<u8> {
    let head = method == "HEAD";
    if !(method == "GET" || head) {
        return response(404, b"not found\n", head);
    }
    match challenge_file(webroot, path).and_then(|p| read_bounded(&p, MAX_TOKEN_FILE).ok()) {
        Some(body) => response(200, &body, head),
        None => response(404, b"not found\n", head),
    }
}

/// The file answering `path`, if `path` is a well-formed challenge URL.
fn challenge_file(webroot: &Path, path: &str) -> Option<PathBuf> {
    let token = path.strip_prefix(CHALLENGE_PREFIX)?;
    let valid = !token.is_empty()
        && token.len() <= 255
        && token
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
    valid.then(|| webroot.join(".well-known/acme-challenge").join(token))
}

fn response(status: u16, body: &[u8], head: bool) -> Vec<u8> {
    let reason = if status == 200 { "OK" } else { "Not Found" };
    let mut out = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\
         Connection: close\r\nServer: onebox\r\n\r\n",
        body.len()
    )
    .into_bytes();
    if !head {
        out.extend_from_slice(body);
    }
    out
}

#[cfg(test)]
mod tests;
