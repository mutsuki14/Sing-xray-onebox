//! One HTTP/1.x exchange of the subscription worker (spec G §2.6): read the
//! request head (httparse, at most 8 KiB), authorize
//! `/sub/<64 lowercase hex token>/<format>`, and answer with v2's exact
//! response bytes. Devices and the snapshot are re-read for every request,
//! so a revoke, reset, disable or republish applies to the next request
//! without restarting anything.
//!
//! Responses (always `Connection: close`):
//! - 200 with the snapshot body and the format's content type;
//! - 400 `Bad Request\n` for a malformed or oversized head;
//! - 405 `Method Not Allowed\n` (+ `Allow: GET, HEAD`) for other methods;
//! - 404 `Not Found\n` for everything else (unknown token or format, query
//!   strings, trailing slashes, percent-encoding, missing snapshot).
//!
//! HEAD gets GET's headers (same `Content-Length`) without a body. A
//! connection closed, failed or out of time before the head is complete
//! gets no response.
//!
//! Time limits ([`Limits`]) cover whole phases, not single reads or
//! writes: in ip mode the worker faces the internet without nginx, and a
//! per-syscall timeout would let a client sending one byte every few
//! seconds (or reading the body that slowly) hold a pool thread for hours.
//! The head must be complete a fixed time after the connection was
//! accepted (time spent queued counts, so connections that went stale in
//! the queue are dropped at once), the response must be written within
//! its own deadline, and the drain after it is bounded in total time.
//! Every read or write waits at most for the time left.
//!
//! Changes from v2: the head is parsed with httparse as it arrives, so a
//! complete head is never refused because the read that completed it
//! crossed 8 KiB (G-8.1#15); deadlines per phase instead of 3 s per
//! read/write; after the response the write side is shut down and leftover
//! input drained briefly, so a client still sending (a body) receives the
//! response instead of a TCP reset.

use super::devices;
use super::snapshot;
use crate::domain::protocol::ClientFormat;
use crate::paths::Paths;
use std::io::{self, ErrorKind, Read, Write};
use std::time::{Duration, Instant};

/// Largest request head (v2 limit).
pub const MAX_HEAD_BYTES: usize = 8192;
const MAX_HEADERS: usize = 64;
/// Bytes handed to one `write` of the response.
const WRITE_CHUNK: usize = 64 * 1024;
/// Shortest wait given to a read or write (socket timeouts cannot be 0).
const MIN_WAIT: Duration = Duration::from_millis(1);
const PLAIN: &str = "text/plain; charset=utf-8";

/// A complete response (head + optional body).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Response {
    pub status: u16,
    pub content_type: &'static str,
    pub body: Vec<u8>,
    /// HEAD request: the body is not sent, its length is.
    pub head: bool,
}

impl Response {
    fn plain(status: u16, body: &str, head: bool) -> Response {
        Response {
            status,
            content_type: PLAIN,
            body: body.as_bytes().to_vec(),
            head,
        }
    }

    pub fn bad_request(head: bool) -> Response {
        Response::plain(400, "Bad Request\n", head)
    }

    pub fn not_found(head: bool) -> Response {
        Response::plain(404, "Not Found\n", head)
    }

    pub fn method_not_allowed(head: bool) -> Response {
        Response::plain(405, "Method Not Allowed\n", head)
    }

    /// The exact bytes on the wire (v2 header order).
    pub fn to_bytes(&self) -> Vec<u8> {
        let phrase = match self.status {
            200 => "OK",
            404 => "Not Found",
            405 => "Method Not Allowed",
            _ => "Bad Request",
        };
        let allow = if self.status == 405 {
            "Allow: GET, HEAD\r\n"
        } else {
            ""
        };
        let mut out = format!(
            "HTTP/1.1 {} {phrase}\r\nContent-Type: {}\r\nContent-Length: {}\r\n\
             Cache-Control: private, no-store\r\nReferrer-Policy: no-referrer\r\n\
             X-Content-Type-Options: nosniff\r\nConnection: close\r\n{allow}\r\n",
            self.status,
            self.content_type,
            self.body.len(),
        )
        .into_bytes();
        if !self.head {
            out.extend_from_slice(&self.body);
        }
        out
    }
}

/// What reading a request head produced.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Head {
    /// Closed (or timed out) before the head was complete: no response.
    Closed,
    /// Malformed, not UTF-8, not HTTP/1.x, or over 8 KiB.
    Bad {
        head: bool,
    },
    Request {
        method: String,
        path: String,
    },
}

/// Read and parse one request head; [`Head::Closed`] unless it is
/// complete by `deadline`. Each read waits at most for the time left. One
/// read is always attempted, and it takes everything buffered (up to the
/// 8 KiB limit), so a client whose connection waited in the queue past the
/// deadline is still served when its head has arrived in full.
pub fn read_head(conn: &mut dyn Conn, deadline: Instant) -> Head {
    let mut buf: Vec<u8> = Vec::with_capacity(1024);
    let mut chunk = [0u8; MAX_HEAD_BYTES];
    let mut attempted = false;
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        if attempted && left.is_zero() {
            return Head::Closed;
        }
        attempted = true;
        if conn.set_read_wait(left.max(MIN_WAIT)).is_err() {
            return Head::Closed;
        }
        let room = MAX_HEAD_BYTES - buf.len();
        let n = match conn.read(&mut chunk[..room]) {
            Ok(0) => return Head::Closed,
            Ok(n) => n,
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(_) => return Head::Closed,
        };
        buf.extend_from_slice(&chunk[..n]);
        match parse(&buf) {
            Some(head) => return head,
            None if buf.len() >= MAX_HEAD_BYTES => return bad(&buf),
            None => {}
        }
    }
}

/// `None` while the head is incomplete.
pub fn parse(buf: &[u8]) -> Option<Head> {
    let mut headers = [httparse::EMPTY_HEADER; MAX_HEADERS];
    let mut request = httparse::Request::new(&mut headers);
    match request.parse(buf) {
        Ok(httparse::Status::Partial) => None,
        Err(_) => Some(bad(buf)),
        Ok(httparse::Status::Complete(len)) => {
            if std::str::from_utf8(&buf[..len]).is_err() {
                return Some(bad(buf));
            }
            Some(Head::Request {
                method: request.method.unwrap_or_default().to_owned(),
                path: request.path.unwrap_or_default().to_owned(),
            })
        }
    }
}

/// v2 decides HEAD by the request line alone, also for 400 answers.
fn bad(buf: &[u8]) -> Head {
    Head::Bad {
        head: buf.starts_with(b"HEAD "),
    }
}

/// The format a request path names, if the token belongs to a device:
/// exactly `["", "sub", token, format]` with a 64-lowercase-hex token.
pub fn authorize(devices: &[crate::domain::config::Device], path: &str) -> Option<ClientFormat> {
    let parts: Vec<&str> = path.split('/').collect();
    let [empty, "sub", token, format] = parts.as_slice() else {
        return None;
    };
    if !empty.is_empty() || !devices::lower_hex(token, 64) {
        return None;
    }
    let format = ClientFormat::REMOTE
        .into_iter()
        .find(|f| f.id() == *format)?;
    devices::authorized(devices, token).then_some(format)
}

/// The response to a parsed head; reads devices and the snapshot now.
pub fn respond(paths: &Paths, head: &Head) -> Option<Response> {
    let (method, path) = match head {
        Head::Closed => return None,
        Head::Bad { head } => return Some(Response::bad_request(*head)),
        Head::Request { method, path } => (method.as_str(), path.as_str()),
    };
    let is_head = method == "HEAD";
    if method != "GET" && !is_head {
        return Some(Response::method_not_allowed(is_head));
    }
    let Some(format) = authorize(&devices::serving(paths), path) else {
        return Some(Response::not_found(is_head));
    };
    let body = snapshot::load(paths)
        .ok()
        .flatten()
        .and_then(|s| s.body(format).map(str::to_owned));
    Some(match body {
        Some(body) => Response {
            status: 200,
            content_type: format.content_type(),
            body: body.into_bytes(),
            head: is_head,
        },
        None => Response::not_found(is_head),
    })
}

/// A connection the worker serves: a stream plus the socket operations
/// around one exchange.
pub trait Conn: Read + Write + Send {
    /// How long each following read may block (`wait` is never zero).
    fn set_read_wait(&self, wait: Duration) -> io::Result<()>;
    /// How long each following write may block (`wait` is never zero).
    fn set_write_wait(&self, wait: Duration) -> io::Result<()>;
    /// Half-close after the response.
    fn shutdown_write(&self) -> io::Result<()>;
}

impl Conn for std::net::TcpStream {
    fn set_read_wait(&self, wait: Duration) -> io::Result<()> {
        self.set_read_timeout(Some(wait))
    }
    fn set_write_wait(&self, wait: Duration) -> io::Result<()> {
        self.set_write_timeout(Some(wait))
    }
    fn shutdown_write(&self) -> io::Result<()> {
        self.shutdown(std::net::Shutdown::Write)
    }
}

impl Conn for std::os::unix::net::UnixStream {
    fn set_read_wait(&self, wait: Duration) -> io::Result<()> {
        self.set_read_timeout(Some(wait))
    }
    fn set_write_wait(&self, wait: Duration) -> io::Result<()> {
        self.set_write_timeout(Some(wait))
    }
    fn shutdown_write(&self) -> io::Result<()> {
        self.shutdown(std::net::Shutdown::Write)
    }
}

/// Time limits of one exchange (module docs), each for a whole phase.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    /// The request head must be complete this long after `accept`.
    pub head: Duration,
    /// The response must be written within this long.
    pub write: Duration,
    /// How long to drain input after the response, in total.
    pub linger: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            head: Duration::from_secs(5),
            write: Duration::from_secs(20),
            linger: Duration::from_millis(200),
        }
    }
}

/// `from + span`, saturating instead of overflowing.
fn deadline(from: Instant, span: Duration) -> Instant {
    from.checked_add(span).unwrap_or(from)
}

/// Serve one connection accepted at `accepted`; I/O errors and expired
/// deadlines end it silently (nothing to report to).
pub fn handle(conn: &mut dyn Conn, paths: &Paths, limits: Limits, accepted: Instant) {
    let head = read_head(conn, deadline(accepted, limits.head));
    let Some(response) = respond(paths, &head) else {
        return;
    };
    let by = deadline(Instant::now(), limits.write);
    if write_by(conn, &response.to_bytes(), by).is_err() {
        return;
    }
    linger(conn, limits.linger);
}

/// Write all of `bytes` before `deadline`, in chunks; each write blocks at
/// most for the time left, so a client reading slowly cannot stretch it.
pub fn write_by(conn: &mut dyn Conn, bytes: &[u8], deadline: Instant) -> io::Result<()> {
    let mut rest = bytes;
    while !rest.is_empty() {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(ErrorKind::TimedOut.into());
        }
        conn.set_write_wait(left.max(MIN_WAIT))?;
        let end = rest.len().min(WRITE_CHUNK);
        match conn.write(&rest[..end]) {
            Ok(0) => return Err(ErrorKind::WriteZero.into()),
            Ok(n) => rest = &rest[n..],
            Err(e) if e.kind() == ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    conn.flush()
}

/// Half-close and discard what the client still sends for at most `limit`
/// in total, so closing does not reset the connection under the response.
fn linger(conn: &mut dyn Conn, limit: Duration) {
    if conn.shutdown_write().is_err() {
        return;
    }
    let until = deadline(Instant::now(), limit);
    let mut sink = [0u8; 4096];
    loop {
        let left = until.saturating_duration_since(Instant::now());
        if left.is_zero() || conn.set_read_wait(left).is_err() {
            return;
        }
        match conn.read(&mut sink) {
            Ok(0) | Err(_) => return,
            Ok(_) => {}
        }
    }
}

#[cfg(test)]
mod tests;
