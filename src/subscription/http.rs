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
//! connection closed or timed out before the head is complete gets no
//! response.
//!
//! Changes from v2: the head is parsed with httparse as it arrives, so a
//! complete head is never refused because the read that completed it
//! crossed 8 KiB (G-8.1#15); after the response the write side is shut
//! down and leftover input drained briefly, so a client still sending
//! (a body) receives the response instead of a TCP reset.

use super::devices;
use super::snapshot;
use crate::domain::protocol::ClientFormat;
use crate::paths::Paths;
use std::io::{self, ErrorKind, Read, Write};

/// Largest request head (v2 limit).
pub const MAX_HEAD_BYTES: usize = 8192;
const READ_CHUNK: usize = 1024;
const MAX_HEADERS: usize = 64;
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

/// Read and parse one request head from `stream`.
pub fn read_head<R: Read + ?Sized>(stream: &mut R) -> Head {
    let mut buf: Vec<u8> = Vec::with_capacity(READ_CHUNK);
    let mut chunk = [0u8; READ_CHUNK];
    loop {
        let room = (MAX_HEAD_BYTES - buf.len()).min(READ_CHUNK);
        let n = match stream.read(&mut chunk[..room]) {
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
    /// Read/write timeouts (3 s in production).
    fn set_timeouts(&self, timeout: std::time::Duration) -> io::Result<()>;
    /// Half-close after the response.
    fn shutdown_write(&self) -> io::Result<()>;
}

impl Conn for std::net::TcpStream {
    fn set_timeouts(&self, timeout: std::time::Duration) -> io::Result<()> {
        self.set_read_timeout(Some(timeout))?;
        self.set_write_timeout(Some(timeout))
    }
    fn shutdown_write(&self) -> io::Result<()> {
        self.shutdown(std::net::Shutdown::Write)
    }
}

impl Conn for std::os::unix::net::UnixStream {
    fn set_timeouts(&self, timeout: std::time::Duration) -> io::Result<()> {
        self.set_read_timeout(Some(timeout))?;
        self.set_write_timeout(Some(timeout))
    }
    fn shutdown_write(&self) -> io::Result<()> {
        self.shutdown(std::net::Shutdown::Write)
    }
}

/// Exchange limits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    pub io_timeout: std::time::Duration,
    /// How long to drain input after the response.
    pub linger: std::time::Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            io_timeout: std::time::Duration::from_secs(3),
            linger: std::time::Duration::from_millis(200),
        }
    }
}

/// Serve one connection; I/O errors end it silently (nothing to report to).
pub fn handle(conn: &mut dyn Conn, paths: &Paths, limits: Limits) {
    if conn.set_timeouts(limits.io_timeout).is_err() {
        return;
    }
    let head = read_head(conn);
    let Some(response) = respond(paths, &head) else {
        return;
    };
    if conn
        .write_all(&response.to_bytes())
        .and_then(|()| conn.flush())
        .is_err()
    {
        return;
    }
    linger(conn, limits.linger);
}

/// Half-close and discard what the client still sends (bounded in time
/// and size) so closing does not reset the connection under the response.
fn linger(conn: &mut dyn Conn, limit: std::time::Duration) {
    if conn.shutdown_write().is_err() || conn.set_timeouts(limit).is_err() {
        return;
    }
    let mut sink = [0u8; 4096];
    for _ in 0..16 {
        match conn.read(&mut sink) {
            Ok(0) | Err(_) => return,
            Ok(_) => {}
        }
    }
}

#[cfg(test)]
mod tests;
