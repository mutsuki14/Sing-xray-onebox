//! Bounded HTTP measurements through curl: health samples, download and
//! upload transfers, and the direct `--connect-to` fetches of the REALITY
//! check. curl validates certificates and resolves names on the proxy side
//! (`socks5h`); this module builds its argv (spec D §4.1), feeds it the
//! body sink and parses its `--write-out` record (D §3.4, §4.2).
//!
//! The body cap is explicit: curl writes the body into a pipe of ours
//! whose reader stops deliberately and closes its end — after `range`
//! measured bytes (downloads, the REALITY page comparison), or after the
//! first chunk curl writes (at most 64 KiB, nothing measured) for requests
//! without a range (health checks, uploads), so a large or endless 2xx body
//! never runs into `--max-time`. curl then fails its next write with
//! CURLE_WRITE_ERROR (23) but still prints its timings, and exit 23 counts
//! as success ONLY when the reader really stopped that way; any other
//! non-zero exit is a real failure.
//!
//! Changes from v2:
//! - the proxy credential reaches curl as `--config -` on stdin instead of
//!   a `curl.conf` file (still never on argv);
//! - the body goes to `--output` (our pipe) instead of curl's stdout, and
//!   the deliberate-stop rule above replaces "exit 23 is fine whenever
//!   received == limit", which also accepted genuine write errors of health
//!   checks (D-8.1#4); like v2, a request without a range does not measure
//!   the body (`received_bytes` 0, hash of nothing);
//! - the statistics come from curl's captured stderr (bounded) instead of
//!   an unbounded file read (D-8.1#25);
//! - a failed request names curl's exit code.

use super::cancel::CancelToken;
use super::socks::{SocksEndpoint, USERNAME};
use super::stats::round3;
use super::url::TestUrl;
use crate::ctx::Ctx;
use crate::error::{Error, Result};
use crate::sys::exec::{Cmd, Output};
use crate::sys::fs::{read_bounded, sha256_hex, TempDir};
use crate::sys::rand::{OsRandom, Random};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::fs::OpenOptions;
use std::io::{self, PipeReader, PipeWriter, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

pub const USER_AGENT: &str = "onebox-probe/2";
/// The timing record, written to stderr after the transfer (curl ≥ 7.63).
pub const WRITE_OUT: &str = concat!(
    "%{stderr}\nONEBOX_STATS:{\"status\":%{response_code},\"setup\":%{time_pretransfer},",
    "\"ttfb\":%{time_starttransfer},\"duration\":%{time_total},\"sent\":%{size_upload}}\n"
);
const STATS_PREFIX: &str = "ONEBOX_STATS:";
/// CURLE_WRITE_ERROR: the body sink was closed (at the cap, or broken).
pub const CURL_WRITE_ERROR: i32 = 23;
/// How much longer than `--max-time` curl may run before it is killed (v2).
const KILL_SLACK: Duration = Duration::from_secs(2);
/// SIGTERM → SIGKILL grace when a curl run is abandoned.
const KILL_GRACE: Duration = Duration::from_millis(500);
const POLL: Duration = Duration::from_millis(50);
const MAX_HEADER_BYTES: u64 = 1024 * 1024;
const PAYLOAD_BLOCK: usize = 64 * 1024;
const READ_CHUNK: usize = 64 * 1024;
/// The most a request without a range reads (one chunk) before it closes
/// the sink.
pub const DISCARD_CAP: usize = READ_CHUNK;
/// Error key of a failed sample in reports (v2).
pub const REQUEST_FAILED: &str = "request_failed";

/// How a request reaches the origin.
#[derive(Clone, Copy, Debug)]
pub enum Route<'a> {
    /// Through a client core's SOCKS inbound; names resolve on the proxy.
    Proxy(&'a SocksEndpoint),
    /// Directly (proxy environment variables ignored), optionally pinned
    /// to `host:port` with `--connect-to` while keeping the URL's name.
    Direct { connect_to: Option<(&'a str, u16)> },
}

/// One measurement.
#[derive(Clone, Copy, Debug)]
pub struct HttpRequest<'a> {
    pub url: &'a TestUrl,
    pub route: Route<'a>,
    /// `--connect-timeout` and `--max-time`, seconds.
    pub timeout_secs: u64,
    pub ca: Option<&'a Path>,
    /// Measure the first `range` body bytes (requested with `--range`);
    /// 0 = no range: the body is not measured and the sink closes after
    /// the first chunk (health checks, uploads).
    pub range: u64,
    /// POST this many random bytes; 0 sends a GET.
    pub upload: u64,
}

/// The files a curl invocation uses.
#[derive(Clone, Copy, Debug)]
pub struct CurlFiles<'a> {
    pub headers: &'a Path,
    /// `--output` target: the body sink.
    pub body: &'a str,
    pub payload: Option<&'a Path>,
}

/// The measurement record (keys alphabetical in JSON, as v2).
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct HttpResult {
    /// Lowercase hex SHA-256 of the received bytes.
    pub body_sha256: String,
    pub download_mbps: f64,
    /// Last `Location` header, trimmed; `""` without one.
    pub location: String,
    /// `200 <= status < 300`.
    pub ok: bool,
    pub received_bytes: u64,
    pub sent_bytes: u64,
    pub setup_ms: f64,
    pub status: u16,
    pub total_ms: f64,
    pub ttfb_ms: f64,
    pub upload_mbps: f64,
}

/// A measurement or the reason it could not be made (`safe_request`).
#[derive(Clone, Debug, PartialEq)]
pub enum Measurement {
    Done(HttpResult),
    Failed(String),
}

impl Measurement {
    /// A 2xx response was measured.
    pub fn ok(&self) -> bool {
        matches!(self, Measurement::Done(r) if r.ok)
    }

    /// Time to first byte of a successful measurement.
    pub fn ok_ttfb(&self) -> Option<f64> {
        match self {
            Measurement::Done(r) if r.ok => Some(r.ttfb_ms),
            _ => None,
        }
    }
}

/// Build the curl command (D §4.1). Proxy credentials are fed on stdin.
pub fn curl_command(req: &HttpRequest, files: &CurlFiles) -> Result<Cmd> {
    let timeout = req.timeout_secs.to_string();
    let mut cmd = Cmd::new("curl")
        .args(["-q", "--silent", "--http1.1", "--proto", "=http,https"])
        .args(["--max-redirs", "0", "--connect-timeout", &timeout])
        .args(["--max-time", &timeout])
        .args(["--header", "Accept-Encoding: identity"])
        .args(["--header", "Connection: close", "--user-agent", USER_AGENT])
        .arg("--dump-header")
        .arg(path_arg(files.headers)?)
        .args(["--write-out", WRITE_OUT]);
    match req.route {
        Route::Proxy(endpoint) => {
            cmd = cmd
                .args(["--config", "-", "--proxy", &endpoint.proxy_url()])
                .args(["--noproxy", ""])
                .stdin_bytes(proxy_config(&endpoint.token));
        }
        Route::Direct { .. } => cmd = cmd.args(["--proxy", "", "--noproxy", "*"]),
    }
    if let Some(ca) = req.ca {
        cmd = cmd.arg("--cacert").arg(path_arg(ca)?);
    }
    if let Route::Direct {
        connect_to: Some((host, port)),
    } = req.route
    {
        cmd = cmd
            .arg("--connect-to")
            .arg(connect_to(req.url, host, port)?);
    }
    if req.range > 0 {
        cmd = cmd.arg("--range").arg(format!("0-{}", req.range - 1));
    }
    if let Some(payload) = files.payload.filter(|_| req.upload > 0) {
        cmd = cmd
            .args(["--request", "POST"])
            .args(["--header", "Content-Type: application/octet-stream"])
            .args(["--header", "Expect:", "--data-binary"])
            .arg(format!("@{}", path_arg(payload)?));
    }
    Ok(cmd.args(["--output", files.body, "--url", req.url.as_str()]))
}

/// curl config read from stdin: the SOCKS login (a hex token needs no
/// escaping inside the quotes).
fn proxy_config(token: &str) -> Vec<u8> {
    format!("proxy-user = \"{USERNAME}:{token}\"\n").into_bytes()
}

fn path_arg(path: &Path) -> Result<&str> {
    path.to_str()
        .ok_or_else(|| Error::msg(format!("路径必须是 UTF-8: {}", path.display())))
}

/// `--connect-to URLHOST:URLPORT:HOST:PORT`, IPv6 hosts bracketed.
fn connect_to(url: &TestUrl, host: &str, port: u16) -> Result<String> {
    ensure!(
        !host.is_empty() && !host.bytes().any(|b| b <= b' ' || b == 0x7f),
        "直连目标地址无效"
    );
    let bracket = |h: &str| {
        if h.contains(':') {
            format!("[{h}]")
        } else {
            h.to_owned()
        }
    };
    Ok(format!(
        "{}:{}:{}:{port}",
        bracket(url.host()),
        url.port(),
        bracket(host)
    ))
}

/// curl's `--write-out` record.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct CurlStats {
    pub status: u16,
    /// Seconds until the transfer could start (proxy path + target TLS).
    pub setup: f64,
    pub ttfb: f64,
    pub duration: f64,
    pub sent: u64,
}

/// The last `ONEBOX_STATS:` line of curl's stderr.
pub fn parse_stats(stderr: &str) -> Result<CurlStats> {
    let record = stderr
        .lines()
        .rev()
        .find_map(|line| line.strip_prefix(STATS_PREFIX))
        .ok_or_else(|| Error::msg("HTTP 请求没有返回统计"))?;
    parse_record(record).ok_or_else(|| Error::msg("HTTP 请求统计无效"))
}

/// The record is not strict JSON: curl prints a missing response code as
/// `000` (v2 then reported every connection failure as an invalid record
/// instead of a failed request). Every field is required.
fn parse_record(record: &str) -> Option<CurlStats> {
    let body = record.trim().strip_prefix('{')?.strip_suffix('}')?;
    let mut fields = std::collections::HashMap::new();
    for pair in body.split(',') {
        let (key, value) = pair.split_once(':')?;
        fields.insert(key.trim().trim_matches('"'), value.trim());
    }
    let number = |key: &str| fields.get(key).and_then(|v| v.parse::<f64>().ok());
    Some(CurlStats {
        status: fields.get("status")?.parse().ok()?,
        setup: number("setup")?,
        ttfb: number("ttfb")?,
        duration: number("duration")?,
        sent: fields.get("sent")?.parse().ok()?,
    })
}

/// What the body sink read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BodyRead {
    /// Measured bytes (0 for a request without a range).
    pub received: u64,
    pub sha256: String,
    /// The reader stopped deliberately — at the range, or after the first
    /// chunk of an unmeasured body — and closed its end, so curl may fail
    /// its next write with exit 23.
    pub capped: bool,
}

impl BodyRead {
    fn empty() -> BodyRead {
        BodyRead {
            received: 0,
            sha256: sha256_hex(b""),
            capped: false,
        }
    }
}

/// Read at most `limit` bytes, hashing them.
pub fn read_capped(mut reader: impl Read, limit: u64) -> io::Result<BodyRead> {
    let mut hash = Sha256::new();
    let mut received = 0u64;
    let mut chunk = vec![0u8; READ_CHUNK];
    while received < limit {
        let want = (limit - received).min(READ_CHUNK as u64) as usize;
        let n = match reader.read(&mut chunk[..want]) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        hash.update(&chunk[..n]);
        received += n as u64;
    }
    Ok(BodyRead {
        received,
        sha256: crate::sys::rand::to_hex(&hash.finalize()),
        capped: limit > 0 && received == limit,
    })
}

/// Read the first chunk curl writes (at most [`DISCARD_CAP`] bytes) without
/// measuring it, then stop: the body of a request without a range.
/// `capped` is set when a chunk arrived (curl may then hit the closed end);
/// end of file before any byte (no body) leaves it unset.
pub fn discard_first_chunk(mut reader: impl Read) -> io::Result<BodyRead> {
    let mut chunk = vec![0u8; DISCARD_CAP];
    loop {
        match reader.read(&mut chunk) {
            Ok(n) => {
                return Ok(BodyRead {
                    capped: n > 0,
                    ..BodyRead::empty()
                })
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
}

/// The explicit cap rule: exit 0 is success; exit 23 only when the sink
/// stopped deliberately (see [`BodyRead::capped`]); anything else failed.
pub fn check_exit(code: i32, body: &BodyRead) -> Result<()> {
    match code {
        0 => Ok(()),
        CURL_WRITE_ERROR if body.capped => Ok(()),
        _ => bail!("HTTP 请求失败（连接、TLS 或超时，curl 退出码 {code}）"),
    }
}

/// Last `Location` header of a `--dump-header` file (all responses are
/// dumped; a redirect is never followed, so the last one is ours).
pub fn location(headers: &str) -> String {
    headers
        .lines()
        .rev()
        .find_map(|line| {
            line.split_once(':')
                .filter(|(name, _)| name.eq_ignore_ascii_case("location"))
                .map(|(_, value)| value.trim().to_owned())
        })
        .unwrap_or_default()
}

/// Combine curl's record with what the sink read.
pub fn result(stats: &CurlStats, body: BodyRead, location: String) -> HttpResult {
    let duration = stats.duration.max(1e-9);
    let mbps = |bytes: u64| round3(bytes as f64 * 8.0 / duration / 1e6);
    HttpResult {
        ok: (200..300).contains(&stats.status),
        status: stats.status,
        setup_ms: round3(stats.setup * 1000.0),
        ttfb_ms: round3(stats.ttfb * 1000.0),
        total_ms: round3(stats.duration * 1000.0),
        download_mbps: mbps(body.received),
        upload_mbps: mbps(stats.sent),
        received_bytes: body.received,
        sent_bytes: stats.sent,
        body_sha256: body.sha256,
        location,
    }
}

/// Run one measurement. Timeouts and cancellation kill curl's process
/// group (`HTTP 请求超时或已取消`).
pub fn measure(ctx: &Ctx, req: &HttpRequest, cancel: &CancelToken) -> Result<HttpResult> {
    let work = TempDir::new("http")?;
    let payload = match req.upload {
        0 => None,
        bytes => Some(write_payload(&work.join("payload"), bytes)?),
    };
    let headers = work.join("headers");
    // Declared before the run so it outlives the child (see `BodySink`).
    let sink = BodySink::open(req.range)?;
    let cmd = curl_command(
        req,
        &CurlFiles {
            headers: &headers,
            body: sink.target(),
            payload: payload.as_deref(),
        },
    )?;
    let limit = Duration::from_secs(req.timeout_secs) + KILL_SLACK;
    let output = wait_curl(ctx, &cmd, limit, cancel);
    let body = sink.finish()?;
    let output = output?;
    let stats = parse_stats(&output.stderr)?;
    check_exit(output.code, &body)?;
    let headers = read_bounded(&headers, MAX_HEADER_BYTES).unwrap_or_default();
    Ok(result(
        &stats,
        body,
        location(&String::from_utf8_lossy(&headers)),
    ))
}

/// [`measure`] with the error kept as text (v2 `safe_request`).
pub fn safe_measure(ctx: &Ctx, req: &HttpRequest, cancel: &CancelToken) -> Measurement {
    match measure(ctx, req, cancel) {
        Ok(result) => Measurement::Done(result),
        Err(e) => Measurement::Failed(e.to_string()),
    }
}

/// Spawn curl and wait until it exits; past `limit` or on cancellation its
/// group is terminated (and reaped) before the error is returned.
fn wait_curl(ctx: &Ctx, cmd: &Cmd, limit: Duration, cancel: &CancelToken) -> Result<Output> {
    let mut child = ctx.exec.spawn(cmd)?;
    let deadline = Instant::now() + limit;
    loop {
        if let Some(output) = child.wait_timeout(POLL)? {
            return Ok(output);
        }
        if cancel.is_cancelled() || Instant::now() >= deadline {
            let _ = child.terminate(KILL_GRACE);
            bail!("HTTP 请求超时或已取消");
        }
    }
}

/// `bytes` random bytes for an upload: one 64 KiB block repeated (v2),
/// written to a new 0600 file.
fn write_payload(path: &Path, bytes: u64) -> Result<PathBuf> {
    let block = OsRandom.bytes(PAYLOAD_BLOCK)?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|e| Error::io(path, e))?;
    let mut remaining = bytes;
    while remaining > 0 {
        let n = remaining.min(PAYLOAD_BLOCK as u64) as usize;
        file.write_all(&block[..n])
            .map_err(|e| Error::io(path, e))?;
        remaining -= n as u64;
    }
    Ok(path.to_path_buf())
}

/// Where curl writes the body: an anonymous pipe that curl opens by its
/// procfs name (`/proc/<our pid>/fd/<write end>`; our descriptors are
/// close-on-exec, so nothing is inherited). A thread reads at most `range`
/// bytes, or one unmeasured chunk without a range, then closes the read
/// end. Our own write end stays open until curl is gone, so the reader
/// cannot see a premature end of file (and curl's open of the write end,
/// which needs a reader, never blocks: the reader closes only after curl
/// wrote); [`BodySink::finish`] drops it, which gives a reader still
/// waiting (no body) its end of file. Invariant: the child must be reaped
/// before the sink is finished or dropped (else the join would wait for
/// curl), which `measure` guarantees by declaring the sink first.
///
/// `/dev/null` is not an option: curl would download a large or endless
/// body until `--max-time` and fail (D-8.1#4).
struct BodySink {
    target: String,
    writer: Option<PipeWriter>,
    reader: Option<JoinHandle<io::Result<BodyRead>>>,
}

impl BodySink {
    fn open(range: u64) -> Result<BodySink> {
        let (reader, writer): (PipeReader, PipeWriter) = io::pipe()?;
        let target = format!("/proc/{}/fd/{}", std::process::id(), writer.as_raw_fd());
        // The OS may refuse a thread (pids limit): fail this measurement
        // only, never panic.
        let reader = std::thread::Builder::new()
            .name("onebox-http-body".into())
            .spawn(move || match range {
                0 => discard_first_chunk(reader),
                limit => read_capped(reader, limit),
            })
            .map_err(|e| Error::msg(format!("无法创建 HTTP 读取线程: {e}")))?;
        Ok(BodySink {
            target,
            writer: Some(writer),
            reader: Some(reader),
        })
    }

    fn target(&self) -> &str {
        &self.target
    }

    fn finish(mut self) -> Result<BodyRead> {
        self.close().unwrap_or_else(|| Ok(BodyRead::empty()))
    }

    /// Drop our write end and collect the reader (once).
    fn close(&mut self) -> Option<Result<BodyRead>> {
        drop(self.writer.take());
        let handle = self.reader.take()?;
        Some(match handle.join() {
            Ok(Ok(body)) => Ok(body),
            Ok(Err(e)) => Err(Error::from(e).wrap("HTTP 响应读取失败")),
            Err(_) => Err(Error::msg("HTTP 响应读取失败")),
        })
    }
}

impl Drop for BodySink {
    fn drop(&mut self) {
        let _ = self.close();
    }
}

#[cfg(test)]
mod tests;
