//! Bidirectional TCP relay of one failover connection with half-close
//! propagation, an idle reaper and cancellation.
//!
//! Each direction is a blocking copy on its own thread (the caller's
//! thread plus one helper), with socket timeouts of [`TICK`] so a blocked
//! read or write rechecks cancellation and idleness without polling the
//! data path. Memory is one 64 KiB buffer per direction (v2 capped its
//! buffers at 256 KiB). When one side reaches end of file the other side's
//! write half is shut down once; the relay ends when both directions are
//! done, after `idle` without progress in either direction (v2: 300 s), on
//! cancellation, or when one direction fails — then both sockets are shut
//! down so the other direction returns at once.
//!
//! Changes from v2: no non-blocking busy loop with 5 ms sleeps (up to
//! 25 600 wake-ups per second with 128 connections, D-8.1#23); the stop
//! signal is the run's `CancelToken` instead of a process-global flag.

use crate::error::{Error, Result};
use crate::linktools::cancel::CancelToken;
use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

/// How often a blocked direction rechecks cancellation and idleness.
pub const TICK: Duration = Duration::from_secs(1);
/// v2's idle reaper.
pub const IDLE: Duration = Duration::from_secs(300);
const CHUNK: usize = 64 * 1024;

/// State shared by the two directions.
struct Shared<'a> {
    started: Instant,
    /// Milliseconds since `started` of the last progress in either direction.
    last_progress: AtomicU64,
    /// Set when one direction stops the whole relay.
    stopped: AtomicBool,
    cancel: &'a CancelToken,
    idle: Duration,
}

impl Shared<'_> {
    fn touch(&self) {
        let now = self.started.elapsed().as_millis() as u64;
        self.last_progress.store(now, Ordering::SeqCst);
    }

    fn should_stop(&self) -> bool {
        // The other direction may have touched after `elapsed` was read.
        let idle_ms = (self.started.elapsed().as_millis() as u64)
            .saturating_sub(self.last_progress.load(Ordering::SeqCst));
        self.stopped.load(Ordering::SeqCst)
            || self.cancel.is_cancelled()
            || Duration::from_millis(idle_ms) >= self.idle
    }

    /// Stop both directions: shut both sockets down completely.
    fn abort(&self, a: &TcpStream, b: &TcpStream) {
        self.stopped.store(true, Ordering::SeqCst);
        let _ = a.shutdown(Shutdown::Both);
        let _ = b.shutdown(Shutdown::Both);
    }
}

fn retryable(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut | io::ErrorKind::Interrupted
    )
}

/// Relay until both sides are done (see module docs). `Ok` also covers a
/// stop by cancellation or idleness.
pub fn relay(
    client: TcpStream,
    upstream: TcpStream,
    cancel: &CancelToken,
    idle: Duration,
) -> Result<()> {
    for stream in [&client, &upstream] {
        stream.set_nonblocking(false)?;
        stream.set_read_timeout(Some(TICK))?;
        stream.set_write_timeout(Some(TICK))?;
    }
    let shared = Shared {
        started: Instant::now(),
        last_progress: AtomicU64::new(0),
        stopped: AtomicBool::new(false),
        cancel,
        idle,
    };
    std::thread::scope(|scope| {
        let back = scope.spawn(|| pump(&upstream, &client, &shared));
        let forward = pump(&client, &upstream, &shared);
        let back = back
            .join()
            .unwrap_or_else(|_| Err(Error::msg("转发线程异常退出")));
        forward.and(back)
    })
}

/// Copy `src` → `dst` until end of file (then half-close `dst`), a stop,
/// or an error (then abort both).
fn pump(src: &TcpStream, dst: &TcpStream, shared: &Shared) -> Result<()> {
    let mut buf = vec![0u8; CHUNK];
    loop {
        if shared.should_stop() {
            shared.abort(src, dst);
            return Ok(());
        }
        let n = match (&*src).read(&mut buf) {
            Ok(0) => {
                let _ = dst.shutdown(Shutdown::Write);
                return Ok(());
            }
            Ok(n) => n,
            Err(e) if retryable(&e) => continue,
            Err(e) => {
                shared.abort(src, dst);
                return Err(e.into());
            }
        };
        shared.touch();
        if let Err(e) = write_all(dst, &buf[..n], shared) {
            shared.abort(src, dst);
            return Err(e);
        }
    }
}

/// Write everything unless the relay is stopped meanwhile.
fn write_all(dst: &TcpStream, mut data: &[u8], shared: &Shared) -> Result<()> {
    while !data.is_empty() {
        if shared.should_stop() {
            return Ok(());
        }
        match (&*dst).write(data) {
            Ok(0) => bail!("转发连接已关闭"),
            Ok(n) => {
                data = &data[n..];
                shared.touch();
            }
            Err(e) if retryable(&e) => continue,
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, TcpListener};
    use std::thread;

    fn pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let one = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let two = listener.accept().unwrap().0;
        one.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        two.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        (one, two)
    }

    /// v2 `relay_propagates_half_close_and_response`.
    #[test]
    fn relay_propagates_half_close_and_response() {
        let (mut a, left) = pair();
        let (right, mut b) = pair();
        let cancel = CancelToken::manual();
        let worker = {
            let cancel = cancel.clone();
            thread::spawn(move || relay(left, right, &cancel, IDLE))
        };
        a.write_all(b"request").unwrap();
        a.shutdown(Shutdown::Write).unwrap();
        let mut request = String::new();
        b.read_to_string(&mut request).unwrap();
        assert_eq!(request, "request");
        b.write_all(b"response").unwrap();
        b.shutdown(Shutdown::Write).unwrap();
        let mut response = String::new();
        a.read_to_string(&mut response).unwrap();
        assert_eq!(response, "response");
        worker.join().unwrap().unwrap();
    }

    #[test]
    fn large_transfers_arrive_intact_both_ways() {
        let (mut a, left) = pair();
        let (right, mut b) = pair();
        let cancel = CancelToken::manual();
        let worker = thread::spawn(move || relay(left, right, &cancel, IDLE));
        let data: Vec<u8> = (0..3_000_000u32).map(|i| (i % 251) as u8).collect();
        let expected = data.clone();
        let writer = {
            let mut a = a.try_clone().unwrap();
            thread::spawn(move || {
                a.write_all(&data).unwrap();
                a.shutdown(Shutdown::Write).unwrap();
            })
        };
        let mut got = Vec::new();
        b.read_to_end(&mut got).unwrap();
        assert!(got == expected, "{} bytes", got.len());
        writer.join().unwrap();
        b.write_all(&expected[..100_000]).unwrap();
        b.shutdown(Shutdown::Write).unwrap();
        let mut back = Vec::new();
        a.read_to_end(&mut back).unwrap();
        assert_eq!(back.len(), 100_000);
        worker.join().unwrap().unwrap();
    }

    #[test]
    fn cancellation_and_idleness_end_a_silent_relay() {
        let (_a, left) = pair();
        let (right, mut b) = pair();
        let cancel = CancelToken::manual();
        let remote = cancel.clone();
        let started = Instant::now();
        let worker = thread::spawn(move || relay(left, right, &remote, IDLE));
        thread::sleep(Duration::from_millis(100));
        cancel.cancel();
        worker.join().unwrap().unwrap();
        assert!(started.elapsed() < Duration::from_secs(4));
        let mut rest = Vec::new();
        assert_eq!(b.read_to_end(&mut rest).unwrap(), 0, "upstream closed");

        let (_a, left) = pair();
        let (right, _b) = pair();
        let started = Instant::now();
        let quiet = CancelToken::manual();
        relay(left, right, &quiet, Duration::from_millis(1500)).unwrap();
        let took = started.elapsed();
        assert!(took >= Duration::from_millis(1500) && took < Duration::from_secs(5), "{took:?}");
    }

    #[test]
    fn a_reset_side_stops_the_other_direction() {
        let (a, left) = pair();
        let (right, mut b) = pair();
        let cancel = CancelToken::manual();
        let worker = thread::spawn(move || relay(left, right, &cancel, IDLE));
        // `a` closes with unread data, so the kernel resets the connection.
        b.write_all(b"never read").unwrap();
        thread::sleep(Duration::from_millis(200));
        drop(a);
        let started = Instant::now();
        let mut rest = Vec::new();
        let _ = b.read_to_end(&mut rest);
        let _ = worker.join().unwrap();
        assert!(started.elapsed() < Duration::from_secs(4));
    }
}
