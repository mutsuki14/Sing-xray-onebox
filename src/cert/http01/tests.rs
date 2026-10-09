use super::*;
use crate::sys::fs::TempDir;
use std::net::Shutdown;

fn webroot_with(token: &str, body: &str) -> TempDir {
    let dir = TempDir::new("http01").unwrap();
    let challenges = dir.join(".well-known/acme-challenge");
    std::fs::create_dir_all(&challenges).unwrap();
    std::fs::write(challenges.join(token), body).unwrap();
    dir
}

fn text(bytes: Vec<u8>) -> String {
    String::from_utf8(bytes).unwrap()
}

#[test]
fn serves_only_challenge_files() {
    let root = webroot_with("tok-EN_1", "tok-EN_1.thumb");
    let ok = text(respond(
        root.path(),
        "GET",
        "/.well-known/acme-challenge/tok-EN_1",
    ));
    assert!(ok.starts_with("HTTP/1.1 200 OK\r\n"), "{ok}");
    assert!(ok.contains("Content-Length: 14\r\n"));
    assert!(ok.ends_with("\r\n\r\ntok-EN_1.thumb"));
    let head = text(respond(
        root.path(),
        "HEAD",
        "/.well-known/acme-challenge/tok-EN_1",
    ));
    assert!(head.starts_with("HTTP/1.1 200 OK") && head.ends_with("\r\n\r\n"));
    assert!(head.contains("Content-Length: 14\r\n"));
    for (method, path) in [
        ("POST", "/.well-known/acme-challenge/tok-EN_1"),
        ("GET", "/.well-known/acme-challenge/missing"),
        ("GET", "/.well-known/acme-challenge/"),
        ("GET", "/.well-known/acme-challenge/../../etc/passwd"),
        ("GET", "/.well-known/acme-challenge/tok-EN_1?x=1"),
        ("GET", "/.well-known/acme-challenge/a/b"),
        ("GET", "/index.html"),
        ("GET", "/"),
    ] {
        let reply = text(respond(root.path(), method, path));
        assert!(
            reply.starts_with("HTTP/1.1 404 Not Found\r\n"),
            "{method} {path}"
        );
    }
}

#[test]
fn symlinked_and_large_challenge_files_are_refused() {
    let root = webroot_with("big", &"x".repeat(17 * 1024));
    let challenges = root.join(".well-known/acme-challenge");
    std::os::unix::fs::symlink("/etc/hostname", challenges.join("link")).unwrap();
    for token in ["big", "link"] {
        let path = format!("/.well-known/acme-challenge/{token}");
        assert!(
            text(respond(root.path(), "GET", &path)).contains("404"),
            "{token}"
        );
    }
}

fn get(port: u16, request: &str) -> String {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    stream.write_all(request.as_bytes()).unwrap();
    let mut reply = String::new();
    stream.read_to_string(&mut reply).unwrap();
    reply
}

#[test]
fn answers_real_connections_and_stops_cleanly() {
    let root = webroot_with("abc", "abc.key");
    // "/" as the system root: the host's real IPv6 facts (dual-stack or v4).
    // A port outside the ephemeral range, which no parallel test binding
    // port 0 can take over once it is released.
    let wanted = crate::cert::testing::free_port();
    let responder = Responder::start(root.path(), wanted, Path::new("/")).unwrap();
    let port = responder.port();
    assert_eq!(port, wanted);
    let reply = get(
        port,
        "GET /.well-known/acme-challenge/abc HTTP/1.1\r\nHost: a.example.com\r\n\r\n",
    );
    assert!(
        reply.starts_with("HTTP/1.1 200 OK") && reply.ends_with("abc.key"),
        "{reply}"
    );
    let reply = get(port, "GET /secret HTTP/1.1\r\nHost: x\r\n\r\n");
    assert!(reply.starts_with("HTTP/1.1 404"), "{reply}");
    // Garbage and early hang-ups get no response and do not hurt.
    assert_eq!(get(port, "\x00\x01 garbage\r\n\r\n"), "");
    let hangup = TcpStream::connect(("127.0.0.1", port)).unwrap();
    hangup.shutdown(Shutdown::Both).unwrap();
    // A second responder cannot take the same port.
    let err = Responder::start(root.path(), port, Path::new("/"))
        .err()
        .unwrap();
    assert!(err.to_string().starts_with(PORT_BUSY), "{err}");
    responder.stop();
    // A child another test forks at that moment holds a copy of the socket
    // until it execs (close-on-exec): the port is released very soon, not
    // necessarily at once.
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while TcpStream::connect(("127.0.0.1", port)).is_ok() {
        assert!(std::time::Instant::now() < deadline, "port released");
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn ipv4_only_hosts_bind_one_listener() {
    let root = webroot_with("t", "t.k");
    let fixture = TempDir::new("http01-noipv6").unwrap();
    let responder = Responder::start(root.path(), 0, fixture.path()).unwrap();
    let reply = get(
        responder.port(),
        "HEAD /.well-known/acme-challenge/t HTTP/1.0\r\n\r\n",
    );
    assert!(
        reply.starts_with("HTTP/1.1 200 OK") && reply.ends_with("\r\n\r\n"),
        "{reply}"
    );
    drop(responder);
}

/// One request on a fresh connection: whatever arrives (empty when the
/// connection is closed or reset without a response).
fn try_get(port: u16, request: &str) -> String {
    let Ok(mut stream) = TcpStream::connect(("127.0.0.1", port)) else {
        return String::new();
    };
    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
    let _ = stream.write_all(request.as_bytes());
    let mut reply = Vec::new();
    let _ = stream.read_to_end(&mut reply);
    String::from_utf8_lossy(&reply).into_owned()
}

#[test]
fn trickling_clients_cannot_hold_every_slot() {
    let root = webroot_with("tok", "tok.key");
    let fixture = TempDir::new("http01-trickle").unwrap();
    let limits = Limits {
        head: Duration::from_millis(300),
        write: Duration::from_millis(300),
    };
    let responder = Responder::start_with(root.path(), 0, fixture.path(), limits).unwrap();
    let port = responder.port();
    // Every slot is taken by a client that never completes its head but
    // sends a byte far more often than any per-read timeout.
    let mut slow = Vec::new();
    for _ in 0..MAX_CONNECTIONS {
        let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
        stream.write_all(b"GET / HTTP/1.1\r\nX: ").unwrap();
        slow.push(stream);
    }
    let waited = Instant::now();
    while responder.active.load(Ordering::SeqCst) < MAX_CONNECTIONS {
        assert!(waited.elapsed() < Duration::from_secs(5), "slots taken");
        std::thread::sleep(POLL);
    }
    let stop = Arc::new(AtomicBool::new(false));
    let mut streams: Vec<TcpStream> = slow.iter().map(|s| s.try_clone().unwrap()).collect();
    let trickle = {
        let stop = stop.clone();
        std::thread::spawn(move || {
            while !stop.load(Ordering::SeqCst) {
                for stream in &mut streams {
                    let _ = stream.write_all(b"x");
                }
                std::thread::sleep(Duration::from_millis(50));
            }
        })
    };
    // A validation request is answered once their head deadline passed.
    let challenge = "GET /.well-known/acme-challenge/tok HTTP/1.1\r\nHost: a\r\n\r\n";
    let started = Instant::now();
    let reply = loop {
        let reply = try_get(port, challenge);
        if reply.starts_with("HTTP/1.1 200") || started.elapsed() > Duration::from_secs(4) {
            break reply;
        }
        std::thread::sleep(Duration::from_millis(100));
    };
    assert!(reply.ends_with("tok.key"), "answered: {reply:?}");
    // The trickling connections were closed by the responder, unanswered.
    let mut first = slow.swap_remove(0);
    first
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let mut rest = Vec::new();
    let closed = first.read_to_end(&mut rest);
    let timed_out =
        |e: &std::io::Error| matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut);
    assert!(
        !closed.as_ref().is_err_and(timed_out),
        "closed by the responder: {closed:?}"
    );
    assert!(rest.is_empty());
    stop.store(true, Ordering::SeqCst);
    trickle.join().unwrap();
    drop(responder);
}
