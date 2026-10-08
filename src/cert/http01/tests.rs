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
    let ok = text(respond(root.path(), "GET", "/.well-known/acme-challenge/tok-EN_1"));
    assert!(ok.starts_with("HTTP/1.1 200 OK\r\n"), "{ok}");
    assert!(ok.contains("Content-Length: 14\r\n"));
    assert!(ok.ends_with("\r\n\r\ntok-EN_1.thumb"));
    let head = text(respond(root.path(), "HEAD", "/.well-known/acme-challenge/tok-EN_1"));
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
        assert!(reply.starts_with("HTTP/1.1 404 Not Found\r\n"), "{method} {path}");
    }
}

#[test]
fn symlinked_and_large_challenge_files_are_refused() {
    let root = webroot_with("big", &"x".repeat(17 * 1024));
    let challenges = root.join(".well-known/acme-challenge");
    std::os::unix::fs::symlink("/etc/hostname", challenges.join("link")).unwrap();
    for token in ["big", "link"] {
        let path = format!("/.well-known/acme-challenge/{token}");
        assert!(text(respond(root.path(), "GET", &path)).contains("404"), "{token}");
    }
}

fn get(port: u16, request: &str) -> String {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
    stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    stream.write_all(request.as_bytes()).unwrap();
    let mut reply = String::new();
    stream.read_to_string(&mut reply).unwrap();
    reply
}

#[test]
fn answers_real_connections_and_stops_cleanly() {
    let root = webroot_with("abc", "abc.key");
    // "/" as the system root: the host's real IPv6 facts (dual-stack or v4).
    let responder = Responder::start(root.path(), 0, Path::new("/")).unwrap();
    let port = responder.port();
    assert_ne!(port, 0);
    let reply = get(
        port,
        "GET /.well-known/acme-challenge/abc HTTP/1.1\r\nHost: a.example.com\r\n\r\n",
    );
    assert!(reply.starts_with("HTTP/1.1 200 OK") && reply.ends_with("abc.key"), "{reply}");
    let reply = get(port, "GET /secret HTTP/1.1\r\nHost: x\r\n\r\n");
    assert!(reply.starts_with("HTTP/1.1 404"), "{reply}");
    // Garbage and early hang-ups get no response and do not hurt.
    assert_eq!(get(port, "\x00\x01 garbage\r\n\r\n"), "");
    let hangup = TcpStream::connect(("127.0.0.1", port)).unwrap();
    hangup.shutdown(Shutdown::Both).unwrap();
    // A second responder cannot take the same port.
    let err = Responder::start(root.path(), port, Path::new("/")).err().unwrap();
    assert!(err.to_string().starts_with(PORT_BUSY), "{err}");
    responder.stop();
    assert!(TcpStream::connect(("127.0.0.1", port)).is_err(), "port released");
}

#[test]
fn ipv4_only_hosts_bind_one_listener() {
    let root = webroot_with("t", "t.k");
    let fixture = TempDir::new("http01-noipv6").unwrap();
    let responder = Responder::start(root.path(), 0, fixture.path()).unwrap();
    let reply = get(responder.port(), "HEAD /.well-known/acme-challenge/t HTTP/1.0\r\n\r\n");
    assert!(reply.starts_with("HTTP/1.1 200 OK") && reply.ends_with("\r\n\r\n"), "{reply}");
    drop(responder);
}
