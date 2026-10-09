//! http_probe against the real curl on PATH (skipped without it).

use super::*;
use crate::linktools::testutil::have;
use std::net::{Ipv4Addr, TcpListener, TcpStream};
use std::thread;

fn real_ctx() -> (TempDir, Ctx) {
    let dir = TempDir::new("linktools-test").unwrap();
    let mut ctx = Ctx::test(dir.path()).0;
    ctx.exec = std::sync::Arc::new(crate::sys::exec::SystemExec);
    (dir, ctx)
}

fn local_url(port: u16, path: &str) -> TestUrl {
    url(&format!("http://127.0.0.1:{port}{path}"))
}

/// Serve `responses` one connection each (head written, then the body).
fn serve(responses: Vec<(String, usize)>) -> (u16, thread::JoinHandle<()>) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    let worker = thread::spawn(move || {
        for (head, body) in responses {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            let mut raw = vec![0; 8192];
            let _ = stream.read(&mut raw);
            let _ = stream.write_all(head.as_bytes());
            let _ = stream.write_all(&vec![b'x'; body]);
        }
    });
    (port, worker)
}

#[test]
fn real_curl_caps_bodies_and_reports_status() {
    if !have("curl") {
        return;
    }
    let (_dir, ctx) = real_ctx();
    let head = |code| {
        format!("HTTP/1.1 {code} Test\r\nContent-Length: 200000\r\nConnection: close\r\n\r\n")
    };
    let (port, worker) = serve(vec![(head(200), 200_000), (head(503), 200_000)]);
    let u = local_url(port, "/");
    let req = HttpRequest {
        url: &u,
        route: Route::Direct { connect_to: None },
        timeout_secs: 3,
        ca: None,
        range: 1024,
        upload: 0,
    };
    let cancel = CancelToken::manual();
    let capped = measure(&ctx, &req, &cancel).unwrap();
    assert_eq!((capped.ok, capped.received_bytes), (true, 1024));
    assert_eq!(capped.body_sha256, sha256_hex(&[b'x'; 1024]));
    let health = measure(&ctx, &HttpRequest { range: 0, ..req }, &cancel).unwrap();
    assert_eq!((health.ok, health.status), (false, 503));
    worker.join().unwrap();
}

/// A 2xx health response with a huge or endless body ends right after
/// the first chunk (v2 closed the pipe at once; `/dev/null` would have
/// downloaded until `--max-time` and failed).
#[test]
fn real_curl_health_checks_do_not_download_the_body() {
    if !have("curl") {
        return;
    }
    let (_dir, ctx) = real_ctx();
    let head = "HTTP/1.1 200 OK\r\nContent-Length: 10485760\r\nConnection: close\r\n\r\n";
    let (port, worker) = serve(vec![(head.into(), 10 * 1024 * 1024)]);
    let u = local_url(port, "/");
    let req = HttpRequest {
        url: &u,
        route: Route::Direct { connect_to: None },
        timeout_secs: 2,
        ca: None,
        range: 0,
        upload: 0,
    };
    let started = Instant::now();
    let r = measure(&ctx, &req, &CancelToken::manual()).unwrap();
    assert!(
        started.elapsed() < Duration::from_millis(1500),
        "{:?}",
        started.elapsed()
    );
    assert_eq!((r.ok, r.status, r.received_bytes), (true, 200, 0));
    worker.join().unwrap();

    // An endless trickle (a streaming endpoint): 1 KiB every 20 ms.
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    let trickle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut raw = [0; 4096];
        let _ = stream.read(&mut raw);
        let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n");
        let started = Instant::now();
        while started.elapsed() < Duration::from_secs(10) {
            if stream.write_all(&[b'y'; 1024]).is_err() {
                return;
            }
            thread::sleep(Duration::from_millis(20));
        }
        panic!("curl kept reading the endless body");
    });
    let u = local_url(port, "/stream");
    let started = Instant::now();
    let r = measure(
        &ctx,
        &HttpRequest { url: &u, ..req },
        &CancelToken::manual(),
    )
    .unwrap();
    assert!(
        started.elapsed() < Duration::from_millis(1500),
        "{:?}",
        started.elapsed()
    );
    assert!(r.ok);
    trickle.join().unwrap();
}

#[test]
fn real_curl_obeys_the_total_deadline_for_slow_headers() {
    if !have("curl") {
        return;
    }
    let (_dir, ctx) = real_ctx();
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    let worker = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut raw = [0; 4096];
        let _ = stream.read(&mut raw);
        let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nX-Slow: ");
        for _ in 0..30 {
            if stream.write_all(b"x").is_err() {
                break;
            }
            thread::sleep(Duration::from_millis(100));
        }
    });
    let u = local_url(port, "/");
    let req = HttpRequest {
        url: &u,
        route: Route::Direct { connect_to: None },
        timeout_secs: 1,
        ca: None,
        range: 0,
        upload: 0,
    };
    let started = Instant::now();
    assert!(measure(&ctx, &req, &CancelToken::manual()).is_err());
    assert!(started.elapsed() < Duration::from_secs(3));
    worker.join().unwrap();
}

#[test]
fn real_curl_uploads_the_exact_size() {
    if !have("curl") {
        return;
    }
    let (_dir, ctx) = real_ctx();
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    let worker = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let head = read_head(&mut stream);
        assert!(head.starts_with("POST /upload HTTP/1.1\r\n"), "{head}");
        let length = header_value(&head, "content-length")
            .parse::<usize>()
            .unwrap();
        assert_eq!(length, 4096);
        let mut payload = vec![0; length];
        stream.read_exact(&mut payload).unwrap();
        stream
            .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            .unwrap();
    });
    let u = local_url(port, "/upload");
    let req = HttpRequest {
        url: &u,
        route: Route::Direct { connect_to: None },
        timeout_secs: 3,
        ca: None,
        range: 0,
        upload: 4096,
    };
    let r = measure(&ctx, &req, &CancelToken::manual()).unwrap();
    assert_eq!((r.ok, r.sent_bytes), (true, 4096));
    worker.join().unwrap();
}

fn read_head(stream: &mut TcpStream) -> String {
    let mut head = Vec::new();
    let mut byte = [0; 1];
    while !head.ends_with(b"\r\n\r\n") {
        stream.read_exact(&mut byte).unwrap();
        head.push(byte[0]);
        assert!(head.len() < 8192);
    }
    String::from_utf8(head).unwrap()
}

fn header_value(head: &str, name: &str) -> String {
    head.lines()
        .find_map(|line| {
            line.split_once(':')
                .filter(|(n, _)| n.eq_ignore_ascii_case(name))
                .map(|(_, v)| v.trim().to_owned())
        })
        .unwrap_or_default()
}

/// A one-shot SOCKS5 server that requires the `onebox-` login and then
/// tunnels to the requested target: proves curl got the credential from
/// stdin and that names reach the proxy unresolved.
#[test]
fn real_curl_logs_in_to_the_proxy_from_stdin() {
    if !have("curl") {
        return;
    }
    let (_dir, ctx) = real_ctx();
    let (origin, origin_worker) = serve(vec![(
        "HTTP/1.1 200 OK\r\nContent-Length: 8\r\nConnection: close\r\n\r\n".into(),
        8,
    )]);
    let token = "cd".repeat(24);
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let ep = SocksEndpoint {
        port: listener.local_addr().unwrap().port(),
        token: token.clone(),
    };
    let proxy = thread::spawn(move || {
        let (mut client, _) = listener.accept().unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let mut greeting = [0u8; 2];
        client.read_exact(&mut greeting).unwrap();
        let mut methods = vec![0u8; usize::from(greeting[1])];
        client.read_exact(&mut methods).unwrap();
        assert!(greeting[0] == 5 && methods.contains(&2), "{methods:?}");
        client.write_all(&[5, 2]).unwrap();
        let mut head = [0u8; 2];
        client.read_exact(&mut head).unwrap();
        let mut user = vec![0u8; usize::from(head[1])];
        client.read_exact(&mut user).unwrap();
        let mut len = [0u8; 1];
        client.read_exact(&mut len).unwrap();
        let mut password = vec![0u8; usize::from(len[0])];
        client.read_exact(&mut password).unwrap();
        assert_eq!(
            (user.as_slice(), password),
            (&b"onebox-"[..], token.into_bytes())
        );
        client.write_all(&[1, 0]).unwrap();
        let mut request = [0u8; 4];
        client.read_exact(&mut request).unwrap();
        let host = crate::linktools::socks::read_address(&mut client, request[3]).unwrap();
        let mut port = [0u8; 2];
        client.read_exact(&mut port).unwrap();
        assert_eq!(
            host, "localhost",
            "socks5h: the name is not resolved by curl"
        );
        let mut upstream =
            TcpStream::connect((Ipv4Addr::LOCALHOST, u16::from_be_bytes(port))).unwrap();
        client
            .write_all(&crate::linktools::socks::REPLY_SUCCEEDED)
            .unwrap();
        let mut down = upstream.try_clone().unwrap();
        let mut up_client = client.try_clone().unwrap();
        let pump = thread::spawn(move || io::copy(&mut down, &mut up_client));
        let _ = io::copy(&mut client, &mut upstream);
        let _ = pump.join();
    });
    let u = url(&format!("http://localhost:{origin}/"));
    let req = HttpRequest {
        url: &u,
        route: Route::Proxy(&ep),
        timeout_secs: 3,
        ca: None,
        range: 1024,
        upload: 0,
    };
    let r = measure(&ctx, &req, &CancelToken::manual()).unwrap();
    assert!(r.ok);
    assert_eq!(r.received_bytes, 8);
    assert_eq!(r.body_sha256, sha256_hex(b"xxxxxxxx"));
    origin_worker.join().unwrap();
    proxy.join().unwrap();
}
