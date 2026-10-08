use super::*;
use crate::linktools::testutil::{arg_after, curl_stats, have};
use crate::sys::exec::{FakeLife, Stdin};
use std::io::Cursor;
use std::net::{Ipv4Addr, TcpListener, TcpStream};
use std::thread;

fn url(text: &str) -> TestUrl {
    TestUrl::parse(text).unwrap()
}

fn endpoint() -> SocksEndpoint {
    SocksEndpoint {
        port: 40123,
        token: "ab".repeat(24),
    }
}

fn files<'a>(body: &'a str, payload: Option<&'a Path>) -> CurlFiles<'a> {
    CurlFiles {
        headers: Path::new("/w/headers"),
        body,
        payload,
    }
}

fn base_args() -> Vec<&'static str> {
    vec![
        "-q",
        "--silent",
        "--http1.1",
        "--proto",
        "=http,https",
        "--max-redirs",
        "0",
        "--connect-timeout",
        "8",
        "--max-time",
        "8",
        "--header",
        "Accept-Encoding: identity",
        "--header",
        "Connection: close",
        "--user-agent",
        "onebox-probe/2",
        "--dump-header",
        "/w/headers",
        "--write-out",
        WRITE_OUT,
    ]
}

#[test]
fn proxied_requests_keep_the_credential_off_argv() {
    let u = url("https://www.gstatic.com/generate_204");
    let ep = endpoint();
    let req = HttpRequest {
        url: &u,
        route: Route::Proxy(&ep),
        timeout_secs: 8,
        ca: None,
        limit: 1024,
        upload: 0,
    };
    let cmd = curl_command(&req, &files("/proc/1/fd/5", None)).unwrap();
    let mut expected = base_args();
    expected.extend([
        "--config",
        "-",
        "--proxy",
        "socks5h://127.0.0.1:40123",
        "--noproxy",
        "",
        "--range",
        "0-1023",
        "--output",
        "/proc/1/fd/5",
        "--url",
        "https://www.gstatic.com/generate_204",
    ]);
    assert_eq!(cmd.program, "curl");
    assert_eq!(cmd.args, expected);
    assert!(!cmd.display().contains(&ep.token));
    let config = format!("proxy-user = \"onebox-:{}\"\n", ep.token);
    assert_eq!(cmd.stdin, Stdin::Bytes(config.into_bytes()));
}

#[test]
fn direct_requests_pin_the_target_and_ignore_proxy_env() {
    let u = url("https://www.example.com/");
    let req = HttpRequest {
        url: &u,
        route: Route::Direct {
            connect_to: Some(("2001:db8::1", 8443)),
        },
        timeout_secs: 3,
        ca: Some(Path::new("/etc/ca.pem")),
        limit: 0,
        upload: 0,
    };
    let cmd = curl_command(&req, &files(DISCARD, None)).unwrap();
    let mut expected = base_args();
    expected[8] = "3";
    expected[10] = "3";
    expected.extend([
        "--proxy",
        "",
        "--noproxy",
        "*",
        "--cacert",
        "/etc/ca.pem",
        "--connect-to",
        "www.example.com:443:[2001:db8::1]:8443",
        "--output",
        "/dev/null",
        "--url",
        "https://www.example.com/",
    ]);
    assert_eq!(cmd.args, expected);
    assert_eq!(cmd.stdin, Stdin::Null);
    for bad in ["", "a b", "x\u{7f}"] {
        let req = HttpRequest {
            route: Route::Direct {
                connect_to: Some((bad, 1)),
            },
            ..req
        };
        let err = curl_command(&req, &files(DISCARD, None)).unwrap_err();
        assert_eq!(err.to_string(), "直连目标地址无效", "{bad:?}");
    }
}

#[test]
fn uploads_post_the_payload_file() {
    let u = url("http://[::1]:8080/upload");
    let req = HttpRequest {
        url: &u,
        route: Route::Direct { connect_to: None },
        timeout_secs: 8,
        ca: None,
        limit: 0,
        upload: 4096,
    };
    let cmd = curl_command(&req, &files(DISCARD, Some(Path::new("/w/payload")))).unwrap();
    let tail: Vec<&str> = cmd.args.iter().skip(25).map(String::as_str).collect();
    assert_eq!(
        tail,
        [
            "--request",
            "POST",
            "--header",
            "Content-Type: application/octet-stream",
            "--header",
            "Expect:",
            "--data-binary",
            "@/w/payload",
            "--output",
            "/dev/null",
            "--url",
            "http://[::1]:8080/upload"
        ]
    );
}

#[test]
fn stats_come_from_the_last_record() {
    let stderr = format!(
        "noise\n{}{}",
        curl_stats(301, 0.1, 0.2, 0.3, 0),
        curl_stats(204, 0.151234, 0.1804, 0.25, 7)
    );
    let stats = parse_stats(&stderr).unwrap();
    assert_eq!(
        stats,
        CurlStats {
            status: 204,
            setup: 0.151234,
            ttfb: 0.1804,
            duration: 0.25,
            sent: 7
        }
    );
    // A connection failure: curl pads the missing response code.
    let failed = "ONEBOX_STATS:{\"status\":000,\"setup\":0.000000,\"ttfb\":0.000000,\"duration\":0.000171,\"sent\":0}";
    let stats = parse_stats(failed).unwrap();
    assert_eq!((stats.status, stats.duration), (0, 0.000171));
    for (text, message) in [
        ("", "HTTP 请求没有返回统计"),
        ("ONEBOX_STATS:{bad", "HTTP 请求统计无效"),
        ("ONEBOX_STATS:{\"status\":200}", "HTTP 请求统计无效"),
        (
            "ONEBOX_STATS:{\"status\":-1,\"setup\":0,\"ttfb\":0,\"duration\":0,\"sent\":0}",
            "HTTP 请求统计无效",
        ),
    ] {
        assert_eq!(parse_stats(text).unwrap_err().to_string(), message);
    }
}

#[test]
fn the_reader_stops_exactly_at_the_cap() {
    let data = vec![b'x'; 200_000];
    let cases = [
        (0u64, 0u64, false),
        (1024, 1024, true),
        (200_000, 200_000, true),
        (300_000, 200_000, false),
    ];
    for (limit, received, capped) in cases {
        let body = read_capped(Cursor::new(&data), limit).unwrap();
        assert_eq!((body.received, body.capped), (received, capped), "{limit}");
        let expected = sha256_hex(&data[..received as usize]);
        assert_eq!(body.sha256, expected);
    }
}

#[test]
fn exit_23_counts_only_at_the_cap() {
    let capped = BodyRead {
        received: 10,
        sha256: String::new(),
        capped: true,
    };
    let open = BodyRead {
        capped: false,
        ..capped.clone()
    };
    assert!(check_exit(0, &open).is_ok());
    assert!(check_exit(CURL_WRITE_ERROR, &capped).is_ok());
    let err = check_exit(CURL_WRITE_ERROR, &open).unwrap_err();
    assert_eq!(
        err.to_string(),
        "HTTP 请求失败（连接、TLS 或超时，curl 退出码 23）"
    );
    assert!(check_exit(7, &capped).is_err());
    assert!(check_exit(28, &open).is_err());
}

#[test]
fn location_is_the_last_header_of_its_name() {
    let headers = "HTTP/1.1 301 Moved\r\nLocation: /first\r\n\r\nHTTP/1.1 302 Found\r\nlocation:  https://x/y \r\nX: 1\r\n";
    assert_eq!(location(headers), "https://x/y");
    assert_eq!(location("HTTP/1.1 200 OK\r\n"), "");
}

#[test]
fn results_round_like_v2() {
    let stats = CurlStats {
        status: 206,
        setup: 0.16,
        ttfb: 0.19,
        duration: 0.812,
        sent: 0,
    };
    let body = BodyRead {
        received: 4_194_304,
        sha256: "h".into(),
        capped: true,
    };
    let r = result(&stats, body, String::new());
    assert!(r.ok);
    assert_eq!(
        (
            r.setup_ms,
            r.ttfb_ms,
            r.total_ms,
            r.download_mbps,
            r.upload_mbps
        ),
        (160.0, 190.0, 812.0, 41.323, 0.0)
    );
    let zero = CurlStats {
        status: 0,
        duration: 0.0,
        ..stats
    };
    let r = result(&zero, BodyRead::empty(), String::new());
    assert!(!r.ok);
    assert_eq!(r.download_mbps, 0.0);
    assert_eq!(
        r.body_sha256,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
    let keys: Vec<String> = match serde_json::to_value(&r).unwrap() {
        serde_json::Value::Object(map) => map.keys().cloned().collect(),
        _ => unreachable!(),
    };
    assert_eq!(
        keys,
        [
            "body_sha256",
            "download_mbps",
            "location",
            "ok",
            "received_bytes",
            "sent_bytes",
            "setup_ms",
            "status",
            "total_ms",
            "ttfb_ms",
            "upload_mbps"
        ]
    );
}

fn fake_ctx() -> (TempDir, Ctx, std::sync::Arc<crate::sys::exec::FakeExec>) {
    let dir = TempDir::new("linktools-test").unwrap();
    let (ctx, exec, _) = Ctx::test(dir.path());
    (dir, ctx, exec)
}

#[test]
fn scripted_measurements() {
    let (_dir, ctx, exec) = fake_ctx();
    exec.on_fn(
        |cmd| cmd.program == "curl" && cmd.args.last().is_some_and(|u| u.ends_with("/ok")),
        |_| {
            Ok(Output {
                code: 0,
                stdout: String::new(),
                stderr: curl_stats(204, 0.1, 0.2, 0.3, 0),
            })
        },
    )
    .on_fn(
        |cmd| cmd.args.last().is_some_and(|u| u.ends_with("/refused")),
        |_| Ok(Output::failure(7, "")),
    )
    .on_fn(
        |cmd| cmd.args.last().is_some_and(|u| u.ends_with("/silent")),
        |_| Ok(Output::success("")),
    );
    let cancel = CancelToken::manual();
    let ok_url = url("https://h/ok");
    let ep = endpoint();
    let req = HttpRequest {
        url: &ok_url,
        route: Route::Proxy(&ep),
        timeout_secs: 2,
        ca: None,
        limit: 65536,
        upload: 0,
    };
    let r = measure(&ctx, &req, &cancel).unwrap();
    assert!(r.ok && r.status == 204 && r.received_bytes == 0);
    assert_eq!(r.ttfb_ms, 200.0);
    let call = exec.calls().pop().unwrap();
    let output = arg_after(&call.args, "--output").unwrap();
    assert!(output.starts_with("/proc/") && output.contains("/fd/"));
    assert!(Measurement::Done(r.clone()).ok());
    assert_eq!(Measurement::Done(r).ok_ttfb(), Some(200.0));

    let refused = url("https://h/refused");
    let m = safe_measure(
        &ctx,
        &HttpRequest {
            url: &refused,
            ..req
        },
        &cancel,
    );
    assert_eq!(m, Measurement::Failed("HTTP 请求没有返回统计".into()));
    let silent = url("https://h/silent");
    let err = measure(
        &ctx,
        &HttpRequest {
            url: &silent,
            ..req
        },
        &cancel,
    )
    .unwrap_err();
    assert_eq!(err.to_string(), "HTTP 请求没有返回统计");
    assert!(!m.ok() && m.ok_ttfb().is_none());
}

#[test]
fn uploads_write_a_private_payload_of_the_requested_size() {
    let (_dir, ctx, exec) = fake_ctx();
    let seen = std::sync::Arc::new(std::sync::Mutex::new(None));
    let record = seen.clone();
    exec.on_fn(
        |cmd| cmd.program == "curl",
        move |cmd| {
            let file = arg_after(&cmd.args, "--data-binary").unwrap();
            let meta = std::fs::metadata(&file[1..]).unwrap();
            use std::os::unix::fs::PermissionsExt;
            *record.lock().unwrap() = Some((meta.len(), meta.permissions().mode() & 0o777));
            Ok(Output {
                code: 0,
                stdout: String::new(),
                stderr: curl_stats(204, 0.1, 0.1, 0.5, meta.len()),
            })
        },
    );
    let u = url("https://h/upload");
    let req = HttpRequest {
        url: &u,
        route: Route::Direct { connect_to: None },
        timeout_secs: 2,
        ca: None,
        limit: 0,
        upload: 100_000,
    };
    let r = measure(&ctx, &req, &CancelToken::manual()).unwrap();
    assert_eq!(*seen.lock().unwrap(), Some((100_000, 0o600)));
    assert_eq!((r.sent_bytes, r.upload_mbps), (100_000, 1.6));
}

#[test]
fn a_hanging_curl_is_killed_on_cancellation() {
    let (_dir, ctx, exec) = fake_ctx();
    exec.on_spawn("curl", &[], FakeLife::UntilKilled, Output::default());
    let cancel = CancelToken::manual();
    cancel.cancel();
    let u = url("https://h/");
    let req = HttpRequest {
        url: &u,
        route: Route::Direct { connect_to: None },
        timeout_secs: 60,
        ca: None,
        limit: 1024,
        upload: 0,
    };
    let started = Instant::now();
    let err = measure(&ctx, &req, &cancel).unwrap_err();
    assert_eq!(err.to_string(), "HTTP 请求超时或已取消");
    assert!(started.elapsed() < Duration::from_secs(5));
    assert_eq!(exec.signals().len(), 1, "terminated");
}

// ---- real curl (skipped without it) ----

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
        limit: 1024,
        upload: 0,
    };
    let cancel = CancelToken::manual();
    let capped = measure(&ctx, &req, &cancel).unwrap();
    assert_eq!((capped.ok, capped.received_bytes), (true, 1024));
    assert_eq!(capped.body_sha256, sha256_hex(&[b'x'; 1024]));
    let health = measure(&ctx, &HttpRequest { limit: 0, ..req }, &cancel).unwrap();
    assert_eq!((health.ok, health.status), (false, 503));
    worker.join().unwrap();
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
        limit: 0,
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
        limit: 0,
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
        limit: 1024,
        upload: 0,
    };
    let r = measure(&ctx, &req, &CancelToken::manual()).unwrap();
    assert!(r.ok);
    assert_eq!(r.received_bytes, 8);
    assert_eq!(r.body_sha256, sha256_hex(b"xxxxxxxx"));
    origin_worker.join().unwrap();
    proxy.join().unwrap();
}
