use super::*;
use crate::subscription::devices::DeviceStore;
use crate::subscription::snapshot::{self, Published};
use crate::subscription::testing::{device, Node, TOKEN};
use std::io::Cursor;
use std::os::unix::net::UnixStream;
use std::time::Duration;

/// A connection over in-memory buffers.
struct Memory {
    input: Cursor<Vec<u8>>,
    output: Vec<u8>,
    /// Read at most this many bytes per call.
    chunk: usize,
}

impl Memory {
    fn new(input: &[u8], chunk: usize) -> Memory {
        Memory {
            input: Cursor::new(input.to_vec()),
            output: Vec::new(),
            chunk,
        }
    }
}

impl Read for Memory {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = buf.len().min(self.chunk);
        self.input.read(&mut buf[..n])
    }
}

impl Write for Memory {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.output.write(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Conn for Memory {
    fn set_timeouts(&self, _timeout: Duration) -> io::Result<()> {
        Ok(())
    }
    fn shutdown_write(&self) -> io::Result<()> {
        Ok(())
    }
}

/// A reader that fails (a timed-out read).
struct TimedOut;

impl Read for TimedOut {
    fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
        Err(io::Error::new(ErrorKind::WouldBlock, "timed out"))
    }
}

fn request(method: &str, path: &str) -> Head {
    Head::Request {
        method: method.into(),
        path: path.into(),
    }
}

#[test]
fn responses_are_v2_bytes() {
    let ok = Response {
        status: 200,
        content_type: "application/json; charset=utf-8",
        body: b"{}\n".to_vec(),
        head: false,
    };
    assert_eq!(
        String::from_utf8(ok.to_bytes()).unwrap(),
        "HTTP/1.1 200 OK\r\nContent-Type: application/json; charset=utf-8\r\nContent-Length: 3\r\n\
         Cache-Control: private, no-store\r\nReferrer-Policy: no-referrer\r\n\
         X-Content-Type-Options: nosniff\r\nConnection: close\r\n\r\n{}\n"
    );
    let head = Response::not_found(true);
    assert_eq!(
        String::from_utf8(head.to_bytes()).unwrap(),
        "HTTP/1.1 404 Not Found\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: 10\r\n\
         Cache-Control: private, no-store\r\nReferrer-Policy: no-referrer\r\n\
         X-Content-Type-Options: nosniff\r\nConnection: close\r\n\r\n",
        "HEAD keeps the length, sends no body"
    );
    let not_allowed = String::from_utf8(Response::method_not_allowed(false).to_bytes()).unwrap();
    assert!(not_allowed.starts_with("HTTP/1.1 405 Method Not Allowed\r\n"));
    assert!(
        not_allowed.ends_with("Connection: close\r\nAllow: GET, HEAD\r\n\r\nMethod Not Allowed\n")
    );
    let bad = String::from_utf8(Response::bad_request(false).to_bytes()).unwrap();
    assert!(
        bad.starts_with("HTTP/1.1 400 Bad Request\r\n") && bad.ends_with("\r\n\r\nBad Request\n")
    );
}

#[test]
fn heads_are_parsed_strictly() {
    let cases: [(&[u8], Option<Head>); 9] = [
        (b"GET /sub/x HTTP/1.1\r\nHost: a\r\n", None),
        (
            b"GET /sub/x HTTP/1.1\r\nHost: a\r\n\r\n",
            Some(request("GET", "/sub/x")),
        ),
        (b"HEAD / HTTP/1.0\r\n\r\n", Some(request("HEAD", "/"))),
        (b"POST / HTTP/1.1\r\n\r\nbody", Some(request("POST", "/"))),
        (b"GET / HTTP/2.0\r\n\r\n", Some(Head::Bad { head: false })),
        (b"HEAD / HTTP/3\r\n\r\n", Some(Head::Bad { head: true })),
        (b"GET  / HTTP/1.1\r\n\r\n", Some(Head::Bad { head: false })),
        (
            b"\x16\x03\x01\x02\x00\r\n\r\n",
            Some(Head::Bad { head: false }),
        ),
        (
            b"GET /\xff HTTP/1.1\r\n\r\n",
            Some(Head::Bad { head: false }),
        ),
    ];
    for (input, want) in cases {
        assert_eq!(parse(input), want, "{:?}", String::from_utf8_lossy(input));
    }
}

#[test]
fn heads_up_to_8_kib_are_read_in_any_chunking() {
    let small = b"GET /sub/a HTTP/1.1\r\nHost: x\r\n\r\n";
    for chunk in [1, 7, 1024] {
        assert_eq!(
            read_head(&mut Memory::new(small, chunk)),
            request("GET", "/sub/a")
        );
    }
    // Complete within 8192 bytes although 1 KiB reads would cross the
    // limit with the last chunk (v2 answered 400 here, G-8.1#15).
    let mut near = b"GET / HTTP/1.1\r\nX-Pad: ".to_vec();
    near.resize(8186, b'a');
    near.extend_from_slice(b"\r\n\r\n");
    near.extend_from_slice(&[b'z'; 100]);
    assert_eq!(near[..8190].len(), 8190);
    assert_eq!(
        read_head(&mut Memory::new(&near, 1024)),
        request("GET", "/")
    );
    let mut huge = b"GET / HTTP/1.1\r\nX-Pad: ".to_vec();
    huge.resize(9000, b'a');
    assert_eq!(
        read_head(&mut Memory::new(&huge, 1024)),
        Head::Bad { head: false }
    );
    let mut huge_head = b"HEAD / HTTP/1.1\r\nX-Pad: ".to_vec();
    huge_head.resize(9000, b'a');
    assert_eq!(
        read_head(&mut Memory::new(&huge_head, 4096)),
        Head::Bad { head: true }
    );
    assert_eq!(
        read_head(&mut Memory::new(b"GET / HTTP/1.1\r\n", 64)),
        Head::Closed,
        "EOF before the end of the head"
    );
    assert_eq!(read_head(&mut TimedOut), Head::Closed);
}

#[test]
fn only_exact_device_paths_are_authorized() {
    let devices = [device("00000000000000aa", "a", TOKEN)];
    assert_eq!(
        authorize(&devices, &format!("/sub/{TOKEN}/singbox")),
        Some(ClientFormat::Singbox)
    );
    assert_eq!(
        authorize(&devices, &format!("/sub/{TOKEN}/singbox-notun")),
        Some(ClientFormat::SingboxNoTun)
    );
    let upper = TOKEN.to_uppercase();
    let rejected = [
        format!("/sub/{TOKEN}/links"),
        format!("/sub/{TOKEN}/state"),
        format!("/sub/{TOKEN}/singbox/"),
        format!("/sub/{TOKEN}/singbox?x=1"),
        format!("/sub/{TOKEN}/%73ingbox"),
        format!("/sub/{TOKEN}/../state.json"),
        format!("/sub/{upper}/singbox"),
        format!("/sub/{}/singbox", &TOKEN[1..]),
        format!("/sub/{}/singbox", "f".repeat(64)),
        format!("sub/{TOKEN}/singbox"),
        format!("//sub/{TOKEN}/singbox"),
        format!("/subs/{TOKEN}/singbox"),
        "/".to_owned(),
        "/sub/".to_owned(),
    ];
    for path in rejected {
        assert_eq!(authorize(&devices, &path), None, "{path}");
    }
    assert_eq!(authorize(&[], &format!("/sub/{TOKEN}/singbox")), None);
}

fn published(formats: &[(&str, &str)]) -> Published {
    Published {
        generation: "0".repeat(24),
        formats: formats
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect(),
    }
}

#[test]
fn responses_read_devices_and_snapshot_per_request() {
    let node = Node::new("sub-http-respond");
    let paths = &node.ctx.paths;
    let url = format!("/sub/{TOKEN}/singbox");
    assert_eq!(respond(paths, &request("GET", &url)).unwrap().status, 404);
    DeviceStore::write(paths, &[device("00000000000000aa", "a", TOKEN)]).unwrap();
    assert_eq!(
        respond(paths, &request("GET", &url)).unwrap().status,
        404,
        "no snapshot yet"
    );
    snapshot::write(
        paths,
        &published(&[("singbox", "{\"v\":1}\n"), ("mihomo", "a: 1\n")]),
    )
    .unwrap();
    let ok = respond(paths, &request("GET", &url)).unwrap();
    assert_eq!(
        (ok.status, ok.content_type, ok.body.as_slice(), ok.head),
        (
            200,
            "application/json; charset=utf-8",
            &b"{\"v\":1}\n"[..],
            false
        )
    );
    let yaml = respond(paths, &request("GET", &format!("/sub/{TOKEN}/mihomo"))).unwrap();
    assert_eq!(yaml.content_type, "text/yaml; charset=utf-8");
    let head = respond(paths, &request("HEAD", &url)).unwrap();
    assert!(head.head && head.status == 200 && head.body.len() == 8);
    let missing = respond(paths, &request("GET", &format!("/sub/{TOKEN}/xray"))).unwrap();
    assert_eq!(missing.status, 404, "format not published");
    assert_eq!(respond(paths, &request("POST", &url)).unwrap().status, 405);
    assert_eq!(respond(paths, &request("DELETE", "/")).unwrap().status, 405);
    assert_eq!(
        respond(paths, &Head::Bad { head: true }).unwrap().status,
        400
    );
    assert_eq!(respond(paths, &Head::Closed), None);

    snapshot::write(paths, &published(&[("singbox", "{\"v\":2}\n")])).unwrap();
    let next = respond(paths, &request("GET", &url)).unwrap();
    assert_eq!(next.body, b"{\"v\":2}\n", "republish visible at once");
    DeviceStore::write(paths, &[]).unwrap();
    assert_eq!(
        respond(paths, &request("GET", &url)).unwrap().status,
        404,
        "revocation visible at once"
    );
}

#[test]
fn handle_writes_one_response_and_survives_trailing_input() {
    let node = Node::new("sub-http-handle");
    let paths = &node.ctx.paths;
    DeviceStore::write(paths, &[device("00000000000000aa", "a", TOKEN)]).unwrap();
    snapshot::write(paths, &published(&[("base64", "bGlua3M=\n")])).unwrap();
    let get = format!("GET /sub/{TOKEN}/base64 HTTP/1.1\r\nHost: x\r\n\r\n");
    let mut conn = Memory::new(get.as_bytes(), 1024);
    handle(&mut conn, paths, Limits::default());
    let text = String::from_utf8(conn.output).unwrap();
    assert!(text.starts_with("HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\n"));
    assert!(text.ends_with("\r\n\r\nbGlua3M=\n"));

    let post = b"POST /x HTTP/1.1\r\nContent-Length: 5\r\n\r\nhello";
    let mut conn = Memory::new(post, 1024);
    handle(&mut conn, paths, Limits::default());
    assert!(String::from_utf8(conn.output)
        .unwrap()
        .starts_with("HTTP/1.1 405"));

    let mut silent = Memory::new(b"GET / HT", 1024);
    handle(&mut silent, paths, Limits::default());
    assert!(silent.output.is_empty(), "incomplete heads get no answer");
}

#[test]
fn handle_over_a_real_socket_pair() {
    let node = Node::new("sub-http-pair");
    let paths = node.ctx.paths.clone();
    DeviceStore::write(&paths, &[device("00000000000000aa", "a", TOKEN)]).unwrap();
    snapshot::write(&paths, &published(&[("xray", "{}\n")])).unwrap();
    let (mut client, server) = UnixStream::pair().unwrap();
    let worker = std::thread::spawn(move || {
        let mut server = server;
        handle(&mut server, &paths, Limits::default());
    });
    client
        .write_all(format!("HEAD /sub/{TOKEN}/xray HTTP/1.0\r\n\r\n").as_bytes())
        .unwrap();
    let mut response = String::new();
    client.read_to_string(&mut response).unwrap();
    worker.join().unwrap();
    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(response.contains("Content-Length: 3\r\n"));
    assert!(response.ends_with("\r\n\r\n"), "HEAD has no body");
}
