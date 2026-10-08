//! End-to-end link tools against real cores on loopback (`#[ignore]`):
//! a sing-box server (VLESS-REALITY in front of an `openssl s_server`
//! handshake target, Hysteria2 over QUIC, Shadowsocks) and real sing-box
//! and Xray client cores driven by `bench`, `reality-check` and
//! `failover`, with curl and openssl from PATH.
//!
//! Run: `ONEBOX_TEST_SINGBOX=/path/sing-box ONEBOX_TEST_XRAY=/path/xray
//! cargo test --lib linktools::e2e -- --ignored`.

use super::bundle;
use super::cancel::CancelToken;
use super::core_client::{CoreBinaries, CoreLauncher, Timing};
use super::failover;
use super::options::{BenchOptions, Common, FailoverOptions, RealityOptions, Scope};
use super::reality::{BODY_DIFFERS, H2};
use super::socks;
use super::testutil::{free_port, have, tls_server, tool, wait_listening, TlsServer};
use super::url::TestUrl;
use crate::ctx::Ctx;
use crate::render::probe::ProbeBundle;
use crate::sys::exec::{Cmd, Exec, RunningChild, SystemExec};
use crate::sys::fs::TempDir;
use serde_json::{json, Value};
use std::io::{Read, Write};
use std::net::{Ipv4Addr, TcpListener, TcpStream, UdpSocket};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

const SHORT_ID: &str = "0123456789abcdef";
const UUID: &str = "6a1c8f2e-3b4d-4e5f-8a9b-0c1d2e3f4a5b";
const PASSWORD: &str = "linktools-e2e-secret";
const SS_METHOD: &str = "aes-128-gcm";
const DOWNLOAD_BYTES: usize = 2 * 1024 * 1024;

/// A tiny HTTP origin: `/health` → 204, `/file` → 200 with 2 MiB (no range
/// support, so the body cap is exercised), `POST /upload` → 204.
fn origin() -> u16 {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            thread::spawn(move || {
                let _ = answer(stream);
            });
        }
    });
    port
}

fn answer(mut stream: TcpStream) -> std::io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") && head.len() < 16384 {
        stream.read_exact(&mut byte)?;
        head.push(byte[0]);
    }
    let head = String::from_utf8_lossy(&head).into_owned();
    let length = head
        .lines()
        .find_map(|l| {
            l.split_once(':')
                .filter(|(n, _)| n.eq_ignore_ascii_case("content-length"))
                .and_then(|(_, v)| v.trim().parse::<u64>().ok())
        })
        .unwrap_or(0);
    std::io::copy(&mut (&mut stream).take(length), &mut std::io::sink())?;
    let path = head.split_whitespace().nth(1).unwrap_or("");
    match path {
        "/file" => {
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Length: {DOWNLOAD_BYTES}\r\nConnection: close\r\n\r\n"
            )?;
            stream.write_all(&vec![b'x'; DOWNLOAD_BYTES])
        }
        "/health" | "/upload" => stream.write_all(
            b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        ),
        _ => stream
            .write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"),
    }
}

/// The running sing-box server and what clients need to reach it.
struct Server {
    reality: u16,
    hysteria: u16,
    shadowsocks: u16,
    public_key: String,
    _child: Mutex<Box<dyn RunningChild>>,
    _dir: TempDir,
}

fn keypair(singbox: &Path) -> (String, String) {
    let cmd = Cmd::new(singbox.to_str().unwrap())
        .args(["generate", "reality-keypair"])
        .timeout(Duration::from_secs(20));
    let out = SystemExec.run(&cmd).unwrap();
    assert!(out.ok(), "{}", out.stderr);
    let field = |name: &str| {
        out.stdout
            .lines()
            .find_map(|l| {
                l.split_once(':')
                    .filter(|(k, _)| k.trim().eq_ignore_ascii_case(name))
                    .map(|(_, v)| v.trim().to_owned())
            })
            .unwrap()
    };
    (field("PrivateKey"), field("PublicKey"))
}

fn free_udp_port() -> u16 {
    UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn start_server(singbox: &Path, tls: &TlsServer) -> Server {
    let (private_key, public_key) = keypair(singbox);
    let (reality, hysteria, shadowsocks) = (free_port(), free_udp_port(), free_port());
    let config = json!({
        "log": {"disabled": true},
        "inbounds": [
            {"type": "vless", "listen": "127.0.0.1", "listen_port": reality,
             "users": [{"uuid": UUID, "flow": "xtls-rprx-vision"}],
             "tls": {"enabled": true, "server_name": "localhost",
                "reality": {"enabled": true, "private_key": private_key, "short_id": [SHORT_ID],
                    "handshake": {"server": "127.0.0.1", "server_port": tls.port}}}},
            {"type": "hysteria2", "listen": "127.0.0.1", "listen_port": hysteria,
             "users": [{"password": PASSWORD}],
             "tls": {"enabled": true, "server_name": "localhost",
                "certificate_path": tls.cert, "key_path": tls.key}},
            {"type": "shadowsocks", "listen": "127.0.0.1", "listen_port": shadowsocks,
             "method": SS_METHOD, "password": PASSWORD}],
        "outbounds": [{"type": "direct", "tag": "direct"}]
    });
    let dir = TempDir::new("linktools-e2e").unwrap();
    let path = dir.join("server.json");
    std::fs::write(&path, config.to_string()).unwrap();
    let cmd = Cmd::new(singbox.to_str().unwrap()).args([
        "run",
        "-c",
        path.to_str().unwrap(),
        "-D",
        dir.path().to_str().unwrap(),
    ]);
    let child = SystemExec.spawn(&cmd).unwrap();
    wait_listening(reality);
    wait_listening(shadowsocks);
    Server {
        reality,
        hysteria,
        shadowsocks,
        public_key,
        _child: Mutex::new(child),
        _dir: dir,
    }
}

fn reality_meta(server: &Server, tls: &TlsServer) -> Value {
    json!({"host": "127.0.0.1", "port": server.reality, "sni": "localhost",
        "reference_host": "127.0.0.1", "reference_port": tls.port})
}

/// Client entries as `probe export` shapes them (sing-box tags = labels,
/// Xray tag `proxy`).
fn client_bundle(server: &Server, tls: &TlsServer) -> ProbeBundle {
    let sb_reality = json!({"type": "vless", "tag": "e2e-VLESS-Reality", "server": "127.0.0.1",
        "server_port": server.reality, "uuid": UUID, "flow": "xtls-rprx-vision",
        "tls": {"enabled": true, "server_name": "localhost",
            "utls": {"enabled": true, "fingerprint": "chrome"},
            "reality": {"enabled": true, "public_key": server.public_key, "short_id": SHORT_ID}}});
    let xr_reality = json!({"protocol": "vless", "tag": "proxy",
        "settings": {"vnext": [{"address": "127.0.0.1", "port": server.reality,
            "users": [{"id": UUID, "encryption": "none", "flow": "xtls-rprx-vision"}]}]},
        "streamSettings": {"network": "raw", "security": "reality",
            "realitySettings": {"serverName": "localhost", "fingerprint": "chrome",
                "publicKey": server.public_key, "shortId": SHORT_ID, "spiderX": "/"}}});
    let hy2 = json!({"type": "hysteria2", "tag": "e2e-Hysteria2", "server": "127.0.0.1",
        "server_port": server.hysteria, "password": PASSWORD,
        "tls": {"enabled": true, "server_name": "localhost", "certificate_path": tls.cert}});
    let ss = json!({"protocol": "shadowsocks", "tag": "proxy",
        "settings": {"servers": [{"address": "127.0.0.1", "port": server.shadowsocks,
            "method": SS_METHOD, "password": PASSWORD}]}});
    let value = json!({"schema": 1, "entries": [
        {"id": "vless-reality", "core": "singbox", "transport": "tcp",
         "tag": "e2e-VLESS-Reality", "outbounds": [sb_reality], "reality": reality_meta(server, tls)},
        {"id": "vless-reality-xray", "core": "xray", "transport": "tcp",
         "tag": "proxy", "outbounds": [xr_reality], "reality": reality_meta(server, tls)},
        {"id": "hysteria2", "core": "singbox", "transport": "udp",
         "tag": "e2e-Hysteria2", "outbounds": [hy2]},
        {"id": "shadowsocks", "core": "xray", "transport": "both",
         "tag": "proxy", "outbounds": [ss]}]});
    ProbeBundle::from_value(value).unwrap()
}

/// Processes whose command line names a temporary client-core dir.
fn leftover_client_cores() -> Vec<String> {
    let mut found = Vec::new();
    for entry in std::fs::read_dir("/proc").unwrap().flatten() {
        let Ok(cmdline) = std::fs::read(entry.path().join("cmdline")) else {
            continue;
        };
        let text = String::from_utf8_lossy(&cmdline).replace('\0', " ");
        if text.contains("onebox-client-") && !text.contains("cargo") {
            found.push(text);
        }
    }
    found
}

fn report(path: &Path) -> Value {
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

struct World {
    ctx: Ctx,
    dir: TempDir,
    bundle_path: PathBuf,
    binaries: CoreBinaries,
    origin: u16,
    tls: TlsServer,
    _server: Server,
}

fn world() -> Option<World> {
    let singbox = tool("ONEBOX_TEST_SINGBOX")?;
    let xray = tool("ONEBOX_TEST_XRAY")?;
    if !have("curl") || !have("openssl") {
        return None;
    }
    let tls = tls_server();
    let server = start_server(&singbox, &tls);
    let dir = TempDir::new("linktools-e2e").unwrap();
    let bundle_path = dir.join("probe.json");
    bundle::write_bundle(&bundle_path, &client_bundle(&server, &tls)).unwrap();
    let mut ctx = Ctx::test(dir.path()).0;
    ctx.exec = Arc::new(SystemExec);
    Some(World {
        ctx,
        bundle_path,
        binaries: CoreBinaries {
            singbox: Some(singbox),
            xray: Some(xray),
        },
        origin: origin(),
        tls,
        dir,
        _server: server,
    })
}

impl World {
    fn common(&self, entries: Option<&[&str]>) -> Common {
        Common {
            bundle: Some(self.bundle_path.clone()),
            entries: entries.map(|ids| ids.iter().map(|s| s.to_string()).collect()),
            binaries: self.binaries.clone(),
            url: self.url("/health"),
            timeout: 5,
            ca: Some(self.tls.cert.clone()),
        }
    }

    fn url(&self, path: &str) -> TestUrl {
        TestUrl::parse(&format!("http://127.0.0.1:{}{path}", self.origin)).unwrap()
    }
}

fn bench(w: &World) {
    let output = w.dir.join("bench.json");
    let opts = BenchOptions {
        common: w.common(None),
        output: Some(output.clone()),
        samples: 3,
        download: Some(w.url("/file")),
        upload: Some(w.url("/upload")),
        bytes: 1_048_576,
    };
    super::bench::run(&w.ctx, &opts).unwrap();
    let report = report(&output);
    assert_eq!(report["scope"], "current-machine-to-proxy-to-origin");
    let entries = report["entries"].as_array().unwrap();
    assert_eq!(entries.len(), 4);
    for row in entries {
        let id = &row["id"];
        assert_eq!(row["request_failure_rate"], 0.0, "{id}: {row}");
        let download = &row["transfers"]["download"];
        assert_eq!(download["ok"], true, "{id}: {download}");
        assert_eq!(download["received_bytes"], 1_048_576, "{id}: capped body");
        let upload = &row["transfers"]["upload"];
        assert_eq!(
            (upload["ok"].clone(), upload["sent_bytes"].clone()),
            (json!(true), json!(1_048_576))
        );
        assert!(row["client_rss_bytes_at_end"].as_u64().unwrap() > 0, "{id}");
        assert!(row["client_cpu_seconds"].as_f64().is_some(), "{id}");
        assert!(row["ttfb_ms"]["median"].as_f64().unwrap() > 0.0);
    }
    assert!(
        leftover_client_cores().is_empty(),
        "{:?}",
        leftover_client_cores()
    );
}

fn reality_check(w: &World) {
    let output = w.dir.join("reality.json");
    let opts = RealityOptions {
        common: w.common(None),
        output: Some(output.clone()),
        scope: Scope::CurrentMachineToServer,
    };
    // Warnings only (the s_server status page is dynamic) or a clean pass.
    match super::reality::run(&w.ctx, &opts) {
        Ok(()) => {}
        Err(e) => assert_eq!(e.exit_code(), 2, "{e}"),
    }
    let report = report(&output);
    let entries = report["entries"].as_array().unwrap();
    assert_eq!(entries.len(), 2, "only the REALITY entries: {report}");
    for row in entries {
        let checks = row["checks"].as_object().unwrap();
        for key in [
            "ordinary_tls13_valid_certificate",
            "same_certificate",
            "same_alpn",
            "same_http_status",
            "same_redirect",
            "authenticated_proxy",
            "wrong_short_id_rejected",
        ] {
            assert_eq!(checks.get(key), Some(&json!(true)), "{key}: {row}");
        }
        assert_eq!(checks.get(H2), Some(&json!(true)), "{row}");
        for warning in row["warnings"].as_array().unwrap() {
            assert_eq!(warning, BODY_DIFFERS, "{row}");
        }
        assert!(row.get("errors").is_none(), "{row}");
    }
}

struct StopOnDrop<'a>(&'a CancelToken);

impl Drop for StopOnDrop<'_> {
    fn drop(&mut self) {
        self.0.cancel();
    }
}

/// SOCKS5 no-auth CONNECT through the failover front, then `GET /health`.
fn health_via_front(front: u16, origin: u16) -> String {
    let mut stream = TcpStream::connect((Ipv4Addr::LOCALHOST, front)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    stream.write_all(&[5, 1, 0]).unwrap();
    let mut method = [0u8; 2];
    stream.read_exact(&mut method).unwrap();
    let mut request = vec![5, 1, 0];
    request.extend(socks::encode_address("127.0.0.1", origin).unwrap());
    stream.write_all(&request).unwrap();
    let mut reply = [0u8; 10];
    stream.read_exact(&mut reply).unwrap();
    assert_eq!(reply, socks::REPLY_SUCCEEDED);
    stream
        .write_all(b"GET /health HTTP/1.1\r\nHost: origin\r\nConnection: close\r\n\r\n")
        .unwrap();
    // No half-close: a proxy chain may turn it into a full close before
    // the response; the origin closes after answering instead.
    let mut text = String::new();
    stream.read_to_string(&mut text).unwrap();
    text
}

fn failover_service(w: &World) {
    let port = free_port();
    let opts = FailoverOptions {
        common: w.common(Some(&["vless-reality", "hysteria2"])),
        port,
        interval: 1,
        ..FailoverOptions::default()
    };
    let bundle = bundle::load(&w.bundle_path).unwrap();
    let entries = bundle::select(
        &bundle,
        opts.common.entries.as_deref(),
        bundle::Selection::Pair,
    )
    .unwrap();
    let cancel = CancelToken::manual();
    let events = Mutex::new(Vec::new());
    let launcher = CoreLauncher {
        ctx: &w.ctx,
        binaries: &w.binaries,
        cancel: &cancel,
        timing: Timing::default(),
    };
    thread::scope(|scope| {
        // A failed assertion below must still stop the service, or the
        // scope would wait for it forever.
        let _stop = StopOnDrop(&cancel);
        let served = scope.spawn(|| {
            let mut emit = |line: &str| {
                events.lock().unwrap().push(line.to_owned());
                Ok(())
            };
            failover::failover(&w.ctx, &launcher, &entries, &opts, &cancel, &mut emit)
        });
        let deadline = Instant::now() + Duration::from_secs(30);
        while !events.lock().unwrap().iter().any(|e| e.contains("ready")) {
            assert!(
                Instant::now() < deadline,
                "not ready: {:?}",
                events.lock().unwrap()
            );
            assert!(!served.is_finished(), "failover ended early");
            thread::sleep(Duration::from_millis(50));
        }
        assert_eq!(
            events.lock().unwrap()[0],
            r#"{"event":"switch","from":null,"to":"vless-reality"}"#
        );
        let response = health_via_front(port, w.origin);
        assert!(response.starts_with("HTTP/1.1 204"), "{response}");
        cancel.cancel();
        served.join().unwrap().unwrap();
    });
    assert!(
        leftover_client_cores().is_empty(),
        "{:?}",
        leftover_client_cores()
    );
}

#[test]
#[ignore = "needs ONEBOX_TEST_SINGBOX, ONEBOX_TEST_XRAY, curl and openssl"]
fn real_cores_bench_reality_check_and_failover() {
    // Signal tests raise SIGINT/SIGTERM; they must not cancel these runs.
    let _signals = crate::sys::signal::TEST_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let Some(w) = world() else {
        return;
    };
    bench(&w);
    reality_check(&w);
    failover_service(&w);
}
