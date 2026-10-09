//! End-to-end checks with real sockets, a real nginx and real certificates
//! (ported from v2's `subscription/e2e.rs`), excluded from ordinary runs:
//!
//! ```text
//! ONEBOX_NGINX_BIN=/path/to/nginx cargo test --lib subscription::e2e -- --ignored --nocapture --test-threads=1
//! ```
//!
//! - ip mode: the worker itself on TCP (IPv4 and, when available, IPv6
//!   loopback): every format, HEAD, 405 for other methods, the 404 rules,
//!   republish under the same URL, disable/enable, revoke and reset taking
//!   effect on the next request;
//! - standalone: the worker on its unix socket behind the rendered
//!   `onebox-subscription-web` config over TLS (test CA), nginx's own 403
//!   for other methods, one copy of each security header, revoke;
//! - site: the `/sub/` location inside the site's TLS 1.3 internal server.
//!
//! The worker runs in-process (`subscription::serve`, which the
//! `onebox subscription serve` unit runs); nginx runs as a child process
//! that is killed when the test ends.

use super::devices::{self, NewDevice};
use super::frontend::{self, WebPhase};
use super::server::{self, Listener};
use super::snapshot;
use super::testing::{ip, site, standalone, Xorshift};
use crate::cert::testing::{free_port, have_openssl, TestCa};
use crate::ctx::Ctx;
use crate::domain::config::{NodeConfig, WebCert};
use crate::domain::protocol::ClientFormat;
use crate::render::fixtures::spec;
use crate::site::{NginxFacts, SitePhase, SiteSubscription};
use crate::state::StateStore;
use crate::sys::exec::SystemExec;
use crate::sys::fs::TempDir;
use crate::sys::lock::{FileLock, BUSY_MESSAGE};
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// A node directory traversable by the nginx workers (like `/etc` and
/// `/run` in production), with the real `/` as system root.
struct Live {
    dir: TempDir,
    ctx: Ctx,
}

impl Live {
    fn new(label: &str) -> Live {
        let dir = TempDir::new(label).unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        let (mut ctx, _, _) = Ctx::test(dir.path());
        ctx.exec = Arc::new(SystemExec);
        ctx.paths.system_root = PathBuf::from("/");
        Live { dir, ctx }
    }

    /// A scratch directory outside the node tree.
    fn scratch(&self, name: &str) -> PathBuf {
        self.dir.join(name)
    }

    fn save(&self, cfg: &NodeConfig) {
        StateStore::save(&self.ctx, cfg).unwrap();
    }

    fn lock(&self) -> FileLock {
        FileLock::acquire(&self.ctx.paths.lock(), BUSY_MESSAGE).unwrap()
    }

    /// Publish `cfg`'s snapshot (what the publish stage writes).
    fn publish(&self, cfg: &NodeConfig) -> snapshot::Published {
        let published = snapshot::render_with(&spec(cfg), &mut Xorshift(9)).unwrap();
        snapshot::write(&self.ctx.paths, &published).unwrap();
        published
    }

    fn add(&self, name: &str) -> NewDevice {
        let cfg = StateStore::load_required(&self.ctx).unwrap().config;
        devices::add_with(&self.ctx, &self.lock(), &cfg, name, &mut Xorshift(11), 1).unwrap()
    }

    /// Start the worker for `listener` and wait until it accepts.
    fn start_worker(&self, listener: Listener) {
        server::record(&self.ctx.paths, listener).unwrap();
        let ctx = self.ctx.clone();
        std::thread::spawn(move || {
            if let Err(e) = server::serve(&ctx) {
                eprintln!("worker failed: {e}");
            }
        });
        let paths = self.ctx.paths.clone();
        wait(|| match listener {
            Listener::Tcp { port } => TcpStream::connect(("127.0.0.1", port)).is_ok(),
            Listener::Unix => {
                std::os::unix::net::UnixStream::connect(paths.subscription_socket()).is_ok()
            }
        });
    }
}

fn wait(ready: impl Fn() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(8);
    while !ready() {
        assert!(Instant::now() < deadline, "listener did not start");
        std::thread::sleep(Duration::from_millis(25));
    }
}

/// `(status, headers, body)` of one plain HTTP/1.0 request.
fn fetch(host: IpAddr, port: u16, method: &str, path: &str) -> (u16, String, String) {
    let mut stream =
        TcpStream::connect_timeout(&SocketAddr::new(host, port), Duration::from_secs(3)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(8)))
        .unwrap();
    write!(
        stream,
        "{method} {path} HTTP/1.0\r\nHost: x\r\nConnection: close\r\n\r\n"
    )
    .unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).unwrap();
    let (headers, body) = response.split_once("\r\n\r\n").unwrap();
    let status = headers.split_whitespace().nth(1).unwrap().parse().unwrap();
    (status, headers.to_ascii_lowercase(), body.to_owned())
}

fn ip_case(address: IpAddr) {
    let live = Live::new("sub-e2e-ip");
    let port = free_port();
    let mut cfg = ip(port);
    if let Some(sub) = cfg.subscription.as_mut() {
        sub.mode = crate::domain::config::SubscriptionMode::Ip { address };
    }
    live.save(&cfg);
    let first = live.publish(&cfg);
    assert_eq!(first.formats.len(), ClientFormat::REMOTE.len());
    let device = live.add("ip-client");
    live.start_worker(Listener::Tcp { port });
    let private = cfg.creds.reality.as_ref().unwrap().private_key.clone();
    for format in ClientFormat::REMOTE {
        let path = format!("/sub/{}/{}", device.token, format.id());
        let (status, headers, body) = fetch(address, port, "GET", &path);
        assert_eq!(status, 200, "{address} {format}");
        assert_eq!(Some(body.as_str()), first.body(format));
        assert!(headers.contains("cache-control: private, no-store"));
        assert!(headers.contains(&format!("content-type: {}", format.content_type())));
        assert!(!body.contains(&private), "server key leaked");
        let (status, headers, body) = fetch(address, port, "HEAD", &path);
        assert_eq!((status, body.as_str()), (200, ""));
        let length = first.body(format).unwrap().len();
        assert!(headers.contains(&format!("content-length: {length}")));
    }
    let url = format!("/sub/{}/singbox", device.token);
    assert_eq!(
        fetch(address, port, "POST", &url).0,
        405,
        "no nginx in front"
    );
    for invalid in [
        format!("/sub/{}/singbox", "0".repeat(64)),
        format!("/sub/{}/state.json", device.token),
        format!("{url}?extra=1"),
        format!("{url}/"),
        "/".to_owned(),
    ] {
        assert_eq!(fetch(address, port, "GET", &invalid).0, 404, "{invalid}");
    }

    let mut refreshed = cfg.clone();
    refreshed.node_name = "ip-refreshed-node".into();
    let second = live.publish(&refreshed);
    assert_ne!(
        first.body(ClientFormat::Singbox),
        second.body(ClientFormat::Singbox)
    );
    assert_eq!(
        Some(fetch(address, port, "GET", &url).2.as_str()),
        second.body(ClientFormat::Singbox)
    );

    snapshot::remove(&live.ctx.paths).unwrap();
    assert_eq!(fetch(address, port, "GET", &url).0, 404, "disabled");
    live.publish(&refreshed);
    assert_eq!(fetch(address, port, "GET", &url).0, 200, "enabled again");

    let reset =
        devices::reset_with(&live.ctx, &live.lock(), &device.id, &mut Xorshift(5), 2).unwrap();
    assert_eq!(
        fetch(address, port, "GET", &url).0,
        404,
        "reset: old URL dead at once"
    );
    let new_url = format!("/sub/{}/singbox", reset.token);
    assert_eq!(fetch(address, port, "GET", &new_url).0, 200);
    devices::revoke(&live.ctx, &live.lock(), &device.id).unwrap();
    assert_eq!(
        fetch(address, port, "GET", &new_url).0,
        404,
        "revoked at once"
    );
    assert!(!live.ctx.paths.subscription().join("tls").exists());
    assert!(
        !frontend::conf_file(&live.ctx.paths).exists(),
        "ip mode has no nginx"
    );
}

#[test]
#[ignore = "binds loopback TCP ports"]
fn ip_mode_worker_serves_tcp_directly() {
    ip_case("127.0.0.1".parse().unwrap());
    if crate::sys::net::ipv6_available(Path::new("/"))
        && std::net::TcpListener::bind("[::1]:0").is_ok()
    {
        ip_case("::1".parse().unwrap());
    } else {
        println!("IPv6 loopback unavailable; IPv4 verified");
    }
}

/// A running nginx child; killed (with its workers) on drop.
struct Nginx(Child);

impl Nginx {
    fn start(bin: &Path, prefix: &Path, conf: &Path) -> Nginx {
        let child = Command::new(bin)
            .arg("-p")
            .arg(prefix)
            .arg("-c")
            .arg(conf)
            .args(["-g", "daemon off;"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        Nginx(child)
    }
}

impl Drop for Nginx {
    /// SIGTERM to the master, which stops its workers (a SIGKILL would
    /// orphan them); SIGKILL only when it does not exit in time.
    fn drop(&mut self) {
        let _ = crate::sys::process::send_signal(self.0.id(), libc::SIGTERM);
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            if matches!(self.0.try_wait(), Ok(Some(_))) {
                return;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn nginx_bin() -> Option<PathBuf> {
    let bin = std::env::var_os(crate::host::nginx::ENV_BIN).map(PathBuf::from);
    if bin.is_none() {
        println!("skipping: set ONEBOX_NGINX_BIN");
    }
    bin.filter(|_| have_openssl())
}

/// `(status, headers, body)` over HTTPS through curl (test CA, pinned host).
fn curl(ca: &Path, host: &str, port: u16, path: &str, extra: &[&str]) -> (u16, String, String) {
    let resolve = format!("{host}:{port}:127.0.0.1");
    let output = Command::new("curl")
        .args([
            "--silent",
            "--show-error",
            "--noproxy",
            "*",
            "--max-time",
            "8",
        ])
        .args(["--resolve", &resolve, "--cacert"])
        .arg(ca)
        .args(if extra.contains(&"--head") {
            &[][..]
        } else {
            &["--dump-header", "-"][..]
        })
        .args(extra)
        .arg(format!("https://{host}:{port}{path}"))
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let text = String::from_utf8(output.stdout).unwrap();
    let (headers, body) = text.split_once("\r\n\r\n").unwrap_or((&text, ""));
    let status = headers.split_whitespace().nth(1).unwrap().parse().unwrap();
    (status, headers.to_ascii_lowercase(), body.to_owned())
}

/// A test-CA leaf for `name` deployed as `dir/{cert,key}.pem`.
fn deploy_cert(ca: &TestCa, scratch: &Path, dir: &Path, name: &str) {
    let (chain, key) = ca.leaf(scratch, &[name], 2, false);
    std::fs::create_dir_all(dir).unwrap();
    std::fs::copy(chain, dir.join("cert.pem")).unwrap();
    std::fs::copy(key, dir.join("key.pem")).unwrap();
}

#[test]
#[ignore = "needs a real nginx in ONEBOX_NGINX_BIN, openssl and curl"]
fn standalone_https_through_nginx() {
    let Some(bin) = nginx_bin() else {
        return;
    };
    let live = Live::new("sub-e2e-standalone");
    let paths = live.ctx.paths.clone();
    let ca = TestCa::create(&live.scratch("test-ca"));
    let port = free_port();
    let cfg = standalone(WebCert::Cloudflare, port);
    live.save(&cfg);
    deploy_cert(
        &ca,
        &live.scratch("leaf"),
        &paths.subscription().join("tls"),
        "sub.example.com",
    );
    let first = live.publish(&cfg);
    let device = live.add("phone");
    live.start_worker(Listener::Unix);

    let facts = NginxFacts::detect(&live.ctx).unwrap();
    let text = frontend::render_for(&paths, &cfg, &facts, WebPhase::Full)
        .unwrap()
        .unwrap();
    let tested = frontend::test_conf(&live.ctx, &text).unwrap();
    frontend::install_web_conf(&live.ctx, &tested).unwrap();
    let _nginx = Nginx::start(&bin, &paths.subscription(), &frontend::conf_file(&paths));
    wait(|| TcpStream::connect(("127.0.0.1", port)).is_ok());

    let url = format!("/sub/{}/singbox", device.token);
    let (status, headers, body) = curl(&ca.cert, "sub.example.com", port, &url, &[]);
    assert_eq!(status, 200);
    assert_eq!(Some(body.as_str()), first.body(ClientFormat::Singbox));
    assert_eq!(
        headers.matches("cache-control: private, no-store").count(),
        1,
        "{headers}"
    );
    assert_eq!(
        headers.matches("x-content-type-options: nosniff").count(),
        1
    );
    let (status, _, body) = curl(&ca.cert, "sub.example.com", port, &url, &["--head"]);
    assert_eq!((status, body.as_str()), (200, ""));
    let (status, _, _) = curl(
        &ca.cert,
        "sub.example.com",
        port,
        &url,
        &["--request", "POST"],
    );
    assert_eq!(status, 403, "nginx rejects other methods");
    for path in [
        format!("/sub/{}/singbox", "0".repeat(64)),
        format!("/sub/{}/key.pem", device.token),
        format!("{url}?x=1"),
        "/".to_owned(),
        "/state.json".to_owned(),
    ] {
        let (status, _, body) = curl(&ca.cert, "sub.example.com", port, &path, &[]);
        assert!([403, 404].contains(&status), "{path}: {status}");
        assert!(!body.contains("PRIVATE KEY"));
    }
    devices::revoke(&live.ctx, &live.lock(), &device.id).unwrap();
    assert_eq!(curl(&ca.cert, "sub.example.com", port, &url, &[]).0, 404);
    assert!(
        paths.subscription().join("client_body_temp").is_dir(),
        "G19: temp under SUBDIR"
    );
    assert!(!paths.run.join("nginx-subscription").exists());
}

#[test]
#[ignore = "needs a real nginx in ONEBOX_NGINX_BIN, openssl and curl"]
fn site_mode_location_inside_the_site() {
    let Some(bin) = nginx_bin() else {
        return;
    };
    let live = Live::new("sub-e2e-site");
    let paths = live.ctx.paths.clone();
    let ca = TestCa::create(&live.scratch("test-ca"));
    let mut cfg = site();
    let internal = free_port();
    if let Some(s) = cfg.site.as_mut() {
        s.internal_port = internal;
    }
    cfg.reality.dest = crate::domain::defaults::site_dest(internal);
    live.save(&cfg);
    deploy_cert(&ca, &live.scratch("leaf"), &paths.site(), "www.example.com");
    std::fs::create_dir_all(&paths.site_root).unwrap();
    std::fs::set_permissions(&paths.site_root, std::fs::Permissions::from_mode(0o755)).unwrap();
    let first = live.publish(&cfg);
    let device = live.add("phone");
    live.start_worker(Listener::Unix);

    let location = super::site_location(&paths, &cfg).unwrap();
    let facts = NginxFacts::detect(&live.ctx).unwrap();
    let sub = SiteSubscription {
        location_block: location.location_block,
    };
    let text =
        crate::site::render_conf_with(&paths, &cfg, Some(&sub), SitePhase::Deferred, &facts, None)
            .unwrap()
            .replace("listen 80;", &format!("listen {};", free_port()))
            .replace("listen [::]:80;", "");
    assert!(text.contains("error_log /dev/null crit;"), "G20");
    let tested = crate::site::test_conf(&live.ctx, &text).unwrap();
    crate::site::install_conf(&live.ctx, &tested).unwrap();
    let _nginx = Nginx::start(&bin, &paths.site(), &crate::site::conf_file(&paths));
    wait(|| TcpStream::connect(("127.0.0.1", internal)).is_ok());

    let url = format!("/sub/{}/singbox", device.token);
    let (status, _, body) = curl(&ca.cert, "www.example.com", internal, &url, &["--tlsv1.3"]);
    assert_eq!(status, 200);
    assert_eq!(Some(body.as_str()), first.body(ClientFormat::Singbox));
    devices::revoke(&live.ctx, &live.lock(), &device.id).unwrap();
    assert_eq!(
        curl(&ca.cert, "www.example.com", internal, &url, &[]).0,
        404
    );
}
