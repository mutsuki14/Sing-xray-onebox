//! End-to-end tests with the official frp binaries (and nginx for web
//! mode), entirely on loopback. Ignored by default; run with
//! `ONEBOX_FRPS_BIN`, `ONEBOX_FRPC_BIN` and `ONEBOX_NGINX_BIN` set:
//! `cargo test frp::e2e -- --ignored`. Ported from v2's e2e suites: the
//! rendered `frps.toml`, the exported client bundle, the private CA and
//! the generated `nginx.conf` must forward real traffic, and wrong
//! credentials must never open a listener.

mod udp;
mod web;

use super::ca::control_cert;
use super::export::{export, ExportRequest};
use super::model::{BindAddr, FrpState, Mode};
use super::render::{quote, server_toml};
use crate::ctx::Ctx;
use crate::domain::config::PortRange;
use crate::paths::Paths;
use crate::sys::exec::{Cmd, Exec, RunningChild, SystemExec, SAFE_PATH};
use crate::sys::fs::{ensure_dir, TempDir};
use crate::ui::ScriptedPrompter;
use std::fs;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

/// Daemons (each in its own session, terminated with its group on drop),
/// an optional origin server thread and the scratch directory.
pub(super) struct Lab {
    pub dir: TempDir,
    pub children: Vec<Box<dyn RunningChild>>,
    pub stop: Arc<AtomicBool>,
    pub origin: Option<thread::JoinHandle<()>>,
}

impl Lab {
    pub fn new(label: &str) -> Lab {
        Lab {
            dir: TempDir::new(label).unwrap(),
            children: Vec::new(),
            stop: Arc::new(AtomicBool::new(false)),
            origin: None,
        }
    }

    pub fn root(&self) -> &Path {
        self.dir.path()
    }

    /// Start `binary args…` in `cwd` (default: the lab) with its output in `{name}.log`, with
    /// a clean environment (no proxy variables).
    pub fn spawn(&mut self, binary: &Path, args: &[&str], cwd: Option<&Path>, name: &str) {
        let log = self.root().join(format!("{name}.log"));
        let cwd = cwd.unwrap_or(self.root()).to_path_buf();
        let cmd = Cmd::new("/bin/sh")
            .args(["-c", "exec \"$0\" \"$@\" >>\"$ONEBOX_E2E_LOG\" 2>&1"])
            .arg(binary.to_string_lossy())
            .args(args.iter().copied())
            .clear_env()
            .env("PATH", SAFE_PATH)
            .env("ONEBOX_E2E_LOG", log.to_string_lossy())
            .cwd(cwd);
        self.children.push(SystemExec.spawn(&cmd).unwrap());
    }

    /// Stop the most recently started daemon (TERM, KILL after 2 s).
    pub fn stop_last(&mut self) {
        if let Some(mut child) = self.children.pop() {
            let _ = child.terminate(Duration::from_secs(2));
        }
    }

    pub fn logs(&self) -> String {
        ["server", "client", "bad-token", "bad-host", "nginx"]
            .into_iter()
            .filter_map(|n| fs::read_to_string(self.root().join(format!("{n}.log"))).ok())
            .collect::<Vec<_>>()
            .join("\n")
    }
}

impl Drop for Lab {
    fn drop(&mut self) {
        while !self.children.is_empty() {
            self.stop_last();
        }
        self.stop.store(true, Ordering::Relaxed);
        if let Some(origin) = self.origin.take() {
            let _ = origin.join();
        }
    }
}

pub(super) fn env_path(key: &str) -> PathBuf {
    PathBuf::from(std::env::var(key).unwrap_or_else(|_| panic!("{key} 未设置")))
}

/// A context over `Paths::isolated(root)` running real programs.
pub(super) fn real_ctx(root: &Path) -> Ctx {
    Ctx {
        paths: Paths::isolated(root),
        exec: Arc::new(SystemExec),
        ui: Arc::new(ScriptedPrompter::unattended()),
    }
}

pub(super) fn ready(port: u16) -> bool {
    TcpStream::connect_timeout(
        &format!("127.0.0.1:{port}").parse().unwrap(),
        Duration::from_millis(150),
    )
    .is_ok()
}

pub(super) fn wait_until(limit: Duration, mut done: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + limit;
    while Instant::now() < deadline {
        if done() {
            return true;
        }
        thread::sleep(Duration::from_millis(30));
    }
    done()
}

fn request(port: u16) -> Option<String> {
    let addr = format!("127.0.0.1:{port}").parse().ok()?;
    let mut stream = TcpStream::connect_timeout(&addr, Duration::from_millis(150)).ok()?;
    stream.set_read_timeout(Some(Duration::from_secs(1))).ok()?;
    stream
        .write_all(b"GET / HTTP/1.1\r\nHost: local.test\r\nConnection: close\r\n\r\n")
        .ok()?;
    let mut response = String::new();
    stream.read_to_string(&mut response).ok()?;
    Some(response)
}

/// Bind `n` loopback TCP ports and keep them reserved until dropped.
pub(super) fn reserve(n: usize) -> (Vec<TcpListener>, Vec<u16>) {
    let sockets: Vec<TcpListener> = (0..n)
        .map(|_| TcpListener::bind(("127.0.0.1", 0)).unwrap())
        .collect();
    let ports = sockets
        .iter()
        .map(|s| s.local_addr().unwrap().port())
        .collect();
    (sockets, ports)
}

/// The control CA, server certificate and `frps.toml` of `state` (checked
/// with `frps verify`).
pub(super) fn server(ctx: &Ctx, state: &FrpState, frps: &Path) -> PathBuf {
    let root = &ctx.paths.frp_root;
    ensure_dir(root, 0o700).unwrap();
    control_cert(ctx, root, &state.domain).unwrap();
    let config = root.join("frps.toml");
    fs::write(&config, server_toml(state, root)).unwrap();
    verify(frps, &config);
    config
}

/// Export the bundle for `req` and point it at 127.0.0.1 (the TLS server
/// name and the pinned CA stay as exported).
pub(super) fn client(ctx: &Ctx, state: &FrpState, req: ExportRequest, frpc: &Path) -> PathBuf {
    let out = export(ctx.ui.as_ref(), &ctx.paths, state, &req, Path::new("/")).unwrap();
    let config = out.join("frpc.toml");
    let text = fs::read_to_string(&config).unwrap().replace(
        &format!("serverAddr = {}", quote(&state.domain)),
        "serverAddr = \"127.0.0.1\"",
    );
    fs::write(&config, text).unwrap();
    verify(frpc, &config);
    config
}

pub(super) fn verify(binary: &Path, config: &Path) {
    let check = Command::new(binary)
        .args(["verify", "-c", config.to_str().unwrap()])
        .current_dir(config.parent().unwrap())
        .output()
        .unwrap();
    assert!(
        check.status.success(),
        "{} verify: {}{}",
        binary.display(),
        String::from_utf8_lossy(&check.stdout),
        String::from_utf8_lossy(&check.stderr)
    );
}

pub(super) fn token() -> String {
    crate::sys::rand::hex(32).unwrap()
}

fn origin(socket: TcpListener, stop: Arc<AtomicBool>) -> thread::JoinHandle<()> {
    socket.set_nonblocking(true).unwrap();
    thread::spawn(move || {
        while !stop.load(Ordering::Relaxed) {
            match socket.accept() {
                Ok((mut connection, _)) => {
                    let _ = connection.set_nonblocking(false);
                    let _ = connection.set_read_timeout(Some(Duration::from_secs(1)));
                    let mut request = [0u8; 4096];
                    if connection.read(&mut request).is_ok() {
                        let body = b"native-frp-end-to-end";
                        let header = format!(
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                            body.len()
                        );
                        let _ = connection.write_all(header.as_bytes());
                        let _ = connection.write_all(body);
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(20))
                }
                Err(_) => break,
            }
        }
    })
}

#[test]
#[ignore = "requires ONEBOX_FRPS_BIN and ONEBOX_FRPC_BIN from the official FRP release"]
fn private_ca_tcp_forwarding_and_credential_rejection() {
    let frps = env_path("ONEBOX_FRPS_BIN");
    let frpc = env_path("ONEBOX_FRPC_BIN");
    let mut lab = Lab::new("frp-e2e-tcp");
    let ctx = real_ctx(lab.root());
    let (sockets, ports) = reserve(2);
    let (control, remote) = (ports[0], ports[1]);
    let origin_socket = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let local = origin_socket.local_addr().unwrap().port();
    lab.origin = Some(origin(origin_socket, lab.stop.clone()));
    let mut state = FrpState::new(
        "control.frp.example".into(),
        token(),
        BindAddr::LoopbackV4,
        Mode::Tcp {
            range: PortRange {
                start: remote,
                end: remote,
            },
        },
    );
    state.bind_port = control;
    let server_config = server(&ctx, &state, &frps);
    let req = ExportRequest {
        output: Some(lab.root().join("client").to_string_lossy().into_owned()),
        kind: Some("tcp".into()),
        local_port: Some(local),
        remote_port: Some(remote),
        ..ExportRequest::default()
    };
    let client_config = client(&ctx, &state, req, &frpc);
    let client_dir = client_config.parent().unwrap().to_path_buf();
    drop(sockets);
    let server_args = ["-c", server_config.to_str().unwrap()];
    lab.spawn(&frps, &server_args, None, "server");
    assert!(
        wait_until(Duration::from_secs(3), || ready(control)),
        "{}",
        lab.logs()
    );
    let client_args = ["-c", client_config.to_str().unwrap()];
    lab.spawn(&frpc, &client_args, Some(&client_dir), "client");
    let forwarded = wait_until(Duration::from_secs(5), || {
        request(remote).is_some_and(|s| s.ends_with("native-frp-end-to-end"))
    });
    assert!(forwarded, "no forwarding: {}", lab.logs());
    lab.stop_last();
    assert!(
        wait_until(Duration::from_secs(3), || !ready(remote)),
        "the proxy listener outlived frpc"
    );

    let text = fs::read_to_string(&client_config).unwrap();
    for (name, wrong) in [
        ("bad-token", text.replace(&state.token, &"0".repeat(64))),
        (
            "bad-host",
            text.replace(
                &format!("transport.tls.serverName = {}", quote(&state.domain)),
                "transport.tls.serverName = \"wrong.frp.example\"",
            ),
        ),
    ] {
        fs::write(&client_config, wrong).unwrap();
        lab.spawn(&frpc, &client_args, Some(&client_dir), name);
        let opened = wait_until(Duration::from_millis(1200), || ready(remote));
        assert!(!opened, "{name} opened a proxy listener: {}", lab.logs());
        lab.stop_last();
    }
    // The rejected clients left nothing behind: the exported bundle
    // connects again.
    fs::write(&client_config, &text).unwrap();
    lab.spawn(&frpc, &client_args, Some(&client_dir), "client");
    let recovered = wait_until(Duration::from_secs(5), || {
        request(remote).is_some_and(|s| s.ends_with("native-frp-end-to-end"))
    });
    assert!(
        recovered,
        "no forwarding after the rejected clients: {}",
        lab.logs()
    );
}
