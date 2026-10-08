//! Opt-in tests using official FRP binaries, entirely on loopback addresses.
use super::*;
use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    process::{Child, Command, Stdio},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread,
    time::Duration,
};

struct Lab {
    root: PathBuf,
    children: Vec<Child>,
    stop: Arc<AtomicBool>,
    origin: Option<thread::JoinHandle<()>>,
}
impl Drop for Lab {
    fn drop(&mut self) {
        for child in &mut self.children {
            let _ = child.kill();
            let _ = child.wait();
        }
        self.stop.store(true, Ordering::Relaxed);
        if let Some(origin) = self.origin.take() {
            let _ = origin.join();
        }
        let _ = fs::remove_dir_all(&self.root);
    }
}
impl Lab {
    fn spawn(&mut self, binary: &Path, config: &Path, name: &str) {
        let log = fs::File::create(self.root.join(format!("{name}.log"))).unwrap();
        let child = Command::new(binary)
            .args(["-c", config.to_str().unwrap()])
            .current_dir(config.parent().unwrap())
            .stdin(Stdio::null())
            .stdout(log.try_clone().unwrap())
            .stderr(log)
            .spawn()
            .unwrap();
        self.children.push(child);
    }
    fn stop_client(&mut self) {
        let mut child = self.children.pop().unwrap();
        child.kill().ok();
        child.wait().unwrap();
    }
    fn logs(&self) -> String {
        ["server", "client", "bad-token", "bad-host"]
            .into_iter()
            .filter_map(|n| fs::read_to_string(self.root.join(format!("{n}.log"))).ok())
            .collect::<Vec<_>>()
            .join("\n")
    }
}
fn ready(port: u16) -> bool {
    TcpStream::connect_timeout(
        &format!("127.0.0.1:{port}").parse().unwrap(),
        Duration::from_millis(150),
    )
    .is_ok()
}
fn request(port: u16) -> Option<String> {
    let mut stream = TcpStream::connect_timeout(
        &format!("127.0.0.1:{port}").parse().ok()?,
        Duration::from_millis(150),
    )
    .ok()?;
    stream.set_read_timeout(Some(Duration::from_secs(1))).ok()?;
    stream
        .set_write_timeout(Some(Duration::from_secs(1)))
        .ok()?;
    stream
        .write_all(b"GET / HTTP/1.1\r\nHost: local.test\r\nConnection: close\r\n\r\n")
        .ok()?;
    let mut response = String::new();
    stream.read_to_string(&mut response).ok()?;
    Some(response)
}

#[test]
#[ignore = "requires ONEBOX_FRPS_BIN and ONEBOX_FRPC_BIN from the official FRP release"]
fn private_ca_tcp_forwarding_and_credential_rejection() {
    let server = PathBuf::from(std::env::var("ONEBOX_FRPS_BIN").expect("ONEBOX_FRPS_BIN"));
    let client = PathBuf::from(std::env::var("ONEBOX_FRPC_BIN").expect("ONEBOX_FRPC_BIN"));
    let root = std::env::temp_dir().join(format!(
        "onebox-native-frp-e2e-{}",
        util::random_hex(8).unwrap()
    ));
    lifecycle::private_dir(&root).unwrap();
    let control_socket = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let remote_socket = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let control = control_socket.local_addr().unwrap().port();
    let remote = remote_socket.local_addr().unwrap().port();
    let origin_socket = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let local = origin_socket.local_addr().unwrap().port();
    origin_socket.set_nonblocking(true).unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let stop_origin = stop.clone();
    let origin = thread::spawn(move || {
        while !stop_origin.load(Ordering::Relaxed) {
            match origin_socket.accept() {
                Ok((mut connection, _)) => {
                    connection
                        .set_read_timeout(Some(Duration::from_secs(1)))
                        .ok();
                    let mut request = [0u8; 4096];
                    if connection.read(&mut request).is_ok() {
                        let body = b"native-frp-end-to-end";
                        let header = format!(
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                            body.len()
                        );
                        connection.write_all(header.as_bytes()).ok();
                        connection.write_all(body).ok();
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(20))
                }
                Err(_) => break,
            }
        }
    });
    let mut lab = Lab {
        root: root.clone(),
        children: Vec::new(),
        stop,
        origin: Some(origin),
    };
    let ctx = Context {
        paths: crate::context::Paths::isolated(&root),
        ..Context::default()
    };
    lifecycle::private_dir(&ctx.paths.frp_root).unwrap();
    let cfg = Config {
        mode: "tcp".into(),
        bind_addr: "127.0.0.1".into(),
        domain: "control.frp.example".into(),
        bind_port: control,
        range_start: remote,
        range_end: remote,
        token: util::random_hex(32).unwrap(),
        ..Config::default()
    };
    lifecycle::control_cert(&ctx, &cfg).unwrap();
    let server_config = ctx.paths.frp_root.join("frps.toml");
    util::atomic_write(
        &server_config,
        render(&ctx, &cfg).unwrap().as_bytes(),
        0o600,
    )
    .unwrap();
    let check = Command::new(&server)
        .args(["verify", "-c", server_config.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        check.status.success(),
        "{}",
        String::from_utf8_lossy(&check.stderr)
    );
    let out = root.join("client");
    export(
        &ctx,
        &cfg,
        &[
            out.to_str().unwrap().into(),
            "--type".into(),
            "tcp".into(),
            "--local-port".into(),
            local.to_string(),
            "--remote-port".into(),
            remote.to_string(),
        ],
    )
    .unwrap();
    let client_config = out.join("frpc.toml");
    let text = fs::read_to_string(&client_config).unwrap().replace(
        &format!("serverAddr = {}", quote(&cfg.domain)),
        "serverAddr = \"127.0.0.1\"",
    );
    util::atomic_write(&client_config, text.as_bytes(), 0o600).unwrap();
    let check = Command::new(&client)
        .args(["verify", "-c", client_config.to_str().unwrap()])
        .current_dir(&out)
        .output()
        .unwrap();
    assert!(
        check.status.success(),
        "{}",
        String::from_utf8_lossy(&check.stderr)
    );
    drop(control_socket);
    drop(remote_socket);
    lab.spawn(&server, &server_config, "server");
    for _ in 0..100 {
        if ready(control) {
            break;
        }
        thread::sleep(Duration::from_millis(30));
    }
    assert!(ready(control), "{}", lab.logs());
    lab.spawn(&client, &client_config, "client");
    let mut connected = false;
    for _ in 0..100 {
        if request(remote).is_some_and(|s| s.ends_with("native-frp-end-to-end")) {
            connected = true;
            break;
        }
        thread::sleep(Duration::from_millis(30));
    }
    assert!(
        connected,
        "FRP native configuration failed real forwarding: {}",
        lab.logs()
    );
    lab.stop_client();
    for _ in 0..100 {
        if !ready(remote) {
            break;
        }
        thread::sleep(Duration::from_millis(30));
    }
    assert!(!ready(remote), "old proxy listener did not close");
    let wrong = text.replace(&cfg.token, &"0".repeat(64));
    util::atomic_write(&client_config, wrong.as_bytes(), 0o600).unwrap();
    lab.spawn(&client, &client_config, "bad-token");
    for _ in 0..40 {
        assert!(
            !ready(remote),
            "wrong token unexpectedly opened a proxy listener"
        );
        thread::sleep(Duration::from_millis(30));
    }
    lab.stop_client();
    let wrong = text.replace(
        &format!("transport.tls.serverName = {}", quote(&cfg.domain)),
        "transport.tls.serverName = \"wrong.frp.example\"",
    );
    util::atomic_write(&client_config, wrong.as_bytes(), 0o600).unwrap();
    lab.spawn(&client, &client_config, "bad-host");
    for _ in 0..40 {
        assert!(
            !ready(remote),
            "wrong TLS name unexpectedly opened a proxy listener"
        );
        thread::sleep(Duration::from_millis(30));
    }
}
