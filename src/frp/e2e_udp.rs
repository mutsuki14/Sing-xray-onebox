//! Real UDP forwarding using the same rendered server and exported client as users.
use super::*;
use std::{io, net::UdpSocket, time::Instant};

fn datagram(port: u16, payload: &[u8]) -> io::Result<Option<Vec<u8>>> {
    // A new socket and nonce for each exchange exclude stale buffered replies.
    let socket = UdpSocket::bind(("127.0.0.1", 0))?;
    socket.connect(("127.0.0.1", port))?;
    socket.set_read_timeout(Some(Duration::from_millis(150)))?;
    socket.set_write_timeout(Some(Duration::from_millis(150)))?;
    socket.send(payload)?;
    let mut response = [0u8; 2048];
    match socket.recv(&mut response) {
        Ok(size) => Ok(Some(response[..size].to_vec())),
        Err(e)
            if matches!(
                e.kind(),
                io::ErrorKind::WouldBlock
                    | io::ErrorKind::TimedOut
                    | io::ErrorKind::ConnectionRefused
            ) =>
        {
            Ok(None)
        }
        Err(e) => Err(e),
    }
}

fn probe(port: u16, marker: &[u8]) -> bool {
    let mut payload = util::random_hex(24).unwrap().into_bytes();
    // Include non-text bytes so the test checks the full datagram, not just text.
    payload.extend_from_slice(&[0, 255, 128, 10]);
    let mut expected = marker.to_vec();
    expected.extend_from_slice(&payload);
    datagram(port, &payload).unwrap().as_deref() == Some(expected.as_slice())
}

#[test]
#[ignore = "requires ONEBOX_FRPS_BIN and ONEBOX_FRPC_BIN from the official FRP release"]
fn private_ca_udp_forwarding_stops_with_client() {
    let server = PathBuf::from(std::env::var("ONEBOX_FRPS_BIN").expect("ONEBOX_FRPS_BIN"));
    let client = PathBuf::from(std::env::var("ONEBOX_FRPC_BIN").expect("ONEBOX_FRPC_BIN"));
    let root = std::env::temp_dir().join(format!(
        "onebox-native-frp-udp-e2e-{}",
        util::random_hex(8).unwrap()
    ));
    lifecycle::private_dir(&root).unwrap();
    let mut lab = Lab {
        root: root.clone(),
        children: Vec::new(),
        stop: Arc::new(AtomicBool::new(false)),
        origin: None,
    };
    let control_socket = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let control = control_socket.local_addr().unwrap().port();
    let remote_socket = loop {
        let socket = UdpSocket::bind(("127.0.0.1", 0)).unwrap();
        // TCP and UDP can independently allocate the same numeric port, while
        // the actual FRP configuration deliberately rejects this overlap.
        if socket.local_addr().unwrap().port() != control {
            break socket;
        }
    };
    let remote = remote_socket.local_addr().unwrap().port();
    let origin_socket = UdpSocket::bind(("127.0.0.1", 0)).unwrap();
    let local = origin_socket.local_addr().unwrap().port();
    assert_ne!(local, remote);
    origin_socket
        .set_read_timeout(Some(Duration::from_millis(50)))
        .unwrap();
    origin_socket
        .set_write_timeout(Some(Duration::from_millis(150)))
        .unwrap();
    let marker = format!("udp-origin-{}:", util::random_hex(24).unwrap()).into_bytes();
    let origin_marker = marker.clone();
    let stop = lab.stop.clone();
    lab.origin = Some(thread::spawn(move || {
        let mut buffer = [0u8; 2048];
        while !stop.load(Ordering::Relaxed) {
            match origin_socket.recv_from(&mut buffer) {
                Ok((size, sender)) => {
                    let mut response = origin_marker.clone();
                    response.extend_from_slice(&buffer[..size]);
                    if origin_socket.send_to(&response, sender).is_err() {
                        break;
                    }
                }
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                    ) => {}
                Err(_) => break,
            }
        }
    }));
    assert!(probe(local, &marker), "UDP origin did not start");

    let ctx = Context {
        paths: crate::context::Paths::isolated(&root),
        ..Context::default()
    };
    lifecycle::private_dir(&ctx.paths.frp_root).unwrap();
    let cfg = Config {
        mode: "tcp".into(),
        bind_addr: "127.0.0.1".into(),
        domain: "udp-control.frp.example".into(),
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
    let out = root.join("client");
    export(
        &ctx,
        &cfg,
        &[
            out.to_str().unwrap().into(),
            "--type".into(),
            "udp".into(),
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
    // Keep the exported CA and TLS server name intact; only bypass DNS so this
    // opt-in test never leaves loopback or requires a real public domain.
    util::atomic_write(&client_config, text.as_bytes(), 0o600).unwrap();
    for (binary, config) in [(&server, &server_config), (&client, &client_config)] {
        let check = Command::new(binary)
            .args(["verify", "-c", config.to_str().unwrap()])
            .current_dir(config.parent().unwrap())
            .output()
            .unwrap();
        assert!(
            check.status.success(),
            "FRP UDP configuration verification failed: {}{}",
            String::from_utf8_lossy(&check.stdout),
            String::from_utf8_lossy(&check.stderr)
        );
    }

    drop(control_socket);
    lab.spawn(&server, &server_config, "server");
    let deadline = Instant::now() + Duration::from_secs(5);
    while !ready(control) && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(30));
    }
    assert!(
        ready(control),
        "UDP FRP server did not start: {}",
        lab.logs()
    );
    drop(remote_socket);
    assert!(
        !probe(remote, &marker),
        "UDP proxy unexpectedly reached origin before frpc started"
    );
    lab.spawn(&client, &client_config, "client");
    let deadline = Instant::now() + Duration::from_secs(8);
    let mut forwarded = false;
    while Instant::now() < deadline {
        if probe(remote, &marker) {
            forwarded = true;
            break;
        }
        thread::sleep(Duration::from_millis(30));
    }
    assert!(
        forwarded,
        "FRP rendered/exported UDP configuration failed forwarding: {}",
        lab.logs()
    );
    assert!(
        probe(remote, &marker),
        "second UDP flow failed: {}",
        lab.logs()
    );

    lab.stop_client();
    // Fresh sockets and nonces cannot receive an earlier in-flight response.
    // Keeping the origin alive also excludes a direct-origin false positive.
    for _ in 0..8 {
        assert!(
            !probe(remote, &marker),
            "UDP forwarding survived frpc shutdown: {}",
            lab.logs()
        );
        thread::sleep(Duration::from_millis(30));
    }
    assert!(
        probe(local, &marker),
        "origin stopped too, invalidating the frpc shutdown check"
    );
}
