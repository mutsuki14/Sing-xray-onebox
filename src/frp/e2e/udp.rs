//! Real UDP forwarding with the rendered server and the exported client.

use super::*;
use std::io;
use std::net::UdpSocket;

fn datagram(port: u16, payload: &[u8]) -> io::Result<Option<Vec<u8>>> {
    // A new socket and nonce per exchange exclude stale buffered replies.
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

/// One datagram with a fresh nonce and non-text bytes comes back prefixed
/// with the origin's marker.
fn probe(port: u16, marker: &[u8]) -> bool {
    let mut payload = crate::sys::rand::hex(24).unwrap().into_bytes();
    payload.extend_from_slice(&[0, 255, 128, 10]);
    let mut expected = marker.to_vec();
    expected.extend_from_slice(&payload);
    datagram(port, &payload).unwrap().as_deref() == Some(expected.as_slice())
}

fn echo(socket: UdpSocket, marker: Vec<u8>, stop: Arc<AtomicBool>) -> thread::JoinHandle<()> {
    socket
        .set_read_timeout(Some(Duration::from_millis(50)))
        .unwrap();
    thread::spawn(move || {
        let mut buffer = [0u8; 2048];
        while !stop.load(Ordering::Relaxed) {
            match socket.recv_from(&mut buffer) {
                Ok((size, sender)) => {
                    let mut response = marker.clone();
                    response.extend_from_slice(&buffer[..size]);
                    if socket.send_to(&response, sender).is_err() {
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
    })
}

#[test]
#[ignore = "requires ONEBOX_FRPS_BIN and ONEBOX_FRPC_BIN from the official FRP release"]
fn private_ca_udp_forwarding_stops_with_client() {
    let frps = env_path("ONEBOX_FRPS_BIN");
    let frpc = env_path("ONEBOX_FRPC_BIN");
    let mut lab = Lab::new("frp-e2e-udp");
    let ctx = real_ctx(lab.root());
    let (sockets, ports) = reserve(1);
    let control = ports[0];
    let remote_socket = loop {
        // TCP and UDP allocate independently; FRP refuses this overlap.
        let socket = UdpSocket::bind(("127.0.0.1", 0)).unwrap();
        if socket.local_addr().unwrap().port() != control {
            break socket;
        }
    };
    let remote = remote_socket.local_addr().unwrap().port();
    let origin_socket = UdpSocket::bind(("127.0.0.1", 0)).unwrap();
    let local = origin_socket.local_addr().unwrap().port();
    let marker = format!("udp-origin-{}:", crate::sys::rand::hex(12).unwrap()).into_bytes();
    lab.origin = Some(echo(origin_socket, marker.clone(), lab.stop.clone()));
    assert!(probe(local, &marker), "the UDP origin did not start");

    let mut state = FrpState::new(
        "udp-control.frp.example".into(),
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
        kind: Some("udp".into()),
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
        wait_until(Duration::from_secs(5), || ready(control)),
        "{}",
        lab.logs()
    );
    drop(remote_socket);
    assert!(!probe(remote, &marker), "forwarding before frpc started");
    let client_args = ["-c", client_config.to_str().unwrap()];
    lab.spawn(&frpc, &client_args, Some(&client_dir), "client");
    let forwarded = wait_until(Duration::from_secs(8), || probe(remote, &marker));
    assert!(forwarded, "no UDP forwarding: {}", lab.logs());
    assert!(probe(remote, &marker), "second flow failed: {}", lab.logs());

    lab.stop_last();
    for _ in 0..8 {
        assert!(
            !probe(remote, &marker),
            "forwarding survived frpc: {}",
            lab.logs()
        );
        thread::sleep(Duration::from_millis(30));
    }
    assert!(probe(local, &marker), "the origin itself must still answer");
}
