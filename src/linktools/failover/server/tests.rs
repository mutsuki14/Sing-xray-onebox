use super::*;
use crate::linktools::failover::revive::ProxySlot;
use crate::linktools::socks::USERNAME;
use crate::linktools::testutil::FakeProxy;
use std::io::Read;
use std::net::Shutdown;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::thread;

/// An echo origin: every connection gets its bytes back.
fn echo_origin() -> u16 {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { return };
            thread::spawn(move || {
                let mut reader = stream.try_clone().unwrap();
                let _ = io::copy(&mut reader, &mut stream);
                let _ = stream.shutdown(Shutdown::Write);
            });
        }
    });
    port
}

/// A client core's SOCKS inbound: requires the `onebox-` login with the
/// fake proxies' token and tunnels CONNECTs; counts tunnels.
fn fake_upstream() -> (u16, Arc<AtomicUsize>) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    let tunnels = Arc::new(AtomicUsize::new(0));
    let count = tunnels.clone();
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { return };
            let count = count.clone();
            thread::spawn(move || {
                let _ = tunnel(stream, &count);
            });
        }
    });
    (port, tunnels)
}

fn tunnel(mut client: TcpStream, count: &AtomicUsize) -> Result<()> {
    let mut hello = [0u8; 3];
    client.read_exact(&mut hello)?;
    client.write_all(&[5, 2])?;
    let token = "0".repeat(48);
    let mut auth = vec![0u8; 3 + USERNAME.len() + token.len()];
    client.read_exact(&mut auth)?;
    if !auth.ends_with(token.as_bytes()) {
        client.write_all(&[1, 1])?;
        return Ok(());
    }
    client.write_all(&[1, 0])?;
    let mut head = [0u8; 4];
    client.read_exact(&mut head)?;
    let host = socks::read_address(&mut client, head[3])?;
    let mut port = [0u8; 2];
    client.read_exact(&mut port)?;
    let mut origin = TcpStream::connect((host.as_str(), u16::from_be_bytes(port)))?;
    count.fetch_add(1, Ordering::SeqCst);
    client.write_all(&socks::REPLY_SUCCEEDED)?;
    let mut down = origin.try_clone()?;
    let mut up = client.try_clone()?;
    let back = thread::spawn(move || {
        let _ = io::copy(&mut down, &mut up);
        let _ = up.shutdown(Shutdown::Write);
    });
    let _ = io::copy(&mut client, &mut origin);
    let _ = origin.shutdown(Shutdown::Write);
    let _ = back.join();
    Ok(())
}

/// Through a SOCKS5 no-auth CONNECT on `front`, send `ping` to the echo
/// origin and read the reply.
fn ping_via(front: u16, origin: u16) -> std::result::Result<String, Vec<u8>> {
    let mut stream = TcpStream::connect((Ipv4Addr::LOCALHOST, front)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    stream.write_all(&[5, 1, 0]).unwrap();
    let mut method = [0u8; 2];
    stream.read_exact(&mut method).unwrap();
    assert_eq!(method, socks::METHOD_SELECTED);
    let mut request = vec![5, 1, 0];
    request.extend(socks::encode_address("127.0.0.1", origin).unwrap());
    stream.write_all(&request).unwrap();
    let mut reply = [0u8; 10];
    stream.read_exact(&mut reply).unwrap();
    if reply != socks::REPLY_SUCCEEDED {
        return Err(reply.to_vec());
    }
    stream.write_all(b"ping").unwrap();
    stream.shutdown(Shutdown::Write).unwrap();
    let mut text = String::new();
    stream.read_to_string(&mut text).unwrap();
    Ok(text)
}

fn free_port() -> u16 {
    TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

#[test]
fn events_are_v2_json_lines() {
    let ids = vec!["tcp".to_string(), "quic".to_string()];
    assert_eq!(
        switch_event(&ids, None, Some(0)).to_string(),
        r#"{"event":"switch","from":null,"to":"tcp"}"#
    );
    assert_eq!(
        switch_event(&ids, Some(0), None).to_string(),
        r#"{"event":"switch","from":"tcp","to":null}"#
    );
    assert_eq!(
        ready_event(&ids, 2080).to_string(),
        r#"{"entries":["tcp","quic"],"event":"ready","socks":"127.0.0.1:2080","tcp_only":true}"#
    );
}

#[test]
fn slots_and_active_index() {
    let slots = Slots::new(2);
    let a = slots.try_take().unwrap();
    let _b = slots.try_take().unwrap();
    assert!(slots.try_take().is_none());
    drop(a);
    assert_eq!(slots.live(), 1);
    assert!(slots.try_take().is_some());
    let active = Active::default();
    assert_eq!(active.get(), None);
    active.set(Some(3));
    assert_eq!(active.get(), Some(3));
    active.set(None);
    assert_eq!(active.get(), None);
}

/// Serve one front connection in a thread with the given route.
fn front_once(route: Option<SocksEndpoint>) -> (u16, thread::JoinHandle<Result<()>>) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    let worker = thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        let cancel = CancelToken::manual();
        handle_client(
            stream,
            &|| route.clone(),
            Duration::from_secs(2),
            &cancel,
            relay::IDLE,
        )
    });
    (port, worker)
}

#[test]
fn clients_are_tunnelled_through_the_active_core() {
    let origin = echo_origin();
    let (upstream, tunnels) = fake_upstream();
    let endpoint = FakeProxy::new(upstream).endpoint().clone();
    let (front, worker) = front_once(Some(endpoint));
    assert_eq!(ping_via(front, origin).unwrap(), "ping");
    worker.join().unwrap().unwrap();
    assert_eq!(tunnels.load(Ordering::SeqCst), 1);
}

#[test]
fn no_healthy_entry_is_host_unreachable() {
    let origin = echo_origin();
    let (front, worker) = front_once(None);
    assert_eq!(ping_via(front, origin).unwrap_err(), REPLY_HOST_UNREACHABLE);
    assert_eq!(
        worker.join().unwrap().unwrap_err().to_string(),
        "无健康入口"
    );

    // An upstream that refuses the credential: also 05 04.
    let (upstream, tunnels) = fake_upstream();
    let wrong = SocksEndpoint {
        port: upstream,
        token: "1".repeat(48),
    };
    let (front, worker) = front_once(Some(wrong));
    assert_eq!(ping_via(front, origin).unwrap_err(), REPLY_HOST_UNREACHABLE);
    assert_eq!(
        worker.join().unwrap().unwrap_err().to_string(),
        "SOCKS 认证失败"
    );
    assert_eq!(tunnels.load(Ordering::SeqCst), 0);
}

struct Harness {
    ids: Vec<String>,
    proxies: Vec<ProxySlot>,
    healthy: Vec<AtomicBool>,
    tunnels: Vec<Arc<AtomicUsize>>,
}

fn harness(count: usize) -> Harness {
    let mut proxies = Vec::new();
    let mut tunnels = Vec::new();
    for _ in 0..count {
        let (port, counter) = fake_upstream();
        proxies.push(ProxySlot::new(Box::new(FakeProxy::new(port))));
        tunnels.push(counter);
    }
    Harness {
        ids: (0..count).map(|i| format!("e{i}")).collect(),
        proxies,
        healthy: (0..count).map(|_| AtomicBool::new(true)).collect(),
        tunnels,
    }
}

fn no_restart(_: usize) -> Result<Box<dyn Proxy>> {
    Err(Error::msg("测试中不重启"))
}

fn wait_for(events: &Mutex<Vec<String>>, needle: &str) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while !events.lock().unwrap().iter().any(|e| e.contains(needle)) {
        assert!(
            Instant::now() < deadline,
            "no event {needle}: {:?}",
            events.lock().unwrap()
        );
        thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn the_service_switches_on_failure_and_stops_cleanly() {
    let h = harness(2);
    let origin = echo_origin();
    let port = free_port();
    let health = |i: usize| h.healthy[i].load(Ordering::SeqCst);
    let svc = Service {
        ids: &h.ids,
        proxies: &h.proxies,
        health: &health,
        restart: &no_restart,
        port,
        interval: Duration::from_millis(50),
        upstream_timeout: Duration::from_secs(2),
        max_clients: MAX_CLIENTS,
        idle: relay::IDLE,
    };
    let events = Mutex::new(Vec::new());
    let cancel = CancelToken::manual();
    thread::scope(|scope| {
        let served = scope.spawn(|| {
            let mut emit = |line: &str| {
                events.lock().unwrap().push(line.to_owned());
                Ok(())
            };
            serve(&svc, FailoverPolicy::new(2, 1, 1, 0), &cancel, &mut emit)
        });
        wait_for(&events, "ready");
        assert_eq!(
            events.lock().unwrap()[..2],
            [
                r#"{"event":"switch","from":null,"to":"e0"}"#.to_string(),
                ready_event(&h.ids, port).to_string()
            ]
        );
        assert_eq!(ping_via(port, origin).unwrap(), "ping");
        assert_eq!(h.tunnels[0].load(Ordering::SeqCst), 1);

        h.healthy[0].store(false, Ordering::SeqCst);
        wait_for(&events, r#""from":"e0","to":"e1""#);
        assert_eq!(ping_via(port, origin).unwrap(), "ping");
        assert_eq!(h.tunnels[1].load(Ordering::SeqCst), 1);

        h.healthy[1].store(false, Ordering::SeqCst);
        wait_for(&events, r#""from":"e1","to":null"#);
        assert_eq!(ping_via(port, origin).unwrap_err(), REPLY_HOST_UNREACHABLE);

        cancel.cancel();
        served.join().unwrap().unwrap();
    });
    assert!(
        h.proxies.iter().all(|p| p.get().exited().is_some()),
        "cores stopped"
    );
    assert!(
        TcpStream::connect((Ipv4Addr::LOCALHOST, port)).is_err(),
        "listener closed"
    );
}

#[test]
fn over_capacity_clients_are_refused_and_bind_errors_reported() {
    let h = harness(2);
    let port = free_port();
    let health = |_: usize| true;
    let svc = Service {
        ids: &h.ids,
        proxies: &h.proxies,
        health: &health,
        restart: &no_restart,
        port,
        interval: Duration::from_secs(60),
        upstream_timeout: Duration::from_secs(2),
        max_clients: 1,
        idle: relay::IDLE,
    };
    let cancel = CancelToken::manual();
    let ready = AtomicBool::new(false);
    thread::scope(|scope| {
        let served = scope.spawn(|| {
            let mut emit = |line: &str| {
                if line.contains("ready") {
                    ready.store(true, Ordering::SeqCst);
                }
                Ok(())
            };
            serve(&svc, FailoverPolicy::new(2, 3, 3, 60), &cancel, &mut emit)
        });
        while !ready.load(Ordering::SeqCst) {
            thread::sleep(Duration::from_millis(10));
        }
        // The first client holds the only slot (handshake pending).
        let holder = TcpStream::connect((Ipv4Addr::LOCALHOST, port)).unwrap();
        thread::sleep(Duration::from_millis(100));
        let mut second = TcpStream::connect((Ipv4Addr::LOCALHOST, port)).unwrap();
        second
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let mut reply = [0u8; 2];
        second.read_exact(&mut reply).unwrap();
        assert_eq!(reply, socks::NO_ACCEPTABLE_METHODS);

        // A second service cannot bind the same port.
        let err = serve(
            &svc,
            FailoverPolicy::new(2, 3, 3, 60),
            &CancelToken::manual(),
            &mut |_| Ok(()),
        )
        .unwrap_err();
        assert!(
            err.to_string()
                .starts_with(&format!("无法监听本机 SOCKS5 端口: 127.0.0.1:{port}")),
            "{err}"
        );
        drop(holder);
        cancel.cancel();
        served.join().unwrap().unwrap();
    });
}

#[test]
fn a_dead_core_is_restarted_and_routed_to_again() {
    let h = harness(2);
    let origin = echo_origin();
    let port = free_port();
    let health = |i: usize| h.healthy[i].load(Ordering::SeqCst);
    let (replacement, replacement_tunnels) = fake_upstream();
    let restarts = AtomicUsize::new(0);
    let restart = |i: usize| -> Result<Box<dyn Proxy>> {
        assert_eq!(i, 0);
        restarts.fetch_add(1, Ordering::SeqCst);
        Ok(Box::new(FakeProxy::new(replacement)))
    };
    let svc = Service {
        ids: &h.ids,
        proxies: &h.proxies,
        health: &health,
        restart: &restart,
        port,
        interval: Duration::from_millis(50),
        upstream_timeout: Duration::from_secs(2),
        max_clients: MAX_CLIENTS,
        idle: relay::IDLE,
    };
    let events = Mutex::new(Vec::new());
    let cancel = CancelToken::manual();
    thread::scope(|scope| {
        let served = scope.spawn(|| {
            let mut emit = |line: &str| {
                events.lock().unwrap().push(line.to_owned());
                Ok(())
            };
            serve(&svc, FailoverPolicy::new(2, 1, 1, 0), &cancel, &mut emit)
        });
        wait_for(&events, "ready");
        // Entry 0's core crashes: its checks fail and it is restarted.
        h.healthy[0].store(false, Ordering::SeqCst);
        h.proxies[0].get().terminate();
        wait_for(&events, r#""from":"e0","to":"e1""#);
        let deadline = Instant::now() + Duration::from_secs(10);
        while restarts.load(Ordering::SeqCst) == 0 {
            assert!(Instant::now() < deadline, "never restarted");
            thread::sleep(Duration::from_millis(10));
        }
        h.healthy[0].store(true, Ordering::SeqCst);
        wait_for(&events, r#""from":"e1","to":"e0""#);
        assert_eq!(ping_via(port, origin).unwrap(), "ping");
        assert_eq!(replacement_tunnels.load(Ordering::SeqCst), 1);
        assert_eq!(
            h.tunnels[0].load(Ordering::SeqCst),
            0,
            "the dead core is unused"
        );
        cancel.cancel();
        served.join().unwrap().unwrap();
    });
    assert_eq!(restarts.load(Ordering::SeqCst), 1);
}
