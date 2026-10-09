use super::*;
use crate::domain::config::WebCert;
use crate::subscription::devices::DeviceStore;
use crate::subscription::http::Limits;
use crate::subscription::snapshot::{self, Published};
use crate::subscription::testing::{device, ip, reality, site, standalone, Node, TOKEN};
use crate::sys::exec::Output;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::os::unix::fs::MetadataExt;

#[test]
fn listener_follows_the_mode() {
    assert_eq!(Listener::of(&ip(9000)), Some(Listener::Tcp { port: 9000 }));
    assert_eq!(Listener::of(&site()), Some(Listener::Unix));
    assert_eq!(
        Listener::of(&standalone(WebCert::Cloudflare, 8448)),
        Some(Listener::Unix)
    );
    assert_eq!(Listener::of(&reality()), None);
    assert_eq!(Listener::Tcp { port: 1 }.to_string(), "TCP 1");
}

#[test]
fn the_record_wins_over_the_configuration() {
    let node = Node::new("sub-srv-resolve");
    let paths = &node.ctx.paths;
    assert!(matches!(resolve(paths), Err(Error::NotInstalled)));
    node.save(&reality());
    assert_eq!(resolve(paths).unwrap_err().to_string(), NOT_ENABLED);
    node.save(&ip(8448));
    assert_eq!(resolve(paths).unwrap(), Listener::Tcp { port: 8448 });
    node.save(&site());
    assert_eq!(resolve(paths).unwrap(), Listener::Unix);

    // publish records the generation being applied before state.json.
    record(paths, Listener::Tcp { port: 9000 }).unwrap();
    assert_eq!(recorded(paths).unwrap(), Some(Listener::Tcp { port: 9000 }));
    assert_eq!(
        std::fs::read_to_string(listener_file(paths)).unwrap(),
        "{\"type\":\"tcp\",\"port\":9000}\n"
    );
    assert_eq!(resolve(paths).unwrap(), Listener::Tcp { port: 9000 });
    forget(paths).unwrap();
    assert_eq!(recorded(paths).unwrap(), None);
    std::fs::write(listener_file(paths), "{\"type\":\"udp\"}").unwrap();
    assert!(resolve(paths).is_err(), "a corrupt record is not guessed around");
}

#[test]
fn v2_data_means_the_v2_socket_layout() {
    let node = Node::new("sub-srv-v2");
    let paths = &node.ctx.paths;
    std::fs::create_dir_all(&paths.root).unwrap();
    std::fs::write(paths.state(), crate::apply::testing::V2_STATE).unwrap();
    let settings = paths.subscription_v2_settings();
    std::fs::create_dir_all(settings.parent().unwrap()).unwrap();
    std::fs::write(
        &settings,
        r#"{"enabled":true,"mode":"ip","domain":"203.0.113.10","port":8448,"method":"none","custom_cert":null,"custom_key":null,"devices":[]}"#,
    )
    .unwrap();
    assert_eq!(resolve(paths).unwrap(), Listener::Unix, "v2 nginx owns the port");
    assert!(!paths.devices().exists(), "the worker writes nothing");
}

#[test]
fn group_ids_from_getent_or_etc_group() {
    assert_eq!(parse_group("www-data:x:33:\nnginx:x:101:a,b\n", "nginx"), Some(101));
    assert_eq!(parse_group("www-data:x:33:\n", "nginx"), None);
    assert_eq!(parse_group("nginx:x:bad:\n", "nginx"), None);
    assert_eq!(parse_group("nginxx:x:5:\n", "nginx"), None);
    let node = Node::new("sub-srv-group");
    node.fake
        .on("getent", &["group", "web"], Output::success("web:x:77:\n"));
    assert_eq!(group_id(&node.ctx, "web").unwrap(), 77);
    let etc = node.ctx.paths.system("/etc/group");
    std::fs::create_dir_all(etc.parent().unwrap()).unwrap();
    std::fs::write(&etc, "nobody:x:65534:\n").unwrap();
    assert_eq!(group_id(&node.ctx, "nobody").unwrap(), 65534);
    assert_eq!(
        group_id(&node.ctx, "ghost").unwrap_err().to_string(),
        "找不到用户组 ghost"
    );
}

#[test]
fn unix_socket_rules() {
    let node = Node::new("sub-srv-unix");
    let paths = &node.ctx.paths;
    let gid = std::fs::metadata(node.dir.path()).unwrap().gid();
    let socket = paths.subscription_socket();
    let listener = bind_unix(paths, gid).unwrap();
    let meta = std::fs::symlink_metadata(&socket).unwrap();
    assert_eq!(meta.mode() & 0o777, 0o660);
    assert_eq!(meta.gid(), gid);
    assert_eq!(
        std::fs::metadata(&paths.run).unwrap().mode() & 0o777,
        0o755
    );
    assert_eq!(
        bind_unix(paths, gid).unwrap_err().to_string(),
        ALREADY_RUNNING
    );
    drop(listener);
    let again = bind_unix(paths, gid).expect("a stale socket is replaced");
    drop(again);
    std::fs::remove_file(&socket).unwrap();
    std::fs::write(&socket, "x").unwrap();
    assert_eq!(
        bind_unix(paths, gid).unwrap_err().to_string(),
        SOCKET_OCCUPIED
    );
}

#[test]
fn tcp_listeners_follow_the_address_family() {
    let node = Node::new("sub-srv-tcp");
    let root = &node.ctx.paths.system_root;
    let v4 = bind_tcp(0, root).unwrap();
    assert_eq!(v4.len(), 1);
    assert!(v4[0].local_addr().unwrap().is_ipv4(), "no IPv6 on this system root");
    let busy = v4[0].local_addr().unwrap().port();
    assert!(bind_tcp(busy, root)
        .unwrap_err()
        .to_string()
        .starts_with(&format!("订阅端口 {busy} 无法监听")));
    if TcpListener::bind("[::1]:0").is_err() {
        return;
    }
    let proc = root.join("proc");
    std::fs::create_dir_all(proc.join("net")).unwrap();
    std::fs::write(proc.join("net/if_inet6"), "").unwrap();
    std::fs::create_dir_all(proc.join("sys/net/ipv6")).unwrap();
    std::fs::write(proc.join("sys/net/ipv6/bindv6only"), "1\n").unwrap();
    let split = bind_tcp(0, root).unwrap();
    assert_eq!(split.len(), 2, "v6-only sockets need a separate IPv4 listener");
    assert_eq!(
        split[0].local_addr().unwrap().port(),
        split[1].local_addr().unwrap().port()
    );
}

fn serve_files(node: &Node) {
    let paths = &node.ctx.paths;
    DeviceStore::write(paths, &[device("00000000000000aa", "a", TOKEN)]).unwrap();
    let published = Published {
        generation: "0".repeat(24),
        formats: [("singbox".to_owned(), "{\"v\":1}\n".to_owned())]
            .into_iter()
            .collect(),
    };
    snapshot::write(paths, &published).unwrap();
}

fn get(port: u16, path: &str) -> String {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    write!(stream, "GET {path} HTTP/1.1\r\nHost: x\r\n\r\n").unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).unwrap();
    response
}

#[test]
fn run_serves_connections_from_every_acceptor() {
    let node = Node::new("sub-srv-run");
    serve_files(&node);
    let first = TcpListener::bind("127.0.0.1:0").unwrap();
    let second = TcpListener::bind("127.0.0.1:0").unwrap();
    let ports = [
        first.local_addr().unwrap().port(),
        second.local_addr().unwrap().port(),
    ];
    let paths = node.ctx.paths.clone();
    std::thread::spawn(move || {
        let acceptors: Vec<Box<dyn Acceptor>> = vec![Box::new(first), Box::new(second)];
        run(&paths, acceptors, PoolSize::default())
    });
    for port in ports {
        let ok = get(port, &format!("/sub/{TOKEN}/singbox"));
        assert!(ok.starts_with("HTTP/1.1 200 OK\r\n") && ok.ends_with("{\"v\":1}\n"));
        assert!(get(port, "/").starts_with("HTTP/1.1 404 Not Found\r\n"));
    }
    assert!(run(&node.ctx.paths, Vec::new(), PoolSize::default()).is_err());
}

#[test]
fn a_full_queue_drops_new_connections() {
    let node = Node::new("sub-srv-pool");
    let limits = Limits {
        io_timeout: Duration::from_secs(2),
        linger: Duration::from_millis(10),
    };
    let size = PoolSize {
        workers: 1,
        queue: 1,
    };
    let pool = Pool::start(&node.ctx.paths, size, limits).unwrap();
    let mut clients = Vec::new();
    let mut submit = || {
        let (client, server) = UnixStream::pair().unwrap();
        clients.push(client);
        pool.submit(Box::new(server))
    };
    assert!(submit(), "taken by the worker (blocks reading)");
    std::thread::sleep(Duration::from_millis(200));
    assert!(submit(), "queued");
    assert!(!submit(), "queue full: dropped");
    drop(clients);
}

#[test]
fn serve_in_ip_mode_listens_on_tcp() {
    let node = Node::new("sub-srv-serve");
    serve_files(&node);
    let port = crate::cert::testing::free_port();
    node.save(&ip(port));
    let ctx = node.ctx.clone();
    std::thread::spawn(move || serve(&ctx));
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while TcpStream::connect(("127.0.0.1", port)).is_err() {
        assert!(std::time::Instant::now() < deadline, "worker did not listen");
        std::thread::sleep(Duration::from_millis(20));
    }
    let ok = get(port, &format!("/sub/{TOKEN}/singbox"));
    assert!(ok.starts_with("HTTP/1.1 200 OK\r\n"), "{ok}");
    DeviceStore::write(&node.ctx.paths, &[]).unwrap();
    assert!(get(port, &format!("/sub/{TOKEN}/singbox")).starts_with("HTTP/1.1 404"));
}
