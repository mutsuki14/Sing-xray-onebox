use super::*;
use crate::cert::testing::{
    acme_calls, engine, fake_acme, have_openssl, serve_release, AcmeScript, Fixture,
};
use crate::domain::config::{SubscriptionConfig, WebCert};
use crate::host::init::InitSystem;
use crate::render::fixtures::spec;
use crate::subscription::testing::{
    device, ip, nginx, reality, site, standalone, systemd, with_subscription, Node, Systemd, TOKEN,
};
use std::os::unix::net::UnixListener;

const PID: u32 = 4242;

fn eng(node: &Node) -> Engine<'_> {
    engine(&node.ctx, InitSystem::Systemd)
}

fn unit(paths: &Paths, name: &str) -> std::path::PathBuf {
    paths.systemd.join(format!("{name}.service"))
}

/// A node with systemd, nginx, a current `EXE` for the worker's PID.
fn host(label: &str) -> (Node, Systemd) {
    let node = Node::new(label);
    let systemd = node.systemd(PID);
    node.nginx();
    node.install_exe();
    node.proc_exe(PID, &node.ctx.paths.executable);
    (node, systemd)
}

#[test]
fn prepare_writes_migrated_devices_once_and_clears_on_reinstall() {
    let node = Node::new("sub-life-prepare");
    let paths = &node.ctx.paths;
    let engine = eng(&node);
    let v2 = [device("00000000000000aa", "手机", TOKEN)];
    prepare(&engine, &ip(8448), Some(&v2), false).unwrap();
    assert_eq!(DeviceStore::load(paths).unwrap().devices(), v2);
    let newer = [device("00000000000000bb", "laptop", TOKEN)];
    DeviceStore::write(paths, &newer).unwrap();
    prepare(&engine, &ip(8448), Some(&v2), false).unwrap();
    assert_eq!(
        DeviceStore::load(paths).unwrap().devices(),
        newer,
        "an existing devices.json is newer than the v2 list"
    );
    prepare(&engine, &reality(), Some(&v2), false).unwrap();
    assert_eq!(DeviceStore::load(paths).unwrap().devices().len(), 1);

    std::fs::write(paths.subscription_v2_settings(), "{}").unwrap();
    std::fs::write(paths.published(), "{}").unwrap();
    server::record(paths, Listener::Unix).unwrap();
    prepare(&engine, &ip(8448), Some(&v2), true).unwrap();
    for gone in [
        paths.devices(),
        paths.subscription_v2_settings(),
        paths.published(),
        server::listener_file(paths),
    ] {
        assert!(!gone.exists(), "{}", gone.display());
    }
    assert!(DeviceStore::load(paths).unwrap().is_empty());
}

#[test]
fn prepare_rechecks_the_address_family_and_the_socket_path() {
    let node = Node::new("sub-life-family");
    let engine = eng(&node);
    let v6 = with_subscription(
        reality(),
        SubscriptionConfig {
            mode: SubscriptionMode::Ip {
                address: "2001:db8::7".parse().unwrap(),
            },
            port: 8448,
        },
    );
    assert_eq!(
        prepare(&engine, &v6, None, false).unwrap_err().to_string(),
        "订阅地址为 IPv6，但当前系统无法监听 IPv6；请启用 IPv6 或使用 IPv4 地址"
    );
    std::fs::create_dir_all(node.ctx.paths.system("/proc/net")).unwrap();
    std::fs::write(node.ctx.paths.system("/proc/net/if_inet6"), "").unwrap();
    prepare(&engine, &v6, None, false).unwrap();

    let mut ctx = node.ctx.clone();
    ctx.paths.run = std::path::PathBuf::from(format!("/{}", "r".repeat(90)));
    let long = engine_for(&ctx);
    assert_eq!(
        prepare(&long, &site(), None, false)
            .unwrap_err()
            .to_string(),
        "订阅 Unix socket 路径过长"
    );
    prepare(&long, &ip(8448), None, false).expect("ip mode uses no socket");
}

fn engine_for(ctx: &crate::ctx::Ctx) -> Engine<'_> {
    engine(ctx, InitSystem::Systemd)
}

#[test]
fn services_per_mode() {
    let (node, systemd) = host("sub-life-services");
    let paths = &node.ctx.paths;
    let engine = eng(&node);
    configure_services(&engine, &standalone(WebCert::Cloudflare, 8448)).unwrap();
    let worker = std::fs::read_to_string(unit(paths, SERVICE)).unwrap();
    assert!(worker.contains("\"subscription\" \"serve\""), "{worker}");
    let web = std::fs::read_to_string(unit(paths, WEB_SERVICE)).unwrap();
    assert!(
        web.contains("After=network-online.target nss-lookup.target onebox-subscription.service")
    );
    std::fs::create_dir_all(paths.subscription()).unwrap();
    std::fs::write(frontend::conf_file(paths), "x").unwrap();

    configure_services(&engine, &ip(8448)).unwrap();
    assert!(unit(paths, SERVICE).exists());
    assert!(!unit(paths, WEB_SERVICE).exists(), "ip mode has no nginx");
    assert!(!frontend::conf_file(paths).exists());
    assert!(systemd.actions().contains(&format!("stop {WEB_SERVICE}")));

    configure_services(&engine, &site()).unwrap();
    assert!(unit(paths, SERVICE).exists() && !unit(paths, WEB_SERVICE).exists());

    configure_services(&engine, &reality()).unwrap();
    assert!(!unit(paths, SERVICE).exists(), "off: no worker unit");
    assert!(!paths.services().join(format!("{SERVICE}.json")).exists());
}

#[test]
fn publish_starts_the_worker_and_restarts_it_only_when_needed() {
    let (node, systemd) = host("sub-life-publish");
    let paths = &node.ctx.paths;
    let engine = eng(&node);
    node.listening(&[8448, 9000]);
    let cfg = ip(8448);
    publish(&engine, &cfg, &spec(&cfg)).unwrap();
    let snap = snapshot::load(paths).unwrap().unwrap();
    assert_eq!(snap.published_formats().len(), 6);
    assert_eq!(
        server::recorded(paths).unwrap(),
        Some(Listener::Tcp { port: 8448 })
    );
    assert_eq!(
        systemd.actions(),
        [format!("start {SERVICE}"), format!("enable {SERVICE}")]
    );

    let before = systemd.actions().len();
    publish(&engine, &cfg, &spec(&cfg)).unwrap();
    assert_eq!(
        systemd.actions()[before..],
        [format!("enable {SERVICE}")],
        "same program, same listener: the running worker keeps serving"
    );

    let old = node.dir.join("old-onebox");
    std::fs::write(&old, "old").unwrap();
    node.proc_exe(PID, &old);
    let before = systemd.actions().len();
    publish(&engine, &cfg, &spec(&cfg)).unwrap();
    assert_eq!(
        systemd.actions()[before],
        format!("restart {SERVICE}"),
        "self-update"
    );

    node.proc_exe(PID, &paths.executable);
    let moved = ip(9000);
    let before = systemd.actions().len();
    publish(&engine, &moved, &spec(&moved)).unwrap();
    assert_eq!(
        systemd.actions()[before],
        format!("restart {SERVICE}"),
        "new port"
    );
    assert_eq!(
        server::recorded(paths).unwrap(),
        Some(Listener::Tcp { port: 9000 })
    );
}

#[test]
fn publish_standalone_installs_the_config_and_starts_nginx() {
    let (node, systemd) = host("sub-life-standalone");
    let paths = &node.ctx.paths;
    let engine = eng(&node);
    std::fs::create_dir_all(&paths.run).unwrap();
    let _socket = UnixListener::bind(paths.subscription_socket()).unwrap();
    let cfg = standalone(WebCert::Http01, 8448);
    configure_services(&engine, &cfg).unwrap();
    publish(&engine, &cfg, &spec(&cfg)).unwrap();
    let conf = std::fs::read_to_string(frontend::conf_file(paths)).unwrap();
    assert!(conf.contains("listen 8448 ssl http2;") && conf.contains("server_name _;"));
    assert_eq!(server::recorded(paths).unwrap(), Some(Listener::Unix));
    assert_eq!(
        systemd.actions(),
        [
            format!("start {SERVICE}"),
            format!("enable {SERVICE}"),
            format!("restart {WEB_SERVICE}"),
            format!("enable {WEB_SERVICE}"),
        ]
    );

    // Switching to ip mode removes the dedicated nginx and its config, and
    // restarts the worker on TCP.
    node.listening(&[8448]);
    let to_ip = ip(8448);
    let before = systemd.actions().len();
    publish(&engine, &to_ip, &spec(&to_ip)).unwrap();
    assert!(!frontend::conf_file(paths).exists());
    assert!(!unit(paths, WEB_SERVICE).exists());
    let after = systemd.actions()[before..].to_vec();
    assert!(after.contains(&format!("stop {WEB_SERVICE}")), "{after:?}");
    assert!(after.contains(&format!("restart {SERVICE}")), "{after:?}");
}

#[test]
fn publish_of_a_disabled_subscription_removes_everything() {
    let (node, systemd) = host("sub-life-off");
    let paths = &node.ctx.paths;
    let engine = eng(&node);
    node.listening(&[8448]);
    let cfg = ip(8448);
    publish(&engine, &cfg, &spec(&cfg)).unwrap();
    let off = reality();
    publish(&engine, &off, &spec(&off)).unwrap();
    assert!(
        !paths.published().exists(),
        "credentials are not left on disk"
    );
    assert!(!server::listener_file(paths).exists());
    assert!(!unit(paths, SERVICE).exists());
    assert!(systemd.actions().contains(&format!("stop {SERVICE}")));
    publish(&engine, &off, &spec(&off)).expect("idempotent");
}

#[test]
fn a_worker_that_never_listens_fails_the_publish() {
    let node = Node::new("sub-life-wait");
    let paths = &node.ctx.paths;
    node.listening(&[]);
    let err = wait_listening(
        paths,
        Listener::Tcp { port: 8448 },
        Duration::from_millis(120),
    )
    .unwrap_err()
    .to_string();
    assert_eq!(
        err,
        "onebox-subscription 未能在 TCP 8448 上开始监听，请查看 onebox service onebox-subscription log"
    );
    node.listening(&[8448]);
    wait_listening(
        paths,
        Listener::Tcp { port: 8448 },
        Duration::from_millis(120),
    )
    .unwrap();
    assert!(wait_listening(paths, Listener::Unix, Duration::ZERO).is_err());
    std::fs::create_dir_all(&paths.run).unwrap();
    let _socket = UnixListener::bind(paths.subscription_socket()).unwrap();
    wait_listening(paths, Listener::Unix, Duration::ZERO).unwrap();
}

#[test]
fn acme_root_must_be_ours() {
    let node = Node::new("sub-life-acme");
    let root = node.dir.join("acme");
    prepare_acme_root(&root).unwrap();
    let mode = |p: &Path| {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(p).unwrap().permissions().mode() & 0o777
    };
    assert_eq!(mode(&root.join(".well-known/acme-challenge")), 0o755);
    assert_eq!(
        std::fs::read_to_string(root.join(OWNED_MARKER)).unwrap(),
        "onebox\n"
    );
    prepare_acme_root(&root).expect("ours: reused");
    let foreign = node.dir.join("foreign");
    std::fs::create_dir_all(&foreign).unwrap();
    std::fs::write(foreign.join("index.html"), "hi").unwrap();
    assert_eq!(
        prepare_acme_root(&foreign).unwrap_err().to_string(),
        ACME_FOREIGN
    );
    let empty = node.dir.join("empty");
    std::fs::create_dir_all(&empty).unwrap();
    prepare_acme_root(&empty).expect("an empty directory is taken over");
}

#[test]
fn certificates_only_for_standalone() {
    let node = Node::new("sub-life-cert-none");
    let engine = eng(&node);
    for cfg in [ip(8448), site(), reality()] {
        assert!(!prepare_certificates(&engine, &cfg, true, None).unwrap());
    }
    assert!(node.fake.history().is_empty(), "no program runs");
}

fn fixture_host(f: &Fixture) -> Systemd {
    let state = systemd(&f.fake, &f.ctx.paths, PID);
    nginx(&f.fake);
    crate::subscription::testing::listening(&f.ctx.paths, &[]);
    state
}

#[test]
fn custom_certificate_is_deployed_without_nginx_bootstrap() {
    if !have_openssl() {
        return;
    }
    let f = Fixture::new("sub-life-custom");
    let systemd = fixture_host(&f);
    let engine = engine(&f.ctx, InitSystem::Systemd);
    let (chain, key) =
        f.ca.leaf(&f.dir.join("src"), &["sub.example.com"], 90, false);
    let cfg = standalone(WebCert::Custom { cert: chain, key }, 8448);
    assert!(prepare_certificates(&engine, &cfg, false, None).unwrap());
    assert!(CertDir::subscription(&f.ctx.paths).has_pair());
    assert!(!prepare_certificates(&engine, &cfg, false, None).unwrap());
    assert!(systemd.actions().is_empty(), "{:?}", systemd.actions());
}

#[test]
fn http01_bootstraps_port_80_exactly_when_acme_runs() {
    if !have_openssl() {
        return;
    }
    let f = Fixture::new("sub-life-http01");
    serve_release(&f.fake);
    let systemd = fixture_host(&f);
    let engine = engine(&f.ctx, InitSystem::Systemd);
    let issued =
        f.ca.leaf(&f.dir.join("issued"), &["sub.example.com"], 90, false);
    fake_acme(
        &f.fake,
        AcmeScript {
            issue: Some(issued),
            ..AcmeScript::default()
        },
    );
    let cfg = standalone(WebCert::Http01, 8448);
    assert!(prepare_certificates(&engine, &cfg, false, None).unwrap());
    let paths = &f.ctx.paths;
    let conf = std::fs::read_to_string(frontend::conf_file(paths)).unwrap();
    assert!(
        conf.contains("listen 80;") && !conf.contains("ssl"),
        "{conf}"
    );
    assert_eq!(systemd.actions(), [format!("restart {WEB_SERVICE}")]);
    let call = acme_calls(&f.fake).pop().unwrap();
    let webroot = paths.subscription_acme().display().to_string();
    assert!(
        call.args.ends_with(&["--webroot".into(), webroot]),
        "{:?}",
        call.args
    );
    assert!(paths.subscription_acme().join(".onebox-owned").exists());

    // Valid pair and nginx serving the webroot: neither bootstrap nor acme.sh.
    let acme_before = acme_calls(&f.fake).len();
    assert!(!prepare_certificates(&engine, &cfg, false, None).unwrap());
    assert_eq!(acme_calls(&f.fake).len(), acme_before);
    assert_eq!(systemd.actions().len(), 1);

    // A forced renewal through the running nginx needs no bootstrap.
    assert!(prepare_certificates(&engine, &cfg, true, None).is_ok());
    assert_eq!(systemd.actions().len(), 1, "{:?}", systemd.actions());
    assert!(acme_calls(&f.fake).len() > acme_before);
}

#[test]
fn http01_bootstrap_refuses_a_busy_port_80() {
    if !have_openssl() {
        return;
    }
    let f = Fixture::new("sub-life-busy80");
    serve_release(&f.fake);
    fixture_host(&f);
    crate::subscription::testing::listening(&f.ctx.paths, &[80]);
    let engine = engine(&f.ctx, InitSystem::Systemd);
    let cfg = standalone(WebCert::Http01, 8448);
    assert_eq!(
        prepare_certificates(&engine, &cfg, false, None)
            .unwrap_err()
            .to_string(),
        PORT80_BUSY
    );
}
