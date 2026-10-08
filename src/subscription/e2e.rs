//! Real nginx/core integration, deliberately excluded from ordinary unit runs.
//! CI: ONEBOX_TEST_BINARY=target/debug/onebox ONEBOX_TEST_SINGBOX=/path/sing-box
//! ONEBOX_NGINX_BIN=/path/nginx cargo test --lib native_site_subscription -- --ignored --nocapture
//! ONEBOX_SITE_CONFIG_ONLY=1 runs only generated nginx configuration checks.
use super::*;
use crate::{
    context::Paths,
    model::{Core, Protocol},
    render,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use std::{
    env,
    path::Path,
    process::{Child, Command, Stdio},
    time::Instant,
};

struct Temp(PathBuf);
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
struct ChildGuard(Child);
impl Drop for ChildGuard {
    fn drop(&mut self) {
        // A process group also owns nginx workers. Never kill a reused PID.
        if matches!(self.0.try_wait(), Ok(None)) {
            unsafe {
                libc::kill(-(self.0.id() as i32), libc::SIGTERM);
            }
            let until = Instant::now() + Duration::from_secs(3);
            while Instant::now() < until {
                if !matches!(self.0.try_wait(), Ok(None)) {
                    return;
                }
                thread::sleep(Duration::from_millis(20));
            }
            unsafe {
                libc::kill(-(self.0.id() as i32), libc::SIGKILL);
            }
            let _ = self.0.wait();
        }
    }
}
struct Environment(&'static str, Option<std::ffi::OsString>);
impl Environment {
    fn set(key: &'static str, value: &Path) -> Self {
        let previous = env::var_os(key);
        env::set_var(key, value);
        Self(key, previous)
    }
}
impl Drop for Environment {
    fn drop(&mut self) {
        if let Some(v) = &self.1 {
            env::set_var(self.0, v);
        } else {
            env::remove_var(self.0);
        }
    }
}
fn start(ctx: &Context, executable: &Path, args: &[String], label: &str) -> Result<ChildGuard> {
    use std::os::unix::process::CommandExt;
    let log = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(ctx.paths.log.join(format!("{label}.log")))?;
    let mut command = Command::new(executable);
    command
        .args(args)
        .stdin(Stdio::null())
        .stdout(log.try_clone()?)
        .stderr(log);
    command
        .env("ONEBOX_DIR", &ctx.paths.root)
        .env("ONEBOX_RUN_DIR", &ctx.paths.run)
        .env("ONEBOX_SITE_ROOT", &ctx.paths.site_root)
        .env("ONEBOX_INIT", "none");
    unsafe {
        command.pre_exec(|| {
            if libc::setsid() < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    Ok(ChildGuard(command.spawn()?))
}
fn wait_tcp(child: &mut ChildGuard, port: u16) -> Result<()> {
    let until = Instant::now() + Duration::from_secs(8);
    while Instant::now() < until {
        if let Some(status) = child.0.try_wait()? {
            return Err(format!("E2E child exited: {status}").into());
        }
        if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(25));
    }
    Err(format!("E2E listener {port} did not start").into())
}
fn port() -> u16 {
    TcpListener::bind(("127.0.0.1", 0))
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}
fn certificate(ctx: &Context, directory: &Path, ca: &Path, ca_key: &Path) -> Result<()> {
    fs::create_dir_all(directory)?;
    let key = directory.join("key.pem");
    let csr = directory.join("request.csr");
    ctx.run(
        "openssl",
        &[
            "req",
            "-new",
            "-newkey",
            "ec",
            "-pkeyopt",
            "ec_paramgen_curve:P-256",
            "-nodes",
            "-keyout",
            util::path_str(&key)?,
            "-out",
            util::path_str(&csr)?,
            "-subj",
            "/CN=onebox-site.test",
        ],
    )?;
    let ext = directory.join("extensions");
    fs::write(&ext, "subjectAltName=DNS:onebox-site.test\nextendedKeyUsage=serverAuth\nbasicConstraints=critical,CA:FALSE\n")?;
    ctx.run(
        "openssl",
        &[
            "x509",
            "-req",
            "-days",
            "2",
            "-sha256",
            "-in",
            util::path_str(&csr)?,
            "-CA",
            util::path_str(ca)?,
            "-CAkey",
            util::path_str(ca_key)?,
            "-CAcreateserial",
            "-extfile",
            util::path_str(&ext)?,
            "-out",
            util::path_str(&directory.join("cert.pem"))?,
        ],
    )?;
    cert::validate_pair(
        ctx,
        &directory.join("cert.pem"),
        &key,
        "onebox-site.test",
        true,
    )
}
fn check_nginx(ctx: &Context, nginx: &Path, prefix: &Path, text: String) -> Result<PathBuf> {
    fs::create_dir_all(prefix)?;
    let conf = prefix.join("nginx.conf");
    util::atomic_write(&conf, text.as_bytes(), 0o600)?;
    let check = if env::var("ONEBOX_SITE_CONFIG_ONLY").as_deref() == Ok("1") {
        // The local sandbox maps only UID 0. Keep the production file intact;
        // nginx -t otherwise fails its chown syscall before checking TLS/paths.
        // Full CI uses the exact generated worker identity without this copy.
        let check = prefix.join("nginx-check.conf");
        let rest = text
            .split_once('\n')
            .ok_or("nginx user directive missing")?
            .1;
        let high_http = port();
        let high_tls = port();
        let mut loopback = String::new();
        for (index, part) in rest.split("listen ").enumerate() {
            if index == 0 {
                loopback.push_str(part);
                continue;
            }
            let (address, suffix) = part
                .split_once(|c: char| c.is_whitespace() || c == ';')
                .ok_or("invalid listen directive")?;
            let sep = &part[address.len()..address.len() + 1];
            let number = address
                .rsplit(':')
                .next()
                .unwrap_or(address)
                .parse::<u16>()?;
            let mapped = if number == 80 {
                high_http
            } else if number == 443 {
                high_tls
            } else {
                number
            };
            let host = if address.starts_with('[') {
                "[::1]"
            } else {
                "127.0.0.1"
            };
            loopback.push_str(&format!("listen {host}:{mapped}{sep}{suffix}"));
        }
        util::atomic_write(
            &check,
            format!("user root root;\n{loopback}").as_bytes(),
            0o600,
        )?;
        check
    } else {
        conf.clone()
    };
    ctx.run(
        util::path_str(nginx)?,
        &[
            "-t",
            "-p",
            util::path_str(prefix)?,
            "-c",
            util::path_str(&check)?,
        ],
    )?;
    Ok(conf)
}
fn start_nginx(ctx: &Context, nginx: &Path, prefix: &Path, conf: &Path) -> Result<ChildGuard> {
    start(
        ctx,
        nginx,
        &[
            "-p".into(),
            prefix.display().to_string(),
            "-c".into(),
            conf.display().to_string(),
            "-g".into(),
            "daemon off;".into(),
        ],
        "nginx",
    )
}
fn fetch(
    ctx: &Context,
    ca: &Path,
    port: u16,
    path: &str,
    head: bool,
    tls: bool,
) -> Result<(u16, String, String)> {
    let id = util::random_hex(8)?;
    let body = ctx.paths.log.join(format!("body-{id}"));
    let headers = ctx.paths.log.join(format!("headers-{id}"));
    let scheme = if tls { "https" } else { "http" };
    let url = format!("{scheme}://onebox-site.test:{port}{path}");
    let mut args = vec![
        "--silent".into(),
        "--show-error".into(),
        "--noproxy".into(),
        "*".into(),
        "--path-as-is".into(),
        "--connect-timeout".into(),
        "3".into(),
        "--max-time".into(),
        "8".into(),
        "--resolve".into(),
        format!("onebox-site.test:{port}:127.0.0.1"),
        "--cacert".into(),
        ca.display().to_string(),
        "--dump-header".into(),
        headers.display().to_string(),
        "--output".into(),
        body.display().to_string(),
        "--write-out".into(),
        "%{http_code}".into(),
    ];
    if tls {
        args.extend(["--tlsv1.3".into(), "--tls-max".into(), "1.3".into()]);
    }
    if head {
        args.push("--head".into());
    }
    args.push(url);
    let result = ctx.output("curl", &args.iter().map(String::as_str).collect::<Vec<_>>())?;
    if !result.success() {
        return Err(format!("E2E curl failed: {}", result.stderr).into());
    }
    let status = result.stdout.trim().parse()?;
    Ok((
        status,
        fs::read_to_string(&body)?,
        fs::read_to_string(&headers)?,
    ))
}
fn write_generation(ctx: &Context, state: &State) -> Result<Published> {
    let snapshot = render_snapshot(ctx, state)?;
    write_snapshot(ctx, &snapshot)?;
    Ok(snapshot)
}
fn core(ctx: &Context, sb: &Path, state: &State) -> Result<ChildGuard> {
    let mut value = render::server(ctx, state, Core::Singbox)?;
    for inbound in value["inbounds"].as_array_mut().ok_or("missing inbound")? {
        inbound["listen"] = "127.0.0.1".into();
    }
    let conf = ctx.paths.root.join("e2e-singbox.json");
    util::atomic_write(&conf, &serde_json::to_vec_pretty(&value)?, 0o600)?;
    ctx.run(
        util::path_str(sb)?,
        &["check", "-c", util::path_str(&conf)?],
    )?;
    start(
        ctx,
        sb,
        &["run".into(), "-c".into(), conf.display().to_string()],
        "singbox",
    )
}

#[test]
#[ignore = "requires real nginx, onebox and sing-box; binds isolated CI TCP 80/443"]
fn native_site_subscription() -> Result<()> {
    let nginx =
        PathBuf::from(env::var("ONEBOX_NGINX_BIN").unwrap_or_else(|_| "/usr/sbin/nginx".into()));
    let config_only = env::var("ONEBOX_SITE_CONFIG_ONLY").as_deref() == Ok("1");
    let temp = Temp(env::temp_dir().join(format!("onebox-site-e2e-{}", util::random_hex(8)?)));
    fs::create_dir(&temp.0)?;
    fs::set_permissions(&temp.0, fs::Permissions::from_mode(0o755))?;
    let ctx = Context {
        paths: Paths::isolated(&temp.0),
        ..Context::default()
    };
    for p in [
        &ctx.paths.root,
        &ctx.paths.log,
        &ctx.paths.run,
        &ctx.paths.site_root,
    ] {
        fs::create_dir_all(p)?;
        fs::set_permissions(p, fs::Permissions::from_mode(0o755))?;
    }
    let ca = temp.0.join("ca.pem");
    let ca_key = temp.0.join("ca.key");
    ctx.run(
        "openssl",
        &[
            "req",
            "-x509",
            "-newkey",
            "ec",
            "-pkeyopt",
            "ec_paramgen_curve:P-256",
            "-nodes",
            "-days",
            "2",
            "-subj",
            "/CN=Onebox E2E isolated CA",
            "-addext",
            "basicConstraints=critical,CA:TRUE",
            "-keyout",
            util::path_str(&ca_key)?,
            "-out",
            util::path_str(&ca)?,
        ],
    )?;
    let _ca_env = Environment::set("SSL_CERT_FILE", &ca);
    certificate(&ctx, &ctx.paths.site(), &ca, &ca_key)?;
    certificate(&ctx, &dir(&ctx).join("tls"), &ca, &ca_key)?;
    let marker = format!("onebox-content-{}", util::random_hex(12)?);
    util::atomic_write(
        &ctx.paths.site_root.join("index.html"),
        marker.as_bytes(),
        0o644,
    )?;
    let challenge = ctx.paths.site_root.join(".well-known/acme-challenge/check");
    util::atomic_write(&challenge, b"acme-local-marker", 0o644)?;
    let inner_port = port();
    let other_port = port();
    let standalone_port = port();
    let mut state = State::default();
    for (key, value) in [
        ("PROTOCOLS", "anytls-reality"),
        ("SERVER_ADDR", "127.0.0.1"),
        ("PASSWORD", "first-node-password"),
        ("UUID", "11111111-2222-4333-8444-555555555555"),
        ("NODE_NAME", "e2e"),
        ("REALITY_SITE_ENABLED", "1"),
        ("REALITY_SITE_HTTPS", "1"),
        ("REALITY_SITE_DOMAIN", "onebox-site.test"),
        ("REALITY_SNI", "onebox-site.test"),
        ("REALITY_SHORT_ID", "0123456789abcdef"),
        ("BLOCK_PRIVATE", "0"),
        ("BLOCK_BT", "0"),
        ("SUBSCRIPTION_DOMAIN", "onebox-site.test"),
    ] {
        state.set(key, value);
    }
    state.set_core(Protocol::AnytlsReality, Core::Singbox);
    state.set_port(Protocol::AnytlsReality, 443);
    state.set("REALITY_SITE_PORT", inner_port);
    state.set("REALITY_DEST", format!("127.0.0.1:{inner_port}"));
    let key = temp.0.join("reality.pem");
    let private = temp.0.join("private.der");
    let public = temp.0.join("public.der");
    ctx.run(
        "openssl",
        &[
            "genpkey",
            "-algorithm",
            "X25519",
            "-out",
            util::path_str(&key)?,
        ],
    )?;
    ctx.run(
        "openssl",
        &[
            "pkey",
            "-in",
            util::path_str(&key)?,
            "-outform",
            "DER",
            "-out",
            util::path_str(&private)?,
        ],
    )?;
    ctx.run(
        "openssl",
        &[
            "pkey",
            "-in",
            util::path_str(&key)?,
            "-pubout",
            "-outform",
            "DER",
            "-out",
            util::path_str(&public)?,
        ],
    )?;
    let secret = fs::read(private)?;
    let public = fs::read(public)?;
    state.set(
        "REALITY_PRIVATE_KEY",
        URL_SAFE_NO_PAD.encode(&secret[secret.len() - 32..]),
    );
    state.set(
        "REALITY_PUBLIC_KEY",
        URL_SAFE_NO_PAD.encode(&public[public.len() - 32..]),
    );
    let mut settings = Settings {
        enabled: true,
        mode: "site".into(),
        domain: "onebox-site.test".into(),
        port: 443,
        method: "custom".into(),
        ..Settings::default()
    };
    let (device, token) = new_device(&mut settings, "e2e-device")?;
    save(&ctx, &settings)?;
    util::atomic_write(&ctx.paths.state(), &serde_json::to_vec(&state)?, 0o600)?;
    let first = write_generation(&ctx, &state)?;
    assert_eq!(
        first.formats.keys().cloned().collect::<Vec<_>>(),
        ["singbox", "singbox-notun"]
    );
    let conf = check_nginx(
        &ctx,
        &nginx,
        &ctx.paths.site(),
        site::config(&ctx, &state, false, false)?,
    )?;
    assert!(
        !fs::read_to_string(&conf)?.contains("listen 443 ssl"),
        "REALITY already owns 443"
    );
    let mut switched = state.clone();
    switched.set_port(Protocol::AnytlsReality, other_port);
    let switched_config = site::config(&ctx, &switched, false, false)?;
    assert!(switched_config.contains("listen 443 ssl"));
    check_nginx(
        &ctx,
        &nginx,
        &temp.0.join("check-switched"),
        switched_config.clone(),
    )?;
    switched.set("REALITY_SITE_HTTPS", 0);
    assert!(validate_site_endpoint(&settings, &switched).is_err());
    switched.set("REALITY_SITE_HTTPS", 1);
    let mut site_conflict = switched.clone();
    site_conflict.set("PROTOCOLS", "anytls-reality trojan");
    site_conflict.set_port(Protocol::Trojan, 443);
    assert!(
        site::reserve_validate(&ctx, &site_conflict).is_err(),
        "nginx must not replace another protocol on TCP443"
    );
    let mut standalone = settings.clone();
    standalone.mode = "standalone".into();
    standalone.port = standalone_port;
    check_nginx(
        &ctx,
        &nginx,
        &dir(&ctx).join("web"),
        web_config(&ctx, &standalone, false)?,
    )?;
    let mut conflict = standalone.clone();
    conflict.port = 443;
    assert!(validate_standalone_ports(&ctx, &conflict, &state).is_err());
    if config_only {
        println!("generated REALITY/site/standalone nginx configurations verified");
        return Ok(());
    }

    let binary = PathBuf::from(env::var("ONEBOX_TEST_BINARY").expect("set ONEBOX_TEST_BINARY"));
    let sb = PathBuf::from(env::var("ONEBOX_TEST_SINGBOX").expect("set ONEBOX_TEST_SINGBOX"));
    let mut worker = start(
        &ctx,
        &binary,
        &["subscription".into(), "serve".into()],
        "subscription",
    )?;
    let until = Instant::now() + Duration::from_secs(5);
    while !socket_path(&ctx).exists() && Instant::now() < until {
        assert!(worker.0.try_wait()?.is_none());
        thread::sleep(Duration::from_millis(20));
    }
    assert!(socket_path(&ctx).exists());
    let mut web = start_nginx(&ctx, &nginx, &ctx.paths.site(), &conf)?;
    wait_tcp(&mut web, inner_port)?;
    let (status, body, _) = fetch(
        &ctx,
        &ca,
        80,
        "/.well-known/acme-challenge/check",
        false,
        false,
    )?;
    assert_eq!(status, 200);
    assert_eq!(body, "acme-local-marker");
    let (status, _, headers) = fetch(&ctx, &ca, 80, "/", false, false)?;
    assert_eq!(status, 301);
    assert!(headers.contains("https://onebox-site.test/"));
    let mut reality = core(&ctx, &sb, &state)?;
    wait_tcp(&mut reality, 443)?;
    let (status, body, _) = fetch(&ctx, &ca, 443, "/", false, true)?;
    assert_eq!(status, 200);
    assert_eq!(body, marker);
    let url = format!("/sub/{token}/singbox");
    let (status, body, headers) = fetch(&ctx, &ca, 443, &url, false, true)?;
    assert_eq!(status, 200);
    assert_eq!(body, first.formats["singbox"]);
    assert!(headers.to_lowercase().contains("no-store"));
    assert!(!body.contains(state.get("REALITY_PRIVATE_KEY")));
    assert!(!body.contains("PRIVATE KEY"));
    let (status, head, _) = fetch(&ctx, &ca, 443, &url, true, true)?;
    assert_eq!(status, 200);
    assert!(!head.contains("first-node-password"));
    let post = ctx.run(
        "curl",
        &[
            "--silent",
            "--show-error",
            "--noproxy",
            "*",
            "--max-time",
            "8",
            "--resolve",
            "onebox-site.test:443:127.0.0.1",
            "--cacert",
            util::path_str(&ca)?,
            "--request",
            "POST",
            "--output",
            "/dev/null",
            "--write-out",
            "%{http_code}",
            &format!("https://onebox-site.test{url}"),
        ],
    )?;
    assert_eq!(post, "403", "nginx must reject methods other than GET/HEAD");
    for path in [
        format!("/sub/{}/singbox", "0".repeat(64)),
        format!("/sub/{token}/mihomo"),
        format!("/sub/{token}/base64"),
        format!("/sub/{token}/provider"),
        format!("/sub/{token}/xray"),
        format!("/sub/{token}/key.pem"),
        format!("/sub/{token}/singbox?x=1"),
        format!("/sub/{token}/../../tls/key.pem"),
        "/.onebox-site-owned".into(),
    ] {
        let (status, body, _) = fetch(&ctx, &ca, 443, &path, false, true)?;
        assert!([403, 404].contains(&status), "path status {status}");
        assert!(!body.contains("PRIVATE KEY"));
    }
    state.set("PASSWORD", "second-node-password");
    let second = render_snapshot(&ctx, &state)?;
    let writer_ctx = ctx.clone();
    let a = first.clone();
    let b = second.clone();
    let writer = thread::spawn(move || {
        for i in 0..80 {
            write_snapshot(&writer_ctx, if i % 2 == 0 { &a } else { &b }).unwrap();
            thread::sleep(Duration::from_millis(2));
        }
    });
    for _ in 0..10 {
        let (status, body, _) = fetch(&ctx, &ca, 443, &url, false, true)?;
        assert_eq!(status, 200);
        assert!(body == first.formats["singbox"] || body == second.formats["singbox"]);
        serde_json::from_str::<serde_json::Value>(&body)?;
    }
    writer.join().unwrap();
    write_snapshot(&ctx, &second)?;
    assert!(fetch(&ctx, &ca, 443, &url, false, true)?
        .1
        .contains("second-node-password"));
    drop(reality);
    drop(web);
    // The same public URL survives moving REALITY off 443 and placing nginx
    // HTTPS reverse proxy in front of the internal TLS 1.3 website.
    util::atomic_write(&conf, switched_config.as_bytes(), 0o600)?;
    web = start_nginx(&ctx, &nginx, &ctx.paths.site(), &conf)?;
    wait_tcp(&mut web, 443)?;
    let (status, body, _) = fetch(&ctx, &ca, 443, "/", false, true)?;
    assert_eq!(status, 200);
    assert_eq!(body, marker);
    assert_eq!(fetch(&ctx, &ca, 443, &url, false, true)?.0, 200);
    let standalone_conf = dir(&ctx).join("web/nginx.conf");
    save(&ctx, &standalone)?;
    let mut independent = start_nginx(&ctx, &nginx, &dir(&ctx).join("web"), &standalone_conf)?;
    wait_tcp(&mut independent, standalone_port)?;
    assert_eq!(fetch(&ctx, &ca, standalone_port, &url, false, true)?.0, 200);
    command(&ctx, &["revoke".into(), device])?;
    assert_eq!(fetch(&ctx, &ca, 443, &url, false, true)?.0, 404);
    assert_eq!(fetch(&ctx, &ca, standalone_port, &url, false, true)?.0, 404);
    drop(independent);
    drop(web);
    drop(worker);
    for name in ["nginx.log", "subscription.log", "singbox.log"] {
        assert!(
            !fs::read_to_string(ctx.paths.log.join(name))?.contains(&token),
            "request token leaked into runtime logs"
        );
    }
    println!("HTTP, TLS1.3, REALITY443, HTTPS reverse proxy, standalone subscription, atomic update and revoke verified");
    Ok(())
}

fn fetch_ip(settings: &Settings, path: &str, method: &str) -> Result<(u16, String, String)> {
    let address = std::net::SocketAddr::new(settings.domain.parse()?, settings.port);
    let mut stream = std::net::TcpStream::connect_timeout(&address, Duration::from_secs(3))?;
    stream.set_read_timeout(Some(Duration::from_secs(8)))?;
    stream.set_write_timeout(Some(Duration::from_secs(3)))?;
    let url = endpoint(settings);
    let host = url
        .strip_prefix("http://")
        .ok_or("IP subscription must use HTTP")?;
    write!(
        stream,
        "{method} {path} HTTP/1.0\r\nHost: {host}\r\nConnection: close\r\n\r\n"
    )?;
    let mut response = String::new();
    stream.read_to_string(&mut response)?;
    let (headers, body) = response
        .split_once("\r\n\r\n")
        .ok_or("missing HTTP headers")?;
    let status = headers
        .split_whitespace()
        .nth(1)
        .ok_or("missing HTTP status")?
        .parse()?;
    Ok((status, body.into(), headers.into()))
}

fn ip_subscription_case(address: &str) -> Result<()> {
    let nginx =
        PathBuf::from(env::var("ONEBOX_NGINX_BIN").unwrap_or_else(|_| "/usr/sbin/nginx".into()));
    let temp = Temp(env::temp_dir().join(format!("onebox-ip-e2e-{}", util::random_hex(8)?)));
    fs::create_dir(&temp.0)?;
    fs::set_permissions(&temp.0, fs::Permissions::from_mode(0o755))?;
    let ctx = Context {
        paths: Paths::isolated(&temp.0),
        ..Context::default()
    };
    for path in [&ctx.paths.root, &ctx.paths.run, &ctx.paths.log] {
        fs::create_dir_all(path)?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o755))?;
    }
    let mut state = State::default();
    for (key, value) in [
        ("PROTOCOLS", "vless-reality"),
        ("SERVER_ADDR", address),
        ("UUID", "11111111-2222-4333-8444-555555555555"),
        ("NODE_NAME", "ip-first-node"),
        ("REALITY_SNI", "example.com"),
        ("REALITY_SHORT_ID", "0123456789abcdef"),
        (
            "REALITY_PRIVATE_KEY",
            "never-publish-this-server-private-key",
        ),
        (
            "REALITY_PUBLIC_KEY",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        ),
    ] {
        state.set(key, value);
    }
    state.set_core(Protocol::VlessReality, Core::Singbox);
    state.set_port(Protocol::VlessReality, 443);
    let mut settings = Settings {
        enabled: true,
        mode: "ip".into(),
        domain: address.into(),
        port: port(),
        method: "none".into(),
        ..Settings::default()
    };
    let (device, token) = new_device(&mut settings, "ip-client")?;
    // Use the production transaction preparation path to enable IP hosting.
    state.set("SUBSCRIPTION_SETTINGS_EXPECTED", "absent");
    state.set(
        "SUBSCRIPTION_SETTINGS_PENDING",
        serde_json::to_string(&settings)?,
    );
    prepare(&ctx, &mut state)?;
    assert_eq!(load(&ctx)?.mode, "ip");
    let first = write_generation(&ctx, &state)?;
    assert_eq!(first.formats.len(), FORMATS.len());
    let expected_host = if address.contains(':') {
        format!("[{address}]")
    } else {
        address.into()
    };
    assert_eq!(
        endpoint(&settings),
        format!("http://{expected_host}:{}", settings.port)
    );
    let config = web_config(&ctx, &settings, false)?;
    assert!(!config.contains("ssl_certificate"));
    assert!(!config.contains("acme-challenge"));
    let conf = check_nginx(&ctx, &nginx, &dir(&ctx), config)?;
    assert!(!dir(&ctx).join("tls").exists());
    assert!(!ctx.paths.site().exists());
    assert!(!ctx.paths.site_root.exists());
    if env::var("ONEBOX_SITE_CONFIG_ONLY").as_deref() == Ok("1") {
        println!("IP {address} nginx configuration verified without DNS/certificates");
        return Ok(());
    }
    let binary = PathBuf::from(env::var("ONEBOX_TEST_BINARY").expect("set ONEBOX_TEST_BINARY"));
    let mut worker = start(
        &ctx,
        &binary,
        &["subscription".into(), "serve".into()],
        "subscription",
    )?;
    let until = Instant::now() + Duration::from_secs(5);
    while !socket_path(&ctx).exists() && Instant::now() < until {
        assert!(worker.0.try_wait()?.is_none());
        thread::sleep(Duration::from_millis(20));
    }
    assert!(socket_path(&ctx).exists());
    let mut web = start_nginx(&ctx, &nginx, &dir(&ctx), &conf)?;
    wait_tcp(&mut web, settings.port)?;
    for format in FORMATS {
        let path = format!("/sub/{token}/{format}");
        let (status, body, headers) = fetch_ip(&settings, &path, "GET")?;
        assert_eq!(status, 200, "{address}/{format}");
        assert_eq!(body, first.formats[format]);
        assert!(headers.to_ascii_lowercase().contains("no-store"));
        assert!(!body.contains(state.get("REALITY_PRIVATE_KEY")));
        let (status, body, headers) = fetch_ip(&settings, &path, "HEAD")?;
        assert_eq!(status, 200);
        assert!(body.is_empty());
        assert!(headers
            .to_ascii_lowercase()
            .contains(&format!("content-length: {}", first.formats[format].len())));
    }
    let path = format!("/sub/{token}/singbox");
    assert_eq!(fetch_ip(&settings, &path, "POST")?.0, 403);
    for invalid in [
        format!("/sub/{}/singbox", "0".repeat(64)),
        format!("/sub/{token}/state.json"),
        format!("/sub/{token}/singbox?extra=1"),
        "/".into(),
    ] {
        assert_eq!(fetch_ip(&settings, &invalid, "GET")?.0, 404);
    }
    state.set("NODE_NAME", "ip-refreshed-node");
    state.set_port(Protocol::VlessReality, 14443);
    let second = write_generation(&ctx, &state)?;
    assert_ne!(first.formats["singbox"], second.formats["singbox"]);
    assert_eq!(
        fetch_ip(&settings, &path, "GET")?.1,
        second.formats["singbox"]
    );
    // The same URL pauses and resumes across disabled/enabled settings.
    settings.enabled = false;
    save(&ctx, &settings)?;
    assert_eq!(fetch_ip(&settings, &path, "GET")?.0, 404);
    settings.enabled = true;
    save(&ctx, &settings)?;
    assert_eq!(fetch_ip(&settings, &path, "GET")?.0, 200);
    command(&ctx, &["revoke".into(), device])?;
    assert_eq!(fetch_ip(&settings, &path, "GET")?.0, 404);
    drop(web);
    drop(worker);
    for name in ["nginx.log", "subscription.log"] {
        assert!(
            !fs::read_to_string(ctx.paths.log.join(name))?.contains(&token),
            "IP request token leaked into runtime logs"
        );
    }
    assert!(!dir(&ctx).join("tls").exists());
    println!("IP {address}: HTTP GET/HEAD, all formats, authorization, stable refresh URL and revoke verified without DNS/certificates");
    Ok(())
}

#[test]
#[ignore = "requires real nginx and onebox; starts isolated HTTP listeners"]
fn native_ip_subscription() -> Result<()> {
    ip_subscription_case("127.0.0.1")?;
    if site::ipv6_available() {
        ip_subscription_case("::1")?;
    } else {
        println!("IPv6 loopback unavailable; IPv4 IP subscription verified");
    }
    Ok(())
}
