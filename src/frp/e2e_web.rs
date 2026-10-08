//! Real domain routing through generated nginx -> frps -> frpc configuration.
use super::*;
use crate::context::{CommandOutput, Runner};
use std::os::unix::fs::PermissionsExt;

struct DeferNginxCheck {
    real: Arc<dyn Runner>,
    nginx: PathBuf,
}
impl Runner for DeferNginxCheck {
    fn output(&self, program: &str, args: &[String]) -> Result<CommandOutput> {
        // The generated wildcard listeners are remapped to loopback below.
        // Run real nginx -t on that otherwise unchanged configuration.
        if Path::new(program) == self.nginx && args.first().is_some_and(|v| v == "-t") {
            Ok(CommandOutput::default())
        } else {
            self.real.output(program, args)
        }
    }
}

fn web_certificate(ctx: &Context) -> Result<PathBuf> {
    let ca = ctx.paths.frp_root.join("web-ca.pem");
    let ca_key = ctx.paths.frp_root.join("web-ca-key.pem");
    let dir = ctx.paths.frp_root.join("web-tls");
    lifecycle::private_dir(&dir)?;
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
            "/CN=Isolated FRP web E2E CA",
            "-addext",
            "basicConstraints=critical,CA:TRUE",
            "-keyout",
            util::path_str(&ca_key)?,
            "-out",
            util::path_str(&ca)?,
        ],
    )?;
    let key = dir.join("key.pem");
    let csr = dir.join("request.csr");
    let ext = dir.join("extensions.cnf");
    util::atomic_write(&ext, b"basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:app.frp.example,DNS:*.apps.frp.example,DNS:unknown.frp.example\n", 0o600)?;
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
            "-subj",
            "/CN=app.frp.example",
            "-keyout",
            util::path_str(&key)?,
            "-out",
            util::path_str(&csr)?,
        ],
    )?;
    ctx.run(
        "openssl",
        &[
            "x509",
            "-req",
            "-in",
            util::path_str(&csr)?,
            "-CA",
            util::path_str(&ca)?,
            "-CAkey",
            util::path_str(&ca_key)?,
            "-set_serial",
            "2",
            "-days",
            "2",
            "-extfile",
            util::path_str(&ext)?,
            "-out",
            util::path_str(&dir.join("cert.pem"))?,
        ],
    )?;
    Ok(ca)
}

fn origin_reply(mut connection: TcpStream, marker: &str) -> std::io::Result<()> {
    connection.set_read_timeout(Some(Duration::from_secs(2)))?;
    connection.set_write_timeout(Some(Duration::from_secs(2)))?;
    let mut header = Vec::new();
    while !header.ends_with(b"\r\n\r\n") && header.len() < 16384 {
        let mut byte = [0u8];
        connection.read_exact(&mut byte)?;
        header.push(byte[0]);
    }
    let header = String::from_utf8_lossy(&header);
    let fields: BTreeMap<_, _> = header
        .lines()
        .skip(1)
        .filter_map(|line| {
            line.split_once(':')
                .map(|(k, v)| (k.to_ascii_lowercase(), v.trim().to_string()))
        })
        .collect();
    if header.starts_with("GET /socket ") {
        if fields.get("upgrade").map(|v| v.to_ascii_lowercase()) != Some("websocket".into())
            || !fields
                .get("connection")
                .is_some_and(|v| v.to_ascii_lowercase().contains("upgrade"))
            || fields.get("sec-websocket-key").map(String::as_str)
                != Some("dGhlIHNhbXBsZSBub25jZQ==")
        {
            connection.write_all(
                b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            )?;
            return Ok(());
        }
        connection.write_all(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n")?;
        let mut prefix = [0u8; 2];
        connection.read_exact(&mut prefix)?;
        if prefix[0] != 0x81 || prefix[1] & 0x80 == 0 || prefix[1] & 0x7f >= 126 {
            return Err(std::io::Error::other(
                "expected a short masked WebSocket text frame",
            ));
        }
        let mut mask = [0u8; 4];
        connection.read_exact(&mut mask)?;
        let mut data = vec![0u8; (prefix[1] & 0x7f) as usize];
        connection.read_exact(&mut data)?;
        for (i, byte) in data.iter_mut().enumerate() {
            *byte ^= mask[i % 4];
        }
        let reply = [marker.as_bytes(), b":", &data].concat();
        if reply.len() >= 126 {
            return Err(std::io::Error::other("test frame too long"));
        }
        connection.write_all(&[0x81, reply.len() as u8])?;
        connection.write_all(&reply)?;
    } else {
        let body = serde_json::to_vec(&serde_json::json!({
            "marker": marker,
            "host": fields.get("host"),
            "proto": fields.get("x-forwarded-proto"),
            "port": fields.get("x-forwarded-port"),
        }))?;
        connection.write_all(
            format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            )
            .as_bytes(),
        )?;
        connection.write_all(&body)?;
    }
    connection.shutdown(std::net::Shutdown::Both)?;
    Ok(())
}

fn fetch(
    lab: &Lab,
    ca: &Path,
    domain: &str,
    port: u16,
    tls: bool,
) -> Result<(u16, String, String)> {
    let key = util::random_hex(6)?;
    let body = lab.root.join(format!("body-{key}"));
    let headers = lab.root.join(format!("headers-{key}"));
    let output = Command::new("curl")
        .args([
            "--disable",
            "--silent",
            "--show-error",
            "--http1.1",
            "--noproxy",
            "*",
            "--connect-timeout",
            "1",
            "--max-time",
            "3",
            "--resolve",
            &format!("{domain}:{port}:127.0.0.1"),
            "--cacert",
            util::path_str(ca)?,
            "--output",
            util::path_str(&body)?,
            "--dump-header",
            util::path_str(&headers)?,
            "--write-out",
            "%{http_code}",
            &format!(
                "{}://{domain}:{port}/probe",
                if tls { "https" } else { "http" }
            ),
        ])
        .output()?;
    if !output.status.success() {
        return Err(format!(
            "HTTPS request failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    Ok((
        String::from_utf8(output.stdout)?.parse()?,
        fs::read_to_string(body)?,
        fs::read_to_string(headers)?,
    ))
}

fn websocket(lab: &mut Lab, ca: &Path, domain: &str, port: u16, marker: &str) -> Result<()> {
    let output = lab.root.join("websocket.out");
    let log = fs::File::create(lab.root.join("websocket.log"))?;
    let mut child = Command::new("openssl")
        .args([
            "s_client",
            "-quiet",
            "-ign_eof",
            "-connect",
            &format!("127.0.0.1:{port}"),
            "-servername",
            domain,
            "-verify_hostname",
            domain,
            "-verify_return_error",
            "-CAfile",
            util::path_str(ca)?,
        ])
        .stdin(Stdio::piped())
        .process_group(0)
        .stdout(fs::File::create(&output)?)
        .stderr(log)
        .spawn()?;
    let mut input = child.stdin.take().ok_or("missing TLS input")?;
    lab.children.push(child);
    input.write_all(format!("GET /socket HTTP/1.1\r\nHost: {domain}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n").as_bytes())?;
    let payload = util::random_hex(8)?;
    let mask = [7u8, 13, 19, 31];
    input.write_all(&[0x81, 0x80 | payload.len() as u8])?;
    input.write_all(&mask)?;
    for (i, byte) in payload.bytes().enumerate() {
        input.write_all(&[byte ^ mask[i % 4]])?;
    }
    drop(input);
    let child = lab.children.last_mut().unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    while child.try_wait()?.is_none() {
        if Instant::now() >= deadline {
            return Err("WebSocket TLS client timed out".into());
        }
        thread::sleep(Duration::from_millis(20));
    }
    let bytes = fs::read(output)?;
    let split = bytes
        .windows(4)
        .position(|b| b == b"\r\n\r\n")
        .ok_or("WebSocket upgrade response missing")?;
    assert!(
        bytes.starts_with(b"HTTP/1.1 101"),
        "{}",
        String::from_utf8_lossy(&bytes)
    );
    let frame = &bytes[split + 4..];
    let expected = format!("{marker}:{payload}");
    assert_eq!(
        frame,
        [vec![0x81, expected.len() as u8], expected.into_bytes()].concat()
    );
    // The completed TLS utility is the last child, not the live frpc.
    lab.stop_client();
    Ok(())
}

fn domain_case(wildcard: bool) -> Result<()> {
    let server = PathBuf::from(std::env::var("ONEBOX_FRPS_BIN")?);
    let client = PathBuf::from(std::env::var("ONEBOX_FRPC_BIN")?);
    let nginx = PathBuf::from(std::env::var("ONEBOX_NGINX_BIN")?);
    let root = std::env::temp_dir().join(format!("onebox-frp-web-{}", util::random_hex(8)?));
    fs::create_dir(&root)?;
    let mut lab = Lab {
        root: root.clone(),
        children: vec![],
        stop: Arc::new(AtomicBool::new(false)),
        origin: None,
    };
    fs::set_permissions(&root, fs::Permissions::from_mode(0o755))?;
    let sockets: Vec<_> = (0..5)
        .map(|_| TcpListener::bind(("127.0.0.1", 0)))
        .collect::<std::io::Result<_>>()?;
    let ports = sockets
        .iter()
        .map(|s| s.local_addr().unwrap().port())
        .collect::<Vec<_>>();
    let origin = TcpListener::bind(("127.0.0.1", 0))?;
    let local = origin.local_addr()?.port();
    origin.set_nonblocking(true)?;
    let marker = format!("frp-web-{}", util::random_hex(10)?);
    let copy_marker = marker.clone();
    let stop_origin = lab.stop.clone();
    let origin = thread::spawn(move || {
        while !stop_origin.load(Ordering::Relaxed) {
            match origin.accept() {
                Ok((connection, _)) => {
                    let _ = origin_reply(connection, &copy_marker);
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(10))
                }
                Err(_) => break,
            }
        }
    });
    lab.origin = Some(origin);
    let base = Context::default();
    let ctx = Context {
        paths: crate::context::Paths::isolated(&root),
        runner: Arc::new(DeferNginxCheck {
            real: base.runner,
            nginx: nginx.clone(),
        }),
        ..base
    };
    lifecycle::private_dir(&ctx.paths.frp_root)?;
    let cfg = Config {
        mode: "web".into(),
        domain: "control.frp.example".into(),
        bind_addr: "127.0.0.1".into(),
        bind_port: ports[0],
        http_port: ports[1],
        https_port: ports[2],
        redirect_port: ports[3],
        range_start: ports[4],
        range_end: ports[4],
        token: util::random_hex(32)?,
        tls_method: "custom".into(),
        web_domain: if wildcard {
            String::new()
        } else {
            "app.frp.example".into()
        },
        subdomain_host: if wildcard {
            "apps.frp.example".into()
        } else {
            String::new()
        },
        cert_input: "test-cert".into(),
        key_input: "test-key".into(),
        ..Config::default()
    };
    lifecycle::control_cert(&ctx, &cfg)?;
    let ca = web_certificate(&ctx)?;
    lifecycle::test_web_config(&ctx, &cfg)?;
    let conf = ctx.paths.frp_root.join("nginx.conf");
    let mut text = fs::read_to_string(&conf)?;
    for port in [cfg.https_port, cfg.redirect_port] {
        text = text.replace(
            &format!("listen {port}"),
            &format!("listen 127.0.0.1:{port}"),
        );
        text = text.replace(
            &format!("listen [::]:{port}"),
            &format!("listen [::1]:{port}"),
        );
    }
    util::atomic_write(&conf, text.as_bytes(), 0o600)?;
    let check = Command::new(&nginx)
        .args([
            "-t",
            "-p",
            util::path_str(&ctx.paths.frp_root)?,
            "-c",
            util::path_str(&conf)?,
        ])
        .output()?;
    assert!(
        check.status.success(),
        "nginx -t failed: {}",
        String::from_utf8_lossy(&check.stderr)
    );
    let server_config = ctx.paths.frp_root.join("frps.toml");
    util::atomic_write(&server_config, render(&ctx, &cfg)?.as_bytes(), 0o600)?;
    let client_dir = root.join("client");
    export(
        &ctx,
        &cfg,
        &[
            client_dir.display().to_string(),
            "--type".into(),
            "http".into(),
            "--local-port".into(),
            local.to_string(),
            "--subdomain".into(),
            "home".into(),
        ],
    )?;
    let client_config = client_dir.join("frpc.toml");
    let text = fs::read_to_string(&client_config)?.replace(
        &format!("serverAddr = {}", quote(&cfg.domain)),
        "serverAddr = \"127.0.0.1\"",
    );
    util::atomic_write(&client_config, text.as_bytes(), 0o600)?;
    for (binary, config) in [(&server, &server_config), (&client, &client_config)] {
        let check = Command::new(binary)
            .args(["verify", "-c", util::path_str(config)?])
            .current_dir(config.parent().unwrap())
            .output()?;
        assert!(
            check.status.success(),
            "FRP verify: {}",
            String::from_utf8_lossy(&check.stderr)
        );
    }
    drop(sockets);
    lab.spawn(&server, &server_config, "server");
    for _ in 0..100 {
        if ready(cfg.bind_port) {
            break;
        }
        thread::sleep(Duration::from_millis(20));
    }
    assert!(ready(cfg.bind_port), "{}", lab.logs());
    let log = fs::File::create(root.join("nginx.log"))?;
    let child = Command::new(&nginx)
        .args([
            "-p",
            util::path_str(&ctx.paths.frp_root)?,
            "-c",
            util::path_str(&conf)?,
            "-g",
            "daemon off;",
        ])
        .stdin(Stdio::null())
        .process_group(0)
        .stdout(log.try_clone()?)
        .stderr(log)
        .spawn()?;
    lab.children.push(child);
    lab.spawn(&client, &client_config, "client");
    let domain = if wildcard {
        "home.apps.frp.example"
    } else {
        "app.frp.example"
    };
    let mut success = None;
    let deadline = Instant::now() + Duration::from_secs(10);
    for _ in 0..100 {
        if let Ok(reply) = fetch(&lab, &ca, domain, cfg.https_port, true) {
            if reply.0 == 200 {
                success = Some(reply);
                break;
            }
        }
        if Instant::now() >= deadline {
            break;
        }
        thread::sleep(Duration::from_millis(20));
    }
    let reply = success.unwrap_or_else(|| {
        panic!(
            "HTTPS domain route failed: {}\n{}",
            lab.logs(),
            fs::read_to_string(ctx.paths.frp_root.join("nginx-error.log")).unwrap_or_default()
        )
    });
    let json: serde_json::Value = serde_json::from_str(&reply.1)?;
    assert_eq!(json["marker"], marker);
    assert_eq!(json["host"], domain);
    assert_eq!(json["proto"], "https");
    assert_eq!(json["port"], cfg.https_port.to_string());
    assert!(
        fetch(
            &lab,
            &ctx.paths.frp_root.join("ca.pem"),
            domain,
            cfg.https_port,
            true
        )
        .is_err(),
        "the control CA must not authenticate the independent website certificate"
    );
    assert!(
        fetch(
            &lab,
            &ca,
            "wrong-certificate.frp.example",
            cfg.https_port,
            true
        )
        .is_err(),
        "HTTPS must reject a hostname outside the certificate SANs"
    );
    let redirect = fetch(&lab, &ca, domain, cfg.redirect_port, false)?;
    assert_eq!(redirect.0, 301);
    assert!(redirect.2.contains(&format!(
        "Location: https://{domain}:{}/probe",
        cfg.https_port
    )));
    let absent = if wildcard {
        "missing.apps.frp.example"
    } else {
        "unknown.frp.example"
    };
    let rejected = fetch(&lab, &ca, absent, cfg.https_port, true)?;
    assert_ne!(rejected.0, 200);
    assert!(
        !rejected.1.contains(&marker),
        "unknown host reached application"
    );
    websocket(&mut lab, &ca, domain, cfg.https_port, &marker)?;
    lab.stop_client();
    let mut gone = false;
    let deadline = Instant::now() + Duration::from_secs(10);
    for _ in 0..100 {
        let reply = fetch(&lab, &ca, domain, cfg.https_port, true)?;
        if reply.0 != 200 && !reply.1.contains(&marker) {
            gone = true;
            break;
        }
        if Instant::now() >= deadline {
            break;
        }
        thread::sleep(Duration::from_millis(20));
    }
    assert!(
        gone,
        "stopping frpc did not remove the HTTPS application route"
    );
    assert!(
        request(local).is_some_and(|v| v.contains(&marker)),
        "origin must remain alive; traffic cannot bypass FRP"
    );
    Ok(())
}

#[test]
#[ignore = "requires official frps/frpc and nginx; isolated loopback HTTPS domain routing"]
fn domain_https_reverse_proxy_and_websocket() -> Result<()> {
    domain_case(false)?;
    domain_case(true)
}
