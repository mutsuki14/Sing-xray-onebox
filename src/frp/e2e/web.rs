//! Real domain routing through the generated nginx.conf → frps → frpc,
//! for a single domain and a wildcard root.

use super::*;
use crate::frp::model::{AppDomain, WebSettings, WebTls};
use crate::frp::render::{nginx_conf, NginxLayout, NginxPhase};
use std::collections::BTreeMap;
use std::os::unix::fs::PermissionsExt;

fn openssl(args: &[&str]) {
    let out = Command::new("openssl").args(args).output().unwrap();
    assert!(
        out.status.success(),
        "openssl {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// A website CA and a leaf for the test names in `FRP_ROOT/web-tls`;
/// returns the CA certificate.
fn web_certificate(root: &Path) -> PathBuf {
    let ca = root.join("web-ca.pem");
    let ca_key = root.join("web-ca-key.pem");
    let dir = root.join("web-tls");
    ensure_dir(&dir, 0o700).unwrap();
    let s = |p: &Path| p.to_string_lossy().into_owned();
    openssl(&[
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
        &s(&ca_key),
        "-out",
        &s(&ca),
    ]);
    let key = dir.join("key.pem");
    let csr = dir.join("request.csr");
    let ext = dir.join("extensions.cnf");
    fs::write(
        &ext,
        "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n\
         extendedKeyUsage=serverAuth\nsubjectAltName=DNS:app.frp.example,DNS:*.apps.frp.example,DNS:unknown.frp.example\n",
    )
    .unwrap();
    openssl(&[
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
        &s(&key),
        "-out",
        &s(&csr),
    ]);
    openssl(&[
        "x509",
        "-req",
        "-in",
        &s(&csr),
        "-CA",
        &s(&ca),
        "-CAkey",
        &s(&ca_key),
        "-set_serial",
        "2",
        "-days",
        "2",
        "-extfile",
        &s(&ext),
        "-out",
        &s(&dir.join("cert.pem")),
    ]);
    ca
}

/// The test origin: JSON with the forwarded headers, or a WebSocket echo
/// on `/socket`.
fn origin_reply(mut connection: TcpStream, marker: &str) -> std::io::Result<()> {
    connection.set_read_timeout(Some(Duration::from_secs(2)))?;
    connection.set_write_timeout(Some(Duration::from_secs(2)))?;
    let mut header = Vec::new();
    while !header.ends_with(b"\r\n\r\n") && header.len() < 16384 {
        let mut byte = [0u8];
        connection.read_exact(&mut byte)?;
        header.push(byte[0]);
    }
    let header = String::from_utf8_lossy(&header).into_owned();
    let fields: BTreeMap<String, String> = header
        .lines()
        .skip(1)
        .filter_map(|line| {
            line.split_once(':')
                .map(|(k, v)| (k.to_ascii_lowercase(), v.trim().to_string()))
        })
        .collect();
    if header.starts_with("GET /socket ") {
        return websocket_echo(connection, &fields, marker);
    }
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
    connection.shutdown(std::net::Shutdown::Both)
}

fn websocket_echo(
    mut connection: TcpStream,
    fields: &BTreeMap<String, String>,
    marker: &str,
) -> std::io::Result<()> {
    let upgrade = fields.get("upgrade").map(|v| v.to_ascii_lowercase()) == Some("websocket".into())
        && fields
            .get("connection")
            .is_some_and(|v| v.to_ascii_lowercase().contains("upgrade"))
        && fields.get("sec-websocket-key").map(String::as_str) == Some("dGhlIHNhbXBsZSBub25jZQ==");
    if !upgrade {
        return connection.write_all(
            b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        );
    }
    connection.write_all(
        b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
          Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n",
    )?;
    let mut prefix = [0u8; 2];
    connection.read_exact(&mut prefix)?;
    if prefix[0] != 0x81 || prefix[1] & 0x80 == 0 || prefix[1] & 0x7f >= 126 {
        return Err(std::io::Error::other("expected a short masked text frame"));
    }
    let mut mask = [0u8; 4];
    connection.read_exact(&mut mask)?;
    let mut data = vec![0u8; usize::from(prefix[1] & 0x7f)];
    connection.read_exact(&mut data)?;
    for (i, byte) in data.iter_mut().enumerate() {
        *byte ^= mask[i % 4];
    }
    let reply = [marker.as_bytes(), b":", &data].concat();
    let len = u8::try_from(reply.len()).map_err(std::io::Error::other)?;
    connection.write_all(&[0x81, len])?;
    connection.write_all(&reply)
}

/// `(status, body, headers)` of `GET /probe` via curl, resolving `domain`
/// to 127.0.0.1 and trusting only `ca`.
fn fetch(
    lab: &Lab,
    ca: &Path,
    domain: &str,
    port: u16,
    tls: bool,
) -> Option<(u16, String, String)> {
    let key = crate::sys::rand::hex(6).ok()?;
    let body = lab.root().join(format!("body-{key}"));
    let headers = lab.root().join(format!("headers-{key}"));
    let scheme = if tls { "https" } else { "http" };
    let output = Command::new("curl")
        .args([
            "--disable",
            "--silent",
            "--show-error",
            "--http1.1",
            "--noproxy",
            "*",
        ])
        .args(["--connect-timeout", "1", "--max-time", "3"])
        .arg("--resolve")
        .arg(format!("{domain}:{port}:127.0.0.1"))
        .arg("--cacert")
        .arg(ca)
        .arg("--output")
        .arg(&body)
        .arg("--dump-header")
        .arg(&headers)
        .args(["--write-out", "%{http_code}"])
        .arg(format!("{scheme}://{domain}:{port}/probe"))
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    Some((
        String::from_utf8_lossy(&output.stdout).parse().ok()?,
        fs::read_to_string(body).unwrap_or_default(),
        fs::read_to_string(headers).unwrap_or_default(),
    ))
}

/// A masked WebSocket text frame through nginx and frp, echoed back.
fn websocket(ca: &Path, domain: &str, port: u16, marker: &str) {
    let payload = crate::sys::rand::hex(8).unwrap();
    let mask = [7u8, 13, 19, 31];
    let mut input = format!(
        "GET /socket HTTP/1.1\r\nHost: {domain}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
         Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"
    )
    .into_bytes();
    input.extend_from_slice(&[0x81, 0x80 | payload.len() as u8]);
    input.extend_from_slice(&mask);
    input.extend(payload.bytes().enumerate().map(|(i, b)| b ^ mask[i % 4]));
    let mut child = Command::new("openssl")
        .args(["s_client", "-quiet", "-ign_eof", "-connect"])
        .arg(format!("127.0.0.1:{port}"))
        .args(["-servername", domain, "-verify_hostname", domain])
        .arg("-verify_return_error")
        .arg("-CAfile")
        .arg(ca)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(&input).unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    while child.try_wait().unwrap().is_none() {
        if Instant::now() >= deadline {
            let _ = child.kill();
            panic!("WebSocket TLS client timed out");
        }
        thread::sleep(Duration::from_millis(20));
    }
    let mut bytes = Vec::new();
    child
        .stdout
        .take()
        .unwrap()
        .read_to_end(&mut bytes)
        .unwrap();
    assert!(
        bytes.starts_with(b"HTTP/1.1 101"),
        "{}",
        String::from_utf8_lossy(&bytes)
    );
    let split = bytes.windows(4).position(|b| b == b"\r\n\r\n").unwrap();
    let expected = format!("{marker}:{payload}");
    assert_eq!(
        &bytes[split + 4..],
        [vec![0x81, expected.len() as u8], expected.into_bytes()].concat()
    );
}

fn serve_origin(lab: &mut Lab, marker: &str) -> u16 {
    let origin = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let local = origin.local_addr().unwrap().port();
    origin.set_nonblocking(true).unwrap();
    let marker = marker.to_owned();
    let stop = lab.stop.clone();
    lab.origin = Some(thread::spawn(move || {
        while !stop.load(Ordering::Relaxed) {
            match origin.accept() {
                Ok((connection, _)) => {
                    let _ = connection.set_nonblocking(false);
                    let _ = origin_reply(connection, &marker);
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(10))
                }
                Err(_) => break,
            }
        }
    }));
    local
}

/// The full nginx configuration with its listeners on 127.0.0.1, tested
/// with the real nginx.
fn nginx_config(ctx: &Ctx, web: &WebSettings, nginx: &Path) -> PathBuf {
    let paths = &ctx.paths;
    for dir in [
        paths.frp_web.clone(),
        paths.frp_web.join("www"),
        paths.frp_web.join("tmp"),
    ] {
        ensure_dir(&dir, 0o755).unwrap();
    }
    let layout = NginxLayout {
        frp_root: &paths.frp_root,
        frp_web: &paths.frp_web,
        worker: "www-data www-data",
        ipv6: false,
    };
    let mut text = nginx_conf(web, &layout, NginxPhase::Full);
    for port in [web.https_port, web.redirect_port] {
        text = text.replace(
            &format!("listen {port}"),
            &format!("listen 127.0.0.1:{port}"),
        );
    }
    let conf = paths.frp_root.join("nginx.conf");
    fs::write(&conf, text).unwrap();
    let check = Command::new(nginx)
        .args(["-t", "-p"])
        .arg(&paths.frp_root)
        .arg("-c")
        .arg(&conf)
        .output()
        .unwrap();
    assert!(
        check.status.success(),
        "nginx -t: {}",
        String::from_utf8_lossy(&check.stderr)
    );
    conf
}

fn domain_case(wildcard: bool) {
    let frps = env_path("ONEBOX_FRPS_BIN");
    let frpc = env_path("ONEBOX_FRPC_BIN");
    let nginx = env_path("ONEBOX_NGINX_BIN");
    let mut lab = Lab::new("frp-e2e-web");
    // nginx workers must traverse the tree.
    fs::set_permissions(lab.root(), fs::Permissions::from_mode(0o755)).unwrap();
    let ctx = real_ctx(lab.root());
    let (sockets, ports) = reserve(4);
    let marker = format!("frp-web-{}", crate::sys::rand::hex(10).unwrap());
    let local = serve_origin(&mut lab, &marker);
    let app = if wildcard {
        AppDomain::Wildcard {
            root: "apps.frp.example".into(),
        }
    } else {
        AppDomain::Single {
            domain: "app.frp.example".into(),
        }
    };
    let web = WebSettings {
        http_port: ports[1],
        https_port: ports[2],
        redirect_port: ports[3],
        app,
        tls: WebTls::Custom {
            cert: "/unused/cert.pem".into(),
            key: "/unused/key.pem".into(),
        },
    };
    let mut state = FrpState::new(
        "control.frp.example".into(),
        token(),
        BindAddr::LoopbackV4,
        Mode::Web(web.clone()),
    );
    state.bind_port = ports[0];
    let server_config = server(&ctx, &state, &frps);
    let frp_dir = ctx.paths.frp_root.parent().unwrap().to_path_buf();
    fs::set_permissions(&frp_dir, fs::Permissions::from_mode(0o755)).unwrap();
    let ca = web_certificate(&ctx.paths.frp_root);
    let conf = nginx_config(&ctx, &web, &nginx);
    let req = ExportRequest {
        output: Some(lab.root().join("client").to_string_lossy().into_owned()),
        kind: Some("http".into()),
        local_port: Some(local),
        subdomain: Some("home".into()),
        ..ExportRequest::default()
    };
    let client_config = client(&ctx, &state, req, &frpc);
    let client_dir = client_config.parent().unwrap().to_path_buf();

    drop(sockets);
    let server_args = ["-c", server_config.to_str().unwrap()];
    lab.spawn(&frps, &server_args, None, "server");
    assert!(
        wait_until(Duration::from_secs(3), || ready(state.bind_port)),
        "{}",
        lab.logs()
    );
    let prefix = ctx.paths.frp_root.to_string_lossy().into_owned();
    let conf_arg = conf.to_string_lossy().into_owned();
    let nginx_args = [
        "-p",
        prefix.as_str(),
        "-c",
        conf_arg.as_str(),
        "-g",
        "daemon off;",
    ];
    lab.spawn(&nginx, &nginx_args, None, "nginx");
    let client_args = ["-c", client_config.to_str().unwrap()];
    lab.spawn(&frpc, &client_args, Some(&client_dir), "client");

    let domain = if wildcard {
        "home.apps.frp.example"
    } else {
        "app.frp.example"
    };
    let mut reply = None;
    wait_until(Duration::from_secs(10), || {
        reply = fetch(&lab, &ca, domain, web.https_port, true).filter(|r| r.0 == 200);
        reply.is_some()
    });
    let Some((_, body, _)) = reply else {
        panic!(
            "HTTPS route failed: {}\n{}",
            lab.logs(),
            fs::read_to_string(ctx.paths.frp_root.join("nginx-error.log")).unwrap_or_default()
        );
    };
    let json: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(json["marker"], marker.as_str());
    assert_eq!(json["host"], domain);
    assert_eq!(json["proto"], "https");
    assert_eq!(json["port"], web.https_port.to_string());

    let control_ca = ctx.paths.frp_root.join("ca.pem");
    assert!(
        fetch(&lab, &control_ca, domain, web.https_port, true).is_none(),
        "the control CA must not authenticate the website"
    );
    assert!(
        fetch(
            &lab,
            &ca,
            "wrong-certificate.frp.example",
            web.https_port,
            true
        )
        .is_none(),
        "names outside the certificate must fail"
    );
    let redirect = fetch(&lab, &ca, domain, web.redirect_port, false).unwrap();
    assert_eq!(redirect.0, 301);
    assert!(redirect.2.contains(&format!(
        "Location: https://{domain}:{}/probe",
        web.https_port
    )));
    let absent = if wildcard {
        "missing.apps.frp.example"
    } else {
        "unknown.frp.example"
    };
    let rejected = fetch(&lab, &ca, absent, web.https_port, true).unwrap();
    assert_ne!(rejected.0, 200);
    assert!(
        !rejected.1.contains(&marker),
        "an unknown host reached the application"
    );
    websocket(&ca, domain, web.https_port, &marker);

    lab.stop_last();
    let gone = wait_until(Duration::from_secs(10), || {
        fetch(&lab, &ca, domain, web.https_port, true)
            .is_some_and(|r| r.0 != 200 && !r.1.contains(&marker))
    });
    assert!(gone, "stopping frpc did not remove the route");
    assert!(
        request(local).is_some_and(|v| v.contains(&marker)),
        "the origin must still answer"
    );
}

#[test]
#[ignore = "requires the official frps/frpc and nginx (ONEBOX_NGINX_BIN); loopback HTTPS routing"]
fn domain_https_reverse_proxy_and_websocket() {
    domain_case(false);
    domain_case(true);
}
