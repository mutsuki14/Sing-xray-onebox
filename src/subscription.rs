//! Authenticated subscription publishing. The HTTP worker reads only a public
//! client snapshot and opaque token digests, never the server's credentials.
use crate::{cert, context::Context, model::State, platform, site, util, Result};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs,
    io::{Read, Write},
    net::TcpListener,
    os::unix::{
        fs::PermissionsExt,
        net::{UnixListener, UnixStream},
    },
    path::PathBuf,
    sync::{mpsc, Arc, Mutex},
    thread,
    time::Duration,
};

const SERVICE: &str = "onebox-subscription";
const WEB_SERVICE: &str = "onebox-subscription-web";
const FORMATS: [&str; 6] = [
    "base64",
    "mihomo",
    "provider",
    "singbox",
    "singbox-notun",
    "xray",
];
#[derive(Clone, Debug, Serialize, Deserialize)]
struct Device {
    id: String,
    name: String,
    hash: String,
    created: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
struct Settings {
    enabled: bool,
    mode: String,
    domain: String,
    port: u16,
    method: String,
    custom_cert: Option<PathBuf>,
    custom_key: Option<PathBuf>,
    devices: Vec<Device>,
}
impl Default for Settings {
    fn default() -> Self {
        Self {
            enabled: false,
            mode: "site".into(),
            domain: String::new(),
            port: 443,
            method: "cf".into(),
            custom_cert: None,
            custom_key: None,
            devices: Vec::new(),
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
struct Published {
    generation: String,
    formats: BTreeMap<String, String>,
}
fn dir(ctx: &Context) -> PathBuf {
    ctx.paths.root.join("subscription")
}
fn settings_path(ctx: &Context) -> PathBuf {
    dir(ctx).join("settings.json")
}
fn published_path(ctx: &Context) -> PathBuf {
    dir(ctx).join("published.json")
}
pub fn socket_path(ctx: &Context) -> PathBuf {
    ctx.paths.run.join("subscription.sock")
}
fn load(ctx: &Context) -> Result<Settings> {
    Ok(load_version(ctx)?.0)
}
fn load_version(ctx: &Context) -> Result<(Settings, String)> {
    let bytes = match fs::read(settings_path(ctx)) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok((Settings::default(), "absent".into()))
        }
        Err(e) => return Err(e.into()),
    };
    let s: Settings = serde_json::from_slice(&bytes)?;
    validate_settings(&s)?;
    Ok((s, util::sha256(&bytes)))
}
fn validate_settings(s: &Settings) -> Result<()> {
    if !matches!(s.mode.as_str(), "site" | "standalone") {
        return Err("订阅托管模式无效".into());
    }
    if s.enabled && (!util::valid_domain(&s.domain) || s.port == 0) {
        return Err("订阅域名或 HTTPS 端口无效".into());
    }
    if !matches!(s.method.as_str(), "cf" | "http" | "custom") {
        return Err("订阅证书方式无效".into());
    }
    if s.devices.len() > 256 {
        return Err("订阅设备超过 256 个".into());
    }
    for d in &s.devices {
        if !valid_hex(&d.hash, 64)
            || !valid_hex(&d.id, 16)
            || d.name.len() > 80
            || d.name.chars().any(char::is_control)
        {
            return Err("订阅设备数据无效".into());
        }
    }
    Ok(())
}
fn save(ctx: &Context, s: &Settings) -> Result<()> {
    validate_settings(s)?;
    let d = dir(ctx);
    util::safe_path(&d)?;
    fs::create_dir_all(&d)?;
    fs::set_permissions(&d, fs::Permissions::from_mode(0o700))?;
    util::atomic_write(&settings_path(ctx), &serde_json::to_vec_pretty(s)?, 0o600)
}
pub fn uses_site(ctx: &Context) -> Result<bool> {
    let s = load(ctx)?;
    Ok(s.enabled && s.mode == "site")
}
fn validate_site_endpoint(settings: &Settings, state: &State) -> Result<()> {
    if settings.enabled && settings.mode == "site" {
        if !state.site_enabled() || settings.domain != state.get("REALITY_SITE_DOMAIN") {
            return Err("订阅复用域名必须等于已启用自建站的域名".into());
        }
        if settings.port != site::public_port(state) {
            return Err(
                "当前变更会改变订阅 URL 端口；请先关闭订阅，完成端口调整后重新启用并更新客户端 URL"
                    .into(),
            );
        }
    }
    Ok(())
}
/// Called only after the workflow has captured its rollback snapshot. Settings
/// are proposed in memory so interruption cannot commit half an enable/disable.
pub fn prepare(ctx: &Context, state: &mut State) -> Result<()> {
    let settings = if let Some(pending) = state.values.remove("SUBSCRIPTION_SETTINGS_PENDING") {
        let expected = state
            .values
            .remove("SUBSCRIPTION_SETTINGS_EXPECTED")
            .ok_or("订阅事务缺少原配置校验值")?;
        let current = load_version(ctx)?.1;
        if expected != current {
            return Err("订阅设备或设置已被其他操作修改，请重试".into());
        }
        let settings: Settings = serde_json::from_str(&pending)?;
        validate_settings(&settings)?;
        validate_site_endpoint(&settings, state)?;
        save(ctx, &settings)?;
        settings
    } else {
        let settings = load(ctx)?;
        validate_site_endpoint(&settings, state)?;
        settings
    };
    if settings.enabled && settings.mode == "standalone" {
        validate_standalone_ports(ctx, &settings, state)?;
    }
    Ok(())
}
/// Renew while the previous HTTP front end is still running, after workflow
/// has opened the temporary ACME firewall allowance.
pub fn prepare_certificates(ctx: &Context, state: &mut State) -> Result<()> {
    if state.flag("CERT_RENEW_SUBSCRIPTION") {
        let settings = load(ctx)?;
        if settings.enabled && settings.mode == "standalone" {
            cert::renew(ctx, &dir(ctx).join("tls"))?;
        }
        state.values.remove("CERT_RENEW_SUBSCRIPTION");
    }
    Ok(())
}
fn valid_hex(s: &str, len: usize) -> bool {
    s.len() == len
        && s.bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}
fn equal(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |v, (a, b)| v | (a ^ b)) == 0
}
fn new_device(s: &mut Settings, name: &str) -> Result<(String, String)> {
    if name.is_empty() || name.len() > 80 || name.chars().any(char::is_control) {
        return Err("设备名称应为 1–80 字符且不能含控制字符".into());
    }
    if s.devices.iter().any(|d| d.name == name) {
        return Err("设备名称已存在".into());
    }
    if s.devices.len() >= 256 {
        return Err("设备数量超过限制".into());
    }
    let token = util::random_hex(32)?;
    let id = util::random_hex(8)?;
    s.devices.push(Device {
        id: id.clone(),
        name: name.into(),
        hash: util::sha256(token.as_bytes()),
        created: util::now(),
    });
    Ok((id, token))
}
fn urls(ctx: &Context, s: &Settings, token: &str) {
    let available = fs::read(published_path(ctx))
        .ok()
        .and_then(|b| serde_json::from_slice::<Published>(&b).ok())
        .map(|p| p.formats)
        .unwrap_or_default();
    let suffix = if s.port == 443 {
        String::new()
    } else {
        format!(":{}", s.port)
    };
    for f in FORMATS {
        if available.contains_key(f) {
            println!("{f}: https://{}{suffix}/sub/{token}/{f}", s.domain);
        }
    }
    if available.contains_key("singbox") {
        let url = format!("https://{}{suffix}/sub/{token}/singbox", s.domain);
        println!(
            "sing-box 导入: sing-box://import-remote-profile?url={}#onebox",
            util::url_encode(&url)
        );
    }
    println!("令牌仅显示一次，请保存；设备撤销只阻止后续下载，不会收回已获取的代理凭据。");
}

pub fn nginx_location(ctx: &Context) -> Result<String> {
    if !uses_site(ctx)? {
        return Ok(String::new());
    }
    location(ctx)
}
fn location(ctx: &Context) -> Result<String> {
    let socket = socket_path(ctx);
    let uri = format!("http://unix:{}:", util::path_str(&socket)?);
    if uri.contains('"')
        || uri.contains('$')
        || uri.contains('\\')
        || uri.chars().any(char::is_control)
    {
        return Err("订阅 socket 路径含不支持的字符".into());
    }
    Ok(format!(
        r#"location ^~ /sub/ {{
        access_log off; error_log /dev/null crit;
        limit_except GET {{ deny all; }}
        proxy_pass "{uri}";
        proxy_http_version 1.1; proxy_set_header Connection "";
        proxy_buffering off; proxy_request_buffering off; proxy_cache off;
        proxy_connect_timeout 3s; proxy_read_timeout 10s;
        add_header Cache-Control "private, no-store" always;
        add_header Referrer-Policy "no-referrer" always;
        add_header X-Content-Type-Options "nosniff" always;
    }}"#
    ))
}
fn acme_root(ctx: &Context) -> PathBuf {
    ctx.paths
        .site_root
        .with_file_name("onebox-subscription-acme")
}
fn web_config(ctx: &Context, s: &Settings, bootstrap: bool) -> Result<String> {
    let d = dir(ctx);
    let tls = d.join("tls");
    let user = site::worker_identity(ctx)?;
    let listen6 = if site::ipv6_available() {
        "listen [::]:80;".to_string()
    } else {
        String::new()
    };
    let https6 = if site::ipv6_available() {
        format!("listen [::]:{} ssl http2;", s.port)
    } else {
        String::new()
    };
    // Parsing errors happen before nginx selects a location; disabling logs
    // only inside /sub/ would still expose a malformed bearer URL globally.
    let temporary = site::nginx_runtime(ctx, "subscription")?;
    let mut config=format!("user {user};\nworker_processes 1;\npid {};\nerror_log /dev/null crit;\nevents {{ worker_connections 256; }}\nhttp {{ {temporary}\naccess_log off; server_tokens off; default_type text/plain; client_max_body_size 1k; keepalive_timeout 10;\n",site::quote_path(&d.join("nginx.pid"))?);
    if s.method == "http" {
        config.push_str(&format!("server {{ listen 80; {listen6} server_name {};\nlocation ^~ /.well-known/acme-challenge/ {{ root {}; try_files $uri =404; }}\nlocation / {{ return 404; }}\n}}\n",s.domain,site::quote_path(&acme_root(ctx))?));
    }
    if !bootstrap {
        config.push_str(&format!("server {{ listen {} ssl http2; {https6} server_name {};\nssl_certificate {}; ssl_certificate_key {}; ssl_protocols TLSv1.2 TLSv1.3;\n{}\nlocation / {{ return 404; }}\n}}\n",s.port,s.domain,site::quote_path(&tls.join("cert.pem"))?,site::quote_path(&tls.join("key.pem"))?,location(ctx)?));
    }
    config.push_str("}\n");
    Ok(config)
}
fn write_web(ctx: &Context, s: &Settings, bootstrap: bool) -> Result<()> {
    let bin = site::nginx(ctx)?;
    let d = dir(ctx);
    let conf = d.join("nginx.conf");
    let old = fs::read(&conf).ok();
    util::atomic_write(&conf, web_config(ctx, s, bootstrap)?.as_bytes(), 0o600)?;
    if let Err(e) = ctx.run(
        util::path_str(&bin)?,
        &[
            "-t",
            "-p",
            util::path_str(&d)?,
            "-c",
            util::path_str(&conf)?,
        ],
    ) {
        if let Some(old) = old {
            let _ = util::atomic_write(&conf, &old, 0o600);
        }
        return Err(e);
    }
    platform::write_service(
        ctx,
        WEB_SERVICE,
        &bin,
        &[
            "-p".into(),
            d.display().to_string(),
            "-c".into(),
            conf.display().to_string(),
            "-g".into(),
            "daemon off;".into(),
        ],
        &[SERVICE.into()],
    )
}
fn validate_standalone_ports(ctx: &Context, s: &Settings, state: &State) -> Result<()> {
    for p in state.protocols() {
        if p.network() != "udp"
            && (state.port(p) == s.port || (s.method == "http" && state.port(p) == 80))
        {
            return Err("订阅 HTTPS/验证端口与代理端口冲突".into());
        }
    }
    if state.site_enabled()
        && (s.port == state.number("REALITY_SITE_PORT", 8443)
            || s.port == 443 && state.flag("REALITY_SITE_HTTPS")
            || s.method == "http")
    {
        return Err("订阅端口与自建站冲突：请复用网站，或为独立站选择其他端口和 DNS 验证".into());
    }
    if state.number("REALITY_GUARD_PORT", 0) == s.port {
        return Err("订阅端口与 REALITY 防偷跑端口冲突".into());
    }
    for (start, end, network) in crate::frp::reserved_ports(ctx)? {
        if network != "udp"
            && ((start..=end).contains(&s.port)
                || s.method == "http" && (start..=end).contains(&80))
        {
            return Err("订阅端口已保留给 FRP".into());
        }
    }
    Ok(())
}
fn prepare_standalone(ctx: &Context, s: &Settings, state: &State) -> Result<()> {
    validate_standalone_ports(ctx, s, state)?;
    let tls = dir(ctx).join("tls");
    let valid = cert::validate_pair(
        ctx,
        &tls.join("cert.pem"),
        &tls.join("key.pem"),
        &s.domain,
        true,
    )
    .is_ok();
    if !valid && s.method == "http" {
        if !platform::running(ctx, WEB_SERVICE) && TcpListener::bind(("0.0.0.0", 80)).is_err() {
            return Err("HTTP-01 的 TCP 80 已被占用，请改用 cf/custom".into());
        }
        let root = acme_root(ctx);
        util::safe_path(&root)?;
        if root.exists()
            && !root.join(".onebox-owned").exists()
            && fs::read_dir(&root)?.next().is_some()
        {
            return Err("订阅 ACME 目录含未托管内容".into());
        }
        fs::create_dir_all(root.join(".well-known/acme-challenge"))?;
        for p in [
            &root,
            &root.join(".well-known"),
            &root.join(".well-known/acme-challenge"),
        ] {
            fs::set_permissions(p, fs::Permissions::from_mode(0o755))?;
        }
        util::atomic_write(&root.join(".onebox-owned"), b"onebox\n", 0o600)?;
        write_web(ctx, s, true)?;
        platform::service(ctx, WEB_SERVICE, "restart")?;
        platform::wait_running(ctx, WEB_SERVICE)?;
    }
    let custom = s.custom_cert.as_deref().zip(s.custom_key.as_deref());
    cert::issue(
        ctx,
        &tls,
        &s.domain,
        &s.method,
        Some(&acme_root(ctx)),
        custom,
    )?;
    cert::validate_pair(
        ctx,
        &tls.join("cert.pem"),
        &tls.join("key.pem"),
        &s.domain,
        true,
    )?;
    write_web(ctx, s, false)?;
    platform::service(ctx, WEB_SERVICE, "restart")?;
    platform::service(ctx, WEB_SERVICE, "enable")?;
    platform::wait_running(ctx, WEB_SERVICE)?;
    site::cron(ctx, "subscription", true)
}
/// All formats become visible in one atomic rename. Never publish probe.json,
/// state.json, server inbounds, private keys, or arbitrary requested files.
fn render_snapshot(ctx: &Context, state: &State) -> Result<Published> {
    let mut formats = BTreeMap::new();
    for f in FORMATS {
        if state.protocols().iter().any(|p| p.supports(f)) {
            let body = crate::render::client(ctx, state, f)?;
            if body.trim().is_empty() {
                return Err(format!("{f} 客户端配置为空").into());
            }
            if body.len() > 8 * 1024 * 1024 {
                return Err("客户端配置过大".into());
            }
            formats.insert(f.into(), body);
        }
    }
    let snapshot = Published {
        generation: util::random_hex(12)?,
        formats,
    };
    if snapshot.formats.is_empty() {
        return Err("没有可发布的客户端配置".into());
    }
    Ok(snapshot)
}
fn write_snapshot(ctx: &Context, snapshot: &Published) -> Result<()> {
    util::atomic_write(&published_path(ctx), &serde_json::to_vec(snapshot)?, 0o600)
}
pub fn publish(ctx: &Context, state: &State) -> Result<()> {
    let s = load(ctx)?;
    if !s.enabled {
        if settings_path(ctx).exists() {
            for name in [WEB_SERVICE, SERVICE] {
                let _ = platform::service(ctx, name, "stop");
                let _ = platform::service(ctx, name, "disable");
            }
        }
        return Ok(());
    }
    validate_site_endpoint(&s, state)?;
    let snapshot = render_snapshot(ctx, state)?;
    save(ctx, &s)?;
    let old = fs::read(published_path(ctx)).ok();
    write_snapshot(ctx, &snapshot)?;
    let result = (|| -> Result<()> {
        platform::write_service(
            ctx,
            SERVICE,
            &ctx.paths.executable,
            &["subscription".into(), "serve".into()],
            &[],
        )?;
        if !platform::running(ctx, SERVICE) {
            platform::service(ctx, SERVICE, "start")?;
        }
        platform::service(ctx, SERVICE, "enable")?;
        platform::wait_running(ctx, SERVICE)?;
        if s.mode == "standalone" {
            prepare_standalone(ctx, &s, state)?;
        } else {
            let _ = platform::service(ctx, WEB_SERVICE, "stop");
            let _ = platform::service(ctx, WEB_SERVICE, "disable");
        }
        Ok(())
    })();
    if result.is_err() {
        if let Some(old) = old {
            let _ = util::atomic_write(&published_path(ctx), &old, 0o600);
        } else {
            let _ = fs::remove_file(published_path(ctx));
        }
    }
    result
}
#[cfg(test)]
#[path = "subscription/e2e.rs"]
mod e2e;
fn authorize(settings: &Settings, path: &str) -> Option<String> {
    if !settings.enabled {
        return None;
    }
    let parts = path.split('/').collect::<Vec<_>>();
    if parts.len() != 4
        || !parts[0].is_empty()
        || parts[1] != "sub"
        || !valid_hex(parts[2], 64)
        || !FORMATS.contains(&parts[3])
    {
        return None;
    }
    let hash = util::sha256(parts[2].as_bytes());
    let mut found = false;
    for d in &settings.devices {
        found |= equal(hash.as_bytes(), d.hash.as_bytes());
    }
    if found {
        Some(parts[3].into())
    } else {
        None
    }
}
fn response(status: u16, body: &[u8], head: bool, content_type: &str) -> Vec<u8> {
    let phrase = match status {
        200 => "OK",
        404 => "Not Found",
        405 => "Method Not Allowed",
        _ => "Bad Request",
    };
    let header=format!("HTTP/1.1 {status} {phrase}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nCache-Control: private, no-store\r\nReferrer-Policy: no-referrer\r\nX-Content-Type-Options: nosniff\r\nConnection: close\r\n{}\r\n",body.len(),if status==405{"Allow: GET, HEAD\r\n"}else{""});
    let mut out = header.into_bytes();
    if !head {
        out.extend_from_slice(body);
    }
    out
}
fn handle(ctx: &Context, mut stream: UnixStream) -> Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(3)))?;
    stream.set_write_timeout(Some(Duration::from_secs(3)))?;
    let mut bytes = Vec::new();
    let mut chunk = [0u8; 1024];
    while bytes.len() < 8192 && !bytes.windows(4).any(|v| v == b"\r\n\r\n") {
        let n = stream.read(&mut chunk)?;
        if n == 0 {
            return Ok(());
        }
        bytes.extend_from_slice(&chunk[..n]);
    }
    let text = std::str::from_utf8(&bytes).unwrap_or("");
    let line = text.split("\r\n").next().unwrap_or("");
    let parts = line.split(' ').collect::<Vec<_>>();
    let head = parts.first() == Some(&"HEAD");
    let (status, body, kind) = if bytes.len() >= 8192
        || parts.len() != 3
        || !matches!(parts.get(2), Some(&"HTTP/1.1") | Some(&"HTTP/1.0"))
    {
        (400, b"Bad Request\n".to_vec(), "text/plain; charset=utf-8")
    } else if !matches!(parts[0], "GET" | "HEAD") {
        (
            405,
            b"Method Not Allowed\n".to_vec(),
            "text/plain; charset=utf-8",
        )
    } else {
        let format = load(ctx).ok().and_then(|s| authorize(&s, parts[1]));
        let body = format.as_ref().and_then(|f| {
            fs::read(published_path(ctx))
                .ok()
                .and_then(|b| serde_json::from_slice::<Published>(&b).ok())
                .and_then(|s| s.formats.get(f).cloned())
        });
        if let (Some(f), Some(body)) = (format, body) {
            let kind = if matches!(f.as_str(), "singbox" | "singbox-notun" | "xray") {
                "application/json; charset=utf-8"
            } else if matches!(f.as_str(), "mihomo" | "provider") {
                "text/yaml; charset=utf-8"
            } else {
                "text/plain; charset=utf-8"
            };
            (200, body.into_bytes(), kind)
        } else {
            (404, b"Not Found\n".to_vec(), "text/plain; charset=utf-8")
        }
    };
    stream.write_all(&response(status, &body, head, kind))?;
    Ok(())
}
fn serve(ctx: &Context) -> Result<()> {
    let socket = socket_path(ctx);
    util::safe_path(&ctx.paths.run)?;
    fs::create_dir_all(&ctx.paths.run)?;
    fs::set_permissions(&ctx.paths.run, fs::Permissions::from_mode(0o755))?;
    if util::path_str(&socket)?.len() > 100 {
        return Err("订阅 Unix socket 路径过长".into());
    }
    if socket.exists() {
        if UnixStream::connect(&socket).is_ok() {
            return Err("订阅服务已在运行".into());
        }
        let meta = fs::symlink_metadata(&socket)?;
        use std::os::unix::fs::FileTypeExt;
        if !meta.file_type().is_socket() {
            return Err("订阅 socket 路径被其他文件占用".into());
        }
        fs::remove_file(&socket)?;
    }
    let listener = UnixListener::bind(&socket)?;
    fs::set_permissions(&socket, fs::Permissions::from_mode(0o660))?;
    let worker = site::worker_user(ctx)?;
    let gid = ctx.run("id", &["-g", &worker])?.trim().parse::<u32>()?;
    let c = std::ffi::CString::new(util::path_str(&socket)?)?;
    if unsafe { libc::chown(c.as_ptr(), libc::geteuid(), gid) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let (tx, rx) = mpsc::sync_channel::<UnixStream>(16);
    let rx = Arc::new(Mutex::new(rx));
    for _ in 0..4 {
        let rx = rx.clone();
        let worker_ctx = ctx.clone();
        thread::spawn(move || loop {
            let stream = match rx.lock().unwrap().recv() {
                Ok(s) => s,
                Err(_) => return,
            };
            let _ = handle(&worker_ctx, stream);
        });
    }
    for stream in listener.incoming().flatten() {
        let _ = tx.try_send(stream);
    }
    Ok(())
}
fn option(args: &[String], key: &str) -> Option<String> {
    args.windows(2).find(|a| a[0] == key).map(|a| a[1].clone())
}
fn apply_settings(ctx: &Context, s: &Settings, expected: &str, mut state: State) -> Result<()> {
    validate_settings(s)?;
    state.set("SUBSCRIPTION_SETTINGS_PENDING", serde_json::to_string(s)?);
    state.set("SUBSCRIPTION_SETTINGS_EXPECTED", expected);
    state.set(
        "SUBSCRIPTION_DOMAIN",
        if s.enabled { s.domain.as_str() } else { "" },
    );
    state.set("SUBSCRIPTION_ENABLED", if s.enabled { 1 } else { 0 });
    state.set("SUBSCRIPTION_MODE", &s.mode);
    state.set("SUBSCRIPTION_PORT", s.port);
    state.set(
        "SUBSCRIPTION_HTTP",
        if s.enabled && s.mode == "standalone" && s.method == "http" {
            1
        } else {
            0
        },
    );
    crate::workflow::apply(ctx, &state)
}
pub fn command(ctx: &Context, args: &[String]) -> Result<()> {
    let action = args.first().map(String::as_str).unwrap_or("info");
    if action == "serve" {
        return serve(ctx);
    }
    // Token changes use the same inter-process lock as workflow transactions.
    // Read after locking so a concurrent revoke cannot be overwritten by add.
    let _lock = if matches!(action, "add" | "revoke" | "remove" | "reset") {
        Some(crate::transaction::acquire(ctx)?)
    } else {
        None
    };
    if _lock.is_some() && crate::transaction::load(ctx)?.is_some() {
        return Err("存在未完成配置事务，请先执行 recover 后修改订阅设备".into());
    }
    let (mut s, expected) = load_version(ctx)?;
    match action {
        "info" | "status" | "list" => {
            println!(
                "订阅: {}；托管: {}；HTTPS: {}:{}",
                if s.enabled { "启用" } else { "关闭" },
                s.mode,
                s.domain,
                s.port
            );
            for d in &s.devices {
                println!("{}  {}  创建于 {}", d.id, d.name, d.created);
            }
            println!("格式: base64 / mihomo / provider / singbox / singbox-notun / xray；兼容性取决于已启用协议。设备令牌仅在创建或重置时显示。");
            Ok(())
        }
        "enable" => {
            let state = crate::state::load(ctx)?;
            s.enabled = true;
            s.mode = option(args, "--mode").unwrap_or_else(|| {
                if state.site_enabled() {
                    "site".into()
                } else {
                    "standalone".into()
                }
            });
            if s.mode == "site" {
                if !state.site_enabled() {
                    return Err("没有可复用的自建站，请使用 --mode standalone --domain 域名 --port 端口 --tls cf|http|custom".into());
                }
                s.domain = state.get("REALITY_SITE_DOMAIN").into();
                s.port = site::public_port(&state);
            } else {
                s.domain = option(args, "--domain").ok_or("独立订阅需要 --domain")?;
                s.port = option(args, "--port")
                    .unwrap_or_else(|| "8448".into())
                    .parse()?;
                s.method = option(args, "--tls").unwrap_or_else(|| "cf".into());
                s.custom_cert = option(args, "--cert").map(PathBuf::from);
                s.custom_key = option(args, "--key").map(PathBuf::from);
            }
            let new = if s.devices.is_empty() {
                Some(new_device(
                    &mut s,
                    &option(args, "--name").unwrap_or_else(|| "default".into()),
                )?)
            } else {
                None
            };
            apply_settings(ctx, &s, &expected, state)?;
            if let Some((id, token)) = new {
                println!("设备 ID: {id}");
                urls(ctx, &s, &token);
            } else {
                println!("订阅已启用；已有设备 URL 保持不变。");
            }
            Ok(())
        }
        "disable" => {
            s.enabled = false;
            apply_settings(ctx, &s, &expected, crate::state::load(ctx)?)?;
            println!("订阅已关闭；所有 URL 暂停访问。");
            Ok(())
        }
        "add" => {
            if !s.enabled {
                return Err("请先 subscription enable".into());
            }
            let name = args.get(1).ok_or("用法: subscription add 设备名称")?;
            let (id, token) = new_device(&mut s, name)?;
            save(ctx, &s)?;
            println!("设备 ID: {id}");
            urls(ctx, &s, &token);
            Ok(())
        }
        "revoke" | "remove" => {
            let id = args.get(1).ok_or("用法: subscription revoke 设备ID")?;
            let old = s.devices.len();
            s.devices.retain(|d| &d.id != id);
            if old == s.devices.len() {
                return Err("设备 ID 不存在".into());
            }
            save(ctx, &s)?;
            println!("设备订阅已撤销；已下载的代理凭据不受影响。");
            Ok(())
        }
        "reset" => {
            let id = args.get(1).ok_or("用法: subscription reset 设备ID")?;
            let token = util::random_hex(32)?;
            let d = s
                .devices
                .iter_mut()
                .find(|d| &d.id == id)
                .ok_or("设备 ID 不存在")?;
            d.hash = util::sha256(token.as_bytes());
            d.created = util::now();
            save(ctx, &s)?;
            urls(ctx, &s, &token);
            Ok(())
        }
        "publish" | "refresh" => crate::workflow::apply(ctx, &crate::state::load(ctx)?),
        "renew" => {
            if !s.enabled {
                return Ok(());
            }
            if s.mode == "site" {
                site::command(ctx, &["renew".into()])
            } else {
                if args.iter().any(|a| a == "--cron")
                    && !cert::renewal_due(ctx, &dir(ctx).join("tls"))?
                {
                    return Ok(());
                }
                let mut state = crate::state::load(ctx)?;
                state.set("CERT_RENEW_SUBSCRIPTION", 1);
                crate::workflow::apply(ctx, &state)
            }
        }
        _ => Err(
            "用法: subscription [enable|disable|info|add 名称|revoke ID|reset ID|publish|renew]"
                .into(),
        ),
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> (Settings, String) {
        let mut s = Settings {
            enabled: true,
            domain: "site.example.com".into(),
            ..Settings::default()
        };
        let (_, t) = new_device(&mut s, "phone").unwrap();
        (s, t)
    }
    #[test]
    fn token_is_opaque_and_revocable() {
        let (mut s, t) = fixture();
        assert!(!serde_json::to_string(&s).unwrap().contains(&t));
        assert_eq!(
            authorize(&s, &format!("/sub/{t}/singbox")),
            Some("singbox".into())
        );
        s.devices.clear();
        assert!(authorize(&s, &format!("/sub/{t}/singbox")).is_none());
    }
    #[test]
    fn path_whitelist_rejects_server_secrets() {
        let (s, t) = fixture();
        for p in [
            format!("/sub/{t}/../state.json"),
            format!("/sub/{t}/probe.json"),
            format!("/sub/{t}/key.pem"),
            format!("/sub/{t}/singbox?x=1"),
            format!("/sub/{t}/%73ingbox"),
            format!("/sub/{t}/singbox/"),
        ] {
            assert!(authorize(&s, &p).is_none());
        }
    }
    #[test]
    fn head_has_get_length_without_body() {
        let r = String::from_utf8(response(200, b"private", true, "text/plain")).unwrap();
        assert!(r.contains("Content-Length: 7\r\n"));
        assert!(!r.ends_with("private"));
        assert!(r.contains("no-store"));
    }
    #[test]
    fn unknown_token_disabled_and_bad_format_fail_closed() {
        let (mut s, t) = fixture();
        assert!(authorize(&s, &format!("/sub/{}/singbox", "f".repeat(64))).is_none());
        assert!(authorize(&s, &format!("/sub/{t}/state")).is_none());
        s.enabled = false;
        assert!(authorize(&s, &format!("/sub/{t}/base64")).is_none());
    }
    #[test]
    fn active_site_urls_cannot_silently_change_domain_or_port() {
        let (settings, _) = fixture();
        let mut state = State::default();
        state.set("PROTOCOLS", "anytls-reality");
        state.set("REALITY_SITE_ENABLED", 1);
        state.set("REALITY_SITE_DOMAIN", &settings.domain);
        state.set("REALITY_SITE_HTTPS", 1);
        state.set_port(crate::model::Protocol::AnytlsReality, 9443);
        assert!(validate_site_endpoint(&settings, &state).is_ok());
        state.set("REALITY_SITE_HTTPS", 0);
        assert!(validate_site_endpoint(&settings, &state).is_err());
        state.set("REALITY_SITE_HTTPS", 1);
        state.set("REALITY_SITE_DOMAIN", "other.example.com");
        assert!(validate_site_endpoint(&settings, &state).is_err());
    }
    #[test]
    fn proposed_settings_are_applied_inside_snapshot_and_detect_concurrent_revoke() {
        let root = std::env::temp_dir().join(format!(
            "onebox-sub-prepare-{}",
            util::random_hex(8).unwrap()
        ));
        let ctx = Context {
            paths: crate::context::Paths::isolated(&root),
            ..Context::default()
        };
        let (mut settings, _) = fixture();
        settings.mode = "standalone".into();
        save(&ctx, &settings).unwrap();
        let expected = load_version(&ctx).unwrap().1;
        let mut state = State::default();
        state.set(
            "SUBSCRIPTION_SETTINGS_PENDING",
            serde_json::to_string(&settings).unwrap(),
        );
        state.set("SUBSCRIPTION_SETTINGS_EXPECTED", expected);
        let mut current = settings.clone();
        current.devices.clear();
        save(&ctx, &current).unwrap();
        assert!(prepare(&ctx, &mut state).is_err());
        assert!(load(&ctx).unwrap().devices.is_empty());
        state.set(
            "SUBSCRIPTION_SETTINGS_PENDING",
            serde_json::to_string(&settings).unwrap(),
        );
        state.set(
            "SUBSCRIPTION_SETTINGS_EXPECTED",
            load_version(&ctx).unwrap().1,
        );
        prepare(&ctx, &mut state).unwrap();
        assert_eq!(load(&ctx).unwrap().devices.len(), 1);
        assert!(state.get("SUBSCRIPTION_SETTINGS_PENDING").is_empty());
        assert!(state.get("SUBSCRIPTION_SETTINGS_EXPECTED").is_empty());
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn http_serves_atomic_generations_and_revocation() {
        let root =
            std::env::temp_dir().join(format!("onebox-sub-test-{}", util::random_hex(8).unwrap()));
        let ctx = Context {
            paths: crate::context::Paths::isolated(&root),
            ..Context::default()
        };
        let (mut s, t) = fixture();
        save(&ctx, &s).unwrap();
        let request = |method: &str, path: &str| {
            let (mut client, server) = UnixStream::pair().unwrap();
            client
                .write_all(
                    format!("{method} {path} HTTP/1.1\r\nHost: example.com\r\n\r\n").as_bytes(),
                )
                .unwrap();
            handle(&ctx, server).unwrap();
            let mut out = String::new();
            client.read_to_string(&mut out).unwrap();
            out
        };
        let path = format!("/sub/{t}/singbox");
        let mut p = Published {
            generation: "one".into(),
            formats: BTreeMap::from([("singbox".into(), "{\"version\":1}".into())]),
        };
        util::atomic_write(
            &published_path(&ctx),
            &serde_json::to_vec(&p).unwrap(),
            0o600,
        )
        .unwrap();
        let old = request("GET", &path);
        assert!(old.starts_with("HTTP/1.1 200"));
        assert!(old.ends_with("{\"version\":1}"));
        assert!(!request("HEAD", &path).contains("version"));
        p.formats.insert("singbox".into(), "{\"version\":2}".into());
        util::atomic_write(
            &published_path(&ctx),
            &serde_json::to_vec(&p).unwrap(),
            0o600,
        )
        .unwrap();
        assert!(request("GET", &path).ends_with("{\"version\":2}"));
        assert!(request("POST", &path).starts_with("HTTP/1.1 405"));
        assert!(request("GET", &format!("/sub/{t}/state.json")).starts_with("HTTP/1.1 404"));
        s.devices.clear();
        save(&ctx, &s).unwrap();
        assert!(request("GET", &path).starts_with("HTTP/1.1 404"));
        fs::remove_dir_all(root).unwrap();
    }
}
