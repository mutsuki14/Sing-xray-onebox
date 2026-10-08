//! Client-side diagnostics. Native proxy cores own transport/crypto; Rust owns
//! process lifetimes, bounded HTTP transfers and the ordered failover policy.
use crate::{context::Context, model::Core as CoreKind, util, Result};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::HashSet,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr, TcpListener, TcpStream},
    os::unix::{fs::OpenOptionsExt, process::CommandExt},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc, Mutex,
    },
    thread,
    time::{Duration, Instant},
};

const MAX_BUNDLE: u64 = 2 * 1024 * 1024;
static STOP: AtomicBool = AtomicBool::new(false);
extern "C" fn stop_signal(_: libc::c_int) {
    STOP.store(true, Ordering::Relaxed);
}
fn stopped() -> bool {
    STOP.load(Ordering::Relaxed)
}
struct Signals {
    old: Vec<(i32, libc::sigaction)>,
}
impl Signals {
    fn install() -> Self {
        STOP.store(false, Ordering::Relaxed);
        let mut old = Vec::new();
        for signal in [libc::SIGINT, libc::SIGTERM] {
            // Handler does nothing except an atomic store (async-signal-safe).
            unsafe {
                let mut action: libc::sigaction = std::mem::zeroed();
                action.sa_sigaction = stop_signal as *const () as usize;
                libc::sigemptyset(&mut action.sa_mask);
                let mut previous = std::mem::zeroed();
                if libc::sigaction(signal, &action, &mut previous) == 0 {
                    old.push((signal, previous));
                }
            }
        }
        Self { old }
    }
}
impl Drop for Signals {
    fn drop(&mut self) {
        for (signal, previous) in &self.old {
            unsafe {
                libc::sigaction(*signal, previous, std::ptr::null_mut());
            }
        }
    }
}

struct Work(PathBuf);
impl Work {
    fn new() -> Result<Self> {
        for _ in 0..8 {
            let path =
                std::env::temp_dir().join(format!("onebox-client-{}", util::random_hex(12)?));
            let mut builder = fs::DirBuilder::new();
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
            match builder.create(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(e) => return Err(e.into()),
            }
        }
        Err("无法创建诊断临时目录".into())
    }
}
impl Drop for Work {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn private_json(path: &Path, value: &Value) -> Result<()> {
    let mut out = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    serde_json::to_writer_pretty(&mut out, value)?;
    out.write_all(b"\n")?;
    out.sync_all()?;
    Ok(())
}
fn validate_bundle(value: Value) -> Result<Vec<Value>> {
    if value.get("schema").and_then(Value::as_u64) != Some(1) {
        return Err("探测配置 schema 无效".into());
    }
    let entries = value
        .get("entries")
        .and_then(Value::as_array)
        .ok_or("探测配置缺少 entries")?;
    if entries.is_empty() || entries.len() > 32 {
        return Err("配置需要 1 至 32 个入口".into());
    }
    let mut seen = HashSet::new();
    for entry in entries {
        let id = entry
            .get("id")
            .and_then(Value::as_str)
            .ok_or("入口 ID 无效")?;
        if id.is_empty()
            || id.len() > 80
            || !id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b))
            || !seen.insert(id)
        {
            return Err("入口 ID 无效或重复".into());
        }
        let core = entry.get("core").and_then(Value::as_str).unwrap_or("");
        if !matches!(core, "singbox" | "xray")
            || !matches!(
                entry.get("transport").and_then(Value::as_str),
                Some("tcp" | "udp" | "both")
            )
        {
            return Err("入口类型无效".into());
        }
        let outs = entry
            .get("outbounds")
            .and_then(Value::as_array)
            .ok_or("入口出站无效")?;
        if outs.is_empty() || outs.len() > 2 {
            return Err("入口出站无效".into());
        }
        let key = if core == "singbox" {
            "type"
        } else {
            "protocol"
        };
        let mut tags = HashSet::new();
        for outbound in outs {
            let kind = outbound.get(key).and_then(Value::as_str).unwrap_or("");
            let allowed = if core == "singbox" {
                matches!(
                    kind,
                    "vless"
                        | "vmess"
                        | "trojan"
                        | "shadowsocks"
                        | "hysteria2"
                        | "tuic"
                        | "anytls"
                        | "shadowtls"
                )
            } else {
                matches!(
                    kind,
                    "vless" | "vmess" | "trojan" | "shadowsocks" | "hysteria"
                )
            };
            if !allowed {
                return Err("出站包含未支持的协议；不允许 direct/block".into());
            }
            let tag = outbound
                .get("tag")
                .and_then(Value::as_str)
                .ok_or("出站标签无效")?;
            if tag.is_empty() || !tags.insert(tag) {
                return Err("出站标签无效或重复".into());
            }
        }
        if entry.get("tag").and_then(Value::as_str) != outs[0].get("tag").and_then(Value::as_str) {
            return Err("出站标签不匹配".into());
        }
        if let Some(meta) = entry.get("reality") {
            for key in ["host", "sni"] {
                if meta
                    .get(key)
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .is_empty()
                {
                    return Err("REALITY 元数据无效".into());
                }
            }
            if !matches!(meta.get("port").and_then(Value::as_u64), Some(1..=65535)) {
                return Err("REALITY 端口无效".into());
            }
        }
    }
    Ok(entries.clone())
}
fn load_bundle(path: &Path) -> Result<Vec<Value>> {
    let mut raw = Vec::new();
    File::open(path)?
        .take(MAX_BUNDLE + 1)
        .read_to_end(&mut raw)?;
    if raw.len() as u64 > MAX_BUNDLE {
        return Err("探测配置超过 2 MiB".into());
    }
    let value = serde_json::from_slice(&raw).map_err(|_| "探测配置不是有效 JSON")?;
    validate_bundle(value)
}
fn ordered(entries: &[Value], order: Option<&str>, pair: bool) -> Result<Vec<Value>> {
    if let Some(order) = order {
        let mut seen = HashSet::new();
        let mut result = Vec::new();
        for id in order.split(',') {
            if !seen.insert(id) {
                return Err("--entries 包含重复的 ID".into());
            }
            let entry = entries
                .iter()
                .find(|e| e["id"].as_str() == Some(id))
                .ok_or("--entries 包含未知 ID（先执行 probe list）")?;
            result.push(entry.clone());
        }
        return Ok(result);
    }
    if pair {
        let mut chosen = Vec::new();
        if let Some(e) = entries
            .iter()
            .find(|e| matches!(e["transport"].as_str(), Some("tcp" | "both")))
        {
            chosen.push(e.clone());
        }
        if let Some(e) = entries.iter().find(|e| e["transport"] == "udp") {
            chosen.push(e.clone());
        }
        if chosen.is_empty() {
            chosen.extend(entries.iter().take(1).cloned());
        }
        return Ok(chosen);
    }
    Ok(entries.to_vec())
}

#[derive(Clone, Debug)]
struct Options {
    bundle: Option<PathBuf>,
    entries: Option<String>,
    singbox: Option<PathBuf>,
    xray: Option<PathBuf>,
    url: String,
    timeout: u64,
    ca: Option<PathBuf>,
    output: Option<PathBuf>,
    samples: usize,
    download_url: Option<String>,
    upload_url: Option<String>,
    bytes: usize,
    port: u16,
    interval: u64,
    failures: u32,
    recoveries: u32,
    cooldown: u64,
    scope: String,
}
impl Default for Options {
    fn default() -> Self {
        Self {
            bundle: None,
            entries: None,
            singbox: None,
            xray: None,
            url: "https://www.gstatic.com/generate_204".into(),
            timeout: 8,
            ca: None,
            output: None,
            samples: 5,
            download_url: None,
            upload_url: None,
            bytes: 4194304,
            port: 2080,
            interval: 15,
            failures: 3,
            recoveries: 3,
            cooldown: 60,
            scope: "current-machine-to-server".into(),
        }
    }
}
fn bounded(value: &str, low: u64, high: u64) -> Result<u64> {
    value
        .parse::<u64>()
        .ok()
        .filter(|v| (low..=high).contains(v))
        .ok_or_else(|| format!("参数必须在 {low}..{high} 之间").into())
}
fn parse_options(command: &str, args: &[String]) -> Result<Options> {
    let mut o = Options::default();
    let mut i = 0;
    while i < args.len() {
        let flag = args[i].as_str();
        if !flag.starts_with('-') && o.bundle.is_none() {
            o.bundle = Some((&args[i]).into());
            i += 1;
            continue;
        }
        let value = args.get(i + 1).ok_or_else(|| format!("{flag} 缺少值"))?;
        match flag {
            "--entries" => o.entries = Some(value.clone()),
            "--singbox" => o.singbox = Some(value.into()),
            "--xray" => o.xray = Some(value.into()),
            "--url" => o.url = value.clone(),
            "--timeout" => o.timeout = bounded(value, 1, 60)?,
            "--ca" => o.ca = Some(value.into()),
            "--output" if command != "failover" => o.output = Some(value.into()),
            "--samples" if command == "bench" => o.samples = bounded(value, 1, 20)? as usize,
            "--download-url" if command == "bench" => o.download_url = Some(value.clone()),
            "--upload-url" if command == "bench" => o.upload_url = Some(value.clone()),
            "--bytes" if command == "bench" => o.bytes = bounded(value, 1024, 67108864)? as usize,
            "--port" if command == "failover" => o.port = bounded(value, 1024, 65535)? as u16,
            "--interval" if command == "failover" => o.interval = bounded(value, 1, 3600)?,
            "--failures" if command == "failover" => o.failures = bounded(value, 1, 20)? as u32,
            "--recoveries" if command == "failover" => o.recoveries = bounded(value, 1, 20)? as u32,
            "--cooldown" if command == "failover" => o.cooldown = bounded(value, 0, 3600)?,
            "--scope"
                if command == "reality-check"
                    && matches!(value.as_str(), "server-local" | "current-machine-to-server") =>
            {
                o.scope = value.clone()
            }
            _ => return Err(format!("未知或不适用的参数: {flag}").into()),
        }
        i += 2;
    }
    for url in std::iter::once(&o.url)
        .chain(o.download_url.iter())
        .chain(o.upload_url.iter())
    {
        url_parts(url)?;
    }
    if let Some(path) = &o.output {
        if fs::symlink_metadata(path).is_ok() {
            return Err("输出文件已存在；请选择新文件路径".into());
        }
    }
    Ok(o)
}

#[derive(Debug)]
struct UrlParts {
    host: String,
    port: u16,
}
fn url_parts(url: &str) -> Result<UrlParts> {
    if url.bytes().any(|b| b <= 32 || b == 127) || url.contains('#') || url.contains('\\') {
        return Err("测试 URL 包含空白、片段或控制字符".into());
    }
    let (scheme, rest) = url.split_once("://").ok_or("测试 URL 必须为 HTTP(S)")?;
    if !matches!(scheme, "http" | "https") {
        return Err("测试 URL 必须为 HTTP(S)".into());
    }
    let authority = rest.split(['/', '?']).next().unwrap_or("");
    if authority.is_empty() || authority.contains('@') {
        return Err("测试 URL 不得包含账号，且必须有主机名".into());
    }
    let default = if scheme == "https" { 443 } else { 80 };
    let (host, port) = if authority.starts_with('[') {
        let end = authority.find(']').ok_or("IPv6 URL 地址无效")?;
        let host = &authority[1..end];
        host.parse::<Ipv6Addr>().map_err(|_| "IPv6 URL 地址无效")?;
        let tail = &authority[end + 1..];
        let port = if tail.is_empty() {
            default
        } else {
            bounded(tail.strip_prefix(':').ok_or("URL 端口无效")?, 1, 65535)? as u16
        };
        (host.into(), port)
    } else {
        let (host, port) = if let Some((host, port)) = authority.rsplit_once(':') {
            (host, bounded(port, 1, 65535)? as u16)
        } else {
            (authority, default)
        };
        if host.is_empty()
            || host.contains(':')
            || !host.is_ascii()
            || host
                .bytes()
                .any(|c| !c.is_ascii_alphanumeric() && !b".-_".contains(&c))
        {
            return Err("URL 主机名无效（国际域名请使用 Punycode）".into());
        }
        (host.into(), port)
    };
    Ok(UrlParts { host, port })
}

struct ManagedChild(Child);
impl ManagedChild {
    fn wait(&mut self, timeout: Duration) -> Result<std::process::ExitStatus> {
        let end = Instant::now() + timeout;
        loop {
            if let Some(status) = self.0.try_wait()? {
                return Ok(status);
            }
            if stopped() || Instant::now() >= end {
                return Err("客户端操作超时或已取消".into());
            }
            thread::sleep(Duration::from_millis(20));
        }
    }
}
impl Drop for ManagedChild {
    fn drop(&mut self) {
        if self.0.try_wait().ok().flatten().is_none() {
            // Every managed child starts a new session; kill the process group
            // to avoid leaving helper processes after timeout or cancellation.
            unsafe {
                libc::kill(-(self.0.id() as i32), libc::SIGTERM);
            }
            let end = Instant::now() + Duration::from_millis(500);
            while Instant::now() < end {
                if self.0.try_wait().ok().flatten().is_some() {
                    return;
                }
                thread::sleep(Duration::from_millis(10));
            }
            unsafe {
                libc::kill(-(self.0.id() as i32), libc::SIGKILL);
            }
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
}
fn spawn(mut command: Command) -> Result<ManagedChild> {
    unsafe {
        command.pre_exec(|| {
            if libc::setsid() < 0 {
                Err(std::io::Error::last_os_error())
            } else {
                Ok(())
            }
        });
    }
    Ok(ManagedChild(command.spawn()?))
}
fn binary(ctx: &Context, kind: CoreKind, explicit: Option<&PathBuf>) -> Result<PathBuf> {
    if let Some(path) = explicit {
        return fs::canonicalize(path)
            .map_err(|_| format!("客户端内核不存在: {}", kind.as_str()).into());
    }
    let local = ctx.paths.core_bin(kind);
    if local.is_file() {
        return Ok(local);
    }
    if let Some(path) = std::env::var_os("PATH").and_then(|paths| {
        std::env::split_paths(&paths)
            .map(|p| p.join(kind.binary()))
            .find(|p| p.is_file())
    }) {
        return fs::canonicalize(path).map_err(Into::into);
    }
    Err(format!("缺少客户端内核: {}", kind.as_str()).into())
}
#[derive(Clone)]
struct Endpoint {
    port: u16,
    token: String,
}
struct ProxyCore {
    endpoint: Endpoint,
    process: Mutex<ManagedChild>,
    _work: Work,
}
impl ProxyCore {
    fn start(ctx: &Context, entry: &Value, options: &Options) -> Result<Self> {
        let kind = if entry["core"] == "singbox" {
            CoreKind::Singbox
        } else {
            CoreKind::Xray
        };
        let path = binary(
            ctx,
            kind,
            if kind == CoreKind::Singbox {
                options.singbox.as_ref()
            } else {
                options.xray.as_ref()
            },
        )?;
        let work = Work::new()?;
        let config_path = work.0.join("config.json");
        let reserve = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        let port = reserve.local_addr()?.port();
        let token = util::random_hex(24)?;
        let config = if kind == CoreKind::Singbox {
            json!({"log":{"disabled":true},"dns":{"servers":[{"type":"local","tag":"local"}]},
                "inbounds":[{"type":"socks","listen":"127.0.0.1","listen_port":port,"users":[{"username":"onebox-","password":token}]}],
                "outbounds":entry["outbounds"],"route":{"final":entry["tag"],"default_domain_resolver":"local"}})
        } else {
            json!({"log":{"loglevel":"none"},"inbounds":[{"protocol":"socks","listen":"127.0.0.1","port":port,
                "settings":{"auth":"password","accounts":[{"user":"onebox-","pass":token}],"udp":true}}],"outbounds":entry["outbounds"]})
        };
        private_json(&config_path, &config)?;
        let mut check = Command::new(&path);
        check
            .current_dir(&work.0)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        if kind == CoreKind::Singbox {
            check
                .args(["check", "-c"])
                .arg(&config_path)
                .arg("-D")
                .arg(&work.0);
        } else {
            check.args(["run", "-test", "-c"]).arg(&config_path);
        }
        if !spawn(check)?.wait(Duration::from_secs(15))?.success() {
            return Err("客户端配置校验失败（检查内核版本；未打印凭据）".into());
        }
        let mut run = Command::new(&path);
        run.current_dir(&work.0)
            .args(["run", "-c"])
            .arg(&config_path)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        if kind == CoreKind::Singbox {
            run.arg("-D").arg(&work.0);
        }
        drop(reserve);
        let process = spawn(run)?;
        let endpoint = Endpoint { port, token };
        let result = Self {
            endpoint,
            process: Mutex::new(process),
            _work: work,
        };
        let deadline = Instant::now() + Duration::from_secs(8);
        while Instant::now() < deadline && !stopped() {
            if result.process.lock().unwrap().0.try_wait()?.is_some() {
                return Err("客户端内核启动失败".into());
            }
            if socks_login(&result.endpoint, Duration::from_millis(300)).is_ok() {
                return Ok(result);
            }
            thread::sleep(Duration::from_millis(50));
        }
        Err("客户端内核启动超时".into())
    }
    fn terminate(&self) {
        let mut process = self.process.lock().unwrap();
        if process.0.try_wait().ok().flatten().is_none() {
            unsafe {
                libc::kill(-(process.0.id() as i32), libc::SIGTERM);
            }
            let _ = process.0.kill();
            let _ = process.0.wait();
        }
    }
    fn resources(&self) -> (Option<f64>, Option<u64>) {
        let pid = self.process.lock().unwrap().0.id();
        let text = match fs::read_to_string(format!("/proc/{pid}/stat")) {
            Ok(v) => v,
            Err(_) => return (None, None),
        };
        let parts: Vec<_> = match text.rsplit_once(')') {
            Some((_, tail)) => tail.split_whitespace().collect(),
            None => return (None, None),
        };
        let number = |i: usize| parts.get(i).and_then(|s| s.parse::<u64>().ok());
        let ticks = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
        let pages = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        let cpu = number(11)
            .zip(number(12))
            .filter(|_| ticks > 0)
            .map(|(a, b)| (a + b) as f64 / ticks as f64);
        let rss = number(21).filter(|_| pages > 0).map(|n| n * pages as u64);
        (cpu, rss)
    }
}
fn read_bytes(stream: &mut TcpStream, n: usize) -> Result<Vec<u8>> {
    let mut bytes = vec![0; n];
    stream.read_exact(&mut bytes)?;
    Ok(bytes)
}
fn socks_login(endpoint: &Endpoint, timeout: Duration) -> Result<TcpStream> {
    let mut stream = TcpStream::connect_timeout(
        &SocketAddr::from((Ipv4Addr::LOCALHOST, endpoint.port)),
        timeout,
    )?;
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;
    stream.write_all(&[5, 1, 2])?;
    if read_bytes(&mut stream, 2)? != [5, 2] {
        return Err("SOCKS 认证方式不匹配".into());
    }
    let mut auth = b"\x01\x07onebox-".to_vec();
    auth.push(endpoint.token.len() as u8);
    auth.extend(endpoint.token.as_bytes());
    stream.write_all(&auth)?;
    if read_bytes(&mut stream, 2)? != [1, 0] {
        return Err("SOCKS 认证失败".into());
    }
    Ok(stream)
}
fn socks_address(stream: &mut TcpStream, atyp: u8) -> Result<String> {
    match atyp {
        1 => {
            let mut raw = [0; 4];
            stream.read_exact(&mut raw)?;
            Ok(Ipv4Addr::from(raw).to_string())
        }
        4 => {
            let mut raw = [0; 16];
            stream.read_exact(&mut raw)?;
            Ok(Ipv6Addr::from(raw).to_string())
        }
        3 => {
            let len = read_bytes(stream, 1)?[0] as usize;
            if len == 0 {
                return Err("SOCKS 域名为空".into());
            }
            String::from_utf8(read_bytes(stream, len)?).map_err(Into::into)
        }
        _ => Err("SOCKS 地址类型无效".into()),
    }
}
fn encode_address(host: &str, port: u16) -> Result<Vec<u8>> {
    let mut out = match host.parse::<IpAddr>() {
        Ok(IpAddr::V4(ip)) => {
            let mut v = vec![1];
            v.extend(ip.octets());
            v
        }
        Ok(IpAddr::V6(ip)) => {
            let mut v = vec![4];
            v.extend(ip.octets());
            v
        }
        Err(_) => {
            if host.is_empty()
                || host.len() > 255
                || !host.is_ascii()
                || host.bytes().any(|b| b <= 32 || b == 127)
            {
                return Err("SOCKS 域名无效".into());
            }
            let mut v = vec![3, host.len() as u8];
            v.extend(host.as_bytes());
            v
        }
    };
    out.extend(port.to_be_bytes());
    Ok(out)
}
fn socks_connect(
    endpoint: &Endpoint,
    host: &str,
    port: u16,
    timeout: Duration,
) -> Result<TcpStream> {
    let mut stream = socks_login(endpoint, timeout)?;
    let mut request = vec![5, 1, 0];
    request.extend(encode_address(host, port)?);
    stream.write_all(&request)?;
    let reply = read_bytes(&mut stream, 4)?;
    if reply[..3] != [5, 0, 0] {
        return Err("代理拒绝连接".into());
    }
    socks_address(&mut stream, reply[3])?;
    read_bytes(&mut stream, 2)?;
    Ok(stream)
}

/// curl supplies certificate validation and proxy-side DNS. The bounded reader
/// closes its pipe at the byte cap; curl then exits with WRITE_ERROR rather than
/// buffering an unbounded response. The write-out record still gives timings.
fn request(
    endpoint: Option<&Endpoint>,
    url: &str,
    options: &Options,
    limit: usize,
    upload: usize,
    direct: Option<(&str, u16)>,
) -> Result<Value> {
    let parts = url_parts(url)?;
    let work = Work::new()?;
    let headers = work.0.join("headers");
    let statistics = work.0.join("statistics");
    let config = work.0.join("curl.conf");
    let stats = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(&statistics)?;
    let mut command = Command::new("curl");
    command
        .arg("-q")
        .args([
            "--silent",
            "--http1.1",
            "--proto",
            "=http,https",
            "--max-redirs",
            "0",
            "--connect-timeout",
        ])
        .arg(options.timeout.to_string())
        .arg("--max-time")
        .arg(options.timeout.to_string())
        .args([
            "--header",
            "Accept-Encoding: identity",
            "--header",
            "Connection: close",
            "--user-agent",
            "onebox-probe/2",
        ])
        .arg("--dump-header")
        .arg(&headers)
        .arg("--write-out")
        .arg(concat!(
            "%{stderr}\nONEBOX_STATS:{\"status\":%{response_code},\"setup\":%{time_pretransfer},",
            "\"ttfb\":%{time_starttransfer},\"duration\":%{time_total},\"sent\":%{size_upload}}\n"
        ))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(stats);
    if let Some(endpoint) = endpoint {
        // Keep the temporary SOCKS credential out of process arguments.
        util::atomic_write(
            &config,
            format!("proxy-user = \"onebox-:{}\"\n", endpoint.token).as_bytes(),
            0o600,
        )?;
        command
            .arg("--config")
            .arg(&config)
            .arg("--proxy")
            .arg(format!("socks5h://127.0.0.1:{}", endpoint.port))
            .args(["--noproxy", ""]);
    } else {
        command.args(["--proxy", "", "--noproxy", "*"]);
    }
    if let Some(ca) = &options.ca {
        command.arg("--cacert").arg(ca);
    }
    if let Some((host, port)) = direct {
        if host.is_empty() || host.bytes().any(|b| b <= 32 || b == 127) {
            return Err("直连目标地址无效".into());
        }
        let bracket = |h: &str| {
            if h.contains(':') {
                format!("[{h}]")
            } else {
                h.to_owned()
            }
        };
        command.arg("--connect-to").arg(format!(
            "{}:{}:{}:{}",
            bracket(&parts.host),
            parts.port,
            bracket(host),
            port
        ));
    }
    if limit > 0 {
        command.arg("--range").arg(format!("0-{}", limit - 1));
    }
    if upload > 0 {
        let payload = work.0.join("payload");
        let mut output = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&payload)?;
        let mut random = File::open("/dev/urandom")?;
        let mut block = vec![0; 65536];
        random.read_exact(&mut block)?;
        let mut remaining = upload;
        while remaining > 0 {
            let count = remaining.min(block.len());
            output.write_all(&block[..count])?;
            remaining -= count;
        }
        drop(output);
        command
            .args([
                "--request",
                "POST",
                "--header",
                "Content-Type: application/octet-stream",
                "--header",
                "Expect:",
            ])
            .arg("--data-binary")
            .arg(format!("@{}", payload.display()));
    }
    command.arg("--url").arg(url);
    let mut child = spawn(command)?;
    let mut body = child.0.stdout.take().ok_or("无法读取 HTTP 响应")?;
    let reader = thread::spawn(move || -> std::io::Result<(usize, String)> {
        let mut count = 0;
        let mut hash = Sha256::new();
        let mut buffer = [0; 65536];
        while count < limit {
            let cap = (limit - count).min(buffer.len());
            let size = body.read(&mut buffer[..cap])?;
            if size == 0 {
                break;
            }
            hash.update(&buffer[..size]);
            count += size;
        }
        drop(body);
        Ok((count, format!("{:x}", hash.finalize())))
    });
    let status = child.wait(Duration::from_secs(options.timeout + 2));
    // On timeout/cancellation close the subprocess before joining a pipe reader.
    if status.is_err() {
        drop(child);
        let _ = reader.join();
        return Err("HTTP 请求超时或已取消".into());
    }
    let status = status?;
    let (received, digest) = reader.join().map_err(|_| "HTTP 响应读取失败")??;
    let raw = fs::read_to_string(&statistics)?;
    let record = raw
        .lines()
        .rev()
        .find_map(|line| line.strip_prefix("ONEBOX_STATS:"))
        .ok_or("HTTP 请求没有返回统计")?;
    let stats: Value = serde_json::from_str(record).map_err(|_| "HTTP 请求统计无效")?;
    let http = stats["status"].as_u64().unwrap_or(0);
    let capped = received == limit && status.code() == Some(23);
    if !status.success() && !capped {
        return Err("HTTP 请求失败（连接、TLS 或超时）".into());
    }
    let duration = stats["duration"].as_f64().unwrap_or(0.0);
    let sent = stats["sent"].as_u64().unwrap_or(0);
    let headers = fs::read_to_string(&headers).unwrap_or_default();
    let location = headers
        .lines()
        .rev()
        .find_map(|line| {
            line.split_once(':')
                .filter(|(name, _)| name.eq_ignore_ascii_case("location"))
                .map(|(_, value)| value.trim())
        })
        .unwrap_or("");
    Ok(
        json!({"ok":(200..300).contains(&http),"status":http,"setup_ms":round(stats["setup"].as_f64().unwrap_or(0.0)*1000.0),
        "ttfb_ms":round(stats["ttfb"].as_f64().unwrap_or(0.0)*1000.0),"total_ms":round(duration*1000.0),"received_bytes":received,"sent_bytes":sent,
        "download_mbps":round(received as f64*8.0/duration.max(1e-9)/1e6),"upload_mbps":round(sent as f64*8.0/duration.max(1e-9)/1e6),"body_sha256":digest,"location":location}),
    )
}
fn safe_request(
    endpoint: Option<&Endpoint>,
    url: &str,
    options: &Options,
    limit: usize,
    upload: usize,
) -> Value {
    request(endpoint, url, options, limit, upload, None)
        .unwrap_or_else(|_| json!({"ok":false,"error":"request_failed"}))
}
fn round(value: f64) -> f64 {
    (value * 1000.0).round() / 1000.0
}
fn distribution(mut values: Vec<f64>) -> Value {
    if values.is_empty() {
        return Value::Null;
    }
    values.sort_by(f64::total_cmp);
    let middle = values.len() / 2;
    let median = if values.len() & 1 == 0 {
        (values[middle - 1] + values[middle]) / 2.0
    } else {
        values[middle]
    };
    json!({"median":round(median),"p95":values[((values.len() as f64*0.95).ceil() as usize)-1]})
}
fn report(value: &Value, output: Option<&Path>) -> Result<()> {
    if let Some(path) = output {
        private_json(path, value)?;
    }
    println!("{}", serde_json::to_string_pretty(value)?);
    Ok(())
}
fn bench(ctx: &Context, entries: &[Value], options: &Options) -> Result<()> {
    let mut rows = Vec::new();
    let mut failed = false;
    for entry in ordered(entries, options.entries.as_deref(), false)? {
        if stopped() {
            break;
        }
        let mut row = json!({"id":entry["id"]});
        let test = (|| -> Result<()> {
            let core = ProxyCore::start(ctx, &entry, options)?;
            let before = core.resources();
            let mut samples = Vec::new();
            for _ in 0..options.samples {
                if stopped() {
                    break;
                }
                samples.push(safe_request(
                    Some(&core.endpoint),
                    &options.url,
                    options,
                    0,
                    0,
                ));
            }
            if samples.is_empty() {
                return Err("测试已停止".into());
            }
            let failures = samples.iter().filter(|s| s["ok"] != true).count();
            failed |= failures > 0;
            row["request_failure_rate"] = json!(failures as f64 / samples.len() as f64);
            row["ttfb_ms"] = distribution(
                samples
                    .iter()
                    .filter(|s| s["ok"] == true)
                    .filter_map(|s| s["ttfb_ms"].as_f64())
                    .collect(),
            );
            row["samples"] = json!(samples
                .iter()
                .map(|s| {
                    let mut copy = serde_json::Map::new();
                    for key in ["ok", "status", "setup_ms", "ttfb_ms", "error"] {
                        if let Some(v) = s.get(key) {
                            copy.insert(key.into(), v.clone());
                        }
                    }
                    Value::Object(copy)
                })
                .collect::<Vec<_>>());
            let mut loaded = Vec::new();
            let mut transfers = serde_json::Map::new();
            for (name, url, limit, upload) in [
                ("download", options.download_url.as_ref(), options.bytes, 0),
                ("upload", options.upload_url.as_ref(), 0, options.bytes),
            ] {
                if stopped() {
                    break;
                }
                let Some(url) = url else {
                    continue;
                };
                let endpoint = core.endpoint.clone();
                let url = url.clone();
                let opts = options.clone();
                let task = thread::spawn(move || {
                    safe_request(Some(&endpoint), &url, &opts, limit, upload)
                });
                while !task.is_finished() && loaded.len() < options.samples * 2 && !stopped() {
                    let sample = safe_request(Some(&core.endpoint), &options.url, options, 0, 0);
                    if sample["ok"] == true {
                        if let Some(v) = sample["ttfb_ms"].as_f64() {
                            loaded.push(v);
                        }
                    }
                    thread::sleep(Duration::from_millis(100));
                }
                let mut transfer = task.join().map_err(|_| "吞吐测试失败")?;
                failed |= transfer["ok"] != true;
                if let Some(object) = transfer.as_object_mut() {
                    object.remove("body_sha256");
                    object.remove("location");
                }
                transfers.insert(name.into(), transfer);
            }
            row["transfers"] = Value::Object(transfers);
            row["loaded_ttfb_ms"] = distribution(loaded);
            let after = core.resources();
            row["client_rss_bytes_at_end"] = json!(after.1);
            row["client_cpu_seconds"] =
                json!(before.0.zip(after.0).map(|(a, b)| round((b - a).max(0.0))));
            Ok(())
        })();
        if test.is_err() {
            row["error"] = json!("client_test_failed: 检查该入口所需内核、版本及配置");
            failed = true;
        }
        rows.push(row);
    }
    report(
        &json!({"schema":1,"scope":"current-machine-to-proxy-to-origin","entries":rows,"cancelled":stopped(),
        "note":"请求失败率不是网络丢包率；setup 包含代理路径与目标 TLS；吞吐包含建连开销；CPU/RSS 仅本机客户端内核。"}),
        options.output.as_deref(),
    )?;
    if stopped() {
        Err(crate::ExitError::new(130, "测试已取消").into())
    } else if failed {
        Err("部分入口测试失败，详见 JSON 报告".into())
    } else {
        Ok(())
    }
}

#[derive(Debug)]
struct FailoverPolicy {
    failures: u32,
    recoveries: u32,
    cooldown: f64,
    bad: Vec<u32>,
    good: Vec<u32>,
    available: Vec<bool>,
    active: Option<usize>,
    last_switch: Option<f64>,
}
impl FailoverPolicy {
    fn new(count: usize, failures: u32, recoveries: u32, cooldown: u64) -> Self {
        Self {
            failures,
            recoveries,
            cooldown: cooldown as f64,
            bad: vec![0; count],
            good: vec![0; count],
            available: vec![false; count],
            active: None,
            last_switch: None,
        }
    }
    fn update(&mut self, results: &[bool], now: f64) -> Option<usize> {
        for (i, ok) in results.iter().copied().enumerate() {
            self.good[i] = if ok {
                self.good[i].saturating_add(1)
            } else {
                0
            };
            self.bad[i] = if ok { 0 } else { self.bad[i].saturating_add(1) };
            if ok && (self.last_switch.is_none() || self.good[i] >= self.recoveries) {
                self.available[i] = true;
            }
            if self.bad[i] >= self.failures {
                self.available[i] = false;
            }
        }
        let candidate = results.iter().enumerate().find_map(|(i, ok)| {
            if *ok && self.available[i] {
                Some(i)
            } else {
                None
            }
        });
        let old = self.active;
        match old {
            None => self.active = candidate,
            Some(active) if !self.available[active] => self.active = candidate,
            Some(active) => {
                if let Some(next) = candidate {
                    if next < active
                        && now - self.last_switch.unwrap_or(f64::NEG_INFINITY) >= self.cooldown
                        && self.good[next] >= self.recoveries
                    {
                        self.active = Some(next);
                    }
                }
            }
        }
        if old != self.active {
            self.last_switch = Some(now);
        }
        self.active
    }
}

/// Bounded, nonblocking relay with TCP half-close support. Switching the policy
/// affects only future connections; established streams keep their core.
fn relay(mut left: TcpStream, mut right: TcpStream) -> Result<()> {
    left.set_nonblocking(true)?;
    right.set_nonblocking(true)?;
    let mut to_left = Vec::new();
    let mut to_right = Vec::new();
    let mut left_read = true;
    let mut right_read = true;
    let mut left_closed = false;
    let mut right_closed = false;
    let mut last = Instant::now();
    let mut buffer = [0; 65536];
    while !stopped() && last.elapsed() < Duration::from_secs(300) {
        if !left_read && to_right.is_empty() && !right_closed {
            let _ = right.shutdown(Shutdown::Write);
            right_closed = true;
        }
        if !right_read && to_left.is_empty() && !left_closed {
            let _ = left.shutdown(Shutdown::Write);
            left_closed = true;
        }
        if !left_read && !right_read && to_left.is_empty() && to_right.is_empty() {
            break;
        }
        let mut progress = false;
        for (stream, readable, destination) in [
            (&mut left, &mut left_read, &mut to_right),
            (&mut right, &mut right_read, &mut to_left),
        ] {
            if !*readable || destination.len() >= 262144 {
                continue;
            }
            let cap = (262144 - destination.len()).min(buffer.len());
            match stream.read(&mut buffer[..cap]) {
                Ok(0) => {
                    *readable = false;
                    progress = true;
                }
                Ok(n) => {
                    destination.extend_from_slice(&buffer[..n]);
                    progress = true;
                }
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                    ) => {}
                Err(e) => return Err(e.into()),
            }
        }
        for (stream, source) in [(&mut left, &mut to_left), (&mut right, &mut to_right)] {
            if source.is_empty() {
                continue;
            }
            match stream.write(source) {
                Ok(0) => return Err("转发连接已关闭".into()),
                Ok(n) => {
                    source.drain(..n);
                    progress = true;
                }
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                    ) => {}
                Err(e) => return Err(e.into()),
            }
        }
        if progress {
            last = Instant::now();
        } else {
            thread::sleep(Duration::from_millis(5));
        }
    }
    Ok(())
}
fn front_connection(
    mut stream: TcpStream,
    cores: &[ProxyCore],
    active: &Mutex<Option<usize>>,
    timeout: u64,
) -> Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    let hello = read_bytes(&mut stream, 2)?;
    if hello[0] != 5 || hello[1] == 0 {
        return Err("SOCKS 请求无效".into());
    }
    let methods = read_bytes(&mut stream, hello[1] as usize)?;
    if !methods.contains(&0) {
        stream.write_all(&[5, 255])?;
        return Ok(());
    }
    stream.write_all(&[5, 0])?;
    let request = read_bytes(&mut stream, 4)?;
    if request[..3] != [5, 1, 0] {
        stream.write_all(&[5, 7, 0, 1, 0, 0, 0, 0, 0, 0])?;
        return Ok(());
    }
    let host = socks_address(&mut stream, request[3])?;
    let port = read_bytes(&mut stream, 2)?;
    let port = u16::from_be_bytes([port[0], port[1]]);
    let selected = *active.lock().unwrap();
    let upstream = selected
        .and_then(|i| cores.get(i))
        .ok_or_else(|| "无健康入口".into())
        .and_then(|core| socks_connect(&core.endpoint, &host, port, Duration::from_secs(timeout)));
    match upstream {
        Ok(upstream) => {
            stream.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0])?;
            relay(stream, upstream)
        }
        Err(e) => {
            let _ = stream.write_all(&[5, 4, 0, 1, 0, 0, 0, 0, 0, 0]);
            Err(e)
        }
    }
}
fn failover(ctx: &Context, entries: &[Value], options: &Options) -> Result<()> {
    let entries = ordered(entries, options.entries.as_deref(), true)?;
    if !(2..=8).contains(&entries.len()) {
        return Err(
            "回退需要 2 至 8 个入口；使用 --entries 指定顺序，或 probe merge 合并服务器配置".into(),
        );
    }
    let mut started = Vec::new();
    for entry in &entries {
        started.push(ProxyCore::start(ctx, entry, options)?);
    }
    let cores = Arc::new(started);
    let active = Arc::new(Mutex::new(None));
    let slots = Arc::new(AtomicUsize::new(0));
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, options.port))?;
    listener.set_nonblocking(true)?;
    let mut policy = FailoverPolicy::new(
        entries.len(),
        options.failures,
        options.recoveries,
        options.cooldown,
    );
    let clock = Instant::now();
    let mut next_round = Instant::now();
    let mut workers = Vec::new();
    let mut ready = false;
    let mut round: Option<thread::JoinHandle<Vec<bool>>> = None;
    let mut failure = None;
    while !stopped() {
        if round.as_ref().is_some_and(|task| task.is_finished()) {
            let health = round
                .take()
                .unwrap()
                .join()
                .unwrap_or_else(|_| vec![false; cores.len()]);
            let old = policy.active;
            let new = policy.update(&health, clock.elapsed().as_secs_f64());
            *active.lock().unwrap() = new;
            if old != new {
                println!(
                    "{}",
                    json!({"event":"switch","from":old.map(|i|entries[i]["id"].clone()),"to":new.map(|i|entries[i]["id"].clone())})
                );
                let _ = std::io::stdout().flush();
            }
            if !ready {
                println!(
                    "{}",
                    json!({"event":"ready","socks":format!("127.0.0.1:{}",options.port),"entries":entries.iter().map(|e|e["id"].clone()).collect::<Vec<_>>(),"tcp_only":true})
                );
                let _ = std::io::stdout().flush();
                ready = true;
            }
            next_round = Instant::now() + Duration::from_secs(options.interval);
        }
        if round.is_none() && Instant::now() >= next_round {
            let endpoints = cores
                .iter()
                .map(|core| core.endpoint.clone())
                .collect::<Vec<_>>();
            let options = options.clone();
            round = Some(thread::spawn(move || {
                thread::scope(|scope| {
                    let handles = endpoints
                        .iter()
                        .map(|endpoint| {
                            scope.spawn(|| {
                                safe_request(Some(endpoint), &options.url, &options, 0, 0)["ok"]
                                    == true
                            })
                        })
                        .collect::<Vec<_>>();
                    handles
                        .into_iter()
                        .map(|handle| handle.join().unwrap_or(false))
                        .collect::<Vec<_>>()
                })
            }));
        }
        loop {
            match listener.accept() {
                Ok((stream, _)) => {
                    if slots.load(Ordering::Relaxed) >= 128 {
                        drop(stream);
                        continue;
                    }
                    slots.fetch_add(1, Ordering::Relaxed);
                    let cores = cores.clone();
                    let active = active.clone();
                    let slots = slots.clone();
                    let timeout = options.timeout;
                    workers.push(thread::spawn(move || {
                        let _ = front_connection(stream, &cores, &active, timeout);
                        slots.fetch_sub(1, Ordering::Relaxed);
                    }));
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => {
                    failure = Some(e);
                    STOP.store(true, Ordering::Relaxed);
                    break;
                }
            }
        }
        let mut i = 0;
        while i < workers.len() {
            if workers[i].is_finished() {
                let _ = workers.swap_remove(i).join();
            } else {
                i += 1;
            }
        }
        thread::sleep(Duration::from_millis(20));
    }
    drop(listener);
    // Wake blocking SOCKS reads before joining relay workers on shutdown.
    for core in cores.iter() {
        core.terminate();
    }
    if let Some(task) = round {
        let _ = task.join();
    }
    for worker in workers {
        let _ = worker.join();
    }
    // Arc references are now gone; dropping cores terminates all native clients.
    drop(cores);
    if let Some(error) = failure {
        Err(error.into())
    } else {
        Ok(())
    }
}

fn captured(mut command: Command, input: Option<&[u8]>, timeout: Duration) -> Result<Vec<u8>> {
    let work = Work::new()?;
    let path = work.0.join("output");
    let output = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(&path)?;
    command.stdout(output.try_clone()?).stderr(output);
    if input.is_some() {
        command.stdin(Stdio::piped());
    } else {
        command.stdin(Stdio::null());
    }
    let mut child = spawn(command)?;
    if let Some(input) = input {
        if let Some(mut stdin) = child.0.stdin.take() {
            stdin.write_all(input)?;
        }
    }
    if !child.wait(timeout)?.success() {
        return Err("TLS 探测失败".into());
    }
    let mut raw = Vec::new();
    File::open(path)?
        .take(1024 * 1024 + 1)
        .read_to_end(&mut raw)?;
    if raw.len() > 1024 * 1024 {
        return Err("TLS 响应过大".into());
    }
    Ok(raw)
}
fn tls_probe(host: &str, port: u16, sni: &str, options: &Options) -> Result<Value> {
    if host.is_empty()
        || host.bytes().any(|b| b <= 32 || b == 127)
        || sni.is_empty()
        || sni.starts_with('-')
        || sni.bytes().any(|b| b <= 32 || b == 127)
    {
        return Err("TLS 探测目标无效".into());
    }
    let address = if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    };
    let mut command = Command::new("openssl");
    command.args([
        "s_client",
        "-connect",
        &address,
        "-servername",
        sni,
        "-verify_hostname",
        sni,
        "-verify_return_error",
        "-tls1_3",
        "-alpn",
        "h2,http/1.1",
        "-showcerts",
        "-no_ign_eof",
    ]);
    if let Some(ca) = &options.ca {
        command.arg("-CAfile").arg(ca);
    }
    let raw = captured(command, None, Duration::from_secs(options.timeout))?;
    let text = String::from_utf8_lossy(&raw);
    let start = text
        .find("-----BEGIN CERTIFICATE-----")
        .ok_or("TLS 响应缺少证书")?;
    let end = text[start..]
        .find("-----END CERTIFICATE-----")
        .ok_or("TLS 响应证书无效")?
        + start
        + "-----END CERTIFICATE-----".len();
    let mut cert = Command::new("openssl");
    cert.args(["x509", "-outform", "DER"]);
    let der = captured(
        cert,
        Some(text[start..end].as_bytes()),
        Duration::from_secs(options.timeout),
    )?;
    let alpn = text
        .lines()
        .find_map(|line| line.strip_prefix("ALPN protocol: "))
        .map(str::trim);
    Ok(json!({"tls":"TLSv1.3","alpn":alpn,"certificate_sha256":util::sha256(&der)}))
}
fn random_wrong_short_id(entry: &Value) -> Result<Value> {
    let mut wrong = entry.clone();
    let target = if entry["core"] == "singbox" {
        wrong.pointer_mut("/outbounds/0/tls/reality/short_id")
    } else {
        wrong.pointer_mut("/outbounds/0/streamSettings/realitySettings/shortId")
    }
    .ok_or("REALITY 出站缺少 short ID")?;
    let old = target.as_str().ok_or("REALITY short ID 类型无效")?;
    let mut next = util::random_hex(8)?;
    while next == old {
        next = util::random_hex(8)?;
    }
    *target = json!(next);
    Ok(wrong)
}
fn reality(ctx: &Context, entries: &[Value], options: &Options) -> Result<()> {
    let mut rows = Vec::new();
    let mut failed = false;
    let mut warned = false;
    for entry in ordered(entries, options.entries.as_deref(), false)? {
        if stopped() {
            break;
        }
        let Some(meta) = entry.get("reality") else {
            continue;
        };
        let mut checks = serde_json::Map::new();
        let mut warnings = Vec::<String>::new();
        let ordinary = (|| -> Result<()> {
            let host = meta["host"].as_str().ok_or("REALITY host 无效")?;
            let port = meta["port"].as_u64().ok_or("REALITY port 无效")? as u16;
            let sni = meta["sni"].as_str().ok_or("REALITY SNI 无效")?;
            let first = tls_probe(host, port, sni, options)?;
            checks.insert("ordinary_tls13_valid_certificate".into(), json!(true));
            checks.insert("ordinary_h2".into(), json!(first["alpn"] == "h2"));
            let reference = meta["reference_host"].as_str().unwrap_or("");
            if !reference.is_empty() {
                let reference_port = meta["reference_port"]
                    .as_u64()
                    .filter(|v| (1..=65535).contains(v))
                    .ok_or("REALITY 参考端口无效")? as u16;
                let second = tls_probe(reference, reference_port, sni, options)?;
                checks.insert(
                    "same_certificate".into(),
                    json!(first["certificate_sha256"] == second["certificate_sha256"]),
                );
                checks.insert("same_alpn".into(), json!(first["alpn"] == second["alpn"]));
                let url = format!("https://{sni}/");
                let first = request(None, &url, options, 65536, 0, Some((host, port)))?;
                let second = request(
                    None,
                    &url,
                    options,
                    65536,
                    0,
                    Some((reference, reference_port)),
                )?;
                checks.insert(
                    "same_http_status".into(),
                    json!(first["status"] == second["status"]),
                );
                checks.insert(
                    "same_redirect".into(),
                    json!(first["location"] == second["location"]),
                );
                if first["body_sha256"] != second["body_sha256"] {
                    warnings
                        .push("前 64 KiB 内容不同；动态页面可能正常，需核对有无特有错误页".into());
                }
            } else {
                warnings.push("自建站未开放可比较的 HTTPS 入口；可在服务器执行本地检查".into());
            }
            Ok(())
        })();
        if ordinary.is_err() {
            checks.insert("ordinary_or_reference_probe".into(), json!(false));
            warnings.push("TLS 或参考站点探测失败；检查地址、CA 和可达性".into());
        }
        let authenticated = (|| -> Result<()> {
            let core = ProxyCore::start(ctx, &entry, options)?;
            let positive =
                safe_request(Some(&core.endpoint), &options.url, options, 0, 0)["ok"] == true;
            checks.insert("authenticated_proxy".into(), json!(positive));
            drop(core);
            // A rejected wrong credential only counts if the valid credential
            // reaches the same origin, so an unavailable origin cannot pass.
            let wrong = random_wrong_short_id(&entry)?;
            let core = ProxyCore::start(ctx, &wrong, options)?;
            let rejected =
                safe_request(Some(&core.endpoint), &options.url, options, 0, 0)["ok"] != true;
            checks.insert(
                "wrong_short_id_rejected".into(),
                json!(positive && rejected),
            );
            Ok(())
        })();
        if authenticated.is_err() {
            checks.insert("authentication_test_completed".into(), json!(false));
        }
        failed |= checks.values().any(|value| value != true);
        warned |= !warnings.is_empty();
        rows.push(json!({"id":entry["id"],"checks":checks,"warnings":warnings}));
    }
    if rows.is_empty() {
        return Err("配置中没有 REALITY 入口".into());
    }
    report(
        &json!({"schema":1,"scope":options.scope,"entries":rows,"cancelled":stopped(),
        "note":"普通 TLS 回落与错误 short ID 的代理拒绝分别测试；不证明不可识别或公网可达。"}),
        options.output.as_deref(),
    )?;
    if stopped() {
        Err(crate::ExitError::new(130, "REALITY 检查已取消").into())
    } else if failed {
        Err("REALITY 检查失败，详见 JSON 报告".into())
    } else if warned {
        Err(crate::ExitError::new(2, "REALITY 检查完成，请核对报告中的警告。").into())
    } else {
        Ok(())
    }
}
fn probe(ctx: &Context, args: &[String]) -> Result<()> {
    match args.first().map(String::as_str) {
        Some("export") if args.len() == 2 => {
            let state = crate::state::load(ctx)?;
            let bundle = crate::render::probe_bundle(ctx, &state, false)?;
            validate_bundle(bundle.clone())?;
            private_json(Path::new(&args[1]), &bundle)?;
            println!("已导出: {}（含客户端凭据，请私密传输）", args[1]);
            Ok(())
        }
        Some("list") if args.len() == 2 => {
            for e in load_bundle(Path::new(&args[1]))? {
                println!(
                    "{}\t{}\t{}",
                    e["id"].as_str().unwrap_or(""),
                    e["transport"].as_str().unwrap_or(""),
                    e["core"].as_str().unwrap_or("")
                );
            }
            Ok(())
        }
        Some("merge") if args.len() >= 3 => {
            let mut entries = Vec::new();
            for (i, path) in args[2..].iter().enumerate() {
                for mut entry in load_bundle(Path::new(path))? {
                    entry["id"] =
                        json!(format!("n{}-{}", i + 1, entry["id"].as_str().unwrap_or("")));
                    entries.push(entry);
                }
            }
            let bundle = json!({"schema":1,"entries":entries});
            validate_bundle(bundle.clone())?;
            private_json(Path::new(&args[1]), &bundle)?;
            println!("已合并到 {}", args[1]);
            Ok(())
        }
        _ => Err(
            "用法: onebox probe export <新文件> | list <配置> | merge <新文件> <配置...>".into(),
        ),
    }
}
fn help(command: &str) {
    if command == "probe" {
        println!("onebox probe export <新文件> | list <配置> | merge <新文件> <配置...>");
        return;
    }
    println!("onebox {command} <probe.json> [--entries ID,ID] [--singbox 路径] [--xray 路径]\n  --url HTTPS健康端点  --timeout 1..60  --ca 自有CA文件");
    match command{
        "bench"=>println!("  --samples 1..20  --download-url URL  --upload-url URL  --bytes 1024..67108864  --output 新报告\n下载与上传仅在明确指定端点时执行，健康检查不跟随跳转。"),
        "failover"=>println!("  --port 1024..65535  --interval 1..3600  --failures 1..20  --recoveries 1..20  --cooldown 0..3600\n仅监听 127.0.0.1；SOCKS5 TCP；既有连接不迁移。支持 TCP 及 QUIC 代理传输。"),
        "reality-check"=>println!("  --output 新报告  --scope server-local|current-machine-to-server\n省略配置文件时，读取本机状态并使用回环地址。"),_=>{}
    }
}
/// Entry point used by the native CLI. No Python or legacy shell is launched.
pub fn command(ctx: &Context, command: &str, args: &[String]) -> Result<()> {
    if args
        .iter()
        .any(|arg| matches!(arg.as_str(), "--help" | "-h"))
    {
        help(command);
        return Ok(());
    }
    if command == "probe" {
        return probe(ctx, args);
    }
    if !matches!(command, "bench" | "failover" | "reality-check") {
        return Err("未知客户端工具命令".into());
    }
    let mut options = parse_options(command, args)?;
    let entries = if let Some(path) = &options.bundle {
        load_bundle(path)?
    } else if command == "reality-check" {
        options.scope = "server-local".into();
        eprintln!("本机回环检查；完整公网路径请在客户端使用 probe export 的配置。");
        validate_bundle(crate::render::probe_bundle(
            ctx,
            &crate::state::load(ctx)?,
            true,
        )?)?
    } else {
        return Err(format!("onebox {command} 需要 probe.json 配置文件").into());
    };
    let _signals = Signals::install();
    match command {
        "bench" => bench(ctx, &entries, &options),
        "failover" => failover(ctx, &entries, &options),
        "reality-check" => reality(ctx, &entries, &options),
        _ => unreachable!(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    fn entry(id: &str) -> Value {
        json!({"id":id,"core":"singbox","transport":"tcp","tag":"proxy","outbounds":[{"type":"vless","tag":"proxy"}]})
    }
    #[test]
    fn validate_protocols_ids_and_limits() {
        let good = entry("first");
        assert_eq!(
            validate_bundle(json!({"schema":1,"entries":[good.clone()]}))
                .unwrap()
                .len(),
            1
        );
        assert!(validate_bundle(json!({"schema":true,"entries":[good.clone()]})).is_err());
        assert!(
            validate_bundle(json!({"schema":1,"entries":[good.clone(),good.clone()]})).is_err()
        );
        let mut bad = good.clone();
        bad["outbounds"][0]["type"] = json!("direct");
        assert!(validate_bundle(json!({"schema":1,"entries":[bad]})).is_err());
        let mut bad = good;
        bad["tag"] = json!("elsewhere");
        assert!(validate_bundle(json!({"schema":1,"entries":[bad]})).is_err());
        let work = Work::new().unwrap();
        let path = work.0.join("large");
        fs::write(&path, vec![b'a'; MAX_BUNDLE as usize + 1]).unwrap();
        assert!(load_bundle(&path).is_err());
    }
    #[test]
    fn exports_never_overwrite_files_or_symlinks() {
        let work = Work::new().unwrap();
        let path = work.0.join("report.json");
        private_json(&path, &json!({"ok":true})).unwrap();
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert!(private_json(&path, &json!({})).is_err());
        let link = work.0.join("link");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        assert!(private_json(&link, &json!({})).is_err());
    }
    #[test]
    fn strict_urls_and_cli_ranges() {
        for url in [
            "file:///etc/passwd",
            "https://a:b@example.org",
            "https://x/#frag",
            "https://x/\r\nInjected:yes",
            "https://[::1]:0/",
            "https://x:65536/",
            "https://x\\@elsewhere",
        ] {
            assert!(url_parts(url).is_err(), "{url}");
        }
        assert_eq!(url_parts("https://[::1]:8443/path?q=1").unwrap().port, 8443);
        assert_eq!(url_parts("http://localhost/").unwrap().host, "localhost");
        assert!(parse_options("bench", &["f".into(), "--timeout".into(), "0".into()]).is_err());
        assert!(parse_options("failover", &["f".into(), "--port".into(), "80".into()]).is_err());
    }
    #[test]
    fn select_order_and_default_tcp_quic_pair() {
        let mut quic = entry("quic");
        quic["transport"] = json!("udp");
        let entries = [quic, entry("tcp"), entry("more")];
        let selected = ordered(&entries, None, true).unwrap();
        assert_eq!(selected[0]["id"], "tcp");
        assert_eq!(selected[1]["id"], "quic");
        assert_eq!(
            ordered(&entries, Some("more,tcp"), false).unwrap()[0]["id"],
            "more"
        );
        for invalid in ["tcp,tcp", "missing", ""] {
            assert!(ordered(&entries, Some(invalid), false).is_err());
        }
    }
    #[test]
    fn failure_streak_not_cumulative() {
        let mut p = FailoverPolicy::new(2, 3, 2, 60);
        assert_eq!(p.update(&[true, true], 0.0), Some(0));
        for (t, ok) in [(1.0, false), (2.0, true), (3.0, false), (4.0, false)] {
            assert_eq!(p.update(&[ok, true], t), Some(0));
        }
        assert_eq!(p.update(&[false, true], 5.0), Some(1));
    }
    #[test]
    fn recovery_needs_streak_and_cooldown() {
        let mut p = FailoverPolicy::new(2, 2, 3, 60);
        p.update(&[true, true], 0.0);
        p.update(&[false, true], 1.0);
        assert_eq!(p.update(&[false, true], 2.0), Some(1));
        for t in [3.0, 4.0, 5.0, 61.0] {
            assert_eq!(p.update(&[true, true], t), Some(1));
        }
        assert_eq!(p.update(&[true, true], 62.0), Some(0));
    }
    #[test]
    fn dead_active_bypasses_cooldown_no_direct() {
        let mut p = FailoverPolicy::new(2, 1, 1, 60);
        assert_eq!(p.update(&[true, true], 0.0), Some(0));
        assert_eq!(p.update(&[false, true], 1.0), Some(1));
        assert_eq!(p.update(&[false, false], 2.0), None);
        assert_eq!(p.update(&[true, false], 3.0), Some(0));
        let mut p = FailoverPolicy::new(3, 1, 2, 0);
        p.update(&[true, false, true], 0.0);
        assert_eq!(p.update(&[false, true, true], 1.0), Some(2));
        assert_eq!(p.update(&[false, true, true], 2.0), Some(1));
    }
    #[test]
    fn distribution_uses_nearest_rank_p95() {
        assert_eq!(
            distribution(vec![4.0, 1.0, 2.0, 3.0]),
            json!({"median":2.5,"p95":4.0})
        );
        assert!(distribution(vec![]).is_null());
    }
    fn pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let one = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let two = listener.accept().unwrap().0;
        one.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        two.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        (one, two)
    }
    #[test]
    fn relay_propagates_half_close_and_response() {
        let (mut a, left) = pair();
        let (right, mut b) = pair();
        let worker = thread::spawn(move || relay(left, right));
        a.write_all(b"request").unwrap();
        a.shutdown(Shutdown::Write).unwrap();
        let mut request = String::new();
        b.read_to_string(&mut request).unwrap();
        assert_eq!(request, "request");
        b.write_all(b"response").unwrap();
        b.shutdown(Shutdown::Write).unwrap();
        let mut response = String::new();
        a.read_to_string(&mut response).unwrap();
        assert_eq!(response, "response");
        worker.join().unwrap().unwrap();
    }
    #[test]
    fn invalid_reality_short_id_is_changed_only_in_copy() {
        let mut original = entry("anytls-reality");
        original["outbounds"][0]["tls"] = json!({"reality":{"short_id":"1234"}});
        let changed = random_wrong_short_id(&original).unwrap();
        assert_eq!(
            original["outbounds"][0]["tls"]["reality"]["short_id"],
            "1234"
        );
        assert_ne!(
            changed["outbounds"][0]["tls"]["reality"]["short_id"],
            "1234"
        );
    }
    #[test]
    fn http_cap_status_and_upload_via_real_curl() {
        if Command::new("curl")
            .arg("--version")
            .stdout(Stdio::null())
            .status()
            .is_err()
        {
            return;
        }
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let worker = thread::spawn(move || {
            for code in [200, 503] {
                let (mut stream, _) = listener.accept().unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(3)))
                    .unwrap();
                let mut raw = vec![0; 8192];
                let _ = stream.read(&mut raw);
                let _ = write!(
                    stream,
                    "HTTP/1.1 {code} Test\r\nContent-Length: 200000\r\nConnection: close\r\n\r\n"
                );
                let _ = stream.write_all(&vec![b'x'; 200000]);
            }
        });
        let options = Options {
            timeout: 3,
            ..Default::default()
        };
        let url = format!("http://127.0.0.1:{port}/");
        let result = request(None, &url, &options, 1024, 0, None).unwrap();
        assert_eq!(result["received_bytes"], 1024);
        assert_eq!(result["ok"], true);
        assert_eq!(
            request(None, &url, &options, 0, 0, None).unwrap()["ok"],
            false
        );
        worker.join().unwrap();
    }
    #[test]
    fn slow_headers_obey_total_deadline() {
        if Command::new("curl")
            .arg("--version")
            .stdout(Stdio::null())
            .status()
            .is_err()
        {
            return;
        }
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let worker = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut raw = [0; 4096];
            let _ = stream.read(&mut raw);
            let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nX-Slow: ");
            for _ in 0..30 {
                if stream.write_all(b"x").is_err() {
                    break;
                }
                thread::sleep(Duration::from_millis(100));
            }
        });
        let started = Instant::now();
        assert!(request(
            None,
            &format!("http://127.0.0.1:{port}/"),
            &Options {
                timeout: 1,
                ..Default::default()
            },
            0,
            0,
            None
        )
        .is_err());
        assert!(started.elapsed() < Duration::from_secs(2));
        worker.join().unwrap();
    }
    #[test]
    fn native_xray_proxy_and_child_cleanup() {
        let Some(binary) = std::env::var_os("ONEBOX_TEST_XRAY").map(PathBuf::from) else {
            return;
        };
        let work = Work::new().unwrap();
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let config = work.0.join("server.json");
        private_json(&config,&json!({"log":{"loglevel":"none"},"inbounds":[{"listen":"127.0.0.1","port":port,"protocol":"shadowsocks","settings":{"method":"aes-128-gcm","password":"runtime-local-test-secret","network":"tcp,udp"}}],"outbounds":[{"protocol":"freedom","tag":"direct"}]})).unwrap();
        let mut server = Command::new(&binary);
        server
            .args(["run", "-c"])
            .arg(&config)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let _server = spawn(server).unwrap();
        let deadline = Instant::now() + Duration::from_secs(3);
        while TcpStream::connect((Ipv4Addr::LOCALHOST, port)).is_err() {
            assert!(Instant::now() < deadline);
            thread::sleep(Duration::from_millis(20));
        }
        let entry = json!({"id":"ss","core":"xray","transport":"both","tag":"proxy","outbounds":[{"protocol":"shadowsocks","tag":"proxy","settings":{"servers":[{"address":"127.0.0.1","port":port,"method":"aes-128-gcm","password":"runtime-local-test-secret"}]}}]});
        let options = Options {
            xray: Some(binary),
            timeout: 2,
            ..Default::default()
        };
        let core = ProxyCore::start(&Context::default(), &entry, &options).unwrap();
        let pid = core.process.lock().unwrap().0.id();
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let http = listener.local_addr().unwrap().port();
        let worker = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut buffer = [0; 4096];
            assert!(stream.read(&mut buffer).unwrap() > 0);
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\nConnection: close\r\n\r\nproxy-ok",
                )
                .unwrap();
        });
        let result = request(
            Some(&core.endpoint),
            &format!("http://127.0.0.1:{http}/"),
            &options,
            1024,
            0,
            None,
        )
        .unwrap();
        assert_eq!(result["ok"], true);
        assert_eq!(result["received_bytes"], 8);
        assert_eq!(result["body_sha256"], util::sha256(b"proxy-ok"));
        worker.join().unwrap();
        drop(core);
        assert!(!Path::new(&format!("/proc/{pid}")).exists());
    }
    #[test]
    fn native_openssl_tls_probe_validates_certificate() {
        if Command::new("openssl")
            .arg("version")
            .stdout(Stdio::null())
            .status()
            .is_err()
        {
            return;
        }
        let work = Work::new().unwrap();
        let cert = work.0.join("cert.pem");
        let key = work.0.join("key.pem");
        let mut generation = Command::new("openssl");
        generation
            .args([
                "req",
                "-x509",
                "-newkey",
                "ec",
                "-pkeyopt",
                "ec_paramgen_curve:P-256",
                "-nodes",
                "-days",
                "1",
                "-subj",
                "/CN=localhost",
                "-addext",
                "subjectAltName=DNS:localhost",
                "-keyout",
            ])
            .arg(&key)
            .arg("-out")
            .arg(&cert);
        captured(generation, None, Duration::from_secs(5)).unwrap();
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let mut server = Command::new("openssl");
        server
            .args(["s_server", "-accept"])
            .arg(format!("127.0.0.1:{port}"))
            .arg("-cert")
            .arg(&cert)
            .arg("-key")
            .arg(&key)
            .args(["-www", "-quiet", "-alpn", "h2,http/1.1"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let _server = spawn(server).unwrap();
        let deadline = Instant::now() + Duration::from_secs(3);
        while TcpStream::connect((Ipv4Addr::LOCALHOST, port)).is_err() {
            assert!(Instant::now() < deadline);
            thread::sleep(Duration::from_millis(20));
        }
        let options = Options {
            ca: Some(cert),
            timeout: 2,
            ..Default::default()
        };
        let result = tls_probe("127.0.0.1", port, "localhost", &options).unwrap();
        assert_eq!(result["tls"], "TLSv1.3");
        assert_eq!(result["alpn"], "h2");
        assert!(tls_probe("127.0.0.1", port, "wrong.localhost", &options).is_err());
        assert!(tls_probe(
            "127.0.0.1",
            port,
            "localhost",
            &Options {
                timeout: 2,
                ..Default::default()
            }
        )
        .is_err());
    }

    fn free_tcp_port() -> u16 {
        TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .unwrap()
            .local_addr()
            .unwrap()
            .port()
    }
    fn test_http_once() -> (u16, thread::JoinHandle<()>) {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        listener.set_nonblocking(true).unwrap();
        let worker = thread::spawn(move || {
            let end = Instant::now() + Duration::from_secs(10);
            let mut stream = loop {
                match listener.accept() {
                    Ok((stream, _)) => break stream,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        if Instant::now() >= end {
                            return;
                        }
                        thread::sleep(Duration::from_millis(20));
                    }
                    Err(_) => return,
                }
            };
            stream
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            let mut raw = [0; 4096];
            let _ = stream.read(&mut raw);
            let _ = stream.write_all(
                b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\nConnection: close\r\n\r\nproxy-ok",
            );
        });
        (port, worker)
    }
    #[test]
    fn native_singbox_quic_and_reality_authentication() {
        let Some(binary) = std::env::var_os("ONEBOX_TEST_SINGBOX").map(PathBuf::from) else {
            return;
        };
        let work = Work::new().unwrap();
        let cert = work.0.join("cert.pem");
        let key = work.0.join("key.pem");
        let mut generation = Command::new("openssl");
        generation
            .args([
                "req",
                "-x509",
                "-newkey",
                "ec",
                "-pkeyopt",
                "ec_paramgen_curve:P-256",
                "-nodes",
                "-days",
                "1",
                "-subj",
                "/CN=localhost",
                "-addext",
                "subjectAltName=DNS:localhost",
                "-keyout",
            ])
            .arg(&key)
            .arg("-out")
            .arg(&cert);
        captured(generation, None, Duration::from_secs(5)).unwrap();
        let tls_port = free_tcp_port();
        let mut tls = Command::new("openssl");
        tls.args(["s_server", "-accept"])
            .arg(format!("127.0.0.1:{tls_port}"))
            .arg("-cert")
            .arg(&cert)
            .arg("-key")
            .arg(&key)
            .args(["-www", "-quiet", "-alpn", "h2,http/1.1"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let _tls = spawn(tls).unwrap();
        let mut pair = Command::new(&binary);
        pair.args(["generate", "reality-keypair"]);
        let raw = captured(pair, None, Duration::from_secs(5)).unwrap();
        let pair = String::from_utf8(raw).unwrap();
        let private = pair
            .lines()
            .find_map(|line| {
                line.split_once(':')
                    .filter(|(name, _)| name.to_lowercase().contains("private"))
                    .map(|(_, key)| key.trim())
            })
            .unwrap();
        let public = pair
            .lines()
            .find_map(|line| {
                line.split_once(':')
                    .filter(|(name, _)| name.to_lowercase().contains("public"))
                    .map(|(_, key)| key.trim())
            })
            .unwrap();
        let any_port = free_tcp_port();
        let hy_port = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let config = work.0.join("server.json");
        private_json(&config,&json!({"log":{"disabled":true},"inbounds":[
            {"type":"anytls","listen":"127.0.0.1","listen_port":any_port,"users":[{"name":"test","password":"local-test"}],"tls":{"enabled":true,"server_name":"localhost","reality":{"enabled":true,"private_key":private,"short_id":["0123456789abcdef"],"handshake":{"server":"127.0.0.1","server_port":tls_port}}}},
            {"type":"hysteria2","listen":"127.0.0.1","listen_port":hy_port,"users":[{"name":"test","password":"local-test"}],"tls":{"enabled":true,"server_name":"localhost","certificate_path":cert,"key_path":key}}],"outbounds":[{"type":"direct","tag":"direct"}]})).unwrap();
        let mut server = Command::new(&binary);
        server
            .args(["run", "-c"])
            .arg(&config)
            .arg("-D")
            .arg(&work.0)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let _server = spawn(server).unwrap();
        let deadline = Instant::now() + Duration::from_secs(3);
        while TcpStream::connect((Ipv4Addr::LOCALHOST, any_port)).is_err() {
            assert!(Instant::now() < deadline);
            thread::sleep(Duration::from_millis(20));
        }
        let options = Options {
            singbox: Some(binary),
            timeout: 2,
            ca: Some(cert.clone()),
            ..Default::default()
        };
        let mut any = json!({"id":"anytls-reality","core":"singbox","transport":"tcp","tag":"proxy","outbounds":[{"type":"anytls","tag":"proxy","server":"127.0.0.1","server_port":any_port,"password":"local-test","tls":{"enabled":true,"server_name":"localhost","utls":{"enabled":true,"fingerprint":"chrome"},"reality":{"enabled":true,"public_key":public,"short_id":"0123456789abcdef"}}}]});
        let hy = json!({"id":"hy","core":"singbox","transport":"udp","tag":"proxy","outbounds":[{"type":"hysteria2","tag":"proxy","server":"127.0.0.1","server_port":hy_port,"password":"local-test","tls":{"enabled":true,"server_name":"localhost","certificate_path":cert}}]});
        for entry in [&any, &hy] {
            let core = ProxyCore::start(&Context::default(), entry, &options).unwrap();
            let (port, worker) = test_http_once();
            let result = request(
                Some(&core.endpoint),
                &format!("http://127.0.0.1:{port}/"),
                &options,
                1024,
                0,
                None,
            )
            .unwrap();
            assert_eq!(result["body_sha256"], util::sha256(b"proxy-ok"));
            worker.join().unwrap();
        }
        let reference = tls_probe("127.0.0.1", tls_port, "localhost", &options).unwrap();
        let fallback = tls_probe("127.0.0.1", any_port, "localhost", &options).unwrap();
        assert_eq!(
            reference["certificate_sha256"],
            fallback["certificate_sha256"]
        );
        // Both attempts use one live origin. A broken implementation that
        // accepts the bad credential receives a 200 and must fail this test.
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        listener.set_nonblocking(true).unwrap();
        let finish = Arc::new(AtomicBool::new(false));
        let done = finish.clone();
        let origin = thread::spawn(move || {
            let end = Instant::now() + Duration::from_secs(10);
            while !done.load(Ordering::Relaxed) && Instant::now() < end {
                if let Ok((mut stream, _)) = listener.accept() {
                    stream
                        .set_read_timeout(Some(Duration::from_secs(2)))
                        .unwrap();
                    let mut raw = [0; 4096];
                    let _ = stream.read(&mut raw);
                    let _ = stream.write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                    );
                } else {
                    thread::sleep(Duration::from_millis(10));
                }
            }
        });
        let valid = ProxyCore::start(&Context::default(), &any, &options).unwrap();
        let url = format!("http://127.0.0.1:{port}/");
        assert_eq!(
            safe_request(Some(&valid.endpoint), &url, &options, 0, 0)["ok"],
            true
        );
        any = random_wrong_short_id(&any).unwrap();
        let wrong = ProxyCore::start(&Context::default(), &any, &options).unwrap();
        let rejected = safe_request(Some(&wrong.endpoint), &url, &options, 0, 0)["ok"] == false;
        finish.store(true, Ordering::Relaxed);
        origin.join().unwrap();
        assert!(rejected);
    }
    #[test]
    fn bounded_upload_reports_sent_bytes() {
        if Command::new("curl")
            .arg("--version")
            .stdout(Stdio::null())
            .status()
            .is_err()
        {
            return;
        }
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let worker = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            let mut request = Vec::new();
            let mut byte = [0; 1];
            while !request.ends_with(b"\r\n\r\n") {
                stream.read_exact(&mut byte).unwrap();
                request.push(byte[0]);
                assert!(request.len() < 8192);
            }
            let header = String::from_utf8(request).unwrap();
            assert!(header.starts_with("POST /upload HTTP/1.1\r\n"));
            let length = header
                .lines()
                .find_map(|line| {
                    line.split_once(':')
                        .filter(|(name, _)| name.eq_ignore_ascii_case("content-length"))
                        .map(|(_, value)| value.trim().parse::<usize>().unwrap())
                })
                .unwrap();
            assert_eq!(length, 4096);
            let mut payload = vec![0; length];
            stream.read_exact(&mut payload).unwrap();
            stream
                .write_all(
                    b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .unwrap();
        });
        let result = request(
            None,
            &format!("http://127.0.0.1:{port}/upload"),
            &Options {
                timeout: 3,
                ..Default::default()
            },
            0,
            4096,
            None,
        )
        .unwrap();
        assert_eq!(result["ok"], true);
        assert_eq!(result["sent_bytes"], 4096);
        worker.join().unwrap();
    }
}
