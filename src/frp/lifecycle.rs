use super::*;
use crate::{cert, network, platform};
use flate2::read::GzDecoder;
use std::{
    fs::{File, OpenOptions},
    io::Read,
    net::IpAddr,
    os::{
        fd::AsRawFd,
        unix::fs::{OpenOptionsExt, PermissionsExt},
    },
    thread,
    time::Duration,
};

static INTERRUPTED: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(0);
extern "C" fn interrupt(signal: libc::c_int) {
    INTERRUPTED.store(signal, std::sync::atomic::Ordering::Relaxed);
}
struct Signals {
    int: libc::sighandler_t,
    term: libc::sighandler_t,
    hup: libc::sighandler_t,
}
impl Signals {
    fn install() -> Result<Self> {
        INTERRUPTED.store(0, std::sync::atomic::Ordering::Relaxed);
        let int =
            unsafe { libc::signal(libc::SIGINT, interrupt as *const () as libc::sighandler_t) };
        if int == libc::SIG_ERR {
            return Err(std::io::Error::last_os_error().into());
        }
        let term =
            unsafe { libc::signal(libc::SIGTERM, interrupt as *const () as libc::sighandler_t) };
        if term == libc::SIG_ERR {
            unsafe {
                libc::signal(libc::SIGINT, int);
            }
            return Err(std::io::Error::last_os_error().into());
        }
        let hup =
            unsafe { libc::signal(libc::SIGHUP, interrupt as *const () as libc::sighandler_t) };
        if hup == libc::SIG_ERR {
            unsafe {
                libc::signal(libc::SIGINT, int);
                libc::signal(libc::SIGTERM, term);
            }
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(Self { int, term, hup })
    }
}
impl Drop for Signals {
    fn drop(&mut self) {
        unsafe {
            libc::signal(libc::SIGINT, self.int);
            libc::signal(libc::SIGTERM, self.term);
            libc::signal(libc::SIGHUP, self.hup);
        }
    }
}
fn cancelled() -> Result<()> {
    if INTERRUPTED.load(std::sync::atomic::Ordering::Relaxed) != 0 {
        Err("FRP 操作已取消".into())
    } else {
        Ok(())
    }
}

pub(super) fn private_dir(path: &Path) -> Result<()> {
    fs::create_dir_all(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

fn path_safe(path: &Path) -> Result<()> {
    util::safe_path(path)?;
    let s = util::path_str(path)?;
    if !s
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b"/_-.".contains(&b))
        || [
            "/",
            "/etc",
            "/opt",
            "/var",
            "/var/lib",
            "/var/log",
            "/run",
            "/usr",
            "/usr/local",
        ]
        .contains(&s)
    {
        return Err(format!("FRP 路径必须为专用绝对目录且不能含空格: {s}").into());
    }
    Ok(())
}

fn check_paths(ctx: &Context) -> Result<()> {
    let roots = [
        &ctx.paths.frp_root,
        &ctx.paths.frp_bin,
        &ctx.paths.frp_web,
        &ctx.paths.frp_log,
        &ctx.paths.frp_run,
    ];
    for (a, path) in roots.iter().enumerate() {
        path_safe(path)?;
        for (b, other) in roots.iter().enumerate() {
            if a != b && (path.starts_with(other) || other.starts_with(path)) {
                return Err("FRP 数据目录不能相同或互相包含".into());
            }
        }
        for other in [
            &ctx.paths.root,
            &ctx.paths.bin,
            &ctx.paths.log,
            &ctx.paths.run,
            &ctx.paths.site_root,
            &ctx.paths.systemd,
            &ctx.paths.initd,
        ] {
            if path.starts_with(other) || other.starts_with(path) {
                return Err("FRP 路径不能与代理、网站或服务目录重叠".into());
            }
        }
    }
    path_safe(&ctx.paths.executable)?;
    Ok(())
}

struct Lock(File);
impl Lock {
    fn acquire(ctx: &Context) -> Result<Self> {
        check_paths(ctx)?;
        let parent = ctx.paths.frp_root.parent().ok_or("FRP 目录没有父目录")?;
        fs::create_dir_all(parent)?;
        let path = parent.join(".onebox-frp.lock");
        util::safe_path(&path)?;
        let f = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)?;
        // The descriptor remains held for the entire transaction.
        if unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err("另一个 FRP 管理操作正在进行".into());
        }
        Ok(Self(f))
    }
}
impl Drop for Lock {
    fn drop(&mut self) {
        unsafe {
            libc::flock(self.0.as_raw_fd(), libc::LOCK_UN);
        }
    }
}

fn copy_tree(source: &Path, dest: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(source)?;
    if metadata.file_type().is_symlink() {
        return Err(format!("FRP 备份拒绝符号链接: {}", source.display()).into());
    }
    if metadata.is_dir() {
        fs::create_dir_all(dest)?;
        fs::set_permissions(dest, metadata.permissions())?;
        for e in fs::read_dir(source)? {
            let e = e?;
            copy_tree(&e.path(), &dest.join(e.file_name()))?;
        }
    } else if metadata.is_file() {
        if let Some(p) = dest.parent() {
            fs::create_dir_all(p)?;
        }
        fs::copy(source, dest)?;
        fs::set_permissions(dest, metadata.permissions())?;
    } else {
        return Err("FRP 数据中有不支持备份的特殊文件".into());
    }
    Ok(())
}

fn unit_paths(ctx: &Context) -> Vec<PathBuf> {
    [SERVER, WEB]
        .iter()
        .flat_map(|name| {
            [
                ctx.paths.systemd.join(format!("{name}.service")),
                ctx.paths.initd.join(name),
            ]
        })
        .collect()
}

struct Snapshot {
    path: PathBuf,
    active: [bool; 2],
    enabled: [bool; 2],
    had_cron: bool,
}
impl Snapshot {
    fn create(ctx: &Context) -> Result<Self> {
        for p in [&ctx.paths.frp_root, &ctx.paths.frp_bin, &ctx.paths.frp_web] {
            if p.exists() && !p.join(".managed").is_file() {
                return Err(format!("拒绝接管非本程序管理的目录: {}", p.display()).into());
            }
        }
        for p in unit_paths(ctx) {
            if p.exists() {
                util::safe_path(&p)?;
                let s = fs::read_to_string(&p)?;
                if !s.contains("Managed by Onebox")
                    && !s.contains("Managed by onebox")
                    && !s.contains("managed by onebox")
                    && !ctx.paths.frp_root.join("services").is_dir()
                {
                    return Err(format!("拒绝接管现有服务: {}", p.display()).into());
                }
            }
        }
        let path = ctx
            .paths
            .frp_root
            .parent()
            .ok_or("FRP 路径无父目录")?
            .join(format!(".onebox-frp-backup-{}", util::random_hex(8)?));
        private_dir(&path)?;
        let active = [
            platform::running(ctx, SERVER) || legacy_running(ctx, SERVER),
            platform::running(ctx, WEB) || legacy_running(ctx, WEB),
        ];
        let enabled = [service_enabled(ctx, SERVER), service_enabled(ctx, WEB)];
        let result = (|| -> Result<bool> {
            for (i, p) in [&ctx.paths.frp_root, &ctx.paths.frp_bin, &ctx.paths.frp_web]
                .iter()
                .enumerate()
            {
                if p.exists() {
                    copy_tree(p, &path.join(format!("dir-{i}")))?;
                }
            }
            for (i, p) in unit_paths(ctx).iter().enumerate() {
                if p.exists() {
                    copy_tree(p, &path.join(format!("unit-{i}")))?;
                }
            }
            let cron = read_cron(ctx)?;
            if let Some(ref cron) = cron {
                util::atomic_write(&path.join("crontab"), cron.as_bytes(), 0o600)?;
            }
            Ok(cron.is_some())
        })();
        match result {
            Ok(had_cron) => Ok(Self {
                path,
                active,
                enabled,
                had_cron,
            }),
            Err(e) => {
                let _ = fs::remove_dir_all(&path);
                Err(e)
            }
        }
    }
    fn rollback(&self, ctx: &Context) -> Result<()> {
        stop(ctx, WEB)?;
        stop(ctx, SERVER)?;
        network::clear_owner(ctx, "frp")?;
        legacy_firewall::clear(ctx)?;
        for name in [WEB, SERVER] {
            let _ = platform::service(ctx, name, "disable");
        }
        for (i, p) in [&ctx.paths.frp_root, &ctx.paths.frp_bin, &ctx.paths.frp_web]
            .iter()
            .enumerate()
        {
            if p.exists() {
                fs::remove_dir_all(p)?;
            }
            let backup = self.path.join(format!("dir-{i}"));
            if backup.exists() {
                copy_tree(&backup, p)?;
            }
        }
        for (i, p) in unit_paths(ctx).iter().enumerate() {
            if p.exists() {
                fs::remove_file(p)?;
            }
            let backup = self.path.join(format!("unit-{i}"));
            if backup.exists() {
                copy_tree(&backup, p)?;
            }
        }
        daemon_reload(ctx)?;
        if self.had_cron {
            let previous = fs::read_to_string(self.path.join("crontab"))?;
            let current = read_cron(ctx)?.ok_or("恢复 FRP 定时任务时找不到 crontab")?;
            let mut lines = current
                .lines()
                .filter(|line| !owned_cron(line))
                .map(str::to_string)
                .collect::<Vec<_>>();
            lines.extend(
                previous
                    .lines()
                    .filter(|line| owned_cron(line))
                    .map(str::to_string),
            );
            let restore = self.path.join("crontab-restore");
            util::atomic_write(&restore, (lines.join("\n") + "\n").as_bytes(), 0o600)?;
            ctx.run("crontab", &[util::path_str(&restore)?])?;
        }
        if installed(ctx) {
            let cfg = load(ctx)?;
            legacy_firewall::clear(ctx)?;
            let ledger = ctx.paths.frp_root.join("firewall-v2.json");
            if ledger.exists() {
                fs::remove_file(ledger)?;
            }
            network::apply_ports(ctx, "frp", &cfg.firewall_ports())?;
            write_services(ctx, &cfg)?;
            for (i, name) in [SERVER, WEB].iter().enumerate() {
                if self.enabled[i] {
                    platform::service(ctx, name, "enable")?;
                }
                if self.active[i] {
                    platform::service(ctx, name, "start")?;
                }
            }
        }
        Ok(())
    }
    fn finish(self, ctx: &Context, result: Result<()>) -> Result<()> {
        match result {
            Ok(()) => {
                fs::remove_dir_all(&self.path)?;
                Ok(())
            }
            Err(error) => match self.rollback(ctx) {
                Ok(()) => {
                    fs::remove_dir_all(&self.path)?;
                    Err(format!("{error}；已恢复旧 FRP 配置与服务状态").into())
                }
                Err(recovery) => Err(format!(
                    "{error}；恢复未完成: {recovery}。备份保留于 {}",
                    self.path.display()
                )
                .into()),
            },
        }
    }
}

fn daemon_reload(ctx: &Context) -> Result<()> {
    if platform::init_system() == "systemd" {
        ctx.run("systemctl", &["daemon-reload"])?;
    }
    Ok(())
}
fn service_enabled(ctx: &Context, name: &str) -> bool {
    if let Ok(o) = ctx.output("systemctl", &["is-enabled", "--quiet", name]) {
        if o.success() {
            return true;
        }
    }
    ctx.output("rc-update", &["show", "default"])
        .is_ok_and(|o| {
            o.success()
                && o.stdout
                    .lines()
                    .any(|l| l.split_whitespace().next() == Some(name))
        })
}
fn legacy_running(ctx: &Context, name: &str) -> bool {
    let pidfile = if name == SERVER {
        ctx.paths.frp_run.join("frps.pid")
    } else {
        ctx.paths.frp_root.join("nginx.pid")
    };
    let Some(pid) = fs::read_to_string(pidfile)
        .ok()
        .and_then(|s| s.trim().parse::<u32>().ok())
        .filter(|p| *p > 1)
    else {
        return false;
    };
    let Ok(data) = fs::read(format!("/proc/{pid}/cmdline")) else {
        return false;
    };
    let text = String::from_utf8_lossy(&data).replace('\0', " ");
    let expected = if name == SERVER {
        ctx.paths.frp_bin.join("frps")
    } else {
        ctx.paths.frp_root.join("nginx.conf")
    };
    text.contains(expected.to_string_lossy().as_ref())
}

pub(super) fn running(ctx: &Context, name: &str) -> bool {
    platform::running(ctx, name) || legacy_running(ctx, name)
}
fn stop(ctx: &Context, name: &str) -> Result<()> {
    let known = ctx
        .paths
        .frp_root
        .join("services")
        .join(format!("{name}.json"))
        .exists()
        || ctx.paths.systemd.join(format!("{name}.service")).exists()
        || ctx.paths.initd.join(name).exists();
    if known {
        platform::service(ctx, name, "stop")?;
    }
    // Native migration of the previous script's init-less PID layout.
    let pidfile = if name == SERVER {
        ctx.paths.frp_run.join("frps.pid")
    } else {
        ctx.paths.frp_root.join("nginx.pid")
    };
    if pidfile.is_file() {
        let text = fs::read_to_string(&pidfile)?;
        if let Ok(pid) = text.trim().parse::<i32>() {
            if pid > 1 {
                if let Ok(cmd) = fs::read(format!("/proc/{pid}/cmdline")) {
                    let cmd = String::from_utf8_lossy(&cmd).replace('\0', " ");
                    let expected = if name == SERVER {
                        ctx.paths.frp_bin.join("frps")
                    } else {
                        ctx.paths.frp_root.join("nginx.conf")
                    };
                    if !cmd.contains(util::path_str(&expected)?) {
                        return Err("旧 FRP PID 已被其他进程复用，拒绝终止".into());
                    }
                    ctx.run("kill", &["-TERM", &pid.to_string()])?;
                    for _ in 0..30 {
                        if !Path::new(&format!("/proc/{pid}")).exists() {
                            break;
                        }
                        thread::sleep(Duration::from_millis(100));
                    }
                    if Path::new(&format!("/proc/{pid}")).exists() {
                        return Err("旧 FRP 进程尚未退出，停止迁移".into());
                    }
                }
            }
        }
        fs::remove_file(pidfile)?;
    }
    Ok(())
}

fn mkdirs(ctx: &Context) -> Result<()> {
    for p in [&ctx.paths.frp_root, &ctx.paths.frp_bin, &ctx.paths.frp_web] {
        private_dir(p)?;
        util::atomic_write(&p.join(".managed"), b"Managed by Onebox FRP\n", 0o600)?;
    }
    for p in [&ctx.paths.frp_log, &ctx.paths.frp_run] {
        private_dir(p)?;
    }
    Ok(())
}

fn check_ports(ctx: &Context, cfg: &Config) -> Result<()> {
    let mut reservations = Vec::new();
    if crate::state::installed(ctx) {
        let s = crate::state::load(ctx)?;
        for p in s.protocols() {
            reservations.push((s.port(p), s.port(p), p.network().to_string()));
        }
        if s.site_enabled() {
            reservations.push((
                s.number("REALITY_SITE_PORT", 8444),
                s.number("REALITY_SITE_PORT", 8444),
                "tcp".into(),
            ));
            reservations.push((80, 80, "tcp".into()));
            if s.flag("REALITY_SITE_HTTPS") {
                reservations.push((443, 443, "tcp".into()));
            }
        }
        if let Some((a, b)) = s.get("HY2_HOP").split_once('-') {
            reservations.push((a.parse()?, b.parse()?, "udp".into()));
        }
    }
    let sockets = ctx.run("ss", &["-H", "-lntu"])?;
    for (lo, hi, proto) in cfg.reservations() {
        for (a, b, p) in &reservations {
            if lo <= *b && *a <= hi && (proto == "both" || p == "both" || proto == *p) {
                return Err(
                    format!("FRP {lo}-{hi}/{proto} 与已有代理或网站 {a}-{b}/{p} 冲突").into(),
                );
            }
        }
        for line in sockets.lines() {
            let fields: Vec<_> = line.split_whitespace().collect();
            if fields.len() < 5 {
                continue;
            }
            let transport = fields[0];
            if proto != "both" && !transport.starts_with(&proto) {
                continue;
            }
            if let Some(port) = fields[4]
                .rsplit(':')
                .next()
                .and_then(|v| v.parse::<u16>().ok())
            {
                if (lo..=hi).contains(&port) {
                    return Err(format!("FRP 端口 {port}/{transport} 已被其他进程占用").into());
                }
            }
        }
    }
    Ok(())
}

fn dns(ctx: &Context, cfg: &Config) -> Result<()> {
    let mut names = vec![cfg.domain.clone()];
    if cfg.mode == "web" {
        names.push(if cfg.subdomain_host.is_empty() {
            cfg.web_domain.clone()
        } else {
            format!("onebox-{}.{}", util::random_hex(4)?, cfg.subdomain_host)
        });
    }
    let mut own = BTreeSet::new();
    if let Ok(text) = ctx.run("ip", &["-j", "address", "show"]) {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&text) {
            if let Some(ifaces) = v.as_array() {
                for iface in ifaces {
                    if let Some(a) = iface["addr_info"].as_array() {
                        for a in a {
                            if let Some(ip) =
                                a["local"].as_str().and_then(|s| s.parse::<IpAddr>().ok())
                            {
                                own.insert(ip);
                            }
                        }
                    }
                }
            }
        }
    }
    let mut discovered = false;
    for name in names {
        let mut ips = BTreeSet::new();
        // Query both families explicitly; ahosts alone can hide stale AAAA
        // records when the local resolver applies AI_ADDRCONFIG.
        for database in ["ahosts", "ahostsv6", "hosts"] {
            if let Ok(result) = ctx.output("getent", &[database, &name]) {
                if result.success() {
                    for ip in result
                        .stdout
                        .lines()
                        .filter_map(|line| line.split_whitespace().next()?.parse::<IpAddr>().ok())
                    {
                        ips.insert(match ip {
                            IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
                            _ => ip,
                        });
                    }
                }
            }
        }
        if ips.is_empty() {
            return Err(format!("无法解析 {name}，请先添加 DNS 记录").into());
        }
        if !discovered && ips.iter().any(|ip| !own.contains(ip)) {
            for url in ["https://api.ipify.org", "https://api6.ipify.org"] {
                if let Ok(s) = ctx.run(
                    "curl",
                    &["-fsS", "--connect-timeout", "3", "--max-time", "5", url],
                ) {
                    if let Ok(ip) = s.trim().parse::<IpAddr>() {
                        own.insert(ip);
                    }
                }
            }
            discovered = true;
        }
        for ip in ips {
            if !own.contains(&ip) {
                return Err(format!(
                    "FRP 域名 {name} 的 {ip} 不属于本机；检查全部 A/AAAA 并关闭 CDN 代理"
                )
                .into());
            }
        }
    }
    Ok(())
}

fn download(ctx: &Context, cfg: &mut Config, output: &Path) -> Result<()> {
    let arch = match std::env::consts::ARCH {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        "arm" => "arm",
        "x86" => "386",
        "riscv64" => "riscv64",
        "loongarch64" => "loong64",
        _ => return Err("FRP 不支持当前 CPU 架构".into()),
    };
    let url = if cfg.version == "latest" {
        "https://api.github.com/repos/fatedier/frp/releases/latest".into()
    } else {
        format!(
            "https://api.github.com/repos/fatedier/frp/releases/tags/v{}",
            cfg.version
        )
    };
    let text = ctx.run(
        "curl",
        &["-fsSL", "--connect-timeout", "10", "--max-time", "60", &url],
    )?;
    let release: serde_json::Value = serde_json::from_str(&text)?;
    if release["draft"] != false || release["prerelease"] != false {
        return Err("拒绝非稳定 FRP Release".into());
    }
    let tag = release["tag_name"]
        .as_str()
        .ok_or("FRP Release 缺少版本")?
        .strip_prefix('v')
        .ok_or("FRP Release 标签无效")?;
    version(tag)?;
    if cfg.version != "latest" && cfg.version != tag {
        return Err("FRP Release 标签与请求不符".into());
    }
    let asset_name = format!("frp_{tag}_linux_{arch}.tar.gz");
    let expected = format!("https://github.com/fatedier/frp/releases/download/v{tag}/{asset_name}");
    let assets: Vec<_> = release["assets"]
        .as_array()
        .ok_or("FRP Release 缺少资源")?
        .iter()
        .filter(|a| a["name"] == asset_name && a["browser_download_url"] == expected)
        .collect();
    if assets.len() != 1 {
        return Err("FRP 安装包缺失或重复".into());
    }
    let asset = assets[0];
    let digest = asset["digest"]
        .as_str()
        .and_then(|s| s.strip_prefix("sha256:"))
        .filter(|s| s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit()))
        .ok_or("FRP 安装包缺少 SHA-256 摘要")?;
    let size = asset["size"]
        .as_u64()
        .filter(|n| *n > 0 && *n < 268435456)
        .ok_or("FRP 包大小无效")?;
    let tarpath = output.with_extension("tar.gz");
    let download_url = match std::env::var("GH_PROXY") {
        Ok(p) if !p.is_empty() => {
            format!("{}{expected}", p.trim_end_matches('/').to_string() + "/")
        }
        _ => expected,
    };
    ctx.run(
        "curl",
        &[
            "-fsSL",
            "--connect-timeout",
            "10",
            "--max-time",
            "300",
            "--output",
            util::path_str(&tarpath)?,
            &download_url,
        ],
    )?;
    if fs::metadata(&tarpath)?.len() != size {
        return Err("FRP 安装包大小校验失败".into());
    }
    let bytes = fs::read(&tarpath)?;
    if util::sha256(&bytes) != digest.to_ascii_lowercase() {
        return Err("FRP 安装包 SHA-256 校验失败".into());
    }
    let mut archive = tar::Archive::new(GzDecoder::new(bytes.as_slice()));
    let member = format!("frp_{tag}_linux_{arch}/frps");
    let mut found = false;
    for entry in archive.entries()? {
        let mut entry = entry?;
        if entry.path()?.as_ref() == Path::new(&member) {
            if found || !entry.header().entry_type().is_file() || entry.size() > 268435456 {
                return Err("FRP 压缩包二进制条目无效".into());
            }
            let mut data = Vec::new();
            entry.read_to_end(&mut data)?;
            util::atomic_write(output, &data, 0o755)?;
            found = true;
        }
    }
    if !found {
        return Err("FRP 包缺少 frps 二进制".into());
    }
    if ctx.run(util::path_str(output)?, &["-v"])?.trim() != tag {
        return Err("frps 二进制版本校验失败".into());
    }
    cfg.version = tag.into();
    fs::remove_file(tarpath)?;
    Ok(())
}

fn success(ctx: &Context, args: &[&str]) -> bool {
    ctx.output("openssl", args).is_ok_and(|o| o.success())
}
fn key_matches(ctx: &Context, cert: &Path, key: &Path) -> bool {
    let (Ok(cert), Ok(key)) = (util::path_str(cert), util::path_str(key)) else {
        return false;
    };
    match (
        ctx.run("openssl", &["x509", "-in", cert, "-pubkey", "-noout"]),
        ctx.run(
            "openssl",
            &["pkey", "-in", key, "-passin", "pass:", "-pubout"],
        ),
    ) {
        (Ok(a), Ok(b)) => !a.trim().is_empty() && a.trim() == b.trim(),
        _ => false,
    }
}

pub(super) fn control_cert(ctx: &Context, cfg: &Config) -> Result<bool> {
    let root = &ctx.paths.frp_root;
    let ca = root.join("ca.pem");
    let cakey = root.join("ca-key.pem");
    let cert = root.join("server-cert.pem");
    let key = root.join("server-key.pem");
    if ca.exists() != cakey.exists() {
        return Err("FRP 私有 CA 文件不完整，保留旧部署等待修复".into());
    }
    if !ca.exists() {
        let conf = root.join("ca.cnf");
        util::atomic_write(&conf,b"[req]\ndistinguished_name=dn\nx509_extensions=ca\nprompt=no\n[dn]\nCN=Onebox FRP private CA\n[ca]\nbasicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\n",0o600)?;
        ctx.run(
            "openssl",
            &[
                "ecparam",
                "-genkey",
                "-name",
                "prime256v1",
                "-out",
                util::path_str(&cakey)?,
            ],
        )?;
        ctx.run(
            "openssl",
            &[
                "req",
                "-new",
                "-x509",
                "-sha256",
                "-days",
                "3650",
                "-key",
                util::path_str(&cakey)?,
                "-config",
                util::path_str(&conf)?,
                "-out",
                util::path_str(&ca)?,
            ],
        )?;
    }
    if !success(
        ctx,
        &[
            "x509",
            "-in",
            util::path_str(&ca)?,
            "-checkend",
            "2592000",
            "-noout",
        ],
    ) || !key_matches(ctx, &ca, &cakey)
    {
        return Err("FRP CA 无效或即将过期；需人工轮换并更新所有客户端".into());
    }
    if success(
        ctx,
        &[
            "x509",
            "-in",
            util::path_str(&cert)?,
            "-checkend",
            "2592000",
            "-noout",
        ],
    ) && success(
        ctx,
        &[
            "verify",
            "-CAfile",
            util::path_str(&ca)?,
            "-verify_hostname",
            &cfg.domain,
            util::path_str(&cert)?,
        ],
    ) && key_matches(ctx, &cert, &key)
    {
        return Ok(false);
    }
    let conf = root.join("server.cnf");
    let csr = root.join("server.csr");
    util::atomic_write(&conf,format!("[req]\ndistinguished_name=dn\nprompt=no\n[dn]\nCN={}\n[server]\nsubjectAltName=DNS:{}\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\n",cfg.domain,cfg.domain).as_bytes(),0o600)?;
    ctx.run(
        "openssl",
        &[
            "ecparam",
            "-genkey",
            "-name",
            "prime256v1",
            "-out",
            util::path_str(&key)?,
        ],
    )?;
    ctx.run(
        "openssl",
        &[
            "req",
            "-new",
            "-sha256",
            "-key",
            util::path_str(&key)?,
            "-config",
            util::path_str(&conf)?,
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
            util::path_str(&cakey)?,
            "-CAcreateserial",
            "-days",
            "397",
            "-sha256",
            "-extfile",
            util::path_str(&conf)?,
            "-extensions",
            "server",
            "-out",
            util::path_str(&cert)?,
        ],
    )?;
    ctx.run(
        "openssl",
        &[
            "verify",
            "-CAfile",
            util::path_str(&ca)?,
            "-verify_hostname",
            &cfg.domain,
            util::path_str(&cert)?,
        ],
    )?;
    for p in [&ca, &cakey, &cert, &key] {
        fs::set_permissions(p, fs::Permissions::from_mode(0o600))?;
    }
    Ok(true)
}

fn nginx(ctx: &Context) -> Result<String> {
    if let Ok(bin) = std::env::var("ONEBOX_NGINX_BIN") {
        path_safe(Path::new(&bin))?;
        return Ok(bin);
    }
    let s = ctx.run("which", &["nginx"])?;
    let path = s.trim();
    path_safe(Path::new(path))?;
    Ok(path.into())
}
fn web_config(ctx: &Context, cfg: &Config, bootstrap: bool) -> Result<()> {
    let mut user = None;
    for candidate in ["nginx", "www-data", "nobody"] {
        if let Ok(group) = ctx.run("id", &["-gn", candidate]) {
            let group = group.trim();
            if !group.is_empty()
                && group
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
            {
                user = Some(format!("{candidate} {group}"));
                break;
            }
        }
    }
    let user = user.ok_or("Nginx 需要非 root 工作进程账号")?;
    let root = util::path_str(&ctx.paths.frp_root)?;
    let www = ctx.paths.frp_web.join("www");
    for p in [
        &ctx.paths.frp_web,
        &www,
        &www.join(".well-known"),
        &www.join(".well-known/acme-challenge"),
        &ctx.paths.frp_web.join("tmp"),
    ] {
        fs::create_dir_all(p)?;
        fs::set_permissions(p, fs::Permissions::from_mode(0o755))?;
    }
    let mut s=format!("# Managed by Onebox FRP\nuser {user};\nworker_processes 1;\npid \"{root}/nginx.pid\";\nerror_log \"{root}/nginx-error.log\" warn;\nevents {{ worker_connections 1024; }}\nhttp {{\n access_log off; server_tokens off; default_type text/plain;\n map $http_upgrade $onebox_frp_connection {{ default upgrade; '' close; }}\n");
    for kind in ["client_body", "proxy", "fastcgi", "uwsgi", "scgi"] {
        s.push_str(&format!(
            " {kind}_temp_path \"{}/tmp/{kind}\";\n",
            ctx.paths.frp_web.display()
        ));
    }
    let names = if cfg.subdomain_host.is_empty() {
        cfg.web_domain.clone()
    } else {
        format!("*.{}", cfg.subdomain_host)
    };
    let ipv6 = cfg.bind_addr == "::"
        || fs::read_to_string("/proc/net/if_inet6").is_ok_and(|s| !s.trim().is_empty());
    let listen = |port: u16, suffix: &str| {
        format!(
            "listen {port}{suffix}; {}",
            if ipv6 {
                format!("listen [::]:{port}{suffix};")
            } else {
                String::new()
            }
        )
    };
    if cfg.redirect_port > 0 {
        let suffix = if cfg.https_port == 443 {
            String::new()
        } else {
            format!(":{}", cfg.https_port)
        };
        s.push_str(&format!(" server {{ {} server_name {names};\n location ^~ /.well-known/acme-challenge/ {{ root \"{}\"; try_files $uri =404; }}\n location / {{ {} }}\n }}\n server {{ {} server_name _; return 404; }}\n",listen(cfg.redirect_port,""),www.display(),if bootstrap{"return 404;".into()}else{format!("return 301 https://$host{suffix}$request_uri;")},listen(cfg.redirect_port," default_server")));
    }
    if !bootstrap {
        let cert = ctx.paths.frp_root.join("web-tls/cert.pem");
        let key = ctx.paths.frp_root.join("web-tls/key.pem");
        let tls = format!(
            "ssl_certificate \"{}\"; ssl_certificate_key \"{}\"; ssl_protocols TLSv1.2 TLSv1.3;",
            cert.display(),
            key.display()
        );
        s.push_str(&format!(" server {{ {} server_name {names}; {tls}\n ssl_session_cache shared:onebox_frp:1m; ssl_session_timeout 10m; client_max_body_size 0;\n location / {{ proxy_pass http://127.0.0.1:{}; proxy_http_version 1.1;\n proxy_set_header Host $host; proxy_set_header Upgrade $http_upgrade; proxy_set_header Connection $onebox_frp_connection;\n proxy_set_header X-Real-IP $remote_addr; proxy_set_header X-Forwarded-For $remote_addr;\n proxy_set_header X-Forwarded-Proto https; proxy_set_header X-Forwarded-Host $host; proxy_set_header X-Forwarded-Port {}; proxy_set_header Forwarded \"\";\n proxy_buffering off; proxy_request_buffering off; proxy_read_timeout 3600s; proxy_send_timeout 3600s;\n }} }}\n server {{ {} server_name _; {tls} return 404; }}\n",listen(cfg.https_port," ssl"),cfg.http_port,cfg.https_port,listen(cfg.https_port," ssl default_server")));
    }
    s.push_str("}\n");
    util::atomic_write(&ctx.paths.frp_root.join("nginx.conf"), s.as_bytes(), 0o600)?;
    ctx.run(
        &nginx(ctx)?,
        &[
            "-t",
            "-p",
            root,
            "-c",
            util::path_str(&ctx.paths.frp_root.join("nginx.conf"))?,
        ],
    )?;
    Ok(())
}

#[cfg(test)]
pub(super) fn test_web_config(ctx: &Context, cfg: &Config) -> Result<()> {
    web_config(ctx, cfg, false)
}

fn write_services(ctx: &Context, cfg: &Config) -> Result<()> {
    platform::write_service(
        ctx,
        SERVER,
        &ctx.paths.frp_bin.join("frps"),
        &[
            "-c".into(),
            util::path_str(&ctx.paths.frp_root.join("frps.toml"))?.into(),
        ],
        &[],
    )?;
    if cfg.mode == "web" {
        platform::write_service(
            ctx,
            WEB,
            Path::new(&nginx(ctx)?),
            &[
                "-p".into(),
                util::path_str(&ctx.paths.frp_root)?.into(),
                "-c".into(),
                util::path_str(&ctx.paths.frp_root.join("nginx.conf"))?.into(),
                "-g".into(),
                "daemon off;".into(),
            ],
            &[],
        )?;
    }
    Ok(())
}

fn read_cron(ctx: &Context) -> Result<Option<String>> {
    match ctx.output("crontab", &["-l"]) {
        Ok(o) if o.success() => Ok(Some(o.stdout)),
        Ok(o)
            if o.code == 1
                && (o.stderr.to_ascii_lowercase().contains("no crontab")
                    || o.stderr
                        .to_ascii_lowercase()
                        .contains("no such file or directory")
                    || o.stderr.is_empty()) =>
        {
            Ok(Some(String::new()))
        }
        Err(e) if e.to_string().contains("No such file") => Ok(None),
        Ok(o) => Err(format!("读取 crontab 失败: {}", o.stderr).into()),
        Err(e) => Err(e),
    }
}
fn owned_cron(line: &str) -> bool {
    [
        "# onebox-frps-renew",
        "# onebox-frps-boot",
        "# onebox-rust:onebox-frps",
        "# onebox-rust:onebox-frp-web",
    ]
    .iter()
    .any(|suffix| line.trim_end().ends_with(suffix))
}
fn cron(ctx: &Context, add: bool) -> Result<()> {
    let Some(existing) = read_cron(ctx)? else {
        if add {
            return Err("缺少 crontab，无法安排证书续期".into());
        }
        return Ok(());
    };
    let mut text = existing
        .lines()
        .filter(|l| !l.ends_with(" # onebox-frps-renew") && !l.ends_with(" # onebox-frps-boot"))
        .collect::<Vec<_>>()
        .join("\n");
    if !text.is_empty() {
        text.push('\n');
    }
    if add {
        let quote = |value: &str| format!("'{}'", value.replace('\'', "'\\''"));
        let command = format!(
            "{} {}",
            platform::service_shell_prefix(ctx)?,
            quote(util::path_str(&ctx.paths.executable)?)
        );
        let renew = quote(util::path_str(&ctx.paths.frp_log.join("renew.log"))?);
        let boot = quote(util::path_str(&ctx.paths.frp_log.join("boot.log"))?);
        text.push_str(&format!("17 3 * * * {command} frps renew --cron >>{renew} 2>&1 # onebox-frps-renew\n@reboot {command} frps start >>{boot} 2>&1 # onebox-frps-boot\n").replace('%', "\\%"));
    }
    let path = ctx
        .paths
        .frp_root
        .parent()
        .ok_or("FRP 目录无父目录")?
        .join(format!(".onebox-frp-cron-{}", util::random_hex(8)?));
    util::atomic_write(&path, text.as_bytes(), 0o600)?;
    let result = ctx.run("crontab", &[util::path_str(&path)?]);
    fs::remove_file(path)?;
    result?;
    Ok(())
}

fn scheduler_ready(ctx: &Context) -> Result<()> {
    match platform::init_system() {
        "systemd" => {
            for name in ["cron", "crond"] {
                if ctx
                    .output("systemctl", &["enable", "--now", name])
                    .is_ok_and(|o| o.success())
                {
                    return Ok(());
                }
            }
        }
        "openrc" => {
            for name in ["crond", "cron"] {
                if ctx
                    .output("rc-service", &[name, "start"])
                    .is_ok_and(|o| o.success())
                {
                    ctx.run("rc-update", &["add", name, "default"])?;
                    return Ok(());
                }
            }
        }
        _ => {
            for name in ["cron", "crond"] {
                if ctx
                    .output("pgrep", &["-x", name])
                    .is_ok_and(|o| o.success())
                {
                    return Ok(());
                }
            }
        }
    }
    Err("需要运行中的 cron 服务执行 FRP 证书自动续期，请启动 cron 后重试".into())
}

fn health(ctx: &Context, cfg: &Config, check_web: bool) -> Result<()> {
    let addr = if cfg.bind_addr == "::1" || cfg.bind_addr == "::" {
        "[::1]"
    } else {
        "127.0.0.1"
    };
    for _ in 0..10 {
        let o = ctx.output(
            "timeout",
            &[
                "4",
                "openssl",
                "s_client",
                "-connect",
                &format!("{addr}:{}", cfg.bind_port),
                "-servername",
                &cfg.domain,
                "-verify_hostname",
                &cfg.domain,
                "-CAfile",
                util::path_str(&ctx.paths.frp_root.join("ca.pem"))?,
                "-verify_return_error",
                "-brief",
            ],
        );
        if platform::running(ctx, SERVER)
            && o.is_ok_and(|o| o.success())
            && (!check_web || cfg.mode != "web" || platform::running(ctx, WEB))
        {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(300));
    }
    Err("FRP 启动或私有 CA / TLS 健康检查失败".into())
}

pub(super) fn apply(ctx: &Context, cfg: &mut Config, rotate: bool) -> Result<()> {
    platform::require_root()?;
    cfg.validate(false)?;
    let _lock = Lock::acquire(ctx)?;
    let _signals = Signals::install()?;
    for (command, package) in [
        ("curl", "curl"),
        ("openssl", "openssl"),
        ("ss", "iproute2"),
        ("ip", "iproute2"),
        ("crontab", "cron"),
        ("timeout", "coreutils"),
    ] {
        platform::ensure_package(ctx, command, package)?;
    }
    if cfg.mode == "web" {
        platform::ensure_package(ctx, "nginx", "nginx")?;
    }
    dns(ctx, cfg)?;
    cancelled()?;
    let snap = Snapshot::create(ctx)?;
    let result = (|| -> Result<()> {
        let staged = snap.path.join("new-frps");
        download(ctx, cfg, &staged)?;
        cancelled()?;
        stop(ctx, WEB)?;
        stop(ctx, SERVER)?;
        cancelled()?;
        check_ports(ctx, cfg)?;
        network::clear_owner(ctx, "frp")?;
        legacy_firewall::clear(ctx)?;
        mkdirs(ctx)?;
        if rotate || cfg.token.is_empty() {
            cfg.token = util::random_hex(32)?;
        }
        control_cert(ctx, cfg)?;
        cancelled()?;
        util::atomic_write(&ctx.paths.frp_bin.join("frps"), &fs::read(staged)?, 0o755)?;
        util::atomic_write(
            &ctx.paths.frp_root.join("frps.toml"),
            render(ctx, cfg)?.as_bytes(),
            0o600,
        )?;
        ctx.run(
            util::path_str(&ctx.paths.frp_bin.join("frps"))?,
            &[
                "verify",
                "-c",
                util::path_str(&ctx.paths.frp_root.join("frps.toml"))?,
            ],
        )?;
        save(ctx, cfg)?;
        platform::install_self(ctx)?;
        write_services(ctx, cfg)?;
        network::apply_ports(ctx, "frp", &cfg.firewall_ports())?;
        if cfg.mode == "web" {
            if cfg.tls_method == "http" {
                web_config(ctx, cfg, true)?;
                platform::service(ctx, WEB, "start")?;
            }
            let old_acme = ctx.paths.frp_root.join("acme");
            let new_acme = ctx.paths.frp_root.join("web-tls/acme");
            if old_acme.is_dir() && !new_acme.exists() {
                copy_tree(&old_acme, &new_acme)?;
            }
            let custom = if cfg.tls_method == "custom" {
                Some((Path::new(&cfg.cert_input), Path::new(&cfg.key_input)))
            } else {
                None
            };
            cert::issue_domains(
                ctx,
                &ctx.paths.frp_root.join("web-tls"),
                &cfg.domains(),
                &cfg.tls_method,
                Some(&ctx.paths.frp_web.join("www")),
                custom,
            )?;
            cancelled()?;
            stop(ctx, WEB)?;
            web_config(ctx, cfg, false)?;
            platform::service(ctx, WEB, "start")?;
            platform::service(ctx, WEB, "enable")?;
        } else if ctx
            .paths
            .frp_root
            .join("services")
            .join(format!("{WEB}.json"))
            .exists()
            || ctx.paths.systemd.join(format!("{WEB}.service")).exists()
            || ctx.paths.initd.join(WEB).exists()
        {
            platform::service(ctx, WEB, "remove")?;
        }
        platform::service(ctx, SERVER, "start")?;
        platform::service(ctx, SERVER, "enable")?;
        health(ctx, cfg, true)?;
        cancelled()?;
        cron(ctx, true)?;
        scheduler_ready(ctx)?;
        cancelled()?;
        // Keep the legacy state solely as an untouched recovery artifact; all reads prefer JSON.
        Ok(())
    })();
    snap.finish(ctx, result)?;
    println!(
        "FRP 已部署。请运行 onebox frps client 导出客户端配置；网站 DNS 与云防火墙仍需由您配置。"
    );
    Ok(())
}

pub(super) fn renew(ctx: &Context, cfg: &Config) -> Result<()> {
    platform::require_root()?;
    let _lock = Lock::acquire(ctx)?;
    let _signals = Signals::install()?;
    let snap = Snapshot::create(ctx)?;
    let result = (|| -> Result<()> {
        let control_changed = control_cert(ctx, cfg)?;
        cancelled()?;
        if cfg.mode == "web" && cfg.tls_method != "custom" {
            if cfg.tls_method == "http" && !running(ctx, WEB) {
                println!("FRP 网站已停止，本次跳过需要 HTTP 入口的续期。");
            } else if ctx.paths.frp_root.join("web-tls").is_dir() {
                if cert::renew(ctx, &ctx.paths.frp_root.join("web-tls"))? {
                    web_config(ctx, cfg, false)?;
                    if platform::running(ctx, WEB) {
                        platform::service(ctx, WEB, "restart")?;
                    }
                }
            } else {
                return Err("旧版网站证书需先运行 onebox frps configure 迁移为原生证书管理".into());
            }
        }
        if control_changed && running(ctx, SERVER) {
            stop(ctx, SERVER)?;
            if !platform::service_spec_path(ctx, SERVER).is_file() {
                write_services(ctx, cfg)?;
            }
            platform::service(ctx, SERVER, "start")?;
            health(ctx, cfg, false)?;
        }
        cancelled()?;
        Ok(())
    })();
    snap.finish(ctx, result)?;
    println!("FRP 证书检查完成，私有 CA 保持不变。");
    Ok(())
}

pub(super) fn service(ctx: &Context, cfg: &Config, action: &str) -> Result<()> {
    platform::require_root()?;
    let _lock = Lock::acquire(ctx)?;
    if action != "start" {
        stop(ctx, WEB)?;
        stop(ctx, SERVER)?;
    }
    if action != "stop" {
        if !platform::service_spec_path(ctx, SERVER).is_file() {
            // Adopt the service description only after validating managed state.
            // The old init-less process uses a different PID file and must exit
            // before the native supervisor can create its replacement.
            stop(ctx, WEB)?;
            stop(ctx, SERVER)?;
            write_services(ctx, cfg)?;
        }
        network::apply_ports(ctx, "frp", &cfg.firewall_ports())?;
        if cfg.mode == "web" {
            platform::service(ctx, WEB, "start")?;
        }
        platform::service(ctx, SERVER, "start")?;
        health(ctx, cfg, true)?;
    }
    Ok(())
}

pub(super) fn uninstall(ctx: &Context) -> Result<()> {
    platform::require_root()?;
    let _lock = Lock::acquire(ctx)?;
    let _signals = Signals::install()?;
    let snap = Snapshot::create(ctx)?;
    let result = (|| -> Result<()> {
        stop(ctx, WEB)?;
        stop(ctx, SERVER)?;
        network::clear_owner(ctx, "frp")?;
        legacy_firewall::clear(ctx)?;
        cron(ctx, false)?;
        for name in [WEB, SERVER] {
            if ctx
                .paths
                .frp_root
                .join("services")
                .join(format!("{name}.json"))
                .exists()
                || ctx.paths.systemd.join(format!("{name}.service")).exists()
                || ctx.paths.initd.join(name).exists()
            {
                platform::service(ctx, name, "remove")?;
            }
        }
        for p in [&ctx.paths.frp_root, &ctx.paths.frp_bin, &ctx.paths.frp_web] {
            if p.exists() {
                fs::remove_dir_all(p)?;
            }
        }
        cancelled()?;
        Ok(())
    })();
    snap.finish(ctx, result)?;
    for p in [&ctx.paths.frp_run, &ctx.paths.frp_log] {
        if p.exists() {
            fs::remove_dir_all(p)?;
        }
    }
    println!("FRP 已卸载，代理与自建站保留。");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    struct MockRunner;
    impl crate::context::Runner for MockRunner {
        fn output(&self, program: &str, args: &[String]) -> Result<crate::context::CommandOutput> {
            let mut out = crate::context::CommandOutput::default();
            if (program == "systemctl"
                && args
                    .first()
                    .is_some_and(|s| s == "is-active" || s == "is-enabled"))
                || program == "rc-update"
                || program == "rc-service"
            {
                out.code = 1;
            }
            if program == "ufw" {
                out.stdout = "Status: inactive\n".into();
            }
            if program == "firewall-cmd" {
                out.code = 1;
            }
            if program == "nft" {
                out.stdout = "{\"nftables\":[]}".into();
            }
            if matches!(program, "iptables" | "ip6tables") && args.iter().any(|s| s == "-C") {
                out.code = 1;
            }
            Ok(out)
        }
    }
    struct DnsRunner(bool);
    impl crate::context::Runner for DnsRunner {
        fn output(&self, program: &str, args: &[String]) -> Result<crate::context::CommandOutput> {
            let mut result = crate::context::CommandOutput::default();
            match program {
                "ip" => result.stdout = r#"[{"addr_info":[{"local":"192.0.2.1"}]}]"#.into(),
                "getent" if args[0] == "ahosts" => {
                    result.stdout = "192.0.2.1 STREAM control.example.com\n".into()
                }
                "getent" if self.0 => result.stdout = "2001:db8::99 control.example.com\n".into(),
                "getent" => result.stdout = "::ffff:192.0.2.1 STREAM control.example.com\n".into(),
                _ => result.code = 1,
            }
            Ok(result)
        }
    }
    #[test]
    fn dns_checks_stale_aaaa_and_normalizes_mapped_ipv4() {
        let cfg = Config {
            mode: "tcp".into(),
            domain: "control.example.com".into(),
            ..Config::default()
        };
        let ctx = Context {
            runner: std::sync::Arc::new(DnsRunner(false)),
            ..Context::default()
        };
        assert!(dns(&ctx, &cfg).is_ok());
        let ctx = Context {
            runner: std::sync::Arc::new(DnsRunner(true)),
            ..Context::default()
        };
        assert!(dns(&ctx, &cfg)
            .unwrap_err()
            .to_string()
            .contains("2001:db8::99"));
    }
    #[test]
    fn data_roots_cannot_overlap() {
        let mut ctx = Context {
            paths: crate::context::Paths::isolated(Path::new("/tmp/onebox-frp-path-test")),
            ..Context::default()
        };
        assert!(check_paths(&ctx).is_ok());
        ctx.paths.frp_web = ctx.paths.frp_root.join("www");
        assert!(check_paths(&ctx).is_err());
    }
    #[test]
    fn private_ca_persists_when_control_domain_changes() {
        if !platform::has("openssl") {
            return;
        }
        let root =
            std::env::temp_dir().join(format!("onebox-frp-ca-{}", util::random_hex(8).unwrap()));
        let ctx = Context {
            paths: crate::context::Paths::isolated(&root),
            ..Context::default()
        };
        private_dir(&ctx.paths.frp_root).unwrap();
        let mut cfg = Config {
            domain: "frp.example.com".into(),
            ..Config::default()
        };
        assert!(control_cert(&ctx, &cfg).unwrap());
        let ca = fs::read(ctx.paths.frp_root.join("ca.pem")).unwrap();
        assert!(!control_cert(&ctx, &cfg).unwrap());
        cfg.domain = "control.example.org".into();
        assert!(control_cert(&ctx, &cfg).unwrap());
        assert_eq!(fs::read(ctx.paths.frp_root.join("ca.pem")).unwrap(), ca);
        ctx.run(
            "openssl",
            &[
                "verify",
                "-CAfile",
                util::path_str(&ctx.paths.frp_root.join("ca.pem")).unwrap(),
                "-verify_hostname",
                &cfg.domain,
                util::path_str(&ctx.paths.frp_root.join("server-cert.pem")).unwrap(),
            ],
        )
        .unwrap();
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn backups_reject_symlink_escape() {
        let root =
            std::env::temp_dir().join(format!("onebox-frp-copy-{}", util::random_hex(8).unwrap()));
        private_dir(&root).unwrap();
        fs::create_dir(root.join("source")).unwrap();
        std::os::unix::fs::symlink("/etc", root.join("source/escape")).unwrap();
        assert!(copy_tree(&root.join("source"), &root.join("backup")).is_err());
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn failed_mutation_restores_token_binary_and_private_ca() {
        let root = std::env::temp_dir().join(format!(
            "onebox-frp-rollback-{}",
            util::random_hex(8).unwrap()
        ));
        let ctx = Context {
            paths: crate::context::Paths::isolated(&root),
            runner: std::sync::Arc::new(MockRunner),
            yes: true,
        };
        mkdirs(&ctx).unwrap();
        let cfg = Config {
            mode: "tcp".into(),
            domain: "frp.example.com".into(),
            token: "b".repeat(64),
            ..Config::default()
        };
        save(&ctx, &cfg).unwrap();
        util::atomic_write(&ctx.paths.frp_bin.join("frps"), b"OLD BINARY", 0o755).unwrap();
        util::atomic_write(
            &ctx.paths.frp_root.join("ca-key.pem"),
            b"KEEP PRIVATE CA",
            0o600,
        )
        .unwrap();
        let snapshot = Snapshot::create(&ctx).unwrap();
        let mut changed = cfg.clone();
        changed.token = "c".repeat(64);
        save(&ctx, &changed).unwrap();
        util::atomic_write(&ctx.paths.frp_bin.join("frps"), b"BROKEN BINARY", 0o755).unwrap();
        util::atomic_write(&ctx.paths.frp_root.join("ca-key.pem"), b"BROKEN CA", 0o600).unwrap();
        let error = snapshot
            .finish(&ctx, Err("simulated failed health check".into()))
            .unwrap_err()
            .to_string();
        assert!(error.contains("已恢复旧 FRP"), "{error}");
        assert_eq!(load(&ctx).unwrap(), cfg);
        assert_eq!(
            fs::read(ctx.paths.frp_bin.join("frps")).unwrap(),
            b"OLD BINARY"
        );
        assert_eq!(
            fs::read(ctx.paths.frp_root.join("ca-key.pem")).unwrap(),
            b"KEEP PRIVATE CA"
        );
        fs::remove_dir_all(root).unwrap();
    }
}
