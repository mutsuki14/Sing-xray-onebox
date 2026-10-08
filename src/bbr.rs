//! TCP BBR management. Release metadata and package bytes are independent trust
//! boundaries: only GitHub's exact image/header pair, size and digest are used.
use crate::{context::Context, platform, util, Result};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    env,
    fs::{self, File, OpenOptions},
    io::Read,
    os::{
        fd::AsRawFd,
        unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt},
    },
    path::{Path, PathBuf},
};

const REPO: &str = "byJoey/Actions-bbr-v3";
const CC: &str = "net.ipv4.tcp_congestion_control";
const QDISC: &str = "net.core.default_qdisc";
const AVAILABLE: &str = "net.ipv4.tcp_available_congestion_control";
const USAGE: &str = "用法: onebox bbr [status|enable [fq|fq_codel|fq_pie|cake]|releases [--max]|install [latest|TAG] [--max] [--apply]]";

#[derive(Clone)]
struct Paths {
    system: PathBuf,
    config: PathBuf,
    data: PathBuf,
    temp: PathBuf,
}
impl Default for Paths {
    fn default() -> Self {
        Self {
            system: "/".into(),
            config: env::var_os("ONEBOX_BBR_CONF")
                .map(PathBuf::from)
                .unwrap_or_else(|| "/etc/sysctl.d/99-onebox-bbr.conf".into()),
            data: env::var_os("ONEBOX_BBR_DIR")
                .map(PathBuf::from)
                .unwrap_or_else(|| "/var/lib/onebox-bbr".into()),
            temp: env::temp_dir(),
        }
    }
}
impl Paths {
    fn at(&self, relative: &str) -> PathBuf {
        self.system.join(relative)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Arch {
    tag: &'static str,
    deb: &'static str,
}
impl Arch {
    fn detect(ctx: &Context) -> Result<Self> {
        match ctx.run("uname", &["-m"])?.trim() {
            "x86_64" => Ok(Self {
                tag: "x86_64",
                deb: "amd64",
            }),
            "aarch64" => Ok(Self {
                tag: "arm64",
                deb: "arm64",
            }),
            _ => Err("Actions-bbr-v3 内核仅支持 x86_64 / aarch64".into()),
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
enum Action {
    Status,
    Enable(String),
    Releases {
        max: bool,
    },
    Install {
        desired: String,
        max: bool,
        apply: bool,
    },
}
fn parse(args: &[String]) -> Result<Action> {
    let action = args.first().map(String::as_str).unwrap_or("status");
    let rest = args.get(1..).unwrap_or_default();
    match action {
        "status" | "menu" if rest.is_empty() => Ok(Action::Status),
        "enable" if rest.len() <= 1 => {
            let queue = rest.first().map(String::as_str).unwrap_or("fq");
            valid_queue(queue)?;
            Ok(Action::Enable(queue.into()))
        }
        "releases" if rest.is_empty() || (rest.len() == 1 && rest[0] == "--max") => {
            Ok(Action::Releases {
                max: !rest.is_empty(),
            })
        }
        "install" => {
            let (mut desired, mut max, mut apply) = (None, false, false);
            for item in rest {
                match item.as_str() {
                    "--max" if !max => max = true,
                    "--apply" if !apply => apply = true,
                    value if !value.starts_with('-') && desired.is_none() => {
                        desired = Some(value.to_string())
                    }
                    _ => return Err(format!("重复或无效的 BBR 参数: {item}\n{USAGE}").into()),
                }
            }
            Ok(Action::Install {
                desired: desired.unwrap_or_else(|| "latest".into()),
                max,
                apply,
            })
        }
        _ => Err(USAGE.into()),
    }
}

pub fn command(ctx: &Context, args: &[String]) -> Result<()> {
    if (args.is_empty() || (args.len() == 1 && args[0] == "menu")) && crate::ui::interactive(ctx) {
        return menu(ctx);
    }
    let paths = Paths::default();
    match parse(args)? {
        Action::Status => status(ctx, &paths),
        Action::Enable(queue) => {
            require_root(ctx)?;
            enable(ctx, &paths, &queue)
        }
        Action::Releases { max } => {
            let arch = Arch::detect(ctx)?;
            for tag in release_tags(arch, max, |url| platform::github_json(ctx, url))? {
                println!("{tag}");
            }
            Ok(())
        }
        Action::Install {
            desired,
            max,
            apply,
        } => install(ctx, &paths, &desired, max, apply),
    }
}

fn menu(ctx: &Context) -> Result<()> {
    loop {
        println!("\nTCP BBR 管理\n1) 状态与实际网卡队列\n2) 启用当前内核 BBR，选择默认队列\n3) 查看 BBRv3 标准版 Release\n4) 安装/更新标准版（先预览，确认后执行）\n5) 查看 BBRv3 Max 实验版 Release\n6) 安装/更新 Max 实验版（先预览，确认后执行）\n0) 返回");
        let choice = crate::ui::choose(ctx, "请选择", 0, 0, 6)?;
        let args = match choice {
            0 => return Ok(()),
            1 => vec!["status".into()],
            2 => {
                println!("1) fq（默认）  2) fq_codel  3) fq_pie  4) cake");
                let queue = crate::ui::choose(ctx, "默认队列", 1, 1, 4)?;
                vec![
                    "enable".into(),
                    ["fq", "fq_codel", "fq_pie", "cake"][queue as usize - 1].into(),
                ]
            }
            3 => vec!["releases".into()],
            5 => vec!["releases".into(), "--max".into()],
            4 | 6 => {
                let tag = crate::ui::ask(ctx, "完整 Release 标签或 latest", "latest")?;
                let mut args = vec!["install".into(), tag, "--apply".into()];
                if choice == 6 {
                    args.push("--max".into());
                }
                args
            }
            _ => unreachable!(),
        };
        // Installation prints its verified plan and asks for confirmation;
        // entering its menu item alone never installs a kernel.
        if let Err(error) = command(ctx, &args) {
            if error.downcast_ref::<crate::ui::Cancelled>().is_some() {
                return Err(error);
            }
            eprintln!("{error}");
        }
    }
}

fn require_root(ctx: &Context) -> Result<()> {
    if ctx.run("id", &["-u"])?.trim() != "0" {
        return Err("此操作需要 root 权限".into());
    }
    Ok(())
}
fn valid_queue(queue: &str) -> Result<()> {
    if !matches!(queue, "fq" | "fq_codel" | "fq_pie" | "cake") {
        return Err("队列应为 fq / fq_codel / fq_pie / cake".into());
    }
    Ok(())
}
fn sysctl(ctx: &Context, key: &str) -> Result<String> {
    Ok(ctx.run("sysctl", &["-n", key])?.trim().into())
}
fn optional_output(ctx: &Context, program: &str, args: &[&str]) -> Option<String> {
    ctx.output(program, args)
        .ok()
        .filter(|out| out.success())
        .map(|out| out.stdout.trim().to_string())
        .filter(|out| !out.is_empty())
}

fn status(ctx: &Context, paths: &Paths) -> Result<()> {
    let kernel = optional_output(ctx, "uname", &["-r"]).unwrap_or_else(|| "未知".into());
    println!(
        "运行内核: {kernel}\nTCP / 默认队列: {} / {}\n可用拥塞算法: {}",
        sysctl(ctx, CC).unwrap_or_else(|_| "未知".into()),
        sysctl(ctx, QDISC).unwrap_or_else(|_| "未知".into()),
        sysctl(ctx, AVAILABLE).unwrap_or_else(|_| "未知".into())
    );
    let version = fs::read_to_string(paths.at("sys/module/tcp_bbr/version")).unwrap_or_default();
    if version.trim() == "3" {
        println!("运行中的 tcp_bbr: v3 (仅 TCP 当前算法为 bbr 时启用)");
    } else {
        println!(
            "运行中的 tcp_bbr 版本: {} (不能仅凭 bbr 名称判断 v3)",
            if version.trim().is_empty() {
                "未知"
            } else {
                version.trim()
            }
        );
    }
    if let Some(version) =
        optional_output(ctx, "modinfo", &["-k", &kernel, "-F", "version", "tcp_bbr"])
    {
        println!("当前内核磁盘上的 tcp_bbr 模块: v{version} (不代表已加载)");
    }
    if let Some(packages) = optional_output(
        ctx,
        "dpkg-query",
        &[
            "-W",
            "-f=${Package}\t${Status}\n",
            "linux-image-*joeyblog-bbrv3*",
        ],
    ) {
        for line in packages.lines() {
            if let Some((package, "install ok installed")) = line.split_once('\t') {
                let running = package.strip_prefix("linux-image-") == Some(kernel.as_str());
                println!(
                    "已安装: {package}{}",
                    if running { "" } else { " (当前未运行)" }
                );
            }
        }
    }
    if paths.config.is_file() {
        println!("Onebox 持久配置: {}", paths.config.display());
    }
    if let Some(queues) = optional_output(ctx, "tc", &["qdisc", "show"]) {
        println!("\n网卡实际队列:\n{queues}");
    }
    config_notice(paths);
    println!("\nTCP BBR 与 Hysteria2/TUIC 的 QUIC 拥塞控制不同；默认队列不等于现有网卡实际队列。");
    Ok(())
}

fn config_notice(paths: &Paths) {
    let mut files = vec![paths.at("etc/sysctl.conf")];
    if let Ok(entries) = fs::read_dir(paths.at("etc/sysctl.d")) {
        files.extend(
            entries
                .flatten()
                .map(|entry| entry.path())
                .filter(|p| p.extension().is_some_and(|ext| ext == "conf")),
        );
    }
    for file in files {
        if file == paths.config {
            continue;
        }
        let Ok(text) = fs::read_to_string(&file) else {
            continue;
        };
        if text.lines().any(|line| {
            line.split_once('=').is_some_and(|(key, _)| {
                let key = key.trim().replace('/', ".");
                key == CC || key == QDISC
            })
        }) {
            eprintln!(
                "其他 TCP/队列配置: {}；请核对启动时覆盖关系，Onebox 不修改此文件",
                file.display()
            );
        }
    }
}

struct Lock(File);
impl Lock {
    fn acquire(paths: &Paths) -> Result<Self> {
        util::safe_path(&paths.data.join("lock"))?;
        util::safe_path(&paths.config)?;
        match fs::symlink_metadata(&paths.config) {
            Ok(meta) if !meta.is_file() => return Err("BBR 配置路径必须是普通文件".into()),
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => return Err(e.into()),
            _ => (),
        }
        fs::create_dir_all(&paths.data)?;
        fs::set_permissions(&paths.data, fs::Permissions::from_mode(0o700))?;
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(paths.data.join("lock"))?;
        if !file.metadata()?.is_file() {
            return Err("BBR 锁必须是普通文件".into());
        }
        // The File owns this descriptor and remains alive until the guard drops.
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err(format!(
                "另一个 BBR 操作正在进行或无法加锁: {}",
                std::io::Error::last_os_error()
            )
            .into());
        }
        Ok(Self(file))
    }
}
impl Drop for Lock {
    fn drop(&mut self) {
        unsafe {
            libc::flock(self.0.as_raw_fd(), libc::LOCK_UN);
        }
    }
}

fn enable(ctx: &Context, paths: &Paths, queue: &str) -> Result<()> {
    valid_queue(queue)?;
    if paths.at("proc/vz").exists() && !paths.at("proc/bc").exists()
        || optional_output(ctx, "systemd-detect-virt", &[]).as_deref() == Some("openvz")
    {
        return Err("OpenVZ 无法修改内核拥塞控制，请在服务商面板开启 BBR".into());
    }
    let _lock = Lock::acquire(paths)?;
    if !sysctl(ctx, AVAILABLE)
        .unwrap_or_default()
        .split_whitespace()
        .any(|s| s == "bbr")
    {
        let _ = ctx.output("modprobe", &["tcp_bbr"]);
    }
    if !sysctl(ctx, AVAILABLE)?
        .split_whitespace()
        .any(|s| s == "bbr")
    {
        return Err("当前内核未提供 BBR；支持的 VPS 可安装 v3 内核，容器请联系宿主机管理员".into());
    }
    apply_runtime_and_persist(ctx, paths, queue, &util::atomic_write)?;
    println!("TCP BBR + {queue} 已启用并保存 (BBR 版本取决于运行内核)");
    println!("默认队列用于新建队列；现有网卡的 tc/整形规则保持原状，可用 onebox bbr status 检查");
    config_notice(paths);
    Ok(())
}

/// A failed write can have happened after rename (e.g. directory fsync). Keep
/// the original file as well as both runtime values until the commit succeeds.
type PersistConfig<'a> = dyn Fn(&Path, &[u8], u32) -> Result<()> + 'a;

fn apply_runtime_and_persist(
    ctx: &Context,
    paths: &Paths,
    queue: &str,
    persist: &PersistConfig<'_>,
) -> Result<()> {
    valid_queue(queue)?;
    let old_cc = sysctl(ctx, CC)?;
    let old_queue = sysctl(ctx, QDISC)?;
    if [&old_cc, &old_queue].iter().any(|value| {
        value.is_empty()
            || !value
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || c == b'_')
    }) {
        return Err("无法安全保存原 TCP/队列参数".into());
    }
    let old_file = match fs::read(&paths.config) {
        Ok(bytes) => Some((
            bytes,
            fs::metadata(&paths.config)?.permissions().mode() & 0o777,
        )),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => return Err(e.into()),
    };
    let _ = ctx.output("modprobe", &[&format!("sch_{queue}")]);
    // Finish or roll back this short critical section before delivering an
    // interrupt. In particular SIGTERM must not skip Rust's Drop restoration
    // between the queue write and the congestion-control write.
    let _signals = SignalMask::critical_section()?;
    let mut guard = SysctlRollback {
        ctx,
        paths,
        old_cc,
        old_queue,
        old_file,
        file_touched: false,
        committed: false,
    };
    ctx.run(
        "sysctl",
        &["-w", &format!("{QDISC}={queue}"), &format!("{CC}=bbr")],
    )?;
    if sysctl(ctx, CC)? != "bbr" || sysctl(ctx, QDISC)? != queue {
        return Err("BBR/队列应用校验失败，恢复原参数与配置".into());
    }
    let contents = format!("# Managed by Onebox\n{QDISC} = {queue}\n{CC} = bbr\n");
    guard.file_touched = true;
    persist(&paths.config, contents.as_bytes(), 0o644)?;
    guard.committed = true;
    Ok(())
}
struct SignalMask(libc::sigset_t);
impl SignalMask {
    fn critical_section() -> Result<Self> {
        let mut blocked = std::mem::MaybeUninit::<libc::sigset_t>::uninit();
        let mut previous = std::mem::MaybeUninit::<libc::sigset_t>::uninit();
        // sigemptyset initializes the opaque sigset_t; pthread_sigmask writes
        // the previous mask before it is read. The guard restores this thread's
        // mask, including any signals already blocked by its caller.
        unsafe {
            if libc::sigemptyset(blocked.as_mut_ptr()) != 0 {
                return Err(std::io::Error::last_os_error().into());
            }
            for signal in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP] {
                if libc::sigaddset(blocked.as_mut_ptr(), signal) != 0 {
                    return Err(std::io::Error::last_os_error().into());
                }
            }
            let result =
                libc::pthread_sigmask(libc::SIG_BLOCK, blocked.as_ptr(), previous.as_mut_ptr());
            if result != 0 {
                return Err(std::io::Error::from_raw_os_error(result).into());
            }
            Ok(Self(previous.assume_init()))
        }
    }
}
impl Drop for SignalMask {
    fn drop(&mut self) {
        let result =
            unsafe { libc::pthread_sigmask(libc::SIG_SETMASK, &self.0, std::ptr::null_mut()) };
        if result != 0 {
            eprintln!(
                "恢复信号屏蔽状态失败: {}",
                std::io::Error::from_raw_os_error(result)
            );
        }
    }
}
struct SysctlRollback<'a> {
    ctx: &'a Context,
    paths: &'a Paths,
    old_cc: String,
    old_queue: String,
    old_file: Option<(Vec<u8>, u32)>,
    file_touched: bool,
    committed: bool,
}
impl Drop for SysctlRollback<'_> {
    fn drop(&mut self) {
        if self.committed {
            return;
        }
        // Restore individually so a failure restoring one cannot skip the other.
        for value in [
            format!("{QDISC}={}", self.old_queue),
            format!("{CC}={}", self.old_cc),
        ] {
            if self.ctx.run("sysctl", &["-w", &value]).is_err() {
                eprintln!("恢复原 TCP/队列参数失败，请手动核对: {value}");
            }
        }
        if self.file_touched {
            let restored = match &self.old_file {
                Some((bytes, mode)) => util::atomic_write(&self.paths.config, bytes, *mode),
                None => match fs::remove_file(&self.paths.config) {
                    Ok(()) => Ok(()),
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
                    Err(e) => Err(e.into()),
                },
            };
            if let Err(error) = restored {
                eprintln!("恢复 BBR 持久配置失败，请手动核对: {error}");
            }
        }
    }
}

fn version_parts(version: &str) -> Option<Vec<u64>> {
    let parts = version.split('.').collect::<Vec<_>>();
    if parts.is_empty()
        || parts
            .iter()
            .any(|part| part.is_empty() || !part.bytes().all(|c| c.is_ascii_digit()))
    {
        return None;
    }
    parts.into_iter().map(|part| part.parse().ok()).collect()
}
fn tag_version(tag: &str, arch: Arch, max: bool) -> Option<Vec<u64>> {
    let version = tag.strip_prefix(arch.tag)?.strip_prefix('-')?;
    let version = if max {
        version.strip_suffix("-max")?
    } else {
        version
    };
    let parts = version_parts(version)?;
    (parts.len() == 2 || parts.len() == 3).then_some(parts)
}
fn kernel_name(tag: &str, arch: Arch, max: bool) -> Result<String> {
    tag_version(tag, arch, max).ok_or("Release 标签与架构/标准或 Max 类型不匹配")?;
    let version = &tag[arch.tag.len() + 1..];
    Ok(if max {
        format!(
            "{}-joeyblog-bbrv3-max",
            version.strip_suffix("-max").unwrap()
        )
    } else {
        format!("{version}-joeyblog-bbrv3")
    })
}
fn release_tags<F>(arch: Arch, max: bool, mut fetch: F) -> Result<Vec<String>>
where
    F: FnMut(&str) -> Result<Value>,
{
    for page in 1..=5 {
        let url = format!("https://api.github.com/repos/{REPO}/releases?per_page=100&page={page}");
        let data = fetch(&url)?;
        let releases = data
            .as_array()
            .ok_or("GitHub Release 响应无效 (可能被 API 限流)")?;
        let mut tags = releases
            .iter()
            .filter(|r| r["draft"] == false && r["prerelease"] == false)
            .filter_map(|r| r["tag_name"].as_str())
            .filter_map(|tag| tag_version(tag, arch, max).map(|version| (version, tag.to_string())))
            .collect::<Vec<_>>();
        tags.sort_by(|a, b| b.cmp(a));
        tags.dedup_by(|a, b| a.1 == b.1);
        if !tags.is_empty() {
            return Ok(tags.into_iter().map(|(_, tag)| tag).collect());
        }
        if releases.len() < 100 {
            break;
        }
    }
    Err(format!(
        "最近 500 个 Release 中未找到 {} / {}；可指定完整 Release 标签",
        arch.tag,
        if max { "Max" } else { "标准版" }
    )
    .into())
}

#[derive(Clone, Debug)]
struct Asset {
    name: String,
    digest: String,
    size: u64,
    url: String,
    package: String,
}
fn manifest(data: &Value, tag: &str, arch: Arch, max: bool) -> Result<(String, Vec<Asset>)> {
    let kernel = kernel_name(tag, arch, max)?;
    if data["tag_name"].as_str() != Some(tag)
        || data["draft"] != false
        || data["prerelease"] != false
    {
        return Err("BBR Release 标签不匹配、尚未发布或为预发布版".into());
    }
    let assets = data["assets"].as_array().ok_or("BBR Release 缺少包列表")?;
    let mut selected = Vec::new();
    for kind in ["image", "headers"] {
        let package = format!("linux-{kind}-{kernel}");
        let prefix = format!("{package}_");
        let suffix = format!("_{}.deb", arch.deb);
        let matches = assets
            .iter()
            .filter(|a| {
                a["name"]
                    .as_str()
                    .is_some_and(|name| name.starts_with(&prefix) && name.ends_with(&suffix))
            })
            .collect::<Vec<_>>();
        if matches.len() != 1 {
            return Err(format!("BBR Release 必须恰好包含一个 {package} 包").into());
        }
        let asset = matches[0];
        let name = asset["name"].as_str().unwrap();
        if !name
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"_.+-".contains(&c))
        {
            return Err("BBR 包文件名不安全".into());
        }
        let expected = format!("https://github.com/{REPO}/releases/download/{tag}/{name}");
        if asset["browser_download_url"].as_str() != Some(expected.as_str()) {
            return Err("BBR 包下载地址不是指定的官方 Release 资产".into());
        }
        let digest = asset["digest"]
            .as_str()
            .and_then(|s| s.strip_prefix("sha256:"))
            .filter(|s| {
                s.len() == 64
                    && s.bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            })
            .ok_or("BBR Release 缺少可信 SHA-256，拒绝安装")?;
        let size = asset["size"]
            .as_u64()
            .filter(|n| *n > 0 && *n <= 2_147_483_648)
            .ok_or("BBR 包大小无效")?;
        selected.push(Asset {
            name: name.into(),
            digest: digest.into(),
            size,
            url: expected,
            package,
        });
    }
    Ok((kernel, selected))
}

fn read_os_release(paths: &Paths) -> Result<BTreeMap<String, String>> {
    let text = fs::read_to_string(paths.at("etc/os-release"))?;
    let mut fields = BTreeMap::new();
    for line in text.lines() {
        if let Some((key, value)) = line.split_once('=') {
            let value = value.trim();
            let unquoted = if value.starts_with('"') && value.ends_with('"') && value.len() >= 2
                || value.starts_with('\'') && value.ends_with('\'') && value.len() >= 2
            {
                &value[1..value.len() - 1]
            } else {
                value
            };
            fields.insert(key.trim().to_string(), unquoted.to_string());
        }
    }
    Ok(fields)
}
fn supported_os(fields: &BTreeMap<String, String>) -> Result<()> {
    let id = fields.get("ID").map(String::as_str).unwrap_or_default();
    let raw_version = fields
        .get("VERSION_ID")
        .map(String::as_str)
        .unwrap_or_default();
    let version = if id == "debian" && raw_version.is_empty() {
        match fields
            .get("VERSION_CODENAME")
            .map(String::as_str)
            .unwrap_or_default()
        {
            "bookworm" => "12",
            "trixie" => "13",
            "forky" => "14",
            "sid" | "unstable" => "999",
            _ => "",
        }
    } else {
        raw_version
    };
    let mut parts =
        version_parts(version).ok_or("系统版本未知，需要 Debian 12+ / Ubuntu 24.04+")?;
    parts.resize(parts.len().max(2), 0);
    match id {
        "debian" if parts[0] >= 12 => Ok(()),
        "ubuntu" if (parts[0], parts[1]) >= (24, 4) => Ok(()),
        _ => {
            Err("BBRv3 内核安装仅支持 Debian 12+ / Ubuntu 24.04+ (其他系统仍可启用自带 BBR)".into())
        }
    }
}
fn container(ctx: &Context, paths: &Paths) -> bool {
    if ctx
        .output("systemd-detect-virt", &["--container", "--quiet"])
        .is_ok_and(|o| o.success())
    {
        return true;
    }
    if [".dockerenv", "run/.containerenv", "run/systemd/container"]
        .iter()
        .any(|p| paths.at(p).exists())
        || paths.at("proc/vz").exists() && !paths.at("proc/bc").exists()
    {
        return true;
    }
    for file in ["proc/version", "proc/sys/kernel/osrelease", "proc/1/cgroup"] {
        let text = fs::read_to_string(paths.at(file))
            .unwrap_or_default()
            .to_ascii_lowercase();
        if [
            "microsoft",
            "wsl",
            "docker",
            "lxc",
            "kubepods",
            "containerd",
            "libpod",
        ]
        .iter()
        .any(|s| text.contains(s))
        {
            return true;
        }
    }
    false
}
fn nonempty_file(path: &Path) -> bool {
    fs::metadata(path).is_ok_and(|m| m.is_file() && m.len() > 0)
}
fn installed_files_ready(paths: &Paths, kernel: &str) -> bool {
    nonempty_file(&paths.at(&format!("boot/vmlinuz-{kernel}")))
        && nonempty_file(&paths.at(&format!("boot/initrd.img-{kernel}")))
        && paths.at(&format!("lib/modules/{kernel}")).is_dir()
}
fn boot_ready(paths: &Paths, kernel: &str) -> Result<()> {
    if kernel.is_empty()
        || !kernel
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._+-".contains(&b))
        || paths.at("proc/device-tree").exists()
        || !nonempty_file(&paths.at("boot/grub/grub.cfg"))
        || !installed_files_ready(paths, kernel)
    {
        return Err("仅支持已有 GRUB、当前内核/模块/initrd 可供回退的常规 VPS；不自动处理设备树、U-Boot 或厂商内核".into());
    }
    Ok(())
}
fn secure_boot_disabled(ctx: &Context, paths: &Paths) -> Result<()> {
    let efi = paths.at("sys/firmware/efi");
    match fs::metadata(&efi) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
        _ => (),
    }
    let mut disabled = false;
    let mut unknown = false;
    if let Ok(entries) = fs::read_dir(efi.join("efivars")) {
        for entry in entries
            .flatten()
            .filter(|e| e.file_name().to_string_lossy().starts_with("SecureBoot-"))
        {
            match fs::read(entry.path()).ok().and_then(|v| v.get(4).copied()) {
                Some(0) => disabled = true,
                Some(1) => return Err("Secure Boot 已启用，不能安装未经本机信任签名的内核".into()),
                _ => unknown = true,
            }
        }
    }
    if disabled && !unknown {
        return Ok(());
    }
    if let Some(output) = optional_output(ctx, "mokutil", &["--sb-state"]) {
        if output
            .lines()
            .any(|line| line.trim() == "SecureBoot disabled")
            && !output
                .lines()
                .any(|line| line.trim() == "SecureBoot enabled")
        {
            return Ok(());
        }
    }
    Err("Secure Boot 状态不明，不能安装未经本机信任签名的内核".into())
}
fn space(ctx: &Context, path: &Path, minimum_kib: u64) -> Result<()> {
    let output = ctx.run("df", &["-Pk", "--", util::path_str(path)?])?;
    let available = output
        .lines()
        .filter(|line| !line.trim().is_empty())
        .nth(1)
        .and_then(|line| line.split_whitespace().nth(3))
        .and_then(|v| v.parse::<u64>().ok());
    if !available.is_some_and(|available| available >= minimum_kib) {
        return Err(format!(
            "{} 空间不足或无法读取 (至少需要 {minimum_kib} KiB 可用空间)",
            path.display()
        )
        .into());
    }
    Ok(())
}
fn has_command(name: &str) -> bool {
    env::var_os("PATH").is_some_and(|path| {
        env::split_paths(&path).any(|dir| {
            fs::metadata(dir.join(name))
                .is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
        })
    })
}
fn kernel_preflight(ctx: &Context, paths: &Paths) -> Result<Arch> {
    if container(ctx, paths) {
        return Err("容器/WSL 共享宿主机内核，不能在此安装 BBRv3 内核".into());
    }
    supported_os(&read_os_release(paths)?)?;
    let arch = Arch::detect(ctx)?;
    for program in [
        "apt-get",
        "dpkg",
        "dpkg-deb",
        "dpkg-query",
        "update-grub",
        "df",
    ] {
        if !has_command(program) {
            return Err(format!("安装 BBRv3 缺少 {program}，请先安装对应系统包").into());
        }
    }
    if ctx.run("dpkg", &["--print-architecture"])?.trim() != arch.deb {
        return Err("系统用户空间架构与内核架构不匹配".into());
    }
    boot_ready(paths, ctx.run("uname", &["-r"])?.trim())?;
    secure_boot_disabled(ctx, paths)?;
    space(ctx, &paths.at("boot"), 524_288)?;
    space(ctx, &paths.system, 2_097_152)?;
    Ok(arch)
}

struct TempDir(PathBuf);
impl TempDir {
    fn new(parent: &Path) -> Result<Self> {
        let path = parent
            .canonicalize()?
            .join(format!("onebox-bbr-{}", util::random_hex(16)?));
        // mkdir, unlike create_dir_all, never accepts an attacker-created name.
        fs::DirBuilder::new().mode(0o700).create(&path)?;
        Ok(Self(path))
    }
}
impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn verify_package(ctx: &Context, file: &Path, asset: &Asset, arch: Arch) -> Result<()> {
    let metadata = fs::symlink_metadata(file)?;
    if !metadata.is_file() || metadata.len() != asset.size {
        return Err("内核包类型或大小不匹配，未执行安装".into());
    }
    let mut hash = Sha256::new();
    let mut input = File::open(file)?;
    let mut buffer = [0u8; 65_536];
    loop {
        let n = input.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        hash.update(&buffer[..n]);
    }
    if format!("{:x}", hash.finalize()) != asset.digest {
        return Err("内核包 SHA-256 不匹配，未执行安装".into());
    }
    let file_arg = util::path_str(file)?;
    let package = ctx.run("dpkg-deb", &["-f", file_arg, "Package"])?;
    let version = ctx.run("dpkg-deb", &["-f", file_arg, "Version"])?;
    let actual_arch = ctx.run("dpkg-deb", &["-f", file_arg, "Architecture"])?;
    let package = package.trim();
    let version = version.trim();
    if package != asset.package
        || actual_arch.trim() != arch.deb
        || version.is_empty()
        || version.chars().any(char::is_whitespace)
        || asset.name != format!("{package}_{version}_{}.deb", arch.deb)
        || file.file_name().and_then(|name| name.to_str()) != Some(asset.name.as_str())
    {
        return Err("内核包 Package/架构/版本/文件名不匹配，未执行安装".into());
    }
    Ok(())
}
fn apply_kernel(ctx: &Context, paths: &Paths, kernel: &str, packages: &[PathBuf]) -> Result<()> {
    if packages.len() != 2 {
        return Err("安装需要已验证的 image + headers 两个包".into());
    }
    let package_args = packages
        .iter()
        .map(|p| util::path_str(p).map(String::from))
        .collect::<Result<Vec<_>>>()?;
    let mut simulate = vec![
        "--simulate",
        "--no-remove",
        "--no-install-recommends",
        "install",
    ]
    .into_iter()
    .map(String::from)
    .collect::<Vec<_>>();
    simulate.extend(package_args.clone());
    ctx.run_args("apt-get", &simulate)?;
    let mut install = vec![
        "-o",
        "DPkg::Lock::Timeout=60",
        "--no-remove",
        "--no-install-recommends",
        "install",
        "-y",
    ]
    .into_iter()
    .map(String::from)
    .collect::<Vec<_>>();
    install.extend(package_args);
    ctx.run_args("apt-get", &install).map_err(|error| {
        format!("内核安装失败；保留旧内核，请检查 apt/dpkg 日志，不要重启: {error}")
    })?;
    for kind in ["image", "headers"] {
        let package = format!("linux-{kind}-{kernel}");
        if ctx
            .run("dpkg-query", &["-W", "-f=${Status}", &package])?
            .trim()
            != "install ok installed"
        {
            return Err("内核包未完成配置，请修复 apt/dpkg 后再重启".into());
        }
    }
    if !installed_files_ready(paths, kernel) {
        return Err("新内核/initrd/模块不完整；旧内核仍保留，请修复引导后再重启".into());
    }
    ctx.run("update-grub", &[])
        .map_err(|error| format!("更新 GRUB 失败；旧内核仍保留，请修复引导后再重启: {error}"))?;
    let grub = fs::read_to_string(paths.at("boot/grub/grub.cfg"))?;
    let target = format!("vmlinuz-{kernel}");
    if !grub.lines().any(|line| {
        let mut words = line.split_whitespace();
        matches!(words.next(), Some("linux" | "linuxefi" | "linux16"))
            && words.next().is_some_and(|word| {
                word.trim_matches(|c| c == '\'' || c == '"')
                    .rsplit('/')
                    .next()
                    == Some(target.as_str())
            })
    }) {
        return Err("GRUB 中未找到新内核；旧内核仍保留，请修复引导后再重启".into());
    }
    Ok(())
}

fn confirm_install(ctx: &Context, tag: &str) -> Result<()> {
    if ctx.yes {
        return Ok(());
    }
    if !crate::ui::confirm(
        ctx,
        &format!("安装 {tag}？请确认有 VPS 控制台与快照，安装后需手动重启"),
        false,
    )? {
        return Err("已取消 BBRv3 内核安装".into());
    }
    Ok(())
}
fn install(ctx: &Context, paths: &Paths, desired: &str, max: bool, apply: bool) -> Result<()> {
    let arch = kernel_preflight(ctx, paths)?;
    let tag = if desired == "latest" {
        release_tags(arch, max, |url| platform::github_json(ctx, url))?.remove(0)
    } else {
        desired.to_string()
    };
    // Validate before making the request so user input cannot alter the API path.
    kernel_name(&tag, arch, max)?;
    let data = platform::github_json(
        ctx,
        &format!("https://api.github.com/repos/{REPO}/releases/tags/{tag}"),
    )?;
    let (kernel, assets) = manifest(&data, &tag, arch, max)?;
    let total = assets.iter().map(|a| a.size).sum::<u64>();
    println!("来源: https://github.com/{REPO}\nRelease: {tag}\n目标内核: {kernel}");
    println!(
        "下载合计: {} MiB；安装 image + headers，保留全部旧内核。",
        total.div_ceil(1_048_576)
    );
    if max {
        println!("Max 为激进吞吐实验版，可能增加延迟、丢包和带宽争抢；仅用于自有链路实验");
    }
    println!("保留现有 GRUB 默认项设置；重启时可能需要在控制台手动选择新内核。");
    if !apply {
        println!("预览完成；加 --apply 执行安装，无人值守同时加 -y。不会自动重启。");
        return Ok(());
    }
    require_root(ctx)?;
    confirm_install(ctx, &tag)?;
    let _lock = Lock::acquire(paths)?;
    // Revalidate after waiting for confirmation: boot files and free space may
    // have changed. Lock serializes all cooperating Onebox BBR writers.
    if kernel_preflight(ctx, paths)? != arch {
        return Err("确认期间系统架构发生变化，取消安装".into());
    }
    let work = TempDir::new(&paths.temp)?;
    space(ctx, &work.0, total.div_ceil(1024) + 262_144)?;
    let mut packages = Vec::new();
    for asset in &assets {
        let file = work.0.join(&asset.name);
        println!("下载 {}", asset.name);
        platform::download(ctx, &asset.url, &file)?;
        verify_package(ctx, &file, asset, arch)?;
        packages.push(file);
    }
    space(ctx, &paths.at("boot"), 524_288)?;
    space(ctx, &paths.system, 2_097_152)?;
    apply_kernel(ctx, paths, &kernel, &packages)?;
    let record = assets
        .iter()
        .map(|a| format!("{}\tsha256:{}\t{}\t{}\n", a.name, a.digest, a.size, a.url))
        .collect::<String>();
    let record_path = paths.data.join("last-install.tsv");
    if let Err(error) = util::safe_path(&record_path)
        .and_then(|_| util::atomic_write(&record_path, record.as_bytes(), 0o600))
    {
        eprintln!("安装成功，但未能保存下载校验记录: {error}");
    }
    let running = optional_output(ctx, "uname", &["-r"]).unwrap_or_else(|| "未知".into());
    println!("已安装 {kernel}；当前仍运行 {running}。请手动重启，再执行 onebox bbr status / onebox bbr enable fq");
    println!("若新内核无法启动，请从 VPS 控制台的 GRUB Advanced options 选择保留的旧内核");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::{CommandOutput, Paths as AppPaths, Runner};
    use serde_json::json;
    use std::{
        os::unix::fs::symlink,
        sync::{Arc, Mutex},
    };

    const ARCH: Arch = Arch {
        tag: "x86_64",
        deb: "amd64",
    };
    const TAG: &str = "x86_64-7.2.8";
    const KERNEL: &str = "7.2.8-joeyblog-bbrv3";

    struct MockState {
        cc: String,
        queue: String,
        available: String,
        fail_apply: bool,
        ignore_apply: bool,
        fail_rollback: bool,
        fail_apt: usize,
        apt_calls: usize,
        fail_grub: bool,
        installed_status: String,
        deb_package: Option<String>,
        deb_arch: String,
        deb_version: String,
        fail_deb: bool,
        df_available: String,
        virtualized: bool,
        secure_boot: Option<String>,
        calls: Vec<(String, Vec<String>)>,
    }
    impl Default for MockState {
        fn default() -> Self {
            Self {
                cc: "cubic".into(),
                queue: "fq_codel".into(),
                available: "reno cubic bbr".into(),
                fail_apply: false,
                ignore_apply: false,
                fail_rollback: false,
                fail_apt: 0,
                apt_calls: 0,
                fail_grub: false,
                installed_status: "install ok installed".into(),
                deb_package: None,
                deb_arch: "amd64".into(),
                deb_version: "7.2.8-1".into(),
                fail_deb: false,
                df_available: "99999999".into(),
                virtualized: false,
                secure_boot: None,
                calls: Vec::new(),
            }
        }
    }
    #[derive(Default)]
    struct MockRunner(Mutex<MockState>);
    fn output(value: impl Into<String>) -> CommandOutput {
        CommandOutput {
            code: 0,
            stdout: value.into(),
            stderr: String::new(),
        }
    }
    fn failure() -> CommandOutput {
        CommandOutput {
            code: 1,
            stdout: String::new(),
            stderr: "injected failure".into(),
        }
    }
    impl Runner for MockRunner {
        fn output(&self, program: &str, args: &[String]) -> Result<CommandOutput> {
            let mut state = self.0.lock().unwrap();
            state.calls.push((program.into(), args.to_vec()));
            let arg = |n: usize| args.get(n).map(String::as_str).unwrap_or_default();
            Ok(match program {
                "id" => output("0\n"),
                "uname" => output(if arg(0) == "-m" { "x86_64" } else { "6.1.0-old" }),
                "systemd-detect-virt" => if state.virtualized { output("lxc") } else { failure() },
                "sysctl" if arg(0) == "-n" => match arg(1) {
                    CC => output(state.cc.clone()), QDISC => output(state.queue.clone()), AVAILABLE => output(state.available.clone()), _ => failure(),
                },
                "sysctl" if arg(0) == "-w" => {
                    let applying = args.iter().any(|a| a == &format!("{CC}=bbr"));
                    if !applying && state.fail_rollback && arg(1).starts_with(QDISC) { return Ok(failure()); }
                    if !state.ignore_apply || !applying {
                        for setting in &args[1..] {
                            if let Some((name, value)) = setting.split_once('=') {
                                match name {
                                    QDISC => state.queue = value.into(),
                                    CC if !applying || !state.fail_apply => state.cc = value.into(),
                                    _ => (),
                                }
                            }
                        }
                    }
                    if applying && state.fail_apply { failure() } else { output("") }
                }
                "modprobe" => output(""),
                "modinfo" => output("3"),
                "tc" => output("qdisc fq_codel 0: root"),
                "mokutil" => state.secure_boot.clone().map(output).unwrap_or_else(failure),
                "df" => output(format!("Filesystem 1024-blocks Used Available Capacity Mounted on\n/dev/test 999999999 0 {} 0% /\n", state.df_available)),
                "dpkg-deb" => {
                    if state.fail_deb { return Ok(failure()); }
                    match arg(2) {
                        "Package" => output(state.deb_package.clone().unwrap_or_else(|| Path::new(arg(1)).file_name().unwrap().to_string_lossy().split('_').next().unwrap().to_string())),
                        "Architecture" => output(state.deb_arch.clone()),
                        "Version" => output(state.deb_version.clone()),
                        _ => failure(),
                    }
                }
                "dpkg-query" => output(state.installed_status.clone()),
                "dpkg" => output("amd64"),
                "apt-get" => {
                    state.apt_calls += 1;
                    if state.apt_calls == state.fail_apt { failure() } else { output("") }
                }
                "update-grub" => if state.fail_grub { failure() } else { output("") },
                _ => return Err(format!("test blocked unexpected program: {program}").into()),
            })
        }
    }
    struct Fixture {
        _temp: TempDir,
        paths: Paths,
        ctx: Context,
        runner: Arc<MockRunner>,
    }
    impl Fixture {
        fn new() -> Self {
            let temp = TempDir::new(&env::temp_dir()).unwrap();
            let paths = Paths {
                system: temp.0.join("system"),
                config: temp.0.join("sysctl/99-onebox-bbr.conf"),
                data: temp.0.join("data"),
                temp: temp.0.clone(),
            };
            fs::create_dir_all(paths.config.parent().unwrap()).unwrap();
            fs::create_dir_all(&paths.system).unwrap();
            fs::write(&paths.config, "old config\n").unwrap();
            fs::set_permissions(&paths.config, fs::Permissions::from_mode(0o600)).unwrap();
            let runner = Arc::new(MockRunner::default());
            let ctx = Context {
                paths: AppPaths::isolated(&temp.0),
                runner: runner.clone(),
                yes: true,
            };
            Self {
                _temp: temp,
                paths,
                ctx,
                runner,
            }
        }
        fn with_state(&self, change: impl FnOnce(&mut MockState)) {
            change(&mut self.runner.0.lock().unwrap());
        }
        fn old_runtime(&self) {
            let state = self.runner.0.lock().unwrap();
            assert_eq!(state.cc, "cubic");
            assert_eq!(state.queue, "fq_codel");
            assert_eq!(
                fs::read_to_string(&self.paths.config).unwrap(),
                "old config\n"
            );
            assert_eq!(
                fs::metadata(&self.paths.config)
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
        fn boot(&self, kernel: &str) {
            fs::create_dir_all(self.paths.at("boot/grub")).unwrap();
            fs::create_dir_all(self.paths.at(&format!("lib/modules/{kernel}"))).unwrap();
            fs::write(self.paths.at(&format!("boot/vmlinuz-{kernel}")), "kernel\n").unwrap();
            fs::write(
                self.paths.at(&format!("boot/initrd.img-{kernel}")),
                "initrd\n",
            )
            .unwrap();
            fs::write(
                self.paths.at("boot/grub/grub.cfg"),
                format!("linux /boot/vmlinuz-{kernel} root=test\n"),
            )
            .unwrap();
        }
        fn calls(&self, program: &str) -> Vec<Vec<String>> {
            self.runner
                .0
                .lock()
                .unwrap()
                .calls
                .iter()
                .filter(|(p, _)| p == program)
                .map(|(_, a)| a.clone())
                .collect()
        }
    }
    fn release() -> Value {
        let assets = ["image", "headers"].iter().map(|kind| {
            let name = format!("linux-{kind}-{KERNEL}_7.2.8-1_amd64.deb");
            json!({ "name": name, "digest": format!("sha256:{}", util::sha256(b"package")), "size": 7,
                "browser_download_url": format!("https://github.com/{REPO}/releases/download/{TAG}/{name}") })
        }).collect::<Vec<_>>();
        json!({"tag_name": TAG, "draft": false, "prerelease": false, "assets": assets})
    }

    #[test]
    fn validates_dispatch_without_side_effects() {
        let args = |items: &[&str]| items.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert_eq!(parse(&[]).unwrap(), Action::Status);
        assert_eq!(
            parse(&args(&["enable"])).unwrap(),
            Action::Enable("fq".into())
        );
        assert_eq!(
            parse(&args(&["install", TAG, "--max", "--apply"])).unwrap(),
            Action::Install {
                desired: TAG.into(),
                max: true,
                apply: true
            }
        );
        for bad in [
            &["status", "extra"][..],
            &["enable", "fq;reboot"],
            &["enable", "fq", "cake"],
            &["releases", "--apply"],
            &["install", "one", "two"],
            &["install", "--unknown"],
            &["install", "--apply", "--apply"],
        ] {
            assert!(parse(&args(bad)).is_err(), "{bad:?}");
        }
    }
    #[test]
    fn enables_all_supported_queues() {
        for queue in ["fq", "fq_codel", "fq_pie", "cake"] {
            let f = Fixture::new();
            enable(&f.ctx, &f.paths, queue).unwrap();
            let state = f.runner.0.lock().unwrap();
            assert_eq!(state.cc, "bbr");
            assert_eq!(state.queue, queue);
            assert!(fs::read_to_string(&f.paths.config)
                .unwrap()
                .contains(&format!("{QDISC} = {queue}")));
        }
    }
    #[test]
    fn runtime_partial_failure_restores_both_values_and_file() {
        let f = Fixture::new();
        f.with_state(|s| s.fail_apply = true);
        assert!(enable(&f.ctx, &f.paths, "cake").is_err());
        f.old_runtime();
        assert_eq!(f.calls("sysctl").iter().filter(|a| a[0] == "-w").count(), 3);
    }
    #[test]
    fn short_sysctl_transaction_restores_callers_signal_mask() {
        fn mask() -> Vec<i32> {
            let mut current = std::mem::MaybeUninit::<libc::sigset_t>::uninit();
            unsafe {
                assert_eq!(
                    libc::pthread_sigmask(
                        libc::SIG_SETMASK,
                        std::ptr::null(),
                        current.as_mut_ptr()
                    ),
                    0
                );
                let current = current.assume_init();
                [libc::SIGINT, libc::SIGTERM, libc::SIGHUP]
                    .iter()
                    .map(|s| libc::sigismember(&current, *s))
                    .collect()
            }
        }
        let before = mask();
        {
            let _guard = SignalMask::critical_section().unwrap();
            assert_eq!(mask(), vec![1, 1, 1]);
        }
        assert_eq!(mask(), before);
        let f = Fixture::new();
        f.with_state(|s| s.fail_apply = true);
        assert!(enable(&f.ctx, &f.paths, "cake").is_err());
        assert_eq!(mask(), before);
    }
    #[test]
    fn runtime_readback_failure_rolls_back() {
        let f = Fixture::new();
        f.with_state(|s| s.ignore_apply = true);
        assert!(enable(&f.ctx, &f.paths, "cake").is_err());
        f.old_runtime();
    }
    #[test]
    fn persistence_failure_restores_runtime_and_existing_mode() {
        let f = Fixture::new();
        let _lock = Lock::acquire(&f.paths).unwrap();
        let write_then_fail = |path: &Path, bytes: &[u8], mode| {
            util::atomic_write(path, bytes, mode)?;
            Err("injected failure after atomic rename".into())
        };
        assert!(apply_runtime_and_persist(&f.ctx, &f.paths, "cake", &write_then_fail).is_err());
        f.old_runtime();
    }
    #[test]
    fn persistence_failure_removes_new_file() {
        let f = Fixture::new();
        fs::remove_file(&f.paths.config).unwrap();
        let write_then_fail = |path: &Path, bytes: &[u8], mode| {
            util::atomic_write(path, bytes, mode)?;
            Err("injected failure after atomic rename".into())
        };
        assert!(apply_runtime_and_persist(&f.ctx, &f.paths, "cake", &write_then_fail).is_err());
        assert!(!f.paths.config.exists());
        let state = f.runner.0.lock().unwrap();
        assert_eq!(
            (state.cc.as_str(), state.queue.as_str()),
            ("cubic", "fq_codel")
        );
    }
    #[test]
    fn rollback_attempts_second_value_even_if_first_restore_fails() {
        let f = Fixture::new();
        f.with_state(|s| s.fail_rollback = true);
        let fail = |_: &Path, _: &[u8], _| Err("persist failure".into());
        assert!(apply_runtime_and_persist(&f.ctx, &f.paths, "cake", &fail).is_err());
        assert_eq!(f.runner.0.lock().unwrap().cc, "cubic");
        assert!(f
            .calls("sysctl")
            .iter()
            .any(|a| a == &vec!["-w".to_string(), format!("{CC}=cubic")]));
    }
    #[test]
    fn cannot_enable_without_bbr() {
        let f = Fixture::new();
        f.with_state(|s| s.available = "reno cubic".into());
        assert!(enable(&f.ctx, &f.paths, "fq").is_err());
        assert!(f.calls("sysctl").iter().all(|a| a[0] != "-w"));
        f.old_runtime();
    }
    #[test]
    fn rejects_unsafe_paths_and_concurrent_writer_before_mutation() {
        let f = Fixture::new();
        let lock = Lock::acquire(&f.paths).unwrap();
        assert!(enable(&f.ctx, &f.paths, "fq").is_err());
        drop(lock);
        let target = f.paths.temp.join("untouched");
        fs::write(&target, "untouched").unwrap();
        fs::remove_file(&f.paths.config).unwrap();
        symlink(&target, &f.paths.config).unwrap();
        assert!(enable(&f.ctx, &f.paths, "fq").is_err());
        assert_eq!(fs::read_to_string(&target).unwrap(), "untouched");
        fs::remove_file(&f.paths.config).unwrap();
        fs::create_dir(&f.paths.config).unwrap();
        assert!(enable(&f.ctx, &f.paths, "fq").is_err());
        assert!(f.calls("sysctl").is_empty());
    }
    #[test]
    fn status_performs_no_writes_or_network_calls() {
        let f = Fixture::new();
        status(&f.ctx, &f.paths).unwrap();
        assert!(!f.paths.data.exists());
        f.old_runtime();
        for (program, args) in &f.runner.0.lock().unwrap().calls {
            assert!(matches!(
                program.as_str(),
                "uname" | "sysctl" | "modinfo" | "tc" | "dpkg-query"
            ));
            if program == "sysctl" {
                assert_eq!(args[0], "-n");
            }
        }
    }
    #[test]
    fn tag_validation_excludes_cross_arch_profile_and_path_injection() {
        for tag in [
            "arm64-7.2.8",
            "x86_64-7.2.8-max",
            "x86_64-7.2.8-rc1",
            "../latest",
            "x86_64-7.2.8/../foo",
            "x86_64-7",
            "x86_64-7.2.3.4",
        ] {
            assert!(tag_version(tag, ARCH, false).is_none(), "{tag}");
        }
        assert!(tag_version("x86_64-7.2", ARCH, false).is_some());
        assert_eq!(
            kernel_name("x86_64-7.2.8-max", ARCH, true).unwrap(),
            "7.2.8-joeyblog-bbrv3-max"
        );
    }
    #[test]
    fn release_list_filters_and_sorts_numeric_versions() {
        let data = json!([
            {"tag_name":"x86_64-7.2.9","draft":false,"prerelease":false},
            {"tag_name":"x86_64-7.2.10","draft":false,"prerelease":false},
            {"tag_name":"x86_64-7.2.10","draft":false,"prerelease":false},
            {"tag_name":"x86_64-7.2.8-max","draft":false,"prerelease":false},
            {"tag_name":"arm64-7.2.99","draft":false,"prerelease":false},
            {"tag_name":"x86_64-99.0","draft":false,"prerelease":true},
            {"tag_name":"x86_64-99.0","draft":true,"prerelease":false}
        ]);
        assert_eq!(
            release_tags(ARCH, false, |_| Ok(data.clone())).unwrap(),
            vec!["x86_64-7.2.10", "x86_64-7.2.9"]
        );
        assert_eq!(
            release_tags(ARCH, true, |_| Ok(data.clone())).unwrap(),
            vec!["x86_64-7.2.8-max"]
        );
        assert!(release_tags(ARCH, false, |_| Ok(json!({"message":"rate limit"}))).is_err());
    }
    #[test]
    fn release_list_paginates_using_only_direct_api_urls() {
        let first = json!((0..100)
            .map(|_| json!({"tag_name":"arm64-7.2.8","draft":false,"prerelease":false}))
            .collect::<Vec<_>>());
        let mut requested = Vec::new();
        let tags =
            release_tags(ARCH, false, |url| {
                requested.push(url.to_string());
                assert!(
                    url.starts_with("https://api.github.com/repos/byJoey/Actions-bbr-v3/releases?")
                );
                if url.ends_with("page=1") {
                    Ok(first.clone())
                } else {
                    Ok(json!([{"tag_name":TAG,"draft":false,"prerelease":false}]))
                }
            })
            .unwrap();
        assert_eq!(tags, vec![TAG]);
        assert_eq!(requested.len(), 2);
    }
    #[test]
    fn exact_manifest_ignores_unrelated_assets() {
        let mut data = release();
        data["assets"].as_array_mut().unwrap().extend([
            json!({"name":"install.sh"}),
            json!({"name":"linux-libc-dev_7.2.8-1_amd64.deb"}),
            json!({"name":"linux-image-debug.deb"}),
        ]);
        let (kernel, assets) = manifest(&data, TAG, ARCH, false).unwrap();
        assert_eq!(kernel, KERNEL);
        assert_eq!(assets.len(), 2);
        assert_eq!(assets[0].package, format!("linux-image-{KERNEL}"));
        assert_eq!(assets[1].package, format!("linux-headers-{KERNEL}"));
    }
    #[test]
    fn rejects_incomplete_or_untrusted_manifest() {
        let changes = [
            ("digest", Value::Null),
            ("digest", json!("sha256:bad")),
            ("digest", json!(format!("sha256:{}", "A".repeat(64)))),
            (
                "browser_download_url",
                json!("https://example.invalid/evil.deb"),
            ),
            ("size", json!(-1)),
            ("size", json!(1.5)),
            ("size", json!(0)),
            ("size", json!(2_147_483_649u64)),
            ("name", json!("../evil.deb")),
        ];
        for (key, value) in changes {
            let mut data = release();
            data["assets"][0][key] = value;
            assert!(manifest(&data, TAG, ARCH, false).is_err(), "{key}");
        }
        for (key, value) in [
            ("tag_name", json!("arm64-7.2.8")),
            ("draft", json!(true)),
            ("prerelease", json!(true)),
            ("draft", Value::Null),
        ] {
            let mut data = release();
            data[key] = value;
            assert!(manifest(&data, TAG, ARCH, false).is_err());
        }
        let mut duplicate = release();
        let asset = duplicate["assets"][0].clone();
        duplicate["assets"].as_array_mut().unwrap().push(asset);
        assert!(manifest(&duplicate, TAG, ARCH, false).is_err());
        let mut missing = release();
        missing["assets"].as_array_mut().unwrap().pop();
        assert!(manifest(&missing, TAG, ARCH, false).is_err());
    }
    #[test]
    fn os_gates_support_release_numbers_and_debian_codenames() {
        let fields = |id: &str, version: &str, codename: &str| {
            BTreeMap::from([
                ("ID".into(), id.into()),
                ("VERSION_ID".into(), version.into()),
                ("VERSION_CODENAME".into(), codename.into()),
            ])
        };
        for (id, version, name) in [
            ("debian", "12", ""),
            ("debian", "13.1", ""),
            ("ubuntu", "24.04", ""),
            ("ubuntu", "26.04", ""),
            ("debian", "", "trixie"),
            ("debian", "", "sid"),
        ] {
            supported_os(&fields(id, version, name)).unwrap();
        }
        for (id, version, name) in [
            ("debian", "11", ""),
            ("ubuntu", "22.04", ""),
            ("ubuntu", "24.03", ""),
            ("alpine", "3.23", ""),
            ("debian", "", "unknown"),
            ("debian", "12;reboot", ""),
            ("ubuntu", "", "noble"),
        ] {
            assert!(supported_os(&fields(id, version, name)).is_err());
        }
    }
    #[test]
    fn rejects_containers_and_wsl() {
        let f = Fixture::new();
        assert!(!container(&f.ctx, &f.paths));
        f.with_state(|s| s.virtualized = true);
        assert!(container(&f.ctx, &f.paths));
        f.with_state(|s| s.virtualized = false);
        fs::create_dir_all(f.paths.at("proc")).unwrap();
        fs::write(f.paths.at("proc/version"), "Linux Microsoft-standard-WSL2").unwrap();
        assert!(container(&f.ctx, &f.paths));
        fs::remove_file(f.paths.at("proc/version")).unwrap();
        fs::write(f.paths.at(".dockerenv"), "").unwrap();
        assert!(container(&f.ctx, &f.paths));
    }
    #[test]
    fn requires_boot_fallback_and_rejects_device_trees() {
        for missing in [
            "boot/grub/grub.cfg",
            "boot/vmlinuz-6.1.0-old",
            "boot/initrd.img-6.1.0-old",
            "lib/modules/6.1.0-old",
        ] {
            let f = Fixture::new();
            f.boot("6.1.0-old");
            boot_ready(&f.paths, "6.1.0-old").unwrap();
            let path = f.paths.at(missing);
            if path.is_dir() {
                fs::remove_dir(path).unwrap();
            } else {
                fs::remove_file(path).unwrap();
            }
            assert!(boot_ready(&f.paths, "6.1.0-old").is_err(), "{missing}");
        }
        let f = Fixture::new();
        f.boot("6.1.0-old");
        fs::create_dir_all(f.paths.at("proc/device-tree")).unwrap();
        assert!(boot_ready(&f.paths, "6.1.0-old").is_err());
        assert!(boot_ready(&f.paths, "../evil").is_err());
    }
    #[test]
    fn secure_boot_fails_closed() {
        let f = Fixture::new();
        secure_boot_disabled(&f.ctx, &f.paths).unwrap(); // Legacy BIOS.
        let vars = f.paths.at("sys/firmware/efi/efivars");
        fs::create_dir_all(&vars).unwrap();
        assert!(secure_boot_disabled(&f.ctx, &f.paths).is_err());
        fs::write(vars.join("SecureBoot-test"), [0, 0, 0, 0, 0]).unwrap();
        secure_boot_disabled(&f.ctx, &f.paths).unwrap();
        for byte in [1, 2] {
            fs::write(vars.join("SecureBoot-test"), [0, 0, 0, 0, byte]).unwrap();
            assert!(secure_boot_disabled(&f.ctx, &f.paths).is_err());
        }
        fs::write(vars.join("SecureBoot-test"), [0, 0, 0, 0]).unwrap();
        assert!(secure_boot_disabled(&f.ctx, &f.paths).is_err());
        f.with_state(|s| s.secure_boot = Some("SecureBoot disabled".into()));
        secure_boot_disabled(&f.ctx, &f.paths).unwrap();
        fs::write(vars.join("SecureBoot-test"), [0, 0, 0, 0, 1]).unwrap();
        assert!(secure_boot_disabled(&f.ctx, &f.paths).is_err()); // Enabled efivar wins over mokutil.
    }
    #[test]
    fn insufficient_or_unknown_space_rejected() {
        let f = Fixture::new();
        space(&f.ctx, &f.paths.system, 2_097_152).unwrap();
        for value in ["0", "524287", "unknown", "-1"] {
            f.with_state(|s| s.df_available = value.into());
            assert!(space(&f.ctx, &f.paths.system, 524_288).is_err());
        }
    }
    #[test]
    fn package_digest_and_size_checked_before_dpkg() {
        let f = Fixture::new();
        let (_, assets) = manifest(&release(), TAG, ARCH, false).unwrap();
        let asset = &assets[0];
        let file = f.paths.temp.join(&asset.name);
        for contents in [&b"Package"[..], &b"wrong size"[..]] {
            fs::write(&file, contents).unwrap();
            assert!(verify_package(&f.ctx, &file, asset, ARCH).is_err());
            assert!(f.calls("dpkg-deb").is_empty());
        }
        fs::write(&file, b"package").unwrap();
        verify_package(&f.ctx, &file, asset, ARCH).unwrap();
        assert_eq!(f.calls("dpkg-deb").len(), 3);
        assert!(f.calls("apt-get").is_empty());
    }
    #[test]
    fn package_metadata_must_match_exact_asset() {
        let f = Fixture::new();
        let (_, assets) = manifest(&release(), TAG, ARCH, false).unwrap();
        let asset = &assets[0];
        let file = f.paths.temp.join(&asset.name);
        fs::write(&file, b"package").unwrap();
        f.with_state(|s| s.deb_arch = "arm64".into());
        assert!(verify_package(&f.ctx, &file, asset, ARCH).is_err());
        f.with_state(|s| {
            s.deb_arch = "amd64".into();
            s.deb_package = Some(format!("linux-headers-{KERNEL}"));
        });
        assert!(verify_package(&f.ctx, &file, asset, ARCH).is_err());
        f.with_state(|s| {
            s.deb_package = None;
            s.deb_version = "7.2.8-2".into();
        });
        assert!(verify_package(&f.ctx, &file, asset, ARCH).is_err());
        f.with_state(|s| {
            s.deb_version = "7.2.8-1".into();
            s.fail_deb = true;
        });
        assert!(verify_package(&f.ctx, &file, asset, ARCH).is_err());
        assert!(f.calls("apt-get").is_empty());
    }
    #[test]
    fn apt_simulation_and_install_never_remove_or_reboot() {
        let f = Fixture::new();
        f.boot(KERNEL);
        let packages = [
            f.paths.temp.join("image.deb"),
            f.paths.temp.join("headers.deb"),
        ];
        apply_kernel(&f.ctx, &f.paths, KERNEL, &packages).unwrap();
        let calls = f.calls("apt-get");
        assert_eq!(calls.len(), 2);
        assert!(calls[0].contains(&"--simulate".into()));
        for args in &calls {
            assert!(args.contains(&"--no-remove".into()));
            assert!(args.contains(&"--no-install-recommends".into()));
            assert!(!args
                .iter()
                .any(|a| matches!(a.as_str(), "purge" | "remove" | "autoremove")));
        }
        assert_eq!(f.calls("update-grub").len(), 1);
        assert!(f.calls("reboot").is_empty());
        assert!(f.calls("shutdown").is_empty());
    }
    #[test]
    fn apt_failures_stop_before_grub() {
        for fail_at in [1, 2] {
            let f = Fixture::new();
            f.boot(KERNEL);
            f.with_state(|s| s.fail_apt = fail_at);
            let packages = [
                f.paths.temp.join("image.deb"),
                f.paths.temp.join("headers.deb"),
            ];
            assert!(apply_kernel(&f.ctx, &f.paths, KERNEL, &packages).is_err());
            assert_eq!(f.calls("apt-get").len(), fail_at);
            assert!(f.calls("update-grub").is_empty());
        }
    }
    #[test]
    fn incomplete_installation_or_grub_entry_is_not_success() {
        for stage in ["unconfigured", "files", "grub", "entry"] {
            let f = Fixture::new();
            f.boot(KERNEL);
            match stage {
                "unconfigured" => {
                    f.with_state(|s| s.installed_status = "install ok unpacked".into())
                }
                "files" => {
                    fs::remove_file(f.paths.at(&format!("boot/initrd.img-{KERNEL}"))).unwrap()
                }
                "grub" => f.with_state(|s| s.fail_grub = true),
                "entry" => fs::write(
                    f.paths.at("boot/grub/grub.cfg"),
                    format!("# linux /boot/vmlinuz-{KERNEL}\nlinux /boot/vmlinuz-{KERNEL}-other\n"),
                )
                .unwrap(),
                _ => unreachable!(),
            }
            let packages = [
                f.paths.temp.join("image.deb"),
                f.paths.temp.join("headers.deb"),
            ];
            assert!(
                apply_kernel(&f.ctx, &f.paths, KERNEL, &packages).is_err(),
                "{stage}"
            );
            assert!(!f.paths.data.join("last-install.tsv").exists());
        }
    }
}
