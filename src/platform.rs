//! Linux integration. Policy stays in Rust; subprocesses are bounded tools.
use crate::{
    context::Context,
    model::{Core, State},
    util, Result,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    env, fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    thread,
    time::Duration,
};

pub const TESTED_XRAY: &str = "26.3.27";
const FALLBACK_SINGBOX: &str = "1.14.2";

pub fn has(program: &str) -> bool {
    if program.contains('/') {
        return fs::metadata(program)
            .map(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
            .unwrap_or(false);
    }
    env::split_paths(&env::var_os("PATH").unwrap_or_default())
        .any(|p| has(&p.join(program).to_string_lossy()))
}
pub fn os_release() -> std::collections::BTreeMap<String, String> {
    fs::read_to_string("/etc/os-release")
        .unwrap_or_default()
        .lines()
        .filter_map(|line| {
            let (key, value) = line.split_once('=')?;
            Some((
                key.to_owned(),
                value.trim_matches('"').trim_matches('\'').to_owned(),
            ))
        })
        .collect()
}
pub fn init_system() -> &'static str {
    match env::var("ONEBOX_INIT").unwrap_or_default().as_str() {
        "systemd" => "systemd",
        "openrc" => "openrc",
        "none" => "none",
        _ if Path::new("/run/systemd/system").is_dir() => "systemd",
        _ if Path::new("/run/openrc").exists() || has("openrc-run") => "openrc",
        _ => "none",
    }
}
pub fn host_info(ctx: &Context) -> Result<Value> {
    let os = os_release();
    let arch = ctx.run("uname", &["-m"])?;
    let kernel = ctx.run("uname", &["-r"])?;
    let virt = ctx
        .output("systemd-detect-virt", &[])
        .ok()
        .filter(|x| x.success())
        .map(|x| x.stdout.trim().to_owned())
        .unwrap_or_else(|| {
            if Path::new("/.dockerenv").exists() {
                "docker".into()
            } else {
                "unknown".into()
            }
        });
    Ok(
        json!({"os":os.get("ID"),"version":os.get("VERSION_ID"),"arch":arch.trim(),"kernel":kernel.trim(),"init":init_system(),"virtualization":virt}),
    )
}
pub fn require_root() -> Result<()> {
    if unsafe { libc::geteuid() } == 0 {
        Ok(())
    } else {
        Err("此操作需要 root 权限".into())
    }
}
pub fn install_self(ctx: &Context) -> Result<()> {
    let source = env::current_exe()?;
    if let (Ok(installed), Ok(current)) = (
        fs::canonicalize(&ctx.paths.executable),
        fs::canonicalize(&source),
    ) {
        if installed == current {
            return Ok(());
        }
    }
    util::safe_path(&ctx.paths.executable)?;
    // An atomic self-update unlinks the old executable. current_exe() then
    // names a non-existent "(deleted)" path, but proc still exposes its inode.
    let bytes = fs::read("/proc/self/exe").or_else(|_| fs::read(source))?;
    if bytes.len() < 20 || &bytes[..4] != b"\x7fELF" {
        return Err("当前程序不是有效 Linux 二进制".into());
    }
    util::atomic_write(&ctx.paths.executable, &bytes, 0o755)
}
pub fn ensure_package(ctx: &Context, command: &str, package: &str) -> Result<()> {
    if has(command) {
        return Ok(());
    }
    require_root()?;
    let id = os_release().get("ID").cloned().unwrap_or_default();
    let cron = matches!(package, "cron" | "cronie" | "crontab");
    let rpm_package = if package == "iproute2" {
        "iproute"
    } else {
        package
    };
    if has("apt-get") {
        ctx.run("apt-get", &["update"])?;
        ctx.run(
            "apt-get",
            &[
                "-o",
                "DPkg::Lock::Timeout=60",
                "install",
                "-y",
                if cron { "cron" } else { package },
            ],
        )?;
    } else if has("dnf") {
        ctx.run(
            "dnf",
            &["install", "-y", if cron { "cronie" } else { rpm_package }],
        )?;
    } else if has("yum") {
        ctx.run(
            "yum",
            &["install", "-y", if cron { "cronie" } else { rpm_package }],
        )?;
    } else if has("apk") {
        ctx.run(
            "apk",
            &["add", "--no-cache", if cron { "dcron" } else { package }],
        )?;
    } else if has("pacman") {
        ctx.run(
            "pacman",
            &["-Sy", "--noconfirm", if cron { "cronie" } else { package }],
        )?;
    } else if has("zypper") {
        ctx.run(
            "zypper",
            &[
                "--non-interactive",
                "install",
                if cron { "cron" } else { package },
            ],
        )?;
    } else {
        return Err(format!("{id}: 未找到受支持的包管理器，请先安装 {package}").into());
    }
    if !has(command) {
        return Err(format!("安装后仍未找到 {command}").into());
    }
    Ok(())
}
fn valid_https(url: &str) -> bool {
    url.starts_with("https://") && !url.chars().any(char::is_whitespace) && !url.contains('\0')
}
fn fetch(ctx: &Context, url: &str, dest: &Path, proxy: bool) -> Result<()> {
    if !valid_https(url) {
        return Err("下载地址必须为 HTTPS".into());
    }
    util::safe_path(dest)?;
    let target = if proxy {
        match env::var("GH_PROXY") {
            Ok(p) if !p.is_empty() => {
                if !valid_https(&p) {
                    return Err("GH_PROXY 必须为 HTTPS 地址".into());
                }
                format!(
                    "{}{url}",
                    if p.ends_with('/') { p } else { format!("{p}/") }
                )
            }
            _ => url.into(),
        }
    } else {
        url.into()
    };
    let parent = dest.parent().ok_or("下载目标缺少目录")?;
    fs::create_dir_all(parent)?;
    let tmp = parent.join(format!(".download-{}", util::random_hex(12)?));
    let result = (|| -> Result<()> {
        if has("curl") {
            ctx.run(
                "curl",
                &[
                    "--fail",
                    "--silent",
                    "--show-error",
                    "--location",
                    "--proto",
                    "=https",
                    "--proto-redir",
                    "=https",
                    "--connect-timeout",
                    "10",
                    "--max-time",
                    "300",
                    "--retry",
                    "2",
                    "--output",
                    util::path_str(&tmp)?,
                    &target,
                ],
            )?;
        } else if has("wget") {
            ctx.run(
                "wget",
                &[
                    "--https-only",
                    "--timeout=30",
                    "--tries=3",
                    "-O",
                    util::path_str(&tmp)?,
                    &target,
                ],
            )?;
        } else {
            return Err("请先安装 curl 或 wget".into());
        }
        if fs::metadata(&tmp)?.len() == 0 {
            return Err("下载内容为空".into());
        }
        fs::rename(&tmp, dest)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(tmp);
    }
    result
}
pub fn download(ctx: &Context, url: &str, dest: &Path) -> Result<()> {
    fetch(ctx, url, dest, true)
}
pub fn github_json(ctx: &Context, url: &str) -> Result<Value> {
    if !url.starts_with("https://api.github.com/") {
        return Err("元信息必须来自 api.github.com".into());
    }
    let dir = std::env::temp_dir().join(format!("onebox-api-{}", util::random_hex(12)?));
    fs::create_dir(&dir)?;
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))?;
    let result = (|| -> Result<Value> {
        let p = dir.join("response.json");
        fetch(ctx, url, &p, false)?;
        if fs::metadata(&p)?.len() > 16 * 1024 * 1024 {
            return Err("API 响应过大".into());
        }
        Ok(serde_json::from_slice(&fs::read(p)?)?)
    })();
    let _ = fs::remove_dir_all(dir);
    result
}
pub fn version_valid(v: &str) -> bool {
    !v.is_empty()
        && v.len() < 80
        && v.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b".-_".contains(&b))
        && v.bytes().any(|b| b.is_ascii_digit())
}
pub fn architecture(ctx: &Context, core: Core) -> Result<String> {
    let raw = ctx.run("uname", &["-m"])?;
    let raw = raw.trim();
    let little = cfg!(target_endian = "little");
    let (sb, xr) = match raw {
        "x86_64" | "amd64" => ("amd64", "64"),
        "i386" | "i486" | "i586" | "i686" | "x86" => ("386", "32"),
        "aarch64" | "arm64" => ("arm64", "arm64-v8a"),
        "s390x" => ("s390x", "s390x"),
        "riscv64" => ("riscv64", "riscv64"),
        "loongarch64" | "loong64" => ("loong64", "loong64"),
        "ppc64le" => ("ppc64le", "ppc64le"),
        "ppc64" => ("", "ppc64"),
        s if s.starts_with("armv7") || s == "armv8l" => {
            let cpu = fs::read_to_string("/proc/cpuinfo").unwrap_or_default();
            if ["vfpv3", "vfpv4", "neon", "asimd"]
                .iter()
                .any(|f| cpu.contains(f))
            {
                ("armv7", "arm32-v7a")
            } else {
                ("armv6", "arm32-v6")
            }
        }
        s if s.starts_with("armv6") => ("armv6", "arm32-v6"),
        s if s.starts_with("arm") => ("armv5", "arm32-v5"),
        s if s.starts_with("mips64") => {
            if little {
                ("mips64le", "mips64le")
            } else {
                ("mips64", "mips64")
            }
        }
        s if s.starts_with("mips") => {
            if little {
                ("mipsle", "mips32le")
            } else {
                ("mips", "mips32")
            }
        }
        _ => return Err(format!("不支持的架构: {raw}").into()),
    };
    let v = if core == Core::Singbox { sb } else { xr };
    if v.is_empty() {
        return Err("此内核没有对应架构发行包".into());
    }
    Ok(v.into())
}
pub fn installed_version(ctx: &Context, core: Core) -> Result<String> {
    let o = ctx.run(util::path_str(&ctx.paths.core_bin(core))?, &["version"])?;
    let n = if core == Core::Singbox { 2 } else { 1 };
    Ok(o.lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(n))
        .ok_or("无法解析内核版本")?
        .trim_start_matches('v')
        .into())
}
fn find_binary(dir: &Path, name: &str) -> Result<Option<PathBuf>> {
    for e in fs::read_dir(dir)? {
        let e = e?;
        let ty = e.file_type()?;
        if ty.is_symlink() {
            continue;
        }
        if ty.is_file() && e.file_name() == name {
            return Ok(Some(e.path()));
        }
        if ty.is_dir() {
            if let Some(p) = find_binary(&e.path(), name)? {
                return Ok(Some(p));
            }
        }
    }
    Ok(None)
}
fn checksum(data: &[u8], want: &str) -> Result<()> {
    if want.len() != 64
        || !want.bytes().all(|b| b.is_ascii_hexdigit())
        || util::sha256(data) != want.to_ascii_lowercase()
    {
        return Err("下载文件 SHA256 不匹配".into());
    }
    Ok(())
}
fn asset_digest(asset: &Value) -> Option<&str> {
    asset.get("digest")?.as_str()?.strip_prefix("sha256:")
}
/// Download and verify into `destination`; never replaces a live core itself.
pub fn prepare_core(ctx: &Context, core: Core, wanted: &str, destination: &Path) -> Result<String> {
    let offline = env::var_os(if core == Core::Singbox {
        "ONEBOX_SINGBOX_BIN"
    } else {
        "ONEBOX_XRAY_BIN"
    });
    if let Some(source) = offline {
        let source = PathBuf::from(source);
        let m = fs::metadata(&source)?;
        if !m.is_file() {
            return Err("本地内核必须是普通文件".into());
        }
        util::atomic_write(destination, &fs::read(&source)?, 0o755)?;
        let o = ctx.run(util::path_str(destination)?, &["version"])?;
        return Ok(o.lines().next().unwrap_or("").to_owned());
    }
    let repo = if core == Core::Singbox {
        "SagerNet/sing-box"
    } else {
        "XTLS/Xray-core"
    };
    let requested = if wanted.is_empty() {
        if core == Core::Xray {
            TESTED_XRAY
        } else {
            "latest"
        }
    } else {
        wanted.trim_start_matches('v')
    };
    if requested != "latest" && !version_valid(requested) {
        return Err("版本格式无效".into());
    }
    let url = if requested == "latest" {
        format!("https://api.github.com/repos/{repo}/releases/latest")
    } else {
        format!("https://api.github.com/repos/{repo}/releases/tags/v{requested}")
    };
    let release = github_json(ctx, &url).or_else(|e| {
        if requested == "latest" && core == Core::Singbox {
            github_json(
                ctx,
                &format!("https://api.github.com/repos/{repo}/releases/tags/v{FALLBACK_SINGBOX}"),
            )
        } else {
            Err(e)
        }
    })?;
    let tag = release["tag_name"].as_str().ok_or("发行信息缺少版本")?;
    let version = tag.trim_start_matches('v');
    if !version_valid(version) || release["draft"] == true {
        return Err("无效发行版本".into());
    }
    if requested != "latest" && version != requested {
        return Err("发行版本与请求不符".into());
    }
    let arch = architecture(ctx, core)?;
    let assets = release["assets"].as_array().ok_or("发行信息缺少文件")?;
    let names = if core == Core::Singbox {
        let suffixes = match arch.as_str() {
            "mips" | "mips64" => vec!["-softfloat"],
            "mipsle" => vec!["-softfloat-musl", "-softfloat", ""],
            "mips64le" => vec!["", "-softfloat"],
            "amd64" | "arm64" => vec!["-musl", "", "-glibc"],
            _ => vec!["-musl", ""],
        };
        suffixes
            .into_iter()
            .map(|suffix| format!("sing-box-{version}-linux-{arch}{suffix}.tar.gz"))
            .collect::<Vec<_>>()
    } else {
        vec![format!("Xray-linux-{arch}.zip")]
    };
    let asset = names
        .iter()
        .find_map(|name| {
            assets
                .iter()
                .find(|a| a["name"].as_str() == Some(name.as_str()))
        })
        .ok_or("找不到对应架构的内核")?;
    let name = asset["name"].as_str().ok_or("文件名无效")?;
    let url = asset["browser_download_url"]
        .as_str()
        .ok_or("下载地址缺失")?;
    if url != format!("https://github.com/{repo}/releases/download/{tag}/{name}") {
        return Err("发行文件地址不可信".into());
    }
    let dir = destination
        .parent()
        .ok_or("下载目录无效")?
        .join(format!(".core-{}", util::random_hex(12)?));
    fs::create_dir_all(&dir)?;
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))?;
    let result = (|| -> Result<String> {
        let package = dir.join(name);
        download(ctx, url, &package)?;
        let bytes = fs::read(&package)?;
        if asset["size"].as_u64() != Some(bytes.len() as u64) {
            return Err("内核包大小与发行元信息不符".into());
        }
        if let Some(sum) = asset_digest(asset) {
            checksum(&bytes, sum)?;
        } else {
            let sum_asset = assets
                .iter()
                .find(|a| {
                    a["name"]
                        .as_str()
                        .map(|n| {
                            if core == Core::Xray {
                                n == format!("{name}.dgst")
                            } else {
                                n.contains("checksums") || n == "sha256sums.txt"
                            }
                        })
                        .unwrap_or(false)
                })
                .ok_or("发行文件缺少 SHA256，拒绝安装")?;
            let sp = dir.join("checksums");
            let su = sum_asset["browser_download_url"]
                .as_str()
                .ok_or("校验文件缺少地址")?;
            if !su.starts_with(&format!(
                "https://github.com/{repo}/releases/download/{tag}/"
            )) {
                return Err("校验地址不可信".into());
            }
            fetch(ctx, su, &sp, false)?;
            let text = fs::read_to_string(sp)?;
            let want = if core == Core::Xray {
                text.lines().find_map(|l| {
                    let (k, v) = l.split_once('=')?;
                    if matches!(k.trim(), "SHA256" | "SHA2-256" | "SHA-256") {
                        Some(v.trim())
                    } else {
                        None
                    }
                })
            } else {
                text.lines().find_map(|l| {
                    let mut p = l.split_whitespace();
                    let s = p.next()?;
                    let f = p.next()?.trim_start_matches('*');
                    (f == name).then_some(s)
                })
            }
            .ok_or("校验文件未包含内核包")?;
            checksum(&bytes, want)?;
        }
        if core == Core::Singbox {
            let mut ar = tar::Archive::new(flate2::read::GzDecoder::new(bytes.as_slice()));
            for e in ar.entries()? {
                let mut e = e?;
                let p = e.path()?.into_owned();
                if p.components().any(|c| {
                    matches!(
                        c,
                        std::path::Component::ParentDir | std::path::Component::RootDir
                    )
                }) || e.header().entry_type().is_symlink()
                    || e.header().entry_type().is_hard_link()
                {
                    return Err("内核压缩包含不安全路径".into());
                }
                e.unpack_in(&dir)?;
            }
        } else {
            ensure_package(ctx, "unzip", "unzip")?;
            ctx.run(
                "unzip",
                &[
                    "-q",
                    "-j",
                    util::path_str(&package)?,
                    "xray",
                    "-d",
                    util::path_str(&dir)?,
                ],
            )?;
        }
        let binary = find_binary(&dir, core.binary())?.ok_or("压缩包未包含内核")?;
        fs::set_permissions(&binary, fs::Permissions::from_mode(0o755))?;
        ctx.run(util::path_str(&binary)?, &["version"])?;
        util::atomic_write(destination, &fs::read(binary)?, 0o755)?;
        Ok(version.into())
    })();
    let _ = fs::remove_dir_all(dir);
    result
}
pub fn ensure_cores(ctx: &Context, state: &mut State) -> Result<()> {
    for core in [Core::Singbox, Core::Xray] {
        if !state.uses(core) {
            continue;
        }
        let p = ctx.paths.core_bin(core);
        let wanted = core_version_wanted(state, core);
        if !p.is_file() {
            prepare_core(ctx, core, &wanted, &p)?;
        }
        let version = installed_version(ctx, core)?;
        if !wanted.is_empty() && wanted != "latest" && wanted.trim_start_matches('v') != version {
            eprintln!("已安装 {core} {version}；更换指定版本请执行 onebox update {core} {wanted}");
        }
        state.set(
            if core == Core::Singbox {
                "SB_VERSION"
            } else {
                "XR_VERSION"
            },
            version,
        );
    }
    Ok(())
}
fn core_version_wanted(state: &State, core: Core) -> String {
    let (key, variable) = if core == Core::Singbox {
        ("SB_VERSION_WANT", "ONEBOX_SINGBOX_VERSION")
    } else {
        ("XR_VERSION_WANT", "ONEBOX_XRAY_VERSION")
    };
    if !state.get(key).is_empty() {
        state.get(key).to_owned()
    } else {
        env::var(variable).unwrap_or_default()
    }
}
pub fn core_check(ctx: &Context, core: Core, config: &Path) -> Result<()> {
    let dir = ctx.paths.run.join("check");
    fs::create_dir_all(&dir)?;
    match core {
        Core::Singbox => {
            ctx.run(
                util::path_str(&ctx.paths.core_bin(core))?,
                &[
                    "check",
                    "-D",
                    util::path_str(&dir)?,
                    "-c",
                    util::path_str(config)?,
                ],
            )?;
        }
        Core::Xray => {
            ctx.run(
                util::path_str(&ctx.paths.core_bin(core))?,
                &["run", "-test", "-c", util::path_str(config)?],
            )?;
        }
    }
    Ok(())
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ServiceSpec {
    pub program: String,
    pub args: Vec<String>,
    pub after: Vec<String>,
    #[serde(default)]
    pub environment: Vec<(String, String)>,
}
const SERVICE_ENV_KEYS: &[&str] = &[
    "ONEBOX_DIR",
    "ONEBOX_BIN_DIR",
    "ONEBOX_LOG_DIR",
    "ONEBOX_RUN_DIR",
    "ONEBOX_SITE_ROOT",
    "ONEBOX_SYSTEMD_DIR",
    "ONEBOX_INITD_DIR",
    "ONEBOX_EXE",
    "ONEBOX_FRPS_DIR",
    "ONEBOX_FRPS_BIN_DIR",
    "ONEBOX_FRPS_WEB_VAR",
    "ONEBOX_FRPS_LOG_DIR",
    "ONEBOX_FRPS_RUN_DIR",
    "ONEBOX_INIT",
];
/// Only reconstruct explicitly managed paths. Never persist the calling
/// shell's environment (which can contain certificate/API credentials).
pub fn service_environment(ctx: &Context) -> Result<Vec<(String, String)>> {
    let paths = [
        &ctx.paths.root,
        &ctx.paths.bin,
        &ctx.paths.log,
        &ctx.paths.run,
        &ctx.paths.site_root,
        &ctx.paths.systemd,
        &ctx.paths.initd,
        &ctx.paths.executable,
        &ctx.paths.frp_root,
        &ctx.paths.frp_bin,
        &ctx.paths.frp_web,
        &ctx.paths.frp_log,
        &ctx.paths.frp_run,
    ];
    let mut environment = Vec::new();
    for (key, path) in SERVICE_ENV_KEYS.iter().zip(paths) {
        let value = util::path_str(path)?;
        quote_unit(value)?;
        environment.push(((*key).into(), value.into()));
    }
    environment.push(("ONEBOX_INIT".into(), init_system().into()));
    Ok(environment)
}
pub fn service_shell_prefix(ctx: &Context) -> Result<String> {
    Ok(format!(
        "env {}",
        service_environment(ctx)?
            .iter()
            .map(|(key, value)| format!("{key}={}", quote_shell(value)))
            .collect::<Vec<_>>()
            .join(" ")
    ))
}
fn valid_service(name: &str) -> Result<()> {
    if name.starts_with("onebox-") && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') {
        Ok(())
    } else {
        Err("服务名无效".into())
    }
}
fn valid_dependency(name: &str) -> Result<()> {
    if name == "network-online.target" || name == "nss-lookup.target" {
        Ok(())
    } else {
        valid_service(name)
    }
}
fn frp_service(name: &str) -> bool {
    matches!(name, "onebox-frps" | "onebox-frp-web")
}
pub fn service_spec_path(ctx: &Context, name: &str) -> PathBuf {
    if frp_service(name) {
        ctx.paths.frp_root.join("services")
    } else {
        ctx.paths.root.join("services")
    }
    .join(format!("{name}.json"))
}
fn run_root<'a>(ctx: &'a Context, name: &str) -> &'a Path {
    if frp_service(name) {
        &ctx.paths.frp_run
    } else {
        &ctx.paths.run
    }
}
fn log_root<'a>(ctx: &'a Context, name: &str) -> &'a Path {
    if frp_service(name) {
        &ctx.paths.frp_log
    } else {
        &ctx.paths.log
    }
}
fn log_path(ctx: &Context, name: &str) -> Option<PathBuf> {
    let mut candidates = vec![log_root(ctx, name).join(format!("{name}.log"))];
    match name {
        "onebox-sing-box" => candidates.push(ctx.paths.log.join("singbox.log")),
        "onebox-xray" => candidates.push(ctx.paths.log.join("xray.log")),
        "onebox-site" => candidates.push(ctx.paths.site().join("error.log")),
        "onebox-frps" => candidates.push(ctx.paths.frp_log.join("frps.log")),
        "onebox-frp-web" => {
            candidates.push(ctx.paths.frp_log.join("nginx.log"));
            candidates.push(ctx.paths.frp_log.join("nginx-error.log"));
            candidates.push(ctx.paths.frp_root.join("error.log"));
        }
        _ => (),
    }
    candidates
        .into_iter()
        .find(|path| path.is_file() && util::safe_path(path).is_ok())
}
fn quote_unit(s: &str) -> Result<String> {
    if s.chars().any(|c| c == '\0' || c == '\n' || c == '\r') {
        return Err("服务参数包含控制字符".into());
    }
    Ok(format!(
        "\"{}\"",
        s.replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('%', "%%")
            .replace('$', "$$")
    ))
}
fn quote_shell(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}
pub fn write_service(
    ctx: &Context,
    name: &str,
    exe: &Path,
    args: &[String],
    after: &[String],
) -> Result<()> {
    valid_service(name)?;
    for dep in after {
        valid_dependency(dep)?;
    }
    let program = util::path_str(exe)?;
    let mut argv = vec![quote_unit(program)?];
    for a in args {
        argv.push(quote_unit(a)?)
    }
    let spec = ServiceSpec {
        program: program.into(),
        args: args.into(),
        after: after.into(),
        environment: service_environment(ctx)?,
    };
    let sp = service_spec_path(ctx, name);
    util::safe_path(&sp)?;
    match init_system() {
        "systemd" => {
            let deps = after
                .iter()
                .map(|s| {
                    if s.ends_with(".target") {
                        s.clone()
                    } else {
                        format!("{s}.service")
                    }
                })
                .collect::<Vec<_>>()
                .join(" ");
            let extra = if name == "onebox-xray" {
                "RestartPreventExitStatus=23\n"
            } else {
                ""
            };
            let pre = if name == "onebox-frps" {
                format!(
                    "ExecStartPre={} frps net-apply\n",
                    quote_unit(util::path_str(&ctx.paths.executable)?)?
                )
            } else {
                String::new()
            };
            // Environment= does not expand $, unlike ExecStart=.
            let environment = spec
                .environment
                .iter()
                .map(|(key, value)| {
                    format!(
                        "Environment=\"{key}={}\"\n",
                        value
                            .replace('\\', "\\\\")
                            .replace('"', "\\\"")
                            .replace('%', "%%")
                    )
                })
                .collect::<String>();
            let unit=format!("[Unit]\nDescription=Onebox {name}\nAfter=network-online.target nss-lookup.target {deps}\nWants=network-online.target {deps}\n[Service]\nType=simple\n{environment}{pre}ExecStart={}\nRestart=on-failure\nRestartSec=5s\nLimitNOFILE=1048576\n{extra}[Install]\nWantedBy=multi-user.target\n",argv.join(" "));
            util::atomic_write(
                &ctx.paths.systemd.join(format!("{name}.service")),
                unit.as_bytes(),
                0o644,
            )?;
            ctx.run("systemctl", &["daemon-reload"])?;
        }
        "openrc" => {
            let command_args = args
                .iter()
                .map(|s| quote_shell(s))
                .collect::<Vec<_>>()
                .join(" ");
            let log = log_root(ctx, name).join(format!("{name}.log"));
            fs::create_dir_all(log_root(ctx, name))?;
            let unit=format!("#!/sbin/openrc-run\nname={}\nsupervisor=supervise-daemon\ncommand={}\ncommand_args={}\noutput_log={}\nerror_log={}\nrespawn_delay=5\nrespawn_max=10\nrespawn_period=120\nrc_ulimit='-n 65535'\ndepend() {{ want net; after net firewall dns {}; }}\n",quote_shell(name),quote_shell(program),quote_shell(&command_args),quote_shell(util::path_str(&log)?),quote_shell(util::path_str(&log)?),after.iter().filter(|s|s.starts_with("onebox-")).cloned().collect::<Vec<_>>().join(" "));
            let unit = if name == "onebox-frps" {
                format!(
                    "{unit}start_pre() {{ {} frps net-apply; }}\n",
                    quote_shell(util::path_str(&ctx.paths.executable)?)
                )
            } else {
                unit
            };
            let environment = spec
                .environment
                .iter()
                .map(|(key, value)| format!("export {key}={}\n", quote_shell(value)))
                .collect::<String>();
            let unit = unit.replacen(
                "#!/sbin/openrc-run\n",
                &format!("#!/sbin/openrc-run\n{environment}"),
                1,
            );
            util::atomic_write(&ctx.paths.initd.join(name), unit.as_bytes(), 0o755)?;
        }
        _ => {}
    }
    util::atomic_write(&sp, &serde_json::to_vec_pretty(&spec)?, 0o600)
}
fn load_spec(ctx: &Context, name: &str) -> Result<ServiceSpec> {
    valid_service(name)?;
    let path = service_spec_path(ctx, name);
    util::safe_path(&path)?;
    let spec = match fs::read(&path) {
        Ok(bytes) => serde_json::from_slice(&bytes)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => legacy_spec(ctx, name)?,
        Err(error) => return Err(error.into()),
    };
    validate_spec(&spec)?;
    Ok(spec)
}
fn validate_spec(spec: &ServiceSpec) -> Result<()> {
    if !Path::new(&spec.program).is_absolute() {
        return Err("服务程序必须是绝对路径".into());
    }
    quote_unit(&spec.program)?;
    for arg in &spec.args {
        quote_unit(arg)?;
    }
    for dependency in &spec.after {
        valid_dependency(dependency)?;
    }
    let mut seen = std::collections::BTreeSet::new();
    for (key, value) in &spec.environment {
        if !SERVICE_ENV_KEYS.contains(&key.as_str()) || !seen.insert(key) {
            return Err("服务环境变量不在路径白名单或重复".into());
        }
        quote_unit(value)?;
        if key == "ONEBOX_INIT" && !matches!(value.as_str(), "none" | "systemd" | "openrc") {
            return Err("服务 init 环境值无效".into());
        }
    }
    Ok(())
}
fn service_core(name: &str) -> Option<Core> {
    match name {
        "onebox-sing-box" => Some(Core::Singbox),
        "onebox-xray" => Some(Core::Xray),
        _ => None,
    }
}
fn owned_config(ctx: &Context, name: &str) -> Option<PathBuf> {
    if let Some(core) = service_core(name) {
        return Some(ctx.paths.core_config(core));
    }
    match name {
        "onebox-site" => Some(ctx.paths.site().join("nginx.conf")),
        "onebox-frps" => Some(ctx.paths.frp_root.join("frps.toml")),
        "onebox-frp-web" => Some(ctx.paths.frp_root.join("nginx.conf")),
        _ => None,
    }
}
fn legacy_spec(ctx: &Context, name: &str) -> Result<ServiceSpec> {
    let config = owned_config(ctx, name).ok_or("服务尚未配置")?;
    util::safe_path(&config)?;
    if !config.is_file() {
        return Err("历史服务配置不存在".into());
    }
    let (program, args) = if let Some(core) = service_core(name) {
        let mut args = vec!["run".into()];
        if core == Core::Singbox {
            args.push("--disable-color".into());
        }
        args.extend(["-c".into(), util::path_str(&config)?.into()]);
        (ctx.paths.core_bin(core), args)
    } else if name == "onebox-frps" {
        if !ctx.paths.frp_root.join(".managed").is_file() {
            return Err("FRP 历史配置缺少管理标记".into());
        }
        (
            ctx.paths.frp_bin.join("frps"),
            vec!["-c".into(), util::path_str(&config)?.into()],
        )
    } else {
        let prefix = if name == "onebox-site" {
            let prefix = ctx.paths.site();
            if !prefix.join(".onebox-site-owned").is_file() {
                return Err("网站历史配置缺少管理标记".into());
            }
            prefix
        } else {
            if !ctx.paths.frp_root.join(".managed").is_file() {
                return Err("FRP 历史配置缺少管理标记".into());
            }
            ctx.paths.frp_root.clone()
        };
        // Discovery must stay read-only: do not call site::nginx, which may
        // install nginx or stop a distribution service as part of setup.
        let program = env::var_os("ONEBOX_NGINX_BIN")
            .map(PathBuf::from)
            .or_else(|| {
                env::split_paths(&env::var_os("PATH").unwrap_or_default())
                    .map(|p| p.join("nginx"))
                    .find(|p| p.is_absolute() && p.is_file())
            })
            .ok_or("找不到历史网站使用的 nginx 程序")?;
        (
            program,
            vec![
                "-p".into(),
                util::path_str(&prefix)?.into(),
                "-c".into(),
                util::path_str(&config)?.into(),
                "-g".into(),
                "daemon off;".into(),
            ],
        )
    };
    Ok(ServiceSpec {
        program: util::path_str(&program)?.into(),
        args,
        after: vec![],
        environment: service_environment(ctx)?,
    })
}
/// A legacy no-init installation has no ServiceSpec or unit files yet. Its
/// fixed core binary/configuration pair still represents an installed service.
pub fn exists(ctx: &Context, name: &str) -> bool {
    if valid_service(name).is_err() {
        return false;
    }
    let spec = service_spec_path(ctx, name);
    if spec.is_file() && load_spec(ctx, name).is_ok() {
        return true;
    }
    if [
        ctx.paths.systemd.join(format!("{name}.service")),
        ctx.paths.initd.join(name),
    ]
    .iter()
    .any(|path| util::safe_path(path).is_ok() && path.is_file())
    {
        return true;
    }
    if init_system() != "none" {
        return false;
    }
    if let Some(core) = service_core(name) {
        let binary = ctx.paths.core_bin(core);
        let config = ctx.paths.core_config(core);
        if util::safe_path(&binary).is_ok()
            && util::safe_path(&config).is_ok()
            && binary.is_file()
            && config.is_file()
        {
            return true;
        }
    }
    pid_matches(ctx, name).is_some()
}
fn pid_paths(ctx: &Context, name: &str) -> Vec<PathBuf> {
    let mut paths = vec![run_root(ctx, name).join(format!("{name}.pid"))];
    match name {
        "onebox-site" => paths.push(ctx.paths.site().join("nginx.pid")),
        "onebox-frps" => paths.push(ctx.paths.frp_run.join("frps.pid")),
        "onebox-frp-web" => paths.push(ctx.paths.frp_root.join("nginx.pid")),
        _ => (),
    }
    paths
}
#[derive(Serialize, Deserialize)]
struct PidRecord {
    pid: i32,
    start: u64,
}
fn process_start(pid: i32) -> Option<u64> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let mut fields = stat.rsplit_once(')')?.1.split_whitespace();
    if matches!(fields.next()?, "Z" | "X" | "x") {
        return None;
    }
    fields.nth(18)?.parse().ok()
}
fn process_executable_matches(pid: i32, program: &Path) -> bool {
    let Ok(executable) = fs::read_link(format!("/proc/{pid}/exe")) else {
        return false;
    };
    // Atomic binary replacement leaves the running executable marked deleted.
    // Canonicalize its directory even if the old binary is temporarily absent.
    let expected = fs::canonicalize(program).ok().or_else(|| {
        Some(
            program
                .parent()?
                .canonicalize()
                .ok()?
                .join(program.file_name()?),
        )
    });
    expected.is_some_and(|expected| {
        Path::new(executable.to_string_lossy().trim_end_matches(" (deleted)")) == expected
    })
}
fn owned_command_matches(ctx: &Context, name: &str, spec: &ServiceSpec, cmdline: &[u8]) -> bool {
    let args = cmdline
        .split(|byte| *byte == 0)
        .filter(|arg| !arg.is_empty())
        .collect::<Vec<_>>();
    if service_core(name).is_some() && args.get(1).copied() != Some(&b"run"[..]) {
        return false;
    }
    let Some(config) = owned_config(ctx, name) else {
        return args.len() == spec.args.len() + 1
            && args
                .iter()
                .skip(1)
                .zip(&spec.args)
                .all(|(actual, expected)| *actual == expected.as_bytes());
    };
    let Ok(config) = util::path_str(&config) else {
        return false;
    };
    let mut found = false;
    for (index, argument) in args.iter().enumerate() {
        if matches!(*argument, b"-c" | b"--config" | b"-config") {
            if args.get(index + 1).copied() != Some(config.as_bytes()) {
                return false;
            }
            found = true;
        }
        if argument.starts_with(b"--config=") || argument.starts_with(b"-config=") {
            let Some(index) = argument.iter().position(|byte| *byte == b'=') else {
                return false;
            };
            let value = &argument[index + 1..];
            if value != config.as_bytes() {
                return false;
            }
            found = true;
        }
    }
    if found {
        return true;
    }
    if !matches!(name, "onebox-site" | "onebox-frp-web") || args.len() != 1 {
        return false;
    }
    // nginx rewrites argv into a single process title. Match a complete known
    // invocation, never a substring that could belong to a different website.
    let Some(prefix) = Path::new(config).parent().and_then(Path::to_str) else {
        return false;
    };
    for trailing_slash in ["", "/"] {
        for foreground in ["", " -g daemon off;"] {
            let expected = format!(
                "nginx: master process {} -p {prefix}{trailing_slash} -c {config}{foreground}",
                spec.program
            );
            if args[0] == expected.as_bytes() {
                return true;
            }
        }
    }
    false
}
fn matching_pid(ctx: &Context, name: &str, path: &Path) -> Option<PidRecord> {
    util::safe_path(path).ok()?;
    let raw = fs::read_to_string(path).ok()?;
    let spec = load_spec(ctx, name).ok()?;
    let record: PidRecord = match serde_json::from_str(&raw) {
        Ok(record) => record,
        Err(_) => {
            // v1 PID files contain a bare number. Adopt only the matching executable
            // and its own configuration, never an unrelated nginx with a reused PID.
            let pid = raw.trim().parse::<i32>().ok()?;
            if pid < 2 {
                return None;
            }
            PidRecord {
                pid,
                start: process_start(pid)?,
            }
        }
    };
    if record.pid < 2
        || process_start(record.pid) != Some(record.start)
        || !process_executable_matches(record.pid, Path::new(&spec.program))
        || !owned_command_matches(
            ctx,
            name,
            &spec,
            &fs::read(format!("/proc/{}/cmdline", record.pid)).ok()?,
        )
    {
        return None;
    }
    if unsafe { libc::kill(record.pid, 0) } == 0 {
        Some(record)
    } else {
        None
    }
}
fn pid_matches(ctx: &Context, name: &str) -> Option<i32> {
    pid_paths(ctx, name)
        .iter()
        .find_map(|path| matching_pid(ctx, name, path).map(|record| record.pid))
}
fn terminate_record(pid: i32, start: u64) -> Result<()> {
    if process_start(pid) != Some(start) {
        let _ = unsafe { libc::waitpid(pid, std::ptr::null_mut(), libc::WNOHANG) };
        return Ok(());
    }
    for signal in [libc::SIGTERM, libc::SIGKILL] {
        if unsafe { libc::kill(pid, signal) } != 0
            && std::io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH)
        {
            return Err(std::io::Error::last_os_error().into());
        }
        for _ in 0..50 {
            if process_start(pid) != Some(start) {
                let _ = unsafe { libc::waitpid(pid, std::ptr::null_mut(), libc::WNOHANG) };
                return Ok(());
            }
            let _ = unsafe { libc::waitpid(pid, std::ptr::null_mut(), libc::WNOHANG) };
            thread::sleep(Duration::from_millis(100));
        }
    }
    Err("后台服务未能退出，已保留 PID 记录".into())
}
pub fn running(ctx: &Context, name: &str) -> bool {
    if valid_service(name).is_err() {
        return false;
    }
    match init_system() {
        "systemd" => ctx
            .output("systemctl", &["is-active", "--quiet", name])
            .map(|o| o.success())
            .unwrap_or(false),
        "openrc" => {
            if !ctx
                .output("rc-service", &[name, "status"])
                .map(|o| o.success())
                .unwrap_or(false)
            {
                return false;
            }
            let path = PathBuf::from("/run/openrc/options")
                .join(name)
                .join("child_pid");
            if let Ok(pid) = fs::read_to_string(path) {
                pid.trim()
                    .parse::<i32>()
                    .ok()
                    .filter(|p| *p > 1 && unsafe { libc::kill(*p, 0) } == 0)
                    .is_some()
            } else {
                true
            }
        }
        _ => pid_matches(ctx, name).is_some(),
    }
}
fn cron_update(ctx: &Context, name: &str, enable: bool) -> Result<()> {
    if !has("crontab") {
        if enable {
            eprintln!("未找到 init 或 crontab；服务不会开机自启，重启后请执行 onebox net-apply && onebox start");
        }
        return Ok(());
    }
    let old = ctx.output("crontab", &["-l"])?;
    if !old.success() && !old.stderr.to_lowercase().contains("no crontab") {
        return Err("无法读取 crontab，未更改自启任务".into());
    }
    let marker = format!("# onebox-rust:{name}");
    let mut lines = old
        .stdout
        .lines()
        .filter(|l| !l.ends_with(&marker))
        .map(str::to_owned)
        .collect::<Vec<_>>();
    if enable {
        lines.push(format!(
            "@reboot {} {} service {name} start >/dev/null 2>&1 {marker}",
            service_shell_prefix(ctx)?,
            quote_shell(util::path_str(&ctx.paths.executable)?)
        ));
    }
    fs::create_dir_all(run_root(ctx, name))?;
    let tmp = run_root(ctx, name).join(format!(".cron-{}", util::random_hex(8)?));
    util::atomic_write(&tmp, format!("{}\n", lines.join("\n")).as_bytes(), 0o600)?;
    let result = ctx.run("crontab", &[util::path_str(&tmp)?]).map(|_| ());
    let _ = fs::remove_file(tmp);
    result
}
pub fn service(ctx: &Context, name: &str, action: &str) -> Result<()> {
    valid_service(name)?;
    if !matches!(
        action,
        "start"
            | "stop"
            | "restart"
            | "enable"
            | "disable"
            | "remove"
            | "reload"
            | "status"
            | "log"
    ) {
        return Err("未知服务操作".into());
    }
    if action == "log" {
        if init_system() == "systemd" {
            print!(
                "{}",
                ctx.run("journalctl", &["--no-pager", "-n", "200", "-u", name])?
            );
        } else {
            let path = log_path(ctx, name).ok_or("服务日志尚不存在")?;
            print!(
                "{}",
                ctx.run("tail", &["-n", "200", "--", util::path_str(&path)?])?
            );
        }
        return Ok(());
    }
    if action == "status" {
        println!(
            "{name}: {}",
            if running(ctx, name) {
                "运行中"
            } else {
                "已停止"
            }
        );
        return Ok(());
    }
    if action == "remove" {
        if !exists(ctx, name) {
            return Ok(());
        }
        service(ctx, name, "stop")?;
        service(ctx, name, "disable")?;
        for p in [
            service_spec_path(ctx, name),
            ctx.paths.systemd.join(format!("{name}.service")),
            ctx.paths.initd.join(name),
        ] {
            if p.exists() {
                fs::remove_file(p)?;
            }
        }
        if init_system() == "systemd" {
            ctx.run("systemctl", &["daemon-reload"])?;
        }
        return Ok(());
    }
    match init_system() {
        "systemd" => {
            ctx.run("systemctl", &[action, name])?;
        }
        "openrc" => {
            if matches!(action, "enable" | "disable") {
                if action == "disable" {
                    let enabled = ctx.run("rc-update", &["show", "default"])?;
                    if !enabled
                        .lines()
                        .any(|line| line.split_whitespace().next() == Some(name))
                    {
                        return Ok(());
                    }
                }
                ctx.run(
                    "rc-update",
                    &[
                        if action == "enable" { "add" } else { "del" },
                        name,
                        "default",
                    ],
                )?;
            } else {
                ctx.run("rc-service", &[name, action])?;
            }
        }
        _ => {
            if matches!(action, "enable" | "disable") {
                return cron_update(ctx, name, action == "enable");
            }
            if matches!(action, "stop" | "restart" | "reload") {
                for pf in pid_paths(ctx, name) {
                    if let Some(record) = matching_pid(ctx, name, &pf) {
                        terminate_record(record.pid, record.start)?;
                    }
                    if pf.exists() {
                        util::safe_path(&pf)?;
                        fs::remove_file(pf)?;
                    }
                }
            }
            if matches!(action, "start" | "restart" | "reload") && !running(ctx, name) {
                let spec = load_spec(ctx, name)?;
                if name == "onebox-frps" {
                    ctx.run(
                        util::path_str(&ctx.paths.executable)?,
                        &["frps", "net-apply"],
                    )?;
                }
                fs::create_dir_all(run_root(ctx, name))?;
                fs::create_dir_all(log_root(ctx, name))?;
                let log = log_root(ctx, name).join(format!("{name}.log"));
                let environment = if spec.environment.is_empty() {
                    service_environment(ctx)?
                } else {
                    spec.environment.clone()
                };
                let pid = ctx.spawn_with_env(&spec.program, &spec.args, &log, &environment)? as i32;
                let start = process_start(pid).ok_or("启动的后台进程已退出")?;
                let record = PidRecord { pid, start };
                if let Err(e) = util::atomic_write(
                    &run_root(ctx, name).join(format!("{name}.pid")),
                    &serde_json::to_vec(&record)?,
                    0o600,
                ) {
                    terminate_record(pid, start)?;
                    return Err(e);
                }
            }
        }
    }
    Ok(())
}
pub fn configure_services(ctx: &Context, state: &State) -> Result<()> {
    for core in [Core::Singbox, Core::Xray] {
        if state.uses(core) {
            let args = if core == Core::Singbox {
                vec![
                    "run".into(),
                    "--disable-color".into(),
                    "-c".into(),
                    util::path_str(&ctx.paths.core_config(core))?.into(),
                ]
            } else {
                vec![
                    "run".into(),
                    "-c".into(),
                    util::path_str(&ctx.paths.core_config(core))?.into(),
                ]
            };
            let after = if state.site_enabled() {
                vec!["onebox-site".into()]
            } else {
                vec![]
            };
            write_service(
                ctx,
                core.service(),
                &ctx.paths.core_bin(core),
                &args,
                &after,
            )?;
            service(ctx, core.service(), "enable")?;
        } else {
            service(ctx, core.service(), "remove")?;
        }
    }
    Ok(())
}
pub fn wait_running(ctx: &Context, name: &str) -> Result<()> {
    for _ in 0..20 {
        if running(ctx, name) {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(100));
    }
    Err(format!("{name} 未能正常运行").into())
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Fixture {
        root: PathBuf,
        ctx: Context,
    }
    impl Fixture {
        fn new() -> Self {
            let root =
                env::temp_dir().join(format!("onebox-platform-{}", util::random_hex(10).unwrap()));
            let ctx = Context {
                paths: crate::context::Paths::isolated(&root),
                ..Context::default()
            };
            for path in [
                &ctx.paths.root,
                &ctx.paths.bin,
                &ctx.paths.run,
                &ctx.paths.log,
            ] {
                fs::create_dir_all(path).unwrap();
            }
            Self { root, ctx }
        }
        fn core(&self, core: Core) {
            fs::write(self.ctx.paths.core_bin(core), b"fixture executable").unwrap();
            fs::write(self.ctx.paths.core_config(core), b"{}").unwrap();
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }
    struct Child(std::process::Child);
    impl Drop for Child {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    fn spawn_ready(command: &mut std::process::Command) -> Child {
        use std::io::Read;
        use std::os::fd::AsRawFd;
        let mut child = Child(
            command
                .stdout(std::process::Stdio::piped())
                .spawn()
                .unwrap(),
        );
        let mut stdout = child.0.stdout.take().unwrap();
        let mut descriptor = libc::pollfd {
            fd: stdout.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let ready = loop {
            let result = unsafe { libc::poll(&mut descriptor, 1, 5000) };
            if result >= 0
                || std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted
            {
                break result;
            }
        };
        assert!(
            ready > 0,
            "fixture did not acknowledge userspace startup: {:?}",
            child.0.try_wait()
        );
        let mut acknowledgement = [0];
        stdout
            .read_exact(&mut acknowledgement)
            .expect("fixture exited before readiness acknowledgement");
        assert_eq!(acknowledgement, [b'R']);
        child
    }
    fn cmdline(args: &[&str]) -> Vec<u8> {
        let mut result = Vec::new();
        for arg in args {
            result.extend_from_slice(arg.as_bytes());
            result.push(0);
        }
        result
    }
    fn visible_proc_namespace() -> bool {
        let pid = std::process::id();
        let visible = fs::read_to_string("/proc/self/stat")
            .ok()
            .and_then(|stat| stat.split_whitespace().next()?.parse::<u32>().ok())
            == Some(pid);
        if !visible {
            eprintln!(
                "SKIP real-process assertions: /proc is mounted from a different PID namespace"
            );
        }
        visible
    }
    #[test]
    fn legacy_core_specs_are_inferred_without_writes() {
        let f = Fixture::new();
        for core in [Core::Singbox, Core::Xray] {
            assert!(!exists(&f.ctx, core.service()));
            f.core(core);
            let spec = load_spec(&f.ctx, core.service()).unwrap();
            assert_eq!(Path::new(&spec.program), f.ctx.paths.core_bin(core));
            assert_eq!(
                spec.args.last().unwrap(),
                f.ctx.paths.core_config(core).to_str().unwrap()
            );
            assert_eq!(exists(&f.ctx, core.service()), init_system() == "none");
            assert!(!service_spec_path(&f.ctx, core.service()).exists());
        }
        let spec_path = service_spec_path(&f.ctx, Core::Singbox.service());
        fs::create_dir_all(spec_path.parent().unwrap()).unwrap();
        fs::write(spec_path, b"invalid JSON").unwrap();
        assert!(load_spec(&f.ctx, Core::Singbox.service()).is_err());
        assert!(!exists(&f.ctx, "../../other"));
        assert!(!exists(&f.ctx, "onebox-unknown"));
    }
    #[test]
    fn process_arguments_require_exact_owned_config() {
        let f = Fixture::new();
        f.core(Core::Singbox);
        let name = Core::Singbox.service();
        let spec = load_spec(&f.ctx, name).unwrap();
        let config = f.ctx.paths.core_config(Core::Singbox);
        let config = config.to_str().unwrap();
        assert!(owned_command_matches(
            &f.ctx,
            name,
            &spec,
            &cmdline(&[&spec.program, "run", "-c", config])
        ));
        for args in [
            vec![spec.program.as_str(), "run", "--note", config],
            vec![
                spec.program.as_str(),
                "run",
                "-c",
                "different.json",
                "--note",
                config,
            ],
            vec![
                spec.program.as_str(),
                "run",
                "-c",
                config,
                "--config",
                "different.json",
            ],
        ] {
            assert!(!owned_command_matches(&f.ctx, name, &spec, &cmdline(&args)));
        }
        let sibling = format!("{config}.other");
        assert!(!owned_command_matches(
            &f.ctx,
            name,
            &spec,
            &cmdline(&[&spec.program, "run", "-c", &sibling])
        ));

        let nginx = ServiceSpec {
            program: "/usr/sbin/nginx".into(),
            args: vec![],
            after: vec![],
            environment: vec![],
        };
        let prefix = f.ctx.paths.site();
        let config = prefix.join("nginx.conf");
        let title = format!(
            "nginx: master process /usr/sbin/nginx -p {}/ -c {}",
            prefix.display(),
            config.display()
        );
        assert!(owned_command_matches(
            &f.ctx,
            "onebox-site",
            &nginx,
            &cmdline(&[&title])
        ));
        assert!(!owned_command_matches(
            &f.ctx,
            "onebox-site",
            &nginx,
            &cmdline(&[&format!("{title}.other")])
        ));
        assert!(!owned_command_matches(
            &f.ctx,
            "onebox-frp-web",
            &nginx,
            &cmdline(&[&title])
        ));
    }
    #[test]
    fn legacy_pid_checks_executable_config_start_time_and_deleted_inode() {
        let visible = visible_proc_namespace();
        let f = Fixture::new();
        let core = Core::Singbox;
        fs::write(f.ctx.paths.core_config(core), b"{}").unwrap();
        // A tiny native test process accepts the same argv as a core, without
        // downloading a core or listening on any host port. Tests run via cargo,
        // so this uses the existing Rust compiler, never an installed service.
        let source = f.root.join("process.rs");
        fs::write(
            &source,
            "use std::io::Write; fn main() { std::io::stdout().write_all(b\"R\").unwrap(); std::io::stdout().flush().unwrap(); loop { std::thread::sleep(std::time::Duration::from_secs(60)); } }",
        )
        .unwrap();
        let compiler = env::var_os("RUSTC").unwrap_or_else(|| "rustc".into());
        let built = std::process::Command::new(&compiler)
            .arg(&source)
            .arg("--crate-name")
            .arg("onebox_process_fixture")
            .arg("-o")
            .arg(f.ctx.paths.core_bin(core))
            .output()
            .unwrap_or_else(|error| {
                panic!(
                    "could not launch Rust compiler {compiler:?}: {error}; direct test-binary execution must preserve RUSTC or the toolchain PATH"
                )
            });
        assert!(
            built.status.success(),
            "{}",
            String::from_utf8_lossy(&built.stderr)
        );
        let binary = f.ctx.paths.core_bin(core);
        let config = f.ctx.paths.core_config(core);
        // spawn() synchronizes exec's close-on-exec pipe, not execution of
        // main(). Reading proc argv/exe in that window can observe the kernel's
        // still-incomplete exec state. A userspace acknowledgement establishes
        // readiness before both positive and negative identity assertions.
        let own = spawn_ready(
            std::process::Command::new(&binary)
                .args(["run", "--disable-color", "-c"])
                .arg(&config),
        );
        if !visible {
            return;
        }
        let own_pid = own.0.id() as i32;
        let start = process_start(own_pid).unwrap();
        let pf = f.ctx.paths.run.join(format!("{}.pid", core.service()));
        fs::write(&pf, own_pid.to_string()).unwrap();
        assert_eq!(pid_matches(&f.ctx, core.service()), Some(own_pid));

        fs::write(
            &pf,
            serde_json::to_vec(&PidRecord {
                pid: own_pid,
                start: start + 1,
            })
            .unwrap(),
        )
        .unwrap();
        assert_eq!(pid_matches(&f.ctx, core.service()), None);
        fs::write(
            &pf,
            serde_json::to_vec(&PidRecord {
                pid: own_pid,
                start,
            })
            .unwrap(),
        )
        .unwrap();
        assert_eq!(pid_matches(&f.ctx, core.service()), Some(own_pid));

        let mut other_config = spawn_ready(
            std::process::Command::new(&binary)
                .args(["run", "-c"])
                .arg(format!("{}.other", config.display())),
        );
        fs::write(&pf, other_config.0.id().to_string()).unwrap();
        assert_eq!(pid_matches(&f.ctx, core.service()), None);
        assert!(other_config.0.try_wait().unwrap().is_none());

        let different = f.root.join("different-program");
        fs::copy(&binary, &different).unwrap();
        let mut other_exe = spawn_ready(
            std::process::Command::new(&different)
                .args(["run", "-c"])
                .arg(&config),
        );
        fs::write(&pf, other_exe.0.id().to_string()).unwrap();
        assert_eq!(pid_matches(&f.ctx, core.service()), None);
        assert!(other_exe.0.try_wait().unwrap().is_none());

        fs::write(&pf, own_pid.to_string()).unwrap();
        fs::remove_file(&binary).unwrap();
        assert_eq!(pid_matches(&f.ctx, core.service()), Some(own_pid));
        // Only no-init service discovery adopts a verified legacy PID.
        assert_eq!(exists(&f.ctx, core.service()), init_system() == "none");
        terminate_record(own_pid, start).unwrap();
        assert!(process_start(own_pid).is_none());
        assert!(other_config.0.try_wait().unwrap().is_none());
        assert!(other_exe.0.try_wait().unwrap().is_none());
    }
    #[test]
    fn zombie_process_is_not_running() {
        if !visible_proc_namespace() {
            return;
        }
        let mut child = Child(std::process::Command::new("/bin/true").spawn().unwrap());
        let pid = child.0.id() as i32;
        for _ in 0..100 {
            let stat = fs::read_to_string(format!("/proc/{pid}/stat")).unwrap_or_default();
            if stat
                .rsplit_once(')')
                .is_some_and(|(_, tail)| tail.split_whitespace().next() == Some("Z"))
            {
                assert!(process_start(pid).is_none());
                child.0.wait().unwrap();
                return;
            }
            thread::sleep(Duration::from_millis(2));
        }
        panic!("test child did not exit");
    }
    #[test]
    fn logs_fall_back_to_legacy_paths_and_prefer_native_file() {
        let f = Fixture::new();
        for (name, legacy) in [
            ("onebox-sing-box", "singbox.log"),
            ("onebox-xray", "xray.log"),
        ] {
            let old = f.ctx.paths.log.join(legacy);
            fs::write(&old, "old log").unwrap();
            assert_eq!(log_path(&f.ctx, name), Some(old));
            let current = f.ctx.paths.log.join(format!("{name}.log"));
            fs::write(&current, "new log").unwrap();
            assert_eq!(log_path(&f.ctx, name), Some(current));
        }
    }
    #[test]
    fn checksum_fails_closed() {
        assert!(checksum(b"x", &util::sha256(b"x")).is_ok());
        assert!(checksum(b"x", &util::sha256(b"y")).is_err());
    }
    #[test]
    fn unsafe_service_args_rejected() {
        assert!(quote_unit("x\nExecStart=/bad").is_err());
        assert_eq!(quote_unit("100% a").unwrap(), "\"100%% a\"");
        assert!(valid_service("onebox-x;id").is_err());
    }
    #[test]
    fn version_cannot_be_path() {
        assert!(!version_valid("../../x"));
        assert!(!version_valid("1.0;id"));
        assert!(version_valid("1.14.2"));
    }
    #[test]
    fn explicit_core_versions_survive_cli_state_transfer() {
        let mut state = State::default();
        state.set("SB_VERSION_WANT", "1.14.2");
        state.set("XR_VERSION_WANT", "26.3.27");
        assert_eq!(core_version_wanted(&state, Core::Singbox), "1.14.2");
        assert_eq!(core_version_wanted(&state, Core::Xray), "26.3.27");
    }
    #[test]
    fn service_environment_persists_only_named_paths_and_init() {
        let f = Fixture::new();
        let environment = service_environment(&f.ctx).unwrap();
        assert_eq!(environment.len(), SERVICE_ENV_KEYS.len());
        assert!(
            environment
                .iter()
                .any(|(key, value)| key == "ONEBOX_DIR"
                    && value == f.ctx.paths.root.to_str().unwrap())
        );
        assert!(environment
            .iter()
            .all(|(key, _)| SERVICE_ENV_KEYS.contains(&key.as_str())));
        let mut spec = ServiceSpec {
            program: "/usr/bin/onebox".into(),
            args: vec![],
            after: vec![],
            environment,
        };
        assert!(validate_spec(&spec).is_ok());
        for key in ["CF_Token", "GH_TOKEN", "ONEBOX_PASSWORD", "PATH"] {
            spec.environment
                .push((key.into(), "not-a-managed-path".into()));
            assert!(
                validate_spec(&spec).is_err(),
                "{key} must never be accepted into a service environment"
            );
            spec.environment.pop();
        }
        let prefix = service_shell_prefix(&f.ctx).unwrap();
        assert!(prefix.starts_with("env ONEBOX_DIR="));
        assert!(!prefix.contains("CF_Token") && !prefix.contains("GH_TOKEN"));
    }
}
