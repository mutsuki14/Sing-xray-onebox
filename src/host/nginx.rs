//! nginx discovery and installation, distro service neutralization, config
//! tests, reload, version-dependent syntax and the worker account.
//!
//! Onebox never uses the distro nginx *service*: every Onebox nginx
//! (`onebox-site`, `onebox-subscription-web`, `onebox-frp-web`) is a private
//! instance with its own prefix and config. Only the binary is shared.
//!
//! Distro service rule (fixes H-8.1#2, where the FRP path left the package's
//! nginx running on port 80): the distro `nginx` service is stopped and
//! disabled
//! 1. right after Onebox installed the package (it then only serves the
//!    distribution's welcome page and would hold 80/443), or
//! 2. when nginx was already installed and the service is enabled, but the
//!    package manager confirms the distro configuration is untouched:
//!    `nginx.conf` and every entry of `sites-enabled/`, `conf.d/`,
//!    `http.d/`, `default.d/` and `vhosts.d/` (links followed) are
//!    configuration files of the package with their packaged content (dpkg
//!    conffile MD5s, or `rpm -V`). An edited default site (hand-made,
//!    `certbot --nginx`), any other site, or a host without dpkg/rpm
//!    (Alpine, whose OpenRC never enables nginx by itself) is left alone;
//!    its port conflicts are reported by the port planner instead.
//!
//! Neither happens with `ONEBOX_NGINX_BIN` (a private build) or without an
//! init system. Neither is part of an apply journal: both only stop a
//! service that serves the distribution's welcome page, so a rolled-back
//! apply does not start it again.
//!
//! Changes from v2:
//! - lookup is `ONEBOX_NGINX_BIN`, PATH, then `/usr/sbin/nginx` (cron's PATH
//!   lacks sbin; F-8.1#1); the override must be an executable file.
//! - the distro service rule above (v2 only disabled it after a fresh
//!   install from the site path, and a failing `systemctl` aborted); an
//!   existing nginx counts as unconfigured only when its package manager
//!   says so, never because of file names.
//! - `test` uses `-q` and returns nginx's own error lines without
//!   timestamps/PIDs.
//! - the worker account comes from the distro configuration's `user`
//!   directive (`nginx -T`) before falling back to www-data/nginx/nobody.
//! - `version()` and [`NginxVersion::supports_http2_directive`] select
//!   `http2 on;` for nginx ≥ 1.25.1 (G-8.1#20, F-8.1#23).

mod distro;

use crate::ctx::Ctx;
use crate::error::{Context, Error, Result};
use crate::host::init;
use crate::host::os::{self, process_env, EnvLookup};
use crate::host::pkg;
use crate::sys::exec::Cmd;
use std::fmt;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Environment variable naming the nginx binary to use.
pub const ENV_BIN: &str = "ONEBOX_NGINX_BIN";
/// Distro binary location checked when PATH has no `nginx`.
const SBIN_NGINX: &str = "/usr/sbin/nginx";
const TEST_TIMEOUT: Duration = Duration::from_secs(30);
/// Fallback worker accounts, in order.
const WORKER_CANDIDATES: [&str; 3] = ["www-data", "nginx", "nobody"];

/// The nginx binary (see the module docs for the lookup order).
pub fn binary(ctx: &Ctx) -> Result<PathBuf> {
    binary_with(ctx, &process_env)
}

/// [`binary`] with an injected environment lookup.
pub fn binary_with(ctx: &Ctx, env: EnvLookup) -> Result<PathBuf> {
    find(ctx, env)?.ok_or_else(|| Error::msg("找不到 nginx"))
}

/// `Ok(None)` when no nginx is installed; an invalid override is an error.
fn find(ctx: &Ctx, env: EnvLookup) -> Result<Option<PathBuf>> {
    if let Some(value) = env(ENV_BIN) {
        let path = PathBuf::from(&value);
        let executable = path.is_absolute()
            && std::fs::metadata(&path)
                .is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0);
        ensure!(executable, "{ENV_BIN} 不存在或不可执行: {value}");
        return Ok(Some(path));
    }
    Ok(ctx
        .exec
        .which("nginx")
        .or_else(|| ctx.exec.which(SBIN_NGINX)))
}

/// Make sure an nginx binary exists (installing the `nginx` package when
/// needed, root required then) and apply the distro service rule.
pub fn ensure_installed(ctx: &Ctx) -> Result<PathBuf> {
    ensure_installed_with(ctx, &process_env, os::is_root())
}

/// [`ensure_installed`] with injected environment and privilege facts.
pub fn ensure_installed_with(ctx: &Ctx, env: EnvLookup, root: bool) -> Result<PathBuf> {
    let init = init::detect_with(ctx, env);
    if let Some(bin) = find(ctx, env)? {
        if env(ENV_BIN).is_none() && distro::service_enabled(ctx, init) && distro::pristine(ctx) {
            distro::neutralize(ctx, init);
        }
        return Ok(bin);
    }
    ensure!(
        !ctx.paths.system("/etc/nginx").exists(),
        "检测到现有 nginx 配置但找不到程序，请先修复 nginx"
    );
    pkg::ensure_as(ctx, "nginx", "nginx", root)?;
    distro::neutralize(ctx, init);
    binary_with(ctx, env)
}

/// `nginx -t -q -p PREFIX -c CONF`; the error carries nginx's messages.
pub fn test(ctx: &Ctx, prefix: &Path, conf: &Path) -> Result<()> {
    let bin = binary(ctx)?;
    let cmd = Cmd::new(bin.to_string_lossy())
        .args(["-t", "-q", "-p"])
        .arg(prefix.to_string_lossy())
        .arg("-c")
        .arg(conf.to_string_lossy())
        .timeout(TEST_TIMEOUT);
    let result = ctx.run(&cmd)?;
    if result.ok() {
        return Ok(());
    }
    let detail = test_summary(&result.stderr);
    let detail = if detail.is_empty() {
        format!("退出码 {}", result.code)
    } else {
        detail
    };
    Err(Error::msg(format!("nginx 配置测试失败: {detail}")))
}

/// nginx's error lines without timestamps, PIDs and the generic
/// "test failed" trailer (at most 8 lines).
pub fn test_summary(stderr: &str) -> String {
    let lines: Vec<String> = stderr
        .lines()
        .map(clean_log_line)
        .filter(|l| !l.is_empty())
        .filter(|l| !(l.starts_with("nginx: configuration file") && l.ends_with("test failed")))
        .collect();
    lines[lines.len().saturating_sub(8)..].join("\n")
}

/// `2026/10/08 18:19:39 [emerg] 24958#24958: msg` → `[emerg] msg`.
fn clean_log_line(line: &str) -> String {
    let line = line.trim();
    let dated = line.len() > 20
        && line.as_bytes()[4] == b'/'
        && line.as_bytes()[13] == b':'
        && line.is_char_boundary(20);
    let line = if dated { &line[20..] } else { line };
    let Some((level, rest)) = line.split_once("] ") else {
        return line.to_string();
    };
    let rest = match rest.split_once(": ") {
        Some((pid, msg)) if pid.bytes().all(|b| b.is_ascii_digit() || b == b'#') => msg,
        _ => rest,
    };
    format!("{level}] {rest}")
}

/// `nginx -p PREFIX -c CONF -s reload` (signals the instance's master).
pub fn reload(ctx: &Ctx, prefix: &Path, conf: &Path) -> Result<()> {
    let bin = binary(ctx)?;
    let cmd = Cmd::new(bin.to_string_lossy())
        .arg("-p")
        .arg(prefix.to_string_lossy())
        .arg("-c")
        .arg(conf.to_string_lossy())
        .args(["-s", "reload"])
        .timeout(TEST_TIMEOUT);
    ctx.check(&cmd).map(|_| ()).context("nginx 重新加载失败")
}

/// An nginx release number.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NginxVersion {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
}

impl NginxVersion {
    /// First release where `listen … http2` is deprecated for `http2 on;`.
    pub const HTTP2_DIRECTIVE: NginxVersion = NginxVersion {
        major: 1,
        minor: 25,
        patch: 1,
    };

    /// Parse `nginx -v` output (`nginx version: nginx/1.24.0 (Ubuntu)`,
    /// `nginx version: openresty/1.21.4.3`).
    pub fn parse(text: &str) -> Option<NginxVersion> {
        let (_, rest) = text.split_once("version:")?;
        let product = rest.split_whitespace().next()?;
        let number = product.rsplit('/').next()?;
        let mut parts = number.split('.').map(|p| {
            let digits: String = p.chars().take_while(char::is_ascii_digit).collect();
            digits.parse::<u32>().ok()
        });
        Some(NginxVersion {
            major: parts.next()??,
            minor: parts.next()??,
            patch: parts.next().flatten().unwrap_or(0),
        })
    }

    /// nginx ≥ 1.25.1 uses `http2 on;`; older ones `listen … ssl http2`.
    pub fn supports_http2_directive(self) -> bool {
        self >= NginxVersion::HTTP2_DIRECTIVE
    }
}

impl fmt::Display for NginxVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

/// Free-function form of [`NginxVersion::supports_http2_directive`].
pub fn supports_http2_directive(version: NginxVersion) -> bool {
    version.supports_http2_directive()
}

/// The installed nginx version (`nginx -v`, printed on stderr).
pub fn version(ctx: &Ctx) -> Result<NginxVersion> {
    let bin = binary(ctx)?;
    let out = ctx.run(
        &Cmd::new(bin.to_string_lossy())
            .arg("-v")
            .timeout(TEST_TIMEOUT),
    )?;
    let text = format!("{}\n{}", out.stderr, out.stdout);
    NginxVersion::parse(&text)
        .filter(|_| out.ok())
        .ok_or_else(|| Error::msg("无法识别 nginx 版本"))
}

/// The unprivileged account nginx workers run as.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Worker {
    pub user: String,
    pub group: String,
}

impl fmt::Display for Worker {
    /// `user group` — the operand of nginx's `user` directive.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.user, self.group)
    }
}

/// The worker account: the distro configuration's `user` directive (from
/// `nginx -T`), else the first existing of www-data, nginx, nobody. Root is
/// never accepted.
pub fn worker(ctx: &Ctx) -> Result<Worker> {
    let configured = binary(ctx).ok().and_then(|bin| {
        let dump = Cmd::new(bin.to_string_lossy())
            .args(["-T", "-q"])
            .timeout(TEST_TIMEOUT);
        let out = ctx.run(&dump).ok().filter(|o| o.ok())?;
        parse_user_directive(&out.stdout)
    });
    let mut candidates: Vec<(String, Option<String>)> = Vec::new();
    if let Some((user, group)) = configured.filter(|(u, _)| u != "root") {
        candidates.push((user, group));
    }
    candidates.extend(WORKER_CANDIDATES.iter().map(|u| (u.to_string(), None)));
    for (user, group) in candidates {
        if !account_exists(ctx, &user) {
            continue;
        }
        let group = match group {
            Some(g) => g,
            None => primary_group(ctx, &user)?,
        };
        ensure!(valid_account(&group), "nginx 工作账号的组名无效");
        return Ok(Worker { user, group });
    }
    Err(Error::msg("缺少 nginx 非 root 工作账号"))
}

/// The worker account's group (for file ownership of served content).
pub fn worker_group(ctx: &Ctx) -> Result<String> {
    Ok(worker(ctx)?.group)
}

fn account_exists(ctx: &Ctx, user: &str) -> bool {
    ctx.run(&Cmd::new("id").args(["-u", user]).timeout(TEST_TIMEOUT))
        .is_ok_and(|o| o.ok())
}

fn primary_group(ctx: &Ctx, user: &str) -> Result<String> {
    let out = ctx.check(&Cmd::new("id").args(["-gn", user]).timeout(TEST_TIMEOUT))?;
    Ok(out.trim().to_string())
}

/// `[A-Za-z0-9_.-]+`, not starting with `-` (v2 rule plus the start).
fn valid_account(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && !name.starts_with('-')
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b))
}

/// The `user NAME [GROUP];` directive of a configuration dump.
pub fn parse_user_directive(text: &str) -> Option<(String, Option<String>)> {
    text.lines().find_map(|line| {
        let code = line.split('#').next().unwrap_or("").trim();
        let statement = code.strip_suffix(';')?.trim();
        let mut words = statement.split_whitespace();
        if words.next()? != "user" {
            return None;
        }
        let user = words.next().filter(|u| valid_account(u))?;
        let group = words.next();
        if words.next().is_some() || group.is_some_and(|g| !valid_account(g)) {
            return None;
        }
        Some((user.to_string(), group.map(str::to_string)))
    })
}

#[cfg(test)]
mod tests;
