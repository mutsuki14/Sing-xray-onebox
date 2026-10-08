//! The distro `nginx` service: is it enabled, is its configuration still
//! exactly what the package shipped, and stopping/disabling it. See the
//! module docs of `host::nginx` for when Onebox neutralizes it.
//!
//! "Unconfigured" is decided by the package manager, never by file names:
//! `nginx.conf` and every entry of the distro include directories (links
//! followed) must be configuration files of the package with their
//! packaged content — dpkg conffile MD5s (`dpkg-query`), or `rpm -V` on
//! RPM systems. Anything else (an edited `sites-enabled/default`, a
//! certbot-managed site, a host without dpkg/rpm) counts as configured.

use crate::ctx::Ctx;
use crate::host::init::InitSystem;
use crate::sys::exec::Cmd;
use crate::ui::out;
use std::collections::{HashMap, HashSet};
use std::time::Duration;

const MAIN_CONF: &str = "/etc/nginx/nginx.conf";
/// Distro include directories that hold (or extend) server blocks.
const INCLUDE_DIRS: [&str; 5] = [
    "/etc/nginx/sites-enabled",
    "/etc/nginx/conf.d",
    "/etc/nginx/http.d",
    "/etc/nginx/default.d",
    "/etc/nginx/vhosts.d",
];
/// dpkg packages owning the distro configuration (Debian/Ubuntu ship it in
/// `nginx-common`, nginx.org packages in `nginx`).
const DPKG_PACKAGES: [&str; 2] = ["nginx-common", "nginx"];
/// Symlink hops followed when resolving an include entry.
const MAX_LINKS: usize = 8;
const QUERY_TIMEOUT: Duration = Duration::from_secs(60);

/// Whether the distro `nginx` service starts at boot.
pub(super) fn service_enabled(ctx: &Ctx, init: InitSystem) -> bool {
    match init {
        InitSystem::Systemd => ctx
            .run(&systemctl(&["is-enabled", "nginx.service"]))
            .is_ok_and(|o| o.ok() && o.stdout.trim() == "enabled"),
        InitSystem::Openrc => {
            std::fs::symlink_metadata(ctx.paths.system("/etc/runlevels/default/nginx")).is_ok()
        }
        InitSystem::None => false,
    }
}

/// The package manager confirms the distro configuration is untouched.
pub(super) fn pristine(ctx: &Ctx) -> bool {
    let Some(files) = config_files(ctx) else {
        return false;
    };
    let Some(db) = PackageFiles::load(ctx) else {
        return false;
    };
    files.iter().all(|file| db.unmodified(ctx, file))
}

/// Stop and disable the distro service. Failures only warn: a service
/// still holding a port is reported by the port planner later.
pub(super) fn neutralize(ctx: &Ctx, init: InitSystem) {
    match init {
        InitSystem::Systemd => {
            let result = ctx.run(&systemctl(&["disable", "--now", "nginx.service"]));
            match result {
                Ok(o) if o.ok() => {}
                Ok(o) => out::warn(format!(
                    "无法停用系统 nginx 服务: {}",
                    first_line(&o.stderr)
                )),
                Err(e) => out::warn(format!("无法停用系统 nginx 服务: {e}")),
            }
        }
        InitSystem::Openrc => {
            let _ = ctx.run(&query(Cmd::new("rc-service").args(["nginx", "stop"])));
            let _ = ctx.run(&query(
                Cmd::new("rc-update").args(["del", "nginx", "default"]),
            ));
        }
        InitSystem::None => return,
    }
    out::info("已停用系统自带的 nginx 服务（Onebox 使用独立的 nginx 实例，避免占用 80/443 端口）");
}

fn systemctl(args: &[&str]) -> Cmd {
    query(Cmd::new("systemctl").args(args.iter().copied()))
}

fn query(cmd: Cmd) -> Cmd {
    cmd.timeout(QUERY_TIMEOUT)
}

fn first_line(text: &str) -> &str {
    text.lines()
        .map(str::trim)
        .find(|l| !l.is_empty())
        .unwrap_or("")
}

/// Host paths of `nginx.conf` and of every include-directory entry, links
/// resolved. `None` when `nginx.conf` is missing or an entry is anything
/// but a (link to a) regular file.
fn config_files(ctx: &Ctx) -> Option<Vec<String>> {
    let mut files = vec![resolve(ctx, MAIN_CONF)?];
    for dir in INCLUDE_DIRS {
        let entries = match std::fs::read_dir(ctx.paths.system(dir)) {
            Ok(entries) => entries,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(_) => return None,
        };
        for entry in entries {
            let name = entry.ok()?.file_name();
            let host = format!("{dir}/{}", name.to_str()?);
            files.push(resolve(ctx, &host)?);
        }
    }
    Some(files)
}

/// Follow symlinks of the host path `host` (targets mapped under
/// `system_root`) to a regular file; returns its normalized host path.
fn resolve(ctx: &Ctx, host: &str) -> Option<String> {
    let mut current = normalize(host)?;
    for _ in 0..MAX_LINKS {
        let local = ctx.paths.system(&current);
        let meta = std::fs::symlink_metadata(&local).ok()?;
        if meta.is_file() {
            return Some(current);
        }
        if !meta.file_type().is_symlink() {
            return None;
        }
        let link = std::fs::read_link(&local).ok()?;
        let target = link.to_str()?;
        current = if target.starts_with('/') {
            normalize(target)?
        } else {
            let (parent, _) = current.rsplit_once('/')?;
            normalize(&format!("{parent}/{target}"))?
        };
    }
    None
}

/// Lexically normalize an absolute path (`.`/`..`/empty components).
fn normalize(path: &str) -> Option<String> {
    if !path.starts_with('/') {
        return None;
    }
    let mut parts: Vec<&str> = Vec::new();
    for part in path.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            other => parts.push(other),
        }
    }
    Some(format!("/{}", parts.join("/")))
}

/// What the package database says about the distro configuration files.
#[derive(Debug, PartialEq, Eq)]
enum PackageFiles {
    /// dpkg conffiles: host path → packaged MD5.
    Dpkg(HashMap<String, String>),
    /// rpm: files of the package owning `nginx.conf`, and those `rpm -V`
    /// reports as differing.
    Rpm {
        owned: HashSet<String>,
        changed: HashSet<String>,
    },
}

impl PackageFiles {
    fn load(ctx: &Ctx) -> Option<PackageFiles> {
        if ctx.has("dpkg-query") {
            return dpkg(ctx);
        }
        if ctx.has("rpm") {
            return rpm(ctx);
        }
        None
    }

    fn unmodified(&self, ctx: &Ctx, path: &str) -> bool {
        match self {
            PackageFiles::Dpkg(sums) => sums
                .get(path)
                .is_some_and(|want| md5(ctx, path).as_deref() == Some(want.as_str())),
            PackageFiles::Rpm { owned, changed } => owned.contains(path) && !changed.contains(path),
        }
    }
}

fn dpkg(ctx: &Ctx) -> Option<PackageFiles> {
    // A package that is not installed only adds a stderr line.
    let cmd = Cmd::new("dpkg-query")
        .args(["-W", "--showformat=${Conffiles}\\n"])
        .args(DPKG_PACKAGES);
    let out = ctx.run(&query(cmd)).ok()?;
    let sums = parse_conffiles(&out.stdout);
    (!sums.is_empty()).then_some(PackageFiles::Dpkg(sums))
}

/// ` /etc/nginx/nginx.conf 3e4d… [obsolete]` lines → path → md5.
fn parse_conffiles(text: &str) -> HashMap<String, String> {
    text.lines()
        .filter_map(|line| {
            let mut words = line.split_whitespace();
            let path = words.next().filter(|p| p.starts_with('/'))?;
            let sum = words.next().filter(|s| is_md5(s))?;
            Some((path.to_owned(), sum.to_ascii_lowercase()))
        })
        .collect()
}

fn is_md5(s: &str) -> bool {
    s.len() == 32 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// MD5 of the file at host path `path` (via `md5sum`, as dpkg records it).
fn md5(ctx: &Ctx, path: &str) -> Option<String> {
    let local = ctx.paths.system(path);
    let cmd = Cmd::new("md5sum").arg(local.to_string_lossy());
    let out = ctx.run(&query(cmd)).ok().filter(|o| o.ok())?;
    let sum = out.stdout.split_whitespace().next().filter(|s| is_md5(s))?;
    Some(sum.to_ascii_lowercase())
}

fn rpm(ctx: &Ctx) -> Option<PackageFiles> {
    let owner = Cmd::new("rpm").args(["-qf", "--queryformat", "%{NAME}\\n", MAIN_CONF]);
    let out = ctx.run(&query(owner)).ok().filter(|o| o.ok())?;
    let name = out.stdout.lines().next()?.trim();
    let valid = !name.is_empty()
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._+-".contains(&b));
    if !valid {
        return None;
    }
    let list = ctx
        .run(&query(Cmd::new("rpm").args(["-ql", name])))
        .ok()
        .filter(|o| o.ok())?;
    let owned = list
        .stdout
        .lines()
        .map(str::trim)
        .filter(|l| l.starts_with('/'))
        .map(str::to_owned)
        .collect();
    // `rpm -V` exits 1 when anything differs; its lines are what counts.
    let verify = ctx.run(&query(Cmd::new("rpm").args(["-V", name]))).ok()?;
    let changed = parse_rpm_verify(&verify.stdout)?;
    Some(PackageFiles::Rpm { owned, changed })
}

/// Paths named by `rpm -V` lines (`S.5....T.  c /etc/nginx/nginx.conf`,
/// `missing   c /etc/nginx/x`). Any other line (an error) makes the result
/// unusable.
fn parse_rpm_verify(text: &str) -> Option<HashSet<String>> {
    let mut changed = HashSet::new();
    for line in text.lines().filter(|l| !l.trim().is_empty()) {
        let words: Vec<&str> = line.split_whitespace().collect();
        let flags = *words.first()?;
        let path = *words.last()?;
        let flags_ok = flags == "missing"
            || (8..=9).contains(&flags.len()) && flags.bytes().all(|b| b"SM5DLUGTP.?".contains(&b));
        if !flags_ok || words.len() < 2 || !path.starts_with('/') {
            return None;
        }
        changed.insert(path.to_owned());
    }
    Some(changed)
}

#[cfg(test)]
mod tests;
