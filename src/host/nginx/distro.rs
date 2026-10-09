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
//!
//! An untouched configuration still serves whatever its document roots
//! hold (`apt install nginx` plus an own `index.html` in `/var/www/html` is
//! a working website), so every file below every `root` directive must be
//! the package's too: shipped unchanged (dpkg `*.md5sums`, `rpm -V`), or a
//! copy of its welcome page (Debian's postinst copies
//! `/usr/share/nginx/html/index.html` to
//! `/var/www/html/index.nginx-debian.html`). A configuration without an
//! absolute, variable-free `root` counts as configured.

use crate::ctx::Ctx;
use crate::host::init::InitSystem;
use crate::sys::exec::Cmd;
use crate::ui::out;
use std::collections::{BTreeSet, HashMap, HashSet};
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
/// dpkg's checksum lists of the files a package shipped (`{package}.md5sums`).
const DPKG_INFO: &str = "/var/lib/dpkg/info";
/// Where the packages keep their welcome page (with a trailing slash).
const WELCOME_DIR: &str = "/usr/share/nginx/html/";
/// Symlink hops followed when resolving an include entry.
const MAX_LINKS: usize = 8;
/// Document-root files inspected at most, and directory levels below a
/// root: the packages ship a handful; more is somebody's website.
const MAX_SERVED_FILES: usize = 64;
const MAX_SERVED_DEPTH: usize = 4;
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

/// The package manager confirms the distro configuration is untouched and
/// that it serves nothing but the package's own files (module docs).
pub(super) fn pristine(ctx: &Ctx) -> bool {
    let Some(files) = config_files(ctx) else {
        return false;
    };
    let Some(db) = PackageFiles::load(ctx) else {
        return false;
    };
    files.iter().all(|file| db.unmodified(ctx, file)) && welcome_only(ctx, &files, &db)
}

/// Every file below every document root of `files` is the package's. A
/// root that does not exist serves nothing.
fn welcome_only(ctx: &Ctx, files: &[String], db: &PackageFiles) -> bool {
    let Some(roots) = document_roots(ctx, files) else {
        return false;
    };
    let mut served = Vec::new();
    !roots.is_empty()
        && roots
            .iter()
            .all(|root| served_files(ctx, root, 0, &mut served))
        && served.iter().all(|file| db.welcome(ctx, file))
}

/// The `root` directives of the configuration files, one per line as the
/// packages write them. `None` when a file cannot be read or a root is
/// relative, holds a variable or is not a plain `root PATH;` line.
fn document_roots(ctx: &Ctx, files: &[String]) -> Option<BTreeSet<String>> {
    let mut roots = BTreeSet::new();
    for file in files {
        let text = std::fs::read_to_string(ctx.paths.system(file)).ok()?;
        for line in text.lines() {
            let line = line.split('#').next().unwrap_or_default().trim();
            let Some(value) = line.strip_prefix("root") else {
                continue;
            };
            if !value.starts_with(char::is_whitespace) {
                continue;
            }
            let value = value.trim().strip_suffix(';')?.trim();
            let value = value.trim_matches(|c| c == '"' || c == '\'');
            if value.contains('$') {
                return None;
            }
            roots.insert(normalize(value)?);
        }
    }
    Some(roots)
}

/// Collect the host path of every non-directory entry below `dir` (links
/// are not followed into directories). `false` when a directory cannot be
/// read, or there are more files or levels than a welcome page needs.
fn served_files(ctx: &Ctx, dir: &str, depth: usize, out: &mut Vec<String>) -> bool {
    let entries = match std::fs::read_dir(ctx.paths.system(dir)) {
        Ok(entries) => entries,
        Err(e) => return depth == 0 && e.kind() == std::io::ErrorKind::NotFound,
    };
    for entry in entries {
        let Ok(entry) = entry else {
            return false;
        };
        let (Some(name), Ok(kind)) = (
            entry.file_name().to_str().map(String::from),
            entry.file_type(),
        ) else {
            return false;
        };
        let host = format!("{}/{name}", dir.trim_end_matches('/'));
        if kind.is_dir() {
            if depth + 1 >= MAX_SERVED_DEPTH || !served_files(ctx, &host, depth + 1, out) {
                return false;
            }
        } else {
            out.push(host);
            if out.len() > MAX_SERVED_FILES {
                return false;
            }
        }
    }
    true
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
    /// dpkg: host path → packaged MD5 of the conffiles, and of the other
    /// files the packages shipped.
    Dpkg {
        conffiles: HashMap<String, String>,
        shipped: HashMap<String, String>,
    },
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

    /// A configuration file of the package with its packaged content.
    fn unmodified(&self, ctx: &Ctx, path: &str) -> bool {
        match self {
            PackageFiles::Dpkg { conffiles, .. } => conffiles
                .get(path)
                .is_some_and(|want| md5(ctx, path).as_deref() == Some(want.as_str())),
            PackageFiles::Rpm { owned, changed } => owned.contains(path) && !changed.contains(path),
        }
    }

    /// A served file the package shipped unchanged, or (dpkg) a copy of
    /// one of its welcome pages.
    fn welcome(&self, ctx: &Ctx, path: &str) -> bool {
        match self {
            PackageFiles::Dpkg { shipped, .. } => md5(ctx, path).is_some_and(|sum| {
                shipped.get(path) == Some(&sum)
                    || shipped
                        .iter()
                        .any(|(file, want)| file.starts_with(WELCOME_DIR) && *want == sum)
            }),
            PackageFiles::Rpm { .. } => self.unmodified(ctx, path),
        }
    }
}

fn dpkg(ctx: &Ctx) -> Option<PackageFiles> {
    // A package that is not installed only adds a stderr line.
    let cmd = Cmd::new("dpkg-query")
        .args(["-W", "--showformat=${Conffiles}\\n"])
        .args(DPKG_PACKAGES);
    let out = ctx.run(&query(cmd)).ok()?;
    let conffiles = parse_conffiles(&out.stdout);
    if conffiles.is_empty() {
        return None;
    }
    // A package that is not installed has no list.
    let shipped = DPKG_PACKAGES
        .iter()
        .filter_map(|package| {
            let list = ctx.paths.system(&format!("{DPKG_INFO}/{package}.md5sums"));
            std::fs::read_to_string(list).ok()
        })
        .flat_map(|text| parse_md5sums(&text))
        .collect();
    Some(PackageFiles::Dpkg { conffiles, shipped })
}

/// `7df3…  usr/share/nginx/html/index.html` lines (paths relative to `/`)
/// → host path → md5.
fn parse_md5sums(text: &str) -> Vec<(String, String)> {
    text.lines()
        .filter_map(|line| {
            let (sum, path) = line.split_once(char::is_whitespace)?;
            let path = path.trim_start();
            (is_md5(sum) && !path.is_empty())
                .then(|| (format!("/{path}"), sum.to_ascii_lowercase()))
        })
        .collect()
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
