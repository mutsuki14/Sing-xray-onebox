//! `bbr status`: read-only (no root, no network, no writes) facts about TCP
//! congestion control, qdiscs, the bbr module and installed BBRv3 kernels,
//! collected as data and rendered separately.
//!
//! Changes from v2: the sysctl conflict scan covers every directory
//! systemd-sysctl reads (`/etc`, `/run`, `/usr/local/lib`, `/usr/lib`,
//! `/lib` `sysctl.d`, with same-name masking) plus `/etc/sysctl.conf`,
//! understands `-key = value` lines, and says which files are loaded after
//! Onebox's file and therefore win at boot (I-8.1#12).

use super::{AVAILABLE, CC, QDISC};
use crate::ctx::Ctx;
use crate::host::sysctl;
use crate::sys::exec::Cmd;
use crate::sys::fs::read_to_string_bounded;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// sysctl.d directories in systemd's precedence order (earlier masks later
/// files of the same name).
pub const SYSCTL_DIRS: [&str; 5] = [
    "/etc/sysctl.d",
    "/run/sysctl.d",
    "/usr/local/lib/sysctl.d",
    "/usr/lib/sysctl.d",
    "/lib/sysctl.d",
];
const MAX_CONF_BYTES: u64 = 1 << 20;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InstalledKernel {
    pub package: String,
    pub running: bool,
}

/// Another file setting the congestion control or default qdisc.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Conflict {
    /// As the admin sees it (`/etc/sysctl.conf`).
    pub path: String,
    /// Loaded after Onebox's file, so its value wins at boot.
    pub overrides: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct StatusReport {
    pub kernel: Option<String>,
    pub congestion: Option<String>,
    pub qdisc: Option<String>,
    pub available: Option<String>,
    /// `/sys/module/tcp_bbr/version` of the loaded module.
    pub loaded_bbr: Option<String>,
    /// `modinfo` version of the module on disk for the running kernel.
    pub disk_bbr: Option<String>,
    pub packages: Vec<InstalledKernel>,
    pub persisted: Option<PathBuf>,
    pub interface_queues: Option<String>,
    pub conflicts: Vec<Conflict>,
}

/// Trimmed stdout of a successful, non-empty command; anything else is
/// "unknown" (status never fails because a tool is missing).
fn optional(ctx: &Ctx, cmd: Cmd) -> Option<String> {
    ctx.run(&cmd)
        .ok()
        .filter(|out| out.ok())
        .map(|out| out.stdout.trim().to_string())
        .filter(|s| !s.is_empty())
}

pub fn collect(ctx: &Ctx) -> StatusReport {
    let kernel = optional(ctx, Cmd::new("uname").arg("-r"));
    let read = |key| sysctl::read(ctx, key).ok().filter(|s| !s.is_empty());
    let loaded_bbr = std::fs::read_to_string(ctx.paths.system("/sys/module/tcp_bbr/version"))
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty());
    let disk_bbr = kernel.as_ref().and_then(|k| {
        optional(
            ctx,
            Cmd::new("modinfo").args(["-k", k, "-F", "version", "tcp_bbr"]),
        )
    });
    StatusReport {
        congestion: read(CC),
        qdisc: read(QDISC),
        available: read(AVAILABLE),
        loaded_bbr,
        disk_bbr,
        packages: installed_kernels(ctx, kernel.as_deref()),
        persisted: ctx
            .paths
            .bbr_conf
            .is_file()
            .then(|| ctx.paths.bbr_conf.clone()),
        interface_queues: optional(ctx, Cmd::new("tc").args(["qdisc", "show"])),
        conflicts: conflicts(ctx),
        kernel,
    }
}

fn installed_kernels(ctx: &Ctx, running: Option<&str>) -> Vec<InstalledKernel> {
    let query = Cmd::new("dpkg-query").args([
        "-W",
        "-f=${Package}\t${Status}\n",
        "linux-image-*joeyblog-bbrv3*",
    ]);
    let Some(listing) = optional(ctx, query) else {
        return Vec::new();
    };
    listing
        .lines()
        .filter_map(|line| match line.split_once('\t') {
            Some((package, "install ok installed")) => Some(InstalledKernel {
                package: package.to_string(),
                running: running.is_some_and(|k| package.strip_prefix("linux-image-") == Some(k)),
            }),
            _ => None,
        })
        .collect()
}

/// The stdout text of `bbr status` (v2 wording and order).
pub fn render(report: &StatusReport) -> String {
    let unknown = |v: &Option<String>| v.clone().unwrap_or_else(|| "未知".into());
    let mut lines = vec![
        format!("运行内核: {}", unknown(&report.kernel)),
        format!(
            "TCP / 默认队列: {} / {}",
            unknown(&report.congestion),
            unknown(&report.qdisc)
        ),
        format!("可用拥塞算法: {}", unknown(&report.available)),
    ];
    lines.push(match report.loaded_bbr.as_deref() {
        Some("3") => "运行中的 tcp_bbr: v3 (仅 TCP 当前算法为 bbr 时启用)".into(),
        other => format!(
            "运行中的 tcp_bbr 版本: {} (不能仅凭 bbr 名称判断 v3)",
            other.unwrap_or("未知")
        ),
    });
    if let Some(version) = &report.disk_bbr {
        lines.push(format!(
            "当前内核磁盘上的 tcp_bbr 模块: v{version} (不代表已加载)"
        ));
    }
    for k in &report.packages {
        let note = if k.running { "" } else { " (当前未运行)" };
        lines.push(format!("已安装: {}{note}", k.package));
    }
    if let Some(path) = &report.persisted {
        lines.push(format!("Onebox 持久配置: {}", path.display()));
    }
    if let Some(queues) = &report.interface_queues {
        lines.push(format!("\n网卡实际队列:\n{queues}"));
    }
    lines.push(
        "\nTCP BBR 与 Hysteria2/TUIC 的 QUIC 拥塞控制不同；默认队列不等于现有网卡实际队列。".into(),
    );
    lines.join("\n")
}

/// Warning lines for other files touching CC/QDISC.
pub fn conflict_notices(conflicts: &[Conflict]) -> Vec<String> {
    conflicts
        .iter()
        .map(|c| {
            if c.overrides {
                format!(
                    "其他 TCP/队列配置: {}（启动时晚于 Onebox 配置加载，会覆盖其设置）；Onebox 不修改此文件",
                    c.path
                )
            } else {
                format!(
                    "其他 TCP/队列配置: {}；请核对启动时覆盖关系，Onebox 不修改此文件",
                    c.path
                )
            }
        })
        .collect()
}

/// Whether a sysctl file sets the congestion control or default qdisc.
pub fn sets_tcp_keys(text: &str) -> bool {
    text.lines().any(|line| {
        let line = line.trim();
        if line.starts_with('#') || line.starts_with(';') {
            return false;
        }
        line.split_once('=').is_some_and(|(key, _)| {
            let key = key.trim().trim_start_matches('-').trim().replace('/', ".");
            key == CC || key == QDISC
        })
    })
}

/// Files that systemd-sysctl / procps would apply and that set our keys,
/// in load order. Onebox's own file (and files it masks) are skipped.
pub fn conflicts(ctx: &Ctx) -> Vec<Conflict> {
    let ours = ctx.paths.bbr_conf.as_path();
    let our_name = ours
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let mut seen_names = BTreeSet::from([our_name.clone()]);
    let mut seen_files = BTreeSet::new();
    let mut files: Vec<(String, PathBuf)> = Vec::new();
    for dir in SYSCTL_DIRS {
        let Ok(entries) = std::fs::read_dir(ctx.paths.system(dir)) else {
            continue;
        };
        let mut names: Vec<String> = entries
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.ends_with(".conf"))
            .collect();
        names.sort();
        for name in names {
            if seen_names.insert(name.clone()) {
                files.push((name.clone(), ctx.paths.system(&format!("{dir}/{name}"))));
            }
        }
    }
    files.sort_by(|a, b| a.0.cmp(&b.0));
    let mut found = Vec::new();
    for (name, path) in files {
        if path == ours {
            continue;
        }
        push_conflict(ctx, &path, name > our_name, &mut seen_files, &mut found);
    }
    let legacy = ctx.paths.system("/etc/sysctl.conf");
    push_conflict(ctx, &legacy, true, &mut seen_files, &mut found);
    found
}

/// Record `path` once per real file (Debian links 99-sysctl.conf to
/// /etc/sysctl.conf) when it sets our keys.
fn push_conflict(
    ctx: &Ctx,
    path: &Path,
    overrides: bool,
    seen: &mut BTreeSet<PathBuf>,
    found: &mut Vec<Conflict>,
) {
    let real = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    if !seen.insert(real.clone()) {
        return;
    }
    let Ok(text) = read_to_string_bounded(&real, MAX_CONF_BYTES) else {
        return;
    };
    if sets_tcp_keys(&text) {
        found.push(Conflict {
            path: super::shown(ctx, path),
            overrides,
        });
    }
}

#[cfg(test)]
mod tests;
