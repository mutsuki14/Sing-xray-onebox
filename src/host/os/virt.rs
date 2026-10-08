//! Virtualization and container facts (used by BBR preflight and doctor).
//!
//! Sources, strongest first: `systemd-detect-virt` when installed, the
//! `container=` variable PID 1 was started with, marker files of docker and
//! podman, OpenVZ's `/proc/vz` (a container when `/proc/bc` is absent; the
//! hardware node has both), and the WSL kernel release string.

use crate::ctx::Ctx;
use crate::sys::exec::Cmd;

/// Container technologies `systemd-detect-virt` can report (systemd docs);
/// anything else it reports is a virtual machine.
const CONTAINER_IDS: [&str; 11] = [
    "openvz",
    "lxc",
    "lxc-libvirt",
    "systemd-nspawn",
    "docker",
    "podman",
    "rkt",
    "wsl",
    "proot",
    "pouch",
    "container-other",
];

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct HostFacts {
    /// What `systemd-detect-virt` reported (`kvm`, `lxc`, …), if not `none`.
    pub virtualization: Option<String>,
    /// Container technology when running inside one (`docker`, `lxc`, …).
    pub container: Option<String>,
    /// OpenVZ/Virtuozzo container (no own kernel; sysctl mostly read-only).
    pub openvz: bool,
    /// Windows Subsystem for Linux.
    pub wsl: bool,
}

impl HostFacts {
    pub fn detect(ctx: &Ctx) -> HostFacts {
        let virtualization = detect_virt(ctx);
        let openvz = virtualization.as_deref() == Some("openvz")
            || ctx.paths.system("/proc/vz").exists() && !ctx.paths.system("/proc/bc").exists();
        let wsl = virtualization.as_deref() == Some("wsl") || wsl_kernel(ctx);
        let container = virtualization
            .as_deref()
            .filter(|v| CONTAINER_IDS.contains(v))
            .map(str::to_owned)
            .or_else(|| container_hint(ctx))
            .or_else(|| openvz.then(|| "openvz".to_owned()));
        HostFacts {
            virtualization,
            container,
            openvz,
            wsl,
        }
    }

    /// Whether we share the host kernel (kernel and most sysctls are not ours).
    pub fn is_container(&self) -> bool {
        self.container.is_some() || self.openvz
    }

    /// Short Chinese description for status output.
    pub fn summary(&self) -> String {
        match (&self.container, &self.virtualization) {
            (Some(c), _) => format!("容器 ({c})"),
            (None, Some(v)) => format!("虚拟机 ({v})"),
            (None, None) if self.wsl => "WSL".to_owned(),
            (None, None) => "物理机或未识别".to_owned(),
        }
    }
}

/// `systemd-detect-virt` output unless it is missing, failed or said `none`.
fn detect_virt(ctx: &Ctx) -> Option<String> {
    if !ctx.has("systemd-detect-virt") {
        return None;
    }
    let out = ctx
        .run(&Cmd::new("systemd-detect-virt").timeout(super::PROBE_TIMEOUT))
        .ok()?;
    let id = out.stdout.trim();
    (out.ok() && !id.is_empty() && id != "none" && is_simple_id(id)).then(|| id.to_owned())
}

/// The container technology announced to PID 1 (`container=lxc`) or by a
/// runtime marker file.
fn container_hint(ctx: &Ctx) -> Option<String> {
    if let Some(environ) = super::read_system_file(ctx, "/proc/1/environ") {
        let announced = environ
            .split('\0')
            .find_map(|entry| entry.strip_prefix("container="))
            .filter(|v| !v.is_empty() && is_simple_id(v));
        if let Some(name) = announced {
            return Some(name.to_owned());
        }
    }
    if ctx.paths.system("/.dockerenv").exists() {
        return Some("docker".to_owned());
    }
    ctx.paths
        .system("/run/.containerenv")
        .exists()
        .then(|| "podman".to_owned())
}

fn wsl_kernel(ctx: &Ctx) -> bool {
    super::read_system_file(ctx, "/proc/sys/kernel/osrelease")
        .is_some_and(|r| r.to_ascii_lowercase().contains("microsoft") || r.contains("WSL"))
}

/// Identifiers we echo back must be short and printable.
fn is_simple_id(s: &str) -> bool {
    s.len() <= 32
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}
