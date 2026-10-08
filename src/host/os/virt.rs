//! Virtualization and container facts (used by BBR preflight and doctor).
//!
//! Container signals, strongest first: `systemd-detect-virt` (and
//! `systemd-detect-virt --container`, which also knows technologies newer
//! than our table), the `/run/systemd/container` marker, what PID 1 was
//! started with (`container=…`, `KUBERNETES_SERVICE_HOST`), marker files of
//! docker, podman and Kubernetes, then container runtimes named in PID 1's
//! cgroup path or the kernel strings (`kubepods`, `libpod`, `containerd`,
//! `docker`, `lxc`; Kubernetes/containerd pods often show nothing else),
//! and OpenVZ's `/proc/vz` (a container when `/proc/bc` is absent; the
//! hardware node has both). WSL is recognized by `systemd-detect-virt` or
//! `microsoft`/`wsl` in the kernel strings.
//!
//! This is every signal of v2's BBR container check (bbr.rs) plus the
//! Kubernetes ones; the BBR kernel preflight must fail closed, so
//! [`HostFacts::kernel_managed_elsewhere`] treats any hit as "not ours".

use crate::ctx::Ctx;
use crate::sys::exec::Cmd;

/// Container technologies `systemd-detect-virt` can report (systemd docs);
/// anything else it reports is a virtual machine, unless `--container`
/// says otherwise.
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

/// Runtime names searched (lower-cased) in PID 1's cgroup and the kernel
/// strings, most specific first, with the technology they imply.
const RUNTIME_HINTS: [(&str, &str); 5] = [
    ("kubepods", "kubernetes"),
    ("libpod", "podman"),
    ("containerd", "containerd"),
    ("docker", "docker"),
    ("lxc", "lxc"),
];

/// Files whose presence means "inside that container".
const MARKERS: [(&str, &str); 4] = [
    ("/.dockerenv", "docker"),
    ("/run/.containerenv", "podman"),
    ("/run/secrets/kubernetes.io", "kubernetes"),
    ("/var/run/secrets/kubernetes.io", "kubernetes"),
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
        let tool = ctx.has("systemd-detect-virt");
        let virtualization = if tool { detect_virt(ctx, &[]) } else { None };
        let openvz = virtualization.as_deref() == Some("openvz")
            || ctx.paths.system("/proc/vz").exists() && !ctx.paths.system("/proc/bc").exists();
        let kernel = kernel_strings(ctx);
        let wsl = virtualization.as_deref() == Some("wsl")
            || kernel.contains("microsoft")
            || kernel.contains("wsl");
        let container = virtualization
            .as_deref()
            .filter(|v| CONTAINER_IDS.contains(v))
            .map(str::to_owned)
            .or_else(|| tool.then(|| detect_virt(ctx, &["--container"])).flatten())
            .or_else(|| container_hint(ctx, &kernel))
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

    /// Whether the running kernel belongs to someone else (container,
    /// OpenVZ, WSL): never install or switch kernels then (v2's BBR rule).
    pub fn kernel_managed_elsewhere(&self) -> bool {
        self.is_container() || self.wsl
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

/// `systemd-detect-virt [args]` output unless it failed or said `none`.
fn detect_virt(ctx: &Ctx, args: &[&str]) -> Option<String> {
    let cmd = Cmd::new("systemd-detect-virt")
        .args(args.iter().copied())
        .timeout(super::PROBE_TIMEOUT);
    let out = ctx.run(&cmd).ok()?;
    let id = out.stdout.trim();
    (out.ok() && !id.is_empty() && id != "none" && is_simple_id(id)).then(|| id.to_owned())
}

/// `/proc/version` and the kernel release, lower-cased.
fn kernel_strings(ctx: &Ctx) -> String {
    ["/proc/version", "/proc/sys/kernel/osrelease"]
        .iter()
        .filter_map(|p| super::read_system_file(ctx, p))
        .collect::<Vec<_>>()
        .join("\n")
        .to_ascii_lowercase()
}

/// The container technology announced by systemd's marker, PID 1's
/// environment, a marker file, or a runtime name in PID 1's cgroup path or
/// the kernel strings.
fn container_hint(ctx: &Ctx, kernel: &str) -> Option<String> {
    if let Some(marker) = super::read_system_file(ctx, "/run/systemd/container") {
        let id = marker.trim();
        let id = if is_simple_id(id) && !id.is_empty() {
            id
        } else {
            "container-other"
        };
        return Some(id.to_owned());
    }
    if let Some(found) = environ_hint(ctx) {
        return Some(found);
    }
    if let Some((_, id)) = MARKERS
        .iter()
        .find(|(path, _)| ctx.paths.system(path).exists())
    {
        return Some((*id).to_owned());
    }
    let cgroup = super::read_system_file(ctx, "/proc/1/cgroup")
        .unwrap_or_default()
        .to_ascii_lowercase();
    RUNTIME_HINTS
        .iter()
        .find(|(needle, _)| cgroup.contains(needle) || kernel.contains(needle))
        .map(|(_, id)| (*id).to_owned())
}

/// `container=NAME` or a Kubernetes service variable in PID 1's environment.
fn environ_hint(ctx: &Ctx) -> Option<String> {
    let environ = super::read_system_file(ctx, "/proc/1/environ")?;
    let mut entries = environ.split('\0');
    let announced = entries
        .clone()
        .find_map(|entry| entry.strip_prefix("container="))
        .filter(|v| !v.is_empty() && is_simple_id(v));
    if let Some(name) = announced {
        return Some(name.to_owned());
    }
    entries
        .any(|entry| entry.starts_with("KUBERNETES_SERVICE_HOST="))
        .then(|| "kubernetes".to_owned())
}

/// Identifiers we echo back must be short and printable.
fn is_simple_id(s: &str) -> bool {
    s.len() <= 32
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}
