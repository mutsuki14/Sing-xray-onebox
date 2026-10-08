use super::*;
use crate::sys::exec::Output;
use crate::sys::fs::TempDir;
use std::fs;
use std::path::Path;

fn write(root: &Path, rel: &str, text: &str) {
    let path = root.join(rel);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, text).unwrap();
}

const DEBIAN: &str = r#"PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"
NAME="Debian GNU/Linux"
VERSION_ID="12"
VERSION="12 (bookworm)"
VERSION_CODENAME=bookworm
ID=debian
HOME_URL="https://www.debian.org/"
"#;

const ROCKY: &str = r#"NAME="Rocky Linux"
VERSION="9.4 (Blue Onyx)"
ID="rocky"
ID_LIKE="rhel centos fedora"
VERSION_ID="9.4"
PRETTY_NAME="Rocky Linux 9.4 (Blue Onyx)"
"#;

#[test]
fn os_release_parsing() {
    let debian = OsInfo::parse(DEBIAN);
    assert_eq!(
        debian,
        OsInfo {
            id: "debian".into(),
            id_like: vec![],
            version_id: "12".into(),
            version_codename: "bookworm".into(),
            pretty_name: "Debian GNU/Linux 12 (bookworm)".into(),
        }
    );
    let rocky = OsInfo::parse(ROCKY);
    assert_eq!(rocky.id_like, ["rhel", "centos", "fedora"]);
    assert!(rocky.is_like("rhel") && rocky.is_like("rocky") && !rocky.is_like("debian"));
    assert_eq!(rocky.label(), "rocky");

    let alpine =
        OsInfo::parse("ID=alpine\nVERSION_ID=3.20.1\nPRETTY_NAME=\"Alpine Linux v3.20\"\n");
    assert_eq!(
        (alpine.id.as_str(), alpine.version_id.as_str()),
        ("alpine", "3.20.1")
    );
}

/// Debian testing/sid has no VERSION_ID; BBR maps the codename instead.
#[test]
fn debian_sid_has_only_a_codename() {
    let sid = OsInfo::parse(
        "PRETTY_NAME=\"Debian GNU/Linux trixie/sid\"\nNAME=\"Debian GNU/Linux\"\n\
         VERSION_CODENAME=trixie\nID=debian\nHOME_URL=\"https://www.debian.org/\"\n",
    );
    assert_eq!(sid.id, "debian");
    assert_eq!(sid.version_id, "");
    assert_eq!(sid.version_codename, "trixie");
    assert_eq!(
        OsInfo::parse("VERSION_CODENAME='Noble'\n").version_codename,
        "noble"
    );
}

#[test]
fn os_release_quoting_follows_the_shell() {
    let cases = [
        (
            r#"PRETTY_NAME="A \"quoted\" \$name\\""#,
            r#"A "quoted" $name\"#,
        ),
        ("PRETTY_NAME='single \\ quoted'", "single \\ quoted"),
        ("PRETTY_NAME=plain", "plain"),
        (r#"PRETTY_NAME="keep \n escape""#, r"keep \n escape"),
        ("PRETTY_NAME=\"unbalanced", "\"unbalanced"),
        ("PRETTY_NAME=\"\"", ""),
    ];
    for (line, want) in cases {
        assert_eq!(OsInfo::parse(line).pretty_name, want, "{line}");
    }
    let noisy = OsInfo::parse("# ID=commented\n\n lowercase=x\nID =bad\nBROKEN\nID=Ubuntu\n");
    assert_eq!(noisy.id, "ubuntu", "ID is lower-cased; junk ignored");
    assert_eq!(OsInfo::default().label(), "linux");
}

#[test]
fn os_release_load_prefers_etc_then_usr_lib() {
    let dir = TempDir::new("os").unwrap();
    let (ctx, _, _) = Ctx::test(dir.path());
    let sys = ctx.paths.system_root.clone();
    assert_eq!(OsInfo::load(&ctx), OsInfo::default());
    write(&sys, "usr/lib/os-release", "ID=arch\n");
    assert_eq!(OsInfo::load(&ctx).id, "arch");
    write(&sys, "etc/os-release", DEBIAN);
    assert_eq!(OsInfo::load(&ctx).id, "debian");
}

/// Debian/Ubuntu/Fedora/Arch/Alpine ship `/etc/os-release` as a relative
/// link to `../usr/lib/os-release`; here `/usr/lib/os-release` is a link
/// as well, so only following links finds the data.
#[test]
fn os_release_is_read_through_symlinks() {
    let dir = TempDir::new("os").unwrap();
    let (ctx, _, _) = Ctx::test(dir.path());
    let sys = ctx.paths.system_root.clone();
    write(&sys, "usr/lib/os-release.d/debian", DEBIAN);
    fs::create_dir_all(sys.join("etc")).unwrap();
    std::os::unix::fs::symlink("os-release.d/debian", sys.join("usr/lib/os-release")).unwrap();
    std::os::unix::fs::symlink("../usr/lib/os-release", sys.join("etc/os-release")).unwrap();
    let info = OsInfo::load(&ctx);
    assert_eq!(
        (info.id.as_str(), info.version_id.as_str()),
        ("debian", "12")
    );

    // Only regular files within the cap count.
    let dir = TempDir::new("os").unwrap();
    let (ctx, _, _) = Ctx::test(dir.path());
    let sys = ctx.paths.system_root.clone();
    fs::create_dir_all(sys.join("etc/os-release")).unwrap();
    write(&sys, "usr/lib/os-release", &"#".repeat(2 << 20));
    assert_eq!(OsInfo::load(&ctx), OsInfo::default());
    fs::create_dir_all(sys.join("usr/lib")).unwrap();
    std::os::unix::fs::symlink("/nonexistent/os-release", sys.join("etc/dangling")).unwrap();
    assert_eq!(read_system_file(&ctx, "/etc/dangling"), None);
}

#[test]
fn root_requirement_message() {
    assert!(require_root_with(true).is_ok());
    assert_eq!(
        require_root_with(false).unwrap_err().to_string(),
        "此操作需要 root 权限"
    );
    assert_eq!(require_root().is_ok(), is_root());
}

#[test]
fn process_env_treats_empty_as_unset() {
    assert_eq!(process_env("ONEBOX_TEST_SURELY_UNSET_VARIABLE"), None);
    assert!(process_env("PATH").is_some());
}

#[test]
fn uname_probes() {
    let dir = TempDir::new("os").unwrap();
    let (ctx, exec, _) = Ctx::test(dir.path());
    exec.on("uname", &["-m"], Output::success("x86_64\n")).on(
        "uname",
        &["-r"],
        Output::success("  \n"),
    );
    assert_eq!(machine(&ctx).unwrap(), "x86_64");
    assert_eq!(
        kernel_release(&ctx).unwrap_err().to_string(),
        "uname -r 没有输出"
    );
    assert!(exec.calls().iter().all(|c| c.timeout.is_some()));
}

#[test]
fn arch_table_matches_v2() {
    let neon = "Features : half thumb fastmult vfp edsp neon vfpv3 tls";
    let cases: &[(&str, &str, bool, Arch)] = &[
        ("x86_64", "", true, Arch::Amd64),
        ("amd64", "", true, Arch::Amd64),
        ("i686", "", true, Arch::I386),
        ("i386", "", true, Arch::I386),
        ("x86", "", true, Arch::I386),
        ("aarch64", "", true, Arch::Arm64),
        ("arm64", "", true, Arch::Arm64),
        ("armv7l", neon, true, Arch::Armv7),
        ("armv7l", "Features : half thumb", true, Arch::Armv6),
        ("armv8l", "Features : asimd", true, Arch::Armv7),
        ("armv6l", neon, true, Arch::Armv6),
        ("armv5tel", "", true, Arch::Armv5),
        ("s390x", "", false, Arch::S390x),
        ("riscv64", "", true, Arch::Riscv64),
        ("loongarch64", "", true, Arch::Loong64),
        ("loong64", "", true, Arch::Loong64),
        ("ppc64le", "", true, Arch::Ppc64le),
        ("ppc64", "", false, Arch::Ppc64),
        ("mips64", "", true, Arch::Mips64le),
        ("mips64", "", false, Arch::Mips64),
        ("mips", "", true, Arch::Mipsle),
        ("mips", "", false, Arch::Mips),
    ];
    for (machine, cpuinfo, little, want) in cases {
        assert_eq!(
            Arch::from_uname(machine, cpuinfo, *little).unwrap(),
            *want,
            "{machine}"
        );
    }
    assert_eq!(
        Arch::from_uname("sparc64", "", false)
            .unwrap_err()
            .to_string(),
        "不支持的架构: sparc64"
    );
}

#[test]
fn arch_detection_reads_cpuinfo_under_system_root() {
    let dir = TempDir::new("os").unwrap();
    let (ctx, exec, _) = Ctx::test(dir.path());
    exec.on("uname", &["-m"], Output::success("armv7l\n"));
    assert_eq!(Arch::detect(&ctx).unwrap(), Arch::Armv6, "no cpuinfo");
    write(
        &ctx.paths.system_root,
        "proc/cpuinfo",
        "Features\t: vfpv4 neon\n",
    );
    assert_eq!(Arch::detect(&ctx).unwrap(), Arch::Armv7);
}

#[test]
fn singbox_and_xray_asset_names() {
    assert_eq!(
        Arch::Amd64.singbox_assets("1.14.2"),
        [
            "sing-box-1.14.2-linux-amd64-musl.tar.gz",
            "sing-box-1.14.2-linux-amd64.tar.gz",
            "sing-box-1.14.2-linux-amd64-glibc.tar.gz",
        ]
    );
    assert_eq!(
        Arch::Mipsle.singbox_assets("1.0"),
        [
            "sing-box-1.0-linux-mipsle-softfloat-musl.tar.gz",
            "sing-box-1.0-linux-mipsle-softfloat.tar.gz",
            "sing-box-1.0-linux-mipsle.tar.gz",
        ]
    );
    assert_eq!(
        Arch::Mips64le.singbox_assets("1.0")[0],
        "sing-box-1.0-linux-mips64le.tar.gz"
    );
    assert_eq!(
        Arch::Mips.singbox_assets("1.0"),
        ["sing-box-1.0-linux-mips-softfloat.tar.gz"]
    );
    assert_eq!(
        Arch::Armv6.singbox_assets("1.0"),
        [
            "sing-box-1.0-linux-armv6-musl.tar.gz",
            "sing-box-1.0-linux-armv6.tar.gz"
        ]
    );
    assert!(Arch::Ppc64.singbox_assets("1.0").is_empty());
    assert_eq!(Arch::Ppc64.singbox(), None);
    let xray: Vec<String> = [
        Arch::Amd64,
        Arch::I386,
        Arch::Arm64,
        Arch::Armv7,
        Arch::Mipsle,
    ]
    .iter()
    .map(|a| a.xray_asset())
    .collect();
    assert_eq!(
        xray,
        [
            "Xray-linux-64.zip",
            "Xray-linux-32.zip",
            "Xray-linux-arm64-v8a.zip",
            "Xray-linux-arm32-v7a.zip",
            "Xray-linux-mips32le.zip"
        ]
    );
}

#[test]
fn frp_onebox_and_bbr_names() {
    assert_eq!(
        Arch::Amd64.frp_asset("0.71.0").as_deref(),
        Some("frp_0.71.0_linux_amd64.tar.gz")
    );
    assert_eq!(Arch::Armv7.frp(), Some("arm_hf"));
    assert_eq!(Arch::Armv5.frp(), Some("arm"));
    assert_eq!(Arch::I386.frp(), None, "frp publishes no linux_386");
    assert_eq!(Arch::S390x.frp_asset("0.71.0"), None);

    let onebox: Vec<Option<String>> = [
        Arch::Amd64,
        Arch::Arm64,
        Arch::I386,
        Arch::Armv7,
        Arch::Armv6,
    ]
    .iter()
    .map(|a| a.onebox_asset())
    .collect();
    assert_eq!(
        onebox,
        [
            Some("onebox-linux-amd64-musl".to_string()),
            Some("onebox-linux-arm64-musl".to_string()),
            Some("onebox-linux-386-musl".to_string()),
            Some("onebox-linux-armv7-musl".to_string()),
            None
        ]
    );
    assert_eq!(
        Arch::Amd64.bbr(),
        Some(BbrArch {
            tag: "x86_64",
            deb: "amd64"
        })
    );
    assert_eq!(Arch::Arm64.bbr().map(|b| b.tag), Some("arm64"));
    assert_eq!(Arch::Armv7.bbr(), None);
    assert_eq!(Arch::Loong64.to_string(), "loong64");
}

fn facts(setup: impl FnOnce(&Path, &crate::sys::exec::FakeExec)) -> HostFacts {
    let dir = TempDir::new("virt").unwrap();
    let (ctx, exec, _) = Ctx::test(dir.path());
    fs::create_dir_all(&ctx.paths.system_root).unwrap();
    setup(&ctx.paths.system_root, &exec);
    HostFacts::detect(&ctx)
}

#[test]
fn virtualization_from_systemd_detect_virt() {
    let kvm = facts(|_, exec| {
        exec.provide("systemd-detect-virt")
            .on(
                "systemd-detect-virt",
                &["--container"],
                Output::failure(1, "none\n"),
            )
            .on("systemd-detect-virt", &[], Output::success("kvm\n"));
    });
    assert_eq!(kvm.virtualization.as_deref(), Some("kvm"));
    assert!(!kvm.is_container() && !kvm.kernel_managed_elsewhere());
    assert_eq!(kvm.summary(), "虚拟机 (kvm)");

    // A technology newer than our table: `--container` classifies it.
    let novel = facts(|_, exec| {
        exec.provide("systemd-detect-virt")
            .on(
                "systemd-detect-virt",
                &["--container"],
                Output::success("newbox\n"),
            )
            .on("systemd-detect-virt", &[], Output::success("newbox\n"));
    });
    assert_eq!(novel.container.as_deref(), Some("newbox"));
    assert!(novel.kernel_managed_elsewhere());

    let lxc = facts(|_, exec| {
        exec.provide("systemd-detect-virt").on(
            "systemd-detect-virt",
            &[],
            Output::success("lxc\n"),
        );
    });
    assert_eq!(lxc.container.as_deref(), Some("lxc"));
    assert_eq!(lxc.summary(), "容器 (lxc)");

    let none = facts(|_, exec| {
        exec.provide("systemd-detect-virt")
            .on("systemd-detect-virt", &[], Output::failure(1, ""));
    });
    assert_eq!(none, HostFacts::default());
    assert_eq!(none.summary(), "物理机或未识别");
}

#[test]
fn container_hints_without_systemd() {
    let environ = facts(|root, _| {
        write(
            root,
            "proc/1/environ",
            "HOME=/\0container=podman\0TERM=xterm\0",
        );
    });
    assert_eq!(environ.container.as_deref(), Some("podman"));
    assert_eq!(environ.virtualization, None, "tool absent: not consulted");

    let docker = facts(|root, _| write(root, ".dockerenv", ""));
    assert_eq!(docker.container.as_deref(), Some("docker"));

    let podman = facts(|root, _| write(root, "run/.containerenv", ""));
    assert_eq!(podman.container.as_deref(), Some("podman"));

    let bogus = facts(|root, _| write(root, "proc/1/environ", "container=a b\0"));
    assert_eq!(bogus.container, None, "unprintable ids are ignored");

    let nspawn = facts(|root, _| write(root, "run/systemd/container", "systemd-nspawn\n"));
    assert_eq!(nspawn.container.as_deref(), Some("systemd-nspawn"));
    let odd = facts(|root, _| write(root, "run/systemd/container", "?? weird"));
    assert_eq!(
        odd.container.as_deref(),
        Some("container-other"),
        "fail closed"
    );
}

/// Kubernetes/containerd pods: no /.dockerenv, no `container=`, usually no
/// systemd-detect-virt — the cgroup path or the pod environment tells.
#[test]
fn kubernetes_and_runtime_hints() {
    let cgroup_v1 = facts(|root, _| {
        write(
            root,
            "proc/1/cgroup",
            "12:memory:/kubepods/burstable/pod0c9e/3f1a\n11:cpu:/kubepods/burstable/pod0c9e/3f1a\n",
        )
    });
    assert_eq!(cgroup_v1.container.as_deref(), Some("kubernetes"));
    assert!(cgroup_v1.kernel_managed_elsewhere());

    let cases = [
        (
            "0::/system.slice/containerd.service/kubepods-besteffort.slice\n",
            "kubernetes",
        ),
        ("0::/machine.slice/libpod-4b1d.scope\n", "podman"),
        ("0::/system.slice/docker-1a2b.scope\n", "docker"),
        ("1:name=systemd:/lxc/ct101\n", "lxc"),
    ];
    for (cgroup, want) in cases {
        let got = facts(|root, _| write(root, "proc/1/cgroup", cgroup));
        assert_eq!(got.container.as_deref(), Some(want), "{cgroup}");
    }
    let host = facts(|root, _| write(root, "proc/1/cgroup", "0::/init.scope\n"));
    assert_eq!(host.container, None);

    let env = facts(|root, _| {
        write(
            root,
            "proc/1/environ",
            "PATH=/bin\0KUBERNETES_SERVICE_HOST=10.96.0.1\0",
        )
    });
    assert_eq!(env.container.as_deref(), Some("kubernetes"));
    let mount = facts(|root, _| {
        fs::create_dir_all(root.join("run/secrets/kubernetes.io/serviceaccount")).unwrap()
    });
    assert_eq!(mount.container.as_deref(), Some("kubernetes"));
    let kernel = facts(|root, _| {
        write(
            root,
            "proc/version",
            "Linux version 5.4.0-docker (gcc) #1 SMP\n",
        )
    });
    assert_eq!(kernel.container.as_deref(), Some("docker"), "v2 parity");
}

#[test]
fn openvz_and_wsl() {
    let guest = facts(|root, _| fs::create_dir_all(root.join("proc/vz")).unwrap());
    assert!(guest.openvz && guest.is_container());
    assert_eq!(guest.container.as_deref(), Some("openvz"));

    let node = facts(|root, _| {
        fs::create_dir_all(root.join("proc/vz")).unwrap();
        fs::create_dir_all(root.join("proc/bc")).unwrap();
    });
    assert!(!node.openvz, "the hardware node has /proc/bc");

    let wsl = facts(|root, _| {
        write(
            root,
            "proc/sys/kernel/osrelease",
            "5.15.153.1-microsoft-standard-WSL2\n",
        )
    });
    assert!(wsl.wsl && !wsl.is_container());
    assert!(
        wsl.kernel_managed_elsewhere(),
        "never install kernels on WSL"
    );
    assert_eq!(wsl.summary(), "WSL");
    let wsl1 = facts(|root, _| {
        write(
            root,
            "proc/version",
            "Linux version 4.4.0-19041-Microsoft\n",
        )
    });
    assert!(wsl1.wsl);
    assert!(guest.kernel_managed_elsewhere());
}
