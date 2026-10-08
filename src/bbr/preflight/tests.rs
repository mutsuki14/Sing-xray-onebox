//! Ported v2 preflight tests plus the per-check report.

use super::*;
use crate::bbr::fixture::{Fixture, OLD_KERNEL};

fn fields(id: &str, version: &str, codename: &str) -> BTreeMap<String, String> {
    BTreeMap::from([
        ("ID".into(), id.into()),
        ("VERSION_ID".into(), version.into()),
        ("VERSION_CODENAME".into(), codename.into()),
    ])
}

#[test]
fn os_gates_support_release_numbers_and_debian_codenames() {
    for (id, version, name) in [
        ("debian", "12", ""),
        ("debian", "13.1", ""),
        ("ubuntu", "24.04", ""),
        ("ubuntu", "26.04", ""),
        ("debian", "", "trixie"),
        ("debian", "", "sid"),
        ("debian", "", "bookworm"),
    ] {
        supported_os(&fields(id, version, name)).unwrap_or_else(|e| panic!("{id} {version}: {e}"));
    }
    for (id, version, name) in [
        ("debian", "11", ""),
        ("ubuntu", "22.04", ""),
        ("ubuntu", "24.03", ""),
        ("alpine", "3.23", ""),
        ("debian", "", "unknown"),
        ("debian", "12;reboot", ""),
        ("ubuntu", "", "noble"),
        ("linuxmint", "22", ""),
    ] {
        assert!(
            supported_os(&fields(id, version, name)).is_err(),
            "{id} {version} {name}"
        );
    }
    assert_eq!(
        supported_os(&fields("debian", "", "unknown"))
            .unwrap_err()
            .to_string(),
        "系统版本未知，需要 Debian 12+ / Ubuntu 24.04+"
    );
    assert_eq!(
        supported_os(&fields("debian", "11", ""))
            .unwrap_err()
            .to_string(),
        "BBRv3 内核安装仅支持 Debian 12+ / Ubuntu 24.04+ (其他系统仍可启用自带 BBR)"
    );
}

#[test]
fn os_release_quotes_are_stripped_without_escapes() {
    let parsed = parse_os_release("ID=\"debian\"\nVERSION_ID='12'\nNAME=\"a\\\"b\"\nBAD\nX=\"\n");
    assert_eq!(parsed["ID"], "debian");
    assert_eq!(parsed["VERSION_ID"], "12");
    assert_eq!(parsed["NAME"], "a\\\"b");
    assert_eq!(parsed["X"], "\"");
}

#[test]
fn rejects_containers_and_wsl() {
    let f = Fixture::new();
    assert!(!is_container(&f.ctx));
    f.host().virtualized = true;
    assert!(is_container(&f.ctx));
    f.host().virtualized = false;
    f.write(
        "/proc/version",
        b"Linux version 6.6 Microsoft-standard-WSL2",
    );
    assert!(is_container(&f.ctx));
    std::fs::remove_file(f.at("/proc/version")).unwrap();
    f.write("/.dockerenv", b"");
    assert!(is_container(&f.ctx));
    std::fs::remove_file(f.at("/.dockerenv")).unwrap();
    f.write("/proc/1/cgroup", b"0::/kubepods/besteffort/pod1\n");
    assert!(is_container(&f.ctx));
    std::fs::remove_file(f.at("/proc/1/cgroup")).unwrap();
    f.write("/proc/vz/x", b"");
    assert!(is_container(&f.ctx), "OpenVZ");
    f.write("/proc/bc/x", b"");
    assert!(!is_container(&f.ctx), "OpenVZ host node");
}

#[test]
fn kernel_build_hosts_named_docker_are_not_containers() {
    let f = Fixture::new();
    f.write(
        "/proc/version",
        b"Linux version 6.1.0 (builder@docker-lxc-farm) (gcc 12) #1 SMP",
    );
    f.write("/proc/1/cgroup", b"0::/init.scope\n");
    assert!(!is_container(&f.ctx));
}

#[test]
fn requires_boot_fallback_and_rejects_device_trees() {
    for (missing, detail) in [
        ("/boot/grub/grub.cfg", "缺少 /boot/grub/grub.cfg"),
        ("/boot/vmlinuz-6.1.0-old", "缺少 /boot/vmlinuz-6.1.0-old"),
        (
            "/boot/initrd.img-6.1.0-old",
            "缺少 /boot/initrd.img-6.1.0-old",
        ),
        ("/lib/modules/6.1.0-old", "缺少 /lib/modules/6.1.0-old"),
    ] {
        let f = Fixture::new();
        f.boot(OLD_KERNEL);
        boot_ready(&f.ctx, OLD_KERNEL).unwrap();
        let path = f.at(missing);
        if path.is_dir() {
            std::fs::remove_dir(path).unwrap();
        } else {
            std::fs::remove_file(path).unwrap();
        }
        let err = boot_ready(&f.ctx, OLD_KERNEL).unwrap_err().to_string();
        assert!(
            err.starts_with("仅支持已有 GRUB、当前内核/模块/initrd 可供回退的常规 VPS"),
            "{err}"
        );
        assert!(err.ends_with(&format!("（{detail}）")), "{err}");
    }
    let f = Fixture::new();
    f.boot(OLD_KERNEL);
    f.write("/boot/grub/grub.cfg", b"");
    assert!(boot_ready(&f.ctx, OLD_KERNEL).is_err(), "empty grub.cfg");
    f.boot(OLD_KERNEL);
    std::fs::create_dir_all(f.at("/proc/device-tree")).unwrap();
    assert!(boot_ready(&f.ctx, OLD_KERNEL)
        .unwrap_err()
        .to_string()
        .contains("设备树"));
    assert!(boot_ready(&f.ctx, "../evil").is_err());
    assert!(boot_ready(&f.ctx, "").is_err());
}

#[test]
fn secure_boot_fails_closed() {
    let f = Fixture::new();
    assert_eq!(secure_boot_disabled(&f.ctx).unwrap(), "传统 BIOS 引导");
    let vars = f.at("/sys/firmware/efi/efivars");
    std::fs::create_dir_all(&vars).unwrap();
    assert_eq!(
        secure_boot_disabled(&f.ctx).unwrap_err().to_string(),
        "Secure Boot 状态不明，不能安装未经本机信任签名的内核"
    );
    std::fs::write(vars.join("SecureBoot-test"), [0, 0, 0, 0, 0]).unwrap();
    secure_boot_disabled(&f.ctx).unwrap();
    for byte in [1, 2] {
        std::fs::write(vars.join("SecureBoot-test"), [0, 0, 0, 0, byte]).unwrap();
        assert!(secure_boot_disabled(&f.ctx).is_err());
    }
    std::fs::write(vars.join("SecureBoot-test"), [0, 0, 0, 0, 1]).unwrap();
    assert_eq!(
        secure_boot_disabled(&f.ctx).unwrap_err().to_string(),
        "Secure Boot 已启用，不能安装未经本机信任签名的内核"
    );
    std::fs::write(vars.join("SecureBoot-test"), [0, 0, 0, 0]).unwrap();
    assert!(secure_boot_disabled(&f.ctx).is_err(), "short variable");
    f.host().secure_boot = Some("SecureBoot disabled\n".into());
    secure_boot_disabled(&f.ctx).unwrap();
    f.host().secure_boot = Some("SecureBoot disabled\nSecureBoot enabled\n".into());
    assert!(
        secure_boot_disabled(&f.ctx).is_err(),
        "contradictory mokutil"
    );
    f.host().secure_boot = Some("SecureBoot disabled\n".into());
    std::fs::write(vars.join("SecureBoot-test"), [0, 0, 0, 0, 1]).unwrap();
    assert!(
        secure_boot_disabled(&f.ctx).is_err(),
        "enabled efivar wins over mokutil"
    );
}

#[test]
fn insufficient_or_unknown_space_rejected() {
    let f = Fixture::new();
    let root = f.ctx.paths.system("/");
    space(&f.ctx, &root, ROOT_MIN_KIB).unwrap();
    for value in ["0", "524287", "unknown", "-1"] {
        f.host().df_available = value.into();
        assert_eq!(
            space(&f.ctx, &f.at("/boot"), BOOT_MIN_KIB)
                .unwrap_err()
                .to_string(),
            "/boot 空间不足或无法读取 (至少需要 524288 KiB 可用空间)"
        );
    }
    f.host().df_available = "524288".into();
    space(&f.ctx, &f.at("/boot"), BOOT_MIN_KIB).unwrap();
    assert!(f.calls("df").iter().all(|a| a[..2] == ["-Pk", "--"]));
}

#[test]
fn eligible_host_passes_every_check_in_order() {
    let f = Fixture::new();
    f.eligible();
    let report = run(&f.ctx);
    assert_eq!(report.arch, Some(crate::bbr::release::X86_64));
    assert!(report.passed(), "{}", report.render());
    assert_eq!(report.result().unwrap(), crate::bbr::release::X86_64);
    let labels: Vec<&str> = report.checks.iter().map(|c| c.label).collect();
    assert_eq!(
        labels,
        [
            "运行环境",
            "系统版本",
            "内核架构",
            "安装工具",
            "软件包架构",
            "引导回退",
            "Secure Boot",
            "/boot 空间",
            "根分区空间"
        ]
    );
    assert!(report
        .render()
        .starts_with("[通过] 运行环境: 独立内核\n[通过] 系统版本: Debian 12\n"));
}

#[test]
fn every_failing_check_is_reported_and_the_first_is_the_error() {
    let f = Fixture::new();
    f.host().virtualized = true;
    f.write("/etc/os-release", b"ID=alpine\nVERSION_ID=3.20\n");
    f.host().df_available = "1".into();
    let report = run(&f.ctx);
    assert!(!report.passed());
    assert_eq!(
        report.first_failure(),
        Some("容器/WSL 共享宿主机内核，不能在此安装 BBRv3 内核")
    );
    let rendered = report.render();
    assert!(
        rendered.contains("[失败] 系统版本: BBRv3 内核安装仅支持"),
        "{rendered}"
    );
    assert!(rendered.contains("[失败] 引导回退"), "{rendered}");
    assert!(rendered.contains("[失败] /boot 空间"), "{rendered}");
    assert!(
        rendered.contains("[通过] 内核架构: x86_64 / amd64"),
        "{rendered}"
    );
    assert_eq!(
        report.result().unwrap_err().to_string(),
        "容器/WSL 共享宿主机内核，不能在此安装 BBRv3 内核"
    );
}

#[test]
fn missing_tools_and_architecture_skip_the_dpkg_check() {
    let dir = crate::sys::fs::TempDir::new("bbr-pre").unwrap();
    let (ctx, exec, _) = Ctx::test(dir.path());
    exec.on(
        "uname",
        &["-m"],
        crate::sys::exec::Output::success("riscv64\n"),
    );
    let report = run(&ctx);
    assert_eq!(report.arch, None);
    let dpkg = report
        .checks
        .iter()
        .find(|c| c.label == "软件包架构")
        .unwrap();
    assert!(matches!(dpkg.outcome, Outcome::Skip(_)));
    assert!(report.render().contains("[跳过] 软件包架构"));
    assert!(report
        .render()
        .contains("[失败] 安装工具: 安装 BBRv3 缺少 apt-get，请先安装对应系统包"));
    assert!(exec.history().iter().all(|c| !c.starts_with("dpkg ")));
    assert!(report.render().contains("无法读取 /etc/os-release"));
}

#[test]
fn userspace_architecture_must_match() {
    let f = Fixture::new();
    f.eligible();
    f.host().machine = "aarch64".into();
    let report = run(&f.ctx);
    assert_eq!(
        report.first_failure(),
        Some("系统用户空间架构与内核架构不匹配")
    );
}
