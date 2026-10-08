//! Ported v2 package/apt/grub tests plus end-to-end install flows.

use super::*;
use crate::bbr::fixture::{release, Fixture, ARCH, KERNEL, PACKAGE, TAG};
use crate::bbr::release::Manifest;
use std::sync::MutexGuard;

fn manifest() -> Manifest {
    Manifest::parse(&release(), TAG, ARCH, false).unwrap()
}

/// The install path installs signal handlers; keep other signal tests out.
fn signals() -> MutexGuard<'static, ()> {
    crate::sys::signal::TEST_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner())
}

fn packages(f: &Fixture) -> Vec<PathBuf> {
    vec![f.dir.join("image.deb"), f.dir.join("headers.deb")]
}

fn request(apply: bool) -> InstallRequest {
    InstallRequest {
        desired: "latest".into(),
        max: false,
        apply,
    }
}

#[test]
fn package_digest_and_size_checked_before_dpkg() {
    let f = Fixture::new();
    let asset = &manifest().assets[0];
    let file = f.dir.join(&asset.name);
    for (contents, message) in [
        (&b"Package"[..], "内核包 SHA-256 不匹配，未执行安装"),
        (&b"wrong size"[..], "内核包类型或大小不匹配，未执行安装"),
    ] {
        std::fs::write(&file, contents).unwrap();
        assert_eq!(
            verify_package(&f.ctx, &file, asset, ARCH)
                .unwrap_err()
                .to_string(),
            message
        );
        assert!(f.calls("dpkg-deb").is_empty());
    }
    std::fs::write(&file, PACKAGE).unwrap();
    verify_package(&f.ctx, &file, asset, ARCH).unwrap();
    assert_eq!(f.calls("dpkg-deb").len(), 3);
    assert!(f.calls("apt-get").is_empty());
    let link = f.dir.join("link.deb");
    std::os::unix::fs::symlink(&file, &link).unwrap();
    assert!(
        verify_package(&f.ctx, &link, asset, ARCH).is_err(),
        "symlinks refused"
    );
}

#[test]
fn package_metadata_must_match_exact_asset() {
    let f = Fixture::new();
    let asset = &manifest().assets[0];
    let file = f.dir.join(&asset.name);
    std::fs::write(&file, PACKAGE).unwrap();
    let mismatch = "内核包 Package/架构/版本/文件名不匹配，未执行安装";
    f.host().deb_arch = "arm64".into();
    assert_eq!(
        verify_package(&f.ctx, &file, asset, ARCH)
            .unwrap_err()
            .to_string(),
        mismatch
    );
    f.host().deb_arch = "amd64".into();
    f.host().deb_package = Some(format!("linux-headers-{KERNEL}"));
    assert!(verify_package(&f.ctx, &file, asset, ARCH).is_err());
    f.host().deb_package = None;
    f.host().deb_version = "7.2.8-2".into();
    assert!(verify_package(&f.ctx, &file, asset, ARCH).is_err());
    f.host().deb_version = "7.2.8 1".into();
    assert!(verify_package(&f.ctx, &file, asset, ARCH).is_err());
    f.host().deb_version = "7.2.8-1".into();
    f.host().fail_deb = true;
    assert!(verify_package(&f.ctx, &file, asset, ARCH).is_err());
    f.host().fail_deb = false;
    let renamed = f.dir.join("other-name.deb");
    std::fs::write(&renamed, PACKAGE).unwrap();
    assert_eq!(
        verify_package(&f.ctx, &renamed, asset, ARCH)
            .unwrap_err()
            .to_string(),
        mismatch
    );
    assert!(f.calls("apt-get").is_empty());
}

#[test]
fn apt_simulation_and_install_never_remove_or_reboot() {
    let _signals = signals();
    let f = Fixture::new();
    f.boot(KERNEL);
    let session = f.session();
    let planned = simulate(&f.ctx, &packages(&f)).unwrap();
    assert_eq!(planned.len(), 2);
    install_kernel(&session, KERNEL, &packages(&f)).unwrap();
    let calls: Vec<_> = f
        .exec
        .calls()
        .into_iter()
        .filter(|c| c.program == "apt-get")
        .collect();
    assert_eq!(calls.len(), 2);
    assert!(calls[0].args.contains(&"--simulate".to_string()));
    for call in &calls {
        assert!(call.args.contains(&"--no-remove".to_string()));
        assert!(call.args.contains(&"--no-install-recommends".to_string()));
        assert!(!call
            .args
            .iter()
            .any(|a| matches!(a.as_str(), "purge" | "remove" | "autoremove")));
        assert!(call
            .env
            .contains(&("DEBIAN_FRONTEND".into(), "noninteractive".into())));
    }
    assert!(calls[1].stream, "install output is streamed");
    assert_eq!(
        calls[1].args[..6],
        [
            "-o",
            "DPkg::Lock::Timeout=60",
            "--no-remove",
            "--no-install-recommends",
            "install",
            "-y"
        ]
    );
    assert_eq!(f.calls("update-grub").len(), 1);
    assert!(f.calls("reboot").is_empty() && f.calls("shutdown").is_empty());
    assert!(f.calls("grub-set-default").is_empty());
}

#[test]
fn apt_failures_stop_before_grub() {
    let _signals = signals();
    for fail_at in [1, 2] {
        let f = Fixture::new();
        f.boot(KERNEL);
        f.host().fail_apt = fail_at;
        let session = f.session();
        let result = simulate(&f.ctx, &packages(&f))
            .and_then(|_| install_kernel(&session, KERNEL, &packages(&f)));
        let err = result.unwrap_err().to_string();
        assert_eq!(f.calls("apt-get").len(), fail_at);
        assert!(f.calls("update-grub").is_empty());
        if fail_at == 2 {
            assert!(
                err.starts_with("内核安装失败；保留旧内核，请检查 apt/dpkg 日志，不要重启"),
                "{err}"
            );
        }
    }
}

#[test]
fn incomplete_installation_or_grub_entry_is_not_success() {
    let _signals = signals();
    for stage in ["unconfigured", "files", "grub", "entry"] {
        let f = Fixture::new();
        f.eligible();
        let expected = match stage {
            "unconfigured" => {
                f.host().installed_status = "install ok unpacked".into();
                "内核包未完成配置，请修复 apt/dpkg 后再重启"
            }
            "files" => {
                f.host().creates_files = false;
                "新内核/initrd/模块不完整；旧内核仍保留，请修复引导后再重启"
            }
            "grub" => {
                f.host().fail_grub = true;
                "更新 GRUB 失败；旧内核仍保留，请修复引导后再重启"
            }
            _ => {
                f.host().adds_entry = false;
                f.write(
                    "/boot/grub/grub.cfg",
                    format!("# linux /boot/vmlinuz-{KERNEL}\nlinux /boot/vmlinuz-{KERNEL}-other\nlinux /boot/vmlinuz-6.1.0-old\n").as_bytes(),
                );
                "GRUB 中未找到新内核；旧内核仍保留，请修复引导后再重启"
            }
        };
        let err = f
            .session()
            .run(crate::bbr::Action::Install(request(true)))
            .unwrap_err()
            .to_string();
        assert!(err.starts_with(expected), "{stage}: {err}");
        assert!(
            !f.ctx.paths.bbr_dir.join("last-install.tsv").exists(),
            "{stage}"
        );
        assert!(f.calls("apt-get").len() == 2, "{stage}");
    }
}

#[test]
fn grub_entry_parsing() {
    let k = KERNEL;
    for (grub, found) in [
        (format!("linux /boot/vmlinuz-{k} root=x"), true),
        (format!("\tlinuxefi\t'/vmlinuz-{k}' ro"), true),
        (format!("linux16 \"/boot/vmlinuz-{k}\""), true),
        (format!("# linux /boot/vmlinuz-{k}"), false),
        (format!("linux /boot/vmlinuz-{k}-other"), false),
        (format!("initrd /boot/initrd.img-{k}"), false),
        (format!("echo linux /boot/vmlinuz-{k}"), false),
    ] {
        assert_eq!(grub_has_kernel(&grub, k), found, "{grub}");
    }
}

#[test]
fn simulation_parsing_and_summary() {
    let text = format!(
        "NOTE: This is only a simulation!\nInst libelf1 [0.188-2] (0.190-1 Debian:12/stable [amd64])\nInst linux-image-{KERNEL} (7.2.8-1 localhost [amd64])\nConf libelf1 (0.190-1 Debian:12/stable [amd64])\n"
    );
    let planned = parse_simulation(&text).unwrap();
    assert_eq!(
        planned,
        [
            Planned {
                package: "libelf1".into(),
                version: "0.190-1".into()
            },
            Planned {
                package: format!("linux-image-{KERNEL}"),
                version: "7.2.8-1".into()
            },
        ]
    );
    assert_eq!(
        simulation_text(&planned, &manifest()),
        format!("apt 预演: 将安装或升级 2 个软件包（含 1 个来自软件源的依赖）\n  libelf1 0.190-1\n  linux-image-{KERNEL} 7.2.8-1")
    );
    assert_eq!(
        simulation_text(&planned[1..], &manifest()),
        format!("apt 预演: 将安装 1 个软件包\n  linux-image-{KERNEL} 7.2.8-1")
    );
    assert_eq!(
        simulation_text(&[], &manifest()),
        "apt 预演: 没有需要安装或升级的软件包"
    );
    assert_eq!(
        parse_simulation("Remv linux-image-6.1.0-old [6.1.0]\n")
            .unwrap_err()
            .to_string(),
        "apt 预演需要删除软件包，已取消安装"
    );
}

#[test]
fn plan_and_record_texts() {
    let m = manifest();
    assert_eq!(
        plan_text(&m, false),
        format!("来源: https://github.com/byJoey/Actions-bbr-v3\nRelease: {TAG}\n目标内核: {KERNEL}\n下载合计: 1 MiB；安装 image + headers，保留全部旧内核。\n保留现有 GRUB 默认项设置；重启时可能需要在控制台手动选择新内核。")
    );
    assert!(plan_text(&m, true).contains("Max 为激进吞吐实验版"));
    let digest = crate::sys::fs::sha256_hex(PACKAGE);
    let record = record_text(&m);
    let lines: Vec<&str> = record.lines().collect();
    assert_eq!(
        lines[0],
        format!("linux-image-{KERNEL}_7.2.8-1_amd64.deb\tsha256:{digest}\t7\thttps://github.com/byJoey/Actions-bbr-v3/releases/download/{TAG}/linux-image-{KERNEL}_7.2.8-1_amd64.deb")
    );
    assert!(lines[1].starts_with(&format!("linux-headers-{KERNEL}_")));
    assert!(record.ends_with('\n'));
}

#[test]
fn preview_needs_no_root_and_changes_nothing() {
    let f = Fixture::new();
    f.eligible();
    let session = crate::bbr::Session {
        ctx: &f.ctx,
        fetcher: &f.github,
        is_root: false,
    };
    session
        .run(crate::bbr::Action::Install(request(false)))
        .unwrap();
    assert_eq!(
        f.github.requests(),
        [
            "https://api.github.com/repos/byJoey/Actions-bbr-v3/releases?per_page=100&page=1",
            "https://api.github.com/repos/byJoey/Actions-bbr-v3/releases/tags/x86_64-7.2.8",
        ]
    );
    assert!(!f.ctx.paths.bbr_dir.exists(), "no lock, no downloads");
    assert!(f.calls("apt-get").is_empty() && f.calls("sysctl").is_empty());
    assert_eq!(
        session
            .run(crate::bbr::Action::Install(request(true)))
            .unwrap_err()
            .to_string(),
        "此操作需要 root 权限"
    );
}

#[test]
fn only_apply_installs_a_missing_curl() {
    // The real transport, as root, on an eligible host without curl.
    let f = Fixture::new();
    f.eligible();
    let curl = crate::bbr::net::CurlFetcher::default();
    let session = crate::bbr::Session {
        ctx: &f.ctx,
        fetcher: &curl,
        is_root: true,
    };
    let err = session
        .run(crate::bbr::Action::Install(request(false)))
        .unwrap_err();
    assert!(err.to_string().ends_with("请先安装 curl"), "{err}");
    assert!(f.calls("apt-get").is_empty(), "a preview mutates nothing");
    assert!(!f.ctx.paths.bbr_dir.exists());

    // `--apply` installs it (the fake apt-get leaves no curl behind).
    let err = session
        .run(crate::bbr::Action::Install(request(true)))
        .unwrap_err();
    assert_eq!(err.to_string(), "安装后仍未找到 curl");
    let apt = f.calls("apt-get");
    assert!(
        apt.iter().any(|a| a.ends_with(&["curl".to_string()])),
        "{apt:?}"
    );
    assert!(f.calls("curl").is_empty());
}

#[test]
fn preview_on_an_ineligible_host_lists_failures_and_fails() {
    let f = Fixture::new();
    f.eligible();
    f.host().virtualized = true;
    let err = f
        .session()
        .run(crate::bbr::Action::Install(request(false)))
        .unwrap_err();
    assert_eq!(
        err.to_string(),
        "容器/WSL 共享宿主机内核，不能在此安装 BBRv3 内核"
    );
    assert_eq!(f.github.requests().len(), 2, "the plan is still shown");
}

#[test]
fn an_ineligible_host_wins_over_release_errors() {
    let f = Fixture::new();
    f.eligible();
    f.host().virtualized = true;
    *f.github.pages.lock().unwrap() =
        vec![serde_json::json!({"message": "API rate limit exceeded"})];
    let err = f
        .session()
        .run(crate::bbr::Action::Install(request(false)))
        .unwrap_err();
    assert_eq!(
        err.to_string(),
        "容器/WSL 共享宿主机内核，不能在此安装 BBRv3 内核"
    );
    f.host().virtualized = false;
    let err = f
        .session()
        .run(crate::bbr::Action::Install(request(false)))
        .unwrap_err();
    assert!(err.to_string().contains("API rate limit exceeded"), "{err}");
}

#[test]
fn user_tags_are_validated_before_any_request() {
    let f = Fixture::new();
    f.eligible();
    for tag in ["../latest", "x86_64-7.2.8-max", "arm64-7.2.8"] {
        let req = InstallRequest {
            desired: tag.into(),
            max: false,
            apply: false,
        };
        let err = f
            .session()
            .run(crate::bbr::Action::Install(req))
            .unwrap_err();
        assert_eq!(err.to_string(), "Release 标签与架构/标准或 Max 类型不匹配");
    }
    assert!(f.github.requests().is_empty());
}

#[test]
fn full_install_downloads_verifies_simulates_confirms_and_records() {
    let _signals = signals();
    let f = Fixture::new();
    f.eligible();
    f.ui.set_assume_yes(false);
    f.ui.set_interactive(true);
    f.ui.push("y");
    let leftover = f.ctx.paths.bbr_dir.join("onebox-download-0123456789abcdef");
    std::fs::create_dir_all(&leftover).unwrap();
    std::fs::write(leftover.join("partial.deb"), b"x").unwrap();
    f.session()
        .run(crate::bbr::Action::Install(request(true)))
        .unwrap();
    assert!(!leftover.exists(), "interrupted staging swept");
    assert_eq!(
        f.ui.prompts(),
        ["安装 x86_64-7.2.8？请确认有 VPS 控制台与快照，安装后需手动重启"]
    );
    let record = std::fs::read_to_string(f.ctx.paths.bbr_dir.join("last-install.tsv")).unwrap();
    assert_eq!(record, record_text(&manifest()));
    use std::os::unix::fs::PermissionsExt;
    let mode = std::fs::metadata(f.ctx.paths.bbr_dir.join("last-install.tsv"))
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600);
    let requests = f.github.requests();
    assert_eq!(requests.len(), 4, "list, release, image, headers");
    assert!(requests[2].ends_with(&format!("linux-image-{KERNEL}_7.2.8-1_amd64.deb")));
    let staging: Vec<_> = std::fs::read_dir(&f.ctx.paths.bbr_dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .filter(|n| n.starts_with("onebox-download-"))
        .collect();
    assert!(staging.is_empty(), "staging removed: {staging:?}");
    let programs = f.programs();
    let simulate_at = f
        .exec
        .calls()
        .iter()
        .position(|c| c.args.contains(&"--simulate".to_string()))
        .unwrap();
    let install_at = f
        .exec
        .calls()
        .iter()
        .position(|c| c.program == "apt-get" && c.args.contains(&"-y".to_string()))
        .unwrap();
    assert!(simulate_at < install_at);
    assert!(!programs
        .iter()
        .any(|p| matches!(p.as_str(), "reboot" | "shutdown")));
}

#[test]
fn declining_after_the_simulation_installs_nothing() {
    let f = Fixture::new();
    f.eligible();
    f.ui.set_assume_yes(false);
    f.ui.set_interactive(true);
    f.ui.push("n");
    let err = f
        .session()
        .run(crate::bbr::Action::Install(request(true)))
        .unwrap_err();
    assert_eq!(err.to_string(), "已取消 BBRv3 内核安装");
    let apt = f.calls("apt-get");
    assert_eq!(apt.len(), 1, "only the simulation ran");
    assert!(apt[0].contains(&"--simulate".to_string()));
    assert!(!f.ctx.paths.bbr_dir.join("last-install.tsv").exists());
    let f = Fixture::new();
    f.eligible();
    f.ui.set_assume_yes(false);
    f.ui.set_interactive(true);
    let err = f
        .session()
        .run(crate::bbr::Action::Install(request(true)))
        .unwrap_err();
    assert!(err.is_cancelled(), "EOF at the prompt cancels (exit 130)");
}

#[test]
fn tampered_downloads_stop_before_dpkg_and_apt() {
    let f = Fixture::new();
    f.eligible();
    *f.github.package.lock().unwrap() = b"evil!!!".to_vec();
    let err = f
        .session()
        .run(crate::bbr::Action::Install(request(true)))
        .unwrap_err();
    assert_eq!(err.to_string(), "内核包 SHA-256 不匹配，未执行安装");
    assert!(f.calls("dpkg-deb").is_empty() && f.calls("apt-get").is_empty());
}

#[test]
fn the_kernel_lock_ignores_the_sysctl_path() {
    let _signals = signals();
    let f = Fixture::new();
    f.eligible();
    let conf = &f.ctx.paths.bbr_conf;
    std::fs::remove_file(conf).unwrap();
    std::fs::create_dir(conf).unwrap();
    f.session()
        .run(crate::bbr::Action::Install(request(true)))
        .unwrap();
    let held = crate::bbr::lock(&f.ctx).unwrap();
    assert_eq!(
        f.session()
            .run(crate::bbr::Action::Install(request(true)))
            .unwrap_err()
            .to_string(),
        "另一个 BBR 操作正在进行；稍后重试"
    );
    drop(held);
}

#[test]
fn space_for_the_staging_directory_is_checked() {
    let f = Fixture::new();
    f.eligible();
    f.host().df_staging = Some("262144".into());
    let err = f
        .session()
        .run(crate::bbr::Action::Install(request(true)))
        .unwrap_err()
        .to_string();
    assert!(
        err.ends_with("空间不足或无法读取 (至少需要 262145 KiB 可用空间)"),
        "{err}"
    );
    assert_eq!(f.github.requests().len(), 2, "nothing downloaded");
}

mod signals;
