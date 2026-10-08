//! Ported v2 status test plus rendering and the conflict scan.

use super::*;
use crate::bbr::fixture::Fixture;

#[test]
fn status_performs_no_writes_or_network_calls() {
    let f = Fixture::new();
    let report = collect(&f.ctx);
    assert!(!f.ctx.paths.bbr_dir.exists());
    f.assert_old_runtime();
    for call in f.exec.calls() {
        let program = call.program_name();
        assert!(
            matches!(
                program.as_str(),
                "uname" | "sysctl" | "modinfo" | "tc" | "dpkg-query"
            ),
            "{}",
            call.display()
        );
        if program == "sysctl" {
            assert_eq!(call.args[0], "-n");
        }
    }
    assert!(f.github.requests().is_empty());
    assert_eq!(report.kernel.as_deref(), Some("6.1.0-old"));
    assert_eq!(report.congestion.as_deref(), Some("cubic"));
    assert_eq!(report.disk_bbr.as_deref(), Some("3"));
}

#[test]
fn render_matches_v2_wording() {
    let report = StatusReport {
        kernel: Some("7.2.8-joeyblog-bbrv3".into()),
        congestion: Some("bbr".into()),
        qdisc: Some("fq".into()),
        available: Some("reno cubic bbr".into()),
        loaded_bbr: Some("3".into()),
        disk_bbr: Some("3".into()),
        packages: vec![
            InstalledKernel {
                package: "linux-image-7.2.8-joeyblog-bbrv3".into(),
                running: true,
            },
            InstalledKernel {
                package: "linux-image-7.1.0-joeyblog-bbrv3".into(),
                running: false,
            },
        ],
        persisted: Some(PathBuf::from("/etc/sysctl.d/99-onebox-bbr.conf")),
        interface_queues: Some("qdisc fq 0: dev eth0 root".into()),
        conflicts: Vec::new(),
    };
    assert_eq!(
        render(&report),
        "运行内核: 7.2.8-joeyblog-bbrv3\n\
TCP / 默认队列: bbr / fq\n\
可用拥塞算法: reno cubic bbr\n\
运行中的 tcp_bbr: v3 (仅 TCP 当前算法为 bbr 时启用)\n\
当前内核磁盘上的 tcp_bbr 模块: v3 (不代表已加载)\n\
已安装: linux-image-7.2.8-joeyblog-bbrv3\n\
已安装: linux-image-7.1.0-joeyblog-bbrv3 (当前未运行)\n\
Onebox 持久配置: /etc/sysctl.d/99-onebox-bbr.conf\n\
\n网卡实际队列:\nqdisc fq 0: dev eth0 root\n\
\nTCP BBR 与 Hysteria2/TUIC 的 QUIC 拥塞控制不同；默认队列不等于现有网卡实际队列。"
    );
    assert_eq!(
        render(&StatusReport::default()),
        "运行内核: 未知\nTCP / 默认队列: 未知 / 未知\n可用拥塞算法: 未知\n运行中的 tcp_bbr 版本: 未知 (不能仅凭 bbr 名称判断 v3)\n\nTCP BBR 与 Hysteria2/TUIC 的 QUIC 拥塞控制不同；默认队列不等于现有网卡实际队列。"
    );
}

#[test]
fn installed_kernels_are_parsed_from_dpkg_query() {
    let f = Fixture::new();
    f.host().installed_status = "linux-image-6.1.0-old\tinstall ok installed\nlinux-image-7.2.8-joeyblog-bbrv3\tinstall ok installed\nlinux-image-7.0-joeyblog-bbrv3\tdeinstall ok config-files\n".into();
    f.write("/sys/module/tcp_bbr/version", b"2\n");
    let report = collect(&f.ctx);
    assert_eq!(
        report.packages,
        [
            InstalledKernel {
                package: "linux-image-6.1.0-old".into(),
                running: true
            },
            InstalledKernel {
                package: "linux-image-7.2.8-joeyblog-bbrv3".into(),
                running: false
            },
        ]
    );
    assert_eq!(report.loaded_bbr.as_deref(), Some("2"));
    assert!(render(&report).contains("运行中的 tcp_bbr 版本: 2 (不能仅凭 bbr 名称判断 v3)"));
    assert_eq!(report.persisted, Some(f.ctx.paths.bbr_conf.clone()));
}

#[test]
fn key_detection_handles_slashes_ignore_prefix_and_comments() {
    for (text, expected) in [
        ("net.ipv4.tcp_congestion_control = bbr\n", true),
        ("net/core/default_qdisc=fq\n", true),
        ("-net.core.default_qdisc = cake\n", true),
        ("  net.ipv4.tcp_congestion_control=cubic", true),
        ("# net.ipv4.tcp_congestion_control = bbr\n", false),
        ("; net.core.default_qdisc = fq\n", false),
        ("net.ipv4.tcp_rmem = 4096 131072\n", false),
        ("", false),
    ] {
        assert_eq!(sets_tcp_keys(text), expected, "{text:?}");
    }
}

#[test]
fn conflicts_cover_every_sysctl_dir_with_masking_and_order() {
    let f = Fixture::new();
    let cc = b"net.ipv4.tcp_congestion_control = cubic\n";
    f.write("/etc/sysctl.d/10-early.conf", cc);
    f.write("/etc/sysctl.d/README", cc);
    f.write(
        "/usr/lib/sysctl.d/50-default.conf",
        b"kernel.pid_max = 4194304\n",
    );
    f.write(
        "/usr/lib/sysctl.d/90-vendor.conf",
        b"net.core.default_qdisc = fq_codel\n",
    );
    f.write("/run/sysctl.d/90-vendor.conf", b"# masks the vendor file\n");
    f.write("/lib/sysctl.d/99-zz-late.conf", cc);
    f.write("/usr/local/lib/sysctl.d/99-onebox-bbr.conf", cc);
    f.write("/etc/sysctl.conf", b"net.core.default_qdisc=fq\n");
    std::os::unix::fs::symlink(
        f.at("/etc/sysctl.conf"),
        f.at("/etc/sysctl.d/99-sysctl.conf"),
    )
    .unwrap();
    let found = conflicts(&f.ctx);
    assert_eq!(
        found,
        [
            Conflict {
                path: "/etc/sysctl.d/10-early.conf".into(),
                overrides: false
            },
            Conflict {
                path: "/etc/sysctl.d/99-sysctl.conf".into(),
                overrides: true
            },
            Conflict {
                path: "/lib/sysctl.d/99-zz-late.conf".into(),
                overrides: true
            },
        ],
        "masked vendor file, our own name and the sysctl.conf duplicate are skipped"
    );
    let notices = conflict_notices(&found);
    assert_eq!(
        notices[0],
        "其他 TCP/队列配置: /etc/sysctl.d/10-early.conf；请核对启动时覆盖关系，Onebox 不修改此文件"
    );
    assert_eq!(
        notices[1],
        "其他 TCP/队列配置: /etc/sysctl.d/99-sysctl.conf（启动时晚于 Onebox 配置加载，会覆盖其设置）；Onebox 不修改此文件"
    );
}

#[test]
fn a_plain_sysctl_conf_is_reported_as_loaded_last() {
    let f = Fixture::new();
    f.write(
        "/etc/sysctl.conf",
        b"net.ipv4.tcp_congestion_control=cubic\n",
    );
    assert_eq!(
        conflicts(&f.ctx),
        [Conflict {
            path: "/etc/sysctl.conf".into(),
            overrides: true
        }]
    );
    assert!(conflicts(&Fixture::new().ctx).is_empty());
}
