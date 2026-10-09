use super::*;
use crate::diag::fixture::{two_core_config, Node};
use crate::diag::CheckStatus;
use crate::domain::config::CoreVersions;
use crate::domain::{fixtures, Protocol};
use crate::error::Error;
use crate::sys::exec::Output;

fn versions(installed: Option<&str>, pin: Option<&str>) -> CoreVersions {
    CoreVersions {
        singbox: installed.map(str::to_owned),
        singbox_pin: pin.map(str::to_owned),
        ..CoreVersions::default()
    }
}

#[test]
fn core_versions_against_pin_and_record() {
    let cases = [
        (
            versions(Some("1.14.2"), None),
            CheckStatus::Pass,
            "版本 1.14.2",
        ),
        (versions(None, None), CheckStatus::Pass, "版本 1.14.2"),
        (
            versions(Some("1.14.2"), Some("1.14.2")),
            CheckStatus::Pass,
            "版本 1.14.2",
        ),
        (
            versions(Some("1.14.2"), Some("latest")),
            CheckStatus::Pass,
            "版本 1.14.2",
        ),
        (
            versions(Some("1.14.2"), Some("v1.12.0")),
            CheckStatus::Warn,
            "已安装 sing-box 1.14.2；更换指定版本请执行 onebox update singbox 1.12.0",
        ),
        (
            versions(Some("1.13.0"), None),
            CheckStatus::Warn,
            "版本 1.14.2，配置记录为 1.13.0；执行 onebox regen 更新记录",
        ),
        // A malformed pin is the update command's problem, not doctor's.
        (
            versions(Some("1.14.2"), Some("bad pin!")),
            CheckStatus::Pass,
            "版本 1.14.2",
        ),
    ];
    for (versions, status, detail) in cases {
        assert_eq!(
            version_check(Core::Singbox, "1.14.2", &versions),
            Check::new("sing-box 内核", status, detail),
            "{versions:?}"
        );
    }
}

#[test]
fn service_verdicts() {
    let failed = || Err(Error::msg("systemctl 执行失败 (5)"));
    let cases: [(Role, bool, Result<bool>, CheckStatus, &str); 7] = [
        (Role::Daemon, true, Ok(true), CheckStatus::Pass, "运行中"),
        (
            Role::Daemon,
            true,
            Ok(false),
            CheckStatus::Warn,
            "运行中，但未设置开机自启；执行 onebox regen",
        ),
        (
            Role::Daemon,
            true,
            failed(),
            CheckStatus::Warn,
            "运行中；无法读取自启状态: systemctl 执行失败 (5)",
        ),
        (
            Role::Daemon,
            false,
            Ok(true),
            CheckStatus::Fail,
            "未运行；查看日志: onebox service onebox-x log",
        ),
        (
            Role::Boot,
            false,
            Ok(true),
            CheckStatus::Pass,
            "已设置开机恢复防火墙与端口跳跃规则",
        ),
        (
            Role::Boot,
            false,
            Ok(false),
            CheckStatus::Warn,
            "未设置开机自启，重启后防火墙与端口跳跃规则不会恢复；执行 onebox regen",
        ),
        (
            Role::Boot,
            false,
            failed(),
            CheckStatus::Warn,
            "无法读取自启状态: systemctl 执行失败 (5)",
        ),
    ];
    for (role, running, enabled, status, detail) in cases {
        assert_eq!(
            service_verdict("onebox-x", role, running, enabled, REGEN),
            Check::new("服务 onebox-x", status, detail)
        );
    }
}

#[test]
fn service_fix_commands_are_the_callers() {
    let check = service_verdict(
        "onebox-frps",
        Role::Daemon,
        true,
        Ok(false),
        "onebox frps start",
    );
    assert_eq!(
        check.detail,
        "运行中，但未设置开机自启；执行 onebox frps start"
    );
}

#[test]
fn required_services_follow_the_configuration() {
    let names = |cfg: &NodeConfig| -> Vec<&'static str> {
        required_services(cfg).into_iter().map(|(n, _)| n).collect()
    };
    let single = fixtures::config(&[(Protocol::Tuic, 443, Core::Singbox)]);
    assert_eq!(names(&single), [SING_BOX, NETWORK]);
    assert_eq!(
        required_services(&single),
        [(SING_BOX, Role::Daemon), (NETWORK, Role::Boot)]
    );
    assert_eq!(names(&two_core_config()), [SING_BOX, XRAY, NETWORK]);

    let mut ip = single.clone();
    ip.subscription = Some(fixtures::ip_subscription(8448));
    assert_eq!(names(&ip), [SUBSCRIPTION, SING_BOX, NETWORK]);

    let mut standalone = single.clone();
    standalone.subscription = Some(fixtures::standalone_subscription(
        "sub.example.org",
        8448,
        crate::domain::config::WebCert::Cloudflare,
    ));
    assert_eq!(
        names(&standalone),
        [SUBSCRIPTION, SUBSCRIPTION_WEB, SING_BOX, NETWORK]
    );

    let reality = fixtures::config(&[(Protocol::VlessReality, 443, Core::Xray)]);
    let site = fixtures::with_site(reality.clone(), "blog.example.org", false);
    assert_eq!(names(&site), [SITE, XRAY, NETWORK]);
    // A site without a REALITY inbound is dormant: no service expected.
    let mut dormant = fixtures::with_site(reality, "blog.example.org", false);
    dormant.inbounds = vec![crate::domain::config::Inbound {
        protocol: Protocol::Tuic,
        port: 443,
        core: Core::Singbox,
    }];
    assert_eq!(names(&dormant), [SING_BOX, NETWORK]);
}

#[test]
fn core_checks_report_unrunnable_binaries_and_missing_configs() {
    let node = Node::new(two_core_config());
    node.fake.on(
        "sing-box",
        &["version"],
        Output::failure(126, "exec format error"),
    );
    let node = node.finish();
    std::fs::remove_file(node.ctx.paths.core_config(Core::Xray)).unwrap();
    let dir = crate::sys::fs::TempDir::new("diag-core").unwrap();
    let checks = core_checks(&node.ctx, &node.cfg, Ok(dir.path()));
    assert_eq!(checks.len(), 3, "{checks:#?}");
    assert_eq!(checks[0].name, "sing-box 内核");
    assert_eq!(checks[0].status, CheckStatus::Fail);
    assert!(
        checks[0].detail.starts_with("无法运行 sing-box"),
        "{:?}",
        checks[0]
    );
    assert_eq!(checks[1], Check::pass("Xray 内核", "版本 26.3.27"));
    assert_eq!(checks[2].name, "Xray 配置");
    assert!(
        checks[2].detail.starts_with("配置文件不存在（"),
        "{:?}",
        checks[2]
    );
}

#[test]
fn without_a_private_directory_the_configuration_is_not_checked() {
    let node = Node::healthy();
    let checks = core_checks(&node.ctx, &node.cfg, Err("权限不足"));
    assert_eq!(
        checks[1],
        Check::warn("sing-box 配置", "无法创建校验临时目录: 权限不足")
    );
    assert!(!node.fake.history().iter().any(|c| c.contains(" check ")));
}
