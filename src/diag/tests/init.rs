//! End-to-end diagnoses under OpenRC and without an init system: service
//! state, autostart and the cron daemon come from different sources there.

use super::super::fixture::{acme_config, check, with_status, Cron, Node, CRON_PID};
use super::super::*;
use crate::host::init::InitSystem;
use crate::sys::exec::Output;
use std::fs;

const SERVICES: [&str; 3] = [
    "服务 onebox-sing-box",
    "服务 onebox-xray",
    "服务 onebox-network",
];

fn statuses(checks: &[Check], names: &[&str]) -> Vec<CheckStatus> {
    names.iter().map(|n| check(checks, n).status).collect()
}

#[test]
fn openrc_services_runlevel_and_cron_script() {
    let node = Node::with_init(acme_config(), InitSystem::Openrc).finish();
    let checks = node.diagnose().checks;
    assert!(
        with_status(&checks, CheckStatus::Fail).is_empty()
            && with_status(&checks, CheckStatus::Warn).is_empty(),
        "{checks:#?}"
    );
    assert_eq!(check(&checks, "证书自动续期").detail, "已安装每日续期任务");
    let history = node.fake.history();
    for call in [
        "rc-service onebox-sing-box status",
        "rc-service onebox-xray status",
        "rc-update show default",
    ] {
        assert!(history.iter().any(|c| c == call), "{call}: {history:?}");
    }
    assert!(
        !history
            .iter()
            .any(|c| c == "rc-service onebox-network status"),
        "the boot oneshot is never asked whether it runs: {history:?}"
    );
    assert!(!history.iter().any(|c| c.starts_with("systemctl")));
}

#[test]
fn openrc_stopped_service_missing_runlevel_entry_and_stopped_cron() {
    let node = Node::with_init(acme_config(), InitSystem::Openrc);
    node.fake
        .on(
            "rc-service",
            &["onebox-xray", "status"],
            Output::failure(3, " * status: stopped\n"),
        )
        .on(
            "rc-update",
            &["show", "default"],
            Output::success("   onebox-xray | default\n      sshd | default\n"),
        );
    for script in ["crond", "cronie", "dcron", "cron"] {
        node.fake
            .on("rc-service", &[script, "status"], Output::failure(3, ""));
    }
    let node = node.finish();
    let checks = node.diagnose().checks;
    assert_eq!(
        statuses(&checks, &SERVICES),
        [CheckStatus::Warn, CheckStatus::Fail, CheckStatus::Warn]
    );
    assert_eq!(
        check(&checks, "服务 onebox-sing-box").detail,
        "运行中，但未设置开机自启；执行 onebox regen"
    );
    let renewal = check(&checks, "证书自动续期");
    assert_eq!(renewal.status, CheckStatus::Warn);
    assert!(renewal.detail.starts_with("cron 未运行"), "{renewal:?}");
}

#[test]
fn no_init_supervised_daemons_boot_lines_and_cron_process() {
    let node = Node::with_init(acme_config(), InitSystem::None).finish();
    let checks = node.diagnose().checks;
    assert!(
        with_status(&checks, CheckStatus::Fail).is_empty()
            && with_status(&checks, CheckStatus::Warn).is_empty(),
        "{checks:#?}"
    );
    assert_eq!(
        check(&checks, "服务 onebox-network").detail,
        "已设置开机恢复防火墙与端口跳跃规则",
        "a boot oneshot passes without a running process"
    );
    let history = node.fake.history();
    assert!(
        !history
            .iter()
            .any(|c| c.starts_with("systemctl") || c.starts_with("rc-")),
        "service state comes from PID records and the crontab: {history:?}"
    );
}

#[test]
fn no_init_stopped_daemon_missing_boot_lines_and_no_cron_process() {
    let mut node = Node::with_init(acme_config(), InitSystem::None);
    node.stopped = vec!["onebox-xray"];
    let node = node.finish();
    let checks = node.diagnose().checks;
    assert_eq!(
        statuses(&checks, &SERVICES),
        [CheckStatus::Pass, CheckStatus::Fail, CheckStatus::Pass]
    );
    fs::remove_dir_all(node.ctx.paths.system(&format!("/proc/{CRON_PID}"))).unwrap();
    let renewal = check(&node.diagnose().checks, "证书自动续期").clone();
    assert_eq!(renewal.status, CheckStatus::Warn);
    assert!(renewal.detail.starts_with("cron 未运行"), "{renewal:?}");

    // A crontab without the boot lines: no autostart, no renewal.
    let mut empty = Node::with_init(acme_config(), InitSystem::None);
    empty.cron = Cron::Empty;
    let empty = empty.finish();
    let checks = empty.diagnose().checks;
    assert_eq!(
        statuses(&checks, &SERVICES),
        [CheckStatus::Warn, CheckStatus::Warn, CheckStatus::Warn]
    );
    assert_eq!(check(&checks, "证书自动续期").status, CheckStatus::Fail);
}

/// Without init and `crontab`, the autostart advice is not `onebox regen`
/// (which cannot help) but what can.
#[test]
fn no_init_without_crontab_explains_what_restores_services() {
    let mut node = Node::with_init(acme_config(), InitSystem::None);
    node.cron = Cron::Missing;
    let node = node.finish();
    let checks = node.diagnose().checks;
    for name in SERVICES {
        let found = check(&checks, name);
        assert_eq!(found.status, CheckStatus::Warn, "{found:?}");
        assert!(
            found.detail.ends_with(crate::diag::node::NO_AUTOSTART_HINT),
            "{found:?}"
        );
        assert!(!found.detail.contains("执行 onebox regen；"), "{found:?}");
    }
    assert_eq!(
        check(&checks, "服务 onebox-network").detail,
        format!(
            "重启后防火墙与端口跳跃规则不会自动恢复；{}",
            crate::diag::node::NO_AUTOSTART_HINT
        )
    );
}
