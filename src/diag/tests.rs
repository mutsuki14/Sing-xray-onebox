//! End-to-end diagnoses of fixture nodes (FakeExec + isolated layouts).

use super::fixture::{
    acme_config, check, interrupted, signals, two_core_config, with_status, x509_output, Cron,
    Node, DAY, NOW,
};
use super::*;
use crate::apply::journal::{self, Journal, Phase};
use crate::apply::program_journal::{self, ProgramJournal};
use crate::apply::snapshot::Snapshot;
use crate::domain::config::{ProxyCertMode, ProxyTls};
use crate::domain::Core;
use crate::error::Error;
use crate::host::cron::CronSnapshot;
use crate::sys::exec::Output;
use std::fs;

fn names(checks: &[Check]) -> Vec<&str> {
    checks.iter().map(|c| c.name.as_str()).collect()
}

#[test]
fn healthy_node_passes_every_applicable_check_in_order() {
    let node = Node::healthy();
    let mut streamed = Vec::new();
    let _signals = signals();
    let diagnosis = node
        .doctor()
        .diagnose(&[], &mut |c| streamed.push(c.clone()))
        .unwrap();
    assert_eq!(
        names(&diagnosis.checks),
        [
            "节点配置",
            "未完成事务",
            "管理程序",
            "sing-box 内核",
            "sing-box 配置",
            "Xray 内核",
            "Xray 配置",
            "服务 onebox-sing-box",
            "服务 onebox-xray",
            "服务 onebox-network",
            "代理证书",
            "防火墙台账",
        ]
    );
    assert_eq!(streamed, diagnosis.checks, "sink sees every check in order");
    let not_passed: Vec<&Check> = diagnosis
        .checks
        .iter()
        .filter(|c| c.status != CheckStatus::Pass)
        .collect();
    assert!(not_passed.is_empty(), "{not_passed:#?}");
    assert_eq!(
        check(&diagnosis.checks, "节点配置").detail,
        "3 个协议：vless-reality、hysteria2、vless-xhttp"
    );
    assert_eq!(
        check(&diagnosis.checks, "sing-box 内核").detail,
        "版本 1.14.2"
    );
    assert!(diagnosis.tally().verdict().is_ok());
}

#[test]
fn core_checks_never_create_the_run_check_directory() {
    let node = Node::healthy();
    node.diagnose();
    assert!(!node.ctx.paths.run.join("check").exists(), "G42");
    let singbox_check = node
        .fake
        .calls()
        .into_iter()
        .find(|c| c.args.first().map(String::as_str) == Some("check"))
        .unwrap();
    let workdir = std::path::PathBuf::from(&singbox_check.args[2]);
    assert!(workdir.starts_with(std::env::temp_dir()), "{workdir:?}");
    assert!(!workdir.exists(), "the private directory is removed");
    assert_eq!(singbox_check.args[1], "-D");
}

#[test]
fn a_broken_core_configuration_fails_with_the_core_message() {
    let node = Node::new(two_core_config());
    node.fake.on(
        "xray",
        &["run", "-test"],
        Output::failure(23, "Xray 26.3.27 (Xray, Penetrates Everything.)\nFailed to start: main: failed to load config files: invalid port\n"),
    );
    let node = node.finish();
    let diagnosis = node.diagnose();
    let xray = check(&diagnosis.checks, "Xray 配置");
    assert_eq!(xray.status, CheckStatus::Fail);
    assert_eq!(
        xray.detail,
        "Xray 配置校验失败: Failed to start: main: failed to load config files: invalid port"
    );
    assert_eq!(
        with_status(&diagnosis.checks, CheckStatus::Fail),
        ["Xray 配置"]
    );
    assert_eq!(
        diagnosis.tally().verdict().unwrap_err().to_string(),
        "体检发现 1 个需要处理的问题"
    );
}

#[test]
fn a_missing_core_binary_skips_its_configuration_check() {
    let node = Node::healthy();
    fs::remove_file(node.ctx.paths.core_bin(Core::Xray)).unwrap();
    let checks = node.diagnose().checks;
    let core = check(&checks, "Xray 内核");
    assert_eq!(core.status, CheckStatus::Fail);
    assert!(core.detail.starts_with("未安装（"), "{}", core.detail);
    assert!(!names(&checks).contains(&"Xray 配置"));
}

#[test]
fn certificates_expired_expiring_and_unreadable() {
    let cases = [
        (NOW - DAY, CheckStatus::Fail, "已于 "),
        (NOW + 3 * DAY, CheckStatus::Warn, "将在 3 天内到期"),
        (NOW + 30 * DAY, CheckStatus::Pass, "有效期至 "),
    ];
    for (expires, status, text) in cases {
        let node = Node::new(two_core_config());
        node.fake.on(
            "openssl",
            &["x509", "-in", &node.proxy_cert()],
            x509_output("www.bing.com", expires),
        );
        let node = node.finish();
        let cert = check(&node.diagnose().checks, "代理证书").clone();
        assert_eq!(cert.status, status, "{cert:?}");
        assert!(cert.detail.contains(text), "{cert:?}");
    }
}

#[test]
fn missing_openssl_is_a_warning_not_an_abort() {
    let node = Node::new(two_core_config());
    node.fake.on_fn(
        |cmd| cmd.program == "openssl",
        |_| Err(Error::msg("未找到程序 openssl")),
    );
    let node = node.finish();
    let diagnosis = node.diagnose();
    let cert = check(&diagnosis.checks, "代理证书");
    assert_eq!(cert.status, CheckStatus::Warn);
    assert_eq!(cert.detail, "无法检查证书: 未找到程序 openssl");
    assert!(diagnosis.tally().verdict().is_ok(), "D-8.1#27");
    assert_eq!(names(&diagnosis.checks).last(), Some(&"防火墙台账"));
}

#[test]
fn a_certificate_openssl_rejects_fails() {
    let node = Node::new(two_core_config());
    node.fake.on(
        "openssl",
        &["x509", "-in", &node.proxy_cert()],
        Output::failure(
            1,
            "Could not read certificate from /etc/onebox/tls/cert.pem\nUnable to load certificate\n",
        ),
    );
    let node = node.finish();
    let diagnosis = node.diagnose();
    assert_eq!(
        check(&diagnosis.checks, "代理证书"),
        &Check::fail(
            "代理证书",
            "证书无法解析: Could not read certificate from /etc/onebox/tls/cert.pem；执行 onebox cert renew proxy"
        )
    );
    assert!(diagnosis.tally().verdict().is_err());
}

#[test]
fn a_missing_certificate_fails() {
    let node = Node::healthy();
    fs::remove_file(crate::cert::CertDir::proxy(&node.ctx.paths).cert()).unwrap();
    let cert = check(&node.diagnose().checks, "代理证书").clone();
    assert_eq!(cert.status, CheckStatus::Fail);
    assert!(cert.detail.starts_with("证书不存在（"), "{cert:?}");
}

#[test]
fn pending_config_and_program_journals_fail() {
    let node = Node::healthy();
    let paths = &node.ctx.paths;
    let mut j = Journal::new(
        "添加协议",
        Some(node.cfg.clone()),
        vec![],
        vec![],
        CronSnapshot::default(),
        Snapshot::default(),
    );
    journal::write(paths, &j).unwrap();
    j.set_phase(paths, Phase::StartCores).unwrap();
    let pending = check(&node.diagnose().checks, "未完成事务").clone();
    assert_eq!(pending.status, CheckStatus::Fail);
    assert_eq!(
        pending.detail,
        "有未完成事务（配置变更「添加协议」停在启动内核阶段）；执行 onebox recover"
    );

    let update = ProgramJournal::new(
        format!("{}{}", program_journal::WORK_PREFIX, "0".repeat(24)),
        None,
        "a".repeat(64),
        None,
    );
    program_journal::write(paths, &update).unwrap();
    let both = check(&node.diagnose().checks, "未完成事务").detail.clone();
    assert_eq!(
        both,
        "有未完成事务（配置变更「添加协议」停在启动内核阶段，程序自更新）；执行 onebox recover"
    );
}

#[test]
fn a_running_operation_turns_failures_into_warnings() {
    let node = Node::new(two_core_config());
    node.fake.on(
        "systemctl",
        &["is-active", "--quiet", "onebox-xray"],
        Output::failure(3, ""),
    );
    let node = node.finish();
    let paths = &node.ctx.paths;
    let j = Journal::new(
        "添加协议",
        Some(node.cfg.clone()),
        vec![],
        vec![],
        CronSnapshot::default(),
        Snapshot::default(),
    );
    journal::write(paths, &j).unwrap();
    let held = crate::sys::lock::FileLock::acquire(&paths.lock(), "busy").unwrap();
    let diagnosis = node.diagnose();
    assert!(diagnosis.operation_running);
    assert!(with_status(&diagnosis.checks, CheckStatus::Fail).is_empty());
    assert_eq!(
        check(&diagnosis.checks, "未完成事务").status,
        CheckStatus::Warn
    );
    assert_eq!(
        check(&diagnosis.checks, "服务 onebox-xray"),
        &Check::warn(
            "服务 onebox-xray",
            "配置操作进行中，可能是暂时的: 未运行；查看日志: onebox service onebox-xray log"
        )
    );
    {
        let _signals = signals();
        assert!(report::run_doctor(&node.doctor(), &[failing_provider]).is_ok());
    }

    drop(held);
    let after = node.diagnose();
    assert!(!after.operation_running);
    assert_eq!(
        with_status(&after.checks, CheckStatus::Fail),
        ["未完成事务", "服务 onebox-xray"]
    );
}

#[test]
fn a_corrupt_journal_is_a_failure_line_not_an_abort() {
    let node = Node::healthy();
    let dir = node.ctx.paths.transaction();
    fs::create_dir_all(&dir).unwrap();
    fs::write(dir.join("journal.json"), "{broken").unwrap();
    let diagnosis = node.diagnose();
    let pending = check(&diagnosis.checks, "未完成事务");
    assert_eq!(pending.status, CheckStatus::Fail);
    assert!(
        pending.detail.starts_with("事务记录无法读取: "),
        "{pending:?}"
    );
    assert!(names(&diagnosis.checks).contains(&"代理证书"), "D-8.1#28");
}

#[test]
fn renewal_cron_line_is_required_for_acme_certificates() {
    let healthy = Node::new(acme_config()).finish();
    let renewal = check(&healthy.diagnose().checks, "证书自动续期").clone();
    assert_eq!(renewal.status, CheckStatus::Pass, "{renewal:?}");

    for (cron, detail) in [
        (
            Cron::Empty,
            "缺少每日续期任务，ACME 证书不会自动续期；执行 onebox regen",
        ),
        (Cron::Missing, "未找到 crontab，ACME 证书不会自动续期"),
    ] {
        let mut node = Node::new(acme_config());
        node.cron = cron;
        let node = node.finish();
        let renewal = check(&node.diagnose().checks, "证书自动续期").clone();
        assert_eq!(renewal.status, CheckStatus::Fail, "{cron:?}");
        assert_eq!(renewal.detail, detail);
    }
}

#[test]
fn renewal_cron_line_is_recommended_for_custom_certificates() {
    let mut cfg = two_core_config();
    cfg.tls = Some(ProxyTls {
        mode: ProxyCertMode::Custom {
            domain: "proxy.example.net".into(),
            cert: "/srv/certs/fullchain.pem".into(),
            key: "/srv/certs/privkey.pem".into(),
        },
        pinned: true,
    });
    let mut node = Node::new(cfg);
    node.cron = Cron::Empty;
    let node = node.finish();
    let renewal = check(&node.diagnose().checks, "证书自动续期").clone();
    assert_eq!(renewal.status, CheckStatus::Warn);
    assert!(renewal.detail.contains("外部证书更新后不会自动部署"));
}

#[test]
fn self_signed_only_nodes_have_no_renewal_check() {
    let node = Node::healthy();
    assert!(!names(&node.diagnose().checks).contains(&"证书自动续期"));
}

#[test]
fn stopped_disabled_and_unconfigured_services() {
    let node = Node::new(two_core_config());
    node.fake
        .on(
            "systemctl",
            &["is-active", "--quiet", "onebox-xray"],
            Output::failure(3, ""),
        )
        .on(
            "systemctl",
            &["is-enabled", "onebox-sing-box"],
            Output::failure(1, "disabled\n"),
        )
        .on(
            "systemctl",
            &["is-enabled", "onebox-network"],
            Output::failure(1, "disabled\n"),
        );
    let node = node.finish();
    let checks = node.diagnose().checks;
    let xray = check(&checks, "服务 onebox-xray");
    assert_eq!(
        (xray.status, xray.detail.as_str()),
        (
            CheckStatus::Fail,
            "未运行；查看日志: onebox service onebox-xray log"
        )
    );
    assert_eq!(
        check(&checks, "服务 onebox-sing-box").status,
        CheckStatus::Warn
    );
    assert_eq!(
        check(&checks, "服务 onebox-network").status,
        CheckStatus::Warn
    );

    fs::remove_file(crate::host::service::unit_file(
        &node.ctx.paths,
        "onebox-network",
    ))
    .unwrap();
    let network = check(&node.diagnose().checks, "服务 onebox-network").clone();
    assert_eq!(
        (network.status, network.detail.as_str()),
        (CheckStatus::Fail, "未配置；执行 onebox regen")
    );
}

pub(super) fn failing_provider(_: &Doctor, _: Option<&crate::domain::NodeConfig>) -> Vec<Check> {
    vec![Check::fail("额外检查", "坏了")]
}

#[test]
fn ctrl_c_stops_the_diagnosis_before_the_interrupted_probe_is_reported() {
    let node = Node::new(two_core_config());
    interrupted(&node.fake, "onebox", "version");
    let node = node.finish();
    let _signals = signals();
    crate::sys::signal::clear();
    let mut shown = Vec::new();
    let err = node
        .doctor()
        .diagnose(&[], &mut |c| shown.push(c.name.clone()))
        .unwrap_err();
    assert!(err.is_cancelled(), "{err}");
    assert_eq!(err.exit_code(), 130);
    assert_eq!(err.report_text(), "操作被信号 2 中断");
    assert_eq!(shown, ["节点配置", "未完成事务"], "管理程序 is not broken");
    assert_eq!(
        crate::sys::signal::pending(),
        None,
        "the signal is consumed"
    );
    // Doctor exits 130 instead of counting problems.
    let err = report::run_doctor(&node.doctor(), &[]).unwrap_err();
    assert!(err.is_cancelled(), "{err}");
}

/// Interrupted while it works, without a line of its own.
fn interrupted_provider(_: &Doctor, _: Option<&crate::domain::NodeConfig>) -> Vec<Check> {
    // SAFETY: raises a signal on this thread; the diagnosis has installed
    // the recording handler.
    unsafe {
        libc::raise(libc::SIGTERM);
    }
    Vec::new()
}

#[test]
fn ctrl_c_during_the_last_provider_still_cancels() {
    let node = Node::healthy();
    let _signals = signals();
    let err = node
        .doctor()
        .diagnose(&[interrupted_provider], &mut |_| {})
        .unwrap_err();
    assert!(err.is_cancelled(), "{err}");
    assert_eq!(err.report_text(), "操作被信号 15 中断");
    assert_eq!(crate::sys::signal::pending(), None);
    // That signal was consumed: the next diagnosis is not cancelled by it.
    assert!(node.doctor().diagnose(&[], &mut |_| {}).is_ok());
}

mod features;
mod init;
