//! End-to-end diagnoses of optional features: the site, the standalone
//! subscription, FRP, extra providers, v2 and broken states.

use super::super::fixture::{check, signals, two_core_config, with_status, Node, NOW};
use super::super::*;
use super::{failing_provider, names};
use crate::apply::program_journal::{self, ProgramJournal};
use crate::domain::config::WebCert;
use crate::domain::{fixtures, Core, Protocol};
use crate::error::Error;
use crate::sys::exec::Output;
use std::fs;

fn site_config() -> crate::domain::NodeConfig {
    fixtures::with_site(
        fixtures::config(&[(Protocol::VlessReality, 443, Core::Singbox)]),
        "blog.example.org",
        false,
    )
}

#[test]
fn an_active_site_adds_its_service_certificate_nginx_test_and_renewal() {
    let node = Node::new(site_config()).finish();
    let checks = node.diagnose().checks;
    for name in [
        "服务 onebox-site",
        "网站证书",
        "网站 nginx 配置",
        "证书自动续期",
    ] {
        assert_eq!(
            check(&checks, name).status,
            CheckStatus::Pass,
            "{name}: {checks:#?}"
        );
    }
    assert!(!names(&checks).contains(&"代理证书"));

    let broken = Node::new(site_config());
    broken.fake.on(
        "nginx",
        &["-t"],
        Output::failure(
            1,
            "nginx: [emerg] unknown directive \"bogus\" in /etc/onebox/site/nginx.conf:3\nnginx: configuration file /etc/onebox/site/nginx.conf test failed\n",
        ),
    );
    let broken = broken.finish();
    let nginx = check(&broken.diagnose().checks, "网站 nginx 配置").clone();
    assert_eq!(nginx.status, CheckStatus::Fail);
    assert!(
        nginx.detail.starts_with("nginx 配置测试失败: "),
        "{nginx:?}"
    );

    fs::remove_file(crate::site::conf_file(&broken.ctx.paths)).unwrap();
    let missing = check(&broken.diagnose().checks, "网站 nginx 配置").clone();
    assert!(
        missing.detail.starts_with("配置文件不存在（"),
        "{missing:?}"
    );
}

#[test]
fn a_standalone_subscription_adds_its_services_and_certificate() {
    let mut cfg = fixtures::config(&[(Protocol::Hysteria2, 443, Core::Singbox)]);
    cfg.subscription = Some(fixtures::standalone_subscription(
        "sub.example.org",
        8448,
        WebCert::Cloudflare,
    ));
    let node = Node::new(cfg.clone()).finish();
    let checks = node.diagnose().checks;
    for name in [
        "服务 onebox-subscription",
        "服务 onebox-subscription-web",
        "订阅证书",
        "订阅 nginx 配置",
        "证书自动续期",
    ] {
        assert_eq!(
            check(&checks, name).status,
            CheckStatus::Pass,
            "{name}: {checks:#?}"
        );
    }
    let test = node
        .fake
        .calls()
        .into_iter()
        .find(|c| c.args.first().map(String::as_str) == Some("-t"))
        .unwrap();
    let prefix = node.ctx.paths.subscription();
    let conf = prefix.join("nginx.conf");
    assert_eq!(
        test.args,
        [
            "-t",
            "-q",
            "-p",
            &prefix.to_string_lossy(),
            "-c",
            &conf.to_string_lossy()
        ]
    );

    let broken = Node::new(cfg);
    broken.fake.on(
        "nginx",
        &["-t"],
        Output::failure(1, "nginx: [emerg] cannot load certificate\n"),
    );
    let broken = broken.finish();
    let nginx = check(&broken.diagnose().checks, "订阅 nginx 配置").clone();
    assert_eq!(
        nginx,
        Check::fail(
            "订阅 nginx 配置",
            "nginx 配置测试失败: nginx: [emerg] cannot load certificate"
        )
    );
}

#[test]
fn the_installed_program_must_exist_and_match() {
    let node = Node::new(two_core_config());
    node.fake
        .on("onebox", &["version"], Output::success("2.0.1\n"));
    let node = node.finish();
    let program = check(&node.diagnose().checks, "管理程序").clone();
    assert_eq!(program.status, CheckStatus::Warn);
    assert!(
        program.detail.contains("执行 onebox regen 安装当前程序"),
        "{program:?}"
    );

    fs::remove_file(&node.ctx.paths.executable).unwrap();
    let program = check(&node.diagnose().checks, "管理程序").clone();
    assert_eq!(program.status, CheckStatus::Fail);
}

#[test]
fn a_v2_state_is_a_warning_with_its_migration_notes() {
    let node = Node::healthy();
    let values = crate::state::v2::fixtures::with(
        crate::state::v2::fixtures::preset1(),
        &[("ONEBOX_FUTURE_KNOB", "1")],
    );
    fs::write(
        node.ctx.paths.state(),
        crate::state::v2::fixtures::file(&values),
    )
    .unwrap();
    let checks = node.diagnose().checks;
    let state = check(&checks, "节点配置");
    assert_eq!(state.status, CheckStatus::Warn);
    assert!(
        state
            .detail
            .ends_with("仍是 2.x 格式，执行 onebox regen 完成升级"),
        "{state:?}"
    );
    let notes: Vec<&Check> = checks.iter().filter(|c| c.name == "配置迁移").collect();
    assert_eq!(notes.len(), 1, "{checks:#?}");
    assert_eq!(notes[0].status, CheckStatus::Warn);
    assert!(notes[0].detail.contains("ONEBOX_FUTURE_KNOB"), "{notes:?}");
}

#[test]
fn an_unreadable_state_fails_but_the_rest_is_still_checked() {
    let node = Node::healthy();
    fs::write(node.ctx.paths.state(), "{").unwrap();
    let checks = node.diagnose().checks;
    assert_eq!(check(&checks, "节点配置").status, CheckStatus::Fail);
    assert_eq!(
        names(&checks),
        ["节点配置", "未完成事务", "管理程序", "防火墙台账"]
    );
}

#[test]
fn nothing_installed_is_not_installed() {
    let dir = crate::sys::fs::TempDir::new("diag-empty").unwrap();
    let (ctx, _, _) = Ctx::test(dir.path());
    let doctor = Doctor {
        ctx: &ctx,
        init: crate::host::init::InitSystem::Systemd,
        now: NOW,
    };
    let _signals = signals();
    let err = doctor.diagnose(&[], &mut |_| {}).unwrap_err();
    assert!(matches!(err, Error::NotInstalled), "{err}");
}

#[test]
fn a_journal_without_state_is_still_diagnosed() {
    let dir = crate::sys::fs::TempDir::new("diag-journal-only").unwrap();
    let (ctx, fake, _) = Ctx::test(dir.path());
    fake.on("onebox", &["version"], Output::success(crate::VERSION));
    let program = ProgramJournal::new(
        format!("{}{}", program_journal::WORK_PREFIX, "1".repeat(24)),
        None,
        "b".repeat(64),
        None,
    );
    program_journal::write(&ctx.paths, &program).unwrap();
    let doctor = Doctor {
        ctx: &ctx,
        init: crate::host::init::InitSystem::Systemd,
        now: NOW,
    };
    let _signals = signals();
    let checks = doctor.diagnose(&[], &mut |_| {}).unwrap().checks;
    assert_eq!(names(&checks), ["节点配置", "未完成事务", "管理程序"]);
    assert_eq!(check(&checks, "节点配置").detail, "未安装代理节点");
    assert_eq!(check(&checks, "未完成事务").status, CheckStatus::Fail);
}

#[test]
fn an_frp_journal_without_any_installation_is_still_diagnosed() {
    // An FRP install that died before writing its state leaves only the
    // journal; FRP's provider reports it, so it is not "not installed".
    let dir = crate::sys::fs::TempDir::new("diag-frp-journal-only").unwrap();
    let (ctx, fake, _) = Ctx::test(dir.path());
    fake.on("onebox", &["version"], Output::success(crate::VERSION));
    fs::create_dir_all(ctx.paths.frp_journal()).unwrap();
    let doctor = Doctor {
        ctx: &ctx,
        init: crate::host::init::InitSystem::Systemd,
        now: NOW,
    };
    let _signals = signals();
    let checks = doctor.diagnose(&[], &mut |_| {}).unwrap().checks;
    assert_eq!(names(&checks), ["节点配置", "未完成事务", "管理程序"]);
    assert_eq!(check(&checks, "未完成事务").status, CheckStatus::Pass);
}

fn write_frp(ctx: &Ctx, state: &str) {
    let root = &ctx.paths.frp_root;
    fs::create_dir_all(root).unwrap();
    fs::write(root.join(".managed"), "").unwrap();
    fs::write(root.join("state.json"), state).unwrap();
}

#[test]
fn frp_state_is_checked_when_installed() {
    let node = Node::healthy();
    write_frp(&node.ctx, "{\"schema\": 2}");
    let frp = check(&node.diagnose().checks, "FRP 服务端").clone();
    assert_eq!(frp.status, CheckStatus::Fail);
    assert!(frp.detail.contains("FRP 状态"), "{frp:?}");

    let state = crate::frp::model::FrpState::new(
        "frp.example.org".into(),
        "f".repeat(64),
        crate::frp::model::BindAddr::AnyV4,
        crate::frp::model::Mode::tcp(),
    );
    crate::frp::model::save(&node.ctx.paths, &state).unwrap();
    let frp = check(&node.diagnose().checks, "FRP 服务端").clone();
    assert_eq!(frp.status, CheckStatus::Pass, "{frp:?}");
    assert!(frp.detail.contains("TCP 模式"));
}

#[test]
fn frp_failures_are_warnings_while_an_frp_operation_runs() {
    let node = Node::healthy();
    write_frp(&node.ctx, "{\"schema\": 2}");
    let paths = &node.ctx.paths;
    fs::create_dir_all(paths.frp_journal()).unwrap();
    let held = crate::sys::lock::FileLock::acquire(&paths.frp_lock(), "busy").unwrap();
    let diagnosis = node.diagnose();
    let frp = check(&diagnosis.checks, "FRP 服务端");
    assert_eq!(frp.status, CheckStatus::Warn, "{frp:?}");
    assert!(frp.detail.starts_with(probe::TRANSIENT), "{frp:?}");
    // An FRP operation says nothing about the node.
    assert!(!diagnosis.operation_running);
    assert_eq!(
        check(&diagnosis.checks, "未完成事务"),
        &Check::pass("未完成事务", "无")
    );

    drop(held);
    let frp = check(&node.diagnose().checks, "FRP 服务端").clone();
    assert_eq!(frp.status, CheckStatus::Fail, "{frp:?}");
}

#[test]
fn frp_only_hosts_are_diagnosed_without_node_checks() {
    let dir = crate::sys::fs::TempDir::new("diag-frp-only").unwrap();
    let (ctx, fake, _) = Ctx::test(dir.path());
    fake.on("onebox", &["version"], Output::success(crate::VERSION));
    fs::write(&ctx.paths.executable, "").unwrap();
    let state = crate::frp::model::FrpState::new(
        "frp.example.org".into(),
        "f".repeat(64),
        crate::frp::model::BindAddr::AnyV4,
        crate::frp::model::Mode::tcp(),
    );
    write_frp(&ctx, "{}");
    crate::frp::model::save(&ctx.paths, &state).unwrap();
    let doctor = Doctor {
        ctx: &ctx,
        init: crate::host::init::InitSystem::Systemd,
        now: NOW,
    };
    let _signals = signals();
    let checks = doctor.diagnose(&[], &mut |_| {}).unwrap().checks;
    assert_eq!(
        names(&checks),
        ["节点配置", "未完成事务", "管理程序", "FRP 服务端"]
    );
    assert!(
        with_status(&checks, CheckStatus::Fail).is_empty(),
        "{checks:#?}"
    );
}

/// Reports what it was given: the diagnosis' facts and the configuration.
fn extra_provider(doctor: &Doctor, cfg: Option<&crate::domain::NodeConfig>) -> Vec<Check> {
    vec![Check::warn(
        "订阅设备",
        format!(
            "收到配置: {}，init {}，now {}",
            cfg.is_some(),
            doctor.init.id(),
            doctor.now
        ),
    )]
}

#[test]
fn extra_providers_run_last_in_order_with_the_diagnosis_facts() {
    let node = Node::healthy();
    let providers: [CheckFn; 2] = [extra_provider, failing_provider];
    let _signals = signals();
    let diagnosis = node.doctor().diagnose(&providers, &mut |_| {}).unwrap();
    let tail: Vec<&Check> = diagnosis.checks.iter().rev().take(2).collect();
    assert_eq!(
        tail[1],
        &Check::warn(
            "订阅设备",
            format!("收到配置: true，init systemd，now {NOW}")
        )
    );
    assert_eq!(tail[0], &Check::fail("额外检查", "坏了"));
    assert_eq!(diagnosis.tally().fail, 1);
}

#[test]
fn doctor_reports_failures_through_its_exit_status() {
    let node = Node::healthy();
    let _signals = signals();
    assert!(report::run_doctor(&node.doctor(), &[]).is_ok());
    let err = report::run_doctor(&node.doctor(), &[failing_provider]).unwrap_err();
    assert_eq!(err.to_string(), "体检发现 1 个需要处理的问题");
}

#[test]
fn hop_ledger_follows_the_configuration() {
    let mut cfg = two_core_config();
    cfg.hy2.hop = Some("20000-20010".parse().unwrap());
    let node = Node::new(cfg).finish();
    let hops = check(&node.diagnose().checks, "端口跳跃").clone();
    assert_eq!(hops.status, CheckStatus::Warn);
    assert_eq!(
        hops.detail,
        "UDP 20000-20010 → 8443 的规则未记录；执行 onebox hop-apply"
    );
}
