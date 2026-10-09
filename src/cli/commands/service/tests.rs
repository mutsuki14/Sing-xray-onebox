use super::*;
use crate::cli::args::{parse, Globals};
use crate::cli::session::testing::{Bench, Call};
use crate::domain::fixtures::config;
use crate::domain::protocol::Core::{Singbox as SB, Xray as XR};
use crate::domain::protocol::Protocol::*;
use crate::host::init::InitSystem;
use crate::sys::exec::Output;

fn root(line: &str) -> bool {
    let argv: Vec<String> = line.split_whitespace().map(String::from).collect();
    let specs = [SERVICE, LOG, STATUS, START];
    let inv = parse(&specs, &argv, Globals::default()).unwrap();
    inv.spec.root.required(&inv.matches)
}

#[test]
fn actions() {
    for (word, action) in [
        ("start", Action::Start),
        ("stop", Action::Stop),
        ("restart", Action::Restart),
        ("enable", Action::Enable),
        ("disable", Action::Disable),
        ("remove", Action::Remove),
        ("status", Action::Status),
        ("log", Action::Log),
    ] {
        assert_eq!(Action::parse(word).unwrap(), action);
    }
    assert_eq!(
        Action::parse("reload").unwrap_err().to_string(),
        "不支持 reload，请使用 restart"
    );
    assert_eq!(
        Action::parse("kill").unwrap_err().to_string(),
        "未知服务操作"
    );
}

#[test]
fn root_policy() {
    assert!(!root("service onebox-site"));
    assert!(!root("service onebox-site status"));
    assert!(!root("service onebox-site log"));
    assert!(root("service onebox-site restart"));
    assert!(!root("status"));
    assert!(!root("log xray"));
    assert!(root("start"));
}

#[test]
fn service_status_and_log_are_read_only() {
    let mut bench = Bench::new();
    bench.is_root = false;
    bench
        .exec
        .on(
            "systemctl",
            &["is-active", "--quiet", "onebox-site"],
            Output::success(""),
        )
        .on("journalctl", &[], Output::success("line 1\nline 2\n"));
    service(&bench.session(), "onebox-site", Action::Status).unwrap();
    service(&bench.session(), "onebox-site", Action::Log).unwrap();
    assert_eq!(bench.output(), "onebox-site: 运行中\nline 1\nline 2");
    assert!(!bench.ctx.paths.lock().exists(), "no lock taken");
    let err = service(&bench.session(), "nginx", Action::Status).unwrap_err();
    assert_eq!(err.to_string(), "服务名无效");
    let err = service(&bench.session(), "onebox-site", Action::Stop).unwrap_err();
    assert_eq!(err.to_string(), "此操作需要 root 权限");
}

#[test]
fn service_changes_take_the_scope_lock() {
    let bench = Bench::new();
    bench
        .exec
        .on("systemctl", &["start", "onebox-site"], Output::success(""))
        .on(
            "systemctl",
            &["is-active", "--quiet", "onebox-site"],
            Output::success(""),
        )
        .on("systemctl", &["stop", "onebox-site"], Output::success(""));
    service(&bench.session(), "onebox-site", Action::Start).unwrap();
    assert_eq!(bench.notes(), ["[完成] onebox-site 已启动"]);
    assert!(bench.ctx.paths.lock().exists());
    // A concurrent configuration change holds the node lock.
    // Wait briefly: a process forked by a concurrent test may hold a
    // duplicate of the descriptor until it execs.
    let held = FileLock::acquire_waiting(
        &bench.ctx.paths.lock(),
        BUSY_MESSAGE,
        std::time::Duration::from_secs(5),
        std::time::Duration::from_millis(20),
    )
    .unwrap();
    let err = service(&bench.session(), "onebox-site", Action::Stop).unwrap_err();
    assert_eq!(err.to_string(), BUSY_MESSAGE);
    // onebox-network takes the node lock itself: started without it.
    bench
        .exec
        .on(
            "systemctl",
            &["start", "onebox-network"],
            Output::success(""),
        )
        .on(
            "systemctl",
            &["is-active", "--quiet", "onebox-network"],
            Output::success(""),
        );
    service(&bench.session(), "onebox-network", Action::Start).unwrap();
    drop(held);
    let history = bench.exec.history();
    assert!(
        history
            .iter()
            .any(|c| c == "systemctl start onebox-network"),
        "{history:?}"
    );
}

#[test]
fn proxy_cores() {
    let bench = Bench::installed(&config(&[(VlessReality, 443, XR), (Tuic, 443, SB)]));
    bench.live.set_running("onebox-xray");
    cores(&bench.session(), Action::Status).unwrap();
    assert_eq!(bench.output(), "singbox: 已停止\nxray: 运行中");
    for name in ["onebox-sing-box", "onebox-xray"] {
        bench
            .exec
            .on("systemctl", &["restart", name], Output::success(""))
            .on(
                "systemctl",
                &["is-active", "--quiet", name],
                Output::success(""),
            );
    }
    cores(&bench.session(), Action::Restart).unwrap();
    assert_eq!(
        bench.notes(),
        ["[完成] sing-box 已重启", "[完成] Xray 已重启"]
    );
}

#[test]
fn start_reports_a_service_that_does_not_come_up() {
    let bench = Bench::installed(&config(&[(VlessReality, 443, XR)]));
    bench
        .exec
        .on("systemctl", &["start", "onebox-xray"], Output::success(""));
    let err = cores(&bench.session(), Action::Start).unwrap_err();
    assert_eq!(err.to_string(), "onebox-xray 未能正常运行");
}

/// No init system: `onebox-network` is a oneshot the supervisor runs to
/// completion, so it never "runs" afterwards; start and restart succeed on
/// the command's own result (the no-init `@reboot … service onebox-network
/// start` line must not log a failure on every boot).
#[test]
fn a_oneshot_start_without_init_does_not_wait_for_a_process() {
    let mut bench = Bench::new();
    bench.live.init = InitSystem::None;
    let paths = &bench.ctx.paths;
    Services::new(&bench.ctx, InitSystem::None)
        .write(&ServiceDef::network(paths))
        .unwrap();
    let exe = paths.executable.to_string_lossy().into_owned();
    bench.exec.on(&exe, &["net-apply"], Output::success(""));
    service(&bench.session(), "onebox-network", Action::Start).unwrap();
    service(&bench.session(), "onebox-network", Action::Restart).unwrap();
    assert_eq!(
        bench.notes(),
        [
            "[完成] onebox-network 已启动",
            "[完成] onebox-network 已重启"
        ]
    );
    assert_eq!(
        bench.exec.history(),
        [format!("{exe} net-apply"), format!("{exe} net-apply")]
    );
    // A failing restore still fails the command.
    let mut bench = Bench::new();
    bench.live.init = InitSystem::None;
    let paths = &bench.ctx.paths;
    Services::new(&bench.ctx, InitSystem::None)
        .write(&ServiceDef::network(paths))
        .unwrap();
    let exe = paths.executable.to_string_lossy().into_owned();
    bench
        .exec
        .on(&exe, &["net-apply"], Output::failure(1, "规则恢复失败"));
    let err = service(&bench.session(), "onebox-network", Action::Start).unwrap_err();
    assert!(err.to_string().contains("规则恢复失败"), "{err}");
}

#[test]
fn logs_of_a_core() {
    let bench = Bench::new();
    bench.exec.on(
        "journalctl",
        &["--no-pager", "-n", "200", "-u", "onebox-xray"],
        Output::success("xray log\n"),
    );
    log(&bench.session(), Core::Xray).unwrap();
    assert_eq!(bench.output(), "xray log");
}

#[test]
fn boot_and_hop_clear() {
    let bench = Bench::new();
    bench.session().engine.boot(&bench.ctx).unwrap();
    assert_eq!(bench.engine.calls(), [Call::Boot]);
    hop_clear(&bench.session()).unwrap();
    assert_eq!(bench.notes(), ["[完成] 已清除端口跳跃规则 0 条"]);
}
