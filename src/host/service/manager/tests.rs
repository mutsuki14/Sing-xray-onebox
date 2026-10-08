use super::*;
use crate::domain::protocol::Core;
use crate::host::cron::testing::{fake_crontab, text};
use crate::host::supervisor::fixture::FakeProc;
use crate::host::supervisor::{Supervisor, Timing};
use crate::sys::exec::{FakeExec, Output, FAKE_PID_BASE};
use crate::sys::fs::TempDir;
use std::os::unix::fs::PermissionsExt;
use std::sync::Arc;

struct Fixture {
    _dir: TempDir,
    ctx: Ctx,
    exec: Arc<FakeExec>,
}

impl Fixture {
    fn new() -> Fixture {
        let dir = TempDir::new("services").unwrap();
        let (ctx, exec, _) = Ctx::test(dir.path());
        Fixture {
            _dir: dir,
            ctx,
            exec,
        }
    }

    fn services(&self, init: InitSystem) -> Services<'_> {
        let policy = Timing {
            term_grace: Duration::from_millis(20),
            kill_grace: Duration::from_millis(20),
            poll: Duration::from_millis(5),
            lock_wait: Duration::from_millis(20),
        };
        let supervisor = Supervisor::with(
            &self.ctx,
            Arc::new(crate::host::supervisor::SystemSignaller),
            policy,
        );
        Services::with_supervisor(&self.ctx, init, supervisor)
    }

    fn xray(&self) -> ServiceDef {
        ServiceDef::core(&self.ctx.paths, Core::Xray, false)
    }

    /// Answer every systemctl/rc-service/rc-update/journalctl call with `out`.
    fn answer_all(&self, out: Output) {
        for program in ["systemctl", "rc-service", "rc-update", "journalctl"] {
            self.exec.on(program, &[], out.clone());
        }
    }
}

fn mode(path: &Path) -> u32 {
    fs::metadata(path).unwrap().permissions().mode() & 0o777
}

#[test]
fn systemd_write_renders_unit_and_spec_then_reloads_once() {
    let f = Fixture::new();
    f.answer_all(Output::success(""));
    let services = f.services(InitSystem::Systemd);
    let xray = f.xray();
    let network = ServiceDef::network(&f.ctx.paths);
    services
        .write_all(&[xray.clone(), network.clone()])
        .unwrap();
    assert_eq!(f.exec.history(), ["systemctl daemon-reload"]);

    let env = services.env();
    let unit = unit_file(&f.ctx.paths, XRAY_NAME);
    assert_eq!(
        fs::read_to_string(&unit).unwrap(),
        render_systemd(&xray, &env).unwrap()
    );
    assert_eq!(mode(&unit), 0o644);
    let spec: ServiceSpec = serde_json::from_slice(&fs::read(xray.spec_path()).unwrap()).unwrap();
    assert_eq!(spec, xray.spec(&env));
    assert_eq!(spec.environment.last().unwrap().1, "systemd");
    assert_eq!(mode(&xray.spec_path()), 0o600);
    assert!(unit_file(&f.ctx.paths, "onebox-network").exists());
    assert!(!script_file(&f.ctx.paths, XRAY_NAME).exists());

    f.exec.clear_history();
    services.write(&xray).unwrap();
    assert_eq!(f.exec.history(), ["systemctl daemon-reload"]);
    let (loaded, loaded_env) = services.load(XRAY_NAME).unwrap();
    assert_eq!((loaded, loaded_env), (xray, env));
}

#[test]
fn openrc_and_supervisor_writes_need_no_commands() {
    let f = Fixture::new();
    let openrc = f.services(InitSystem::Openrc);
    let frps = ServiceDef::frps(&f.ctx.paths);
    openrc.write(&frps).unwrap();
    let script = script_file(&f.ctx.paths, "onebox-frps");
    assert_eq!(mode(&script), 0o755);
    assert_eq!(
        fs::read_to_string(&script).unwrap(),
        render_openrc(&frps, &openrc.env()).unwrap()
    );
    assert!(f.ctx.paths.frp_log.is_dir(), "OpenRC output log directory");
    assert!(frps.spec_path().starts_with(&f.ctx.paths.frp_root));

    let none = f.services(InitSystem::None);
    let xray = f.xray();
    none.write(&xray).unwrap();
    assert!(!unit_file(&f.ctx.paths, XRAY_NAME).exists());
    assert!(!script_file(&f.ctx.paths, XRAY_NAME).exists());
    assert_eq!(none.load(XRAY_NAME).unwrap().1.last().unwrap().1, "none");
    assert!(f.exec.history().is_empty());
}

#[test]
fn invalid_definitions_write_nothing() {
    let f = Fixture::new();
    let services = f.services(InitSystem::Systemd);
    let mut def = f.xray();
    def.args.push("x\nExecStartPost=/bin/sh".into());
    assert!(services.write(&def).is_err());
    assert!(!def.spec_path().exists() && !unit_file(&f.ctx.paths, XRAY_NAME).exists());
    assert!(f.exec.history().is_empty());
}

#[test]
fn actions_map_to_each_init_system() {
    let cases = [
        (InitSystem::Systemd, "start", "systemctl start onebox-xray"),
        (
            InitSystem::Systemd,
            "restart",
            "systemctl restart onebox-xray",
        ),
        (
            InitSystem::Systemd,
            "enable",
            "systemctl enable onebox-xray",
        ),
        (InitSystem::Openrc, "start", "rc-service onebox-xray start"),
        (
            InitSystem::Openrc,
            "restart",
            "rc-service onebox-xray restart",
        ),
        (
            InitSystem::Openrc,
            "enable",
            "rc-update add onebox-xray default",
        ),
    ];
    for (init, action, want) in cases {
        let f = Fixture::new();
        f.answer_all(Output::success(""));
        let services = f.services(init);
        match action {
            "start" => services.start(XRAY_NAME),
            "restart" => services.restart(XRAY_NAME),
            _ => services.enable(XRAY_NAME),
        }
        .unwrap();
        assert_eq!(f.exec.history(), [want], "{init:?} {action}");
        let cmd = &f.exec.calls()[0];
        assert!(cmd.timeout.is_some(), "service managers run with a timeout");
    }
}

#[test]
fn failing_actions_report_the_manager_error() {
    let f = Fixture::new();
    f.exec.on(
        "systemctl",
        &["start"],
        Output::failure(1, "Job for onebox-xray.service failed.\n"),
    );
    let err = f
        .services(InitSystem::Systemd)
        .start(XRAY_NAME)
        .unwrap_err();
    assert_eq!(
        err.to_string(),
        "systemctl 执行失败 (1): Job for onebox-xray.service failed."
    );
    assert!(f.services(InitSystem::Systemd).start("../x").is_err());
}

#[test]
fn systemd_stop_and_disable_tolerate_missing_units() {
    let f = Fixture::new();
    f.exec.on(
        "systemctl",
        &["stop"],
        Output::failure(5, "Unit not loaded."),
    );
    let services = f.services(InitSystem::Systemd);
    services.stop(XRAY_NAME).unwrap();
    services.disable(XRAY_NAME).unwrap();
    assert_eq!(
        f.exec.history(),
        ["systemctl stop onebox-xray"],
        "no unit file: no disable"
    );

    let f = Fixture::new();
    f.exec
        .on("systemctl", &["stop"], Output::failure(1, "denied"));
    assert!(f.services(InitSystem::Systemd).stop(XRAY_NAME).is_err());
}

#[test]
fn remove_stops_disables_deletes_and_reloads() {
    let f = Fixture::new();
    f.answer_all(Output::success(""));
    let services = f.services(InitSystem::Systemd);
    let xray = f.xray();
    services.write(&xray).unwrap();
    f.exec.clear_history();
    services.remove(XRAY_NAME).unwrap();
    assert_eq!(
        f.exec.history(),
        [
            "systemctl stop onebox-xray",
            "systemctl disable onebox-xray",
            "systemctl daemon-reload"
        ]
    );
    assert!(!xray.spec_path().exists() && !unit_file(&f.ctx.paths, XRAY_NAME).exists());
    assert!(!services.exists(XRAY_NAME));

    // Nothing installed: nothing to do.
    f.exec.clear_history();
    services.remove(XRAY_NAME).unwrap();
    assert!(f.exec.history().is_empty());
}

#[test]
fn remove_of_a_spec_only_service_never_fails_on_systemd() {
    let f = Fixture::new();
    let none = f.services(InitSystem::None);
    let xray = f.xray();
    none.write(&xray).unwrap();
    f.exec.on(
        "systemctl",
        &["stop"],
        Output::failure(5, "Unit onebox-xray.service not loaded."),
    );
    let services = f.services(InitSystem::Systemd);
    assert!(services.exists(XRAY_NAME));
    services.remove(XRAY_NAME).unwrap();
    assert_eq!(f.exec.history(), ["systemctl stop onebox-xray"]);
    assert!(!xray.spec_path().exists());
}

#[test]
fn openrc_disable_and_remove_use_the_default_runlevel() {
    let f = Fixture::new();
    let listing = " onebox-xray | default\n onebox-xray-extra | default\n";
    f.exec
        .on("rc-update", &["show"], Output::success(listing))
        .on("rc-update", &["del"], Output::success(""))
        .on("rc-service", &[], Output::success(""));
    let services = f.services(InitSystem::Openrc);
    services.write(&f.xray()).unwrap();
    assert!(services.enabled(XRAY_NAME).unwrap());
    f.exec.clear_history();
    services.remove(XRAY_NAME).unwrap();
    assert_eq!(
        f.exec.history(),
        [
            "rc-service onebox-xray stop",
            "rc-update show default",
            "rc-update del onebox-xray default"
        ]
    );
    assert!(!script_file(&f.ctx.paths, XRAY_NAME).exists());

    // Not listed (only a longer name is): disable does nothing.
    let f = Fixture::new();
    f.exec.on(
        "rc-update",
        &["show"],
        Output::success(" onebox-xray-extra | default\n"),
    );
    f.services(InitSystem::Openrc).disable(XRAY_NAME).unwrap();
    assert_eq!(f.exec.history(), ["rc-update show default"]);
}

#[test]
fn systemd_enablement_follows_is_enabled_exit_codes() {
    for (code, want) in [
        (0, Some(true)),
        (1, Some(false)),
        (4, Some(false)),
        (5, None),
    ] {
        let f = Fixture::new();
        f.exec
            .on("systemctl", &["is-enabled"], Output::failure(code, "x"))
            .on("systemctl", &["daemon-reload"], Output::success(""));
        let services = f.services(InitSystem::Systemd);
        services.write(&f.xray()).unwrap();
        let got = services.enabled(XRAY_NAME);
        match want {
            Some(want) => assert_eq!(got.unwrap(), want, "code {code}"),
            None => assert_eq!(
                got.unwrap_err().to_string(),
                "无法读取 onebox-xray 自启状态"
            ),
        }
    }
    let f = Fixture::new();
    assert!(
        !f.services(InitSystem::Systemd).enabled(XRAY_NAME).unwrap(),
        "not installed"
    );
    assert!(f.exec.history().is_empty());
}

#[test]
fn openrc_running_checks_the_supervised_child() {
    let f = Fixture::new();
    f.exec.on("rc-service", &[], Output::success("started"));
    let services = f.services(InitSystem::Openrc);
    assert!(
        services.running(XRAY_NAME),
        "no child_pid recorded: trust rc-service"
    );
    let options = f.ctx.paths.system("/run/openrc/options/onebox-xray");
    fs::create_dir_all(&options).unwrap();
    fs::write(options.join("child_pid"), "4242\n").unwrap();
    assert!(!services.running(XRAY_NAME), "recorded child is gone");
    let procs = FakeProc::new(&f.ctx.paths.system_root);
    procs.add(4242, 1, Path::new("/opt/xray"), &["xray"]);
    assert!(services.running(XRAY_NAME));
    fs::write(options.join("child_pid"), "1").unwrap();
    assert!(!services.running(XRAY_NAME));

    let f = Fixture::new();
    f.exec.on("rc-service", &[], Output::failure(3, "stopped"));
    assert!(!f.services(InitSystem::Openrc).running(XRAY_NAME));
    assert_eq!(
        f.services(InitSystem::Openrc).status_line(XRAY_NAME),
        "onebox-xray: 已停止"
    );
}

#[test]
fn wait_running_reports_the_service() {
    let f = Fixture::new();
    f.exec
        .on("systemctl", &["is-active"], Output::failure(3, ""));
    let services = f.services(InitSystem::Systemd);
    let err = services
        .wait_running(XRAY_NAME, Duration::from_millis(150))
        .unwrap_err();
    assert_eq!(err.to_string(), "onebox-xray 未能正常运行");
    assert!(f.exec.history().len() >= 2, "polled");

    let f = Fixture::new();
    f.exec.on("systemctl", &["is-active"], Output::success(""));
    let services = f.services(InitSystem::Systemd);
    services.wait_running(XRAY_NAME, Duration::ZERO).unwrap();
    assert_eq!(services.status_line(XRAY_NAME), "onebox-xray: 运行中");
}

#[test]
fn logs_come_from_the_journal_or_the_first_log_file() {
    let f = Fixture::new();
    f.exec.on("journalctl", &[], Output::success("journal\n"));
    assert_eq!(
        f.services(InitSystem::Systemd).logs(XRAY_NAME, 50).unwrap(),
        "journal\n"
    );
    assert_eq!(
        f.exec.history(),
        ["journalctl --no-pager -n 50 -u onebox-xray"]
    );

    let services = f.services(InitSystem::None);
    let err = services.logs(XRAY_NAME, 10).unwrap_err();
    assert_eq!(err.to_string(), "服务日志尚不存在");
    let log = &f.ctx.paths.log;
    fs::create_dir_all(log).unwrap();
    fs::write(log.join("xray.log"), "old 1\nold 2\n").unwrap();
    assert_eq!(services.logs(XRAY_NAME, 1).unwrap(), "old 2\n");
    fs::write(log.join("onebox-xray.log"), "new\n").unwrap();
    assert_eq!(services.logs(XRAY_NAME, 10).unwrap(), "new\n");

    let site = f.ctx.paths.site();
    fs::create_dir_all(&site).unwrap();
    fs::write(site.join("error.log"), "site error\n").unwrap();
    assert_eq!(services.logs("onebox-site", 5).unwrap(), "site error\n");
}

#[test]
fn no_init_autostart_is_one_owned_crontab_line() {
    let f = Fixture::new();
    let cron = fake_crontab(&f.exec, Some("MAILTO=root\n0 1 * * * backup\n"));
    let services = f.services(InitSystem::None);
    services.write(&f.xray()).unwrap();
    assert!(!services.enabled(XRAY_NAME).unwrap());
    services.enable(XRAY_NAME).unwrap();
    let installed = text(&cron);
    let lines: Vec<&str> = installed.lines().collect();
    assert_eq!(lines[..2], ["MAILTO=root", "0 1 * * * backup"]);
    assert_eq!(lines.len(), 3);
    assert!(
        lines[2].starts_with("@reboot PATH=/usr/local/sbin:"),
        "{installed}"
    );
    assert!(lines[2].contains("ONEBOX_INIT='none'"));
    assert!(lines[2].contains(&format!(
        "'{}' service onebox-xray start >>'{}/boot.log' 2>&1 # onebox:boot:onebox-xray",
        f.ctx.paths.executable.display(),
        f.ctx.paths.log.display()
    )));
    assert!(f.ctx.paths.log.is_dir());
    assert!(services.enabled(XRAY_NAME).unwrap());

    // Enabling again changes nothing (no reinstall).
    let installs = |f: &Fixture| {
        f.exec
            .history()
            .iter()
            .filter(|c| !c.ends_with(" -l"))
            .count()
    };
    let before = installs(&f);
    services.enable(XRAY_NAME).unwrap();
    assert_eq!(installs(&f), before);

    services.disable(XRAY_NAME).unwrap();
    assert_eq!(text(&cron), "MAILTO=root\n0 1 * * * backup\n");
    assert!(!services.enabled(XRAY_NAME).unwrap());
}

#[test]
fn no_init_enable_migrates_the_v2_autostart_line() {
    let f = Fixture::new();
    let v2 = "@reboot env ONEBOX_DIR='/etc/onebox' '/usr/local/bin/onebox' service onebox-xray start >/dev/null 2>&1 # onebox-rust:onebox-xray";
    let cron = fake_crontab(&f.exec, Some(&format!("{v2}\n5 * * * * mine\n")));
    let services = f.services(InitSystem::None);
    services.write(&f.xray()).unwrap();
    assert!(
        services.enabled(XRAY_NAME).unwrap(),
        "v2 marker counts as enabled"
    );
    services.enable(XRAY_NAME).unwrap();
    let installed = text(&cron);
    let lines: Vec<&str> = installed.lines().collect();
    assert_eq!(lines.len(), 2);
    assert!(
        lines[0].ends_with("# onebox:boot:onebox-xray"),
        "replaced in place"
    );
    assert_eq!(lines[1], "5 * * * * mine");
}

#[test]
fn no_init_without_crontab_warns_and_continues() {
    let f = Fixture::new();
    let services = f.services(InitSystem::None);
    services.write(&f.xray()).unwrap();
    services.enable(XRAY_NAME).unwrap();
    services.disable(XRAY_NAME).unwrap();
    assert!(!services.enabled(XRAY_NAME).unwrap());
    assert!(f.exec.history().is_empty());
}

#[test]
fn no_init_start_and_stop_go_through_the_supervisor() {
    let f = Fixture::new();
    let services = f.services(InitSystem::None);
    let xray = f.xray();
    services.write(&xray).unwrap();
    fs::create_dir_all(&f.ctx.paths.bin).unwrap();
    fs::write(&xray.program, b"xray").unwrap();
    let procs = FakeProc::new(&f.ctx.paths.system_root);
    let program = xray.program.to_string_lossy().into_owned();
    let mut argv = vec![program.as_str()];
    argv.extend(xray.args.iter().map(String::as_str));
    procs.add(FAKE_PID_BASE, 11, &xray.program, &argv);

    assert!(!services.running(XRAY_NAME));
    services.start(XRAY_NAME).unwrap();
    assert!(services.running(XRAY_NAME));
    let (cmd, _) = &f.exec.spawned()[0];
    assert!(cmd
        .env
        .contains(&("ONEBOX_INIT".to_owned(), "none".to_owned())));
    // The fake process is gone before stop: the stale record is dropped.
    procs.remove(FAKE_PID_BASE);
    services.stop(XRAY_NAME).unwrap();
    assert!(!xray.pid_file().exists());
    // Unconfigured services are already stopped; starting them is an error.
    services.stop("onebox-site").unwrap();
    assert_eq!(
        services.start("onebox-site").unwrap_err().to_string(),
        "服务尚未配置: onebox-site"
    );
}

#[test]
fn loading_validates_the_spec_and_fills_a_missing_environment() {
    let f = Fixture::new();
    let services = f.services(InitSystem::None);
    let path = f.xray().spec_path();
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(&path, b"not json").unwrap();
    assert!(services.load(XRAY_NAME).is_err());
    assert!(!services.exists(XRAY_NAME));
    fs::write(
        &path,
        br#"{"program":"/opt/onebox/bin/xray","args":["run"],"after":[],"environment":[["CF_Token","x"]]}"#,
    )
    .unwrap();
    assert_eq!(
        services.load(XRAY_NAME).unwrap_err().to_string(),
        "服务环境变量不在路径白名单或重复"
    );
    fs::write(
        &path,
        br#"{"program":"/opt/onebox/bin/xray","args":["run","-c","/etc/onebox/xray.json"],"after":[]}"#,
    )
    .unwrap();
    let (def, env) = services.load(XRAY_NAME).unwrap();
    assert_eq!(def.restart_prevent_status, Some(23));
    assert_eq!(env, services.env());

    // A unit file alone makes a service exist; a symlinked one does not.
    let unit = unit_file(&f.ctx.paths, "onebox-site");
    fs::create_dir_all(unit.parent().unwrap()).unwrap();
    std::os::unix::fs::symlink("/dev/null", &unit).unwrap();
    assert!(!services.exists("onebox-site"));
    fs::remove_file(&unit).unwrap();
    fs::write(&unit, "[Unit]\n").unwrap();
    assert!(services.exists("onebox-site"));
    assert!(!services.exists("onebox-"));
}

#[test]
fn specs_below_a_symlinked_directory_are_refused() {
    let f = Fixture::new();
    let elsewhere = f.ctx.paths.root.with_file_name("elsewhere");
    fs::create_dir_all(&elsewhere).unwrap();
    fs::create_dir_all(&f.ctx.paths.root).unwrap();
    std::os::unix::fs::symlink(&elsewhere, f.ctx.paths.services()).unwrap();
    let services = f.services(InitSystem::None);
    assert!(services.write(&f.xray()).is_err());
    assert!(fs::read_dir(&elsewhere).unwrap().next().is_none());
}

const XRAY_NAME: &str = "onebox-xray";
