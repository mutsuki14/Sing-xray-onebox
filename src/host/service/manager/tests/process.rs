//! Round trips per init, lock handover and main PIDs.

use super::*;

#[test]
fn every_known_definition_loads_back_unchanged_under_every_init() {
    for init in InitSystem::ALL {
        let f = Fixture::new();
        f.answer_all(Output::success(""));
        let services = f.services(init);
        let p = &f.ctx.paths;
        let nginx = Path::new("/usr/sbin/nginx");
        let defs = [
            ServiceDef::core(p, Core::Singbox, true),
            ServiceDef::core(p, Core::Xray, false),
            ServiceDef::site(p, nginx),
            ServiceDef::network(p),
            ServiceDef::subscription(p),
            ServiceDef::subscription_web(p, nginx),
            ServiceDef::frps(p),
            ServiceDef::frp_web(p, nginx),
        ];
        services.write_all(&defs).unwrap();
        for def in defs {
            let (loaded, env) = services.load(def.name()).unwrap();
            assert_eq!(loaded, def, "{init:?} {}", def.name());
            assert_eq!(env, services.env());
        }
    }
}

#[test]
fn a_held_lock_reaches_only_helpers_that_take_it() {
    // systemd/OpenRC cannot hand a lock to a unit: refused up front.
    let f = Fixture::new();
    f.answer_all(Output::success(""));
    let node = FileLock::acquire(&f.ctx.paths.lock(), "busy").unwrap();
    let frp = FileLock::acquire(&f.ctx.paths.frp_lock(), "busy").unwrap();
    for init in [InitSystem::Systemd, InitSystem::Openrc] {
        let services = f.services(init);
        for (name, lock) in [("onebox-network", &node), ("onebox-frps", &frp)] {
            let err = services.start_with_lock(name, lock).unwrap_err();
            assert!(err.to_string().contains("自行获取配置锁"), "{err}");
            assert!(services.restart_with_lock(name, lock).is_err());
        }
    }
    assert!(f.exec.history().is_empty(), "nothing ran");
    // Other services (or another lock) start normally.
    let services = f.services(InitSystem::Systemd);
    services.start_with_lock(XRAY_NAME, &node).unwrap();
    services.start_with_lock("onebox-network", &frp).unwrap();
    services.restart_with_lock("onebox-frps", &node).unwrap();
    assert_eq!(
        f.exec.history(),
        [
            "systemctl start onebox-xray",
            "systemctl start onebox-network",
            "systemctl restart onebox-frps"
        ]
    );

    // Without init the network restore inherits the node lock.
    let f = Fixture::new();
    let node = FileLock::acquire(&f.ctx.paths.lock(), "busy").unwrap();
    let services = f.services(InitSystem::None);
    services.write(&ServiceDef::network(&f.ctx.paths)).unwrap();
    let exe = f.ctx.paths.executable.to_string_lossy().into_owned();
    f.exec.on(&exe, &["net-apply"], Output::success(""));
    services.start_with_lock("onebox-network", &node).unwrap();
    let call = &f.exec.calls()[0];
    assert_eq!(call.display(), format!("{exe} net-apply"));
    assert_eq!(call.inherit_lock_fd, Some(node.raw_fd()));
}

#[test]
fn main_pid_under_every_init() {
    // systemd: MainPID, 0 meaning none.
    let f = Fixture::new();
    f.exec
        .on(
            "systemctl",
            &["show", "-p", "MainPID", "onebox-xray"],
            Output::success("MainPID=4321\n"),
        )
        .on(
            "systemctl",
            &["show", "-p", "MainPID", "onebox-site"],
            Output::success("MainPID=0\n"),
        )
        .on(
            "systemctl",
            &["show"],
            Output::failure(1, "Failed to connect to bus"),
        );
    let services = f.services(InitSystem::Systemd);
    assert_eq!(services.main_pid(XRAY_NAME).unwrap(), Some(4321));
    assert_eq!(services.main_pid("onebox-site").unwrap(), None);
    assert!(services.main_pid("onebox-frps").is_err());
    assert!(services.main_pid("../x").is_err());
    assert!(f.exec.calls().iter().all(|c| c.timeout.is_some()));

    // OpenRC: the recorded child while it exists.
    let f = Fixture::new();
    let services = f.services(InitSystem::Openrc);
    assert_eq!(services.main_pid(XRAY_NAME).unwrap(), None);
    let options = f.ctx.paths.system("/run/openrc/options/onebox-xray");
    fs::create_dir_all(&options).unwrap();
    fs::write(options.join("child_pid"), "4242\n").unwrap();
    assert_eq!(services.main_pid(XRAY_NAME).unwrap(), None, "gone");
    FakeProc::new(&f.ctx.paths.system_root).add(4242, 1, Path::new("/opt/xray"), &["xray"]);
    assert_eq!(services.main_pid(XRAY_NAME).unwrap(), Some(4242));
    assert!(f.exec.history().is_empty());

    // No init: the supervisor's verified record.
    let f = Fixture::new();
    let services = f.services(InitSystem::None);
    assert_eq!(
        services.main_pid(XRAY_NAME).unwrap(),
        None,
        "not configured"
    );
    let xray = f.xray();
    services.write(&xray).unwrap();
    fs::create_dir_all(&f.ctx.paths.bin).unwrap();
    fs::write(xray.program(), b"xray").unwrap();
    let program = xray.program().to_string_lossy().into_owned();
    let mut argv = vec![program.as_str()];
    argv.extend(xray.args().iter().map(String::as_str));
    FakeProc::new(&f.ctx.paths.system_root).add(FAKE_PID_BASE, 11, xray.program(), &argv);
    assert_eq!(services.main_pid(XRAY_NAME).unwrap(), None, "no record");
    services.start(XRAY_NAME).unwrap();
    assert_eq!(services.main_pid(XRAY_NAME).unwrap(), Some(FAKE_PID_BASE));
}
