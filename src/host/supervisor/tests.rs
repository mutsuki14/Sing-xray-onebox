use super::fixture::FakeProc;
use super::*;
use crate::domain::protocol::Core;
use crate::host::init::InitSystem;
use crate::host::service::{service_env, ServiceDef, NOFILE_LIMIT};
use crate::sys::exec::{FakeExec, Output, FAKE_PID_BASE, SAFE_PATH};
use crate::sys::fs::TempDir;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::sync::Mutex;

/// Signals against fake `/proc` entries: a delivered signal removes the
/// process unless the fixture says it ignores that signal.
struct FakeSignals {
    procs: FakeProc,
    sent: Mutex<Vec<(u32, i32)>>,
    ignored: Vec<i32>,
}

impl Signaller for FakeSignals {
    fn signal(&self, pid: u32, signal: i32) -> Result<bool> {
        self.sent.lock().unwrap().push((pid, signal));
        if !self.procs.exists(pid) {
            return Ok(false);
        }
        if !self.ignored.contains(&signal) {
            self.procs.remove(pid);
        }
        Ok(true)
    }
}

struct Fixture {
    _dir: TempDir,
    ctx: Ctx,
    exec: Arc<FakeExec>,
    procs: FakeProc,
}

impl Fixture {
    fn new() -> Fixture {
        let dir = TempDir::new("supervisor").unwrap();
        let (ctx, exec, _) = Ctx::test(dir.path());
        let procs = FakeProc::new(&ctx.paths.system_root);
        Fixture {
            _dir: dir,
            ctx,
            exec,
            procs,
        }
    }

    /// The sing-box service with a real (fake) binary on disk.
    fn core(&self) -> ServiceDef {
        let def = ServiceDef::core(&self.ctx.paths, Core::Singbox, false);
        fs::create_dir_all(def.program().parent().unwrap()).unwrap();
        fs::write(def.program(), b"bin").unwrap();
        def
    }

    /// A fake process of `def` (its exact command line).
    fn run(&self, def: &ServiceDef, pid: u32, start: u64) {
        let program = def.program().to_string_lossy().into_owned();
        let mut argv = vec![program.as_str()];
        argv.extend(def.args().iter().map(String::as_str));
        self.procs.add(pid, start, def.program(), &argv);
    }

    fn supervisor(&self, ignored: &[i32]) -> (Supervisor<'_>, Arc<FakeSignals>) {
        let signals = Arc::new(FakeSignals {
            procs: FakeProc::new(&self.ctx.paths.system_root),
            sent: Mutex::new(Vec::new()),
            ignored: ignored.to_vec(),
        });
        let policy = Timing {
            term_grace: Duration::from_millis(30),
            kill_grace: Duration::from_millis(30),
            poll: Duration::from_millis(5),
            lock_wait: Duration::from_millis(50),
        };
        (
            Supervisor::with(&self.ctx, signals.clone(), policy),
            signals,
        )
    }

    fn env(&self) -> Vec<(String, String)> {
        service_env(&self.ctx.paths, InitSystem::None)
    }
}

fn record(path: &Path) -> String {
    fs::read_to_string(path).unwrap()
}

#[test]
fn start_spawns_an_isolated_daemon_and_records_its_identity() {
    let f = Fixture::new();
    let def = f.core();
    let (sup, _) = f.supervisor(&[]);
    f.run(&def, FAKE_PID_BASE, 777);
    assert!(!sup.running(&def), "no record yet");

    sup.start(&def, &f.env()).unwrap();
    let spawned = f.exec.spawned();
    assert_eq!(spawned.len(), 1);
    let (cmd, log) = &spawned[0];
    assert_eq!(cmd.program, def.program().to_string_lossy());
    assert_eq!(cmd.args, def.args());
    assert!(cmd.clear_env, "daemons never inherit the admin shell");
    assert_eq!(cmd.env[0], ("PATH".to_owned(), SAFE_PATH.to_owned()));
    assert_eq!(cmd.env[1..], f.env()[..]);
    assert_eq!(
        cmd.nofile,
        Some(NOFILE_LIMIT),
        "the units' open-files limit"
    );
    assert_eq!(log, &f.ctx.paths.log.join("onebox-sing-box.log"));

    let pid_file = def.pid_file();
    assert_eq!(
        record(&pid_file),
        format!(r#"{{"pid":{FAKE_PID_BASE},"start":777}}"#)
    );
    assert_eq!(
        fs::metadata(&pid_file).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let found = sup.find(&def).unwrap();
    assert_eq!(
        found.record,
        PidRecord {
            pid: FAKE_PID_BASE,
            start: 777
        }
    );
    assert!(!found.legacy);

    // Already running: nothing is spawned again.
    sup.start(&def, &f.env()).unwrap();
    assert_eq!(f.exec.spawned().len(), 1);
}

#[test]
fn a_daemon_that_exits_at_once_fails_the_start() {
    let f = Fixture::new();
    let def = f.core();
    let (sup, _) = f.supervisor(&[]);
    let err = sup.start(&def, &f.env()).unwrap_err();
    assert_eq!(err.to_string(), SPAWN_EXITED);
    assert!(!def.pid_file().exists());

    f.run(&def, FAKE_PID_BASE + 1, 5);
    f.procs.zombie(FAKE_PID_BASE + 1);
    assert_eq!(
        sup.start(&def, &f.env()).unwrap_err().to_string(),
        SPAWN_EXITED
    );
}

#[test]
fn stop_terminates_then_kills_and_removes_the_record() {
    for (ignored, expected) in [
        (vec![], vec![libc::SIGTERM]),
        (vec![libc::SIGTERM], vec![libc::SIGTERM, libc::SIGKILL]),
    ] {
        let f = Fixture::new();
        let def = f.core();
        let (sup, signals) = f.supervisor(&ignored);
        f.run(&def, 4321, 9);
        write_record(
            &def.pid_file(),
            &PidRecord {
                pid: 4321,
                start: 9,
            },
        )
        .unwrap();
        assert!(sup.running(&def));
        sup.stop(&def).unwrap();
        let sent: Vec<i32> = signals.sent.lock().unwrap().iter().map(|s| s.1).collect();
        assert_eq!(sent, expected);
        assert!(!def.pid_file().exists());
        assert!(!sup.running(&def));
    }
}

#[test]
fn a_process_surviving_sigkill_keeps_its_record() {
    let f = Fixture::new();
    let def = f.core();
    let (sup, signals) = f.supervisor(&[libc::SIGTERM, libc::SIGKILL]);
    f.run(&def, 4321, 9);
    write_record(
        &def.pid_file(),
        &PidRecord {
            pid: 4321,
            start: 9,
        },
    )
    .unwrap();
    assert_eq!(sup.stop(&def).unwrap_err().to_string(), STOP_FAILED);
    assert_eq!(signals.sent.lock().unwrap().len(), 2);
    assert!(def.pid_file().exists(), "record kept for a later attempt");
}

#[test]
fn reused_or_foreign_pids_are_never_signalled() {
    let f = Fixture::new();
    let def = f.core();
    let (sup, signals) = f.supervisor(&[]);
    let pid_file = def.pid_file();

    // Same PID, different start time: the PID was reused.
    f.run(&def, 50, 2);
    write_record(&pid_file, &PidRecord { pid: 50, start: 1 }).unwrap();
    assert!(!sup.running(&def));
    // Another program with our arguments.
    let other = f.ctx.paths.bin.join("other");
    fs::write(&other, b"x").unwrap();
    f.procs
        .add(51, 3, &other, &[&other.to_string_lossy(), "run", "-c", "x"]);
    // Our program with another configuration.
    let program = def.program().to_string_lossy().into_owned();
    f.procs.add(
        52,
        4,
        def.program(),
        &[&program, "run", "-c", "/elsewhere.json"],
    );
    for (pid, start) in [(51, 3), (52, 4), (1, 1), (0, 0)] {
        write_record(&pid_file, &PidRecord { pid, start }).unwrap();
        assert!(!sup.running(&def), "pid {pid}");
    }
    sup.stop(&def).unwrap();
    assert!(signals.sent.lock().unwrap().is_empty());
    assert!(!pid_file.exists(), "stale record removed");
    assert!(f.procs.exists(51) && f.procs.exists(52));
}

#[test]
fn legacy_pid_files_are_adopted_kept_and_removed_on_stop() {
    let f = Fixture::new();
    let nginx = f.ctx.paths.bin.join("nginx");
    fs::create_dir_all(&f.ctx.paths.bin).unwrap();
    fs::write(&nginx, b"nginx").unwrap();
    let def = ServiceDef::site(&f.ctx.paths, &nginx);
    let legacy = def.legacy_pid_files()[0].clone();
    fs::create_dir_all(legacy.parent().unwrap()).unwrap();
    let site = f.ctx.paths.site();
    let title = format!(
        "nginx: master process {} -p {}/ -c {}/nginx.conf",
        nginx.display(),
        site.display(),
        site.display()
    );
    f.procs.add_title(700, 70, &nginx, &title);
    fs::write(&legacy, "700\n").unwrap();
    let (sup, signals) = f.supervisor(&[]);

    let found = sup.find(&def).unwrap();
    assert!(found.legacy);
    assert_eq!(
        found.record,
        PidRecord {
            pid: 700,
            start: 70
        }
    );
    sup.start(&def, &f.env()).unwrap();
    assert!(f.exec.spawned().is_empty(), "adopted, not started twice");
    assert_eq!(record(&def.pid_file()), r#"{"pid":700,"start":70}"#);
    assert!(!sup.find(&def).unwrap().legacy);
    // nginx keeps using its own pid file (`nginx -s reload`): it stays.
    assert_eq!(record(&legacy), "700\n");
    sup.start(&def, &f.env()).unwrap();
    assert!(legacy.exists() && f.exec.spawned().is_empty());

    // Stop removes both files.
    sup.stop(&def).unwrap();
    assert_eq!(*signals.sent.lock().unwrap(), [(700, libc::SIGTERM)]);
    assert!(!legacy.exists() && !def.pid_file().exists());

    // A legacy file naming somebody else's process is dropped untouched.
    let foreign = format!(
        "nginx: master process {} -c /etc/nginx/nginx.conf",
        nginx.display()
    );
    f.procs.add_title(701, 71, &nginx, &foreign);
    fs::write(&legacy, "701").unwrap();
    assert!(!sup.running(&def));
    sup.stop(&def).unwrap();
    assert!(f.procs.exists(701) && !legacy.exists());
}

#[test]
fn pre_start_runs_first_and_its_failure_aborts() {
    let f = Fixture::new();
    let def = ServiceDef::frps(&f.ctx.paths);
    fs::create_dir_all(&f.ctx.paths.frp_bin).unwrap();
    fs::write(def.program(), b"frps").unwrap();
    let exe = f.ctx.paths.executable.to_string_lossy().into_owned();
    f.exec.on(
        &exe,
        &["frps", "net-apply"],
        Output::failure(1, "防火墙失败"),
    );
    let (sup, _) = f.supervisor(&[]);
    let err = sup.start(&def, &f.env()).unwrap_err();
    assert!(err.to_string().contains("防火墙失败"), "{err}");
    assert!(f.exec.spawned().is_empty());

    let f = Fixture::new();
    let def = ServiceDef::frps(&f.ctx.paths);
    fs::create_dir_all(&f.ctx.paths.frp_bin).unwrap();
    fs::write(def.program(), b"frps").unwrap();
    let exe = f.ctx.paths.executable.to_string_lossy().into_owned();
    f.exec.on(&exe, &["frps", "net-apply"], Output::success(""));
    f.run(&def, FAKE_PID_BASE, 1);
    let (sup, _) = f.supervisor(&[]);
    sup.start(&def, &f.env()).unwrap();
    let calls = f.exec.calls();
    assert_eq!(calls.len(), 2);
    assert_eq!(calls[0].display(), format!("{exe} frps net-apply"));
    assert!(calls[0].clear_env && calls[0].timeout.is_some());
    assert_eq!(calls[1].program, def.program().to_string_lossy());
    assert_eq!(def.pid_file(), f.ctx.paths.frp_run.join("onebox-frps.pid"));
    assert!(def.pid_file().exists());
}

#[test]
fn a_oneshot_runs_synchronously_without_a_record() {
    let f = Fixture::new();
    let def = ServiceDef::network(&f.ctx.paths);
    let exe = f.ctx.paths.executable.to_string_lossy().into_owned();
    f.exec.on(&exe, &["net-apply"], Output::success("ok"));
    let (sup, _) = f.supervisor(&[]);
    sup.start(&def, &f.env()).unwrap();
    assert_eq!(f.exec.history(), [format!("{exe} net-apply")]);
    assert!(f.exec.calls()[0].clear_env);
    assert!(f.exec.spawned().is_empty() && !def.pid_file().exists());
    assert!(!sup.running(&def));

    let f2 = Fixture::new();
    let exe = f2.ctx.paths.executable.to_string_lossy().into_owned();
    f2.exec
        .on(&exe, &["net-apply"], Output::failure(3, "规则恢复失败"));
    let (sup, _) = f2.supervisor(&[]);
    let def = ServiceDef::network(&f2.ctx.paths);
    let err = sup.start(&def, &f2.env()).unwrap_err();
    assert!(err.to_string().contains("规则恢复失败"));
}

#[test]
fn runtime_directories_exist_before_the_daemon_starts() {
    let f = Fixture::new();
    let nginx = f.ctx.paths.bin.join("nginx");
    fs::create_dir_all(&f.ctx.paths.bin).unwrap();
    fs::write(&nginx, b"nginx").unwrap();
    let def = ServiceDef::frp_web(&f.ctx.paths, &nginx);
    let runtime = f.ctx.paths.run.join("nginx-frp");
    assert_eq!(def.runtime_dirs(), std::slice::from_ref(&runtime));
    let (sup, _) = f.supervisor(&[]);
    // The spawn finds no process: the start fails, the directory is there.
    assert!(sup.start(&def, &f.env()).is_err());
    assert_eq!(f.exec.spawned().len(), 1);
    for dir in [&f.ctx.paths.run, &runtime] {
        let mode = fs::metadata(dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o755, "{}", dir.display());
    }
}

#[test]
fn helpers_inherit_only_the_lock_they_take() {
    let f = Fixture::new();
    let exe = f.ctx.paths.executable.to_string_lossy().into_owned();
    f.exec.on(&exe, &[], Output::success(""));
    let (sup, _) = f.supervisor(&[]);
    let node = FileLock::acquire(&f.ctx.paths.lock(), "busy").unwrap();
    let frp = FileLock::acquire(&f.ctx.paths.frp_lock(), "busy").unwrap();

    let network = ServiceDef::network(&f.ctx.paths);
    sup.start_with_lock(&network, &f.env(), &node).unwrap();
    sup.start_with_lock(&network, &f.env(), &frp).unwrap();
    sup.start(&network, &f.env()).unwrap();
    let inherited: Vec<_> = f.exec.calls().iter().map(|c| c.inherit_lock_fd).collect();
    assert_eq!(inherited, [Some(node.raw_fd()), None, None]);

    // The FRP pre-start gets the FRP lock; the daemon never gets one.
    f.exec.clear_history();
    let frps = ServiceDef::frps(&f.ctx.paths);
    fs::create_dir_all(&f.ctx.paths.frp_bin).unwrap();
    fs::write(frps.program(), b"frps").unwrap();
    f.run(&frps, FAKE_PID_BASE, 5);
    sup.restart_with_lock(&frps, &f.env(), &frp).unwrap();
    let calls = f.exec.calls();
    assert_eq!(calls[0].display(), format!("{exe} frps net-apply"));
    assert_eq!(calls[0].inherit_lock_fd, Some(frp.raw_fd()));
    assert_eq!(calls[1].inherit_lock_fd, None);
}

#[test]
fn signal_errors_are_reported_in_chinese() {
    let text = |e: std::io::Error| signal_error(42, &e).to_string();
    assert_eq!(
        text(std::io::Error::from_raw_os_error(libc::EPERM)),
        "无法向进程 42 发送信号: 权限不足"
    );
    assert_eq!(
        text(std::io::Error::from_raw_os_error(libc::EINVAL)),
        "无法向进程 42 发送信号: 信号无效"
    );
    assert_eq!(
        text(std::io::ErrorKind::InvalidInput.into()),
        "无法向进程 42 发送信号: 进程号无效"
    );
    assert_eq!(
        SystemSignaller.signal(1, 0).unwrap_err().to_string(),
        "无法向进程 1 发送信号: 进程号无效"
    );
}

#[test]
fn restart_stops_the_old_process_and_spawns_a_new_one() {
    let f = Fixture::new();
    let def = f.core();
    let (sup, signals) = f.supervisor(&[]);
    f.run(&def, 99, 1);
    write_record(&def.pid_file(), &PidRecord { pid: 99, start: 1 }).unwrap();
    f.run(&def, FAKE_PID_BASE, 2);
    sup.restart(&def, &f.env()).unwrap();
    assert_eq!(*signals.sent.lock().unwrap(), [(99, libc::SIGTERM)]);
    assert_eq!(f.exec.spawned().len(), 1);
    assert_eq!(sup.find(&def).unwrap().record.pid, FAKE_PID_BASE);
}

#[test]
fn concurrent_operations_on_one_service_are_serialized() {
    let f = Fixture::new();
    let def = f.core();
    let (sup, _) = f.supervisor(&[]);
    fs::create_dir_all(def.run_dir()).unwrap();
    let held = FileLock::acquire(&def.run_dir().join("onebox-sing-box.lock"), "busy").unwrap();
    let err = sup.start(&def, &f.env()).unwrap_err();
    assert!(matches!(err, Error::Busy(_)), "{err}");
    assert!(err.to_string().contains("onebox-sing-box"));
    assert!(f.exec.spawned().is_empty());
    drop(held);
    f.run(&def, FAKE_PID_BASE, 3);
    sup.start(&def, &f.env()).unwrap();
}

#[test]
fn pid_records_parse_json_or_bare_integers() {
    let start_of = |pid: u32| (pid == 77).then_some(1234);
    for (text, want) in [
        (
            r#"{"pid":77,"start":5}"#,
            Some(PidRecord { pid: 77, start: 5 }),
        ),
        (
            "77\n",
            Some(PidRecord {
                pid: 77,
                start: 1234,
            }),
        ),
        ("78", None),
        ("1", None),
        (r#"{"pid":1,"start":5}"#, None),
        ("-5", None),
        ("abc", None),
        ("", None),
    ] {
        assert_eq!(parse_record(text, start_of), want, "{text:?}");
    }
}

/// /proc of this test process is visible (not another PID namespace).
fn visible_proc() -> bool {
    let own = fs::read_to_string("/proc/self/stat")
        .ok()
        .and_then(|s| s.split_whitespace().next()?.parse::<u32>().ok());
    own == Some(std::process::id())
}

/// Stops a real test daemon even when an assertion fails.
struct KillOnDrop<'a>(&'a Supervisor<'a>, &'a ServiceDef);

impl Drop for KillOnDrop<'_> {
    fn drop(&mut self) {
        let _ = self.0.stop(self.1);
    }
}

/// A context executing real programs, with `system_root` = `/`.
fn real_ctx(dir: &TempDir) -> Ctx {
    let mut paths = crate::paths::Paths::isolated(dir.path());
    paths.system_root = "/".into();
    Ctx {
        paths,
        exec: Arc::new(crate::sys::exec::SystemExec),
        ui: Arc::new(crate::ui::ScriptedPrompter::new(Vec::<String>::new())),
    }
}

#[test]
fn real_daemons_are_started_identified_and_stopped() {
    let Some(sleep) = crate::sys::exec::which_in("sleep", std::ffi::OsStr::new("")) else {
        return;
    };
    if !visible_proc() {
        eprintln!("SKIP: /proc belongs to another PID namespace");
        return;
    }
    let dir = TempDir::new("supervisor-real").unwrap();
    let ctx = real_ctx(&dir);
    let def = ServiceDef::new(
        &ctx.paths,
        "onebox-sleep",
        &sleep,
        vec!["300".into()],
        vec![],
    );
    let sup = Supervisor::new(&ctx);
    let env = service_env(&ctx.paths, InitSystem::None);
    sup.start(&def, &env).unwrap();
    let _cleanup = KillOnDrop(&sup, &def);
    let found = sup.find(&def).expect("the real process is identified");
    assert!(found.record.pid >= 2);
    let environ = fs::read(format!("/proc/{}/environ", found.record.pid)).unwrap();
    let environ = String::from_utf8_lossy(&environ);
    assert!(environ.contains("ONEBOX_INIT=none") && environ.contains(SAFE_PATH));
    assert!(!environ.contains("CARGO"), "cleared environment: {environ}");
    // The open-files limit of the units, or the hard limit when lower.
    let limits = fs::read_to_string(format!("/proc/{}/limits", found.record.pid)).unwrap();
    let row = limits
        .lines()
        .find(|l| l.starts_with("Max open files"))
        .unwrap();
    let values: Vec<u64> = row
        .split_whitespace()
        .filter_map(|w| w.parse().ok())
        .collect();
    assert_eq!(values[0], NOFILE_LIMIT.min(values[1]), "{row}");

    let other = ServiceDef::new(
        &ctx.paths,
        "onebox-sleep",
        &sleep,
        vec!["301".into()],
        vec![],
    );
    assert!(!sup.running(&other), "different arguments are not ours");
    sup.stop(&def).unwrap();
    assert!(!sup.running(&def));
    assert!(identity::process_start(Path::new("/"), found.record.pid).is_none());
}

/// Real nginx (set `ONEBOX_TEST_NGINX` to its path): the master renames
/// itself, and the site is still recognized by its title.
#[test]
#[ignore = "needs a real nginx in ONEBOX_TEST_NGINX"]
fn real_nginx_is_recognized_by_its_title() {
    let Some(nginx) = std::env::var_os("ONEBOX_TEST_NGINX").map(PathBuf::from) else {
        return;
    };
    if !visible_proc() {
        return;
    }
    let dir = TempDir::new("supervisor-nginx").unwrap();
    let ctx = real_ctx(&dir);
    let def = ServiceDef::site(&ctx.paths, &nginx);
    let site = ctx.paths.site();
    fs::create_dir_all(site.join("logs")).unwrap();
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let user = if crate::sys::process::is_root() {
        "user root root;\n"
    } else {
        ""
    };
    let conf = format!(
        "{user}error_log {0}/error.log;\npid {0}/nginx.pid;\nevents {{}}\nhttp {{\n  \
         client_body_temp_path {0}/tmp;\n  proxy_temp_path {0}/tmp;\n  \
         fastcgi_temp_path {0}/tmp;\n  uwsgi_temp_path {0}/tmp;\n  scgi_temp_path {0}/tmp;\n  \
         access_log off;\n  server {{ listen 127.0.0.1:{port}; }}\n}}\n",
        site.display()
    );
    fs::write(site.join("nginx.conf"), conf).unwrap();
    let sup = Supervisor::new(&ctx);
    sup.start(&def, &service_env(&ctx.paths, InitSystem::None))
        .unwrap();
    let _cleanup = KillOnDrop(&sup, &def);
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut titled = false;
    while Instant::now() < deadline && !titled {
        if let Some(found) = sup.find(&def) {
            titled = identity::process_argv(Path::new("/"), found.record.pid)
                .is_some_and(|argv| argv.len() == 1);
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(titled, "nginx master identified by its process title");
    sup.stop(&def).unwrap();
    assert!(!sup.running(&def));
}
