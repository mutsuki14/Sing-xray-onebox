use super::system::format_secs;
use super::*;
use crate::sys::fs::TempDir;
use crate::sys::signal::{self, SignalScope};
use std::time::Instant;

fn sh(script: &str) -> Cmd {
    Cmd::new("/bin/sh").args(["-c", script])
}

fn run(cmd: &Cmd) -> Output {
    SystemExec.run(cmd).unwrap()
}

/// True when `pid` is gone or a zombie.
fn dead(pid: u32) -> bool {
    match std::fs::read_to_string(format!("/proc/{pid}/stat")) {
        Err(_) => true,
        Ok(stat) => stat
            .rsplit_once(") ")
            .is_some_and(|(_, rest)| rest.starts_with('Z')),
    }
}

fn wait_until(limit: Duration, mut done: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + limit;
    while Instant::now() < deadline {
        if done() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    done()
}

fn signal_guard() -> std::sync::MutexGuard<'static, ()> {
    signal::TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

fn daemon(script: &str) -> Cmd {
    sh(script).daemon_env(&[])
}

fn reap(pid: u32) {
    // SAFETY: waiting for our own (detached) child; status pointer is null.
    unsafe {
        libc::waitpid(pid as libc::pid_t, std::ptr::null_mut(), 0);
    }
}

#[test]
fn captures_output_and_exit_code() {
    let out = run(&sh("echo out; echo err >&2; exit 3"));
    assert_eq!(out.code, 3);
    assert_eq!(out.stdout, "out\n");
    assert_eq!(out.stderr, "err\n");
    assert!(!out.ok());
    assert!(run(&sh("true")).ok());
}

#[test]
fn signal_death_reports_128_plus_signal() {
    assert_eq!(run(&sh("kill -TERM $$")).code, 128 + libc::SIGTERM);
}

#[test]
fn non_utf8_output_is_lossy() {
    let out = run(&sh("printf '\\377ok'"));
    assert_eq!(out.stdout, "\u{fffd}ok");
}

#[test]
fn large_stdin_does_not_deadlock() {
    let input: Vec<u8> = (0..2_000_000u32).map(|i| b'a' + (i % 26) as u8).collect();
    let out = run(&Cmd::new("cat").stdin_bytes(input.clone()));
    assert!(out.ok());
    assert_eq!(out.stdout.as_bytes(), &input[..]);
}

#[test]
fn environment_policy() {
    // (sh supplies its own default PATH, so probe HOME instead.)
    let out = run(&sh("echo \"$A|${HOME-unset}\"").clear_env().env("A", "1"));
    assert_eq!(out.stdout, "1|unset\n");
    let out = run(&Cmd::new("sh")
        .args(["-c", "echo \"$PATH|$ONEBOX_DIR\""])
        .daemon_env(&[("ONEBOX_DIR".into(), "/etc/onebox".into())]));
    assert_eq!(out.stdout, format!("{SAFE_PATH}|/etc/onebox\n"));
    // Without clear_env the parent environment is inherited.
    let out = run(&sh("echo \"$HOME\""));
    assert_eq!(out.stdout.trim(), std::env::var("HOME").unwrap_or_default());
}

#[test]
fn bare_names_resolve_through_safe_path_and_keep_argv0() {
    // A useless PATH (as under cron) still finds system programs, exactly
    // like `which`; argv[0] remains the bare name.
    let out = run(&Cmd::new("cat")
        .arg("/proc/self/cmdline")
        .clear_env()
        .env("PATH", "/nonexistent"));
    assert!(out.ok(), "{}", out.stderr);
    assert_eq!(out.stdout, "cat\0/proc/self/cmdline\0");
    let missing = SystemExec.run(&Cmd::new("definitely-not-a-program-xyz").clear_env());
    assert!(missing.is_err());
}

#[test]
fn working_directory() {
    let dir = TempDir::new("exec-cwd").unwrap();
    let out = run(&sh("pwd -P").cwd(dir.path()));
    let expected = std::fs::canonicalize(dir.path()).unwrap();
    assert_eq!(out.stdout.trim(), expected.to_str().unwrap());
}

#[test]
fn children_start_with_an_empty_signal_mask() {
    let _block = crate::sys::signal::BlockSignals::new().unwrap();
    let out = run(&Cmd::new("cat").arg("/proc/self/status"));
    let blocked = out
        .stdout
        .lines()
        .find_map(|l| l.strip_prefix("SigBlk:"))
        .unwrap()
        .trim()
        .to_string();
    assert_eq!(u64::from_str_radix(&blocked, 16).unwrap(), 0);
}

#[test]
fn timeout_kills_the_whole_group() {
    let _g = signal_guard();
    let started = Instant::now();
    let out = run(&sh("sleep 30 & echo $!; wait").timeout(Duration::from_millis(300)));
    assert!(started.elapsed() < Duration::from_secs(5));
    assert_eq!(out.code, TIMEOUT_EXIT);
    assert_eq!(out.stderr, "命令超时（0.3 秒）");
    let grandchild: u32 = out.stdout.trim().parse().unwrap();
    assert!(
        wait_until(Duration::from_secs(3), || dead(grandchild)),
        "background sleep survived the timeout"
    );
}

#[test]
fn timeout_bounds_output_held_open_by_background_children() {
    // The direct child exits at once, but a background sleep keeps its
    // stdout open: the run must still end near the deadline and the
    // straggler must be killed.
    let _g = signal_guard();
    let started = Instant::now();
    let out = run(&sh("sleep 5 & echo $!").timeout(Duration::from_millis(500)));
    let elapsed = started.elapsed();
    assert!(elapsed < Duration::from_millis(2500), "took {elapsed:?}");
    assert_eq!(out.code, 0, "the command itself succeeded");
    let straggler: u32 = out.stdout.trim().parse().unwrap();
    assert!(
        wait_until(Duration::from_secs(3), || dead(straggler)),
        "background sleep survived"
    );
}

#[test]
fn background_children_that_release_the_pipes_are_left_alone() {
    let _g = signal_guard();
    let started = Instant::now();
    let out = run(&sh("sleep 3 >/dev/null 2>&1 & echo $!").timeout(Duration::from_secs(10)));
    assert!(started.elapsed() < Duration::from_secs(2));
    let daemon: u32 = out.stdout.trim().parse().unwrap();
    assert!(!dead(daemon), "nothing held the pipes, nothing is killed");
    // SAFETY: cleaning up the sleep started above.
    unsafe {
        libc::kill(daemon as libc::pid_t, libc::SIGKILL);
    }
}

#[test]
fn fast_commands_finish_before_their_timeout() {
    let _g = signal_guard();
    let started = Instant::now();
    let out = run(&sh("echo done").timeout(Duration::from_secs(10)));
    assert!(started.elapsed() < Duration::from_secs(1));
    assert_eq!((out.code, out.stdout.as_str()), (0, "done\n"));
    assert_eq!(format_secs(Duration::from_secs(8)), "8");
}

/// A timed child that exits 7 on SIGINT; the marker appears once the trap is set.
fn trapping_child(marker: &Path) -> Cmd {
    sh(&format!(
        "trap 'exit 7' INT; : > '{}'; sleep 5",
        marker.display()
    ))
    .timeout(Duration::from_secs(10))
}

/// Raise SIGINT on a helper thread once `marker` exists (the handler is
/// installed then, so the test process is never killed).
fn interrupt_when_ready(marker: PathBuf) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        assert!(wait_until(Duration::from_secs(5), || marker.exists()));
        // SAFETY: raising a signal on this thread; a recording handler is
        // installed by the waiting exec call.
        unsafe {
            libc::raise(libc::SIGINT);
        }
    })
}

#[test]
fn ctrl_c_is_forwarded_to_timed_children_under_an_owner_scope() {
    let _g = signal_guard();
    signal::clear();
    let dir = TempDir::new("exec-forward").unwrap();
    let marker = dir.join("ready");
    let scope = SignalScope::install().unwrap();
    let helper = interrupt_when_ready(marker.clone());
    let started = Instant::now();
    let out = run(&trapping_child(&marker));
    helper.join().unwrap();
    assert!(started.elapsed() < Duration::from_secs(3));
    assert_eq!(out.code, 7, "the child saw the forwarded SIGINT");
    assert_eq!(signal::pending(), Some(libc::SIGINT), "left for the owner");
    assert!(signal::check().unwrap_err().is_cancelled());
    signal::clear();
    drop(scope);
}

#[test]
fn ctrl_c_cancels_timed_children_without_an_owner_scope() {
    let _g = signal_guard();
    signal::clear();
    let dir = TempDir::new("exec-cancel").unwrap();
    let marker = dir.join("ready");
    let helper = interrupt_when_ready(marker.clone());
    let started = Instant::now();
    let err = SystemExec.run(&trapping_child(&marker)).unwrap_err();
    helper.join().unwrap();
    assert!(started.elapsed() < Duration::from_secs(3));
    assert!(err.is_cancelled(), "{err}");
    assert_eq!(err.exit_code(), 130);
    assert!(err.to_string().starts_with("sh 被信号 2 中断"), "{err}");
    assert_eq!(signal::pending(), None, "consumed by the cancellation");
}

#[test]
fn children_ignoring_a_forwarded_signal_are_killed() {
    let _g = signal_guard();
    let dir = TempDir::new("exec-stubborn").unwrap();
    let marker = dir.join("ready");
    let scope = SignalScope::install().unwrap();
    let helper = interrupt_when_ready(marker.clone());
    let cmd = sh(&format!(
        "trap '' INT; : > '{}'; sleep 30",
        marker.display()
    ))
    .timeout(Duration::from_secs(30));
    let started = Instant::now();
    let out = run(&cmd);
    helper.join().unwrap();
    let elapsed = started.elapsed();
    assert!(elapsed < Duration::from_secs(6), "took {elapsed:?}");
    assert_eq!(out.code, 128 + libc::SIGKILL);
    signal::clear();
    drop(scope);
}

#[test]
fn missing_working_directories_are_named() {
    let err = SystemExec
        .run(&Cmd::new("/bin/ls").cwd("/nonexistent-onebox-dir"))
        .unwrap_err();
    assert_eq!(err.to_string(), "工作目录不存在: /nonexistent-onebox-dir");
    let dir = TempDir::new("exec-cwd-file").unwrap();
    let file = dir.join("file");
    std::fs::write(&file, "").unwrap();
    let err = SystemExec.run(&Cmd::new("/bin/ls").cwd(&file)).unwrap_err();
    assert_eq!(
        err.to_string(),
        format!("工作目录不是目录: {}", file.display())
    );
    let err = SystemExec
        .spawn_detached(
            &daemon("true").cwd("/nonexistent-onebox-dir"),
            &dir.join("d.log"),
        )
        .unwrap_err();
    assert_eq!(err.to_string(), "工作目录不存在: /nonexistent-onebox-dir");
}

#[test]
fn spawn_failures_name_the_program() {
    for program in ["/nonexistent/prog", "definitely-not-a-program-xyz"] {
        let err = SystemExec.run(&Cmd::new(program)).unwrap_err();
        assert_eq!(err.to_string(), format!("未找到程序 {program}"));
    }
    let dir = TempDir::new("exec-perm").unwrap();
    let file = dir.join("not-executable");
    std::fs::write(&file, "#!/bin/sh\n").unwrap();
    let program = file.to_str().unwrap();
    let err = SystemExec.run(&Cmd::new(program)).unwrap_err();
    assert_eq!(err.to_string(), format!("无法执行 {program}: 权限不足"));
    assert!(SystemExec.run(&sh("true").inherit_lock(-1)).is_err());
}

#[test]
fn detached_spawn_logs_and_starts_a_session() {
    let dir = TempDir::new("exec-spawn").unwrap();
    let log = dir.join("logs/daemon.log");
    let pid = SystemExec
        .spawn_detached(&daemon("echo hello; echo oops >&2; sleep 1"), &log)
        .unwrap();
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).unwrap();
    let fields: Vec<&str> = stat.rsplit_once(") ").unwrap().1.split(' ').collect();
    assert_eq!(fields[3], pid.to_string(), "session id equals the pid");
    assert!(wait_until(Duration::from_secs(5), || {
        std::fs::read_to_string(&log).is_ok_and(|s| s.contains("hello") && s.contains("oops"))
    }));
    reap(pid);
    let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode(&log), 0o600);
    assert_eq!(mode(&dir.join("logs")), 0o700);
    // Appends, never truncates.
    let pid = SystemExec
        .spawn_detached(&daemon("echo again"), &log)
        .unwrap();
    reap(pid);
    let text = std::fs::read_to_string(&log).unwrap();
    assert!(text.contains("hello") && text.ends_with("again\n"));
}

#[test]
fn detached_spawn_refuses_symlinked_logs_and_locks() {
    let dir = TempDir::new("exec-spawn-link").unwrap();
    let target = dir.join("target");
    std::fs::write(&target, "").unwrap();
    let link = dir.join("link.log");
    std::os::unix::fs::symlink(&target, &link).unwrap();
    let err = SystemExec
        .spawn_detached(&daemon("true"), &link)
        .unwrap_err();
    assert!(err.to_string().contains("不允许符号链接"), "{err}");
    assert!(SystemExec
        .spawn_detached(&daemon("true").inherit_lock(3), &dir.join("x.log"))
        .is_err());
}

#[test]
fn detached_daemons_need_an_isolated_environment() {
    let dir = TempDir::new("exec-daemon-env").unwrap();
    let log = dir.join("d.log");
    let err = SystemExec.spawn_detached(&sh("true"), &log).unwrap_err();
    assert_eq!(err.to_string(), DAEMON_ENV_REQUIRED);
    assert!(!log.exists(), "refused before anything is created");
    // A cleared environment without PATH gets SAFE_PATH; cwd defaults to /.
    let cmd = Cmd::new("/bin/sh")
        .args(["-c", "echo \"$PATH|$(pwd -P)|${SECRET-unset}\""])
        .clear_env();
    let pid = SystemExec.spawn_detached(&cmd, &log).unwrap();
    reap(pid);
    let text = std::fs::read_to_string(&log).unwrap();
    assert_eq!(text, format!("{SAFE_PATH}|/|unset\n"));
    let pid = SystemExec
        .spawn_detached(&daemon("pwd -P").cwd(dir.path()), &log)
        .unwrap();
    reap(pid);
    let expected = std::fs::canonicalize(dir.path()).unwrap();
    assert!(std::fs::read_to_string(&log)
        .unwrap()
        .ends_with(&format!("{}\n", expected.display())));
}

#[test]
fn which_lookup() {
    assert!(SystemExec.which("sh").is_some());
    assert_eq!(SystemExec.which("/bin/sh"), Some(PathBuf::from("/bin/sh")));
    assert_eq!(SystemExec.which("definitely-not-a-program-xyz"), None);
    assert_eq!(SystemExec.which(""), None);
    assert_eq!(SystemExec.which("./sh"), None);
    // An empty or relative PATH still finds system programs via SAFE_PATH.
    assert!(which_in("sh", std::ffi::OsStr::new("")).is_some());
    assert!(which_in("sh", std::ffi::OsStr::new(".:relative")).is_some());
    let dir = TempDir::new("exec-which").unwrap();
    std::fs::write(dir.join("tool"), "").unwrap();
    let path = std::ffi::OsString::from(dir.path());
    assert_eq!(which_in("tool", &path), None, "not executable");
    std::fs::set_permissions(dir.join("tool"), std::fs::Permissions::from_mode(0o755)).unwrap();
    assert_eq!(which_in("tool", &path), Some(dir.join("tool")));
}

#[test]
fn cmd_builder_and_display() {
    let cmd = Cmd::new("/usr/sbin/nginx")
        .args(["-t", "-c"])
        .arg("/etc/x.conf");
    assert_eq!(cmd.program_name(), "nginx");
    assert_eq!(cmd.display(), "/usr/sbin/nginx -t -c /etc/x.conf");
    let cmd = Cmd::new("x").clear_env().inherit_lock(7).stream();
    assert!(cmd.clear_env && cmd.stream);
    assert_eq!(cmd.inherit_lock_fd, Some(7));
}

#[test]
fn supervised_children_report_output_and_exit() {
    let mut child = SystemExec
        .spawn(&sh("echo out; echo err >&2; exit 3"))
        .unwrap();
    let out = child.wait_timeout(Duration::from_secs(5)).unwrap().unwrap();
    assert_eq!((out.code, out.stdout.as_str()), (3, "out\n"));
    assert_eq!(out.stderr, "err\n");
    assert_eq!(child.try_wait().unwrap(), Some(out), "result is cached");
    child.kill_group(libc::SIGKILL).unwrap();
}

#[test]
fn supervised_children_lead_a_session_and_terminate_as_a_group() {
    let dir = TempDir::new("exec-supervise").unwrap();
    let pidfile = dir.join("pid");
    let script = format!("sleep 30 & echo $! > '{}'; wait", pidfile.display());
    let mut child = SystemExec.spawn(&sh(&script)).unwrap();
    let pid = child.pid();
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).unwrap();
    let fields: Vec<&str> = stat.rsplit_once(") ").unwrap().1.split(' ').collect();
    assert_eq!(fields[3], pid.to_string(), "session id equals the pid");
    assert!(wait_until(Duration::from_secs(5), || {
        std::fs::read_to_string(&pidfile).is_ok_and(|s| s.ends_with('\n'))
    }));
    let grandchild: u32 = std::fs::read_to_string(&pidfile)
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    assert_eq!(child.try_wait().unwrap(), None);
    assert_eq!(
        child.wait_timeout(Duration::from_millis(100)).unwrap(),
        None
    );
    let out = child.terminate(Duration::from_secs(2)).unwrap();
    assert_eq!(out.code, 128 + libc::SIGTERM);
    assert!(wait_until(Duration::from_secs(3), || dead(grandchild)));
}

#[test]
fn dropping_a_supervised_child_kills_and_reaps_it() {
    let child = SystemExec.spawn(&Cmd::new("sleep").arg("30")).unwrap();
    let pid = child.pid();
    assert!(!dead(pid));
    let started = Instant::now();
    drop(child);
    assert!(started.elapsed() < Duration::from_secs(3));
    assert!(
        !Path::new(&format!("/proc/{pid}")).exists(),
        "killed and reaped"
    );
}

#[test]
fn supervised_children_honor_the_command_timeout() {
    let mut child = SystemExec
        .spawn(&sh("echo started; sleep 30").timeout(Duration::from_millis(200)))
        .unwrap();
    let out = child.wait_timeout(Duration::from_secs(5)).unwrap().unwrap();
    assert_eq!(out.code, TIMEOUT_EXIT);
    assert_eq!(out.stdout, "started\n");
    assert_eq!(out.stderr, "命令超时（0.2 秒）");
}

#[test]
fn supervised_spawn_preconditions() {
    let err = SystemExec.spawn(&sh("true").inherit_lock(3)).err().unwrap();
    assert_eq!(err.to_string(), "子进程不能继承配置锁");
    let err = SystemExec
        .spawn(&Cmd::new("/nonexistent/prog"))
        .err()
        .unwrap();
    assert_eq!(err.to_string(), "未找到程序 /nonexistent/prog");
}

#[test]
fn supervised_output_keeps_the_tail() {
    let mut child = SystemExec
        .spawn(&sh("head -c 3000000 /dev/zero | tr '\\0' a; echo END"))
        .unwrap();
    let out = child
        .wait_timeout(Duration::from_secs(10))
        .unwrap()
        .unwrap();
    assert_eq!(out.stdout.len(), 1 << 20);
    assert!(out.stdout.ends_with("aaaEND\n"));
}
