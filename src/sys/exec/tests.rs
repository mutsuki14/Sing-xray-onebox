use super::*;
use crate::sys::fs::TempDir;
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
    let _g = crate::sys::signal::TEST_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
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
fn fast_commands_finish_before_their_timeout() {
    let _g = crate::sys::signal::TEST_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let out = run(&sh("echo done").timeout(Duration::from_secs(10)));
    assert_eq!((out.code, out.stdout.as_str()), (0, "done\n"));
    assert_eq!(format_secs(Duration::from_secs(8)), "8");
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
        .spawn_detached(&sh("echo hello; echo oops >&2; sleep 1"), &log)
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
    let pid = SystemExec.spawn_detached(&sh("echo again"), &log).unwrap();
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
    let err = SystemExec.spawn_detached(&sh("true"), &link).unwrap_err();
    assert!(err.to_string().contains("不允许符号链接"), "{err}");
    assert!(SystemExec
        .spawn_detached(&sh("true").inherit_lock(3), &dir.join("x.log"))
        .is_err());
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
fn fake_rules_match_in_order() {
    let fake = FakeExec::new();
    fake.on("systemctl", &["is-active"], Output::success("active\n"))
        .on("systemctl", &[], Output::failure(5, "generic"))
        .on("/usr/sbin/nginx", &["-t"], Output::success("syntax ok"));
    let active = fake
        .run(&Cmd::new("systemctl").args(["is-active", "onebox-xray"]))
        .unwrap();
    assert_eq!(active.stdout, "active\n");
    let other = fake.run(&Cmd::new("/bin/systemctl").arg("stop")).unwrap();
    assert_eq!(other.code, 5, "matched by file name");
    assert!(fake
        .run(&Cmd::new("/usr/sbin/nginx").arg("-t"))
        .unwrap()
        .ok());
    let miss = fake.run(&Cmd::new("nginx").arg("-t")).unwrap();
    assert_eq!(miss.code, 127, "rule program is a path; bare name differs");
    assert_eq!(miss.stderr, "fake: unexpected command: nginx -t");
    assert_eq!(
        fake.history(),
        [
            "systemctl is-active onebox-xray",
            "/bin/systemctl stop",
            "/usr/sbin/nginx -t",
            "nginx -t"
        ]
    );
}

#[test]
fn fake_closures_spawns_and_which() {
    let fake = FakeExec::new();
    fake.on_fn(
        |cmd| cmd.program == "curl",
        |cmd| Ok(Output::success(cmd.args.join(","))),
    )
    .on_fn(
        |cmd| cmd.program == "boom",
        |_| Err(Error::msg("未找到程序 boom")),
    );
    assert_eq!(
        fake.run(&Cmd::new("curl").args(["-4", "x"]))
            .unwrap()
            .stdout,
        "-4,x"
    );
    assert!(fake.run(&Cmd::new("boom")).is_err());
    let log = Path::new("/tmp/x.log");
    let first = fake.spawn_detached(&Cmd::new("frps"), log).unwrap();
    let second = fake.spawn_detached(&Cmd::new("frps"), log).unwrap();
    assert_eq!((first, second), (FAKE_PID_BASE, FAKE_PID_BASE + 1));
    assert_eq!(fake.spawned().len(), 2);
    assert_eq!(fake.calls().len(), 4);
    fake.provide("nft");
    assert_eq!(fake.which("nft"), Some(PathBuf::from("/usr/bin/nft")));
    assert_eq!(
        fake.which("/usr/sbin/nft"),
        Some(PathBuf::from("/usr/sbin/nft"))
    );
    assert_eq!(fake.which("ufw"), None);
    fake.clear_history();
    assert!(fake.history().is_empty());
}
