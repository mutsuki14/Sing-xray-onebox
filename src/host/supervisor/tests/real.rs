//! Real processes (`sleep`, an opt-in real nginx) under `/proc`.

use super::*;

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

/// Real nginx (`ONEBOX_NGINX_BIN`, as CI provides it): the master renames
/// itself, and the site is still recognized by its title.
#[test]
#[ignore = "needs a real nginx in ONEBOX_NGINX_BIN"]
fn real_nginx_is_recognized_by_its_title() {
    let Some(nginx) = crate::sys::testenv::tool(crate::host::nginx::ENV_BIN) else {
        return;
    };
    if !visible_proc() {
        eprintln!("SKIP: /proc belongs to another PID namespace");
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
