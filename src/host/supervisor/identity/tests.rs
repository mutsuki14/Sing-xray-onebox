use super::*;
use crate::domain::protocol::Core;
use crate::host::service::{ServiceDef, SUBSCRIPTION};
use crate::host::supervisor::fixture::{cmdline, stat_line, FakeProc};
use crate::paths::Paths;
use crate::sys::fs::TempDir;

fn argv(words: &[&str]) -> Vec<Vec<u8>> {
    split_cmdline(&cmdline(words))
}

#[test]
fn start_time_is_field_22_after_the_command_name() {
    for (comm, state, start, want) in [
        ("sing-box", "S", 123, Some(123)),
        ("a) (b", "R", 99, Some(99)),
        ("nginx: master", "D", 7, Some(7)),
        ("zombie", "Z", 5, None),
        ("dead", "X", 5, None),
        ("dead", "x", 5, None),
    ] {
        assert_eq!(
            parse_start(&stat_line(42, comm, state, start)),
            want,
            "{comm}"
        );
    }
    assert_eq!(parse_start("42 (x) S 1 2"), None, "truncated");
    assert_eq!(parse_start("garbage"), None);
}

#[test]
fn reads_start_argv_and_executable_from_the_system_root() {
    let dir = TempDir::new("identity").unwrap();
    let program = dir.join("bin/sing-box");
    std::fs::create_dir_all(program.parent().unwrap()).unwrap();
    std::fs::write(&program, b"bin").unwrap();
    let system = dir.join("system");
    let procs = FakeProc::new(&system);
    procs.add(100, 555, &program, &[&program.to_string_lossy(), "run"]);
    assert_eq!(process_start(&system, 100), Some(555));
    assert_eq!(process_start(&system, 101), None);
    assert_eq!(
        process_argv(&system, 100).unwrap(),
        argv(&[&program.to_string_lossy(), "run"])
    );
    assert!(executable_matches(&system, 100, &program));
    assert!(!executable_matches(&system, 100, &dir.join("bin/xray")));

    // Atomic replacement: the running image shows as deleted, and the
    // binary may be briefly absent.
    let deleted = format!("{} (deleted)", program.display());
    procs.add(102, 1, Path::new(&deleted), &["x"]);
    assert!(executable_matches(&system, 102, &program));
    std::fs::remove_file(&program).unwrap();
    assert!(executable_matches(&system, 102, &program));
    assert!(!executable_matches(
        &system,
        102,
        &dir.join("missing/sing-box")
    ));

    procs.zombie(100);
    assert_eq!(process_start(&system, 100), None);
}

#[test]
fn cores_need_run_and_their_exact_config() {
    let p = Paths::from_lookup(|_| None).unwrap();
    let def = ServiceDef::core(&p, Core::Singbox, false);
    let bin = "/opt/onebox/bin/sing-box";
    let conf = "/etc/onebox/sing-box.json";
    for (words, want) in [
        (vec![bin, "run", "--disable-color", "-c", conf], true),
        (vec![bin, "run", "-c", conf], true),
        (vec![bin, "run", "--config", conf], true),
        (vec![bin, "run", &format!("--config={conf}")], true),
        (vec![bin, "check", "-c", conf], false),
        (vec![bin, "run", "--note", conf], false),
        (
            vec![bin, "run", "-c", "different.json", "--note", conf],
            false,
        ),
        (
            vec![bin, "run", "-c", conf, "--config", "different.json"],
            false,
        ),
        (vec![bin, "run", "-c", conf, "-config=other.json"], false),
        (vec![bin, "run", "-c", &format!("{conf}.other")], false),
        (vec![bin, "run", "-c"], false),
        (vec![bin], false),
        (vec![], false),
    ] {
        assert_eq!(command_matches(&def, &argv(&words)), want, "{words:?}");
    }
}

#[test]
fn services_without_a_config_need_exact_arguments() {
    let p = Paths::from_lookup(|_| None).unwrap();
    let def = ServiceDef::subscription(&p);
    assert_eq!(def.name(), SUBSCRIPTION);
    let exe = "/usr/local/bin/onebox";
    assert!(command_matches(
        &def,
        &argv(&[exe, "subscription", "serve"])
    ));
    assert!(!command_matches(&def, &argv(&[exe, "subscription"])));
    assert!(!command_matches(
        &def,
        &argv(&[exe, "subscription", "serve", "-x"])
    ));
    assert!(!command_matches(
        &def,
        &argv(&[exe, "subscription", "renew"])
    ));
}

#[test]
fn every_nginx_service_is_recognized_by_its_master_title() {
    let p = Paths::from_lookup(|_| None).unwrap();
    let nginx = Path::new("/usr/sbin/nginx");
    for (def, prefix) in [
        (ServiceDef::site(&p, nginx), "/etc/onebox/site"),
        (
            ServiceDef::subscription_web(&p, nginx),
            "/etc/onebox/subscription",
        ),
        (ServiceDef::frp_web(&p, nginx), "/etc/onebox-frp"),
    ] {
        let conf = format!("{prefix}/nginx.conf");
        let title = |p: &str, tail: &str| {
            vec![
                format!("nginx: master process /usr/sbin/nginx -p {p} -c {conf}{tail}")
                    .into_bytes(),
            ]
        };
        for (slash, tail) in [
            ("", " -g daemon off;"),
            ("/", ""),
            ("", ""),
            ("/", " -g daemon off;"),
        ] {
            assert!(
                command_matches(&def, &title(&format!("{prefix}{slash}"), tail)),
                "{} {slash:?} {tail:?}",
                def.name()
            );
        }
        let other_site = title("/srv/www", " -g daemon off;");
        assert!(!command_matches(&def, &other_site), "{}", def.name());
        let suffixed = vec![format!(
            "nginx: master process /usr/sbin/nginx -p {prefix} -c {conf}.other -g daemon off;"
        )
        .into_bytes()];
        assert!(!command_matches(&def, &suffixed));
        let other_program = vec![format!(
            "nginx: master process /usr/local/sbin/nginx -p {prefix} -c {conf} -g daemon off;"
        )
        .into_bytes()];
        assert!(!command_matches(&def, &other_program));
        assert!(!command_matches(&def, &[b"nginx: worker process".to_vec()]));
        // Before setproctitle the argv is still the real one.
        let mut words = vec!["/usr/sbin/nginx"];
        words.extend(def.args().iter().map(String::as_str));
        assert!(command_matches(&def, &argv(&words)));
    }
    // A title is only accepted for nginx services.
    let def = ServiceDef::frps(&p);
    assert!(!command_matches(
        &def,
        &[b"nginx: master process /opt/onebox-frp/frps -c /etc/onebox-frp/frps.toml".to_vec()]
    ));
}

#[test]
fn cmdline_splitting_drops_padding() {
    assert_eq!(
        split_cmdline(b"nginx: master process x\0\0\0\0"),
        vec![b"nginx: master process x".to_vec()]
    );
    assert_eq!(split_cmdline(b"a\0b\0"), vec![b"a".to_vec(), b"b".to_vec()]);
    assert!(split_cmdline(b"").is_empty());
}
