use super::*;
use crate::host::init::InitSystem;

fn paths() -> Paths {
    Paths::from_lookup(|_| None).unwrap()
}

#[test]
fn known_services_carry_their_traits_as_data() {
    let p = paths();
    let nginx = Path::new("/usr/sbin/nginx");

    let xray = ServiceDef::core(&p, Core::Xray, true);
    assert_eq!(xray.name, XRAY);
    assert_eq!(xray.restart_prevent_status, Some(23));
    assert_eq!(xray.after, ["onebox-site"]);
    assert_eq!(xray.identity.subcommand.as_deref(), Some("run"));
    assert_eq!(xray.identity.config, Some(p.core_config(Core::Xray)));
    assert_eq!(xray.log_files, [p.log.join("xray.log")]);

    let singbox = ServiceDef::core(&p, Core::Singbox, false);
    assert_eq!(singbox.restart_prevent_status, None);
    assert!(singbox.after.is_empty());
    assert_eq!(singbox.log_files, [p.log.join("singbox.log")]);

    for (def, conf) in [
        (ServiceDef::site(&p, nginx), p.site().join("nginx.conf")),
        (
            ServiceDef::subscription_web(&p, nginx),
            p.subscription().join("nginx.conf"),
        ),
        (
            ServiceDef::frp_web(&p, nginx),
            p.frp_root.join("nginx.conf"),
        ),
    ] {
        assert!(
            def.identity.nginx_title,
            "{} is recognized by its title",
            def.name
        );
        assert_eq!(def.identity.config, Some(conf));
        assert_eq!(def.args[4..], ["-g", "daemon off;"]);
    }

    let frps = ServiceDef::frps(&p);
    assert_eq!(
        frps.pre_start,
        Some(vec![
            "/usr/local/bin/onebox".into(),
            "frps".into(),
            "net-apply".into()
        ])
    );
    assert_eq!(frps.run_dir, p.frp_run);
    assert_eq!(frps.log_dir, p.frp_log);
    assert_eq!(
        frps.spec_path(),
        p.frp_root.join("services/onebox-frps.json")
    );
    assert_eq!(frps.pid_file(), p.frp_run.join("onebox-frps.pid"));
    assert_eq!(frps.legacy_pid_files, [p.frp_run.join("frps.pid")]);

    let web = ServiceDef::frp_web(&p, nginx);
    assert_eq!(web.legacy_pid_files, [p.frp_root.join("nginx.pid")]);
    assert_eq!(
        web.log_candidates(),
        [
            p.frp_log.join("onebox-frp-web.log"),
            p.frp_log.join("nginx.log"),
            p.frp_log.join("nginx-error.log"),
            p.frp_root.join("error.log"),
        ]
    );

    let network = ServiceDef::network(&p);
    assert_eq!(network.kind, ServiceKind::Oneshot);
    assert!(network.after_firewall);
    assert_eq!(network.program, p.executable);
    assert_eq!(network.identity, Identity::default());

    let site = ServiceDef::site(&p, nginx);
    assert_eq!(site.legacy_pid_files, [p.site().join("nginx.pid")]);
    assert_eq!(site.spec_path(), p.root.join("services/onebox-site.json"));
    assert_eq!(site.log_file(), p.log.join("onebox-site.log"));
}

#[test]
fn spec_round_trip_keeps_the_v2_shape() {
    let p = paths();
    let def = ServiceDef::subscription_web(&p, Path::new("/usr/sbin/nginx"));
    let env = service_env(&p, InitSystem::None);
    let spec = def.spec(&env);
    let json = serde_json::to_value(&spec).unwrap();
    assert_eq!(
        json,
        serde_json::json!({
            "program": "/usr/sbin/nginx",
            "args": ["-p", "/etc/onebox/subscription", "-c",
                     "/etc/onebox/subscription/nginx.conf", "-g", "daemon off;"],
            "after": ["onebox-subscription"],
            "environment": env.iter().map(|(k, v)| vec![k, v]).collect::<Vec<_>>(),
        })
    );
    assert_eq!(
        ServiceDef::from_spec(&p, SUBSCRIPTION_WEB, &spec).unwrap(),
        def
    );

    // A v2 spec without "environment" still loads.
    let v2: ServiceSpec = serde_json::from_str(
        r#"{"program":"/opt/onebox/bin/xray","args":["run","-c","/etc/onebox/xray.json"],"after":[]}"#,
    )
    .unwrap();
    assert!(v2.environment.is_empty());
    let loaded = ServiceDef::from_spec(&p, XRAY, &v2).unwrap();
    assert_eq!(loaded, ServiceDef::core(&p, Core::Xray, false));
}

#[test]
fn service_env_is_the_fourteen_allowlisted_variables() {
    let p = paths();
    for (init, value) in [
        (InitSystem::Systemd, "systemd"),
        (InitSystem::Openrc, "openrc"),
        (InitSystem::None, "none"),
    ] {
        let env = service_env(&p, init);
        assert_eq!(env.len(), 14);
        assert_eq!(env[0], ("ONEBOX_DIR".to_owned(), "/etc/onebox".to_owned()));
        assert_eq!(env[13], (INIT_ENV.to_owned(), value.to_owned()));
        validate_env(&env).unwrap();
    }
}

#[test]
fn spec_validation_rejects_credentials_and_injection() {
    let p = paths();
    let good = ServiceDef::network(&p).spec(&service_env(&p, InitSystem::Systemd));
    good.validate().unwrap();
    type Mutation = Box<dyn Fn(&mut ServiceSpec)>;
    let cases: Vec<(&str, Mutation)> = vec![
        (
            "CF_Token",
            Box::new(|s| s.environment.push(("CF_Token".into(), "x".into()))),
        ),
        (
            "GH_TOKEN",
            Box::new(|s| s.environment.push(("GH_TOKEN".into(), "x".into()))),
        ),
        (
            "PATH",
            Box::new(|s| s.environment.push(("PATH".into(), "/tmp".into()))),
        ),
        (
            "ONEBOX_PASSWORD",
            Box::new(|s| s.environment.push(("ONEBOX_PASSWORD".into(), "x".into()))),
        ),
        (
            "duplicate",
            Box::new(|s| {
                let first = s.environment[0].clone();
                s.environment.push(first);
            }),
        ),
        (
            "init value",
            Box::new(|s| s.environment[13].1 = "upstart".into()),
        ),
        (
            "env newline",
            Box::new(|s| s.environment[0].1 = "/etc\nX=1".into()),
        ),
        (
            "relative program",
            Box::new(|s| s.program = "onebox".into()),
        ),
        ("arg newline", Box::new(|s| s.args.push("a\rb".into()))),
        ("program NUL", Box::new(|s| s.program = "/bin/a\0b".into())),
        ("dependency", Box::new(|s| s.after.push("sshd".into()))),
        (
            "dependency injection",
            Box::new(|s| s.after.push("onebox-x;id".into())),
        ),
    ];
    for (label, mutate) in cases {
        let mut spec = good.clone();
        mutate(&mut spec);
        assert!(spec.validate().is_err(), "{label} must be rejected");
    }
    let mut targets = good.clone();
    targets.after = TARGETS
        .iter()
        .map(|t| t.to_string())
        .chain(["onebox-site".into()])
        .collect();
    targets.validate().unwrap();
}

#[test]
fn names_and_definitions_are_validated() {
    for name in ["onebox-xray", "onebox-sing-box", "onebox-A1"] {
        validate_name(name).unwrap();
    }
    for name in [
        "onebox-",
        "onebox",
        "xray",
        "onebox-x;id",
        "../../other",
        "onebox-a_b",
        "onebox-é",
    ] {
        assert!(validate_name(name).is_err(), "{name}");
    }
    let p = paths();
    let mut def = ServiceDef::frps(&p);
    def.validate().unwrap();
    def.pre_start = Some(vec![]);
    assert!(def.validate().is_err(), "empty pre-start");
    def.pre_start = Some(vec!["frps".into()]);
    assert!(def.validate().is_err(), "relative pre-start");
    let mut def = ServiceDef::frps(&p);
    def.description = "x\n[Service]".into();
    assert!(def.validate().is_err());
    assert!(ServiceDef::from_spec(&p, "bad name", &def.spec(&[])).is_err());
}

#[test]
fn arg_after_finds_flag_values() {
    let args: Vec<String> = ["-p", "/a", "-c", "/a/n.conf"]
        .iter()
        .map(|s| s.to_string())
        .collect();
    assert_eq!(arg_after(&args, "-c"), Some("/a/n.conf"));
    assert_eq!(arg_after(&args, "-p"), Some("/a"));
    assert_eq!(arg_after(&args, "-g"), None);
    assert_eq!(arg_after(&args[..3], "-c"), None);
}

#[test]
fn unit_and_script_paths() {
    let p = paths();
    assert_eq!(
        unit_file(&p, XRAY),
        PathBuf::from("/etc/systemd/system/onebox-xray.service")
    );
    assert_eq!(
        script_file(&p, XRAY),
        PathBuf::from("/etc/init.d/onebox-xray")
    );
    assert_eq!(init_value(InitSystem::None), "none");
}
