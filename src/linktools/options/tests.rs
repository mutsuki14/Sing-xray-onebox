use super::*;
use crate::sys::fs::TempDir;

fn matches(positionals: &[&str], values: &[(&'static str, &str)]) -> Matches {
    let mut m = Matches {
        positionals: positionals.iter().map(|s| s.to_string()).collect(),
        ..Matches::default()
    };
    for (key, value) in values {
        m.values.entry(key).or_default().push(value.to_string());
    }
    m
}

#[test]
fn defaults_are_v2s() {
    let bench = BenchOptions::from_matches(&matches(&["probe.json"], &[])).unwrap();
    assert_eq!(
        bench,
        BenchOptions {
            common: Common {
                bundle: Some("probe.json".into()),
                ..Common::default()
            },
            ..BenchOptions::default()
        }
    );
    assert_eq!(
        bench.common.url.as_str(),
        "https://www.gstatic.com/generate_204"
    );
    assert_eq!(
        (bench.common.timeout, bench.samples, bench.bytes),
        (8, 5, 4_194_304)
    );
    let failover = FailoverOptions::from_matches(&matches(&["p"], &[])).unwrap();
    assert_eq!(
        (
            failover.port,
            failover.interval,
            failover.failures,
            failover.recoveries,
            failover.cooldown
        ),
        (2080, 15, 3, 3, 60)
    );
    let reality = RealityOptions::from_matches(&matches(&["p"], &[])).unwrap();
    assert_eq!(reality.scope().unwrap(), Scope::CurrentMachineToServer);
    assert_eq!(reality.scope().unwrap().id(), "current-machine-to-server");
}

#[test]
fn every_flag_is_read() {
    let m = matches(
        &["b.json"],
        &[
            (ENTRIES, "a, b"),
            (SINGBOX, "/x/sing-box"),
            (XRAY, "/x/xray"),
            (URL, "http://127.0.0.1:8080/ok"),
            (TIMEOUT, "60"),
            (SAMPLES, "20"),
            (DOWNLOAD_URL, "https://d/x"),
            (UPLOAD_URL, "https://u/x"),
            (BYTES, "1024"),
        ],
    );
    let o = BenchOptions::from_matches(&m).unwrap();
    assert_eq!(
        o.common.entries,
        Some(vec!["a".to_string(), " b".to_string()])
    );
    assert_eq!(
        o.common.binaries.singbox,
        Some(PathBuf::from("/x/sing-box"))
    );
    assert_eq!(o.common.binaries.xray, Some(PathBuf::from("/x/xray")));
    assert_eq!(o.common.url.port(), 8080);
    assert_eq!((o.common.timeout, o.samples, o.bytes), (60, 20, 1024));
    assert_eq!(o.download.unwrap().host(), "d");
    assert_eq!(o.upload.unwrap().host(), "u");
    let m = matches(
        &["b"],
        &[
            (PORT, "65535"),
            (INTERVAL, "3600"),
            (FAILURES, "1"),
            (RECOVERIES, "20"),
            (COOLDOWN, "0"),
        ],
    );
    let f = FailoverOptions::from_matches(&m).unwrap();
    assert_eq!(
        (f.port, f.interval, f.failures, f.recoveries, f.cooldown),
        (65535, 3600, 1, 20, 0)
    );
}

#[test]
fn ranges_are_digits_only_and_name_the_flag() {
    let cases: [(&'static str, &str, &str); 9] = [
        (TIMEOUT, "0", "--timeout 必须是 1..60 之间的整数"),
        (TIMEOUT, "+5", "--timeout 必须是 1..60 之间的整数"),
        (TIMEOUT, "61", "--timeout 必须是 1..60 之间的整数"),
        (TIMEOUT, "", "--timeout 必须是 1..60 之间的整数"),
        (SAMPLES, "21", "--samples 必须是 1..20 之间的整数"),
        (BYTES, "1023", "--bytes 必须是 1024..67108864 之间的整数"),
        (
            BYTES,
            "67108865",
            "--bytes 必须是 1024..67108864 之间的整数",
        ),
        (
            TIMEOUT,
            "99999999999999999999999",
            "--timeout 必须是 1..60 之间的整数",
        ),
        (URL, "file:///etc/passwd", "测试 URL 必须为 HTTP(S)"),
    ];
    for (flag, value, message) in cases {
        let err = BenchOptions::from_matches(&matches(&["b"], &[(flag, value)])).unwrap_err();
        assert_eq!(err.to_string(), message, "{flag} {value:?}");
    }
    let failover: [(&'static str, &str, &str); 5] = [
        (PORT, "80", "--port 必须是 1024..65535 之间的整数"),
        (PORT, "65536", "--port 必须是 1024..65535 之间的整数"),
        (INTERVAL, "0", "--interval 必须是 1..3600 之间的整数"),
        (RECOVERIES, "21", "--recoveries 必须是 1..20 之间的整数"),
        (COOLDOWN, "3601", "--cooldown 必须是 0..3600 之间的整数"),
    ];
    for (flag, value, message) in failover {
        let err = FailoverOptions::from_matches(&matches(&["b"], &[(flag, value)])).unwrap_err();
        assert_eq!(err.to_string(), message, "{flag} {value:?}");
    }
    let err = BenchOptions::from_matches(&matches(&["b"], &[(DOWNLOAD_URL, "https://a@b/")]));
    assert_eq!(
        err.unwrap_err().to_string(),
        "测试 URL 不得包含账号，且必须有主机名"
    );
}

#[test]
fn scope_rules() {
    let with = |positionals: &[&str], scope: &str| {
        RealityOptions::from_matches(&matches(positionals, &[(SCOPE, scope)]))
    };
    assert_eq!(
        with(&["b"], "server-local").unwrap().scope().unwrap(),
        Scope::ServerLocal
    );
    assert_eq!(
        with(&["b"], "current-machine-to-server")
            .unwrap()
            .scope()
            .unwrap(),
        Scope::CurrentMachineToServer
    );
    assert_eq!(
        with(&[], "server-local").unwrap().scope().unwrap(),
        Scope::ServerLocal
    );
    let local = RealityOptions::from_matches(&matches(&[], &[])).unwrap();
    assert_eq!(
        (local.scope().unwrap(), local.common.bundle),
        (Scope::ServerLocal, None)
    );
    assert_eq!(
        with(&[], "current-machine-to-server")
            .unwrap_err()
            .to_string(),
        "省略探测配置时只能执行本机回环检查（--scope server-local）"
    );
    assert_eq!(
        with(&["b"], "anywhere").unwrap_err().to_string(),
        "--scope 只能是 server-local 或 current-machine-to-server"
    );
    // Options built directly (menus) follow the same rule.
    let direct = RealityOptions::default();
    assert_eq!(direct.scope().unwrap(), Scope::ServerLocal, "no bundle");
    let forced = RealityOptions {
        scope: Some(Scope::CurrentMachineToServer),
        ..RealityOptions::default()
    };
    assert!(forced.scope().is_err());
}

#[test]
fn outputs_must_be_new_files_in_existing_directories() {
    let dir = TempDir::new("linktools-test").unwrap();
    let fresh = dir.join("report.json");
    let fresh_text = fresh.to_str().unwrap();
    let o = BenchOptions::from_matches(&matches(&["b"], &[(OUTPUT, fresh_text)])).unwrap();
    assert_eq!(o.output.as_deref(), Some(fresh.as_path()));

    fs::write(&fresh, "x").unwrap();
    let err = BenchOptions::from_matches(&matches(&["b"], &[(OUTPUT, fresh_text)])).unwrap_err();
    assert_eq!(err.to_string(), "输出文件已存在；请选择新文件路径");
    let link = dir.join("dangling");
    std::os::unix::fs::symlink(dir.join("nowhere"), &link).unwrap();
    assert!(
        check_output(&link).is_err(),
        "dangling symlink counts as existing"
    );
    let missing = dir.join("no/such/dir/r.json");
    let err = check_output(&missing).unwrap_err();
    assert_eq!(
        err.to_string(),
        format!(
            "输出文件所在目录不存在: {}",
            dir.join("no/such/dir").display()
        )
    );
    assert!(check_output(Path::new("onebox-surely-absent-report.json")).is_ok());
}

#[test]
fn ca_files_must_exist() {
    let dir = TempDir::new("linktools-test").unwrap();
    let ca = dir.join("ca.pem");
    let err = Common::from_matches(&matches(&["b"], &[(CA, ca.to_str().unwrap())])).unwrap_err();
    assert_eq!(
        err.to_string(),
        format!("--ca 文件不存在或不是普通文件: {}", ca.display())
    );
    fs::write(&ca, "pem").unwrap();
    let common = Common::from_matches(&matches(&["b"], &[(CA, ca.to_str().unwrap())])).unwrap();
    assert_eq!(common.ca, Some(ca));
    let err = Common::from_matches(&matches(&["b"], &[(CA, dir.path().to_str().unwrap())]));
    assert!(err.is_err(), "a directory is not a CA file");
}
