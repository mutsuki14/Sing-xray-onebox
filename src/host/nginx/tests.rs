use super::*;
use crate::host::init::InitSystem;
use crate::sys::exec::{FakeExec, Output};
use crate::sys::fs::TempDir;
use std::fs;
use std::sync::Arc;

struct Fixture {
    _dir: TempDir,
    ctx: Ctx,
    exec: Arc<FakeExec>,
}

fn fixture() -> Fixture {
    let dir = TempDir::new("nginx").unwrap();
    let (ctx, exec, _) = Ctx::test(dir.path());
    fs::create_dir_all(&ctx.paths.system_root).unwrap();
    Fixture {
        _dir: dir,
        ctx,
        exec,
    }
}

impl Fixture {
    fn system_file(&self, rel: &str, text: &str) {
        let path = self.ctx.paths.system(rel);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, text).unwrap();
    }

    fn init(&self, init: InitSystem) {
        match init {
            InitSystem::Systemd => {
                fs::create_dir_all(self.ctx.paths.system("/run/systemd/system")).unwrap()
            }
            InitSystem::Openrc => self.system_file("/run/openrc", ""),
            InitSystem::None => {}
        }
    }

    /// `dnf install -y nginx` succeeds and provides the binary.
    fn installable(&self) {
        self.exec.provide("dnf");
        let fake = Arc::clone(&self.exec);
        self.exec.on_fn(
            |c| c.program == "dnf",
            move |_| {
                fake.provide("nginx");
                Ok(Output::success(""))
            },
        );
    }

    fn history(&self) -> Vec<String> {
        self.exec.history()
    }
}

fn no_env(_: &str) -> Option<String> {
    None
}

const DEBIAN_CONF: &str = "user www-data;\nworker_processes auto;\nevents {}\nhttp {\n\tinclude /etc/nginx/conf.d/*.conf;\n\tinclude /etc/nginx/sites-enabled/*;\n}\n";

// ---- discovery --------------------------------------------------------------

#[test]
fn binary_lookup_order() {
    let f = fixture();
    assert_eq!(
        binary_with(&f.ctx, &no_env).unwrap_err().to_string(),
        "找不到 nginx"
    );
    f.exec.provide("/usr/sbin/nginx");
    assert_eq!(
        binary_with(&f.ctx, &no_env).unwrap(),
        PathBuf::from("/usr/sbin/nginx")
    );
    f.exec.provide("nginx");
    assert_eq!(
        binary_with(&f.ctx, &no_env).unwrap(),
        PathBuf::from("/usr/bin/nginx"),
        "PATH first"
    );

    let custom = f._dir.join("custom-nginx");
    fs::write(&custom, "#!/bin/sh\n").unwrap();
    let shown = custom.to_string_lossy().into_owned();
    let env = |k: &str| (k == ENV_BIN).then(|| shown.clone());
    let err = binary_with(&f.ctx, &env).unwrap_err();
    assert_eq!(
        err.to_string(),
        format!("ONEBOX_NGINX_BIN 不存在或不可执行: {shown}")
    );
    fs::set_permissions(&custom, fs::Permissions::from_mode(0o755)).unwrap();
    assert_eq!(binary_with(&f.ctx, &env).unwrap(), custom);
    let relative = |k: &str| (k == ENV_BIN).then(|| "nginx".to_string());
    assert!(binary_with(&f.ctx, &relative).is_err());
}

// ---- installation and the distro service ------------------------------------

#[test]
fn fresh_install_neutralizes_the_distro_service() {
    for (init, expected) in [
        (
            InitSystem::Systemd,
            vec![
                "dnf install -y nginx",
                "systemctl disable --now nginx.service",
            ],
        ),
        (
            InitSystem::Openrc,
            vec![
                "dnf install -y nginx",
                "rc-service nginx stop",
                "rc-update del nginx default",
            ],
        ),
        (InitSystem::None, vec!["dnf install -y nginx"]),
    ] {
        let f = fixture();
        f.init(init);
        f.installable();
        let bin = ensure_installed_with(&f.ctx, &no_env, true).unwrap();
        assert_eq!(bin, PathBuf::from("/usr/bin/nginx"));
        assert_eq!(f.history(), expected, "{init}");
    }
}

#[test]
fn install_preconditions() {
    let f = fixture();
    f.installable();
    let err = ensure_installed_with(&f.ctx, &no_env, false).unwrap_err();
    assert_eq!(err.to_string(), "此操作需要 root 权限");

    let f = fixture();
    f.installable();
    f.system_file("/etc/nginx/nginx.conf", DEBIAN_CONF);
    let err = ensure_installed_with(&f.ctx, &no_env, true).unwrap_err();
    assert_eq!(
        err.to_string(),
        "检测到现有 nginx 配置但找不到程序，请先修复 nginx"
    );
    assert!(f.history().is_empty(), "nothing installed");
}

#[test]
fn failed_disable_only_warns() {
    let f = fixture();
    f.init(InitSystem::Systemd);
    f.installable();
    f.exec.on(
        "systemctl",
        &["disable"],
        Output::failure(
            1,
            "Failed to disable unit: Unit file nginx.service does not exist.\n",
        ),
    );
    assert!(ensure_installed_with(&f.ctx, &no_env, true).is_ok());
}

#[test]
fn private_build_is_used_as_is() {
    // A private build named by ONEBOX_NGINX_BIN: no install, no service
    // inspection (distro rule details: nginx/distro/tests.rs).
    let f = fixture();
    f.init(InitSystem::Systemd);
    let custom = f._dir.join("nginx");
    fs::write(&custom, "").unwrap();
    fs::set_permissions(&custom, fs::Permissions::from_mode(0o755)).unwrap();
    let shown = custom.to_string_lossy().into_owned();
    let env = |k: &str| (k == ENV_BIN).then(|| shown.clone());
    assert_eq!(ensure_installed_with(&f.ctx, &env, false).unwrap(), custom);
    assert!(f.history().is_empty());
}

// ---- commands ---------------------------------------------------------------

#[test]
fn config_test_arguments_and_errors() {
    let f = fixture();
    f.exec.provide("nginx");
    let prefix = Path::new("/etc/onebox/site");
    let conf = Path::new("/etc/onebox/site/nginx.conf");
    f.exec.on("nginx", &["-t"], Output::success(""));
    test(&f.ctx, prefix, conf).unwrap();
    let cmd = &f.exec.calls()[0];
    assert_eq!(
        cmd.args,
        [
            "-t",
            "-q",
            "-p",
            "/etc/onebox/site",
            "-c",
            "/etc/onebox/site/nginx.conf"
        ]
    );
    assert_eq!(cmd.timeout, Some(TEST_TIMEOUT));

    let f = fixture();
    f.exec.provide("nginx");
    f.exec.on(
        "nginx",
        &["-t"],
        Output::failure(
            1,
            "2026/10/08 18:19:39 [emerg] 24958#24958: unknown directive \"bogus\" in /x/bad.conf:2\n\
             nginx: configuration file /x/bad.conf test failed\n",
        ),
    );
    assert_eq!(
        test(&f.ctx, prefix, conf).unwrap_err().to_string(),
        "nginx 配置测试失败: [emerg] unknown directive \"bogus\" in /x/bad.conf:2"
    );
    let f = fixture();
    f.exec.provide("nginx");
    f.exec.on("nginx", &[], Output::failure(1, ""));
    assert_eq!(
        test(&f.ctx, prefix, conf).unwrap_err().to_string(),
        "nginx 配置测试失败: 退出码 1"
    );
}

#[test]
fn test_summary_cleaning() {
    let cases = [
        (
            "2026/10/08 18:19:39 [warn] 1#1: the \"listen ... http2\" directive is deprecated",
            "[warn] the \"listen ... http2\" directive is deprecated",
        ),
        (
            "nginx: [emerg] open() \"/x/nginx.conf\" failed (2: No such file or directory)",
            "nginx: [emerg] open() \"/x/nginx.conf\" failed (2: No such file or directory)",
        ),
        ("nginx: configuration file /x test failed", ""),
        ("plain line", "plain line"),
        ("2026/10/08 18:19:39 中文消息", "中文消息"),
    ];
    for (input, want) in cases {
        assert_eq!(test_summary(input), want, "{input}");
    }
}

#[test]
fn reload_signals_the_instance() {
    let f = fixture();
    f.exec.provide("nginx");
    f.exec.on("nginx", &["-p"], Output::success(""));
    reload(&f.ctx, Path::new("/p"), Path::new("/p/nginx.conf")).unwrap();
    assert_eq!(
        f.exec.calls()[0].args,
        ["-p", "/p", "-c", "/p/nginx.conf", "-s", "reload"]
    );
    let f = fixture();
    f.exec.provide("nginx");
    f.exec.on(
        "nginx",
        &[],
        Output::failure(
            1,
            "nginx: [error] invalid PID number \"\" in \"/p/nginx.pid\"",
        ),
    );
    let err = reload(&f.ctx, Path::new("/p"), Path::new("/p/nginx.conf")).unwrap_err();
    assert!(err
        .to_string()
        .starts_with("nginx 重新加载失败: nginx 执行失败 (1)"));
}

#[test]
fn version_parsing_and_http2_syntax() {
    let v = |a, b, c| NginxVersion {
        major: a,
        minor: b,
        patch: c,
    };
    let cases = [
        ("nginx version: nginx/1.24.0 (Ubuntu)", Some(v(1, 24, 0))),
        ("nginx version: nginx/1.25.1", Some(v(1, 25, 1))),
        ("nginx version: openresty/1.21.4.3", Some(v(1, 21, 4))),
        ("nginx version: nginx/1.27", Some(v(1, 27, 0))),
        ("nginx version: freenginx/1.27.2\n", Some(v(1, 27, 2))),
        ("nginx: invalid option", None),
        ("nginx version: nginx/x.y", None),
    ];
    for (text, want) in cases {
        assert_eq!(NginxVersion::parse(text), want, "{text}");
    }
    assert!(!v(1, 24, 0).supports_http2_directive());
    assert!(!v(1, 25, 0).supports_http2_directive());
    assert!(supports_http2_directive(v(1, 25, 1)));
    assert!(v(1, 26, 0).supports_http2_directive());
    assert!(v(2, 0, 0).supports_http2_directive());
    assert_eq!(v(1, 24, 0).to_string(), "1.24.0");

    let f = fixture();
    f.exec.provide("nginx");
    f.exec.on(
        "nginx",
        &["-v"],
        Output::failure(0, "nginx version: nginx/1.24.0 (Ubuntu)\n"),
    );
    assert_eq!(version(&f.ctx).unwrap(), v(1, 24, 0));
    let f = fixture();
    f.exec.provide("nginx");
    f.exec.on("nginx", &["-v"], Output::failure(1, "boom"));
    assert_eq!(
        version(&f.ctx).unwrap_err().to_string(),
        "无法识别 nginx 版本"
    );
}

// ---- worker account -----------------------------------------------------------

#[test]
fn user_directive_parsing() {
    let cases = [
        ("user www-data;", Some(("www-data", None))),
        (
            "  user nginx nginx;  # distro default",
            Some(("nginx", Some("nginx"))),
        ),
        (
            "# configuration file /etc/nginx/nginx.conf:\nuser  nobody nogroup;\n",
            Some(("nobody", Some("nogroup"))),
        ),
        ("#user www-data;\nuser nginx;", Some(("nginx", None))),
        ("userid on;\nuser_agent x;", None),
        ("user a b c;", None),
        ("user $bad;", None),
        ("user www-data", None),
        ("", None),
    ];
    for (text, want) in cases {
        let want = want.map(|(u, g): (&str, Option<&str>)| (u.to_string(), g.map(str::to_string)));
        assert_eq!(parse_user_directive(text), want, "{text}");
    }
}

fn accounts(exec: &FakeExec, users: &[(&str, &str)]) {
    for (user, group) in users {
        exec.on("id", &["-u", user], Output::success("33\n")).on(
            "id",
            &["-gn", user],
            Output::success(format!("{group}\n")),
        );
    }
    exec.on("id", &[], Output::failure(1, "id: no such user"));
}

#[test]
fn worker_from_the_distro_configuration() {
    let f = fixture();
    f.exec.provide("nginx");
    f.exec.on(
        "nginx",
        &["-T"],
        Output::success("# configuration file /etc/nginx/nginx.conf:\nuser nginx;\nevents {}\n"),
    );
    accounts(&f.exec, &[("www-data", "www-data"), ("nginx", "nginx")]);
    let w = worker(&f.ctx).unwrap();
    assert_eq!((w.user.as_str(), w.group.as_str()), ("nginx", "nginx"));
    assert_eq!(w.to_string(), "nginx nginx");
    assert_eq!(worker_group(&f.ctx).unwrap(), "nginx");

    // An explicit group in the directive wins over `id -gn`.
    let f = fixture();
    f.exec.provide("nginx");
    f.exec
        .on("nginx", &["-T"], Output::success("user nobody nogroup;\n"));
    accounts(&f.exec, &[("nobody", "nobody")]);
    assert_eq!(worker(&f.ctx).unwrap().to_string(), "nobody nogroup");
}

#[test]
fn worker_fallbacks() {
    // No nginx -T (or root in it): first existing candidate.
    let f = fixture();
    f.exec.provide("nginx");
    f.exec.on("nginx", &["-T"], Output::success("user root;\n"));
    accounts(&f.exec, &[("nginx", "nginx"), ("nobody", "nogroup")]);
    assert_eq!(worker(&f.ctx).unwrap().to_string(), "nginx nginx");

    let f = fixture();
    accounts(&f.exec, &[("www-data", "www-data"), ("nginx", "nginx")]);
    assert_eq!(
        worker(&f.ctx).unwrap().to_string(),
        "www-data www-data",
        "no binary: candidates in order"
    );

    let f = fixture();
    accounts(&f.exec, &[]);
    assert_eq!(
        worker(&f.ctx).unwrap_err().to_string(),
        "缺少 nginx 非 root 工作账号"
    );

    let f = fixture();
    accounts(&f.exec, &[("www-data", "bad group")]);
    assert_eq!(
        worker(&f.ctx).unwrap_err().to_string(),
        "nginx 工作账号的组名无效"
    );
}

/// Real nginx: `ONEBOX_NGINX_BIN=…/usr/sbin/nginx cargo test -- --ignored`.
#[test]
#[ignore = "needs a real nginx binary in ONEBOX_NGINX_BIN"]
fn real_nginx_test_and_version() {
    let dir = TempDir::new("nginx-real").unwrap();
    let ctx = Ctx {
        paths: crate::paths::Paths::isolated(dir.path()),
        exec: Arc::new(crate::sys::exec::SystemExec),
        ui: Arc::new(crate::ui::ScriptedPrompter::new(Vec::<String>::new())),
    };
    let p = dir.path().display();
    let good = dir.join("good.conf");
    fs::write(
        &good,
        format!(
            "pid {p}/nginx.pid;\nerror_log {p}/error.log;\nevents {{}}\n\
             http {{ access_log off; client_body_temp_path {p}/cb; proxy_temp_path {p}/px;\n\
             fastcgi_temp_path {p}/f; uwsgi_temp_path {p}/u; scgi_temp_path {p}/s;\n\
             server {{ listen 127.0.0.1:18089; }} }}\n"
        ),
    )
    .unwrap();
    let bad = dir.join("bad.conf");
    fs::write(&bad, "events {}\nhttp { bogus on; }\n").unwrap();
    test(&ctx, dir.path(), &good).unwrap();
    let err = test(&ctx, dir.path(), &bad).unwrap_err().to_string();
    assert!(
        err.starts_with("nginx 配置测试失败: [emerg] unknown directive \"bogus\""),
        "{err}"
    );
    let version = version(&ctx).unwrap();
    assert!(version.major >= 1, "{version}");
}
