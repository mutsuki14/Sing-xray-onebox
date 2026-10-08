use super::*;
use crate::host::nginx::ensure_installed_with;
use crate::sys::exec::{FakeExec, Output};
use crate::sys::fs::{sha256_hex, TempDir};
use std::fs;
use std::os::unix::fs::symlink;
use std::sync::Arc;

const NGINX_CONF: &str = "user www-data;\nworker_processes auto;\nevents {}\nhttp {\n\
    \tinclude /etc/nginx/conf.d/*.conf;\n\tinclude /etc/nginx/sites-enabled/*;\n}\n";
const DEFAULT_SITE: &str =
    "server {\n\tlisten 80 default_server;\n\troot /var/www/html;\n\tserver_name _;\n}\n";
const CERTBOT_SITE: &str = "server {\n\tserver_name blog.example.com;\n\troot /var/www/html;\n\
    \tlisten 443 ssl; # managed by Certbot\n\tssl_certificate /etc/letsencrypt/live/blog/fullchain.pem;\n}\n";
const DISABLE: &str = "systemctl disable --now nginx.service";

/// Stand-in for MD5 in tests: content-derived, 32 hex characters.
fn fake_md5(bytes: &[u8]) -> String {
    sha256_hex(bytes)[..32].to_owned()
}

fn no_env(_: &str) -> Option<String> {
    None
}

struct Host {
    _dir: TempDir,
    ctx: Ctx,
    exec: Arc<FakeExec>,
}

/// An installed nginx under `init`, its service enabled or not.
fn host(init: InitSystem, enabled: bool) -> Host {
    let dir = TempDir::new("nginx-distro").unwrap();
    let (ctx, exec, _) = Ctx::test(dir.path());
    fs::create_dir_all(&ctx.paths.system_root).unwrap();
    match init {
        InitSystem::Systemd => fs::create_dir_all(ctx.paths.system("/run/systemd/system")).unwrap(),
        InitSystem::Openrc => {
            fs::create_dir_all(ctx.paths.system("/run")).unwrap();
            fs::write(ctx.paths.system("/run/openrc"), "").unwrap()
        }
        InitSystem::None => {}
    }
    exec.provide("nginx");
    let (code, state) = if enabled {
        (0, "enabled\n")
    } else {
        (1, "disabled\n")
    };
    exec.on(
        "systemctl",
        &["is-enabled"],
        Output {
            code,
            stdout: state.into(),
            stderr: String::new(),
        },
    )
    .on("systemctl", &["disable"], Output::success(""))
    .on("rc-service", &[], Output::success(""))
    .on("rc-update", &[], Output::success(""));
    Host {
        _dir: dir,
        ctx,
        exec,
    }
}

impl Host {
    fn file(&self, host_path: &str, text: &str) -> &Self {
        let path = self.ctx.paths.system(host_path);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, text).unwrap();
        self
    }

    fn link(&self, host_path: &str, target: &str) -> &Self {
        let path = self.ctx.paths.system(host_path);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        symlink(target, path).unwrap();
        self
    }

    /// dpkg knows `packaged` (host path, packaged content) as conffiles;
    /// `md5sum` hashes what is on disk.
    fn dpkg(&self, packaged: &[(&str, &str)]) -> &Self {
        let listing: String = packaged
            .iter()
            .map(|(path, text)| format!(" {path} {}\n", fake_md5(text.as_bytes())))
            .collect();
        self.exec
            .provide("dpkg-query")
            .provide("md5sum")
            .on(
                "dpkg-query",
                &[],
                Output {
                    code: 1,
                    stdout: format!("{listing}\n"),
                    stderr: "dpkg-query: no packages found matching nginx\n".into(),
                },
            )
            .on_fn(
                |c| c.program == "md5sum",
                |c| {
                    let bytes = fs::read(&c.args[0])?;
                    let sum = fake_md5(&bytes);
                    Ok(Output::success(format!("{sum}  {}\n", c.args[0])))
                },
            );
        self
    }

    /// The Debian package layout with the packaged files untouched.
    fn debian_defaults(&self) -> &Self {
        self.file(MAIN_CONF, NGINX_CONF)
            .file("/etc/nginx/sites-available/default", DEFAULT_SITE)
            .link(
                "/etc/nginx/sites-enabled/default",
                "/etc/nginx/sites-available/default",
            )
    }

    fn debian_db(&self) -> &Self {
        self.dpkg(&[
            (MAIN_CONF, NGINX_CONF),
            ("/etc/nginx/sites-available/default", DEFAULT_SITE),
            ("/etc/nginx/mime.types", "types {}"),
        ])
    }

    /// rpm: `nginx` owns `owned`; `rpm -V` prints `verify`.
    fn rpm(&self, owned: &[&str], verify: &str) -> &Self {
        let list: String = owned.iter().map(|p| format!("{p}\n")).collect();
        let code = i32::from(!verify.is_empty());
        self.exec
            .provide("rpm")
            .on("rpm", &["-qf"], Output::success("nginx\n"))
            .on("rpm", &["-ql", "nginx"], Output::success(list))
            .on(
                "rpm",
                &["-V", "nginx"],
                Output {
                    code,
                    stdout: verify.into(),
                    stderr: String::new(),
                },
            );
        self
    }

    fn history(&self) -> Vec<String> {
        ensure_installed_with(&self.ctx, &no_env, true).unwrap();
        self.exec.history()
    }

    fn neutralized(&self) -> bool {
        self.history().iter().any(|c| c == DISABLE)
    }
}

// ---- Debian / dpkg --------------------------------------------------------

#[test]
fn pristine_debian_package_is_neutralized() {
    let h = host(InitSystem::Systemd, true);
    h.debian_defaults().debian_db();
    let history = h.history();
    assert_eq!(history[0], "systemctl is-enabled nginx.service");
    assert_eq!(
        history[1],
        "dpkg-query -W --showformat=${Conffiles}\\n nginx-common nginx"
    );
    assert!(history[2].starts_with("md5sum ") && history[2].ends_with("/etc/nginx/nginx.conf"));
    assert!(
        history[3].ends_with("/etc/nginx/sites-available/default"),
        "link followed"
    );
    assert_eq!(history[4], DISABLE);
    assert_eq!(history.len(), 5);
}

#[test]
fn edited_default_site_is_left_alone() {
    // certbot --nginx rewrote the default site the package symlinks.
    let h = host(InitSystem::Systemd, true);
    h.debian_defaults()
        .debian_db()
        .file("/etc/nginx/sites-available/default", CERTBOT_SITE);
    assert!(!h.neutralized());

    // A hand-made `default` in sites-enabled (not the package's link).
    let h = host(InitSystem::Systemd, true);
    h.file(MAIN_CONF, NGINX_CONF)
        .file("/etc/nginx/sites-enabled/default", DEFAULT_SITE)
        .debian_db();
    assert!(!h.neutralized(), "not a package conffile");
}

#[test]
fn other_configuration_is_left_alone() {
    let cases: [(&str, &str); 4] = [
        ("/etc/nginx/sites-enabled/blog", "server { listen 80; }"),
        ("/etc/nginx/conf.d/app.conf", "server {}"),
        ("/etc/nginx/http.d/default.conf", "server {}"),
        ("/etc/nginx/default.d/php.conf", "location ~ \\.php$ {}"),
    ];
    for (path, text) in cases {
        let h = host(InitSystem::Systemd, true);
        h.debian_defaults().debian_db().file(path, text);
        assert!(!h.neutralized(), "{path}");
    }
    let h = host(InitSystem::Systemd, true);
    h.debian_defaults().debian_db().file(
        MAIN_CONF,
        &format!("{NGINX_CONF}include /srv/sites/*.conf;\n"),
    );
    assert!(!h.neutralized(), "edited nginx.conf");
}

#[test]
fn unverifiable_hosts_are_left_alone() {
    // No dpkg or rpm (Alpine, source builds).
    let h = host(InitSystem::Systemd, true);
    h.debian_defaults();
    assert_eq!(h.history(), ["systemctl is-enabled nginx.service"]);

    // dpkg without nginx conffiles.
    let h = host(InitSystem::Systemd, true);
    h.debian_defaults().dpkg(&[]);
    assert!(!h.neutralized());

    // No nginx.conf, a dangling link, a directory entry.
    let h = host(InitSystem::Systemd, true);
    h.debian_db();
    assert!(!h.neutralized(), "missing nginx.conf");
    let h = host(InitSystem::Systemd, true);
    h.debian_defaults()
        .debian_db()
        .link("/etc/nginx/sites-enabled/old", "../sites-available/old");
    assert!(!h.neutralized(), "dangling link");
    let h = host(InitSystem::Systemd, true);
    h.debian_defaults().debian_db();
    fs::create_dir_all(h.ctx.paths.system("/etc/nginx/conf.d/sub")).unwrap();
    assert!(!h.neutralized(), "directory entry");

    // Not enabled: nothing is even inspected.
    let h = host(InitSystem::Systemd, false);
    h.debian_defaults().debian_db();
    assert_eq!(h.history(), ["systemctl is-enabled nginx.service"]);
}

#[test]
fn openrc_default_runlevel() {
    let h = host(InitSystem::Openrc, true);
    h.debian_defaults().debian_db();
    assert!(h.history().is_empty(), "not in the default runlevel");
    let h = host(InitSystem::Openrc, true);
    h.debian_defaults()
        .debian_db()
        .link("/etc/runlevels/default/nginx", "/etc/init.d/nginx");
    let history = h.history();
    assert_eq!(
        &history[history.len() - 2..],
        ["rc-service nginx stop", "rc-update del nginx default"]
    );
}

// ---- RPM ------------------------------------------------------------------

/// RHEL's packaged nginx.conf carries the default server block itself.
const RHEL_CONF: &str =
    "events {}\nhttp {\n include /etc/nginx/conf.d/*.conf;\n server {\n  listen 80;\n }\n}\n";

#[test]
fn rpm_verification() {
    let owned = [MAIN_CONF, "/etc/nginx/mime.types", "/etc/nginx/conf.d"];
    let h = host(InitSystem::Systemd, true);
    h.file(MAIN_CONF, RHEL_CONF).rpm(&owned, "");
    let history = h.history();
    assert_eq!(
        &history[1..4],
        [
            "rpm -qf --queryformat %{NAME}\\n /etc/nginx/nginx.conf",
            "rpm -ql nginx",
            "rpm -V nginx",
        ]
    );
    assert_eq!(history.last().map(String::as_str), Some(DISABLE));

    // Another file of the package differs: still pristine for us.
    let h = host(InitSystem::Systemd, true);
    h.file(MAIN_CONF, RHEL_CONF)
        .rpm(&owned, ".M.......  c /etc/nginx/mime.types\n");
    assert!(h.neutralized());

    let refused = [
        "S.5....T.  c /etc/nginx/nginx.conf\n",
        "missing   c /etc/nginx/nginx.conf\n",
        "error: cannot open Packages database\n",
    ];
    for verify in refused {
        let h = host(InitSystem::Systemd, true);
        h.file(MAIN_CONF, RHEL_CONF).rpm(&owned, verify);
        assert!(!h.neutralized(), "{verify}");
    }
    let h = host(InitSystem::Systemd, true);
    h.file(MAIN_CONF, RHEL_CONF)
        .file("/etc/nginx/conf.d/app.conf", "server {}")
        .rpm(&owned, "");
    assert!(!h.neutralized(), "conf.d entry not owned by the package");
}

// ---- helpers --------------------------------------------------------------

#[test]
fn path_resolution() {
    assert_eq!(
        normalize("/etc/nginx/../nginx/./x//y").as_deref(),
        Some("/etc/nginx/x/y")
    );
    assert_eq!(normalize("/../..").as_deref(), Some("/"));
    assert_eq!(normalize("relative"), None);

    let h = host(InitSystem::None, false);
    h.file("/etc/nginx/sites-available/default", DEFAULT_SITE)
        .link("/etc/nginx/sites-enabled/a", "../sites-available/default")
        .link("/etc/nginx/sites-enabled/b", "a")
        .link("/etc/nginx/sites-enabled/loop", "loop")
        .link(
            "/etc/nginx/sites-enabled/up",
            "../../../../etc/nginx/sites-available/default",
        );
    let resolve = |p: &str| resolve(&h.ctx, p);
    let default = Some("/etc/nginx/sites-available/default".to_owned());
    assert_eq!(resolve("/etc/nginx/sites-enabled/a"), default);
    assert_eq!(resolve("/etc/nginx/sites-enabled/b"), default, "chains");
    assert_eq!(
        resolve("/etc/nginx/sites-enabled/up"),
        default,
        "stays in the root"
    );
    assert_eq!(resolve("/etc/nginx/sites-enabled/loop"), None);
    assert_eq!(resolve("/etc/nginx/sites-enabled"), None, "directory");
    assert_eq!(resolve("/etc/nginx/missing"), None);
}

#[test]
fn package_listing_parsers() {
    let sums = parse_conffiles(
        "\n /etc/nginx/nginx.conf 3E4D1C2B3E4D1C2B3E4D1C2B3E4D1C2B\n \
         /etc/nginx/old.conf 00000000000000000000000000000000 obsolete\n \
         /etc/nginx/new.conf newconffile\n garbage\n",
    );
    assert_eq!(sums.len(), 2);
    assert_eq!(
        sums["/etc/nginx/nginx.conf"],
        "3e4d1c2b3e4d1c2b3e4d1c2b3e4d1c2b"
    );

    let changed =
        parse_rpm_verify("S.5....T.  c /etc/nginx/nginx.conf\nmissing     /etc/nginx/x\n").unwrap();
    assert!(changed.contains("/etc/nginx/nginx.conf") && changed.contains("/etc/nginx/x"));
    assert_eq!(parse_rpm_verify("").unwrap().len(), 0);
    assert_eq!(parse_rpm_verify("package nginx is not installed\n"), None);
    assert_eq!(parse_rpm_verify("S.5....T.  c relative\n"), None);
}
