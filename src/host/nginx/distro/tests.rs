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
const WELCOME: &str = "<h1>Welcome to nginx!</h1>\n";
const DEBIAN_WELCOME: &str = "/var/www/html/index.nginx-debian.html";

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

    /// `{package}.md5sums` lists `files` (host path, packaged content).
    fn shipped(&self, package: &str, files: &[(&str, &str)]) -> &Self {
        let list: String = files
            .iter()
            .map(|(path, text)| {
                let relative = path.trim_start_matches('/');
                format!("{}  {relative}\n", fake_md5(text.as_bytes()))
            })
            .collect();
        self.file(&format!("/var/lib/dpkg/info/{package}.md5sums"), &list)
    }

    /// The Debian package layout with the packaged files untouched, and
    /// the welcome page its postinst copies into `/var/www/html`.
    fn debian_defaults(&self) -> &Self {
        self.file(MAIN_CONF, NGINX_CONF)
            .file("/etc/nginx/sites-available/default", DEFAULT_SITE)
            .link(
                "/etc/nginx/sites-enabled/default",
                "/etc/nginx/sites-available/default",
            )
            .file("/usr/share/nginx/html/index.html", WELCOME)
            .file(DEBIAN_WELCOME, WELCOME)
    }

    fn debian_db(&self) -> &Self {
        self.dpkg(&[
            (MAIN_CONF, NGINX_CONF),
            ("/etc/nginx/sites-available/default", DEFAULT_SITE),
            ("/etc/nginx/mime.types", "types {}"),
        ])
        .shipped(
            "nginx-common",
            &[
                ("/usr/share/nginx/html/index.html", WELCOME),
                ("/usr/share/doc/nginx-common/copyright", "copyright"),
            ],
        )
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
    assert!(history[4].starts_with("md5sum ") && history[4].ends_with(DEBIAN_WELCOME));
    assert_eq!(history[5], DISABLE);
    assert_eq!(history.len(), 6);
    assert!(
        h.exec.calls().iter().all(|c| c.is_c_locale()),
        "probe output is parsed untranslated"
    );
}

#[test]
fn own_pages_in_the_default_root_are_left_alone() {
    // (case, files added to the Debian defaults, neutralized)
    let deep = "/var/www/html/a/b/c/d/page.html";
    type Files<'a> = &'a [(&'a str, &'a str)];
    let cases: [(&str, Files, bool); 6] = [
        ("only the welcome page", &[], true),
        (
            "own index.html beside the welcome page",
            &[("/var/www/html/index.html", "<h1>My blog</h1>")],
            false,
        ),
        (
            "edited welcome page",
            &[(DEBIAN_WELCOME, "<h1>Welcome to my shop</h1>")],
            false,
        ),
        (
            "own files in a subdirectory",
            &[("/var/www/html/blog/post.html", "post")],
            false,
        ),
        (
            "a packaged file that is not a welcome page",
            &[("/var/www/html/copyright", "copyright")],
            false,
        ),
        ("deeper than a welcome page", &[(deep, WELCOME)], false),
    ];
    for (case, extra, neutralized) in cases {
        let h = host(InitSystem::Systemd, true);
        h.debian_defaults().debian_db();
        for (path, text) in extra {
            h.file(path, text);
        }
        assert_eq!(h.neutralized(), neutralized, "{case}");
    }

    // A missing document root serves nothing.
    let h = host(InitSystem::Systemd, true);
    h.debian_defaults().debian_db();
    fs::remove_dir_all(h.ctx.paths.system("/var/www")).unwrap();
    assert!(h.neutralized(), "no /var/www/html");

    // Without dpkg's file list the welcome page cannot be proven.
    let h = host(InitSystem::Systemd, true);
    h.debian_defaults().debian_db();
    fs::remove_file(
        h.ctx
            .paths
            .system("/var/lib/dpkg/info/nginx-common.md5sums"),
    )
    .unwrap();
    assert!(!h.neutralized(), "no md5sums");

    // Too many files for a welcome page.
    let h = host(InitSystem::Systemd, true);
    h.debian_defaults().debian_db();
    for n in 0..MAX_SERVED_FILES {
        h.file(&format!("/var/www/html/copy{n}.html"), WELCOME);
    }
    assert!(!h.neutralized(), "a whole site");
}

#[test]
fn document_roots_must_be_plain_absolute_paths() {
    let sites = [
        ("root /srv/$host;", false),
        ("root html;", false),
        ("root /srv/site", false),
        (
            "# root /srv/site;\n\troot /var/www/html; # the default",
            true,
        ),
        ("root \"/var/www/html/\";", true),
    ];
    for (directive, neutralized) in sites {
        let site = format!("server {{\n\tlisten 80 default_server;\n\t{directive}\n}}\n");
        let h = host(InitSystem::Systemd, true);
        h.debian_defaults()
            .file("/etc/nginx/sites-available/default", &site)
            .dpkg(&[
                (MAIN_CONF, NGINX_CONF),
                ("/etc/nginx/sites-available/default", &site),
            ])
            .shipped(
                "nginx-common",
                &[("/usr/share/nginx/html/index.html", WELCOME)],
            );
        assert_eq!(h.neutralized(), neutralized, "{directive}");
    }
    // A packaged configuration without any server root is not understood.
    let h = host(InitSystem::Systemd, true);
    h.file(MAIN_CONF, NGINX_CONF)
        .dpkg(&[(MAIN_CONF, NGINX_CONF)])
        .shipped(
            "nginx-common",
            &[("/usr/share/nginx/html/index.html", WELCOME)],
        );
    assert!(!h.neutralized(), "no root directive");
}

#[test]
fn nginx_org_package_serves_its_shipped_pages() {
    const DEFAULT_CONF: &str = "server {\n    listen 80;\n    location / {\n        \
        root   /usr/share/nginx/html;\n        index  index.html index.htm;\n    }\n}\n";
    let h = host(InitSystem::Systemd, true);
    h.file(MAIN_CONF, NGINX_CONF)
        .file("/etc/nginx/conf.d/default.conf", DEFAULT_CONF)
        .file("/usr/share/nginx/html/index.html", WELCOME)
        .file("/usr/share/nginx/html/50x.html", "50x")
        .dpkg(&[
            (MAIN_CONF, NGINX_CONF),
            ("/etc/nginx/conf.d/default.conf", DEFAULT_CONF),
        ])
        .shipped(
            "nginx",
            &[
                ("/usr/share/nginx/html/index.html", WELCOME),
                ("/usr/share/nginx/html/50x.html", "50x"),
            ],
        );
    assert!(h.neutralized());
    h.exec.clear_history();
    h.file("/usr/share/nginx/html/50x.html", "my error page");
    assert!(!h.neutralized(), "edited shipped page");
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
const RHEL_CONF: &str = "events {}\nhttp {\n include /etc/nginx/conf.d/*.conf;\n server {\n  \
    listen 80;\n  root /usr/share/nginx/html;\n }\n}\n";
const RHEL_INDEX: &str = "/usr/share/nginx/html/index.html";

#[test]
fn rpm_verification() {
    let owned = [
        MAIN_CONF,
        "/etc/nginx/mime.types",
        "/etc/nginx/conf.d",
        "/usr/share/nginx/html",
        RHEL_INDEX,
    ];
    let h = host(InitSystem::Systemd, true);
    h.file(MAIN_CONF, RHEL_CONF)
        .file(RHEL_INDEX, WELCOME)
        .rpm(&owned, "");
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
        .file(RHEL_INDEX, WELCOME)
        .rpm(&owned, ".M.......  c /etc/nginx/mime.types\n");
    assert!(h.neutralized());

    // The served root: an edited welcome page, an own page.
    let h = host(InitSystem::Systemd, true);
    h.file(MAIN_CONF, RHEL_CONF)
        .file(RHEL_INDEX, "<h1>My site</h1>")
        .rpm(&owned, &format!("S.5....T.    {RHEL_INDEX}\n"));
    assert!(!h.neutralized(), "edited welcome page");
    let h = host(InitSystem::Systemd, true);
    h.file(MAIN_CONF, RHEL_CONF)
        .file(RHEL_INDEX, WELCOME)
        .file("/usr/share/nginx/html/shop.html", "shop")
        .rpm(&owned, "");
    assert!(!h.neutralized(), "page not owned by the package");

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
