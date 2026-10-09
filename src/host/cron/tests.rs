use super::testing::{fake_crontab, lines, text};
use super::*;
use crate::host::init::InitSystem;
use crate::sys::exec::{FakeExec, Output};
use crate::sys::fs::TempDir;
use std::sync::Arc;

pub(super) fn default_paths() -> Paths {
    Paths::from_lookup(|_| None).unwrap()
}

pub(super) fn tab(text: &str) -> Crontab {
    Crontab::parse(&default_paths(), text)
}

fn tag(s: &str) -> Tag {
    Tag::new(s).unwrap()
}

fn tags(tab: &Crontab) -> Vec<String> {
    tab.owned().map(|(t, _)| t.to_string()).collect()
}

pub(super) const V1_BOOT: &str =
    "@reboot /usr/local/bin/onebox net-apply >/dev/null 2>&1; /usr/local/bin/onebox start >/dev/null 2>&1";

#[test]
fn classifies_v3_tags_and_every_older_marker() {
    let o = Ownership::of(&default_paths());
    let cases: &[(&str, Option<&str>)] = &[
        ("17 4 * * * x renew --cron >>'/l' 2>&1 # onebox:renew", Some("renew")),
        ("@reboot x # onebox:boot:onebox-xray  \t\r", Some("boot:onebox-xray")),
        ("17 3 * * * x # onebox:frp-renew", Some("frp-renew")),
        ("x # onebox:bad tag", None),
        ("x # onebox:", None),
        ("x #onebox:renew", None),
        ("17 4 * * * /usr/local/bin/onebox cert renew proxy --cron >/dev/null 2>&1 # onebox-native-cert-proxy", Some("renew")),
        ("17 4 * * * onebox cert renew site # onebox-native-cert-site\r", Some("renew")),
        ("17 4 * * * x # onebox-native-cert-subscription ", Some("renew")),
        ("@reboot onebox service onebox-xray start # onebox-rust:onebox-xray", Some("boot:onebox-xray")),
        ("@reboot onebox frps start # onebox-rust:onebox-frps", Some("boot:onebox-frps")),
        ("@reboot x # onebox-rust:../../evil", None),
        ("17 3 * * * x frps renew --cron >>'/l' 2>&1 # onebox-frps-renew", Some("frp-renew")),
        ("@reboot x frps start >>'/b' 2>&1 # onebox-frps-boot", Some("frp-boot")),
        (V1_BOOT, Some("legacy-boot")),
        (&format!("  {V1_BOOT}\r"), Some("legacy-boot")),
        ("@reboot '/usr/local/bin/onebox' net-apply >/dev/null 2>&1; /usr/local/bin/onebox start >/dev/null 2>&1", Some("legacy-boot")),
        (&format!("{V1_BOOT}; admin-command"), None),
        (&format!("{V1_BOOT} # note"), None),
        ("@reboot /opt/other/onebox net-apply >/dev/null 2>&1; /opt/other/onebox start >/dev/null 2>&1", None),
        ("0 0 * * * \"/etc/onebox/tls/acme\"/acme.sh --cron --home \"/etc/onebox/tls/acme\" > /dev/null", None),
        ("0 0 * * * /etc/onebox/tls/acme/acme.sh --cron --home /etc/onebox/tls/acme > /dev/null", Some("renew")),
        ("0 0 * * * /etc/onebox/site/acme/acme.sh --cron", Some("renew")),
        ("0 0 * * * /etc/onebox/site/acme/acme.sh --cronjob", None),
        ("0 3 * * * /usr/local/bin/onebox cert-renew site --cron", Some("renew")),
        ("0 3 * * * /usr/local/bin/onebox cert-renew other --cron", None),
        ("* * * * * admin-command # other", None),
        ("MAILTO=root", None),
        ("", None),
    ];
    for (line, want) in cases {
        let got = o.classify(line);
        assert_eq!(got.as_ref().map(Tag::as_str), *want, "{line:?}");
    }
    // The v1 line follows the configured executable, quoted when needed.
    let mut paths = default_paths();
    paths.executable = "/opt/my onebox/bin".into();
    let o = Ownership::of(&paths);
    let quoted = "@reboot '/opt/my onebox/bin' net-apply >/dev/null 2>&1; '/opt/my onebox/bin' start >/dev/null 2>&1";
    assert_eq!(o.classify(quoted), Some(Tag::legacy_boot()));
    let bare = "@reboot /opt/my onebox/bin net-apply >/dev/null 2>&1; /opt/my onebox/bin start >/dev/null 2>&1";
    assert_eq!(o.classify(bare), None);
}

#[test]
fn tags_are_validated() {
    assert!(Tag::new("boot:onebox-xray").is_ok());
    for bad in ["", "a b", "x\n", "a;b", &"x".repeat(97)] {
        assert!(Tag::new(bad).is_err(), "{bad:?}");
    }
    assert_eq!(
        Tag::boot("onebox-site").unwrap().as_str(),
        "boot:onebox-site"
    );
    assert!(Tag::boot("sshd").is_err());
}

#[test]
fn scopes_split_node_and_frp_lines() {
    for (t, node) in [
        ("renew", true),
        ("legacy-boot", true),
        ("boot:onebox-xray", true),
        ("boot:onebox-subscription-web", true),
        ("frp-renew", false),
        ("frp-boot", false),
        ("boot:onebox-frps", false),
        ("boot:onebox-frp-web", false),
    ] {
        assert_eq!(Scope::Node.covers(&tag(t)), node, "{t}");
        assert_eq!(Scope::Frp.covers(&tag(t)), !node, "{t}");
    }
}

#[test]
fn text_round_trips_and_always_ends_with_a_newline() {
    let original = "MAILTO=root\r\n# comment\n\n0 1 * * * job";
    let t = tab(original);
    assert_eq!(t.text(), "MAILTO=root\r\n# comment\n\n0 1 * * * job\n");
    assert!(t.is_modified(), "the missing final newline is added");
    let t = tab("a\nb\n");
    assert_eq!(t.text(), "a\nb\n");
    assert!(!t.is_modified());
    assert_eq!(tab("").text(), "");
}

#[test]
fn replace_swaps_a_group_in_place_and_keeps_foreign_order() {
    let original = "MAILTO=root\n\
        17 4 * * * a # onebox-native-cert-proxy\n\
        0 1 * * * backup\n\
        17 4 * * * b # onebox-native-cert-site\n\
        @reboot c # onebox-rust:onebox-xray\n\
        17 4 * * * d # onebox-native-cert-subscription\n\
        30 2 * * * report\n";
    let mut t = tab(original);
    assert_eq!(t.lines_for("renew").len(), 3);
    assert_eq!(
        t.lines_for("boot:"),
        ["@reboot c # onebox-rust:onebox-xray"]
    );
    assert_eq!(t.lines_for("").len(), 4);
    let renew = "17 4 * * * new # onebox:renew".to_owned();
    assert!(t
        .replace(&Tag::renew(), std::slice::from_ref(&renew))
        .unwrap());
    assert_eq!(
        t.text(),
        "MAILTO=root\n17 4 * * * new # onebox:renew\n0 1 * * * backup\n\
         @reboot c # onebox-rust:onebox-xray\n30 2 * * * report\n"
    );
    // Same content again: unchanged.
    assert!(!t.replace(&Tag::renew(), &[renew]).unwrap());

    // A new group is appended.
    let boot = "@reboot s # onebox:boot:onebox-sing-box".to_owned();
    t.replace(
        &Tag::boot("onebox-sing-box").unwrap(),
        std::slice::from_ref(&boot),
    )
    .unwrap();
    assert!(t.text().ends_with(&format!("30 2 * * * report\n{boot}\n")));
    assert_eq!(
        tags(&t),
        ["renew", "boot:onebox-xray", "boot:onebox-sing-box"]
    );

    // An empty replacement removes the group.
    assert!(t.replace(&Tag::renew(), &[]).unwrap());
    assert!(!t.has(&Tag::renew()));
}

#[test]
fn replace_refuses_lines_of_another_owner() {
    let mut t = tab("a\n");
    for bad in [
        "17 4 * * * x # onebox:frp-renew",
        "17 4 * * * foreign",
        "17 4 * * * x # onebox:renew\n* * * * * evil # onebox:renew",
    ] {
        assert!(
            t.replace(&Tag::renew(), &[bad.to_owned()]).is_err(),
            "{bad:?}"
        );
    }
    assert_eq!(t.text(), "a\n", "nothing changed");
}

#[test]
fn remove_and_remove_scope() {
    let mut t = tab(&format!(
        "a\n{V1_BOOT}\n@reboot x # onebox:boot:onebox-frps\nb # onebox:renew\nc\n"
    ));
    assert!(t.remove(&Tag::legacy_boot()));
    assert!(!t.remove(&Tag::legacy_boot()));
    assert!(t.remove_scope(Scope::Node));
    assert_eq!(t.text(), "a\n@reboot x # onebox:boot:onebox-frps\nc\n");
    assert!(t.remove_scope(Scope::Frp));
    assert_eq!(t.text(), "a\nc\n");
}

#[test]
fn remove_v3_lines_keeps_older_forms_and_other_scopes() {
    let text = format!(
        "a\n{V1_BOOT}\n{}\n{}\n{}\n{}\n{}\n{}\nb # onebox:renew\n",
        lines::renew(),
        lines::boot("onebox-xray"),
        lines::v2_cert("proxy"),
        lines::v2_boot("onebox-xray"),
        lines::frp_renew(),
        lines::RETIRED,
    );
    let mut t = tab(&text);
    assert!(t.remove_v3_lines(Scope::Node));
    assert_eq!(
        t.text(),
        format!(
            "a\n{V1_BOOT}\n{}\n{}\n{}\n{}\n",
            lines::v2_cert("proxy"),
            lines::v2_boot("onebox-xray"),
            lines::frp_renew(),
            lines::RETIRED,
        )
    );
    assert!(!t.remove_v3_lines(Scope::Node));
    assert!(t.remove_v3_lines(Scope::Frp));
    assert!(!t.text().contains(" # onebox:"));
}

#[test]
fn listing_tells_no_crontab_from_failures() {
    let ok = |code: i32, stdout: &str, stderr: &str| Output {
        code,
        stdout: stdout.into(),
        stderr: stderr.into(),
    };
    for (out, want) in [
        (ok(0, "a\n", ""), Some("a\n")),
        (ok(1, "", "no crontab for root\n"), Some("")),
        (ok(1, "", "crontab: no crontab for root"), Some("")),
        (
            ok(
                1,
                "",
                "crontab: can't open 'root': No such file or directory\n",
            ),
            Some(""),
        ),
        (ok(1, "", ""), Some("")),
        (
            ok(1, "", "crontab: your UID isn't in the passwd file"),
            None,
        ),
        (ok(1, "a\n", "no crontab for root"), None),
        (ok(2, "", "no crontab for root"), None),
        (ok(124, "", ""), None),
    ] {
        match want {
            Some(text) => assert_eq!(listing(&out).unwrap(), text, "{out:?}"),
            None => assert!(
                listing(&out)
                    .unwrap_err()
                    .to_string()
                    .starts_with("无法读取当前 crontab"),
                "{out:?}"
            ),
        }
    }
}

pub(super) struct Fixture {
    _dir: TempDir,
    pub(super) ctx: Ctx,
    pub(super) exec: Arc<FakeExec>,
}

pub(super) fn fixture() -> Fixture {
    let dir = TempDir::new("cron").unwrap();
    let (ctx, exec, _) = Ctx::test(dir.path());
    Fixture {
        _dir: dir,
        ctx,
        exec,
    }
}

#[test]
fn install_uses_a_private_temp_file_and_cleans_it_up() {
    let f = fixture();
    let state = fake_crontab(&f.exec, None);
    let mut t = Crontab::read(&f.ctx).unwrap();
    assert_eq!(t.text(), "");
    assert!(!t.save(&f.ctx).unwrap(), "unchanged: nothing installed");
    t.replace(&Tag::renew(), &["0 4 * * * x # onebox:renew".into()])
        .unwrap();
    assert!(t.save(&f.ctx).unwrap());
    assert_eq!(text(&state), "0 4 * * * x # onebox:renew\n");
    let history = f.exec.history();
    assert_eq!(history[0], "crontab -l");
    let file = history[1].strip_prefix("crontab ").unwrap();
    assert!(file.starts_with(
        &f.ctx
            .paths
            .run
            .join(TEMP_PREFIX)
            .to_string_lossy()
            .into_owned()
    ));
    assert!(!Path::new(file).exists(), "temp file removed");
    assert!(f.exec.calls().iter().all(|c| c.timeout.is_some()));

    let f = fixture();
    f.exec.on("crontab", &["-l"], Output::success("a\n")).on(
        "crontab",
        &[],
        Output::failure(1, "errors in crontab file"),
    );
    let mut t = Crontab::read(&f.ctx).unwrap();
    t.remove_scope(Scope::Node);
    t.replace(&Tag::renew(), &["0 4 * * * x # onebox:renew".into()])
        .unwrap();
    let err = t.install(&f.ctx).unwrap_err();
    assert!(err.to_string().contains("errors in crontab file"));
    let leftovers = std::fs::read_dir(&f.ctx.paths.run).unwrap().count();
    assert_eq!(leftovers, 0);
}

#[test]
fn concurrent_edits_never_drop_each_others_lines() {
    let f = fixture();
    let state = fake_crontab(&f.exec, Some("a\n"));
    let renew = lines::renew();
    let frp = lines::frp_renew();
    std::thread::scope(|scope| {
        let ctx = &f.ctx;
        let slow = scope.spawn(|| {
            Crontab::edit(ctx, |tab| {
                // Holds the crontab between read and install.
                std::thread::sleep(std::time::Duration::from_millis(150));
                tab.replace(&Tag::renew(), std::slice::from_ref(&renew))
            })
        });
        std::thread::sleep(std::time::Duration::from_millis(30));
        let fast = Crontab::edit(ctx, |tab| {
            tab.replace(&Tag::frp_renew(), std::slice::from_ref(&frp))
        });
        assert!(fast.unwrap());
        assert!(slow.join().unwrap().unwrap());
    });
    assert_eq!(text(&state), format!("a\n{renew}\n{frp}\n"));
    assert!(f.ctx.paths.run.join("crontab.lock").exists());

    // A failing change installs nothing.
    f.exec.clear_history();
    let err = Crontab::edit(&f.ctx, |tab| -> Result<()> {
        tab.remove_scope(Scope::Node);
        Err(Error::msg("中止"))
    });
    assert_eq!(err.unwrap_err().to_string(), "中止");
    assert_eq!(f.exec.history(), ["crontab -l"]);
}

#[test]
fn generated_lines_are_owned_by_their_tag() {
    let paths = default_paths();
    for (t, args) in [
        (Tag::renew(), vec!["renew", "--cron"]),
        (
            Tag::boot("onebox-xray").unwrap(),
            vec!["service", "onebox-xray", "start"],
        ),
        (Tag::frp_renew(), vec!["frps", "renew", "--cron"]),
    ] {
        let l = line(
            "@daily",
            &paths,
            InitSystem::None,
            &args,
            Path::new("/var/log/x.log"),
            &t,
        )
        .unwrap();
        let mut c = tab("x\n");
        c.replace(&t, &[l]).unwrap();
        assert!(c.has(&t));
    }
}

#[test]
fn cron_daemon_checks_per_init_system() {
    // systemd: an active unit is enough.
    let f = fixture();
    f.exec.provide("crontab");
    f.exec
        .on(
            "systemctl",
            &["is-active", "--quiet", "crond"],
            Output::success(""),
        )
        .on("systemctl", &[], Output::failure(3, ""));
    ensure_scheduler_as(&f.ctx, InitSystem::Systemd, true).unwrap();
    assert_eq!(
        f.exec.history(),
        [
            "systemctl is-active --quiet cron",
            "systemctl is-active --quiet crond"
        ]
    );
    // systemd: none active, the second can be enabled.
    let f = fixture();
    f.exec.provide("crontab");
    f.exec
        .on(
            "systemctl",
            &["enable", "--now", "crond"],
            Output::success(""),
        )
        .on("systemctl", &[], Output::failure(1, ""));
    ensure_scheduler_as(&f.ctx, InitSystem::Systemd, true).unwrap();
    assert_eq!(
        f.exec.history().last().unwrap(),
        "systemctl enable --now crond"
    );
    let f = fixture();
    f.exec.provide("crontab");
    f.exec.on("systemctl", &[], Output::failure(1, ""));
    assert_eq!(
        ensure_scheduler_as(&f.ctx, InitSystem::Systemd, true)
            .unwrap_err()
            .to_string(),
        NOT_RUNNING
    );

    // OpenRC: the first script that starts joins the default runlevel.
    let f = fixture();
    f.exec.provide("crontab");
    f.exec
        .on("rc-service", &["cronie", "start"], Output::success(""))
        .on("rc-service", &[], Output::failure(1, "does not exist"))
        .on(
            "rc-update",
            &["add", "cronie", "default"],
            Output::success(""),
        );
    ensure_scheduler_as(&f.ctx, InitSystem::Openrc, true).unwrap();
    assert_eq!(
        f.exec.history(),
        [
            "rc-service crond start",
            "rc-service cronie start",
            "rc-update add cronie default"
        ]
    );
    let f = fixture();
    f.exec.provide("crontab");
    f.exec
        .on("rc-service", &["crond", "start"], Output::success(""))
        .on("rc-update", &[], Output::failure(1, "denied"));
    assert!(ensure_scheduler_as(&f.ctx, InitSystem::Openrc, true).is_err());

    // No init: a cron process must exist.
    let f = fixture();
    f.exec.provide("crontab");
    assert!(ensure_scheduler_as(&f.ctx, InitSystem::None, true).is_err());
    let proc_dir = f.ctx.paths.system("/proc/321");
    std::fs::create_dir_all(&proc_dir).unwrap();
    std::fs::write(proc_dir.join("comm"), "crond\n").unwrap();
    ensure_scheduler_as(&f.ctx, InitSystem::None, true).unwrap();
}

#[test]
fn scheduler_active_only_looks() {
    let f = fixture();
    f.exec
        .on(
            "systemctl",
            &["is-active", "--quiet", "cronie"],
            Output::success(""),
        )
        .on("systemctl", &[], Output::failure(3, ""))
        .on(
            "rc-service",
            &["dcron", "status"],
            Output::success(" * status: started"),
        )
        .on("rc-service", &[], Output::failure(3, " * status: stopped"));
    assert!(scheduler_active(&f.ctx, InitSystem::Systemd));
    assert!(scheduler_active(&f.ctx, InitSystem::Openrc));
    assert!(!scheduler_active(&f.ctx, InitSystem::None));
    let calls = f.exec.history();
    assert!(
        calls
            .iter()
            .all(|c| c.contains("is-active") || c.ends_with(" status")),
        "never starts or enables: {calls:?}"
    );

    let f = fixture();
    f.exec.on("systemctl", &[], Output::failure(3, "")).on(
        "rc-service",
        &[],
        Output::failure(3, ""),
    );
    assert!(!scheduler_active(&f.ctx, InitSystem::Systemd));
    assert!(!scheduler_active(&f.ctx, InitSystem::Openrc));
    assert_eq!(f.exec.history().len(), 3 + 4);
}

#[test]
fn ensure_scheduler_installs_crontab_through_the_package_manager() {
    let f = fixture();
    let proc_dir = f.ctx.paths.system("/proc/9");
    std::fs::create_dir_all(&proc_dir).unwrap();
    std::fs::write(proc_dir.join("comm"), "cron\n").unwrap();
    f.exec.provide("apk");
    let exec = Arc::clone(&f.exec);
    f.exec.on_fn(
        |cmd| cmd.program == "apk",
        move |_| {
            exec.provide("crontab");
            Ok(Output::success(""))
        },
    );
    ensure_scheduler_as(&f.ctx, InitSystem::None, true).unwrap();
    assert_eq!(f.exec.history(), ["apk add --no-cache dcron"]);

    // Already installed: no package manager call.
    f.exec.clear_history();
    ensure_scheduler_as(&f.ctx, InitSystem::None, true).unwrap();
    assert!(f.exec.history().is_empty());

    // Missing and not root: the package manager is never asked.
    let f = fixture();
    let err = ensure_scheduler_as(&f.ctx, InitSystem::None, false).unwrap_err();
    assert!(f.exec.history().is_empty(), "{err}");
}
