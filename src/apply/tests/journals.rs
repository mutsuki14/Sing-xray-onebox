//! Crash journals, corrupt journals, journals written by v2 and recovery
//! under a lock inherited from a self-update parent.

use super::*;
use crate::apply::harness::{singbox_only, two_cores, Fault};
use crate::apply::snapshot::{take, v2_fixed_targets, v2_node_allowlist_with};
use crate::apply::testing::{
    acme_deployment, acme_home, build_v2_layout, file, v2_journal_text, v2_paths,
};
use crate::host::cron::testing::lines;
use crate::host::service as svc;
use crate::sys::exec::{Cmd, Exec, SystemExec};
use crate::sys::fs::TempDir;
use serde_json::Value;
use std::fs;
use std::panic::{catch_unwind, AssertUnwindSafe};

/// Apply [`big_change`] and "crash" at `point`: the journal stays.
fn crash_at(host: &Host, point: Checkpoint) {
    host.features.inject(Fault::Crash(point));
    let req = big_change(host);
    let crashed = catch_unwind(AssertUnwindSafe(|| host.apply(req)));
    assert!(crashed.is_err(), "the fake crash panics");
    host.features.clear();
}

#[test]
fn crash_journals_at_every_phase_are_recovered_idempotently() {
    for point in uncommitted_points() {
        let host = installed_host();
        let before = host.world();
        crash_at(&host, point.clone());
        let pending = journal::load(host.paths()).unwrap().unwrap();
        let expected = match &point {
            Checkpoint::Stage(phase) => phase.clone(),
            Checkpoint::Saved => Phase::Finalize,
        };
        assert_eq!(pending.phase(), &expected);
        assert_eq!(
            recover_all(&host.ctx, &host.lock).unwrap(),
            Recovery::RolledBack,
            "{point:?}"
        );
        assert_eq!(
            before.diff(&host.world()),
            Vec::<String>::new(),
            "{point:?}"
        );
        assert_eq!(
            recover_all(&host.ctx, &host.lock).unwrap(),
            Recovery::Nothing
        );
        assert_eq!(
            before.diff(&host.world()),
            Vec::<String>::new(),
            "{point:?}"
        );
        assert_invariants(&host);
    }
}

#[test]
fn a_crash_during_the_rollback_is_finished_by_the_next_recovery() {
    let host = installed_host();
    let before = host.world();
    crash_at(&host, Checkpoint::Stage(Phase::StartCores));
    // Pretend the first recovery died in rollback-files: rerunning every
    // rollback phase from the start must be harmless.
    let mut pending = journal::load(host.paths()).unwrap().unwrap();
    pending
        .set_phase(host.paths(), Phase::RollbackFiles)
        .unwrap();
    assert_eq!(
        recover_all(&host.ctx, &host.lock).unwrap(),
        Recovery::RolledBack
    );
    assert_eq!(before.diff(&host.world()), Vec::<String>::new());
}

#[test]
fn a_journal_committed_before_the_crash_is_only_cleaned_up() {
    let host = installed_host();
    crash_at(&host, Checkpoint::Stage(Phase::Finalize));
    assert_eq!(
        journal::load(host.paths()).unwrap().unwrap().phase(),
        &Phase::Committed
    );
    host.exec.clear_history();
    assert_eq!(
        recover_all(&host.ctx, &host.lock).unwrap(),
        Recovery::Finished
    );
    assert!(host.history().is_empty(), "{:?}", host.history());
    assert_eq!(host.installed().inbounds, singbox_only().inbounds);
    assert_no_journal(&host);
}

#[test]
fn a_corrupt_snapshot_runs_no_command_and_keeps_the_journal() {
    let host = installed_host();
    crash_at(&host, Checkpoint::Stage(Phase::StartCores));
    let state_slot = journal::files_dir(host.paths()).join("item-0");
    let mut bytes = fs::read(&state_slot).unwrap();
    bytes.extend_from_slice(b" tampered");
    fs::write(&state_slot, bytes).unwrap();
    let before = host.world();
    host.exec.clear_history();
    let err = recover_all(&host.ctx, &host.lock).unwrap_err().to_string();
    assert!(err.contains("快照文件缺失或校验失败: item-0"), "{err}");
    assert!(host.history().is_empty(), "{:?}", host.history());
    assert_eq!(before.diff(&host.world()), Vec::<String>::new());
    assert_eq!(
        journal::load(host.paths()).unwrap().unwrap().phase(),
        &Phase::StartCores
    );
    // Every later apply refuses the same way, before any side effect.
    let err = host.apply(host.change(two_cores(), "修改")).unwrap_err();
    assert!(err.to_string().contains("快照文件缺失或校验失败"), "{err}");
    assert!(host.history().is_empty());
}

#[test]
fn a_journal_with_a_foreign_target_is_refused() {
    let host = installed_host();
    crash_at(&host, Checkpoint::Stage(Phase::PrepareCores));
    let path = journal::dir(host.paths()).join(journal::JOURNAL_FILE);
    let mut doc: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    doc["snapshot"]["entries"][0]["target"] = "/etc/passwd".into();
    fs::write(&path, serde_json::to_vec_pretty(&doc).unwrap()).unwrap();
    host.exec.clear_history();
    let err = recover_all(&host.ctx, &host.lock).unwrap_err().to_string();
    assert!(err.contains("快照路径范围不合法"), "{err}");
    assert!(host.history().is_empty());
}

/// The v2 fixture layout with the journal `onebox-v2` wrote for it (phase
/// `prepare-cores`), its snapshot taken by v3 into `files/` — which must
/// equal what v2 recorded.
fn v2_host() -> Host {
    let dir = TempDir::new("apply-v2-journal").unwrap();
    let root = dir.path().to_path_buf();
    let paths = build_v2_layout(&root);
    assert_eq!(paths, v2_paths(&root));
    let host = Host::with_paths(dir, paths);
    let paths = host.paths();
    fs::create_dir(journal::dir(paths)).unwrap();
    let mut targets = v2_fixed_targets(paths);
    targets.push(acme_deployment(&root));
    let allow = v2_node_allowlist_with(paths, &[acme_home(&root)]);
    let taken = take(&targets, &journal::files_dir(paths), &allow).unwrap();
    let mut doc: Value = serde_json::from_str(&v2_journal_text(&root)).unwrap();
    // v3 snapshots exactly what v2 snapshotted (slots, presence, digests),
    // except the retired deployment file, whose text names the root it was
    // captured under.
    let mut ours = serde_json::to_value(&taken).unwrap();
    let mut theirs = doc["snapshot"].clone();
    for snapshot in [&mut ours, &mut theirs] {
        snapshot["entries"][38]["sha256"] = Value::Null;
    }
    assert_eq!(ours, theirs, "v3 snapshots what v2 snapshotted");
    doc["snapshot"] = serde_json::to_value(&taken).unwrap();
    doc["active_services"] = serde_json::json!([svc::SING_BOX]);
    doc["enabled_services"] = serde_json::json!([svc::SING_BOX, "onebox-net"]);
    doc["cron_available"] = true.into();
    doc["cron_lines"] = serde_json::json!([v2_cert_line(paths)]);
    let path = journal::dir(paths).join(journal::JOURNAL_FILE);
    fs::write(&path, serde_json::to_vec_pretty(&doc).unwrap()).unwrap();
    host
}

fn v2_cert_line(paths: &crate::paths::Paths) -> String {
    lines::v2_cert("proxy").replace(lines::EXE, &paths.executable.display().to_string())
}

#[test]
fn a_journal_written_by_v2_is_rolled_back_with_its_migrated_old_state() {
    let host = v2_host();
    let paths = host.paths().clone();
    // The live layout before v2's interrupted regen changed it.
    let before = host.world();
    // What the interrupted v2 apply had done already.
    file(&paths.state(), 0o600, b"{\"values\":{}}");
    file(&paths.clients().join("links.txt"), 0o644, b"new links");
    file(
        &paths.core_config(crate::domain::protocol::Core::Xray),
        0o600,
        b"{}",
    );
    fs::remove_file(paths.tls().join("cert.pem")).unwrap();
    file(
        &paths.systemd.join("onebox-sing-box.service"),
        0o644,
        b"[Unit]",
    );
    host.set_crontab("0 1 * * * /usr/bin/true\n");
    assert_eq!(
        recover_all(&host.ctx, &host.lock).unwrap(),
        Recovery::RolledBack
    );
    // Files are v2's again, byte for byte (the ledgers were rebuilt).
    let after = host.world();
    let ledgers = [
        "etc/firewall-v2.json",
        "etc/hop-v2.json",
        "etc/.transaction",
    ];
    assert_eq!(
        before
            .clone()
            .without(&ledgers)
            .file_diff(&after.clone().without(&ledgers)),
        Vec::<String>::new()
    );
    // The old state's rules and hops came back (migrated from v2 values).
    let rules = &after.iptables;
    assert!(
        rules
            .iter()
            .any(|r| r.contains("filter INPUT -p tcp --dport 443 ")),
        "{rules:?}"
    );
    assert!(
        rules.iter().any(
            |r| r.starts_with("nat PREROUTING -p udp --dport 30000:30100 ")
                && r.ends_with("--to-ports 443")
        ),
        "{rules:?}"
    );
    // Services and the crontab as journaled: the v2 line returns, the
    // foreign line stays; legacy units are only enabled, never started.
    assert!(host.unit(svc::SING_BOX).active);
    assert!(host.unit("onebox-net").enabled);
    let history = host.history();
    assert!(
        !history.iter().any(|h| h.contains("start onebox-net")),
        "{history:?}"
    );
    assert_eq!(
        host.crontab(),
        format!("0 1 * * * /usr/bin/true\n{}\n", v2_cert_line(&paths))
    );
    assert_no_journal(&host);
    assert_eq!(
        recover_all(&host.ctx, &host.lock).unwrap(),
        Recovery::Nothing
    );
    assert_invariants(&host);
}

/// The child of `an_inherited_lock_skips_the_parents_records`: recovers the
/// node journal under the inherited lock.
#[test]
fn inherited_lock_recovery_child() {
    let Some(root) = std::env::var_os(CHILD_ROOT) else {
        return;
    };
    let dir = TempDir::new("unused").unwrap();
    let host = Host::with_paths(
        dir,
        crate::paths::Paths::isolated(std::path::Path::new(&root)),
    );
    assert!(host.lock.is_inherited());
    let outcome = recover_all(&host.ctx, &host.lock).unwrap();
    assert_eq!(outcome, Recovery::RolledBack);
    let history = host.history();
    assert!(
        !history
            .iter()
            .any(|h| h.contains("start onebox-subscription")),
        "{history:?}"
    );
    assert!(history
        .iter()
        .any(|h| h == "systemctl start onebox-sing-box"));
    println!("inherited recovery done");
}

const CHILD_ROOT: &str = "ONEBOX_APPLY_INHERITED_TEST_ROOT";

#[test]
fn an_inherited_lock_skips_the_parents_records() {
    if std::env::var_os(CHILD_ROOT).is_some() {
        return;
    }
    let host = installed_host();
    // A running subscription worker (unit present) when the change began.
    file(
        &host.paths().systemd.join("onebox-subscription.service"),
        0o644,
        b"[Unit]",
    );
    host.set_unit(
        svc::SUBSCRIPTION,
        Unit {
            active: true,
            enabled: true,
        },
    );
    crash_at(&host, Checkpoint::Stage(Phase::StartCores));
    // A self-update record only the parent may handle (garbage: reading it
    // would fail the child's recovery).
    let record = host.paths().self_update_journal();
    file(&record, 0o600, b"not for the child");
    let exe = std::env::current_exe().unwrap();
    let out = SystemExec
        .run(
            &Cmd::new(exe.to_string_lossy())
                .args([
                    "--exact",
                    "apply::tests::journals::inherited_lock_recovery_child",
                    "--nocapture",
                    "--test-threads=1",
                ])
                .env(CHILD_ROOT, host.dir.path().to_string_lossy())
                .inherit_lock(host.lock.raw_fd()),
        )
        .unwrap();
    assert!(out.ok(), "{}\n{}", out.stdout, out.stderr);
    assert!(
        out.stdout.contains("inherited recovery done"),
        "{}",
        out.stdout
    );
    assert_no_journal(&host);
    assert_eq!(fs::read(&record).unwrap(), b"not for the child");
}
