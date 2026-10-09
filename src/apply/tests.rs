//! End-to-end tests of the apply engine on the fake host (`harness.rs`).

mod boot;
mod commit;
mod faults;
mod journals;
mod policies;

use super::features::Checkpoint;
use super::harness::{line, ran, Host, Unit, OLD_MANAGER};
use super::journal::{self, Phase};
use super::recover::{recover_all, Recovery};
use crate::error::Error;
use std::path::Path;

/// Every forward stage whose checkpoint precedes the commit point.
fn uncommitted_points() -> Vec<Checkpoint> {
    Phase::STAGES
        .into_iter()
        .filter(|p| *p != Phase::Finalize)
        .map(Checkpoint::Stage)
        .chain([Checkpoint::Saved])
        .collect()
}

/// An installed two-core node whose installed manager differs from the
/// running one (so prepare-state rewrites it) and whose crontab still has a
/// v2 renewal line next to foreign ones (so finalize rewrites it), with
/// history cleared.
fn installed_host() -> Host {
    let host = Host::new();
    host.install(super::harness::two_cores());
    crate::apply::testing::file(&host.paths().executable, 0o755, OLD_MANAGER);
    host.set_crontab(&legacy_crontab(host.paths()));
    host.exec.clear_history();
    host.features.clear();
    host
}

/// Foreign lines around a v2 `# onebox-native-cert-proxy` line.
fn legacy_crontab(paths: &crate::paths::Paths) -> String {
    use crate::host::cron::testing::lines;
    let exe = paths.executable.display().to_string();
    let v2 = lines::v2_cert("proxy").replace(lines::EXE, &exe);
    format!("MAILTO=root\n{v2}\n0 1 * * * /usr/bin/foreign\n")
}

fn assert_no_journal(host: &Host) {
    assert!(
        journal::load(host.paths()).unwrap().is_none(),
        "journal left behind"
    );
    let leftovers: Vec<_> = std::fs::read_dir(&host.paths().root)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_string_lossy().starts_with(".transaction"))
        .collect();
    assert!(leftovers.is_empty(), "{leftovers:?}");
}

/// The invariants every test checks at the end: nothing was asked (G12),
/// the network oneshot was never stopped or started.
fn assert_invariants(host: &Host) {
    assert!(host.ui.prompts().is_empty(), "{:?}", host.ui.prompts());
    let history = host.history();
    for action in ["stop", "start", "restart"] {
        assert!(
            !ran(&history, &line("systemctl", &[action, "onebox-network"])),
            "{action} onebox-network: {history:?}"
        );
    }
}

/// A change that touches everything: one core removed, one port moved, a
/// core binary replaced and (with [`installed_host`]) the manager rewritten.
fn big_change(host: &Host) -> super::ApplyRequest {
    let candidate = host.paths().run.join("candidate-sing-box");
    crate::apply::testing::file(&candidate, 0o755, b"\x7fELF replacement sing-box");
    let mut req = host.change(super::harness::singbox_only(), "修改");
    req.intents.replace_cores = vec![(crate::domain::protocol::Core::Singbox, candidate)];
    req
}

fn exists(path: &Path) -> bool {
    std::fs::symlink_metadata(path).is_ok()
}

fn err_text(e: &Error) -> String {
    e.report_text()
}
