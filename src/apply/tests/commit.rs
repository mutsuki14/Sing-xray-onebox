//! Successful applies: what a committed generation consists of.

use super::*;
use crate::apply::harness::{singbox_only, two_cores, MANAGER, SING_BOX, XRAY};
use crate::apply::ApplyRequest;
use crate::domain::protocol::Core;
use crate::host::service as svc;
use std::fs;

#[test]
fn a_first_install_commits_every_part_of_the_generation() {
    let host = Host::new();
    host.install(two_cores());
    let paths = host.paths();
    assert_no_journal(&host);
    let saved = host.installed();
    assert_eq!(saved.versions.singbox.as_deref(), Some("1.14.2"));
    assert_eq!(saved.versions.xray.as_deref(), Some("26.3.27"));
    assert_eq!(saved.routing.own_cidrs, ["203.0.113.10/32"]);
    assert_eq!(fs::read(&paths.executable).unwrap(), MANAGER);
    for core in Core::ALL {
        let config = fs::read_to_string(paths.core_config(core)).unwrap();
        assert!(
            config.contains("203.0.113.10/32"),
            "{core:?}: own address blocked"
        );
        let unit = paths.systemd.join(format!("{}.service", core.service()));
        assert!(unit.is_file(), "{}", unit.display());
        assert_eq!(
            host.unit(core.service()),
            Unit {
                active: true,
                enabled: true
            }
        );
    }
    assert!(paths.clients().join("probe.json").is_file());
    // The boot oneshot is written and enabled, never started (it takes the
    // node lock this apply holds).
    assert!(paths.systemd.join("onebox-network.service").is_file());
    assert_eq!(
        host.unit(svc::NETWORK),
        Unit {
            active: false,
            enabled: true
        }
    );
    // Public ports are open; REALITY's guard is not.
    let rules = host.world().iptables;
    let has = |needle: &str| rules.iter().any(|r| r.contains(needle));
    assert!(has("filter INPUT -p tcp --dport 443 "), "{rules:?}");
    assert!(has("--dport 8388 ") && !has("--dport 18000"), "{rules:?}");
    // A self-signed-free node needs no crontab line.
    assert_eq!(host.crontab(), "");
    assert_invariants(&host);
}

#[test]
fn a_change_removes_what_the_new_generation_no_longer_uses() {
    let host = Host::new();
    host.install(two_cores());
    let req = host.change(singbox_only(), "修改端口");
    host.apply(req).unwrap();
    let paths = host.paths();
    assert!(!exists(&paths.core_config(Core::Xray)));
    assert!(!exists(&paths.systemd.join("onebox-xray.service")));
    assert_eq!(host.unit(svc::XRAY), Unit::default());
    assert!(fs::read_to_string(paths.core_config(Core::Singbox))
        .unwrap()
        .contains("8443"));
    // The unused core binary stays (v2 parity); its config is gone.
    assert_eq!(fs::read(paths.core_bin(Core::Xray)).unwrap(), XRAY);
    let rules = host.world().iptables;
    assert!(rules.iter().any(|r| r.contains("--dport 8443 ")));
    assert!(!rules.iter().any(|r| r.contains("--dport 8388 ")));
    assert_eq!(host.installed().inbounds, singbox_only().inbounds);
    assert_no_journal(&host);
    assert_invariants(&host);
}

#[test]
fn stages_persist_their_phase_before_acting_and_report_progress_in_order() {
    let host = Host::new();
    host.install(two_cores());
    // A crash right after each stage leaves the journal in that stage.
    for phase in [
        Phase::PrepareCores,
        Phase::ApplyNetwork,
        Phase::PublishClients,
    ] {
        host.features
            .inject(super::super::harness::Fault::Crash(Checkpoint::Stage(
                phase.clone(),
            )));
        let req = host.change(singbox_only(), "修改");
        let crashed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| host.apply(req)));
        assert!(crashed.is_err());
        let journal = journal::load(host.paths()).unwrap().unwrap();
        assert_eq!(journal.phase(), &phase);
        assert_eq!(journal.reason(), Some("修改"));
        host.features.clear();
        assert_eq!(
            recover_all(&host.ctx, &host.lock).unwrap(),
            Recovery::RolledBack
        );
    }
    assert_invariants(&host);
}

#[test]
fn replacement_cores_are_swapped_in_and_their_versions_recorded() {
    let host = Host::new();
    host.install(two_cores());
    let candidate = host.paths().run.join("candidate-sing-box");
    crate::apply::testing::file(&candidate, 0o700, b"\x7fELF sing-box 1.14.3");
    host.exec.on(
        "sing-box",
        &["version"],
        crate::sys::exec::Output::success("sing-box version 1.14.3\n"),
    );
    let mut req = host.change(two_cores(), "更新内核");
    req.intents.replace_cores = vec![(Core::Singbox, candidate)];
    host.apply(req).unwrap();
    let bin = host.paths().core_bin(Core::Singbox);
    assert_eq!(fs::read(&bin).unwrap(), b"\x7fELF sing-box 1.14.3");
    use std::os::unix::fs::PermissionsExt;
    assert_eq!(
        fs::metadata(&bin).unwrap().permissions().mode() & 0o777,
        0o755
    );
    // The first rule still answers `version` (rules match in order); the
    // replacement itself is what this test checks.
    assert_ne!(fs::read(&bin).unwrap(), SING_BOX);
    assert_invariants(&host);
}

#[test]
fn unusable_replacements_are_refused() {
    let host = Host::new();
    host.install(two_cores());
    let mut missing = host.change(two_cores(), "更新内核");
    missing.intents.replace_cores = vec![(Core::Xray, host.paths().run.join("missing"))];
    let before = host.world();
    let err = host.apply(missing).unwrap_err();
    assert!(err_text(&err).ends_with("待更新内核文件无效"), "{err}");
    assert_eq!(before.diff(&host.world()), Vec::<String>::new());
    // A core the configuration does not use is refused before any journal.
    let mut unused = host.change(singbox_only(), "更新内核");
    unused.intents.replace_cores = vec![(Core::Xray, host.paths().core_bin(Core::Xray))];
    host.exec.clear_history();
    assert_eq!(
        host.apply(unused).unwrap_err().to_string(),
        "待更新内核不在配置中或重复"
    );
    assert!(host.history().is_empty(), "{:?}", host.history());
    assert_no_journal(&host);
}

#[test]
fn an_install_over_an_existing_hash_needs_the_current_state() {
    let host = Host::new();
    host.install(two_cores());
    // `ApplyRequest::install` reads the current hash, so a reinstall works.
    let req = ApplyRequest::install(&host.ctx, singbox_only(), "重装").unwrap();
    host.apply(req).unwrap();
    assert_eq!(host.installed().inbounds, singbox_only().inbounds);
}
