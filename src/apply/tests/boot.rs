//! `net-apply` at boot (spec B §4.6, G18).

use super::*;
use crate::apply::boot::boot_locked;
use crate::apply::harness::{Fault, NEW_IPS};
use crate::domain::protocol::Core;
use std::fs;

/// After a reboot: no firewall rule or hop is live, nothing runs.
fn reboot(host: &Host) {
    host.iptables.lock().unwrap().clear();
    for unit in host.units.lock().unwrap().values_mut() {
        unit.active = false;
    }
    host.exec.clear_history();
    host.features.clear();
}

#[test]
fn unchanged_addresses_only_bring_the_rules_back() {
    let host = installed_host();
    let live_rules = host.world().iptables;
    reboot(&host);
    let before = host.world();
    boot_locked(&host.ctx, &host.lock, &host.features).unwrap();
    let after = host.world();
    // Rules are live again with their recorded tokens; nothing else moved.
    assert_eq!(after.iptables, live_rules);
    assert_eq!(before.file_diff(&after), Vec::<String>::new());
    assert_eq!(before.units, after.units, "boot starts nothing (G18)");
    let history = host.history();
    assert!(
        !history.iter().any(|h| h.contains("version")),
        "{history:?}"
    );
    assert!(
        !history.iter().any(|h| h.starts_with("systemctl start")),
        "{history:?}"
    );
    assert!(host.features.calls().is_empty());
    assert_invariants(&host);
}

#[test]
fn changed_addresses_regenerate_the_node() {
    let host = installed_host();
    reboot(&host);
    host.set_ips(NEW_IPS);
    boot_locked(&host.ctx, &host.lock, &host.features).unwrap();
    let saved = host.installed();
    assert_eq!(
        saved.routing.own_cidrs,
        ["198.51.100.7/32", "203.0.113.10/32"]
    );
    let config = fs::read_to_string(host.paths().core_config(Core::Singbox)).unwrap();
    assert!(
        config.contains("198.51.100.7/32"),
        "self access stays blocked"
    );
    assert_no_journal(&host);
    assert_invariants(&host);
}

#[test]
fn a_failed_boot_regeneration_rolls_back_without_touching_the_oneshot() {
    let host = installed_host();
    reboot(&host);
    let before = host.world();
    host.set_ips(NEW_IPS);
    host.features
        .inject(Fault::Fail(Checkpoint::Stage(Phase::StartCores)));
    let err = boot_locked(&host.ctx, &host.lock, &host.features).unwrap_err();
    assert!(
        err_text(&err).starts_with("配置未应用，已恢复原状态"),
        "{err}"
    );
    // The rollback restarts what was running at that time: nothing.
    assert_eq!(before.file_diff(&host.world()), Vec::<String>::new());
    assert_invariants(&host);
}

#[test]
fn addresses_are_not_refreshed_when_private_targets_are_allowed() {
    let host = Host::new();
    let mut cfg = super::super::harness::two_cores();
    cfg.routing.block_private = false;
    host.install(cfg);
    reboot(&host);
    host.set_ips(NEW_IPS);
    boot_locked(&host.ctx, &host.lock, &host.features).unwrap();
    assert!(!host.history().iter().any(|h| h.starts_with("ip ")));
    assert_eq!(host.installed().routing.own_cidrs, ["203.0.113.10/32"]);
}

#[test]
fn boot_recovers_a_pending_journal_first() {
    let host = installed_host();
    host.features
        .inject(Fault::Crash(Checkpoint::Stage(Phase::ApplyNetwork)));
    let req = big_change(&host);
    let crashed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| host.apply(req)));
    assert!(crashed.is_err());
    host.features.clear();
    boot_locked(&host.ctx, &host.lock, &host.features).unwrap();
    assert_no_journal(&host);
    assert_eq!(
        host.installed().inbounds,
        super::super::harness::two_cores().inbounds
    );
}

#[test]
fn boot_on_a_host_without_a_node_says_so() {
    let host = Host::new();
    let err = boot_locked(&host.ctx, &host.lock, &host.features).unwrap_err();
    assert!(matches!(err, Error::NotInstalled), "{err}");
}

#[test]
fn a_failed_address_refresh_still_restores_the_saved_rules() {
    let host = installed_host();
    let live_rules = host.world().iptables;
    reboot(&host);
    host.fail_always("ip -j address");
    let err = boot_locked(&host.ctx, &host.lock, &host.features).unwrap_err();
    assert!(
        err_text(&err).starts_with("已按保存的配置恢复防火墙规则，但无法读取本机地址"),
        "{err}"
    );
    assert_eq!(host.world().iptables, live_rules);
    assert_eq!(host.installed().routing.own_cidrs, ["203.0.113.10/32"]);
}

/// Boot waits for the node lock instead of failing when another operation
/// (a `@reboot` service start, a renewal) holds it.
#[test]
fn boot_waits_for_the_node_lock() {
    use crate::apply::boot::boot_lock;
    use crate::sys::lock::{FileLock, BUSY_MESSAGE};
    use std::time::Duration;
    let dir = crate::sys::fs::TempDir::new("boot-lock").unwrap();
    let paths = crate::paths::Paths::isolated(dir.path());
    let held = FileLock::acquire(&paths.lock(), BUSY_MESSAGE).unwrap();
    let err = boot_lock(&paths, Duration::ZERO).unwrap_err();
    assert!(matches!(err, Error::Busy(_)), "{err}");
    let releaser = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(300));
        drop(held);
    });
    let lock = boot_lock(&paths, Duration::from_secs(30)).unwrap();
    assert!(!lock.is_inherited());
    releaser.join().unwrap();
}
