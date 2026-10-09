//! Rollbacks that run into trouble: rollback-services is best effort, and
//! rollback-stop clears each network part independently.

use super::*;
use crate::apply::harness::{singbox_only, Fault};
use crate::host::service as svc;

const RUNNING: Unit = Unit {
    active: true,
    enabled: true,
};

/// The old generation's Shadowsocks rule cannot be inserted again.
const OLD_RULE_INSERT: &str = "iptables -w 5 -I INPUT 1 -p tcp --dport 8388 ";

#[test]
fn old_rules_that_cannot_be_recreated_only_warn_and_the_rollback_finishes() {
    let host = installed_host();
    let before = host.world();
    host.features
        .inject(Fault::Fail(Checkpoint::Stage(Phase::StartCores)));
    host.fail_always(OLD_RULE_INSERT);
    let text = err_text(&host.apply(host.change(singbox_only(), "修改")).unwrap_err());
    assert!(
        text.starts_with("配置未应用，已恢复原状态: 注入故障"),
        "{text}"
    );
    // The journal is finished: later applies are not blocked by it.
    assert_no_journal(&host);
    for name in [svc::SING_BOX, svc::XRAY] {
        assert_eq!(host.unit(name), RUNNING, "{name}");
    }
    // Everything but the missing rule is the old generation.
    let after = host.world();
    assert_eq!(before.file_diff(&after), Vec::<String>::new());
    assert_eq!(before.units, after.units);
    assert_eq!(before.cron, after.cron);
    assert!(!after.iptables.iter().any(|r| r.contains("--dport 8388 ")));
    // net-apply (the warning's advice) brings it back once possible.
    host.clear_faults();
    crate::apply::boot::boot_locked(&host.ctx, &host.lock, &host.features).unwrap();
    assert_eq!(before.diff(&host.world()), Vec::<String>::new());
    assert_invariants(&host);
}

#[test]
fn every_service_is_restored_even_when_one_cannot_start() {
    let host = installed_host();
    let before = host.world();
    // Before start-cores, so only the rollback starts services.
    host.features
        .inject(Fault::Fail(Checkpoint::Stage(Phase::StopOldServices)));
    host.fail_always(OLD_RULE_INSERT);
    // sing-box starts first in the canonical order; Xray must still start.
    host.fail_always("systemctl start onebox-sing-box");
    let text = err_text(&host.apply(host.change(singbox_only(), "修改")).unwrap_err());
    assert!(text.starts_with("配置失败: 注入故障"), "{text}");
    assert!(
        text.contains("；恢复未完成: 启动 onebox-sing-box: systemctl 执行失败"),
        "{text}"
    );
    assert!(!text.contains("iptables"), "rules only warn: {text}");
    // Enable states, the crontab and the other service are back.
    assert_eq!(host.unit(svc::XRAY), RUNNING);
    assert_eq!(
        host.unit(svc::SING_BOX),
        Unit {
            active: false,
            enabled: true
        }
    );
    assert!(host.unit(svc::NETWORK).enabled);
    assert_eq!(host.crontab(), before.cron);
    let files = host.world().without(&["etc/.transaction"]);
    assert_eq!(before.file_diff(&files), Vec::<String>::new());
    // The journal is kept at rollback-services; recover finishes the job.
    let journal = journal::load(host.paths()).unwrap().unwrap();
    assert_eq!(journal.phase(), &Phase::RollbackServices);
    host.clear_faults();
    assert_eq!(
        recover_all(&host.ctx, &host.lock).unwrap(),
        Recovery::RolledBack
    );
    assert_eq!(before.diff(&host.world()), Vec::<String>::new());
    assert_no_journal(&host);
    assert_invariants(&host);
}

#[test]
fn a_service_that_exits_right_after_its_restart_keeps_the_journal() {
    let host = installed_host();
    let before = host.world();
    // Before start-cores, so only the rollback starts services.
    host.features
        .inject(Fault::Fail(Checkpoint::Stage(Phase::StopOldServices)));
    // The restart "succeeds", then the core is gone.
    host.crash_after_start(svc::SING_BOX);
    let text = err_text(&host.apply(host.change(singbox_only(), "修改")).unwrap_err());
    assert!(text.starts_with("配置失败: 注入故障"), "{text}");
    assert!(
        text.contains("；恢复未完成: 启动 onebox-sing-box: onebox-sing-box 启动后立即退出"),
        "{text}"
    );
    assert!(!host.unit(svc::SING_BOX).active);
    assert_eq!(host.unit(svc::XRAY), RUNNING);
    let journal = journal::load(host.paths()).unwrap().unwrap();
    assert_eq!(journal.phase(), &Phase::RollbackServices);
    // Once the core stays up, recover finishes the rollback.
    host.clear_faults();
    assert_eq!(
        recover_all(&host.ctx, &host.lock).unwrap(),
        Recovery::RolledBack
    );
    assert_eq!(before.diff(&host.world()), Vec::<String>::new());
    assert_no_journal(&host);
    assert_invariants(&host);
}

/// v2 reported the two firewall owners separately, and a broken
/// `firewall-acme.json` must not keep the proxy rules and hops live.
#[test]
fn a_broken_acme_ledger_does_not_stop_the_proxy_rules_from_being_cleared() {
    let host = installed_host();
    let acme = host.paths().root.join("firewall-acme.json");
    crate::apply::testing::file(&acme, 0o600, b"{ not json");
    let before = host.world();
    host.features
        .inject(Fault::Fail(Checkpoint::Stage(Phase::StartCores)));
    let text = err_text(&host.apply(host.change(singbox_only(), "修改")).unwrap_err());
    assert!(text.contains("；恢复未完成: 清理 ACME 防火墙: "), "{text}");
    assert!(!text.contains("清理当前网络"), "{text}");
    // rollback-stop still removed the new generation's proxy rules.
    let live = host.world().iptables;
    assert!(
        !live.iter().any(|r| r.contains("onebox-proxy-")),
        "{live:?}"
    );
    let journal = journal::load(host.paths()).unwrap().unwrap();
    assert_eq!(journal.phase(), &Phase::RollbackStop);
    // With the ledger repaired, recover completes (and restores the
    // snapshot's copy of it, broken as it was).
    crate::apply::testing::file(&acme, 0o600, b"{\"rules\":[]}");
    assert_eq!(
        recover_all(&host.ctx, &host.lock).unwrap(),
        Recovery::RolledBack
    );
    assert_eq!(before.diff(&host.world()), Vec::<String>::new());
    assert_invariants(&host);
}
