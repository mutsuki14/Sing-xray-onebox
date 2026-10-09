use super::*;
use crate::frp::lifecycle::{apply, Change};
use crate::frp::testing::{tcp_state, FakeHost};
use crate::host::service::FRPS;

fn statuses(checks: &[Check]) -> Vec<(String, CheckStatus)> {
    checks.iter().map(|c| (c.name.clone(), c.status)).collect()
}

#[test]
fn nothing_to_check_without_frp() {
    let h = FakeHost::new();
    assert!(checks_with(&h.runtime()).is_empty());
}

#[test]
fn a_healthy_installation_passes() {
    let h = FakeHost::new();
    let rt = h.runtime();
    let mut state = tcp_state();
    state.token.clear();
    apply(
        &rt,
        state,
        Change {
            reason: "安装",
            ..Change::default()
        },
    )
    .unwrap();
    let pass = CheckStatus::Pass;
    assert_eq!(
        statuses(&checks_with(&rt)),
        [
            ("FRP 事务".to_owned(), pass),
            ("FRP 状态".to_owned(), pass),
            ("frps 程序".to_owned(), pass),
            (FRPS.to_owned(), pass),
            ("FRP 私有 CA".to_owned(), pass),
            ("FRP 控制证书".to_owned(), pass),
            ("FRP 续期任务".to_owned(), pass),
        ]
    );
    // Stopped service, missing cron line, pending transaction.
    rt.services().stop(FRPS).unwrap();
    h.set_crontab("");
    let lock = rt.lock().unwrap();
    let _txn = crate::frp::txn::Txn::begin(&rt, &lock, "测试", &[]).unwrap();
    let found = statuses(&checks_with(&rt));
    assert!(found.contains(&("FRP 事务".to_owned(), CheckStatus::Fail)));
    assert!(found.contains(&(FRPS.to_owned(), CheckStatus::Warn)));
    assert!(found.contains(&("FRP 续期任务".to_owned(), CheckStatus::Warn)));
}

#[test]
fn a_broken_state_fails() {
    let h = FakeHost::new();
    let paths = &h.ctx.paths;
    crate::frp::runtime::mkdirs(paths).unwrap();
    std::fs::write(paths.frp_root.join("state.json"), "{").unwrap();
    let found = checks_with(&h.runtime());
    assert_eq!(found.len(), 2);
    assert_eq!(found[1].name, "FRP 状态");
    assert_eq!(found[1].status, CheckStatus::Fail);
}

#[test]
fn a_crashed_fresh_install_is_reported_without_a_state() {
    let h = FakeHost::new();
    let rt = h.runtime();
    let paths = &h.ctx.paths;
    let lock = rt.lock().unwrap();
    {
        // The install dies after the trees exist, before state.json.
        let _txn =
            crate::frp::txn::Txn::begin(&rt, &lock, "安装", &crate::frp::journal::targets(paths))
                .unwrap();
        crate::frp::runtime::mkdirs(paths).unwrap();
    }
    assert!(!model::installed(paths));
    let found = checks_with(&rt);
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].name, "FRP 事务");
    assert_eq!(found[0].status, CheckStatus::Fail);
    assert!(
        found[0].detail.contains("未完成的 FRP 事务（安装"),
        "{:?}",
        found[0]
    );
    assert_eq!(journal::notice(paths).as_deref(), Some(journal::PENDING));
}

#[test]
fn finished_journals_only_need_cleanup() {
    let h = FakeHost::new();
    let rt = h.runtime();
    let paths = &h.ctx.paths;
    let _lock = rt.lock().unwrap();
    let mut j = journal::create(paths, "配置", journal::Before::default(), &[]).unwrap();
    j.set_phase(paths, journal::Phase::Committed).unwrap();
    let found = checks_with(&rt);
    assert_eq!(
        statuses(&found),
        [("FRP 事务".to_owned(), CheckStatus::Warn)]
    );
    assert!(found[0].detail.ends_with("待清理；执行 onebox recover"));
    assert_eq!(
        journal::notice(paths).unwrap(),
        "FRP 事务日志待清理；执行 onebox recover"
    );
    journal::remove(paths).unwrap();
    assert_eq!(journal::notice(paths), None);
}
