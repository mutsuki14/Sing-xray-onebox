use super::*;
use crate::frp::lifecycle::{apply, Change};
use crate::frp::testing::{tcp_state, FakeHost};
use crate::host::service::FRPS;

fn statuses(checks: &[Check]) -> Vec<(String, CheckStatus)> {
    checks.iter().map(|c| (c.name.clone(), c.status)).collect()
}

#[test]
fn nothing_to_check_without_frp() {
    let Some(h) = FakeHost::new() else { return };
    assert!(checks_with(&h.runtime()).is_empty());
}

#[test]
fn a_healthy_installation_passes() {
    let Some(h) = FakeHost::new() else { return };
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
    let Some(h) = FakeHost::new() else { return };
    let paths = &h.ctx.paths;
    crate::frp::runtime::mkdirs(paths).unwrap();
    std::fs::write(paths.frp_root.join("state.json"), "{").unwrap();
    let found = checks_with(&h.runtime());
    assert_eq!(found.len(), 2);
    assert_eq!(found[1].name, "FRP 状态");
    assert_eq!(found[1].status, CheckStatus::Fail);
}
