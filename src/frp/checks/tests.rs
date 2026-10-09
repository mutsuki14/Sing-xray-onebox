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
            ("frps 程序".to_owned(), pass),
            (FRPS.to_owned(), pass),
            ("FRP 私有 CA".to_owned(), pass),
            ("FRP 控制证书".to_owned(), pass),
            ("FRP 续期任务".to_owned(), pass),
        ]
    );
    // Stopped service, missing cron line, pending transaction (left by a
    // crash: nobody holds the lock).
    rt.services().stop(FRPS).unwrap();
    h.set_crontab("");
    let lock = rt.lock().unwrap();
    drop(crate::frp::txn::Txn::begin(&rt, &lock, "测试", &[]).unwrap());
    drop(lock);
    let found = statuses(&checks_with(&rt));
    assert!(found.contains(&("FRP 事务".to_owned(), CheckStatus::Fail)));
    assert!(found.contains(&(FRPS.to_owned(), CheckStatus::Warn)));
    assert!(found.contains(&("FRP 续期任务".to_owned(), CheckStatus::Warn)));
}

#[test]
fn an_operation_in_progress_is_not_a_failure() {
    let h = FakeHost::new();
    let rt = h.runtime();
    let paths = &h.ctx.paths;
    apply(
        &rt,
        tcp_state(),
        Change {
            reason: "安装",
            ..Change::default()
        },
    )
    .unwrap();
    std::fs::remove_file(paths.frp_bin.join("frps")).unwrap();
    let lock = rt.lock().unwrap();
    let txn = crate::frp::txn::Txn::begin(&rt, &lock, "续期", &[]).unwrap();
    let found = checks_with(&rt);
    assert_eq!(
        found[0],
        Check::warn(
            "FRP 事务",
            "另一个 FRP 操作正在进行（续期，阶段 prepared）；完成后重新执行 onebox doctor"
        )
    );
    let binary = found.iter().find(|c| c.name == "frps 程序").unwrap();
    assert_eq!(
        binary,
        &Check::warn(
            "frps 程序",
            format!("{}frps 缺失或无法运行", probe::TRANSIENT)
        )
    );
    assert!(found.iter().all(|c| !c.is_fail()), "{found:#?}");

    // The operation died: its journal is to recover, the binary is missing.
    drop(txn);
    drop(lock);
    let found = checks_with(&rt);
    assert_eq!(found[0].status, CheckStatus::Fail, "{:?}", found[0]);
    assert!(found[0].detail.ends_with("请执行 onebox recover"));
    let binary = found.iter().find(|c| c.name == "frps 程序").unwrap();
    assert_eq!(binary.status, CheckStatus::Fail);
}

#[test]
fn journal_verdicts() {
    let journal = |phase: journal::Phase| {
        Ok(Some(Journal {
            version: journal::VERSION,
            reason: "配置".into(),
            phase,
            active: vec![],
            enabled: vec![],
            cron: Default::default(),
            snapshot: Default::default(),
        }))
    };
    let unreadable = || Err(crate::error::Error::msg("FRP 事务日志无效"));
    let busy = |what: &str| {
        Check::warn(
            "FRP 事务",
            format!("另一个 FRP 操作正在进行（{what}）；完成后重新执行 onebox doctor"),
        )
    };
    let cases = [
        (Ok(None), false, Check::pass("FRP 事务", "无未完成事务")),
        (Ok(None), true, Check::pass("FRP 事务", "无未完成事务")),
        (
            journal(journal::Phase::WriteFiles),
            false,
            Check::fail(
                "FRP 事务",
                "未完成的 FRP 事务（配置，阶段 write-files）；请执行 onebox recover",
            ),
        ),
        (
            journal(journal::Phase::WriteFiles),
            true,
            busy("配置，阶段 write-files"),
        ),
        (
            journal(journal::Phase::Committed),
            false,
            Check::warn(
                "FRP 事务",
                "已结束的 FRP 事务（配置，阶段 committed）待清理；执行 onebox recover",
            ),
        ),
        (
            journal(journal::Phase::Committed),
            true,
            busy("配置，阶段 committed"),
        ),
        (
            unreadable(),
            false,
            Check::fail("FRP 事务", "事务日志无法读取: FRP 事务日志无效"),
        ),
        (unreadable(), true, busy("事务日志正在更新")),
    ];
    for (found, running, want) in cases {
        assert_eq!(journal_verdict(found, running), want, "{running}");
    }
}

#[test]
fn a_broken_state_fails() {
    let h = FakeHost::new();
    let paths = &h.ctx.paths;
    crate::frp::runtime::mkdirs(paths).unwrap();
    std::fs::write(paths.frp_root.join("state.json"), "{").unwrap();
    // The unreadable state is the built-in `FRP 服务端` failure.
    let found = checks_with(&h.runtime());
    assert_eq!(
        statuses(&found),
        [("FRP 事务".to_owned(), CheckStatus::Pass)]
    );
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
    drop(lock);
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
    let lock = rt.lock().unwrap();
    let mut j = journal::create(paths, "配置", journal::Before::default(), &[]).unwrap();
    j.set_phase(paths, journal::Phase::Committed).unwrap();
    drop(lock);
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
