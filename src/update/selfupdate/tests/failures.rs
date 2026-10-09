//! Signals around the swap and failures after the journal was written.

use super::*;

// ---- signals ---------------------------------------------------------------

#[test]
fn ctrl_c_during_the_regen_reports_the_recovery_and_exits_130() {
    // The child (same process group) dies of the Ctrl+C; the parent has
    // the signal blocked until the recovery is done, then records it
    // instead of dying before it reported anything.
    let mut fx = Fx::new(true, Some("3.0.0"));
    fx.engine = FakeEngine::new(Recover::ProgramJournalCurrent);
    *fx.regen_signal.lock().unwrap() = Some(libc::SIGINT);
    *fx.regen_reply.lock().unwrap() = Output::failure(130, "");
    fx.serve(&Rel::stable("3.0.1"));
    let err = fx.run(None, false).unwrap_err();
    assert_eq!(err.exit_code(), 130);
    assert_eq!(
        err.report_text(),
        "更新失败，已恢复原程序: 新版本重新生成配置失败（退出码 130）"
    );
    assert_eq!(fx.exe(), program("3.0.0\n"));
    assert_eq!(fx.state(), fx.old_state);
    assert!(!journal_path(fx.paths()).exists());
    assert!(fx.work_dirs().is_empty());

    // A failed recovery is still explained (and its work dir named).
    let mut fx = Fx::new(true, Some("3.0.0"));
    fx.engine = FakeEngine::new(Recover::FailWithJournal("恢复失败"));
    *fx.regen_signal.lock().unwrap() = Some(libc::SIGINT);
    fx.fail_regen("");
    fx.serve(&Rel::stable("3.0.1"));
    let err = fx.run(None, false).unwrap_err();
    let work = fx.work_dirs();
    assert_eq!(work.len(), 1);
    assert_eq!(err.exit_code(), 130);
    assert_eq!(
        err.report_text(),
        format!(
            "更新失败: {REGEN_FAILED}；恢复需要重试: 恢复失败；备份: {}",
            work[0].display()
        )
    );
    assert_eq!(fx.warnings.all(), [retention_notice(&work[0])]);

    // A stale process keeps exit code 75: it must end either way.
    let mut fx = Fx::new(true, Some("3.0.0"));
    fx.engine = FakeEngine::new(Recover::ProgramJournal);
    *fx.regen_signal.lock().unwrap() = Some(libc::SIGTERM);
    fx.fail_regen("");
    fx.serve(&Rel::stable("3.0.1"));
    let result = fx.run(None, false);
    assert_eq!(exit_code(&result), Some(EXIT_STALE_PROCESS));
}

#[test]
fn a_signal_to_the_parent_alone_does_not_undo_a_finished_update() {
    // `kill -TERM <updater>` while the child regenerates successfully.
    let fx = Fx::new(true, Some("3.0.0"));
    *fx.regen_signal.lock().unwrap() = Some(libc::SIGTERM);
    let rel = Rel::stable("3.0.1");
    fx.serve(&rel);
    assert_done(fx.run(None, false));
    assert_eq!(fx.exe(), rel.binary);
}

#[test]
fn a_signal_before_the_journal_cancels_and_cleans_up() {
    // Arrives while the download is probed; the snapshot is taken, but the
    // journal is never written and the work dir (keys!) is removed.
    let fx = Fx::new(true, Some("3.0.0"));
    *fx.probe_signal.lock().unwrap() = Some(libc::SIGINT);
    fx.serve(&Rel::stable("3.0.1"));
    let err = fx.run(None, false).unwrap_err();
    assert!(err.is_cancelled());
    assert_eq!(err.exit_code(), 130);
    assert_eq!(err.report_text(), "操作被信号 2 中断");
    fx.assert_untouched(&program("3.0.0\n"));
}

// ---- failures after the journal was written -----------------------------

#[test]
fn a_failed_regen_restores_the_old_manager_and_configuration() {
    let mut fx = Fx::new(true, Some("3.0.0"));
    fx.engine = FakeEngine::new(Recover::ProgramJournal);
    fx.fail_regen("端口 443 已被占用");
    fx.serve(&Rel::stable("3.0.1"));
    let result = fx.run(None, false);
    assert_eq!(exit_code(&result), Some(EXIT_STALE_PROCESS));
    assert_eq!(
        result.unwrap_err().to_string(),
        format!("更新失败，已恢复原程序: {REGEN_FAILED}；请重新执行命令以使用恢复后的程序")
    );
    assert_eq!(fx.exe(), program("3.0.0\n"));
    assert_eq!(fx.state(), fx.old_state);
    assert!(!journal_path(fx.paths()).exists());
    assert!(fx.work_dirs().is_empty());
    assert_eq!(fx.engine.recover_calls(), 2);
    // The restored manager regenerated under the same lock.
    let regens = fx.regens();
    assert_eq!(regens.len(), 2);
    assert_eq!(regens[1].phase, Some(ProgramPhase::Recovering));
    assert_eq!(regens[1].exe, program("3.0.0\n"));
    assert_eq!(regens[1].fd_target, regens[0].fd_target);
}

#[test]
fn a_recovery_in_the_restored_process_is_a_plain_failure() {
    let mut fx = Fx::new(true, Some("3.0.0"));
    fx.engine = FakeEngine::new(Recover::ProgramJournalCurrent);
    fx.fail_regen("");
    fx.serve(&Rel::stable("3.0.1"));
    let err = fx.run(None, false).unwrap_err();
    assert_eq!(err.exit_code(), 1);
    assert_eq!(
        err.to_string(),
        format!("更新失败，已恢复原程序: {REGEN_FAILED}")
    );
    assert_eq!(fx.exe(), program("3.0.0\n"));
    assert!(fx.work_dirs().is_empty());
}

#[test]
fn a_failed_recovery_keeps_the_record_and_its_work_dir() {
    let mut fx = Fx::new(true, Some("3.0.0"));
    fx.engine = FakeEngine::new(Recover::FailWithJournal("恢复失败"));
    fx.fail_regen("boom");
    let rel = Rel::stable("3.0.1");
    fx.serve(&rel);
    let err = fx.run(None, false).unwrap_err().to_string();
    let work = fx.work_dirs();
    assert_eq!(work.len(), 1);
    assert_eq!(
        err,
        format!(
            "更新失败: {REGEN_FAILED}；恢复需要重试: 恢复失败；备份: {}",
            work[0].display()
        )
    );
    let record = load(fx.paths()).unwrap().unwrap();
    assert_eq!(record.phase, Replaced);
    assert_eq!(fx.exe(), rel.binary);
    // The next recovery (any command) finishes it.
    let lock = FileLock::acquire(&fx.paths().lock(), BUSY_MESSAGE).unwrap();
    let again = journal::recover_program_locked(&fx.ctx, &lock);
    assert_eq!(exit_code(&again), Some(EXIT_STALE_PROCESS));
    assert_eq!(fx.exe(), program("3.0.0\n"));
    assert_eq!(fx.state(), fx.old_state);
    assert!(fx.work_dirs().is_empty());
}

#[test]
fn a_failed_cleanup_after_commit_is_reported_without_recovery() {
    let mut fx = Fx::new(true, Some("3.0.0"));
    fx.hook = Hook::BreakJournal(Committed);
    let rel = Rel::stable("3.0.1");
    fx.serve(&rel);
    let err = fx.run(None, false).unwrap_err().to_string();
    assert!(
        err.starts_with("程序更新已提交，但恢复记录清理失败: ")
            && err.ends_with("；请执行 recover 完成清理"),
        "{err}"
    );
    assert_eq!(fx.engine.recover_calls(), 1, "no rollback after commit");
    assert_eq!(fx.exe(), rel.binary);
    assert_eq!(fx.work_dirs().len(), 1, "kept while the record exists");
}

#[test]
fn crash_windows_hand_off_to_the_program_journal_recovery() {
    for phase in [Prepared, Replacing, Replaced, Committed] {
        let mut fx = Fx::new(true, Some("3.0.0"));
        fx.hook = Hook::Crash(phase);
        let rel = Rel::stable("3.0.1");
        fx.serve(&rel);
        let crashed = catch_unwind(AssertUnwindSafe(|| fx.run(None, false)));
        assert!(crashed.is_err(), "{phase:?}");
        assert_eq!(load(fx.paths()).unwrap().unwrap().phase, phase);
        // The dead process released its locks.
        let lock = FileLock::acquire(&fx.paths().lock(), BUSY_MESSAGE).unwrap();
        let recovered = journal::recover_program_locked(&fx.ctx, &lock);
        if phase == Committed {
            recovered.unwrap();
            assert_eq!(fx.exe(), rel.binary, "a commit is never undone");
            assert_eq!(fx.state().unwrap(), b"{\"rewritten\":true}");
        } else {
            assert_eq!(exit_code(&recovered), Some(EXIT_STALE_PROCESS), "{phase:?}");
            assert_eq!(fx.exe(), program("3.0.0\n"), "{phase:?}");
            assert_eq!(fx.state(), fx.old_state, "{phase:?}");
        }
        assert!(!journal_path(fx.paths()).exists());
        assert!(fx.work_dirs().is_empty());
    }
}

#[test]
fn locks_and_pending_journals_stop_the_update_before_any_download() {
    let fx = Fx::new(true, Some("3.0.0"));
    let rel = Rel::stable("3.0.1");
    fx.serve(&rel);
    let held = FileLock::acquire(&fx.paths().update_lock(), "x").unwrap();
    let err = fx.run(None, false).unwrap_err();
    assert!(matches!(&err, Error::Busy(m) if m == UPDATE_BUSY), "{err}");
    drop(held);
    let held = FileLock::acquire(&fx.paths().lock(), "x").unwrap();
    let err = fx.run(None, false).unwrap_err();
    assert!(matches!(&err, Error::Busy(m) if m == BUSY_MESSAGE), "{err}");
    drop(held);
    assert_eq!(fx.engine.recover_calls(), 0);

    let mut fx = Fx::new(true, Some("3.0.0"));
    fx.engine = FakeEngine::new(Recover::Refuse("存在未完成事务，请先 recover"));
    fx.serve(&rel);
    let err = fx.run(None, false).unwrap_err();
    assert_eq!(err.to_string(), "存在未完成事务，请先 recover");
    assert_eq!(fx.curl_urls(), [rel.api_url()]);
    fx.assert_untouched(&program("3.0.0\n"));
}
