use super::*;
use crate::apply::journal::Phase;
use crate::diag::survey::FrpFound;
use crate::domain::{fixtures, Core};
use crate::frp::model::{AppDomain, BindAddr, FrpState, Mode, WebSettings, WebTls};
use crate::state::{Loaded, StateHash};
use crate::sys::fs::TempDir;
use std::fs;

fn loaded(origin: Origin) -> NodeState {
    NodeState::Loaded(Box::new(Loaded {
        config: fixtures::config(&[(Protocol::Tuic, 443, Core::Singbox)]),
        hash: StateHash::absent(),
        origin,
    }))
}

#[test]
fn state_checks_by_origin() {
    assert_eq!(
        state_checks(&NodeState::Absent),
        [Check::pass(STATE, "未安装代理节点")]
    );
    assert_eq!(
        state_checks(&NodeState::Invalid("state.json 无效".into())),
        [Check::fail(STATE, "state.json 无效")]
    );
    assert_eq!(
        state_checks(&loaded(Origin::V3)),
        [Check::pass(STATE, "1 个协议：tuic")]
    );
    let v2 = loaded(Origin::V2 {
        devices: None,
        warnings: vec!["提示一".into(), "提示二".into()],
    });
    assert_eq!(
        state_checks(&v2),
        [
            Check::warn(
                STATE,
                "1 个协议：tuic；仍是 2.x 格式，执行 onebox regen 完成升级"
            ),
            Check::warn(MIGRATION, "提示一"),
            Check::warn(MIGRATION, "提示二"),
        ]
    );
}

#[test]
fn protocol_summary_lists_ids_in_order() {
    let cfg = fixtures::config(&[
        (Protocol::Hysteria2, 443, Core::Singbox),
        (Protocol::Shadowsocks, 8388, Core::Xray),
    ]);
    assert_eq!(protocol_summary(&cfg), "2 个协议：hysteria2、shadowsocks");
    let mut empty = cfg;
    empty.inbounds.clear();
    assert_eq!(protocol_summary(&empty), "没有协议");
}

#[test]
fn pending_journal_verdicts() {
    let info = |reason: Option<&str>, phase: Phase| PhaseInfo {
        version: 2,
        phase,
        reason: reason.map(str::to_owned),
    };
    let pending = |config: Option<PhaseInfo>, program: bool| Ok(Pending { config, program });
    let cases = [
        (
            pending(Some(info(Some("安装"), Phase::PrepareCertificates)), false),
            false,
            Check::fail(
                JOURNAL,
                "有未完成事务（配置变更「安装」停在准备证书阶段）；执行 onebox recover",
            ),
        ),
        (
            pending(Some(info(None, Phase::RollbackFiles)), false),
            false,
            Check::fail(
                JOURNAL,
                "有未完成事务（配置变更停在回滚：恢复文件阶段）；执行 onebox recover",
            ),
        ),
        (
            pending(None, true),
            false,
            Check::fail(JOURNAL, "有未完成事务（程序自更新）；执行 onebox recover"),
        ),
        (
            pending(Some(info(Some("添加协议"), Phase::Committed)), true),
            false,
            Check::fail(
                JOURNAL,
                "有未完成事务（配置变更「添加协议」停在已提交阶段，程序自更新）；执行 onebox recover",
            ),
        ),
        (
            pending(Some(info(Some("添加协议"), Phase::StartCores)), false),
            true,
            Check::warn(
                JOURNAL,
                "另一个配置操作正在进行（配置变更「添加协议」停在启动内核阶段）；完成后重新执行 onebox doctor",
            ),
        ),
        (pending(None, false), true, Check::pass(JOURNAL, "无")),
        (
            Err(Error::msg("事务日志过大")),
            false,
            Check::fail(JOURNAL, "事务记录无法读取: 事务日志过大"),
        ),
        (
            Err(Error::msg("事务日志无效")),
            true,
            Check::warn(
                JOURNAL,
                "另一个配置操作正在进行（事务记录正在更新）；完成后重新执行 onebox doctor",
            ),
        ),
    ];
    for (pending, busy, want) in cases {
        assert_eq!(journal_verdict(pending, busy), want);
    }
}

/// The journal line as `diagnose` computes it.
fn journal_now(paths: &Paths) -> Check {
    journal_check(paths, operation_running(paths))
}

#[test]
fn a_journal_of_a_running_operation_is_a_warning() {
    let dir = TempDir::new("diag-journal-busy").unwrap();
    let paths = Paths::isolated(dir.path());
    let cfg = fixtures::config(&[(Protocol::Tuic, 443, Core::Singbox)]);
    let journal = crate::apply::journal::Journal::new(
        "安装",
        Some(cfg),
        vec![],
        vec![],
        Default::default(),
        Default::default(),
    );
    journal::write(&paths, &journal).unwrap();
    assert_eq!(journal_now(&paths).status, CheckStatus::Fail);
    assert!(
        !paths.lock().exists(),
        "probing never creates the lock file"
    );
    let held = FileLock::acquire(&paths.lock(), BUSY_MESSAGE).unwrap();
    assert!(operation_running(&paths));
    assert_eq!(journal_now(&paths).status, CheckStatus::Warn);

    // Caught mid-cleanup: the directory is there, journal.json is gone.
    fs::remove_file(paths.transaction().join("journal.json")).unwrap();
    assert_eq!(
        journal_now(&paths),
        Check::warn(
            JOURNAL,
            "另一个配置操作正在进行（事务记录正在更新）；完成后重新执行 onebox doctor"
        )
    );
    drop(held);
    let check = journal_now(&paths);
    assert_eq!(check.status, CheckStatus::Fail, "{check:?}");
    assert!(check.detail.starts_with("事务记录无法读取: "), "{check:?}");
}

#[test]
fn the_lock_is_probed_only_while_a_journal_exists() {
    let dir = TempDir::new("diag-journal-lock").unwrap();
    let paths = Paths::isolated(dir.path());
    fs::create_dir_all(&paths.root).unwrap();
    let _held = FileLock::acquire(&paths.lock(), BUSY_MESSAGE).unwrap();
    assert!(!operation_running(&paths), "no journal: not probed");
    fs::write(paths.self_update_journal(), "{").unwrap();
    assert!(operation_running(&paths), "a self-update journal counts");
}

#[test]
fn an_frp_operation_runs_while_its_journal_exists_and_its_lock_is_held() {
    let dir = TempDir::new("diag-frp-lock").unwrap();
    let paths = Paths::isolated(dir.path());
    let lock = paths.frp_lock();
    fs::create_dir_all(lock.parent().unwrap()).unwrap();
    // (journal, lock held, running)
    let cases = [
        (false, false, false),
        (false, true, false),
        (true, false, false),
        (true, true, true),
    ];
    for (journal, held, want) in cases {
        let _ = fs::remove_dir(paths.frp_journal());
        let _ = fs::remove_file(&lock);
        if journal {
            fs::create_dir(paths.frp_journal()).unwrap();
        }
        let guard = held.then(|| FileLock::acquire(&lock, BUSY_MESSAGE).unwrap());
        assert_eq!(frp_operation_running(&paths), want, "{journal} {held}");
        assert_eq!(lock.exists(), guard.is_some(), "probing never creates it");
        // The node lock says nothing about FRP, and the reverse.
        assert!(!operation_running(&paths));
    }
}

#[test]
fn failures_are_downgraded_while_an_operation_runs() {
    assert_eq!(
        downgrade(Check::fail("服务 onebox-xray", "未运行")),
        Check::warn("服务 onebox-xray", format!("{TRANSIENT}未运行"))
    );
    let warn = Check::warn("x", "y");
    assert_eq!(downgrade(warn.clone()), warn);
    let pass = Check::pass("x", "y");
    assert_eq!(downgrade(pass.clone()), pass);
}

#[test]
fn journal_check_without_journals_passes() {
    let dir = TempDir::new("diag-journal").unwrap();
    let paths = Paths::isolated(dir.path());
    assert_eq!(journal_now(&paths), Check::pass(JOURNAL, "无"));
    // A `.transaction` that is a file is corrupt, not "nothing pending".
    fs::create_dir_all(&paths.root).unwrap();
    fs::write(paths.transaction(), "").unwrap();
    let check = journal_now(&paths);
    assert_eq!(check.status, CheckStatus::Fail);
    assert!(
        check.detail.starts_with("事务记录无法读取: 事务目录无效"),
        "{check:?}"
    );
}

#[test]
fn program_versions() {
    let exe = "/usr/local/bin/onebox";
    let cases = [
        ("3.0.0", "3.0.0", CheckStatus::Pass, "/usr/local/bin/onebox（3.0.0）"),
        (
            "3.0.1",
            "3.0.0",
            CheckStatus::Warn,
            "/usr/local/bin/onebox 是更新的 3.0.1，本次运行的是 3.0.0；请直接运行 /usr/local/bin/onebox",
        ),
        (
            "2.0.1",
            "3.0.0",
            CheckStatus::Warn,
            "/usr/local/bin/onebox 是 2.0.1，本次运行的是 3.0.0；执行 onebox regen 安装当前程序",
        ),
        (
            "garbage",
            "3.0.0",
            CheckStatus::Warn,
            "/usr/local/bin/onebox 是 garbage，本次运行的是 3.0.0；执行 onebox regen 安装当前程序",
        ),
    ];
    for (installed, running, status, detail) in cases {
        assert_eq!(
            version_check(exe, installed, running),
            Check::new(PROGRAM, status, detail),
            "{installed}"
        );
    }
}

#[test]
fn program_check_reports_a_program_that_cannot_run() {
    let dir = TempDir::new("diag-program").unwrap();
    let (ctx, fake, _) = Ctx::test(dir.path());
    fs::write(&ctx.paths.executable, "").unwrap();
    fake.on(
        "onebox",
        &["version"],
        crate::sys::exec::Output::failure(126, ""),
    );
    let check = program_check(&ctx);
    assert_eq!(check.status, CheckStatus::Fail);
    assert!(
        check.detail.ends_with("无法运行（退出码 126）"),
        "{check:?}"
    );
}

fn ledger(dir: &std::path::Path, owner: &str, rules: &str) -> Result<Ledger> {
    let path = dir.join(format!("{owner}.json"));
    fs::write(&path, rules).unwrap();
    Ledger::load(&path, owner)
}

const ONE_RULE: &str = r#"{"rules":[{"backend":"ufw","port":443,"udp":false,"token":"onebox-proxy-0123456789abcdef"}]}"#;

#[test]
fn firewall_ledgers() {
    let dir = TempDir::new("diag-ledger").unwrap();
    let d = dir.path();
    assert_eq!(
        firewall_check(ledger(d, "proxy", ONE_RULE), ledger(d, "acme", "{}")),
        Check::pass(FIREWALL, "已记录 1 条端口规则")
    );
    assert_eq!(
        firewall_check(ledger(d, "proxy", "{}"), ledger(d, "acme", ONE_RULE)),
        Check::warn(
            FIREWALL,
            "临时证书验证规则仍在（1 条）；执行 onebox regen 清理"
        )
    );
    let broken = firewall_check(ledger(d, "proxy", "[1"), ledger(d, "acme", "{}"));
    assert_eq!(broken.status, CheckStatus::Fail);
    assert!(broken.detail.starts_with("防火墙台账无效"), "{broken:?}");
    let missing = Ledger::load(&d.join("absent.json"), "proxy");
    assert_eq!(
        firewall_check(missing, Ledger::load(&d.join("absent2.json"), "acme")),
        Check::pass(FIREWALL, "已记录 0 条端口规则")
    );
}

fn hop(start: u16, end: u16, target: u16) -> Hop {
    Hop {
        backend: "nft".into(),
        start,
        end,
        target,
        token: "onebox-hop-0123456789abcdef".into(),
    }
}

/// (recorded hops, configuration, expected check).
type HopCase<'a> = (Result<Vec<Hop>>, Option<&'a NodeConfig>, Option<Check>);

#[test]
fn hop_checks() {
    let plain = fixtures::config(&[(Protocol::Hysteria2, 8443, Core::Singbox)]);
    let mut hopping = plain.clone();
    hopping.hy2.hop = Some("20000-20010".parse().unwrap());
    let cases: [HopCase; 6] = [
        (Ok(vec![]), Some(&plain), None),
        (Ok(vec![hop(1, 2, 3)]), None, None),
        (
            Ok(vec![hop(20000, 20010, 8443)]),
            Some(&plain),
            Some(Check::warn(
                HOPS,
                "配置未启用端口跳跃，但仍记录 1 条规则；执行 onebox hop-clear",
            )),
        ),
        (
            Ok(vec![hop(20000, 20010, 8443)]),
            Some(&hopping),
            Some(Check::pass(HOPS, "UDP 20000-20010 → 8443")),
        ),
        (
            Ok(vec![hop(20000, 20010, 443)]),
            Some(&hopping),
            Some(Check::warn(
                HOPS,
                "UDP 20000-20010 → 8443 的规则未记录；执行 onebox hop-apply",
            )),
        ),
        (
            Err(Error::msg("端口跳跃台账无效")),
            None,
            Some(Check::fail(HOPS, "端口跳跃台账无效")),
        ),
    ];
    for (recorded, cfg, want) in cases {
        assert_eq!(hop_check(recorded, cfg), want);
    }
}

#[test]
fn frp_checks() {
    assert_eq!(frp_check(&FrpFound::Absent), None);
    assert_eq!(
        frp_check(&FrpFound::Invalid("FRP 状态 x 无效".into())),
        Some(Check::fail(FRP, "FRP 状态 x 无效"))
    );
    let tcp = FrpState::new(
        "frp.example.org".into(),
        "0".repeat(64),
        BindAddr::AnyV4,
        Mode::tcp(),
    );
    assert_eq!(
        frp_check(&FrpFound::Loaded(Box::new(tcp))),
        Some(Check::pass(FRP, "状态正常（TCP 模式，frp 0.71.0）"))
    );
    let mut web = FrpState::new(
        "203.0.113.7".into(),
        "0".repeat(64),
        BindAddr::AnyV4,
        Mode::Web(WebSettings::new(
            AppDomain::Single {
                domain: "app.example.org".into(),
            },
            WebTls::Http01,
        )),
    );
    web.version = "0.71.0".into();
    let check = frp_check(&FrpFound::Loaded(Box::new(web))).unwrap();
    assert_eq!(check.status, CheckStatus::Warn);
    assert!(
        check
            .detail
            .starts_with("网站模式；FRP 控制域名 203.0.113.7"),
        "{check:?}"
    );
}
