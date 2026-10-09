use super::*;
use crate::cli::session::testing::{Bench, Call};
use crate::domain::fixtures::{config, with_site};
use crate::domain::protocol::Core::{Singbox as SB, Xray as XR};
use crate::domain::protocol::Protocol::*;
use std::sync::Mutex;

/// A scripted result for one dispatched command line.
type Scripted = (String, fn() -> Error);

/// Records dispatched command lines; `fail` scripts their result.
#[derive(Default)]
struct Calls {
    argv: Mutex<Vec<String>>,
    fail: Mutex<Vec<Scripted>>,
}

impl Calls {
    fn lines(&self) -> Vec<String> {
        self.argv.lock().unwrap().clone()
    }
    fn fail_on(&self, line: &str, error: fn() -> Error) {
        self.fail.lock().unwrap().push((line.to_owned(), error));
    }
}

impl Dispatcher for Calls {
    fn dispatch(&self, _session: &Session, argv: &[&str]) -> Result<()> {
        let line = argv.join(" ");
        self.argv.lock().unwrap().push(line.clone());
        let fail = self.fail.lock().unwrap();
        match fail.iter().find(|(l, _)| *l == line) {
            Some((_, error)) => Err(error()),
            None => Ok(()),
        }
    }
}

fn menu_run(bench: &Bench, calls: &Calls, answers: &[&str]) -> Result<()> {
    bench.answers(answers);
    let session = bench.session();
    let menu = Menu {
        session: &session,
        dispatcher: calls,
    };
    let result = menu.main();
    assert_eq!(
        bench.ui.remaining(),
        0,
        "unused answers; prompts: {:?}",
        bench.ui.prompts()
    );
    result
}

fn node() -> NodeConfig {
    let mut cfg = config(&[
        (VlessReality, 443, XR),
        (Hysteria2, 443, SB),
        (Tuic, 8443, SB),
    ]);
    cfg.versions.singbox = Some("1.14.2".into());
    cfg.versions.xray = Some("26.3.27".into());
    cfg
}

#[test]
fn installed_main_menu_layout() {
    let bench = Bench::installed(&node());
    bench.live.set_running("onebox-sing-box");
    bench.live.set_running("onebox-xray");
    menu_run(&bench, &Calls::default(), &["0"]).unwrap();
    let expected = "Onebox 3.0.0 · sing-box 1.14.2 · Xray 26.3.27
节点 203.0.113.10 · 3 个协议 · 内核运行中
  1) 节点信息与分享  查看节点、导出客户端配置、二维码
  2) 协议管理        添加 / 删除协议、修改端口
  3) 连接与伪装      连接地址、REALITY 目标、ShadowTLS、TLS 证书
  4) 远程订阅
  5) 自有域名网站
  6) 服务            状态、启动/停止/重启、日志
  7) 性能与诊断      调优、体检、链路测试、BBR
  8) 备份与恢复      快照、恢复、故障恢复、重新生成配置
  9) FRP 服务端
 10) 更新            程序、内核、更新渠道
 11) 重装 / 卸载
  0) 退出
请选择";
    assert_eq!(bench.ui.prompts(), [expected]);
}

/// `onebox` without arguments and without a terminal prints the command
/// overview; it never reaches the host (the unit test context is isolated).
#[test]
fn without_a_terminal_the_overview_is_printed() {
    let bench = Bench::installed(&node());
    bench.ui.set_interactive(false);
    let help = unanswerable(bench.ui.as_ref()).unwrap();
    assert!(help.contains("不带参数运行 onebox 打开交互菜单"), "{help}");
    run(&bench.ctx).unwrap();
    assert!(bench.ui.prompts().is_empty(), "no menu shown");
    assert!(bench.exec.history().is_empty(), "the host is not queried");
    // A terminal, or -y (which picks 0) opens the menu.
    bench.ui.set_interactive(true);
    assert!(unanswerable(bench.ui.as_ref()).is_none());
    bench.unattended();
    assert!(unanswerable(bench.ui.as_ref()).is_none());
}

#[test]
fn header_core_states() {
    let bench = Bench::installed(&node());
    let session = bench.session();
    assert!(header(&session, Some(&node())).ends_with("内核已停止"));
    bench.live.set_running("onebox-xray");
    assert!(header(&session, Some(&node())).ends_with("部分内核已停止"));
    assert_eq!(header(&session, None), "Onebox 3.0.0\n尚未安装节点");
}

#[test]
fn not_installed_menu_and_g29() {
    let bench = Bench::new();
    let calls = Calls::default();
    menu_run(&bench, &calls, &["3", "4", "5", "0"]).unwrap();
    assert_eq!(calls.lines(), ["frps", "bbr", "update-script"]);
    let prompt = &bench.ui.prompts()[0];
    assert!(prompt.starts_with("Onebox 3.0.0\n尚未安装节点\n 1) 安装\n 2) 安装预演\n 3) FRP 服务端\n 4) BBR\n 5) 更新程序\n 0) 退出"), "{prompt}");
    // A backup and an unreadable journal add restore and recovery.
    let backup = bench.ctx.paths.backups().join("1791000000-1a2b3c4d");
    std::fs::create_dir_all(&backup).unwrap();
    std::fs::write(backup.join("manifest.json"), "{}").unwrap();
    let journal = bench.ctx.paths.transaction();
    std::fs::create_dir_all(&journal).unwrap();
    std::fs::write(journal.join("journal.json"), "not json").unwrap();
    let calls = Calls::default();
    menu_run(&bench, &calls, &["6", "", "7", "0"]).unwrap();
    assert_eq!(calls.lines(), ["backups", "restore latest", "recover"]);
}

#[test]
fn unattended_exits_and_eof_cancels() {
    let bench = Bench::installed(&node());
    bench.unattended();
    menu_run(&bench, &Calls::default(), &[]).unwrap();
    let bench = Bench::installed(&node());
    let err = menu_run(&bench, &Calls::default(), &["99", "x"]).unwrap_err();
    assert!(err.is_cancelled(), "EOF at the menu prompt");
    assert_eq!(bench.ui.errors(), ["请输入 0–11", "请输入 0–11"]);
}

#[test]
fn outcome_rules() {
    let bench = Bench::new();
    let session = bench.session();
    let calls = Calls::default();
    let menu = Menu {
        session: &session,
        dispatcher: &calls,
    };
    assert!(menu.outcome(Ok(())).is_ok());
    let exit0 = menu.outcome(Err(Error::exit(
        0,
        "程序更新已完成；请重新执行 onebox 以使用新版本",
    )));
    assert!(matches!(exit0, Err(Error::Exit { code: 0, .. })));
    let exit75 = menu.outcome(Err(Error::exit(75, "自更新恢复已完成")));
    assert!(matches!(exit75, Err(Error::Exit { code: 75, .. })));
    menu.outcome(Err(Error::exit(
        2,
        "REALITY 检查完成，请核对报告中的警告。",
    )))
    .unwrap();
    menu.outcome(Err(Error::Cancelled)).unwrap();
    menu.outcome(Err(Error::Cancelled.wrap("测试已取消")))
        .unwrap();
    menu.outcome(Err(Error::msg("端口无效或被占用"))).unwrap();
    menu.outcome(Err(Error::exit(1, "失败"))).unwrap();
    assert_eq!(
        bench.notes(),
        [
            "[警告] REALITY 检查完成，请核对报告中的警告。",
            "[提示] 操作已取消",
            "[提示] 测试已取消",
            "[错误] 端口无效或被占用",
            "[错误] 失败",
        ]
    );
}

#[test]
fn info_submenu_navigation() {
    let bench = Bench::installed(&node());
    menu_run(&bench, &Calls::default(), &["1", "1", "0", "0"]).unwrap();
    assert!(bench
        .output()
        .starts_with("Onebox 3.0.0  地址: 203.0.113.10"));
    let prompts = bench.ui.prompts();
    assert!(
        prompts[1].starts_with(
            "节点信息与分享\n  地址 203.0.113.10 · 3 个协议 · 节点名称 onebox\n 1) 查看节点信息"
        ),
        "{}",
        prompts[1]
    );
    assert!(prompts[1].ends_with(" 0) 返回\n请选择"));
}

#[test]
fn update_script_success_ends_the_menu() {
    let bench = Bench::installed(&node());
    let calls = Calls::default();
    calls.fail_on("update-script", || {
        Error::exit(0, "程序更新已完成；请重新执行 onebox 以使用新版本")
    });
    calls.fail_on("reality-check", || {
        Error::exit(2, "REALITY 检查完成，请核对报告中的警告。")
    });
    // reality-check with warnings continues; the update ends everything.
    let err = menu_run(&bench, &calls, &["7", "10", "0", "10", "2"]).unwrap_err();
    assert!(matches!(err, Error::Exit { code: 0, .. }));
    assert_eq!(calls.lines(), ["reality-check", "update-script"]);
}

#[test]
fn errors_and_cancellations_inside_actions_return_to_the_submenu() {
    let bench = Bench::installed(&node());
    let calls = Calls::default();
    calls.fail_on("subscription info", || Error::Cancelled);
    calls.fail_on("subscription disable", || Error::msg("订阅未启用"));
    menu_run(&bench, &calls, &["4", "1", "6", "0", "0"]).unwrap();
    assert_eq!(calls.lines(), ["subscription info", "subscription disable"]);
    assert_eq!(bench.notes(), ["[提示] 操作已取消", "[错误] 订阅未启用"]);
}

#[test]
fn subscription_enable_dialog() {
    let bench = Bench::installed(&node());
    let calls = Calls::default();
    menu_run(
        &bench,
        &calls,
        &["4", "2", "2", "1", "bad", "", "0", "8448", "0", "0"],
    )
    .unwrap();
    assert_eq!(
        calls.lines(),
        ["subscription enable --mode ip --address 203.0.113.10 --port 8448"]
    );
    assert!(bench.notes().contains(&format!(
        "[警告] {}",
        "请选择 ip、standalone，或已启用自建站时选择 site。"
    )));
    assert_eq!(
        bench.ui.errors(),
        [
            "订阅地址必须是 IPv4 或 IPv6 字面地址，不能含域名、端口、路径或 zone ID",
            "端口不能为 0"
        ]
    );
    // With a site, site mode is the default.
    let site = with_site(node(), "www.example.com", true);
    let bench = Bench::installed(&site);
    let calls = Calls::default();
    menu_run(&bench, &calls, &["4", "2", "", "0", "0"]).unwrap();
    assert_eq!(calls.lines(), ["subscription enable --mode site"]);
}

#[test]
fn standalone_subscription_and_devices() {
    let bench = Bench::installed(&node());
    let calls = Calls::default();
    menu_run(
        &bench,
        &calls,
        &[
            "4",
            "2",
            "3",
            "sub.example.com",
            "",
            "2", // standalone, cf
            "3",
            "", // add device "phone"
            "4",
            "xyz",
            "0123456789ABCDEF", // revoke
            "0",
            "0",
        ],
    )
    .unwrap();
    assert_eq!(
        calls.lines(),
        [
            "subscription enable --mode standalone --domain sub.example.com --port 8448 --tls cf",
            "subscription add phone",
            "subscription info",
            "subscription revoke 0123456789abcdef",
        ]
    );
    assert_eq!(bench.ui.errors(), ["设备 ID 应为 16 位十六进制"]);
}

#[test]
fn backup_update_and_frp_entries() {
    let bench = Bench::installed(&node());
    let calls = Calls::default();
    menu_run(
        &bench,
        &calls,
        &[
            "8", "1", "", "2", "3", "", "4", "0", // backups
            "9", // frps
            "10", "1", "3", "4", "2", "0", // updates
            "0",
        ],
    )
    .unwrap();
    assert_eq!(
        calls.lines(),
        [
            "backup manual",
            "backups",
            "backups",
            "restore latest",
            "recover",
            "frps",
            "update-check",
            "update",
            "update-channel testing",
        ]
    );
}

#[test]
fn regen_from_the_backup_menu() {
    let bench = Bench::installed(&node());
    menu_run(&bench, &Calls::default(), &["8", "5", "0", "0"]).unwrap();
    assert_eq!(bench.engine.calls(), [Call::Apply]);
    assert_eq!(bench.engine.single().reason, "重新生成配置");
    assert_eq!(bench.output(), "配置已更新");
}

#[test]
fn typed_actions_check_root() {
    let mut bench = Bench::installed(&node());
    bench.is_root = false;
    menu_run(&bench, &Calls::default(), &["2", "1", "0", "0"]).unwrap();
    assert_eq!(bench.notes(), ["[错误] 此操作需要 root 权限"]);
    assert!(bench.engine.calls().is_empty());
}

#[test]
fn protocol_submenu_shows_the_table_and_adds() {
    let bench = Bench::installed(&node());
    menu_run(&bench, &Calls::default(), &["2", "1", "3", "", "0", "0"]).unwrap();
    let prompts = bench.ui.prompts();
    assert!(
        prompts[1].starts_with("协议管理\n协议                  内核      端口\n"),
        "{}",
        prompts[1]
    );
    let req = bench.engine.single();
    assert_eq!(req.reason, "添加协议");
    assert!(req.config.has(VlessWs));
}

#[test]
fn tuning_previews_then_asks() {
    let bench = Bench::installed(&node());
    menu_run(
        &bench,
        &Calls::default(),
        &["7", "1", "n", "1", "", "0", "0"],
    )
    .unwrap();
    assert_eq!(
        bench.output(),
        "调优预览: HY2=auto up= down= resource=balanced\n调优预览: HY2=auto up= down= resource=balanced"
    );
    let req = bench.engine.single();
    assert_eq!(req.reason, "调优");
    let prompts = bench.ui.prompts();
    assert!(prompts[1].starts_with("性能与诊断\n  Hysteria2 调优 未设置 · 资源档位 balanced"));
}

#[test]
fn link_tests_build_their_command_lines() {
    let bench = Bench::installed(&node());
    let probe = bench.ctx.paths.clients().join("probe.json");
    std::fs::create_dir_all(probe.parent().unwrap()).unwrap();
    std::fs::write(&probe, "{}").unwrap();
    let probe = probe.to_string_lossy().into_owned();
    let calls = Calls::default();
    menu_run(
        &bench,
        &calls,
        &[
            "7",
            "8",
            "",
            "http://x",
            "",
            "n1-a,n2-b",
            "30",
            "3",
            "",
            "",
            "", // bench
            "9",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "", // failover
            "0",
            "0",
        ],
    )
    .unwrap();
    assert_eq!(
        calls.lines(),
        [
            format!("bench {probe} --url https://www.gstatic.com/generate_204 --entries n1-a,n2-b --samples 3"),
            format!("failover {probe} --url https://www.gstatic.com/generate_204 --port 2080 --interval 15 --failures 3 --recoveries 3 --cooldown 60"),
        ]
    );
    assert_eq!(
        bench.ui.errors(),
        ["请输入 https:// 开头的地址", "请输入 1–20 的整数"]
    );
}

#[test]
fn site_submenu_defaults_to_current_values() {
    let bench = Bench::installed(&with_site(node(), "www.example.com", true));
    menu_run(&bench, &Calls::default(), &["5", "4", "n", "0", "0"]).unwrap();
    let prompts = bench.ui.prompts();
    assert!(prompts[1].starts_with("自有域名网站\n  www.example.com · HTTPS 443 入口开启 · 模板 minimal · 配色 forest\n  标题 山间手记"), "{}", prompts[1]);
    assert_eq!(prompts[2], "开启网站 HTTPS 443 入口?");
    let req = bench.engine.single();
    assert!(!req.config.site.unwrap().https_entry);
}

#[test]
fn helpers() {
    assert_eq!(backup_id("latest").unwrap(), "latest");
    assert_eq!(
        backup_id("1791000000-1a2b3c4d").unwrap(),
        "1791000000-1a2b3c4d"
    );
    assert!(backup_id("../x").is_err());
    assert!(backup_id("").is_err());
    let dir = crate::sys::fs::TempDir::new("menu-backups").unwrap();
    assert!(!has_backups(dir.path()));
    std::fs::create_dir_all(dir.join(".new-x")).unwrap();
    std::fs::write(dir.join(".new-x/manifest.json"), "{}").unwrap();
    assert!(!has_backups(dir.path()), "staging directories do not count");
    std::fs::create_dir_all(dir.join("1-a")).unwrap();
    std::fs::write(dir.join("1-a/manifest.json"), "{}").unwrap();
    assert!(has_backups(dir.path()));
}
