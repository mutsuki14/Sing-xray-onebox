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
    let menu = Menu::new(&session, calls);
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
    assert_eq!(calls.lines(), ["backups", "restore -- latest", "recover"]);
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
    let menu = Menu::new(&session, &calls);
    assert!(menu.outcome(Ok(())).is_ok());
    let exit0 = menu.outcome(Err(Error::exit(
        0,
        "程序更新已完成；请重新执行 onebox 以使用新版本",
    )));
    assert!(matches!(exit0, Err(Error::Exit { code: 0, .. })));
    let exit75 = menu.outcome(Err(Error::exit(75, "自更新恢复已完成")));
    assert!(matches!(exit75, Err(Error::Exit { code: 75, .. })));
    let wrapped = Error::Context {
        message: "程序更新".into(),
        source: Box::new(Error::exit(75, "自更新恢复已完成")),
    };
    let wrapped = menu.outcome(Err(wrapped)).unwrap_err();
    assert_eq!(
        wrapped.exit_code(),
        75,
        "a wrapped exit 75 still ends the menu"
    );
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
    let err = menu_run(&bench, &calls, &["7", "11", "0", "10", "2"]).unwrap_err();
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
            "subscription add -- phone",
            "subscription info",
            "subscription revoke -- 0123456789abcdef",
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
            "backup -- manual",
            "backups",
            "backups",
            "restore -- latest",
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
    assert!(prompts[1].starts_with(
        "性能与诊断\n  Hysteria2 调优 未设置 · 混淆 关闭 · 端口跳跃 关闭 · 资源档位 balanced"
    ));
}

#[test]
fn hysteria2_obfuscation_and_hopping_from_the_menu() {
    let bench = Bench::installed(&node());
    // Obfuscation on, a bad range re-asked, then applied (Enter = yes).
    let answers = ["7", "4", "y", "30000", "30000-30100", "", "0", "0"];
    menu_run(&bench, &Calls::default(), &answers).unwrap();
    assert_eq!(bench.ui.errors(), ["端口范围格式应为 起始-结束: 30000"]);
    let hy2 = bench.engine.single().config.hy2;
    assert!(hy2.obfs);
    assert_eq!(hy2.hop.unwrap().to_string(), "30000-30100");
    assert!(bench
        .output()
        .ends_with("Hysteria2 混淆=on 端口跳跃=30000-30100"));
    assert!(bench
        .notes()
        .contains(&format!("[提示] {}", crate::cli::commands::tune::REIMPORT)));
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
            "9",
            "",
            "http://x",
            "",
            "n1-a,n2-b",
            "30",
            "3",
            "",
            "",
            "", // bench
            "10",
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
            format!("bench --url https://www.gstatic.com/generate_204 --entries n1-a,n2-b --samples 3 -- {probe}"),
            format!("failover --url https://www.gstatic.com/generate_204 --port 2080 --interval 15 --failures 3 --recoveries 3 --cooldown 60 -- {probe}"),
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
fn site_enable_asks_for_the_entrance() {
    let bench = Bench::installed(&node());
    // 启用网站: domain, entrance closed, HTTP-01 certificate.
    let answers = ["5", "2", "www.example.com", "n", "", "0", "0"];
    menu_run(&bench, &Calls::default(), &answers).unwrap();
    assert!(bench
        .ui
        .prompts()
        .contains(&"开启网站 HTTPS 443 入口?".to_owned()));
    let site = bench.engine.single().config.site.unwrap();
    assert_eq!(site.domain, "www.example.com");
    assert!(!site.https_entry, "closed from the start");
}

/// 启用网站 on an existing site: Enter keeps its domain, entrance and
/// certificate method (a custom pair defaults to its files).
#[test]
fn site_enable_defaults_to_the_existing_site() {
    use crate::domain::config::WebCert;
    let dir = crate::sys::fs::TempDir::new("menu-site-cert").unwrap();
    let (cert, key) = (dir.join("fullchain.pem"), dir.join("key.pem"));
    std::fs::write(&cert, "CERT").unwrap();
    std::fs::write(&key, "KEY").unwrap();
    let custom = WebCert::Custom { cert, key };
    // (certificate, Enter at every question of 启用网站 — the token is
    // asked before the apply)
    let mut cases: Vec<(WebCert, &[&str])> =
        vec![(custom, &["5", "2", "", "", "", "", "", "0", "0"])];
    if std::env::var_os("CF_Token").is_none() {
        let answers: &[&str] = &["5", "2", "", "", "", "fake-token-0123", "", "0", "0"];
        cases.push((WebCert::Cloudflare, answers));
    }
    for (method, answers) in cases {
        let mut cfg = with_site(node(), "www.example.com", false);
        if let Some(site) = cfg.site.as_mut() {
            site.cert = method.clone();
        }
        let bench = Bench::installed(&cfg);
        menu_run(&bench, &Calls::default(), answers).unwrap();
        let site = bench.engine.single().config.site.unwrap();
        assert_eq!(site.domain, "www.example.com");
        assert!(!site.https_entry, "kept closed");
        assert_eq!(site.cert, method);
    }
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

/// EOF (or Ctrl+C) at a submenu's own prompt leaves the whole menu with
/// 130 — also from a nested submenu — while one inside an action returns
/// to the submenu (`errors_and_cancellations_inside_actions…`).
#[test]
fn eof_at_a_submenu_prompt_exits() {
    let bench = Bench::installed(&node());
    let err = menu_run(&bench, &Calls::default(), &["4"]).unwrap_err();
    assert!(err.is_cancelled());
    assert_eq!(bench.ui.prompts().len(), 2, "main menu, then the submenu");
    // Nested: performance → probe bundles → EOF.
    let bench = Bench::installed(&node());
    let err = menu_run(&bench, &Calls::default(), &["7", "8"]).unwrap_err();
    assert!(err.is_cancelled());
    let prompts = bench.ui.prompts();
    assert_eq!(prompts.len(), 3, "{prompts:?}");
    assert!(prompts[2].starts_with("探测配置\n  本机探测配置 尚未生成\n 1) 导出本机探测配置"));
}

#[test]
fn probe_bundles_export_list_and_merge() {
    let bench = Bench::installed(&node());
    let dir = bench.dir.path();
    let existing = dir.join("server-a.json");
    std::fs::write(&existing, "{}").unwrap();
    let existing = existing.to_string_lossy().into_owned();
    let out = dir.join("all.json").to_string_lossy().into_owned();
    let export = dir.join("export.json").to_string_lossy().into_owned();
    let calls = Calls::default();
    menu_run(
        &bench,
        &calls,
        &[
            "7",
            "8", // performance → probe bundles
            "1",
            &existing,
            &export, // export: an existing target is re-asked
            "2",
            "missing.json",
            &existing, // list: a missing file is re-asked
            "3",
            &out,
            "9",
            "2",
            &existing,
            &existing, // merge two bundles
            "0",
            "0",
            "0",
        ],
    )
    .unwrap();
    assert_eq!(
        calls.lines(),
        [
            format!("probe export -- {export}"),
            format!("probe list -- {existing}"),
            format!("probe merge -- {out} {existing} {existing}"),
        ]
    );
    assert_eq!(
        bench.ui.errors(),
        [
            format!("目标已存在: {existing}"),
            "文件不存在: missing.json".to_owned(),
            "请输入 2–8 的整数".to_owned(),
        ]
    );
    let prompts = bench.ui.prompts();
    for expected in [
        "导出到新文件（不可已存在）",
        "合并到新文件（不可已存在）",
        "要合并的文件数",
        "第 1 份探测配置文件",
        "第 2 份探测配置文件",
    ] {
        assert!(
            prompts.iter().any(|p| p == expected),
            "{expected}: {prompts:?}"
        );
    }
}

/// Typed values that look like options are passed after `--`, and the
/// real registry treats them as data.
#[test]
fn typed_values_are_never_options() {
    let bench = Bench::installed(&node());
    let calls = Calls::default();
    menu_run(
        &bench,
        &calls,
        &["4", "3", "-y", "0", "8", "1", "--help", "0", "0"],
    )
    .unwrap();
    assert_eq!(
        calls.lines(),
        ["subscription add -- -y", "backup -- --help"]
    );
    // Through the registry: `probe list -- -y` reads a file named `-y`.
    let session = bench.session();
    let err = Registry
        .dispatch(&session, &["probe", "list", "--", "-y"])
        .unwrap_err()
        .to_string();
    assert!(err.contains("-y"), "{err}");
    assert!(
        !err.contains("不支持选项") && !err.contains("多余的参数"),
        "{err}"
    );
}

/// A terminal that receives `signal` when the question `at` is asked
/// (Ctrl+C, `kill`); every answer comes from `inner`.
struct SignalAt {
    inner: Arc<crate::ui::ScriptedPrompter>,
    at: &'static str,
    signal: libc::c_int,
}

impl SignalAt {
    fn raise_at(&self, prompt: &str) {
        if prompt == self.at {
            // SAFETY: raising a cancellation signal while the menu's
            // prompter holds its recording handler.
            unsafe {
                libc::raise(self.signal);
            }
        }
    }
}

impl crate::ui::Prompter for SignalAt {
    fn interactive(&self) -> bool {
        true
    }
    fn assume_yes(&self) -> bool {
        false
    }
    fn input(&self, prompt: &str, default: &str) -> Result<String> {
        self.raise_at(prompt);
        self.inner.input(prompt, default)
    }
    fn input_with(
        &self,
        prompt: &str,
        default: &str,
        check: &dyn Fn(&str) -> Result<String>,
    ) -> Result<String> {
        self.raise_at(prompt);
        self.inner.input_with(prompt, default, check)
    }
    fn confirm(&self, prompt: &str, default: bool) -> Result<bool> {
        self.raise_at(prompt);
        self.inner.confirm(prompt, default)
    }
    fn select(
        &self,
        title: &str,
        items: &[String],
        default: usize,
        back: bool,
    ) -> Result<Option<usize>> {
        self.inner.select(title, items, default, back)
    }
    fn select_many(&self, title: &str, items: &[String], default: &[usize]) -> Result<Vec<usize>> {
        self.inner.select_many(title, items, default)
    }
    fn secret(&self, prompt: &str) -> Result<String> {
        self.inner.secret(prompt)
    }
}

/// At an action's question Ctrl+C cancels only the action (back to the
/// submenu), but SIGTERM — `kill`, a supervisor's stop — ends the menu
/// with 130, as it did without the menu's handlers.
#[test]
fn only_ctrl_c_at_a_question_returns_to_the_menu() {
    let _signals = crate::sys::signal::TEST_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    crate::sys::signal::clear();
    // 自有域名网站 → 修改标题, signalled there; then 返回, 退出.
    // (signal, answers, menu ends cancelled)
    let cases: [(libc::c_int, &[&str], bool); 2] = [
        (libc::SIGINT, &["5", "7", "typed", "0", "0"], false),
        (libc::SIGTERM, &["5", "7", "typed"], true),
    ];
    for (signal, answers, ends) in cases {
        let bench = Bench::installed(&with_site(node(), "www.example.com", true));
        bench.answers(answers);
        let ui = SignalAt {
            inner: bench.ui.clone(),
            at: "网站标题",
            signal,
        };
        let ctx = Ctx {
            ui: Arc::new(interrupt::Interruptible::new(Arc::new(ui))),
            ..bench.ctx.clone()
        };
        let session =
            Session::new(&ctx, &bench.engine, &bench.live, true).with_printer(&bench.printed);
        let calls = Calls::default();
        let result = Menu::new(&session, &calls).main();
        assert_eq!(bench.ui.remaining(), 0, "{signal}");
        assert!(bench.engine.calls().is_empty(), "{signal}");
        if ends {
            let err = result.unwrap_err();
            assert_eq!(err.exit_code(), 130);
            assert_eq!(err.report_text(), "操作被信号 15 中断");
            assert!(bench.notes().is_empty(), "{:?}", bench.notes());
        } else {
            result.unwrap();
            assert_eq!(bench.notes(), ["[提示] 操作已取消"]);
        }
        crate::sys::signal::clear();
    }
}
