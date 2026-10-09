use super::*;

fn ok(_: &Ctx, _: &Matches) -> Result<()> {
    Ok(())
}

fn root_unless_info(m: &Matches) -> bool {
    m.path.last() != Some(&"info")
}

// The whole tree is `static`: this file compiling proves the schema types
// are const-constructible.
static FRPS: [CommandSpec; 3] = [
    CommandSpec::new("install", Group::Feature, "安装 FRP 服务端")
        .options(&[OptSpec::value("mode", "模式", "tcp / web")])
        .dry_run()
        .handler(ok),
    CommandSpec::new("info", Group::Feature, "查看 FRP")
        .options(&[OptSpec::flag("json", "JSON 输出")])
        .root(Root::NotRequired)
        .handler(ok),
    CommandSpec::new("log", Group::Feature, "FRP 日志")
        .aliases(&["logs"])
        .handler(ok),
];

static SUBSCRIPTION: [CommandSpec; 2] = [
    CommandSpec::new("enable", Group::Feature, "启用订阅")
        .options(&[OptSpec::value("mode", "模式", "ip / site / standalone")])
        .handler(ok),
    CommandSpec::new("add", Group::Feature, "添加设备")
        .args(&[ArgSpec::required("名称", "设备名称")])
        .handler(ok),
];

static BBR: [CommandSpec; 2] = [
    CommandSpec::new("info", Group::Feature, "BBR 状态")
        .root(Root::NotRequired)
        .handler(ok),
    // A feature module may declare its own `help` subcommand.
    CommandSpec::new("help", Group::Feature, "BBR 说明")
        .root(Root::NotRequired)
        .handler(ok),
];

static COMMANDS: [CommandSpec; 8] = [
    CommandSpec::new("install", Group::Node, "安装节点")
        .options(&[
            OptSpec::value("protocols", "列表", "协议列表"),
            OptSpec::value("port", "协议=端口", "端口").repeated(),
            OptSpec::value("name", "名称", "节点名称"),
            OptSpec::flag("force", "强制"),
        ])
        .dry_run()
        .handler(ok),
    CommandSpec::new("add", Group::Node, "添加协议")
        .args(&[ArgSpec::required("协议", "协议")])
        .options(&[OptSpec::value("port", "端口", "端口")])
        .handler(ok),
    CommandSpec::new("del", Group::Node, "删除协议")
        .aliases(&["remove"])
        .args(&[ArgSpec::optional("协议", "协议")])
        .handler(ok),
    CommandSpec::new("frps", Group::Feature, "FRP 服务端")
        .options(&[OptSpec::flag("json", "JSON 输出")])
        .subcommands(&FRPS)
        .root(Root::Custom(root_unless_info)),
    CommandSpec::new("subscription", Group::Feature, "远程订阅")
        .aliases(&["sub", "subscribe"])
        .args(&[ArgSpec::optional("操作", "兼容旧写法")])
        .subcommands(&SUBSCRIPTION)
        .handler(ok),
    CommandSpec::new("render", Group::Hidden, "渲染")
        .args(&[
            ArgSpec::required("类型", "server/inbound"),
            ArgSpec::optional("参数", "其余参数").many(),
        ])
        .handler(ok),
    CommandSpec::new("backup", Group::Maintain, "备份")
        .args(&[ArgSpec::optional("标签", "备份标签")])
        .handler(ok),
    // A group with a default action and no positional arguments.
    CommandSpec::new("bbr", Group::Feature, "BBR")
        .subcommands(&BBR)
        .handler(ok),
];

fn argv(line: &str) -> Vec<String> {
    line.split_whitespace().map(String::from).collect()
}

fn parse_line(line: &str) -> Result<Invocation<'static>> {
    let args = argv(line);
    let (globals, rest) = leading_globals(&args);
    parse(&COMMANDS, rest, globals)
}

fn matches(line: &str) -> Matches {
    parse_line(line)
        .unwrap_or_else(|e| panic!("{line}: {e}"))
        .matches
}

fn error(line: &str) -> String {
    match parse_line(line) {
        Ok(inv) => panic!("{line}: unexpectedly parsed {:?}", inv.matches),
        Err(e) => e.to_string(),
    }
}

#[test]
fn option_forms() {
    let m = matches(
        "install --protocols vless-reality,trojan --port vless-reality=443 --port=trojan=8443 --name=a=b --force",
    );
    assert_eq!(m.path, ["install"]);
    assert_eq!(m.value("protocols"), Some("vless-reality,trojan"));
    assert_eq!(m.values("--port"), ["vless-reality=443", "trojan=8443"]);
    assert_eq!(m.value("name"), Some("a=b"), "split at the first '='");
    assert!(m.flag("force") && m.flag("--force"));
    assert!(!m.assume_yes && !m.dry_run);
    assert_eq!(m.values("missing"), &[] as &[String]);
    // Empty values and values that look like short options are accepted.
    let args = vec!["install".to_string(), "--name".into(), "".into()];
    let inv = parse(&COMMANDS, &args, Globals::default()).unwrap();
    assert_eq!(inv.matches.value("name"), Some(""));
    assert_eq!(matches("install --name -5").value("name"), Some("-5"));
}

#[test]
fn errors() {
    for (line, message) in [
        ("install --protocols", "--protocols 需要参数"),
        ("install --protocols --force", "--protocols 需要参数"),
        ("install --name --yes", "--name 需要参数"),
        ("install --force=1", "--force 不接受值"),
        ("install --dry-run=1", "--dry-run 不接受值"),
        ("install --yes=1", "--yes 不接受值"),
        ("install --name a --name b", "重复选项: --name"),
        ("install --force --force", "重复选项: --force"),
        (
            "install --bogus",
            "install 不支持选项 --bogus；请执行 onebox install --help",
        ),
        (
            "install --bogus=1",
            "install 不支持选项 --bogus；请执行 onebox install --help",
        ),
        (
            "install -x",
            "install 不支持选项 -x；请执行 onebox install --help",
        ),
        ("add", "缺少参数: 协议"),
        ("add a b", "多余的参数: b"),
        ("del x y", "多余的参数: y"),
        ("render", "缺少参数: 类型"),
        ("nope", "未知命令: nope；请执行 onebox help"),
        ("frps bogus", "未知子命令: bogus；请执行 onebox frps --help"),
        ("frps info --dry-run", "此命令不支持 --dry-run"),
        ("add x --dry-run", "此命令不支持 --dry-run"),
        (
            "frps --json install",
            "frps install 不支持选项 --json；请执行 onebox frps install --help",
        ),
        (
            "frps info --mode web",
            "frps info 不支持选项 --mode；请执行 onebox frps info --help",
        ),
        ("subscription add", "缺少参数: 名称"),
        ("subscription a b", "多余的参数: b"),
        ("bbr enabel", "未知子命令: enabel；请执行 onebox bbr --help"),
        ("bbr info extra", "多余的参数: extra"),
    ] {
        assert_eq!(error(line), message, "{line}");
    }
    assert_eq!(
        parse(&COMMANDS, &[], Globals::default())
            .unwrap_err()
            .to_string(),
        "缺少命令；请执行 onebox help"
    );
}

#[test]
fn yes_only_in_flag_position() {
    assert!(matches("install -y --name x").assume_yes);
    assert!(matches("add vless --yes").assume_yes);
    assert!(matches("-y add vless").assume_yes);
    let m = matches("install --name -y");
    assert_eq!(m.value("name"), Some("-y"));
    assert!(!m.assume_yes, "an option value is never the global flag");
    let inv = parse_line("install --name -h").unwrap();
    assert_eq!(inv.matches.value("name"), Some("-h"));
    assert!(!inv.help);
}

#[test]
fn help_skips_validation() {
    for line in [
        "add --help",
        "add -h",
        "--help add",
        "frps install --help",
        "frps",
    ] {
        let inv = parse_line(line).unwrap_or_else(|e| panic!("{line}: {e}"));
        assert!(inv.help, "{line}");
    }
    // Unknown options are still errors.
    assert!(parse_line("add --bogus --help").is_err());
    let inv = parse_line("frps install -h").unwrap();
    assert_eq!(inv.chain.len(), 2);
    assert_eq!(inv.spec.name, "install");
}

#[test]
fn subcommands_and_aliases() {
    let inv = parse_line("frps install --dry-run --mode web").unwrap();
    assert!(!inv.help);
    assert_eq!(inv.matches.path, ["frps", "install"]);
    assert!(inv.matches.dry_run);
    assert_eq!(inv.matches.value("mode"), Some("web"));
    // Options valid for both levels may precede the subcommand.
    let m = matches("frps --json info");
    assert_eq!(m.path, ["frps", "info"]);
    assert!(m.flag("json"));
    assert_eq!(matches("frps logs").path, ["frps", "log"]);
    assert_eq!(matches("remove trojan").path, ["del"]);
    assert_eq!(matches("remove trojan").positional(0), Some("trojan"));
    // A command group with its own handler runs without subcommand…
    let inv = parse_line("sub").unwrap();
    assert!(!inv.help);
    assert_eq!(inv.matches.path, ["subscription"]);
    // …or takes an unknown first word as its own positional.
    assert_eq!(matches("subscribe legacy").positionals, ["legacy"]);
    let m = matches("subscription add 手机");
    assert_eq!(m.path, ["subscription", "add"]);
    assert_eq!(m.positional(0), Some("手机"));
    assert_eq!(
        matches("subscription enable --mode ip").value("mode"),
        Some("ip")
    );
}

#[test]
fn positional_edge_cases() {
    assert_eq!(matches("del -- --weird").positionals, ["--weird"]);
    assert_eq!(matches("backup -").positionals, ["-"]);
    assert_eq!(
        matches("render outbound vless-reality xray").positionals,
        ["outbound", "vless-reality", "xray"]
    );
    assert_eq!(matches("render server").positionals, ["server"]);
    assert!(matches("del").positionals.is_empty());
    // After `--` words are data: not -y, --help, a subcommand or `help`.
    let m = matches("subscription add -- -y");
    assert_eq!(
        (m.path.clone(), m.positionals.clone()),
        (vec!["subscription", "add"], vec!["-y".to_string()])
    );
    assert!(!m.assume_yes);
    let inv = parse_line("backup -- --help").unwrap();
    assert!(!inv.help);
    assert_eq!(inv.matches.positionals, ["--help"]);
    let m = matches("subscription -- enable");
    assert_eq!(m.path, ["subscription"], "no subcommand after --");
    assert_eq!(m.positionals, ["enable"]);
    assert_eq!(error("bbr -- help"), "多余的参数: help");
}

#[test]
fn leading_global_switches() {
    let args = argv("-y -h install -y");
    let (globals, rest) = leading_globals(&args);
    assert_eq!(
        globals,
        Globals {
            assume_yes: true,
            help: true
        }
    );
    assert_eq!(rest, ["install", "-y"]);
    let (globals, rest) = leading_globals(&[]);
    assert_eq!(globals, Globals::default());
    assert!(rest.is_empty());
}

#[test]
fn typed_accessors() {
    let m = matches("install --name abc --port vless-reality=443");
    assert_eq!(
        m.parse::<u16>("name").unwrap_err().to_string(),
        "--name 的值无效: abc"
    );
    assert_eq!(m.parse::<u16>("--protocols").unwrap(), None);
    let m = matches("add 8443");
    assert_eq!(m.parse_positional::<u16>(0, "端口").unwrap(), Some(8443));
    assert_eq!(m.parse_positional::<u16>(1, "端口").unwrap(), None);
    let m = matches("add x");
    assert_eq!(
        m.parse_positional::<u16>(0, "端口")
            .unwrap_err()
            .to_string(),
        "端口 无效: x"
    );
    assert_eq!(matches("frps install").command(), "frps install");
}

#[test]
fn root_policy_is_evaluated_on_the_leaf() {
    let inv = parse_line("frps info").unwrap();
    assert!(!inv.spec.root.required(&inv.matches));
    let inv = parse_line("frps install").unwrap();
    assert!(
        inv.spec.root.required(&inv.matches),
        "install defaults to Required"
    );
    let frps = find(&COMMANDS, "frps").unwrap();
    assert!(frps.root.required(&matches("frps install")));
    assert!(!frps.root.required(&matches("frps info")));
}

#[test]
fn spec_helpers() {
    let install = find(&COMMANDS, "install").unwrap();
    assert!(install.option("port").unwrap().repeat);
    assert!(install.option("port").unwrap().takes_value());
    assert!(!install.option("force").unwrap().takes_value());
    assert!(install.option("nope").is_none());
    assert!(find(&COMMANDS, "sub").unwrap().is_named("subscribe"));
    assert!(find(&COMMANDS, "render").unwrap().hidden);
    assert_eq!(Group::Diagnose.title(), "诊断");
    assert_eq!(
        Group::VISIBLE.map(Group::title),
        ["节点", "客户端", "服务", "功能", "诊断", "维护"]
    );
}

#[test]
fn help_word_under_command_groups() {
    // `frps help` shows the frps page (v2 form), `frps help install` the
    // subcommand's page.
    let inv = parse_line("frps help").unwrap();
    assert!(inv.help);
    assert_eq!(inv.chain.len(), 1);
    assert_eq!(inv.spec.name, "frps");
    let inv = parse_line("frps help install").unwrap();
    assert!(inv.help);
    assert_eq!(inv.matches.path, ["frps", "install"]);
    // Groups with their own handler and legacy positionals too.
    let inv = parse_line("sub help").unwrap();
    assert!(inv.help);
    assert_eq!(inv.matches.path, ["subscription"]);
    assert!(inv.matches.positionals.is_empty());
    // A declared `help` subcommand wins over the generic help.
    let inv = parse_line("bbr help").unwrap();
    assert!(!inv.help);
    assert_eq!(inv.matches.path, ["bbr", "help"]);
    assert_eq!(inv.spec.name, "help");
    // Commands without subcommands treat `help` as an ordinary word.
    assert_eq!(matches("del help").positionals, ["help"]);
    assert_eq!(error("add a help"), "多余的参数: help");
}

#[test]
fn group_with_default_action_runs_without_subcommand() {
    let inv = parse_line("bbr").unwrap();
    assert!(!inv.help);
    assert_eq!(inv.matches.path, ["bbr"]);
    assert_eq!(matches("bbr info").path, ["bbr", "info"]);
}
