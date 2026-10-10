//! Table tests over the real command tree: names and aliases, accepted and
//! rejected options, root policy (bare groups on their default action,
//! G15), `--dry-run` gating, and help snapshots.

use super::*;
use crate::cli::args::Invocation;
use crate::cli::session::testing::Bench;

fn argv(line: &str) -> Vec<String> {
    line.split_whitespace().map(String::from).collect()
}

fn invoke(line: &str) -> Result<Invocation<'static>> {
    let words = argv(line);
    let (globals, rest) = args::leading_globals(&words);
    args::parse(COMMANDS, rest, globals)
}

fn root(line: &str) -> bool {
    let inv = invoke(line).unwrap_or_else(|e| panic!("{line}: {e}"));
    assert!(!inv.help, "{line} resolved to help");
    requires_root(inv.spec, &inv.matches)
}

#[test]
fn names_aliases_and_handlers() {
    let mut names: Vec<&str> = COMMANDS
        .iter()
        .flat_map(|c| std::iter::once(c.name).chain(c.aliases.iter().copied()))
        .collect();
    let total = names.len();
    names.sort_unstable();
    names.dedup();
    assert_eq!(names.len(), total, "duplicate command names");
    for spec in COMMANDS {
        assert!(spec.handler.is_some(), "{} has no handler", spec.name);
        for sub in spec.subcommands {
            assert!(
                sub.handler.is_some(),
                "{} {} has no handler",
                spec.name,
                sub.name
            );
        }
    }
    for (line, path) in [
        ("config links", &["client"][..]),
        ("remove trojan", &["del"]),
        ("logs xray", &["log"]),
        ("hop-apply", &["net-apply"]),
        ("boot", &["net-apply"]),
        ("cert status", &["cert", "info"]),
        ("site status", &["site", "info"]),
        ("cert-renew proxy --cron", &["cert-renew"]),
        ("tune hy2 auto", &["tune", "hy2"]),
        ("bbr status", &["bbr", "status"]),
        ("probe list x.json", &["probe", "list"]),
    ] {
        let inv = invoke(line).unwrap_or_else(|e| panic!("{line}: {e}"));
        assert_eq!(inv.matches.path, path, "{line}");
    }
}

#[test]
fn v2_command_names_are_registered() {
    // Every v2 command and alias (spec B §2.4), plus the new `renew` and
    // `boot`.
    for name in [
        "install",
        "plan",
        "add",
        "del",
        "remove",
        "port",
        "addr",
        "reset",
        "sni",
        "regen",
        "info",
        "client",
        "config",
        "qr",
        "site",
        "cert",
        "cert-renew",
        "bbr",
        "tune",
        "probe",
        "bench",
        "failover",
        "reality-check",
        "start",
        "stop",
        "restart",
        "status",
        "log",
        "logs",
        "service",
        "net-apply",
        "hop-apply",
        "hop-clear",
        "uninstall",
        "render",
        "version",
        "help",
        "renew",
        "boot",
        "subscription",
        "subscribe",
        "sub",
        "frps",
        "doctor",
        "support",
        "backup",
        "backups",
        "restore",
        "recover",
        "update",
        "update-script",
        "update-check",
        "update-channel",
    ] {
        assert!(find(COMMANDS, name).is_some(), "{name}");
    }
}

#[test]
fn root_policy_table() {
    for (line, expected) in [
        ("plan", false),
        ("plan --preset 2 --json", false),
        ("install", true),
        ("install --dry-run", false),
        ("install --dry-run --json", false),
        ("add trojan", true),
        ("del trojan", true),
        ("port trojan 8443", true),
        ("addr --addr 1.2.3.4", true),
        ("reset", true),
        ("sni --sni www.apple.com", true),
        ("regen", true),
        ("info", false),
        ("client", false),
        ("config links", false),
        ("qr", false),
        ("render", false),
        ("render outbound trojan xray", false),
        ("status", true),
        ("start", true),
        ("stop", true),
        ("restart", true),
        ("log", false),
        ("logs xray", false),
        // `service … status` needs root only without an init system
        // (checked when it runs).
        ("service onebox-site", false),
        ("service onebox-site status", false),
        ("service onebox-site log", false),
        ("service onebox-site restart", true),
        ("tune", true),
        ("tune status", true),
        ("tune hy2 auto", true),
        ("tune hy2 auto --apply", true),
        ("tune reset --apply", true),
        ("cert", false),
        ("cert info", false),
        ("cert set --tls self", true),
        ("cert renew", true),
        ("cert-renew site --cron", true),
        ("renew --cron", true),
        ("site", false),
        ("site info", false),
        ("site enable www.example.com", true),
        ("site preview", true),
        ("bbr", false),
        ("bbr status", false),
        ("bbr enable", true),
        ("bbr install --dry-run", false),
        ("probe list x.json", false),
        ("probe export x.json", true),
        ("bench p.json", false),
        ("reality-check", true),
        ("reality-check p.json", false),
        ("net-apply", true),
        ("boot", true),
        ("hop-clear", true),
        ("uninstall", true),
        ("version", false),
        ("help", false),
    ] {
        assert_eq!(root(line), expected, "{line}");
    }
}

#[test]
fn per_command_options() {
    for line in [
        "install --preset 1 --port vless-reality=443 --port tuic=8443 -y --force",
        "install -y --protocols trojan --tls cf --domain v.example.com",
        "add hysteria2 --hy2-hop 20000-30000 --hy2-obfs --port 8443",
        "add trojan --tls custom --domain a.example.com --cert c.pem --key k.pem",
        "addr --addr 1.2.3.4 --name hk",
        "sni --reality-site www.example.com --site-title 手记 --site-https off",
        "tune hy2 measured --up 20 --down 100 --apply",
        "cert set --tls cf --domain v.example.com",
        "site enable www.example.com --tls custom --cert a --key b",
        "site template docs --title 文档 --description 说明 --theme slate",
        "client mihomo --yes",
        "renew --cron",
    ] {
        invoke(line).unwrap_or_else(|e| panic!("{line}: {e}"));
    }
    for (line, message) in [
        (
            "addr --port 443",
            "addr 不支持选项 --port；请执行 onebox addr --help",
        ),
        (
            "sni --tls self",
            "sni 不支持选项 --tls；请执行 onebox sni --help",
        ),
        (
            "del trojan --core xray",
            "del 不支持选项 --core；请执行 onebox del --help",
        ),
        (
            "install --apply",
            "install 不支持选项 --apply；请执行 onebox install --help",
        ),
        (
            "tune resource balanced --up 1",
            "tune resource 不支持选项 --up；请执行 onebox tune resource --help",
        ),
        (
            "info --json",
            "info 不支持选项 --json；请执行 onebox info --help",
        ),
        ("add trojan --dry-run", "此命令不支持 --dry-run"),
        ("regen --dry-run", "此命令不支持 --dry-run"),
        ("site enable a.example.com --tls", "--tls 需要参数"),
        ("install --name a --name b", "重复选项: --name"),
        ("port a b c", "多余的参数: c"),
        ("cert renew a b", "多余的参数: b"),
        ("site bogus", "未知子命令: bogus；请执行 onebox site --help"),
    ] {
        match invoke(line) {
            Ok(inv) => panic!("{line}: parsed {:?}", inv.matches),
            Err(e) => assert_eq!(e.to_string(), message, "{line}"),
        }
    }
}

#[test]
fn bare_groups_run_their_default_action() {
    for line in ["cert", "site", "tune", "bbr", "render", "probe"] {
        let inv = invoke(line).unwrap();
        assert!(!inv.help, "{line} keeps its v2 default action");
        assert!(inv.spec.handler.is_some());
    }
    for line in ["cert help", "site help", "tune --help", "install -h"] {
        assert!(invoke(line).unwrap().help, "{line}");
    }
}

#[test]
fn global_help_snapshot() {
    let text = help::global_help(COMMANDS);
    let expected = format!(
        "Onebox {} — sing-box / Xray 一键管理

用法: onebox [命令] [选项]
      不带参数运行 onebox 打开交互菜单

节点:
  install         安装节点（交互向导，或 -y 无人值守）
  plan            只读安装预演（不写文件、不联网、不申请证书）
  add             添加协议（自动分配端口，需要时准备证书）
  del             删除协议（至少保留一个）
  port            修改协议端口
  addr            修改客户端连接地址与节点名称
  sni             更换 REALITY / ShadowTLS 伪装目标（凭据不变）
  reset           重置全部 UUID、密码与密钥（客户端需重新导入）
  tune            Hysteria2 与资源调优（默认只预览）

客户端:
  info            节点信息、凭据与导出方式
  client          导出客户端配置到标准输出（另见 qr）
  qr              在终端显示分享链接二维码

服务:
  status          代理内核运行状态
  start           启动代理内核
  stop            停止代理内核
  restart         重启代理内核
  log             代理内核日志（最近 200 行）
  service         单独控制某个 Onebox 服务

功能:
  site            自有域名 REALITY 网站
  cert            代理、网站与订阅证书
  subscription    远程订阅：按设备授权的客户端配置 URL
  bbr             TCP BBR 与 BBRv3 内核
  frps            独立 FRP 服务端

诊断:
  doctor          体检：内核、配置、服务、证书、网站、订阅、FRP 与未完成事务
  support         生成脱敏诊断文件（不含凭据、IP 地址和域名，不会自动上传）
  probe           导出、查看或合并链路测试用的探测配置
  bench           经临时客户端内核测试真实链路的延迟、吞吐与资源占用
  failover        本机 SOCKS5 故障切换（TCP CONNECT；既有连接不迁移；Ctrl+C 结束）
  reality-check   检查 REALITY 回落与参考站点的一致性及错误 short ID 的拒绝

维护:
  regen           按当前状态重新生成并应用全部配置（凭据不变；也用于从 v2 迁移）
  renew           立即强制续期全部证书（计划任务每天执行 renew --cron，只续期 30 天内到期的）
  backup          备份当前配置
  backups         列出备份
  restore         恢复备份
  recover         回滚中断的配置事务与自更新
  update          更新正在使用的内核
  update-script   更新 Onebox 程序
  update-check    检查程序更新（不下载、不替换）
  update-channel  查看或设置程序更新渠道
  uninstall       卸载代理节点（保留网站内容、快照与 FRP）
  version         显示程序版本
  help            显示帮助

通用选项: -y/--yes 无人值守（使用默认值并自动确认）  -h/--help 显示帮助
查看命令说明: onebox help 命令，或 onebox 命令 --help",
        crate::VERSION
    );
    assert_eq!(text, expected);
}

#[test]
fn command_help_snapshots() {
    let page = |words: &[&str]| {
        let words: Vec<String> = words.iter().map(|w| w.to_string()).collect();
        help::command_help(&resolve_chain(COMMANDS, &words).unwrap())
    };
    assert_eq!(
        page(&["tune"]),
        "Hysteria2 与资源调优（默认只预览）

用法:
  onebox tune [status]
  onebox tune hy2 auto|conservative|measured [--up N --down N] [--apply]
  onebox tune hy2 [档位] [--obfs on|off] [--hop 起-止|off] [--apply]
  onebox tune resource balanced|low-memory|throughput [--apply]
  onebox tune reset [--apply]

子命令:
  status    当前调优设置
  hy2       Hysteria2 拥塞与带宽档位、混淆与端口跳跃
  resource  QUIC 接收窗口与并发流档位
  reset     恢复默认调优

通用选项: -y/--yes 无人值守（使用默认值并自动确认）  -h/--help 显示帮助"
    );
    assert_eq!(
        page(&["service"]),
        "单独控制某个 Onebox 服务

用法:
  onebox service 服务名 [start|stop|restart|enable|disable|remove|status|log]

参数:
  服务名  onebox-…，如 onebox-site
  操作    默认 status

通用选项: -y/--yes 无人值守（使用默认值并自动确认）  -h/--help 显示帮助"
    );
    let install = page(&["install"]);
    assert!(
        install.contains("  --force                        已安装时允许 -y 重装"),
        "{install}"
    );
    assert!(install.ends_with("  --dry-run                      仅预览，不做任何修改\n\n通用选项: -y/--yes 无人值守（使用默认值并自动确认）  -h/--help 显示帮助"));
    let del = page(&["del"]);
    assert!(del.contains("别名: remove"));
    assert!(!help::global_help(COMMANDS).contains("render"), "hidden");
}

#[test]
fn dispatch_applies_the_root_policy() {
    let bench = Bench::new();
    dispatch(COMMANDS, &bench.ctx, &["version"], false).unwrap();
    dispatch(COMMANDS, &bench.ctx, &["site", "--help"], false).unwrap();
    let err = dispatch(COMMANDS, &bench.ctx, &["uninstall"], false).unwrap_err();
    assert_eq!(err.to_string(), "此操作需要 root 权限");
    let err = dispatch(COMMANDS, &bench.ctx, &["nope"], true).unwrap_err();
    assert_eq!(err.to_string(), "未知命令: nope；请执行 onebox help");
    for feature in ["subscription", "frps", "doctor", "support"] {
        dispatch(COMMANDS, &bench.ctx, &[feature, "--help"], false).unwrap();
    }
    for diagnose in ["doctor", "support"] {
        let err = dispatch(COMMANDS, &bench.ctx, &[diagnose], false).unwrap_err();
        assert_eq!(err.to_string(), "此操作需要 root 权限", "{diagnose}");
    }
    let err = dispatch(COMMANDS, &bench.ctx, &["probe"], false).unwrap_err();
    assert_eq!(err.to_string(), crate::linktools::cli::PROBE_USAGE);
}
