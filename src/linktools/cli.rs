//! Command specs and handlers of `probe`, `bench`, `failover` and
//! `reality-check`; the CLI registry only lists [`COMMANDS`].
//!
//! Root policy: only `probe export` and the server-local `reality-check`
//! (no bundle) read the node state and require root; everything else works
//! on a client machine (v2 never checked root, so those two failed with a
//! permission error instead).
//!
//! Changes from v2: per-command `--help` (v2's tool help was unreachable,
//! D-8.1#1); options a tool does not take, repeated options and stray
//! positionals are rejected by the shared parser with its messages
//! (`bench 不支持选项 --port`, `重复选项: --url`, `多余的参数: x`) instead of
//! `未知或不适用的参数`; a bare `probe` is the usage error, as in v2.

use super::bundle;
use super::options::{self as o, BenchOptions, FailoverOptions, RealityOptions};
use crate::cli::args::{ArgSpec, CommandSpec, Group, Matches, OptSpec, Root};
use crate::ctx::Ctx;
use crate::error::{Error, Result};
use crate::ui::out;
use std::path::Path;

pub const PROBE_USAGE: &str =
    "用法: onebox probe export <新文件> | list <配置> | merge <新文件> <配置...>";

const ENTRIES: OptSpec = OptSpec::value(
    o::ENTRIES,
    "ID,ID",
    "按优先级选择入口，逗号分隔（ID 见 probe list）",
);
const SINGBOX: OptSpec = OptSpec::value(o::SINGBOX, "路径", "客户端 sing-box 程序");
const XRAY: OptSpec = OptSpec::value(o::XRAY, "路径", "客户端 Xray 程序");
const URL: OptSpec = OptSpec::value(
    o::URL,
    "URL",
    "健康检测地址，应返回 2xx，不跟随跳转（默认 https://www.gstatic.com/generate_204）",
);
const TIMEOUT: OptSpec = OptSpec::value(o::TIMEOUT, "秒", "连接与请求超时 1..60（默认 8）");
const CA: OptSpec = OptSpec::value(o::CA, "文件", "自有 CA 证书");
const OUTPUT: OptSpec =
    OptSpec::value(o::OUTPUT, "新文件", "同时保存报告（不可已存在，权限 0600）");
const SAMPLES: OptSpec = OptSpec::value(o::SAMPLES, "次数", "健康检测次数 1..20（默认 5）");
const DOWNLOAD_URL: OptSpec = OptSpec::value(
    o::DOWNLOAD_URL,
    "URL",
    "下载测速地址（仅在指定时执行，读取至多 --bytes 字节）",
);
const UPLOAD_URL: OptSpec = OptSpec::value(
    o::UPLOAD_URL,
    "URL",
    "已授权的上传测速地址（仅在指定时执行，POST --bytes 随机字节）",
);
const BYTES: OptSpec = OptSpec::value(
    o::BYTES,
    "字节",
    "传输字节数 1024..67108864（默认 4194304）",
);
const PORT: OptSpec = OptSpec::value(
    o::PORT,
    "端口",
    "本机 SOCKS5 端口 1024..65535（默认 2080，仅监听 127.0.0.1）",
);
const INTERVAL: OptSpec = OptSpec::value(o::INTERVAL, "秒", "健康检测间隔 1..3600（默认 15）");
const FAILURES: OptSpec = OptSpec::value(o::FAILURES, "次数", "切换前连续失败次数 1..20（默认 3）");
const RECOVERIES: OptSpec =
    OptSpec::value(o::RECOVERIES, "次数", "恢复前连续成功次数 1..20（默认 3）");
const COOLDOWN: OptSpec = OptSpec::value(
    o::COOLDOWN,
    "秒",
    "切回高优先级入口前的冷却期 0..3600（默认 60）",
);
const SCOPE: OptSpec = OptSpec::value(
    o::SCOPE,
    "范围",
    "server-local | current-machine-to-server（报告中的检查范围）",
);

const BUNDLE_ARG: ArgSpec = ArgSpec::required("probe.json", "probe export 导出的探测配置");

const EXPORT: CommandSpec = CommandSpec::new(
    "export",
    Group::Diagnose,
    "导出本机节点的探测配置（含客户端凭据，请私密传输）",
)
.args(&[ArgSpec::required("新文件", "不可已存在；权限 0600")])
.root(Root::Required)
.handler(probe_export);

const LIST: CommandSpec = CommandSpec::new("list", Group::Diagnose, "列出探测配置的入口")
    .args(&[ArgSpec::required("配置", "探测配置文件")])
    .root(Root::NotRequired)
    .handler(probe_list);

const MERGE: CommandSpec = CommandSpec::new(
    "merge",
    Group::Diagnose,
    "合并多台服务器的探测配置（入口 ID 加前缀 n1-、n2-…）",
)
.args(&[
    ArgSpec::required("新文件", "不可已存在；权限 0600"),
    ArgSpec::required("配置", "至少两份探测配置，按优先级排列").many(),
])
.root(Root::NotRequired)
.handler(probe_merge);

pub const PROBE: CommandSpec = CommandSpec::new(
    "probe",
    Group::Diagnose,
    "导出、查看或合并链路测试用的探测配置",
)
.usage(&[
    "probe export <新文件>",
    "probe list <配置>",
    "probe merge <新文件> <配置...>",
])
.subcommands(&[EXPORT, LIST, MERGE])
.root(Root::NotRequired)
.handler(probe_usage);

pub const BENCH: CommandSpec = CommandSpec::new(
    "bench",
    Group::Diagnose,
    "经临时客户端内核测试真实链路的延迟、吞吐与资源占用",
)
.usage(&["bench <probe.json> [选项]"])
.args(&[BUNDLE_ARG])
.options(&[
    ENTRIES,
    SINGBOX,
    XRAY,
    URL,
    TIMEOUT,
    CA,
    OUTPUT,
    SAMPLES,
    DOWNLOAD_URL,
    UPLOAD_URL,
    BYTES,
])
.root(Root::NotRequired)
.handler(bench_command);

pub const FAILOVER: CommandSpec = CommandSpec::new(
    "failover",
    Group::Diagnose,
    "本机 SOCKS5 故障切换（TCP CONNECT；既有连接不迁移；Ctrl+C 结束）",
)
.usage(&["failover <probe.json> [选项]"])
.args(&[BUNDLE_ARG])
.options(&[
    ENTRIES, SINGBOX, XRAY, URL, TIMEOUT, CA, PORT, INTERVAL, FAILURES, RECOVERIES, COOLDOWN,
])
.root(Root::NotRequired)
.handler(failover_command);

pub const REALITY_CHECK: CommandSpec = CommandSpec::new(
    "reality-check",
    Group::Diagnose,
    "检查 REALITY 回落与参考站点的一致性及错误 short ID 的拒绝",
)
.usage(&["reality-check [probe.json] [选项]"])
.args(&[ArgSpec::optional(
    "probe.json",
    "探测配置；省略时读取本机状态并使用回环地址（需 root）",
)])
.options(&[ENTRIES, SINGBOX, XRAY, URL, TIMEOUT, CA, OUTPUT, SCOPE])
.root(Root::Custom(server_local))
.handler(reality_command);

/// The link-tool commands, in help order.
pub const COMMANDS: [CommandSpec; 4] = [PROBE, BENCH, FAILOVER, REALITY_CHECK];

/// Server-local `reality-check` reads the node state.
fn server_local(m: &Matches) -> bool {
    m.positional(0).is_none()
}

fn probe_usage(_ctx: &Ctx, _m: &Matches) -> Result<()> {
    Err(Error::msg(PROBE_USAGE))
}

fn positional(m: &Matches, index: usize) -> Result<&str> {
    m.positional(index).ok_or_else(|| Error::msg(PROBE_USAGE))
}

fn probe_export(ctx: &Ctx, m: &Matches) -> Result<()> {
    let target = positional(m, 0)?;
    let bundle = bundle::from_node(ctx, false)?;
    bundle::write_bundle(Path::new(target), &bundle)?;
    out::data(&format!("已导出: {target}（含客户端凭据，请私密传输）"))
}

fn probe_list(_ctx: &Ctx, m: &Matches) -> Result<()> {
    let bundle = bundle::load(Path::new(positional(m, 0)?))?;
    out::data(&bundle::list_lines(&bundle).join("\n"))
}

fn probe_merge(_ctx: &Ctx, m: &Matches) -> Result<()> {
    let target = positional(m, 0)?;
    let inputs = m.positionals[1..]
        .iter()
        .map(|path| bundle::load(Path::new(path)))
        .collect::<Result<Vec<_>>>()?;
    let merged = bundle::merge(&inputs)?;
    bundle::write_bundle(Path::new(target), &merged)?;
    out::data(&format!("已合并到 {target}"))
}

fn bench_command(ctx: &Ctx, m: &Matches) -> Result<()> {
    super::bench::run(ctx, &BenchOptions::from_matches(m)?)
}

fn failover_command(ctx: &Ctx, m: &Matches) -> Result<()> {
    super::failover::run(ctx, &FailoverOptions::from_matches(m)?)
}

fn reality_command(ctx: &Ctx, m: &Matches) -> Result<()> {
    super::reality::run(ctx, &RealityOptions::from_matches(m)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::args::{parse, Globals};
    use crate::cli::help::command_help;
    use crate::domain::protocol::{Core, Transport};
    use crate::linktools::testutil::{bundle as fixture, entry};
    use crate::sys::fs::TempDir;
    use std::fs;

    fn words(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    fn invoke(ctx: &Ctx, argv: &[&str]) -> Result<()> {
        let inv = parse(&COMMANDS, &words(argv), Globals::default())?;
        let handler = inv.spec.handler.ok_or_else(|| Error::msg("no handler"))?;
        handler(ctx, &inv.matches)
    }

    fn root_needed(argv: &[&str]) -> bool {
        let inv = parse(&COMMANDS, &words(argv), Globals::default()).unwrap();
        inv.spec.root.required(&inv.matches)
    }

    #[test]
    fn root_is_needed_only_to_read_the_node_state() {
        assert!(root_needed(&["probe", "export", "x.json"]));
        assert!(!root_needed(&["probe", "list", "x.json"]));
        assert!(!root_needed(&[
            "probe", "merge", "o.json", "a.json", "b.json"
        ]));
        assert!(!root_needed(&["bench", "p.json"]));
        assert!(!root_needed(&["failover", "p.json", "--port", "3000"]));
        assert!(!root_needed(&["reality-check", "p.json"]));
        assert!(root_needed(&["reality-check", "--timeout", "5"]));
    }

    #[test]
    fn options_are_per_tool() {
        let dir = TempDir::new("linktools-test").unwrap();
        let (ctx, _, _) = Ctx::test(dir.path());
        let cases = [
            (
                &["bench", "p", "--port", "3000"][..],
                "bench 不支持选项 --port；请执行 onebox bench --help",
            ),
            (
                &["failover", "p", "--output", "r"],
                "failover 不支持选项 --output；请执行 onebox failover --help",
            ),
            (
                &["reality-check", "--samples", "3"],
                "reality-check 不支持选项 --samples；请执行 onebox reality-check --help",
            ),
            (&["bench", "p", "q"], "多余的参数: q"),
            (&["bench"], "缺少参数: probe.json"),
            (
                &["bench", "p", "--url", "https://a/", "--url", "https://b/"],
                "重复选项: --url",
            ),
            (&["bench", "p", "--timeout"], "--timeout 需要参数"),
            (&["probe"], PROBE_USAGE),
            (
                &["probe", "show"],
                "未知子命令: show；请执行 onebox probe --help",
            ),
            (&["probe", "merge", "o"], "缺少参数: 配置"),
            (
                &["bench", "p", "--timeout", "0"],
                "--timeout 必须是 1..60 之间的整数",
            ),
        ];
        for (argv, message) in cases {
            let err = invoke(&ctx, argv).unwrap_err();
            assert_eq!(err.to_string(), message, "{argv:?}");
        }
    }

    #[test]
    fn help_pages_exist_for_every_tool() {
        for argv in [
            &["bench", "--help"][..],
            &["probe", "--help"],
            &["probe", "merge", "-h"],
        ] {
            let inv = parse(&COMMANDS, &words(argv), Globals::default()).unwrap();
            assert!(inv.help, "{argv:?}");
            let page = command_help(&inv.chain);
            assert!(page.contains("用法:"), "{page}");
        }
        let inv = parse(
            &COMMANDS,
            &words(&["failover", "--help"]),
            Globals::default(),
        )
        .unwrap();
        let page = command_help(&inv.chain);
        for flag in [
            "--port 端口",
            "--interval 秒",
            "--failures 次数",
            "--recoveries 次数",
            "--cooldown 秒",
        ] {
            assert!(page.contains(flag), "{flag} in {page}");
        }
    }

    #[test]
    fn probe_list_and_merge_work_on_files() {
        let dir = TempDir::new("linktools-test").unwrap();
        let (ctx, _, _) = Ctx::test(dir.path());
        let a = dir.join("a.json");
        let b = dir.join("b.json");
        bundle::write_bundle(
            &a,
            &fixture(vec![entry("vless-reality", Core::Singbox, Transport::Tcp)]),
        )
        .unwrap();
        bundle::write_bundle(
            &b,
            &fixture(vec![entry("hysteria2", Core::Singbox, Transport::Udp)]),
        )
        .unwrap();
        let path = |p: &std::path::Path| p.to_str().unwrap().to_owned();
        invoke(&ctx, &["probe", "list", &path(&a)]).unwrap();
        let merged = dir.join("all.json");
        invoke(
            &ctx,
            &["probe", "merge", &path(&merged), &path(&a), &path(&b)],
        )
        .unwrap();
        let text = fs::read_to_string(&merged).unwrap();
        assert!(text.contains("\"n1-vless-reality\"") && text.contains("\"n2-hysteria2\""));
        let err = invoke(
            &ctx,
            &["probe", "merge", &path(&merged), &path(&a), &path(&b)],
        )
        .unwrap_err();
        assert!(err.to_string().starts_with("目标已存在"), "{err}");
        let err = invoke(
            &ctx,
            &["probe", "merge", &path(&dir.join("one.json")), &path(&a)],
        )
        .unwrap_err();
        assert_eq!(err.to_string(), "probe merge 至少需要两份探测配置");
        let err = invoke(&ctx, &["probe", "export", &path(&dir.join("e.json"))]).unwrap_err();
        assert_eq!(err.to_string(), "尚未安装 Onebox，请先执行 onebox install");
        assert!(!dir.join("e.json").exists());
    }
}
