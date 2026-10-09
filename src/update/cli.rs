//! Command specs and handlers: `update`, `update-script`, `update-check`,
//! `update-channel` (spec G §2.1, §2.8; COMPLETENESS G15, G16, G37). The
//! registry adds [`COMMANDS`]; menus dispatch fixed argv vectors to them.
//!
//! Root policy: `update` and `update-script` need root; `update-check` and
//! printing the channel do not; saving a channel does.
//!
//! Changes from v2: arity errors come from the shared parser (`多余的参数:
//! …` instead of `只接受一个更新渠道` / `用法: …`); `update-channel` without
//! an argument needs no root (G-8.1#16); `update` accepts `--force`
//! (downgrade or reinstall).

use super::channel::{self, Channel};
use super::cores::CoreSelection;
use crate::cli::args::{ArgSpec, CommandSpec, Group, Matches, OptSpec, Root};
use crate::ctx::Ctx;
use crate::error::Result;
use crate::ui::out;

const CHANNEL_ARG: ArgSpec = ArgSpec::optional("渠道", "stable / testing（默认使用已保存的渠道）");

/// `update [singbox|sing-box|xray|all] [版本] [--force]`.
pub const UPDATE: CommandSpec = CommandSpec::new("update", Group::Maintain, "更新正在使用的内核")
    .usage(&["update [singbox|sing-box|xray|all] [版本] [--force]"])
    .args(&[
        ArgSpec::optional(
            "内核",
            "singbox / sing-box / xray / all（默认：配置使用的全部内核）",
        ),
        ArgSpec::optional(
            "版本",
            "版本号或 latest；省略时 Xray 为 26.3.27、sing-box 为最新版，全部更新时沿用固定版本",
        ),
    ])
    .options(&[OptSpec::flag("force", "允许降级或重新安装相同版本")])
    .root(Root::Required)
    .handler(update_command);

/// `update-script [stable|testing]` (v2 name kept).
pub const UPDATE_SCRIPT: CommandSpec =
    CommandSpec::new("update-script", Group::Maintain, "更新 Onebox 程序")
        .usage(&["update-script [stable|testing]"])
        .args(&[CHANNEL_ARG])
        .root(Root::Required)
        .handler(update_script_command);

/// `update-check [stable|testing]`.
pub const UPDATE_CHECK: CommandSpec = CommandSpec::new(
    "update-check",
    Group::Maintain,
    "检查程序更新（不下载、不替换）",
)
.usage(&["update-check [stable|testing]"])
.args(&[CHANNEL_ARG])
.root(Root::NotRequired)
.handler(update_check_command);

/// `update-channel [stable|testing]`.
pub const UPDATE_CHANNEL: CommandSpec = CommandSpec::new(
    "update-channel",
    Group::Maintain,
    "查看或设置程序更新渠道",
)
.usage(&["update-channel [stable|testing]"])
.args(&[ArgSpec::optional("渠道", "stable / testing；省略时只显示")])
.root(Root::Custom(saves_channel))
.handler(update_channel_command);

/// Every update command, in help order.
pub const COMMANDS: [CommandSpec; 4] = [UPDATE, UPDATE_SCRIPT, UPDATE_CHECK, UPDATE_CHANNEL];

/// `update-channel` needs root only to save a channel.
fn saves_channel(m: &Matches) -> bool {
    m.positional(0).is_some()
}

/// The optional channel positional.
pub fn channel_arg(m: &Matches) -> Result<Option<Channel>> {
    m.positional(0).map(str::parse).transpose()
}

/// `update`'s positionals and flag: selection, version, `--force`.
pub fn core_args(m: &Matches) -> Result<(CoreSelection, Option<&str>, bool)> {
    let selection = CoreSelection::parse(m.positional(0))?;
    Ok((selection, m.positional(1), m.flag("force")))
}

fn update_command(ctx: &Ctx, m: &Matches) -> Result<()> {
    let (selection, version, force) = core_args(m)?;
    super::update_cores(ctx, selection, version, force)
}

fn update_script_command(ctx: &Ctx, m: &Matches) -> Result<()> {
    super::self_update(ctx, channel_arg(m)?, false)
}

fn update_check_command(ctx: &Ctx, m: &Matches) -> Result<()> {
    super::self_update(ctx, channel_arg(m)?, true)
}

fn update_channel_command(ctx: &Ctx, m: &Matches) -> Result<()> {
    out::data(&channel_command(ctx, channel_arg(m)?)?)
}

/// `update-channel [CH]`: save `CH` when given, then describe the channel
/// in effect.
pub fn channel_command(ctx: &Ctx, chosen: Option<Channel>) -> Result<String> {
    let current = match chosen {
        Some(ch) => {
            channel::save(&ctx.paths, ch)?;
            ch
        }
        None => channel::saved(&ctx.paths)?,
    };
    Ok(channel::describe(current))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::args::{parse, Globals};
    use crate::domain::protocol::Core;
    use crate::sys::fs::TempDir;

    fn words(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    fn matches(list: &[&str]) -> Result<Matches> {
        parse(&COMMANDS, &words(list), Globals::default()).map(|inv| inv.matches)
    }

    fn needs_root(list: &[&str]) -> bool {
        let inv = parse(&COMMANDS, &words(list), Globals::default()).unwrap();
        inv.spec.root.required(&inv.matches)
    }

    #[test]
    fn update_forms() {
        let cases: [(&[&str], CoreSelection, Option<&str>, bool); 6] = [
            (&["update"], CoreSelection::All, None, false),
            (&["update", "all", "latest"], CoreSelection::All, Some("latest"), false),
            (&["update", "singbox"], CoreSelection::One(Core::Singbox), None, false),
            (
                &["update", "sing-box", "1.14.2"],
                CoreSelection::One(Core::Singbox),
                Some("1.14.2"),
                false,
            ),
            (
                &["update", "xray", "26.3.27", "--force"],
                CoreSelection::One(Core::Xray),
                Some("26.3.27"),
                true,
            ),
            (
                &["update", "--force", "-y", "xray"],
                CoreSelection::One(Core::Xray),
                None,
                true,
            ),
        ];
        for (argv, selection, version, force) in cases {
            let m = matches(argv).unwrap();
            assert_eq!(core_args(&m).unwrap(), (selection, version, force), "{argv:?}");
            assert!(needs_root(argv), "{argv:?}");
        }
        let unknown = matches(&["update", "v2ray"]).unwrap();
        assert_eq!(core_args(&unknown).unwrap_err().to_string(), "未知内核");
        for (argv, message) in [
            (&["update", "xray", "1", "2"][..], "多余的参数: 2"),
            (
                &["update", "--dry-run"],
                "此命令不支持 --dry-run",
            ),
            (
                &["update-script", "--force"],
                "update-script 不支持选项 --force；请执行 onebox update-script --help",
            ),
            (&["update-check", "stable", "testing"], "多余的参数: testing"),
        ] {
            assert_eq!(matches(argv).unwrap_err().to_string(), message, "{argv:?}");
        }
    }

    #[test]
    fn channel_commands_and_root_policy() {
        assert!(needs_root(&["update-script"]));
        assert!(needs_root(&["update-script", "testing"]));
        assert!(!needs_root(&["update-check"]));
        assert!(!needs_root(&["update-check", "testing"]));
        assert!(!needs_root(&["update-channel"]));
        assert!(needs_root(&["update-channel", "stable"]));
        let m = matches(&["update-check", "testing"]).unwrap();
        assert_eq!(channel_arg(&m).unwrap(), Some(Channel::Testing));
        let m = matches(&["update-script"]).unwrap();
        assert_eq!(channel_arg(&m).unwrap(), None);
        let m = matches(&["update-channel", "beta"]).unwrap();
        assert_eq!(
            channel_arg(&m).unwrap_err().to_string(),
            "更新渠道仅支持 stable/testing"
        );
    }

    #[test]
    fn update_channel_prints_and_saves() {
        let dir = TempDir::new("update-cli").unwrap();
        let (ctx, _, _) = Ctx::test(dir.path());
        assert_eq!(channel_command(&ctx, None).unwrap(), "当前更新渠道: stable");
        assert!(!ctx.paths.update_channel().exists(), "printing writes nothing");
        assert_eq!(
            channel_command(&ctx, Some(Channel::Testing)).unwrap(),
            "当前更新渠道: testing"
        );
        assert_eq!(
            std::fs::read(ctx.paths.update_channel()).unwrap(),
            b"testing\n"
        );
        assert_eq!(channel_command(&ctx, None).unwrap(), "当前更新渠道: testing");
    }

    #[test]
    fn specs_are_registered_with_handlers() {
        let names: Vec<&str> = COMMANDS.iter().map(|c| c.name).collect();
        assert_eq!(
            names,
            ["update", "update-script", "update-check", "update-channel"]
        );
        assert!(COMMANDS.iter().all(|c| c.handler.is_some() && !c.hidden));
    }
}
