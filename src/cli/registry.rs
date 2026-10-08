//! The command registry: the static command tree, root policy and the few
//! built-in commands that run without a context.
//!
//! Feature modules contribute their own `static` [`CommandSpec`]s; adding a
//! command means appending it to [`COMMANDS`] (order = help order within
//! each group).

use super::args::{find, ArgSpec, CommandSpec, Group, Matches, Root};
use super::help;
use crate::ctx::Ctx;
use crate::error::{Error, Result};
use crate::ui::out;

/// Every top-level command.
pub static COMMANDS: &[CommandSpec] = &[VERSION, HELP];

const VERSION: CommandSpec = CommandSpec::new("version", Group::Maintain, "显示程序版本")
    .root(Root::NotRequired)
    .handler(version_command);

const HELP: CommandSpec = CommandSpec::new("help", Group::Maintain, "显示帮助")
    .usage(&["help [命令 [子命令]]"])
    .args(&[ArgSpec::optional("命令", "要查看说明的命令及子命令").many()])
    .root(Root::NotRequired)
    .handler(help_command);

/// Whether the resolved command needs root for these matches.
pub fn requires_root(spec: &CommandSpec, matches: &Matches) -> bool {
    spec.root.required(matches)
}

/// Fail unless running as root.
pub fn require_root() -> Result<()> {
    if crate::sys::process::is_root() {
        Ok(())
    } else {
        Err(Error::msg("此操作需要 root 权限"))
    }
}

/// Commands that must work without a context: `version` is run by v2's
/// self-update to verify a new binary, and neither it nor `help` should
/// fail because of an invalid `ONEBOX_*` path override.
pub fn builtin(spec: &CommandSpec, matches: &Matches) -> Option<Result<()>> {
    match spec.name {
        "version" => Some(print_version()),
        "help" => Some(print_help(&matches.positionals)),
        _ => None,
    }
}

/// `onebox` without arguments. The interactive menu lands in a later work
/// package; until then the overview is shown.
pub fn menu(_assume_yes: bool) -> Result<()> {
    out::data(&help::global_help(COMMANDS))
}

/// `version` prints exactly the version (v2 parents compare it verbatim).
pub fn print_version() -> Result<()> {
    out::data(crate::VERSION)
}

/// `help [command [subcommand…]]`.
pub fn print_help(words: &[String]) -> Result<()> {
    if words.is_empty() {
        return out::data(&help::global_help(COMMANDS));
    }
    let chain = resolve_chain(COMMANDS, words)?;
    out::data(&help::command_help(&chain))
}

/// Look up `words` as a command path (names or aliases).
pub fn resolve_chain<'a>(
    commands: &'a [CommandSpec],
    words: &[String],
) -> Result<Vec<&'a CommandSpec>> {
    let Some((first, rest)) = words.split_first() else {
        return Ok(Vec::new());
    };
    let mut spec = find(commands, first)
        .ok_or_else(|| Error::msg(format!("未知命令: {first}；请执行 onebox help")))?;
    let mut chain = vec![spec];
    for word in rest {
        let path = chain.iter().map(|c| c.name).collect::<Vec<_>>().join(" ");
        spec = spec.subcommand(word).ok_or_else(|| {
            Error::msg(format!("未知子命令: {word}；请执行 onebox {path} --help"))
        })?;
        chain.push(spec);
    }
    Ok(chain)
}

fn version_command(_ctx: &Ctx, _matches: &Matches) -> Result<()> {
    print_version()
}

fn help_command(_ctx: &Ctx, matches: &Matches) -> Result<()> {
    print_help(&matches.positionals)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn words(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn registry_names_are_unique() {
        let mut names: Vec<&str> = COMMANDS
            .iter()
            .flat_map(|c| std::iter::once(c.name).chain(c.aliases.iter().copied()))
            .collect();
        let total = names.len();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), total);
    }

    #[test]
    fn builtins_need_no_root_or_context() {
        for name in ["version", "help"] {
            let spec = find(COMMANDS, name).unwrap();
            assert!(!requires_root(spec, &Matches::default()));
            assert!(builtin(spec, &Matches::default()).is_some());
            assert!(spec.handler.is_some());
        }
    }

    #[test]
    fn chain_resolution() {
        let chain = resolve_chain(COMMANDS, &words(&["help"])).unwrap();
        assert_eq!(chain[0].name, "help");
        assert_eq!(
            resolve_chain(COMMANDS, &words(&["nope"]))
                .unwrap_err()
                .to_string(),
            "未知命令: nope；请执行 onebox help"
        );
        assert_eq!(
            resolve_chain(COMMANDS, &words(&["version", "x"]))
                .unwrap_err()
                .to_string(),
            "未知子命令: x；请执行 onebox version --help"
        );
        assert!(resolve_chain(COMMANDS, &[]).unwrap().is_empty());
    }

    #[test]
    fn root_policy_variants() {
        fn needs_root_with_apply(m: &Matches) -> bool {
            m.flag("apply")
        }
        let spec =
            CommandSpec::new("tune", Group::Node, "调优").root(Root::Custom(needs_root_with_apply));
        let mut matches = Matches::default();
        assert!(!requires_root(&spec, &matches));
        matches.flags.push("apply");
        assert!(requires_root(&spec, &matches));
        let default = CommandSpec::new("install", Group::Node, "安装");
        assert!(
            requires_root(&default, &Matches::default()),
            "root by default"
        );
        let check = require_root();
        assert_eq!(check.is_ok(), crate::sys::process::is_root());
        if let Err(e) = check {
            assert_eq!(e.to_string(), "此操作需要 root 权限");
        }
    }
}
