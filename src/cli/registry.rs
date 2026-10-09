//! The command registry: the static command tree, root policy, dispatch
//! of fixed command lines (menus) and the few built-in commands that run
//! without a context.
//!
//! Feature modules contribute their own `const` [`CommandSpec`]s; adding a
//! command means appending it to [`COMMANDS`] (order = help order within
//! each group). The commands of the wave-C modules are added at the marked
//! place; the menus already reach them through [`dispatch`].

use super::args::{self, find, ArgSpec, CommandSpec, Globals, Group, Matches, Root};
use super::commands::{
    cert, client, connection, info, install, node, service, site, tune, uninstall,
};
use super::help;
use crate::ctx::Ctx;
use crate::error::{Error, Result};
use crate::ui::out;

/// Every top-level command.
pub static COMMANDS: &[CommandSpec] = &[
    // 节点
    install::INSTALL,
    install::PLAN,
    node::ADD,
    node::DEL,
    node::PORT,
    connection::ADDR,
    connection::SNI,
    node::RESET,
    tune::TUNE,
    // 客户端
    info::INFO,
    client::CLIENT,
    client::QR,
    // 服务
    service::STATUS,
    service::START,
    service::STOP,
    service::RESTART,
    service::LOG,
    service::SERVICE,
    // 功能
    site::SITE,
    cert::CERT,
    crate::bbr::COMMAND,
    // 诊断
    crate::linktools::PROBE,
    crate::linktools::BENCH,
    crate::linktools::FAILOVER,
    crate::linktools::REALITY_CHECK,
    // 维护
    node::REGEN,
    cert::RENEW,
    uninstall::UNINSTALL,
    VERSION,
    HELP,
    // 隐藏（兼容入口与内部入口）
    cert::CERT_RENEW,
    service::NET_APPLY,
    service::HOP_CLEAR,
    client::RENDER,
    // wave C modules: subscription, frps, update, update-script, update-check, update-channel, doctor, support, backup, backups, restore, recover
    // …and, with the backup module, set UNINSTALL_BACKUP (below) to crate::backup::create_locked.
];

const VERSION: CommandSpec = CommandSpec::new("version", Group::Maintain, "显示程序版本")
    .root(Root::NotRequired)
    .handler(version_command);

const HELP: CommandSpec = CommandSpec::new("help", Group::Maintain, "显示帮助")
    .usage(&["help [命令 [子命令]]"])
    .args(&[ArgSpec::optional("命令", "要查看说明的命令及子命令").many()])
    .root(Root::NotRequired)
    .handler(help_command);

/// The backup `uninstall` takes under the node lock (G11). The second
/// wave-C integration point (see the marked list above): set it to
/// `crate::backup::create_locked`; until then uninstall refuses to remove
/// anything without a backup. A test fails once the backup module provides
/// `create_locked` while this is still unwired.
pub const UNINSTALL_BACKUP: uninstall::BackupHook = backup_not_wired;

const BACKUP_NOT_WIRED: &str = "备份模块尚未接入，无法在卸载前保存快照；已中止卸载";

fn backup_not_wired(
    _ctx: &Ctx,
    _lock: &crate::sys::lock::FileLock,
    _label: &str,
) -> Result<String> {
    Err(Error::msg(BACKUP_NOT_WIRED))
}

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
/// fail because of an invalid `ONEBOX_*` path override. Matched on the
/// canonical command path, so a feature module's own `help` or `version`
/// subcommand (e.g. `frps help`) is never taken over.
pub fn builtin(matches: &Matches) -> Option<Result<()>> {
    match matches.path.as_slice() {
        ["version"] => Some(print_version()),
        ["help"] => Some(print_help(&matches.positionals)),
        _ => None,
    }
}

/// Run a fixed command line (`argv[0]` = command word) through `commands`
/// with its root policy, as the menus do. `-y` follows the context.
pub fn dispatch(commands: &[CommandSpec], ctx: &Ctx, argv: &[&str], is_root: bool) -> Result<()> {
    let words: Vec<String> = argv.iter().map(|w| w.to_string()).collect();
    let globals = Globals {
        assume_yes: ctx.ui.assume_yes(),
        help: false,
    };
    let invocation = args::parse(commands, &words, globals)?;
    if invocation.help {
        return out::data(&help::command_help(&invocation.chain));
    }
    let spec = invocation.spec;
    let handler = spec
        .handler
        .ok_or_else(|| Error::msg(format!("命令尚未实现: {}", invocation.matches.command())))?;
    if requires_root(spec, &invocation.matches) && !is_root {
        return Err(Error::msg("此操作需要 root 权限"));
    }
    handler(ctx, &invocation.matches)
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
mod spec_tests;
#[cfg(test)]
mod tests;
