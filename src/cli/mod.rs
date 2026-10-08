//! Command line: declarative argument parsing, command registry, help,
//! interactive menus and wizards.
//!
//! Dispatch order: UTF-8 check → leading `-y`/`--help` → no arguments opens
//! the menu → `--version`/`-V` → parse against the registry → help pages and
//! context-free built-ins → `Ctx::system` → root policy → handler.

pub mod args;
pub mod help;
pub mod registry;

use crate::ctx::Ctx;
use crate::error::{Error, Result};
use std::ffi::OsString;

/// Entry point used by `main`.
pub fn run(args: Vec<OsString>) -> Result<()> {
    let args = utf8_args(args)?;
    let auto = auto_from_env(std::env::var_os("ONEBOX_AUTO").as_deref());
    let (globals, rest) = args::leading_globals(&args);
    let Some(first) = rest.first() else {
        return if globals.help {
            registry::print_help(&[])
        } else {
            registry::menu(globals.assume_yes || auto)
        };
    };
    if matches!(first.as_str(), "--version" | "-V") {
        return registry::print_version();
    }
    let mut invocation = args::parse(registry::COMMANDS, rest, globals)?;
    if invocation.help {
        return crate::ui::out::data(&help::command_help(&invocation.chain));
    }
    invocation.matches.assume_yes |= auto;
    let spec = invocation.spec;
    if let Some(result) = registry::builtin(&invocation.matches) {
        return result;
    }
    let handler = spec
        .handler
        .ok_or_else(|| Error::msg(format!("命令尚未实现: {}", invocation.matches.command())))?;
    let ctx = Ctx::system(invocation.matches.assume_yes)?;
    if registry::requires_root(spec, &invocation.matches) {
        registry::require_root()?;
    }
    handler(&ctx, &invocation.matches)
}

/// argv must be UTF-8 (v2 panicked on anything else).
fn utf8_args(args: Vec<OsString>) -> Result<Vec<String>> {
    args.into_iter()
        .map(|a| a.into_string().map_err(|_| Error::msg("参数必须是 UTF-8")))
        .collect()
}

/// `ONEBOX_AUTO=1` (exactly) means `-y`.
fn auto_from_env(value: Option<&std::ffi::OsStr>) -> bool {
    value.is_some_and(|v| v == "1")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::ffi::OsStringExt;

    fn os(list: &[&str]) -> Vec<OsString> {
        list.iter().map(OsString::from).collect()
    }

    #[test]
    fn non_utf8_arguments_are_rejected() {
        let err = run(vec![OsString::from_vec(vec![0xff, 0xfe])]).unwrap_err();
        assert_eq!(err.to_string(), "参数必须是 UTF-8");
    }

    #[test]
    fn auto_env_must_be_exactly_one() {
        assert!(auto_from_env(Some("1".as_ref())));
        assert!(!auto_from_env(Some("true".as_ref())));
        assert!(!auto_from_env(Some("".as_ref())));
        assert!(!auto_from_env(None));
    }

    #[test]
    fn builtins_and_help_dispatch() {
        for argv in [
            &["version"][..],
            &["-V"],
            &["--version"],
            &["-y", "version"],
            &["help"],
            &["help", "version"],
            &["--help"],
            &["-h", "help"],
            &["version", "--help"],
            &[],
        ] {
            run(os(argv)).unwrap_or_else(|e| panic!("{argv:?}: {e}"));
        }
    }

    #[test]
    fn errors_surface_with_hints() {
        for (argv, message) in [
            (&["nope"][..], "未知命令: nope；请执行 onebox help"),
            (&["version", "extra"], "多余的参数: extra"),
            (
                &["version", "--json"],
                "version 不支持选项 --json；请执行 onebox version --help",
            ),
            (&["version", "--dry-run"], "此命令不支持 --dry-run"),
            (&["help", "nope"], "未知命令: nope；请执行 onebox help"),
        ] {
            assert_eq!(run(os(argv)).unwrap_err().to_string(), message, "{argv:?}");
        }
    }
}
