//! Declarative command schema and argument parser.
//!
//! Every command declares its options, positional arguments, subcommands,
//! root policy and `--dry-run` support in a `static` [`CommandSpec`] tree;
//! the parser rejects anything a command does not declare.
//!
//! Changes from v2 (spec B §2.5, B-9.1#13–15, A-8.1#23): options are
//! per-command instead of one global allowlist; `-y/--yes` and `-h/--help`
//! are recognized only in flag position, never when they are the value of
//! an option (`--name -y` sets the name to `-y`); `--help` shows the help of
//! the command it follows; `--dry-run` is accepted exactly where declared.

use crate::ctx::Ctx;
use crate::error::{Error, Result};
use std::collections::BTreeMap;
use std::str::FromStr;

/// A command implementation.
pub type Handler = fn(&Ctx, &Matches) -> Result<()>;

/// Help-screen category.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Group {
    Node,
    Client,
    Service,
    Feature,
    Diagnose,
    Maintain,
    /// Never listed (compatibility aliases, internal entry points).
    Hidden,
}

impl Group {
    /// Visible groups in help order.
    pub const VISIBLE: [Group; 6] = [
        Group::Node,
        Group::Client,
        Group::Service,
        Group::Feature,
        Group::Diagnose,
        Group::Maintain,
    ];

    pub fn title(self) -> &'static str {
        match self {
            Group::Node => "节点",
            Group::Client => "客户端",
            Group::Service => "服务",
            Group::Feature => "功能",
            Group::Diagnose => "诊断",
            Group::Maintain => "维护",
            Group::Hidden => "隐藏",
        }
    }
}

/// Whether a command needs root, evaluated on the parsed invocation so a
/// module can decide per subaction/option (e.g. `tune` only with `--apply`).
#[derive(Clone, Copy, Debug)]
pub enum Root {
    Required,
    NotRequired,
    /// `true` = root required for these matches.
    Custom(fn(&Matches) -> bool),
}

impl Root {
    pub fn required(&self, matches: &Matches) -> bool {
        match self {
            Root::Required => true,
            Root::NotRequired => false,
            Root::Custom(decide) => decide(matches),
        }
    }
}

/// A `--long` option. `value` is the value's display name (`None` = flag).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OptSpec {
    /// Name without the leading dashes, e.g. `"protocols"`.
    pub long: &'static str,
    pub value: Option<&'static str>,
    /// May be given several times (every value is kept).
    pub repeat: bool,
    /// Repeats are accepted but only the last value counts (v2's `frps`
    /// options); help does not call such an option repeatable.
    pub last_wins: bool,
    pub help: &'static str,
}

impl OptSpec {
    pub const fn flag(long: &'static str, help: &'static str) -> OptSpec {
        OptSpec {
            long,
            value: None,
            repeat: false,
            last_wins: false,
            help,
        }
    }

    pub const fn value(long: &'static str, value: &'static str, help: &'static str) -> OptSpec {
        OptSpec {
            long,
            value: Some(value),
            repeat: false,
            last_wins: false,
            help,
        }
    }

    /// May be given several times (values accumulate in order).
    pub const fn repeated(mut self) -> OptSpec {
        self.repeat = true;
        self
    }

    /// May be given several times; read it with `values(..).last()`.
    pub const fn last_wins(mut self) -> OptSpec {
        self.repeat = true;
        self.last_wins = true;
        self
    }

    pub fn takes_value(&self) -> bool {
        self.value.is_some()
    }
}

/// A positional argument.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ArgSpec {
    pub name: &'static str,
    pub required: bool,
    /// Absorbs all remaining positionals (must be last).
    pub many: bool,
    pub help: &'static str,
}

impl ArgSpec {
    pub const fn required(name: &'static str, help: &'static str) -> ArgSpec {
        ArgSpec {
            name,
            required: true,
            many: false,
            help,
        }
    }

    pub const fn optional(name: &'static str, help: &'static str) -> ArgSpec {
        ArgSpec {
            name,
            required: false,
            many: false,
            help,
        }
    }

    pub const fn many(mut self) -> ArgSpec {
        self.many = true;
        self
    }
}

/// One node of the command tree. Build with [`CommandSpec::new`] and the
/// `const` builder methods so specs can live in `static` items.
#[derive(Clone, Copy, Debug)]
pub struct CommandSpec {
    pub name: &'static str,
    pub aliases: &'static [&'static str],
    pub summary: &'static str,
    /// Usage lines without the leading `onebox ` (generated when empty).
    pub usage: &'static [&'static str],
    pub group: Group,
    pub options: &'static [OptSpec],
    pub args: &'static [ArgSpec],
    pub subcommands: &'static [CommandSpec],
    pub root: Root,
    pub dry_run: bool,
    pub hidden: bool,
    /// `None` for pure command groups (their help is shown instead).
    pub handler: Option<Handler>,
}

impl CommandSpec {
    /// A visible command that requires root (the safe default), with no
    /// options, arguments, subcommands or handler yet.
    pub const fn new(name: &'static str, group: Group, summary: &'static str) -> CommandSpec {
        CommandSpec {
            name,
            aliases: &[],
            summary,
            usage: &[],
            group,
            options: &[],
            args: &[],
            subcommands: &[],
            root: Root::Required,
            dry_run: false,
            hidden: matches!(group, Group::Hidden),
            handler: None,
        }
    }

    pub const fn aliases(mut self, aliases: &'static [&'static str]) -> Self {
        self.aliases = aliases;
        self
    }
    pub const fn usage(mut self, usage: &'static [&'static str]) -> Self {
        self.usage = usage;
        self
    }
    pub const fn options(mut self, options: &'static [OptSpec]) -> Self {
        self.options = options;
        self
    }
    pub const fn args(mut self, args: &'static [ArgSpec]) -> Self {
        self.args = args;
        self
    }
    pub const fn subcommands(mut self, subcommands: &'static [CommandSpec]) -> Self {
        self.subcommands = subcommands;
        self
    }
    pub const fn root(mut self, root: Root) -> Self {
        self.root = root;
        self
    }
    pub const fn dry_run(mut self) -> Self {
        self.dry_run = true;
        self
    }
    pub const fn hidden(mut self) -> Self {
        self.hidden = true;
        self
    }
    pub const fn handler(mut self, handler: Handler) -> Self {
        self.handler = Some(handler);
        self
    }

    /// Name or alias match.
    pub fn is_named(&self, word: &str) -> bool {
        self.name == word || self.aliases.contains(&word)
    }

    pub fn subcommand(&self, word: &str) -> Option<&CommandSpec> {
        self.subcommands.iter().find(|c| c.is_named(word))
    }

    pub fn option(&self, long: &str) -> Option<&OptSpec> {
        self.options.iter().find(|o| o.long == long)
    }
}

/// Find a top-level command by name or alias.
pub fn find<'a>(commands: &'a [CommandSpec], word: &str) -> Option<&'a CommandSpec> {
    commands.iter().find(|c| c.is_named(word))
}

/// The parsed invocation handed to a [`Handler`].
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Matches {
    /// Canonical command names from the top, e.g. `["frps", "install"]`.
    pub path: Vec<&'static str>,
    pub positionals: Vec<String>,
    /// Flags given (long names without dashes).
    pub flags: Vec<&'static str>,
    /// Option values in argv order, keyed by long name without dashes.
    pub values: BTreeMap<&'static str, Vec<String>>,
    /// `-y/--yes` (or `ONEBOX_AUTO=1`, merged by `cli::run`).
    pub assume_yes: bool,
    pub dry_run: bool,
}

/// Accessors take the long name with or without the leading `--`.
fn key(long: &str) -> &str {
    long.trim_start_matches("--")
}

impl Matches {
    /// `"frps install"`.
    pub fn command(&self) -> String {
        self.path.join(" ")
    }

    pub fn flag(&self, long: &str) -> bool {
        self.flags.contains(&key(long))
    }

    /// The value of a (non-repeated) option.
    pub fn value(&self, long: &str) -> Option<&str> {
        self.values
            .get(key(long))
            .and_then(|v| v.first())
            .map(String::as_str)
    }

    /// All values of a repeatable option, in argv order.
    pub fn values(&self, long: &str) -> &[String] {
        self.values.get(key(long)).map_or(&[], Vec::as_slice)
    }

    pub fn positional(&self, index: usize) -> Option<&str> {
        self.positionals.get(index).map(String::as_str)
    }

    /// Parse an option value; a bad value → `--opt 的值无效: v`.
    pub fn parse<T: FromStr>(&self, long: &str) -> Result<Option<T>> {
        self.value(long)
            .map(|v| {
                v.parse::<T>()
                    .map_err(|_| Error::msg(format!("--{} 的值无效: {v}", key(long))))
            })
            .transpose()
    }

    /// Parse positional `index`; a bad value → `{name} 无效: v`.
    pub fn parse_positional<T: FromStr>(&self, index: usize, name: &str) -> Result<Option<T>> {
        self.positional(index)
            .map(|v| {
                v.parse::<T>()
                    .map_err(|_| Error::msg(format!("{name} 无效: {v}")))
            })
            .transpose()
    }
}

/// Global switches found before the command word.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Globals {
    pub assume_yes: bool,
    pub help: bool,
}

/// Consume leading `-y/--yes` and `-h/--help` (`onebox -y install` must keep
/// working); returns the switches and the remaining arguments.
pub fn leading_globals(args: &[String]) -> (Globals, &[String]) {
    let mut globals = Globals::default();
    let mut rest = args;
    while let Some((first, tail)) = rest.split_first() {
        match first.as_str() {
            "-y" | "--yes" => globals.assume_yes = true,
            "-h" | "--help" => globals.help = true,
            _ => break,
        }
        rest = tail;
    }
    (globals, rest)
}

/// A resolved command line.
#[derive(Debug)]
pub struct Invocation<'a> {
    /// Specs from the top-level command down to the resolved leaf.
    pub chain: Vec<&'a CommandSpec>,
    /// The resolved (leaf) command, i.e. the last element of `chain`.
    pub spec: &'a CommandSpec,
    pub matches: Matches,
    /// Help requested (or a command group invoked without subcommand).
    pub help: bool,
}

/// Parse `args` (command word first, leading globals already split off).
pub fn parse<'a>(
    commands: &'a [CommandSpec],
    args: &[String],
    globals: Globals,
) -> Result<Invocation<'a>> {
    let (word, rest) = args
        .split_first()
        .ok_or_else(|| Error::msg("缺少命令；请执行 onebox help"))?;
    let top = find(commands, word)
        .ok_or_else(|| Error::msg(format!("未知命令: {word}；请执行 onebox help")))?;
    let mut parser = Parser {
        chain: vec![top],
        leaf: top,
        matches: Matches {
            path: vec![top.name],
            assume_yes: globals.assume_yes,
            ..Matches::default()
        },
        help: globals.help,
    };
    let mut tokens = rest.iter();
    while let Some(token) = tokens.next() {
        match token.as_str() {
            // Everything after `--` is data: never an option, a
            // subcommand or the `help` word (menus pass typed values so).
            "--" => parser.matches.positionals.extend(tokens.by_ref().cloned()),
            "-y" | "--yes" => parser.matches.assume_yes = true,
            "-h" | "--help" => parser.help = true,
            t if t.starts_with("--") => {
                let next = tokens.as_slice().first();
                if parser.option(t, next)? {
                    tokens.next();
                }
            }
            t if t.starts_with('-') && t.len() > 1 => return Err(parser.unknown_option(t)),
            t => parser.positional(t)?,
        }
    }
    parser.finish()
}

struct Parser<'a> {
    chain: Vec<&'a CommandSpec>,
    leaf: &'a CommandSpec,
    matches: Matches,
    help: bool,
}

impl<'a> Parser<'a> {
    fn unknown_option(&self, option: &str) -> Error {
        let cmd = self.matches.command();
        Error::msg(format!(
            "{cmd} 不支持选项 {option}；请执行 onebox {cmd} --help"
        ))
    }

    /// Handle `--name[=value]`; returns whether the next token was consumed.
    fn option(&mut self, token: &str, next: Option<&String>) -> Result<bool> {
        let (name, inline) = match token.split_once('=') {
            Some((name, value)) => (name, Some(value)),
            None => (token, None),
        };
        if matches!(name, "--dry-run" | "--yes" | "--help") {
            if inline.is_some() {
                return Err(Error::msg(format!("{name} 不接受值")));
            }
            self.matches.dry_run |= name == "--dry-run";
            self.matches.assume_yes |= name == "--yes";
            self.help |= name == "--help";
            return Ok(false);
        }
        let spec = *self
            .leaf
            .option(&name[2..])
            .ok_or_else(|| self.unknown_option(name))?;
        if spec.value.is_none() {
            if inline.is_some() {
                return Err(Error::msg(format!("{name} 不接受值")));
            }
            if self.matches.flags.contains(&spec.long) && !spec.repeat {
                return Err(Error::msg(format!("重复选项: {name}")));
            }
            self.matches.flags.push(spec.long);
            return Ok(false);
        }
        let (value, consumed) = match (inline, next) {
            (Some(value), _) => (value.to_string(), false),
            (None, Some(next)) if !next.starts_with("--") => (next.clone(), true),
            _ => return Err(Error::msg(format!("{name} 需要参数"))),
        };
        let values = self.matches.values.entry(spec.long).or_default();
        if !values.is_empty() && !spec.repeat {
            return Err(Error::msg(format!("重复选项: {name}")));
        }
        values.push(value);
        Ok(consumed)
    }

    /// A positional word: the first one may select a subcommand. Under a
    /// command group, `help` (unless the group declares a `help`
    /// subcommand) shows the group's help, as v2's `onebox frps help` did;
    /// any other unknown word is a mistyped subcommand unless the group
    /// declares positional arguments of its own (legacy forms).
    fn positional(&mut self, word: &str) -> Result<()> {
        let leaf = self.leaf;
        if !leaf.subcommands.is_empty() && self.matches.positionals.is_empty() {
            if let Some(sub) = leaf.subcommand(word) {
                return self.descend(sub);
            }
            if word == "help" {
                self.help = true;
                return Ok(());
            }
            if leaf.handler.is_none() || leaf.args.is_empty() {
                let cmd = self.matches.command();
                return Err(Error::msg(format!(
                    "未知子命令: {word}；请执行 onebox {cmd} --help"
                )));
            }
        }
        self.matches.positionals.push(word.to_string());
        Ok(())
    }

    /// Enter a subcommand; options given before it must be valid there too.
    fn descend(&mut self, sub: &'a CommandSpec) -> Result<()> {
        self.chain.push(sub);
        self.leaf = sub;
        self.matches.path.push(sub.name);
        let flags = self.matches.flags.iter().map(|f| (*f, false));
        let values = self.matches.values.keys().map(|v| (*v, true));
        for (long, takes_value) in flags.chain(values).collect::<Vec<_>>() {
            if sub.option(long).map(OptSpec::takes_value) != Some(takes_value) {
                return Err(self.unknown_option(&format!("--{long}")));
            }
        }
        Ok(())
    }

    fn finish(self) -> Result<Invocation<'a>> {
        let spec = self.leaf;
        let group_without_action = !spec.subcommands.is_empty() && spec.handler.is_none();
        let help = self.help || group_without_action;
        if !help {
            if self.matches.dry_run && !spec.dry_run {
                return Err(Error::msg("此命令不支持 --dry-run"));
            }
            check_arity(spec, &self.matches.positionals)?;
        }
        Ok(Invocation {
            chain: self.chain,
            spec,
            matches: self.matches,
            help,
        })
    }
}

fn check_arity(spec: &CommandSpec, positionals: &[String]) -> Result<()> {
    let mut used = 0;
    for arg in spec.args {
        let available = positionals.len() - used;
        if arg.required && available == 0 {
            return Err(Error::msg(format!("缺少参数: {}", arg.name)));
        }
        if arg.many {
            used = positionals.len();
            break;
        }
        used += usize::from(available > 0);
    }
    match positionals.get(used) {
        Some(extra) => Err(Error::msg(format!("多余的参数: {extra}"))),
        None => Ok(()),
    }
}

#[cfg(test)]
mod tests;
