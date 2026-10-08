//! Chinese help rendering from the command tree: a grouped global overview
//! and per-command pages (usage, options, arguments, subcommands).
//!
//! Changes from v2: help is generated from the same specs the parser uses,
//! so it cannot drift; `onebox CMD --help` shows that command's page
//! instead of the global text (B-9.1#13).

use super::args::{CommandSpec, Group};
use crate::sys::text::{display_width, pad_right};
use crate::VERSION;

const GLOBAL_OPTIONS: &str =
    "通用选项: -y/--yes 无人值守（使用默认值并自动确认）  -h/--help 显示帮助";

/// `  name  summary` lines padded to `width`.
fn rows(width: usize, pairs: &[(String, &str)]) -> Vec<String> {
    pairs
        .iter()
        .map(|(left, right)| format!("  {}  {right}", pad_right(left, width)))
        .collect()
}

fn widest(pairs: &[(String, &str)]) -> usize {
    pairs
        .iter()
        .map(|(l, _)| display_width(l))
        .max()
        .unwrap_or(0)
}

/// The overview printed by `onebox help`.
pub fn global_help(commands: &[CommandSpec]) -> String {
    let visible = |c: &&CommandSpec| !c.hidden && c.group != Group::Hidden;
    let width = commands
        .iter()
        .filter(visible)
        .map(|c| display_width(c.name))
        .max()
        .unwrap_or(0);
    let mut lines = vec![
        format!("Onebox {VERSION} — sing-box / Xray 一键管理"),
        String::new(),
        "用法: onebox [命令] [选项]".to_string(),
        "      不带参数运行 onebox 打开交互菜单".to_string(),
    ];
    for group in Group::VISIBLE {
        let pairs: Vec<(String, &str)> = commands
            .iter()
            .filter(visible)
            .filter(|c| c.group == group)
            .map(|c| (c.name.to_string(), c.summary))
            .collect();
        if pairs.is_empty() {
            continue;
        }
        lines.push(String::new());
        lines.push(format!("{}:", group.title()));
        lines.extend(rows(width, &pairs));
    }
    lines.push(String::new());
    lines.push(GLOBAL_OPTIONS.to_string());
    lines.push("查看命令说明: onebox help 命令，或 onebox 命令 --help".to_string());
    lines.join("\n")
}

/// Usage line generated from the schema when a spec declares none.
fn default_usage(path: &str, spec: &CommandSpec) -> String {
    let mut parts = vec![path.to_string()];
    if !spec.subcommands.is_empty() {
        parts.push(if spec.handler.is_some() {
            "[子命令]".to_string()
        } else {
            "子命令".to_string()
        });
    }
    if !spec.options.is_empty() || spec.dry_run {
        parts.push("[选项]".to_string());
    }
    for arg in spec.args {
        let name = if arg.many {
            format!("{}...", arg.name)
        } else {
            arg.name.to_string()
        };
        parts.push(if arg.required {
            name
        } else {
            format!("[{name}]")
        });
    }
    parts.join(" ")
}

fn option_rows(spec: &CommandSpec) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = spec
        .options
        .iter()
        .map(|o| {
            let left = match o.value {
                Some(value) => format!("--{} {value}", o.long),
                None => format!("--{}", o.long),
            };
            let right = if o.repeat {
                format!("{}（可重复）", o.help)
            } else {
                o.help.to_string()
            };
            (left, right)
        })
        .collect();
    if spec.dry_run {
        out.push(("--dry-run".into(), "仅预览，不做任何修改".into()));
    }
    out
}

fn section(lines: &mut Vec<String>, title: &str, pairs: &[(String, &str)]) {
    if pairs.is_empty() {
        return;
    }
    lines.push(String::new());
    lines.push(format!("{title}:"));
    lines.extend(rows(widest(pairs), pairs));
}

/// The page printed by `onebox CMD [SUB] --help` / `onebox help CMD [SUB]`.
/// `chain` runs from the top-level command to the one being described.
pub fn command_help(chain: &[&CommandSpec]) -> String {
    let Some(spec) = chain.last() else {
        return String::new();
    };
    let path = chain.iter().map(|c| c.name).collect::<Vec<_>>().join(" ");
    let mut lines = vec![spec.summary.to_string(), String::new(), "用法:".to_string()];
    if spec.usage.is_empty() {
        lines.push(format!("  onebox {}", default_usage(&path, spec)));
    } else {
        lines.extend(spec.usage.iter().map(|u| format!("  onebox {u}")));
    }
    if !spec.aliases.is_empty() {
        lines.push(String::new());
        lines.push(format!("别名: {}", spec.aliases.join(", ")));
    }
    let options = option_rows(spec);
    let options: Vec<(String, &str)> = options
        .iter()
        .map(|(l, r)| (l.clone(), r.as_str()))
        .collect();
    section(&mut lines, "选项", &options);
    let args: Vec<(String, &str)> = spec
        .args
        .iter()
        .map(|a| (a.name.to_string(), a.help))
        .collect();
    section(&mut lines, "参数", &args);
    let subs: Vec<(String, &str)> = spec
        .subcommands
        .iter()
        .filter(|c| !c.hidden)
        .map(|c| (c.name.to_string(), c.summary))
        .collect();
    section(&mut lines, "子命令", &subs);
    lines.push(String::new());
    lines.push(GLOBAL_OPTIONS.to_string());
    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::args::{ArgSpec, OptSpec};

    static SUBS: [CommandSpec; 3] = [
        CommandSpec::new("enable", Group::Feature, "启用订阅").options(&[OptSpec::value(
            "mode",
            "模式",
            "ip / site / standalone",
        )]),
        CommandSpec::new("info", Group::Feature, "查看订阅"),
        CommandSpec::new("serve", Group::Feature, "订阅服务进程").hidden(),
    ];
    static COMMANDS: [CommandSpec; 5] = [
        CommandSpec::new("install", Group::Node, "安装节点")
            .usage(&["install [--protocols 列表] [--addr 地址]"])
            .options(&[
                OptSpec::value("protocols", "列表", "协议列表，逗号分隔"),
                OptSpec::value("port", "协议=端口", "指定协议端口").repeated(),
                OptSpec::flag("force", "已安装时强制重装"),
            ])
            .dry_run(),
        CommandSpec::new("del", Group::Node, "删除协议")
            .aliases(&["remove"])
            .args(&[ArgSpec::optional("协议", "要删除的协议")]),
        CommandSpec::new("subscription", Group::Feature, "远程订阅").subcommands(&SUBS),
        CommandSpec::new("version", Group::Maintain, "显示版本号"),
        CommandSpec::new("net-apply", Group::Hidden, "开机恢复网络规则"),
    ];

    #[test]
    fn global_help_snapshot() {
        let expected = format!(
            "Onebox {VERSION} — sing-box / Xray 一键管理

用法: onebox [命令] [选项]
      不带参数运行 onebox 打开交互菜单

节点:
  install       安装节点
  del           删除协议

功能:
  subscription  远程订阅

维护:
  version       显示版本号

通用选项: -y/--yes 无人值守（使用默认值并自动确认）  -h/--help 显示帮助
查看命令说明: onebox help 命令，或 onebox 命令 --help"
        );
        assert_eq!(global_help(&COMMANDS), expected);
    }

    #[test]
    fn command_help_snapshot() {
        let expected = "安装节点

用法:
  onebox install [--protocols 列表] [--addr 地址]

选项:
  --protocols 列表  协议列表，逗号分隔
  --port 协议=端口  指定协议端口（可重复）
  --force           已安装时强制重装
  --dry-run         仅预览，不做任何修改

通用选项: -y/--yes 无人值守（使用默认值并自动确认）  -h/--help 显示帮助";
        assert_eq!(command_help(&[&COMMANDS[0]]), expected);
    }

    #[test]
    fn generated_usage_aliases_and_arguments() {
        let expected = "删除协议

用法:
  onebox del [协议]

别名: remove

参数:
  协议  要删除的协议

通用选项: -y/--yes 无人值守（使用默认值并自动确认）  -h/--help 显示帮助";
        assert_eq!(command_help(&[&COMMANDS[1]]), expected);
    }

    #[test]
    fn group_help_lists_visible_subcommands() {
        let text = command_help(&[&COMMANDS[2]]);
        assert!(text.contains("  onebox subscription 子命令\n"), "{text}");
        assert!(text.contains("子命令:\n  enable  启用订阅\n  info    查看订阅"));
        assert!(!text.contains("serve"));
        let sub = command_help(&[&COMMANDS[2], &SUBS[0]]);
        assert!(
            sub.contains("  onebox subscription enable [选项]\n"),
            "{sub}"
        );
        assert!(sub.contains("  --mode 模式  ip / site / standalone"));
    }

    #[test]
    fn empty_chain_is_empty_help() {
        assert_eq!(command_help(&[]), "");
    }
}
