//! Command specs and handlers for `backup`, `backups`, `restore`, `recover`
//! and `net-apply` (registered by the CLI; see `cli::registry`).
//!
//! Output (v2): `backup` prints the new id on stdout; `backups` prints one
//! `{id}\t{label}` line per backup, newest first; `restore` asks
//! `恢复备份 {id}？当前配置会先备份` (default no; declining is a silent
//! success) and prints `备份已恢复` on stdout.
//!
//! Changes from v2: `backups` orders by creation time and says so when
//! there is none; `restore` shows what it is about to restore (label, time,
//! v2 migration notes) before asking; a v1 backup is refused before the
//! question; `recover` reports what it did.

use super::restore::{self, preview};
use super::store::{self, BackupKind};
use crate::apply::{self, journal, program_journal};
use crate::cli::args::{ArgSpec, CommandSpec, Group, Matches, Root};
use crate::ctx::Ctx;
use crate::error::Result;
use crate::sys::time::format_utc;
use crate::ui::out;

/// Default label of `onebox backup`.
pub const MANUAL_LABEL: &str = "manual";

pub const BACKUP: CommandSpec = CommandSpec::new("backup", Group::Maintain, "备份当前配置")
    .usage(&["backup [标签]"])
    .args(&[ArgSpec::optional("标签", "备份说明（默认 manual）")])
    .handler(backup_command);

pub const BACKUPS: CommandSpec = CommandSpec::new("backups", Group::Maintain, "列出备份")
    .root(Root::NotRequired)
    .handler(backups_command);

pub const RESTORE: CommandSpec = CommandSpec::new("restore", Group::Maintain, "恢复备份")
    .usage(&["restore [备份ID|latest]"])
    .args(&[ArgSpec::optional(
        "备份ID",
        "要恢复的备份（默认 latest，即最新备份）",
    )])
    .handler(restore_command);

pub const RECOVER: CommandSpec =
    CommandSpec::new("recover", Group::Maintain, "回滚中断的配置事务与自更新")
        .handler(recover_command);

/// The boot oneshot's entry (`onebox-network` runs `onebox net-apply`).
pub const NET_APPLY: CommandSpec =
    CommandSpec::new("net-apply", Group::Hidden, "开机恢复防火墙与端口跳跃规则")
        .aliases(&["hop-apply", "boot"])
        .handler(net_apply_command);

/// Every command of this module, for the registry.
pub const COMMANDS: [CommandSpec; 5] = [BACKUP, BACKUPS, RESTORE, RECOVER, NET_APPLY];

fn backup_command(ctx: &Ctx, m: &Matches) -> Result<()> {
    let label = m.positional(0).unwrap_or(MANUAL_LABEL);
    let id = super::create(ctx, label)?;
    out::data(&id)
}

fn backups_command(ctx: &Ctx, _m: &Matches) -> Result<()> {
    let backups = store::list(&ctx.paths)?;
    if backups.is_empty() {
        out::info("没有备份");
        return Ok(());
    }
    let lines: Vec<String> = backups
        .iter()
        .map(|b| format!("{}\t{}", b.id, b.label))
        .collect();
    out::data(&lines.join("\n"))
}

fn restore_command(ctx: &Ctx, m: &Matches) -> Result<()> {
    let wanted = m.positional(0).unwrap_or("latest");
    let (id, validated) = preview(&ctx.paths, wanted)?;
    let created = format_utc(validated.manifest.created);
    out::kv(&[
        ("备份", id.as_str()),
        ("说明", validated.manifest.label.as_str()),
        ("时间", created.as_str()),
    ]);
    if !ctx
        .ui
        .confirm(&format!("恢复备份 {id}？当前配置会先备份"), false)?
    {
        return Ok(());
    }
    restore::restore(ctx, &id)
}

fn recover_command(ctx: &Ctx, _m: &Matches) -> Result<()> {
    let lock = apply::node_lock(ctx)?;
    let program = program_journal::load(&ctx.paths)?.is_some();
    let outcome = apply::recover::recover_all(ctx, &lock)?;
    if outcome == apply::recover::Recovery::Nothing && !program {
        out::ok("没有需要恢复的事务");
    }
    Ok(())
}

fn net_apply_command(ctx: &Ctx, _m: &Matches) -> Result<()> {
    apply::boot(ctx)
}

/// `restore` candidates for menus: restorable backups, newest first.
pub fn restorable(ctx: &Ctx) -> Result<Vec<store::BackupInfo>> {
    Ok(store::list(&ctx.paths)?
        .into_iter()
        .filter(|b| b.kind == BackupKind::Current)
        .collect())
}

/// Whether a node or self-update journal waits for `recover` (menus).
pub fn recovery_due(ctx: &Ctx) -> Result<bool> {
    Ok(journal::pending(&ctx.paths)?.any())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::fixtures;
    use crate::domain::protocol::{Core, Protocol};
    use crate::error::Error;
    use crate::state::StateStore;
    use crate::sys::fs::TempDir;
    use crate::ui::ScriptedPrompter;
    use std::sync::Arc;

    fn matches(positionals: &[&str]) -> Matches {
        Matches {
            positionals: positionals.iter().map(|s| s.to_string()).collect(),
            ..Matches::default()
        }
    }

    fn installed() -> (TempDir, Ctx, Arc<ScriptedPrompter>) {
        let dir = TempDir::new("backup-cli").unwrap();
        let (ctx, _, ui) = Ctx::test(dir.path());
        let cfg = fixtures::config(&[(Protocol::VlessReality, 443, Core::Singbox)]);
        StateStore::save(&ctx, &cfg).unwrap();
        (dir, ctx, ui)
    }

    #[test]
    fn specs_declare_names_aliases_and_root_policy() {
        let names: Vec<&str> = COMMANDS.iter().map(|c| c.name).collect();
        assert_eq!(
            names,
            ["backup", "backups", "restore", "recover", "net-apply"]
        );
        for spec in COMMANDS {
            let root = !matches!(spec.root, Root::NotRequired);
            assert_eq!(root, spec.name != "backups", "{}", spec.name);
            assert!(spec.handler.is_some());
        }
        assert!(NET_APPLY.is_named("hop-apply") && NET_APPLY.is_named("boot"));
        const { assert!(NET_APPLY.hidden) };
    }

    #[test]
    fn backup_then_list_then_decline_a_restore() {
        let (_dir, ctx, ui) = installed();
        backup_command(&ctx, &matches(&[])).unwrap();
        backup_command(&ctx, &matches(&["升级前"])).unwrap();
        let listed = store::list(&ctx.paths).unwrap();
        let labels: Vec<&str> = listed.iter().map(|b| b.label.as_str()).collect();
        assert_eq!(labels.len(), 2);
        assert!(labels.contains(&MANUAL_LABEL) && labels.contains(&"升级前"));
        backups_command(&ctx, &matches(&[])).unwrap();
        // Declining the confirmation is a silent success; nothing changed.
        ui.push("n");
        let before = std::fs::read(ctx.paths.state()).unwrap();
        restore_command(&ctx, &matches(&["latest"])).unwrap();
        assert_eq!(std::fs::read(ctx.paths.state()).unwrap(), before);
        assert_eq!(ui.prompts().len(), 1);
        assert!(
            ui.prompts()[0].contains("当前配置会先备份"),
            "{:?}",
            ui.prompts()
        );
        assert_eq!(store::list(&ctx.paths).unwrap().len(), 2);
    }

    #[test]
    fn restore_reports_unusable_backups_before_asking() {
        let (_dir, ctx, ui) = installed();
        let err = restore_command(&ctx, &matches(&[])).unwrap_err();
        assert_eq!(err.to_string(), "没有备份");
        let err = restore_command(&ctx, &matches(&["../x"])).unwrap_err();
        assert_eq!(err.to_string(), "备份 ID 无效");
        assert!(ui.prompts().is_empty());
    }

    #[test]
    fn recover_and_net_apply_entry_points() {
        let dir = TempDir::new("backup-cli-recover").unwrap();
        let (ctx, exec, ui) = Ctx::test(dir.path());
        recover_command(&ctx, &matches(&[])).unwrap();
        assert!(recovery_due(&ctx).is_ok_and(|due| !due));
        let err = net_apply_command(&ctx, &matches(&[])).unwrap_err();
        assert!(matches!(err, Error::NotInstalled), "{err}");
        assert!(exec.calls().is_empty());
        assert!(ui.prompts().is_empty());
        assert!(restorable(&ctx).unwrap().is_empty());
    }
}
