//! Retire only the boot hooks emitted by the old Onebox network manager.
use crate::{context::Context, util, Result};
use std::{fs, io::ErrorKind, path::PathBuf};

const NAMES: [&str; 2] = ["onebox-net", "onebox-hop"];

pub fn legacy_paths(ctx: &Context) -> Result<Vec<PathBuf>> {
    let local = ctx
        .paths
        .initd
        .parent()
        .ok_or("init.d 路径没有父目录")?
        .join("local.d");
    let paths = NAMES
        .iter()
        .map(|name| ctx.paths.systemd.join(format!("{name}.service")))
        .chain(NAMES.iter().map(|name| ctx.paths.initd.join(name)))
        .chain(NAMES.iter().map(|name| local.join(format!("{name}.start"))))
        .collect::<Vec<_>>();
    for path in &paths {
        util::safe_path(path)?;
    }
    Ok(paths)
}

/// Match the complete legacy line, never a substring identifying one command.
/// In particular a neighbouring command, comment or redirection is not ours.
pub fn legacy_cron(ctx: &Context, line: &str) -> bool {
    let Ok(program) = util::path_str(&ctx.paths.executable) else {
        return false;
    };
    if !ctx.paths.executable.is_absolute()
        || program.chars().any(char::is_control)
        || line.contains(['\n', '\0'])
    {
        return false;
    }
    let quoted = super::quote_shell(program);
    let mut forms = vec![quoted.as_str()];
    // An unquoted shell word must not contain expansions, separators or spaces.
    if program
        .bytes()
        .all(|c| c.is_ascii_alphanumeric() || b"/._-+:,@%=".contains(&c))
    {
        forms.push(program);
    }
    let line = line.trim_matches([' ', '\t', '\r']);
    forms.iter().any(|first| {
        forms.iter().any(|second| {
            line == format!(
                "@reboot {first} net-apply >/dev/null 2>&1; {second} start >/dev/null 2>&1"
            )
        })
    })
}

fn cron_replacement(ctx: &Context) -> Result<Option<String>> {
    let output = match ctx.output("crontab", &["-l"]) {
        Ok(output) => output,
        Err(error)
            if error
                .downcast_ref::<std::io::Error>()
                .is_some_and(|e| e.kind() == ErrorKind::NotFound) =>
        {
            return Ok(None);
        }
        Err(error) => return Err(error),
    };
    if !output.success() {
        let message = output.stderr.trim();
        let absent = message.starts_with("no crontab for ")
            || message.starts_with("crontab: no crontab for ")
            || (message.starts_with("crontab: can't open '")
                && message.ends_with("': No such file or directory"));
        if output.code == 1 && output.stdout.is_empty() && absent && message.lines().count() == 1 {
            return Ok(None);
        }
        return Err(format!(
            "无法读取 crontab，旧开机任务保持不变 ({}): {}",
            output.code, message
        )
        .into());
    }
    let filtered = output
        .stdout
        .split_inclusive('\n')
        .filter(|line| !legacy_cron(ctx, line.trim_end_matches('\n')))
        .collect::<String>();
    Ok((filtered != output.stdout).then_some(filtered))
}

fn write_cron(ctx: &Context, contents: &str) -> Result<()> {
    util::safe_path(&ctx.paths.run)?;
    let path = ctx
        .paths
        .run
        .join(format!(".legacy-boot-cron-{}", util::random_hex(12)?));
    util::safe_path(&path)?;
    util::atomic_write(&path, contents.as_bytes(), 0o600)?;
    let result = ctx.run("crontab", &[util::path_str(&path)?]);
    let cleanup = fs::remove_file(&path);
    match (result, cleanup) {
        (Ok(_), Ok(())) => Ok(()),
        (Err(error), Ok(())) => Err(error),
        (Ok(_), Err(error)) => Err(error.into()),
        (Err(error), Err(cleanup)) => {
            Err(format!("{error}；清理 {} 失败: {cleanup}", path.display()).into())
        }
    }
}

pub fn migrate(ctx: &Context) -> Result<()> {
    migrate_for_init(ctx, super::init_system())
}

fn migrate_for_init(ctx: &Context, init: &str) -> Result<()> {
    let paths = legacy_paths(ctx)?;
    util::safe_path(&ctx.paths.executable)?;
    util::safe_path(&ctx.paths.run)?;
    // Validate the entire fixed set before disabling or deleting anything.
    let mut present = Vec::with_capacity(paths.len());
    for path in &paths {
        present.push(match fs::symlink_metadata(path) {
            Ok(metadata) if metadata.is_file() => true,
            Ok(_) => return Err(format!("旧开机任务不是普通文件: {}", path.display()).into()),
            Err(error) if error.kind() == ErrorKind::NotFound => false,
            Err(error) => return Err(error.into()),
        });
    }
    let cron = cron_replacement(ctx)?;
    let enabled = if init == "openrc" && present[2..4].iter().any(|value| *value) {
        Some(ctx.run("rc-update", &["show", "default"])?)
    } else {
        None
    };
    let mut reload = false;
    for (index, path) in paths.iter().enumerate() {
        if !present[index] {
            continue;
        }
        if index < 2 && init == "systemd" {
            // An old oneshot may be the process currently invoking this command.
            // Never use stop, --now or restart here.
            ctx.run("systemctl", &["disable", NAMES[index]])?;
            reload = true;
        } else if (2..4).contains(&index) {
            if let Some(enabled) = &enabled {
                let name = NAMES[index - 2];
                if enabled
                    .lines()
                    .any(|line| line.split_whitespace().next() == Some(name))
                {
                    ctx.run("rc-update", &["del", name, "default"])?;
                }
            }
        }
        util::safe_path(path)?;
        fs::remove_file(path)?;
        fs::File::open(path.parent().ok_or("旧开机任务没有父目录")?)?.sync_all()?;
    }
    if reload {
        ctx.run("systemctl", &["daemon-reload"])?;
    }
    if let Some(cron) = cron {
        write_cron(ctx, &cron)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::{CommandOutput, Paths, Runner};
    use std::sync::{Arc, Mutex};

    #[derive(Default)]
    struct Fake {
        cron: Mutex<String>,
        commands: Mutex<Vec<String>>,
        enabled: String,
        fail: String,
        missing_crontab: bool,
    }
    impl Runner for Fake {
        fn output(&self, program: &str, args: &[String]) -> Result<CommandOutput> {
            let command = format!("{program} {}", args.join(" "));
            self.commands.lock().unwrap().push(command.clone());
            if program == "crontab" && self.missing_crontab {
                return Err(std::io::Error::from(ErrorKind::NotFound).into());
            }
            if !self.fail.is_empty() && command.starts_with(&self.fail) {
                return Ok(CommandOutput {
                    code: 1,
                    stderr: "injected failure".into(),
                    ..Default::default()
                });
            }
            let stdout = if command == "crontab -l" {
                self.cron.lock().unwrap().clone()
            } else if program == "crontab" {
                *self.cron.lock().unwrap() = fs::read_to_string(&args[0])?;
                String::new()
            } else if command == "rc-update show default" {
                self.enabled.clone()
            } else if program == "systemctl" || program == "rc-update" {
                String::new()
            } else {
                return Err(format!("unexpected command: {command}").into());
            };
            Ok(CommandOutput {
                stdout,
                ..Default::default()
            })
        }
    }
    struct Fixture {
        root: PathBuf,
        ctx: Context,
        fake: Arc<Fake>,
    }
    impl Fixture {
        fn new(fake: Fake) -> Self {
            let root = std::env::temp_dir().join(format!(
                "onebox-legacy-boot-{}",
                util::random_hex(10).unwrap()
            ));
            let fake = Arc::new(fake);
            let ctx = Context {
                paths: Paths::isolated(&root),
                runner: fake.clone(),
                yes: true,
            };
            Self { root, ctx, fake }
        }
        fn create(&self, index: usize) -> PathBuf {
            let path = legacy_paths(&self.ctx).unwrap()[index].clone();
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(&path, b"legacy owned boot hook").unwrap();
            path
        }
        fn line(&self) -> String {
            let exe = self.ctx.paths.executable.display();
            format!("@reboot {exe} net-apply >/dev/null 2>&1; {exe} start >/dev/null 2>&1")
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    #[test]
    fn cron_matches_whole_command_and_shell_quoted_paths_only() {
        let mut f = Fixture::new(Fake::default());
        let line = f.line();
        assert!(legacy_cron(&f.ctx, &line));
        assert!(legacy_cron(&f.ctx, &format!(" \t{line}\r")));
        for unrelated in [
            format!("{line}; /bin/true"),
            format!("{line} # custom job"),
            format!("{line} && /bin/true"),
            format!("{line}\n/bin/true"),
            line.replace("@reboot", "0 * * * *"),
            line.replace(" net-apply ", " frps net-apply "),
            line.replace(" start ", " start-other "),
            line.replace(" >/dev/null", " >>/dev/null"),
            line.replace("onebox ", "onebox-other "),
        ] {
            assert!(!legacy_cron(&f.ctx, &unrelated), "{unrelated}");
        }
        f.ctx.paths.executable = f.root.join("quoted ' name");
        let quote = super::super::quote_shell(f.ctx.paths.executable.to_str().unwrap());
        assert!(legacy_cron(
            &f.ctx,
            &format!("@reboot {quote} net-apply >/dev/null 2>&1; {quote} start >/dev/null 2>&1")
        ));
        assert!(!legacy_cron(&f.ctx, &f.line()));
    }

    #[test]
    fn systemd_migration_is_exact_and_idempotent_without_stopping() {
        let f = Fixture::new(Fake::default());
        let paths = (0..6).map(|i| f.create(i)).collect::<Vec<_>>();
        let neighbour = f.ctx.paths.systemd.join("onebox-network.service");
        fs::write(&neighbour, b"native network service").unwrap();
        let local = f.ctx.paths.initd.join("local");
        fs::write(&local, b"shared local service").unwrap();
        let custom = format!("{}; /bin/true", f.line());
        let original = format!(
            "MAILTO=admin\n{}\n{custom}\n# leave final newline untouched",
            f.line()
        );
        *f.fake.cron.lock().unwrap() = original;
        migrate_for_init(&f.ctx, "systemd").unwrap();
        assert!(paths.iter().all(|path| !path.exists()));
        assert!(neighbour.exists() && local.exists());
        assert_eq!(
            *f.fake.cron.lock().unwrap(),
            format!("MAILTO=admin\n{custom}\n# leave final newline untouched")
        );
        let before = f.fake.commands.lock().unwrap().clone();
        assert!(before.contains(&"systemctl disable onebox-net".into()));
        assert!(before.contains(&"systemctl disable onebox-hop".into()));
        assert_eq!(
            before
                .iter()
                .filter(|c| *c == "systemctl daemon-reload")
                .count(),
            1
        );
        assert!(before
            .iter()
            .all(|c| !c.contains("stop") && !c.contains("--now") && !c.starts_with("rc-update")));
        migrate_for_init(&f.ctx, "systemd").unwrap();
        let after = f.fake.commands.lock().unwrap();
        assert_eq!(&after[..before.len()], before.as_slice());
        assert_eq!(&after[before.len()..], &["crontab -l"]);
        assert!(fs::read_dir(&f.ctx.paths.run).unwrap().next().is_none());
    }

    #[test]
    fn openrc_only_disables_exact_enabled_hooks_and_preserves_local() {
        let f = Fixture::new(Fake {
            enabled: " onebox-net | default\n onebox-hop-extra | default\n local | default\n"
                .into(),
            ..Default::default()
        });
        for index in 2..6 {
            f.create(index);
        }
        let local = f.ctx.paths.initd.join("local");
        fs::write(&local, b"shared").unwrap();
        migrate_for_init(&f.ctx, "openrc").unwrap();
        assert!(local.exists());
        assert_eq!(
            *f.fake.commands.lock().unwrap(),
            [
                "crontab -l",
                "rc-update show default",
                "rc-update del onebox-net default"
            ]
        );
    }

    #[test]
    fn read_and_disable_errors_preserve_files_and_fail_closed() {
        for fail in ["crontab -l", "systemctl disable onebox-net"] {
            let f = Fixture::new(Fake {
                fail: fail.into(),
                ..Default::default()
            });
            let path = f.create(0);
            *f.fake.cron.lock().unwrap() = f.line();
            assert!(migrate_for_init(&f.ctx, "systemd").is_err());
            assert!(path.exists());
            assert_eq!(*f.fake.cron.lock().unwrap(), f.line());
        }
    }

    #[test]
    fn symlinks_are_rejected_before_any_commands() {
        use std::os::unix::fs::symlink;
        let f = Fixture::new(Fake::default());
        let path = f.create(0);
        let outside = f.root.join("unrelated");
        fs::write(&outside, b"keep").unwrap();
        fs::remove_file(&path).unwrap();
        symlink(&outside, &path).unwrap();
        assert!(legacy_paths(&f.ctx).is_err());
        assert!(migrate_for_init(&f.ctx, "systemd").is_err());
        assert!(f.fake.commands.lock().unwrap().is_empty());
        assert_eq!(fs::read(outside).unwrap(), b"keep");
    }

    #[test]
    fn missing_crontab_does_not_prevent_file_migration() {
        let f = Fixture::new(Fake {
            missing_crontab: true,
            ..Default::default()
        });
        let path = f.create(4);
        migrate_for_init(&f.ctx, "none").unwrap();
        assert!(!path.exists());
    }
}
