//! Builder for owned crontab lines.

use super::{Tag, MARKER};
use crate::error::{Error, Result};
use crate::host::init::InitSystem;
use crate::host::service::service_env;
use crate::paths::Paths;
use crate::sys::exec::SAFE_PATH;
use crate::sys::text::{cron_escape, quote_shell};
use std::path::Path;

/// `@` schedules cron implementations agree on.
const NAMED_SCHEDULES: [&str; 8] = [
    "@reboot",
    "@yearly",
    "@annually",
    "@monthly",
    "@weekly",
    "@daily",
    "@midnight",
    "@hourly",
];

/// One owned line: `{schedule} mkdir -p '{log dir}' 2>/dev/null; PATH={SAFE_PATH}
/// env ONEBOX_…='…' '{exe}' {args} >>'{log}' 2>&1 # onebox:{tag}`.
///
/// The job runs the managed executable with the fixed PATH and the service
/// variables (`ONEBOX_INIT` = `init`), appending its output to `log`; the
/// line recreates the log directory first (see `command`). Plain
/// arguments stay bare, others are single-quoted; every `%` of the command
/// is escaped (cron would turn it into a newline).
pub fn line(
    schedule: &str,
    paths: &Paths,
    init: InitSystem,
    args: &[&str],
    log: &Path,
    tag: &Tag,
) -> Result<String> {
    validate_schedule(schedule)?;
    if !log.is_absolute() {
        return Err(Error::msg("计划任务日志必须是绝对路径"));
    }
    let args: Vec<String> = args.iter().map(|a| a.to_string()).collect();
    let command = command(
        &service_env(paths, init),
        &paths.executable.to_string_lossy(),
        &args,
        &log.to_string_lossy(),
    );
    if command.chars().any(char::is_control) {
        return Err(Error::msg("计划任务命令包含控制字符"));
    }
    Ok(assemble(schedule, &command, tag))
}

/// The command of a v3 line before `%` escaping: [`job_command`] preceded
/// by `mkdir -p '{log dir}' 2>/dev/null;`. The shell runs no command whose
/// redirection it cannot open, and the log directory may vanish long after
/// the line was written (`/var/log` on tmpfs, an administrator freeing
/// space): without it renewals and no-init autostart would silently stop.
pub(super) fn command(env: &[(String, String)], exe: &str, args: &[String], log: &str) -> String {
    let dir = Path::new(log).parent().unwrap_or(Path::new("/"));
    format!(
        "mkdir -p {} 2>/dev/null; {}",
        quote_shell(&dir.to_string_lossy()),
        job_command(env, exe, args, log)
    )
}

/// `PATH={SAFE_PATH} env {K='v'…} '{exe}' {args} >>'{log}' 2>&1` (the whole
/// command of the lines earlier v3 builds wrote).
pub(super) fn job_command(
    env: &[(String, String)],
    exe: &str,
    args: &[String],
    log: &str,
) -> String {
    let mut words = vec![format!("PATH={SAFE_PATH}"), "env".to_owned()];
    words.push(env_words(env));
    words.push(quote_shell(exe));
    words.extend(args.iter().map(|a| shell_word(a)));
    words.push(format!(">>{}", quote_shell(log)));
    words.push("2>&1".to_owned());
    words.retain(|w| !w.is_empty());
    words.join(" ")
}

/// `KEY='value' …` (an `env` prefix's assignments).
pub(super) fn env_words(env: &[(String, String)]) -> String {
    env.iter()
        .map(|(key, value)| format!("{key}={}", quote_shell(value)))
        .collect::<Vec<_>>()
        .join(" ")
}

/// `{schedule} {escaped command} # onebox:{tag}`.
pub(super) fn assemble(schedule: &str, command: &str, tag: &Tag) -> String {
    format!("{schedule} {}{MARKER}{tag}", cron_escape(command))
}

/// Split `{schedule} {command}`: a named `@` schedule or five time fields.
pub(super) fn split_schedule(text: &str) -> Option<(&str, &str)> {
    let end = if text.starts_with('@') {
        text.find(' ')?
    } else {
        text.match_indices(' ').nth(4)?.0
    };
    let schedule = &text[..end];
    validate_schedule(schedule).ok()?;
    Some((schedule, &text[end + 1..]))
}

/// Five time fields of `[A-Za-z0-9*/,-]` or a named `@` schedule.
fn validate_schedule(schedule: &str) -> Result<()> {
    let fields: Vec<&str> = schedule.split(' ').collect();
    let ok = if schedule.starts_with('@') {
        NAMED_SCHEDULES.contains(&schedule)
    } else {
        fields.len() == 5
            && fields.iter().all(|f| {
                !f.is_empty()
                    && f.bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"*/,-".contains(&b))
            })
    };
    if ok {
        Ok(())
    } else {
        Err(Error::msg(format!("计划任务时间格式无效: {schedule}")))
    }
}

/// A plain word stays bare (readable lines); anything else is quoted.
pub(super) fn shell_word(word: &str) -> String {
    let plain = !word.is_empty()
        && word
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_./:=@+,-".contains(&b));
    if plain {
        word.to_owned()
    } else {
        quote_shell(word)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn paths() -> Paths {
        Paths::from_lookup(|_| None).unwrap()
    }

    const ENV_NONE: &str = "env ONEBOX_DIR='/etc/onebox' ONEBOX_BIN_DIR='/opt/onebox/bin' \
        ONEBOX_LOG_DIR='/var/log/onebox' ONEBOX_RUN_DIR='/run/onebox' \
        ONEBOX_SITE_ROOT='/var/lib/onebox-site' ONEBOX_SYSTEMD_DIR='/etc/systemd/system' \
        ONEBOX_INITD_DIR='/etc/init.d' ONEBOX_EXE='/usr/local/bin/onebox' \
        ONEBOX_FRPS_DIR='/etc/onebox-frp' ONEBOX_FRPS_BIN_DIR='/opt/onebox-frp' \
        ONEBOX_FRPS_WEB_VAR='/var/lib/onebox-frp' ONEBOX_FRPS_LOG_DIR='/var/log/onebox-frp' \
        ONEBOX_FRPS_RUN_DIR='/run/onebox-frp' ONEBOX_INIT='none'";

    #[test]
    fn renders_the_documented_shape() {
        let tag = Tag::boot("onebox-xray").unwrap();
        let got = line(
            "@reboot",
            &paths(),
            InitSystem::None,
            &["service", "onebox-xray", "start"],
            Path::new("/var/log/onebox/boot.log"),
            &tag,
        )
        .unwrap();
        assert_eq!(
            got,
            format!(
                "@reboot mkdir -p '/var/log/onebox' 2>/dev/null; PATH={SAFE_PATH} {ENV_NONE} \
                 '/usr/local/bin/onebox' service onebox-xray start >>'/var/log/onebox/boot.log' \
                 2>&1 # onebox:boot:onebox-xray"
            )
        );
        let renew = line(
            "17 4 * * *",
            &paths(),
            InitSystem::Systemd,
            &["renew", "--cron"],
            Path::new("/var/log/onebox/renew.log"),
            &Tag::renew(),
        )
        .unwrap();
        assert!(
            renew.starts_with(
                "17 4 * * * mkdir -p '/var/log/onebox' 2>/dev/null; PATH=/usr/local/sbin:"
            ),
            "{renew}"
        );
        assert!(renew.contains("ONEBOX_INIT='systemd' '/usr/local/bin/onebox' renew --cron >>"));
        assert!(renew.ends_with(">>'/var/log/onebox/renew.log' 2>&1 # onebox:renew"));
    }

    #[test]
    fn quotes_and_escapes_percent() {
        let mut p = paths();
        p.executable = "/opt/my tools/50%/onebox".into();
        let got = line(
            "0 3 * * 1",
            &p,
            InitSystem::Openrc,
            &["frps", "it's", "a b", "100%"],
            Path::new("/var/log/x%y/run.log"),
            &Tag::frp_renew(),
        )
        .unwrap();
        assert!(
            got.starts_with(r"0 3 * * 1 mkdir -p '/var/log/x\%y' 2>/dev/null; PATH="),
            "{got}"
        );
        assert!(
            got.contains(r"ONEBOX_EXE='/opt/my tools/50\%/onebox'"),
            "{got}"
        );
        assert!(got.contains(r"'/opt/my tools/50\%/onebox' frps 'it'\''s' 'a b' '100\%'"));
        assert!(got.contains(r">>'/var/log/x\%y/run.log' 2>&1 # onebox:frp-renew"));
        assert_eq!(got.matches('%').count(), got.matches(r"\%").count());
    }

    /// The shell runs no command whose redirection it cannot open: the
    /// line recreates a vanished log directory (tmpfs `/var/log`, deleted
    /// by an administrator) instead of silently skipping the job.
    #[test]
    fn jobs_run_when_the_log_directory_is_gone() {
        let tmp = crate::sys::fs::TempDir::new("cron-log").unwrap();
        let run = |command: &str| {
            std::process::Command::new("sh")
                .args(["-c", command])
                .stderr(std::process::Stdio::null())
                .status()
                .unwrap()
        };
        let read = |log: &Path| std::fs::read_to_string(log).unwrap();
        let args = ["-c".to_owned(), "echo ran".to_owned()];
        let env = [("ONEBOX_DIR".to_owned(), "/etc/onebox".to_owned())];
        // What earlier builds wrote: the job never starts.
        let old = tmp.join("old/renew.log");
        run(&job_command(&env, "/bin/sh", &args, &old.to_string_lossy()));
        assert!(!old.exists());
        for log in [tmp.join("new/renew.log"), tmp.join("deep/onebox/renew.log")] {
            let command = command(&env, "/bin/sh", &args, &log.to_string_lossy());
            assert!(run(&command).success(), "{command}");
            assert_eq!(read(&log), "ran\n", "{command}");
            // An existing directory and log are kept and appended to.
            assert!(run(&command).success());
            assert_eq!(read(&log), "ran\nran\n");
        }
    }

    #[test]
    fn rejects_bad_schedules_logs_and_control_characters() {
        let tag = Tag::renew();
        let log = Path::new("/var/log/onebox/renew.log");
        for schedule in [
            "",
            "@often",
            "* * * *",
            "* * * * * *",
            "1  2 * * *",
            "* * * * ;",
            "0 4 * * *\n",
        ] {
            assert!(
                line(schedule, &paths(), InitSystem::None, &[], log, &tag).is_err(),
                "{schedule:?}"
            );
        }
        for schedule in ["@reboot", "@daily", "*/5 1-3 * jan mon,tue"] {
            assert!(line(schedule, &paths(), InitSystem::None, &[], log, &tag).is_ok());
        }
        assert!(line(
            "@daily",
            &paths(),
            InitSystem::None,
            &[],
            Path::new("x.log"),
            &tag
        )
        .is_err());
        assert!(line("@daily", &paths(), InitSystem::None, &["a\nb"], log, &tag).is_err());
    }
}
