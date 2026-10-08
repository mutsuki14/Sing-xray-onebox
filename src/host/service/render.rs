//! Pure renderers: [`ServiceDef`] + service environment → systemd unit or
//! OpenRC script text, reproducing the v2 templates byte for byte (spec E
//! §3.4–3.5) except the fixes listed in the parent module.

use super::{validate_env, ServiceDef, ServiceKind, TARGETS};
use crate::error::Result;
use crate::sys::text::{quote_shell, quote_unit, quote_unit_env};

/// The open-files limit of every daemon (systemd `LimitNOFILE`, the OpenRC
/// `start_pre`, the supervisor), lowered to the hard limit where it cannot
/// be raised.
pub const NOFILE_LIMIT: u64 = 1_048_576;
/// Creates runtime directories under systemd (an absolute path: systemd
/// before 239 does not search `PATH`).
const SYSTEMD_MKDIR: &str = "/bin/mkdir";

/// Units a oneshot that restores firewall state waits for under systemd.
const SYSTEMD_FIREWALLS: [&str; 6] = [
    "netfilter-persistent",
    "iptables",
    "ip6tables",
    "nftables",
    "firewalld",
    "ufw",
];
/// The same under OpenRC (it has no netfilter-persistent script).
const OPENRC_FIREWALLS: [&str; 5] = ["iptables", "ip6tables", "nftables", "firewalld", "ufw"];

/// The systemd unit for `def` with `env` as `Environment=` lines.
pub fn render_systemd(def: &ServiceDef, env: &[(String, String)]) -> Result<String> {
    def.validate()?;
    validate_env(env)?;
    let deps: Vec<String> = def.after.iter().map(|d| systemd_dep(d)).collect();
    let mut after: Vec<String> = vec![TARGETS[0].into()];
    if def.kind == ServiceKind::Daemon {
        // Daemons resolve names at start (REALITY targets, ACME servers).
        after.push(TARGETS[1].into());
    }
    if def.after_firewall {
        after.extend(SYSTEMD_FIREWALLS.iter().map(|f| format!("{f}.service")));
    }
    after.extend(deps.iter().cloned());
    let wants: Vec<String> = std::iter::once(TARGETS[0].to_owned()).chain(deps).collect();

    let mut unit = format!(
        "[Unit]\nDescription={}\nAfter={}\nWants={}\n[Service]\n",
        def.description,
        after.join(" "),
        wants.join(" ")
    );
    unit.push_str(match def.kind {
        ServiceKind::Daemon => "Type=simple\n",
        ServiceKind::Oneshot => "Type=oneshot\nRemainAfterExit=yes\n",
    });
    for (key, value) in env {
        unit.push_str(&format!("Environment={}\n", quote_unit_env(key, value)?));
    }
    if !def.runtime_dirs.is_empty() {
        let mkdir = mkdir_argv(SYSTEMD_MKDIR, def);
        unit.push_str(&format!("ExecStartPre={}\n", systemd_command(&mkdir)?));
    }
    if let Some(pre) = &def.pre_start {
        unit.push_str(&format!("ExecStartPre={}\n", systemd_command(pre)?));
    }
    unit.push_str(&format!("ExecStart={}\n", systemd_exec(def)?));
    if def.kind == ServiceKind::Daemon {
        unit.push_str(&format!(
            "Restart=on-failure\nRestartSec=5s\nLimitNOFILE={NOFILE_LIMIT}\n"
        ));
        if let Some(status) = def.restart_prevent_status {
            unit.push_str(&format!("RestartPreventExitStatus={status}\n"));
        }
    }
    unit.push_str("[Install]\nWantedBy=multi-user.target\n");
    Ok(unit)
}

/// The OpenRC script for `def` with `env` exported at the top.
pub fn render_openrc(def: &ServiceDef, env: &[(String, String)]) -> Result<String> {
    def.validate()?;
    validate_env(env)?;
    let mut script = String::from("#!/sbin/openrc-run\n");
    for (key, value) in env {
        script.push_str(&format!("export {key}={}\n", quote_shell(value)));
    }
    script.push_str(&format!("name={}\n", quote_shell(&def.name)));
    match def.kind {
        ServiceKind::Daemon => script.push_str(&openrc_daemon(def)),
        ServiceKind::Oneshot => script.push_str(&openrc_oneshot(def)),
    }
    script.push_str(&openrc_start_pre(def));
    Ok(script)
}

/// `start_pre()`: the open-files limit (daemons; supervise-daemon and its
/// child inherit it from this shell), runtime directories, then the
/// pre-start command, whose status is the function's.
fn openrc_start_pre(def: &ServiceDef) -> String {
    let mut steps = Vec::new();
    if def.kind == ServiceKind::Daemon {
        steps.push(format!(
            "ulimit -n {NOFILE_LIMIT} 2>/dev/null || ulimit -n \"$(ulimit -Hn)\" 2>/dev/null || :"
        ));
    }
    if !def.runtime_dirs.is_empty() {
        let mkdir = mkdir_argv("mkdir", def);
        let words: Vec<String> = mkdir.iter().map(|w| shell_word(w)).collect();
        steps.push(format!("{} || return 1", words.join(" ")));
    }
    if let Some(pre) = &def.pre_start {
        steps.push(shell_command(pre));
    }
    if steps.is_empty() {
        return String::new();
    }
    let body: String = steps.iter().map(|s| format!("  {s}\n")).collect();
    format!("start_pre() {{\n{body}}}\n")
}

/// `mkdir -p -m 0755 DIR…`: missing parents get the umask default (0755
/// under systemd and OpenRC); existing directories keep their modes.
fn mkdir_argv(program: &str, def: &ServiceDef) -> Vec<String> {
    let mut argv: Vec<String> = [program, "-p", "-m", "0755"]
        .iter()
        .map(|w| w.to_string())
        .collect();
    argv.extend(
        def.runtime_dirs
            .iter()
            .map(|d| d.to_string_lossy().into_owned()),
    );
    argv
}

fn openrc_daemon(def: &ServiceDef) -> String {
    let program = def.program.to_string_lossy();
    // OpenRC evals command_args, so the joined quoted words are quoted again.
    let args = def.args.iter().map(|a| quote_shell(a)).collect::<Vec<_>>();
    let log = quote_shell(&def.log_file().to_string_lossy());
    format!(
        "supervisor=supervise-daemon\ncommand={}\ncommand_args={}\noutput_log={log}\n\
         error_log={log}\nrespawn_delay=5\nrespawn_max=10\nrespawn_period=120\n{}",
        quote_shell(&program),
        quote_shell(&args.join(" ")),
        openrc_depend(def)
    )
}

fn openrc_oneshot(def: &ServiceDef) -> String {
    let banner = def.banner.as_deref().unwrap_or(&def.description);
    let command = std::iter::once(def.program.to_string_lossy().into_owned())
        .chain(def.args.iter().cloned())
        .map(|w| quote_shell(&w))
        .collect::<Vec<_>>()
        .join(" ");
    format!(
        "{}start() {{\n  ebegin {}\n  {command}\n  eend $?\n}}\nstop() {{ return 0; }}\n",
        openrc_depend(def),
        quote_shell(banner)
    )
}

/// `depend()`: OpenRC has no systemd targets, so only Onebox services are
/// listed besides the fixed `net firewall dns` facilities.
fn openrc_depend(def: &ServiceDef) -> String {
    let mut after = vec!["net", "firewall", "dns"];
    if def.after_firewall {
        after.extend(OPENRC_FIREWALLS);
    }
    after.extend(
        def.after
            .iter()
            .filter(|d| d.starts_with("onebox-"))
            .map(String::as_str),
    );
    format!("depend() {{ want net; after {}; }}\n", after.join(" "))
}

fn systemd_dep(dependency: &str) -> String {
    if dependency.ends_with(".target") {
        dependency.to_owned()
    } else {
        format!("{dependency}.service")
    }
}

/// `ExecStart=`: every word quoted (`%` and `$` taken literally).
fn systemd_exec(def: &ServiceDef) -> Result<String> {
    let mut words = vec![quote_unit(&def.program.to_string_lossy())?];
    for arg in &def.args {
        words.push(quote_unit(arg)?);
    }
    Ok(words.join(" "))
}

/// A helper command line: the program quoted, plain words bare (v2 wrote
/// `ExecStartPre="/usr/local/bin/onebox" frps net-apply`).
fn systemd_command(argv: &[String]) -> Result<String> {
    let mut words = Vec::with_capacity(argv.len());
    for (index, word) in argv.iter().enumerate() {
        words.push(if index > 0 && plain_word(word) {
            word.clone()
        } else {
            quote_unit(word)?
        });
    }
    Ok(words.join(" "))
}

fn shell_command(argv: &[String]) -> String {
    argv.iter()
        .enumerate()
        .map(|(index, word)| {
            if index > 0 {
                shell_word(word)
            } else {
                quote_shell(word)
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// A plain word bare, anything else single-quoted.
fn shell_word(word: &str) -> String {
    if plain_word(word) {
        word.to_owned()
    } else {
        quote_shell(word)
    }
}

/// A word that needs no quoting for systemd or sh (no specifiers, no
/// expansions, no separators).
fn plain_word(word: &str) -> bool {
    !word.is_empty()
        && word
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_./:=@+,-".contains(&b))
}

#[cfg(test)]
mod tests;
