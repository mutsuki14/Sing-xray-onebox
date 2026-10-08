//! Process identity under `/proc` (read below `Paths::system_root`, so tests
//! use fixture trees): start time, executable and argv of a PID, and the
//! rules deciding whether that process is the service's own.

use crate::host::service::{arg_after, ServiceDef};
use std::fs;
use std::path::{Path, PathBuf};

/// `/proc/{pid}` below `system_root`.
fn proc_dir(system_root: &Path, pid: u32) -> PathBuf {
    system_root.join("proc").join(pid.to_string())
}

/// Start time (field 22, clock ticks since boot) of a live process; `None`
/// when it does not exist or is a zombie/dead (state Z, X or x).
pub fn process_start(system_root: &Path, pid: u32) -> Option<u64> {
    let stat = fs::read_to_string(proc_dir(system_root, pid).join("stat")).ok()?;
    parse_start(&stat)
}

/// Parse `/proc/PID/stat`. The command name (field 2) may contain spaces
/// and parentheses, so fields are counted after the last `)`.
pub fn parse_start(stat: &str) -> Option<u64> {
    let mut fields = stat.rsplit_once(')')?.1.split_whitespace();
    if matches!(fields.next()?, "Z" | "X" | "x") {
        return None;
    }
    // After the state (field 3) come fields 4..; starttime is field 22.
    fields.nth(18)?.parse().ok()
}

/// argv of `pid` (empty entries, e.g. title padding, removed).
pub fn process_argv(system_root: &Path, pid: u32) -> Option<Vec<Vec<u8>>> {
    let raw = fs::read(proc_dir(system_root, pid).join("cmdline")).ok()?;
    Some(split_cmdline(&raw))
}

pub fn split_cmdline(raw: &[u8]) -> Vec<Vec<u8>> {
    raw.split(|b| *b == 0)
        .filter(|arg| !arg.is_empty())
        .map(<[u8]>::to_vec)
        .collect()
}

/// `/proc/PID/exe` names `program`. An atomically replaced binary shows as
/// `… (deleted)`, and a binary may be briefly absent during replacement,
/// so the expected path falls back to the canonical directory + file name.
pub fn executable_matches(system_root: &Path, pid: u32, program: &Path) -> bool {
    let Ok(link) = fs::read_link(proc_dir(system_root, pid).join("exe")) else {
        return false;
    };
    let link = link.to_string_lossy();
    let actual = Path::new(link.trim_end_matches(" (deleted)"));
    let expected = fs::canonicalize(program).ok().or_else(|| {
        let parent = program.parent()?.canonicalize().ok()?;
        Some(parent.join(program.file_name()?))
    });
    expected.is_some_and(|expected| actual == expected)
}

/// Whether `argv` is an invocation of `def` (see [`Identity`] for the
/// rules).
///
/// [`Identity`]: crate::host::service::Identity
pub fn command_matches(def: &ServiceDef, argv: &[Vec<u8>]) -> bool {
    if def.identity().nginx_title && argv.len() == 1 {
        return nginx_title_matches(def, &argv[0]);
    }
    if argv.is_empty() {
        return false;
    }
    if let Some(sub) = &def.identity().subcommand {
        if argv.get(1).map(Vec::as_slice) != Some(sub.as_bytes()) {
            return false;
        }
    }
    match &def.identity().config {
        Some(config) => config_matches(argv, &config.to_string_lossy()),
        None => {
            argv.len() == def.args().len() + 1
                && argv[1..]
                    .iter()
                    .zip(def.args())
                    .all(|(actual, expected)| actual.as_slice() == expected.as_bytes())
        }
    }
}

/// Every config option names exactly `config`, and at least one exists
/// (`--note CONFIG` or a trailing `--config other` do not qualify).
fn config_matches(argv: &[Vec<u8>], config: &str) -> bool {
    let config = config.as_bytes();
    let mut found = false;
    for (index, arg) in argv.iter().enumerate() {
        let arg = arg.as_slice();
        if matches!(arg, b"-c" | b"--config" | b"-config") {
            if argv.get(index + 1).map(Vec::as_slice) != Some(config) {
                return false;
            }
            found = true;
        }
        for prefix in [&b"--config="[..], b"-config="] {
            if let Some(value) = arg.strip_prefix(prefix) {
                if value != config {
                    return false;
                }
                found = true;
            }
        }
    }
    found
}

/// nginx rewrites argv into `nginx: master process {argv joined}`. Only a
/// complete known invocation matches, never a substring (another website's
/// nginx must not be adopted). The prefix may carry a trailing slash and
/// `-g daemon off;` may be absent (older Onebox versions).
fn nginx_title_matches(def: &ServiceDef, title: &[u8]) -> bool {
    let program = def.program().to_string_lossy();
    let mut candidates = vec![format!(
        "nginx: master process {program} {}",
        def.args().join(" ")
    )];
    if let (Some(prefix), Some(config)) = (arg_after(def.args(), "-p"), arg_after(def.args(), "-c"))
    {
        let prefix = prefix.trim_end_matches('/');
        for slash in ["", "/"] {
            for foreground in ["", " -g daemon off;"] {
                candidates.push(format!(
                    "nginx: master process {program} -p {prefix}{slash} -c {config}{foreground}"
                ));
            }
        }
    }
    candidates.iter().any(|c| c.as_bytes() == title)
}

#[cfg(test)]
mod tests;
