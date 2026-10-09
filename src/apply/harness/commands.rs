//! The command fakes behind the test host's [`FakeExec`]: injected
//! failures, `systemctl`, `iptables`, `ip` and the core binaries.

use super::{lock, SING_BOX, XRAY};
use crate::domain::protocol::Core;
use crate::paths::Paths;
use crate::sys::exec::{FakeExec, Output};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};

/// One fake systemd unit's state.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Unit {
    pub active: bool,
    pub enabled: bool,
}

pub type Units = Arc<Mutex<BTreeMap<String, Unit>>>;

/// One injected command failure: a needle of the command line, whether it
/// fires only once, and whether the command is "killed by Ctrl+C" (SIGINT
/// raised in this process, as the forwarding wait scope would see it).
#[derive(Clone, Debug)]
pub struct CommandFault {
    pub needle: String,
    pub once: bool,
    pub interrupt: bool,
}

pub type Faults = Arc<Mutex<Vec<CommandFault>>>;

/// For each probed needle, whether INT, TERM and HUP were all blocked in
/// the calling thread each time a command containing it ran (the command
/// itself runs as usual).
pub type MaskProbes = Arc<Mutex<Vec<(String, Vec<bool>)>>>;

/// Whether INT, TERM and HUP are all blocked in the calling thread.
pub fn cancel_signals_blocked() -> bool {
    // SAFETY: queries this thread's mask into a zeroed sigset.
    unsafe {
        let mut current: libc::sigset_t = std::mem::zeroed();
        libc::pthread_sigmask(libc::SIG_SETMASK, std::ptr::null(), &mut current);
        [libc::SIGINT, libc::SIGTERM, libc::SIGHUP]
            .iter()
            .all(|s| libc::sigismember(&current, *s) == 1)
    }
}

/// A rule that never matches: it only records the signal mask of probed
/// commands (installed before every other rule).
pub(super) fn probe_rule(exec: &FakeExec) -> MaskProbes {
    let probes: MaskProbes = Arc::default();
    let shared = probes.clone();
    exec.on_fn(
        move |cmd| {
            let line = cmd.display();
            for (needle, seen) in lock(&shared).iter_mut() {
                if line.contains(needle.as_str()) {
                    seen.push(cancel_signals_blocked());
                }
            }
            false
        },
        |cmd| Ok(Output::failure(127, format!("probe: {}", cmd.display()))),
    );
    probes
}

/// The first rule: commands containing an injected needle fail (one-shot
/// faults are consumed by their first match).
pub(super) fn fault_rule(exec: &FakeExec) -> Faults {
    let faults: Faults = Arc::default();
    let shared = faults.clone();
    let interrupted = Arc::new(Mutex::new(false));
    let raise = interrupted.clone();
    exec.on_fn(
        move |cmd| {
            let line = cmd.display();
            let mut faults = lock(&shared);
            match faults.iter().position(|f| line.contains(f.needle.as_str())) {
                Some(i) => {
                    *lock(&interrupted) = faults[i].interrupt;
                    if faults[i].once {
                        faults.remove(i);
                    }
                    true
                }
                None => false,
            }
        },
        move |cmd| {
            if std::mem::take(&mut *lock(&raise)) {
                // SAFETY: raising SIGINT while the apply's signal scope has a
                // recording handler installed (the test holds TEST_LOCK).
                unsafe {
                    libc::raise(libc::SIGINT);
                }
                return Ok(Output::failure(130, "interrupted"));
            }
            Ok(Output::failure(
                1,
                format!("injected failure: {}", cmd.display()),
            ))
        },
    );
    faults
}

/// Units that crash right after every start: the first `is-active` query
/// after a start still sees them up (the start "succeeded"), later queries
/// see them stopped.
pub type Crashing = Arc<Mutex<BTreeSet<String>>>;

/// `systemctl` over an in-memory unit table (a cron daemon runs).
pub(super) fn fake_systemd(exec: &FakeExec) -> (Units, Crashing) {
    let running = Unit {
        active: true,
        enabled: true,
    };
    let units: Units = Arc::new(Mutex::new(BTreeMap::from([("cron".to_owned(), running)])));
    let crashing: Crashing = Arc::default();
    let dying: Crashing = Arc::default();
    let (shared, crash) = (units.clone(), crashing.clone());
    exec.on_fn(
        |cmd| cmd.program == "systemctl",
        move |cmd| Ok(systemctl(&shared, &crash, &dying, &cmd.args)),
    );
    (units, crashing)
}

fn systemctl(units: &Units, crashing: &Crashing, dying: &Crashing, args: &[String]) -> Output {
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let mut table = lock(units);
    if let ["start" | "restart", name] = args.as_slice() {
        if lock(crashing).contains(*name) {
            lock(dying).insert((*name).to_owned());
        }
    }
    let mut set = |name: &str, f: &dyn Fn(&mut Unit)| {
        f(table.entry(name.to_owned()).or_default());
        Output::success("")
    };
    match args.as_slice() {
        ["daemon-reload"] => Output::success(""),
        ["is-active", "--quiet", name] => {
            let up = table.get(*name).is_some_and(|u| u.active);
            if up && lock(dying).remove(*name) {
                // Answered "up" once; the process is gone afterwards.
                table.entry((*name).to_owned()).or_default().active = false;
            }
            if up {
                Output::success("")
            } else {
                Output::failure(3, "")
            }
        }
        ["is-enabled", name] => match table.get(*name) {
            Some(u) if u.enabled => Output::success("enabled\n"),
            _ => Output::failure(1, "disabled\n"),
        },
        ["start" | "restart", name] => set(name, &|u| u.active = true),
        ["stop", name] => set(name, &|u| u.active = false),
        ["enable", name] => set(name, &|u| u.enabled = true),
        ["disable", name] => set(name, &|u| u.enabled = false),
        other => Output::failure(1, format!("fake systemctl: {other:?}")),
    }
}

/// `iptables` (filter and nat) over an in-memory rule set; `ip6tables` is
/// absent (the fake system has no IPv6).
pub(super) fn fake_iptables(exec: &FakeExec) -> Arc<Mutex<BTreeSet<String>>> {
    let rules: Arc<Mutex<BTreeSet<String>>> = Arc::default();
    exec.provide("iptables");
    let shared = rules.clone();
    exec.on_fn(
        |cmd| cmd.program == "iptables",
        move |cmd| Ok(iptables(&shared, &cmd.args)),
    );
    rules
}

fn iptables(rules: &Mutex<BTreeSet<String>>, args: &[String]) -> Output {
    let mut a: Vec<&str> = args.iter().map(String::as_str).collect();
    if a.starts_with(&["-w", "5"]) {
        a.drain(..2);
    }
    let table = if a.first() == Some(&"-t") {
        let t = a[1];
        a.drain(..2);
        t
    } else {
        "filter"
    };
    let Some((op, rest)) = a.split_first() else {
        return Output::failure(2, "fake iptables: no operation");
    };
    let Some((chain, mut spec)) = rest.split_first() else {
        return Output::success("");
    };
    if *op == "-I" && spec.first().is_some_and(|w| w.parse::<u32>().is_ok()) {
        spec = &spec[1..];
    }
    let key = format!("{table} {chain} {}", spec.join(" "));
    let mut set = lock(rules);
    match *op {
        "-S" => Output::success(format!("-P {chain} ACCEPT\n")),
        "-I" | "-A" => {
            set.insert(key);
            Output::success("")
        }
        "-C" if set.contains(&key) => Output::success(""),
        "-C" => Output::failure(1, "Bad rule (does a matching rule exist in that chain?)."),
        "-D" if set.remove(&key) => Output::success(""),
        _ => Output::failure(1, "fake iptables: no such rule"),
    }
}

pub(super) fn fake_ip(exec: &FakeExec) -> Arc<Mutex<String>> {
    let ips = Arc::new(Mutex::new(super::IPS.to_owned()));
    let shared = ips.clone();
    exec.on_fn(
        |cmd| cmd.program == "ip",
        move |_| Ok(Output::success(lock(&shared).clone())),
    );
    ips
}

/// Core binaries (installed when `seed`) answering `version` and config
/// checks.
pub(super) fn fake_cores(exec: &FakeExec, paths: &Paths, seed: bool) {
    for (core, bytes) in [(Core::Singbox, SING_BOX), (Core::Xray, XRAY)] {
        if seed {
            crate::apply::testing::file(&paths.core_bin(core), 0o755, bytes);
        }
    }
    exec.on(
        "sing-box",
        &["version"],
        Output::success("sing-box version 1.14.2\n"),
    )
    .on("sing-box", &["check"], Output::success(""))
    .on(
        "xray",
        &["version"],
        Output::success("Xray 26.3.27 (Xray, Penetrates Everything.) 0 (go1.24 linux/amd64)\n"),
    )
    .on(
        "xray",
        &["run", "-test"],
        Output::success("Configuration OK."),
    );
}
