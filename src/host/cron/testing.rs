//! Test support: a crontab held in memory behind [`FakeExec`] rules.

use crate::sys::exec::{FakeExec, Output};
use std::os::unix::fs::PermissionsExt;
use std::sync::{Arc, Mutex};

/// The fake crontab's state; `None` = the user has no crontab yet.
pub type CronState = Arc<Mutex<Option<String>>>;

/// Answer `crontab -l` from the state and `crontab FILE` by storing FILE
/// (which must be a private 0600 file). Also makes `crontab` available.
pub fn fake_crontab(exec: &FakeExec, initial: Option<&str>) -> CronState {
    let state: CronState = Arc::new(Mutex::new(initial.map(str::to_owned)));
    exec.provide("crontab");
    let list = state.clone();
    exec.on_fn(
        |cmd| cmd.program == "crontab" && cmd.args == ["-l"],
        move |_| {
            Ok(match list.lock().unwrap().as_ref() {
                Some(text) => Output::success(text.clone()),
                None => Output::failure(1, "no crontab for root\n"),
            })
        },
    );
    let install = state.clone();
    exec.on_fn(
        |cmd| cmd.program == "crontab" && cmd.args.len() == 1 && cmd.args[0] != "-l",
        move |cmd| {
            let path = std::path::Path::new(&cmd.args[0]);
            let mode = std::fs::metadata(path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "crontab temp files are private");
            *install.lock().unwrap() = Some(std::fs::read_to_string(path).unwrap());
            Ok(Output::success(""))
        },
    );
    state
}

/// The installed text (`""` when none).
pub fn text(state: &CronState) -> String {
    state.lock().unwrap().clone().unwrap_or_default()
}
