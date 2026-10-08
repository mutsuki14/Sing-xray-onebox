//! A scripted `sysctl` for tests (used by the sysctl and BBR tests).

use crate::sys::exec::{Cmd, FakeExec, Output};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, MutexGuard};

/// What the next `sysctl -w` does.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum WriteFault {
    /// Apply the assignments before this index, then fail naming the key
    /// at the index (`FailAt(1)` = partial write, `FailAt(0)` = rejected).
    FailAt(usize),
    /// Report success without changing anything (read-back must notice).
    Ignore,
}

#[derive(Debug, Default)]
pub(crate) struct SysctlState {
    pub values: BTreeMap<String, String>,
    /// Consumed by the next `-w` call.
    pub next_write: Option<WriteFault>,
    /// Single-assignment writes of this key fail (restore failures).
    pub fail_restore: Option<String>,
    /// stderr of a failed write.
    pub write_error: String,
    /// Every `-w` call's assignments, in order.
    pub writes: Vec<Vec<String>>,
}

#[derive(Clone)]
pub(crate) struct FakeSysctl(Arc<Mutex<SysctlState>>);

impl FakeSysctl {
    /// Answer `sysctl -n` / `sysctl -w` on `exec` from an in-memory table.
    pub fn install(exec: &FakeExec, values: &[(&str, &str)]) -> FakeSysctl {
        let state = SysctlState {
            values: values
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            write_error: "injected failure".into(),
            ..SysctlState::default()
        };
        let fake = FakeSysctl(Arc::new(Mutex::new(state)));
        let model = fake.clone();
        exec.on_fn(
            |c| c.program_name() == "sysctl",
            move |c| Ok(model.answer(c)),
        );
        fake
    }

    pub fn state(&self) -> MutexGuard<'_, SysctlState> {
        self.0.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn get(&self, key: &str) -> String {
        self.state().values.get(key).cloned().unwrap_or_default()
    }

    fn answer(&self, c: &Cmd) -> Output {
        let mut state = self.state();
        match c.args.first().map(String::as_str) {
            Some("-n") => match c.args.get(1).and_then(|k| state.values.get(k)) {
                Some(value) => Output::success(format!("{value}\n")),
                None => Output::failure(255, "sysctl: cannot stat key"),
            },
            Some("-w") => write(&mut state, &c.args[1..]),
            _ => Output::failure(2, "unsupported"),
        }
    }
}

fn write(state: &mut SysctlState, assignments: &[String]) -> Output {
    state.writes.push(assignments.to_vec());
    let fault = state.next_write.take();
    let pairs: Vec<(String, String)> = assignments
        .iter()
        .filter_map(|a| a.split_once('='))
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    if pairs.len() == 1 && state.fail_restore.as_deref() == Some(pairs[0].0.as_str()) {
        return Output::failure(1, state.write_error.clone());
    }
    match fault {
        Some(WriteFault::Ignore) => Output::success(""),
        Some(WriteFault::FailAt(index)) => {
            for (k, v) in pairs.iter().take(index) {
                state.values.insert(k.clone(), v.clone());
            }
            let failing = pairs.get(index).map(|(k, _)| k.clone()).unwrap_or_default();
            Output::failure(
                1,
                format!("sysctl: setting key \"{failing}\": {}", state.write_error),
            )
        }
        None => {
            for (k, v) in pairs {
                state.values.insert(k, v);
            }
            Output::success("")
        }
    }
}
