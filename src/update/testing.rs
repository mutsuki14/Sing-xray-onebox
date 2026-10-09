//! Fixtures shared by the update tests: fake programs that answer
//! `version`, a recording apply engine, an injected environment.

use super::Engine;
use crate::apply::program_journal;
use crate::apply::ApplyRequest;
use crate::ctx::Ctx;
use crate::domain::protocol::Core;
use crate::error::{Error, Result, EXIT_STALE_PROCESS};
use crate::sys::exec::{FakeExec, Output};
use crate::sys::lock::FileLock;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

/// Separates a fake program's header from the `version` output it carries.
const MARKER: &[u8] = b"OUT:";

/// A fake ELF executable whose `version` prints `output` (see
/// [`answer_versions`]).
pub fn program(output: &str) -> Vec<u8> {
    let mut bytes = b"\x7fELF".to_vec();
    bytes.resize(32, 0);
    bytes.extend_from_slice(MARKER);
    bytes.extend_from_slice(output.as_bytes());
    bytes
}

/// `{path} version` prints what the file at `path` carries (fake programs
/// from [`program`]); a missing file fails like a missing program.
pub fn answer_versions(exec: &FakeExec) {
    exec.on_fn(
        |cmd| cmd.args == ["version"],
        |cmd| {
            let Ok(bytes) = fs::read(&cmd.program) else {
                return Ok(Output::failure(127, "not found"));
            };
            let at = bytes.windows(MARKER.len()).position(|w| w == MARKER);
            Ok(match at {
                Some(at) => Output::success(String::from_utf8_lossy(&bytes[at + MARKER.len()..])),
                None => Output::failure(1, "exec format error"),
            })
        },
    );
}

/// Write `bytes` to `path` with `mode`, creating parents.
pub fn write(path: &Path, mode: u32, bytes: &[u8]) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, bytes).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
}

pub fn mode(path: &Path) -> u32 {
    fs::metadata(path).unwrap().permissions().mode() & 0o7777
}

/// An environment lookup over fixed pairs.
#[derive(Clone, Debug, Default)]
pub struct FakeEnv(pub Vec<(String, String)>);

impl FakeEnv {
    pub fn set(&mut self, key: &str, value: impl Into<String>) {
        self.0.push((key.to_owned(), value.into()));
    }

    pub fn get(&self, key: &str) -> Option<String> {
        self.0
            .iter()
            .rev()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.clone())
    }
}

/// How [`FakeEngine::recover`] behaves.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Recover {
    /// Nothing to recover.
    Nothing,
    /// The real self-update recovery (`program_journal`); this test process
    /// is never the restored manager, so a recovery ends with exit 75.
    ProgramJournal,
    /// The real recovery, run as if this process were the restored manager
    /// (exit 75 becomes success).
    ProgramJournalCurrent,
    /// Fails while a self-update journal exists (a recovery that must be
    /// retried); succeeds otherwise.
    FailWithJournal(&'static str),
    /// Always fails (a pending journal that cannot be recovered).
    Refuse(&'static str),
}

/// What the engine received when asked to apply.
#[derive(Clone, Debug)]
pub struct Applied {
    pub request: ApplyRequest,
    /// The staged core binaries' contents at apply time.
    pub staged: Vec<(Core, PathBuf, Vec<u8>)>,
}

/// A recording [`Engine`].
pub struct FakeEngine {
    pub recover: Recover,
    pub apply_error: Option<&'static str>,
    recovered: Mutex<usize>,
    applied: Mutex<Vec<Applied>>,
}

impl FakeEngine {
    pub fn new(recover: Recover) -> FakeEngine {
        FakeEngine {
            recover,
            apply_error: None,
            recovered: Mutex::new(0),
            applied: Mutex::new(Vec::new()),
        }
    }

    pub fn recover_calls(&self) -> usize {
        *self.recovered.lock().unwrap()
    }

    pub fn applied(&self) -> Vec<Applied> {
        self.applied.lock().unwrap().clone()
    }
}

impl Engine for FakeEngine {
    fn recover(&self, ctx: &Ctx, lock: &FileLock) -> Result<()> {
        lock.verify(&ctx.paths.lock())?;
        *self.recovered.lock().unwrap() += 1;
        match self.recover {
            Recover::Nothing => Ok(()),
            Recover::ProgramJournal => program_journal::recover_program_locked(ctx, lock),
            Recover::ProgramJournalCurrent => {
                match program_journal::recover_program_locked(ctx, lock) {
                    Err(Error::Exit {
                        code: EXIT_STALE_PROCESS,
                        ..
                    }) => Ok(()),
                    other => other,
                }
            }
            Recover::FailWithJournal(message) => match program_journal::load(&ctx.paths)? {
                Some(_) => Err(Error::msg(message)),
                None => Ok(()),
            },
            Recover::Refuse(message) => Err(Error::msg(message)),
        }
    }

    fn apply(&self, ctx: &Ctx, lock: &FileLock, req: ApplyRequest) -> Result<()> {
        lock.verify(&ctx.paths.lock())?;
        let staged = req
            .intents
            .replace_cores
            .iter()
            .map(|(core, path)| (*core, path.clone(), fs::read(path).unwrap_or_default()))
            .collect();
        self.applied.lock().unwrap().push(Applied {
            request: req,
            staged,
        });
        match self.apply_error {
            Some(message) => Err(Error::msg(message)),
            None => Ok(()),
        }
    }
}
