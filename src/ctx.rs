//! The context passed to every operation: paths, process execution and the
//! interaction policy. Tests build one with `Ctx::test`.

use crate::error::{Error, Result};
use crate::paths::Paths;
use crate::sys::exec::{Cmd, Exec, Output};
use crate::ui::Prompter;
use std::sync::Arc;

#[derive(Clone)]
pub struct Ctx {
    pub paths: Paths,
    pub exec: Arc<dyn Exec>,
    pub ui: Arc<dyn Prompter>,
}

impl Ctx {
    /// Production context. `assume_yes` comes from `-y/--yes` or `ONEBOX_AUTO=1`.
    pub fn system(assume_yes: bool) -> Result<Ctx> {
        Ok(Ctx {
            paths: Paths::from_env()?,
            exec: Arc::new(crate::sys::exec::SystemExec),
            ui: crate::ui::system_prompter(assume_yes),
        })
    }

    /// Run a command; a non-zero exit status is NOT an error.
    pub fn run(&self, cmd: &Cmd) -> Result<Output> {
        self.exec.run(cmd)
    }

    /// Run a command and return stdout; a non-zero exit becomes `Error::Command`.
    pub fn check(&self, cmd: &Cmd) -> Result<String> {
        let out = self.exec.run(cmd)?;
        if out.ok() {
            Ok(out.stdout)
        } else {
            let detail = if out.stderr.trim().is_empty() {
                out.stdout
            } else {
                out.stderr
            };
            Err(Error::Command {
                program: cmd.program_name(),
                code: out.code,
                detail,
            })
        }
    }

    pub fn has(&self, program: &str) -> bool {
        self.exec.which(program).is_some()
    }
}
