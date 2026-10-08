//! The context passed to every operation: paths, process execution and the
//! interaction policy. Tests build one with `Ctx::test`.

use crate::error::{Error, Result};
use crate::paths::Paths;
use crate::sys::exec::{Cmd, Exec, FakeExec, Output};
use crate::ui::{Prompter, ScriptedPrompter};
use std::path::Path;
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

    /// Test context over `Paths::isolated(root)` with a [`FakeExec`] and an
    /// interactive [`ScriptedPrompter`] without answers; the returned handles
    /// script commands/answers and inspect what happened.
    pub fn test(root: &Path) -> (Ctx, Arc<FakeExec>, Arc<ScriptedPrompter>) {
        let exec = Arc::new(FakeExec::new());
        let ui = Arc::new(ScriptedPrompter::new(Vec::<String>::new()));
        let ctx = Ctx {
            paths: Paths::isolated(root),
            exec: exec.clone(),
            ui: ui.clone(),
        };
        (ctx, exec, ui)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_context_wires_fakes() {
        let root = Path::new("/tmp/onebox-ctx-test");
        let (ctx, exec, ui) = Ctx::test(root);
        assert_eq!(ctx.paths, Paths::isolated(root));
        exec.on("nginx", &["-t"], Output::success("ok"))
            .on("nginx", &[], Output::failure(1, "  bad config \n"))
            .provide("nginx");
        assert_eq!(ctx.check(&Cmd::new("nginx").arg("-t")).unwrap(), "ok");
        let err = ctx
            .check(&Cmd::new("/usr/sbin/nginx").arg("-s"))
            .unwrap_err();
        assert_eq!(err.to_string(), "nginx 执行失败 (1): bad config");
        assert!(!ctx.run(&Cmd::new("other")).unwrap().ok());
        assert!(ctx.has("nginx") && !ctx.has("caddy"));
        ui.push("答案");
        assert_eq!(ctx.ui.input("问题", "").unwrap(), "答案");
        assert_eq!(ui.prompts(), ["问题"]);
    }
}
