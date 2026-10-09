//! `doctor` and `support` with the feature modules' checks.
//!
//! `diag` never imports a feature module (they depend on it for
//! [`Check`]), so the providers are listed here and passed through
//! [`diag::doctor_with`] / [`diag::support_command_with`]; the specs are
//! `diag`'s own with the handlers swapped.

use crate::cert::Engine;
use crate::cli::args::{CommandSpec, Matches};
use crate::ctx::Ctx;
use crate::diag::{self, Check, CheckFn, Doctor};
use crate::domain::NodeConfig;
use crate::error::Result;

pub const DOCTOR: CommandSpec = diag::DOCTOR.handler(doctor);
pub const SUPPORT: CommandSpec = diag::SUPPORT.handler(support);

/// Run after the built-in checks, in this order, by both commands.
pub const PROVIDERS: &[CheckFn] = &[subscription_checks, frp_checks];

fn doctor(ctx: &Ctx, _matches: &Matches) -> Result<()> {
    diag::doctor_with(ctx, PROVIDERS)
}

fn support(ctx: &Ctx, _matches: &Matches) -> Result<()> {
    diag::support_command_with(ctx, PROVIDERS)
}

/// The subscription's lines (none without a loadable configuration or
/// with the subscription off), queried through the doctor's init system.
fn subscription_checks(doctor: &Doctor, cfg: Option<&NodeConfig>) -> Vec<Check> {
    let Some(cfg) = cfg else {
        return Vec::new();
    };
    let mut engine = Engine::system(doctor.ctx);
    engine.init = doctor.init;
    crate::subscription::checks::checks_with(&engine, cfg)
}

/// FRP's lines (none when FRP is not installed and left no journal).
fn frp_checks(doctor: &Doctor, _cfg: Option<&NodeConfig>) -> Vec<Check> {
    let mut rt = crate::frp::runtime::Runtime::system(doctor.ctx);
    rt.init = doctor.init;
    crate::frp::checks::checks_with(&rt)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::args::Group;

    #[test]
    fn specs_keep_diag_metadata_with_provider_handlers() {
        for (ours, theirs) in [(&DOCTOR, &diag::DOCTOR), (&SUPPORT, &diag::SUPPORT)] {
            assert_eq!(ours.name, theirs.name);
            assert_eq!(ours.summary, theirs.summary);
            assert_eq!(ours.group, Group::Diagnose);
            assert!(ours.root.required(&Matches::default()));
            assert_ne!(
                ours.handler.map(|h| h as usize),
                theirs.handler.map(|h| h as usize),
                "{} must run the providers",
                ours.name
            );
        }
        assert_eq!(PROVIDERS.len(), 2);
    }

    #[test]
    fn providers_are_silent_on_an_empty_host() {
        let dir = crate::sys::fs::TempDir::new("diagnose-providers").unwrap();
        let (ctx, _, _) = Ctx::test(dir.path());
        let doctor = Doctor {
            ctx: &ctx,
            init: crate::host::init::InitSystem::Systemd,
            now: 0,
        };
        for provider in PROVIDERS {
            assert!(provider(&doctor, None).is_empty());
        }
    }

    #[test]
    fn a_crashed_frp_install_on_a_host_without_a_node_is_diagnosed() {
        let dir = crate::sys::fs::TempDir::new("diagnose-frp-journal").unwrap();
        let (ctx, fake, _) = Ctx::test(dir.path());
        fake.on(
            "onebox",
            &["version"],
            crate::sys::exec::Output::success(crate::VERSION),
        );
        // `frps install` died before writing its state: only the journal.
        let parent = ctx.paths.frp_lock().parent().unwrap().to_path_buf();
        std::fs::create_dir_all(parent).unwrap();
        crate::frp::journal::create(&ctx.paths, "安装", Default::default(), &[]).unwrap();
        let doctor = Doctor {
            ctx: &ctx,
            init: crate::host::init::InitSystem::Systemd,
            now: 0,
        };
        let _signals = crate::diag::fixture::signals();
        let checks = doctor.diagnose(PROVIDERS, &mut |_| {}).unwrap().checks;
        let journal = checks.iter().find(|c| c.name == "FRP 事务").unwrap();
        assert_eq!(
            journal,
            &Check::fail(
                "FRP 事务",
                "未完成的 FRP 事务（安装，阶段 prepared）；请执行 onebox recover"
            )
        );
    }
}
