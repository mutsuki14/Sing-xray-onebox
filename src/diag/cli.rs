//! Command specs and handlers of `doctor` and `support`; the CLI registry
//! lists [`COMMANDS`]. Both read root-owned state, so both require root
//! (v2 checked nothing and failed on permissions).
//!
//! The CLI passes the feature modules' check providers by keeping the
//! specs and swapping the handlers: `DOCTOR.handler(h)` with `h` calling
//! [`super::doctor_with`], `SUPPORT.handler(h)` with `h` calling
//! [`support_command_with`] (see [`super::registry`]).

use super::CheckFn;
use crate::cli::args::{CommandSpec, Group, Matches, Root};
use crate::ctx::Ctx;
use crate::error::Result;
use crate::ui::out;

pub const DOCTOR: CommandSpec = CommandSpec::new(
    "doctor",
    Group::Diagnose,
    "体检：内核、配置、服务、证书、网站、订阅、FRP 与未完成事务",
)
.root(Root::Required)
.handler(doctor_command);

pub const SUPPORT: CommandSpec = CommandSpec::new(
    "support",
    Group::Diagnose,
    "生成脱敏诊断文件（不含凭据、IP 地址和域名，不会自动上传）",
)
.root(Root::Required)
.handler(support_command);

pub const COMMANDS: [CommandSpec; 2] = [DOCTOR, SUPPORT];

fn doctor_command(ctx: &Ctx, _matches: &Matches) -> Result<()> {
    super::doctor(ctx)
}

fn support_command(ctx: &Ctx, _matches: &Matches) -> Result<()> {
    support_command_with(ctx, super::EXTRA_CHECKS)
}

/// `onebox support` with explicit providers: writes the report and prints
/// `已生成脱敏诊断文件: {path}` on stdout (v2 wording).
pub fn support_command_with(ctx: &Ctx, extra: &[CheckFn]) -> Result<()> {
    let path = super::support_with(ctx, extra)?;
    out::data(&support_message(&path))
}

pub fn support_message(path: &std::path::Path) -> String {
    format!("已生成脱敏诊断文件: {}", path.display())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::args::{find, parse, Globals};

    fn words(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn specs_parse_and_require_root() {
        for name in ["doctor", "support"] {
            let spec = find(&COMMANDS, name).unwrap();
            assert!(spec.root.required(&Matches::default()), "{name}");
            assert!(spec.handler.is_some());
            assert_eq!(spec.group, Group::Diagnose);
            let invocation = parse(&COMMANDS, &words(&[name]), Globals::default()).unwrap();
            assert_eq!(invocation.matches.path, [name]);
            assert!(!invocation.help);
        }
    }

    #[test]
    fn stray_arguments_and_options_are_rejected() {
        let err = parse(&COMMANDS, &words(&["doctor", "x"]), Globals::default()).unwrap_err();
        assert_eq!(err.to_string(), "多余的参数: x");
        let err = parse(
            &COMMANDS,
            &words(&["support", "--json"]),
            Globals::default(),
        )
        .unwrap_err();
        assert_eq!(
            err.to_string(),
            "support 不支持选项 --json；请执行 onebox support --help"
        );
        let err = parse(
            &COMMANDS,
            &words(&["doctor", "--dry-run"]),
            Globals::default(),
        )
        .unwrap_err();
        assert_eq!(err.to_string(), "此命令不支持 --dry-run");
        let help = parse(&COMMANDS, &words(&["doctor", "--help"]), Globals::default()).unwrap();
        assert!(help.help);
    }

    #[test]
    fn support_message_is_v2_wording() {
        assert_eq!(
            support_message(std::path::Path::new("/etc/onebox/support-1-ab.json")),
            "已生成脱敏诊断文件: /etc/onebox/support-1-ab.json"
        );
    }
}
