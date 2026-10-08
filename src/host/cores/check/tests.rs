use super::*;
use crate::sys::exec::{FakeExec, Output};
use crate::sys::fs::TempDir;
use std::os::unix::fs::PermissionsExt;
use std::sync::Arc;

fn fixture() -> (TempDir, Ctx, Arc<FakeExec>) {
    let dir = TempDir::new("cores-check").unwrap();
    let (ctx, exec, _) = Ctx::test(dir.path());
    (dir, ctx, exec)
}

fn mode(path: &Path) -> u32 {
    std::fs::metadata(path).unwrap().permissions().mode() & 0o777
}

#[test]
fn check_config_commands_and_errors() {
    let (dir, ctx, exec) = fixture();
    let config = dir.join("sing-box.json");
    exec.on_fn(
        |c| c.program_name() == "sing-box" && c.args[0] == "check",
        |_| {
            Ok(Output::failure(
                1,
                "\x1b[31mFATAL\x1b[0m[0000] decode config at /x.json: inbounds[0]: unknown inbound type: bogus\n",
            ))
        },
    )
    .on_fn(
        |c| c.program_name() == "xray",
        |_| {
            Ok(Output {
                code: 23,
                stdout: "Xray 26.3.27 (Xray, Penetrates Everything.) d2758a0 (go1.26.1 linux/amd64)\n\
                         A unified platform for anti-censorship.\n\
                         2026/10/08 18:20:02.221502 [Info] infra/conf/serial: Reading config: x\n\
                         Failed to start: main: failed to load config files\n"
                    .into(),
                stderr: String::new(),
            })
        },
    );
    let err = check_config(&ctx, Core::Singbox, &config).unwrap_err();
    assert_eq!(
        err.to_string(),
        "sing-box 配置校验失败: FATAL[0000] decode config at /x.json: inbounds[0]: unknown inbound type: bogus"
    );
    let err = check_config(&ctx, Core::Xray, &config).unwrap_err();
    assert_eq!(
        err.to_string(),
        "Xray 配置校验失败: Failed to start: main: failed to load config files"
    );
    let check_dir = ctx.paths.run.join("check");
    let calls = exec.history();
    assert_eq!(
        calls[0],
        format!(
            "{} check -D {} -c {}",
            ctx.paths.core_bin(Core::Singbox).display(),
            check_dir.display(),
            config.display()
        )
    );
    assert_eq!(
        calls[1],
        format!(
            "{} run -test -c {}",
            ctx.paths.core_bin(Core::Xray).display(),
            config.display()
        )
    );
    assert_eq!(mode(&check_dir), 0o700);
    assert_eq!(mode(&ctx.paths.run), 0o755, "run root stays traversable");
    assert!(exec
        .calls()
        .iter()
        .all(|c| c.timeout == Some(CHECK_TIMEOUT)));

    let staged = dir.join("candidate/xray");
    let (_ok_dir, ok, ok_exec) = fixture();
    ok_exec.on("xray", &["run"], Output::success("Configuration OK."));
    check_config_with(&ok, Core::Xray, &staged, &config).unwrap();
    assert!(!ok.paths.run.exists(), "Xray needs no work dir");
    let (_quiet_dir, quiet, quiet_exec) = fixture();
    quiet_exec.on("sing-box", &[], Output::failure(2, ""));
    let err = check_config(&quiet, Core::Singbox, &config).unwrap_err();
    assert_eq!(err.to_string(), "sing-box 配置校验失败: 退出码 2");
}

#[test]
fn check_config_in_uses_the_callers_dir_and_creates_nothing() {
    let (dir, ctx, exec) = fixture();
    exec.on("sing-box", &["check"], Output::success("")).on(
        "xray",
        &["run"],
        Output::success("Configuration OK."),
    );
    let config = dir.join("sing-box.json");
    let private = TempDir::new("doctor-check").unwrap();
    for core in [Core::Singbox, Core::Xray] {
        check_config_in(&ctx, core, &config, private.path()).unwrap();
    }
    assert_eq!(
        exec.history(),
        [
            format!(
                "{} check -D {} -c {}",
                ctx.paths.core_bin(Core::Singbox).display(),
                private.path().display(),
                config.display()
            ),
            format!(
                "{} run -test -c {}",
                ctx.paths.core_bin(Core::Xray).display(),
                config.display()
            ),
        ]
    );
    assert!(!ctx.paths.run.exists(), "doctor must not create RUN/check");
    // Failures read exactly like check_config's.
    let (_bad_dir, bad, bad_exec) = fixture();
    bad_exec.on("sing-box", &["check"], Output::failure(1, "FATAL bad\n"));
    let err = check_config_in(&bad, Core::Singbox, &config, private.path()).unwrap_err();
    assert_eq!(err.to_string(), "sing-box 配置校验失败: FATAL bad");
    // The work dir must exist: it is the caller's private directory.
    let missing = dir.join("missing");
    let err = check_config_in(&ctx, Core::Singbox, &config, &missing).unwrap_err();
    assert_eq!(
        err.to_string(),
        format!("校验工作目录无效: {}", missing.display())
    );
}

#[test]
fn check_summary_keeps_the_tail() {
    let text: String = (1..=20).map(|i| format!("line {i}\n")).collect();
    assert_eq!(
        check_summary(Core::Singbox, &text),
        (13..=20)
            .map(|i| format!("line {i}"))
            .collect::<Vec<_>>()
            .join("\n")
    );
    assert_eq!(
        check_summary(Core::Singbox, "\x1b[1;31mred\x1b[0m\r\n"),
        "red"
    );
    assert_eq!(
        check_summary(Core::Xray, &"x".repeat(5000)).chars().count(),
        2000
    );
}
