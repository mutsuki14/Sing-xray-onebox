//! The real-tool contract of the tests (one helper for every module): a
//! test that needs a real program or file takes its path from a variable
//! (`ONEBOX_TEST_SINGBOX`, `ONEBOX_NGINX_BIN`, …) or finds the program on
//! PATH, and skips with a message when it is missing — unless CI's
//! `ONEBOX_TEST_REQUIRE_FULL=1` turns the skip into a failure (panic), so a
//! renamed or forgotten variable can never make a CI test pass unrun.

use std::ffi::OsString;
use std::path::PathBuf;

/// CI's switch: every skip for a missing tool, variable or file fails.
pub const REQUIRE_FULL: &str = "ONEBOX_TEST_REQUIRE_FULL";

/// An environment lookup (the process environment outside these tests).
type Env<'a> = &'a dyn Fn(&str) -> Option<OsString>;

fn process(key: &str) -> Option<OsString> {
    std::env::var_os(key)
}

/// Skip for `reason` (printed), or panic under `ONEBOX_TEST_REQUIRE_FULL=1`.
pub fn skip(reason: &str) {
    skip_in(reason, &process);
}

fn skip_in(reason: &str, env: Env) {
    let required = env(REQUIRE_FULL).is_some_and(|v| v == "1");
    assert!(!required, "{reason}，但 {REQUIRE_FULL}=1");
    eprintln!("跳过：{reason}");
}

/// A real tool (or file) from `var`. Unset or empty: skip (returns `None`).
pub fn tool(var: &str) -> Option<PathBuf> {
    tool_in(var, &process)
}

fn tool_in(var: &str, env: Env) -> Option<PathBuf> {
    let path = env(var).filter(|v| !v.is_empty()).map(PathBuf::from);
    if path.is_none() {
        skip_in(&format!("未设置 {var}"), env);
    }
    path
}

/// Whether a program runs (tests that need curl/openssl skip without it).
pub fn have(program: &str) -> bool {
    let probe = if program == "openssl" {
        "version"
    } else {
        "--version"
    };
    let found = std::process::Command::new(program)
        .arg(probe)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok();
    if !found {
        skip(&format!("未找到 {program}"));
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The variable, `ONEBOX_TEST_REQUIRE_FULL`, and the lookup's result
    /// (`Err`: the test fails).
    type Case = (
        Option<&'static str>,
        Option<&'static str>,
        Result<Option<&'static str>, ()>,
    );

    #[test]
    fn missing_tools_skip_unless_ci_requires_them() {
        let cases: [Case; 6] = [
            (Some("/opt/xray"), None, Ok(Some("/opt/xray"))),
            (Some("/opt/xray"), Some("1"), Ok(Some("/opt/xray"))),
            (None, None, Ok(None)),
            (Some(""), Some("0"), Ok(None)),
            (None, Some("1"), Err(())),
            (Some(""), Some("1"), Err(())),
        ];
        for (value, full, want) in cases {
            let env = move |key: &str| match key {
                "ONEBOX_TEST_XRAY" => value.map(OsString::from),
                REQUIRE_FULL => full.map(OsString::from),
                _ => None,
            };
            let got = std::panic::catch_unwind(|| tool_in("ONEBOX_TEST_XRAY", &env)).map_err(drop);
            let want = want.map(|path| path.map(PathBuf::from));
            assert_eq!(got, want, "{value:?} {full:?}");
        }
    }
}
