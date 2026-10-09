//! Real-core doctor checks (`#[ignore]`): the core checks run the tested
//! sing-box and Xray binaries against rendered server configurations, in a
//! private work directory, and report a broken configuration with the
//! core's own message.
//!
//! Run: `ONEBOX_TEST_SINGBOX=/path/sing-box ONEBOX_TEST_XRAY=/path/xray
//! cargo test -- --ignored diag::realcore`. Unset variables skip the test.

use super::{node, CheckStatus};
use crate::ctx::Ctx;
use crate::domain::{fixtures, Core, Protocol};
use crate::render::{self, NodeSpec};
use crate::sys::exec::SystemExec;
use crate::sys::fs::TempDir;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::Arc;

fn tool(var: &str) -> Option<PathBuf> {
    let path = std::env::var_os(var).filter(|p| !p.is_empty());
    if path.is_none() {
        eprintln!("跳过：未设置 {var}");
    }
    path.map(PathBuf::from)
}

#[test]
#[ignore = "needs ONEBOX_TEST_SINGBOX and ONEBOX_TEST_XRAY"]
fn real_cores_accept_rendered_configs_and_reject_broken_ones() {
    let (Some(singbox), Some(xray)) = (tool("ONEBOX_TEST_SINGBOX"), tool("ONEBOX_TEST_XRAY"))
    else {
        return;
    };
    let dir = TempDir::new("diag-realcore").unwrap();
    let (mut ctx, _, _) = Ctx::test(dir.path());
    ctx.exec = Arc::new(SystemExec);
    let paths = ctx.paths.clone();
    let cfg = fixtures::config(&[
        (Protocol::VlessReality, 443, Core::Singbox),
        (Protocol::VlessXhttp, 2053, Core::Xray),
    ]);
    let spec = NodeSpec::new(&cfg, &paths, None).unwrap();
    fs::create_dir_all(&paths.bin).unwrap();
    fs::create_dir_all(&paths.root).unwrap();
    for (core, binary) in [(Core::Singbox, &singbox), (Core::Xray, &xray)] {
        let installed = paths.core_bin(core);
        fs::copy(binary, &installed).unwrap();
        fs::set_permissions(&installed, fs::Permissions::from_mode(0o755)).unwrap();
        let text = render::server_text(&spec, core).unwrap();
        fs::write(paths.core_config(core), text).unwrap();
    }
    let work = TempDir::new("diag-realcore-work").unwrap();
    let checks = node::core_checks(&ctx, &cfg, Ok(work.path()));
    assert_eq!(checks.len(), 4, "{checks:#?}");
    assert!(
        checks.iter().all(|c| c.status == CheckStatus::Pass),
        "{checks:#?}"
    );
    assert!(!paths.run.join("check").exists(), "G42");

    fs::write(
        paths.core_config(Core::Singbox),
        r#"{"inbounds":[{"type":"no-such-inbound"}]}"#,
    )
    .unwrap();
    fs::write(
        paths.core_config(Core::Xray),
        r#"{"inbounds":[{"port":0,"protocol":"vless"}"#,
    )
    .unwrap();
    let checks = node::core_checks(&ctx, &cfg, Ok(work.path()));
    for (index, prefix) in [(1, "sing-box 配置校验失败: "), (3, "Xray 配置校验失败: ")]
    {
        let check = &checks[index];
        assert_eq!(check.status, CheckStatus::Fail, "{check:?}");
        assert!(check.detail.starts_with(prefix), "{check:?}");
        assert!(
            check.detail.len() > prefix.len(),
            "the core's message is kept"
        );
    }
}
