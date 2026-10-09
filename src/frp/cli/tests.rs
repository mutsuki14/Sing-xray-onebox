use super::*;
use crate::cli::args::{parse, Globals};
use crate::domain::config::PortRange;
use crate::frp::draft::ModeKind;
use crate::frp::testing::FakeHost;
use std::fs;

fn argv(words: &[&str]) -> Vec<String> {
    words.iter().map(|w| w.to_string()).collect()
}

/// Parse `onebox {words}` against the `frps` tree.
fn parsed(words: &[&str]) -> Result<(Matches, bool)> {
    let invocation = parse(
        std::slice::from_ref(&COMMAND),
        &argv(words),
        Globals::default(),
    )?;
    Ok((invocation.matches, invocation.help))
}

fn action(words: &[&str]) -> Result<Action> {
    let (m, _) = parsed(words)?;
    from_matches(&m, Path::new("/work"))
}

#[test]
fn v2_names_and_aliases() {
    assert_eq!(action(&["frps"]).unwrap(), Action::Menu);
    assert_eq!(action(&["frps", "menu"]).unwrap(), Action::Menu);
    assert_eq!(action(&["frps", "status"]).unwrap(), Action::Info);
    assert_eq!(action(&["frps", "logs"]).unwrap(), Action::Log);
    assert_eq!(action(&["frps", "help"]).unwrap(), Action::Help);
    assert_eq!(action(&["frps", "net-apply"]).unwrap(), Action::NetApply);
    assert_eq!(
        action(&["frps", "update", "v0.72.0"]).unwrap(),
        Action::Update(Some("0.72.0".into()))
    );
    assert_eq!(action(&["frps", "update"]).unwrap(), Action::Update(None));
    assert_eq!(
        action(&["frps", "renew", "--cron"]).unwrap(),
        Action::Renew { cron: true }
    );
    assert_eq!(
        action(&["frps", "stop"]).unwrap(),
        Action::Service(ServiceAction::Stop)
    );
    let Action::Configure {
        flags,
        dry_run,
        plan,
    } = action(&[
        "frps",
        "configure",
        "--mode",
        "tcp",
        "--allow-ports",
        "30000-30010",
        "--dry-run",
    ])
    .unwrap()
    else {
        panic!("configure")
    };
    assert!(dry_run && !plan);
    assert_eq!(flags.mode, Some(ModeKind::Tcp));
    assert_eq!(
        flags.range,
        Some(PortRange {
            start: 30000,
            end: 30010
        })
    );
    let Action::Client(req) = action(&[
        "frps",
        "export",
        "out",
        "--type",
        "udp",
        "--remote-port",
        "20001",
    ])
    .unwrap() else {
        panic!("client")
    };
    assert_eq!(req.output.as_deref(), Some("out"));
    assert_eq!(req.kind.as_deref(), Some("udp"));
    assert_eq!(req.remote_port, Some(20001));
    let (_, help) = parsed(&["frps", "--help"]).unwrap();
    assert!(help);
}

#[test]
fn options_are_checked_per_subcommand() {
    for (words, message) in [
        (
            &["frps", "start", "--mode", "tcp"][..],
            "frps start 不支持选项 --mode",
        ),
        (&["frps", "info", "--dry-run"], "此命令不支持 --dry-run"),
        (&["frps", "renew", "x"], "多余的参数: x"),
        (&["frps", "nope"], "未知子命令: nope"),
        (
            &["frps", "client", "--local-port", "x", "out"],
            "--local-port 的值无效: x",
        ),
        (&["frps", "plan", "--port"], "--port 需要参数"),
    ] {
        let err = parsed(words)
            .and_then(|(m, _)| from_matches(&m, Path::new("/")).map(drop))
            .unwrap_err()
            .to_string();
        assert!(err.starts_with(message), "{words:?}: {err}");
    }
}

#[test]
fn root_policy() {
    for (words, root) in [
        (&["frps"][..], false),
        (&["frps", "info"], false),
        (&["frps", "plan", "--mode", "tcp"], false),
        (&["frps", "install", "--dry-run"], false),
        (&["frps", "install"], true),
        (&["frps", "client", "x"], false),
        (&["frps", "log"], false),
        (&["frps", "start"], true),
        (&["frps", "renew", "--cron"], true),
        (&["frps", "uninstall"], true),
        (&["frps", "net-apply"], true),
    ] {
        let (m, _) = parsed(words).unwrap();
        let invocation = parse(
            std::slice::from_ref(&COMMAND),
            &argv(words),
            Globals::default(),
        )
        .unwrap();
        assert_eq!(
            crate::cli::registry::requires_root(invocation.spec, &m),
            root,
            "{words:?}"
        );
    }
}

fn session(h: &FakeHost, root: bool) -> Session<'_> {
    Session {
        rt: h.runtime(),
        cwd: h.dir.path().to_path_buf(),
        is_root: root,
    }
}

fn tcp_flags() -> Flags {
    Flags {
        mode: Some(ModeKind::Tcp),
        domain: Some("frp.example.com".into()),
        range: Some(PortRange {
            start: 20000,
            end: 20010,
        }),
        ..Flags::default()
    }
}

fn install(flags: Flags) -> Action {
    Action::Configure {
        flags,
        dry_run: false,
        plan: false,
    }
}

#[test]
fn previews_and_declined_confirmations_change_nothing() {
    let h = FakeHost::new();
    let s = session(&h, false);
    s.run(Action::Info).unwrap();
    s.run(Action::Configure {
        flags: tcp_flags(),
        dry_run: true,
        plan: true,
    })
    .unwrap();
    assert!(!h.ctx.paths.frp_root.exists());
    let s = session(&h, true);
    h.ui.push("n");
    s.run(install(tcp_flags())).unwrap();
    assert!(!h.ctx.paths.frp_root.exists());
    assert_eq!(h.ui.prompts(), [CONFIRM_DEPLOY]);
}

#[test]
fn unattended_install_update_and_uninstall() {
    let h = FakeHost::new();
    h.ui.set_assume_yes(true);
    let s = session(&h, true);
    s.run(install(tcp_flags())).unwrap();
    assert!(model::installed(&h.ctx.paths));
    assert!(h.running(FRPS));
    h.exec.clear_history();
    s.run(Action::Update(None)).unwrap();
    assert!(
        !h.history().iter().any(|c| c.starts_with("systemctl stop")),
        "the running version is kept as it is"
    );
    let out = h.dir.join("bundle");
    s.run(Action::Client(ExportRequest {
        output: Some(out.to_string_lossy().into_owned()),
        remote_port: Some(20003),
        ..ExportRequest::default()
    }))
    .unwrap();
    assert!(fs::read_to_string(out.join("frpc.toml"))
        .unwrap()
        .contains("remotePort = 20003"));
    s.run(Action::Uninstall).unwrap();
    assert!(!model::installed(&h.ctx.paths));
    assert_eq!(
        s.run(Action::Uninstall).unwrap_err().to_string(),
        model::NOT_INSTALLED
    );
}

fn cf_flags() -> Flags {
    Flags {
        domain: Some("frp.example.com".into()),
        web_domain: Some("app.example.com".into()),
        tls: Some(draft::TlsKind::Cloudflare),
        ..Flags::default()
    }
}

#[test]
fn cloudflare_credentials_are_never_written_before_the_transaction() {
    let h = FakeHost::new();
    // Unattended without credentials: refused before anything is written
    // (v2 created FRP_ROOT here and then refused every install, H-8.1#1).
    h.ui.set_assume_yes(true);
    let err = session(&h, true).run(install(cf_flags())).unwrap_err();
    assert_eq!(err.to_string(), cloudflare::MISSING);
    assert!(!h.ctx.paths.frp_root.exists());
    // Interactive: asked for, then the confirmation is declined.
    h.ui.set_assume_yes(false);
    h.ui.set_interactive(true);
    h.ui.extend(["fake-token-0123", "", "n"]);
    session(&h, true).run(install(cf_flags())).unwrap();
    assert!(!h.ctx.paths.frp_root.exists());
    assert_eq!(
        h.ui.prompts(),
        [
            "Cloudflare API Token",
            "Cloudflare Account ID（可留空自动查询）",
            CONFIRM_DEPLOY
        ]
    );
}

#[test]
fn root_is_required_for_changes() {
    let h = FakeHost::new();
    let s = session(&h, false);
    for action in [
        Action::Service(ServiceAction::Start),
        Action::Uninstall,
        Action::RotateToken,
        install(tcp_flags()),
    ] {
        assert_eq!(s.run(action).unwrap_err().to_string(), ROOT_REQUIRED);
    }
    s.run(Action::Help).unwrap();
}

#[test]
fn menu_items_stay_in_the_menu() {
    let h = FakeHost::new();
    // 2 = status; 4 = start (refused without root); 3 = export (not
    // installed); then back.
    h.ui.extend(["2", "4", "3", "0"]);
    session(&h, false).run(Action::Menu).unwrap();
    assert_eq!(h.ui.remaining(), 0);
    let menu = &h.ui.menus()[0];
    assert!(
        menu.starts_with("FRP 服务端\n未安装\n   1) 安装/配置\n"),
        "{menu}"
    );
    assert!(menu.ends_with("  11) 卸载\n   0) 返回"), "{menu}");
    // EOF at the menu prompt itself leaves with 130.
    let err = session(&h, false).run(Action::Menu).unwrap_err();
    assert!(err.is_cancelled());
    // Without a terminal the bare command shows the status.
    h.ui.set_interactive(false);
    session(&h, false).run(Action::Menu).unwrap();
}

#[test]
fn the_menu_runs_the_wizard_and_survives_its_cancellation() {
    let h = FakeHost::new();
    // 1 = configure → wizard: mode tcp, then `q` cancels; 0 = back.
    h.ui.extend(["1", "2", "q", "0"]);
    session(&h, true).run(Action::Menu).unwrap();
    assert_eq!(h.ui.remaining(), 0);
    assert!(!h.ctx.paths.frp_root.exists());
}

#[test]
fn help_text_is_v2() {
    assert!(HELP.starts_with("onebox frps [plan|install|configure|info|status|"));
    assert!(HELP.ends_with("--version 0.71.0|latest --dry-run"));
    assert!(std::ptr::eq(cli_spec(), &COMMAND));
}
