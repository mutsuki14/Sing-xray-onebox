//! Grammar, CLI wiring, root policy and the interactive menu.

use super::fixture::{Fixture, TAG};
use super::*;
use crate::cli::args::{parse as parse_cli, Globals};

fn words(list: &[&str]) -> Vec<String> {
    list.iter().map(|s| s.to_string()).collect()
}

fn install(desired: &str, max: bool, apply: bool) -> Action {
    Action::Install(InstallRequest {
        desired: desired.into(),
        max,
        apply,
    })
}

#[test]
fn validates_dispatch_without_side_effects() {
    for (args, action) in [
        (&[][..], Action::Menu),
        (&["menu"], Action::Menu),
        (&["status"], Action::Status),
        (&["enable"], Action::Enable(Queue::Fq)),
        (&["enable", "cake"], Action::Enable(Queue::Cake)),
        (&["releases"], Action::Releases { max: false }),
        (&["releases", "--max"], Action::Releases { max: true }),
        (&["install"], install("latest", false, false)),
        (
            &["install", TAG, "--max", "--apply"],
            install(TAG, true, true),
        ),
        (&["install", "--apply", TAG], install(TAG, false, true)),
    ] {
        assert_eq!(parse(&words(args)).unwrap(), action, "{args:?}");
    }
    for bad in [
        &["status", "extra"][..],
        &["enable", "fq;reboot"],
        &["enable", "fq", "cake"],
        &["releases", "--apply"],
        &["install", "one", "two"],
        &["install", "--unknown"],
        &["install", "--apply", "--apply"],
        &["info"],
        &["list"],
        &["preview"],
        &["menu", "x"],
    ] {
        assert!(parse(&words(bad)).is_err(), "{bad:?}");
    }
    assert_eq!(parse(&words(&["nope"])).unwrap_err().to_string(), USAGE);
    assert!(USAGE.contains("menu|status"), "usage lists menu (I-8.1#17)");
    assert_eq!(
        parse(&words(&["install", "--apply", "--apply"]))
            .unwrap_err()
            .to_string(),
        format!("重复或无效的 BBR 参数: --apply\n{USAGE}")
    );
    assert_eq!(
        parse(&words(&["enable", "pfifo"])).unwrap_err().to_string(),
        "队列应为 fq / fq_codel / fq_pie / cake"
    );
}

#[test]
fn root_policy_is_decided_by_the_action() {
    for (action, root) in [
        (Action::Menu, false),
        (Action::Status, false),
        (Action::Releases { max: true }, false),
        (install("latest", false, false), false),
        (install("latest", true, true), true),
        (Action::Enable(Queue::Fq), true),
    ] {
        assert_eq!(action.requires_root(), root, "{action:?}");
        assert_eq!(action.mutates(), root, "{action:?}");
    }
}

/// Parse a real command line against the `bbr` spec.
fn cli(args: &[&str]) -> crate::error::Result<(Action, bool)> {
    let commands = [COMMAND];
    let invocation = parse_cli(&commands, &words(args), Globals::default())?;
    let root = crate::cli::registry::requires_root(invocation.spec, &invocation.matches);
    Ok((from_matches(&invocation.matches)?, root))
}

#[test]
fn command_spec_maps_to_actions_and_root_policy() {
    for (args, action, root) in [
        (&["bbr"][..], Action::Menu, false),
        (&["bbr", "menu"], Action::Menu, false),
        (&["bbr", "status"], Action::Status, false),
        (&["bbr", "enable"], Action::Enable(Queue::Fq), true),
        (
            &["bbr", "enable", "fq_pie"],
            Action::Enable(Queue::FqPie),
            true,
        ),
        (
            &["bbr", "releases", "--max"],
            Action::Releases { max: true },
            false,
        ),
        (&["bbr", "install"], install("latest", false, false), false),
        (
            &["bbr", "install", TAG, "--max"],
            install(TAG, true, false),
            false,
        ),
        (
            &["bbr", "install", "--apply"],
            install("latest", false, true),
            true,
        ),
        (
            &["bbr", "install", "--dry-run"],
            install("latest", false, false),
            false,
        ),
    ] {
        assert_eq!(cli(args).unwrap(), (action, root), "{args:?}");
    }
    for (args, message) in [
        (&["bbr", "status", "x"][..], "多余的参数: x"),
        (
            &["bbr", "enable", "x"],
            "队列应为 fq / fq_codel / fq_pie / cake",
        ),
        (
            &["bbr", "releases", "--apply"],
            "bbr releases 不支持选项 --apply；请执行 onebox bbr releases --help",
        ),
        (
            &["bbr", "install", "--apply", "--apply"],
            "重复选项: --apply",
        ),
        (
            &["bbr", "install", "--apply", "--dry-run"],
            "--dry-run 与 --apply 不能同时使用",
        ),
        (&["bbr", "status", "--dry-run"], "此命令不支持 --dry-run"),
        (
            &["bbr", "info"],
            "未知子命令: info；请执行 onebox bbr --help",
        ),
    ] {
        assert_eq!(cli(args).unwrap_err().to_string(), message, "{args:?}");
    }
    assert!(COMMAND.handler.is_some());
    assert!(COMMAND.subcommands.iter().all(|s| s.handler.is_some()));
}

#[test]
fn bbr_without_a_terminal_shows_status() {
    let f = Fixture::new();
    let session = Session {
        ctx: &f.ctx,
        fetcher: &f.github,
        is_root: false,
    };
    session.run(Action::Menu).unwrap();
    assert!(f.ui.menus().is_empty());
    assert!(f.calls("uname").contains(&vec!["-r".to_string()]));
}

fn interactive(f: &Fixture, answers: &[&str]) {
    f.ui.set_assume_yes(false);
    f.ui.set_interactive(true);
    f.ui.extend(answers.iter().copied());
}

/// The BBR menu as the fixture's host shows it.
const MENU_TITLE: &str = "TCP BBR 管理\nTCP / 默认队列: cubic / fq_codel";

fn bbr_menus(f: &Fixture) -> usize {
    f.ui.menus()
        .iter()
        .filter(|m| m.starts_with(MENU_TITLE))
        .count()
}

#[test]
fn menu_builds_actions_and_returns_on_zero() {
    let f = Fixture::new();
    interactive(&f, &["1", "3", "0"]);
    let session = f.session();
    session.run(Action::Menu).unwrap();
    let menus = f.ui.menus();
    assert_eq!(menus.len(), 3);
    assert!(
        menus[0].starts_with(&format!("{MENU_TITLE}\n  1) 状态与实际网卡队列")),
        "current values first: {}",
        menus[0]
    );
    assert!(menus[0].ends_with("  6) 安装/更新 Max 实验版（先预览，确认后执行）\n  0) 返回"));
    assert_eq!(
        f.github.requests(),
        ["https://api.github.com/repos/byJoey/Actions-bbr-v3/releases?per_page=100&page=1"]
    );
    assert_eq!(f.ui.remaining(), 0);
}

#[test]
fn enter_at_the_menu_goes_back() {
    let f = Fixture::new();
    interactive(&f, &[""]);
    f.session().run(Action::Menu).unwrap();
    assert_eq!(bbr_menus(&f), 1);
    assert_eq!(
        crate::ui::select_prompt(MENU.len(), BACK, true),
        "请选择 [默认: 0]: "
    );
}

#[test]
fn menu_enable_picks_a_queue_and_back_returns_to_the_menu() {
    let f = Fixture::new();
    interactive(&f, &["2", "0", "2", "4", "0"]);
    f.session().run(Action::Menu).unwrap();
    assert_eq!(f.sysctl.get(QDISC), "cake");
    assert_eq!(f.sysctl.get(CC), "bbr");
    let menus = f.ui.menus();
    assert!(menus[1].starts_with("默认队列\n  1) fq（默认）"));
    assert!(
        menus[4].starts_with("TCP BBR 管理\nTCP / 默认队列: bbr / cake"),
        "the header follows the change: {}",
        menus[4]
    );
}

#[test]
fn menu_checks_root_before_asking_follow_up_questions() {
    let f = Fixture::new();
    interactive(&f, &["2", "4", "1", "0"]);
    let session = Session {
        ctx: &f.ctx,
        fetcher: &f.github,
        is_root: false,
    };
    session.run(Action::Menu).unwrap();
    assert_eq!(f.sysctl.get(CC), "cubic", "enable refused without root");
    assert!(f
        .calls("sysctl")
        .iter()
        .all(|a| a[0] == "-n" || a.is_empty()));
    assert_eq!(bbr_menus(&f), 4, "no queue picker, no tag prompt");
    assert_eq!(f.ui.menus().len(), 4);
    assert!(!f
        .ui
        .prompts()
        .contains(&"完整 Release 标签或 latest".to_string()));
}

#[test]
fn menu_install_previews_then_asks_before_installing() {
    let f = Fixture::new();
    f.eligible();
    interactive(&f, &["4", "", "n", "0"]);
    f.session().run(Action::Menu).unwrap();
    assert!(f
        .ui
        .prompts()
        .contains(&"完整 Release 标签或 latest".to_string()));
    assert!(f
        .ui
        .prompts()
        .iter()
        .any(|p| p.starts_with("安装 x86_64-7.2.8？")));
    let apt = f.calls("apt-get");
    assert_eq!(apt.len(), 1, "declined after the simulation");
}

#[test]
fn a_mistyped_tag_is_asked_again() {
    let f = Fixture::new();
    interactive(&f, &["6", "x86_64-7.2.8", "x86_64-7.2.8-max"]);
    let err = f.session().run(Action::Menu).unwrap_err();
    assert!(err.is_cancelled());
    assert_eq!(
        f.ui.errors(),
        ["Release 标签与架构/标准或 Max 类型不匹配"],
        "a standard tag is not a Max tag"
    );
    assert_eq!(
        f.github.requests(),
        [crate::bbr::release::tag_url("x86_64-7.2.8-max")]
    );
}

#[test]
fn eof_in_the_menu_cancels() {
    let f = Fixture::new();
    interactive(&f, &[]);
    let err = f.session().run(Action::Menu).unwrap_err();
    assert!(err.is_cancelled());
    assert_eq!(err.exit_code(), 130);
}

#[test]
fn eof_in_a_follow_up_question_returns_to_the_menu() {
    for (answers, prompt) in [
        (&["2"][..], "默认队列"),
        (&["4"], "完整 Release 标签或 latest"),
    ] {
        let f = Fixture::new();
        interactive(&f, answers);
        let err = f.session().run(Action::Menu).unwrap_err();
        assert!(err.is_cancelled() && err.exit_code() == 130, "{prompt}");
        assert!(f.ui.prompts().contains(&prompt.to_string()));
        assert_eq!(bbr_menus(&f), 2, "{prompt}: shown again, then EOF leaves");
        assert_eq!(f.sysctl.get(CC), "cubic");
    }
}

#[test]
fn eof_at_the_install_confirmation_returns_to_the_menu() {
    let f = Fixture::new();
    f.eligible();
    interactive(&f, &["4", ""]);
    let err = f.session().run(Action::Menu).unwrap_err();
    assert!(err.is_cancelled());
    assert!(f
        .ui
        .prompts()
        .iter()
        .any(|p| p.starts_with("安装 x86_64-7.2.8？")));
    assert_eq!(bbr_menus(&f), 2);
    assert_eq!(f.calls("apt-get").len(), 1, "only the simulation ran");
    assert!(f.calls("update-grub").is_empty());
}

#[test]
fn releases_print_newest_first() {
    let f = Fixture::new();
    *f.github.pages.lock().unwrap() = vec![serde_json::json!([
        {"tag_name": "x86_64-7.1", "draft": false, "prerelease": false},
        {"tag_name": "x86_64-7.2.8-max", "draft": false, "prerelease": false},
    ])];
    let session = Session {
        ctx: &f.ctx,
        fetcher: &f.github,
        is_root: false,
    };
    session.run(Action::Releases { max: true }).unwrap();
    session.run(Action::Releases { max: false }).unwrap();
    f.host().machine = "ppc64le".into();
    assert_eq!(
        session
            .run(Action::Releases { max: false })
            .unwrap_err()
            .to_string(),
        "Actions-bbr-v3 内核仅支持 x86_64 / aarch64"
    );
}

#[test]
fn queues_round_trip() {
    for queue in Queue::ALL {
        assert_eq!(Queue::parse(queue.id()).unwrap(), queue);
    }
}
