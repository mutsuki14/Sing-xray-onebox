use super::*;
use crate::cli::args::{parse as parse_args, Globals};
use crate::cli::session::testing::{Bench, Call};
use crate::domain::fixtures::{config, with_site};
use crate::domain::protocol::Core::{Singbox as SB, Xray as XR};
use crate::domain::protocol::Protocol::*;
use std::fs;

fn action(line: &str) -> Result<SiteAction> {
    let argv: Vec<String> = line.split_whitespace().map(String::from).collect();
    let inv = parse_args(&[SITE], &argv, Globals::default())?;
    parse(&inv.matches)
}

fn root(line: &str) -> bool {
    let argv: Vec<String> = line.split_whitespace().map(String::from).collect();
    let inv = parse_args(&[SITE], &argv, Globals::default()).unwrap();
    inv.spec.root.required(&inv.matches)
}

fn site_node() -> NodeConfig {
    with_site(config(&[(VlessReality, 443, XR)]), "www.example.com", true)
}

#[test]
fn parsing() {
    assert_eq!(action("site").unwrap(), SiteAction::Info);
    assert_eq!(action("site status").unwrap(), SiteAction::Info);
    // (command line, HTTPS entrance)
    for (line, https_entry) in [
        ("site enable www.example.com --tls cf", true),
        ("site enable www.example.com --tls cf --site-https on", true),
        (
            "site enable www.example.com --tls cf --site-https off",
            false,
        ),
    ] {
        assert_eq!(
            action(line).unwrap(),
            SiteAction::Enable {
                domain: "www.example.com".into(),
                cert: WebCert::Cloudflare,
                https_entry,
            },
            "{line}"
        );
    }
    assert_eq!(
        action("site template --title 手记").unwrap(),
        SiteAction::Template(PageEdit {
            title: Some("手记".into()),
            ..PageEdit::default()
        }),
        "--title is never the template name"
    );
    assert_eq!(
        action("site template profile --theme ocean").unwrap(),
        SiteAction::Template(PageEdit {
            template: Some(SiteTemplate::Profile),
            theme: Some(SiteTheme::Ocean),
            ..PageEdit::default()
        })
    );
    assert_eq!(
        action("site restore").unwrap(),
        SiteAction::Restore("latest".into())
    );
    assert_eq!(action("site https off").unwrap(), SiteAction::Https(false));
    for (line, message) in [
        ("site enable", ENABLE_USAGE),
        (
            "site enable a.example.com --tls self",
            crate::cert::PUBLIC_REQUIRED,
        ),
        (
            "site enable a.example.com --site-https maybe",
            "--site-https 应为 on/off",
        ),
        ("site https", "用法: site https on|off"),
        ("site https maybe", "用法: site https on|off"),
        ("site title", "用法: site title 标题"),
        ("site import", "用法: site import 目录"),
        ("site theme dark", "主题应为 forest/ocean/slate"),
        ("site template fancy", "模板应为 minimal/profile/docs"),
        ("site bogus", "未知子命令: bogus；请执行 onebox site --help"),
    ] {
        assert_eq!(action(line).unwrap_err().to_string(), message, "{line}");
    }
}

#[test]
fn root_policy() {
    assert!(!root("site"));
    assert!(!root("site info"));
    assert!(!root("site status"));
    assert!(root("site enable a.example.com"));
    assert!(root("site preview"));
    assert!(root("site renew"));
}

#[test]
fn enable_and_disable() {
    let bench = Bench::installed(&config(&[(VlessReality, 443, XR)]));
    let enable = |https_entry| SiteAction::Enable {
        domain: "WWW.Example.com".into(),
        cert: WebCert::Http01,
        https_entry,
    };
    let (req, message) = plan_change(&bench.session(), enable(true))
        .unwrap()
        .unwrap();
    assert_eq!(req.reason, "启用网站");
    assert!(message.is_none());
    let site = req.config.site.clone().unwrap();
    assert_eq!(site.domain, "www.example.com");
    assert!(site.https_entry);
    assert_eq!(req.config.reality.dest.to_string(), "127.0.0.1:10443");
    // Closed from the start, on a new site and on an open existing one.
    for cfg in [config(&[(VlessReality, 443, XR)]), site_node()] {
        let bench = Bench::installed(&cfg);
        let (req, _) = plan_change(&bench.session(), enable(false))
            .unwrap()
            .unwrap();
        assert!(!req.config.site.unwrap().https_entry);
    }
    // TCP 443 held by a non-REALITY inbound or by FRP: a closed entrance
    // is planned with the site (never opened in between), an open one is
    // refused.
    let trojan = config(&[(VlessReality, 8443, XR), (Trojan, 443, SB)]);
    let reality = config(&[(VlessReality, 8443, XR)]);
    for (cfg, frp) in [(trojan, false), (reality, true)] {
        let mut bench = Bench::installed(&cfg);
        if frp {
            bench.live.frp = vec![crate::domain::ports::Reservation {
                start: 443,
                end: 443,
                transport: crate::domain::protocol::Transport::Tcp,
                label: "frps".into(),
            }];
        }
        let (req, _) = plan_change(&bench.session(), enable(false))
            .unwrap()
            .unwrap();
        assert!(!req.config.site.unwrap().https_entry);
        assert!(plan_change(&bench.session(), enable(true)).is_err());
    }
    let bench = Bench::installed(&config(&[(Trojan, 443, SB)]));
    let err = plan_change(&bench.session(), enable(true)).unwrap_err();
    assert_eq!(
        err.to_string(),
        "自建 REALITY 网站需要先开启 REALITY 协议；独立订阅请用 subscription enable"
    );
    let err = plan_change(&bench.session(), SiteAction::Disable).unwrap_err();
    assert_eq!(err.to_string(), "网站未启用");
    let bench = Bench::installed(&site_node());
    let (req, _) = plan_change(&bench.session(), SiteAction::Disable)
        .unwrap()
        .unwrap();
    assert!(req.config.site.is_none());
    assert_eq!(req.config.reality.sni, "www.microsoft.com");
}

#[test]
fn page_edits_publish_the_template() {
    let bench = Bench::installed(&site_node());
    let store = ContentStore::new(&bench.ctx.paths);
    // Imported content: edits of the generated page are refused.
    fs::create_dir_all(&bench.ctx.paths.site_root).unwrap();
    fs::write(store.index(), "custom").unwrap();
    let err = plan_change(&bench.session(), SiteAction::Title("新标题".into())).unwrap_err();
    assert_eq!(err.to_string(), EDITED);
    // A template switch replaces the page deliberately.
    let (req, message) = plan_change(
        &bench.session(),
        SiteAction::Template(PageEdit {
            template: Some(SiteTemplate::Docs),
            title: Some("文档".into()),
            ..PageEdit::default()
        }),
    )
    .unwrap()
    .unwrap();
    assert_eq!(message, Some(PUBLISHED));
    assert_eq!(req.intents.site_content, Some(SiteContent::Template));
    let site = req.config.site.unwrap();
    assert_eq!(
        (site.template, site.title.as_str()),
        (SiteTemplate::Docs, "文档")
    );
    // Generated content can be edited.
    fs::remove_file(store.index()).unwrap();
    store.ensure_default("<html>generated</html>").unwrap();
    for action in [
        SiteAction::Title("新标题".into()),
        SiteAction::Theme(SiteTheme::Slate),
        SiteAction::Description("记录".into()),
    ] {
        let (req, message) = plan_change(&bench.session(), action).unwrap().unwrap();
        assert_eq!(req.intents.site_content, Some(SiteContent::Template));
        assert_eq!(message, Some(PUBLISHED));
    }
}

#[test]
fn import_and_restore_are_checked_first() {
    let bench = Bench::installed(&site_node());
    let missing = bench.dir.join("nope");
    let err = plan_change(
        &bench.session(),
        SiteAction::Import(missing.to_string_lossy().into_owned()),
    )
    .unwrap_err();
    assert!(
        err.to_string().starts_with("导入目录不存在或不是目录"),
        "{err}"
    );
    let upload = bench.dir.join("upload");
    fs::create_dir_all(&upload).unwrap();
    fs::write(upload.join("index.html"), "hi").unwrap();
    let (req, message) = plan_change(
        &bench.session(),
        SiteAction::Import(upload.to_string_lossy().into_owned()),
    )
    .unwrap()
    .unwrap();
    assert_eq!(message, Some(PUBLISHED));
    assert!(matches!(
        req.intents.site_content,
        Some(SiteContent::Import(_))
    ));
    for (id, message) in [
        ("latest", "没有网站备份"),
        ("../x", "无效备份 ID"),
        ("1700000000-deadbeef", "网站备份不存在: 1700000000-deadbeef"),
    ] {
        let err = plan_change(&bench.session(), SiteAction::Restore(id.into())).unwrap_err();
        assert_eq!(err.to_string(), message, "{id}");
    }
    fs::create_dir_all(
        ContentStore::new(&bench.ctx.paths)
            .backups_dir()
            .join("1700000000-deadbeef"),
    )
    .unwrap();
    let (req, message) = plan_change(&bench.session(), SiteAction::Restore("latest".into()))
        .unwrap()
        .unwrap();
    assert_eq!(message, Some(RESTORED));
    assert_eq!(
        req.intents.site_content,
        Some(SiteContent::Restore("latest".into()))
    );
    let plain = Bench::installed(&config(&[(VlessReality, 443, XR)]));
    let err = plan_change(&plain.session(), SiteAction::Restore("latest".into())).unwrap_err();
    assert_eq!(err.to_string(), "请先启用网站");
}

#[test]
fn run_applies_and_prints() {
    let bench = Bench::installed(&site_node());
    run(&bench.session(), SiteAction::Https(false)).unwrap();
    assert_eq!(bench.engine.calls(), [Call::Apply]);
    assert_eq!(bench.engine.single().reason, "修改网站入口");
    assert!(bench.output().is_empty());
    run(&bench.session(), SiteAction::Template(PageEdit::default())).unwrap();
    assert_eq!(bench.output(), PUBLISHED);
}

#[test]
fn preview_writes_a_private_file() {
    let mut bench = Bench::installed(&config(&[(VlessReality, 443, XR)]));
    let edit = PageEdit {
        title: Some("预览 <b>".into()),
        ..PageEdit::default()
    };
    preview(&bench.session(), &edit).unwrap();
    let path = ContentStore::new(&bench.ctx.paths).preview_file();
    assert_eq!(bench.output(), path.to_string_lossy());
    let html = fs::read_to_string(&path).unwrap();
    assert!(html.contains("预览 &lt;b&gt;"));
    bench.is_root = false;
    assert!(preview(&bench.session(), &edit).is_err());
    // Without a site and without options: the v2 default page.
    bench.is_root = true;
    preview(&bench.session(), &PageEdit::default()).unwrap();
    let html = fs::read_to_string(&path).unwrap();
    assert!(html.contains(defaults::SITE_TITLE), "{html}");
    assert!(html.contains(defaults::SITE_DESCRIPTION), "{html}");
}

#[test]
fn page_edits_without_a_site_ask_to_enable_it() {
    let bench = Bench::installed(&config(&[(VlessReality, 443, XR)]));
    for action in [
        SiteAction::Title("新标题".into()),
        SiteAction::Theme(SiteTheme::Slate),
        SiteAction::Description("记录".into()),
    ] {
        let err = plan_change(&bench.session(), action).unwrap_err();
        assert_eq!(err.to_string(), "请先启用网站");
    }
}

#[test]
fn info_shows_the_site() {
    let bench = Bench::installed(&site_node());
    info(&bench.session()).unwrap();
    let out = bench.output();
    assert!(
        out.starts_with("网站: 开启；域名: www.example.com；内部端口: 10443；公网端口: 443"),
        "{out}"
    );
}
