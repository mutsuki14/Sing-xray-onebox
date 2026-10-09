use super::*;
use crate::cli::args::{parse as parse_args, Globals};
use crate::cli::session::testing::{Bench, Call};
use crate::domain::fixtures::config;
use crate::domain::protocol::Core::{Singbox as SB, Xray as XR};
use crate::domain::protocol::Protocol::*;

fn matches(line: &str) -> Matches {
    let argv: Vec<String> = line.split_whitespace().map(String::from).collect();
    parse_args(&[TUNE], &argv, Globals::default())
        .unwrap_or_else(|e| panic!("{line}: {e}"))
        .matches
}

fn root(line: &str) -> bool {
    let argv: Vec<String> = line.split_whitespace().map(String::from).collect();
    let inv = parse_args(&[TUNE], &argv, Globals::default()).unwrap();
    inv.spec.root.required(&inv.matches)
}

#[test]
fn parsing_by_name() {
    assert_eq!(parse(&matches("tune")).unwrap(), None);
    assert_eq!(parse(&matches("tune status")).unwrap(), None);
    assert_eq!(
        parse(&matches("tune hy2 measured --up 20 --down 100 --apply")).unwrap(),
        Some(Tune::hy2(Hy2Profile::Measured, Some(20), Some(100)))
    );
    assert_eq!(
        parse(&matches("tune hy2 --apply auto")).unwrap(),
        Some(Tune::hy2(Hy2Profile::Auto, None, None)),
        "--apply anywhere"
    );
    assert_eq!(
        parse(&matches("tune resource low-memory")).unwrap(),
        Some(Tune::Resource(ResourceProfile::LowMemory))
    );
    assert_eq!(
        parse(&matches("tune reset --apply")).unwrap(),
        Some(Tune::Reset)
    );
    for (line, message) in [
        ("tune hy2 --apply", NEEDS_HY2_CHANGE),
        ("tune hy2 fast", "Hy2 档位无效"),
        ("tune resource", "需要 balanced/low-memory/throughput"),
        ("tune resource huge", "资源档位无效"),
        ("tune hy2 measured --up 1.5", BAD_BANDWIDTH),
        ("tune hy2 measured --down x", BAD_BANDWIDTH),
    ] {
        assert_eq!(
            parse(&matches(line)).unwrap_err().to_string(),
            message,
            "{line}"
        );
    }
    let argv: Vec<String> = ["tune", "reset", "--up", "1"].map(String::from).to_vec();
    assert!(parse_args(&[TUNE], &argv, Globals::default()).is_err());
}

#[test]
fn root_only_with_apply() {
    assert!(!root("tune"));
    assert!(!root("tune status"));
    assert!(!root("tune hy2 auto"));
    assert!(root("tune hy2 auto --apply"));
    assert!(!root("tune resource throughput"));
    assert!(root("tune reset --apply"));
}

fn hy2_node() -> NodeConfig {
    config(&[(VlessReality, 443, XR), (Hysteria2, 443, SB)])
}

fn env() -> PlanEnv<'static> {
    PlanEnv::offline(true, 0)
}

#[test]
fn status_lines() {
    let mut cfg = hy2_node();
    assert_eq!(
        status_text(&cfg),
        "HY2_PROFILE=\nHY2_UP_MBPS=\nHY2_DOWN_MBPS=\nRESOURCE_PROFILE=balanced"
    );
    cfg = plan_tune(
        &cfg,
        Tune::hy2(Hy2Profile::Measured, Some(20), Some(100)),
        &env(),
    )
    .unwrap();
    assert_eq!(
        status_text(&cfg),
        "HY2_PROFILE=measured\nHY2_UP_MBPS=20\nHY2_DOWN_MBPS=100\nRESOURCE_PROFILE=balanced"
    );
    assert_eq!(
        preview_line(&cfg),
        "调优预览: HY2=measured up=20 down=100 resource=balanced"
    );
    let reset = plan_tune(&cfg, Tune::Reset, &env()).unwrap();
    assert_eq!(
        preview_line(&reset),
        "调优预览: HY2= up= down= resource=balanced"
    );
}

#[test]
fn preview_and_apply() {
    let mut bench = Bench::installed(&hy2_node());
    let change = Tune::Resource(ResourceProfile::Throughput);
    tune(&bench.session(), change, false).unwrap();
    assert_eq!(
        bench.output(),
        "调优预览: HY2= up= down= resource=throughput\n添加 --apply 才会应用"
    );
    assert!(bench.engine.calls().is_empty());
    bench.is_root = false;
    let err = tune(&bench.session(), change, true).unwrap_err();
    assert_eq!(err.to_string(), "此操作需要 root 权限");
    bench.is_root = true;
    tune(&bench.session(), change, true).unwrap();
    assert_eq!(bench.engine.calls(), [Call::Apply]);
    let req = bench.engine.single();
    assert_eq!(req.reason, "调优");
    assert_eq!(req.config.resource_profile, ResourceProfile::Throughput);
}

#[test]
fn planner_rules_surface() {
    let xray_hy2 = config(&[(Hysteria2, 443, XR)]);
    let err = plan_tune(&xray_hy2, Tune::hy2(Hy2Profile::Auto, None, None), &env()).unwrap_err();
    assert_eq!(
        err.to_string(),
        "Xray 承载的 Hysteria2 不支持带宽调优，请改用 sing-box 承载"
    );
    let err = plan_tune(
        &hy2_node(),
        Tune::hy2(Hy2Profile::Measured, Some(20), None),
        &env(),
    )
    .unwrap_err();
    assert_eq!(err.to_string(), "measured 需要 --up 和 --down");
    let bench = Bench::installed(&hy2_node());
    status(&bench.session()).unwrap();
    assert!(bench.output().starts_with("HY2_PROFILE="));
}

#[test]
fn parsing_obfuscation_and_hopping() {
    let range = |s: &str| s.parse::<PortRange>().unwrap();
    // (command line, change)
    for (line, change) in [
        ("tune hy2 --obfs on", Tune::hy2_transport(Some(true), None)),
        (
            "tune hy2 --hop 30000-30100 --apply",
            Tune::hy2_transport(None, Some(Some(range("30000-30100")))),
        ),
        (
            "tune hy2 --obfs off --hop off",
            Tune::hy2_transport(Some(false), Some(None)),
        ),
        (
            "tune hy2 auto --obfs on",
            Tune::Hy2 {
                profile: Some(Hy2Profile::Auto),
                up: None,
                down: None,
                obfs: Some(true),
                hop: None,
            },
        ),
    ] {
        assert_eq!(parse(&matches(line)).unwrap(), Some(change), "{line}");
    }
    for (line, message) in [
        ("tune hy2 --obfs maybe", "--obfs 应为 on/off"),
        ("tune hy2 --hop 30000", "端口范围格式应为 起始-结束: 30000"),
        ("tune hy2 --hop on --up 5", "端口范围格式应为 起始-结束: on"),
        (
            "tune hy2 --obfs on --up 5",
            "--up/--down 仅用于 measured 档位",
        ),
    ] {
        assert_eq!(
            parse(&matches(line)).unwrap_err().to_string(),
            message,
            "{line}"
        );
    }
    assert!(root("tune hy2 --obfs on --apply"));
}

#[test]
fn obfuscation_and_hopping_after_install() {
    let cfg = hy2_node();
    let change = Tune::hy2_transport(Some(true), Some(Some("30000-30100".parse().unwrap())));
    let next = plan_tune(&cfg, change, &env()).unwrap();
    assert!(next.hy2.obfs);
    assert_eq!(next.hy2.hop.unwrap().to_string(), "30000-30100");
    assert_eq!(next.hy2.profile, cfg.hy2.profile, "the profile is kept");
    assert!(needs_reimport(&cfg, &next));
    // Only the given setting changes; off turns hopping off.
    let off = plan_tune(&next, Tune::hy2_transport(None, Some(None)), &env()).unwrap();
    assert!(off.hy2.obfs && off.hy2.hop.is_none());
    // A range over another UDP listener is refused (TUIC on 30050/udp).
    let tuic = config(&[(Hysteria2, 443, SB), (Tuic, 30050, SB)]);
    assert!(plan_tune(&tuic, change, &env()).is_err());
    let err = plan_tune(&config(&[(VlessReality, 443, XR)]), change, &env()).unwrap_err();
    assert_eq!(err.to_string(), "未启用 Hysteria2");
    // Preview, apply, and the re-import notice.
    let bench = Bench::installed(&cfg);
    tune(&bench.session(), change, true).unwrap();
    assert_eq!(
        bench.output(),
        "调优预览: HY2= up= down= resource=balanced\nHysteria2 混淆=on 端口跳跃=30000-30100"
    );
    let req = bench.engine.single();
    assert!(req.config.hy2.obfs);
    assert_eq!(bench.notes(), [format!("[提示] {REIMPORT}")]);
}
