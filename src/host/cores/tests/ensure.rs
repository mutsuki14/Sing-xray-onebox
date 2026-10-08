//! `ensure_installed`: the apply engine's core hook (G2 pin semantics).

use super::*;

#[test]
fn ensure_installed_downloads_when_missing() {
    let mut f = fixture();
    let binary = serve_singbox(&mut f, "1.15.0", &format!("{SB_API}/latest"));
    f.serve();
    let bin = f.ctx.paths.bin.clone();
    versions(&f.exec, vec![(bin.clone(), singbox_says("1.15.0"))]);
    let v =
        ensure_installed_with(&f.ctx, &no_env, Core::Singbox, &CoreVersions::default()).unwrap();
    assert_eq!(v, "1.15.0");
    let live = f.ctx.paths.core_bin(Core::Singbox);
    assert_eq!(std::fs::read(&live).unwrap(), binary);
    let names: Vec<String> = std::fs::read_dir(&bin)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(names, ["sing-box"], "staging removed");

    // Installed and unpinned: nothing is fetched again.
    f.exec.clear_history();
    let v =
        ensure_installed_with(&f.ctx, &no_env, Core::Singbox, &CoreVersions::default()).unwrap();
    assert_eq!(v, "1.15.0");
    assert!(f.curl_urls().is_empty());
}

/// A live sing-box binary reporting `version`.
fn live_singbox(f: &Fixture, version: &str) -> PathBuf {
    let live = f.ctx.paths.core_bin(Core::Singbox);
    std::fs::create_dir_all(live.parent().unwrap()).unwrap();
    std::fs::write(&live, fake_elf("old")).unwrap();
    versions(
        &f.exec,
        vec![
            (live.clone(), singbox_says(version)),
            (f.ctx.paths.bin.clone(), singbox_says("1.14.2")),
        ],
    );
    live
}

#[test]
fn ensure_installed_never_replaces_a_working_core() {
    // A migrated v2 pin older than the installed core: no downgrade, no
    // network (the v2 → v3 upgrade must not depend on GitHub).
    let f = fixture();
    f.serve();
    let live = live_singbox(&f, "1.14.2");
    let old_pin = CoreVersions {
        singbox_pin: Some("1.12.0".into()),
        ..CoreVersions::default()
    };
    let v = ensure_installed_with(&f.ctx, &no_env, Core::Singbox, &old_pin).unwrap();
    assert_eq!(v, "1.14.2");
    assert_eq!(std::fs::read(&live).unwrap(), fake_elf("old"), "untouched");
    assert!(f.curl_urls().is_empty());

    // Same for a newer pin and for the environment's wish.
    let newer = CoreVersions {
        singbox_pin: Some("v1.15.0".into()),
        ..CoreVersions::default()
    };
    assert_eq!(
        ensure_installed_with(&f.ctx, &no_env, Core::Singbox, &newer).unwrap(),
        "1.14.2"
    );
    let env = |k: &str| (k == "ONEBOX_SINGBOX_VERSION").then(|| "1.13.0".to_owned());
    let unpinned = CoreVersions::default();
    assert_eq!(
        ensure_installed_with(&f.ctx, &env, Core::Singbox, &unpinned).unwrap(),
        "1.14.2"
    );
    // `latest` is satisfied by whatever is installed.
    let latest = CoreVersions {
        singbox_pin: Some("latest".into()),
        ..CoreVersions::default()
    };
    assert_eq!(
        ensure_installed_with(&f.ctx, &no_env, Core::Singbox, &latest).unwrap(),
        "1.14.2"
    );
    assert!(f.curl_urls().is_empty());
}

#[test]
fn pin_mismatch_hint_names_the_update_command() {
    let exact = |v: &str| Wanted::Exact(v.into());
    let cases = [
        (
            Core::Singbox,
            Some(exact("1.12.0")),
            Some("已安装 sing-box 1.14.2；更换指定版本请执行 onebox update singbox 1.12.0"),
        ),
        (
            Core::Xray,
            Some(exact("25.1.1")),
            Some("已安装 Xray 1.14.2；更换指定版本请执行 onebox update xray 25.1.1"),
        ),
        (Core::Singbox, Some(exact("1.14.2")), None),
        (Core::Singbox, Some(Wanted::Latest), None),
        (Core::Singbox, Some(Wanted::Default), None),
        (Core::Singbox, None, None),
    ];
    for (core, wish, want) in cases {
        let hint = pin_hint(core, "1.14.2", wish.as_ref());
        assert_eq!(hint.as_deref(), want, "{core:?} {wish:?}");
    }
}

#[test]
fn a_broken_core_is_downloaded_in_the_pinned_version() {
    let mut f = fixture();
    let binary = serve_singbox(&mut f, "1.14.2", &format!("{SB_API}/tags/v1.14.2"));
    f.serve();
    let live = f.ctx.paths.core_bin(Core::Singbox);
    std::fs::create_dir_all(live.parent().unwrap()).unwrap();
    std::fs::write(&live, b"truncated").unwrap();
    versions(
        &f.exec,
        vec![
            (live.clone(), Output::failure(126, "Exec format error")),
            (f.ctx.paths.bin.clone(), singbox_says("1.14.2")),
        ],
    );
    let pinned = CoreVersions {
        singbox_pin: Some("v1.14.2".into()),
        ..CoreVersions::default()
    };
    let v = ensure_installed_with(&f.ctx, &no_env, Core::Singbox, &pinned).unwrap();
    assert_eq!(v, "1.14.2");
    assert_eq!(std::fs::read(&live).unwrap(), binary, "replaced in place");
}

#[test]
fn environment_versions_apply_when_nothing_is_pinned() {
    let mut f = fixture();
    let binary = serve_singbox(&mut f, "1.14.2", &format!("{SB_API}/tags/v1.14.2"));
    f.serve();
    versions(
        &f.exec,
        vec![(f.ctx.paths.bin.clone(), singbox_says("1.14.2"))],
    );
    let env = |k: &str| (k == "ONEBOX_SINGBOX_VERSION").then(|| "v1.14.2".to_owned());
    let v = ensure_installed_with(&f.ctx, &env, Core::Singbox, &CoreVersions::default()).unwrap();
    assert_eq!(v, "1.14.2");
    let live = f.ctx.paths.core_bin(Core::Singbox);
    assert_eq!(std::fs::read(&live).unwrap(), binary);
    assert_eq!(
        f.curl_urls()[0],
        format!("{SB_API}/tags/v1.14.2"),
        "not latest"
    );

    // The pin wins over the environment.
    std::fs::remove_file(&live).unwrap();
    f.exec.clear_history();
    let env = |k: &str| (k == "ONEBOX_SINGBOX_VERSION").then(|| "1.13.0".to_owned());
    let pinned = CoreVersions {
        singbox_pin: Some("1.14.2".into()),
        ..CoreVersions::default()
    };
    ensure_installed_with(&f.ctx, &env, Core::Singbox, &pinned).unwrap();
    assert_eq!(f.curl_urls()[0], format!("{SB_API}/tags/v1.14.2"));

    // `latest` while installing a missing core keeps v2's fallback.
    let mut f = fixture();
    serve_singbox(&mut f, "1.14.2", &format!("{SB_API}/tags/v1.14.2"));
    f.route(format!("{SB_API}/latest"), Reply::http(403));
    f.serve();
    versions(
        &f.exec,
        vec![(f.ctx.paths.bin.clone(), singbox_says("1.14.2"))],
    );
    let env = |k: &str| (k == "ONEBOX_SINGBOX_VERSION").then(|| "latest".to_owned());
    let v = ensure_installed_with(&f.ctx, &env, Core::Singbox, &CoreVersions::default()).unwrap();
    assert_eq!(v, "1.14.2");

    let bad = |k: &str| (k == "ONEBOX_XRAY_VERSION").then(|| "../x".to_owned());
    let err =
        ensure_installed_with(&f.ctx, &bad, Core::Xray, &CoreVersions::default()).unwrap_err();
    assert_eq!(
        err.to_string(),
        "环境变量 ONEBOX_XRAY_VERSION: 版本格式无效: ../x"
    );
    assert_eq!(version_env(Core::Xray), "ONEBOX_XRAY_VERSION");
}

#[test]
fn ensure_installed_sweeps_v2_and_v3_leftovers() {
    let f = fixture();
    f.serve();
    live_singbox(&f, "1.14.2");
    let bin = f.ctx.paths.bin.clone();
    let aged = |name: &str| {
        let dir = bin.join(name);
        std::fs::create_dir(&dir).unwrap();
        std::fs::write(dir.join(".download-0123"), b"partial").unwrap();
        let old = std::time::SystemTime::now() - Duration::from_secs(2 * 3600);
        std::fs::File::open(&dir)
            .unwrap()
            .set_modified(old)
            .unwrap();
    };
    aged(".core-0123456789abcdef01234567");
    aged("onebox-core-stage-0011223344556677");
    std::fs::create_dir(bin.join(".core-fresh")).unwrap();
    ensure_installed_with(&f.ctx, &no_env, Core::Singbox, &CoreVersions::default()).unwrap();
    let mut names: Vec<String> = std::fs::read_dir(&bin)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    assert_eq!(names, [".core-fresh", "sing-box"]);
}

#[test]
fn ensure_installed_replaces_a_broken_binary_and_refuses_odd_paths() {
    let mut f = fixture();
    let binary = fake_elf("xray new");
    let package = xray_zip(&f.dir, &binary);
    let tag = "v26.3.27";
    let name = "Xray-linux-64.zip";
    let asset = asset_json(repo(Core::Xray), tag, name, &package, true);
    f.route(
        format!("{XR_API}/tags/{tag}"),
        release_json(tag, false, vec![asset]),
    )
    .route(
        Asset::expected_url(repo(Core::Xray), tag, name),
        Reply::body(package),
    );
    f.serve();
    let live = f.ctx.paths.core_bin(Core::Xray);
    std::fs::create_dir_all(live.parent().unwrap()).unwrap();
    std::fs::write(&live, b"garbage").unwrap();
    let bin = f.ctx.paths.bin.clone();
    versions(
        &f.exec,
        vec![
            (
                live.clone(),
                Output::failure(126, "cannot execute binary file"),
            ),
            (bin, xray_says("26.3.27")),
        ],
    );
    let v = ensure_installed_with(&f.ctx, &no_env, Core::Xray, &CoreVersions::default()).unwrap();
    assert_eq!(v, "26.3.27");
    assert_eq!(std::fs::read(&live).unwrap(), binary);

    std::fs::remove_file(&live).unwrap();
    std::fs::create_dir(&live).unwrap();
    let err =
        ensure_installed_with(&f.ctx, &no_env, Core::Xray, &CoreVersions::default()).unwrap_err();
    assert_eq!(
        err.to_string(),
        format!("内核路径不是普通文件: {}", live.display())
    );
    // A missing core needs a valid wish: there is nothing to keep.
    std::fs::remove_dir(&live).unwrap();
    f.exec.clear_history();
    let bad_pin = CoreVersions {
        xray_pin: Some("bad pin".into()),
        ..CoreVersions::default()
    };
    let err = ensure_installed_with(&f.ctx, &no_env, Core::Xray, &bad_pin).unwrap_err();
    assert_eq!(err.to_string(), "版本格式无效: bad pin");
    assert!(f.curl_urls().is_empty());
}

#[test]
fn a_malformed_wish_only_warns_while_the_core_works() {
    // v2 stored `--singbox-version` as given; v2 then only printed its
    // hint. A working core is kept and the apply goes on.
    let f = fixture();
    f.serve();
    let live = live_singbox(&f, "1.14.2");
    for pin in ["beta", "LATEST", "1.12.0+x"] {
        let versions = CoreVersions {
            singbox_pin: Some(pin.into()),
            ..CoreVersions::default()
        };
        let v = ensure_installed_with(&f.ctx, &no_env, Core::Singbox, &versions).unwrap();
        assert_eq!(v, "1.14.2", "{pin}");
    }
    let env = |k: &str| (k == "ONEBOX_SINGBOX_VERSION").then(|| "beta".to_owned());
    let v = ensure_installed_with(&f.ctx, &env, Core::Singbox, &CoreVersions::default()).unwrap();
    assert_eq!(v, "1.14.2");
    assert_eq!(std::fs::read(&live).unwrap(), fake_elf("old"), "untouched");
    assert!(f.curl_urls().is_empty());
}

#[test]
fn keep_notice_wording() {
    let bad = Wanted::parse(Some("beta")).map(Some);
    assert_eq!(
        keep_notice(Core::Singbox, "1.14.2", &bad).as_deref(),
        Some("版本格式无效: beta；已保留已安装的 sing-box 1.14.2")
    );
    let exact = Ok(Some(Wanted::Exact("1.12.0".into())));
    assert_eq!(
        keep_notice(Core::Singbox, "1.14.2", &exact),
        pin_hint(
            Core::Singbox,
            "1.14.2",
            Some(&Wanted::Exact("1.12.0".into()))
        )
    );
    assert_eq!(keep_notice(Core::Xray, "26.3.27", &Ok(None)), None);
}

#[test]
fn installing_a_missing_core_needs_curl_and_offline_cores_do_not() {
    let f = fixture();
    // Neither curl nor a package manager: the download is refused before
    // any lookup (as root after looking for a package manager).
    let err = ensure_installed_with(&f.ctx, &no_env, Core::Singbox, &CoreVersions::default())
        .unwrap_err();
    assert!(err.to_string().ends_with("请先安装 curl"), "{err}");
    assert!(f.curl_urls().is_empty());

    // The offline override needs no network at all.
    let source = f.dir.join("offline-sing-box");
    std::fs::write(&source, fake_elf("offline")).unwrap();
    let bin = f.ctx.paths.bin.clone();
    versions(
        &f.exec,
        vec![
            (source.clone(), singbox_says("1.14.2")),
            (bin, singbox_says("1.14.2")),
        ],
    );
    let path = source.to_string_lossy().into_owned();
    let env = move |k: &str| (k == "ONEBOX_SINGBOX_BIN").then(|| path.clone());
    let v = ensure_installed_with(&f.ctx, &env, Core::Singbox, &CoreVersions::default()).unwrap();
    assert_eq!(v, "1.14.2");
    assert_eq!(
        std::fs::read(f.ctx.paths.core_bin(Core::Singbox)).unwrap(),
        fake_elf("offline")
    );
}
