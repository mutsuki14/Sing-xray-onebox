//! Ported v2 tag/release/manifest tests plus global release sorting.

use super::*;
use crate::bbr::fixture::{release, ARCH, KERNEL, TAG};
use serde_json::json;

fn published(tag: &str) -> Value {
    json!({"tag_name": tag, "draft": false, "prerelease": false})
}

#[test]
fn tag_validation_excludes_cross_arch_profile_and_path_injection() {
    for tag in [
        "arm64-7.2.8",
        "x86_64-7.2.8-max",
        "x86_64-7.2.8-rc1",
        "../latest",
        "x86_64-7.2.8/../foo",
        "x86_64-7",
        "x86_64-7.2.3.4",
        "x86_64-",
        "x86_64-7..2",
        "x86_64-７.2",
    ] {
        assert!(tag_version(tag, ARCH, false).is_none(), "{tag}");
        assert!(kernel_name(tag, ARCH, false).is_err(), "{tag}");
    }
    assert!(tag_version("x86_64-7.2", ARCH, false).is_some());
    assert!(
        tag_version("x86_64-7.2.8", ARCH, true).is_none(),
        "Max needs -max"
    );
    assert_eq!(kernel_name(TAG, ARCH, false).unwrap(), KERNEL);
    assert_eq!(
        kernel_name("x86_64-7.2.8-max", ARCH, true).unwrap(),
        "7.2.8-joeyblog-bbrv3-max"
    );
    assert_eq!(
        kernel_name("arm64-7.3", ARM64, false).unwrap(),
        "7.3-joeyblog-bbrv3"
    );
    assert_eq!(
        kernel_name("x86_64-7.2.8-rc1", ARCH, false)
            .unwrap_err()
            .to_string(),
        "Release 标签与架构/标准或 Max 类型不匹配"
    );
}

#[test]
fn architectures_from_uname() {
    assert_eq!(Arch::from_machine("x86_64\n").unwrap(), X86_64);
    assert_eq!(Arch::from_machine("aarch64").unwrap(), ARM64);
    assert_eq!(
        Arch::from_machine("riscv64").unwrap_err().to_string(),
        "Actions-bbr-v3 内核仅支持 x86_64 / aarch64"
    );
    assert_eq!(version_parts("7.2.10"), Some(vec![7, 2, 10]));
    assert_eq!(version_parts(""), None);
    assert_eq!(version_parts("99999999999999999999"), None);
}

#[test]
fn release_list_filters_and_sorts_numeric_versions() {
    let data = json!([
        {"tag_name":"x86_64-7.2.9","draft":false,"prerelease":false},
        {"tag_name":"x86_64-7.2.10","draft":false,"prerelease":false},
        {"tag_name":"x86_64-7.2.10","draft":false,"prerelease":false},
        {"tag_name":"x86_64-7.2.8-max","draft":false,"prerelease":false},
        {"tag_name":"arm64-7.2.99","draft":false,"prerelease":false},
        {"tag_name":"x86_64-99.0","draft":false,"prerelease":true},
        {"tag_name":"x86_64-99.0","draft":true,"prerelease":false},
        {"tag_name":"x86_64-98.0","draft":false},
        {"tag_name":"x86_64-97.0","draft":null,"prerelease":false}
    ]);
    let mut fetch = |_: &str| Ok(data.clone());
    assert_eq!(
        release_tags(ARCH, false, &mut fetch).unwrap(),
        ["x86_64-7.2.10", "x86_64-7.2.9"]
    );
    assert_eq!(
        release_tags(ARCH, true, &mut fetch).unwrap(),
        ["x86_64-7.2.8-max"]
    );
    let mut limited = |_: &str| Ok(json!({"message": "API rate limit exceeded"}));
    assert_eq!(
        release_tags(ARCH, false, &mut limited)
            .unwrap_err()
            .to_string(),
        "GitHub Release 响应无效 (可能被 API 限流): API rate limit exceeded"
    );
    let mut empty = |_: &str| Ok(json!([]));
    assert_eq!(
        release_tags(ARCH, true, &mut empty)
            .unwrap_err()
            .to_string(),
        "最近 500 个 Release 中未找到 x86_64 / Max；可指定完整 Release 标签"
    );
}

#[test]
fn release_list_paginates_using_only_direct_api_urls() {
    let first = json!((0..100)
        .map(|_| published("arm64-7.2.8"))
        .collect::<Vec<_>>());
    let mut requested = Vec::new();
    let mut fetch = |url: &str| {
        requested.push(url.to_string());
        assert!(url.starts_with("https://api.github.com/repos/byJoey/Actions-bbr-v3/releases?"));
        Ok(if url.ends_with("page=1") {
            first.clone()
        } else {
            json!([published(TAG)])
        })
    };
    assert_eq!(release_tags(ARCH, false, &mut fetch).unwrap(), [TAG]);
    assert_eq!(requested.len(), 2);
}

#[test]
fn newer_releases_on_later_pages_win() {
    // Page 1 is full and already has a match; v2 stopped there.
    let mut page1: Vec<Value> = (0..99).map(|_| published("arm64-7.2.8")).collect();
    page1.push(published("x86_64-7.1.5"));
    let page2 = json!([published("x86_64-7.2.1"), published("x86_64-6.9")]);
    let mut pages = 0;
    let mut fetch = |url: &str| {
        pages += 1;
        Ok(if url.ends_with("page=1") {
            Value::Array(page1.clone())
        } else {
            page2.clone()
        })
    };
    assert_eq!(
        release_tags(ARCH, false, &mut fetch).unwrap(),
        ["x86_64-7.2.1", "x86_64-7.1.5", "x86_64-6.9"]
    );
    assert_eq!(pages, 2, "page 2 was short, so scanning stopped");
    let full: Vec<Value> = (0..100).map(|_| published("arm64-1.0")).collect();
    let mut calls = 0;
    let mut always_full = |_: &str| {
        calls += 1;
        Ok(Value::Array(full.clone()))
    };
    assert!(release_tags(ARCH, false, &mut always_full).is_err());
    assert_eq!(calls, 5, "at most five pages");
}

#[test]
fn exact_manifest_ignores_unrelated_assets() {
    let mut data = release();
    data["assets"].as_array_mut().unwrap().extend([
        json!({"name":"install.sh"}),
        json!({"name":"linux-libc-dev_7.2.8-1_amd64.deb"}),
        json!({"name":"linux-image-debug.deb"}),
        json!({"name": format!("linux-image-{KERNEL}-dbg_7.2.8-1_amd64.deb")}),
        json!({"name": format!("linux-image-{KERNEL}_7.2.8-1_arm64.deb")}),
    ]);
    let manifest = Manifest::parse(&data, TAG, ARCH, false).unwrap();
    assert_eq!(manifest.kernel, KERNEL);
    assert_eq!(manifest.tag, TAG);
    assert_eq!(manifest.assets.len(), 2);
    assert_eq!(manifest.assets[0].package, format!("linux-image-{KERNEL}"));
    assert_eq!(
        manifest.assets[1].package,
        format!("linux-headers-{KERNEL}")
    );
    assert_eq!(manifest.total(), 14);
    assert_eq!(
        manifest.assets[0].url,
        format!("https://github.com/byJoey/Actions-bbr-v3/releases/download/{TAG}/linux-image-{KERNEL}_7.2.8-1_amd64.deb")
    );
}

#[test]
fn rejects_incomplete_or_untrusted_manifest() {
    let changes = [
        (
            "digest",
            Value::Null,
            "BBR Release 缺少可信 SHA-256，拒绝安装",
        ),
        (
            "digest",
            json!("sha256:bad"),
            "BBR Release 缺少可信 SHA-256，拒绝安装",
        ),
        (
            "digest",
            json!(format!("sha256:{}", "A".repeat(64))),
            "BBR Release 缺少可信 SHA-256，拒绝安装",
        ),
        (
            "digest",
            json!("a".repeat(64)),
            "BBR Release 缺少可信 SHA-256，拒绝安装",
        ),
        (
            "browser_download_url",
            json!("https://example.invalid/evil.deb"),
            "BBR 包下载地址不是指定的官方 Release 资产",
        ),
        ("size", json!(-1), "BBR 包大小无效"),
        ("size", json!(1.5), "BBR 包大小无效"),
        ("size", json!(0), "BBR 包大小无效"),
        ("size", json!(2_147_483_649u64), "BBR 包大小无效"),
        ("size", json!("7"), "BBR 包大小无效"),
        (
            "name",
            json!("../evil.deb"),
            "BBR Release 必须恰好包含一个 linux-image-7.2.8-joeyblog-bbrv3 包",
        ),
        (
            "name",
            json!(format!("linux-image-{KERNEL}_7.2.8 1_amd64.deb")),
            "BBR 包文件名不安全",
        ),
    ];
    for (key, value, message) in changes {
        let mut data = release();
        data["assets"][0][key] = value;
        assert_eq!(
            Manifest::parse(&data, TAG, ARCH, false)
                .unwrap_err()
                .to_string(),
            message,
            "{key}"
        );
    }
    for (key, value) in [
        ("tag_name", json!("arm64-7.2.8")),
        ("draft", json!(true)),
        ("prerelease", json!(true)),
        ("draft", Value::Null),
        ("prerelease", json!("false")),
    ] {
        let mut data = release();
        data[key] = value;
        assert_eq!(
            Manifest::parse(&data, TAG, ARCH, false)
                .unwrap_err()
                .to_string(),
            "BBR Release 标签不匹配、尚未发布或为预发布版"
        );
    }
    let mut duplicate = release();
    let asset = duplicate["assets"][0].clone();
    duplicate["assets"].as_array_mut().unwrap().push(asset);
    assert!(Manifest::parse(&duplicate, TAG, ARCH, false).is_err());
    let mut missing = release();
    missing["assets"].as_array_mut().unwrap().pop();
    assert_eq!(
        Manifest::parse(&missing, TAG, ARCH, false)
            .unwrap_err()
            .to_string(),
        "BBR Release 必须恰好包含一个 linux-headers-7.2.8-joeyblog-bbrv3 包"
    );
    let mut no_assets = release();
    no_assets["assets"] = Value::Null;
    assert_eq!(
        Manifest::parse(&no_assets, TAG, ARCH, false)
            .unwrap_err()
            .to_string(),
        "BBR Release 缺少包列表"
    );
    assert!(Manifest::parse(&release(), "../latest", ARCH, false).is_err());
}

#[test]
fn urls_are_built_from_validated_tags_only() {
    assert_eq!(
        tag_url(TAG),
        "https://api.github.com/repos/byJoey/Actions-bbr-v3/releases/tags/x86_64-7.2.8"
    );
    assert_eq!(
        list_url(3),
        "https://api.github.com/repos/byJoey/Actions-bbr-v3/releases?per_page=100&page=3"
    );
}
