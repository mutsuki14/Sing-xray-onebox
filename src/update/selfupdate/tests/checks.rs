//! `update-check`, channel and release rules, asset verification.

use super::*;

#[test]
fn update_check_reports_and_changes_nothing() {
    let fx = Fx::new(true, Some("3.0.0"));
    let rel = Rel::stable("3.0.1");
    fx.serve(&rel);
    fx.run(None, true).unwrap();
    assert_eq!(fx.curl_urls(), [rel.api_url()]);
    assert_eq!(fx.engine.recover_calls(), 0);
    assert!(!fx.paths().update_lock().exists(), "no lock taken");
    assert!(!fx.paths().lock().exists());
    fx.assert_untouched(&program("3.0.0\n"));
}

#[test]
fn stable_downgrades_are_refused_by_check_and_update() {
    for check_only in [true, false] {
        let fx = Fx::new(true, Some("3.0.2"));
        let rel = Rel::stable("3.0.1");
        fx.serve(&rel);
        let err = fx.run(None, check_only).unwrap_err();
        assert_eq!(err.to_string(), NEWER_INSTALLED);
        assert_eq!(fx.curl_urls(), [rel.api_url()]);
        assert_eq!(fx.engine.recover_calls(), 0);
        fx.assert_untouched(&program("3.0.2\n"));
    }
}

#[test]
fn testing_channel_follows_the_testing_tag() {
    let fx = Fx::new(true, Some("3.0.2"));
    channel::save(fx.paths(), Channel::Testing).unwrap();
    let rel = Rel::testing("3.0.1");
    fx.serve(&rel);
    // The testing build's version is unknown before the download: the
    // check passes, the update refuses once it probed the binary.
    fx.run(None, true).unwrap();
    let err = fx.run(None, false).unwrap_err();
    assert_eq!(err.to_string(), DOWNLOADED_OLDER);
    assert_eq!(
        fx.curl_urls(),
        [rel.api_url(), rel.api_url(), rel.asset_url()]
    );
    fx.assert_untouched(&program("3.0.2\n"));
    // An explicit channel wins over the saved one.
    let err = fx.run(Some(Channel::Stable), true).unwrap_err();
    assert!(err.to_string().contains("404"), "{err}");
    assert_eq!(fx.curl_urls().last().unwrap(), &format!("{API}/latest"));
}

#[test]
fn a_testing_build_installs_once_its_probed_version_passes() {
    // No tag to compare with: the probed version must be a supported 3.x,
    // not older than the installed manager.
    let fx = Fx::new(true, Some("3.0.1"));
    let rel = Rel::testing("3.0.2");
    fx.serve(&rel);
    assert_done(fx.run(Some(Channel::Testing), false));
    assert_eq!(fx.phases(), [Prepared, Replacing, Replaced, Committed]);
    assert_eq!(fx.exe(), rel.binary);
    assert_eq!(fx.regens().len(), 1);
    assert_eq!(fx.curl_urls(), [rel.api_url(), rel.asset_url()]);
    assert!(fx.work_dirs().is_empty());
    // The same build is "already current" the next time.
    fx.run(Some(Channel::Testing), false).unwrap();
    assert_eq!(fx.phases().len(), 4, "no second replacement");
}

#[test]
fn channel_mismatches_are_refused() {
    let cases = [
        Rel {
            prerelease: true,
            ..Rel::stable("3.0.1")
        },
        Rel {
            draft: true,
            ..Rel::stable("3.0.1")
        },
        Rel {
            draft: true,
            ..Rel::testing("3.0.1")
        },
    ];
    for rel in cases {
        let fx = Fx::new(true, Some("3.0.0"));
        fx.serve(&rel);
        let err = fx.run(Some(rel.channel), true).unwrap_err();
        assert_eq!(err.to_string(), "更新来源不是指定渠道的有效发布", "{rel:?}");
    }
}

#[test]
fn a_cpu_without_a_release_build_keeps_the_manager() {
    let fx = Fx::on("riscv64", true, Some("3.0.0"));
    fx.serve(&Rel::stable("3.0.1"));
    let err = fx.run(None, true).unwrap_err();
    assert_eq!(
        err.to_string(),
        "此发布缺少 onebox-linux-riscv64-musl；保持已安装程序"
    );
}

// ---- asset verification ---------------------------------------------------

#[test]
fn asset_verification_uses_the_api_digest_or_the_direct_checksum_file() {
    struct Case {
        digest: Digest,
        proxy: bool,
        /// `Ok(curl URLs after the API call)` or `Err(error text part)`.
        expect: std::result::Result<Vec<&'static str>, &'static str>,
    }
    let cases = [
        Case {
            digest: Digest::Api,
            proxy: true,
            expect: Ok(vec!["proxied-asset"]),
        },
        Case {
            digest: Digest::Sums,
            proxy: true,
            expect: Ok(vec!["sums", "proxied-asset"]),
        },
        Case {
            digest: Digest::Sums,
            proxy: false,
            expect: Ok(vec!["sums", "asset"]),
        },
        Case {
            digest: Digest::Neither,
            proxy: false,
            expect: Err("onebox-linux-amd64-musl 缺少 SHA256 校验信息，拒绝安装"),
        },
        Case {
            digest: Digest::Wrong,
            proxy: false,
            expect: Err("下载文件 SHA256 不匹配: onebox-linux-amd64-musl"),
        },
    ];
    for case in cases {
        let mut fx = Fx::new(false, Some("3.0.0"));
        if case.proxy {
            fx.env.set("GH_PROXY", PROXY);
        }
        let rel = Rel {
            digest: case.digest,
            ..Rel::stable("3.0.1")
        };
        fx.serve(&rel);
        let result = fx.run(None, false);
        let label = format!("{:?} proxy={}", case.digest, case.proxy);
        match case.expect {
            Ok(urls) => {
                assert_done(result);
                let want: Vec<String> = std::iter::once(rel.api_url())
                    .chain(urls.iter().map(|u| match *u {
                        "sums" => rel.sums_url(),
                        "asset" => rel.asset_url(),
                        _ => format!("{PROXY}{}", rel.asset_url()),
                    }))
                    .collect();
                assert_eq!(fx.curl_urls(), want, "{label}");
                assert_eq!(fx.exe(), rel.binary, "{label}");
            }
            Err(part) => {
                let err = result.unwrap_err().to_string();
                assert!(err.contains(part), "{label}: {err}");
                fx.assert_untouched(&program("3.0.0\n"));
            }
        }
    }
}

#[test]
fn wrong_sizes_and_non_programs_are_refused() {
    let short = Rel {
        served: Some(program("3.0.1")),
        ..Rel::stable("3.0.1")
    };
    let script = Rel::stable("3.0.1").with_binary(b"#!/bin/sh\necho 3.0.1 # padding\n".to_vec());
    for (rel, part) in [(short, "大小与发行元信息不符"), (script, NOT_ELF)] {
        let fx = Fx::new(true, Some("3.0.0"));
        fx.serve(&rel);
        let err = fx.run(None, false).unwrap_err().to_string();
        assert!(err.contains(part), "{err}");
        fx.assert_untouched(&program("3.0.0\n"));
    }
}
