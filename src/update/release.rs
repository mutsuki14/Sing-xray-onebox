//! The manager's own GitHub release for a channel, the asset for this CPU,
//! version rules and the report printed before an update (spec G §2.9,
//! §4.2–4.3).
//!
//! Trust chain: metadata over direct TLS from api.github.com (never
//! `GH_PROXY`); the channel's release must not be a draft (stable: nor a
//! prerelease); the asset `onebox-linux-{arch}-musl` must sit at exactly
//! `https://github.com/{REPOSITORY}/releases/download/{tag}/{name}`. Its size
//! and SHA-256 are checked by `host::fetch::download_asset` (the API digest,
//! or the release's `SHA256SUMS` fetched directly from github.com when the
//! API has none — G-8.1#6, G26).
//!
//! Changes from v2:
//! - versions are ordered with semver precedence (`domain::version`), so a
//!   prerelease such as `3.1.0-rc.1` sorts before `3.1.0` (v2 dropped the
//!   suffix and treated them as equal);
//! - an architecture without a release build names the sing-box spelling
//!   of the CPU (`armv6`, `riscv64`, …) in the "missing asset" message, as
//!   v2 did, without first mapping it through the core tables.

use super::channel::Channel;
use crate::domain::version::Semver;
use crate::error::{Error, Result};
use crate::host::fetch::{self, Asset, Release};
use crate::host::os::{Arch, EnvLookup};
use crate::{Ctx, REPOSITORY};

/// Release file holding checksums for assets the API has no digest for.
pub const CHECKSUMS: &str = "SHA256SUMS";
/// Release lines shown at most (v2).
pub const BODY_LINES: usize = 12;
/// Characters per release line shown at most (v2).
pub const BODY_LINE_CHARS: usize = 200;
const WRONG_CHANNEL: &str = "更新来源不是指定渠道的有效发布";
const URL_MISMATCH: &str = "发布文件地址与仓库不匹配";
const NOT_SEMVER: &str = "版本需要 major.minor.patch";

/// A verified-to-be-sane release of the manager for one channel.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SelfRelease {
    pub channel: Channel,
    pub release: Release,
    /// `onebox-linux-{arch}-musl` of this release.
    pub asset: Asset,
    /// What the report calls the release version: the tag without `v` on
    /// stable (a semantic version), the literal `testing` on testing.
    pub remote: String,
}

impl SelfRelease {
    /// The release's semantic version (stable only; testing builds are
    /// known only after their `version` was probed).
    pub fn version(&self) -> Option<Semver> {
        match self.channel {
            Channel::Stable => Semver::parse(&self.remote),
            Channel::Testing => None,
        }
    }
}

/// Look up the channel's release and pick this CPU's asset.
pub fn lookup(ctx: &Ctx, env: EnvLookup, channel: Channel) -> Result<SelfRelease> {
    let release = fetch::github_release_with(ctx, env, REPOSITORY, &channel.which())?;
    let arch = Arch::detect(ctx)?;
    select(channel, release, &asset_name(arch))
}

/// The release checks of [`lookup`] once the metadata is known.
pub fn select(channel: Channel, release: Release, asset_name: &str) -> Result<SelfRelease> {
    check_channel(&release, channel)?;
    let asset = release
        .asset(asset_name)
        .cloned()
        .ok_or_else(|| Error::msg(format!("此发布缺少 {asset_name}；保持已安装程序")))?;
    ensure!(
        asset.url == Asset::expected_url(REPOSITORY, &release.tag, &asset.name),
        "{URL_MISMATCH}"
    );
    let remote = remote_version(channel, &release.tag)?;
    Ok(SelfRelease {
        channel,
        release,
        asset,
        remote,
    })
}

/// `onebox-linux-{amd64|arm64|386|armv7}-musl`; other CPUs get the name
/// they would have (the release then lacks it).
pub fn asset_name(arch: Arch) -> String {
    arch.onebox_asset()
        .unwrap_or_else(|| format!("onebox-linux-{}-musl", arch.id()))
}

/// Drafts never qualify; stable also refuses prereleases (a field missing
/// in the metadata counts as set, so it fails safe).
pub fn check_channel(release: &Release, channel: Channel) -> Result<()> {
    let prerelease_refused = channel == Channel::Stable && release.prerelease;
    ensure!(!release.draft && !prerelease_refused, "{WRONG_CHANNEL}");
    Ok(())
}

/// The report's release version: stable → the tag without `v` (must be a
/// semantic version); testing → `testing`.
pub fn remote_version(channel: Channel, tag: &str) -> Result<String> {
    match channel {
        Channel::Stable => {
            parse(tag)?;
            Ok(tag.strip_prefix('v').unwrap_or(tag).to_owned())
        }
        Channel::Testing => Ok(super::channel::TESTING_TAG.to_owned()),
    }
}

/// A semantic version, or v2's `版本需要 major.minor.patch`.
pub fn parse(version: &str) -> Result<Semver> {
    Semver::parse(version).ok_or_else(|| Error::msg(NOT_SEMVER))
}

/// The version a `{program} version` call printed: trimmed, one leading
/// `v` dropped, a semantic version.
pub fn reported_version(output: &str) -> Result<String> {
    let text = output.trim();
    let text = text.strip_prefix('v').unwrap_or(text);
    parse(text)?;
    Ok(text.to_owned())
}

/// `Err(message)` when `candidate` is older than `installed`.
pub fn refuse_older(candidate: &str, installed: &str, message: &str) -> Result<()> {
    ensure!(parse(candidate)? >= parse(installed)?, "{message}");
    Ok(())
}

/// The three version lines, then up to [`BODY_LINES`] release-note lines
/// (two-space indent, control characters removed, at most
/// [`BODY_LINE_CHARS`] characters each).
pub fn report_lines(channel: Channel, installed: &str, remote: &str, body: &str) -> Vec<String> {
    let mut lines = vec![
        format!("更新渠道: {channel}"),
        format!("当前版本: {installed}"),
        format!("发布版本: {remote}"),
    ];
    lines.extend(body.lines().take(BODY_LINES).map(|line| {
        let clean: String = line
            .chars()
            .filter(|c| !c.is_control())
            .take(BODY_LINE_CHARS)
            .collect();
        format!("  {clean}")
    }));
    lines
}

#[cfg(test)]
mod tests {
    use super::*;

    fn asset(name: &str, tag: &str) -> Asset {
        Asset {
            name: name.into(),
            url: Asset::expected_url(REPOSITORY, tag, name),
            size: 10,
            digest: None,
        }
    }

    fn release(tag: &str, draft: bool, prerelease: bool) -> Release {
        Release {
            tag: tag.into(),
            draft,
            prerelease,
            body: String::new(),
            assets: vec![asset("onebox-linux-amd64-musl", tag), asset(CHECKSUMS, tag)],
        }
    }

    #[test]
    fn channel_rules_for_drafts_and_prereleases() {
        let cases = [
            (Channel::Stable, false, false, true),
            (Channel::Stable, false, true, false),
            (Channel::Stable, true, false, false),
            (Channel::Testing, false, true, true),
            (Channel::Testing, false, false, true),
            (Channel::Testing, true, true, false),
        ];
        for (channel, draft, prerelease, ok) in cases {
            let result = check_channel(&release("v3.0.1", draft, prerelease), channel);
            match result {
                Ok(()) => assert!(ok, "{channel} {draft} {prerelease}"),
                Err(e) => {
                    assert!(!ok, "{channel} {draft} {prerelease}");
                    assert_eq!(e.to_string(), WRONG_CHANNEL);
                }
            }
        }
    }

    #[test]
    fn asset_selection_and_url_pinning() {
        let found = select(
            Channel::Stable,
            release("v3.0.1", false, false),
            "onebox-linux-amd64-musl",
        )
        .unwrap();
        assert_eq!(found.remote, "3.0.1");
        assert_eq!(found.version(), Semver::parse("3.0.1"));
        assert_eq!(found.asset.name, "onebox-linux-amd64-musl");

        let missing = select(
            Channel::Stable,
            release("v3.0.1", false, false),
            "onebox-linux-riscv64-musl",
        )
        .unwrap_err();
        assert_eq!(
            missing.to_string(),
            "此发布缺少 onebox-linux-riscv64-musl；保持已安装程序"
        );

        for url in [
            "https://github.com/someone/fork/releases/download/v3.0.1/onebox-linux-amd64-musl",
            "https://github.com/mutsuki14/Sing-xray-onebox/releases/download/v3.0.0/onebox-linux-amd64-musl",
            "http://github.com/mutsuki14/Sing-xray-onebox/releases/download/v3.0.1/onebox-linux-amd64-musl",
        ] {
            let mut r = release("v3.0.1", false, false);
            r.assets[0].url = url.into();
            let err = select(Channel::Stable, r, "onebox-linux-amd64-musl").unwrap_err();
            assert_eq!(err.to_string(), URL_MISMATCH, "{url}");
        }

        let testing = select(
            Channel::Testing,
            release("testing", false, true),
            "onebox-linux-amd64-musl",
        )
        .unwrap();
        assert_eq!(testing.remote, "testing");
        assert_eq!(testing.version(), None);
        // A stable tag must be a semantic version.
        let err = select(
            Channel::Stable,
            release("nightly", false, false),
            "onebox-linux-amd64-musl",
        )
        .unwrap_err();
        assert_eq!(err.to_string(), NOT_SEMVER);
    }

    #[test]
    fn asset_names_per_cpu() {
        assert_eq!(asset_name(Arch::Amd64), "onebox-linux-amd64-musl");
        assert_eq!(asset_name(Arch::Arm64), "onebox-linux-arm64-musl");
        assert_eq!(asset_name(Arch::I386), "onebox-linux-386-musl");
        assert_eq!(asset_name(Arch::Armv7), "onebox-linux-armv7-musl");
        assert_eq!(asset_name(Arch::Armv6), "onebox-linux-armv6-musl");
        assert_eq!(asset_name(Arch::Riscv64), "onebox-linux-riscv64-musl");
    }

    #[test]
    fn version_rules() {
        assert_eq!(reported_version("3.0.0\n").unwrap(), "3.0.0");
        assert_eq!(reported_version(" v3.1.0-rc.1 ").unwrap(), "3.1.0-rc.1");
        for bad in ["", "3.0", "Onebox 3.0.0", "3.0.0\n3.0.1", "../../1"] {
            assert_eq!(
                reported_version(bad).unwrap_err().to_string(),
                NOT_SEMVER,
                "{bad:?}"
            );
        }
        let cases = [
            ("3.0.1", "3.0.0", true),
            ("3.0.0", "3.0.0", true),
            ("2.9.9", "3.0.0", false),
            ("1.99.1", "2.0.0", false),
            ("3.1.0-rc.1", "3.1.0", false),
            ("3.1.0", "3.1.0-rc.1", true),
            ("10.0.0", "9.9.9", true),
        ];
        for (candidate, installed, ok) in cases {
            let result = refuse_older(candidate, installed, "拒绝降级");
            assert_eq!(result.is_ok(), ok, "{candidate} vs {installed}");
        }
        assert_eq!(
            refuse_older("2.0", "3.0.0", "x").unwrap_err().to_string(),
            NOT_SEMVER
        );
        assert_eq!(remote_version(Channel::Stable, "v3.0.1").unwrap(), "3.0.1");
        assert_eq!(remote_version(Channel::Stable, "3.0.1").unwrap(), "3.0.1");
        assert_eq!(
            remote_version(Channel::Testing, "anything").unwrap(),
            "testing"
        );
    }

    #[test]
    fn report_shows_versions_and_sanitized_notes() {
        let long = "长".repeat(250);
        let body =
            format!("## 更新\r\n- 修复\t问题\x1b[31m\n\n{long}\n4\n5\n6\n7\n8\n9\n10\n11\n12\n13");
        let lines = report_lines(Channel::Stable, "3.0.0", "3.0.1", &body);
        assert_eq!(
            lines[..3],
            ["更新渠道: stable", "当前版本: 3.0.0", "发布版本: 3.0.1"]
        );
        assert_eq!(lines.len(), 3 + BODY_LINES);
        assert_eq!(lines[3], "  ## 更新");
        assert_eq!(lines[4], "  - 修复问题[31m");
        assert_eq!(lines[5], "  ");
        assert_eq!(lines[6].chars().count(), 2 + BODY_LINE_CHARS);
        assert_eq!(lines.last().unwrap(), "  11");
        assert_eq!(
            report_lines(Channel::Testing, "3.0.0", "testing", "").len(),
            3
        );
    }
}
