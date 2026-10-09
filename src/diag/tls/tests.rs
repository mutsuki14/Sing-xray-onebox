use super::*;
use crate::diag::CheckStatus;
use crate::domain::config::WebCert;
use crate::domain::{fixtures, Core, Protocol};

const NOW: u64 = 1_800_000_000;

#[test]
fn expiry_verdicts() {
    let cases = [
        (None, CheckStatus::Warn, "无法读取证书有效期".to_owned()),
        (
            Some(NOW),
            CheckStatus::Fail,
            format!(
                "已于 {} 过期；执行 onebox cert renew proxy",
                format_utc(NOW)
            ),
        ),
        (
            Some(NOW - 10 * DAY),
            CheckStatus::Fail,
            format!(
                "已于 {} 过期；执行 onebox cert renew proxy",
                format_utc(NOW - 10 * DAY)
            ),
        ),
        (
            Some(NOW + 3600),
            CheckStatus::Warn,
            format!(
                "将在 1 天内到期（{}）；执行 onebox cert renew proxy",
                format_utc(NOW + 3600)
            ),
        ),
        (
            Some(NOW + WARN_SECS - 1),
            CheckStatus::Warn,
            format!(
                "将在 7 天内到期（{}）；执行 onebox cert renew proxy",
                format_utc(NOW + WARN_SECS - 1)
            ),
        ),
        (
            Some(NOW + WARN_SECS),
            CheckStatus::Pass,
            format!("有效期至 {}（剩余 7 天）", format_utc(NOW + WARN_SECS)),
        ),
        (
            Some(NOW + 3650 * DAY),
            CheckStatus::Pass,
            format!("有效期至 {}（剩余 3650 天）", format_utc(NOW + 3650 * DAY)),
        ),
    ];
    for (expires, status, detail) in cases {
        assert_eq!(
            expiry_check(CertScope::Proxy, expires, NOW),
            Check::new("代理证书", status, detail),
            "{expires:?}"
        );
    }
    let site = expiry_check(CertScope::Site, Some(NOW), NOW);
    assert_eq!(site.name, "网站证书");
    assert!(site.detail.ends_with("执行 onebox cert renew site"));
}

#[test]
fn renewal_verdicts() {
    use RenewNeed::{Recommended, Required};
    let cases = [
        (
            Required,
            Ok(true),
            true,
            CheckStatus::Pass,
            "已安装每日续期任务",
        ),
        (
            Recommended,
            Ok(true),
            true,
            CheckStatus::Pass,
            "已安装每日续期任务",
        ),
        (
            Required,
            Ok(false),
            false,
            CheckStatus::Fail,
            "缺少每日续期任务，ACME 证书不会自动续期；执行 onebox regen",
        ),
        (
            Recommended,
            Ok(false),
            false,
            CheckStatus::Warn,
            "缺少每日续期任务，外部证书更新后不会自动部署；执行 onebox regen",
        ),
        (
            Required,
            Err("无法读取当前 crontab (2): x".to_owned()),
            false,
            CheckStatus::Fail,
            "无法读取当前 crontab (2): x，ACME 证书不会自动续期",
        ),
        (
            Required,
            Ok(true),
            false,
            CheckStatus::Warn,
            "cron 未运行，续期任务不会执行（ACME 证书不会自动续期）；请启动系统 cron 服务",
        ),
    ];
    for (need, line, scheduler, status, detail) in cases {
        assert_eq!(
            renewal_verdict(need, line.clone(), scheduler),
            Check::new(RENEWAL, status, detail),
            "{need:?} {line:?} {scheduler}"
        );
    }
}

#[test]
fn certificates_in_effect() {
    let paths = Paths::isolated(std::path::Path::new("/t"));
    let scopes = |cfg: &NodeConfig| -> Vec<CertScope> {
        certificates(cfg, &paths)
            .into_iter()
            .map(|(s, _)| s)
            .collect()
    };
    let reality = fixtures::config(&[(Protocol::VlessReality, 443, Core::Singbox)]);
    assert!(scopes(&reality).is_empty());
    let tuic = fixtures::config(&[(Protocol::Tuic, 443, Core::Singbox)]);
    assert_eq!(scopes(&tuic), [CertScope::Proxy]);
    assert_eq!(certificates(&tuic, &paths)[0].1, CertDir::new("/t/etc/tls"));

    let mut all = fixtures::with_site(
        fixtures::config(&[
            (Protocol::VlessReality, 443, Core::Singbox),
            (Protocol::Hysteria2, 8443, Core::Singbox),
        ]),
        "blog.example.org",
        false,
    );
    all.subscription = Some(fixtures::standalone_subscription(
        "sub.example.org",
        8448,
        WebCert::Cloudflare,
    ));
    assert_eq!(
        scopes(&all),
        [CertScope::Proxy, CertScope::Site, CertScope::Subscription]
    );
    assert_eq!(
        certificates(&all, &paths)[2].1,
        CertDir::new("/t/etc/subscription/tls")
    );

    // The site mode shares the site certificate; ip mode has none.
    let mut site_mode = all.clone();
    site_mode.subscription = Some(crate::domain::config::SubscriptionConfig {
        mode: crate::domain::config::SubscriptionMode::Site,
        port: 443,
    });
    assert_eq!(scopes(&site_mode), [CertScope::Proxy, CertScope::Site]);
    let mut ip = tuic;
    ip.subscription = Some(fixtures::ip_subscription(8448));
    assert_eq!(scopes(&ip), [CertScope::Proxy]);
}
