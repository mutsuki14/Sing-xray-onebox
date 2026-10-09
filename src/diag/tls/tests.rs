use super::*;
use crate::diag::CheckStatus;
use crate::domain::config::WebCert;
use crate::domain::{fixtures, Core, Protocol};

const NOW: u64 = 1_800_000_000;

fn proxy() -> CertProbe {
    CertProbe::node(CertScope::Proxy, &CertDir::new("/t/etc/tls"))
}

#[test]
fn node_probes_name_their_renew_command() {
    assert_eq!(
        proxy(),
        CertProbe {
            name: "代理证书".into(),
            dir: "/t/etc/tls".into(),
            renew: "onebox cert renew proxy".into(),
            deploy: "onebox regen".into(),
        }
    );
}

#[test]
fn expiry_verdicts() {
    const WEEK: u64 = 7 * DAY;
    let renew = "执行 onebox cert renew proxy";
    let cases = [
        (None, CheckStatus::Warn, "无法读取证书有效期".to_owned()),
        (
            Some(NOW - 1),
            CheckStatus::Fail,
            format!("已于 {} 过期；{renew}", format_utc(NOW - 1)),
        ),
        (
            Some(NOW - 10 * DAY),
            CheckStatus::Fail,
            format!("已于 {} 过期；{renew}", format_utc(NOW - 10 * DAY)),
        ),
        (
            Some(NOW),
            CheckStatus::Warn,
            format!("将在 1 天内到期（{}）；{renew}", format_utc(NOW)),
        ),
        (
            Some(NOW + 3600),
            CheckStatus::Warn,
            format!("将在 1 天内到期（{}）；{renew}", format_utc(NOW + 3600)),
        ),
        (
            Some(NOW + WEEK - 1),
            CheckStatus::Warn,
            format!("将在 7 天内到期（{}）；{renew}", format_utc(NOW + WEEK - 1)),
        ),
        (
            Some(NOW + WEEK),
            CheckStatus::Pass,
            format!("有效期至 {}（剩余 7 天）", format_utc(NOW + WEEK)),
        ),
        (
            Some(NOW + 3650 * DAY),
            CheckStatus::Pass,
            format!("有效期至 {}（剩余 3650 天）", format_utc(NOW + 3650 * DAY)),
        ),
    ];
    for (expires, status, detail) in cases {
        assert_eq!(
            expiry_check(&proxy(), expires, NOW),
            Check::new("代理证书", status, detail),
            "{expires:?}"
        );
    }
    let site = expiry_check(
        &CertProbe::node(CertScope::Site, &CertDir::new("/s")),
        Some(NOW - 1),
        NOW,
    );
    assert_eq!(site.name, "网站证书");
    assert!(site.detail.ends_with("执行 onebox cert renew site"));
}

/// `cert info` (`CertStatus::warning`) and doctor agree at every boundary
/// of the 7-day window.
#[test]
fn expiry_agrees_with_cert_status_warning() {
    use crate::cert::store::days_until;
    use crate::cert::CertStatus;
    for offset in [
        -(DAY as i64),
        -1,
        0,
        1,
        6 * DAY as i64,
        7 * DAY as i64 - 1,
        7 * DAY as i64,
        8 * DAY as i64 - 1,
        8 * DAY as i64,
        30 * DAY as i64,
    ] {
        let at = (NOW as i64 + offset) as u64;
        let status = CertStatus {
            dir: "/d".into(),
            x509: Default::default(),
            days_left: Some(days_until(at, NOW)),
            metadata: None,
        };
        let cert_says = match status.warning(CERT_WARNING_DAYS) {
            None => CheckStatus::Pass,
            Some(w) if w == "证书已过期" => CheckStatus::Fail,
            Some(_) => CheckStatus::Warn,
        };
        assert_eq!(
            expiry_check(&proxy(), Some(at), NOW).status,
            cert_says,
            "{offset}"
        );
    }
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
            renewal_job_verdict(&node_renewal_job(need), line.clone(), scheduler),
            Check::new(RENEWAL, status, detail),
            "{need:?} {line:?} {scheduler}"
        );
    }
    let frp = RenewalJob {
        name: "FRP 续期任务",
        tag: Tag::frp_renew(),
        required: false,
        effect: "网站证书不会自动续期",
        fix: "onebox frps renew",
    };
    assert_eq!(
        renewal_job_verdict(&frp, Ok(false), false),
        Check::warn(
            "FRP 续期任务",
            "缺少每日续期任务，网站证书不会自动续期；执行 onebox frps renew"
        )
    );
}

#[test]
fn nginx_configurations_in_use() {
    let paths = Paths::isolated(std::path::Path::new("/t"));
    let reality = fixtures::config(&[(Protocol::VlessReality, 443, Core::Singbox)]);
    assert!(nginx_configs(&reality, &paths).is_empty());
    let mut both = fixtures::with_site(reality.clone(), "blog.example.org", false);
    both.subscription = Some(fixtures::standalone_subscription(
        "sub.example.org",
        8448,
        WebCert::Cloudflare,
    ));
    assert_eq!(
        nginx_configs(&both, &paths),
        [
            (SITE_NGINX, paths.site(), paths.site().join("nginx.conf")),
            (
                SUBSCRIPTION_NGINX,
                paths.subscription(),
                paths.subscription().join("nginx.conf")
            ),
        ]
    );
    let mut ip = reality;
    ip.subscription = Some(fixtures::ip_subscription(8448));
    assert!(
        nginx_configs(&ip, &paths).is_empty(),
        "ip mode runs no nginx"
    );
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

#[test]
fn real_openssl_certificates_by_remaining_validity() {
    use crate::cert::testing::{have_openssl, self_signed, Fixture};
    if !have_openssl() {
        return;
    }
    for (days, status, text) in [
        (3, CheckStatus::Warn, "将在 3 天内到期"),
        (30, CheckStatus::Pass, "有效期至 "),
    ] {
        let fixture = Fixture::new("diag-cert");
        let dir = CertDir::proxy(&fixture.ctx.paths);
        self_signed(dir.path(), &["www.bing.com"], days);
        let doctor = Doctor {
            ctx: &fixture.ctx,
            init: crate::host::init::InitSystem::None,
            now: crate::sys::time::now(),
        };
        let check = certificate_check(&doctor, &CertProbe::node(CertScope::Proxy, &dir));
        assert_eq!(check.status, status, "{check:?}");
        assert!(check.detail.contains(text), "{check:?}");
    }
}
