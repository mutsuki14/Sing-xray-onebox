use super::*;
use crate::cert::CertScope;
use crate::cli::args::{parse, Globals};
use crate::cli::session::testing::{Bench, Call};
use crate::domain::config::{AcmeMethod, ProxyCertMode};
use crate::domain::fixtures::config;
use crate::domain::protocol::Core::{Singbox as SB, Xray as XR};
use crate::domain::protocol::Protocol::*;
use std::sync::Mutex;

fn invocation(line: &str) -> (bool, Matches) {
    let argv: Vec<String> = line.split_whitespace().map(String::from).collect();
    let inv = parse(&[CERT, CERT_RENEW, RENEW], &argv, Globals::default())
        .unwrap_or_else(|e| panic!("{line}: {e}"));
    (inv.spec.root.required(&inv.matches), inv.matches)
}

/// Manual renewals are forced (F-8.1#3): the help must not read like a
/// due check, or repeated runs hit the Let's Encrypt rate limits.
#[test]
fn renew_help_says_manual_runs_are_forced() {
    let cert_renew = CERT.subcommands.iter().find(|c| c.name == "renew");
    for summary in [RENEW.summary, cert_renew.map_or("", |c| c.summary)] {
        assert!(
            summary.starts_with("立即强制续期") && summary.contains("--cron"),
            "{summary}"
        );
        assert!(summary.contains("30 天内到期"), "{summary}");
    }
    assert!(CRON.help.contains("30 天内到期"), "{}", CRON.help);
}

#[test]
fn command_forms_and_root() {
    let (root, m) = invocation("cert");
    assert!(!root && m.path == ["cert"]);
    let (root, m) = invocation("cert status");
    assert!(!root && m.path == ["cert", "info"]);
    let (root, m) = invocation("cert renew proxy --cron");
    assert!(root && m.flag("cron"));
    assert_eq!(targets(&m).unwrap(), CertScopes::only(CertScope::Proxy));
    let (_, m) = invocation("cert --cron renew site");
    assert!(m.flag("cron") && m.path == ["cert", "renew"]);
    let (root, m) = invocation("cert-renew subscription --cron");
    assert!(root);
    assert_eq!(
        targets(&m).unwrap(),
        CertScopes::only(CertScope::Subscription)
    );
    let (_, m) = invocation("cert renew");
    assert_eq!(targets(&m).unwrap(), CertScopes::ALL);
    let (_, m) = invocation("cert renew bogus");
    assert_eq!(
        targets(&m).unwrap_err().to_string(),
        "续期目标应为 proxy/site/subscription/all"
    );
    let (root, _) = invocation("renew --cron");
    assert!(root);
    let (root, _) = invocation("cert set --tls self");
    assert!(root);
}

#[test]
fn info_lists_certificate_directories() {
    let bench = Bench::installed(&config(&[(VlessReality, 443, XR)]));
    info(&bench.session()).unwrap();
    assert_eq!(
        bench.output(),
        "代理证书\n  未配置证书\n网站证书\n  未配置证书"
    );
    let mut cfg = config(&[(VlessReality, 443, XR)]);
    cfg.subscription = Some(crate::domain::fixtures::standalone_subscription(
        "sub.example.com",
        8448,
        crate::domain::config::WebCert::Cloudflare,
    ));
    let bench = Bench::installed(&cfg);
    info(&bench.session()).unwrap();
    assert!(bench.output().ends_with("订阅证书\n  未配置证书"));
}

fn trojan() -> NodeConfig {
    config(&[(Trojan, 443, SB)])
}

#[test]
fn set_asks_interactively_or_needs_tls() {
    let bench = Bench::installed(&trojan());
    bench.answers(&["2", "proxy.example.com"]);
    set(&bench.session(), None).unwrap();
    let req = bench.engine.single();
    assert_eq!(req.reason, "更换代理证书");
    assert_eq!(
        req.config.tls.unwrap().mode,
        ProxyCertMode::Acme {
            domain: "proxy.example.com".into(),
            method: AcmeMethod::Http01
        }
    );
    assert_eq!(bench.ui.prompts()[0], "选择代理证书方式");
    bench.unattended();
    let err = set(&bench.session(), None).unwrap_err();
    assert_eq!(err.to_string(), SET_NEEDS_TLS);
}

#[test]
fn set_with_options() {
    let bench = Bench::installed(&trojan());
    bench.unattended();
    let args = opt::CertArgs {
        choice: Some(plan::ProxyCertChoice::SelfSigned),
        vmess_host: None,
    };
    set(&bench.session(), Some(args)).unwrap();
    assert_eq!(bench.engine.single().reason, "更换代理证书");
    let reality = Bench::installed(&config(&[(VlessReality, 443, XR)]));
    let args = opt::CertArgs {
        choice: Some(plan::ProxyCertChoice::SelfSigned),
        vmess_host: None,
    };
    let err = set(&reality.session(), Some(args)).unwrap_err();
    assert_eq!(
        err.to_string(),
        "当前协议无需代理 TLS 证书，自建站证书请使用 site 管理"
    );
}

#[test]
fn set_with_cloudflare_needs_credentials_first() {
    if std::env::var_os("CF_Token").is_some() {
        return;
    }
    let bench = Bench::installed(&trojan());
    bench.unattended();
    let args = opt::CertArgs {
        choice: Some(plan::ProxyCertChoice::Acme {
            domain: "proxy.example.com".into(),
            method: AcmeMethod::Cloudflare,
        }),
        vmess_host: None,
    };
    let err = set(&bench.session(), Some(args.clone())).unwrap_err();
    assert_eq!(err.to_string(), crate::cert::cloudflare::MISSING);
    assert!(bench.engine.calls().is_empty(), "nothing applied");
    let bench = Bench::installed(&trojan());
    bench.answers(&["fake-token-0123", ""]);
    set(&bench.session(), Some(args)).unwrap();
    let creds = bench.engine.single().intents.cloudflare.unwrap();
    assert_eq!(creds.get("CF_Token"), Some("fake-token-0123"));
}

static REPORT: Mutex<Option<RenewReport>> = Mutex::new(None);

fn scripted(
    _ctx: &Ctx,
    lock: &FileLock,
    _cfg: &NodeConfig,
    opts: &RenewOptions,
    _cf: Option<&CfCredentials>,
) -> Result<RenewReport> {
    assert!(lock.path().ends_with(".apply.lock"));
    assert_eq!(opts.force, !opts.scheduled, "manual renewals force");
    Ok(REPORT.lock().unwrap().clone().unwrap_or_default())
}

#[test]
fn renewal_outcomes() {
    let _guard = serial();
    let bench = Bench::installed(&config(&[(VlessReality, 443, XR)]));
    *REPORT.lock().unwrap() = None;
    renew_with(&bench.session(), CertScopes::ALL, false, scripted).unwrap();
    assert_eq!(bench.notes(), ["[提示] 没有需要续期的证书"]);
    assert_eq!(bench.engine.calls(), [Call::RecoverLocked]);
    renew_with(&bench.session(), CertScopes::ALL, true, scripted).unwrap();
    assert_eq!(bench.notes().len(), 1, "silent under --cron");
    *REPORT.lock().unwrap() = Some(RenewReport {
        renewed: vec![CertScope::Proxy],
        proxy_identity_changed: true,
        ..RenewReport::default()
    });
    renew_with(&bench.session(), CertScopes::ALL, true, scripted).unwrap();
    let calls = bench.engine.calls();
    assert_eq!(calls.last(), Some(&Call::ApplyLocked));
    let req = bench.engine.single();
    assert_eq!(req.reason, "证书续期");
    assert_eq!(req.config, bench.state(), "unchanged configuration");
    *REPORT.lock().unwrap() = Some(RenewReport {
        failed: vec![
            (CertScope::Site, "boom".into()),
            (CertScope::Proxy, "x".into()),
        ],
        ..RenewReport::default()
    });
    let err = renew_with(&bench.session(), CertScopes::ALL, false, scripted).unwrap_err();
    assert_eq!(err.to_string(), "证书续期失败: 网站证书、代理证书");
    *REPORT.lock().unwrap() = None;
}

/// The republishing apply after a proxy identity change carries the
/// credentials resolved for the renewal (the apply never prompts).
#[test]
fn identity_change_apply_carries_the_resolved_credentials() {
    if std::env::var_os("CF_Token").is_some() {
        return;
    }
    let _guard = serial();
    let mut cfg = trojan();
    cfg.tls = Some(crate::domain::config::ProxyTls {
        mode: ProxyCertMode::Acme {
            domain: "proxy.example.com".into(),
            method: AcmeMethod::Cloudflare,
        },
        pinned: false,
    });
    let bench = Bench::installed(&cfg);
    bench.answers(&["fake-token-0123", ""]);
    *REPORT.lock().unwrap() = Some(RenewReport {
        renewed: vec![CertScope::Proxy],
        proxy_identity_changed: true,
        ..RenewReport::default()
    });
    let result = renew_with(&bench.session(), CertScopes::ALL, false, scripted);
    *REPORT.lock().unwrap() = None;
    result.unwrap();
    assert_eq!(
        bench.engine.calls(),
        [Call::RecoverLocked, Call::ApplyLocked]
    );
    let creds = bench.engine.single().intents.cloudflare.unwrap();
    assert_eq!(creds.get("CF_Token"), Some("fake-token-0123"));
}

/// A renewer that deploys a new pinned pair (the leaf changed) outside
/// any transaction, as `cert::renew_all` does.
fn rotating(
    ctx: &Ctx,
    _lock: &FileLock,
    _cfg: &NodeConfig,
    _opts: &RenewOptions,
    _cf: Option<&CfCredentials>,
) -> Result<RenewReport> {
    let dir = CertDir::proxy(&ctx.paths);
    std::fs::write(dir.key(), "NEW KEY").unwrap();
    std::fs::write(dir.cert(), "NEW CERT").unwrap();
    std::fs::write(dir.metadata_file(), "{\"new\":true}").unwrap();
    Ok(RenewReport {
        renewed: vec![CertScope::Proxy],
        proxy_identity_changed: true,
        ..RenewReport::default()
    })
}

/// The republishing apply fails: the old pair (and its metadata) is put
/// back and the running cores restarted, so pinned clients keep working
/// and the next renewal retries; the error says so.
#[test]
fn a_failed_republish_puts_the_previous_pair_back() {
    let _guard = serial();
    let bench = Bench::installed(&trojan());
    let dir = CertDir::proxy(&bench.ctx.paths);
    std::fs::create_dir_all(dir.path()).unwrap();
    std::fs::write(dir.key(), "OLD KEY").unwrap();
    std::fs::write(dir.cert(), "OLD CERT").unwrap();
    // No metadata before: it is removed again.
    bench.live.set_running("onebox-sing-box");
    bench
        .exec
        .on(
            "systemctl",
            &["restart", "onebox-sing-box"],
            crate::sys::exec::Output::success(""),
        )
        .on(
            "systemctl",
            &["is-active", "--quiet", "onebox-sing-box"],
            crate::sys::exec::Output::success(""),
        );
    bench
        .engine
        .fail_applies_with("配置未应用，已恢复原状态: 内核启动失败");
    let err = renew_with(&bench.session(), CertScopes::ALL, true, rotating).unwrap_err();
    assert_eq!(
        err.to_string(),
        format!("{PAIR_RESTORED}: 配置未应用，已恢复原状态: 内核启动失败")
    );
    assert_eq!(std::fs::read_to_string(dir.key()).unwrap(), "OLD KEY");
    assert_eq!(std::fs::read_to_string(dir.cert()).unwrap(), "OLD CERT");
    assert!(!dir.metadata_file().exists());
    assert_eq!(
        bench.engine.calls(),
        [Call::RecoverLocked, Call::ApplyLocked]
    );
    let history = bench.exec.history();
    assert!(
        history
            .iter()
            .any(|c| c == "systemctl restart onebox-sing-box"),
        "{history:?}"
    );
}

/// An engine whose republishing apply fails after it committed (and
/// changed `state.json`) and/or kept its journal, as `apply_locked` can.
struct Failing {
    message: String,
    commits: bool,
    keeps_journal: bool,
}

impl crate::cli::session::Engine for Failing {
    fn apply(&self, ctx: &Ctx, req: crate::apply::ApplyRequest) -> Result<()> {
        self.apply_locked(
            ctx,
            &FileLock::acquire(&ctx.paths.lock(), BUSY_MESSAGE)?,
            req,
        )
    }
    fn apply_locked(
        &self,
        ctx: &Ctx,
        _lock: &FileLock,
        req: crate::apply::ApplyRequest,
    ) -> Result<()> {
        if self.commits {
            let mut cfg = req.config;
            cfg.node_name = "committed".into();
            crate::state::StateStore::save(ctx, &cfg)?;
        }
        if self.keeps_journal {
            std::fs::create_dir_all(journal::dir(&ctx.paths))?;
        }
        Err(Error::msg(self.message.clone()))
    }
    fn recover(&self, _ctx: &Ctx) -> Result<()> {
        Ok(())
    }
    fn recover_locked(&self, _ctx: &Ctx, _lock: &FileLock) -> Result<()> {
        Ok(())
    }
    fn boot(&self, _ctx: &Ctx) -> Result<()> {
        Ok(())
    }
}

/// The previous pair goes back only after a clean rollback: an apply that
/// committed already published the new pins, and a kept journal restores
/// the new pair on recovery (its snapshot was taken after the renewal) —
/// `ROOT/tls` keeps the new pair, nothing is restarted, and the error says
/// what to do.
#[test]
fn a_failed_republish_keeps_the_new_pair_unless_rolled_back() {
    let _guard = serial();
    let committed = format!("{COMMITTED_UNCLEAN}: 重命名失败；请执行 recover 清理");
    let unfinished = "配置失败: 内核启动失败；恢复未完成: 端口被占用；\
                      事务日志保留于 /etc/onebox/.transaction，请执行 recover";
    let rolled_back = "配置未应用，已恢复原状态: 内核启动失败";
    let cases = [
        // (error, commits, keeps journal, expected error, pair restored)
        (
            rolled_back,
            false,
            false,
            format!("{PAIR_RESTORED}: {rolled_back}"),
            true,
        ),
        (committed.as_str(), false, true, committed.clone(), false),
        (committed.as_str(), false, false, committed.clone(), false),
        // A commit seen in state.json, whatever the error says.
        ("注入故障", true, false, "注入故障".to_owned(), false),
        (
            unfinished,
            false,
            true,
            format!("{REPUBLISH_PENDING}: {unfinished}"),
            false,
        ),
    ];
    for (message, commits, keeps_journal, expected, restored) in cases {
        let bench = Bench::installed(&trojan());
        let dir = CertDir::proxy(&bench.ctx.paths);
        std::fs::create_dir_all(dir.path()).unwrap();
        std::fs::write(dir.key(), "OLD KEY").unwrap();
        std::fs::write(dir.cert(), "OLD CERT").unwrap();
        bench.live.set_running("onebox-sing-box");
        bench
            .exec
            .on(
                "systemctl",
                &["restart", "onebox-sing-box"],
                crate::sys::exec::Output::success(""),
            )
            .on(
                "systemctl",
                &["is-active", "--quiet", "onebox-sing-box"],
                crate::sys::exec::Output::success(""),
            );
        let engine = Failing {
            message: message.to_owned(),
            commits,
            keeps_journal,
        };
        let session =
            Session::new(&bench.ctx, &engine, &bench.live, true).with_printer(&bench.printed);
        let err = renew_with(&session, CertScopes::ALL, true, rotating).unwrap_err();
        assert_eq!(err.to_string(), expected, "{message}");
        let key = std::fs::read_to_string(dir.key()).unwrap();
        assert_eq!(
            key,
            if restored { "OLD KEY" } else { "NEW KEY" },
            "{message}"
        );
        let restarted = bench
            .exec
            .history()
            .iter()
            .any(|c| c == "systemctl restart onebox-sing-box");
        assert_eq!(restarted, restored, "{message}");
    }
}

#[test]
fn renewal_needs_root_and_a_free_lock() {
    let _guard = serial();
    let mut bench = Bench::installed(&config(&[(VlessReality, 443, XR)]));
    bench.is_root = false;
    let err = renew_with(&bench.session(), CertScopes::ALL, false, scripted).unwrap_err();
    assert_eq!(err.to_string(), "此操作需要 root 权限");
    bench.is_root = true;
    let _held = FileLock::acquire(&bench.ctx.paths.lock(), BUSY_MESSAGE).unwrap();
    let err = renew_with(&bench.session(), CertScopes::ALL, false, scripted).unwrap_err();
    assert_eq!(err.to_string(), BUSY_MESSAGE);
    assert!(bench.engine.calls().is_empty());
}

/// The scripted report is shared: renewal tests run one at a time.
pub(super) fn serial() -> std::sync::MutexGuard<'static, ()> {
    static SERIAL: Mutex<()> = Mutex::new(());
    SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}
