use super::*;
use crate::cert::testing::{have_openssl, Fixture};
use crate::cert::CertDir;
use crate::domain::config::WebCert;
use crate::subscription::testing::{ip, reality, standalone, systemd, Node};
use crate::sys::lock::BUSY_MESSAGE;

#[test]
fn manual_renewals_force_and_scheduled_ones_do_not() {
    let manual = options(false);
    assert_eq!(manual.targets, CertScopes::only(CertScope::Subscription));
    assert!(manual.force && !manual.scheduled);
    let cron = options(true);
    assert!(cron.scheduled && !cron.force);
}

#[test]
fn off_and_ip_mode_renew_nothing() {
    let node = Node::new("sub-renew-ip");
    let lock = node.lock();
    renew(&node.ctx, &lock, &reality(), false, None).unwrap();
    renew(&node.ctx, &lock, &ip(8448), true, None).unwrap();
    assert!(node.fake.history().is_empty(), "no certificate work at all");
    assert!(!CertDir::subscription(&node.ctx.paths).path().exists());
}

#[test]
fn standalone_renewal_reports_failures_as_errors() {
    if !have_openssl() {
        return;
    }
    let f = Fixture::new("sub-renew-custom");
    let state = systemd(&f.fake, &f.ctx.paths, 1);
    let lock = FileLock::acquire(&f.ctx.paths.lock(), BUSY_MESSAGE).unwrap();
    let (chain, key) =
        f.ca.leaf(&f.dir.join("src"), &["sub.example.com"], 90, false);
    let cfg = standalone(
        WebCert::Custom {
            cert: chain.clone(),
            key: key.clone(),
        },
        8448,
    );
    renew(&f.ctx, &lock, &cfg, false, None).unwrap();
    assert!(CertDir::subscription(&f.ctx.paths).has_pair());
    assert!(
        state.actions().is_empty(),
        "nginx not running: nothing restarted"
    );

    std::fs::remove_file(&chain).unwrap();
    std::fs::remove_dir_all(CertDir::subscription(&f.ctx.paths).path()).unwrap();
    let err = renew(&f.ctx, &lock, &cfg, false, None)
        .unwrap_err()
        .to_string();
    assert!(err.starts_with("订阅证书续期失败: "), "{err}");
}
