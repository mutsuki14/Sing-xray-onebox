//! The lifecycle without systemd: OpenRC, and no init system at all (the
//! built-in supervisor, `boot:` crontab lines and the FRP lock handed to
//! the `frps net-apply` pre-start hook, G25).

use super::{change, install_tcp};
use crate::cert::cloudflare::CfCredentials;
use crate::cert::testing::{fake_acme, AcmeScript};
use crate::frp::journal;
use crate::frp::lifecycle::{apply, net_apply, renew, service, uninstall, Change, ServiceAction};
use crate::frp::model::{self, WebTls};
use crate::frp::testing::{tcp_state, web_state, FakeHost};
use crate::host::init::InitSystem;
use crate::host::service::{script_file, unit_file, FRPS, FRP_WEB};

/// The `frps net-apply` hook runs Onebox ran itself: `true` for each run
/// that inherited the FRP lock.
fn hooks(h: &FakeHost) -> Vec<bool> {
    let exe = h.ctx.paths.executable.to_string_lossy().into_owned();
    h.exec
        .calls()
        .iter()
        .filter(|c| c.program == exe && c.args == ["frps", "net-apply"])
        .map(|c| c.inherit_lock_fd.is_some())
        .collect()
}

fn frps_spawns(h: &FakeHost) -> usize {
    h.exec
        .spawned()
        .iter()
        .filter(|(c, _)| c.program.ends_with("/frps"))
        .count()
}

#[test]
fn without_an_init_system_frps_is_supervised_and_starts_from_crontab() {
    let h = FakeHost::with_init(InitSystem::None);
    h.set_crontab(
        "MAILTO=root\n\
         @reboot env ONEBOX_DIR='/etc/onebox' '/usr/local/bin/onebox' frps start >>'/var/log/onebox-frp/boot.log' 2>&1 # onebox-frps-boot\n\
         0 1 * * * /usr/bin/true\n",
    );
    install_tcp(&h);
    let paths = &h.ctx.paths;
    assert!(h.running(FRPS));
    assert_eq!(frps_spawns(&h), 1);
    // The pre-start hook ran with the held FRP lock handed over (it would
    // find the lock busy otherwise) and the service environment.
    assert_eq!(hooks(&h), [true]);
    let exe = paths.executable.to_string_lossy().into_owned();
    let hook = h
        .exec
        .calls()
        .into_iter()
        .find(|c| c.program == exe)
        .unwrap();
    assert!(hook.clear_env);
    // G25: v2's `frps start` boot line is replaced by the service line.
    let tab = h.crontab();
    let lines: Vec<&str> = tab.lines().collect();
    assert_eq!(lines.len(), 4, "{tab}");
    assert_eq!(lines[0], "MAILTO=root");
    assert_eq!(lines[1], "0 1 * * * /usr/bin/true");
    assert!(!tab.contains("onebox-frps-boot") && !tab.contains("# onebox:frp-boot"));
    assert!(tab.contains("frps renew --cron"), "{tab}");
    let boot = lines
        .iter()
        .find(|l| l.ends_with("# onebox:boot:onebox-frps"))
        .unwrap();
    assert!(boot.starts_with("@reboot PATH="), "{boot}");
    assert!(boot.contains(" service onebox-frps start >>"), "{boot}");
    assert!(h.enabled(FRPS));
    // No unit files: Onebox runs the service itself.
    assert!(!unit_file(paths, FRPS).exists() && !script_file(paths, FRPS).exists());
    assert!(paths.frp_root.join("services/onebox-frps.json").is_file());
}

#[test]
fn without_an_init_system_a_rollback_restores_the_boot_lines_from_crontab() {
    let h = FakeHost::with_init(InitSystem::None);
    let before = install_tcp(&h);
    // A foreign line after Onebox's: positions must survive the rollback.
    h.set_crontab(&format!("{}0 2 * * * /usr/bin/foreign\n", h.crontab()));
    let tab = h.crontab();
    let spawned = frps_spawns(&h);
    h.set_healthy(false);
    let mut next = before.clone();
    next.bind_port = 7002;
    let err = apply(&h.runtime(), next, change("配置")).unwrap_err();
    assert!(
        err.to_string().ends_with(crate::frp::txn::ROLLED_BACK),
        "{err}"
    );
    let paths = &h.ctx.paths;
    assert_eq!(model::load(paths).unwrap().unwrap(), before);
    // The crontab is exactly what it was (the disable during the rollback
    // removed the boot line; the crontab restore brought it back).
    assert_eq!(h.crontab(), tab);
    assert!(h.enabled(FRPS));
    // The old frps runs again, started with the lock handed over: the
    // failed start and the restart, three hook runs in all.
    assert!(h.running(FRPS));
    assert_eq!(frps_spawns(&h), spawned + 2);
    assert_eq!(hooks(&h), [true, true, true]);
    assert!(!journal::exists(paths));
    // Service control and uninstall work the same way.
    h.set_healthy(true);
    let rt = h.runtime();
    let lock = rt.lock().unwrap();
    service(&rt, &lock, ServiceAction::Stop).unwrap();
    assert!(!h.running(FRPS) && h.enabled(FRPS));
    service(&rt, &lock, ServiceAction::Start).unwrap();
    assert!(h.running(FRPS));
    uninstall(&rt, &lock).unwrap();
    assert!(!h.running(FRPS));
    assert!(!h.crontab().contains("onebox"), "{}", h.crontab());
}

#[test]
fn openrc_installs_scripts_and_the_default_runlevel() {
    let h = FakeHost::with_init(InitSystem::Openrc);
    let before = install_tcp(&h);
    let paths = &h.ctx.paths;
    assert!(script_file(paths, FRPS).is_file());
    assert!(!unit_file(paths, FRPS).exists());
    assert!(h.running(FRPS) && h.enabled(FRPS));
    assert!(h
        .history()
        .contains(&"rc-update add onebox-frps default".to_owned()));
    // OpenRC enables the service: no boot line, and the hook is the
    // init system's to run (it finds the lock busy and proceeds).
    let tab = h.crontab();
    assert!(!tab.contains("# onebox:boot:"), "{tab}");
    assert!(hooks(&h).is_empty());
    // A failed change is rolled back and re-enabled through rc-update.
    h.break_unit(FRPS, true);
    let mut next = before.clone();
    next.bind_port = 7002;
    apply(&h.runtime(), next, change("配置")).unwrap_err();
    h.break_unit(FRPS, false);
    assert_eq!(model::load(paths).unwrap().unwrap(), before);
    assert!(h.enabled(FRPS));
    assert!(!journal::exists(paths));
    net_apply(&h.ctx).unwrap();
}

#[test]
fn without_an_init_system_web_mode_has_a_boot_line_per_service() {
    let Some(h) = FakeHost::real_openssl(InitSystem::None) else {
        return;
    };
    let pair = h.public_pair("issued", &["app.example.com"]);
    fake_acme(
        &h.exec,
        AcmeScript {
            issue: Some(pair),
            ..AcmeScript::default()
        },
    );
    let mut state = web_state(WebTls::Cloudflare);
    state.token.clear();
    let install = Change {
        cloudflare: Some(CfCredentials::token("fake-token-0123", None).unwrap()),
        ..change("安装")
    };
    apply(&h.runtime(), state, install).unwrap();
    assert!(h.running(FRPS) && h.running(FRP_WEB));
    assert!(h.enabled(FRPS) && h.enabled(FRP_WEB));
    // Back to tcp: the web service and its boot line go.
    let installed = model::load(&h.ctx.paths).unwrap().unwrap();
    let mut tcp = installed.clone();
    tcp.mode = tcp_state().mode;
    apply(&h.runtime(), tcp, change("配置")).unwrap();
    assert!(h.running(FRPS) && !h.running(FRP_WEB));
    assert!(h.enabled(FRPS) && !h.enabled(FRP_WEB));
    assert!(
        !h.crontab().contains("boot:onebox-frp-web"),
        "{}",
        h.crontab()
    );
}

/// v2's FRP boot line (any init system).
const V2_BOOT: &str = "@reboot env ONEBOX_DIR='/etc/onebox' '/usr/local/bin/onebox' frps start >>'/var/log/onebox-frp/boot.log' 2>&1 # onebox-frps-boot\n";

#[test]
fn without_an_init_system_renew_keeps_the_autostart_choice() {
    // (autostart before the renewal, v2 boot line present, autostart after)
    let cases = [
        ("enabled stays enabled", true, false, true),
        ("disabled stays disabled", false, false, false),
        ("v2's frps start line is converted", false, true, true),
    ];
    for (name, enabled, v2_line, want) in cases {
        let h = FakeHost::with_init(InitSystem::None);
        install_tcp(&h);
        let rt = h.runtime();
        if !enabled {
            // `onebox service onebox-frps disable`
            rt.services().disable(FRPS).unwrap();
            assert!(!h.enabled(FRPS), "{name}");
        }
        if v2_line {
            h.set_crontab(&format!("{}{V2_BOOT}", h.crontab()));
        }
        renew(&rt, &rt.lock().unwrap(), true).unwrap();
        assert_eq!(h.enabled(FRPS), want, "{name}: {}", h.crontab());
        assert!(!h.crontab().contains("onebox-frps-boot"), "{name}");
    }
}
