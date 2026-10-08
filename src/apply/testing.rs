//! Test fixtures shared by the apply leaf modules: a real journal written
//! by the v2.0.1 binary and the layout it was taken from.
//!
//! `fixtures/v2-journal.json` was produced by running `onebox-v2 regen`
//! (ONEBOX_INIT=none, offline fake cores) on the layout [`build_v2_layout`]
//! creates and killing it in phase `prepare-cores`; the layout root was
//! replaced by `@ROOT@`. Its snapshot entries (slots, presence, digests)
//! are therefore exactly what v2 computes for that layout.

use crate::paths::Paths;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

pub const V2_JOURNAL: &str = include_str!("fixtures/v2-journal.json");
pub const V2_STATE: &[u8] = include_bytes!("fixtures/v2-state.json");
const ROOT_PLACEHOLDER: &str = "@ROOT@";

/// The paths the fixture was captured with.
pub fn v2_paths(root: &Path) -> Paths {
    let mut paths = Paths::isolated(root);
    paths.initd = root.join("initd/init.d");
    paths.executable = root.join("usr/onebox");
    paths
}

/// The acme.sh home of the fixture (`ACME_HOME` during the capture).
pub fn acme_home(root: &Path) -> PathBuf {
    root.join("acme-home")
}

/// The fixture's retired acme.sh deployment (snapshotted by v2 as item-38).
pub fn acme_deployment(root: &Path) -> PathBuf {
    acme_home(root).join("example.com_ecc/example.com.conf")
}

/// The v2 journal text with the fixture root replaced by `root`.
pub fn v2_journal_text(root: &Path) -> String {
    V2_JOURNAL.replace(ROOT_PLACEHOLDER, &root.to_string_lossy())
}

pub fn file(path: &Path, mode: u32, content: &[u8]) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, content).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
}

pub fn dir(path: &Path, mode: u32) {
    fs::create_dir_all(path).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
}

/// Recreate the live layout the fixture journal was taken from (same
/// contents and modes; see `capture-v2-journal.sh` in the work notes).
pub fn build_v2_layout(root: &Path) -> Paths {
    let paths = v2_paths(root);
    let etc = &paths.root;
    dir(etc, 0o700);
    file(&paths.state(), 0o600, V2_STATE);
    dir(&etc.join("tls"), 0o700);
    file(&etc.join("tls/cert.pem"), 0o600, b"CERT");
    file(&etc.join("tls/key.pem"), 0o600, b"KEY");
    dir(&etc.join("tls/acme"), 0o700);
    file(&etc.join("tls/acme/acme.sh"), 0o755, b"#!/bin/sh code");
    dir(&etc.join("tls/acme/dnsapi"), 0o755);
    file(&etc.join("tls/acme/dnsapi/dns_cf.sh"), 0o644, b"cf");
    file(&etc.join("tls/acme/account.conf"), 0o600, b"ACCOUNT");
    file(&etc.join("tls/acme/hook.sh"), 0o640, b"hook");
    dir(&etc.join("client"), 0o750);
    file(&etc.join("client/links.txt"), 0o644, b"vless://x");
    file(&etc.join("client/节点.txt"), 0o600, b"unicode");
    file(&etc.join("client/empty"), 0o600, b"");
    dir(&etc.join("client/nested"), 0o711);
    dir(&etc.join("client/nested/deeper"), 0o700);
    file(&etc.join("client/nested/deeper/z"), 0o400, b"zz");
    file(&etc.join("client/nested/A"), 0o644, b"upper");
    file(&etc.join("client/nested/a"), 0o644, b"lower");
    dir(&etc.join("site"), 0o700);
    dir(&etc.join("site/empty"), 0o700);
    file(&etc.join("site/nginx.pid"), 0o600, b"123");
    file(&etc.join("site/error.log"), 0o600, b"err");
    dir(&etc.join("site/content-backups"), 0o700);
    file(&etc.join("site/content-backups/old"), 0o600, b"old");
    file(&etc.join("firewall-v2.json"), 0o600, br#"{"rules":[]}"#);
    file(&etc.join("hop-v2.json"), 0o600, b"[]");
    dir(&etc.join("backups"), 0o700);
    file(&etc.join("backups/keep"), 0o600, b"backup");
    dir(&paths.site_root, 0o755);
    file(&paths.site_root.join("index.html"), 0o644, b"<h1>site</h1>");
    file(
        &paths.site_root.join(".onebox-site-owned"),
        0o600,
        b"onebox",
    );
    dir(&paths.systemd, 0o755);
    file(&paths.systemd.join("onebox-net.service"), 0o644, b"[Unit]");
    dir(&paths.initd, 0o755);
    let local = root.join("initd/local.d");
    dir(&local, 0o755);
    file(&local.join("onebox-hop.start"), 0o755, b"#!/bin/sh");
    file(&local.join("admin.start"), 0o755, b"#!/bin/sh admin");
    let deployment = format!(
        "# onebox-rust-retired-deployment={}\nLe_Domain='example.com'\nLe_RealFullChainPath=''\nLe_RealKeyPath=''\n",
        etc.join("tls").display()
    );
    dir(&acme_home(root).join("example.com_ecc"), 0o700);
    file(&acme_deployment(root), 0o600, deployment.as_bytes());
    dir(&acme_home(root).join("other.org_ecc"), 0o700);
    file(
        &acme_home(root).join("other.org_ecc/other.org.conf"),
        0o600,
        b"Le_RealFullChainPath='/etc/x.pem'",
    );
    paths
}
