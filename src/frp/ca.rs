//! The private CA and the control-channel certificate (spec H §4.3).
//!
//! frpc authenticates frps with a CA Onebox creates once (EC P-256, 3650
//! days, `CN=Onebox FRP private CA`) and pins in every exported bundle; the
//! server certificate (397 days, `DNS:{control domain}`) is reissued when it
//! expires within 30 days, no longer verifies for the control domain, or
//! does not match its key. The CA itself survives domain changes and is
//! never regenerated while one of its two files exists; `frps rotate-ca`
//! replaces it explicitly ([`discard`]).
//!
//! Changes from v2: keys and certificates are generated in a private
//! staging directory and renamed into place with mode 0600 (v2 created
//! them with the process umask and chmodded afterwards); the CSR and the
//! serial file stay in the staging directory, which is always removed (v2
//! left `server.csr` and `ca.srl` behind); a CA that is about to expire
//! can be rotated with `frps rotate-ca` (v2 had no way out, H-8.1#10).

use crate::ctx::Ctx;
use crate::error::{Error, Result};
use crate::sys::exec::Cmd;
use crate::sys::fs::{atomic_write, ensure_dir, remove_tree_if_exists};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

const TIMEOUT: Duration = Duration::from_secs(60);
/// Renewal window of the CA check and the server certificate (30 days).
const WINDOW_SECS: &str = "2592000";
const STAGE_PREFIX: &str = ".issue-";

/// A CA that cannot stay in use (v2 text plus the command that rotates it).
pub const CA_INVALID: &str =
    "FRP CA 无效或即将过期；需人工轮换并更新所有客户端（onebox frps rotate-ca）";

/// The v2 `ca.cnf`.
pub const CA_CNF: &str = "[req]\ndistinguished_name=dn\nx509_extensions=ca\nprompt=no\n[dn]\n\
CN=Onebox FRP private CA\n[ca]\nbasicConstraints=critical,CA:TRUE,pathlen:0\n\
keyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\n";

/// The v2 `server.cnf` for the control domain.
pub fn server_cnf(domain: &str) -> String {
    format!(
        "[req]\ndistinguished_name=dn\nprompt=no\n[dn]\nCN={domain}\n[server]\n\
         subjectAltName=DNS:{domain}\nbasicConstraints=critical,CA:FALSE\n\
         keyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\n"
    )
}

/// The control-channel files under `FRP_ROOT`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ControlFiles {
    pub root: PathBuf,
}

impl ControlFiles {
    pub fn new(root: &Path) -> ControlFiles {
        ControlFiles {
            root: root.to_path_buf(),
        }
    }
    pub fn ca(&self) -> PathBuf {
        self.root.join("ca.pem")
    }
    pub fn ca_key(&self) -> PathBuf {
        self.root.join("ca-key.pem")
    }
    pub fn cert(&self) -> PathBuf {
        self.root.join("server-cert.pem")
    }
    pub fn key(&self) -> PathBuf {
        self.root.join("server-key.pem")
    }
}

fn arg(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

fn openssl(args: &[&str]) -> Cmd {
    Cmd::new("openssl")
        .args(args.iter().copied())
        .timeout(TIMEOUT)
}

fn succeeds(ctx: &Ctx, args: &[&str]) -> bool {
    ctx.run(&openssl(args)).is_ok_and(|o| o.ok())
}

/// The certificate's public key equals the key's (both non-empty).
fn key_matches(ctx: &Ctx, cert: &Path, key: &Path) -> bool {
    let cert_key = ctx
        .check(&openssl(&["x509", "-in", &arg(cert), "-pubkey", "-noout"]))
        .ok();
    let key_pub = crate::cert::openssl::key_pubkey(ctx, key).ok();
    match (cert_key, key_pub) {
        (Some(a), Some(b)) => !a.trim().is_empty() && a.trim() == b.trim(),
        _ => false,
    }
}

/// Whether `cert` is valid for 30 more days and verifies for `domain`
/// against `ca`.
fn verifies(ctx: &Ctx, ca: &Path, cert: &Path, domain: &str) -> bool {
    succeeds(
        ctx,
        &[
            "x509",
            "-in",
            &arg(cert),
            "-checkend",
            WINDOW_SECS,
            "-noout",
        ],
    ) && succeeds(
        ctx,
        &[
            "verify",
            "-CAfile",
            &arg(ca),
            "-verify_hostname",
            domain,
            &arg(cert),
        ],
    )
}

/// Make sure the CA exists and is healthy and the server certificate is
/// valid for `domain`; returns whether the server certificate changed.
pub fn control_cert(ctx: &Ctx, frp_root: &Path, domain: &str) -> Result<bool> {
    let files = ControlFiles::new(frp_root);
    let (ca, ca_key) = (files.ca(), files.ca_key());
    ensure!(
        ca.exists() == ca_key.exists(),
        "FRP 私有 CA 文件不完整，保留旧部署等待修复"
    );
    if !ca.exists() {
        in_stage(frp_root, |stage| create_ca(ctx, &files, stage))?;
    }
    let ca_ok = succeeds(
        ctx,
        &["x509", "-in", &arg(&ca), "-checkend", WINDOW_SECS, "-noout"],
    ) && key_matches(ctx, &ca, &ca_key);
    ensure!(ca_ok, "{CA_INVALID}");
    if verifies(ctx, &ca, &files.cert(), domain) && key_matches(ctx, &files.cert(), &files.key()) {
        return Ok(false);
    }
    in_stage(frp_root, |stage| issue_server(ctx, &files, stage, domain))?;
    Ok(true)
}

/// Run `work` with a private staging directory below `root`, removed
/// afterwards whatever happens.
fn in_stage(root: &Path, work: impl FnOnce(&Path) -> Result<()>) -> Result<()> {
    // Leftovers of an interrupted run (the caller holds the FRP lock).
    crate::sys::fs::sweep_stale(root, STAGE_PREFIX, Duration::ZERO)?;
    let stage = root.join(format!("{STAGE_PREFIX}{}", crate::sys::rand::hex(8)?));
    ensure_dir(&stage, 0o700)?;
    let result = work(&stage);
    let cleanup = remove_tree_if_exists(&stage);
    result?;
    cleanup.map(drop)
}

/// Move a generated file into place with mode 0600.
fn install(staged: &Path, target: &Path) -> Result<()> {
    fs::set_permissions(staged, fs::Permissions::from_mode(0o600))
        .map_err(|e| Error::io(staged, e))?;
    fs::rename(staged, target).map_err(|e| Error::io(target, e))
}

fn create_ca(ctx: &Ctx, files: &ControlFiles, stage: &Path) -> Result<()> {
    let conf = files.root.join("ca.cnf");
    atomic_write(&conf, CA_CNF.as_bytes(), 0o600)?;
    let (key, cert) = (stage.join("ca-key.pem"), stage.join("ca.pem"));
    ctx.check(&openssl(&[
        "ecparam",
        "-genkey",
        "-name",
        "prime256v1",
        "-out",
        &arg(&key),
    ]))?;
    ctx.check(&openssl(&[
        "req",
        "-new",
        "-x509",
        "-sha256",
        "-days",
        "3650",
        "-key",
        &arg(&key),
        "-config",
        &arg(&conf),
        "-out",
        &arg(&cert),
    ]))?;
    install(&key, &files.ca_key())?;
    install(&cert, &files.ca())
}

fn issue_server(ctx: &Ctx, files: &ControlFiles, stage: &Path, domain: &str) -> Result<()> {
    let conf = files.root.join("server.cnf");
    atomic_write(&conf, server_cnf(domain).as_bytes(), 0o600)?;
    let key = stage.join("server-key.pem");
    let csr = stage.join("server.csr");
    let cert = stage.join("server-cert.pem");
    ctx.check(&openssl(&[
        "ecparam",
        "-genkey",
        "-name",
        "prime256v1",
        "-out",
        &arg(&key),
    ]))?;
    ctx.check(&openssl(&[
        "req",
        "-new",
        "-sha256",
        "-key",
        &arg(&key),
        "-config",
        &arg(&conf),
        "-out",
        &arg(&csr),
    ]))?;
    ctx.check(&openssl(&[
        "x509",
        "-req",
        "-in",
        &arg(&csr),
        "-CA",
        &arg(&files.ca()),
        "-CAkey",
        &arg(&files.ca_key()),
        "-CAserial",
        &arg(&stage.join("ca.srl")),
        "-CAcreateserial",
        "-days",
        "397",
        "-sha256",
        "-extfile",
        &arg(&conf),
        "-extensions",
        "server",
        "-out",
        &arg(&cert),
    ]))?;
    ctx.check(&openssl(&[
        "verify",
        "-CAfile",
        &arg(&files.ca()),
        "-verify_hostname",
        domain,
        &arg(&cert),
    ]))?;
    install(&key, &files.key())?;
    install(&cert, &files.cert())
}

/// Delete the CA and the control certificate so the next
/// [`control_cert`] creates new ones (`frps rotate-ca`; every exported
/// client must be exported again). Runs inside an FRP transaction.
pub fn discard(frp_root: &Path) -> Result<()> {
    let files = ControlFiles::new(frp_root);
    for path in [files.cert(), files.key(), files.ca(), files.ca_key()] {
        crate::sys::fs::remove_file_if_exists(&path)?;
    }
    Ok(())
}

/// Seconds until `cert` expires is below `secs` (or it cannot be read).
pub fn expires_within(ctx: &Ctx, cert: &Path, secs: u64) -> bool {
    !succeeds(
        ctx,
        &[
            "x509",
            "-in",
            &arg(cert),
            "-checkend",
            &secs.to_string(),
            "-noout",
        ],
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cert::testing::have_openssl;
    use crate::sys::exec::SystemExec;
    use crate::sys::fs::TempDir;
    use std::sync::Arc;

    fn real_ctx(root: &Path) -> Ctx {
        let (mut ctx, _, _) = Ctx::test(root);
        ctx.exec = Arc::new(SystemExec);
        ctx
    }

    fn openssl_ok(ctx: &Ctx, args: &[&str]) {
        ctx.check(&openssl(args)).unwrap();
    }

    #[test]
    fn configs_are_v2_text() {
        assert_eq!(
            CA_CNF,
            "[req]\ndistinguished_name=dn\nx509_extensions=ca\nprompt=no\n[dn]\nCN=Onebox FRP private CA\n[ca]\nbasicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\n"
        );
        assert_eq!(
            server_cnf("frp.example.com"),
            "[req]\ndistinguished_name=dn\nprompt=no\n[dn]\nCN=frp.example.com\n[server]\nsubjectAltName=DNS:frp.example.com\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\n"
        );
    }

    #[test]
    fn private_ca_persists_when_control_domain_changes() {
        if !have_openssl() {
            return;
        }
        let dir = TempDir::new("frp-ca").unwrap();
        let ctx = real_ctx(dir.path());
        let root = &ctx.paths.frp_root;
        ensure_dir(root, 0o700).unwrap();
        assert!(control_cert(&ctx, root, "frp.example.com").unwrap());
        let files = ControlFiles::new(root);
        let ca = fs::read(files.ca()).unwrap();
        for path in [files.ca(), files.ca_key(), files.cert(), files.key()] {
            let mode = fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600, "{}", path.display());
        }
        assert!(!control_cert(&ctx, root, "frp.example.com").unwrap());
        assert!(control_cert(&ctx, root, "control.example.org").unwrap());
        assert_eq!(fs::read(files.ca()).unwrap(), ca);
        openssl_ok(
            &ctx,
            &[
                "verify",
                "-CAfile",
                &arg(&files.ca()),
                "-verify_hostname",
                "control.example.org",
                &arg(&files.cert()),
            ],
        );
        // Nothing but the four PEMs and the two configurations is left.
        let mut names: Vec<String> = fs::read_dir(root)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        assert_eq!(
            names,
            [
                "ca-key.pem",
                "ca.cnf",
                "ca.pem",
                "server-cert.pem",
                "server-key.pem",
                "server.cnf"
            ]
        );
        assert!(!expires_within(&ctx, &files.cert(), 86400));
        assert!(expires_within(&ctx, &root.join("missing.pem"), 1));
    }

    #[test]
    fn a_mismatched_server_key_is_replaced() {
        if !have_openssl() {
            return;
        }
        let dir = TempDir::new("frp-ca-key").unwrap();
        let ctx = real_ctx(dir.path());
        let root = &ctx.paths.frp_root;
        ensure_dir(root, 0o700).unwrap();
        control_cert(&ctx, root, "frp.example.com").unwrap();
        let files = ControlFiles::new(root);
        fs::copy(files.ca_key(), files.key()).unwrap();
        assert!(control_cert(&ctx, root, "frp.example.com").unwrap());
        assert!(key_matches(&ctx, &files.cert(), &files.key()));
    }

    #[test]
    fn incomplete_or_expiring_cas_are_refused() {
        let dir = TempDir::new("frp-ca-bad").unwrap();
        let (ctx, exec, _) = Ctx::test(dir.path());
        let root = &ctx.paths.frp_root;
        ensure_dir(root, 0o700).unwrap();
        fs::write(root.join("ca.pem"), "x").unwrap();
        let err = control_cert(&ctx, root, "frp.example.com").unwrap_err();
        assert_eq!(
            err.to_string(),
            "FRP 私有 CA 文件不完整，保留旧部署等待修复"
        );
        assert!(exec.history().is_empty(), "nothing ran");
        fs::write(root.join("ca-key.pem"), "y").unwrap();
        // The fake openssl fails every check: the CA counts as invalid.
        let err = control_cert(&ctx, root, "frp.example.com").unwrap_err();
        assert_eq!(err.to_string(), CA_INVALID);
        assert_eq!(fs::read_to_string(root.join("ca.pem")).unwrap(), "x");
    }

    #[test]
    fn a_ca_expiring_within_30_days_is_refused() {
        if !have_openssl() {
            return;
        }
        let dir = TempDir::new("frp-ca-old").unwrap();
        let ctx = real_ctx(dir.path());
        let root = &ctx.paths.frp_root;
        ensure_dir(root, 0o700).unwrap();
        let files = ControlFiles::new(root);
        let conf = root.join("ca.cnf");
        fs::write(&conf, CA_CNF).unwrap();
        openssl_ok(
            &ctx,
            &[
                "ecparam",
                "-genkey",
                "-name",
                "prime256v1",
                "-out",
                &arg(&files.ca_key()),
            ],
        );
        openssl_ok(
            &ctx,
            &[
                "req",
                "-new",
                "-x509",
                "-sha256",
                "-days",
                "10",
                "-key",
                &arg(&files.ca_key()),
                "-config",
                &arg(&conf),
                "-out",
                &arg(&files.ca()),
            ],
        );
        let err = control_cert(&ctx, root, "frp.example.com").unwrap_err();
        assert!(err.to_string().starts_with("FRP CA 无效或即将过期"));
        assert!(!files.cert().exists());
    }
}
