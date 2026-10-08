//! Self-signed certificates: EC P-256, 3650 days, the exact v2
//! `openssl.cnf` (F §3.6), generated in a private staging directory
//! `<D>/.issue-<16 hex>` that is always removed afterwards.

use super::openssl::Trust;
use super::store::{install_pair, CertDir};
use crate::ctx::Ctx;
use crate::error::Result;
use crate::sys::exec::Cmd;
use crate::sys::fs::{atomic_write, ensure_dir, remove_tree_if_exists};
use std::net::IpAddr;
use std::time::Duration;

pub const VALID_DAYS: u32 = 3650;
const TIMEOUT: Duration = Duration::from_secs(60);

/// The v2 `openssl.cnf`: CN = first name, SAN `DNS:`/`IP:` per name.
pub fn openssl_cnf(names: &[String]) -> String {
    let alt = names
        .iter()
        .map(|n| {
            let kind = if n.parse::<IpAddr>().is_ok() {
                "IP"
            } else {
                "DNS"
            };
            format!("{kind}:{n}")
        })
        .collect::<Vec<_>>()
        .join(",");
    let cn = names.first().map(String::as_str).unwrap_or("");
    format!(
        "[req]\ndistinguished_name=dn\nx509_extensions=extensions\nprompt=no\n[dn]\nCN={cn}\n\
         [extensions]\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n\
         extendedKeyUsage=serverAuth\nsubjectAltName={alt}\n"
    )
}

/// Generate a new pair for `names` and deploy it into `dir` (pinned
/// validation for every name). Returns whether the deployed pair changed.
pub fn generate(ctx: &Ctx, dir: &CertDir, names: &[String]) -> Result<bool> {
    dir.ensure()?;
    let stage = dir
        .path()
        .join(format!(".issue-{}", crate::sys::rand::hex(8)?));
    let result = generate_in(ctx, dir, &stage, names);
    let _ = remove_tree_if_exists(&stage);
    result
}

fn generate_in(
    ctx: &Ctx,
    dir: &CertDir,
    stage: &std::path::Path,
    names: &[String],
) -> Result<bool> {
    ensure_dir(stage, 0o700)?;
    let cnf = stage.join("openssl.cnf");
    atomic_write(&cnf, openssl_cnf(names).as_bytes(), 0o600)?;
    let (cert, key) = (stage.join("cert.pem"), stage.join("key.pem"));
    let path = |p: &std::path::Path| p.to_string_lossy().into_owned();
    let cmd = Cmd::new("openssl")
        .args([
            "req",
            "-x509",
            "-newkey",
            "ec",
            "-pkeyopt",
            "ec_paramgen_curve:prime256v1",
            "-nodes",
            "-days",
            &VALID_DAYS.to_string(),
            "-config",
            &path(&cnf),
            "-keyout",
            &path(&key),
            "-out",
            &path(&cert),
        ])
        .timeout(TIMEOUT);
    ctx.check(&cmd)?;
    install_pair(ctx, dir, &cert, &key, names, Trust::Pinned)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cert::openssl::{publicly_trusted, validate_pair};
    use crate::cert::testing::{have_openssl, Fixture};
    use crate::render::tls::TlsMaterial;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn config_is_byte_identical_to_v2() {
        let names = vec!["www.bing.com".to_owned(), "203.0.113.7".to_owned()];
        assert_eq!(
            openssl_cnf(&names),
            "[req]\ndistinguished_name=dn\nx509_extensions=extensions\nprompt=no\n[dn]\n\
             CN=www.bing.com\n[extensions]\nbasicConstraints=critical,CA:FALSE\n\
             keyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\n\
             subjectAltName=DNS:www.bing.com,IP:203.0.113.7\n"
        );
    }

    #[test]
    fn generates_pinned_pairs_and_removes_the_stage() {
        if !have_openssl() {
            return;
        }
        let f = Fixture::new("cert-self");
        let dir = CertDir::proxy(&f.ctx.paths);
        let names = vec!["www.bing.com".to_owned(), "203.0.113.7".to_owned()];
        assert!(generate(&f.ctx, &dir, &names).unwrap());
        for name in &names {
            validate_pair(&f.ctx, &dir.cert(), &dir.key(), name, Trust::Pinned).unwrap();
        }
        assert!(!publicly_trusted(
            &f.ctx,
            &dir.cert(),
            &dir.key(),
            "www.bing.com"
        ));
        assert!(
            validate_pair(&f.ctx, &dir.cert(), &dir.key(), "other.com", Trust::Pinned).is_err()
        );
        let mode = std::fs::metadata(dir.key()).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        let leftovers: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|n| n.starts_with('.'))
            .collect();
        assert!(leftovers.is_empty(), "{leftovers:?}");
        let first = TlsMaterial::deployed(&f.ctx.paths).unwrap();
        assert!(generate(&f.ctx, &dir, &names).unwrap());
        assert_ne!(
            TlsMaterial::deployed(&f.ctx.paths).unwrap().pin(),
            first.pin()
        );
        let days = crate::cert::store::days_left(&f.ctx, &dir).unwrap();
        assert!((3648..=3650).contains(&days), "{days}");
    }
}
