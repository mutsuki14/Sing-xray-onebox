//! Certificate material for client exports: the `CERTIFICATE` blocks of the
//! deployed proxy certificate and the proxy pin.
//!
//! Only certificates are ever extracted: a private key concatenated into
//! `cert.pem` (a common mistake) is skipped and can never reach a client.
//! Every block is re-encoded canonically (base64 wrapped at 64 columns) so
//! exports are byte-stable whatever line endings the source used.
//!
//! Changes from v2:
//! - the file is read once per render and the material shared by every
//!   protocol and format (v2 re-read it for every protocol, so a renewal
//!   racing a render could mix pins in one export, C-8.1 #13);
//! - malformed base64 gets a Chinese message instead of the raw decoder text.
//!
//! Kept from v2 (C-8.1 #14): the pin is the SHA-256 of the *first*
//! certificate's DER, and [`TlsMaterial::pin`] is its only definition.
//! Contract with the certificate stage and renewal (ARCH §5 cert, G9):
//! - `ROOT/tls/cert.pem` is deployed with the key-matching leaf as its first
//!   block, written as [`TlsMaterial::with_leaf_first`] +
//!   [`TlsMaterial::to_pem`] (TLS servers need this order anyway: they send
//!   the file's first certificate as their own);
//! - the proxy certificate identity is computed only as
//!   `TlsMaterial::deployed(paths)?.pin()`, never by other code, so the
//!   identity renewal compares is the one clients pin.

use super::spec::CERT_FILE;
use crate::error::{Error, Result};
use crate::paths::Paths;
use crate::sys::fs::{read_to_string_bounded, sha256_hex};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use std::path::Path;

const BEGIN: &str = "-----BEGIN CERTIFICATE-----";
const END: &str = "-----END CERTIFICATE-----";
/// Width of the base64 lines in re-encoded PEM blocks (RFC 7468).
const PEM_LINE: usize = 64;
/// Certificate files are small; anything larger is not a certificate chain.
const MAX_PEM_BYTES: u64 = 1024 * 1024;
/// DER encodings of X.509 certificates start with a SEQUENCE tag.
const DER_SEQUENCE: u8 = 0x30;

/// Parsed certificate chain. Invariant: at least one certificate, and
/// `digests[i]` is the SHA-256 of the DER of `pems[i]`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TlsMaterial {
    pems: Vec<String>,
    digests: Vec<String>,
}

impl TlsMaterial {
    /// Parse every `CERTIFICATE` block of a PEM file, in file order; other
    /// blocks and text are ignored.
    pub fn from_pem(text: &str) -> Result<TlsMaterial> {
        let mut pems = Vec::new();
        let mut digests = Vec::new();
        let mut rest = text;
        while let Some(start) = rest.find(BEGIN) {
            let body = &rest[start + BEGIN.len()..];
            let finish = body
                .find(END)
                .ok_or_else(|| Error::msg("TLS 证书 PEM 缺少结束标记"))?;
            let encoded: String = body[..finish]
                .chars()
                .filter(|c| !c.is_ascii_whitespace())
                .collect();
            digests.push(sha256_hex(&decode_der(&encoded)?));
            pems.push(canonical_pem(&encoded));
            rest = &body[finish + END.len()..];
        }
        ensure!(
            !pems.is_empty(),
            "TLS 证书文件未包含 CERTIFICATE，拒绝导出未验证配置"
        );
        Ok(TlsMaterial { pems, digests })
    }

    /// Read and parse a certificate file (regular file, no symlink).
    pub fn load(path: &Path) -> Result<TlsMaterial> {
        Self::from_pem(&read_to_string_bounded(path, MAX_PEM_BYTES)?)
    }

    /// The deployed proxy certificate, `ROOT/tls/cert.pem`.
    pub fn deployed(paths: &Paths) -> Result<TlsMaterial> {
        Self::load(&paths.tls().join(CERT_FILE))
    }

    /// Every certificate block, canonical PEM, each ending in `"\n"`.
    pub fn pems(&self) -> &[String] {
        &self.pems
    }

    /// The proxy pin: lowercase hex SHA-256 of the first certificate's DER.
    /// The single definition of the proxy certificate identity: clients pin
    /// it (Xray `pinnedPeerCertSha256`, mihomo `fingerprint`, link
    /// `pcs` / `pinSHA256` / `hpkp`) and renewal compares it. It is the
    /// leaf's because deployment puts the leaf first (module docs).
    pub fn pin(&self) -> &str {
        &self.digests[0]
    }

    /// The same chain with block `index` (the key-matching leaf, found by
    /// the certificate stage) moved to the front; the other blocks keep
    /// their order.
    pub fn with_leaf_first(mut self, index: usize) -> Result<TlsMaterial> {
        ensure!(
            index < self.pems.len(),
            "证书链只有 {} 个证书，没有第 {} 个",
            self.pems.len(),
            index + 1
        );
        self.pems[..=index].rotate_right(1);
        self.digests[..=index].rotate_right(1);
        Ok(self)
    }

    /// The chain as one PEM file (canonical blocks, file order): what the
    /// certificate stage writes to `ROOT/tls/cert.pem`.
    pub fn to_pem(&self) -> String {
        self.pems.concat()
    }
}

fn decode_der(encoded: &str) -> Result<Vec<u8>> {
    let der = STANDARD
        .decode(encoded)
        .map_err(|_| Error::msg("TLS 证书 PEM 内容不是有效的 Base64"))?;
    if der.first() != Some(&DER_SEQUENCE) {
        return Err(Error::msg("TLS 证书不是有效 DER 序列"));
    }
    Ok(der)
}

/// `BEGIN` line, base64 wrapped at 64 columns, `END` line, final newline.
/// `encoded` is validated base64, hence ASCII, so char chunks are byte chunks.
fn canonical_pem(encoded: &str) -> String {
    let chars: Vec<char> = encoded.chars().collect();
    let lines: Vec<String> = chars
        .chunks(PEM_LINE)
        .map(|line| line.iter().collect())
        .collect();
    format!("{BEGIN}\n{}\n{END}\n", lines.join("\n"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// DER `30 03 02 01 01` (a SEQUENCE holding INTEGER 1), as in v2's tests.
    const TINY: &str = "MAMCAQE=";

    fn block(body: &str) -> String {
        format!("{BEGIN}\n{body}\n{END}\n")
    }

    #[test]
    fn pin_is_sha256_of_first_der_and_private_keys_are_skipped() {
        let key = "-----BEGIN PRIVATE KEY-----\nSECRET\n-----END PRIVATE KEY-----\n";
        let second = "MAYCAQICAQM="; // 30 06 02 01 02 02 01 03
        let text = format!("junk\n{}{key}{}", block(TINY), block(second));
        let m = TlsMaterial::from_pem(&text).unwrap();
        assert_eq!(m.pems().len(), 2);
        assert_eq!(m.pems()[0], block(TINY));
        assert!(m.pems().iter().all(|p| !p.contains("SECRET")));
        assert_eq!(m.pin(), sha256_hex(&[0x30, 0x03, 0x02, 0x01, 0x01]));
        assert_eq!(m.to_pem(), format!("{}{}", block(TINY), block(second)));
    }

    #[test]
    fn a_reordered_chain_deploys_with_the_pin_of_its_leaf() {
        let deployed = crate::render::fixtures::material("chain");
        let [leaf, ca] = deployed.pems() else {
            panic!("the test chain is leaf + CA");
        };
        // A custom chain given CA first pins the CA until the leaf moves up.
        let given = TlsMaterial::from_pem(&format!("{ca}{leaf}")).unwrap();
        assert_ne!(given.pin(), deployed.pin());
        let fixed = given.with_leaf_first(1).unwrap();
        assert_eq!(fixed.pin(), deployed.pin());
        assert_eq!(fixed.to_pem(), format!("{leaf}{ca}"));
        assert_eq!(TlsMaterial::from_pem(&fixed.to_pem()).unwrap(), fixed);
        // Moving the first block is a no-op; a missing block is an error.
        assert_eq!(fixed.clone().with_leaf_first(0).unwrap(), fixed);
        let err = fixed.with_leaf_first(2).unwrap_err().to_string();
        assert_eq!(err, "证书链只有 2 个证书，没有第 3 个");
    }

    #[test]
    fn rotation_keeps_the_order_of_the_other_blocks() {
        let blocks: Vec<String> = ["MAMCAQE=", "MAMCAQI=", "MAMCAQM="]
            .iter()
            .map(|b| block(b))
            .collect();
        let m = TlsMaterial::from_pem(&blocks.concat()).unwrap();
        let third_pin = sha256_hex(&[0x30, 0x03, 0x02, 0x01, 0x03]);
        let moved = m.with_leaf_first(2).unwrap();
        let expected = [&blocks[2], &blocks[0], &blocks[1]];
        assert!(moved.pems().iter().eq(expected));
        assert_eq!(moved.pin(), third_pin);
    }

    #[test]
    fn reencodes_with_64_column_lines() {
        let der: Vec<u8> = std::iter::once(0x30).chain(1..=99).collect();
        let encoded = STANDARD.encode(&der);
        let messy = encoded
            .as_bytes()
            .chunks(10)
            .map(|c| String::from_utf8_lossy(c).into_owned())
            .collect::<Vec<_>>()
            .join("\r\n  ");
        let m = TlsMaterial::from_pem(&block(&messy)).unwrap();
        let lines: Vec<&str> = m.pems()[0].lines().collect();
        assert_eq!(lines[0], BEGIN);
        assert_eq!(lines[1].len(), 64);
        assert_eq!(lines[1..lines.len() - 1].concat(), encoded);
        assert_eq!(*lines.last().unwrap(), END);
        assert!(m.pems()[0].ends_with("-----\n"));
    }

    #[test]
    fn rejects_invalid_material_with_v2_messages() {
        let cases = [
            ("no certificate here", "TLS 证书文件未包含 CERTIFICATE"),
            (&format!("{BEGIN}\n{TINY}\n") as &str, "缺少结束标记"),
            (&block("@@@@"), "不是有效的 Base64"),
            (&block("AAAA"), "不是有效 DER 序列"),
            (&block(""), "不是有效 DER 序列"),
        ];
        for (text, message) in cases {
            let err = TlsMaterial::from_pem(text).unwrap_err().to_string();
            assert!(err.contains(message), "{text:?}: {err}");
        }
    }

    #[test]
    fn load_reads_regular_files_only() {
        let dir = crate::sys::fs::TempDir::new("tls").unwrap();
        let path = dir.join("cert.pem");
        std::fs::write(&path, block(TINY)).unwrap();
        assert_eq!(TlsMaterial::load(&path).unwrap().pems().len(), 1);
        let paths = Paths::isolated(dir.path());
        assert!(TlsMaterial::deployed(&paths).is_err());
        std::fs::create_dir_all(paths.tls()).unwrap();
        std::fs::copy(&path, paths.tls().join(CERT_FILE)).unwrap();
        assert_eq!(
            TlsMaterial::deployed(&paths).unwrap(),
            TlsMaterial::load(&path).unwrap()
        );
        let link = dir.join("link.pem");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        assert!(TlsMaterial::load(&link).is_err());
        assert!(TlsMaterial::load(&dir.join("missing.pem")).is_err());
    }
}
