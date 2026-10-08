//! Credential generation and format checks. Output formats are identical to v2
//! so clients keep working across upgrades and exports look the same:
//!
//! | field | format |
//! |---|---|
//! | uuid | 32 hex with nibble 12 = `4`, nibble 16 = `8`, as 8-4-4-4-12 |
//! | password / shadowtls password | hex of 20 bytes |
//! | hy2 obfs password | hex of 16 bytes |
//! | clash secret | hex of 24 bytes |
//! | REALITY short id | hex of 8 bytes |
//! | SS key | std base64 of 32 bytes (`*256*` / `*chacha*` methods) or 16 bytes |
//! | ShadowTLS SS key | std base64 of 16 bytes |
//! | ws / vmess / xhttp path | `/` + hex of 6 bytes |
//! | gRPC service | hex of 6 bytes |
//! | REALITY keys | X25519, base64url without padding (43 chars) |
//!
//! Changes from v2: X25519 keys are generated in-process (x25519-dalek)
//! instead of shelling out to `openssl genpkey` and slicing DER files.

use super::config::{Credentials, RealityKeys};
use super::defaults;
use crate::error::{Error, Result};
use crate::sys::rand::Random;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use x25519_dalek::{PublicKey, StaticSecret};

const PASSWORD_BYTES: usize = 20;
const HY2_OBFS_BYTES: usize = 16;
const SHADOWTLS_BYTES: usize = 20;
const CLASH_SECRET_BYTES: usize = 24;
const SHORT_ID_BYTES: usize = 8;
const PATH_BYTES: usize = 6;
const SHADOWTLS_SS_KEY_BYTES: usize = 16;
const X25519_BYTES: usize = 32;

/// Fresh credentials for every protocol (v2 generates all of them on every
/// install, whichever protocols use them). REALITY keys are left out: they
/// exist only while a REALITY inbound does (see [`reality_keys`]).
pub fn generate(rng: &mut dyn Random, ss_method: &str) -> Result<Credentials> {
    Ok(Credentials {
        uuid: rng.uuid()?,
        password: rng.hex(PASSWORD_BYTES)?,
        ss_method: ss_method.to_owned(),
        ss_password: rng.base64(ss_key_len(ss_method))?,
        hy2_obfs_password: rng.hex(HY2_OBFS_BYTES)?,
        shadowtls_password: rng.hex(SHADOWTLS_BYTES)?,
        shadowtls_ss_password: rng.base64(SHADOWTLS_SS_KEY_BYTES)?,
        clash_secret: rng.hex(CLASH_SECRET_BYTES)?,
        reality: None,
        ws_path: path(rng)?,
        vmess_path: path(rng)?,
        xhttp_path: path(rng)?,
        grpc_service: rng.hex(PATH_BYTES)?,
    })
}

/// Regenerate the secrets v2 `reset` rotates (uuid, passwords, SS keys, REALITY
/// keys and short id, Hysteria2 obfs, ShadowTLS secrets, clash secret).
/// Paths and the gRPC service name are kept, as are absent REALITY keys.
pub fn reset(creds: &mut Credentials, rng: &mut dyn Random) -> Result<()> {
    creds.uuid = rng.uuid()?;
    creds.password = rng.hex(PASSWORD_BYTES)?;
    creds.ss_password = rng.base64(ss_key_len(&creds.ss_method))?;
    if creds.reality.is_some() {
        creds.reality = Some(reality_keys(rng)?);
    }
    creds.hy2_obfs_password = rng.hex(HY2_OBFS_BYTES)?;
    creds.shadowtls_password = rng.hex(SHADOWTLS_BYTES)?;
    creds.shadowtls_ss_password = rng.base64(SHADOWTLS_SS_KEY_BYTES)?;
    creds.clash_secret = rng.hex(CLASH_SECRET_BYTES)?;
    Ok(())
}

/// A new X25519 key pair and short id. The secret is clamped like `openssl`,
/// `xray x25519` and `sing-box generate reality-keypair` do, so the stored
/// private key is canonical (cores clamp on use either way).
pub fn reality_keys(rng: &mut dyn Random) -> Result<RealityKeys> {
    let mut secret = [0u8; X25519_BYTES];
    rng.fill(&mut secret)?;
    secret[0] &= 248;
    secret[31] &= 127;
    secret[31] |= 64;
    let short_id = rng.hex(SHORT_ID_BYTES)?;
    Ok(keys_from_secret(secret, short_id))
}

/// Encode a key pair from raw secret bytes (no clamping applied here).
pub fn keys_from_secret(secret: [u8; X25519_BYTES], short_id: String) -> RealityKeys {
    let public = PublicKey::from(&StaticSecret::from(secret));
    RealityKeys {
        private_key: URL_SAFE_NO_PAD.encode(secret),
        public_key: URL_SAFE_NO_PAD.encode(public.as_bytes()),
        short_id,
    }
}

/// Public key (base64url) belonging to a stored private key.
pub fn public_key_for(private_key: &str) -> Result<String> {
    let secret = decode_x25519(private_key).ok_or_else(|| Error::msg("REALITY 私钥格式无效"))?;
    Ok(keys_from_secret(secret, String::new()).public_key)
}

/// SS-2022 key size: 32 bytes for AES-256 and ChaCha20 methods, else 16.
pub fn ss_key_len(method: &str) -> usize {
    if method.contains("256") || method.contains("chacha") {
        32
    } else {
        16
    }
}

fn path(rng: &mut dyn Random) -> Result<String> {
    Ok(format!("/{}", rng.hex(PATH_BYTES)?))
}

fn decode_x25519(text: &str) -> Option<[u8; X25519_BYTES]> {
    let bytes = URL_SAFE_NO_PAD.decode(text).ok()?;
    bytes.try_into().ok()
}

fn is_hex(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// `8-4-4-4-12` hexadecimal (case-insensitive; v1 states may be upper-case).
pub fn valid_uuid(s: &str) -> bool {
    let groups: Vec<&str> = s.split('-').collect();
    groups.len() == 5
        && groups
            .iter()
            .zip([8, 4, 4, 4, 12])
            .all(|(g, n)| g.len() == n && is_hex(g))
}

/// Free-form secret (v1 allowed arbitrary passwords): non-empty, no control
/// characters, bounded so it fits every client format.
pub fn valid_secret(s: &str) -> bool {
    !s.is_empty() && s.len() <= 256 && !s.chars().any(char::is_control)
}

pub fn valid_ss_method(method: &str) -> bool {
    defaults::SS_METHODS.contains(&method)
}

/// Standard base64 decoding to exactly the method's key length.
pub fn valid_ss_key(method: &str, key: &str) -> bool {
    STANDARD
        .decode(key)
        .is_ok_and(|bytes| bytes.len() == ss_key_len(method))
}

/// URL path for WS / XHTTP transports: `/` followed by URL-safe characters.
pub fn valid_path(s: &str) -> bool {
    s.starts_with('/')
        && s.len() <= 128
        && s.bytes()
            .skip(1)
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~' | b'/'))
}

/// gRPC service name: non-empty `[A-Za-z0-9._-]`.
pub fn valid_grpc_service(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
}

/// REALITY short id: 2–16 hex characters, even length (Xray rule).
pub fn valid_short_id(s: &str) -> bool {
    is_hex(s) && s.len() <= 16 && s.len().is_multiple_of(2)
}

/// Keys decode to 32 bytes each and the public key belongs to the private key.
pub fn check_reality_keys(keys: &RealityKeys) -> Result<()> {
    let public = public_key_for(&keys.private_key)?;
    ensure!(
        decode_x25519(&keys.public_key).is_some(),
        "REALITY 公钥格式无效"
    );
    ensure!(public == keys.public_key, "REALITY 公钥与私钥不匹配");
    ensure!(valid_short_id(&keys.short_id), "REALITY ShortID 无效");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sys::rand::SeqRandom;

    fn hex_to_bytes(hex: &str) -> [u8; 32] {
        let mut out = [0u8; 32];
        for (i, b) in out.iter_mut().enumerate() {
            *b = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap();
        }
        out
    }

    #[test]
    fn rfc7748_vector() {
        let secret =
            hex_to_bytes("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        let keys = keys_from_secret(secret, "00".into());
        let public = URL_SAFE_NO_PAD.decode(&keys.public_key).unwrap();
        assert_eq!(
            public,
            hex_to_bytes("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
        );
        assert_eq!(URL_SAFE_NO_PAD.decode(&keys.private_key).unwrap(), secret);
        assert_eq!(keys.private_key.len(), 43);
        assert_eq!(public_key_for(&keys.private_key).unwrap(), keys.public_key);
    }

    #[test]
    fn generated_formats_match_v2() {
        let mut rng = SeqRandom(0);
        let c = generate(&mut rng, defaults::SS_METHOD).unwrap();
        assert!(valid_uuid(&c.uuid));
        assert_eq!(&c.uuid[14..15], "4");
        assert_eq!(&c.uuid[19..20], "8");
        assert_eq!(c.password.len(), 40);
        assert_eq!(c.hy2_obfs_password.len(), 32);
        assert_eq!(c.shadowtls_password.len(), 40);
        assert_eq!(c.clash_secret.len(), 48);
        assert_eq!(c.ss_password.len(), 24);
        assert!(valid_ss_key(&c.ss_method, &c.ss_password));
        assert_eq!(c.shadowtls_ss_password.len(), 24);
        for p in [&c.ws_path, &c.vmess_path, &c.xhttp_path] {
            assert_eq!(p.len(), 13);
            assert!(valid_path(p));
        }
        assert_eq!(c.grpc_service.len(), 12);
        assert!(!c.grpc_service.starts_with('/'));
        assert!(c.reality.is_none());
    }

    #[test]
    fn ss_key_length_depends_on_method() {
        let table = [
            ("2022-blake3-aes-128-gcm", 16, 24),
            ("2022-blake3-aes-256-gcm", 32, 44),
            ("2022-blake3-chacha20-poly1305", 32, 44),
        ];
        for (method, bytes, chars) in table {
            assert_eq!(ss_key_len(method), bytes);
            let c = generate(&mut SeqRandom(7), method).unwrap();
            assert_eq!(c.ss_password.len(), chars, "{method}");
            assert!(valid_ss_key(method, &c.ss_password));
        }
        assert!(!valid_ss_key(
            "2022-blake3-aes-256-gcm",
            "AAAAAAAAAAAAAAAAAAAAAA=="
        ));
        assert!(!valid_ss_key("2022-blake3-aes-128-gcm", "not base64!"));
    }

    #[test]
    fn generated_reality_keys_are_clamped_and_consistent() {
        let keys = reality_keys(&mut SeqRandom(200)).unwrap();
        let secret = URL_SAFE_NO_PAD.decode(&keys.private_key).unwrap();
        assert_eq!(secret[0] & 7, 0);
        assert_eq!(secret[31] & 0xc0, 0x40);
        assert_eq!(keys.short_id.len(), 16);
        check_reality_keys(&keys).unwrap();
        let mut bad = keys.clone();
        bad.public_key = reality_keys(&mut SeqRandom(1)).unwrap().public_key;
        assert_eq!(
            check_reality_keys(&bad).unwrap_err().to_string(),
            "REALITY 公钥与私钥不匹配"
        );
        bad.private_key = "short".into();
        assert!(check_reality_keys(&bad).is_err());
    }

    #[test]
    fn reset_rotates_secrets_and_keeps_paths() {
        let mut rng = SeqRandom(3);
        let mut c = generate(&mut rng, defaults::SS_METHOD).unwrap();
        c.reality = Some(reality_keys(&mut rng).unwrap());
        let before = c.clone();
        reset(&mut c, &mut rng).unwrap();
        assert_ne!(c.uuid, before.uuid);
        assert_ne!(c.password, before.password);
        assert_ne!(c.ss_password, before.ss_password);
        assert_ne!(c.hy2_obfs_password, before.hy2_obfs_password);
        assert_ne!(c.shadowtls_password, before.shadowtls_password);
        assert_ne!(c.shadowtls_ss_password, before.shadowtls_ss_password);
        assert_ne!(c.clash_secret, before.clash_secret);
        assert_ne!(c.reality, before.reality);
        assert_eq!(c.ws_path, before.ws_path);
        assert_eq!(c.vmess_path, before.vmess_path);
        assert_eq!(c.xhttp_path, before.xhttp_path);
        assert_eq!(c.grpc_service, before.grpc_service);
        assert_eq!(c.ss_method, before.ss_method);

        let mut without = generate(&mut rng, defaults::SS_METHOD).unwrap();
        reset(&mut without, &mut rng).unwrap();
        assert!(without.reality.is_none());
    }

    #[test]
    fn format_checks() {
        assert!(valid_uuid("1F0C2A9E-7B1D-4C3E-8A5F-0123456789AB"));
        assert!(!valid_uuid("1f0c2a9e7b1d4c3e8a5f0123456789ab"));
        assert!(!valid_uuid("1f0c2a9e-7b1d-4c3e-8a5f-0123456789ag"));
        assert!(valid_secret("hello world"));
        assert!(!valid_secret(""));
        assert!(!valid_secret("a\nb"));
        assert!(valid_path("/a1b2c3"));
        assert!(!valid_path("a1b2"));
        assert!(!valid_path("/a b"));
        assert!(valid_grpc_service("a1b2c3"));
        assert!(!valid_grpc_service("/a1"));
        assert!(valid_short_id("0123456789abcdef"));
        assert!(!valid_short_id("abc"));
        assert!(!valid_short_id("0123456789abcdef01"));
        assert!(!valid_short_id(""));
        assert!(valid_ss_method("2022-blake3-aes-256-gcm"));
        assert!(!valid_ss_method("aes-128-gcm"));
    }
}
