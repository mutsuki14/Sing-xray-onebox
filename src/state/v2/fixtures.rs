//! Hand-built v2 states following the spec examples (spec A §3.3, B §5.2,
//! G §3.2), shared by the migration and store tests.

use crate::domain::credentials::keys_from_secret;
use std::collections::BTreeMap;

/// RFC 7748 Alice key pair as v2 stored it (base64url, no padding).
pub(crate) fn reality_pair() -> (String, String) {
    let mut secret = [0u8; 32];
    let hex = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a";
    for (i, b) in secret.iter_mut().enumerate() {
        *b = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap_or(0);
    }
    let keys = keys_from_secret(secret, String::new());
    (keys.private_key, keys.public_key)
}

pub(crate) const UUID: &str = "1f0c2a9e-7b1d-4c3e-8a5f-0123456789ab";
pub(crate) const PASSWORD: &str = "0123456789abcdef0123456789abcdef01234567";
pub(crate) const SS_KEY_16: &str = "AAECAwQFBgcICQoLDA0ODw==";
pub(crate) const CLASH: &str = "00112233445566778899aabbccddeeff0011223344556677";

pub(crate) fn map(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
    pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

/// `install --preset 1 --addr 203.0.113.10 -y` with a self-signed certificate.
pub(crate) fn preset1() -> BTreeMap<String, String> {
    let (private, public) = reality_pair();
    let mut values = map(&[
        ("BLOCK_BT", "1"),
        ("BLOCK_PRIVATE", "1"),
        ("CERT_FILE", "/etc/onebox/tls/cert.pem"),
        ("CERT_PINNED", "1"),
        ("CLASH_SECRET", CLASH),
        ("CORE_hysteria2", "singbox"),
        ("CORE_tuic", "singbox"),
        ("CORE_vless_reality", "singbox"),
        ("GRPC_SERVICE", "a1b2c3d4e5f6"),
        ("HY2_OBFS_PASSWORD", "00112233445566778899aabbccddeeff"),
        ("INSTALLED_AT", "1791000000"),
        ("KEY_FILE", "/etc/onebox/tls/key.pem"),
        ("LISTEN_ADDR", "::"),
        ("NODE_NAME", "onebox"),
        ("OWN_IP_CIDRS", "[\"203.0.113.10/32\"]"),
        ("PASSWORD", PASSWORD),
        ("PORT_hysteria2", "443"),
        ("PORT_tuic", "8443"),
        ("PORT_vless_reality", "443"),
        ("PROTOCOLS", "vless-reality hysteria2 tuic"),
        ("REALITY_DEST", "www.microsoft.com:443"),
        ("REALITY_GUARD_PORT", "18000"),
        ("REALITY_SHORT_ID", "0123456789abcdef"),
        ("REALITY_SITE_TITLE", "山间手记"),
        ("REALITY_SNI", "www.microsoft.com"),
        ("RESOURCE_PROFILE", "balanced"),
        ("SB_VERSION", "1.12.0"),
        ("SERVER_ADDR", "203.0.113.10"),
        ("SERVER_IPV4", "203.0.113.10"),
        ("SHADOWTLS_PASSWORD", PASSWORD),
        ("SHADOWTLS_SNI", "www.microsoft.com"),
        ("SHADOWTLS_SS_PASSWORD", SS_KEY_16),
        ("SS_METHOD", "2022-blake3-aes-128-gcm"),
        ("SS_PASSWORD", SS_KEY_16),
        ("TLS_MODE", "self"),
        ("TLS_SNI", "www.bing.com"),
        ("UUID", UUID),
        ("VMESS_PATH", "/a1b2c3d4e5f7"),
        ("WS_PATH", "/a1b2c3d4e5f8"),
        ("XHTTP_PATH", "/a1b2c3d4e5f9"),
    ]);
    values.insert("REALITY_PRIVATE_KEY".into(), private);
    values.insert("REALITY_PUBLIC_KEY".into(), public);
    values
}

/// The v2 file shape of `values`.
pub(crate) fn file(values: &BTreeMap<String, String>) -> Vec<u8> {
    let doc = serde_json::json!({ "values": values });
    serde_json::to_vec_pretty(&doc).unwrap_or_default()
}

/// A v2 `subscription/settings.json` with two devices.
pub(crate) fn settings(mode: &str, domain: &str, port: u16, method: &str) -> serde_json::Value {
    serde_json::json!({
        "enabled": true,
        "mode": mode,
        "domain": domain,
        "port": port,
        "method": method,
        "custom_cert": null,
        "custom_key": null,
        "devices": [
            {"id": "3f9a1c0d7e5b2a64", "name": "default",
             "hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
             "created": 1760000000u64},
            {"id": "0011223344556677", "name": "手机",
             "hash": "a3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
             "created": 1760000001u64}
        ]
    })
}
