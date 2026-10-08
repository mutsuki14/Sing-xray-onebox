//! Shared test inputs for the renderers: deterministic configurations
//! (from `domain::fixtures`) and the committed golden test certificates.

use super::spec::NodeSpec;
use super::tls::TlsMaterial;
use crate::domain::config::NodeConfig;
use crate::domain::fixtures;
use crate::domain::protocol::{Core, Protocol};
use crate::paths::Paths;
use std::path::{Path, PathBuf};

pub(crate) use fixtures::{config, ip_subscription, with_site};

/// `tests/golden` of this crate.
pub(crate) fn golden_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/golden")
}

/// A committed test certificate pair (`selfsigned` or `chain`).
pub(crate) fn cert_pair(name: &str) -> (PathBuf, PathBuf) {
    let dir = golden_dir().join("certs").join(name);
    (dir.join("cert.pem"), dir.join("key.pem"))
}

pub(crate) fn material(name: &str) -> TlsMaterial {
    TlsMaterial::load(&cert_pair(name).0).unwrap()
}

/// Paths rooted at `/onebox-test` (nothing is read or written there).
pub(crate) fn paths() -> Paths {
    let mut paths = Paths::isolated(Path::new("/onebox-test"));
    paths.root = PathBuf::from("/onebox-test/etc");
    paths
}

/// Resolve `cfg` with the self-signed test certificate.
pub(crate) fn spec(cfg: &NodeConfig) -> NodeSpec {
    NodeSpec::new(cfg, &paths(), Some(&material("selfsigned"))).unwrap()
}

/// `spec(config(inbounds))`.
pub(crate) fn spec_with(inbounds: &[(Protocol, u16, Core)]) -> NodeSpec {
    spec(&config(inbounds))
}

/// Every protocol on its default core, ports 10001.. (TCP/UDP collide-free).
pub(crate) fn all_protocols() -> NodeConfig {
    let inbounds: Vec<(Protocol, u16, Core)> = Protocol::ALL
        .iter()
        .enumerate()
        .map(|(i, p)| (*p, 10001 + i as u16, p.cores()[0]))
        .collect();
    config(&inbounds)
}
