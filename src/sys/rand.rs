//! Randomness from /dev/urandom: bytes, hex, UUIDv4-style ids, base64 keys.
//!
//! Domain code takes a `&mut dyn Random` so tests can be deterministic;
//! [`OsRandom`] is the production source.

use crate::error::{Context, Result};
use base64::Engine;
use std::io::Read;

pub trait Random {
    fn fill(&mut self, buf: &mut [u8]) -> Result<()>;

    fn bytes(&mut self, n: usize) -> Result<Vec<u8>> {
        let mut buf = vec![0u8; n];
        self.fill(&mut buf)?;
        Ok(buf)
    }
    /// `2 * n` lowercase hex characters.
    fn hex(&mut self, n: usize) -> Result<String> {
        Ok(to_hex(&self.bytes(n)?))
    }
    /// v2 format: 32 hex with nibble 12 = '4' and nibble 16 = '8', as 8-4-4-4-12.
    fn uuid(&mut self) -> Result<String> {
        let mut h: Vec<char> = self.hex(16)?.chars().collect();
        h[12] = '4';
        h[16] = '8';
        let s: String = h.into_iter().collect();
        Ok(format!(
            "{}-{}-{}-{}-{}",
            &s[0..8],
            &s[8..12],
            &s[12..16],
            &s[16..20],
            &s[20..32]
        ))
    }
    /// Standard base64 (with padding) of `n` random bytes.
    fn base64(&mut self, n: usize) -> Result<String> {
        Ok(base64::engine::general_purpose::STANDARD.encode(self.bytes(n)?))
    }
}

/// Reads /dev/urandom.
pub struct OsRandom;

impl Random for OsRandom {
    fn fill(&mut self, buf: &mut [u8]) -> Result<()> {
        std::fs::File::open("/dev/urandom")
            .and_then(|mut f| f.read_exact(buf))
            .context("无法读取 /dev/urandom")
    }
}

/// Deterministic source for tests: a simple counter-based stream.
pub struct SeqRandom(pub u8);

impl Random for SeqRandom {
    fn fill(&mut self, buf: &mut [u8]) -> Result<()> {
        for b in buf {
            *b = self.0;
            self.0 = self.0.wrapping_add(1);
        }
        Ok(())
    }
}

/// Convenience: `n` random bytes as hex from the OS source.
pub fn hex(n: usize) -> Result<String> {
    OsRandom.hex(n)
}

pub fn to_hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats() {
        let mut r = SeqRandom(0);
        let uuid = r.uuid().unwrap();
        assert_eq!(uuid.len(), 36);
        assert_eq!(&uuid[14..15], "4");
        assert_eq!(&uuid[19..20], "8");
        assert_eq!(r.hex(4).unwrap().len(), 8);
        assert_eq!(r.base64(16).unwrap().len(), 24);
        assert_eq!(OsRandom.hex(20).unwrap().len(), 40);
    }
}
