//! The per-owner firewall ledger (`firewall-v2.json` & co.), byte-compatible
//! with v2 so ledgers written by v2 are reconciled (and cleaned up) by v3.
//!
//! Shape (pretty JSON, no trailing newline, mode 0600):
//! `{"rules":[{"backend","port","end","udp","zone","family","table","chain","token","permanent"}]}`.
//! Fields other than `backend`, `port`, `udp` default when absent; `end` 0
//! means a single port. Rows are validated on load because their values end
//! up in command arguments.

use super::{safe_word, Firewalld, Iptables, Location, Nft, Proto, Rule, Ufw};
use crate::error::{Context, Error, Result};
use crate::paths::Paths;
use crate::sys::fs::{atomic_write, read_bounded};
use crate::sys::lock::FileLock;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Ledgers are small; anything bigger is not ours.
const MAX_LEDGER_BYTES: u64 = 4 << 20;
/// How long to wait for another process working on the same owner.
pub(super) const LOCK_WAIT: Duration = Duration::from_secs(30);
const LOCK_BUSY: &str = "另一个防火墙操作正在进行；稍后重试";

/// v2 ledger location: `frp` under the FRP root, `proxy` as
/// `firewall-v2.json`, every other owner as `firewall-{owner}.json`.
pub fn ledger_path(paths: &Paths, owner: &str) -> PathBuf {
    match owner {
        "frp" => paths.frp_root.join("firewall-v2.json"),
        "proxy" => paths.root.join("firewall-v2.json"),
        other => paths.root.join(format!("firewall-{other}.json")),
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct LedgerFile {
    #[serde(default)]
    rules: Vec<Row>,
}

/// One v2 ledger row (field order = v2 serialization order).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
struct Row {
    backend: String,
    port: u16,
    #[serde(default)]
    end: u16,
    udp: bool,
    #[serde(default)]
    zone: String,
    #[serde(default)]
    family: String,
    #[serde(default)]
    table: String,
    #[serde(default)]
    chain: String,
    #[serde(default)]
    token: String,
    #[serde(default)]
    permanent: bool,
}

/// A recorded rule and where it lives.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub location: Location,
    pub rule: Rule,
}

/// The loaded ledger of one owner. Mutate `entries`, then [`Ledger::save`].
#[derive(Debug)]
pub struct Ledger {
    path: PathBuf,
    pub entries: Vec<Entry>,
}

impl Ledger {
    /// Read the ledger at `path`; a missing file is an empty ledger. The
    /// file must be a regular file (never followed through a symlink).
    pub fn load(path: &Path, owner: &str) -> Result<Ledger> {
        let entries = match read_bounded(path, MAX_LEDGER_BYTES) {
            Ok(bytes) => parse(&bytes, owner)
                .with_context(|| format!("防火墙台账无效: {}", path.display()))?,
            Err(Error::Io { source, .. }) if source.kind() == std::io::ErrorKind::NotFound => {
                Vec::new()
            }
            Err(e) => return Err(e),
        };
        Ok(Ledger {
            path: path.to_path_buf(),
            entries,
        })
    }

    /// Atomically replace the ledger file (0600).
    pub fn save(&self) -> Result<()> {
        let file = LedgerFile {
            rules: self.entries.iter().map(row_of).collect(),
        };
        atomic_write(&self.path, &serde_json::to_vec_pretty(&file)?, 0o600)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Drop the entry carrying `token` (tokens are unique per ledger).
    pub fn remove_token(&mut self, token: &str) {
        self.entries.retain(|e| e.rule.token != token);
    }
}

fn parse(bytes: &[u8], owner: &str) -> Result<Vec<Entry>> {
    let file: LedgerFile = serde_json::from_slice(bytes)?;
    file.rules
        .into_iter()
        .enumerate()
        .map(|(i, row)| entry_of(row, owner).with_context(|| format!("第 {} 条规则", i + 1)))
        .collect()
}

/// Validate a row and turn it into a typed entry.
fn entry_of(row: Row, owner: &str) -> Result<Entry> {
    if row.port == 0 {
        return Err(Error::msg("端口不能为0"));
    }
    if !safe_word(&row.token) {
        return Err(Error::msg("规则标记无效"));
    }
    let location = location_of(&row)?;
    Ok(Entry {
        location,
        rule: Rule {
            owner: owner.to_string(),
            proto: if row.udp { Proto::Udp } else { Proto::Tcp },
            start: row.port,
            end: row.end.max(row.port),
            token: row.token,
        },
    })
}

fn location_of(row: &Row) -> Result<Location> {
    let words = |values: &[&str]| values.iter().all(|v| safe_word(v));
    match row.backend.as_str() {
        "ufw" => Ok(Location::Ufw(Ufw)),
        "iptables" => Ok(Location::Iptables(Iptables { v6: false })),
        "ip6tables" => Ok(Location::Iptables(Iptables { v6: true })),
        "firewalld" if words(&[&row.zone]) => Ok(Location::Firewalld(Firewalld {
            zone: row.zone.clone(),
            permanent: row.permanent,
        })),
        "nft"
            if matches!(row.family.as_str(), "ip" | "ip6" | "inet")
                && words(&[&row.table, &row.chain]) =>
        {
            Ok(Location::Nft(Nft {
                family: row.family.clone(),
                table: row.table.clone(),
                chain: row.chain.clone(),
            }))
        }
        "firewalld" | "nft" => Err(Error::msg("防火墙位置无效")),
        _ => Err(Error::msg("未知防火墙台账类型")),
    }
}

fn row_of(entry: &Entry) -> Row {
    let rule = &entry.rule;
    let mut row = Row {
        backend: entry.location.backend().name().to_string(),
        port: rule.start,
        end: rule.end,
        udp: rule.proto.is_udp(),
        token: rule.token.clone(),
        ..Row::default()
    };
    match &entry.location {
        Location::Firewalld(f) => {
            row.zone = f.zone.clone();
            row.permanent = f.permanent;
        }
        Location::Nft(n) => {
            row.family = n.family.clone();
            row.table = n.table.clone();
            row.chain = n.chain.clone();
        }
        Location::Ufw(_) | Location::Iptables(_) => {}
    }
    row
}

/// Serialize ledger mutations of one owner: `{ledger}.lock` (v2 path,
/// e.g. `firewall-v2.lock`), waiting up to `wait` for another holder.
pub(super) fn lock(ledger: &Path, wait: Duration) -> Result<FileLock> {
    super::lock_waiting(&ledger.with_extension("lock"), LOCK_BUSY, wait)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sys::fs::TempDir;
    use std::time::Instant;

    /// A v2 ledger as v2's `serde_json::to_vec_pretty` wrote it.
    const V2_LEDGER: &str = r#"{
  "rules": [
    {
      "backend": "iptables",
      "port": 443,
      "end": 443,
      "udp": false,
      "zone": "",
      "family": "",
      "table": "",
      "chain": "",
      "token": "onebox-proxy-0123456789abcdef",
      "permanent": false
    },
    {
      "backend": "firewalld",
      "port": 20000,
      "end": 40000,
      "udp": true,
      "zone": "public",
      "family": "",
      "table": "",
      "chain": "",
      "token": "onebox-proxy-89abcdef01234567",
      "permanent": true
    },
    {
      "backend": "nft",
      "port": 8443,
      "end": 8443,
      "udp": true,
      "zone": "",
      "family": "inet",
      "table": "filter",
      "chain": "input",
      "token": "onebox-proxy-fedcba9876543210",
      "permanent": false
    }
  ]
}"#;

    #[test]
    fn v2_ledgers_round_trip_byte_for_byte() {
        let dir = TempDir::new("ledger").unwrap();
        let path = dir.join("firewall-v2.json");
        std::fs::write(&path, V2_LEDGER).unwrap();
        let ledger = Ledger::load(&path, "proxy").unwrap();
        assert_eq!(ledger.entries.len(), 3);
        assert_eq!(
            ledger.entries[1].location,
            Location::Firewalld(Firewalld {
                zone: "public".into(),
                permanent: true
            })
        );
        assert_eq!(ledger.entries[1].rule.proto, Proto::Udp);
        assert_eq!(ledger.entries[2].rule.owner, "proxy");
        ledger.save().unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), V2_LEDGER);
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn missing_fields_default_like_v2() {
        let dir = TempDir::new("ledger").unwrap();
        let path = dir.join("firewall-acme.json");
        std::fs::write(
            &path,
            r#"{"rules":[{"backend":"ufw","port":80,"udp":false,"token":"onebox-acme-00"}]}"#,
        )
        .unwrap();
        let ledger = Ledger::load(&path, "acme").unwrap();
        let rule = &ledger.entries[0].rule;
        assert_eq!((rule.start, rule.end), (80, 80), "end 0 means one port");
        assert_eq!(ledger.entries[0].location, Location::Ufw(Ufw));
        assert!(Ledger::load(&dir.join("absent.json"), "acme")
            .unwrap()
            .entries
            .is_empty());
        std::fs::write(&path, "{}").unwrap();
        assert!(Ledger::load(&path, "acme").unwrap().entries.is_empty());
    }

    #[test]
    fn unsafe_rows_are_rejected() {
        let dir = TempDir::new("ledger").unwrap();
        let path = dir.join("firewall-v2.json");
        for (row, message) in [
            (
                r#"{"backend":"pf","port":1,"udp":false,"token":"t"}"#,
                "未知防火墙台账类型",
            ),
            (
                r#"{"backend":"ufw","port":0,"udp":false,"token":"t"}"#,
                "端口不能为0",
            ),
            (
                r#"{"backend":"ufw","port":1,"udp":false,"token":"a b"}"#,
                "规则标记无效",
            ),
            (r#"{"backend":"ufw","port":1,"udp":false}"#, "规则标记无效"),
            (
                r#"{"backend":"firewalld","port":1,"udp":false,"zone":"x;y","token":"t"}"#,
                "防火墙位置无效",
            ),
            (
                r#"{"backend":"nft","port":1,"udp":false,"family":"bridge","table":"t","chain":"c","token":"t"}"#,
                "防火墙位置无效",
            ),
        ] {
            std::fs::write(&path, format!(r#"{{"rules":[{row}]}}"#)).unwrap();
            let err = Ledger::load(&path, "proxy").unwrap_err().to_string();
            assert!(err.contains("防火墙台账无效"), "{err}");
            assert!(err.ends_with(message), "{err}");
        }
    }

    #[test]
    fn symlinked_ledgers_are_refused() {
        let dir = TempDir::new("ledger").unwrap();
        let target = dir.join("elsewhere.json");
        std::fs::write(&target, r#"{"rules":[]}"#).unwrap();
        let path = dir.join("firewall-v2.json");
        std::os::unix::fs::symlink(&target, &path).unwrap();
        assert!(Ledger::load(&path, "proxy").is_err());
    }

    #[test]
    fn ledger_paths_match_v2() {
        let paths = Paths::from_lookup(|_| None).unwrap();
        assert_eq!(
            ledger_path(&paths, "proxy"),
            PathBuf::from("/etc/onebox/firewall-v2.json")
        );
        assert_eq!(
            ledger_path(&paths, "acme"),
            PathBuf::from("/etc/onebox/firewall-acme.json")
        );
        assert_eq!(
            ledger_path(&paths, "frp"),
            PathBuf::from("/etc/onebox-frp/firewall-v2.json")
        );
        assert_eq!(
            ledger_path(&paths, "frp").with_extension("lock"),
            PathBuf::from("/etc/onebox-frp/firewall-v2.lock")
        );
    }

    #[test]
    fn lock_waits_then_reports_busy() {
        let dir = TempDir::new("ledger").unwrap();
        let path = dir.join("firewall-v2.json");
        let held = lock(&path, Duration::ZERO).unwrap();
        assert_eq!(held.path(), dir.join("firewall-v2.lock"));
        let start = Instant::now();
        let err = lock(&path, Duration::from_millis(250)).unwrap_err();
        assert!(start.elapsed() >= Duration::from_millis(250));
        assert_eq!(err.to_string(), LOCK_BUSY);
        drop(held);
        lock(&path, Duration::ZERO).unwrap();
    }
}
