//! The port fields of an FRP state: what frps and the web nginx listen on,
//! what other components must leave to FRP, and what the firewall opens.
//! Kept apart from the rest of the state so that the node side can plan
//! its ports from these fields alone: a problem elsewhere in the FRP state
//! (a domain, the token, the version) must not stop node port planning.

use crate::domain::config::PortRange;
use crate::domain::ports::Reservation;
use crate::domain::protocol::Transport;
use crate::error::Result;
use serde::Deserialize;
use std::collections::BTreeSet;

/// A forwarding range spans at most this many ports.
pub const MAX_RANGE_PORTS: u32 = 1000;
const INVALID_PORTS: &str = "FRP 端口无效，转发范围必须为 1 至 1000 个端口";

/// Every port of one FRP state, per mode.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PortLayout {
    /// Web mode: frps' vhost port (loopback), nginx HTTPS and the optional
    /// HTTP redirect port (0 = disabled). No forwarding range.
    Web {
        bind_port: u16,
        http_port: u16,
        https_port: u16,
        redirect_port: u16,
    },
    /// Tcp mode: public TCP/UDP forwarding inside `range`.
    Tcp { bind_port: u16, range: PortRange },
}

impl PortLayout {
    pub fn bind_port(&self) -> u16 {
        match *self {
            PortLayout::Web { bind_port, .. } | PortLayout::Tcp { bind_port, .. } => bind_port,
        }
    }

    /// Ports frps or the web nginx listen on outside the range: the bind
    /// port, plus the vhost, HTTPS and (when enabled) redirect ports in
    /// web mode.
    pub fn listeners(&self) -> Vec<u16> {
        match *self {
            PortLayout::Web {
                bind_port,
                http_port,
                https_port,
                redirect_port,
            } => [bind_port, http_port, https_port, redirect_port]
                .into_iter()
                .filter(|p| *p != 0)
                .collect(),
            PortLayout::Tcp { bind_port, .. } => vec![bind_port],
        }
    }

    /// Non-zero ports, a range of 1–1000 ports (tcp), and no listener used
    /// twice or inside the range (v2 messages).
    pub fn check(&self) -> Result<()> {
        let nonzero = match *self {
            PortLayout::Web {
                bind_port,
                http_port,
                https_port,
                ..
            } => bind_port != 0 && http_port != 0 && https_port != 0,
            PortLayout::Tcp { bind_port, range } => {
                bind_port != 0
                    && range.start != 0
                    && range.start <= range.end
                    && u32::from(range.end - range.start) < MAX_RANGE_PORTS
            }
        };
        ensure!(nonzero, "{INVALID_PORTS}");
        let range = match *self {
            PortLayout::Tcp { range, .. } => Some(range),
            PortLayout::Web { .. } => None,
        };
        let mut seen = BTreeSet::new();
        let clash = self
            .listeners()
            .into_iter()
            .any(|p| !seen.insert(p) || range.is_some_and(|r| r.contains(p)));
        ensure!(!clash, "FRP 监听端口重复或落在转发范围内");
        Ok(())
    }

    /// Ports other Onebox components must leave to FRP — also while FRP is
    /// stopped. The forwarding range only in tcp mode, where it is public
    /// (H-8.1#8). The listeners are reserved for TCP alone, as in v2 (H
    /// §1.2), also the web-mode bind port that is the one `allowPorts`
    /// entry ([`PortLayout::allow_ports`]): reserving its UDP side would
    /// reject node configurations v2 accepted (a Hysteria2 hop range or a
    /// UDP inbound covering it), the v2→v3 upgrade `regen` included.
    pub fn reservations(&self) -> Vec<Reservation> {
        let reserve = |port: u16, label: &str| Reservation {
            start: port,
            end: port,
            transport: Transport::Tcp,
            label: label.to_owned(),
        };
        let mut out = vec![reserve(self.bind_port(), "控制端口")];
        match *self {
            PortLayout::Web {
                http_port,
                https_port,
                redirect_port,
                ..
            } => {
                out.push(reserve(http_port, "HTTP 端口"));
                out.push(reserve(https_port, "HTTPS 端口"));
                if redirect_port != 0 {
                    out.push(reserve(redirect_port, "HTTP 跳转端口"));
                }
            }
            PortLayout::Tcp { range, .. } => out.push(Reservation {
                start: range.start,
                end: range.end,
                transport: Transport::Both,
                label: "转发端口".to_owned(),
            }),
        }
        out
    }

    /// The frps `allowPorts` entries `(start, end)`, never empty: the
    /// renderer must emit exactly these in both modes, since an empty
    /// `allowPorts` lets a client with the token bind any port (in web
    /// mode on loopback, next to the node's site, guard and subscription
    /// listeners). Tcp mode: the forwarding range. Web mode has no
    /// forwarding: the bind port alone, whose TCP side frps holds itself.
    /// Its UDP side is not reserved (see [`PortLayout::reservations`]): a
    /// UDP proxy there needs the token and binds 127.0.0.1 only, where a
    /// node UDP listener on that port already holds it.
    pub fn allow_ports(&self) -> Vec<(u16, u16)> {
        match *self {
            PortLayout::Web { bind_port, .. } => vec![(bind_port, bind_port)],
            PortLayout::Tcp { range, .. } => vec![(range.start, range.end)],
        }
    }

    /// What the FRP firewall owner opens: the bind port; in web mode HTTPS
    /// and the redirect port (the vhost port stays on loopback); in tcp mode
    /// the whole range for TCP and UDP.
    pub fn firewall_ports(&self) -> Vec<(u16, u16, Transport)> {
        let bind = self.bind_port();
        let mut out = vec![(bind, bind, Transport::Tcp)];
        match *self {
            PortLayout::Web {
                https_port,
                redirect_port,
                ..
            } => {
                out.push((https_port, https_port, Transport::Tcp));
                if redirect_port != 0 {
                    out.push((redirect_port, redirect_port, Transport::Tcp));
                }
            }
            PortLayout::Tcp { range, .. } => out.push((range.start, range.end, Transport::Both)),
        }
        out
    }
}

/// The port fields of a schema-2 `state.json`; every other member is
/// ignored, so only a broken port field makes the reservations unreadable.
#[derive(Deserialize)]
pub(super) struct StoredPorts {
    bind_port: u16,
    mode: StoredMode,
}

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
enum StoredMode {
    Web {
        http_port: u16,
        https_port: u16,
        redirect_port: u16,
    },
    Tcp {
        range: PortRange,
    },
}

impl From<StoredPorts> for PortLayout {
    fn from(stored: StoredPorts) -> PortLayout {
        let bind_port = stored.bind_port;
        match stored.mode {
            StoredMode::Web {
                http_port,
                https_port,
                redirect_port,
            } => PortLayout::Web {
                bind_port,
                http_port,
                https_port,
                redirect_port,
            },
            StoredMode::Tcp { range } => PortLayout::Tcp { bind_port, range },
        }
    }
}
