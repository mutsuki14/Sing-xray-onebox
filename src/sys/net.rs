//! Network facts: /proc/net listener probing, IPv6 availability, the host's
//! global addresses (`ip -j address`), public IP detection.
//!
//! Changes from v2: the /proc tables are read under `Paths::system_root` so
//! tests use fixtures; one `ipv6_available` (v2 had two different ones: a
//! `[::1]` bind test for listeners and nginx, /proc flags for ip6tables and
//! hop tables, which could disagree, F-8.1#25); detected public addresses
//! must match the requested family.

use crate::ctx::Ctx;
use crate::error::{Error, Result};
use crate::sys::exec::Cmd;
use std::collections::BTreeSet;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, UdpSocket};
use std::os::fd::{FromRawFd, OwnedFd};
use std::path::Path;
use std::time::Duration;

/// TCP state code for LISTEN in /proc/net/tcp*.
const TCP_LISTEN: &str = "0A";

/// Whether something listens on `port` (TCP LISTEN sockets, or any bound UDP
/// socket), judged from `{system_root}/proc/net/{tcp,tcp6|udp,udp6}`. When
/// none of the tables is readable, fall back to a bind test on 0.0.0.0
/// (a failed bind counts as "in use"). Port 0 is always "in use".
pub fn listening(system_root: &Path, port: u16, tcp: bool) -> bool {
    if port == 0 {
        return true;
    }
    let tables: [&str; 2] = if tcp {
        ["proc/net/tcp", "proc/net/tcp6"]
    } else {
        ["proc/net/udp", "proc/net/udp6"]
    };
    let mut readable = false;
    for table in tables {
        if let Ok(text) = std::fs::read_to_string(system_root.join(table)) {
            readable = true;
            if table_has_port(&text, port, tcp) {
                return true;
            }
        }
    }
    if readable {
        return false;
    }
    if tcp {
        TcpListener::bind(("0.0.0.0", port)).is_err()
    } else {
        UdpSocket::bind(("0.0.0.0", port)).is_err()
    }
}

/// Scan one /proc/net socket table (header line first). Columns:
/// `sl local_address rem_address st ...` with `local_address` = `HEXIP:HEXPORT`.
pub fn table_has_port(text: &str, port: u16, require_listen: bool) -> bool {
    text.lines().skip(1).any(|line| {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 4 {
            return false;
        }
        let local_port = fields[1]
            .rsplit_once(':')
            .and_then(|(_, hex)| u16::from_str_radix(hex, 16).ok());
        local_port == Some(port) && (!require_listen || fields[3] == TCP_LISTEN)
    })
}

/// Whether the host uses IPv6: the stack exists (`/proc/net/if_inet6`) and
/// is not switched off globally (`net.ipv6.conf.all.disable_ipv6` is not
/// `1`; an unreadable flag counts as enabled), read under `system_root`.
/// The one answer for the `::` listener default, nginx `listen [::]`,
/// ip6tables rules and ip6 hop tables, so they never disagree.
pub fn ipv6_available(system_root: &Path) -> bool {
    system_root.join("proc/net/if_inet6").exists()
        && std::fs::read_to_string(system_root.join("proc/sys/net/ipv6/conf/all/disable_ipv6"))
            .map(|s| s.trim() != "1")
            .unwrap_or(true)
}

/// TCP listeners on every address for `port` (0 = any free port): without
/// IPv6 one on `0.0.0.0`; with IPv6 one on `[::]` made v6-only explicitly
/// plus one on `0.0.0.0` with the port the first got. Setting
/// `IPV6_V6ONLY` on the socket makes the pair independent of the host's
/// `net.ipv6.bindv6only` (relying on the sysctl failed when the value read
/// and the kernel's behaviour differed). A kernel that refuses IPv6
/// sockets although `ipv6_available` said yes gets the IPv4 listener only.
pub fn bind_tcp_all(port: u16, system_root: &Path) -> io::Result<Vec<TcpListener>> {
    let v4 = |port: u16| TcpListener::bind(SocketAddr::from((Ipv4Addr::UNSPECIFIED, port)));
    if !ipv6_available(system_root) {
        return Ok(vec![v4(port)?]);
    }
    let v6 = match bind_v6only(port) {
        Ok(listener) => listener,
        Err(e) if e.raw_os_error() == Some(libc::EAFNOSUPPORT) => return Ok(vec![v4(port)?]),
        Err(e) => return Err(e),
    };
    let bound = v6.local_addr()?.port();
    Ok(vec![v6, v4(bound)?])
}

/// A listening `[::]:port` socket with `IPV6_V6ONLY` and `SO_REUSEADDR`
/// (what `TcpListener::bind` sets), close-on-exec.
fn bind_v6only(port: u16) -> io::Result<TcpListener> {
    // SAFETY: plain socket(2); the descriptor is owned right away.
    let raw = unsafe { libc::socket(libc::AF_INET6, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `raw` is a fresh, valid descriptor nobody else owns.
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };
    set_flag(&fd, libc::SOL_SOCKET, libc::SO_REUSEADDR)?;
    set_flag(&fd, libc::IPPROTO_IPV6, libc::IPV6_V6ONLY)?;
    let addr = libc::sockaddr_in6 {
        sin6_family: libc::AF_INET6 as libc::sa_family_t,
        sin6_port: port.to_be(),
        sin6_flowinfo: 0,
        sin6_addr: libc::in6_addr {
            s6_addr: Ipv6Addr::UNSPECIFIED.octets(),
        },
        sin6_scope_id: 0,
    };
    use std::os::fd::AsRawFd;
    // SAFETY: `addr` is a valid sockaddr_in6 and its exact size is passed.
    let bound = unsafe {
        libc::bind(
            fd.as_raw_fd(),
            (&addr as *const libc::sockaddr_in6).cast(),
            std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
        )
    };
    if bound != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: listen(2) on our own bound socket.
    if unsafe { libc::listen(fd.as_raw_fd(), 128) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(TcpListener::from(fd))
}

fn set_flag(fd: &OwnedFd, level: libc::c_int, name: libc::c_int) -> io::Result<()> {
    use std::os::fd::AsRawFd;
    let on: libc::c_int = 1;
    // SAFETY: setsockopt(2) with a pointer to a live c_int and its size.
    let rc = unsafe {
        libc::setsockopt(
            fd.as_raw_fd(),
            level,
            name,
            (&on as *const libc::c_int).cast(),
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// The host's global unicast addresses as sorted, unique `ip/32` and
/// `ip/128` strings (used by routing rules that must not proxy traffic to
/// the server itself). Runs `ip -j address show scope global`.
pub fn own_global_cidrs(ctx: &Ctx) -> Result<Vec<String>> {
    let out = ctx.check(&Cmd::new("ip").args(["-j", "address", "show", "scope", "global"]))?;
    parse_ip_addresses(&out)
}

/// Parse `ip -j address` output into sorted unique host CIDRs.
pub fn parse_ip_addresses(json: &str) -> Result<Vec<String>> {
    let doc: serde_json::Value = serde_json::from_str(json)?;
    let interfaces = doc
        .as_array()
        .ok_or_else(|| Error::msg("ip 地址清单不是 JSON 数组"))?;
    let mut cidrs = BTreeSet::new();
    for interface in interfaces {
        let Some(addresses) = interface["addr_info"].as_array() else {
            continue;
        };
        for address in addresses {
            if let Some(raw) = address["local"].as_str() {
                let ip: IpAddr = raw
                    .parse()
                    .map_err(|_| Error::msg("ip 地址清单包含无效 IP"))?;
                let bits = if ip.is_ipv4() { 32 } else { 128 };
                cidrs.insert(format!("{ip}/{bits}"));
            }
        }
    }
    Ok(cidrs.into_iter().collect())
}

/// The public address seen by api(6).ipify.org, or `None` when detection
/// fails or the answer is not an address of the requested family.
pub fn detect_public_ip(ctx: &Ctx, v6: bool) -> Option<IpAddr> {
    let (family, endpoint) = if v6 {
        ("-6", "https://api6.ipify.org")
    } else {
        ("-4", "https://api.ipify.org")
    };
    let cmd = Cmd::new("curl")
        .args(["-fsS", family, "--max-time", "8", endpoint])
        .timeout(Duration::from_secs(12));
    let out = ctx.run(&cmd).ok().filter(|o| o.ok())?;
    let ip: IpAddr = out.stdout.trim().parse().ok()?;
    (ip.is_ipv6() == v6).then_some(ip)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sys::exec::Output;
    use crate::sys::fs::TempDir;

    const TCP: &str = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:01BB 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1 1 0000000000000000 100 0 0 10 0
   1: 0100007F:1F90 0100007F:D3A2 01 00000000:00000000 00:00000000 00000000     0        0 2 1 0000000000000000 20 4 30 10 -1
";
    const TCP6: &str = "  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000000000000000000000000000:20FB 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 3 1 0000000000000000 100 0 0 10 0
";
    const UDP: &str = "   sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops
  100: 00000000:0035 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 4 2 0000000000000000 0
";

    fn fixture() -> TempDir {
        let dir = TempDir::new("net").unwrap();
        let net = dir.join("proc/net");
        std::fs::create_dir_all(&net).unwrap();
        std::fs::write(net.join("tcp"), TCP).unwrap();
        std::fs::write(net.join("tcp6"), TCP6).unwrap();
        std::fs::write(net.join("udp"), UDP).unwrap();
        dir
    }

    #[test]
    fn proc_tables() {
        let dir = fixture();
        for (port, tcp, expected) in [
            (443, true, true),   // IPv4 LISTEN
            (8443, true, true),  // IPv6 LISTEN (0x20FB)
            (8080, true, false), // ESTABLISHED only
            (53, false, true),   // UDP, any state
            (443, false, false), // TCP port, UDP query
            (0, true, true),     // port 0 is never free
            (9999, true, false),
        ] {
            assert_eq!(
                listening(dir.path(), port, tcp),
                expected,
                "{port} tcp={tcp}"
            );
        }
    }

    #[test]
    fn table_parser_tolerates_garbage() {
        assert!(!table_has_port(
            "header\n\nshort line\n  0: zz:zz 0 0A",
            443,
            true
        ));
        assert!(table_has_port("h\n 0: 00000000:01BB x 0A", 443, true));
        assert!(!table_has_port("h\n 0: 00000000:01BB x 01", 443, true));
        assert!(table_has_port("h\n 0: 00000000:01BB x 01", 443, false));
    }

    #[test]
    fn unreadable_tables_fall_back_to_bind_test() {
        let dir = TempDir::new("net-empty").unwrap();
        let listener = TcpListener::bind(("0.0.0.0", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        assert!(listening(dir.path(), port, true));
        drop(listener);
        let socket = UdpSocket::bind(("0.0.0.0", 0)).unwrap();
        let port = socket.local_addr().unwrap().port();
        assert!(listening(dir.path(), port, false));
    }

    #[test]
    fn ip_address_inventory() {
        let json = r#"[
          {"ifname":"lo","addr_info":[]},
          {"ifname":"eth0","addr_info":[
            {"family":"inet","local":"203.0.113.10","prefixlen":24},
            {"family":"inet6","local":"2001:db8::10","prefixlen":64},
            {"family":"inet","local":"203.0.113.10","prefixlen":24}
          ]},
          {"ifname":"eth1","addr_info":[{"family":"inet","local":"198.51.100.7"}]},
          {"ifname":"wg0"}
        ]"#;
        assert_eq!(
            parse_ip_addresses(json).unwrap(),
            ["198.51.100.7/32", "2001:db8::10/128", "203.0.113.10/32"]
        );
        assert_eq!(
            parse_ip_addresses("{}").unwrap_err().to_string(),
            "ip 地址清单不是 JSON 数组"
        );
        assert_eq!(
            parse_ip_addresses(r#"[{"addr_info":[{"local":"bogus"}]}]"#)
                .unwrap_err()
                .to_string(),
            "ip 地址清单包含无效 IP"
        );
        assert!(parse_ip_addresses("not json").is_err());
    }

    #[test]
    fn own_cidrs_and_public_ip_go_through_exec() {
        let dir = TempDir::new("net-ctx").unwrap();
        let (ctx, exec, _) = Ctx::test(dir.path());
        exec.on(
            "ip",
            &["-j", "address", "show", "scope", "global"],
            Output::success(r#"[{"addr_info":[{"local":"192.0.2.1"}]}]"#),
        )
        .on("curl", &["-fsS", "-4"], Output::success("192.0.2.1\n"))
        .on("curl", &["-fsS", "-6"], Output::success("192.0.2.1\n"));
        assert_eq!(own_global_cidrs(&ctx).unwrap(), ["192.0.2.1/32"]);
        assert_eq!(
            detect_public_ip(&ctx, false),
            Some("192.0.2.1".parse().unwrap())
        );
        assert_eq!(detect_public_ip(&ctx, true), None, "family mismatch");
        let calls = exec.calls();
        let curl = calls.iter().find(|c| c.program == "curl").unwrap();
        assert_eq!(
            curl.args,
            ["-fsS", "-4", "--max-time", "8", "https://api.ipify.org"]
        );
        assert!(curl.timeout.is_some());
    }

    #[test]
    fn failed_detection_is_none() {
        let dir = TempDir::new("net-fail").unwrap();
        let (ctx, exec, _) = Ctx::test(dir.path());
        exec.on("curl", &[], Output::failure(6, "Could not resolve host"));
        assert_eq!(detect_public_ip(&ctx, false), None);
        exec.on("ip", &[], Output::failure(1, "ip: not found"));
        assert!(own_global_cidrs(&ctx).is_err());
    }

    #[test]
    fn ipv6_follows_the_proc_flags_under_the_system_root() {
        let dir = TempDir::new("net-v6").unwrap();
        assert!(!ipv6_available(dir.path()), "no IPv6 stack");
        let inet6 = dir.join("proc/net/if_inet6");
        std::fs::create_dir_all(inet6.parent().unwrap()).unwrap();
        std::fs::write(&inet6, "").unwrap();
        assert!(ipv6_available(dir.path()), "unreadable flag = enabled");
        let flag = dir.join("proc/sys/net/ipv6/conf/all/disable_ipv6");
        std::fs::create_dir_all(flag.parent().unwrap()).unwrap();
        std::fs::write(&flag, "0\n").unwrap();
        assert!(ipv6_available(dir.path()));
        std::fs::write(&flag, "1\n").unwrap();
        assert!(!ipv6_available(dir.path()), "disabled globally");
    }
}
