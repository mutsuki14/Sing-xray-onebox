//! Typed readers over the v2 key/value bag: protocols, identity,
//! credentials and handshake targets.

use crate::domain::config::*;
use crate::domain::credentials::{self as creds};
use crate::domain::defaults;
use crate::domain::protocol::{Core, Protocol};
use crate::domain::validate::{valid_domain, valid_label};
use crate::error::{Error, Result};
use crate::sys::rand::Random;
use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

pub(super) struct V2<'a> {
    values: &'a BTreeMap<String, String>,
    warnings: Vec<String>,
}

/// `PORT_` / `CORE_` suffix: the protocol id with `-` → `_`.
pub(super) fn protocol_key(protocol: Protocol) -> String {
    protocol.id().replace('-', "_")
}

impl<'a> V2<'a> {
    pub(super) fn new(values: &'a BTreeMap<String, String>) -> Self {
        V2 {
            values,
            warnings: Vec::new(),
        }
    }

    pub(super) fn values(&self) -> &'a BTreeMap<String, String> {
        self.values
    }

    /// Raw value, `""` when absent (v2 `State::get`).
    pub(super) fn get(&self, key: &str) -> &'a str {
        self.values.get(key).map_or("", String::as_str)
    }

    /// Trimmed value, `None` when absent or blank.
    pub(super) fn nonempty(&self, key: &str) -> Option<&'a str> {
        Some(self.get(key).trim()).filter(|v| !v.is_empty())
    }

    /// v2 flags are exactly `"1"`.
    pub(super) fn flag(&self, key: &str) -> bool {
        self.get(key) == "1"
    }

    pub(super) fn warn(&mut self, message: impl Into<String>) {
        self.warnings.push(message.into());
    }

    pub(super) fn into_warnings(self) -> Vec<String> {
        self.warnings
    }

    /// Optional parsed value; an unparsable value is dropped with a warning.
    pub(super) fn parse_lenient<T: FromStr>(&mut self, key: &str) -> Option<T> {
        let raw = self.nonempty(key)?;
        let parsed = raw.parse().ok();
        if parsed.is_none() {
            self.warn(format!("v2 字段 {key} 无效，已忽略: {raw}"));
        }
        parsed
    }

    /// `PROTOCOLS` in stored order with `PORT_`/`CORE_`. A missing port is an
    /// error (v2 silently assumed 443, spec A §8.1 #3).
    pub(super) fn inbounds(&self) -> Result<Vec<Inbound>> {
        let mut out: Vec<Inbound> = Vec::new();
        for token in self.get("PROTOCOLS").split_whitespace() {
            let protocol: Protocol = token.parse()?;
            ensure!(!out.iter().any(|i| i.protocol == protocol), "协议重复");
            let key = protocol_key(protocol);
            let port = self
                .nonempty(&format!("PORT_{key}"))
                .and_then(|p| p.parse::<u16>().ok())
                .filter(|p| *p != 0)
                .ok_or_else(|| Error::msg(format!("{protocol} 端口无效")))?;
            let core = match self.nonempty(&format!("CORE_{key}")) {
                Some(core) => core.parse::<Core>()?,
                None => protocol.cores()[0],
            };
            ensure!(protocol.supports_core(core), "{protocol} 不支持 {core}");
            out.push(Inbound {
                protocol,
                port,
                core,
            });
        }
        ensure!(!out.is_empty(), "状态缺少协议列表");
        Ok(out)
    }

    pub(super) fn node_name(&mut self) -> String {
        match self.nonempty("NODE_NAME") {
            Some(name) if valid_label(name) => name.to_owned(),
            Some(name) => {
                self.warn(format!("v2 节点名称无效，已改为 onebox: {name:?}"));
                defaults::NODE_NAME.to_owned()
            }
            None => defaults::NODE_NAME.to_owned(),
        }
    }

    /// `SERVER_ADDR` (falling back to the detected addresses) plus the
    /// detected families; the address's own family is forced to the address
    /// (v2 could leave a stale value there, B-9.1 #8).
    pub(super) fn server(&mut self) -> Result<ServerAddr> {
        let mut ipv4 = self.parse_lenient::<Ipv4Addr>("SERVER_IPV4");
        let mut ipv6 = self.parse_lenient::<Ipv6Addr>("SERVER_IPV6");
        let addr = match self.nonempty("SERVER_ADDR") {
            Some(raw) => raw
                .parse::<Host>()
                .map_err(|_| Error::msg(format!("v2 字段 SERVER_ADDR 无效: {raw}")))?,
            None => {
                let ip = ipv4.map(IpAddr::V4).or(ipv6.map(IpAddr::V6));
                let ip = ip.ok_or("v2 状态缺少 SERVER_ADDR")?;
                self.warn(format!("v2 状态缺少 SERVER_ADDR，已使用 {ip}"));
                Host::Ip(ip)
            }
        };
        let addr = match addr {
            Host::Ip(ip) => Host::Ip(ip.to_canonical()),
            host => host,
        };
        match addr {
            Host::Ip(IpAddr::V4(v4)) if ipv4 != Some(v4) => {
                self.stale_family("SERVER_IPV4", ipv4.map(|x| x.to_string()), &v4);
                ipv4 = Some(v4);
            }
            Host::Ip(IpAddr::V6(v6)) if ipv6 != Some(v6) => {
                self.stale_family("SERVER_IPV6", ipv6.map(|x| x.to_string()), &v6);
                ipv6 = Some(v6);
            }
            _ => {}
        }
        Ok(ServerAddr {
            addr,
            ipv4,
            ipv6,
            ipv4_warp: self.flag("SERVER_IPV4_WARP"),
            ipv6_warp: self.flag("SERVER_IPV6_WARP"),
        })
    }

    fn stale_family(&mut self, key: &str, old: Option<String>, new: &dyn std::fmt::Display) {
        if let Some(old) = old {
            self.warn(format!("{key}={old} 与连接地址不一致，已改为 {new}"));
        }
    }

    /// `LISTEN_ADDR`; v2 installs always wrote it. Without it the IPv4
    /// wildcard is the one address that binds on every host.
    pub(super) fn listen(&mut self) -> Result<IpAddr> {
        match self.nonempty("LISTEN_ADDR") {
            Some(raw) => raw
                .parse()
                .map_err(|_| Error::msg(format!("v2 字段 LISTEN_ADDR 无效: {raw}"))),
            None => {
                self.warn("v2 状态缺少 LISTEN_ADDR，已使用 0.0.0.0（仅 IPv4）");
                Ok(defaults::listen(false))
            }
        }
    }

    pub(super) fn credentials(
        &mut self,
        inbounds: &[Inbound],
        rng: &mut dyn Random,
    ) -> Result<Credentials> {
        use Protocol::*;
        let uses = |ps: &[Protocol]| inbounds.iter().any(|i| ps.contains(&i.protocol));
        let ss_method = self.ss_method(uses(&[Shadowsocks]))?;
        let ss_len = creds::ss_key_len(&ss_method);
        let st_method = defaults::SHADOWTLS_SS_METHOD;
        let obfs = uses(&[Hysteria2]) && self.flag("HY2_OBFS");
        let any_reality = inbounds.iter().any(|i| i.protocol.reality());
        let uuid_users = [VlessReality, VlessXhttp, VlessGrpc, VlessWs, VmessWs, Tuic];
        let password_users = [Trojan, Hysteria2, Tuic, Anytls, AnytlsReality];
        Ok(Credentials {
            uuid: self.secret("UUID", &creds::valid_uuid, uses(&uuid_users), rng, |r| {
                r.uuid()
            })?,
            password: self.secret(
                "PASSWORD",
                &creds::valid_secret,
                uses(&password_users),
                rng,
                |r| r.hex(20),
            )?,
            ss_password: self.secret(
                "SS_PASSWORD",
                &|k| creds::valid_ss_key(&ss_method, k),
                uses(&[Shadowsocks]),
                rng,
                |r| r.base64(ss_len),
            )?,
            ss_method,
            hy2_obfs_password: self.secret(
                "HY2_OBFS_PASSWORD",
                &creds::valid_secret,
                obfs,
                rng,
                |r| r.hex(16),
            )?,
            shadowtls_password: self.secret(
                "SHADOWTLS_PASSWORD",
                &creds::valid_secret,
                uses(&[Shadowtls]),
                rng,
                |r| r.hex(20),
            )?,
            shadowtls_ss_password: self.secret(
                "SHADOWTLS_SS_PASSWORD",
                &|k| creds::valid_ss_key(st_method, k),
                uses(&[Shadowtls]),
                rng,
                |r| r.base64(16),
            )?,
            clash_secret: self.secret("CLASH_SECRET", &creds::valid_secret, true, rng, |r| {
                r.hex(24)
            })?,
            reality: self.reality_keys(any_reality, rng)?,
            ws_path: self.secret("WS_PATH", &creds::valid_path, uses(&[VlessWs]), rng, path)?,
            vmess_path: self.secret(
                "VMESS_PATH",
                &creds::valid_path,
                uses(&[VmessWs]),
                rng,
                path,
            )?,
            xhttp_path: self.secret(
                "XHTTP_PATH",
                &creds::valid_path,
                uses(&[VlessXhttp]),
                rng,
                path,
            )?,
            grpc_service: self.secret(
                "GRPC_SERVICE",
                &creds::valid_grpc_service,
                uses(&[VlessGrpc]),
                rng,
                |r| r.hex(6),
            )?,
        })
    }

    fn ss_method(&mut self, used: bool) -> Result<String> {
        match self.nonempty("SS_METHOD") {
            None => Ok(defaults::SS_METHOD.to_owned()),
            Some(m) if creds::valid_ss_method(m) => Ok(m.to_owned()),
            Some(m) if used => bail!("Shadowsocks 加密方式无效: {m}"),
            Some(m) => {
                self.warn(format!("v2 字段 SS_METHOD 无效，已改为默认值: {m}"));
                Ok(defaults::SS_METHOD.to_owned())
            }
        }
    }

    /// A credential: kept when valid; invalid and used → error; otherwise
    /// generated (warning when an enabled protocol uses it).
    fn secret(
        &mut self,
        key: &str,
        valid: &dyn Fn(&str) -> bool,
        used: bool,
        rng: &mut dyn Random,
        generate: impl FnOnce(&mut dyn Random) -> Result<String>,
    ) -> Result<String> {
        match self.nonempty(key) {
            Some(value) if valid(value) => return Ok(value.to_owned()),
            Some(_) if used => bail!("v2 字段 {key} 无效"),
            Some(_) => self.warn(format!("v2 字段 {key} 无效，已重新生成")),
            None if used => self.warn(format!("v2 状态缺少 {key}，已生成新值；请更新客户端")),
            None => {}
        }
        generate(rng)
    }

    /// REALITY keys while a REALITY inbound exists. The public key is always
    /// derived from the private key (a mismatch is reported).
    fn reality_keys(
        &mut self,
        any_reality: bool,
        rng: &mut dyn Random,
    ) -> Result<Option<RealityKeys>> {
        if !any_reality {
            return Ok(None);
        }
        let Some(private_key) = self.nonempty("REALITY_PRIVATE_KEY") else {
            self.warn("v2 状态缺少 REALITY 密钥，已生成新密钥；请更新客户端");
            return creds::reality_keys(rng).map(Some);
        };
        let public_key = creds::public_key_for(private_key)
            .map_err(|_| Error::msg("v2 字段 REALITY_PRIVATE_KEY 无效"))?;
        if self.nonempty("REALITY_PUBLIC_KEY") != Some(public_key.as_str()) {
            self.warn("REALITY_PUBLIC_KEY 与私钥不一致或缺失，已按私钥重新计算");
        }
        let short_id = match self.nonempty("REALITY_SHORT_ID") {
            Some(id) if creds::valid_short_id(id) => id.to_owned(),
            Some(_) => bail!("v2 字段 REALITY_SHORT_ID 无效"),
            None => {
                self.warn("v2 状态缺少 REALITY_SHORT_ID，已生成新值；请更新客户端");
                rng.hex(8)?
            }
        };
        Ok(Some(RealityKeys {
            private_key: private_key.to_owned(),
            public_key,
            short_id,
        }))
    }

    /// `REALITY_SNI` / `REALITY_DEST` / `REALITY_GUARD_PORT` (0 = allocate).
    pub(super) fn reality_target(&mut self) -> Result<RealityTarget> {
        let sni = self.domain_or_default("REALITY_SNI", defaults::REALITY_SNI)?;
        let dest = match self.nonempty("REALITY_DEST") {
            Some(raw) => raw
                .parse::<HostPort>()
                .map_err(|_| Error::msg(format!("v2 字段 REALITY_DEST 无效: {raw}")))?,
            None => defaults::handshake_dest(&sni),
        };
        let guard_port = self.parse_lenient::<u16>("REALITY_GUARD_PORT").unwrap_or(0);
        Ok(RealityTarget {
            sni,
            dest,
            guard_port,
        })
    }

    /// `SHADOWTLS_SNI` / `SHADOWTLS_DEST` (dropped when it is the default target).
    pub(super) fn shadowtls(&mut self) -> Result<ShadowTls> {
        let sni = self.domain_or_default("SHADOWTLS_SNI", defaults::SHADOWTLS_SNI)?;
        let dest = match self.nonempty("SHADOWTLS_DEST") {
            Some(raw) => {
                let dest = raw
                    .parse::<HostPort>()
                    .map_err(|_| Error::msg(format!("v2 字段 SHADOWTLS_DEST 无效: {raw}")))?;
                Some(dest).filter(|d| *d != defaults::handshake_dest(&sni))
            }
            None => None,
        };
        Ok(ShadowTls { sni, dest })
    }

    /// Lower-cased domain value, the default when absent; invalid → error.
    pub(super) fn domain_or_default(&self, key: &str, default: &str) -> Result<String> {
        match self.nonempty(key) {
            Some(raw) => {
                let domain = raw.to_ascii_lowercase();
                ensure!(valid_domain(&domain), "v2 字段 {key} 无效: {raw}");
                Ok(domain)
            }
            None => Ok(default.to_owned()),
        }
    }

    pub(super) fn installed_at(&mut self) -> u64 {
        self.parse_lenient("INSTALLED_AT").unwrap_or(0)
    }
}

fn path(rng: &mut dyn Random) -> Result<String> {
    Ok(format!("/{}", rng.hex(6)?))
}
