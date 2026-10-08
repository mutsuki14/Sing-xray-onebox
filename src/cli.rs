use crate::{
    backup, bbr, cert,
    context::Context,
    diagnostics, frp,
    model::{Core, Protocol, State, PROTOCOLS},
    network, platform, render, runtime, site, state, subscription, ui, update, util, workflow,
    Result, VERSION,
};
use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine,
};
use serde_json::json;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    net::IpAddr,
};

#[derive(Default, Debug)]
struct Options {
    values: BTreeMap<String, String>,
    flags: BTreeSet<String>,
    ports: Vec<(Protocol, u16)>,
}
impl Options {
    fn parse(args: &[String]) -> Result<Self> {
        let mut out = Self::default();
        let mut i = 0;
        while i < args.len() {
            let arg = &args[i];
            let (name, inline) = arg
                .split_once('=')
                .map(|(k, v)| (k, Some(v)))
                .unwrap_or((arg.as_str(), None));
            if [
                "--dry-run",
                "--json",
                "--hy2-obfs",
                "--no-bbr",
                "--apply",
                "--help",
            ]
            .contains(&name)
            {
                if inline.is_some() {
                    return Err(format!("{name} 不接受值").into());
                }
                out.flags.insert(name.into());
            } else if [
                "--preset",
                "--protocols",
                "--core",
                "--sni",
                "--reality-site",
                "--site-title",
                "--site-https",
                "--reality-dest",
                "--tls",
                "--domain",
                "--addr",
                "--name",
                "--port",
                "--hy2-hop",
                "--hy2-core",
                "--xray-version",
                "--singbox-version",
                "--up",
                "--down",
                "--cert",
                "--key",
            ]
            .contains(&name)
            {
                let value = if let Some(v) = inline {
                    v.to_string()
                } else {
                    i += 1;
                    args.get(i)
                        .filter(|v| !v.starts_with("--"))
                        .ok_or_else(|| format!("{name} 需要参数"))?
                        .clone()
                };
                if name == "--port" {
                    let (p, v) = value.split_once('=').ok_or("--port 格式为 协议=端口")?;
                    let port: u16 = v.parse()?;
                    if port == 0 {
                        return Err("端口不能为 0".into());
                    }
                    let p = p.parse()?;
                    if out.ports.iter().any(|(old, _)| *old == p) {
                        return Err("重复指定协议端口".into());
                    }
                    out.ports.push((p, port));
                } else if out.values.insert(name.into(), value).is_some() {
                    return Err(format!("重复选项: {name}").into());
                }
            } else {
                return Err(format!("未知选项: {arg}").into());
            }
            i += 1;
        }
        Ok(out)
    }
    fn get(&self, key: &str) -> Option<&str> {
        self.values.get(key).map(String::as_str)
    }
    fn has(&self, key: &str) -> bool {
        self.flags.contains(key)
    }
}
fn presets(n: u32) -> Result<(Vec<Protocol>, Core)> {
    let (names, core) = match n {
        1 => ("vless-reality hysteria2 tuic", Core::Singbox),
        2 => ("vless-reality vless-xhttp shadowsocks", Core::Xray),
        3 => (
            "vless-reality vless-xhttp hysteria2 tuic anytls",
            Core::Xray,
        ),
        4 => (
            "vless-reality vless-grpc trojan shadowsocks hysteria2 tuic anytls shadowtls vmess-ws",
            Core::Singbox,
        ),
        5 => ("vless-ws vmess-ws", Core::Singbox),
        6 => ("vless-reality", Core::Xray),
        _ => return Err("预设应为 1–7，自定义需要选择协议".into()),
    };
    Ok((
        names
            .split_whitespace()
            .map(str::parse)
            .collect::<Result<_>>()?,
        core,
    ))
}
fn protocol_list(value: &str) -> Result<Vec<Protocol>> {
    let mut out = Vec::new();
    for name in value
        .split(|c: char| c == ',' || c.is_whitespace())
        .filter(|s| !s.is_empty())
    {
        let p = name.parse()?;
        if !out.contains(&p) {
            out.push(p)
        }
    }
    if out.is_empty() {
        return Err("至少选择一种协议".into());
    }
    Ok(PROTOCOLS.into_iter().filter(|p| out.contains(p)).collect())
}
fn protocol_menu(ctx: &Context) -> Result<Vec<Protocol>> {
    for (i, p) in PROTOCOLS.iter().enumerate() {
        println!(
            "  {}) {}{}",
            i + 1,
            p.title(),
            if *p == Protocol::AnytlsReality {
                " (仅 sing-box 完整配置)"
            } else {
                ""
            }
        );
    }
    let answer = ui::ask(ctx, "选择协议编号，以空格或逗号分隔", "1")?;
    let mut selected = Vec::new();
    for number in answer
        .split(|c: char| c == ',' || c.is_whitespace())
        .filter(|s| !s.is_empty())
    {
        let n: usize = number.parse()?;
        selected.push(
            *PROTOCOLS
                .get(n.checked_sub(1).ok_or("编号无效")?)
                .ok_or("编号无效")?,
        )
    }
    protocol_list(
        &selected
            .iter()
            .map(|p| p.as_str())
            .collect::<Vec<_>>()
            .join(" "),
    )
}
fn set_protocols(s: &mut State, list: &[Protocol]) {
    s.set(
        "PROTOCOLS",
        list.iter()
            .map(|p| p.as_str())
            .collect::<Vec<_>>()
            .join(" "),
    );
}
fn plain(value: &str) -> Result<&str> {
    if value.chars().any(char::is_control) {
        Err("参数不能包含控制字符".into())
    } else {
        Ok(value)
    }
}
fn apply_options(s: &mut State, o: &Options) -> Result<()> {
    if o.get("--reality-site").is_some()
        && (o.get("--sni").is_some() || o.get("--reality-dest").is_some())
    {
        return Err("--reality-site 不能与 --sni/--reality-dest 同时指定".into());
    }
    for (key, field) in [
        ("--addr", "SERVER_ADDR"),
        ("--name", "NODE_NAME"),
        ("--domain", "DOMAIN"),
        ("--site-title", "REALITY_SITE_TITLE"),
        ("--hy2-hop", "HY2_HOP"),
        ("--xray-version", "XR_VERSION_WANT"),
        ("--singbox-version", "SB_VERSION_WANT"),
        ("--cert", "CUSTOM_CERT"),
        ("--key", "CUSTOM_KEY"),
    ] {
        if let Some(v) = o.get(key) {
            s.set(field, plain(v)?);
        }
    }
    if let Some(mode) = o.get("--tls") {
        match mode {
            "self" | "custom" => s.set("TLS_MODE", mode),
            "acme" | "http" => {
                s.set("TLS_MODE", "acme");
                s.set("ACME_METHOD", "standalone");
            }
            "cf" => {
                s.set("TLS_MODE", "acme");
                s.set("ACME_METHOD", "cf");
            }
            _ => return Err("--tls 应为 self/acme/cf/custom".into()),
        }
    }
    if let Some(domain) = o.get("--sni") {
        if !util::valid_domain(domain) {
            return Err("REALITY SNI 域名无效".into());
        }
        s.set("REALITY_SNI", domain);
        s.set("REALITY_DEST", format!("{domain}:443"));
        s.set("SHADOWTLS_SNI", domain);
        s.set("SHADOWTLS_DEST", format!("{domain}:443"));
        s.set("REALITY_SITE_ENABLED", 0);
    }
    if let Some(domain) = o.get("--reality-site") {
        if !s.any_reality() || !util::valid_domain(domain) {
            return Err("自建站需要 REALITY 协议及有效域名".into());
        }
        s.set("REALITY_SITE_ENABLED", 1);
        s.set("REALITY_SITE_DOMAIN", domain);
        s.set("REALITY_SNI", domain);
        s.set("REALITY_SITE_HTTPS", 1);
        s.set("REALITY_SITE_PORT", s.number("REALITY_SITE_PORT", 10443));
        s.set(
            "REALITY_DEST",
            format!("127.0.0.1:{}", s.number("REALITY_SITE_PORT", 10443)),
        );
    }
    if let Some(value) = o.get("--site-https") {
        if !s.site_enabled() {
            return Err("--site-https 需要先启用自建站".into());
        }
        s.set(
            "REALITY_SITE_HTTPS",
            match value {
                "on" => "1",
                "off" => "0",
                _ => return Err("--site-https 应为 on/off".into()),
            },
        );
    }
    if let Some(value) = o.get("--reality-dest") {
        let (host, port) = value.rsplit_once(':').ok_or("握手目标格式为 主机:端口")?;
        if host.is_empty() || port.parse::<u16>().ok().filter(|p| *p > 0).is_none() {
            return Err("握手目标无效".into());
        }
        s.set("REALITY_DEST", plain(value)?);
    }
    if o.has("--hy2-obfs") {
        s.set("HY2_OBFS", 1);
    }
    for (p, port) in &o.ports {
        if !s.enabled(*p) {
            return Err(format!("未选择协议: {p}").into());
        }
        s.set_port(*p, *port);
    }
    if let Some(core) = o.get("--hy2-core") {
        let core: Core = core.parse()?;
        if !s.enabled(Protocol::Hysteria2) {
            return Err("未选择 hysteria2".into());
        }
        s.set_core(Protocol::Hysteria2, core);
    }
    Ok(())
}
fn port_available(
    ctx: &Context,
    s: &State,
    p: Protocol,
    port: u16,
    old: Option<&State>,
) -> Result<bool> {
    if port == 0 {
        return Ok(false);
    }
    let udp = p.network() != "tcp";
    let tcp = p.network() != "udp";
    for other in s.protocols() {
        if other == p {
            continue;
        }
        if s.get(&format!("PORT_{}", other.as_str().replace('-', "_")))
            .is_empty()
        {
            continue;
        }
        if s.port(other) == port
            && ((tcp && other.network() != "udp") || (udp && other.network() != "tcp"))
        {
            let shared = matches!(
                (p, other),
                (Protocol::VlessReality, Protocol::VlessXhttp)
                    | (Protocol::VlessXhttp, Protocol::VlessReality)
            ) && s.core(p) == Core::Xray
                && s.core(other) == Core::Xray;
            if !shared {
                return Ok(false);
            }
        }
    }
    if tcp
        && ((s.site_enabled() && [s.number("REALITY_SITE_PORT", 10443), 80].contains(&port))
            || port == s.number("REALITY_GUARD_PORT", 0))
    {
        return Ok(false);
    }
    if tcp && s.site_enabled() && s.flag("REALITY_SITE_HTTPS") && port == 443 && !p.reality() {
        return Ok(false);
    }
    if tcp
        && s.flag("SUBSCRIPTION_ENABLED")
        && matches!(s.get("SUBSCRIPTION_MODE"), "standalone" | "ip")
        && (port == s.number("SUBSCRIPTION_PORT", 8448)
            || (port == 80
                && s.get("SUBSCRIPTION_MODE") == "standalone"
                && s.flag("SUBSCRIPTION_HTTP")))
    {
        return Ok(false);
    }
    for (lo, hi, net) in frp::reserved_ports(ctx)? {
        if port >= lo && port <= hi && ((tcp && net != "udp") || (udp && net != "tcp")) {
            return Ok(false);
        }
    }
    for is_udp in [false, true] {
        if is_udp && !udp || !is_udp && !tcp {
            continue;
        }
        let managed = old.is_some_and(|s| {
            s.protocols().iter().any(|x| {
                s.port(*x) == port
                    && (if is_udp {
                        x.network() != "tcp"
                    } else {
                        x.network() != "udp"
                    })
            })
        });
        let old_site =
            !is_udp && old.is_some_and(|s| s.site_enabled() && site::public_port(s) == port);
        if !managed && !old_site && network::port_in_use(port, is_udp) {
            return Ok(false);
        }
    }
    Ok(true)
}
fn assign_ports(
    ctx: &Context,
    s: &mut State,
    o: &Options,
    old: Option<&State>,
    interactive: bool,
) -> Result<()> {
    for p in s.protocols() {
        let key = format!("PORT_{}", p.as_str().replace('-', "_"));
        if !s.get(&key).is_empty() {
            if !port_available(ctx, s, p, s.port(p), old)? {
                return Err(format!("{p} 端口不可用: {}", s.port(p)).into());
            }
            continue;
        }
        let candidates: &[u16] = match p {
            Protocol::Shadowsocks => &[8388, 8389, 8390],
            Protocol::VmessWs => &[8080, 2082, 8880],
            _ => &[443, 8443, 2053, 2083, 2087, 2096, 9443],
        };
        let mut suggested = None;
        for port in candidates.iter().copied().chain(20000..21000) {
            if port_available(ctx, s, p, port, old)? {
                suggested = Some(port);
                break;
            }
        }
        let port = suggested.ok_or("未找到空闲端口")?;
        if interactive && !o.has("--dry-run") {
            loop {
                let raw = ui::ask(ctx, &format!("{} 端口", p.title()), &port.to_string())?;
                if let Ok(value) = raw.parse::<u16>() {
                    if port_available(ctx, s, p, value, old)? {
                        s.set_port(p, value);
                        break;
                    }
                }
                eprintln!("端口无效或被占用");
            }
        } else {
            s.set_port(p, port);
        }
    }
    Ok(())
}
fn defaults(s: &mut State) {
    for (k, v) in [
        ("NODE_NAME", "onebox"),
        (
            "LISTEN_ADDR",
            if site::ipv6_available() {
                "::"
            } else {
                "0.0.0.0"
            },
        ),
        ("REALITY_SNI", "www.microsoft.com"),
        ("REALITY_DEST", "www.microsoft.com:443"),
        ("SHADOWTLS_SNI", "www.microsoft.com"),
        ("TLS_SNI", "www.bing.com"),
        ("SS_METHOD", "2022-blake3-aes-128-gcm"),
        ("BLOCK_PRIVATE", "1"),
        ("BLOCK_BT", "1"),
        ("RESOURCE_PROFILE", "balanced"),
        ("REALITY_SITE_TITLE", "山间手记"),
    ] {
        if s.get(k).is_empty() {
            s.set(k, v)
        }
    }
    if s.needs_cert() && s.get("TLS_MODE").is_empty() {
        s.set("TLS_MODE", "self")
    }
}
fn credentials(ctx: &Context, s: &mut State, reset: bool) -> Result<()> {
    if reset {
        for k in [
            "UUID",
            "PASSWORD",
            "SS_PASSWORD",
            "REALITY_PRIVATE_KEY",
            "REALITY_PUBLIC_KEY",
            "REALITY_SHORT_ID",
            "HY2_OBFS_PASSWORD",
            "SHADOWTLS_PASSWORD",
            "SHADOWTLS_SS_PASSWORD",
            "CLASH_SECRET",
        ] {
            s.values.remove(k);
        }
    }
    if s.get("UUID").is_empty() {
        let mut v = util::random_hex(16)?.into_bytes();
        v[12] = b'4';
        v[16] = b'8';
        let v = String::from_utf8(v)?;
        s.set(
            "UUID",
            format!(
                "{}-{}-{}-{}-{}",
                &v[..8],
                &v[8..12],
                &v[12..16],
                &v[16..20],
                &v[20..]
            ),
        );
    }
    for (k, n) in [
        ("PASSWORD", 20),
        ("HY2_OBFS_PASSWORD", 16),
        ("SHADOWTLS_PASSWORD", 20),
        ("CLASH_SECRET", 24),
        ("REALITY_SHORT_ID", 8),
    ] {
        if s.get(k).is_empty() {
            s.set(k, util::random_hex(n)?);
        }
    }
    for (k, bytes) in [
        (
            "SS_PASSWORD",
            if s.get("SS_METHOD").contains("256") || s.get("SS_METHOD").contains("chacha") {
                32
            } else {
                16
            },
        ),
        ("SHADOWTLS_SS_PASSWORD", 16),
    ] {
        if s.get(k).is_empty() {
            let hex = util::random_hex(bytes)?;
            let data = (0..hex.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&hex[i..i + 2], 16))
                .collect::<std::result::Result<Vec<_>, _>>()?;
            s.set(k, STANDARD.encode(data));
        }
    }
    for k in ["WS_PATH", "VMESS_PATH", "XHTTP_PATH", "GRPC_SERVICE"] {
        if s.get(k).is_empty() {
            s.set(
                k,
                format!(
                    "{}{}",
                    if k == "GRPC_SERVICE" { "" } else { "/" },
                    util::random_hex(6)?
                ),
            );
        }
    }
    if s.any_reality() && s.get("REALITY_PRIVATE_KEY").is_empty() {
        let dir = std::env::temp_dir().join(format!("onebox-key-{}", util::random_hex(12)?));
        fs::create_dir(&dir)?;
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))?;
        let result = (|| -> Result<()> {
            let private = dir.join("key.pem");
            let private_der = dir.join("key.der");
            let public_der = dir.join("public.der");
            ctx.run(
                "openssl",
                &[
                    "genpkey",
                    "-algorithm",
                    "X25519",
                    "-out",
                    util::path_str(&private)?,
                ],
            )?;
            ctx.run(
                "openssl",
                &[
                    "pkey",
                    "-in",
                    util::path_str(&private)?,
                    "-outform",
                    "DER",
                    "-out",
                    util::path_str(&private_der)?,
                ],
            )?;
            ctx.run(
                "openssl",
                &[
                    "pkey",
                    "-in",
                    util::path_str(&private)?,
                    "-pubout",
                    "-outform",
                    "DER",
                    "-out",
                    util::path_str(&public_der)?,
                ],
            )?;
            let key = fs::read(private_der)?;
            let public = fs::read(public_der)?;
            if key.len() < 32 || public.len() < 32 {
                return Err("生成 X25519 密钥失败".into());
            }
            s.set(
                "REALITY_PRIVATE_KEY",
                URL_SAFE_NO_PAD.encode(&key[key.len() - 32..]),
            );
            s.set(
                "REALITY_PUBLIC_KEY",
                URL_SAFE_NO_PAD.encode(&public[public.len() - 32..]),
            );
            Ok(())
        })();
        let _ = fs::remove_dir_all(dir);
        result?;
    }
    if s.get("REALITY_GUARD_PORT").is_empty() {
        let reserved = frp::reserved_ports(ctx)?;
        let p = (18000..20000)
            .find(|p| {
                !network::port_in_use(*p, false)
                    && !s.protocols().iter().any(|x| s.port(*x) == *p)
                    && !reserved
                        .iter()
                        .any(|(lo, hi, net)| *p >= *lo && *p <= *hi && net != "udp")
                    && !(s.site_enabled()
                        && [
                            80,
                            site::public_port(s),
                            s.number("REALITY_SITE_PORT", 10443),
                        ]
                        .contains(p))
                    && !(s.flag("SUBSCRIPTION_ENABLED")
                        && matches!(s.get("SUBSCRIPTION_MODE"), "standalone" | "ip")
                        && *p == s.number("SUBSCRIPTION_PORT", 8448))
            })
            .ok_or("没有空闲的 REALITY guard 端口")?;
        s.set("REALITY_GUARD_PORT", p);
    }
    Ok(())
}
fn detect_address(ctx: &Context, s: &mut State) -> Result<()> {
    if !s.get("SERVER_ADDR").is_empty() {
        let value = s.get("SERVER_ADDR").to_string();
        if let Ok(ip) = value.parse::<IpAddr>() {
            s.set(
                if ip.is_ipv4() {
                    "SERVER_IPV4"
                } else {
                    "SERVER_IPV6"
                },
                ip,
            );
        } else if !util::valid_domain(&value) {
            return Err("服务器地址应为 IP 或域名".into());
        }
        return Ok(());
    }
    for (family, endpoint, key) in [
        ("-4", "https://api.ipify.org", "SERVER_IPV4"),
        ("-6", "https://api6.ipify.org", "SERVER_IPV6"),
    ] {
        if let Ok(out) = ctx.run("curl", &["-fsS", family, "--max-time", "8", endpoint]) {
            if let Ok(ip) = out.trim().parse::<IpAddr>() {
                s.set(key, ip);
            }
        }
    }
    let default = s.get_or("SERVER_IPV4", s.get("SERVER_IPV6")).to_string();
    let value = if ui::interactive(ctx) {
        ui::ask(ctx, "客户端连接的公网 IP 或域名", &default)?
    } else {
        default
    };
    if value.is_empty() {
        return Err("无法检测公网地址，请使用 --addr 指定".into());
    }
    s.set("SERVER_ADDR", value);
    detect_address(ctx, s)
}
fn choose_reality(ctx: &Context, s: &mut State, o: &Options) -> Result<()> {
    if !s.any_reality()
        || o.get("--sni").is_some()
        || o.get("--reality-site").is_some()
        || !ui::interactive(ctx)
    {
        return Ok(());
    }
    println!("REALITY 目标：1) Microsoft  2) Apple  3) 自定义域名  4) 自有域名一键建站");
    match ui::choose(ctx, "选择目标", 1, 1, 4)? {
        1 => {
            s.set("REALITY_SNI", "www.microsoft.com");
            s.set("REALITY_DEST", "www.microsoft.com:443");
            s.set("REALITY_SITE_ENABLED", 0);
        }
        2 => {
            s.set("REALITY_SNI", "www.apple.com");
            s.set("REALITY_DEST", "www.apple.com:443");
            s.set("REALITY_SITE_ENABLED", 0);
        }
        3 => {
            let name = ui::ask(ctx, "握手域名", s.get("REALITY_SNI"))?;
            if !util::valid_domain(&name) {
                return Err("域名无效".into());
            }
            s.set("REALITY_DEST", format!("{name}:443"));
            s.set("REALITY_SNI", name);
            s.set("REALITY_SITE_ENABLED", 0);
        }
        4 => {
            let name = ui::ask(ctx, "已解析到本机的自有域名", s.get("REALITY_SITE_DOMAIN"))?;
            let mut options = Options::default();
            options.values.insert("--reality-site".into(), name);
            apply_options(s, &options)?;
            let title = ui::ask(ctx, "网站标题", s.get_or("REALITY_SITE_TITLE", "山间手记"))?;
            s.set("REALITY_SITE_TITLE", title);
            s.set(
                "REALITY_SITE_HTTPS",
                if ui::confirm(ctx, "开启网站 HTTPS 443 入口?", true)? {
                    "1"
                } else {
                    "0"
                },
            );
        }
        _ => unreachable!(),
    }
    Ok(())
}
fn build_install(ctx: &Context, args: &[String], dry: bool) -> Result<State> {
    let o = Options::parse(args)?;
    let (list, default_core) = if let Some(value) = o.get("--protocols") {
        (protocol_list(value)?, Core::Singbox)
    } else {
        let preset = if let Some(v) = o.get("--preset") {
            v.parse()?
        } else if !dry && ui::interactive(ctx) {
            println!("1) Reality+Hy2+TUIC  2) Xray经典  3) 双内核  4) sing-box全家桶  5) CDN  6) 仅Reality  7) 自定义");
            ui::choose(ctx, "选择组合", 1, 1, 7)?
        } else {
            1
        };
        if preset == 7 {
            if dry || !ui::interactive(ctx) {
                return Err("自定义预设需要 --protocols".into());
            }
            (protocol_menu(ctx)?, Core::Singbox)
        } else {
            presets(preset)?
        }
    };
    let core = o
        .get("--core")
        .map(str::parse)
        .transpose()?
        .unwrap_or(default_core);
    let mut s = State::default();
    set_protocols(&mut s, &list);
    for p in list {
        s.set_core(
            p,
            if p == Protocol::Hysteria2 {
                Core::Singbox
            } else if p.cores().contains(&core) {
                core
            } else {
                p.cores()[0]
            },
        );
    }
    defaults(&mut s);
    apply_options(&mut s, &o)?;
    if !dry {
        choose_reality(ctx, &mut s, &o)?;
        if o.get("--tls").is_none()
            && ui::interactive(ctx)
            && (s.needs_cert() || s.enabled(Protocol::VmessWs))
        {
            let mut values = certificate_options(ctx, true)?;
            if values.get(1).is_some_and(|mode| mode != "self") {
                values.extend(words(&[
                    "--domain",
                    &ui::ask(ctx, "代理证书域名", s.get("DOMAIN"))?,
                ]));
            }
            apply_options(&mut s, &Options::parse(&values)?)?;
        }
        detect_address(ctx, &mut s)?;
        credentials(ctx, &mut s, false)?;
    }
    let old = if state::installed(ctx) {
        Some(state::load(ctx)?)
    } else {
        None
    };
    assign_ports(ctx, &mut s, &o, old.as_ref(), !dry && ui::interactive(ctx))?;
    if s.enabled(Protocol::VmessWs) {
        s.set(
            "VMESS_TLS",
            if matches!(s.get("TLS_MODE"), "acme" | "custom") {
                1
            } else {
                0
            },
        );
    }
    state::attach_expected(ctx, &mut s)?;
    s.validate()?;
    Ok(s)
}
fn plan(ctx: &Context, args: &[String]) -> Result<()> {
    let s = build_install(ctx, args, true)?;
    let rows=s.protocols().iter().map(|p|json!({"protocol":p.as_str(),"core":s.core(*p).as_str(),"port":s.port(*p),"network":p.network()})).collect::<Vec<_>>();
    if args.iter().any(|s| s == "--json") {
        println!(
            "{}",
            serde_json::to_string_pretty(
                &json!({"dry_run":true,"protocols":rows,"site":s.site_enabled(),"directory":ctx.paths.root})
            )?
        );
    } else {
        println!("只读安装预演（未写文件、下载内核或申请证书）");
        for p in s.protocols() {
            println!("{} | {} | {}/{}", p, s.core(p), s.port(p), p.network());
        }
        println!("配置目录: {}", ctx.paths.root.display());
        if s.site_enabled() {
            println!(
                "网站: {}，申请正式证书，HTTPS 443: {}",
                s.get("REALITY_SITE_DOMAIN"),
                s.flag("REALITY_SITE_HTTPS")
            );
        }
    }
    Ok(())
}
fn info(ctx: &Context) -> Result<()> {
    let s = state::load(ctx)?;
    println!("Onebox {VERSION}  地址: {}", s.get("SERVER_ADDR"));
    for p in s.protocols() {
        let clients = ["singbox", "xray", "mihomo", "link"]
            .into_iter()
            .filter(|c| p.supports(c))
            .collect::<Vec<_>>()
            .join(", ");
        println!(
            "{}  {}:{}  {}  客户端: {}",
            p.title(),
            p.network(),
            s.port(p),
            s.core(p),
            clients
        );
    }
    if s.any_reality() {
        println!(
            "REALITY SNI: {}  公钥: {}  ShortID: {}",
            s.get("REALITY_SNI"),
            s.get("REALITY_PUBLIC_KEY"),
            s.get("REALITY_SHORT_ID")
        );
    }
    println!("UUID: {}\n密码: {}", s.get("UUID"), s.get("PASSWORD"));
    if s.enabled(Protocol::AnytlsReality) {
        println!("AnyTLS-REALITY 请使用 sing-box 完整配置或远程配置订阅。");
    }
    println!("配置目录: {}\n导出: onebox client singbox | mihomo | links\n订阅: onebox subscription info",ctx.paths.clients().display());
    Ok(())
}
fn choose_enabled(ctx: &Context, s: &State, p: Option<&String>) -> Result<Protocol> {
    if let Some(p) = p {
        let p = p.parse()?;
        if !s.enabled(p) {
            return Err("协议未启用".into());
        }
        return Ok(p);
    }
    let list = s.protocols();
    for (i, p) in list.iter().enumerate() {
        println!("{}) {}", i + 1, p.title())
    }
    let n = ui::choose(ctx, "选择协议", 1, 1, list.len() as u32)?;
    Ok(list[n as usize - 1])
}
fn modify(ctx: &Context, action: &str, args: &[String]) -> Result<()> {
    let old = state::load(ctx)?;
    let mut s = old.clone();
    match action {
        "add" => {
            let p = if let Some(value) = args.first().filter(|s| !s.starts_with('-')) {
                value.parse()?
            } else {
                let selected = protocol_menu(ctx)?;
                if selected.len() != 1 {
                    return Err("添加操作请只选择一个协议".into());
                }
                selected[0]
            };
            if s.enabled(p) {
                return Err("协议已存在".into());
            }
            let rest = if args.first().is_some_and(|a| !a.starts_with('-')) {
                &args[1..]
            } else {
                args
            };
            let o = Options::parse(rest)?;
            let prefer = o
                .get("--core")
                .map(str::parse)
                .transpose()?
                .unwrap_or(s.core(old.protocols()[0]));
            let mut list = s.protocols();
            list.push(p);
            set_protocols(&mut s, &list);
            s.set_core(
                p,
                if p == Protocol::Hysteria2 {
                    Core::Singbox
                } else if p.cores().contains(&prefer) {
                    prefer
                } else {
                    p.cores()[0]
                },
            );
            defaults(&mut s);
            apply_options(&mut s, &o)?;
            if p.reality() && !old.any_reality() {
                choose_reality(ctx, &mut s, &o)?
            }
            credentials(ctx, &mut s, false)?;
            assign_ports(ctx, &mut s, &o, Some(&old), ui::interactive(ctx))?;
        }
        "del" | "remove" => {
            let p = choose_enabled(ctx, &s, args.first())?;
            if s.protocols().len() <= 1 {
                return Err("至少保留一个协议；全部删除请使用 uninstall".into());
            }
            let list = s
                .protocols()
                .into_iter()
                .filter(|x| *x != p)
                .collect::<Vec<_>>();
            set_protocols(&mut s, &list);
            for key in ["PORT_", "CORE_"] {
                s.values
                    .remove(&format!("{key}{}", p.as_str().replace('-', "_")));
            }
            if !s.any_reality() {
                s.set("REALITY_SITE_ENABLED", 0);
            }
        }
        "port" => {
            let p = choose_enabled(ctx, &s, args.first())?;
            let raw = if let Some(v) = args.get(1) {
                v.clone()
            } else {
                ui::ask(ctx, "新端口", &s.port(p).to_string())?
            };
            let port = raw.parse()?;
            if !port_available(ctx, &s, p, port, Some(&old))? {
                return Err("端口无效或被占用".into());
            }
            s.set_port(p, port);
        }
        "addr" => {
            if args.first().is_some_and(|s| s.starts_with('-')) {
                apply_options(&mut s, &Options::parse(args)?)?;
            } else {
                let address = ui::ask(ctx, "连接 IP 或域名", s.get("SERVER_ADDR"))?;
                s.set("SERVER_ADDR", address);
                let name = ui::ask(ctx, "节点名称", s.get("NODE_NAME"))?;
                s.set("NODE_NAME", name);
            }
            detect_address(ctx, &mut s)?;
        }
        "reset" => {
            if !ui::confirm(ctx, "重置全部节点凭据？客户端需要更新配置或订阅", false)?
            {
                return Ok(());
            }
            credentials(ctx, &mut s, true)?;
        }
        "sni" => {
            let o = Options::parse(args)?;
            if !s.any_reality() && !s.enabled(Protocol::Shadowtls) {
                return Err("没有启用 REALITY 或 ShadowTLS".into());
            }
            apply_options(&mut s, &o)?;
            choose_reality(ctx, &mut s, &o)?;
            if s.enabled(Protocol::Shadowtls) && o.get("--sni").is_none() {
                let name = ui::ask(ctx, "ShadowTLS 握手域名", s.get("SHADOWTLS_SNI"))?;
                if !util::valid_domain(&name) {
                    return Err("域名无效".into());
                }
                s.set("SHADOWTLS_SNI", name);
            }
        }
        "regen" => {}
        _ => return Err("未知变更".into()),
    }
    workflow::apply(ctx, &s)?;
    println!("配置已更新");
    if action == "add" && s.enabled(Protocol::AnytlsReality) {
        println!("AnyTLS-REALITY: onebox client singbox，或使用 sing-box 远程配置订阅");
    }
    Ok(())
}
fn tune(ctx: &Context, args: &[String]) -> Result<()> {
    let mut s = state::load(ctx)?;
    let action = args.first().map(String::as_str).unwrap_or("status");
    if action == "status" {
        for k in [
            "HY2_PROFILE",
            "HY2_UP_MBPS",
            "HY2_DOWN_MBPS",
            "RESOURCE_PROFILE",
        ] {
            println!("{k}={}", s.get(k));
        }
        return Ok(());
    }
    let o = Options::parse(if action == "reset" {
        &args[1..]
    } else {
        args.get(2..).unwrap_or(&[])
    })?;
    match action {
        "hy2" => {
            let mode = args.get(1).ok_or("需要 auto/conservative/measured")?;
            if !["auto", "conservative", "measured"].contains(&mode.as_str()) {
                return Err("Hy2 档位无效".into());
            }
            s.set("HY2_PROFILE", mode);
            for (flag, key) in [("--up", "HY2_UP_MBPS"), ("--down", "HY2_DOWN_MBPS")] {
                if let Some(value) = o.get(flag) {
                    let n: f64 = value.parse()?;
                    if !n.is_finite() || n <= 0.0 || n > 100000.0 {
                        return Err("带宽值无效".into());
                    }
                    s.set(key, value);
                }
            }
            if mode == "measured"
                && (s.get("HY2_UP_MBPS").is_empty() || s.get("HY2_DOWN_MBPS").is_empty())
            {
                return Err("measured 需要 --up 和 --down".into());
            }
        }
        "resource" => {
            let mode = args.get(1).ok_or("需要 balanced/low-memory/throughput")?;
            if !["balanced", "low-memory", "throughput"].contains(&mode.as_str()) {
                return Err("资源档位无效".into());
            }
            s.set("RESOURCE_PROFILE", mode);
        }
        "reset" => {
            for key in ["HY2_PROFILE", "HY2_UP_MBPS", "HY2_DOWN_MBPS"] {
                s.values.remove(key);
            }
            s.set("RESOURCE_PROFILE", "balanced");
        }
        _ => return Err("用法: tune status|hy2|resource|reset".into()),
    }
    println!(
        "调优预览: HY2={} up={} down={} resource={}",
        s.get("HY2_PROFILE"),
        s.get("HY2_UP_MBPS"),
        s.get("HY2_DOWN_MBPS"),
        s.get("RESOURCE_PROFILE")
    );
    if o.has("--apply") {
        workflow::apply(ctx, &s)?
    } else {
        println!("添加 --apply 才会应用")
    }
    Ok(())
}
fn proxy_service(ctx: &Context, action: &str) -> Result<()> {
    let s = state::load(ctx)?;
    for core in [Core::Singbox, Core::Xray] {
        if s.uses(core) {
            if action == "status" {
                println!(
                    "{}: {}",
                    core,
                    if platform::running(ctx, core.service()) {
                        "运行中"
                    } else {
                        "已停止"
                    }
                );
            } else {
                platform::service(ctx, core.service(), action)?;
            }
        }
    }
    Ok(())
}
fn uninstall(ctx: &Context) -> Result<()> {
    state::load(ctx)?;
    if !ui::confirm(
        ctx,
        "卸载代理服务和配置？FRP 保持独立管理，网站内容与备份将保留",
        false,
    )? {
        return Ok(());
    }
    let _ = backup::create(ctx, "before-uninstall")?;
    let _lock = crate::transaction::acquire(ctx)?;
    if crate::transaction::load(ctx)?.is_some() {
        return Err("存在未完成事务，请先执行 recover".into());
    }
    for name in crate::transaction::SERVICES {
        platform::service(ctx, name, "remove")?;
    }
    network::clear(ctx)?;
    for target in ["proxy", "site", "subscription"] {
        site::cron(ctx, target, false)?;
    }
    for core in [Core::Singbox, Core::Xray] {
        for path in [ctx.paths.core_bin(core), ctx.paths.core_config(core)] {
            if path.exists() {
                fs::remove_file(path)?
            }
        }
    }
    for path in [ctx.paths.state(), ctx.paths.legacy_state()] {
        if path.exists() {
            fs::remove_file(path)?
        }
    }
    for path in [ctx.paths.clients(), ctx.paths.root.join("subscription")] {
        if path.exists() {
            util::safe_path(&path)?;
            fs::remove_dir_all(path)?;
        }
    }
    println!("代理已卸载，网站内容和备份保留于原目录；FRP 可用 onebox frps 管理");
    Ok(())
}
fn help() {
    println!("Onebox v{VERSION} — Rust 原生管理程序\n\n用法: onebox [命令] [选项]\n  install | plan [--protocols 列表 --core singbox|xray --addr IP或域名 --port 协议=端口]\n  add 协议 | del 协议 | port 协议 端口 | addr | reset | sni | regen\n  info | client mihomo|provider|singbox|singbox-notun|xray|links|sub|qr\n  subscription enable|info|add 名称|revoke ID|reset ID|disable\n  subscription enable --mode ip --address IP [--port 8448]（HTTP，无需域名）\n  site info|https|template|title|import|restore|preview|renew\n  cert status|set|renew | cert-renew proxy|site|subscription\n  start|stop|restart|status|log | update [singbox|xray] [版本]\n  update-script|update-check|update-channel [stable|testing]\n  backup [标签] | backups | restore ID|latest | recover | doctor | support\n  bbr | frps | tune | probe | bench | failover | reality-check\n  uninstall | version | help\n\n通用选项: -y/--yes 使用明确的默认值；EOF 取消操作。\nREALITY选项: --sni 域名 或 --reality-site 自有域名 [--site-https on|off]\n证书选项: --tls self|acme|cf|custom --domain 域名 [--cert 文件 --key 文件]\n协议: {}",PROTOCOLS.iter().map(|p|p.as_str()).collect::<Vec<_>>().join(", "));
}
fn words(values: &[&str]) -> Vec<String> {
    values.iter().map(|v| (*v).to_owned()).collect()
}
fn certificate_options(ctx: &Context, proxy: bool) -> Result<Vec<String>> {
    let choices = if proxy {
        "self / acme / cf / custom"
    } else {
        "http / cf / custom"
    };
    let method = ui::ask(
        ctx,
        &format!("证书方式 {choices}"),
        if proxy { "self" } else { "http" },
    )?;
    let mut args = words(&["--tls", &method]);
    if method == "custom" {
        args.extend(words(&[
            "--cert",
            &ui::ask(ctx, "完整证书链路径", "")?,
            "--key",
            &ui::ask(ctx, "私钥路径", "")?,
        ]));
    }
    Ok(args)
}
fn cert_change(ctx: &Context, args: &[String]) -> Result<()> {
    let mut s = state::load(ctx)?;
    let values = if args.is_empty() {
        let mut values = certificate_options(ctx, true)?;
        if values.get(1).is_some_and(|m| m != "self") {
            values.extend(words(&[
                "--domain",
                &ui::ask(ctx, "证书域名", s.get("DOMAIN"))?,
            ]));
        }
        values
    } else {
        args.to_vec()
    };
    let options = Options::parse(&values)?;
    if options.get("--tls").is_none() {
        return Err("cert set 需要 --tls self|acme|cf|custom".into());
    }
    apply_options(&mut s, &options)?;
    if s.enabled(Protocol::VmessWs) {
        s.set(
            "VMESS_TLS",
            if matches!(s.get("TLS_MODE"), "acme" | "custom") {
                1
            } else {
                0
            },
        );
    }
    if !s.needs_cert() {
        return Err("当前协议无需代理 TLS 证书，自建站证书请使用 site 管理".into());
    }
    workflow::apply(ctx, &s)
}
fn subscription_menu(ctx: &Context) -> Result<Vec<String>> {
    println!("1) 查看设备  2) 启用/配置  3) 新建设备  4) 撤销设备\n5) 重置设备链接  6) 关闭订阅  7) 重新发布  0) 返回");
    let n = ui::choose(ctx, "订阅操作", 0, 0, 7)?;
    let mut args = words(&["subscription"]);
    match n {
        0 => return Ok(vec![]),
        1 => args.push("info".into()),
        2 => {
            let s = state::load(ctx)?;
            let mode = loop {
                let value = ui::ask(
                    ctx,
                    "托管方式 ip(IP直连 HTTP) / site(复用自建站 HTTPS) / standalone(独立域名 HTTPS)",
                    if s.site_enabled() { "site" } else { "ip" },
                )?;
                if matches!(value.as_str(), "ip" | "standalone")
                    || value == "site" && s.site_enabled()
                {
                    break value;
                }
                eprintln!("请选择 ip、standalone，或已启用自建站时选择 site。");
            };
            args.extend(words(&["enable", "--mode", &mode]));
            if mode == "ip" {
                eprintln!("HTTP 不加密订阅内容和令牌；需要加密传输时请选择 HTTPS 托管方式。");
                args.extend(words(&[
                    "--address",
                    &ui::ask(
                        ctx,
                        "订阅 IP（IPv4 或 IPv6，无需方括号）",
                        &subscription::default_address(&s).unwrap_or_default(),
                    )?,
                    "--port",
                    &ui::ask(ctx, "HTTP 订阅端口", "8448")?,
                ]));
            } else if mode == "standalone" {
                args.extend(words(&[
                    "--domain",
                    &ui::ask(ctx, "订阅域名（已解析到本机）", "")?,
                    "--port",
                    &ui::ask(ctx, "HTTPS 端口", "8448")?,
                ]));
                args.extend(certificate_options(ctx, false)?);
            }
        }
        3 => args.extend(words(&["add", &ui::ask(ctx, "设备名称", "phone")?])),
        4 | 5 => {
            subscription::command(ctx, &words(&["info"]))?;
            args.extend(words(&[
                if n == 4 { "revoke" } else { "reset" },
                &ui::ask(ctx, "设备 ID", "")?,
            ]));
        }
        6 => args.push("disable".into()),
        _ => args.push("publish".into()),
    }
    Ok(args)
}
fn website_menu(ctx: &Context) -> Result<Vec<String>> {
    println!("1) 查看  2) 启用  3) 关闭  4) HTTPS 443 入口\n5) 更换模板  6) 修改标题  7) 导入网站  8) 恢复内容  9) 续期证书  0) 返回");
    let n = ui::choose(ctx, "网站操作", 0, 0, 9)?;
    let mut args = words(&["site"]);
    match n {
        0 => return Ok(vec![]),
        1 => args.push("info".into()),
        2 => {
            args.extend(words(&[
                "enable",
                &ui::ask(ctx, "网站域名（已解析到本机）", "")?,
            ]));
            args.extend(certificate_options(ctx, false)?);
        }
        3 => args.push("disable".into()),
        4 => args.extend(words(&[
            "https",
            &ui::ask(ctx, "开启 on / 关闭 off", "on")?,
        ])),
        5 => args.extend(words(&[
            "template",
            &ui::ask(ctx, "模板 minimal / profile / docs", "minimal")?,
        ])),
        6 => args.extend(words(&["title", &ui::ask(ctx, "网站标题", "山间手记")?])),
        7 => args.extend(words(&["import", &ui::ask(ctx, "本地网站目录", "")?])),
        8 => args.extend(words(&[
            "restore",
            &ui::ask(ctx, "网站备份 ID 或 latest", "latest")?,
        ])),
        _ => args.push("renew".into()),
    }
    Ok(args)
}
fn performance_menu(ctx: &Context) -> Result<Vec<String>> {
    println!("1) 当前配置  2) Hy2 自动  3) Hy2 保守  4) Hy2 指定带宽\n5) 资源配置  6) 重置调优  7) 连通性探测  8) 测速  9) 故障切换演练  10) REALITY 检查  0) 返回");
    let n = ui::choose(ctx, "性能操作", 0, 0, 10)?;
    let mut args = match n {
        0 => return Ok(vec![]),
        1 => words(&["tune", "status"]),
        2 => words(&["tune", "hy2", "auto"]),
        3 => words(&["tune", "hy2", "conservative"]),
        4 => words(&[
            "tune",
            "hy2",
            "measured",
            "--up",
            &ui::ask(ctx, "上传 Mbps", "100")?,
            "--down",
            &ui::ask(ctx, "下载 Mbps", "100")?,
        ]),
        5 => words(&[
            "tune",
            "resource",
            &ui::ask(ctx, "balanced / low-memory / throughput", "balanced")?,
        ]),
        6 => words(&["tune", "reset"]),
        7 => {
            println!("1) 导出本机探测配置  2) 查看配置入口  3) 合并多份配置  0) 返回");
            match ui::choose(ctx, "探测配置操作", 0, 0, 3)? {
                0 => return Ok(vec![]),
                1 => words(&[
                    "probe",
                    "export",
                    &ui::ask(ctx, "导出到新文件（不可已存在）", "probe-export.json")?,
                ]),
                2 => words(&[
                    "probe",
                    "list",
                    &ui::ask(ctx, "探测配置文件", "probe.json")?,
                ]),
                _ => {
                    let mut args = words(&[
                        "probe",
                        "merge",
                        &ui::ask(ctx, "合并到新文件（不可已存在）", "combined.json")?,
                    ]);
                    let count = ui::choose(ctx, "要合并的文件数", 2, 2, 8)?;
                    for index in 1..=count {
                        args.push(ui::ask(
                            ctx,
                            &format!("第 {index} 份探测配置文件"),
                            &format!("server-{index}.json"),
                        )?);
                    }
                    args
                }
            }
        }
        8 | 9 => {
            let local = ctx.paths.clients().join("probe.json");
            let default = if local.is_file() {
                local.to_string_lossy().into_owned()
            } else {
                "probe.json".into()
            };
            let mut args = words(&[
                if n == 8 { "bench" } else { "failover" },
                &ui::ask(ctx, "探测配置文件", &default)?,
                "--url",
                &ui::ask(
                    ctx,
                    "HTTPS 健康检测地址（应返回 2xx）",
                    "https://www.gstatic.com/generate_204",
                )?,
            ]);
            let entries = ui::ask(ctx, "入口 ID（逗号分隔，留空自动选择）", "")?;
            if !entries.is_empty() {
                args.extend(words(&["--entries", &entries]));
            }
            if n == 8 {
                args.extend(words(&[
                    "--samples",
                    &ui::choose(ctx, "健康检测次数", 5, 1, 20)?.to_string(),
                ]));
                for (flag, prompt) in [
                    ("--download-url", "下载测速 HTTPS 地址（留空跳过）"),
                    ("--upload-url", "已授权上传测速的 HTTPS 地址（留空跳过）"),
                    ("--output", "报告保存到新文件（留空打印到终端）"),
                ] {
                    let value = ui::ask(ctx, prompt, "")?;
                    if !value.is_empty() {
                        args.extend(words(&[flag, &value]));
                    }
                }
            } else {
                println!("仅监听本机 SOCKS5 TCP；连续检测失败才切换，Ctrl+C 结束。");
                for (flag, prompt, default, min, max) in [
                    ("--port", "本机 SOCKS5 端口", 2080, 1024, 65535),
                    ("--interval", "健康检测间隔（秒）", 15, 1, 3600),
                    ("--failures", "切换前连续失败次数", 3, 1, 20),
                    ("--recoveries", "恢复前连续成功次数", 3, 1, 20),
                    ("--cooldown", "恢复冷却期（秒）", 60, 0, 3600),
                ] {
                    args.extend(words(&[
                        flag,
                        &ui::choose(ctx, prompt, default, min, max)?.to_string(),
                    ]));
                }
            }
            args
        }
        _ => words(&["reality-check"]),
    };
    if (2..=6).contains(&n) && ui::confirm(ctx, "应用此调优配置？", true)? {
        args.push("--apply".into());
    }
    Ok(args)
}
fn menu(ctx: &Context) -> Result<()> {
    loop {
        println!("\nOnebox {VERSION}\n1) 安装/重装  2) 节点信息  3) 客户端配置  4) 添加协议\n5) 删除协议  6) 修改端口  7) 服务状态  8) 重启服务\n9) 更新内核  10) 订阅管理  11) 网站管理  12) FRP\n13) BBR  14) 体检  15) 快照备份  16) 更新程序\n17) 修改连接地址  18) 重置凭据  19) REALITY 目标  20) TLS 证书\n21) 性能与连通性  22) 恢复备份  23) 查看日志  24) 服务启停\n25) 更新渠道  26) 重新生成配置  27) 故障恢复  28) 卸载  0) 退出");
        let n = ui::choose(ctx, "请选择", 0, 0, 28)?;
        if n == 0 {
            return Ok(());
        }
        let result = (|| -> Result<()> {
            let command = match n {
                1 => words(&["install"]),
                2 => words(&["info"]),
                3 => words(&["client"]),
                4 => words(&["add"]),
                5 => words(&["del"]),
                6 => words(&["port"]),
                7 => words(&["status"]),
                8 => words(&["restart"]),
                9 => words(&["update"]),
                10 => subscription_menu(ctx)?,
                11 => website_menu(ctx)?,
                12 => words(&["frps"]),
                13 => words(&["bbr"]),
                14 => words(&["doctor"]),
                15 => words(&["backup"]),
                16 => words(&["update-script"]),
                17 => words(&["addr"]),
                18 => words(&["reset"]),
                19 => words(&["sni"]),
                20 => {
                    println!("1) 查看证书  2) 更换代理证书  3) 续期证书  0) 返回");
                    match ui::choose(ctx, "证书操作", 0, 0, 3)? {
                        0 => vec![],
                        1 => words(&["cert", "status"]),
                        2 => words(&["cert", "set"]),
                        _ => words(&["cert", "renew"]),
                    }
                }
                21 => performance_menu(ctx)?,
                22 => {
                    backup::list(ctx)?;
                    words(&["restore", &ui::ask(ctx, "备份 ID 或 latest", "latest")?])
                }
                23 => words(&["log", &ui::ask(ctx, "内核 singbox / xray", "singbox")?]),
                24 => words(&[&ui::ask(ctx, "启动 start / 停止 stop", "start")?]),
                25 => words(&[
                    "update-channel",
                    &ui::ask(ctx, "stable / testing", "stable")?,
                ]),
                26 => words(&["regen"]),
                27 => words(&["recover"]),
                _ => words(&["uninstall"]),
            };
            if command.is_empty() {
                Ok(())
            } else {
                dispatch(ctx, &command)
            }
        })();
        if let Err(e) = result {
            if e.downcast_ref::<ui::Cancelled>().is_some()
                || e.downcast_ref::<crate::ExitError>().is_some()
            {
                return Err(e);
            }
            eprintln!("错误: {e}");
        }
    }
}
pub fn dispatch(ctx: &Context, args: &[String]) -> Result<()> {
    if args.is_empty() {
        return menu(ctx);
    }
    let command = args[0].as_str();
    let rest = &args[1..];
    if ["help", "--help", "-h"].contains(&command) {
        help();
        return Ok(());
    }
    if ["version", "--version", "-V"].contains(&command) {
        println!("{VERSION}");
        return Ok(());
    }
    if rest.iter().any(|s| s == "--help" || s == "-h") {
        help();
        return Ok(());
    }
    if rest.iter().any(|s| s == "--dry-run") && !matches!(command, "plan" | "install") {
        return Err("此命令不支持 --dry-run；请使用 plan 或对应模块的 plan 命令".into());
    }
    let readonly = [
        "plan",
        "info",
        "client",
        "config",
        "render",
        "doctor",
        "backups",
        "support",
        "probe",
        "bench",
        "failover",
        "reality-check",
        "status",
        "log",
        "logs",
        "update-check",
    ];
    let subaction = rest.first().map(String::as_str).unwrap_or("info");
    let module_readonly = match command {
        "bbr" => matches!(
            subaction,
            "info" | "status" | "releases" | "list" | "preview"
        ),
        "frps" => matches!(
            subaction,
            "info" | "status" | "plan" | "client" | "log" | "logs"
        ),
        "subscription" | "subscribe" | "sub" | "site" | "cert" => {
            matches!(subaction, "info" | "status" | "list")
        }
        "tune" => !rest.iter().any(|s| s == "--apply"),
        "service" => matches!(
            rest.get(1).map(String::as_str).unwrap_or("status"),
            "status" | "log"
        ),
        _ => false,
    };
    if !readonly.contains(&command)
        && !module_readonly
        && !(command == "install" && rest.iter().any(|s| s == "--dry-run"))
    {
        platform::require_root()?;
    }
    match command {
        "plan" => plan(ctx, rest),
        "install" if rest.iter().any(|s| s == "--dry-run") => plan(ctx, rest),
        "install" => {
            let options = Options::parse(rest)?;
            if state::installed(ctx) && !ui::confirm(ctx, "重新安装会生成新凭据，继续？", false)?
            {
                return Ok(());
            }
            platform::ensure_package(ctx, "openssl", "openssl")?;
            platform::ensure_package(ctx, "curl", "curl")?;
            platform::ensure_package(ctx, "ip", "iproute2")?;
            let s = build_install(ctx, rest, false)?;
            workflow::apply(ctx, &s)?;
            if !options.has("--no-bbr")
                && ui::interactive(ctx)
                && ui::confirm(ctx, "启用系统自带 BBR?", true)?
            {
                if let Err(e) = bbr::command(ctx, &["enable".into()]) {
                    eprintln!("代理安装成功；可选 BBR 设置失败: {e}");
                }
            }
            info(ctx)
        }
        "add" | "del" | "remove" | "port" | "addr" | "reset" | "sni" | "regen" => {
            modify(ctx, command, rest)
        }
        "info" => info(ctx),
        "client" | "config" => {
            let format = if let Some(v) = rest.first() {
                v.clone()
            } else {
                let s = state::load(ctx)?;
                ui::ask(
                    ctx,
                    "格式 mihomo/singbox/singbox-notun/xray/links/sub/qr",
                    if s.protocols().iter().any(|p| p.supports("mihomo")) {
                        "mihomo"
                    } else {
                        "singbox"
                    },
                )?
            };
            if format == "qr" {
                let s = state::load(ctx)?;
                let links = render::client(ctx, &s, "links")?;
                if links.trim().is_empty() {
                    return Err("没有可生成二维码的通用链接，请使用 sing-box 配置".into());
                }
                for line in links.lines() {
                    print!(
                        "{}",
                        ctx.run("qrencode", &["-t", "ANSIUTF8", "-m", "1", line])?
                    );
                }
                Ok(())
            } else {
                let s = state::load(ctx)?;
                if s.enabled(Protocol::AnytlsReality) && !format.starts_with("sing") {
                    eprintln!("此格式不包含 AnyTLS-REALITY，请使用 singbox 远程配置或完整 JSON");
                }
                println!("{}", render::client(ctx, &s, &format)?);
                Ok(())
            }
        }
        "qr" => dispatch(ctx, &["client".into(), "qr".into()]),
        "subscription" | "subscribe" | "sub" => subscription::command(ctx, rest),
        "site" => site::command(ctx, rest),
        "cert" if subaction == "set" => cert_change(ctx, &rest[1..]),
        "cert" => cert::command(ctx, rest),
        "cert-renew" => {
            let mut values = vec!["renew".into()];
            if rest.first().is_some_and(|s| s == "subscription") {
                values.extend_from_slice(&rest[1..]);
                subscription::command(ctx, &values)
            } else {
                values.extend_from_slice(rest);
                cert::command(ctx, &values)
            }
        }
        "frps" => frp::command(ctx, rest),
        "bbr" => bbr::command(ctx, rest),
        "tune" => tune(ctx, rest),
        "probe" | "bench" | "failover" | "reality-check" => runtime::command(ctx, command, rest),
        "update" | "update-script" | "update-check" | "update-channel" => {
            update::command(ctx, args)
        }
        "start" | "stop" | "restart" | "status" => proxy_service(ctx, command),
        "service" => {
            let name = rest.first().ok_or("缺少服务名称")?;
            platform::service(
                ctx,
                name,
                rest.get(1).map(String::as_str).unwrap_or("status"),
            )
        }
        "log" | "logs" => {
            let core: Core = rest
                .first()
                .map(String::as_str)
                .unwrap_or("singbox")
                .parse()?;
            platform::service(ctx, core.service(), "log")
        }
        "net-apply" | "hop-apply" => workflow::restore_network(ctx),
        "hop-clear" => network::clear_hops(ctx),
        "backup" => {
            println!(
                "{}",
                backup::create(ctx, rest.first().map(String::as_str).unwrap_or("manual"))?
            );
            Ok(())
        }
        "backups" => backup::list(ctx),
        "restore" => backup::restore(ctx, rest.first().map(String::as_str).unwrap_or("latest")),
        "recover" => workflow::recover(ctx),
        "doctor" => diagnostics::doctor(ctx),
        "support" => diagnostics::support(ctx),
        "uninstall" => uninstall(ctx),
        "render" => {
            let s = state::load(ctx)?;
            let kind = rest.first().map(String::as_str).unwrap_or("server");
            let output = match kind {
                "server" => render::server(
                    ctx,
                    &s,
                    rest.get(1)
                        .map(String::as_str)
                        .unwrap_or("singbox")
                        .parse()?,
                )?,
                "inbound" => render::inbound(ctx, &s, rest.get(1).ok_or("需要协议")?.parse()?)?,
                "outbound" => render::outbound(
                    ctx,
                    &s,
                    rest.get(1).ok_or("需要协议")?.parse()?,
                    rest.get(2)
                        .map(String::as_str)
                        .unwrap_or("singbox")
                        .parse()?,
                )?,
                "probe" => render::probe_bundle(ctx, &s, false)?,
                _ => return Err("render 格式为 server/inbound/outbound/probe".into()),
            };
            println!("{}", serde_json::to_string_pretty(&output)?);
            Ok(())
        }
        _ => Err(format!("未知命令: {command}；请执行 onebox help").into()),
    }
}
pub fn run() -> Result<()> {
    let mut ctx = Context::default();
    let args = std::env::args()
        .skip(1)
        .filter(|s| {
            if s == "-y" || s == "--yes" {
                ctx.yes = true;
                false
            } else {
                true
            }
        })
        .collect::<Vec<_>>();
    if std::env::var("ONEBOX_AUTO").ok().as_deref() == Some("1") {
        ctx.yes = true;
    }
    dispatch(&ctx, &args)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ip_subscription_port_is_reserved_for_tcp_proxies() {
        let mut s = State::default();
        s.set("SUBSCRIPTION_ENABLED", 1);
        s.set("SUBSCRIPTION_MODE", "ip");
        s.set("SUBSCRIPTION_PORT", 18448);
        for protocol in [Protocol::Anytls, Protocol::VlessReality, Protocol::Trojan] {
            assert!(!port_available(&Context::default(), &s, protocol, 18448, None).unwrap());
        }
    }
    #[test]
    fn options_reject_typos_duplicates_invalid_ports() {
        for a in [
            vec!["--protcols", "anytls"],
            vec!["--port", "anytls=0"],
            vec!["--name", "a", "--name", "b"],
        ] {
            assert!(
                Options::parse(&a.into_iter().map(str::to_string).collect::<Vec<_>>()).is_err()
            );
        }
    }
    #[test]
    fn protocol_order_preserves_old_numbering() {
        assert_eq!(PROTOCOLS[10], Protocol::Shadowtls);
        assert_eq!(PROTOCOLS[11], Protocol::AnytlsReality);
        assert_eq!(
            protocol_list("anytls-reality,anytls,anytls").unwrap(),
            vec![Protocol::Anytls, Protocol::AnytlsReality]
        );
    }
    #[test]
    fn site_and_protocol_constraints() {
        let mut s = State::default();
        set_protocols(&mut s, &[Protocol::Anytls]);
        let o = Options::parse(&["--reality-site".into(), "test.example".into()]).unwrap();
        assert!(apply_options(&mut s, &o).is_err());
        set_protocols(&mut s, &[Protocol::AnytlsReality]);
        apply_options(&mut s, &o).unwrap();
        assert_eq!(s.get("REALITY_DEST"), "127.0.0.1:10443");
        assert!(!s.needs_cert());
    }
}
