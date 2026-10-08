//! Independently owned FRP deployment, native configuration and lifecycle.
use crate::{context::Context, util, Result};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
};

#[cfg(test)]
mod e2e;
mod legacy_firewall;
mod lifecycle;

const TESTED_VERSION: &str = "0.71.0";
const SERVER: &str = "onebox-frps";
const WEB: &str = "onebox-frp-web";

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Config {
    mode: String,
    domain: String,
    bind_addr: String,
    bind_port: u16,
    http_port: u16,
    https_port: u16,
    redirect_port: u16,
    web_domain: String,
    subdomain_host: String,
    range_start: u16,
    range_end: u16,
    token: String,
    tls_method: String,
    cert_input: String,
    key_input: String,
    version: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            mode: "web".into(),
            domain: String::new(),
            bind_addr: if fs::read_to_string("/proc/net/if_inet6")
                .is_ok_and(|s| !s.trim().is_empty())
            {
                "::"
            } else {
                "0.0.0.0"
            }
            .into(),
            bind_port: 7000,
            http_port: 7080,
            https_port: 443,
            redirect_port: 80,
            web_domain: String::new(),
            subdomain_host: String::new(),
            range_start: 20000,
            range_end: 20100,
            token: String::new(),
            tls_method: "http".into(),
            cert_input: String::new(),
            key_input: String::new(),
            version: TESTED_VERSION.into(),
        }
    }
}

fn version(s: &str) -> Result<(u32, u32, u32)> {
    let n: Vec<_> = s
        .split('.')
        .map(str::parse::<u32>)
        .collect::<std::result::Result<_, _>>()?;
    if n.len() != 3 || n[0] != 0 || (n[0], n[1], n[2]) < (0, 71, 0) {
        return Err("FRP 版本须为 0.71.0 或更新的稳定版本".into());
    }
    Ok((n[0], n[1], n[2]))
}

impl Config {
    fn validate(&self, credentials: bool) -> Result<()> {
        for s in [
            &self.mode,
            &self.domain,
            &self.bind_addr,
            &self.web_domain,
            &self.subdomain_host,
            &self.token,
            &self.tls_method,
            &self.cert_input,
            &self.key_input,
            &self.version,
        ] {
            if s.chars().any(char::is_control) {
                return Err("FRP 参数不能含控制字符".into());
            }
        }
        if !["web", "tcp"].contains(&self.mode.as_str()) {
            return Err("FRP 模式应为 web 或 tcp".into());
        }
        if !["0.0.0.0", "::", "127.0.0.1", "::1"].contains(&self.bind_addr.as_str()) {
            return Err("FRP 监听地址无效".into());
        }
        if !util::valid_domain(&self.domain) {
            return Err("请设置有效的 FRP 控制域名".into());
        }
        if self.version != "latest" {
            version(&self.version)?;
        }
        if (credentials || !self.token.is_empty())
            && (self.token.len() != 64
                || !self
                    .token
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)))
        {
            return Err("FRP token 必须为 64 位小写十六进制值".into());
        }
        if self.bind_port == 0
            || self.http_port == 0
            || self.https_port == 0
            || self.range_start == 0
            || self.range_end < self.range_start
            || self.range_end - self.range_start > 999
        {
            return Err("FRP 端口无效，转发范围必须为 1 至 1000 个端口".into());
        }
        let mut seen = BTreeSet::new();
        let mut listeners = vec![self.bind_port];
        if self.mode == "web" {
            listeners.extend(
                [self.http_port, self.https_port, self.redirect_port]
                    .into_iter()
                    .filter(|p| *p > 0),
            );
        }
        for port in listeners {
            if !seen.insert(port) || (self.range_start..=self.range_end).contains(&port) {
                return Err("FRP 监听端口重复或落在转发范围内".into());
            }
        }
        if self.mode == "web" {
            if self.subdomain_host.is_empty() {
                if !util::valid_domain(&self.web_domain) {
                    return Err("请设置有效应用域名".into());
                }
            } else if !self.web_domain.is_empty()
                || !util::valid_domain(&self.subdomain_host)
                || self.subdomain_host.len() > 238
            {
                return Err("应用域名与泛域名根不能并用".into());
            }
            if !["http", "cf", "custom"].contains(&self.tls_method.as_str()) {
                return Err("网站证书方式应为 http、cf 或 custom".into());
            }
            if self.tls_method == "http"
                && (!self.subdomain_host.is_empty() || self.redirect_port != 80)
            {
                return Err("HTTP-01 要求 TCP 80 且不支持泛域名；泛域名请选择 cf 或 custom".into());
            }
            if self.tls_method == "custom"
                && (self.cert_input.is_empty() || self.key_input.is_empty())
            {
                return Err("自备证书需要 --cert 与 --key".into());
            }
        }
        Ok(())
    }
    fn reservations(&self) -> Vec<(u16, u16, String)> {
        let mut v = vec![(self.bind_port, self.bind_port, "tcp".into())];
        if self.mode == "web" {
            for p in [self.http_port, self.https_port, self.redirect_port] {
                if p > 0 {
                    v.push((p, p, "tcp".into()));
                }
            }
        }
        v.push((self.range_start, self.range_end, "both".into()));
        v
    }
    fn firewall_ports(&self) -> Vec<(u16, bool)> {
        let mut v = vec![(self.bind_port, false)];
        if self.mode == "web" {
            v.push((self.https_port, false));
            if self.redirect_port > 0 {
                v.push((self.redirect_port, false));
            }
        } else {
            for p in self.range_start..=self.range_end {
                v.push((p, false));
                v.push((p, true));
            }
        }
        v
    }
    fn domains(&self) -> Vec<String> {
        if self.subdomain_host.is_empty() {
            vec![self.web_domain.clone()]
        } else {
            vec![
                self.subdomain_host.clone(),
                format!("*.{}", self.subdomain_host),
            ]
        }
    }
}

fn installed(ctx: &Context) -> bool {
    ctx.paths.frp_root.join(".managed").is_file()
        && (ctx.paths.frp_root.join("state.json").is_file()
            || ctx.paths.frp_root.join("state.conf").is_file())
}

fn legacy_state(input: &str) -> Result<Config> {
    const KEYS: [&str; 16] = [
        "FRPS_MODE",
        "FRPS_DOMAIN",
        "FRPS_BIND_ADDR",
        "FRPS_BIND_PORT",
        "FRPS_HTTP_PORT",
        "FRPS_HTTPS_PORT",
        "FRPS_REDIRECT_PORT",
        "FRPS_WEB_DOMAIN",
        "FRPS_SUBDOMAIN_HOST",
        "FRPS_RANGE_START",
        "FRPS_RANGE_END",
        "FRPS_TOKEN",
        "FRPS_TLS_METHOD",
        "FRPS_CERT_INPUT",
        "FRPS_KEY_INPUT",
        "FRPS_VERSION",
    ];
    let mut m = BTreeMap::new();
    for line in input.lines().filter(|s| !s.is_empty()) {
        let (key, value) = line.split_once('=').ok_or("旧 FRP 状态格式无效")?;
        if !KEYS.contains(&key)
            || value.chars().any(char::is_control)
            || m.insert(key, value).is_some()
        {
            return Err("旧 FRP 状态含未知或重复键".into());
        }
    }
    for k in &KEYS {
        if !m.contains_key(k) {
            return Err(format!("旧 FRP 状态缺少 {k}").into());
        }
    }
    let n = |k: &str| -> Result<u16> { Ok(m[k].parse()?) };
    let cfg = Config {
        mode: m["FRPS_MODE"].into(),
        domain: m["FRPS_DOMAIN"].into(),
        bind_addr: m["FRPS_BIND_ADDR"].into(),
        bind_port: n("FRPS_BIND_PORT")?,
        http_port: n("FRPS_HTTP_PORT")?,
        https_port: n("FRPS_HTTPS_PORT")?,
        redirect_port: n("FRPS_REDIRECT_PORT")?,
        web_domain: m["FRPS_WEB_DOMAIN"].into(),
        subdomain_host: m["FRPS_SUBDOMAIN_HOST"].into(),
        range_start: n("FRPS_RANGE_START")?,
        range_end: n("FRPS_RANGE_END")?,
        token: m["FRPS_TOKEN"].into(),
        tls_method: m["FRPS_TLS_METHOD"].into(),
        cert_input: m["FRPS_CERT_INPUT"].into(),
        key_input: m["FRPS_KEY_INPUT"].into(),
        version: m["FRPS_VERSION"].into(),
    };
    cfg.validate(true)?;
    Ok(cfg)
}

fn load(ctx: &Context) -> Result<Config> {
    if !installed(ctx) {
        return Err("尚未安装托管 FRP；运行 onebox frps install".into());
    }
    let path = if ctx.paths.frp_root.join("state.json").exists() {
        ctx.paths.frp_root.join("state.json")
    } else {
        ctx.paths.frp_root.join("state.conf")
    };
    util::safe_path(&path)?;
    let data = fs::read_to_string(&path)?;
    if data.len() > 65536 {
        return Err("FRP 状态文件异常大".into());
    }
    let cfg: Config = if path.extension().is_some_and(|s| s == "json") {
        serde_json::from_str(&data)?
    } else {
        legacy_state(&data)?
    };
    cfg.validate(true)?;
    Ok(cfg)
}

fn save(ctx: &Context, cfg: &Config) -> Result<()> {
    cfg.validate(true)?;
    util::atomic_write(
        &ctx.paths.frp_root.join("state.json"),
        &serde_json::to_vec_pretty(cfg)?,
        0o600,
    )
}

/// Includes stopped FRP instances and not-yet-connected clients' reserved ranges.
pub fn reserved_ports(ctx: &Context) -> Result<Vec<(u16, u16, String)>> {
    if !installed(ctx) {
        return Ok(Vec::new());
    }
    Ok(load(ctx)?.reservations())
}

fn parse(cfg: &mut Config, args: &[String]) -> Result<bool> {
    let mut dry = false;
    let mut i = 0;
    let mut domain_opt = "";
    while i < args.len() {
        let opt = args[i].as_str();
        if opt == "--dry-run" {
            dry = true;
            i += 1;
            continue;
        }
        if opt == "-y" || opt == "--yes" {
            i += 1;
            continue;
        }
        let value = args
            .get(i + 1)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| format!("{opt} 缺少值"))?;
        match opt {
            "--mode" => cfg.mode = value.clone(),
            "--domain" => cfg.domain = value.to_ascii_lowercase(),
            "--port" => cfg.bind_port = value.parse()?,
            "--http-port" => cfg.http_port = value.parse()?,
            "--https-port" => cfg.https_port = value.parse()?,
            "--redirect-port" => cfg.redirect_port = value.parse()?,
            "--web-domain" | "--subdomain-host" => {
                if !domain_opt.is_empty() && domain_opt != opt {
                    return Err("--web-domain 与 --subdomain-host 不能同时使用".into());
                }
                domain_opt = opt;
                if opt == "--web-domain" {
                    cfg.web_domain = value.to_ascii_lowercase();
                    cfg.subdomain_host.clear();
                } else {
                    cfg.subdomain_host = value.to_ascii_lowercase();
                    cfg.web_domain.clear();
                }
            }
            "--allow-ports" => {
                let (a, b) = value
                    .split_once('-')
                    .ok_or("--allow-ports 格式为 20000-20100")?;
                cfg.range_start = a.parse()?;
                cfg.range_end = b.parse()?;
            }
            "--tls" => cfg.tls_method = value.clone(),
            "--cert" => cfg.cert_input = value.clone(),
            "--key" => cfg.key_input = value.clone(),
            "--version" => cfg.version = value.trim_start_matches('v').into(),
            _ => return Err(format!("未知 FRP 选项: {opt}").into()),
        }
        i += 2;
    }
    Ok(dry)
}

fn summary(cfg: &Config) {
    println!(
        "FRP {} / v{}\n控制入口: {}:{}（TLS + 私有 CA + token）",
        cfg.mode, cfg.version, cfg.domain, cfg.bind_port
    );
    println!("控制域名 A / AAAA 应直接指向 VPS，关闭 CDN 代理。凭据不在此处显示。");
    if cfg.mode == "web" {
        let host = if cfg.subdomain_host.is_empty() {
            cfg.web_domain.clone()
        } else {
            format!("app.{}", cfg.subdomain_host)
        };
        println!(
            "应用入口: https://{}{}{}/\n内部转发: 127.0.0.1:{}；证书方式: {}",
            host,
            if cfg.https_port == 443 { "" } else { ":" },
            if cfg.https_port == 443 {
                String::new()
            } else {
                cfg.https_port.to_string()
            },
            cfg.http_port,
            cfg.tls_method
        );
        if !cfg.subdomain_host.is_empty() {
            println!(
                "添加泛域名解析 *.{}，客户端 subdomain = app",
                cfg.subdomain_host
            );
        }
        if cfg.tls_method == "http" {
            println!("HTTP-01 申请和自动续期需要持续开放公网 TCP 80。");
        }
    } else {
        println!(
            "公网 TCP / UDP 转发范围: {}-{}",
            cfg.range_start, cfg.range_end
        );
    }
    for (lo, hi, p) in cfg.reservations() {
        println!("保留端口: {lo}-{hi}/{p}");
    }
}

#[derive(Debug)]
struct Back;
impl std::fmt::Display for Back {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "返回上一步")
    }
}
impl std::error::Error for Back {}
fn ask(ctx: &Context, prompt: &str, default: &str) -> Result<String> {
    let value = crate::ui::ask(ctx, prompt, default)?;
    match value.to_ascii_lowercase().as_str() {
        "q" => Err(Box::new(crate::ui::Cancelled)),
        "b" => Err(Box::new(Back)),
        _ => Ok(value),
    }
}
fn choose(ctx: &Context, prompt: &str, default: u32, min: u32, max: u32) -> Result<u32> {
    loop {
        let value = ask(ctx, prompt, &default.to_string())?;
        if let Ok(n) = value.parse::<u32>() {
            if (min..=max).contains(&n) {
                return Ok(n);
            }
        }
        if ctx.yes {
            return Err("默认选项无效".into());
        }
        eprintln!("请输入 {min}–{max}，b 返回，q 取消");
    }
}
fn ask_port(ctx: &Context, prompt: &str, default: u16, zero: bool) -> Result<u16> {
    loop {
        let value = ask(ctx, prompt, &default.to_string())?;
        if let Ok(n) = value.parse::<u16>() {
            if zero || n > 0 {
                return Ok(n);
            }
        }
        if ctx.yes {
            return Err("默认端口无效".into());
        }
        eprintln!("端口范围为 {}–65535", if zero { 0 } else { 1 });
    }
}
fn ask_domain(ctx: &Context, prompt: &str, default: &str) -> Result<String> {
    loop {
        let domain = ask(ctx, prompt, default)?.to_ascii_lowercase();
        if util::valid_domain(&domain) {
            return Ok(domain);
        }
        if ctx.yes {
            return Err("默认域名无效".into());
        }
        eprintln!("请输入完整域名，不包含协议、路径或 *.");
    }
}
fn wizard(ctx: &Context, cfg: &mut Config) -> Result<()> {
    println!("FRP 配置向导：回车保留默认值；b 返回上一步；q 取消。确认后才修改系统。");
    let mut step = 0usize;
    loop {
        let result = (|| -> Result<()> {
            match step {
                0 => {
                    cfg.mode = if choose(
                        ctx,
                        "模式：1 HTTPS 网站，2 TCP / UDP 转发",
                        if cfg.mode == "web" { 1 } else { 2 },
                        1,
                        2,
                    )? == 1
                    {
                        "web"
                    } else {
                        "tcp"
                    }
                    .into();
                }
                1 => cfg.domain = ask_domain(ctx, "控制域名", &cfg.domain)?,
                2 => cfg.bind_port = ask_port(ctx, "控制端口", cfg.bind_port, false)?,
                3 => {
                    if cfg.mode == "web" {
                        let wildcard = choose(
                            ctx,
                            "应用域名：1 单域名，2 泛域名",
                            if cfg.subdomain_host.is_empty() { 1 } else { 2 },
                            1,
                            2,
                        )?;
                        if wildcard == 1 {
                            cfg.web_domain = ask_domain(ctx, "应用域名", &cfg.web_domain)?;
                            cfg.subdomain_host.clear();
                        } else {
                            cfg.subdomain_host =
                                ask_domain(ctx, "泛域名根（不带 *.）", &cfg.subdomain_host)?;
                            cfg.web_domain.clear();
                        }
                    } else {
                        loop {
                            let range = ask(
                                ctx,
                                "允许转发端口范围",
                                &format!("{}-{}", cfg.range_start, cfg.range_end),
                            )?;
                            let valid = range
                                .split_once('-')
                                .and_then(|(a, b)| {
                                    Some((a.parse::<u16>().ok()?, b.parse::<u16>().ok()?))
                                })
                                .filter(|(a, b)| *a > 0 && b >= a && b - a <= 999);
                            if let Some((a, b)) = valid {
                                cfg.range_start = a;
                                cfg.range_end = b;
                                break;
                            }
                            eprintln!("请输入递增端口范围，最多 1000 个，例如 20000-20100");
                        }
                    }
                }
                4 => {
                    if cfg.mode == "web" {
                        let default = match cfg.tls_method.as_str() {
                            "cf" => 2,
                            "custom" => 3,
                            _ => {
                                if cfg.subdomain_host.is_empty() {
                                    1
                                } else {
                                    2
                                }
                            }
                        };
                        cfg.tls_method = match choose(
                            ctx,
                            "证书：1 HTTP-01，2 Cloudflare DNS，3 自备证书",
                            default,
                            1,
                            3,
                        )? {
                            1 => "http",
                            2 => "cf",
                            _ => "custom",
                        }
                        .into();
                        if cfg.tls_method == "http" && !cfg.subdomain_host.is_empty() {
                            return Err("泛域名需要 Cloudflare DNS 或自备证书".into());
                        }
                        if cfg.tls_method == "cf" {
                            println!("Cloudflare DNS 使用 CF_Token 与 CF_Account_ID 环境变量；已有账户配置可继续复用。");
                        }
                    }
                }
                5 => {
                    if cfg.mode == "web" {
                        cfg.http_port = ask_port(ctx, "frps 内部 HTTP 端口", cfg.http_port, false)?;
                        cfg.https_port = ask_port(ctx, "公开 HTTPS 端口", cfg.https_port, false)?;
                        cfg.redirect_port = if cfg.tls_method == "http" {
                            80
                        } else {
                            ask_port(ctx, "HTTP 跳转端口（0 关闭）", cfg.redirect_port, true)?
                        };
                    }
                }
                6 => {
                    if cfg.mode == "web" && cfg.tls_method == "custom" {
                        cfg.cert_input = ask(ctx, "证书完整链路径", &cfg.cert_input)?;
                        cfg.key_input = ask(ctx, "未加密私钥路径", &cfg.key_input)?;
                    }
                }
                _ => cfg.validate(false)?,
            }
            Ok(())
        })();
        match result {
            Ok(()) => {
                if step >= 7 {
                    return Ok(());
                }
                step += 1;
            }
            Err(e) if e.is::<Back>() => step = step.saturating_sub(1),
            Err(e) if e.is::<crate::ui::Cancelled>() => return Err(e),
            Err(e) => {
                eprintln!("{e}");
                if step >= 7 {
                    step = 2;
                }
            }
        }
    }
}

fn quote(s: &str) -> String {
    serde_json::to_string(s).expect("string serialization")
}

fn cf_credentials(ctx: &Context, cfg: &Config) -> Result<()> {
    if cfg.mode != "web" || cfg.tls_method != "cf" {
        return Ok(());
    }
    crate::cert::ensure_cf_credentials(ctx, &ctx.paths.frp_root.join("web-tls"))
}

fn render(ctx: &Context, cfg: &Config) -> Result<String> {
    cfg.validate(true)?;
    let p = &ctx.paths.frp_root;
    let mut out=format!("bindAddr = {}\nbindPort = {}\nproxyBindAddr = {}\nauth.method = \"token\"\nauth.token = {}\nauth.additionalScopes = [\"HeartBeats\", \"NewWorkConns\"]\ntransport.tls.force = true\ntransport.tls.certFile = {}\ntransport.tls.keyFile = {}\nallowPorts = [{{ start = {}, end = {} }}]\nmaxPortsPerClient = 10\nlog.to = \"console\"\nlog.level = \"info\"\nlog.disablePrintColor = true\n",quote(&cfg.bind_addr),cfg.bind_port,quote(if cfg.mode=="web"{"127.0.0.1"}else{&cfg.bind_addr}),quote(&cfg.token),quote(util::path_str(&p.join("server-cert.pem"))?),quote(util::path_str(&p.join("server-key.pem"))?),cfg.range_start,cfg.range_end);
    if cfg.mode == "web" {
        out.push_str(&format!("vhostHTTPPort = {}\n", cfg.http_port));
        if !cfg.subdomain_host.is_empty() {
            out.push_str(&format!("subDomainHost = {}\n", quote(&cfg.subdomain_host)));
        }
    }
    Ok(out)
}

fn export(ctx: &Context, cfg: &Config, args: &[String]) -> Result<()> {
    let mut kind = if cfg.mode == "web" {
        "http".into()
    } else {
        "tcp".into()
    };
    let mut lp = 8080u16;
    let mut rp = cfg.range_start;
    let mut sub = "www".to_string();
    let mut output = String::new();
    if args.is_empty() {
        if !crate::ui::interactive(ctx) {
            return Err("用法: onebox frps client 新目录 [--type http|tcp|udp --local-port N --remote-port N --subdomain 标签]".into());
        }
        let mut step = 0usize;
        loop {
            let result = (|| -> Result<()> {
                match step {
                    0 => {
                        if cfg.mode == "tcp" {
                            kind = if choose(
                                ctx,
                                "转发协议：1 TCP，2 UDP",
                                if kind == "udp" { 2 } else { 1 },
                                1,
                                2,
                            )? == 1
                            {
                                "tcp"
                            } else {
                                "udp"
                            }
                            .into();
                        }
                    }
                    1 => lp = ask_port(ctx, "内网服务端口", lp, false)?,
                    2 => {
                        if cfg.mode == "tcp" {
                            rp = ask_port(ctx, "公网转发端口", rp, false)?;
                            if !(cfg.range_start..=cfg.range_end).contains(&rp) {
                                return Err("端口不在允许转发范围内".into());
                            }
                        } else if !cfg.subdomain_host.is_empty() {
                            sub = ask(ctx, "子域标签", &sub)?;
                            if sub.len() > 63
                                || sub.is_empty()
                                || sub.starts_with('-')
                                || sub.ends_with('-')
                                || !sub.bytes().all(|b| {
                                    b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-'
                                })
                            {
                                return Err("子域标签无效".into());
                            }
                        }
                    }
                    _ => {
                        let selected = ask(
                            ctx,
                            "导出到新的目录",
                            if output.is_empty() {
                                "./frpc-client"
                            } else {
                                &output
                            },
                        )?;
                        if Path::new(&selected).exists() {
                            return Err("导出目录已存在，请选择新目录".into());
                        }
                        output = selected;
                    }
                }
                Ok(())
            })();
            match result {
                Ok(()) => {
                    if step >= 3 {
                        break;
                    }
                    step += 1;
                }
                Err(e) if e.is::<Back>() => step = step.saturating_sub(1),
                Err(e) if e.is::<crate::ui::Cancelled>() => return Err(e),
                Err(e) => eprintln!("{e}"),
            }
        }
    } else {
        output.clone_from(&args[0]);
        let mut i = 1;
        while i < args.len() {
            let v = args.get(i + 1).ok_or("导出选项缺少值")?;
            match args[i].as_str() {
                "--type" => kind = v.clone(),
                "--local-port" => lp = v.parse()?,
                "--remote-port" => rp = v.parse()?,
                "--subdomain" => sub = v.clone(),
                _ => return Err(format!("未知导出选项: {}", args[i]).into()),
            }
            i += 2;
        }
    }
    if lp == 0
        || !matches!(
            (cfg.mode.as_str(), kind.as_str()),
            ("web", "http") | ("tcp", "tcp") | ("tcp", "udp")
        )
    {
        return Err("FRP 导出协议或本地端口无效".into());
    }
    if kind != "http" && !(cfg.range_start..=cfg.range_end).contains(&rp) {
        return Err("公网转发端口不在允许范围内".into());
    }
    if sub.len() > 63
        || sub.is_empty()
        || sub.starts_with('-')
        || sub.ends_with('-')
        || !sub
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    {
        return Err("子域标签无效".into());
    }
    let output = PathBuf::from(output);
    let output = if output.is_absolute() {
        output
    } else {
        std::env::current_dir()?.join(output)
    };
    util::safe_path(&output)?;
    if output.exists() {
        return Err("导出目录已存在，请选择新的目录".into());
    }
    let domain = if cfg.subdomain_host.is_empty() {
        cfg.web_domain.clone()
    } else {
        format!("{sub}.{}", cfg.subdomain_host)
    };
    let mut text=format!("serverAddr = {}\nserverPort = {}\nauth.method = \"token\"\nauth.token = {}\nauth.additionalScopes = [\"HeartBeats\", \"NewWorkConns\"]\ntransport.tls.enable = true\ntransport.tls.serverName = {}\ntransport.tls.trustedCaFile = \"./ca.pem\"\nlog.to = \"console\"\nlog.disablePrintColor = true\n\n[[proxies]]\nname = {}\ntype = {}\nlocalIP = \"127.0.0.1\"\nlocalPort = {lp}\n",quote(&cfg.domain),cfg.bind_port,quote(&cfg.token),quote(&cfg.domain),quote(&format!("onebox-{kind}-{}",if kind=="http"{domain.clone()}else{rp.to_string()})),quote(&kind));
    if kind == "http" {
        if cfg.subdomain_host.is_empty() {
            text.push_str(&format!("customDomains = [{}]\n", quote(&domain)));
        } else {
            text.push_str(&format!("subdomain = {}\n", quote(&sub)));
        }
        text.push_str("requestHeaders.set.\"X-Forwarded-Proto\" = \"https\"\n");
    } else {
        text.push_str(&format!("remotePort = {rp}\n"));
    }
    let ca = fs::read(ctx.paths.frp_root.join("ca.pem"))?;
    fs::create_dir(&output)?;
    let result = (|| -> Result<()> {
        lifecycle::private_dir(&output)?;
        util::atomic_write(&output.join("frpc.toml"), text.as_bytes(), 0o600)?;
        util::atomic_write(&output.join("ca.pem"), &ca, 0o600)?;
        let endpoint = if kind == "http" {
            format!("https://{domain}:{}/", cfg.https_port)
        } else {
            format!("{}:{rp} ({kind})", cfg.domain)
        };
        let readme=format!("本目录含 FRP token，请私密保存。不要复制服务端 CA 私钥。\n在内网机器安装 frpc {}，复制整个目录并进入该目录：\nfrpc verify -c frpc.toml\nfrpc -c frpc.toml\n内网服务：127.0.0.1:{lp}\n访问：{endpoint}\n必须保留 trustedCaFile 与 serverName 校验。\n",cfg.version);
        util::atomic_write(&output.join("README.txt"), readme.as_bytes(), 0o600)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_dir_all(&output);
    }
    result?;
    println!(
        "已导出 {}；将整个目录复制到内网机器后运行 frpc",
        output.display()
    );
    Ok(())
}

pub fn command(ctx: &Context, args: &[String]) -> Result<()> {
    let action = args.first().map(String::as_str).unwrap_or("menu");
    let rest = args.get(1..).unwrap_or(&[]);
    match action {
        "help" | "--help" => {
            println!("onebox frps [plan|install|configure|info|status|start|stop|restart|update [版本]|renew|rotate-token|client [新目录]|log|uninstall]\n配置参数：--mode web|tcp --domain 控制域名 --web-domain 应用域名 / --subdomain-host 泛域名根\n--port 7000 --http-port 7080 --https-port 443 --redirect-port 80 --allow-ports 20000-20100\n--tls http|cf|custom --cert 完整链 --key 私钥 --version 0.71.0|latest --dry-run");
            Ok(())
        }
        "plan" | "install" | "configure" => {
            let mut cfg = if installed(ctx) {
                load(ctx)?
            } else {
                Config::default()
            };
            let dry = parse(&mut cfg, rest)?;
            if action != "plan" && !dry && rest.is_empty() && crate::ui::interactive(ctx) {
                wizard(ctx, &mut cfg)?;
            }
            cfg.validate(false)?;
            summary(&cfg);
            if action == "plan" || dry {
                println!("以上仅为预览，未联网、未修改配置。实际安装会验证 DNS 和端口。");
                return Ok(());
            }
            cf_credentials(ctx, &cfg)?;
            if !crate::ui::confirm(ctx, "确认部署上述 FRP 配置？已有连接将短暂中断", false)?
            {
                return Ok(());
            }
            lifecycle::apply(ctx, &mut cfg, false)
        }
        "info" | "status" => {
            if !rest.is_empty() {
                return Err("状态命令不接受参数".into());
            }
            if !installed(ctx) {
                println!("尚未安装 FRP；运行 onebox frps install");
                return Ok(());
            }
            let cfg = load(ctx)?;
            summary(&cfg);
            println!(
                "frps: {}",
                if lifecycle::running(ctx, SERVER) {
                    "运行中"
                } else {
                    "已停止"
                }
            );
            if cfg.mode == "web" {
                println!(
                    "网站: {}",
                    if lifecycle::running(ctx, WEB) {
                        "运行中"
                    } else {
                        "已停止"
                    }
                );
            }
            Ok(())
        }
        "menu" => {
            if !crate::ui::interactive(ctx) {
                return command(ctx, &["info".into()]);
            }
            loop {
                println!("FRP：1 安装/配置，2 状态，3 导出客户端，4 启动，5 停止，6 重启，7 更新，8 续期，9 轮换 token，10 日志，11 卸载，0 返回");
                let n = match choose(ctx, "请选择", 0, 0, 11) {
                    Ok(n) => n,
                    Err(e) if e.is::<Back>() || e.is::<crate::ui::Cancelled>() => return Ok(()),
                    Err(e) => return Err(e),
                };
                if n == 0 {
                    return Ok(());
                }
                let a = [
                    "",
                    "configure",
                    "info",
                    "client",
                    "start",
                    "stop",
                    "restart",
                    "update",
                    "renew",
                    "rotate-token",
                    "log",
                    "uninstall",
                ][n as usize];
                if let Err(e) = command(ctx, &[a.into()]) {
                    eprintln!("{e}");
                }
            }
        }
        _ => {
            let mut cfg = load(ctx)?;
            match action {
                "client" => export(ctx, &cfg, rest),
                "net-apply" => {
                    if !rest.is_empty() {
                        return Err("net-apply 不接受参数".into());
                    }
                    crate::platform::require_root()?;
                    crate::network::apply_ports(ctx, "frp", &cfg.firewall_ports())
                }
                "update" | "rotate-token" => {
                    if rest.len() > usize::from(action == "update") {
                        return Err("参数过多".into());
                    }
                    if action == "update" {
                        cfg.version = rest
                            .first()
                            .map(|s| s.trim_start_matches('v').to_string())
                            .unwrap_or_else(|| "latest".into());
                    }
                    cfg.validate(true)?;
                    summary(&cfg);
                    cf_credentials(ctx, &cfg)?;
                    if !crate::ui::confirm(
                        ctx,
                        if action == "rotate-token" {
                            "轮换 token 会使所有旧客户端失效，确认继续？"
                        } else {
                            "确认更新 FRP？连接将短暂中断"
                        },
                        false,
                    )? {
                        return Ok(());
                    }
                    lifecycle::apply(ctx, &mut cfg, action == "rotate-token")
                }
                "renew" => {
                    if !rest.is_empty() && !(rest.len() == 1 && rest[0] == "--cron") {
                        return Err("renew 仅接受 --cron".into());
                    }
                    lifecycle::renew(ctx, &cfg)
                }
                "uninstall" => {
                    if !rest.is_empty() {
                        return Err("uninstall 不接受参数".into());
                    }
                    if !crate::ui::confirm(
                        ctx,
                        "卸载 FRP、独立配置与证书？已导出配置将失效",
                        false,
                    )? {
                        return Ok(());
                    }
                    lifecycle::uninstall(ctx)
                }
                "start" | "stop" | "restart" => {
                    if !rest.is_empty() {
                        return Err("服务命令不接受参数".into());
                    }
                    lifecycle::service(ctx, &cfg, action)
                }
                "log" => {
                    if !rest.is_empty() {
                        return Err("log 不接受参数".into());
                    }
                    let o = ctx.output(
                        "journalctl",
                        &["-u", SERVER, "-u", WEB, "-n", "80", "--no-pager"],
                    );
                    match o {
                        Ok(o) if o.success() => print!("{}", o.stdout),
                        _ => {
                            for name in [SERVER, WEB, "frps"] {
                                let p = ctx.paths.frp_log.join(format!("{name}.log"));
                                if let Ok(s) = fs::read_to_string(p) {
                                    for line in s
                                        .lines()
                                        .rev()
                                        .take(80)
                                        .collect::<Vec<_>>()
                                        .into_iter()
                                        .rev()
                                    {
                                        println!("{line}");
                                    }
                                }
                            }
                        }
                    }
                    Ok(())
                }
                _ => Err(format!("未知 FRP 操作: {action}").into()),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn config() -> Config {
        Config {
            domain: "control.example.com".into(),
            web_domain: "app.example.com".into(),
            token: "a".repeat(64),
            ..Config::default()
        }
    }
    #[test]
    fn protocol_and_port_validation() {
        let mut c = config();
        assert!(c.validate(true).is_ok());
        c.http_port = c.bind_port;
        assert!(c.validate(true).is_err());
        c.http_port = 7080;
        c.subdomain_host = "example.com".into();
        c.web_domain.clear();
        assert!(c.validate(true).is_err());
        c.tls_method = "cf".into();
        assert!(c.validate(true).is_ok());
        c.range_end = c.range_start + 1000;
        assert!(c.validate(true).is_err());
    }
    #[test]
    fn server_enforces_ca_tls_and_loopback_web() {
        let ctx = Context::default();
        let s = render(&ctx, &config()).unwrap();
        assert!(s.contains("transport.tls.force = true"));
        assert!(s.contains("proxyBindAddr = \"127.0.0.1\""));
        assert!(s.contains("\"HeartBeats\", \"NewWorkConns\""));
        assert!(!s.contains("webServer"));
    }
    #[test]
    fn reservations_include_inactive_forwarding() {
        let mut c = config();
        c.mode = "tcp".into();
        assert_eq!(c.reservations()[1], (20000, 20100, "both".into()));
        assert_eq!(c.firewall_ports().len(), 203);
        assert!(!config().firewall_ports().contains(&(7080, false)));
        assert!(config()
            .reservations()
            .contains(&(20000, 20100, "both".into())));
        assert!(!config().firewall_ports().contains(&(20000, false)));
    }
    #[test]
    fn conflicting_domain_flags_rejected() {
        let mut c = config();
        assert!(parse(
            &mut c,
            &[
                "--web-domain",
                "app.example.com",
                "--subdomain-host",
                "example.com"
            ]
            .map(String::from)
        )
        .is_err());
    }
    #[test]
    fn legacy_is_data_never_code() {
        assert!(legacy_state("FRPS_TOKEN=$(touch /tmp/owned)\n").is_err());
        assert!(legacy_state("FRPS_MODE=tcp\nFRPS_MODE=web\n").is_err());
        assert!(legacy_state("export FRPS_DOMAIN=example.com\n").is_err());
    }
    #[test]
    fn old_state_migration_preserves_credentials() {
        let text=format!("FRPS_MODE=tcp\nFRPS_DOMAIN=frp.example.com\nFRPS_BIND_ADDR=::\nFRPS_BIND_PORT=7000\nFRPS_HTTP_PORT=7080\nFRPS_HTTPS_PORT=443\nFRPS_REDIRECT_PORT=80\nFRPS_WEB_DOMAIN=\nFRPS_SUBDOMAIN_HOST=\nFRPS_RANGE_START=20000\nFRPS_RANGE_END=20000\nFRPS_TOKEN={}\nFRPS_TLS_METHOD=http\nFRPS_CERT_INPUT=\nFRPS_KEY_INPUT=\nFRPS_VERSION=0.71.0\n","f".repeat(64));
        let c = legacy_state(&text).unwrap();
        assert_eq!(c.token, "f".repeat(64));
        assert_eq!(c.range_start, c.range_end);
        assert_eq!(c.bind_addr, "::");
        assert!(legacy_state(&(text + "FRPS_TOKEN=bad\n")).is_err());
    }
    #[test]
    fn exported_client_pins_private_ca_and_never_overwrites() {
        use std::os::unix::fs::PermissionsExt;
        let root = std::env::temp_dir().join(format!(
            "onebox-frp-export-{}",
            util::random_hex(8).unwrap()
        ));
        let ctx = Context {
            paths: crate::context::Paths::isolated(&root),
            ..Context::default()
        };
        fs::create_dir_all(&ctx.paths.frp_root).unwrap();
        fs::write(ctx.paths.frp_root.join("ca.pem"), "PUBLIC CA").unwrap();
        fs::write(ctx.paths.frp_root.join("ca-key.pem"), "PRIVATE CA KEY").unwrap();
        let output = root.join("export");
        let args = vec![
            output.to_str().unwrap().to_string(),
            "--local-port".into(),
            "8081".into(),
        ];
        export(&ctx, &config(), &args).unwrap();
        let text = fs::read_to_string(output.join("frpc.toml")).unwrap();
        assert!(text.contains("transport.tls.trustedCaFile = \"./ca.pem\""));
        assert!(text.contains("transport.tls.serverName = \"control.example.com\""));
        assert!(text.contains("localPort = 8081"));
        assert!(!output.join("ca-key.pem").exists());
        assert_eq!(
            fs::metadata(output.join("frpc.toml"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        assert!(export(&ctx, &config(), &args).is_err());
        assert_eq!(fs::read_to_string(output.join("frpc.toml")).unwrap(), text);
        fs::remove_dir_all(root).unwrap();
    }
}
