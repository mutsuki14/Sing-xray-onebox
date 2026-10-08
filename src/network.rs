//! Managed firewall rules. Every created rule is journalled before continuing.
use crate::{
    context::Context,
    model::{Protocol, State},
    platform, util, Result,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::BTreeSet,
    fs,
    net::{TcpListener, UdpSocket},
    os::{fd::AsRawFd, unix::fs::OpenOptionsExt},
    path::PathBuf,
};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
struct Rule {
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
#[derive(Default, Serialize, Deserialize)]
struct Ledger {
    #[serde(default)]
    rules: Vec<Rule>,
}
fn owner_valid(owner: &str) -> Result<()> {
    if !owner.is_empty()
        && owner.len() < 32
        && owner
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
    {
        Ok(())
    } else {
        Err("防火墙所有者名称无效".into())
    }
}
fn ledger_path(ctx: &Context, owner: &str) -> PathBuf {
    if owner == "frp" {
        ctx.paths.frp_root.join("firewall-v2.json")
    } else if owner == "proxy" {
        ctx.paths.root.join("firewall-v2.json")
    } else {
        ctx.paths.root.join(format!("firewall-{owner}.json"))
    }
}
fn load(ctx: &Context, owner: &str) -> Result<Ledger> {
    let p = ledger_path(ctx, owner);
    util::safe_path(&p)?;
    if p.exists() {
        Ok(serde_json::from_slice(&fs::read(p)?)?)
    } else {
        Ok(Ledger::default())
    }
}
fn save(ctx: &Context, owner: &str, ledger: &Ledger) -> Result<()> {
    util::atomic_write(
        &ledger_path(ctx, owner),
        &serde_json::to_vec_pretty(ledger)?,
        0o600,
    )
}
fn lock(ctx: &Context, owner: &str) -> Result<fs::File> {
    let path = ledger_path(ctx, owner).with_extension("lock");
    util::safe_path(&path)?;
    fs::create_dir_all(path.parent().ok_or("无效台账路径")?)?;
    let f = fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    if unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(f)
}
fn span(r: &Rule, sep: &str) -> String {
    if r.end > r.port {
        format!("{}{}{}", r.port, sep, r.end)
    } else {
        r.port.to_string()
    }
}
fn ranges(ports: &BTreeSet<(u16, bool)>) -> Vec<(u16, u16, bool)> {
    let mut out = Vec::new();
    for udp in [false, true] {
        let mut current: Option<(u16, u16, bool)> = None;
        for (p, _) in ports.iter().filter(|(_, u)| *u == udp) {
            match current {
                Some((start, end, u)) if end.checked_add(1) == Some(*p) => {
                    current = Some((start, *p, u))
                }
                Some(old) => {
                    out.push(old);
                    current = Some((*p, *p, udp));
                }
                None => current = Some((*p, *p, udp)),
            }
        }
        if let Some(r) = current {
            out.push(r)
        }
    }
    out
}
fn ipv6_available() -> bool {
    std::path::Path::new("/proc/net/if_inet6").exists()
        && fs::read_to_string("/proc/sys/net/ipv6/conf/all/disable_ipv6")
            .map(|s| s.trim() != "1")
            .unwrap_or(true)
}
fn proto(udp: bool) -> &'static str {
    if udp {
        "udp"
    } else {
        "tcp"
    }
}
fn nft_word(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}
fn nft_chains(ctx: &Context) -> Result<Vec<(String, String, String)>> {
    let raw = ctx.run("nft", &["-j", "list", "ruleset"])?;
    let doc: Value = serde_json::from_str(&raw)?;
    let mut found = Vec::new();
    for entry in doc["nftables"].as_array().ok_or("nft ruleset 格式无效")? {
        let c = &entry["chain"];
        if c["hook"] != "input" {
            continue;
        }
        let f = c["family"].as_str().ok_or("缺少 nft family")?;
        if !matches!(f, "ip" | "ip6" | "inet") {
            continue;
        }
        let t = c["table"].as_str().ok_or("缺少 nft table")?;
        let n = c["name"].as_str().ok_or("缺少 nft chain")?;
        if !nft_word(t) || !nft_word(n) {
            return Err("nft 表或链名无法安全管理".into());
        }
        found.push((f.into(), t.into(), n.into()));
    }
    Ok(found)
}
fn nft_delete(ctx: &Context, r: &Rule) -> Result<()> {
    let out = ctx.run(
        "nft",
        &["-j", "-a", "list", "chain", &r.family, &r.table, &r.chain],
    )?;
    let doc: Value = serde_json::from_str(&out)?;
    let rows = doc["nftables"].as_array().ok_or("nft chain 格式无效")?;
    for row in rows {
        let rule = &row["rule"];
        if rule["comment"].as_str() == Some(r.token.as_str()) {
            let handle = rule["handle"]
                .as_u64()
                .ok_or("nft handle 无效")?
                .to_string();
            ctx.run(
                "nft",
                &[
                    "delete", "rule", &r.family, &r.table, &r.chain, "handle", &handle,
                ],
            )?;
        }
    }
    Ok(())
}
fn exists(ctx: &Context, r: &Rule) -> Result<bool> {
    let port = span(r, ":");
    let pn = format!(
        "{}/{}",
        span(r, if r.backend == "ufw" { ":" } else { "-" }),
        proto(r.udp)
    );
    match r.backend.as_str() {
        "iptables" | "ip6tables" => {
            let q = ctx.output(
                &r.backend,
                &[
                    "-w",
                    "5",
                    "-C",
                    "INPUT",
                    "-p",
                    proto(r.udp),
                    "--dport",
                    &port,
                    "-m",
                    "comment",
                    "--comment",
                    &r.token,
                    "-j",
                    "ACCEPT",
                ],
            )?;
            if q.code > 1 {
                return Err("无法检查 iptables 规则".into());
            }
            Ok(q.success())
        }
        "firewalld" => {
            let z = format!("--zone={}", r.zone);
            let q = format!("--query-port={pn}");
            let mut args = vec![z.as_str(), q.as_str()];
            if r.permanent {
                args.push("--permanent")
            }
            let out = ctx.output("firewall-cmd", &args)?;
            if out.code > 1 {
                return Err("无法检查 firewalld 规则".into());
            }
            Ok(out.success())
        }
        "ufw" => Ok(ctx
            .run("ufw", &["status", "numbered"])?
            .lines()
            .any(|l| l.contains(&r.token))),
        "nft" => {
            let out = ctx.run(
                "nft",
                &["-j", "list", "chain", &r.family, &r.table, &r.chain],
            )?;
            let doc: Value = serde_json::from_str(&out)?;
            Ok(doc["nftables"]
                .as_array()
                .ok_or("nft chain格式无效")?
                .iter()
                .any(|row| row["rule"]["comment"].as_str() == Some(r.token.as_str())))
        }
        _ => Err("未知防火墙台账类型".into()),
    }
}
fn remove(ctx: &Context, r: &Rule) -> Result<()> {
    let port = span(r, ":");
    let pn = format!(
        "{}/{}",
        span(r, if r.backend == "ufw" { ":" } else { "-" }),
        proto(r.udp)
    );
    match r.backend.as_str() {
        "iptables" | "ip6tables" => {
            let args = [
                "-w",
                "5",
                "-C",
                "INPUT",
                "-p",
                proto(r.udp),
                "--dport",
                &port,
                "-m",
                "comment",
                "--comment",
                &r.token,
                "-j",
                "ACCEPT",
            ];
            let q = ctx.output(&r.backend, &args)?;
            if q.code == 1 {
                return Ok(());
            }
            if !q.success() {
                return Err("无法检查已有 iptables 规则".into());
            }
            let mut args = args.to_vec();
            args[2] = "-D";
            ctx.run(&r.backend, &args)?;
        }
        "firewalld" => {
            let zone = format!("--zone={}", r.zone);
            let query = format!("--query-port={pn}");
            let mut args = vec![zone.as_str(), query.as_str()];
            if r.permanent {
                args.push("--permanent")
            }
            let q = ctx.output("firewall-cmd", &args)?;
            if q.code == 1 {
                return Ok(());
            }
            if !q.success() {
                return Err("无法检查已有 firewalld 规则".into());
            }
            let rm = format!("--remove-port={pn}");
            args[1] = &rm;
            ctx.run("firewall-cmd", &args)?;
        }
        "ufw" => {
            let out = ctx.run("ufw", &["status", "numbered"])?;
            let mut numbers = out
                .lines()
                .filter(|l| l.contains(&r.token))
                .filter_map(|l| {
                    l.trim()
                        .strip_prefix('[')
                        .and_then(|l| l.split_once(']'))
                        .and_then(|(n, _)| n.trim().parse::<u32>().ok())
                })
                .collect::<Vec<_>>();
            numbers.sort_unstable_by(|a, b| b.cmp(a));
            for n in numbers {
                ctx.run("ufw", &["--force", "delete", &n.to_string()])?;
            }
        }
        "nft" => nft_delete(ctx, r)?,
        _ => return Err("未知防火墙台账类型".into()),
    }
    Ok(())
}
fn append_created(ctx: &Context, owner: &str, ledger: &mut Ledger, rule: Rule) -> Result<()> {
    ledger.rules.push(rule.clone());
    if let Err(e) = save(ctx, owner, ledger) {
        ledger.rules.pop();
        if let Err(cleanup) = remove(ctx, &rule) {
            return Err(format!("台账保存失败: {e}；新规则清理失败: {cleanup}").into());
        }
        return Err(e);
    }
    Ok(())
}
fn create(ctx: &Context, r: &Rule) -> Result<bool> {
    let port = span(r, ":");
    let pn = format!(
        "{}/{}",
        span(r, if r.backend == "ufw" { ":" } else { "-" }),
        proto(r.udp)
    );
    match r.backend.as_str() {
        "iptables" | "ip6tables" => {
            ctx.run(
                &r.backend,
                &[
                    "-w",
                    "5",
                    "-I",
                    "INPUT",
                    "1",
                    "-p",
                    proto(r.udp),
                    "--dport",
                    &port,
                    "-m",
                    "comment",
                    "--comment",
                    &r.token,
                    "-j",
                    "ACCEPT",
                ],
            )?;
        }
        "firewalld" => {
            let z = format!("--zone={}", r.zone);
            let q = format!("--query-port={pn}");
            let mut args = vec![z.as_str(), q.as_str()];
            if r.permanent {
                args.push("--permanent")
            }
            let exists = ctx.output("firewall-cmd", &args)?;
            if exists.success() {
                return Ok(false);
            }
            if exists.code != 1 {
                return Err("firewalld 查询失败，未变更规则".into());
            }
            let add = format!("--add-port={pn}");
            args[1] = &add;
            ctx.run("firewall-cmd", &args)?;
        }
        "ufw" => {
            ctx.run("ufw", &["allow", &pn, "comment", &r.token])?;
        }
        "nft" => {
            ctx.run(
                "nft",
                &[
                    "insert",
                    "rule",
                    &r.family,
                    &r.table,
                    &r.chain,
                    proto(r.udp),
                    "dport",
                    &span(r, "-"),
                    "accept",
                    "comment",
                    &format!("\"{}\"", r.token),
                ],
            )?;
        }
        _ => return Err("未知防火墙后端".into()),
    }
    Ok(true)
}
fn backends(ctx: &Context) -> Result<Vec<Rule>> {
    let base = Rule {
        backend: String::new(),
        port: 0,
        end: 0,
        udp: false,
        zone: String::new(),
        family: String::new(),
        table: String::new(),
        chain: String::new(),
        token: String::new(),
        permanent: false,
    };
    if platform::has("ufw") {
        let o = ctx.output("ufw", &["status"])?;
        if o.success() && o.stdout.lines().any(|l| l.trim() == "Status: active") {
            return Ok(vec![Rule {
                backend: "ufw".into(),
                ..base
            }]);
        }
    }
    if platform::has("firewall-cmd") {
        let o = ctx.output("firewall-cmd", &["--state"])?;
        if o.success() && o.stdout.trim() == "running" {
            let active = ctx.run("firewall-cmd", &["--get-active-zones"])?;
            let mut zones = active
                .lines()
                .filter(|l| !l.starts_with(char::is_whitespace) && !l.trim().is_empty())
                .map(|l| l.split_whitespace().next().unwrap().to_owned())
                .collect::<Vec<_>>();
            if zones.is_empty() {
                zones.push(
                    ctx.run("firewall-cmd", &["--get-default-zone"])?
                        .trim()
                        .into(),
                )
            }
            let mut out = vec![];
            for zone in zones {
                if !nft_word(&zone) {
                    return Err("firewalld zone 无效".into());
                }
                for permanent in [false, true] {
                    out.push(Rule {
                        backend: "firewalld".into(),
                        zone: zone.clone(),
                        permanent,
                        ..base.clone()
                    });
                }
            }
            return Ok(out);
        }
    }
    // A native nft ruleset may contain multiple input base chains: all must allow the port.
    if platform::has("nft") {
        let chains = nft_chains(ctx)?;
        if !chains.is_empty() {
            return Ok(chains
                .into_iter()
                .map(|(family, table, chain)| Rule {
                    backend: "nft".into(),
                    family,
                    table,
                    chain,
                    ..base.clone()
                })
                .collect());
        }
    }
    let mut out = vec![];
    for binary in ["iptables", "ip6tables"] {
        if platform::has(binary) && (binary != "ip6tables" || ipv6_available()) {
            ctx.run(binary, &["-w", "5", "-S", "INPUT"])?;
            out.push(Rule {
                backend: binary.into(),
                ..base.clone()
            });
        }
    }
    Ok(out)
}
/// bool=true denotes UDP. Existing administrator rules are never adopted.
pub fn apply_ports(ctx: &Context, owner: &str, ports: &[(u16, bool)]) -> Result<()> {
    owner_valid(owner)?;
    if ports.iter().any(|(p, _)| *p == 0) {
        return Err("防火墙端口不能为0".into());
    }
    let _lock = lock(ctx, owner)?;
    let wanted = ports.iter().copied().collect::<BTreeSet<_>>();
    let mut ledger = load(ctx, owner)?;
    let backends = backends(ctx)?;
    let grouped = ranges(&wanted);
    for (port, end, udp) in grouped.iter().copied() {
        for b in &backends {
            if let Some(r) = ledger.rules.iter().find(|r| {
                r.port == port
                    && r.end.max(r.port) == end
                    && r.udp == udp
                    && r.backend == b.backend
                    && r.family == b.family
                    && r.table == b.table
                    && r.chain == b.chain
                    && r.zone == b.zone
                    && r.permanent == b.permanent
            }) {
                if !exists(ctx, r)? {
                    create(ctx, r)?;
                }
                continue;
            }
            let r = Rule {
                port,
                end,
                udp,
                token: format!("onebox-{owner}-{}", util::random_hex(8)?),
                ..b.clone()
            };
            if create(ctx, &r)? {
                append_created(ctx, owner, &mut ledger, r)?;
            }
        }
    }
    let mut i = 0;
    while i < ledger.rules.len() {
        if !grouped.contains(&(
            ledger.rules[i].port,
            ledger.rules[i].end.max(ledger.rules[i].port),
            ledger.rules[i].udp,
        )) {
            remove(ctx, &ledger.rules[i])?;
            ledger.rules.remove(i);
            save(ctx, owner, &ledger)?;
        } else {
            i += 1
        }
    }
    save(ctx, owner, &ledger)
}
pub fn clear_owner(ctx: &Context, owner: &str) -> Result<()> {
    owner_valid(owner)?;
    let _lock = lock(ctx, owner)?;
    let mut ledger = load(ctx, owner)?;
    let mut failed = Vec::new();
    let mut i = 0;
    while i < ledger.rules.len() {
        match remove(ctx, &ledger.rules[i]) {
            Ok(()) => {
                ledger.rules.remove(i);
                save(ctx, owner, &ledger)?;
            }
            Err(e) => {
                failed.push(e.to_string());
                i += 1
            }
        }
    }
    if failed.is_empty() {
        Ok(())
    } else {
        Err(format!("部分规则未清理，已保留台账: {}", failed.join("; ")).into())
    }
}
pub fn port_in_use(port: u16, udp: bool) -> bool {
    if port == 0 {
        return true;
    }
    let hex = format!("{port:04X}");
    let files = if udp {
        ["/proc/net/udp", "/proc/net/udp6"]
    } else {
        ["/proc/net/tcp", "/proc/net/tcp6"]
    };
    let mut readable = false;
    for file in files {
        if let Ok(s) = fs::read_to_string(file) {
            readable = true;
            for line in s.lines().skip(1) {
                let f = line.split_whitespace().collect::<Vec<_>>();
                if f.len() > 3
                    && f[1].rsplit(':').next() == Some(hex.as_str())
                    && (udp || f[3] == "0A")
                {
                    return true;
                }
            }
        }
    }
    if readable {
        return false;
    }
    if udp {
        UdpSocket::bind(("0.0.0.0", port)).is_err()
    } else {
        TcpListener::bind(("0.0.0.0", port)).is_err()
    }
}
fn hop_path(ctx: &Context) -> PathBuf {
    ctx.paths.root.join("hop-v2.json")
}
#[derive(Serialize, Deserialize, Clone)]
struct Hop {
    backend: String,
    start: u16,
    end: u16,
    target: u16,
    token: String,
}
fn remove_hop(ctx: &Context, hop: &Hop) -> Result<()> {
    if hop.backend == "nft" {
        if !nft_word(&hop.token) {
            return Err("跳跃表名称无效".into());
        }
        let doc: Value = serde_json::from_str(&ctx.run("nft", &["-j", "list", "tables"])?)?;
        for family in ["ip", "ip6", "inet"] {
            if doc["nftables"]
                .as_array()
                .ok_or("nft tables格式错误")?
                .iter()
                .any(|row| {
                    row["table"]["family"] == family
                        && row["table"]["name"].as_str() == Some(hop.token.as_str())
                })
            {
                ctx.run("nft", &["delete", "table", family, &hop.token])?;
            }
        }
        return Ok(());
    }
    let range = format!("{}:{}", hop.start, hop.end);
    let target = hop.target.to_string();
    let args = [
        "-w",
        "5",
        "-t",
        "nat",
        "-C",
        "PREROUTING",
        "-p",
        "udp",
        "--dport",
        &range,
        "-m",
        "addrtype",
        "--dst-type",
        "LOCAL",
        "-m",
        "comment",
        "--comment",
        &hop.token,
        "-j",
        "REDIRECT",
        "--to-ports",
        &target,
    ];
    let q = ctx.output(&hop.backend, &args)?;
    if q.code == 1 {
        return Ok(());
    }
    if !q.success() {
        return Err("无法读取跳跃规则".into());
    }
    let mut args = args.to_vec();
    args[4] = "-D";
    ctx.run(&hop.backend, &args)?;
    Ok(())
}
pub fn clear_hops(ctx: &Context) -> Result<()> {
    let path = hop_path(ctx);
    if !path.exists() {
        return Ok(());
    }
    let mut hops: Vec<Hop> = serde_json::from_slice(&fs::read(&path)?)?;
    while let Some(h) = hops.first() {
        remove_hop(ctx, h)?;
        hops.remove(0);
        util::atomic_write(&path, &serde_json::to_vec(&hops)?, 0o600)?;
    }
    Ok(())
}
/// Retire rules with the v1 ownership marker and its explicit plain-rule ledger.
/// Never infer ownership from a listening port alone.
fn migrate_legacy(ctx: &Context) -> Result<()> {
    let marker = ctx.paths.root.join("firewall-v1-migrated");
    if marker.exists() || !ctx.paths.legacy_state().exists() {
        return Ok(());
    }
    for backend in ["iptables", "ip6tables"] {
        if !platform::has(backend) || (backend == "ip6tables" && !ipv6_available()) {
            continue;
        }
        for (table, chain) in [("filter", "INPUT"), ("nat", "PREROUTING")] {
            let text = ctx.run(backend, &["-w", "5", "-t", table, "-S", chain])?;
            for line in text.lines() {
                let words = line
                    .split_whitespace()
                    .map(|s| s.trim_matches('"').to_owned())
                    .collect::<Vec<_>>();
                if words.len() < 3 || words[0] != "-A" || words[1] != chain {
                    continue;
                }
                if !words.windows(2).any(|w| {
                    w[0] == "--comment" && matches!(w[1].as_str(), "onebox" | "onebox-hop")
                }) {
                    continue;
                }
                let mut args = vec![
                    "-w".into(),
                    "5".into(),
                    "-t".into(),
                    table.into(),
                    "-D".into(),
                ];
                args.extend(words.into_iter().skip(1));
                ctx.run_args(backend, &args)?;
            }
        }
    }
    if platform::has("nft") {
        let rules: Value =
            serde_json::from_str(&ctx.run("nft", &["-j", "-a", "list", "ruleset"])?)?;
        for row in rules["nftables"].as_array().ok_or("旧 nft ruleset 无效")? {
            let r = &row["rule"];
            if r["comment"] != "onebox" {
                continue;
            }
            let family = r["family"].as_str().ok_or("旧规则family缺失")?;
            let table = r["table"].as_str().ok_or("旧规则table缺失")?;
            let chain = r["chain"].as_str().ok_or("旧规则chain缺失")?;
            let handle = r["handle"].as_u64().ok_or("旧规则handle缺失")?.to_string();
            if ![family, table, chain].iter().all(|s| nft_word(s)) {
                return Err("旧规则名称无效".into());
            }
            ctx.run(
                "nft",
                &["delete", "rule", family, table, chain, "handle", &handle],
            )?;
        }
        for row in rules["nftables"].as_array().ok_or("旧 nft ruleset 无效")? {
            let table = &row["table"];
            if table["name"] == "onebox_hop" {
                let family = table["family"].as_str().ok_or("旧NAT family缺失")?;
                if matches!(family, "ip" | "ip6") {
                    ctx.run("nft", &["delete", "table", family, "onebox_hop"])?;
                }
            }
        }
    }
    let legacy = ctx.paths.root.join("firewall.list");
    if legacy.is_file() {
        let content = fs::read_to_string(&legacy)?;
        let mut remaining = content
            .lines()
            .filter(|line| !line.trim().is_empty())
            .map(str::to_owned)
            .collect::<Vec<_>>();
        while let Some(line) = remaining.first().cloned() {
            let words = line.split_whitespace().collect::<Vec<_>>();
            if words.len() != 2 {
                return Err("旧防火墙台账格式无效".into());
            }
            let (range, transport) = words[1].split_once('/').ok_or("旧防火墙端口无效")?;
            if !matches!(transport, "tcp" | "udp")
                || !range
                    .split('-')
                    .all(|s| s.parse::<u16>().ok().filter(|p| *p > 0).is_some())
            {
                return Err("旧防火墙范围无效".into());
            }
            let converted = range.replace('-', ":");
            match words[0] {
                "ufw" => {
                    if platform::has("ufw") {
                        ctx.run(
                            "ufw",
                            &[
                                "--force",
                                "delete",
                                "allow",
                                &format!("{converted}/{transport}"),
                            ],
                        )?;
                    }
                }
                "firewalld" => {
                    if platform::has("firewall-cmd") {
                        let mut zone = ctx
                            .run("firewall-cmd", &["--get-default-zone"])?
                            .trim()
                            .to_owned();
                        for family in ["-4", "-6"] {
                            let routes = ctx.run("ip", &[family, "route", "show", "default"])?;
                            let words = routes.split_whitespace().collect::<Vec<_>>();
                            if let Some(i) = words.iter().position(|w| *w == "dev") {
                                if let Some(dev) = words.get(i + 1) {
                                    let out = ctx.output(
                                        "firewall-cmd",
                                        &[&format!("--get-zone-of-interface={dev}")],
                                    )?;
                                    if out.success() && !out.stdout.trim().is_empty() {
                                        zone = out.stdout.trim().into();
                                    }
                                    break;
                                }
                            }
                        }
                        for permanent in [false, true] {
                            let mut args = vec![
                                format!("--zone={zone}"),
                                format!("--query-port={range}/{transport}"),
                            ];
                            if permanent {
                                args.push("--permanent".into())
                            }
                            let q = ctx.output(
                                "firewall-cmd",
                                &args.iter().map(String::as_str).collect::<Vec<_>>(),
                            )?;
                            if q.success() {
                                args[1] = format!("--remove-port={range}/{transport}");
                                ctx.run_args("firewall-cmd", &args)?;
                            } else if q.code != 1 {
                                return Err("旧firewalld规则查询失败".into());
                            }
                        }
                    }
                }
                "iptables" | "ip6tables" => {
                    if platform::has(words[0]) {
                        let q = ctx.output(
                            words[0],
                            &[
                                "-w", "5", "-C", "INPUT", "-p", transport, "--dport", &converted,
                                "-j", "ACCEPT",
                            ],
                        )?;
                        if q.success() {
                            ctx.run(
                                words[0],
                                &[
                                    "-w", "5", "-D", "INPUT", "-p", transport, "--dport",
                                    &converted, "-j", "ACCEPT",
                                ],
                            )?;
                        } else if q.code != 1 {
                            return Err("旧iptables规则查询失败".into());
                        }
                    }
                }
                _ => return Err("旧防火墙台账类型无效".into()),
            }
            remaining.remove(0);
            util::atomic_write(
                &legacy,
                format!("{}\n", remaining.join("\n"))
                    .trim_start_matches('\n')
                    .as_bytes(),
                0o600,
            )?;
        }
    }
    util::atomic_write(&marker, b"v2\n", 0o600)
}
fn configure_hops(ctx: &Context, state: &State) -> Result<()> {
    if !state.enabled(Protocol::Hysteria2) || state.get("HY2_HOP").is_empty() {
        return clear_hops(ctx);
    }
    let (start, end) = state
        .get("HY2_HOP")
        .split_once('-')
        .ok_or("跳跃范围格式无效")?;
    let start: u16 = start.parse()?;
    let end: u16 = end.parse()?;
    if start < 1024 || start >= end {
        return Err("跳跃范围必须为1024以上递增端口".into());
    }
    clear_hops(ctx)?;
    let mut hops = vec![];
    if platform::has("nft") {
        let target = state.port(Protocol::Hysteria2);
        let token = format!("onebox_hop_{}", util::random_hex(8)?);
        let families = if ipv6_available() {
            vec!["ip", "ip6"]
        } else {
            vec!["ip"]
        };
        let script=families.iter().map(|family|format!("table {family} {token} {{ chain prerouting {{ type nat hook prerouting priority -100; policy accept; fib daddr type local udp dport {start}-{end} redirect to :{target}; }} }}\n")).collect::<String>();
        let file = ctx
            .paths
            .root
            .join(format!(".nft-{}", util::random_hex(8)?));
        util::atomic_write(&file, script.as_bytes(), 0o600)?;
        let result = ctx.run("nft", &["-f", util::path_str(&file)?]);
        let _ = fs::remove_file(file);
        result?;
        let h = Hop {
            backend: "nft".into(),
            start,
            end,
            target,
            token,
        };
        hops.push(h.clone());
        if let Err(e) = util::atomic_write(&hop_path(ctx), &serde_json::to_vec(&hops)?, 0o600) {
            let _ = remove_hop(ctx, &h);
            return Err(e);
        }
        return Ok(());
    }
    for binary in ["iptables", "ip6tables"] {
        if !platform::has(binary) || (binary == "ip6tables" && !ipv6_available()) {
            continue;
        }
        let target = state.port(Protocol::Hysteria2);
        let token = format!("onebox-hop-{}", util::random_hex(8)?);
        let range = format!("{start}:{end}");
        let target_s = target.to_string();
        ctx.run(
            binary,
            &[
                "-w",
                "5",
                "-t",
                "nat",
                "-A",
                "PREROUTING",
                "-p",
                "udp",
                "--dport",
                &range,
                "-m",
                "addrtype",
                "--dst-type",
                "LOCAL",
                "-m",
                "comment",
                "--comment",
                &token,
                "-j",
                "REDIRECT",
                "--to-ports",
                &target_s,
            ],
        )?;
        let h = Hop {
            backend: binary.into(),
            start,
            end,
            target,
            token,
        };
        hops.push(h.clone());
        if let Err(e) = util::atomic_write(&hop_path(ctx), &serde_json::to_vec(&hops)?, 0o600) {
            let _ = remove_hop(ctx, &h);
            return Err(e);
        }
    }
    if hops.is_empty() {
        return Err("端口跳跃需要 nft 或 iptables/ip6tables".into());
    }
    Ok(())
}
pub fn desired_ports(state: &State) -> Result<Vec<(u16, bool)>> {
    let mut ports = BTreeSet::new();
    for p in state.protocols() {
        if p.network() != "udp" {
            ports.insert((state.port(p), false));
        }
        if p.network() != "tcp" {
            ports.insert((state.port(p), true));
        }
    }
    if state.flag("SUBSCRIPTION_ENABLED") && state.get("SUBSCRIPTION_MODE") == "standalone" {
        ports.insert((state.number("SUBSCRIPTION_PORT", 443), false));
        if state.flag("SUBSCRIPTION_HTTP") {
            ports.insert((80, false));
        }
    }
    if state.site_enabled() {
        ports.insert((80, false));
        if state.flag("REALITY_SITE_HTTPS") {
            ports.insert((443, false));
        }
    }
    if state.get("TLS_MODE") == "acme" && state.get("ACME_METHOD") == "standalone" {
        ports.insert((80, false));
    }
    if state.enabled(Protocol::Hysteria2) && !state.get("HY2_HOP").is_empty() {
        let (a, b) = state.get("HY2_HOP").split_once('-').ok_or("跳跃范围错误")?;
        let (a, b) = (a.parse::<u16>()?, b.parse::<u16>()?);
        if a < 1024 || a >= b {
            return Err("跳跃范围错误".into());
        }
        for p in a..=b {
            ports.insert((p, true));
        }
    }
    Ok(ports.into_iter().collect())
}
pub fn apply(ctx: &Context, state: &State) -> Result<()> {
    migrate_legacy(ctx)?;
    apply_ports(ctx, "proxy", &desired_ports(state)?)?;
    configure_hops(ctx, state)?;
    platform::write_service(
        ctx,
        "onebox-network",
        &ctx.paths.executable,
        &["net-apply".into()],
        &[],
    )?;
    platform::service(ctx, "onebox-network", "enable")
}
pub fn clear(ctx: &Context) -> Result<()> {
    let rules = clear_rules(ctx);
    let service = platform::service(ctx, "onebox-network", "remove");
    rules.and(service)
}
/// Remove owned rules without stopping a network-restoration process that may
/// currently be rolling its own transaction back during boot.
pub fn clear_rules(ctx: &Context) -> Result<()> {
    migrate_legacy(ctx)?;
    let a = clear_hops(ctx);
    let b = clear_owner(ctx, "proxy");
    a.and(b)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn port_policy_tracks_transport() {
        let mut s = State::default();
        s.set("PROTOCOLS", "anytls-reality hysteria2");
        s.set_port(Protocol::AnytlsReality, 443);
        s.set_port(Protocol::Hysteria2, 443);
        assert_eq!(desired_ports(&s).unwrap(), vec![(443, false), (443, true)]);
        s.set("REALITY_SITE_ENABLED", "1");
        s.set("REALITY_SITE_HTTPS", "1");
        assert!(desired_ports(&s).unwrap().contains(&(80, false)));
    }
    #[test]
    fn reject_hop_overflow() {
        let mut s = State::default();
        s.set("PROTOCOLS", "hysteria2");
        s.set("HY2_HOP", "65000-99999");
        assert!(desired_ports(&s).is_err());
    }
    #[test]
    fn reject_owner_injection() {
        assert!(owner_valid("frp").is_ok());
        assert!(owner_valid("../frp").is_err());
    }
}

#[cfg(test)]
mod failure_tests {
    use super::*;
    use crate::context::{CommandOutput, Paths, Runner};
    use std::sync::{Arc, Mutex};
    struct Mock {
        calls: Mutex<Vec<Vec<String>>>,
    }
    impl Runner for Mock {
        fn output(&self, _: &str, args: &[String]) -> Result<CommandOutput> {
            self.calls.lock().unwrap().push(args.to_vec());
            Ok(CommandOutput {
                code: if args.iter().any(|a| a == "-D") && args.iter().any(|a| a == "443") {
                    7
                } else {
                    0
                },
                stdout: String::new(),
                stderr: String::new(),
            })
        }
    }
    fn rule(port: u16) -> Rule {
        Rule {
            backend: "iptables".into(),
            port,
            end: port,
            udp: false,
            zone: String::new(),
            family: String::new(),
            table: String::new(),
            chain: String::new(),
            token: format!("onebox-test-{port}"),
            permanent: false,
        }
    }
    #[test]
    fn failed_cleanup_retains_only_failed_owned_rule() {
        let root = std::env::temp_dir().join(format!(
            "onebox-network-test-{}",
            util::random_hex(8).unwrap()
        ));
        let mock = Arc::new(Mock {
            calls: Mutex::new(vec![]),
        });
        let ctx = Context {
            paths: Paths::isolated(&root),
            runner: mock.clone(),
            yes: true,
        };
        save(
            &ctx,
            "proxy",
            &Ledger {
                rules: vec![rule(443), rule(8443)],
            },
        )
        .unwrap();
        assert!(clear_owner(&ctx, "proxy").is_err());
        let left = load(&ctx, "proxy").unwrap();
        assert_eq!(left.rules.len(), 1);
        assert_eq!(left.rules[0].port, 443);
        for call in mock.calls.lock().unwrap().iter() {
            assert!(call.iter().any(|a| a == "--comment"));
            assert!(call.iter().any(|a| a.starts_with("onebox-test-")));
        }
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn contiguous_ports_are_compressed_without_merging_transports() {
        let ports = [(80, false), (81, false), (82, true), (83, true), (85, true)]
            .into_iter()
            .collect();
        assert_eq!(
            ranges(&ports),
            vec![(80, 81, false), (82, 83, true), (85, 85, true)]
        );
    }
    #[test]
    fn actual_rule_query_does_not_trust_saved_ledger() {
        struct Missing;
        impl Runner for Missing {
            fn output(&self, _: &str, _: &[String]) -> Result<CommandOutput> {
                Ok(CommandOutput {
                    code: 1,
                    ..Default::default()
                })
            }
        }
        let ctx = Context {
            runner: Arc::new(Missing),
            ..Context::default()
        };
        assert!(!exists(&ctx, &rule(443)).unwrap());
    }
    #[test]
    fn subscription_ports_are_included_only_for_standalone() {
        let mut s = State::default();
        s.set("SUBSCRIPTION_ENABLED", "1");
        s.set("SUBSCRIPTION_MODE", "standalone");
        s.set("SUBSCRIPTION_PORT", "8443");
        s.set("SUBSCRIPTION_HTTP", "1");
        assert_eq!(desired_ports(&s).unwrap(), vec![(80, false), (8443, false)]);
        s.set("SUBSCRIPTION_MODE", "site");
        assert!(desired_ports(&s).unwrap().is_empty());
    }
}
