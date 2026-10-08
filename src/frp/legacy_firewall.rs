//! Import cleanup for the v1 FRP firewall ownership ledger. No shell is used.
use super::*;

#[derive(Debug, PartialEq, Eq)]
struct Entry {
    backend: String,
    port: String,
    proto: String,
    extra: Vec<String>,
}
fn identifier(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b))
}
fn parse(line: &str) -> Result<Entry> {
    let words: Vec<_> = line.split_whitespace().collect();
    if words.len() < 2 {
        return Err("旧 FRP 防火墙台账格式无效".into());
    }
    let (port, proto) = words[1].split_once('/').ok_or("旧防火墙台账缺少协议")?;
    if !["tcp", "udp"].contains(&proto) {
        return Err("旧防火墙台账协议无效".into());
    }
    let bounds: Vec<_> = port
        .split('-')
        .map(str::parse::<u16>)
        .collect::<std::result::Result<_, _>>()?;
    if bounds.is_empty()
        || bounds.len() > 2
        || bounds[0] == 0
        || bounds.last().unwrap() < &bounds[0]
    {
        return Err("旧防火墙端口范围无效".into());
    }
    match words[0] {
        "ufw" | "iptables" | "ip6tables" => {
            if words.len() != 2 {
                return Err("旧防火墙参数数量错误".into());
            }
        }
        "firewalld" => {
            if words.len() != 4
                || !identifier(words[2])
                || !["runtime", "permanent"].contains(&words[3])
            {
                return Err("旧 firewalld 台账无效".into());
            }
        }
        "nft" => {
            if words.len() != 5
                || !["ip", "ip6", "inet"].contains(&words[2])
                || !identifier(words[3])
                || !identifier(words[4])
            {
                return Err("旧 nft 台账无效".into());
            }
        }
        _ => return Err("未知旧防火墙后端".into()),
    }
    Ok(Entry {
        backend: words[0].into(),
        port: port.into(),
        proto: proto.into(),
        extra: words[2..].iter().map(|s| s.to_string()).collect(),
    })
}

fn close(ctx: &Context, e: &Entry) -> Result<()> {
    match e.backend.as_str() {
        "ufw" => {
            let listing = ctx.run("ufw", &["status", "numbered"])?;
            let expected = format!("{}/{}", e.port.replace('-', ":"), e.proto);
            let mut ids = Vec::new();
            for line in listing.lines() {
                let Some((body, comment)) = line.rsplit_once('#') else {
                    continue;
                };
                if comment.trim() != "onebox-frp"
                    || body.contains(" OUT ")
                    || body.contains(" FWD ")
                    || body.contains(" on ")
                {
                    continue;
                }
                let Some((index, rule)) = body
                    .trim()
                    .strip_prefix('[')
                    .and_then(|s| s.split_once(']'))
                else {
                    continue;
                };
                let words: Vec<_> = rule.split_whitespace().collect();
                if words.first() != Some(&expected.as_str())
                    || !words.contains(&"ALLOW")
                    || !words.contains(&"Anywhere")
                {
                    continue;
                }
                ids.push(index.trim().parse::<u32>()?);
            }
            ids.sort_unstable_by(|a, b| b.cmp(a));
            for id in ids {
                ctx.run("ufw", &["--force", "delete", &id.to_string()])?;
            }
        }
        "firewalld" => {
            let mut args = vec![format!("--zone={}", e.extra[0])];
            if e.extra[1] == "permanent" {
                args.push("--permanent".into());
            }
            let query = format!("--query-port={}/{}", e.port, e.proto);
            let mut check = args.clone();
            check.push(query);
            let o = ctx.runner.output("firewall-cmd", &check)?;
            match o.code {
                0 => {
                    args.push(format!("--remove-port={}/{}", e.port, e.proto));
                    ctx.run_args("firewall-cmd", &args)?;
                }
                1 => {}
                _ => return Err(format!("无法查询旧 firewalld 规则: {}", o.stderr).into()),
            }
        }
        "iptables" | "ip6tables" => {
            let port = e.port.replace('-', ":");
            let args = [
                "-t",
                "filter",
                "-C",
                "INPUT",
                "-p",
                &e.proto,
                "--dport",
                &port,
                "-m",
                "comment",
                "--comment",
                "onebox-frp",
                "-j",
                "ACCEPT",
            ];
            for _ in 0..1024 {
                let o = ctx.output(&e.backend, &args)?;
                match o.code {
                    0 => {
                        let mut delete = args;
                        delete[2] = "-D";
                        ctx.run(&e.backend, &delete)?;
                    }
                    1 => return Ok(()),
                    _ => return Err(format!("无法查询旧 {} 规则: {}", e.backend, o.stderr).into()),
                }
            }
            return Err("旧防火墙有异常数量的重复规则".into());
        }
        "nft" => {
            let listing = ctx.run(
                "nft",
                &["-a", "list", "chain", &e.extra[0], &e.extra[1], &e.extra[2]],
            )?;
            let expected = format!("{} dport {} accept comment \"onebox-frp\"", e.proto, e.port);
            for line in listing.lines() {
                let Some((rule, handle)) = line.rsplit_once("# handle ") else {
                    continue;
                };
                if rule.trim() != expected {
                    continue;
                }
                let id = handle.trim().parse::<u64>()?;
                ctx.run(
                    "nft",
                    &[
                        "delete",
                        "rule",
                        &e.extra[0],
                        &e.extra[1],
                        &e.extra[2],
                        "handle",
                        &id.to_string(),
                    ],
                )?;
            }
        }
        _ => unreachable!(),
    }
    Ok(())
}

pub(super) fn clear(ctx: &Context) -> Result<()> {
    let path = ctx.paths.frp_root.join("firewall.list");
    util::safe_path(&path)?;
    if !path.exists() {
        return Ok(());
    }
    let text = fs::read_to_string(&path)?;
    if text.len() > 1024 * 1024 {
        return Err("旧防火墙台账异常大".into());
    }
    let mut lines = text
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(str::to_owned)
        .collect::<Vec<_>>();
    // Validate the entire file before performing any deletion.
    for line in &lines {
        parse(line)?;
    }
    while let Some(line) = lines.first() {
        close(ctx, &parse(line)?)?;
        lines.remove(0);
        let remaining = lines.join("\n") + if lines.is_empty() { "" } else { "\n" };
        util::atomic_write(&path, remaining.as_bytes(), 0o600)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ledger_is_strictly_validated() {
        assert!(parse("firewalld 20000-20100/udp public permanent").is_ok());
        assert!(parse("nft 443/tcp inet filter input").is_ok());
        assert!(parse("iptables 65536/tcp").is_err());
        assert!(parse("ufw 443/tcp extra").is_err());
        assert!(parse("nft 443/tcp inet filter;rm input").is_err());
        assert!(parse("firewalld 443/tcp public all").is_err());
        assert!(parse("iptables 100-1/tcp").is_err());
    }
}
