//! Certificate lifecycle. ACME is an external protocol client; all policy,
//! validation, deployment and renewal scheduling remain in this Rust module.
use crate::{context::Context, model::State, util, Result};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};

#[derive(Clone, Debug, Serialize, Deserialize)]
struct Certificate {
    domains: Vec<String>,
    method: String,
    webroot: Option<PathBuf>,
    source_cert: Option<PathBuf>,
    source_key: Option<PathBuf>,
    #[serde(default)]
    last_attempt: u64,
    #[serde(default)]
    last_success: u64,
    #[serde(default)]
    last_error: Option<String>,
}
fn metadata(dir: &Path) -> PathBuf {
    dir.join("certificate.json")
}
fn save(dir: &Path, m: &Certificate) -> Result<()> {
    util::atomic_write(&metadata(dir), &serde_json::to_vec_pretty(m)?, 0o600)
}
fn legacy_home() -> PathBuf {
    std::env::var_os("ACME_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| "/root/.acme.sh".into())
}
fn deployment_values(text: &str) -> Result<std::collections::BTreeMap<String, String>> {
    let mut values = std::collections::BTreeMap::new();
    for line in text.lines() {
        let Some((key, value)) = line.trim().split_once('=') else {
            continue;
        };
        if [
            "Le_RealCertPath",
            "Le_RealCACertPath",
            "Le_RealKeyPath",
            "Le_RealFullChainPath",
            "Le_ReloadCmd",
        ]
        .contains(&key)
            && values
                .insert(key.into(), crate::state::shell_literal(value)?)
                .is_some()
        {
            return Err("旧 ACME 部署字段重复，停止迁移".into());
        }
    }
    Ok(values)
}
fn deployment_marker(ctx: &Context) -> String {
    format!(
        "# onebox-rust-retired-deployment={}",
        ctx.paths.tls().display()
    )
}
fn old_deployment_owned(ctx: &Context, text: &str, old_state: bool) -> Result<bool> {
    let marked = text.lines().any(|line| line == deployment_marker(ctx));
    if !marked && (!old_state || !text.contains(util::path_str(&ctx.paths.tls())?)) {
        return Ok(false);
    }
    let values = deployment_values(text)?;
    let get = |key: &str| values.get(key).map(String::as_str).unwrap_or("");
    if !get("Le_RealCertPath").is_empty() || !get("Le_RealCACertPath").is_empty() {
        return Ok(false);
    }
    let full = ctx.paths.tls().join("cert.pem");
    let key = ctx.paths.tls().join("key.pem");
    let exact = get("Le_RealFullChainPath") == util::path_str(&full)?
        && get("Le_RealKeyPath") == util::path_str(&key)?;
    Ok((old_state && exact)
        || (marked
            && (exact
                || (get("Le_RealFullChainPath").is_empty() && get("Le_RealKeyPath").is_empty()))))
}
/// Only exact Onebox certificate deployments are included. Retired markers
/// remain discoverable after state migration so an interrupted commit can
/// still restore the same external files from its transaction snapshot.
pub fn legacy_deployment_paths(ctx: &Context) -> Result<Vec<PathBuf>> {
    let home = legacy_home();
    legacy_deployment_paths_in(ctx, &home)
}
fn legacy_deployment_paths_in(ctx: &Context, home: &Path) -> Result<Vec<PathBuf>> {
    if !home.exists() {
        return Ok(Vec::new());
    }
    util::safe_path(home)?;
    let old_state = ctx.paths.legacy_state().is_file();
    let mut result = Vec::new();
    for entry in fs::read_dir(home)? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().to_string();
        let Some(domain) = name.strip_suffix("_ecc") else {
            continue;
        };
        if !util::valid_domain(domain) || !entry.file_type()?.is_dir() {
            continue;
        }
        let path = entry.path().join(format!("{domain}.conf"));
        if !path.is_file() {
            continue;
        }
        util::safe_path(&path)?;
        if fs::metadata(&path)?.len() > 256 * 1024 {
            return Err("旧 ACME 域名配置过大".into());
        }
        let text = fs::read_to_string(&path)?;
        if old_deployment_owned(ctx, &text, old_state)? {
            result.push(path);
        }
    }
    result.sort();
    Ok(result)
}
/// Keep shared ACME cron and every other domain intact. Disable only deployment
/// to Onebox-owned cert/key paths; issuance/account data remains available.
pub fn disable_legacy_deployments(ctx: &Context) -> Result<()> {
    for path in legacy_deployment_paths(ctx)? {
        disable_legacy_file(ctx, &path)?;
    }
    Ok(())
}
fn disable_legacy_file(ctx: &Context, path: &Path) -> Result<()> {
    let text = fs::read_to_string(path)?;
    let values = deployment_values(&text)?;
    if let Some(reload) = values.get("Le_ReloadCmd").filter(|v| !v.is_empty()) {
        let decoded = if let Some(encoded) = reload
            .strip_prefix("__ACME_BASE64__START_")
            .and_then(|v| v.strip_suffix("__ACME_BASE64__END_"))
        {
            use base64::Engine;
            String::from_utf8(base64::engine::general_purpose::STANDARD.decode(encoded)?)?
        } else {
            reload.clone()
        };
        let expected = format!(
            "{} restart >/dev/null 2>&1 || true",
            ctx.paths.executable.display()
        );
        if decoded != expected && decoded != "/usr/local/bin/onebox restart >/dev/null 2>&1 || true"
        {
            return Err(
                "旧 Onebox ACME 配置包含自定义 reload 命令，请先检查该域名的部署钩子".into(),
            );
        }
    }
    let mut output = String::new();
    let marker = deployment_marker(ctx);
    for line in text.lines() {
        if line == marker {
            continue;
        }
        if let Some((key, _)) = line.trim().split_once('=') {
            if ["Le_RealKeyPath", "Le_RealFullChainPath", "Le_ReloadCmd"].contains(&key) {
                output.push_str(&format!("{key}=''\n"));
                continue;
            }
        }
        output.push_str(line);
        output.push('\n');
    }
    output.push_str(&marker);
    output.push('\n');
    util::atomic_write(path, output.as_bytes(), 0o600)?;
    Ok(())
}
fn owned_dir(dir: &Path) -> Result<()> {
    util::safe_path(dir)?;
    fs::create_dir_all(dir)?;
    fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
    Ok(())
}
fn domain_valid(domain: &str) -> bool {
    domain.parse::<std::net::IpAddr>().is_ok()
        || util::valid_domain(domain.strip_prefix("*.").unwrap_or(domain))
}
fn check_domains(domains: &[String], method: &str) -> Result<()> {
    if domains.is_empty() || domains.len() > 32 {
        return Err("证书域名数量无效".into());
    }
    for domain in domains {
        if !domain_valid(domain)
            || (domain.parse::<std::net::IpAddr>().is_ok() && !matches!(method, "self" | "custom"))
        {
            return Err("证书域名无效".into());
        }
        if domain.starts_with("*.") && !matches!(method, "cf" | "custom" | "self") {
            return Err("泛域名需要 DNS 验证或自备证书".into());
        }
    }
    if !matches!(method, "self" | "http" | "standalone" | "cf" | "custom") {
        return Err("证书方式应为 self/http/standalone/cf/custom".into());
    }
    Ok(())
}
/// Validate dates, server purpose, names, and that the public keys match.
pub fn validate_pair(
    ctx: &Context,
    cert: &Path,
    key: &Path,
    domain: &str,
    public_trust: bool,
) -> Result<()> {
    if !domain_valid(domain) {
        return Err("证书域名无效".into());
    }
    if !cert.is_file() || !key.is_file() {
        return Err("证书或私钥文件不存在".into());
    }
    let cert_s = util::path_str(cert)?;
    let key_s = util::path_str(key)?;
    ctx.run(
        "openssl",
        &["x509", "-in", cert_s, "-noout", "-checkend", "0"],
    )?;
    let certificate_key = ctx.run("openssl", &["x509", "-in", cert_s, "-pubkey", "-noout"])?;
    let private_key = ctx.run("openssl", &["pkey", "-in", key_s, "-pubout"])?;
    if certificate_key.trim() != private_key.trim() {
        return Err("证书与私钥不匹配".into());
    }
    // verify_hostname checks OpenSSL's verification result; x509 -checkhost on
    // older OpenSSL can print a mismatch while exiting successfully.
    let check_name = domain
        .strip_prefix("*.")
        .map(|s| format!("onebox-cert-check.{s}"))
        .unwrap_or_else(|| domain.into());
    let verify_name = if domain.parse::<std::net::IpAddr>().is_ok() {
        "-verify_ip"
    } else {
        "-verify_hostname"
    };
    let mut args = vec!["verify", "-purpose", "sslserver", verify_name, &check_name];
    if public_trust {
        args.extend(["-untrusted", cert_s]);
    } else {
        args.extend(["-partial_chain", "-trusted", cert_s]);
    }
    args.push(cert_s);
    ctx.run("openssl", &args)?;
    if domain.starts_with("*.") {
        let san = ctx.run("openssl", &["x509", "-in", cert_s, "-noout", "-text"])?;
        if !san
            .split(|c: char| c == ',' || c.is_whitespace())
            .any(|v| v == format!("DNS:{domain}"))
        {
            return Err("证书缺少要求的泛域名 SAN".into());
        }
    }
    Ok(())
}
fn current_valid(
    ctx: &Context,
    dir: &Path,
    domains: &[String],
    public: bool,
    seconds: u32,
) -> bool {
    if domains.iter().any(|d| {
        validate_pair(ctx, &dir.join("cert.pem"), &dir.join("key.pem"), d, public).is_err()
    }) {
        return false;
    }
    ctx.output(
        "openssl",
        &[
            "x509",
            "-in",
            util::path_str(&dir.join("cert.pem")).unwrap_or(""),
            "-noout",
            "-checkend",
            &seconds.to_string(),
        ],
    )
    .map(|o| o.success())
    .unwrap_or(false)
}
fn cf_values(text: &str) -> std::collections::BTreeMap<String, String> {
    let mut values = std::collections::BTreeMap::new();
    for line in text.lines() {
        let Some((key, value)) = line.trim().split_once('=') else {
            continue;
        };
        let key = key.strip_prefix("SAVED_").unwrap_or(key);
        if ![
            "CF_Token",
            "CF_Key",
            "CF_Email",
            "CF_Account_ID",
            "CF_Zone_ID",
        ]
        .contains(&key)
        {
            continue;
        }
        let value = value.trim();
        let value = if value.len() >= 2
            && ((value.starts_with('\'') && value.ends_with('\''))
                || (value.starts_with('"') && value.ends_with('"')))
        {
            &value[1..value.len() - 1]
        } else {
            value
        };
        // Cloudflare tokens, IDs, API keys and email addresses need no shell
        // interpolation. Reject executable syntax instead of sourcing files.
        if !value.is_empty()
            && value.len() <= 1024
            && value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"@._+-".contains(&b))
        {
            values.insert(key.to_string(), value.to_string());
        }
    }
    values
}
/// Shared by proxy/site/subscription and FRP. Credentials stay in the process
/// environment and acme's private account file, never the main state or logs.
pub fn ensure_cf_credentials(ctx: &Context, directory: &Path) -> Result<()> {
    ensure_cf_credentials_from(ctx, directory, None)
}
fn ensure_cf_credentials_from(
    ctx: &Context,
    directory: &Path,
    legacy_home: Option<&Path>,
) -> Result<()> {
    let mut values = std::collections::BTreeMap::new();
    let mut accounts = vec![directory.join("acme/account.conf")];
    if let Some(parent) = directory.parent() {
        accounts.push(parent.join("acme/account.conf"));
    }
    if let Some(home) = legacy_home {
        accounts.push(home.join("account.conf"));
    }
    for account in accounts.into_iter().rev() {
        if let Ok(text) = fs::read_to_string(account) {
            values.extend(cf_values(&text));
        }
    }
    let saved_path = directory.join("acme/onebox-dns.json");
    if saved_path.is_file() {
        let saved: std::collections::BTreeMap<String, String> =
            serde_json::from_slice(&fs::read(&saved_path)?)?;
        for (key, value) in saved {
            if [
                "CF_Token",
                "CF_Key",
                "CF_Email",
                "CF_Account_ID",
                "CF_Zone_ID",
            ]
            .contains(&key.as_str())
                && !value.is_empty()
                && !value.chars().any(char::is_control)
            {
                values.insert(key, value);
            }
        }
    }
    for key in [
        "CF_Token",
        "CF_Key",
        "CF_Email",
        "CF_Account_ID",
        "CF_Zone_ID",
    ] {
        if let Ok(value) = std::env::var(key) {
            if !value.is_empty() && !value.chars().any(char::is_control) {
                values.insert(key.into(), value);
            }
        }
    }
    let complete = values.contains_key("CF_Token")
        || (values.contains_key("CF_Key") && values.contains_key("CF_Email"));
    if !complete {
        if !crate::ui::interactive(ctx) {
            return Err("Cloudflare DNS 验证缺少凭据，请提供 CF_Token（可同时提供 CF_Account_ID），或在交互终端输入".into());
        }
        let token = crate::ui::secret(ctx, "Cloudflare API Token")?;
        if token.is_empty() || token.chars().any(char::is_control) {
            return Err("Cloudflare API Token 不能为空或含控制字符".into());
        }
        let account = crate::ui::ask(ctx, "Cloudflare Account ID（可留空自动查询）", "")?;
        if !account.is_empty()
            && (account.len() != 32 || !account.bytes().all(|b| b.is_ascii_hexdigit()))
        {
            return Err("Cloudflare Account ID 应为 32 位十六进制值".into());
        }
        values.insert("CF_Token".into(), token);
        if !account.is_empty() {
            values.insert("CF_Account_ID".into(), account);
        }
    }
    // Persist before a valid legacy certificate takes the no-issuance path.
    // Otherwise a cron process would lose the migrated environment next day.
    owned_dir(&directory.join("acme"))?;
    util::atomic_write(&saved_path, &serde_json::to_vec(&values)?, 0o600)?;
    for (key, value) in values {
        std::env::set_var(key, value);
    }
    Ok(())
}
fn install_acme(ctx: &Context, dir: &Path) -> Result<PathBuf> {
    let home = dir.join("acme");
    owned_dir(&home)?;
    let exe = home.join("acme.sh");
    // Fixed upstream release. Never execute downloaded pipe content or a proxy
    // response without checking the complete file first.
    if !exe.is_file() {
        let tmp = home.join(format!(".download-{}", util::random_hex(8)?));
        let result = (|| -> Result<()> {
            ctx.run(
                "curl",
                &[
                    "--proto",
                    "=https",
                    "--tlsv1.2",
                    "-fLsS",
                    "--connect-timeout",
                    "15",
                    "--max-time",
                    "90",
                    "https://raw.githubusercontent.com/acmesh-official/acme.sh/3.1.6/acme.sh",
                    "-o",
                    util::path_str(&tmp)?,
                ],
            )?;
            let data = fs::read(&tmp)?;
            if data.len() < 10000
                || !data.starts_with(b"#!/usr/bin/env sh") && !data.starts_with(b"#!/bin/sh")
                || !String::from_utf8_lossy(&data).contains("acme.sh")
            {
                return Err("ACME 下载内容无效".into());
            }
            util::atomic_write(&exe, &data, 0o700)
        })();
        let _ = fs::remove_file(tmp);
        result?;
    }
    let dns = home.join("dnsapi");
    owned_dir(&dns)?;
    let dns_cf = dns.join("dns_cf.sh");
    if !dns_cf.is_file() {
        let tmp = dns.join(format!(".download-{}", util::random_hex(8)?));
        let result = (|| -> Result<()> {
            ctx.run("curl", &["--proto","=https","--tlsv1.2","-fLsS","--connect-timeout","15","--max-time","90","https://raw.githubusercontent.com/acmesh-official/acme.sh/3.1.6/dnsapi/dns_cf.sh","-o",util::path_str(&tmp)?])?;
            let data = fs::read(&tmp)?;
            if data.len() < 1000 || !String::from_utf8_lossy(&data).contains("dns_cf_add()") {
                return Err("Cloudflare ACME 插件下载内容无效".into());
            }
            util::atomic_write(&dns_cf, &data, 0o700)
        })();
        let _ = fs::remove_file(tmp);
        result?;
    }
    Ok(exe)
}
fn acme(ctx: &Context, dir: &Path, m: &Certificate, renewal: bool) -> Result<()> {
    if m.method == "cf" {
        ensure_cf_credentials(ctx, dir)?;
    }
    let exe = install_acme(ctx, dir)?;
    let home = dir.join("acme");
    let cert_home = home.join("certs");
    owned_dir(&cert_home)?;
    let primary = &m.domains[0];
    let renewing = renewal
        && cert_home
            .join(format!("{primary}_ecc/{primary}.conf"))
            .is_file();
    let mut args = vec![
        "--home".into(),
        util::path_str(&home)?.into(),
        "--config-home".into(),
        util::path_str(&home)?.into(),
        "--cert-home".into(),
        util::path_str(&cert_home)?.into(),
        "--server".into(),
        "letsencrypt".into(),
    ];
    args.push(if renewing { "--renew" } else { "--issue" }.into());
    for d in &m.domains {
        args.push("-d".into());
        args.push(d.clone());
    }
    if renewing {
        args.push("--ecc".into());
    } else {
        args.extend(["--keylength".into(), "ec-256".into(), "--force".into()]);
        match m.method.as_str() {
            "http" => {
                args.push("--webroot".into());
                args.push(
                    util::path_str(m.webroot.as_deref().ok_or("HTTP 验证缺少网站目录")?)?.into(),
                );
            }
            "standalone" => args.push("--standalone".into()),
            "cf" => args.extend(["--dns".into(), "dns_cf".into()]),
            _ => return Err("无效 ACME 验证方式".into()),
        }
    }
    // Do not include acme's stdout/stderr: DNS provider errors can contain API tokens.
    let result = ctx.output(
        util::path_str(&exe)?,
        &args.iter().map(String::as_str).collect::<Vec<_>>(),
    )?;
    if !result.success() && result.code != 2 {
        return Err(format!(
            "ACME 验证或签发失败，退出码 {}；请检查 DNS、端口及账户配置",
            result.code
        )
        .into());
    }
    let source = cert_home.join(format!("{primary}_ecc"));
    deploy_pair(
        ctx,
        dir,
        &source.join("fullchain.cer"),
        &source.join(format!("{primary}.key")),
        &m.domains,
        true,
    )
}
fn deploy_pair(
    ctx: &Context,
    dir: &Path,
    source_cert: &Path,
    source_key: &Path,
    domains: &[String],
    public: bool,
) -> Result<()> {
    for domain in domains {
        validate_pair(ctx, source_cert, source_key, domain, public)?;
    }
    let cert_data = fs::read(source_cert)?;
    let key_data = fs::read(source_key)?;
    let dest_cert = dir.join("cert.pem");
    let dest_key = dir.join("key.pem");
    let old_cert = fs::read(&dest_cert).ok();
    let old_key = fs::read(&dest_key).ok();
    let result = (|| -> Result<()> {
        util::atomic_write(&dest_key, &key_data, 0o600)?;
        util::atomic_write(&dest_cert, &cert_data, 0o600)?;
        Ok(())
    })();
    if result.is_err() {
        for (path, data) in [(&dest_cert, old_cert), (&dest_key, old_key)] {
            if let Some(data) = data {
                let _ = util::atomic_write(path, &data, 0o600);
            } else {
                let _ = fs::remove_file(path);
            }
        }
    }
    result
}
fn generate_self(ctx: &Context, dir: &Path, domains: &[String]) -> Result<()> {
    let stage = dir.join(format!(".issue-{}", util::random_hex(8)?));
    owned_dir(&stage)?;
    let result = (|| -> Result<()> {
        let alt = domains
            .iter()
            .map(|d| {
                format!(
                    "{}:{d}",
                    if d.parse::<std::net::IpAddr>().is_ok() {
                        "IP"
                    } else {
                        "DNS"
                    }
                )
            })
            .collect::<Vec<_>>()
            .join(",");
        let config = stage.join("openssl.cnf");
        util::atomic_write(&config,format!("[req]\ndistinguished_name=dn\nx509_extensions=extensions\nprompt=no\n[dn]\nCN={}\n[extensions]\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName={alt}\n",domains[0]).as_bytes(),0o600)?;
        ctx.run(
            "openssl",
            &[
                "req",
                "-x509",
                "-newkey",
                "ec",
                "-pkeyopt",
                "ec_paramgen_curve:prime256v1",
                "-nodes",
                "-days",
                "3650",
                "-config",
                util::path_str(&config)?,
                "-keyout",
                util::path_str(&stage.join("key.pem"))?,
                "-out",
                util::path_str(&stage.join("cert.pem"))?,
            ],
        )?;
        deploy_pair(
            ctx,
            dir,
            &stage.join("cert.pem"),
            &stage.join("key.pem"),
            domains,
            false,
        )
    })();
    let _ = fs::remove_dir_all(stage);
    result
}
pub fn issue(
    ctx: &Context,
    dir: &Path,
    domain: &str,
    method: &str,
    webroot: Option<&Path>,
    custom: Option<(&Path, &Path)>,
) -> Result<()> {
    issue_domains(ctx, dir, &[domain.into()], method, webroot, custom)
}
pub fn issue_domains(
    ctx: &Context,
    dir: &Path,
    domains: &[String],
    method: &str,
    webroot: Option<&Path>,
    custom: Option<(&Path, &Path)>,
) -> Result<()> {
    check_domains(domains, method)?;
    owned_dir(dir)?;
    if method == "cf" {
        ensure_cf_credentials(ctx, dir)?;
    }
    let previous = fs::read(metadata(dir))
        .ok()
        .and_then(|b| serde_json::from_slice::<Certificate>(&b).ok());
    let (source_cert, source_key) = custom
        .map(|(a, b)| (Some(a.to_path_buf()), Some(b.to_path_buf())))
        .unwrap_or((None, None));
    let mut m = Certificate {
        domains: domains.to_vec(),
        method: method.into(),
        webroot: webroot.map(Path::to_path_buf),
        source_cert,
        source_key,
        last_attempt: util::now(),
        last_success: 0,
        last_error: None,
    };
    if let Some(old) = previous.as_ref() {
        m.last_success = old.last_success;
    }
    let same = previous
        .as_ref()
        .map(|p| p.method == method && p.domains == domains && p.webroot == m.webroot)
        .unwrap_or(false);
    if method != "custom"
        && (same || previous.is_none())
        && current_valid(
            ctx,
            dir,
            domains,
            !matches!(method, "self" | "custom"),
            86400,
        )
    {
        m.last_success = util::now();
        return save(dir, &m);
    }
    let result = match method {
        "custom" => {
            let (c, k) = custom.ok_or("自备证书需要 --cert 和 --key")?;
            deploy_pair(ctx, dir, c, k, domains, false)
        }
        "self" => generate_self(ctx, dir, domains),
        _ => acme(ctx, dir, &m, false),
    };
    match result {
        Ok(()) => {
            m.last_success = util::now();
            save(dir, &m)
        }
        Err(e) => {
            m.last_error = Some("签发失败；原部署证书保持不变".into());
            let _ = save(dir, &m);
            Err(e)
        }
    }
}
/// Read-only preflight for scheduled work, avoiding needless proxy restarts.
pub fn renewal_due(ctx: &Context, dir: &Path) -> Result<bool> {
    let m: Certificate = serde_json::from_slice(&fs::read(metadata(dir))?)?;
    if m.method == "custom" {
        return Ok(m.source_cert.as_ref().and_then(|p| fs::read(p).ok())
            != fs::read(dir.join("cert.pem")).ok()
            || m.source_key.as_ref().and_then(|p| fs::read(p).ok())
                != fs::read(dir.join("key.pem")).ok());
    }
    Ok(!current_valid(
        ctx,
        dir,
        &m.domains,
        m.method != "self",
        30 * 86400,
    ))
}
/// Returns whether deployed bytes changed. Does not restart unrelated services.
pub fn renew(ctx: &Context, dir: &Path) -> Result<bool> {
    let mut m: Certificate = serde_json::from_slice(&fs::read(metadata(dir))?)?;
    check_domains(&m.domains, &m.method)?;
    let before = fs::read(dir.join("cert.pem")).unwrap_or_default();
    m.last_attempt = util::now();
    let result = match m.method.as_str() {
        "custom" => {
            let c = m.source_cert.as_deref().ok_or("未记录外部证书路径")?;
            let k = m.source_key.as_deref().ok_or("未记录外部私钥路径")?;
            deploy_pair(ctx, dir, c, k, &m.domains, false)
        }
        "self" => {
            if current_valid(ctx, dir, &m.domains, false, 86400 * 30) {
                Ok(())
            } else {
                generate_self(ctx, dir, &m.domains)
            }
        }
        _ => acme(ctx, dir, &m, true),
    };
    match result {
        Ok(()) => {
            m.last_success = util::now();
            m.last_error = None;
            save(dir, &m)?;
            Ok(before != fs::read(dir.join("cert.pem"))?)
        }
        Err(e) => {
            m.last_error = Some("续期失败；原证书未替换".into());
            let _ = save(dir, &m);
            Err(e)
        }
    }
}
pub fn prepare(ctx: &Context, state: &mut State) -> Result<()> {
    if !state.needs_cert() {
        state.values.remove("CERT_RENEW_PROXY");
        return Ok(());
    }
    if state.flag("CERT_RENEW_PROXY") {
        if metadata(&ctx.paths.tls()).is_file() {
            renew(ctx, &ctx.paths.tls())?;
        }
        state.values.remove("CERT_RENEW_PROXY");
    }
    let mode = state.get_or("TLS_MODE", "self").to_string();
    let domain = if mode == "self" {
        state.get_or("TLS_SNI", "www.bing.com")
    } else {
        state.get("DOMAIN")
    }
    .to_string();
    let method = if mode == "acme" {
        state.get_or("ACME_METHOD", "standalone")
    } else {
        mode.as_str()
    }
    .to_string();
    let cert_source = PathBuf::from(state.get_or("CUSTOM_CERT", state.get("CERT_FILE")));
    let key_source = PathBuf::from(state.get_or("CUSTOM_KEY", state.get("KEY_FILE")));
    let custom = if method == "custom" {
        Some((cert_source.as_path(), key_source.as_path()))
    } else {
        None
    };
    let method = if method == "standalone"
        && state.site_enabled()
        && state.get("REALITY_SITE_DOMAIN") == domain
    {
        "http"
    } else {
        &method
    };
    if method == "cf" {
        let legacy = legacy_home();
        ensure_cf_credentials_from(ctx, &ctx.paths.tls(), Some(&legacy))?;
    }
    issue(
        ctx,
        &ctx.paths.tls(),
        &domain,
        method,
        Some(&ctx.paths.site_root),
        custom,
    )?;
    if mode == "custom" {
        state.set("CUSTOM_CERT", cert_source.display());
        state.set("CUSTOM_KEY", key_source.display());
    }
    state.set("TLS_MODE", mode);
    state.set("CERT_FILE", ctx.paths.tls().join("cert.pem").display());
    state.set("KEY_FILE", ctx.paths.tls().join("key.pem").display());
    let trusted = validate_pair(
        ctx,
        &ctx.paths.tls().join("cert.pem"),
        &ctx.paths.tls().join("key.pem"),
        &domain,
        true,
    )
    .is_ok();
    state.set("CERT_PINNED", if trusted { "0" } else { "1" });
    crate::site::cron(ctx, "proxy", true)?;
    Ok(())
}
pub fn prepare_site(ctx: &Context, state: &State) -> Result<()> {
    let method = state.get_or("SITE_ACME_METHOD", "http");
    if method == "self" {
        return Err("公网网站及订阅需要正式证书，不能使用自签证书".into());
    }
    let cert = Path::new(state.get("SITE_CUSTOM_CERT"));
    let key = Path::new(state.get("SITE_CUSTOM_KEY"));
    issue(
        ctx,
        &ctx.paths.site(),
        state.get("REALITY_SITE_DOMAIN"),
        method,
        Some(&ctx.paths.site_root),
        if method == "custom" {
            Some((cert, key))
        } else {
            None
        },
    )?;
    validate_pair(
        ctx,
        &ctx.paths.site().join("cert.pem"),
        &ctx.paths.site().join("key.pem"),
        state.get("REALITY_SITE_DOMAIN"),
        true,
    )
}
pub fn status(ctx: &Context, dir: &Path) -> Result<()> {
    let cert = dir.join("cert.pem");
    if !cert.is_file() {
        println!("未配置证书");
        return Ok(());
    }
    let out = ctx.run(
        "openssl",
        &[
            "x509",
            "-in",
            util::path_str(&cert)?,
            "-noout",
            "-subject",
            "-dates",
        ],
    )?;
    print!("{out}");
    if let Ok(bytes) = fs::read(metadata(dir)) {
        if let Ok(m) = serde_json::from_slice::<Certificate>(&bytes) {
            println!(
                "方式: {}；上次成功: {}；结果: {}",
                m.method,
                m.last_success,
                m.last_error.as_deref().unwrap_or("成功")
            );
        }
    }
    Ok(())
}
pub fn command(ctx: &Context, args: &[String]) -> Result<()> {
    match args.first().map(String::as_str).unwrap_or("info") {
        "info" | "status" => {
            println!("代理证书");
            status(ctx, &ctx.paths.tls())?;
            println!("网站证书");
            status(ctx, &ctx.paths.site())
        }
        "renew" => {
            let which = args.get(1).map(String::as_str).unwrap_or("all");
            let mut state = crate::state::load(ctx)?;
            if !matches!(which, "proxy" | "site" | "all") {
                return Err("续期目标应为 proxy/site/all".into());
            }
            if matches!(which, "proxy" | "all")
                && state.needs_cert()
                && metadata(&ctx.paths.tls()).is_file()
                && (!args.iter().any(|a| a == "--cron") || renewal_due(ctx, &ctx.paths.tls())?)
            {
                state.set("CERT_RENEW_PROXY", 1);
            }
            if matches!(which, "site" | "all")
                && state.site_enabled()
                && metadata(&ctx.paths.site()).is_file()
                && (!args.iter().any(|a| a == "--cron") || renewal_due(ctx, &ctx.paths.site())?)
            {
                state.set("CERT_RENEW_SITE", 1);
            }
            if !state.flag("CERT_RENEW_PROXY") && !state.flag("CERT_RENEW_SITE") {
                return Ok(());
            }
            crate::workflow::apply(ctx, &state)
        }
        _ => Err("用法: onebox cert [info|renew [proxy|site|all]]".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn legacy_retirement_is_exact_idempotent_and_keeps_account_data() {
        use base64::Engine;
        let root =
            std::env::temp_dir().join(format!("onebox-old-acme-{}", util::random_hex(8).unwrap()));
        let ctx = Context {
            paths: crate::context::Paths::isolated(&root),
            ..Context::default()
        };
        let home = root.join("old-acme");
        let file = home.join("proxy.example.com_ecc/proxy.example.com.conf");
        let other = home.join("other.example.com_ecc/other.example.com.conf");
        let reload = base64::engine::general_purpose::STANDARD
            .encode("/usr/local/bin/onebox restart >/dev/null 2>&1 || true");
        let text = format!("Le_Domain='proxy.example.com'\nLe_RealFullChainPath='{}'\nLe_RealKeyPath='{}'\nLe_ReloadCmd='__ACME_BASE64__START_{reload}__ACME_BASE64__END_'\nLe_API='https://acme-v02.api.letsencrypt.org/directory'\n",ctx.paths.tls().join("cert.pem").display(),ctx.paths.tls().join("key.pem").display());
        util::atomic_write(&file, text.as_bytes(), 0o600).unwrap();
        util::atomic_write(&other,b"Le_RealFullChainPath='/etc/other/cert.pem'\nLe_RealKeyPath='/etc/other/key.pem'\nLe_ReloadCmd='custom command'\n",0o600).unwrap();
        util::atomic_write(&ctx.paths.legacy_state(), b"PROTOCOLS=trojan\n", 0o600).unwrap();
        assert_eq!(
            legacy_deployment_paths_in(&ctx, &home).unwrap(),
            std::slice::from_ref(&file)
        );
        disable_legacy_file(&ctx, &file).unwrap();
        let retired = fs::read_to_string(&file).unwrap();
        assert!(retired.contains("Le_RealKeyPath=''"));
        assert!(retired.contains("Le_ReloadCmd=''"));
        assert!(retired.contains("Le_API='https://acme-v02.api.letsencrypt.org/directory'"));
        assert!(fs::read_to_string(&other)
            .unwrap()
            .contains("custom command"));
        fs::remove_file(ctx.paths.legacy_state()).unwrap();
        assert_eq!(
            legacy_deployment_paths_in(&ctx, &home).unwrap(),
            std::slice::from_ref(&file)
        );
        disable_legacy_file(&ctx, &file).unwrap();
        assert_eq!(fs::read_to_string(&file).unwrap(), retired);
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn saved_cloudflare_credentials_are_data_not_shell() {
        let parsed = cf_values("SAVED_CF_Token='valid-token_123'\nCF_Account_ID=0123456789abcdef0123456789abcdef\nCF_Key=$(touch /tmp/forbidden)\nCF_Email='admin@example.test'; run_something\n");
        assert_eq!(
            parsed.get("CF_Token").map(String::as_str),
            Some("valid-token_123")
        );
        assert!(parsed.contains_key("CF_Account_ID"));
        assert!(!parsed.contains_key("CF_Key"));
        assert!(!parsed.contains_key("CF_Email"));
    }
    #[test]
    fn wildcard_requires_dns_or_custom() {
        assert!(check_domains(&["*.example.com".into()], "http").is_err());
        assert!(check_domains(&["example.com".into(), "*.example.com".into()], "cf").is_ok());
    }
    #[test]
    fn reject_domain_injection() {
        for d in [
            "example.com\nfoo",
            "-a.example.com",
            "*.bad",
            "example.com/path",
        ] {
            assert!(!domain_valid(d));
        }
    }
    #[test]
    fn metadata_contains_no_dns_token() {
        let m = Certificate {
            domains: vec!["example.com".into()],
            method: "cf".into(),
            webroot: None,
            source_cert: None,
            source_key: None,
            last_attempt: 0,
            last_success: 0,
            last_error: None,
        };
        let text = serde_json::to_string(&m).unwrap();
        assert!(!text.contains("CF_Token"));
    }
    #[test]
    fn self_certificate_is_pinned_and_wrong_key_rejected() {
        let root =
            std::env::temp_dir().join(format!("onebox-cert-test-{}", util::random_hex(8).unwrap()));
        let ctx = Context {
            paths: crate::context::Paths::isolated(&root),
            ..Context::default()
        };
        let a = root.join("a");
        let b = root.join("b");
        issue(&ctx, &a, "test.example.com", "self", None, None).unwrap();
        issue(&ctx, &b, "test.example.com", "self", None, None).unwrap();
        validate_pair(
            &ctx,
            &a.join("cert.pem"),
            &a.join("key.pem"),
            "test.example.com",
            false,
        )
        .unwrap();
        assert!(validate_pair(
            &ctx,
            &a.join("cert.pem"),
            &b.join("key.pem"),
            "test.example.com",
            false
        )
        .is_err());
        assert!(validate_pair(
            &ctx,
            &a.join("cert.pem"),
            &a.join("key.pem"),
            "other.example.com",
            false
        )
        .is_err());
        assert!(validate_pair(
            &ctx,
            &a.join("cert.pem"),
            &a.join("key.pem"),
            "test.example.com",
            true
        )
        .is_err());
        let before = fs::read(a.join("cert.pem")).unwrap();
        assert!(!renew(&ctx, &a).unwrap());
        assert_eq!(before, fs::read(a.join("cert.pem")).unwrap());
        assert_eq!(
            fs::metadata(a.join("key.pem"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        fs::remove_dir_all(root).unwrap();
    }
}
