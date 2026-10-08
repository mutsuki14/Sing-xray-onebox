use crate::{context::Context, model::Core, platform, state, util, Result};
use serde_json::json;
use std::{fs, io::Write};

pub fn doctor(ctx: &Context) -> Result<()> {
    let s = state::load(ctx)?;
    let mut failures = 0;
    for core in [Core::Singbox, Core::Xray] {
        if !s.uses(core) {
            continue;
        }
        match platform::core_check(ctx, core, &ctx.paths.core_config(core)) {
            Ok(()) => println!("[通过] {core} 配置有效"),
            Err(_) => {
                println!("[失败] {core} 配置校验失败，请查看本机核心日志");
                failures += 1;
            }
        }
        if platform::running(ctx, core.service()) {
            println!("[通过] {core} 运行中")
        } else {
            println!("[失败] {core} 未运行");
            failures += 1;
        }
    }
    for (name, dir) in [
        ("代理证书", ctx.paths.tls()),
        ("网站证书", ctx.paths.site()),
    ] {
        let cert = dir.join("cert.pem");
        if cert.exists() {
            let ok = ctx
                .output(
                    "openssl",
                    &[
                        "x509",
                        "-checkend",
                        "604800",
                        "-noout",
                        "-in",
                        util::path_str(&cert)?,
                    ],
                )?
                .success();
            println!(
                "[{}] {name} {}",
                if ok { "通过" } else { "警告" },
                if ok {
                    "至少7天内有效"
                } else {
                    "将在7天内到期或已失效"
                }
            );
        }
    }
    if crate::transaction::load(ctx)?.is_some() || ctx.paths.root.join(".self-update.json").exists()
    {
        println!("[警告] 有未完成事务；执行 onebox recover");
        failures += 1;
    }
    println!("公网 DNS、防火墙和客户端真实连通性请配合 onebox reality-check / bench 检查。");
    if failures > 0 {
        return Err(format!("体检发现 {failures} 个需要处理的问题").into());
    }
    Ok(())
}
pub fn support(ctx: &Context) -> Result<()> {
    let s = state::load(ctx)?;
    let entries=s.protocols().iter().map(|p|json!({"protocol":p.as_str(),"core":s.core(*p).as_str(),"port":s.port(*p),"network":p.network()})).collect::<Vec<_>>();
    let cores=[Core::Singbox,Core::Xray].into_iter().filter(|c|s.uses(*c)).map(|c|json!({"core":c.as_str(),"running":platform::running(ctx,c.service()),"version":platform::installed_version(ctx,c).unwrap_or_default()})).collect::<Vec<_>>();
    let report = json!({"program_version":crate::VERSION,"host":platform::host_info(ctx)?,"protocols":entries,"cores":cores,"certificate_mode":s.get("TLS_MODE"),"owned_site":s.site_enabled(),"subscription":s.flag("SUBSCRIPTION_ENABLED"),"pending_recovery":(crate::transaction::load(ctx)?.is_some() || ctx.paths.root.join(".self-update.json").exists()),"note":"No credentials, IP addresses, domain names, logs or certificate contents are included."});
    let path = ctx.paths.root.join(format!("support-{}.json", util::now()));
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)?;
    file.write_all(&serde_json::to_vec_pretty(&report)?)?;
    file.sync_all()?;
    println!("已生成脱敏诊断文件: {}", path.display());
    Ok(())
}
