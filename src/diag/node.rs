//! Cores (binary, version, configuration) and the services a configuration
//! needs (running and starting at boot).

use super::Check;
use crate::apply::journal;
use crate::ctx::Ctx;
use crate::domain::config::{CoreVersions, SubscriptionMode};
use crate::domain::{Core, NodeConfig};
use crate::error::Result;
use crate::host::cores::{self, Wanted};
use crate::host::service::{
    Services, NETWORK, SING_BOX, SITE, SUBSCRIPTION, SUBSCRIPTION_WEB, XRAY,
};
use std::path::Path;

/// Command that installs what a node check finds missing.
pub const REGEN: &str = "onebox regen";

/// `sing-box 内核` / `Xray 内核`.
pub fn core_name(core: Core) -> String {
    format!("{} 内核", core.title())
}

/// `sing-box 配置` / `Xray 配置`.
pub fn config_name(core: Core) -> String {
    format!("{} 配置", core.title())
}

/// `服务 onebox-site`.
pub fn service_name(name: &str) -> String {
    format!("服务 {name}")
}

/// For each used core: the binary and its version, then (when the binary
/// works) its configuration, checked in `workdir` (an `Err` explains why
/// no private directory could be made).
pub fn core_checks(ctx: &Ctx, cfg: &NodeConfig, workdir: Result<&Path, &str>) -> Vec<Check> {
    let mut checks = Vec::new();
    for core in cfg.cores() {
        let binary = binary_check(ctx, cfg, core);
        let usable = !binary.is_fail();
        checks.push(binary);
        if usable {
            checks.push(config_check(ctx, core, workdir));
        }
    }
    checks
}

fn binary_check(ctx: &Ctx, cfg: &NodeConfig, core: Core) -> Check {
    let bin = ctx.paths.core_bin(core);
    let regular = std::fs::symlink_metadata(&bin).is_ok_and(|m| m.is_file());
    if !regular {
        return Check::fail(
            core_name(core),
            format!("未安装（{}）；执行 onebox regen 重新下载", bin.display()),
        );
    }
    match cores::installed_version(ctx, &bin, core) {
        Ok(version) => version_check(core, &version, &cfg.versions),
        Err(e) => Check::fail(core_name(core), e.to_string()),
    }
}

/// The running version against the pin (v2's hint) and the recorded one.
pub fn version_check(core: Core, version: &str, versions: &CoreVersions) -> Check {
    let name = core_name(core);
    let wish = versions
        .pin(core)
        .and_then(|pin| Wanted::parse(Some(pin)).ok());
    if let Some(hint) = cores::pin_hint(core, version, wish.as_ref()) {
        return Check::warn(name, hint);
    }
    match versions.installed(core) {
        Some(recorded) if recorded != version => Check::warn(
            name,
            format!("版本 {version}，配置记录为 {recorded}；执行 onebox regen 更新记录"),
        ),
        _ => Check::pass(name, format!("版本 {version}")),
    }
}

fn config_check(ctx: &Ctx, core: Core, workdir: Result<&Path, &str>) -> Check {
    let name = config_name(core);
    let config = ctx.paths.core_config(core);
    if !config.is_file() {
        return Check::fail(
            name,
            format!("配置文件不存在（{}）；执行 onebox regen", config.display()),
        );
    }
    let dir = match workdir {
        Ok(dir) => dir,
        Err(e) => return Check::warn(name, format!("无法创建校验临时目录: {e}")),
    };
    match cores::check_config_in(ctx, core, &config, dir) {
        Ok(()) => Check::pass(name, "配置有效"),
        Err(e) => Check::fail(name, e.to_string()),
    }
}

/// How a service is expected to behave.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    /// Long-running: must run and start at boot.
    Daemon,
    /// A boot oneshot restoring firewall and hop rules (`onebox-network`):
    /// must start at boot only; whether it "runs" is never asked.
    Boot,
}

/// The node services `cfg` needs, in the canonical service order.
pub fn required_services(cfg: &NodeConfig) -> Vec<(&'static str, Role)> {
    let standalone = matches!(
        cfg.subscription.as_ref().map(|s| &s.mode),
        Some(SubscriptionMode::Standalone { .. })
    );
    let wanted = |name: &str| match name {
        SUBSCRIPTION => cfg.subscription.is_some(),
        SITE => cfg.site_active().is_some(),
        SUBSCRIPTION_WEB => standalone,
        SING_BOX => cfg.uses(Core::Singbox),
        XRAY => cfg.uses(Core::Xray),
        NETWORK => true,
        _ => false,
    };
    journal::SERVICES
        .into_iter()
        .filter(|name| wanted(name))
        .map(|name| {
            let role = if name == NETWORK {
                Role::Boot
            } else {
                Role::Daemon
            };
            (name, role)
        })
        .collect()
}

pub fn service_checks(services: &Services, cfg: &NodeConfig) -> Vec<Check> {
    required_services(cfg)
        .into_iter()
        .map(|(name, role)| service_check(services, name, role, REGEN))
        .collect()
}

/// `服务 {name}`: configured, running (daemons) and starting at boot under
/// the services' init system; `fix` is the command that configures it
/// (`onebox regen` for node services).
pub fn service_check(services: &Services, name: &str, role: Role, fix: &str) -> Check {
    if !services.exists(name) {
        return Check::fail(service_name(name), format!("未配置；执行 {fix}"));
    }
    let running = role == Role::Daemon && services.running(name);
    if !services.autostart_available() && (running || role == Role::Boot) {
        return no_autostart_verdict(name, role);
    }
    service_verdict(name, role, running, services.enabled(name), fix)
}

/// A configured service on a host without init or `crontab`: nothing can
/// start it at boot, and `onebox regen` cannot change that.
pub fn no_autostart_verdict(name: &str, role: Role) -> Check {
    let what = match role {
        Role::Daemon => "运行中；",
        Role::Boot => "重启后防火墙与端口跳跃规则不会自动恢复；",
    };
    Check::warn(service_name(name), format!("{what}{NO_AUTOSTART_HINT}"))
}

/// What to do about autostart without init or `crontab`.
pub const NO_AUTOSTART_HINT: &str =
    "未找到 init 或 crontab，无法开机自启：安装 cron 后执行 onebox regen，或在重启后执行 onebox net-apply && onebox start";

/// The verdict for a configured service from its facts.
pub fn service_verdict(
    name: &str,
    role: Role,
    running: bool,
    enabled: Result<bool>,
    fix: &str,
) -> Check {
    let label = service_name(name);
    match role {
        Role::Daemon if !running => Check::fail(
            label,
            format!("未运行；查看日志: onebox service {name} log"),
        ),
        Role::Daemon => match enabled {
            Ok(true) => Check::pass(label, "运行中"),
            Ok(false) => Check::warn(label, format!("运行中，但未设置开机自启；执行 {fix}")),
            Err(e) => Check::warn(label, format!("运行中；无法读取自启状态: {e}")),
        },
        Role::Boot => match enabled {
            Ok(true) => Check::pass(label, "已设置开机恢复防火墙与端口跳跃规则"),
            Ok(false) => Check::warn(
                label,
                format!("未设置开机自启，重启后防火墙与端口跳跃规则不会恢复；执行 {fix}"),
            ),
            Err(e) => Check::warn(label, format!("无法读取自启状态: {e}")),
        },
    }
}

#[cfg(test)]
mod tests;
