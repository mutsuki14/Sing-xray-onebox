//! check-configurations, stop-old-services, commit-configurations,
//! configure-services, apply-website, apply-network, start-cores.

use super::Run;
use crate::apply::journal;
use crate::apply::network;
use crate::domain::protocol::Core;
use crate::error::{Context, Result};
use crate::host::cores;
use crate::host::service::{self as svc, ServiceDef, WAIT_RUNNING};
use crate::render::{self, NodeSpec};
use crate::sys::fs::{atomic_write, copy_file, remove_file_if_exists};
use std::path::PathBuf;

/// Staged standalone subscription nginx config (inside the journal
/// directory, so it disappears with it).
pub const WEB_CONF_STAGED: &str = "subscription-web.conf.new";
/// Stopped before configurations change (v2 list; the subscription worker
/// and the network oneshot keep running, publish restarts the worker).
pub const STOP_OLD: [&str; 4] = [svc::SING_BOX, svc::XRAY, svc::SUBSCRIPTION_WEB, svc::SITE];

/// `.transaction/{binary}.new.json`.
pub fn staged_config(run: &Run, core: Core) -> PathBuf {
    journal::dir(&run.ctx.paths).join(format!("{}.new.json", core.binary()))
}

/// check-configurations (K7): everything that can be checked before any
/// service stops — core configs with the core binaries, the site and
/// standalone subscription nginx configs with `nginx -t` on staged files.
pub fn check_configurations(run: &mut Run) -> Result<()> {
    let ctx = run.ctx;
    let spec = NodeSpec::load(&run.cfg, &ctx.paths)?;
    for core in run.cfg.cores() {
        let path = staged_config(run, core);
        let text = render::server_text(&spec, core)?;
        atomic_write(&path, text.as_bytes(), 0o600)?;
        cores::check_config(ctx, core, &path)
            .with_context(|| format!("{} 配置校验失败", core.title()))?;
    }
    run.site_sub = run.features.site_location(&ctx.paths, &run.cfg);
    if run.cfg.site_active().is_some() {
        run.features
            .site_check(ctx, &run.cfg, run.site_sub.as_ref())?;
    }
    if let Some(text) = run.features.subscription_web_conf(ctx, &run.cfg)? {
        let staged = journal::dir(&ctx.paths).join(WEB_CONF_STAGED);
        atomic_write(&staged, text.as_bytes(), 0o600)?;
        run.features
            .nginx_test(ctx, &ctx.paths.subscription(), &staged)?;
        run.web_conf = Some(staged);
    }
    run.spec = Some(spec);
    Ok(())
}

pub fn stop_old_services(run: &mut Run) -> Result<()> {
    for name in STOP_OLD {
        if run.services.exists(name) {
            run.services.stop(name)?;
        }
    }
    Ok(())
}

/// Move the checked configs into place; unused cores lose theirs.
pub fn commit_configurations(run: &mut Run) -> Result<()> {
    let paths = &run.ctx.paths;
    for core in Core::ALL {
        let target = paths.core_config(core);
        if run.cfg.uses(core) {
            copy_file(&staged_config(run, core), &target, 0o600)?;
        } else {
            remove_file_if_exists(&target)?;
        }
    }
    Ok(())
}

/// Units of the used cores (ordered after the site when it is the REALITY
/// target) written and enabled, unused core services removed, then the
/// subscription's units.
pub fn configure_services(run: &mut Run) -> Result<()> {
    let paths = &run.ctx.paths;
    let after_site = run.cfg.site_active().is_some();
    let defs: Vec<ServiceDef> = run
        .cfg
        .cores()
        .into_iter()
        .map(|core| ServiceDef::core(paths, core, after_site))
        .collect();
    run.services.write_all(&defs)?;
    for def in &defs {
        run.services.enable(def.name())?;
    }
    for core in Core::ALL.into_iter().filter(|c| !run.cfg.uses(*c)) {
        run.services.remove(core.service())?;
    }
    run.features.subscription_services(run.ctx, &run.cfg)
}

/// The site with its tested config, or the site turned off.
pub fn apply_website(run: &mut Run) -> Result<()> {
    if run.cfg.site_active().is_some() {
        run.features
            .site_apply(run.ctx, &run.cfg, run.site_sub.as_ref())
    } else {
        run.features.site_disable(run.ctx)
    }
}

/// Firewall rules and hops, then the boot oneshot's unit: written and
/// enabled, never started — its `net-apply` takes the node lock this
/// process holds (v2 did the same).
pub fn apply_network(run: &mut Run) -> Result<()> {
    network::apply_rules(run.ctx, &run.cfg)?;
    run.services.write(&ServiceDef::network(&run.ctx.paths))?;
    run.services.enable(svc::NETWORK)
}

pub fn start_cores(run: &mut Run) -> Result<()> {
    for core in run.cfg.cores() {
        run.services.start(core.service())?;
        run.services.wait_running(core.service(), WAIT_RUNNING)?;
    }
    Ok(())
}
