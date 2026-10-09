//! The feature modules the apply engine drives (certificates, website,
//! subscription, manager self-install) behind one trait, so the engine's
//! ordering, journaling and rollback can be tested without openssl, acme.sh
//! or nginx. [`SystemFeatures`] is the only production implementation and
//! forwards every call unchanged; host-level work (service manager, cores,
//! firewall, hops, crontab, rendering) is called directly by the stages.
//!
//! Invariant (G12): no method is allowed to ask the prompter anything; every
//! input (Cloudflare credentials, content intents) is passed in.
//!
//! Changes from v2: v2's workflow called the modules directly and let them
//! read and write magic keys of the state map; here each hook has typed
//! inputs, and [`Features::checkpoint`] gives tests a fault-injection point
//! after every stage and after the final save.

use crate::apply::journal::Phase;
use crate::cert::{self, CfCredentials};
use crate::ctx::Ctx;
use crate::domain::config::Device;
use crate::domain::NodeConfig;
use crate::error::Result;
use crate::paths::Paths;
use crate::render::NodeSpec;
use crate::site::{self, SiteContent, SitePrepared, SiteSubscription};
use crate::subscription;
use std::path::{Path, PathBuf};

/// Where a test may inject a failure (production never fails there).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Checkpoint {
    /// After the actions of a stage, before the next stage begins.
    Stage(Phase),
    /// After `state.json` was written, before the journal says `committed`.
    Saved,
}

/// Feature hooks called by the stages (signatures of the owning modules).
pub trait Features {
    /// prepare-state: copy the running program to `EXE` (G28 rules).
    fn install_self(&self, ctx: &Ctx) -> Result<bool>;
    /// prepare-state: migrated / cleared subscription devices.
    fn prepare_subscription(
        &self,
        ctx: &Ctx,
        cfg: &NodeConfig,
        migrated: Option<&[Device]>,
        clear: bool,
    ) -> Result<()>;
    /// prepare-certificates: the standalone subscription certificate.
    fn subscription_certificates(
        &self,
        ctx: &Ctx,
        cfg: &NodeConfig,
        force: bool,
        cf: Option<&CfCredentials>,
    ) -> Result<bool>;
    /// prepare-certificates: site content, nginx, unit and certificate.
    fn site_prepare(
        &self,
        ctx: &Ctx,
        cfg: &mut NodeConfig,
        content: Option<&SiteContent>,
        force: bool,
        cf: Option<&CfCredentials>,
    ) -> Result<SitePrepared>;
    /// prepare-certificates: the proxy certificate (records trust on `cfg`).
    fn proxy_certificate(
        &self,
        ctx: &Ctx,
        cfg: &mut NodeConfig,
        force: bool,
        cf: Option<&CfCredentials>,
    ) -> Result<bool>;
    /// The `/sub/` location the site nginx serves (subscription in site mode).
    fn site_location(&self, paths: &Paths, cfg: &NodeConfig) -> Option<SiteSubscription>;
    /// check-configurations: render and `nginx -t` the site config (staged).
    fn site_check(
        &self,
        ctx: &Ctx,
        cfg: &NodeConfig,
        sub: Option<&SiteSubscription>,
    ) -> Result<Option<PathBuf>>;
    /// check-configurations: the standalone subscription nginx config.
    fn subscription_web_conf(&self, ctx: &Ctx, cfg: &NodeConfig) -> Result<Option<String>>;
    /// `nginx -t` of a staged config with `prefix`.
    fn nginx_test(&self, ctx: &Ctx, prefix: &Path, conf: &Path) -> Result<()>;
    /// configure-services: the subscription worker / web units.
    fn subscription_services(&self, ctx: &Ctx, cfg: &NodeConfig) -> Result<()>;
    /// apply-website with an active site.
    fn site_apply(&self, ctx: &Ctx, cfg: &NodeConfig, sub: Option<&SiteSubscription>)
        -> Result<()>;
    /// apply-website without an active site.
    fn site_disable(&self, ctx: &Ctx) -> Result<()>;
    /// publish-subscription: install the web config tested earlier.
    fn install_web_conf(&self, ctx: &Ctx, tested: &Path) -> Result<()>;
    /// publish-subscription: snapshot and worker / web service state.
    fn publish_subscription(&self, ctx: &Ctx, cfg: &NodeConfig, spec: &NodeSpec) -> Result<()>;
    /// Fault-injection point for tests; production always continues.
    fn checkpoint(&self, _point: &Checkpoint) -> Result<()> {
        Ok(())
    }
}

/// The production hooks: straight calls into the owning modules.
pub struct SystemFeatures;

impl Features for SystemFeatures {
    fn install_self(&self, ctx: &Ctx) -> Result<bool> {
        crate::host::selfexe::install_self(ctx)
    }

    fn prepare_subscription(
        &self,
        ctx: &Ctx,
        cfg: &NodeConfig,
        migrated: Option<&[Device]>,
        clear: bool,
    ) -> Result<()> {
        subscription::prepare(ctx, cfg, migrated, clear)
    }

    fn subscription_certificates(
        &self,
        ctx: &Ctx,
        cfg: &NodeConfig,
        force: bool,
        cf: Option<&CfCredentials>,
    ) -> Result<bool> {
        subscription::prepare_certificates(ctx, cfg, force, cf)
    }

    fn site_prepare(
        &self,
        ctx: &Ctx,
        cfg: &mut NodeConfig,
        content: Option<&SiteContent>,
        force: bool,
        cf: Option<&CfCredentials>,
    ) -> Result<SitePrepared> {
        site::prepare(ctx, cfg, content, force, cf)
    }

    fn proxy_certificate(
        &self,
        ctx: &Ctx,
        cfg: &mut NodeConfig,
        force: bool,
        cf: Option<&CfCredentials>,
    ) -> Result<bool> {
        cert::prepare_proxy(ctx, cfg, force, cf)
    }

    fn site_location(&self, paths: &Paths, cfg: &NodeConfig) -> Option<SiteSubscription> {
        subscription::site_location(paths, cfg)
    }

    fn site_check(
        &self,
        ctx: &Ctx,
        cfg: &NodeConfig,
        sub: Option<&SiteSubscription>,
    ) -> Result<Option<PathBuf>> {
        site::check(ctx, cfg, sub)
    }

    fn subscription_web_conf(&self, ctx: &Ctx, cfg: &NodeConfig) -> Result<Option<String>> {
        subscription::render_web_conf(ctx, cfg)
    }

    fn nginx_test(&self, ctx: &Ctx, prefix: &Path, conf: &Path) -> Result<()> {
        crate::host::nginx::test(ctx, prefix, conf)
    }

    fn subscription_services(&self, ctx: &Ctx, cfg: &NodeConfig) -> Result<()> {
        subscription::configure_services(ctx, cfg)
    }

    fn site_apply(
        &self,
        ctx: &Ctx,
        cfg: &NodeConfig,
        sub: Option<&SiteSubscription>,
    ) -> Result<()> {
        site::apply(ctx, cfg, sub)
    }

    fn site_disable(&self, ctx: &Ctx) -> Result<()> {
        site::disable(ctx)
    }

    fn install_web_conf(&self, ctx: &Ctx, tested: &Path) -> Result<()> {
        subscription::install_web_conf(ctx, tested)
    }

    fn publish_subscription(&self, ctx: &Ctx, cfg: &NodeConfig, spec: &NodeSpec) -> Result<()> {
        subscription::publish(ctx, cfg, spec)
    }
}
