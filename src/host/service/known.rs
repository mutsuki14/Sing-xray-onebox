//! The known services: constructors and the single table of per-service
//! traits ([`traits`]). Definitions rebuilt from a spec go through the same
//! table, so `from_spec(def.spec(env)) == def` for every constructor.

use super::{
    arg_after, nginx_runtime_dir, path_string, validate_name, Identity, Scope, ServiceDef,
    ServiceKind, ServiceSpec, FRPS, FRP_WEB, NETWORK, SING_BOX, SITE, SUBSCRIPTION,
    SUBSCRIPTION_WEB, XRAY,
};
use crate::domain::protocol::Core;
use crate::error::Result;
use crate::paths::Paths;
use std::path::{Path, PathBuf};

impl ServiceDef {
    /// A definition of `name` with the traits Onebox associates with it.
    /// Unknown names get plain daemon defaults.
    pub fn new(
        paths: &Paths,
        name: &str,
        program: impl Into<PathBuf>,
        args: Vec<String>,
        after: Vec<String>,
    ) -> ServiceDef {
        let mut def = ServiceDef {
            name: name.to_owned(),
            description: format!("Onebox {name}"),
            program: program.into(),
            args,
            after,
            after_firewall: false,
            kind: ServiceKind::Daemon,
            banner: None,
            pre_start: None,
            runtime_dirs: Vec::new(),
            restart_prevent_status: None,
            run_dir: paths.run.clone(),
            log_dir: paths.log.clone(),
            spec_dir: paths.services(),
            identity: Identity::default(),
            legacy_pid_files: Vec::new(),
            log_files: Vec::new(),
            scope: Scope::Node,
            takes_lock: None,
        };
        traits(&mut def, paths);
        def
    }

    /// The traits of `name` without a command: where its spec, PID, lock and
    /// log files are, for services that may not be configured (yet).
    pub fn skeleton(paths: &Paths, name: &str) -> ServiceDef {
        ServiceDef::new(paths, name, PathBuf::new(), Vec::new(), Vec::new())
    }

    /// `onebox-sing-box` / `onebox-xray`, after the website when it serves
    /// the REALITY target.
    pub fn core(paths: &Paths, core: Core, after_site: bool) -> ServiceDef {
        let config = path_string(&paths.core_config(core));
        let args = match core {
            Core::Singbox => vec!["run", "--disable-color", "-c", config.as_str()],
            Core::Xray => vec!["run", "-c", config.as_str()],
        };
        let after = if after_site {
            vec![SITE.to_owned()]
        } else {
            vec![]
        };
        ServiceDef::new(
            paths,
            core.service(),
            paths.core_bin(core),
            owned(&args),
            after,
        )
    }

    /// The private nginx serving the own-domain website.
    pub fn site(paths: &Paths, nginx: &Path) -> ServiceDef {
        let args = nginx_args(&paths.site());
        ServiceDef::new(paths, SITE, nginx, args, vec![])
    }

    /// Boot-time restoration of firewall and hop rules (`onebox net-apply`).
    pub fn network(paths: &Paths) -> ServiceDef {
        let args = owned(&["net-apply"]);
        ServiceDef::new(paths, NETWORK, &paths.executable, args, vec![])
    }

    /// The subscription worker (`onebox subscription serve`).
    pub fn subscription(paths: &Paths) -> ServiceDef {
        let args = owned(&["subscription", "serve"]);
        ServiceDef::new(paths, SUBSCRIPTION, &paths.executable, args, vec![])
    }

    /// The nginx front of the subscription worker.
    pub fn subscription_web(paths: &Paths, nginx: &Path) -> ServiceDef {
        let args = nginx_args(&paths.subscription());
        let after = vec![SUBSCRIPTION.to_owned()];
        ServiceDef::new(paths, SUBSCRIPTION_WEB, nginx, args, after)
    }

    /// The FRP server.
    pub fn frps(paths: &Paths) -> ServiceDef {
        let config = path_string(&paths.frp_root.join("frps.toml"));
        let args = owned(&["-c", config.as_str()]);
        ServiceDef::new(paths, FRPS, paths.frp_bin.join("frps"), args, vec![])
    }

    /// The nginx of FRP web mode.
    pub fn frp_web(paths: &Paths, nginx: &Path) -> ServiceDef {
        let args = nginx_args(&paths.frp_root);
        ServiceDef::new(paths, FRP_WEB, nginx, args, vec![])
    }

    /// Rebuild a definition from its persisted spec (validated first).
    pub fn from_spec(paths: &Paths, name: &str, spec: &ServiceSpec) -> Result<ServiceDef> {
        validate_name(name)?;
        spec.validate()?;
        Ok(ServiceDef::new(
            paths,
            name,
            &spec.program,
            spec.args.clone(),
            spec.after.clone(),
        ))
    }
}

/// The per-service traits — the only place that knows them. Identity
/// configs are taken from the definition's own `-c` argument so they always
/// match how the process was started.
fn traits(def: &mut ServiceDef, paths: &Paths) {
    let config = arg_after(&def.args, "-c").map(PathBuf::from);
    match def.name.as_str() {
        SING_BOX | XRAY => {
            def.identity = Identity {
                subcommand: def.args.first().cloned(),
                config,
                nginx_title: false,
            };
            let legacy = if def.name == SING_BOX {
                "singbox.log"
            } else {
                "xray.log"
            };
            def.log_files = vec![paths.log.join(legacy)];
            if def.name == XRAY {
                def.restart_prevent_status = Some(23);
            }
        }
        SITE => {
            nginx(def, config, paths, "site");
            def.legacy_pid_files = vec![paths.site().join("nginx.pid")];
            def.log_files = vec![paths.site().join("error.log")];
        }
        SUBSCRIPTION_WEB => nginx(def, config, paths, "subscription"),
        NETWORK => {
            def.kind = ServiceKind::Oneshot;
            def.description = "Onebox network rule restoration".into();
            def.banner = Some("Restoring Onebox network rules".into());
            def.after_firewall = true;
            // `onebox net-apply` takes the node lock.
            def.takes_lock = Some(Scope::Node);
        }
        FRPS => {
            frp(def, paths);
            let exe = path_string(&paths.executable);
            def.pre_start = Some(owned(&[exe.as_str(), "frps", "net-apply"]));
            // `onebox frps net-apply` may take the FRP lock.
            def.takes_lock = Some(Scope::Frp);
            def.identity.config = config;
            def.legacy_pid_files = vec![paths.frp_run.join("frps.pid")];
            def.log_files = vec![paths.frp_log.join("frps.log")];
        }
        FRP_WEB => {
            frp(def, paths);
            nginx(def, config, paths, "frp");
            def.legacy_pid_files = vec![paths.frp_root.join("nginx.pid")];
            def.log_files = vec![
                paths.frp_log.join("nginx.log"),
                paths.frp_log.join("nginx-error.log"),
                paths.frp_root.join("error.log"),
            ];
        }
        _ => {}
    }
}

/// FRP services keep their records, logs and specs in the FRP trees.
fn frp(def: &mut ServiceDef, paths: &Paths) {
    def.run_dir = paths.frp_run.clone();
    def.log_dir = paths.frp_log.clone();
    def.spec_dir = paths.frp_root.join("services");
    def.scope = Scope::Frp;
}

/// nginx: recognized by its master title; its temp-path parent is created
/// before every start.
fn nginx(def: &mut ServiceDef, config: Option<PathBuf>, paths: &Paths, scope: &str) {
    def.identity = Identity {
        subcommand: None,
        config,
        nginx_title: true,
    };
    def.runtime_dirs = vec![nginx_runtime_dir(paths, scope)];
}

/// `-p {prefix} -c {prefix}/nginx.conf -g "daemon off;"` (foreground nginx).
fn nginx_args(prefix: &Path) -> Vec<String> {
    let config = path_string(&prefix.join("nginx.conf"));
    let prefix = path_string(prefix);
    owned(&[
        "-p",
        prefix.as_str(),
        "-c",
        config.as_str(),
        "-g",
        "daemon off;",
    ])
}

fn owned(words: &[&str]) -> Vec<String> {
    words.iter().map(|w| w.to_string()).collect()
}
