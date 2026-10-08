use crate::{model::Core, Result};
use std::{env, path::{Path, PathBuf}, process::Command, sync::Arc};

#[derive(Clone, Debug)]
pub struct Paths {
    pub root: PathBuf, pub bin: PathBuf, pub log: PathBuf, pub run: PathBuf,
    pub site_root: PathBuf, pub systemd: PathBuf, pub initd: PathBuf,
    pub executable: PathBuf, pub frp_root: PathBuf, pub frp_bin: PathBuf,
    pub frp_web: PathBuf, pub frp_log: PathBuf, pub frp_run: PathBuf,
}
fn env_path(name: &str, default: &str) -> PathBuf {
    env::var_os(name).map(PathBuf::from).unwrap_or_else(|| default.into())
}
impl Default for Paths {
    fn default() -> Self {
        Self {
            root: env_path("ONEBOX_DIR", "/etc/onebox"),
            bin: env_path("ONEBOX_BIN_DIR", "/opt/onebox/bin"),
            log: env_path("ONEBOX_LOG_DIR", "/var/log/onebox"),
            run: env_path("ONEBOX_RUN_DIR", "/run/onebox"),
            site_root: env_path("ONEBOX_SITE_ROOT", "/var/lib/onebox-site"),
            systemd: env_path("ONEBOX_SYSTEMD_DIR", "/etc/systemd/system"),
            initd: env_path("ONEBOX_INITD_DIR", "/etc/init.d"),
            executable: env_path("ONEBOX_EXE", "/usr/local/bin/onebox"),
            frp_root: env_path("ONEBOX_FRPS_DIR", "/etc/onebox-frp"),
            frp_bin: env_path("ONEBOX_FRPS_BIN_DIR", "/opt/onebox-frp"),
            frp_web: env_path("ONEBOX_FRPS_WEB_VAR", "/var/lib/onebox-frp"),
            frp_log: env_path("ONEBOX_FRPS_LOG_DIR", "/var/log/onebox-frp"),
            frp_run: env_path("ONEBOX_FRPS_RUN_DIR", "/run/onebox-frp"),
        }
    }
}
impl Paths {
    pub fn state(&self) -> PathBuf { self.root.join("state.json") }
    pub fn legacy_state(&self) -> PathBuf { self.root.join("onebox.conf") }
    pub fn clients(&self) -> PathBuf { self.root.join("client") }
    pub fn tls(&self) -> PathBuf { self.root.join("tls") }
    pub fn site(&self) -> PathBuf { self.root.join("site") }
    pub fn core_bin(&self, core: Core) -> PathBuf { self.bin.join(core.binary()) }
    pub fn core_config(&self, core: Core) -> PathBuf { self.root.join(format!("{}.json", core.binary())) }
    pub fn isolated(root: &Path) -> Self {
        Self {root:root.join("etc"),bin:root.join("bin"),log:root.join("log"),run:root.join("run"),
            site_root:root.join("www"),systemd:root.join("systemd"),initd:root.join("initd"),executable:root.join("onebox"),
            frp_root:root.join("frp/etc"),frp_bin:root.join("frp/bin"),frp_web:root.join("frp/web"),frp_log:root.join("frp/log"),frp_run:root.join("frp/run")}
    }
}

#[derive(Clone, Debug, Default)]
pub struct CommandOutput { pub code: i32, pub stdout: String, pub stderr: String }
impl CommandOutput { pub fn success(&self) -> bool {self.code == 0} }
pub trait Runner: Send + Sync {
    fn output(&self, program: &str, args: &[String]) -> Result<CommandOutput>;
}
pub struct SystemRunner;
impl Runner for SystemRunner {
    fn output(&self, program: &str, args: &[String]) -> Result<CommandOutput> {
        let out = Command::new(program).args(args).output()?;
        Ok(CommandOutput {code:out.status.code().unwrap_or(128), stdout:String::from_utf8_lossy(&out.stdout).into(), stderr:String::from_utf8_lossy(&out.stderr).into()})
    }
}
#[derive(Clone)]
pub struct Context { pub paths: Paths, pub runner: Arc<dyn Runner>, pub yes: bool }
impl Default for Context {fn default()->Self{Self{paths:Paths::default(),runner:Arc::new(SystemRunner),yes:false}}}
impl Context {
    pub fn output(&self, program: &str, args: &[&str]) -> Result<CommandOutput> {
        self.runner.output(program, &args.iter().map(|v|v.to_string()).collect::<Vec<_>>())
    }
    pub fn run(&self, program: &str, args: &[&str]) -> Result<String> {
        let result=self.output(program,args)?;
        if !result.success() {return Err(format!("{program} 执行失败 ({}): {}",result.code,result.stderr.trim()).into())}
        Ok(result.stdout)
    }
    pub fn run_args(&self, program: &str, args: &[String]) -> Result<String> {
        self.run(program,&args.iter().map(String::as_str).collect::<Vec<_>>())
    }
}

