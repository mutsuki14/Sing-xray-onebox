use crate::{model::Core, Result};
use std::{
    env,
    path::{Path, PathBuf},
    process::Command,
    sync::Arc,
};

#[derive(Clone, Debug)]
pub struct Paths {
    pub root: PathBuf,
    pub bin: PathBuf,
    pub log: PathBuf,
    pub run: PathBuf,
    pub site_root: PathBuf,
    pub systemd: PathBuf,
    pub initd: PathBuf,
    pub executable: PathBuf,
    pub frp_root: PathBuf,
    pub frp_bin: PathBuf,
    pub frp_web: PathBuf,
    pub frp_log: PathBuf,
    pub frp_run: PathBuf,
}
fn env_path(name: &str, default: &str) -> PathBuf {
    env::var_os(name)
        .map(PathBuf::from)
        .unwrap_or_else(|| default.into())
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
    pub fn state(&self) -> PathBuf {
        self.root.join("state.json")
    }
    pub fn legacy_state(&self) -> PathBuf {
        self.root.join("onebox.conf")
    }
    pub fn clients(&self) -> PathBuf {
        self.root.join("client")
    }
    pub fn tls(&self) -> PathBuf {
        self.root.join("tls")
    }
    pub fn site(&self) -> PathBuf {
        self.root.join("site")
    }
    pub fn core_bin(&self, core: Core) -> PathBuf {
        self.bin.join(core.binary())
    }
    pub fn core_config(&self, core: Core) -> PathBuf {
        self.root.join(format!("{}.json", core.binary()))
    }
    pub fn isolated(root: &Path) -> Self {
        Self {
            root: root.join("etc"),
            bin: root.join("bin"),
            log: root.join("log"),
            run: root.join("run"),
            site_root: root.join("www"),
            systemd: root.join("systemd"),
            initd: root.join("initd"),
            executable: root.join("onebox"),
            frp_root: root.join("frp/etc"),
            frp_bin: root.join("frp/bin"),
            frp_web: root.join("frp/web"),
            frp_log: root.join("frp/log"),
            frp_run: root.join("frp/run"),
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct CommandOutput {
    pub code: i32,
    pub stdout: String,
    pub stderr: String,
}
impl CommandOutput {
    pub fn success(&self) -> bool {
        self.code == 0
    }
}
pub trait Runner: Send + Sync {
    fn output(&self, program: &str, args: &[String]) -> Result<CommandOutput>;
    fn output_with_lock(
        &self,
        _program: &str,
        _args: &[String],
        _lock_fd: std::os::fd::RawFd,
    ) -> Result<CommandOutput> {
        Err("此运行器不支持受控更新锁传递".into())
    }
    fn spawn(&self, _program: &str, _args: &[String], _stdout: &Path) -> Result<u32> {
        Err("后台启动未实现于此运行器".into())
    }
    fn spawn_with_env(
        &self,
        program: &str,
        args: &[String],
        stdout: &Path,
        _environment: &[(String, String)],
    ) -> Result<u32> {
        self.spawn(program, args, stdout)
    }
}
pub struct SystemRunner;
impl Runner for SystemRunner {
    fn output(&self, program: &str, args: &[String]) -> Result<CommandOutput> {
        use std::os::unix::process::CommandExt;
        let mut command = Command::new(program);
        command.args(args);
        unsafe {
            command.pre_exec(reset_child_signals);
        }
        let out = command.output()?;
        Ok(CommandOutput {
            code: out.status.code().unwrap_or(128),
            stdout: String::from_utf8_lossy(&out.stdout).into(),
            stderr: String::from_utf8_lossy(&out.stderr).into(),
        })
    }
    fn output_with_lock(
        &self,
        program: &str,
        args: &[String],
        lock_fd: std::os::fd::RawFd,
    ) -> Result<CommandOutput> {
        use std::os::unix::process::CommandExt;
        if lock_fd < 0 {
            return Err("更新锁描述符无效".into());
        }
        let mut command = Command::new(program);
        command.args(args).env("ONEBOX_INHERITED_LOCK_FD", "198");
        // Only the child duplicates this descriptor; the parent's CLOEXEC
        // lock stays private and owns the transaction throughout regeneration.
        unsafe {
            command.pre_exec(move || {
                reset_child_signals()?;
                if lock_fd != 198 && libc::dup2(lock_fd, 198) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                let flags = libc::fcntl(198, libc::F_GETFD);
                if flags < 0 || libc::fcntl(198, libc::F_SETFD, flags & !libc::FD_CLOEXEC) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let out = command.output()?;
        Ok(CommandOutput {
            code: out.status.code().unwrap_or(128),
            stdout: String::from_utf8_lossy(&out.stdout).into(),
            stderr: String::from_utf8_lossy(&out.stderr).into(),
        })
    }
    fn spawn(&self, program: &str, args: &[String], stdout: &Path) -> Result<u32> {
        self.spawn_with_env(program, args, stdout, &[])
    }
    fn spawn_with_env(
        &self,
        program: &str,
        args: &[String],
        stdout: &Path,
        environment: &[(String, String)],
    ) -> Result<u32> {
        use std::{
            fs::OpenOptions,
            os::unix::{fs::OpenOptionsExt, process::CommandExt},
            process::Stdio,
        };
        if let Some(parent) = stdout.parent() {
            std::fs::create_dir_all(parent)?;
        }
        crate::util::safe_path(stdout)?;
        let log = OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(stdout)?;
        let mut command = Command::new(program);
        command
            .args(args)
            .envs(environment.iter().map(|(key, value)| (key, value)))
            .stdin(Stdio::null())
            .stdout(log.try_clone()?)
            .stderr(log);
        // The child starts a new session; no shell or inherited terminal is involved.
        unsafe {
            command.pre_exec(|| {
                reset_child_signals()?;
                if libc::setsid() < 0 {
                    Err(std::io::Error::last_os_error())
                } else {
                    Ok(())
                }
            });
        }
        Ok(command.spawn()?.id())
    }
}
fn reset_child_signals() -> std::io::Result<()> {
    unsafe {
        let mut mask: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut mask);
        let rc = libc::pthread_sigmask(libc::SIG_SETMASK, &mask, std::ptr::null_mut());
        if rc != 0 {
            return Err(std::io::Error::from_raw_os_error(rc));
        }
    }
    Ok(())
}
#[derive(Clone)]
pub struct Context {
    pub paths: Paths,
    pub runner: Arc<dyn Runner>,
    pub yes: bool,
}
impl Default for Context {
    fn default() -> Self {
        Self {
            paths: Paths::default(),
            runner: Arc::new(SystemRunner),
            yes: false,
        }
    }
}
impl Context {
    pub fn spawn(&self, program: &str, args: &[String], stdout: &Path) -> Result<u32> {
        self.runner.spawn(program, args, stdout)
    }
    pub fn spawn_with_env(
        &self,
        program: &str,
        args: &[String],
        stdout: &Path,
        environment: &[(String, String)],
    ) -> Result<u32> {
        self.runner
            .spawn_with_env(program, args, stdout, environment)
    }
    pub fn output(&self, program: &str, args: &[&str]) -> Result<CommandOutput> {
        self.runner.output(
            program,
            &args.iter().map(|v| v.to_string()).collect::<Vec<_>>(),
        )
    }
    pub fn run(&self, program: &str, args: &[&str]) -> Result<String> {
        let result = self.output(program, args)?;
        if !result.success() {
            return Err(format!(
                "{program} 执行失败 ({}): {}",
                result.code,
                result.stderr.trim()
            )
            .into());
        }
        Ok(result.stdout)
    }
    pub fn run_with_lock(
        &self,
        program: &str,
        args: &[&str],
        lock_fd: std::os::fd::RawFd,
    ) -> Result<String> {
        let result = self.runner.output_with_lock(
            program,
            &args.iter().map(|v| v.to_string()).collect::<Vec<_>>(),
            lock_fd,
        )?;
        if !result.success() {
            return Err(format!(
                "{program} 执行失败 ({}): {}",
                result.code,
                result.stderr.trim()
            )
            .into());
        }
        Ok(result.stdout)
    }
    pub fn run_args(&self, program: &str, args: &[String]) -> Result<String> {
        self.run(
            program,
            &args.iter().map(String::as_str).collect::<Vec<_>>(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn inherited_lock_child() {
        if env::var("ONEBOX_INHERITED_LOCK_FD").ok().as_deref() != Some("198") {
            return;
        }
        let path = std::fs::read_link("/proc/self/fd/198").unwrap();
        let mut ctx = Context::default();
        ctx.paths.root = path.parent().unwrap().into();
        let lock = crate::transaction::acquire(&ctx).unwrap();
        assert!(env::var_os("ONEBOX_INHERITED_LOCK_FD").is_none());
        assert_eq!(unsafe { libc::fcntl(198, libc::F_GETFD) }, -1);
        assert!(crate::transaction::acquire(&ctx).is_err());
        drop(lock);
        println!("inherited lock verified");
    }
    #[test]
    fn update_child_keeps_parent_transaction_locked() {
        // Other parallel tests may fork while this test owns its descriptor;
        // their temporary pre-exec copies can briefly retain flock ownership.
        // Run the whole assertion in an otherwise idle test process instead
        // of weakening the post-drop lock-release requirement.
        const ISOLATED: &str = "ONEBOX_TEST_LOCK_PARENT_ISOLATED";
        if env::var(ISOLATED).ok().as_deref() != Some("1") {
            let output = std::process::Command::new(env::current_exe().unwrap())
                .args([
                    "--exact",
                    "context::tests::update_child_keeps_parent_transaction_locked",
                    "--nocapture",
                ])
                .env(ISOLATED, "1")
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            return;
        }
        let dir = env::temp_dir().join(format!(
            "onebox-lock-handoff-{}",
            crate::util::random_hex(8).unwrap()
        ));
        let ctx = Context {
            paths: Paths::isolated(&dir),
            ..Context::default()
        };
        let lock = crate::transaction::acquire(&ctx).unwrap();
        let exe = env::current_exe().unwrap();
        let result = SystemRunner
            .output_with_lock(
                exe.to_str().unwrap(),
                &[
                    "--exact".into(),
                    "context::tests::inherited_lock_child".into(),
                    "--nocapture".into(),
                ],
                lock.as_raw_fd(),
            )
            .unwrap();
        assert!(result.success(), "{}\n{}", result.stdout, result.stderr);
        assert!(result.stdout.contains("inherited lock verified"));
        assert!(
            crate::transaction::acquire(&ctx).is_err(),
            "child must not unlock the parent's open-file description"
        );
        drop(lock);
        assert!(crate::transaction::acquire(&ctx).is_ok());
        std::fs::remove_dir_all(dir).unwrap();
    }
}
