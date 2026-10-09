use super::*;
use crate::apply::program_journal::{journal_path, load, WORK_PREFIX};
use crate::domain::fixtures;
use crate::domain::protocol::{Core, Protocol};
use crate::host::fetch::testing::{serve, url_arg, Reply};
use crate::host::fetch::Asset;
use crate::sys::exec::{FakeExec, Stdin};
use crate::sys::fs::{sha256_hex, TempDir};
use crate::update::testing::{
    answer_versions, mode, program, version_reply, write, FakeEngine, FakeEnv, Recover, Warnings,
};
use serde_json::json;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use ProgramPhase::{Committed, Prepared, Replaced, Replacing};

mod checks;
mod failures;

const API: &str = "https://api.github.com/repos/mutsuki14/Sing-xray-onebox/releases";
const ASSET: &str = "onebox-linux-amd64-musl";
const PROXY: &str = "https://mirror.example/";
const REGEN_FAILED: &str = "新版本重新生成配置失败（退出码 1）";

/// Where a release gets its asset checksum from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Digest {
    /// The API `digest` (and a `SHA256SUMS` that is never needed).
    Api,
    /// No API digest; the release's `SHA256SUMS`.
    Sums,
    /// Neither.
    Neither,
    /// An API digest that does not match.
    Wrong,
}

#[derive(Clone, Debug)]
struct Rel {
    channel: Channel,
    tag: String,
    draft: bool,
    prerelease: bool,
    binary: Vec<u8>,
    /// What the server sends instead of `binary` (size mismatch).
    served: Option<Vec<u8>>,
    digest: Digest,
}

impl Rel {
    fn stable(version: &str) -> Rel {
        Rel {
            channel: Channel::Stable,
            tag: format!("v{version}"),
            draft: false,
            prerelease: false,
            binary: program(&format!("{version}\n")),
            served: None,
            digest: Digest::Api,
        }
    }

    /// A testing build whose `version` prints `version`.
    fn testing(version: &str) -> Rel {
        Rel {
            channel: Channel::Testing,
            tag: "testing".into(),
            prerelease: true,
            ..Rel::stable(version)
        }
    }

    fn with_binary(mut self, binary: Vec<u8>) -> Rel {
        self.binary = binary;
        self
    }

    fn api_url(&self) -> String {
        match self.channel {
            Channel::Stable => format!("{API}/latest"),
            Channel::Testing => format!("{API}/tags/testing"),
        }
    }

    fn asset_url(&self) -> String {
        Asset::expected_url(REPOSITORY, &self.tag, ASSET)
    }

    fn sums_url(&self) -> String {
        Asset::expected_url(REPOSITORY, &self.tag, CHECKSUMS)
    }

    fn sums(&self) -> String {
        format!(
            "{}  onebox-linux-arm64-musl\n{}  {ASSET}\n",
            "0".repeat(64),
            sha256_hex(&self.binary)
        )
    }

    fn json(&self) -> String {
        let mut asset = json!({
            "name": ASSET,
            "size": self.binary.len(),
            "browser_download_url": self.asset_url(),
        });
        match self.digest {
            Digest::Api => asset["digest"] = json!(format!("sha256:{}", sha256_hex(&self.binary))),
            Digest::Wrong => asset["digest"] = json!(format!("sha256:{}", "ab".repeat(32))),
            Digest::Sums | Digest::Neither => {}
        }
        let mut assets = vec![asset];
        if self.digest != Digest::Neither {
            assets.push(json!({
                "name": CHECKSUMS,
                "size": self.sums().len(),
                "browser_download_url": self.sums_url(),
            }));
        }
        json!({
            "tag_name": self.tag,
            "draft": self.draft,
            "prerelease": self.prerelease,
            "body": "- 修复问题\n- 改进更新",
            "assets": assets,
        })
        .to_string()
    }
}

/// What the observer does after a journal phase became durable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Hook {
    Observe,
    /// Simulate the process dying right after this phase.
    Crash(ProgramPhase),
    /// Make the journal impossible to remove (a directory) after this phase.
    BreakJournal(ProgramPhase),
}

#[derive(Clone, Debug)]
struct Seen {
    phase: ProgramPhase,
    on_disk: Option<ProgramJournal>,
    exe: Vec<u8>,
}

#[derive(Clone, Debug)]
struct Regen {
    cmd: Cmd,
    /// The journal phase while it ran.
    phase: Option<ProgramPhase>,
    exe: Vec<u8>,
    node_locked: bool,
    update_locked: bool,
    /// What the inherited descriptor refers to.
    fd_target: Option<PathBuf>,
}

struct Fx {
    _dir: TempDir,
    ctx: Ctx,
    exec: Arc<FakeExec>,
    env: FakeEnv,
    engine: FakeEngine,
    hook: Hook,
    seen: Mutex<Vec<Seen>>,
    regen_reply: Arc<Mutex<Output>>,
    regens: Arc<Mutex<Vec<Regen>>>,
    /// Raised by the child `regen` / by `new version` (a signal from the
    /// terminal or `kill` at that moment).
    regen_signal: Arc<Mutex<Option<i32>>>,
    probe_signal: Arc<Mutex<Option<i32>>>,
    warnings: Warnings,
    old_state: Option<Vec<u8>>,
}

/// The fake network for `rel` (payloads behind `GH_PROXY` when set).
impl Fx {
    fn new(installed: bool, exe_version: Option<&str>) -> Fx {
        Fx::on("x86_64", installed, exe_version)
    }

    fn on(machine: &str, installed: bool, exe_version: Option<&str>) -> Fx {
        let dir = TempDir::new("selfupdate").unwrap();
        let (ctx, exec, _) = Ctx::test(dir.path());
        exec.on("uname", &["-m"], Output::success(format!("{machine}\n")));
        let probe_signal = Arc::new(Mutex::new(None));
        let raise = probe_signal.clone();
        exec.on_fn(
            |cmd| cmd.args == ["version"] && cmd.program.ends_with(&format!("/{NEW_FILE}")),
            move |cmd| {
                raise_signal(&raise);
                version_reply(cmd)
            },
        );
        answer_versions(&exec);
        let old_state = installed.then(|| {
            let cfg = fixtures::config(&[(Protocol::VlessReality, 443, Core::Singbox)]);
            StateStore::save(&ctx, &cfg).unwrap();
            fs::read(ctx.paths.state()).unwrap()
        });
        if let Some(version) = exe_version {
            write(
                &ctx.paths.executable,
                0o755,
                &program(&format!("{version}\n")),
            );
        }
        let regen_reply = Arc::new(Mutex::new(Output::success("配置已更新\n")));
        let regens = Arc::new(Mutex::new(Vec::new()));
        let regen_signal = Arc::new(Mutex::new(None));
        let child = Child {
            paths: ctx.paths.clone(),
            reply: regen_reply.clone(),
            seen: regens.clone(),
            signal: regen_signal.clone(),
        };
        answer_regen(&exec, child);
        Fx {
            _dir: dir,
            ctx,
            exec,
            env: FakeEnv::default(),
            engine: FakeEngine::new(Recover::Nothing),
            hook: Hook::Observe,
            seen: Mutex::new(Vec::new()),
            regen_reply,
            regens,
            regen_signal,
            probe_signal,
            warnings: Warnings::default(),
            old_state,
        }
    }

    fn paths(&self) -> &Paths {
        &self.ctx.paths
    }

    fn serve(&self, rel: &Rel) {
        let asset_url = match self.env.get("GH_PROXY") {
            Some(proxy) => format!("{proxy}{}", rel.asset_url()),
            None => rel.asset_url(),
        };
        let payload = rel.served.clone().unwrap_or_else(|| rel.binary.clone());
        serve(
            &self.exec,
            vec![
                (rel.api_url(), Reply::body(rel.json())),
                (asset_url, Reply::body(payload)),
                (rel.sums_url(), Reply::body(rel.sums())),
            ],
        );
    }

    fn fail_regen(&self, stderr: &str) {
        *self.regen_reply.lock().unwrap() = Output::failure(1, stderr);
    }

    fn run(&self, channel: Option<Channel>, check_only: bool) -> Result<()> {
        // The replacement installs signal handlers (process-wide).
        let _signals = signal::TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let env = |key: &str| self.env.get(key);
        let on_phase = |phase: ProgramPhase| {
            let on_disk = load(self.paths()).ok().flatten();
            let exe = fs::read(&self.paths().executable).unwrap_or_default();
            self.seen.lock().unwrap().push(Seen {
                phase,
                on_disk,
                exe,
            });
            match self.hook {
                Hook::Crash(at) if at == phase => panic!("simulated crash after {phase:?}"),
                Hook::BreakJournal(at) if at == phase => {
                    let path = journal_path(self.paths());
                    fs::remove_file(&path).unwrap();
                    fs::create_dir(&path).unwrap();
                }
                _ => {}
            }
        };
        let updater = Updater {
            ctx: &self.ctx,
            env: &env,
            engine: &self.engine,
            on_phase: &on_phase,
            warn: &|m| self.warnings.push(m),
        };
        let result = updater.self_update(channel, check_only);
        assert_eq!(signal::pending(), None, "a signal is consumed");
        result
    }

    fn seen(&self) -> Vec<Seen> {
        self.seen.lock().unwrap().clone()
    }

    fn phases(&self) -> Vec<ProgramPhase> {
        self.seen().iter().map(|s| s.phase).collect()
    }

    fn regens(&self) -> Vec<Regen> {
        self.regens.lock().unwrap().clone()
    }

    fn curl_urls(&self) -> Vec<String> {
        self.exec
            .calls()
            .iter()
            .filter(|c| c.program == "curl")
            .map(|c| url_arg(c).to_owned())
            .collect()
    }

    fn exe(&self) -> Vec<u8> {
        fs::read(&self.paths().executable).unwrap_or_default()
    }

    /// `.onebox-update-*` directories next to the executable.
    fn work_dirs(&self) -> Vec<PathBuf> {
        let parent = self.paths().executable.parent().unwrap();
        fs::read_dir(parent)
            .unwrap()
            .map(|e| e.unwrap().path())
            .filter(|p| {
                p.file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| n.starts_with(WORK_PREFIX))
            })
            .collect()
    }

    fn state(&self) -> Option<Vec<u8>> {
        fs::read(self.paths().state()).ok()
    }

    /// Nothing changed: old manager, no journal, no work dir, no phases.
    fn assert_untouched(&self, exe: &[u8]) {
        assert_eq!(self.exe(), exe);
        assert!(!journal_path(self.paths()).exists());
        assert!(self.work_dirs().is_empty());
        assert!(self.phases().is_empty());
        assert!(self.regens().is_empty());
        assert_eq!(self.state(), self.old_state);
    }
}

fn busy(path: &Path) -> bool {
    matches!(FileLock::acquire(path, "busy"), Err(Error::Busy(_)))
}

/// Send the configured signal (if any) to this thread, as a terminal
/// Ctrl+C or a `kill` would at that moment. While the updater blocks
/// signals it stays pending until the block ends.
fn raise_signal(signal: &Mutex<Option<i32>>) {
    if let Some(sig) = *signal.lock().unwrap() {
        // SAFETY: raising a standard signal; the updater's recording
        // handlers are installed (and the test holds TEST_LOCK).
        unsafe {
            libc::raise(sig);
        }
    }
}

/// The fake child `regen` and what it reports back.
struct Child {
    paths: Paths,
    reply: Arc<Mutex<Output>>,
    seen: Arc<Mutex<Vec<Regen>>>,
    signal: Arc<Mutex<Option<i32>>>,
}

/// `EXE regen`: records what the child would see; as the update's child
/// (journal not `recovering`) it rewrites state.json, raises the configured
/// signal and answers `reply`.
fn answer_regen(exec: &FakeExec, child: Child) {
    let Child {
        paths,
        reply,
        seen,
        signal,
    } = child;
    exec.on_fn(
        |cmd| cmd.args == ["regen"],
        move |cmd| {
            let phase = load(&paths).ok().flatten().map(|j| j.phase);
            seen.lock().unwrap().push(Regen {
                cmd: cmd.clone(),
                phase,
                exe: fs::read(&paths.executable).unwrap_or_default(),
                node_locked: busy(&paths.lock()),
                update_locked: busy(&paths.update_lock()),
                fd_target: cmd
                    .inherit_lock_fd
                    .and_then(|fd| fs::read_link(format!("/proc/self/fd/{fd}")).ok()),
            });
            if phase == Some(ProgramPhase::Recovering) {
                return Ok(Output::success(""));
            }
            if paths.state().exists() {
                fs::write(paths.state(), b"{\"rewritten\":true}").unwrap();
            }
            raise_signal(&signal);
            Ok(reply.lock().unwrap().clone())
        },
    );
}

fn exit_code(result: &Result<()>) -> Option<i32> {
    match result {
        Err(Error::Exit { code, .. }) => Some(*code),
        _ => None,
    }
}

fn assert_done(result: Result<()>) {
    match result {
        Err(Error::Exit { code: 0, message }) => assert_eq!(message, DONE),
        other => panic!("expected Exit 0, got {other:?}"),
    }
}

// ---- the replacement -----------------------------------------------------

#[test]
fn successful_update_walks_the_journal_phases() {
    let fx = Fx::new(true, Some("3.0.0"));
    let rel = Rel::stable("3.0.1");
    fx.serve(&rel);
    assert_done(fx.run(None, false));

    let seen = fx.seen();
    assert_eq!(fx.phases(), [Prepared, Replacing, Replaced, Committed]);
    for s in &seen {
        assert_eq!(s.on_disk.as_ref().map(|j| j.phase), Some(s.phase));
    }
    let old = program("3.0.0\n");
    let exes: Vec<&[u8]> = seen.iter().map(|s| s.exe.as_slice()).collect();
    assert_eq!(exes, [&old[..], &old, &rel.binary, &rel.binary]);
    let record = seen[0].on_disk.clone().unwrap();
    assert_eq!(record.version, journal::VERSION);
    assert!(record.work.starts_with(WORK_PREFIX));
    assert!(record.old_existed);
    assert_eq!(record.old_sha256, sha256_hex(&old));
    assert_eq!(record.new_sha256, sha256_hex(&rel.binary));
    let snapshot = record.snapshot.expect("an installed node is snapshotted");
    let state = snapshot.entry(&fx.paths().state()).unwrap();
    assert!(state.present);

    let regens = fx.regens();
    assert_eq!(regens.len(), 1);
    let regen = &regens[0];
    assert_eq!(regen.cmd.program, fx.paths().executable.to_str().unwrap());
    assert_eq!(regen.cmd.args, ["regen"]);
    assert_eq!(regen.cmd.stdin, Stdin::Null);
    assert!(!regen.cmd.stream, "output is captured");
    assert!(regen.cmd.env.contains(&(
        "ONEBOX_DIR".into(),
        fx.paths().root.to_string_lossy().into()
    )));
    assert_eq!(regen.phase, Some(Replaced));
    assert_eq!(regen.exe, rel.binary);
    assert!(regen.node_locked && regen.update_locked);
    let lock = fs::canonicalize(fx.paths().lock()).unwrap();
    assert_eq!(regen.fd_target.as_deref(), Some(lock.as_path()));

    assert_eq!(fx.exe(), rel.binary);
    assert_eq!(mode(&fx.paths().executable), 0o755);
    assert!(!journal_path(fx.paths()).exists());
    assert!(fx.work_dirs().is_empty());
    assert_eq!(fx.engine.recover_calls(), 1);
    // The API digest authenticates the asset: no checksum file needed.
    assert_eq!(fx.curl_urls(), [rel.api_url(), rel.asset_url()]);
    // Both locks are released afterwards.
    assert!(!busy(&fx.paths().lock()) && !busy(&fx.paths().update_lock()));
}

#[test]
fn a_host_without_a_node_only_replaces_the_manager() {
    let fx = Fx::new(false, Some("3.0.0"));
    let rel = Rel::stable("3.0.1");
    fx.serve(&rel);
    assert_done(fx.run(None, false));
    let record = fx.seen()[0].on_disk.clone().unwrap();
    assert!(record.snapshot.is_none() && record.old_existed);
    assert!(fx.regens().is_empty());
    assert_eq!(fx.exe(), rel.binary);
}

#[test]
fn a_missing_manager_is_installed_on_a_host_without_a_node() {
    // Without EXE the running program's version is the installed one.
    let fx = Fx::new(false, None);
    let rel = Rel::stable("3.0.1");
    fx.serve(&rel);
    assert_done(fx.run(None, false));
    let record = fx.seen()[0].on_disk.clone().unwrap();
    assert!(!record.old_existed && record.old_sha256.is_empty());
    assert_eq!(fx.exe(), rel.binary);
    assert_eq!(mode(&fx.paths().executable), 0o755);
}

#[test]
fn an_installed_node_without_its_manager_is_refused() {
    let fx = Fx::new(true, None);
    let rel = Rel::stable("3.0.1");
    fx.serve(&rel);
    let err = fx.run(None, false).unwrap_err();
    assert_eq!(err.to_string(), MANAGER_MISSING);
    assert_eq!(fx.curl_urls(), [rel.api_url()], "nothing downloaded");
    fx.assert_untouched(&[]);
}

#[test]
fn identical_content_needs_no_replacement() {
    let fx = Fx::new(true, Some("3.0.1"));
    let rel = Rel::stable("3.0.1");
    fx.serve(&rel);
    fx.run(None, false).unwrap();
    fx.assert_untouched(&rel.binary);
    assert_eq!(fx.curl_urls(), [rel.api_url(), rel.asset_url()]);
}

#[test]
fn the_downloaded_version_is_checked_before_anything_changes() {
    let cases = [
        // (release, installed, error)
        (
            Rel::testing("x").with_binary(program("3.0.0\n")),
            "3.0.1",
            DOWNLOADED_OLDER.to_owned(),
        ),
        (
            Rel::stable("3.0.1").with_binary(program("3.0.2\n")),
            "3.0.0",
            TAG_MISMATCH.to_owned(),
        ),
        (
            Rel::testing("x").with_binary(program("2.0.1\n")),
            "3.0.0",
            "不支持自更新到 2.0.1：2.x 及更早版本无法处理 3.x 的自更新恢复记录".to_owned(),
        ),
        (
            Rel::testing("x").with_binary(program("Onebox\n")),
            "3.0.0",
            "无法识别下载程序的版本: 版本需要 major.minor.patch".to_owned(),
        ),
        (
            Rel::testing("x").with_binary(b"\x7fELF not runnable at all".to_vec()),
            "3.0.0",
            "无法识别下载程序的版本: new 执行失败 (1): exec format error".to_owned(),
        ),
    ];
    for (rel, installed, message) in cases {
        let fx = Fx::new(true, Some(installed));
        fx.serve(&rel);
        let err = fx.run(Some(rel.channel), false).unwrap_err();
        assert_eq!(err.to_string(), message);
        fx.assert_untouched(&program(&format!("{installed}\n")));
    }
}

#[test]
fn an_installed_2x_manager_is_refused_before_the_download() {
    let fx = Fx::new(true, Some("2.0.1"));
    let rel = Rel::stable("3.0.1");
    fx.serve(&rel);
    let err = fx.run(None, false).unwrap_err();
    assert_eq!(
        err.to_string(),
        "已安装的管理程序为 2.0.1，请先执行 onebox update-script 由它升级到 3.x"
    );
    assert_eq!(fx.curl_urls(), [rel.api_url()]);
    fx.assert_untouched(&program("2.0.1\n"));
}

#[test]
fn a_symlinked_manager_is_refused() {
    let fx = Fx::new(false, None);
    let real = fx.paths().root.join("real-onebox");
    write(&real, 0o755, &program("3.0.0\n"));
    std::os::unix::fs::symlink(&real, &fx.paths().executable).unwrap();
    fx.serve(&Rel::stable("3.0.1"));
    let err = fx.run(None, false).unwrap_err().to_string();
    assert!(err.contains("是符号链接，无法安全替换"), "{err}");
    assert!(fx.work_dirs().is_empty());
}

#[test]
fn orphaned_work_dirs_are_swept_but_never_a_journaled_one() {
    let fx = Fx::new(false, Some("3.0.0"));
    let parent = fx.paths().executable.parent().unwrap().to_path_buf();
    let orphan = parent.join(format!("{WORK_PREFIX}{}", "a".repeat(24)));
    write(&orphan.join(NEW_FILE), 0o700, b"left by a killed update");
    let rel = Rel::stable("3.0.1");
    fx.serve(&rel);
    assert_done(fx.run(None, false));
    assert!(!orphan.exists());
    assert!(fx.work_dirs().is_empty());

    // With a journal present (recovery failed earlier) nothing is swept,
    // and the update does not start.
    let mut fx = Fx::new(false, Some("3.0.0"));
    fx.engine = FakeEngine::new(Recover::FailWithJournal("恢复失败"));
    let (name, kept) = journal::create_work_dir(fx.paths()).unwrap();
    let record = ProgramJournal::new(name, None, sha256_hex(b"x"), None);
    journal::write(fx.paths(), &record).unwrap();
    fx.serve(&rel);
    assert_eq!(fx.run(None, false).unwrap_err().to_string(), "恢复失败");
    assert!(kept.exists());
    assert_eq!(fx.exe(), program("3.0.0\n"));
}

#[test]
fn the_public_sweep_keeps_what_a_journal_or_an_updater_may_need() {
    let _signals = signal::TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let fx = Fx::new(true, Some("3.0.0"));
    let parent = fx.paths().executable.parent().unwrap().to_path_buf();
    let orphan = parent.join(format!("{WORK_PREFIX}{}", "b".repeat(24)));
    write(&orphan.join(CONFIG_DIR).join("state.json"), 0o600, b"{}");
    let lock = FileLock::acquire(&fx.paths().lock(), BUSY_MESSAGE).unwrap();

    // An unreadable journal: keep everything for a manual look.
    write(&journal_path(fx.paths()), 0o600, b"{oops");
    crate::update::sweep_orphans(fx.paths(), &lock);
    assert!(orphan.exists());
    // A readable journal (referring to another directory): kept too.
    let record = ProgramJournal::new(
        format!("{WORK_PREFIX}{}", "c".repeat(24)),
        None,
        sha256_hex(b"x"),
        None,
    );
    journal::write(fx.paths(), &record).unwrap();
    crate::update::sweep_orphans(fx.paths(), &lock);
    assert!(orphan.exists());
    fs::remove_file(journal_path(fx.paths())).unwrap();
    // An updater holds the update lock: it may be using the directory.
    let update = FileLock::acquire(&fx.paths().update_lock(), "x").unwrap();
    crate::update::sweep_orphans(fx.paths(), &lock);
    assert!(orphan.exists());
    drop(update);
    // A lock that is not the node lock proves nothing.
    let other = FileLock::acquire(&fx.paths().root.join("other.lock"), "x").unwrap();
    crate::update::sweep_orphans(fx.paths(), &other);
    assert!(orphan.exists());
    // Otherwise the orphan goes.
    crate::update::sweep_orphans(fx.paths(), &lock);
    assert!(!orphan.exists());
    assert!(
        !busy(&fx.paths().update_lock()),
        "the update lock is released"
    );
}

#[test]
fn a_successful_regen_repeats_the_childs_output_and_warnings() {
    let fx = Fx::new(true, Some("3.0.0"));
    *fx.regen_reply.lock().unwrap() = Output {
        code: 0,
        stdout: "节点信息已更新\n".into(),
        stderr: "[1/14] 准备…\n[警告] 证书将在 5 天后过期\n\u{1b}[33m[警告]\u{1b}[0m 已取消固定\n[完成] 重新生成配置完成\n"
            .into(),
    };
    fx.serve(&Rel::stable("3.0.1"));
    assert_done(fx.run(None, false));
    assert_eq!(fx.warnings.all(), ["证书将在 5 天后过期", "已取消固定"]);
}

// ---- pure helpers ----------------------------------------------------------

#[test]
fn failure_messages() {
    let work = Path::new("/usr/local/bin/.onebox-update-0123");
    let cases: [(Option<Result<()>>, i32, &str); 5] = [
        (
            None,
            1,
            "程序更新已提交，但恢复记录清理失败: 坏了；请执行 recover 完成清理",
        ),
        (Some(Ok(())), 1, "更新失败，已恢复原程序: 坏了"),
        (
            Some(Err(Error::exit(75, journal::STALE_PROCESS))),
            75,
            "更新失败，已恢复原程序: 坏了；请重新执行命令以使用恢复后的程序",
        ),
        (
            Some(Err(Error::msg("再坏"))),
            1,
            "更新失败: 坏了；恢复需要重试: 再坏；备份: /usr/local/bin/.onebox-update-0123",
        ),
        // Restored and finished; only the restored manager's regen failed.
        (
            Some(Err(Error::msg(format!(
                "{}并已重新启动服务，但再坏；排除问题后执行 onebox regen",
                journal::RESTORED_ONLY
            )))),
            1,
            "更新失败: 坏了；原程序与配置已恢复并已重新启动服务，但再坏；排除问题后执行 onebox regen",
        ),
    ];
    for (recovery, code, text) in cases {
        let err = failure(Error::msg("坏了"), recovery, work);
        assert_eq!((err.exit_code(), err.to_string().as_str()), (code, text));
    }
    // A recovery that reports exit 75 inside context still succeeded.
    let wrapped = Error::Context {
        message: "恢复失败".into(),
        source: Box::new(Error::exit(75, journal::STALE_PROCESS)),
    };
    let err = failure(Error::msg("坏了"), Some(Err(wrapped)), work);
    assert_eq!(err.exit_code(), 75);
    assert_eq!(
        err.to_string(),
        "更新失败，已恢复原程序: 坏了；请重新执行命令以使用恢复后的程序"
    );
    assert_eq!(
        retention_notice(work),
        "更新工作目录保留供恢复: /usr/local/bin/.onebox-update-0123"
    );
}

#[test]
fn child_output_joins_what_the_child_said() {
    let both = Output {
        code: 1,
        stdout: "进度\n".into(),
        stderr: "\n[错误] 端口冲突\n".into(),
    };
    assert_eq!(
        child_output(&both).as_deref(),
        Some("进度\n[错误] 端口冲突")
    );
    assert_eq!(
        child_output(&Output::failure(1, "只有错误")).as_deref(),
        Some("只有错误")
    );
    assert_eq!(child_output(&Output::failure(1, " \n")), None);
}

#[test]
fn child_report_keeps_stdout_and_warning_lines() {
    let output = Output {
        code: 0,
        stdout: "\n节点 203.0.113.10\n".into(),
        stderr: "[提示] x\n  [警告] 端口\t8443 未开放\n\u{1b}[33m[警告]\u{1b}[0m 已取消固定\n[警告]\n[错误]不是警告\n".into(),
    };
    assert_eq!(
        child_report(&output),
        ChildReport {
            stdout: "节点 203.0.113.10".into(),
            warnings: vec!["端口8443 未开放".into(), "已取消固定".into()],
        }
    );
    assert_eq!(child_report(&Output::success("")), ChildReport::default());
    // The child repeats its warnings on stdout for v2 parents: shown once.
    let echoed = Output {
        code: 0,
        stdout: "[警告] 已取消固定\n配置已更新\n".into(),
        stderr: "[警告] 已取消固定\n".into(),
    };
    assert_eq!(
        child_report(&echoed),
        ChildReport {
            stdout: "配置已更新".into(),
            warnings: vec!["已取消固定".into()],
        }
    );
}
