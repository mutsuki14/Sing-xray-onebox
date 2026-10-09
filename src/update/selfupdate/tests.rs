use super::*;
use crate::apply::program_journal::{journal_path, load, WORK_PREFIX};
use crate::domain::fixtures;
use crate::domain::protocol::{Core, Protocol};
use crate::host::fetch::testing::{serve, url_arg, Reply};
use crate::host::fetch::Asset;
use crate::sys::exec::{FakeExec, Stdin};
use crate::sys::fs::{sha256_hex, TempDir};
use crate::update::testing::{answer_versions, mode, program, write, FakeEngine, FakeEnv, Recover};
use serde_json::json;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use ProgramPhase::{Committed, Prepared, Replaced, Replacing};

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
        answer_regen(&exec, &ctx.paths, regen_reply.clone(), regens.clone());
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
        };
        updater.self_update(channel, check_only)
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

/// `EXE regen`: records what the child would see; as the update's child
/// (journal not `recovering`) it rewrites state.json and answers `reply`.
fn answer_regen(
    exec: &FakeExec,
    paths: &Paths,
    reply: Arc<Mutex<Output>>,
    seen: Arc<Mutex<Vec<Regen>>>,
) {
    let paths = paths.clone();
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

// ---- update-check and release rules ------------------------------------

#[test]
fn update_check_reports_and_changes_nothing() {
    let fx = Fx::new(true, Some("3.0.0"));
    let rel = Rel::stable("3.0.1");
    fx.serve(&rel);
    fx.run(None, true).unwrap();
    assert_eq!(fx.curl_urls(), [rel.api_url()]);
    assert_eq!(fx.engine.recover_calls(), 0);
    assert!(!fx.paths().update_lock().exists(), "no lock taken");
    assert!(!fx.paths().lock().exists());
    fx.assert_untouched(&program("3.0.0\n"));
}

#[test]
fn stable_downgrades_are_refused_by_check_and_update() {
    for check_only in [true, false] {
        let fx = Fx::new(true, Some("3.0.2"));
        let rel = Rel::stable("3.0.1");
        fx.serve(&rel);
        let err = fx.run(None, check_only).unwrap_err();
        assert_eq!(err.to_string(), NEWER_INSTALLED);
        assert_eq!(fx.curl_urls(), [rel.api_url()]);
        assert_eq!(fx.engine.recover_calls(), 0);
        fx.assert_untouched(&program("3.0.2\n"));
    }
}

#[test]
fn testing_channel_follows_the_testing_tag() {
    let fx = Fx::new(true, Some("3.0.2"));
    channel::save(fx.paths(), Channel::Testing).unwrap();
    let rel = Rel::testing("3.0.1");
    fx.serve(&rel);
    // The testing build's version is unknown before the download: the
    // check passes, the update refuses once it probed the binary.
    fx.run(None, true).unwrap();
    let err = fx.run(None, false).unwrap_err();
    assert_eq!(err.to_string(), DOWNLOADED_OLDER);
    assert_eq!(
        fx.curl_urls(),
        [rel.api_url(), rel.api_url(), rel.asset_url()]
    );
    fx.assert_untouched(&program("3.0.2\n"));
    // An explicit channel wins over the saved one.
    let err = fx.run(Some(Channel::Stable), true).unwrap_err();
    assert!(err.to_string().contains("404"), "{err}");
    assert_eq!(fx.curl_urls().last().unwrap(), &format!("{API}/latest"));
}

#[test]
fn channel_mismatches_are_refused() {
    let cases = [
        Rel {
            prerelease: true,
            ..Rel::stable("3.0.1")
        },
        Rel {
            draft: true,
            ..Rel::stable("3.0.1")
        },
        Rel {
            draft: true,
            ..Rel::testing("3.0.1")
        },
    ];
    for rel in cases {
        let fx = Fx::new(true, Some("3.0.0"));
        fx.serve(&rel);
        let err = fx.run(Some(rel.channel), true).unwrap_err();
        assert_eq!(err.to_string(), "更新来源不是指定渠道的有效发布", "{rel:?}");
    }
}

#[test]
fn a_cpu_without_a_release_build_keeps_the_manager() {
    let fx = Fx::on("riscv64", true, Some("3.0.0"));
    fx.serve(&Rel::stable("3.0.1"));
    let err = fx.run(None, true).unwrap_err();
    assert_eq!(
        err.to_string(),
        "此发布缺少 onebox-linux-riscv64-musl；保持已安装程序"
    );
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
fn asset_verification_uses_the_api_digest_or_the_direct_checksum_file() {
    struct Case {
        digest: Digest,
        proxy: bool,
        /// `Ok(curl URLs after the API call)` or `Err(error text part)`.
        expect: std::result::Result<Vec<&'static str>, &'static str>,
    }
    let cases = [
        Case {
            digest: Digest::Api,
            proxy: true,
            expect: Ok(vec!["proxied-asset"]),
        },
        Case {
            digest: Digest::Sums,
            proxy: true,
            expect: Ok(vec!["sums", "proxied-asset"]),
        },
        Case {
            digest: Digest::Sums,
            proxy: false,
            expect: Ok(vec!["sums", "asset"]),
        },
        Case {
            digest: Digest::Neither,
            proxy: false,
            expect: Err("onebox-linux-amd64-musl 缺少 SHA256 校验信息，拒绝安装"),
        },
        Case {
            digest: Digest::Wrong,
            proxy: false,
            expect: Err("下载文件 SHA256 不匹配: onebox-linux-amd64-musl"),
        },
    ];
    for case in cases {
        let mut fx = Fx::new(false, Some("3.0.0"));
        if case.proxy {
            fx.env.set("GH_PROXY", PROXY);
        }
        let rel = Rel {
            digest: case.digest,
            ..Rel::stable("3.0.1")
        };
        fx.serve(&rel);
        let result = fx.run(None, false);
        let label = format!("{:?} proxy={}", case.digest, case.proxy);
        match case.expect {
            Ok(urls) => {
                assert_done(result);
                let want: Vec<String> = std::iter::once(rel.api_url())
                    .chain(urls.iter().map(|u| match *u {
                        "sums" => rel.sums_url(),
                        "asset" => rel.asset_url(),
                        _ => format!("{PROXY}{}", rel.asset_url()),
                    }))
                    .collect();
                assert_eq!(fx.curl_urls(), want, "{label}");
                assert_eq!(fx.exe(), rel.binary, "{label}");
            }
            Err(part) => {
                let err = result.unwrap_err().to_string();
                assert!(err.contains(part), "{label}: {err}");
                fx.assert_untouched(&program("3.0.0\n"));
            }
        }
    }
}

#[test]
fn wrong_sizes_and_non_programs_are_refused() {
    let short = Rel {
        served: Some(program("3.0.1")),
        ..Rel::stable("3.0.1")
    };
    let script = Rel::stable("3.0.1").with_binary(b"#!/bin/sh\necho 3.0.1 # padding\n".to_vec());
    for (rel, part) in [(short, "大小与发行元信息不符"), (script, NOT_ELF)] {
        let fx = Fx::new(true, Some("3.0.0"));
        fx.serve(&rel);
        let err = fx.run(None, false).unwrap_err().to_string();
        assert!(err.contains(part), "{err}");
        fx.assert_untouched(&program("3.0.0\n"));
    }
}

// ---- failures after the journal was written -----------------------------

#[test]
fn a_failed_regen_restores_the_old_manager_and_configuration() {
    let mut fx = Fx::new(true, Some("3.0.0"));
    fx.engine = FakeEngine::new(Recover::ProgramJournal);
    fx.fail_regen("端口 443 已被占用");
    fx.serve(&Rel::stable("3.0.1"));
    let result = fx.run(None, false);
    assert_eq!(exit_code(&result), Some(EXIT_STALE_PROCESS));
    assert_eq!(
        result.unwrap_err().to_string(),
        format!("更新失败，已恢复原程序: {REGEN_FAILED}；请重新执行命令以使用恢复后的程序")
    );
    assert_eq!(fx.exe(), program("3.0.0\n"));
    assert_eq!(fx.state(), fx.old_state);
    assert!(!journal_path(fx.paths()).exists());
    assert!(fx.work_dirs().is_empty());
    assert_eq!(fx.engine.recover_calls(), 2);
    // The restored manager regenerated under the same lock.
    let regens = fx.regens();
    assert_eq!(regens.len(), 2);
    assert_eq!(regens[1].phase, Some(ProgramPhase::Recovering));
    assert_eq!(regens[1].exe, program("3.0.0\n"));
    assert_eq!(regens[1].fd_target, regens[0].fd_target);
}

#[test]
fn a_recovery_in_the_restored_process_is_a_plain_failure() {
    let mut fx = Fx::new(true, Some("3.0.0"));
    fx.engine = FakeEngine::new(Recover::ProgramJournalCurrent);
    fx.fail_regen("");
    fx.serve(&Rel::stable("3.0.1"));
    let err = fx.run(None, false).unwrap_err();
    assert_eq!(err.exit_code(), 1);
    assert_eq!(
        err.to_string(),
        format!("更新失败，已恢复原程序: {REGEN_FAILED}")
    );
    assert_eq!(fx.exe(), program("3.0.0\n"));
    assert!(fx.work_dirs().is_empty());
}

#[test]
fn a_failed_recovery_keeps_the_record_and_its_work_dir() {
    let mut fx = Fx::new(true, Some("3.0.0"));
    fx.engine = FakeEngine::new(Recover::FailWithJournal("恢复失败"));
    fx.fail_regen("boom");
    let rel = Rel::stable("3.0.1");
    fx.serve(&rel);
    let err = fx.run(None, false).unwrap_err().to_string();
    let work = fx.work_dirs();
    assert_eq!(work.len(), 1);
    assert_eq!(
        err,
        format!(
            "更新失败: {REGEN_FAILED}；恢复需要重试: 恢复失败；备份: {}",
            work[0].display()
        )
    );
    let record = load(fx.paths()).unwrap().unwrap();
    assert_eq!(record.phase, Replaced);
    assert_eq!(fx.exe(), rel.binary);
    // The next recovery (any command) finishes it.
    let lock = FileLock::acquire(&fx.paths().lock(), BUSY_MESSAGE).unwrap();
    let again = journal::recover_program_locked(&fx.ctx, &lock);
    assert_eq!(exit_code(&again), Some(EXIT_STALE_PROCESS));
    assert_eq!(fx.exe(), program("3.0.0\n"));
    assert_eq!(fx.state(), fx.old_state);
    assert!(fx.work_dirs().is_empty());
}

#[test]
fn a_failed_cleanup_after_commit_is_reported_without_recovery() {
    let mut fx = Fx::new(true, Some("3.0.0"));
    fx.hook = Hook::BreakJournal(Committed);
    let rel = Rel::stable("3.0.1");
    fx.serve(&rel);
    let err = fx.run(None, false).unwrap_err().to_string();
    assert!(
        err.starts_with("程序更新已提交，但恢复记录清理失败: ")
            && err.ends_with("；请执行 recover 完成清理"),
        "{err}"
    );
    assert_eq!(fx.engine.recover_calls(), 1, "no rollback after commit");
    assert_eq!(fx.exe(), rel.binary);
    assert_eq!(fx.work_dirs().len(), 1, "kept while the record exists");
}

#[test]
fn crash_windows_hand_off_to_the_program_journal_recovery() {
    for phase in [Prepared, Replacing, Replaced, Committed] {
        let mut fx = Fx::new(true, Some("3.0.0"));
        fx.hook = Hook::Crash(phase);
        let rel = Rel::stable("3.0.1");
        fx.serve(&rel);
        let crashed = catch_unwind(AssertUnwindSafe(|| fx.run(None, false)));
        assert!(crashed.is_err(), "{phase:?}");
        assert_eq!(load(fx.paths()).unwrap().unwrap().phase, phase);
        // The dead process released its locks.
        let lock = FileLock::acquire(&fx.paths().lock(), BUSY_MESSAGE).unwrap();
        let recovered = journal::recover_program_locked(&fx.ctx, &lock);
        if phase == Committed {
            recovered.unwrap();
            assert_eq!(fx.exe(), rel.binary, "a commit is never undone");
            assert_eq!(fx.state().unwrap(), b"{\"rewritten\":true}");
        } else {
            assert_eq!(exit_code(&recovered), Some(EXIT_STALE_PROCESS), "{phase:?}");
            assert_eq!(fx.exe(), program("3.0.0\n"), "{phase:?}");
            assert_eq!(fx.state(), fx.old_state, "{phase:?}");
        }
        assert!(!journal_path(fx.paths()).exists());
        assert!(fx.work_dirs().is_empty());
    }
}

#[test]
fn locks_and_pending_journals_stop_the_update_before_any_download() {
    let fx = Fx::new(true, Some("3.0.0"));
    let rel = Rel::stable("3.0.1");
    fx.serve(&rel);
    let held = FileLock::acquire(&fx.paths().update_lock(), "x").unwrap();
    let err = fx.run(None, false).unwrap_err();
    assert!(matches!(&err, Error::Busy(m) if m == UPDATE_BUSY), "{err}");
    drop(held);
    let held = FileLock::acquire(&fx.paths().lock(), "x").unwrap();
    let err = fx.run(None, false).unwrap_err();
    assert!(matches!(&err, Error::Busy(m) if m == BUSY_MESSAGE), "{err}");
    drop(held);
    assert_eq!(fx.engine.recover_calls(), 0);

    let mut fx = Fx::new(true, Some("3.0.0"));
    fx.engine = FakeEngine::new(Recover::Refuse("存在未完成事务，请先 recover"));
    fx.serve(&rel);
    let err = fx.run(None, false).unwrap_err();
    assert_eq!(err.to_string(), "存在未完成事务，请先 recover");
    assert_eq!(fx.curl_urls(), [rel.api_url()]);
    fx.assert_untouched(&program("3.0.0\n"));
}

// ---- pure helpers ----------------------------------------------------------

#[test]
fn failure_messages() {
    let work = Path::new("/usr/local/bin/.onebox-update-0123");
    let cases: [(Option<Result<()>>, i32, &str); 4] = [
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
    ];
    for (recovery, code, text) in cases {
        let err = failure(Error::msg("坏了"), recovery, work);
        assert_eq!((err.exit_code(), err.to_string().as_str()), (code, text));
    }
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
