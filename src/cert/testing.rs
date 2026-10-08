//! Test helpers: a real-openssl context, throw-away certificates (a test CA,
//! CA-signed leaves, self-signed pairs) and [`HybridExec`], which runs the
//! real openssl while every other program is scripted by a [`FakeExec`].
//!
//! Public verification against the test CA works by giving openssl
//! `SSL_CERT_FILE` (its default store) — the production code runs the very
//! same `openssl verify` command.

use crate::cert::acme::AcmeRelease;
use crate::cert::Engine;
use crate::ctx::Ctx;
use crate::error::Result;
use crate::host::fetch::testing::{serve, Reply};
use crate::host::init::InitSystem;
use crate::paths::Paths;
use crate::sys::exec::{Cmd, Exec, FakeExec, Output, RunningChild, SystemExec};
use crate::sys::fs::{sha256_hex, TempDir};
use crate::ui::ScriptedPrompter;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

/// Whether a usable `openssl` is installed; tests that need it skip
/// otherwise (unless `ONEBOX_TEST_REQUIRE_FULL=1`, which makes it fatal).
pub fn have_openssl() -> bool {
    let found = SystemExec.which("openssl").is_some();
    if !found {
        assert!(
            std::env::var("ONEBOX_TEST_REQUIRE_FULL").as_deref() != Ok("1"),
            "openssl is required"
        );
        eprintln!("skipping: openssl not installed");
    }
    found
}

/// Runs `openssl` for real (with `SSL_CERT_FILE` = the test CA when set)
/// and everything else through the fake.
pub struct HybridExec {
    pub fake: Arc<FakeExec>,
    pub ca_file: Option<PathBuf>,
}

impl HybridExec {
    fn real(&self, cmd: &Cmd) -> bool {
        cmd.program_name() == "openssl"
    }

    fn with_ca(&self, cmd: &Cmd) -> Cmd {
        let mut cmd = cmd.clone();
        if let Some(ca) = &self.ca_file {
            cmd = cmd.env("SSL_CERT_FILE", ca.to_string_lossy());
        }
        cmd
    }
}

impl Exec for HybridExec {
    fn run(&self, cmd: &Cmd) -> Result<Output> {
        if self.real(cmd) {
            SystemExec.run(&self.with_ca(cmd))
        } else {
            self.fake.run(cmd)
        }
    }
    fn spawn(&self, cmd: &Cmd) -> Result<Box<dyn RunningChild>> {
        self.fake.spawn(cmd)
    }
    fn spawn_detached(&self, cmd: &Cmd, log: &Path) -> Result<u32> {
        self.fake.spawn_detached(cmd, log)
    }
    fn which(&self, program: &str) -> Option<std::path::PathBuf> {
        if program == "openssl" {
            SystemExec.which(program)
        } else {
            self.fake.which(program)
        }
    }
}

/// A test fixture: temp root, isolated paths, hybrid exec and a test CA.
pub struct Fixture {
    pub dir: TempDir,
    pub ctx: Ctx,
    pub fake: Arc<FakeExec>,
    pub ca: TestCa,
}

impl Fixture {
    pub fn new(label: &str) -> Fixture {
        let dir = TempDir::new(label).unwrap();
        let ca = TestCa::create(&dir.join("test-ca"));
        let fake = Arc::new(FakeExec::new());
        let exec = HybridExec {
            fake: fake.clone(),
            ca_file: Some(ca.cert.clone()),
        };
        let ui = Arc::new(ScriptedPrompter::new(Vec::<String>::new()));
        let ctx = Ctx {
            paths: Paths::isolated(dir.path()),
            exec: Arc::new(exec),
            ui,
        };
        Fixture { dir, ctx, fake, ca }
    }

    /// A context running the real openssl without the test CA in its store.
    pub fn untrusting_ctx(&self) -> Ctx {
        Ctx {
            exec: Arc::new(HybridExec {
                fake: self.fake.clone(),
                ca_file: None,
            }),
            ..self.ctx.clone()
        }
    }
}

fn openssl(args: &[&str]) {
    let out = SystemExec
        .run(&Cmd::new("openssl").args(args.iter().copied()))
        .unwrap();
    assert!(out.ok(), "openssl {args:?}: {}", out.stderr);
}

fn p(path: &Path) -> &str {
    path.to_str().unwrap()
}

/// A throw-away CA that signs leaf certificates.
pub struct TestCa {
    pub cert: PathBuf,
    pub key: PathBuf,
}

impl TestCa {
    pub fn create(dir: &Path) -> TestCa {
        std::fs::create_dir_all(dir).unwrap();
        let cert = dir.join("ca.pem");
        let key = dir.join("ca.key");
        let cnf = dir.join("ca.cnf");
        std::fs::write(
            &cnf,
            "[req]\ndistinguished_name=dn\nx509_extensions=ext\nprompt=no\n[dn]\nCN=Onebox Test CA\n\
             [ext]\nbasicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\n\
             subjectKeyIdentifier=hash\n",
        )
        .unwrap();
        openssl(&[
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
            p(&cnf),
            "-keyout",
            p(&key),
            "-out",
            p(&cert),
        ]);
        TestCa { cert, key }
    }

    /// A leaf for `names` valid `days` days: `(chain = leaf + CA, key)` in
    /// `out`, with the chain written in `order`.
    pub fn leaf(
        &self,
        out: &Path,
        names: &[&str],
        days: u32,
        ca_first: bool,
    ) -> (PathBuf, PathBuf) {
        std::fs::create_dir_all(out).unwrap();
        let key = out.join("key.pem");
        let csr = out.join("leaf.csr");
        let leaf = out.join("leaf.pem");
        let ext = out.join("leaf.ext");
        let san = san_list(names);
        std::fs::write(
            &ext,
            format!(
                "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n\
                 extendedKeyUsage=serverAuth\nsubjectAltName={san}\n"
            ),
        )
        .unwrap();
        openssl(&[
            "req",
            "-new",
            "-newkey",
            "ec",
            "-pkeyopt",
            "ec_paramgen_curve:prime256v1",
            "-nodes",
            "-subj",
            &format!("/CN={}", names[0]),
            "-keyout",
            p(&key),
            "-out",
            p(&csr),
        ]);
        openssl(&[
            "x509",
            "-req",
            "-in",
            p(&csr),
            "-CA",
            p(&self.cert),
            "-CAkey",
            p(&self.key),
            "-CAcreateserial",
            "-days",
            &days.to_string(),
            "-extfile",
            p(&ext),
            "-out",
            p(&leaf),
        ]);
        let leaf_pem = std::fs::read_to_string(&leaf).unwrap();
        let ca_pem = std::fs::read_to_string(&self.cert).unwrap();
        let chain = out.join("chain.pem");
        let text = if ca_first {
            format!("{ca_pem}{leaf_pem}")
        } else {
            format!("{leaf_pem}{ca_pem}")
        };
        std::fs::write(&chain, text).unwrap();
        (chain, key)
    }
}

fn san_list(names: &[&str]) -> String {
    names
        .iter()
        .map(|n| {
            if n.parse::<std::net::IpAddr>().is_ok() {
                format!("IP:{n}")
            } else {
                format!("DNS:{n}")
            }
        })
        .collect::<Vec<_>>()
        .join(",")
}

/// A self-signed pair for `names` in `out` (`cert.pem`, `key.pem`).
pub fn self_signed(out: &Path, names: &[&str], days: u32) -> (PathBuf, PathBuf) {
    std::fs::create_dir_all(out).unwrap();
    let cnf = out.join("self.cnf");
    std::fs::write(
        &cnf,
        format!(
            "[req]\ndistinguished_name=dn\nx509_extensions=ext\nprompt=no\n[dn]\nCN={}\n[ext]\n\
             basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n\
             extendedKeyUsage=serverAuth\nsubjectAltName={}\n",
            names[0],
            san_list(names)
        ),
    )
    .unwrap();
    let (cert, key) = (out.join("cert.pem"), out.join("key.pem"));
    openssl(&[
        "req",
        "-x509",
        "-newkey",
        "ec",
        "-pkeyopt",
        "ec_paramgen_curve:prime256v1",
        "-nodes",
        "-days",
        &days.to_string(),
        "-config",
        p(&cnf),
        "-keyout",
        p(&key),
        "-out",
        p(&cert),
    ]);
    (cert, key)
}

/// Stand-ins for the pinned acme.sh files.
pub const FAKE_ACME: &[u8] = b"#!/bin/sh\n# fake acme.sh for tests\n";
pub const FAKE_DNS_CF: &[u8] = b"#!/bin/sh\ndns_cf_add() { :; }\n";

/// The release pinned to [`FAKE_ACME`] / [`FAKE_DNS_CF`] (real URLs).
pub fn test_release() -> AcmeRelease {
    let mut release = AcmeRelease::pinned();
    release.script.sha256 = sha256_hex(FAKE_ACME);
    release.dns_cf.sha256 = sha256_hex(FAKE_DNS_CF);
    release
}

/// Serve the fake acme.sh files through the fake curl.
pub fn serve_release(fake: &FakeExec) {
    let release = test_release();
    serve(
        fake,
        vec![
            (release.script.url.clone(), Reply::body(FAKE_ACME)),
            (release.dns_cf.url.clone(), Reply::body(FAKE_DNS_CF)),
        ],
    );
}

fn no_env(_: &str) -> Option<String> {
    None
}

/// A free TCP port for the responder (bound and released at once).
pub fn free_port() -> u16 {
    std::net::TcpListener::bind("0.0.0.0:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// Engine over `ctx` with the fake release, a free responder port, no
/// environment and `init`.
pub fn engine(ctx: &Ctx, init: InitSystem) -> Engine<'_> {
    Engine {
        ctx,
        release: test_release(),
        http01_port: free_port(),
        env: &no_env,
        init,
    }
}

/// How the fake acme.sh behaves on its next calls.
#[derive(Clone, Debug, Default)]
pub struct AcmeScript {
    /// `(chain, key)` it "issues" (copied into the acme.sh cert home).
    pub issue: Option<(PathBuf, PathBuf)>,
    pub code: i32,
    pub output: String,
    /// Fetch the challenge token over HTTP from 127.0.0.1:port and fail
    /// unless the responder serves it.
    pub fetch_port: Option<u16>,
    /// Fail (exit 1) for this primary name whatever `code` says.
    pub fail_for: Option<String>,
}

/// Shared, adjustable script of the fake acme.sh.
pub type Script = Arc<Mutex<AcmeScript>>;

/// Install the fake acme.sh: writes a token to `--webroot`, records
/// `Le_Webroot` on `--issue`, copies the scripted pair on success.
pub fn fake_acme(fake: &FakeExec, script: AcmeScript) -> Script {
    let shared = Arc::new(Mutex::new(script));
    let handle = shared.clone();
    fake.on_fn(
        |cmd| cmd.program.ends_with("/acme.sh"),
        move |cmd| {
            let s = handle.lock().unwrap().clone();
            Ok(run_fake_acme(cmd, &s))
        },
    );
    shared
}

/// The acme.sh commands recorded by `fake`.
pub fn acme_calls(fake: &FakeExec) -> Vec<Cmd> {
    fake.calls()
        .into_iter()
        .filter(|c| c.program.ends_with("/acme.sh"))
        .collect()
}

fn run_fake_acme(cmd: &Cmd, s: &AcmeScript) -> Output {
    let arg = |flag: &str| {
        let at = cmd.args.iter().position(|a| a == flag)?;
        cmd.args.get(at + 1).cloned()
    };
    let primary = arg("-d").unwrap();
    if s.fail_for.as_deref() == Some(primary.as_str()) {
        return Output::failure(1, "Verify error: DNS problem");
    }
    let webroot = arg("--webroot");
    if let Some(w) = &webroot {
        let dir = Path::new(w).join(".well-known/acme-challenge");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("tok"), "tok.key").unwrap();
        if s.fetch_port.is_some_and(|port| !fetch_token(port)) {
            return Output::failure(
                1,
                "Invalid response from http://x/.well-known/acme-challenge/tok",
            );
        }
    }
    if let Some((chain, key)) = s.issue.as_ref().filter(|_| s.code == 0) {
        let home = PathBuf::from(arg("--cert-home").unwrap()).join(format!("{primary}_ecc"));
        std::fs::create_dir_all(&home).unwrap();
        std::fs::copy(chain, home.join("fullchain.cer")).unwrap();
        std::fs::copy(key, home.join(format!("{primary}.key"))).unwrap();
        if cmd.args.iter().any(|a| a == "--issue") {
            let recorded = webroot.unwrap_or_else(|| "dns_cf".into());
            std::fs::write(
                home.join(format!("{primary}.conf")),
                format!("Le_Domain='{primary}'\nLe_Webroot='{recorded}'\n"),
            )
            .unwrap();
        }
    }
    Output {
        code: s.code,
        stdout: s.output.clone(),
        stderr: String::new(),
    }
}

fn fetch_token(port: u16) -> bool {
    use std::io::{Read, Write};
    let Ok(mut stream) = std::net::TcpStream::connect(("127.0.0.1", port)) else {
        return false;
    };
    let _ = stream.write_all(b"GET /.well-known/acme-challenge/tok HTTP/1.1\r\nHost: x\r\n\r\n");
    let mut reply = String::new();
    let _ = stream.read_to_string(&mut reply);
    reply.starts_with("HTTP/1.1 200") && reply.ends_with("tok.key")
}
