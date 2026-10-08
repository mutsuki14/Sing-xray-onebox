//! Test helpers: a real-openssl context, throw-away certificates (a test CA,
//! CA-signed leaves, self-signed pairs) and [`HybridExec`], which runs the
//! real openssl while every other program is scripted by a [`FakeExec`].
//!
//! Public verification against the test CA works by giving openssl
//! `SSL_CERT_FILE` (its default store) — the production code runs the very
//! same `openssl verify` command.

use crate::ctx::Ctx;
use crate::error::Result;
use crate::paths::Paths;
use crate::sys::exec::{Cmd, Exec, FakeExec, Output, RunningChild, SystemExec};
use crate::sys::fs::TempDir;
use crate::ui::ScriptedPrompter;
use std::path::{Path, PathBuf};
use std::sync::Arc;

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
    pub ui: Arc<ScriptedPrompter>,
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
            ui: ui.clone(),
        };
        Fixture {
            dir,
            ctx,
            fake,
            ui,
            ca,
        }
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
            "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
            "-nodes", "-days", "3650", "-config", p(&cnf), "-keyout", p(&key), "-out", p(&cert),
        ]);
        TestCa {
            cert,
            key,
        }
    }

    /// A leaf for `names` valid `days` days: `(chain = leaf + CA, key)` in
    /// `out`, with the chain written in `order`.
    pub fn leaf(&self, out: &Path, names: &[&str], days: u32, ca_first: bool) -> (PathBuf, PathBuf) {
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
            "req", "-new", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes",
            "-subj", &format!("/CN={}", names[0]), "-keyout", p(&key), "-out", p(&csr),
        ]);
        openssl(&[
            "x509", "-req", "-in", p(&csr), "-CA", p(&self.cert), "-CAkey", p(&self.key),
            "-CAcreateserial", "-days", &days.to_string(), "-extfile", p(&ext), "-out", p(&leaf),
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
        "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes",
        "-days", &days.to_string(), "-config", p(&cnf), "-keyout", p(&key), "-out", p(&cert),
    ]);
    (cert, key)
}
