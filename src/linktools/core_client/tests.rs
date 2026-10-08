use super::*;
use crate::domain::protocol::Transport;
use crate::linktools::testutil::entry;
use crate::sys::exec::FakeLife;
use std::io::{Read, Write};
use std::sync::Arc;
use std::thread;

fn fast() -> Timing {
    Timing {
        check: Duration::from_secs(5),
        ready: Duration::from_millis(400),
        poll: Duration::from_millis(10),
        login: Duration::from_millis(100),
    }
}

#[test]
fn temporary_configs_are_exactly_v2s() {
    let mut sb = entry("vless-reality", Core::Singbox, Transport::Tcp);
    sb.tag = "onebox-VLESS".into();
    sb.outbounds = vec![json!({"type": "vless", "tag": "onebox-VLESS"})];
    assert_eq!(
        client_config(&sb, 30001, "tok"),
        json!({"log":{"disabled":true},
            "dns":{"servers":[{"type":"local","tag":"local"}]},
            "inbounds":[{"type":"socks","listen":"127.0.0.1","listen_port":30001,
                "users":[{"username":"onebox-","password":"tok"}]}],
            "outbounds":[{"type":"vless","tag":"onebox-VLESS"}],
            "route":{"final":"onebox-VLESS","default_domain_resolver":"local"}})
    );
    let xr = entry("trojan", Core::Xray, Transport::Tcp);
    assert_eq!(
        client_config(&xr, 30002, "tok"),
        json!({"log":{"loglevel":"none"},
            "inbounds":[{"protocol":"socks","listen":"127.0.0.1","port":30002,
                "settings":{"auth":"password","accounts":[{"user":"onebox-","pass":"tok"}],"udp":true}}],
            "outbounds":[{"protocol":"vless","tag":"proxy"}]})
    );
}

#[test]
fn check_and_run_command_lines() {
    let work = Path::new("/tmp/w");
    let bin = Path::new("/opt/onebox/bin/sing-box");
    let check = check_command(Core::Singbox, bin, work).unwrap();
    assert_eq!(
        check.display(),
        "/opt/onebox/bin/sing-box check -c /tmp/w/config.json -D /tmp/w"
    );
    assert_eq!(check.cwd.as_deref(), Some(work));
    let run = run_command(Core::Singbox, bin, work).unwrap();
    assert_eq!(
        run.display(),
        "/opt/onebox/bin/sing-box run -c /tmp/w/config.json -D /tmp/w"
    );
    let xray = Path::new("/usr/bin/xray");
    assert_eq!(
        check_command(Core::Xray, xray, work).unwrap().display(),
        "/usr/bin/xray run -test -c /tmp/w/config.json"
    );
    assert_eq!(
        run_command(Core::Xray, xray, work).unwrap().display(),
        "/usr/bin/xray run -c /tmp/w/config.json"
    );
}

fn write_exe(path: &Path, mode: u32) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, "#!/bin/sh\n").unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
}

#[test]
fn binaries_are_looked_up_flag_then_bin_dir_then_path() {
    let dir = TempDir::new("linktools-test").unwrap();
    let (ctx, exec, _) = Ctx::test(dir.path());
    let err = locate(&ctx, Core::Xray, None).unwrap_err();
    assert_eq!(err.to_string(), "缺少客户端内核: xray");
    exec.provide("xray");
    assert_eq!(
        locate(&ctx, Core::Xray, None).unwrap(),
        PathBuf::from("/usr/bin/xray")
    );
    let own = ctx.paths.core_bin(Core::Xray);
    write_exe(&own, 0o644);
    assert_eq!(
        locate(&ctx, Core::Xray, None).unwrap(),
        PathBuf::from("/usr/bin/xray"),
        "a non-executable own core is skipped"
    );
    fs::set_permissions(&own, fs::Permissions::from_mode(0o755)).unwrap();
    assert_eq!(locate(&ctx, Core::Xray, None).unwrap(), own);

    let flag = dir.join("custom/xray");
    write_exe(&flag, 0o755);
    let real = fs::canonicalize(&flag).unwrap();
    assert_eq!(locate(&ctx, Core::Xray, Some(&flag)).unwrap(), real);
    fs::set_permissions(&flag, fs::Permissions::from_mode(0o600)).unwrap();
    let err = locate(&ctx, Core::Xray, Some(&flag)).unwrap_err();
    assert_eq!(
        err.to_string(),
        format!("客户端内核不可执行: {}", flag.display())
    );
    let err = locate(&ctx, Core::Singbox, Some(&dir.join("missing"))).unwrap_err();
    assert_eq!(err.to_string(), "客户端内核不存在: singbox");
}

#[test]
fn proc_parsers() {
    let stat = "4242 (sing box) S 1 4242 4242 0 -1 4194560 100 0 0 0 150 50 0 0 20 0 9 0 \
                12345 1000000 2500 18446744073709551615";
    assert_eq!(parse_cpu_seconds(stat), Some(2.0));
    assert_eq!(parse_cpu_seconds("garbage"), None);
    assert_eq!(parse_cpu_seconds("1 (x) S 1"), None);
    let status = "Name:\tsing-box\nVmPeak:\t  50000 kB\nVmRSS:\t   30720 kB\nThreads:\t9\n";
    assert_eq!(parse_rss_bytes(status), Some(31_457_280));
    assert_eq!(parse_rss_bytes("VmRSS:\t12 MB\n"), None);
    assert_eq!(parse_rss_bytes("Name:\tx\n"), None);
}

#[test]
fn core_messages_are_shown_without_credentials() {
    let mut e = entry("x", Core::Singbox, Transport::Tcp);
    e.outbounds = vec![json!({"type": "vless", "tag": "proxy",
        "uuid": "11111111-2222", "tls": {"reality": {"public_key": "PUBKEY-abc"}}})];
    let secrets = secrets(&e, &"f".repeat(48));
    let output = Output {
        code: 1,
        stdout: "Xray banner\n".into(),
        stderr: format!(
            "line one\nFATAL\x1b[31m bad uuid 11111111-2222 key PUBKEY-abc token {}\n\n",
            "f".repeat(48)
        ),
    };
    assert_eq!(
        redacted_detail(&output, &secrets),
        "FATAL bad uuid *** key *** token ***"
    );
    let stdout_only = Output::success("Failed to start: 11111111-2222 invalid\n");
    assert_eq!(
        redacted_detail(&stdout_only, &secrets),
        "Failed to start: *** invalid"
    );
    let long = Output::failure(1, "x".repeat(500));
    assert_eq!(redacted_detail(&long, &secrets).chars().count(), DETAIL_CHARS);
}

/// Reads the port and token of the config named by a check command.
fn config_of(cmd: &Cmd) -> (u16, String) {
    let path = &cmd.args[2];
    let config: Value = serde_json::from_str(&fs::read_to_string(path).unwrap()).unwrap();
    let inbound = &config["inbounds"][0];
    (
        inbound["listen_port"].as_u64().unwrap() as u16,
        inbound["users"][0]["password"].as_str().unwrap().to_owned(),
    )
}

/// A fake core's SOCKS inbound: binds `port` once the reservation is gone
/// and accepts one login with `token`.
fn fake_inbound(port: u16, token: String) -> thread::JoinHandle<bool> {
    thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(5);
        let listener = loop {
            match TcpListener::bind((Ipv4Addr::LOCALHOST, port)) {
                Ok(l) => break l,
                Err(_) if Instant::now() < deadline => thread::sleep(Duration::from_millis(2)),
                Err(_) => return false,
            }
        };
        let Ok((mut stream, _)) = listener.accept() else {
            return false;
        };
        let mut hello = [0u8; 3];
        stream.read_exact(&mut hello).unwrap();
        stream.write_all(&[5, 2]).unwrap();
        let mut auth = vec![0u8; 2 + USERNAME.len() + 1 + token.len()];
        stream.read_exact(&mut auth).unwrap();
        let ok = auth.ends_with(token.as_bytes());
        stream.write_all(&[1, if ok { 0 } else { 1 }]).unwrap();
        ok
    })
}

fn sb_entry() -> ProbeEntry {
    entry("vless-reality", Core::Singbox, Transport::Tcp)
}

fn start(ctx: &Ctx, cancel: &CancelToken) -> Result<ClientCore> {
    ClientCore::start(ctx, &sb_entry(), Path::new("/bin/sing-box"), cancel, fast())
}

#[test]
fn a_core_is_ready_once_its_socks_login_works() {
    let dir = TempDir::new("linktools-test").unwrap();
    let (ctx, exec, _) = Ctx::test(dir.path());
    let inbound = Arc::new(Mutex::new(None));
    let slot = inbound.clone();
    exec.on_fn(
        |cmd| cmd.program_name() == "sing-box" && cmd.args[0] == "check",
        move |cmd| {
            let (port, token) = config_of(cmd);
            *slot.lock().unwrap() = Some(fake_inbound(port, token));
            Ok(Output::success(""))
        },
    )
    .on_spawn("sing-box", &["run"], FakeLife::UntilKilled, Output::default());
    let core = start(&ctx, &CancelToken::manual()).unwrap();
    assert!(inbound.lock().unwrap().take().unwrap().join().unwrap());
    assert_eq!(core.endpoint().token.len(), 48);
    assert!(core.endpoint().token.bytes().all(|b| b.is_ascii_hexdigit()));
    assert_eq!(core.exited(), None);
    assert_eq!(core.resources(), Resources::default(), "fake pid has no /proc");
    let run = exec.calls().pop().unwrap();
    assert_eq!(run.args[..2], ["run", "-c"]);
    let config = PathBuf::from(&run.args[2]);
    let mode = fs::metadata(&config).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
    let work = config.parent().unwrap().to_path_buf();
    assert_eq!(fs::metadata(&work).unwrap().permissions().mode() & 0o777, 0o700);
    core.terminate();
    assert_eq!(exec.signals(), [(core.pid(), libc::SIGTERM)]);
    assert!(core.exited().is_some());
    drop(core);
    assert!(!work.exists(), "work dir removed with the core");
}

#[test]
fn startup_failures_are_distinguished() {
    let dir = TempDir::new("linktools-test").unwrap();
    let (ctx, exec, _) = Ctx::test(dir.path());
    exec.on("sing-box", &["check"], Output::failure(1, "FATAL unknown field"));
    let err = start(&ctx, &CancelToken::manual()).err().unwrap();
    assert_eq!(
        err.to_string(),
        "客户端配置校验失败（检查内核版本；未打印凭据；退出码 1）: FATAL unknown field"
    );

    let (ctx, exec, _) = Ctx::test(dir.path());
    exec.on("sing-box", &["check"], Output::success(""))
        .on_spawn("sing-box", &["run"], FakeLife::Exits, Output::failure(2, ""));
    let err = start(&ctx, &CancelToken::manual()).err().unwrap();
    assert_eq!(err.to_string(), "客户端内核启动失败（退出码 2）");

    let (ctx, exec, _) = Ctx::test(dir.path());
    exec.on("sing-box", &["check"], Output::success(""))
        .on_spawn("sing-box", &["run"], FakeLife::UntilKilled, Output::default());
    let err = start(&ctx, &CancelToken::manual()).err().unwrap();
    assert_eq!(err.to_string(), "客户端内核启动超时");
    // Cancelled while waiting for readiness.
    let cancel = CancelToken::manual();
    let remote = cancel.clone();
    let timer = thread::spawn(move || {
        thread::sleep(Duration::from_millis(50));
        remote.cancel();
    });
    let err = start(&ctx, &cancel).err().unwrap();
    timer.join().unwrap();
    assert!(err.is_cancelled(), "{err}");
    let killed = exec.signals();
    assert_eq!(killed.len(), 2, "both unready cores were stopped: {killed:?}");
}

#[test]
fn a_port_lost_to_another_process_is_retried() {
    let dir = TempDir::new("linktools-test").unwrap();
    let (ctx, exec, _) = Ctx::test(dir.path());
    let held = Arc::new(Mutex::new(Vec::new()));
    let thief = held.clone();
    exec.on("sing-box", &["check"], Output::success(""))
        .on_fn(
            |cmd| cmd.args.first().is_some_and(|a| a == "run"),
            move |cmd| {
                // Another process grabs the port between reservation and bind.
                let path = &cmd.args[2];
                let config: Value =
                    serde_json::from_str(&fs::read_to_string(path).unwrap()).unwrap();
                let port = config["inbounds"][0]["listen_port"].as_u64().unwrap() as u16;
                thief
                    .lock()
                    .unwrap()
                    .push(TcpListener::bind((Ipv4Addr::LOCALHOST, port)).unwrap());
                Ok(Output::failure(1, "listen: address already in use"))
            },
        );
    let err = start(&ctx, &CancelToken::manual()).err().unwrap();
    assert_eq!(err.to_string(), "客户端内核启动失败：本机端口被占用");
    assert_eq!(held.lock().unwrap().len(), START_ATTEMPTS);
}
