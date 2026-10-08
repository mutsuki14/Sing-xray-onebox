use super::*;
use crate::domain::protocol::{Core, Protocol};
use crate::render::fixtures::{config, spec, spec_with};
use crate::sys::fs::TempDir;
use std::os::unix::fs::PermissionsExt;
use Core::{Singbox as SB, Xray as XR};
use Protocol::*;

fn files(names: &[&str]) -> Vec<(String, Vec<u8>)> {
    names
        .iter()
        .map(|n| (n.to_string(), format!("{n}\n").into_bytes()))
        .collect()
}

fn mode(path: &Path) -> u32 {
    fs::metadata(path).unwrap().permissions().mode() & 0o777
}

fn listing(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    names.sort();
    names
}

#[test]
fn creates_then_replaces_the_whole_directory() {
    let tmp = TempDir::new("publish").unwrap();
    let target = tmp.join("root/client");
    let first = replace_dir(&target, &files(&["a.txt", "b.txt"])).unwrap();
    assert!(first.warnings.is_empty());
    assert_eq!(listing(&target), ["a.txt", "b.txt"]);
    assert_eq!(mode(&target), 0o700);
    assert_eq!(mode(&target.join("a.txt")), 0o600);
    assert_eq!(mode(&tmp.join("root")), 0o700);
    fs::write(target.join("user-file"), "x").unwrap();
    replace_dir(&target, &files(&["c.txt"])).unwrap();
    assert_eq!(listing(&target), ["c.txt"]);
    assert_eq!(fs::read_to_string(target.join("c.txt")).unwrap(), "c.txt\n");
    assert_eq!(
        listing(&tmp.join("root")),
        ["client"],
        "no stage left behind"
    );
}

#[test]
fn stale_stage_directories_are_swept() {
    let tmp = TempDir::new("publish").unwrap();
    let target = tmp.join("client");
    let stale = tmp.join(".client-new-0123456789abcdef01234567");
    fs::create_dir(&stale).unwrap();
    fs::write(stale.join("links.txt"), "old credentials").unwrap();
    fs::write(tmp.join(".clientele"), "unrelated").unwrap();
    replace_dir(&target, &files(&["x"])).unwrap();
    assert_eq!(listing(tmp.path()), [".clientele", "client"]);
}

#[test]
fn refuses_symlinks_files_and_bad_names_without_side_effects() {
    let tmp = TempDir::new("publish").unwrap();
    let real = tmp.join("real");
    fs::create_dir(&real).unwrap();
    let link = tmp.join("client");
    std::os::unix::fs::symlink(&real, &link).unwrap();
    let err = replace_dir(&link, &files(&["x"])).unwrap_err().to_string();
    assert!(err.starts_with("不允许符号链接"), "{err}");
    let file = tmp.join("plain");
    fs::write(&file, "x").unwrap();
    let err = replace_dir(&file, &files(&["x"])).unwrap_err().to_string();
    assert!(err.starts_with("客户端目录路径不是目录"), "{err}");
    let target = tmp.join("out");
    for bad in ["", ".", "..", "a/b", "nul\0"] {
        let err = replace_dir(&target, &files(&[bad]))
            .unwrap_err()
            .to_string();
        assert!(err.starts_with("发布文件名无效"), "{bad:?}: {err}");
    }
    let err = replace_dir(&target, &files(&["a", "a"]))
        .unwrap_err()
        .to_string();
    assert_eq!(err, "发布文件名重复: a");
    assert_eq!(listing(tmp.path()), ["client", "plain", "real"]);
    assert!(listing(&real).is_empty());
}

#[test]
fn client_files_follow_the_supported_formats() {
    let names = |s: &NodeSpec| -> Vec<String> {
        client_files(s)
            .unwrap()
            .into_iter()
            .map(|(n, _)| n)
            .collect()
    };
    assert_eq!(
        names(&spec_with(&[(Trojan, 443, XR)])),
        [
            "links.txt",
            "sub.txt",
            "mihomo.yaml",
            "provider.yaml",
            "sing-box.json",
            "sing-box-notun.json",
            "xray.json",
            "probe.json"
        ]
    );
    assert_eq!(
        names(&spec_with(&[(AnytlsReality, 443, SB)])),
        ["sing-box.json", "sing-box-notun.json", "probe.json"]
    );
    assert_eq!(
        names(&spec_with(&[(VlessXhttp, 443, XR)])),
        [
            "links.txt",
            "sub.txt",
            "mihomo.yaml",
            "provider.yaml",
            "xray.json",
            "probe.json"
        ]
    );
    let all = client_files(&spec_with(&[(Trojan, 443, SB)])).unwrap();
    let probe = &all.last().unwrap().1;
    assert!(!probe.ends_with(b"\n"));
    assert!(all[..all.len() - 1].iter().all(|(_, b)| b.ends_with(b"\n")));
}

#[test]
fn write_clients_publishes_and_a_render_error_keeps_the_old_directory() {
    let tmp = TempDir::new("publish").unwrap();
    let paths = Paths::isolated(tmp.path());
    let published = write_clients(&paths, &spec_with(&[(Trojan, 443, SB)])).unwrap();
    assert!(published.warnings.is_empty());
    let target = paths.clients();
    let before = fs::read(target.join("sing-box.json")).unwrap();
    assert!(target.join("xray.json").exists());
    // A pinned certificate that was not loaded cannot render client files.
    let unloaded = NodeSpec::new(&config(&[(Anytls, 443, SB)]), &paths, None).unwrap();
    assert!(write_clients(&paths, &unloaded).is_err());
    assert_eq!(fs::read(target.join("sing-box.json")).unwrap(), before);
    assert!(target.join("xray.json").exists());
    assert_eq!(listing(&paths.root), ["client"]);
    // Switching to AnyTLS-REALITY drops the formats that cannot carry it.
    write_clients(&paths, &spec(&config(&[(AnytlsReality, 443, SB)]))).unwrap();
    assert_eq!(
        listing(&target),
        ["probe.json", "sing-box-notun.json", "sing-box.json"]
    );
}
