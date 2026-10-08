use super::*;
use crate::sys::fs::TempDir;
use tar::EntryType;

const BIN: &[u8] = b"\x7fELF fake core binary";
const MAX: u64 = 1 << 20;

/// `(raw name, bytes, entry type)` members of a test tarball.
type TarMember<'a> = (&'a str, &'a [u8], EntryType);
/// `(name, bytes, deflate, unix mode)` members of a test zip.
type ZipEntry<'a> = (&'a str, &'a [u8], bool, u32);

fn tmp() -> TempDir {
    TempDir::new("archive").unwrap()
}

fn tar_result(members: &[(&str, &[u8], EntryType)]) -> (TempDir, Result<u64>) {
    let dir = tmp();
    let package = dir.join("p.tar.gz");
    write_tar_gz(&package, members);
    let result = extract_tar_gz(&package, "sing-box", &dir.join("out"), MAX);
    (dir, result)
}

fn zip_result(members: &[(&str, &[u8], bool, u32)]) -> (TempDir, Result<u64>) {
    let dir = tmp();
    let package = dir.join("p.zip");
    write_zip(&package, members);
    let result = extract_zip(&package, "xray", &dir.join("out"), MAX);
    (dir, result)
}

#[test]
fn tar_extracts_only_the_named_binary() {
    let (dir, result) = tar_result(&[
        ("sing-box-1.0-linux-amd64/", b"", EntryType::Directory),
        (
            "sing-box-1.0-linux-amd64/LICENSE",
            b"MIT",
            EntryType::Regular,
        ),
        ("sing-box-1.0-linux-amd64/sing-box", BIN, EntryType::Regular),
    ]);
    assert_eq!(result.unwrap(), BIN.len() as u64);
    assert_eq!(std::fs::read(dir.join("out")).unwrap(), BIN);
    assert!(
        !dir.join("sing-box-1.0-linux-amd64").exists(),
        "nothing else unpacked"
    );
}

#[test]
fn tar_refusals() {
    let cases: [(&[TarMember], &str); 7] = [
        (
            &[("dir/LICENSE", b"x", EntryType::Regular)],
            "压缩包未包含 sing-box",
        ),
        (
            &[
                ("a/sing-box", BIN, EntryType::Regular),
                ("b/sing-box", BIN, EntryType::Regular),
            ],
            "压缩包含多个 sing-box",
        ),
        (&[("../sing-box", BIN, EntryType::Regular)], UNSAFE),
        (&[("/usr/bin/sing-box", BIN, EntryType::Regular)], UNSAFE),
        (
            &[
                ("dir/sing-box", BIN, EntryType::Regular),
                ("dir/../../etc/x", b"x", EntryType::Regular),
            ],
            UNSAFE,
        ),
        (&[("dir/link", b"", EntryType::Symlink)], UNSAFE),
        (&[("dir/sing-box", b"", EntryType::Link)], UNSAFE),
    ];
    for (members, want) in cases {
        let (_dir, result) = tar_result(members);
        assert_eq!(result.unwrap_err().to_string(), want, "{members:?}");
    }
}

#[test]
fn tar_size_cap_and_corruption() {
    let dir = tmp();
    let package = dir.join("p.tar.gz");
    write_tar_gz(&package, &[("sing-box", &[7u8; 64], EntryType::Regular)]);
    let err = extract_tar_gz(&package, "sing-box", &dir.join("out"), 63).unwrap_err();
    assert_eq!(err.to_string(), "sing-box 超过大小上限（63 字节）");
    let err = extract_tar_gz(&package, "frps", &dir.join("frps"), 1 << 20).unwrap_err();
    assert_eq!(err.to_string(), "压缩包未包含 frps", "generic for FRP");
    std::fs::write(&package, b"\x1f\x8bnot really gzip").unwrap();
    let err = extract_tar_gz(&package, "sing-box", &dir.join("out2"), MAX).unwrap_err();
    assert!(err.to_string().starts_with(CORRUPT), "{err}");
}

#[test]
fn zip_stored_and_deflated_members() {
    for deflate in [false, true] {
        let payload = BIN.repeat(100);
        let (dir, result) = zip_result(&[
            ("geoip.dat", b"geo data", deflate, 0o100644),
            ("xray", &payload, deflate, 0o100755),
            ("LICENSE", b"MPL", deflate, 0o100644),
        ]);
        assert_eq!(result.unwrap(), payload.len() as u64);
        assert_eq!(std::fs::read(dir.join("out")).unwrap(), payload);
    }
    let (dir, result) = zip_result(&[("bin/xray", BIN, true, 0)]);
    assert_eq!(result.unwrap(), BIN.len() as u64, "nested and no unix mode");
    assert_eq!(std::fs::read(dir.join("out")).unwrap(), BIN);
}

#[test]
fn zip_refusals() {
    let cases: [(&[ZipEntry], &str); 7] = [
        (&[("LICENSE", b"x", true, 0o100644)], "压缩包未包含 xray"),
        (
            &[("dir/", b"", false, 0o40755), ("dir/geo", b"x", false, 0)],
            "压缩包未包含 xray",
        ),
        (
            &[("a/xray", BIN, true, 0), ("b/xray", BIN, false, 0)],
            "压缩包含多个 xray",
        ),
        (&[("../xray", BIN, true, 0)], UNSAFE),
        (&[("/xray", BIN, true, 0)], UNSAFE),
        (&[("dir\\..\\xray", BIN, true, 0)], UNSAFE),
        (&[("xray", b"/usr/bin/evil", false, 0o120777)], UNSAFE),
    ];
    for (members, want) in cases {
        let (_dir, result) = zip_result(members);
        assert_eq!(result.unwrap_err().to_string(), want, "{members:?}");
    }
}

#[test]
fn zip_detects_corruption_and_size() {
    let dir = tmp();
    let package = dir.join("p.zip");
    write_zip(&package, &[("xray", BIN, false, 0o100755)]);
    let mut bytes = std::fs::read(&package).unwrap();
    // Flip one byte of the stored payload (after the 30-byte header + name).
    bytes[30 + 4 + 3] ^= 0xff;
    std::fs::write(&package, &bytes).unwrap();
    let err = extract_zip(&package, "xray", &dir.join("out"), MAX).unwrap_err();
    assert_eq!(err.to_string(), "压缩包已损坏（CRC 校验失败）");
    assert!(!dir.join("out").exists(), "bad output removed");

    write_zip(&package, &[("xray", &[1u8; 100], true, 0)]);
    let err = extract_zip(&package, "xray", &dir.join("out"), 99).unwrap_err();
    assert_eq!(err.to_string(), "xray 超过大小上限（99 字节）");
    write_zip(&package, &[("xray", &[1u8; 100], false, 0)]);
    let err = extract_zip(&package, "xray", &dir.join("out"), 99).unwrap_err();
    assert_eq!(err.to_string(), "xray 超过大小上限（99 字节）");
    assert_eq!(
        too_big("sing-box", 512 << 20).to_string(),
        "sing-box 超过大小上限（512 MiB）"
    );

    for broken in [&b""[..], b"PK\x03\x04short", &bytes[..bytes.len() - 10]] {
        std::fs::write(&package, broken).unwrap();
        let err = extract_zip(&package, "xray", &dir.join("out"), MAX).unwrap_err();
        assert!(err.to_string().starts_with(CORRUPT), "{err}");
    }
}

#[test]
fn output_must_not_exist() {
    let dir = tmp();
    let package = dir.join("p.zip");
    write_zip(&package, &[("xray", BIN, true, 0)]);
    std::fs::write(dir.join("out"), b"existing").unwrap();
    assert!(extract_zip(&package, "xray", &dir.join("out"), MAX).is_err());
    assert_eq!(std::fs::read(dir.join("out")).unwrap(), b"existing");
}

/// Real release packages (`ONEBOX_TEST_XRAY_ZIP=…/Xray-linux-64.zip`,
/// `ONEBOX_TEST_SINGBOX_TGZ=…/sing-box-1.14.2-linux-amd64-musl.tar.gz`).
#[test]
#[ignore = "needs real release packages"]
fn real_release_packages() {
    let dir = tmp();
    if let Some(zip) = std::env::var_os("ONEBOX_TEST_XRAY_ZIP") {
        let n = extract_zip(Path::new(&zip), "xray", &dir.join("xray"), 512 << 20).unwrap();
        assert!(n > 1 << 20);
        crate::host::fetch::check_elf(&dir.join("xray")).unwrap();
    }
    if let Some(tgz) = std::env::var_os("ONEBOX_TEST_SINGBOX_TGZ") {
        let out = dir.join("sing-box");
        let n = extract_tar_gz(Path::new(&tgz), "sing-box", &out, 512 << 20).unwrap();
        assert!(n > 1 << 20);
        crate::host::fetch::check_elf(&out).unwrap();
    }
}
