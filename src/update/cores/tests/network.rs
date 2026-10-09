//! Releases looked up and downloaded over the (fake) network.

use super::*;

fn singbox_package(version: &str, binary: &[u8]) -> (String, Vec<u8>) {
    let name = format!("sing-box-{version}-linux-amd64-musl.tar.gz");
    let mut builder = tar::Builder::new(flate2::write::GzEncoder::new(
        Vec::new(),
        flate2::Compression::fast(),
    ));
    let mut header = tar::Header::new_gnu();
    header.set_size(binary.len() as u64);
    header.set_mode(0o755);
    header.set_entry_type(tar::EntryType::Regular);
    header.set_cksum();
    builder
        .append_data(
            &mut header,
            format!("sing-box-{version}-linux-amd64-musl/sing-box"),
            binary,
        )
        .unwrap();
    let package = builder.into_inner().unwrap().finish().unwrap();
    (name, package)
}

fn singbox_release(version: &str, name: &str, package: &[u8]) -> Reply {
    let tag = format!("v{version}");
    Reply::body(
        json!({
            "tag_name": tag,
            "draft": false,
            "prerelease": false,
            "body": "",
            "assets": [{
                "name": name,
                "size": package.len(),
                "browser_download_url": Asset::expected_url(cores::repo(Core::Singbox), &tag, name),
                "digest": format!("sha256:{}", sha256_hex(package)),
            }],
        })
        .to_string(),
    )
}

#[test]
fn releases_are_downloaded_and_verified_into_the_staging_directory() {
    let fx = Fx::both();
    let binary = says(Core::Singbox, "1.14.3");
    let (name, package) = singbox_package("1.14.3", &binary);
    let url = Asset::expected_url(cores::repo(Core::Singbox), "v1.14.3", &name);
    serve(
        &fx.exec,
        vec![
            (SB_API.into(), singbox_release("1.14.3", &name, &package)),
            (url.clone(), Reply::body(package.clone())),
        ],
    );
    fx.run(CoreSelection::All, None, false).unwrap();
    let applied = fx.request();
    assert_eq!(replaced(&applied), [Core::Singbox]);
    assert_eq!(applied.staged[0].2, binary);
    assert_eq!(versions(&applied).singbox.as_deref(), Some("1.14.3"));
    // Xray 26.3.27 is the target and installed: no lookup for it.
    assert_eq!(fx.curl_calls(), [SB_API.to_owned(), url]);
    assert!(fx.staging_dirs().is_empty());
}

#[test]
fn a_failed_download_leaves_no_staging_directory() {
    let fx = Fx::both();
    let binary = says(Core::Singbox, "1.14.3");
    let (name, package) = singbox_package("1.14.3", &binary);
    // The package is not served (404).
    serve(
        &fx.exec,
        vec![(SB_API.into(), singbox_release("1.14.3", &name, &package))],
    );
    let err = fx.run(CoreSelection::All, None, false).unwrap_err();
    assert!(err.to_string().contains("404"), "{err}");
    assert!(fx.applied().is_empty());
    assert!(fx.staging_dirs().is_empty());
}
