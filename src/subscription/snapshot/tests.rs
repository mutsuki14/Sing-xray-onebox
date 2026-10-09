use super::*;
use crate::domain::fixtures::config;
use crate::domain::protocol::{Core, Protocol};
use crate::render::fixtures::spec;
use crate::subscription::testing::{reality, Node, Xorshift};
use ClientFormat::*;

#[test]
fn supported_formats_follow_the_capability_table() {
    let cases: [(&[(Protocol, u16, Core)], &[ClientFormat]); 4] = [
        (
            &[(Protocol::VlessReality, 443, Core::Singbox)],
            &[Base64, Mihomo, Provider, Singbox, SingboxNoTun, Xray],
        ),
        (
            &[(Protocol::AnytlsReality, 443, Core::Singbox)],
            &[Singbox, SingboxNoTun],
        ),
        (
            &[(Protocol::VlessXhttp, 443, Core::Xray)],
            &[Base64, Mihomo, Provider, Xray],
        ),
        (
            &[(Protocol::Shadowtls, 443, Core::Singbox)],
            &[Mihomo, Provider, Singbox, SingboxNoTun],
        ),
    ];
    for (inbounds, want) in cases {
        assert_eq!(supported_formats(&config(inbounds)), want, "{inbounds:?}");
    }
}

#[test]
fn render_publishes_exactly_the_client_documents() {
    let cfg = reality();
    let spec = spec(&cfg);
    let published = render_with(&spec, &mut Xorshift(3)).unwrap();
    assert_eq!(published.published_formats(), supported_formats(&cfg));
    assert_eq!(published.generation.len(), 24);
    assert!(crate::subscription::devices::lower_hex(&published.generation, 24));
    let private = &cfg.creds.reality.as_ref().unwrap().private_key;
    for format in published.published_formats() {
        let body = published.body(format).unwrap();
        assert_eq!(body, crate::render::client(&spec, format).unwrap());
        assert!(!body.contains(private.as_str()), "{format} leaks the key");
    }
    assert_eq!(published.body(Links), None, "links are not a remote format");
    let other = render_with(&spec, &mut Xorshift(4)).unwrap();
    assert_ne!(other.generation, published.generation);
    assert_eq!(other.formats, published.formats);
}

#[test]
fn bodies_must_be_non_blank_and_bounded() {
    assert_eq!(
        check_body(Mihomo, " \n").unwrap_err().to_string(),
        "mihomo 客户端配置为空"
    );
    let huge = "x".repeat(MAX_BODY_BYTES + 1);
    assert_eq!(check_body(Xray, &huge).unwrap_err().to_string(), TOO_LARGE);
    assert!(check_body(Xray, &huge[1..]).is_ok());
}

#[test]
fn files_keep_the_v2_shape() {
    let node = Node::new("sub-snap-files");
    let paths = &node.ctx.paths;
    assert_eq!(load(paths).unwrap(), None);
    assert!(!remove(paths).unwrap());
    let snapshot = Published {
        generation: "0123456789abcdef01234567".into(),
        formats: [("singbox".to_owned(), "{}\n".to_owned()), ("base64".to_owned(), "x\n".to_owned())]
            .into_iter()
            .collect(),
    };
    write(paths, &snapshot).unwrap();
    let bytes = std::fs::read_to_string(paths.published()).unwrap();
    assert_eq!(
        bytes,
        r#"{"generation":"0123456789abcdef01234567","formats":{"base64":"x\n","singbox":"{}\n"}}"#
    );
    assert_eq!(load(paths).unwrap(), Some(snapshot.clone()));
    assert_eq!(snapshot.published_formats(), [Base64, Singbox]);
    // A snapshot written by v2 (same shape) is read as is.
    std::fs::write(
        paths.published(),
        r#"{"generation":"aaaaaaaaaaaaaaaaaaaaaaaa","formats":{"xray":"{}"}}"#,
    )
    .unwrap();
    assert_eq!(load(paths).unwrap().unwrap().body(Xray), Some("{}"));
    std::fs::write(paths.published(), "not json").unwrap();
    assert!(load(paths)
        .unwrap_err()
        .to_string()
        .starts_with("订阅快照 published.json 无效"));
    assert!(remove(paths).unwrap());
    assert!(!paths.published().exists());
}
