use super::*;
use crate::subscription::testing::{device, ip, reality, Node, Xorshift, TOKEN};
use crate::sys::rand::SeqRandom;
use serde_json::json;
use std::os::unix::fs::PermissionsExt;

fn write_v2_settings(node: &Node, enabled: bool, devices: serde_json::Value) {
    let path = node.ctx.paths.subscription_v2_settings();
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    let doc = json!({
        "enabled": enabled, "mode": "ip", "domain": "203.0.113.10", "port": 8448,
        "method": "none", "custom_cert": null, "custom_key": null, "devices": devices,
    });
    std::fs::write(path, serde_json::to_vec_pretty(&doc).unwrap()).unwrap();
}

fn v2_device(id: &str, name: &str) -> serde_json::Value {
    json!({"id": id, "name": name, "hash": token_hash(TOKEN), "created": 1})
}

#[test]
fn load_prefers_devices_json_then_v2_settings_then_empty() {
    let node = Node::new("sub-dev-load");
    let paths = &node.ctx.paths;
    let empty = DeviceStore::load(paths).unwrap();
    assert_eq!((empty.source(), empty.is_empty()), (Source::Empty, true));

    write_v2_settings(
        &node,
        false,
        json!([
            v2_device("00000000000000aa", "手机"),
            v2_device("00000000000000aa", "duplicate id"),
            v2_device("NOT-HEX", "bad id"),
            v2_device("00000000000000bb", "laptop"),
        ]),
    );
    let v2 = DeviceStore::load(paths).unwrap();
    assert_eq!(v2.source(), Source::V2Settings);
    let names: Vec<&str> = v2.devices().iter().map(|d| d.name.as_str()).collect();
    assert_eq!(
        names,
        ["手机", "laptop"],
        "invalid and duplicate entries skipped"
    );

    DeviceStore::write(paths, &[device("00000000000000cc", "tablet", TOKEN)]).unwrap();
    let v3 = DeviceStore::load(paths).unwrap();
    assert_eq!(v3.source(), Source::Devices);
    assert_eq!(v3.devices().len(), 1);
    assert_eq!(list(paths).unwrap()[0].name, "tablet");
}

#[test]
fn write_is_private_validated_and_versioned() {
    let node = Node::new("sub-dev-write");
    let paths = &node.ctx.paths;
    DeviceStore::write(paths, &[device("0123456789abcdef", "a", TOKEN)]).unwrap();
    let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode(&paths.devices()), 0o600);
    assert_eq!(mode(&paths.subscription()), 0o700);
    let text = std::fs::read_to_string(paths.devices()).unwrap();
    assert!(text.starts_with("{\n  \"schema\": 1,\n  \"devices\": [") && text.ends_with("}\n"));
    assert!(!text.contains(TOKEN));

    let bad = [
        device("0123456789ABCDEF", "upper", TOKEN),
        Device {
            hash: "x".into(),
            ..device("0123456789abcdef", "short hash", TOKEN)
        },
        device("0123456789abcdef", "", TOKEN),
        device("0123456789abcdef", "tab\tname", TOKEN),
        device("0123456789abcdef", &"x".repeat(81), TOKEN),
    ];
    for d in bad {
        let err = DeviceStore::write(paths, std::slice::from_ref(&d)).unwrap_err();
        assert_eq!(err.to_string(), "订阅设备数据无效", "{d:?}");
    }
    let twice = [
        device("0123456789abcdef", "a", TOKEN),
        device("0123456789abcdef", "b", TOKEN),
    ];
    assert!(DeviceStore::write(paths, &twice).is_err(), "ids are unique");
    let many: Vec<Device> = (0..257)
        .map(|i| device(&format!("{i:016x}"), &format!("d{i}"), TOKEN))
        .collect();
    assert_eq!(
        DeviceStore::write(paths, &many).unwrap_err().to_string(),
        "订阅设备超过 256 个"
    );

    std::fs::write(paths.devices(), r#"{"schema":2,"devices":[]}"#).unwrap();
    assert!(DeviceStore::load(paths)
        .unwrap_err()
        .to_string()
        .contains("schema 2"));
    std::fs::write(paths.devices(), "[]").unwrap();
    assert!(DeviceStore::load(paths)
        .unwrap_err()
        .to_string()
        .starts_with("订阅设备数据无效"));
}

#[test]
fn create_follows_v2_name_rules_and_hashes_the_token() {
    let mut store = DeviceStore {
        devices: Vec::new(),
        source: Source::Empty,
        endpoint: None,
    };
    let mut rng = Xorshift(7);
    let new = store.create("  手机  ", &mut rng, 42).unwrap();
    assert_eq!(new.name, "手机", "trimmed");
    assert!(lower_hex(&new.id, 16) && lower_hex(&new.token, 64));
    let stored = &store.devices()[0];
    assert_eq!(stored.hash, token_hash(&new.token));
    assert_eq!(stored.created, 42);
    assert!(
        !format!("{new:?}").contains(&new.token),
        "Debug hides the token"
    );

    let cases: [(&str, &str); 5] = [
        ("", BAD_NAME),
        ("   ", BAD_NAME),
        ("a\u{7}b", BAD_NAME),
        (&"汉".repeat(27), BAD_NAME),
        ("手机", DUPLICATE_NAME),
    ];
    for (name, message) in cases {
        let err = store.create(name, &mut rng, 1).unwrap_err();
        assert_eq!(err.to_string(), message, "{name:?}");
    }
    assert!(
        store.create(&"汉".repeat(26), &mut rng, 1).is_ok(),
        "78 bytes fit"
    );
    while store.devices().len() < MAX_DEVICES {
        let name = format!("d{}", store.devices().len());
        store.create(&name, &mut rng, 1).unwrap();
    }
    assert_eq!(
        store
            .create("one more", &mut rng, 1)
            .unwrap_err()
            .to_string(),
        TOO_MANY
    );
    let ids: BTreeSet<&str> = store.devices().iter().map(|d| d.id.as_str()).collect();
    assert_eq!(ids.len(), MAX_DEVICES, "ids are unique");
}

#[test]
fn ids_collide_rarely_but_never_twice() {
    // A source that repeats the same 8 bytes for the first two ids.
    struct Repeating(u8);
    impl Random for Repeating {
        fn fill(&mut self, buf: &mut [u8]) -> Result<()> {
            let value = if self.0 < 4 { 0 } else { self.0 };
            buf.fill(value);
            self.0 = self.0.wrapping_add(1);
            Ok(())
        }
    }
    let mut store = DeviceStore {
        devices: vec![device("0000000000000000", "a", TOKEN)],
        source: Source::Devices,
        endpoint: None,
    };
    let new = store.create("b", &mut Repeating(0), 1).unwrap();
    assert_ne!(new.id, "0000000000000000");
}

#[test]
fn revoke_and_reset_by_exact_id() {
    let mut store = DeviceStore {
        devices: vec![
            device("00000000000000aa", "a", TOKEN),
            device("00000000000000bb", "b", TOKEN),
        ],
        source: Source::Devices,
        endpoint: None,
    };
    let mut rng = SeqRandom(1);
    assert_eq!(
        store.revoke("00000000000000a").unwrap_err().to_string(),
        UNKNOWN_ID
    );
    assert_eq!(
        store.reset("nope", &mut rng, 1).unwrap_err().to_string(),
        UNKNOWN_ID
    );
    let reset = store.reset("00000000000000bb", &mut rng, 99).unwrap();
    assert_eq!(
        (reset.id.as_str(), reset.name.as_str()),
        ("00000000000000bb", "b")
    );
    let b = &store.devices()[1];
    assert_eq!((b.hash.clone(), b.created), (token_hash(&reset.token), 99));
    assert_eq!(store.revoke("00000000000000aa").unwrap().name, "a");
    assert!(
        !authorized(store.devices(), TOKEN),
        "old token no longer works"
    );
    assert!(authorized(store.devices(), &reset.token));
}

#[test]
fn authorization_compares_every_hash() {
    let devices = [
        device("00000000000000aa", "a", &"a".repeat(64)),
        device("00000000000000bb", "b", TOKEN),
    ];
    assert!(authorized(&devices, TOKEN));
    assert!(!authorized(&devices, &"f".repeat(64)));
    assert!(!authorized(&[], TOKEN));
    for (a, b, equal) in [
        ("abc", "abc", true),
        ("abc", "abd", false),
        ("abc", "abcd", false),
        ("", "", true),
    ] {
        assert_eq!(
            constant_time_eq(a.as_bytes(), b.as_bytes()),
            equal,
            "{a} {b}"
        );
    }
}

#[test]
fn serving_fails_closed_and_honors_v2_enabled() {
    let node = Node::new("sub-dev-serving");
    let paths = &node.ctx.paths;
    assert!(serving(paths).is_empty());
    write_v2_settings(&node, false, json!([v2_device("00000000000000aa", "a")]));
    assert!(
        serving(paths).is_empty(),
        "v2 disabled subscription serves nobody"
    );
    write_v2_settings(&node, true, json!([v2_device("00000000000000aa", "a")]));
    assert_eq!(serving(paths).len(), 1);
    std::fs::write(paths.devices(), "{broken").unwrap();
    assert!(
        serving(paths).is_empty(),
        "a broken devices.json is not bypassed"
    );
    DeviceStore::write(paths, &[]).unwrap();
    assert!(serving(paths).is_empty(), "v3 list wins even when empty");
}

#[test]
fn changes_need_the_lock_an_enabled_subscription_and_no_pending_journal() {
    let node = Node::new("sub-dev-ops");
    let ctx = &node.ctx;
    node.save(&reality());
    let lock = node.lock();
    let mut rng = SeqRandom(3);
    let err = add_with(ctx, &lock, &reality(), "phone", &mut rng, 5).unwrap_err();
    assert_eq!(err.to_string(), NOT_ENABLED);
    assert!(!ctx.paths.devices().exists());

    let cfg = ip(8448);
    node.save(&cfg);
    let phone = add_with(ctx, &lock, &cfg, "phone", &mut rng, 5).unwrap();
    let stored = list(&ctx.paths).unwrap();
    assert_eq!(stored.len(), 1);
    assert!(
        authorized(&stored, &phone.token),
        "on disk before it is shown"
    );

    let reset = reset_with(ctx, &lock, &phone.id, &mut rng, 6).unwrap();
    assert!(authorized(&list(&ctx.paths).unwrap(), &reset.token));
    assert!(!authorized(&list(&ctx.paths).unwrap(), &phone.token));

    node.pending_journal();
    for err in [
        add_with(ctx, &lock, &cfg, "tablet", &mut rng, 7).unwrap_err(),
        revoke(ctx, &lock, &phone.id).unwrap_err(),
        reset_with(ctx, &lock, &phone.id, &mut rng, 7).unwrap_err(),
    ] {
        assert_eq!(err.to_string(), PENDING);
    }
    std::fs::remove_dir_all(ctx.paths.transaction()).unwrap();
    revoke(ctx, &lock, &phone.id).unwrap();
    assert!(list(&ctx.paths).unwrap().is_empty());
    assert_eq!(
        revoke(ctx, &lock, &phone.id).unwrap_err().to_string(),
        UNKNOWN_ID
    );
}

#[test]
fn a_node_still_in_v2_state_refuses_device_changes() {
    let node = Node::new("sub-dev-v2-node");
    let ctx = &node.ctx;
    // v2 still owns the node (the v3 bootstrap runs from a temp file).
    std::fs::create_dir_all(&ctx.paths.root).unwrap();
    std::fs::write(
        ctx.paths.state(),
        r#"{"values":{"PROTOCOLS":"vless-reality"}}"#,
    )
    .unwrap();
    let id = "00000000000000aa";
    write_v2_settings(&node, true, json!([v2_device(id, "手机")]));
    let lock = node.lock();
    let mut rng = SeqRandom(1);
    for err in [
        add_with(ctx, &lock, &ip(8448), "laptop", &mut rng, 9).unwrap_err(),
        revoke(ctx, &lock, id).unwrap_err(),
        reset_with(ctx, &lock, id, &mut rng, 9).unwrap_err(),
        record_endpoint(ctx, &lock, "http://203.0.113.10:8448").unwrap_err(),
    ] {
        assert_eq!(err.to_string(), V2_NODE);
    }
    assert!(!ctx.paths.devices().exists(), "nothing v2 would not read");
    assert_eq!(serving(&ctx.paths).len(), 1, "the v2 device still works");
    // Once migrated (state.json in v3 shape), changes work again.
    node.save(&ip(8448));
    revoke(ctx, &lock, id).unwrap();
    assert!(list(&ctx.paths).unwrap().is_empty());
}

/// Revoking never needs the configuration: a state.json that cannot be
/// read or parsed is not taken for a v2 node (the worker serves on
/// regardless), so a leaked device can still be revoked at once.
#[test]
fn an_unreadable_state_json_does_not_block_revoking() {
    let node = Node::new("sub-dev-bad-state");
    let ctx = &node.ctx;
    std::fs::create_dir_all(&ctx.paths.root).unwrap();
    let state = ctx.paths.state();
    let target = node.dir.join("elsewhere.json");
    std::fs::write(&target, r#"{"values":{}}"#).unwrap();
    let id = "00000000000000aa";
    let lock = node.lock();
    let cases: [(&str, Option<&str>); 5] = [
        ("truncated", Some(r#"{"values":"#)),
        ("not json", Some("garbage")),
        ("unknown object", Some(r#"{"foo":1}"#)),
        ("not an object", Some("[1,2]")),
        ("symlink", None),
    ];
    for (label, content) in cases {
        let _ = std::fs::remove_file(&state);
        match content {
            Some(text) => std::fs::write(&state, text).unwrap(),
            None => std::os::unix::fs::symlink(&target, &state).unwrap(),
        }
        assert!(
            crate::state::StateStore::is_v2_at(&ctx.paths).is_err(),
            "{label}"
        );
        DeviceStore::write(&ctx.paths, &[device(id, "phone", TOKEN)]).unwrap();
        revoke(ctx, &lock, id).unwrap_or_else(|e| panic!("{label}: {e}"));
        assert!(list(&ctx.paths).unwrap().is_empty(), "{label}");
    }
}

#[test]
fn a_foreign_lock_is_refused() {
    let node = Node::new("sub-dev-foreign");
    node.save(&ip(8448));
    let other = node.dir.join("other.lock");
    let lock = FileLock::acquire(&other, "busy").unwrap();
    let err = revoke(&node.ctx, &lock, "00000000000000aa").unwrap_err();
    assert_eq!(err.to_string(), "配置锁不属于当前实例");
}

#[test]
fn first_v3_change_persists_v2_devices() {
    let node = Node::new("sub-dev-migrate");
    let ctx = &node.ctx;
    node.save(&ip(8448));
    write_v2_settings(&node, true, json!([v2_device("00000000000000aa", "手机")]));
    let lock = node.lock();
    let added = add_with(ctx, &lock, &ip(8448), "laptop", &mut SeqRandom(1), 9).unwrap();
    let store = DeviceStore::load(&ctx.paths).unwrap();
    assert_eq!(store.source(), Source::Devices);
    let names: Vec<&str> = store.devices().iter().map(|d| d.name.as_str()).collect();
    assert_eq!(names, ["手机", added.name.as_str()]);
    assert!(
        ctx.paths.subscription_v2_settings().exists(),
        "v2's file is left for v2"
    );
}
