use super::*;

#[test]
fn host_parsing() {
    assert_eq!(
        "203.0.113.5".parse::<Host>().unwrap().url_host(),
        "203.0.113.5"
    );
    assert_eq!(
        "[2001:db8::1]".parse::<Host>().unwrap().url_host(),
        "[2001:db8::1]"
    );
    assert_eq!(
        "WWW.Example.COM".parse::<Host>().unwrap().to_string(),
        "www.example.com"
    );
    assert!("bad host".parse::<Host>().is_err());
}

#[test]
fn host_port_parsing() {
    let hp: HostPort = "www.microsoft.com:443".parse().unwrap();
    assert_eq!(hp.to_string(), "www.microsoft.com:443");
    let v6: HostPort = "[2001:db8::1]:8443".parse().unwrap();
    assert_eq!(v6.to_string(), "[2001:db8::1]:8443");
    assert!("2001:db8::1:443".parse::<HostPort>().is_err());
    assert!("example.com:0".parse::<HostPort>().is_err());
    assert!("example.com".parse::<HostPort>().is_err());
    assert!("[example.com]:443".parse::<HostPort>().is_err());
    assert!(":443".parse::<HostPort>().is_err());
    // Handshake targets accept resolver host names (v2 parity).
    for (raw, shown) in [
        ("localhost:8443", "localhost:8443"),
        ("Reality_Test.lan:443", "reality_test.lan:443"),
        ("127.0.0.1:24443", "127.0.0.1:24443"),
    ] {
        let hp: HostPort = raw.parse().unwrap();
        assert_eq!(hp.to_string(), shown);
        let json = serde_json::to_value(&hp).unwrap();
        assert_eq!(serde_json::from_value::<HostPort>(json).unwrap(), hp);
    }
    for bad in [
        "a b:443",
        "-x.example:443",
        "1.2.3:443",
        "x..y:443",
        "é.example:443",
    ] {
        assert!(bad.parse::<HostPort>().is_err(), "{bad}");
    }
    // Public addresses stay strict.
    assert!("localhost".parse::<Host>().is_err());
}

#[test]
fn port_range_parsing() {
    let r: PortRange = "20000-30000".parse().unwrap();
    assert!(r.contains(25000) && !r.contains(19999));
    assert!("3000-2000".parse::<PortRange>().is_err());
    assert_eq!(
        serde_json::to_value(r).unwrap(),
        serde_json::json!("20000-30000")
    );
}

#[test]
fn tagged_enums_serialize_readably() {
    let mode = ProxyCertMode::Acme {
        domain: "a.example.com".into(),
        method: AcmeMethod::Cloudflare,
    };
    assert_eq!(
        serde_json::to_value(&mode).unwrap(),
        serde_json::json!({"type": "acme", "domain": "a.example.com", "method": "cloudflare"})
    );
    let sub = SubscriptionMode::Ip {
        address: "203.0.113.5".parse().unwrap(),
    };
    assert_eq!(
        serde_json::to_value(&sub).unwrap(),
        serde_json::json!({"type": "ip", "address": "203.0.113.5"})
    );
}
