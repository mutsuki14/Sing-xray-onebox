use super::*;
use crate::domain::fixtures::{self, config, with_site};
use std::net::Ipv6Addr;
use std::path::PathBuf;
use Core::{Singbox as SB, Xray as XR};
use Protocol::*;

fn base() -> NodeConfig {
    config(&[
        (VlessReality, 443, SB),
        (Hysteria2, 443, SB),
        (Tuic, 8443, SB),
    ])
}

fn err(cfg: &NodeConfig) -> String {
    cfg.validate().unwrap_err().to_string()
}

#[test]
fn fixtures_are_valid() {
    base().validate().unwrap();
    config(&[
        (VlessReality, 443, XR),
        (VlessXhttp, 443, XR),
        (Shadowsocks, 8388, XR),
    ])
    .validate()
    .unwrap();
    with_site(base(), "www.example.com", true)
        .validate()
        .unwrap();
}

#[test]
fn negative_table() {
    type Mutation = fn(&mut NodeConfig);
    let cases: Vec<(&str, Mutation)> = vec![
        ("配置 schema 无效: 2", |c| c.schema = 2),
        (
            "配置由更新版本的 Onebox 写入（schema 4），请先更新程序",
            |c| c.schema = 4,
        ),
        ("配置缺少协议列表", |c| c.inbounds.clear()),
        ("协议重复", |c| {
            let first = c.inbounds[0];
            c.inbounds.push(first)
        }),
        ("tuic 端口无效", |c| c.inbounds[2].port = 0),
        ("tuic 不支持 xray", |c| c.inbounds[2].core = Core::Xray),
        (
            "节点名称不能为空或超过 128 个字符，且不能包含控制字符",
            |c| c.node_name = "a\u{1b}[31m".into(),
        ),
        (
            "节点名称不能为空或超过 128 个字符，且不能包含控制字符",
            |c| c.node_name = " ".into(),
        ),
        (
            "节点名称不能为空或超过 128 个字符，且不能包含控制字符",
            |c| c.node_name = "节".repeat(129),
        ),
        ("连接地址与记录的 IPv4 不一致", |c| {
            c.server.ipv4 = None
        }),
        ("连接地址与记录的 IPv6 不一致", |c| {
            c.server.addr = Host::Ip(IpAddr::V6(Ipv6Addr::LOCALHOST))
        }),
        ("UUID 格式无效", |c| c.creds.uuid = "not-a-uuid".into()),
        ("节点密码无效", |c| c.creds.password.clear()),
        ("Shadowsocks 加密方式无效: aes-128-gcm", |c| {
            c.creds.ss_method = "aes-128-gcm".into()
        }),
        ("Shadowsocks 密钥与加密方式不匹配", |c| {
            c.creds.ss_method = "2022-blake3-aes-256-gcm".into()
        }),
        ("Hysteria2 混淆密码无效", |c| {
            c.creds.hy2_obfs_password = "a\nb".into()
        }),
        ("ShadowTLS 密码无效", |c| {
            c.creds.shadowtls_password.clear()
        }),
        ("ShadowTLS 的 Shadowsocks 密钥无效", |c| {
            c.creds.shadowtls_ss_password = "abc".into()
        }),
        ("Clash API 密钥无效", |c| c.creds.clash_secret.clear()),
        ("WS 路径无效: ws", |c| c.creds.ws_path = "ws".into()),
        ("XHTTP 路径无效: /a b", |c| {
            c.creds.xhttp_path = "/a b".into()
        }),
        ("gRPC 服务名无效", |c| {
            c.creds.grpc_service = "/svc".into()
        }),
        ("缺少 REALITY 密钥", |c| c.creds.reality = None),
        (
            "未启用 REALITY 协议时不应保留 REALITY 密钥",
            |c| {
                c.inbounds.remove(0);
            },
        ),
        ("REALITY 公钥与私钥不匹配", |c| {
            if let Some(k) = c.creds.reality.as_mut() {
                std::mem::swap(&mut k.private_key, &mut k.public_key);
            }
        }),
        ("REALITY ShortID 无效", |c| {
            if let Some(k) = c.creds.reality.as_mut() {
                k.short_id = "xyz".into();
            }
        }),
        ("REALITY SNI 域名无效", |c| {
            c.reality.sni = "1.2.3.4".into()
        }),
        ("REALITY guard 端口缺失或与代理冲突", |c| {
            c.inbounds[0].core = Core::Xray;
            c.reality.guard_port = 0;
        }),
        ("ShadowTLS SNI 域名无效", |c| {
            c.shadowtls.sni = "bad domain".into()
        }),
        ("当前协议需要代理 TLS 证书", |c| c.tls = None),
        ("当前协议无需代理 TLS 证书", |c| {
            c.inbounds.truncate(1)
        }),
        ("自签证书域名无效", |c| {
            c.tls = Some(ProxyTls {
                mode: ProxyCertMode::SelfSigned { sni: "x".into() },
                pinned: true,
            })
        }),
        ("自签证书必须由客户端固定指纹", |c| {
            if let Some(t) = c.tls.as_mut() {
                t.pinned = false;
            }
        }),
        ("证书域名无效", |c| {
            c.tls = Some(ProxyTls {
                mode: ProxyCertMode::Acme {
                    domain: "*.example.com".into(),
                    method: AcmeMethod::Cloudflare,
                },
                pinned: false,
            })
        }),
        ("证书路径必须为绝对路径", |c| {
            c.tls = Some(ProxyTls {
                mode: ProxyCertMode::Custom {
                    domain: "proxy.example.com".into(),
                    cert: PathBuf::from("cert.pem"),
                    key: PathBuf::from("/k.pem"),
                },
                pinned: false,
            })
        }),
        ("VMess TLS 仅适用于 VMess-WS", |c| c.vmess_tls = true),
        ("跳跃端口范围无效", |c| {
            c.hy2.hop = Some(PortRange { start: 80, end: 90 })
        }),
        ("Hysteria2 带宽必须为 1–10000 的整数 Mbps", |c| {
            c.hy2.profile = Some(Hy2Profile::Measured);
            c.hy2.up_mbps = Some(20_000);
            c.hy2.down_mbps = Some(100);
        }),
        ("measured 需要 --up 和 --down", |c| {
            c.hy2.profile = Some(Hy2Profile::Measured);
            c.hy2.up_mbps = Some(100);
        }),
        ("仅 measured 档位可设置带宽", |c| {
            c.hy2.profile = Some(Hy2Profile::Auto);
            c.hy2.up_mbps = Some(100);
        }),
        (
            "Xray 承载的 Hysteria2 不支持带宽调优，请改用 sing-box 承载",
            |c| {
                c.inbounds[1].core = Core::Xray;
                c.hy2.profile = Some(Hy2Profile::Conservative);
            },
        ),
        (
            "Xray 承载的 Hysteria2 不支持资源调优，请改用 sing-box 承载",
            |c| {
                c.inbounds[1].core = Core::Xray;
                c.resource_profile = ResourceProfile::LowMemory;
            },
        ),
        ("本机地址列表格式无效: 10.0.0.1/33", |c| {
            c.routing.own_cidrs = vec!["203.0.113.10/32".into(), "10.0.0.1/33".into()]
        }),
        ("内核版本无效: 1.0 beta", |c| {
            c.versions.xray_pin = Some("1.0 beta".into())
        }),
    ];
    for (want, mutate) in cases {
        let mut cfg = base();
        mutate(&mut cfg);
        assert_eq!(err(&cfg), want);
    }
}

#[test]
fn site_rules() {
    let site = with_site(base(), "www.example.com", true);
    type Mutation = fn(&mut NodeConfig);
    let cases: Vec<(&str, Mutation)> = vec![
        ("自建站需要 REALITY 协议及有效域名", |c| {
            c.inbounds.remove(0);
            c.creds.reality = None;
        }),
        ("自建站需要 REALITY 协议及有效域名", |c| {
            if let Some(s) = c.site.as_mut() {
                s.domain = "bad".into();
            }
        }),
        ("网站内部 TLS 端口必须大于等于 1024", |c| {
            if let Some(s) = c.site.as_mut() {
                s.internal_port = 443;
            }
        }),
        (
            "网站标题不能为空或超过 128 个字符，且不能包含控制字符",
            |c| {
                if let Some(s) = c.site.as_mut() {
                    s.title = "\t".into();
                }
            },
        ),
        ("网站描述不能包含控制字符", |c| {
            if let Some(s) = c.site.as_mut() {
                s.description = "a\rb".into();
            }
        }),
        ("证书路径必须为绝对路径", |c| {
            if let Some(s) = c.site.as_mut() {
                s.cert = WebCert::Custom {
                    cert: "/c.pem".into(),
                    key: "k.pem".into(),
                };
            }
        }),
        ("网站备份 ID 无效", |c| {
            if let Some(s) = c.site.as_mut() {
                s.last_content_backup = Some("../x".into());
            }
        }),
        (
            "自建站启用时 REALITY 目标必须为 127.0.0.1:10443，SNI 必须为网站域名",
            |c| c.reality.dest = crate::domain::defaults::handshake_dest("www.example.com"),
        ),
        (
            "自建站启用时 REALITY 目标必须为 127.0.0.1:10443，SNI 必须为网站域名",
            |c| c.reality.sni = "www.microsoft.com".into(),
        ),
    ];
    for (want, mutate) in cases {
        let mut cfg = site.clone();
        mutate(&mut cfg);
        assert_eq!(err(&cfg), want);
    }
}

#[test]
fn subscription_rules() {
    let mut ok = base();
    ok.subscription = Some(fixtures::ip_subscription(8448));
    ok.validate().unwrap();
    ok.subscription = Some(fixtures::standalone_subscription(
        "sub.example.com",
        8448,
        WebCert::Http01,
    ));
    ok.validate().unwrap();
    let mut site = with_site(base(), "www.example.com", true);
    site.subscription = Some(SubscriptionConfig {
        mode: SubscriptionMode::Site,
        port: 443,
    });
    site.validate().unwrap();

    type Mutation = fn(&mut NodeConfig);
    let cases: Vec<(&str, Mutation)> = vec![
        ("订阅端口无效", |c| {
            c.subscription = Some(fixtures::ip_subscription(0))
        }),
        ("订阅地址不能是未指定地址或组播地址", |c| {
            c.subscription = Some(SubscriptionConfig {
                mode: SubscriptionMode::Ip {
                    address: "::".parse().unwrap(),
                },
                port: 8448,
            })
        }),
        ("订阅地址应使用 IPv4 形式，不能是 IPv4 映射的 IPv6 地址", |c| {
            c.subscription = Some(SubscriptionConfig {
                mode: SubscriptionMode::Ip {
                    address: "::ffff:192.0.2.5".parse().unwrap(),
                },
                port: 8448,
            })
        }),
        ("订阅域名无效", |c| {
            c.subscription = Some(fixtures::standalone_subscription(
                "1.2.3.4",
                8448,
                WebCert::Cloudflare,
            ))
        }),
        ("订阅证书方式无效", |c| {
            c.subscription = Some(SubscriptionConfig {
                mode: SubscriptionMode::Standalone {
                    domain: "sub.example.com".into(),
                    cert: WebCert::Cloudflare,
                    http01_port80: true,
                },
                port: 8448,
            })
        }),
        (
            "没有可复用的自建站，请使用 --mode ip --address IP，或 --mode standalone --domain 域名 --tls cf|http|custom",
            |c| {
                c.subscription = Some(SubscriptionConfig {
                    mode: SubscriptionMode::Site,
                    port: 443,
                })
            },
        ),
    ];
    for (want, mutate) in cases {
        let mut cfg = base();
        mutate(&mut cfg);
        assert_eq!(err(&cfg), want);
    }

    if let Some(s) = site.site.as_mut() {
        s.https_entry = false;
    }
    site.inbounds[0].port = 8443;
    site.inbounds[2].port = 9443;
    assert_eq!(
        err(&site),
        "当前变更会改变订阅 URL 端口；请先关闭订阅，完成端口调整后重新启用并更新客户端 URL"
    );
}

#[test]
fn helpers() {
    assert!(valid_cidr("203.0.113.10/32"));
    assert!(valid_cidr("2001:db8::1/128"));
    assert!(!valid_cidr("2001:db8::1/129"));
    assert!(!valid_cidr("203.0.113.10"));
    assert!(!valid_cidr("host/24"));
    assert!(valid_version("v26.3.27"));
    assert!(valid_version("1.13.0-beta.1"));
    assert!(!valid_version(""));
    assert!(!valid_version("1;rm"));
    assert!(valid_label("山间手记"));
    assert!(!valid_label(""));
    assert_eq!(check_schema(3).map_err(|e| e.to_string()), Ok(()));
}
