# Allowed differences between v2.0.1 and v3 render output

The golden test (`src/render/golden.rs`) requires every v3 output to equal the
v2 output of the same case, and every v2 refusal (`.err`) to be a v3 refusal
with the same message. The differences below are deliberate. Each one is a
named rule in the test (`ALLOWED`), applied only where it is listed; the test
fails when a listed difference stops occurring or occurs in any file not
listed here.

## Differences exercised by the golden cases

### D1-xray-hy2-obfs-masquerade

An Xray Hysteria2 server with Salamander obfuscation no longer sets
`streamSettings.hysteriaSettings.masquerade`. v2 always added the masquerade
site on Xray, while sing-box uses one or the other (spec C §8.1 #3). An
obfuscated server cannot be probed as a plain QUIC/HTTP3 site, so the
masquerade did nothing except make the two cores behave differently for the
same configuration. Without obfuscation both cores still masquerade as
`https://www.bing.com`.

Files:
- `c06-custom-pinned-ipv6/render-server-xray.json`
- `c06-custom-pinned-ipv6/render-inbound-hysteria2.json`

### D2-no-node-message

A client format without any supported node is refused with
`当前协议组合没有支持 {format} 格式的节点，请改用 {usable formats}` (spec C
§8.1 #17). v2 said `当前协议组合没有 links 支持的节点` for the Base64
subscription (`sub`), `没有可导出到 mihomo 的协议；AnyTLS-REALITY 需要 sing-box
JSON` for mihomo and the provider, and never named a format that works. The
rule applies only to `client-*.err` files whose v2 message is one of those
no-node texts, and requires the v3 message to start with the no-node text
of the same format; every other refusal must keep the v2 text exactly.

Files:
- `c09-anytls-reality-only/client-links.err`
- `c09-anytls-reality-only/client-mihomo.err`
- `c09-anytls-reality-only/client-provider.err`
- `c09-anytls-reality-only/client-sub.err`
- `c09-anytls-reality-only/client-xray.err`
- `c10-xhttp-only/client-singbox-notun.err`
- `c10-xhttp-only/client-singbox.err`

## Refusals: only the error line

A `.err` file is v2's whole stderr. Only its final `[错误] …` line is the
renderer's message. The one other line v2 printed there,
`此格式不包含 AnyTLS-REALITY，请使用 singbox 远程配置或完整 JSON`, came from the
`client` command before rendering and belongs to the CLI; the test accepts
exactly that line and no other.

## Differences handled by comparing structure

### mihomo.yaml and provider.yaml are YAML

v2 wrote both as pretty JSON (valid YAML 1.2 flow style). v3 writes
block-style YAML (`src/render/yaml.rs`). The test compares the document
structure (`mihomo::config` / `mihomo::provider`) with the v2 JSON and also
parses the emitted YAML back with a strict reader and compares again. The
files `client-mihomo.out` and `client-provider.out` are therefore never
compared as text.

## Behavior changes the golden cases do not exercise

These are covered by unit tests in `src/render/` instead; the fixtures avoid
them so the parity comparison stays exact.

- `render inbound|outbound` for a protocol that is not enabled is an error
  (`未启用协议 …`); v2 rendered it with port 443.
- The probe bundle's loopback view (`reality-check` on the server) connects
  to the listen address when it is a specific address (spec C §8.1 #21);
  the golden probe files are the public view.
- Plain VMess-WS sends `NodeConfig::vmess_host` as `Host` (ARCH §10). The v2
  migration fills it from `DOMAIN`, so migrated nodes render exactly as v2.
- A dormant website (`REALITY_SITE_ENABLED=0`) no longer contributes its
  domain to the client direct-routing rules: v2 read `REALITY_SITE_DOMAIN`
  even while the site was off, v3 drops dormant site settings on migration.
- The REALITY site port has one source (the internal port). v2 rendered the
  guard target from `REALITY_DEST` and the Xray redirect from
  `REALITY_SITE_PORT`; the cases keep both equal.
- Migration normalizes inconsistent address families (a `SERVER_IPV4` that
  differs from an IPv4 `SERVER_ADDR` is replaced by it); the cases are
  consistent.
