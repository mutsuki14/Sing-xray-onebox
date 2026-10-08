# Allowed differences between v2.0.1 and v3 render output

The golden test (`src/render/golden.rs`) requires every v3 output to equal the
v2 output of the same case. The differences below are deliberate. Each one
is a named transformation in the test (`ALLOWED`), applied to the v2 value
before the comparison; the test fails when a listed difference stops
occurring or occurs in any file not listed here.

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

- Error texts are not compared, only that v2 and v3 both fail. A format
  without supported nodes now names itself and the usable formats (v2 said
  `links` for `base64`, spec C §8.1 #17).
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
