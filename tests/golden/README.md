# Render golden files

Reference outputs of Onebox v2.0.1 for fixed node states. The unit test
`render::golden` (in `src/render/golden.rs`) migrates every case with the
real v2 migration (`state::v2::migrate`), renders it with v3 and requires
the same output, apart from the differences listed in `ALLOWED_DIFFS.md`.
`render::realcore` (ignored by default) feeds every document to the real
cores.

## Layout

```
certs/<pair>/{cert,key}.pem    fixed test-only certificates (never secret)
  selfsigned/                  EC P-256, CN www.bing.com (self-signed mode)
  chain/                       leaf proxy.example.com + test CA (chain, pinned custom mode)
cases/<name>/
  state.json                   v2 state ({"values":{…}})
  settings.json                v2 subscription/settings.json (optional)
  cert                         name of the certificate pair to deploy (optional)
  expected/                    v2 outputs, written by generate.sh
generate.sh                    regenerates expected/ with a v2 binary
ALLOWED_DIFFS.md               accepted v2 → v3 differences
```

`expected/` holds the exact stdout of the v2 commands (`println!` adds one
newline after the rendered text): `render-server-<core>.json`,
`render-inbound-<protocol>.json`, `render-outbound-<protocol>-<core>.json`,
`render-probe.json` and `client-<format>.out`. A command v2 refused leaves a
`.err` file with its stderr instead; v3 must refuse it with the message of
its final `[错误]` line (see `ALLOWED_DIFFS.md` for the exceptions).

## Cases

| case | covers |
|---|---|
| c01-singbox-full | every sing-box protocol, self-signed pinned TLS, VMess TLS, Hy2 obfs + hop + conservative + throughput, own CIDRs, CJK node name, reserved characters in the password |
| c02-xray-full-acme | every Xray protocol, ACME (not pinned), domain server address, dual stack, AES-256 SS, separate XHTTP port, Xray Hy2 hop, standalone subscription |
| c03-dual-shared443-ipv6 | Xray Vision + XHTTP sharing TCP 443, sing-box Hy2 measured + low-memory on UDP 443, IPv6-only server, `BLOCK_PRIVATE=0` `BLOCK_BT=0`, IPv6 IP subscription |
| c04-site-https | own-domain site with HTTPS entry (dest `127.0.0.1:10443`), Xray guard to the site, site subscription |
| c05-site-nohttps | own-domain site without HTTPS entry (dest `127.0.0.1:10444`), plain VMess with CDN `Host`, `BLOCK_BT=0` |
| c06-custom-pinned-ipv6 | custom certificate chain (pinned), Xray WS / Trojan / Hy2 obfs / plain VMess, IPv6 address, IPv4 WARP flag |
| c07-vmess-plain | no TLS at all, IPv6 WARP flag, IPv4 wildcard listen |
| c08-shadowtls-anytls-reality | ShadowTLS with a custom handshake target, AnyTLS-REALITY with an IPv6 target, Hy2 masquerade + hop + auto + low-memory |
| c09-anytls-reality-only | only the sing-box JSON formats support it; specific listen address |
| c10-xhttp-only | no sing-box client support, `BLOCK_PRIVATE=0` alone |

## Regenerating

```sh
tests/golden/generate.sh /path/to/onebox-v2          # every case
tests/golden/generate.sh /path/to/onebox-v2 c04-site-https
```

The script needs `jq` and a v2.0.1 `onebox` binary. Each case is deployed to
`/tmp/onebox-golden/<name>` (so certificate paths in server configs are the
same on every machine) and rendered with `ONEBOX_DIR` pointing there; the
deployment is removed afterwards. Review the diff of `expected/` before
committing: these files are the parity contract.

## Real-core checks

```sh
ONEBOX_TEST_SINGBOX=/path/sing-box ONEBOX_TEST_XRAY=/path/xray \
ONEBOX_TEST_MIHOMO=/path/mihomo cargo test -- --ignored realcore
```

Xray client documents need `geosite.dat` / `geoip.dat` in
`ONEBOX_TEST_XRAY_ASSETS` (default: the xray binary's directory). mihomo
downloads its geodata once into a cache under the system temp directory.
