#!/usr/bin/env bash
# FRP regression tests: temporary files / mocked downloads only, no host changes.
# shellcheck disable=SC2034
set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd)
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
export ONEBOX_SOURCE_ONLY=1 NO_COLOR=1
export ONEBOX_DIR="$WORK/proxy" ONEBOX_BIN_DIR="$WORK/proxy-bin" ONEBOX_LOG_DIR="$WORK/proxy-log" ONEBOX_RUN_DIR="$WORK/proxy-run"
export ONEBOX_FRPS_DIR="$WORK/frp" ONEBOX_FRPS_BIN_DIR="$WORK/frp-bin" ONEBOX_FRPS_WEB_VAR="$WORK/public" ONEBOX_FRPS_LOG_DIR="$WORK/frp-log" ONEBOX_FRPS_RUN_DIR="$WORK/frp-run"
export ONEBOX_FRPS_LOCK="$WORK/frp.lock" ONEBOX_FRPS_SYSTEMD_DIR="$WORK/systemd"
# shellcheck source=../onebox.sh
. "$ROOT/onebox.sh"
# Development fallback; distributions use the same functions inlined in onebox.sh.
if ! declare -F _frps_defaults >/dev/null; then
	# shellcheck source=../lib/frps.sh
	. "$ROOT/lib/frps.sh"
	# shellcheck source=../lib/frps-domain.sh
	. "$ROOT/lib/frps-domain.sh"
fi
# DNS tests must never fall through to public IP discovery over the network.
detect_public_ip() { return 0; }
PASS=0 FAIL=0
check() {
	local label=$1
	shift
	if ("$@") >"$WORK/result" 2>&1; then PASS=$((PASS + 1));
	else FAIL=$((FAIL + 1)); printf '[失败] %s\n' "$label"; cat "$WORK/result"; fi
}
reject() { ! "$@"; }
contains() { grep -qF -- "$2" "$1"; }
absent() { ! grep -qF -- "$2" "$1"; }
set_valid() {
	_frps_defaults
	FRPS_MODE=web FRPS_DOMAIN=control.example.com FRPS_WEB_DOMAIN=app.example.com
	FRPS_TOKEN=$(printf '%064d' 1)
	FRPS_TLS_METHOD=custom FRPS_CERT_INPUT="$WORK/app.pem" FRPS_KEY_INPUT="$WORK/app.key"
}
validate_value() { set_valid; printf -v "$1" '%s' "$2"; _frps_validate; }
mkdir -p "$FRPS_DIR" "$FRPS_BIN_DIR" "$FRPS_WEB_VAR" "$FRPS_LOG_DIR" "$FRPS_RUN_DIR" "$FRPS_SYSTEMD_DIR"
chmod 700 "$FRPS_DIR"
_frps_defaults
check 'default mode is web' test "$FRPS_MODE" = web
check 'default range starts at 20000' test "$FRPS_RANGE_START" = 20000
check 'default range ends at 20100' test "$FRPS_RANGE_END" = 20100
set_valid
check 'valid web settings' _frps_validate
check 'invalid mode' reject validate_value FRPS_MODE invalid
check 'invalid control domain' reject validate_value FRPS_DOMAIN 'example.com;id'
check 'invalid bind address' reject validate_value FRPS_BIND_ADDR '0.0.0.0"'
check 'zero bind port' reject validate_value FRPS_BIND_PORT 0
check 'leading-zero port' reject validate_value FRPS_BIND_PORT 07000
check 'out-of-range port' reject validate_value FRPS_BIND_PORT 65536
check 'invalid token' reject validate_value FRPS_TOKEN 'secret"
bad'
check 'unsupported old version' reject validate_value FRPS_VERSION 0.1.0
check 'version command injection' reject validate_value FRPS_VERSION '$(id)'
check 'range reversed' reject validate_value FRPS_RANGE_START 20101
check 'range larger than 1000 ports' reject validate_value FRPS_RANGE_END 21000
check '1000 port range accepted' validate_value FRPS_RANGE_END 20999
check 'overlap control and internal HTTP' reject validate_value FRPS_HTTP_PORT 7000
check 'overlap control and allowed range' reject validate_value FRPS_BIND_PORT 20000
check 'zero HTTP redirect allowed with custom certificate' validate_value FRPS_REDIRECT_PORT 0
check 'control character in custom path rejected' reject validate_value FRPS_CERT_INPUT $'/tmp/cert\nFRPS_TOKEN=bad'
check 'FRP paths separate from proxy directories' _frps_paths_safe
nested_path() { FRPS_DIR="$ONEBOX_DIR/frp"; _frps_paths_safe; }
check 'FRP path under proxy cannot be removed accidentally' reject nested_path
same_root_path() { FRPS_WEB_VAR=$FRPS_DIR; _frps_paths_safe; }
check 'public and private FRP roots cannot be identical' reject same_root_path
public_under_private() { FRPS_WEB_VAR="$FRPS_DIR/public"; _frps_paths_safe; }
check 'public FRP content cannot be nested under private configuration' reject public_under_private
service_data_path() { FRPS_DIR=$FRPS_SYSTEMD_DIR; _frps_paths_safe; }
check 'FRP data root cannot replace service directory' reject service_data_path

state_roundtrip() {
	set_valid
	: >"$FRPS_DIR/.managed"
	_frps_save || return 1
	local saved=$FRPS_TOKEN
	FRPS_DOMAIN=discard.example.com FRPS_TOKEN=''
	_frps_load && [ "$FRPS_DOMAIN" = control.example.com ] && [ "$FRPS_TOKEN" = "$saved" ] && [ "$(stat -c %a "$FRPS_STATE")" = 600 ]
}
check 'plain state round-trip and private permissions' state_roundtrip
state_injection() {
	set_valid; _frps_save || return 1; : >"$FRPS_DIR/.managed"
	printf 'FRPS_DOMAIN=$(touch %s)\n' "$WORK/executed" >>"$FRPS_STATE"
	if _frps_load; then return 1; fi
	[ ! -e "$WORK/executed" ]
}
check 'state content is never eval or sourced' state_injection
state_unknown() { set_valid; _frps_save; : >"$FRPS_DIR/.managed"; printf 'PATH=/tmp\n' >>"$FRPS_STATE"; _frps_load; }
check 'unknown state key rejected' reject state_unknown
state_duplicate() { set_valid; _frps_save; : >"$FRPS_DIR/.managed"; printf 'FRPS_MODE=tcp\n' >>"$FRPS_STATE"; _frps_load; }
check 'duplicate state key rejected' reject state_duplicate
state_missing() { set_valid; _frps_save; : >"$FRPS_DIR/.managed"; sed -i '/^FRPS_DOMAIN=/d' "$FRPS_STATE"; _frps_load; }
check 'missing state key rejected' reject state_missing
state_empty_token() { set_valid; FRPS_TOKEN=''; _frps_save; : >"$FRPS_DIR/.managed"; _frps_load; }
check 'installed state cannot contain empty token' reject state_empty_token

control_certificates() {
	set_valid
	_frps_control_certificate || return 1
	local ca server
	ca=$(sha256sum "$FRPS_DIR/ca.pem") server=$(sha256sum "$FRPS_DIR/server-cert.pem")
	openssl verify -CAfile "$FRPS_DIR/ca.pem" -verify_hostname "$FRPS_DOMAIN" "$FRPS_DIR/server-cert.pem" >/dev/null || return 1
	[ "$(stat -c %a "$FRPS_DIR/ca-key.pem")" = 600 ] && [ "$(stat -c %a "$FRPS_DIR/server-key.pem")" = 600 ] || return 1
	_frps_control_certificate && [ "$ca" = "$(sha256sum "$FRPS_DIR/ca.pem")" ] && [ "$server" = "$(sha256sum "$FRPS_DIR/server-cert.pem")" ] || return 1
	FRPS_DOMAIN=changed.example.com
	_frps_control_certificate && [ "$ca" = "$(sha256sum "$FRPS_DIR/ca.pem")" ] && [ "$server" != "$(sha256sum "$FRPS_DIR/server-cert.pem")" ] &&
		openssl verify -CAfile "$FRPS_DIR/ca.pem" -verify_hostname "$FRPS_DOMAIN" "$FRPS_DIR/server-cert.pem" >/dev/null
}
check 'private CA, matching leaf, unchanged reuse and domain rotation' control_certificates
render_web() {
	set_valid; _frps_render || return 1
	contains "$FRPS_CONF" 'proxyBindAddr = "127.0.0.1"' && contains "$FRPS_CONF" 'transport.tls.force = true' &&
		contains "$FRPS_CONF" 'auth.additionalScopes = ["HeartBeats", "NewWorkConns"]' &&
		contains "$FRPS_CONF" "auth.token = \"$FRPS_TOKEN\"" && [ "$(stat -c %a "$FRPS_CONF")" = 600 ] && absent "$FRPS_CONF" 'webServer'
}
check 'web render is loopback-only, TLS required, no dashboard, private token' render_web
render_tcp() { set_valid; FRPS_MODE=tcp; _frps_render && contains "$FRPS_CONF" "proxyBindAddr = \"$FRPS_BIND_ADDR\"" && absent "$FRPS_CONF" vhostHTTPPort; }
check 'TCP render excludes HTTP virtual host' render_tcp
render_no_token() { set_valid; FRPS_TOKEN=''; _frps_render; }
check 'render rejects absent token' reject render_no_token

make_certificate() {
	local name=$1 sans=$2
	openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 2 -subj /CN=app.example.com \
		-addext "subjectAltName=$sans" -keyout "$WORK/$name.key" -out "$WORK/$name.pem" >/dev/null 2>&1
}
make_certificate app DNS:app.example.com
make_certificate wildcard 'DNS:apps.example.com,DNS:*.apps.example.com'
make_certificate fakewild 'DNS:apps.example.com,DNS:onebox-cert-check.apps.example.com'
web_certificate() { set_valid; _frps_web_certificate && _frps_web_cert_validate && [ "$(stat -c %a "$FRPS_DIR/web-key.pem")" = 600 ]; }
check 'custom website certificate copied and validated' web_certificate
bad_web_domain() { set_valid; FRPS_WEB_DOMAIN=wrong.example.com; _frps_web_cert_validate "$WORK/app.pem" "$WORK/app.key"; }
check 'wrong certificate hostname rejected despite openssl x509 exit zero' reject bad_web_domain
bad_web_key() { set_valid; _frps_web_cert_validate "$WORK/app.pem" "$WORK/wildcard.key"; }
check 'wrong certificate private key rejected' reject bad_web_key
wildcard_certificate() { set_valid; FRPS_SUBDOMAIN_HOST=apps.example.com; _frps_web_cert_validate "$WORK/$1.pem" "$WORK/$1.key"; }
check 'wildcard certificate covers root and arbitrary subdomain' wildcard_certificate wildcard
check 'one probe hostname cannot imitate wildcard certificate' reject wildcard_certificate fakewild
wildcard_http() { set_valid; FRPS_TLS_METHOD=http FRPS_SUBDOMAIN_HOST=apps.example.com; _frps_domain_validate; }
check 'wildcard certificate forbids HTTP-01' reject wildcard_http
http_wrong_port() { set_valid; FRPS_TLS_METHOD=http FRPS_REDIRECT_PORT=8080; _frps_domain_validate; }
check 'HTTP-01 requires standard port 80' reject http_wrong_port
tcp_ignores_web() { set_valid; FRPS_MODE=tcp FRPS_TLS_METHOD='' FRPS_WEB_DOMAIN='' FRPS_SUBDOMAIN_HOST=''; _frps_domain_validate && _frps_web_certificate; }
check 'TCP mode does not require nginx or web certificates' tcp_ignores_web
dns_mixed_addresses() {
	set_valid
	own_ip_list() { printf '203.0.113.1\n'; }
	resolve_domain() { printf '203.0.113.1\n203.0.113.2\n'; }
	_frps_check_dns
}
check 'DNS rejects even one foreign A/AAAA address' reject dns_mixed_addresses
dns_wildcard() {
	set_valid; FRPS_SUBDOMAIN_HOST=apps.example.com
	own_ip_list() { printf '203.0.113.1\n'; }
	resolve_domain() { printf '%s\n' "$1" >>"$WORK/dns-probes"; printf '203.0.113.1\n'; }
	_frps_check_dns && grep -q '^onebox-.*\.apps.example.com$' "$WORK/dns-probes"
}
check 'wildcard DNS tested with random subdomain' dns_wildcard
dns_nat() {
	set_valid
	local nat_found=0 calls=0 start=${1:-empty}
	own_ip_list() {
		if [ "$nat_found" = 1 ]; then printf '203.0.113.9\n2001:db8::1\n';
		elif [ "$start" = ipv6 ]; then printf '2001:db8::1\n'; fi
	}
	detect_public_ip() { nat_found=1; calls=$((calls + 1)); }
	resolve_domain() { printf '203.0.113.9\n2001:db8::1\n'; }
	_frps_check_dns && [ "$calls" = 1 ]
}
check 'NAT DNS discovers public address once when interface list is empty' dns_nat empty
check 'NAT DNS discovers IPv4 alongside an existing native IPv6 address' dns_nat ipv6
cron_isolation() {
	cat >"$WORK/cron" <<EOF
0 1 * * * "$FRPS_DIR/acme/acme.sh" --cron --home "$FRPS_DIR/acme"
1 2 * * * cp "$FRPS_DIR/acme/acme.sh" --cron /backup
2 3 * * * "/etc/onebox/site/acme/acme.sh" --cron --home "/etc/onebox/site/acme"
3 4 * * * /usr/local/bin/onebox frps renew --cron
EOF
	crontab() { if [ "$1" = -l ]; then cat "$WORK/cron"; else cat >"$WORK/cron"; fi; }
	_frps_acme_cron_remove && [ "$(wc -l <"$WORK/cron")" = 3 ] && contains "$WORK/cron" 'cp ' && contains "$WORK/cron" 'site/acme/acme.sh' && contains "$WORK/cron" 'frps renew --cron'
}
check 'ACME cron removal preserves unrelated jobs and managed FRP renewal' cron_isolation

export_web() {
	set_valid
	_frps_export "$WORK/export-web" http 8080 '' >"$WORK/export-output" || return 1
	contains "$WORK/export-web/frpc.toml" 'transport.tls.trustedCaFile = "./ca.pem"' &&
		contains "$WORK/export-web/frpc.toml" 'customDomains = ["app.example.com"]' &&
		contains "$WORK/export-web/frpc.toml" 'requestHeaders.set."X-Forwarded-Proto" = "https"' &&
		[ "$(stat -c %a "$WORK/export-web")" = 700 ] && [ "$(stat -c %a "$WORK/export-web/frpc.toml")" = 600 ] &&
		[ "$(find "$WORK/export-web" -type f | wc -l)" = 3 ] && absent "$WORK/export-output" "$FRPS_TOKEN"
}
check 'client export contains CA + private token but no private keys/logged token' export_web
export_existing() { set_valid; _frps_export "$WORK/export-web" http 8080 ''; }
check 'export refuses to overwrite existing directory' reject export_existing
export_wildcard() { set_valid; FRPS_SUBDOMAIN_HOST=apps.example.com; _frps_export "$WORK/export-wildcard" http 8080 '' demo && contains "$WORK/export-wildcard/frpc.toml" 'subdomain = "demo"'; }
check 'wildcard export uses subdomain' export_wildcard
export_bad_subdomain() { set_valid; FRPS_SUBDOMAIN_HOST=apps.example.com; _frps_export "$WORK/export-bad" http 8080 '' '-bad'; }
check 'malformed subdomain rejected' reject export_bad_subdomain
export_bad_remote() { set_valid; FRPS_MODE=tcp; _frps_export "$WORK/export-bad-range" tcp 22 1; }
check 'TCP export enforces allowPorts range' reject export_bad_remote
export_tcp() { set_valid; FRPS_MODE=tcp; _frps_export "$WORK/export-tcp" tcp 22 20022 && contains "$WORK/export-tcp/frpc.toml" 'remotePort = 20022'; }
check 'TCP client configuration export' export_tcp
export_empty_token() { set_valid; FRPS_TOKEN=''; _frps_export "$WORK/export-empty-token" http 8080 ''; }
check 'client export rejects empty token' reject export_empty_token

# Use the actual proxy/site/hopping guards and saved FRP state. Only socket
# observation is mocked: a stopped service must still reserve future listeners.
reservation_fixture() {
	set_valid
	FRPS_MODE=${1:-tcp}
	_frps_save || return 1
	: >"$FRPS_DIR/.managed"
	reset_state
	_frps_service_active() { return 1; }
	port_in_use() { return 1; }
}
reservation_range() { reservation_fixture && _frps_reserved "$1" "$2"; }
check 'stopped FRP reserves an unopened TCP remote port' reservation_range 20050 tcp
check 'stopped FRP reserves an unopened UDP remote port' reservation_range 20050 udp
check 'stopped FRP allows UDP reuse of its TCP control port' reject reservation_range 7000 udp
check 'remote port outside saved range remains available' reject reservation_range 20101 tcp
future_proxy_port() { reservation_fixture; port_ok "$1" "$2"; }
check 'new TCP proxy cannot claim stopped FRP remote port' reject future_proxy_port 20050 vless-reality
check 'new UDP proxy cannot claim stopped FRP remote port' reject future_proxy_port 20050 hysteria2
check 'new mixed TCP/UDP proxy cannot claim stopped FRP remote port' reject future_proxy_port 20050 shadowsocks
check 'new proxy may use port outside FRP reservation' future_proxy_port 20101 vless-reality
future_web_proxy() { reservation_fixture web; port_ok 443 vless-reality; }
check 'new REALITY 443 cannot take over stopped FRP HTTPS entrance' reject future_web_proxy
future_hop() { reservation_fixture; hop_range_conflicts "$1"; }
check 'future Hysteria2 hop range reports overlap with stopped FRP' future_hop 19990-20001
check 'non-overlapping Hysteria2 hop range is accepted' reject future_hop 20101-20200
future_hop_web() { reservation_fixture web; hop_range_conflicts 440-445; }
check 'UDP hopping may overlap a web-only TCP listener' reject future_hop_web
site_reservation() {
	reservation_fixture "${1:-tcp}"
	case "${2:-}" in
	http) FRPS_BIND_PORT=80 ;;
	internal) FRPS_BIND_PORT=9443 ;;
	esac
	_frps_save || return 1
	PROTOCOLS=vless-reality
	pset CORE vless-reality xray; pset PORT vless-reality 8443
	REALITY_SITE_ENABLED=1 REALITY_SITE_DOMAIN=site.example.com REALITY_SITE_PORT=9443 REALITY_SITE_HTTPS=1
	site_validate_ports
}
check 'website may coexist with unrelated stopped FRP TCP range' site_reservation tcp
check 'website cannot claim FRP-reserved HTTP-01 port' reject site_reservation tcp http
check 'website cannot claim FRP-reserved local TLS target' reject site_reservation tcp internal
check 'website cannot claim stopped FRP public HTTPS entrance' reject site_reservation web
guard_skips_frp() {
	reservation_fixture
	printf '0\n' >"$WORK/guard-counter"
	rand_port() {
		if [ "$(cat "$WORK/guard-counter")" = 0 ]; then printf '1\n' >"$WORK/guard-counter"; printf '20050\n'; else printf '25000\n'; fi
	}
	[ "$(pick_guard_port)" = 25000 ]
}
check 'REALITY local guard allocation skips stopped FRP reservations' guard_skips_frp
existing_proxy_reservation() {
	reservation_fixture
	PROTOCOLS=hysteria2
	pset CORE hysteria2 singbox; pset PORT hysteria2 "${1:-7000}"
	HY2_HOP=${2:-}
	if [ -z "$HY2_HOP" ]; then
		PROTOCOLS=vless-reality; pset CORE vless-reality xray; pset PORT vless-reality "$1"
	fi
	save_state || return 1
	_frps_check_ports
}
check 'FRP configuration respects an already saved proxy control-port reservation' reject existing_proxy_reservation 7000
check 'FRP range respects an already saved Hysteria2 hopping range' reject existing_proxy_reservation 15000 20040-20060

download_fixture() {
	local version=$1 member="frp_${1}_linux_amd64" digest bytes
	mkdir -p "$WORK/archive/$member"
	printf '#!/bin/sh\nprintf "%%s\\n" "%s"\n' "$version" >"$WORK/archive/$member/frps"
	cp "$WORK/archive/$member/frps" "$WORK/archive/$member/frpc"
	tar -czf "$WORK/release.tar.gz" -C "$WORK/archive" "$member"
	digest=$(sha256sum "$WORK/release.tar.gz" | cut -d' ' -f1) bytes=$(wc -c <"$WORK/release.tar.gz")
	jq -n --arg version "$version" --arg digest "sha256:$digest" --argjson size "$bytes" \
		'{tag_name:("v"+$version),draft:false,prerelease:false,assets:[{name:("frp_"+$version+"_linux_amd64.tar.gz"),browser_download_url:("https://github.com/fatedier/frp/releases/download/v"+$version+"/frp_"+$version+"_linux_amd64.tar.gz"),digest:$digest,size:$size}]}' >"$WORK/release.json"
}
download_mock() {
	uname() { [ "${1:-}" != -m ] || { printf 'x86_64\n'; return 0; }; command uname "$@"; }
	http_get() { if [[ "$1" == https://api.github.com/* ]]; then cat "$WORK/release.json"; else cp "$WORK/release.tar.gz" "$2"; fi; }
	gh_url() { printf '%s' "$1"; }
	_frps_download "$WORK/download-frps" "$WORK/download-frpc"
}
download_case() {
	local kind=$1 filter='.'
	set_valid
	if [ "$kind" = tag-drift ]; then download_fixture 0.99.0; else download_fixture "$TESTED_FRP_VERSION"; fi
	case "$kind" in
	missing-digest) filter='del(.assets[0].digest)' ;;
	bad-digest) filter='.assets[0].digest = "sha256:0000000000000000000000000000000000000000000000000000000000000000"' ;;
	bad-size) filter='.assets[0].size += 1' ;;
	foreign-url) filter='.assets[0].browser_download_url = "https://example.com/frp.tar.gz"' ;;
	duplicate) filter='.assets += [.assets[0]]' ;;
	draft) filter='.draft=true' ;;
	prerelease) filter='.prerelease=true' ;;
	oversize) filter='.assets[0].size=268435456' ;;
	latest) FRPS_VERSION=latest ;;
	esac
	jq "$filter" "$WORK/release.json" >"$WORK/changed.json" && mv "$WORK/changed.json" "$WORK/release.json" || return 1
	download_mock
}
check 'verified release downloads server and client fixtures' download_case valid
check 'latest release can resolve supported stable version' download_case latest
for case_name in missing-digest bad-digest bad-size foreign-url duplicate draft prerelease oversize tag-drift; do
	check "download rejects $case_name" reject download_case "$case_name"
done
printf 'FRP 回归测试: %s 通过, %s 失败\n' "$PASS" "$FAIL"
[ "$FAIL" = 0 ]
