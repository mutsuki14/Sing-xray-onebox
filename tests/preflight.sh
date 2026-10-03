#!/usr/bin/env bash
# 预演复用真实选择器, 用副作用哨兵保证不安装/写状态/联网/生成凭据。
# shellcheck disable=SC2034
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/.." && pwd)
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
export ONEBOX_SOURCE_ONLY=1 ONEBOX_DIR="$WORK/etc" ONEBOX_BIN_DIR="$WORK/bin" \
	ONEBOX_LOG_DIR="$WORK/log" ONEBOX_RUN_DIR="$WORK/run" ONEBOX_SITE_ROOT="$WORK/public" NO_COLOR=1
# shellcheck source=../onebox.sh
. "$ROOT/onebox.sh"
# Development assembly only: remove this source after integrating the feature.
# shellcheck source=/dev/null
PASS=0 FAIL=0
check() {
	if ( "$@" ); then PASS=$((PASS + 1)); else
		FAIL=$((FAIL + 1)); printf '[失败] %s\n' "$*"
		cat "$WORK/out" "$WORK/err" 2>/dev/null || true
	fi
}

fixture() {
	command rm -rf "$ONEBOX_DIR" "$WORK/forbidden"
	command mkdir -p "$ONEBOX_DIR"
	reset_state
	detect_os() { OS_NAME=TestLinux; }
	detect_init() { INIT=systemd; }
	port_in_use() { return 1; }
	_site_running() { return 1; }
	_site_owns_https_listener() { return 1; }
	local fn
	for fn in require_root install_base_deps ensure_cmds pkg_install pkg_update save_state load_state gen_credentials \
		gen_uuid gen_reality_keypair gen_ss_password rand_hex rand_str rand_base64 \
		detect_public_ip check_domain_points_here resolve_domain check_tls13 \
		obtain_cert cert_acme acme acme_install site_prepare site_issue_cert \
		apply_all apply_services site_service svc_start svc_stop svc_restart \
		fw_rule fw_apply net_persist hop_rules http_get curl wget; do
		eval "$fn() { printf '%s\\n' '$fn' >>\"\$WORK/forbidden\"; return 99; }"
	done
}
run_plan() { do_install_plan >"$WORK/out" 2>"$WORK/err"; }
text_has() { grep -qF -- "$1" "$WORK/out"; }
no_effects() { [ ! -e "$WORK/forbidden" ]; }

preset_matches_shared_catalog() {
	fixture
	parse_install_opts --preset "$1"
	run_plan || return 1
	local p prefer expected
	prefer=$(preset_field "$1" 4)
	for p in $(preset_field "$1" 3); do
		if proto_supports_core "$p" "$prefer" && ! proto_core_experimental "$p" "$prefer"; then expected=$prefer
		else expected=$(proto_cores "$p"); expected=${expected%% *}; fi
		text_has "$p | $expected |" || return 1
	done
	no_effects
}
for preset in 1 2 3 4 5 6; do check preset_matches_shared_catalog "$preset"; done

xray_shared_port() {
	fixture; parse_install_opts --preset 2
	run_plan && text_has 'vless-reality | xray | 443/tcp' && text_has 'vless-xhttp | xray | 443/tcp' && no_effects
}
check xray_shared_port

custom_core_fallback() {
	fixture; parse_install_opts --protocols vless-reality,tuic --core xray
	run_plan && text_has 'vless-reality | xray |' && text_has 'tuic | singbox |' && no_effects
}
check custom_core_fallback

explicit_hy2_xray() {
	fixture; parse_install_opts --protocols hysteria2 --hy2-core xray
	run_plan && text_has 'hysteria2 | xray |' && no_effects
}
check explicit_hy2_xray

explicit_port_conflicts() {
	fixture; parse_install_opts --protocols vless-reality,trojan --port vless-reality=443 --port trojan=443
	! run_plan && grep -q '冲突' "$WORK/err" && no_effects
}
check explicit_port_conflicts

foreign_listener_conflicts() {
	fixture; parse_install_opts --preset 6 --port vless-reality=24443
	port_in_use() { [ "$1/$2" = 24443/tcp ]; }
	! run_plan && grep -q '已被其他程序占用' "$WORK/err" && no_effects
}
check foreign_listener_conflicts

existing_onebox_port_is_reused_without_loading_secrets() {
	fixture
	printf 'PROTOCOLS=vless-reality\nPORT_vless_reality=24443\nPASSWORD=DoNotPrintThisSecret\nprintf BAD >"%s/forbidden"\n' "$WORK" >"$STATE_FILE"
	parse_install_opts --preset 6 --port vless-reality=24443
	port_in_use() { [ "$1/$2" = 24443/tcp ]; }
	run_plan && text_has '已有 onebox' && ! text_has DoNotPrintThisSecret && no_effects
}
check existing_onebox_port_is_reused_without_loading_secrets

owned_site_default_https() {
	fixture; parse_install_opts --preset 6 --reality-site site.example.com
	run_plan && text_has 'HTTPS 网站入口: https://site.example.com/' && text_has "$REALITY_SITE_ROOT/index.html" && no_effects
}
check owned_site_default_https

owned_site_nonstandard_entry() {
	fixture; parse_install_opts --preset 6 --reality-site site.example.com --site-https off --port vless-reality=24443
	run_plan && text_has 'HTTPS 网站入口: https://site.example.com:24443/' && no_effects
}
check owned_site_nonstandard_entry

owned_site_http_conflict() {
	fixture; parse_install_opts --preset 6 --reality-site site.example.com
	port_in_use() { [ "$1/$2" = 80/tcp ]; }
	! run_plan && grep -q 'TCP 80' "$WORK/err" && no_effects
}
check owned_site_http_conflict

owned_site_frontend_conflict() {
	fixture; parse_install_opts --preset 6 --reality-site site.example.com --port vless-reality=24443
	port_in_use() { [ "$1/$2" = 443/tcp ]; }
	! run_plan && grep -q 'TCP 443' "$WORK/err" && no_effects
}
check owned_site_frontend_conflict

acme_no_dns_or_ip_lookup() {
	fixture; parse_install_opts --protocols trojan --tls acme --domain tls.example.com
	run_plan && text_has 'ACME, 域名=tls.example.com, 验证方式=standalone' && text_has '待实际安装现场校验' && no_effects
}
check acme_no_dns_or_ip_lookup

cf_no_credentials_requested() {
	fixture; unset CF_Token CF_Key CF_Email
	parse_install_opts --protocols trojan --tls cf --domain tls.example.com
	run_plan && text_has 'Cloudflare API 凭据须在实际签发时提供' && no_effects
}
check cf_no_credentials_requested

vmess_tls_port_follows_real_tls_choice() {
	fixture; parse_install_opts --protocols vmess-ws --tls cf --domain tls.example.com
	run_plan && text_has 'vmess-ws | singbox | 2096/tcp' && no_effects
}
check vmess_tls_port_follows_real_tls_choice

vmess_plain_port_follows_real_tls_choice() {
	fixture; parse_install_opts --protocols vmess-ws
	run_plan && text_has 'vmess-ws | singbox | 8080/tcp' && no_effects
}
check vmess_plain_port_follows_real_tls_choice

caller_state_is_unchanged() {
	fixture; PROTOCOLS=before; AUTO_YES=0; pset PORT vless-reality 12345
	parse_install_opts --preset 6
	run_plan && [ "$PROTOCOLS" = before ] && [ "$AUTO_YES" = 0 ] && [ "$(pget PORT vless-reality)" = 12345 ] && no_effects
}
check caller_state_is_unchanged

existing_files_are_unchanged() {
	fixture
	printf 'PROTOCOLS=vless-reality\nPORT_vless_reality=24443\nPASSWORD=DoNotPrintThisSecret\n' >"$STATE_FILE"
	printf 'user site content\n' >"$ONEBOX_DIR/user-content"
	local before after
	before=$(find "$ONEBOX_DIR" -type f -exec cksum {} + | sort)
	parse_install_opts --preset 6 --reality-site site.example.com
	run_plan || return 1
	after=$(find "$ONEBOX_DIR" -type f -exec cksum {} + | sort)
	[ "$before" = "$after" ] && no_effects
}
check existing_files_are_unchanged

hop_conflict_nonzero() {
	fixture; parse_install_opts --protocols hysteria2,tuic --hy2-hop 20000-30000 --port tuic=24443
	run_plan && return 1
	grep -q '端口跳跃范围' "$WORK/err" && no_effects
}
check hop_conflict_nonzero

bad_address_nonzero() {
	fixture; parse_install_opts --preset 6 --addr 'bad host!'
	! run_plan && grep -q '无效的客户端连接地址' "$WORK/err" && no_effects
}
check bad_address_nonzero

printf '安装预演回归: %s 通过, %s 失败\n' "$PASS" "$FAIL"
[ "$FAIL" = 0 ]
