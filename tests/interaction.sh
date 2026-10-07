#!/usr/bin/env bash
# Input and menu regression checks; all service actions are mocked.
# shellcheck disable=SC2034
set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd)
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
export ONEBOX_SOURCE_ONLY=1 NO_COLOR=1
export ONEBOX_DIR="$WORK/proxy" ONEBOX_FRPS_DIR="$WORK/frp"
# shellcheck source=../onebox.sh
. "$ROOT/onebox.sh"
PASS=0 FAIL=0
check() {
	local label=$1
	shift
	if ("$@") >"$WORK/result" 2>&1; then PASS=$((PASS + 1));
	else FAIL=$((FAIL + 1)); printf '[失败] %s\n' "$label"; cat "$WORK/result"; fi
}

# Use an inherited pipe so every question consumes the next answer, as a TTY
# would. Opening a regular fixture file for each read would replay line one.
input() { AUTO_YES=0; exec 9< <(printf '%s' "$1"); TTY_IN=/dev/fd/9; }
eof_cancels() {
	local rc=0
	rm -f "$WORK/continued" "$WORK/cleanup"
	(
		input ''
		trap ': >"$WORK/cleanup"' EXIT
		"$@"
		: >"$WORK/continued"
	) >"$WORK/closed" 2>&1 || rc=$?
	[ "$rc" = 130 ] && [ ! -e "$WORK/continued" ] && [ -f "$WORK/cleanup" ] &&
		grep -qF '输入已结束' "$WORK/closed"
}
check 'EOF stops ordinary input instead of selecting its default' eof_cancels ask answer '设置' default
check 'EOF cannot accept a default-yes confirmation' eof_cancels ask_yn '确认' y
check 'EOF cannot continue after a default-no confirmation' eof_cancels ask_yn '确认' n
check 'EOF stops numeric input before caller fallback' eof_cancels ask_num answer '端口' 443 1 65535
check 'EOF stops domain input even with a valid default' eof_cancels ask_domain answer '域名' example.com
check 'EOF stops domain input without a default' eof_cancels ask_domain answer '域名' ''
check 'EOF stops hidden credential input' eof_cancels ask_secret answer '密钥'
check 'EOF at pause ends the menu instead of redrawing it' eof_cancels pause
check 'EOF stops confirm with default yes' eof_cancels confirm '确认' y

conditional_eof() {
	local rc=0
	rm -f "$WORK/changed" "$WORK/fallback"
	(input ''; if confirm '执行变更' y; then : >"$WORK/changed"; else : >"$WORK/fallback"; fi) || rc=$?
	[ "$rc" = 130 ] && [ ! -e "$WORK/changed" ] && [ ! -e "$WORK/fallback" ]
}
check 'conditional callers cannot convert EOF into a yes or no action' conditional_eof
numeric_fallback_eof() {
	local rc=0
	rm -f "$WORK/fallback"
	(input ''; ask_num answer '类型' 1 1 2 || : >"$WORK/fallback") || rc=$?
	[ "$rc" = 130 ] && [ ! -e "$WORK/fallback" ]
}
check 'legacy numeric fallback cannot execute after EOF' numeric_fallback_eof
partial_eof() {
	local rc=0
	rm -f "$WORK/continued"
	(input 'yes'; ask_yn '确认' n; : >"$WORK/continued") || rc=$?
	[ "$rc" = 130 ] && [ ! -e "$WORK/continued" ]
}
check 'an unterminated line is not an implicit confirmation' partial_eof
retry_then_eof() {
	local rc=0
	(input $'bad\n'; ask_num answer '端口' 443 1 65535) || rc=$?
	[ "$rc" = 130 ]
}
check 'invalid input followed by EOF stops reprompting' retry_then_eof
read_failure() {
	local rc=0
	(AUTO_YES=0 TTY_IN="$WORK/missing-input"; ask answer '设置' default) || rc=$?
	[ "$rc" = 130 ]
}
check 'unavailable terminal input cancels explicitly' read_failure

blank_default() { local answer=''; input $'\n'; ask answer '设置' default; [ "$answer" = default ]; }
check 'Enter still accepts a text default' blank_default
yes_default() { input $'\n'; ask_yn '确认' y; }
check 'Enter still accepts default yes' yes_default
no_default() { input $'\n'; ! ask_yn '确认' n; }
check 'Enter still accepts default no' no_default
numeric_retry() { local answer=''; input $'wrong\n70000\n00443\n'; ask_num answer '端口' 80 1 65535; [ "$answer" = 443 ]; }
check 'numeric validation retries then normalizes leading zeros' numeric_retry
domain_retry() { local answer=''; input $'invalid\nhttps://app.example.com/path\n'; ask_domain answer '域名' ''; [ "$answer" = app.example.com ]; }
check 'domain validation retries and strips pasted URL prefix' domain_retry
secret_input() { local answer=''; input $' token-123 \n'; ask_secret answer '密钥' 2>"$WORK/secret-output"; [ "$answer" = token-123 ] && ! grep -qF token-123 "$WORK/secret-output"; }
check 'secret input is collected without appearing in output' secret_input
noninteractive_defaults() {
	local answer=''
	AUTO_YES=0 TTY_IN=''
	ask answer '设置' default && [ "$answer" = default ] &&
		ask_num answer '端口' 443 1 65535 && [ "$answer" = 443 ] &&
		ask_domain answer '域名' example.com && [ "$answer" = example.com ] &&
		! confirm '危险操作' n
}
check 'noninteractive defaults remain compatible and confirmations default to no' noninteractive_defaults
auto_yes() {
	local answer=''
	AUTO_YES=1 TTY_IN=/dev/null
	confirm '执行' n && ask answer '设置' default && [ "$answer" = default ] &&
		ask_num answer '端口' 443 1 65535 && [ "$answer" = 443 ] &&
		ask_domain answer '域名' example.com && [ "$answer" = example.com ]
}
check '-y still skips terminal reads and accepts explicit confirmation' auto_yes

header_mocks() {
	AUTO_YES=0 TTY_IN=''
	OS_NAME=Test ARCH_RAW=amd64 VIRT=mock
	bbr_status() { printf 'BBR'; }
	update_channel_get() { printf 'stable'; }
	is_installed() { return 1; }
	clear() { : >"$WORK/clear-called"; }
}
frp_header() {
	local installed=$1 state=$2 running=$3 expected=$4
	header_mocks
	FRPS_DOMAIN=unchanged.example.com FRPS_TOKEN=unchanged
	_frps_installed() { [ "$installed" = 1 ]; }
	_frps_load() { FRPS_DOMAIN=private.example.com FRPS_TOKEN=private-token; printf 'private-token\n'; [ "$state" = 1 ]; }
	_frps_service_active() { [ "$running" = 1 ]; }
	menu_header >"$WORK/header"
	grep -qF "$expected" "$WORK/header" && ! grep -qF private-token "$WORK/header" &&
		[ "$FRPS_DOMAIN" = unchanged.example.com ] && [ "$FRPS_TOKEN" = unchanged ] && [ ! -e "$WORK/clear-called" ]
}
check 'header distinguishes an absent independent FRP installation' frp_header 0 0 0 'FRP 独立服务: 未安装'
check 'header reports malformed FRP state without leaking credentials' frp_header 1 0 0 'FRP 独立服务: 配置待检查'
check 'header reports stopped FRP even when proxy is not installed' frp_header 1 1 0 'FRP 独立服务: 已安装，未运行'
check 'header reports running FRP without mutating caller state' frp_header 1 1 1 'FRP 独立服务: 运行中'

menu_mocks() {
	menu_header() { :; }
	pause() { :; }
	require_installed() { :; }
	managed_change() { printf 'managed:%s\n' "$1" >>"$WORK/actions"; [ "$1" != do_update_script ]; }
	show_info() { printf 'info\n' >>"$WORK/actions"; }
	show_client() { printf 'client\n' >>"$WORK/actions"; }
	service_menu() { printf 'service\n' >>"$WORK/actions"; }
	bbr_menu() { printf 'bbr\n' >>"$WORK/actions"; }
	do_uninstall() { printf 'uninstall\n' >>"$WORK/actions"; }
	site_menu() { printf 'site\n' >>"$WORK/actions"; }
	do_doctor() { printf 'doctor\n' >>"$WORK/actions"; }
	do_cert_status() { printf 'cert-status\n' >>"$WORK/actions"; }
	recovery_menu() { printf 'recovery\n' >>"$WORK/actions"; }
	do_support_bundle() { printf 'support\n' >>"$WORK/actions"; }
	update_menu() { printf 'update\n' >>"$WORK/actions"; }
	plan_menu() { printf 'plan\n' >>"$WORK/actions"; }
	link_tools_menu() { printf 'links\n' >>"$WORK/actions"; }
	tuning_menu() { printf 'tuning\n' >>"$WORK/actions"; }
	do_frps() { printf 'frps\n' >>"$WORK/actions"; }
	STATE_FILE="$WORK/menu-state"; : >"$STATE_FILE"
}
menu_route() {
	local choice=$1 expected=$2
	menu_mocks
	: >"$WORK/actions"
	(input "$choice"$'\n0\n'; main_menu) >"$WORK/menu" || return 1
	[ "$(cat "$WORK/actions")" = "$expected" ]
}
while IFS='|' read -r choice expected; do
	check "main menu option $choice keeps its original action" menu_route "$choice" "$expected"
done <<'ROUTES'
1|managed:do_install
2|info
3|client
4|managed:do_add_protocol
5|managed:do_del_protocol
6|managed:do_change_port
7|managed:do_change_addr
8|managed:do_reset_credentials
9|service
10|managed:do_update_core
11|managed:do_cert
12|bbr
13|managed:do_update_script
14|uninstall
15|managed:do_change_sni
16|site
17|doctor
18|cert-status
19|recovery
20|support
21|update
22|plan
23|links
24|tuning
25|frps
ROUTES
menu_layout() {
	menu_mocks
	(input $'0\n'; main_menu) >"$WORK/menu" || return 1
	grep -qF '部署与连接' "$WORK/menu" && grep -qF '代理与网站配置' "$WORK/menu" &&
		grep -qF '运行与诊断' "$WORK/menu" && grep -qF '性能与维护' "$WORK/menu" &&
		[ "$(sed -n 's/^  \([0-9][0-9]*\)\..*/\1/p' "$WORK/menu" | sort -n | tr '\n' ' ')" = "$(seq 0 25 | tr '\n' ' ')" ]
}
check 'main menu groups tasks while displaying every numeric option exactly once' menu_layout
menu_eof() {
	local rc=0
	menu_mocks
	: >"$WORK/actions"
	(input ''; main_menu) || rc=$?
	[ "$rc" = 130 ] && [ ! -s "$WORK/actions" ]
}
check 'main-menu EOF exits with no operation dispatched' menu_eof
action_eof() {
	local rc=0
	menu_mocks
	rm -f "$WORK/paused" "$WORK/actions"
	do_frps() { ask answer '设置' default; printf 'frps\n' >>"$WORK/actions"; }
	pause() { : >"$WORK/paused"; }
	(input $'25\n'; main_menu) || rc=$?
	[ "$rc" = 130 ] && [ ! -e "$WORK/paused" ] && [ ! -e "$WORK/actions" ]
}
check 'EOF inside a menu operation exits without asking for another Enter' action_eof
menu_pause() {
	local choice=$1 action_rc=$2 expected=$3
	menu_mocks
	rm -f "$WORK/paused"
	do_frps() { return "$action_rc"; }
	pause() { : >"$WORK/paused"; }
	(input "$choice"$'\n0\n'; main_menu) || return 1
	if [ "$expected" = yes ]; then [ -f "$WORK/paused" ]; else [ ! -e "$WORK/paused" ]; fi
}
check 'returning from FRP skips the duplicate pause in the main menu' menu_pause 25 0 no
check 'FRP failure still pauses so the error remains visible' menu_pause 25 1 yes
check 'other main-menu actions retain their pause' menu_pause 2 0 yes

printf 'Interaction tests: %s passed, %s failed\n' "$PASS" "$FAIL"
[ "$FAIL" = 0 ]
