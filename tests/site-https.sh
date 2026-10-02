#!/usr/bin/env bash
# 网站标准 HTTPS 入口回归: 仅临时文件与 mock，不绑定端口或操作系统服务。
# shellcheck disable=SC2034
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/.." && pwd)
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
export ONEBOX_SOURCE_ONLY=1 ONEBOX_DIR="$WORK/default" ONEBOX_SITE_ROOT="$WORK/public" NO_COLOR=1
# shellcheck source=../onebox.sh
. "$ROOT/onebox.sh"
PASS=0 FAIL=0
check() {
	local label=$1
	shift
	if "$@"; then PASS=$((PASS + 1)); else FAIL=$((FAIL + 1)); printf '  [失败] %s\n' "$label"; fi
}
eq() { [ "$1" = "$2" ]; }
not() { ! "$@"; }

fixture() {
	reset_state
	ONEBOX_DIR="$WORK/$1/etc"
	STATE_FILE="$ONEBOX_DIR/onebox.conf" SB_CONF="$ONEBOX_DIR/sing-box.json" XR_CONF="$ONEBOX_DIR/xray.json"
	CLIENT_DIR="$ONEBOX_DIR/client" REALITY_SITE_DIR="$ONEBOX_DIR/site"
	REALITY_SITE_ROOT="$WORK/$1/public" SITE_ACME_HOME="$REALITY_SITE_DIR/acme"
	CERT_TXN_BAK='' SITE_TXN_BAK='' INIT=none
	PROTOCOLS=vless-reality
	pset CORE vless-reality singbox
	pset PORT vless-reality 8443
	REALITY_SITE_ENABLED=1 REALITY_SITE_HTTPS='' REALITY_SITE_DOMAIN=site.example.com
	REALITY_SITE_PORT=18443 REALITY_SITE_TITLE='HTTPS regression'
	REALITY_SNI=$REALITY_SITE_DOMAIN REALITY_DEST="127.0.0.1:$REALITY_SITE_PORT"
	REALITY_PRIVATE_KEY=private REALITY_PUBLIC_KEY=public REALITY_SHORT_ID=0123abcd
	UUID=550e8400-e29b-41d4-a716-446655440000 CLASH_SECRET=test-secret
	SERVER_ADDR=203.0.113.9 SERVER_IPV4=203.0.113.9
	OPT_SITE_HTTPS='' OPT_REALITY_SITE='' OPT_SITE_TITLE='' OPT_SNI='' OPT_REALITY_DEST=''
}

fixture modes
check '旧状态空值默认关闭 HTTPS 443' not site_https_enabled
check '关闭时保留 REALITY 非标准公开端口' eq "$(site_public_port)" 8443
REALITY_SITE_HTTPS=1
check '显式启用 HTTPS 443' site_https_enabled
check 'REALITY 非 443 时采用独立反代' site_uses_https_proxy
check '网站公开端口固定为 443' eq "$(site_public_port)" 443
check 'REALITY 协议端口不随网站改变' eq "$(site_reality_port)" 8443
pset PORT vless-reality 443
check 'REALITY 443 自动复用不再开启反代' not site_uses_https_proxy
PROTOCOLS='vless-reality vless-xhttp'
pset PORT vless-reality 8443
pset CORE vless-xhttp xray
pset PORT vless-xhttp 443
check '多个 REALITY 入站优先复用已有 443' not site_uses_https_proxy
REALITY_SITE_ENABLED=0
check '网站停用后 HTTPS 标记不产生监听' not site_https_enabled
REALITY_SITE_ENABLED=1 PROTOCOLS=shadowsocks
check '没有 REALITY 时 HTTPS 标记不产生监听' not site_https_enabled

fixture ports
REALITY_SITE_HTTPS=1
check '独立反代的有效端口布局' site_validate_ports
PROTOCOLS='vless-reality trojan'
pset CORE trojan singbox
pset PORT trojan 443
check '拒绝与非 REALITY TCP 443 冲突' not site_validate_ports 2>/dev/null
PROTOCOLS='vless-reality shadowsocks'
pset CORE shadowsocks singbox
pset PORT shadowsocks 443
check '拒绝与 TCP+UDP 443 协议冲突' not site_validate_ports 2>/dev/null
PROTOCOLS='vless-reality hysteria2'
pset CORE hysteria2 singbox
pset PORT hysteria2 443
check 'UDP 443 可与网站 TCP 443 并存' site_validate_ports
REALITY_GUARD_PORT=443
check '拒绝与本机 REALITY 防护端口 443 冲突' not site_validate_ports 2>/dev/null
REALITY_GUARD_PORT=''
REALITY_SITE_HTTPS=0 PROTOCOLS='vless-reality trojan'
check '入口关闭时允许其他 TLS 协议使用 443' site_validate_ports

cli_ok() (
	fixture "cli-$1"
	parse_install_opts --site-https "$1" >/dev/null 2>&1 && [ "$OPT_SITE_HTTPS" = "$1" ]
)
cli_rejected() { (parse_install_opts --site-https "$@") >/dev/null 2>&1; [ "$?" -ne 0 ]; }
check 'CLI 接受 --site-https on' cli_ok on
check 'CLI 接受 --site-https off' cli_ok off
check 'CLI 拒绝无效 HTTPS 取值' cli_rejected yes
check 'CLI 拒绝缺失 HTTPS 取值' cli_rejected
check 'CLI 拒绝空 HTTPS 取值' cli_rejected ''

choose_default() (
	fixture "choose-$1-$2"
	REALITY_SITE_HTTPS=$1 OPT_SITE_HTTPS=$2 AUTO_YES=1 TTY_IN=''
	choose_owned_reality >/dev/null 2>&1 || return 1
	[ "$REALITY_SITE_HTTPS" = "$3" ] && [ "$(pget PORT vless-reality)" = 8443 ] &&
		[ "$REALITY_DEST" = '127.0.0.1:18443' ]
)
check '新建站点默认选择标准 HTTPS 入口' choose_default '' '' 1
check '已有关闭选择再次配置时保留关闭' choose_default 0 '' 0
check 'CLI off 覆盖新站点默认开启' choose_default '' off 0
check 'CLI on 可重新开启已有关闭设置' choose_default 0 on 1

state_roundtrip() (
	fixture "state-$1"
	REALITY_SITE_HTTPS=$1
	save_state || return 1
	REALITY_SITE_HTTPS=wrong
	load_state && [ "$REALITY_SITE_HTTPS" = "$1" ]
)
old_state_stays_off() (
	fixture old-state
	REALITY_SITE_HTTPS=1
	save_state || return 1
	sed -i '/^REALITY_SITE_HTTPS=/d' "$STATE_FILE"
	load_state && ! site_https_enabled && [ "$(site_public_port)" = 8443 ]
)
check '状态文件保存开启选择' state_roundtrip 1
check '状态文件保存关闭选择' state_roundtrip 0
check '加载旧版本状态不会意外新增 443 监听' old_state_stays_off

signature_changes_with_owner() (
	fixture signatures
	REALITY_SITE_HTTPS=1
	local proxy_sig public
	proxy_sig=$(_site_signature) public=$(site_public_port)
	pset PORT vless-reality 443
	[ "$public" = "$(site_public_port)" ] && [ "$proxy_sig" != "$(_site_signature)" ]
)
check '公开 URL 不变时 443 归属切换仍触发配置更新' signature_changes_with_owner

nginx_modes() (
	fixture nginx
	REALITY_SITE_HTTPS=1
	site_nginx_check() { :; }
	site_write_nginx defer || return 1
	grep -qF 'listen 127.0.0.1:18443 ssl http2;' "$REALITY_SITE_DIR/nginx.conf" &&
		grep -qF 'return 301 https://site.example.com$request_uri;' "$REALITY_SITE_DIR/nginx.conf" &&
		! grep -qE 'listen (\[::\]:)?443 ' "$REALITY_SITE_DIR/nginx.conf" || return 1
	site_write_nginx || return 1
	grep -qF 'listen 443 ssl http2;' "$REALITY_SITE_DIR/nginx.conf" &&
		grep -qF 'proxy_pass https://127.0.0.1:18443;' "$REALITY_SITE_DIR/nginx.conf" &&
		grep -qF 'proxy_ssl_verify on;' "$REALITY_SITE_DIR/nginx.conf" || return 1
	pset PORT vless-reality 443
	site_write_nginx && ! grep -qE 'listen (\[::\]:)?443 ' "$REALITY_SITE_DIR/nginx.conf"
)
check '预备阶段不监听 443，独立反代和复用生成不同配置' nginx_modes

takeover_port_allowed() (
	fixture "takeover-$1"
	REALITY_SITE_HTTPS=${2:-1} REALITY_SITE_ENABLED=${3:-1}
	mkdir -p "$REALITY_SITE_DIR"
	printf '443\n' >"$REALITY_SITE_DIR/frontend-port"
	# Do not infer ownership from a stale marker or unrelated listener.
	MOCK_RUNNING=$1
	_site_running() { [ "$MOCK_RUNNING" = 1 ]; }
	port_in_use() { [ "$1" = 443 ] && [ "$2" = tcp ]; }
	port_ok 443 "${4:-vless-reality}" >/dev/null 2>&1
)
check '允许 REALITY 接管本脚本站点正在监听的 443' takeover_port_allowed 1
check '过期归属标记不能绕过外部 443 占用检查' not takeover_port_allowed 0
check '关闭 HTTPS 后允许其他 TLS 协议接管原 nginx 443' takeover_port_allowed 1 0 1 trojan
check '关闭网站后允许其他 TLS 协议接管原 nginx 443' takeover_port_allowed 1 1 0 trojan

# Keep real snapshot/config/apply/rollback code. Model only process ownership,
# DNS/ACME/cron/firewall and generated core files, all within this fixture.
mock_runtime() {
	MOCK_CORE_PORT=$(pget PORT vless-reality)
	MOCK_CORE_OWNER=$(pget CORE vless-reality)
	MOCK_INSTALLED=" $MOCK_CORE_OWNER "
	MOCK_SITE_PORT=0 MOCK_SITE_RUNNING=1 MOCK_FAULT=''
	EVENTS="$ONEBOX_DIR/events"
	mkdir -p "$REALITY_SITE_DIR" "$REALITY_SITE_ROOT" "$CLIENT_DIR"
	: >"$REALITY_SITE_DIR/.onebox-site-owned"
	: >"$REALITY_SITE_ROOT/.onebox-site-owned"
	printf 'custom content\n' >"$REALITY_SITE_ROOT/index.html"
	printf 'old-client\n' >"$CLIENT_DIR/links.txt"
	printf 'old-server\n' >"$SB_CONF"
	_site_running() { [ "$MOCK_SITE_RUNNING" = 1 ]; }
	site_nginx_check() { :; }
	_site_cert_usable() { :; }
	site_check_dns() { printf 'unexpected-dns\n' >>"$EVENTS"; return 1; }
	site_issue_cert() { printf 'unexpected-acme\n' >>"$EVENTS"; return 1; }
	site_install_nginx() { :; }
	ensure_cmds() { :; }
	_site_write_service() { :; }
	_site_enable_unit() { :; }
	_site_disable_unit() { :; }
	_site_cron_lines() { :; }
	_site_cron_enable() { :; }
	_site_cron_remove() { :; }
	_fw_snapshot() { printf unchanged; }
	fw_rule() { :; }
	fw_apply() { :; }
	hop_rules() { :; }
	hop_setup() { :; }
	sleep() { :; }
	port_in_use() {
		[ "$2" = tcp ] && { [ "$1" = "$MOCK_CORE_PORT" ] || [ "$1" = "$MOCK_SITE_PORT" ]; }
	}
	site_service() {
		printf 'site:%s\n' "$1" >>"$EVENTS"
		if [ "$1" = stop ]; then MOCK_SITE_RUNNING=0 MOCK_SITE_PORT=0; return 0; fi
		if [ "$1" = start ] && [ "$MOCK_SITE_RUNNING" = 1 ]; then return 0; fi
		local next=0
		if grep -qF 'listen 443 ssl http2;' "$REALITY_SITE_DIR/nginx.conf"; then next=443; fi
		if [ "$next" = 443 ] && [ "$MOCK_CORE_PORT" = 443 ]; then printf 'collision\n' >>"$EVENTS"; return 1; fi
		MOCK_SITE_PORT=$next MOCK_SITE_RUNNING=1
		printf 'site-port:%s\n' "$next" >>"$EVENTS"
	}
	site_health() { :; }
	site_https_health() { [ "$MOCK_FAULT" != frontend ]; }
	svc_exists() { [[ "$MOCK_INSTALLED" == *" $1 "* ]]; }
	svc_write() { if ! svc_exists "$1"; then MOCK_INSTALLED+="$1 "; fi; }
	svc_enable() { :; }
	svc_remove() { svc_stop "$1"; }
	svc_stop() {
		printf 'core:stop:%s\n' "$1" >>"$EVENTS"
		if [ "$MOCK_CORE_OWNER" = "$1" ]; then MOCK_CORE_PORT=0; fi
	}
	svc_start() {
		printf 'core:start:%s\n' "$1" >>"$EVENTS"
		local next
		next=$(pget PORT vless-reality)
		if [ "$next" = 443 ] && [ "$MOCK_SITE_PORT" = 443 ]; then printf 'collision\n' >>"$EVENTS"; return 1; fi
		MOCK_CORE_PORT=$next MOCK_CORE_OWNER=$1
	}
	svc_active() { [ "$MOCK_CORE_PORT" != 0 ] && [ "$MOCK_CORE_OWNER" = "$1" ]; }
	svc_logs() { :; }
	prepare_site_and_renewal() { site_prepare; }
	prepare_server_configs() { printf 'new-server\n' >"${SB_CONF%.json}.new.json"; }
	own_ip_cidrs() { printf '"203.0.113.9/32"'; }
	cert_txn_rollback() { site_rollback; }
	cert_txn_commit() { site_commit; }
	write_client_files() {
		printf 'new-client\n' >"$CLIENT_DIR/links.txt"
		[ "$MOCK_FAULT" != client ]
	}
	# Establish the previously committed listener and its real on-disk snapshot.
	site_write_nginx || return 1
	if site_uses_https_proxy; then MOCK_SITE_PORT=443; fi
	printf '%s\n' "$MOCK_SITE_PORT" >"$REALITY_SITE_DIR/frontend-port"
	printf '%s\n' "$REALITY_SITE_PORT" >"$REALITY_SITE_DIR/local-port"
	_site_signature >"$REALITY_SITE_DIR/settings.sha256"
	save_state
}

transition() (
	local old=$1 new=$2 fault=$3 oldcore=${4:-singbox} newcore=${5:-singbox} rc expected=0
	fixture "transition-$old-$new-${fault:-ok}-$oldcore-$newcore"
	REALITY_SITE_HTTPS=1
	REALITY_GUARD_PORT=19000
	pset PORT vless-reality "$old"
	pset CORE vless-reality "$oldcore"
	mock_runtime || return 1
	command cp "$STATE_FILE" "$ONEBOX_DIR/expected-state"
	command cp "$REALITY_SITE_DIR/nginx.conf" "$ONEBOX_DIR/expected-nginx"
	pset PORT vless-reality "$new"
	pset CORE vless-reality "$newcore"
	prepare_server_configs() {
		local nextconf
		nextconf=$(svc_conf "$(pget CORE vless-reality)")
		printf 'new-server\n' >"${nextconf%.json}.new.json"
	}
	MOCK_FAULT=$fault
	[ -z "$fault" ] || expected=2
	apply_all >/dev/null 2>&1
	rc=$?
	[ "$rc" = "$expected" ] && ! grep -qE 'collision|unexpected-' "$EVENTS" || return 1
	[ -z "$SITE_TXN_BAK" ] || return 1
	if [ -n "$fault" ]; then
		cmp -s "$STATE_FILE" "$ONEBOX_DIR/expected-state" &&
			cmp -s "$REALITY_SITE_DIR/nginx.conf" "$ONEBOX_DIR/expected-nginx" &&
			[ "$(cat "$CLIENT_DIR/links.txt")" = old-client ] && [ "$MOCK_CORE_PORT" = "$old" ] &&
			[ "$MOCK_CORE_OWNER" = "$oldcore" ] || return 1
		if [ "$old" = 443 ]; then [ "$MOCK_SITE_PORT" = 0 ]; else [ "$MOCK_SITE_PORT" = 443 ]; fi
	else
		[ "$MOCK_CORE_PORT" = "$new" ] && [ "$MOCK_CORE_OWNER" = "$newcore" ] &&
			[ "$(cat "$CLIENT_DIR/links.txt")" = new-client ] || return 1
		if [ "$new" = 443 ]; then [ "$MOCK_SITE_PORT" = 0 ]; else [ "$MOCK_SITE_PORT" = 443 ]; fi
	fi
)
check 'REALITY 443 → nginx 443：先停旧核心再启反代' transition 443 8443 ''
check 'nginx 443 → REALITY 443：先释放反代监听再启核心' transition 8443 443 ''
check '反代健康检查失败恢复旧 REALITY 443 与全部文件' transition 443 8443 frontend
check '新核心已占 443 后发生写入失败仍能恢复旧 nginx 443' transition 8443 443 client
check '新反代已占 443 后发生写入失败仍能恢复旧 REALITY 443' transition 443 8443 client
check '旧 Xray 443 改为 sing-box 非 443 时先停止已删除的 Xray' transition 443 8443 '' xray singbox
check '跨核心接管 443 后失败仍恢复原核心和 nginx 443' transition 8443 443 client singbox xray

resume_deferred_frontend() (
	fixture resume
	REALITY_SITE_HTTPS=1
	mock_runtime || return 1
	site_write_nginx defer || return 1
	printf '0\n' >"$REALITY_SITE_DIR/frontend-port"
	MOCK_SITE_PORT=0
	_site_cron_lines() { printf '%s\n' 'mock --cron'; }
	site_https_health() {
		[ "$(cat "$REALITY_SITE_DIR/frontend-port")" = 0 ] && [ "$MOCK_SITE_PORT" = 443 ]
	}
	site_prepare && [ ! -f "$EVENTS" ] && site_apply_service || return 1
	[ "$(cat "$REALITY_SITE_DIR/frontend-port")" = 443 ] && [ "$MOCK_SITE_PORT" = 443 ] &&
		[ -n "$SITE_TXN_BAK" ] && site_commit
)
check '准备中断后快速路径仍会激活 443，并在健康通过后更新标记' resume_deferred_frontend

unchanged_frontend_no_restart() (
	fixture unchanged
	REALITY_SITE_HTTPS=1
	mock_runtime || return 1
	_site_cron_lines() { printf '%s\n' 'mock --cron'; }
	site_prepare && site_apply_service || return 1
	[ "$(cat "$REALITY_SITE_DIR/frontend-port")" = 443 ] && [ "$MOCK_SITE_PORT" = 443 ] &&
		[ -z "$SITE_TXN_BAK" ] && [ "$(cat "$EVENTS")" = site:start ]
)
check '健康且未变更的站点不重签证书、不重启 nginx' unchanged_frontend_no_restart

activation_failure_preserves_marker() (
	fixture "activation-$1"
	REALITY_SITE_HTTPS=1
	mock_runtime || return 1
	site_write_nginx defer || return 1
	printf '0\n' >"$REALITY_SITE_DIR/frontend-port"
	MOCK_SITE_PORT=0
	case "$1" in
		snapshot) _site_txn_begin() { return 1; } ;;
		config) site_write_nginx() { return 1; } ;;
		restart) site_service() { return 1; } ;;
		health) site_https_health() { return 1; } ;;
	esac
	if site_apply_service >/dev/null 2>&1; then return 1; fi
	[ "$(cat "$REALITY_SITE_DIR/frontend-port")" = 0 ]
)
for phase in snapshot config restart health; do
	check "激活 ${phase} 失败不写入成功的 443 标记" activation_failure_preserves_marker "$phase"
done

external_listener_rejected() (
	fixture external
	REALITY_SITE_HTTPS=1
	mock_runtime || return 1
	MOCK_SITE_RUNNING=0 MOCK_SITE_PORT=0
	# Force preparation rather than the unchanged configuration fast path.
	REALITY_SITE_TITLE=changed
	port_in_use() { [ "$1" = 443 ] && [ "$2" = tcp ]; }
	if site_prepare >/dev/null 2>&1; then return 1; fi
	[ -z "$SITE_TXN_BAK" ] && [ ! -f "$EVENTS" ] && [ "$(cat "$REALITY_SITE_ROOT/index.html")" = 'custom content' ]
)
check '外部 TCP 443 占用在改写配置和停服务之前被拒绝' external_listener_rejected

stopping_failure_blocks_site() (
	fixture stop-failure
	REALITY_SITE_HTTPS=1
	mock_runtime || return 1
	svc_stop() { printf 'core:stop-failed\n' >>"$EVENTS"; return 1; }
	if apply_services >/dev/null 2>&1; then return 1; fi
	! grep -qE '^site:|^core:start:' "$EVENTS"
)
check '旧核心停止失败不启动反代或新核心' stopping_failure_blocks_site

firewall_includes_frontend() (
	fixture firewall
	REALITY_SITE_HTTPS=1
	local calls="$ONEBOX_DIR/rules"
	mkdir -p "$ONEBOX_DIR"
	_fw_ledger_migrate() { :; }
	fw_rule() { printf '%s %s %s\n' "$1" "$2" "$3" >>"$calls"; }
	fw_apply open && fw_apply close || return 1
	grep -qxF 'open 443 tcp' "$calls" && grep -qxF 'close 443 tcp' "$calls" &&
		grep -qxF 'open 8443 tcp' "$calls" && ! grep -qF '18443' "$calls"
)
check '防火墙包含公开 443 和 REALITY 端口但不开放本机端口' firewall_includes_frontend

printf '\nHTTPS 入口测试: %s 通过, %s 失败\n' "$PASS" "$FAIL"
[ "$FAIL" = 0 ]
