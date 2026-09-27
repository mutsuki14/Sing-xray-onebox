#!/usr/bin/env bash
# 配置提交与命令失败回归: 全部文件在临时目录, 系统服务和网络操作均为 mock。
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
	if "$@"; then PASS=$((PASS + 1)); else FAIL=$((FAIL + 1)); printf '  [失败] %s\n' "$*"; fi
}

fixture() {
	reset_state
	ONEBOX_DIR="$WORK/$1/etc"
	STATE_FILE="$ONEBOX_DIR/onebox.conf" SB_CONF="$ONEBOX_DIR/sing-box.json" XR_CONF="$ONEBOX_DIR/xray.json"
	CLIENT_DIR="$ONEBOX_DIR/client"
	CERT_TXN_BAK='' SITE_TXN_BAK=''
	PROTOCOLS=shadowsocks INIT=none
	pset CORE shadowsocks singbox
	pset PORT shadowsocks 8388
	save_state || return 1
	mkdir -p "$CLIENT_DIR"
	printf 'old-server' >"$SB_CONF"
	printf 'old-client' >"$CLIENT_DIR/links.txt"
	command cp "$STATE_FILE" "$ONEBOX_DIR/expected-state"
	pset PORT shadowsocks 8488
}

mock_apply() {
	FIRED=0 SERVICE_CALLS=0
	prepare_site_and_renewal() { return 0; }
	prepare_server_configs() { printf 'new-server' >"${SB_CONF%.json}.new.json"; }
	own_ip_cidrs() { printf '%s' '"203.0.113.9/32"'; }
	cert_txn_rollback() { return 0; }
	cert_txn_commit() {
		printf 'commit\n' >>"$ONEBOX_DIR/events"
		[ "$FAULT" != certificate ]
	}
	apply_services() {
		SERVICE_CALLS=$((SERVICE_CALLS + 1))
		if { [ "$FAULT" = service ] || [ "$FAULT" = recovery ]; } && [ "$SERVICE_CALLS" = 1 ]; then return 1; fi
		return 0
	}
	svc_remove() { printf 'remove:%s\n' "$1" >>"$ONEBOX_DIR/events"; }
	fw_apply() {
		printf 'firewall:%s:%s\n' "$1" "$(pget PORT shadowsocks)" >>"$ONEBOX_DIR/events"
		if [ "$FAULT" = firewall ] && [ "$1" = open ] && [ "$(pget PORT shadowsocks)" = 8488 ]; then return 1; fi
		return 0
	}
	hop_rules() { return 0; }
	hop_setup() { [ "$FAULT" != hop ] || [ "$(pget PORT shadowsocks)" = 8388 ]; }
	net_persist() { printf 'net:%s\n' "$1" >>"$ONEBOX_DIR/events"; }
	_none_autostart_del() { printf 'autostart:del\n' >>"$ONEBOX_DIR/events"; }
	write_client_files() {
		mkdir -p "$CLIENT_DIR"
		printf 'new-client' >"$CLIENT_DIR/links.txt"
		printf 'clients\n' >>"$ONEBOX_DIR/events"
		[ "$FAULT" != client ]
	}
	cp() {
		if [ "$FAULT" = snapshot ] && [[ "$*" == *'.rollback.'* ]]; then return 1; fi
		if [ "$FAULT" = recovery ] && [[ "$2" == *'.rollback.'* ]] && [[ "$3" == *'.restore.'* ]]; then return 1; fi
		command cp "$@"
	}
	mv() {
		if [ "$FIRED" = 0 ]; then
			if { [ "$FAULT" = config ] && [[ "$*" == *'.new.json'* ]]; } ||
				{ [ "$FAULT" = state ] && [[ "$*" == *'onebox.conf.tmp.'* ]]; }; then FIRED=1; return 1; fi
		fi
		command mv "$@"
	}
}

failure_restores_all() (
	local FAULT=$1 expected_rc=2 rc
	fixture "$FAULT" || return 1
	mock_apply
	[ "$FAULT" != snapshot ] || expected_rc=1
	apply_all >/dev/null 2>&1
	rc=$?
	[ "$rc" = "$expected_rc" ] &&
		cmp -s "$STATE_FILE" "$ONEBOX_DIR/expected-state" &&
		[ "$(cat "$SB_CONF")" = old-server ] &&
		[ "$(cat "$CLIENT_DIR/links.txt")" = old-client ] || return 1
	if [ "$FAULT" = snapshot ]; then [ ! -f "$ONEBOX_DIR/events" ]; fi
)

for phase in snapshot config state service firewall hop client certificate; do check failure_restores_all "$phase"; done

failed_recovery_keeps_snapshot() (
	local FAULT=recovery rc
	fixture recovery || return 1
	mock_apply
	apply_all >/dev/null 2>&1
	rc=$?
	[ "$rc" = 2 ] || return 1
	local backups=("$ONEBOX_DIR"/.rollback.*/complete)
	[ -f "${backups[0]}" ] && [ -f "${backups[0]%/complete}/onebox.conf" ]
)
check failed_recovery_keeps_snapshot

first_install_failure_leaves_no_broken_state() (
	local FAULT=service rc
	fixture first-install || return 1
	rm -f "$STATE_FILE" "$SB_CONF"
	rm -rf "$CLIENT_DIR"
	mock_apply
	apply_all >/dev/null 2>&1
	rc=$?
	[ "$rc" = 2 ] && [ ! -e "$STATE_FILE" ] && [ ! -e "$SB_CONF" ] && [ ! -e "$CLIENT_DIR" ] &&
		grep -q 'remove:singbox' "$ONEBOX_DIR/events"
)
check first_install_failure_leaves_no_broken_state

first_install_late_failure_cleans_boot_tasks() (
	local CLEANUP_FAULT=$1 FAULT=client rc
	fixture "fresh-boot-$CLEANUP_FAULT" || return 1
	rm -f "$STATE_FILE" "$SB_CONF"
	rm -rf "$CLIENT_DIR"
	mock_apply
	hop_setup() { : >"$ONEBOX_DIR/network-task"; : >"$ONEBOX_DIR/autostart-task"; }
	net_persist() {
		printf 'net:%s\n' "$1" >>"$ONEBOX_DIR/events"
		[ "$CLEANUP_FAULT" != network ] || return 1
		rm -f "$ONEBOX_DIR/network-task"
	}
	_none_autostart_del() {
		printf 'autostart:del\n' >>"$ONEBOX_DIR/events"
		[ "$CLEANUP_FAULT" != autostart ] || return 1
		rm -f "$ONEBOX_DIR/autostart-task"
	}
	apply_all >"$ONEBOX_DIR/result.log" 2>&1
	rc=$?
	[ "$rc" = 2 ] && [ ! -e "$STATE_FILE" ] &&
		grep -q 'net:del' "$ONEBOX_DIR/events" && grep -q 'autostart:del' "$ONEBOX_DIR/events" || return 1
	local backups=("$ONEBOX_DIR"/.rollback.*/complete)
	if [ "$CLEANUP_FAULT" = none ]; then
		[ ! -e "$ONEBOX_DIR/network-task" ] && [ ! -e "$ONEBOX_DIR/autostart-task" ] && [ ! -f "${backups[0]}" ]
	else
		[ -f "${backups[0]}" ] && grep -q '已保留原始文件备份' "$ONEBOX_DIR/result.log"
	fi
)
for cleanup in none network autostart; do check first_install_late_failure_cleans_boot_tasks "$cleanup"; done

commit_is_last() (
	local FAULT=none
	fixture success || return 1
	mock_apply
	apply_all >/dev/null 2>&1 || return 1
	[ "$(tail -n 2 "$ONEBOX_DIR/events")" = $'clients\ncommit' ] &&
		[ "$(cat "$CLIENT_DIR/links.txt")" = new-client ]
)
check commit_is_last

invalid_state_is_rejected() (
	fixture invalid-state || return 1
	printf '%s\n' "PROTOCOLS='unterminated" >"$STATE_FILE"
	! load_state >/dev/null 2>&1
)
check invalid_state_is_rejected

failed_state_load_is_rejected() (
	fixture failed-state || return 1
	printf '%s\n' 'PROTOCOLS=shadowsocks' 'false' >"$STATE_FILE"
	! load_state >/dev/null 2>&1
)
check failed_state_load_is_rejected

client_generation_failure_preserves_existing() (
	fixture client-generation || return 1
	gen_links() { printf 'new-link'; }
	gen_mihomo() { return 1; }
	gen_singbox_client() { printf '{}'; }
	gen_xray_client() { printf '{}'; }
	if write_client_files >/dev/null 2>&1; then return 1; fi
	[ "$(cat "$CLIENT_DIR/links.txt")" = old-client ]
)
check client_generation_failure_preserves_existing

service_failure_is_reported() (
	fixture service-command || return 1
	require_installed() { return 0; }
	svc_start() { return 1; }
	svc_status_text() { printf 'stopped'; }
	sleep() { :; }
	! do_service start >/dev/null 2>&1
)
check service_failure_is_reported

missing_value_is_rejected() (
	local option=$1
	# 生产脚本不启用 nounset，不能靠测试脚本的 set -u 掩盖缺参校验缺陷。
	! (set +u; parse_install_opts "$option") >/dev/null 2>&1
)
for option in --name --sni --addr --reality-dest --protocols --xray-version; do check missing_value_is_rejected "$option"; done

empty_protocol_list_is_rejected() (
	! (parse_install_opts --protocols ',,,') >/dev/null 2>&1
)
check empty_protocol_list_is_rejected

echo "通过 ${PASS} 项, 失败 ${FAIL} 项"
[ "$FAIL" = 0 ]
