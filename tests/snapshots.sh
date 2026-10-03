#!/usr/bin/env bash
# Persistent snapshot regressions: no service, network or system mutations.
# shellcheck disable=SC2034
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/.." && pwd)
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
export ONEBOX_SOURCE_ONLY=1 ONEBOX_DIR="$WORK/default" ONEBOX_SITE_ROOT="$WORK/default-public" NO_COLOR=1
# shellcheck source=../onebox.sh
. "$ROOT/onebox.sh"

PASS=0 FAIL=0
check() {
	local label=$1
	shift
	if "$@"; then PASS=$((PASS + 1)); else FAIL=$((FAIL + 1)); printf '  [失败] %s\n' "$label"; fi
}

fixture() {
	local base
	base=$(mktemp -d "$WORK/case.XXXXXX")
	ONEBOX_DIR="$base/etc" STATE_FILE="$base/etc/onebox.conf"
	SB_CONF="$ONEBOX_DIR/sing-box.json" XR_CONF="$ONEBOX_DIR/xray.json"
	CLIENT_DIR="$ONEBOX_DIR/client" TLS_DIR="$ONEBOX_DIR/tls"
	REALITY_SITE_DIR="$ONEBOX_DIR/site" REALITY_SITE_ROOT="$base/public"
	SITE_ACME_HOME="$REALITY_SITE_DIR/acme" ACME_HOME="$base/acme" ACME_SH="$ACME_HOME/acme.sh"
	CERT_TXN_BAK='' SITE_TXN_BAK='' SNAPSHOT_RESTORE_SOURCE='' INIT=none
	ONEBOX_BACKUP_MAX_BYTES=67108864 FAULT='' SERVICE_CALLS=0
	reset_state
	PROTOCOLS=shadowsocks TLS_MODE=self CLASH_SECRET=secret
	SERVER_ADDR=203.0.113.9 SERVER_IPV4=203.0.113.9
	pset CORE shadowsocks singbox
	pset PORT shadowsocks 8388
	mkdir -p "$CLIENT_DIR" "$TLS_DIR" "$REALITY_SITE_DIR" "$REALITY_SITE_ROOT"
	printf 'old certificate\n' >"$TLS_DIR/cert.pem"
	printf 'old private key\n' >"$TLS_DIR/key.pem"
	printf 'old config\n' >"$SB_CONF"
	printf 'old client\n' >"$CLIENT_DIR/links.txt"
	printf 'old page\n' >"$REALITY_SITE_ROOT/index.html"
	printf 'old settings\n' >"$REALITY_SITE_DIR/content-settings.tsv"
	: >"$REALITY_SITE_DIR/.onebox-site-owned"
	: >"$REALITY_SITE_ROOT/.onebox-site-owned"
	save_state
	# Retain real file transactions and apply_all; mock only external actions.
	_site_running() { return 1; }
	_site_cron_lines() { :; }
	_site_cron_remove() { :; }
	_site_disable_unit() { :; }
	site_service() { :; }
	site_prepare() { :; }
	site_commit() { rm -rf "$SITE_TXN_BAK"; SITE_TXN_BAK=''; }
	fw_rule() { :; }
	fw_apply() { :; }
	_fw_ledger_migrate() { :; }
	hop_rules() { :; }
	hop_setup() { :; }
	prepare_server_configs() {
		printf 'validated\n' >>"$ONEBOX_DIR/events"
		[ "$FAULT" != validation ] || return 1
		printf 'config-port=%s\n' "$(pget PORT shadowsocks)" >"${SB_CONF%.json}.new.json"
	}
	apply_services() {
		SERVICE_CALLS=$((SERVICE_CALLS + 1))
		[ "$FAULT" != service ] || [ "$SERVICE_CALLS" -gt 1 ]
	}
	svc_exists() { return 1; }
	svc_stop() { :; }
	all_cores_do() { :; }
	own_ip_cidrs() { printf '"203.0.113.9/32"'; }
	write_client_files() {
		mkdir -p "$CLIENT_DIR"
		printf 'regenerated client\n' >"$CLIENT_DIR/links.txt"
	}
}

capture_and_restore() (
	fixture
	local id
	id=$(snapshot_create baseline) || return 1
	pset PORT shadowsocks 8488
	save_state
	printf 'new config\n' >"$SB_CONF"
	printf 'new client\n' >"$CLIENT_DIR/links.txt"
	printf 'new certificate\n' >"$TLS_DIR/cert.pem"
	printf 'new page\n' >"$REALITY_SITE_ROOT/index.html"
	do_restore "$id" >/dev/null 2>&1 || return 1
	load_state && [ "$(pget PORT shadowsocks)" = 8388 ] &&
		[ "$(cat "$SB_CONF")" = config-port=8388 ] &&
		[ "$(cat "$CLIENT_DIR/links.txt")" = 'old client' ] &&
		[ "$(cat "$TLS_DIR/cert.pem")" = 'old certificate' ] &&
		[ "$(cat "$REALITY_SITE_ROOT/index.html")" = 'old page' ] &&
		[ "$(cat "$ONEBOX_DIR/events")" = validated ] &&
		[ "$(stat -c %a "$REALITY_SITE_ROOT")" = 755 ] &&
		[ "$(stat -c %a "$TLS_DIR/key.pem")" = 600 ]
)
check '恢复真实状态、证书、页面、客户端，并校验重生成的核心配置' capture_and_restore

reads_disk_state() (
	fixture
	pset PORT shadowsocks 9999
	local id
	id=$(snapshot_create pending) || return 1
	_snapshot_load_state "$(_snapshot_root)/$id/state.dat" && [ "$(pget PORT shadowsocks)" = 8388 ]
)
check '自动备份读取磁盘成功状态而非未应用变量' reads_disk_state

retention_and_modes() (
	fixture
	local i id
	for i in 1 2 3 4 5 6 7; do id=$(snapshot_create "backup $i") || return 1; done
	[ -d "$(_snapshot_root)/$id" ] && [ "$(_snapshot_ids "$(_snapshot_root)" | wc -l)" = 5 ] &&
		[ "$(cat "$(_snapshot_root)/$(_snapshot_ids "$(_snapshot_root)" | tail -n1)/label")" = 'backup 3' ] &&
		[ -z "$(find "$(_snapshot_root)" -type d ! -perm 700 -print -quit)" ] &&
		[ -z "$(find "$(_snapshot_root)" -type f ! -perm 600 -print -quit)" ]
)
check '保留最近五份且目录700文件600，刚创建的快照不会被清理' retention_and_modes

reject_tampering() (
	fixture
	local id
	id=$(snapshot_create original) || return 1
	printf 'tampered\n' >>"$(_snapshot_root)/$id/client/links.txt"
	! do_restore "$id" >/dev/null 2>&1 && [ ! -f "$ONEBOX_DIR/events" ] &&
		[ "$(cat "$TLS_DIR/cert.pem")" = 'old certificate' ]
)
check '任何备份文件篡改在写入或停止服务前被拒绝' reject_tampering

reject_path() (
	fixture
	! do_restore "$1" >/dev/null 2>&1 && [ ! -f "$ONEBOX_DIR/events" ]
)
check '拒绝路径穿越 ID' reject_path ../../tls
check '拒绝绝对路径 ID' reject_path /etc

reject_symlink() (
	fixture
	case "$1" in
		root) ln -s "$WORK" "$ONEBOX_DIR/backups" ;;
		content) ln -s "$TLS_DIR/key.pem" "$REALITY_SITE_ROOT/linked-key" ;;
		tls) mv "$TLS_DIR" "$ONEBOX_DIR/tls-original"; ln -s "$ONEBOX_DIR/tls-original" "$TLS_DIR" ;;
	esac
	! snapshot_create bad >/dev/null 2>&1
)
check '拒绝快照根目录符号链接' reject_symlink root
check '拒绝网页目录内符号链接逃逸' reject_symlink content
check '拒绝受管证书目录符号链接' reject_symlink tls

bounded_size_preserves_previous() (
	fixture
	local id
	id=$(snapshot_create good) || return 1
	ONEBOX_BACKUP_MAX_BYTES=10
	! snapshot_create too-large >/dev/null 2>&1 && [ -d "$(_snapshot_root)/$id" ] &&
		[ "$(_snapshot_ids "$(_snapshot_root)" | wc -l)" = 1 ]
)
check '超限失败保留已有快照且不发布半份备份' bounded_size_preserves_previous

state_is_data() (
	fixture
	local file="$ONEBOX_DIR/data" marker="$ONEBOX_DIR/executed"
	_snapshot_write_state >"$file"
	printf 'NODE_NAME\0$(touch %s)\0' "$marker" >>"$file"
	# Duplicate keys are rejected before decoding; arbitrary keys are also rejected.
	! _snapshot_load_state "$file" >/dev/null 2>&1 && [ ! -e "$marker" ] || return 1
	printf 'PROTOCOLS\0shadowsocks\0CORE_shadowsocks\0singbox\0PORT_shadowsocks\08388\0' >"$file"
	printf 'NODE_NAME\0$(touch %s)\0' "$marker" >>"$file"
	_snapshot_load_state "$file" >/dev/null 2>&1 && [ ! -e "$marker" ]
)
check '状态按白名单数据读取，不执行 shell 语法或重复字段' state_is_data

failure_restores_current() (
	fixture
	local id
	id=$(snapshot_create old) || return 1
	pset PORT shadowsocks 8488
	save_state
	printf 'current certificate\n' >"$TLS_DIR/cert.pem"
	printf 'current page\n' >"$REALITY_SITE_ROOT/index.html"
	printf 'current config\n' >"$SB_CONF"
	printf 'current client\n' >"$CLIENT_DIR/links.txt"
	FAULT=$1
	if do_restore "$id" >/dev/null 2>&1; then return 1; fi
	load_state && [ "$(pget PORT shadowsocks)" = 8488 ] &&
		[ "$(cat "$TLS_DIR/cert.pem")" = 'current certificate' ] &&
		[ "$(cat "$REALITY_SITE_ROOT/index.html")" = 'current page' ] &&
		[ "$(cat "$SB_CONF")" = 'current config' ] &&
		[ "$(cat "$CLIENT_DIR/links.txt")" = 'current client' ]
)
check '核心校验失败恢复当前证书与页面并保留服务端状态' failure_restores_current validation
check '服务启动失败恢复当前状态、客户端、证书和页面' failure_restores_current service

current_backup_required() (
	fixture
	local id
	id=$(snapshot_create old) || return 1
	# Target verification succeeds, but the current website is now too large.
	printf 'new page\n' >"$REALITY_SITE_ROOT/index.html"
	ln -s "$TLS_DIR/key.pem" "$REALITY_SITE_ROOT/unbackupable"
	! do_restore "$id" >/dev/null 2>&1 && [ ! -f "$ONEBOX_DIR/events" ] &&
		[ "$(cat "$REALITY_SITE_ROOT/index.html")" = 'new page' ]
)
check '无法备份当前状态时禁止开始恢复' current_backup_required

exclude_history_and_software() (
	fixture
	mkdir -p "$REALITY_SITE_DIR/content-backups/old" "$SITE_ACME_HOME"
	printf 'history' >"$REALITY_SITE_DIR/content-backups/old/index.html"
	printf 'executable' >"$SITE_ACME_HOME/acme.sh"
	local id
	id=$(snapshot_create bounded) || return 1
	[ -f "$(_snapshot_root)/$id/site/content-settings.tsv" ] &&
		[ ! -e "$(_snapshot_root)/$id/site/acme" ] && [ ! -e "$(_snapshot_root)/$id/site/content-backups" ]
)
check '备份当前网站设置但排除嵌套历史和 ACME 可执行程序' exclude_history_and_software

restore_oldest_retained() (
	fixture
	local id i
	id=$(snapshot_create oldest) || return 1
	for i in 1 2 3 4; do snapshot_create newer >/dev/null || return 1; done
	printf 'current page\n' >"$REALITY_SITE_ROOT/index.html"
	do_restore "$id" >/dev/null 2>&1 && [ "$(cat "$REALITY_SITE_ROOT/index.html")" = 'old page' ]
)
check '恢复最旧快照时，恢复前备份的保留策略不会删除正在读取的数据' restore_oldest_retained

unowned_live_directory_rejected() (
	fixture
	local id
	id=$(snapshot_create old) || return 1
	rm "$REALITY_SITE_ROOT/.onebox-site-owned"
	printf 'foreign content\n' >"$REALITY_SITE_ROOT/index.html"
	! do_restore "$id" >/dev/null 2>&1 && [ "$(cat "$REALITY_SITE_ROOT/index.html")" = 'foreign content' ]
)
check '拒绝覆盖已不归 onebox 管理的公开目录' unowned_live_directory_rejected

external_cert_untouched() (
	fixture
	local id
	TLS_MODE=custom CERT_FILE="$WORK/external-cert" KEY_FILE="$WORK/external-key"
	printf 'external cert\n' >"$CERT_FILE"
	printf 'external key\n' >"$KEY_FILE"
	save_state
	id=$(snapshot_create custom) || return 1
	printf 'renewed external cert\n' >"$CERT_FILE"
	do_restore "$id" >/dev/null 2>&1 && [ "$(cat "$CERT_FILE")" = 'renewed external cert' ] &&
		[ "$(cat "$KEY_FILE")" = 'external key' ]
)
check '自定义外部证书保持引用，不覆盖其他软件续期后的文件' external_cert_untouched

standalone_restore_stops_site() (
	fixture
	TLS_MODE=acme DOMAIN=cert.example.com ACME_METHOD=standalone
	save_state
	local id
	id=$(snapshot_create standalone) || return 1
	TLS_MODE=self PROTOCOLS='shadowsocks vless-reality' REALITY_SITE_ENABLED=1
	REALITY_SITE_DOMAIN=site.example.com REALITY_SITE_PORT=18443
	pset CORE vless-reality singbox
	pset PORT vless-reality 443
	save_state
	MOCK_SITE_RUNNING=1 BOUND=0
	site_service() { if [ "$1" = stop ]; then MOCK_SITE_RUNNING=0; fi; }
	cert_acme() { [ "$MOCK_SITE_RUNNING" = 0 ] || return 1; BOUND=1; }
	do_restore "$id" >/dev/null 2>&1 && [ "$BOUND" = 1 ] && [ "$TLS_MODE" = acme ]
)
check '恢复关闭网站的 standalone ACME 时先释放受管 HTTP80' standalone_restore_stops_site

corrupt_fifo_is_not_read() (
	fixture
	local bad output
	bad="$(_snapshot_root)/20261003T000000Z-abcdef"
	mkdir -p "$bad"
	mkfifo "$bad/order"
	output=$(timeout 3 bash -c "$(declare -f _snapshot_ids _snapshot_id_valid); _snapshot_ids \"\$1\"" _ "$(_snapshot_root)") || return 1
	[ -z "$output" ]
)
check '损坏快照的 FIFO 元数据不会使枚举永久阻塞' corrupt_fifo_is_not_read

snapshot_owns_copied_content() (
	fixture
	local id ownership_log="$ONEBOX_DIR/ownership.log"
	chown() { printf '%s\n' "$*" >>"$ownership_log"; command chown "$@"; }
	id=$(snapshot_create owner) || return 1
	grep -qF -- "-R $(id -u):$(id -g) " "$ownership_log" &&
		[ "$(stat -c %u "$(_snapshot_root)/$id/public/index.html")" = "$(id -u)" ]
)
check '快照复制后归一化文件所有者为执行管理员' snapshot_owns_copied_content

real_core_validation() (
	fixture
	SB_BIN=$ONEBOX_TEST_SINGBOX
	SS_METHOD=2022-blake3-aes-128-gcm SS_PASSWORD=$(gen_ss_password 2022-blake3-aes-128-gcm)
	save_state
	local id
	id=$(snapshot_create real-core) || return 1
	pset PORT shadowsocks 8488
	save_state
	prepare_server_configs() {
		gen_singbox_server >"${SB_CONF%.json}.new.json" && _check_config singbox "${SB_CONF%.json}.new.json"
	}
	do_restore "$id" && grep -q '8388' "$SB_CONF" && _check_config singbox "$SB_CONF"
)
if [ -n "${ONEBOX_TEST_SINGBOX:-}" ]; then check '真实 sing-box 检查恢复的核心配置' real_core_validation; fi

printf '\n快照测试: %s 通过, %s 失败\n' "$PASS" "$FAIL"
[ "$FAIL" = 0 ]
