#!/usr/bin/env bash
# Recovery and renewal ownership regressions. All services, cron and firewall
# operations are mocked; only temporary files are changed.
# shellcheck disable=SC2034
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/.." && pwd)
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
export ONEBOX_SOURCE_ONLY=1 ONEBOX_DIR="$WORK/etc" ONEBOX_SITE_ROOT="$WORK/web" NO_COLOR=1
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
	ONEBOX_DIR="$base/etc" REALITY_SITE_DIR="$base/etc/site" REALITY_SITE_ROOT="$base/web"
	SITE_ACME_HOME="$REALITY_SITE_DIR/acme" TLS_DIR="$ONEBOX_DIR/tls" STATE_FILE="$ONEBOX_DIR/onebox.conf"
	ACME_HOME="$base/acme" ACME_SH="$base/acme/acme.sh" INIT=none
	SITE_TXN_BAK='' CERT_TXN_BAK='' CERT_TXN_ACME_D='' CERT_TXN_NEW_ACME='' CERT_TXN_OLD_ACME=''
	reset_state
	PROTOCOLS=vless-reality REALITY_SITE_ENABLED=1 REALITY_SITE_DOMAIN=site.example.com REALITY_SITE_PORT=18443
	pset CORE vless-reality singbox
	pset PORT vless-reality 443
	mkdir -p "$REALITY_SITE_DIR" "$REALITY_SITE_ROOT" "$TLS_DIR"
	: >"$REALITY_SITE_DIR/.onebox-site-owned"
	: >"$REALITY_SITE_ROOT/.onebox-site-owned"
	printf 'original configuration\n' >"$REALITY_SITE_DIR/nginx.conf"
	printf 'original page\n' >"$REALITY_SITE_ROOT/index.html"
	printf 'original certificate\n' >"$TLS_DIR/cert.pem"
	_site_running() { return 1; }
	_site_cron_lines() { :; }
	_site_cron_remove() { :; }
	site_service() { :; }
	fw_rule() { :; }
}

restore_retry() (
	fixture
	_site_txn_begin || exit 1
	local backup=$SITE_TXN_BAK failed=0 rc
	printf 'changed configuration\n' >"$REALITY_SITE_DIR/nginx.conf"
	printf 'changed page\n' >"$REALITY_SITE_ROOT/index.html"
	mv() {
		if [ "$failed" = 0 ] && [ "${*: -1}" = "$REALITY_SITE_ROOT" ]; then failed=1; return 1; fi
		command mv "$@"
	}
	site_rollback >/dev/null 2>&1; rc=$?
	[ "$rc" != 0 ] && [ -f "$backup/site/nginx.conf" ] && [ -f "$backup/root/index.html" ] || exit 1
	site_rollback >/dev/null 2>&1 || exit 1
	[ "$(cat "$REALITY_SITE_DIR/nginx.conf")" = 'original configuration' ] &&
		[ "$(cat "$REALITY_SITE_ROOT/index.html")" = 'original page' ] && [ -z "$SITE_TXN_BAK" ]
)
check '第二个目录恢复失败后重试不丢失已恢复的站点配置' restore_retry

restore_copy_failure() (
	fixture
	_site_txn_begin || exit 1
	local backup=$SITE_TXN_BAK failed=0 rc
	printf 'changed page\n' >"$REALITY_SITE_ROOT/index.html"
	cp() {
		if [ "$failed" = 0 ] && [ "${2:-}" = "$backup/root" ]; then failed=1; return 1; fi
		command cp "$@"
	}
	site_rollback >/dev/null 2>&1; rc=$?
	[ "$rc" != 0 ] && [ "$(cat "$REALITY_SITE_ROOT/index.html")" = 'changed page' ] || exit 1
	site_rollback >/dev/null 2>&1 || exit 1
	[ "$(cat "$REALITY_SITE_ROOT/index.html")" = 'original page' ]
)
check '恢复暂存复制失败时保留当前页面及完整备份' restore_copy_failure

restore_restart_failure() (
	fixture
	_site_running() { return 0; }
	_site_txn_begin || exit 1
	local fail_start=1 backup=$SITE_TXN_BAK rc
	site_service() { [ "$1" != start ] || [ "$fail_start" = 0 ]; }
	site_rollback >/dev/null 2>&1; rc=$?
	[ "$rc" != 0 ] && [ -d "$backup/site" ] && [ -d "$backup/root" ] || exit 1
	fail_start=0
	site_rollback >/dev/null 2>&1 && [ -z "$SITE_TXN_BAK" ]
)
check '恢复后启动失败会保留可重试的站点备份' restore_restart_failure

certificate_waits_for_site() (
	fixture
	cert_txn_begin || exit 1
	local backup=$CERT_TXN_BAK rc
	printf 'changed certificate\n' >"$TLS_DIR/cert.pem"
	site_rollback() { return 1; }
	cert_txn_rollback >/dev/null 2>&1; rc=$?
	[ "$rc" != 0 ] && [ -d "$backup" ] && [ "$(cat "$TLS_DIR/cert.pem")" = 'changed certificate' ] || exit 1
	site_rollback() { return 0; }
	cert_txn_rollback >/dev/null 2>&1 || exit 1
	[ "$(cat "$TLS_DIR/cert.pem")" = 'original certificate' ]
)
check '证书回滚不会吞掉网站恢复失败或提前消耗证书备份' certificate_waits_for_site

commit_preserves_signal_guard() (
	fixture
	_site_txn_begin || exit 1
	trap '' INT TERM HUP
	site_commit || exit 1
	[ "$(trap -p INT)" = "trap -- '' SIGINT" ] &&
		[ "$(trap -p TERM)" = "trap -- '' SIGTERM" ] && [ -z "$SITE_TXN_BAK" ]
)
check '网站提交不提前解除外层配置事务的信号保护' commit_preserves_signal_guard

cron_fixture() {
	local base
	base=$(mktemp -d "$WORK/cron.XXXXXX")
	ONEBOX_DIR="$base/etc" REALITY_SITE_DIR="$base/etc/site" SITE_ACME_HOME="$base/etc/site/acme" INIT=none
	CRON_FILE="$base/crontab"
	CRON_READ_FAILURE=0 CRON_WRITES=0
	_site_scheduler_ready() { return 0; }
	has() { if [ "$1" = crontab ]; then return 0; fi; command -v "$1" >/dev/null 2>&1; }
	crontab() {
		case "$1" in
		-l)
			if [ "$CRON_READ_FAILURE" = 1 ]; then printf 'crontab: Permission denied\n' >&2; return 1; fi
			if [ ! -f "$CRON_FILE" ]; then printf 'no crontab for root\n' >&2; return 1; fi
			cat "$CRON_FILE"
			;;
		-) CRON_WRITES=$((CRON_WRITES + 1)); cat >"$CRON_FILE" ;;
		*) return 1 ;;
		esac
	}
}

cron_ownership() (
	cron_fixture
	cat >"$CRON_FILE" <<EOF
@reboot /usr/local/bin/onebox start
5 2 * * * cp ${SITE_ACME_HOME}/account.conf /backup/account.conf
6 2 * * * tar -czf /backup/acme.tar.gz ${SITE_ACME_HOME}/
0 3 * * * "${SITE_ACME_HOME}/acme.sh" --cron --home "${SITE_ACME_HOME}"
@reboot nginx -p "${REALITY_SITE_DIR}/" # onebox-site-autostart
EOF
	_site_cron_enable || exit 1
	[ "$(grep -c '^@reboot ' "$CRON_FILE")" = 1 ] && grep -q 'onebox start' "$CRON_FILE" || exit 1
	! grep -q 'onebox-site-autostart' "$CRON_FILE" || exit 1
	grep -q '/backup/account.conf' "$CRON_FILE" && grep -q '/backup/acme.tar.gz' "$CRON_FILE" || exit 1
	[ "$(_site_cron_lines | wc -l)" -eq 1 ] || exit 1
	_site_cron_remove || exit 1
	! grep -q -- '--cron' "$CRON_FILE" && grep -q '/backup/account.conf' "$CRON_FILE" && grep -q '/backup/acme.tar.gz' "$CRON_FILE"
)
check '仅维护网站续期任务，保留独立备份且不产生双重开机启动' cron_ownership

cron_read_failure() (
	cron_fixture
	printf '5 2 * * * unrelated-backup\n' >"$CRON_FILE"
	CRON_READ_FAILURE=1
	local rc
	_site_cron_enable >/dev/null 2>&1; rc=$?
	[ "$rc" != 0 ] && [ "$(cat "$CRON_FILE")" = '5 2 * * * unrelated-backup' ] || exit 1
	_site_cron_remove >/dev/null 2>&1; rc=$?
	[ "$rc" != 0 ] && [ "$(cat "$CRON_FILE")" = '5 2 * * * unrelated-backup' ]
)
check '读取crontab失败不会覆盖或宣称已移除现有任务' cron_read_failure

cron_initial_absence() (
	cron_fixture
	_site_cron_enable || exit 1
	grep -q -- '--cron' "$CRON_FILE" && ! grep -q '^@reboot ' "$CRON_FILE"
)
check '首次没有crontab时仍可安装网站续期任务' cron_initial_absence

cron_snapshot_failure() (
	fixture
	local rc
	_site_cron_lines() { return 1; }
	_site_txn_begin >/dev/null 2>&1; rc=$?
	[ "$rc" != 0 ] && [ -z "$SITE_TXN_BAK" ] && [ "$(cat "$REALITY_SITE_ROOT/index.html")" = 'original page' ]
)
check '无法备份现有cron时不启动不完整的网站事务' cron_snapshot_failure

disable_unit_failure() (
	fixture
	local fixture_unit="$ONEBOX_DIR/site.service" rc
	: >"$fixture_unit"
	_site_unit_path() { printf '%s' "$fixture_unit"; }
	INIT=systemd
	systemctl() { return 1; }
	_site_disable_unit >/dev/null 2>&1; rc=$?
	[ "$rc" != 0 ] || exit 1
	SITE_TXN_BAK=$(mktemp -d "$ONEBOX_DIR/backup.XXXXXX")
	REALITY_SITE_ENABLED=0
	site_service() { return 0; }
	site_commit >/dev/null 2>&1; rc=$?
	[ "$rc" != 0 ] && [ -d "$SITE_TXN_BAK" ] && [ ! -f "$REALITY_SITE_DIR/.disabled" ]
)
check '禁用系统服务失败不会报告网站已成功停用' disable_unit_failure

acme_fixture() {
	fixture
	TLS_MODE=acme ACME_METHOD=standalone DOMAIN=old.example.com
	mkdir -p "$ACME_HOME/${DOMAIN}_ecc"
	printf "Le_Webroot='no'\n" >"$ACME_HOME/${DOMAIN}_ecc/${DOMAIN}.conf"
	printf "SAVED_CF_Token='original'\n" >"$ACME_HOME/account.conf"
	printf '#!/bin/sh\nexit 0\n' >"$ACME_SH"
	chmod 700 "$ACME_SH"
	save_state
	write_client_files() { return 0; }
	all_cores_do() { return 0; }
}

old_renewal_remove_failure() (
	acme_fixture
	cert_txn_begin || exit 1
	local backup=$CERT_TXN_BAK rc committed=0
	TLS_MODE=self
	acme() { return 1; }
	site_commit() { committed=1; return 0; }
	cert_txn_commit >/dev/null 2>&1; rc=$?
	[ "$rc" != 0 ] && [ "$committed" = 0 ] && [ -d "$backup" ] &&
		[ -f "$ONEBOX_DIR/.acme-old.rollback/old.example.com.conf" ]
)
check '旧域名续期取消失败时不提交网站或删除证书备份' old_renewal_remove_failure

old_renewal_remove_then_site_failure() (
	acme_fixture
	cert_txn_begin || exit 1
	TLS_MODE=self
	acme() { [ "$1" = --remove ] && mv "$ACME_HOME/old.example.com_ecc/old.example.com.conf" "$ACME_HOME/old.example.com_ecc/old.example.com.conf.removed"; }
	site_commit() { return 1; }
	local rc
	cert_txn_commit >/dev/null 2>&1; rc=$?
	[ "$rc" != 0 ] && [ ! -f "$ACME_HOME/old.example.com_ecc/old.example.com.conf" ] || exit 1
	cert_txn_rollback >/dev/null 2>&1 || exit 1
	[ "$(cat "$ACME_HOME/old.example.com_ecc/old.example.com.conf")" = "Le_Webroot='no'" ] && [ -z "$CERT_TXN_BAK" ]
)
check '旧续期取消成功而网站提交失败时能恢复旧域名部署' old_renewal_remove_then_site_failure

acme_restore_retry() (
	acme_fixture
	cert_txn_begin || exit 1
	local backup=$CERT_TXN_BAK failed=0 rc
	cp -a "$ACME_HOME/old.example.com_ecc" "$ONEBOX_DIR/.acme-rollback"
	CERT_TXN_ACME_D=old.example.com
	printf 'changed deployment\n' >"$ACME_HOME/old.example.com_ecc/old.example.com.conf"
	printf 'changed account\n' >"$ACME_HOME/account.conf"
	printf 'changed certificate\n' >"$TLS_DIR/cert.pem"
	mv() {
		if [ "$failed" = 0 ] && [ "${3:-}" = "$ACME_HOME/account.conf" ]; then failed=1; return 1; fi
		command mv "$@"
	}
	cert_txn_rollback >/dev/null 2>&1; rc=$?
	[ "$rc" != 0 ] && [ -d "$backup" ] && [ -d "$ONEBOX_DIR/.acme-rollback" ] && [ "$CERT_TXN_ACME_D" = old.example.com ] || exit 1
	cert_txn_rollback >/dev/null 2>&1 || exit 1
	[ "$(cat "$ACME_HOME/old.example.com_ecc/old.example.com.conf")" = "Le_Webroot='no'" ] &&
		[ "$(cat "$ACME_HOME/account.conf")" = "SAVED_CF_Token='original'" ] &&
		[ "$(cat "$TLS_DIR/cert.pem")" = 'original certificate' ] && [ -z "$CERT_TXN_BAK" ]
)
check 'ACME部署已恢复但账户替换失败后重试不消耗任一备份' acme_restore_retry

certificate_client_failure() (
	acme_fixture
	cert_txn_begin || exit 1
	local backup=$CERT_TXN_BAK rc
	write_client_files() { return 1; }
	cert_txn_rollback >/dev/null 2>&1; rc=$?
	[ "$rc" != 0 ] && [ -d "$backup" ] || exit 1
	write_client_files() { return 0; }
	cert_txn_rollback >/dev/null 2>&1 && [ -z "$CERT_TXN_BAK" ]
)
check '客户端恢复失败会保留证书事务供重试' certificate_client_failure

certificate_restart_failure() (
	acme_fixture
	cert_txn_begin || exit 1
	local backup=$CERT_TXN_BAK rc
	all_cores_do() { return 1; }
	cert_txn_rollback >/dev/null 2>&1; rc=$?
	[ "$rc" != 0 ] && [ -d "$backup" ] || exit 1
	all_cores_do() { return 0; }
	cert_txn_rollback >/dev/null 2>&1 && [ -z "$CERT_TXN_BAK" ]
)
check '内核重启失败会保留证书事务供重试' certificate_restart_failure

certificate_files_only() (
	acme_fixture
	cp "$STATE_FILE" "$ONEBOX_DIR/expected-state"
	cert_txn_begin || exit 1
	write_client_files() { printf 'unexpected\n' >"$ONEBOX_DIR/client-called"; return 1; }
	all_cores_do() { printf 'unexpected\n' >"$ONEBOX_DIR/restart-called"; return 1; }
	cert_txn_rollback --files-only >/dev/null 2>&1 || exit 1
	[ ! -e "$ONEBOX_DIR/client-called" ] && [ ! -e "$ONEBOX_DIR/restart-called" ] &&
		cmp -s "$STATE_FILE" "$ONEBOX_DIR/expected-state" && [ -z "$CERT_TXN_BAK" ]
)
check '外层应用事务可只恢复证书文件且不重写状态或客户端' certificate_files_only

certificate_account_absence() (
	fixture
	cert_txn_begin || exit 1
	mkdir -p "$ACME_HOME"
	printf "SAVED_CF_Token='new failed attempt'\n" >"$ACME_HOME/account.conf"
	cert_txn_rollback >/dev/null 2>&1 && [ ! -f "$ACME_HOME/account.conf" ]
)
check '原来无ACME账户配置时撤销失败申请新增的凭据' certificate_account_absence

printf '通过 %s 项, 失败 %s 项\n' "$PASS" "$FAIL"
[ "$FAIL" = 0 ]
