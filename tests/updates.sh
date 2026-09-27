#!/usr/bin/env bash
# 更新失败与中断的回归测试，只使用临时文件和模拟内核。
# shellcheck disable=SC2034
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/.." && pwd)
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
export ONEBOX_SOURCE_ONLY=1 NO_COLOR=1 ONEBOX_DIR="$WORK/etc" ONEBOX_BIN_DIR="$WORK/bin"
# shellcheck source=../onebox.sh
. "$ROOT/onebox.sh"
PASS=0 FAIL=0
check() {
	if "$@"; then PASS=$((PASS + 1)); else FAIL=$((FAIL + 1)); printf '[失败] %s\n' "$*"; fi
}
fixture() {
	ONEBOX_DIR="$WORK/$1/etc" BIN_DIR="$WORK/$1/bin"
	STATE_FILE="$ONEBOX_DIR/onebox.conf" SB_BIN="$BIN_DIR/sing-box" XR_BIN="$BIN_DIR/xray"
	mkdir -p "$BIN_DIR" "$ONEBOX_DIR"
	printf '#!/bin/sh\necho sing-box version old-sb\n' >"$SB_BIN"
	printf '#!/bin/sh\necho Xray old-xr\n' >"$XR_BIN"
	chmod +x "$SB_BIN" "$XR_BIN"
	reset_state
	PROTOCOLS='shadowsocks trojan'
	pset CORE shadowsocks singbox
	pset CORE trojan xray
	require_installed() { :; }
	install_singbox() { printf '#!/bin/sh\necho sing-box version new-sb\n' >"$SB_BIN"; }
	install_xray() { printf '#!/bin/sh\necho Xray new-xr\n' >"$XR_BIN"; }
	ask_yn() { return 1; }
	apply_all() { printf '%s|%s\n' "$(sb_installed_version)" "$(xr_installed_version)" >>"$ONEBOX_DIR/applied"; }
}
core_backup_failure() (
	fixture backup
	cp() { [ "$2" != "$XR_BIN" ] || return 1; command cp "$@"; }
	! do_update_core all >/dev/null 2>&1 &&
		[ "$(sb_installed_version)|$(xr_installed_version)" = 'old-sb|old-xr' ] && [ ! -f "$ONEBOX_DIR/applied" ]
)
core_second_download_failure() (
	fixture download
	install_xray() { return 1; }
	! do_update_core all >/dev/null 2>&1 && [ "$(sb_installed_version)|$(xr_installed_version)" = 'old-sb|old-xr' ]
)
core_installer_exit() (
	fixture exited
	install_xray() { exit 1; }
	! do_update_core all >/dev/null 2>&1 && [ "$(sb_installed_version)|$(xr_installed_version)" = 'old-sb|old-xr' ]
)
core_apply_failure() (
	fixture apply
	apply_all() {
		printf '%s|%s\n' "$(sb_installed_version)" "$(xr_installed_version)" >>"$ONEBOX_DIR/applied"
		[ "$(sb_installed_version)" = old-sb ]
	}
	! do_update_core all >/dev/null 2>&1 && [ "$(tail -n1 "$ONEBOX_DIR/applied")" = 'old-sb|old-xr' ]
)
core_restore_failure_keeps_backup() (
	fixture restore
	install_xray() { return 1; }
	mv() { case "$*" in *'.restore'*) return 1 ;; esac; command mv "$@"; }
	! do_update_core all >/dev/null 2>&1 &&
		[ "$(find "${BIN_DIR%/*}" -path '*/.dl.*/singbox' -exec cat {} \; | tail -n1)" = 'echo sing-box version old-sb' ]
)
core_unknown_rejected() (
	fixture unknown
	! do_update_core typo >/dev/null 2>&1 && [ ! -f "$ONEBOX_DIR/applied" ]
)
core_success() (
	fixture success
	printf 'unrelated backup\n' >"$SB_BIN.bak"
	do_update_core singbox >/dev/null 2>&1 &&
		[ "$(sb_installed_version)|$(xr_installed_version)" = 'new-sb|old-xr' ] &&
		[ "$(cat "$SB_BIN.bak")" = 'unrelated backup' ] && [ "$(cat "$ONEBOX_DIR/applied")" = 'new-sb|old-xr' ]
)
script_fixture() {
	CMD_PATH="$WORK/script-$1/onebox"
	mkdir -p "${CMD_PATH%/*}"
	printf '#!/usr/bin/env bash\n# Sing-Xray-Onebox\nreadonly SCRIPT_VERSION="old"\nexit 0\n' >"$CMD_PATH"
	cp "$CMD_PATH" "${CMD_PATH}.original"
	chmod +x "$CMD_PATH"
	is_installed() { return 0; }
	http_get() { printf '#!/usr/bin/env bash\n# Sing-Xray-Onebox\nreadonly SCRIPT_VERSION="new"\nexit %s\n' "${NEW_SCRIPT_RC:-0}" >"$2"; }
}
script_apply_failure() (
	script_fixture apply
	NEW_SCRIPT_RC=1
	! do_update_script >/dev/null 2>&1 && cmp -s "$CMD_PATH" "${CMD_PATH}.original"
)
script_replace_failure() (
	script_fixture replace
	mv() { return 1; }
	! do_update_script >/dev/null 2>&1 && cmp -s "$CMD_PATH" "${CMD_PATH}.original"
)
script_replace_interrupted() (
	script_fixture interrupted
	mv() { command mv "$@" || return; kill -TERM "$BASHPID"; }
	! do_update_script >/dev/null 2>&1 && cmp -s "$CMD_PATH" "${CMD_PATH}.original"
)
script_backup_failure() (
	script_fixture backup
	cp() { return 1; }
	! do_update_script >/dev/null 2>&1 && cmp -s "$CMD_PATH" "${CMD_PATH}.original"
)
script_invalid_download() (
	script_fixture invalid
	http_get() { printf 'not a script\n' >"$2"; }
	! do_update_script >/dev/null 2>&1 && cmp -s "$CMD_PATH" "${CMD_PATH}.original"
)
script_success() (
	script_fixture success
	do_update_script >/dev/null 2>&1 && grep -q 'SCRIPT_VERSION="new"' "$CMD_PATH"
)
check core_backup_failure
check core_second_download_failure
check core_installer_exit
check core_apply_failure
check core_restore_failure_keeps_backup
check core_unknown_rejected
check core_success
check script_apply_failure
check script_replace_failure
check script_replace_interrupted
check script_backup_failure
check script_invalid_download
check script_success
printf '更新测试：通过 %s 项，失败 %s 项\n' "$PASS" "$FAIL"
[ "$FAIL" = 0 ]
