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
write_script_fixture() {
	local path=$1 version=$2 rc=${3:-0}
	cat >"$path" <<EOF
#!/usr/bin/env bash
# Sing-Xray-Onebox
readonly SCRIPT_VERSION="${version}"
if [ "\${1:-}" = regen ]; then printf '%s\\n' called >>"$SCRIPT_REGEN_LOG"; fi
exit $rc
EOF
}
script_fixture() {
	ONEBOX_SCRIPT_URL=https://example.test/onebox.sh
	CMD_PATH="$WORK/script-$1/onebox"
	SCRIPT_REGEN_LOG="${CMD_PATH}.regen-calls"
	mkdir -p "${CMD_PATH%/*}"
	write_script_fixture "$CMD_PATH" 1.1.0
	cp "$CMD_PATH" "${CMD_PATH}.original"
	chmod +x "$CMD_PATH"
	is_installed() { return 0; }
	http_get() { write_script_fixture "$2" "${NEW_SCRIPT_VERSION:-1.2.1}" "${NEW_SCRIPT_RC:-0}"; }
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
	do_update_script >/dev/null 2>&1 && grep -q 'SCRIPT_VERSION="1.2.1"' "$CMD_PATH" &&
		[ "$(cat "$SCRIPT_REGEN_LOG")" = called ]
)
script_downgrade_rejected() (
	script_fixture downgrade
	NEW_SCRIPT_VERSION=1.0.0
	! do_update_script >/dev/null 2>&1 && cmp -s "$CMD_PATH" "${CMD_PATH}.original" && [ ! -e "$SCRIPT_REGEN_LOG" ]
)
script_missing_version_rejected() (
	script_fixture missing-version
	http_get() { printf '#!/usr/bin/env bash\n# Sing-Xray-Onebox\nexit 0\n' >"$2"; }
	! do_update_script >/dev/null 2>&1 && cmp -s "$CMD_PATH" "${CMD_PATH}.original"
)
script_invalid_version_rejected() (
	script_fixture invalid-version
	NEW_SCRIPT_VERSION=nightly
	! do_update_script >/dev/null 2>&1 && cmp -s "$CMD_PATH" "${CMD_PATH}.original"
)
script_identical_skips_regen() (
	script_fixture identical
	http_get() { command cp "$CMD_PATH" "$2"; }
	local out
	out=$(do_update_script 2>&1) && [ ! -e "$SCRIPT_REGEN_LOG" ] &&
		cmp -s "$CMD_PATH" "${CMD_PATH}.original" && printf '%s' "$out" | grep -q '最新'
)
script_same_version_changed_content() (
	script_fixture same-version
	http_get() { write_script_fixture "$2" 1.1.0; printf '# same-version improvement\n' >>"$2"; }
	do_update_script >/dev/null 2>&1 && grep -q 'same-version improvement' "$CMD_PATH" &&
		[ "$(cat "$SCRIPT_REGEN_LOG")" = called ]
)
script_compares_installed_version() (
	script_fixture installed-newer
	write_script_fixture "$CMD_PATH" 2.0.0
	command cp "$CMD_PATH" "${CMD_PATH}.original"
	NEW_SCRIPT_VERSION=1.9.0
	! do_update_script >/dev/null 2>&1 && cmp -s "$CMD_PATH" "${CMD_PATH}.original" && [ ! -e "$SCRIPT_REGEN_LOG" ]
)
script_running_copy_version_not_used() (
	script_fixture installed-older
	write_script_fixture "$CMD_PATH" 0.9.0
	NEW_SCRIPT_VERSION=1.0.0
	do_update_script >/dev/null 2>&1 && grep -q 'SCRIPT_VERSION="1.0.0"' "$CMD_PATH"
)
script_download_failure_not_success() (
	script_fixture download-error
	http_get() { printf 'incomplete response\n' >"$2"; return 1; }
	local out rc
	out=$(do_update_script 2>&1)
	rc=$?
	[ "$rc" != 0 ] && cmp -s "$CMD_PATH" "${CMD_PATH}.original" && [ ! -e "$SCRIPT_REGEN_LOG" ] &&
		! printf '%s' "$out" | grep -q '脚本已更新'
)
script_real_main_regen_failure() (
	script_fixture real-main
	# 使用与生产相同的入口保护, 并确保子进程真正执行 main / regen。
	unset ONEBOX_SOURCE_ONLY
	http_get() {
		cat >"$2" <<EOF
#!/usr/bin/env bash
# Sing-Xray-Onebox
readonly SCRIPT_VERSION="1.2.1"
main() {
    [ "\${1:-}" = regen ] || return 2
    printf '%s\\n' new-regen >>"$SCRIPT_REGEN_LOG"
    return 42
}
[ -n "\${ONEBOX_SOURCE_ONLY:-}" ] || main "\$@"
EOF
	}
	! do_update_script >/dev/null 2>&1 && cmp -s "$CMD_PATH" "${CMD_PATH}.original" &&
		[ "$(cat "$SCRIPT_REGEN_LOG")" = $'new-regen\ncalled' ]
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
check script_downgrade_rejected
check script_missing_version_rejected
check script_invalid_version_rejected
check script_identical_skips_regen
check script_same_version_changed_content
check script_compares_installed_version
check script_running_copy_version_not_used
check script_download_failure_not_success
check script_real_main_regen_failure
printf '更新测试：通过 %s 项，失败 %s 项\n' "$PASS" "$FAIL"
[ "$FAIL" = 0 ]
