#!/usr/bin/env bash
# Channel resolution is read-only; all network responses and files are fixtures.
# shellcheck disable=SC2034
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/.." && pwd)
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
export ONEBOX_SOURCE_ONLY=1 NO_COLOR=1 ONEBOX_DIR="$WORK/etc"
# shellcheck source=../onebox.sh
. "${ONEBOX_TEST_SCRIPT:-$ROOT/onebox.sh}"
PASS=0 FAIL=0
check() {
	if "$@"; then PASS=$((PASS + 1)); else FAIL=$((FAIL + 1)); printf '[失败] %s\n' "$*"; fi
}
fixture() {
	ONEBOX_DIR="$WORK/$1" CMD_PATH="$WORK/$1/onebox"
	mkdir -p "$ONEBOX_DIR"
	unset ONEBOX_SCRIPT_URL
	GH_PROXY=""
	API_MODE=release SCRIPT_FIXTURE_VERSION=1.3.0
	API_BODY='{"tag_name":"v1.3.0","draft":false,"prerelease":false,"body":"修复更新。\n保留现有节点。","assets":[{"tag_name":"v9.9.9"}]}'
	BRANCH_BODY='{"default_branch":"claude/linux-vps-proxy-script-1m1ksn"}'
	API_CALLS="$ONEBOX_DIR/api-calls"
	_update_api_fetch() {
		printf '%s\n' "$1" >>"$API_CALLS"
		case "$1" in
		*/releases/latest)
			case "$API_MODE" in unavailable) return 1 ;; missing) return 2 ;; esac
			printf '%s\n' "$API_BODY" >"$2"
			;;
		"https://api.github.com/repos/$SCRIPT_REPO")
			[ "$API_MODE" != missing-repo ] || return 2
			printf '%s\n' "$BRANCH_BODY" >"$2"
			;;
		*) return 1 ;;
		esac
	}
	http_get() {
		printf '%s\n' "$1" >"$ONEBOX_DIR/download-url"
		printf '#!/usr/bin/env bash\n# Sing-Xray-Onebox\nreadonly SCRIPT_VERSION="%s"\nprintf executed >"%s"\n' "$SCRIPT_FIXTURE_VERSION" "$ONEBOX_DIR/executed" >"$2"
	}
}
default_channel() (
	fixture default
	[ "$(update_channel_get)" = stable ] && [ ! -e "$(update_channel_file)" ]
)
channel_persists_outside_state() (
	fixture channel
	do_update_channel testing >/dev/null || return 1
	reset_state
	[ "$(update_channel_get)" = testing ] && [ "$(stat -c '%a' "$(update_channel_file)")" = 600 ] && [ ! -e "$ONEBOX_DIR/onebox.conf" ]
)
invalid_channel_keeps_preference() (
	fixture invalid-channel
	do_update_channel testing >/dev/null
	! do_update_channel beta >/dev/null 2>&1 && [ "$(update_channel_get)" = testing ]
)
bad_saved_channel_rejected() (
	fixture invalid-saved
	printf 'stable\nmalicious\n' >"$(update_channel_file)"
	! script_update_resolve >/dev/null 2>&1
)
channel_write_failure_keeps_preference() (
	fixture failed-write
	do_update_channel testing >/dev/null
	mv() { return 1; }
	! do_update_channel stable >/dev/null 2>&1 && [ "$(update_channel_get)" = testing ]
)
channel_symlink_target_rejected() (
	fixture channel-link
	mkdir "$ONEBOX_DIR/foreign"
	ln -s "$ONEBOX_DIR/foreign" "$(update_channel_file)"
	! do_update_channel stable >/dev/null 2>&1 && [ -z "$(ls -A "$ONEBOX_DIR/foreign")" ]
)
stable_uses_validated_tag() (
	fixture stable
	script_update_resolve || return 1
	[ "$UPDATE_SOURCE" = release ] && [ "$UPDATE_RELEASE_VERSION" = 1.3.0 ] &&
		[ "$UPDATE_URL" = "https://raw.githubusercontent.com/$SCRIPT_REPO/refs/tags/v1.3.0/onebox.sh" ] &&
		[ "$UPDATE_SUMMARY" = $'修复更新。\n保留现有节点。' ]
)
testing_uses_default_branch() (
	fixture testing
	script_update_resolve testing || return 1
	[ "$UPDATE_URL" = "https://raw.githubusercontent.com/$SCRIPT_REPO/refs/heads/claude/linux-vps-proxy-script-1m1ksn/onebox.sh" ] &&
		[ "$(wc -l <"$API_CALLS")" = 1 ] && [ "$(update_channel_get)" = stable ]
)
missing_release_warns_and_keeps_stable() (
	fixture fallback
	API_MODE=missing
	script_update_resolve >"$ONEBOX_DIR/out" 2>&1 || return 1
	[ "$UPDATE_CHANNEL" = stable ] && [ "$UPDATE_SOURCE" = branch-fallback ] &&
		grep -q '尚无正式 Release' "$ONEBOX_DIR/out" && [ "$(wc -l <"$API_CALLS")" = 2 ]
)
api_failure_does_not_fallback() (
	fixture unavailable
	API_MODE=unavailable
	! script_update_resolve >/dev/null 2>&1 && [ "$(wc -l <"$API_CALLS")" = 1 ] && [ -z "$UPDATE_URL" ]
)
missing_repo_not_no_release() (
	fixture missing-repo
	_update_api_fetch() { return 2; }
	! script_update_resolve >/dev/null 2>&1 && [ -z "$UPDATE_URL" ]
)
invalid_tag_rejected() (
	fixture invalid-tag
	API_BODY='{"tag_name":"../../evil","draft":false,"prerelease":false}'
	! script_update_resolve >/dev/null 2>&1 && [ -z "$UPDATE_URL" ]
)
prerelease_rejected() (
	fixture prerelease
	API_BODY='{"tag_name":"v1.3.0","draft":false,"prerelease":true}'
	! script_update_resolve >/dev/null 2>&1
)
invalid_branch_rejected() (
	fixture invalid-branch
	BRANCH_BODY='{"default_branch":"main/../../evil"}'
	! script_update_resolve testing >/dev/null 2>&1
)
override_skips_api() (
	fixture override
	ONEBOX_SCRIPT_URL=https://example.test/my-onebox.sh
	script_update_resolve || return 1
	[ "$UPDATE_SOURCE" = custom ] && [ "$UPDATE_URL" = "$ONEBOX_SCRIPT_URL" ] && [ ! -f "$API_CALLS" ]
)
invalid_override_rejected() (
	fixture invalid-override
	ONEBOX_SCRIPT_URL='file:///tmp/script'
	! script_update_resolve >/dev/null 2>&1 && [ ! -f "$API_CALLS" ]
)
tag_script_mismatch_rejected() (
	fixture mismatch
	SCRIPT_FIXTURE_VERSION=1.2.0
	! script_update_download "$ONEBOX_DIR/new" >/dev/null 2>&1 && [ ! -e "$ONEBOX_DIR/executed" ]
)
download_never_executes() (
	fixture no-execution
	script_update_download "$ONEBOX_DIR/new" >/dev/null || return 1
	[ "$UPDATE_REMOTE_VERSION" = 1.3.0 ] && [ ! -e "$ONEBOX_DIR/executed" ]
)
uninstalled_check_is_read_only() (
	fixture uninstalled
	do_update_check >"$ONEBOX_DIR/out" 2>&1 || return 1
	grep -q '未安装' "$ONEBOX_DIR/out" && grep -q '1.3.0' "$ONEBOX_DIR/out" &&
		[ ! -f "$CMD_PATH" ] && [ ! -f "$(update_channel_file)" ] && [ ! -e "$ONEBOX_DIR/executed" ]
)
check_reports_older_release() (
	fixture newer-installed
	printf '#!/usr/bin/env bash\n# Sing-Xray-Onebox\nreadonly SCRIPT_VERSION="1.4.0"\n' >"$CMD_PATH"
	do_update_check >"$ONEBOX_DIR/out" 2>&1 || return 1
	grep -q '拒绝降级' "$ONEBOX_DIR/out" && [ "$(script_file_version "$CMD_PATH")" = 1.4.0 ]
)
json_nested_key_not_used() (
	fixture nested
	printf '%s' '{"assets":[{"tag_name":"v9.9.9"}],"tag_name":"v1.3.0"}' >"$ONEBOX_DIR/json"
	[ "$(_update_json_field "$ONEBOX_DIR/json" tag_name)" = v1.3.0 ]
)
json_duplicate_key_rejected() (
	fixture duplicate
	printf '%s' '{"tag_name":"v1.3.0","tag_name":"v9.9.9"}' >"$ONEBOX_DIR/json"
	! _update_json_field "$ONEBOX_DIR/json" tag_name >/dev/null 2>&1
)
json_truncated_document_rejected() (
	fixture truncated
	printf '%s' '{"tag_name":"v1.3.0"' >"$ONEBOX_DIR/json"
	! _update_json_field "$ONEBOX_DIR/json" tag_name >/dev/null 2>&1
)
summary_is_data_and_bounded() (
	fixture summary
	UPDATE_SUMMARY='$(touch /tmp/onebox-release-summary-must-not-execute)'
	UPDATE_SUMMARY+=$'\n\033[31mnot a terminal command\r'
	UPDATE_SUMMARY+=$(printf '\nline %s' {1..20})
	script_update_summary >"$ONEBOX_DIR/out"
	grep -qF '$(touch /tmp/onebox-release-summary-must-not-execute)' "$ONEBOX_DIR/out" &&
		! grep -q $'\033' "$ONEBOX_DIR/out" && [ "$(wc -l <"$ONEBOX_DIR/out")" -le 14 ]
)
api_status_is_classified() (
	local fixture_http_status=$1 transport_rc=$2 expected=$3 rc
	GH_PROXY=""
	has() { [ "$1" = curl ]; }
	curl() { printf '%s' "$fixture_http_status"; return "$transport_rc"; }
	_update_api_fetch "https://api.github.com/repos/$SCRIPT_REPO/releases/latest" "$WORK/unused-body" >/dev/null 2>&1
	rc=$?
	[ "$rc" = "$expected" ]
)
api_wget_404_is_classified() (
	GH_PROXY=""
	has() { return 1; }
	wget() { printf '  HTTP/1.1 404 Not Found\n' >&2; return 8; }
	_update_api_fetch "https://api.github.com/repos/$SCRIPT_REPO/releases/latest" "$WORK/unused-body" >/dev/null 2>&1
	[ "$?" = 2 ]
)
api_uses_explicit_proxy_after_failure() (
	local calls="$WORK/proxy-api-calls"
	GH_PROXY=https://proxy.example.test/
	has() { [ "$1" = curl ]; }
	curl() {
		local fixture_url=${*: -1}
		printf '%s\n' "$fixture_url" >>"$calls"
		case "$fixture_url" in https://api.github.com/*) printf 503 ;; https://proxy.example.test/https://api.github.com/*) printf 200 ;; *) return 1 ;; esac
	}
	_update_api_fetch "https://api.github.com/repos/$SCRIPT_REPO/releases/latest" "$WORK/unused-body" >/dev/null 2>&1 &&
		[ "$(wc -l <"$calls")" = 2 ]
)

for test in channel_symlink_target_rejected default_channel channel_persists_outside_state invalid_channel_keeps_preference bad_saved_channel_rejected \
	channel_write_failure_keeps_preference stable_uses_validated_tag testing_uses_default_branch \
	missing_release_warns_and_keeps_stable api_failure_does_not_fallback missing_repo_not_no_release invalid_tag_rejected \
	prerelease_rejected invalid_branch_rejected override_skips_api invalid_override_rejected tag_script_mismatch_rejected \
	download_never_executes uninstalled_check_is_read_only check_reports_older_release json_nested_key_not_used \
	json_duplicate_key_rejected json_truncated_document_rejected summary_is_data_and_bounded; do
	check "$test"
done
check api_status_is_classified 200 0 0
check api_status_is_classified 404 0 2
check api_status_is_classified 403 0 1
check api_status_is_classified 500 0 1
check api_status_is_classified 000 7 1
check api_wget_404_is_classified
check api_uses_explicit_proxy_after_failure
printf '发布渠道测试：通过 %s 项，失败 %s 项\n' "$PASS" "$FAIL"
[ "$FAIL" = 0 ]
