#!/usr/bin/env bash
# Local support archives and tracked renewal use only temporary paths/mock ACME.
# shellcheck disable=SC2034
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/.." && pwd)
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
export ONEBOX_SOURCE_ONLY=1 NO_COLOR=1 ONEBOX_DIR="$WORK/etc"
# shellcheck source=../onebox.sh
. "$ROOT/onebox.sh"
PASS=0 FAIL=0
check() { if "$@"; then PASS=$((PASS + 1)); else FAIL=$((FAIL + 1)); printf '[FAIL] %s\n' "$*"; fi; }
fixture() {
	ONEBOX_DIR="$WORK/$1" STATE_FILE="$WORK/$1/onebox.conf"
	REALITY_SITE_DIR="$ONEBOX_DIR/site" SITE_ACME_HOME="$REALITY_SITE_DIR/acme"
	ACME_HOME="$ONEBOX_DIR/acme" ACME_SH="$ACME_HOME/acme.sh"
	mkdir -p "$ONEBOX_DIR"
	load_state() { reset_state; UUID=secret-uuid PASSWORD=secret-password REALITY_PRIVATE_KEY=secret-private-key; PROTOCOLS=vless-reality; TLS_MODE=acme DOMAIN=proxy.example.com REALITY_SITE_ENABLED=1 REALITY_SITE_DOMAIN=site.example.com; }
	is_installed() { return 0; }
	sb_installed_version() { echo 1.14.2; }
	xr_installed_version() { echo 26.3.27; }
	core_used() { [ "$1" = singbox ]; }
	svc_active() { return 0; }
	do_doctor() { printf 'diagnostic failure secret-password secret-private-key secret-uuid %s\n' "${CF_Token:-}"; return 1; }
	CF_Token=secret-cloud-token
	printf 'NEVER_COPY_RAW_CONFIG\n' >"$STATE_FILE"
	mkdir -p "$SITE_ACME_HOME" "$ACME_HOME"
	mkdir -p "$SITE_ACME_HOME/site.example.com_ecc" "$ACME_HOME/proxy.example.com_ecc"
	: >"$SITE_ACME_HOME/site.example.com_ecc/site.example.com.conf"
	: >"$ACME_HOME/proxy.example.com_ecc/proxy.example.com.conf"
	cat >"$ACME_SH" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$*" >>"${ACME_CALLS:?}"
exit "${ACME_RC:-0}"
EOF
	cp "$ACME_SH" "$SITE_ACME_HOME/acme.sh"
	chmod +x "$ACME_SH" "$SITE_ACME_HOME/acme.sh"
	export ACME_CALLS="$ONEBOX_DIR/acme-calls" ACME_RC=0
}
archive_redacted() (
	fixture archive
	do_support_bundle >"$WORK/archive-out" || return 1
	local archive
	archive=$(find "$ONEBOX_DIR/support" -name '*.tar.gz')
	[ -n "$archive" ] && [ "$(stat -c %a "$archive")" = 600 ] || return 1
	mkdir "$WORK/extracted"
	tar -xzf "$archive" -C "$WORK/extracted" || return 1
	[ "$(find "$WORK/extracted" -type f | wc -l)" -eq 3 ] &&
		! grep -rE 'secret-|NEVER_COPY_RAW_CONFIG' "$WORK/extracted" &&
		grep -q REDACTED "$WORK/extracted/doctor.txt"
)
archive_symlink_rejected() (
	fixture archive-link
	mkdir -p "$WORK/foreign"
	ln -s "$WORK/foreign" "$ONEBOX_DIR/support"
	! do_support_bundle >/dev/null 2>&1 && [ -z "$(ls -A "$WORK/foreign")" ]
)
archive_parent_symlink_rejected() (
	fixture archive-parent
	ln -s "$ONEBOX_DIR" "$WORK/alias"
	ONEBOX_DIR="$WORK/alias/nested"
	! do_support_bundle >/dev/null 2>&1
)
archive_tar_failure_cleanup() (
	fixture archive-tar
	tar() { return 1; }
	! do_support_bundle >/dev/null 2>&1 && [ -z "$(ls -A "$ONEBOX_DIR/support")" ]
)
renew_success() (
	fixture renew
	do_cert_renew proxy >/dev/null 2>&1 &&
		[ "$(sed -n '2,3p' "$ONEBOX_DIR/renewal-proxy.status")" = $'success\nmanual' ] &&
		grep -q -- '--renew -d proxy.example.com --ecc --force' "$ACME_CALLS" &&
		[ "$(stat -c %a "$ONEBOX_DIR/renewal-proxy.status")" = 600 ]
)
renew_cron_skip() (
	fixture renew-cron
	ACME_RC=2
	do_cert_renew site --cron >/dev/null 2>&1 &&
		[ "$(sed -n '2,3p' "$ONEBOX_DIR/renewal-site.status")" = $'success\ncron' ] &&
		grep -q -- '--renew -d site.example.com --ecc' "$ACME_CALLS" && ! grep -q -- '--force' "$ACME_CALLS"
)
renew_failure() (
	fixture renew-fail
	ACME_RC=9
	local rc
	do_cert_renew proxy >/dev/null 2>&1; rc=$?
	[ "$rc" = 9 ] && [ "$(sed -n 2p "$ONEBOX_DIR/renewal-proxy.status")" = failed ]
)
renew_bad_kind() (
	fixture renew-bad
	! do_cert_renew ../../foreign >/dev/null 2>&1 && [ ! -f "$ACME_CALLS" ]
)
renew_disabled_site() (
	fixture renew-disabled
	site_enabled() { return 1; }
	! do_cert_renew site >/dev/null 2>&1 && [ ! -f "$ACME_CALLS" ]
)
renew_status_link_rejected() (
	fixture renew-status-link
	mkdir -p "$ONEBOX_DIR/foreign"
	ln -s "$ONEBOX_DIR/foreign" "$ONEBOX_DIR/renewal-site.status"
	! renewal_record site running manual && [ -z "$(ls -A "$ONEBOX_DIR/foreign")" ]
)
renew_extra_args_rejected() (
	fixture renew-extra
	! do_cert_renew site --cron unexpected >/dev/null 2>&1 && [ ! -f "$ACME_CALLS" ]
)
renew_missing_deployment() (
	fixture renew-missing
	rm -f "$SITE_ACME_HOME/site.example.com_ecc/site.example.com.conf"
	! do_cert_renew site --cron >/dev/null 2>&1 && [ ! -f "$ACME_CALLS" ] &&
		[ "$(sed -n 2p "$ONEBOX_DIR/renewal-site.status")" = failed ]
)
renew_content_lock() (
	fixture renew-lock
	mkdir "$REALITY_SITE_DIR/.content-lock"
	! do_cert_renew site --cron >/dev/null 2>&1 && [ ! -f "$ACME_CALLS" ] || return 1
	rmdir "$REALITY_SITE_DIR/.content-lock"
	do_cert_renew site --cron >/dev/null 2>&1 && [ ! -d "$REALITY_SITE_DIR/.content-lock" ]
)
check archive_redacted
check archive_symlink_rejected
check archive_parent_symlink_rejected
check archive_tar_failure_cleanup
check renew_success
check renew_cron_skip
check renew_failure
check renew_bad_kind
check renew_disabled_site
check renew_status_link_rejected
check renew_extra_args_rejected
check renew_missing_deployment
check renew_content_lock
printf 'Support/renewal: %s passed, %s failed\n' "$PASS" "$FAIL"
[ "$FAIL" = 0 ]
