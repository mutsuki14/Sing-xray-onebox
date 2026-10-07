#!/usr/bin/env bash
# ACME integration mocks; never contact a CA, alter DNS or use the host crontab.
# shellcheck disable=SC2034
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/.." && pwd)
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
# shellcheck source=../lib/frps-domain.sh
. "$ROOT/lib/frps-domain.sh"
PASS=0 FAIL=0
check() {
	if (FRPS_DIR="$WORK/$1"; mkdir -p "$FRPS_DIR"; "$@"); then PASS=$((PASS + 1));
	else FAIL=$((FAIL + 1)); printf '[失败] %s\n' "$*"; fi
}
fixture() {
	FRPS_MODE=web FRPS_DOMAIN=frp.example.com FRPS_WEB_DOMAIN=app.example.com FRPS_SUBDOMAIN_HOST=''
	FRPS_HTTP_PORT=7080 FRPS_HTTPS_PORT=443 FRPS_REDIRECT_PORT=80 FRPS_TLS_METHOD=http
	FRPS_WEB_ROOT="$FRPS_DIR/public" ACME_RC=0 INSTALL_RC=0 CERT_INVALID=0
	: >"$FRPS_DIR/calls"; : >"$FRPS_DIR/cron"
	has() { [ "$1" = crontab ]; }
	err() { printf '%s\n' "$*" >&2; }
	valid_domain() { [[ "$1" = *.* && "$1" != *[[:space:]]* ]]; }
	_site_read_crontab() { cat "$FRPS_DIR/cron"; }
	crontab() { [ "$1" = - ] || return 99; cat >"$FRPS_DIR/new-cron"; mv "$FRPS_DIR/new-cron" "$FRPS_DIR/cron"; }
	_frps_web_cert_validate() { [ "$CERT_INVALID" = 0 ] && [ -s "$FRPS_DIR/web-key.pem" ] && [ -s "$FRPS_DIR/web-cert.pem" ]; }
	acme_install() {
		printf 'install\n' >>"$FRPS_DIR/calls"
		mkdir -p "$ACME_HOME/${FRPS_SUBDOMAIN_HOST:-$FRPS_WEB_DOMAIN}_ecc"
		printf '#!/bin/sh\nexit 0\n' >"$ACME_SH"; chmod 700 "$ACME_SH"
		: >"$ACME_HOME/${FRPS_SUBDOMAIN_HOST:-$FRPS_WEB_DOMAIN}_ecc/${FRPS_SUBDOMAIN_HOST:-$FRPS_WEB_DOMAIN}.conf"
		printf '1 2,8,14,20 * * * "%s"/acme.sh --cron --home "%s" > /dev/null\n' "$ACME_HOME" "$ACME_HOME" >>"$FRPS_DIR/cron"
		return "$INSTALL_RC"
	}
	acme() {
		printf '%s\n' "$*" >>"$FRPS_DIR/calls"
		case "$1" in
		--issue) [ "${CF_Token:-}" != mock-cf-token ] || printenv CF_Token >"$FRPS_DIR/token-seen"; return "$ACME_RC" ;;
		--install-cert | --renew)
			[ "$ACME_RC" -ne 1 ] || return 1
			# Real acme.sh saves install target paths in the domain config and
			# writes them on renewal; emulate that contract, not a real certificate.
			printf 'mock-fullchain\n' >"$FRPS_DIR/web-cert.pem"
			printf 'mock-private-key\n' >"$FRPS_DIR/web-key.pem"
			return "$ACME_RC"
			;;
		*) return 99 ;;
		esac
	}
}
cron_quote_formats() {
	fixture
	cat >"$FRPS_DIR/cron" <<EOF
0 1 * * * $FRPS_DIR/acme/acme.sh --cron --home $FRPS_DIR/acme
0 2 * * * "$FRPS_DIR/acme/acme.sh" --cron --home "$FRPS_DIR/acme"
0 3 * * * '$FRPS_DIR/acme/acme.sh' --cron --home '$FRPS_DIR/acme'
0 4 * * * "$FRPS_DIR/acme"/acme.sh --cron --home "$FRPS_DIR/acme"
0 5 * * * '$FRPS_DIR/acme'/acme.sh --cron --home '$FRPS_DIR/acme'
0 6 * * * cp "$FRPS_DIR/acme/acme.sh" --cron /backup
0 7 * * * "$FRPS_DIR/acme/acme.sh" --issue -d app.example.com
0 8 * * * "$FRPS_DIR/acme-other"/acme.sh --cron --home "$FRPS_DIR/acme-other"
0 9 * * * /usr/local/bin/onebox frps renew --cron
# preserve comments and unrelated proxy certificate renewal
0 10 * * * "/etc/onebox/site/acme"/acme.sh --cron --home "/etc/onebox/site/acme"
EOF
	_frps_acme_cron_remove && [ "$(wc -l <"$FRPS_DIR/cron")" = 6 ] &&
		grep -q 'cp ' "$FRPS_DIR/cron" && grep -q -- '--issue' "$FRPS_DIR/cron" &&
		grep -q acme-other "$FRPS_DIR/cron" && grep -q 'frps renew' "$FRPS_DIR/cron" &&
		grep -q '^# preserve' "$FRPS_DIR/cron" && grep -q /etc/onebox/site "$FRPS_DIR/cron"
}
cron_read_failure_preserves_existing() {
	fixture; printf 'original' >"$FRPS_DIR/cron"
	_site_read_crontab() { return 1; }
	! _frps_acme_cron_remove && [ "$(cat "$FRPS_DIR/cron")" = original ]
}
http_issue_webroot_targets() {
	fixture
	_frps_web_certificate && grep -qxF -- "--issue -d app.example.com --webroot $FRPS_WEB_ROOT -k ec-256 --server letsencrypt" "$FRPS_DIR/calls" &&
		grep -qxF -- "--install-cert -d app.example.com --ecc --key-file $FRPS_DIR/web-key.pem --fullchain-file $FRPS_DIR/web-cert.pem --reloadcmd :" "$FRPS_DIR/calls" &&
		[ "$(stat -c %a "$FRPS_DIR/web-cert.pem")" = 600 ] && [ "$(stat -c %a "$FRPS_DIR/web-key.pem")" = 600 ] && ! grep -q '[^[:space:]]' "$FRPS_DIR/cron"
}
cf_wildcard_and_environment() {
	fixture; FRPS_TLS_METHOD=cf FRPS_SUBDOMAIN_HOST=apps.example.com FRPS_WEB_DOMAIN='' FRPS_REDIRECT_PORT=0
	export CF_Token=mock-cf-token
	_frps_web_certificate && grep -qxF -- '--issue -d apps.example.com -d *.apps.example.com --dns dns_cf -k ec-256 --server letsencrypt' "$FRPS_DIR/calls" &&
		grep -qF -- '--install-cert -d apps.example.com --ecc' "$FRPS_DIR/calls" &&
		[ "$(cat "$FRPS_DIR/token-seen")" = mock-cf-token ] && ! grep -q '[^[:space:]]' "$FRPS_DIR/cron"
}
failed_install_removes_added_cron() { fixture; INSTALL_RC=1; ! _frps_web_certificate && ! grep -q '[^[:space:]]' "$FRPS_DIR/cron" && ! grep -q -- '--issue' "$FRPS_DIR/calls"; }
failed_issue_no_deploy() { fixture; ACME_RC=1; ! _frps_web_certificate && ! grep -q -- '--install-cert' "$FRPS_DIR/calls" && [ ! -e "$FRPS_DIR/web-key.pem" ]; }
invalid_cert_rejected() { fixture; CERT_INVALID=1; ! _frps_web_certificate; }
renew_fixture() {
	fixture
	ACME_HOME="$FRPS_DIR/acme" ACME_SH="$FRPS_DIR/acme/acme.sh"
	acme_install || return 1
	: >"$FRPS_DIR/calls"
}
cron_renew_without_force() {
	renew_fixture
	_frps_web_renew --cron && [ "$(cat "$FRPS_DIR/calls")" = '--renew -d app.example.com --ecc' ] &&
		[ "$(stat -c %a "$FRPS_DIR/web-key.pem")" = 600 ] && ! grep -q '[^[:space:]]' "$FRPS_DIR/cron"
}
manual_renew_forced() { renew_fixture; _frps_web_renew manual && [ "$(cat "$FRPS_DIR/calls")" = '--renew -d app.example.com --ecc --force' ]; }
renew_skip_is_success() { renew_fixture; ACME_RC=2; _frps_web_renew --cron; }
renew_error_is_failure() { renew_fixture; ACME_RC=1; ! _frps_web_renew --cron; }
renew_missing_state_no_call() { renew_fixture; rm "$ACME_HOME/app.example.com_ecc/app.example.com.conf"; ! _frps_web_renew --cron 2>/dev/null && [ ! -s "$FRPS_DIR/calls" ]; }
check cron_quote_formats
check cron_read_failure_preserves_existing
check http_issue_webroot_targets
check cf_wildcard_and_environment
check failed_install_removes_added_cron
check failed_issue_no_deploy
check invalid_cert_rejected
check cron_renew_without_force
check manual_renew_forced
check renew_skip_is_success
check renew_error_is_failure
check renew_missing_state_no_call
printf 'FRP ACME 回归: %s 通过, %s 失败\n' "$PASS" "$FAIL"
[ "$FAIL" = 0 ]
