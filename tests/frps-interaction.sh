#!/usr/bin/env bash
# Interactive FRP regressions: pipe-backed terminal input and isolated fixtures.
# No network, packages, services, firewall or real credentials are used.
# shellcheck disable=SC2034
set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd)
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
export ONEBOX_SOURCE_ONLY=1 NO_COLOR=1
# shellcheck source=../onebox.sh
. "$ROOT/onebox.sh"
if ! declare -F _frps_ui_read >/dev/null; then
	# shellcheck source=../lib/frps-ui.sh
	. "$ROOT/lib/frps-ui.sh"
fi
FRPS_APPLY_DEFINITION=$(declare -f _frps_apply)
PASS=0 FAIL=0 NUMBER=0
contains() { grep -qF -- "$2" "$1"; }
absent() { ! grep -qF -- "$2" "$1"; }
fixture() {
	CASE_DIR="$WORK/case-$NUMBER"
	mkdir -p "$CASE_DIR"
	cd "$CASE_DIR" || return 1
	FRPS_DIR="$CASE_DIR/frp" FRPS_BIN_DIR="$CASE_DIR/bin" FRPS_WEB_VAR="$CASE_DIR/web"
	FRPS_LOG_DIR="$CASE_DIR/log" FRPS_RUN_DIR="$CASE_DIR/run" FRPS_LOCK="$CASE_DIR/lock"
	FRPS_STATE="$FRPS_DIR/state.conf" FRPS_CONF="$FRPS_DIR/frps.toml" FRPS_BIN="$FRPS_BIN_DIR/frps"
	FRPS_WEB_ROOT="$FRPS_WEB_VAR/www" FRPS_SYSTEMD_DIR="$CASE_DIR/systemd" INITD_DIR="$CASE_DIR/initd"
	ONEBOX_DIR="$CASE_DIR/proxy" STATE_FILE="$ONEBOX_DIR/state"
	TTY_IN=/dev/stdin AUTO_YES=0
	unset CF_Token CF_Key CF_Email CF_Account_ID CF_Zone_ID
	host_has_ipv6() { return 1; }
	is_interactive() { return 0; }
	setup_tty() { TTY_IN=/dev/stdin; }
	port_in_use() { return 1; }
	_frps_service_active() { return 1; }
	_frps_proxy_reservations() { return 0; }
	_frps_defaults
	FRPS_DOMAIN=control.example.com FRPS_WEB_DOMAIN=app.example.com
	FRPS_TOKEN=$(printf '%064d' 1)
	mkdir -p "$FRPS_DIR"
	printf 'fixture-public-ca\n' >"$FRPS_DIR/ca.pem"
	# Guard against accidental implementation calls crossing the fixture boundary.
	init_env() { printf 'unexpected init_env\n' >&2; return 99; }
	ensure_cmds() { printf 'unexpected package install\n' >&2; return 99; }
	curl() { printf 'unexpected network\n' >&2; return 99; }
	_frps_apply() { printf 'unexpected apply\n' >&2; return 99; }
	_frps_service() { printf 'unexpected service action\n' >&2; return 99; }
	_frps_fw_apply() { printf 'unexpected firewall action\n' >&2; return 99; }
	detect_os() { return 0; }
	detect_init() { INIT=none; }
	require_root() { return 0; }
}
check() {
	local label=$1
	shift
	NUMBER=$((NUMBER + 1))
	if (fixture; "$@") >"$WORK/result" 2>&1; then PASS=$((PASS + 1));
	else FAIL=$((FAIL + 1)); printf '[失败] %s\n' "$label"; cat "$WORK/result"; fi
}
input() {
	local answers=$1
	shift
	"$@" < <(printf '%s' "$answers") >"$CASE_DIR/transcript" 2>&1
}
read_value() {
	local result=''
	input $'typed value\n' _frps_ui_read result '示例' fallback && [ "$result" = 'typed value' ]
}
read_default() {
	local result=''
	input $'\n' _frps_ui_read result '示例' fallback && [ "$result" = fallback ]
}
read_abort() {
	local answer=$1 expected=$2 result=unchanged rc=0
	input "$answer" _frps_ui_read result '示例' fallback || rc=$?
	[ "$rc" = "$expected" ] && [ "$result" = unchanged ]
}
read_eof() {
	local answers=$1 helper=${2:-_frps_ui_read} result=unchanged rc=0
	(input "$answers" "$helper" result '示例' fallback; : >"$CASE_DIR/eof-accepted") || rc=$?
	[ "$rc" = 130 ] && [ ! -e "$CASE_DIR/eof-accepted" ] && [ "$result" = unchanged ]
}
read_secret() {
	local result=''
	input $'new-secret-value\n' _frps_ui_read result '凭据' old-secret-value secret || return 1
	[ "$result" = new-secret-value ] && absent "$CASE_DIR/transcript" new-secret-value && absent "$CASE_DIR/transcript" old-secret-value
}
choice_retry() {
	local result=''
	input $'9\n2\n' _frps_ui_choice result '选择' 1 '^[12]$' && [ "$result" = 2 ]
}
number_retry() {
	local result=''
	input $'nope\n0\n65536\n07001\n' _frps_ui_number result '端口' 7000 1 65535 && [ "$result" = 7001 ]
}
number_zero() {
	local result=''
	input $'0\n' _frps_ui_number result '跳转端口' 80 0 65535 && [ "$result" = 0 ]
}
domain_normalize() {
	local result=''
	input $'https://APP.Example.com/path\n' _frps_ui_domain result '域名' '' && [ "$result" = app.example.com ]
}
domain_retry() {
	local result=''
	input $'bad domain\nlocalhost\napp.example.com\n' _frps_ui_domain result '域名' '' && [ "$result" = app.example.com ]
}
domain_wildcard() {
	local result=''
	input $'*.APPS.Example.com\n' _frps_ui_domain result '泛域名根' '' wildcard && [ "$result" = apps.example.com ]
}
helper_cancel() {
	local helper=$1 expected=$2 answers=$3 result=unchanged rc=0
	shift 3
	input "$answers" "$helper" result '示例' '' "$@" || rc=$?
	[ "$rc" = "$expected" ] && [ "$result" = unchanged ]
}
port_free() {
	_frps_ui_prepare_ports
	_frps_ui_port_available 8443 tcp
}
port_external() {
	port_in_use() { [ "$1/$2" = 443/tcp ]; }
	_frps_ui_prepare_ports
	! _frps_ui_port_available 443 tcp
}
port_proxy_reserved() {
	_frps_proxy_reservations() { printf '443 tcp\n45000-45100 udp\n'; }
	_frps_ui_prepare_ports
	! _frps_ui_port_available 443 tcp && ! _frps_ui_port_available 45050 udp && _frps_ui_port_available 45050 tcp
}
port_own() {
	: >"$FRPS_DIR/.managed"
	_frps_save || return 1
	_frps_service_active() { return 0; }
	port_in_use() { [ "$1/$2" = 443/tcp ]; }
	_frps_ui_prepare_ports
	_frps_ui_port_available 443 tcp
}
cf_environment() {
	CF_Token=environment-secret
	input '' _frps_ui_cf_credentials && [ "$CF_Token" = environment-secret ] && absent "$CASE_DIR/transcript" environment-secret
}
cf_legacy_environment() {
	CF_Key=legacy-secret CF_Email=owner@example.com
	input '' _frps_ui_cf_credentials && absent "$CASE_DIR/transcript" legacy-secret
}
cf_new_token() {
	input $'new-cf-secret\n2\nzone-fixture\naccount-fixture\n' _frps_ui_cf_credentials || return 1
	[ "$CF_Token" = new-cf-secret ] && [ "${CF_Zone_ID:-}" = zone-fixture ] && [ "${CF_Account_ID:-}" = account-fixture ] || return 1
	absent "$CASE_DIR/transcript" new-cf-secret && _frps_save && absent "$FRPS_STATE" new-cf-secret && absent "$FRPS_STATE" CF_Token
}
cf_blank_retry() {
	input $'\nnew-cf-secret\n\n' _frps_ui_cf_credentials && [ "$CF_Token" = new-cf-secret ] && absent "$CASE_DIR/transcript" new-cf-secret
}
cf_saved() {
	mkdir -p "$FRPS_DIR/acme"
	printf '%s\n' "SAVED_CF_Token='stored-secret'" >"$FRPS_DIR/acme/account.conf"
	printf 'touch %q\n' "$CASE_DIR/executed" >>"$FRPS_DIR/acme/account.conf"
	input $'\n' _frps_ui_cf_credentials && [ ! -e "$CASE_DIR/executed" ] && [ -z "${CF_Token:-}" ] && absent "$CASE_DIR/transcript" stored-secret
}
cf_saved_replace() {
	mkdir -p "$FRPS_DIR/acme"
	printf '%s\n' "SAVED_CF_Token='stored-secret'" >"$FRPS_DIR/acme/account.conf"
	input $'2\nreplacement-secret\n\n' _frps_ui_cf_credentials && [ "$CF_Token" = replacement-secret ] && absent "$CASE_DIR/transcript" replacement-secret && absent "$CASE_DIR/transcript" stored-secret
}
cf_empty_saved() {
	mkdir -p "$FRPS_DIR/acme"
	printf '%s\n' "SAVED_CF_Token=''" >"$FRPS_DIR/acme/account.conf"
	! _frps_ui_saved_cf
}
cf_current_domain_saved() {
	local primary
	for primary in app.example.com apps.example.com; do
		if [ "$primary" = apps.example.com ]; then FRPS_SUBDOMAIN_HOST=$primary; FRPS_WEB_DOMAIN=''; fi
		mkdir -p "$FRPS_DIR/acme/${primary}_ecc"
		printf '%s\n' "CF_Token='domain-stored-secret'" >"$FRPS_DIR/acme/${primary}_ecc/$primary.conf"
		printf 'touch %q\n' "$CASE_DIR/executed" >>"$FRPS_DIR/acme/${primary}_ecc/$primary.conf"
		input $'\n' _frps_ui_cf_credentials || return 1
		[ ! -e "$CASE_DIR/executed" ] && [ -z "${CF_Token:-}" ] && absent "$CASE_DIR/transcript" domain-stored-secret || return 1
	done
}
cf_other_domain_not_reused() {
	mkdir -p "$FRPS_DIR/acme/other.example.com_ecc"
	printf '%s\n' "CF_Token='other-domain-secret'" >"$FRPS_DIR/acme/other.example.com_ecc/other.example.com.conf"
	! _frps_ui_saved_cf
}
cf_cancel() {
	local rc=0
	input $'q\n' _frps_ui_cf_credentials || rc=$?
	[ "$rc" = 125 ] && [ -z "${CF_Token:-}" ] && [ ! -e "$FRPS_STATE" ]
}
wizard_web() {
	input $'\n\n\n\n\n\n\n\n' _frps_wizard || return 1
	[ "$FRPS_MODE/$FRPS_TLS_METHOD/$FRPS_HTTPS_PORT/$FRPS_REDIRECT_PORT" = web/http/443/80 ] && [ ! -e "$FRPS_STATE" ]
}
wizard_wildcard() {
	CF_Token=fixture-cf-token
	input $'\n\n2\n*.APPS.Example.com\n\n\n\n\n\n' _frps_wizard || return 1
	[ "$FRPS_SUBDOMAIN_HOST" = apps.example.com ] && [ -z "$FRPS_WEB_DOMAIN" ] && [ "$FRPS_TLS_METHOD" = cf ] && absent "$CASE_DIR/transcript" fixture-cf-token
}
wizard_busy_https() {
	CF_Token=fixture-cf-token
	port_in_use() { [ "$2" = tcp ] && { [ "$1" = 443 ] || [ "$1" = 80 ]; }; }
	input $'\n\n\n\n\n\n\n\n\n' _frps_wizard || return 1
	[ "$FRPS_HTTPS_PORT/$FRPS_TLS_METHOD/$FRPS_REDIRECT_PORT" = 8443/cf/0 ] && [ ! -e "$FRPS_STATE" ]
}
wizard_back() {
	input $'\n\n\n\n b \nnew-control.example.com\n\nnew-app.example.com\n\n\n\n\n' _frps_wizard || return 1
	[ "$FRPS_DOMAIN" = new-control.example.com ] && [ "$FRPS_WEB_DOMAIN" = new-app.example.com ] && [ ! -e "$FRPS_STATE" ]
}
wizard_tcp_range() {
	input $'2\n\n\n45000\n46000\n45000\n45999\n\n' _frps_wizard || return 1
	[ "$FRPS_MODE/$FRPS_RANGE_START/$FRPS_RANGE_END" = tcp/45000/45999 ] && absent "$CASE_DIR/transcript" 'Cloudflare API Token'
}
wizard_cancel() {
	local answers=$1 rc=0
	input "$answers" _frps_wizard || rc=$?
	[ "$rc" = 125 ] && [ ! -e "$FRPS_STATE" ] && [ ! -e "$FRPS_CONF" ]
}
wizard_eof() {
	local rc=0
	(input '' _frps_wizard; : >"$CASE_DIR/eof-accepted") || rc=$?
	[ "$rc" = 130 ] && [ ! -e "$CASE_DIR/eof-accepted" ] && [ ! -e "$FRPS_STATE" ]
}
client_web() {
	input "$(printf '9090\n%s\n' "$CASE_DIR/client")"$'\n' _frps_client_wizard || return 1
	contains "$CASE_DIR/client/frpc.toml" 'localPort = 9090' && contains "$CASE_DIR/client/frpc.toml" 'customDomains = ["app.example.com"]' && contains "$CASE_DIR/client/frpc.toml" 'transport.tls.trustedCaFile = "./ca.pem"'
}
client_wildcard() {
	FRPS_SUBDOMAIN_HOST=apps.example.com FRPS_WEB_DOMAIN='' FRPS_TLS_METHOD=cf
	input "$(printf '9091\nbad.label\nhome\n%s\n' "$CASE_DIR/client")"$'\n' _frps_client_wizard || return 1
	contains "$CASE_DIR/client/frpc.toml" 'subdomain = "home"' && contains "$CASE_DIR/client/frpc.toml" 'localPort = 9091'
}
client_tcp() {
	FRPS_MODE=tcp
	input "$(printf '1\n22\n19999\n20001\n%s\n' "$CASE_DIR/client")"$'\n' _frps_client_wizard || return 1
	contains "$CASE_DIR/client/frpc.toml" 'type = "tcp"' && contains "$CASE_DIR/client/frpc.toml" 'localPort = 22' && contains "$CASE_DIR/client/frpc.toml" 'remotePort = 20001'
}
client_udp() {
	FRPS_MODE=tcp
	input "$(printf '2\n27015\n20002\n%s\n' "$CASE_DIR/client")"$'\n' _frps_client_wizard || return 1
	contains "$CASE_DIR/client/frpc.toml" 'type = "udp"' && contains "$CASE_DIR/client/frpc.toml" 'localPort = 27015' && contains "$CASE_DIR/client/frpc.toml" 'remotePort = 20002'
}
client_existing_dir() {
	mkdir "$CASE_DIR/keep"
	printf 'keep-me\n' >"$CASE_DIR/keep/existing"
	input "$(printf '8081\n%s\n%s\n' "$CASE_DIR/keep" "$CASE_DIR/client")"$'\n' _frps_client_wizard || return 1
	contains "$CASE_DIR/keep/existing" keep-me && [ ! -e "$CASE_DIR/keep/frpc.toml" ] && contains "$CASE_DIR/client/frpc.toml" 'localPort = 8081'
}
client_back() {
	input "$(printf '8081\nb\n9092\n%s\n' "$CASE_DIR/client")"$'\n' _frps_client_wizard || return 1
	contains "$CASE_DIR/client/frpc.toml" 'localPort = 9092'
}
client_cancel() {
	local rc=0
	input $'q\n' _frps_client_wizard || rc=$?
	[ "$rc" = 125 ] && [ ! -e "$CASE_DIR/client" ]
}
wizard_version_retry() {
	input $'\n\n\n\n\n\n\n2\n\ninvalid\n0.1.0\nlatest\n' _frps_wizard || return 1
	[ "$FRPS_VERSION" = latest ] && [ ! -e "$FRPS_STATE" ]
}
review_result() {
	local answer=$1 expected=$2 rc=0
	FRPS_UI_WIZARD=1
	input "$answer" _frps_review || rc=$?
	[ "$rc" = "$expected" ] && contains "$CASE_DIR/transcript" control.example.com && contains "$CASE_DIR/transcript" app.example.com && absent "$CASE_DIR/transcript" "$FRPS_TOKEN"
}
review_rotation() {
	FRPS_UI_WIZARD=1
	input $'1\n' _frps_review 1 && contains "$CASE_DIR/transcript" '旧客户端会失效' && absent "$CASE_DIR/transcript" "$FRPS_TOKEN"
}
apply_cancel() {
	local rc=0
	eval "$FRPS_APPLY_DEFINITION"
	FRPS_UI_WIZARD=1
	input $'0\n' _frps_apply || rc=$?
	[ "$rc" = 125 ] && absent "$CASE_DIR/transcript" 'unexpected' && [ ! -e "$FRPS_STATE" ]
}
cli_client_interactive() {
	: >"$FRPS_DIR/.managed"
	_frps_save || return 1
	input "$(printf '8123\n%s\n' "$CASE_DIR/client")"$'\n' do_frps client || return 1
	contains "$CASE_DIR/client/frpc.toml" 'localPort = 8123'
}
cli_client_noninteractive() {
	: >"$FRPS_DIR/.managed"
	_frps_save || return 1
	is_interactive() { return 1; }
	input '' do_frps client "$CASE_DIR/client" --local-port 8124 || return 1
	contains "$CASE_DIR/client/frpc.toml" 'localPort = 8124'
}
menu_uninstalled() {
	do_frps() { : >"$CASE_DIR/unexpected-action"; return 99; }
	input $'3\n0\n' _frps_menu && [ ! -e "$CASE_DIR/unexpected-action" ] && contains "$CASE_DIR/transcript" '请先选择 1 安装'
}
menu_cancel() {
	input $'q\n' _frps_menu
}
cli_plan_noninteractive() {
	is_interactive() { return 1; }
	input '' do_frps plan --mode tcp --domain control.example.com || return 1
	contains "$CASE_DIR/transcript" control.example.com && absent "$CASE_DIR/transcript" 'unexpected'
}
cli_conflicting_domains() {
	local first second rc
	is_interactive() { return 1; }
	for first in --web-domain --subdomain-host; do
		if [ "$first" = --web-domain ]; then second=--subdomain-host; else second=--web-domain; fi
		rc=0
		input '' do_frps plan --domain control.example.com "$first" app.example.com "$second" apps.example.com --tls cf || rc=$?
		[ "$rc" = 1 ] && contains "$CASE_DIR/transcript" '不能同时使用' && absent "$CASE_DIR/transcript" 'unexpected' || return 1
	done
}
check 'input accepts supplied value' read_value
check 'blank input explicitly accepts default' read_default
check 'q cancels without accepting default' read_abort $'q\n' 125
check 'b returns to previous step without accepting default' read_abort $'b\n' 126
check 'EOF exits without accepting default' read_eof ''
check 'unfinished input followed by EOF does not accept default' read_eof 'partial'
check 'secret input never prints entered or default credentials' read_secret
check 'invalid menu choice can be corrected in place' choice_retry
check 'number input retries invalid range and normalizes leading zero' number_retry
check 'zero remains a valid disabled redirect port' number_zero
check 'domain input strips URL and lowercases DNS name' domain_normalize
check 'invalid domain can be corrected in place' domain_retry
check 'wildcard input accepts star prefix and stores root domain' domain_wildcard
check 'choice q propagates cancellation' helper_cancel _frps_ui_choice 125 $'q\n' '^[12]$'
check 'number b propagates previous-step request' helper_cancel _frps_ui_number 126 $'b\n' 1 65535
check 'domain EOF exits instead of looping' read_eof '' _frps_ui_domain
check 'free port remains available to the wizard' port_free
check 'external listener is detected before deployment' port_external
check 'proxy TCP and UDP reservations respect protocol and range' port_proxy_reserved
check 'existing FRP listener remains selectable when reconfiguring' port_own
check 'Cloudflare token in environment is reused without printing it' cf_environment
check 'Cloudflare legacy environment pair remains supported' cf_legacy_environment
check 'new hidden token supports explicit IDs and stays out of FRP state' cf_new_token
check 'blank Cloudflare token can be corrected in place' cf_blank_retry
check 'saved Cloudflare credentials are reused without executing account file' cf_saved
check 'saved Cloudflare token can be replaced without exposing either value' cf_saved_replace
check 'empty saved Cloudflare token does not pass readiness check' cf_empty_saved
check 'current single or wildcard domain credentials are reused without executing domain file' cf_current_domain_saved
check 'Cloudflare credentials belonging only to another domain are not reused' cf_other_domain_not_reused
check 'Cloudflare cancellation does not persist partial credentials' cf_cancel
check 'single-domain wizard accepts safe defaults without applying changes' wizard_web
check 'wildcard wizard automatically defaults to DNS certificate validation' wizard_wildcard
check 'occupied 80 and 443 suggest DNS validation with 8443 and no redirect' wizard_busy_https
check 'previous-step navigation lets domains be corrected' wizard_back
check 'TCP range retries an oversized range without asking website credentials' wizard_tcp_range
check 'wizard q cancels before any mutation' wizard_cancel $'q\n'
check 'wizard q during domain input cancels before any mutation' wizard_cancel $'\nq\n'
check 'wizard EOF exits before any mutation' wizard_eof
check 'web client wizard exports selected local port and mandatory CA verification' client_web
check 'wildcard client wizard retries invalid label and exports chosen subdomain' client_wildcard
check 'TCP client wizard retries out-of-range public port and exports local SSH port' client_tcp
check 'UDP client wizard exports UDP and the chosen local service port' client_udp
check 'client export retries existing directory without overwriting content' client_existing_dir
check 'client previous-step navigation can correct the local port' client_back
check 'client cancellation creates no export directory' client_cancel
check 'invalid advanced version is retried without leaving the step' wizard_version_retry
check 'review explicitly accepts deployment after displaying nonsecret summary' review_result $'1\n' 0
check 'review can return to edit settings' review_result $'2\n' 126
check 'review blank input cancels by default' review_result $'\n' 125
check 'token rotation review explains client invalidation without printing token' review_rotation
check 'canceling deployment review occurs before dependencies and host changes' apply_cancel
check 'client command without options enters wizard at a terminal' cli_client_interactive
check 'explicit client CLI options stay usable without a terminal' cli_client_noninteractive
check 'uninstalled menu rejects hidden service actions before invoking anything' menu_uninstalled
check 'menu q returns cleanly to parent' menu_cancel
check 'noninteractive plan remains usable without applying changes' cli_plan_noninteractive
check 'CLI rejects mutually exclusive domain options in either order' cli_conflicting_domains

printf '\nFRP interaction: %s passed, %s failed\n' "$PASS" "$FAIL"
[ "$FAIL" = 0 ]
