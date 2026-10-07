#!/usr/bin/env bash
# FRP lifecycle fault-injection tests. All paths and service/firewall/cron effects
# are redirected to a temporary fixture; no package installation or host changes.
# shellcheck disable=SC2034
set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd)
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
export ONEBOX_SOURCE_ONLY=1 NO_COLOR=1
# shellcheck source=../onebox.sh
. "$ROOT/onebox.sh"
if ! declare -F _frps_defaults >/dev/null; then
	# shellcheck source=../lib/frps.sh
	. "$ROOT/lib/frps.sh"
	# shellcheck source=../lib/frps-domain.sh
	. "$ROOT/lib/frps-domain.sh"
	# shellcheck source=../lib/frps-firewall.sh
	. "$ROOT/lib/frps-firewall.sh"
fi
SERVICE_DEFINITION=$(declare -f _frps_service)
HEALTH_DEFINITION=$(declare -f _frps_health)
PASS=0 FAIL=0 NUMBER=0
contains() { grep -qF -- "$2" "$1"; }
absent() { ! grep -qF -- "$2" "$1"; }
backup_path() { find "$CASE_ROOT" -maxdepth 1 -type d -name '.onebox-frps-backup.*' | head -n1; }
fixture() {
	export CASE_ROOT="$WORK/case-$NUMBER"
	mkdir -p "$CASE_ROOT"
	ONEBOX_DIR="$CASE_ROOT/proxy" BIN_DIR="$CASE_ROOT/proxy-bin" LOG_DIR="$CASE_ROOT/proxy-log" RUN_DIR="$CASE_ROOT/proxy-run"
	STATE_FILE="$ONEBOX_DIR/onebox.conf"
	FRPS_DIR="$CASE_ROOT/frp" FRPS_BIN_DIR="$CASE_ROOT/frp-bin" FRPS_WEB_VAR="$CASE_ROOT/public"
	FRPS_LOG_DIR="$CASE_ROOT/frp-log" FRPS_RUN_DIR="$CASE_ROOT/frp-run" FRPS_LOCK="$CASE_ROOT/frp.lock"
	FRPS_SYSTEMD_DIR="$CASE_ROOT/systemd" INITD_DIR="$CASE_ROOT/initd"
	FRPS_BIN="$FRPS_BIN_DIR/frps" FRPS_CONF="$FRPS_DIR/frps.toml" FRPS_STATE="$FRPS_DIR/state.conf" FRPS_WEB_ROOT="$FRPS_WEB_VAR/www"
	INIT=systemd CMD_PATH="$CASE_ROOT/onebox" ONEBOX_NGINX_BIN="$CASE_ROOT/nginx"
	mkdir -p "$ONEBOX_DIR" "$BIN_DIR" "$LOG_DIR" "$RUN_DIR" "$FRPS_SYSTEMD_DIR" "$INITD_DIR"
	printf 'proxy-config-must-survive\n' >"$STATE_FILE"
	printf 'proxy-binary-must-survive\n' >"$BIN_DIR/proxy"
	printf 'proxy-firewall-must-survive\n' >"$ONEBOX_DIR/firewall.list"
	printf '#!/bin/sh\nexit 0\n' >"$ONEBOX_NGINX_BIN"
	chmod 755 "$ONEBOX_NGINX_BIN"
	printf '12 1 * * * /usr/bin/backup-onebox # unrelated\n' >"$CASE_ROOT/cron"
	: >"$CASE_ROOT/actions"
	_frps_defaults
	FRPS_MODE=web FRPS_DOMAIN=control.example.com FRPS_WEB_DOMAIN=app.example.com FRPS_TLS_METHOD=custom
	FRPS_TOKEN=$(printf '%064d' 1)
	_frps_make_dirs
	printf 'old-frps-config\n' >"$FRPS_CONF"
	printf 'old-web-config\n' >"$FRPS_DIR/nginx.conf"
	printf 'old-control-cert\n' >"$FRPS_DIR/server-cert.pem"
	printf 'old-web-cert\n' >"$FRPS_DIR/web-cert.pem"
	printf 'old-private-ca\n' >"$FRPS_DIR/ca.pem"
	_frps_save
	printf '# Managed by Onebox FRP\nold-frps-unit\n' >"$(_frps_unit frps)"
	printf '# Managed by Onebox FRP\nold-web-unit\n' >"$(_frps_unit web)"
	printf 'mock 7000/tcp\n' >"$FRPS_DIR/firewall.list"
	printf 'old-public-content\n' >"$FRPS_WEB_VAR/keep"
	printf '#!/bin/sh\nprintf "%%s\\n" "%s"\n' "$TESTED_FRP_VERSION" >"$FRPS_BIN"
	chmod 755 "$FRPS_BIN"
	: >"$CASE_ROOT/active-frps"; : >"$CASE_ROOT/enabled-frps"
	# All subprocess-visible side effects stay under CASE_ROOT.
	init_env() { INIT=systemd; }
	ensure_cmds() { return 0; }
	confirm() { return 0; }
	_frps_check_dns() { return 0; }
	_frps_ensure_manager() { return 0; }
	_frps_dns_info() { return 0; }
	_frps_proxy_reservations() { [ -z "${RESERVED_PORTS:-}" ] || printf '%s\n' "$RESERVED_PORTS"; return 0; }
	port_in_use() { [ "${PORT_IN_USE:-}" = "$1/$2" ]; }
	_frps_service_active() { [ -f "$CASE_ROOT/active-$1" ]; }
	_frps_service_enabled() { [ -f "$CASE_ROOT/enabled-$1" ]; }
	_frps_service() {
		local action=$1 kind=$2
		printf '%s %s\n' "$action" "$kind" >>"$CASE_ROOT/actions"
		[ ! -f "$CASE_ROOT/fail-stop-persistent" ] || [ "$action" != stop ] || return 1
		if [ -f "$CASE_ROOT/fail-$action-$kind" ]; then rm -f "$CASE_ROOT/fail-$action-$kind"; return 1; fi
		case "$action" in
		start | restart) : >"$CASE_ROOT/active-$kind" ;;
		stop) rm -f "$CASE_ROOT/active-$kind" ;;
		enable) : >"$CASE_ROOT/enabled-$kind" ;;
		disable) rm -f "$CASE_ROOT/enabled-$kind" ;;
		reload) : ;;
		*) return 1 ;;
		esac
	}
	systemctl() { printf 'systemctl %s\n' "$*" >>"$CASE_ROOT/actions"; return 0; }
	crontab() {
		case "${1:-}" in -l) cat "$CASE_ROOT/cron" ;; -) cat >"$CASE_ROOT/cron" ;; *) cp "$1" "$CASE_ROOT/cron" ;; esac
	}
	_frps_fw_close_entry() {
		[[ "$1" != *keep-on-failure* ]] || return 1
		_frps_fw_ledger_del "$1"
	}
	_frps_fw_apply() {
		printf 'firewall %s\n' "$1" >>"$CASE_ROOT/actions"
		_frps_fw_ledger_add 'mock 7000/tcp'
		if [ -f "$CASE_ROOT/fail-firewall-open" ]; then rm -f "$CASE_ROOT/fail-firewall-open"; return 1; fi
	}
	_frps_download() {
		[ ! -f "$CASE_ROOT/fail-download" ] || return 1
		cat >"$1" <<EOF
#!/bin/sh
if [ "\$1" = -v ]; then printf '%s\n' "$TESTED_FRP_VERSION"; exit 0; fi
[ ! -f "\$CASE_ROOT/fail-verify" ]
EOF
		chmod 755 "$1"
	}
	_frps_control_certificate() { [ -f "$FRPS_DIR/server-cert.pem" ] || printf 'control-cert\n' >"$FRPS_DIR/server-cert.pem"; }
	_frps_web_certificate() { printf 'new-web-cert\n' >"$FRPS_DIR/web-cert.pem"; [ ! -f "$CASE_ROOT/fail-certificate" ]; }
	_frps_web_render() { printf 'new-web-config-%s\n' "$1" >"$FRPS_DIR/nginx.conf"; }
	_frps_web_check() { [ ! -f "$CASE_ROOT/fail-web-check" ]; }
	_frps_web_renew() { printf 'web-renew %s\n' "${1:-}" >>"$CASE_ROOT/actions"; [ ! -f "$CASE_ROOT/rotate-web" ] || printf 'changed-web-cert\n' >"$FRPS_DIR/web-cert.pem"; }
	site_install_nginx() { return 0; }
	_frps_health() { [ ! -f "$CASE_ROOT/fail-health" ]; }
	_enable_cron_service() { return 0; }
	_site_scheduler_ready() {
		printf 'scheduler readiness\n' >>"$CASE_ROOT/actions"
		[ ! -f "$CASE_ROOT/fail-scheduler" ]
	}
}
check() {
	local label=$1
	shift
	NUMBER=$((NUMBER + 1))
	if (fixture && "$@") >"$WORK/result" 2>&1; then PASS=$((PASS + 1));
	else FAIL=$((FAIL + 1)); printf '[失败] %s\n' "$label"; cat "$WORK/result"; fi
}
proxy_intact() {
	contains "$STATE_FILE" proxy-config-must-survive && contains "$BIN_DIR/proxy" proxy-binary-must-survive && contains "$ONEBOX_DIR/firewall.list" proxy-firewall-must-survive
}
old_restored() {
	contains "$FRPS_CONF" old-frps-config && contains "$FRPS_DIR/web-cert.pem" old-web-cert && contains "$FRPS_WEB_VAR/keep" old-public-content &&
		contains "$(_frps_unit frps)" old-frps-unit && contains "$CASE_ROOT/cron" unrelated &&
		[ -f "$CASE_ROOT/active-frps" ] && [ -f "$CASE_ROOT/enabled-frps" ] &&
		[ ! -f "$CASE_ROOT/active-web" ] && [ ! -f "$CASE_ROOT/enabled-web" ] && proxy_intact
}
apply_fails_at() {
	: >"$CASE_ROOT/fail-$1"
	if _frps_apply; then return 1; fi
	old_restored && [ -z "$(backup_path)" ]
}
check 'configuration validation failure restores prior files and service state' apply_fails_at verify
check 'certificate failure restores prior certificate, units and cron' apply_fails_at certificate
check 'new service start failure restores previously active instance' apply_fails_at start-frps
check 'firewall apply failure returns to prior deployment' apply_fails_at firewall-open
check 'health failure restores old configuration and service state' apply_fails_at health
check 'download failure keeps old deployment and credentials' apply_fails_at download
check 'inactive cron scheduler restores old deployment and scheduled tasks' apply_fails_at scheduler

incomplete_snapshot() {
	cp() {
		local last=${*: -1}
		case "$last" in */dir-1) return 1 ;; esac
		command cp "$@"
	}
	if (_frps_begin); then return 1; fi
	old_restored && [ ! -s "$CASE_ROOT/actions" ] && [ -z "$(backup_path)" ]
}
check 'incomplete snapshot never invokes destructive rollback or service changes' incomplete_snapshot
foreign_directory() { rm "$FRPS_WEB_VAR/.managed"; if (_frps_begin); then return 1; fi; old_restored && [ ! -s "$CASE_ROOT/actions" ]; }
check 'existing foreign content directory is not adopted' foreign_directory
foreign_unit() { printf 'administrator service\n' >"$(_frps_unit frps)"; if (_frps_begin); then return 1; fi; contains "$(_frps_unit frps)" 'administrator service' && [ ! -s "$CASE_ROOT/actions" ]; }
check 'existing foreign service unit is not adopted' foreign_unit

partial_firewall_cleanup() {
	printf 'mock 7000/tcp\nkeep-on-failure 443/tcp\n' >"$FRPS_DIR/firewall.list"
	: >"$CASE_ROOT/fail-download"
	if _frps_apply; then return 1; fi
	local backup
	backup=$(backup_path)
	[ -n "$backup" ] && [ -f "$backup/complete" ] && contains "$backup/dir-0/frps.toml" old-frps-config &&
		contains "$FRPS_DIR/firewall.list" 'keep-on-failure 443/tcp' && absent "$FRPS_DIR/firewall.list" 'mock 7000/tcp' && proxy_intact
}
check 'partial firewall cleanup retains pending ledger and complete backup' partial_firewall_cleanup
stop_failure() {
	: >"$CASE_ROOT/fail-download"; : >"$CASE_ROOT/fail-stop-persistent"
	if _frps_apply; then return 1; fi
	[ -n "$(backup_path)" ] && contains "$FRPS_DIR/firewall.list" 'mock 7000/tcp' && contains "$FRPS_CONF" old-frps-config && [ -f "$CASE_ROOT/active-frps" ]
}
check 'failed service stop prevents overwriting live configuration' stop_failure

rollback_disabled_active() {
	rm -f "$CASE_ROOT/enabled-frps"; : >"$CASE_ROOT/active-web"; : >"$CASE_ROOT/enabled-web"; : >"$CASE_ROOT/fail-certificate"
	if _frps_apply; then return 1; fi
	[ -f "$CASE_ROOT/active-frps" ] && [ ! -f "$CASE_ROOT/enabled-frps" ] && [ -f "$CASE_ROOT/active-web" ] && [ -f "$CASE_ROOT/enabled-web" ]
}
check 'rollback restores active and enabled flags independently' rollback_disabled_active
fresh_failure() {
	rm -rf "$FRPS_DIR" "$FRPS_BIN_DIR" "$FRPS_WEB_VAR"
	rm -f "$(_frps_unit frps)" "$(_frps_unit web)" "$CASE_ROOT/active-frps" "$CASE_ROOT/enabled-frps"
	: >"$CASE_ROOT/fail-certificate"
	if _frps_apply; then return 1; fi
	[ ! -e "$FRPS_DIR" ] && [ ! -e "$FRPS_BIN_DIR" ] && [ ! -e "$FRPS_WEB_VAR" ] && [ ! -f "$CASE_ROOT/active-frps" ] && [ -z "$(backup_path)" ] && proxy_intact
}
check 'failed first installation removes only newly owned resources' fresh_failure
success_apply() {
	_frps_apply && [ -f "$CASE_ROOT/active-frps" ] && [ -f "$CASE_ROOT/active-web" ] &&
		[ -f "$CASE_ROOT/enabled-frps" ] && [ -f "$CASE_ROOT/enabled-web" ] &&
		contains "$FRPS_CONF" 'transport.tls.force = true' && contains "$CASE_ROOT/cron" onebox-frps-renew && [ -z "$(backup_path)" ] && proxy_intact
}
check 'successful apply commits services, configuration and scheduler' success_apply
uninstall_independent() {
	_frps_uninstall && [ ! -e "$FRPS_DIR" ] && [ ! -e "$FRPS_BIN_DIR" ] && [ ! -e "$FRPS_WEB_VAR" ] &&
		[ ! -e "$(_frps_unit frps)" ] && [ ! -e "$CASE_ROOT/active-frps" ] &&
		contains "$CASE_ROOT/cron" unrelated && [ -z "$(backup_path)" ] && proxy_intact
}
check 'FRP uninstall retains all proxy resources and unrelated cron' uninstall_independent
uninstall_firewall_failure() {
	printf 'keep-on-failure 443/tcp\n' >>"$FRPS_DIR/firewall.list"
	if _frps_uninstall; then return 1; fi
	[ -d "$FRPS_DIR" ] && contains "$FRPS_DIR/firewall.list" 'keep-on-failure 443/tcp' && [ -n "$(backup_path)" ] && proxy_intact
}
check 'failed uninstall retains remaining firewall ledger and recovery backup' uninstall_firewall_failure

port_collision() { RESERVED_PORTS='443 tcp'; _frps_check_ports; }
reject_port_collision() { ! port_collision; }
check 'existing proxy port reservation blocks FRP use' reject_port_collision

renew_unchanged() {
	: >"$CASE_ROOT/active-web"
	_frps_renew --cron && absent "$CASE_ROOT/actions" 'restart ' && absent "$CASE_ROOT/actions" 'reload ' && [ -z "$(backup_path)" ]
}
check 'daily certificate check does not restart unchanged services' renew_unchanged
renew_web_changed() {
	FRPS_TLS_METHOD=cf; _frps_save
	: >"$CASE_ROOT/active-web"; : >"$CASE_ROOT/rotate-web"
	_frps_renew --cron && contains "$CASE_ROOT/actions" 'reload web' && absent "$CASE_ROOT/actions" 'restart frps' && contains "$FRPS_DIR/web-cert.pem" changed-web-cert
}
check 'changed public certificate reloads only web service' renew_web_changed
renew_stopped() {
	FRPS_TLS_METHOD=http; _frps_save
	rm -f "$CASE_ROOT/active-frps" "$CASE_ROOT/active-web"
	_frps_renew --cron && absent "$CASE_ROOT/actions" 'web-renew' && absent "$CASE_ROOT/actions" 'start ' && absent "$CASE_ROOT/actions" 'restart '
}
check 'renewal leaves intentionally stopped services stopped' renew_stopped
renew_control_with_stopped_web() {
	eval "$HEALTH_DEFINITION"
	_frps_control_certificate() { printf 'changed-control-cert\n' >"$FRPS_DIR/server-cert.pem"; }
	port_in_use() { return 0; }
	timeout() { return 0; }
	sleep() { return 0; }
	rm -f "$CASE_ROOT/active-web"
	_frps_renew --cron && contains "$FRPS_DIR/server-cert.pem" changed-control-cert &&
		[ -f "$CASE_ROOT/active-frps" ] && [ ! -f "$CASE_ROOT/active-web" ]
}
check 'control certificate rotation succeeds with website intentionally stopped' renew_control_with_stopped_web

background_lock() {
	# Restore only the real process launcher; the fake executable reports whether
	# it inherited the mutation lock descriptor, then exits promptly.
	eval "$SERVICE_DEFINITION"
	INIT=none
	_frps_pid_running() { return 1; }
	cat >"$FRPS_BIN" <<'EOF'
#!/bin/sh
if [ -e /proc/$$/fd/8 ]; then printf 'inherited\n'; else printf 'closed\n'; fi >"$CASE_ROOT/lock-observation"
EOF
	chmod 755 "$FRPS_BIN"
	(_frps_lock && _frps_service start frps) || return 1
	local i
	for i in 1 2 3 4 5 6 7 8 9 10; do [ ! -f "$CASE_ROOT/lock-observation" ] || break; sleep 0.05; done
	contains "$CASE_ROOT/lock-observation" closed
}
check 'background process cannot inherit the management lock descriptor' background_lock
printf 'FRP 生命周期测试: %s 通过, %s 失败\n' "$PASS" "$FAIL"
[ "$FAIL" = 0 ]
