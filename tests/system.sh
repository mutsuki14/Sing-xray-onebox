#!/usr/bin/env bash
# 系统集成失败路径: 只使用临时目录和命令 mock, 不修改系统服务/防火墙。
# shellcheck disable=SC2034
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/.." && pwd)
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
export ONEBOX_SOURCE_ONLY=1 ONEBOX_DIR="$WORK/etc" ONEBOX_INITD_DIR="$WORK/initd" NO_COLOR=1
# shellcheck source=../onebox.sh
. "$ROOT/onebox.sh"
reset_state
mkdir -p "$ONEBOX_DIR" "$INITD_DIR"
PASS=0 FAIL=0
check() {
	if ( "$@" ); then PASS=$((PASS + 1)); else
		FAIL=$((FAIL + 1)); printf '[失败] %s\n' "$*"
	fi
}

fw_batch_failure() {
	PROTOCOLS='shadowsocks hysteria2'
	pset PORT shadowsocks 8388; pset PORT hysteria2 8443
	_fw_ledger_migrate() { :; }
	fw_rule() { printf '%s %s\n' "$2" "$3" >>"$WORK/fw-batch"; [ "$2/$3" != 8388/tcp ]; }
	site_enabled() { return 1; }
	! fw_apply open && [ "$(wc -l <"$WORK/fw-batch")" = 3 ]
}
check fw_batch_failure

firewalld_fixture() {
	rm -f "$(_fw_ledger)"
	_fw_ufw_active() { return 1; }
	_fw_firewalld_active() { return 0; }
	ip() { echo 'default via 192.0.2.1 dev eth0'; }
}
firewalld_default_zone() {
	firewalld_fixture
	firewall-cmd() {
		case "$*" in
		--get-zone-of-interface=*) echo 'no zone'; return 1 ;;
		*--zone=*) return 2 ;;
		*--query-port=*) return 1 ;;
		esac
		return 0
	}
	fw_rule open 443 tcp && _fw_ledger_has 'firewalld 443/tcp'
}
check firewalld_default_zone

firewalld_ipv6_zone() {
	firewalld_fixture
	ip() { [ "$1" = -6 ] && echo 'default via 2001:db8::1 dev eth6'; return 0; }
	firewall-cmd() {
		case "$*" in
		--get-zone-of-interface=eth6) echo public6 ;;
		*--query-port=*) return 1 ;;
		--zone=public6*) return 0 ;;
		*) return 2 ;;
		esac
	}
	fw_rule open 443 tcp
}
check firewalld_ipv6_zone

firewalld_partial_add_tracked() {
	firewalld_fixture
	firewall-cmd() {
		case "$*" in --get-zone-of-interface=*) echo public ;; *--query-port=*|*--permanent*--add-port=*) return 1 ;; *) return 0 ;; esac
	}
	! fw_rule open 443 tcp && _fw_ledger_has 'firewalld 443/tcp'
}
check firewalld_partial_add_tracked

iptables_add_failure() {
	_fw_ufw_active() { return 1; }; _fw_firewalld_active() { return 1; }
	has() { [ "$1" = iptables ]; }
	_fw_iptables_blocking() { return 0; }
	iptables() { return 4; }
	_fw_nft() { return 0; }
	! fw_rule open 443 tcp
}
check iptables_add_failure

iptables_delete_failure_keeps_ledger() {
	_fw_ufw_active() { return 1; }; _fw_firewalld_active() { return 1; }
	has() { [ "$1" = iptables ]; }
	iptables() { return 4; }
	_fw_nft() { return 0; }
	printf 'iptables 443/tcp\n' >"$(_fw_ledger)"
	! fw_rule close 443 tcp && _fw_ledger_has 'iptables 443/tcp'
}
check iptables_delete_failure_keeps_ledger

iptables_delete_missing_is_idempotent() {
	iptables() { return 1; }
	_ipt_rule iptables del filter INPUT -p tcp --dport 443 -- -j ACCEPT
}
check iptables_delete_missing_is_idempotent

nft_add_failure() {
	_fw_nft_block_chains() { echo 'inet filter input'; }
	nft() { case "$1" in list) return 0 ;; insert) return 1 ;; esac; }
	! _fw_nft open 443 tcp
}
check nft_add_failure

nft_delete_failure() {
	_fw_nft_block_chains() { echo 'inet filter input'; }
	nft() { case "$1" in -a) echo 'tcp dport 443 accept comment "onebox" # handle 12' ;; delete) return 1 ;; esac; }
	! _fw_nft close 443 tcp
}
check nft_delete_failure

nft_inspection_failure() {
	has() { [ "$1" = nft ]; }
	nft() { return 1; }
	! _fw_nft open 443 tcp
}
check nft_inspection_failure

nft_delete_inspection_failure() {
	_fw_nft_block_chains() { echo 'inet filter input'; }
	nft() { return 1; }
	! _fw_nft close 443 tcp
}
check nft_delete_inspection_failure

service_fixture() {
	PROTOCOLS=vless-reality; pset CORE vless-reality singbox
	site_apply_service() { :; }
	svc_write() { :; }; svc_enable() { :; }; svc_exists() { return 1; }
	svc_stop() { :; }; svc_start() { :; }; svc_active() { return 0; }
	sleep() { :; }; info() { :; }
}
service_write_failure() { service_fixture; svc_write() { return 1; }; ! apply_services; }
service_enable_failure() { service_fixture; svc_enable() { return 1; }; ! apply_services; }
service_stop_failure_with_old_process_active() { service_fixture; svc_stop() { return 1; }; ! apply_services; }
service_start_failure_with_old_process_active() { service_fixture; svc_start() { return 1; }; ! apply_services; }
check service_write_failure
check service_enable_failure
check service_stop_failure_with_old_process_active
check service_start_failure_with_old_process_active

service_stop_propagates_error() {
	INIT=systemd
	systemctl() { return 1; }
	! svc_stop singbox
}
check service_stop_propagates_error

service_remove_preserves_failed_stop() {
	INIT=openrc
	printf 'original unit\n' >"$INITD_DIR/$SB_SERVICE"
	svc_stop() { return 1; }
	! svc_remove singbox && [ -f "$INITD_DIR/$SB_SERVICE" ]
}
check service_remove_preserves_failed_stop

service_write_openrc_failure() {
	INIT=openrc
	INITD_DIR="$WORK/missing/initd"
	! svc_write singbox 2>/dev/null
}
check service_write_openrc_failure

cron_write_failure() {
	has() { [ "$1" = crontab ]; }
	crontab() { return 1; }
	! _none_autostart_add
}
check cron_write_failure

hop_persistence_failure() {
	PROTOCOLS=''; HY2_HOP=''
	hop_rules() { :; }
	net_persist() { return 1; }
	! hop_setup
}
check hop_persistence_failure

acme_firewall_failure_tracks_partial_changes() {
	CERT_TXN_FW80=0
	site_enabled() { return 1; }
	acme_install() { :; }
	has() { return 0; }
	port_taken_by_other() { return 1; }
	port_in_use() { return 1; }
	_fw_snapshot() { cat "$WORK/acme-fw" 2>/dev/null; }
	fw_rule() { printf 'partial runtime opening\n' >"$WORK/acme-fw"; return 1; }
	acme() { : >"$WORK/unexpected-acme"; return 0; }
	! cert_acme test.example.com standalone 2>/dev/null &&
		[ "$CERT_TXN_FW80" = 1 ] && [ ! -e "$WORK/unexpected-acme" ]
}
check acme_firewall_failure_tracks_partial_changes

cron_delete_failure() {
	has() { [ "$1" = crontab ]; }
	crontab() {
		if [ "$1" = -l ]; then printf '@reboot %s start\n' "$CMD_PATH"; else return 1; fi
	}
	! _none_autostart_del
}
check cron_delete_failure

cron_delete_missing_is_idempotent() {
	has() { [ "$1" = crontab ]; }
	crontab() { [ "$1" = -l ] || return 1; printf '# unrelated task\n'; }
	_none_autostart_del
}
check cron_delete_missing_is_idempotent

cron_delete_preserves_other_jobs() {
	has() { [ "$1" = crontab ]; }
	crontab() {
		if [ "$1" = -l ]; then printf '# unrelated task\n@reboot %s start\n' "$CMD_PATH"; else cat >"$WORK/remaining-cron"; fi
	}
	_none_autostart_del && [ "$(cat "$WORK/remaining-cron")" = '# unrelated task' ]
}
check cron_delete_preserves_other_jobs

net_delete_fixture() {
	INIT=systemd
	_net_service_file() { printf '%s/net.service' "$WORK"; }
	printf 'original unit\n' >"$WORK/net.service"
	systemctl() { return 0; }
	rm() { return 0; }
}
net_delete_disable_failure() {
	net_delete_fixture
	systemctl() { [ "$1" != disable ]; }
	! net_persist del && [ -f "$WORK/net.service" ]
}
check net_delete_disable_failure

net_delete_remove_failure() {
	net_delete_fixture
	rm() { return 1; }
	! net_persist del
}
check net_delete_remove_failure

net_delete_reload_failure() {
	net_delete_fixture
	systemctl() { [ "$1" != daemon-reload ]; }
	! net_persist del
}
check net_delete_reload_failure

net_delete_missing_is_idempotent() {
	net_delete_fixture
	_net_service_file() { printf '%s/missing-net.service' "$WORK"; }
	systemctl() { return 1; }
	net_persist del
}
check net_delete_missing_is_idempotent

net_openrc_delete_failure() {
	INIT=openrc
	rm() { return 1; }
	! net_persist del
}
check net_openrc_delete_failure

printf '系统集成回归: %s 通过, %s 失败\n' "$PASS" "$FAIL"
[ "$FAIL" = 0 ]
