#!/usr/bin/env bash
# Isolated command mocks only: never invoke a real firewall.
# shellcheck disable=SC2034
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/.." && pwd)
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
# shellcheck source=../lib/frps-firewall.sh
. "$ROOT/lib/frps-firewall.sh"
PASS=0 FAIL=0
check() {
	if (FRPS_DIR="$WORK/$1"; mkdir -p "$FRPS_DIR"; has() { return 1; }; host_has_ipv6() { return 0; }; "$@"); then
		PASS=$((PASS + 1))
	else FAIL=$((FAIL + 1)); printf '[失败] %s\n' "$*"; fi
}
valid_ports() { _frps_fw_port_valid 1 && _frps_fw_port_valid 65535 && _frps_fw_port_valid 20000-20100; }
invalid_ports() { local p; for p in 0 65536 01 5-1 1:2 '1;echo' '1-2-3' -1 ''; do ! _frps_fw_port_valid "$p" || return 1; done; }
invalid_proto() { ! _frps_fw_rule open 7000 icmp; }
invalid_action() { ! _frps_fw_rule reset 7000 tcp; }
check valid_ports
check invalid_ports
check invalid_proto
check invalid_action
ledger_idempotent() { _frps_fw_ledger_add 'ufw 7000/tcp' && _frps_fw_ledger_add 'ufw 7000/tcp' && [ "$(wc -l <"$(_frps_fw_ledger)")" = 1 ]; }
ledger_delete_exact() { _frps_fw_ledger_add 'ufw 7000/tcp'; _frps_fw_ledger_add 'ufw 7000/udp'; _frps_fw_ledger_del 'ufw 7000/tcp' && ! _frps_fw_ledger_has 'ufw 7000/tcp' && _frps_fw_ledger_has 'ufw 7000/udp'; }
ledger_no_proxy_migration() { STATE_FILE="$FRPS_DIR/state"; printf 'proxy-state' >"$STATE_FILE"; load_state() { return 99; }; _frps_fw_ledger_add 'ufw 7000/tcp' && [ "$(cat "$(_frps_fw_ledger)")" = 'ufw 7000/tcp' ]; }
ledger_symlink_rejected() { printf unchanged >"$FRPS_DIR/target"; ln -s target "$(_frps_fw_ledger)"; ! _frps_fw_ledger_add 'ufw 7000/tcp' && [ "$(cat "$FRPS_DIR/target")" = unchanged ]; }
check ledger_idempotent
check ledger_delete_exact
check ledger_no_proxy_migration
check ledger_symlink_rejected

ufw_fixture() {
	has() { [ "$1" = ufw ]; }
	: >"$FRPS_DIR/ufw.status"; : >"$FRPS_DIR/ufw.numbered"; : >"$FRPS_DIR/calls"
	UFW_FAIL=''
	ufw() {
		printf '%s\n' "$*" >>"$FRPS_DIR/calls"
		case "$*" in
		'status numbered') [ "$UFW_FAIL" != list ] || return 1; cat "$FRPS_DIR/ufw.numbered" ;;
		status) printf 'Status: active\n'; cat "$FRPS_DIR/ufw.status" ;;
		allow*) [ "$UFW_FAIL" != add ] ;;
		'--force delete'*) [ "$UFW_FAIL" != delete ] ;;
		*) return 99 ;;
		esac
	}
}
ufw_existing_preserved() { ufw_fixture; echo '7000/tcp ALLOW IN Anywhere # user-rule' >"$FRPS_DIR/ufw.status"; _frps_fw_rule open 7000 tcp && [ ! -f "$(_frps_fw_ledger)" ] && ! grep -q '^allow' "$FRPS_DIR/calls"; }
ufw_existing_protocol_agnostic() { ufw_fixture; echo '7000 ALLOW Anywhere' >"$FRPS_DIR/ufw.status"; _frps_fw_rule open 7000 tcp && [ ! -f "$(_frps_fw_ledger)" ]; }
ufw_restricted_not_adopted() { ufw_fixture; echo '7000/tcp ALLOW IN 192.0.2.2' >"$FRPS_DIR/ufw.status"; _frps_fw_rule open 7000 tcp && grep -qx 'allow 7000/tcp comment onebox-frp' "$FRPS_DIR/calls" && _frps_fw_ledger_has 'ufw 7000/tcp'; }
ufw_add_failure_retryable() { ufw_fixture; UFW_FAIL=add; ! _frps_fw_rule open 7000 tcp && _frps_fw_ledger_has 'ufw 7000/tcp'; }
ufw_ledger_failure_no_add() { ufw_fixture; _frps_fw_ledger_add() { return 1; }; ! _frps_fw_rule open 7000 tcp && ! grep -q '^allow' "$FRPS_DIR/calls"; }
ufw_close_only_owner() {
	ufw_fixture; _frps_fw_ledger_add 'ufw 7000/tcp'
	cat >"$FRPS_DIR/ufw.numbered" <<'EOF'
[ 1] 7000/tcp ALLOW IN Anywhere # user
[ 2] 7000/tcp ALLOW IN Anywhere # onebox
[ 3] 7000/tcp ALLOW IN Anywhere # onebox-frp
[ 4] 7000/tcp (v6) ALLOW IN Anywhere (v6) # onebox-frp
[ 5] 7000/udp ALLOW IN Anywhere # onebox-frp
[ 6] 7000/tcp ALLOW IN Anywhere # onebox-frp-other
EOF
	_frps_fw_rule close 7000 tcp && [ "$(grep '^--force' "$FRPS_DIR/calls")" = $'--force delete 4\n--force delete 3' ] && ! _frps_fw_ledger_has 'ufw 7000/tcp'
}
ufw_close_failure_keeps_ledger() { ufw_fixture; _frps_fw_ledger_add 'ufw 7000/tcp'; echo '[ 1] 7000/tcp ALLOW IN Anywhere # onebox-frp' >"$FRPS_DIR/ufw.numbered"; UFW_FAIL=delete; ! _frps_fw_close_all && _frps_fw_ledger_has 'ufw 7000/tcp'; }
ufw_listing_failure_keeps_ledger() { ufw_fixture; _frps_fw_ledger_add 'ufw 7000/tcp'; UFW_FAIL=list; ! _frps_fw_close_all && _frps_fw_ledger_has 'ufw 7000/tcp'; }
ufw_unowned_replacement_preserved() { ufw_fixture; _frps_fw_ledger_add 'ufw 7000/tcp'; echo '[ 1] 7000/tcp ALLOW IN Anywhere # user' >"$FRPS_DIR/ufw.numbered"; _frps_fw_close_all && ! grep -q '^--force' "$FRPS_DIR/calls"; }
ufw_owned_recovered() { ufw_fixture; echo '7000/tcp ALLOW IN Anywhere # onebox-frp' >"$FRPS_DIR/ufw.status"; _frps_fw_rule open 7000 tcp && _frps_fw_ledger_has 'ufw 7000/tcp'; }
ufw_ranges() { ufw_fixture; _frps_fw_rule open 20000-20100 udp && grep -qx 'allow 20000:20100/udp comment onebox-frp' "$FRPS_DIR/calls"; }
check ufw_existing_preserved
check ufw_existing_protocol_agnostic
check ufw_restricted_not_adopted
check ufw_add_failure_retryable
check ufw_ledger_failure_no_add
check ufw_close_only_owner
check ufw_close_failure_keeps_ledger
check ufw_listing_failure_keeps_ledger
check ufw_unowned_replacement_preserved
check ufw_owned_recovered
check ufw_ranges

firewalld_fixture() {
	has() { [ "$1" = firewall-cmd ]; }
	ip() { printf 'default via 192.0.2.1 dev eth0\n'; }
	FW_ZONE=public FW_FAIL=''
	: >"$FRPS_DIR/fw.rules"; : >"$FRPS_DIR/calls"
	firewall-cmd() {
		printf '%s\n' "$*" >>"$FRPS_DIR/calls"
		local scope=runtime zone='' arg action='' port=''
		case "$*" in --state) echo running; return ;; --get-zone-of-interface=*) echo "$FW_ZONE"; return ;; --get-default-zone) echo public; return ;; esac
		for arg in "$@"; do case "$arg" in --zone=*) zone=${arg#*=} ;; --permanent) scope=permanent ;; --query-port=*|--add-port=*|--remove-port=*) action=${arg%%=*}; port=${arg#*=} ;; esac; done
		case "$action" in
		--query-port) [ "$FW_FAIL" != query ] || return 254; grep -qx "$zone $scope $port" "$FRPS_DIR/fw.rules" ;;
		--add-port) [ "$FW_FAIL" != "$scope" ] || return 1; printf '%s\n' "$zone $scope $port" >>"$FRPS_DIR/fw.rules" ;;
		--remove-port) [ "$FW_FAIL" != delete ] || return 1; grep -vx "$zone $scope $port" "$FRPS_DIR/fw.rules" >"$FRPS_DIR/fw.tmp"; mv "$FRPS_DIR/fw.tmp" "$FRPS_DIR/fw.rules" ;;
		*) return 99 ;;
		esac
	}
}
firewalld_existing_preserved() { firewalld_fixture; printf 'public runtime 7000/tcp\npublic permanent 7000/tcp\n' >"$FRPS_DIR/fw.rules"; _frps_fw_rule open 7000 tcp && [ ! -f "$(_frps_fw_ledger)" ]; }
firewalld_existing_runtime_preserved() { firewalld_fixture; echo 'public runtime 7000/tcp' >"$FRPS_DIR/fw.rules"; _frps_fw_rule open 7000 tcp && _frps_fw_ledger_has 'firewalld 7000/tcp public permanent' && ! _frps_fw_ledger_has 'firewalld 7000/tcp public runtime' && _frps_fw_close_all && [ "$(cat "$FRPS_DIR/fw.rules")" = 'public runtime 7000/tcp' ]; }
firewalld_existing_permanent_preserved() { firewalld_fixture; echo 'public permanent 7000/tcp' >"$FRPS_DIR/fw.rules"; _frps_fw_rule open 7000 tcp && _frps_fw_close_all && [ "$(cat "$FRPS_DIR/fw.rules")" = 'public permanent 7000/tcp' ]; }
firewalld_partial_add_cleanup() { firewalld_fixture; FW_FAIL=permanent; ! _frps_fw_rule open 7000 tcp && _frps_fw_ledger_has 'firewalld 7000/tcp public runtime' && _frps_fw_close_all && [ ! -s "$FRPS_DIR/fw.rules" ]; }
firewalld_zone_change_cleanup() { firewalld_fixture; _frps_fw_rule open 7000 tcp || return; FW_ZONE=other; _frps_fw_close_all && [ ! -s "$FRPS_DIR/fw.rules" ] && ! grep -q -- '--zone=other' "$FRPS_DIR/calls"; }
firewalld_delete_failure_keeps_ledger() { firewalld_fixture; _frps_fw_rule open 7000 tcp || return; FW_FAIL=delete; ! _frps_fw_close_all && [ "$(wc -l <"$(_frps_fw_ledger)")" = 2 ]; }
firewalld_query_failure_no_add() { firewalld_fixture; FW_FAIL=query; ! _frps_fw_rule open 7000 tcp && ! grep -q -- '--add-port' "$FRPS_DIR/calls"; }
firewalld_default_zone_fallback() { firewalld_fixture; FW_ZONE=''; _frps_fw_rule open 7000 tcp && _frps_fw_ledger_has 'firewalld 7000/tcp public runtime'; }
check firewalld_existing_preserved
check firewalld_existing_runtime_preserved
check firewalld_existing_permanent_preserved
check firewalld_partial_add_cleanup
check firewalld_zone_change_cleanup
check firewalld_delete_failure_keeps_ledger
check firewalld_query_failure_no_add
check firewalld_default_zone_fallback

iptables_fixture() {
	has() { [ "$1" = iptables ]; }
	IPT_FAIL='' IPT_POLICY=DROP
	: >"$FRPS_DIR/calls"; printf 0 >"$FRPS_DIR/ipt.count"
	iptables() {
		printf '%s\n' "$*" >>"$FRPS_DIR/calls"
		local n; n=$(cat "$FRPS_DIR/ipt.count")
		case "$*" in
		'-S INPUT') [ "$IPT_FAIL" != list ] || return 4; echo "-P INPUT $IPT_POLICY" ;;
		'-t filter -C'*) [ "$IPT_FAIL" != comment ] || return 2; [ "$n" -gt 0 ] ;;
		'-t filter -I'*) [ "$IPT_FAIL" != add ] || return 4; printf '%s' "$((n+1))" >"$FRPS_DIR/ipt.count" ;;
		'-t filter -D'*) [ "$IPT_FAIL" != delete ] || return 4; printf '%s' "$((n-1))" >"$FRPS_DIR/ipt.count" ;;
		*) return 99 ;;
		esac
	}
}
iptables_roundtrip_only_owner() { iptables_fixture; _frps_fw_rule open 7000 tcp && _frps_fw_rule open 7000 tcp && [ "$(cat "$FRPS_DIR/ipt.count")" = 1 ] && _frps_fw_close_all && [ "$(cat "$FRPS_DIR/ipt.count")" = 0 ] && ! grep -- '-[CID] INPUT' "$FRPS_DIR/calls" | grep -vq -- '--comment onebox-frp '; }
iptables_no_comment_no_plain() { iptables_fixture; IPT_FAIL=comment; ! _frps_fw_rule open 7000 tcp && ! grep -q -- '-I INPUT' "$FRPS_DIR/calls"; }
iptables_partial_add_retryable() { iptables_fixture; IPT_FAIL=add; ! _frps_fw_rule open 7000 tcp && _frps_fw_ledger_has 'iptables 7000/tcp'; }
iptables_delete_failure_keeps_ledger() { iptables_fixture; _frps_fw_rule open 7000 tcp || return; IPT_FAIL=delete; ! _frps_fw_close_all && _frps_fw_ledger_has 'iptables 7000/tcp'; }
iptables_open_policy_no_rule() { iptables_fixture; IPT_POLICY=ACCEPT; _frps_fw_rule open 7000 tcp && [ ! -f "$(_frps_fw_ledger)" ]; }
iptables_inspection_failure() { iptables_fixture; IPT_FAIL=list; ! _frps_fw_rule open 7000 tcp; }
iptables_missing_rule_close() { iptables_fixture; _frps_fw_ledger_add 'iptables 7000/tcp'; _frps_fw_close_all && ! _frps_fw_ledger_has 'iptables 7000/tcp'; }
check iptables_roundtrip_only_owner
check iptables_no_comment_no_plain
check iptables_partial_add_retryable
check iptables_delete_failure_keeps_ledger
check iptables_open_policy_no_rule
check iptables_inspection_failure
check iptables_missing_rule_close

nft_fixture() {
	has() { [ "$1" = nft ]; }
	NFT_FAIL=''
	: >"$FRPS_DIR/calls"; : >"$FRPS_DIR/nft.rules"
	nft() {
		printf '%s\n' "$*" >>"$FRPS_DIR/calls"
		case "$*" in
		'list ruleset') printf 'table inet filter {\n chain input {\n type filter hook input priority 0; policy drop;\n }\n}\n' ;;
		'list chain'*|'-a list chain'*) [ "$NFT_FAIL" != list ] || return 1; cat "$FRPS_DIR/nft.rules" ;;
		'insert rule'*) [ "$NFT_FAIL" != add ] || return 1; echo 'tcp dport 7000 accept comment "onebox-frp" # handle 12' >>"$FRPS_DIR/nft.rules" ;;
		'delete rule'*) [ "$NFT_FAIL" != delete ] || return 1; grep -v '# handle 12$' "$FRPS_DIR/nft.rules" >"$FRPS_DIR/nft.tmp"; mv "$FRPS_DIR/nft.tmp" "$FRPS_DIR/nft.rules" ;;
		*) return 99 ;;
		esac
	}
}
nft_roundtrip_only_owner() { nft_fixture; echo 'tcp dport 7000 accept comment "onebox" # handle 11' >"$FRPS_DIR/nft.rules"; _frps_fw_rule open 7000 tcp && _frps_fw_ledger_has 'nft 7000/tcp inet filter input' && _frps_fw_close_all && [ "$(cat "$FRPS_DIR/nft.rules")" = 'tcp dport 7000 accept comment "onebox" # handle 11' ]; }
nft_policy_change_cleanup() { nft_fixture; _frps_fw_rule open 7000 tcp || return; _frps_fw_nft_chains() { return 0; }; _frps_fw_close_all && [ ! -s "$FRPS_DIR/nft.rules" ]; }
nft_add_failure_keeps_ledger() { nft_fixture; NFT_FAIL=add; ! _frps_fw_rule open 7000 tcp && _frps_fw_ledger_has 'nft 7000/tcp inet filter input'; }
nft_delete_failure_keeps_ledger() { nft_fixture; _frps_fw_rule open 7000 tcp || return; NFT_FAIL=delete; ! _frps_fw_close_all && _frps_fw_ledger_has 'nft 7000/tcp inet filter input'; }
nft_inspection_failure() { nft_fixture; NFT_FAIL=list; ! _frps_fw_rule open 7000 tcp; }
check nft_roundtrip_only_owner
check nft_policy_change_cleanup
check nft_add_failure_keeps_ledger
check nft_delete_failure_keeps_ledger
check nft_inspection_failure

batch_fixture() { FRPS_BIND_PORT=7000; : >"$FRPS_DIR/batch"; _frps_fw_rule() { printf '%s %s %s\n' "$@" >>"$FRPS_DIR/batch"; }; }
web_batch_no_internal_port() { batch_fixture; FRPS_MODE=web FRPS_HTTPS_PORT=443 FRPS_REDIRECT_PORT=80 FRPS_HTTP_PORT=7080; _frps_fw_apply open && [ "$(cat "$FRPS_DIR/batch")" = $'open 7000 tcp\nopen 443 tcp\nopen 80 tcp' ]; }
web_batch_zero_skipped() { batch_fixture; FRPS_MODE=web FRPS_HTTPS_PORT=443 FRPS_REDIRECT_PORT=0; _frps_fw_apply open && [ "$(wc -l <"$FRPS_DIR/batch")" = 2 ]; }
tcp_batch_range() { batch_fixture; FRPS_MODE=tcp FRPS_RANGE_START=20000 FRPS_RANGE_END=20100; _frps_fw_apply open && [ "$(cat "$FRPS_DIR/batch")" = $'open 7000 tcp\nopen 20000-20100 tcp\nopen 20000-20100 udp' ]; }
invalid_batch_no_mutation() { batch_fixture; FRPS_MODE=tcp FRPS_RANGE_START=20000 FRPS_RANGE_END=10000; ! _frps_fw_apply open && [ ! -s "$FRPS_DIR/batch" ]; }
batch_failure_reported() { batch_fixture; FRPS_MODE=web FRPS_HTTPS_PORT=443 FRPS_REDIRECT_PORT=80; _frps_fw_rule() { printf '%s\n' "$2" >>"$FRPS_DIR/batch"; [ "$2" != 443 ]; }; ! _frps_fw_apply open && [ "$(wc -l <"$FRPS_DIR/batch")" = 3 ]; }
close_all_backend_unavailable_retained() { _frps_fw_ledger_add 'ufw 7000/tcp'; ! _frps_fw_close_all && _frps_fw_ledger_has 'ufw 7000/tcp'; }
close_all_malformed_retained() { _frps_fw_ledger_add 'iptables 1;echo/tcp'; ! _frps_fw_close_all && _frps_fw_ledger_has 'iptables 1;echo/tcp'; }
close_only_matching_key() { _frps_fw_ledger_add 'ufw 7000/tcp'; _frps_fw_ledger_add 'ufw 8000/tcp'; _frps_fw_close_entry() { _frps_fw_ledger_del "$1"; }; _frps_fw_rule close 7000 tcp && [ "$(cat "$(_frps_fw_ledger)")" = 'ufw 8000/tcp' ]; }
check web_batch_no_internal_port
check web_batch_zero_skipped
check tcp_batch_range
check invalid_batch_no_mutation
check batch_failure_reported
check close_all_backend_unavailable_retained
check close_all_malformed_retained
check close_only_matching_key
printf 'FRP 防火墙回归: %s 通过, %s 失败\n' "$PASS" "$FAIL"
[ "$FAIL" = 0 ]
