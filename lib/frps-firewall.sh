#!/usr/bin/env bash
# FRP-owned firewall rules. Embedded into onebox.sh; no proxy-state migration.
# Journal each new rule before applying it so a partial failure remains retryable.

_frps_fw_ledger() { printf '%s/firewall.list' "$FRPS_DIR"; }
_frps_fw_ledger_has() { grep -qxF "$1" "$(_frps_fw_ledger)" 2>/dev/null; }
_frps_fw_ledger_add() (
	umask 077
	local f tmp
	f=$(_frps_fw_ledger)
	[ ! -L "$f" ] && [ ! -L "$FRPS_DIR" ] || return 1
	_frps_fw_ledger_has "$1" && return 0
	mkdir -p "$FRPS_DIR" || return 1
	tmp=$(mktemp "$FRPS_DIR/.firewall.XXXXXX") || return 1
	if { [ ! -e "$f" ] || cat "$f"; } >"$tmp" && printf '%s\n' "$1" >>"$tmp" && mv -f "$tmp" "$f"; then
		return 0
	fi
	rm -f "$tmp"
	return 1
)
_frps_fw_ledger_del() (
	umask 077
	local f tmp rc
	f=$(_frps_fw_ledger)
	[ ! -L "$f" ] || return 1
	[ -f "$f" ] || return 0
	tmp=$(mktemp "$FRPS_DIR/.firewall.XXXXXX") || return 1
	grep -vxF "$1" "$f" >"$tmp"; rc=$?
	if [ "$rc" -le 1 ] && mv -f "$tmp" "$f"; then return 0; fi
	rm -f "$tmp"
	return 1
)
_frps_fw_port_valid() {
	local first last
	[[ "$1" =~ ^[1-9][0-9]{0,4}(-[1-9][0-9]{0,4})?$ ]] || return 1
	first=${1%%-*}; last=${1##*-}
	[ "$first" -le "$last" ] && [ "$last" -le 65535 ]
}
_frps_fw_ufw_active() { has ufw && LC_ALL=C ufw status 2>/dev/null | grep -q '^Status: active'; }
_frps_fw_firewalld_active() { has firewall-cmd && [ "$(firewall-cmd --state 2>/dev/null)" = running ]; }

# Only delete UFW rules with our exact owner comment. Numbered deletions run
# backwards to preserve numbering, including separate IPv4 and IPv6 entries.
_frps_fw_ufw_numbers() {
	local port=${1/-/:} proto=$2 listing
	listing=$(LC_ALL=C ufw status numbered 2>/dev/null) || return 1
	printf '%s\n' "$listing" | awk -v p="$port" -v proto="$proto" '
		/ on |OUT|FWD/ { next }
		/#[[:space:]]*onebox-frp[[:space:]]*$/ {
			line=$0; sub(/^\[[[:space:]]*/, "", line); n=line; sub(/\].*$/, "", n)
			sub(/^[^]]*\][[:space:]]*/, "", line); split(line,a,/[[:space:]]+/)
			if (a[1] == p "/" proto && line ~ /ALLOW( IN)?[[:space:]]+Anywhere/) print n
		}' | sort -rn
}
_frps_fw_ufw_open() {
	local port=$1 proto=$2 status key="ufw $1/$2" ipt_port=${1/-/:}
	status=$(LC_ALL=C ufw status 2>/dev/null) || return 1
	if printf '%s\n' "$status" | grep -vE ' on |OUT|FWD' |
		grep -qE "^${ipt_port}(/${proto})?( \\(v6\\))?[[:space:]]+ALLOW( IN)?[[:space:]]+Anywhere"; then
		# A prior owned rule may survive a lost ledger; ownership is its comment.
		if printf '%s\n' "$status" | grep -vE ' on |OUT|FWD' |
			grep -E "^${ipt_port}/${proto}( \\(v6\\))?[[:space:]]+ALLOW( IN)?[[:space:]]+Anywhere" |
			grep -qE '#[[:space:]]*onebox-frp[[:space:]]*$'; then
			_frps_fw_ledger_add "$key" || return 1
		fi
		return 0
	fi
	_frps_fw_ledger_add "$key" || return 1
	ufw allow "${ipt_port}/${proto}" comment onebox-frp >/dev/null 2>&1
}
_frps_fw_firewalld_zone() {
	local dev zone=''
	dev=$(ip route show default 2>/dev/null | awk '{for(i=1;i<NF;i++) if($i=="dev") {print $(i+1);exit}}')
	[ -n "$dev" ] || dev=$(ip -6 route show default 2>/dev/null | awk '{for(i=1;i<NF;i++) if($i=="dev") {print $(i+1);exit}}')
	if [ -n "$dev" ]; then zone=$(firewall-cmd --get-zone-of-interface="$dev" 2>/dev/null) || zone=''; fi
	[ -n "$zone" ] || zone=$(firewall-cmd --get-default-zone 2>/dev/null) || return 1
	[[ "$zone" =~ ^[a-zA-Z0-9_.-]+$ ]] || return 1
	printf '%s' "$zone"
}
_frps_fw_firewalld_open() {
	local port=$1 proto=$2 zone scope rc args=()
	zone=$(_frps_fw_firewalld_zone) || return 1
	for scope in runtime permanent; do
		args=(--zone="$zone"); [ "$scope" != permanent ] || args+=(--permanent)
		firewall-cmd "${args[@]}" --query-port="$port/$proto" >/dev/null 2>&1; rc=$?
		[ "$rc" -ne 0 ] || continue # Never adopt pre-existing runtime/permanent rules.
		[ "$rc" = 1 ] || return 1
		_frps_fw_ledger_add "firewalld $port/$proto $zone $scope" || return 1
		firewall-cmd "${args[@]}" --add-port="$port/$proto" >/dev/null 2>&1 || return 1
	done
}
_frps_fw_iptables_open() {
	local tool=$1 port=$2 proto=$3 rules rc
	rules=$("$tool" -S INPUT 2>/dev/null) || return 1
	printf '%s\n' "$rules" | grep -qE '^-P INPUT (DROP|REJECT)|-j (REJECT|DROP)' || return 0
	"$tool" -t filter -C INPUT -p "$proto" --dport "${port/-/:}" -m comment --comment onebox-frp -j ACCEPT 2>/dev/null; rc=$?
	[ "$rc" -le 1 ] || return 1
	_frps_fw_ledger_add "$tool $port/$proto" || return 1
	[ "$rc" != 0 ] || return 0
	# No unowned fallback if xt_comment is unavailable.
	"$tool" -t filter -I INPUT -p "$proto" --dport "${port/-/:}" -m comment --comment onebox-frp -j ACCEPT 2>/dev/null
}
_frps_fw_nft_chains() {
	local rules
	rules=$(nft list ruleset 2>/dev/null) || return 1
	printf '%s\n' "$rules" | awk '
		$1=="table" {fam=$2;tbl=$3;next}
		$1=="chain" {ch=$2;hook=0;blk=0;next}
		/hook input/ {hook=1;if(/policy drop/)blk=1;next}
		hook && /^[[:space:]]*(counter( packets [0-9]+ bytes [0-9]+)? )?(drop|reject)/ {blk=1;next}
		$1=="}" && ch!="" {if(hook&&blk&&ch!="INPUT"&&tbl!="firewalld")print fam,tbl,ch;ch="";hook=0;blk=0}'
}
_frps_fw_nft_open() {
	local port=$1 proto=$2 chains fam tbl chain listing rule rc=0
	chains=$(_frps_fw_nft_chains) || return 1
	rule="$proto dport $port accept comment \"onebox-frp\""
	while read -r fam tbl chain; do
		[ -n "$chain" ] || continue
		[[ "$fam" =~ ^(ip|ip6|inet)$ && "$tbl" =~ ^[a-zA-Z0-9_.-]+$ && "$chain" =~ ^[a-zA-Z0-9_.-]+$ ]] || { rc=1; continue; }
		listing=$(nft list chain "$fam" "$tbl" "$chain" 2>/dev/null) || { rc=1; continue; }
		_frps_fw_ledger_add "nft $port/$proto $fam $tbl $chain" || { rc=1; continue; }
		printf '%s\n' "$listing" | grep -qF "$rule" && continue
		nft insert rule "$fam" "$tbl" "$chain" "$proto" dport "$port" accept comment '"onebox-frp"' 2>/dev/null || rc=1
	done <<<"$chains"
	return "$rc"
}

# Close the exact journal entry, regardless of current firewall backend/zone.
# Do not discard entries on failure: callers can retry after fixing the backend.
_frps_fw_close_entry() {
	local entry=$1 backend key a b c extra port proto rc listing rule handles h args=()
	read -r backend key a b c extra <<<"$entry"
	port=${key%/*}; proto=${key##*/}
	_frps_fw_port_valid "$port" && [[ "$proto" =~ ^(tcp|udp)$ ]] && [ -z "$extra" ] || return 1
	case "$backend" in
	ufw)
		[ -z "$a$b$c" ] && has ufw || return 1
		handles=$(_frps_fw_ufw_numbers "$port" "$proto") || return 1
		for h in $handles; do [[ "$h" =~ ^[0-9]+$ ]] || return 1; ufw --force delete "$h" >/dev/null 2>&1 || return 1; done
		;;
	firewalld)
		[[ "$a" =~ ^[a-zA-Z0-9_.-]+$ && "$b" =~ ^(runtime|permanent)$ ]] && [ -z "$c" ] && has firewall-cmd || return 1
		args=(--zone="$a"); [ "$b" != permanent ] || args+=(--permanent)
		firewall-cmd "${args[@]}" --query-port="$key" >/dev/null 2>&1; rc=$?
		case "$rc" in 0) firewall-cmd "${args[@]}" --remove-port="$key" >/dev/null 2>&1 || return 1 ;; 1) : ;; *) return 1 ;; esac
		;;
	iptables | ip6tables)
		[ -z "$a$b$c" ] && has "$backend" || return 1
		while :; do
			"$backend" -t filter -C INPUT -p "$proto" --dport "${port/-/:}" -m comment --comment onebox-frp -j ACCEPT 2>/dev/null; rc=$?
			case "$rc" in 0) ;; 1) break ;; *) return 1 ;; esac
			"$backend" -t filter -D INPUT -p "$proto" --dport "${port/-/:}" -m comment --comment onebox-frp -j ACCEPT 2>/dev/null || return 1
		done
		;;
	nft)
		[[ "$a" =~ ^(ip|ip6|inet)$ && "$b" =~ ^[a-zA-Z0-9_.-]+$ && "$c" =~ ^[a-zA-Z0-9_.-]+$ ]] && has nft || return 1
		# The chain may now accept traffic; locate the recorded chain directly.
		listing=$(nft -a list chain "$a" "$b" "$c" 2>/dev/null) || return 1
		rule="$proto dport $port accept comment \"onebox-frp\""
		handles=$(printf '%s\n' "$listing" | grep -F "$rule" | sed -n 's/.*# handle \([0-9]*\).*/\1/p')
		for h in $handles; do nft delete rule "$a" "$b" "$c" handle "$h" 2>/dev/null || return 1; done
		;;
	*) return 1 ;;
	esac
	_frps_fw_ledger_del "$entry"
}
_frps_fw_close_all() {
	local entry entries rc=0 f
	f=$(_frps_fw_ledger)
	[ ! -L "$f" ] || return 1
	[ -f "$f" ] || return 0
	entries=$(cat "$f") || return 1
	while IFS= read -r entry; do
		[ -n "$entry" ] || continue
		_frps_fw_close_entry "$entry" || rc=1
	done <<<"$entries"
	return "$rc"
}
_frps_fw_rule() {
	local act=$1 port=$2 proto=$3 rc=0 tool entry entries backend key rest
	_frps_fw_port_valid "$port" && [[ "$proto" =~ ^(tcp|udp)$ ]] || return 1
	case "$act" in
	close)
		[ ! -L "$(_frps_fw_ledger)" ] || return 1
		[ -f "$(_frps_fw_ledger)" ] || return 0
		entries=$(cat "$(_frps_fw_ledger)") || return 1
		while IFS= read -r entry; do
			read -r backend key rest <<<"$entry"
			[ "$key" != "$port/$proto" ] || _frps_fw_close_entry "$entry" || rc=1
		done <<<"$entries"
		return "$rc"
		;;
	open) ;;
	*) return 1 ;;
	esac
	if _frps_fw_ufw_active; then _frps_fw_ufw_open "$port" "$proto"; return $?; fi
	if _frps_fw_firewalld_active; then _frps_fw_firewalld_open "$port" "$proto"; return $?; fi
	for tool in iptables ip6tables; do
		has "$tool" || continue
		[ "$tool" != ip6tables ] || host_has_ipv6 || continue
		_frps_fw_iptables_open "$tool" "$port" "$proto" || rc=1
	done
	if has nft; then _frps_fw_nft_open "$port" "$proto" || rc=1; fi
	return "$rc"
}
_frps_fw_apply() {
	local act=${1:-open} rc=0 port range
	case "$act" in open | close) ;; *) return 1 ;; esac
	[[ "$FRPS_MODE" =~ ^(web|tcp)$ ]] || return 1
	_frps_fw_port_valid "$FRPS_BIND_PORT" && [[ "$FRPS_BIND_PORT" != *-* ]] || return 1
	if [ "$FRPS_MODE" = web ]; then
		for port in "$FRPS_HTTPS_PORT" "$FRPS_REDIRECT_PORT"; do
			[ "$port" = 0 ] || { _frps_fw_port_valid "$port" && [[ "$port" != *-* ]]; } || return 1
		done
	else
		range="$FRPS_RANGE_START-$FRPS_RANGE_END"
		_frps_fw_port_valid "$range" || return 1
	fi
	_frps_fw_rule "$act" "$FRPS_BIND_PORT" tcp || rc=1
	if [ "$FRPS_MODE" = web ]; then
		for port in "$FRPS_HTTPS_PORT" "$FRPS_REDIRECT_PORT"; do
			[ "$port" = 0 ] || _frps_fw_rule "$act" "$port" tcp || rc=1
		done
	else
		_frps_fw_rule "$act" "$range" tcp || rc=1
		_frps_fw_rule "$act" "$range" udp || rc=1
	fi
	return "$rc"
}
