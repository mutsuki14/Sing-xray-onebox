#!/usr/bin/env bash
# Real cores, loopback only; no services, firewall or public traffic.
# Required XR; optional SB enables tuned Hysteria2 coverage.
# shellcheck disable=SC2034
set -eu
ROOT=$(cd "$(dirname "$0")/.." && pwd)
WORK=$(mktemp -d)
XR=$(readlink -f "${XR:?set XR}")
SB=${SB:-}
[ -z "$SB" ] || SB=$(readlink -f "$SB")
PIDS=()
cleanup() {
	local pid
	for pid in "${PIDS[@]}"; do kill "$pid" 2>/dev/null || true; done
	for pid in "${PIDS[@]}"; do wait "$pid" 2>/dev/null || true; done
	if [ "${KEEP:-0}" = 1 ]; then echo "$WORK"; else rm -rf "$WORK"; fi
}
trap cleanup EXIT
export ONEBOX_SOURCE_ONLY=1 ONEBOX_DIR="$WORK/etc" ONEBOX_SITE_ROOT="$WORK/www"
# shellcheck source=../onebox.sh
. "$ROOT/onebox.sh"
reset_state
XR_BIN=$XR SB_BIN=$SB
SERVER_ADDR=127.0.0.1 SERVER_IPV4=127.0.0.1 LISTEN_ADDR=127.0.0.1
BLOCK_PRIVATE=0 BLOCK_BT=0 NODE_NAME=e2e
PROTOCOLS=shadowsocks SS_METHOD=2022-blake3-aes-128-gcm
SS_PASSWORD=$(gen_ss_password "$SS_METHOD")
pset CORE shadowsocks xray
free_port() { python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])'; }
for name in tcp-a tcp-b; do
	pset PORT shadowsocks "$(free_port)"
	gen_xray_server >"$WORK/$name.json"
	"$XR" run -c "$WORK/$name.json" >"$WORK/$name.log" 2>&1 &
	PIDS+=("$!")
	gen_probe_bundle | jq --arg name "$name" '.entries[0].id=$name' >"$WORK/$name-bundle.json"
done
if [ -n "$SB" ]; then
	PROTOCOLS=hysteria2 PASSWORD=private-hy2-test TLS_MODE=self TLS_SNI=localhost
	CERT_FILE="$WORK/cert.pem" KEY_FILE="$WORK/key.pem"
	openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout "$KEY_FILE" -out "$CERT_FILE" \
		-days 1 -subj '/CN=localhost' -addext 'subjectAltName=DNS:localhost' >"$WORK/pki.log" 2>&1
	pset CORE hysteria2 singbox
	for profile in auto conservative measured; do
		pset PORT hysteria2 "$(free_port)"
		HY2_PROFILE=$profile HY2_UP_MBPS=20 HY2_DOWN_MBPS=30 RESOURCE_PROFILE=low-memory
		[ "$profile" != measured ] || RESOURCE_PROFILE=throughput
		validate_tuning
		gen_singbox_server >"$WORK/$profile.json"
		"$SB" check -c "$WORK/$profile.json" >"$WORK/$profile-check.log" 2>&1
		"$SB" run -c "$WORK/$profile.json" >"$WORK/$profile.log" 2>&1 &
		PIDS+=("$!")
		gen_probe_bundle | jq --arg name "udp-$profile" '.entries[0].id=$name' >"$WORK/udp-$profile-bundle.json"
	done
fi
python3 "$ROOT/lib/client_runtime.py" merge "$WORK/bundle.json" "$WORK/"*-bundle.json
python3 "$ROOT/tests/client_runtime_e2e.py" "$WORK" "$XR" "$SB" "${PIDS[0]}"
