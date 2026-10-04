#!/usr/bin/env bash
# Pure configuration/state tests. No system services or sysctl writes.
# shellcheck disable=SC2034
set -eu
ROOT=$(cd "$(dirname "$0")/.." && pwd)
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
export ONEBOX_SOURCE_ONLY=1 ONEBOX_DIR="$WORK/etc" ONEBOX_SITE_ROOT="$WORK/site"
# shellcheck source=../onebox.sh
. "$ROOT/onebox.sh"
reset_state
PROTOCOLS='hysteria2 vless-reality'
pset CORE hysteria2 singbox; pset CORE vless-reality xray
pset PORT hysteria2 4443; pset PORT vless-reality 443
SERVER_ADDR=203.0.113.1 LISTEN_ADDR=127.0.0.1 NODE_NAME=perf
UUID=550e8400-e29b-41d4-a716-446655440000 PASSWORD=secret
TLS_MODE=acme DOMAIN=example.org CERT_FILE=/not-read.pem KEY_FILE=/not-read.key
REALITY_SNI=example.org REALITY_DEST=example.org:443
REALITY_PRIVATE_KEY=must-never-export REALITY_PUBLIC_KEY=public REALITY_SHORT_ID=0123abcd
sb_installed_version() { echo 1.14.2; }
PASS=0
check() { "$@" || { echo "FAIL: $*" >&2; exit 1; }; PASS=$((PASS + 1)); }
reject() { if "$@" 2>/dev/null; then echo "unexpected success: $*" >&2; exit 1; fi; PASS=$((PASS + 1)); }

HY2_PROFILE=measured HY2_UP_MBPS=20 HY2_DOWN_MBPS=100
check validate_tuning
check jq -e '.up_mbps == 100 and .down_mbps == 20' < <(sb_inbound hysteria2)
check jq -e '.up_mbps == 20 and .down_mbps == 100' < <(sbc_outbound hysteria2)
check grep -q '    up: 20' < <(mh_proxy hysteria2)
HY2_UP_MBPS=020; reject validate_tuning
HY2_UP_MBPS=10001; reject validate_tuning
HY2_UP_MBPS=1; HY2_DOWN_MBPS='2, "insecure": true'; reject validate_tuning
HY2_PROFILE=auto HY2_UP_MBPS='' HY2_DOWN_MBPS=''
check jq -e '.ignore_client_bandwidth and (has("up_mbps") | not)' < <(sb_inbound hysteria2)
check jq -e '(has("up_mbps") or has("bbr_profile")) | not' < <(sbc_outbound hysteria2)
HY2_PROFILE=conservative
check jq -e '.bbr_profile == "conservative"' < <(sbc_outbound hysteria2)
check test "$(mh_min_version)" = 1.19.32
sb_installed_version() { echo 1.13.7; }
reject validate_tuning
sb_installed_version() { echo 1.14.2; }
pset CORE hysteria2 xray; reject validate_tuning
pset CORE hysteria2 singbox
RESOURCE_PROFILE=low-memory
check jq -e '.stream_receive_window == 2097152 and .connection_receive_window == 5242880 and .max_concurrent_streams == 64' < <(sb_inbound hysteria2)
check jq -e 'has("max_concurrent_streams") | not' < <(sbc_outbound hysteria2)
RESOURCE_PROFILE=throughput
check jq -e '.connection_receive_window == 41943040' < <(sbc_outbound hysteria2)
check save_state
HY2_PROFILE=''; RESOURCE_PROFILE=''; check load_state
check test "$HY2_PROFILE" = conservative
check test "$RESOURCE_PROFILE" = throughput
before=$(sha256sum "$STATE_FILE")
check do_tune hy2 measured --up 10 --down 50 >"$WORK/preview.log"
check test "$before" = "$(sha256sum "$STATE_FILE")"
reject do_tune hy2 auto --up 12 >"$WORK/invalid.log"
reject do_tune resource imaginary >"$WORK/invalid.log"
reject do_tune reset --unexpected >"$WORK/invalid.log"
# Application is covered by existing transaction machinery; assert that it is
# reached only after the preview passes and that a snapshot precedes it.
init_env() { :; }
snapshot_checkpoint() { echo snapshot >>"$WORK/order"; }
apply_or_die() { echo apply >>"$WORK/order"; save_state; }
check do_tune resource low-memory --apply >"$WORK/apply.log"
check test "$(cat "$WORK/order")" = "$(printf 'snapshot\napply')"
check load_state
check test "$RESOURCE_PROFILE" = low-memory
check do_tune reset --apply >"$WORK/reset.log"
check load_state
check test -z "$HY2_PROFILE$RESOURCE_PROFILE"
check do_probe export "$WORK/export.json"
check test "$(stat -c %a "$WORK/export.json")" = 600
reject do_probe export "$WORK/export.json"
check jq -e '.entries | length == 2' "$WORK/export.json"
reject grep -q must-never-export "$WORK/export.json"
check python3 "$ROOT/lib/client_runtime.py" list "$WORK/export.json"
check python3 "$ROOT/lib/client_runtime.py" merge "$WORK/merged.json" "$WORK/export.json" "$WORK/export.json"
check jq -e '.entries[2].id == "n2-hysteria2"' "$WORK/merged.json"
REALITY_SITE_ENABLED=1 REALITY_SITE_DOMAIN=example.org REALITY_SITE_PORT=18443
REALITY_DEST=127.0.0.1:18443 REALITY_SITE_HTTPS=1
check jq -e '.entries[1].reality.reference_host == "203.0.113.1" and .entries[1].reality.reference_port == 443' < <(gen_probe_bundle)
check jq -e '.entries[1].reality.host == "127.0.0.1" and .entries[1].reality.reference_port == 18443' < <(gen_probe_bundle local)
REALITY_SITE_HTTPS=0
check jq -e '.entries[1].reality.reference_host == ""' < <(gen_probe_bundle)
check python3 "$ROOT/scripts/embed-runtime.py" --check
printf 'Performance configuration tests: %s passed\n' "$PASS"
