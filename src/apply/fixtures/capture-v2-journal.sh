#!/bin/sh
# Regenerate v2-journal.json: build the layout `apply::testing::build_v2_layout`
# mirrors, run the v2.0.1 binary's `regen` on it (ONEBOX_INIT=none, fake
# offline cores that block) and SIGKILL it once the journal is published
# (phase prepare-cores). The layout root is replaced by @ROOT@.
# Usage: capture-v2-journal.sh /path/to/onebox-v2 /tmp/scratch-root OUT_DIR
set -eu
V2=${1:?path to the onebox v2.0.1 binary}
T=${2:?scratch root (deleted and recreated)}
OUT=${3:?output directory}
STATE=$(cd "$(dirname "$0")" && pwd)/v2-state.json
. "$(cd "$(dirname "$0")" && pwd)/v2-layout.sh"
md 755 "$T/fake"
printf '#!/bin/sh\nsleep 300\n' >"$T/fake/sing-box"
chmod 755 "$T/fake/sing-box"
cp "$T/fake/sing-box" "$T/fake/xray"
env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin HOME="$T" \
	ONEBOX_DIR="$T/etc" ONEBOX_BIN_DIR="$T/bin" ONEBOX_LOG_DIR="$T/log" ONEBOX_RUN_DIR="$T/run" \
	ONEBOX_SITE_ROOT="$T/www" ONEBOX_SYSTEMD_DIR="$T/systemd" ONEBOX_INITD_DIR="$T/initd/init.d" \
	ONEBOX_EXE="$T/usr/onebox" ONEBOX_INIT=none ACME_HOME="$T/acme-home" \
	ONEBOX_SINGBOX_BIN="$T/fake/sing-box" ONEBOX_XRAY_BIN="$T/fake/xray" \
	"$V2" regen >"$T/v2.out" 2>"$T/v2.err" &
PID=$!
i=0
while [ ! -f "$T/etc/.transaction/journal.json" ] && [ $i -lt 200 ]; do
	sleep 0.05
	i=$((i + 1))
done
# Let it reach the blocking fake core (phase prepare-cores).
sleep 1
kill -9 "$PID" 2>/dev/null || true
wait "$PID" 2>/dev/null || true
echo "--- v2 stderr"
cat "$T/v2.err"
echo "--- v2 stdout"
cat "$T/v2.out"
ls -la "$T/etc/.transaction" "$T/etc/.transaction/files"
mkdir -p "$OUT"
sed "s#$T#@ROOT@#g" "$T/etc/.transaction/journal.json" >"$OUT/v2-journal.json"
