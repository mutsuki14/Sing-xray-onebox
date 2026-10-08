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
rm -rf "$T"
mkdir -p "$T"
umask 022
mk() { # mode path content
	mkdir -p "$(dirname "$2")"
	printf '%s' "$3" >"$2"
	chmod "$1" "$2"
}
md() {
	mkdir -p "$2"
	chmod "$1" "$2"
}
md 700 "$T/etc"
cp "$STATE" "$T/etc/state.json"
chmod 600 "$T/etc/state.json"
md 700 "$T/etc/tls"
mk 600 "$T/etc/tls/cert.pem" "CERT"
mk 600 "$T/etc/tls/key.pem" "KEY"
md 700 "$T/etc/tls/acme"
mk 755 "$T/etc/tls/acme/acme.sh" "#!/bin/sh code"
md 755 "$T/etc/tls/acme/dnsapi"
mk 644 "$T/etc/tls/acme/dnsapi/dns_cf.sh" "cf"
mk 600 "$T/etc/tls/acme/account.conf" "ACCOUNT"
mk 640 "$T/etc/tls/acme/hook.sh" "hook"
md 750 "$T/etc/client"
mk 644 "$T/etc/client/links.txt" "vless://x"
mk 600 "$T/etc/client/节点.txt" "unicode"
mk 600 "$T/etc/client/empty" ""
md 711 "$T/etc/client/nested"
md 700 "$T/etc/client/nested/deeper"
mk 400 "$T/etc/client/nested/deeper/z" "zz"
mk 644 "$T/etc/client/nested/A" "upper"
mk 644 "$T/etc/client/nested/a" "lower"
md 700 "$T/etc/site"
md 700 "$T/etc/site/empty"
mk 600 "$T/etc/site/nginx.pid" "123"
mk 600 "$T/etc/site/error.log" "err"
md 700 "$T/etc/site/content-backups"
mk 600 "$T/etc/site/content-backups/old" "old"
mk 600 "$T/etc/firewall-v2.json" '{"rules":[]}'
mk 600 "$T/etc/hop-v2.json" '[]'
md 700 "$T/etc/backups"
mk 600 "$T/etc/backups/keep" "backup"
md 755 "$T/www"
mk 644 "$T/www/index.html" "<h1>site</h1>"
mk 600 "$T/www/.onebox-site-owned" "onebox"
md 755 "$T/systemd"
mk 644 "$T/systemd/onebox-net.service" "[Unit]"
md 755 "$T/initd/init.d"
md 755 "$T/initd/local.d"
mk 755 "$T/initd/local.d/onebox-hop.start" "#!/bin/sh"
mk 755 "$T/initd/local.d/admin.start" "#!/bin/sh admin"
md 700 "$T/acme-home/example.com_ecc"
printf '# onebox-rust-retired-deployment=%s\nLe_Domain=%s\nLe_RealFullChainPath=%s\nLe_RealKeyPath=%s\n' \
	"$T/etc/tls" "'example.com'" "''" "''" >"$T/acme-home/example.com_ecc/example.com.conf"
chmod 600 "$T/acme-home/example.com_ecc/example.com.conf"
md 700 "$T/acme-home/other.org_ecc"
mk 600 "$T/acme-home/other.org_ecc/other.org.conf" "Le_RealFullChainPath='/etc/x.pem'"
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
