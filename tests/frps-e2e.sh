#!/usr/bin/env bash
# Real frps/frpc + nginx integration. Temporary files and local high ports only;
# no system services, firewall edits, software installation or public ACME calls.
# FRPS_TEST_BIN=/path/frps FRPC_TEST_BIN=/path/frpc ONEBOX_TEST_NGINX=/path/nginx bash tests/frps-e2e.sh
# KEEP=1 retains the temporary fixtures; failures always retain diagnostic logs.
# shellcheck disable=SC2034
set -eu
ROOT=$(cd "$(dirname "$0")/.." && pwd)
FRPS_TEST_BIN=$(readlink -f "${FRPS_TEST_BIN:?set FRPS_TEST_BIN}")
FRPC_TEST_BIN=$(readlink -f "${FRPC_TEST_BIN:?set FRPC_TEST_BIN}")
ONEBOX_TEST_NGINX=$(readlink -f "${ONEBOX_TEST_NGINX:?set ONEBOX_TEST_NGINX}")
for bin in "$FRPS_TEST_BIN" "$FRPC_TEST_BIN" "$ONEBOX_TEST_NGINX"; do
	[ -x "$bin" ] || { echo "Not executable: $bin" >&2; exit 2; }
done
for cmd in python3 openssl; do
	command -v "$cmd" >/dev/null || { echo "Missing test dependency: $cmd" >&2; exit 2; }
done
WORK=$(mktemp -d)
cleanup() {
	local result=$?
	if [ "$result" != 0 ] || [ "${KEEP:-0}" = 1 ]; then
		echo "FRP E2E logs: $WORK"
	else
		rm -rf "$WORK"
	fi
}
trap cleanup EXIT
export ONEBOX_SOURCE_ONLY=1 ONEBOX_DIR="$WORK/onebox" ONEBOX_BIN_DIR="$WORK/bin" \
	ONEBOX_RUN_DIR="$WORK/run" ONEBOX_LOG_DIR="$WORK/log" NO_COLOR=1
# shellcheck source=../onebox.sh
. "$ROOT/onebox.sh"
declare -F _frps_render >/dev/null || { echo 'FRP support missing from onebox.sh' >&2; exit 2; }
FRPS_BIN=$FRPS_TEST_BIN
ONEBOX_NGINX_BIN=$ONEBOX_TEST_NGINX

read -r TCP_CONTROL WEB_CONTROL HTTP_INTERNAL HTTPS_PORT REDIRECT_PORT HTTP_BACKEND UDP_BACKEND RANGE_START RANGE_END < <(
	python3 "$ROOT/tests/frps_e2e.py" allocate "$WORK"
)
[[ "${RANGE_END:-}" =~ ^[0-9]+$ ]] || { echo 'Port allocation failed' >&2; exit 2; }

setup_frps() {
	_frps_defaults
	FRPS_DIR="$WORK/$1" FRPS_BIN_DIR="$WORK/frp-bin" FRPS_CONF="$WORK/$1/frps.toml"
	FRPS_STATE="$WORK/$1/state.conf"
	FRPS_WEB_ROOT="$WORK/$1-public/www" FRPS_WEB_VAR="$WORK/$1-public"
	FRPS_DOMAIN=frp.example.test FRPS_TOKEN=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
	FRPS_BIND_ADDR=127.0.0.1
	FRPS_MODE=$1 FRPS_BIND_PORT=$2 FRPS_HTTP_PORT=$HTTP_INTERNAL
	FRPS_HTTPS_PORT=$HTTPS_PORT FRPS_REDIRECT_PORT=$REDIRECT_PORT
	FRPS_WEB_DOMAIN=app.example.test FRPS_SUBDOMAIN_HOST=""
	FRPS_TLS_METHOD=custom
	FRPS_RANGE_START=$RANGE_START FRPS_RANGE_END=$RANGE_END
	mkdir -p "$FRPS_DIR" "$FRPS_WEB_ROOT" "$FRPS_WEB_VAR"
	_frps_control_certificate
	_frps_render
	"$FRPS_TEST_BIN" verify -c "$FRPS_CONF" >"$FRPS_DIR/verify.log" 2>&1 || {
		cat "$FRPS_DIR/verify.log" >&2
		return 1
	}
}
setup_frps tcp "$TCP_CONTROL"
_frps_export "$WORK/tcp/client-tcp" tcp "$HTTP_BACKEND" "$RANGE_START" www
_frps_export "$WORK/tcp/client-udp" udp "$UDP_BACKEND" "$((RANGE_START + 1))" www
_frps_export "$WORK/tcp/client-bad-token" tcp "$HTTP_BACKEND" "$((RANGE_START + 2))" www
_frps_export "$WORK/tcp/client-bad-ca" tcp "$HTTP_BACKEND" "$((RANGE_START + 3))" www
_frps_export "$WORK/tcp/client-bad-name" tcp "$HTTP_BACKEND" "$((RANGE_START + 4))" www
# The exporter correctly refuses out-of-range remote ports. This fixture starts
# with an allowed export, then alters it to exercise frps's actual enforcement.
_frps_export "$WORK/tcp/client-bad-port" tcp "$HTTP_BACKEND" "$RANGE_START" www

setup_frps web "$WEB_CONTROL"
_frps_export "$WORK/web/client-http" http "$HTTP_BACKEND" 0 www
# A separate local CA proves wrong roots cannot authenticate the control server.
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 2 \
	-keyout "$WORK/web/web-key.pem" -out "$WORK/web/web-cert.pem" \
	-subj '/CN=app.example.test' -addext 'subjectAltName=DNS:app.example.test' \
	>"$WORK/web/web-pki.log" 2>&1
chmod 600 "$WORK/web/web-key.pem" "$WORK/web/web-cert.pem"
if ! _frps_web_render 0; then
	"$ONEBOX_TEST_NGINX" -t -p "$FRPS_DIR/" -c "$FRPS_DIR/nginx.conf" >&2 || true
	exit 1
fi
# nginx workers need to traverse the local fixture; the exported credentials keep
# their production 0700/0600 permissions and are never served as site files.
chmod 755 "$WORK" "$FRPS_WEB_ROOT" "$FRPS_WEB_VAR"
python3 "$ROOT/tests/frps_e2e.py" run "$WORK" "$FRPS_TEST_BIN" "$FRPC_TEST_BIN" "$ONEBOX_TEST_NGINX"
