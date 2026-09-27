#!/usr/bin/env bash
# 自有域名网站端到端测试：真实 nginx + sing-box / Xray，仅临时目录与回环高端口。
# 不安装软件、不调用 systemd/OpenRC、不申请公网证书、不修改防火墙。
# SB=/path/sing-box XR=/path/xray ONEBOX_TEST_NGINX=/path/nginx bash tests/site-e2e.sh
# KEEP=1 保留日志与测试目录。
# shellcheck disable=SC2034
set -u

HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/.." && pwd)
SB=${SB:-$(command -v sing-box || true)}
XR=${XR:-$(command -v xray || true)}
NGINX=${ONEBOX_TEST_NGINX:-}
for bin in "$SB" "$XR" "$NGINX"; do
	[ -n "$bin" ] && [ -x "$bin" ] || {
		echo "缺少测试内核：请设置 SB、XR、ONEBOX_TEST_NGINX 为可执行文件路径" >&2
		exit 2
	}
done
for cmd in python3 jq openssl curl timeout; do
	command -v "$cmd" >/dev/null || { echo "缺少测试依赖: $cmd" >&2; exit 2; }
done
SB=$(readlink -f "$SB") XR=$(readlink -f "$XR") NGINX=$(readlink -f "$NGINX")
WORK=$(mktemp -d)
PIDS=()
PASS=0 FAIL=0
cleanup() {
	local pid
	for pid in "${PIDS[@]}"; do kill -TERM "$pid" 2>/dev/null || true; done
	for pid in "${PIDS[@]}"; do wait "$pid" 2>/dev/null || true; done
	if [ "${KEEP:-0}" = 1 ] || [ "$FAIL" -gt 0 ]; then
		echo "测试目录: $WORK"
	else
		rm -rf "$WORK"
	fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

export ONEBOX_SOURCE_ONLY=1 ONEBOX_DIR="$WORK/etc" ONEBOX_SITE_ROOT="$WORK/www" \
	ONEBOX_BIN_DIR="$WORK/bin" ONEBOX_RUN_DIR="$WORK/run" ONEBOX_LOG_DIR="$WORK/log" NO_COLOR=1
# shellcheck source=../onebox.sh
. "$ROOT/onebox.sh"
declare -F site_write_nginx >/dev/null || { echo "当前脚本未包含自有域名站点功能" >&2; exit 2; }
SB_BIN=$SB XR_BIN=$XR ONEBOX_NGINX_BIN=$NGINX

fatal() { echo "[夹具失败] $*" >&2; FAIL=$((FAIL + 1)); exit 1; }
check() {
	local label=$1
	shift
	if "$@"; then
		PASS=$((PASS + 1))
		printf '[通过] %s\n' "$label"
	else
		FAIL=$((FAIL + 1))
		printf '[失败] %s\n' "$label" >&2
	fi
}
start_bg() {
	local log=$1
	shift
	"$@" >"$log" 2>&1 &
	PIDS+=($!)
}
wait_tcp() {
	local port=$1 i
	for i in $(seq 1 50); do
		(exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null && return 0
		sleep 0.1
	done
	return 1
}

# 同时绑定临时套接字分配互不重复的回环端口；只在真正启动夹具前释放。
read -r HTTP_PORT TARGET_TLS_PORT SB_PORT XR_PORT GUARD_PORT SB_SOCKS XR_SOCKS TARGET_HTTP_PORT < <(
	python3 - <<'PY'
import socket
sockets = []
for _ in range(8):
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    sockets.append(s)
print(" ".join(str(s.getsockname()[1]) for s in sockets))
PY
)
[[ "${TARGET_HTTP_PORT:-}" =~ ^[0-9]+$ ]] || fatal "无法分配回环端口"
SITE_MARKER="onebox-site-e2e-$(rand_hex 8)"
PROXY_MARKER="onebox-proxy-e2e-$(rand_hex 8)"
mkdir -p "$REALITY_SITE_DIR" "$REALITY_SITE_ROOT/.well-known/acme-challenge" "$WORK/pki" "$WORK/target" || fatal "创建目录"
# root 执行时 nginx worker 使用非 root 账号，需要遍历临时网页的父目录。
chmod 755 "$WORK" "$REALITY_SITE_ROOT" "$REALITY_SITE_ROOT/.well-known" "$REALITY_SITE_ROOT/.well-known/acme-challenge"
printf '%s\n' "$PROXY_MARKER" >"$WORK/target/index.html"
printf '%s\n' "$SITE_MARKER" >"$REALITY_SITE_ROOT/.well-known/acme-challenge/probe"

(
	set -e
	cd "$WORK/pki"
	openssl ecparam -genkey -name prime256v1 -noout -out ca.key
	openssl req -new -x509 -sha256 -days 2 -key ca.key -out ca.pem -subj '/CN=Onebox Site E2E CA'
	openssl ecparam -genkey -name prime256v1 -noout -out site.key
	openssl req -new -key site.key -out site.csr -subj '/CN=test.example'
	printf 'subjectAltName=DNS:test.example\nextendedKeyUsage=serverAuth\n' >site.ext
	openssl x509 -req -sha256 -days 2 -in site.csr -CA ca.pem -CAkey ca.key -CAcreateserial -extfile site.ext -out site.pem
) >"$WORK/pki.log" 2>&1 || fatal "生成本地 CA 和网站证书"
cp "$WORK/pki/site.pem" "$REALITY_SITE_DIR/cert.pem"
cp "$WORK/pki/site.key" "$REALITY_SITE_DIR/key.pem"
chmod 600 "$REALITY_SITE_DIR/key.pem"

setup_state() {
	local core=$1 port=$2
	reset_state
	PROTOCOLS=vless-reality
	pset CORE vless-reality "$core"
	pset PORT vless-reality "$port"
	SERVER_ADDR=127.0.0.1 SERVER_IPV4=127.0.0.1 SERVER_IPV6="" LISTEN_ADDR=127.0.0.1
	REALITY_SITE_ENABLED=1 REALITY_SITE_DOMAIN=test.example REALITY_SITE_PORT=$TARGET_TLS_PORT
	REALITY_SITE_TITLE=$SITE_MARKER REALITY_SNI=test.example REALITY_DEST="127.0.0.1:$TARGET_TLS_PORT"
	REALITY_GUARD_PORT=$GUARD_PORT
	BLOCK_PRIVATE=1 BLOCK_BT=1 NODE_NAME=site-e2e
	UUID=$(gen_uuid)
	gen_reality_keypair || fatal "生成 REALITY 密钥"
	REALITY_SHORT_ID=$(rand_hex 8)
}

setup_state singbox "$SB_PORT"
site_render_index >"$REALITY_SITE_ROOT/index.html" || fatal "生成网页"
# 生成生产 nginx 配置，再仅把 HTTP80 改为回环高端口。延后校验，避免 root/80 权限需求。
(
	site_nginx_check() { return 0; }
	site_write_nginx
) || fatal "生成 nginx 配置"
sed -i -e "s/listen 80;/listen 127.0.0.1:${HTTP_PORT};/" -e '/listen \[::\]:80;/d' "$REALITY_SITE_DIR/nginx.conf"
"$NGINX" -t -p "$REALITY_SITE_DIR/" -c "$REALITY_SITE_DIR/nginx.conf" >"$WORK/nginx-check.log" 2>&1 || fatal "实际 nginx 配置检查，详见 nginx-check.log"
start_bg "$WORK/nginx.log" "$NGINX" -p "$REALITY_SITE_DIR/" -c "$REALITY_SITE_DIR/nginx.conf" -g 'daemon off;'
start_bg "$WORK/target.log" python3 -m http.server "$TARGET_HTTP_PORT" --bind 127.0.0.1 --directory "$WORK/target"
wait_tcp "$TARGET_TLS_PORT" && wait_tcp "$HTTP_PORT" && wait_tcp "$TARGET_HTTP_PORT" || fatal "nginx / HTTP 夹具未监听"

http_challenge() {
	local result
	result=$(curl --noproxy '*' -fsS --max-time 5 "http://127.0.0.1:$HTTP_PORT/.well-known/acme-challenge/probe") && [ "$result" = "$SITE_MARKER" ]
}
http_redirect() {
	curl --noproxy '*' -sSI --max-time 5 "http://127.0.0.1:$HTTP_PORT/notes?from=e2e" |
		tr -d '\r' | grep -qiF "Location: https://test.example:$SB_PORT/notes?from=e2e"
}
browser_get() {
	local port=$1 file=$2
	curl --noproxy '*' --http1.1 --tlsv1.3 --tls-max 1.3 --cacert "$WORK/pki/ca.pem" \
		--resolve "test.example:$port:127.0.0.1" -fsS --max-time 8 "https://test.example:$port/" >"$file" 2>"$file.log" &&
		grep -qF "$SITE_MARKER" "$file"
}
browser_h2() {
	local port=$1 file=$2
	timeout 8 openssl s_client -connect "127.0.0.1:$port" -servername test.example \
		-CAfile "$WORK/pki/ca.pem" -verify_return_error -verify_hostname test.example -tls1_3 -alpn h2 \
		</dev/null >"$file" 2>&1 || return 1
	grep -q 'TLSv1.3' "$file" && grep -q 'ALPN protocol: h2' "$file" && grep -q 'Verify return code: 0 (ok)' "$file"
}
check 'nginx HTTP-01 webroot 可读' http_challenge
check 'nginx HTTP 跳转携带真实 REALITY 高端口与路径' http_redirect
check 'nginx HTTPS 本地 CA / 站点内容正常' browser_get "$TARGET_TLS_PORT" "$WORK/nginx-page.html"
check 'nginx TLS 1.3 / h2 正常' browser_h2 "$TARGET_TLS_PORT" "$WORK/nginx-h2.log"

authenticated_get() {
	local socks=$1 result
	result=$(curl --noproxy '' --socks5-hostname "127.0.0.1:$socks" -fsS --max-time 8 \
		"http://allowed.site-e2e.test:$TARGET_HTTP_PORT/" 2>/dev/null) && [ "$result" = "$PROXY_MARKER" ]
}
private_rejected() {
	local socks=$1 file=$2
	# 与正向请求相同目标服务，只有地址改为直接 loopback。夹具白名单不得匹配。
	if curl --noproxy '' --socks5-hostname "127.0.0.1:$socks" -fsS --max-time 4 \
		"http://127.0.0.1:$TARGET_HTTP_PORT/" >"$file" 2>"$file.log"; then return 1; fi
	! grep -qF "$PROXY_MARKER" "$file"
}
wrong_sni_backend() {
	curl --noproxy '*' --insecure --http1.1 --resolve "wrong.example:$TARGET_TLS_PORT:127.0.0.1" \
		-fsS --max-time 5 "https://wrong.example:$TARGET_TLS_PORT/" >"$WORK/wrong-backend.html" 2>/dev/null &&
		grep -qF "$SITE_MARKER" "$WORK/wrong-backend.html"
}
wrong_sni_rejected() {
	# --insecure 排除客户端证书校验造成的假通过；后端本身确实会接受该 SNI。
	if curl --noproxy '*' --insecure --http1.1 --resolve "wrong.example:$XR_PORT:127.0.0.1" \
		-fsS --max-time 4 "https://wrong.example:$XR_PORT/" >"$WORK/wrong-xray.html" 2>"$WORK/wrong-xray.log"; then return 1; fi
	! grep -qF "$SITE_MARKER" "$WORK/wrong-xray.html"
}

run_round() {
	local core=$1 port=$2 socks=$3 dir="$WORK/$1"
	mkdir -p "$dir"
	setup_state "$core" "$port"
	if [ "$core" = singbox ]; then
		gen_singbox_server >"$dir/server-raw.json"
		# 唯一测试域名的白名单只用于证明认证代理链路；生产私网规则全部保留。
		jq '.route.rules = [{"inbound":["vless-reality-in"],"domain":["allowed.site-e2e.test"],"action":"route","outbound":"direct","override_address":"127.0.0.1"}] + .route.rules' \
			"$dir/server-raw.json" >"$dir/server.json" || fatal 'sing-box 测试配置'
		"$SB" check -c "$dir/server.json" >"$dir/server-check.log" 2>&1 || fatal 'sing-box 服务端配置检查'
		start_bg "$dir/server.log" "$SB" run -c "$dir/server.json"
		cat >"$dir/client.json" <<EOF
{"log":{"level":"warn"},"inbounds":[{"type":"mixed","listen":"127.0.0.1","listen_port":$socks}],"outbounds":[$(sbc_outbound vless-reality)],"route":{"final":$(json_str "$(node_name vless-reality)")}}
EOF
		start_bg "$dir/client.log" "$SB" run -c "$dir/client.json"
	else
		gen_xray_server >"$dir/server-raw.json"
		jq --arg target "127.0.0.1:$TARGET_HTTP_PORT" \
			'.outbounds += [{"tag":"site-e2e-target","protocol":"freedom","settings":{"redirect":$target,"finalRules":[{"action":"allow"}]}}]
			| .routing.rules = [{"type":"field","inboundTag":["vless-reality-in"],"domain":["full:allowed.site-e2e.test"],"outboundTag":"site-e2e-target"}] + .routing.rules' \
			"$dir/server-raw.json" >"$dir/server.json" || fatal 'Xray 测试配置'
		"$XR" run -test -c "$dir/server.json" >"$dir/server-check.log" 2>&1 || fatal 'Xray 服务端配置检查'
		start_bg "$dir/server.log" "$XR" run -c "$dir/server.json"
		cat >"$dir/client.json" <<EOF
{"log":{"loglevel":"warning"},"inbounds":[{"listen":"127.0.0.1","port":$socks,"protocol":"socks","settings":{"udp":true}}],"outbounds":[$(xrc_outbound vless-reality proxy)]}
EOF
		start_bg "$dir/client.log" "$XR" run -c "$dir/client.json"
	fi
	wait_tcp "$port" && wait_tcp "$socks" || fatal "$core 服务端或客户端未监听"
	check "$core 公网 REALITY 入口提供受信网站页面" browser_get "$port" "$dir/browser.html"
	check "$core 公网 REALITY 入口支持 TLS 1.3 / h2" browser_h2 "$port" "$dir/h2.log"
	check "$core 认证客户端仍可代理访问测试目标" authenticated_get "$socks"
	check "$core 认证客户端仍禁止直接访问 loopback" private_rejected "$socks" "$dir/private.txt"
	if [ "$core" = xray ]; then
		check '错误 SNI 的 nginx 后端控制组可访问' wrong_sni_backend
		check 'Xray guard 拒绝错误 SNI（不依赖客户端验签）' wrong_sni_rejected
	fi
}

run_round singbox "$SB_PORT" "$SB_SOCKS"
run_round xray "$XR_PORT" "$XR_SOCKS"
printf '\n站点端到端测试：通过 %s 项，失败 %s 项\n' "$PASS" "$FAIL"
[ "$FAIL" = 0 ]
