#!/usr/bin/env bash
# 独立 HTTPS 入口端到端测试: 真实 nginx、本地 CA、回环高端口，不修改系统。
# ONEBOX_TEST_NGINX=/path/nginx bash tests/site-https-e2e.sh
# shellcheck disable=SC2034
set -u

HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/.." && pwd)
NGINX=${ONEBOX_TEST_NGINX:-}
[ -n "$NGINX" ] && [ -x "$NGINX" ] || { echo '请设置 ONEBOX_TEST_NGINX 为 nginx 可执行文件路径' >&2; exit 2; }
for cmd in python3 openssl curl timeout; do
	command -v "$cmd" >/dev/null || { echo "缺少测试依赖: $cmd" >&2; exit 2; }
done
NGINX=$(readlink -f "$NGINX")
WORK=$(mktemp -d)
NGINX_PID=''
PASS=0 FAIL=0
stop_nginx() {
	[ -n "$NGINX_PID" ] || return 0
	kill -TERM "$NGINX_PID" 2>/dev/null || true
	wait "$NGINX_PID" 2>/dev/null || true
	NGINX_PID=''
}
cleanup() {
	stop_nginx
	if [ "${KEEP:-0}" = 1 ] || [ "$FAIL" -gt 0 ]; then echo "测试目录: $WORK"; else rm -rf "$WORK"; fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

export ONEBOX_SOURCE_ONLY=1 ONEBOX_DIR="$WORK/etc" ONEBOX_SITE_ROOT="$WORK/www" \
	ONEBOX_BIN_DIR="$WORK/bin" ONEBOX_RUN_DIR="$WORK/run" ONEBOX_LOG_DIR="$WORK/log" NO_COLOR=1
# shellcheck source=../onebox.sh
. "$ROOT/onebox.sh"
ONEBOX_NGINX_BIN=$NGINX
fatal() { echo "[夹具失败] $*" >&2; FAIL=$((FAIL + 1)); exit 1; }
check() {
	local label=$1
	shift
	if "$@"; then PASS=$((PASS + 1)); printf '[通过] %s\n' "$label";
	else FAIL=$((FAIL + 1)); printf '[失败] %s\n' "$label" >&2; fi
}
wait_tcp() {
	local port=$1 i
	for i in $(seq 1 50); do
		(exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null && return 0
		sleep 0.1
	done
	return 1
}
start_nginx() {
	"$NGINX" -t -p "$REALITY_SITE_DIR/" -c "$REALITY_SITE_DIR/nginx.conf" >>"$WORK/nginx-check.log" 2>&1 || fatal 'nginx 配置检查'
	"$NGINX" -p "$REALITY_SITE_DIR/" -c "$REALITY_SITE_DIR/nginx.conf" -g 'daemon off;' >>"$WORK/nginx.log" 2>&1 &
	NGINX_PID=$!
	wait_tcp "$HTTPS_PORT" && wait_tcp "$TARGET_PORT" || fatal 'nginx 未开始监听'
}

read -r HTTP_PORT HTTPS_PORT TARGET_PORT PRIVATE_PORT REALITY_PORT < <(
	python3 - <<'PY'
import socket
sockets = []
for _ in range(5):
    s = socket.socket()
    s.bind(('127.0.0.1', 0))
    sockets.append(s)
print(' '.join(str(s.getsockname()[1]) for s in sockets))
PY
)
[[ "${REALITY_PORT:-}" =~ ^[0-9]+$ ]] || fatal '无法分配回环端口'
mkdir -p "$REALITY_SITE_DIR" "$REALITY_SITE_ROOT/folder" "$REALITY_SITE_ROOT/.well-known/acme-challenge" "$WORK/pki"
chmod 755 "$WORK" "$REALITY_SITE_ROOT" "$REALITY_SITE_ROOT/folder" "$REALITY_SITE_ROOT/.well-known" "$REALITY_SITE_ROOT/.well-known/acme-challenge"
# 生产中的私密父目录不可被 worker 遍历；大文件测试覆盖代理意外落盘的问题。
chmod 700 "$REALITY_SITE_DIR"
printf 'FOLDER-CONTENT\n' >"$REALITY_SITE_ROOT/folder/index.html"
printf 'ACME-CONTENT\n' >"$REALITY_SITE_ROOT/.well-known/acme-challenge/probe"
python3 - "$REALITY_SITE_ROOT/large.txt" <<'PY'
import pathlib, sys
pathlib.Path(sys.argv[1]).write_bytes(b'onebox-large-response\n' * 65536)
PY
(
	set -e
	cd "$WORK/pki"
	openssl ecparam -genkey -name prime256v1 -noout -out ca.key
	openssl req -new -x509 -sha256 -days 2 -key ca.key -out ca.pem -subj '/CN=Onebox HTTPS E2E CA'
	openssl ecparam -genkey -name prime256v1 -noout -out other-ca.key
	openssl req -new -x509 -sha256 -days 2 -key other-ca.key -out other-ca.pem -subj '/CN=Unrelated CA'
	openssl ecparam -genkey -name prime256v1 -noout -out site.key
	openssl req -new -key site.key -out site.csr -subj '/CN=test.example'
	printf 'subjectAltName=DNS:test.example\nextendedKeyUsage=serverAuth\n' >site.ext
	openssl x509 -req -sha256 -days 2 -in site.csr -CA ca.pem -CAkey ca.key -CAcreateserial -extfile site.ext -out site.pem
) >"$WORK/pki.log" 2>&1 || fatal '创建本地 CA / 网站证书'
cp "$WORK/pki/site.pem" "$REALITY_SITE_DIR/cert.pem"
cp "$WORK/pki/site.key" "$REALITY_SITE_DIR/key.pem"
chmod 600 "$REALITY_SITE_DIR/key.pem"
reset_state
PROTOCOLS=vless-reality
pset CORE vless-reality singbox
pset PORT vless-reality "$REALITY_PORT"
REALITY_SITE_ENABLED=1 REALITY_SITE_HTTPS=1 REALITY_SITE_DOMAIN=test.example REALITY_SITE_PORT=$TARGET_PORT
REALITY_SITE_TITLE=HTTPS-E2E-CONTENT REALITY_SNI=test.example REALITY_DEST="127.0.0.1:$TARGET_PORT"
site_render_index >"$REALITY_SITE_ROOT/index.html" || fatal '生成网站内容'
(
	site_nginx_check() { return 0; }
	site_write_nginx
) || fatal '生成生产 nginx 配置'
# 仅替换监听地址、信任 CA 和加入测试观察头/私网控制组；反代配置保持生产生成结果。
python3 - "$REALITY_SITE_DIR/nginx.conf" "$HTTP_PORT" "$HTTPS_PORT" "$PRIVATE_PORT" "$WORK/pki/ca.pem" <<'PY'
import pathlib, re, sys
path, http, https, private, ca = sys.argv[1:]
p = pathlib.Path(path)
s = p.read_text().replace('listen 80;', f'listen 127.0.0.1:{http};')
s = s.replace('listen 443 ssl http2;', f'listen 127.0.0.1:{https} ssl http2;')
s = re.sub(r'^\s*listen \[::\]:(80|443)[^;]*;\n', '', s, flags=re.M)
s = re.sub(r'proxy_ssl_trusted_certificate "[^"]+";', f'proxy_ssl_trusted_certificate "{ca}";', s)
s = s.replace('        index index.html;', '''        index index.html;
        add_header X-Test-Host $http_host always;
        add_header X-Test-Forwarded-For $http_x_forwarded_for always;
        add_header X-Test-Forwarded-Proto $http_x_forwarded_proto always;
        add_header X-Test-Forwarded $http_forwarded always;
        add_header X-Test-Args $args always;''')
s = s.rstrip()
assert s.endswith('}')
s = s[:-1] + f'    server {{ listen 127.0.0.1:{private}; location / {{ return 200 "PRIVATE-CANARY"; }} }}\n}}\n'
p.write_text(s)
PY
cp "$REALITY_SITE_DIR/nginx.conf" "$WORK/good.conf"
start_nginx

fetch() {
	local path=$1
	shift
	curl --noproxy '*' --http1.1 --cacert "$WORK/pki/ca.pem" --resolve "test.example:$HTTPS_PORT:127.0.0.1" \
		-sS --max-time 8 -D "$WORK/response.headers" -o "$WORK/response.body" -w '%{http_code}' "$@" "https://test.example:$HTTPS_PORT$path"
}
header_is() { tr -d '\r' <"$WORK/response.headers" | grep -qixF "$1: $2"; }
header_absent() { ! grep -qi "^$1:" "$WORK/response.headers"; }
tls_handshake() {
	local port=$1 version=$2
	timeout 8 openssl s_client -connect "127.0.0.1:$port" -servername test.example -CAfile "$WORK/pki/ca.pem" \
		-verify_return_error -verify_hostname test.example "$version" -alpn h2 </dev/null >"$WORK/tls.log" 2>&1 &&
		grep -q 'ALPN protocol: h2' "$WORK/tls.log" && grep -q 'Verify return code: 0 (ok)' "$WORK/tls.log"
}
check 'HTTPS 入口返回网站正文' test "$(fetch /)" = 200
check '正文来自生成的网站' grep -q HTTPS-E2E-CONTENT "$WORK/response.body"
check '公网入口支持 TLS1.2 / h2' tls_handshake "$HTTPS_PORT" -tls1_2
check '公网入口支持 TLS1.3 / h2' tls_handshake "$HTTPS_PORT" -tls1_3
check '内部 REALITY 目标仍支持 TLS1.3 / h2' tls_handshake "$TARGET_PORT" -tls1_3
check '内部目标仍拒绝 TLS1.2' test "$(tls_handshake "$TARGET_PORT" -tls1_2; printf '%s' "$?")" != 0
check 'HTTP-01 webroot 保持可用' test "$(curl --noproxy '*' -fsS --max-time 5 "http://127.0.0.1:$HTTP_PORT/.well-known/acme-challenge/probe")" = ACME-CONTENT
curl --noproxy '*' -sS --max-time 5 -D "$WORK/response.headers" -o /dev/null "http://127.0.0.1:$HTTP_PORT/path?a=1"
check 'HTTP 跳转为无内部端口的 HTTPS 域名' header_is Location 'https://test.example/path?a=1'
check '请求携带 query 和伪造头仍可访问' test "$(fetch '/?a=one&b=two' -H 'Host: attacker.example' -H 'X-Forwarded-For: 10.0.0.1' -H 'X-Forwarded-Proto: http' -H 'Forwarded: for=10.0.0.1;proto=http')" = 200
check '后端 Host 固定为本站域名' header_is X-Test-Host test.example
check '后端 XFF 使用实际连接地址' header_is X-Test-Forwarded-For 127.0.0.1
check '后端协议固定为 HTTPS' header_is X-Test-Forwarded-Proto https
check '客户端 Forwarded 头不会透传' header_absent X-Test-Forwarded
check '查询字符串完整透传' header_is X-Test-Args 'a=one&b=two'
check '目录规范化跳转通过反代返回' test "$(fetch /folder)" = 301
check '目录跳转使用相对路径避免泄漏内部端口' header_is Location /folder/
check '自动跟随目录跳转仍能访问网站' test "$(fetch /folder -L)" = 200
check '目录正文正确' grep -q FOLDER-CONTENT "$WORK/response.body"
check '大响应无需写入私密目录' test "$(fetch /large.txt)" = 200
check '大响应内容完整' cmp -s "$REALITY_SITE_ROOT/large.txt" "$WORK/response.body"
check 'POST 保持静态后端的 405 行为' test "$(fetch / --data 'a=one&b=two')" = 405
check '私网控制组确实提供不同内容' test "$(curl --noproxy '*' -fsS --max-time 5 "http://127.0.0.1:$PRIVATE_PORT/")" = PRIVATE-CANARY
check '绝对 URI 不能把反代变成私网正向代理' test "$(fetch /private --request-target "http://127.0.0.1:$PRIVATE_PORT/private")" = 404
check '返回内容不包含私网控制组' test "$(grep -c PRIVATE-CANARY "$WORK/response.body")" = 0
check 'TLS 入口拒绝明文 HTTP' test "$(curl --noproxy '*' -sS --max-time 5 -o /dev/null -w '%{http_code}' "http://127.0.0.1:$HTTPS_PORT/")" = 400

# 反向控制: 客户端仍信任前端证书，只有 nginx 对后端的信任/名称改变，必须返回 502。
stop_nginx
sed 's/proxy_ssl_name test.example;/proxy_ssl_name wrong.example;/' "$WORK/good.conf" >"$REALITY_SITE_DIR/nginx.conf"
start_nginx
check '后端证书名称不匹配时拒绝代理' test "$(fetch /)" = 502
stop_nginx
sed "s|proxy_ssl_trusted_certificate \"$WORK/pki/ca.pem\";|proxy_ssl_trusted_certificate \"$WORK/pki/other-ca.pem\";|" "$WORK/good.conf" >"$REALITY_SITE_DIR/nginx.conf"
start_nginx
check '后端证书 CA 不受信时拒绝代理' test "$(fetch /)" = 502

printf '\nHTTPS 反代端到端: %s 通过, %s 失败\n' "$PASS" "$FAIL"
[ "$FAIL" = 0 ]
