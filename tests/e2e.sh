#!/usr/bin/env bash
# 状态变量由被加载的 onebox.sh 函数间接使用
# shellcheck disable=SC2034
#
# 端到端测试: 用 onebox.sh 的生成函数产出服务端与客户端配置,
# 在本机回环地址上启动真实的 sing-box / Xray 服务端, 再分别用
# sing-box / Xray / mihomo 客户端 (以及 mihomo 解析分享链接订阅)
# 发起 TCP 与 UDP 请求, 验证每个 协议 × 服务端内核 × 客户端 组合都能真正连通.
#
# 用法:
#   SB=/path/sing-box XR=/path/xray MH=/path/mihomo bash tests/e2e.sh [轮次...]
#   轮次: sb (优先 sing-box 服务端)  xr (优先 Xray 服务端)  ca-sb / ca-xr (受信任证书, 不跳过验证)
#         xr-share (Xray: Vision 与 XHTTP 共用端口)  xr-hy2 (Xray 承载 Hysteria2 + 混淆)
#   环境变量 KEEP=1 保留工作目录, VERBOSE=1 打印失败时的日志
#
set -u

HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/.." && pwd)
SB=${SB:-$(command -v sing-box || true)}
XR=${XR:-$(command -v xray || true)}
MH=${MH:-$(command -v mihomo || true)}
for b in "$SB" "$XR" "$MH"; do
	[ -x "$b" ] || {
		echo "缺少可执行文件, 请通过 SB / XR / MH 环境变量指定 sing-box / xray / mihomo 路径" >&2
		exit 2
	}
done
for c in python3 curl openssl jq; do
	command -v "$c" >/dev/null || {
		echo "缺少命令: $c" >&2
		exit 2
	}
done

WORK=$(mktemp -d)
PIDS=()
cleanup() {
	local p
	for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null; done
	wait 2>/dev/null
	if [ -n "${KEEP:-}" ]; then echo "工作目录保留在: $WORK"; else rm -rf "$WORK"; fi
}
trap cleanup EXIT

export ONEBOX_SOURCE_ONLY=1 ONEBOX_DIR="$WORK/etc" NO_COLOR=1
# shellcheck source=../onebox.sh
. "$ROOT/onebox.sh"
SB_BIN=$SB XR_BIN=$XR

MARKER="onebox-e2e-$(rand_hex 6)"
# 动态分配空闲端口 (TCP 与 UDP 均未被占用), 避免与本机其他程序冲突
USED_PORTS=" "
free_port() {
	local p i
	for i in $(seq 1 200); do
		p=$(((RANDOM * 32768 + RANDOM) % 20000 + 40000))
		case "$USED_PORTS" in *" $p "*) continue ;; esac
		port_in_use "$p" tcp && continue
		port_in_use "$p" udp && continue
		USED_PORTS+="$p "
		FREE_PORT=$p
		return 0
	done
	echo "无法分配空闲端口" >&2
	exit 2
}
free_port && HTTP_PORT=$FREE_PORT
free_port && TLS_TARGET_PORT=$FREE_PORT
free_port && UDP_ECHO_PORT=$FREE_PORT

bg() {
	# bg 日志文件 命令...
	local log=$1
	shift
	"$@" >"$log" 2>&1 &
	PIDS+=($!)
	echo $!
}

wait_tcp() {
	local port=$1 i
	for i in $(seq 1 50); do
		(exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null && return 0
		sleep 0.1
	done
	return 1
}

# ---------------------------------------------------------------------------
# 夹具: HTTP 目标, TLS1.3 目标 (REALITY / ShadowTLS 握手站点), UDP 回显, 本地 CA
# ---------------------------------------------------------------------------
setup_fixtures() {
	mkdir -p "$WORK/www" "$WORK/pki"
	echo "$MARKER" >"$WORK/www/index.html"
	bg "$WORK/http.log" python3 -m http.server "$HTTP_PORT" --bind 127.0.0.1 --directory "$WORK/www" >/dev/null

	# 本地 CA 与两张证书: reality.test (TLS 目标站点) / onebox.test (受信任证书轮次)
	(
		cd "$WORK/pki" || exit 1
		openssl ecparam -genkey -name prime256v1 -noout -out ca.key
		openssl req -new -x509 -sha256 -days 30 -key ca.key -out ca.pem -subj "/CN=Onebox E2E CA"
		for cn in reality.test onebox.test; do
			openssl ecparam -genkey -name prime256v1 -noout -out "$cn.key"
			openssl req -new -key "$cn.key" -out "$cn.csr" -subj "/CN=$cn"
			printf 'subjectAltName=DNS:%s\nextendedKeyUsage=serverAuth\n' "$cn" >"$cn.ext"
			openssl x509 -req -sha256 -days 30 -in "$cn.csr" -CA ca.pem -CAkey ca.key -CAcreateserial -extfile "$cn.ext" -out "$cn.pem"
		done
		cat ca.pem /etc/ssl/certs/ca-certificates.crt >bundle.pem 2>/dev/null || cp ca.pem bundle.pem
	) >/dev/null 2>&1

	cat >"$WORK/tls_target.py" <<'EOF'
import http.server, socketserver, ssl, sys
port, cert, key = int(sys.argv[1]), sys.argv[2], sys.argv[3]
class H(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *a): pass
class S(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.minimum_version = ssl.TLSVersion.TLSv1_3
ctx.set_alpn_protocols(["h2", "http/1.1"])
ctx.load_cert_chain(cert, key)
srv = S(("127.0.0.1", port), H)
srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
srv.serve_forever()
EOF
	bg "$WORK/tls_target.log" python3 "$WORK/tls_target.py" "$TLS_TARGET_PORT" "$WORK/pki/reality.test.pem" "$WORK/pki/reality.test.key" >/dev/null

	cat >"$WORK/udp_echo.py" <<'EOF'
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("127.0.0.1", int(sys.argv[1])))
while True:
    d, a = s.recvfrom(65535)
    s.sendto(d, a)
EOF
	bg "$WORK/udp_echo.log" python3 "$WORK/udp_echo.py" "$UDP_ECHO_PORT" >/dev/null

	# SOCKS5 UDP ASSOCIATE 客户端: 通过代理向 UDP 回显服务发包并校验回包
	cat >"$WORK/socks_udp.py" <<'EOF'
import socket, struct, sys, os
proxy_port, target_port = int(sys.argv[1]), int(sys.argv[2])
t = socket.create_connection(("127.0.0.1", proxy_port), timeout=8)
t.sendall(b"\x05\x01\x00")
if t.recv(2) != b"\x05\x00": sys.exit("auth")
t.sendall(b"\x05\x03\x00\x01" + socket.inet_aton("0.0.0.0") + struct.pack(">H", 0))
r = t.recv(262)
if len(r) < 10 or r[1] != 0: sys.exit("associate failed %r" % r)
atyp = r[3]
if atyp == 1:
    host = socket.inet_ntoa(r[4:8]); port = struct.unpack(">H", r[8:10])[0]
elif atyp == 4:
    host = socket.inet_ntop(socket.AF_INET6, r[4:20]); port = struct.unpack(">H", r[20:22])[0]
else:
    l = r[4]; host = r[5:5+l].decode(); port = struct.unpack(">H", r[5+l:7+l])[0]
if host in ("0.0.0.0", "::"): host = "127.0.0.1"
u = socket.socket(socket.AF_INET6 if ":" in host else socket.AF_INET, socket.SOCK_DGRAM)
u.settimeout(5)
payload = os.urandom(16).hex().encode()
# 192.0.2.53 (TEST-NET-1) 只有测试服务端会改写到 127.0.0.1, 直连必然不通
hdr = b"\x00\x00\x00\x01" + socket.inet_aton("192.0.2.53") + struct.pack(">H", target_port)
for _ in range(3):
    u.sendto(hdr + payload, (host, port))
    try:
        d, _ = u.recvfrom(65535)
    except socket.timeout:
        continue
    if d.endswith(payload):
        print("ok"); sys.exit(0)
sys.exit("no echo")
EOF
	wait_tcp "$HTTP_PORT" && wait_tcp "$TLS_TARGET_PORT" || {
		echo "夹具启动失败" >&2
		exit 2
	}
	sleep 0.5
	local pid
	for pid in "${PIDS[@]}"; do
		kill -0 "$pid" 2>/dev/null || {
			echo "夹具进程退出 (端口冲突?):" >&2
			tail -n 3 "$WORK"/*.log >&2
			exit 2
		}
	done
}

# ---------------------------------------------------------------------------
# 轮次配置
# ---------------------------------------------------------------------------
# setup_round 名称 优先内核 TLS模式(self|custom) [协议列表]
setup_round() {
	local name=$1 prefer=$2 tls=$3 list=${4:-$ALL_PROTOCOLS} p
	RDIR="$WORK/$name"
	mkdir -p "$RDIR"
	reset_state
	PROTOCOLS=$(normalize_protocols $list)
	assign_cores "$prefer"
	for p in $PROTOCOLS; do
		free_port
		pset PORT "$p" "$FREE_PORT"
	done
	# Vision 与 XHTTP 共用同一端口 (XHTTP 作为 Vision 的回落)
	[ -n "${SHARE_XHTTP_PORT:-}" ] && pset PORT vless-xhttp "$(pget PORT vless-reality)"
	SERVER_ADDR=127.0.0.1 SERVER_IPV4=127.0.0.1 SERVER_IPV6="" LISTEN_ADDR=127.0.0.1
	NODE_NAME="e2e-$name" BLOCK_PRIVATE=0 BLOCK_BT=1
	REALITY_SNI=reality.test REALITY_DEST="127.0.0.1:${TLS_TARGET_PORT}"
	SHADOWTLS_SNI=reality.test SHADOWTLS_DEST="127.0.0.1:${TLS_TARGET_PORT}"
	HY2_OBFS=${HY2_OBFS_TEST:-0}
	gen_credentials
	TLS_DIR="$RDIR/tls"
	case "$tls" in
	self)
		TLS_MODE=self TLS_SNI=www.bing.com
		cert_self_signed "$TLS_SNI" >/dev/null
		;;
	custom)
		TLS_MODE=custom DOMAIN=onebox.test TLS_SNI=onebox.test
		cert_custom "$WORK/pki/onebox.test.pem" "$WORK/pki/onebox.test.key" >/dev/null
		[ "$CERT_PINNED" = 0 ] || echo "  警告: 测试 CA 未被识别为受信任, 本轮将以指纹固定方式测试"
		;;
	esac
}

start_servers() {
	local ok=0
	# 测试目标域名 e2e.target 只有服务端能解析 (改写到 127.0.0.1), 保证流量确实经过代理
	if core_used singbox; then
		gen_singbox_server |
			jq '.route.rules = [{"domain": ["e2e.target"], "ip_cidr": ["192.0.2.53/32"], "action": "route-options", "override_address": "127.0.0.1"}] + .route.rules' \
				>"$RDIR/sb-server.json"
		if ! "$SB" check -c "$RDIR/sb-server.json" >"$RDIR/sb-check.log" 2>&1; then
			echo "  sing-box 服务端配置校验失败:"
			sed 's/^/    /' "$RDIR/sb-check.log"
			ok=1
		fi
		bg "$RDIR/sb-server.log" "$SB" run -c "$RDIR/sb-server.json" >/dev/null
	fi
	if core_used xray; then
		gen_xray_server |
			jq '.outbounds += [{"tag": "e2e", "protocol": "freedom", "settings": {"redirect": "127.0.0.1:0", "finalRules": [{"action": "allow"}]}}]
				| .routing.rules = [{"type": "field", "domain": ["full:e2e.target"], "outboundTag": "e2e"}, {"type": "field", "ip": ["192.0.2.53/32"], "outboundTag": "e2e"}] + .routing.rules' \
				>"$RDIR/xr-server.json"
		if ! "$XR" run -test -c "$RDIR/xr-server.json" >"$RDIR/xr-check.log" 2>&1; then
			echo "  Xray 服务端配置校验失败:"
			tail -n 5 "$RDIR/xr-check.log" | sed 's/^/    /'
			ok=1
		fi
		bg "$RDIR/xr-server.log" "$XR" run -c "$RDIR/xr-server.json" >/dev/null
	fi
	local p
	for p in $PROTOCOLS; do
		[ "$(proto_net "$p")" = udp ] && continue
		wait_tcp "$(pget PORT "$p")" || {
			echo "  $(proto_title "$p") 服务端端口未监听, 服务端日志:"
			tail -n 5 "$RDIR"/*-server.log 2>/dev/null | sed 's/^/    /'
			ok=1
		}
	done
	sleep 0.5
	return $ok
}

stop_all_round() {
	local p
	for p in "${PIDS[@]:3}"; do kill "$p" 2>/dev/null; done
	wait "${PIDS[@]:3}" 2>/dev/null
	PIDS=("${PIDS[@]:0:3}")
}

# ---------------------------------------------------------------------------
# 客户端
# ---------------------------------------------------------------------------

client_config_singbox() {
	local p=$1 port=$2
	cat <<EOF
{
  "log": { "level": "warn" },
  "inbounds": [{ "type": "mixed", "listen": "127.0.0.1", "listen_port": ${port} }],
  "outbounds": [
$(sbc_outbound "$p")
  ],
  "route": { "final": $(json_str "$(node_name "$p")") }
}
EOF
}

client_config_xray() {
	local p=$1 port=$2
	cat <<EOF
{
  "log": { "loglevel": "warning" },
  "inbounds": [{ "listen": "127.0.0.1", "port": ${port}, "protocol": "socks", "settings": { "udp": true, "ip": "127.0.0.1" } }],
  "outbounds": [
$(xrc_outbound "$p" proxy)
  ]
}
EOF
}

client_config_mihomo() {
	local p=$1 port=$2
	cat <<EOF
mixed-port: ${port}
allow-lan: false
mode: rule
log-level: warning
ipv6: false
dns:
  enable: false
proxies:
$(mh_proxy "$p")
rules:
  - MATCH,$(node_name "$p")
EOF
}

# 通过 mihomo 解析 Base64 订阅 (分享链接) 来连接
client_config_link() {
	local p=$1 port=$2 dir=$3
	gen_links | b64 >"$dir/sub.txt"
	cat <<EOF
mixed-port: ${port}
allow-lan: false
mode: rule
log-level: warning
ipv6: false
dns:
  enable: false
proxy-providers:
  sub:
    type: file
    path: ./sub.txt
    health-check: { enable: false }
proxy-groups:
  - name: G
    type: select
    use: [sub]
    filter: $(yq "^$(node_name "$p" | sed 's/[.[\]()*+?^$|\\]/\\&/g')\$")
rules:
  - MATCH,G
EOF
}

# run_client 客户端类型 协议  -> 输出 "tcp结果 udp结果"
run_client() {
	local c=$1 p=$2 port dir pid tcp="FAIL" udp="FAIL" out
	free_port
	port=$FREE_PORT
	dir="$RDIR/client-$c-$p"
	mkdir -p "$dir"
	case "$c" in
	singbox)
		client_config_singbox "$p" "$port" >"$dir/config.json"
		pid=$(bg "$dir/client.log" "$SB" run -c "$dir/config.json")
		;;
	xray)
		client_config_xray "$p" "$port" >"$dir/config.json"
		pid=$(bg "$dir/client.log" "$XR" run -c "$dir/config.json")
		;;
	mihomo)
		client_config_mihomo "$p" "$port" >"$dir/config.yaml"
		pid=$(bg "$dir/client.log" "$MH" -d "$dir" -f "$dir/config.yaml")
		;;
	link)
		client_config_link "$p" "$port" "$dir" >"$dir/config.yaml"
		pid=$(bg "$dir/client.log" "$MH" -d "$dir" -f "$dir/config.yaml")
		;;
	esac
	if wait_tcp "$port"; then
		sleep 0.3
		out=$(curl -s --noproxy '' --max-time 10 -x "socks5h://127.0.0.1:${port}" "http://e2e.target:${HTTP_PORT}/" 2>/dev/null)
		[ "$out" = "$MARKER" ] && tcp=ok
		if python3 "$WORK/socks_udp.py" "$port" "$UDP_ECHO_PORT" >"$dir/udp.log" 2>&1; then udp=ok; fi
	fi
	kill "$pid" 2>/dev/null
	wait "$pid" 2>/dev/null
	if [ "$tcp" != ok ] && [ -n "${VERBOSE:-}" ]; then
		echo "---- $c / $p client log ----" >&2
		tail -n 15 "$dir/client.log" >&2
	fi
	echo "$tcp $udp"
}

# 期望的 UDP 支持 (协议+客户端): 不支持 UDP 的组合记为 n/a
udp_expected() {
	local c=$1 p=$2
	case "$p" in
	vless-ws | vmess-ws | vless-grpc | vless-xhttp | vless-reality | trojan | shadowsocks | hysteria2 | tuic | anytls | shadowtls) return 0 ;;
	esac
	return 1
}

TOTAL=0 FAILED=0
RESULTS=()

run_round() {
	local name=$1 prefer=$2 tls=$3 list=${4:-$ALL_PROTOCOLS} p c r tcp udp
	echo
	echo "=== 轮次 ${name}: 优先内核=${prefer} 证书=${tls} ==="
	# 信任本地测试 CA (REALITY/ShadowTLS 目标站点与 ca-* 轮次的证书由它签发);
	# 需在 setup_round 之前设置, 以便自有证书被识别为受信任 (客户端严格校验而非固定指纹)
	export SSL_CERT_FILE="$WORK/pki/bundle.pem"
	setup_round "$name" "$prefer" "$tls" "$list"
	local started=0
	if start_servers; then
		started=1
	elif grep -qs 'address already in use' "$RDIR"/*-server.log; then
		# 端口在分配后被本机其他程序抢占 (与测试无关的竞争): 重新分配端口后再试一次
		echo "  端口被其他程序占用, 重新分配端口后重试"
		stop_all_round
		rm -f "$RDIR"/*-server.log
		setup_round "$name" "$prefer" "$tls" "$list"
		start_servers && started=1
	fi
	if [ "$started" = 0 ]; then
		FAILED=$((FAILED + 1))
		TOTAL=$((TOTAL + 1))
		RESULTS+=("$name server-start FAIL")
	fi
	for p in $PROTOCOLS; do
		for c in singbox xray mihomo link; do
			case "$c" in
			singbox) proto_client_ok "$p" singbox || continue ;;
			xray) proto_client_ok "$p" xray || continue ;;
			mihomo) proto_client_ok "$p" mihomo || continue ;;
			link) proto_client_ok "$p" link || continue ;;
			esac
			if [ "$c" = link ] && [ "$p" = tuic ] && [ "$TLS_MODE" = self ]; then
				# mihomo 的链接解析器不支持 tuic:// 的跳过证书验证参数, 自签证书下无法验证 (已知限制)
				printf '  %-4s %-22s %-9s (mihomo 链接解析不支持 TUIC 自签证书, 跳过)\n' SKIP "$(proto_title "$p")" "$c"
				continue
			fi
			local status=PASS attempt
			for attempt in 1 2; do
				r=$(run_client "$c" "$p")
				tcp=${r% *} udp=${r#* }
				udp_expected "$c" "$p" || udp="n/a"
				if [ "$tcp" = ok ] && { [ "$udp" = ok ] || [ "$udp" = n/a ]; }; then
					[ "$attempt" = 2 ] && status="PASS(重试)"
					break
				fi
				status=FAIL
			done
			TOTAL=$((TOTAL + 1))
			[ "$status" = FAIL ] && FAILED=$((FAILED + 1))
			printf '  %-10s %-22s %-9s 服务端=%-8s TCP=%-4s UDP=%-4s\n' "$status" "$(proto_title "$p")" "$c" "$(core_title "$(pget CORE "$p")")" "$tcp" "$udp"
			RESULTS+=("$name $p $c $status tcp=$tcp udp=$udp")
		done
	done
	stop_all_round
}

setup_fixtures

ROUNDS=("$@")
[ ${#ROUNDS[@]} -gt 0 ] || ROUNDS=(sb xr ca-sb ca-xr xr-share xr-hy2)
for r in "${ROUNDS[@]}"; do
	case "$r" in
	sb) run_round sb singbox self ;;
	xr) run_round xr xray self ;;
	ca-sb) HY2_OBFS_TEST=1 run_round ca-sb singbox custom "vless-ws vmess-ws trojan hysteria2 tuic anytls" ;;
	ca-xr) run_round ca-xr xray custom "vless-ws vmess-ws trojan" ;;
	xr-share) SHARE_XHTTP_PORT=1 run_round xr-share xray self "vless-reality vless-xhttp" ;;
	xr-hy2) OPT_HY2_CORE=xray HY2_OBFS_TEST=1 run_round xr-hy2 xray self "hysteria2" ;;
	*) echo "未知轮次: $r" >&2 ;;
	esac
done

echo
echo "共 ${TOTAL} 项, 失败 ${FAILED} 项"
[ "$FAILED" = 0 ]
