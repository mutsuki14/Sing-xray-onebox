#!/usr/bin/env bash
# AnyTLS + REALITY 回归: 不联网、不启动服务、不写宿主机配置。
# shellcheck disable=SC2034
set -u

HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/.." && pwd)
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
export ONEBOX_SOURCE_ONLY=1 ONEBOX_DIR="$WORK/etc" ONEBOX_BIN_DIR="$WORK/bin" \
	ONEBOX_LOG_DIR="$WORK/log" ONEBOX_RUN_DIR="$WORK/run" ONEBOX_SITE_ROOT="$WORK/public" NO_COLOR=1
# shellcheck source=../onebox.sh
. "$ROOT/onebox.sh"

PASS=0 FAIL=0
eq() {
	if [ "$2" = "$3" ]; then PASS=$((PASS + 1)); else
		FAIL=$((FAIL + 1))
		printf '  [失败] %s\n    实际: %s\n    期望: %s\n' "$1" "$2" "$3"
	fi
}
yes_() { if "$@"; then echo yes; else echo no; fi; }
port_in_use() { return 1; }
fixture() {
	reset_state
	PROTOCOLS=anytls-reality
	pset CORE anytls-reality singbox
	pset PORT anytls-reality 18443
	PASSWORD='password with "quotes" & spaces'
	REALITY_PRIVATE_KEY=private-key-not-for-client
	REALITY_PUBLIC_KEY=public-key-for-client
	REALITY_SHORT_ID=0123456789abcdef
	REALITY_SNI=www.example.com REALITY_DEST=www.example.com:443
	SERVER_ADDR=2001:db8::9 SERVER_IPV4=203.0.113.9
	NODE_NAME='测试 "AnyTLS"' BLOCK_PRIVATE=1 BLOCK_BT=1
	LISTEN_ADDR=127.0.0.1
}

fixture
eq '协议可单独选择且去重' "$(normalize_protocols anytls-reality anytls-reality)" anytls-reality
eq '仅支持 sing-box 服务端' "$(proto_cores anytls-reality)" singbox
eq 'Xray 服务端不可承载' "$(yes_ proto_supports_core anytls-reality xray)" no
assign_cores xray
eq '偏好 Xray 时仍分配 sing-box' "$(pget CORE anytls-reality)" singbox
eq '按 TCP 入口管理防火墙' "$(proto_net anytls-reality)" tcp
eq '识别 REALITY 凭据依赖' "$(yes_ any_reality)" yes
eq '无需普通 TLS 证书' "$(yes_ any_needs_cert)" no
eq 'sing-box 可导出' "$(yes_ proto_client_ok anytls-reality singbox)" yes
for client in xray mihomo link; do
	eq "$client 不可静默降级为普通 AnyTLS" "$(yes_ proto_client_ok anytls-reality "$client")" no
done
for renderer in link_of mh_proxy xrc_outbound xr_inbound; do
	eq "$renderer 直接调用也拒绝输出不兼容配置" "$(
		out=$("$renderer" anytls-reality proxy 2>/dev/null); rc=$?
		printf '%s|%s' "$rc" "$out"
	)" '1|'
done

inbound=$(sb_inbound anytls-reality)
eq '服务端使用 AnyTLS 身份验证和 REALITY 传输' "$(printf '%s' "$inbound" | jq -r '[.type, .tag, (.tls.enabled|tostring), (.tls.reality.enabled|tostring)]|join("|")')" 'anytls|anytls-reality-in|true|true'
eq '服务端密码完整转义' "$(printf '%s' "$inbound" | jq -r '.users[0].password')" "$PASSWORD"
eq '服务端不混入 VLESS UUID 或 flow' "$(printf '%s' "$inbound" | jq '[.users[]|has("uuid") or has("flow")]|any')" false
eq '服务端握手目标及端口' "$(printf '%s' "$inbound" | jq -r '.tls.reality.handshake|.server+":"+(.server_port|tostring)')" www.example.com:443
eq '服务端 REALITY 使用私钥和 short ID' "$(printf '%s' "$inbound" | jq -r '.tls.reality|.private_key+"|"+.short_id[0]')" "$REALITY_PRIVATE_KEY|$REALITY_SHORT_ID"
eq '服务端无普通 TLS 证书依赖' "$(printf '%s' "$inbound" | jq '.tls|has("certificate_path") or has("key_path") or has("certificate")')" false

outbound=$(sbc_outbound anytls-reality)
eq '客户端保留 IPv6 服务地址与端口' "$(printf '%s' "$outbound" | jq -r '.server+"|"+(.server_port|tostring)')" '2001:db8::9|18443'
eq '客户端使用 AnyTLS 且密码一致' "$(printf '%s' "$outbound" | jq -r '.type+"|"+.password')" "anytls|$PASSWORD"
eq '客户端强制 REALITY 和 uTLS' "$(printf '%s' "$outbound" | jq '[.tls.enabled,.tls.reality.enabled,.tls.utls.enabled]|all')" true
eq '客户端公钥、short ID、SNI 一致' "$(printf '%s' "$outbound" | jq -r '.tls|.server_name+"|"+.reality.public_key+"|"+.reality.short_id')" "$REALITY_SNI|$REALITY_PUBLIC_KEY|$REALITY_SHORT_ID"
eq '客户端不跳过认证或泄漏服务端私钥' "$(printf '%s' "$outbound" | jq '[..|objects|has("private_key") or (.insecure // false)]|any')" false

# 与普通 AnyTLS 并存时，两种传输必须保持独立。
PROTOCOLS='anytls anytls-reality'
pset CORE anytls singbox
pset PORT anytls 19443
TLS_MODE=acme TLS_SNI=tls.example.com CERT_FILE="$WORK/cert.pem" KEY_FILE="$WORK/key.pem"
eq '混合安装仍为普通 AnyTLS 保留证书需求' "$(yes_ any_needs_cert)" yes
server=$(gen_singbox_server)
eq '两种协议各生成一个独立入口' "$(printf '%s' "$server" | jq '[.inbounds[]|select(.type=="anytls")]|length')" 2
eq '普通 AnyTLS 不被转换为 REALITY' "$(printf '%s' "$server" | jq '.inbounds[]|select(.tag=="anytls-in")|.tls|has("certificate_path") and (has("reality")|not)')" true
eq '不同 TCP 入口不可复用同一端口' "$(yes_ port_ok 19443 anytls-reality 2>/dev/null)" no
save_state
eq '新协议端口计入已管理的 TCP 端口' "$(yes_ port_used_by_onebox 18443 tcp)" yes
eq '新协议不额外声明同号 UDP 监听端口' "$(yes_ port_used_by_onebox 18443 udp)" no

# 无 VLESS 协议时也必须生成 REALITY 凭据，并保存/恢复其配置。
fixture
REALITY_PRIVATE_KEY='' REALITY_PUBLIC_KEY='' REALITY_SHORT_ID=''
gen_reality_keypair() { REALITY_PRIVATE_KEY=generated-private; REALITY_PUBLIC_KEY=generated-public; }
gen_credentials
eq '独立安装会生成 REALITY 密钥' "$REALITY_PRIVATE_KEY|$REALITY_PUBLIC_KEY" 'generated-private|generated-public'
eq '独立安装生成 8 字节 short ID' "$([[ "$REALITY_SHORT_ID" =~ ^[0-9a-f]{16}$ ]] && echo yes)" yes
save_state
reset_state
load_state
eq '状态往返保留新协议、端口和内核' "$PROTOCOLS|$(pget PORT anytls-reality)|$(pget CORE anytls-reality)" 'anytls-reality|18443|singbox'
eq '状态往返保留 REALITY 密钥' "$REALITY_PRIVATE_KEY|$REALITY_PUBLIC_KEY" 'generated-private|generated-public'

# 独立新协议不应因空链接/不支持的客户端阻断全部客户端文件生成。
fixture
mkdir -p "$CLIENT_DIR"
printf 'stale unsupported export\n' >"$CLIENT_DIR/xray.json"
printf 'stale unsupported export\n' >"$CLIENT_DIR/mihomo.yaml"
eq '仅新协议时写出客户端文件成功' "$(yes_ write_client_files)" yes
eq 'sing-box 完整配置保留唯一 REALITY 节点' "$(jq '[.outbounds[]|select(.type=="anytls")|.tls.reality.enabled]|length==1 and all' "$CLIENT_DIR/sing-box-notun.json")" true
eq '客户端文件权限限制为 600' "$(stat -c %a "$CLIENT_DIR/sing-box-notun.json")" 600
eq '不保留旧 Xray 配置' "$([ -e "$CLIENT_DIR/xray.json" ] && echo yes || echo no)" no
eq '不保留旧 mihomo 配置或生成空文件' "$([ -e "$CLIENT_DIR/mihomo.yaml" ] && echo yes || echo no)" no
eq '不导出可能丢失 REALITY 的 URI' "$(cat "$CLIENT_DIR/links.txt" 2>/dev/null)" ''
eq '不保留可能降级的旧 mihomo 内容' "$(yes_ grep -q 'stale unsupported export' "$CLIENT_DIR/mihomo.yaml" 2>/dev/null)" no
eq 'probe bundle 可独立测量新协议' "$(jq -r '.entries[0]|.id+"|"+.core+"|"+.reality.sni' "$CLIENT_DIR/probe.json")" 'anytls-reality|singbox|www.example.com'
eq '所有导出文件均不含服务端私钥' "$(yes_ grep -R -q -F "$REALITY_PRIVATE_KEY" "$CLIENT_DIR")" no
for format in mihomo clash xray links link sub; do
	eq "查看不支持的 $format 格式返回失败且无配置输出" "$(
		out=$(show_client "$format" 2>"$WORK/show-$format.log"); rc=$?
		printf '%s|%s' "$rc" "$out"
	)" '1|'
	eq "$format 提示使用完整 sing-box 配置" "$(yes_ grep -q 'onebox client singbox' "$WORK/show-$format.log")" yes
done
eq '无通用链接时二维码不尝试安装依赖或生成输出' "$(
	has() { return 1; }
	ensure_cmds() { touch "$WORK/qr-dependency-attempted"; return 1; }
	qrencode() { touch "$WORK/qr-render-attempted"; }
	out=$(show_client qr 2>"$WORK/show-qr.log"); rc=$?
	attempted=no
	if [ -e "$WORK/qr-dependency-attempted" ] || [ -e "$WORK/qr-render-attempted" ]; then attempted=yes; fi
	printf '%s|%s|%s' "$rc" "$out" "$attempted"
)" '1||no'
eq '客户端菜单默认选择可用的 sing-box 配置' "$(
	ask_num() { printf '%s' "$3" >"$WORK/client-default"; printf -v "$1" '%s' "$3"; }
	show_client >"$WORK/client-menu.log" 2>&1
	cat "$WORK/client-default"
)" 2

# 混合安装仍导出受支持的普通 AnyTLS，且不把新协议当作普通 TLS 节点。
PROTOCOLS='anytls anytls-reality'
pset CORE anytls singbox; pset PORT anytls 19443
TLS_MODE=acme TLS_SNI=tls.example.com DOMAIN=tls.example.com
eq '混合组合完整生成所有支持的客户端格式' "$(yes_ write_client_files)" yes
eq '通用 URI 仅包含普通 AnyTLS 端口' "$(sed -n 's/.*@\[2001:db8::9\]:\([0-9]*\).*/\1/p' "$CLIENT_DIR/links.txt")" 19443
eq 'mihomo 仅包含普通 AnyTLS 端口' "$(sed -n 's/^    port: //p' "$CLIENT_DIR/mihomo.yaml")" 19443
eq 'sing-box 保留两种独立 AnyTLS 传输' "$(jq '[.outbounds[]|select(.type=="anytls")]|length' "$CLIENT_DIR/sing-box-notun.json")" 2
fixture

# 自建站沿用 REALITY 本地握手目标，不回退到证书模式。
REALITY_SITE_ENABLED=1 REALITY_SITE_DOMAIN=owned.example.com REALITY_SITE_PORT=24443
REALITY_SNI=$REALITY_SITE_DOMAIN REALITY_DEST=127.0.0.1:24443
eq '自建站握手使用内部 HTTPS 端口' "$(sb_inbound anytls-reality | jq -r '.tls.reality.handshake|.server+":"+(.server_port|tostring)')" '127.0.0.1:24443'
eq '自建站客户端 SNI 保留域名' "$(sbc_outbound anytls-reality | jq -r '.tls.server_name')" owned.example.com

# 使用真实 add/del 调度，屏蔽安装/服务操作，覆盖只有这个 REALITY
# 协议时的新增、网站保留及最终清理，而不依赖已有 VLESS 入口。
eq '新增协议返回成功且生成独立 REALITY 凭据' "$(
	fixture
	PROTOCOLS=anytls
	pset CORE anytls singbox; pset PORT anytls 19443
	pset CORE anytls-reality ''; pset PORT anytls-reality ''
	REALITY_PRIVATE_KEY='' REALITY_PUBLIC_KEY='' REALITY_SHORT_ID=''
	REALITY_SNI='' REALITY_DEST='' AUTO_YES=1
	require_installed() { :; }
	ensure_cores() { :; }
	apply_or_die() { :; }
	choose_reality_target() { REALITY_SNI=www.example.com REALITY_DEST=www.example.com:443; }
	choose_tls() { return 99; }
	obtain_cert() { return 99; }
	if do_add_protocol anytls-reality >"$WORK/add.log" 2>&1; then result=ok; else result=failed; fi
	printf '%s|%s|%s' "$result" "$(pget CORE anytls-reality)" "$REALITY_PRIVATE_KEY"
)" 'ok|singbox|generated-private'
eq '删除 VLESS 后独立 AnyTLS-REALITY 继续保留自建站' "$(
	fixture
	PROTOCOLS='vless-reality anytls-reality' REALITY_SITE_ENABLED=1
	pset CORE vless-reality singbox; pset PORT vless-reality 19443
	require_installed() { :; }; apply_or_die() { :; }
	do_del_protocol vless-reality >/dev/null
	printf '%s|%s' "$PROTOCOLS" "$REALITY_SITE_ENABLED"
)" 'anytls-reality|1'
eq '删除最后一个 AnyTLS-REALITY 后停用自建站' "$(
	fixture
	PROTOCOLS='anytls anytls-reality' REALITY_SITE_ENABLED=1
	pset CORE anytls singbox; pset PORT anytls 19443
	require_installed() { :; }; apply_or_die() { :; }
	do_del_protocol anytls-reality >/dev/null
	printf '%s|%s' "$PROTOCOLS" "$REALITY_SITE_ENABLED"
)" 'anytls|0'

printf 'AnyTLS-REALITY 回归: %s 通过, %s 失败\n' "$PASS" "$FAIL"
[ "$FAIL" = 0 ]
