#!/usr/bin/env bash
# 协议配置回归: 临时状态、证书与配置, 不安装软件、不联网、不启动系统服务。
# shellcheck disable=SC2034
set -u

HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/.." && pwd)
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
export ONEBOX_SOURCE_ONLY=1 ONEBOX_DIR="$WORK/etc" ONEBOX_BIN_DIR="$WORK/bin" \
	ONEBOX_LOG_DIR="$WORK/log" ONEBOX_RUN_DIR="$WORK/run" ONEBOX_INITD_DIR="$WORK/initd" \
	ONEBOX_SITE_ROOT="$WORK/public" NO_COLOR=1
# shellcheck source=../onebox.sh
. "$ROOT/onebox.sh"

PASS=0 FAIL=0
eq() {
	if [ "$2" = "$3" ]; then
		PASS=$((PASS + 1))
	else
		FAIL=$((FAIL + 1))
		printf '  [失败] %s\n    实际: %s\n    期望: %s\n' "$1" "$2" "$3"
	fi
}
yes_() { if "$@"; then echo yes; else echo no; fi; }
port_in_use() { return 1; }
check_tls13() { return 0; }

# 跳跃范围的目标 UDP 端口可以位于范围内, 其他 UDP 协议仍不可使用该范围。
reset_state
PROTOCOLS='hysteria2 tuic shadowsocks trojan'
HY2_HOP=20000-40000
for port in 20000 30000 40000; do
	eq "Hysteria2 自身可使用跳跃范围端口 $port" "$(yes_ port_ok "$port" hysteria2 2>/dev/null)" yes
	eq "TUIC 不可使用跳跃范围端口 $port" "$(yes_ port_ok "$port" tuic 2>/dev/null)" no
done
eq "SS 的 UDP 不可占用跳跃范围" "$(yes_ port_ok 30000 shadowsocks 2>/dev/null)" no
eq "同编号 TCP 端口不受 UDP 跳跃影响" "$(yes_ port_ok 30000 trojan 2>/dev/null)" yes
eq "范围外 UDP 端口仍可使用" "$(yes_ port_ok 40001 tuic 2>/dev/null)" yes
pset PORT tuic 30000
eq "Hysteria2 仍不可使用其他协议已分配的 UDP 端口" "$(yes_ port_ok 30000 hysteria2 2>/dev/null)" no

owned_fixture() {
	reset_state
	AUTO_YES=1 OPT_REALITY_SITE='' OPT_SNI='' OPT_REALITY_DEST=''
	PROTOCOLS='vless-reality'
	pset CORE vless-reality singbox
	pset PORT vless-reality 8443
	REALITY_SITE_ENABLED=1 REALITY_SITE_DOMAIN=site.example.com REALITY_SITE_PORT=18443
	REALITY_SITE_TITLE='Test Site'
	REALITY_SNI=$REALITY_SITE_DOMAIN REALITY_DEST="127.0.0.1:$REALITY_SITE_PORT"
	REALITY_PRIVATE_KEY=private REALITY_PUBLIC_KEY=public REALITY_SHORT_ID=0123abcd
	UUID=550e8400-e29b-41d4-a716-446655440000
	SERVER_ADDR=203.0.113.9 SERVER_IPV4=203.0.113.9
}

# 新安装和后续 add 必须采用外部握手站点, 避免 ShadowTLS:443 握手回到自己。
eq "新安装自有网站 + ShadowTLS 默认使用外部握手站点" "$(
	owned_fixture
	PROTOCOLS='vless-reality shadowtls'
	pset CORE shadowtls singbox
	pset PORT shadowtls 443
	OPT_REALITY_SITE=site.example.com
	choose_extras >/dev/null
	printf '[%s]\n' "$(sb_inbound shadowtls)" | jq -r '.[0].handshake | "\(.server):\(.server_port)"'
)" www.microsoft.com:443
eq "现有自有网站 add ShadowTLS 默认使用独立外部站点" "$(
	owned_fixture
	require_installed() { :; }
	fill_missing_credentials() { :; }
	ensure_cores() { :; }
	apply_or_die() { :; }
	do_add_protocol shadowtls >/dev/null
	printf '%s|%s' "$SHADOWTLS_DEST" "$(pget PORT shadowtls)"
)" 'www.microsoft.com:443|443'
# die 会退出子 shell; 捕获退出码, 不能误把空输出当作成功。
eq "本机域名拒绝返回非零" "$(
	(owned_fixture; choose_sni() { printf -v "$1" '%s' Site.Example.COM; }; choose_shadowtls_target) >/dev/null 2>&1
	printf '%s' "$?"
)" 1
eq "交互选择本机域名后可重选外部站点" "$(
	owned_fixture
	choices=0
	is_interactive() { return 0; }
	choose_sni() {
		choices=$((choices + 1))
		if [ "$choices" = 1 ]; then printf -v "$1" '%s' SITE.EXAMPLE.COM; else printf -v "$1" '%s' addons.mozilla.org; fi
	}
	choose_shadowtls_target >/dev/null 2>&1
	printf '%s|%s' "$SHADOWTLS_DEST" "$choices"
)" 'addons.mozilla.org:443|2'
eq "外部 REALITY 目标仍可作为 ShadowTLS 默认值" "$(
	owned_fixture
	REALITY_SITE_ENABLED=0 REALITY_SITE_DOMAIN='' REALITY_SNI=addons.mozilla.org
	choose_shadowtls_target >/dev/null
	printf '%s' "$SHADOWTLS_DEST"
)" addons.mozilla.org:443

# VMess v2rayN JSON 分享格式支持 insecure / pcs。验证真实证书摘要和所有信任模式。
# 上游定义: 2dust/v2rayN, ServiceLib/Models/Dto/VmessQRCode.cs 和 Handler/Fmt/VmessFmt.cs。
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj /CN=proxy.example.com \
	-keyout "$WORK/key.pem" -out "$WORK/cert.pem" >/dev/null 2>&1 || exit 1
pin=$(openssl x509 -in "$WORK/cert.pem" -noout -fingerprint -sha256 | cut -d= -f2 | tr -d ':' | tr '[:upper:]' '[:lower:]')
reset_state
PROTOCOLS=vmess-ws TLS_MODE=self VMESS_TLS=1 CERT_FILE="$WORK/cert.pem" TLS_SNI=proxy.example.com
SERVER_ADDR=2001:db8::9 NODE_PREFIX='test "node"' UUID=550e8400-e29b-41d4-a716-446655440000 VMESS_PATH='/ws?q=1&v=2'
pset PORT vmess-ws 8443
vmess_json() { local uri; uri=$(link_of vmess-ws); printf '%s' "${uri#vmess://}" | base64 -d; }
json=$(vmess_json)
eq "VMess 自签 TLS 链接含固定证书指纹" "$(printf '%s' "$json" | jq -r .pcs)" "$pin"
eq "VMess 自签 TLS 链接可跳过 CA 并由指纹校验" "$(printf '%s' "$json" | jq -r '.tls + "|" + .insecure')" 'tls|1'
eq "VMess 分享 JSON 保留 IPv6 地址和 WebSocket 路径" "$(printf '%s' "$json" | jq -r '.add + "|" + .path')" '2001:db8::9|/ws?q=1&v=2'
eq "VMess 分享指纹与 Xray 全配置一致" "$(xrc_outbound vmess-ws proxy | jq -r .streamSettings.tlsSettings.pinnedPeerCertSha256)" "$pin"
TLS_MODE=custom CERT_PINNED=1
eq "自行提供的非受信证书同样导出 pin" "$(vmess_json | jq -r .pcs)" "$pin"
TLS_MODE=acme CERT_PINNED=0 DOMAIN=proxy.example.com
eq "受信证书链接不关闭 CA 校验" "$(vmess_json | jq 'has("insecure") or has("pcs")')" false
TLS_MODE=self VMESS_TLS=0
eq "明文 WS 链接不携带无用 TLS 信任设置" "$(vmess_json | jq -r '[.tls, (has("insecure") or has("pcs") | tostring)] | join("|")')" '|false'

printf '配置回归: %s 通过, %s 失败\n' "$PASS" "$FAIL"
[ "$FAIL" = 0 ]
