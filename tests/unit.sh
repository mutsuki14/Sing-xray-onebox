#!/usr/bin/env bash
# 状态变量由被加载的 onebox.sh 函数间接使用
# shellcheck disable=SC2034
#
# 单元测试: 纯函数 (无需网络与内核文件)
# 用法: bash tests/unit.sh
#
set -u

HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/.." && pwd)
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

export ONEBOX_SOURCE_ONLY=1 ONEBOX_DIR="$WORK/etc" NO_COLOR=1
# shellcheck source=../onebox.sh
. "$ROOT/onebox.sh"

PASS=0 FAIL=0
eq() {
	# eq "说明" 实际值 期望值
	if [ "$2" = "$3" ]; then
		PASS=$((PASS + 1))
	else
		FAIL=$((FAIL + 1))
		printf '  [失败] %s\n    实际: %s\n    期望: %s\n' "$1" "$2" "$3"
	fi
}
yes_() { if "$@"; then echo yes; else echo no; fi; }

# --- 系统识别 ---------------------------------------------------------------
osr() {
	# osr 文件内容 -> 输出 "ID|VERSION_ID"
	printf '%s\n' "$1" >"$WORK/os-release"
	OS_RELEASE_FILE="$WORK/os-release" detect_os
	printf '%s|%s' "$OS_ID" "$OS_VER"
}
eq "Ubuntu" "$(osr 'ID=ubuntu
VERSION_ID="24.04"
PRETTY_NAME="Ubuntu 24.04 LTS"')" "ubuntu|24.04"
eq "CentOS 7" "$(osr 'NAME="CentOS Linux"
ID="centos"
ID_LIKE="rhel fedora"
VERSION_ID="7"')" "centos|7"
eq "Alpine" "$(osr 'NAME="Alpine Linux"
ID=alpine
VERSION_ID=3.20.3')" "alpine|3.20.3"
eq "Rocky (大写 ID 转小写)" "$(osr 'ID="Rocky"
VERSION_ID="9.4"')" "rocky|9.4"

# --- 架构映射 ---------------------------------------------------------------
arch_of() {
	FAKE_ARCH=$1
	uname() { echo "$FAKE_ARCH"; }
	detect_arch
	unset -f uname
	printf '%s|%s' "$SB_ARCH" "$XR_ARCH"
}
eq "x86_64" "$(arch_of x86_64)" "amd64|64"
eq "aarch64" "$(arch_of aarch64)" "arm64|arm64-v8a"
eq "i686" "$(arch_of i686)" "386|32"
eq "s390x" "$(arch_of s390x)" "s390x|s390x"
eq "riscv64" "$(arch_of riscv64)" "riscv64|riscv64"
eq "loongarch64" "$(arch_of loongarch64)" "loong64|loong64"
# uname -m 对 MIPS 不区分字节序, 按本机 ELF 头判断 (测试机为小端)
eq "mips (小端主机)" "$(arch_of mips)" "mipsle|mips32le"
eq "mips64 (小端主机)" "$(arch_of mips64)" "mips64le|mips64le"

# --- 编码与转义 -------------------------------------------------------------
eq "urlencode ASCII" "$(urlencode 'a b#c&d?e=f%g+h/')" "a%20b%23c%26d%3Fe%3Df%25g%2Bh%2F"
eq "urlencode 中文" "$(urlencode '香港')" "%E9%A6%99%E6%B8%AF"
eq "urlencode 保留字符" "$(urlencode 'A-z_0.9~')" "A-z_0.9~"
eq "urlencode emoji" "$(urlencode '🇭🇰')" "%F0%9F%87%AD%F0%9F%87%B0"
eq "json_str 转义" "$(json_str 'a"b\c')" '"a\"b\\c"'
eq "yq 单引号转义" "$(yq "it's")" "'it''s'"
eq "b64" "$(printf 'hello' | b64)" "aGVsbG8="

# --- 版本比较 ---------------------------------------------------------------
eq "ver_ge 1.12.0 >= 1.11.9" "$(yes_ ver_ge 1.12.0 1.11.9)" yes
eq "ver_ge 1.9 >= 1.10" "$(yes_ ver_ge 1.9 1.10)" no
eq "ver_ge 5.15.0 >= 4.9" "$(yes_ ver_ge 5.15.0 4.9)" yes
eq "ver_ge 4.4.0 >= 4.9" "$(yes_ ver_ge 4.4.0 4.9)" no
eq "ver_ge 相等" "$(yes_ ver_ge 26.3.27 26.3.27)" yes

# --- 校验 -------------------------------------------------------------------
eq "域名 www.bing.com" "$(yes_ valid_domain www.bing.com)" yes
eq "域名 1" "$(yes_ valid_domain 1)" no
eq "域名 localhost" "$(yes_ valid_domain localhost)" no
eq "域名 带空格" "$(yes_ valid_domain 'a b.com')" no

# --- 随机值 -----------------------------------------------------------------
s=$(rand_str 24)
eq "rand_str 24 位字母数字" "$([[ "$s" =~ ^[A-Za-z0-9]{24}$ ]] && echo ok)" ok
eq "rand_hex 8 字节" "$([[ "$(rand_hex 8)" =~ ^[0-9a-f]{16}$ ]] && echo ok)" ok
eq "UUID 格式" "$([[ "$(gen_uuid)" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$ ]] && echo ok)" ok
eq "SS-2022 aes-128 密钥 16 字节" "$(gen_ss_password 2022-blake3-aes-128-gcm | base64 -d | wc -c | tr -d ' ')" 16
eq "SS-2022 aes-256 密钥 32 字节" "$(gen_ss_password 2022-blake3-aes-256-gcm | base64 -d | wc -c | tr -d ' ')" 32
p=$(rand_port)
eq "rand_port 范围" "$([ "$p" -ge 10000 ] && [ "$p" -le 30000 ] && echo ok)" ok

# --- 协议目录与状态 ---------------------------------------------------------
reset_state
eq "normalize_protocols 排序去重" "$(normalize_protocols tuic vless-reality tuic hysteria2)" "vless-reality hysteria2 tuic"
PROTOCOLS="vless-reality vless-xhttp hysteria2 trojan"
assign_cores xray
eq "assign_cores xray: reality" "$(pget CORE vless-reality)" xray
eq "assign_cores xray: hysteria2 -> sing-box" "$(pget CORE hysteria2)" singbox
assign_cores singbox
eq "assign_cores singbox: xhttp -> xray" "$(pget CORE vless-xhttp)" xray
eq "core_used xray" "$(yes_ core_used xray)" yes
eq "any_needs_cert" "$(yes_ any_needs_cert)" yes
PROTOCOLS="vless-reality"
eq "any_needs_cert (仅 reality)" "$(yes_ any_needs_cert)" no

# 状态保存与读取 (含特殊字符)
reset_state
PROTOCOLS="vless-reality hysteria2"
NODE_NAME="香港 A'b"
PASSWORD='p@ss w"rd$x'
pset PORT vless-reality 443
pset CORE vless-reality xray
save_state
eq "状态文件权限" "$(stat -c %a "$STATE_FILE")" 600
reset_state
load_state
eq "读取 PROTOCOLS" "$PROTOCOLS" "vless-reality hysteria2"
eq "读取 NODE_NAME" "$NODE_NAME" "香港 A'b"
eq "读取 PASSWORD" "$PASSWORD" 'p@ss w"rd$x'
eq "读取 PORT" "$(pget PORT vless-reality)" 443
eq "读取 CORE" "$(pget CORE vless-reality)" xray

# 端口归属 (区分 tcp / udp)
eq "443/tcp 属于 reality" "$(yes_ port_used_by_onebox 443 tcp)" yes
eq "443/udp 不属于 reality" "$(yes_ port_used_by_onebox 443 udp)" no

# IPv6 地址在链接中加方括号
SERVER_ADDR="2001:db8::1"
eq "uri_host IPv6" "$(uri_host)" "[2001:db8::1]"
SERVER_ADDR="1.2.3.4"
eq "uri_host IPv4" "$(uri_host)" "1.2.3.4"

# --- 评审发现的问题回归测试 ------------------------------------------------
reset_state
PROTOCOLS="shadowsocks"
pset CORE shadowsocks xray
eq "端口前导零被拒绝" "$(yes_ port_ok 0443 shadowsocks 2>/dev/null)" no
eq "端口 65536 被拒绝" "$(yes_ port_ok 65536 shadowsocks 2>/dev/null)" no

# ask(): 去掉方向键产生的转义序列与控制字符
printf 'HK\033[D\033[C-01\033OA\n' >"$WORK/tty"
got=$(
	AUTO_YES=0 TTY_IN="$WORK/tty"
	v=""
	ask v "名称" "x" 2>/dev/null
	printf '%s' "$v"
)
eq "ask 去除转义序列" "$got" "HK-01"

# 节点名含逗号时 sing-box 客户端 selector 与 tag 一致; 无 sing-box 可用协议时不输出配置
reset_state
PROTOCOLS="vless-reality shadowsocks" NODE_NAME="HK,01" SERVER_ADDR=1.2.3.4
UUID=$(gen_uuid) SS_METHOD=2022-blake3-aes-128-gcm SS_PASSWORD=$(gen_ss_password 2022-blake3-aes-128-gcm)
REALITY_SNI=www.microsoft.com REALITY_PUBLIC_KEY=abc REALITY_SHORT_ID=0123abcd
pset PORT vless-reality 443
pset PORT shadowsocks 8388
if command -v jq >/dev/null 2>&1; then
	eq "selector 引用的节点均存在" "$(gen_singbox_client notun | jq -r '([.outbounds[].tag]) as $t | [.outbounds[] | select(.type == "selector" or .type == "urltest") | .outbounds[] | select(. as $x | $t | index($x) | not)] | length')" 0
fi
PROTOCOLS="vless-xhttp"
sb_gen_quiet() { gen_singbox_client notun >/dev/null; }
eq "无 sing-box 可用协议时不生成" "$(yes_ sb_gen_quiet)" no

# 端口跳跃范围仅在 Hysteria2 启用时生效
PROTOCOLS="tuic" HY2_HOP="20000-40000"
eq "未启用 Hysteria2 时不占用跳跃范围" "$(yes_ port_in_hop_range 25000)" no
PROTOCOLS="hysteria2 tuic"
eq "启用 Hysteria2 时占用跳跃范围" "$(yes_ port_in_hop_range 25000)" yes

# VMess TLS 状态固定, 不随证书方式变化
PROTOCOLS="vmess-ws" TLS_MODE=self VMESS_TLS=1
eq "VMESS_TLS=1 覆盖自签默认" "$(yes_ vmess_tls_enabled)" yes
TLS_MODE=acme VMESS_TLS=0
eq "VMESS_TLS=0 覆盖 ACME 默认" "$(yes_ vmess_tls_enabled)" no

# 显示宽度补齐
eq "pad 中文" "$(pad 协议 6)|" "协议  |"
eq "pad ASCII" "$(pad ab 4)|" "ab  |"

echo "通过 ${PASS} 项, 失败 ${FAIL} 项"
[ "$FAIL" = 0 ]
