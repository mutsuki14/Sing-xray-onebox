#!/usr/bin/env bash
#
# Sing-Xray-Onebox —— sing-box / Xray 多协议组合一键安装与管理脚本
#
#   项目地址: https://github.com/mutsuki14/Sing-xray-onebox
#   支持系统: Debian / Ubuntu / CentOS / RHEL / Rocky / Alma / Fedora / Oracle /
#             Amazon Linux / openEuler / Alpine / Arch / openSUSE 等
#   支持架构: amd64 / arm64 / armv7 / armv6 / 386 / s390x / riscv64 / loong64 ...
#   服务端内核: sing-box, Xray (可单独或同时使用)
#   客户端输出: 分享链接 / 订阅, mihomo (Clash Meta), sing-box, Xray
#
#   用法:  bash onebox.sh            # 交互式菜单
#          bash onebox.sh help       # 查看全部命令
#
# shellcheck disable=SC2317

# ---------------------------------------------------------------------------
# POSIX 前置段: 若不是在 bash 中运行 (例如 Alpine 的 sh), 尝试安装 bash 后重新执行
# ---------------------------------------------------------------------------
if [ -z "${BASH_VERSION:-}" ]; then
	if ! command -v bash >/dev/null 2>&1; then
		if command -v apk >/dev/null 2>&1; then
			apk add --no-cache bash >/dev/null 2>&1
		elif command -v opkg >/dev/null 2>&1; then
			opkg update >/dev/null 2>&1 && opkg install bash >/dev/null 2>&1
		fi
	fi
	if command -v bash >/dev/null 2>&1 && [ -f "$0" ]; then
		exec bash "$0" "$@"
	fi
	echo "本脚本需要 bash, 请先安装 bash 后执行: bash $0" >&2
	exit 1
fi

if [ "${BASH_VERSINFO[0]:-0}" -lt 4 ]; then
	echo "本脚本需要 bash 4.0 或更高版本 (当前: ${BASH_VERSION})" >&2
	exit 1
fi

export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:${PATH}"
umask 022

# ---------------------------------------------------------------------------
# 常量
# ---------------------------------------------------------------------------
readonly SCRIPT_VERSION="1.0.0"
readonly SCRIPT_REPO="mutsuki14/Sing-xray-onebox"
readonly SCRIPT_RAW_URL="https://raw.githubusercontent.com/${SCRIPT_REPO}/main/onebox.sh"

ONEBOX_DIR="${ONEBOX_DIR:-/etc/onebox}"
BIN_DIR="${ONEBOX_BIN_DIR:-/opt/onebox/bin}"
LOG_DIR="${ONEBOX_LOG_DIR:-/var/log/onebox}"
RUN_DIR="${ONEBOX_RUN_DIR:-/run/onebox}"
STATE_FILE="${ONEBOX_DIR}/onebox.conf"
TLS_DIR="${ONEBOX_DIR}/tls"
CLIENT_DIR="${ONEBOX_DIR}/client"
SB_CONF="${ONEBOX_DIR}/sing-box.json"
XR_CONF="${ONEBOX_DIR}/xray.json"
SB_BIN="${BIN_DIR}/sing-box"
XR_BIN="${BIN_DIR}/xray"
CMD_PATH="/usr/local/bin/onebox"
SB_SERVICE="onebox-sing-box"
XR_SERVICE="onebox-xray"

# 当 GitHub 最新版本号无法获取时使用的保底版本
readonly FALLBACK_SB_VERSION="1.14.2"
readonly FALLBACK_XR_VERSION="26.3.27"

# 全部协议 (顺序即菜单顺序)
readonly ALL_PROTOCOLS="vless-reality vless-xhttp vless-grpc vless-ws vmess-ws trojan shadowsocks hysteria2 tuic anytls shadowtls"

# 运行参数 (可由命令行 / 环境变量覆盖)
AUTO_YES="${ONEBOX_AUTO:-0}"      # 1 = 全部使用默认值, 不再询问
GH_PROXY="${GH_PROXY:-}"          # GitHub 下载加速前缀, 例如 https://ghfast.top/
LOCAL_SB_BIN="${ONEBOX_SINGBOX_BIN:-}" # 使用本地 sing-box 二进制 (离线安装)
LOCAL_XR_BIN="${ONEBOX_XRAY_BIN:-}"    # 使用本地 xray 二进制 (离线安装)

# ---------------------------------------------------------------------------
# 输出与交互
# ---------------------------------------------------------------------------
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
	RED=$'\033[31m' GREEN=$'\033[32m' YELLOW=$'\033[33m' BLUE=$'\033[36m' BOLD=$'\033[1m' PLAIN=$'\033[0m'
else
	RED='' GREEN='' YELLOW='' BLUE='' BOLD='' PLAIN=''
fi

info() { printf '%s[信息]%s %s\n' "$GREEN" "$PLAIN" "$*"; }
warn() { printf '%s[警告]%s %s\n' "$YELLOW" "$PLAIN" "$*" >&2; }
err() { printf '%s[错误]%s %s\n' "$RED" "$PLAIN" "$*" >&2; }
die() {
	err "$@"
	exit 1
}
title() { printf '\n%s%s==== %s ====%s\n' "$BOLD" "$BLUE" "$*" "$PLAIN"; }
hr() { printf '%s\n' "------------------------------------------------------------"; }

# 交互输入来源: 标准输入是终端时直接读取; 通过管道运行 (curl | bash) 时改从 /dev/tty 读取
TTY_IN=""
setup_tty() {
	if [ -t 0 ]; then
		TTY_IN=/dev/stdin
	elif (: </dev/tty) 2>/dev/null; then
		TTY_IN=/dev/tty
	else
		TTY_IN=""
	fi
}

# is_interactive: 是否可以向用户提问
is_interactive() { [ "$AUTO_YES" != 1 ] && [ -n "$TTY_IN" ]; }

# ask VAR "提示" "默认值"  —— 读取一行输入, 为空时使用默认值
# (局部变量使用 _a_ 前缀, 避免与调用方传入的变量名冲突)
ask() {
	local _a_var=$1 _a_prompt=$2 _a_def=${3-} _a_val=""
	if is_interactive; then
		if [ -n "$_a_def" ]; then
			printf '%s [默认: %s%s%s]: ' "$_a_prompt" "$YELLOW" "$_a_def" "$PLAIN" >&2
		else
			printf '%s: ' "$_a_prompt" >&2
		fi
		IFS= read -r _a_val <"$TTY_IN" || _a_val=""
		# 去掉首尾空白
		_a_val="${_a_val#"${_a_val%%[![:space:]]*}"}"
		_a_val="${_a_val%"${_a_val##*[![:space:]]}"}"
	fi
	[ -z "$_a_val" ] && _a_val=$_a_def
	printf -v "$_a_var" '%s' "$_a_val"
}

# ask_yn "提示" y|n  —— 是返回 0, 否返回 1
ask_yn() {
	local _y_prompt=$1 _y_def=${2:-y} _y_val
	while :; do
		ask _y_val "$_y_prompt (y/n)" "$_y_def"
		case "$_y_val" in
		[Yy] | [Yy][Ee][Ss]) return 0 ;;
		[Nn] | [Nn][Oo]) return 1 ;;
		*)
			warn "请输入 y 或 n"
			is_interactive || return 1
			;;
		esac
	done
}

# confirm "提示" [默认 y|n]  —— 用于确认操作; 指定了 -y 时直接视为确认
confirm() {
	[ "$AUTO_YES" = 1 ] && return 0
	ask_yn "$1" "${2:-n}"
}

# ask_num VAR "提示" 默认值 最小值 最大值
ask_num() {
	local _n_var=$1 _n_prompt=$2 _n_def=$3 _n_min=$4 _n_max=$5 _n_val
	while :; do
		ask _n_val "$_n_prompt" "$_n_def"
		if [[ "$_n_val" =~ ^[0-9]+$ ]] && [ "$_n_val" -ge "$_n_min" ] && [ "$_n_val" -le "$_n_max" ]; then
			printf -v "$_n_var" '%s' "$_n_val"
			return 0
		fi
		warn "请输入 ${_n_min}-${_n_max} 之间的数字"
		is_interactive || return 1
	done
}

pause() {
	is_interactive || return 0
	printf '%s' "按回车键继续..." >&2
	IFS= read -r _ <"$TTY_IN" || true
}

has() { command -v "$1" >/dev/null 2>&1; }

# pad 文本 宽度 —— 按终端显示宽度补齐空格 (中文字符按 2 列计算, printf %-Ns 按字节计算会错位)
pad() {
	local s=$1 w=$2 bytes non width
	bytes=$(printf '%s' "$s" | LC_ALL=C wc -c)
	non=$(printf '%s' "$s" | LC_ALL=C tr -d '\000-\177' | LC_ALL=C wc -c)
	width=$((bytes - non + non / 3 * 2))
	printf '%s' "$s"
	[ "$width" -lt "$w" ] && printf '%*s' $((w - width)) ''
	return 0
}

# 生成随机字符串 (字母数字)
rand_str() {
	local len=${1:-16} s=""
	while [ "${#s}" -lt "$len" ]; do
		s+=$(head -c 64 /dev/urandom | LC_ALL=C tr -dc 'A-Za-z0-9')
	done
	printf '%s' "${s:0:$len}"
}

rand_hex() { head -c "${1:-8}" /dev/urandom | od -An -tx1 | tr -d ' \n'; }

rand_base64() { head -c "${1:-16}" /dev/urandom | base64 | tr -d '\n'; }

# 10000-30000 之间的随机端口 (避开常见的临时端口范围)
rand_port() { printf '%s' $(((RANDOM * 32768 + RANDOM) % 20001 + 10000)); }

# URL 编码 (用于分享链接中的参数与备注)
urlencode() {
	local LC_ALL=C s=$1 i c out=""
	for ((i = 0; i < ${#s}; i++)); do
		c=${s:i:1}
		case "$c" in
		[A-Za-z0-9.~_-]) out+=$c ;;
		*) out+=$(printf '%%%02X' "'$c") ;;
		esac
	done
	printf '%s' "$out"
}

# base64 单行输出 (兼容 busybox)
b64() { base64 | tr -d '\n'; }

# JSON 字符串转义
json_str() {
	local s=$1
	s=${s//\\/\\\\}
	s=${s//\"/\\\"}
	s=${s//$'\n'/\\n}
	s=${s//$'\t'/\\t}
	s=${s//$'\r'/\\r}
	printf '"%s"' "$s"
}

# 版本比较: ver_ge 1.12.0 1.11.9 -> 真
ver_ge() {
	[ "$1" = "$2" ] && return 0
	local IFS=.- i a b
	read -ra a <<<"$1"
	read -ra b <<<"$2"
	for ((i = 0; i < 4; i++)); do
		local x=${a[i]:-0} y=${b[i]:-0}
		x=${x//[!0-9]/} y=${y//[!0-9]/}
		x=${x:-0} y=${y:-0}
		((10#$x > 10#$y)) && return 0
		((10#$x < 10#$y)) && return 1
	done
	return 0
}

# ---------------------------------------------------------------------------
# 系统检测
# ---------------------------------------------------------------------------
OS_ID="" OS_LIKE="" OS_VER="" OS_NAME="" PKG="" INIT="" VIRT="" ARCH_RAW=""
SB_ARCH="" XR_ARCH=""

require_root() {
	[ "$(id -u)" = 0 ] || die "请使用 root 用户运行本脚本 (可先执行 sudo -i)"
}

_osr_get() {
	# 读取 os-release 中的字段并去掉引号
	sed -n "s/^$1=//p" "${OS_RELEASE_FILE:-/etc/os-release}" 2>/dev/null | head -n1 | tr -d "\"'"
}

detect_os() {
	if [ -r "${OS_RELEASE_FILE:-/etc/os-release}" ]; then
		OS_ID=$(_osr_get ID | tr 'A-Z' 'a-z')
		OS_LIKE=$(_osr_get ID_LIKE | tr 'A-Z' 'a-z')
		OS_VER=$(_osr_get VERSION_ID)
		OS_NAME=$(_osr_get PRETTY_NAME)
	elif [ -r /etc/redhat-release ]; then
		OS_ID=centos OS_LIKE="rhel fedora"
		OS_NAME=$(head -n1 /etc/redhat-release)
		OS_VER=$(grep -oE '[0-9]+' /etc/redhat-release | head -n1)
	elif [ -r /etc/alpine-release ]; then
		OS_ID=alpine OS_VER=$(cat /etc/alpine-release) OS_NAME="Alpine Linux ${OS_VER}"
	elif [ -r /etc/debian_version ]; then
		OS_ID=debian OS_VER=$(cat /etc/debian_version) OS_NAME="Debian ${OS_VER}"
	fi
	[ -n "$OS_NAME" ] || OS_NAME="${OS_ID:-unknown} ${OS_VER}"

	# 以实际存在的包管理器为准 (比按发行版 ID 判断更可靠)
	if has apt-get; then
		PKG=apt
	elif has dnf; then
		PKG=dnf
	elif has yum; then
		PKG=yum
	elif has apk; then
		PKG=apk
	elif has pacman; then
		PKG=pacman
	elif has zypper; then
		PKG=zypper
	elif has xbps-install; then
		PKG=xbps
	elif has emerge; then
		PKG=emerge
	else
		PKG=""
	fi
}

detect_init() {
	if [ -d /run/systemd/system ] && has systemctl; then
		INIT=systemd
	elif [ -x /sbin/openrc-run ] || has openrc-run; then
		INIT=openrc
	else
		INIT=none
	fi
}

detect_virt() {
	VIRT=""
	if has systemd-detect-virt; then
		VIRT=$(systemd-detect-virt 2>/dev/null)
	fi
	if [ -z "$VIRT" ] || [ "$VIRT" = none ]; then
		if [ -d /proc/vz ] && [ ! -d /proc/bc ]; then
			VIRT=openvz
		elif [ -f /.dockerenv ]; then
			VIRT=docker
		elif grep -qa 'container=lxc' /proc/1/environ 2>/dev/null; then
			VIRT=lxc
		elif grep -qa 'container=' /proc/1/environ 2>/dev/null; then
			VIRT=container
		fi
	fi
	[ -n "$VIRT" ] || VIRT=none
}

is_container_virt() {
	case "$VIRT" in openvz | lxc | lxc-libvirt | docker | podman | container | systemd-nspawn | wsl) return 0 ;; *) return 1 ;; esac
}

detect_arch() {
	ARCH_RAW=$(uname -m)
	case "$ARCH_RAW" in
	x86_64 | amd64) SB_ARCH=amd64 XR_ARCH=64 ;;
	i386 | i486 | i586 | i686 | x86) SB_ARCH=386 XR_ARCH=32 ;;
	armv7* | armv8l) SB_ARCH=armv7 XR_ARCH=arm32-v7a ;;
	aarch64 | arm64 | armv8*) SB_ARCH=arm64 XR_ARCH=arm64-v8a ;;
	armv6*) SB_ARCH=armv6 XR_ARCH=arm32-v6 ;;
	armv5* | armv4* | arm) SB_ARCH=armv5 XR_ARCH=arm32-v5 ;;
	s390x) SB_ARCH=s390x XR_ARCH=s390x ;;
	riscv64) SB_ARCH=riscv64 XR_ARCH=riscv64 ;;
	loongarch64 | loong64) SB_ARCH=loong64 XR_ARCH=loong64 ;;
	ppc64le) SB_ARCH=ppc64le XR_ARCH=ppc64le ;;
	mips64el | mips64le) SB_ARCH=mips64le XR_ARCH=mips64le ;;
	mips64) SB_ARCH=mips64 XR_ARCH=mips64 ;;
	mipsel | mipsle) SB_ARCH=mipsle XR_ARCH=mips32le ;;
	mips) SB_ARCH=mips XR_ARCH=mips32 ;;
	*) die "暂不支持的 CPU 架构: ${ARCH_RAW}" ;;
	esac
	# 32 位 ARM 若内核报告 v7 但无硬件浮点, 退回 v6
	if [ "$SB_ARCH" = armv7 ] && [ -r /proc/cpuinfo ] && ! grep -qiE 'vfpv3|vfpv4|neon' /proc/cpuinfo; then
		SB_ARCH=armv6 XR_ARCH=arm32-v6
	fi
}

# ---------------------------------------------------------------------------
# 软件包安装
# ---------------------------------------------------------------------------
_PKG_UPDATED=0
pkg_update() {
	[ "$_PKG_UPDATED" = 1 ] && return 0
	_PKG_UPDATED=1
	case "$PKG" in
	apt) DEBIAN_FRONTEND=noninteractive apt-get update -qq >/dev/null 2>&1 ;;
	apk) apk update >/dev/null 2>&1 ;;
	pacman) pacman -Sy --noconfirm >/dev/null 2>&1 ;;
	zypper) zypper -n refresh >/dev/null 2>&1 ;;
	xbps) xbps-install -S >/dev/null 2>&1 ;;
	esac
	return 0
}

pkg_install() {
	[ $# -gt 0 ] || return 0
	case "$PKG" in
	apt) DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends "$@" >/dev/null 2>&1 ;;
	dnf) dnf install -y -q "$@" >/dev/null 2>&1 ;;
	yum) yum install -y -q "$@" >/dev/null 2>&1 ;;
	apk) apk add --no-cache "$@" >/dev/null 2>&1 ;;
	pacman) pacman -S --noconfirm --needed "$@" >/dev/null 2>&1 ;;
	zypper) zypper -n install -y "$@" >/dev/null 2>&1 ;;
	xbps) xbps-install -y "$@" >/dev/null 2>&1 ;;
	emerge) emerge --quiet --noreplace "$@" >/dev/null 2>&1 ;;
	*) return 1 ;;
	esac
}

# 命令 -> 各包管理器下的包名
pkg_name_of() {
	local cmd=$1
	case "$cmd:$PKG" in
	ss:dnf | ss:yum) echo iproute ;;
	ss:emerge) echo sys-apps/iproute2 ;;
	ss:*) echo iproute2 ;;
	qrencode:apk) echo libqrencode-tools ;;
	qrencode:emerge) echo media-gfx/qrencode ;;
	crontab:apt) echo cron ;;
	crontab:apk) echo cronie ;;
	crontab:xbps) echo cronie ;;
	crontab:emerge) echo sys-process/cronie ;;
	crontab:*) echo cronie ;;
	update-ca-certificates:* | ca-certificates:*) echo ca-certificates ;;
	base64:* | od:* | head:*) echo coreutils ;;
	*) echo "$cmd" ;;
	esac
}

# ensure_cmds cmd1 cmd2 ...  —— 缺少的命令自动安装对应软件包
ensure_cmds() {
	local c missing=() pkgs=()
	for c in "$@"; do has "$c" || missing+=("$c"); done
	[ ${#missing[@]} -eq 0 ] && return 0
	[ -n "$PKG" ] || {
		warn "未识别的包管理器, 请手动安装: ${missing[*]}"
		return 1
	}
	for c in "${missing[@]}"; do pkgs+=("$(pkg_name_of "$c")"); done
	info "安装依赖: ${pkgs[*]}"
	pkg_update
	pkg_install "${pkgs[@]}" || {
		# 逐个安装, 避免一个包名不存在导致全部失败
		for c in "${pkgs[@]}"; do pkg_install "$c" || true; done
	}
	for c in "${missing[@]}"; do has "$c" || return 1; done
	return 0
}

install_base_deps() {
	local need=(tar openssl base64 od awk sed grep head)
	has curl || has wget || need+=(curl)
	has ss || has netstat || need+=(ss)
	[ -d /etc/ssl/certs ] || need+=(ca-certificates)
	ensure_cmds "${need[@]}" || true
	# CA 证书: 某些精简镜像默认不带
	if [ ! -s /etc/ssl/certs/ca-certificates.crt ] && [ ! -s /etc/pki/tls/certs/ca-bundle.crt ] && [ ! -s /etc/ssl/ca-bundle.pem ]; then
		pkg_update
		pkg_install ca-certificates || true
	fi
	local c
	for c in tar openssl base64 od awk sed grep head; do
		has "$c" || die "缺少必需命令: $c, 请手动安装后重试"
	done
	has curl || has wget || die "缺少 curl 或 wget, 请手动安装后重试"
}

# ---------------------------------------------------------------------------
# 网络: 下载 / 公网 IP
# ---------------------------------------------------------------------------
# http_get URL [输出文件]  (无输出文件时打印到标准输出)
http_get() {
	local url=$1 out=${2:-}
	if has curl; then
		if [ -n "$out" ]; then
			curl -fsSL --retry 2 --connect-timeout 10 --max-time 300 -o "$out" "$url"
		else
			curl -fsSL --retry 2 --connect-timeout 10 --max-time 30 "$url"
		fi
	else
		if [ -n "$out" ]; then
			wget -q -T 30 -t 2 -O "$out" "$url"
		else
			wget -q -T 15 -t 2 -O - "$url"
		fi
	fi
}

# 带 GitHub 加速前缀的下载
gh_url() {
	local url=$1
	if [ -n "$GH_PROXY" ]; then
		printf '%s%s' "${GH_PROXY%/}/" "$url"
	else
		printf '%s' "$url"
	fi
}

# 获取 GitHub 仓库最新 release 的版本号 (不带 v 前缀)
gh_latest_version() {
	local repo=$1 tag=""
	tag=$(http_get "https://api.github.com/repos/${repo}/releases/latest" 2>/dev/null |
		sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -n1)
	if [ -z "$tag" ] && has curl; then
		# 备用: 解析 releases/latest 跳转地址
		tag=$(curl -fsSI --connect-timeout 10 --max-time 20 "$(gh_url "https://github.com/${repo}/releases/latest")" 2>/dev/null |
			tr -d '\r' | sed -n 's#^[Ll]ocation:.*/releases/tag/\(.*\)$#\1#p' | tail -n1)
	fi
	tag=${tag#v}
	[[ "$tag" =~ ^[0-9]+\.[0-9]+(\.[0-9]+)?$ ]] || tag=""
	printf '%s' "$tag"
}

_ip_from() {
	# _ip_from 4|6 URL
	local fam=$1 url=$2 ip=""
	if has curl; then
		ip=$(curl -"$fam" -fsS --connect-timeout 4 --max-time 6 "$url" 2>/dev/null)
	else
		ip=$(wget -"$fam" -q -T 6 -t 1 -O - "$url" 2>/dev/null)
	fi
	ip=$(printf '%s' "$ip" | tr -d ' \r\n')
	case "$fam" in
	4) [[ "$ip" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || ip="" ;;
	6) [[ "$ip" =~ ^[0-9a-fA-F:]+$ ]] && [[ "$ip" == *:* ]] || ip="" ;;
	esac
	printf '%s' "$ip"
}

detect_public_ip() {
	SERVER_IPV4="" SERVER_IPV6=""
	local u
	for u in https://api.ipify.org https://ipv4.icanhazip.com https://api-ipv4.ip.sb/ip https://ifconfig.co/ip; do
		SERVER_IPV4=$(_ip_from 4 "$u")
		[ -n "$SERVER_IPV4" ] && break
	done
	for u in https://api64.ipify.org https://ipv6.icanhazip.com https://api-ipv6.ip.sb/ip https://ifconfig.co/ip; do
		SERVER_IPV6=$(_ip_from 6 "$u")
		[ -n "$SERVER_IPV6" ] && break
	done
	if [ -z "$SERVER_IPV4" ] && [ -z "$SERVER_IPV6" ]; then
		# 离线兜底: 取默认路由网卡上的地址
		SERVER_IPV4=$(ip -4 route get 1.1.1.1 2>/dev/null | sed -n 's/.* src \([0-9.]*\).*/\1/p' | head -n1)
	fi
}

# 本机是否启用了 IPv6 (决定监听 :: 还是 0.0.0.0)
host_has_ipv6() { [ -f /proc/net/if_inet6 ] && [ "$(cat /proc/sys/net/ipv6/conf/all/disable_ipv6 2>/dev/null || echo 0)" != 1 ]; }

# ---------------------------------------------------------------------------
# 端口
# ---------------------------------------------------------------------------
# port_in_use 端口 tcp|udp
port_in_use() {
	local port=$1 proto=${2:-tcp} hex
	if has ss; then
		if [ "$proto" = udp ]; then
			ss -lnu 2>/dev/null | awk 'NR>1{print $4}' | grep -qE "[:.]${port}\$"
		else
			ss -lnt 2>/dev/null | awk 'NR>1{print $4}' | grep -qE "[:.]${port}\$"
		fi
		return $?
	fi
	if has netstat; then
		if [ "$proto" = udp ]; then
			netstat -lnu 2>/dev/null | awk '{print $4}' | grep -qE "[:.]${port}\$"
		else
			netstat -lnt 2>/dev/null | awk '{print $4}' | grep -qE "[:.]${port}\$"
		fi
		return $?
	fi
	# 兜底: 直接解析 /proc/net
	hex=$(printf '%04X' "$port")
	if [ "$proto" = udp ]; then
		cat /proc/net/udp /proc/net/udp6 2>/dev/null | awk -v p=":$hex" 'NR>1 && substr($2, length($2)-4)==p {f=1} END{exit !f}'
	else
		cat /proc/net/tcp /proc/net/tcp6 2>/dev/null | awk -v p=":$hex" 'NR>1 && $4=="0A" && substr($2, length($2)-4)==p {f=1} END{exit !f}'
	fi
}

# ---------------------------------------------------------------------------
# 状态 (保存在 /etc/onebox/onebox.conf)
# ---------------------------------------------------------------------------
readonly STATE_KEYS="PROTOCOLS SERVER_ADDR SERVER_IPV4 SERVER_IPV6 NODE_NAME LISTEN_ADDR
UUID PASSWORD SS_METHOD SS_PASSWORD
REALITY_PRIVATE_KEY REALITY_PUBLIC_KEY REALITY_SHORT_ID REALITY_SNI REALITY_DEST
WS_PATH VMESS_PATH XHTTP_PATH GRPC_SERVICE
HY2_OBFS HY2_OBFS_PASSWORD HY2_HOP
SHADOWTLS_SNI SHADOWTLS_DEST SHADOWTLS_PASSWORD SHADOWTLS_SS_PASSWORD
TLS_MODE DOMAIN TLS_SNI CERT_FILE KEY_FILE ACME_METHOD
SB_VERSION XR_VERSION BLOCK_PRIVATE BLOCK_BT INSTALLED_AT"

# 初始化全部状态变量为空 (避免继承同名环境变量)
reset_state() {
	local k p
	for k in $STATE_KEYS; do printf -v "$k" '%s' ""; done
	for p in $ALL_PROTOCOLS; do
		pset PORT "$p" ""
		pset CORE "$p" ""
	done
}

# pget PORT vless-reality  -> 取 PORT_vless_reality
pget() {
	local __v="$1_${2//-/_}"
	printf '%s' "${!__v-}"
}
# pset PORT vless-reality 443
pset() { printf -v "$1_${2//-/_}" '%s' "$3"; }

save_state() {
	mkdir -p "$ONEBOX_DIR" && chmod 700 "$ONEBOX_DIR"
	local tmp="${STATE_FILE}.tmp" k p v
	{
		echo "# Sing-Xray-Onebox 状态文件 (由脚本自动生成, 请勿手动修改)"
		for k in $STATE_KEYS; do printf '%s=%q\n' "$k" "${!k-}"; done
		for p in $ALL_PROTOCOLS; do
			for k in PORT CORE; do
				v="${k}_${p//-/_}"
				if [ -n "${!v-}" ]; then printf '%s=%q\n' "$v" "${!v}"; fi
			done
		done
	} >"$tmp"
	[ -s "$tmp" ] || die "无法写入 ${STATE_FILE}"
	chmod 600 "$tmp"
	mv -f "$tmp" "$STATE_FILE"
}

load_state() {
	[ -f "$STATE_FILE" ] || return 1
	reset_state
	# shellcheck disable=SC1090
	. "$STATE_FILE"
}

is_installed() { [ -f "$STATE_FILE" ] && [ -n "$(sed -n 's/^PROTOCOLS=//p' "$STATE_FILE" 2>/dev/null | tr -d "'\"")" ]; }

# ---------------------------------------------------------------------------
# 协议目录
# ---------------------------------------------------------------------------
proto_title() {
	case "$1" in
	vless-reality) echo "VLESS-Reality-Vision" ;;
	vless-xhttp) echo "VLESS-XHTTP-Reality" ;;
	vless-grpc) echo "VLESS-gRPC-Reality" ;;
	vless-ws) echo "VLESS-WS-TLS" ;;
	vmess-ws) echo "VMess-WS" ;;
	trojan) echo "Trojan-TLS" ;;
	shadowsocks) echo "Shadowsocks-2022" ;;
	hysteria2) echo "Hysteria2" ;;
	tuic) echo "TUIC-v5" ;;
	anytls) echo "AnyTLS" ;;
	shadowtls) echo "ShadowTLS-v3" ;;
	*) echo "$1" ;;
	esac
}

proto_desc() {
	case "$1" in
	vless-reality) echo "无需域名, 抗封锁首选, TCP" ;;
	vless-xhttp) echo "无需域名, XHTTP 分包传输, 仅 Xray" ;;
	vless-grpc) echo "无需域名, gRPC 多路复用" ;;
	vless-ws) echo "WebSocket+TLS, 可套 CDN (建议有域名)" ;;
	vmess-ws) echo "WebSocket, 可套 CDN, 兼容性最好" ;;
	trojan) echo "TLS 伪装, 经典稳定" ;;
	shadowsocks) echo "SS-2022, 轻量高速, TCP+UDP" ;;
	hysteria2) echo "QUIC/UDP, 暴力加速, 弱网首选" ;;
	tuic) echo "QUIC/UDP, 低延迟" ;;
	anytls) echo "TLS 流量填充, 抗 TLS-in-TLS 识别" ;;
	shadowtls) echo "借用大站 TLS 握手, 包裹 SS-2022" ;;
	esac
}

# 可承载该协议的服务端内核 (首个为默认)
proto_cores() {
	case "$1" in
	vless-xhttp) echo "xray" ;;
	hysteria2 | tuic | anytls | shadowtls) echo "singbox" ;;
	*) echo "singbox xray" ;;
	esac
}

proto_supports_core() {
	case " $(proto_cores "$1") " in *" $2 "*) return 0 ;; *) return 1 ;; esac
}

# 协议使用的传输层: tcp / udp / both
proto_net() {
	case "$1" in
	hysteria2 | tuic) echo udp ;;
	shadowsocks) echo both ;;
	*) echo tcp ;;
	esac
}

proto_uses_reality() { case "$1" in vless-reality | vless-xhttp | vless-grpc) return 0 ;; *) return 1 ;; esac; }

# 是否需要 TLS 证书
proto_needs_cert() {
	case "$1" in
	vless-ws | trojan | hysteria2 | tuic | anytls) return 0 ;;
	*) return 1 ;;
	esac
}

# vmess-ws 仅在拥有正式证书 (ACME / 自有证书) 时启用 TLS, 否则为明文 WS (便于套 CDN)
vmess_tls_enabled() { [ "$TLS_MODE" = acme ] || [ "$TLS_MODE" = custom ]; }

# 客户端支持情况: proto_client_ok 协议 link|mihomo|singbox|xray
proto_client_ok() {
	local p=$1 c=$2
	case "$c" in
	link) [ "$p" != shadowtls ] ;;
	mihomo) return 0 ;;
	singbox) [ "$p" != vless-xhttp ] ;;
	xray) case "$p" in hysteria2 | tuic | anytls | shadowtls) return 1 ;; *) return 0 ;; esac ;;
	*) return 1 ;;
	esac
}

proto_enabled() { case " $PROTOCOLS " in *" $1 "*) return 0 ;; *) return 1 ;; esac; }

# 某内核是否承载了至少一个协议
core_used() {
	local p
	for p in $PROTOCOLS; do
		[ "$(pget CORE "$p")" = "$1" ] && return 0
	done
	return 1
}

any_needs_cert() {
	local p
	for p in $PROTOCOLS; do
		proto_needs_cert "$p" && return 0
		[ "$p" = vmess-ws ] && vmess_tls_enabled && return 0
	done
	return 1
}

any_reality() {
	local p
	for p in $PROTOCOLS; do proto_uses_reality "$p" && return 0; done
	return 1
}

# 节点显示名: <前缀>-<协议>
node_name() { printf '%s-%s' "${NODE_NAME:-onebox}" "$(proto_title "$1")"; }

# 客户端连接用的 TLS SNI
tls_server_name() {
	if [ "$TLS_MODE" = acme ] || [ "$TLS_MODE" = custom ]; then
		printf '%s' "${DOMAIN:-$TLS_SNI}"
	else
		printf '%s' "$TLS_SNI"
	fi
}

# 客户端是否需要跳过证书校验 (自签证书)
tls_insecure() { [ "$TLS_MODE" = self ]; }

# 分享链接/客户端配置中使用的服务器地址 (IPv6 需加方括号的场合由调用方处理)
server_host() { printf '%s' "$SERVER_ADDR"; }
uri_host() {
	case "$SERVER_ADDR" in *:*) printf '[%s]' "$SERVER_ADDR" ;; *) printf '%s' "$SERVER_ADDR" ;; esac
}

# ---------------------------------------------------------------------------
# 内核安装 (sing-box / Xray)
# ---------------------------------------------------------------------------
_install_bin() {
	# _install_bin 源文件 目标文件
	mkdir -p "$(dirname "$2")"
	cp -f "$1" "$2.new" && chmod 755 "$2.new" && mv -f "$2.new" "$2"
}

sb_installed_version() { [ -x "$SB_BIN" ] && "$SB_BIN" version 2>/dev/null | awk 'NR==1{print $3}'; }
xr_installed_version() { [ -x "$XR_BIN" ] && "$XR_BIN" version 2>/dev/null | awk 'NR==1{print $2}'; }

# sing-box 候选安装包: 优先 musl 静态构建 (glibc / musl 系统通用, 不依赖 glibc 版本)
sb_asset_candidates() {
	local v=$1
	printf '%s\n' "sing-box-${v}-linux-${SB_ARCH}-musl.tar.gz" "sing-box-${v}-linux-${SB_ARCH}.tar.gz"
	[ "$SB_ARCH" = amd64 ] && printf '%s\n' "sing-box-${v}-linux-amd64v3.tar.gz"
	return 0
}

install_singbox() {
	local ver=${1:-} tmp asset url bin="" got=""
	if [ -n "$LOCAL_SB_BIN" ]; then
		[ -x "$LOCAL_SB_BIN" ] || die "本地 sing-box 文件不可执行: $LOCAL_SB_BIN"
		info "使用本地 sing-box: $LOCAL_SB_BIN"
		_install_bin "$LOCAL_SB_BIN" "$SB_BIN" || die "安装 sing-box 失败"
		SB_VERSION=$(sb_installed_version)
		return 0
	fi
	if [ -z "$ver" ]; then
		info "查询 sing-box 最新版本..."
		ver=$(gh_latest_version SagerNet/sing-box)
		[ -n "$ver" ] || {
			warn "无法获取 sing-box 最新版本, 使用内置版本 ${FALLBACK_SB_VERSION}"
			ver=$FALLBACK_SB_VERSION
		}
	fi
	tmp=$(mktemp -d)
	for asset in $(sb_asset_candidates "$ver"); do
		url=$(gh_url "https://github.com/SagerNet/sing-box/releases/download/v${ver}/${asset}")
		info "下载 ${asset}"
		rm -rf "${tmp:?}"/*
		http_get "$url" "$tmp/pkg.tar.gz" || continue
		tar -xzf "$tmp/pkg.tar.gz" -C "$tmp" 2>/dev/null || continue
		bin=$(find "$tmp" -type f -name sing-box 2>/dev/null | head -n1)
		[ -n "$bin" ] || continue
		chmod +x "$bin"
		if "$bin" version >/dev/null 2>&1; then
			got=$asset
			break
		fi
		warn "${asset} 无法在本机运行, 尝试其他构建..."
	done
	if [ -z "$got" ]; then
		rm -rf "$tmp"
		err "sing-box ${ver} 下载或运行失败 (架构: ${SB_ARCH})"
		[ -z "$GH_PROXY" ] && warn "若服务器访问 GitHub 困难, 可设置加速前缀后重试, 例如: GH_PROXY=https://ghfast.top/ onebox"
		return 1
	fi
	_install_bin "$bin" "$SB_BIN" || {
		rm -rf "$tmp"
		err "安装 sing-box 失败"
		return 1
	}
	rm -rf "$tmp"
	SB_VERSION=$(sb_installed_version)
	info "sing-box ${SB_VERSION} 安装完成 (${got})"
}

install_xray() {
	local ver=${1:-} tmp asset url sum want
	if [ -n "$LOCAL_XR_BIN" ]; then
		[ -x "$LOCAL_XR_BIN" ] || die "本地 xray 文件不可执行: $LOCAL_XR_BIN"
		info "使用本地 Xray: $LOCAL_XR_BIN"
		_install_bin "$LOCAL_XR_BIN" "$XR_BIN" || die "安装 Xray 失败"
		XR_VERSION=$(xr_installed_version)
		return 0
	fi
	ensure_cmds unzip || {
		err "缺少 unzip, 无法安装 Xray"
		return 1
	}
	if [ -z "$ver" ]; then
		info "查询 Xray 最新版本..."
		ver=$(gh_latest_version XTLS/Xray-core)
		[ -n "$ver" ] || {
			warn "无法获取 Xray 最新版本, 使用内置版本 ${FALLBACK_XR_VERSION}"
			ver=$FALLBACK_XR_VERSION
		}
	fi
	asset="Xray-linux-${XR_ARCH}.zip"
	url=$(gh_url "https://github.com/XTLS/Xray-core/releases/download/v${ver}/${asset}")
	tmp=$(mktemp -d)
	info "下载 ${asset} (v${ver})"
	if ! http_get "$url" "$tmp/xray.zip"; then
		rm -rf "$tmp"
		err "Xray ${ver} 下载失败 (架构: ${XR_ARCH})"
		[ -z "$GH_PROXY" ] && warn "若服务器访问 GitHub 困难, 可设置加速前缀后重试, 例如: GH_PROXY=https://ghfast.top/ onebox"
		return 1
	fi
	# 校验 SHA256 (官方 .dgst 文件)
	if has sha256sum && http_get "${url}.dgst" "$tmp/xray.dgst" 2>/dev/null; then
		want=$(sed -n 's/^SHA2-256= *//p' "$tmp/xray.dgst" | tr -d '\r' | head -n1)
		sum=$(sha256sum "$tmp/xray.zip" | awk '{print $1}')
		if [ -n "$want" ] && [ "$want" != "$sum" ]; then
			rm -rf "$tmp"
			err "Xray 安装包 SHA256 校验失败"
			return 1
		fi
	fi
	if ! unzip -qo "$tmp/xray.zip" -d "$tmp/x" >/dev/null 2>&1 || [ ! -f "$tmp/x/xray" ]; then
		rm -rf "$tmp"
		err "Xray 安装包解压失败"
		return 1
	fi
	chmod +x "$tmp/x/xray"
	if ! "$tmp/x/xray" version >/dev/null 2>&1; then
		rm -rf "$tmp"
		err "下载的 Xray 无法在本机运行 (架构: ${XR_ARCH})"
		return 1
	fi
	_install_bin "$tmp/x/xray" "$XR_BIN" || {
		rm -rf "$tmp"
		err "安装 Xray 失败"
		return 1
	}
	rm -rf "$tmp"
	XR_VERSION=$(xr_installed_version)
	info "Xray ${XR_VERSION} 安装完成"
}

# ---------------------------------------------------------------------------
# 密钥 / 凭据生成
# ---------------------------------------------------------------------------
gen_uuid() {
	local u="" h
	if [ -r /proc/sys/kernel/random/uuid ]; then
		u=$(cat /proc/sys/kernel/random/uuid)
	elif [ -x "$SB_BIN" ]; then
		u=$("$SB_BIN" generate uuid 2>/dev/null)
	elif [ -x "$XR_BIN" ]; then
		u=$("$XR_BIN" uuid 2>/dev/null)
	fi
	if ! [[ "$u" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]]; then
		h=$(rand_hex 16)
		u=$(printf '%s-%s-4%s-%x%s-%s' "${h:0:8}" "${h:8:4}" "${h:13:3}" $(((0x${h:16:1} & 3) | 8)) "${h:17:3}" "${h:20:12}")
	fi
	printf '%s' "$u"
}

# 生成 REALITY 密钥对 (sing-box 或 Xray 均可, 输出格式不同需兼容解析)
gen_reality_keypair() {
	local out=""
	[ -x "$SB_BIN" ] && out=$("$SB_BIN" generate reality-keypair 2>/dev/null)
	[ -z "$out" ] && [ -x "$XR_BIN" ] && out=$("$XR_BIN" x25519 2>/dev/null)
	REALITY_PRIVATE_KEY=$(printf '%s\n' "$out" | awk -F':[[:space:]]*' 'tolower($1) ~ /private/ {print $2; exit}' | tr -d ' \r')
	REALITY_PUBLIC_KEY=$(printf '%s\n' "$out" | awk -F':[[:space:]]*' 'tolower($1) ~ /public|password/ {print $2; exit}' | tr -d ' \r')
	[ -n "$REALITY_PRIVATE_KEY" ] && [ -n "$REALITY_PUBLIC_KEY" ] || die "生成 REALITY 密钥对失败"
}

# SS-2022 密钥长度: aes-128 为 16 字节, 其余 32 字节
ss_key_len() {
	case "$1" in
	2022-blake3-aes-128-gcm) echo 16 ;;
	2022-blake3-aes-256-gcm | 2022-blake3-chacha20-poly1305) echo 32 ;;
	*) echo 0 ;;
	esac
}

gen_ss_password() {
	local n
	n=$(ss_key_len "$1")
	if [ "$n" -gt 0 ]; then rand_base64 "$n"; else rand_str 24; fi
}

# ---------------------------------------------------------------------------
# 服务管理 (systemd / OpenRC / 无 init 的容器环境)
# ---------------------------------------------------------------------------
svc_name() { case "$1" in singbox) echo "$SB_SERVICE" ;; xray) echo "$XR_SERVICE" ;; esac; }
svc_bin() { case "$1" in singbox) echo "$SB_BIN" ;; xray) echo "$XR_BIN" ;; esac; }
svc_conf() { case "$1" in singbox) echo "$SB_CONF" ;; xray) echo "$XR_CONF" ;; esac; }
core_title() { case "$1" in singbox) echo "sing-box" ;; xray) echo "Xray" ;; esac; }

svc_write() {
	local core=$1 name bin conf
	name=$(svc_name "$core") bin=$(svc_bin "$core") conf=$(svc_conf "$core")
	case "$INIT" in
	systemd)
		cat >"/etc/systemd/system/${name}.service" <<EOF
[Unit]
Description=Sing-Xray-Onebox $(core_title "$core") Service
Documentation=https://github.com/${SCRIPT_REPO}
After=network-online.target nss-lookup.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=${bin} run -c ${conf}
Restart=on-failure
RestartSec=5s
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF
		systemctl daemon-reload >/dev/null 2>&1
		;;
	openrc)
		cat >"/etc/init.d/${name}" <<EOF
#!/sbin/openrc-run

name="${name}"
description="Sing-Xray-Onebox $(core_title "$core") Service"
supervisor="supervise-daemon"
command="${bin}"
command_args="run -c ${conf}"
output_log="${LOG_DIR}/${core}.log"
error_log="${LOG_DIR}/${core}.log"
respawn_delay=5
respawn_max=0
rc_ulimit="-n 1048576"

depend() {
	need net
	after firewall dns
}

start_pre() {
	checkpath -d -m 0755 "${LOG_DIR}"
}
EOF
		chmod 755 "/etc/init.d/${name}"
		;;
	esac
	return 0
}

svc_enable() {
	local name
	name=$(svc_name "$1")
	case "$INIT" in
	systemd) systemctl enable "$name" >/dev/null 2>&1 ;;
	openrc) rc-update add "$name" default >/dev/null 2>&1 ;;
	none) _none_autostart_add ;;
	esac
}

svc_disable() {
	local name
	name=$(svc_name "$1")
	case "$INIT" in
	systemd) systemctl disable "$name" >/dev/null 2>&1 ;;
	openrc) rc-update del "$name" default >/dev/null 2>&1 ;;
	esac
	return 0
}

_none_pidfile() { echo "${RUN_DIR}/$(svc_name "$1").pid"; }

_none_running() {
	local pf pid
	pf=$(_none_pidfile "$1")
	[ -f "$pf" ] || return 1
	pid=$(cat "$pf" 2>/dev/null)
	[ -n "$pid" ] && kill -0 "$pid" 2>/dev/null
}

# 无 init 系统时, 借助 crontab @reboot 实现开机自启
_none_autostart_add() {
	has crontab || return 0
	crontab -l 2>/dev/null | grep -q "${CMD_PATH} start" && return 0
	(
		crontab -l 2>/dev/null
		echo "@reboot ${CMD_PATH} start >/dev/null 2>&1"
	) | crontab - 2>/dev/null
	return 0
}

_none_autostart_del() {
	has crontab || return 0
	crontab -l 2>/dev/null | grep -q "${CMD_PATH} start" || return 0
	crontab -l 2>/dev/null | grep -v "${CMD_PATH} start" | crontab - 2>/dev/null
	return 0
}

svc_start() {
	local core=$1 name
	name=$(svc_name "$core")
	case "$INIT" in
	systemd) systemctl start "$name" >/dev/null 2>&1 ;;
	openrc) rc-service "$name" start >/dev/null 2>&1 ;;
	none)
		_none_running "$core" && return 0
		mkdir -p "$RUN_DIR" "$LOG_DIR"
		nohup "$(svc_bin "$core")" run -c "$(svc_conf "$core")" >>"${LOG_DIR}/${core}.log" 2>&1 &
		echo $! >"$(_none_pidfile "$core")"
		;;
	esac
}

svc_stop() {
	local core=$1 name pf
	name=$(svc_name "$core")
	case "$INIT" in
	systemd) systemctl stop "$name" >/dev/null 2>&1 ;;
	openrc) rc-service "$name" stop >/dev/null 2>&1 ;;
	none)
		pf=$(_none_pidfile "$core")
		if _none_running "$core"; then
			kill "$(cat "$pf")" 2>/dev/null
			sleep 1
		fi
		rm -f "$pf"
		;;
	esac
	return 0
}

svc_restart() {
	local core=$1
	case "$INIT" in
	systemd) systemctl restart "$(svc_name "$core")" >/dev/null 2>&1 ;;
	openrc) rc-service "$(svc_name "$core")" restart >/dev/null 2>&1 ;;
	none)
		svc_stop "$core"
		svc_start "$core"
		;;
	esac
}

svc_active() {
	local core=$1 name
	name=$(svc_name "$core")
	case "$INIT" in
	systemd) systemctl is-active --quiet "$name" ;;
	openrc) rc-service "$name" status >/dev/null 2>&1 ;;
	none) _none_running "$core" ;;
	esac
}

svc_exists() {
	local name
	name=$(svc_name "$1")
	case "$INIT" in
	systemd) [ -f "/etc/systemd/system/${name}.service" ] ;;
	openrc) [ -f "/etc/init.d/${name}" ] ;;
	none) _none_running "$1" || { [ -x "$(svc_bin "$1")" ] && [ -f "$(svc_conf "$1")" ]; } ;;
	esac
}

svc_remove() {
	local core=$1 name
	name=$(svc_name "$core")
	svc_stop "$core"
	svc_disable "$core"
	case "$INIT" in
	systemd)
		rm -f "/etc/systemd/system/${name}.service"
		systemctl daemon-reload >/dev/null 2>&1
		systemctl reset-failed "$name" >/dev/null 2>&1
		;;
	openrc) rm -f "/etc/init.d/${name}" ;;
	esac
	return 0
}

svc_logs() {
	local core=$1 n=${2:-50}
	case "$INIT" in
	systemd) journalctl -u "$(svc_name "$core")" -n "$n" --no-pager 2>/dev/null ;;
	*) tail -n "$n" "${LOG_DIR}/${core}.log" 2>/dev/null ;;
	esac
}

svc_status_text() {
	if ! svc_exists "$1"; then
		printf '%s' "${YELLOW}未安装${PLAIN}"
	elif svc_active "$1"; then
		printf '%s' "${GREEN}运行中${PLAIN}"
	else
		printf '%s' "${RED}已停止${PLAIN}"
	fi
}

# 按当前协议分配, 启停相应内核; 启动后检查是否正常运行
apply_services() {
	local core ok=0
	for core in singbox xray; do
		if core_used "$core"; then
			svc_write "$core"
			svc_enable "$core"
			svc_restart "$core"
		elif svc_exists "$core"; then
			svc_remove "$core"
		fi
	done
	sleep 2
	for core in singbox xray; do
		core_used "$core" || continue
		if svc_active "$core"; then
			info "$(core_title "$core") 服务运行正常"
		else
			ok=1
			err "$(core_title "$core") 服务启动失败, 最近日志:"
			svc_logs "$core" 20 >&2
		fi
	done
	return $ok
}

# ---------------------------------------------------------------------------
# 防火墙
# ---------------------------------------------------------------------------
_fw_ufw_active() { has ufw && ufw status 2>/dev/null | grep -q '^Status: active'; }
_fw_firewalld_active() { has firewall-cmd && [ "$(firewall-cmd --state 2>/dev/null)" = running ]; }

# iptables 的 INPUT 链是否会拦截新端口 (默认策略为 DROP 或存在 REJECT/DROP 规则, 如甲骨文云镜像)
_fw_iptables_blocking() {
	local t=$1
	has "$t" || return 1
	"$t" -S INPUT 2>/dev/null | grep -qE '^-P INPUT (DROP|REJECT)|-j (REJECT|DROP)'
}

_fw_iptables_persist() {
	if has netfilter-persistent; then
		netfilter-persistent save >/dev/null 2>&1
	elif [ -d /etc/iptables ]; then
		iptables-save >/etc/iptables/rules.v4 2>/dev/null
		has ip6tables-save && ip6tables-save >/etc/iptables/rules.v6 2>/dev/null
	elif [ -f /etc/sysconfig/iptables ] && has service; then
		service iptables save >/dev/null 2>&1
		[ -f /etc/sysconfig/ip6tables ] && service ip6tables save >/dev/null 2>&1
	elif [ "$INIT" = openrc ] && [ -x /etc/init.d/iptables ]; then
		/etc/init.d/iptables save >/dev/null 2>&1
		[ -x /etc/init.d/ip6tables ] && /etc/init.d/ip6tables save >/dev/null 2>&1
	fi
	return 0
}

# fw_rule open|close 端口或范围(a-b) tcp|udp
fw_rule() {
	local act=$1 port=$2 proto=$3 ipt_port changed=0 t
	ipt_port=${port/-/:}
	if _fw_ufw_active; then
		if [ "$act" = open ]; then
			ufw allow "${ipt_port}/${proto}" >/dev/null 2>&1
		else
			ufw delete allow "${ipt_port}/${proto}" >/dev/null 2>&1
		fi
	fi
	if _fw_firewalld_active; then
		if [ "$act" = open ]; then
			firewall-cmd --permanent --add-port="${port}/${proto}" >/dev/null 2>&1
		else
			firewall-cmd --permanent --remove-port="${port}/${proto}" >/dev/null 2>&1
		fi
		firewall-cmd --reload >/dev/null 2>&1
	fi
	for t in iptables ip6tables; do
		if [ "$act" = open ]; then
			_fw_iptables_blocking "$t" || continue
			"$t" -C INPUT -p "$proto" --dport "$ipt_port" -m comment --comment onebox -j ACCEPT 2>/dev/null && continue
			"$t" -I INPUT -p "$proto" --dport "$ipt_port" -m comment --comment onebox -j ACCEPT 2>/dev/null ||
				"$t" -I INPUT -p "$proto" --dport "$ipt_port" -j ACCEPT 2>/dev/null
			changed=1
		else
			has "$t" || continue
			while "$t" -D INPUT -p "$proto" --dport "$ipt_port" -m comment --comment onebox -j ACCEPT 2>/dev/null; do changed=1; done
		fi
	done
	[ "$changed" = 1 ] && _fw_iptables_persist
	return 0
}

# 放行 / 关闭当前全部协议端口
fw_apply() {
	local act=${1:-open} p port net
	for p in $PROTOCOLS; do
		port=$(pget PORT "$p")
		[ -n "$port" ] || continue
		net=$(proto_net "$p")
		case "$net" in
		tcp) fw_rule "$act" "$port" tcp ;;
		udp) fw_rule "$act" "$port" udp ;;
		both)
			fw_rule "$act" "$port" tcp
			fw_rule "$act" "$port" udp
			;;
		esac
	done
	if proto_enabled hysteria2 && [ -n "$HY2_HOP" ]; then
		fw_rule "$act" "$HY2_HOP" udp
	fi
	return 0
}

# ---------------------------------------------------------------------------
# Hysteria2 端口跳跃 (UDP 端口范围 -> 实际监听端口)
# ---------------------------------------------------------------------------
HOP_SERVICE="onebox-hop"

# hop_rules add|del
hop_rules() {
	local act=$1 port range t
	port=$(pget PORT hysteria2)
	range=$HY2_HOP
	[ -n "$port" ] && [ -n "$range" ] || return 0
	if has iptables; then
		for t in iptables ip6tables; do
			has "$t" || continue
			[ "$t" = ip6tables ] && ! host_has_ipv6 && continue
			while "$t" -t nat -D PREROUTING -p udp --dport "${range/-/:}" -m comment --comment onebox-hop -j REDIRECT --to-ports "$port" 2>/dev/null; do :; done
			if [ "$act" = add ]; then
				"$t" -t nat -A PREROUTING -p udp --dport "${range/-/:}" -m comment --comment onebox-hop -j REDIRECT --to-ports "$port" 2>/dev/null ||
					warn "${t} 添加端口跳跃规则失败"
			fi
		done
	elif has nft; then
		nft delete table inet onebox_hop >/dev/null 2>&1
		if [ "$act" = add ]; then
			nft -f - <<EOF || warn "nftables 添加端口跳跃规则失败"
table inet onebox_hop {
	chain prerouting {
		type nat hook prerouting priority dstnat; policy accept;
		udp dport ${range} redirect to :${port}
	}
}
EOF
		fi
	else
		warn "未找到 iptables / nftables, 无法设置端口跳跃"
		return 1
	fi
	return 0
}

# 端口跳跃规则开机自动恢复
hop_persist() {
	local act=$1
	case "$INIT" in
	systemd)
		if [ "$act" = add ]; then
			cat >"/etc/systemd/system/${HOP_SERVICE}.service" <<EOF
[Unit]
Description=Sing-Xray-Onebox Hysteria2 port hopping rules
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=${CMD_PATH} hop-apply
ExecStop=${CMD_PATH} hop-clear

[Install]
WantedBy=multi-user.target
EOF
			systemctl daemon-reload >/dev/null 2>&1
			systemctl enable "$HOP_SERVICE" >/dev/null 2>&1
		else
			systemctl disable "$HOP_SERVICE" >/dev/null 2>&1
			rm -f "/etc/systemd/system/${HOP_SERVICE}.service"
			systemctl daemon-reload >/dev/null 2>&1
		fi
		;;
	openrc)
		if [ "$act" = add ]; then
			mkdir -p /etc/local.d
			printf '#!/bin/sh\n%s hop-apply >/dev/null 2>&1\n' "$CMD_PATH" >/etc/local.d/onebox-hop.start
			chmod 755 /etc/local.d/onebox-hop.start
			rc-update add local default >/dev/null 2>&1
		else
			rm -f /etc/local.d/onebox-hop.start
		fi
		;;
	esac
	return 0
}

hop_setup() {
	if proto_enabled hysteria2 && [ -n "$HY2_HOP" ]; then
		hop_rules add && hop_persist add
	else
		hop_rules del
		hop_persist del
	fi
	return 0
}

# ---------------------------------------------------------------------------
# BBR
# ---------------------------------------------------------------------------
bbr_status() {
	local cc qd
	cc=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null)
	qd=$(sysctl -n net.core.default_qdisc 2>/dev/null)
	printf '%s' "${cc:-未知} / ${qd:-未知}"
}

enable_bbr() {
	local kv
	if [ "$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null)" = bbr ]; then
		info "BBR 已处于启用状态 ($(bbr_status))"
		return 0
	fi
	if [ "$VIRT" = openvz ] || [ "$VIRT" = lxc ]; then
		warn "当前虚拟化为 ${VIRT}, 无法修改内核拥塞控制, 请在宿主机或服务商面板开启 BBR"
		return 1
	fi
	kv=$(uname -r | cut -d- -f1)
	if ! ver_ge "$kv" "4.9"; then
		warn "当前内核 ${kv} 低于 4.9, 不支持 BBR, 请先升级内核"
		return 1
	fi
	has modprobe && modprobe tcp_bbr >/dev/null 2>&1
	mkdir -p /etc/sysctl.d
	cat >/etc/sysctl.d/99-onebox-bbr.conf <<EOF
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
EOF
	sysctl -p /etc/sysctl.d/99-onebox-bbr.conf >/dev/null 2>&1
	if [ "$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null)" = bbr ]; then
		info "BBR 已启用 ($(bbr_status))"
	else
		warn "BBR 启用失败, 当前: $(bbr_status)"
		return 1
	fi
}

# ---------------------------------------------------------------------------
# TLS 证书
# ---------------------------------------------------------------------------
ACME_HOME="${ACME_HOME:-/root/.acme.sh}"
ACME_SH="${ACME_HOME}/acme.sh"

# 自签 ECC 证书 (兼容 OpenSSL 1.0.2 ~ 3.x / LibreSSL)
cert_self_signed() {
	local cn=$1 cnf
	mkdir -p "$TLS_DIR" && chmod 700 "$TLS_DIR"
	cnf=$(mktemp)
	cat >"$cnf" <<EOF
[req]
distinguished_name = dn
x509_extensions = v3_ext
prompt = no

[dn]
CN = ${cn}

[v3_ext]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = DNS:${cn}
EOF
	if openssl ecparam -genkey -name prime256v1 -noout -out "$TLS_DIR/key.pem" >/dev/null 2>&1 &&
		openssl req -new -x509 -sha256 -days 3650 -key "$TLS_DIR/key.pem" -out "$TLS_DIR/cert.pem" -config "$cnf" >/dev/null 2>&1; then
		rm -f "$cnf"
		chmod 600 "$TLS_DIR/key.pem"
		chmod 644 "$TLS_DIR/cert.pem"
		CERT_FILE="$TLS_DIR/cert.pem" KEY_FILE="$TLS_DIR/key.pem"
		info "已生成自签证书 (CN=${cn}, 有效期 10 年)"
		return 0
	fi
	rm -f "$cnf"
	err "生成自签证书失败"
	return 1
}

cert_sha256() {
	# 证书 DER 的 SHA256 指纹 (小写十六进制, 无冒号)
	[ -f "$CERT_FILE" ] || return 0
	openssl x509 -in "$CERT_FILE" -noout -fingerprint -sha256 2>/dev/null | sed 's/.*=//; s/://g' | tr 'A-F' 'a-f'
}

cert_expiry() {
	[ -f "$CERT_FILE" ] || return 0
	openssl x509 -in "$CERT_FILE" -noout -enddate 2>/dev/null | sed 's/notAfter=//'
}

# 解析域名 (A/AAAA), 通过系统解析或 DoH
resolve_domain() {
	local d=$1 out=""
	if has getent; then
		out=$(getent ahosts "$d" 2>/dev/null | awk '{print $1}' | sort -u)
	fi
	if [ -z "$out" ] && has curl; then
		out=$(
			for t in A AAAA; do
				curl -fsS --max-time 6 -H 'accept: application/dns-json' "https://1.1.1.1/dns-query?name=${d}&type=${t}" 2>/dev/null |
					grep -oE '"data":"[^"]+"' | sed 's/"data":"//; s/"$//'
			done
		)
	fi
	printf '%s\n' "$out" | grep -E '^[0-9a-fA-F:.]+$'
}

check_domain_points_here() {
	local d=$1 ips
	ips=$(resolve_domain "$d")
	if [ -z "$ips" ]; then
		warn "无法解析域名 ${d}"
		return 1
	fi
	if printf '%s\n' "$ips" | grep -qxF -e "${SERVER_IPV4:-_none_}" -e "${SERVER_IPV6:-_none_}"; then
		return 0
	fi
	warn "域名 ${d} 解析到 [$(printf '%s' "$ips" | tr '\n' ' ')], 与本机 IP (${SERVER_IPV4:-无} / ${SERVER_IPV6:-无}) 不一致"
	return 1
}

acme_install() {
	[ -x "$ACME_SH" ] && return 0
	ensure_cmds curl || return 1
	ensure_cmds crontab || warn "未能安装 cron, 证书将无法自动续期"
	_enable_cron_service
	local email=$1
	[ -n "$email" ] || email="$(rand_str 8 | tr 'A-Z' 'a-z')@gmail.com"
	info "安装 acme.sh ..."
	if ! (cd /tmp && curl -fsSL https://get.acme.sh | sh -s -- email="$email" >/dev/null 2>&1); then
		# get.acme.sh 不可用时从 GitHub 安装
		local tmp
		tmp=$(mktemp -d)
		http_get "$(gh_url https://raw.githubusercontent.com/acmesh-official/acme.sh/master/acme.sh)" "$tmp/acme.sh" &&
			(cd "$tmp" && sh acme.sh --install -m "$email" >/dev/null 2>&1)
		rm -rf "$tmp"
	fi
	[ -x "$ACME_SH" ] || {
		err "acme.sh 安装失败"
		return 1
	}
	"$ACME_SH" --upgrade --auto-upgrade >/dev/null 2>&1
	"$ACME_SH" --set-default-ca --server letsencrypt >/dev/null 2>&1
}

_enable_cron_service() {
	case "$INIT" in
	systemd)
		local s
		for s in cron crond cronie; do
			systemctl enable --now "$s" >/dev/null 2>&1 && break
		done
		;;
	openrc)
		local s
		for s in crond cronie dcron; do
			if [ -x "/etc/init.d/$s" ]; then
				rc-update add "$s" default >/dev/null 2>&1
				rc-service "$s" start >/dev/null 2>&1
				break
			fi
		done
		;;
	esac
	return 0
}

# cert_acme 域名 standalone|cf  (cf 需预先 export CF_Token 等变量)
cert_acme() {
	local d=$1 method=$2 args=() rc
	acme_install || return 1
	case "$method" in
	standalone)
		ensure_cmds socat || warn "未能安装 socat, standalone 模式可能失败"
		if port_in_use 80 tcp; then
			err "80 端口被占用, standalone 模式需要临时占用 80 端口, 请先停止占用该端口的程序"
			return 1
		fi
		args=(--standalone)
		[ -z "$SERVER_IPV4" ] && [ -n "$SERVER_IPV6" ] && args+=(--listen-v6)
		;;
	cf) args=(--dns dns_cf) ;;
	*) return 1 ;;
	esac
	info "申请证书: ${d} (Let's Encrypt, ECC)"
	"$ACME_SH" --issue -d "$d" "${args[@]}" -k ec-256 --server letsencrypt
	rc=$?
	# rc=2 表示证书未到期无需续签, 也视为成功
	if [ "$rc" != 0 ] && [ "$rc" != 2 ]; then
		err "证书申请失败 (acme.sh 退出码 ${rc}), 请检查域名解析 / 80 端口 / API 令牌"
		return 1
	fi
	mkdir -p "$TLS_DIR" && chmod 700 "$TLS_DIR"
	"$ACME_SH" --install-cert -d "$d" --ecc \
		--key-file "$TLS_DIR/key.pem" \
		--fullchain-file "$TLS_DIR/cert.pem" \
		--reloadcmd "${CMD_PATH} restart >/dev/null 2>&1 || true" >/dev/null 2>&1 || {
		err "证书安装失败"
		return 1
	}
	chmod 600 "$TLS_DIR/key.pem"
	CERT_FILE="$TLS_DIR/cert.pem" KEY_FILE="$TLS_DIR/key.pem"
	info "证书已安装, 将由 acme.sh 自动续期"
}

cert_custom() {
	local c=$1 k=$2
	[ -f "$c" ] && [ -f "$k" ] || {
		err "证书或私钥文件不存在"
		return 1
	}
	openssl x509 -in "$c" -noout >/dev/null 2>&1 || {
		err "无法解析证书文件: $c"
		return 1
	}
	mkdir -p "$TLS_DIR" && chmod 700 "$TLS_DIR"
	cp -f "$c" "$TLS_DIR/cert.pem" && cp -f "$k" "$TLS_DIR/key.pem" && chmod 600 "$TLS_DIR/key.pem"
	CERT_FILE="$TLS_DIR/cert.pem" KEY_FILE="$TLS_DIR/key.pem"
}

# ---------------------------------------------------------------------------
# 服务端配置: sing-box
# ---------------------------------------------------------------------------
# 用逗号把多个 JSON 片段连接起来
json_join() {
	local first=1 x
	for x in "$@"; do
		[ -n "$x" ] || continue
		[ "$first" = 1 ] || printf ',\n'
		printf '%s' "$x"
		first=0
	done
}

_sb_cert_tls() {
	# _sb_cert_tls [alpn JSON 数组]
	local alpn=${1:-}
	printf '{
        "enabled": true,
        "server_name": %s,%s
        "certificate_path": %s,
        "key_path": %s
      }' "$(json_str "$(tls_server_name)")" "${alpn:+
        \"alpn\": ${alpn},}" "$(json_str "$CERT_FILE")" "$(json_str "$KEY_FILE")"
}

_sb_reality_tls() {
	printf '{
        "enabled": true,
        "server_name": %s,
        "reality": {
          "enabled": true,
          "handshake": {
            "server": %s,
            "server_port": %s
          },
          "private_key": %s,
          "short_id": [%s]
        }
      }' "$(json_str "$REALITY_SNI")" "$(json_str "${REALITY_DEST%:*}")" "${REALITY_DEST##*:}" \
		"$(json_str "$REALITY_PRIVATE_KEY")" "$(json_str "$REALITY_SHORT_ID")"
}

sb_inbound() {
	local p=$1 port listen
	port=$(pget PORT "$p")
	listen=$(json_str "${LISTEN_ADDR:-::}")
	case "$p" in
	vless-reality)
		printf '    {
      "type": "vless",
      "tag": "vless-reality-in",
      "listen": %s,
      "listen_port": %s,
      "users": [{ "name": "onebox", "uuid": %s, "flow": "xtls-rprx-vision" }],
      "tls": %s
    }' "$listen" "$port" "$(json_str "$UUID")" "$(_sb_reality_tls)"
		;;
	vless-grpc)
		printf '    {
      "type": "vless",
      "tag": "vless-grpc-in",
      "listen": %s,
      "listen_port": %s,
      "users": [{ "name": "onebox", "uuid": %s }],
      "tls": %s,
      "transport": { "type": "grpc", "service_name": %s }
    }' "$listen" "$port" "$(json_str "$UUID")" "$(_sb_reality_tls)" "$(json_str "$GRPC_SERVICE")"
		;;
	vless-ws)
		printf '    {
      "type": "vless",
      "tag": "vless-ws-in",
      "listen": %s,
      "listen_port": %s,
      "users": [{ "name": "onebox", "uuid": %s }],
      "tls": %s,
      "transport": { "type": "ws", "path": %s, "max_early_data": 2048, "early_data_header_name": "Sec-WebSocket-Protocol" }
    }' "$listen" "$port" "$(json_str "$UUID")" "$(_sb_cert_tls '["http/1.1"]')" "$(json_str "$WS_PATH")"
		;;
	vmess-ws)
		local tls=""
		vmess_tls_enabled && tls=",
      \"tls\": $(_sb_cert_tls '["http/1.1"]')"
		printf '    {
      "type": "vmess",
      "tag": "vmess-ws-in",
      "listen": %s,
      "listen_port": %s,
      "users": [{ "name": "onebox", "uuid": %s, "alterId": 0 }]%s,
      "transport": { "type": "ws", "path": %s, "max_early_data": 2048, "early_data_header_name": "Sec-WebSocket-Protocol" }
    }' "$listen" "$port" "$(json_str "$UUID")" "$tls" "$(json_str "$VMESS_PATH")"
		;;
	trojan)
		printf '    {
      "type": "trojan",
      "tag": "trojan-in",
      "listen": %s,
      "listen_port": %s,
      "users": [{ "name": "onebox", "password": %s }],
      "tls": %s
    }' "$listen" "$port" "$(json_str "$PASSWORD")" "$(_sb_cert_tls '["h2","http/1.1"]')"
		;;
	shadowsocks)
		printf '    {
      "type": "shadowsocks",
      "tag": "shadowsocks-in",
      "listen": %s,
      "listen_port": %s,
      "method": %s,
      "password": %s
    }' "$listen" "$port" "$(json_str "$SS_METHOD")" "$(json_str "$SS_PASSWORD")"
		;;
	hysteria2)
		# 未通过认证的 HTTP/3 访问反代到 bing 伪装成普通网站; 启用混淆后伪装无意义, 省略
		local extra=',
      "masquerade": { "type": "proxy", "url": "https://www.bing.com", "rewrite_host": true }'
		[ "$HY2_OBFS" = 1 ] && extra=",
      \"obfs\": { \"type\": \"salamander\", \"password\": $(json_str "$HY2_OBFS_PASSWORD") }"
		printf '    {
      "type": "hysteria2",
      "tag": "hysteria2-in",
      "listen": %s,
      "listen_port": %s,
      "users": [{ "name": "onebox", "password": %s }]%s,
      "tls": %s
    }' "$listen" "$port" "$(json_str "$PASSWORD")" "$extra" "$(_sb_cert_tls '["h3"]')"
		;;
	tuic)
		printf '    {
      "type": "tuic",
      "tag": "tuic-in",
      "listen": %s,
      "listen_port": %s,
      "users": [{ "name": "onebox", "uuid": %s, "password": %s }],
      "congestion_control": "bbr",
      "tls": %s
    }' "$listen" "$port" "$(json_str "$UUID")" "$(json_str "$PASSWORD")" "$(_sb_cert_tls '["h3"]')"
		;;
	anytls)
		printf '    {
      "type": "anytls",
      "tag": "anytls-in",
      "listen": %s,
      "listen_port": %s,
      "users": [{ "name": "onebox", "password": %s }],
      "tls": %s
    }' "$listen" "$port" "$(json_str "$PASSWORD")" "$(_sb_cert_tls)"
		;;
	shadowtls)
		local st_dest=${SHADOWTLS_DEST:-${SHADOWTLS_SNI}:443}
		printf '    {
      "type": "shadowtls",
      "tag": "shadowtls-in",
      "listen": %s,
      "listen_port": %s,
      "version": 3,
      "users": [{ "name": "onebox", "password": %s }],
      "handshake": { "server": %s, "server_port": %s },
      "strict_mode": true,
      "detour": "shadowtls-ss-in"
    },
    {
      "type": "shadowsocks",
      "tag": "shadowtls-ss-in",
      "listen": "127.0.0.1",
      "network": "tcp",
      "method": "2022-blake3-aes-128-gcm",
      "password": %s
    }' "$listen" "$port" "$(json_str "$SHADOWTLS_PASSWORD")" "$(json_str "${st_dest%:*}")" "${st_dest##*:}" "$(json_str "$SHADOWTLS_SS_PASSWORD")"
		;;
	esac
}

gen_singbox_server() {
	local p inbounds=() rules=()
	for p in $PROTOCOLS; do
		[ "$(pget CORE "$p")" = singbox ] || continue
		inbounds+=("$(sb_inbound "$p")")
	done
	local strategy
	strategy=$(sb_dns_strategy)
	rules+=('      { "action": "sniff" }')
	[ "${BLOCK_BT:-1}" = 1 ] && rules+=('      { "protocol": "bittorrent", "action": "reject" }')
	if [ "${BLOCK_PRIVATE:-1}" = 1 ]; then
		# 先解析域名再匹配私有地址, 否则 localhost 之类的域名会绕过拦截
		rules+=("      { \"action\": \"resolve\", \"strategy\": \"${strategy}\" }")
		rules+=('      { "ip_is_private": true, "action": "reject" }')
	fi
	cat <<EOF
{
  "log": { "level": "warn", "timestamp": true },
  "dns": {
    "servers": [{ "type": "local", "tag": "local" }]
  },
  "inbounds": [
$(json_join "${inbounds[@]}")
  ],
  "outbounds": [{ "type": "direct", "tag": "direct" }],
  "route": {
    "rules": [
$(json_join "${rules[@]}")
    ],
    "default_domain_resolver": { "server": "local", "strategy": "${strategy}" },
    "final": "direct"
  }
}
EOF
}

# 仅有 IPv4 或仅有 IPv6 出口时, 让域名解析优先对应协议栈
sb_dns_strategy() {
	if [ -n "$SERVER_IPV4" ] && [ -z "$SERVER_IPV6" ]; then
		echo ipv4_only
	elif [ -z "$SERVER_IPV4" ] && [ -n "$SERVER_IPV6" ]; then
		echo ipv6_only
	else
		echo prefer_ipv4
	fi
}

# ---------------------------------------------------------------------------
# 服务端配置: Xray
# ---------------------------------------------------------------------------
readonly PRIVATE_CIDRS='"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.168.0.0/16", "198.18.0.0/15", "224.0.0.0/3", "::/127", "fc00::/7", "fe80::/10", "ff00::/8"'

_xr_reality() {
	printf '"security": "reality",
        "realitySettings": {
          "target": %s,
          "serverNames": [%s],
          "privateKey": %s,
          "shortIds": [%s]
        }' "$(json_str "$REALITY_DEST")" "$(json_str "$REALITY_SNI")" "$(json_str "$REALITY_PRIVATE_KEY")" "$(json_str "$REALITY_SHORT_ID")"
}

_xr_tls() {
	local alpn=${1:-'"http/1.1"'}
	printf '"security": "tls",
        "tlsSettings": {
          "serverName": %s,
          "alpn": [%s],
          "certificates": [{ "certificateFile": %s, "keyFile": %s }]
        }' "$(json_str "$(tls_server_name)")" "$alpn" "$(json_str "$CERT_FILE")" "$(json_str "$KEY_FILE")"
}

readonly XR_SNIFFING='"sniffing": { "enabled": true, "destOverride": ["http", "tls", "quic"], "routeOnly": true }'

xr_inbound() {
	local p=$1 port
	port=$(pget PORT "$p")
	case "$p" in
	vless-reality)
		printf '    {
      "tag": "vless-reality-in",
      "port": %s,
      "protocol": "vless",
      "settings": { "clients": [{ "id": %s, "flow": "xtls-rprx-vision", "email": "onebox" }], "decryption": "none" },
      "streamSettings": {
        "network": "raw",
        %s
      },
      %s
    }' "$port" "$(json_str "$UUID")" "$(_xr_reality)" "$XR_SNIFFING"
		;;
	vless-xhttp)
		printf '    {
      "tag": "vless-xhttp-in",
      "port": %s,
      "protocol": "vless",
      "settings": { "clients": [{ "id": %s, "email": "onebox" }], "decryption": "none" },
      "streamSettings": {
        "network": "xhttp",
        "xhttpSettings": { "path": %s, "mode": "auto" },
        %s
      },
      %s
    }' "$port" "$(json_str "$UUID")" "$(json_str "$XHTTP_PATH")" "$(_xr_reality)" "$XR_SNIFFING"
		;;
	vless-grpc)
		printf '    {
      "tag": "vless-grpc-in",
      "port": %s,
      "protocol": "vless",
      "settings": { "clients": [{ "id": %s, "email": "onebox" }], "decryption": "none" },
      "streamSettings": {
        "network": "grpc",
        "grpcSettings": { "serviceName": %s },
        %s
      },
      %s
    }' "$port" "$(json_str "$UUID")" "$(json_str "$GRPC_SERVICE")" "$(_xr_reality)" "$XR_SNIFFING"
		;;
	vless-ws)
		printf '    {
      "tag": "vless-ws-in",
      "port": %s,
      "protocol": "vless",
      "settings": { "clients": [{ "id": %s, "email": "onebox" }], "decryption": "none" },
      "streamSettings": {
        "network": "ws",
        "wsSettings": { "path": %s },
        %s
      },
      %s
    }' "$port" "$(json_str "$UUID")" "$(json_str "$WS_PATH")" "$(_xr_tls)" "$XR_SNIFFING"
		;;
	vmess-ws)
		local sec='"security": "none"'
		vmess_tls_enabled && sec=$(_xr_tls)
		printf '    {
      "tag": "vmess-ws-in",
      "port": %s,
      "protocol": "vmess",
      "settings": { "clients": [{ "id": %s, "email": "onebox" }] },
      "streamSettings": {
        "network": "ws",
        "wsSettings": { "path": %s },
        %s
      },
      %s
    }' "$port" "$(json_str "$UUID")" "$(json_str "$VMESS_PATH")" "$sec" "$XR_SNIFFING"
		;;
	trojan)
		printf '    {
      "tag": "trojan-in",
      "port": %s,
      "protocol": "trojan",
      "settings": { "clients": [{ "password": %s, "email": "onebox" }] },
      "streamSettings": {
        "network": "raw",
        %s
      },
      %s
    }' "$port" "$(json_str "$PASSWORD")" "$(_xr_tls '"h2", "http/1.1"')" "$XR_SNIFFING"
		;;
	shadowsocks)
		printf '    {
      "tag": "shadowsocks-in",
      "port": %s,
      "protocol": "shadowsocks",
      "settings": { "method": %s, "password": %s, "network": "tcp,udp" },
      %s
    }' "$port" "$(json_str "$SS_METHOD")" "$(json_str "$SS_PASSWORD")" "$XR_SNIFFING"
		;;
	esac
}

gen_xray_server() {
	local p inbounds=() rules=()
	for p in $PROTOCOLS; do
		[ "$(pget CORE "$p")" = xray ] || continue
		inbounds+=("$(xr_inbound "$p")")
	done
	[ "${BLOCK_BT:-1}" = 1 ] && rules+=('      { "type": "field", "protocol": ["bittorrent"], "outboundTag": "block" }')
	[ "${BLOCK_PRIVATE:-1}" = 1 ] && rules+=("      { \"type\": \"field\", \"ip\": [${PRIVATE_CIDRS}], \"outboundTag\": \"block\" }")
	cat <<EOF
{
  "log": { "loglevel": "warning" },
  "inbounds": [
$(json_join "${inbounds[@]}")
  ],
  "outbounds": [
    { "tag": "direct", "protocol": "freedom", "settings": { "domainStrategy": "$(xr_domain_strategy)" } },
    { "tag": "block", "protocol": "blackhole" }
  ],
  "routing": {
    "domainStrategy": "IPIfNonMatch",
    "rules": [
$(json_join "${rules[@]}")
    ]
  }
}
EOF
}

xr_domain_strategy() {
	if [ -n "$SERVER_IPV4" ] && [ -z "$SERVER_IPV6" ]; then
		echo UseIPv4
	elif [ -z "$SERVER_IPV4" ] && [ -n "$SERVER_IPV6" ]; then
		echo UseIPv6
	else
		echo UseIPv4v6
	fi
}

# ---------------------------------------------------------------------------
# 写入并校验服务端配置 (校验失败时保留旧配置)
# ---------------------------------------------------------------------------
_write_checked() {
	# _write_checked 内核 目标文件 生成函数
	local core=$1 dst=$2 fn=$3 tmp out
	tmp="${dst%.json}.new.json"
	"$fn" >"$tmp" || return 1
	chmod 600 "$tmp"
	case "$core" in
	singbox) out=$("$SB_BIN" check -c "$tmp" 2>&1) ;;
	xray) out=$("$XR_BIN" run -test -c "$tmp" 2>&1) ;;
	esac
	if [ $? -ne 0 ]; then
		err "$(core_title "$core") 配置校验失败:"
		printf '%s\n' "$out" | tail -n 15 >&2
		rm -f "$tmp"
		return 1
	fi
	mv -f "$tmp" "$dst"
}

write_server_configs() {
	mkdir -p "$ONEBOX_DIR"
	if core_used singbox; then
		_write_checked singbox "$SB_CONF" gen_singbox_server || return 1
	else
		rm -f "$SB_CONF"
	fi
	if core_used xray; then
		_write_checked xray "$XR_CONF" gen_xray_server || return 1
	else
		rm -f "$XR_CONF"
	fi
	return 0
}

# ---------------------------------------------------------------------------
# 客户端: 分享链接
# ---------------------------------------------------------------------------
# 自签证书时附加的参数: 跳过证书验证 (NekoBox / Shadowrocket 等) + 证书指纹固定 pcs
# (v2rayN 的 Xray 内核与 mihomo 使用; Xray 26 已不再接受 allowInsecure)
_insecure_q() {
	tls_insecure || return 0
	local fp
	fp=$(cert_sha256)
	printf '&allowInsecure=1&insecure=1'
	[ -n "$fp" ] && printf '&pcs=%s' "$fp"
	return 0
}

link_of() {
	local p=$1 port host name sni q fp
	port=$(pget PORT "$p")
	host=$(uri_host)
	name=$(urlencode "$(node_name "$p")")
	sni=$(urlencode "$(tls_server_name)")
	local rq
	rq="security=reality&sni=$(urlencode "$REALITY_SNI")&fp=chrome&pbk=${REALITY_PUBLIC_KEY}&sid=${REALITY_SHORT_ID}"
	case "$p" in
	vless-reality)
		echo "vless://${UUID}@${host}:${port}?encryption=none&flow=xtls-rprx-vision&${rq}&type=tcp&headerType=none#${name}"
		;;
	vless-xhttp)
		echo "vless://${UUID}@${host}:${port}?encryption=none&${rq}&type=xhttp&path=$(urlencode "$XHTTP_PATH")&mode=auto#${name}"
		;;
	vless-grpc)
		echo "vless://${UUID}@${host}:${port}?encryption=none&${rq}&type=grpc&serviceName=$(urlencode "$GRPC_SERVICE")&mode=gun#${name}"
		;;
	vless-ws)
		echo "vless://${UUID}@${host}:${port}?encryption=none&security=tls&sni=${sni}&fp=chrome&alpn=http%2F1.1$(_insecure_q)&type=ws&host=${sni}&path=$(urlencode "$WS_PATH")#${name}"
		;;
	vmess-ws)
		# v2rayN 格式 (与 v2rayN 导出的键集合一致): v/port/aid 为字符串, 标准 base64 (带填充)
		# TLS 时 alpn=http/1.1 (不要输出空 alpn: mihomo 会解析成 alpn:[""]); 明文 WS 时 host 用 DOMAIN (如有)
		local json vtls="" vsni="" valpn="" vfp="" vhost=${DOMAIN:-}
		if vmess_tls_enabled; then
			vtls=tls vsni=$(tls_server_name) valpn=http/1.1 vfp=chrome vhost=$(tls_server_name)
		fi
		json=$(printf '{"v":"2","ps":%s,"add":%s,"port":"%s","id":"%s","aid":"0","scy":"auto","net":"ws","type":"none","host":%s,"path":%s,"tls":"%s","sni":%s,"alpn":"%s","fp":"%s"}' \
			"$(json_str "$(node_name "$p")")" "$(json_str "$SERVER_ADDR")" "$port" "$UUID" \
			"$(json_str "$vhost")" "$(json_str "$VMESS_PATH")" "$vtls" "$(json_str "$vsni")" "$valpn" "$vfp")
		echo "vmess://$(printf '%s' "$json" | b64)"
		;;
	trojan)
		echo "trojan://$(urlencode "$PASSWORD")@${host}:${port}?security=tls&sni=${sni}&fp=chrome&alpn=h2%2Chttp%2F1.1$(_insecure_q)&type=tcp&headerType=none#${name}"
		;;
	shadowsocks)
		# SIP002: base64url(method:password), 无填充 (v2rayN/NekoBox/Shadowrocket/mihomo/Hiddify 均可解析)
		echo "ss://$(printf '%s' "${SS_METHOD}:${SS_PASSWORD}" | b64 | tr '+/' '-_' | tr -d '=')@${host}:${port}#${name}"
		;;
	hysteria2)
		q="sni=${sni}&alpn=h3"
		if tls_insecure; then
			q+="&insecure=1"
			fp=$(cert_sha256)
			[ -n "$fp" ] && q+="&pinSHA256=${fp}"
		fi
		[ "$HY2_OBFS" = 1 ] && q+="&obfs=salamander&obfs-password=$(urlencode "$HY2_OBFS_PASSWORD")"
		[ -n "$HY2_HOP" ] && q+="&mport=${HY2_HOP}"
		echo "hysteria2://$(urlencode "$PASSWORD")@${host}:${port}/?${q}#${name}"
		;;
	tuic)
		q="sni=${sni}&alpn=h3&congestion_control=bbr&udp_relay_mode=native"
		tls_insecure && q+="&allow_insecure=1&insecure=1"
		echo "tuic://${UUID}:$(urlencode "$PASSWORD")@${host}:${port}?${q}#${name}"
		;;
	anytls)
		q="sni=${sni}"
		if tls_insecure; then
			q+="&insecure=1"
			fp=$(cert_sha256)
			[ -n "$fp" ] && q+="&hpkp=${fp}"
		fi
		echo "anytls://$(urlencode "$PASSWORD")@${host}:${port}/?${q}#${name}"
		;;
	esac
}

gen_links() {
	local p
	for p in $PROTOCOLS; do
		proto_client_ok "$p" link || continue
		link_of "$p"
	done
}

# ---------------------------------------------------------------------------
# 客户端: mihomo (Clash Meta)
# ---------------------------------------------------------------------------
# YAML 单引号字符串
yq() { printf "'%s'" "${1//\'/\'\'}"; }

_mh_tls_common() {
	# 证书类协议的 sni; 自签证书时跳过 CA 校验并固定证书指纹
	printf '    %s: %s\n' "${1:-sni}" "$(yq "$(tls_server_name)")"
	if tls_insecure; then
		printf '    skip-cert-verify: true\n'
		printf '    fingerprint: %s\n' "$(cert_sha256)"
	fi
	return 0
}

_mh_reality() {
	printf '    tls: true\n    servername: %s\n    client-fingerprint: chrome\n    reality-opts:\n      public-key: %s\n      short-id: %s\n' \
		"$(yq "$REALITY_SNI")" "$(yq "$REALITY_PUBLIC_KEY")" "$(yq "$REALITY_SHORT_ID")"
}

mh_proxy() {
	local p=$1 port
	port=$(pget PORT "$p")
	printf '  - name: %s\n' "$(yq "$(node_name "$p")")"
	printf '    server: %s\n    port: %s\n' "$(yq "$SERVER_ADDR")" "$port"
	case "$p" in
	vless-reality)
		printf '    type: vless\n    uuid: %s\n    network: tcp\n    flow: xtls-rprx-vision\n    udp: true\n' "$UUID"
		_mh_reality
		;;
	vless-xhttp)
		printf '    type: vless\n    uuid: %s\n    network: xhttp\n    udp: true\n' "$UUID"
		_mh_reality
		printf '    xhttp-opts:\n      path: %s\n      mode: auto\n' "$(yq "$XHTTP_PATH")"
		;;
	vless-grpc)
		printf '    type: vless\n    uuid: %s\n    network: grpc\n    udp: true\n' "$UUID"
		_mh_reality
		printf '    grpc-opts:\n      grpc-service-name: %s\n' "$(yq "$GRPC_SERVICE")"
		;;
	vless-ws)
		printf '    type: vless\n    uuid: %s\n    network: ws\n    udp: true\n    tls: true\n    client-fingerprint: chrome\n    alpn: [http/1.1]\n' "$UUID"
		_mh_tls_common servername
		printf '    ws-opts:\n      path: %s\n      headers:\n        Host: %s\n' "$(yq "$WS_PATH")" "$(yq "$(tls_server_name)")"
		;;
	vmess-ws)
		printf '    type: vmess\n    uuid: %s\n    alterId: 0\n    cipher: auto\n    network: ws\n    udp: true\n' "$UUID"
		if vmess_tls_enabled; then
			printf '    tls: true\n    client-fingerprint: chrome\n'
			_mh_tls_common servername
			printf '    ws-opts:\n      path: %s\n      headers:\n        Host: %s\n' "$(yq "$VMESS_PATH")" "$(yq "$(tls_server_name)")"
		else
			printf '    tls: false\n    ws-opts:\n      path: %s\n' "$(yq "$VMESS_PATH")"
			[ -n "$DOMAIN" ] && printf '      headers:\n        Host: %s\n' "$(yq "$DOMAIN")"
		fi
		;;
	trojan)
		printf '    type: trojan\n    password: %s\n    udp: true\n    client-fingerprint: chrome\n    alpn: [h2, http/1.1]\n' "$(yq "$PASSWORD")"
		_mh_tls_common sni
		;;
	shadowsocks)
		printf '    type: ss\n    cipher: %s\n    password: %s\n    udp: true\n' "$SS_METHOD" "$(yq "$SS_PASSWORD")"
		;;
	hysteria2)
		printf '    type: hysteria2\n    password: %s\n    alpn: [h3]\n' "$(yq "$PASSWORD")"
		[ -n "$HY2_HOP" ] && printf '    ports: %s\n' "$(yq "$HY2_HOP")"
		[ "$HY2_OBFS" = 1 ] && printf '    obfs: salamander\n    obfs-password: %s\n' "$(yq "$HY2_OBFS_PASSWORD")"
		_mh_tls_common sni
		;;
	tuic)
		printf '    type: tuic\n    uuid: %s\n    password: %s\n    alpn: [h3]\n    congestion-controller: bbr\n    udp-relay-mode: native\n    reduce-rtt: true\n' "$UUID" "$(yq "$PASSWORD")"
		_mh_tls_common sni
		;;
	anytls)
		printf '    type: anytls\n    password: %s\n    udp: true\n    client-fingerprint: chrome\n' "$(yq "$PASSWORD")"
		_mh_tls_common sni
		;;
	shadowtls)
		printf '    type: ss\n    cipher: 2022-blake3-aes-128-gcm\n    password: %s\n    udp: true\n    udp-over-tcp: true\n    udp-over-tcp-version: 2\n    client-fingerprint: chrome\n' "$(yq "$SHADOWTLS_SS_PASSWORD")"
		printf '    plugin: shadow-tls\n    plugin-opts:\n      host: %s\n      password: %s\n      version: 3\n' "$(yq "$SHADOWTLS_SNI")" "$(yq "$SHADOWTLS_PASSWORD")"
		;;
	esac
}

gen_mihomo() {
	local p names=()
	for p in $PROTOCOLS; do
		proto_client_ok "$p" mihomo || continue
		names+=("$(node_name "$p")")
	done
	cat <<'EOF'
# Sing-Xray-Onebox 生成的 mihomo (Clash Meta) 配置
# 适用: Clash Verge Rev / Mihomo Party / FlClash / ClashMi / Clash Meta for Android 等
mixed-port: 7890
allow-lan: false
mode: rule
log-level: info
ipv6: true
unified-delay: true
tcp-concurrent: true
find-process-mode: strict
external-controller: 127.0.0.1:9090
profile:
  store-selected: true
  store-fake-ip: true

geodata-mode: true
geo-auto-update: true
geo-update-interval: 24
geox-url:
  geoip: https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/geoip.dat
  geosite: https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/geosite.dat
  mmdb: https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/country.mmdb
  asn: https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/GeoLite2-ASN.mmdb

sniffer:
  enable: true
  sniff:
    HTTP:
      ports: [80, 8080-8880]
      override-destination: true
    TLS:
      ports: [443, 8443]
    QUIC:
      ports: [443, 8443]

tun:
  enable: false
  stack: mixed
  auto-route: true
  auto-detect-interface: true
  dns-hijack:
    - any:53

dns:
  enable: true
  ipv6: true
  listen: 0.0.0.0:1053
  enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.1/16
  fake-ip-filter:
    - '*.lan'
    - '*.local'
    - '+.msftconnecttest.com'
    - '+.msftncsi.com'
    - 'time.*.com'
    - 'ntp.*.com'
  default-nameserver:
    - 223.5.5.5
    - 119.29.29.29
  nameserver:
    - https://dns.alidns.com/dns-query
    - https://doh.pub/dns-query
  proxy-server-nameserver:
    - https://dns.alidns.com/dns-query
    - https://doh.pub/dns-query
  nameserver-policy:
    'geosite:geolocation-!cn':
      - https://dns.cloudflare.com/dns-query#节点选择
      - https://dns.google/dns-query#节点选择

proxies:
EOF
	for p in $PROTOCOLS; do
		proto_client_ok "$p" mihomo || continue
		mh_proxy "$p"
	done
	echo
	echo "proxy-groups:"
	echo "  - name: 节点选择"
	echo "    type: select"
	echo "    proxies:"
	echo "      - 自动选择"
	for p in "${names[@]}"; do printf '      - %s\n' "$(yq "$p")"; done
	echo "      - DIRECT"
	echo "  - name: 自动选择"
	echo "    type: url-test"
	echo "    url: https://www.gstatic.com/generate_204"
	echo "    interval: 300"
	echo "    tolerance: 50"
	echo "    proxies:"
	for p in "${names[@]}"; do printf '      - %s\n' "$(yq "$p")"; done
	cat <<'EOF'

rules:
  - GEOSITE,private,DIRECT
  - GEOIP,private,DIRECT,no-resolve
  - GEOSITE,category-ads-all,REJECT
  - GEOSITE,cn,DIRECT
  - GEOIP,CN,DIRECT
  - MATCH,节点选择
EOF
}

# ---------------------------------------------------------------------------
# 客户端: sing-box (兼容 1.12 及以上)
# ---------------------------------------------------------------------------
# 自签证书以 PEM 内嵌到客户端配置 (sing-box 1.12+ 支持), 保持证书校验而非跳过验证
_sbc_pinned_cert() {
	local line out="" first=1
	[ -f "$CERT_FILE" ] || return 0
	while IFS= read -r line; do
		[ -n "$line" ] || continue
		[ "$first" = 1 ] || out+=", "
		out+=$(json_str "$line")
		first=0
	done <"$CERT_FILE"
	printf '[%s]' "$out"
}

_sbc_tls_cert() {
	# 证书类协议的客户端 TLS
	local alpn=${1:-} utls=${2:-1}
	printf '{ "enabled": true, "server_name": %s' "$(json_str "$(tls_server_name)")"
	tls_insecure && printf ', "certificate": %s' "$(_sbc_pinned_cert)"
	[ -n "$alpn" ] && printf ', "alpn": %s' "$alpn"
	[ "$utls" = 1 ] && printf ', "utls": { "enabled": true, "fingerprint": "chrome" }'
	printf ' }'
}

_sbc_reality() {
	printf '{ "enabled": true, "server_name": %s, "utls": { "enabled": true, "fingerprint": "chrome" }, "reality": { "enabled": true, "public_key": %s, "short_id": %s } }' \
		"$(json_str "$REALITY_SNI")" "$(json_str "$REALITY_PUBLIC_KEY")" "$(json_str "$REALITY_SHORT_ID")"
}

sbc_outbound() {
	local p=$1 port tag srv
	port=$(pget PORT "$p")
	tag=$(json_str "$(node_name "$p")")
	srv="\"server\": $(json_str "$SERVER_ADDR"), \"server_port\": ${port}"
	case "$p" in
	vless-reality)
		printf '    { "type": "vless", "tag": %s, %s, "uuid": "%s", "flow": "xtls-rprx-vision", "tls": %s }' "$tag" "$srv" "$UUID" "$(_sbc_reality)"
		;;
	vless-grpc)
		printf '    { "type": "vless", "tag": %s, %s, "uuid": "%s", "tls": %s, "transport": { "type": "grpc", "service_name": %s } }' \
			"$tag" "$srv" "$UUID" "$(_sbc_reality)" "$(json_str "$GRPC_SERVICE")"
		;;
	vless-ws)
		printf '    { "type": "vless", "tag": %s, %s, "uuid": "%s", "tls": %s, "transport": { "type": "ws", "path": %s, "headers": { "Host": %s }, "max_early_data": 2048, "early_data_header_name": "Sec-WebSocket-Protocol" } }' \
			"$tag" "$srv" "$UUID" "$(_sbc_tls_cert '["http/1.1"]')" "$(json_str "$WS_PATH")" "$(json_str "$(tls_server_name)")"
		;;
	vmess-ws)
		local tls="" host=""
		vmess_tls_enabled && tls=", \"tls\": $(_sbc_tls_cert '["http/1.1"]')"
		host=$(tls_server_name)
		vmess_tls_enabled || host=${DOMAIN:-}
		printf '    { "type": "vmess", "tag": %s, %s, "uuid": "%s", "security": "auto", "alter_id": 0%s, "transport": { "type": "ws", "path": %s%s, "max_early_data": 2048, "early_data_header_name": "Sec-WebSocket-Protocol" } }' \
			"$tag" "$srv" "$UUID" "$tls" "$(json_str "$VMESS_PATH")" "${host:+, \"headers\": { \"Host\": $(json_str "$host") \}}"
		;;
	trojan)
		printf '    { "type": "trojan", "tag": %s, %s, "password": %s, "tls": %s }' "$tag" "$srv" "$(json_str "$PASSWORD")" "$(_sbc_tls_cert '["h2","http/1.1"]')"
		;;
	shadowsocks)
		printf '    { "type": "shadowsocks", "tag": %s, %s, "method": %s, "password": %s }' "$tag" "$srv" "$(json_str "$SS_METHOD")" "$(json_str "$SS_PASSWORD")"
		;;
	hysteria2)
		local extra=""
		[ "$HY2_OBFS" = 1 ] && extra+=", \"obfs\": { \"type\": \"salamander\", \"password\": $(json_str "$HY2_OBFS_PASSWORD") }"
		if [ -n "$HY2_HOP" ]; then
			extra+=", \"server_ports\": [$(json_str "${HY2_HOP/-/:}")], \"hop_interval\": \"30s\""
		fi
		printf '    { "type": "hysteria2", "tag": %s, %s, "password": %s%s, "tls": %s }' "$tag" "$srv" "$(json_str "$PASSWORD")" "$extra" "$(_sbc_tls_cert '["h3"]' 0)"
		;;
	tuic)
		printf '    { "type": "tuic", "tag": %s, %s, "uuid": "%s", "password": %s, "congestion_control": "bbr", "udp_relay_mode": "native", "zero_rtt_handshake": false, "tls": %s }' \
			"$tag" "$srv" "$UUID" "$(json_str "$PASSWORD")" "$(_sbc_tls_cert '["h3"]' 0)"
		;;
	anytls)
		printf '    { "type": "anytls", "tag": %s, %s, "password": %s, "tls": %s }' "$tag" "$srv" "$(json_str "$PASSWORD")" "$(_sbc_tls_cert)"
		;;
	shadowtls)
		printf '    { "type": "shadowsocks", "tag": %s, "method": "2022-blake3-aes-128-gcm", "password": %s, "udp_over_tcp": { "enabled": true, "version": 2 }, "detour": %s },\n' \
			"$tag" "$(json_str "$SHADOWTLS_SS_PASSWORD")" "$(json_str "$(node_name "$p")-tls")"
		printf '    { "type": "shadowtls", "tag": %s, %s, "version": 3, "password": %s, "tls": { "enabled": true, "server_name": %s, "utls": { "enabled": true, "fingerprint": "chrome" } } }' \
			"$(json_str "$(node_name "$p")-tls")" "$srv" "$(json_str "$SHADOWTLS_PASSWORD")" "$(json_str "$SHADOWTLS_SNI")"
		;;
	esac
}

# gen_singbox_client [tun|notun]
gen_singbox_client() {
	local mode=${1:-tun} p nodes=() outs=() names inbounds
	for p in $PROTOCOLS; do
		proto_client_ok "$p" singbox || continue
		nodes+=("$(json_str "$(node_name "$p")")")
		outs+=("$(sbc_outbound "$p")")
	done
	names=$(
		IFS=,
		printf '%s' "${nodes[*]}"
	)
	names=${names//,/, }
	inbounds='    { "type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1", "listen_port": 2080 }'
	if [ "$mode" = tun ]; then
		inbounds='    {
      "type": "tun",
      "tag": "tun-in",
      "address": ["172.19.0.1/30", "fdfe:dcba:9876::1/126"],
      "auto_route": true,
      "strict_route": true,
      "stack": "mixed"
    },
'"$inbounds"
	fi
	cat <<EOF
{
  "log": { "level": "info", "timestamp": true },
  "dns": {
    "servers": [
      { "type": "https", "tag": "dns-remote", "server": "1.1.1.1", "tls": { "server_name": "cloudflare-dns.com" }, "detour": "proxy" },
      { "type": "udp", "tag": "dns-direct", "server": "223.5.5.5" }
    ],
    "rules": [
      { "clash_mode": "Direct", "server": "dns-direct" },
      { "clash_mode": "Global", "server": "dns-remote" },
      { "rule_set": "geosite-cn", "server": "dns-direct" }
    ],
    "final": "dns-remote",
    "strategy": "prefer_ipv4"
  },
  "inbounds": [
${inbounds}
  ],
  "outbounds": [
    { "type": "selector", "tag": "proxy", "outbounds": ["auto", ${names}, "direct"], "default": "auto" },
    { "type": "urltest", "tag": "auto", "outbounds": [${names}], "url": "https://www.gstatic.com/generate_204", "interval": "3m", "tolerance": 50 },
$(json_join "${outs[@]}"),
    { "type": "direct", "tag": "direct" }
  ],
  "route": {
    "rules": [
      { "action": "sniff" },
      { "protocol": "dns", "action": "hijack-dns" },
      { "ip_is_private": true, "outbound": "direct" },
      { "clash_mode": "Direct", "outbound": "direct" },
      { "clash_mode": "Global", "outbound": "proxy" },
      { "rule_set": ["geosite-cn", "geoip-cn"], "outbound": "direct" }
    ],
    "rule_set": [
      { "type": "remote", "tag": "geosite-cn", "format": "binary", "url": "https://testingcf.jsdelivr.net/gh/SagerNet/sing-geosite@rule-set/geosite-cn.srs", "download_detour": "direct" },
      { "type": "remote", "tag": "geoip-cn", "format": "binary", "url": "https://testingcf.jsdelivr.net/gh/SagerNet/sing-geoip@rule-set/geoip-cn.srs", "download_detour": "direct" }
    ],
    "final": "proxy",
    "auto_detect_interface": true,
    "default_domain_resolver": "dns-direct"
  },
  "experimental": {
    "cache_file": { "enabled": true },
    "clash_api": { "external_controller": "127.0.0.1:9090", "default_mode": "Rule" }
  }
}
EOF
}

# ---------------------------------------------------------------------------
# 客户端: Xray
# ---------------------------------------------------------------------------
_xrc_reality() {
	printf '"security": "reality", "realitySettings": { "serverName": %s, "fingerprint": "chrome", "password": %s, "shortId": %s, "spiderX": "/" }' \
		"$(json_str "$REALITY_SNI")" "$(json_str "$REALITY_PUBLIC_KEY")" "$(json_str "$REALITY_SHORT_ID")"
}

_xrc_tls() {
	# Xray 26 起已移除 allowInsecure, 自签证书改用证书指纹固定 (pinnedPeerCertSha256)
	local alpn=${1:-'"http/1.1"'} pin=""
	tls_insecure && pin=", \"pinnedPeerCertSha256\": $(json_str "$(cert_sha256)")"
	printf '"security": "tls", "tlsSettings": { "serverName": %s, "fingerprint": "chrome", "alpn": [%s]%s }' \
		"$(json_str "$(tls_server_name)")" "$alpn" "$pin"
}

xrc_outbound() {
	local p=$1 tag=$2 port addr
	port=$(pget PORT "$p")
	addr=$(json_str "$SERVER_ADDR")
	case "$p" in
	vless-reality)
		printf '    { "tag": "%s", "protocol": "vless", "settings": { "vnext": [{ "address": %s, "port": %s, "users": [{ "id": "%s", "flow": "xtls-rprx-vision", "encryption": "none" }] }] }, "streamSettings": { "network": "raw", %s } }' \
			"$tag" "$addr" "$port" "$UUID" "$(_xrc_reality)"
		;;
	vless-xhttp)
		printf '    { "tag": "%s", "protocol": "vless", "settings": { "vnext": [{ "address": %s, "port": %s, "users": [{ "id": "%s", "encryption": "none" }] }] }, "streamSettings": { "network": "xhttp", "xhttpSettings": { "path": %s, "mode": "auto" }, %s } }' \
			"$tag" "$addr" "$port" "$UUID" "$(json_str "$XHTTP_PATH")" "$(_xrc_reality)"
		;;
	vless-grpc)
		printf '    { "tag": "%s", "protocol": "vless", "settings": { "vnext": [{ "address": %s, "port": %s, "users": [{ "id": "%s", "encryption": "none" }] }] }, "streamSettings": { "network": "grpc", "grpcSettings": { "serviceName": %s }, %s } }' \
			"$tag" "$addr" "$port" "$UUID" "$(json_str "$GRPC_SERVICE")" "$(_xrc_reality)"
		;;
	vless-ws)
		printf '    { "tag": "%s", "protocol": "vless", "settings": { "vnext": [{ "address": %s, "port": %s, "users": [{ "id": "%s", "encryption": "none" }] }] }, "streamSettings": { "network": "ws", "wsSettings": { "path": %s, "host": %s }, %s } }' \
			"$tag" "$addr" "$port" "$UUID" "$(json_str "$WS_PATH")" "$(json_str "$(tls_server_name)")" "$(_xrc_tls)"
		;;
	vmess-ws)
		local sec='"security": "none"' host=${DOMAIN:-}
		if vmess_tls_enabled; then
			sec=$(_xrc_tls)
			host=$(tls_server_name)
		fi
		printf '    { "tag": "%s", "protocol": "vmess", "settings": { "vnext": [{ "address": %s, "port": %s, "users": [{ "id": "%s", "security": "auto" }] }] }, "streamSettings": { "network": "ws", "wsSettings": { "path": %s%s }, %s } }' \
			"$tag" "$addr" "$port" "$UUID" "$(json_str "$VMESS_PATH")" "${host:+, \"host\": $(json_str "$host")}" "$sec"
		;;
	trojan)
		printf '    { "tag": "%s", "protocol": "trojan", "settings": { "servers": [{ "address": %s, "port": %s, "password": %s }] }, "streamSettings": { "network": "raw", %s } }' \
			"$tag" "$addr" "$port" "$(json_str "$PASSWORD")" "$(_xrc_tls '"h2", "http/1.1"')"
		;;
	shadowsocks)
		printf '    { "tag": "%s", "protocol": "shadowsocks", "settings": { "servers": [{ "address": %s, "port": %s, "method": %s, "password": %s }] } }' \
			"$tag" "$addr" "$port" "$(json_str "$SS_METHOD")" "$(json_str "$SS_PASSWORD")"
		;;
	esac
}

gen_xray_client() {
	local p outs=() first=1 tag
	for p in $PROTOCOLS; do
		proto_client_ok "$p" xray || continue
		if [ "$first" = 1 ]; then tag=proxy; else tag=$p; fi
		first=0
		outs+=("$(xrc_outbound "$p" "$tag")")
	done
	[ ${#outs[@]} -gt 0 ] || return 1
	cat <<EOF
{
  "log": { "loglevel": "warning" },
  "inbounds": [
    { "tag": "socks-in", "listen": "127.0.0.1", "port": 10808, "protocol": "socks", "settings": { "udp": true }, "sniffing": { "enabled": true, "destOverride": ["http", "tls", "quic"], "routeOnly": true } },
    { "tag": "http-in", "listen": "127.0.0.1", "port": 10809, "protocol": "http", "sniffing": { "enabled": true, "destOverride": ["http", "tls"], "routeOnly": true } }
  ],
  "outbounds": [
$(json_join "${outs[@]}"),
    { "tag": "direct", "protocol": "freedom" },
    { "tag": "block", "protocol": "blackhole" }
  ],
  "routing": {
    "domainStrategy": "IPIfNonMatch",
    "rules": [
      { "type": "field", "ip": [${PRIVATE_CIDRS}], "outboundTag": "direct" },
      { "type": "field", "domain": ["geosite:cn"], "outboundTag": "direct" },
      { "type": "field", "ip": ["geoip:cn"], "outboundTag": "direct" }
    ]
  }
}
EOF
}

# ---------------------------------------------------------------------------
# 写出全部客户端文件
# ---------------------------------------------------------------------------
write_client_files() {
	mkdir -p "$CLIENT_DIR" && chmod 700 "$CLIENT_DIR"
	gen_links >"$CLIENT_DIR/links.txt"
	b64 <"$CLIENT_DIR/links.txt" >"$CLIENT_DIR/sub.txt"
	gen_mihomo >"$CLIENT_DIR/mihomo.yaml"
	gen_singbox_client tun >"$CLIENT_DIR/sing-box.json"
	gen_singbox_client notun >"$CLIENT_DIR/sing-box-notun.json"
	if gen_xray_client >"$CLIENT_DIR/xray.json.tmp"; then
		mv -f "$CLIENT_DIR/xray.json.tmp" "$CLIENT_DIR/xray.json"
	else
		rm -f "$CLIENT_DIR/xray.json.tmp" "$CLIENT_DIR/xray.json"
	fi
	chmod 600 "$CLIENT_DIR"/* 2>/dev/null
	return 0
}

# ---------------------------------------------------------------------------
# 安装流程
# ---------------------------------------------------------------------------
# 预设组合: 编号|名称|协议列表|内核偏好
readonly PRESETS="1|推荐: Reality-Vision + Hysteria2 + TUIC (sing-box 单内核, TCP+UDP 互补)|vless-reality hysteria2 tuic|singbox
2|Xray 经典: Reality-Vision + XHTTP-Reality + SS-2022 (Xray 单内核)|vless-reality vless-xhttp shadowsocks|xray
3|双内核全能: Xray(Reality-Vision/XHTTP) + sing-box(Hysteria2/TUIC/AnyTLS)|vless-reality vless-xhttp hysteria2 tuic anytls|xray
4|sing-box 全家桶: Reality/gRPC/Trojan/SS/Hy2/TUIC/AnyTLS/ShadowTLS/VMess|vless-reality vless-grpc trojan shadowsocks hysteria2 tuic anytls shadowtls vmess-ws|singbox
5|CDN 组合: VLESS-WS-TLS + VMess-WS (建议使用域名)|vless-ws vmess-ws|xray
6|极简: 仅 VLESS-Reality-Vision (Xray)|vless-reality|xray
7|自定义组合 (自由选择协议与内核)||"

preset_field() {
	# preset_field 编号 字段序号(2=名称 3=协议 4=内核)
	printf '%s\n' "$PRESETS" | awk -F'|' -v n="$1" -v f="$2" '$1==n {print $f}'
}

# 把协议列表按照 ALL_PROTOCOLS 顺序排序并去重
normalize_protocols() {
	local want=" $* " p out=""
	for p in $ALL_PROTOCOLS; do
		case "$want" in *" $p "*) out+="$p " ;; esac
	done
	printf '%s' "${out% }"
}

protocol_by_index() {
	local i=0 p
	for p in $ALL_PROTOCOLS; do
		i=$((i + 1))
		[ "$i" = "$1" ] && {
			printf '%s' "$p"
			return 0
		}
	done
	return 1
}

print_protocol_table() {
	local i=0 p cores c
	printf '  %s%s %s %s %s%s\n' "$BOLD" "$(pad 编号 4)" "$(pad 协议 22)" "$(pad 可用内核 15)" "说明" "$PLAIN"
	for p in $ALL_PROTOCOLS; do
		i=$((i + 1))
		cores=""
		for c in $(proto_cores "$p"); do cores+="$(core_title "$c")/"; done
		printf '  %-4s %-22s %-15s %s\n' "$i" "$(proto_title "$p")" "${cores%/}" "$(proto_desc "$p")"
	done
}

# 为每个协议分配内核
assign_cores() {
	local prefer=$1 p cores
	for p in $PROTOCOLS; do
		cores=$(proto_cores "$p")
		if proto_supports_core "$p" "$prefer"; then
			pset CORE "$p" "$prefer"
		else
			pset CORE "$p" "${cores%% *}"
		fi
	done
}

# 端口在本次配置中是否已被其他协议使用 (同为 TCP 或同为 UDP 视为冲突)
port_taken_by_other() {
	local port=$1 net=$2 self=$3 p pp pn
	for p in $PROTOCOLS; do
		[ "$p" = "$self" ] && continue
		pp=$(pget PORT "$p")
		[ "$pp" = "$port" ] || continue
		pn=$(proto_net "$p")
		if [ "$net" = both ] || [ "$pn" = both ] || [ "$net" = "$pn" ]; then
			return 0
		fi
	done
	return 1
}

# 端口是否落在 Hysteria2 端口跳跃范围内 (UDP)
port_in_hop_range() {
	local port=$1 a b
	[ -n "$HY2_HOP" ] || return 1
	a=${HY2_HOP%-*} b=${HY2_HOP#*-}
	[ "$port" -ge "$a" ] && [ "$port" -le "$b" ]
}

# 我们自己的服务正在使用的端口不算占用 (重新配置时)
port_used_by_onebox() {
	local port=$1 p
	[ -f "$STATE_FILE" ] || return 1
	grep -qE "^PORT_[a-z0-9_]+=${port}\$" "$STATE_FILE"
}

port_ok() {
	local port=$1 p=$2 net
	net=$(proto_net "$p")
	[[ "$port" =~ ^[0-9]+$ ]] && [ "$port" -ge 1 ] && [ "$port" -le 65535 ] || {
		warn "端口需为 1-65535 之间的数字"
		return 1
	}
	if port_taken_by_other "$port" "$net" "$p"; then
		warn "端口 ${port} 已分配给其他协议"
		return 1
	fi
	if [ "$net" != tcp ] && port_in_hop_range "$port"; then
		warn "端口 ${port} 位于 Hysteria2 端口跳跃范围 ${HY2_HOP} 内"
		return 1
	fi
	if ! port_used_by_onebox "$port"; then
		if [ "$net" != udp ] && port_in_use "$port" tcp; then
			warn "TCP 端口 ${port} 已被其他程序占用"
			return 1
		fi
		if [ "$net" != tcp ] && port_in_use "$port" udp; then
			warn "UDP 端口 ${port} 已被其他程序占用"
			return 1
		fi
	fi
	return 0
}

default_port_for() {
	local p=$1 cand port i
	case "$p" in
	vless-reality | hysteria2 | anytls | trojan | shadowtls) cand="443 8443 2053 2083 2087 2096" ;;
	vless-ws) cand="2053 2083 2087 2096 8443 443" ;;
	vmess-ws) if vmess_tls_enabled; then cand="2096 2087 2083 8443"; else cand="8080 8880 2052 2082 2086 2095"; fi ;;
	*) cand="" ;;
	esac
	for port in $cand; do
		port_ok "$port" "$p" 2>/dev/null && {
			printf '%s' "$port"
			return 0
		}
	done
	for i in $(seq 1 50); do
		port=$(rand_port)
		port_ok "$port" "$p" 2>/dev/null && {
			printf '%s' "$port"
			return 0
		}
	done
	rand_port
}

choose_ports() {
	local p port def
	title "端口设置"
	for p in $PROTOCOLS; do
		pset PORT "$p" ""
	done
	for p in $PROTOCOLS; do
		def=$(opt_port_for "$p") || def=$(default_port_for "$p")
		while :; do
			ask port "$(proto_title "$p") 端口 ($(proto_net "$p" | sed 's/both/tcp+udp/'))" "$def"
			if port_ok "$port" "$p"; then
				pset PORT "$p" "$port"
				break
			fi
			is_interactive || die "端口 ${port} 不可用"
		done
	done
}

readonly REALITY_SNI_LIST="www.microsoft.com www.apple.com addons.mozilla.org www.amazon.com dl.google.com www.tesla.com"

# 检查目标站点是否支持 TLS 1.3 (REALITY / ShadowTLS 的要求)
check_tls13() {
	local host=$1 out
	has openssl || return 0
	openssl s_client -help 2>&1 | grep -q -- '-tls1_3' || return 0
	out=$(echo | timeout 8 openssl s_client -connect "${host}:443" -servername "$host" -tls1_3 2>/dev/null) || true
	printf '%s' "$out" | grep -q 'TLSv1.3'
}

choose_sni() {
	local _s_var=$1 _s_prompt=$2 _s_def=$3 _s_i=0 _s_x _s_ans
	echo "  可选伪装站点 (需支持 TLS1.3, 建议选择离服务器近、未被墙的大站):"
	for _s_x in $REALITY_SNI_LIST; do
		_s_i=$((_s_i + 1))
		printf '    %d) %s\n' "$_s_i" "$_s_x"
	done
	printf '    %d) 自定义\n' $((_s_i + 1))
	ask _s_ans "$_s_prompt (输入编号或域名)" "$_s_def"
	if [[ "$_s_ans" =~ ^[0-9]+$ ]]; then
		if [ "$_s_ans" -ge 1 ] && [ "$_s_ans" -le "$_s_i" ]; then
			_s_ans=$(printf '%s\n' $REALITY_SNI_LIST | sed -n "${_s_ans}p")
		else
			ask _s_ans "请输入自定义伪装域名" ""
		fi
	fi
	_s_ans=${_s_ans#https://}
	_s_ans=${_s_ans%%/*}
	[ -n "$_s_ans" ] || _s_ans=$(printf '%s\n' $REALITY_SNI_LIST | head -n1)
	if check_tls13 "$_s_ans"; then
		info "${_s_ans} 支持 TLS 1.3"
	else
		warn "无法确认 ${_s_ans} 支持 TLS 1.3 (可能是本机网络问题), 若连接失败请更换伪装站点"
	fi
	printf -v "$_s_var" '%s' "$_s_ans"
}

choose_tls() {
	local m d
	any_needs_cert || proto_enabled vmess-ws || {
		TLS_MODE=""
		return 0
	}
	title "TLS 证书"
	echo "  部分协议 ($(for p in $PROTOCOLS; do proto_needs_cert "$p" && printf '%s ' "$(proto_title "$p")"; done)) 需要 TLS 证书:"
	echo "    1) 自签证书 (无需域名, 客户端将跳过证书验证) [默认]"
	echo "    2) ACME 申请正式证书 —— HTTP 验证 (域名需已解析到本机, 且 80 端口空闲)"
	echo "    3) ACME 申请正式证书 —— Cloudflare DNS API 验证"
	echo "    4) 使用已有证书文件"
	ask_num m "请选择" "${OPT_TLS_CHOICE:-1}" 1 4 || m=1
	case "$m" in
	1)
		TLS_MODE=self
		ask TLS_SNI "自签证书使用的域名 (SNI)" "${OPT_SNI_SELF:-www.bing.com}"
		;;
	2 | 3)
		TLS_MODE=acme
		while :; do
			ask DOMAIN "请输入已解析到本机的域名" "${OPT_DOMAIN:-}"
			[ -n "$DOMAIN" ] && break
			is_interactive || die "未指定域名 (--domain)"
		done
		TLS_SNI=$DOMAIN
		if [ "$m" = 2 ]; then
			ACME_METHOD=standalone
			if ! check_domain_points_here "$DOMAIN"; then
				confirm "域名解析似乎未指向本机 (若开启了 CDN 代理请先关闭), 仍然继续?" n || die "已取消"
			fi
		else
			ACME_METHOD=cf
			if [ -z "${CF_Token:-}" ] && [ -z "${CF_Key:-}" ]; then
				ask d "Cloudflare API Token (需 Zone.DNS 编辑权限)" ""
				export CF_Token="$d"
				ask d "Cloudflare Account ID (可留空)" ""
				[ -n "$d" ] && export CF_Account_ID="$d"
			fi
		fi
		;;
	4)
		TLS_MODE=custom
		ask DOMAIN "证书对应的域名" "${OPT_DOMAIN:-}"
		TLS_SNI=$DOMAIN
		ask CUSTOM_CERT "证书文件路径 (fullchain)" ""
		ask CUSTOM_KEY "私钥文件路径" ""
		;;
	esac
}

obtain_cert() {
	case "$TLS_MODE" in
	self) cert_self_signed "$TLS_SNI" ;;
	acme) cert_acme "$DOMAIN" "$ACME_METHOD" ;;
	custom) cert_custom "$CUSTOM_CERT" "$CUSTOM_KEY" ;;
	*) return 0 ;;
	esac
}

choose_protocols() {
	local n prefer ans i p sel=""
	title "选择协议组合"
	printf '%s\n' "$PRESETS" | awk -F'|' '{printf "  %s) %s\n", $1, $2}'
	ask_num n "请选择组合" "${OPT_PRESET:-1}" 1 7 || n=1
	if [ "$n" != 7 ]; then
		PROTOCOLS=$(preset_field "$n" 3)
		prefer=$(preset_field "$n" 4)
	else
		echo
		print_protocol_table
		echo
		while :; do
			ask ans "请输入协议编号 (多个用空格或逗号分隔)" "${OPT_CUSTOM:-1 8 9}"
			sel=""
			for i in ${ans//,/ }; do
				p=$(protocol_by_index "$i") || {
					warn "无效编号: $i"
					sel=""
					break
				}
				sel+="$p "
			done
			[ -n "$sel" ] && break
			is_interactive || die "协议选择无效"
		done
		PROTOCOLS=$(normalize_protocols $sel)
		echo
		echo "  两种内核都支持的协议优先使用:"
		echo "    1) sing-box (支持协议最多, 内存占用低) [默认]"
		echo "    2) Xray (VLESS/XHTTP 原生实现)"
		ask_num i "请选择" "${OPT_CORE_CHOICE:-1}" 1 2 || i=1
		[ "$i" = 2 ] && prefer=xray || prefer=singbox
	fi
	[ -n "${OPT_CORE:-}" ] && prefer=$OPT_CORE
	assign_cores "$prefer"
}

choose_extras() {
	if any_reality; then
		title "REALITY 伪装站点"
		choose_sni REALITY_SNI "REALITY 目标站点" "${OPT_SNI:-1}"
		REALITY_DEST="${OPT_REALITY_DEST:-${REALITY_SNI}:443}"
	fi
	if proto_enabled shadowtls; then
		title "ShadowTLS 握手站点"
		choose_sni SHADOWTLS_SNI "ShadowTLS 握手站点" "${REALITY_SNI:-${OPT_SNI:-1}}"
		SHADOWTLS_DEST="${SHADOWTLS_SNI}:443"
	fi
	if proto_enabled hysteria2; then
		title "Hysteria2 选项"
		HY2_OBFS=0 HY2_HOP=""
		if ask_yn "是否启用 Salamander 混淆 (可对抗 QUIC 识别, 但会失去 HTTP/3 伪装)" "${OPT_HY2_OBFS:-n}"; then
			HY2_OBFS=1
		fi
		if [ "$INIT" != none ] && ask_yn "是否启用端口跳跃 (UDP 端口范围转发到 Hysteria2 端口)" "$([ -n "${OPT_HY2_HOP:-}" ] && echo y || echo n)"; then
			local r
			while :; do
				ask r "端口跳跃范围 (起始-结束)" "${OPT_HY2_HOP:-20000-40000}"
				if [[ "$r" =~ ^([0-9]+)-([0-9]+)$ ]] && [ "${BASH_REMATCH[1]}" -ge 1024 ] && [ "${BASH_REMATCH[2]}" -le 65535 ] &&
					[ "${BASH_REMATCH[1]}" -lt "${BASH_REMATCH[2]}" ]; then
					HY2_HOP=$r
					break
				fi
				warn "格式错误, 示例: 20000-40000"
				is_interactive || break
			done
		fi
	fi
}

choose_address() {
	local def
	title "服务器地址"
	info "检测公网 IP ..."
	detect_public_ip
	echo "  IPv4: ${SERVER_IPV4:-无}"
	echo "  IPv6: ${SERVER_IPV6:-无}"
	if [ "$TLS_MODE" = acme ] || [ "$TLS_MODE" = custom ]; then
		def=$DOMAIN
	else
		def=${SERVER_IPV4:-$SERVER_IPV6}
	fi
	[ -n "${OPT_ADDR:-}" ] && def=$OPT_ADDR
	while :; do
		ask SERVER_ADDR "客户端连接使用的地址 (IP 或域名)" "$def"
		SERVER_ADDR=${SERVER_ADDR#[}
		SERVER_ADDR=${SERVER_ADDR%]}
		[ -n "$SERVER_ADDR" ] && break
		is_interactive || die "无法检测公网 IP, 请使用 --addr 指定"
	done
	local h
	h=$(hostname 2>/dev/null | cut -d. -f1 | LC_ALL=C tr -cd 'A-Za-z0-9_-')
	ask NODE_NAME "节点名称前缀" "${OPT_NAME:-${h:-onebox}}"
	NODE_NAME=$(printf '%s' "$NODE_NAME" | tr -d '#&=?/\\"'"'"' ')
	[ -n "$NODE_NAME" ] || NODE_NAME=onebox
}

print_plan() {
	local p
	title "安装确认"
	printf '  %s %s %s\n' "$(pad 协议 22)" "$(pad 端口 12)" "内核"
	for p in $PROTOCOLS; do
		printf '  %-22s %-12s %s\n' "$(proto_title "$p")" "$(proto_net "$p" | sed 's/both/tcp+udp/')/$(pget PORT "$p")" "$(core_title "$(pget CORE "$p")")"
	done
	echo "  服务器地址: ${SERVER_ADDR}"
	[ -n "$REALITY_SNI" ] && echo "  REALITY 目标: ${REALITY_SNI}"
	case "$TLS_MODE" in
	self) echo "  TLS 证书: 自签 (${TLS_SNI})" ;;
	acme) echo "  TLS 证书: Let's Encrypt (${DOMAIN}, $([ "$ACME_METHOD" = cf ] && echo Cloudflare DNS || echo HTTP) 验证)" ;;
	custom) echo "  TLS 证书: 自有证书 (${DOMAIN})" ;;
	esac
	[ -n "$HY2_HOP" ] && echo "  Hysteria2 端口跳跃: ${HY2_HOP}"
	[ "$HY2_OBFS" = 1 ] && echo "  Hysteria2 混淆: salamander"
	hr
}

gen_credentials() {
	UUID=$(gen_uuid)
	PASSWORD=$(rand_str 20)
	SS_METHOD=${SS_METHOD:-2022-blake3-aes-128-gcm}
	SS_PASSWORD=$(gen_ss_password "$SS_METHOD")
	any_reality && {
		gen_reality_keypair
		REALITY_SHORT_ID=$(rand_hex 8)
	}
	WS_PATH="/$(rand_str 10 | tr 'A-Z' 'a-z')"
	VMESS_PATH="/$(rand_str 10 | tr 'A-Z' 'a-z')"
	XHTTP_PATH="/$(rand_str 10 | tr 'A-Z' 'a-z')"
	GRPC_SERVICE="$(rand_str 10 | tr 'A-Z' 'a-z')"
	HY2_OBFS_PASSWORD=$(rand_str 16)
	SHADOWTLS_PASSWORD=$(rand_str 20)
	SHADOWTLS_SS_PASSWORD=$(gen_ss_password 2022-blake3-aes-128-gcm)
}

# 按需补齐缺失的凭据 (添加协议时使用, 不改变已有凭据)
fill_missing_credentials() {
	[ -n "$UUID" ] || UUID=$(gen_uuid)
	[ -n "$PASSWORD" ] || PASSWORD=$(rand_str 20)
	[ -n "$SS_METHOD" ] || SS_METHOD=2022-blake3-aes-128-gcm
	[ -n "$SS_PASSWORD" ] || SS_PASSWORD=$(gen_ss_password "$SS_METHOD")
	if any_reality && [ -z "$REALITY_PRIVATE_KEY" ]; then
		gen_reality_keypair
	fi
	[ -n "$REALITY_SHORT_ID" ] || REALITY_SHORT_ID=$(rand_hex 8)
	[ -n "$WS_PATH" ] || WS_PATH="/$(rand_str 10 | tr 'A-Z' 'a-z')"
	[ -n "$VMESS_PATH" ] || VMESS_PATH="/$(rand_str 10 | tr 'A-Z' 'a-z')"
	[ -n "$XHTTP_PATH" ] || XHTTP_PATH="/$(rand_str 10 | tr 'A-Z' 'a-z')"
	[ -n "$GRPC_SERVICE" ] || GRPC_SERVICE="$(rand_str 10 | tr 'A-Z' 'a-z')"
	[ -n "$HY2_OBFS_PASSWORD" ] || HY2_OBFS_PASSWORD=$(rand_str 16)
	[ -n "$SHADOWTLS_PASSWORD" ] || SHADOWTLS_PASSWORD=$(rand_str 20)
	[ -n "$SHADOWTLS_SS_PASSWORD" ] || SHADOWTLS_SS_PASSWORD=$(gen_ss_password 2022-blake3-aes-128-gcm)
	return 0
}

ensure_cores() {
	local core
	for core in singbox xray; do
		core_used "$core" || continue
		case "$core" in
		singbox) [ -x "$SB_BIN" ] && [ -z "$LOCAL_SB_BIN" ] && [ "${FORCE_CORE_UPDATE:-0}" != 1 ] || install_singbox || return 1 ;;
		xray) [ -x "$XR_BIN" ] && [ -z "$LOCAL_XR_BIN" ] && [ "${FORCE_CORE_UPDATE:-0}" != 1 ] || install_xray || return 1 ;;
		esac
	done
	SB_VERSION=$(sb_installed_version)
	XR_VERSION=$(xr_installed_version)
	# 生成 REALITY 密钥需要至少一个内核
	if any_reality && [ ! -x "$SB_BIN" ] && [ ! -x "$XR_BIN" ]; then
		install_xray || return 1
	fi
	return 0
}

# 把脚本安装为 onebox 命令
install_self() {
	local src
	src=$(readlink -f "$0" 2>/dev/null || echo "$0")
	if [ -f "$src" ] && [ "$src" != "$CMD_PATH" ] && head -n 5 "$src" 2>/dev/null | grep -q 'Sing-Xray-Onebox'; then
		cp -f "$src" "$CMD_PATH.new" && chmod 755 "$CMD_PATH.new" && mv -f "$CMD_PATH.new" "$CMD_PATH"
	elif [ ! -f "$CMD_PATH" ] || [ "$src" != "$CMD_PATH" ]; then
		http_get "$(gh_url "$SCRIPT_RAW_URL")" "$CMD_PATH.new" 2>/dev/null &&
			head -n 5 "$CMD_PATH.new" | grep -q 'Sing-Xray-Onebox' &&
			chmod 755 "$CMD_PATH.new" && mv -f "$CMD_PATH.new" "$CMD_PATH"
		rm -f "$CMD_PATH.new"
	fi
	[ -x "$CMD_PATH" ] && info "管理命令已安装: ${BOLD}onebox${PLAIN}" || warn "管理命令 onebox 安装失败, 可继续使用本脚本进行管理"
	return 0
}

# 应用当前状态: 生成配置 -> 服务 -> 防火墙 -> 客户端文件
apply_all() {
	write_server_configs || return 1
	save_state
	apply_services || warn "部分服务未能正常启动, 请查看上方日志"
	fw_apply open
	hop_setup
	write_client_files
	return 0
}

do_install() {
	local old_protocols=""
	if is_installed; then
		load_state
		old_protocols=$PROTOCOLS
		warn "检测到已安装 (协议: ${PROTOCOLS}), 继续将覆盖现有配置并重新生成全部凭据"
		confirm "确定重新安装?" n || return 0
	fi
	install_base_deps
	if [ -n "$old_protocols" ]; then
		# 先停止旧服务, 释放端口, 以便重新检测端口占用
		fw_apply close
		hop_rules del
		svc_stop singbox
		svc_stop xray
	fi
	reset_state
	choose_protocols
	choose_extras
	choose_tls
	choose_ports
	choose_address
	print_plan
	confirm "确认开始安装?" y || die "已取消"

	# sing-box 监听 "::" 为双栈; 内核禁用 IPv6 时会自动退回 IPv4 ("0.0.0.0" 则仅 IPv4)
	LISTEN_ADDR="::"
	BLOCK_PRIVATE=${OPT_BLOCK_PRIVATE:-1}
	BLOCK_BT=1
	mkdir -p "$ONEBOX_DIR" "$CLIENT_DIR" "$LOG_DIR" && chmod 700 "$ONEBOX_DIR"

	ensure_cores || die "内核安装失败"
	gen_credentials
	obtain_cert || die "证书配置失败"
	INSTALLED_AT=$(date '+%Y-%m-%d %H:%M:%S')
	install_self
	apply_all || die "配置生成失败"

	if ! is_container_virt && [ "$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null)" != bbr ]; then
		if ask_yn "是否开启 BBR 拥塞控制 (推荐)" "${OPT_BBR:-y}"; then enable_bbr || true; fi
	fi
	echo
	info "安装完成!"
	show_info
	echo
	info "以后可随时输入 ${BOLD}onebox${PLAIN} 打开管理菜单"
}

# ---------------------------------------------------------------------------
# 信息展示
# ---------------------------------------------------------------------------
require_installed() {
	is_installed || die "尚未安装, 请先执行安装 (onebox install)"
	load_state
}

show_qr() {
	local p
	if ! has qrencode; then
		ensure_cmds qrencode >/dev/null 2>&1 || {
			warn "未能安装 qrencode, 无法显示二维码"
			return 1
		}
	fi
	for p in $PROTOCOLS; do
		proto_client_ok "$p" link || continue
		printf '\n%s%s%s\n' "$YELLOW" "$(node_name "$p")" "$PLAIN"
		qrencode -t ANSIUTF8 -m 1 "$(link_of "$p")"
	done
}

show_info() {
	local p c
	title "节点信息"
	printf '  %s %s %s %s\n' "$(pad 协议 22)" "$(pad 端口 14)" "$(pad 内核 9)" "客户端"
	for p in $PROTOCOLS; do
		local cl=""
		for c in link mihomo singbox xray; do
			proto_client_ok "$p" "$c" || continue
			case "$c" in link) cl+="链接 " ;; mihomo) cl+="mihomo " ;; singbox) cl+="sing-box " ;; xray) cl+="Xray " ;; esac
		done
		printf '  %-22s %-14s %-9s %s\n' "$(proto_title "$p")" "$(proto_net "$p" | sed 's/both/tcp+udp/')/$(pget PORT "$p")" \
			"$(core_title "$(pget CORE "$p")")" "$cl"
	done
	echo
	echo "  服务器地址 : ${SERVER_ADDR}"
	echo "  UUID       : ${UUID}"
	echo "  密码       : ${PASSWORD}"
	if any_reality; then
		echo "  REALITY    : SNI=${REALITY_SNI}  公钥=${REALITY_PUBLIC_KEY}  ShortID=${REALITY_SHORT_ID}"
	fi
	proto_enabled shadowsocks && echo "  SS-2022    : ${SS_METHOD} / ${SS_PASSWORD}"
	if [ -n "$TLS_MODE" ]; then
		case "$TLS_MODE" in
		self) echo "  TLS 证书   : 自签 (SNI=${TLS_SNI}, 客户端需开启 跳过证书验证/insecure)" ;;
		*) echo "  TLS 证书   : ${DOMAIN} (到期: $(cert_expiry))" ;;
		esac
	fi
	proto_enabled hysteria2 && [ -n "$HY2_HOP" ] && echo "  Hy2 端口跳跃: ${HY2_HOP}"
	proto_enabled shadowtls && echo "  ShadowTLS  : 握手站点=${SHADOWTLS_SNI}  (仅 sing-box / mihomo 客户端支持)"
	proto_enabled vless-xhttp && echo "  提示: XHTTP 仅 Xray 内核客户端 (v2rayN/v2rayNG 等) 与新版 mihomo 支持, sing-box 客户端不支持"

	title "分享链接 (v2rayN / v2rayNG / NekoBox / Shadowrocket / Hiddify / Karing)"
	if [ -s "$CLIENT_DIR/links.txt" ]; then
		while IFS= read -r c; do printf '%s\n\n' "$c"; done <"$CLIENT_DIR/links.txt"
	else
		echo "  (无)"
	fi
	title "客户端配置文件"
	echo "  订阅 (Base64)     : ${CLIENT_DIR}/sub.txt"
	echo "  mihomo / Clash    : ${CLIENT_DIR}/mihomo.yaml"
	echo "  sing-box (TUN)    : ${CLIENT_DIR}/sing-box.json"
	echo "  sing-box (代理端口): ${CLIENT_DIR}/sing-box-notun.json"
	[ -f "$CLIENT_DIR/xray.json" ] && echo "  Xray              : ${CLIENT_DIR}/xray.json"
	echo "  查看: onebox client mihomo | singbox | singbox-notun | xray | sub | links"
}

show_client() {
	local which=${1:-}
	if [ -z "$which" ]; then
		title "查看客户端配置"
		echo "  1) mihomo / Clash Meta (YAML)"
		echo "  2) sing-box (TUN 模式, 适用于 SFA/SFI/SFM/GUI 客户端)"
		echo "  3) sing-box (仅代理端口 127.0.0.1:2080)"
		echo "  4) Xray"
		echo "  5) 分享链接"
		echo "  6) Base64 订阅内容"
		echo "  7) 二维码"
		local n
		ask_num n "请选择" 1 1 7 || return 0
		case "$n" in 1) which=mihomo ;; 2) which=singbox ;; 3) which=singbox-notun ;; 4) which=xray ;; 5) which=links ;; 6) which=sub ;; 7) which=qr ;; esac
	fi
	case "$which" in
	mihomo | clash) cat "$CLIENT_DIR/mihomo.yaml" ;;
	singbox | sing-box) cat "$CLIENT_DIR/sing-box.json" ;;
	singbox-notun | sing-box-notun) cat "$CLIENT_DIR/sing-box-notun.json" ;;
	xray)
		if [ -f "$CLIENT_DIR/xray.json" ]; then cat "$CLIENT_DIR/xray.json"; else warn "当前协议组合中没有 Xray 客户端支持的协议"; fi
		;;
	links | link) cat "$CLIENT_DIR/links.txt" ;;
	sub) cat "$CLIENT_DIR/sub.txt" && echo ;;
	qr) show_qr ;;
	*) die "未知类型: ${which} (可选: mihomo singbox singbox-notun xray links sub qr)" ;;
	esac
}

# ---------------------------------------------------------------------------
# 管理操作
# ---------------------------------------------------------------------------
all_cores_do() {
	local act=$1 core
	for core in singbox xray; do
		core_used "$core" || continue
		case "$act" in
		start) svc_start "$core" ;;
		stop) svc_stop "$core" ;;
		restart) svc_restart "$core" ;;
		esac
	done
}

do_service() {
	local act=$1 core
	require_installed
	case "$act" in
	start | stop | restart)
		all_cores_do "$act"
		[ "$act" = start ] && [ -n "$HY2_HOP" ] && proto_enabled hysteria2 && hop_rules add
		sleep 1
		for core in singbox xray; do
			core_used "$core" && echo "  $(core_title "$core"): $(svc_status_text "$core")"
		done
		;;
	status)
		for core in singbox xray; do
			core_used "$core" || continue
			echo "  $(core_title "$core") $( [ "$core" = singbox ] && sb_installed_version || xr_installed_version): $(svc_status_text "$core")"
		done
		;;
	esac
	return 0
}

do_log() {
	local core=${1:-}
	require_installed
	if [ -z "$core" ]; then
		for core in singbox xray; do
			core_used "$core" || continue
			title "$(core_title "$core") 日志"
			svc_logs "$core" 50
		done
	else
		case "$core" in sing-box) core=singbox ;; esac
		svc_logs "$core" 100
	fi
}

do_add_protocol() {
	local p=${1:-} i ans prefer port
	require_installed
	if [ -z "$p" ]; then
		title "添加协议"
		print_protocol_table
		ask ans "请输入要添加的协议编号" ""
		p=$(protocol_by_index "$ans") || die "无效编号"
	fi
	case " $ALL_PROTOCOLS " in *" $p "*) ;; *) die "未知协议: $p" ;; esac
	proto_enabled "$p" && die "$(proto_title "$p") 已存在"
	PROTOCOLS=$(normalize_protocols $PROTOCOLS "$p")
	# 内核: 优先使用已在运行的内核
	prefer=$(pget CORE "$(printf '%s' "$PROTOCOLS" | awk '{print $1}')")
	if [ "$(proto_cores "$p")" = "singbox xray" ]; then
		if [ -n "${OPT_CORE:-}" ]; then
			prefer=$OPT_CORE
		elif is_interactive; then
			echo "  该协议可用内核: 1) sing-box  2) Xray"
			ask_num i "请选择" "$([ "$prefer" = xray ] && echo 2 || echo 1)" 1 2 || i=1
			[ "$i" = 2 ] && prefer=xray || prefer=singbox
		fi
		pset CORE "$p" "${prefer:-singbox}"
	else
		pset CORE "$p" "$(proto_cores "$p")"
	fi
	fill_missing_credentials
	if proto_uses_reality "$p" && [ -z "$REALITY_SNI" ]; then
		choose_sni REALITY_SNI "REALITY 目标站点" "${OPT_SNI:-1}"
		REALITY_DEST="${REALITY_SNI}:443"
	fi
	if [ "$p" = shadowtls ] && [ -z "$SHADOWTLS_SNI" ]; then
		choose_sni SHADOWTLS_SNI "ShadowTLS 握手站点" "${REALITY_SNI:-1}"
		SHADOWTLS_DEST="${SHADOWTLS_SNI}:443"
	fi
	if { proto_needs_cert "$p" || { [ "$p" = vmess-ws ] && vmess_tls_enabled; }; } && [ -z "$TLS_MODE" ]; then
		choose_tls
		obtain_cert || die "证书配置失败"
	fi
	[ "$p" = hysteria2 ] && [ -z "$HY2_OBFS" ] && HY2_OBFS=0
	ensure_cores || die "内核安装失败"
	[ -n "$REALITY_PRIVATE_KEY" ] || ! any_reality || gen_reality_keypair
	port=$(opt_port_for "$p") || port=$(default_port_for "$p")
	while :; do
		ask port "$(proto_title "$p") 端口" "$port"
		port_ok "$port" "$p" && break
		is_interactive || die "端口 ${port} 不可用"
	done
	pset PORT "$p" "$port"
	apply_all || die "应用配置失败"
	info "已添加 $(proto_title "$p")"
	link_of "$p" 2>/dev/null
}

do_del_protocol() {
	local p=${1:-} ans i=0 x
	require_installed
	if [ -z "$p" ]; then
		title "删除协议"
		for x in $PROTOCOLS; do
			i=$((i + 1))
			printf '  %d) %s\n' "$i" "$(proto_title "$x")"
		done
		ask ans "请输入要删除的协议编号" ""
		p=$(printf '%s\n' $PROTOCOLS | sed -n "${ans}p")
		[ -n "$p" ] || die "无效编号"
	fi
	proto_enabled "$p" || die "未启用协议: $p"
	[ "$(printf '%s\n' $PROTOCOLS | wc -l)" -gt 1 ] || die "至少需要保留一个协议, 如需全部移除请使用卸载"
	fw_apply close
	[ "$p" = hysteria2 ] && hop_rules del
	PROTOCOLS=$(printf '%s\n' $PROTOCOLS | grep -vx "$p" | tr '\n' ' ')
	PROTOCOLS=${PROTOCOLS% }
	pset PORT "$p" ""
	pset CORE "$p" ""
	apply_all || die "应用配置失败"
	info "已删除 $(proto_title "$p")"
}

do_change_port() {
	local p=${1:-} port=${2:-} ans i=0 x
	require_installed
	if [ -z "$p" ]; then
		title "修改端口"
		for x in $PROTOCOLS; do
			i=$((i + 1))
			printf '  %d) %-22s 当前端口: %s\n' "$i" "$(proto_title "$x")" "$(pget PORT "$x")"
		done
		ask ans "请选择协议编号" ""
		p=$(printf '%s\n' $PROTOCOLS | sed -n "${ans}p")
		[ -n "$p" ] || die "无效编号"
	fi
	proto_enabled "$p" || die "未启用协议: $p"
	while :; do
		[ -n "$port" ] || ask port "$(proto_title "$p") 新端口" "$(pget PORT "$p")"
		port_ok "$port" "$p" && break
		is_interactive || die "端口 ${port} 不可用"
		port=""
	done
	fw_apply close
	hop_rules del
	pset PORT "$p" "$port"
	apply_all || die "应用配置失败"
	info "$(proto_title "$p") 端口已修改为 ${port}"
}

do_reset_credentials() {
	require_installed
	confirm "将重新生成全部 UUID / 密码 / REALITY 密钥, 旧的客户端配置将失效, 继续?" n || return 0
	gen_credentials
	apply_all || die "应用配置失败"
	info "凭据已重置, 请重新导入客户端配置"
	show_info
}

do_change_addr() {
	require_installed
	choose_address
	apply_all || die "应用配置失败"
	info "已更新客户端地址"
}

do_update_core() {
	local which=${1:-all}
	require_installed
	FORCE_CORE_UPDATE=1
	if [ "$which" = all ] || [ "$which" = singbox ] || [ "$which" = sing-box ]; then
		if [ -x "$SB_BIN" ] || core_used singbox; then
			local old
			old=$(sb_installed_version)
			install_singbox && info "sing-box: ${old:-无} -> $(sb_installed_version)"
		fi
	fi
	if [ "$which" = all ] || [ "$which" = xray ]; then
		if [ -x "$XR_BIN" ] || core_used xray; then
			local old
			old=$(xr_installed_version)
			install_xray && info "Xray: ${old:-无} -> $(xr_installed_version)"
		fi
	fi
	FORCE_CORE_UPDATE=0
	apply_all || warn "应用配置失败"
}

do_update_script() {
	local tmp
	tmp=$(mktemp)
	info "下载最新脚本..."
	if http_get "$(gh_url "$SCRIPT_RAW_URL")" "$tmp" && head -n 5 "$tmp" | grep -q 'Sing-Xray-Onebox' && bash -n "$tmp" 2>/dev/null; then
		chmod 755 "$tmp"
		mv -f "$tmp" "$CMD_PATH"
		info "脚本已更新: $(sed -n 's/^readonly SCRIPT_VERSION="\(.*\)"/\1/p' "$CMD_PATH")"
		if is_installed; then
			# 用新脚本重新生成配置, 以应用新版本的改进
			"$CMD_PATH" regen >/dev/null 2>&1 || true
		fi
	else
		rm -f "$tmp"
		err "脚本更新失败"
		return 1
	fi
}

do_cert() {
	require_installed
	title "证书管理"
	case "$TLS_MODE" in
	"") echo "  当前协议无需证书" ;;
	self) echo "  当前: 自签证书 (SNI=${TLS_SNI}, 到期: $(cert_expiry))" ;;
	acme) echo "  当前: Let's Encrypt ${DOMAIN} (到期: $(cert_expiry)), acme.sh 自动续期" ;;
	custom) echo "  当前: 自有证书 ${DOMAIN} (到期: $(cert_expiry))" ;;
	esac
	echo "  1) 重新申请 / 更换证书"
	echo "  2) 强制续期 (ACME)"
	echo "  0) 返回"
	local n
	ask_num n "请选择" 0 0 2 || return 0
	case "$n" in
	1)
		local old_mode=$TLS_MODE
		TLS_MODE=""
		local saved=$PROTOCOLS
		# choose_tls 需要至少一个证书协议才会询问
		any_needs_cert || PROTOCOLS="$PROTOCOLS trojan"
		choose_tls
		PROTOCOLS=$saved
		[ -n "$TLS_MODE" ] || TLS_MODE=$old_mode
		obtain_cert || die "证书配置失败"
		[ "$TLS_MODE" = acme ] || [ "$TLS_MODE" = custom ] && ask_yn "是否把客户端连接地址改为 ${DOMAIN}?" y && SERVER_ADDR=$DOMAIN
		apply_all || die "应用配置失败"
		info "证书已更新"
		;;
	2)
		[ "$TLS_MODE" = acme ] || die "当前不是 ACME 证书"
		"$ACME_SH" --renew -d "$DOMAIN" --ecc --force && info "续期完成"
		;;
	esac
}

do_uninstall() {
	local purge=0
	if [ "${1:-}" = "--purge" ]; then purge=1; fi
	title "卸载"
	confirm "确定卸载 Sing-Xray-Onebox (将删除全部服务、配置与内核)?" n || return 0
	load_state 2>/dev/null || true
	fw_apply close 2>/dev/null
	hop_rules del 2>/dev/null
	hop_persist del 2>/dev/null
	svc_remove singbox
	svc_remove xray
	_none_autostart_del
	if [ "$TLS_MODE" = acme ] && [ -x "$ACME_SH" ] && [ -n "$DOMAIN" ]; then
		"$ACME_SH" --remove -d "$DOMAIN" --ecc >/dev/null 2>&1
	fi
	rm -rf "$ONEBOX_DIR" "$BIN_DIR" "$LOG_DIR" "$RUN_DIR"
	rmdir "$(dirname "$BIN_DIR")" 2>/dev/null
	if [ -f /etc/sysctl.d/99-onebox-bbr.conf ]; then
		if [ "$purge" = 1 ] || ask_yn "是否同时移除 BBR 设置?" n; then
			rm -f /etc/sysctl.d/99-onebox-bbr.conf
		fi
	fi
	rm -f "$CMD_PATH"
	info "卸载完成"
}

# ---------------------------------------------------------------------------
# 菜单
# ---------------------------------------------------------------------------
menu_header() {
	clear 2>/dev/null || true
	printf '%s%s' "$BOLD" "$BLUE"
	cat <<'EOF'
   ____  _                 __  __                ___             _
  / ___|(_)_ __   __ _     \ \/ /_ __ __ _ _   _ / _ \ _ __   ___| |__   _____  __
  \___ \| | '_ \ / _` |_____\  /| '__/ _` | | | | | | | '_ \ / _ \ '_ \ / _ \ \/ /
   ___) | | | | | (_| |_____/  \| | | (_| | |_| | |_| | | | |  __/ |_) | (_) >  <
  |____/|_|_| |_|\__, |    /_/\_\_|  \__,_|\__, |\___/|_| |_|\___|_.__/ \___/_/\_\
                 |___/                     |___/
EOF
	printf '%s' "$PLAIN"
	printf '  sing-box / Xray 多协议组合一键脚本  v%s\n' "$SCRIPT_VERSION"
	hr
	printf '  系统: %s (%s)  虚拟化: %s  BBR: %s\n' "$OS_NAME" "$ARCH_RAW" "$VIRT" "$(bbr_status)"
	if is_installed; then
		load_state
		printf '  sing-box: %s %s   Xray: %s %s\n' "$(sb_installed_version || true)" "$(core_used singbox && svc_status_text singbox || printf '%s' '未使用')" \
			"$(xr_installed_version || true)" "$(core_used xray && svc_status_text xray || printf '%s' '未使用')"
		printf '  协议: %s\n' "$(for p in $PROTOCOLS; do printf '%s ' "$(proto_title "$p")"; done)"
	else
		printf '  状态: %s未安装%s\n' "$YELLOW" "$PLAIN"
	fi
	hr
}

main_menu() {
	local n
	while :; do
		menu_header
		cat <<EOF
  ${GREEN}1.${PLAIN}  安装 / 重装 (选择协议组合)
  ${GREEN}2.${PLAIN}  查看节点信息与分享链接
  ${GREEN}3.${PLAIN}  查看客户端配置 (mihomo / sing-box / Xray / 订阅 / 二维码)
  ${GREEN}4.${PLAIN}  添加协议
  ${GREEN}5.${PLAIN}  删除协议
  ${GREEN}6.${PLAIN}  修改端口
  ${GREEN}7.${PLAIN}  修改客户端连接地址 / 节点名称
  ${GREEN}8.${PLAIN}  重置 UUID / 密码 / 密钥
  ${GREEN}9.${PLAIN}  启动 / 停止 / 重启 / 日志
  ${GREEN}10.${PLAIN} 更新内核 (sing-box / Xray)
  ${GREEN}11.${PLAIN} 证书管理
  ${GREEN}12.${PLAIN} 开启 BBR
  ${GREEN}13.${PLAIN} 更新脚本
  ${GREEN}14.${PLAIN} 卸载
  ${GREEN}0.${PLAIN}  退出
EOF
		hr
		ask_num n "请选择" 0 0 14 || exit 0
		case "$n" in
		0) exit 0 ;;
		1) (do_install) ;;
		2) (require_installed && show_info) ;;
		3) (require_installed && show_client) ;;
		4) (do_add_protocol) ;;
		5) (do_del_protocol) ;;
		6) (do_change_port) ;;
		7) (do_change_addr) ;;
		8) (do_reset_credentials) ;;
		9) service_menu ;;
		10) (do_update_core all) ;;
		11) (do_cert) ;;
		12) (enable_bbr) ;;
		13) (do_update_script) && exec "$CMD_PATH" ;;
		14) (do_uninstall) && ! [ -f "$STATE_FILE" ] && exit 0 ;;
		esac
		pause
	done
}

service_menu() {
	local n
	echo "  1) 启动  2) 停止  3) 重启  4) 状态  5) 查看日志  0) 返回"
	ask_num n "请选择" 0 0 5 || return 0
	case "$n" in
	1) (do_service start) ;;
	2) (do_service stop) ;;
	3) (do_service restart) ;;
	4) (do_service status) ;;
	5) (do_log) ;;
	esac
}

# ---------------------------------------------------------------------------
# 命令行
# ---------------------------------------------------------------------------
usage() {
	cat <<EOF
Sing-Xray-Onebox v${SCRIPT_VERSION} —— sing-box / Xray 多协议组合一键脚本

用法: onebox [命令] [选项]

命令:
  (无)                     打开交互式管理菜单
  install                  安装 / 重装
  info                     查看节点信息与分享链接
  client <类型>            输出客户端配置: mihomo | singbox | singbox-notun | xray | links | sub | qr
  add <协议>               添加协议
  del <协议>               删除协议
  port <协议> <端口>       修改端口
  addr                     修改客户端连接地址 / 节点名称
  reset                    重置全部 UUID / 密码 / 密钥
  start | stop | restart | status
  log [singbox|xray]       查看日志
  update [singbox|xray]    更新内核 (默认全部)
  update-script            更新本脚本
  cert                     证书管理
  bbr                      开启 BBR
  regen                    按当前设置重新生成全部配置
  uninstall                卸载
  help | version

install 选项 (用于无人值守安装):
  --preset <1-7>           协议组合 (1=Reality+Hy2+TUIC, 2=Xray 经典, 3=双内核, 4=sing-box 全家桶, 5=CDN, 6=仅 Reality, 7=自定义)
  --protocols <a,b,...>    自定义协议列表 (隐含 --preset 7), 可选:
                           ${ALL_PROTOCOLS// /, }
  --core <singbox|xray>    两种内核都支持的协议优先使用的内核
  --sni <域名>             REALITY / ShadowTLS 伪装站点
  --tls <self|acme|cf>     证书方式: 自签 / ACME HTTP 验证 / ACME Cloudflare DNS 验证 (cf 需设置 CF_Token 环境变量)
  --domain <域名>          ACME 证书域名
  --addr <IP 或域名>       客户端连接地址 (默认自动检测公网 IP)
  --name <名称>            节点名称前缀
  --port <协议>=<端口>     指定端口, 可重复使用
  --hy2-hop <起-止>        Hysteria2 端口跳跃范围, 例如 20000-40000
  --hy2-obfs               Hysteria2 启用 salamander 混淆
  --no-bbr                 不开启 BBR
  -y, --yes                全部使用默认值, 不再询问

环境变量:
  GH_PROXY=https://ghfast.top/    GitHub 下载加速前缀 (国内服务器)
  ONEBOX_SINGBOX_BIN / ONEBOX_XRAY_BIN   使用本地内核文件 (离线安装)

示例:
  bash onebox.sh install --preset 1 -y
  bash onebox.sh install --protocols vless-reality,hysteria2,anytls --core singbox -y
  CF_Token=xxxx bash onebox.sh install --preset 5 --tls cf --domain v.example.com -y
EOF
}

OPT_PORTS=""
parse_install_opts() {
	while [ $# -gt 0 ]; do
		case "$1" in
		--preset) OPT_PRESET=$2 && shift ;;
		--protocols)
			OPT_PRESET=7
			local x idx="" i p
			for x in ${2//,/ }; do
				i=0
				for p in $ALL_PROTOCOLS; do
					i=$((i + 1))
					[ "$p" = "$x" ] && idx+="$i "
				done
				case " $ALL_PROTOCOLS " in *" $x "*) ;; *) die "未知协议: $x" ;; esac
			done
			OPT_CUSTOM=${idx% }
			shift
			;;
		--core)
			case "$2" in singbox | sing-box) OPT_CORE=singbox OPT_CORE_CHOICE=1 ;; xray) OPT_CORE=xray OPT_CORE_CHOICE=2 ;; *) die "--core 仅支持 singbox 或 xray" ;; esac
			shift
			;;
		--sni) OPT_SNI=$2 && shift ;;
		--reality-dest) OPT_REALITY_DEST=$2 && shift ;;
		--tls)
			case "$2" in self) OPT_TLS_CHOICE=1 ;; acme | http) OPT_TLS_CHOICE=2 ;; cf | cloudflare) OPT_TLS_CHOICE=3 ;; *) die "--tls 仅支持 self / acme / cf" ;; esac
			shift
			;;
		--domain) OPT_DOMAIN=$2 && shift ;;
		--addr) OPT_ADDR=$2 && shift ;;
		--name) OPT_NAME=$2 && shift ;;
		--port) OPT_PORTS+="$2 " && shift ;;
		--hy2-hop) OPT_HY2_HOP=$2 && shift ;;
		--hy2-obfs) OPT_HY2_OBFS=y ;;
		--no-bbr) OPT_BBR=n ;;
		--allow-private) OPT_BLOCK_PRIVATE=0 ;;
		-y | --yes) AUTO_YES=1 ;;
		*) die "未知选项: $1 (onebox help 查看帮助)" ;;
		esac
		shift
	done
}

# --port 协议=端口 的预设值
opt_port_for() {
	local p=$1 kv
	for kv in $OPT_PORTS; do
		[ "${kv%%=*}" = "$p" ] && {
			printf '%s' "${kv#*=}"
			return 0
		}
	done
	return 1
}

init_env() {
	require_root
	setup_tty
	detect_os
	detect_init
	detect_virt
	detect_arch
}

main() {
	# 全局选项 -y / --yes 可出现在任意位置
	local a args=()
	for a in "$@"; do
		case "$a" in
		-y | --yes) AUTO_YES=1 ;;
		*) args+=("$a") ;;
		esac
	done
	set -- "${args[@]}"
	local cmd=${1:-menu}
	[ $# -gt 0 ] && shift
	case "$cmd" in
	help | -h | --help)
		usage
		return 0
		;;
	version | -v | --version)
		echo "$SCRIPT_VERSION"
		return 0
		;;
	esac
	init_env
	case "$cmd" in
	menu) main_menu ;;
	install)
		parse_install_opts "$@"
		do_install
		;;
	info) require_installed && show_info ;;
	client | config) require_installed && show_client "${1:-}" ;;
	qr) require_installed && show_qr ;;
	links) require_installed && cat "$CLIENT_DIR/links.txt" ;;
	add)
		parse_install_opts "${@:2}"
		do_add_protocol "${1:-}"
		;;
	del | remove) do_del_protocol "${1:-}" ;;
	port) do_change_port "${1:-}" "${2:-}" ;;
	addr)
		parse_install_opts "$@"
		do_change_addr
		;;
	reset) do_reset_credentials ;;
	start | stop | restart | status) do_service "$cmd" ;;
	log | logs) do_log "${1:-}" ;;
	update) do_update_core "${1:-all}" ;;
	update-script) do_update_script ;;
	cert) do_cert ;;
	bbr) enable_bbr ;;
	regen)
		require_installed
		apply_all
		;;
	hop-apply)
		load_state && hop_rules add
		;;
	hop-clear)
		load_state && hop_rules del
		;;
	uninstall) do_uninstall "$@" ;;
	*)
		usage
		return 1
		;;
	esac
}

# ONEBOX_SOURCE_ONLY=1 时仅加载函数 (供测试使用)
[ -n "${ONEBOX_SOURCE_ONLY:-}" ] || main "$@"
