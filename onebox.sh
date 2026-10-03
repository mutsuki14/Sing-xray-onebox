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

# 以 sh 调用 bash 时处于 POSIX 模式, bash 5.1 之前该模式下不支持进程替换等语法, 先退出 POSIX 模式
case ":${SHELLOPTS:-}:" in *:posix:*) set +o posix ;; esac

if [ "${BASH_VERSINFO[0]:-0}" -lt 4 ]; then
	echo "本脚本需要 bash 4.0 或更高版本 (当前: ${BASH_VERSION})" >&2
	exit 1
fi

export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:${PATH}"
umask 022

# ---------------------------------------------------------------------------
# 常量
# ---------------------------------------------------------------------------
readonly SCRIPT_VERSION="1.3.0"
readonly SCRIPT_REPO="mutsuki14/Sing-xray-onebox"
readonly SCRIPT_RAW_URL="${ONEBOX_SCRIPT_URL:-https://raw.githubusercontent.com/${SCRIPT_REPO}/claude/linux-vps-proxy-script-1m1ksn/onebox.sh}"

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
INITD_DIR="${ONEBOX_INITD_DIR:-/etc/init.d}"
SB_SERVICE="onebox-sing-box"
XR_SERVICE="onebox-xray"

# 当 GitHub 最新版本号无法获取时使用的保底版本
readonly FALLBACK_SB_VERSION="1.14.2"
# Xray 默认安装经过测试的版本: 26.4 之后的预发布版 REALITY 服务端要求客户端携带 X25519MLKEM768,
# 会拒绝 sing-box 客户端. 可用 --xray-version latest 或 onebox update xray 主动升级.
readonly TESTED_XR_VERSION="26.3.27"
XR_VERSION_WANT="${ONEBOX_XRAY_VERSION:-}"
XR_VERSION_WANT="${XR_VERSION_WANT#v}"

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
		# 去掉方向键等产生的 ANSI 转义序列及其他控制字符 (否则会写进节点名 / 地址, 破坏客户端配置)
		if [[ "$_a_val" == *[[:cntrl:]]* ]]; then
			local _a_esc=$'\033'
			_a_val=$(printf '%s' "$_a_val" | sed "s/${_a_esc}\[[0-9;?]*[A-Za-z~]//g; s/${_a_esc}O[A-Za-z]//g")
			_a_val=${_a_val//[[:cntrl:]]/}
		fi
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
		if [[ "$_n_val" =~ ^[0-9]{1,6}$ ]] && [ "$((10#$_n_val))" -ge "$_n_min" ] && [ "$((10#$_n_val))" -le "$_n_max" ]; then
			printf -v "$_n_var" '%s' "$((10#$_n_val))"
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

# URL 编码. musl 的 C 区域把 0x80-0xFF 字节映射为 U+DF80..U+DFFF, bash 的 printf "'c"
# 在 Alpine 上会得到 0xDFE4 而不是 0xE4, 因此只取最后两位十六进制.
urlencode() {
	local LC_ALL=C s=$1 i c o out=""
	for ((i = 0; i < ${#s}; i++)); do
		c=${s:i:1}
		case "$c" in
		[A-Za-z0-9.~_-]) out+=$c ;;
		*)
			printf -v o '%02X' "'$c"
			out+="%${o: -2}"
			;;
		esac
	done
	printf '%s' "$out"
}

# ask_secret VAR "提示"  —— 读取不回显的敏感输入 (如 API Token)
ask_secret() {
	local _k_var=$1 _k_val=""
	if is_interactive; then
		printf '%s: ' "$2" >&2
		IFS= read -rs _k_val <"$TTY_IN" || _k_val=""
		printf '\n' >&2
	fi
	printf -v "$_k_var" '%s' "${_k_val//[[:cntrl:][:space:]]/}"
}

valid_ipv4() { [[ "$1" =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$ ]] && [ "${BASH_REMATCH[1]}" -le 255 ] && [ "${BASH_REMATCH[2]}" -le 255 ] && [ "${BASH_REMATCH[3]}" -le 255 ] && [ "${BASH_REMATCH[4]}" -le 255 ]; }
valid_ipv6() {
	local addr=$1 left right part tail count=0 compressed=0
	local groups=()
	[[ "$addr" =~ ^[0-9a-fA-F:.]+$ ]] && [[ "$addr" == *:* ]] || return 1
	# An IPv4 suffix occupies the final two 16-bit groups.
	if [[ "$addr" == *.* ]]; then
		tail=${addr##*:}
		valid_ipv4 "$tail" || return 1
		addr="${addr%:*}:0:0"
	fi
	if [[ "$addr" == *::* ]]; then
		compressed=1
		left=${addr%%::*} right=${addr#*::}
		[[ "$right" != *::* && "$left" != *: && "$right" != :* ]] || return 1
		addr="${left}${left:+:}${right}"
		addr=${addr%:}
	else
		[[ "$addr" != :* && "$addr" != *: ]] || return 1
	fi
	IFS=: read -r -a groups <<<"$addr"
	for part in "${groups[@]}"; do
		[[ "$part" =~ ^[0-9a-fA-F]{1,4}$ ]] || return 1
		count=$((count + 1))
	done
	if [ "$compressed" = 1 ]; then [ "$count" -lt 8 ]; else [ "$count" -eq 8 ]; fi
}

# 合法域名 (至少包含一个点, 仅字母数字与连字符)
valid_domain() {
	[[ "$1" =~ ^([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$ ]]
}

# ask_domain VAR "提示" "默认值"  —— 读取并校验域名
ask_domain() {
	local _d_var=$1 _d_prompt=$2 _d_def=${3-} _d_val
	while :; do
		ask _d_val "$_d_prompt" "$_d_def"
		_d_val=${_d_val#http://}
		_d_val=${_d_val#https://}
		_d_val=${_d_val%%/*}
		if valid_domain "$_d_val"; then
			printf -v "$_d_var" '%s' "$_d_val"
			return 0
		fi
		warn "请输入合法的域名, 例如 www.example.com"
		is_interactive || die "域名无效: ${_d_val:-<空>}"
	done
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
	s=${s//[[:cntrl:]]/}
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
OS_ID="" OS_VER="" OS_NAME="" PKG="" INIT="" VIRT="" ARCH_RAW=""
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
		OS_VER=$(_osr_get VERSION_ID)
		OS_NAME=$(_osr_get PRETTY_NAME)
	elif [ -r /etc/redhat-release ]; then
		OS_ID=centos
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
	elif has openrc-run && has rc-service && { [ -d /run/openrc ] || [ -f /run/openrc/softlevel ]; }; then
		# 仅当 OpenRC 真正作为 init 运行时 (Alpine 的 docker 镜像装了 openrc 但未启动)
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
		elif [ -f /run/.containerenv ]; then
			VIRT=podman
		elif grep -qa 'container=lxc' /proc/1/environ 2>/dev/null; then
			VIRT=lxc
		elif grep -qa 'container=' /proc/1/environ 2>/dev/null; then
			VIRT=container
		elif grep -qaE 'lxcfs|/lxc/' /proc/1/cgroup 2>/dev/null; then
			VIRT=lxc
		fi
	fi
	[ -n "$VIRT" ] || VIRT=none
}

is_container_virt() {
	case "$VIRT" in openvz | lxc | lxc-libvirt | docker | podman | rkt | container | systemd-nspawn | wsl | proot | pouch) return 0 ;; *) return 1 ;; esac
}

# 本机字节序: 读取 ELF 头第 6 字节 (EI_DATA: 01=小端 02=大端). MIPS 的 uname -m 不区分字节序.
_elf_le() { [ "$(od -An -tx1 -j5 -N1 /proc/self/exe 2>/dev/null | tr -d ' \n')" = 01 ]; }

detect_arch() {
	ARCH_RAW=$(uname -m)
	case "$ARCH_RAW" in
	x86_64 | amd64) SB_ARCH=amd64 XR_ARCH=64 ;;
	i386 | i486 | i586 | i686 | x86) SB_ARCH=386 XR_ARCH=32 ;;
	armv7* | armv8l) SB_ARCH=armv7 XR_ARCH=arm32-v7a ;;
	aarch64 | arm64 | armv8*) SB_ARCH=arm64 XR_ARCH=arm64-v8a ;;
	armv6*) SB_ARCH=armv6 XR_ARCH=arm32-v6 ;;
	armv5* | arm) SB_ARCH=armv5 XR_ARCH=arm32-v5 ;;
	s390x) SB_ARCH=s390x XR_ARCH=s390x ;;
	riscv64) SB_ARCH=riscv64 XR_ARCH=riscv64 ;;
	loongarch64 | loong64) SB_ARCH=loong64 XR_ARCH=loong64 ;;
	ppc64le) SB_ARCH=ppc64le XR_ARCH=ppc64le ;;
	ppc64) SB_ARCH="" XR_ARCH=ppc64 ;; # sing-box 无 ppc64 (大端) 构建
	mips64*) if _elf_le; then SB_ARCH=mips64le XR_ARCH=mips64le; else SB_ARCH=mips64 XR_ARCH=mips64; fi ;;
	mips*) if _elf_le; then SB_ARCH=mipsle XR_ARCH=mips32le; else SB_ARCH=mips XR_ARCH=mips32; fi ;;
	*) die "暂不支持的 CPU 架构: ${ARCH_RAW}" ;;
	esac
	# 32 位 ARM 若内核报告 v7 但无硬件浮点 (VFPv3), 退回 v6
	if [ "$SB_ARCH" = armv7 ] && [ -r /proc/cpuinfo ] && ! grep -qiE 'vfpv3|vfpv4|neon|asimd' /proc/cpuinfo; then
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
	apt) DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=120 update -qq >/dev/null 2>&1 ;;
	apk) apk update >/dev/null 2>&1 ;;
	pacman) : ;; # 不单独 -Sy (部分升级风险), 见 pkg_install
	zypper) zypper -n refresh >/dev/null 2>&1 ;;
	xbps) xbps-install -S >/dev/null 2>&1 || { xbps-install -Syu xbps >/dev/null 2>&1; } ;;
	esac
	return 0
}

pkg_install() {
	[ $# -gt 0 ] || return 0
	case "$PKG" in
	apt) DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=120 -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold install -y -qq --no-install-recommends "$@" >/dev/null 2>&1 ;;
	dnf) dnf install -y -q "$@" >/dev/null 2>&1 ;;
	yum) yum install -y -q "$@" >/dev/null 2>&1 ;;
	apk) apk add --no-cache "$@" >/dev/null 2>&1 ;;
	pacman)
		# 先尝试不刷新数据库; 失败 (数据库过旧导致 404) 时整体升级后再装, 避免 -Sy 部分升级
		pacman -S --noconfirm --needed "$@" >/dev/null 2>&1 || pacman -Syu --noconfirm --needed "$@" >/dev/null 2>&1
		;;
	zypper) zypper -n install -y --no-recommends "$@" >/dev/null 2>&1 ;;
	xbps) xbps-install -y "$@" >/dev/null 2>&1 ;;
	emerge) emerge --ask=n --quiet --noreplace "$@" >/dev/null 2>&1 ;;
	*) return 1 ;;
	esac
}

# 命令 -> 各包管理器下的包名; 多个候选用空格分隔, 依次尝试
pkg_name_of() {
	local cmd=$1
	case "$cmd:$PKG" in
	ss:dnf | ss:yum) echo iproute ;;
	ss:apk) echo "iproute2-ss iproute2" ;;
	ss:emerge) echo sys-apps/iproute2 ;;
	ss:*) echo iproute2 ;;
	qrencode:apk) echo "libqrencode-tools libqrencode" ;; # Alpine <=3.18 的 qrencode 在 libqrencode 包内
	qrencode:emerge) echo media-gfx/qrencode ;;
	crontab:apt) echo cron ;;
	crontab:apk) echo cronie ;;
	crontab:emerge) echo sys-process/cronie ;;
	crontab:*) echo cronie ;;
	update-ca-certificates:* | ca-certificates:*) echo ca-certificates ;;
	base64:* | od:* | head:*) echo coreutils ;;
	unzip:emerge) echo app-arch/unzip ;;
	*) echo "$cmd" ;;
	esac
}

# RHEL 系启用 EPEL (qrencode 在 EL9/EL10 仅 EPEL 提供; EL7/EL8 在 base/AppStream)
enable_epel() {
	case "$PKG" in dnf | yum) ;; *) return 1 ;; esac
	local major=${OS_VER%%.*}
	case "$OS_ID" in
	ol) pkg_install "oracle-epel-release-el${major}" ;;
	amzn) [ "$major" = 2 ] && has amazon-linux-extras && amazon-linux-extras install -y epel >/dev/null 2>&1 ;;
	rhel) pkg_install "https://dl.fedoraproject.org/pub/epel/epel-release-latest-${major}.noarch.rpm" ;;
	fedora | openeuler) return 1 ;;
	*) pkg_install epel-release ;;
	esac
}

ensure_cmds() {
	local c n missing=() pkgs=() cands
	for c in "$@"; do has "$c" || missing+=("$c"); done
	[ ${#missing[@]} -eq 0 ] && return 0
	[ -n "$PKG" ] || {
		warn "未识别的包管理器, 请手动安装: ${missing[*]}"
		return 1
	}
	for c in "${missing[@]}"; do
		cands=$(pkg_name_of "$c")
		pkgs+=("${cands%% *}")
	done
	info "安装依赖: ${pkgs[*]}"
	pkg_update
	pkg_install "${pkgs[@]}" || true
	# 批量安装失败或仍缺失时: 逐个尝试候选包名 (一个包名不存在不影响其他)
	for c in "${missing[@]}"; do
		has "$c" && continue
		for n in $(pkg_name_of "$c"); do
			pkg_install "$n" && has "$c" && break
		done
		if ! has "$c" && [ "$c" = qrencode ] && enable_epel; then
			pkg_install qrencode
		fi
	done
	for c in "${missing[@]}"; do has "$c" || return 1; done
	return 0
}

# EOL 发行版的软件源修正 (CentOS 7 -> vault, Debian 10 -> archive)
fix_eol_repos() {
	if [ "$OS_ID" = centos ] && [ "${OS_VER%%.*}" = 7 ] && ls /etc/yum.repos.d/CentOS-*.repo >/dev/null 2>&1 &&
		grep -q '^mirrorlist=http://mirrorlist.centos.org' /etc/yum.repos.d/CentOS-*.repo; then
		warn "CentOS 7 已停止维护, 软件源切换到 vault.centos.org"
		sed -i -e 's|^mirrorlist=|#mirrorlist=|' \
			-e 's|^#[[:space:]]*baseurl=http://mirror.centos.org/centos/\$releasever|baseurl=https://vault.centos.org/7.9.2009|' \
			-e 's|^#[[:space:]]*baseurl=http://mirror.centos.org/altarch/\$releasever|baseurl=https://vault.centos.org/altarch/7.9.2009|' \
			/etc/yum.repos.d/CentOS-*.repo
		yum clean all >/dev/null 2>&1
	fi
	if [ "$OS_ID" = debian ] && [ "${OS_VER%%.*}" = 10 ] && grep -qsE '^deb.*[[:space:]]buster' /etc/apt/sources.list &&
		! grep -qs 'archive.debian.org' /etc/apt/sources.list; then
		warn "Debian 10 已停止维护, 软件源切换到 archive.debian.org"
		sed -i -E \
			-e 's#^(deb(-src)?[[:space:]]+)https?://[^[:space:]]+/debian-security/?[[:space:]]+buster/updates#\1[check-valid-until=no] http://archive.debian.org/debian-security buster/updates#' \
			-e 's#^(deb(-src)?[[:space:]]+)https?://[^[:space:]]+/debian/?[[:space:]]+buster#\1[check-valid-until=no] http://archive.debian.org/debian buster#' \
			/etc/apt/sources.list
	fi
}

install_base_deps() {
	fix_eol_repos
	local need=(curl tar openssl base64 od awk sed grep head)
	has ss || has netstat || need+=(ss)
	ensure_cmds "${need[@]}" || true
	if [ ! -s /etc/ssl/certs/ca-certificates.crt ] && [ ! -s /etc/pki/tls/certs/ca-bundle.crt ] && [ ! -s /etc/ssl/ca-bundle.pem ] && [ ! -s /etc/ssl/cert.pem ]; then
		pkg_update
		pkg_install ca-certificates || true
	fi
	local c
	for c in curl tar openssl base64 od awk sed grep head; do
		has "$c" || die "缺少必需命令: $c, 请手动安装后重试"
	done
}

# ---------------------------------------------------------------------------
# 网络: 下载 / 公网 IP
# ---------------------------------------------------------------------------
# http_get URL [输出文件]  (无输出文件时打印到标准输出)
http_get() {
	local url=$1 out=${2:-}
	if has curl; then
		if [ -n "$out" ]; then
			# 不限制总时长 (大文件在慢速线路上可能需要数分钟), 改为: 连续 60 秒低于 1KB/s 才判定失败
			curl -fsSL --retry 2 --connect-timeout 15 --speed-limit 1024 --speed-time 60 -o "$out" "$url"
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

# 最新 release 版本号 (不带 v). 依次尝试: API 直连 -> API 经加速 -> releases/latest 跳转/页面 (直连, 经加速)
_gh_tag_from_page() {
	local out
	out=$(curl -sS -D - --connect-timeout 10 --max-time 25 "$1" 2>/dev/null | tr -d '\r')
	{
		printf '%s\n' "$out" | sed -n 's#^[Ll]ocation:.*/releases/tag/\([^/?#[:space:]]*\).*#\1#p'
		printf '%s\n' "$out" | grep -o '/releases/tag/v\{0,1\}[0-9][^"&?#<>/[:space:]\\]*' | sed 's#.*/##'
	} | head -n1
}

gh_latest_version() {
	local repo=$1 tag="" u
	for u in "https://api.github.com/repos/${repo}/releases/latest" "$(gh_url "https://api.github.com/repos/${repo}/releases/latest")"; do
		tag=$(http_get "$u" 2>/dev/null | sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -n1)
		[ -n "$tag" ] && break
		[ -n "$GH_PROXY" ] || break
	done
	if [ -z "$tag" ]; then
		for u in "https://github.com/${repo}/releases/latest" "$(gh_url "https://github.com/${repo}/releases/latest")"; do
			tag=$(_gh_tag_from_page "$u")
			[ -n "$tag" ] && break
			[ -n "$GH_PROXY" ] || break
		done
	fi
	tag=${tag#v}
	[[ "$tag" =~ ^[0-9]+\.[0-9]+(\.[0-9]+)?$ ]] || tag=""
	printf '%s' "$tag"
}

_ip_from() {
	local fam=$1 url=$2 ip=""
	ip=$(curl -"$fam" -fsS --connect-timeout 4 --max-time 6 "$url" 2>/dev/null)
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
	for u in https://api.ipify.org https://ipv4.icanhazip.com https://api-ipv4.ip.sb/ip https://ipv4.ddnspod.com https://ifconfig.co/ip; do
		SERVER_IPV4=$(_ip_from 4 "$u")
		[ -n "$SERVER_IPV4" ] && break
	done
	for u in https://api64.ipify.org https://ipv6.icanhazip.com https://api-ipv6.ip.sb/ip https://ipv6.ddnspod.com https://ifconfig.co/ip; do
		SERVER_IPV6=$(_ip_from 6 "$u")
		[ -n "$SERVER_IPV6" ] && break
	done
	# 出口经过 Cloudflare WARP 时, 检测到的是 WARP 出口地址, 无法用于入站连接
	SERVER_IPV4_WARP=0 SERVER_IPV6_WARP=0
	if [ -n "$SERVER_IPV4" ] && curl -4 -fsS --max-time 5 https://www.cloudflare.com/cdn-cgi/trace 2>/dev/null | grep -qE '^warp=(on|plus)'; then
		SERVER_IPV4_WARP=1
		warn "IPv4 出口经过 Cloudflare WARP (${SERVER_IPV4}), 该地址不能用于客户端连接"
	fi
	if [ -n "$SERVER_IPV6" ] && curl -6 -fsS --max-time 5 https://www.cloudflare.com/cdn-cgi/trace 2>/dev/null | grep -qE '^warp=(on|plus)'; then
		SERVER_IPV6_WARP=1
		warn "IPv6 出口经过 Cloudflare WARP (${SERVER_IPV6}), 该地址不能用于客户端连接"
	fi
	if [ -z "$SERVER_IPV4" ] && [ -n "$SERVER_IPV6" ] && [ -z "$GH_PROXY" ]; then
		warn "检测到纯 IPv6 服务器: GitHub 不支持 IPv6, 下载内核可能失败"
		warn "可设置支持 IPv6 的加速前缀后重试, 例如: GH_PROXY=https://ghproxy.net/ onebox, 或先配置 WARP / NAT64"
	fi
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
readonly STATE_KEYS="PROTOCOLS SERVER_ADDR SERVER_IPV4 SERVER_IPV6 SERVER_IPV4_WARP SERVER_IPV6_WARP NODE_NAME LISTEN_ADDR
UUID PASSWORD SS_METHOD SS_PASSWORD
REALITY_PRIVATE_KEY REALITY_PUBLIC_KEY REALITY_SHORT_ID REALITY_SNI REALITY_DEST
REALITY_SITE_ENABLED REALITY_SITE_DOMAIN REALITY_SITE_PORT REALITY_SITE_TITLE REALITY_SITE_HTTPS
WS_PATH VMESS_PATH XHTTP_PATH GRPC_SERVICE
HY2_OBFS HY2_OBFS_PASSWORD HY2_HOP
SHADOWTLS_SNI SHADOWTLS_DEST SHADOWTLS_PASSWORD SHADOWTLS_SS_PASSWORD
TLS_MODE DOMAIN TLS_SNI CERT_FILE KEY_FILE ACME_METHOD
SB_VERSION XR_VERSION BLOCK_PRIVATE BLOCK_BT REALITY_GUARD_PORT VMESS_TLS CLASH_SECRET CERT_PINNED OWN_IP_CIDRS INSTALLED_AT"

# 状态变量通过 STATE_KEYS 间接读写, shellcheck 无法追踪
# shellcheck disable=SC2034
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
	mkdir -p "$ONEBOX_DIR" && chmod 700 "$ONEBOX_DIR" || return 1
	local tmp k p v failed=0
	tmp=$(mktemp "${STATE_FILE}.tmp.XXXXXX") || return 1
	{
		printf '%s\n' '# Sing-Xray-Onebox 状态文件 (由脚本自动生成, 请勿手动修改)' || failed=1
		for k in $STATE_KEYS; do printf '%s=%q\n' "$k" "${!k-}" || failed=1; done
		for p in $ALL_PROTOCOLS; do
			for k in PORT CORE; do
				v="${k}_${p//-/_}"
				if [ -n "${!v-}" ]; then printf '%s=%q\n' "$v" "${!v}" || failed=1; fi
			done
		done
	} >"$tmp" || failed=1
	if [ "$failed" = 0 ] && [ -s "$tmp" ] && chmod 600 "$tmp" && mv -f "$tmp" "$STATE_FILE"; then return 0; fi
	rm -f "$tmp"
	err "无法完整保存状态文件: ${STATE_FILE}"
	return 1
}

load_state() {
	[ -f "$STATE_FILE" ] || return 1
	bash -n "$STATE_FILE" 2>/dev/null || { err "状态文件语法无效: ${STATE_FILE}"; return 1; }
	reset_state
	# shellcheck disable=SC1090
	. "$STATE_FILE" || { err "状态文件加载失败: ${STATE_FILE}"; return 1; }
	[ -n "$PROTOCOLS" ] || { err "状态文件缺少协议列表: ${STATE_FILE}"; return 1; }
	# 旧版本状态文件没有 VMESS_TLS: 按当时的规则推导并固定下来
	if proto_enabled vmess-ws && [ -z "${VMESS_TLS:-}" ]; then
		if vmess_tls_default; then VMESS_TLS=1; else VMESS_TLS=0; fi
	fi
	return 0
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
	hysteria2) echo "QUIC/UDP, 暴力加速, 弱网首选 (Xray 承载为实验性)" ;;
	tuic) echo "QUIC/UDP, 低延迟" ;;
	anytls) echo "TLS 流量填充, 抗 TLS-in-TLS 识别" ;;
	shadowtls) echo "借用大站 TLS 握手, 包裹 SS-2022" ;;
	esac
}

# 可承载该协议的服务端内核 (首个为默认)
proto_cores() {
	case "$1" in
	vless-xhttp) echo "xray" ;;
	hysteria2) echo "singbox xray" ;;
	tuic | anytls | shadowtls) echo "singbox" ;;
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

# vmess-ws 是否启用 TLS: 安装 / 添加时按证书方式决定并保存 (VMESS_TLS), 之后更换证书不会悄悄改变
# 默认: 拥有正式证书 (ACME / 自有证书) 时启用 TLS, 否则为明文 WS (便于套 CDN)
vmess_tls_default() { [ "$TLS_MODE" = acme ] || [ "$TLS_MODE" = custom ]; }
vmess_tls_enabled() {
	case "${VMESS_TLS:-}" in
	1) return 0 ;;
	0) return 1 ;;
	*) vmess_tls_default ;;
	esac
}

# 客户端支持情况: proto_client_ok 协议 link|mihomo|singbox|xray
proto_client_ok() {
	local p=$1 c=$2
	case "$c" in
	link) [ "$p" != shadowtls ] ;;
	mihomo) return 0 ;;
	singbox) [ "$p" != vless-xhttp ] ;;
	xray) case "$p" in tuic | anytls | shadowtls) return 1 ;; *) return 0 ;; esac ;;
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

# 客户端是否需要固定证书指纹 (自签证书, 或不受公共 CA 信任的自有证书如 Cloudflare 源证书)
tls_insecure() { [ "$TLS_MODE" = self ] || [ "${CERT_PINNED:-0}" = 1 ]; }

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

# 下载/解压用的临时目录: 放在安装目录旁 (部分 VPS 的 /tmp 为 noexec 或很小的 tmpfs)
core_tmpdir() { mkdir -p "${BIN_DIR%/*}" && mktemp -d "${BIN_DIR%/*}/.dl.XXXXXX"; }

sb_installed_version() { [ -x "$SB_BIN" ] && "$SB_BIN" version 2>/dev/null | awk 'NR==1{print $3}'; }
xr_installed_version() { [ -x "$XR_BIN" ] && "$XR_BIN" version 2>/dev/null | awk 'NR==1{print $2}'; }

# sing-box 候选安装包 (按优先级). 依据 v1.14.2 / v1.12.25 实际 release 资产:
#  - 1.13+: amd64/arm64/386/armv7/riscv64/loong64 有 -musl (CGO+musl 静态, glibc/musl 通用) 与 -glibc (动态);
#    无后缀的 amd64/arm64 包是 purego 构建 (动态链接 glibc, Alpine 上 "not found"), 其余架构无后缀包为纯静态.
#  - mips/mips64 只有 -softfloat; mipsle 为 -softfloat-musl / (hardfloat) / -softfloat; 不存在 amd64v3.
sb_asset_candidates() {
	local p="sing-box-${1}-linux-"
	case "$SB_ARCH" in
	amd64 | arm64) printf '%s\n' "${p}${SB_ARCH}-musl.tar.gz" "${p}${SB_ARCH}.tar.gz" "${p}${SB_ARCH}-glibc.tar.gz" ;;
	386) printf '%s\n' "${p}386.tar.gz" "${p}386-musl.tar.gz" "${p}386-softfloat.tar.gz" ;;
	armv7 | riscv64 | loong64) printf '%s\n' "${p}${SB_ARCH}.tar.gz" "${p}${SB_ARCH}-musl.tar.gz" ;;
	mipsle) printf '%s\n' "${p}mipsle-softfloat.tar.gz" "${p}mipsle-softfloat-musl.tar.gz" "${p}mipsle.tar.gz" ;;
	mips64le) printf '%s\n' "${p}mips64le.tar.gz" "${p}mips64le-softfloat.tar.gz" ;;
	mips | mips64) printf '%s\n' "${p}${SB_ARCH}-softfloat.tar.gz" ;;
	armv5 | armv6 | s390x | ppc64le) printf '%s\n' "${p}${SB_ARCH}.tar.gz" ;;
	esac
	return 0
}

# Xray .dgst: 由 `openssl dgst -sha256 FILE | sed 's/([^)]*)//g'` 生成 -> "SHA2-256= <hex>" (OpenSSL 3), 旧版为 "SHA256= <hex>"
xr_dgst_sha256() { sed -n 's/^SHA2\{0,1\}-\{0,1\}256= *\([0-9a-fA-F]\{64\}\).*/\1/p' "$1" | head -n1; }

install_singbox() {
	local ver=${1:-} tmp asset url bin="" got=""
	if [ -n "$LOCAL_SB_BIN" ]; then
		[ -x "$LOCAL_SB_BIN" ] || die "本地 sing-box 文件不可执行: $LOCAL_SB_BIN"
		info "使用本地 sing-box: $LOCAL_SB_BIN"
		_install_bin "$LOCAL_SB_BIN" "$SB_BIN" || die "安装 sing-box 失败"
		SB_VERSION=$(sb_installed_version)
		return 0
	fi
	[ -n "$SB_ARCH" ] || {
		err "sing-box 未提供 ${ARCH_RAW} 架构的构建"
		return 1
	}
	if [ -z "$ver" ]; then
		info "查询 sing-box 最新版本..."
		ver=$(gh_latest_version SagerNet/sing-box)
		[ -n "$ver" ] || {
			warn "无法获取 sing-box 最新版本, 使用内置版本 ${FALLBACK_SB_VERSION}"
			ver=$FALLBACK_SB_VERSION
		}
	fi
	tmp=$(core_tmpdir) || {
		err "无法创建临时目录"
		return 1
	}
	for asset in $(sb_asset_candidates "$ver"); do
		url=$(gh_url "https://github.com/SagerNet/sing-box/releases/download/v${ver}/${asset}")
		info "下载 ${asset}"
		rm -rf "${tmp:?}"/*
		http_get "$url" "$tmp/pkg.tar.gz" || continue
		tar -xzf "$tmp/pkg.tar.gz" -C "$tmp" 2>/dev/null || continue
		rm -f "$tmp/pkg.tar.gz"
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
	local ver=${1:-} tmp asset url sum want b bin=""
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
	[ -n "$ver" ] || ver=${XR_VERSION_WANT:-$TESTED_XR_VERSION}
	if [ "$ver" = latest ]; then
		info "查询 Xray 最新版本..."
		ver=$(gh_latest_version XTLS/Xray-core)
		[ -n "$ver" ] || {
			warn "无法获取 Xray 最新版本, 使用经过测试的版本 ${TESTED_XR_VERSION}"
			ver=$TESTED_XR_VERSION
		}
	fi
	ver=${ver#v}
	asset="Xray-linux-${XR_ARCH}.zip"
	url=$(gh_url "https://github.com/XTLS/Xray-core/releases/download/v${ver}/${asset}")
	tmp=$(core_tmpdir) || {
		err "无法创建临时目录"
		return 1
	}
	info "下载 ${asset} (v${ver})"
	if ! http_get "$url" "$tmp/xray.zip"; then
		rm -rf "$tmp"
		err "Xray ${ver} 下载失败 (架构: ${XR_ARCH})"
		[ -z "$GH_PROXY" ] && warn "若服务器访问 GitHub 困难, 可设置加速前缀后重试, 例如: GH_PROXY=https://ghfast.top/ onebox"
		return 1
	fi
	# 校验 SHA256 (官方 .dgst: "SHA2-256= <hex>")
	if has sha256sum && http_get "${url}.dgst" "$tmp/xray.dgst" 2>/dev/null; then
		want=$(xr_dgst_sha256 "$tmp/xray.dgst")
		sum=$(sha256sum "$tmp/xray.zip" | awk '{print $1}')
		if [ -n "$want" ] && [ "$want" != "$sum" ]; then
			rm -rf "$tmp"
			err "Xray 安装包 SHA256 校验失败"
			return 1
		fi
	fi
	# 只解压可执行文件 (geoip.dat/geosite.dat 约 30MB, 服务端配置未使用)
	unzip -qo "$tmp/xray.zip" 'xray*' -d "$tmp/x" >/dev/null 2>&1
	# mips32/mips32le 包内同时有 xray (hardfloat) 与 xray_softfloat, 无 FPU 的设备需用后者
	for b in $(case "$XR_ARCH" in mips32*) echo "xray_softfloat xray" ;; *) echo xray ;; esac); do
		[ -f "$tmp/x/$b" ] || continue
		chmod +x "$tmp/x/$b"
		"$tmp/x/$b" version >/dev/null 2>&1 && bin="$tmp/x/$b" && break
	done
	if [ -z "$bin" ]; then
		rm -rf "$tmp"
		err "Xray 解压失败或无法在本机运行 (架构: ${XR_ARCH})"
		return 1
	fi
	_install_bin "$bin" "$XR_BIN" || {
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

# 内核的运行参数: sing-box 输出到文件时需 --disable-color, 否则日志里全是 ANSI 转义码
svc_args() {
	case "$1" in
	singbox) echo "run --disable-color -c $(svc_conf singbox)" ;;
	xray) echo "run -c $(svc_conf xray)" ;;
	esac
}

# 文件描述符上限
nofile_limit() {
	# 取可设置的最大值 (root 可提高硬上限; 容器内受限时逐级降低)
	local n
	for n in 1048576 524288 262144 65535; do
		(ulimit -n "$n") 2>/dev/null && {
			printf '%s' "$n"
			return 0
		}
	done
	ulimit -Hn
}

# 日志超过 10MB 时清空 (OpenRC / 无 init 模式下日志写入文件, 没有轮转)
trim_log() { [ -f "$1" ] && [ "$(wc -c <"$1" 2>/dev/null || echo 0)" -gt 10485760 ] && : >"$1"; return 0; }

svc_write() {
	local core=$1 name bin args extra="" site_order=""
	name=$(svc_name "$core") bin=$(svc_bin "$core") args=$(svc_args "$core")
	# Xray 配置错误时退出码为 23, 不必无限重启 (与官方 Xray-install 一致)
	[ "$core" = xray ] && extra="RestartPreventExitStatus=23"
	site_enabled && site_order="Wants=onebox-site.service
After=onebox-site.service"
	case "$INIT" in
	systemd)
		cat >"/etc/systemd/system/${name}.service" <<EOF || return 1
[Unit]
Description=Sing-Xray-Onebox $(core_title "$core") Service
Documentation=https://github.com/${SCRIPT_REPO}
After=network-online.target nss-lookup.target
Wants=network-online.target
${site_order}

[Service]
Type=simple
ExecStart=${bin} ${args}
Restart=on-failure
RestartSec=5s
${extra}
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF
		systemctl daemon-reload >/dev/null 2>&1 || return 1
		;;
	openrc)
		cat >"${INITD_DIR}/${name}" <<EOF || return 1
#!/sbin/openrc-run

name="${name}"
description="Sing-Xray-Onebox $(core_title "$core") Service"
supervisor="supervise-daemon"
command="${bin}"
command_args="${args}"
output_log="${LOG_DIR}/${core}.log"
error_log="${LOG_DIR}/${core}.log"
respawn_delay=5
respawn_max=10
respawn_period=120
rc_ulimit="-n $(nofile_limit)"

depend() {
	want net
	after net firewall dns
}

start_pre() {
	checkpath -d -m 0700 "${LOG_DIR}"
	# 日志超过 10MB 时清空
	if [ -f "${LOG_DIR}/${core}.log" ] && [ "\$(wc -c <"${LOG_DIR}/${core}.log")" -gt 10485760 ]; then
		: >"${LOG_DIR}/${core}.log"
	fi
	return 0
}
EOF
		chmod 755 "${INITD_DIR}/${name}" || return 1
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
	systemd) systemctl disable "$name" >/dev/null 2>&1 || return 1 ;;
	openrc)
		if rc-update show default 2>/dev/null | grep -qw "$name"; then
			rc-update del "$name" default >/dev/null 2>&1 || return 1
		fi
		;;
	esac
	return 0
}

_none_pidfile() { echo "${RUN_DIR}/$(svc_name "$1").pid"; }

_none_running() {
	local pf pid
	pf=$(_none_pidfile "$1")
	[ -f "$pf" ] || return 1
	pid=$(cat "$pf" 2>/dev/null)
	[ -n "$pid" ] && kill -0 "$pid" 2>/dev/null || return 1
	# 防止 pid 被其他进程复用: 进程命令行里应包含内核路径
	# (不用 /proc/PID/exe: 更新内核后会变成 "... (deleted)", 符号链接时也对不上)
	[ -r "/proc/$pid/cmdline" ] || return 0
	tr '\0' ' ' <"/proc/$pid/cmdline" 2>/dev/null | grep -qF "$(svc_bin "$1")"
}

_none_start() {
	local core=$1 log
	_none_running "$core" && return 0
	log="${LOG_DIR}/${core}.log"
	(umask 077 && mkdir -p "$RUN_DIR" "$LOG_DIR" && : >>"$log")
	trim_log "$log"
	# setsid: 脱离当前会话, 关闭 SSH 终端不会影响. svc_args 需要按空格拆分
	# shellcheck disable=SC2046
	(
		ulimit -n "$(nofile_limit)" 2>/dev/null
		if has setsid; then
			exec setsid "$(svc_bin "$core")" $(svc_args "$core") >>"$log" 2>&1 </dev/null
		else
			exec nohup "$(svc_bin "$core")" $(svc_args "$core") >>"$log" 2>&1 </dev/null
		fi
	) &
	echo $! >"$(_none_pidfile "$core")"
}

_none_stop() {
	local core=$1 pf pid i
	pf=$(_none_pidfile "$core")
	if _none_running "$core"; then
		pid=$(cat "$pf")
		kill "$pid" 2>/dev/null
		# 等待退出 (最多 5 秒), 否则紧接着的 start 会因端口仍被占用而失败
		for i in 1 2 3 4 5; do
			kill -0 "$pid" 2>/dev/null || break
			sleep 1
		done
		kill -0 "$pid" 2>/dev/null && kill -9 "$pid" 2>/dev/null
	fi
	rm -f "$pf"
}

# 无 init 系统时, 借助 crontab @reboot 实现开机自启
_none_autostart_add() {
	if ! has crontab; then
		warn "未检测到 init 系统与 crontab, 服务不会开机自启; 重启后请执行: onebox net-apply && onebox start"
		return 0
	fi
	crontab -l 2>/dev/null | grep -q "${CMD_PATH} start" && return 0
	(
		crontab -l 2>/dev/null
		echo "@reboot ${CMD_PATH} net-apply >/dev/null 2>&1; ${CMD_PATH} start >/dev/null 2>&1"
	) | crontab - 2>/dev/null || return 1
	return 0
}

_none_autostart_del() {
	has crontab || return 0
	local current
	current=$(crontab -l 2>/dev/null) || return 0
	printf '%s\n' "$current" | grep -qF "${CMD_PATH} start" || return 0
	printf '%s\n' "$current" | grep -vF "${CMD_PATH} start" | crontab - 2>/dev/null
}

svc_start() {
	local core=$1 name
	name=$(svc_name "$core")
	case "$INIT" in
	systemd) systemctl start "$name" >/dev/null 2>&1 ;;
	openrc) rc-service "$name" start >/dev/null 2>&1 ;;
	none) _none_start "$core" ;;
	esac
}

svc_stop() {
	local core=$1 name
	name=$(svc_name "$core")
	case "$INIT" in
	systemd) systemctl stop "$name" >/dev/null 2>&1 || return 1 ;;
	openrc) rc-service "$name" stop >/dev/null 2>&1 || return 1 ;;
	none) _none_stop "$core" || return 1 ;;
	esac
	return 0
}

svc_restart() {
	local core=$1
	case "$INIT" in
	systemd) systemctl restart "$(svc_name "$core")" >/dev/null 2>&1 ;;
	openrc) rc-service "$(svc_name "$core")" restart >/dev/null 2>&1 ;;
	none)
		svc_stop "$core" || return 1
		svc_start "$core"
		;;
	esac
}

svc_active() {
	local core=$1 name
	name=$(svc_name "$core")
	case "$INIT" in
	systemd) systemctl is-active --quiet "$name" ;;
	openrc)
		# supervise-daemon 在子进程反复崩溃时仍报告 started, 需检查其记录的子进程
		rc-service "$name" status >/dev/null 2>&1 || return 1
		local cp
		cp=$(cat "/run/openrc/options/${name}/child_pid" 2>/dev/null)
		if [ -n "$cp" ]; then
			kill -0 "$cp" 2>/dev/null
		else
			_proc_running_bin "$(svc_bin "$core")"
		fi
		;;
	none) _none_running "$core" ;;
	esac
}

# 是否有以该可执行文件运行的进程
_proc_running_bin() {
	local p a
	for p in /proc/[0-9]*; do
		a=$(tr '\0' ' ' <"$p/cmdline" 2>/dev/null) || continue
		case "$a" in "$1 "*) return 0 ;; esac
	done
	return 1
}

svc_exists() {
	local name
	name=$(svc_name "$1")
	case "$INIT" in
	systemd) [ -f "/etc/systemd/system/${name}.service" ] ;;
	openrc) [ -f "${INITD_DIR}/${name}" ] ;;
	none) _none_running "$1" || { [ -x "$(svc_bin "$1")" ] && [ -f "$(svc_conf "$1")" ]; } ;;
	esac
}

svc_remove() {
	local core=$1 name
	name=$(svc_name "$core")
	# 未安装的服务无需 stop/disable (systemd 对不存在的 unit 返回失败)。
	svc_exists "$core" || return 0
	svc_stop "$core" || return 1
	svc_disable "$core" || return 1
	case "$INIT" in
	systemd)
		rm -f "/etc/systemd/system/${name}.service" || return 1
		systemctl daemon-reload >/dev/null 2>&1 || return 1
		systemctl reset-failed "$name" >/dev/null 2>&1
		;;
	openrc) rm -f "${INITD_DIR}/${name}" || return 1 ;;
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
			svc_write "$core" || return 1
			svc_enable "$core" || return 1
		elif svc_exists "$core"; then
			svc_remove "$core" || return 1
		fi
	done
	# 先全部停止再启动: 端口在两个内核之间迁移时 (如 REALITY 从 Xray 改到 sing-box) 避免冲突
	for core in singbox xray; do
		core_used "$core" || continue
		svc_stop "$core" || return 1
	done
	# Release the old core's 443 before nginx takes it; nginx releases its own
	# 443 before starting a REALITY core that will own the public entrance.
	site_apply_service || return 1
	for core in singbox xray; do
		core_used "$core" || continue
		svc_start "$core" || ok=1
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

# iptables 的 INPUT 链是否会拦截新端口 (默认策略 DROP, 或存在无条件 REJECT/DROP, 如甲骨文云镜像)
_fw_iptables_blocking() {
	has "$1" || return 1
	# 宁可多判: 多加几条 ACCEPT 无害, 漏判则端口不通
	"$1" -S INPUT 2>/dev/null | grep -qE '^-P INPUT (DROP|REJECT)|-j (REJECT|DROP)'
}

# _ipt_rule 命令 check|add|del 表 链 匹配条件... -- 目标...
# 带 onebox 注释; 内核缺少 xt_comment 时退回无注释形式. check/del 两种形式都尝试,
# 否则无注释规则会在每次运行时重复添加且永远删不掉. (-m comment 必须位于 -j 之前)
_ipt_rule() {
	local t=$1 act=$2 table=$3 chain=$4 m=() j=()
	shift 4
	while [ $# -gt 0 ] && [ "$1" != -- ]; do m+=("$1"); shift; done
	shift
	j=("$@")
	case "$act" in
	check)
		"$t" -t "$table" -C "$chain" "${m[@]}" -m comment --comment onebox "${j[@]}" 2>/dev/null ||
			"$t" -t "$table" -C "$chain" "${m[@]}" "${j[@]}" 2>/dev/null
		;;
	add)
		# IPT_PLAIN=1 表示因缺少 xt_comment 而添加了无注释规则
		IPT_PLAIN=0
		"$t" -t "$table" -I "$chain" "${m[@]}" -m comment --comment onebox "${j[@]}" 2>/dev/null && return 0
		IPT_PLAIN=1
		"$t" -t "$table" -I "$chain" "${m[@]}" "${j[@]}" 2>/dev/null
		;;
	del | delc | delp)
		# del: 两种形式都删; delc: 仅删带 onebox 注释的; delp: 仅删无注释的 (仅用于本脚本在缺少 xt_comment 时添加的规则)
		local status
		if [ "$act" != delp ]; then
			while :; do
				"$t" -t "$table" -D "$chain" "${m[@]}" -m comment --comment onebox "${j[@]}" 2>/dev/null
				status=$?
				[ "$status" = 0 ] || break
			done
			# 无匹配规则 / 缺少 comment 模块可继续; 权限或锁错误必须保留台账并上报。
			[ "$status" -le 2 ] || return 1
			"$t" -t "$table" -C "$chain" "${m[@]}" -m comment --comment onebox "${j[@]}" 2>/dev/null && return 1
		fi
		if [ "$act" != delc ]; then
			while :; do
				"$t" -t "$table" -D "$chain" "${m[@]}" "${j[@]}" 2>/dev/null
				status=$?
				[ "$status" = 0 ] || break
			done
			[ "$status" -le 1 ] || return 1
			"$t" -t "$table" -C "$chain" "${m[@]}" "${j[@]}" 2>/dev/null && return 1
		fi
		return 0
		;;
	esac
}

# 原生 nftables 规则集中会拦截入站的 input 链 (policy drop 或含无条件 drop/reject): 输出 "family table chain"
# 跳过 iptables-nft 兼容表 (链名 INPUT, 由 iptables 分支处理) 与 firewalld 自己的表
_fw_nft_block_chains() {
	has nft || return 0
	local rules
	rules=$(nft list ruleset 2>/dev/null) || return 1
	printf '%s\n' "$rules" | awk '
		$1 == "table" { fam = $2; tbl = $3; next }
		$1 == "chain" { ch = $2; hook = 0; blk = 0; next }
		/hook input/ { hook = 1; if (/policy drop/) blk = 1; next }
		hook && /^[[:space:]]*(counter( packets [0-9]+ bytes [0-9]+)? )?(drop|reject)/ { blk = 1; next }
		$1 == "}" && ch != "" {
			if (hook && blk && ch != "INPUT" && tbl != "firewalld") print fam, tbl, ch
			ch = ""; hook = 0; blk = 0
		}'
}

# _fw_nft open|close 端口或范围(a-b) tcp|udp
_fw_nft() {
	local act=$1 port=$2 proto=$3 fam tbl ch h rule rc=0 chains listing
	rule="$proto dport $port accept comment \"onebox\""
	chains=$(_fw_nft_block_chains) || return 1
	while read -r fam tbl ch; do
		[ -n "$ch" ] || continue
		if [ "$act" = open ]; then
			nft list chain "$fam" "$tbl" "$ch" 2>/dev/null | grep -qF "$rule" && continue
			nft insert rule "$fam" "$tbl" "$ch" "$proto" dport "$port" accept comment '"onebox"' 2>/dev/null || rc=1
		else
			listing=$(nft -a list chain "$fam" "$tbl" "$ch" 2>/dev/null) || { rc=1; continue; }
			for h in $(printf '%s\n' "$listing" | grep -F "$rule" | sed -n 's/.*# handle \([0-9]*\).*/\1/p'); do
				nft delete rule "$fam" "$tbl" "$ch" handle "$h" 2>/dev/null || rc=1
			done
		fi
	done <<<"$chains"
	return "$rc"
}

# 防火墙台账: 记录本脚本实际添加的放行规则 ("后端 端口/协议"), 关闭时只删除台账中的规则,
# 不会误删用户自己事先为同一端口添加的规则
_fw_ledger() { printf '%s' "$ONEBOX_DIR/firewall.list"; }
_fw_ledger_has() { grep -qxF "$1" "$(_fw_ledger)" 2>/dev/null; }
_fw_ledger_add() {
	_fw_ledger_has "$1" && return 0
	# 首次写入台账前, 先把旧版本 (无台账) 放行的端口迁移进来
	[ -f "$(_fw_ledger)" ] || [ ! -f "$STATE_FILE" ] || (load_state && _fw_ledger_migrate) >/dev/null 2>&1
	mkdir -p "$ONEBOX_DIR" && printf '%s\n' "$1" >>"$(_fw_ledger)"
}

# 防火墙当前状态快照 (用于判断某次放行是否真的新增了规则)
_fw_snapshot() {
	cat "$(_fw_ledger)" 2>/dev/null
	has iptables && iptables -S INPUT 2>/dev/null
	has ip6tables && ip6tables -S INPUT 2>/dev/null
	has nft && nft list ruleset 2>/dev/null | grep -F 'comment "onebox"'
	return 0
}
_fw_ledger_del() {
	local f
	f=$(_fw_ledger)
	[ -f "$f" ] || return 0
	grep -vxF "$1" "$f" >"$f.tmp" 2>/dev/null
	mv -f "$f.tmp" "$f"
}

# fw_rule open|close 端口或范围(a-b) tcp|udp
fw_rule() {
	local act=$1 port=$2 proto=$3 ipt_port=${2/-/:} t key="${2}/${3}" rc=0
	# ufw / firewalld 自己管理 INPUT, 此时不再直接改 iptables (否则规则重复, 且 ufw 下 INPUT 策略恒为 DROP)
	if _fw_ufw_active; then
		if [ "$act" = open ]; then
			if _fw_ledger_has "ufw $key"; then
				# 已记入台账: 重复执行 ufw allow 是幂等的 (规则被手动删除时可恢复)
				ufw allow "${ipt_port}/${proto}" comment onebox >/dev/null 2>&1 || ufw allow "${ipt_port}/${proto}" >/dev/null 2>&1
				return $?
			fi
			# 用户已自行放行该端口: 不接管
			# (仅无来源 / 网卡限制的入站 ALLOW 规则才算)
			LC_ALL=C ufw status 2>/dev/null | grep -vE ' on |OUT|FWD' |
				grep -qE "^${ipt_port}(/${proto})?( \(v6\))?[[:space:]]+ALLOW( IN)?[[:space:]]+Anywhere" && return 0
			ufw allow "${ipt_port}/${proto}" comment onebox >/dev/null 2>&1 || ufw allow "${ipt_port}/${proto}" >/dev/null 2>&1 || return 1
			_fw_ledger_add "ufw $key" || return 1
		elif _fw_ledger_has "ufw $key"; then
			ufw delete allow "${ipt_port}/${proto}" >/dev/null 2>&1 || return 1
			_fw_ledger_del "ufw $key" || return 1
		fi
		return 0
	fi
	if _fw_firewalld_active; then
		# 运行时 + 永久各写一次, 不做 --reload: 每次 reload 要数秒, 且 iptables 后端 (CentOS 7) 的 reload 会清掉端口跳跃的 NAT 规则
		# 默认路由网卡若被绑定到非默认 zone, 端口要开在那个 zone 里
		local z=() zone="" dev
		dev=$(ip route show default 2>/dev/null | awk '{for (i = 1; i < NF; i++) if ($i == "dev") {print $(i + 1); exit}}')
		[ -n "$dev" ] || dev=$(ip -6 route show default 2>/dev/null | awk '{for (i = 1; i < NF; i++) if ($i == "dev") {print $(i + 1); exit}}')
		if [ -n "$dev" ]; then
			# 未绑定 zone 时命令会输出 "no zone" 并失败, 应使用默认 zone。
			zone=$(firewall-cmd --get-zone-of-interface="$dev" 2>/dev/null) || zone=""
		fi
		[ -n "$zone" ] && z=(--zone="$zone")
		if [ "$act" = open ]; then
			if ! _fw_ledger_has "firewalld $key"; then
				if firewall-cmd "${z[@]}" --permanent --query-port="${port}/${proto}" >/dev/null 2>&1; then
					firewall-cmd "${z[@]}" --add-port="${port}/${proto}" >/dev/null 2>&1
					return $?
				fi
			fi
			firewall-cmd "${z[@]}" --add-port="${port}/${proto}" >/dev/null 2>&1 || return 1
			# runtime 已修改便立即记录, permanent 失败时回滚仍能关闭本次新增端口。
			_fw_ledger_add "firewalld $key" || return 1
			firewall-cmd "${z[@]}" --permanent --add-port="${port}/${proto}" >/dev/null 2>&1 || return 1
		elif _fw_ledger_has "firewalld $key"; then
			firewall-cmd "${z[@]}" --remove-port="${port}/${proto}" >/dev/null 2>&1 || return 1
			firewall-cmd "${z[@]}" --permanent --remove-port="${port}/${proto}" >/dev/null 2>&1 || return 1
			_fw_ledger_del "firewalld $key" || return 1
		fi
		return 0
	fi
	for t in iptables ip6tables; do
		has "$t" || continue
		[ "$t" = ip6tables ] && ! host_has_ipv6 && continue
		if [ "$act" = open ]; then
			_fw_iptables_blocking "$t" || continue
			_ipt_rule "$t" check filter INPUT -p "$proto" --dport "$ipt_port" -- -j ACCEPT && continue
			# 带注释的规则可凭注释识别; 仅无注释的回退形式需要记入台账
			if _ipt_rule "$t" add filter INPUT -p "$proto" --dport "$ipt_port" -- -j ACCEPT; then
				if [ "$IPT_PLAIN" = 1 ]; then _fw_ledger_add "$t $key" || rc=1; fi
			else
				rc=1
			fi
		else
			_ipt_rule "$t" delc filter INPUT -p "$proto" --dport "$ipt_port" -- -j ACCEPT || rc=1
			if _fw_ledger_has "$t $key"; then
				if _ipt_rule "$t" delp filter INPUT -p "$proto" --dport "$ipt_port" -- -j ACCEPT; then
					_fw_ledger_del "$t $key" || rc=1
				else
					rc=1
				fi
			fi
		fi
	done
	_fw_nft "$act" "$port" "$proto" || rc=1
	return "$rc"
}

# 旧版本安装 (无台账) 通过 ufw / firewalld 放行的端口: 首次使用时记入台账, 以便之后能正常关闭
_fw_ledger_migrate() {
	[ -f "$(_fw_ledger)" ] && return 0
	[ -f "$STATE_FILE" ] || return 0
	local backend="" p port net
	_fw_ufw_active && backend=ufw
	[ -z "$backend" ] && _fw_firewalld_active && backend=firewalld
	mkdir -p "$ONEBOX_DIR" && : >"$(_fw_ledger)" || return 1
	[ -n "$backend" ] || return 0
	for p in $PROTOCOLS; do
		port=$(pget PORT "$p")
		[ -n "$port" ] || continue
		net=$(proto_net "$p")
		if [ "$net" != udp ]; then _fw_ledger_add "$backend ${port}/tcp" || return 1; fi
		if [ "$net" != tcp ]; then _fw_ledger_add "$backend ${port}/udp" || return 1; fi
	done
	if [ "$TLS_MODE" = acme ] && [ "$ACME_METHOD" = standalone ]; then _fw_ledger_add "$backend 80/tcp" || return 1; fi
	return 0
}

# 放行 / 关闭当前全部协议端口 (幂等; 开机时由 onebox-net 服务重新执行, 不依赖系统的规则保存机制)
fw_apply() {
	local act=${1:-open} p port net rc=0
	_fw_ledger_migrate || return 1
	for p in $PROTOCOLS; do
		port=$(pget PORT "$p")
		[ -n "$port" ] || continue
		net=$(proto_net "$p")
		case "$net" in
		tcp) fw_rule "$act" "$port" tcp || rc=1 ;;
		udp) fw_rule "$act" "$port" udp || rc=1 ;;
		both)
			fw_rule "$act" "$port" tcp || rc=1
			fw_rule "$act" "$port" udp || rc=1
			;;
		esac
	done
	# ACME HTTP-01 (standalone) 申请与续期都需要入站 TCP 80
	if [ "$TLS_MODE" = acme ] && [ "$ACME_METHOD" = standalone ]; then
		fw_rule "$act" 80 tcp || rc=1
	fi
	if site_enabled; then fw_rule "$act" 80 tcp || rc=1; fi
	if site_https_enabled; then fw_rule "$act" 443 tcp || rc=1; fi
	# 端口跳跃: NAT 在 INPUT 之前完成, INPUT 看到的已是 Hysteria2 实际端口, 无需放行整个范围 (云安全组仍需放行)
	return "$rc"
}

# ---------------------------------------------------------------------------
# Hysteria2 端口跳跃 (UDP 端口范围 -> 实际监听端口)
# ---------------------------------------------------------------------------
NET_SERVICE="onebox-net"

_hop_nft() {
	local act=$1 port=$2 range=$3 fam
	for fam in ip ip6; do
		nft delete table "$fam" onebox_hop >/dev/null 2>&1
	done
	[ "$act" = add ] || return 0
	for fam in ip ip6; do
		[ "$fam" = ip6 ] && ! host_has_ipv6 && continue
		# 用 ip/ip6 两张表 + 数字优先级: inet 族 NAT 需内核 5.2+, 优先级关键字需较新的 nft
		nft -f - <<EOF || { [ "$fam" = ip6 ] && warn "nftables 添加 IPv6 端口跳跃规则失败" && continue; return 1; }
table ${fam} onebox_hop {
	chain prerouting {
		type nat hook prerouting priority -100; policy accept;
		fib daddr type local udp dport ${range} redirect to :${port}
	}
}
EOF
	done
}

# 端口跳跃范围与其他 UDP 协议端口冲突时输出冲突项 (协议/端口), 无冲突返回 1
hop_range_conflicts() {
	local range=$1 a b p port net out=""
	a=${range%-*} b=${range#*-}
	for p in $PROTOCOLS; do
		[ "$p" = hysteria2 ] && continue
		port=$(pget PORT "$p")
		[ -n "$port" ] || continue
		net=$(proto_net "$p")
		[ "$net" = tcp ] && continue
		[ "$port" -ge "$a" ] && [ "$port" -le "$b" ] && out+="$(proto_title "$p")/${port} "
	done
	[ -n "$out" ] && printf '%s' "${out% }"
}

# 端口跳跃范围内被其他程序监听的 UDP 端口 (如 WireGuard / Tailscale), 仅用于提示
hop_range_foreign_udp() {
	local range=$1 a b hy out="" line port pid exe own
	a=${range%-*} b=${range#*-}
	hy=$(pget PORT hysteria2)
	has ss || return 1
	while IFS= read -r line; do
		port=$(printf '%s' "$line" | awk '{n=split($4, x, ":"); print x[n]}')
		[[ "$port" =~ ^[0-9]+$ ]] || continue
		[ "$port" = "$hy" ] && continue
		[ "$port" -ge "$a" ] && [ "$port" -le "$b" ] || continue
		case "$(printf '%s' "$line" | awk '{print $4}')" in 127.* | '[::1]'* | ::1:*) continue ;; esac
		port_used_by_onebox "$port" udp && continue
		# onebox 自身内核的出站 UDP 套接字 (按进程可执行文件判断, 而非进程名); 无属主的内核套接字 (如内核 WireGuard) 不跳过
		own=0
		for pid in $(printf '%s' "$line" | grep -o 'pid=[0-9]*' | cut -d= -f2); do
			exe=$(readlink "/proc/$pid/exe" 2>/dev/null)
			exe=${exe% (deleted)}
			if [ -n "$exe" ] && { [ "$exe" = "$SB_BIN" ] || [ "$exe" = "$XR_BIN" ]; }; then own=1; else own=0 && break; fi
		done
		[ "$own" = 1 ] && continue
		case " $out " in *" $port "*) ;; *) out+="${port} " ;; esac
	done < <(ss -lnup 2>/dev/null | awk 'NR>1')
	[ -n "$out" ] && printf '%s' "${out% }"
}

# hop_rules add|del
hop_rules() {
	local act=$1 port range t ok=1 m
	port=$(pget PORT hysteria2)
	range=$HY2_HOP
	[ -n "$port" ] && [ -n "$range" ] || return 0
	# 只改写发往本机地址的 UDP (addrtype LOCAL), 不影响 Docker / WireGuard 等转发流量
	m=(-p udp --dport "${range/-/:}" -m addrtype --dst-type LOCAL)
	for t in iptables ip6tables; do
		has "$t" || continue
		_ipt_rule "$t" del nat PREROUTING "${m[@]}" -- -j REDIRECT --to-ports "$port"
		# 兼容旧版本写入的规则 (无 addrtype 限制 / onebox-hop 注释)
		_ipt_rule "$t" delc nat PREROUTING -p udp --dport "${range/-/:}" -- -j REDIRECT --to-ports "$port"
		while "$t" -t nat -D PREROUTING -p udp --dport "${range/-/:}" -m comment --comment onebox-hop -j REDIRECT --to-ports "$port" 2>/dev/null; do :; done
	done
	has nft && _hop_nft del
	[ "$act" = add ] || return 0
	if has iptables && _ipt_rule iptables add nat PREROUTING "${m[@]}" -- -j REDIRECT --to-ports "$port"; then
		ok=0
		if host_has_ipv6 && has ip6tables; then
			_ipt_rule ip6tables add nat PREROUTING "${m[@]}" -- -j REDIRECT --to-ports "$port" ||
				warn "ip6tables 添加端口跳跃规则失败 (IPv6 客户端将无法使用端口跳跃)"
		fi
	elif has nft && _hop_nft add "$port" "$range"; then
		ok=0
	fi
	return "$ok"
}

# 开机自动恢复防火墙放行与端口跳跃 (onebox net-apply = fw_apply open + hop_rules add)
# 排在各防火墙服务之后: nftables.service 的 "flush ruleset"、firewalld/netfilter-persistent 的加载都会清掉先加的规则
_net_service_file() { printf '/etc/systemd/system/%s.service' "$NET_SERVICE"; }

net_persist() {
	local act=$1 unit
	unit=$(_net_service_file)
	case "$INIT" in
	systemd)
		if [ "$act" = add ]; then
			cat >"$unit" <<EOF || return 1
[Unit]
Description=Sing-Xray-Onebox firewall openings and Hysteria2 port hopping
After=network-online.target netfilter-persistent.service iptables.service ip6tables.service nftables.service firewalld.service ufw.service
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=${CMD_PATH} net-apply

[Install]
WantedBy=multi-user.target
EOF
			systemctl daemon-reload >/dev/null 2>&1 || return 1
			systemctl enable "$NET_SERVICE" >/dev/null 2>&1 || return 1
		else
			if [ -e "$unit" ] || [ -L "$unit" ]; then
				systemctl disable "$NET_SERVICE" >/dev/null 2>&1 || return 1
				rm -f "$unit" || return 1
				systemctl daemon-reload >/dev/null 2>&1 || return 1
			fi
		fi
		;;
	openrc)
		# local 服务在 default 运行级最后执行 (在 iptables / nftables 服务之后)
		if [ "$act" = add ]; then
			mkdir -p /etc/local.d || return 1
			printf '#!/bin/sh\n%s net-apply >/dev/null 2>&1\n' "$CMD_PATH" >/etc/local.d/onebox-net.start || return 1
			chmod 755 /etc/local.d/onebox-net.start || return 1
			rc-update add local default >/dev/null 2>&1 || return 1
		else
			rm -f /etc/local.d/onebox-net.start || return 1
		fi
		;;
	esac
	# 清理旧版本的 onebox-hop 服务
	if [ -f /etc/systemd/system/onebox-hop.service ]; then
		systemctl disable onebox-hop >/dev/null 2>&1 || return 1
		rm -f /etc/systemd/system/onebox-hop.service || return 1
		systemctl daemon-reload >/dev/null 2>&1 || return 1
	fi
	rm -f /etc/local.d/onebox-hop.start
}

hop_setup() {
	if proto_enabled hysteria2 && [ -n "$HY2_HOP" ]; then
		if ! hop_rules add; then
			# 缺少 iptables / nftables 时先尝试安装
			{ ensure_cmds iptables >/dev/null 2>&1 || ensure_cmds nft >/dev/null 2>&1; } && hop_rules add
		fi
		if [ $? -ne 0 ] || ! { has iptables || has nft; }; then
			warn "无法设置 Hysteria2 端口跳跃规则 (需要 iptables 或 nftables 以及内核 NAT 支持), 已关闭端口跳跃"
			hop_rules del
			has nft && _hop_nft del
			HY2_HOP=""
			save_state
		fi
	else
		hop_rules del
	fi
	net_persist add
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
	local kv conf=/etc/sysctl.d/99-onebox-bbr.conf
	if [ "$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null)" = bbr ]; then
		info "BBR 已处于启用状态 ($(bbr_status))"
		return 0
	fi
	if [ "$VIRT" = openvz ]; then
		warn "OpenVZ 无法修改内核拥塞控制, 请在服务商面板开启 BBR"
		return 1
	fi
	kv=$(uname -r | cut -d- -f1)
	if ! ver_ge "$kv" "4.9"; then
		warn "当前内核 ${kv} 低于 4.9, 不支持 BBR, 请先升级内核"
		return 1
	fi
	# LXC 等容器无法加载模块, 但宿主机已加载 tcp_bbr 时 (内核 4.15+ 每个网络命名空间独立) 仍可设置, 所以直接尝试
	grep -qw bbr /proc/sys/net/ipv4/tcp_available_congestion_control 2>/dev/null ||
		{ has modprobe && modprobe tcp_bbr >/dev/null 2>&1; }
	if ! grep -qw bbr /proc/sys/net/ipv4/tcp_available_congestion_control 2>/dev/null; then
		warn "内核未提供 BBR 模块 (tcp_bbr)$(is_container_virt && printf ', 容器环境请在宿主机或服务商面板开启')"
		return 1
	fi
	mkdir -p /etc/sysctl.d
	printf 'net.core.default_qdisc = fq\nnet.ipv4.tcp_congestion_control = bbr\n' >"$conf"
	sysctl -p "$conf" >/dev/null 2>&1
	if [ "$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null)" = bbr ]; then
		info "BBR 已启用 ($(bbr_status))"
	else
		rm -f "$conf"
		warn "BBR 启用失败, 当前: $(bbr_status)"
		return 1
	fi
}


# ---------------------------------------------------------------------------
# TLS 证书
# ---------------------------------------------------------------------------
ACME_HOME="${ACME_HOME:-/root/.acme.sh}"
ACME_SH="${ACME_HOME}/acme.sh"
ACME_RAW="https://raw.githubusercontent.com/acmesh-official/acme.sh/master"

# 统一调用 acme.sh 并固定 --home (sudo 保留普通用户 HOME 时, acme.sh 默认会去 $HOME/.acme.sh 找配置)
acme() { "$ACME_SH" --home "$ACME_HOME" "$@"; }

# 自签 ECC 证书 (已验证: OpenSSL 1.0.2k / 1.1.1 / 3.0 / 3.5, LibreSSL 2.7)
cert_self_signed() {
	local cn=$1 cnf san
	# SNI 填的是 IP 时必须用 IP 类型的 SAN, 否则 sing-box 客户端用 tls.certificate 固定证书时主机名校验失败
	san="DNS:${cn}"
	[[ "$cn" =~ ^[0-9]+(\.[0-9]+){3}$ || "$cn" == *:* ]] && san="IP:${cn}"
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
keyUsage = critical,digitalSignature
extendedKeyUsage = serverAuth
subjectAltName = ${san}
EOF
	if openssl ecparam -genkey -name prime256v1 -noout -out "$TLS_DIR/key.pem" >/dev/null 2>&1 &&
		openssl req -new -x509 -sha256 -days 3650 -key "$TLS_DIR/key.pem" -out "$TLS_DIR/cert.pem" -config "$cnf" >/dev/null 2>&1; then
		rm -f "$cnf"
		chmod 600 "$TLS_DIR/key.pem"
		chmod 644 "$TLS_DIR/cert.pem"
		CERT_FILE="$TLS_DIR/cert.pem" KEY_FILE="$TLS_DIR/key.pem" CERT_PINNED=0
		info "已生成自签证书 (CN=${cn}, 有效期 10 年)"
		return 0
	fi
	rm -f "$cnf"
	err "生成自签证书失败"
	return 1
}

# 叶子证书 DER 的 SHA256 (小写 hex, 无冒号). 以下场景通用:
#   mihomo `fingerprint:` / Xray `pinnedPeerCertSha256` 与分享链接 `pcs=` / Hysteria2 `pinSHA256=`
cert_sha256() {
	[ -f "$CERT_FILE" ] || return 0
	openssl x509 -in "$CERT_FILE" -noout -fingerprint -sha256 2>/dev/null | sed 's/.*=//; s/://g' | tr 'A-F' 'a-f'
}

# 叶子证书公钥 (SPKI DER) 的 SHA256, 标准 base64 —— 仅 sing-box >= 1.13 的 certificate_public_key_sha256 使用
cert_spki_sha256() {
	[ -f "$CERT_FILE" ] || return 0
	openssl x509 -in "$CERT_FILE" -noout -pubkey 2>/dev/null | sed '/-----/d' | base64 -d 2>/dev/null |
		openssl dgst -sha256 -binary | base64 | tr -d '\n'
}

cert_expiry() {
	[ -f "$CERT_FILE" ] || return 0
	openssl x509 -in "$CERT_FILE" -noout -enddate 2>/dev/null | sed 's/notAfter=//'
}

# 只保留 IPv4 / IPv6 字面量 (不能只用 [0-9a-f:.]: 形如 cafe.be. 的 CNAME 也会匹配)
_ip_filter() { grep -E '^([0-9]{1,3}\.){3}[0-9]{1,3}$|^[0-9a-fA-F]{0,4}(:[0-9a-fA-F]{0,4}){2,7}$'; }

# 解析域名 (A/AAAA). 优先 DoH: 与 CA 看到的公网解析一致, 不受 /etc/hosts (如 127.0.1.1 主机名) 与本地缓存影响
resolve_domain() {
	local d=$1 out="" t u
	if has curl; then
		for u in https://cloudflare-dns.com/dns-query https://dns.google/resolve https://dns.alidns.com/resolve; do
			out=$(
				for t in A AAAA; do
					curl -fsS --max-time 6 -H 'accept: application/dns-json' "${u}?name=${d}&type=${t}" 2>/dev/null |
						grep -oE '"data": *"[^"]*"' | sed 's/^"data": *"//; s/"$//'
				done | _ip_filter
			)
			[ -n "$out" ] && break
		done
	fi
	if [ -z "$out" ] && has getent; then
		out=$(getent ahosts "$d" 2>/dev/null | awk '{print $1}' | _ip_filter)
	fi
	[ -n "$out" ] && printf '%s\n' "$out" | sort -u
}

check_domain_points_here() {
	local d=$1 ips
	ips=$(resolve_domain "$d")
	if [ -z "$ips" ]; then
		warn "无法解析域名 ${d}"
		return 1
	fi
	if printf '%s\n' "$ips" | grep -qixF -e "${SERVER_IPV4:-_none_}" -e "${SERVER_IPV6:-_none_}"; then
		return 0
	fi
	warn "域名 ${d} 解析到 [$(printf '%s' "$ips" | tr '\n' ' ')], 与本机 IP (${SERVER_IPV4:-无} / ${SERVER_IPV6:-无}) 不一致"
	return 1
}

# acme_install [邮箱]  —— Let's Encrypt 自 2025-06 起不再使用/保存联系邮箱, 可留空; 不要伪造随机 gmail 地址
acme_install() {
	local email=${1:-} args=() tmp
	if [ ! -x "$ACME_SH" ]; then
		ensure_cmds curl || return 1
		ensure_cmds crontab || true
		_enable_cron_service
		[ -n "$email" ] && args+=(--email "$email")
		if ! has crontab; then
			# 没有 crontab 时 acme.sh --install 会直接失败 ("Pre-check failed"), 必须显式 --nocron
			args+=(--nocron)
			warn "未找到 crontab, 证书不会自动续期; 请自行安排每日执行: ${ACME_SH} --cron --home ${ACME_HOME}"
		fi
		info "安装 acme.sh ..."
		tmp=$(mktemp -d)
		# 1) 完整在线安装 (含 dnsapi/, 需访问 github.com 下载源码包)
		(cd "$tmp" && http_get "${ACME_RAW}/acme.sh" acme.sh &&
			sh acme.sh --install-online --home "$ACME_HOME" --noprofile "${args[@]}") >/dev/null 2>&1
		# 2) github.com 不可达: 单文件安装 (可走 GH_PROXY), 缺少的 dnsapi 下面单独补
		if [ ! -x "$ACME_SH" ]; then
			(cd "$tmp" && http_get "$(gh_url "${ACME_RAW}/acme.sh")" acme.sh &&
				sh acme.sh --install --home "$ACME_HOME" --noprofile "${args[@]}") >/dev/null 2>&1
		fi
		rm -rf "$tmp"
		[ -x "$ACME_SH" ] || {
			err "acme.sh 安装失败"
			return 1
		}
	fi
	if [ ! -f "$ACME_HOME/dnsapi/dns_cf.sh" ]; then
		mkdir -p "$ACME_HOME/dnsapi"
		http_get "$(gh_url "${ACME_RAW}/dnsapi/dns_cf.sh")" "$ACME_HOME/dnsapi/dns_cf.sh" >/dev/null 2>&1 ||
			rm -f "$ACME_HOME/dnsapi/dns_cf.sh"
	fi
	acme --set-default-ca --server letsencrypt >/dev/null 2>&1
	return 0
}

_enable_cron_service() {
	local s
	case "$INIT" in
	systemd)
		for s in cron crond cronie; do
			systemctl enable --now "$s" >/dev/null 2>&1 && break
		done
		;;
	openrc)
		for s in crond cronie dcron fcron; do
			if [ -x "/etc/init.d/$s" ]; then
				rc-update add "$s" default >/dev/null 2>&1
				rc-service "$s" start >/dev/null 2>&1
				break
			fi
		done
		;;
	none) warn "未检测到 init 系统, cron 可能未运行, 证书需手动续期: ${ACME_SH} --cron --home ${ACME_HOME}" ;;
	esac
	return 0
}

# cert_acme 域名 standalone|cf  (cf: 需预先 export CF_Token [+CF_Account_ID|CF_Zone_ID] 或 CF_Key+CF_Email)
cert_acme() {
	local d=$1 method=$2 args=() rc
	acme_install "${ACME_EMAIL:-}" || return 1
	case "$method" in
	standalone)
		if site_enabled; then
			# 托管网站持续监听 80: 使用同一挑战目录, 签发与续期都不必暂停网站。
			args=(--webroot "$REALITY_SITE_ROOT")
		else
		# acme.sh 3.1+ standalone 用 socat, 没有 socat 时回退到 python3
		has socat || has python3 || ensure_cmds socat || warn "未能安装 socat, standalone 模式可能失败"
		# 新配置中仍有协议使用 TCP 80 时无法使用 HTTP 验证 (申请与每次续期都需要 80 端口)
		if port_taken_by_other 80 tcp ""; then
			err "有协议占用 TCP 80 端口, 无法使用 HTTP 验证, 请先修改该协议端口或改用 Cloudflare DNS 验证"
			return 1
		fi
		if port_in_use 80 tcp && port_used_by_onebox 80 tcp; then
			# 旧配置 (重装前) 的协议占用了 80 端口: 申请期间暂停内核, 之后应用新配置时重启
			svc_stop singbox
			svc_stop xray
			ACME_STOPPED_CORES=1
			# 申请过程中被中断时恢复内核
			trap 'trap "" INT TERM HUP; svc_exists singbox && svc_start singbox; svc_exists xray && svc_start xray; cert_txn_rollback; exit 130' INT TERM HUP
		fi
		if port_in_use 80 tcp; then
			err "80 端口被占用, standalone 模式需要临时占用 80 端口, 请先停止占用该端口的程序"
			if [ "${ACME_STOPPED_CORES:-0}" = 1 ]; then
				txn_traps
				svc_exists singbox && svc_start singbox
				svc_exists xray && svc_start xray
			fi
			return 1
		fi
		# HTTP-01 需要入站 TCP 80 可达; 续期时同样需要, 因此常开 (fw_apply 中按 TLS_MODE/ACME_METHOD 维护)
		# 记录 80 端口是否由本次申请新放行 (比较放行前后的防火墙状态), 事务回滚时关闭
		local fw_before
		fw_before=$(_fw_snapshot)
		fw_rule open 80 tcp
		rc=$?
		[ "$(_fw_snapshot)" != "$fw_before" ] && CERT_TXN_FW80=1
		if [ "$rc" != 0 ]; then
			err "无法放行证书验证所需的 TCP 80 端口"
			return 1
		fi
		warn "请确认云服务商安全组 / 防火墙已放行 TCP 80 (申请与每次续期都需要)"
		args=(--standalone)
		[ -z "$SERVER_IPV4" ] && [ -n "$SERVER_IPV6" ] && args+=(--listen-v6)
		fi
		;;
	cf)
		if [ -z "${CF_Token:-}" ] && { [ -z "${CF_Key:-}" ] || [ -z "${CF_Email:-}" ]; }; then
			err "Cloudflare DNS 验证需要 CF_Token (或 CF_Key + CF_Email)"
			return 1
		fi
		[ -f "$ACME_HOME/dnsapi/dns_cf.sh" ] || {
			err "缺少 acme.sh 的 dnsapi/dns_cf.sh, 无法使用 Cloudflare DNS 验证"
			return 1
		}
		args=(--dns dns_cf)
		;;
	*) return 1 ;;
	esac
	# 该域名已有 acme.sh 部署时: 验证方式变化需强制重新签发 (否则 acme.sh 跳过, 续期仍用旧方式);
	# 且事务回滚时不能删除这个事先已存在的部署, 而是恢复其原有配置 (验证方式 / 证书)
	local conf="$ACME_HOME/${d}_ecc/${d}.conf" preexist=0 stored want
	if [ -f "$conf" ]; then
		preexist=1
		if [ -n "$CERT_TXN_BAK" ] && [ -z "$CERT_TXN_ACME_D" ]; then
			local acme_backup
			acme_backup=$(mktemp -d "$ONEBOX_DIR/.acme-snapshot.XXXXXX") || { err "无法创建 ACME 部署备份"; return 1; }
			if ! cp -a "$ACME_HOME/${d}_ecc" "$acme_backup/deployment"; then
				rm -rf "$acme_backup"
				err "无法完整备份现有 ACME 部署，已取消证书变更"
				return 1
			fi
			if ! rm -rf "$ONEBOX_DIR/.acme-rollback" || ! mv "$acme_backup/deployment" "$ONEBOX_DIR/.acme-rollback"; then
				rm -rf "$acme_backup"
				err "无法保存 ACME 部署备份，已取消证书变更"
				return 1
			fi
			rm -rf "$acme_backup"
			CERT_TXN_ACME_D=$d
		fi
		stored=$(sed -n "s/^Le_Webroot='\{0,1\}\([^']*\)'\{0,1\}$/\1/p" "$conf" | head -n1)
		case "$method" in standalone) if site_enabled; then want=$REALITY_SITE_ROOT; else want=no; fi ;; cf) want=dns_cf ;; esac
		[ -n "$stored" ] && [ "$stored" != "$want" ] && args+=(--force)
	fi
	info "申请证书: ${d} (Let's Encrypt, ECC)"
	# Cloudflare 凭据只传给 acme.sh (其会保存到 account.conf 供续期使用)
	CF_Token=${CF_Token:-} CF_Account_ID=${CF_Account_ID:-} CF_Zone_ID=${CF_Zone_ID:-} CF_Key=${CF_Key:-} CF_Email=${CF_Email:-} \
		acme --issue -d "$d" "${args[@]}" -k ec-256 --server letsencrypt
	rc=$?
	# 签发成功即记录新部署, 使后续失败能在回滚时撤销 (事先已存在的部署不记录)
	[ "$preexist" = 0 ] && { [ "$rc" = 0 ] || [ "$rc" = 2 ]; } && CERT_TXN_NEW_ACME=$d
	# rc=2: 证书已存在且未到续期时间 (acme.sh RENEW_SKIP), 视为成功
	if [ "$rc" != 0 ] && [ "$rc" != 2 ]; then
		err "证书申请失败 (acme.sh 退出码 ${rc}), 请检查域名解析 / 80 端口 / API 令牌"
		if [ "${ACME_STOPPED_CORES:-0}" = 1 ]; then
			txn_traps
			svc_exists singbox && svc_start singbox
			svc_exists xray && svc_start xray
		fi
		return 1
	fi
	[ "${ACME_STOPPED_CORES:-0}" = 1 ] && txn_traps
	mkdir -p "$TLS_DIR" && chmod 700 "$TLS_DIR"
	acme --install-cert -d "$d" --ecc \
		--key-file "$TLS_DIR/key.pem" \
		--fullchain-file "$TLS_DIR/cert.pem" \
		--reloadcmd "${CMD_PATH} restart >/dev/null 2>&1 || true" >/dev/null 2>&1 || {
		err "证书安装失败"
		return 1
	}
	chmod 600 "$TLS_DIR/key.pem"
	CERT_FILE="$TLS_DIR/cert.pem" KEY_FILE="$TLS_DIR/key.pem" CERT_PINNED=0
	info "证书已安装, 将由 acme.sh 自动续期"
}

cert_custom() {
	local c=$1 k=$2
	# 只转为绝对路径, 不解析符号链接 (certbot 的 live/ 目录是指向 archive/ 的链接, 续期后链接指向新文件)
	case "$c" in /*) ;; *) c="$PWD/$c" ;; esac
	case "$k" in /*) ;; *) k="$PWD/$k" ;; esac
	[ -f "$c" ] && [ -f "$k" ] || {
		err "证书或私钥文件不存在"
		return 1
	}
	openssl x509 -in "$c" -noout >/dev/null 2>&1 || {
		err "无法解析证书文件: $c"
		return 1
	}
	# 证书与私钥必须配对 (比较两者的公钥), 否则内核启动时才报错
	if [ "$(openssl x509 -in "$c" -noout -pubkey 2>/dev/null)" != "$(openssl pkey -in "$k" -pubout 2>/dev/null)" ]; then
		err "证书与私钥不匹配"
		return 1
	fi
	# 证书需覆盖所填域名
	if [ -n "$DOMAIN" ] && openssl x509 -help 2>&1 | grep -q -- '-checkhost' &&
		! openssl x509 -in "$c" -noout -checkhost "$DOMAIN" 2>/dev/null | grep -q 'does match'; then
		err "证书不包含域名 ${DOMAIN}"
		return 1
	fi
	# 不受公共 CA 信任的证书 (如 Cloudflare 源证书): 客户端改为固定证书指纹
	CERT_PINNED=0
	if ! openssl verify -untrusted "$c" "$c" >/dev/null 2>&1; then
		CERT_PINNED=1
		warn "该证书不受公共 CA 信任 (如 Cloudflare 源证书), 直连的客户端将固定证书指纹"
	fi
	# 直接引用原文件 (certbot 等续期后自动生效; Xray 需重启: 可在续期钩子中执行 onebox restart)
	CERT_FILE=$c KEY_FILE=$k
	info "使用证书: ${c}"
}

# 本机时钟与 HTTPS 服务器 Date 头的偏差 (秒, 绝对值); 获取失败返回 1
# SS-2022 要求客户端/服务端时间差 <= 30s, VMess(AEAD) <= 120s
clock_skew() {
	local u d dd mo y hms m remote now
	for u in https://www.cloudflare.com https://www.apple.com http://www.baidu.com; do
		d=$(curl -ksSI --max-time 6 "$u" 2>/dev/null | tr -d '\r' | sed -n 's/^[Dd]ate: *//p' | head -n1)
		[ -n "$d" ] && break
	done
	# 形如: Sat, 26 Sep 2026 17:05:53 GMT
	read -r _ dd mo y hms _ <<<"$d"
	[ -n "$hms" ] || return 1
	m=JanFebMarAprMayJunJulAugSepOctNovDec
	m=${m%%"$mo"*}
	[ ${#m} -lt 36 ] || return 1
	remote=$(date -u -d "$(printf '%s-%02d-%02d' "$y" $((${#m} / 3 + 1)) "$((10#$dd))") $hms" +%s 2>/dev/null) || return 1
	now=$(date -u +%s)
	echo $((remote > now ? remote - now : now - remote))
}

check_clock() {
	local skew
	skew=$(clock_skew) || return 0
	[ "$skew" -le 10 ] && return 0
	warn "本机时间与网络时间相差约 ${skew} 秒 (Shadowsocks-2022 允许 30 秒, VMess 允许 120 秒), 请开启时间同步"
	case "$INIT" in
	systemd) has timedatectl && info "可执行: timedatectl set-ntp true (或安装 chrony)" ;;
	openrc) info "可执行: apk add chrony && rc-update add chronyd && rc-service chronyd start" ;;
	esac
	return 1
}

# ---------------------------------------------------------------------------
# 自有域名 REALITY 网站 (独立 nginx / ACME / 事务管理)
# ---------------------------------------------------------------------------
# Optional owned-domain REALITY website. Inlined into onebox.sh for distribution.
# nginx has its own config/service/PID; distro nginx configuration is never edited.
REALITY_SITE_DIR="${ONEBOX_DIR}/site"
REALITY_SITE_ROOT="${ONEBOX_SITE_ROOT:-/var/lib/onebox-site}"
SITE_SERVICE="onebox-site"
SITE_ACME_HOME="${REALITY_SITE_DIR}/acme"
SITE_TXN_BAK=""

site_enabled() { [ "${REALITY_SITE_ENABLED:-}" = 1 ] && any_reality; }
site_https_enabled() { site_enabled && [ "${REALITY_SITE_HTTPS:-0}" = 1 ]; }
site_uses_https_proxy() { site_https_enabled && [ "$(site_reality_port)" != 443 ]; }
_site_owns_https_listener() { [ "$(cat "$REALITY_SITE_DIR/frontend-port" 2>/dev/null)" = 443 ] && _site_running; }
site_nginx_bin() { if [ -n "${ONEBOX_NGINX_BIN:-}" ]; then [ -x "$ONEBOX_NGINX_BIN" ] && printf '%s' "$ONEBOX_NGINX_BIN"; else command -v nginx; fi; }
site_reality_port() {
	local p first="" port
	for p in $PROTOCOLS; do
		proto_uses_reality "$p" || continue
		port=$(pget PORT "$p")
		[ -n "$port" ] || continue
		[ "$port" = 443 ] && { printf '443'; return 0; }
		[ -n "$first" ] || first=$port
	done
	[ -n "$first" ] || return 1
	printf '%s' "$first"
}
site_public_port() {
	if site_https_enabled; then printf '443'; else site_reality_port; fi
}

site_html_escape() {
	local s=$1
	# Bash replacement strings can interpret & on newer Bash; use sed explicitly.
	printf '%s' "$s" | sed -e 's/\&/\&amp;/g' -e 's/</\&lt;/g' -e 's/>/\&gt;/g' -e 's/"/\&quot;/g' -e "s/'/\&#39;/g"
}

site_render_index() {
	local title domain
	title=$(site_html_escape "${REALITY_SITE_TITLE:-山间手记}")
	domain=$(site_html_escape "$REALITY_SITE_DOMAIN")
	cat <<EOF
<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="description" content="一个安放文字、想法与日常观察的地方。"><meta name="color-scheme" content="light"><title>${title}</title>
<style>
:root{--paper:#f7f6ee;--ink:#233e32;--muted:#617167;--line:#d8dfd4;--leaf:#dce9d7}*{box-sizing:border-box}html{scroll-behavior:smooth}body{margin:0;background:var(--paper);color:var(--ink);font:16px/1.8 system-ui,-apple-system,"PingFang SC","Microsoft YaHei",sans-serif}a{color:inherit;text-decoration:none}a:focus-visible{outline:2px solid var(--ink);outline-offset:6px}.wrap{width:min(1080px,calc(100% - 48px));margin:auto}header{display:flex;align-items:center;justify-content:space-between;gap:24px;padding:28px 0;border-bottom:1px solid var(--line)}.brand{font-weight:700;letter-spacing:.04em;overflow-wrap:anywhere}nav{display:flex;gap:26px;flex-shrink:0;font-size:14px;color:var(--muted)}nav a:hover{text-decoration:underline;text-underline-offset:5px}.hero{display:grid;grid-template-columns:1.5fr 1fr;align-items:center;gap:64px;padding:96px 0}.eyebrow{margin:0 0 20px;font-size:12px;letter-spacing:.18em;color:var(--muted)}h1{margin:0;font-family:Georgia,"Songti SC",serif;font-size:clamp(36px,5.3vw,62px);font-weight:500;line-height:1.3;letter-spacing:-.035em}.intro{max-width:470px;margin:26px 0 30px;color:var(--muted)}.button{display:inline-block;padding:10px 22px;border:1px solid var(--ink);border-radius:28px;font-size:14px}.button:hover{background:var(--ink);color:var(--paper)}.art{position:relative;aspect-ratio:1;border-radius:48% 48% 10px 10px;background:var(--leaf);overflow:hidden}.art:before{content:"";position:absolute;width:62%;height:62%;left:19%;top:17%;border:1px solid #7d9a78;border-radius:50%}.art:after{content:"";position:absolute;width:1px;height:78%;background:#7d9a78;left:50%;bottom:0;transform:rotate(24deg);transform-origin:bottom}.art span{position:absolute;left:24px;bottom:20px;color:#54714f;font:italic 14px Georgia,serif;letter-spacing:.06em}section{scroll-margin-top:30px}.about{display:grid;grid-template-columns:1fr 2fr;gap:48px;padding:46px 0;border-top:1px solid var(--line)}h2{margin:0;font-size:22px;font-weight:600}.about p{margin:0;color:var(--muted);max-width:650px}.notes{padding:42px 0 72px}.section-top{display:flex;align-items:baseline;justify-content:space-between;gap:20px;margin-bottom:24px}.section-top span{font-size:13px;color:var(--muted)}.cards{display:grid;grid-template-columns:1fr 1fr;gap:22px}article{padding:28px;border:1px solid var(--line);border-radius:12px;background:#fffdf6}.tag{font-size:12px;color:var(--muted)}h3{margin:12px 0;font-size:20px;font-weight:600}article p{margin:0;color:var(--muted);font-size:15px}footer{display:flex;justify-content:space-between;gap:20px;padding:26px 0 34px;border-top:1px solid var(--line);font-size:12px;color:var(--muted);overflow-wrap:anywhere}@media(max-width:680px){.wrap{width:calc(100% - 36px)}header{align-items:flex-start;flex-direction:column;gap:12px}nav{gap:24px}.hero{grid-template-columns:1fr;gap:36px;padding:54px 0}.art{max-width:280px;width:100%;justify-self:center}.about{grid-template-columns:1fr;gap:18px;padding:32px 0}.cards{grid-template-columns:1fr}.section-top{align-items:flex-start;flex-direction:column;gap:4px}footer{flex-direction:column;gap:4px}}@media(prefers-reduced-motion:reduce){html{scroll-behavior:auto}}
</style></head><body><div class="wrap">
<header><a class="brand" href="#home">${title}</a><nav aria-label="主导航"><a href="#home">首页</a><a href="#about">关于</a><a href="#notes">记录</a></nav></header>
<main><section class="hero" id="home" aria-labelledby="hero-title"><div><p class="eyebrow">文字 · 想法 · 日常</p><h1 id="hero-title">给思考一点空间，<br>给日常一些留白。</h1><p class="intro">这里是一个安放文字的小地方。记录值得停留的瞬间，也整理那些尚未成形的想法。</p><a class="button" href="#notes">读一读随手记录 ↗</a></div><div class="art" aria-hidden="true"><span>A little room to think.</span></div></section>
<section class="about" id="about" aria-labelledby="about-title"><h2 id="about-title">关于这里</h2><p>写作让模糊的想法渐渐清晰，也让平常的生活留下痕迹。这个小站从简单的记录开始，不急着得出答案，只希望保持观察、好奇与表达。</p></section>
<section class="notes" id="notes" aria-labelledby="notes-title"><div class="section-top"><h2 id="notes-title">随手记录</h2><span>一些可以慢慢读的片段</span></div><div class="cards"><article><span class="tag">关于记录</span><h3>从一个小念头开始</h3><p>不必等到想法完整才动笔。记下一句话、一个问题，或一个忽然注意到的细节，就已经为之后的思考留下了入口。</p></article><article><span class="tag">关于日常</span><h3>留意身边的细节</h3><p>光线移动的方向，街角树叶的颜色，一段让人停顿的文字。许多值得记住的事，就藏在这些不起眼的片刻里。</p></article></div></section></main>
<footer><span>${title} · ${domain}</span><span>保持好奇，慢慢记录。</span></footer></div></body></html>
EOF
}

site_validate_ports() {
	site_enabled || return 0
	valid_domain "${REALITY_SITE_DOMAIN:-}" || { err "自有站点需要合法域名"; return 1; }
	local port=${REALITY_SITE_PORT:-} p pp net
	[[ "$port" =~ ^[1-9][0-9]{0,4}$ ]] && [ "$port" -ge 1024 ] && [ "$port" -le 65535 ] || { err "站点内部 TLS 端口必须为 1024–65535"; return 1; }
	[ "$port" != "${REALITY_GUARD_PORT:-}" ] && [ "${REALITY_GUARD_PORT:-}" != 80 ] || { err "站点端口与 REALITY 防偷跑端口冲突"; return 1; }
	if site_https_enabled && [ "${REALITY_GUARD_PORT:-}" = 443 ]; then err "TCP 443 与 REALITY 防偷跑端口冲突，请先更换该端口"; return 1; fi
	for p in $PROTOCOLS; do
		net=$(proto_net "$p")
		[ "$net" = udp ] && continue
		pp=$(pget PORT "$p")
		if [ "$pp" = 80 ] || [ "$pp" = "$port" ]; then err "${p} 的 TCP 端口 ${pp} 与自有站点冲突"; return 1; fi
		if site_https_enabled && [ "$pp" = 443 ] && ! proto_uses_reality "$p"; then
			err "${p} 已使用 TCP 443，请先更换该协议端口或关闭网站 443 入口"
			return 1
		fi
	done
	site_reality_port >/dev/null || { err "自有站点至少需要一个 REALITY TCP 入站"; return 1; }
}

_site_paths_safe() {
	local p
	for p in "$REALITY_SITE_DIR" "$REALITY_SITE_ROOT" "$SITE_ACME_HOME"; do
		[[ "$p" =~ ^/[A-Za-z0-9_./-]+$ ]] && [[ "$p" != *'/../'* && "$p" != */.. && "$p" != *'/./'* ]] || { err "站点路径需要不含空格与特殊字符的绝对路径: $p"; return 1; }
		case "$p" in /|/etc|/var|/var/lib|/root|/home|/usr|/opt|/tmp|/run) err "拒绝使用系统目录作为站点专属目录: $p"; return 1 ;; esac
		[ ! -L "$p" ] || { err "站点目录不能是符号链接: $p"; return 1; }
	done
	case "$REALITY_SITE_ROOT/" in "$ONEBOX_DIR/"*) err "站点内容需放在公开可遍历的独立目录，不能放入私密配置目录"; return 1 ;; esac
	for p in "$REALITY_SITE_DIR" "$REALITY_SITE_ROOT"; do
		if [ -d "$p" ] && [ ! -f "$p/.onebox-site-owned" ]; then
			[ -z "$(ls -A "$p" 2>/dev/null)" ] || { err "目录已存在且不归 onebox 站点管理: $p"; return 1; }
		fi
	done
}

_site_hash() { openssl dgst -sha256 2>/dev/null | sed 's/^.*= *//'; }
_site_signature() { printf '%s\n' "$REALITY_SITE_DOMAIN" "$REALITY_SITE_PORT" "$(site_public_port)" "${REALITY_SITE_TITLE:-山间手记}" "$REALITY_SITE_ROOT" "${REALITY_SITE_HTTPS:-0}" "$(site_uses_https_proxy && echo nginx || echo reality)" | _site_hash; }
_site_unit_path() { case "$INIT" in systemd) printf '/etc/systemd/system/%s.service' "$SITE_SERVICE" ;; openrc) printf '%s/%s' "$INITD_DIR" "$SITE_SERVICE" ;; none) return 0 ;; esac; }
_site_running() {
	local pid
	[ -f "$REALITY_SITE_DIR/nginx.pid" ] || return 1
	pid=$(cat "$REALITY_SITE_DIR/nginx.pid")
	[[ "$pid" =~ ^[1-9][0-9]*$ ]] && kill -0 "$pid" 2>/dev/null || return 1
	[ -r "/proc/$pid/cmdline" ] || return 1
	tr '\0' ' ' <"/proc/$pid/cmdline" | grep -qF "$REALITY_SITE_DIR/nginx.conf"
}

site_nginx_check() { "$(site_nginx_bin)" -t -p "$REALITY_SITE_DIR/" -c "$REALITY_SITE_DIR/nginx.conf" >/dev/null 2>&1; }

_site_ca_bundle() {
	local path
	for path in /etc/ssl/certs/ca-certificates.crt /etc/pki/tls/certs/ca-bundle.crt /etc/ssl/ca-bundle.pem /etc/ssl/cert.pem; do
		if [ -r "$path" ] && [ -s "$path" ]; then printf '%s' "$path"; return 0; fi
	done
	err "找不到系统 CA 证书包，请先安装 ca-certificates"
	return 1
}

site_write_nginx() {
	local public user="" group="" u ipv6="" suffix="" https="" https_ipv6="" ca
	public=$(site_public_port) || return 1
	[ "$public" = 443 ] || suffix=":${public}"
	for u in nginx www-data nobody; do
		id "$u" >/dev/null 2>&1 || continue
		user=$u group=$(id -gn "$u")
		break
	done
	[ -n "$user" ] || { err "nginx 需要非 root 工作进程账号"; return 1; }
	if host_has_ipv6; then ipv6='listen [::]:80;'; https_ipv6='listen [::]:443 ssl http2;'; fi
	# defer 先只启动 HTTP-01 与本机目标，公网 443 由服务切换阶段接管。
	if [ "${1:-}" != defer ] && site_uses_https_proxy; then
		ca=$(_site_ca_bundle) || return 1
		https=$(cat <<EOF
    server {
        listen 443 ssl http2;
        ${https_ipv6}
        server_name ${REALITY_SITE_DOMAIN};
        ssl_certificate "${REALITY_SITE_DIR}/cert.pem";
        ssl_certificate_key "${REALITY_SITE_DIR}/key.pem";
        ssl_protocols TLSv1.2 TLSv1.3;
        ssl_ecdh_curve X25519:prime256v1;
        ssl_session_cache shared:onebox_site:1m;
        ssl_session_timeout 10m;
        location / {
            proxy_pass https://127.0.0.1:${REALITY_SITE_PORT};
            proxy_ssl_server_name on;
            proxy_ssl_name ${REALITY_SITE_DOMAIN};
            proxy_ssl_protocols TLSv1.3;
            proxy_ssl_verify on;
            proxy_ssl_verify_depth 3;
            proxy_ssl_trusted_certificate "${ca}";
            proxy_http_version 1.1;
            proxy_set_header Host ${REALITY_SITE_DOMAIN};
            proxy_set_header X-Real-IP \$remote_addr;
            proxy_set_header X-Forwarded-For \$remote_addr;
            proxy_set_header X-Forwarded-Proto https;
            proxy_set_header X-Forwarded-Host ${REALITY_SITE_DOMAIN};
            proxy_set_header X-Forwarded-Port 443;
            proxy_set_header Forwarded "";
            proxy_set_header Connection "";
            proxy_redirect off;
            # 私密配置目录不供 worker 遍历，代理请求/响应不写临时文件。
            proxy_buffering off;
            proxy_request_buffering off;
        }
    }
EOF
)
	fi
	mkdir -p "$REALITY_SITE_DIR/tmp" || return 1
	cat >"$REALITY_SITE_DIR/nginx.conf" <<EOF || return 1
# Managed exclusively by onebox; no /etc/nginx includes.
user ${user} ${group};
worker_processes 1;
pid "${REALITY_SITE_DIR}/nginx.pid";
error_log "${REALITY_SITE_DIR}/error.log" warn;
events { worker_connections 512; }
http {
    access_log off;
    server_tokens off;
    charset utf-8;
    default_type application/octet-stream;
    types { text/html html htm; text/css css; application/javascript js; image/png png; image/jpeg jpg jpeg; image/svg+xml svg; image/x-icon ico; text/plain txt; }
    client_body_temp_path "${REALITY_SITE_DIR}/tmp";
    proxy_temp_path "${REALITY_SITE_DIR}/tmp/proxy";
    fastcgi_temp_path "${REALITY_SITE_DIR}/tmp/fastcgi";
    uwsgi_temp_path "${REALITY_SITE_DIR}/tmp/uwsgi";
    scgi_temp_path "${REALITY_SITE_DIR}/tmp/scgi";
    sendfile on;
    keepalive_timeout 30;
    server {
        listen 80;
        ${ipv6}
        server_name ${REALITY_SITE_DOMAIN};
        location ^~ /.well-known/acme-challenge/ { root "${REALITY_SITE_ROOT}"; default_type text/plain; try_files \$uri =404; }
        location / { return 301 https://${REALITY_SITE_DOMAIN}${suffix}\$request_uri; }
    }
    server {
        listen 127.0.0.1:${REALITY_SITE_PORT} ssl http2;
        server_name ${REALITY_SITE_DOMAIN};
        ssl_certificate "${REALITY_SITE_DIR}/cert.pem";
        ssl_certificate_key "${REALITY_SITE_DIR}/key.pem";
        ssl_protocols TLSv1.3;
        ssl_ecdh_curve X25519:prime256v1;
        ssl_session_cache shared:onebox_site:1m;
        ssl_session_timeout 10m;
        # REALITY 与反代入口可能使用不同公网端口，目录跳转保持相对路径。
        absolute_redirect off;
        root "${REALITY_SITE_ROOT}";
        index index.html;
        add_header X-Content-Type-Options nosniff always;
        add_header Referrer-Policy strict-origin-when-cross-origin always;
        location ~ /\\. { deny all; }
        location / { try_files \$uri \$uri/ =404; }
    }
${https}
}
EOF
	site_nginx_check || { err "站点 nginx 配置校验失败（需 nginx 支持 TLS 1.3 和 HTTP/2）"; return 1; }
}

site_install_nginx() {
	site_nginx_bin >/dev/null 2>&1 && return 0
	# Package post-install may start distro nginx. Only stop it when nginx/config/service
	# were all absent beforehand, so an existing website is never taken over.
	if [ -d /etc/nginx ] || [ -e /etc/systemd/system/nginx.service ] || [ -e /lib/systemd/system/nginx.service ] || [ -e /usr/lib/systemd/system/nginx.service ] || [ -e "$INITD_DIR/nginx" ]; then
		err "检测到现有 nginx 文件但找不到 nginx 命令，请先修复原 nginx 安装；不会接管已有站点"
		return 1
	fi
	ensure_cmds nginx || return 1
	case "$INIT" in
	systemd) systemctl stop nginx >/dev/null 2>&1; systemctl disable nginx >/dev/null 2>&1 ;;
	openrc) rc-service nginx stop >/dev/null 2>&1; rc-update del nginx default >/dev/null 2>&1 ;;
	none) [ ! -f /run/nginx.pid ] || "$(site_nginx_bin)" -s quit >/dev/null 2>&1 ;;
	esac
	site_nginx_bin >/dev/null 2>&1
}

_site_write_service() {
	local bin unit
	bin=$(site_nginx_bin) || return 1
	[[ "$bin" =~ ^/[A-Za-z0-9_./-]+$ ]] || { err "nginx 可执行路径包含不支持的字符"; return 1; }
	unit=$(_site_unit_path)
	case "$INIT" in
	systemd)
		cat >"$unit" <<EOF
[Unit]
Description=Onebox owned-domain website
After=network.target
[Service]
Type=forking
PIDFile=${REALITY_SITE_DIR}/nginx.pid
ExecStartPre=${bin} -t -p ${REALITY_SITE_DIR}/ -c ${REALITY_SITE_DIR}/nginx.conf
ExecStart=${bin} -p ${REALITY_SITE_DIR}/ -c ${REALITY_SITE_DIR}/nginx.conf
ExecReload=${bin} -p ${REALITY_SITE_DIR}/ -c ${REALITY_SITE_DIR}/nginx.conf -s reload
KillSignal=SIGQUIT
TimeoutStopSec=15
Restart=on-failure
PrivateTmp=true
NoNewPrivileges=true
[Install]
WantedBy=multi-user.target
EOF
		systemctl daemon-reload >/dev/null 2>&1 || return 1
		;;
	openrc)
		cat >"$unit" <<EOF
#!/sbin/openrc-run
name="${SITE_SERVICE}"
description="Onebox owned-domain website"
command="${bin}"
command_args="-p ${REALITY_SITE_DIR}/ -c ${REALITY_SITE_DIR}/nginx.conf"
pidfile="${REALITY_SITE_DIR}/nginx.pid"
depend() { need net; }
start_pre() { "${bin}" -t -p "${REALITY_SITE_DIR}/" -c "${REALITY_SITE_DIR}/nginx.conf"; }
EOF
		chmod 755 "$unit" || return 1
		;;
	none) warn "未检测到 init 系统：站点使用独立 nginx 守护进程，随 onebox 的统一开机任务启动（需 crontab）" ;;
	esac
	cat >"$REALITY_SITE_DIR/reload.sh" <<EOF
#!/usr/bin/env bash
set -e
"${bin}" -t -p "${REALITY_SITE_DIR}/" -c "${REALITY_SITE_DIR}/nginx.conf"
if [ -f "${REALITY_SITE_DIR}/.disabled" ]; then exit 0; fi
"${bin}" -p "${REALITY_SITE_DIR}/" -c "${REALITY_SITE_DIR}/nginx.conf" -s reload
EOF
	chmod 700 "$REALITY_SITE_DIR/reload.sh"
}

site_service() {
	local action=${1:-status} bin pid i
	[ -f "$REALITY_SITE_DIR/.onebox-site-owned" ] || { [ "$action" = stop ] && return 0; return 1; }
	case "$action" in
	status) if _site_running; then info "自有站点运行中"; return 0; else info "自有站点未运行"; return 1; fi ;;
	start | restart) site_nginx_check || return 1 ;;
	stop) ;; *) return 1 ;;
	esac
	if [ "$action" = restart ]; then site_service stop || return 1; action=start; fi
	if [ "$action" = start ]; then
		_site_running && return 0
		case "$INIT" in
		systemd) systemctl start "$SITE_SERVICE" >/dev/null 2>&1 ;;
		openrc) rc-service "$SITE_SERVICE" start >/dev/null 2>&1 ;;
		none) bin=$(site_nginx_bin) && "$bin" -p "$REALITY_SITE_DIR/" -c "$REALITY_SITE_DIR/nginx.conf" ;;
		esac
		return $?
	fi
	case "$INIT" in
	systemd) systemctl stop "$SITE_SERVICE" >/dev/null 2>&1 ;;
	openrc) rc-service "$SITE_SERVICE" stop >/dev/null 2>&1 ;;
	none)
		if _site_running; then
			pid=$(cat "$REALITY_SITE_DIR/nginx.pid")
			kill -QUIT "$pid" 2>/dev/null || return 1
			for i in 1 2 3 4 5; do _site_running || break; sleep 1; done
			_site_running && return 1
		fi
		;;
	esac
	! _site_running
}

# An independent backup job may refer to the ACME directory. Only the renewal
# command and the legacy, explicitly marked boot command belong to this site.
_site_cron_filter() {
	awk -v mode="$1" -v exe="$SITE_ACME_HOME/acme.sh" -v root="$REALITY_SITE_DIR/" -v manager="$CMD_PATH" '
		{ own = (index($0,exe) && /(^|[ \t])--cron([ \t]|$)/) ||
		        (index($0,manager) && /cert-renew[ \t]+site[ \t]+--cron([ \t]|$)/) ||
		        (index($0,root) && /# onebox-site-autostart([ \t]|$)/)
		  if ((mode == "owned" && own) || (mode == "keep" && !own)) print }
	'
}

_site_read_crontab() {
	local tmp out rc message
	tmp=$(mktemp) || return 1
	out=$(LC_ALL=C crontab -l 2>"$tmp")
	rc=$?
	message=$(cat "$tmp")
	rm -f "$tmp"
	if [ "$rc" = 0 ]; then
		[ -z "$out" ] || printf '%s\n' "$out"
		return 0
	fi
	# Vixie/Cronie and BusyBox distinguish an absent user crontab by these
	# diagnostics. Other read failures must not become an empty replacement.
	if [ -z "$out" ]; then
		case "$message" in
		*'no crontab for '* | *"can't open '"*': No such file or directory') return 0 ;;
		esac
	fi
	err "无法读取现有 crontab，已保留原任务且取消站点任务变更"
	return 1
}

_site_cron_lines() {
	has crontab || return 0
	local current
	current=$(_site_read_crontab) || return 1
	printf '%s\n' "$current" | _site_cron_filter owned
}
_site_cron_remove() {
	has crontab || return 0
	local current filtered
	current=$(_site_read_crontab) || return 1
	filtered=$(printf '%s\n' "$current" | _site_cron_filter keep)
	[ "$current" = "$filtered" ] || printf '%s\n' "$filtered" | crontab -
}
_site_scheduler_ready() {
	ensure_cmds crontab || { err "自有站点需要 crontab 自动续期，安装失败"; return 1; }
	local s file name
	case "$INIT" in
	systemd)
		_enable_cron_service
		for s in cron crond cronie; do systemctl is-active --quiet "$s" 2>/dev/null && return 0; done
		;;
	openrc)
		_enable_cron_service
		for s in crond cronie dcron fcron; do rc-service "$s" status >/dev/null 2>&1 && return 0; done
		;;
	none)
		for file in /proc/[0-9]*/comm; do
			IFS= read -r name <"$file" 2>/dev/null || continue
			case "$name" in cron | crond | cronie | dcron | fcron) return 0 ;; esac
		done
		;;
	esac
	err "cron 未运行，无法保证站点证书自动续期；请先启动 cron 服务后重试"
	return 1
}
_site_cron_enable() {
	_site_scheduler_ready || return 1
	local current wanted
	current=$(_site_read_crontab) || return 1
	current=$(printf '%s\n' "$current" | _site_cron_filter keep)
	wanted="17 3 * * * \"${CMD_PATH}\" cert-renew site --cron >/dev/null 2>&1"
	# The global onebox @reboot starts the site before proxy cores. A second
	# direct nginx job races for its sockets and can abort the proxy startup.
	{ [ -z "$current" ] || printf '%s\n' "$current"; printf '%s\n' "$wanted"; } | crontab -
}

_site_txn_begin() {
	[ -n "$SITE_TXN_BAK" ] && return 0
	mkdir -p "$ONEBOX_DIR" || return 1
	local unit backup
	backup=$(mktemp -d "$ONEBOX_DIR/.site-rollback.XXXXXX") || return 1
	printf '%s\n' "$REALITY_SITE_DIR" >"$backup/site-path"
	printf '%s\n' "$REALITY_SITE_ROOT" >"$backup/root-path"
	_site_running && : >"$backup/running"
	unit=$(_site_unit_path)
	printf '%s\n' "$unit" >"$backup/unit-path"
	if [ -n "$unit" ] && [ -e "$unit" ]; then cp -p "$unit" "$backup/unit" || { rm -rf "$backup"; return 1; }; fi
	case "$INIT" in systemd) systemctl is-enabled --quiet "$SITE_SERVICE" 2>/dev/null && : >"$backup/enabled" ;; openrc) rc-update show default 2>/dev/null | grep -qw "$SITE_SERVICE" && : >"$backup/enabled" ;; esac
	if [ -d "$REALITY_SITE_DIR" ]; then cp -a "$REALITY_SITE_DIR" "$backup/site" || { rm -rf "$backup"; return 1; }; fi
	if [ -d "$REALITY_SITE_ROOT" ]; then cp -a "$REALITY_SITE_ROOT" "$backup/root" || { rm -rf "$backup"; return 1; }; fi
	_site_cron_lines >"$backup/cron" || { rm -rf "$backup"; return 1; }
	# Do not expose an incomplete snapshot to rollback: copy failure must never
	# cause the original website to be deleted while restoring a partial backup.
	SITE_TXN_BAK=$backup
	declare -F txn_traps >/dev/null && txn_traps
	return 0
}

site_check_dns() {
	local resolved own ip
	resolved=$(resolve_domain "$REALITY_SITE_DOMAIN")
	[ -n "$resolved" ] || { err "无法解析站点域名 ${REALITY_SITE_DOMAIN}"; return 1; }
	own=$(own_ip_list)
	[ -n "$own" ] || { err "无法确认本机公网地址，不能申请站点证书"; return 1; }
	while IFS= read -r ip; do
		printf '%s\n' "$own" | grep -qixF "$ip" || { err "域名 ${REALITY_SITE_DOMAIN} 的地址 ${ip} 不属于本机，请将全部 A/AAAA 直连本机并关闭 CDN 代理"; return 1; }
	done <<<"$resolved"
}

_site_cert_usable() {
	[ -s "$REALITY_SITE_DIR/cert.pem" ] && [ -s "$REALITY_SITE_DIR/key.pem" ] || return 1
	[ "$(cat "$REALITY_SITE_DIR/cert-domain" 2>/dev/null)" = "$REALITY_SITE_DOMAIN" ] || return 1
	openssl x509 -in "$REALITY_SITE_DIR/cert.pem" -checkend 3600 -noout >/dev/null 2>&1 &&
		openssl verify -untrusted "$REALITY_SITE_DIR/cert.pem" "$REALITY_SITE_DIR/cert.pem" >/dev/null 2>&1
}

site_issue_cert() (
	# Separate ACME account/home/renewal target; proxy TLS_* variables are untouched.
	ACME_HOME=$SITE_ACME_HOME ACME_SH="$SITE_ACME_HOME/acme.sh"
	acme_install "${ACME_EMAIL:-}" || exit 1
	local rc old
	old=$(cat "$REALITY_SITE_DIR/cert-domain" 2>/dev/null)
	if [ -n "$old" ] && [ "$old" != "$REALITY_SITE_DOMAIN" ]; then
		acme --remove -d "$old" --ecc >/dev/null 2>&1 || exit 1
	fi
	acme --issue -d "$REALITY_SITE_DOMAIN" --webroot "$REALITY_SITE_ROOT" -k ec-256 --server letsencrypt
	rc=$?
	[ "$rc" = 0 ] || [ "$rc" = 2 ] || exit "$rc"
	acme --install-cert -d "$REALITY_SITE_DOMAIN" --ecc --key-file "$REALITY_SITE_DIR/key.pem" --fullchain-file "$REALITY_SITE_DIR/cert.pem" --reloadcmd "$REALITY_SITE_DIR/reload.sh" || exit 1
	chmod 600 "$REALITY_SITE_DIR/key.pem" || exit 1
	printf '%s\n' "$REALITY_SITE_DOMAIN" >"$REALITY_SITE_DIR/cert-domain"
)

site_health() {
	local out
	_site_running || return 1
	# TLS1.3 and h2 must actually negotiate; config parsing alone is insufficient.
	out=$(printf '' | timeout 8 openssl s_client -connect "127.0.0.1:${REALITY_SITE_PORT}" -servername "$REALITY_SITE_DOMAIN" -tls1_3 -alpn h2 2>/dev/null) || return 1
	printf '%s\n' "$out" | grep -q 'ALPN protocol: h2' || { err "站点未成功协商 HTTP/2"; return 1; }
	curl --noproxy '*' -fsS --connect-timeout 3 --max-time 8 --resolve "${REALITY_SITE_DOMAIN}:${REALITY_SITE_PORT}:127.0.0.1" "https://${REALITY_SITE_DOMAIN}:${REALITY_SITE_PORT}/" -o /dev/null
}

_site_enable_unit() { case "$INIT" in systemd) systemctl enable "$SITE_SERVICE" >/dev/null 2>&1 ;; openrc) rc-update add "$SITE_SERVICE" default >/dev/null 2>&1 ;; none) return 0 ;; esac; }
_site_disable_unit() {
	local unit enabled
	unit=$(_site_unit_path)
	[ -n "$unit" ] && [ -f "$unit" ] || return 0
	case "$INIT" in
	systemd) systemctl disable "$SITE_SERVICE" >/dev/null 2>&1 ;;
	openrc)
		enabled=$(rc-update show default 2>/dev/null) || return 1
		printf '%s\n' "$enabled" | grep -qw "$SITE_SERVICE" || return 0
		rc-update del "$SITE_SERVICE" default >/dev/null 2>&1
		;;
	none) return 0 ;;
	*) return 1 ;;
	esac
}

_site_prepare_inner() {
	local signature needs_cert=0 old_port="" was_running=0 before hash fw_rc
	site_validate_ports && _site_paths_safe || return 1
	signature=$(_site_signature)
	_site_cert_usable || needs_cert=1
	# Re-generating unchanged proxy configs never depends on DNS/CA reachability.
	if [ "$needs_cert" = 0 ] && [ "$(cat "$REALITY_SITE_DIR/settings.sha256" 2>/dev/null)" = "$signature" ] && [ -f "$REALITY_SITE_DIR/nginx.conf" ] && [ -f "$REALITY_SITE_ROOT/index.html" ]; then
		if [ ! -f "$REALITY_SITE_DIR/.disabled" ] && _site_running && _site_cron_lines | grep -qF -- '--cron'; then
			# Upgrade legacy direct ACME jobs without restarting a healthy site.
			if ! _site_cron_lines | grep -qF -- 'cert-renew site --cron'; then
				_site_txn_begin && _site_cron_enable || return 1
			fi
			site_nginx_check
			return $?
		fi
		_site_txn_begin || return 1
		rm -f "$REALITY_SITE_DIR/.disabled"
		site_service start && _site_enable_unit && _site_cron_enable
		return $?
	fi
	[ "$needs_cert" = 0 ] || site_check_dns || return 1
	_site_running && was_running=1
	old_port=$(cat "$REALITY_SITE_DIR/local-port" 2>/dev/null)
	if port_in_use 80 tcp && [ "$was_running" != 1 ]; then err "TCP 80 已被其他服务使用，不能启用自有站点"; return 1; fi
	if port_in_use "$REALITY_SITE_PORT" tcp && { [ "$was_running" != 1 ] || [ "$old_port" != "$REALITY_SITE_PORT" ]; }; then err "站点内部 TLS 端口 ${REALITY_SITE_PORT} 已被占用"; return 1; fi
	if site_uses_https_proxy && port_in_use 443 tcp && ! _site_owns_https_listener && ! port_used_by_onebox 443 tcp; then
		err "TCP 443 已被其他程序占用，请先释放该端口或关闭网站 443 入口"
		return 1
	fi
	_site_txn_begin || return 1
	site_install_nginx && ensure_cmds timeout || return 1
	mkdir -p "$REALITY_SITE_DIR" "$REALITY_SITE_ROOT/.well-known/acme-challenge" || return 1
	chmod 700 "$REALITY_SITE_DIR" || return 1
	chmod 755 "$REALITY_SITE_ROOT" "$REALITY_SITE_ROOT/.well-known" "$REALITY_SITE_ROOT/.well-known/acme-challenge" || return 1
	: >"$REALITY_SITE_DIR/.onebox-site-owned"
	: >"$REALITY_SITE_ROOT/.onebox-site-owned"
	rm -f "$REALITY_SITE_DIR/.disabled"
	hash=""
	[ ! -f "$REALITY_SITE_ROOT/index.html" ] || hash=$(_site_hash <"$REALITY_SITE_ROOT/index.html")
	if [ ! -f "$REALITY_SITE_ROOT/index.html" ] || { [ -n "$hash" ] && [ "$hash" = "$(cat "$REALITY_SITE_DIR/index.sha256" 2>/dev/null)" ]; }; then
		site_render_index >"$REALITY_SITE_ROOT/index.html" || return 1
		chmod 644 "$REALITY_SITE_ROOT/index.html"
		_site_hash <"$REALITY_SITE_ROOT/index.html" >"$REALITY_SITE_DIR/index.sha256"
	fi
	if [ "$needs_cert" = 1 ]; then
		# Temporary local-only certificate makes nginx able to serve HTTP-01 webroot.
		(umask 077; openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 2 -subj "/CN=${REALITY_SITE_DOMAIN}" -keyout "$REALITY_SITE_DIR/key.pem" -out "$REALITY_SITE_DIR/cert.pem") >/dev/null 2>&1 || return 1
	fi
	# Prepare only HTTP-01 and loopback TLS while the old proxy core is running.
	# The public 443 listener is activated after apply_services stops old cores.
	site_write_nginx defer && _site_write_service || return 1
	before=$(_fw_snapshot)
	fw_rule open 80 tcp
	fw_rc=$?
	[ "$(_fw_snapshot)" = "$before" ] || : >"$SITE_TXN_BAK/fw80"
	[ "$fw_rc" = 0 ] || { err "站点 TCP 80 防火墙放行失败"; return 1; }
	site_service restart || return 1
	printf '0\n' >"$REALITY_SITE_DIR/frontend-port" || return 1
	if [ "$needs_cert" = 1 ]; then site_issue_cert || return 1; fi
	# nginx reload is asynchronous; allow old workers a short drain interval.
	local attempt healthy=0
	for attempt in 1 2 3; do
		if site_health; then healthy=1; break; fi
		[ "$attempt" = 3 ] || sleep 1
	done
	[ "$healthy" = 1 ] || { err "站点 HTTPS/TLS1.3/HTTP2 健康检查失败"; return 1; }
	printf '%s\n' "$signature" >"$REALITY_SITE_DIR/settings.sha256"
	printf '%s\n' "$REALITY_SITE_PORT" >"$REALITY_SITE_DIR/local-port"
	_site_enable_unit && _site_cron_enable
}

site_prepare() {
	if ! site_enabled; then
		[ ! -f "$REALITY_SITE_DIR/.onebox-site-owned" ] || _site_txn_begin
		return $?
	fi
	if _site_prepare_inner; then return 0; fi
	site_rollback
	return 1
}

site_apply_service() {
	if ! site_enabled; then site_service stop; return $?; fi
	if site_uses_https_proxy && [ "$(cat "$REALITY_SITE_DIR/frontend-port" 2>/dev/null)" != 443 ]; then
		# This also covers an interrupted preparation resumed by regen.
		_site_txn_begin || return 1
		site_write_nginx && site_service restart || return 1
		site_https_health || { err "网站 TCP 443 反代健康检查失败"; return 1; }
		printf '443\n' >"$REALITY_SITE_DIR/frontend-port" || return 1
	else
		site_nginx_check && site_service start
	fi
}

site_https_health() {
	curl --noproxy '*' -fsS --connect-timeout 3 --max-time 8 --resolve "${REALITY_SITE_DOMAIN}:443:127.0.0.1" "https://${REALITY_SITE_DOMAIN}/" -o /dev/null
}

site_commit() {
	[ -n "$SITE_TXN_BAK" ] || return 0
	if ! site_enabled && [ -f "$REALITY_SITE_DIR/.onebox-site-owned" ]; then
		site_service stop || return 1
		_site_disable_unit || { err "无法取消站点开机启动，保留事务以便回滚"; return 1; }
		_site_cron_remove || return 1
		: >"$REALITY_SITE_DIR/.disabled" || return 1
		info "自有站点已停用，页面与证书保留在 ${REALITY_SITE_ROOT}"
	fi
	rm -rf "$SITE_TXN_BAK"
	SITE_TXN_BAK=""
	# apply_all still has to restore firewall rules and write client files.
	# Its outer certificate transaction releases signal suppression at the end.
	return 0
}

# Copy into the destination filesystem before replacing the live directory.
# Keep the original snapshot until the ENTIRE rollback succeeds, so a second
# rollback after any later failure can safely restore both paths again.
_site_restore_directory() {
	local source=$1 target=$2 staging
	if [ ! -d "$source" ]; then rm -rf "$target"; return $?; fi
	staging=$(mktemp -d "${target%/*}/.onebox-restore.XXXXXX") || return 1
	if ! cp -a "$source" "$staging/content"; then rm -rf "$staging"; return 1; fi
	if ! rm -rf "$target" || ! mv -T "$staging/content" "$target"; then rm -rf "$staging"; return 1; fi
	rm -rf "$staging"
}

_site_rollback_inner() {
	local backup=$SITE_TXN_BAK unit had_running=0 current
	unit=$(cat "$backup/unit-path")
	[ ! -f "$backup/running" ] || had_running=1
	site_service stop >/dev/null 2>&1 || { err "无法停止站点进程，回滚备份保留在 $backup"; return 1; }
	_site_disable_unit || return 1
	_site_cron_remove || return 1
	# The directory paths were captured before changes, independent of loaded state.
	REALITY_SITE_DIR=$(cat "$backup/site-path")
	REALITY_SITE_ROOT=$(cat "$backup/root-path")
	SITE_ACME_HOME="$REALITY_SITE_DIR/acme"
	_site_restore_directory "$backup/site" "$REALITY_SITE_DIR" || { err "站点配置恢复失败，备份保留在 $backup"; return 1; }
	_site_restore_directory "$backup/root" "$REALITY_SITE_ROOT" || { err "站点内容恢复失败，备份保留在 $backup"; return 1; }
	if [ -n "$unit" ]; then
		if [ -f "$backup/unit" ]; then cp -p "$backup/unit" "$unit" || return 1; else rm -f "$unit" || return 1; fi
	fi
	[ "$INIT" != systemd ] || systemctl daemon-reload >/dev/null 2>&1 || return 1
	[ ! -f "$backup/enabled" ] || _site_enable_unit || return 1
	if [ -s "$backup/cron" ]; then
		has crontab || return 1
		current=$(_site_read_crontab) || return 1
		{ [ -z "$current" ] || printf '%s\n' "$current"; cat "$backup/cron"; } | crontab - || return 1
	fi
	if [ "$had_running" = 1 ]; then site_service start || { err "站点回滚后未能恢复运行，备份保留在 $backup"; return 1; }; fi
	[ ! -f "$backup/fw80" ] || fw_rule close 80 tcp || return 1
	rm -rf "$backup"
	SITE_TXN_BAK=""
	return 0
}

site_rollback() {
	[ -n "$SITE_TXN_BAK" ] && [ -d "$SITE_TXN_BAK" ] || return 0
	local ignored=0 rc
	[ "$(trap -p INT)" != "trap -- '' SIGINT" ] || ignored=1
	trap '' INT TERM HUP
	_site_rollback_inner
	rc=$?
	if [ "$ignored" = 0 ]; then declare -F txn_traps >/dev/null && txn_traps; fi
	return "$rc"
}

site_remove() {
	[ -f "$REALITY_SITE_DIR/.onebox-site-owned" ] || return 0
	site_service stop || return 1
	_site_disable_unit || return 1
	_site_cron_remove || return 1
	local unit
	unit=$(_site_unit_path)
	[ -z "$unit" ] || rm -f "$unit"
	[ "$INIT" != systemd ] || systemctl daemon-reload >/dev/null 2>&1
	[ ! -f "$REALITY_SITE_ROOT/.onebox-site-owned" ] || rm -rf "$REALITY_SITE_ROOT"
	rm -rf "$REALITY_SITE_DIR"
}

site_info() {
	site_enabled || return 0
	local port suffix=""
	port=$(site_public_port)
	[ "$port" = 443 ] || suffix=":${port}"
	printf '  自有站点   : https://%s%s/\n  页面文件   : %s/index.html\n  内部目标   : 127.0.0.1:%s (TLS1.3 + HTTP/2)\n' "$REALITY_SITE_DOMAIN" "$suffix" "$REALITY_SITE_ROOT" "$REALITY_SITE_PORT"
	if site_https_enabled; then
		if site_uses_https_proxy; then echo "  443 入口   : nginx HTTPS 反代 → 本机网站端口"; else echo "  443 入口   : 复用 REALITY 443 的网站回落"; fi
	fi
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
		# ip_is_private 不含 100.64.0.0/10 (阿里云元数据 100.100.100.200 / Tailscale) 等, 与 Xray 使用同一列表
		local own
		own=$(own_ip_cidrs)
		rules+=("      { \"ip_cidr\": [${PRIVATE_CIDRS}${own:+, ${own}}], \"action\": \"reject\" }")
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

# 本机的公网 / 全局地址: 代理用户经本机地址访问本机服务时会绕过防火墙与云安全组, 需一并屏蔽
own_ip_list() {
	{
		[ -n "${SERVER_IPV4:-}" ] && [ "${SERVER_IPV4_WARP:-0}" != 1 ] && printf '%s\n' "$SERVER_IPV4"
		[ -n "${SERVER_IPV6:-}" ] && [ "${SERVER_IPV6_WARP:-0}" != 1 ] && printf '%s\n' "$SERVER_IPV6"
		ip -o addr show scope global 2>/dev/null | awk '{sub(/\/.*/, "", $4); print $4}'
	} | grep -E '^[0-9a-fA-F:.]+$' | grep -E '\.|:' |
		grep -vE '^(10\.|127\.|169\.254\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|100\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\.|[fF][cCdD]|[fF][eE]80)' | sort -u
}

# own_ip_cidrs  -> JSON 字符串列表 (不含方括号), 例如 "1.2.3.4/32", "2001:db8::1/128"
own_ip_cidrs() {
	local ip out=""
	for ip in $(own_ip_list); do
		case "$ip" in *:*) out+="\"${ip}/128\", " ;; *) out+="\"${ip}/32\", " ;; esac
	done
	printf '%s' "${out%, }"
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
# 与 Xray 内置的私有/保留地址表 (common/geodata/consts.go, 26.4+ freedom 默认屏蔽所用) 保持一致; 不依赖 geoip.dat
# IPv4 映射地址 (::ffff:a.b.c.d) 会被 Xray 规范化为 IPv4, 无需单列; 不要加入 64:ff9b::/96 (纯 IPv6 VPS 的 NAT64)
readonly PRIVATE_CIDRS='"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/3", "::/127", "fc00::/7", "fe80::/10", "ff00::/8"'

# Vision 与 XHTTP 共用端口时, XHTTP 入站监听的 Linux 抽象 unix socket (不占用端口, 无文件权限问题)
XR_XHTTP_SOCK="${XR_XHTTP_SOCK:-@onebox-xhttp}"
# REALITY 防偷跑: REALITY 的 target 指向 127.0.0.1:REALITY_GUARD_PORT 上的 dokodemo-door, 仅放行 SNI=REALITY_SNI 的回落流量
# (dokodemo-door 不能监听 unix socket: 其 Network() 不含 unix, Xray 会静默跳过该入站)

xr_listen() { json_str "${LISTEN_ADDR:-0.0.0.0}"; }

# vless-reality 与 vless-xhttp 均由 Xray 承载且端口相同 -> XHTTP 作为 Vision 入站的回落
xr_xhttp_shared() {
	proto_enabled vless-reality && proto_enabled vless-xhttp &&
		[ "$(pget CORE vless-reality)" = xray ] && [ "$(pget CORE vless-xhttp)" = xray ] &&
		[ "$(pget PORT vless-reality)" = "$(pget PORT vless-xhttp)" ]
}

# 是否有 Xray 承载的 REALITY 入站
xr_has_reality() {
	local p
	for p in $PROTOCOLS; do
		proto_uses_reality "$p" && [ "$(pget CORE "$p")" = xray ] && return 0
	done
	return 1
}

xr_reality_guard() { [ -n "${REALITY_GUARD_PORT:-}" ] && xr_has_reality; }

_xr_reality() {
	local target=$REALITY_DEST
	xr_reality_guard && target="127.0.0.1:${REALITY_GUARD_PORT}"
	printf '"security": "reality",
        "realitySettings": {
          "target": %s,
          "serverNames": [%s],
          "privateKey": %s,
          "shortIds": [%s]
        }' "$(json_str "$target")" "$(json_str "$REALITY_SNI")" "$(json_str "$REALITY_PRIVATE_KEY")" "$(json_str "$REALITY_SHORT_ID")"
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
	local p=$1 port listen
	port=$(pget PORT "$p")
	listen=$(xr_listen)
	case "$p" in
	vless-reality)
		local fb=""
		xr_xhttp_shared && fb=",
        \"fallbacks\": [{ \"dest\": $(json_str "$XR_XHTTP_SOCK"), \"xver\": 1 }]"
		printf '    {
      "tag": "vless-reality-in",
      "listen": %s,
      "port": %s,
      "protocol": "vless",
      "settings": {
        "clients": [{ "id": %s, "flow": "xtls-rprx-vision", "email": "onebox" }],
        "decryption": "none"%s
      },
      "streamSettings": {
        "network": "raw",
        %s
      },
      %s
    }' "$listen" "$port" "$(json_str "$UUID")" "$fb" "$(_xr_reality)" "$XR_SNIFFING"
		;;
	vless-xhttp)
		if xr_xhttp_shared; then
			# 由 vless-reality 入站解密 REALITY 后回落至此 (h2c), PROXY protocol 传递真实客户端地址
			printf '    {
      "tag": "vless-xhttp-in",
      "listen": %s,
      "protocol": "vless",
      "settings": { "clients": [{ "id": %s, "email": "onebox" }], "decryption": "none" },
      "streamSettings": {
        "network": "xhttp",
        "xhttpSettings": { "path": %s, "mode": "auto" },
        "sockopt": { "acceptProxyProtocol": true }
      },
      %s
    }' "$(json_str "$XR_XHTTP_SOCK")" "$(json_str "$UUID")" "$(json_str "$XHTTP_PATH")" "$XR_SNIFFING"
		else
			printf '    {
      "tag": "vless-xhttp-in",
      "listen": %s,
      "port": %s,
      "protocol": "vless",
      "settings": { "clients": [{ "id": %s, "email": "onebox" }], "decryption": "none" },
      "streamSettings": {
        "network": "xhttp",
        "xhttpSettings": { "path": %s, "mode": "auto" },
        %s
      },
      %s
    }' "$listen" "$port" "$(json_str "$UUID")" "$(json_str "$XHTTP_PATH")" "$(_xr_reality)" "$XR_SNIFFING"
		fi
		;;
	vless-grpc)
		printf '    {
      "tag": "vless-grpc-in",
      "listen": %s,
      "port": %s,
      "protocol": "vless",
      "settings": { "clients": [{ "id": %s, "email": "onebox" }], "decryption": "none" },
      "streamSettings": {
        "network": "grpc",
        "grpcSettings": { "serviceName": %s },
        %s
      },
      %s
    }' "$listen" "$port" "$(json_str "$UUID")" "$(json_str "$GRPC_SERVICE")" "$(_xr_reality)" "$XR_SNIFFING"
		;;
	vless-ws)
		printf '    {
      "tag": "vless-ws-in",
      "listen": %s,
      "port": %s,
      "protocol": "vless",
      "settings": { "clients": [{ "id": %s, "email": "onebox" }], "decryption": "none" },
      "streamSettings": {
        "network": "ws",
        "wsSettings": { "path": %s },
        %s
      },
      %s
    }' "$listen" "$port" "$(json_str "$UUID")" "$(json_str "$WS_PATH")" "$(_xr_tls)" "$XR_SNIFFING"
		;;
	vmess-ws)
		local sec='"security": "none"'
		vmess_tls_enabled && sec=$(_xr_tls)
		printf '    {
      "tag": "vmess-ws-in",
      "listen": %s,
      "port": %s,
      "protocol": "vmess",
      "settings": { "clients": [{ "id": %s, "email": "onebox" }] },
      "streamSettings": {
        "network": "ws",
        "wsSettings": { "path": %s },
        %s
      },
      %s
    }' "$listen" "$port" "$(json_str "$UUID")" "$(json_str "$VMESS_PATH")" "$sec" "$XR_SNIFFING"
		;;
	trojan)
		printf '    {
      "tag": "trojan-in",
      "listen": %s,
      "port": %s,
      "protocol": "trojan",
      "settings": { "clients": [{ "password": %s, "email": "onebox" }] },
      "streamSettings": {
        "network": "raw",
        %s
      },
      %s
    }' "$listen" "$port" "$(json_str "$PASSWORD")" "$(_xr_tls '"h2", "http/1.1"')" "$XR_SNIFFING"
		;;
	shadowsocks)
		printf '    {
      "tag": "shadowsocks-in",
      "listen": %s,
      "port": %s,
      "protocol": "shadowsocks",
      "settings": { "method": %s, "password": %s, "network": "tcp,udp" },
      %s
    }' "$listen" "$port" "$(json_str "$SS_METHOD")" "$(json_str "$SS_PASSWORD")" "$XR_SNIFFING"
		;;
	hysteria2)
		# Xray >= 26.3.27. 注意: 认证只认 settings.clients[].auth (文档写的 users 与 hysteriaSettings.auth 在入站下均不生效);
		# 服务端必须显式 alpn h3, 否则所有客户端握手失败 (no application protocol)
		local obfs=""
		[ "$HY2_OBFS" = 1 ] && obfs=",
        \"finalmask\": { \"udp\": [{ \"type\": \"salamander\", \"settings\": { \"password\": $(json_str "$HY2_OBFS_PASSWORD") } }] }"
		printf '    {
      "tag": "hysteria2-in",
      "listen": %s,
      "port": %s,
      "protocol": "hysteria",
      "settings": { "version": 2, "clients": [{ "auth": %s, "email": "onebox" }] },
      "streamSettings": {
        "network": "hysteria",
        "hysteriaSettings": { "version": 2, "masquerade": { "type": "proxy", "url": "https://www.bing.com", "rewriteHost": true } },
        %s%s
      },
      %s
    }' "$listen" "$port" "$(json_str "$PASSWORD")" "$(_xr_tls '"h3"')" "$obfs" "$XR_SNIFFING"
		;;
	esac
}

# REALITY 防偷跑: 未通过 REALITY 认证的连接会被原样转发给 target; 若 target 是 CDN 站点,
# 任何人都能把本机当作该 CDN 的免费中转. 先经 dokodemo-door 嗅探 SNI, 只放行 REALITY_SNI (Xray-examples 官方模板)
xr_reality_guard_inbound() {
	printf '    {
      "tag": "reality-dest-in",
      "listen": "127.0.0.1",
      "port": %s,
      "protocol": "dokodemo-door",
      "settings": { "address": %s, "port": %s, "network": "tcp" },
      "sniffing": { "enabled": true, "destOverride": ["tls"], "routeOnly": true }
    }' "$REALITY_GUARD_PORT" "$(json_str "${REALITY_DEST%:*}")" "${REALITY_DEST##*:}"
}

gen_xray_server() {
	local p inbounds=() rules=() ds=AsIs direct_settings="" site_outbound="" guard_outbound=direct
	for p in $PROTOCOLS; do
		[ "$(pget CORE "$p")" = xray ] || continue
		inbounds+=("$(xr_inbound "$p")")
	done
	if xr_reality_guard; then
		inbounds+=("$(xr_reality_guard_inbound)")
		if site_enabled; then
			guard_outbound=reality-site
			site_outbound="    { \"tag\": \"reality-site\", \"protocol\": \"freedom\", \"settings\": { \"redirect\": $(json_str "127.0.0.1:${REALITY_SITE_PORT}"), \"finalRules\": [{ \"action\": \"allow\", \"network\": \"tcp\", \"ip\": [\"127.0.0.1/32\"], \"port\": $(json_str "$REALITY_SITE_PORT") }, { \"action\": \"block\" }] } },"
		fi
		rules+=("      { \"type\": \"field\", \"inboundTag\": [\"reality-dest-in\"], \"domain\": [$(json_str "full:${REALITY_SNI}")], \"outboundTag\": $(json_str "$guard_outbound") }")
		rules+=('      { "type": "field", "inboundTag": ["reality-dest-in"], "outboundTag": "block" }')
	fi
	[ "${BLOCK_BT:-1}" = 1 ] && rules+=('      { "type": "field", "protocol": ["bittorrent"], "outboundTag": "block" }')
	if [ "${BLOCK_PRIVATE:-1}" = 1 ]; then
		local own
		own=$(own_ip_cidrs)
		rules+=("      { \"type\": \"field\", \"ip\": [${PRIVATE_CIDRS}${own:+, ${own}}], \"outboundTag\": \"block\" }")
		ds=IPIfNonMatch # 仅在存在 IP 规则时才需要为域名解析 IP
	else
		# Xray >= 26.4 的 freedom 默认阻止 VLESS/VMess/Trojan/SS/Hysteria 入站访问私有地址, 关闭屏蔽时需显式放行
		# (26.3.27 会忽略未知字段 finalRules)
		direct_settings='"settings": { "finalRules": [{ "action": "allow" }] }, '
	fi
	cat <<EOF
{
  "log": { "loglevel": "warning", "access": "none" },
  "inbounds": [
$(json_join "${inbounds[@]}")
  ],
  "outbounds": [
    { "tag": "direct", "protocol": "freedom", ${direct_settings}"streamSettings": { "sockopt": { "domainStrategy": "$(xr_domain_strategy)" } } },
${site_outbound}
    { "tag": "block", "protocol": "blackhole" }
  ],
  "routing": {
    "domainStrategy": "${ds}",
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
# 两阶段写入: 先生成并校验全部内核的新配置 (*.new.json), 全部通过后再替换, 任一失败则不改动现有配置
_check_config() {
	# _check_config 内核 文件
	local out
	case "$1" in
	singbox) out=$("$SB_BIN" check -c "$2" 2>&1) ;;
	xray) out=$("$XR_BIN" run -test -c "$2" 2>&1) ;;
	esac || {
		err "$(core_title "$1") 配置校验失败:"
		printf '%s\n' "$out" | tail -n 15 >&2
		return 1
	}
}

prepare_server_configs() {
	local core conf fn tmp
	mkdir -p "$ONEBOX_DIR"
	for core in singbox xray; do
		core_used "$core" || continue
		conf=$(svc_conf "$core")
		tmp="${conf%.json}.new.json"
		case "$core" in singbox) fn=gen_singbox_server ;; xray) fn=gen_xray_server ;; esac
		(umask 077 && "$fn" >"$tmp") || {
			rm -f "$tmp"
			return 1
		}
		_check_config "$core" "$tmp" || {
			rm -f "${SB_CONF%.json}.new.json" "${XR_CONF%.json}.new.json"
			return 1
		}
	done
	return 0
}

commit_server_configs() {
	local core conf
	for core in singbox xray; do
		conf=$(svc_conf "$core")
		if core_used "$core"; then
			mv -f "${conf%.json}.new.json" "$conf" || return 1
		else
			rm -f "$conf" || return 1
		fi
	done
	return 0
}

write_server_configs() { prepare_server_configs && commit_server_configs; }

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
		local json vtls="" vsni="" valpn="" vfp="" vhost=${DOMAIN:-} vtrust=""
		if vmess_tls_enabled; then
			vtls=tls vsni=$(tls_server_name) valpn=http/1.1 vfp=chrome vhost=$(tls_server_name)
			# v2rayN VmessQRCode 支持 insecure / pcs; TLS 自签时必须随链接传递证书固定信息。
			if tls_insecure; then
				vtrust=",\"insecure\":\"1\",\"pcs\":$(json_str "$(cert_sha256)")"
			fi
		fi
		json=$(printf '{"v":"2","ps":%s,"add":%s,"port":"%s","id":"%s","aid":"0","scy":"auto","net":"ws","type":"none","host":%s,"path":%s,"tls":"%s","sni":%s,"alpn":"%s","fp":"%s"%s}' \
			"$(json_str "$(node_name "$p")")" "$(json_str "$SERVER_ADDR")" "$port" "$UUID" \
			"$(json_str "$vhost")" "$(json_str "$VMESS_PATH")" "$vtls" "$(json_str "$vsni")" "$valpn" "$vfp" "$vtrust")
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
# 内核版本要求 (按协议): AnyTLS >= 1.19.3, VLESS-XHTTP >= 1.19.22, Hysteria2 端口跳跃 >= 1.18.2
# YAML 单引号字符串
yq() {
	local q="'"
	printf "'%s'" "${1//$q/$q$q}"
}

_mh_tls_common() {
	# 证书类协议的 sni; 自签证书时跳过 CA 校验并固定证书指纹 (mihomo 在设置 fingerprint 时始终校验指纹)
	printf '    %s: %s\n' "${1:-sni}" "$(yq "$(tls_server_name)")"
	if tls_insecure; then
		printf '    skip-cert-verify: true\n'
		printf '    fingerprint: %s\n' "$(yq "$(cert_sha256)")"
	fi
	return 0
}

_mh_reality() {
	printf '    tls: true\n    servername: %s\n    client-fingerprint: chrome\n    reality-opts:\n      public-key: %s\n      short-id: %s\n      support-x25519mlkem768: true\n' \
		"$(yq "$REALITY_SNI")" "$(yq "$REALITY_PUBLIC_KEY")" "$(yq "$REALITY_SHORT_ID")"
}

# WebSocket 选项: 路径 / Host / 0-RTT 早期数据 (与 sing-box 服务端 max_early_data 2048 一致, Xray 服务端自动识别)
_mh_ws_opts() {
	printf '    ws-opts:\n      path: %s\n' "$(yq "$1")"
	[ -n "${2:-}" ] && printf '      headers:\n        Host: %s\n' "$(yq "$2")"
	printf '      max-early-data: 2048\n      early-data-header-name: Sec-WebSocket-Protocol\n'
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
		_mh_ws_opts "$WS_PATH" "$(tls_server_name)"
		;;
	vmess-ws)
		printf '    type: vmess\n    uuid: %s\n    alterId: 0\n    cipher: auto\n    network: ws\n    udp: true\n' "$UUID"
		if vmess_tls_enabled; then
			printf '    tls: true\n    client-fingerprint: chrome\n    alpn: [http/1.1]\n'
			_mh_tls_common servername
			_mh_ws_opts "$VMESS_PATH" "$(tls_server_name)"
		else
			printf '    tls: false\n'
			_mh_ws_opts "$VMESS_PATH" "${DOMAIN:-}"
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
		# 端口跳跃: 设置 ports 后客户端只在该范围内随机选端口 (port 仅作展示/兼容), 默认每 30 秒换一次
		[ -n "$HY2_HOP" ] && printf '    ports: %s\n    hop-interval: 30\n' "$(yq "$HY2_HOP")"
		[ "$HY2_OBFS" = 1 ] && printf '    obfs: salamander\n    obfs-password: %s\n' "$(yq "$HY2_OBFS_PASSWORD")"
		_mh_tls_common sni
		;;
	tuic)
		# 服务端未开启 0-RTT (zero_rtt_handshake=false), 客户端同样不启用 reduce-rtt
		printf '    type: tuic\n    uuid: %s\n    password: %s\n    alpn: [h3]\n    congestion-controller: bbr\n    udp-relay-mode: native\n' "$UUID" "$(yq "$PASSWORD")"
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

# 所需的最低 mihomo 内核版本 (取所含协议的最大值)
mh_min_version() {
	local v=1.18.2
	proto_enabled anytls && v=1.19.3
	proto_enabled vless-xhttp && v=1.19.22
	printf '%s' "$v"
}

# 外部控制 API 密钥: 由 UUID 派生, 重新生成配置时保持不变
# (未设密钥时, 默认 CORS 允许任意网页调用本机 API, 可直接 PUT /configs 替换整个配置)
# 外部控制 API 密钥: 随机生成并保存在状态中 (不能由分享链接中的 UUID 推导)
mh_secret() { printf '%s' "${CLASH_SECRET:-}"; }

gen_mihomo() {
	local p names=()
	for p in $PROTOCOLS; do
		proto_client_ok "$p" mihomo || continue
		names+=("$(node_name "$p")")
	done
	cat <<EOF
# Sing-Xray-Onebox 生成的 mihomo (Clash Meta) 配置
# 适用: Clash Verge Rev / Mihomo Party / FlClash / ClashMi / Clash Meta for Android 等
# 需要 mihomo 内核 >= $(mh_min_version), 请使用客户端最新版 (旧内核不认识 anytls 会拒绝整个配置; 1.19.22 之前 XHTTP 节点无法连接)
mixed-port: 7890
allow-lan: false
mode: rule
log-level: info
ipv6: true
unified-delay: true
tcp-concurrent: true
external-controller: 127.0.0.1:9090
secret: $(yq "$(mh_secret)")
EOF
	cat <<'EOF'
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
  skip-domain:
    - 'Mijia Cloud'
    - '+.push.apple.com'

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
  listen: 127.0.0.1:1053
  enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.1/16
  fake-ip-filter:
    - 'geosite:private'
    - 'geosite:connectivity-check'
    - '+.lan'
    - '+.local'
    - '+.home.arpa'
    - 'time.*.com'
    - 'ntp.*.com'
    - '+.pool.ntp.org'
    - '+.stun.*.*'
    - '+.stun.*.*.*'
    - '+.srv.nintendo.net'
    - '+.stun.playstation.net'
    - 'xbox.*.microsoft.com'
    - '+.xboxlive.com'
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
    'geosite:cn':
      - https://dns.alidns.com/dns-query
      - https://doh.pub/dns-query
    'geosite:geolocation-!cn':
      - 'https://dns.cloudflare.com/dns-query#节点选择'
      - 'https://dns.google/dns-query#节点选择'

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
  - GEOSITE,geolocation-!cn,节点选择
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
	[ ${#outs[@]} -gt 0 ] || return 1
	names=$(printf '%s, ' "${nodes[@]}")
	names=${names%, }
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
    "clash_api": { "external_controller": "127.0.0.1:9090", "secret": "$(mh_secret)", "default_mode": "Rule" }
  }
}
EOF
}

# ---------------------------------------------------------------------------
# 客户端: Xray
# ---------------------------------------------------------------------------
_xrc_reality() {
	# publicKey: 所有 Xray 版本通用 (password 为 25.x 新增的别名, 旧核心会报 empty publicKey)
	printf '"security": "reality", "realitySettings": { "serverName": %s, "fingerprint": "chrome", "publicKey": %s, "shortId": %s, "spiderX": "/" }' \
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
	hysteria2)
		# Xray 客户端 >= 26.1.13 支持 hysteria2 出站; 端口跳跃 (udpHop) / quicParams 需 >= 26.3.27
		local fm="" hop=""
		[ "$HY2_OBFS" = 1 ] && fm="\"udp\": [{ \"type\": \"salamander\", \"settings\": { \"password\": $(json_str "$HY2_OBFS_PASSWORD") } }]"
		[ -n "$HY2_HOP" ] && hop="\"quicParams\": { \"udpHop\": { \"ports\": $(json_str "$HY2_HOP"), \"interval\": \"25-35\" } }"
		[ -n "$fm" ] && [ -n "$hop" ] && fm+=", "
		fm+=$hop
		printf '    { "tag": "%s", "protocol": "hysteria", "settings": { "version": 2, "address": %s, "port": %s }, "streamSettings": { "network": "hysteria", "hysteriaSettings": { "version": 2, "auth": %s }, %s%s } }' \
			"$tag" "$addr" "$port" "$(json_str "$PASSWORD")" "$(_xrc_tls '"h3"')" "${fm:+, \"finalmask\": { ${fm} \}}"
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
	# 远程 DNS (DoH 1.1.1.1) 经默认出站 (即 proxy) 发出; 国内域名走 223.5.5.5 直连, 避免 DNS 泄露与污染
	cat <<EOF
{
  "log": { "loglevel": "warning" },
  "dns": {
    "servers": [
      "https://1.1.1.1/dns-query",
      { "address": "223.5.5.5", "domains": ["geosite:cn"], "expectIPs": ["geoip:cn"], "skipFallback": true }
    ],
    "queryStrategy": "UseIP"
  },
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
      { "type": "field", "ip": ["223.5.5.5"], "outboundTag": "direct" },
      { "type": "field", "ip": [${PRIVATE_CIDRS}], "outboundTag": "direct" },
      { "type": "field", "domain": ["geosite:category-ads-all"], "outboundTag": "block" },
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
	mkdir -p "$CLIENT_DIR" && chmod 700 "$CLIENT_DIR" || return 1
	local tmp p f failed=0 has_sb=0 has_xr=0
	tmp=$(mktemp -d "$CLIENT_DIR/.new.XXXXXX") || return 1
	for p in $PROTOCOLS; do
		proto_client_ok "$p" singbox && has_sb=1
		proto_client_ok "$p" xray && has_xr=1
	done
	gen_links >"$tmp/links.txt" || failed=1
	b64 <"$tmp/links.txt" >"$tmp/sub.txt" || failed=1
	gen_mihomo >"$tmp/mihomo.yaml" || failed=1
	if [ "$has_sb" = 1 ]; then
		gen_singbox_client tun >"$tmp/sing-box.json" || failed=1
		gen_singbox_client notun >"$tmp/sing-box-notun.json" || failed=1
	fi
	if [ "$has_xr" = 1 ]; then gen_xray_client >"$tmp/xray.json" || failed=1; fi
	if [ "$failed" = 0 ]; then chmod 600 "$tmp"/* || failed=1; fi
	if [ "$failed" = 0 ]; then
		for f in links.txt sub.txt mihomo.yaml sing-box.json sing-box-notun.json xray.json; do
			if [ -f "$tmp/$f" ]; then
				mv -f "$tmp/$f" "$CLIENT_DIR/$f" || { failed=1; break; }
			else
				rm -f "$CLIENT_DIR/$f" || { failed=1; break; }
			fi
		done
	fi
	rm -rf "$tmp"
	[ "$failed" = 0 ]
}

# ---------------------------------------------------------------------------
# 安装流程
# ---------------------------------------------------------------------------
# 预设组合: 编号|名称|协议列表|内核偏好
readonly PRESETS="1|推荐: Reality-Vision + Hysteria2 + TUIC (sing-box 单内核, TCP+UDP 互补)|vless-reality hysteria2 tuic|singbox
2|Xray 经典: Reality-Vision + XHTTP-Reality 共用 443 + SS-2022 (Xray 单内核)|vless-reality vless-xhttp shadowsocks|xray
3|双内核全能: Xray(Reality-Vision/XHTTP) + sing-box(Hysteria2/TUIC/AnyTLS)|vless-reality vless-xhttp hysteria2 tuic anytls|xray
4|sing-box 全家桶: Reality/gRPC/Trojan/SS/Hy2/TUIC/AnyTLS/ShadowTLS/VMess|vless-reality vless-grpc trojan shadowsocks hysteria2 tuic anytls shadowtls vmess-ws|singbox
5|CDN 组合: VLESS-WS-TLS + VMess-WS (建议使用域名)|vless-ws vmess-ws|singbox
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
	echo "  注: Xray 26 已将 gRPC/WS/VMess/Trojan/SS 标记为不推荐 (仍可用, 无移除计划), 建议由 sing-box 承载"
}

# 为每个协议分配内核
# Xray 的 Hysteria2 服务端较新 (26.3.27 起), 不参与自动分配, 仅在明确指定时 (--hy2-core xray / 添加协议时手动选择) 使用
proto_core_experimental() { [ "$1:$2" = hysteria2:xray ]; }

assign_cores() {
	local prefer=$1 p cores
	for p in $PROTOCOLS; do
		cores=$(proto_cores "$p")
		if proto_supports_core "$p" "$prefer" && ! proto_core_experimental "$p" "$prefer"; then
			pset CORE "$p" "$prefer"
		else
			pset CORE "$p" "${cores%% *}"
		fi
	done
	if proto_enabled hysteria2 && [ "${OPT_HY2_CORE:-}" = xray ]; then pset CORE hysteria2 xray; fi
	return 0
}

# 端口在本次配置中是否已被其他协议使用 (同为 TCP 或同为 UDP 视为冲突)
xr_can_share_port() {
	case "$1:$2" in
	vless-xhttp:vless-reality | vless-reality:vless-xhttp)
		[ "$(pget CORE vless-reality)" = xray ] && [ "$(pget CORE vless-xhttp)" = xray ] ;;
	*) return 1 ;;
	esac
}

port_taken_by_other() {
	local port=$1 net=$2 self=$3 p pp pn
	# REALITY 防偷跑用的本机 dokodemo 端口 (仅 127.0.0.1/TCP)
	[ "$net" != udp ] && [ "$port" = "${REALITY_GUARD_PORT:-}" ] && return 0
	for p in $PROTOCOLS; do
		[ "$p" = "$self" ] && continue
		pp=$(pget PORT "$p")
		[ "$pp" = "$port" ] || continue
		xr_can_share_port "$self" "$p" && continue
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
	proto_enabled hysteria2 && [ -n "$HY2_HOP" ] || return 1
	a=${HY2_HOP%-*} b=${HY2_HOP#*-}
	[ "$port" -ge "$a" ] && [ "$port" -le "$b" ]
}

# 端口是否正被本脚本已部署的协议以同一传输层 (tcp/udp) 使用 —— 重新配置时不算冲突
# port_used_by_onebox 端口 tcp|udp
port_used_by_onebox() {
	local port=$1 want=$2 var p pn
	[ -f "$STATE_FILE" ] || return 1
	for var in $(sed -n "s/^PORT_\([a-z0-9_]*\)=['\"]\{0,1\}${port}['\"]\{0,1\}\$/\1/p" "$STATE_FILE"); do
		p=${var//_/-}
		pn=$(proto_net "$p")
		[ "$pn" = both ] || [ "$pn" = "$want" ] && return 0
	done
	return 1
}

port_ok() {
	local port=$1 p=$2 net takeover=0
	net=$(proto_net "$p")
	[[ "$port" =~ ^[1-9][0-9]{0,4}$ ]] && [ "$port" -le 65535 ] || {
		warn "端口需为 1-65535 之间的数字"
		return 1
	}
	if site_enabled && [ "$net" != udp ] && { [ "$port" = 80 ] || [ "$port" = "$REALITY_SITE_PORT" ]; }; then
		warn "TCP ${port} 已保留给自有域名网站 (HTTP 80 / 本机 HTTPS ${REALITY_SITE_PORT})"
		return 1
	fi
	if site_https_enabled && [ "$port" = 443 ] && [ "$net" != udp ]; then
		proto_uses_reality "$p" || { warn "TCP 443 已保留给网站入口，可与 REALITY 共用"; return 1; }
	fi
	# A previously managed nginx listener is also released when HTTPS/the site
	# is being disabled; do not mistake it for an unrelated process then.
	if [ "$port" = 443 ] && [ "$net" != udp ] && _site_owns_https_listener; then takeover=1; fi
	if [ "$port" = 80 ] && [ "$net" != udp ] && [ "$TLS_MODE" = acme ] && [ "$ACME_METHOD" = standalone ]; then
		warn "TCP 80 端口需保留给 ACME HTTP 验证 (证书申请与续期)"
		return 1
	fi
	if port_taken_by_other "$port" "$net" "$p"; then
		warn "端口 ${port} 已分配给其他协议"
		return 1
	fi
	if [ "$p" != hysteria2 ] && [ "$net" != tcp ] && port_in_hop_range "$port"; then
		warn "端口 ${port} 位于 Hysteria2 端口跳跃范围 ${HY2_HOP} 内"
		return 1
	fi
	if [ "$net" != udp ] && [ "$takeover" != 1 ] && port_in_use "$port" tcp && ! port_used_by_onebox "$port" tcp; then
		warn "TCP 端口 ${port} 已被其他程序占用"
		return 1
	fi
	if [ "$net" != tcp ] && port_in_use "$port" udp && ! port_used_by_onebox "$port" udp; then
		warn "UDP 端口 ${port} 已被其他程序占用"
		return 1
	fi
	return 0
}

# REALITY 防偷跑用的本机 dokodemo-door 端口 (仅监听 127.0.0.1/TCP)
pick_guard_port() {
	local i port
	for i in $(seq 1 100); do
		port=$(rand_port)
		site_https_enabled && [ "$port" = 443 ] && continue
		site_enabled && [ "$port" = "$REALITY_SITE_PORT" ] && continue
		port_taken_by_other "$port" tcp "" && continue
		port_in_use "$port" tcp && continue
		printf '%s' "$port"
		return 0
	done
	return 1
}

default_port_for() {
	local p=$1 cand port i
	case "$p" in
	vless-reality | hysteria2 | anytls | trojan | shadowtls) cand="443 8443 2053 2083 2087 2096" ;;
	vless-xhttp) xr_can_share_port vless-xhttp vless-reality && cand=$(pget PORT vless-reality) ;;
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

# 不含 apple / icloud: Xray 会警告此类目标可能导致 IP 被封
readonly REALITY_SNI_LIST="www.microsoft.com addons.mozilla.org www.amazon.com dl.google.com www.tesla.com"

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
	[ "$_s_var" = REALITY_SNI ] && printf '    %d) 使用自己的域名 + 一键建站 (网页 / 正式证书 / 自动续期)\n' $((_s_i + 2))
	ask _s_ans "$_s_prompt (输入编号或域名)" "$_s_def"
	if [[ "$_s_ans" =~ ^[0-9]+$ ]]; then
		if [ "$_s_var" = REALITY_SNI ] && [ "$_s_ans" -eq $((_s_i + 2)) ]; then
			choose_owned_reality
			return $?
		fi
		if [ "$_s_ans" -ge 1 ] && [ "$_s_ans" -le "$_s_i" ]; then
			_s_ans=$(printf '%s\n' $REALITY_SNI_LIST | sed -n "${_s_ans}p")
		else
			_s_ans=""
		fi
	fi
	_s_ans=${_s_ans#https://}
	_s_ans=${_s_ans%%/*}
	valid_domain "$_s_ans" || ask_domain _s_ans "请输入自定义伪装域名" ""
	if [ "${ONEBOX_PLAN_ONLY:-0}" = 1 ]; then
		info "${_s_ans} 的 TLS 1.3 支持将在实际安装时检查"
	elif check_tls13 "$_s_ans"; then
		info "${_s_ans} 支持 TLS 1.3"
	else
		warn "无法确认 ${_s_ans} 支持 TLS 1.3 (可能是本机网络问题), 若连接失败请更换伪装站点"
	fi
	printf -v "$_s_var" '%s' "$_s_ans"
	[ "$_s_var" = REALITY_SNI ] && REALITY_SITE_ENABLED=0
	return 0
}

# 自有域名与 REALITY 共用公网入口, TLS 网站仅监听 loopback, 不把目标指回自身的 443。
choose_owned_reality() {
	local port i
	ask_domain REALITY_SITE_DOMAIN "请输入自己的域名 (A/AAAA 直连解析到本 VPS, 关闭 CDN 代理)" "${OPT_REALITY_SITE:-${REALITY_SITE_DOMAIN:-}}"
	REALITY_SITE_DOMAIN=${REALITY_SITE_DOMAIN,,}
	[ "${#REALITY_SITE_DOMAIN}" -le 253 ] || die "域名过长"
	ask REALITY_SITE_TITLE "网站标题 (会自动生成可编辑的个人主页)" "${OPT_SITE_TITLE:-${REALITY_SITE_TITLE:-山间手记}}"
	[ -n "$REALITY_SITE_TITLE" ] && [ "${#REALITY_SITE_TITLE}" -le 80 ] && [[ "$REALITY_SITE_TITLE" != *[[:cntrl:]]* ]] || die "网站标题需为 1-80 个字符且不含控制字符"
	if [ -z "${REALITY_SITE_PORT:-}" ]; then
		for i in $(seq 1 30); do
			case "$i" in 1) port=8444 ;; 2) port=9444 ;; *) port=$(rand_port) ;; esac
			[ "$port" = "${REALITY_GUARD_PORT:-}" ] && continue
			port_taken_by_other "$port" tcp "" && continue
			port_in_use "$port" tcp && continue
			REALITY_SITE_PORT=$port
			break
		done
	fi
	[ -n "$REALITY_SITE_PORT" ] || die "无法为网站分配本机 HTTPS 端口"
	REALITY_SITE_ENABLED=1
	REALITY_SNI=$REALITY_SITE_DOMAIN
	REALITY_DEST="127.0.0.1:${REALITY_SITE_PORT}"
	choose_site_https
	info "将生成网站并申请 Let's Encrypt 证书; 请放行 TCP 80 与 REALITY 对外端口"
}

choose_site_https() {
	local def=y
	[ "${REALITY_SITE_HTTPS:-}" != 0 ] || def=n
	case "${OPT_SITE_HTTPS:-}" in on) def=y ;; off) def=n ;; esac
	if ask_yn "是否启用网站域名的 HTTPS 443 入口 (反代到网站端口；已有 REALITY 443 时自动复用)" "$def"; then
		REALITY_SITE_HTTPS=1
		info "网站地址将为 https://${REALITY_SITE_DOMAIN}/，请放行 TCP 443"
	else
		REALITY_SITE_HTTPS=0
	fi
}

choose_reality_target() {
	if [ -n "${OPT_REALITY_SITE:-}" ]; then
		choose_owned_reality
	else
		local def=${OPT_SNI:-${REALITY_SNI:-1}}
		if site_enabled && [ -z "${OPT_SNI:-}" ]; then def=$(($(printf '%s\n' $REALITY_SNI_LIST | wc -l) + 2)); fi
		choose_sni REALITY_SNI "REALITY 目标站点" "$def"
	fi
	if site_enabled; then
		REALITY_DEST="127.0.0.1:${REALITY_SITE_PORT}"
	else
		if [ -n "${REALITY_SITE_DOMAIN:-}" ] && [ "$REALITY_SNI" = "$REALITY_SITE_DOMAIN" ] && [ -z "${OPT_REALITY_DEST:-}" ]; then
			die "该域名是本机托管网站, 请选择使用自己的域名 + 一键建站, 避免 REALITY 目标指向自身公网端口"
		fi
		REALITY_DEST="${OPT_REALITY_DEST:-${REALITY_SNI}:443}"
	fi
	[ -z "${OPT_SITE_HTTPS:-}" ] || site_enabled || die "--site-https 需要先启用自有域名网站"
}

# ShadowTLS 独立使用外部握手站点, 不能默认继承直连本机的自有域名。
choose_shadowtls_target() {
	local def=${SHADOWTLS_SNI:-${REALITY_SNI:-${OPT_SNI:-1}}}
	if site_enabled && [ -z "${SHADOWTLS_SNI:-}" ]; then def=1; fi
	while :; do
		choose_sni SHADOWTLS_SNI "ShadowTLS 握手站点" "$def"
		if [ -z "${REALITY_SITE_DOMAIN:-}" ] || [ "${SHADOWTLS_SNI,,}" != "${REALITY_SITE_DOMAIN,,}" ]; then break; fi
		warn "该域名指向本机自有网站, 不能用作 ShadowTLS 外部握手站点, 请选择其他域名"
		is_interactive || die "ShadowTLS 握手站点不能使用本机自有域名"
		def=1
	done
	SHADOWTLS_DEST="${SHADOWTLS_SNI}:443"
}

choose_tls() {
	local m d
	any_needs_cert || proto_enabled vmess-ws || {
		TLS_MODE=""
		return 0
	}
	title "TLS 证书"
	echo "  以下协议需要 (或可选) TLS 证书: $(for p in $PROTOCOLS; do { proto_needs_cert "$p" || [ "$p" = vmess-ws ]; } && printf '%s ' "$(proto_title "$p")"; done)"
	echo "    1) 自签证书 (无需域名, 客户端通过证书指纹校验) [默认]"
	echo "    2) ACME 申请正式证书 —— HTTP 验证 (域名需已解析到本机, 且 80 端口空闲)"
	echo "    3) ACME 申请正式证书 —— Cloudflare DNS API 验证"
	echo "    4) 使用已有证书文件"
	ask_num m "请选择" "${OPT_TLS_CHOICE:-1}" 1 4 || m=1
	case "$m" in
	1)
		TLS_MODE=self
		ask_domain TLS_SNI "自签证书使用的域名 (SNI)" "${OPT_SNI_SELF:-www.bing.com}"
		;;
	2 | 3)
		TLS_MODE=acme
		ask_domain DOMAIN "请输入已解析到本机的域名" "${OPT_DOMAIN:-}"
		TLS_SNI=$DOMAIN
		if [ "$m" = 2 ]; then
			ACME_METHOD=standalone
			if [ "${ONEBOX_PLAN_ONLY:-0}" != 1 ]; then
				[ -n "$SERVER_IPV4$SERVER_IPV6" ] || detect_public_ip
				if ! check_domain_points_here "$DOMAIN"; then
					confirm "域名解析似乎未指向本机 (若开启了 CDN 代理请先关闭), 仍然继续?" n || die "已取消"
				fi
			fi
		else
			ACME_METHOD=cf
			if [ "${ONEBOX_PLAN_ONLY:-0}" != 1 ] && [ -z "${CF_Token:-}" ] && { [ -z "${CF_Key:-}" ] || [ -z "${CF_Email:-}" ]; }; then
				while :; do
					ask_secret d "Cloudflare API Token (需 Zone.DNS 编辑权限, 输入不回显)"
					[ -n "$d" ] && break
					is_interactive || die "未提供 Cloudflare API Token (请设置环境变量 CF_Token)"
				done
				# 不 export: 仅在调用 acme.sh 时传入 (见 cert_acme), 避免泄露给之后启动的内核进程
				CF_Token=$d
				ask d "Cloudflare Account ID (可留空)" ""
				[ -n "$d" ] && CF_Account_ID=$d
			fi
		fi
		;;
	4)
		TLS_MODE=custom
		ask_domain DOMAIN "证书对应的域名" "${OPT_DOMAIN:-}"
		TLS_SNI=$DOMAIN
		ask CUSTOM_CERT "证书文件路径 (fullchain)" ""
		ask CUSTOM_KEY "私钥文件路径" ""
		;;
	esac
}

# ---------------------------------------------------------------------------
# 证书变更事务: 备份 TLS 目录并记录旧的 ACME 域名; 新配置成功应用后提交, 失败时恢复
# ---------------------------------------------------------------------------
CERT_TXN_BAK="" CERT_TXN_OLD_ACME="" CERT_TXN_NEW_ACME="" CERT_TXN_ACME_D=""

# 信号处理: 证书事务进行中 (新配置尚未提交) 时, Ctrl-C 等中断先回滚事务再退出;
# 事务结束后恢复默认. apply_all 提交配置后会屏蔽中断, 直到调用方提交 / 回滚事务
txn_traps() {
	if [ -n "$CERT_TXN_BAK${SITE_TXN_BAK:-}" ]; then
		trap 'trap "" INT TERM HUP; cert_txn_rollback; exit 130' INT TERM HUP
	else
		trap - INT TERM HUP
	fi
}

cert_txn_begin() {
	# Nested preparation must retain the earliest complete snapshot.
	[ -n "$CERT_TXN_BAK" ] && return 0
	local staging old_acme="" backup="$ONEBOX_DIR/.tls-rollback"
	mkdir -p "$ONEBOX_DIR" || return 1
	staging=$(mktemp -d "$ONEBOX_DIR/.cert-snapshot.XXXXXX") || return 1
	if [ -d "$TLS_DIR" ]; then
		cp -a "$TLS_DIR" "$staging/tls" || { rm -rf "$staging"; err "无法完整备份 TLS 证书，已取消变更"; return 1; }
	else
		mkdir -p "$staging/tls" || { rm -rf "$staging"; return 1; }
	fi
	# acme.sh may persist API credentials even on issuance failure.
	if [ -f "$ACME_HOME/account.conf" ]; then
		cp -p "$ACME_HOME/account.conf" "$staging/account.conf" || { rm -rf "$staging"; err "无法备份 ACME 账户配置，已取消变更"; return 1; }
	else
		: >"$staging/account.absent" || { rm -rf "$staging"; return 1; }
	fi
	[ ! -f "$STATE_FILE" ] || old_acme=$(
		load_state >/dev/null 2>&1
		[ "$TLS_MODE" = acme ] && printf '%s' "$DOMAIN"
	)
	# Commit may remove this previous domain's renewal before switching to a
	# new domain/self-signed certificate. Keep its deployment reversible too.
	if [ -n "$old_acme" ] && [ -d "$ACME_HOME/${old_acme}_ecc" ]; then
		cp -a "$ACME_HOME/${old_acme}_ecc" "$staging/old-deployment" || { rm -rf "$staging"; err "无法备份旧域名的续期部署，已取消变更"; return 1; }
	fi
	if ! rm -rf "$backup" "$ONEBOX_DIR/.acme-rollback" "$ONEBOX_DIR/.acme-account.rollback" "$ONEBOX_DIR/.acme-account.absent.rollback" "$ONEBOX_DIR/.acme-old.rollback" ||
		! mv "$staging/tls" "$backup"; then
		rm -rf "$staging"
		err "无法保存 TLS 证书备份，已取消变更"
		return 1
	fi
	if { [ -f "$staging/account.absent" ] && ! mv "$staging/account.absent" "$ONEBOX_DIR/.acme-account.absent.rollback"; } ||
		{ [ -d "$staging/old-deployment" ] && ! mv "$staging/old-deployment" "$ONEBOX_DIR/.acme-old.rollback"; }; then
		rm -rf "$staging" "$backup" "$ONEBOX_DIR/.acme-account.rollback" "$ONEBOX_DIR/.acme-account.absent.rollback" "$ONEBOX_DIR/.acme-old.rollback"
		err "无法保存完整的 ACME 备份，已取消变更"
		return 1
	fi
	if [ -f "$staging/account.conf" ] && ! mv "$staging/account.conf" "$ONEBOX_DIR/.acme-account.rollback"; then
		rm -rf "$staging" "$backup"
		err "无法保存 ACME 账户备份，已取消变更"
		return 1
	fi
	rm -rf "$staging"
	# Only a fully prepared snapshot may activate destructive rollback.
	CERT_TXN_BAK=$backup
	CERT_TXN_FW80=0
	CERT_TXN_OLD_ACME=$old_acme CERT_TXN_NEW_ACME="" CERT_TXN_ACME_D=""
	# 旧版本 (无防火墙台账) 升级: 在证书申请改动防火墙之前先迁移台账
	[ -f "$STATE_FILE" ] && [ ! -f "$(_fw_ledger)" ] && (load_state && _fw_ledger_migrate) >/dev/null 2>&1
	txn_traps
	return 0
}

cert_txn_commit() {
	# 不再使用旧域名的 ACME 证书时, 取消其自动续期; 否则续期时 acme.sh 会覆盖新证书 (导致固定指纹的客户端全部失效)
	# Do this BEFORE site_commit discards its rollback snapshot. A removed
	# deployment is safe to skip on retry and is restored from .acme-old.rollback.
	if [ -n "$CERT_TXN_BAK" ] && [ -n "$CERT_TXN_OLD_ACME" ] && { [ "$TLS_MODE" != acme ] || [ "$DOMAIN" != "$CERT_TXN_OLD_ACME" ]; } &&
		[ -f "$ACME_HOME/${CERT_TXN_OLD_ACME}_ecc/${CERT_TXN_OLD_ACME}.conf" ]; then
		if [ ! -x "$ACME_SH" ] || ! acme --remove -d "$CERT_TXN_OLD_ACME" --ecc >/dev/null 2>&1; then
			err "无法停止旧域名证书续期，已保留备份并取消提交"
			return 1
		fi
		info "已停止旧域名 ${CERT_TXN_OLD_ACME} 的证书自动续期"
	fi
	site_commit || return 1
	[ -n "$CERT_TXN_BAK" ] || { txn_traps; return 0; }
	rm -rf "$CERT_TXN_BAK" "$ONEBOX_DIR/.acme-rollback" "$ONEBOX_DIR/.acme-account.rollback" "$ONEBOX_DIR/.acme-account.absent.rollback" "$ONEBOX_DIR/.acme-old.rollback"
	CERT_TXN_BAK="" CERT_TXN_ACME_D="" CERT_TXN_NEW_ACME="" CERT_TXN_OLD_ACME=""
	txn_traps
	return 0
}

_cert_txn_rollback_inner() {
	local mode=${1:-} need80=0 tmp
	# 新申请的 ACME 域名 (与旧的不同) 取消部署, 防止其续期覆盖恢复后的证书
	if [ -n "$CERT_TXN_NEW_ACME" ] && [ "$CERT_TXN_NEW_ACME" != "$CERT_TXN_OLD_ACME" ] &&
		[ -f "$ACME_HOME/${CERT_TXN_NEW_ACME}_ecc/${CERT_TXN_NEW_ACME}.conf" ]; then
		[ -x "$ACME_SH" ] && acme --remove -d "$CERT_TXN_NEW_ACME" --ecc >/dev/null 2>&1 || return 1
	fi
	# 事先已存在的 acme.sh 部署: 恢复其原配置 (本次可能以新的验证方式强制重新签发过)
	if [ -n "$CERT_TXN_ACME_D" ] && [ -d "$ONEBOX_DIR/.acme-rollback" ]; then
		mkdir -p "$ACME_HOME" || return 1
		_site_restore_directory "$ONEBOX_DIR/.acme-rollback" "$ACME_HOME/${CERT_TXN_ACME_D}_ecc" || return 1
	fi
	if [ -n "$CERT_TXN_OLD_ACME" ] && [ -d "$ONEBOX_DIR/.acme-old.rollback" ]; then
		mkdir -p "$ACME_HOME" || return 1
		_site_restore_directory "$ONEBOX_DIR/.acme-old.rollback" "$ACME_HOME/${CERT_TXN_OLD_ACME}_ecc" || return 1
	fi
	if [ -f "$ONEBOX_DIR/.acme-account.rollback" ]; then
		mkdir -p "$ACME_HOME" || return 1
		tmp=$(mktemp "$ACME_HOME/.onebox-account.XXXXXX") || return 1
		if ! cp -p "$ONEBOX_DIR/.acme-account.rollback" "$tmp" || ! mv -f "$tmp" "$ACME_HOME/account.conf"; then rm -f "$tmp"; return 1; fi
	elif [ -f "$ONEBOX_DIR/.acme-account.absent.rollback" ]; then
		rm -f "$ACME_HOME/account.conf" || return 1
	fi
	_site_restore_directory "$CERT_TXN_BAK" "$TLS_DIR" || return 1
	# 用恢复后的状态与证书重新生成客户端文件并重启内核
	if [ -f "$STATE_FILE" ]; then
		load_state || return 1
		# apply_all restores the exact client-file snapshot and restarts services
		# itself. Other callers must surface failures and retain retryable backups.
		if [ "$mode" != --files-only ]; then
			write_client_files || return 1
			all_cores_do restart || return 1
		fi
		{ [ "$TLS_MODE" = acme ] && [ "$ACME_METHOD" = standalone ]; } && need80=1
		port_taken_by_other 80 tcp "" && need80=1
	fi
	# 本次申请临时放行的 80 端口, 恢复后的配置 (磁盘上的状态) 不再需要时关闭
	site_enabled && need80=1
	if [ "${CERT_TXN_FW80:-0}" = 1 ] && [ "$need80" = 0 ]; then fw_rule close 80 tcp || return 1; fi
	return 0
}

cert_txn_rollback() {
	# Do not continue or report success after an incomplete website rollback.
	trap '' INT TERM HUP
	site_rollback || { txn_traps; return 1; }
	[ -n "$CERT_TXN_BAK" ] && [ -d "$CERT_TXN_BAK" ] || {
		CERT_TXN_BAK=""
		txn_traps
		return 0
	}
	if ! _cert_txn_rollback_inner "${1:-}"; then
		err "证书、续期配置或服务尚未完全恢复，备份保留在 $CERT_TXN_BAK"
		txn_traps
		return 1
	fi
	rm -rf "$CERT_TXN_BAK" "$ONEBOX_DIR/.acme-rollback" "$ONEBOX_DIR/.acme-account.rollback" "$ONEBOX_DIR/.acme-account.absent.rollback" "$ONEBOX_DIR/.acme-old.rollback"
	CERT_TXN_BAK="" CERT_TXN_ACME_D="" CERT_TXN_NEW_ACME="" CERT_TXN_OLD_ACME=""
	txn_traps
	return 0
}

# 旧版本升级时补齐新增的状态项; 有变化时立即保存 (回滚路径也会调用)
state_migrate() {
	local changed=0
	if [ -z "${CLASH_SECRET:-}" ]; then
		CLASH_SECRET=$(rand_str 24)
		changed=1
	fi
	if xr_has_reality && [ -z "${REALITY_GUARD_PORT:-}" ]; then
		REALITY_GUARD_PORT=$(pick_guard_port)
		changed=1
	fi
	[ "$changed" = 1 ] && [ -f "$STATE_FILE" ] && save_state
	return 0
}

obtain_cert() {
	local rc
	site_prepare || return 1
	case "$TLS_MODE" in
	self) cert_self_signed "$TLS_SNI" ;;
	acme) cert_acme "$DOMAIN" "$ACME_METHOD" ;;
	custom) cert_custom "$CUSTOM_CERT" "$CUSTOM_KEY" ;;
	*) return 0 ;;
	esac
	rc=$?
	return "$rc"
}

# 网站启停时迁移主代理证书的 HTTP 验证方式, 防止旧 standalone 续期争抢 80。
prepare_site_and_renewal() {
	site_prepare || return 1
	[ "$TLS_MODE" = acme ] && [ "$ACME_METHOD" = standalone ] || return 0
	local conf="$ACME_HOME/${DOMAIN}_ecc/${DOMAIN}.conf" stored want=no
	[ -f "$conf" ] || return 0
	stored=$(sed -n "s/^Le_Webroot='\\{0,1\\}\\([^']*\\)'\\{0,1\\}$/\\1/p" "$conf" | head -n1)
	site_enabled && want=$REALITY_SITE_ROOT
	[ "$stored" = "$want" ] && return 0
	# 只迁移本功能涉及的 standalone / 自有网站 webroot, 不接管其他工具的部署。
	if site_enabled || [ "$stored" = "$REALITY_SITE_ROOT" ]; then
		[ -n "$CERT_TXN_BAK" ] || cert_txn_begin || return 1
		if ! site_enabled; then site_service stop || return 1; fi
		cert_acme "$DOMAIN" standalone || return 1
	fi
	return 0
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
	[ -z "${OPT_REALITY_SITE:-}" ] || any_reality || die "--reality-site 需要至少启用一个 REALITY 协议"
	if any_reality; then
		title "REALITY 伪装站点"
		choose_reality_target
	fi
	[ -z "${OPT_SITE_HTTPS:-}" ] || site_enabled || die "--site-https 需要先启用自有域名网站"
	if proto_enabled shadowtls; then
		title "ShadowTLS 握手站点"
		choose_shadowtls_target
	fi
	proto_enabled hysteria2 && choose_hy2_opts
}

# Hysteria2 混淆 / 端口跳跃 (安装与添加协议时使用)
choose_hy2_opts() {
	local r
	title "Hysteria2 选项"
	HY2_OBFS=0 HY2_HOP=""
	if ask_yn "是否启用 Salamander 混淆 (可对抗 QUIC 识别, 但会失去 HTTP/3 伪装)" "${OPT_HY2_OBFS:-n}"; then
		HY2_OBFS=1
	fi
	if [ "$INIT" = none ]; then
		[ -n "${OPT_HY2_HOP:-}" ] && warn "未检测到 systemd / OpenRC, 无法在开机时恢复端口跳跃规则, 已忽略 --hy2-hop"
		return 0
	fi
	ask_yn "是否启用端口跳跃 (UDP 端口范围转发到 Hysteria2 端口)" "$([ -n "${OPT_HY2_HOP:-}" ] && echo y || echo n)" || return 0
	while :; do
		ask r "端口跳跃范围 (起始-结束)" "${OPT_HY2_HOP:-20000-40000}"
		if [[ "$r" =~ ^([1-9][0-9]*)-([1-9][0-9]*)$ ]] && [ "${BASH_REMATCH[1]}" -ge 1024 ] && [ "${BASH_REMATCH[2]}" -le 65535 ] &&
			[ "${BASH_REMATCH[1]}" -lt "${BASH_REMATCH[2]}" ]; then
			local c
			if c=$(hop_range_conflicts "$r"); then
				# 范围内的 UDP 流量会被转发到 Hysteria2, 不能包含其他 UDP 协议的端口
				warn "端口跳跃范围 ${r} 包含其他 UDP 协议的端口: ${c}"
				is_interactive || die "端口跳跃范围与现有端口冲突: ${c}"
				continue
			fi
			if c=$(hop_range_foreign_udp "$r"); then
				warn "端口跳跃范围内有其他程序监听的 UDP 端口 (${c}), 发往这些端口的流量将被转发到 Hysteria2"
				if is_interactive && ! ask_yn "仍然使用该范围?" y; then continue; fi
			fi
			HY2_HOP=$r
			return 0
		fi
		warn "格式错误, 示例: 20000-40000"
		is_interactive || die "端口跳跃范围无效: $r"
	done
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
	elif site_enabled; then
		def=$REALITY_SITE_DOMAIN
	elif [ -n "$SERVER_IPV4" ] && [ "${SERVER_IPV4_WARP:-0}" != 1 ]; then
		def=$SERVER_IPV4
	elif [ -n "$SERVER_IPV6" ] && [ "${SERVER_IPV6_WARP:-0}" != 1 ]; then
		def=$SERVER_IPV6
	else
		def=${SERVER_IPV4:-$SERVER_IPV6}
	fi
	# 修改地址时默认保留当前值
	def=${OPT_ADDR:-${SERVER_ADDR:-$def}}
	while :; do
		ask SERVER_ADDR "客户端连接使用的地址 (IP 或域名)" "$def"
		SERVER_ADDR=${SERVER_ADDR#*://}
		SERVER_ADDR=${SERVER_ADDR%%/*}
		SERVER_ADDR=${SERVER_ADDR#[}
		SERVER_ADDR=${SERVER_ADDR%]}
		if valid_ipv4 "$SERVER_ADDR" || valid_ipv6 "$SERVER_ADDR" || valid_domain "$SERVER_ADDR"; then
			break
		fi
		[ -n "$SERVER_ADDR" ] && warn "地址无效 (只填 IP 或域名, 不带端口): ${SERVER_ADDR}"
		is_interactive || die "无法确定客户端连接地址, 请使用 --addr 指定 IP 或域名"
	done
	local h
	h=$(hostname 2>/dev/null | cut -d. -f1 | LC_ALL=C tr -cd 'A-Za-z0-9_-')
	ask NODE_NAME "节点名称前缀" "${OPT_NAME:-${NODE_NAME:-${h:-onebox}}}"
	NODE_NAME=$(printf '%s' "$NODE_NAME" | tr -d '#&=?/\\"'"'"' ,:;|')
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
	site_enabled && echo "  自有网站: ${REALITY_SITE_DOMAIN} → ${REALITY_DEST} (网页 + Let's Encrypt + 自动续期)"
	site_https_enabled && echo "  网站入口: https://${REALITY_SITE_DOMAIN}/ (TCP 443，自动选择反代或 REALITY 回落)"
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
	REALITY_GUARD_PORT=$(pick_guard_port)
	CLASH_SECRET=$(rand_str 24)
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
	[ -n "$REALITY_GUARD_PORT" ] || REALITY_GUARD_PORT=$(pick_guard_port)
	[ -n "$CLASH_SECRET" ] || CLASH_SECRET=$(rand_str 24)
	return 0
}

ensure_cores() {
	local core
	for core in singbox xray; do
		core_used "$core" || continue
		case "$core" in
		# 已安装的内核不在这里替换 (没有备份 / 回滚); 版本不一致时提示使用 onebox update
		singbox)
			if [ ! -x "$SB_BIN" ] || [ "${FORCE_CORE_UPDATE:-0}" = 1 ]; then
				install_singbox "${SB_VERSION_WANT:-}" || return 1
			elif [ -n "${SB_VERSION_WANT:-}" ] && [ "$SB_VERSION_WANT" != "$(sb_installed_version)" ]; then
				warn "已安装 sing-box $(sb_installed_version), 如需更换版本请执行: onebox update singbox ${SB_VERSION_WANT}"
			fi
			;;
		xray)
			if [ ! -x "$XR_BIN" ] || [ "${FORCE_CORE_UPDATE:-0}" = 1 ]; then
				install_xray || return 1
			elif [ -n "${XR_VERSION_WANT:-}" ] && [ "$XR_VERSION_WANT" != "$(xr_installed_version)" ]; then
				warn "已安装 Xray $(xr_installed_version), 如需更换版本请执行: onebox update xray ${XR_VERSION_WANT}"
			fi
			;;
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

# 恢复已完整建立的快照。恢复失败保留快照, 不将缺失/不完整备份视为原文件不存在。
_apply_restore_files() {
	local bak=$1 f restore failed=0
	[ -f "$bak/complete" ] || return 1
	for f in "$STATE_FILE" "$SB_CONF" "$XR_CONF"; do
		if [ -f "$bak/${f##*/}" ]; then
			restore=$(mktemp "${f}.restore.XXXXXX") || { failed=1; continue; }
			if ! cp -p "$bak/${f##*/}" "$restore" || ! mv -f "$restore" "$f"; then failed=1; rm -f "$restore"; fi
		else
			rm -f "$f" || failed=1
		fi
	done
	if [ -d "$bak/client" ]; then
		restore=$(mktemp -d "$ONEBOX_DIR/.client-restore.XXXXXX") || return 1
		if cp -a "$bak/client/." "$restore/" && rm -rf "$CLIENT_DIR" && mv "$restore" "$CLIENT_DIR"; then :; else failed=1; rm -rf "$restore"; fi
	else
		rm -rf "$CLIENT_DIR" || failed=1
	fi
	[ "$failed" = 0 ]
}

_apply_rollback() {
	local bak=$1 had_old=$2 failed=0 core
	# The old website may need 443 currently held by a newly started core.
	for core in singbox xray; do
		if svc_exists "$core"; then svc_stop "$core" || failed=1; fi
	done
	# 尽量撤销新规则, 然后根据旧状态重新放行; 每一步都保留失败信息。
	fw_apply close || failed=1
	hop_rules del || failed=1
	_apply_restore_files "$bak" || failed=1
	if [ "$had_old" = 1 ]; then
		if load_state; then
			cert_txn_rollback --files-only || failed=1
			apply_services || failed=1
			fw_apply open || failed=1
			hop_setup || failed=1
		else
			failed=1
			cert_txn_rollback --files-only || failed=1
		fi
	else
		svc_remove singbox || failed=1
		svc_remove xray || failed=1
		net_persist del || failed=1
		if [ "$INIT" = none ]; then _none_autostart_del || failed=1; fi
		cert_txn_rollback --files-only || failed=1
	fi
	if [ "$failed" = 0 ]; then
		rm -rf "$bak"
	else
		warn "自动恢复尚未全部完成, 已保留原始文件备份: $bak"
	fi
	txn_traps
	[ "$failed" = 0 ]
}

# 返回 0 成功; 1 准备失败; 2 提交失败 (已尝试恢复, 恢复不全时保留备份并明确提示)。
apply_all() {
	local bak had_old=0 f snapshot_ok=1 failed=0
	# 旧版本升级: 补齐新增的状态项 (随后与新配置一起保存)
	if xr_has_reality && [ -z "${REALITY_GUARD_PORT:-}" ]; then REALITY_GUARD_PORT=$(pick_guard_port); fi
	[ -n "${CLASH_SECRET:-}" ] || CLASH_SECRET=$(rand_str 24)
	OWN_IP_CIDRS=$(own_ip_cidrs)
	mkdir -p "$ONEBOX_DIR" || { cert_txn_rollback; return 1; }
	bak=$(mktemp -d "$ONEBOX_DIR/.rollback.XXXXXX") || { cert_txn_rollback; return 1; }
	[ ! -f "$STATE_FILE" ] || had_old=1
	for f in "$STATE_FILE" "$SB_CONF" "$XR_CONF"; do
		if [ -f "$f" ]; then cp -p "$f" "$bak/" || snapshot_ok=0; fi
	done
	if [ -d "$CLIENT_DIR" ]; then cp -a "$CLIENT_DIR" "$bak/client" || snapshot_ok=0; fi
	if [ "$snapshot_ok" != 1 ] || ! : >"$bak/complete"; then
		rm -rf "$bak"
		cert_txn_rollback
		err "无法完整备份原配置, 已中止应用"
		return 1
	fi
	if ! prepare_site_and_renewal || ! prepare_server_configs; then
		if cert_txn_rollback; then rm -rf "$bak"; else warn "证书或网站恢复失败, 原配置备份保留在: $bak"; fi
		return 1
	fi
	trap '' INT TERM HUP
	if [ "$had_old" = 1 ]; then
		(load_state && fw_apply close && hop_rules del) || failed=1
	elif [ ! -f "$(_fw_ledger)" ]; then
		: >"$(_fw_ledger)" || failed=1
	fi
	if [ "$failed" = 0 ]; then commit_server_configs || failed=1; fi
	if [ "$failed" = 0 ]; then save_state || failed=1; fi
	if [ "$failed" = 0 ]; then apply_services || failed=1; fi
	if [ "$failed" = 0 ]; then fw_apply open || failed=1; fi
	if [ "$failed" = 0 ]; then hop_setup || failed=1; fi
	if [ "$failed" = 0 ]; then write_client_files || failed=1; fi
	if [ "$failed" = 0 ]; then snapshot_restore_clients || failed=1; fi
	# 网站/证书快照必须保留到网络和所有客户端文件都已成功发布。
	if [ "$failed" = 0 ]; then cert_txn_commit || failed=1; fi
	if [ "$failed" != 0 ]; then
		warn "应用配置失败, 正在恢复修改前的状态..."
		_apply_rollback "$bak" "$had_old" || true
		return 2
	fi
	rm -rf "$bak"
	txn_traps
	snapshot_checkpoint applied
	return 0
}

# 应用配置 (含进行中的证书变更事务), 失败时回滚并给出明确原因
apply_or_die() {
	local rc
	apply_all
	rc=$?
	if [ "$rc" = 0 ]; then
		return 0
	fi
	cert_txn_rollback
	case "$rc" in
	1) die "站点准备或配置校验失败, 已撤销配置变更 (详见上方日志)" ;;
	*) die "应用配置失败, 已尝试恢复原配置 (请检查上方恢复结果, 或执行 onebox log)" ;;
	esac
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
	reset_state
	choose_protocols
	choose_extras
	choose_tls
	if proto_enabled vmess-ws; then vmess_tls_default && VMESS_TLS=1 || VMESS_TLS=0; fi
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
	# 重装时备份旧证书, 新配置失败时一并恢复
	cert_txn_begin || die "无法备份原证书，安装已中止"
	obtain_cert || {
		cert_txn_rollback
		die "证书配置失败"
	}
	# shellcheck disable=SC2034 # 通过 STATE_KEYS 保存
	INSTALLED_AT=$(date '+%Y-%m-%d %H:%M:%S')
	install_self
	# 旧服务 (重装时) 在新配置校验通过后才会被停止 / 替换
	local rc
	apply_all
	rc=$?
	if [ "$rc" = 0 ]; then
		:
	elif [ -n "$old_protocols" ]; then
		cert_txn_rollback
		[ "$rc" = 1 ] && die "配置未通过内核校验, 安装中止 (原配置保持不变)"
		die "服务启动失败, 已恢复为重装前的配置 (详见上方日志)"
	else
		# 全新安装失败也回滚证书, 不提交可能仍待恢复的事务。
		cert_txn_rollback
		[ "$rc" = 1 ] && die "配置未通过内核校验, 安装中止"
		die "安装应用失败, 请根据上方恢复结果排查后重新安装"
	fi

	if proto_enabled shadowsocks || proto_enabled shadowtls || proto_enabled vmess-ws; then
		check_clock || true
	fi
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
	load_state || die "已安装的状态文件无法加载, 请先恢复配置备份"
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
	site_enabled && site_info
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
	[ -f "$CLIENT_DIR/sing-box.json" ] && echo "  sing-box (TUN)    : ${CLIENT_DIR}/sing-box.json"
	[ -f "$CLIENT_DIR/sing-box-notun.json" ] && echo "  sing-box (代理端口): ${CLIENT_DIR}/sing-box-notun.json"
	[ -f "$CLIENT_DIR/xray.json" ] && echo "  Xray              : ${CLIENT_DIR}/xray.json"
	echo "  mihomo / sing-box 本地控制面板 (127.0.0.1:9090) 密钥: $(mh_secret)"
	echo "  mihomo 需要内核 >= $(mh_min_version) (请使用客户端最新版)"
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
	singbox | sing-box | singbox-notun | sing-box-notun)
		local f="$CLIENT_DIR/sing-box.json"
		case "$which" in *notun) f="$CLIENT_DIR/sing-box-notun.json" ;; esac
		if [ -f "$f" ]; then cat "$f"; else warn "当前协议组合中没有 sing-box 客户端支持的协议"; fi
		;;
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
	local act=$1 core failed=0
	for core in singbox xray; do
		core_used "$core" || continue
		case "$act" in
		start) svc_start "$core" || failed=1 ;;
		stop) svc_stop "$core" || failed=1 ;;
		restart) svc_restart "$core" || failed=1 ;;
		esac
	done
	[ "$failed" = 0 ]
}

do_service() {
	local act=$1 core failed=0
	require_installed
	case "$act" in
	start | stop | restart)
		if site_enabled; then
			if ! site_service "$act"; then [ "$act" = stop ] || return 1; failed=1; fi
		fi
		all_cores_do "$act" || failed=1
		if [ "$act" = start ] && [ -n "$HY2_HOP" ] && proto_enabled hysteria2; then hop_rules add || failed=1; fi
		sleep 1
		for core in singbox xray; do
			core_used "$core" && echo "  $(core_title "$core"): $(svc_status_text "$core")"
		done
		;;
	status)
		site_enabled && site_service status
		for core in singbox xray; do
			core_used "$core" || continue
			echo "  $(core_title "$core") $( [ "$core" = singbox ] && sb_installed_version || xr_installed_version): $(svc_status_text "$core")"
		done
		;;
	esac
	[ "$failed" = 0 ]
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
	[ -z "${OPT_REALITY_SITE:-}" ] || proto_uses_reality "$p" || die "添加协议时 --reality-site 仅适用于 REALITY 协议"
	[ -z "${OPT_SITE_HTTPS:-}" ] || proto_uses_reality "$p" || die "添加协议时 --site-https 仅适用于 REALITY 协议"
	proto_enabled "$p" && die "$(proto_title "$p") 已存在"
	# 内核: 优先使用已在运行的内核 (取已有协议中第一个的内核)
	local x
	prefer=""
	for x in $PROTOCOLS; do
		prefer=$(pget CORE "$x")
		[ -n "$prefer" ] && break
	done
	PROTOCOLS=$(normalize_protocols $PROTOCOLS "$p")
	if [ "$(proto_cores "$p")" = "singbox xray" ]; then
		# Hysteria2 默认 sing-box (Xray 承载为实验性)
		proto_core_experimental "$p" xray && prefer=singbox
		if [ "$p" = hysteria2 ] && [ -n "${OPT_HY2_CORE:-}" ]; then
			prefer=$OPT_HY2_CORE
		elif [ -n "${OPT_CORE:-}" ] && ! proto_core_experimental "$p" "$OPT_CORE"; then
			prefer=$OPT_CORE
		elif is_interactive; then
			echo "  该协议可用内核: 1) sing-box  2) Xray$(proto_core_experimental "$p" xray && printf ' (实验性)')"
			ask_num i "请选择" "$([ "$prefer" = xray ] && echo 2 || echo 1)" 1 2 || i=1
			[ "$i" = 2 ] && prefer=xray || prefer=singbox
		fi
		pset CORE "$p" "${prefer:-singbox}"
	else
		pset CORE "$p" "$(proto_cores "$p")"
	fi
	fill_missing_credentials
	if proto_uses_reality "$p" && { [ -z "$REALITY_SNI" ] || [ -n "${OPT_REALITY_SITE:-}${OPT_SNI:-}${OPT_SITE_HTTPS:-}" ]; }; then
		choose_reality_target
	fi
	[ -z "${OPT_SITE_HTTPS:-}" ] || site_enabled || die "--site-https 需要先启用自有域名网站"
	if [ "$p" = shadowtls ] && [ -z "$SHADOWTLS_SNI" ]; then
		choose_shadowtls_target
	fi
	# 先完成所有可能失败的选择与检查, 最后再申请证书 (之后只剩应用配置, 失败会整体回滚)
	local need_cert=0
	if proto_needs_cert "$p" && [ -z "$TLS_MODE" ]; then
		choose_tls
		need_cert=1
	fi
	[ "$p" = vmess-ws ] && { vmess_tls_default && VMESS_TLS=1 || VMESS_TLS=0; }
	[ "$p" = hysteria2 ] && choose_hy2_opts
	ensure_cores || die "内核安装失败"
	[ -n "$REALITY_PRIVATE_KEY" ] || ! any_reality || gen_reality_keypair
	port=$(opt_port_for "$p") || port=$(default_port_for "$p")
	while :; do
		ask port "$(proto_title "$p") 端口" "$port"
		port_ok "$port" "$p" && break
		is_interactive || die "端口 ${port} 不可用"
	done
	pset PORT "$p" "$port"
	if [ "$need_cert" = 1 ]; then
		cert_txn_begin || die "无法备份原证书，协议添加已中止"
		obtain_cert || {
			cert_txn_rollback
			die "证书配置失败"
		}
	fi
	apply_or_die
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
	PROTOCOLS=$(printf '%s\n' $PROTOCOLS | grep -vx "$p" | tr '\n' ' ')
	PROTOCOLS=${PROTOCOLS% }
	pset PORT "$p" ""
	pset CORE "$p" ""
	[ "$p" = hysteria2 ] && HY2_HOP="" HY2_OBFS=""
	[ "$p" = vmess-ws ] && VMESS_TLS=""
	if ! any_reality && [ "${REALITY_SITE_ENABLED:-}" = 1 ]; then
		REALITY_SITE_ENABLED=0
		info "已删除最后一个 REALITY 协议, 将停止网站和续期, 保留网页内容供以后恢复"
	fi
	apply_or_die
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
	pset PORT "$p" "$port"
	apply_or_die
	info "$(proto_title "$p") 端口已修改为 ${port}"
}

do_reset_credentials() {
	require_installed
	confirm "将重新生成全部 UUID / 密码 / REALITY 密钥, 旧的客户端配置将失效, 继续?" n || return 0
	gen_credentials
	apply_or_die
	info "凭据已重置, 请重新导入客户端配置"
	show_info
}

do_change_addr() {
	require_installed
	choose_address
	apply_or_die
	info "已更新客户端地址"
}

do_change_sni() {
	require_installed
	[ -z "${OPT_REALITY_SITE:-}" ] || any_reality || die "--reality-site 需要至少启用一个 REALITY 协议"
	if ! any_reality && ! proto_enabled shadowtls; then
		die "当前协议中没有 REALITY / ShadowTLS, 无需伪装站点"
	fi
	if any_reality; then
		title "更换 REALITY 伪装站点 (当前: ${REALITY_SNI})"
		choose_reality_target
	fi
	if proto_enabled shadowtls; then
		title "更换 ShadowTLS 握手站点 (当前: ${SHADOWTLS_SNI})"
		choose_sni SHADOWTLS_SNI "ShadowTLS 握手站点" "${OPT_SNI:-$SHADOWTLS_SNI}"
		SHADOWTLS_DEST="${SHADOWTLS_SNI}:443"
	fi
	apply_or_die
	info "伪装站点已更新 (UUID / 密钥不变), 请重新导入或修改客户端中的 SNI"
}

_restore_core_update() {
	local backup=$1 targets=$2 applied=$3 core bin failed=0
	for core in $targets; do
		bin=$(svc_bin "$core")
		if [ -f "$backup/$core" ]; then
			cp -p "$backup/$core" "$bin.restore" && mv -f "$bin.restore" "$bin" || failed=1
		else
			rm -f "$bin" || failed=1
		fi
	done
	if [ "$failed" != 0 ]; then err "内核恢复失败，已保留备份: $backup"; return 1; fi
	if [ "$applied" = 1 ]; then
		SB_VERSION=$(sb_installed_version) XR_VERSION=$(xr_installed_version)
		apply_all || { err "旧内核已恢复，但服务恢复失败，备份保留于: $backup"; return 1; }
	fi
	return 0
}

do_update_core() (
	local which=${1:-all} core bin targets="" backup committed=0 applied=0 update_rc
	require_installed
	case "$which" in all | singbox | sing-box | xray) ;; *) err "未知内核: $which"; return 1 ;; esac
	for core in singbox xray; do
		case "$which:$core" in all:* | singbox:singbox | sing-box:singbox | xray:xray) ;; *) continue ;; esac
		bin=$(svc_bin "$core")
		{ [ -x "$bin" ] || core_used "$core"; } && targets+=" $core"
	done
	[ -n "$targets" ] || { err "所选内核尚未安装"; return 1; }
	backup=$(core_tmpdir) || return 1
	chmod 700 "$backup" || { rm -rf "$backup"; return 1; }
	# 所有备份完整落盘后才能替换任何内核，不覆盖以前失败时保留的备份。
	for core in $targets; do
		bin=$(svc_bin "$core")
		if [ -e "$bin" ] && ! cp -p "$bin" "$backup/$core"; then
			rm -rf "$backup"
			err "无法备份 $(core_title "$core")，已取消内核更新"
			return 1
		fi
	done
	trap 'update_rc=$?; trap "" INT TERM HUP; if [ "$committed" != 1 ]; then if _restore_core_update "$backup" "$targets" "$applied"; then rm -rf "$backup"; else update_rc=1; fi; else rm -rf "$backup"; fi; exit "$update_rc"' EXIT
	trap 'exit 130' INT
	trap 'exit 143' TERM HUP
	if [ "$which" = all ] || [ "$which" = singbox ] || [ "$which" = sing-box ]; then
		if [ -x "$SB_BIN" ] || core_used singbox; then
			local old
			old=$(sb_installed_version)
			if install_singbox "${SB_VERSION_WANT:-}"; then
				info "sing-box: ${old:-无} -> $(sb_installed_version)"
			else
				err "sing-box 更新失败，恢复本次更新前的内核"
				return 1
			fi
		fi
	fi
	if [ "$which" = all ] || [ "$which" = xray ]; then
		if [ -x "$XR_BIN" ] || core_used xray; then
			local old xv=$TESTED_XR_VERSION
			old=$(xr_installed_version)
			warn "经过测试的 Xray 版本为 ${TESTED_XR_VERSION}; 更新的版本中 REALITY 服务端会拒绝不支持 X25519MLKEM768 的客户端 (如 sing-box)"
			if [ -n "$XR_VERSION_WANT" ]; then
				xv=$XR_VERSION_WANT
			elif ask_yn "是否仍然安装 Xray 最新版?" n; then
				# 使用 ask_yn: -y / 非交互时取默认值 n, 不会自动升级到未经测试的版本
				xv=latest
			fi
			if install_xray "$xv"; then
				info "Xray: ${old:-无} -> $(xr_installed_version)"
			else
				err "Xray 更新失败，恢复本次更新前的内核"
				return 1
			fi
		fi
	fi
	applied=1
	if ! apply_all; then
		err "新内核配置应用失败，恢复旧版本内核"
		return 1
	fi
	committed=1
	return 0
)

# 只读取版本声明，不执行尚未验证的下载内容。
script_file_version() {
	local version
	version=$(sed -n 's/^readonly SCRIPT_VERSION="\([^"]*\)"$/\1/p' "$1" | head -n 1)
	[[ "$version" =~ ^[0-9]{1,6}\.[0-9]{1,6}\.[0-9]{1,6}$ ]] || return 1
	printf '%s' "$version"
}

do_update_script() (
	local staging tmp out old_version new_version installed=0 committed=0 replaced=0 update_rc
	[ $# -le 1 ] || { err "用法: onebox update-script [stable|testing]"; return 1; }
	staging=$(mktemp -d "${CMD_PATH%/*}/.onebox-update.XXXXXX") || return 1
	chmod 700 "$staging" || { rm -rf "$staging"; return 1; }
	tmp="$staging/new"
	if [ -f "$CMD_PATH" ]; then
		cp -p "$CMD_PATH" "$staging/old" || { rm -rf "$staging"; err "无法备份原脚本，更新已取消"; return 1; }
	fi
	is_installed && installed=1
	trap 'update_rc=$?; trap "" INT TERM HUP; if [ "$committed" != 1 ] && [ "$replaced" = 1 ]; then if [ -f "$staging/old" ]; then if cp -p "$staging/old" "$staging/restore" && mv -f "$staging/restore" "$CMD_PATH"; then [ "$installed" != 1 ] || "$CMD_PATH" regen >/dev/null 2>&1 || warn "旧脚本已恢复，但配置恢复失败，请执行 onebox log 检查"; else err "脚本恢复失败，备份保留于: $staging"; exit 1; fi; else rm -f "$CMD_PATH"; fi; fi; rm -rf "$staging"; exit "$update_rc"' EXIT
	trap 'exit 130' INT
	trap 'exit 143' TERM HUP
	old_version=$(script_file_version "$CMD_PATH" 2>/dev/null) || old_version=$SCRIPT_VERSION
	info "当前管理脚本版本: ${old_version} (${CMD_PATH})"
	info "下载最新脚本..."
	if script_update_download "$tmp" "${1:-}"; then
		new_version=$(script_file_version "$tmp") || { err "下载内容缺少有效脚本版本，原脚本已保留"; return 1; }
		if ! ver_ge "$new_version" "$old_version"; then
			err "下载版本 ${new_version} 低于已安装版本 ${old_version}，已拒绝降级；请检查更新地址或 GitHub 加速缓存"
			return 1
		fi
		if [ -f "$CMD_PATH" ] && cmp -s "$tmp" "$CMD_PATH"; then
			committed=1
			info "当前已是下载源提供的最新脚本 (${old_version})，无需重新应用配置"
			return 0
		fi
		info "准备更新管理脚本: ${old_version} -> ${new_version}"
		script_update_summary
		chmod 755 "$tmp" || return 1
		# 在原子替换前启用恢复，覆盖 mv 已成功但尚未来得及赋值时的中断。
		replaced=1
		mv -f "$tmp" "$CMD_PATH" || { err "无法替换管理脚本，原脚本已保留"; return 1; }
		if [ "$installed" = 1 ]; then
			# 用新脚本重新生成配置, 以应用新版本的改进
			if out=$("$CMD_PATH" regen 2>&1); then
				info "已按新版本重新生成配置"
			else
				printf '%s\n' "$out" | tail -n 20 >&2
				err "新脚本配置应用失败，恢复原管理脚本"
				return 1
			fi
		fi
	else
		err "脚本下载或校验失败，原脚本已保留；请检查网络、更新地址和 GitHub 加速设置"
		return 1
	fi
	committed=1
	info "脚本已更新: ${old_version} -> ${new_version} (${CMD_PATH})"
)

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
		cert_txn_begin || die "无法备份原证书，证书变更已中止"
		obtain_cert || {
			cert_txn_rollback
			die "证书配置失败"
		}
		{ [ "$TLS_MODE" = acme ] || [ "$TLS_MODE" = custom ]; } && ask_yn "是否把客户端连接地址改为 ${DOMAIN}?" y && SERVER_ADDR=$DOMAIN
		if proto_enabled vmess-ws; then
			local want=0
			vmess_tls_default && want=1
			if [ "$want" != "${VMESS_TLS:-0}" ]; then
				if [ "$want" = 1 ]; then
					ask_yn "是否为 VMess-WS 启用 TLS (现有 VMess 客户端需重新导入, 端口将重新选择)?" n && VMESS_TLS=1
				else
					ask_yn "是否将 VMess-WS 改为明文 WS (现有 VMess 客户端需重新导入, 端口将重新选择)?" n && VMESS_TLS=0
				fi
				if [ "$VMESS_TLS" = "$want" ]; then
					pset PORT vmess-ws ""
					pset PORT vmess-ws "$(default_port_for vmess-ws)"
					info "VMess-WS 端口改为 $(pget PORT vmess-ws)"
				fi
			fi
		fi
		apply_or_die
		info "证书已更新"
		;;
	2)
		[ "$TLS_MODE" = acme ] || die "当前不是 ACME 证书"
		do_cert_renew proxy
		;;
	esac
}

do_uninstall() {
	local purge=0
	if [ "${1:-}" = "--purge" ]; then purge=1; fi
	title "卸载"
	confirm "确定卸载 Sing-Xray-Onebox (将删除全部服务、配置、内核及托管网站)?" n || return 0
	load_state 2>/dev/null || true
	fw_apply close 2>/dev/null
	hop_rules del 2>/dev/null
	net_persist del 2>/dev/null
	svc_remove singbox
	svc_remove xray
	site_remove || die "托管网站停止或清理失败, 已保留配置供排查, 请检查 onebox-site 服务后重试卸载"
	_none_autostart_del
	if [ "$TLS_MODE" = acme ] && [ -x "$ACME_SH" ] && [ -n "$DOMAIN" ]; then
		acme --remove -d "$DOMAIN" --ecc >/dev/null 2>&1
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
	printf '  更新渠道: %s (菜单 21 检查更新)\n' "$(update_channel_get 2>/dev/null || printf '设置无效')"
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
  ${GREEN}8.${PLAIN}  重置 UUID / 密码 / 密钥 (伪装站点见 15)
  ${GREEN}9.${PLAIN}  启动 / 停止 / 重启 / 日志
  ${GREEN}10.${PLAIN} 更新内核 (sing-box / Xray)
  ${GREEN}11.${PLAIN} 证书管理
  ${GREEN}12.${PLAIN} 开启 BBR
  ${GREEN}13.${PLAIN} 更新脚本
  ${GREEN}14.${PLAIN} 卸载
  ${GREEN}15.${PLAIN} 更换 REALITY / ShadowTLS 伪装站点
  ${GREEN}16.${PLAIN} 自有域名网站信息 / 证书续期
  ${GREEN}17.${PLAIN} 一键体检
  ${GREEN}18.${PLAIN} 证书状态
  ${GREEN}19.${PLAIN} 备份 / 恢复最近状态
  ${GREEN}20.${PLAIN} 生成脱敏诊断包
  ${GREEN}21.${PLAIN} 检查更新 / 切换渠道
  ${GREEN}22.${PLAIN} 安装前预演
  ${GREEN}0.${PLAIN}  退出
EOF
		hr
		ask_num n "请选择" 0 0 22 || exit 0
		case "$n" in
		0) exit 0 ;;
		1) (managed_change do_install) ;;
		2) (require_installed && show_info) ;;
		3) (require_installed && show_client) ;;
		4) (managed_change do_add_protocol) ;;
		5) (managed_change do_del_protocol) ;;
		6) (managed_change do_change_port) ;;
		7) (managed_change do_change_addr) ;;
		8) (managed_change do_reset_credentials) ;;
		9) service_menu ;;
		10) (managed_change do_update_core all) ;;
		11) (managed_change do_cert) ;;
		12) (enable_bbr) ;;
		13) (managed_change do_update_script) && exec "$CMD_PATH" ;;
		14) (do_uninstall) && ! [ -f "$STATE_FILE" ] && exit 0 ;;
		15) (managed_change do_change_sni) ;;
		16) (require_installed && site_menu) ;;
		17) (do_doctor) ;;
		18) (do_cert_status) ;;
		19) (recovery_menu) ;;
		20) (do_support_bundle) ;;
		21) update_menu ;;
		22) (plan_menu) ;;
		esac
		pause
	done
}

site_menu() {
	site_enabled || { warn "尚未启用自有域名网站, 请在菜单 15 中选择一键建站"; return 0; }
	site_info
	local n
	echo "  1) 强制续期网站证书  2) 配置 HTTPS 443 入口  3) 网站内容管理  4) 证书状态  0) 返回"
	ask_num n "请选择" 0 0 4 || return 0
	case "$n" in 1) do_site renew ;; 2) managed_change do_site https ;; 3) site_manage_menu ;; 4) do_cert_status ;; esac
	return 0
}

do_site() {
	require_installed
	site_enabled || die "未启用自有域名网站, 请执行 onebox sni --reality-site 你的域名"
	case "${1:-info}" in
	info) site_info ;;
	https)
		case "${2:-}" in
		on) REALITY_SITE_HTTPS=1 ;;
		off) REALITY_SITE_HTTPS=0 ;;
		"") choose_site_https ;;
		*) die "用法: onebox site https [on|off]" ;;
		esac
		apply_or_die
		site_info
		;;
	renew)
		do_cert_renew site
		;;
	*) die "用法: onebox site [info|renew|https [on|off]]" ;;
	esac
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
  plan [安装选项]          只读预演协议、端口、服务与文件变更
  info                     查看节点信息与分享链接
  client <类型>            输出客户端配置: mihomo | singbox | singbox-notun | xray | links | sub | qr
  add <协议>               添加协议
  del <协议>               删除协议
  port <协议> <端口>       修改端口
  addr                     修改客户端连接地址 / 节点名称
  reset                    重置全部 UUID / 密码 / 密钥
  sni [--sni 域名]         更换 REALITY / ShadowTLS 伪装站点 (凭据不变)
  sni --reality-site 域名  使用自有域名一键建站并设为 REALITY 目标
  site [info|renew]        查看网站信息 / 强制续期网站证书
  site https [on|off]      开启或关闭网站的 HTTPS 443 入口
  site template <minimal|profile|docs> [--title 标题] [--description 简介] [--theme forest|ocean|slate]
  site title <标题>       修改内置模板标题
  site import <目录>      备份后导入静态网站（需 index.html）
  site restore [ID|latest] 恢复网站内容备份
  site preview <模板>     生成未发布的本地 HTML 预览
  start | stop | restart | status
  log [singbox|xray]       查看日志
  update [singbox|xray] [版本]  更新内核 (默认全部; Xray 默认保持经过测试的版本)
  update-script [stable|testing] 更新本脚本
  update-check [stable|testing] 只读检查可用更新
  update-channel [stable|testing] 查看或保存更新渠道
  doctor                   一键体检（只读；公网可达性需外部验证）
  cert status              查看证书有效期、续期任务与最近结果
  cert-renew [proxy|site] [--cron] 续期并记录结果（--cron 不强制签发）
  backup [标签]            创建本机快照（保留最近 5 份）
  backups                  列出本机快照
  restore <ID>             恢复快照（先备份当前状态）
  support                  生成本地脱敏诊断包
  cert                     证书管理
  bbr                      开启 BBR
  regen                    按当前设置重新生成全部配置
  uninstall                卸载
  help | version

install 选项 (用于无人值守安装):
  --dry-run               仅预演，不安装、不改配置、不申请证书
  --preset <1-7>           协议组合 (1=Reality+Hy2+TUIC, 2=Xray 经典, 3=双内核, 4=sing-box 全家桶, 5=CDN, 6=仅 Reality, 7=自定义)
  --protocols <a,b,...>    自定义协议列表 (隐含 --preset 7), 可选:
                           ${ALL_PROTOCOLS// /, }
  --core <singbox|xray>    两种内核都支持的协议优先使用的内核
  --sni <域名>             REALITY / ShadowTLS 伪装站点
  --reality-site <域名>    使用自己的域名, 自动建立网站并申请 / 续期正式证书 (TCP 80 需可达)
  --site-title <标题>      网站标题 (默认 山间手记, 可修改生成的网页)
  --site-https on|off      自建网站启用域名 443 入口 (新建时默认 on)
  --tls <self|acme|cf>     证书方式: 自签 / ACME HTTP 验证 / ACME Cloudflare DNS 验证 (cf 需设置 CF_Token 环境变量)
  --domain <域名>          ACME 证书域名
  --addr <IP 或域名>       客户端连接地址 (默认自动检测公网 IP)
  --name <名称>            节点名称前缀
  --port <协议>=<端口>     指定端口, 可重复使用
  --hy2-hop <起-止>        Hysteria2 端口跳跃范围, 例如 20000-40000
  --hy2-obfs               Hysteria2 启用 salamander 混淆
  --hy2-core <singbox|xray> Hysteria2 服务端内核 (默认 sing-box; Xray 为实验性)
  --xray-version <版本|latest>  指定 Xray 版本 (默认安装经过测试的 ${TESTED_XR_VERSION})
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
		--preset | --protocols | --core | --sni | --reality-site | --site-title | --site-https | --reality-dest | --tls | --domain | --addr | --name | --port | --hy2-hop | --hy2-core | --xray-version)
			[ $# -ge 2 ] && [ -n "$2" ] && [[ "$2" != --* ]] || die "$1 需要一个非空参数值"
			;;
		esac
		case "$1" in
		--preset)
			[[ "${2:-}" =~ ^[1-7]$ ]] || die "--preset 取值为 1-7"
			OPT_PRESET=$2
			shift
			;;
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
			[ -n "$OPT_CUSTOM" ] || die "--protocols 至少需要一个协议"
			shift
			;;
		--core)
			case "$2" in singbox | sing-box) OPT_CORE=singbox OPT_CORE_CHOICE=1 ;; xray) OPT_CORE=xray OPT_CORE_CHOICE=2 ;; *) die "--core 仅支持 singbox 或 xray" ;; esac
			shift
			;;
		--sni) OPT_SNI=$2 && shift ;;
		--reality-site)
			[ -n "${2:-}" ] && valid_domain "$2" && [ "${#2}" -le 253 ] || die "--reality-site 需要有效域名, 例如 www.example.com"
			OPT_REALITY_SITE=${2,,}
			shift
			;;
		--site-title)
			[ -n "${2:-}" ] && [ "${#2}" -le 80 ] && [[ "$2" != *[[:cntrl:]]* ]] || die "--site-title 需要 1-80 个字符且不含控制字符"
			OPT_SITE_TITLE=$2
			shift
			;;
		--site-https)
			case "$2" in on | off) OPT_SITE_HTTPS=$2 ;; *) die "--site-https 仅支持 on / off" ;; esac
			shift
			;;
		--reality-dest) OPT_REALITY_DEST=$2 && shift ;;
		--tls)
			case "$2" in self) OPT_TLS_CHOICE=1 ;; acme | http) OPT_TLS_CHOICE=2 ;; cf | cloudflare) OPT_TLS_CHOICE=3 ;; *) die "--tls 仅支持 self / acme / cf" ;; esac
			shift
			;;
		--domain) OPT_DOMAIN=$2 && shift ;;
		--addr) OPT_ADDR=$2 && shift ;;
		--name) OPT_NAME=$2 && shift ;;
		--port)
			case " $ALL_PROTOCOLS " in *" ${2%%=*} "*) ;; *) die "--port 格式为 <协议>=<端口>, 未知协议: ${2%%=*}" ;; esac
			[[ "${2#*=}" =~ ^[1-9][0-9]{0,4}$ ]] && [ "${2#*=}" -le 65535 ] || die "--port 端口无效: ${2#*=}"
			OPT_PORTS+="$2 "
			shift
			;;
		--hy2-hop)
			[[ "${2:-}" =~ ^([1-9][0-9]*)-([1-9][0-9]*)$ ]] && [ "${BASH_REMATCH[1]}" -ge 1024 ] && [ "${BASH_REMATCH[2]}" -le 65535 ] &&
				[ "${BASH_REMATCH[1]}" -lt "${BASH_REMATCH[2]}" ] || die "--hy2-hop 格式为 起始-结束, 例如 20000-40000"
			OPT_HY2_HOP=$2
			shift
			;;
		--hy2-obfs) OPT_HY2_OBFS=y ;;
		--hy2-core)
			case "$2" in singbox | sing-box) OPT_HY2_CORE=singbox ;; xray) OPT_HY2_CORE=xray ;; *) die "--hy2-core 仅支持 singbox 或 xray" ;; esac
			shift
			;;
		--xray-version) XR_VERSION_WANT=${2#v} && shift ;;
		--no-bbr) OPT_BBR=n ;;
		--allow-private) OPT_BLOCK_PRIVATE=0 ;;
		-y | --yes) AUTO_YES=1 ;;
		*) die "未知选项: $1 (onebox help 查看帮助)" ;;
		esac
		shift
	done
	if [ -n "${OPT_REALITY_SITE:-}" ] && [ -n "${OPT_SNI:-}${OPT_REALITY_DEST:-}" ]; then
		die "--reality-site 与 --sni / --reality-dest 不能同时使用"
	fi
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
	plan)
		parse_install_opts "$@"
		do_install_plan
		return $?
		;;
	update-check)
		do_update_check "$@"
		return $?
		;;
	esac
	if [ "$cmd" = install ]; then
		local dry_run=0 install_args=()
		for a in "$@"; do
			case "$a" in --dry-run) dry_run=1 ;; *) install_args+=("$a") ;; esac
		done
		if [ "$dry_run" = 1 ]; then
			parse_install_opts "${install_args[@]}"
			do_install_plan
			return $?
		fi
	fi
	init_env
	case "$cmd" in
	menu) main_menu ;;
	install)
		parse_install_opts "$@"
		managed_change do_install
		;;
	info) require_installed && show_info ;;
	client | config) require_installed && show_client "${1:-}" ;;
	qr) require_installed && show_qr ;;
	links) require_installed && cat "$CLIENT_DIR/links.txt" ;;
	add)
		parse_install_opts "${@:2}"
		managed_change do_add_protocol "${1:-}"
		;;
	del | remove) managed_change do_del_protocol "${1:-}" ;;
	port) managed_change do_change_port "${1:-}" "${2:-}" ;;
	addr)
		parse_install_opts "$@"
		managed_change do_change_addr
		;;
	reset) managed_change do_reset_credentials ;;
	start | stop | restart | status) do_service "$cmd" ;;
	log | logs) do_log "${1:-}" ;;
	update)
		if [ -n "${2:-}" ]; then
			case "${1:-}" in
			singbox | sing-box) SB_VERSION_WANT=${2#v} ;;
			xray) XR_VERSION_WANT=${2#v} ;;
			esac
		fi
		managed_change do_update_core "${1:-all}"
		;;
	update-script) managed_change do_update_script "$@" ;;
	update-channel) do_update_channel "$@" ;;
	cert) if [ "${1:-}" = status ]; then do_cert_status; else managed_change do_cert; fi ;;
	cert-renew) do_cert_renew "$@" ;;
	support) do_support_bundle ;;
	doctor) do_doctor ;;
	backup) do_backup "$@" ;;
	backups) do_backups ;;
	restore) do_restore "$@" ;;
	site)
		case "${1:-info}" in
		title | template | import | restore) managed_change do_site_manage "$@" ;;
		preview) do_site_manage "$@" ;;
		https) managed_change do_site "$@" ;;
		*) do_site "${1:-info}" "${2:-}" ;;
		esac
		;;
	bbr) enable_bbr ;;
	regen)
		require_installed
		managed_change apply_or_die
		;;
	sni)
		parse_install_opts "$@"
		managed_change do_change_sni
		;;
	net-apply | hop-apply)
		load_state && {
			# 本机地址变化 (如 DHCP / 更换 IP) 时重新生成服务端配置, 保持对本机地址的屏蔽
			if [ "${BLOCK_PRIVATE:-1}" = 1 ] && [ "$(own_ip_cidrs)" != "${OWN_IP_CIDRS:-}" ]; then
				apply_all >/dev/null 2>&1 || true
			fi
			fw_apply open
			hop_rules add
		}
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


# BEGIN preflight
# ---------------------------------------------------------------------------
# 安装前预演: 复用安装选项与选择函数, 在子 shell 中计算, 不改变已安装状态。
# choose_sni/choose_tls 在 ONEBOX_PLAN_ONLY=1 时只跳过网络探测/凭据询问。
# ---------------------------------------------------------------------------
_plan_port_observation() {
	local port=$1 net=$2 item busy=""
	if [ "${PLAN_PORTS_KNOWN:-0}" != 1 ]; then printf '占用状态未检查'; return 0; fi
	for item in tcp udp; do
		[ "$net" = both ] || [ "$net" = "$item" ] || continue
		if port_in_use "$port" "$item"; then
			if port_used_by_onebox "$port" "$item" 2>/dev/null; then busy+="${item}:已有 onebox "; else busy+="${item}:已占用 "; fi
		fi
	done
	printf '%s' "${busy:-当前未监听}"
}

_plan_required_tcp() {
	local port=$1 label=$2 owner=${3:-none} allowed=0
	printf '  TCP %-5s %-26s %s\n' "$port" "$label" "$(_plan_port_observation "$port" tcp)"
	port_in_use "$port" tcp || return 0
	case "$owner" in
	site) _site_running && allowed=1 ;;
	https) { _site_owns_https_listener || port_used_by_onebox "$port" tcp; } && allowed=1 ;;
	core) port_used_by_onebox "$port" tcp && allowed=1 ;;
	esac
	[ "$allowed" = 1 ] && return 0
	err "冲突: ${label} 需要 TCP ${port}, 当前由其他服务监听"
	return 1
}

_plan_services_and_files() {
	local core name
	printf '\n将涉及的服务和文件 (实际安装时):\n'
	for core in singbox xray; do
		core_used "$core" || continue
		name=$(svc_name "$core")
		printf '  服务: %s\n  内核: %s\n  配置: %s\n' "$name" "$(svc_bin "$core")" "$(svc_conf "$core")"
		case "$INIT" in
		systemd) printf '  服务文件: /etc/systemd/system/%s.service\n' "$name" ;;
		openrc) printf '  服务文件: %s/%s\n' "$INITD_DIR" "$name" ;;
		none) printf '  启动方式: 后台进程 + root crontab @reboot (需 cron 可用)\n' ;;
		esac
	done
	printf '  状态: %s\n  客户端配置: %s/\n  管理命令: %s\n  日志: %s/\n  运行目录: %s/\n' "$STATE_FILE" "$CLIENT_DIR" "$CMD_PATH" "$LOG_DIR" "$RUN_DIR"
	case "$INIT" in
	systemd) printf '  网络恢复: /etc/systemd/system/%s.service\n' "$NET_SERVICE" ;;
	openrc) printf '  网络恢复: /etc/local.d/onebox-net.start\n' ;;
	esac
	printf '  防火墙: 按上述协议/站点端口放行; 台账 %s/firewall.list\n' "$ONEBOX_DIR"
	if [ -n "$TLS_MODE" ]; then printf '  协议证书: %s/\n' "$TLS_DIR"; fi
	if [ "$TLS_MODE" = acme ]; then printf '  协议证书签发/续期: %s/ + root crontab\n' "$ACME_HOME"; fi
	if site_enabled; then
		printf '  网站服务: %s (nginx)\n  网站内容: %s/index.html\n  网站配置/证书: %s/\n  网站签发/续期: %s/ + root crontab\n' "$SITE_SERVICE" "$REALITY_SITE_ROOT" "$REALITY_SITE_DIR" "$SITE_ACME_HOME"
	fi
	printf '  依赖: 实际安装时按需安装系统工具与上述内核'
	if site_enabled; then printf '、nginx、cron'; fi
	printf '\n'
}

do_install_plan() (
	# 子 shell 同时隔离 AUTO_YES、选项选择结果、临时随机端口和状态变量。
	AUTO_YES=1 ONEBOX_PLAN_ONLY=1
	local p port net detail source status=0 observed had_install=0 unreadable=0
	local PLAN_PORTS_KNOWN=0
	detect_os
	detect_init
	if { has ss && ss -lnt >/dev/null 2>&1 && ss -lnu >/dev/null 2>&1; } ||
		{ has netstat && netstat -lnt >/dev/null 2>&1 && netstat -lnu >/dev/null 2>&1; } ||
		{ [ -r /proc/net/tcp ] && [ -r /proc/net/udp ]; }; then PLAN_PORTS_KNOWN=1; fi
	if { [ -d "$ONEBOX_DIR" ] && { [ ! -r "$ONEBOX_DIR" ] || [ ! -x "$ONEBOX_DIR" ]; }; } ||
		{ [ -e "$STATE_FILE" ] && [ ! -r "$STATE_FILE" ]; }; then
		unreadable=1
	else
		is_installed && had_install=1
	fi
	reset_state
	# 与真正安装共用协议/内核/站点/证书选择; 这些函数只设置内存变量。
	choose_protocols >/dev/null
	choose_extras >/dev/null
	choose_tls >/dev/null
	if proto_enabled vmess-ws; then vmess_tls_default && VMESS_TLS=1 || VMESS_TLS=0; fi
	printf '安装前预演 (只读, 未预留端口)\n'
	printf '系统: %s; 服务管理: %s\n' "${OS_NAME:-未知}" "$INIT"
	if [ "$unreadable" = 1 ]; then printf '当前权限无法读取已有安装, 无法完整判断已占用端口是否属于 onebox; 请使用 sudo 再次预演。\n'; fi
	if [ "$had_install" = 1 ]; then
		printf '已有安装: 真正执行 install 将重建配置与凭据, 并停止/移除未选中的旧内核服务; 本次不读取或显示原凭据。\n'
	fi
	printf '\n协议 | 内核 | 监听端口 | 来源 | 当前状态\n'
	for p in $PROTOCOLS; do pset PORT "$p" ''; done
	for p in $PROTOCOLS; do
		if port=$(opt_port_for "$p"); then source=指定; else port=$(default_port_for "$p"); source=建议; fi
		net=$(proto_net "$p")
		observed=$(_plan_port_observation "$port" "$net")
		printf '%s | %s | %s/%s | %s | %s\n' "$p" "$(pget CORE "$p")" "$port" "$net" "$source" "$observed"
		if ! detail=$(port_ok "$port" "$p" 2>&1); then
			printf '  冲突: %s\n' "$detail" >&2
			status=1
		fi
		# 保留冲突端口, 后续协议仍可发现与它的重叠, 一次报告完整列表。
		pset PORT "$p" "$port"
	done
	if xr_has_reality; then
		REALITY_GUARD_PORT=$(pick_guard_port) || { err '无法为 REALITY 防偷跑分配本机端口'; status=1; }
		printf '  REALITY 防偷跑: 127.0.0.1:%s/TCP (建议)\n' "${REALITY_GUARD_PORT:-未能分配}"
	fi
	if site_enabled; then
		site_validate_ports || status=1
		port=$(site_public_port)
		printf '\nHTTPS 网站入口: https://%s%s/\n' "$REALITY_SITE_DOMAIN" "$([ "$port" = 443 ] || printf ':%s' "$port")"
		printf '  本机网站 TLS: 127.0.0.1:%s/TCP\n' "$REALITY_SITE_PORT"
		_plan_required_tcp 80 '网站 HTTP/证书验证' site || status=1
		if site_uses_https_proxy; then _plan_required_tcp 443 '网站 HTTPS 反向代理' https || status=1; fi
	elif [ "$TLS_MODE" = acme ] && [ "$ACME_METHOD" = standalone ]; then
		_plan_required_tcp 80 '协议证书 HTTP 验证' core || status=1
	fi
	if [ -n "$HY2_HOP" ]; then printf '  Hysteria2 UDP 跳跃范围: %s (云防火墙需另行放行)\n' "$HY2_HOP"; fi
	if [ -n "$REALITY_SNI" ]; then printf '  REALITY 目标: %s → %s (待现场验证)\n' "$REALITY_SNI" "$REALITY_DEST"; fi
	if [ -n "$SHADOWTLS_SNI" ]; then printf '  ShadowTLS 握手目标: %s (待现场验证)\n' "$SHADOWTLS_SNI"; fi
	if [ -n "${OPT_ADDR:-}" ]; then
		SERVER_ADDR=${OPT_ADDR#*://}; SERVER_ADDR=${SERVER_ADDR%%/*}; SERVER_ADDR=${SERVER_ADDR#[}; SERVER_ADDR=${SERVER_ADDR%]}
		if ! { valid_ipv4 "$SERVER_ADDR" || valid_ipv6 "$SERVER_ADDR" || valid_domain "$SERVER_ADDR"; }; then
			err "无效的客户端连接地址: ${OPT_ADDR}"; status=1
		fi
	elif [ -n "$DOMAIN" ]; then SERVER_ADDR=$DOMAIN
	elif site_enabled; then SERVER_ADDR=$REALITY_SITE_DOMAIN
	else SERVER_ADDR='实际安装时检测公网 IP'; fi
	printf '\n客户端连接地址: %s\n' "$SERVER_ADDR"
	case "$TLS_MODE" in
	self) printf '协议证书: 自签, SNI=%s; 实际安装时生成新证书\n' "$TLS_SNI" ;;
	acme) printf '协议证书: ACME, 域名=%s, 验证方式=%s\n' "$DOMAIN" "$ACME_METHOD" ;;
	'') printf '协议证书: 当前协议无需单独证书\n' ;;
	esac
	_plan_services_and_files
	printf '\n待实际安装现场校验: DNS A/AAAA、域名归属、云防火墙、TLS 目标兼容性、证书签发和自动续期。\n'
	if [ "$ACME_METHOD" = cf ]; then printf 'Cloudflare API 凭据须在实际签发时提供; 预演不校验或显示令牌。\n'; fi
	[ "$PLAN_PORTS_KNOWN" = 1 ] || printf '当前环境无法检查监听端口, 请在目标 VPS 上再次预演。\n'
	printf '建议端口可能随占用情况或随机分配变化; 需要固定时使用 --port 协议=端口。\n'
	if [ "$status" = 0 ]; then printf '本机检查未发现冲突; 未执行安装, 不代表公网连通性或证书签发已验证。\n'
	else printf '发现冲突, 请调整上述选项后重新预演。\n' >&2; fi
	return "$status"
)

# END preflight


# BEGIN support
# ---------------------------------------------------------------------------
# 本地诊断包：仅收集白名单状态，不打包配置、原始日志、私钥或环境变量。
# ---------------------------------------------------------------------------
_support_path_safe() {
	local path=$1 part current=""
	local -a parts
	[[ "$path" = /* && "$path" != *[[:cntrl:]]* ]] || return 1
	IFS=/ read -r -a parts <<<"$path"
	for part in "${parts[@]}"; do
		[ -n "$part" ] || continue
		case "$part" in . | ..) return 1 ;; esac
		current+="/$part"
		[ ! -L "$current" ] || return 1
	done
}

_support_redact() {
	local line key secret
	while IFS= read -r line || [ -n "$line" ]; do
		for key in UUID PASSWORD SS_PASSWORD REALITY_PRIVATE_KEY REALITY_SHORT_ID CLASH_SECRET HY2_OBFS_PASSWORD SHADOWTLS_PASSWORD SHADOWTLS_SS_PASSWORD CF_Token CF_Key CF_Email CF_Account_ID; do
			secret=${!key-}
			[ -z "$secret" ] || line=${line//"$secret"/[REDACTED]}
		done
		printf '%s\n' "$line"
	done | LC_ALL=C tr -d '\000-\010\013\014\016-\037\177'
}

do_support_bundle() (
	local base="$ONEBOX_DIR/support" staging archive output rc=0 core version
	umask 077
	_support_path_safe "$base" || { err "诊断包目录包含不安全路径或符号链接"; return 1; }
	mkdir -p "$base" && chmod 700 "$base" || return 1
	staging=$(mktemp -d "$base/.build.XXXXXX") || return 1
	archive=$(mktemp "$base/.archive.XXXXXX") || { rm -rf "$staging"; return 1; }
	trap 'rm -rf "$staging"; rm -f "$archive"' EXIT
	trap 'exit 130' INT
	trap 'exit 143' TERM HUP
	# Load only the existing local state, never migrate or regenerate it.
	if is_installed; then load_state >/dev/null 2>&1 || rc=1; else reset_state; fi
	{
		printf 'Onebox support report\nGenerated (UTC): %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
		printf 'Script: %s\nSystem: %s %s\nArchitecture: %s\nInit: %s\n' "$SCRIPT_VERSION" "${OS_ID:-unknown}" "${OS_VER:-unknown}" "${ARCH_RAW:-unknown}" "${INIT:-unknown}"
		if is_installed; then printf 'Installation: present\n'; else printf 'Installation: absent\n'; fi
		printf 'State readable: %s\n' "$([ "$rc" = 0 ] && echo yes || echo no)"
		for core in singbox xray; do
			if [ "$core" = singbox ]; then version=$(sb_installed_version); else version=$(xr_installed_version); fi
			[[ "$version" =~ ^[v0-9A-Za-z._+-]{1,64}$ ]] || version=unknown
			printf '%s version: %s\n' "$core" "$version"
			if core_used "$core"; then
				if svc_active "$core"; then printf '%s service: running\n' "$core"; else printf '%s service: stopped\n' "$core"; fi
			else printf '%s service: not configured\n' "$core"; fi
		done
	} | _support_redact >"$staging/summary.txt" || return 1
	# doctor intentionally suppresses raw core/config-check errors.
	(do_doctor 2>&1 || true) | _support_redact >"$staging/doctor.txt" || return 1
	cat >"$staging/README.txt" <<'EOF' || return 1
This locally generated report contains allowlisted system/service status and
diagnostic results. It does not include raw logs, configuration files, private
keys, subscriptions or an environment dump. Known credential values are also
redacted. Domain names, addresses and local paths may remain in diagnostic
results; review the report before sharing. No report has been uploaded.
EOF
	chmod 600 "$staging"/* || return 1
	tar -czf "$archive" -C "$staging" summary.txt doctor.txt README.txt || return 1
	output="$base/onebox-support-$(date -u '+%Y%m%dT%H%M%SZ')-${staging##*.}.tar.gz"
	chmod 600 "$archive" && mv -fT "$archive" "$output" || return 1
	info "诊断包已生成: $output"
	info "包含域名、地址及本机路径；分享前请检查内容。文件未上传。"
)

# END support


# BEGIN renewal
# ---------------------------------------------------------------------------
# 为手动及计划证书续期记录可查询结果，不保存 ACME 输出或凭据。
# ---------------------------------------------------------------------------
renewal_record() {
	local kind=$1 result=$2 method=$3 tmp target
	case "$kind:$result:$method" in
	proxy:running:cron | proxy:running:manual | proxy:success:cron | proxy:success:manual | proxy:failed:cron | proxy:failed:manual | site:running:cron | site:running:manual | site:success:cron | site:success:manual | site:failed:cron | site:failed:manual) ;;
	*) return 1 ;;
	esac
	_support_path_safe "$ONEBOX_DIR" || return 1
	target="$ONEBOX_DIR/renewal-${kind}.status"
	[ ! -L "$target" ] && [ ! -d "$target" ] || return 1
	mkdir -p "$ONEBOX_DIR" || return 1
	tmp=$(mktemp "$ONEBOX_DIR/.renewal-status.XXXXXX") || return 1
	if printf '%s\n%s\n%s\n' "$(date +%s)" "$result" "$method" >"$tmp" && chmod 600 "$tmp" && mv -fT "$tmp" "$target"; then return 0; fi
	rm -f "$tmp"
	return 1
}

do_cert_renew() (
	local kind=${1:-proxy} option=${2:-} method=manual rc=1 target renewal_home exe content_lock=''
	[ $# -le 2 ] || { err "用法: onebox cert-renew [proxy|site] [--cron]"; return 1; }
	case "$kind" in proxy | site) ;; *) err "用法: onebox cert-renew [proxy|site] [--cron]"; return 1 ;; esac
	case "$option" in "") ;; --cron) method=cron ;; *) err "仅支持 --cron 续期选项"; return 1 ;; esac
	require_installed
	if [ "$kind" = site ]; then
		site_enabled || { err "自有域名网站未启用"; return 1; }
		target=$REALITY_SITE_DOMAIN renewal_home=$SITE_ACME_HOME exe="$SITE_ACME_HOME/acme.sh"
	else
		[ "$TLS_MODE" = acme ] || { err "当前代理证书不是 ACME 证书"; return 1; }
		target=$DOMAIN renewal_home=$ACME_HOME exe=$ACME_SH
	fi
	[ -x "$exe" ] || { err "未找到证书续期程序"; return 1; }
	if ! valid_domain "$target" || [ ! -f "$renewal_home/${target}_ecc/${target}.conf" ]; then
		renewal_record "$kind" failed "$method" || true
		err "缺少当前域名的 ACME 续期部署，请重新配置该域名证书"
		return 1
	fi
	# Both site and proxy HTTP-01 renewal can use the managed website root.
	# Do not replace that tree while ACME is writing or serving challenges.
	if site_enabled; then
		_support_path_safe "$REALITY_SITE_DIR" || return 1
		content_lock="$REALITY_SITE_DIR/.content-lock"
		mkdir "$content_lock" 2>/dev/null || { err "网站内容或证书操作正在进行，请稍后重试"; return 1; }
		trap 'rmdir "$content_lock" 2>/dev/null || true' EXIT
	fi
	renewal_record "$kind" running "$method" || { err "无法记录证书续期状态，已取消"; return 1; }
	trap 'renewal_record "$kind" failed "$method"; exit 130' INT
	trap 'renewal_record "$kind" failed "$method"; exit 143' TERM HUP
	if [ "$method" = cron ]; then
		"$exe" --home "$renewal_home" --renew -d "$target" --ecc
	else
		"$exe" --home "$renewal_home" --renew -d "$target" --ecc --force
	fi
	rc=$?
	if [ "$rc" = 0 ] || [ "$rc" = 2 ]; then
		renewal_record "$kind" success "$method" || { err "续期检查完成，但结果记录失败"; return 1; }
		info "证书续期检查完成 ($kind)"
		return 0
	fi
	renewal_record "$kind" failed "$method" || true
	err "证书续期失败 ($kind)，请查看上方错误"
	return "$rc"
)

# END renewal

# BEGIN releases
# Stable/testing update channels. Keep the preference outside onebox.conf so
# reset_state, reinstalls and older state schemas do not silently change it.
update_channel_file() { printf '%s/update-channel' "$ONEBOX_DIR"; }

update_channel_get() {
	local channel=${1:-} file
	file=$(update_channel_file)
	if [ -z "$channel" ]; then
		_support_path_safe "$file" && [ ! -d "$file" ] || { err "更新渠道文件路径不安全"; return 1; }
		if [ -f "$file" ]; then channel=$(cat "$file") || return 1; else channel=stable; fi
	fi
	case "$channel" in stable | testing) printf '%s' "$channel" ;; *) err "无效更新渠道: ${channel} (仅支持 stable / testing)"; return 1 ;; esac
}

do_update_channel() {
	local channel file tmp
	[ $# -le 1 ] || { err "用法: onebox update-channel [stable|testing]"; return 1; }
	channel=$(update_channel_get "${1:-}") || return 1
	if [ $# = 0 ]; then info "当前更新渠道: ${channel}"; return 0; fi
	file=$(update_channel_file)
	_support_path_safe "$ONEBOX_DIR" && [ ! -L "$file" ] && [ ! -d "$file" ] || { err "更新渠道文件路径不安全"; return 1; }
	mkdir -p "$ONEBOX_DIR" || return 1
	tmp=$(mktemp "${file}.tmp.XXXXXX") || return 1
	if ! printf '%s\n' "$channel" >"$tmp" || ! chmod 600 "$tmp" || ! mv -fT "$tmp" "$file"; then
		rm -f "$tmp"
		err "无法保存更新渠道，原设置已保留"
		return 1
	fi
	info "更新渠道已设为 ${channel}；执行 onebox update-check 查看可用版本"
}

# Parse a single TOP-LEVEL string/boolean from JSON without jq or eval.
# Validate the whole document; ignore nested names and reject duplicate keys.
# Unicode escapes remain printable literal escapes (GitHub emits UTF-8 text).
_update_json_field() {
	local file=$1 key=$2 kind=${3:-string}
	[ "$(wc -c <"$file")" -le 1048576 ] || return 1
	awk -v wanted="$key" -v kind="$kind" '
	function ws() { while (substr(doc,p,1) ~ /^[ \t\r\n]$/) p++ }
	function bad() { failed=1; exit 1 }
	function str(    out,c,e,h) {
		if (substr(doc,p++,1)!="\"") bad()
		out=""
		while (p<=length(doc)) {
			c=substr(doc,p++,1)
			if (c=="\"") { value=out; type="string"; return }
			if (c ~ /[[:cntrl:]]/) bad()
			if (c!="\\") { out=out c; continue }
			e=substr(doc,p++,1)
			if (e=="\"" || e=="\\" || e=="/") out=out e
			else if (e=="n") out=out "\n"
			else if (e=="r") out=out "\r"
			else if (e=="t") out=out "\t"
			else if (e=="b" || e=="f") out=out " "
			else if (e=="u") {
				h=substr(doc,p,4)
				if (length(h)!=4 || h ~ /[^0-9a-fA-F]/) bad()
				out=out "\\u" h; p+=4
			} else bad()
		}
		bad()
	}
	function val(depth,    c,k,rest,n) {
		if (depth>64) bad()
		ws(); c=substr(doc,p,1)
		if (c=="\"") { str(); return }
		if (c=="{" || c=="[") {
			p++; ws()
			if (substr(doc,p,1)==(c=="{" ? "}" : "]")) { p++; type="container"; value=""; return }
			while (1) {
				if (c=="{") { ws(); str(); k=value; ws(); if (substr(doc,p++,1)!=":") bad() }
				val(depth+1)
				if (depth==0 && c=="{" && k==wanted) {
					if (found++) bad()
					answer=value; answer_type=type
				}
				ws(); n=substr(doc,p++,1)
				if (n==(c=="{" ? "}" : "]")) break
				if (n!=",") bad()
			}
			type="container"; value=""; return
		}
		rest=substr(doc,p)
		if (substr(rest,1,4)=="true") { p+=4; type="boolean"; value="true"; return }
		if (substr(rest,1,5)=="false") { p+=5; type="boolean"; value="false"; return }
		if (substr(rest,1,4)=="null") { p+=4; type="null"; value=""; return }
		if (match(rest,/^-?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?/)) { p+=RLENGTH; type="number"; value=""; return }
		bad()
	}
	{ doc=doc $0 "\n" }
	END {
		if (failed) exit 1
		p=1; ws(); if (substr(doc,p,1)!="{") exit 1
		val(0); ws()
		if (p<=length(doc) || !found || answer_type!=kind) exit 1
		printf "%s",answer
	}' "$file"
}

# Return 2 ONLY for an observed HTTP 404. Network/rate-limit/server failures
# must never look like an empty release list and silently switch to testing.
_update_api_request() {
	local url=$1 output=$2 status rc headers
	if has curl; then
		status=$(curl -sSL --retry 2 --connect-timeout 10 --max-time 30 \
			-H 'Accept: application/vnd.github+json' -H 'X-GitHub-Api-Version: 2022-11-28' \
			-o "$output" -w '%{http_code}' "$url")
		rc=$?
	else
		headers=$(mktemp) || return 1
		wget -q -S -T 20 -t 2 -O "$output" "$url" 2>"$headers"
		rc=$?
		status=$(awk '$1 ~ /^HTTP\// && $2 ~ /^[0-9][0-9][0-9]$/ {code=$2} END {print code}' "$headers")
		rm -f "$headers"
	fi
	UPDATE_API_STATUS=$status
	[ "$status" != 404 ] || return 2
	[ "$rc" = 0 ] && [ "$status" = 200 ] && return 0
	return 1
}

_update_api_fetch() {
	local url=$1 output=$2 rc
	_update_api_request "$url" "$output"
	rc=$?
	if [ "$rc" = 1 ] && [ -n "${GH_PROXY:-}" ]; then
		_update_api_request "$(gh_url "$url")" "$output"
		rc=$?
	fi
	if [ "$rc" = 1 ]; then err "GitHub 更新信息获取失败 (HTTP ${UPDATE_API_STATUS:-未知})，未更改更新源；请稍后重试"; fi
	return "$rc"
}

_update_valid_ref() {
	local ref=$1
	[ "${#ref}" -le 200 ] && [[ "$ref" =~ ^[A-Za-z0-9_][A-Za-z0-9._/-]*$ ]] || return 1
	case "$ref" in *..* | *//* | */.* | *. | */ | *.lock | */*.lock/*) return 1 ;; esac
	return 0
}

_update_default_ref() {
	local json=$1 branch
	_update_api_fetch "https://api.github.com/repos/${SCRIPT_REPO}" "$json" || { err "无法确认仓库默认分支"; return 1; }
	branch=$(_update_json_field "$json" default_branch) && _update_valid_ref "$branch" || { err "仓库默认分支信息无效"; return 1; }
	UPDATE_REF=$branch
	UPDATE_URL="https://raw.githubusercontent.com/${SCRIPT_REPO}/refs/heads/${branch}/onebox.sh"
}

_script_update_resolve_inner() {
	local requested=${1:-} json=$2 rc tag draft prerelease
	UPDATE_CHANNEL=$(update_channel_get "$requested") || return 1
	UPDATE_URL="" UPDATE_REF="" UPDATE_RELEASE_VERSION="" UPDATE_SUMMARY="" UPDATE_REMOTE_VERSION="" UPDATE_SOURCE=""
	if [ -n "${ONEBOX_SCRIPT_URL:-}" ]; then
		[[ "$ONEBOX_SCRIPT_URL" =~ ^https?://[^[:space:]]+$ ]] || { err "ONEBOX_SCRIPT_URL 必须是有效的 HTTP(S) 地址"; return 1; }
		UPDATE_URL=$ONEBOX_SCRIPT_URL UPDATE_SOURCE=custom
		UPDATE_SUMMARY="本次使用显式指定的 ONEBOX_SCRIPT_URL，未查询发布渠道。"
		return 0
	fi
	if [ "$UPDATE_CHANNEL" = testing ]; then
		_update_default_ref "$json" || return 1
		UPDATE_SOURCE=branch
		UPDATE_SUMMARY="测试渠道跟随默认开发分支；尚未作为正式 Release 发布的更改也会包含在内。"
		return 0
	fi
	_update_api_fetch "https://api.github.com/repos/${SCRIPT_REPO}/releases/latest" "$json"
	rc=$?
	case "$rc" in
	0)
		tag=$(_update_json_field "$json" tag_name) &&
			draft=$(_update_json_field "$json" draft boolean) &&
			prerelease=$(_update_json_field "$json" prerelease boolean) || { err "正式 Release 信息无效"; return 1; }
		[[ "$tag" =~ ^v?[0-9]{1,6}\.[0-9]{1,6}\.[0-9]{1,6}$ ]] && [ "$draft" = false ] && [ "$prerelease" = false ] || { err "正式 Release 的标签或发布状态无效"; return 1; }
		UPDATE_SOURCE=release UPDATE_REF=$tag UPDATE_RELEASE_VERSION=${tag#v}
		UPDATE_URL="https://raw.githubusercontent.com/${SCRIPT_REPO}/refs/tags/${tag}/onebox.sh"
		UPDATE_SUMMARY=$(_update_json_field "$json" body) || UPDATE_SUMMARY="此 Release 未提供更新摘要。"
		;;
	2)
		# Also verify the repository exists: private/missing repositories return 404 too.
		_update_default_ref "$json" || return 1
		UPDATE_SOURCE='branch-fallback'
		UPDATE_SUMMARY="仓库尚无正式 Release，本次回退到默认分支；保存的渠道仍为 stable。"
		warn "$UPDATE_SUMMARY"
		;;
	*) return 1 ;;
	esac
}

script_update_resolve() {
	local json rc
	[ $# -le 1 ] || { err "仅支持一个更新渠道参数: stable / testing"; return 1; }
	json=$(mktemp) || return 1
	_script_update_resolve_inner "${1:-}" "$json"
	rc=$?
	rm -f "$json"
	return "$rc"
}

script_update_download() {
	local output=$1 requested=${2:-}
	script_update_resolve "$requested" || return 1
	info "更新渠道: ${UPDATE_CHANNEL}；来源: ${UPDATE_SOURCE}${UPDATE_REF:+ (${UPDATE_REF})}"
	http_get "$(gh_url "$UPDATE_URL")" "$output" && head -n 5 "$output" | grep -q 'Sing-Xray-Onebox' && bash -n "$output" 2>/dev/null || { err "更新脚本下载或语法校验失败"; return 1; }
	UPDATE_REMOTE_VERSION=$(script_file_version "$output") || { err "下载内容缺少有效脚本版本"; return 1; }
	if [ -n "$UPDATE_RELEASE_VERSION" ] && [ "$UPDATE_REMOTE_VERSION" != "$UPDATE_RELEASE_VERSION" ]; then
		err "Release 标签版本 ${UPDATE_RELEASE_VERSION} 与脚本版本 ${UPDATE_REMOTE_VERSION} 不一致，已拒绝更新"
		return 1
	fi
}

script_update_summary() {
	[ -n "${UPDATE_SUMMARY:-}" ] || return 0
	printf '更新摘要:\n'
	# Never evaluate release text, or send terminal control characters through.
	printf '%s\n' "$UPDATE_SUMMARY" | awk 'NR<=12 {gsub(/[[:cntrl:]]/, " "); print "  " substr($0,1,200)} NR==13 {print "  …（更多内容请查看仓库 Release）"; exit}'
}

do_update_check() (
	local work old_version="" new_version
	[ $# -le 1 ] || { err "用法: onebox update-check [stable|testing]"; return 1; }
	work=$(mktemp -d) || return 1
	trap 'rm -rf "$work"' EXIT
	if [ -f "$CMD_PATH" ]; then old_version=$(script_file_version "$CMD_PATH") || true; fi
	info "已安装管理脚本: ${old_version:-未安装}；当前运行脚本: ${SCRIPT_VERSION}"
	script_update_download "$work/onebox.sh" "${1:-}" || return 1
	new_version=$UPDATE_REMOTE_VERSION
	info "远端脚本版本: ${new_version}"
	if [ -n "$old_version" ]; then
		if ! ver_ge "$new_version" "$old_version"; then
			warn "已安装版本高于当前渠道版本，将保留已安装版本，拒绝降级"
		elif cmp -s "$work/onebox.sh" "$CMD_PATH"; then
			info "已是该渠道提供的最新内容"
		elif [ "$new_version" = "$old_version" ]; then
			info "版本号相同，但脚本内容有更新"
		else
			info "发现可用更新: ${old_version} -> ${new_version}"
		fi
	fi
	script_update_summary
	info "本次只检查更新，未替换脚本或修改节点配置"
)

# END releases

# BEGIN diagnostics
# 只读诊断与证书状态。入口在子 shell 内加载状态，不改变调用者变量或部署文件。
# 退出码: 0=通过, 1=发现错误, 2=仅警告或检查不完整。
_diag_report() {
	local level=$1 label=$2 message=$3 hint=${4:-}
	case "$level" in
	ok) DIAG_OK=$((DIAG_OK + 1)); printf '[通过] %s: %s\n' "$label" "$message" ;;
	fail) DIAG_FAIL=$((DIAG_FAIL + 1)); printf '[失败] %s: %s\n' "$label" "$message" ;;
	warn) DIAG_WARN=$((DIAG_WARN + 1)); printf '[提示] %s: %s\n' "$label" "$message" ;;
	*) printf '[信息] %s: %s\n' "$label" "$message" ;;
	esac
	[ -z "$hint" ] || printf '  建议: %s\n' "$hint"
	return 0
}

_diag_finish() {
	printf '\n通过 %s 项，失败 %s 项，提示 %s 项。未修改服务、配置或证书。\n' "$DIAG_OK" "$DIAG_FAIL" "$DIAG_WARN"
	[ "$DIAG_FAIL" = 0 ] || return 1
	[ "$DIAG_WARN" = 0 ] || return 2
}

_diag_load_state() {
	local protocol core port invalid=0
	if [ ! -f "$STATE_FILE" ]; then
		_diag_report fail 安装状态 未找到安装状态 '先执行 onebox install。'
		return 1
	fi
	if ! load_state >/dev/null 2>&1; then
		_diag_report fail 安装状态 '状态文件不可读、语法错误或缺少协议列表' '检查状态文件权限及最近备份；不要直接重装覆盖原配置。'
		return 1
	fi
	for protocol in $PROTOCOLS; do
		case " $ALL_PROTOCOLS " in *" $protocol "*) ;; *) _diag_report fail 安装状态 '协议列表含未知项目' '检查状态文件或恢复最近备份。'; invalid=1; continue ;; esac
		core=$(pget CORE "$protocol") port=$(pget PORT "$protocol")
		if ! proto_supports_core "$protocol" "$core"; then _diag_report fail "$(proto_title "$protocol")" '缺少内核分配或内核不支持此协议' '检查状态文件中的内核分配，恢复最近备份。'; invalid=1; fi
		if ! [[ "$port" =~ ^[1-9][0-9]{0,4}$ ]] || [ "$port" -gt 65535 ]; then _diag_report fail "$(proto_title "$protocol")" '未配置有效监听端口' '使用 onebox port 设置有效端口。'; invalid=1; fi
	done
	[ "$invalid" = 0 ] || return 1
	_diag_report ok 安装状态 已加载
}

_diag_now() { date +%s; }
_diag_epoch_text() {
	[[ "$1" =~ ^[0-9]{1,12}$ ]] || return 1
	date -u -d "@$1" '+%Y-%m-%d %H:%M:%S UTC' 2>/dev/null || printf 'Unix 时间 %s' "$1"
}

_diag_cert_epoch() {
	# OpenSSL 的 GMT 文本转换成 GNU date / BusyBox date 都能读取的格式。
	local month day clock year zone number
	read -r month day clock year zone <<<"$1"
	case "$month" in Jan) number=01 ;; Feb) number=02 ;; Mar) number=03 ;; Apr) number=04 ;; May) number=05 ;; Jun) number=06 ;; Jul) number=07 ;; Aug) number=08 ;; Sep) number=09 ;; Oct) number=10 ;; Nov) number=11 ;; Dec) number=12 ;; *) return 1 ;; esac
	[[ "$day" =~ ^[0-9]{1,2}$ && "$year" =~ ^[0-9]{4}$ && "$clock" =~ ^[0-9]{2}:[0-9]{2}:[0-9]{2}$ && "$zone" = GMT ]] || return 1
	LC_ALL=C date -u -d "$year-$number-$(printf '%02d' "$((10#$day))") $clock" +%s 2>/dev/null
}

_diag_cert_name() {
	local file=$1 name=$2 option=-checkhost output
	[[ "$name" == *:* ]] || valid_ipv4 "$name" && option=-checkip
	if ! openssl x509 -help 2>&1 | grep -q -- "$option"; then return 2; fi
	output=$(LC_ALL=C openssl x509 -in "$file" -noout "$option" "$name" 2>/dev/null) || return 1
	# 部分 OpenSSL 版本在名称不匹配时仍返回 0，因此同时检查判定文本。
	[[ "$output" == *' does match certificate'* ]]
}

_diag_cert_notice() {
	local active=$1
	shift
	if [ "$active" = 1 ]; then _diag_report "$@"; else shift; _diag_report info "$@"; fi
}

_diag_certificate() {
	local label=$1 file=$2 key=$3 name=$4 pinned=$5 active=$6 dates expiry begin end_epoch='' begin_epoch='' now='' days rc public private
	printf '\n%s\n' "$label"
	if [ "$active" != 1 ]; then _diag_report info 状态 '已停用，以下仅展示保留证书'; fi
	if ! has openssl; then _diag_cert_notice "$active" warn "$label" '缺少 openssl，未检查证书' '安装 openssl 后重新执行；本命令不会安装依赖。'; return 0; fi
	if [ -z "$file" ] || [ ! -r "$file" ]; then _diag_cert_notice "$active" fail "$label" '证书文件缺失或不可读' '通过 onebox cert 或 onebox site info 检查证书配置。'; return 0; fi
	dates=$(LC_ALL=C openssl x509 -in "$file" -noout -startdate -enddate 2>/dev/null) || {
		_diag_cert_notice "$active" fail "$label" '无法解析 PEM 证书' '检查证书文件格式，恢复可用证书后重试。'; return 0;
	}
	expiry=$(printf '%s\n' "$dates" | sed -n 's/^notAfter=//p')
	begin=$(printf '%s\n' "$dates" | sed -n 's/^notBefore=//p')
	printf '  到期: %s\n' "$expiry"
	end_epoch=$(_diag_cert_epoch "$expiry") && begin_epoch=$(_diag_cert_epoch "$begin") && now=$(_diag_now) || now=''
	if [[ "$now" =~ ^[0-9]+$ && "$end_epoch" =~ ^[0-9]+$ && "$begin_epoch" =~ ^[0-9]+$ ]]; then
		if [ "$now" -lt "$begin_epoch" ]; then
			_diag_cert_notice "$active" fail 有效期 '证书尚未生效' '检查系统时钟与证书 notBefore 时间。'
		elif [ "$now" -ge "$end_epoch" ]; then
			_diag_cert_notice "$active" fail 有效期 "已过期 $(((now - end_epoch) / 86400)) 天" '立即检查续期任务；代理证书用 onebox cert，网站证书用 onebox site renew。'
		else
			days=$(((end_epoch - now + 86399) / 86400))
			if [ "$days" -le 30 ]; then _diag_cert_notice "$active" warn 有效期 "剩余 ${days} 天" '检查续期任务和最近续期记录。'; else _diag_report ok 有效期 "剩余 ${days} 天"; fi
		fi
	else
		_diag_cert_notice "$active" warn 有效期 '剩余天数未知，系统 date 无法解析证书时间' '根据上方到期时间人工核对，检查 date 命令。'
	fi
	if [ -n "$name" ]; then
		_diag_cert_name "$file" "$name"; rc=$?
		case "$rc" in
		0) _diag_report ok 证书名称 "覆盖 ${name}" ;;
		2) _diag_cert_notice "$active" warn 证书名称 '当前 openssl 不支持名称检查，结果未知' '升级 openssl 后重新执行。' ;;
		*) _diag_cert_notice "$active" fail 证书名称 "不覆盖 ${name}" '更换覆盖当前域名/IP 的证书，或修正 onebox 中的域名。' ;;
		esac
	else _diag_cert_notice "$active" warn 证书名称 '未配置需要验证的域名/IP'; fi
	if [ ! -r "$key" ]; then _diag_cert_notice "$active" fail 私钥 '文件缺失或不可读' '恢复与证书配套的私钥及文件权限。';
	else
		public=$(openssl x509 -in "$file" -noout -pubkey 2>/dev/null)
		private=$(openssl pkey -in "$key" -passin pass: -pubout 2>/dev/null)
		if [ -n "$public" ] && [ "$public" = "$private" ]; then _diag_report ok 私钥 与证书匹配;
		else _diag_cert_notice "$active" fail 私钥 '无法读取或与证书不匹配' '恢复配套的无交互密码私钥；不会在此输出私钥内容。'; fi
	fi
	if [ "$pinned" = 1 ]; then _diag_report info 信任方式 '自签或固定证书，由客户端固定证书校验';
	elif openssl verify -untrusted "$file" "$file" >/dev/null 2>&1; then _diag_report ok 证书链 '受本机系统 CA 信任';
	else _diag_cert_notice "$active" fail 证书链 '本机系统 CA 验证失败' '检查完整证书链、系统 ca-certificates 和系统时间。'; fi
}

_diag_read_cron() {
	DIAG_CRON_STATE=unknown DIAG_CRON_TEXT=''
	has crontab || return 0
	if DIAG_CRON_TEXT=$(LC_ALL=C crontab -l 2>&1); then DIAG_CRON_STATE=ok;
	else
		case "$DIAG_CRON_TEXT" in *'no crontab for '* | *"can't open '"*': No such file or directory') DIAG_CRON_STATE=ok ;; esac
		DIAG_CRON_TEXT=''
	fi
}

_diag_has_renew_job() {
	local kind=$1 renewal_home=$2 line clean
	while IFS= read -r line; do
		clean=${line#"${line%%[![:space:]]*}"}
		case "$clean" in '' | \#*) continue ;; esac
		# 去掉 shell 引号后只检查命令，不执行 cron 内容，不显示含凭据的原始行。
		clean=${clean//\"/} clean=${clean//\'/}
		case " $clean " in
		*" ${CMD_PATH} cert-renew ${kind} "*) return 0 ;;
		*" ${renewal_home}/acme.sh "*) [[ " $clean " =~ [[:space:]]--cron[[:space:]] ]] && return 0 ;;
		esac
	done <<<"$DIAG_CRON_TEXT"
	return 1
}

_diag_renew_record() {
	local kind=$1 active=$2 epoch result method extra record="$ONEBOX_DIR/renewal-${1}.status"
	if [ -r "$record" ]; then
		{ IFS= read -r epoch; IFS= read -r result; IFS= read -r method; IFS= read -r extra || true; } <"$record"
		if [[ "$epoch" =~ ^[0-9]{1,12}$ && "$result" =~ ^(success|failed|running)$ && "$method" =~ ^(cron|manual)$ && -z "$extra" ]]; then
			case "$method" in cron) method=定时 ;; manual) method=手动 ;; esac
			case "$result" in success) result=成功 ;; failed) result=失败 ;; running) result='执行中（未记录完成结果）' ;; esac
			_diag_report info 最近续期 "$(_diag_epoch_text "$epoch") / ${method} / ${result}"
			if [ "$result" = 失败 ]; then _diag_cert_notice "$active" warn 续期结果 '最近一次续期失败' '检查 DNS、80 端口和 CA 连接后，再执行对应的续期命令。'; fi
			return 0
		fi
	fi
	_diag_report info 最近续期 '未知（未找到有效的续期结果记录）'
}

_diag_renewal() {
	local kind=$1 mode=$2 renewal_home=$3 active=$4
	if [ "$active" != 1 ]; then _diag_report info 自动续期 '当前未使用该证书，不要求存在续期任务';
	elif [ "$mode" = self ]; then _diag_report info 自动续期 '不适用（自签证书；更换后需重新导入客户端）';
	elif [ "$mode" != acme ]; then _diag_report info 自动续期 '未知（自有证书由外部工具或人工管理）';
	elif [ "$DIAG_CRON_STATE" != ok ]; then _diag_report warn 自动续期 '未知（缺少 crontab 或无法读取当前用户的 crontab）' '检查 crontab 命令、权限与调度服务；本命令不会安装依赖。';
	elif _diag_has_renew_job "$kind" "$renewal_home"; then _diag_report ok 自动续期 '已找到当前用户的续期任务（未验证调度器是否执行）';
	else _diag_report warn 自动续期 '当前用户 crontab 未找到续期任务；其他调度方式未知' '检查 crontab 或自行维护的 systemd timer，恢复对应证书的定时续期。'; fi
	[ "$mode" = acme ] || active=0
	_diag_renew_record "$kind" "$active"
}

_diag_certificate_panels() {
	local pinned=0 active=0
	_diag_read_cron
	if any_needs_cert; then active=1; fi
	if any_needs_cert || [ -n "${TLS_MODE:-}" ]; then
		tls_insecure && pinned=1
		_diag_certificate 代理TLS "${CERT_FILE:-}" "${KEY_FILE:-}" "$(tls_server_name)" "$pinned" "$active"
		_diag_renewal proxy "${TLS_MODE:-}" "$ACME_HOME" "$active"
	else _diag_report info 代理TLS 当前协议不需要独立证书; fi
	active=0
	if site_enabled; then active=1; fi
	if [ "$active" = 1 ] || [ -f "$REALITY_SITE_DIR/cert.pem" ]; then
		_diag_certificate 自建站 "$REALITY_SITE_DIR/cert.pem" "$REALITY_SITE_DIR/key.pem" "${REALITY_SITE_DOMAIN:-}" 0 "$active"
		_diag_renewal site acme "$SITE_ACME_HOME" "$active"
	else _diag_report info 自建站 未配置证书; fi
}

_diag_ip_key() {
	local ip=${1,,} left right piece count out='' value a b c d
	local -a lhs=() rhs=()
	if [[ "$ip" != *:* ]]; then
		valid_ipv4 "$ip" || return 1
		IFS=. read -r a b c d <<<"$ip"
		printf '4:%d.%d.%d.%d' "$((10#$a))" "$((10#$b))" "$((10#$c))" "$((10#$d))"
		return 0
	fi
	[[ "$ip" =~ ^[0-9a-f:]+$ ]] || return 1
	if [[ "$ip" == *::* ]]; then
		left=${ip%%::*} right=${ip#*::}
		[[ "$right" != *::* ]] || return 1
		IFS=: read -r -a lhs <<<"$left"
		IFS=: read -r -a rhs <<<"$right"
		count=$((8 - ${#lhs[@]} - ${#rhs[@]}))
		[ "$count" -gt 0 ] || return 1
		while [ "$count" -gt 0 ]; do lhs+=(0); count=$((count - 1)); done
		lhs+=("${rhs[@]}")
	else IFS=: read -r -a lhs <<<"$ip"; [ "${#lhs[@]}" = 8 ] || return 1; fi
	for piece in "${lhs[@]}"; do
		[[ "$piece" =~ ^[0-9a-f]{1,4}$ ]] || return 1
		printf -v value '%04x' "$((16#$piece))"
		out+=$value
	done
	printf '6:%s' "$out"
}

_diag_resolve_domain() {
	# 每个域名至多 21 秒：三个 DoH 服务各查 A/AAAA，最后限时查询 NSS。
	local domain=$1 result='' server type
	if has curl; then
		for server in https://cloudflare-dns.com/dns-query https://dns.google/resolve https://dns.alidns.com/resolve; do
			result=$(
				for type in A AAAA; do
					curl -fsS --connect-timeout 2 --max-time 3 -H 'accept: application/dns-json' "${server}?name=${domain}&type=${type}" 2>/dev/null |
						grep -oE '"data": *"[^"]*"' | sed 's/^"data": *"//; s/"$//'
				done | _ip_filter
			)
			[ -z "$result" ] || break
		done
	fi
	if [ -z "$result" ] && has getent && has timeout; then result=$(timeout 3 getent ahosts "$domain" 2>/dev/null | awk '{print $1}' | _ip_filter); fi
	[ -z "$result" ] || printf '%s\n' "$result" | sort -u
}

_diag_dns() {
	local domain=$1 strict=$2 ips own ip key keys='' mismatch=0 count=0
	if ! valid_domain "$domain"; then _diag_report fail DNS '配置的域名格式无效' '修正域名后重新执行体检。'; return 0; fi
	if ! has curl && { ! has getent || ! has timeout; }; then _diag_report warn "DNS ${domain}" '缺少 curl 或 getent+timeout，未检查解析' '安装所需解析工具后重试。'; return 0; fi
	ips=$(_diag_resolve_domain "$domain" 2>/dev/null)
	if [ -z "$ips" ]; then _diag_report fail "DNS ${domain}" '未解析到 A/AAAA 地址' '核对域名解析与本机 DNS/DoH 网络。'; return 0; fi
	own=$(own_ip_list 2>/dev/null)
	while IFS= read -r ip; do key=$(_diag_ip_key "$ip") && keys+="|$key|"; done <<<"$own"
	if [ -z "$keys" ]; then _diag_report warn "DNS ${domain}" '无法确认本机公网地址，不能判断解析归属' '检查网卡地址与 onebox addr 中保存的服务器地址。'; return 0; fi
	while IFS= read -r ip; do
		key=$(_diag_ip_key "$ip") || { mismatch=1; continue; }
		count=$((count + 1))
		[[ "$keys" == *"|$key|"* ]] || mismatch=1
	done <<<"$ips"
	if [ "$mismatch" = 0 ] && [ "$count" -gt 0 ]; then _diag_report ok "DNS ${domain}" '本次解析到的 A/AAAA 均属于本机';
	elif [ "$strict" = 1 ]; then _diag_report fail "DNS ${domain}" '存在未指向本机的 A/AAAA 地址' '将自建站全部 A/AAAA 直连本机并关闭 CDN 代理。';
	else _diag_report warn "DNS ${domain}" '存在未指向本机的 A/AAAA 地址' '若未使用 CDN，请修正解析；若使用 CDN，请另行确认回源地址和支持的协议。'; fi
}

_diag_core_check() (
	local core=$1 bin=$2 conf=$3 work
	work=$(mktemp -d) || return 1
	trap 'rm -rf "$work"' EXIT
	case "$core" in
	singbox) timeout 15 "$bin" check -D "$work" -c "$conf" ;;
	xray) cd "$work" && timeout 15 "$bin" run -test -c "$conf" ;;
	esac
)

_diag_core() {
	local core=$1 bin conf rc
	bin=$(svc_bin "$core") conf=$(svc_conf "$core")
	if svc_active "$core" >/dev/null 2>&1; then _diag_report ok "$(core_title "$core") 服务" 运行中;
	else _diag_report fail "$(core_title "$core") 服务" 未运行 '执行 onebox log 查看原因；确认配置后再手动执行 onebox restart。'; fi
	if [ ! -x "$bin" ]; then _diag_report fail "$(core_title "$core") 内核" '可执行文件缺失或不可执行' '检查内核文件和执行权限，必要时运行 onebox update。'; return 0; fi
	if [ ! -r "$conf" ]; then _diag_report fail "$(core_title "$core") 配置" '文件缺失或不可读' '检查配置权限或备份，确认状态后执行 onebox regen。'; return 0; fi
	if ! has timeout; then _diag_report warn "$(core_title "$core") 配置" '缺少 timeout，跳过限时校验' '安装 timeout 后重试；本命令不会安装依赖。'; return 0; fi
	# 不回显 checker 的任何输出，避免错误消息包含密码、UUID 或私钥。
	_diag_core_check "$core" "$bin" "$conf" >/dev/null 2>&1
	rc=$?
	if [ "$rc" = 0 ]; then _diag_report ok "$(core_title "$core") 配置" '内核校验通过';
	else _diag_report fail "$(core_title "$core") 配置" "内核校验失败（退出码 ${rc}，原始输出已隐藏）" '在本机核对内核版本和服务配置；不要公开包含凭据的完整配置或日志。'; fi
}

_diag_listener_owner() {
	local port=$1 net=$2 flag=t owner=''
	[ "$net" != udp ] || flag=u
	if has ss; then
		owner=$(ss -H -ln"$flag"p 2>/dev/null | awk -v p="$port" '$4 ~ (":" p "$") {print}' | sed -n 's/.*users:(("\([^"]*\)".*/\1/p' | head -n1)
	elif has netstat; then
		owner=$(netstat -ln"$flag"p 2>/dev/null | awk -v p="$port" '$4 ~ (":" p "$") {sub(/^[0-9]+\//,"",$7); print $7; exit}')
	fi
	[[ "$owner" =~ ^[A-Za-z0-9_.+-]{1,64}$ ]] || owner=未知
	printf '%s' "$owner"
}

_diag_listeners() {
	local protocol port net transport owner expected
	if ! has ss && ! has netstat && [ ! -r /proc/net/tcp ]; then
		_diag_report warn 监听端口 '无法读取本机监听信息' '检查 ss / netstat 或 /proc 权限。'
		return 0
	fi
	for protocol in $PROTOCOLS; do
		port=$(pget PORT "$protocol") net=$(proto_net "$protocol")
		case "$(pget CORE "$protocol")" in singbox) expected=sing-box ;; *) expected=xray ;; esac
		for transport in tcp udp; do
			[ "$net" = both ] || [ "$net" = "$transport" ] || continue
			if port_in_use "$port" "$transport"; then
				owner=$(_diag_listener_owner "$port" "$transport")
				if [ "$owner" = 未知 ] || [ "$owner" = "$expected" ]; then
					_diag_report ok "$protocol $port/$transport" "已监听（进程: $owner）；协议握手仍需从客户端验证"
				else
					_diag_report warn "$protocol $port/$transport" "监听进程为 $owner，预期 $expected" '检查是否有其他服务占用了节点端口。'
				fi
			else _diag_report fail "$protocol $port/$transport" '未发现监听' '检查内核启动日志、监听地址和端口配置。'; fi
		done
	done
}

_diag_http_probe() {
	local domain=$1 port=$2 addr=${3:-127.0.0.1}
	curl --noproxy '*' --http1.1 --connect-timeout 3 --max-time 8 -fsS --resolve "$domain:$port:$addr" "https://$domain:$port/" -o /dev/null >/dev/null 2>&1
}

_diag_site() {
	local output port addr=127.0.0.1
	if ! site_enabled; then _diag_report info 自建站 '未启用，跳过内部 HTTPS 和网站入口检查'; return 0; fi
	if _site_running; then _diag_report ok 网站服务 运行中;
	else _diag_report fail 网站服务 未运行 '检查 onebox site info 和网站服务日志。'; fi
	if has curl; then
		if _diag_http_probe "$REALITY_SITE_DOMAIN" "$REALITY_SITE_PORT"; then _diag_report ok 网站内部HTTPS '本机连接、证书验证与 HTTP 请求通过';
		else _diag_report fail 网站内部HTTPS '本机请求失败（可能是监听、证书或 HTTP 状态）' '核对网站证书与 nginx 服务；执行 onebox site info 查看内部端口。'; fi
		port=$(site_public_port)
		if ! site_uses_https_proxy; then
			case "${LISTEN_ADDR:-}" in ::) addr='[::1]' ;; *:*) addr="[$LISTEN_ADDR]" ;; '' | 0.0.0.0) ;; *) addr=$LISTEN_ADDR ;; esac
		fi
		if _diag_http_probe "$REALITY_SITE_DOMAIN" "$port" "$addr"; then _diag_report ok "网站入口 ${port}" '本机连接通过；公网可达性未验证';
		else _diag_report fail "网站入口 ${port}" '本机 HTTPS 请求失败' '检查该端口的 nginx / REALITY 服务、SNI 与证书配置。'; fi
		[ "$port" = 443 ] || _diag_report info 443入口 "未启用，当前网站入口为 ${port}"
	else _diag_report warn 网站HTTPS '缺少 curl，内部与入口 HTTP/证书探测未执行' '安装 curl 后重试。'; fi
	if has openssl && has timeout; then
		output=$(timeout 8 openssl s_client -connect "127.0.0.1:$REALITY_SITE_PORT" -servername "$REALITY_SITE_DOMAIN" -tls1_3 -alpn h2 </dev/null 2>/dev/null)
		if printf '%s\n' "$output" | grep -q 'ALPN protocol: h2'; then _diag_report ok REALITY内部目标 '可协商 TLS1.3 / h2';
		else _diag_report fail REALITY内部目标 '未成功协商 TLS1.3 / h2' '检查 nginx 的 ssl_protocols、http2 与内部监听端口。'; fi
	else _diag_report warn REALITY内部目标 '缺少 openssl/timeout，TLS1.3 与 h2 检查未执行' '安装缺失工具后重试。'; fi
}

do_cert_status() (
	DIAG_OK=0 DIAG_WARN=0 DIAG_FAIL=0
	printf '证书状态（只读）\n'
	if _diag_load_state; then _diag_certificate_panels; fi
	_diag_finish
)

do_doctor() (
	DIAG_OK=0 DIAG_WARN=0 DIAG_FAIL=0
	printf 'Onebox 一键体检（只读）\n'
	if _diag_load_state; then
		local core
		for core in singbox xray; do core_used "$core" && _diag_core "$core"; done
		_diag_listeners
		if site_enabled; then _diag_dns "$REALITY_SITE_DOMAIN" 1; fi
		if any_needs_cert && [ -n "${DOMAIN:-}" ] && { ! site_enabled || [ "${DOMAIN,,}" != "${REALITY_SITE_DOMAIN,,}" ]; }; then _diag_dns "$DOMAIN" 0; fi
		_diag_certificate_panels
		_diag_site
	fi
	printf '\n公网连通性未验证：本机探测不能验证云安全组、外部防火墙或运营商路径，请从外部网络验证网站和代理端口。\n'
	_diag_finish
)

# END diagnostics

# BEGIN site-management
# Website content management: private metadata/backups, no shell evaluation of imported files.
_sm_path() {
	local path=$1 part walk='' parts=()
	[ -n "$path" ] || { err "目录路径不能为空"; return 1; }
	[[ "$path" != *[[:cntrl:]]* ]] || { err "路径不能包含控制字符"; return 1; }
	[[ "$path" = /* ]] || path="$PWD/$path"
	IFS=/ read -r -a parts <<<"$path"
	for part in "${parts[@]}"; do
		[ -n "$part" ] || continue
		case "$part" in . | ..) err "请使用不含 . 或 .. 的明确目录路径"; return 1 ;; esac
		walk+="/$part"
		[ ! -L "$walk" ] || { err "路径不能经过符号链接: $walk"; return 1; }
	done
	case "$walk" in '' | / | /etc | /var | /var/lib | /root | /home | /usr | /opt | /tmp | /run | /proc | /proc/* | /sys | /sys/* | /dev | /dev/*)
		err "不能使用系统目录作为网站内容目录"; return 1 ;;
	esac
	printf '%s' "$walk"
}

_sm_tree_safe() {
	local tree=$1 entry listing failed=0
	[ -d "$tree" ] && [ ! -L "$tree" ] || return 1
	listing=$(mktemp) || return 1
	if ! find "$tree" -print0 >"$listing"; then rm -f "$listing"; return 1; fi
	while IFS= read -r -d '' entry; do
		if [ -L "$entry" ] || { [ ! -d "$entry" ] && [ ! -f "$entry" ]; }; then
			err "静态网站不能包含符号链接或特殊文件: $entry"; failed=1; break
		fi
	done <"$listing"
	rm -f "$listing"
	[ "$failed" = 0 ]
}

_sm_paths() {
	SM_ROOT=$(_sm_path "$REALITY_SITE_ROOT") || return 1
	SM_PRIVATE=$(_sm_path "$REALITY_SITE_DIR") || return 1
	case "$SM_ROOT/" in "$SM_PRIVATE/"*) err "网页目录不能位于私密配置目录内"; return 1 ;; esac
	case "$SM_PRIVATE/" in "$SM_ROOT/"*) err "网页目录不能包含私密配置目录"; return 1 ;; esac
	[ -f "$SM_ROOT/.onebox-site-owned" ] && [ -f "$SM_PRIVATE/.onebox-site-owned" ] || { err "当前网站目录缺少管理标记，请先完成建站"; return 1; }
	[ ! -L "$SM_PRIVATE/.onebox-site-owned" ] || return 1
	_sm_tree_safe "$SM_ROOT" || return 1
	SM_SETTINGS="$SM_PRIVATE/content-settings.tsv"
	SM_BACKUPS="$SM_PRIVATE/content-backups"
	_sm_path "$SM_SETTINGS" >/dev/null && _sm_path "$SM_BACKUPS" >/dev/null || return 1
	[ ! -e "$SM_SETTINGS" ] || [ -f "$SM_SETTINGS" ] || return 1
}

_sm_text_valid() {
	local text=$1 maximum=$2
	[ -n "$text" ] && [ "${#text}" -le "$maximum" ] && [[ "$text" != *[[:cntrl:]]* ]]
}

_sm_settings_read() {
	local file=$1 key value extra seen=' ' decoded expected
	SM_KIND=custom SM_TEMPLATE=legacy SM_TITLE=${REALITY_SITE_TITLE:-山间手记}
	SM_DESCRIPTION='记录日常，整理想法，分享值得停留的片刻。' SM_THEME=forest SM_INDEX_HASH=''
	if [ ! -f "$file" ]; then
		if [ -f "$SM_ROOT/index.html" ]; then
			expected=$(site_render_index | _site_hash)
			[[ "$expected" =~ ^[a-f0-9]{64}$ ]] || return 1
			[ "$(_site_hash <"$SM_ROOT/index.html")" != "$expected" ] || SM_KIND=template
		fi
		return 0
	fi
	[ ! -L "$file" ] || return 1
	while IFS=$'\t' read -r key value extra; do
		[ -n "$key" ] && [ -z "$extra" ] || return 1
		case "$seen" in *" $key "*) return 1 ;; esac
		seen+="$key "
		case "$key" in
		version) [ "$value" = 1 ] || return 1 ;;
		kind) SM_KIND=$value ;;
		template) SM_TEMPLATE=$value ;;
		theme) SM_THEME=$value ;;
		index_sha256) SM_INDEX_HASH=$value ;;
		title | description)
			[[ "$value" =~ ^[A-Za-z0-9+/=]+$ ]] || return 1
			decoded=$(printf '%s' "$value" | base64 -d 2>/dev/null) || return 1
			if [ "$key" = title ]; then SM_TITLE=$decoded; else SM_DESCRIPTION=$decoded; fi
			;;
		*) return 1 ;;
		esac
	done <"$file"
	for key in version kind template theme index_sha256 title description; do case "$seen" in *" $key "*) ;; *) return 1 ;; esac; done
	case "$SM_KIND:$SM_TEMPLATE" in template:minimal | template:profile | template:docs | template:legacy | import:none) ;; *) return 1 ;; esac
	case "$SM_THEME" in forest | ocean | slate) ;; *) return 1 ;; esac
	_sm_text_valid "$SM_TITLE" 80 && _sm_text_valid "$SM_DESCRIPTION" 240 && [[ "$SM_INDEX_HASH" =~ ^[a-f0-9]{64}$ ]] || return 1
}

_sm_settings_write() {
	local file=$1 hash=$2
	{
		printf 'version\t1\nkind\t%s\ntemplate\t%s\ntheme\t%s\nindex_sha256\t%s\n' "$SM_KIND" "$SM_TEMPLATE" "$SM_THEME" "$hash" &&
		printf 'title\t%s\ndescription\t%s\n' "$(printf '%s' "$SM_TITLE" | b64)" "$(printf '%s' "$SM_DESCRIPTION" | b64)"
	} >"$file" && chmod 600 "$file"
}

_sm_render() {
	local title description accent wash
	title=$(site_html_escape "$SM_TITLE") description=$(site_html_escape "$SM_DESCRIPTION")
	case "$SM_THEME" in forest) accent='#21614c' wash='#edf5ef' ;; ocean) accent='#155e8b' wash='#eaf3fa' ;; slate) accent='#374151' wash='#f1f3f5' ;; *) return 1 ;; esac
	if [ "$SM_TEMPLATE" = legacy ]; then local REALITY_SITE_TITLE=$SM_TITLE; site_render_index; return $?; fi
	cat <<EOF
<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><meta name="description" content="$description"><title>$title</title>
<style>:root{--accent:$accent;--wash:$wash}*{box-sizing:border-box}body{margin:0;background:#fcfcf9;color:#222d29;font:17px/1.85 system-ui,-apple-system,"PingFang SC","Microsoft YaHei",sans-serif}a{color:var(--accent)}.wrap{width:min(960px,calc(100% - 40px));margin:auto}header{display:flex;justify-content:space-between;gap:20px;padding:24px 0;border-bottom:1px solid #ddd}header a{text-decoration:none;overflow-wrap:anywhere}.hero{padding:90px 0 60px}h1{font-size:clamp(36px,7vw,64px);line-height:1.2;letter-spacing:-.04em;overflow-wrap:anywhere;margin:0 0 24px}h2{font-size:26px;line-height:1.4}.intro{font-size:20px;max-width:640px;color:#58645f;overflow-wrap:anywhere}.label{font-size:12px;letter-spacing:.2em;color:var(--accent)}.panel{padding:30px;border-radius:18px;background:var(--wash)}.grid{display:grid;grid-template-columns:1fr 1fr;gap:24px;margin:28px 0 64px}.profile{display:grid;grid-template-columns:2fr 1fr;gap:36px;align-items:center}.monogram{display:grid;place-items:center;aspect-ratio:1;background:var(--wash);border-radius:50%;font-size:64px;color:var(--accent)}.docs{display:grid;grid-template-columns:190px 1fr;gap:44px;padding:48px 0}.docs nav a{display:block;padding:7px 0}.docs section{padding-bottom:32px;scroll-margin-top:24px}footer{border-top:1px solid #ddd;padding:26px 0;color:#69746e;font-size:13px;overflow-wrap:anywhere}a:focus-visible{outline:2px solid var(--accent);outline-offset:5px}@media(max-width:640px){.grid,.profile,.docs{grid-template-columns:1fr}.hero{padding:55px 0 35px}.monogram{max-width:160px}.docs{gap:18px}.docs nav{display:flex;gap:18px;flex-wrap:wrap}header{flex-wrap:wrap}}</style></head><body><div class="wrap"><header><a href="#home">$title</a><a href="#about">关于</a></header>
EOF
	case "$SM_TEMPLATE" in
	minimal)
		printf '<main id="home"><section class="hero"><p class="label">NOTES &amp; IDEAS</p><h1>%s</h1><p class="intro">%s</p></section><section class="panel" id="about"><h2>留一点空间，给值得记录的事</h2><p>这里收集日常观察、阅读笔记和正在探索的问题。欢迎慢慢阅读。</p></section><div class="grid"><section><h2>日常记录</h2><p>从小处开始，把想法写下来。</p></section><section><h2>持续探索</h2><p>保持好奇，也为新的理解留出空间。</p></section></div></main>\n' "$title" "$description"
		;;
	profile)
		printf '<main id="home"><section class="hero profile"><div><p class="label">PERSONAL SPACE</p><h1>%s</h1><p class="intro">%s</p></div><div class="monogram" aria-hidden="true">✦</div></section><div class="grid" id="about"><section class="panel"><h2>关于这个空间</h2><p>展示自己的作品，分享思考过程，也记录一路积累的经验。</p></section><section class="panel"><h2>最近在关注</h2><p>学习新知识、尝试新方法，把有价值的事情一点点做好。</p></section></div></main>\n' "$title" "$description"
		;;
	docs)
		printf '<main id="home"><section class="hero"><p class="label">KNOWLEDGE BASE</p><h1>%s</h1><p class="intro">%s</p></section><div class="docs"><nav aria-label="文档目录"><a href="#start">开始阅读</a><a href="#notes">记录方法</a><a href="#about">关于文档</a></nav><div><section id="start"><h2>开始阅读</h2><p>按主题整理内容，让信息更容易找到，也更容易持续更新。</p></section><section id="notes"><h2>记录方法</h2><p>先说明问题，再写下过程与结论。保留必要的背景，方便之后回顾。</p></section><section id="about"><h2>关于文档</h2><p>这是一个持续生长的知识空间，欢迎从最感兴趣的部分开始。</p></section></div></div></main>\n' "$title" "$description"
		;;
	*) return 1 ;;
	esac
	printf '<footer>%s · 持续记录，慢慢成长。</footer></div></body></html>\n' "$title"
}

_sm_options() {
	while [ "$#" -gt 0 ]; do
		[ "$#" -ge 2 ] || { err "$1 需要参数"; return 1; }
		case "$1" in --title) SM_TITLE=$2 ;; --description) SM_DESCRIPTION=$2 ;; --theme) SM_THEME=$2 ;; *) err "未知网站选项: $1"; return 1 ;; esac
		shift 2
	done
	_sm_text_valid "$SM_TITLE" 80 || { err "标题需为 1–80 个字符且不含控制字符"; return 1; }
	_sm_text_valid "$SM_DESCRIPTION" 240 || { err "简介需为 1–240 个字符且不含控制字符"; return 1; }
	case "$SM_THEME" in forest | ocean | slate) ;; *) err "配色可选 forest、ocean、slate"; return 1 ;; esac
}

_sm_snapshot() {
	local pending id latest
	mkdir -p "$SM_BACKUPS" && chmod 700 "$SM_BACKUPS" || return 1
	_sm_path "$SM_BACKUPS/latest" >/dev/null || return 1
	pending=$(mktemp -d "$SM_BACKUPS/.pending.XXXXXX") || return 1
	if ! cp -a "$SM_ROOT" "$pending/root" || ! printf '%s\n' "$SM_ROOT" >"$pending/root-path"; then rm -rf "$pending"; return 1; fi
	_sm_tree_safe "$pending/root" || { rm -rf "$pending"; return 1; }
	if [ -f "$SM_SETTINGS" ] && ! cp -p "$SM_SETTINGS" "$pending/settings.tsv"; then rm -rf "$pending"; return 1; fi
	: >"$pending/complete" || { rm -rf "$pending"; return 1; }
	id="$(date -u +%Y%m%dT%H%M%SZ)-$(rand_hex 4)"
	mv -T "$pending" "$SM_BACKUPS/$id" || { rm -rf "$pending"; return 1; }
	latest=$(mktemp "$SM_BACKUPS/.latest.XXXXXX") || return 1
	if ! printf '%s\n' "$id" >"$latest" || ! mv -fT "$latest" "$SM_BACKUPS/latest"; then rm -f "$latest"; return 1; fi
	printf '%s' "$id"
}

_sm_publish() (
	local stage=$1 settings=$2 backup=$3 hold moved=0 published=0 committed=0 exit_code
	hold="${SM_ROOT%/*}/.onebox-content-old-${backup##*/}"
	[ ! -e "$hold" ] && [ ! -L "$hold" ] || return 1
	trap 'exit_code=$?; trap "" INT TERM HUP; if [ "$committed" != 1 ] && [ "$moved" = 1 ]; then
		if [ "$published" = 1 ]; then mv -T "$SM_ROOT" "$stage" || { err "发布恢复失败，原网站保留在: $hold；备份: $backup"; exit 1; };
		elif [ -e "$SM_ROOT" ] || [ -L "$SM_ROOT" ]; then
			if [ -e "$hold.concurrent" ] || [ -L "$hold.concurrent" ] || ! mv -T "$SM_ROOT" "$hold.concurrent"; then err "并发修改妨碍恢复，原网站: $hold；备份: $backup"; exit 1; fi
			warn "并发新增的目录保留在: $hold.concurrent"
		fi
		if ! mv -T "$hold" "$SM_ROOT"; then err "无法恢复原网站，原目录: $hold；备份: $backup"; exit 1; fi
		if [ -f "$backup/settings.tsv" ]; then cp -p "$backup/settings.tsv" "$SM_SETTINGS" || { err "内容设置恢复失败，备份: $backup"; exit 1; }; else rm -f "$SM_SETTINGS"; fi
	fi; [ "$committed" != 1 ] || rm -rf "$hold"; exit "$exit_code"' EXIT
	trap 'exit 130' INT
	trap 'exit 143' TERM HUP
	# Each rename publishes a complete tree; the previous tree and persistent backup
	# remain available until both content and private metadata have committed.
	trap '' INT TERM HUP
	mv -T "$SM_ROOT" "$hold" || return 1
	moved=1
	if ! mv -T "$stage" "$SM_ROOT"; then return 1; fi
	published=1
	if [ -n "$settings" ]; then mv -fT "$settings" "$SM_SETTINGS" || return 1; else rm -f "$SM_SETTINGS" || return 1; fi
	committed=1
	return 0
)

_sm_prepare_permissions() {
	local root=$1
	_sm_tree_safe "$root" || return 1
	find "$root" -type d -exec chmod 755 {} + && find "$root" -type f -exec chmod 644 {} + || return 1
	: >"$root/.onebox-site-owned" && chmod 644 "$root/.onebox-site-owned"
}

_sm_backup_select() {
	local id=${1:-latest}
	if [ "$id" = latest ]; then
		_sm_path "$SM_BACKUPS/latest" >/dev/null || return 1
		[ -f "$SM_BACKUPS/latest" ] || { err "没有可用的网站内容备份索引"; return 1; }
		id=$(cat "$SM_BACKUPS/latest" 2>/dev/null) || { err "还没有网站内容备份"; return 1; }
	fi
	[[ "$id" =~ ^[0-9]{8}T[0-9]{6}Z-[a-f0-9]{8}$ ]] || { err "没有可用备份，或备份编号无效"; return 1; }
	_sm_path "$SM_BACKUPS/$id" >/dev/null || return 1
	_sm_tree_safe "$SM_BACKUPS/$id" || return 1
	[ -f "$SM_BACKUPS/$id/complete" ] && [ -f "$SM_BACKUPS/$id/root-path" ] && [ "$(cat "$SM_BACKUPS/$id/root-path" 2>/dev/null)" = "$SM_ROOT" ] || { err "备份不完整或不属于当前网站"; return 1; }
	printf '%s' "$SM_BACKUPS/$id"
}

do_site_manage() (
	local action=${1:-} source='' backup='' stage='' settings='' lock='' preview='' expected
	[ "$#" -gt 0 ] && shift
	require_installed
	site_enabled || { err "未启用自有域名网站，请先运行 onebox sni --reality-site 你的域名"; return 1; }
	_sm_paths || return 1
	lock="$SM_PRIVATE/.content-lock"
	mkdir "$lock" 2>/dev/null || { err "另一个网站内容操作正在进行，请稍后重试"; return 1; }
	trap '[ -z "$stage" ] || rm -rf "$stage"; [ -z "$settings" ] || rm -f "$settings"; [ -z "$lock" ] || rmdir "$lock" 2>/dev/null' EXIT
	trap 'exit 130' INT
	trap 'exit 143' TERM HUP
	_sm_settings_read "$SM_SETTINGS" || { err "网站内容设置损坏，请先从完整备份恢复"; [ "$action" = restore ] || return 1; }
	case "$action" in
	title)
		[ "$#" = 1 ] || { err "用法: onebox site title <标题>"; return 1; }
		[ "$SM_KIND" = template ] || { err "导入或自定义网页不支持自动改标题，请编辑原始网页后重新导入"; return 1; }
		if [ -n "$SM_INDEX_HASH" ] && [ "$(_site_hash <"$SM_ROOT/index.html")" != "$SM_INDEX_HASH" ]; then err "主页已手工修改，不能用模板覆盖；请修改原网页后重新导入"; return 1; fi
		SM_TITLE=$1
		_sm_options || return 1
		;;
	template | preview)
		[ "$#" -ge 1 ] || { err "模板可选 minimal、profile、docs"; return 1; }
		SM_TEMPLATE=$1 SM_KIND=template
		shift
		case "$SM_TEMPLATE" in minimal | profile | docs) ;; *) err "模板可选 minimal、profile、docs"; return 1 ;; esac
		_sm_options "$@" || return 1
		if [ "$action" = preview ]; then
			_sm_path "$SM_PRIVATE/previews" >/dev/null || return 1
			mkdir -p "$SM_PRIVATE/previews" && chmod 700 "$SM_PRIVATE/previews" || return 1
			preview=$(mktemp "$SM_PRIVATE/previews/${SM_TEMPLATE}.XXXXXX.html") || return 1
			if ! _sm_render >"$preview" || ! chmod 600 "$preview"; then rm -f "$preview"; return 1; fi
			info "预览已生成，尚未发布: $preview"
			return 0
		fi
		;;
	import)
		[ "$#" = 1 ] || { err "用法: onebox site import <静态网站目录>"; return 1; }
		source=$(_sm_path "$1") || return 1
		case "$source" in /etc/* | /usr/* | /bin | /bin/* | /sbin | /sbin/* | /lib | /lib/* | /lib64 | /lib64/* | /var/log | /var/log/*) err "不能导入系统文件目录"; return 1 ;; esac
		case "$source/" in "$SM_ROOT/"* | "$SM_PRIVATE/"*) err "不能从当前网站或私密配置目录中递归导入"; return 1 ;; esac
		case "$SM_ROOT/" in "$source/"*) err "导入目录不能包含当前网站"; return 1 ;; esac
		case "$SM_PRIVATE/" in "$source/"*) err "导入目录不能包含私密配置"; return 1 ;; esac
		_sm_tree_safe "$source" && [ -f "$source/index.html" ] && [ -s "$source/index.html" ] || { err "请导入含 index.html 的普通静态文件目录"; return 1; }
		SM_KIND=import SM_TEMPLATE=none SM_TITLE='导入的网站' SM_DESCRIPTION='由本地静态文件目录导入。' SM_THEME=forest
		;;
	restore)
		[ "$#" -le 1 ] || { err "用法: onebox site restore [备份编号|latest]"; return 1; }
		source=$(_sm_backup_select "${1:-latest}") || return 1
		;;
	*) err "网站内容命令: title、template、import、restore、preview"; return 1 ;;
	esac
	backup=$(_sm_snapshot) || { err "无法完整备份原网站，已取消发布"; return 1; }
	backup="$SM_BACKUPS/$backup"
	stage=$(mktemp -d "${SM_ROOT%/*}/.onebox-content.XXXXXX") || return 1
	settings=$(mktemp "$SM_PRIVATE/.content-settings.XXXXXX") || return 1
	case "$action" in
	import)
		# A public tree must be owned by the publishing user, never by its source author.
		cp -R -P "$source/." "$stage/" && _sm_tree_safe "$stage" || return 1
		;;
	restore)
		cp -R -P "$source/root/." "$stage/" && _sm_tree_safe "$stage" || return 1
		if [ -f "$source/settings.tsv" ]; then cp -p "$source/settings.tsv" "$settings" || return 1; _sm_settings_read "$settings" || { err "备份内容设置损坏"; return 1; }; else rm -f "$settings"; settings=''; fi
		;;
	*) cp -R -P "$SM_ROOT/." "$stage/" && _sm_tree_safe "$stage" && _sm_render >"$stage/index.html" || return 1 ;;
	esac
	if [ "$action" = import ] || [ "$action" = restore ]; then
		# Content changes must not replace an active HTTP-01 validation challenge.
		rm -rf "$stage/.well-known/acme-challenge" || return 1
		if [ -d "$SM_ROOT/.well-known/acme-challenge" ]; then mkdir -p "$stage/.well-known" && cp -R -P "$SM_ROOT/.well-known/acme-challenge" "$stage/.well-known/" || return 1; fi
	fi
	_sm_prepare_permissions "$stage" && [ -f "$stage/index.html" ] && [ -s "$stage/index.html" ] || return 1
	if [ "$action" != restore ]; then
		expected=$(_site_hash <"$stage/index.html")
		[[ "$expected" =~ ^[a-f0-9]{64}$ ]] || return 1
		_sm_settings_write "$settings" "$expected" || return 1
	fi
	_sm_publish "$stage" "$settings" "$backup" || { err "发布失败，原网站恢复信息见上方；完整备份: ${backup##*/}"; return 1; }
	stage='' settings=''
	info "网站内容已发布；变更前完整备份: ${backup##*/}"
)

site_manage_menu() {
	local choice value template description theme
	site_enabled || { warn "请先启用自有域名网站"; return 1; }
	printf '%s\n' '  1) 修改标题  2) 切换模板  3) 导入静态网站  4) 恢复备份  5) 预览模板  0) 返回'
	ask_num choice "请选择" 0 0 5 || return 1
	case "$choice" in
	0) return 0 ;;
	1) ask value "新标题" "${REALITY_SITE_TITLE:-山间手记}"; do_site_manage title "$value" ;;
	2 | 5)
		ask template "模板 (minimal/profile/docs)" minimal
		ask value "标题" "${REALITY_SITE_TITLE:-山间手记}"
		ask description "简介" '记录日常，整理想法，分享值得停留的片刻。'
		ask theme "配色 (forest/ocean/slate)" forest
		if [ "$choice" = 2 ]; then do_site_manage template "$template" --title "$value" --description "$description" --theme "$theme"; else do_site_manage preview "$template" --title "$value" --description "$description" --theme "$theme"; fi
		;;
	3) ask value "静态网站目录 (需包含 index.html)" ''; do_site_manage import "$value" ;;
	4) ask value "备份编号 (latest 为最近一次变更前)" latest; do_site_manage restore "$value" ;;
	esac
}

# END site-management

# BEGIN menus
# Shared mutation wrapper: snapshots read the previous on-disk state before edits.
managed_change() {
	snapshot_checkpoint "before-${1#do_}"
	"$@"
}

recovery_menu() {
	local choice label id
	echo '  1) 立即备份  2) 查看备份  3) 恢复备份  0) 返回'
	ask_num choice "请选择" 0 0 3 || return 0
	case "$choice" in
	1) ask label "备份标签" manual; do_backup "$label" ;;
	2) do_backups ;;
	3)
		do_backups || return 1
		ask id "要恢复的完整备份 ID" ''
		[ -n "$id" ] || return 0
		confirm "恢复会替换当前节点设置和网页，并先备份当前状态，继续?" n || return 0
		do_restore "$id"
		;;
	esac
}

update_menu() {
	local choice channel
	echo '  1) 检查更新  2) 更新脚本  3) 选择更新渠道  0) 返回'
	ask_num choice "请选择" 0 0 3 || return 0
	case "$choice" in
	1) do_update_check ;;
	2) managed_change do_update_script && exec "$CMD_PATH" ;;
	3)
		ask channel "渠道 (stable 稳定版 / testing 测试版)" "$(update_channel_get)"
		do_update_channel "$channel"
		;;
	esac
}

plan_menu() (
	local preset
	ask_num preset "预演哪个协议组合 (1–7，见安装菜单)" 1 1 7 || return 0
	OPT_PRESET=$preset
	do_install_plan
)

# END menus

# BEGIN snapshots
# Persistent, local snapshots. Only declarative state is decoded; snapshot files
# are never sourced. Core executables, ACME programs/accounts and system files
# stay outside the archive. Format 1 supports the same script major version and
# managed paths; restored configs are validated by the installed cores.
SNAPSHOT_RESTORE_SOURCE=""

_snapshot_root() { printf '%s/backups' "$ONEBOX_DIR"; }
_snapshot_id_valid() { [[ "$1" =~ ^[0-9]{8}T[0-9]{6}Z-[A-Za-z0-9]{6}$ ]]; }
_snapshot_path_safe() {
	local path=$1
	[[ "$path" = /* && "$path" != / && "$path" != *'/../'* && "$path" != */.. && "$path" != *'/./'* && "$path" != */. ]] || return 1
	while [ "$path" != / ] && [ -n "$path" ]; do
		[ ! -L "$path" ] || return 1
		path=${path%/*}; [ -n "$path" ] || path=/
	done
}
_snapshot_paths() {
	local path
	case "$ONEBOX_DIR" in /|/etc|/var|/var/lib|/root|/home|/usr|/opt|/tmp|/run) return 1 ;; esac
	# Never infer a destructive destination from snapshot metadata.
	[ "$STATE_FILE" = "$ONEBOX_DIR/onebox.conf" ] && [ "$CLIENT_DIR" = "$ONEBOX_DIR/client" ] &&
		[ "$TLS_DIR" = "$ONEBOX_DIR/tls" ] && [ "$REALITY_SITE_DIR" = "$ONEBOX_DIR/site" ] || return 1
	for path in "$ONEBOX_DIR" "$(_snapshot_root)" "$CLIENT_DIR" "$TLS_DIR" "$REALITY_SITE_DIR" "$REALITY_SITE_ROOT"; do
		_snapshot_path_safe "$path" || { err "快照路径包含符号链接或不安全路径: $path"; return 1; }
	done
	case "$REALITY_SITE_ROOT" in /etc|/var|/var/lib|/root|/home|/usr|/opt|/tmp|/run) return 1 ;; esac
	case "$REALITY_SITE_ROOT/" in "$ONEBOX_DIR/"*) return 1 ;; esac
	for path in "$REALITY_SITE_DIR" "$REALITY_SITE_ROOT"; do
		if [ -d "$path" ] && [ ! -f "$path/.onebox-site-owned" ] && [ -n "$(ls -A "$path")" ]; then
			err "拒绝覆盖不归 onebox 管理的网站目录: $path"
			return 1
		fi
	done
}
_snapshot_tree_safe() {
	local tree=$1 file bytes total=0 count=0 limit=${ONEBOX_BACKUP_MAX_BYTES:-67108864}
	[[ "$limit" =~ ^[1-9][0-9]{0,9}$ ]] || return 1
	[ ! -e "$tree" ] && return 0
	_snapshot_path_safe "$tree" || return 1
	[ -z "$(find "$tree" \( -type l -o \( ! -type d ! -type f \) -o \( -type f -links +1 \) \) -print -quit)" ] || {
		err "快照不接受符号链接、硬链接或特殊文件: $tree"; return 1;
	}
	while IFS= read -r -d '' file; do
		[[ "$file" != *[[:cntrl:]]* ]] || { err "快照文件名不能包含控制字符"; return 1; }
		bytes=$(stat -c %s "$file") || return 1
		total=$((total + bytes)) count=$((count + 1))
		if [ "$total" -gt "$limit" ] || [ "$count" -gt 4096 ]; then
			err "快照超过大小限制 ${limit} 字节或 4096 个文件；请先缩减网站内容"
			return 1
		fi
	done < <(find "$tree" -type f -print0)
}
_snapshot_keys() {
	local key proto
	printf '%s\n' $STATE_KEYS
	for proto in $ALL_PROTOCOLS; do for key in PORT CORE; do printf '%s_%s\n' "$key" "${proto//-/_}"; done; done
}
_snapshot_write_state() {
	local key
	while IFS= read -r key; do printf '%s\0%s\0' "$key" "${!key-}" || return 1; done < <(_snapshot_keys)
}
_snapshot_load_state() {
	local file=$1 key="" value allowed
	local -A seen=()
	allowed=" $(_snapshot_keys | tr '\n' ' ')"
	reset_state
	while IFS= read -r -d '' key; do
		IFS= read -r -d '' value || return 1
		[[ "$key" =~ ^[A-Z][A-Za-z0-9_]*$ && "$allowed" == *" $key "* ]] || return 1
		[ -z "${seen[$key]+yes}" ] || return 1
		seen[$key]=1
		printf -v "$key" '%s' "$value"
	done <"$file"
	[ -z "$key" ] && [ -n "${PROTOCOLS:-}" ] || return 1
	local proto
	for proto in $PROTOCOLS; do
		case " $ALL_PROTOCOLS " in *" $proto "*) ;; *) return 1 ;; esac
		case "$(pget CORE "$proto")" in singbox|xray) ;; *) return 1 ;; esac
		value=$(pget PORT "$proto")
		[[ "$value" =~ ^[1-9][0-9]{0,4}$ ]] && [ "$value" -le 65535 ] || return 1
	done
	case "${TLS_MODE:-}" in ''|self|acme|custom) ;; *) return 1 ;; esac
	if [ "${TLS_MODE:-}" = acme ]; then
		valid_domain "$DOMAIN" || return 1
		case "$ACME_METHOD" in standalone|cf) ;; *) return 1 ;; esac
	fi
	site_validate_ports
}
_snapshot_hash() { openssl dgst -sha256 "$1" 2>/dev/null | sed 's/^.*= *//'; }
_snapshot_manifest() {
	local dir=$1 file hash
	while IFS= read -r -d '' file; do
		[ "$file" != "$dir/manifest" ] || continue
		hash=$(_snapshot_hash "$file")
		[[ "$hash" =~ ^[a-f0-9]{64}$ ]] || return 1
		printf '%s\0%s\0' "$hash" "${file#"$dir/"}" || return 1
	done < <(find "$dir" -type f -print0)
}
_snapshot_verify() {
	local dir=$1 hash="" rel count=0 actual version
	_snapshot_tree_safe "$dir" || return 1
	[ "$(stat -c %u "$dir")" = "$(id -u)" ] && [ "$(stat -c %a "$dir")" = 700 ] || return 1
	[ "$(cat "$dir/format" 2>/dev/null)" = 1 ] || return 1
	version=$(cat "$dir/version")
	[ "${version%%.*}" = "${SCRIPT_VERSION%%.*}" ] || { err "快照主版本与当前脚本不兼容"; return 1; }
	[ "$(cat "$dir/paths")" = "$(printf '%s\n' "$ONEBOX_DIR" "$REALITY_SITE_ROOT")" ] || { err "快照仅支持在原受管路径恢复"; return 1; }
	local -A seen=()
	while IFS= read -r -d '' hash; do
		IFS= read -r -d '' rel || return 1
		[[ "$hash" =~ ^[a-f0-9]{64}$ && "$rel" != /* && "$rel" != manifest && -n "$rel" ]] || return 1
		case "/$rel/" in */../*|*/./*) return 1 ;; esac
		[ -z "${seen[$rel]+yes}" ] && [ -f "$dir/$rel" ] || return 1
		seen[$rel]=1
		[ "$hash" = "$(_snapshot_hash "$dir/$rel")" ] || { err "快照校验失败: $rel"; return 1; }
		count=$((count + 1))
	done <"$dir/manifest"
	[ -z "$hash" ] || return 1
	actual=$(find "$dir" -type f | wc -l)
	[ "$actual" -eq "$((count + 1))" ] && (_snapshot_load_state "$dir/state.dat")
}
_snapshot_copy_optional() {
	local source=$1 target=$2
	[ -e "$source" ] || return 0
	_snapshot_tree_safe "$source" && cp -a "$source" "$target"
}
_snapshot_capture() (
	local dir=$1 label=$2 order=$3 file
	load_state || return 1
	_snapshot_write_state >"$dir/state.dat" || return 1
	printf '1\n' >"$dir/format"
	printf '%s\n' "$SCRIPT_VERSION" >"$dir/version"
	printf '%s\n' "$label" >"$dir/label"
	printf '%s\n' "$order" >"$dir/order"
	printf '%s\n' "$ONEBOX_DIR" "$REALITY_SITE_ROOT" >"$dir/paths"
	_snapshot_copy_optional "$SB_CONF" "$dir/sing-box.json" &&
		_snapshot_copy_optional "$XR_CONF" "$dir/xray.json" &&
		_snapshot_copy_optional "$CLIENT_DIR" "$dir/client" &&
		_snapshot_copy_optional "$TLS_DIR" "$dir/tls" || return 1
	if [ -f "$REALITY_SITE_DIR/.onebox-site-owned" ]; then
		mkdir "$dir/site" || return 1
		for file in cert.pem key.pem cert-domain index.sha256 content-settings.tsv; do
			_snapshot_copy_optional "$REALITY_SITE_DIR/$file" "$dir/site/$file" || return 1
		done
		[ ! -d "$REALITY_SITE_ROOT" ] || [ -f "$REALITY_SITE_ROOT/.onebox-site-owned" ] || return 1
		_snapshot_copy_optional "$REALITY_SITE_ROOT" "$dir/public" || return 1
	fi
	_snapshot_tree_safe "$dir" || return 1
	_snapshot_manifest "$dir" >"$dir/manifest" || return 1
	chown -R "$(id -u):$(id -g)" "$dir" &&
		find "$dir" -type d -exec chmod 700 {} + && find "$dir" -type f -exec chmod 600 {} +
)
_snapshot_prune() {
	local root dir count=1 keep=$1
	root=$(_snapshot_root)
	while IFS= read -r dir; do
		_snapshot_id_valid "$dir" || continue
		[ "$dir" != "$keep" ] || continue
		[ -d "$root/$dir" ] && [ ! -L "$root/$dir" ] || continue
		count=$((count + 1))
		[ "$count" -le 5 ] || rm -rf -- "${root:?}/${dir:?}" || return 1
	done < <(_snapshot_ids "$root")
}
_snapshot_ids() {
	local path order
	for path in "$1"/*; do
		[ -d "$path" ] && [ ! -L "$path" ] || continue
		_snapshot_id_valid "${path##*/}" || continue
		[ -f "$path/order" ] && [ ! -L "$path/order" ] || continue
		order=$(cat "$path/order" 2>/dev/null)
		[[ "$order" =~ ^[1-9][0-9]{0,8}$ ]] && printf '%09d %s\n' "$order" "${path##*/}"
	done | sort -r | cut -d ' ' -f2-
}
snapshot_create() {
	local label=${1:-manual} root tmp id newest order=1
	[ "${#label}" -le 80 ] && [[ "$label" != *[[:cntrl:]]* ]] || { err "备份标签最多80个字符，不能含控制字符"; return 1; }
	_snapshot_paths || return 1
	root=$(_snapshot_root)
	if [ -e "$root" ] && [ "$(stat -c %u "$root")" != "$(id -u)" ]; then return 1; fi
	mkdir -p "$root" && chmod 700 "$root" || return 1
	newest=$(_snapshot_ids "$root" | head -n1)
	if [ -n "$newest" ]; then order=$(cat "$root/$newest/order"); order=$((order + 1)); fi
	tmp=$(mktemp -d "$root/.snapshot.XXXXXX") || return 1
	if ! _snapshot_capture "$tmp" "$label" "$order" || ! _snapshot_verify "$tmp"; then rm -rf -- "$tmp"; return 1; fi
	id="$(date -u +%Y%m%dT%H%M%SZ)-${tmp##*.}"
	if ! mv -T "$tmp" "$root/$id"; then rm -rf -- "$tmp"; return 1; fi
	_snapshot_prune "$id" || warn "快照已保存，但旧快照清理失败"
	printf '%s\n' "$id"
}
snapshot_checkpoint() {
	[ -f "$STATE_FILE" ] || return 0
	local id
	if id=$(snapshot_create "${1:-automatic}"); then
		info "已保存本机快照: $id"
	else
		warn "未能保存自动快照，已有快照保持可用；可执行 onebox backup 重试"
	fi
	return 0
}
do_backup() {
	local id
	[ $# -le 1 ] || { err "用法: onebox backup [标签]"; return 1; }
	id=$(snapshot_create "${1:-manual}") || return 1
	info "快照已保存: $id（包含私钥；仅本机保留最近5份）"
}
do_backups() {
	local root dir
	_snapshot_paths || return 1
	root=$(_snapshot_root)
	[ -d "$root" ] || { info "暂无快照"; return 0; }
	printf 'ID\t版本\t标签\n'
	while IFS= read -r dir; do
		_snapshot_id_valid "$dir" && [ ! -L "$root/$dir" ] || continue
		[ -f "$root/$dir/version" ] && [ ! -L "$root/$dir/version" ] &&
			[ -f "$root/$dir/label" ] && [ ! -L "$root/$dir/label" ] || continue
		printf '%s\t%s\t%s\n' "$dir" "$(cat "$root/$dir/version")" "$(cat "$root/$dir/label")"
	done < <(_snapshot_ids "$root")
}

# Called by apply_all after normal client generation, before certificate commit.
snapshot_restore_clients() {
	[ -n "${SNAPSHOT_RESTORE_SOURCE:-}" ] || return 0
	_site_restore_directory "$SNAPSHOT_RESTORE_SOURCE/client" "$CLIENT_DIR"
}
_snapshot_restore_assets() {
	local dir=$1 file
	_site_restore_directory "$dir/tls" "$TLS_DIR" || return 1
	if [ -d "$dir/public" ]; then
		_site_restore_directory "$dir/public" "$REALITY_SITE_ROOT" || return 1
		find "$REALITY_SITE_ROOT" -type d -exec chmod 755 {} + && find "$REALITY_SITE_ROOT" -type f -exec chmod 644 {} + || return 1
	fi
	if [ -d "$dir/site" ]; then
		mkdir -p "$REALITY_SITE_DIR" && chmod 700 "$REALITY_SITE_DIR" || return 1
		: >"$REALITY_SITE_DIR/.onebox-site-owned"
		for file in cert.pem key.pem index.sha256 content-settings.tsv; do
			if [ -f "$dir/site/$file" ]; then cp -p "$dir/site/$file" "$REALITY_SITE_DIR/$file" || return 1; else rm -f "$REALITY_SITE_DIR/$file" || return 1; fi
		done
		# Keep the live cert-domain and ACME home: a domain change must remove the
		# previous renewal before installing the target deployment. Never restore
		# nginx configs with a 443 listener before the old core has stopped.
		rm -f "$REALITY_SITE_DIR/settings.sha256" || return 1
	fi
}
do_restore() {
	local id=${1:-} root source staging before rc
	[ $# = 1 ] || { err "用法: onebox restore <备份ID>"; return 1; }
	_snapshot_id_valid "$id" || { err "请使用 onebox backups 列出的快照 ID"; return 1; }
	_snapshot_paths || return 1
	root=$(_snapshot_root) source="$(_snapshot_root)/$id"
	[ -d "$source" ] && [ ! -L "$source" ] && _snapshot_verify "$source" || { err "快照不存在、不兼容或完整性校验失败"; return 1; }
	load_state || return 1
	[ -z "${CERT_TXN_BAK:-}${SITE_TXN_BAK:-}" ] || { err "有尚未完成的事务，请先完成恢复"; return 1; }
	# Stage the selected snapshot before saving current state: retention may
	# otherwise remove the oldest selected ID when the sixth backup is created.
	staging=$(mktemp -d "$root/.restore.XXXXXX") || return 1
	if ! cp -a "$source/." "$staging/"; then rm -rf -- "$staging"; return 1; fi
	before=$(snapshot_create before-restore) || { rm -rf -- "$staging"; err "当前状态备份失败，未开始恢复"; return 1; }
	if [ -d "$CLIENT_DIR" ] && ! cp -a "$CLIENT_DIR" "$staging/previous-client"; then rm -rf -- "$staging"; return 1; fi
	info "恢复前备份: $before"
	if ! cert_txn_begin || ! _site_txn_begin; then cert_txn_rollback --files-only; rm -rf -- "$staging"; return 1; fi
	if ! _snapshot_load_state "$staging/state.dat" || ! _snapshot_restore_assets "$staging"; then
		cert_txn_rollback --files-only
		rm -rf -- "$staging"
		return 1
	fi
	# Rebind managed ACME certificates using the existing transaction. This can
	# require network access/DNS credentials; a failure leaves the old deployment
	# recoverable. External custom-certificate paths are read, never overwritten.
	rc=0
	site_prepare || rc=1
	if [ "$rc" = 0 ] && [ "$TLS_MODE" = acme ]; then
		if [ "$ACME_METHOD" = standalone ] && ! site_enabled; then site_service stop || rc=1; fi
		if [ "$rc" = 0 ]; then cert_acme "$DOMAIN" "$ACME_METHOD" || rc=1; fi
	fi
	if [ "$rc" != 0 ]; then
		cert_txn_rollback
		_site_restore_directory "$staging/previous-client" "$CLIENT_DIR" || err "原客户端目录恢复失败，请使用快照 $before"
		rm -rf -- "$staging"
		return 1
	fi
	SNAPSHOT_RESTORE_SOURCE=$staging
	apply_all
	rc=$?
	SNAPSHOT_RESTORE_SOURCE=""
	if [ "$rc" != 0 ]; then
		_site_restore_directory "$staging/previous-client" "$CLIENT_DIR" || err "原客户端目录恢复失败，请使用快照 $before"
	fi
	rm -rf -- "$staging"
	if [ "$rc" != 0 ]; then err "恢复未成功，已尝试回滚；恢复前快照: $before"; return "$rc"; fi
	info "已恢复快照 $id；证书续期使用当前 ACME 安装，未恢复系统软件"
}

# END snapshots

# ONEBOX_SOURCE_ONLY=1 时仅加载函数 (供测试使用)
[ -n "${ONEBOX_SOURCE_ONLY:-}" ] || main "$@"
