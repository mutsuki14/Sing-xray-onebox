#!/bin/sh
# Sing-Xray-Onebox: thin Linux launcher; all management logic lives in Rust.
set -u
umask 077
readonly SCRIPT_VERSION="2.0.1"
readonly ONEBOX_REPOSITORY="mutsuki14/Sing-xray-onebox"

fail() { printf 'onebox: %s\n' "$*" >&2; exit 1; }

[ "$(uname -s)" = Linux ] || fail '仅支持 Linux；其他平台请查看仓库的源码构建说明。'

# An explicit local executable is trusted as supplied; never download or replace it.
if [ -n "${ONEBOX_NATIVE_BIN:-}" ]; then
    [ -f "$ONEBOX_NATIVE_BIN" ] && [ -x "$ONEBOX_NATIVE_BIN" ] || fail 'ONEBOX_NATIVE_BIN 必须指向可执行的本地文件。'
    # Check and execute the same file; bare names must not trigger a PATH search.
    case "$ONEBOX_NATIVE_BIN" in */*) native=$ONEBOX_NATIVE_BIN ;; *) native=./$ONEBOX_NATIVE_BIN ;; esac
    exec "$native" "$@"
fi

case "$(uname -m)" in
    x86_64|amd64) arch=amd64 ;;
    aarch64|arm64) arch=arm64 ;;
    i586|i686) arch=386 ;;
    armv7*|armv8l) arch=armv7 ;;
    *) fail "当前架构没有预编译版本；请从 https://github.com/$ONEBOX_REPOSITORY/tree/main 获取源码并运行 cargo build --release，或用 ONEBOX_NATIVE_BIN 指定已构建的程序。" ;;
esac

command -v curl >/dev/null 2>&1 || fail '请先安装 curl（用于强制 HTTPS 下载与重定向），或通过 ONEBOX_NATIVE_BIN 使用离线程序。'
if command -v sha256sum >/dev/null 2>&1; then hasher=sha256sum
elif command -v shasum >/dev/null 2>&1; then hasher=shasum
elif command -v openssl >/dev/null 2>&1; then hasher=openssl
else fail '请先安装 sha256sum、shasum 或 openssl 以验证下载。'
fi

asset="onebox-linux-$arch-musl"
base="https://github.com/$ONEBOX_REPOSITORY/releases/download/v$SCRIPT_VERSION"
proxy=${GH_PROXY:-}
if [ -n "$proxy" ]; then
    case "$proxy" in https://*) ;; *) fail 'GH_PROXY 必须是 HTTPS 前缀。' ;; esac
    case "$proxy" in *[[:space:]]*) fail 'GH_PROXY 不能包含空白字符。' ;; esac
    base="${proxy%/}/$base"
fi

work=$(mktemp -d "${TMPDIR:-/tmp}/onebox-native.XXXXXXXX") || fail '无法创建下载临时目录。'
child=''
cleanup() { rm -rf -- "$work"; }
interrupted() {
    signal=$1
    code=$2
    trap '' HUP INT TERM
    if [ -n "$child" ]; then
        # POSIX background commands may inherit SIGINT=ignore. TERM requests
        # the same native transaction cancellation even on such shells.
        [ "$signal" != INT ] || signal=TERM
        kill -"$signal" "$child" 2>/dev/null || :
        # Give native rollback time to finish, but never wait indefinitely for
        # an unresponsive process. Its durable journal supports later recovery.
        (
            pause=''
            trap '[ -z "$pause" ] || { kill "$pause" 2>/dev/null || :; wait "$pause" 2>/dev/null || :; }; exit 0' HUP INT TERM
            sleep 30 &
            pause=$!
            wait "$pause" || exit 0
            kill -KILL "$child" 2>/dev/null || :
        ) &
        watchdog=$!
        wait "$child" 2>/dev/null || :
        kill -TERM "$watchdog" 2>/dev/null || :
        wait "$watchdog" 2>/dev/null || :
    fi
    exit "$code"
}
trap cleanup 0
trap 'interrupted HUP 129' HUP
trap 'interrupted INT 130' INT
trap 'interrupted TERM 143' TERM

fetch() {
    curl --proto '=https' --proto-redir '=https' --tlsv1.2 -fLsS --connect-timeout 15 --max-time 300 --retry 2 -o "$2" "$1" &
    child=$!
    fetch_status=0
    wait "$child" || fetch_status=$?
    child=''
    return "$fetch_status"
}

fetch "$base/SHA256SUMS" "$work/SHA256SUMS" || fail "无法下载 v$SCRIPT_VERSION 校验文件；请确认该版本已发布，或使用 ONEBOX_NATIVE_BIN 离线运行。"
[ "$(wc -c < "$work/SHA256SUMS")" -le 65536 ] || fail '校验文件异常大。'
expected=$(awk -v name="$asset" '
    $2 == name {
        count++
        if (NF != 2 || length($1) != 64 || $1 ~ /[^0-9a-fA-F]/) bad = 1
        hash = $1
    }
    END { if (count != 1 || bad) exit 1; print tolower(hash) }
' "$work/SHA256SUMS") || fail "SHA256SUMS 未唯一列出 $asset。"

fetch "$base/$asset" "$work/$asset" || fail "无法下载 $asset。"
size=$(wc -c < "$work/$asset")
[ "$size" -gt 0 ] && [ "$size" -le 134217728 ] || fail '下载文件为空或异常大。'
case "$hasher" in
    sha256sum) actual=$(sha256sum "$work/$asset") || fail '无法计算 SHA-256。'; actual=${actual%% *} ;;
    shasum) actual=$(shasum -a 256 "$work/$asset") || fail '无法计算 SHA-256。'; actual=${actual%% *} ;;
    openssl) actual=$(openssl dgst -sha256 "$work/$asset") || fail '无法计算 SHA-256。'; actual=${actual##* } ;;
esac
[ "$actual" = "$expected" ] || fail 'SHA-256 校验失败，未执行下载内容。'
chmod 700 "$work/$asset" || fail '无法设置程序执行权限。'
reported=$("$work/$asset" --version) || fail '下载程序无法报告版本。'
[ "$reported" = "$SCRIPT_VERSION" ] || fail "下载程序版本与 v$SCRIPT_VERSION 不匹配，未运行请求的命令。"

# A child preserves the file for Rust's install_self() and lets this launcher
# clean up after success, failure, or a forwarded signal. Explicit stdin keeps
# interactive menus usable even though the command runs asynchronously.
exec 3<&0
"$work/$asset" "$@" <&3 3<&- &
child=$!
exec 3<&-
status=0
wait "$child" || status=$?
child=''
exit "$status"
