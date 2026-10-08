#!/bin/sh
# Sing-Xray-Onebox: thin Linux launcher; all management logic lives in the Rust binary.
#
#   sh onebox.sh [command] [options...]      arguments are passed through verbatim
#   ONEBOX_NATIVE_BIN=./onebox sh onebox.sh  run a local build offline (no download, no PATH search)
#   GH_PROXY=https://mirror.example/         fetch the release assets through an HTTPS mirror prefix
#
# The pinned release binary is fetched over HTTPS only, must match a uniquely
# listed SHA256SUMS entry and report exactly SCRIPT_VERSION before it runs.
set -u
umask 077
readonly SCRIPT_VERSION="3.0.0"
readonly ONEBOX_REPOSITORY="mutsuki14/Sing-xray-onebox"
readonly MAX_SUMS_BYTES=65536
readonly MAX_BINARY_BYTES=134217728

fail() { printf '[错误] %s\n' "$*" >&2; exit 1; }

[ "$(uname -s)" = Linux ] || fail '仅支持 Linux；其他平台请参考仓库 README 从源码构建。'

# An explicit local program is trusted as supplied: never downloaded, replaced
# or looked up in PATH (a bare name means the file in the current directory).
if [ -n "${ONEBOX_NATIVE_BIN:-}" ]; then
    case "$ONEBOX_NATIVE_BIN" in /*) native=$ONEBOX_NATIVE_BIN ;; *) native=./$ONEBOX_NATIVE_BIN ;; esac
    [ -f "$native" ] && [ -x "$native" ] || fail "ONEBOX_NATIVE_BIN 必须指向可执行的本地文件：$ONEBOX_NATIVE_BIN"
    exec "$native" "$@"
fi

machine=$(uname -m)
case "$machine" in
    x86_64|amd64) arch=amd64 ;;
    aarch64|arm64) arch=arm64 ;;
    i586|i686) arch=386 ;;
    armv7*|armv8l) arch=armv7 ;;
    *) fail "当前架构（$machine）没有预编译版本；请从 https://github.com/$ONEBOX_REPOSITORY 获取源码并运行 cargo build --release，再用 ONEBOX_NATIVE_BIN 指定构建出的程序。" ;;
esac

command -v curl >/dev/null 2>&1 || fail '请先安装 curl（下载全程强制 HTTPS），或用 ONEBOX_NATIVE_BIN 运行本地程序。'
if command -v sha256sum >/dev/null 2>&1; then hasher=sha256sum
elif command -v shasum >/dev/null 2>&1; then hasher=shasum
elif command -v openssl >/dev/null 2>&1; then hasher=openssl
else fail '请先安装 sha256sum、shasum 或 openssl，用于校验下载内容。'
fi

asset="onebox-linux-$arch-musl"
base="https://github.com/$ONEBOX_REPOSITORY/releases/download/v$SCRIPT_VERSION"
proxy=${GH_PROXY:-}
if [ -n "$proxy" ]; then
    case "$proxy" in https://?*) ;; *) fail 'GH_PROXY 必须是以 https:// 开头的前缀。' ;; esac
    case "$proxy" in *[[:space:][:cntrl:]]*) fail 'GH_PROXY 不能包含空白或控制字符。' ;; esac
    base="${proxy%/}/$base"
fi

work=''
child=''
cleanup() { [ -z "$work" ] || rm -rf -- "$work"; }
# Forward a signal to the running child (curl or onebox) and wait for it, so a
# cancelled change can roll back before the download is removed.
forward() {
    trap '' HUP INT TERM
    if [ -n "$child" ]; then
        # Asynchronous children of a non-interactive shell may ignore SIGINT;
        # TERM requests the same cancellation everywhere.
        signal=$1
        [ "$signal" != INT ] || signal=TERM
        kill -"$signal" "$child" 2>/dev/null || :
        # Allow 30 s for rollback, never wait forever: the transaction journal
        # of an unresponsive process supports a later `onebox recover`.
        (
            pause=''
            trap '[ -z "$pause" ] || { kill "$pause"; wait "$pause"; } 2>/dev/null; exit 0' HUP INT TERM
            sleep 30 &
            pause=$!
            wait "$pause" || exit 0
            kill -KILL "$child" 2>/dev/null || :
        ) </dev/null >/dev/null 2>&1 &
        watchdog=$!
        wait "$child" 2>/dev/null || :
        kill -TERM "$watchdog" 2>/dev/null || :
        wait "$watchdog" 2>/dev/null || :
    fi
    exit "$2"
}
trap cleanup 0
trap 'forward HUP 129' HUP
trap 'forward INT 130' INT
trap 'forward TERM 143' TERM

work=$(mktemp -d "${TMPDIR:-/tmp}/onebox-download.XXXXXXXX") || fail '无法创建下载临时目录，请检查 TMPDIR。'

# fetch URL DEST MAX_BYTES — HTTPS only (redirects included), TLS 1.2 or newer.
fetch() {
    curl --proto '=https' --proto-redir '=https' --tlsv1.2 -fLsS --connect-timeout 15 --retry 3 \
        --speed-limit 1024 --speed-time 60 --max-time 1800 --max-filesize "$3" -o "$2" "$1" &
    child=$!
    fetched=0
    wait "$child" || fetched=$?
    child=''
    return "$fetched"
}
file_size() { if [ -f "$1" ]; then wc -c < "$1" | tr -d '[:space:]'; else echo 0; fi; }
sha256() {
    case "$hasher" in
        sha256sum) sha256sum ;;
        shasum) shasum -a 256 ;;
        openssl) openssl dgst -sha256 ;;
    esac < "$1"
}

[ ! -t 2 ] || printf '[提示] 正在下载并校验 Onebox %s（linux-%s）…\n' "$SCRIPT_VERSION" "$arch" >&2
sums=$work/SHA256SUMS
fetch "$base/SHA256SUMS" "$sums" "$MAX_SUMS_BYTES" ||
    fail "无法下载 v$SCRIPT_VERSION 的校验文件 SHA256SUMS；请检查网络或 GH_PROXY、确认该版本已发布，或用 ONEBOX_NATIVE_BIN 运行本地程序。"
[ "$(file_size "$sums")" -le "$MAX_SUMS_BYTES" ] || fail '校验文件 SHA256SUMS 异常大，已停止。'
expected=$(awk -v name="$asset" '
    $2 == name {
        count++
        if (NF != 2 || length($1) != 64 || $1 ~ /[^0-9A-Fa-f]/) bad = 1
        hash = $1
    }
    END { if (count != 1 || bad) exit 1; print tolower(hash) }
' "$sums") || fail "SHA256SUMS 没有唯一且格式正确的 $asset 条目，已停止。"

bin=$work/$asset
fetch "$base/$asset" "$bin" "$MAX_BINARY_BYTES" || fail "无法下载 $asset；请检查网络或 GH_PROXY。"
size=$(file_size "$bin")
[ "$size" -gt 0 ] && [ "$size" -le "$MAX_BINARY_BYTES" ] || fail "下载的 $asset 为空或异常大，已停止。"
digest=$(sha256 "$bin") || fail '无法计算 SHA-256。'
case "$hasher" in openssl) actual=${digest##* } ;; *) actual=${digest%% *} ;; esac
[ "$actual" = "$expected" ] || fail 'SHA-256 校验失败，未执行下载内容。'
chmod 700 "$bin" || fail '无法设置程序执行权限。'
reported=$("$bin" --version </dev/null) ||
    fail "下载的程序无法运行；若 ${TMPDIR:-/tmp} 所在分区禁止执行（noexec），请用 TMPDIR 指定其他目录。"
[ "$reported" = "$SCRIPT_VERSION" ] || fail "下载的程序版本与 v$SCRIPT_VERSION 不匹配，未运行请求的命令。"

# Run as a child rather than exec: the launcher forwards signals and removes the
# download afterwards (installing copies /proc/self/exe). An asynchronous child
# would get /dev/null as stdin, so fd 3 hands it the original one.
if ! { command exec 3<&0; } 2>/dev/null; then exec 3</dev/null; fi
"$bin" "$@" <&3 3<&- &
child=$!
exec 3<&-
status=0
wait "$child" || status=$?
child=''
exit "$status"
