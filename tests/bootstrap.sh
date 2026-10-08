#!/usr/bin/env bash
# Fixture-only test of the onebox.sh launcher: fake uname, curl, hashers and a
# fake onebox on a private PATH. No network, no real download, no services.
#
#   bash tests/bootstrap.sh
#   ONEBOX_BOOTSTRAP_TEST_PATH=FILE           test another launcher file
#   ONEBOX_BOOTSTRAP_TEST_SHELLS="dash bash"  shells to run it with, each one required (default: sh bash dash
#                                             busybox, those present); busybox uses only its applets, like Alpine
#   ONEBOX_BOOTSTRAP_QUICK=1                  skip the 30-second watchdog case
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
LAUNCHER=${ONEBOX_BOOTSTRAP_TEST_PATH:-$ROOT/onebox.sh}
[[ $LAUNCHER == /* ]] || LAUNCHER=$PWD/$LAUNCHER
REPO=mutsuki14/Sing-xray-onebox
SHELL_NAME=static
CASE=header
WORK=$(mktemp -d)
trap 'rm -rf -- "$WORK"' EXIT

die() {
    printf 'FAIL [%s] %s: %s\n' "$SHELL_NAME" "$CASE" "$*" >&2
    for stream in stdout stderr; do
        [[ ! -s $WORK/$stream ]] || { printf -- '--- %s ---\n' "$stream" >&2; cat "$WORK/$stream" >&2; }
    done
    exit 1
}

# --- Static header ---
# 1.x updaters validate the line-2 marker; scripts/check-version.sh relies on
# the exact SCRIPT_VERSION line.
[[ $(sed -n 1p "$LAUNCHER") == '#!/bin/sh' ]] || die 'line 1 must be #!/bin/sh'
sed -n 2p "$LAUNCHER" | grep -q '^# Sing-Xray-Onebox: ' || die 'line 2 must carry the Sing-Xray-Onebox marker'
VERSION=$(sed -n 's/^readonly SCRIPT_VERSION="\([0-9]*\.[0-9]*\.[0-9]*\)"$/\1/p' "$LAUNCHER")
[[ $VERSION =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || die 'missing exact readonly SCRIPT_VERSION="X.Y.Z" line'
[[ $(grep -c '^readonly SCRIPT_VERSION=' "$LAUNCHER") == 1 ]] || die 'SCRIPT_VERSION must be set exactly once'
grep -qx "readonly ONEBOX_REPOSITORY=\"$REPO\"" "$LAUNCHER" || die 'missing exact ONEBOX_REPOSITORY line'
sh -n "$LAUNCHER" || die 'sh -n failed'
bash -n "$LAUNCHER" || die 'bash -n failed'
BASE_URL="https://github.com/$REPO/releases/download/v$VERSION"

# --- Fixtures ---
REAL_SHA256SUM=$(command -v sha256sum) || die 'sha256sum is required to run this test'
mkdir -p "$WORK/sys" "$WORK/assets" "$WORK/tmp" "$WORK/home" "$WORK/cwd/sub" "$WORK/cwd/empty"
# Real tools the launcher and fakes may use; hashers and curl are deliberately
# absent. SYS is the directory of the shell under test (busybox: its applets).
TOOLS=(awk cat chmod cp mkdir mktemp rm sleep tr truncate wc)
for tool in "${TOOLS[@]}"; do
    path=$(command -v "$tool") || die "$tool is required to run this test"
    ln -s "$path" "$WORK/sys/$tool"
done
SYS=$WORK/sys
fake() { mkdir -p "$WORK/fake/$1"; cat > "$WORK/fake/$1/$1"; chmod 755 "$WORK/fake/$1/$1"; }
fake_path() { local dirs='' name; for name; do dirs+="$WORK/fake/$name:"; done; printf '%s%s' "$dirs" "$SYS"; }

fake uname <<'EOF'
#!/bin/sh
case "${1:-}" in -s) printf '%s\n' "$MOCK_OS" ;; -m) printf '%s\n' "$MOCK_ARCH" ;; *) exit 1 ;; esac
EOF
fake curl <<'EOF'
#!/bin/sh
# Fake curl: logs each call and serves fixtures by URL basename.
printf '%s\n' "$*" >> "$FIXTURES/curl-args.log"
output='' url=''
while [ "$#" -gt 0 ]; do
    case "$1" in
        -o|--output) shift; output=$1 ;;
        https://*) url=$1 ;;
    esac
    shift
done
[ -n "$output" ] && [ -n "$url" ] || exit 2
if [ "${MOCK_WAIT:-}" = fetch ]; then
    trap 'printf HUP > "$FIXTURES/fetch-signalled"; exit 42' HUP
    trap 'printf INT > "$FIXTURES/fetch-signalled"; exit 42' INT
    trap 'printf TERM > "$FIXTURES/fetch-signalled"; exit 42' TERM
    printf ready > "$FIXTURES/fetch-ready"
    while :; do sleep 0.1; done
fi
printf '%s\n' "$url" >> "$FIXTURES/fetch.log"
name=${url##*/}
[ "$name" != "${MOCK_FETCH_FAIL:-}" ] || exit 22
if [ "$name" = SHA256SUMS ]; then
    cp "${MOCK_SUMS:-$MOCK_ASSETS/SHA256SUMS}" "$output" || exit 22
elif [ "${MOCK_CORRUPT:-0}" = 1 ]; then
    printf 'corrupted executable\n' > "$output"
else
    cp "$MOCK_ASSETS/$name" "$output" || exit 22
    [ -z "${MOCK_TRUNCATE:-}" ] || truncate -s "$MOCK_TRUNCATE" "$output"
fi
EOF
fake sha256sum <<'EOF'
#!/bin/sh
printf 'sha256sum %s\n' "$*" >> "$FIXTURES/hash.log"
[ "${MOCK_HASH_FAIL:-0}" != 1 ] || exit 1
exec "$REAL_SHA256SUM" "$@"
EOF
fake shasum <<'EOF'
#!/bin/sh
printf 'shasum %s\n' "$*" >> "$FIXTURES/hash.log"
[ "$*" = '-a 256' ] || exit 2
exec "$REAL_SHA256SUM"
EOF
fake openssl <<'EOF'
#!/bin/sh
printf 'openssl %s\n' "$*" >> "$FIXTURES/hash.log"
[ "$*" = 'dgst -sha256' ] || exit 2
sum=$("$REAL_SHA256SUM") || exit 1
printf 'SHA2-256(stdin)= %s\n' "${sum%% *}"
EOF
fake decoy <<'EOF'
#!/bin/sh
printf 'decoy\n' > "$FIXTURES/decoy-ran"
exit 91
EOF
mv "$WORK/fake/decoy/decoy" "$WORK/fake/decoy/native"

# The fake onebox: reports a version, records how it was started, may wait for signals.
cat > "$WORK/native" <<'EOF'
#!/bin/sh
if [ "${1:-}" = --version ]; then
    [ "${MOCK_VERSION_FAIL:-0}" != 1 ] || exit 3
    printf '%s\n' "$MOCK_NATIVE_VERSION"
    exit 0
fi
printf '%s\0' "$#" "$@" > "$FIXTURES/args"
printf '%s\n' "$0" > "$FIXTURES/self"
if { true <&3; } 2>/dev/null; then echo open; else echo closed; fi > "$FIXTURES/fd3"
printf 'executed\n' > "$FIXTURES/executed"
if [ "${MOCK_READ_STDIN:-0}" = 1 ]; then
    IFS= read -r line
    printf '%s\n' "$line" > "$FIXTURES/stdin"
fi
case "${MOCK_WAIT:-}" in
    signal)
        trap 'printf HUP > "$FIXTURES/signalled"; exit 42' HUP
        trap 'printf INT > "$FIXTURES/signalled"; exit 42' INT
        trap 'printf TERM > "$FIXTURES/signalled"; exit 42' TERM
        printf '%s' "$$" > "$FIXTURES/pid"
        printf ready > "$FIXTURES/ready"
        while :; do sleep 0.1; done ;;
    ignore)
        trap '' HUP INT TERM
        printf '%s' "$$" > "$FIXTURES/pid"
        printf ready > "$FIXTURES/ready"
        while :; do sleep 0.1; done ;;
esac
exit "${MOCK_NATIVE_RC:-0}"
EOF
chmod 755 "$WORK/native"
# Distinct bytes per architecture, so a wrong manifest line can never match.
declare -A HASH
for arch in amd64 arm64 386 armv7; do
    { cat "$WORK/native"; printf '# fixture for %s\n' "$arch"; } > "$WORK/assets/onebox-linux-$arch-musl"
    chmod 755 "$WORK/assets/onebox-linux-$arch-musl"
    sum=$("$REAL_SHA256SUM" < "$WORK/assets/onebox-linux-$arch-musl")
    HASH[$arch]=${sum%% *}
done
for arch in amd64 arm64 386 armv7; do
    printf '%s  onebox-linux-%s-musl\n' "${HASH[$arch]}" "$arch"
done > "$WORK/assets/SHA256SUMS"

# PATH depends on the shell under test: launch() and the signal cases add it.
BASE_ENV=(
    "HOME=$WORK/home" "TMPDIR=$WORK/tmp" "FIXTURES=$WORK"
    "MOCK_OS=Linux" "MOCK_ARCH=x86_64" "MOCK_ASSETS=$WORK/assets" "MOCK_NATIVE_VERSION=$VERSION"
    "REAL_SHA256SUM=$REAL_SHA256SUM"
)
printf '%s\0' "${BASE_ENV[@]}" > "$WORK/base.env"

# --- Helpers ---
SH=()
# launch [VAR=value...] -- [args...]: run the launcher with a clean environment
# (later assignments win, so PATH=... replaces DEFAULT_PATH).
# LAUNCH_CWD and LAUNCH_STDIN (a file, or "closed") adjust the invocation.
launch() {
    local -a vars=()
    while [[ $# -gt 0 && $1 != -- ]]; do vars+=("$1"); shift; done
    [[ $# -gt 0 ]] && shift
    set +e
    if [[ ${LAUNCH_STDIN:-} == closed ]]; then
        (cd "${LAUNCH_CWD:-$WORK}" && exec env -i "$DEFAULT_PATH" "${BASE_ENV[@]}" "${vars[@]}" "${SH[@]}" "$LAUNCHER" "$@") \
            > "$WORK/stdout" 2> "$WORK/stderr" <&-
    else
        (cd "${LAUNCH_CWD:-$WORK}" && exec env -i "$DEFAULT_PATH" "${BASE_ENV[@]}" "${vars[@]}" "${SH[@]}" "$LAUNCHER" "$@") \
            > "$WORK/stdout" 2> "$WORK/stderr" < "${LAUNCH_STDIN:-/dev/null}"
    fi
    STATUS=$?
    set -e
}
start() {
    CASE=$1
    rm -f "$WORK"/{args,self,fd3,executed,stdin,fetch.log,curl-args.log,hash.log,decoy-ran,stdout,stderr}
    rm -rf "${WORK:?}/tmp"
    mkdir "$WORK/tmp"
}
expect_status() { [[ $STATUS == "$1" ]] || die "exit status $STATUS, expected $1"; }
expect_error() {
    [[ $STATUS == 1 ]] || die "exit status $STATUS, expected 1"
    grep -q -- "$1" "$WORK/stderr" || die "stderr does not match: $1"
}
expect_ran() { [[ -f $WORK/executed ]] || die 'the program did not run'; }
expect_not_ran() { [[ ! -f $WORK/executed ]] || die 'the program ran although it must not'; }
expect_fetches() {
    local count=0
    [[ ! -f $WORK/fetch.log ]] || count=$(wc -l < "$WORK/fetch.log")
    [[ $count == "$1" ]] || die "$count downloads, expected $1"
}
expect_fetched() { grep -qxF -- "$1" "$WORK/fetch.log" || die "not downloaded: $1"; }
expect_clean_tmp() { [[ -z $(find "$WORK/tmp" -mindepth 1 -print -quit) ]] || die 'temporary files were left behind'; }
expect_quiet() { [[ ! -s $WORK/stderr ]] || die 'unexpected stderr output'; }
expect_args() {
    local -a got=()
    mapfile -d '' got < "$WORK/args"
    [[ ${got[0]} == "$#" ]] || die "the program got ${got[0]} arguments, expected $#"
    local i=1 arg
    for arg; do
        [[ ${got[i]} == "$arg" ]] || die "argument $i is '${got[i]}', expected '$arg'"
        i=$((i + 1))
    done
}
# A successful verified download that ran the program with the given status.
expect_online_run() {
    expect_status "$1"
    expect_ran
    expect_fetches 2
    expect_clean_tmp
}
sums_file() { local file=$WORK/sums-$1; cat > "$file"; printf '%s' "$file"; }
pad_to() {
    local size
    size=$(wc -c < "$1")
    printf '%*s\n' $(($2 - size - 1)) '' | tr ' ' '#' >> "$1"
    [[ $(wc -c < "$1") == "$2" ]] || die "could not pad $1"
}
GOOD_SUMS=$(cat "$WORK/assets/SHA256SUMS")
AMD64=onebox-linux-amd64-musl
OTHERS=$(grep -v " $AMD64\$" "$WORK/assets/SHA256SUMS")

run_cases() {
    # --- Offline mode: no network, no arch check, no temp dir, no PATH search ---
    start offline-absolute
    launch ONEBOX_NATIVE_BIN="$WORK/native" MOCK_NATIVE_RC=37 MOCK_ARCH=armv6l PATH="$(fake_path uname)" -- \
        'hello world' '' '--flag=literal$()' '*' $'two\nlines'
    expect_status 37
    expect_args 'hello world' '' '--flag=literal$()' '*' $'two\nlines'
    expect_fetches 0
    expect_clean_tmp
    [[ $(cat "$WORK/self") == "$WORK/native" ]] || die 'offline mode must exec the given file'

    start offline-missing
    launch ONEBOX_NATIVE_BIN="$WORK/missing" --
    expect_error 'ONEBOX_NATIVE_BIN'
    expect_fetches 0

    start offline-directory
    launch ONEBOX_NATIVE_BIN="$WORK/cwd" --
    expect_error 'ONEBOX_NATIVE_BIN'

    start offline-not-executable
    cp "$WORK/native" "$WORK/cwd/plain"
    chmod 644 "$WORK/cwd/plain"
    launch ONEBOX_NATIVE_BIN="$WORK/cwd/plain" --
    expect_error 'ONEBOX_NATIVE_BIN'
    expect_not_ran
    expect_fetches 0

    start offline-bare-name-uses-cwd
    cp "$WORK/native" "$WORK/cwd/native"
    LAUNCH_CWD=$WORK/cwd launch ONEBOX_NATIVE_BIN=native MOCK_NATIVE_RC=38 PATH="$(fake_path decoy uname)" --
    expect_status 38
    [[ ! -e $WORK/decoy-ran ]] || die 'a bare name must not be looked up in PATH'
    # bash hands the interpreter an absolute path, dash keeps ./native.
    self=$(cat "$WORK/self")
    [[ $self == ./native || $self == "$WORK/cwd/native" ]] || die "a bare name must run ./NAME, ran $self"

    start offline-bare-name-never-searches-path
    LAUNCH_CWD=$WORK/cwd/empty launch ONEBOX_NATIVE_BIN=native PATH="$(fake_path decoy uname)" --
    expect_error 'ONEBOX_NATIVE_BIN'
    [[ ! -e $WORK/decoy-ran ]] || die 'a bare name must not be looked up in PATH'

    start offline-relative-path
    cp "$WORK/native" "$WORK/cwd/sub/native"
    LAUNCH_CWD=$WORK/cwd launch ONEBOX_NATIVE_BIN=sub/native MOCK_NATIVE_RC=39 --
    expect_status 39
    expect_ran

    start offline-option-like-name
    cp "$WORK/native" "$WORK/cwd/-native"
    LAUNCH_CWD=$WORK/cwd launch ONEBOX_NATIVE_BIN=-native MOCK_NATIVE_RC=40 -- --help
    expect_status 40
    expect_args --help

    start offline-requires-linux
    launch ONEBOX_NATIVE_BIN="$WORK/native" MOCK_OS=Darwin --
    expect_error '仅支持 Linux'
    expect_not_ran

    start empty-native-bin-means-online
    launch ONEBOX_NATIVE_BIN= MOCK_NATIVE_RC=0 --
    expect_online_run 0

    # --- Online mode: architectures, URLs, proxy prefix ---
    local pair machine asset
    for pair in x86_64:amd64 amd64:amd64 aarch64:arm64 arm64:arm64 i586:386 i686:386 armv7l:armv7 armv7:armv7 armv8l:armv7; do
        machine=${pair%%:*}
        asset=onebox-linux-${pair#*:}-musl
        start "arch-$machine"
        launch MOCK_ARCH="$machine" MOCK_NATIVE_RC=19 GH_PROXY=https://mirror.example/ -- version
        expect_online_run 19
        expect_fetched "https://mirror.example/$BASE_URL/SHA256SUMS"
        expect_fetched "https://mirror.example/$BASE_URL/$asset"
        expect_args version
    done
    for machine in armv6l i386 mips riscv64 ppc64le s390x; do
        start "unsupported-arch-$machine"
        launch MOCK_ARCH="$machine" --
        expect_error 'cargo build --release'
        grep -qF -- "$machine" "$WORK/stderr" || die 'the message must name the machine'
        expect_fetches 0
    done
    start not-linux
    launch MOCK_OS=Darwin --
    expect_error '仅支持 Linux'
    expect_fetches 0

    start direct-download
    launch MOCK_NATIVE_RC=0 -- 'hello world' '' '--flag=literal$()' $'two\nlines'
    expect_online_run 0
    expect_quiet
    [[ $(cat "$WORK/fetch.log") == "$BASE_URL/SHA256SUMS"$'\n'"$BASE_URL/$AMD64" ]] || die 'unexpected download order or URLs'
    expect_args 'hello world' '' '--flag=literal$()' $'two\nlines'
    [[ $(cat "$WORK/fd3") == closed ]] || die 'fd 3 must be closed in the program'
    [[ $(cat "$WORK/self") == "$WORK"/tmp/*/"$AMD64" ]] || die 'the program must run from the temporary download'
    local sums_call binary_call
    sums_call=$(sed -n 1p "$WORK/curl-args.log")
    binary_call=$(sed -n 2p "$WORK/curl-args.log")
    local flag
    for flag in '--proto =https' '--proto-redir =https' '--tlsv1.2' '-fLsS' '--retry'; do
        [[ " $sums_call " == *" $flag "* && " $binary_call " == *" $flag "* ]] || die "curl lacks $flag"
    done
    [[ " $sums_call " == *' --max-filesize 65536 '* ]] || die 'SHA256SUMS download must be capped at 64 KiB'
    [[ " $binary_call " == *' --max-filesize 134217728 '* ]] || die 'binary download must be capped at 128 MiB'

    start proxy-without-trailing-slash
    launch GH_PROXY=https://mirror.example --
    expect_online_run 0
    expect_fetched "https://mirror.example/$BASE_URL/$AMD64"

    start proxy-with-path
    launch GH_PROXY=https://mirror.example/gh/ --
    expect_online_run 0
    expect_fetched "https://mirror.example/gh/$BASE_URL/SHA256SUMS"

    local proxy
    for proxy in http://mirror.example mirror.example https:// 'https://mirror.example/ x' \
        $'https://mirror.example/\tx' $'https://mirror.example/\nx' $'https://mirror.example/\001'; do
        start "invalid-proxy-$(printf '%q' "$proxy")"
        launch GH_PROXY="$proxy" --
        expect_error 'GH_PROXY'
        expect_fetches 0
    done

    # --- Tools ---
    start missing-curl
    launch PATH="$(fake_path uname sha256sum)" --
    expect_error 'curl'
    expect_not_ran

    start prefers-sha256sum
    launch PATH="$(fake_path uname curl sha256sum shasum openssl)" --
    expect_online_run 0
    [[ $(cat "$WORK/hash.log") == 'sha256sum ' ]] || die 'sha256sum must be preferred and read stdin'

    local hasher
    for hasher in shasum openssl; do
        start "hasher-$hasher"
        launch PATH="$(fake_path uname curl "$hasher")" --
        expect_online_run 0
        grep -q "^$hasher " "$WORK/hash.log" || die "$hasher was not used"

        start "hasher-$hasher-mismatch"
        launch PATH="$(fake_path uname curl "$hasher")" MOCK_CORRUPT=1 --
        expect_error 'SHA-256'
        expect_not_ran
        expect_clean_tmp
    done

    start no-hasher
    launch PATH="$(fake_path uname curl)" --
    expect_error 'sha256sum、shasum 或 openssl'
    expect_fetches 0

    start hasher-fails
    launch MOCK_HASH_FAIL=1 --
    expect_error '无法计算 SHA-256'
    expect_not_ran
    expect_clean_tmp

    start unusable-tmpdir
    launch TMPDIR="$WORK/does-not-exist" --
    expect_error 'TMPDIR'
    expect_fetches 0

    # --- Manifest: a unique, well-formed line for this asset, or nothing runs ---
    local -A manifest=(
        [duplicate]="$GOOD_SUMS"$'\n'"${HASH[amd64]}  $AMD64"
        [conflicting-duplicate]="$GOOD_SUMS"$'\n'"${HASH[arm64]}  $AMD64"
        [missing]="$OTHERS"
        [binary-mode]="$OTHERS"$'\n'"${HASH[amd64]} *$AMD64"
        [short-hash]="${HASH[amd64]:0:63}  $AMD64"
        [long-hash]="${HASH[amd64]}0  $AMD64"
        [non-hex]="g${HASH[amd64]:1}  $AMD64"
        [extra-field]="${HASH[amd64]}  $AMD64  extra"
        [relative-name]="${HASH[amd64]}  ./$AMD64"
        [malformed-duplicate]="$GOOD_SUMS"$'\n'"${HASH[amd64]:0:10}  $AMD64"
        [crlf]="${HASH[amd64]}  $AMD64"$'\r'
        [tab-separator]="${HASH[amd64]}"$'\t'"$AMD64"
        [vertical-tab]="${HASH[amd64]}  $AMD64"$'\v'
        [form-feed]="${HASH[amd64]}  $AMD64"$'\f'
        [non-ascii]="${HASH[amd64]}  $AMD64"$'\xc2\xa0'
        [empty]=''
    )
    local name file
    for name in "${!manifest[@]}"; do
        start "manifest-$name"
        if [[ $name == empty ]]; then file=$(sums_file "$name" < /dev/null); else file=$(sums_file "$name" <<< "${manifest[$name]}"); fi
        launch MOCK_SUMS="$file" --
        expect_error "SHA256SUMS.*$AMD64"
        expect_not_ran
        expect_fetches 1
        expect_clean_tmp
    done

    start manifest-uppercase-hash
    file=$(sums_file upper <<< "${HASH[amd64]^^}  $AMD64")
    launch MOCK_SUMS="$file" --
    expect_online_run 0

    start manifest-at-size-limit
    file=$(sums_file at-limit <<< "$GOOD_SUMS")
    pad_to "$file" 65536
    launch MOCK_SUMS="$file" --
    expect_online_run 0

    start manifest-oversized
    file=$(sums_file oversized <<< "$GOOD_SUMS")
    pad_to "$file" 65537
    launch MOCK_SUMS="$file" --
    expect_error '异常大'
    expect_not_ran
    expect_fetches 1

    start manifest-download-fails
    launch MOCK_FETCH_FAIL=SHA256SUMS --
    expect_error "v$VERSION.*SHA256SUMS"
    expect_not_ran
    expect_fetches 1
    expect_clean_tmp

    # --- Binary: size, checksum and version gates ---
    start binary-download-fails
    launch MOCK_FETCH_FAIL="$AMD64" --
    expect_error "无法下载 $AMD64"
    expect_not_ran
    expect_clean_tmp

    start checksum-mismatch
    launch MOCK_CORRUPT=1 --
    expect_error 'SHA-256 校验失败'
    expect_not_ran
    expect_clean_tmp

    start empty-binary
    launch MOCK_TRUNCATE=0 --
    expect_error '为空或异常大'
    expect_not_ran

    start oversized-binary
    launch MOCK_TRUNCATE=134217729 --
    expect_error '为空或异常大'
    expect_not_ran
    expect_clean_tmp

    local reported
    for reported in 2.0.1 "$VERSION-rc.1" "v$VERSION" "$VERSION extra"; do
        start "version-mismatch-$reported"
        launch MOCK_NATIVE_VERSION="$reported" -- install
        expect_error '版本.*不匹配'
        expect_not_ran
        expect_clean_tmp
    done

    start version-command-fails
    launch MOCK_VERSION_FAIL=1 --
    expect_error '无法运行'
    expect_not_ran
    expect_clean_tmp

    # --- The child keeps the caller's stdin ---
    start stdin-preserved
    printf 'stdin preserved\n' > "$WORK/input"
    LAUNCH_STDIN=$WORK/input launch MOCK_READ_STDIN=1 --
    expect_online_run 0
    [[ $(cat "$WORK/stdin") == 'stdin preserved' ]] || die 'stdin did not reach the program'

    start stdin-closed
    LAUNCH_STDIN=closed launch MOCK_NATIVE_RC=5 --
    expect_online_run 5
}

# --- Shells under test ---
# busybox also supplies every tool (an Alpine userland: its awk, for example,
# splits fields on \r), other shells use the host tools. An explicitly listed
# shell that cannot be tested is an error; a default one is skipped with a note.
CASE=shell-selection
declare -a SHELL_SPECS=() SHELL_SYS=()
declare -A SEEN=()
read -ra wanted <<< "${ONEBOX_BOOTSTRAP_TEST_SHELLS:-sh bash dash busybox}"
unusable() {
    [[ -z ${ONEBOX_BOOTSTRAP_TEST_SHELLS:-} ]] || die "$*"
    printf 'bootstrap: skipping %s\n' "$*" >&2
}
for name in "${wanted[@]}"; do
    path=$(command -v "$name") || { unusable "$name: not found"; continue; }
    real=$(readlink -f "$path")
    [[ -z ${SEEN[$real]:-} ]] || continue
    SEEN[$real]=1
    if [[ $(basename "$real") == busybox ]]; then
        # Call the binary itself: as /bin/sh (Alpine) it would run "sh" as a script.
        "$real" sh -c : 2>/dev/null || { unusable "$real: no sh applet"; continue; }
        # A standalone busybox shell runs its own applets before PATH, so the
        # fake uname, curl and hashers could not be injected.
        if env -i PATH="$WORK/cwd/empty" "$real" sh -c 'command -v uname' >/dev/null 2>&1; then
            unusable "$real: its shell prefers applets to PATH (standalone build)"
            continue
        fi
        applets=$("$real" --list) || die "$real --list failed"
        sys=$WORK/sys-busybox-${#SEEN[@]}
        mkdir "$sys"
        for tool in "${TOOLS[@]}"; do
            grep -qx -- "$tool" <<< "$applets" || { unusable "$real: no $tool applet"; continue 2; }
            ln -s "$real" "$sys/$tool"
        done
        SHELL_SPECS+=("$real sh")
        SHELL_SYS+=("$sys")
    else
        SHELL_SPECS+=("$path")
        SHELL_SYS+=("$WORK/sys")
    fi
done
[[ ${#SHELL_SPECS[@]} -gt 0 ]] || die 'no shell to test with'

SIGNAL_ARGS=()
for i in "${!SHELL_SPECS[@]}"; do
    read -ra SH <<< "${SHELL_SPECS[i]}"
    SHELL_NAME=${SHELL_SPECS[i]}
    SYS=${SHELL_SYS[i]}
    DEFAULT_PATH="PATH=$(fake_path uname curl sha256sum)"
    SIGNAL_ARGS+=("${DEFAULT_PATH#PATH=}" "${SHELL_SPECS[i]}")
    run_cases
    tools=host
    [[ $SYS == "$WORK/sys" ]] || tools=busybox
    printf 'bootstrap [%s, %s tools]: offline, architectures, proxy, tools, manifest, size, version and stdin cases passed\n' \
        "$SHELL_NAME" "$tools"
done

# --- Signals: forwarding (INT becomes TERM), exit codes, watchdog, cleanup ---
SHELL_NAME=all
CASE=signals
python3 - "$LAUNCHER" "$WORK" "${ONEBOX_BOOTSTRAP_QUICK:-0}" "${SIGNAL_ARGS[@]}" <<'PY'
import itertools, os, pathlib, signal, subprocess, sys, threading, time

launcher, work, quick = sys.argv[1], pathlib.Path(sys.argv[2]), sys.argv[3] == '1'
# (PATH for this shell, shell command) pairs.
shells = [(path, spec.split(' ')) for path, spec in zip(sys.argv[4::2], sys.argv[5::2])]
base = dict(item.split('=', 1) for item in (work / 'base.env').read_text().split('\0') if item)
serial = itertools.count()


class Failure(Exception):
    pass


def check(ok, message):
    if not ok:
        raise Failure(message)


def drain(stream, sink):
    sink.append(stream.read())


def run(target, name, wait, sig, code, signalled, timeout=10.0, min_elapsed=0.0):
    """Start the launcher, signal it once its child is ready, check the outcome."""
    path, shell = target
    label = f'[{" ".join(shell)}] {name}'
    fixtures = work / 'signal' / str(next(serial))
    (fixtures / 'tmp').mkdir(parents=True)
    env = dict(base, PATH=path, FIXTURES=str(fixtures), TMPDIR=str(fixtures / 'tmp'), MOCK_WAIT=wait)
    ready = fixtures / ('fetch-ready' if wait == 'fetch' else 'ready')
    proc = subprocess.Popen([*shell, launcher], env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, start_new_session=True)
    out, err = [], []
    readers = [threading.Thread(target=drain, args=(proc.stdout, out)),
               threading.Thread(target=drain, args=(proc.stderr, err))]
    for reader in readers:
        reader.start()
    try:
        deadline = time.monotonic() + 10
        while not ready.exists():
            check(proc.poll() is None, f'{label}: launcher exited early ({proc.returncode})')
            check(time.monotonic() < deadline, f'{label}: child never became ready')
            time.sleep(0.02)
        sent = time.monotonic()
        proc.send_signal(sig)
        try:
            status = proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            raise Failure(f'{label}: launcher did not exit within {timeout:.0f} s')
        elapsed = time.monotonic() - sent
        check(status == code, f'{label}: exit status {status}, expected {code}')
        check(elapsed >= min_elapsed, f'{label}: exited after {elapsed:.1f} s, expected >= {min_elapsed} s')
        for reader in readers:
            reader.join(timeout=3)
            check(not reader.is_alive(), f'{label}: a leftover process still holds stdout/stderr')
        if signalled:
            marker = fixtures / ('fetch-signalled' if wait == 'fetch' else 'signalled')
            got = marker.read_text() if marker.exists() else 'nothing'
            check(got == signalled, f'{label}: child received {got}, expected {signalled}')
        if wait == 'ignore':
            pid = int((fixtures / 'pid').read_text())
            try:
                os.kill(pid, 0)
                alive = True
            except ProcessLookupError:
                alive = False
            check(not alive, f'{label}: the unresponsive child was not killed')
        check(not list((fixtures / 'tmp').iterdir()), f'{label}: temporary download not removed')
        print(f'bootstrap {label}: ok ({elapsed:.1f} s)', flush=True)
    except Failure:
        sys.stderr.write(f'--- stderr ---\n{b"".join(err).decode(errors="replace")}\n')
        raise
    finally:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        proc.wait()


CASES = [
    ('term-while-running', 'signal', signal.SIGTERM, 143, 'TERM'),
    ('int-while-running-becomes-term', 'signal', signal.SIGINT, 130, 'TERM'),
    ('hup-while-running', 'signal', signal.SIGHUP, 129, 'HUP'),
    ('term-while-downloading', 'fetch', signal.SIGTERM, 143, 'TERM'),
    ('int-while-downloading-becomes-term', 'fetch', signal.SIGINT, 130, 'TERM'),
    ('hup-while-downloading', 'fetch', signal.SIGHUP, 129, 'HUP'),
]
failures = []
for target in shells:
    for case in CASES:
        try:
            run(target, *case)
        except Failure as error:
            failures.append(str(error))

if not quick:
    # The watchdog kills a child that ignores the forwarded signal after 30 s;
    # run every shell at once so the suite pays the wait only once.
    def slow(target):
        try:
            run(target, 'watchdog-kills-unresponsive-child', 'ignore', signal.SIGTERM, 143, None,
                timeout=45, min_elapsed=29)
        except Failure as error:
            failures.append(str(error))
    threads = [threading.Thread(target=slow, args=(target,)) for target in shells]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

for failure in failures:
    print(f'FAIL {failure}', file=sys.stderr)
sys.exit(1 if failures else 0)
PY
printf 'bootstrap: all launcher cases passed for %s shell(s)\n' "${#SHELL_SPECS[@]}"
