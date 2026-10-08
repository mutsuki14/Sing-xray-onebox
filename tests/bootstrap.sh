#!/usr/bin/env bash
# The launcher is tested only with temporary fixtures; no real download/service.
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
BOOTSTRAP=${ONEBOX_BOOTSTRAP_TEST_PATH:-$ROOT/scripts/bootstrap.sh}
# 1.x validates this marker before it accepts an update launcher.
head -n 5 "$BOOTSTRAP" | grep -q 'Sing-Xray-Onebox'
grep -qx 'readonly SCRIPT_VERSION="2.0.1"' "$BOOTSTRAP"
WORK=$(mktemp -d)
trap 'rm -rf -- "$WORK"' EXIT
mkdir -p "$WORK/bin" "$WORK/assets" "$WORK/tmp"
export FIXTURES="$WORK" TMPDIR="$WORK/tmp"
export MOCK_ARCH=x86_64 MOCK_OS=Linux
export MOCK_NATIVE_RC=0 MOCK_NATIVE_ARGS="$WORK/args" MOCK_NATIVE_EXECUTED="$WORK/executed"
export MOCK_FETCH_LOG="$WORK/fetch.log"
export PATH="$WORK/bin:$PATH"

cat > "$WORK/bin/uname" <<'EOF'
#!/bin/sh
case "$1" in -s) printf '%s\n' "$MOCK_OS" ;; -m) printf '%s\n' "$MOCK_ARCH" ;; *) exit 1 ;; esac
EOF
cat > "$WORK/native" <<'EOF'
#!/bin/sh
if [ "${1:-}" = --version ]; then
    printf '%s\n' "${MOCK_NATIVE_VERSION:-2.0.1}"
    exit 0
fi
printf '%s\0' "$@" > "$MOCK_NATIVE_ARGS"
printf 'executed\n' > "$MOCK_NATIVE_EXECUTED"
if [ "${MOCK_READ_STDIN:-0}" = 1 ]; then
    IFS= read -r line
    printf '%s\n' "$line" > "$FIXTURES/stdin"
fi
if [ "${MOCK_WAIT_SIGNAL:-0}" = 1 ]; then
    trap 'printf terminated > "$FIXTURES/terminated"; exit 42' TERM
    printf ready > "$FIXTURES/ready"
    while :; do sleep 0.1; done
fi
exit "$MOCK_NATIVE_RC"
EOF
cat > "$WORK/bin/curl" <<'EOF'
#!/bin/sh
output='' url=''
while [ "$#" -gt 0 ]; do
    case "$1" in
        -o|--output) shift; output=$1 ;;
        https://*) url=$1 ;;
    esac
    shift
done
[ -n "$output" ] && [ -n "$url" ] || exit 2
if [ "${MOCK_WAIT_FETCH:-0}" = 1 ]; then
    trap 'printf terminated > "$FIXTURES/fetch-terminated"; exit 42' TERM
    printf ready > "$FIXTURES/fetch-ready"
    while :; do sleep 0.1; done
fi
printf '%s\n' "$url" >> "$MOCK_FETCH_LOG"
name=${url##*/}
if [ "${MOCK_CORRUPT:-0}" = 1 ] && [ "$name" != SHA256SUMS ]; then
    printf 'corrupted executable\n' > "$output"
else
    cp "$FIXTURES/assets/$name" "$output"
fi
EOF
chmod +x "$WORK/bin/uname" "$WORK/bin/curl" "$WORK/native"
for arch in amd64 arm64 386 armv7; do
    cp "$WORK/native" "$WORK/assets/onebox-linux-$arch-musl"
done
(cd "$WORK/assets" && sha256sum onebox-linux-*-musl > SHA256SUMS)

run_status() {
    set +e
    "$@" > "$WORK/stdout" 2> "$WORK/stderr"
    STATUS=$?
    set -e
}
clean_tmp() { [[ -z $(find "$WORK/tmp" -mindepth 1 -print -quit) ]]; }

sh -n "$BOOTSTRAP"
bash -n "$BOOTSTRAP"
grep -qx 'readonly SCRIPT_VERSION="2.0.1"' "$BOOTSTRAP"

# Explicit offline execution preserves arguments and status without downloading.
run_status env ONEBOX_NATIVE_BIN="$WORK/native" MOCK_NATIVE_RC=37 sh "$BOOTSTRAP" 'hello world' '' '--flag=literal$()'
[[ $STATUS == 37 && ! -e "$WORK/fetch.log" ]]
python3 - "$WORK/args" <<'PY'
import pathlib, sys
assert pathlib.Path(sys.argv[1]).read_bytes().split(b'\0') == [b'hello world', b'', b'--flag=literal$()', b'']
PY
clean_tmp
run_status env ONEBOX_NATIVE_BIN="$WORK/missing" sh "$BOOTSTRAP"
[[ $STATUS != 0 ]]
cat > "$WORK/bin/native" <<'EOF'
#!/bin/sh
exit 91
EOF
chmod +x "$WORK/bin/native"
cd "$WORK"
run_status env ONEBOX_NATIVE_BIN=native MOCK_NATIVE_RC=38 sh "$BOOTSTRAP"
[[ $STATUS == 38 ]]
cd "$ROOT"

# Each advertised architecture selects its exact fixed-release asset.
for pair in x86_64:amd64 aarch64:arm64 i686:386 armv7l:armv7; do
    arch=${pair%:*}; asset=${pair#*:}
    rm -f "$WORK/fetch.log" "$WORK/executed"
    run_status env -u ONEBOX_NATIVE_BIN MOCK_ARCH="$arch" MOCK_NATIVE_RC=19 GH_PROXY=https://mirror.example/ sh "$BOOTSTRAP" version
    [[ $STATUS == 19 && -f "$WORK/executed" ]]
    grep -qx "https://mirror.example/https://github.com/mutsuki14/Sing-xray-onebox/releases/download/v2.0.1/onebox-linux-$asset-musl" "$WORK/fetch.log"
    [[ $(wc -l < "$WORK/fetch.log") == 2 ]]
    clean_tmp
done

# Invalid bytes and ambiguous manifests are rejected before execution.
rm -f "$WORK/executed"
run_status env -u ONEBOX_NATIVE_BIN MOCK_CORRUPT=1 sh "$BOOTSTRAP"
[[ $STATUS != 0 && ! -f "$WORK/executed" ]]
grep -q 'SHA-256' "$WORK/stderr"
clean_tmp
cp "$WORK/assets/SHA256SUMS" "$WORK/original-sums"
cat "$WORK/original-sums" >> "$WORK/assets/SHA256SUMS"
run_status env -u ONEBOX_NATIVE_BIN sh "$BOOTSTRAP"
[[ $STATUS != 0 && ! -f "$WORK/executed" ]]
clean_tmp
mv "$WORK/original-sums" "$WORK/assets/SHA256SUMS"
run_status env -u ONEBOX_NATIVE_BIN MOCK_NATIVE_VERSION=1.7.0 sh "$BOOTSTRAP" install
[[ $STATUS != 0 && ! -f "$WORK/executed" ]]
grep -q '版本.*不匹配' "$WORK/stderr"
clean_tmp

run_status env -u ONEBOX_NATIVE_BIN MOCK_ARCH=armv6l sh "$BOOTSTRAP"
[[ $STATUS != 0 ]]
grep -q 'cargo build --release' "$WORK/stderr"
run_status env -u ONEBOX_NATIVE_BIN MOCK_OS=Darwin sh "$BOOTSTRAP"
[[ $STATUS != 0 ]]
run_status env -u ONEBOX_NATIVE_BIN GH_PROXY=http://mirror.example sh "$BOOTSTRAP"
[[ $STATUS != 0 ]]

# The online child keeps stdin, and the launcher waits before removing its file.
printf 'stdin preserved\n' | env -u ONEBOX_NATIVE_BIN MOCK_READ_STDIN=1 sh "$BOOTSTRAP"
grep -qx 'stdin preserved' "$WORK/stdin"
clean_tmp
env -u ONEBOX_NATIVE_BIN MOCK_WAIT_SIGNAL=1 sh "$BOOTSTRAP" > "$WORK/signal-out" 2> "$WORK/signal-err" &
launcher=$!
for _ in {1..100}; do [[ ! -e "$WORK/ready" ]] || break; sleep 0.02; done
[[ -e "$WORK/ready" ]]
kill -TERM "$launcher"
set +e
wait "$launcher"
STATUS=$?
set -e
[[ $STATUS == 143 && -f "$WORK/terminated" ]]
clean_tmp
rm -f "$WORK/ready" "$WORK/terminated"
python3 - "$BOOTSTRAP" "$WORK" <<'PY'
import os, pathlib, signal, subprocess, sys, time
launcher, root = sys.argv[1], pathlib.Path(sys.argv[2])
for setting, ready, stopped, sig, code in [
    ('MOCK_WAIT_SIGNAL', 'ready', 'terminated', signal.SIGINT, 130),
    ('MOCK_WAIT_FETCH', 'fetch-ready', 'fetch-terminated', signal.SIGTERM, 143),
    ('MOCK_WAIT_FETCH', 'fetch-ready', 'fetch-terminated', signal.SIGINT, 130),
]:
    env = dict(os.environ, **{setting: '1'})
    env.pop('ONEBOX_NATIVE_BIN', None)
    (root / ready).unlink(missing_ok=True)
    (root / stopped).unlink(missing_ok=True)
    with (root / 'signal-out').open('w') as out, (root / 'signal-err').open('w') as err:
        proc = subprocess.Popen(['sh', launcher], env=env, stdout=out, stderr=err,
                                start_new_session=True)
        try:
            deadline = time.monotonic() + 5
            while not (root / ready).exists() and time.monotonic() < deadline:
                assert proc.poll() is None, 'launcher exited before child startup'
                time.sleep(.02)
            assert (root / ready).exists(), 'child did not start'
            proc.send_signal(sig)
            assert proc.wait(timeout=5) == code, 'signal status was not preserved'
            assert (root / stopped).exists(), 'signal did not cancel the child'
            assert not list((root / 'tmp').iterdir()), 'temporary download not removed'
        finally:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            proc.wait()
PY
clean_tmp
printf 'bootstrap: syntax, offline/online arguments, four targets, checksums, stdin, signals and cleanup passed\n'
