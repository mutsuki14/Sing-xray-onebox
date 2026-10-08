#!/bin/sh
# Regenerate the v2 reference outputs of every golden case.
#
# Usage: tests/golden/generate.sh /path/to/onebox-v2 [case ...]
#
# Each case under tests/golden/cases/<name>/ is deployed to a fixed root
# /tmp/onebox-golden/<name> (state.json, subscription/settings.json and the
# certificate pair named by the optional `cert` file), so the certificate
# paths inside the server configs are the same on every machine. The v2
# binary then renders everything with ONEBOX_DIR pointing at that root and
# the results are written to cases/<name>/expected/:
#
#   render-server-<core>.json        `onebox render server <core>`
#   render-inbound-<p>.json          `onebox render inbound <p>`
#   render-outbound-<p>-<core>.json  `onebox render outbound <p> <core>`
#   render-probe.json                `onebox render probe`
#   client-<format>.out              `onebox client <format>`
#
# Files hold the exact stdout of v2 (its `println!` adds one "\n" after the
# rendered text). A command that fails writes `<name>.err` (v2 stderr)
# instead; v3 must then fail too. Requires jq.
set -eu

V2=${1:?usage: generate.sh /path/to/onebox-v2 [case ...]}
shift
HERE=$(cd "$(dirname "$0")" && pwd)
BASE=/tmp/onebox-golden
CORES="singbox xray"
FORMATS="links sub mihomo provider singbox singbox-notun xray"

run_v2() { # root output-stem args...
	root=$1
	stem=$2
	shift 2
	if env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin HOME="$root" \
		ONEBOX_DIR="$root" ONEBOX_RUN_DIR="$root/run" ONEBOX_LOG_DIR="$root/log" \
		ONEBOX_BIN_DIR="$root/bin" ONEBOX_SITE_ROOT="$root/www" \
		"$V2" "$@" >"$stem.out.tmp" 2>"$stem.err.tmp"; then
		mv "$stem.out.tmp" "$stem.$EXT"
		rm -f "$stem.err.tmp"
	else
		mv "$stem.err.tmp" "$stem.err"
		rm -f "$stem.out.tmp"
	fi
}

deploy() { # case-dir root
	rm -rf "$2"
	mkdir -p "$2/subscription"
	cp "$1/state.json" "$2/state.json"
	if [ -f "$1/settings.json" ]; then
		cp "$1/settings.json" "$2/subscription/settings.json"
	fi
	if [ -f "$1/cert" ]; then
		mkdir -p "$2/tls"
		pair=$(cat "$1/cert")
		cp "$HERE/certs/$pair/cert.pem" "$HERE/certs/$pair/key.pem" "$2/tls/"
	fi
}

generate() { # case-name
	dir="$HERE/cases/$1"
	root="$BASE/$1"
	out="$dir/expected"
	deploy "$dir" "$root"
	rm -rf "$out"
	mkdir -p "$out"
	EXT=json
	for core in $CORES; do
		run_v2 "$root" "$out/render-server-$core" render server "$core"
	done
	run_v2 "$root" "$out/render-probe" render probe
	for p in $(jq -r '.values.PROTOCOLS' "$dir/state.json"); do
		run_v2 "$root" "$out/render-inbound-$p" render inbound "$p"
		for core in $CORES; do
			run_v2 "$root" "$out/render-outbound-$p-$core" render outbound "$p" "$core"
		done
	done
	EXT=out
	for format in $FORMATS; do
		run_v2 "$root" "$out/client-$format" client "$format"
	done
	rm -rf "$root"
	echo "generated $1"
}

if [ "$#" -eq 0 ]; then
	for dir in "$HERE"/cases/*/; do
		name=${dir%/}
		generate "${name##*/}"
	done
else
	for name in "$@"; do
		generate "$name"
	done
fi
