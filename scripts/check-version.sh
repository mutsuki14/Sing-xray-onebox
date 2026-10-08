#!/bin/sh
# Single version source check (CI and release): Cargo.toml [package] version must
# equal the onebox.sh SCRIPT_VERSION pin and the onebox entry of Cargo.lock.
#
#   scripts/check-version.sh          print the version when everything agrees
#   scripts/check-version.sh TAG      additionally require TAG (vX.Y.Z or refs/tags/vX.Y.Z) == v<version>
set -eu
root=$(cd "$(dirname "$0")/.." && pwd)

die() { printf 'check-version: %s\n' "$*" >&2; exit 1; }
semver() { printf '%s\n' "$1" | grep -Eqx '(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)'; }

case "${1:-}" in -h|--help) sed -n '2,6s/^# \{0,1\}//p' "$0"; exit 0 ;; esac
[ "$#" -le 1 ] || die 'usage: scripts/check-version.sh [TAG]'

version=$(awk '
    /^[ \t]*\[/ { in_package = ($0 ~ /^[ \t]*\[package\][ \t]*(#.*)?$/); next }
    in_package && /^[ \t]*version[ \t]*=/ {
        value = $0
        sub(/^[ \t]*version[ \t]*=[ \t]*"/, "", value)
        sub(/".*$/, "", value)
        print value
        exit
    }
' "$root/Cargo.toml")
semver "$version" || die "Cargo.toml has no plain X.Y.Z [package] version (found '$version')"

pins=$(grep -c '^readonly SCRIPT_VERSION=' "$root/onebox.sh" || :)
[ "$pins" = 1 ] || die "onebox.sh must set SCRIPT_VERSION exactly once (found $pins)"
grep -qx "readonly SCRIPT_VERSION=\"$version\"" "$root/onebox.sh" ||
    die "onebox.sh pins $(sed -n 's/^readonly SCRIPT_VERSION=//p' "$root/onebox.sh"), Cargo.toml says \"$version\""

locked=$(awk '
    /^\[\[package\]\]/ { name = ""; next }
    /^name = / { name = $3; gsub(/"/, "", name); next }
    /^version = / && name == "onebox" { value = $3; gsub(/"/, "", value); print value; exit }
' "$root/Cargo.lock")
[ "$locked" = "$version" ] || die "Cargo.lock records onebox '$locked', Cargo.toml says '$version' (run cargo update --workspace)"

if [ "$#" = 1 ]; then
    tag=${1#refs/tags/}
    [ "$tag" = "v$version" ] || die "tag '$tag' does not match the Cargo.toml version (expected v$version)"
fi
printf '%s\n' "$version"
