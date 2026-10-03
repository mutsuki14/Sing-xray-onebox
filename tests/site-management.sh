#!/usr/bin/env bash
# 静态网页内容管理回归：真实临时目录，不启动服务、不执行导入文件。
# shellcheck disable=SC2034,SC2329
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/.." && pwd)
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
export ONEBOX_SOURCE_ONLY=1 NO_COLOR=1 ONEBOX_DIR="$WORK/etc" ONEBOX_SITE_ROOT="$WORK/public"
# shellcheck source=../onebox.sh
. "$ROOT/onebox.sh"
if [ -n "${ONEBOX_SITE_MANAGEMENT_FRAGMENT:-}" ]; then
	# shellcheck source=/dev/null
	. "$ONEBOX_SITE_MANAGEMENT_FRAGMENT"
fi
PASS=0 FAIL=0 SKIP=0
check() {
	if "$@"; then
		PASS=$((PASS + 1))
	else
		local rc=$?
		if [ "$rc" = 77 ]; then SKIP=$((SKIP + 1)); printf '[跳过] %s (需要改变临时文件 owner 的权限)\n' "$*"
		else FAIL=$((FAIL + 1)); printf '[失败] %s\n' "$*"; fi
	fi
}
fixture() {
	REALITY_SITE_ROOT="$WORK/$1/public" REALITY_SITE_DIR="$WORK/$1/private"
	STATE_FILE="$WORK/$1/onebox.conf"
	reset_state
	PROTOCOLS=vless-reality
	pset CORE vless-reality singbox
	pset PORT vless-reality 443
	REALITY_SITE_ENABLED=1 REALITY_SITE_TITLE='原始标题' REALITY_SITE_DOMAIN=site.example.com
	mkdir -p "$REALITY_SITE_ROOT/.well-known/acme-challenge" "$REALITY_SITE_DIR"
	: >"$REALITY_SITE_ROOT/.onebox-site-owned"
	: >"$REALITY_SITE_DIR/.onebox-site-owned"
	site_render_index >"$REALITY_SITE_ROOT/index.html"
	printf 'current-challenge' >"$REALITY_SITE_ROOT/.well-known/acme-challenge/token"
	printf 'main-state-untouched\n' >"$STATE_FILE"
	require_installed() { :; }
}
run_manage() { do_site_manage "$@" >"$WORK/result" 2>&1; }
template_variants() (
	fixture templates
	local name label
	for name in minimal profile docs; do
		case "$name" in minimal) label='NOTES &amp; IDEAS' ;; profile) label='PERSONAL SPACE' ;; docs) label='KNOWLEDGE BASE' ;; esac
		run_manage template "$name" --title 'A & <script>"title"</script>' --description '简介 <b> & "文字"' --theme ocean || return 1
		grep -Fq "$label" "$REALITY_SITE_ROOT/index.html" &&
			grep -Fq '&lt;script&gt;' "$REALITY_SITE_ROOT/index.html" &&
			! grep -Fq '<script>' "$REALITY_SITE_ROOT/index.html" &&
			grep -Fq '#155e8b' "$REALITY_SITE_ROOT/index.html" || return 1
	done
	[ "$(cat "$STATE_FILE")" = main-state-untouched ] &&
		[ "$(stat -c %a "$REALITY_SITE_DIR/content-settings.tsv")" = 600 ] &&
		[ "$(stat -c %a "$REALITY_SITE_DIR/content-backups")" = 700 ]
)
title_legacy_and_template() (
	fixture titles
	run_manage title '兼容旧主页' && grep -Fq '兼容旧主页' "$REALITY_SITE_ROOT/index.html" || return 1
	run_manage template docs --description '保留这段简介' --theme slate && run_manage title '新的标题' || return 1
	grep -Fq 'KNOWLEDGE BASE' "$REALITY_SITE_ROOT/index.html" &&
		grep -Fq '保留这段简介' "$REALITY_SITE_ROOT/index.html" &&
		grep -Fq '#374151' "$REALITY_SITE_ROOT/index.html" &&
		grep -Fq '新的标题' "$REALITY_SITE_ROOT/index.html"
)
title_manual_edit_rejected() (
	fixture manual
	run_manage template minimal || return 1
	printf '\ncustom edit\n' >>"$REALITY_SITE_ROOT/index.html"
	local old; old=$(_site_hash <"$REALITY_SITE_ROOT/index.html")
	! run_manage title forbidden && [ "$(_site_hash <"$REALITY_SITE_ROOT/index.html")" = "$old" ]
)
title_custom_initial_rejected() (
	fixture custom
	printf 'custom homepage' >"$REALITY_SITE_ROOT/index.html"
	! run_manage title forbidden && [ "$(cat "$REALITY_SITE_ROOT/index.html")" = 'custom homepage' ]
)
preview_private_and_unpublished() (
	fixture preview
	local old preview; old=$(_site_hash <"$REALITY_SITE_ROOT/index.html")
	run_manage preview profile --title '预览标题' || return 1
	preview=$(find "$REALITY_SITE_DIR/previews" -type f)
	[ "$(_site_hash <"$REALITY_SITE_ROOT/index.html")" = "$old" ] &&
		[ ! -e "$REALITY_SITE_DIR/content-settings.tsv" ] && [ ! -e "$REALITY_SITE_DIR/content-backups" ] &&
		grep -Fq '尚未发布' "$WORK/result" && grep -Fq '预览标题' "$preview" &&
		[ "$(stat -c %a "$preview")" = 600 ] && [ "$(stat -c %a "$REALITY_SITE_DIR/previews")" = 700 ]
)
full_backup_and_restore() (
	fixture restore
	local first second
	mkdir -p "$REALITY_SITE_ROOT/assets"
	printf 'original asset' >"$REALITY_SITE_ROOT/assets/old.css"
	run_manage template docs --title '文档标题' --theme slate || return 1
	first=$(cat "$REALITY_SITE_DIR/content-backups/latest")
	printf 'later asset' >"$REALITY_SITE_ROOT/assets/old.css"
	run_manage template profile --title '个人标题' || return 1
	second=$(cat "$REALITY_SITE_DIR/content-backups/latest")
	printf 'unwanted' >"$REALITY_SITE_ROOT/extra.txt"
	run_manage restore "$second" || return 1
	[ ! -e "$REALITY_SITE_ROOT/extra.txt" ] && grep -Fq '文档标题' "$REALITY_SITE_ROOT/index.html" &&
		[ "$(cat "$REALITY_SITE_ROOT/assets/old.css")" = 'later asset' ] || return 1
	run_manage title '恢复后可改标题' && grep -Fq 'KNOWLEDGE BASE' "$REALITY_SITE_ROOT/index.html" || return 1
	run_manage restore "$first" || return 1
	[ ! -e "$REALITY_SITE_DIR/content-settings.tsv" ] &&
		[ "$(cat "$REALITY_SITE_ROOT/assets/old.css")" = 'original asset' ] &&
		grep -Fq '原始标题' "$REALITY_SITE_ROOT/index.html"
)
latest_chronological() (
	fixture latest
	run_manage template minimal --title first && run_manage title second && run_manage title third && run_manage restore || return 1
	grep -Fq '<title>second</title>' "$REALITY_SITE_ROOT/index.html"
)
import_nonexecuting() (
	fixture import
	local source="$WORK/import/source"
	mkdir -p "$source/assets" "$source/.well-known/acme-challenge"
	printf '<!doctype html><title>Imported</title>' >"$source/index.html"
	printf 'image bytes' >"$source/assets/image.png"
	printf '#!/bin/sh\ntouch "%s"\n' "$WORK/should-not-exist" >"$source/build.sh"
	chmod 755 "$source/build.sh"
	printf 'bad challenge' >"$source/.well-known/acme-challenge/evil"
	run_manage import "$source" || return 1
	[ "$(cat "$REALITY_SITE_ROOT/assets/image.png")" = 'image bytes' ] &&
		[ ! -e "$WORK/should-not-exist" ] && [ "$(stat -c %a "$REALITY_SITE_ROOT/build.sh")" = 644 ] &&
		[ "$(cat "$REALITY_SITE_ROOT/.well-known/acme-challenge/token")" = current-challenge ] &&
		[ ! -e "$REALITY_SITE_ROOT/.well-known/acme-challenge/evil" ] && ! run_manage title forbidden &&
		grep -Fq '<title>Imported</title>' "$REALITY_SITE_ROOT/index.html"
)
restore_keeps_current_challenge() (
	fixture challenge
	run_manage template minimal || return 1
	printf new-validation >"$REALITY_SITE_ROOT/.well-known/acme-challenge/token"
	run_manage restore && [ "$(cat "$REALITY_SITE_ROOT/.well-known/acme-challenge/token")" = new-validation ]
)
bad_import() (
	local attack=$1 source target
	fixture "bad-$attack"
	source="$WORK/bad-$attack/source"
	mkdir -p "$source"
	printf 'source' >"$source/index.html"
	case "$attack" in
	root-symlink) ln -s "$source" "$WORK/bad-$attack/link"; source="$WORK/bad-$attack/link" ;;
	ancestor-symlink) mkdir -p "$source/child"; printf child >"$source/child/index.html"; ln -s "$source" "$WORK/bad-$attack/link"; source="$WORK/bad-$attack/link/child" ;;
	file-symlink) ln -s "$STATE_FILE" "$source/secret" ;;
	broken-symlink) ln -s "$source/missing" "$source/broken" ;;
	fifo) mkfifo "$source/pipe" ;;
	self) source="$REALITY_SITE_ROOT" ;;
	child) mkdir "$REALITY_SITE_ROOT/child"; printf child >"$REALITY_SITE_ROOT/child/index.html"; source="$REALITY_SITE_ROOT/child" ;;
	ancestor) source="$WORK/bad-$attack"; printf root >"$source/index.html" ;;
	private) source="$REALITY_SITE_DIR"; printf private >"$source/index.html" ;;
	dotdot) source="$source/../source" ;;
	empty) source='' ;;
	missing-index) rm "$source/index.html" ;;
	directory-index) rm "$source/index.html"; mkdir "$source/index.html" ;;
	esac
	target=$(_site_hash <"$REALITY_SITE_ROOT/index.html")
	! run_manage import "$source" && [ "$(_site_hash <"$REALITY_SITE_ROOT/index.html")" = "$target" ]
)
invalid_options() (
	fixture options
	! run_manage template unknown && ! run_manage template minimal --theme red &&
		! run_manage template minimal --title '' && ! run_manage template minimal --title $'line1\nline2' &&
		! run_manage template minimal --description "$(printf 'a%.0s' {1..241})" &&
		! run_manage template minimal --unknown value && ! run_manage template minimal --title &&
		! run_manage title && ! run_manage restore ../secret && ! run_manage missing-command &&
		[ ! -e "$REALITY_SITE_DIR/content-backups" ]
)
disabled_rejected() (
	fixture disabled
	REALITY_SITE_ENABLED=0
	! run_manage template minimal && grep -Fq '未启用' "$WORK/result" && [ ! -e "$REALITY_SITE_DIR/content-backups" ]
)
existing_lock_rejected() (
	fixture lock
	mkdir "$REALITY_SITE_DIR/.content-lock"
	! run_manage template minimal && [ -d "$REALITY_SITE_DIR/.content-lock" ]
)
metadata_not_executed() (
	fixture metadata
	# The payload must remain literal: metadata is data, never sourced.
	# shellcheck disable=SC2016
	printf 'kind\t$(touch %s)\n' "$WORK/metadata-command" >"$REALITY_SITE_DIR/content-settings.tsv"
	! run_manage template minimal && [ ! -e "$WORK/metadata-command" ]
)
unsafe_backup_rejected() (
	fixture unsafe-backup
	run_manage template minimal || return 1
	local id; id=$(cat "$REALITY_SITE_DIR/content-backups/latest")
	ln -s "$STATE_FILE" "$REALITY_SITE_DIR/content-backups/$id/root/secret"
	! run_manage restore "$id" && grep -Fq 'NOTES &amp; IDEAS' "$REALITY_SITE_ROOT/index.html"
)
unsafe_private_paths_rejected() (
	fixture private-paths
	ln -s "$STATE_FILE" "$REALITY_SITE_DIR/content-settings.tsv"
	! run_manage template minimal || return 1
	rm "$REALITY_SITE_DIR/content-settings.tsv"
	mkdir "$REALITY_SITE_DIR/content-backups"
	ln -s "$STATE_FILE" "$REALITY_SITE_DIR/content-backups/latest"
	! run_manage template minimal && [ "$(cat "$STATE_FILE")" = main-state-untouched ]
)
failed_tree_listing_rejected() (
	fixture find-failure
	find() { return 1; }
	! run_manage template minimal && [ ! -e "$REALITY_SITE_DIR/content-backups" ]
)
staged_symlink_rejected() (
	fixture staged-symlink
	local source="$WORK/staged-symlink/source"
	mkdir "$source"
	printf source >"$source/index.html"
	cp() {
		local from="${*: -2:1}" to="${*: -1}"
		command cp "$@" || return 1
		if [ "$from" = "$source/." ]; then
			rm -f "$to/index.html"
			ln -s "$STATE_FILE" "$to/index.html"
		fi
	}
	! run_manage import "$source" && [ "$(cat "$STATE_FILE")" = main-state-untouched ] &&
		grep -Fq '原始标题' "$REALITY_SITE_ROOT/index.html"
)
import_owned_by_publisher() (
	fixture foreign-owner
	local source="$WORK/foreign-owner/source" owner
	owner=$(id -u)
	[ "$owner" = 0 ] || return 77
	mkdir "$source"
	printf 'foreign-owned homepage' >"$source/index.html"
	chown -R 65534:65534 "$source" 2>/dev/null || return 77
	run_manage import "$source" && [ "$(stat -c %u "$REALITY_SITE_ROOT")" = "$owner" ] &&
		[ "$(stat -c %u "$REALITY_SITE_ROOT/index.html")" = "$owner" ]
)
backup_fifo_rejected() (
	fixture backup-fifo
	run_manage template minimal || return 1
	local id; id=$(cat "$REALITY_SITE_DIR/content-backups/latest")
	rm "$REALITY_SITE_DIR/content-backups/$id/root-path"
	mkfifo "$REALITY_SITE_DIR/content-backups/$id/root-path"
	! run_manage restore "$id" || return 1
	rm "$REALITY_SITE_DIR/content-backups/latest"
	mkfifo "$REALITY_SITE_DIR/content-backups/latest"
	! run_manage restore
)
concurrent_root_creation_rolls_back() (
	fixture concurrent-root
	local old; old=$(_site_hash <"$REALITY_SITE_ROOT/index.html")
	mv() {
		local from="${*: -2:1}" to="${*: -1}"
		command mv "$@" || return 1
		if [ "$from" = "$REALITY_SITE_ROOT" ] && [[ "$to" = *'/.onebox-content-old-'* ]] && [[ "$to" != *.concurrent ]]; then
			mkdir -p "$REALITY_SITE_ROOT/new-child"
			printf 'concurrent write' >"$REALITY_SITE_ROOT/new-child/token"
		fi
	}
	! run_manage template docs && [ "$(_site_hash <"$REALITY_SITE_ROOT/index.html")" = "$old" ] &&
		[ "$(find "$WORK/concurrent-root" -path '*.concurrent/new-child/token' -exec cat {} \;)" = 'concurrent write' ]
)
failed_copy_preserves_original() (
	local failure=$1 old
	fixture "failed-$failure"
	run_manage template minimal --title original || return 1
	old=$(_site_hash <"$REALITY_SITE_ROOT/index.html")
	command cp "$REALITY_SITE_DIR/content-settings.tsv" "$WORK/failed-$failure/settings-original"
	cp() {
		case "$failure:$*" in snapshot:*'.pending.'* | stage:*'.onebox-content.'*) return 1 ;; esac
		command cp "$@"
	}
	! run_manage template docs --title forbidden && [ "$(_site_hash <"$REALITY_SITE_ROOT/index.html")" = "$old" ] &&
		cmp -s "$REALITY_SITE_DIR/content-settings.tsv" "$WORK/failed-$failure/settings-original" &&
		[ ! -e "$REALITY_SITE_DIR/.content-lock" ]
)
failed_publish_rolls_back() (
	local failure=$1 old
	fixture "publish-$failure"
	run_manage template minimal --title original || return 1
	old=$(_site_hash <"$REALITY_SITE_ROOT/index.html")
	cp "$REALITY_SITE_DIR/content-settings.tsv" "$WORK/publish-$failure/settings-original"
	mv() {
		local from="${*: -2:1}" to="${*: -1}"
		if [ "$failure" = content ] && [[ "$from" = *'/.onebox-content.'* ]] && [ "$to" = "$REALITY_SITE_ROOT" ]; then return 1; fi
		if [ "$failure" = metadata ] && [[ "$from" = *'/.content-settings.'* ]]; then return 1; fi
		command mv "$@"
	}
	! run_manage template profile --title forbidden && [ "$(_site_hash <"$REALITY_SITE_ROOT/index.html")" = "$old" ] &&
		cmp -s "$REALITY_SITE_DIR/content-settings.tsv" "$WORK/publish-$failure/settings-original" &&
		[ -f "$REALITY_SITE_DIR/content-backups/$(cat "$REALITY_SITE_DIR/content-backups/latest")/root/index.html" ] &&
		[ ! -e "$REALITY_SITE_DIR/.content-lock" ]
)
failed_recovery_preserves_backup() (
	fixture failed-recovery
	run_manage template minimal --title original || return 1
	mv() {
		local from="${*: -2:1}"
		case "$*" in *'/.onebox-content.'* | *'/.onebox-content-old-'*)
			[ "$from" = "$REALITY_SITE_ROOT" ] || return 1 ;;
		esac
		command mv "$@"
	}
	! run_manage template docs --title forbidden || return 1
	local backup; backup="$REALITY_SITE_DIR/content-backups/$(cat "$REALITY_SITE_DIR/content-backups/latest")"
	grep -Fq '<title>original</title>' "$backup/root/index.html" && grep -Fq '无法恢复' "$WORK/result"
)

check template_variants
check title_legacy_and_template
check title_manual_edit_rejected
check title_custom_initial_rejected
check preview_private_and_unpublished
check full_backup_and_restore
check latest_chronological
check import_nonexecuting
check restore_keeps_current_challenge
for attack in root-symlink ancestor-symlink file-symlink broken-symlink fifo self child ancestor private dotdot empty missing-index directory-index; do check bad_import "$attack"; done
check invalid_options
check disabled_rejected
check existing_lock_rejected
check metadata_not_executed
check unsafe_backup_rejected
check unsafe_private_paths_rejected
check failed_tree_listing_rejected
check staged_symlink_rejected
check import_owned_by_publisher
check backup_fifo_rejected
check concurrent_root_creation_rolls_back
check failed_copy_preserves_original snapshot
check failed_copy_preserves_original stage
check failed_publish_rolls_back content
check failed_publish_rolls_back metadata
check failed_recovery_preserves_backup
printf '\n网站内容管理测试: %s 通过, %s 失败, %s 跳过\n' "$PASS" "$FAIL" "$SKIP"
[ "$FAIL" = 0 ]
