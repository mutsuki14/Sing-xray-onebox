#!/usr/bin/env bash
# No host changes: real local .deb archives, mocked apt/sysctl/boot operations.
# shellcheck disable=SC2034
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/.." && pwd)
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
export ONEBOX_SOURCE_ONLY=1 NO_COLOR=1
# shellcheck source=../onebox.sh
. "$ROOT/onebox.sh"
PASS=0 FAIL=0
KERNEL=7.2.8-joeyblog-bbrv3
TAG=x86_64-7.2.8
FIXTURES="$WORK/packages"
mkdir -p "$FIXTURES"
for kind in image headers; do
	package="linux-$kind-$KERNEL"
	mkdir -p "$WORK/build-$kind/DEBIAN"
	printf 'Package: %s\nVersion: 7.2.8-1\nArchitecture: amd64\nMaintainer: Test <test@example.invalid>\nDescription: test archive only\n' "$package" >"$WORK/build-$kind/DEBIAN/control"
	dpkg-deb --build "$WORK/build-$kind" "$FIXTURES/${package}_7.2.8-1_amd64.deb" >/dev/null || exit 1
done
# Deny real system mutations even if a fixture forgets to override a command.
apt-get() { echo unexpected-apt >>"$WORK/unsafe"; return 91; }
sysctl() { echo unexpected-sysctl >>"$WORK/unsafe"; return 91; }
modprobe() { return 0; }
update-grub() { echo unexpected-grub >>"$WORK/unsafe"; return 91; }
reboot() { echo unexpected-reboot >>"$WORK/unsafe"; return 91; }
shutdown() { echo unexpected-shutdown >>"$WORK/unsafe"; return 91; }

check() {
	local case_dir="$WORK/case-$((PASS + FAIL))"
	mkdir -p "$case_dir"
	if (
		CASE=$case_dir
		BBR_DATA_DIR="$CASE/data" BBR_SYSCTL_CONF="$CASE/sysctl/99-onebox-bbr.conf"
		TMPDIR="$CASE" AUTO_YES=1 TTY_IN=""
		"$@"
	) >"$case_dir/log" 2>&1; then
		PASS=$((PASS + 1)); printf '[通过] %s\n' "$*"
	else
		FAIL=$((FAIL + 1)); printf '[失败] %s\n' "$*"; cat "$case_dir/log"
	fi
}

release_fixture() {
	local file name digest size
	: >"$CASE/assets"
	for file in "$FIXTURES"/*.deb; do
		name=${file##*/}; digest=$(sha256sum "$file"); digest=${digest%% *}; size=$(wc -c <"$file")
		jq -n --arg name "$name" --arg digest "sha256:$digest" --argjson size "$size" --arg url "https://github.com/$BBR_REPO/releases/download/$TAG/$name" \
			'{name:$name,digest:$digest,size:$size,browser_download_url:$url}' >>"$CASE/assets"
	done
	jq -s --arg tag "$TAG" '{tag_name:$tag,draft:false,prerelease:false,assets:.}' "$CASE/assets" >"$CASE/release"
	printf '[{"tag_name":"x86_64-7.2.8","draft":false,"prerelease":false}]' >"$CASE/tags"
	_bbr_api() { printf '%s\n' "$1" >>"$CASE/api"; case "$1" in releases/tags/*) cat "$CASE/release" ;; *) cat "$CASE/tags" ;; esac; }
	BBR_ARCH=x86_64 BBR_DEB_ARCH=amd64
}
alter_release() { jq "$1" "$CASE/release" >"$CASE/changed" && mv "$CASE/changed" "$CASE/release"; }
platform_fixture() {
	OS_ID=debian OS_VER=12 VIRT=none
	uname() { case "$1" in -m) echo x86_64 ;; -r) echo 6.1.0-old ;; esac; }
	dpkg() { [ "$*" = --print-architecture ] && echo amd64; }
	systemd-detect-virt() { return 1; }
	_bbr_boot_ready() { return 0; }
	_bbr_secure_boot_disabled() { return 0; }
	_bbr_space() { return 0; }
}
kernel_fixture() {
	platform_fixture
	release_fixture
	require_root() { return 0; }
	_bbr_installed_files_ready() { return 0; }
	_bbr_grub_has_kernel() { return 0; }
	dpkg-query() { printf 'install ok installed'; }
	update-grub() { echo grub >>"$CASE/actions"; return 0; }
	http_get() { printf '%s\n' "$1" >>"$CASE/downloads"; cp "$FIXTURES/${1##*/}" "$2"; }
	apt-get() {
		printf '%s\n' "$*" >>"$CASE/actions"
		[[ " $* " = *' --no-remove '* && " $* " = *' --no-install-recommends '* && " $* " = *' install '* ]] || return 92
		[[ " $* " != *' purge '* && " $* " != *' remove '* && " $* " != *' autoremove '* ]] || return 93
	}
}

valid_manifest() { release_fixture; _bbr_manifest "$TAG" standard "$CASE/manifest" && [ "$(wc -l <"$CASE/manifest")" = 2 ]; }
manifest_rejects() { release_fixture; alter_release "$1" && ! _bbr_manifest "$TAG" standard "$CASE/manifest"; }
check valid_manifest
check manifest_rejects '.assets[0].digest = null'
check manifest_rejects '.assets[0].digest = "sha256:bad"'
check manifest_rejects '.assets[0].browser_download_url = "https://example.invalid/evil.deb"'
check manifest_rejects '.assets[0].name = "../evil.deb"'
check manifest_rejects '.assets[0].size = -1'
check manifest_rejects '.assets[0].size = 1.5'
check manifest_rejects '.assets += [.assets[0]]'
check manifest_rejects '.assets = [.assets[0]]'
check manifest_rejects '.prerelease = true'
check manifest_rejects '.draft = true'
check manifest_rejects '.tag_name = "arm64-7.2.8"'
extra_assets_ignored() {
	release_fixture
	alter_release '.assets += [{name:"linux-image-debug.deb"},{name:"linux-libc-dev_7.2.8-1_amd64.deb"},{name:"install.sh"}]'
	_bbr_manifest "$TAG" standard "$CASE/manifest" && [ "$(wc -l <"$CASE/manifest")" = 2 ]
}
check extra_assets_ignored
invalid_tags() {
	release_fixture
	! _bbr_manifest 'x86_64-7.2.8-max' standard "$CASE/m" &&
	! _bbr_manifest 'arm64-7.2.8' standard "$CASE/m" &&
	! _bbr_manifest '../latest' standard "$CASE/m" &&
	[ ! -e "$CASE/api" ] &&
	_bbr_tag_valid 'x86_64-7.2.8-max' max &&
	[ "$(_bbr_kernel_name 'arm64-7.2.8-max')" = 7.2.8-joeyblog-bbrv3-max ]
}
check invalid_tags
tag_filtering() {
	release_fixture
	jq -n '["x86_64-7.2.8-max","arm64-7.2.8","x86_64-7.2.9","x86_64-7.2.10","x86_64-7.2.99-rc1"] | map({tag_name:.,draft:false,prerelease:false}) + [{tag_name:"x86_64-99.0",draft:false,prerelease:true}]' >"$CASE/tags"
	[ "$(_bbr_tags standard)" = $'x86_64-7.2.10\nx86_64-7.2.9' ] && [ "$(_bbr_tags max)" = x86_64-7.2.8-max ]
}
check tag_filtering
api_error_rejected() { release_fixture; echo '{"message":"rate limit"}' >"$CASE/tags"; ! _bbr_tags standard; }
check api_error_rejected
pagination() {
	release_fixture
	_bbr_api() {
		case "$1" in
		*page=1) jq -n '[range(100) | {tag_name:"arm64-7.2.8",draft:false,prerelease:false}]' ;;
		*page=2) cat "$CASE/tags" ;;
		*) return 9 ;;
		esac
	}
	[ "$(_bbr_tags standard)" = "$TAG" ]
}
check pagination
metadata_ignores_proxy() {
	GH_PROXY=https://proxy.invalid
	http_get() { printf '%s' "$1"; }
	[ "$(_bbr_api 'releases?per_page=100')" = "https://api.github.com/repos/$BBR_REPO/releases?per_page=100" ]
}
check metadata_ignores_proxy

platform_rejects() { platform_fixture; eval "$1"; ! _bbr_kernel_preflight; }
check platform_rejects 'OS_ID=ubuntu OS_VER=22.04'
check platform_rejects 'OS_ID=debian OS_VER=11'
check platform_rejects 'OS_ID=alpine OS_VER=3.23'
check platform_rejects 'VIRT=lxc'
check platform_rejects 'VIRT=wsl'
check platform_rejects 'systemd-detect-virt() { return 0; }'
check platform_rejects 'uname() { echo riscv64; }'
check platform_rejects 'dpkg() { echo arm64; }'
check platform_rejects '_bbr_secure_boot_disabled() { return 1; }'
check platform_rejects '_bbr_boot_ready() { return 1; }'
check platform_rejects '_bbr_space() { return 1; }'
platform_accepts() { platform_fixture; eval "$1"; _bbr_kernel_preflight; }
check platform_accepts 'OS_ID=debian OS_VER=12'
check platform_accepts 'OS_ID=ubuntu OS_VER=24.04'
check platform_accepts 'OS_VER=""; _osr_get() { echo trixie; }'
check platform_accepts 'uname() { echo aarch64; }; dpkg() { echo arm64; }'
space_fails_closed() { df() { printf 'header\nfs 1 1 unknown 99%% /boot\n'; }; ! _bbr_space /boot 524288; }
check space_fails_closed

secure_boot_variable() {
	local byte=$1 expected=$2
	mkdir -p "$CASE/sys/firmware/efi/efivars"
	# Four attribute bytes precede the UEFI variable's value.
	printf '\000\000\000\000%b' "$byte" >"$CASE/sys/firmware/efi/efivars/SecureBoot-test"
	mokutil() { return 1; }
	if [ "$expected" = accept ]; then _bbr_secure_boot_disabled "$CASE/sys"; else ! _bbr_secure_boot_disabled "$CASE/sys"; fi
}
check secure_boot_variable '\000' accept
check secure_boot_variable '\001' reject
check secure_boot_variable '\002' reject
secure_boot_unknown() { mkdir -p "$CASE/sys/firmware/efi"; mokutil() { return 1; }; ! _bbr_secure_boot_disabled "$CASE/sys"; }
check secure_boot_unknown
legacy_bios() { mkdir -p "$CASE/sys"; _bbr_secure_boot_disabled "$CASE/sys"; }
check legacy_bios
boot_fixture() {
	uname() { echo old-kernel; }
	mkdir -p "$CASE/root/boot/grub" "$CASE/root/lib/modules/old-kernel"
	printf 'existing grub\n' >"$CASE/root/boot/grub/grub.cfg"
	printf 'existing kernel\n' >"$CASE/root/boot/vmlinuz-old-kernel"
	printf 'existing initrd\n' >"$CASE/root/boot/initrd.img-old-kernel"
}
boot_fallback_present() { boot_fixture; _bbr_boot_ready "$CASE/root"; }
check boot_fallback_present
boot_fallback_missing() { boot_fixture; rm -rf "$CASE/root/$1"; ! _bbr_boot_ready "$CASE/root"; }
check boot_fallback_missing boot/grub/grub.cfg
check boot_fallback_missing boot/vmlinuz-old-kernel
check boot_fallback_missing boot/initrd.img-old-kernel
check boot_fallback_missing lib/modules/old-kernel
device_tree_rejected() { boot_fixture; mkdir -p "$CASE/root/proc/device-tree"; ! _bbr_boot_ready "$CASE/root"; }
check device_tree_rejected

preview_no_changes() {
	kernel_fixture
	bbr_install_kernel latest standard 0 && [ ! -e "$CASE/downloads" ] && [ ! -e "$CASE/actions" ] && [ ! -e "$BBR_DATA_DIR" ]
}
check preview_no_changes
cancel_no_changes() {
	kernel_fixture
	AUTO_YES=0
	! bbr_install_kernel latest standard 1 && [ ! -e "$CASE/downloads" ] && [ ! -e "$CASE/actions" ] && [ ! -e "$BBR_DATA_DIR" ]
}
check cancel_no_changes
install_success() {
	kernel_fixture
	bbr_install_kernel latest standard 1 &&
	[ "$(wc -l <"$CASE/downloads")" = 2 ] && [ "$(wc -l <"$CASE/actions")" = 3 ] &&
	[ -s "$BBR_DATA_DIR/last-install.tsv" ] && [ ! -e "$BBR_SYSCTL_CONF" ] &&
	! compgen -G "$CASE/onebox-bbr.*" >/dev/null
}
check install_success
download_fails() { kernel_fixture; http_get() { return 1; }; ! bbr_install_kernel "$TAG" standard 1 && [ ! -e "$CASE/actions" ]; }
check download_fails
checksum_rejects() {
	kernel_fixture
	# Same byte length, wrong digest: never reach apt, even via GH_PROXY.
	GH_PROXY=https://proxy.invalid
	http_get() { cp "$FIXTURES/${1##*/}" "$2"; printf X | dd of="$2" bs=1 count=1 conv=notrunc status=none; }
	! bbr_install_kernel "$TAG" standard 1 && [ ! -e "$CASE/actions" ]
}
check checksum_rejects
size_rejects() { kernel_fixture; alter_release '.assets[0].size += 1'; ! bbr_install_kernel "$TAG" standard 1 && [ ! -e "$CASE/actions" ]; }
check size_rejects
deb_arch_rejects() { release_fixture; BBR_DEB_ARCH=arm64; ! _bbr_verify_deb "$FIXTURES/linux-image-${KERNEL}_7.2.8-1_amd64.deb" "$KERNEL"; }
check deb_arch_rejects
deb_package_rejects() { release_fixture; ! _bbr_verify_deb "$FIXTURES/linux-image-${KERNEL}_7.2.8-1_amd64.deb" 7.2.9-joeyblog-bbrv3; }
check deb_package_rejects
deb_metadata_failure_blocks_install() {
	kernel_fixture
	dpkg-deb() { return 1; }
	! bbr_install_kernel "$TAG" standard 1 && [ ! -e "$CASE/actions" ]
}
check deb_metadata_failure_blocks_install
apt_simulation_rejects() {
	kernel_fixture
	apt-get() { printf '%s\n' "$*" >>"$CASE/actions"; return 100; }
	! bbr_install_kernel "$TAG" standard 1 && [ "$(wc -l <"$CASE/actions")" = 1 ] && [ ! -e "$BBR_DATA_DIR/last-install.tsv" ]
}
check apt_simulation_rejects
apt_install_failure() {
	kernel_fixture
	apt-get() { printf '%s\n' "$*" >>"$CASE/actions"; [ "$1" = --simulate ]; }
	! bbr_install_kernel "$TAG" standard 1 && [ "$(wc -l <"$CASE/actions")" = 2 ] && [ ! -e "$BBR_DATA_DIR/last-install.tsv" ]
}
check apt_install_failure
boot_failure() {
	kernel_fixture
	eval "$1"
	! bbr_install_kernel "$TAG" standard 1 && [ ! -e "$BBR_DATA_DIR/last-install.tsv" ]
}
check boot_failure 'update-grub() { return 1; }'
check boot_failure '_bbr_installed_files_ready() { return 1; }'
check boot_failure '_bbr_grub_has_kernel() { return 1; }'
check boot_failure 'dpkg-query() { echo "install ok unpacked"; }'
concurrent_install_rejected() {
	kernel_fixture
	_bbr_lock || return 1
	! bbr_install_kernel "$TAG" standard 1 && [ ! -e "$CASE/downloads" ] && [ ! -e "$CASE/actions" ]
}
check concurrent_install_rejected

sysctl_fixture() {
	VIRT=none
	mkdir -p "$(dirname "$BBR_SYSCTL_CONF")"
	printf 'old config\n' >"$BBR_SYSCTL_CONF"
	echo cubic >"$CASE/cc"; echo fq_codel >"$CASE/qd"
	_bbr_config_notice() { :; }
	sysctl() {
		local arg qd
		case "$1" in
		-n)
			case "$2" in
			net.ipv4.tcp_available_congestion_control) echo 'reno cubic bbr' ;;
			net.ipv4.tcp_congestion_control) cat "$CASE/cc" ;;
			net.core.default_qdisc) cat "$CASE/qd" ;;
			esac ;;
		-p)
			qd=$(sed -n 's/^net.core.default_qdisc = //p' "$2")
			printf '%s\n' "$qd" >"$CASE/qd"
			[ "${SYSCTL_FAIL:-0}" = 0 ] || return 1
			echo bbr >"$CASE/cc" ;;
		-w)
			shift
			for arg in "$@"; do
				case "$arg" in net.core.default_qdisc=*) printf '%s\n' "${arg#*=}" >"$CASE/qd" ;; net.ipv4.tcp_congestion_control=*) printf '%s\n' "${arg#*=}" >"$CASE/cc" ;; esac
			done ;;
		*) return 1 ;;
		esac
	}
}
enable_selects_queue() {
	sysctl_fixture
	enable_bbr "$1" && [ "$(cat "$CASE/cc")" = bbr ] && [ "$(cat "$CASE/qd")" = "$1" ] && grep -q "= $1$" "$BBR_SYSCTL_CONF"
}
check enable_selects_queue fq
check enable_selects_queue fq_codel
check enable_selects_queue fq_pie
check enable_selects_queue cake
already_bbr_updates_queue() {
	sysctl_fixture
	echo bbr >"$CASE/cc"
	enable_bbr fq && [ "$(cat "$CASE/qd")" = fq ] && grep -q 'Managed by Onebox' "$BBR_SYSCTL_CONF"
}
check already_bbr_updates_queue
partial_sysctl_rollback() {
	sysctl_fixture
	SYSCTL_FAIL=1
	! enable_bbr cake && [ "$(cat "$CASE/cc")" = cubic ] && [ "$(cat "$CASE/qd")" = fq_codel ] && [ "$(cat "$BBR_SYSCTL_CONF")" = 'old config' ]
}
check partial_sysctl_rollback
persist_failure_rollback() {
	sysctl_fixture
	mv() { return 1; }
	! enable_bbr fq && [ "$(cat "$CASE/cc")" = cubic ] && [ "$(cat "$CASE/qd")" = fq_codel ] && [ "$(cat "$BBR_SYSCTL_CONF")" = 'old config' ]
}
check persist_failure_rollback
invalid_queue_rejected() { sysctl_fixture; ! enable_bbr 'fq;reboot' && [ "$(cat "$BBR_SYSCTL_CONF")" = 'old config' ]; }
check invalid_queue_rejected
symlink_rejected() {
	sysctl_fixture
	printf 'untouched\n' >"$CASE/other"
	rm "$BBR_SYSCTL_CONF"; ln -s "$CASE/other" "$BBR_SYSCTL_CONF"
	! enable_bbr fq && [ "$(cat "$CASE/other")" = untouched ] && [ "$(cat "$CASE/cc")" = cubic ]
}
check symlink_rejected
config_directory_rejected() {
	sysctl_fixture
	rm "$BBR_SYSCTL_CONF"; mkdir "$BBR_SYSCTL_CONF"
	! enable_bbr fq && [ "$(cat "$CASE/cc")" = cubic ] && [ ! -e "$BBR_SYSCTL_CONF/config" ]
}
check config_directory_rejected
status_no_mutations() {
	sysctl_fixture
	dpkg-query() { return 1; }; tc() { echo 'qdisc existing-root'; }; modinfo() { echo 3; }
	_bbr_api() { echo network >>"$CASE/mutations"; return 1; }
	bbr_show_status >"$CASE/status" && grep -q '不代表已加载' "$CASE/status" && grep -q existing-root "$CASE/status" &&
	[ ! -e "$CASE/mutations" ] && [ ! -e "$BBR_DATA_DIR" ] && [ "$(cat "$BBR_SYSCTL_CONF")" = 'old config' ]
}
check status_no_mutations
dispatch_validation() {
	setup_tty() { :; }; detect_os() { :; }; detect_virt() { :; }
	bbr_install_kernel() { printf '%s\n' "$*" >"$CASE/dispatch"; }
	do_bbr install latest --max --apply && [ "$(cat "$CASE/dispatch")" = 'latest max 1' ] &&
	! do_bbr install latest second && ! do_bbr install --unknown && ! do_bbr status extra
}
check dispatch_validation

if [ -e "$WORK/unsafe" ]; then cat "$WORK/unsafe"; exit 1; fi
printf '\nBBR: %s passed, %s failed\n' "$PASS" "$FAIL"
[ "$FAIL" = 0 ]
