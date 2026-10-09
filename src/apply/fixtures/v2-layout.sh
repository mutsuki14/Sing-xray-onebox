#!/bin/sh
# Shared by the capture scripts: build, at $T, the layout
# `apply::testing::build_v2_layout` mirrors (same contents and modes).
# STATE must name fixtures/v2-state.json.
rm -rf "$T"
mkdir -p "$T"
umask 022
mk() { # mode path content
	mkdir -p "$(dirname "$2")"
	printf '%s' "$3" >"$2"
	chmod "$1" "$2"
}
md() {
	mkdir -p "$2"
	chmod "$1" "$2"
}
md 700 "$T/etc"
cp "$STATE" "$T/etc/state.json"
chmod 600 "$T/etc/state.json"
md 700 "$T/etc/tls"
mk 600 "$T/etc/tls/cert.pem" "CERT"
mk 600 "$T/etc/tls/key.pem" "KEY"
md 700 "$T/etc/tls/acme"
mk 755 "$T/etc/tls/acme/acme.sh" "#!/bin/sh code"
md 755 "$T/etc/tls/acme/dnsapi"
mk 644 "$T/etc/tls/acme/dnsapi/dns_cf.sh" "cf"
mk 600 "$T/etc/tls/acme/account.conf" "ACCOUNT"
mk 640 "$T/etc/tls/acme/hook.sh" "hook"
md 750 "$T/etc/client"
mk 644 "$T/etc/client/links.txt" "vless://x"
mk 600 "$T/etc/client/节点.txt" "unicode"
mk 600 "$T/etc/client/empty" ""
md 711 "$T/etc/client/nested"
md 700 "$T/etc/client/nested/deeper"
mk 400 "$T/etc/client/nested/deeper/z" "zz"
mk 644 "$T/etc/client/nested/A" "upper"
mk 644 "$T/etc/client/nested/a" "lower"
md 700 "$T/etc/site"
md 700 "$T/etc/site/empty"
mk 600 "$T/etc/site/nginx.pid" "123"
mk 600 "$T/etc/site/error.log" "err"
md 700 "$T/etc/site/content-backups"
mk 600 "$T/etc/site/content-backups/old" "old"
mk 600 "$T/etc/firewall-v2.json" '{"rules":[]}'
mk 600 "$T/etc/hop-v2.json" '[]'
md 700 "$T/etc/backups"
mk 600 "$T/etc/backups/keep" "backup"
md 755 "$T/www"
mk 644 "$T/www/index.html" "<h1>site</h1>"
mk 600 "$T/www/.onebox-site-owned" "onebox"
md 755 "$T/systemd"
mk 644 "$T/systemd/onebox-net.service" "[Unit]"
md 755 "$T/initd/init.d"
md 755 "$T/initd/local.d"
mk 755 "$T/initd/local.d/onebox-hop.start" "#!/bin/sh"
mk 755 "$T/initd/local.d/admin.start" "#!/bin/sh admin"
md 700 "$T/acme-home/example.com_ecc"
printf '# onebox-rust-retired-deployment=%s\nLe_Domain=%s\nLe_RealFullChainPath=%s\nLe_RealKeyPath=%s\n' \
	"$T/etc/tls" "'example.com'" "''" "''" >"$T/acme-home/example.com_ecc/example.com.conf"
chmod 600 "$T/acme-home/example.com_ecc/example.com.conf"
md 700 "$T/acme-home/other.org_ecc"
mk 600 "$T/acme-home/other.org_ecc/other.org.conf" "Le_RealFullChainPath='/etc/x.pem'"
