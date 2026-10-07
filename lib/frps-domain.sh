# Independent FRP website / public certificate helpers. Inlined for distribution.
# The control channel uses its own private CA managed by the FRP lifecycle module.

_frps_nginx_bin() {
	if [ -n "${ONEBOX_NGINX_BIN:-}" ]; then
		[ -x "$ONEBOX_NGINX_BIN" ] && printf '%s' "$ONEBOX_NGINX_BIN"
	else command -v nginx; fi
}

_frps_domain_validate() {
	local value
	case "${FRPS_MODE:-}" in tcp | web) ;; *) err 'FRP 模式必须为 tcp 或 web'; return 1 ;; esac
	valid_domain "${FRPS_DOMAIN:-}" && [ "${#FRPS_DOMAIN}" -le 253 ] || { err 'FRP 控制域名无效'; return 1; }
	[ "$FRPS_MODE" = web ] || return 0
	if [ -n "${FRPS_SUBDOMAIN_HOST:-}" ]; then
		valid_domain "$FRPS_SUBDOMAIN_HOST" && [ "${#FRPS_SUBDOMAIN_HOST}" -le 238 ] || { err 'FRP 泛域名根无效'; return 1; }
		[ "${FRPS_TLS_METHOD:-}" != http ] || { err '泛域名证书需要 Cloudflare DNS 验证或自备证书'; return 1; }
	else
		valid_domain "${FRPS_WEB_DOMAIN:-}" && [ "${#FRPS_WEB_DOMAIN}" -le 253 ] || { err 'FRP 应用域名无效'; return 1; }
	fi
	case "${FRPS_TLS_METHOD:-}" in http | cf | custom) ;; *) err '网站证书方式必须为 http、cf 或 custom'; return 1 ;; esac
	for value in "${FRPS_HTTP_PORT:-}" "${FRPS_HTTPS_PORT:-}"; do
		[[ "$value" =~ ^[1-9][0-9]{0,4}$ ]] && [ "$value" -le 65535 ] || { err 'FRP 网站端口无效'; return 1; }
	done
	value=${FRPS_REDIRECT_PORT:-0}
	[[ "$value" =~ ^(0|[1-9][0-9]{0,4})$ ]] && [ "$value" -le 65535 ] || { err 'FRP HTTP 入口端口无效'; return 1; }
	if [ "$FRPS_TLS_METHOD" = http ] && [ "$value" != 80 ]; then err 'HTTP-01 验证要求 HTTP 入口为 TCP 80'; return 1; fi
	[ "$FRPS_HTTP_PORT" != "$FRPS_HTTPS_PORT" ] && [ "$FRPS_HTTP_PORT" != "$value" ] && [ "$FRPS_HTTPS_PORT" != "$value" ] || {
		err 'FRP 内部 HTTP、公开 HTTPS 与重定向端口不能相同'; return 1;
	}
}

_frps_web_cert_names() {
	if [ -n "${FRPS_SUBDOMAIN_HOST:-}" ]; then printf '%s\n%s\n' "$FRPS_SUBDOMAIN_HOST" "*.$FRPS_SUBDOMAIN_HOST";
	else printf '%s\n' "$FRPS_WEB_DOMAIN"; fi
}

_frps_web_server_names() {
	if [ -n "${FRPS_SUBDOMAIN_HOST:-}" ]; then printf '*.%s' "$FRPS_SUBDOMAIN_HOST";
	else printf '%s' "$FRPS_WEB_DOMAIN"; fi
}

_frps_check_dns() {
	local own resolved domain ip discovered=0 names="$FRPS_DOMAIN"
	_frps_domain_validate || return 1
	if [ "$FRPS_MODE" = web ]; then
		if [ -n "${FRPS_SUBDOMAIN_HOST:-}" ]; then
			names+=" onebox-$(openssl rand -hex 5).$FRPS_SUBDOMAIN_HOST"
		else names+=" $FRPS_WEB_DOMAIN"; fi
	fi
	own=$(own_ip_list)
	if [ -z "$own" ]; then detect_public_ip; own=$(own_ip_list); discovered=1; fi
	[ -n "$own" ] || { err '无法确认本机公网地址，不能验证 FRP 域名'; return 1; }
	for domain in $names; do
		resolved=$(resolve_domain "$domain")
		[ -n "$resolved" ] || { err "无法解析 FRP 域名 $domain，请先添加 DNS 记录"; return 1; }
		while IFS= read -r ip; do
			# NAT guests may have only private interfaces (or native IPv6 plus
			# NAT IPv4). Discover the public egress once before rejecting DNS.
			if [ "$discovered" = 0 ] && ! printf '%s\n' "$own" | grep -qixF "$ip"; then
				detect_public_ip; own=$(own_ip_list); discovered=1
			fi
			printf '%s\n' "$own" | grep -qixF "$ip" || { err "FRP 域名 $domain 的地址 $ip 不属于本机，请检查全部 A/AAAA 并关闭 CDN 代理"; return 1; }
		done <<<"$resolved"
	done
}

_frps_dns_info() {
	printf '  控制域名: %s → 本 VPS 公网 A/AAAA，关闭 CDN 代理\n' "$FRPS_DOMAIN"
	if [ "${FRPS_MODE:-}" = web ]; then
		if [ -n "${FRPS_SUBDOMAIN_HOST:-}" ]; then
			printf '  泛域解析: *.%s → 本 VPS 公网 A/AAAA，关闭 CDN 代理\n' "$FRPS_SUBDOMAIN_HOST"
			printf '  客户端 subdomain = "app" → https://app.%s' "$FRPS_SUBDOMAIN_HOST"
		else printf '  应用域名: %s → 本 VPS 公网 A/AAAA，关闭 CDN 代理\n  网站地址: https://%s' "$FRPS_WEB_DOMAIN" "$FRPS_WEB_DOMAIN"; fi
		[ "${FRPS_HTTPS_PORT:-443}" = 443 ] || printf ':%s' "$FRPS_HTTPS_PORT"
		printf '/\n'
		[ "${FRPS_TLS_METHOD:-}" != http ] || printf '  HTTP-01 签发和续期需持续放行公网 TCP 80；云防火墙也需放行。\n'
	fi
	printf '  无 IPv6 连通性时请删除 AAAA；本脚本不会修改域名商 DNS 记录。\n'
}

_frps_web_check() {
	local bin
	bin=$(_frps_nginx_bin) || return 1
	"$bin" -t -p "$FRPS_DIR/" -c "$FRPS_DIR/nginx.conf" >/dev/null 2>&1
}

# Bootstrap serves HTTP-01 only; the lifecycle caller starts the web service
# before issuance, then renders the full config and restarts/reloads that service.
_frps_web_render() {
	local bootstrap=${1:-0} user='' group='' candidate ipv6='' https_ipv6='' names suffix='' tmp http_port
	[ "${FRPS_MODE:-}" = web ] || return 0
	_frps_domain_validate || return 1
	case "$bootstrap" in 0 | 1) ;; *) return 1 ;; esac
	for candidate in nginx www-data nobody; do
		id "$candidate" >/dev/null 2>&1 || continue
		user=$candidate group=$(id -gn "$candidate")
		break
	done
	[ -n "$user" ] || { err 'nginx 需要非 root 工作进程账号'; return 1; }
	names=$(_frps_web_server_names)
	http_port=${FRPS_REDIRECT_PORT:-0}
	if [ "$bootstrap" = 1 ]; then
		[ "$FRPS_TLS_METHOD" = http ] && [ "$http_port" = 80 ] || return 1
	fi
	[ "$FRPS_HTTPS_PORT" = 443 ] || suffix=":$FRPS_HTTPS_PORT"
	if host_has_ipv6; then
		ipv6="listen [::]:$http_port;"
		https_ipv6="listen [::]:$FRPS_HTTPS_PORT ssl;"
	fi
	mkdir -p "$FRPS_DIR" "$FRPS_WEB_ROOT/.well-known/acme-challenge" || return 1
	chmod 700 "$FRPS_DIR" || return 1
	chmod 755 "$FRPS_WEB_VAR" "$FRPS_WEB_ROOT" "$FRPS_WEB_ROOT/.well-known" "$FRPS_WEB_ROOT/.well-known/acme-challenge" || return 1
	tmp=$(mktemp "$FRPS_DIR/.nginx.XXXXXX") || return 1
	{
		cat <<EOF
# Managed by onebox FRP; no system nginx includes.
user $user $group;
worker_processes 1;
pid "$FRPS_DIR/nginx.pid";
error_log "$FRPS_DIR/nginx-error.log" warn;
events { worker_connections 1024; }
http {
    access_log off;
    server_tokens off;
    default_type text/plain;
    map \$http_upgrade \$onebox_frp_connection { default upgrade; '' close; }
    client_body_temp_path "$FRPS_WEB_VAR/tmp/body";
    proxy_temp_path "$FRPS_WEB_VAR/tmp/proxy";
    fastcgi_temp_path "$FRPS_WEB_VAR/tmp/fastcgi";
    uwsgi_temp_path "$FRPS_WEB_VAR/tmp/uwsgi";
    scgi_temp_path "$FRPS_WEB_VAR/tmp/scgi";
EOF
		if [ "$http_port" != 0 ]; then
			cat <<EOF
    server {
        listen $http_port;
        $ipv6
        server_name $names;
        location ^~ /.well-known/acme-challenge/ {
            root "$FRPS_WEB_ROOT";
            try_files \$uri =404;
        }
EOF
			if [ "$bootstrap" = 1 ]; then printf '        location / { return 404; }\n';
			else printf '        location / { return 301 https://$host%s$request_uri; }\n' "$suffix"; fi
			printf '    }\n'
			# Prevent unrecognised Host values from becoming open redirects.
			printf '    server { listen %s default_server; ' "$http_port"
			[ -z "$ipv6" ] || printf 'listen [::]:%s default_server; ' "$http_port"
			printf 'server_name _; return 404; }\n'
		fi
		if [ "$bootstrap" = 0 ]; then
			cat <<EOF
    server {
        listen $FRPS_HTTPS_PORT ssl;
        $https_ipv6
        server_name $names;
        ssl_certificate "$FRPS_DIR/web-cert.pem";
        ssl_certificate_key "$FRPS_DIR/web-key.pem";
        ssl_protocols TLSv1.2 TLSv1.3;
        ssl_session_cache shared:onebox_frp:1m;
        ssl_session_timeout 10m;
        client_max_body_size 0;
        location / {
            proxy_pass http://127.0.0.1:$FRPS_HTTP_PORT;
            proxy_http_version 1.1;
            proxy_set_header Host \$host;
            proxy_set_header Upgrade \$http_upgrade;
            proxy_set_header Connection \$onebox_frp_connection;
            proxy_set_header X-Real-IP \$remote_addr;
            proxy_set_header X-Forwarded-For \$remote_addr;
            proxy_set_header X-Forwarded-Proto https;
            proxy_set_header X-Forwarded-Host \$host;
            proxy_set_header X-Forwarded-Port $FRPS_HTTPS_PORT;
            proxy_set_header Forwarded "";
            proxy_buffering off;
            proxy_request_buffering off;
            proxy_read_timeout 3600s;
            proxy_send_timeout 3600s;
        }
    }
    server {
        listen $FRPS_HTTPS_PORT ssl default_server;
EOF
			[ -z "$https_ipv6" ] || printf '        listen [::]:%s ssl default_server;\n' "$FRPS_HTTPS_PORT"
			cat <<EOF
        server_name _;
        ssl_certificate "$FRPS_DIR/web-cert.pem";
        ssl_certificate_key "$FRPS_DIR/web-key.pem";
        ssl_protocols TLSv1.2 TLSv1.3;
        return 404;
    }
EOF
		fi
		printf '}\n'
	} >"$tmp" || { rm -f "$tmp"; return 1; }
	# nginx creates its own worker-owned child directories, outside the secret root.
	mkdir -p "$FRPS_WEB_VAR/tmp" && chmod 755 "$FRPS_WEB_VAR/tmp" && chmod 600 "$tmp" && mv -f "$tmp" "$FRPS_DIR/nginx.conf" || { rm -f "$tmp"; return 1; }
	_frps_web_check
}

_frps_web_cert_validate() {
	local cert=${1:-$FRPS_DIR/web-cert.pem} key=${2:-$FRPS_DIR/web-key.pem} domain cert_pub key_pub
	[ -s "$cert" ] && [ -s "$key" ] || { err '网站证书或私钥为空'; return 1; }
	openssl x509 -in "$cert" -noout -checkend 3600 >/dev/null 2>&1 || { err '网站证书已过期或即将过期'; return 1; }
	# Verify validity times and server usage without assuming GNU date syntax.
	# The supplied leaf is a local trust anchor for these checks only; this does
	# not claim that browsers trust a self-signed or incomplete custom chain.
	openssl verify -partial_chain -trusted "$cert" -purpose sslserver "$cert" >/dev/null 2>&1 || {
		err '网站证书生效时间、签名或服务端用途校验失败'; return 1;
	}
	cert_pub=$(openssl x509 -in "$cert" -noout -pubkey 2>/dev/null) || return 1
	key_pub=$(openssl pkey -in "$key" -passin pass: -pubout 2>/dev/null) || { err '无法读取网站私钥（请使用未加密私钥）'; return 1; }
	[ -n "$cert_pub" ] && [ "$cert_pub" = "$key_pub" ] || { err '网站证书与私钥不匹配'; return 1; }
	while IFS= read -r domain; do
		if [[ "$domain" == \*.* ]]; then
			# A certificate for one concrete probe hostname is not a wildcard.
			openssl x509 -in "$cert" -noout -ext subjectAltName 2>/dev/null | tr ',' '\n' |
				sed 's/^[[:space:]]*//; s/[[:space:]]*$//' | grep -qixF "DNS:$domain" || {
				err "网站证书缺少泛域名 SAN $domain"; return 1;
			}
			domain="onebox-cert-check.${domain#*.}"
		fi
		# x509 -checkhost may return zero on mismatch; verify fails reliably.
		openssl verify -partial_chain -trusted "$cert" -purpose sslserver -verify_hostname "$domain" "$cert" >/dev/null 2>&1 || {
			err "网站证书未覆盖域名 $domain"; return 1;
		}
	done < <(_frps_web_cert_names)
}

# acme_install may add its own scheduler. Keep only the lifecycle module's
# managed `onebox frps renew --cron` task, without touching unrelated cron jobs.
_frps_acme_cron_remove() {
	has crontab || return 0
	local current filtered
	current=$(_site_read_crontab) || return 1
	filtered=$(printf '%s\n' "$current" | awk -v exe="$FRPS_DIR/acme/acme.sh" '
		# acme.sh quotes only its home directory: "/home/acme"/acme.sh.
		# Normalise quoting of this single token, then require an exact path.
		{ cmd=$6; gsub(/["\047]/, "", cmd); own = (cmd == exe && $7 == "--cron");
		  if (!own) print; }') || return 1
	[ "$current" = "$filtered" ] || printf '%s\n' "$filtered" | crontab -
}

_frps_web_certificate() (
	[ "${FRPS_MODE:-}" = web ] || return 0
	_frps_domain_validate || return 1
	local name primary='' args=() rc staged
	mkdir -p "$FRPS_DIR" && chmod 700 "$FRPS_DIR" || return 1
	if [ "$FRPS_TLS_METHOD" = custom ]; then
		[ -f "${FRPS_CERT_INPUT:-}" ] && [ -f "${FRPS_KEY_INPUT:-}" ] || { err '请提供自备 fullchain 与私钥文件'; return 1; }
		_frps_web_cert_validate "$FRPS_CERT_INPUT" "$FRPS_KEY_INPUT" || return 1
		staged=$(mktemp -d "$FRPS_DIR/.web-certificate.XXXXXX") || return 1
		trap 'rm -rf "$staged"' EXIT
		cp "$FRPS_CERT_INPUT" "$staged/cert" && cp "$FRPS_KEY_INPUT" "$staged/key" && chmod 600 "$staged/cert" "$staged/key" || return 1
		mv -f "$staged/cert" "$FRPS_DIR/web-cert.pem" && mv -f "$staged/key" "$FRPS_DIR/web-key.pem"
		return $?
	fi
	ACME_HOME="$FRPS_DIR/acme" ACME_SH="$FRPS_DIR/acme/acme.sh"
	acme_install "${FRPS_ACME_EMAIL:-}"; rc=$?
	_frps_acme_cron_remove || return 1
	[ "$rc" = 0 ] || return "$rc"
	while IFS= read -r name; do args+=(-d "$name"); [ -n "$primary" ] || primary=$name; done < <(_frps_web_cert_names)
	if [ "$FRPS_TLS_METHOD" = http ]; then args+=(--webroot "$FRPS_WEB_ROOT"); else args+=(--dns dns_cf); fi
	acme --issue "${args[@]}" -k ec-256 --server letsencrypt
	rc=$?
	[ "$rc" = 0 ] || [ "$rc" = 2 ] || return "$rc"
	# No reload command: the caller validates the new certificate and coordinates
	# service reloads inside the independent FRP transaction.
	acme --install-cert -d "$primary" --ecc --key-file "$FRPS_DIR/web-key.pem" --fullchain-file "$FRPS_DIR/web-cert.pem" --reloadcmd ':' || return 1
	chmod 600 "$FRPS_DIR/web-cert.pem" "$FRPS_DIR/web-key.pem" || return 1
	_frps_web_cert_validate
)

_frps_web_renew() (
	local method=${1:-manual} primary rc args=()
	[ "${FRPS_MODE:-}" = web ] || { err '当前 FRP 模式没有网站证书'; return 1; }
	[ "${FRPS_TLS_METHOD:-}" != custom ] || { err '自备证书请替换原证书文件后重新配置；不使用 ACME 自动续期'; return 1; }
	case "$method" in cron | --cron) ;; manual | '') args+=(--force) ;; *) return 1 ;; esac
	ACME_HOME="$FRPS_DIR/acme" ACME_SH="$FRPS_DIR/acme/acme.sh"
	primary=$(_frps_web_cert_names | head -n1)
	[ -x "$ACME_SH" ] && [ -f "$ACME_HOME/${primary}_ecc/${primary}.conf" ] || { err '缺少 FRP 网站证书续期部署'; return 1; }
	acme --renew -d "$primary" --ecc "${args[@]}"
	rc=$?
	_frps_acme_cron_remove || return 1
	[ "$rc" = 0 ] || [ "$rc" = 2 ] || return "$rc"
	chmod 600 "$FRPS_DIR/web-cert.pem" "$FRPS_DIR/web-key.pem" || return 1
	_frps_web_cert_validate
)
