# FRP server management. Embedded into onebox.sh by scripts/embed-frps.py.
readonly TESTED_FRP_VERSION="0.71.0"
FRPS_DIR="${ONEBOX_FRPS_DIR:-/etc/onebox-frp}"
FRPS_BIN_DIR="${ONEBOX_FRPS_BIN_DIR:-/opt/onebox-frp}"
FRPS_BIN="$FRPS_BIN_DIR/frps"
FRPS_CONF="$FRPS_DIR/frps.toml"
FRPS_STATE="$FRPS_DIR/state.conf"
FRPS_WEB_VAR="${ONEBOX_FRPS_WEB_VAR:-/var/lib/onebox-frp}"
FRPS_WEB_ROOT="$FRPS_WEB_VAR/www"
FRPS_LOG_DIR="${ONEBOX_FRPS_LOG_DIR:-/var/log/onebox-frp}"
FRPS_RUN_DIR="${ONEBOX_FRPS_RUN_DIR:-/run/onebox-frp}"
FRPS_LOCK="${ONEBOX_FRPS_LOCK:-/run/onebox-frp.lock}"
FRPS_SYSTEMD_DIR="${ONEBOX_FRPS_SYSTEMD_DIR:-/etc/systemd/system}"
readonly FRPS_KEYS="FRPS_MODE FRPS_DOMAIN FRPS_BIND_ADDR FRPS_BIND_PORT FRPS_HTTP_PORT FRPS_HTTPS_PORT FRPS_REDIRECT_PORT FRPS_WEB_DOMAIN FRPS_SUBDOMAIN_HOST FRPS_RANGE_START FRPS_RANGE_END FRPS_TOKEN FRPS_TLS_METHOD FRPS_CERT_INPUT FRPS_KEY_INPUT FRPS_VERSION"

_frps_defaults() {
	FRPS_MODE=web FRPS_DOMAIN="" FRPS_BIND_PORT=7000 FRPS_HTTP_PORT=7080
	FRPS_HTTPS_PORT=443 FRPS_REDIRECT_PORT=80 FRPS_WEB_DOMAIN="" FRPS_SUBDOMAIN_HOST=""
	FRPS_RANGE_START=20000 FRPS_RANGE_END=20100 FRPS_TOKEN="" FRPS_TLS_METHOD=http
	FRPS_CERT_INPUT="" FRPS_KEY_INPUT="" FRPS_VERSION=$TESTED_FRP_VERSION
	FRPS_BIND_ADDR=0.0.0.0
	host_has_ipv6 && FRPS_BIND_ADDR=::
	return 0
}

_frps_installed() { [ -f "$FRPS_DIR/.managed" ] && [ -f "$FRPS_STATE" ]; }
_frps_paths_safe() {
	local path other roots_seen=" "
	for path in "$FRPS_DIR" "$FRPS_BIN_DIR" "$FRPS_WEB_VAR" "$FRPS_LOG_DIR" "$FRPS_RUN_DIR" "$FRPS_LOCK" "$FRPS_SYSTEMD_DIR"; do
		[[ "$path" =~ ^/[A-Za-z0-9_./-]+$ ]] && _support_path_safe "$path" || { err "FRP 路径必须是无符号链接的绝对路径，且不能包含空格"; return 1; }
		[[ "$path" != *//* && "$path" != */ ]] || { err "FRP 路径不能含重复或末尾斜杠"; return 1; }
		case "$path" in / | /etc | /opt | /var | /var/lib | /var/log | /run | /usr | /usr/local) err "FRP 路径不能指向系统顶层目录"; return 1 ;; esac
	done
	for path in "$FRPS_DIR" "$FRPS_BIN_DIR" "$FRPS_WEB_VAR" "$FRPS_LOG_DIR" "$FRPS_RUN_DIR"; do
		[[ "$roots_seen" != *" $path "* ]] || { err "FRP 数据根目录不能相同"; return 1; }
		roots_seen+="$path "
		for other in "$FRPS_DIR" "$FRPS_BIN_DIR" "$FRPS_WEB_VAR" "$FRPS_LOG_DIR" "$FRPS_RUN_DIR"; do
			[ "$path" = "$other" ] && continue
			case "$path/" in "$other/"*) err "FRP 数据根目录不能互相包含"; return 1 ;; esac
			case "$other/" in "$path/"*) err "FRP 数据根目录不能互相包含"; return 1 ;; esac
		done
		for other in "$FRPS_SYSTEMD_DIR" "$INITD_DIR"; do
			case "$path/" in "$other/"*) err "FRP 数据目录不能位于服务目录中"; return 1 ;; esac
			case "$other/" in "$path/"*) err "FRP 数据目录不能包含服务目录"; return 1 ;; esac
		done
		case "$FRPS_LOCK/" in "$path/"*) err "FRP 锁文件必须独立于可回滚的数据目录"; return 1 ;; esac
		for other in "$ONEBOX_DIR" "$BIN_DIR" "$LOG_DIR" "$RUN_DIR"; do
			case "$path/" in "$other/"*) err "FRP 数据必须独立于代理数据目录"; return 1 ;; esac
			case "$other/" in "$path/"*) err "FRP 数据路径不能包含代理数据目录"; return 1 ;; esac
		done
	done
}

_frps_load() {
	local key value frps_seen_keys=" "
	_frps_installed && _support_path_safe "$FRPS_STATE" || return 1
	_frps_defaults
	while IFS='=' read -r key value || [ -n "$key" ]; do
		[ -n "$key" ] || continue
		[[ " $FRPS_KEYS " = *" $key "* && "$frps_seen_keys" != *" $key "* && "$value" != *[[:cntrl:]]* ]] || { err "FRP 状态文件无效"; return 1; }
		printf -v "$key" '%s' "$value"
		frps_seen_keys+="$key "
	done <"$FRPS_STATE"
	for key in $FRPS_KEYS; do [[ "$frps_seen_keys" = *" $key "* ]] || { err "FRP 状态缺少 $key"; return 1; }; done
	[[ "$FRPS_TOKEN" =~ ^[a-f0-9]{64}$ ]] || { err "FRP 状态缺少有效 token"; return 1; }
	_frps_validate
}

_frps_save() {
	local tmp key
	tmp=$(mktemp "$FRPS_DIR/.state.XXXXXX") || return 1
	for key in $FRPS_KEYS; do printf '%s=%s\n' "$key" "${!key}"; done >"$tmp" || { rm -f "$tmp"; return 1; }
	chmod 600 "$tmp" && mv -f "$tmp" "$FRPS_STATE"
}

_frps_port_valid() { [[ "$1" =~ ^[1-9][0-9]{0,4}$ ]] && [ "$1" -le 65535 ]; }
_frps_validate() {
	local port key frps_seen_ports=" "
	for key in $FRPS_KEYS; do [[ "${!key-}" != *[[:cntrl:]]* ]] || { err "FRP 参数不能含控制字符"; return 1; }; done
	case "$FRPS_MODE" in web | tcp) ;; *) err "FRP 模式应为 web 或 tcp"; return 1 ;; esac
	case "$FRPS_BIND_ADDR" in 0.0.0.0 | :: | 127.0.0.1 | ::1) ;; *) err "FRP 监听地址无效"; return 1 ;; esac
	valid_domain "$FRPS_DOMAIN" && [ "${#FRPS_DOMAIN}" -le 253 ] || { err "请设置有效的 FRP 控制域名"; return 1; }
	[[ "$FRPS_VERSION" = latest || "$FRPS_VERSION" =~ ^0\.[0-9]+\.[0-9]+$ ]] || { err "FRP 版本格式无效"; return 1; }
	[ "$FRPS_VERSION" = latest ] || ver_ge "$FRPS_VERSION" "$TESTED_FRP_VERSION" || { err "FRP 需要 >= $TESTED_FRP_VERSION"; return 1; }
	[[ -z "$FRPS_TOKEN" || "$FRPS_TOKEN" =~ ^[a-f0-9]{64}$ ]] || { err "FRP token 必须为自动生成的 64 位十六进制值"; return 1; }
	for key in FRPS_BIND_PORT FRPS_HTTP_PORT FRPS_HTTPS_PORT FRPS_RANGE_START FRPS_RANGE_END; do
		_frps_port_valid "${!key}" || { err "$key 端口无效"; return 1; }
	done
	[ "$FRPS_REDIRECT_PORT" = 0 ] || _frps_port_valid "$FRPS_REDIRECT_PORT" || return 1
	[ "$FRPS_RANGE_START" -le "$FRPS_RANGE_END" ] && [ "$((FRPS_RANGE_END - FRPS_RANGE_START))" -le 999 ] || { err "FRP 转发端口范围最多 1000 个"; return 1; }
	for port in "$FRPS_BIND_PORT" $([ "$FRPS_MODE" != web ] || printf '%s %s %s' "$FRPS_HTTP_PORT" "$FRPS_HTTPS_PORT" "$FRPS_REDIRECT_PORT"); do
		[ "$port" != 0 ] || continue
		[[ "$frps_seen_ports" != *" $port "* ]] || { err "FRP 监听端口不能重复"; return 1; }; frps_seen_ports+="$port "
		[ "$port" -lt "$FRPS_RANGE_START" ] || [ "$port" -gt "$FRPS_RANGE_END" ] || { err "FRP 监听端口不能位于转发端口范围中"; return 1; }
	done
	_frps_domain_validate
}

_frps_lock() {
	_frps_paths_safe || return 1
	has flock || { err "FRP 写操作需要 flock (util-linux)"; return 1; }
	mkdir -p "$(dirname "$FRPS_LOCK")" || return 1
	exec 8>"$FRPS_LOCK" || return 1
	flock -n 8 || { err "另一个 FRP 管理操作正在进行"; return 1; }
}

# No eval/source: stored credentials and values are data, never shell code.
_frps_render() {
	_frps_validate && [[ "$FRPS_TOKEN" =~ ^[a-f0-9]{64}$ ]] || return 1
	local proxy_addr=$FRPS_BIND_ADDR
	[ "$FRPS_MODE" != web ] || proxy_addr=127.0.0.1
	cat >"$FRPS_CONF" <<EOF
bindAddr = "$FRPS_BIND_ADDR"
bindPort = $FRPS_BIND_PORT
proxyBindAddr = "$proxy_addr"
auth.method = "token"
auth.token = "$FRPS_TOKEN"
auth.additionalScopes = ["HeartBeats", "NewWorkConns"]
transport.tls.force = true
transport.tls.certFile = "$FRPS_DIR/server-cert.pem"
transport.tls.keyFile = "$FRPS_DIR/server-key.pem"
allowPorts = [{ start = $FRPS_RANGE_START, end = $FRPS_RANGE_END }]
maxPortsPerClient = 10
log.to = "console"
log.level = "info"
log.disablePrintColor = true
EOF
	if [ "$FRPS_MODE" = web ]; then
		printf 'vhostHTTPPort = %s\n' "$FRPS_HTTP_PORT" >>"$FRPS_CONF"
		[ -z "$FRPS_SUBDOMAIN_HOST" ] || printf 'subDomainHost = "%s"\n' "$FRPS_SUBDOMAIN_HOST" >>"$FRPS_CONF"
	fi
	chmod 600 "$FRPS_CONF"
}

_frps_control_certificate() (
	local work
	valid_domain "$FRPS_DOMAIN" || return 1
	mkdir -p "$FRPS_DIR" && chmod 700 "$FRPS_DIR" || return 1
	umask 077
	work=$(mktemp -d "$FRPS_DIR/.control-cert.XXXXXX") || return 1
	trap 'rm -rf "$work"' EXIT
	if [ ! -e "$FRPS_DIR/ca.pem" ] && [ ! -e "$FRPS_DIR/ca-key.pem" ]; then
		cat >"$work/ca.cnf" <<'EOF'
[req]
distinguished_name=dn
x509_extensions=ca
prompt=no
[dn]
CN=Onebox FRP private CA
[ca]
basicConstraints=critical,CA:TRUE,pathlen:0
keyUsage=critical,keyCertSign,cRLSign
subjectKeyIdentifier=hash
EOF
		openssl ecparam -genkey -name prime256v1 -out "$work/ca-key.pem" >/dev/null 2>&1 &&
			openssl req -new -x509 -sha256 -days 3650 -key "$work/ca-key.pem" -config "$work/ca.cnf" -out "$work/ca.pem" >/dev/null 2>&1 || return 1
		mv "$work/ca.pem" "$FRPS_DIR/ca.pem" && mv "$work/ca-key.pem" "$FRPS_DIR/ca-key.pem" || return 1
	fi
	openssl x509 -in "$FRPS_DIR/ca.pem" -checkend 2592000 -noout >/dev/null 2>&1 &&
		[ "$(openssl x509 -in "$FRPS_DIR/ca.pem" -pubkey -noout 2>/dev/null)" = "$(openssl pkey -in "$FRPS_DIR/ca-key.pem" -pubout 2>/dev/null)" ] || { err "FRP CA 无效或即将过期，请保留旧部署并人工处理 CA 轮换"; return 1; }
	if openssl x509 -in "$FRPS_DIR/server-cert.pem" -checkend 2592000 -noout >/dev/null 2>&1 &&
		openssl verify -CAfile "$FRPS_DIR/ca.pem" -verify_hostname "$FRPS_DOMAIN" "$FRPS_DIR/server-cert.pem" >/dev/null 2>&1 &&
		[ "$(openssl x509 -in "$FRPS_DIR/server-cert.pem" -pubkey -noout 2>/dev/null)" = "$(openssl pkey -in "$FRPS_DIR/server-key.pem" -pubout 2>/dev/null)" ]; then return 0; fi
	cat >"$work/server.cnf" <<EOF
[req]
distinguished_name=dn
prompt=no
[dn]
CN=$FRPS_DOMAIN
[server]
subjectAltName=DNS:$FRPS_DOMAIN
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=serverAuth
EOF
	openssl ecparam -genkey -name prime256v1 -out "$work/server-key.pem" >/dev/null 2>&1 &&
		openssl req -new -sha256 -key "$work/server-key.pem" -config "$work/server.cnf" -out "$work/server.csr" >/dev/null 2>&1 &&
		openssl x509 -req -in "$work/server.csr" -CA "$FRPS_DIR/ca.pem" -CAkey "$FRPS_DIR/ca-key.pem" -CAcreateserial -days 397 -sha256 -extfile "$work/server.cnf" -extensions server -out "$work/server-cert.pem" >/dev/null 2>&1 &&
		openssl verify -CAfile "$FRPS_DIR/ca.pem" -verify_hostname "$FRPS_DOMAIN" "$work/server-cert.pem" >/dev/null 2>&1 || return 1
	mv "$work/server-cert.pem" "$FRPS_DIR/server-cert.pem" && mv "$work/server-key.pem" "$FRPS_DIR/server-key.pem"
)

_frps_download() (
	local output=$1 client_output=${2:-} arch version=$FRPS_VERSION requested=$FRPS_VERSION json asset url digest size work member
	case "$(uname -m)" in x86_64) arch=amd64 ;; aarch64 | arm64) arch=arm64 ;; armv7* | armv6*) arch=arm ;; riscv64) arch=riscv64 ;; loongarch64) arch=loong64 ;; *) err "FRP 暂不支持此 CPU 架构"; return 1 ;; esac
	case "$version" in latest) url=https://api.github.com/repos/fatedier/frp/releases/latest ;; *) url="https://api.github.com/repos/fatedier/frp/releases/tags/v$version" ;; esac
	json=$(http_get "$url") || { err "读取 FRP Release 失败"; return 1; }
	version=$(printf '%s' "$json" | jq -er 'select(.draft == false and .prerelease == false) | .tag_name | select(test("^v0[.][0-9]+[.][0-9]+$"))') || return 1
	version=${version#v}
	[ "$requested" = latest ] || [ "$version" = "$requested" ] || { err "FRP Release 标签与请求版本不符"; return 1; }
	ver_ge "$version" "$TESTED_FRP_VERSION" || return 1
	asset="frp_${version}_linux_${arch}.tar.gz"
	url="https://github.com/fatedier/frp/releases/download/v$version/$asset"
	digest=$(printf '%s' "$json" | jq -er --arg name "$asset" --arg url "$url" '[.assets[] | select(.name == $name and .browser_download_url == $url)] | select(length == 1) | .[0].digest | select(test("^sha256:[0-9a-f]{64}$"))') || { err "FRP 安装包缺少 SHA-256 校验值"; return 1; }
	size=$(printf '%s' "$json" | jq -er --arg name "$asset" '.assets[] | select(.name == $name) | .size | select(type == "number" and . > 0 and . < 268435456 and floor == .)') || return 1
	work=$(mktemp -d) || return 1
	trap 'rm -rf "$work"' EXIT
	http_get "$(gh_url "$url")" "$work/frp.tar.gz" && [ "$(wc -c <"$work/frp.tar.gz")" = "$size" ] &&
		printf '%s  %s\n' "${digest#sha256:}" "$work/frp.tar.gz" | sha256sum -c - >/dev/null || { err "FRP 下载或 SHA-256 校验失败"; return 1; }
	member="frp_${version}_linux_${arch}"
	tar -xOzf "$work/frp.tar.gz" "$member/frps" >"$output" && chmod 755 "$output" && [ "$("$output" -v)" = "$version" ] || return 1
	if [ -n "$client_output" ]; then
		tar -xOzf "$work/frp.tar.gz" "$member/frpc" >"$client_output" && chmod 755 "$client_output" && [ "$("$client_output" -v)" = "$version" ] || return 1
	fi
)

_frps_export() (
	local output=$1 type=$2 local_port=$3 remote_port=$4 subdomain=${5:-www} domain tmp
	_frps_validate && _frps_port_valid "$local_port" && [[ "$FRPS_TOKEN" =~ ^[a-f0-9]{64}$ ]] || return 1
	case "$FRPS_MODE/$type" in web/http | tcp/tcp | tcp/udp) ;; *) err "web 模式只导出 HTTP 域名隧道；tcp 模式只导出公网 TCP/UDP 隧道"; return 1 ;; esac
	if [ "$type" = http ]; then
		[[ "$subdomain" =~ ^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$ ]] || { err "子域名标签无效"; return 1; }
		domain=$FRPS_WEB_DOMAIN
		[ -z "$FRPS_SUBDOMAIN_HOST" ] || domain="$subdomain.$FRPS_SUBDOMAIN_HOST"
	else
		_frps_port_valid "$remote_port" && [ "$remote_port" -ge "$FRPS_RANGE_START" ] && [ "$remote_port" -le "$FRPS_RANGE_END" ] || { err "转发端口不在允许范围内"; return 1; }
	fi
	case "$output" in /*) ;; *) output="$PWD/$output" ;; esac
	_support_path_safe "$output" && [ ! -e "$output" ] || { err "导出目录已存在或含不安全路径"; return 1; }
	umask 077
	mkdir "$output" || return 1
	tmp=$output
	trap '[ -z "$tmp" ] || rm -rf "$tmp"' EXIT
	cp "$FRPS_DIR/ca.pem" "$output/ca.pem" || return 1
	cat >"$output/frpc.toml" <<EOF
serverAddr = "$FRPS_DOMAIN"
serverPort = $FRPS_BIND_PORT
auth.method = "token"
auth.token = "$FRPS_TOKEN"
auth.additionalScopes = ["HeartBeats", "NewWorkConns"]
transport.tls.enable = true
transport.tls.serverName = "$FRPS_DOMAIN"
transport.tls.trustedCaFile = "./ca.pem"
log.to = "console"
log.disablePrintColor = true

[[proxies]]
name = "onebox-$type-${domain:-$remote_port}"
type = "$type"
localIP = "127.0.0.1"
localPort = $local_port
EOF
	if [ "$type" = http ]; then
		if [ -n "$FRPS_SUBDOMAIN_HOST" ]; then printf 'subdomain = "%s"\n' "$subdomain"; else printf 'customDomains = ["%s"]\n' "$domain"; fi >>"$output/frpc.toml"
		printf 'requestHeaders.set."X-Forwarded-Proto" = "https"\n' >>"$output/frpc.toml"
	else printf 'remotePort = %s\n' "$remote_port" >>"$output/frpc.toml"; fi
	printf '此目录含 FRP token，请私密保存。不要复制服务端 CA 私钥。\n在内网机器安装同版本 frpc，将此整个目录复制过去，先 cd 到目录，再运行：\nfrpc verify -c frpc.toml\nfrpc -c frpc.toml\n后端：127.0.0.1:%s\n' "$local_port" >"$output/README.txt"
	if [ "$type" = http ]; then printf '访问：https://%s:%s/\n' "$domain" "$FRPS_HTTPS_PORT"; else printf '访问：%s:%s (%s)\n' "$FRPS_DOMAIN" "$remote_port" "$type"; fi >>"$output/README.txt"
	chmod 600 "$output"/* || return 1
	tmp=""
	info "已导出客户端配置与 CA 到 $output (不包含服务器私钥)"
)

_frps_unit() {
	if [ "$INIT" = systemd ]; then printf '%s/onebox-frp%s.service' "$FRPS_SYSTEMD_DIR" "$([ "$1" = frps ] && echo s || echo -web)";
	else printf '%s/onebox-frp%s' "$INITD_DIR" "$([ "$1" = frps ] && echo s || echo -web)"; fi
}
_frps_name() { if [ "$1" = frps ]; then echo onebox-frps; else echo onebox-frp-web; fi; }
_frps_pid_running() {
	local kind=$1 pid bin
	if [ "$kind" = frps ]; then bin=$FRPS_BIN; pid=$(cat "$FRPS_RUN_DIR/frps.pid" 2>/dev/null); else bin=$(_frps_nginx_bin); pid=$(cat "$FRPS_DIR/nginx.pid" 2>/dev/null); fi
	[[ "$pid" =~ ^[1-9][0-9]*$ ]] && kill -0 "$pid" 2>/dev/null && [ -r "/proc/$pid/cmdline" ] || return 1
	tr '\0' ' ' <"/proc/$pid/cmdline" | grep -qF "$bin" || return 1
	if [ "$kind" = web ]; then tr '\0' ' ' <"/proc/$pid/cmdline" | grep -qF "$FRPS_DIR/nginx.conf"; fi
}
_frps_service_active() {
	case "$INIT" in
	systemd) systemctl is-active --quiet "$(_frps_name "$1")" ;;
	openrc) rc-service "$(_frps_name "$1")" status >/dev/null 2>&1 ;;
	none) _frps_pid_running "$1" ;;
	esac
}
_frps_service_enabled() {
	case "$INIT" in
	systemd) systemctl is-enabled --quiet "$(_frps_name "$1")" ;;
	openrc) rc-update show default 2>/dev/null | grep -qw "$(_frps_name "$1")" ;;
	none) return 1 ;;
	esac
}
_frps_service() {
	local action=$1 kind=$2 name pid i log bin
	name=$(_frps_name "$kind")
	if [ "$action/$kind" = reload/web ]; then
		_frps_web_check && "$(_frps_nginx_bin)" -p "$FRPS_DIR/" -c "$FRPS_DIR/nginx.conf" -s reload 8>&-
		return $?
	fi
	case "$INIT" in
	systemd)
		case "$action" in stop | disable) [ -f "$(_frps_unit "$kind")" ] || return 0 ;; esac
		systemctl "$action" "$name" >/dev/null 2>&1 8>&-
		;;
	openrc)
		case "$action" in
		enable) rc-update add "$name" default >/dev/null 2>&1 ;;
		disable) _frps_service_enabled "$kind" || return 0; rc-update del "$name" default >/dev/null 2>&1 ;;
		stop) _frps_service_active "$kind" || return 0; rc-service "$name" stop >/dev/null 2>&1 ;;
			*) rc-service "$name" "$action" >/dev/null 2>&1 8>&- ;;
		esac
		;;
	none)
		case "$action" in
		enable | disable) return 0 ;;
		restart) _frps_service stop "$kind" && _frps_service start "$kind" ;;
		reload) if [ "$kind" = web ]; then "$(_frps_nginx_bin)" -p "$FRPS_DIR/" -c "$FRPS_DIR/nginx.conf" -s reload; else _frps_service restart frps; fi ;;
		start)
			_frps_pid_running "$kind" && return 0
			mkdir -p "$FRPS_LOG_DIR" "$FRPS_RUN_DIR" && chmod 700 "$FRPS_LOG_DIR" "$FRPS_RUN_DIR" || return 1
			if [ "$kind" = web ]; then "$(_frps_nginx_bin)" -p "$FRPS_DIR/" -c "$FRPS_DIR/nginx.conf" 8>&-; return $?; fi
			log="$FRPS_LOG_DIR/frps.log"; trim_log "$log"
			(exec 8>&-; umask 077; exec nohup "$FRPS_BIN" -c "$FRPS_CONF" >>"$log" 2>&1 </dev/null) &
			printf '%s\n' "$!" >"$FRPS_RUN_DIR/frps.pid"
			;;
		stop)
			_frps_pid_running "$kind" || return 0
			if [ "$kind" = frps ]; then pid=$(cat "$FRPS_RUN_DIR/frps.pid"); else pid=$(cat "$FRPS_DIR/nginx.pid"); fi
			kill "$pid" 2>/dev/null || return 1
			for i in 1 2 3 4 5; do _frps_pid_running "$kind" || break; sleep 1; done
			_frps_pid_running "$kind" && { err "FRP 服务尚未停止，请检查进程 $pid"; return 1; }
			[ "$kind" != frps ] || rm -f "$FRPS_RUN_DIR/frps.pid"
			return 0
			;;
		*) return 1 ;;
		esac
		;;
	*) return 1 ;;
	esac
}
_frps_write_services() {
	local kind name bin args unit
	mkdir -p "$FRPS_LOG_DIR" "$FRPS_RUN_DIR" || return 1
	chmod 700 "$FRPS_LOG_DIR" "$FRPS_RUN_DIR" || return 1
	for kind in frps web; do
		[ "$kind" != web ] || [ "$FRPS_MODE" = web ] || continue
		name=$(_frps_name "$kind"); unit=$(_frps_unit "$kind")
		if [ "$kind" = frps ]; then bin=$FRPS_BIN; args="-c $FRPS_CONF"; else bin=$(_frps_nginx_bin); args="-p $FRPS_DIR/ -c $FRPS_DIR/nginx.conf -g 'daemon off;'"; fi
		[[ "$bin" =~ ^/[A-Za-z0-9_./-]+$ ]] || return 1
		case "$INIT" in
		systemd)
			cat >"$unit" <<UNIT
# Managed by Onebox FRP
[Unit]
Description=Onebox FRP $kind
After=network-online.target
Wants=network-online.target
[Service]
Type=simple
ExecStart=$bin $args
Restart=on-failure
RestartSec=5
NoNewPrivileges=true
PrivateTmp=true
LimitNOFILE=65535
KillMode=mixed
TimeoutStopSec=15
[Install]
WantedBy=multi-user.target
UNIT
			if [ "$kind" = frps ]; then sed -i "/^ExecStart=/i ExecStartPre=$CMD_PATH frps net-apply" "$unit"; fi
			;;
		openrc)
			cat >"$unit" <<UNIT
#!/sbin/openrc-run
# Managed by Onebox FRP
name="$name"
supervisor="supervise-daemon"
command="$bin"
command_args="$args"
output_log="$FRPS_LOG_DIR/$kind.log"
error_log="$FRPS_LOG_DIR/$kind.log"
respawn_delay=5
respawn_max=10
respawn_period=120
depend() { need net; after firewall; }
UNIT
			if [ "$kind" = frps ]; then printf 'start_pre() { "%s" frps net-apply; }\n' "$CMD_PATH" >>"$unit"; fi
			chmod 755 "$unit" || return 1
			;;
		esac
	done
	[ "$INIT" != systemd ] || systemctl daemon-reload
}
_frps_health() {
	local i addr=127.0.0.1 scope=${1:-all}
	[ "$FRPS_BIND_ADDR" != ::1 ] || addr='[::1]'
	for i in 1 2 3 4 5 6 7 8 9 10; do
		if _frps_service_active frps && port_in_use "$FRPS_BIND_PORT" tcp &&
			timeout 4 openssl s_client -connect "$addr:$FRPS_BIND_PORT" -servername "$FRPS_DOMAIN" -verify_hostname "$FRPS_DOMAIN" -CAfile "$FRPS_DIR/ca.pem" -verify_return_error </dev/null >/dev/null 2>&1; then
			if [ "$FRPS_MODE" != web ] || [ "$scope" = frps ]; then return 0; fi
			_frps_service_active web && _frps_web_check && port_in_use "$FRPS_HTTPS_PORT" tcp && return 0
		fi
		sleep 1
	done
	err "FRP 服务启动或 TLS 健康检查失败"
	return 1
}

# Static reservations also protect stopped instances and remote ports that a
# client has not opened yet. Existing proxy/hopping reservations are symmetric.
_frps_reserved() (
	local port=$1 proto=$2
	_frps_load >/dev/null 2>&1 || return 1
	if [ "$proto" != udp ]; then
		[ "$port" = "$FRPS_BIND_PORT" ] && return 0
		if [ "$FRPS_MODE" = web ]; then
			[ "$port" = "$FRPS_HTTP_PORT" ] || [ "$port" = "$FRPS_HTTPS_PORT" ] || [ "$port" = "$FRPS_REDIRECT_PORT" ] && return 0
		fi
	fi
	[ "$FRPS_MODE" = tcp ] && [ "$port" -ge "$FRPS_RANGE_START" ] && [ "$port" -le "$FRPS_RANGE_END" ]
)
_frps_hop_conflict() (
	_frps_load >/dev/null 2>&1 && [ "$FRPS_MODE" = tcp ] || return 1
	_frps_ranges_overlap "$1" "$FRPS_RANGE_START-$FRPS_RANGE_END" || return 1
	printf 'FRP/%s-%s' "$FRPS_RANGE_START" "$FRPS_RANGE_END"
)
_frps_proxy_reservations() (
	[ -f "$STATE_FILE" ] || return 0
	load_state || return 1
	local p port net
	for p in $PROTOCOLS; do port=$(pget PORT "$p"); net=$(proto_net "$p"); printf '%s %s\n' "$port" "$net"; done
	if site_enabled; then printf '80 tcp\n%s tcp\n' "$REALITY_SITE_PORT"; site_https_enabled && echo '443 tcp'; fi
	[ "$TLS_MODE/$ACME_METHOD" != acme/standalone ] || echo '80 tcp'
	[ -z "$REALITY_GUARD_PORT" ] || printf '%s tcp\n' "$REALITY_GUARD_PORT"
	[ -z "$HY2_HOP" ] || printf '%s udp\n' "$HY2_HOP"
	return 0
)
_frps_wanted_ports() {
	printf '%s tcp\n' "$FRPS_BIND_PORT"
	if [ "$FRPS_MODE" = web ]; then
		printf '%s tcp\n%s tcp\n' "$FRPS_HTTP_PORT" "$FRPS_HTTPS_PORT"
		[ "$FRPS_REDIRECT_PORT" = 0 ] || printf '%s tcp\n' "$FRPS_REDIRECT_PORT"
	else printf '%s-%s both\n' "$FRPS_RANGE_START" "$FRPS_RANGE_END"; fi
}
_frps_ranges_overlap() {
	local lo=${1%-*} hi=${1#*-} other_lo=${2%-*} other_hi=${2#*-}
	[[ "$lo$hi$other_lo$other_hi" =~ ^[0-9]+$ ]] && [ "$lo" -le "$other_hi" ] && [ "$other_lo" -le "$hi" ]
}
_frps_check_ports() {
	local requested reserved range proto port other_proto lo hi p
	requested=$(_frps_wanted_ports)
	reserved=$(_frps_proxy_reservations) || { err "无法读取已有代理端口分配，取消 FRP 配置"; return 1; }
	while read -r range proto; do
		while read -r port other_proto; do
			[ -n "$port" ] || continue
			[ "$proto" = both ] || [ "$other_proto" = both ] || [ "$proto" = "$other_proto" ] || continue
			_frps_ranges_overlap "$range" "$port" && { err "FRP $range/$proto 与已有代理/网站/端口跳跃 $port/$other_proto 冲突；请选择其他端口或独立 VPS"; return 1; }
		done <<<"$reserved"
		lo=${range%-*}; hi=${range#*-}
		for ((p=lo; p<=hi; p++)); do
			if { [ "$proto" != udp ] && port_in_use "$p" tcp; } || { [ "$proto" != tcp ] && port_in_use "$p" udp; }; then
				err "FRP 需要的 $p/$proto 已被其他服务占用，未接管该服务"; return 1
			fi
		done
	done <<<"$requested"
}

_frps_cron() {
	local action=$1 current tmp
	has crontab || { [ "$action" = del ] && return 0; err "需要 crontab 安排证书自动续期"; return 1; }
	current=$(_site_read_crontab) || return 1
	tmp=$(mktemp) || return 1
	printf '%s\n' "$current" | sed '/ # onebox-frps-renew$/d; / # onebox-frps-boot$/d' >"$tmp"
	if [ "$action" = add ]; then
		printf '17 3 * * * %s frps renew --cron >>%s/renew.log 2>&1 # onebox-frps-renew\n' "$CMD_PATH" "$FRPS_LOG_DIR" >>"$tmp"
		[ "$INIT" != none ] || printf '@reboot %s frps start >>%s/boot.log 2>&1 # onebox-frps-boot\n' "$CMD_PATH" "$FRPS_LOG_DIR" >>"$tmp"
	fi
	crontab "$tmp"; local rc=$?; rm -f "$tmp"; return "$rc"
}
_frps_snapshot() {
	local backup=$1 path kind index=0
	for path in "$FRPS_DIR" "$FRPS_BIN_DIR" "$FRPS_WEB_VAR"; do
		if [ -e "$path" ]; then cp -a "$path" "$backup/dir-$index" || return 1; fi
		index=$((index + 1))
	done
	for kind in frps web; do
		path=$(_frps_unit "$kind")
		[ ! -f "$path" ] || cp -p "$path" "$backup/unit-$kind" || return 1
		_frps_service_active "$kind" && touch "$backup/active-$kind"
		_frps_service_enabled "$kind" && touch "$backup/enabled-$kind"
	done
	if has crontab; then _site_read_crontab >"$backup/cron" || return 1; fi
	touch "$backup/complete"
}
_frps_rollback() {
	local backup=$1 path kind index=0 failed=0
	[ -f "$backup/complete" ] || return 1
	_frps_service stop web || failed=1
	_frps_service stop frps || failed=1
	[ "$failed" = 0 ] || { err "FRP 新服务未停止，拒绝覆盖运行文件；备份保留在 $backup"; return 1; }
	_frps_fw_close_all || failed=1
	# Do not lose a cleanup ledger when firewall restoration needs a retry.
	[ "$failed" = 0 ] || { err "FRP 防火墙清理失败，保留配置与备份 $backup"; return 1; }
	for kind in frps web; do _frps_service disable "$kind" || failed=1; done
	for path in "$FRPS_DIR" "$FRPS_BIN_DIR" "$FRPS_WEB_VAR"; do
		rm -rf "$path" || failed=1
		[ ! -d "$backup/dir-$index" ] || cp -a "$backup/dir-$index" "$path" || failed=1
		index=$((index + 1))
	done
	for kind in frps web; do
		path=$(_frps_unit "$kind")
		if [ -f "$backup/unit-$kind" ]; then cp -p "$backup/unit-$kind" "$path" || failed=1; else rm -f "$path" || failed=1; fi
	done
	[ "$INIT" != systemd ] || systemctl daemon-reload || failed=1
	[ ! -f "$backup/cron" ] || crontab "$backup/cron" || failed=1
	if _frps_installed; then
		_frps_load && _frps_fw_apply open || failed=1
		for kind in frps web; do
			[ ! -f "$backup/enabled-$kind" ] || _frps_service enable "$kind" || failed=1
			[ ! -f "$backup/active-$kind" ] || _frps_service start "$kind" || failed=1
		done
	fi
	[ "$failed" = 0 ] || { err "FRP 恢复未完成，请保留 $backup 并检查服务/防火墙"; return 1; }
}
_frps_mutation_cleanup() {
	local rc=$1
	trap - EXIT INT TERM HUP
	if [ "${FRPS_TXN_OK:-0}" != 1 ]; then
		_frps_rollback "$FRPS_BACKUP" || return 1
		warn "FRP 操作失败，已恢复旧配置和服务状态"
	fi
	rm -rf "$FRPS_BACKUP"
	return "$rc"
}
_frps_begin() {
	local path kind
	_frps_lock || return 1
	for path in "$FRPS_DIR" "$FRPS_BIN_DIR" "$FRPS_WEB_VAR"; do
		if [ -e "$path" ] && [ ! -f "$path/.managed" ]; then err "FRP 路径已有非本脚本文件，拒绝接管: $path"; return 1; fi
	done
	for kind in frps web; do
		path=$(_frps_unit "$kind")
		[ ! -e "$path" ] || { [ -f "$path" ] && [ ! -L "$path" ] && grep -qF '# Managed by Onebox FRP' "$path"; } || { err "拒绝接管现有 FRP 服务: $path"; return 1; }
	done
	mkdir -p "$(dirname "$FRPS_DIR")" || return 1
	FRPS_BACKUP=$(mktemp -d "$(dirname "$FRPS_DIR")/.onebox-frps-backup.XXXXXX") || return 1
	chmod 700 "$FRPS_BACKUP" || return 1
	_frps_snapshot "$FRPS_BACKUP" || { rm -rf "$FRPS_BACKUP"; return 1; }
	FRPS_TXN_OK=0
	trap '_frps_mutation_cleanup $?; exit $?' EXIT
	trap 'exit 130' INT
	trap 'exit 143' TERM HUP
}
_frps_make_dirs() {
	local path
	for path in "$FRPS_DIR" "$FRPS_BIN_DIR" "$FRPS_WEB_VAR"; do
		mkdir -p "$path" && chmod 700 "$path" && touch "$path/.managed" || return 1
	done
	mkdir -p "$FRPS_LOG_DIR" "$FRPS_RUN_DIR" && chmod 700 "$FRPS_LOG_DIR" "$FRPS_RUN_DIR"
}
_frps_ensure_manager() {
	install_self || return 1
	[ -x "$CMD_PATH" ] && grep -qF '# BEGIN embedded-frps' "$CMD_PATH" || { err "FRP 需要可用的 onebox 管理命令以启停和续期，请先保存最新版脚本后执行"; return 1; }
}

_frps_apply() (
	local rotate=${1:-0} staged
	_frps_validate || return 1
	init_env
	for staged in curl jq openssl tar timeout flock crontab sha256sum ip; do ensure_cmds "$staged" || return 1; done
	_frps_check_dns || return 1
	confirm "部署 FRP $FRPS_MODE 模式？只管理 FRP 自身服务、证书及端口" n || return 1
	_frps_begin || return 1
	_frps_make_dirs || return 1
	_frps_ensure_manager || return 1
	# Download/validate new binary before stopping the running instance.
	staged="$FRPS_BACKUP/new-frps"
	_frps_download "$staged" || return 1
	FRPS_VERSION=$("$staged" -v) || return 1
	_frps_service stop web && _frps_service stop frps || return 1
	_frps_check_ports || return 1
	_frps_fw_close_all || return 1
	[ "$rotate" != 1 ] && [ -n "$FRPS_TOKEN" ] || FRPS_TOKEN=$(rand_hex 32)
	_frps_control_certificate || return 1
	cp "$staged" "$FRPS_BIN" && chmod 755 "$FRPS_BIN" || return 1
	_frps_render && "$FRPS_BIN" verify -c "$FRPS_CONF" >/dev/null || { err "frps 配置校验失败"; return 1; }
	_frps_save || return 1
	if [ "$FRPS_MODE" = web ]; then site_install_nginx || return 1; fi
	_frps_write_services && _frps_fw_apply open || return 1
	if [ "$FRPS_MODE/$FRPS_TLS_METHOD" = web/http ]; then
		_frps_web_render 1 && _frps_service start web || return 1
	fi
	_frps_web_certificate || return 1
	if [ "$FRPS_MODE" = web ]; then
		_frps_service stop web && _frps_web_render 0 && _frps_service start web && _frps_service enable web || return 1
	else
		_frps_service disable web || return 1
		rm -f "$(_frps_unit web)"
		[ "$INIT" != systemd ] || systemctl daemon-reload || return 1
	fi
	_frps_service start frps && _frps_service enable frps && _frps_health && _frps_cron add || return 1
	_site_scheduler_ready || { err "FRP 需要运行中的 cron 服务执行证书检查"; return 1; }
	FRPS_TXN_OK=1
	info "FRP 已部署：$FRPS_MODE / v$FRPS_VERSION；请导出客户端配置并在内网机器运行 frpc"
	_frps_dns_info
)

_frps_renew() (
	local mode=${1:-manual} frps_active=0 web_active=0
	_frps_load && _frps_begin || return 1
	_frps_service_active frps && frps_active=1
	_frps_service_active web && web_active=1
	trim_log "$FRPS_LOG_DIR/renew.log"
	_frps_control_certificate || return 1
	if [ "$FRPS_MODE" = web ] && [ "$FRPS_TLS_METHOD" != custom ]; then
		if [ "$FRPS_TLS_METHOD" != http ] || [ "$web_active" = 1 ]; then
			_frps_web_renew "$mode" && _frps_web_check || return 1
		else warn "FRP 网站已停止，本次跳过需要 HTTP 入口的续期"; fi
	fi
	if [ "$web_active" = 1 ] && ! cmp -s "$FRPS_BACKUP/dir-0/web-cert.pem" "$FRPS_DIR/web-cert.pem"; then _frps_service reload web || return 1; fi
	if [ "$frps_active" = 1 ] && ! cmp -s "$FRPS_BACKUP/dir-0/server-cert.pem" "$FRPS_DIR/server-cert.pem"; then
		_frps_service restart frps && _frps_health frps || return 1
	fi
	FRPS_TXN_OK=1
	[ "$mode" = --cron ] || info "FRP 证书检查/续期完成 (私有 CA 保持不变)"
)
_frps_uninstall() (
	_frps_load || { err "未安装托管 FRP"; return 1; }
	confirm "卸载 FRP 服务、独立配置和证书？原有代理和网站保留" n || return 1
	_frps_begin || return 1
	_frps_service stop web && _frps_service stop frps && _frps_fw_close_all && _frps_cron del || return 1
	_frps_service disable web && _frps_service disable frps || return 1
	rm -f "$(_frps_unit web)" "$(_frps_unit frps)" || return 1
	[ "$INIT" != systemd ] || systemctl daemon-reload || return 1
	rm -rf "$FRPS_DIR" "$FRPS_BIN_DIR" "$FRPS_WEB_VAR" "$FRPS_RUN_DIR" "$FRPS_LOG_DIR" || return 1
	FRPS_TXN_OK=1
	info "FRP 已卸载；已导出的客户端 token/配置不再有效"
)

_frps_parse() {
	FRPS_DRY_RUN=0
	while [ $# -gt 0 ]; do
		case "$1" in
		--dry-run) FRPS_DRY_RUN=1; shift; continue ;;
		--mode | --domain | --port | --http-port | --https-port | --redirect-port | --web-domain | --subdomain-host | --allow-ports | --tls | --cert | --key | --version)
			[ $# -ge 2 ] && [ -n "$2" ] || { err "$1 缺少值"; return 1; }
			case "$1" in
			--mode) FRPS_MODE=$2 ;; --domain) FRPS_DOMAIN=${2,,} ;; --port) FRPS_BIND_PORT=$2 ;;
			--http-port) FRPS_HTTP_PORT=$2 ;; --https-port) FRPS_HTTPS_PORT=$2 ;; --redirect-port) FRPS_REDIRECT_PORT=$2 ;;
			--web-domain) FRPS_WEB_DOMAIN=${2,,}; FRPS_SUBDOMAIN_HOST="" ;;
			--subdomain-host) FRPS_SUBDOMAIN_HOST=${2,,}; FRPS_WEB_DOMAIN="" ;;
			--allow-ports) [[ "$2" =~ ^[1-9][0-9]{0,4}-[1-9][0-9]{0,4}$ ]] || { err '--allow-ports 格式为 20000-20100'; return 1; }; FRPS_RANGE_START=${2%-*}; FRPS_RANGE_END=${2#*-} ;;
			--tls) FRPS_TLS_METHOD=$2 ;; --cert) FRPS_CERT_INPUT=$2 ;; --key) FRPS_KEY_INPUT=$2 ;; --version) FRPS_VERSION=${2#v} ;;
			esac
			shift 2 ;;
		*) err "未知 FRP 选项: $1"; return 1 ;;
		esac
	done
}
_frps_wizard() {
	local n
	ask n '用途: 1=域名 HTTPS 网站，2=公网 TCP/UDP 转发' "$([ "$FRPS_MODE" = tcp ] && echo 2 || echo 1)"
	case "$n" in 1) FRPS_MODE=web ;; 2) FRPS_MODE=tcp ;; *) return 1 ;; esac
	ask_domain FRPS_DOMAIN 'FRP 控制域名 (DNS 直连 VPS)' "$FRPS_DOMAIN"
	ask_num FRPS_BIND_PORT 'frpc 控制连接端口' "$FRPS_BIND_PORT" 1024 65535 || return 1
	if [ "$FRPS_MODE" = web ]; then
		ask n '应用域名: 1=单域名，2=泛域名' "$([ -n "$FRPS_SUBDOMAIN_HOST" ] && echo 2 || echo 1)"
		case "$n" in
		1) FRPS_SUBDOMAIN_HOST=""; ask_domain FRPS_WEB_DOMAIN '应用域名 (例如 app.example.com)' "$FRPS_WEB_DOMAIN" ;;
		2) FRPS_WEB_DOMAIN=""; ask_domain FRPS_SUBDOMAIN_HOST '泛域名根 (例如 apps.example.com，DNS 配置 *.apps.example.com)' "$FRPS_SUBDOMAIN_HOST" ;;
		*) return 1 ;;
		esac
		ask_num FRPS_HTTP_PORT 'frps 内部 HTTP 端口 (仅回环监听)' "$FRPS_HTTP_PORT" 1024 65535 || return 1
		ask_num FRPS_HTTPS_PORT '公网 HTTPS 端口 (443 被 REALITY/网站占用时可选 8443)' "$FRPS_HTTPS_PORT" 1 65535 || return 1
		ask FRPS_TLS_METHOD '网站证书: http / cf / custom (泛域名仅 cf/custom)' "$FRPS_TLS_METHOD"
		ask_num FRPS_REDIRECT_PORT 'HTTP 跳转入口 (HTTP验证须80；cf/custom可填0关闭)' "$FRPS_REDIRECT_PORT" 0 65535 || return 1
		if [ "$FRPS_TLS_METHOD" = custom ]; then ask FRPS_CERT_INPUT '完整证书链文件路径' "$FRPS_CERT_INPUT"; ask FRPS_KEY_INPUT '私钥文件路径' "$FRPS_KEY_INPUT"; fi
	else
		ask_num FRPS_RANGE_START '允许的公网转发端口起点' "$FRPS_RANGE_START" 1024 65535 || return 1
		ask_num FRPS_RANGE_END '允许的公网转发端口终点 (最多1000个)' "$FRPS_RANGE_END" "$FRPS_RANGE_START" 65535 || return 1
	fi
	_frps_validate
}
_frps_info() {
	_frps_load || { info '未安装 FRP；onebox frps install 可独立安装'; return 0; }
	printf 'FRP v%s / %s 模式\n控制入口: %s:%s (TLS + 私有 CA + token)\n' "$FRPS_VERSION" "$FRPS_MODE" "$FRPS_DOMAIN" "$FRPS_BIND_PORT"
	printf 'frps: %s\n' "$(_frps_service_active frps && echo 运行中 || echo 已停止)"
	if [ "$FRPS_MODE" = web ]; then
		printf '网站: %s；内部 HTTP: 127.0.0.1:%s\n' "$(_frps_service_active web && echo 运行中 || echo 已停止)" "$FRPS_HTTP_PORT"
		printf '网站证书: '; openssl x509 -in "$FRPS_DIR/web-cert.pem" -noout -enddate 2>/dev/null || true
	else printf '公网 TCP/UDP 转发范围: %s-%s\n' "$FRPS_RANGE_START" "$FRPS_RANGE_END"; fi
	printf '控制证书: '; openssl x509 -in "$FRPS_DIR/server-cert.pem" -noout -enddate 2>/dev/null || true
	printf '配置: %s\n凭据隐藏；用 onebox frps client 目录 导出客户端。Dashboard 默认关闭。\n' "$FRPS_CONF"
	_frps_dns_info
}
_frps_plan() {
	_frps_validate || return 1
	printf 'FRP 预览 (未联网、未安装、未修改配置)\n模式: %s；版本: %s\n' "$FRPS_MODE" "$FRPS_VERSION"
	_frps_dns_info
	printf '计划端口 (现有站点/代理或其他进程占用时将拒绝部署):\n'
	_frps_wanted_ports
	printf '配置/二进制: %s / %s\n' "$FRPS_DIR" "$FRPS_BIN_DIR"
	if [ "$FRPS_MODE" = web ]; then printf '独立 Nginx + %s 网站证书；frps 转发端口只绑定回环地址。\n' "$FRPS_TLS_METHOD"; fi
	printf '控制 TLS 由独立私有 CA 签名；客户端必须携带导出的 ca.pem。\n'
}
_frps_client_cli() {
	local output=${1:-} type local_port=8080 remote_port=$FRPS_RANGE_START name=www
	[ -n "$output" ] || { err '用法: onebox frps client 新目录 [--type http|tcp|udp --local-port N --remote-port N --subdomain 标签]'; return 1; }
	shift
	if [ "$FRPS_MODE" = web ]; then type=http; else type=tcp; fi
	while [ $# -gt 0 ]; do
		[ $# -ge 2 ] || return 1
		case "$1" in --type) type=$2 ;; --local-port) local_port=$2 ;; --remote-port) remote_port=$2 ;; --subdomain) name=$2 ;; *) err "未知导出选项: $1"; return 1 ;; esac
		shift 2
	done
	_frps_export "$output" "$type" "$local_port" "$remote_port" "$name"
}
_frps_menu() {
	local choice dir
	is_interactive || { _frps_info; return; }
	while :; do
		title 'FRP 服务端 / 域名管理'
		printf '1) 安装 / 重新配置\n2) 状态与 DNS 说明\n3) 导出客户端配置\n4) 启动\n5) 停止\n6) 重启\n7) 更新 frps\n8) 检查/续期证书\n9) 轮换 token\n10) 日志\n11) 卸载 FRP\n0) 返回\n'
		ask choice '请选择' 0
		case "$choice" in
		0) return 0 ;;
		1) (do_frps install) ;; 2) _frps_info ;;
		3) ask dir '新的客户端导出目录' /root/frpc-client; (do_frps client "$dir") ;;
		4) (do_frps start) ;; 5) (do_frps stop) ;; 6) (do_frps restart) ;;
		7) (do_frps update) ;; 8) (do_frps renew) ;; 9) (do_frps rotate-token) ;;
		10) (do_frps log) ;; 11) (do_frps uninstall) ;; *) warn '无效选项' ;;
		esac
	done
}

do_frps() (
	local action=${1:-menu}
	[ $# = 0 ] || shift
	setup_tty; detect_os; detect_init
	case "$action" in
	plan | install | configure)
		if _frps_installed; then _frps_load || return 1; else _frps_defaults; fi
		_frps_parse "$@" || return 1
		if [ "$action" != plan ] && [ "$FRPS_DRY_RUN" = 0 ] && [ $# = 0 ] && is_interactive; then _frps_wizard || return 1; fi
		if [ "$action" = plan ] || [ "$FRPS_DRY_RUN" = 1 ]; then _frps_plan; else _frps_apply; fi
		return $?
		;;
	help | --help)
		printf 'onebox frps [plan|install|configure|info|status|start|stop|restart|update [版本]|renew|rotate-token|client 新目录|log|uninstall]\n配置参数: --mode web|tcp --domain 控制域名 --web-domain 应用域名 / --subdomain-host 泛域名根\n--port 7000 --http-port 7080 --https-port 443 --redirect-port 80 --allow-ports 20000-20100\n--tls http|cf|custom --cert 完整链 --key 私钥 --version %s|latest --dry-run\n' "$TESTED_FRP_VERSION"
		return 0 ;;
	esac
	require_root
	case "$action" in
	menu) [ $# = 0 ] && _frps_menu ;;
	info | status) [ $# = 0 ] && _frps_info ;;
	*)
		_frps_load || { err '尚未安装 FRP 或配置无效'; return 1; }
		case "$action" in
		# Invoked by the service manager while the parent apply holds the lock.
		net-apply) [ $# = 0 ] && _frps_fw_apply open ;;
		client) _frps_client_cli "$@" ;;
		update) [ $# -le 1 ] || return 1; FRPS_VERSION=${1:-latest}; FRPS_VERSION=${FRPS_VERSION#v}; _frps_apply ;;
		rotate-token) [ $# = 0 ] && _frps_apply 1 ;;
		renew) [ $# = 0 ] || { [ $# = 1 ] && [ "$1" = --cron ]; } || return 1; _frps_renew "${1:-manual}" ;;
		uninstall) [ $# = 0 ] && _frps_uninstall ;;
		start | stop | restart)
			[ $# = 0 ] && _frps_lock || return 1
			if [ "$action" != start ]; then _frps_service stop web && _frps_service stop frps || return 1; fi
			if [ "$action" != stop ]; then
				_frps_fw_apply open || return 1
				[ "$FRPS_MODE" != web ] || _frps_service start web || return 1
				_frps_service start frps && _frps_health || return 1
			fi
			;;
		log)
			[ $# = 0 ] || return 1
			if [ "$INIT" = systemd ]; then journalctl -u onebox-frps -u onebox-frp-web -n 80 --no-pager;
			else tail -n 80 "$FRPS_LOG_DIR/frps.log" "$FRPS_DIR/nginx-error.log" 2>/dev/null; fi
			;;
		*) err "未知 FRP 命令: $action；查看 onebox frps help"; return 1 ;;
		esac
		;;
	esac
)
