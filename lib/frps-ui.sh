# FRP interactive flows. No mutations until the reviewed deployment is accepted.

_frps_ui_read() {
	local _fui_target=$1 _fui_prompt=$2 _fui_default=${3-} _fui_value
	if [ "${4:-}" = secret ]; then ask_secret _fui_value "$_fui_prompt" || return 130;
	else ask _fui_value "$_fui_prompt" "$_fui_default" || return 130; fi
	case "$_fui_value" in q | Q) return 125 ;; b | B) return 126 ;; esac
	printf -v "$_fui_target" '%s' "$_fui_value"
}
_frps_ui_choice() {
	local _fuc_target=$1 _fuc_prompt=$2 _fuc_default=$3 _fuc_pattern=$4 _fuc_value
	while :; do
		_frps_ui_read _fuc_value "$_fuc_prompt" "$_fuc_default" || return $?
		if [[ "$_fuc_value" =~ $_fuc_pattern ]]; then printf -v "$_fuc_target" '%s' "$_fuc_value"; return 0; fi
		warn '请选择列出的选项；b 返回上一步，q 取消'
		is_interactive || return 1
	done
}
_frps_ui_number() {
	local _fun_target=$1 _fun_prompt=$2 _fun_default=$3 _fun_min=$4 _fun_max=$5 _fun_value
	while :; do
		_frps_ui_read _fun_value "$_fun_prompt" "$_fun_default" || return $?
		if [[ "$_fun_value" =~ ^[0-9]{1,6}$ ]] && [ "$((10#$_fun_value))" -ge "$_fun_min" ] && [ "$((10#$_fun_value))" -le "$_fun_max" ]; then
			printf -v "$_fun_target" '%s' "$((10#$_fun_value))"; return 0
		fi
		warn "请输入 $_fun_min–$_fun_max 之间的整数"
		is_interactive || return 1
	done
}
_frps_ui_domain() {
	local _fud_target=$1 _fud_prompt=$2 _fud_default=$3 _fud_value
	while :; do
		_frps_ui_read _fud_value "$_fud_prompt" "$_fud_default" || return $?
		_fud_value=${_fud_value,,}; _fud_value=${_fud_value#https://}; _fud_value=${_fud_value#http://}
		_fud_value=${_fud_value%%/*}; _fud_value=${_fud_value%.}
		[ "${4:-}" != wildcard ] || _fud_value=${_fud_value#\*.}
		if valid_domain "$_fud_value" && [ "${#_fud_value}" -le 253 ]; then printf -v "$_fud_target" '%s' "$_fud_value"; return 0; fi
		warn '请输入完整域名，例如 app.example.com；不包含端口'
		is_interactive || return 1
	done
}

_frps_ui_prepare_ports() {
	FRPS_UI_PROXY_PORTS=$(_frps_proxy_reservations) || { err '无法读取已有代理端口，请先检查原配置'; return 1; }
	FRPS_UI_OWNED_PORTS=$(
		_frps_load >/dev/null 2>&1 || exit 0
		if _frps_service_active frps; then
			printf '%s tcp\n' "$FRPS_BIND_PORT"
			if [ "$FRPS_MODE" = web ]; then printf '%s tcp\n' "$FRPS_HTTP_PORT"; else printf '%s-%s both\n' "$FRPS_RANGE_START" "$FRPS_RANGE_END"; fi
		fi
		if [ "$FRPS_MODE" = web ] && _frps_service_active web; then
			printf '%s tcp\n' "$FRPS_HTTPS_PORT"
			[ "$FRPS_REDIRECT_PORT" = 0 ] || printf '%s tcp\n' "$FRPS_REDIRECT_PORT"
		fi
		:
	) || return 1
}
_frps_ui_port_available() {
	local port=$1 proto=$2 range other net owned
	for net in tcp udp; do
		[ "$proto" = both ] || [ "$proto" = "$net" ] || continue
		while read -r range other; do
			[ -n "$range" ] && { [ "$other" = both ] || [ "$other" = "$net" ]; } || continue
			_frps_ranges_overlap "$port" "$range" && return 1
		done <<<"${FRPS_UI_PROXY_PORTS:-}"
		port_in_use "$port" "$net" || continue
		owned=0
		while read -r range other; do
			[ -n "$range" ] && { [ "$other" = both ] || [ "$other" = "$net" ]; } || continue
			_frps_ranges_overlap "$port" "$range" && owned=1
		done <<<"${FRPS_UI_OWNED_PORTS:-}"
		[ "$owned" = 1 ] || return 1
	done
}
_frps_ui_port() {
	local _fup_target=$1 _fup_prompt=$2 _fup_default=$3 _fup_min=${4:-1} _fup_value
	while :; do
		_frps_ui_number _fup_value "$_fup_prompt" "$_fup_default" "$_fup_min" 65535 || return $?
		if [ "$_fup_value" = 0 ] || _frps_ui_port_available "$_fup_value" tcp; then printf -v "$_fup_target" '%s' "$_fup_value"; return 0; fi
		warn "TCP $_fup_value 已被其他服务占用或预留，请更换端口"
		is_interactive || return 1
	done
}
_frps_ui_suggest_port() {
	local candidate
	for candidate in "$@"; do _frps_ui_port_available "$candidate" tcp && { printf '%s' "$candidate"; return 0; }; done
	printf '%s' "$1"
}
_frps_ui_check_ports() {
	local range proto port end
	_frps_ui_prepare_ports || return 1
	while read -r range proto; do
		port=${range%-*}; end=${range#*-}
		while [ "$port" -le "$end" ]; do
			_frps_ui_port_available "$port" "$proto" || { err "$port/$proto 已被其他服务占用或预留；请调整端口后重试"; return 1; }
			port=$((port + 1))
		done
	done < <(_frps_wanted_ports)
}

# Inspect credential presence only. Never source or print an ACME account file.
_frps_ui_saved_cf() {
	local file primary
	primary=$(_frps_web_cert_names | head -n1)
	# dns_cf stores zone-scoped credentials in the current domain's config.
	for file in "$FRPS_DIR/acme/account.conf" "$FRPS_DIR/acme/${primary}_ecc/$primary.conf"; do
		[ -r "$file" ] || continue
		if grep -qE "^(SAVED_)?CF_Token=['\"][^'\"]+['\"]$" "$file" || {
			grep -qE "^(SAVED_)?CF_Key=['\"][^'\"]+['\"]$" "$file" && grep -qE "^(SAVED_)?CF_Email=['\"][^'\"]+['\"]$" "$file"
		}; then return 0; fi
	done
	return 1
}
_frps_ui_cf_credentials() {
	local choice token id
	if [ -n "${CF_Token:-}" ] || { [ -n "${CF_Key:-}" ] && [ -n "${CF_Email:-}" ]; }; then
		info '使用本次环境中提供的 Cloudflare 凭据（内容隐藏）'; return 0
	fi
	if _frps_ui_saved_cf; then
		_frps_ui_choice choice 'Cloudflare 已保存凭据：1 继续使用 / 2 更换 Token' 1 '^[12]$' || return $?
		[ "$choice" != 1 ] || return 0
	fi
	info 'Token 需要目标域名的 Zone DNS 编辑与 Zone 读取权限；输入不回显，凭据仅由 ACME 保存用于续期。'
	while :; do
		_frps_ui_read token 'Cloudflare API Token（b 返回，q 取消）' '' secret || return $?
		[ -n "$token" ] && break
		warn 'Token 不能为空'
		is_interactive || return 1
	done
	_frps_ui_choice choice '1 自动查找域名区域 / 2 指定 Zone ID 与 Account ID' 1 '^[12]$' || return $?
	if [ "$choice" = 2 ]; then
		_frps_ui_read id 'Zone ID（可留空）' "${CF_Zone_ID:-}" || return $?
		CF_Zone_ID=$id
		_frps_ui_read id 'Account ID（可留空）' "${CF_Account_ID:-}" || return $?
		CF_Account_ID=$id
	fi
	CF_Token=$token
	export CF_Token CF_Zone_ID CF_Account_ID
}

_frps_wizard_step() {
	local step=$1 choice preferred port
	case "$step" in
	1)
		_frps_ui_choice choice '用途：1 域名 HTTPS 网站 / 2 公网 TCP、UDP 转发' "$([ "$FRPS_MODE" = tcp ] && echo 2 || echo 1)" '^[12]$' || return $?
		if [ "$choice" = 1 ]; then FRPS_MODE=web; else FRPS_MODE=tcp; fi ;;
	2)
		_frps_ui_domain FRPS_DOMAIN '控制域名（frpc 连接的地址，DNS 直连 VPS）' "$FRPS_DOMAIN" || return $?
		[ "$FRPS_MODE" = web ] || return 0
		_frps_ui_choice choice '应用域名：1 单域名 / 2 泛域名（多个内网网站）' "$([ -n "$FRPS_SUBDOMAIN_HOST" ] && echo 2 || echo 1)" '^[12]$' || return $?
		if [ "$choice" = 1 ]; then
			_frps_ui_domain FRPS_WEB_DOMAIN '浏览器访问域名' "$FRPS_WEB_DOMAIN" || return $?
			FRPS_SUBDOMAIN_HOST=''
		else
			_frps_ui_domain FRPS_SUBDOMAIN_HOST '泛域名根（例如 apps.example.com，可输入 *.apps.example.com）' "$FRPS_SUBDOMAIN_HOST" wildcard || return $?
			FRPS_WEB_DOMAIN=''
			[ "$FRPS_TLS_METHOD" != http ] || FRPS_TLS_METHOD=cf
			info '泛域名证书使用 Cloudflare DNS 验证或自备证书。'
		fi ;;
	3)
		preferred=$(_frps_ui_suggest_port "$FRPS_BIND_PORT" 7001 7002)
		_frps_ui_port FRPS_BIND_PORT 'frpc 控制连接端口' "$preferred" || return $?
		if [ "$FRPS_MODE" = web ]; then
			preferred=$(_frps_ui_suggest_port "$FRPS_HTTPS_PORT" 8443 9443)
			[ "$preferred" = "$FRPS_HTTPS_PORT" ] || info "原 HTTPS 端口不可用，建议 $preferred；浏览器地址需带此端口。"
			_frps_ui_port FRPS_HTTPS_PORT '公网 HTTPS 端口' "$preferred" || return $?
		else
			while :; do
				_frps_ui_number FRPS_RANGE_START '允许转发的端口起点' "$FRPS_RANGE_START" 1 65535 || return $?
				_frps_ui_number FRPS_RANGE_END '允许转发的端口终点（最多 1000 个）' "$FRPS_RANGE_END" "$FRPS_RANGE_START" 65535 || return $?
				[ "$((FRPS_RANGE_END - FRPS_RANGE_START))" -le 999 ] && break
				warn '范围最多包含 1000 个端口，请重新填写'
			done
		fi ;;
	4)
		[ "$FRPS_MODE" = web ] || { info 'TCP/UDP 模式使用私有 CA 控制证书，无需网站证书。'; return 0; }
		case "$FRPS_TLS_METHOD" in http) preferred=1 ;; cf) preferred=2 ;; *) preferred=3 ;; esac
		if [ -n "$FRPS_SUBDOMAIN_HOST" ] || ! _frps_ui_port_available 80 tcp; then
			[ "$preferred" != 1 ] || preferred=2
			info 'HTTP 验证当前不可用（泛域名或 TCP 80 已被占用），请选择 DNS 验证或自备证书。'
		fi
		while :; do
			_frps_ui_choice choice '网站证书：1 HTTP 自动签发 / 2 Cloudflare DNS 自动签发 / 3 自备证书' "$preferred" '^[123]$' || return $?
			[ "$choice" != 1 ] || { [ -z "$FRPS_SUBDOMAIN_HOST" ] && _frps_ui_port_available 80 tcp; } && break
			warn 'HTTP-01 需要单域名和可用的 TCP 80，请选择 2 或 3'
		done
		case "$choice" in
		1) FRPS_TLS_METHOD=http; FRPS_REDIRECT_PORT=80; info 'HTTP 入口固定为 80，用于验证、续期和跳转 HTTPS。' ;;
		2) FRPS_TLS_METHOD=cf; _frps_ui_cf_credentials || return $? ;;
		3)
			FRPS_TLS_METHOD=custom
			while :; do
				_frps_ui_read FRPS_CERT_INPUT '完整证书链文件路径' "$FRPS_CERT_INPUT" || return $?
				_frps_ui_read FRPS_KEY_INPUT '未加密私钥文件路径' "$FRPS_KEY_INPUT" || return $?
				if [ -s "$FRPS_CERT_INPUT" ] && [ -s "$FRPS_KEY_INPUT" ]; then
					if ! has openssl || _frps_web_cert_validate "$FRPS_CERT_INPUT" "$FRPS_KEY_INPUT"; then break; fi
				else warn '证书或私钥文件不存在/为空，请重新选择'; fi
			done ;;
		esac
		if [ "$FRPS_TLS_METHOD" != http ]; then
			port=$FRPS_REDIRECT_PORT
			[ "$port" = 0 ] || _frps_ui_port_available "$port" tcp || port=0
			_frps_ui_port FRPS_REDIRECT_PORT 'HTTP 跳转端口（0 关闭，不影响 DNS 验证）' "$port" 0 || return $?
		fi ;;
	5)
		preferred=1
		if [ "$FRPS_MODE" = web ]; then
			printf '内部 HTTP 端口: %s（仅回环）\n' "$FRPS_HTTP_PORT"
			_frps_ui_port_available "$FRPS_HTTP_PORT" tcp || preferred=2
		fi
		printf 'FRP 版本: %s\n' "$FRPS_VERSION"
		_frps_ui_choice choice '高级设置：1 保留当前值 / 2 修改' "$preferred" '^[12]$' || return $?
		if [ "$choice" = 2 ]; then
			if [ "$FRPS_MODE" = web ]; then
				preferred=$(_frps_ui_suggest_port "$FRPS_HTTP_PORT" 7081 7082)
				_frps_ui_port FRPS_HTTP_PORT '内部 HTTP 端口' "$preferred" || return $?
			fi
			while :; do
				_frps_ui_read FRPS_VERSION "FRP 版本（$TESTED_FRP_VERSION 或更新版本，也可 latest）" "$FRPS_VERSION" || return $?
				FRPS_VERSION=${FRPS_VERSION#v}
				if [ "$FRPS_VERSION" = latest ] || { [[ "$FRPS_VERSION" =~ ^0\.[0-9]+\.[0-9]+$ ]] && ver_ge "$FRPS_VERSION" "$TESTED_FRP_VERSION"; }; then break; fi
				warn "版本格式无效或早于 $TESTED_FRP_VERSION，请重新填写"
			done
		fi ;;
	esac
}
_frps_wizard() {
	local step=1 rc labels=('用途' '域名' '公网端口' '网站证书' '高级设置')
	_frps_ui_prepare_ports || return 1
	info '回车保留默认值；b 返回上一步；q 取消。本向导只收集配置，最后确认后才部署。'
	while :; do
		title "FRP 配置 $step/5 · ${labels[step-1]}"
		_frps_wizard_step "$step"; rc=$?
		case "$rc" in
		0)
			if [ "$step" = 5 ]; then
				if _frps_validate && _frps_ui_check_ports; then return 0; fi
				warn '配置尚未通过检查，返回端口步骤；可用 b 调整前面的设置。'; step=3
			elif [ "$step/$FRPS_MODE" = 3/tcp ]; then step=5;
			else step=$((step + 1)); fi ;;
		126)
			if [ "$step/$FRPS_MODE" = 5/tcp ]; then step=3;
			elif [ "$step" != 1 ]; then step=$((step - 1)); fi ;;
		125) info '已取消 FRP 配置'; return 125 ;;
		*) return "$rc" ;;
		esac
	done
}

_frps_review() {
	local choice
	title '确认 FRP 部署'
	_frps_summary
	if _frps_installed; then
		info '将更新已有 FRP，保留私有 CA；部署时会短暂中断隧道。'
		info '控制域名、端口或模式改变后，请重新导出客户端配置。'
	fi
	if [ "${1:-0}" = 1 ]; then warn '即将轮换 token：旧客户端会失效，完成后必须重新导出并替换配置。'; fi
	if [ "${FRPS_UI_WIZARD:-0}" = 1 ] && is_interactive; then
		_frps_ui_choice choice '1 确认部署 / 2 返回修改 / 0 取消' 0 '^[012]$' || return $?
		case "$choice" in 1) return 0 ;; 2) return 126 ;; *) return 125 ;; esac
	fi
	confirm '按上述配置部署 FRP？' n || return 125
}
_frps_next_steps() {
	printf '\n下一步：onebox frps client  可交互选择内网端口并导出配置。\n'
	printf '在内网机器安装同版本 frpc，复制导出目录后运行 frpc -c frpc.toml。\n'
}

_frps_client_wizard() {
	local step=1 rc choice type local_port=8080 remote_port=$FRPS_RANGE_START name=www output=/root/frpc-client suffix=1
	if [ "$FRPS_MODE" = web ]; then type=http; step=2; else type=tcp; fi
	while [ -e "$output" ]; do output="/root/frpc-client-$suffix"; suffix=$((suffix + 1)); done
	info '导出向导：b 返回上一步，q 取消；不会覆盖现有目录。'
	while :; do
		rc=0
		case "$step" in
		1)
			if [ "$FRPS_MODE" = tcp ]; then
				_frps_ui_choice choice '转发协议：1 TCP / 2 UDP' "$([ "$type" = udp ] && echo 2 || echo 1)" '^[12]$'; rc=$?
				if [ "$rc" = 0 ]; then if [ "$choice" = 1 ]; then type=tcp; else type=udp; fi; fi
			else info '网站模式导出 HTTP 隧道，公网由 HTTPS 入口访问。'; fi ;;
		2) _frps_ui_number local_port '内网机器上 127.0.0.1 服务端口' "$local_port" 1 65535; rc=$? ;;
		3)
			if [ "$type" != http ]; then
				_frps_ui_number remote_port "公网转发端口（$FRPS_RANGE_START–$FRPS_RANGE_END）" "$remote_port" "$FRPS_RANGE_START" "$FRPS_RANGE_END"; rc=$?
			elif [ -n "$FRPS_SUBDOMAIN_HOST" ]; then
				_frps_ui_choice name "子域名标签（例如 home → home.$FRPS_SUBDOMAIN_HOST）" "$name" '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$'; rc=$?
			else printf '应用域名: %s\n' "$FRPS_WEB_DOMAIN"; fi ;;
		4)
			_frps_ui_read output '新的导出目录（包含敏感 token，请私密传输）' "$output"; rc=$?
			if [ "$rc" = 0 ]; then
				case "$output" in /*) ;; *) output="$PWD/$output" ;; esac
				if [ -e "$output" ] || ! _support_path_safe "$output"; then warn '目录已存在或路径不安全，请使用新目录'; continue; fi
				_frps_export "$output" "$type" "$local_port" "$remote_port" "$name" || return 1
				printf '复制整个目录到内网机器后：\n  cd %q\n  frpc verify -c frpc.toml\n  frpc -c frpc.toml\n' "$output"
				return 0
			fi ;;
		esac
		case "$rc" in
		0) step=$((step + 1)) ;;
		126)
			if [ "$type/$step" = http/4 ] && [ -z "$FRPS_SUBDOMAIN_HOST" ]; then step=2;
			elif [ "$type/$step" != http/2 ] && [ "$step" != 1 ]; then step=$((step - 1)); fi ;;
		125) info '已取消客户端导出'; return 125 ;;
		*) return "$rc" ;;
		esac
	done
}
