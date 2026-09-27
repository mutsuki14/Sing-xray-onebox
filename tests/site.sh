#!/usr/bin/env bash
# 自有域名 REALITY 站点回归测试: 仅写临时目录, 不安装软件或改动系统服务。
# 可选: ONEBOX_TEST_NGINX=/path/to/nginx 额外验证真实 nginx 配置语法。
# shellcheck disable=SC2034
set -u

HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/.." && pwd)
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
export ONEBOX_SOURCE_ONLY=1 ONEBOX_DIR="$WORK/etc" ONEBOX_BIN_DIR="$WORK/bin" \
	ONEBOX_LOG_DIR="$WORK/log" ONEBOX_RUN_DIR="$WORK/run" ONEBOX_INITD_DIR="$WORK/initd" \
	ONEBOX_SITE_ROOT="$WORK/public" NO_COLOR=1
# shellcheck source=../onebox.sh
. "$ROOT/onebox.sh"

PASS=0 FAIL=0
eq() {
	if [ "$2" = "$3" ]; then
		PASS=$((PASS + 1))
	else
		FAIL=$((FAIL + 1))
		printf '  [失败] %s\n    实际: %s\n    期望: %s\n' "$1" "$2" "$3"
	fi
}
yes_() { if "$@"; then echo yes; else echo no; fi; }
has_text() { case "$1" in *"$2"*) return 0 ;; *) return 1 ;; esac; }
cli_rejected() { (parse_install_opts "$@") >/dev/null 2>&1; [ "$?" -ne 0 ]; }

site_fixture() {
	reset_state
	PROTOCOLS="vless-reality"
	pset CORE vless-reality singbox
	pset PORT vless-reality 443
	REALITY_SITE_ENABLED=1 REALITY_SITE_DOMAIN=site.example.com REALITY_SITE_PORT=18443
	REALITY_SITE_TITLE='My Site'
	REALITY_SNI=$REALITY_SITE_DOMAIN REALITY_DEST="127.0.0.1:$REALITY_SITE_PORT"
	REALITY_GUARD_PORT=""
	REALITY_PRIVATE_KEY=private REALITY_PUBLIC_KEY=public REALITY_SHORT_ID=0123abcd
	UUID=550e8400-e29b-41d4-a716-446655440000
	SERVER_ADDR=203.0.113.9 SERVER_IPV4=203.0.113.9
}

# CLI 与状态文件必须完整保留域名和标题, 特殊字符不能变成 shell 代码。
site_fixture
parse_install_opts --reality-site site.example.com --site-title 'Hello & <welcome>'
eq "CLI 自有站点域名" "${OPT_REALITY_SITE:-}" site.example.com
eq "CLI 站点标题" "${OPT_SITE_TITLE:-}" 'Hello & <welcome>'
eq "CLI 拒绝空域名" "$(yes_ cli_rejected --reality-site '')" yes
eq "CLI 拒绝域名中的配置注入" "$(yes_ cli_rejected --reality-site 'example.com;return 200;')" yes
eq "CLI 拒绝空标题" "$(yes_ cli_rejected --site-title '')" yes
eq "CLI 拒绝标题换行" "$(yes_ cli_rejected --site-title $'line1\nline2')" yes
eq "CLI 拒绝超长标题" "$(yes_ cli_rejected --site-title "$(printf 'a%.0s' {1..81})")" yes
eq "CLI 拒绝站点和远程目标混用" "$(yes_ cli_rejected --reality-site site.example.com --reality-dest other.example.com:443)" yes
parse_install_opts --reality-site Site.Example.COM
eq "CLI 域名归一化为小写" "$OPT_REALITY_SITE" site.example.com
REALITY_SITE_TITLE='A & <script>alert("x")</script> $(touch never)'
save_state
reset_state
load_state
eq "状态保存站点开关" "$REALITY_SITE_ENABLED" 1
eq "状态保存域名" "$REALITY_SITE_DOMAIN" site.example.com
eq "状态保存内部端口" "$REALITY_SITE_PORT" 18443
eq "状态保存标题特殊字符" "$REALITY_SITE_TITLE" 'A & <script>alert("x")</script> $(touch never)'
eq "状态文件仅属主可读写" "$(stat -c %a "$STATE_FILE")" 600
eq "设置自有站点不产生公网地址回环" "$(
	AUTO_YES=1 OPT_SNI='' OPT_REALITY_DEST=''
	choose_reality_target >/dev/null
	printf '%s|%s' "$REALITY_SNI" "$REALITY_DEST"
)" 'site.example.com|127.0.0.1:18443'
eq "删除最后一个 REALITY 协议关闭站点" "$(
	site_fixture
	PROTOCOLS='vless-reality shadowsocks'
	pset CORE shadowsocks singbox
	pset PORT shadowsocks 8388
	require_installed() { :; }
	apply_or_die() { :; }
	do_del_protocol vless-reality >/dev/null
	printf '%s|%s' "$REALITY_SITE_ENABLED" "$PROTOCOLS"
)" '0|shadowsocks'

# 标题作为文字显示, 不能注入 HTML、脚本或属性。
html=$(site_render_index)
eq "标题中的脚本标签被转义" "$(yes_ has_text "$html" '&lt;script&gt;')" yes
eq "页面没有原始注入脚本" "$(yes_ has_text "$html" '<script>alert(')" no
eq "标题中的 & 被转义" "$(yes_ has_text "$html" 'A &amp;')" yes
eq "HTML 特殊字符转义" "$(yes_ has_text "$(site_html_escape '<&>')" '&lt;&amp;&gt;')" yes

# nginx 的 HTTP 重定向必须使用真正公开的 REALITY 端口。
site_fixture
eq "标准 HTTPS 端口" "$(site_public_port)" 443
pset PORT vless-reality 8443
eq "非标准 HTTPS 端口" "$(site_public_port)" 8443
PROTOCOLS="vless-reality vless-xhttp"
pset CORE vless-xhttp xray
pset PORT vless-xhttp 443
eq "多个 REALITY 入站时优先 443" "$(site_public_port)" 443

# 独立的 HTTP-01 / TLS 回环监听不能与现有 TCP 服务冲突。
site_fixture
eq "正常站点端口布局" "$(yes_ site_validate_ports 2>/dev/null)" yes
pset PORT vless-reality 80
eq "REALITY TCP 80 冲突被拒绝" "$(yes_ site_validate_ports 2>/dev/null)" no
pset PORT vless-reality 18443
eq "REALITY 与内部 TLS 端口冲突被拒绝" "$(yes_ site_validate_ports 2>/dev/null)" no
site_fixture
PROTOCOLS="vless-reality shadowsocks"
pset CORE shadowsocks singbox
pset PORT shadowsocks 80
eq "Shadowsocks TCP+UDP 80 冲突被拒绝" "$(yes_ site_validate_ports 2>/dev/null)" no
site_fixture
PROTOCOLS="vless-reality hysteria2"
pset CORE hysteria2 singbox
pset PORT hysteria2 80
eq "仅 UDP 80 不影响 HTTP 验证" "$(yes_ site_validate_ports 2>/dev/null)" yes
REALITY_GUARD_PORT=18443
eq "REALITY 保护端口与内部 TLS 端口冲突被拒绝" "$(yes_ site_validate_ports 2>/dev/null)" no
site_fixture
REALITY_SITE_PORT=65536
eq "内部端口超范围被拒绝" "$(yes_ site_validate_ports 2>/dev/null)" no
site_fixture
REALITY_SITE_DOMAIN='site.example.com;}'
eq "nginx 域名注入被拒绝" "$(yes_ site_validate_ports 2>/dev/null)" no

# nginx 只使用自己的配置、证书和静态目录。常规回归不需要安装 nginx。
site_fixture
site_nginx_check() { return 0; }
site_write_nginx
conf=$(cat "$REALITY_SITE_DIR/nginx.conf")
eq "TLS 监听仅限回环地址" "$(yes_ has_text "$conf" 'listen 127.0.0.1:18443 ssl http2;')" yes
eq "TLS 1.3 已启用" "$(yes_ has_text "$conf" 'ssl_protocols TLSv1.3;')" yes
eq "HTTP 80 承载域名验证" "$(yes_ has_text "$conf" 'listen 80;')" yes
eq "保留 HTTP-01 验证目录" "$(yes_ has_text "$conf" 'location ^~ /.well-known/acme-challenge/')" yes
eq "标准端口重定向不多带内部端口" "$(yes_ has_text "$conf" 'return 301 https://site.example.com$request_uri;')" yes
eq "使用站点独立证书" "$(yes_ has_text "$conf" "ssl_certificate \"${REALITY_SITE_DIR}/cert.pem\";")" yes
eq "不加载发行版 nginx 站点配置" "$(yes_ has_text "$conf" 'include /etc/nginx/')" no
pset PORT vless-reality 8443
site_write_nginx
conf=$(cat "$REALITY_SITE_DIR/nginx.conf")
eq "修改公网端口后重定向同步更新" "$(yes_ has_text "$conf" 'return 301 https://site.example.com:8443$request_uri;')" yes
if [ -n "${ONEBOX_TEST_NGINX:-}" ]; then
	openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 2 \
		-subj /CN=site.example.com -addext subjectAltName=DNS:site.example.com \
		-keyout "$REALITY_SITE_DIR/key.pem" -out "$REALITY_SITE_DIR/cert.pem" >/dev/null 2>&1
	eq "真实 nginx 校验生成配置" "$(yes_ "$ONEBOX_TEST_NGINX" -t -p "$REALITY_SITE_DIR/" -c "$REALITY_SITE_DIR/nginx.conf" 2>/dev/null)" yes
fi

# mock 外部副作用, 保留真实站点事务和配置生成逻辑。
mock_site_environment() {
	INIT=none
	REALITY_SITE_DIR="$WORK/transaction-site"
	REALITY_SITE_ROOT="$WORK/transaction-public"
	SITE_ACME_HOME="$REALITY_SITE_DIR/acme"
	SITE_TXN_BAK=""
	site_check_dns() { return 0; }
	site_install_nginx() { return 0; }
	ensure_cmds() { return 0; }
	site_nginx_bin() { printf '%s' /usr/sbin/nginx; }
	_site_cron_lines() { :; }
	_site_cron_remove() { :; }
	_site_cron_enable() { :; }
	_site_enable_unit() { :; }
	_site_disable_unit() { :; }
	port_in_use() { return 1; }
	site_issue_cert() { printf '%s' "$REALITY_SITE_DOMAIN" >"$REALITY_SITE_DIR/cert-domain"; }
	site_service() { printf '%s\n' "$1" >>"$WORK/site-service.log"; }
	_site_running() { [ "${MOCK_WAS_RUNNING:-0}" = 1 ]; }
	fw_rule() { :; }
	_fw_snapshot() { printf '%s' unchanged; }
	site_health() { return 1; }
}
transaction_failure_restores_existing() (
	site_fixture
	mock_site_environment
	MOCK_WAS_RUNNING=1
	mkdir -p "$REALITY_SITE_DIR" "$REALITY_SITE_ROOT"
	: >"$REALITY_SITE_DIR/.onebox-site-owned"
	: >"$REALITY_SITE_ROOT/.onebox-site-owned"
	printf '%s' 'custom user website' >"$REALITY_SITE_ROOT/index.html"
	printf '%s' 'previous nginx config' >"$REALITY_SITE_DIR/nginx.conf"
	printf '%s' 'previous certificate' >"$REALITY_SITE_DIR/cert.pem"
	if site_prepare >/dev/null 2>&1; then return 1; fi
	[ "$(cat "$REALITY_SITE_ROOT/index.html")" = 'custom user website' ] &&
		[ "$(cat "$REALITY_SITE_DIR/nginx.conf")" = 'previous nginx config' ] &&
		[ "$(cat "$REALITY_SITE_DIR/cert.pem")" = 'previous certificate' ] &&
		[ -z "$SITE_TXN_BAK" ] && [ "$(tail -n 1 "$WORK/site-service.log")" = start ]
)
transaction_failure_cleans_new_site() (
	site_fixture
	mock_site_environment
	# 上一项发生在子 shell, 目录仍可能保留旧站点, 此项使用独立路径。
	REALITY_SITE_DIR="$WORK/new-site" REALITY_SITE_ROOT="$WORK/new-public"
	SITE_ACME_HOME="$REALITY_SITE_DIR/acme"
	if site_prepare >/dev/null 2>&1; then return 1; fi
	[ ! -e "$REALITY_SITE_DIR" ] && [ ! -e "$REALITY_SITE_ROOT" ] && [ -z "$SITE_TXN_BAK" ]
)
snapshot_failure_preserves_custom_site() (
	site_fixture
	mock_site_environment
	REALITY_SITE_DIR="$WORK/snapshot-site" REALITY_SITE_ROOT="$WORK/snapshot-public"
	SITE_ACME_HOME="$REALITY_SITE_DIR/acme"
	mkdir -p "$REALITY_SITE_DIR" "$REALITY_SITE_ROOT"
	: >"$REALITY_SITE_DIR/.onebox-site-owned"
	: >"$REALITY_SITE_ROOT/.onebox-site-owned"
	printf '%s' 'irreplaceable custom content' >"$REALITY_SITE_ROOT/index.html"
	printf '%s' 'original configuration' >"$REALITY_SITE_DIR/nginx.conf"
	cp() { return 1; }
	if site_prepare >/dev/null 2>&1; then return 1; fi
	[ "$(cat "$REALITY_SITE_ROOT/index.html" 2>/dev/null)" = 'irreplaceable custom content' ] &&
		[ "$(cat "$REALITY_SITE_DIR/nginx.conf" 2>/dev/null)" = 'original configuration' ] && [ -z "$SITE_TXN_BAK" ]
)
core_apply_failure_restores_site() (
	site_fixture
	mock_site_environment
	ONEBOX_DIR="$WORK/apply/etc"
	STATE_FILE="$ONEBOX_DIR/onebox.conf"
	SB_CONF="$ONEBOX_DIR/sing-box.json" XR_CONF="$ONEBOX_DIR/xray.json"
	REALITY_SITE_DIR="$ONEBOX_DIR/site" REALITY_SITE_ROOT="$WORK/apply/public"
	SITE_ACME_HOME="$REALITY_SITE_DIR/acme"
	MOCK_WAS_RUNNING=1 MOCK_APPLY_ATTEMPTS=0
	mkdir -p "$REALITY_SITE_DIR" "$REALITY_SITE_ROOT"
	: >"$REALITY_SITE_DIR/.onebox-site-owned"
	: >"$REALITY_SITE_ROOT/.onebox-site-owned"
	printf '%s' 'custom page before core update' >"$REALITY_SITE_ROOT/index.html"
	printf '%s' 'previous website config' >"$REALITY_SITE_DIR/nginx.conf"
	printf '%s' 'previous proxy config' >"$SB_CONF"
	save_state
	REALITY_SITE_DOMAIN=new.example.com REALITY_SNI=new.example.com
	site_health() { return 0; }
	own_ip_cidrs() { printf '%s' '"203.0.113.9/32"'; }
	prepare_server_configs() { printf '%s' 'new proxy config' >"$SB_CONF.new"; }
	commit_server_configs() { mv -f "$SB_CONF.new" "$SB_CONF"; }
	apply_services() { MOCK_APPLY_ATTEMPTS=$((MOCK_APPLY_ATTEMPTS + 1)); [ "$MOCK_APPLY_ATTEMPTS" -gt 1 ]; }
	fw_apply() { :; }
	hop_rules() { :; }
	hop_setup() { :; }
	write_client_files() { :; }
	apply_all >/dev/null 2>&1
	local rc=$?
	load_state
	[ "$rc" = 2 ] && [ "$MOCK_APPLY_ATTEMPTS" = 2 ] &&
		[ "$REALITY_SITE_DOMAIN" = site.example.com ] &&
		[ "$(cat "$REALITY_SITE_ROOT/index.html")" = 'custom page before core update' ] &&
		[ "$(cat "$REALITY_SITE_DIR/nginx.conf")" = 'previous website config' ] &&
		[ "$(cat "$SB_CONF")" = 'previous proxy config' ] && [ -z "$SITE_TXN_BAK" ]
)
eq "健康检查失败恢复网页、配置、证书与原服务" "$(yes_ transaction_failure_restores_existing)" yes
eq "首次建立站点失败清理新文件" "$(yes_ transaction_failure_cleans_new_site)" yes
eq "备份失败不能删除原有自定义网站" "$(yes_ snapshot_failure_preserves_custom_site)" yes
eq "网站已准备但代理启动失败时整体回滚" "$(yes_ core_apply_failure_restores_site)" yes

# 两个内核的握手目标必须始终是本机 TLS 站点, 避免解析到自身公开端口后循环。
site_fixture
eq "sing-box REALITY 握手目标为回环" "$(_sb_reality_tls | jq -r '.reality.handshake.server')" 127.0.0.1
eq "sing-box REALITY 握手端口为站点内部端口" "$(_sb_reality_tls | jq -r '.reality.handshake.server_port')" 18443
pset CORE vless-reality xray
REALITY_GUARD_PORT=18444 BLOCK_PRIVATE=1 BLOCK_BT=1
ip() { :; }
xr=$(gen_xray_server)
unset -f ip
eq "Xray REALITY 先进入回环 SNI 保护端口" "$(printf '%s' "$xr" | jq -r '.inbounds[] | select(.tag == "vless-reality-in") | .streamSettings.realitySettings.target')" 127.0.0.1:18444
eq "Xray SNI 保护只转发回环站点" "$(printf '%s' "$xr" | jq -r '.inbounds[] | select(.tag == "reality-dest-in") | .settings | "\(.address):\(.port)"')" 127.0.0.1:18443
eq "普通出站没有全局放开私有地址" "$(printf '%s' "$xr" | jq '[.outbounds[] | select(.tag == "direct") | .settings.finalRules[]? | select(.action == "allow")] | length')" 0
eq "代理私有地址屏蔽保留" "$(printf '%s' "$xr" | jq '[.routing.rules[] | select(.outboundTag == "block") | .ip[]? | select(. == "100.64.0.0/10")] | length')" 1
eq "站点专用出站限定回环 TLS 目标" "$(printf '%s' "$xr" | jq '[.outbounds[] | select(.tag != "direct" and .protocol == "freedom") | select(.settings.redirect == "127.0.0.1:18443")] | length')" 1

echo "通过 ${PASS} 项, 失败 ${FAIL} 项"
[ "$FAIL" = 0 ]
