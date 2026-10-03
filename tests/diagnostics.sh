#!/usr/bin/env bash
# 真实临时证书 + 只读服务/DNS/HTTP mock，禁止修改系统。
# shellcheck disable=SC2034
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/.." && pwd)
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
export ONEBOX_SOURCE_ONLY=1 ONEBOX_DIR="$WORK/etc" ONEBOX_BIN_DIR="$WORK/bin" ONEBOX_RUN_DIR="$WORK/run" ONEBOX_LOG_DIR="$WORK/log" ONEBOX_SITE_ROOT="$WORK/www" NO_COLOR=1
# shellcheck source=../onebox.sh
. "$ROOT/onebox.sh"
# 集成片段后删除第二个 source。
# shellcheck source=/dev/null
REAL_RESOLVER=$(declare -f _diag_resolve_domain)
PASS=0 FAIL=0 STATUS=0 OUTPUT=''
eq() {
	if [ "$2" = "$3" ]; then PASS=$((PASS + 1));
	else FAIL=$((FAIL + 1)); printf '[失败] %s: 实际 %s，期望 %s\n' "$1" "$2" "$3"; fi
}
contains() { [[ "$OUTPUT" == *"$1"* ]]; }
yes_() { if "$@"; then echo yes; else echo no; fi; }
run() { OUTPUT=$("$@" 2>&1); STATUS=$?; }
forbidden() { printf 'mutation called\n' >>"$WORK/mutations"; return 99; }
for fn in ensure_cmds pkg_install acme site_issue_cert site_prepare site_apply_service apply_all apply_services svc_start svc_stop svc_restart obtain_cert cert_self_signed gen_credentials; do eval "$fn() { forbidden; }"; done
has() { [ "$1" != "${MISSING_CMD:-}" ] && command -v "$1" >/dev/null 2>&1; }
svc_active() { [ "${MOCK_ACTIVE:-1}" = 1 ]; }
port_in_use() { [ "${MOCK_PORT_ACTIVE:-1}" = 1 ]; }
_diag_listener_owner() { printf '%s' "${MOCK_PORT_OWNER:-sing-box}"; }
own_ip_list() { printf '%s\n' "${MOCK_OWN:-203.0.113.9}"; }
resolve_domain() { [ -n "${MOCK_DNS:-}" ] && printf '%s\n' "$MOCK_DNS"; }
_diag_resolve_domain() { resolve_domain "$@"; }
crontab() {
	[ "${1:-}" = -l ] || { forbidden; return 99; }
	case "${MOCK_CRON_MODE:-ok}" in ok) printf '%s\n' "${MOCK_CRON:-}" ;; empty) echo 'no crontab for root' >&2; return 1 ;; *) echo 'private-sensitive-error' >&2; return 1 ;; esac
}
_site_running() { [ "${MOCK_SITE_ACTIVE:-1}" = 1 ]; }
_diag_http_probe() { printf '%s\n' "$*" >>"$WORK/probes"; [ "${MOCK_HTTP:-1}" = 1 ]; }
openssl() {
	case "${1:-}" in s_client) [ "${MOCK_H2:-1}" = 1 ] && printf 'ALPN protocol: h2\n' ;; verify) [ "${MOCK_TRUST:-1}" = 1 ] ;; *) command openssl "$@" ;; esac
}
# timeout 必须仍调用当前 shell 中的 openssl mock，不建立真实网络连接。
timeout() { shift; "$@"; }
mkdir -p "$BIN_DIR" "$WORK/pki"
cat >"$SB_BIN" <<'EOF'
#!/usr/bin/env bash
printf 'SENSITIVE-CORE-OUTPUT secret-private-key password uuid\n'
exit "${FAKE_CORE_RC:-0}"
EOF
chmod +x "$SB_BIN"
command openssl req -x509 -newkey rsa:2048 -nodes -days 90 -subj /CN=proxy.example.com -addext 'subjectAltName=DNS:proxy.example.com,IP:203.0.113.9,IP:2001:db8::9' -keyout "$WORK/pki/key.pem" -out "$WORK/pki/cert.pem" >/dev/null 2>&1 || exit 1
END_EPOCH=$(_diag_cert_epoch "$(command openssl x509 -in "$WORK/pki/cert.pem" -noout -enddate | cut -d= -f2-)")
START_EPOCH=$(_diag_cert_epoch "$(command openssl x509 -in "$WORK/pki/cert.pem" -noout -startdate | cut -d= -f2-)")
fixture() {
	reset_state
	PROTOCOLS=trojan TLS_MODE=self TLS_SNI=proxy.example.com CERT_FILE="$WORK/pki/cert.pem" KEY_FILE="$WORK/pki/key.pem"
	pset CORE trojan singbox
	pset PORT trojan 8443
	INIT=none MOCK_ACTIVE=1 MOCK_CRON='' MOCK_CRON_MODE=ok MOCK_DNS=203.0.113.9 MOCK_OWN=203.0.113.9
	MOCK_SITE_ACTIVE=1 MOCK_HTTP=1 MOCK_H2=1 MOCK_TRUST=1 MISSING_CMD=''
	MOCK_PORT_ACTIVE=1 MOCK_PORT_OWNER=sing-box
	export FAKE_CORE_RC=0
	_diag_now() { date +%s; }
	rm -f "$ONEBOX_DIR/renewal-proxy.status" "$ONEBOX_DIR/renewal-site.status" "$WORK/probes"
	save_state
	printf '{}\n' >"$SB_CONF"
}
site_fixture() {
	fixture
	PROTOCOLS='vless-reality trojan'
	pset CORE vless-reality singbox
	pset PORT vless-reality 443
	REALITY_SITE_ENABLED=1 REALITY_SITE_HTTPS=1 REALITY_SITE_DOMAIN=proxy.example.com REALITY_SITE_PORT=18443 REALITY_SNI=proxy.example.com LISTEN_ADDR='::'
	mkdir -p "$REALITY_SITE_DIR"
	cp "$WORK/pki/cert.pem" "$REALITY_SITE_DIR/cert.pem"
	cp "$WORK/pki/key.pem" "$REALITY_SITE_DIR/key.pem"
	MOCK_CRON="17 3 * * * $CMD_PATH cert-renew site >/dev/null 2>&1"
	save_state
}
run do_doctor
eq '未安装时返回失败' "$STATUS" 1
eq '未安装时给出提示' "$(yes_ contains 'onebox install')" yes
fixture
before=$(cksum "$STATE_FILE" "$SB_CONF" "$CERT_FILE" "$KEY_FILE")
run do_doctor
eq '正常体检通过' "$STATUS" 0
eq '校验器输出不会泄漏' "$(yes_ contains SENSITIVE-CORE-OUTPUT)" no
eq '明确本机检查不等于公网连通' "$(yes_ contains 公网连通性未验证)" yes
eq '状态配置证书保持不变' "$(cksum "$STATE_FILE" "$SB_CONF" "$CERT_FILE" "$KEY_FILE")" "$before"
MOCK_PORT_ACTIVE=0
run do_doctor
eq '未监听的节点端口被报告' "$STATUS" 1
MOCK_PORT_ACTIVE=1 MOCK_PORT_OWNER=nginx
run do_doctor
eq '异常占用进程返回提示' "$STATUS" 2
eq '异常占用进程名称可见' "$(yes_ contains '监听进程为 nginx')" yes
MOCK_PORT_OWNER=sing-box
run do_cert_status
eq '真实证书状态通过' "$STATUS" 0
eq '显示到期时间' "$(yes_ contains 到期:)" yes
eq '显示剩余天数' "$(yes_ contains 剩余)" yes
eq '无续期记录明确未知' "$(yes_ contains '未知（未找到有效的续期结果记录）')" yes
_diag_now() { echo "$((END_EPOCH + 1))"; }
run do_cert_status
eq '过期真实证书失败' "$STATUS" 1
eq '过期状态明确' "$(yes_ contains 已过期)" yes
_diag_now() { echo "$((END_EPOCH - 7 * 86400))"; }
run do_cert_status
eq '临期返回提示状态' "$STATUS" 2
eq '临期剩余天数正确' "$(yes_ contains '剩余 7 天')" yes
_diag_now() { echo "$((START_EPOCH - 1))"; }
run do_cert_status
eq '尚未生效证书失败' "$STATUS" 1
PROTOCOLS=shadowsocks
pset CORE shadowsocks singbox
pset PORT shadowsocks 8388
save_state
run do_cert_status
eq '不再使用的旧证书仅展示，不误报部署失败' "$STATUS" 0
fixture
TLS_SNI=wrong.example.com
save_state
run do_cert_status
eq '名称不匹配失败' "$STATUS" 1
eq '名称不匹配指出目标' "$(yes_ contains '不覆盖 wrong.example.com')" yes
for TLS_SNI in 203.0.113.9 2001:db8::9; do save_state; run do_cert_status; eq "真实证书 IP SAN $TLS_SNI" "$STATUS" 0; done
fixture
KEY_FILE="$WORK/missing-key"
save_state
run do_cert_status
eq '缺少私钥失败' "$STATUS" 1
fixture
MISSING_CMD=openssl
run do_cert_status
eq '缺少openssl只提示未检查' "$STATUS" 2
MISSING_CMD='' MOCK_ACTIVE=0
run do_doctor
eq '服务未启动失败' "$STATUS" 1
MOCK_ACTIVE=1 FAKE_CORE_RC=1
run do_doctor
eq '核心配置校验失败' "$STATUS" 1
eq '失败校验器输出仍不泄漏' "$(yes_ contains SENSITIVE-CORE-OUTPUT)" no
FAKE_CORE_RC=0 MISSING_CMD=timeout
run do_doctor
eq '缺少限时工具跳过检查' "$STATUS" 2
fixture
TLS_MODE=acme DOMAIN=proxy.example.com CERT_PINNED=1
save_state
MOCK_CRON="17 3 * * * \"$ACME_HOME/acme.sh\" --cron --home \"$ACME_HOME\""
run do_cert_status
eq '识别旧acme续期任务' "$STATUS" 0
MOCK_CRON="17 3 * * * $CMD_PATH cert-renew proxy >/dev/null 2>&1"
printf '1770000000\nsuccess\ncron\n' >"$ONEBOX_DIR/renewal-proxy.status"
run do_cert_status
eq '识别新续期任务' "$STATUS" 0
eq '显示续期成功记录' "$(yes_ contains '定时 / 成功')" yes
printf '1770000000\nfailed\nmanual\n' >"$ONEBOX_DIR/renewal-proxy.status"
run do_cert_status
eq '续期失败记录提示' "$STATUS" 2
printf '$(touch %s)\nprivate-sensitive-result\nsecret\n' "$WORK/injected" >"$ONEBOX_DIR/renewal-proxy.status"
run do_cert_status
eq '畸形记录不执行代码' "$(test -e "$WORK/injected" && echo yes || echo no)" no
eq '畸形记录不暴露内容' "$(yes_ contains private-sensitive-result)" no
eq '畸形记录明确未知' "$(yes_ contains 未找到有效的续期结果记录)" yes
MOCK_CRON="# 17 3 * * * $CMD_PATH cert-renew proxy"
run do_cert_status
eq '注释任务不是有效续期' "$STATUS" 2
MOCK_CRON_MODE=error
run do_cert_status
eq '无法读取cron提示未知' "$STATUS" 2
eq 'cron错误内容不泄漏' "$(yes_ contains private-sensitive-error)" no
site_fixture
MOCK_DNS='2001:db8::9' MOCK_OWN='2001:0db8:0000:0000:0000:0000:0000:0009'
run do_doctor
eq 'IPv6不同文本形式不误报DNS' "$STATUS" 0
eq 'IPv6监听用IPv6本机接口探测' "$(grep -c 'proxy.example.com 443 \[::1\]' "$WORK/probes")" 1
MOCK_DNS=$'203.0.113.9\n198.51.100.7' MOCK_OWN=203.0.113.9
run do_doctor
eq '自建站部分DNS指向其他主机失败' "$STATUS" 1
eq '提示全部A/AAAA应直连' "$(yes_ contains '全部 A/AAAA')" yes
MOCK_DNS=''
run do_doctor
eq '解析失败' "$STATUS" 1
MOCK_DNS=203.0.113.9 MOCK_HTTP=0
run do_doctor
eq '内部或入口HTTP失败' "$STATUS" 1
MOCK_HTTP=1 MOCK_H2=0
run do_doctor
eq '内部目标不支持h2失败' "$STATUS" 1
eq '诊断未调用任何变更函数' "$(test -e "$WORK/mutations" && echo yes || echo no)" no
printf "PROTOCOLS='broken\n" >"$STATE_FILE"
before=$(cksum "$STATE_FILE")
run do_doctor
eq '状态损坏失败' "$STATUS" 1
eq '状态损坏保持文件原样' "$(cksum "$STATE_FILE")" "$before"
resolved=$(
	eval "$REAL_RESOLVER"
	curl() {
		case " $* " in *' --connect-timeout 2 --max-time 3 '*) ;; *) return 99 ;; esac
		printf '%s\n' '{"Answer":[{"type":1,"data":"203.0.113.9"},{"type":5,"data":"cafe.be."}]}'
	}
	_diag_resolve_domain proxy.example.com
)
eq 'DoH带连接和总超时且过滤CNAME' "$resolved" 203.0.113.9
resolved=$(
	eval "$REAL_RESOLVER"
	curl() { return 28; }
	timeout() { [ "$1" = 3 ] || return 99; shift; "$@"; }
	getent() { printf '203.0.113.9 STREAM proxy.example.com\n'; }
	_diag_resolve_domain proxy.example.com
)
eq 'DoH失败后的NSS查询也受超时约束' "$resolved" 203.0.113.9
fixture
_diag_cert_epoch() { return 1; }
run do_cert_status
eq '时间解析失败安全降级为未知' "$STATUS" 2
pset CORE trojan ''
save_state
run do_doctor
eq '协议缺少内核分配不能误判为健康' "$STATUS" 1
printf '诊断回归: %s 通过, %s 失败\n' "$PASS" "$FAIL"
[ "$FAIL" = 0 ]
