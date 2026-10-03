#!/usr/bin/env bash
#
# 生命周期测试: 以 root 在一次性环境 (容器 / CI) 中真实执行安装脚本的各个命令,
# 检查服务、端口、状态文件、分享链接与客户端配置是否符合预期.
#
# 警告: 会在本机安装并卸载 /etc/onebox /opt/onebox /usr/local/bin/onebox, 请勿在生产机器上运行.
#
# 用法: ONEBOX_LIFECYCLE=1 SB=/path/sing-box XR=/path/xray [MH=/path/mihomo] bash tests/lifecycle.sh
#
set -u

HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/.." && pwd)
SCRIPT="$ROOT/onebox.sh"

[ "${ONEBOX_LIFECYCLE:-}" = 1 ] || {
	echo "该测试会修改系统, 请在一次性环境中设置 ONEBOX_LIFECYCLE=1 后运行" >&2
	exit 2
}
[ "$(id -u)" = 0 ] || {
	echo "需要 root" >&2
	exit 2
}
SB=${SB:-$(command -v sing-box || true)}
XR=${XR:-$(command -v xray || true)}
MH=${MH:-$(command -v mihomo || true)}
[ -x "$SB" ] && [ -x "$XR" ] || {
	echo "请通过 SB / XR 环境变量指定 sing-box / xray 路径" >&2
	exit 2
}
export ONEBOX_SINGBOX_BIN="$SB" ONEBOX_XRAY_BIN="$XR" NO_COLOR=1
# sing-box check 会在工作目录生成 cache.db, 使用临时目录
LC_TMP=$(mktemp -d)
trap 'rm -rf "$LC_TMP"' EXIT

PASS=0 FAIL=0
ok() {
	PASS=$((PASS + 1))
	echo "  [通过] $*"
}
bad() {
	FAIL=$((FAIL + 1))
	echo "  [失败] $*"
}
check() {
	# check "说明" 命令...
	local d=$1
	shift
	if "$@" >/dev/null 2>&1; then ok "$d"; else bad "$d"; fi
}

conf_get() { sed -n "s/^$1=//p" /etc/onebox/onebox.conf | tr -d "'"; }
listening() {
	# listening 端口 tcp|udp
	if [ "$2" = udp ]; then ss -lnu | awk 'NR>1{print $4}' | grep -qE "[:.]$1\$"; else ss -lnt | awk 'NR>1{print $4}' | grep -qE "[:.]$1\$"; fi
}
link_count() { grep -c '://' /etc/onebox/client/links.txt 2>/dev/null || echo 0; }
# 按可执行文件路径匹配进程 (避免命令行文本误匹配)
proc_running() {
	local p
	for p in /proc/[0-9]*; do
		[ "$(readlink "$p/exe" 2>/dev/null)" = "/opt/onebox/bin/$1" ] && return 0
	done
	return 1
}

step() { printf '\n== %s ==\n' "$*"; }

# 清理残留
[ -x /usr/local/bin/onebox ] && /usr/local/bin/onebox uninstall -y >/dev/null 2>&1

step "安装: vless-reality + hysteria2 + tuic (sing-box)"
bash "$SCRIPT" install --protocols vless-reality,hysteria2,tuic --core singbox --addr 127.0.0.1 --name lc \
	--sni www.microsoft.com --no-bbr -y >/tmp/onebox-lc-install.log 2>&1
check "安装命令成功" [ $? = 0 ] || true
check "状态文件存在且权限为 600" [ "$(stat -c %a /etc/onebox/onebox.conf 2>/dev/null)" = 600 ]
check "onebox 命令已安装" [ -x /usr/local/bin/onebox ]
check "sing-box 服务端配置通过校验" "$SB" check -D "$LC_TMP" -c /etc/onebox/sing-box.json
check "sing-box 进程运行中" proc_running sing-box
check "Xray 未被使用" [ ! -f /etc/onebox/xray.json ]
P_REALITY=$(conf_get PORT_vless_reality)
P_HY2=$(conf_get PORT_hysteria2)
P_TUIC=$(conf_get PORT_tuic)
check "REALITY 端口 ${P_REALITY}/tcp 监听" listening "$P_REALITY" tcp
check "Hysteria2 端口 ${P_HY2}/udp 监听" listening "$P_HY2" udp
check "TUIC 端口 ${P_TUIC}/udp 监听" listening "$P_TUIC" udp
check "分享链接数量为 3" [ "$(link_count)" = 3 ]
check "sing-box 客户端配置通过校验" "$SB" check -D "$LC_TMP" -c /etc/onebox/client/sing-box.json
check "sing-box 客户端配置 (无 TUN) 通过校验" "$SB" check -D "$LC_TMP" -c /etc/onebox/client/sing-box-notun.json
check "Xray 客户端配置为合法 JSON" jq -e . /etc/onebox/client/xray.json
if [ -x "$MH" ]; then
	mkdir -p /tmp/onebox-lc-mh && cp /etc/onebox/client/mihomo.yaml /tmp/onebox-lc-mh/config.yaml
	check "mihomo 客户端配置通过校验" timeout 60 "$MH" -t -d /tmp/onebox-lc-mh -f /tmp/onebox-lc-mh/config.yaml
fi
check "订阅内容可 Base64 解码" sh -c 'base64 -d /etc/onebox/client/sub.txt | grep -q "^vless://"'
check "onebox info 正常" onebox info
check "onebox client mihomo 正常" sh -c 'onebox client mihomo | grep -q "^proxies:"'

step "管理命令: 只读预演 / 体检 / 证书 / 备份恢复 / 诊断包"
BEFORE_STATE=$(cksum /etc/onebox/onebox.conf)
check "plan 命令正常" onebox plan --preset 6 --sni www.microsoft.com
check "install --dry-run 正常" onebox install --dry-run --preset 6
check "预演保持状态文件不变" test "$(cksum /etc/onebox/onebox.conf)" = "$BEFORE_STATE"
check "真实核心与监听端口体检正常" onebox doctor
check "自签证书状态正常" onebox cert status
check "自动快照已建立" test -d /etc/onebox/backups
check "手动创建快照" onebox backup lifecycle
BACKUP_ID=$(onebox backups | awk 'NR==2 {print $1}')
cp /etc/onebox/client/links.txt "$LC_TMP/original-links"
printf '\nLIFECYCLE-RESTORE-CANARY\n' >>/etc/onebox/client/links.txt
check "恢复快照通过真实核心校验并重启服务" onebox restore "$BACKUP_ID"
check "恢复了原客户端文件" cmp -s "$LC_TMP/original-links" /etc/onebox/client/links.txt
check "恢复后 sing-box 仍运行" proc_running sing-box
check "保存测试更新渠道" onebox update-channel testing
check "更新渠道已保存" test "$(cat /etc/onebox/update-channel)" = testing
check "恢复稳定更新渠道" onebox update-channel stable
check "生成本地诊断包" onebox support
SUPPORT_ARCHIVE=$(find /etc/onebox/support -name '*.tar.gz' | head -n1)
check "诊断包可读取" tar -tzf "$SUPPORT_ARCHIVE"

step "添加协议: vless-xhttp (Xray) 与 anytls"
check "添加 vless-xhttp" onebox add vless-xhttp -y
check "添加 anytls" onebox add anytls -y
check "Xray 进程运行中" proc_running xray
check "Xray 服务端配置通过校验" "$XR" run -test -c /etc/onebox/xray.json
P_XHTTP=$(conf_get PORT_vless_xhttp)
check "XHTTP 端口 ${P_XHTTP}/tcp 监听" listening "$P_XHTTP" tcp
check "AnyTLS 端口 $(conf_get PORT_anytls)/tcp 监听" listening "$(conf_get PORT_anytls)" tcp
check "分享链接数量为 5" [ "$(link_count)" = 5 ]
check "重复添加被拒绝" sh -c '! onebox add anytls -y'

step "修改端口 / 删除协议"
NEWP=$((P_HY2 + 7))
check "修改 hysteria2 端口为 ${NEWP}" onebox port hysteria2 "$NEWP" -y
sleep 1
check "新端口 ${NEWP}/udp 监听" listening "$NEWP" udp
check "旧端口 ${P_HY2}/udp 不再监听" sh -c "! ss -lnu | awk 'NR>1{print \$4}' | grep -qE '[:.]${P_HY2}\$'"
check "删除 tuic" onebox del tuic -y
check "分享链接数量为 4" [ "$(link_count)" = 4 ]
check "状态中已无 tuic" sh -c '! grep -q "tuic" /etc/onebox/onebox.conf'

step "重置凭据 / 修改地址"
OLD_UUID=$(conf_get UUID)
check "重置凭据" onebox reset -y
check "UUID 已变化" [ "$(conf_get UUID)" != "$OLD_UUID" ]
check "链接使用新 UUID" grep -q "$(conf_get UUID)" /etc/onebox/client/links.txt
check "修改地址为 127.0.0.2" onebox addr --addr 127.0.0.2 --name lc2 -y
check "链接地址已更新" grep -q "@127.0.0.2:" /etc/onebox/client/links.txt

step "输入校验 / 伪装站点 / 地址保留"
check "前导零端口被拒绝" sh -c '! onebox port hysteria2 0450 -y'
check "拒绝后 sing-box 仍在运行" proc_running sing-box
OLD_UUID=$(conf_get UUID)
check "更换伪装站点" onebox sni --sni addons.mozilla.org -y
check "REALITY SNI 已更新" [ "$(conf_get REALITY_SNI)" = addons.mozilla.org ]
check "更换伪装站点不改变 UUID" [ "$(conf_get UUID)" = "$OLD_UUID" ]
check "链接中 SNI 已更新" grep -q "sni=addons.mozilla.org" /etc/onebox/client/links.txt
check "仅修改节点名称" onebox addr --name lc3 -y
check "修改名称时保留地址" [ "$(conf_get SERVER_ADDR)" = 127.0.0.2 ]
check "节点名称已更新" [ "$(conf_get NODE_NAME)" = lc3 ]

step "服务启动失败时自动回滚"
# 用包装脚本模拟: 新配置含 anytls 时 sing-box 启动即退出 (但 check 通过)
# (运行中的可执行文件不能直接覆盖写入, 需写到临时文件再 mv 替换)
cp /opt/onebox/bin/sing-box /opt/onebox/bin/sing-box.real
cat >/opt/onebox/bin/sing-box.wrap <<'WRAP'
#!/bin/sh
if [ "$1" = run ] && grep -q anytls-in /etc/onebox/sing-box.json 2>/dev/null; then echo "simulated failure" >&2; exit 1; fi
exec /opt/onebox/bin/sing-box.real "$@"
WRAP
chmod +x /opt/onebox/bin/sing-box.wrap
mv -f /opt/onebox/bin/sing-box.wrap /opt/onebox/bin/sing-box
onebox del anytls -y >/dev/null 2>&1
# (不带 ONEBOX_SINGBOX_BIN: 否则 add 会用本地内核文件替换掉模拟故障的包装脚本)
check "添加协议因服务失败而报错退出" sh -c '! env -u ONEBOX_SINGBOX_BIN onebox add anytls -y'
check "状态已回滚 (无 anytls)" sh -c '! grep -q "^PROTOCOLS=.*anytls" /etc/onebox/onebox.conf'
check "服务端配置已回滚" sh -c '! grep -q anytls-in /etc/onebox/sing-box.json'
check "回滚后 sing-box 恢复运行" proc_running sing-box.real
mv -f /opt/onebox/bin/sing-box.real /opt/onebox/bin/sing-box
check "恢复后重启正常" onebox restart
check "sing-box 运行中" proc_running sing-box

step "服务启停 / 重新生成"
check "stop" onebox stop
sleep 1
check "sing-box 已停止" bash -c "$(declare -f proc_running); ! proc_running sing-box"
check "start" onebox start
sleep 1
check "sing-box 已启动" proc_running sing-box
check "Xray 已启动" proc_running xray
check "restart" onebox restart
check "regen" onebox regen
check "status" onebox status

step "卸载"
check "卸载命令成功" onebox uninstall -y
check "配置目录已删除" [ ! -e /etc/onebox ]
check "内核目录已删除" [ ! -e /opt/onebox ]
check "onebox 命令已删除" [ ! -e /usr/local/bin/onebox ]
sleep 1
check "无残留进程" bash -c "$(declare -f proc_running); ! proc_running sing-box && ! proc_running xray"

step "预设 2 (Xray 经典) 安装与卸载"
bash "$SCRIPT" install --preset 2 --addr 127.0.0.1 --no-bbr -y >/tmp/onebox-lc-install2.log 2>&1
check "预设 2 安装成功" [ $? = 0 ] || true
check "Xray 进程运行中" proc_running xray
check "sing-box 未被使用" [ ! -f /etc/onebox/sing-box.json ]
check "REALITY 使用 443 端口" [ "$(conf_get PORT_vless_reality)" = 443 ]
check "卸载" onebox uninstall -y

echo
echo "通过 ${PASS} 项, 失败 ${FAIL} 项"
[ "$FAIL" = 0 ]
