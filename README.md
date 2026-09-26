# Sing-Xray-Onebox

**sing-box / Xray 多协议组合 · 交互式一键安装与管理脚本**

适用于各类 Linux VPS，一条命令部署 VLESS-Reality、XHTTP、Hysteria2、TUIC、AnyTLS、Trojan、SS-2022、ShadowTLS 等协议的任意组合，
服务端可选 **sing-box** 或 **Xray** 内核（也可双内核共存），并自动生成适用于 **sing-box / Xray / mihomo (Clash Meta)** 客户端的完整配置、
分享链接、Base64 订阅与二维码。

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/mutsuki14/Sing-xray-onebox/main/onebox.sh)
```

安装完成后，随时输入 `onebox` 打开管理菜单。

---

## 特性

- **协议组合随心选**：7 套预设组合 + 自定义组合，11 种协议可自由搭配。
- **双内核**：sing-box 与 Xray 可单独使用，也可同时使用（例如 Xray 跑 Reality/XHTTP，sing-box 跑 Hysteria2/TUIC/AnyTLS）。
- **四类客户端输出**：
  - 分享链接 + Base64 订阅 + 终端二维码（v2rayN / v2rayNG / NekoBox / Shadowrocket / Hiddify / Karing 等）
  - mihomo 完整 YAML（Clash Verge Rev / Mihomo Party / FlClash / ClashMi / Clash Meta for Android）
  - sing-box 完整 JSON（TUN 版与纯代理端口版，兼容 sing-box 1.12 ~ 1.14，适用于 SFA / SFI / SFM / GUI.for.SingBox）
  - Xray 客户端 JSON
- **广泛的系统支持**：Debian / Ubuntu / CentOS / RHEL / Rocky / Alma / Oracle / Fedora / Amazon Linux / openEuler /
  Alpine / Arch / openSUSE 等；systemd 与 OpenRC；amd64 / arm64 / armv7 / armv6 / 386 / s390x / riscv64 / loong64 等架构。
  sing-box 优先使用 musl 静态构建，老旧 glibc 与 Alpine 均可运行。
- **证书**：自签证书（客户端自动固定证书指纹，无需关闭校验即可安全连接）/ Let's Encrypt（HTTP 验证或 Cloudflare DNS 验证，acme.sh 自动续期）/ 自有证书。
- **贴心细节**：自动检测端口占用、放行防火墙（ufw / firewalld / iptables，含甲骨文云默认规则）、Hysteria2 端口跳跃、BBR、
  屏蔽 BT 与回环/内网访问、配置写入前先经内核校验（失败不覆盖旧配置）、国内服务器 GitHub 加速。
- **经过真实流量测试**：仓库自带端到端测试，覆盖 *协议 × 服务端内核 × 客户端* 的全部组合（TCP 与 UDP）。

## 快速开始

需要 root 权限。

```bash
# curl
bash <(curl -fsSL https://raw.githubusercontent.com/mutsuki14/Sing-xray-onebox/main/onebox.sh)

# 或 wget
bash <(wget -qO- https://raw.githubusercontent.com/mutsuki14/Sing-xray-onebox/main/onebox.sh)

# Alpine 默认没有 bash 与 curl: 可先 apk add --no-cache bash curl, 或者下载后用 sh 运行 (脚本会自动安装 bash):
wget -O onebox.sh https://raw.githubusercontent.com/mutsuki14/Sing-xray-onebox/main/onebox.sh && sh onebox.sh

# 国内服务器 (GitHub 访问困难) 可设置加速前缀:
GH_PROXY=https://ghfast.top/ bash <(curl -fsSL https://ghfast.top/https://raw.githubusercontent.com/mutsuki14/Sing-xray-onebox/main/onebox.sh)
```

运行后选择 **1. 安装**，依次选择协议组合、伪装站点、证书方式与端口（直接回车即使用推荐的默认值），脚本会完成其余全部工作。

## 协议组合

| 编号 | 组合 | 内核 | 说明 |
|---|---|---|---|
| 1 | VLESS-Reality-Vision + Hysteria2 + TUIC | sing-box | **推荐**。无需域名，TCP 与 UDP 协议互为备份 |
| 2 | VLESS-Reality-Vision + VLESS-XHTTP-Reality + SS-2022 | Xray | Xray 官方推荐的 Reality 方案 |
| 3 | Reality-Vision、XHTTP (Xray) + Hysteria2、TUIC、AnyTLS (sing-box) | 双内核 | 各取所长 |
| 4 | Reality / gRPC-Reality / Trojan / SS-2022 / Hysteria2 / TUIC / AnyTLS / ShadowTLS / VMess-WS | sing-box | 全家桶 |
| 5 | VLESS-WS-TLS + VMess-WS | Xray | 可套 CDN，建议使用域名 |
| 6 | VLESS-Reality-Vision | Xray | 极简单协议 |
| 7 | 自定义 | 任选 | 从 11 种协议中任意组合，并选择优先内核 |

## 协议 / 内核 / 客户端 支持矩阵

| 协议 | 服务端内核 | 分享链接 | mihomo | sing-box | Xray | 证书 |
|---|---|---|---|---|---|---|
| VLESS-Reality-Vision | sing-box / Xray | ✅ | ✅ | ✅ | ✅ | 无需 (REALITY) |
| VLESS-XHTTP-Reality | Xray | ✅ | ✅ | ❌ | ✅ | 无需 (REALITY) |
| VLESS-gRPC-Reality | sing-box / Xray | ✅ | ✅ | ✅ | ✅ | 无需 (REALITY) |
| VLESS-WS-TLS | sing-box / Xray | ✅ | ✅ | ✅ | ✅ | 自签 / ACME |
| VMess-WS | sing-box / Xray | ✅ | ✅ | ✅ | ✅ | 可选 (有正式证书时启用 TLS) |
| Trojan-TLS | sing-box / Xray | ✅ | ✅ | ✅ | ✅ | 自签 / ACME |
| Shadowsocks-2022 | sing-box / Xray | ✅ | ✅ | ✅ | ✅ | 无需 |
| Hysteria2 | sing-box | ✅ | ✅ | ✅ | ❌ | 自签 / ACME |
| TUIC-v5 | sing-box | ✅ | ✅ | ✅ | ❌ | 自签 / ACME |
| AnyTLS | sing-box | ✅ | ✅ | ✅ | ❌ | 自签 / ACME |
| ShadowTLS-v3 | sing-box | ❌ (无通用链接格式) | ✅ | ✅ | ❌ | 借用大站握手 |

> Xray 26 起对 gRPC / WebSocket / VMess / Trojan / Shadowsocks 输出“已弃用”警告，这些协议默认建议由 sing-box 承载；
> REALITY 建议使用 443 端口（Xray 会对非 443 端口给出警告）。

## 客户端导入

| 客户端 | 推荐导入方式 |
|---|---|
| v2rayN / v2rayNG / NekoBox / Shadowrocket / Karing | 复制分享链接、扫描二维码，或导入 `sub.txt` 中的 Base64 订阅内容 |
| Clash Verge Rev / Mihomo Party / FlClash / ClashMi / CMFA | 导入 `mihomo.yaml`（`onebox client mihomo` 输出） |
| sing-box 官方客户端 (SFA / SFI / SFM) / GUI.for.SingBox | 导入 `sing-box.json`（TUN 模式） |
| sing-box 命令行 | `sing-box-notun.json`，本地 `127.0.0.1:2080` 混合代理端口 |
| Xray 命令行 | `xray.json`，本地 socks `127.0.0.1:10808` / http `127.0.0.1:10809` |
| Hiddify | 建议导入 sing-box 配置（其链接解析对 Hysteria2 混淆密码、AnyTLS 支持不完整） |

客户端文件均位于服务器 `/etc/onebox/client/`，也可以用命令直接打印：

```bash
onebox info                  # 节点信息 + 分享链接
onebox client mihomo         # mihomo / Clash Meta 配置
onebox client singbox        # sing-box 配置 (TUN)
onebox client singbox-notun  # sing-box 配置 (仅代理端口)
onebox client xray           # Xray 配置
onebox client sub            # Base64 订阅内容
onebox qr                    # 终端二维码
```

**客户端版本要求**：mihomo 内核需 ≥ 1.19.3（含 VLESS-XHTTP 时需 ≥ 1.19.22），sing-box 客户端需 ≥ 1.12。
生成的 mihomo / sing-box 配置为本地控制面板 (127.0.0.1:9090) 设置了密钥（`onebox info` 中显示），DNS 仅监听本机。
Stash 的部分字段名与 mihomo 不同（如证书指纹、Hysteria2 密码），Shadowrocket 建议直接导入分享链接或订阅。

**自签证书说明**：选择自签证书时，脚本会把证书指纹写入客户端配置——mihomo 使用 `fingerprint`，Xray 使用 `pinnedPeerCertSha256`，
sing-box 直接内嵌证书；分享链接同时附带 `allowInsecure=1`/`insecure=1` 与 `pcs` / `pinSHA256` / `hpkp` 指纹参数，兼顾新旧客户端。
已知限制：mihomo 通过订阅链接导入 **TUIC + 自签证书** 时无法跳过验证（其链接解析器不支持），请改用 `mihomo.yaml`；
mihomo 链接导入会忽略 Hysteria2 端口跳跃参数 `mport`。

## 管理命令

```text
onebox                     打开交互式管理菜单
onebox install             安装 / 重装
onebox info                查看节点信息与分享链接
onebox client <类型>       输出客户端配置: mihomo | singbox | singbox-notun | xray | links | sub | qr
onebox add <协议>          添加协议            例: onebox add hysteria2
onebox del <协议>          删除协议
onebox port <协议> <端口>  修改端口            例: onebox port vless-reality 8443
onebox addr                修改客户端连接地址 / 节点名称
onebox reset               重置全部 UUID / 密码 / 密钥
onebox start | stop | restart | status
onebox log [singbox|xray]  查看日志
onebox update [singbox|xray]   更新内核
onebox update-script       更新脚本
onebox cert                证书管理 (更换 / 续期)
onebox bbr                 开启 BBR
onebox uninstall           卸载
```

协议名称：`vless-reality` `vless-xhttp` `vless-grpc` `vless-ws` `vmess-ws` `trojan` `shadowsocks` `hysteria2` `tuic` `anytls` `shadowtls`

## 无人值守安装

```bash
# 预设 1, 全部默认值
bash onebox.sh install --preset 1 -y

# 自定义协议与内核
bash onebox.sh install --protocols vless-reality,hysteria2,anytls --core singbox -y

# 指定端口、伪装站点、Hysteria2 端口跳跃
bash onebox.sh install --protocols vless-reality,hysteria2 --port vless-reality=443 --port hysteria2=8443 \
    --sni www.apple.com --hy2-hop 20000-40000 -y

# CDN 组合 + Cloudflare DNS 申请证书
CF_Token=xxxxxxxx bash onebox.sh install --preset 5 --tls cf --domain v.example.com -y
```

| 选项 | 说明 |
|---|---|
| `--preset <1-7>` | 协议组合 |
| `--protocols a,b,...` | 自定义协议列表 |
| `--core singbox\|xray` | 两种内核都支持的协议优先使用的内核 |
| `--sni <域名>` | REALITY / ShadowTLS 伪装站点 |
| `--tls self\|acme\|cf` | 证书方式：自签 / ACME HTTP 验证 / ACME Cloudflare DNS 验证 |
| `--domain <域名>` | 证书域名 |
| `--addr <IP或域名>` | 客户端连接地址（默认自动检测公网 IP） |
| `--name <名称>` | 节点名称前缀 |
| `--port <协议>=<端口>` | 指定端口，可重复 |
| `--hy2-hop <起-止>` | Hysteria2 端口跳跃范围 |
| `--hy2-obfs` | Hysteria2 启用 salamander 混淆 |
| `--no-bbr` | 不开启 BBR |
| `-y` | 不再询问，全部使用默认值 |

环境变量：`GH_PROXY`（GitHub 加速前缀）、`ONEBOX_SINGBOX_BIN` / `ONEBOX_XRAY_BIN`（使用本地内核文件离线安装）。

## 文件位置

| 路径 | 内容 |
|---|---|
| `/etc/onebox/onebox.conf` | 脚本状态（端口、凭据等，权限 600） |
| `/etc/onebox/sing-box.json`、`/etc/onebox/xray.json` | 服务端配置 |
| `/etc/onebox/tls/` | 证书 |
| `/etc/onebox/client/` | 客户端配置、分享链接、订阅 |
| `/opt/onebox/bin/` | sing-box / xray 内核 |
| `onebox-sing-box`、`onebox-xray` | 系统服务名 (systemd / OpenRC) |
| `/usr/local/bin/onebox` | 管理命令 |

## 常见问题

**安装成功但连不上？**
1. 在云服务商控制台的安全组 / 防火墙中放行对应端口（TCP 与 UDP 分别放行，Hysteria2 / TUIC 使用 UDP；
   启用了 Hysteria2 端口跳跃时还需放行整个 UDP 端口范围；使用 ACME HTTP 验证时需放行 TCP 80，续期同样需要）。
   本机防火墙（ufw / firewalld / iptables / nftables）由脚本自动放行，并在开机时由 `onebox-net` 服务自动恢复。
2. `onebox status` 与 `onebox log` 检查服务状态。
3. REALITY 连接失败时尝试更换伪装站点（`onebox reset` 或重新安装），站点需支持 TLS 1.3，且尽量与服务器地理位置接近。

**REALITY 伪装站点怎么选？** 选择支持 TLS 1.3 / H2、非 CDN 回源、在国内可正常访问的大站，例如 `www.microsoft.com`、`www.apple.com`、`addons.mozilla.org`。脚本会自动检测所选站点是否支持 TLS 1.3。

**国内 VPS 下载失败？** 设置 `GH_PROXY=https://ghfast.top/`（或其他可用的 GitHub 加速前缀）后重新运行。

**纯 IPv6 VPS？** GitHub 不支持 IPv6，下载内核需要借助支持 IPv6 的 GitHub 加速前缀（如 `GH_PROXY=https://ghproxy.net/`）或先配置 WARP / NAT64。

**支持哪些老系统？** CentOS 7 与 Debian 10 已停止维护，脚本会自动把软件源切换到 vault.centos.org / archive.debian.org。
sing-box 使用 musl 静态构建，不依赖系统 glibc 版本。

**SS-2022 / ShadowTLS / VMess 连接失败？** 这些协议对时间敏感：SS-2022 要求服务器与客户端时间误差在 30 秒以内，VMess 为 120 秒。
脚本安装时会检测服务器时间偏差，请开启时间同步（`timedatectl set-ntp true` 或安装 chrony）。

**如何更新？** `onebox update` 更新内核，`onebox update-script` 更新脚本（会用新脚本重新生成配置，凭据不变）。

## 测试

仓库自带的测试直接调用脚本的配置生成函数，在本机回环地址上运行真实的服务端与客户端：

```bash
# 端到端: 每个 协议 × 服务端内核 × 客户端 (sing-box / Xray / mihomo / 分享链接) 组合均验证 TCP 与 UDP 连通
SB=/path/sing-box XR=/path/xray MH=/path/mihomo bash tests/e2e.sh

# 生命周期: 真实执行 install / add / del / port / reset / addr / start / stop / uninstall (会修改系统, 仅在容器或 CI 中运行)
ONEBOX_LIFECYCLE=1 SB=/path/sing-box XR=/path/xray MH=/path/mihomo bash tests/lifecycle.sh
```

测试目标只能经由代理服务端访问（服务端将测试专用的域名 / TEST-NET 地址改写到本机），因此任何绕过代理的“假通过”都会被判为失败。

## 免责声明

本项目仅供学习与研究网络技术使用，请遵守当地法律法规。
