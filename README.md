# Sing-Xray-Onebox

**sing-box / Xray 多协议组合 · 交互式一键安装与管理脚本**

适用于各类 Linux VPS，一条命令部署 VLESS-Reality、XHTTP、Hysteria2、TUIC、AnyTLS、Trojan、SS-2022、ShadowTLS 等协议的任意组合，
服务端可选 **sing-box** 或 **Xray** 内核（也可双内核共存），并自动生成适用于 **sing-box / Xray / mihomo (Clash Meta)** 客户端的完整配置、
分享链接、Base64 订阅与二维码。

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/mutsuki14/Sing-xray-onebox/claude/linux-vps-proxy-script-1m1ksn/onebox.sh)
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
- **自有域名 REALITY 网站**：使用自己的域名一键生成可编辑的主页、申请 Let's Encrypt 证书并自动续期，普通浏览器与 REALITY 客户端共用公网入口。
- **管理与恢复**：只读安装预演、一键体检、证书状态、稳定/测试更新渠道、本机快照与手动恢复、静态网站模板和内容导入、本地脱敏诊断包。
- **贴心细节**：自动检测端口占用、放行防火墙（ufw / firewalld / iptables，含甲骨文云默认规则）、Hysteria2 端口跳跃、BBR、
  屏蔽 BT 与回环/内网访问、配置写入前先经内核校验（失败不覆盖旧配置）、国内服务器 GitHub 加速。
- **经过真实流量测试**：仓库自带端到端测试，覆盖 *协议 × 服务端内核 × 客户端* 的全部组合（TCP 与 UDP）。

## 快速开始

需要 root 权限。

```bash
# curl
bash <(curl -fsSL https://raw.githubusercontent.com/mutsuki14/Sing-xray-onebox/claude/linux-vps-proxy-script-1m1ksn/onebox.sh)

# 或 wget
bash <(wget -qO- https://raw.githubusercontent.com/mutsuki14/Sing-xray-onebox/claude/linux-vps-proxy-script-1m1ksn/onebox.sh)

# Alpine 默认没有 bash 与 curl: 可先 apk add --no-cache bash curl, 或者下载后用 sh 运行 (脚本会自动安装 bash):
wget -O onebox.sh https://raw.githubusercontent.com/mutsuki14/Sing-xray-onebox/claude/linux-vps-proxy-script-1m1ksn/onebox.sh && sh onebox.sh

# 国内服务器 (GitHub 访问困难) 可设置加速前缀:
GH_PROXY=https://ghfast.top/ bash <(curl -fsSL https://ghfast.top/https://raw.githubusercontent.com/mutsuki14/Sing-xray-onebox/claude/linux-vps-proxy-script-1m1ksn/onebox.sh)
```

运行后选择 **1. 安装**，依次选择协议组合、伪装站点、证书方式与端口（直接回车即使用推荐的默认值），脚本会完成其余全部工作。

## 协议组合

| 编号 | 组合 | 内核 | 说明 |
|---|---|---|---|
| 1 | VLESS-Reality-Vision + Hysteria2 + TUIC | sing-box | **推荐**。无需域名，TCP 与 UDP 协议互为备份 |
| 2 | VLESS-Reality-Vision + VLESS-XHTTP-Reality + SS-2022 | Xray | Xray 官方推荐的 Reality 方案，Vision 与 XHTTP 共用 443 端口 |
| 3 | Reality-Vision、XHTTP (Xray) + Hysteria2、TUIC、AnyTLS (sing-box) | 双内核 | 各取所长 |
| 4 | Reality / gRPC-Reality / Trojan / SS-2022 / Hysteria2 / TUIC / AnyTLS / ShadowTLS / VMess-WS | sing-box | 全家桶 |
| 5 | VLESS-WS-TLS + VMess-WS | sing-box | 可套 CDN，建议使用域名 |
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
| Hysteria2 | sing-box / Xray (实验性) | ✅ | ✅ | ✅ | ✅ | 自签 / ACME |
| TUIC-v5 | sing-box | ✅ | ✅ | ✅ | ❌ | 自签 / ACME |
| AnyTLS | sing-box | ✅ | ✅ | ✅ | ❌ | 自签 / ACME |
| ShadowTLS-v3 | sing-box | ❌ (无通用链接格式) | ✅ | ✅ | ❌ | 借用大站握手 |

> Xray 26 起对 gRPC / WebSocket / VMess / Trojan / Shadowsocks 输出“已弃用”警告，这些协议默认建议由 sing-box 承载；
> REALITY 建议使用 443 端口（Xray 会对非 443 端口给出警告）；两者都由 Xray 承载时，VLESS-XHTTP-Reality 默认与 Vision 共用 443 端口。
> Xray 承载 REALITY 时会启用官方推荐的 SNI 过滤，防止服务器被他人当作伪装站点 CDN 的免费中转。
>
> **关于 Xray 版本**：脚本默认安装经过测试的 Xray 26.3.27。更新的 Xray（26.4 之后）REALITY 服务端要求客户端支持
> X25519MLKEM768，会拒绝 sing-box 客户端，因此 `onebox update xray` 会先提示确认；也可用 `--xray-version latest` 显式指定。

## 使用自己的域名作为 REALITY 网站

安装时、首次添加 REALITY 协议时，或执行 `onebox sni` 更换目标时，在 REALITY 目标站点菜单选择 **7. 自有域名一键建站**，输入域名和网站标题，再选择是否启用 **HTTPS 443 入口**（新建时默认开启）。
脚本会建立一个可直接访问的主页，为该域名申请 Let's Encrypt 证书，并将 REALITY 的握手目标设为本机网站。
开启 443 入口后，直接访问 `https://你的域名/`：如果 REALITY 已监听 TCP 443，则复用其网站回落；否则由独立 nginx 监听 443，并反代到本机网站的内部 HTTPS 端口。已有网站升级时保持原设置，可手动开启。
已有节点切换此模式时保留 UUID 与 REALITY 密钥，客户端需要更新 SNI，或重新导入生成的配置。

开始前需要：

- 将域名的 A / AAAA 记录直接解析到此 VPS 的公网地址；使用 Cloudflare 等 DNS 服务时关闭该记录的 CDN 代理。配置了 AAAA 时，对应 IPv6 地址也必须可达。
- 在云安全组中放行 **TCP 80** 和实际使用的 **REALITY TCP 端口**。TCP 80 用于网站访问和证书申请、自动续期，需持续可达。
- 确保 TCP 80 未被其他程序占用。脚本使用独立 nginx 实例，不接管现有 nginx 网站；发现端口冲突会明确报错。
- 开启 443 入口还需在云安全组放行 **TCP 443**。其他程序或非 REALITY 协议占用该端口时，请先释放端口或关闭此选项；UDP 443 可以继续使用。

```bash
# 新安装：默认协议组合 + 自有域名网站
bash onebox.sh install --preset 1 --reality-site www.example.com --site-title "我的手记" -y

# 已安装：将 REALITY 目标切换为自己的域名
onebox sni --reality-site www.example.com --site-title "我的手记"

# 添加 REALITY 协议时启用自有域名网站
onebox add vless-reality --reality-site www.example.com

# 查看网站地址、文件位置和证书信息；必要时手动强制续期
onebox site info
onebox site renew

# 已建站：开启/关闭标准 HTTPS 入口，也可在网站管理菜单中设置
onebox site https on
onebox site https off

# 无交互安装时显式指定（off 保持通过 REALITY 实际端口访问）
bash onebox.sh install --preset 1 --reality-site www.example.com --site-https on -y
```

`onebox site` 与 `onebox site info` 等效。`--reality-site` 不能与 `--sni` 或 `--reality-dest` 同时使用。

网站与代理的连接方式：

| 流量 | 处理方式 |
|---|---|
| 浏览器访问 HTTP 80 | nginx 提供 ACME 验证文件，其余请求跳转到网站 HTTPS 地址 |
| 开启网站 443 入口 | 已有 REALITY 443 时复用；否则 nginx 通过 HTTPS 反代内部网站，访问地址不带端口号 |
| 浏览器访问 REALITY 公网端口 | REALITY 将普通 TLS 请求转给本机 nginx，呈现网站 |
| 合法 REALITY 客户端 | 由相应 sing-box / Xray 核心处理代理流量 |
| nginx 的 HTTPS 监听 | 仅监听 `127.0.0.1`；优先分配 8444，冲突时尝试 9444 等空闲端口，无需对公网开放 |

网站地址优先使用监听 443 的 REALITY 入站；没有 REALITY 443 时，地址会包含实际端口，例如 `https://www.example.com:8443/`。
脚本提供的本机 HTTPS 网站启用 TLS 1.3 和 HTTP/2；网站使用独立的 acme.sh 目录管理证书与续期任务。

默认主页位于 **`/var/lib/onebox-site/index.html`**，可直接编辑 HTML 替换内容；`onebox regen` 不会覆盖用户修改后的主页。
其他代理协议使用 HTTP 验证证书时，启用网站会将验证迁移到网站目录，避免争用 80 端口；停用网站时恢复 standalone 验证。
切换回外部 REALITY 目标，或删除最后一个 REALITY 协议时，脚本停止托管网站和其续期任务，但保留网页内容。
执行 `onebox uninstall` 会删除托管网站及其管理文件，保留系统安装的 nginx 软件包。

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
onebox sni [--sni 域名]    更换 REALITY / ShadowTLS 伪装站点 (凭据不变)
onebox sni --reality-site 域名   使用自有域名一键建站并设为 REALITY 目标
onebox site [info|renew]    查看托管网站信息 / 强制续期网站证书
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

正式安装前可先执行 `onebox plan` 或 `bash onebox.sh install --dry-run`，附带下面相同的安装选项。预演只读取当前环境，列出协议、建议端口、冲突及会涉及的服务/文件；不联网、不预留端口、不安装依赖，也不申请证书。自动端口、DNS、CA 和公网可达性仍需在实际安装时校验。

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
| `--reality-site <域名>` | 自有域名 REALITY 网站，自动建站、申请证书与续期；不能与 `--sni` / `--reality-dest` 同用 |
| `--site-title <标题>` | 自动生成主页的标题（默认“山间手记”；已有主页不会被覆盖） |
| `--site-https on\|off` | 自建网站的域名 443 入口，新建默认开启；已有网站可用 `onebox site https on` 开启 |
| `--tls self\|acme\|cf` | 证书方式：自签 / ACME HTTP 验证 / ACME Cloudflare DNS 验证 |
| `--domain <域名>` | 证书域名 |
| `--addr <IP或域名>` | 客户端连接地址（默认自动检测公网 IP） |
| `--name <名称>` | 节点名称前缀 |
| `--port <协议>=<端口>` | 指定端口，可重复 |
| `--hy2-hop <起-止>` | Hysteria2 端口跳跃范围 |
| `--hy2-obfs` | Hysteria2 启用 salamander 混淆 |
| `--hy2-core singbox\|xray` | Hysteria2 服务端内核（默认 sing-box，Xray 为实验性） |
| `--xray-version <版本\|latest>` | 指定 Xray 版本（默认 26.3.27） |
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
| `/var/lib/onebox-site/index.html` | 自有域名网站主页，可直接编辑；具体管理路径见 `onebox site info` |
| `/opt/onebox/bin/` | sing-box / xray 内核 |
| `onebox-sing-box`、`onebox-xray` | 系统服务名 (systemd / OpenRC) |
| `/usr/local/bin/onebox` | 管理命令 |

## 常见问题

**安装成功但连不上？**
1. 在云服务商控制台的安全组 / 防火墙中放行对应端口（TCP 与 UDP 分别放行，Hysteria2 / TUIC 使用 UDP；
   启用了 Hysteria2 端口跳跃时还需放行整个 UDP 端口范围；使用 ACME HTTP 验证时需放行 TCP 80，续期同样需要）。
   本机防火墙（ufw / firewalld / iptables / nftables）由脚本自动放行，并在开机时由 `onebox-net` 服务自动恢复。
2. `onebox status` 与 `onebox log` 检查服务状态。
3. REALITY 连接失败时尝试更换伪装站点：`onebox sni`（或菜单 15，UUID 与密钥保持不变），站点需支持 TLS 1.3，且尽量与服务器地理位置接近。

**REALITY 伪装站点怎么选？** 选择支持 TLS 1.3 / H2、非 CDN 回源、在国内可正常访问的大站，例如 `www.microsoft.com`、`www.apple.com`、`addons.mozilla.org`。脚本会自动检测所选站点是否支持 TLS 1.3。
也可在目标菜单选择 7，使用自己的域名一键建站；准备要求与管理方式见上文“使用自己的域名作为 REALITY 网站”。

**国内 VPS 下载失败？** 设置 `GH_PROXY=https://ghfast.top/`（或其他可用的 GitHub 加速前缀）后重新运行。

**纯 IPv6 VPS？** GitHub 不支持 IPv6，下载内核需要借助支持 IPv6 的 GitHub 加速前缀（如 `GH_PROXY=https://ghproxy.net/`）或先配置 WARP / NAT64。
配置了 WARP 时，脚本会识别出 WARP 出口地址（不能用于入站连接），默认改用本机 IPv6 作为客户端连接地址。

**支持哪些老系统？** CentOS 7 与 Debian 10 已停止维护，脚本会自动把软件源切换到 vault.centos.org / archive.debian.org。
sing-box 使用 musl 静态构建，不依赖系统 glibc 版本。

**SS-2022 / ShadowTLS / VMess 连接失败？** 这些协议对时间敏感：SS-2022 要求服务器与客户端时间误差在 30 秒以内，VMess 为 120 秒。
脚本安装时会检测服务器时间偏差，请开启时间同步（`timedatectl set-ntp true` 或安装 chrony）。

## 日常管理与故障恢复（1.3.0）

| 需求 | 命令或菜单 |
|---|---|
| 只读体检 | `onebox doctor`，菜单 17 |
| 证书有效期、续期任务和最近结果 | `onebox cert status`，菜单 18 |
| 本机备份与恢复 | `onebox backup 标签`、`onebox backups`、`onebox restore ID`，菜单 19 |
| 本地脱敏诊断包 | `onebox support`，菜单 20 |
| 检查更新、选择渠道 | `onebox update-check`、`onebox update-channel stable`，菜单 21 |
| 安装前预演 | `onebox plan --preset 6`，菜单 22 |
| 网站模板、标题、导入及恢复 | 菜单 16 → 网站内容管理 |

体检分别检查核心服务/配置、监听端口、DNS、证书、网站内部 HTTPS 和对外入口。本机探测成功不代表公网可达；云安全组和外部网络需要从另一台设备验证。返回码 `0` 表示通过，`1` 表示发现错误，`2` 表示只有提示或部分检查无法完成。命令不安装依赖、不改配置或服务，核心检查的临时文件单独隔离并清理。

证书面板会明确区分过期、临期、名称不匹配及续期结果未知。通过 `onebox cert-renew proxy` / `onebox site renew` 发起的续期会记录结果。新的网站定时任务使用 `onebox cert-renew site --cron`，只检查该域名、未到期不强制签发；旧任务在下次应用站点配置时迁移。外部工具或尚未接入记录的历史任务，其最近结果显示未知，发现 crontab 也不等同于任务已经成功执行。

### 网站内容

```bash
onebox site preview profile --title '我的主页' --theme ocean
onebox site template profile --title '我的主页' --description '作品与日常记录' --theme ocean
onebox site title '新的标题'
onebox site import /root/my-static-site
onebox site restore latest
```

模板可选 `minimal`、`profile`、`docs`，配色可选 `forest`、`ocean`、`slate`。预览仅生成私有目录内的 HTML 文件，下载该文件即可查看，线上内容不会变化。导入目录需有 `index.html`，不执行其中的文件；拒绝符号链接、特殊文件、系统目录及递归导入。每次发布前备份完整原网站，失败恢复旧内容；当前 ACME 验证目录会保留。导入或手工改过的页面不会被“修改标题”自动覆盖，请编辑源网页后重新导入。内容备份位于 `/etc/onebox/site/content-backups/`，发布结果会显示备份 ID。

### 节点快照

常规配置变更前和成功应用后自动保存快照，默认路径 `/etc/onebox/backups/`，保留最近 5 份。快照包含节点凭据、受管证书/私钥、客户端文件和当前网站内容，因此目录权限为 `700`、文件为 `600`；它与可以用于求助的诊断包用途不同。自动备份失败会明确警告，已有快照保留，配置操作仍可继续；手动恢复前的当前备份必须成功。

恢复只支持同一脚本主版本及相同受管路径，会校验快照完整性、重新生成并校验核心配置，再恢复服务；失败尝试回滚。默认每份快照最多 64 MiB / 4096 个文件，可用 `ONEBOX_BACKUP_MAX_BYTES` 调整字节上限。不会备份内核程序或恢复系统软件；外部自定义证书保持引用，ACME 重新绑定可能需要联网和现有 DNS 凭据。它用于本机配置恢复，不是跨 VPS 迁移工具。

### 诊断包

`onebox support` 在 `/etc/onebox/support/` 生成权限为 `600` 的压缩包，仅收集白名单系统/服务状态和体检结果，并进一步屏蔽已知凭据。不打包原始日志、配置、私钥、订阅或环境变量，也不自动上传。报告仍可能含域名、IP 和本机路径，分享前请自行查看。

### 更新与发布

`onebox update` 只更新 sing-box / Xray 内核（可指定版本，如 `onebox update singbox 1.14.2`；新内核不接受当前配置时自动恢复旧版本）。
更新管理脚本和菜单功能请执行 `onebox update-script`（菜单 13），成功后用 `onebox version` 核验版本，再执行 `onebox` 打开新菜单；更新会重新生成配置，凭据不变。
新版更新器会拒绝降级；下载内容与已安装脚本完全一致时跳过替换和配置应用，同版本号但内容有变化时仍可更新。

默认渠道为 `stable`，优先使用最新正式 GitHub Release 的版本标签；仓库还没有 Release 时会明确提示并回退默认分支。`testing` 跟随默认开发分支。API 限流、网络或服务器错误不会静默切换渠道。`onebox update-channel testing` 保存偏好，`onebox update-script testing` 只覆盖当次操作；`ONEBOX_SCRIPT_URL` 显式地址仍优先。菜单首页显示运行版本和渠道，`onebox update-check` 展示已安装/远端版本及发布摘要，且不替换文件。

维护者推送与 `SCRIPT_VERSION` 一致的 `vX.Y.Z` 标签后，Release 工作流检查该提交属于默认分支，运行更新相关测试，再发布 `onebox.sh` 和 `SHA256SUMS`。客户端按标签获取同一份源码；下载 Release 资产时可用校验文件检查完整性。

**旧版 1.0.0 更新脚本失败，或更新后菜单没有变化？** 旧版默认从 `main/onebox.sh` 下载，但本仓库的默认分支是 `claude/linux-vps-proxy-script-1m1ksn`，旧地址会返回 404。
在 VPS 的 root 终端执行下面的一次性迁移命令，无需重装节点：

```bash
ONEBOX_SCRIPT_URL=https://raw.githubusercontent.com/mutsuki14/Sing-xray-onebox/claude/linux-vps-proxy-script-1m1ksn/onebox.sh onebox update-script
onebox version
onebox
```

非 root 用户可在上述更新命令前加 `sudo env`，并把 `onebox` 换成完整路径 `/usr/local/bin/onebox`。这只临时覆盖本次下载地址，升级后使用新脚本的正确默认地址。
旧版若已替换文件但提示“配置重新生成失败”，当前菜单可能仍显示旧版本；退出菜单后用 `onebox version` 核验，并保留失败信息。
如果仍无法更新，请提供 `onebox version` 和 `onebox update-script` 的完整输出，以便区分下载失败与配置应用失败。

**使用已有证书（certbot 等）？** 选择“使用已有证书文件”时脚本直接引用原文件，续期后 sing-box 自动加载新证书；
Xray 需要重启，可在 certbot 的续期钩子中加入 `onebox restart`（例如 `--deploy-hook "onebox restart"`）。
不受公共 CA 信任的证书（如 Cloudflare 源证书）会被识别出来，直连客户端改为固定证书指纹。

**安全相关的默认设置**：服务端拒绝通过代理访问内网、回环地址以及本机自身的公网地址（防止借代理访问 VPS 上只对防火墙开放的服务）；
屏蔽 BT；Xray 不记录访问日志；日志目录权限 700；mihomo / sing-box 客户端控制接口带随机密钥；Cloudflare Token 输入不回显。

**修改失败会不会把节点搞坏？** 不会。所有修改（添加 / 删除协议、改端口、换证书、重装等）都会先用内核校验新配置，
校验通过后才替换；若新配置下服务无法启动，脚本会自动回滚到修改前的配置并以非零状态退出。
更换证书时若申请失败、配置无法生效或中途按 Ctrl-C，证书文件、acme.sh 的域名配置与 Cloudflare 凭据、临时放行的 80 端口也会一并恢复。

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
