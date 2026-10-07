# Sing-Xray-Onebox

**sing-box / Xray 多协议组合 · 交互式一键安装与管理脚本**

当前版本：**v1.6.0**。默认分支：[`main`](https://github.com/mutsuki14/Sing-xray-onebox/tree/main)。

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
- **自有域名 REALITY 网站**：使用自己的域名一键生成可编辑的主页、申请 Let's Encrypt 证书并自动续期，普通浏览器与 REALITY 客户端共用公网入口。
- **管理与恢复**：只读安装预演、一键体检、证书状态、稳定/测试更新渠道、本机快照与手动恢复、静态网站模板和内容导入、本地脱敏诊断包。
- **链路与性能**：真实客户端链路测试、Hysteria2 拥塞与接收窗口调优、REALITY 一致性检查，以及带连续失败阈值、恢复冷却期的客户端多入口回退。
- **BBR 管理**：启用系统自带 TCP BBR，选择默认队列；集成 [byJoey/Actions-bbr-v3](https://github.com/byJoey/Actions-bbr-v3) 的标准版 / Max 版内核 Release，支持安装预览、指定版本与下载校验，保留旧内核。
- **FRP 服务端**：独立管理官方 frps，支持控制域名、强制 TLS 与 token、HTTPS 应用域名 / 泛域名、证书申请与续期、TCP/UDP 转发范围、客户端配置导出和失败回滚。
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
onebox bbr                 BBR / BBRv3 管理菜单 (非交互时显示状态)
onebox frps                FRP 服务端与域名管理
onebox uninstall           卸载
```

协议名称：`vless-reality` `vless-xhttp` `vless-grpc` `vless-ws` `vmess-ws` `trojan` `shadowsocks` `hysteria2` `tuic` `anytls` `shadowtls`

## BBR / BBRv3 管理

主菜单 **12** 或 `onebox bbr` 打开管理菜单。普通代理安装仍只尝试启用当前内核的 BBR；`--no-bbr` 可跳过。升级脚本、打开菜单和查看状态不会安装 Linux 内核。

```bash
onebox bbr status                      # TCP 算法、默认/实际队列、模块与已装内核
onebox bbr enable                      # 当前内核 BBR + fq，需要 root
onebox bbr enable fq_codel             # 还支持 fq_pie / cake，取决于内核
onebox bbr releases                    # 当前 CPU 架构的标准版 Release
onebox bbr install                     # 预览最新标准版，不安装
onebox bbr install latest --apply      # 安装前再次确认，需要 root
onebox bbr install x86_64-7.2.8 --apply # 示例：标签应以 releases 实际输出为准
onebox bbr releases --max
onebox bbr install latest --max        # 预览 Max 实验版；安装仍需 --apply
```

无人值守安装必须显式指定 `--apply -y`。普通预览需要联网查询 Release，但不安装依赖、不修改 sysctl/引导。状态查询不联网，也不要求 root。`onebox bbr` 在非交互环境只显示状态；自动化启用 BBR 请使用 `onebox bbr enable`。

| 功能 | 条件与行为 |
|---|---|
| 启用当前内核 BBR | 适用于提供 `tcp_bbr` 的系统；需要 `flock`（util-linux）。OpenVZ 不支持，其他容器受宿主机能力限制 |
| 安装 BBRv3 Linux 内核 | Debian 12+ / Ubuntu 24.04+，x86_64 / aarch64，用户空间架构匹配；不支持容器、WSL、设备树 / U-Boot / 厂商引导链 |
| 引导与空间检查 | 已有 GRUB 和可回退的当前内核、initrd、模块；EFI 必须确认 Secure Boot 关闭；`/boot` 至少空闲 512 MiB，根分区 2 GiB，临时目录容纳下载包并留 256 MiB |
| 依赖 | `jq`、curl 或 wget、apt-get、dpkg、dpkg-deb、dpkg-query、sha256sum、update-grub、flock；缺失时提示手动安装 |
| Release 选择 | 按 CPU 与标准/Max 类型过滤，排除草稿和预发布；在最近最多 500 项中找到首个包含匹配版本的分页，按版本号排序。更早版本可指定完整标签 |
| 安装文件 | 仅 image + headers，校验 GitHub API 提供的 SHA-256、大小、URL、包名、架构和版本；不安装 linux-libc-dev 或调试包 |
| 失败与重启 | apt 使用 `--no-remove`，不删除旧内核；安装失败、引导生成失败时停止并提示修复。不会自动重启，也不改 GRUB 默认启动项 |

内核由 **[byJoey/Actions-bbr-v3](https://github.com/byJoey/Actions-bbr-v3)** 构建与发布，Onebox 独立实现下载、验证和安装流程，未复制或执行上游 `install.sh`。GitHub 元数据直连获取；`GH_PROXY` 只用于包下载，内容必须与直连元数据中的校验值一致。校验保证下载完整性，不替代对上游构建者的信任；缺少校验值的旧 Release 会被拒绝。最终下载记录保存在 `/var/lib/onebox-bbr/last-install.tsv`。

**安装前确认有 VPS 控制台访问和可恢复的磁盘快照。** 安装完成后选择维护时间手动重启，必要时在 GRUB 里选择新内核，再执行 `onebox bbr status`、`onebox bbr enable fq`。已安装包不代表正在运行，算法名称 `bbr` 也不证明是 v3；状态页分别报告运行内核、运行中的模块版本和磁盘模块版本。若新内核不能启动，从控制台 GRUB 的 Advanced options 选择保留的旧内核；修复引导前不要清理旧包。卸载 Onebox 不卸载 Linux 内核。

默认使用标准版；**Max** 提高探测与窗口策略的激进程度，仅用于自有链路吞吐实验，可能增加延迟、丢包和带宽争抢，不保证更快。上游的极限 sysctl 配置、测速软件安装、模块黑名单和快捷命令 `b` 不会自动应用。

BBR/队列配置保存到 `/etc/sysctl.d/99-onebox-bbr.conf`，应用失败恢复原运行参数并保留原文件。其他工具（包括上游的 `99-joeyblog.conf`）有相同参数时会提示检查覆盖关系。选择队列仅修改 `net.core.default_qdisc`，**不会替换正在运行的网卡队列或已有带宽整形规则**；查看 `tc qdisc show` 或状态页确认实际队列，新建队列/重启后再检查。系统 TCP BBR 与 Hysteria2/TUIC 的 QUIC 拥塞控制是不同层，后者继续使用 `onebox tune`。

## FRP 服务端与完整域名配置

`onebox frps` 管理独立的 [fatedier/frp](https://github.com/fatedier/frp) 服务端。默认安装 **0.71.0**，下载时校验官方 GitHub Release 的 SHA-256、文件大小与版本；可指定更新版本或 `latest`。配置预览用 `onebox frps plan`，实际安装 / 配置需要确认；无人值守时显式添加 `-y`。

| 模式 | 用途与公网入口 | 内部连接 |
|---|---|---|
| `web`（默认） | 浏览器通过应用域名的 HTTPS 443 访问内网网站；支持单域名或一级泛域名 | 独立 Nginx 终止 HTTPS，保留 Host 反代到 `127.0.0.1:7080` 的 frps HTTP 入口；客户端使用 `type = "http"` |
| `tcp` | 通过控制域名与选定公网端口访问内网 TCP / UDP 服务 | 仅开放配置的转发范围，默认 `20000-20100`；不启用网站虚拟主机或 Nginx |

两种模式均默认使用 TCP 7000 建立 frpc → frps 控制连接，强制 TLS、生成随机 token，并认证心跳和新工作连接。不启用 Dashboard。网站模式的 HTTP 入口仅监听回环，不直接开放公网 TCP/UDP 转发；需要通用公网端口转发时选择 `tcp` 模式。

### 准备 DNS 与端口

先在 DNS 服务商处手动添加记录，脚本会检查解析结果，但不会替你创建或修改 DNS 记录。

| 记录示例 | 用途 | 指向 |
|---|---|---|
| `frp.example.com` | 两种模式都需要的控制域名 | VPS 的公网 A；使用 IPv6 时同时配置正确 AAAA |
| `app.example.com` | 单应用网站模式的访问域名 | 同一 VPS 的公网 A / AAAA |
| `*.apps.example.com` | 泛域网站模式，例如 `home.apps.example.com` | 同一 VPS 的公网 A / AAAA |

所有已发布的 A / AAAA 必须指向当前 VPS；残留的旧 IP、错误 AAAA 或 CDN 代理地址会导致预检失败。Cloudflare 等服务的记录请设为 **仅 DNS，关闭 CDN 代理**。主机有可用 IPv6 时，控制服务默认使用 `::` 监听；否则使用 IPv4。云安全组也需放行控制端口，以及所选模式的 HTTPS / HTTP 入口或 TCP/UDP 转发范围。

安装会检查已有代理、REALITY 网站、Hysteria2 跳跃范围和其他进程的端口；冲突时停止，不接管已有服务。已有 443 / 80 占用时，可为 FRP 选择 **8443 + Cloudflare DNS 验证 + `--redirect-port 0`**，访问地址相应为 `https://app.example.com:8443/`。HTTP-01 必须使用并持续开放 TCP 80，不能用其他端口替代。

### 安装网站模式

```bash
# 只读预览：控制域名 + 应用域名，默认使用 HTTP-01 申请网站证书
onebox frps plan --mode web --domain frp.example.com --web-domain app.example.com

# 实际安装：HTTPS 443，HTTP 80 自动跳转至 HTTPS，并用于证书验证
onebox frps install --mode web --domain frp.example.com --web-domain app.example.com --tls http

# 导出给内网机器：示例网站运行在该机器的 127.0.0.1:8080
onebox frps client /root/frpc-home --type http --local-port 8080
```

若需避开已占用的 80 / 443，使用 Cloudflare DNS API token 申请证书。相关凭据由独立的 FRP ACME 配置保存以便续期，不要提交到仓库或分享给他人。

```bash
CF_Token='替换为你的 DNS API Token' onebox frps install \
  --mode web --domain frp.example.com --web-domain app.example.com \
  --tls cf --https-port 8443 --redirect-port 0
```

泛域名模式需要 Cloudflare DNS 验证或自备泛域证书，HTTP-01 不支持。下例导出 `home.apps.example.com` 的客户端；每台内网机器可选择不同的一级子域标签。

```bash
CF_Token='替换为你的 DNS API Token' onebox frps install \
  --mode web --domain frp.example.com --subdomain-host apps.example.com --tls cf
onebox frps client /root/frpc-home --type http --local-port 8080 --subdomain home

# 自备网站 fullchain 与未加密私钥：证书需覆盖应用域名；泛域模式需同时覆盖根域和 *.根域
onebox frps configure --tls custom --cert /root/fullchain.pem --key /root/privkey.pem
```

### 安装 TCP / UDP 模式

```bash
onebox frps install --mode tcp --domain frp.example.com --allow-ports 45000-45100

# 公网 frp.example.com:45001 → 内网机器 127.0.0.1:22
onebox frps client /root/frpc-ssh --type tcp --local-port 22 --remote-port 45001

# UDP 服务示例：公网 45002 → 内网机器 127.0.0.1:27015
onebox frps client /root/frpc-udp --type udp --local-port 27015 --remote-port 45002
```

`--remote-port` 必须落在已配置范围内。整个范围会为 FRP 预留并按 TCP / UDP 放行，即使某个端口尚无客户端连接；后续配置代理时也会避开 FRP 的保留端口。目标服务自身的登录、访问控制等设置仍由该服务管理。

### 客户端配置与证书

导出目录必须尚不存在。目录权限为 `700`，文件为 `600`，包含 `frpc.toml`、公开的 `ca.pem` 和使用说明；配置含 token，**不包含 CA 私钥、服务端私钥或网站私钥**。在内网机器安装与服务端相同版本的官方 frpc，私密传输整个导出目录，然后先进入该目录再运行：

```bash
cd /path/to/frpc-home
frpc verify -c frpc.toml
frpc -c frpc.toml
```

配置中的 `transport.tls.trustedCaFile = "./ca.pem"` 与控制域名校验必须保留；仅开启 TLS 而移除 CA 文件会失去服务端证书验证。网站模式已经生成 HTTPS 协议转发头，Nginx 支持 WebSocket。改变控制域名或执行 `rotate-token` 后，需要重新导出并更新各客户端配置。

控制连接和浏览器网站使用两套证书：控制连接由私有 CA 签发（CA 有效期约 10 年，服务端证书 397 天）；浏览器使用 ACME 公有证书或自备证书。每日计划任务检查续期，控制证书变化时才重启 frps，网站证书更新后 reload 独立 Nginx。网站证书通过 HTTP-01 续期时，需要保持 HTTP 80 入口可达。自备网站证书不自动申请或续期；更新原证书文件后执行 `onebox frps configure --tls custom --cert ... --key ...`。私有 CA 临近到期会明确报错，需要人工规划 CA 轮换和客户端重新分发。

### 管理与参数

```bash
onebox frps info                          # 域名、端口、配置与证书位置
onebox frps status                        # 独立 FRP 服务状态
onebox frps start                         # 也支持 stop / restart
onebox frps log                           # 服务日志
onebox frps configure --port 7001         # 调整配置，失败恢复原配置和服务状态
onebox frps update                        # 更新官方 FRP 稳定版
onebox frps update 0.71.0                 # 指定版本（最低支持 0.71.0）
onebox frps renew                         # 检查控制证书并续期托管网站证书
onebox frps rotate-token                  # 更换 token，随后重新导出客户端
onebox frps uninstall                     # 单独卸载 FRP
```

`plan` / `install` / `configure` 接受下列参数：

| 参数 | 含义 / 默认值 |
|---|---|
| `--mode web\|tcp` | 网站域名模式 / 通用 TCP、UDP 模式，默认 `web` |
| `--domain 域名` | FRP 控制域名，两种模式都必填 |
| `--web-domain 域名` / `--subdomain-host 根域` | 网站模式使用单应用域名或泛域名根，二选一 |
| `--port 7000` | 控制连接端口 |
| `--http-port 7080` | 网站模式的内部回环 HTTP 端口，不对公网放行 |
| `--https-port 443` | 网站模式的公网 HTTPS 端口 |
| `--redirect-port 80` | HTTP 跳转入口；`0` 关闭。HTTP-01 必须为 `80` |
| `--allow-ports 20000-20100` | 通用模式允许的 TCP / UDP 转发范围 |
| `--tls http\|cf\|custom` | 网站证书验证方式；不改变控制连接的私有 CA 方案 |
| `--cert 文件 --key 文件` | 自备网站证书 fullchain 与未加密私钥 |
| `--version 0.71.0\|latest` | 官方 frp 版本，最低支持 `0.71.0` |

FRP 的状态、证书、防火墙台账、服务与续期任务独立管理；普通 `onebox uninstall` 保留 FRP 及所需管理命令，删除 FRP 请使用 `onebox frps uninstall`。防火墙仅清理本功能记录的规则，已有用户规则保留。安装、配置与更新使用临时事务备份，失败时尝试恢复旧文件、服务与防火墙；恢复未完成时保留备份并提示处理位置。**代理的 `onebox snapshot` 不包含 FRP**，FRP 当前没有公开的历史快照 / 手动恢复命令。

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
| `/etc/onebox-frp/` | 独立 FRP 状态、`frps.toml`、私有 CA / 服务端证书、网站证书、Nginx 配置与防火墙台账 |
| `/opt/onebox-frp/frps` | 官方 FRP 服务端程序 |
| `/var/lib/onebox-frp/`、`/var/log/onebox-frp/` | FRP 网站验证目录、运行数据与日志 |
| `onebox-frps`、`onebox-frp-web` | FRP 控制服务与独立网站入口的系统服务名 |
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

默认渠道为 `stable`，优先使用最新正式 GitHub Release 的版本标签；仓库还没有 Release 时会明确提示并回退默认分支。`testing` 跟随默认分支 `main`。API 限流、网络或服务器错误不会静默切换渠道。`onebox update-channel testing` 保存偏好，`onebox update-script testing` 只覆盖当次操作；`ONEBOX_SCRIPT_URL` 显式地址仍优先。菜单首页显示运行版本和渠道，`onebox update-check` 展示已安装/远端版本及发布摘要，且不替换文件。

维护者推送与 `SCRIPT_VERSION` 一致的 `vX.Y.Z` 标签后，Release 工作流检查该提交属于默认分支，运行更新相关测试，再发布 `onebox.sh` 和 `SHA256SUMS`。客户端按标签获取同一份源码；下载 Release 资产时可用校验文件检查完整性。

**旧版 1.0.0 更新脚本失败，或更新后菜单没有变化？** 早期仓库没有 `main` 分支，旧版下载地址曾因此返回 404。现在 `main` 已建立并设为默认分支，包含最新代码。
若旧版仍更新失败，可在 VPS 的 root 终端执行下面的命令，显式从 `main` 更新，无需重装节点：

```bash
ONEBOX_SCRIPT_URL=https://raw.githubusercontent.com/mutsuki14/Sing-xray-onebox/main/onebox.sh onebox update-script
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

## 链路测试、调优与回退（1.4.0）

菜单 **23** 提供探测配置导出和 REALITY 本机检查，菜单 **24** 提供调优。`onebox.sh` 内嵌客户端工具；日常安装不新增 Python 依赖，**运行探测/回退工具的客户端**需要 Bash 4+、Python 3.8+，以及对应的 sing-box / Xray 可执行文件。无需 root，不会启动系统服务。

### 真实链路测试

先在服务器导出，再将 `onebox.sh` 和导出的文件私密复制到实际使用代理的客户端。也可使用 `/etc/onebox/client/probe.json`，它随客户端配置一起生成。

```bash
# 服务器：目标文件必须不存在，权限为 0600；包含客户端凭据，不含服务端私钥
onebox probe export /root/probe.json

# 客户端：查看 ID，再从真实客户端网络进行测试
bash onebox.sh probe list probe.json
bash onebox.sh bench probe.json --output bench-before.json

# 自选、允许你进行测试的端点；下载最多读取 4 MiB，上传 POST 4 MiB
bash onebox.sh bench probe.json --entries vless-reality,hysteria2 \
  --download-url https://your-test.example/4MiB.bin \
  --upload-url https://your-test.example/upload --bytes 4194304 \
  --samples 5 --output bench-after.json
```

`--singbox /path/sing-box`、`--xray /path/xray` 可指定客户端内核，否则从 PATH 寻找。每个入口启动独立的临时原生客户端，所有测试请求通过该入口；没有直连兜底。目标域名由代理链路解析；代理服务器自身域名仍使用客户端本地 DNS。默认只访问 `https://www.gstatic.com/generate_204` 做轻量检测，`--url` 可替换为返回 2xx 的稳定端点；不跟随跳转，不关闭 TLS 校验。下载/上传只有显式传入 URL 才执行，上传端点应由你管理或授权使用。

报告包含逐次建连/目标 TLS 总耗时（`setup_ms`）、TTFB 的中位数与 P95、请求失败率、实测字节数与吞吐，以及传输期间的 TTFB、本机客户端内核 CPU 时间和结束时 RSS。吞吐包含建连开销，短测试不能代表最大带宽；请求失败率**不等于网络丢包率**，也不测 VPS CPU 或逐包 RTT。在 VPS 自己运行只代表该机器的路径，不能代表客户端到 VPS 的性能。报告不包含凭据、完整 URL 或原始日志；`--output` 不覆盖已有文件。存在失败时返回 1。

### Hysteria2 与资源调优

```bash
onebox tune status
onebox tune hy2 auto                         # 预览：原生 BBR 自动估计带宽
onebox tune hy2 conservative --apply         # 保守 BBR
onebox tune hy2 measured --up 20 --down 100 --apply
onebox tune resource low-memory --apply
onebox tune resource throughput --apply
onebox tune resource balanced --apply        # 撤销接收窗口覆盖，保留拥塞选择
onebox tune reset --apply                    # 恢复全部原生默认设置
```

命令默认只预览，`--apply` 才备份并应用；菜单中的“自动/保守/实测”等选项直接应用。配置经过内核校验，失败由原有事务恢复。可用 `onebox backups` / `onebox restore ID` 回到调优前的精确状态。应用后需重新导入客户端配置/探测文件，再用同一客户端、端点和参数对比报告。

| 选项 | 实际改变 | 适用范围 |
|---|---|---|
| `auto` | 服务端要求客户端使用 BBR，不指定固定带宽 | sing-box Hysteria2 服务端 |
| `conservative` | 上述行为 + `bbr_profile=conservative` | sing-box 服务端/客户端 ≥ 1.14；mihomo ≥ 1.19.32 |
| `measured` | 指定上传/下载 Mbps，选择 Hysteria 带宽控制；服务端方向自动反转 | sing-box Hysteria2 服务端；sing-box / mihomo 客户端 |
| `balanced` | 不覆盖内核接收窗口和并发默认值 | 原生默认行为 |
| `low-memory` | 流/连接接收窗口 2 / 5 MiB；服务端并发流上限 64 | sing-box Hysteria2 ≥ 1.14；客户端窗口同时输出到 mihomo |
| `throughput` | 流/连接接收窗口 16 / 40 MiB；服务端并发流上限 1024 | 同上；高时延/带宽链路需实测验证 |

`--up` 和 `--down` 始终以**客户端视角**填写，范围 1–10000 整数 Mbps。请依据可用带宽并留余量；随意填大数可能拥塞。窗口是上限而非预分配量，高并发下仍可能增加内存占用。保持 QUIC 默认 MTU 探测和握手特征设置，不关闭私网拦截。系统 TCP BBR、UDP socket buffer 和 QUIC 拥塞控制是不同层面的设置，本功能仅报告系统参数，不修改 sysctl。

这些调优不作用于 TUIC 或 Xray Hysteria2 服务端；不支持的服务端组合会明确拒绝。Xray 客户端和分享链接不携带这些新增调优字段，需要完整 sing-box / mihomo 配置才能复现实测设置。原有未调优的 sing-box 客户端仍兼容 ≥ 1.12。

### REALITY 一致性检查

```bash
onebox reality-check                           # 服务器：回环检查
bash onebox.sh reality-check probe.json         # 客户端：真实路径检查
bash onebox.sh reality-check probe.json --entries vless-reality \
  --url https://your-test.example/health --output reality-report.json
```

检查普通 TLS 访问的证书名称/信任链、TLS 1.3、h2、参考目标与节点的证书/ALPN/HTTP 状态/重定向一致性；比较页面前 64 KiB 摘要，内容不同给出警告。还会分别启动正确凭据和错误 short ID 的真实客户端，验证正常代理成功、错误凭据无法代理。动态页面或负载均衡证书可能产生差异，需要人工核对，不能仅据此认定被识别。

自建站的远端参考入口使用服务器的 HTTPS 443；未启用时提示无法从客户端比较，服务器回环检查仍比较实际内部端口。自有测试 CA 可通过 `--ca` 指定。只检查配置中的入口与参考站，不枚举其他目标。返回 0 表示所检项目通过，1 表示有失败，2 表示只有警告。普通 TLS 回落和错误凭据拒绝分别验证，不声称捕获了错误 REALITY 握手的完整指纹，也不保证不可识别。本机检查不证明公网可达。

### 客户端多入口回退

```bash
# 一个服务器：默认选首个 TCP 入口为主、首个 UDP 传输入口为备
bash onebox.sh failover probe.json

# 不同服务器/IP：分别导出，然后在客户端合并（不复制服务端私钥）
bash onebox.sh probe merge combined.json server-a.json server-b.json
bash onebox.sh probe list combined.json
bash onebox.sh failover combined.json \
  --entries n1-vless-reality,n2-hysteria2 \
  --port 2080 --interval 15 --failures 3 --recoveries 3 --cooldown 60
```

应用程序连接 `socks5h://127.0.0.1:2080`，域名应通过 SOCKS 发送。`--entries` 从左到右为优先级，支持 2–8 个入口；没有 TCP+UDP 组合时可显式选择两个入口。每轮经各入口请求健康端点，连续失败达到阈值才切换，优先入口连续恢复且冷却期到期才切回；全部失败时拒绝新连接，不直连。冷却期不妨碍从已经故障的入口紧急切走。

这是前台运行的 **SOCKS5 CONNECT/TCP** 工具：Hysteria2/TUIC 入口可用 UDP 传输承载这些 TCP 流，但本地接口不提供 SOCKS UDP ASSOCIATE、HTTP 代理或 TUN；游戏等原生 UDP 应用继续使用完整客户端配置。只切换新连接，不迁移或主动切断已有连接。Ctrl+C 会清理临时内核、配置与监听端口。监听仅限本机，临时内核另设随机认证；每个所选入口运行一个内核，低内存设备建议只选两个。最多同时处理 128 条连接，空闲连接 5 分钟回收。

同 IP 的多协议能应对部分协议/传输故障，不能应对整个 IP 不可达；IP 冗余需要合并实际不同服务器的配置。健康端点失效也会触发切换，请使用稳定的自有端点。合并文件含所有入口的客户端凭据，保持私密。

## 测试

仓库自带的测试直接调用脚本的配置生成函数，在本机回环地址上运行真实的服务端与客户端：

```bash
python3 scripts/embed-runtime.py --check
python3 -m unittest discover -s tests -p 'test_*.py' -v
bash tests/performance.sh
bash tests/bbr.sh                      # 临时目录与命令 mock，不安装/删除内核、不重启
SB=/path/sing-box XR=/path/xray bash tests/client-runtime-e2e.sh
```

`lib/client_runtime.py` 是客户端工具源码，修改后运行 `python3 scripts/embed-runtime.py` 同步到单文件脚本；CI 检查两份代码一致。新增端到端用例覆盖带宽/窗口配置后的真实 Hysteria2、上传/下载、错误凭据、主入口中断与恢复；网站端到端用例包含 REALITY 一致性和错误 short ID 验证。

```bash
# 端到端: 每个 协议 × 服务端内核 × 客户端 (sing-box / Xray / mihomo / 分享链接) 组合均验证 TCP 与 UDP 连通
SB=/path/sing-box XR=/path/xray MH=/path/mihomo bash tests/e2e.sh

# 生命周期: 真实执行 install / add / del / port / reset / addr / start / stop / uninstall (会修改系统, 仅在容器或 CI 中运行)
ONEBOX_LIFECYCLE=1 SB=/path/sing-box XR=/path/xray MH=/path/mihomo bash tests/lifecycle.sh
```

完整协议矩阵的测试目标只能经由代理服务端访问（服务端将测试专用的域名 / TEST-NET 地址改写到本机），因此绕过代理的“假通过”会被判为失败。客户端工具测试另有错误凭据拒绝和真实入口中断用例。

## 免责声明

本项目仅供学习与研究网络技术使用，请遵守当地法律法规。
