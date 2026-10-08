# 安装与部署

本文说明系统要求、无人值守安装、端口、证书和 REALITY 目标。交互安装直接运行 `onebox`（或引导脚本）并选择 **1) 安装**，向导步骤见 [README](../README.md#安装向导)。

## 系统要求

| 项目 | 要求 |
|---|---|
| 系统 | Linux；systemd、OpenRC 或无 init 环境（容器）。可用 `ONEBOX_INIT=systemd\|openrc\|none` 强制指定 |
| 架构 | 预编译：`amd64`、`arm64`、`386`（i586 及以上）、`armv7`。其他架构需源码构建，并受上游内核支持限制 |
| 权限 | 安装和修改配置需要 root；`help`、`version`、`plan` 和客户端链路工具不需要 |
| 依赖 | `openssl`、`curl`、`iproute2` 缺失时通过 apt-get / dnf / yum / apk / pacman / zypper 自动安装；网站、独立订阅和 FRP 网站模式另需 nginx（同样自动安装） |
| 网络 | 下载内核需访问 GitHub；受限网络设置 `GH_PROXY` |

| 架构 | Release 资产 | Rust 目标 |
|---|---|---|
| x86_64 | `onebox-linux-amd64-musl` | `x86_64-unknown-linux-musl` |
| aarch64 | `onebox-linux-arm64-musl` | `aarch64-unknown-linux-musl` |
| i586 / i686 | `onebox-linux-386-musl` | `i586-unknown-linux-musl` |
| ARMv7 | `onebox-linux-armv7-musl` | `armv7-unknown-linux-musleabihf` |

## 安装预演

正式安装前可用相同的选项预演，结果只读：不联网、不预留端口、不安装依赖、不申请证书。

```bash
onebox plan --preset 1
onebox install --protocols vless-reality,hysteria2 --dry-run
onebox plan --preset 2 --json          # 机器可读输出
```

预演按当前主机的端口占用分配端口；DNS、证书和公网可达性在实际安装时才检查。

## 无人值守安装

`-y` 使用默认值并自动确认。首次运行可以把参数直接交给引导脚本：

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/mutsuki14/Sing-xray-onebox/main/onebox.sh) install --preset 1 -y
```

已安装 `onebox` 后：

```bash
# 推荐组合，全部默认值
onebox install --preset 1 -y

# 自定义协议与优先内核
onebox install --protocols vless-reality,hysteria2,anytls --core singbox -y

# 指定端口、伪装目标与 Hysteria2 端口跳跃
onebox install --protocols vless-reality,hysteria2 \
  --port vless-reality=443 --port hysteria2=8443 \
  --sni www.apple.com --hy2-hop 20000-40000 -y

# CDN 组合 + Cloudflare DNS 证书
CF_Token='DNS API Token' onebox install --preset 5 --tls cf --domain v.example.com -y

# 自有域名 REALITY 网站
onebox install --preset 1 --reality-site www.example.com --site-title '我的手记' -y

# 已安装时无人值守重装：必须加 --force（会生成全新凭据）
onebox install --preset 1 -y --force
```

已安装时，交互重装会先确认；`-y` 重装必须同时给出 `--force`，否则报错并提示改用 `onebox regen`（保留现有凭据重新生成配置）。

### 安装选项

| 选项 | 说明 |
|---|---|
| `--preset 1-7` | 协议组合（见 [README](../README.md#协议组合)）；7 为自定义，无人值守时需配合 `--protocols` |
| `--protocols a,b,…` | 自定义协议列表，逗号或空格分隔，按标准顺序保存 <!-- TODO: verify how --preset + --protocols together is handled --> |
| `--core singbox\|xray` | 两种内核都支持的协议优先使用的内核；预设各有默认值 |
| `--addr IP或域名` | 客户端连接地址，默认自动检测公网 IPv4，其次 IPv6 |
| `--name 名称` | 节点名称前缀，默认 `onebox`；客户端中显示为 `名称-协议` |
| `--port 协议=端口` | 指定端口，可重复 |
| `--sni 域名` | REALITY 与 ShadowTLS 的伪装域名，握手目标为 `域名:443` |
| `--reality-dest 主机:端口` | 单独指定 REALITY 握手目标（SNI 不变） |
| `--reality-site 域名` | 自有域名网站作为 REALITY 目标，见 [website.md](website.md)；不能与 `--sni`、`--reality-dest` 同用 |
| `--site-title 标题` | 自动生成主页的标题，默认“山间手记” |
| `--site-https on\|off` | 网站的标准 HTTPS 443 入口，默认 `on` |
| `--tls self\|acme\|cf\|custom` | 代理证书方式：自签 / HTTP-01（`http` 同 `acme`）/ Cloudflare DNS / 自备 |
| `--domain 域名` | 证书域名；不使用域名证书时，作为 VMess-WS 客户端发送的 Host（套 CDN） |
| `--cert 文件 --key 文件` | 自备证书的完整链与未加密私钥 |
| `--hy2-hop 起-止` | Hysteria2 UDP 端口跳跃范围（起始 ≥ 1024） |
| `--hy2-obfs` | Hysteria2 启用 salamander 混淆 |
| `--hy2-core singbox\|xray` | Hysteria2 的服务端内核，默认 sing-box（Xray 为实验性，且不支持调优） |
| `--singbox-version 版本\|latest` | 固定 sing-box 版本，默认最新稳定版 |
| `--xray-version 版本\|latest` | 固定 Xray 版本，默认 `26.3.27` |
| `--no-bbr` | 安装结束后不询问启用 BBR |
| `--force` | 允许 `-y` 覆盖已有安装 |
| `--json` | 仅 `plan`：输出 JSON |
| `--dry-run` | 仅 `install`：等同 `plan` |
| `-y` / `--yes` | 无人值守 |

每个命令只接受自己的选项，写错或不适用的选项会报错（`{命令} 不支持选项 {选项}`）。完整列表以 `onebox install --help` 为准。

### 环境变量

| 变量 | 作用 |
|---|---|
| `GH_PROXY` | GitHub 下载加速前缀，必须为 `https://`；校验信息仍以 GitHub 官方元数据为准 |
| `ONEBOX_NATIVE_BIN` | 引导脚本直接运行该本地程序，不联网 |
| `ONEBOX_SINGBOX_BIN` / `ONEBOX_XRAY_BIN` | 使用本地内核文件代替下载 <!-- TODO: verify still supported in v3 --> |
| `CF_Token`、`CF_Account_ID` | Cloudflare DNS 验证凭据；交互时也可隐藏输入 |
| `ONEBOX_AUTO=1` | 等同 `-y` |
| `ONEBOX_INIT` | 强制 init 类型：`systemd`、`openrc`、`none` |
| `NO_COLOR` | 关闭彩色输出 |

## 端口

端口按协议自动分配，先尝试候选端口，全部占用时使用 20000–20999 中第一个空闲端口：

| 协议 | 候选端口 |
|---|---|
| Shadowsocks-2022 | 8388、8389、8390 |
| VMess-WS | 8080、2082、8880 |
| 其他协议 | 443、8443、2053、2083、2087、2096、9443 |

空闲主机上的结果：预设 1 为 Reality 443/TCP、Hysteria2 443/UDP、TUIC 8443/UDP；预设 2 为 Reality 与 XHTTP 共用 443/TCP、SS-2022 8388/TCP+UDP。

规则：

- TCP 与 UDP 分别计算；只有同由 Xray 承载的 VLESS-Reality-Vision 与 VLESS-XHTTP-Reality 可以共用 TCP 端口。
- 自动分配会避开已在监听的端口，以及 Onebox 自己预留的端口：网站 80 / 443、网站内部端口 10443（仅本机回环）、REALITY 防偷跑端口（18000–19999，仅 Xray 承载 REALITY 时）、订阅端口 8448、HTTP-01 证书验证的 80、Hysteria2 跳跃范围、FRP 预留端口。
- 本机防火墙（ufw、firewalld、nftables、iptables）由程序自动放行，开机由 `onebox-network` 服务恢复；**云服务商安全组需要手动放行**，TCP 与 UDP 分开（Hysteria2、TUIC 为 UDP；端口跳跃需放行整个 UDP 范围）。
- 安装后修改端口：`onebox port 协议 端口`；冲突时报错且不修改。

## 证书

只有 VLESS-WS-TLS、Trojan-TLS、Hysteria2、TUIC、AnyTLS（以及启用 TLS 的 VMess-WS）需要代理证书；REALITY 类协议、SS-2022 和 ShadowTLS 不需要。

| 方式 | `--tls` | 条件 | 说明 |
|---|---|---|---|
| 自签 | `self` | 无 | 默认。EC P-256，有效期 10 年，SNI `www.bing.com`；完整客户端配置固定证书指纹 |
| Let's Encrypt HTTP-01 | `acme` / `http` | 域名 A/AAAA 直接解析到本机，TCP 80 可从公网访问 | 由内置验证服务或本机 Onebox 网站应答；续期同样需要 80 |
| Let's Encrypt DNS | `cf` | 域名托管在 Cloudflare | `CF_Token` 需要该区域的 DNS 编辑权限；不占用 80 端口 |
| 自备证书 | `custom` | 证书覆盖所用域名 | `--cert` 完整链、`--key` 私钥；复制到受管目录 |

```bash
onebox cert                                      # 查看代理与网站证书状态
onebox cert set --tls cf --domain v.example.com  # 更换代理证书方式
onebox cert set --tls custom --domain v.example.com --cert /root/fullchain.pem --key /root/privkey.pem
onebox cert renew proxy                          # 立即强制续期（自备证书：重新复制源文件）
```

- 证书由 acme.sh 3.1.6 申请（程序固定其 SHA-256）；Cloudflare 凭据只传给 acme.sh，并以 0600 权限保存供续期使用。
- 每天 04:17 的一个计划任务（`onebox renew --cron`）检查代理、网站和订阅证书，30 天内到期才续期，续期后只重启或重载相关服务。<!-- TODO: verify `onebox renew` output/flags -->
- 面向浏览器的网站和 HTTPS 订阅必须使用公有可信证书，不能自签。
- 更新了自备证书的源文件后执行 `onebox cert renew proxy`（网站用 `onebox site renew`）重新部署。

## REALITY 目标

REALITY 协议借用一个真实 HTTPS 站点完成握手。安装时可选：

| 选项 | 握手目标 |
|---|---|
| 1) Microsoft（默认） | `www.microsoft.com:443` |
| 2) Apple | `www.apple.com:443` |
| 3) 自定义域名 | `域名:443` |
| 4) 自有域名一键建站 | 本机网站，见 [website.md](website.md) |

选择建议：支持 TLS 1.3 与 HTTP/2、非 CDN 代理、在客户端所在网络可正常访问、地理位置靠近服务器的大站，例如 `www.microsoft.com`、`www.apple.com`、`addons.mozilla.org`。

```bash
onebox sni                                   # 交互更换（UUID 与密钥不变）
onebox sni --sni www.apple.com               # 同时更换 REALITY 与 ShadowTLS 目标
onebox sni --reality-dest 198.51.100.7:443    # 高级：SNI 不变，只改握手目标（如目标站的固定 IP）
onebox sni --reality-site www.example.com    # 改用自有域名网站
```

更换目标后客户端需要更新 SNI：重新导入配置，或刷新远程订阅。Xray 承载 REALITY 时只转发与配置 SNI 一致的握手（SNI 过滤），防止服务器被他人当作免费中转。

## 安装后调整

| 命令 | 作用 |
|---|---|
| `onebox add 协议 [--core …]` | 添加协议，自动分配端口；需要时自动准备证书 |
| `onebox del 协议` | 删除协议（至少保留一个；全部删除请用 `uninstall`） |
| `onebox port 协议 端口` | 修改端口 |
| `onebox addr [--addr …] [--name …]` | 修改客户端连接地址与节点名称 |
| `onebox sni` | 更换 REALITY / ShadowTLS 目标 |
| `onebox cert set …` | 更换代理证书 |
| `onebox reset` | 重置全部 UUID、密码与密钥（客户端需重新导入） |
| `onebox regen` | 按当前状态重新生成全部配置，凭据不变 |

每次修改都是一次事务：先渲染并用内核校验新配置，再停止旧服务、写入、启动；任一步失败自动恢复原状态。
