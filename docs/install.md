# 安装与部署

本文说明系统要求、无人值守安装、端口、证书和 REALITY 目标。交互安装直接运行 `onebox`（或引导脚本）并选择 **1) 安装**，向导步骤见 [README](../README.md#安装向导)。

## 系统要求

| 项目 | 要求 |
|---|---|
| 系统 | Linux；systemd、OpenRC 或无 init 环境（容器）。可用 `ONEBOX_INIT=systemd\|openrc\|none` 强制指定 |
| 架构 | 预编译：`amd64`、`arm64`、`386`（i586 及以上）、`armv7`。其他架构需源码构建，并受上游内核支持限制 |
| 权限 | 安装和修改配置需要 root；节点配置仅 root 可读，查看节点信息、导出客户端配置也需要 root。`help`、`version`、未安装时的 `plan`，以及使用探测配置文件的 `bench`、`failover` 不需要 root |
| 依赖 | `openssl`、`curl`、`iproute2` 缺失时通过 apt-get / dnf / yum / apk / pacman / zypper 自动安装；使用 Let's Encrypt 证书时还需要 cron（缺失时自动安装并启动）；网站、独立 HTTPS 订阅和 FRP 网站模式另需 nginx（同样自动安装） |
| 网络 | 引导脚本下载程序，以及 Onebox 下载代理内核、FRP、BBRv3 内核包和程序更新，都需访问 GitHub。设置 `GH_PROXY` 后引导脚本的下载全部经前缀；Onebox 自己的下载只有文件本身经前缀，Release 元数据（api.github.com）、缺少摘要时的 `SHA256SUMS` / `.dgst`（github.com），以及 Let's Encrypt 证书所需的 acme.sh 脚本（raw.githubusercontent.com）始终直连，主机必须能直接访问这些地址（见下文[环境变量](#环境变量)中的信任说明）。安装时还会访问 api.ipify.org / api6.ipify.org 检测公网地址（检测失败时用 `--addr` 指定） |

| 架构 | Release 资产 | Rust 目标 |
|---|---|---|
| x86_64 | `onebox-linux-amd64-musl` | `x86_64-unknown-linux-musl` |
| aarch64 | `onebox-linux-arm64-musl` | `aarch64-unknown-linux-musl` |
| i586 / i686 | `onebox-linux-386-musl` | `i586-unknown-linux-musl` |
| ARMv7 | `onebox-linux-armv7-musl` | `armv7-unknown-linux-musleabihf` |

## 安装预演

正式安装前可用相同的选项预演，结果只读：不写文件、不联网、不安装依赖、不申请证书。

```bash
onebox plan --preset 1
onebox install --protocols vless-reality,hysteria2 --dry-run
onebox plan --preset 2 --json          # 机器可读输出
```

输出每个协议的内核、端口和传输层（如 `vless-reality | singbox | 443/tcp`）。预演按当前主机的端口占用分配端口；公网地址检测、证书申请（以及它依赖的 DNS 解析和 80 端口可达性）在实际安装时才进行。`--json` 只能用于 `plan` 和 `install --dry-run`。

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

# CDN 组合 + Cloudflare DNS 证书：Token 隐藏输入后导出，避免写进 shell 历史
read -rs CF_Token && export CF_Token
onebox install --preset 5 --tls cf --domain v.example.com -y

# 自有域名 REALITY 网站
onebox install --preset 1 --reality-site www.example.com --site-title '我的手记' -y

# 已安装时无人值守重装：必须加 --force（会生成全新凭据并清除订阅设备）
onebox install --preset 1 -y --force
```

- 既没有终端输入、也打不开 `/dev/tty` 时（例如 cron、CI、不分配终端的 `ssh 主机 onebox install …`）同样按无人值守处理；在终端里执行的脚本仍会进入交互向导，脚本中请始终加 `-y`。无人值守时无法检测公网地址会报错，请用 `--addr` 指定。
- 已安装时，交互重装会先确认（`重新安装会生成新凭据并清除订阅设备，继续？`）；`-y` 重装必须同时给出 `--force`，否则报错并提示改用 `onebox regen`（保留现有凭据重新生成配置）。v2 的 `-y` 重装会直接覆盖，v3 改为必须加 `--force`。

### 安装选项

与 `onebox install --help` 一致（`onebox plan` 接受同样的选项）：

| 选项 | 说明 |
|---|---|
| `--preset 1-7` | 协议组合编号（见 [README](../README.md#协议组合)）；7 为自定义，无人值守时配合 `--protocols` |
| `--protocols 列表` | 协议 ID 列表，逗号或空格分隔，按标准顺序保存。与 `--preset` 二选一，只有 `--preset 7` 可以同时给出 |
| `--core singbox\|xray` | 两种内核都支持的协议优先使用的内核；预设各有默认值，`--protocols` 默认 sing-box（Hysteria2 由 `--hy2-core` 决定） |
| `--addr IP或域名` | 客户端连接地址，默认自动检测公网 IPv4，其次 IPv6 |
| `--name 名称` | 节点名称前缀，默认 `onebox`；客户端中显示为 `名称-协议`（如 `onebox-Hysteria2`） |
| `--port 协议=端口` | 指定协议端口，可重复 |
| `--sni 域名` | REALITY 与 ShadowTLS 的伪装域名，握手目标为 `域名:443` |
| `--reality-dest 主机:端口` | 单独指定 REALITY 握手目标（SNI 不变）；与 `--sni` 同时给出时在其后生效 |
| `--reality-site 域名` | 以自有域名网站作为 REALITY 目标（域名需解析到本机），见 [website.md](website.md)；不能与 `--sni`、`--reality-dest` 同用。用此选项时网站证书为 HTTP-01（在交互向导第 2 步选择建站才能选其他方式，安装后也可用 `onebox site enable 域名 --tls cf\|custom` 更换）；HTTPS 443 入口默认开启（见 `--site-https`）；之后执行 `site enable` 时入口同样默认开启，需要保持关闭时加 `--site-https off` |
| `--site-title 标题` | 自动生成主页的标题，默认“山间手记”；只能与 `--reality-site` 同用 |
| `--site-https on\|off` | 网站的 HTTPS 443 入口，默认 `on`；只能与 `--reality-site` 同用 |
| `--tls self\|acme\|cf\|custom` | 代理证书：自签 / HTTP-01（`http` 同 `acme`）/ Cloudflare DNS / 自备；后三种需要 `--domain` |
| `--domain 域名` | 证书域名；不使用域名证书时，作为 VMess-WS 客户端发送的 Host（套 CDN） |
| `--cert 文件` | 自备证书的完整链（`--tls custom`） |
| `--key 文件` | 自备证书的私钥，必须未加密（`--tls custom`） |
| `--hy2-hop 起-止` | Hysteria2 UDP 端口跳跃范围（起始 ≥ 1024） |
| `--hy2-obfs` | Hysteria2 启用 salamander 混淆 |
| `--hy2-core singbox\|xray` | Hysteria2 的服务端内核，默认 sing-box（Xray 为实验性，且不支持调优） |
| `--singbox-version 版本\|latest` | 固定 sing-box 版本，默认最新稳定版 |
| `--xray-version 版本\|latest` | 固定 Xray 版本，默认 `26.3.27` |
| `--no-bbr` | 安装结束后不询问启用 BBR（只有交互安装才会询问） |
| `--force` | 已安装时允许 `-y` 重装（生成全新凭据并清除订阅设备） |
| `--json` | 仅预演：输出 JSON |
| `--dry-run` | 仅预览，不做任何修改（等同 `plan`） |
| `-y` / `--yes` | 通用选项：无人值守（使用默认值并自动确认） |

- `--singbox-version` / `--xray-version`（及 `ONEBOX_SINGBOX_VERSION` / `ONEBOX_XRAY_VERSION`）只决定尚未安装的内核下载哪个版本，并记为固定版本；重装时已安装且能运行的内核原样保留，指定的版本号与之不同时只提示 `已安装 …；更换指定版本请执行 onebox update …`。更换已安装内核的版本请执行 `onebox update singbox|xray 版本`（降级加 `--force`）。
- `latest` 表示安装最新稳定版且不固定版本，sing-box 与 Xray 相同；最新的 Xray 不是 `26.3.27` 时会提示兼容风险（查询最新版本失败时改装 `26.3.27`）。已安装的 Xray 换到最新版请执行 `onebox update xray latest`（会提示兼容风险并要求确认）。
- 每个命令只接受自己的选项，写错或不适用的选项会报错（如 `install 不支持选项 --bogus；请执行 onebox install --help`）。

### 环境变量

| 变量 | 作用 |
|---|---|
| `GH_PROXY` | GitHub 下载加速前缀，必须以 `https://` 开头。引导脚本的 `SHA256SUMS` 与程序都经该前缀下载，镜像可同时替换二者，请只使用可信镜像。Onebox 程序（安装、添加协议、更新时）下载代理内核、FRP、BBRv3 内核包和程序更新时只有文件内容经前缀传输；Release 元数据和校验值（api.github.com，缺少摘要时为 github.com 上的 `SHA256SUMS` / `.dgst`）以及 acme.sh 脚本（raw.githubusercontent.com，程序固定其 SHA-256）始终直连 GitHub、不经前缀 |
| `GH_TOKEN` | 可选的 GitHub 令牌，只用于提高 API 请求的速率限制 |
| `ONEBOX_NATIVE_BIN` | 引导脚本直接运行该本地程序，不联网、不校验 |
| `ONEBOX_SINGBOX_BIN` / `ONEBOX_XRAY_BIN` | 使用该本地内核文件代替下载（离线安装与更新；不能是符号链接） |
| `ONEBOX_SINGBOX_VERSION` / `ONEBOX_XRAY_VERSION` | 未给出 `--singbox-version` / `--xray-version` 时使用的固定版本 |
| `CF_Token`、`CF_Account_ID` | Cloudflare DNS 验证凭据（也支持 `CF_Zone_ID`，或旧式 `CF_Key` + `CF_Email`）；交互时也可隐藏输入。避免把 Token 直接写在命令行（会进入 shell 历史），可用 `read -rs CF_Token && export CF_Token` |
| `ONEBOX_AUTO=1` | 等同 `-y`（值必须恰好为 `1`） |
| `ONEBOX_INIT` | 强制 init 类型：`systemd`、`openrc`、`none` |
| `NO_COLOR` | 设为非空值时关闭彩色输出 |

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
- 自动分配会避开已在监听的端口，以及 Onebox 自己预留的端口：网站的 80 / 443 与内部端口 10443（仅本机回环）、Xray 承载 REALITY 时的本机 guard 端口（在 18000–19999 中选取，仅本机回环）、启用 IP 或独立订阅时的订阅端口（默认 8448）、HTTP-01 证书验证的 80、Hysteria2 跳跃范围、FRP 服务端占用的端口。
- 本机防火墙（ufw、firewalld、nftables、iptables）由程序自动放行，开机由 `onebox-network` 服务恢复；**云服务商安全组需要手动放行**，TCP 与 UDP 分开（Hysteria2、TUIC 为 UDP；端口跳跃需放行整个 UDP 范围）。
- 安装后修改端口：`onebox port 协议 端口`；冲突时报错且不修改。

## 证书

只有 VLESS-WS-TLS、Trojan-TLS、Hysteria2、TUIC、AnyTLS（以及启用 TLS 的 VMess-WS）需要代理证书；REALITY 类协议、SS-2022 和 ShadowTLS 不需要。

| 方式 | `--tls` | 条件 | 说明 |
|---|---|---|---|
| 自签 | `self` | 无 | 默认。EC P-256，有效期 10 年，SNI `www.bing.com`；完整客户端配置固定证书指纹 |
| Let's Encrypt HTTP-01 | `acme` / `http` | 域名 A/AAAA 直接解析到本机，TCP 80 可从公网访问 | 由内置验证服务应答；本机已有 Onebox 网站或独立订阅占用 80 时由它们应答。续期同样需要 80 |
| Let's Encrypt DNS | `cf` | 域名托管在 Cloudflare | `CF_Token` 需要该区域的 DNS 编辑权限；不占用 80 端口 |
| 自备证书 | `custom` | 证书覆盖所用域名 | `--cert` 完整链、`--key` 私钥；复制到受管目录 `/etc/onebox/tls/` |

```bash
onebox cert                                      # 查看代理、网站（及独立订阅）证书状态
onebox cert set --tls cf --domain v.example.com  # 更换代理证书方式
onebox cert set --tls custom --domain v.example.com --cert /root/fullchain.pem --key /root/privkey.pem
onebox cert renew proxy                          # 立即续期代理证书（目标可选 proxy / site / subscription / all）
```

- 证书由 acme.sh 3.1.6 向 Let's Encrypt 申请（程序固定其 SHA-256）；Cloudflare 凭据只传给 acme.sh，并以 0600 权限保存在证书目录中供续期使用；只有确实要签发或续期时才需要凭据，证书有效且未到续期时间时，其他修改不会询问。
- 存在 Let's Encrypt 或自备证书（代理、网站或独立 HTTPS 订阅）时，程序在 crontab 写入一条计划任务：每天 4:17（系统时区）执行 `onebox renew --cron`，日志写入 `/var/log/onebox/renew.log`。只有自签证书时不写计划任务。使用 Let's Encrypt 而 cron 无法运行时，在开始配置前报错（`cron 未运行，无法启用证书自动续期；请启动系统 cron 服务`）；自备证书只警告。
- 计划任务只续期到期的证书，无事可做时不输出：Let's Encrypt 证书 30 天内到期时续期，自签证书 30 天内到期时重新生成，自备证书在源文件内容变化后重新部署。
- 续期不执行完整配置事务，只重启受影响且正在运行的服务：代理证书 → 代理内核（sing-box / Xray）；网站证书（也是 `site` 模式订阅使用的证书）→ `onebox-site`；独立 HTTPS 订阅证书 → `onebox-subscription-web`。例外：代理证书的身份变化时——客户端固定的证书指纹改变（如自签证书重新生成、私有 CA 签发的自备证书更换），或证书是否公有可信发生变化——程序用当前配置执行一次完整配置事务，重新发布客户端配置和订阅，此时客户端需要重新导入或刷新订阅。
- 手动执行 `onebox renew`、`onebox cert renew`、`onebox site renew` 或 `onebox subscription renew` 时，所选的 Let's Encrypt 证书不论是否到期都会续期，请勿频繁执行。续期与其他修改共用一把锁，计划任务遇到其他操作时最多等待 10 分钟；取得锁后先完成或回滚遗留的未完成配置事务（同 `onebox recover`），再检查证书。
- 面向浏览器的网站和 HTTPS 订阅必须使用公有可信证书，不能自签。
- 更新了自备证书的源文件后，可等待计划任务，或立即执行 `onebox cert renew proxy`（网站用 `onebox site renew`）重新部署。`--cert` / `--key` 可以是符号链接，如 certbot 的 `/etc/letsencrypt/live/域名/fullchain.pem` 与 `privkey.pem`：certbot 续期后链接指向新文件，计划任务同样重新部署。

v2 的每次证书续期都会执行完整配置事务并重启全部内核，且使用三条计划任务；v3 合并为一条 `renew --cron`，并且只重启受影响的服务。

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
onebox sni --reality-dest 198.51.100.7:443   # 高级：SNI 不变，只改握手目标（如目标站的固定 IP）
onebox sni --reality-site www.example.com    # 改用自有域名网站
```

更换 SNI 后客户端需要更新：重新导入配置，或刷新远程订阅（只改 `--reality-dest` 时客户端无需变化）。Xray 承载 REALITY 时只转发与配置 SNI 一致的握手（SNI 过滤），其他探测一律丢弃，防止服务器被他人当作免费中转。

## 安装后调整

| 命令 | 作用 |
|---|---|
| `onebox add 协议 [--core …]` | 添加协议，自动分配端口（`--port` 可指定）；需要时自动准备证书 |
| `onebox del 协议` | 删除协议（至少保留一个；全部删除请用 `uninstall`） |
| `onebox port 协议 端口` | 修改端口 |
| `onebox addr [--addr …] [--name …]` | 修改客户端连接地址与节点名称 |
| `onebox sni` | 更换 REALITY / ShadowTLS 目标 |
| `onebox cert set …` | 更换代理证书 |
| `onebox reset` | 重置全部 UUID、密码与密钥（客户端需重新导入） |
| `onebox regen` | 按当前状态重新生成并应用全部配置，凭据不变 |

每次修改都是一次事务：先渲染并用内核校验新配置，再停止旧服务、写入、启动；任一步失败自动恢复原状态。
