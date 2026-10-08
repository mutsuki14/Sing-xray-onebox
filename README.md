# Sing-Xray-Onebox

**sing-box / Xray 多协议组合 · Rust 原生安装与管理工具**

当前版本：**v2.0.0**。默认分支：[`main`](https://github.com/mutsuki14/Sing-xray-onebox/tree/main)。

适用于各类 Linux VPS，一条命令部署 VLESS-Reality、XHTTP、Hysteria2、TUIC、AnyTLS、AnyTLS-REALITY、Trojan、SS-2022、ShadowTLS 等协议的任意组合，
服务端可选 **sing-box** 或 **Xray** 内核（也可双内核共存），按协议支持情况自动生成适用于 **sing-box / Xray / mihomo (Clash Meta)** 客户端的完整配置、
分享链接、Base64 订阅与二维码。支持通过 HTTPS 发布按设备授权的远程订阅；AnyTLS-REALITY 仅提供 sing-box 完整配置。

2.0 将协议配置、服务管理、证书、FRP、BBR、更新、恢复和客户端链路工具迁移到 Rust。`onebox.sh` 只负责检测 Linux 架构、下载固定版本的原生程序、校验 SHA-256 并启动；不再包含或调用旧版 Bash / Python 业务实现。

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/mutsuki14/Sing-xray-onebox/main/onebox.sh)
```

安装完成后，输入 `onebox` 打开管理菜单。2.0 重新整理了主菜单：**10 订阅、11 网站、12 FRP、13 BBR、16 更新程序、21 性能与连通性**；协议选择编号与现有预设保持兼容。

---

## 特性

- **协议组合随心选**：预设与自定义组合，12 种协议可自由搭配。
- **双内核**：sing-box 与 Xray 可单独使用，也可同时使用（例如 Xray 跑 Reality/XHTTP，sing-box 跑 Hysteria2/TUIC/AnyTLS）。
- **四类客户端输出**：
  - 分享链接 + Base64 订阅 + 终端二维码（v2rayN / v2rayNG / NekoBox / Shadowrocket / Hiddify / Karing 等）
  - mihomo 完整 YAML（Clash Verge Rev / Mihomo Party / FlClash / ClashMi / Clash Meta for Android）
  - sing-box 完整 JSON（TUN 版与纯代理端口版，兼容 sing-box 1.12 ~ 1.14，适用于 SFA / SFI / SFM / GUI.for.SingBox）
  - Xray 客户端 JSON
- **Linux 原生程序**：提供 amd64、arm64、32 位 x86（i586 及以上）、armv7 的 musl 静态构建；支持 systemd、OpenRC，以及无 init 环境的进程管理。其他 Linux 架构需自行源码构建，仍受上游代理内核的架构支持限制。
- **证书**：自签证书（完整客户端配置固定证书信任）/ Let's Encrypt（HTTP 验证或 Cloudflare DNS 验证，acme.sh 自动续期）/ 自有证书。
- **自有域名 REALITY 网站**：使用自己的域名一键生成可编辑的主页、申请 Let's Encrypt 证书并自动续期，普通浏览器与 REALITY 客户端共用公网入口。
- **AnyTLS-REALITY**：sing-box 服务端与客户端支持 AnyTLS + REALITY，可选择外部握手目标或自有域名网站；与普通 AnyTLS 分开配置。
- **HTTPS 远程订阅**：复用自建网站或独立域名入口，按设备创建、撤销、重置订阅链接；提供 Base64、mihomo 完整配置 / provider、sing-box 和 Xray 配置。
- **管理与恢复**：只读安装预演、一键体检、证书状态、稳定/测试更新渠道、本机快照与手动恢复、静态网站模板和内容导入、本地脱敏诊断包。
- **链路与性能**：真实客户端链路测试、Hysteria2 拥塞与接收窗口调优、REALITY 一致性检查，以及带连续失败阈值、恢复冷却期的客户端多入口回退。
- **BBR 管理**：启用系统自带 TCP BBR，选择默认队列；集成 [byJoey/Actions-bbr-v3](https://github.com/byJoey/Actions-bbr-v3) 的标准版 / Max 版内核 Release，支持安装预览、指定版本与下载校验，保留旧内核。
- **FRP 服务端**：独立管理官方 frps，支持控制域名、强制 TLS 与 token、HTTPS 应用域名 / 泛域名、证书申请与续期、TCP/UDP 转发范围、客户端配置导出和失败回滚。
- **贴心细节**：自动检测端口占用、放行防火墙（ufw / firewalld / iptables，含甲骨文云默认规则）、Hysteria2 端口跳跃、BBR、
  屏蔽 BT 与回环/内网访问、配置写入前先经内核校验（失败不覆盖旧配置）、国内服务器 GitHub 加速。
- **可重复验证**：Native CI 运行 Rust 单元测试、真实代理内核的协议与客户端矩阵、生命周期 / 迁移 / 故障恢复测试，以及四个发布架构的构建检查；通过后才生成正式发布资产。

## 快速开始

安装及系统配置变更需要 root 权限；查看帮助、版本和客户端链路测试无需 root。原生程序下载需要 `curl`（强制 HTTPS 下载与重定向），以及 `sha256sum`、`shasum`、`openssl` 三者之一。

```bash
# curl
bash <(curl -fsSL https://raw.githubusercontent.com/mutsuki14/Sing-xray-onebox/main/onebox.sh)

# 或用 wget 获取入口（运行入口仍需安装 curl）
bash <(wget -qO- https://raw.githubusercontent.com/mutsuki14/Sing-xray-onebox/main/onebox.sh)

# Alpine：先 apk add --no-cache curl；使用 POSIX sh，无需安装 Bash
wget -O onebox.sh https://raw.githubusercontent.com/mutsuki14/Sing-xray-onebox/main/onebox.sh && sh onebox.sh

# 国内服务器 (GitHub 访问困难) 可设置加速前缀:
GH_PROXY=https://ghfast.top/ bash <(curl -fsSL https://ghfast.top/https://raw.githubusercontent.com/mutsuki14/Sing-xray-onebox/main/onebox.sh)
```

运行后选择 **1. 安装**，依次选择协议组合、伪装站点、证书方式与端口。回车接受显示的默认值，EOF 取消操作。安装后 `/usr/local/bin/onebox` 是持久保存的原生程序，日常管理不再重新下载引导文件。

### 预编译架构与源码构建

| Linux 架构 | Release 资产 | Rust 目标 |
|---|---|---|
| x86_64 / amd64 | `onebox-linux-amd64-musl` | `x86_64-unknown-linux-musl` |
| aarch64 / arm64 | `onebox-linux-arm64-musl` | `aarch64-unknown-linux-musl` |
| i586 / i686 | `onebox-linux-386-musl` | `i586-unknown-linux-musl` |
| ARMv7 | `onebox-linux-armv7-musl` | `armv7-unknown-linux-musleabihf` |

引导固定下载 **v2.0.0** 的资产并验证同一 Release 的 `SHA256SUMS`，下载或校验失败即退出。没有预编译资产的架构（如 ARMv6、s390x、riscv64、loongarch64）不会自动选择不匹配的程序。可在支持 Rust 的 Linux 环境构建：

```bash
git clone https://github.com/mutsuki14/Sing-xray-onebox.git
cd Sing-xray-onebox
cargo build --release --locked
./target/release/onebox --version
sudo ./target/release/onebox

# 已取得可信的本地程序：引导不联网、不下载
ONEBOX_NATIVE_BIN=/absolute/path/onebox sh onebox.sh --version
```

源码构建需要 Rust / Cargo 和本机链接工具链。交叉编译与发布流程见 `.github/workflows/native-release.yml`；musl 构建减少对 glibc 的依赖，不代表所有发行版、内核版本和上游代理程序都兼容。

### 从 1.x 迁移

先退出旧版菜单，在终端保存备份，然后下载新入口执行 **`regen`**；已有协议、端口、UUID、密码、REALITY 密钥和网站内容沿用原状态。不要用 `install` 代替迁移，重装会生成新凭据。

```bash
# 仍在旧版时保存一份本机备份
onebox backup before-rust

# root 终端：更新管理程序并重新生成现有配置
curl -fL https://raw.githubusercontent.com/mutsuki14/Sing-xray-onebox/main/onebox.sh -o onebox.sh
sh onebox.sh regen
onebox version
onebox doctor
```

原生程序将 `/etc/onebox/onebox.conf` 作为旧格式数据读取，不执行其中的 Shell 代码；第一次成功保存时写入权限 `600` 的 `state.json`，并保留 `onebox.conf.pre-rust`。此后以 `state.json` 为准，直接修改旧文件不会生效。旧版 NUL 格式快照仍可通过 `onebox restore ID` 校验并恢复到原管理路径。

FRP 保留独立的 `/etc/onebox-frp/` 状态，读取旧 `state.conf` 后在下一次成功配置时保存为 `state.json`；节点迁移不会重置 FRP token 或替换私有 CA。旧版客户端探测文件仍可交给原生 `probe` / `bench` / `failover` 使用，客户端不再需要 Python。

迁移与配置应用使用持久化事务日志，失败会尝试恢复旧文件、服务状态和受管防火墙规则；若上次被强制终止或恢复未完成，执行 `onebox recover` 后再继续。发布资产暂不可下载时，请等待该版本 Native CI 与发布流程完成，或使用上述源码构建方式。

## 协议组合

| 编号 | 组合 | 内核 | 说明 |
|---|---|---|---|
| 1 | VLESS-Reality-Vision + Hysteria2 + TUIC | sing-box | **推荐**。无需域名，TCP 与 UDP 协议互为备份 |
| 2 | VLESS-Reality-Vision + VLESS-XHTTP-Reality + SS-2022 | Xray | Xray 官方推荐的 Reality 方案，Vision 与 XHTTP 共用 443 端口 |
| 3 | Reality-Vision、XHTTP (Xray) + Hysteria2、TUIC、AnyTLS (sing-box) | 双内核 | 各取所长 |
| 4 | Reality / gRPC-Reality / Trojan / SS-2022 / Hysteria2 / TUIC / AnyTLS / ShadowTLS / VMess-WS | sing-box | 全家桶 |
| 5 | VLESS-WS-TLS + VMess-WS | sing-box | 可套 CDN，建议使用域名 |
| 6 | VLESS-Reality-Vision | Xray | 极简单协议 |
| 7 | 自定义 | 任选 | 从 12 种协议中任意组合，并选择优先内核 |

AnyTLS-REALITY 可在自定义组合中选择，或安装后执行 `onebox add anytls-reality` 添加；现有预设仍使用普通 AnyTLS。

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
| AnyTLS-REALITY | sing-box ≥ 1.12.0 | ❌ (仅完整 JSON) | ❌ | ✅ (≥ 1.12.0) | ❌ | 无需 (REALITY) |

> Xray 26 起对 gRPC / WebSocket / VMess / Trojan / Shadowsocks 输出“已弃用”警告，这些协议默认建议由 sing-box 承载；
> REALITY 建议使用 443 端口（Xray 会对非 443 端口给出警告）；两者都由 Xray 承载时，VLESS-XHTTP-Reality 默认与 Vision 共用 443 端口。
> Xray 承载 REALITY 时会启用官方推荐的 SNI 过滤，防止服务器被他人当作伪装站点 CDN 的免费中转。
>
> **关于 Xray 版本**：程序默认安装 Xray 26.3.27。更新的 Xray（26.4 之后）REALITY 服务端要求客户端支持
> X25519MLKEM768，会拒绝 sing-box 客户端，因此 `onebox update xray` 会先提示确认；也可用 `--xray-version latest` 显式指定。

## AnyTLS-REALITY

`anytls` 使用普通 TLS，需要自签、ACME 或自备证书；新增的 `anytls-reality` 使用 REALITY 密钥、short ID、SNI 和握手目标，默认无需自备域名或证书。两者可同时安装，分别使用独立端口。AnyTLS-REALITY 沿用现有 REALITY 目标选择、密钥管理与自有域名建站功能。

```bash
# 已安装：更新程序后添加协议，再导出 sing-box 配置
onebox update-script
onebox add anytls-reality
onebox client singbox

# 只使用本地代理端口的客户端配置
onebox client singbox-notun

# 新安装：指定外部 REALITY 握手目标
bash onebox.sh install --protocols anytls-reality --core singbox --sni www.microsoft.com -y

# 可选：添加协议时，使用自己的域名一键建站并开启 HTTPS 443 入口
onebox add anytls-reality --reality-site www.example.com --site-https on
```

服务端与客户端均需 **sing-box ≥ 1.12.0** 且使用带 `with_utls` 的构建（官方发行包已包含）。请导入生成的 `sing-box.json` 或 `sing-box-notun.json`；其他应用是否可用，取决于其内置 sing-box 版本和是否支持完整配置导入。

**AnyTLS-REALITY 不支持 mihomo / Xray，也不提供通用分享链接、Base64 节点订阅或二维码。** 不要把普通 `anytls://` 链接用于此协议。普通 AnyTLS 的分享与 mihomo 支持保持不变。兼容性依据：[sing-box AnyTLS](https://sing-box.sagernet.org/configuration/inbound/anytls/)、[sing-box TLS / REALITY](https://sing-box.sagernet.org/configuration/shared/tls/)、[mihomo AnyTLS](https://wiki.metacubex.one/en/config/proxies/anytls/)。

选择自有域名网站时，程序仍会为网站申请和续期证书；域名解析、端口与证书要求见下一节。

## 使用自己的域名作为 REALITY 网站

安装时或执行 `onebox sni` 更换目标时，选择自有域名模式，输入域名和网站标题，再选择是否启用 **HTTPS 443 入口**（新建时默认开启）。也可使用下面的命令行参数。
程序会建立一个可直接访问的主页，为该域名申请 Let's Encrypt 证书，并将 REALITY 的握手目标设为本机网站。
开启 443 入口后，直接访问 `https://你的域名/`：如果 REALITY 已监听 TCP 443，则复用其网站回落；否则由独立 nginx 监听 443，并反代到本机网站的内部 HTTPS 端口。已有网站升级时保持原设置，可手动开启。
已有节点切换此模式时保留 UUID 与 REALITY 密钥，客户端需要更新 SNI，或重新导入生成的配置。

开始前需要：

- 将域名的 A / AAAA 记录直接解析到此 VPS 的公网地址；使用 Cloudflare 等 DNS 服务时关闭该记录的 CDN 代理。配置了 AAAA 时，对应 IPv6 地址也必须可达。
- 在云安全组中放行 **TCP 80** 和实际使用的 **REALITY TCP 端口**。TCP 80 用于网站访问和证书申请、自动续期，需持续可达。
- 确保 TCP 80 未被其他程序占用。程序使用独立 nginx 实例，不接管现有 nginx 网站；发现端口冲突会明确报错。
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
| nginx 的内部 HTTPS 监听 | 仅监听 `127.0.0.1`；具体端口见 `onebox site info`，无需对公网开放 |

开启网站 443 入口时，网站地址为 `https://www.example.com/`；关闭该入口后使用实际 REALITY 端口，例如 `https://www.example.com:8443/`。
程序提供的本机 HTTPS 网站启用 TLS 1.3 和 HTTP/2；网站使用独立的 acme.sh 目录管理证书与续期任务。

默认主页位于 **`/var/lib/onebox-site/index.html`**，可直接编辑 HTML 替换内容；`onebox regen` 不会覆盖用户修改后的主页。
其他代理协议使用 HTTP 验证证书时，启用网站会复用网站的验证目录，避免争用 80 端口。
切换回外部 REALITY 目标，或删除最后一个 REALITY 协议时，程序停止托管网站和其续期任务，但保留网页内容。订阅正在复用网站时，须先关闭订阅或切换到独立入口，才能关闭网站或改变订阅所用的端口。
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
onebox client provider       # 仅含节点的 mihomo proxy-provider YAML
onebox client singbox        # sing-box 配置 (TUN)
onebox client singbox-notun  # sing-box 配置 (仅代理端口)
onebox client xray           # Xray 配置
onebox client sub            # Base64 订阅内容
onebox qr                    # 终端二维码
```

**客户端版本要求**：mihomo 内核需 ≥ 1.19.3（含 VLESS-XHTTP 时需 ≥ 1.19.22），sing-box 客户端需 ≥ 1.12。
AnyTLS-REALITY 仅包含在 sing-box 完整配置中，不会加入 mihomo / Xray 配置或分享链接；上表其他客户端的链接导入方式不适用于该协议。
生成的 mihomo / sing-box 配置为本地控制面板 (127.0.0.1:9090) 设置了密钥（`onebox info` 中显示），DNS 仅监听本机。
Stash 的部分字段名与 mihomo 不同（如证书指纹、Hysteria2 密码），Shadowrocket 建议直接导入分享链接或订阅。

**自签证书说明**：选择自签证书时，程序会把证书指纹写入客户端配置——mihomo 使用 `fingerprint`，Xray 使用 `pinnedPeerCertSha256`，
sing-box 直接内嵌证书；分享链接同时附带 `allowInsecure=1`/`insecure=1` 与 `pcs` / `pinSHA256` / `hpkp` 指纹参数，兼顾新旧客户端。
已知限制：mihomo 通过订阅链接导入 **TUIC + 自签证书** 时无法跳过验证（其链接解析器不支持），请改用 `mihomo.yaml`；
mihomo 链接导入会忽略 Hysteria2 端口跳跃参数 `mport`。

## HTTPS 远程订阅

`onebox client sub` 输出的是本地 Base64 内容；2.0 新增的 **`onebox subscription`** 将客户端配置托管为可更新的 HTTPS URL。首次启用会创建设备 `default`，之后可为手机、电脑等分别创建链接。配置成功应用后会同步发布，失败时保留旧的可用版本。

### 选择订阅入口

```bash
# 已启用自有域名 REALITY 网站：复用其证书、域名和公网端口
onebox subscription enable --mode site

# 没有自建站，或需要独立入口：先把 sub.example.com 直接解析到 VPS
# 默认独立 HTTPS 端口为 8448，需在云安全组放行；CF Token 可由隐藏输入提供
onebox subscription enable --mode standalone --domain sub.example.com --port 8448 --tls cf

# 独立入口也支持 HTTP-01；TCP 80 必须空闲并持续对公网可达
onebox subscription enable --mode standalone --domain sub.example.com --port 8448 --tls http

# 自备公有可信证书，需覆盖订阅域名
onebox subscription enable --mode standalone --domain sub.example.com --port 8448 \
  --tls custom --cert /root/fullchain.pem --key /root/privkey.pem
```

独立入口检查 DNS、证书与端口，不接管已有服务；可用端口允许时可选择 `--port 443`。复用自建站时不增加公网端口，普通网页和 `/sub/…` 使用同一个 HTTPS 入口。订阅不通过 FRP 入口发布；FRP 配置继续单独导出。

### 设备与导入格式

```bash
onebox subscription info                 # 查看设备 ID、状态和入口
onebox subscription add phone            # 创建设备并显示其各格式 URL
onebox subscription add laptop
onebox subscription reset DEVICE_ID       # 换新令牌，旧链接立即失效
onebox subscription revoke DEVICE_ID      # 撤销该设备的后续订阅下载
onebox subscription publish              # 重新生成、校验并发布当前配置
onebox subscription renew                # 续期订阅使用的证书
onebox subscription disable              # 停止全部远程订阅访问
```

| URL 末段 | 返回内容 | 使用方式 |
|---|---|---|
| `base64` | Base64 节点链接 | 导入支持相应协议的客户端订阅 |
| `mihomo` | 完整 mihomo YAML | 作为远程配置导入 |
| `provider` | 仅含 `proxies` 的 YAML | 在已有 mihomo 配置的 `proxy-providers` 中引用 |
| `singbox` | sing-box 完整 JSON，TUN 模式 | 作为远程配置导入；也输出 `sing-box://import-remote-profile` 导入链接 |
| `singbox-notun` | sing-box 完整 JSON，仅本地代理端口 | 下载并交给 sing-box 使用 |
| `xray` | Xray 客户端 JSON | 交给支持完整 Xray 配置的客户端 |

链接形如 `https://域名[:端口]/sub/设备令牌/singbox`。令牌仅在创建或重置时显示，服务器保存其哈希；忘记链接应执行 `reset`，`info` 不会还原令牌。不要把链接、二维码或包含链接的截图公开。撤销订阅只能阻止后续下载，**不会撤销已下载的节点密码**；如需使旧节点配置失效，使用 `onebox reset` 轮换节点凭据后重新分发。

每种格式只包含它支持的协议，没有可用节点的格式不会发布。**AnyTLS-REALITY 仍仅进入 `singbox` / `singbox-notun`**，不会因为使用远程订阅而获得 mihomo、Xray 或通用节点链接支持。混合部署时，Base64 和 mihomo 订阅会缺少不兼容节点。ShadowTLS 也应使用完整客户端配置。

从 1.x 升级后，原有本地客户端文件仍可使用；远程订阅默认关闭，需自行启用并把设备 URL 添加到客户端。设备链接不替代内核版本要求，客户端是否支持自动刷新、TUN 或远程配置导入以该客户端能力为准。

## 管理命令

```text
onebox                     打开交互式管理菜单
onebox install             安装 / 重装
onebox info                查看节点信息与分享链接
onebox client <类型>       输出配置: mihomo | provider | singbox | singbox-notun | xray | links | sub | qr
onebox subscription ...    HTTPS 订阅: enable | info | add | reset | revoke | publish | disable
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
onebox update-script       更新原生管理程序（保留旧命令名）
onebox cert                证书管理 (更换 / 续期)
onebox bbr                 BBR / BBRv3 管理菜单 (非交互时显示状态)
onebox frps                FRP 服务端与域名管理
onebox backup [标签]       保存节点、证书、网站、客户端与订阅快照
onebox backups             列出快照
onebox restore ID|latest   恢复快照
onebox recover             恢复未完成事务
onebox uninstall           卸载
```

协议名称：`vless-reality` `vless-xhttp` `vless-grpc` `vless-ws` `vmess-ws` `trojan` `shadowsocks` `hysteria2` `tuic` `anytls` `shadowtls` `anytls-reality`

## BBR / BBRv3 管理

主菜单 **13** 或 `onebox bbr` 打开管理菜单。交互安装结束可选择启用当前内核的 BBR；`--no-bbr` 可跳过。无人值守安装后可显式执行 `onebox bbr enable`。升级程序、打开菜单和查看状态不会安装 Linux 内核。

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
| 启用当前内核 BBR | 适用于提供 `tcp_bbr` 的系统；OpenVZ 不支持，其他容器受宿主机能力限制 |
| 安装 BBRv3 Linux 内核 | Debian 12+ / Ubuntu 24.04+，x86_64 / aarch64，用户空间架构匹配；不支持容器、WSL、设备树 / U-Boot / 厂商引导链 |
| 引导与空间检查 | 已有 GRUB 和可回退的当前内核、initrd、模块；EFI 必须确认 Secure Boot 关闭；`/boot` 至少空闲 512 MiB，根分区 2 GiB，临时目录容纳下载包并留 256 MiB |
| 依赖 | `curl`、apt-get、dpkg、dpkg-deb、dpkg-query、update-grub、df 及系统网络管理工具；校验、JSON 解析与锁由 Rust 实现 |
| Release 选择 | 按 CPU 与标准/Max 类型过滤，排除草稿和预发布；在最近最多 500 项中找到首个包含匹配版本的分页，按版本号排序。更早版本可指定完整标签 |
| 安装文件 | 仅 image + headers，校验 GitHub API 提供的 SHA-256、大小、URL、包名、架构和版本；不安装 linux-libc-dev 或调试包 |
| 失败与重启 | apt 使用 `--no-remove`，不删除旧内核；安装失败、引导生成失败时停止并提示修复。不会自动重启，也不改 GRUB 默认启动项 |

内核由 **[byJoey/Actions-bbr-v3](https://github.com/byJoey/Actions-bbr-v3)** 构建与发布，Onebox 独立实现下载、验证和安装流程，未复制或执行上游 `install.sh`。GitHub 元数据直连获取；`GH_PROXY` 只用于包下载，内容必须与直连元数据中的校验值一致。校验保证下载完整性，不替代对上游构建者的信任；缺少校验值的旧 Release 会被拒绝。最终下载记录保存在 `/var/lib/onebox-bbr/last-install.tsv`。

**安装前确认有 VPS 控制台访问和可恢复的磁盘快照。** 安装完成后选择维护时间手动重启，必要时在 GRUB 里选择新内核，再执行 `onebox bbr status`、`onebox bbr enable fq`。已安装包不代表正在运行，算法名称 `bbr` 也不证明是 v3；状态页分别报告运行内核、运行中的模块版本和磁盘模块版本。若新内核不能启动，从控制台 GRUB 的 Advanced options 选择保留的旧内核；修复引导前不要清理旧包。卸载 Onebox 不卸载 Linux 内核。

默认使用标准版；**Max** 提高探测与窗口策略的激进程度，仅用于自有链路吞吐实验，可能增加延迟、丢包和带宽争抢，不保证更快。上游的极限 sysctl 配置、测速软件安装、模块黑名单和快捷命令 `b` 不会自动应用。

BBR/队列配置保存到 `/etc/sysctl.d/99-onebox-bbr.conf`，应用失败恢复原运行参数并保留原文件。其他工具（包括上游的 `99-joeyblog.conf`）有相同参数时会提示检查覆盖关系。选择队列仅修改 `net.core.default_qdisc`，**不会替换正在运行的网卡队列或已有带宽整形规则**；查看 `tc qdisc show` 或状态页确认实际队列，新建队列/重启后再检查。系统 TCP BBR 与 Hysteria2/TUIC 的 QUIC 拥塞控制是不同层，后者继续使用 `onebox tune`。

## FRP 服务端与完整域名配置

`onebox frps` 管理独立的 [fatedier/frp](https://github.com/fatedier/frp) 服务端。默认安装 **0.71.0**，下载时校验官方 GitHub Release 的 SHA-256、文件大小与版本；可指定更新版本或 `latest`。配置预览用 `onebox frps plan`，实际安装 / 配置需要确认；无人值守时显式添加 `-y`。

直接运行 `onebox frps install` 或 `onebox frps configure`，不附加参数，即可进入交互向导：**用途 → 域名 → 公网端口 → 网站证书 → 高级设置**；TCP/UDP 模式自动跳过网站证书步骤。回车保留默认值，`b` 返回上一步，`q` 取消，Ctrl+D 结束输入并安全退出。最后显示部署摘要，可确认部署、返回修改或取消；确认后才安装依赖、验证 DNS、申请证书并应用配置。

向导会检查端口占用和已有代理的预留范围，并建议可用的候选端口；例如 443 不可用时建议 8443 或 9443。泛域名默认选择 Cloudflare DNS 验证；TCP 80 已被占用时，HTTP-01 不可选，需使用 DNS 验证或自备证书。Cloudflare Token 输入不回显，可使用环境变量提供的凭据；已有有效凭据会自动复用；也可使用环境变量提供新的 Token。DNS 记录仍需提前手动配置。

| 模式 | 用途与公网入口 | 内部连接 |
|---|---|---|
| `web`（默认） | 浏览器通过应用域名的 HTTPS 443 访问内网网站；支持单域名或一级泛域名 | 独立 Nginx 终止 HTTPS，保留 Host 反代到 `127.0.0.1:7080` 的 frps HTTP 入口；客户端使用 `type = "http"` |
| `tcp` | 通过控制域名与选定公网端口访问内网 TCP / UDP 服务 | 仅开放配置的转发范围，默认 `20000-20100`；不启用网站虚拟主机或 Nginx |

两种模式均默认使用 TCP 7000 建立 frpc → frps 控制连接，强制 TLS、生成随机 token，并认证心跳和新工作连接。不启用 Dashboard。网站模式的 HTTP 入口仅监听回环，不直接开放公网 TCP/UDP 转发；需要通用公网端口转发时选择 `tcp` 模式。

### 准备 DNS 与端口

先在 DNS 服务商处手动添加记录，程序会检查解析结果，但不会替你创建或修改 DNS 记录。

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

已部署 FRP 后，直接运行 **`onebox frps client`** 可交互导出：选择内网服务端口，按模式选择 TCP / UDP 与公网转发端口，或填写泛域名的子域标签，再指定新的导出目录。目录已存在时可重新选择；`b` 返回上一步，`q` 或 Ctrl+D 取消。原有带目录和选项的命令仍可用于自动化，例如 `onebox frps client /root/frpc-home --type http --local-port 8080`。

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
onebox frps install                       # 无附加参数：交互安装向导
onebox frps configure                     # 无附加参数：交互重新配置
onebox frps client                        # 交互选择内网服务并导出客户端配置
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

FRP 的状态、证书、防火墙台账、服务与续期任务独立管理；普通 `onebox uninstall` 保留 FRP 及所需管理命令，删除 FRP 请使用 `onebox frps uninstall`。防火墙仅清理本功能记录的规则，已有用户规则保留。安装、配置与更新使用临时事务备份，失败时尝试恢复旧文件、服务与防火墙；恢复未完成时保留备份并提示处理位置。**代理的 `onebox backup` 不包含 FRP**，FRP 当前没有公开的历史快照 / 手动恢复命令。

## 无人值守安装

正式安装前可执行 `onebox plan` 或 `onebox install --dry-run`，附带相同的安装选项。原生程序的预演只读取当前环境，不联网、不预留端口、不安装依赖，也不申请证书；通过 `onebox.sh` 首次运行时，引导仍需联网下载原生程序。自动端口、DNS、CA 和公网可达性仍需在实际安装时校验。

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
| `--tls self\|acme\|cf\|custom` | 代理证书方式：自签 / ACME HTTP / Cloudflare DNS / 自备；自备需 `--cert` 与 `--key` |
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

环境变量：`GH_PROXY`（HTTPS GitHub 下载加速前缀）、`ONEBOX_NATIVE_BIN`（引导使用指定的本地管理程序）、`ONEBOX_SINGBOX_BIN` / `ONEBOX_XRAY_BIN`（使用本地代理内核文件）。系统依赖、DNS 检查和 ACME 仍可能需要联网。

## 文件位置

| 路径 | 内容 |
|---|---|
| `/etc/onebox/state.json` | 原生状态（端口、凭据等，权限 600） |
| `/etc/onebox/onebox.conf.pre-rust` | 首次成功迁移时保留的旧版状态副本 |
| `/etc/onebox/sing-box.json`、`/etc/onebox/xray.json` | 服务端配置 |
| `/etc/onebox/tls/` | 证书 |
| `/etc/onebox/client/` | 客户端配置、分享链接、本地 Base64 内容与探测配置 |
| `/etc/onebox/subscription/` | HTTPS 订阅设置、设备令牌哈希、已发布客户端快照与独立入口证书 |
| `/etc/onebox/backups/` | 手动节点快照 |
| `/var/lib/onebox-site/index.html` | 自有域名网站主页，可直接编辑；具体管理路径见 `onebox site info` |
| `/opt/onebox/bin/` | sing-box / xray 内核 |
| `/etc/onebox-frp/` | 独立 FRP 状态、`frps.toml`、私有 CA / 服务端证书、网站证书、Nginx 配置与防火墙台账 |
| `/opt/onebox-frp/frps` | 官方 FRP 服务端程序 |
| `/var/lib/onebox-frp/`、`/var/log/onebox-frp/` | FRP 网站验证目录、运行数据与日志 |
| `onebox-frps`、`onebox-frp-web` | FRP 控制服务与独立网站入口的系统服务名 |
| `onebox-sing-box`、`onebox-xray` | 代理系统服务名 |
| `onebox-subscription`、`onebox-subscription-web` | 订阅服务与独立 HTTPS 入口（启用时） |
| `/usr/local/bin/onebox` | 管理命令 |

## 常见问题

**安装成功但连不上？**
1. 在云服务商控制台的安全组 / 防火墙中放行对应端口（TCP 与 UDP 分别放行，Hysteria2 / TUIC 使用 UDP；
   启用了 Hysteria2 端口跳跃时还需放行整个 UDP 端口范围；使用 ACME HTTP 验证时需放行 TCP 80，续期同样需要）。
   本机防火墙（ufw / firewalld / iptables / nftables）由程序自动放行，并在开机时由 `onebox-network` 服务自动恢复。
2. `onebox status` 与 `onebox log` 检查服务状态。
3. REALITY 连接失败时尝试更换伪装站点：`onebox sni`（或菜单 19，UUID 与密钥保持不变），站点需支持 TLS 1.3，且尽量与服务器地理位置接近。

**REALITY 伪装站点怎么选？** 选择支持 TLS 1.3 / H2、非 CDN 回源、在国内可正常访问的大站，例如 `www.microsoft.com`、`www.apple.com`、`addons.mozilla.org`。程序会自动检测所选站点是否支持 TLS 1.3。
也可选择自有域名模式，一键建站；准备要求与管理方式见上文“使用自己的域名作为 REALITY 网站”。

**国内 VPS 下载失败？** 设置 `GH_PROXY=https://ghfast.top/`（或其他可用的 GitHub 加速前缀）后重新运行。

**纯 IPv6 VPS？** GitHub 不支持 IPv6，下载内核需要借助支持 IPv6 的 GitHub 加速前缀（如 `GH_PROXY=https://ghproxy.net/`）或先配置 WARP / NAT64。
配置了 WARP 时，程序会识别出 WARP 出口地址（不能用于入站连接），默认改用本机 IPv6 作为客户端连接地址。

**支持哪些系统？** 原生程序面向 Linux，管理依赖通过系统包管理器安装。请使用仍受支持的软件源和系统版本；2.0 不自动把旧发行版的软件源改为归档源。Onebox 的四个预编译包使用 musl 静态链接，上游代理内核和系统工具仍有各自的兼容要求。

**SS-2022 / ShadowTLS / VMess 连接失败？** 这些协议对时间敏感：SS-2022 要求服务器与客户端时间误差在 30 秒以内，VMess 为 120 秒。
请确保服务器和客户端开启时间同步（`timedatectl set-ntp true` 或安装 chrony）。

## 日常管理与故障恢复

| 需求 | 命令 |
|---|---|
| 检查核心配置、服务与证书临期 | `onebox doctor` |
| 证书状态与续期 | `onebox cert status`、`onebox cert-renew proxy`、`onebox site renew` |
| 本机备份与恢复 | `onebox backup 标签`、`onebox backups`、`onebox restore ID` |
| 恢复中断的配置事务 | `onebox recover` |
| 生成脱敏诊断文件 | `onebox support` |
| 检查更新、选择渠道 | `onebox update-check`、`onebox update-channel stable` |
| 安装前预演 | `onebox plan --preset 6` |
| 网站内容管理 | `onebox site template`、`title`、`import`、`restore` |

`doctor` 检查正在使用的核心配置、服务状态、代理/网站证书临期和未完成事务；发现配置或服务问题以非零状态退出。它不替代公网 DNS、云安全组和真实客户端连通性检查，可配合 `onebox reality-check` / `bench` 定位链路问题。

证书由各自的管理目录与续期任务维护，代理、网站、独立订阅和 FRP 分开处理。日常任务先检查是否需要续期；手动命令可重新申请或部署。查看 `onebox cert status`、`onebox site info`、`onebox frps info` 了解对应证书。

### 网站内容

```bash
onebox site preview profile --title '我的主页' --theme ocean
onebox site template profile --title '我的主页' --description '作品与日常记录' --theme ocean
onebox site title '新的标题'
onebox site import /root/my-static-site
onebox site restore latest
```

模板可选 `minimal`、`profile`、`docs`，配色可选 `forest`、`ocean`、`slate`。预览仅生成私有目录内的 HTML 文件，下载该文件即可查看，线上内容不会变化。导入目录需有 `index.html`，不执行其中的文件；拒绝符号链接、特殊文件、系统目录及递归导入。每次发布前备份完整原网站，失败恢复旧内容；当前 ACME 验证目录会保留。导入或手工改过的页面不会被“修改标题”自动覆盖，请编辑源网页后重新导入。内容备份位于 `/etc/onebox/site/content-backups/`，可用 `onebox site restore latest` 恢复。

### 节点快照

`onebox backup 标签` 保存快照到 `/etc/onebox/backups/`，保留最近 5 份。快照包含节点状态、受管证书/私钥、网站内容、客户端文件和订阅设置，因此目录权限为 `700`、文件为 `600`。它含敏感凭据，不能作为公开诊断材料。FRP、代理内核二进制和操作系统不包含在节点快照中。

恢复前校验完整性，成功备份当前状态后才应用目标快照；核心配置不通过或服务启动失败会触发事务回滚。兼容导入旧版的格式 1 快照，但旧快照须恢复到原管理路径。每份备份最多 64 MiB / 4096 个文件。配置事务的临时回滚副本不等于可长期选择的历史快照，需要保留版本时请主动执行 `backup`。

恢复快照也会恢复其中的订阅设备列表：此前撤销的设备可能重新出现，请核对 `onebox subscription info`。该功能用于本机配置恢复，不是完整系统或跨 VPS 迁移工具。

### 诊断文件

`onebox support` 在 `/etc/onebox/support-时间戳.json` 生成权限为 `600` 的 JSON，记录程序/核心版本、系统信息、协议端口、服务状态和事务状态。不打包原始日志、节点凭据、域名、IP、私钥、订阅内容或环境变量，也不自动上传。

### 更新与发布

`onebox update` 只更新 sing-box / Xray 内核，可指定版本，例如 `onebox update singbox 1.14.2`。新内核不接受配置或启动失败时尝试恢复旧版本。

`onebox update-script` 保留了旧命令名，2.0 中更新的是**原生管理程序**。下载时校验 Release 资产大小和 SHA-256，核验 ELF 与版本，之后原子替换并重新生成配置；失败恢复旧程序和配置。拒绝降级，相同内容跳过替换。更新会结束当前菜单；用 `onebox version` 核验后，重新执行 `onebox` 打开新版本。

```bash
onebox update-check
onebox update-script
onebox version
onebox update-channel stable
```

默认 `stable` 使用最新正式 GitHub Release；`testing` 对应名为 `testing` 的预发布资产，只有维护者实际发布该渠道后才能使用。**不再从 main 分支源码直接执行管理逻辑，也不在 Release 缺失时自动回退下载旧 Shell 脚本。** `onebox update-script testing` 仅选择本次渠道，`onebox update-channel testing` 保存偏好；旧环境变量 `ONEBOX_SCRIPT_URL` 不作为 Rust 更新源。旧版升级路径见前面的“从 1.x 迁移”。

发布工作流仅为默认分支 `main` 的已通过 Native CI 的提交构建四个 musl 资产。检查构建与版本后，先上传草稿、下载复核 `SHA256SUMS`，再公开 Release；`BUILD-INFO.json` 记录源码 SHA、CI 与构建工具信息。`workflow_dispatch`、版本标签或成功的 Native CI 可触发检查，未通过 CI、主分支已变化或已有不匹配版本时不会发布。

**使用已有证书（certbot 等）？** 2.0 将校验后的证书和私钥复制到各自受管目录，保留源路径供后续部署。更新源文件后执行 `onebox cert-renew proxy`（网站用 `onebox site renew`，独立订阅用 `onebox subscription renew`），或配置相应的续期部署钩子。只重启核心不会重新复制外部证书。面向浏览器的网站和订阅需公有可信证书；代理自签证书通过完整客户端配置固定信任。

**修改失败如何恢复？** 应用过程先记录持久事务并校验新配置，失败尝试恢复旧配置、证书、程序、服务及受管防火墙规则。Ctrl+C / TERM 也进入取消与回滚流程；进程被强制杀死或系统断电后，保留的事务可用 `onebox recover` 继续恢复。若恢复仍失败，保留错误与事务目录，处理问题后再次运行，不要直接删除回滚文件。

## 链路测试、调优与回退

菜单 **21** 提供链路工具与调优入口。探测、测速和回退由 Rust 原生实现；客户端需要适配本机 Linux 架构的 `onebox`、`curl`、`openssl` 以及相应的 sing-box / Xray 可执行文件，无需 Bash / Python，也无需 root，不启动系统服务。

### 真实链路测试

先在服务器导出，再将适配客户端架构的原生 `onebox` 和导出的文件私密复制到实际使用代理的 Linux 客户端。也可使用 `/etc/onebox/client/probe.json`，它随客户端配置一起生成。

```bash
# 服务器：目标文件必须不存在，权限为 0600；包含客户端凭据，不含服务端私钥
onebox probe export /root/probe.json

# 客户端：查看 ID，再从真实客户端网络进行测试
./onebox probe list probe.json
./onebox bench probe.json --output bench-before.json

# 自选、允许你进行测试的端点；下载最多读取 4 MiB，上传 POST 4 MiB
./onebox bench probe.json --entries vless-reality,hysteria2 \
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

命令默认只预览，`--apply` 才应用；菜单中的相应选项在确认后应用。配置经过内核校验，失败由事务恢复。需要长期保留调优前的状态时，先运行 `onebox backup before-tuning`，之后可用 `onebox restore ID` 恢复。应用后需重新导入客户端配置/探测文件，再用同一客户端、端点和参数对比报告。

| 选项 | 实际改变 | 适用范围 |
|---|---|---|
| `auto` | 服务端要求客户端使用 BBR，不指定固定带宽 | sing-box Hysteria2 服务端 |
| `conservative` | 上述行为 + `bbr_profile=conservative` | sing-box 服务端/客户端 ≥ 1.14；mihomo ≥ 1.19.32 |
| `measured` | 指定上传/下载 Mbps，选择 Hysteria 带宽控制；服务端方向自动反转 | sing-box Hysteria2 服务端；sing-box / mihomo 客户端 |
| `balanced` | 不覆盖内核接收窗口和并发默认值 | 原生默认行为 |
| `low-memory` | 流/连接接收窗口 2 / 5 MiB；服务端并发流上限 64 | sing-box Hysteria2 ≥ 1.14；客户端窗口同时输出到 mihomo |
| `throughput` | 流/连接接收窗口 16 / 40 MiB；服务端并发流上限 1024 | 同上；高时延/带宽链路需实测验证 |

`--up` 和 `--down` 始终以**客户端视角**填写，单位为 Mbps，需为大于 0 且不超过 100000 的数值。请依据可用带宽并留余量；随意填大数可能拥塞。窗口是上限而非预分配量，高并发下仍可能增加内存占用。保持 QUIC 默认 MTU 探测和握手特征设置，不关闭私网拦截。系统 TCP BBR、UDP socket buffer 和 QUIC 拥塞控制是不同层面的设置，本功能仅报告系统参数，不修改 sysctl。

这些调优不作用于 TUIC 或 Xray Hysteria2 服务端；不支持的服务端组合会明确拒绝。Xray 客户端和分享链接不携带这些新增调优字段，需要完整 sing-box / mihomo 配置才能复现实测设置。原有未调优的 sing-box 客户端仍兼容 ≥ 1.12。

### REALITY 一致性检查

```bash
onebox reality-check                           # 服务器：回环检查
./onebox reality-check probe.json         # 客户端：真实路径检查
./onebox reality-check probe.json --entries vless-reality \
  --url https://your-test.example/health --output reality-report.json
```

检查普通 TLS 访问的证书名称/信任链、TLS 1.3、h2、参考目标与节点的证书/ALPN/HTTP 状态/重定向一致性；比较页面前 64 KiB 摘要，内容不同给出警告。还会分别启动正确凭据和错误 short ID 的真实客户端，验证正常代理成功、错误凭据无法代理。动态页面或负载均衡证书可能产生差异，需要人工核对，不能仅据此认定被识别。

自建站的远端参考入口使用服务器的 HTTPS 443；未启用时提示无法从客户端比较，服务器回环检查仍比较实际内部端口。自有测试 CA 可通过 `--ca` 指定。只检查配置中的入口与参考站，不枚举其他目标。返回 0 表示所检项目通过，1 表示有失败，2 表示只有警告。普通 TLS 回落和错误凭据拒绝分别验证，不声称捕获了错误 REALITY 握手的完整指纹，也不保证不可识别。本机检查不证明公网可达。

### 客户端多入口回退

```bash
# 一个服务器：默认选首个 TCP 入口为主、首个 UDP 传输入口为备
./onebox failover probe.json

# 不同服务器/IP：分别导出，然后在客户端合并（不复制服务端私钥）
./onebox probe merge combined.json server-a.json server-b.json
./onebox probe list combined.json
./onebox failover combined.json \
  --entries n1-vless-reality,n2-hysteria2 \
  --port 2080 --interval 15 --failures 3 --recoveries 3 --cooldown 60
```

应用程序连接 `socks5h://127.0.0.1:2080`，域名应通过 SOCKS 发送。`--entries` 从左到右为优先级，支持 2–8 个入口；没有 TCP+UDP 组合时可显式选择两个入口。每轮经各入口请求健康端点，连续失败达到阈值才切换，优先入口连续恢复且冷却期到期才切回；全部失败时拒绝新连接，不直连。冷却期不妨碍从已经故障的入口紧急切走。

这是前台运行的 **SOCKS5 CONNECT/TCP** 工具：Hysteria2/TUIC 入口可用 UDP 传输承载这些 TCP 流，但本地接口不提供 SOCKS UDP ASSOCIATE、HTTP 代理或 TUN；游戏等原生 UDP 应用继续使用完整客户端配置。只切换新连接，不迁移或主动切断已有连接。Ctrl+C 会清理临时内核、配置与监听端口。监听仅限本机，临时内核另设随机认证；每个所选入口运行一个内核，低内存设备建议只选两个。最多同时处理 128 条连接，空闲连接 5 分钟回收。

同 IP 的多协议能应对部分协议/传输故障，不能应对整个 IP 不可达；IP 冗余需要合并实际不同服务器的配置。健康端点失效也会触发切换，请使用稳定的自有端点。合并文件含所有入口的客户端凭据，保持私密。

## 开发与测试

运行 Rust 静态检查和单元测试，以及仅使用本地模拟文件的引导测试：

```bash
cargo fmt --check
cargo clippy --all-targets --locked -- -D warnings
cargo test --all-targets --locked
bash tests/bootstrap.sh
```

真实协议测试使用官方 sing-box / Xray / mihomo；`tests/fetch_tools.py` 可按固定版本下载并校验测试工具。下列生命周期测试会运行服务、修改受控测试目录与网络状态，适合容器或 CI 环境：

```bash
cargo build --locked
ONEBOX_TEST_BINARY="$PWD/target/debug/onebox" \
  ONEBOX_TEST_SINGBOX=/path/sing-box ONEBOX_TEST_XRAY=/path/xray \
  MH=/path/mihomo python3 tests/native_e2e.py

sudo env ONEBOX_TEST_BINARY="$PWD/target/debug/onebox" \
  ONEBOX_TEST_SINGBOX=/path/sing-box python3 tests/native_lifecycle.py --require-full

# 原生运行时、FRP、HTTPS 订阅等标记为 ignored 的真实进程测试
ONEBOX_TEST_BINARY="$PWD/target/debug/onebox" \
  ONEBOX_TEST_SINGBOX=/path/sing-box ONEBOX_TEST_XRAY=/path/xray \
  ONEBOX_FRPS_BIN=/path/frps ONEBOX_FRPC_BIN=/path/frpc \
  ONEBOX_NGINX_BIN=/path/nginx cargo test --lib --locked -- --include-ignored --test-threads=1
```

完整 CI 步骤见 `.github/workflows/ci.yml`。协议矩阵、错误凭据拒绝、客户端回退、迁移、失败注入与恢复分别测试；不能用配置生成成功代替真实连通性测试。测试状态以相应提交的 Native CI 结果为准。

## 免责声明

本项目仅供学习与研究网络技术使用，请遵守当地法律法规。
