# Sing-Xray-Onebox

**sing-box / Xray 多协议代理服务端 · 一键安装与管理（v3.0.0）**

Onebox 用一条命令在 Linux VPS 上部署 VLESS-Reality、XHTTP、Hysteria2、TUIC、AnyTLS、Trojan、SS-2022、ShadowTLS 等 12 种协议的任意组合，服务端内核可选 sing-box、Xray 或两者共存，并自动生成 sing-box / mihomo / Xray 客户端完整配置、分享链接、Base64 订阅和二维码。3.x 是一个静态链接的 Rust 程序 `onebox`；`onebox.sh` 只负责下载、校验并启动它。

## 特性

- **协议组合**：6 个预设或自定义组合；sing-box 与 Xray 可单独或同时承载。
- **客户端输出**：sing-box（TUN / 仅代理端口）、mihomo（含 proxy-provider）、Xray 完整配置，分享链接、Base64、终端二维码。
- **证书**：自签（客户端固定指纹）、Let's Encrypt（HTTP-01 或 Cloudflare DNS）、自备证书；每日自动续期，只重启受影响的服务（详见 [install.md](docs/install.md#证书)）。
- **自有域名网站**：用自己的域名作为 REALITY 目标，自动建站、申请证书，支持模板与内容导入。
- **远程订阅**：IP 直连 HTTP 或域名 HTTPS，按设备创建、撤销、重置链接。
- **FRP 服务端**：HTTPS 网站转发或 TCP/UDP 端口转发，一键导出 frpc 配置。
- **性能与诊断**：BBR / BBRv3、Hysteria2 调优、真实链路测速、多入口回退、REALITY 一致性检查、体检。
- **安全变更**：所有修改先校验后写入，失败自动回滚；快照备份、故障恢复、脱敏诊断包。
- **平台**：systemd、OpenRC 与无 init 环境；预编译 amd64、arm64、386（i586+）、armv7。

## 快速开始

仅支持 Linux，需要 root 权限；引导脚本需要 `curl`，以及 `sha256sum`、`shasum`、`openssl` 三者之一。

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/mutsuki14/Sing-xray-onebox/main/onebox.sh)
```

其他方式：

```bash
# 国内服务器（GitHub 访问困难）：经 HTTPS 镜像前缀下载。引导脚本、校验文件和程序
# 都由镜像提供，镜像可以同时替换它们：使用镜像即信任镜像，请只用可信镜像。
# 程序随后下载内核等文件时也经镜像，但 Release 元数据始终直连 api.github.com，申请
# Let's Encrypt 证书需直连 raw.githubusercontent.com：主机仍需能访问这两个地址（见 docs/install.md#系统要求）
GH_PROXY=https://ghfast.top/ bash <(curl -fsSL https://ghfast.top/https://raw.githubusercontent.com/mutsuki14/Sing-xray-onebox/main/onebox.sh)

# Alpine 等无 Bash 的系统（先 apk add curl）：引导脚本是 POSIX sh
curl -fsSL https://raw.githubusercontent.com/mutsuki14/Sing-xray-onebox/main/onebox.sh -o onebox.sh && sh onebox.sh

# 本地传入程序（不经引导脚本下载）：先把 onebox.sh、程序和同一 Release 的 SHA256SUMS
# （从 GitHub Release 页面直接取得）放到当前目录，自行校验并赋予执行权限，再交给引导脚本
# （它不校验 ONEBOX_NATIVE_BIN）。安装节点时仍会联网下载 sing-box / Xray、缺失的依赖包并检测公网地址；
# 完全离线需预装依赖、为所用内核设置 ONEBOX_SINGBOX_BIN / ONEBOX_XRAY_BIN、用 --addr 指定地址，且不用 Let's Encrypt
# 证书（见 docs/install.md#环境变量）
grep ' onebox-linux-amd64-musl$' SHA256SUMS | sha256sum -c - && chmod 700 onebox-linux-amd64-musl \
  && ONEBOX_NATIVE_BIN=./onebox-linux-amd64-musl sh onebox.sh

# 源码构建（其他 CPU 架构）
git clone https://github.com/mutsuki14/Sing-xray-onebox.git && cd Sing-xray-onebox
cargo build --release --locked && sudo ./target/release/onebox
```

首次运行选择 **1) 安装**。安装后程序固定在 `/usr/local/bin/onebox`，以后直接执行 `onebox` 打开菜单。引导脚本固定为自身版本（3.0.0）：只下载同一版本 Release 的程序，用该 Release 的 `SHA256SUMS` 校验（使用 `GH_PROXY` 时校验文件同样经镜像下载），并确认程序报告的版本一致后才运行；`ONEBOX_NATIVE_BIN` 指定的本地程序按原样运行，引导脚本不做任何校验。下载的程序在临时目录中运行，若 `/tmp` 禁止执行（noexec），用 `TMPDIR` 指定其他目录。无人值守安装见 [docs/install.md](docs/install.md)。

## 交互菜单

`onebox` 不带参数时打开菜单，顶部两行显示版本、正在使用的内核与节点状态（下例为双内核节点）：

```text
Onebox 3.0.0 · sing-box 1.14.2 · Xray 26.3.27
节点 203.0.113.10 · 5 个协议 · 内核运行中
  1) 节点信息与分享  查看节点、导出客户端配置、二维码
  2) 协议管理        添加 / 删除协议、修改端口
  3) 连接与伪装      连接地址、REALITY 目标、ShadowTLS、TLS 证书
  4) 远程订阅
  5) 自有域名网站
  6) 服务            状态、启动/停止/重启、日志
  7) 性能与诊断      调优、体检、链路测试、BBR
  8) 备份与恢复      快照、恢复、故障恢复、重新生成配置
  9) FRP 服务端
 10) 更新            程序、内核、更新渠道
 11) 重装 / 卸载
  0) 退出
请选择 [默认: 0]:
```

未安装时顶部显示 `尚未安装节点`，菜单为 `1) 安装  2) 安装预演  3) FRP 服务端  4) BBR  5) 更新程序`；存在快照时另有 `恢复快照`，存在未完成的配置事务时另有 `故障恢复`。每个子菜单先显示当前设置，再列出操作（`0) 返回`）；输入有误会提示并重新询问；操作失败显示 `[错误] …` 后回到原菜单。在菜单提示处按 Ctrl+D 或 Ctrl+C 退出（退出码 130），在某个操作的提问中按 Ctrl+D 或 Ctrl+C 只取消该操作（提示 `[提示] 操作已取消` 后回到原菜单）；收到 TERM 或 HUP 信号（`kill`、关闭终端）时菜单退出（退出码 130）。只有既没有终端输入、也打不开 `/dev/tty` 时（例如 cron、CI、不分配终端的 `ssh 主机 onebox`），`onebox` 才打印命令概览而不打开菜单；标准输入是管道但仍在终端中运行时，菜单照常从终端读取。

## 安装向导

每一步以 `步骤 i/5 · 标题` 开头，只询问命令行选项没有给出的内容：

| 步骤 | 内容 |
|---|---|
| 1/5 协议组合 | 选择预设 1–6，或 7 自定义多选（含两种内核都支持的协议时再选优先内核） |
| 2/5 伪装目标 | 选择了任一 REALITY 类协议、且命令行未指定伪装目标时：Microsoft、Apple、自定义域名或自有域名一键建站 |
| 3/5 证书 | 选择了任一需要证书的协议（或 VMess-WS）、且未给出 `--tls` 时：无域名推荐自签；有域名可选 Let's Encrypt（HTTP-01 / Cloudflare DNS）或自备证书 |
| 4/5 连接地址与端口 | 显示检测到的公网 IPv4 / IPv6 作为默认地址；端口自动分配，可选自定义 |
| 5/5 确认 | 汇总表（协议、内核、端口、传输层），`确认安装？ [Y/n]` |

确认后按阶段显示进度（如 `[3/13] 准备证书…`）；成功后询问是否启用系统 BBR（`--no-bbr` 跳过），再显示节点信息卡和下一步提示（如 `onebox client mihomo`、`onebox subscription enable`）。

## 协议组合

| 预设 | 协议 | 内核 | 说明 |
|---|---|---|---|
| 1 | VLESS-Reality-Vision + Hysteria2 + TUIC | sing-box | **推荐**，无需域名，TCP 与 UDP 互为备份 |
| 2 | VLESS-Reality-Vision + VLESS-XHTTP-Reality + SS-2022 | Xray | Vision 与 XHTTP 共用 443 端口 |
| 3 | Reality-Vision、XHTTP（Xray）+ Hysteria2、TUIC、AnyTLS（sing-box） | 双内核 | 各取所长 |
| 4 | Reality、gRPC-Reality、Trojan、SS-2022、Hysteria2、TUIC、AnyTLS、ShadowTLS、VMess-WS | sing-box | 全家桶 |
| 5 | VLESS-WS-TLS + VMess-WS | sing-box | 可套 CDN，建议使用域名证书 |
| 6 | VLESS-Reality-Vision | Xray | 单协议，最简部署 |
| 7 | 自定义 | 任选 | 12 种协议任意组合；两种内核都支持的协议默认用 sing-box，可改选 Xray |

协议 ID（用于 `--protocols`、`add`、`del`、`port`）：`vless-reality` `vless-xhttp` `vless-grpc` `vless-ws` `vmess-ws` `trojan` `shadowsocks` `hysteria2` `tuic` `anytls` `shadowtls` `anytls-reality`。

## 协议与客户端支持

| 协议 | 服务端内核 | 链接 / Base64 | mihomo | sing-box | Xray | 证书 |
|---|---|:-:|:-:|:-:|:-:|---|
| VLESS-Reality-Vision | sing-box / Xray | ✅ | ✅ | ✅ | ✅ | 无需（REALITY） |
| VLESS-XHTTP-Reality | Xray | ✅ | ✅ | ❌ | ✅ | 无需（REALITY） |
| VLESS-gRPC-Reality | sing-box / Xray | ✅ | ✅ | ✅ | ✅ | 无需（REALITY） |
| VLESS-WS-TLS | sing-box / Xray | ✅ | ✅ | ✅ | ✅ | 需要 |
| VMess-WS | sing-box / Xray | ✅ | ✅ | ✅ | ✅ | 可选（有正式证书时启用 TLS） |
| Trojan-TLS | sing-box / Xray | ✅ | ✅ | ✅ | ✅ | 需要 |
| Shadowsocks-2022 | sing-box / Xray | ✅ | ✅ | ✅ | ✅ | 无需 |
| Hysteria2 | sing-box / Xray（实验性） | ✅ | ✅ | ✅ | ✅ | 需要 |
| TUIC-v5 | sing-box | ✅ | ✅ | ✅ | ❌ | 需要 |
| AnyTLS | sing-box | ✅ | ✅ | ✅ | ❌ | 需要 |
| ShadowTLS-v3 | sing-box | ❌ | ✅ | ✅ | ❌ | 借用大站握手 |
| AnyTLS-REALITY | sing-box | ❌ | ❌ | ✅ | ❌ | 无需（REALITY） |

- “需要”证书时默认自签，客户端完整配置会固定证书指纹；也可改用 Let's Encrypt 或自备证书。
- 客户端版本：sing-box ≥ 1.12，mihomo ≥ 1.19.3（含 XHTTP 时 ≥ 1.19.22）。AnyTLS-REALITY 只能通过 sing-box 完整配置使用。
- 默认安装 Xray 26.3.27（与 sing-box REALITY 客户端测试过的版本）。其他 Xray 版本可能拒绝 sing-box REALITY 客户端，`onebox update xray` 换到其他版本前会提示并要求确认。

## 常用命令

| 命令 | 作用 |
|---|---|
| `onebox` | 打开交互菜单 |
| `onebox install` | 安装（交互向导；无人值守选项见 [install.md](docs/install.md)） |
| `onebox plan --preset 1` | 只读安装预演：不写文件、不联网、不申请证书 |
| `onebox info` | 节点信息、凭据与导出方式 |
| `onebox client mihomo` | 导出客户端配置，另有 `singbox` `singbox-notun` `xray` `links` `sub` `provider` |
| `onebox qr` | 在终端显示分享链接二维码 |
| `onebox add hysteria2` / `onebox del tuic` | 添加 / 删除协议 |
| `onebox port vless-reality 8443` | 修改协议端口 |
| `onebox sni` | 更换 REALITY / ShadowTLS 伪装目标（凭据不变） |
| `onebox subscription enable` | 启用远程订阅，详见 [subscription.md](docs/subscription.md) |
| `onebox status` / `onebox log xray` | 内核运行状态 / 内核日志（最近 200 行） |
| `onebox restart` | 重启代理内核 |
| `onebox doctor` | 体检：内核、配置、服务、证书、网站、订阅、FRP 与未完成事务 |
| `onebox backup 标签` / `onebox restore latest` | 保存快照 / 恢复快照 |
| `onebox update-script` / `onebox update` | 更新本程序 / 更新正在使用的内核 |

`onebox help` 按类别列出全部命令；`onebox help 命令` 或 `onebox 命令 --help` 查看单个命令的用法与选项。`-y` 表示无人值守（使用默认值并自动确认）。

## 文档

| 文档 | 内容 |
|---|---|
| [安装与部署](docs/install.md) | 无人值守安装、预设、端口、证书、REALITY 目标 |
| [客户端导入](docs/clients.md) | 各客户端导入方式、导出格式、二维码、AnyTLS-REALITY |
| [远程订阅](docs/subscription.md) | IP / 自有域名网站 / 独立域名三种入口、设备管理 |
| [自有域名网站](docs/website.md) | 自有域名网站作为 REALITY 目标、模板、内容导入与恢复 |
| [FRP 服务端](docs/frp.md) | 网站模式、TCP/UDP 模式、客户端导出 |
| [BBR / BBRv3](docs/bbr.md) | 启用 BBR、安装 BBRv3 内核及风险 |
| [性能与链路测试](docs/performance.md) | Hysteria2 调优、测速、多入口回退、REALITY 检查 |
| [日常维护](docs/maintenance.md) | 服务、日志、体检、备份恢复、更新、卸载、文件位置 |
| [常见问题](docs/troubleshooting.md) | 连不上、证书、端口、事务与报错 |
| [从 v2 升级](docs/upgrade-v2.md) | v3 的变化与修复的问题 |
| [开发与测试](docs/development.md) | 架构、构建、测试与发布流程 |

## 从 v2 升级

v3 可原地升级 v2.x：协议、端口、UUID、密码、REALITY 密钥、证书、网站内容、订阅设备链接和 FRP 配置全部保留，安装路径和服务名不变。

```bash
onebox backup before-v3        # 可选：用于在 v3 内恢复节点状态，不能回到 v2
onebox update-script           # v2 内置的程序更新：下载、校验 3.x，替换后自动 regen
onebox version                 # 应显示 3.0.0
onebox doctor
```

也可以用引导脚本完成同样的迁移：`curl -fsSL https://raw.githubusercontent.com/mutsuki14/Sing-xray-onebox/main/onebox.sh -o onebox.sh && sh onebox.sh regen`。**不要用 `install` 代替迁移**，重装会生成新凭据并清除订阅设备。迁移失败会自动回滚并保留 v2；迁移成功后没有受支持的降级方式，需要退路请在升级前做 VPS 磁盘快照（详见 [upgrade-v2.md](docs/upgrade-v2.md#回退)）。首次保存时原 v2 状态另存为 `/etc/onebox/state.v2.json`。

1.x（`/etc/onebox/onebox.conf`）不能直接升级，程序会提示先经 v2.0.1 迁移：

```bash
curl -fsSL https://raw.githubusercontent.com/mutsuki14/Sing-xray-onebox/v2.0.1/onebox.sh -o onebox-v2.sh && sh onebox-v2.sh regen
```

完成后再按上面的步骤更新到 3.x。v3 的全部变化见 [docs/upgrade-v2.md](docs/upgrade-v2.md)。

## 许可与免责声明

本项目以 MIT 许可发布。仅供学习与研究网络技术使用，请遵守所在地法律法规；使用者自行承担部署与使用的责任。
