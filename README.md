# Sing-Xray-Onebox

**sing-box / Xray 多协议代理服务端 · 一键安装与管理（v3.0.0）**

Onebox 用一条命令在 Linux VPS 上部署 VLESS-Reality、XHTTP、Hysteria2、TUIC、AnyTLS、Trojan、SS-2022、ShadowTLS 等 12 种协议的任意组合，服务端内核可选 sing-box、Xray 或两者共存，并自动生成 sing-box / mihomo / Xray 客户端完整配置、分享链接、Base64 订阅和二维码。3.x 是一个静态链接的 Rust 程序 `onebox`；`onebox.sh` 只负责下载、校验并启动它。

## 特性

- **协议组合**：7 个预设或自定义组合；sing-box 与 Xray 可单独或同时承载。
- **客户端输出**：sing-box（TUN / 仅代理端口）、mihomo、Xray 完整配置，分享链接、Base64、终端二维码。
- **证书**：自签（客户端固定指纹）、Let's Encrypt（HTTP-01 或 Cloudflare DNS）、自备证书，自动续期。
- **自有域名网站**：用自己的域名作为 REALITY 目标，自动建站、申请证书，支持模板与内容导入。
- **远程订阅**：IP 直连 HTTP 或域名 HTTPS，按设备创建、撤销、重置链接。
- **FRP 服务端**：HTTPS 网站转发或 TCP/UDP 端口转发，一键导出 frpc 配置。
- **性能与诊断**：BBR / BBRv3、Hysteria2 调优、真实链路测速、多入口回退、REALITY 一致性检查、体检。
- **安全变更**：所有修改先校验后写入，失败自动回滚；快照备份、故障恢复、脱敏诊断包。
- **平台**：systemd、OpenRC 与无 init 环境；预编译 amd64、arm64、386（i586+）、armv7。

## 快速开始

需要 root 权限；引导脚本需要 `curl`，以及 `sha256sum`、`shasum`、`openssl` 三者之一。

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/mutsuki14/Sing-xray-onebox/main/onebox.sh)
```

其他方式：

```bash
# 国内服务器（GitHub 访问困难）：设置 HTTPS 加速前缀
GH_PROXY=https://ghfast.top/ bash <(curl -fsSL https://ghfast.top/https://raw.githubusercontent.com/mutsuki14/Sing-xray-onebox/main/onebox.sh)

# Alpine 等无 Bash 的系统（先 apk add curl）：引导脚本是 POSIX sh
curl -fsSL https://raw.githubusercontent.com/mutsuki14/Sing-xray-onebox/main/onebox.sh -o onebox.sh && sh onebox.sh

# 离线：使用已取得的可信程序，引导脚本不联网、不下载
ONEBOX_NATIVE_BIN=/root/onebox-linux-amd64-musl sh onebox.sh

# 源码构建（其他 CPU 架构）
git clone https://github.com/mutsuki14/Sing-xray-onebox.git && cd Sing-xray-onebox
cargo build --release --locked && sudo ./target/release/onebox
```

首次运行选择 **1) 安装**。安装后程序固定在 `/usr/local/bin/onebox`，以后直接执行 `onebox` 打开菜单。引导脚本只下载与自身版本一致的 Release 资产，并用同一 Release 的 `SHA256SUMS` 校验<!-- TODO: verify launcher still pins its own version -->；无人值守安装见 [docs/install.md](docs/install.md)。

## 交互菜单

`onebox` 不带参数时打开菜单，顶部显示版本与节点状态：

```text
Onebox 3.0.0 · sing-box 1.14.2 · Xray 26.3.27
节点 203.0.113.10 · 3 个协议 · 内核运行中

 1) 节点信息与分享     查看节点、导出客户端配置、二维码
 2) 协议管理           添加 / 删除协议、修改端口
 3) 连接与伪装         连接地址、REALITY 目标、ShadowTLS、TLS 证书
 4) 远程订阅
 5) 自有域名网站
 6) 服务               状态、启动/停止/重启、日志
 7) 性能与诊断         调优、体检、链路测试、BBR
 8) 备份与恢复         快照、恢复、故障恢复、重新生成配置
 9) FRP 服务端
10) 更新               程序、内核、更新渠道
11) 重装 / 卸载
 0) 退出
```

未安装时菜单为 `1) 安装  2) 安装预演  3) FRP 服务端  4) BBR  5) 更新程序  0) 退出`。每个子菜单先显示当前设置，再列出操作（`0) 返回`）；输入有误会提示并重新询问，操作失败显示 `[错误] …` 后回到原菜单；Ctrl+D 退出（退出码 130）。

## 安装向导

| 步骤 | 内容 |
|---|---|
| 1/5 协议组合 | 选择预设 1–6，或 7 自定义多选 |
| 2/5 伪装目标 | 仅选了 REALITY 协议时：Microsoft、Apple、自定义域名或自有域名一键建站 |
| 3/5 证书 | 仅选了需要证书的协议时：无域名推荐自签；有域名可选 Let's Encrypt 或自备证书 |
| 4/5 连接地址与端口 | 显示检测到的公网 IP；端口自动分配，可选自定义 |
| 5/5 确认 | 汇总表（协议、内核、端口、传输层），`确认安装？ [Y/n]` |

确认后按阶段显示进度（`[i/n] 阶段名…`），完成后显示节点信息卡和下一步提示（如 `onebox client mihomo`、`onebox subscription enable`），最后可选择启用系统 BBR。

## 协议组合

| 预设 | 协议 | 内核 | 说明 |
|---|---|---|---|
| 1 | VLESS-Reality-Vision + Hysteria2 + TUIC | sing-box | **推荐**，无需域名，TCP 与 UDP 互为备份 |
| 2 | VLESS-Reality-Vision + VLESS-XHTTP-Reality + SS-2022 | Xray | Vision 与 XHTTP 共用 443 端口 |
| 3 | Reality-Vision、XHTTP（Xray）+ Hysteria2、TUIC、AnyTLS（sing-box） | 双内核 | 各取所长 |
| 4 | Reality、gRPC-Reality、Trojan、SS-2022、Hysteria2、TUIC、AnyTLS、ShadowTLS、VMess-WS | sing-box | 全家桶 |
| 5 | VLESS-WS-TLS + VMess-WS | sing-box | 可套 CDN，建议使用域名证书 |
| 6 | VLESS-Reality-Vision | Xray | 单协议，最简部署 |
| 7 | 自定义 | 任选 | 12 种协议任意组合，并选择优先内核 |

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
- 默认安装 Xray 26.3.27。更新的 Xray REALITY 服务端会拒绝 sing-box 客户端，`onebox update xray` 更换版本前会要求确认。

## 常用命令

| 命令 | 作用 |
|---|---|
| `onebox` | 打开交互菜单 |
| `onebox install` | 安装（交互向导；无人值守选项见 [install.md](docs/install.md)） |
| `onebox plan --preset 1` | 只读安装预演，不写文件、不联网 |
| `onebox info` | 节点信息与分享链接 |
| `onebox client mihomo` | 导出客户端配置，另有 `singbox` `singbox-notun` `xray` `links` `sub` `provider` |
| `onebox qr` | 在终端显示分享链接二维码 |
| `onebox add hysteria2` / `onebox del tuic` | 添加 / 删除协议 |
| `onebox port vless-reality 8443` | 修改协议端口 |
| `onebox sni` | 更换 REALITY / ShadowTLS 伪装目标（凭据不变） |
| `onebox subscription enable` | 启用远程订阅，详见 [subscription.md](docs/subscription.md) |
| `onebox status` / `onebox log xray` | 服务状态 / 查看日志 |
| `onebox restart` | 重启代理服务 |
| `onebox doctor` | 体检：配置、服务、证书、网站、订阅、FRP、未完成事务 |
| `onebox backup 标签` / `onebox restore latest` | 保存快照 / 恢复快照 |
| `onebox update-script` / `onebox update` | 更新本程序 / 更新内核 |

`onebox help` 按类别列出全部命令；`onebox 命令 --help` 查看单个命令的用法与选项。`-y` 表示无人值守（使用默认值并自动确认）。

## 文档

| 文档 | 内容 |
|---|---|
| [安装与部署](docs/install.md) | 无人值守安装、预设、端口、证书、REALITY 目标 |
| [客户端导入](docs/clients.md) | 各客户端导入方式、导出格式、二维码、AnyTLS-REALITY |
| [远程订阅](docs/subscription.md) | IP / 自建站 / 独立域名三种入口、设备管理 |
| [自有域名网站](docs/website.md) | 自建 REALITY 网站、模板、内容导入与恢复 |
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
onebox backup before-v3        # 可选：先保存一份快照
onebox update-script           # v2 内置的程序更新：下载、校验 3.x，替换后自动 regen
onebox version                 # 应显示 3.0.0
onebox doctor
```

也可以用引导脚本完成同样的迁移：`curl -fsSL https://raw.githubusercontent.com/mutsuki14/Sing-xray-onebox/main/onebox.sh -o onebox.sh && sh onebox.sh regen`。**不要用 `install` 代替迁移**，重装会生成新凭据。迁移失败会自动回滚并保留 v2；首次保存时原 v2 状态另存为 `/etc/onebox/state.v2.json`。

1.x（`/etc/onebox/onebox.conf`）不能直接升级，程序会提示先经 v2.0.1 迁移：

```bash
curl -fsSL https://raw.githubusercontent.com/mutsuki14/Sing-xray-onebox/v2.0.1/onebox.sh -o onebox-v2.sh && sh onebox-v2.sh regen
```

完成后再按上面的步骤更新到 3.x。v3 的全部变化见 [docs/upgrade-v2.md](docs/upgrade-v2.md)。

## 许可与免责声明

本项目以 MIT 许可发布。仅供学习与研究网络技术使用，请遵守所在地法律法规；使用者自行承担部署与使用的责任。
