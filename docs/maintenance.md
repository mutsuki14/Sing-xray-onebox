# 日常维护

## 服务与日志

```bash
onebox status                     # 各代理内核是否运行
onebox start | stop | restart     # 启动 / 停止 / 重启代理内核
onebox log                        # sing-box 日志（最近 200 行）
onebox log xray                   # Xray 日志
onebox service onebox-site restart   # 单独控制某个 Onebox 服务
onebox service onebox-site log
```

`service` 支持的操作：`start`、`stop`、`restart`、`enable`、`disable`、`status`、`log`。<!-- TODO: verify final action list --> systemd 上日志来自 `journalctl`；OpenRC 和无 init 环境写入 `/var/log/onebox/<服务名>.log`。

| 服务 | 作用 |
|---|---|
| `onebox-sing-box`、`onebox-xray` | 代理内核 |
| `onebox-site` | 自有域名网站（独立 nginx） |
| `onebox-subscription`、`onebox-subscription-web` | 订阅服务、独立 HTTPS 订阅入口 |
| `onebox-network` | 开机恢复防火墙规则与端口跳跃（执行 `onebox net-apply`，别名 `boot`） |
| `onebox-frps`、`onebox-frp-web` | FRP 服务端与其网站入口 |

无 init 环境（如部分容器）由 Onebox 自己管理进程，并通过 `@reboot` 计划任务开机启动。

## 体检与诊断包

```bash
onebox doctor     # 体检
onebox support    # 生成脱敏诊断文件
```

`doctor` 逐项输出 `[通过]`、`[警告]`、`[失败]`：内核配置有效性、服务运行状态、代理 / 网站 / 订阅证书（7 天内到期为警告）、网站、订阅、FRP，以及未完成的事务；有失败项时退出码非零。它不检查公网 DNS、云安全组和真实客户端连通性，这些请配合 `onebox reality-check` / `bench`（见 [performance.md](performance.md)）。

`support` 在 `/etc/onebox/` 生成权限 600 的 JSON（`support-时间戳…json`）<!-- TODO: verify file name pattern -->，记录程序与内核版本、系统信息、协议端口、服务和事务状态；**不含**凭据、IP、域名、私钥、订阅内容、原始日志或环境变量，也不会自动上传。

## 快照备份与恢复

```bash
onebox backup before-change    # 保存快照，标签可选（默认 manual）
onebox backups                 # 列出快照（按创建时间，最新在前）
onebox restore latest          # 恢复最新快照；也可指定 ID
```

- 快照保存在 `/etc/onebox/backups/`，包含节点状态、受管证书与私钥、网站内容、客户端文件和订阅设置；目录 700、文件 600，**含敏感凭据**，不要当作公开诊断材料。
- 保留最近 5 份<!-- TODO: verify retention -->；单份最多 64 MiB / 4096 个文件。FRP、内核程序和操作系统不在快照中。
- 恢复前校验完整性，先把当前状态另存为 `before-restore` 快照，再以事务方式应用；内核校验或启动失败会自动回滚。
- 恢复会带回快照中的订阅设备列表，之前撤销的设备可能重新出现，请核对 `onebox subscription info`。
- v2 生成的快照可直接恢复；1.x 格式的快照不再支持。
- 快照用于本机恢复，不是完整系统或跨 VPS 迁移工具。

## 中断恢复与重新生成

每次配置变更都记录持久事务日志：先渲染并校验新配置，再替换文件和服务；任一步失败恢复原文件、证书、服务和受管防火墙规则，提示 `配置未应用，已恢复原状态: …`。Ctrl+C / TERM 会在当前阶段结束后取消并回滚（退出码 130）。

```bash
onebox recover    # 进程被强制结束或断电后，继续完成恢复
onebox regen      # 按当前状态重新生成并应用全部配置（凭据不变）
```

- 看到 `检测到未完成事务` 或 `请执行 recover` 时先运行 `onebox recover`。恢复仍失败时，错误信息会指出保留的事务目录；排除问题后再次运行，**不要手动删除** `/etc/onebox/.transaction/`。
- `regen` 用于修复被手动改坏的服务或配置文件，以及从 v2 迁移；直接修改生成的配置文件不会被保留，下次变更会重新生成。

## 更新

```bash
onebox update-check              # 只检查，不下载
onebox update-script             # 更新 Onebox 程序（保留旧命令名）
onebox update-channel            # 查看更新渠道；update-channel testing 切换
onebox update                    # 更新正在使用的内核
onebox update singbox 1.14.2     # 指定内核版本
onebox update xray 26.3.27
onebox version
```

**程序更新**：从所选渠道的 GitHub Release 下载 `onebox-linux-{架构}-musl`，校验 API 提供的 SHA-256 或 Release 的 `SHA256SUMS`，确认版本后原子替换并自动 `regen`；失败恢复旧程序和配置。拒绝降级，内容相同则跳过。更新完成后当前进程（包括菜单）结束，重新执行 `onebox` 即可使用新版本。

| 渠道 | 来源 |
|---|---|
| `stable`（默认） | 最新正式 Release |
| `testing` | 名为 `testing` 的预发布；只在维护者发布后可用 |

`update-script testing` 只对本次生效，`update-channel testing` 保存偏好。

**内核更新**：只更新当前协议实际使用的内核，遵守安装时 `--singbox-version` / `--xray-version` 的固定版本；目标版本低于已安装版本时需要 `--force`<!-- TODO: verify flag spelling and position -->。Xray 默认 26.3.27，指定其他版本前会要求确认（更新的 Xray 会拒绝 sing-box 客户端的 REALITY 连接；`-y` 视为同意）。新内核未通过配置校验或启动失败时恢复旧版本。

## 计划任务

Onebox 只管理自己带标记的 crontab 行，不改动其他行：

| 标记 | 时间 | 作用 |
|---|---|---|
| `# onebox:renew` | 每天 04:17 | `onebox renew --cron`：检查代理、网站、独立订阅证书，30 天内到期才续期 |
| `# onebox:frp-renew` | 每天 03:17 | FRP 证书检查与续期 |
| `# onebox:boot:服务名` | `@reboot` | 仅无 init 环境：开机启动服务 |

每行都带固定的 `PATH` 和 Onebox 的路径环境变量，不含任何凭据；输出追加到 `/var/log/onebox/` 下的日志。<!-- TODO: verify log file names -->

## 卸载

```bash
onebox uninstall           # 卸载代理节点
onebox frps uninstall      # 单独卸载 FRP
```

卸载前确认，并自动保存 `before-uninstall` 快照。删除代理服务、内核、服务端与客户端配置、订阅、受管防火墙规则与计划任务。**保留**：网站内容、节点快照、FRP（独立管理）、系统安装的 nginx 软件包，以及安装的 Linux 内核。<!-- TODO: verify exact list of what uninstall removes and keeps -->

## 文件位置

| 路径 | 内容 |
|---|---|
| `/usr/local/bin/onebox` | 管理程序 |
| `/etc/onebox/state.json` | 节点状态（schema 3，权限 600） |
| `/etc/onebox/state.v2.json` | 从 v2 迁移时保留的原状态 |
| `/etc/onebox/sing-box.json`、`xray.json` | 服务端配置 |
| `/etc/onebox/tls/` | 代理证书 |
| `/etc/onebox/client/` | 客户端配置与探测配置 |
| `/etc/onebox/subscription/` | 订阅设备（只存令牌哈希）、已发布快照、独立入口证书 |
| `/etc/onebox/site/` | 网站管理目录、网站证书、内容备份 |
| `/etc/onebox/backups/` | 节点快照 |
| `/var/lib/onebox-site/` | 网站网页 |
| `/opt/onebox/bin/` | sing-box / xray 内核 |
| `/var/log/onebox/` | 日志（非 systemd 环境）与计划任务输出 |
| `/etc/onebox-frp/`、`/opt/onebox-frp/` | FRP 状态、证书与程序 |
| `/etc/sysctl.d/99-onebox-bbr.conf` | BBR 设置 |

各根目录可用环境变量覆盖（如 `ONEBOX_DIR`、`ONEBOX_BIN_DIR`，见 [development.md](development.md)），一般无需修改。
