# 日常维护

## 服务与日志

```bash
onebox status                        # 各代理内核是否运行（不需要 root）
onebox start | stop | restart        # 启动 / 停止 / 重启代理内核
onebox log                           # sing-box 日志（最近 200 行，别名 logs）
onebox log xray                      # Xray 日志
onebox service onebox-site restart   # 单独控制某个 Onebox 服务
onebox service onebox-site log
```

`service 服务名 [操作]` 支持的操作：`start`、`stop`、`restart`、`enable`、`disable`、`remove`、`status`（默认）、`log`。服务没有 `reload`，请用 `restart`。`status` 和 `log` 不需要 root；`start` 遇到正在进行的配置变更时会等待其结束（最长 5 分钟）再启动，并确认服务已经运行。

日志位置：systemd 上来自 `journalctl`；OpenRC 和无 init 环境写入 `/var/log/onebox/<服务名>.log`（FRP 服务写入 `/var/log/onebox-frp/`）。

| 服务 | 作用 |
|---|---|
| `onebox-sing-box`、`onebox-xray` | 代理内核 |
| `onebox-site` | 自有域名网站（独立 nginx） |
| `onebox-subscription`、`onebox-subscription-web` | 订阅服务、独立 HTTPS 订阅入口（nginx） |
| `onebox-network` | 开机恢复防火墙规则与端口跳跃（执行 `onebox net-apply`，别名 `boot`） |
| `onebox-frps`、`onebox-frp-web` | FRP 服务端与其网站入口 |

无 init 环境（如部分容器）由 Onebox 自己管理进程，每个启用的服务对应一条 `@reboot` 计划任务用于开机启动（见[计划任务](#计划任务)）。

## 体检与诊断包

```bash
onebox doctor     # 体检
onebox support    # 生成脱敏诊断文件
```

`doctor` 逐行输出 `[通过]`、`[警告]`、`[失败]`，最后汇总。检查内容：节点状态文件、未完成的事务、已安装的程序、内核程序与配置有效性、服务运行与开机自启、代理 / 网站 / 独立订阅证书（已过期或缺失为失败，7 天内到期为警告）、网站与订阅的 nginx 配置、续期计划任务、防火墙与端口跳跃记录，以及 FRP。有失败项时提示 `体检发现 N 个需要处理的问题` 并以退出码 1 结束，警告不影响退出码。它不检查公网 DNS、云安全组和真实客户端连通性，这些请配合 `onebox reality-check` / `bench`（见 [performance.md](performance.md)）。

`support` 在 `/etc/onebox/` 生成权限 600 的 `support-{Unix 时间}-{随机串}.json`，并打印 `已生成脱敏诊断文件: 路径`。文件记录程序版本、系统信息（架构、发行版、内核、init、虚拟化）、协议与端口、内核版本与运行状态、证书方式、启用的功能、是否有待恢复的事务，以及脱敏后的全部体检结果；**不含**凭据、IP 地址、域名、日志或证书内容，也不会自动上传。`doctor` 和 `support` 都需要 root。

## 备份与恢复

```bash
onebox backup before-change    # 保存备份并打印备份 ID；标签可选（默认 manual）
onebox backups                 # 列出备份（按创建时间，最新在前）
onebox restore latest          # 恢复最新备份（默认 latest）；也可指定备份 ID
```

- 备份（快照）保存在 `/etc/onebox/backups/`，包含节点状态、代理证书与私钥、网站管理目录与证书、网站网页、订阅设备与订阅证书、客户端文件；目录 700、文件 600，**含敏感凭据**，不要当作公开诊断材料。
- 保留最近 5 份；单份最多 64 MiB / 4096 个文件。FRP、内核程序和操作系统不在备份中。
- `restore` 先显示备份 ID、说明和时间并确认（默认否，`-y` 视为同意）。恢复前校验完整性，把当前状态另存为 `before-restore` 备份，再以事务方式应用；内核校验或启动失败会自动回滚。客户端文件不从备份复制，而是按恢复后的配置重新生成。
- 恢复会带回备份中的订阅设备列表，之前撤销的设备可能重新出现，请核对 `onebox subscription info`。
- v2 生成的备份可直接恢复（自动迁移）；1.x 格式的备份会被拒绝，需先用 2.0.1 恢复后再升级。
- 备份用于本机恢复，不是完整系统或跨 VPS 迁移工具。

## 中断恢复与重新生成

每次配置变更都记录持久事务日志：先渲染并校验新配置，再替换文件和服务；任一步失败恢复原文件、证书、服务和受管防火墙规则，提示 `配置未应用，已恢复原状态: …`。Ctrl+C / TERM 会在当前阶段结束后取消并回滚（退出码 130）。

```bash
onebox recover    # 进程被强制结束或断电后，回滚中断的事务
onebox regen      # 按当前状态重新生成并应用全部配置（凭据不变）
```

- `recover` 依次处理节点配置事务、被中断的程序更新和 FRP 事务；没有待处理的内容时提示 `没有需要恢复的事务`。下一次配置变更开始前也会先自动恢复遗留事务。
- 看到 `存在未完成事务，请先 recover` 或以 `请执行 recover` 结尾的错误时运行 `onebox recover`。恢复仍失败时，错误信息会指出保留的事务目录；排除问题后再次运行，**不要手动删除** `/etc/onebox/.transaction/`。
- `regen` 用于修复被手动改坏的服务或配置文件，以及从 v2 迁移；直接修改生成的配置文件不会被保留，下次变更会重新生成。

## 更新

```bash
onebox update-check              # 只检查，不下载（不需要 root）
onebox update-script             # 更新 Onebox 程序（保留旧命令名）
onebox update-channel            # 查看更新渠道；update-channel testing 切换
onebox update                    # 更新正在使用的内核
onebox update singbox 1.14.2     # 指定内核版本（并固定该版本）
onebox update xray 26.3.27 --force
onebox version
```

**程序更新**：从所选渠道的 GitHub Release 下载 `onebox-linux-{架构}-musl`，用 API 提供的 SHA-256 或 Release 的 `SHA256SUMS`（直接从 github.com 获取）校验，确认版本后替换程序并由新版本自动 `regen`；失败恢复旧程序和配置。拒绝降级，内容相同则提示 `已是当前发布的最新内容`。成功后提示 `程序更新已完成；请重新执行 onebox 以使用新版本` 并结束当前进程（包括菜单），重新执行 `onebox` 即可使用新版本。

| 渠道 | 来源 |
|---|---|
| `stable`（默认） | 最新正式 Release |
| `testing` | 名为 `testing` 的预发布；只在维护者发布后可用 |

`update-script testing` 只对本次生效，`update-channel testing` 保存偏好。

**内核更新**：只更新当前配置实际使用的内核，所有目标先下载校验，再在一次配置事务中替换；新内核未通过配置校验或启动失败时恢复旧版本。

| 命令 | 目标版本 | 固定版本 |
|---|---|---|
| `onebox update` / `update all` | 已固定的版本，否则推荐版本 | 不变 |
| `onebox update 内核` | 推荐版本 | 取消固定 |
| `onebox update 内核 latest` | 最新 Release | 取消固定 |
| `onebox update 内核 版本` | 指定版本 | 固定为该版本 |

- 推荐版本：sing-box 为最新版，Xray 为 26.3.27。安装时的 `--singbox-version` / `--xray-version` 同样会固定版本。
- 目标低于已安装版本时拒绝降级，需要追加 `--force`（`--force` 也会重新安装相同版本）；不带内核名的 `onebox update` 遇到更高的已安装版本时保持不变并提示。
- Xray 目标不是 26.3.27 时先警告（更新的 Xray 可能拒绝 sing-box 的 REALITY 客户端）并要求确认，`-y` 视为同意。
- 版本号只能用于单个内核；两个内核都在使用时 `update all 版本` 会被拒绝。

## 计划任务

Onebox 只管理自己带标记的 crontab 行，不改动其他行：

| 标记 | 时间 | 作用 | 输出 |
|---|---|---|---|
| `# onebox:renew` | 每天 04:17 | `onebox renew --cron`：检查代理、网站、独立订阅证书，30 天内到期才续期 | `/var/log/onebox/renew.log` |
| `# onebox:frp-renew` | 每天 03:17 | `onebox frps renew --cron`：FRP 证书检查与续期 | `/var/log/onebox-frp/renew.log` |
| `# onebox:boot:服务名` | `@reboot` | 仅无 init 环境：开机执行 `onebox service 服务名 start` | `/var/log/onebox/boot.log`（FRP 为 `/var/log/onebox-frp/boot.log`） |

- `renew` 行只在存在 Let's Encrypt 或自备证书（代理、网站或独立订阅）时安装；只有自签证书的节点不需要计划任务。需要 Let's Encrypt 证书但 cron 未运行时，配置变更会在开始前报错；自备证书只给出警告。
- 续期等待正在进行的配置操作结束（最长 10 分钟），只续期到期的证书，并只重启受影响的服务：代理证书 → 代理内核，网站证书 → `onebox-site`，独立订阅证书 → `onebox-subscription-web`。只有代理证书的指纹或公共信任状态发生变化（例如自签证书重新生成）时，才执行一次完整配置事务，重新发布客户端配置与订阅。无事可做时不输出。
- 时间按系统时区。每行都带固定的 `PATH` 和 Onebox 的路径环境变量，不含任何凭据。
- 手动执行 `onebox renew` 会强制续期全部证书（单个证书：`onebox cert renew proxy|site|subscription`）。

## 卸载

```bash
onebox uninstall           # 卸载代理节点
onebox frps uninstall      # 单独卸载 FRP
```

`uninstall` 先确认（默认否，`-y` 视为同意），然后自动保存 `before-uninstall` 备份（失败则中止）。

- **删除**：服务 `onebox-sing-box`、`onebox-xray`、`onebox-site`、`onebox-subscription`、`onebox-subscription-web`、`onebox-network`；受管防火墙规则与端口跳跃规则；节点的计划任务；sing-box / Xray 内核与服务端配置；`/etc/onebox/client/`、`/etc/onebox/subscription/`（含订阅设备）、代理证书目录 `/etc/onebox/tls/`（含私钥）、服务定义；最后删除 `state.json` 与 `state.v2.json`。
- **保留**：网站管理目录与证书、网站网页及其内容备份、`/etc/onebox/backups/`、`onebox` 程序、FRP（独立管理）、系统安装的 nginx 软件包，以及 BBR 设置与通过 `onebox bbr` 安装的系统内核。
- 某一步失败时其余步骤照常执行，最后汇总报错，状态文件保留；解决问题后再次执行 `onebox uninstall` 即可。

## 文件位置

| 路径 | 内容 |
|---|---|
| `/usr/local/bin/onebox` | 管理程序 |
| `/etc/onebox/state.json` | 节点状态（schema 3，权限 600） |
| `/etc/onebox/state.v2.json` | 从 v2 迁移时保留的原状态 |
| `/etc/onebox/sing-box.json`、`xray.json` | 服务端配置 |
| `/etc/onebox/tls/` | 代理证书 |
| `/etc/onebox/client/` | 客户端配置与探测配置 `probe.json` |
| `/etc/onebox/subscription/` | 订阅设备（只存令牌哈希）、已发布内容、独立入口证书 |
| `/etc/onebox/site/` | 网站管理目录、网站证书、内容备份 |
| `/etc/onebox/backups/` | 节点备份 |
| `/etc/onebox/support-*.json` | 诊断文件 |
| `/var/lib/onebox-site/` | 网站网页 |
| `/opt/onebox/bin/` | sing-box / xray 内核 |
| `/var/log/onebox/` | 服务日志（非 systemd 环境）与计划任务输出 |
| `/etc/onebox-frp/`、`/opt/onebox-frp/`、`/var/log/onebox-frp/` | FRP 状态与证书、程序、日志 |
| `/etc/sysctl.d/99-onebox-bbr.conf` | BBR 设置 |

各根目录可用环境变量覆盖（如 `ONEBOX_DIR`、`ONEBOX_BIN_DIR`，见 [development.md](development.md)），一般无需修改。
