# 从 v2 升级到 v3

v3 是完全重写的版本，可原地升级 v2.x：协议、端口、UUID、密码、REALITY 密钥、证书、网站内容、订阅设备链接和 FRP 配置全部保留。

## 升级方式

```bash
onebox backup before-v3     # 可选：用于在 v3 内恢复节点状态，不能回到 v2
onebox update-script        # 由 v2 下载并安装 3.x
onebox version              # 应显示 3.0.0
onebox doctor
```

v2 的 `update-script` 从 GitHub 最新 Release 下载 `onebox-linux-{架构}-musl`，用 API 提供的 SHA-256 校验，确认新程序 `version` 输出为 `3.0.0` 后替换 `/usr/local/bin/onebox`，再在持有配置锁的情况下让 v3 执行一次 `regen`：读取并迁移 v2 状态，以完整事务重写服务单元、计划任务、服务端与客户端配置和订阅内容，并重启订阅服务到新版本。期间代理内核会短暂重启。v3 迁移失败时会先回滚自己的事务再退出，v2 随后恢复旧程序，节点保持 v2 状态。

也可以用引导脚本完成同样的迁移（例如主机无法直连 `api.github.com`，需要配合 `GH_PROXY` 时）：

```bash
curl -fsSL https://raw.githubusercontent.com/mutsuki14/Sing-xray-onebox/main/onebox.sh -o onebox.sh
sh onebox.sh regen

# 无法直连 GitHub 时，脚本本身和发布文件都经加速前缀下载
curl -fsSL https://ghfast.top/https://raw.githubusercontent.com/mutsuki14/Sing-xray-onebox/main/onebox.sh -o onebox.sh
GH_PROXY=https://ghfast.top/ sh onebox.sh regen
```

引导脚本下载 3.0.0 程序并执行 `regen`，迁移时把自己安装到 `/usr/local/bin/onebox`；失败同样整体回滚，保留 v2。`GH_PROXY` 镜像同时提供程序和校验文件 `SHA256SUMS`，可以同时替换二者，请只使用可信的前缀。

**不要用 `install` 代替迁移**，重装会生成新凭据并清除订阅设备。升级后客户端无需重新导入；不过 v3 修复了若干客户端配置问题（见下文），重新导入或刷新订阅可获得修复。

## 回退

- 只有迁移**失败**时才会自动回滚：v3 撤销自己的事务，v2 恢复旧程序并重新生成 v2 配置，节点保持 v2 状态。
- 迁移**成功**后没有受支持的降级方式：v2 无法读取 schema 3 的状态，订阅设备也已移到 `devices.json`。`onebox backup before-v3` 这类备份只能在 v3 内恢复节点状态，不能回到 v2。
- 需要保留回到 v2 的退路时，请在升级前做一次 VPS / 磁盘快照，需要时在服务商控制台整体恢复。

## 从 1.x 升级

v3 不再读取 1.x 的 `/etc/onebox/onebox.conf`，也不能恢复 1.x 格式的备份。检测到 1.x 配置时会提示：

```text
检测到 Onebox 1.x 配置（onebox.conf）。3.x 只能从 2.x 升级：请先执行 curl -fsSL https://raw.githubusercontent.com/mutsuki14/Sing-xray-onebox/v2.0.1/onebox.sh -o onebox-v2.sh && sh onebox-v2.sh regen，再更新到 3.x。
```

按提示先用 v2.0.1 执行 `regen`（生成 v2 的 `state.json`），确认 `onebox doctor` 正常后，再按上一节升级。FRP 的 1.x 状态文件 `/etc/onebox-frp/state.conf` 仍可读取，下一次 FRP 变更时写入新格式的 `state.json`（`state.conf` 保持不动）。

## 保持不变

- **路径与服务名**：`/etc/onebox`、`/opt/onebox/bin`、`/var/lib/onebox-site`、`/etc/onebox-frp` 等全部路径，`onebox-sing-box`、`onebox-xray`、`onebox-site`、`onebox-subscription(-web)`、`onebox-network`、`onebox-frps`、`onebox-frp-web` 等服务名。
- **防火墙与锁**：防火墙台账 `firewall-v2.json`、端口跳跃台账 `hop-v2.json`、各锁文件路径。
- **命令行**：v2 的命令名、别名和选项名保持不变，但每个命令只接受属于自己的选项（见[不再接受的 v2 写法](#不再接受的-v2-写法)）。v2 写入的服务单元与计划任务所调用的命令（`net-apply`、`cert renew … --cron`、`subscription renew --cron`、`subscription serve`、`service 名称 start`、`frps net-apply`、`frps renew --cron`、`frps start`）在被重写前仍然有效。
- **协议与预设**：协议 ID、预设 1–7 及其协议列表、客户端文件名（`/etc/onebox/client/` 下）。
- **订阅**：设备 ID、令牌（只存哈希）和 `/sub/令牌/格式` 链接不变。
- **备份**：v2 备份（schema 2）可直接 `restore`（自动迁移，带回其中的订阅设备）。v3 写出的备份沿用同一清单格式（schema 2），但其中的 `state.json` 是 schema 3，只能由 v3 恢复。
- **事务恢复**：v2 留下的未完成配置事务和程序更新日志，v3 的 `onebox recover` 都能恢复。

## 变化

### 状态文件

`/etc/onebox/state.json` 从 v2 的 `{"values": {...}}` 字符串表改为带类型的 `"schema": 3` 结构，加载时完整校验。首次保存时，原 v2 文件另存为 `/etc/onebox/state.v2.json`（权限 600）。

| 字段 | 内容 |
|---|---|
| `schema` | 固定为 `3` |
| `node_name`、`server`、`listen` | 节点名称、客户端连接地址（及检测到的 IPv4 / IPv6）、监听地址 |
| `inbounds` | 协议列表：`protocol`、`port`、`core` |
| `creds` | UUID、密码、REALITY 密钥、路径等凭据 |
| `reality`、`shadowtls` | 伪装目标（含 Xray REALITY 使用的本地 guard 端口） |
| `site`、`tls`、`subscription` | 网站、代理证书、订阅入口（未使用时为 `null`） |
| `vmess_tls`、`vmess_host`、`hy2`、`resource_profile`、`routing` | 协议细节、调优与出站限制 |
| `versions`、`installed_at` | 已安装与固定的内核版本、安装时间 |

- 状态文件由程序维护，请用命令修改，不要手动编辑。
- v2 程序无法读取 schema 3；v3 不提供降级（见[回退](#回退)）。`state.v2.json` 只是升级前原始状态的存档，供排查问题时参考。
- 订阅入口设置合并进 `state.json`；设备列表单独保存在 `/etc/onebox/subscription/devices.json`（只含令牌哈希）。
- 迁移时逐项说明被补全、规范化或丢弃的值。例如 v2 中与已安装版本不一致的内核固定版本（v2 的 `onebox update` 会忽略它）会被取消，避免升级时降级内核。

### 设置只在生效时保留

v2 关闭网站或删除最后一个需要证书的协议后，会在状态里保留原来的网站、证书设置并在以后重新启用时沿用。v3 不再保留这些“休眠”设置：重新启用时从默认值开始（自签证书；网站标题“山间手记”、模板 minimal、配色 forest），除非命令中另行指定。网站网页和内容备份仍保留在磁盘上；REALITY 密钥与 v2 一样在删除最后一个 REALITY 协议后保留。

### 计划任务

v2 的多条计划任务合并为带统一标记的行，固定 `PATH`，输出写入日志文件（v2 丢弃到 `/dev/null`）：

| v2 | v3 |
|---|---|
| `… cert renew proxy --cron … # onebox-native-cert-proxy` | 合并为一行 `17 4 * * * … renew --cron >>'/var/log/onebox/renew.log' 2>&1 # onebox:renew` |
| `… cert renew site --cron … # onebox-native-cert-site` | 同上 |
| `… subscription renew --cron … # onebox-native-cert-subscription` | 同上 |
| `@reboot … service 名称 start … # onebox-rust:名称`（仅无 init） | `@reboot … service 名称 start >>'/var/log/onebox/boot.log' 2>&1 # onebox:boot:名称` |
| `… frps renew --cron … # onebox-frps-renew` | `17 3 * * * … frps renew --cron >>'/var/log/onebox-frp/renew.log' 2>&1 # onebox:frp-renew` |
| `@reboot … frps start … # onebox-frps-boot` | systemd / OpenRC 下删除（服务已设为开机启动）；无 init 时改为 `# onebox:boot:onebox-frps`（网站模式另有 `onebox-frp-web`） |

- 节点的行在升级时的 `regen` 中改写。`renew` 行只在存在 Let's Encrypt 或自备证书时安装；只有自签证书的节点会删除 v2 的三条续期行，不再需要计划任务。
- FRP 的行在下一次 FRP 事务中改写：任意 FRP 变更，或每天 03:17 由旧行触发的 `frps renew --cron`。在此之前 v2 的行继续有效。
- 续期不再每次执行完整配置事务，通常只重启受影响的服务（见 [maintenance.md](maintenance.md#计划任务)）。

### 交互与命令行

- **主菜单重新编排**为 11 项（见 [README](../README.md#交互菜单)），v2 的 1–28 编号不再适用；协议选择编号和预设编号不变。菜单提示处按 Ctrl+D 或 Ctrl+C 退出（退出码 130），操作中的提问按 Ctrl+C 只取消该操作。
- 安装向导分为 5 步，最后显示汇总表确认；配置应用时逐阶段显示进度。
- 每个命令都有自己的帮助：`onebox 命令 --help` 或 `onebox help 命令`（有子命令的命令也可用 `onebox 命令 help`）。
- 新命令：`onebox renew`（立即强制续期全部证书；计划任务用 `renew --cron`，只续期 30 天内到期的证书）、`onebox boot`（`net-apply` 的别名）、`onebox frps rotate-ca`（轮换 FRP 私有 CA 与控制证书，已导出的客户端需重新导出）。
- 二维码由程序直接绘制，不再需要 `qrencode`。
- 菜单中操作出错后回到当前子菜单（v2 回到主菜单）；文本输入校验失败时就地重新询问，不再中止操作。
- 重装（已安装时 `install`）会清除订阅设备，旧订阅链接全部失效。
- `uninstall` 现在同时删除代理证书目录 `/etc/onebox/tls/`（含私钥）、订阅数据与服务定义；网站内容、备份和 FRP 仍保留（见 [maintenance.md](maintenance.md#卸载)）。

### 不再接受的 v2 写法

v2 对所有命令接受同一组选项（无关的选项被忽略，个别甚至绕过检查直接生效）；v3 按命令校验，以下写法会报错（或输出格式不同），脚本需要调整：

- 不属于该命令的选项：例如 `addr --port`、`addr --sni`、`sni --port`，提示 `{命令} 不支持选项 {选项}；请执行 onebox {命令} --help`。`--dry-run` 只用于 `plan`、`install`、`frps install|configure` 和 `bbr install`，其他命令提示 `此命令不支持 --dry-run`。
- `-y` / `--yes`、`-h` / `--help` 只在作为独立参数时生效，不会再吞掉选项值（`--name -y` 把名称设为 `-y`）。
- 已安装时 `install -y` 必须加 `--force`。
- `--preset N` 与 `--protocols` 同时使用时 `N` 必须为 7；`--site-title` 需要配合 `--reality-site`；`--cert` / `--key` 需要配合 `--tls custom`。
- `cert set` 在 `-y` 下必须给出 `--tls`（v2 静默选择自签证书）。
- `service 名称 reload` 不再支持，请用 `restart`。
- 两个内核都在使用时 `update all 版本` 被拒绝（版本号只能用于单个内核）；`update 内核` 指定当前未使用的内核时报错。
- `probe merge` 至少需要两份输入。
- `onebox client mihomo` 以及 `mihomo.yaml`、`provider.yaml` 和订阅的 `mihomo` / `provider` 格式输出标准 YAML，不再是 JSON；按 JSON 解析的脚本需要改用 YAML 解析。`onebox client` 的输出末尾只有一个换行。

## v3 修复的 v2 问题

**端口与配置**

- 默认值统一：网站内部端口默认 10443（v2 不同模块分别使用 8443 / 10443 / 8444）；订阅端口默认 8448（v2 部分模块对独立模式按 443 处理）。
- 自动分配端口时避开 Hysteria2 跳跃范围、HTTP-01 的 80 端口、网站、订阅和 FRP 预留端口，不再先分配再报冲突。
- `addr`、`sni` 只接受各自的选项（v2 的 `addr --port` 等写法会绕过端口检查）。
- 修改 ShadowTLS 伪装域名时同步清除单独指定的握手地址（v2 可能残留旧目标）。
- 修改连接地址不再残留旧的 IPv4 / IPv6，订阅和客户端不会用到过期 IP。
- `add` 添加需要证书的协议时自动准备证书，并重新计算 VMess-WS 是否启用 TLS。
- Hysteria2 带宽统一校验为 1–10000 的整数 Mbps（v2 调优接受小数或更大值，应用时才失败）；Xray 承载的 Hysteria2 明确拒绝不支持的调优（v2 静默忽略）。
- 未安装时提示“尚未安装”，而不是原始文件错误。

**交互与命令行**

- `-y` 不会再静默重装并更换全部凭据。
- 菜单不再把输入的文字当作命令执行。
- 事务中按 Ctrl+C 取消时退出码为 130（v2 为 1）。
- `frps --help`、各链路工具的 `--help` 可以显示对应帮助；`frps install|configure --dry-run` 可用；`bbr` 预览不再要求 root。

**证书与网站**

- 计划任务带固定 `PATH` 并记录日志，精简 cron 环境下续期也能找到 nginx 和防火墙工具（v2 可能静默失败直到证书过期）；三个续期任务合并为一个，不再同时抢锁。
- 证书续期不再执行完整配置事务、重启全部服务：只重启受影响的服务；只有客户端固定了证书指纹（自签证书，或不受公共信任的自备证书）且证书更换，或公共信任状态改变时，才重新发布客户端配置与订阅。
- 只有自签证书时不再要求 cron 运行（v2 在无 cron 的容器中连自签安装也会失败）。
- 重启后网站与订阅入口的 nginx 临时目录在服务启动时自动重建（v2 重启后可能无法启动）。
- 手动续期真正强制续期。
- HTTP-01 不再依赖 `socat`；已有 Onebox 网站占用 80 时，其他域名的证书也能通过它验证。
- Cloudflare 凭据只传给 acme.sh，不再泄漏到其他进程；acme.sh 按固定 SHA-256 校验。
- 证书指纹取与私钥匹配的叶证书，不受证书链顺序影响。
- 网站内容备份限制为最近 10 份（v2 无限增长）。

**服务、防火墙与备份**

- 后台服务以干净的环境变量启动，管理员 shell 中的 Token 等不会被继承。
- `/etc/init.d` 等系统目录是符号链接的发行版不再因此无法应用配置。
- 已卸载的防火墙工具（如 ufw）残留规则不再导致整个变更失败；HTTP-01 所需的 80 端口规则在各种写法下一致放行。
- 备份按创建时间排序而不是按名称（v2 中 1.x 格式的备份名会排在最前，导致 `restore latest` 选错、轮换误删新备份）。

**订阅与更新**

- 新建或重置设备时总能拿到令牌（v2 在订阅内容缺失时不显示链接，令牌就此丢失）。
- IP 直连订阅由程序直接提供，不再需要 nginx（升级时移除 ip 模式的 `onebox-subscription-web`）。
- 独立 HTTPS 订阅（`standalone`）证书续期只重启订阅入口，不再重启全部代理内核。
- 程序更新后订阅服务会重启到新版本。
- 程序更新可用 Release 的 `SHA256SUMS` 校验（v2 只依赖 API 提供的摘要）。
- 内核更新只针对使用中的内核；遵守并维护固定版本；拒绝静默降级；更换 Xray 版本前会确认（v2 只打印警告）。

**FRP、BBR 与诊断**

- FRP：`--tls cf` 首次安装不再被拒绝；系统 nginx 包不再占用 80 / 443；泛域名摘要与导出的子域标签一致；版本未变时不再重新下载 frps；网站模式不再无故预留 20000–20100；私有 CA 临近到期时可用 `frps rotate-ca` 轮换。
- BBR：内核安装时实时显示 apt / dpkg 输出。
- `doctor` 覆盖网站、订阅、计划任务和 FRP；已过期或缺失的证书记为失败；`openssl` 缺失或事务日志损坏时报告为检查项而不是中断；诊断包文件名不会冲突。
