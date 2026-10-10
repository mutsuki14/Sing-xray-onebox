# 常见问题

先运行 `onebox doctor`，它会指出配置、服务、证书、计划任务和未完成事务中的问题。下面按现象列出常见原因。

## 连接

### 安装成功但客户端连不上

1. **云安全组**：在服务商控制台放行实际端口，TCP 与 UDP 分开（Hysteria2、TUIC 是 UDP；启用端口跳跃需放行整个 UDP 范围；HTTP-01 证书需要 TCP 80，续期同样需要）。本机防火墙由程序自动放行。
2. **服务状态**：`onebox status`，再看 `onebox log` / `onebox log xray`。
3. **客户端配置是否最新**：改过端口、目标、证书或重置过凭据后需要重新导入或刷新订阅。
4. **REALITY 失败**：换一个伪装目标（`onebox sni`，凭据不变），目标需支持 TLS 1.3，且尽量与服务器地理位置接近；可用 `onebox reality-check` 检查。
5. **时间同步**：SS-2022 要求服务器与客户端时间误差在 30 秒内，VMess 在 120 秒内。开启时间同步：`timedatectl set-ntp true` 或安装 chrony。

### 部分协议能用、部分不能

多半是 UDP 被封或未放行（Hysteria2 / TUIC），或客户端版本不支持（见 [clients.md](clients.md#客户端版本要求)）。在客户端用 `onebox bench probe.json` 逐个入口测试（见 [performance.md](performance.md)）。

### 更新 Xray 后 sing-box 客户端连不上 REALITY

26.4 之后的 Xray REALITY 服务端要求客户端支持 X25519MLKEM768，会拒绝 sing-box 客户端。退回测试版本：`onebox update xray 26.3.27 --force`（目标低于已安装版本时必须加 `--force`，同时会固定该版本）；或删除该协议后用 `onebox add 协议 --core singbox` 改由 sing-box 承载（VLESS-XHTTP 只能由 Xray 承载）。

## 安装与下载

### 下载失败 / GitHub 无法访问

- 设置 HTTPS 加速前缀后重试：`GH_PROXY=https://ghfast.top/`（或其他可用前缀）。引导脚本的校验文件和程序都经前缀下载，镜像可以同时替换二者，请只使用可信前缀。
- Onebox 程序（包括首次安装）下载内核、FRP、BBR 内核包和程序更新时，版本信息与校验值始终直连 `api.github.com` / `github.com`，前缀只用于传输文件内容；因此主机仍需能直连 GitHub API。
- 提示 `GitHub API 拒绝或限流；可设置 GH_TOKEN 后重试` 时，导出一个 GitHub 令牌：`read -rs GH_TOKEN && export GH_TOKEN`，再重新执行命令。
- 纯 IPv6 主机无法直连 GitHub，需要先配置 NAT64 或 WARP；也可用 `ONEBOX_SINGBOX_BIN` / `ONEBOX_XRAY_BIN` 指定本地内核文件代替下载（见 [install.md](install.md#环境变量)）。
- 发布资产暂时下载不到时，可等待发布流程完成，或[源码构建](../README.md#快速开始)。

### 纯 IPv6 或配置了 WARP

安装时默认通过外部服务检测公网 IPv4，其次 IPv6，作为客户端连接地址。开启 WARP 等出站代理时检测到的是出口地址，不能用于入站；请在安装时用 `--addr` 指定，或安装后执行 `onebox addr --addr 本机地址`。

### 提示需要 root、未安装或没有终端

| 提示 | 处理 |
|---|---|
| `此操作需要 root 权限` | 用 root 或 `sudo` 运行 |
| `尚未安装 Onebox，请先执行 onebox install` | 当前主机没有节点状态 |
| `已安装 Onebox；无人值守重装会生成新凭据，请追加 --force，或使用 onebox regen 保留现有凭据` | 确认要重装就加 `--force`，否则用 `regen` |
| `当前没有交互终端，请通过参数提供配置并使用 -y` | 在脚本或无终端环境中运行，请提供完整参数并加 `-y` |
| `无人值守模式请通过环境变量提供凭据` | `-y` 时无法输入密码类信息 |
| `Cloudflare DNS 验证缺少凭据，请提供 CF_Token（可同时提供 CF_Account_ID），或在交互终端输入` | 通过环境变量 `CF_Token` 提供 Cloudflare Token，或在交互终端运行 |
| `{命令} 不支持选项 {选项}；请执行 onebox {命令} --help` | 选项写错或不属于该命令 |
| `检测到 Onebox 1.x 配置（onebox.conf）…` | 先用 v2.0.1 迁移，见 [upgrade-v2.md](upgrade-v2.md#从-1x-升级) |
| `配置由更新版本的 Onebox 写入（schema N），请先更新程序` | 程序比状态文件旧，执行 `onebox update-script` |

## 端口

### 端口被占用或冲突

自动分配会避开已监听和已预留的端口；手动指定的端口不可用时会报错且不做任何修改。用 `ss -lntup` 查看占用者，或换端口：`onebox port 协议 端口`。只有 Xray 承载的 VLESS-Reality-Vision 与 VLESS-XHTTP 可以共用 TCP 端口。

### 网站或证书需要的 80 / 443 被占用

自有域名网站与 HTTP-01 证书需要 TCP 80；网站的 443 入口需要 TCP 443 未被其他程序或非 REALITY 协议占用。释放端口；代理证书可改用 Cloudflare DNS 验证（`--tls cf`），不再需要 80；也可关闭网站的 443 入口（`onebox site https off`）。Onebox 使用独立的 nginx 实例，不接管系统已有的 nginx 网站。

## 证书

### Let's Encrypt 申请失败

- 域名 A / AAAA 必须直接指向本机，关闭 CDN 代理；有 AAAA 时 IPv6 必须可达。
- HTTP-01：TCP 80 必须从公网可达（云安全组）且未被占用。
- Cloudflare DNS：`CF_Token` 需要该区域的 DNS 编辑权限；`CF_Account_ID` 可留空自动查询。
- 提示 `cron 未运行，无法启用证书自动续期；请启动系统 cron 服务`：Let's Encrypt 证书需要计划任务续期，先启动 cron / crond 服务再重试。
- Let's Encrypt 有频率限制，多次失败后请稍后再试。失败时原证书和配置保持不变。

### 证书快到期

`onebox doctor` 会在证书 7 天内到期时警告，并检查续期计划任务。确认计划任务存在（`crontab -l | grep onebox:renew`；只有自签证书时没有这一行，属正常）、cron 服务在运行，查看 `/var/log/onebox/renew.log`，然后手动续期：`onebox renew`（强制续期全部证书），或单独执行 `onebox cert renew proxy`、`onebox site renew`、`onebox subscription renew`。

## 事务与并发

| 提示 | 原因与处理 |
|---|---|
| `另一个配置操作正在进行；稍后重试` | 另一个 Onebox 命令（或计划任务）正在修改配置，等它结束 |
| `另一个更新正在进行` / `另一个 FRP 管理操作正在进行` | 另一个程序或内核更新、FRP 操作正在运行，等它结束 |
| `配置已被其他操作修改，请重新读取后重试` | 在你操作期间配置被改过，重新执行命令 |
| `存在未完成事务，请先 recover` / `检测到未完成事务，请先恢复` / `FRP 存在未完成事务，请先执行 onebox recover` | 上次操作被强制中断，执行 `onebox recover` |
| `配置未应用，已恢复原状态: …` | 新配置未通过校验或服务启动失败，已自动回滚；按冒号后的原因处理 |
| `配置失败: …；恢复未完成: …；事务日志保留于 …，请执行 recover` | 自动回滚也失败，按提示处理后执行 `onebox recover`；不要删除事务目录 |

## 订阅

| 现象 | 处理 |
|---|---|
| 链接返回 404 | 令牌错误、设备已撤销、订阅已关闭，或该格式没有可用节点（如只有 AnyTLS-REALITY 时没有 `mihomo`）；忘记令牌请 `onebox subscription reset 设备ID` |
| 客户端拒绝 HTTP 订阅 | 换用 `site` 或 `standalone` 的 HTTPS 入口 |
| 切换入口后旧链接失效 | 令牌不变，只需把 URL 的协议、地址和端口改成新入口 |

## 更新

- `onebox update-script` 成功后提示 `程序更新已完成；请重新执行 onebox 以使用新版本` 并结束当前进程（包括菜单），这是预期行为，重新运行 `onebox` 即可。
- 退出码 75（`自更新恢复已完成；当前进程仍是被替换版本，请重新执行命令以使用恢复后的程序`）：上次程序更新被中断并已恢复，重新执行命令即可。
- `原程序与配置已恢复…，但恢复后的管理程序重新生成配置失败: …；排除问题后执行 onebox regen`：更新失败后原程序与配置已恢复，只是重新生成配置失败（例如证书续期一直失败）。原先运行或开机自启的服务按恢复后的文件重新启动，消息中的 `并已重新启动 …` 列出实际启动的服务，`未完成: …` 列出未能完成的步骤。按错误信息排除原因后执行 `onebox regen`。若当前进程仍是被替换版本，消息末尾会提示重新执行命令，退出码为 75（菜单随之退出）。

## 退出码

| 退出码 | 含义 |
|---|---|
| 0 | 成功 |
| 1 | 错误（标准错误输出 `[错误] …`） |
| 2 | `reality-check` 只有警告（输出 `[警告] …`） |
| 75 | 程序更新恢复已完成，需重新执行命令 |
| 130 | 已取消（Ctrl+C、Ctrl+D 或输入结束） |
