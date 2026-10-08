# 常见问题

先运行 `onebox doctor`，它会指出配置、服务、证书和未完成事务中的问题。下面按现象列出常见原因。

## 连接

### 安装成功但客户端连不上

1. **云安全组**：在服务商控制台放行实际端口，TCP 与 UDP 分开（Hysteria2、TUIC 是 UDP；启用端口跳跃需放行整个 UDP 范围；HTTP-01 证书需要 TCP 80，续期同样需要）。本机防火墙由程序自动放行。
2. **服务状态**：`onebox status`，再看 `onebox log` / `onebox log xray`。
3. **客户端配置是否最新**：改过端口、目标、证书或重置过凭据后需要重新导入或刷新订阅。
4. **REALITY 失败**：换一个伪装目标（`onebox sni`，凭据不变），目标需支持 TLS 1.3，且尽量与服务器地理位置接近；可用 `onebox reality-check` 检查。
5. **时间同步**：SS-2022 要求服务器与客户端时间误差在 30 秒内，VMess 在 120 秒内。开启时间同步：`timedatectl set-ntp true` 或安装 chrony。

### 部分协议能用、部分不能

多半是 UDP 被封或未放行（Hysteria2 / TUIC），或客户端版本不支持（见 [clients.md](clients.md#客户端版本要求)）。在客户端用 `onebox bench probe.json` 逐个入口测试（[performance.md](performance.md)）。

### 更新 Xray 后 sing-box 客户端连不上 REALITY

26.4 之后的 Xray REALITY 服务端要求客户端支持 X25519MLKEM768，会拒绝 sing-box 客户端。退回测试版本：`onebox update xray 26.3.27`（版本低于当前时需加 `--force`）<!-- TODO: verify -->，或改由 sing-box 承载该协议。

## 安装与下载

### 下载失败 / GitHub 无法访问

设置 HTTPS 加速前缀后重试：`GH_PROXY=https://ghfast.top/`（或其他可用前缀）。引导脚本的校验文件和程序都经前缀下载，镜像可以同时替换二者，请只使用可信前缀。纯 IPv6 主机无法直连 GitHub，需要支持 IPv6 的加速前缀，或先配置 WARP / NAT64。发布资产暂时下载不到时，可等待发布流程完成，或[源码构建](../README.md#快速开始)。

### 纯 IPv6 或配置了 WARP

程序会识别 WARP 出口地址（不能用于入站），默认改用本机 IPv6 作为客户端连接地址；也可用 `onebox addr --addr 地址` 指定。

### 提示需要 root、未安装或没有终端

| 提示 | 处理 |
|---|---|
| `此操作需要 root 权限` | 用 root 或 `sudo` 运行 |
| `尚未安装 Onebox，请先执行 onebox install` | 当前主机没有节点状态 |
| `已安装 Onebox；无人值守重装会生成新凭据，请追加 --force，或使用 onebox regen 保留现有凭据` | 确认要重装就加 `--force`，否则用 `regen` |
| `无人值守模式请通过环境变量提供凭据` | `-y` 时无法输入密码类信息，例如通过 `CF_Token` 提供 Cloudflare Token |
| `{命令} 不支持选项 {选项}` | 选项写错或不属于该命令，查看 `onebox 命令 --help` |
| `检测到 Onebox 1.x 配置（onebox.conf）…` | 先用 v2.0.1 迁移，见 [upgrade-v2.md](upgrade-v2.md#从-1x-升级) |
| `配置由更新版本的 Onebox 写入（schema N），请先更新程序` | 程序比状态文件旧，执行 `onebox update-script` |

## 端口

### 端口被占用或冲突

自动分配会避开已监听和已预留的端口；手动指定的端口不可用时会报错且不做任何修改。用 `ss -lntup` 查看占用者，或换端口：`onebox port 协议 端口`。只有 Xray 承载的 Vision 与 XHTTP 可以共用 TCP 端口。

### 网站或证书需要的 80 / 443 被占用

网站与 HTTP-01 证书需要 TCP 80；网站 443 入口需要 TCP 443 未被其他程序或非 REALITY 协议占用。释放端口，或改用 Cloudflare DNS 证书（`--tls cf`）、关闭 443 入口（`onebox site https off`）。Onebox 使用独立的 nginx 实例，不接管系统已有的 nginx 网站。

## 证书

### Let's Encrypt 申请失败

- 域名 A / AAAA 必须直接指向本机，关闭 CDN 代理；有 AAAA 时 IPv6 必须可达。
- HTTP-01：TCP 80 必须从公网可达（云安全组）且未被占用。
- Cloudflare DNS：`CF_Token` 需要该区域的 DNS 编辑权限；`CF_Account_ID` 可留空自动查询。
- Let's Encrypt 有频率限制，多次失败后请稍后再试。失败时原证书和配置保持不变。

### 证书快到期

`onebox doctor` 会在 7 天内到期时警告。检查计划任务是否存在（`crontab -l | grep onebox:renew`）、cron 服务是否运行，然后手动续期：`onebox cert renew proxy`、`onebox site renew`、`onebox subscription renew`。

## 事务与并发

| 提示 | 原因与处理 |
|---|---|
| `另一个配置操作正在进行；稍后重试` | 另一个 Onebox 命令（或计划任务）正在修改配置，等它结束 |
| `配置已被其他操作修改，请重新读取后重试` | 在你操作期间配置被改过，重新执行命令 |
| `检测到未完成事务` / `请执行 recover` | 上次操作被强制中断，执行 `onebox recover` |
| `配置未应用，已恢复原状态: …` | 新配置未通过校验或服务启动失败，已自动回滚；按冒号后的原因处理 |
| `配置失败: …；恢复未完成: …` | 自动回滚也失败，按提示处理后执行 `onebox recover`；不要删除事务目录 |

## 订阅

| 现象 | 处理 |
|---|---|
| 链接返回 404 | 令牌错误、设备已撤销，或该格式没有可用节点（如只有 AnyTLS-REALITY 时没有 `mihomo`）；忘记令牌请 `onebox subscription reset 设备ID` |
| 客户端拒绝 HTTP 订阅 | 换用 `site` 或 `standalone` 的 HTTPS 入口 |
| 切换入口后旧链接失效 | 令牌不变，只需把 URL 的协议、地址和端口改成新入口 |

## 更新

- `onebox update-script` 成功后程序会结束当前进程（包括菜单），这是预期行为，重新运行 `onebox` 即可。
- 退出码 75（`自更新恢复已完成；当前进程仍是被替换版本…`）：上次程序更新被中断并已恢复，重新执行命令即可。

## 退出码

| 退出码 | 含义 |
|---|---|
| 0 | 成功 |
| 1 | 错误（标准错误输出 `[错误] …`） |
| 2 | `reality-check` 只有警告 |
| 75 | 程序更新恢复已完成，需重新执行命令 |
| 130 | 已取消（Ctrl+C、Ctrl+D 或输入结束） |
