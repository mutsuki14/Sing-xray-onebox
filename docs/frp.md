# FRP 服务端

`onebox frps` 管理一个独立的 [fatedier/frp](https://github.com/fatedier/frp) 服务端，用于把内网机器的网站或端口发布到这台 VPS。它与代理节点分开保存状态、证书、防火墙规则、计划任务和服务，可以单独安装和卸载。默认安装 frp **0.71.0**；下载官方 Release 时校验大小和 SHA-256（GitHub API 摘要或 Release 自带的校验和文件），并确认 `frps -v` 输出与版本一致。`GH_PROXY` 只用于下载安装包，`GH_TOKEN` 用于 GitHub API 限流。

## 两种模式

| 模式 | 公网入口 | 内部连接 |
|---|---|---|
| `web`（默认） | 浏览器通过应用域名的 HTTPS（默认 443）访问内网网站；支持单域名或一级泛域名 | 独立 nginx（服务 `onebox-frp-web`）终止 HTTPS，保留 Host 反代到 `127.0.0.1:7080` 的 frps HTTP 入口；客户端用 `type = "http"` |
| `tcp` | 控制域名 + 指定的公网端口，转发内网 TCP / UDP 服务 | 只允许配置的转发范围（默认 `20000-20100`）；不使用 nginx |

两种模式都默认用 TCP 7000 建立 frpc → frps 控制连接：强制 TLS（Onebox 私有 CA 签发的服务端证书）、随机 64 位十六进制 token，并用 token 认证心跳和工作连接。不启用 Dashboard。TCP 模式下每个客户端最多占用 10 个转发端口。

## 准备 DNS 与端口

先在 DNS 服务商处手动添加记录（程序只检查，不会创建或修改）：

| 记录示例 | 用途 | 指向 |
|---|---|---|
| `frp.example.com` | 控制域名，两种模式都需要 | 本机公网 A（有 IPv6 时同时配置正确的 AAAA） |
| `app.example.com` | 网站模式，单应用域名 | 本机公网 A / AAAA |
| `*.apps.example.com` | 网站模式，泛域名（如 `home.apps.example.com`） | 本机公网 A / AAAA |

- 安装时会解析控制域名和应用域名（泛域名用一个随机子域名检查），所有 A / AAAA 都必须指向本机；残留旧 IP、错误 AAAA 或 CDN 代理地址都会导致检查失败。Cloudflare 记录请设为**仅 DNS**。
- 域名必须是 DNS 名称，不能是 IP 地址。v2 曾允许 IP：这类旧配置升级后原样保留，但每个 FRP 命令都会提示（作为控制域名时 frpc 无法校验服务端证书），修改该项时必须改为域名。
- 云安全组放行控制端口，以及网站模式的 HTTPS（和 HTTP 跳转）端口，或 TCP 模式的整个转发范围（TCP 与 UDP）。本机防火墙由 Onebox 自动放行。
- 安装会检查代理节点（含网站、订阅、Hysteria2 跳跃范围和 HTTP-01 的 80 端口）以及其他进程占用的端口，冲突时停止，不接管已有服务。80 / 443 已被占用时，可改用 `--https-port 8443 --tls cf --redirect-port 0`，访问地址为 `https://app.example.com:8443/`。HTTP-01 必须使用并持续开放 TCP 80。
- 缺少的 curl、openssl、iproute2、cron 会自动安装；网站模式还需要 nginx：未安装时自动安装发行版的 nginx 包，并停用只提供默认欢迎页的系统 nginx 服务，FRP 只使用自己的 `onebox-frp-web` 实例。

## 安装

在交互终端中不带任何配置参数运行 `onebox frps install`（或 `configure`）进入向导；已安装时以当前配置作为默认值。向导依次询问：

1. 模式：1 HTTPS 网站，2 TCP / UDP 转发
2. 控制域名
3. 控制端口
4. 网站模式：单域名或泛域名，以及应用域名 / 泛域名根；TCP 模式：允许转发的端口范围（最多 1000 个端口）
5. 网站模式：证书方式（HTTP-01、Cloudflare DNS 或自备证书）
6. 网站模式：frps 内部 HTTP 端口、公开 HTTPS 端口、HTTP 跳转端口（HTTP-01 固定为 80，不再询问）
7. 自备证书：证书完整链与未加密私钥的路径（相对路径按当前目录解析）

回车保留默认值，`b` 返回上一步，`q` 或 Ctrl+D 取消。整体校验失败时显示原因并回到“控制端口”继续修改。选择 Cloudflare DNS 时，如果环境变量和已保存的凭据中都没有 Token，会在确认前隐藏输入。最后显示部署摘要，确认（默认否）后才修改系统。

带参数时不进入向导：参数叠加在当前配置（未安装时为默认值）上，显示摘要后请求确认，`-y` 自动确认。不适用于所选模式的参数会提示“已忽略”。先用 `plan` 或 `--dry-run` 预览（不联网、不修改系统）：

```bash
# 只读预览：网站模式，单应用域名
onebox frps plan --mode web --domain frp.example.com --web-domain app.example.com

# 网站模式：HTTPS 443，HTTP 80 跳转并用于证书验证
onebox frps install --mode web --domain frp.example.com --web-domain app.example.com --tls http

# 避开已占用的 80 / 443：Cloudflare DNS 证书 + 8443
# （Token 先隐藏输入并导出；不导出时程序会在交互终端中隐藏询问）
read -rs CF_Token && export CF_Token
onebox frps install --mode web \
  --domain frp.example.com --web-domain app.example.com \
  --tls cf --https-port 8443 --redirect-port 0

# 泛域名：需要 Cloudflare DNS 或自备泛域证书（HTTP-01 不支持）
onebox frps install --mode web \
  --domain frp.example.com --subdomain-host apps.example.com --tls cf

# TCP / UDP 转发模式
onebox frps install --mode tcp --domain frp.example.com --allow-ports 45000-45100
```

避免把 Cloudflare Token 直接写在命令行（会进入 shell 历史）；也可提供 `CF_Account_ID`。凭据随网站证书保存在 `/etc/onebox-frp/web-tls/acme/onebox-dns.json`（0600），供自动续期使用。

TCP 模式的整个转发范围会为 FRP 预留并按 TCP / UDP 放行，之后配置代理节点时会自动避开。网站模式不预留转发范围（v2 会无故预留 20000–20100），客户端也不能在网站模式下开 TCP / UDP 代理。

## 导出客户端配置

```bash
onebox frps client                                                       # 交互导出（别名 export）
onebox frps client /root/frpc-home --type http --local-port 8080         # 网站：内网 127.0.0.1:8080
onebox frps client /root/frpc-home --type http --local-port 8080 --subdomain home   # 泛域名：home.apps.example.com
onebox frps client /root/frpc-ssh --type tcp --local-port 22 --remote-port 45001    # 公网 45001 → 内网 22
onebox frps client /root/frpc-udp --type udp --local-port 27015 --remote-port 45002
```

不给目录时进入交互：TCP 模式依次询问协议（TCP / UDP）、内网端口和公网端口，网站模式询问内网端口（泛域名还询问子域标签），最后询问导出目录（默认 `./frpc-client`）。只给选项不给目录会报用法错误。默认值：网站模式 `--type http`、TCP 模式 `tcp`，`--local-port 8080`，`--remote-port` 为转发范围起点，`--subdomain www`。`--type` 必须与模式一致，`--remote-port` 必须在转发范围内。

导出目录必须尚不存在（上级目录需已存在），权限 700，文件 600，包含 `frpc.toml`、公开的 `ca.pem` 和 `README.txt`；含 token，**不含 CA 私钥、服务端私钥或网站私钥**。在内网机器安装与服务端相同版本的官方 frpc，私密复制整个目录，进入目录后运行：

```bash
frpc verify -c frpc.toml
frpc -c frpc.toml
```

必须保留 `transport.tls.trustedCaFile = "./ca.pem"` 和 `transport.tls.serverName` 校验；移除 CA 文件会失去服务端身份验证。更改控制域名或控制端口、执行 `rotate-token` 或 `rotate-ca` 后，需要重新导出并更新所有客户端。

## 证书

| 用途 | 证书 | 续期 |
|---|---|---|
| frpc ↔ frps 控制连接 | 私有 CA（EC P-256，3650 天）签发的服务端证书（397 天） | 剩余不足 30 天、控制域名变化或与私钥不匹配时重新签发；每日 03:17 和每次 FRP 变更时检查，证书变化且 frps 正在运行时才重启 frps |
| 浏览器访问的网站 | Let's Encrypt（`http` / `cf`）或自备证书（`custom`） | 每日 03:17 检查，剩余不足 30 天时续期；证书更新后重写配置并重启 `onebox-frp-web`。HTTP-01 需保持 80 可达，网站服务停止时本次跳过 |

两类证书由同一条计划任务 `onebox frps renew --cron` 处理。手动执行 `onebox frps renew` 时会**强制**续期网站证书（不论是否到期，注意 Let's Encrypt 的频率限制）。网站证书续期失败不影响控制证书，原证书保持不变，命令以错误结束。

自备网站证书不会自动申请：在原路径替换证书文件后，每日检查（或 `onebox frps renew`）会部署新文件并重启网站服务；证书路径变化时执行 `onebox frps configure --tls custom --cert 文件 --key 文件`。泛域名的自备证书需同时覆盖根域和 `*.根域`。

私有 CA 剩余不足 30 天时，`renew`、`configure`、`update` 和 `rotate-token` 都会报错停止：

```text
FRP CA 无效或即将过期；需人工轮换并更新所有客户端（onebox frps rotate-ca）
```

`onebox doctor` 也会把它报告为失败项。此时执行 `onebox frps rotate-ca`：生成新的私有 CA 和控制证书（token 不变）并重新部署 FRP，然后重新导出并分发所有客户端。v2 没有这个命令；它只在命令行提供，不在 FRP 菜单中。

## 管理命令

```bash
onebox frps                         # 管理菜单（无终端时显示状态）
onebox frps info                    # 配置摘要与服务状态（别名 status；不显示 token）
onebox frps configure --port 7001   # 在当前配置上修改；失败自动恢复原配置和服务
onebox frps start | stop | restart  # stop 保留防火墙规则与开机自启
onebox frps log                     # frps 与网站服务最近 80 行日志（别名 logs）
onebox frps update                  # 更新到官方最新稳定版
onebox frps update 0.71.0           # 指定版本（不低于 0.71.0）
onebox frps renew                   # 检查控制证书并续期网站证书
onebox frps rotate-token            # 更换 token，随后重新导出客户端
onebox frps rotate-ca               # 更换私有 CA，随后重新导出客户端
onebox frps uninstall               # 单独卸载 FRP
onebox frps --help
```

`configure`、`update`、`rotate-token`、`rotate-ca` 先显示摘要再请求确认，`uninstall` 直接请求确认（都默认否，`-y` 自动确认）；部署期间已有连接会短暂中断。`update` 到正在运行的版本时只提示“无需更新”，不做任何修改。`plan`、`install --dry-run`、`info`、`client` 和 `log` 不修改系统，不要求 root；但已安装时它们要读取仅 root 可读的状态文件，实际仍需以 root 运行。

`plan` / `install` / `configure` 的参数：

| 参数 | 含义 / 默认值 |
|---|---|
| `--mode web\|tcp` | 网站模式 / TCP、UDP 转发模式，默认 `web` |
| `--domain 域名` | 控制域名，必填 |
| `--web-domain 域名` / `--subdomain-host 根域` | 网站模式的单应用域名或泛域名根，二选一 |
| `--port 7000` | 控制连接端口 |
| `--http-port 7080` | 网站模式的内部 HTTP 端口（仅本机） |
| `--https-port 443` | 网站模式的公网 HTTPS 端口 |
| `--redirect-port 80` | HTTP 跳转端口，`0` 关闭；HTTP-01 时必须为 `80` |
| `--allow-ports 20000-20100` | TCP 模式的转发范围（最多 1000 个端口） |
| `--tls http\|cf\|custom` | 网站证书方式，默认 `http`；不影响控制连接的私有 CA |
| `--cert 文件 --key 文件` | 自备网站证书完整链与未加密私钥（相对路径按当前目录解析） |
| `--version 0.71.0\|latest` | frp 版本，最低 `0.71.0`；新安装默认 `0.71.0`，已安装时保持当前版本 |
| `--dry-run` | 只预览，不联网、不修改 |

## 事务、恢复与计划任务

- 安装、配置、更新、token / CA 轮换、续期和卸载都在事务中执行：失败或被 Ctrl+C 中断时恢复原文件、服务、防火墙规则和计划任务。版本未变时不会重新下载 frps。
- 断电或进程被杀留下的未完成事务（`/etc/.onebox-frp-journal`）会在下一个 FRP 管理命令开始时自动回滚，也可以执行 `onebox recover`。在此之前 `onebox frps info` 会提示，开机时 `onebox-frps` 也会拒绝启动：`FRP 存在未完成事务，请先执行 onebox recover`。
- 同一时间只允许一个 FRP 管理操作（`另一个 FRP 管理操作正在进行`）。如果在确认期间另一个操作改了 FRP 配置（例如轮换了 token），本次修改会被拒绝，需重新执行。
- 防火墙只清理 FRP 自己记录的规则；开机时 `onebox-frps` 启动前会先恢复这些规则。
- 计划任务（每次 FRP 变更和续期时重写）：

  ```text
  17 3 * * * PATH=… env ONEBOX_…='…' '/usr/local/bin/onebox' frps renew --cron >>'/var/log/onebox-frp/renew.log' 2>&1 # onebox:frp-renew
  ```

  没有 init 系统时还会为 `onebox-frps`（网站模式另加 `onebox-frp-web`）各写一行 `@reboot … service 服务名 start`（标记 `# onebox:boot:服务名`）。v2 的 `# onebox-frps-renew` 与 `# onebox-frps-boot` 行在升级后第一次 FRP 变更或夜间续期时被替换；systemd / OpenRC 下不再需要 `@reboot` 行（服务已设为开机自启）。

## 卸载与文件位置

`onebox frps uninstall` 停止并删除 `onebox-frps`、`onebox-frp-web` 服务，清除 FRP 的防火墙规则和计划任务，删除 `/etc/onebox-frp`（状态、私有 CA、证书、Cloudflare 凭据）、`/opt/onebox-frp`、`/var/lib/onebox-frp`、`/var/log/onebox-frp` 和 `/run/onebox-frp`。代理节点、自建网站、nginx 软件包和 `onebox` 程序保留；已导出的客户端配置随之失效。

`onebox uninstall`（卸载代理节点）保留 FRP；节点快照 `onebox backup` 不包含 FRP。`onebox doctor` 会检查 FRP 的事务、程序版本、服务、私有 CA、控制证书、网站证书和续期任务。

| 内容 | 位置 |
|---|---|
| 状态、`frps.toml`、私有 CA 与控制证书、网站证书 | `/etc/onebox-frp/`（`web-tls/` 为网站证书） |
| frps 程序 | `/opt/onebox-frp/frps` |
| 网站验证目录与 nginx 临时文件 | `/var/lib/onebox-frp/` |
| 日志（续期、开机；无 systemd 时也含服务日志） | `/var/log/onebox-frp/` |
| 服务 | `onebox-frps`、`onebox-frp-web`（仅网站模式） |
