# FRP 服务端

`onebox frps` 管理一个独立的 [fatedier/frp](https://github.com/fatedier/frp) 服务端，用于把内网机器的网站或端口发布到这台 VPS。它与代理节点分开保存状态、证书、防火墙规则和服务，可以单独安装和卸载。默认安装 frp **0.71.0**，下载时校验官方 Release 的 SHA-256、大小与版本。

## 两种模式

| 模式 | 公网入口 | 内部连接 |
|---|---|---|
| `web`（默认） | 浏览器通过应用域名的 HTTPS 443 访问内网网站；支持单域名或一级泛域名 | 独立 nginx 终止 HTTPS，保留 Host 反代到 `127.0.0.1:7080` 的 frps HTTP 入口；客户端用 `type = "http"` |
| `tcp` | 控制域名 + 指定的公网端口，转发内网 TCP / UDP 服务 | 只开放配置的转发范围（默认 `20000-20100`）；不使用 nginx |

两种模式都默认用 TCP 7000 建立 frpc → frps 控制连接：强制 TLS（私有 CA 签发的服务端证书）、随机 token，并认证心跳和工作连接。不启用 Dashboard。

## 准备 DNS 与端口

先在 DNS 服务商处手动添加记录（程序只检查，不会创建或修改）：

| 记录示例 | 用途 | 指向 |
|---|---|---|
| `frp.example.com` | 控制域名，两种模式都需要 | 本机公网 A（有 IPv6 时同时配置正确的 AAAA） |
| `app.example.com` | 网站模式，单应用域名 | 本机公网 A / AAAA |
| `*.apps.example.com` | 网站模式，泛域名（如 `home.apps.example.com`） | 本机公网 A / AAAA |

- 所有 A / AAAA 都必须指向本机；残留旧 IP、错误 AAAA 或 CDN 代理地址都会导致预检失败。Cloudflare 记录请设为**仅 DNS**。
- 云安全组放行控制端口，以及网站模式的 HTTPS（和 HTTP 跳转）端口，或 TCP 模式的转发范围（TCP 与 UDP）。
- 安装会检查代理节点、网站、Hysteria2 跳跃范围和其他进程占用的端口，冲突时停止，不接管已有服务。80 / 443 已被占用时，可改用 `--https-port 8443 --tls cf --redirect-port 0`，访问地址为 `https://app.example.com:8443/`。HTTP-01 必须使用并持续开放 TCP 80。

## 安装

不带参数运行 `onebox frps install` 进入向导：依次选择用途、域名、端口和网站证书（TCP 模式跳过证书），回车保留默认值，`b` 返回上一步，`q` 或 Ctrl+D 取消；最后显示部署摘要并确认。<!-- TODO: verify final wizard steps/keys -->

带参数时直接部署（`-y` 跳过确认）。先用 `plan` 或 `--dry-run` 预览：

```bash
# 只读预览：网站模式，单应用域名
onebox frps plan --mode web --domain frp.example.com --web-domain app.example.com

# 网站模式：HTTPS 443，HTTP 80 跳转并用于证书验证
onebox frps install --mode web --domain frp.example.com --web-domain app.example.com --tls http

# 避开已占用的 80 / 443：Cloudflare DNS 证书 + 8443
CF_Token='DNS API Token' onebox frps install --mode web \
  --domain frp.example.com --web-domain app.example.com \
  --tls cf --https-port 8443 --redirect-port 0

# 泛域名：需要 Cloudflare DNS 或自备泛域证书（HTTP-01 不支持）
CF_Token='DNS API Token' onebox frps install --mode web \
  --domain frp.example.com --subdomain-host apps.example.com --tls cf

# TCP / UDP 转发模式
onebox frps install --mode tcp --domain frp.example.com --allow-ports 45000-45100
```

整个转发范围会为 FRP 预留并按 TCP / UDP 放行；之后配置代理节点时会自动避开。网站模式不预留转发范围。

## 导出客户端配置

```bash
onebox frps client                                                       # 交互导出
onebox frps client /root/frpc-home --type http --local-port 8080         # 网站：内网 127.0.0.1:8080
onebox frps client /root/frpc-home --type http --local-port 8080 --subdomain home   # 泛域名：home.apps.example.com
onebox frps client /root/frpc-ssh --type tcp --local-port 22 --remote-port 45001    # 公网 45001 → 内网 22
onebox frps client /root/frpc-udp --type udp --local-port 27015 --remote-port 45002
```

导出目录必须尚不存在，权限 700，文件 600，包含 `frpc.toml`、公开的 `ca.pem` 和 `README.txt`；含 token，**不含 CA 私钥、服务端私钥或网站私钥**。`--remote-port` 必须在转发范围内。在内网机器安装与服务端相同版本的官方 frpc，私密复制整个目录，进入目录后运行：

```bash
frpc verify -c frpc.toml
frpc -c frpc.toml
```

必须保留 `transport.tls.trustedCaFile = "./ca.pem"` 和服务器名校验；移除 CA 文件会失去服务端身份验证。更改控制域名或执行 `rotate-token` 后，需要重新导出并更新所有客户端。

## 证书

| 用途 | 证书 | 续期 |
|---|---|---|
| frpc ↔ frps 控制连接 | 私有 CA（约 10 年）签发的服务端证书（397 天） | 每日 03:17 检查，变化时才重启 frps |
| 浏览器访问的网站 | Let's Encrypt（`http` / `cf`）或自备证书（`custom`） | 每日检查，更新后重载 nginx；HTTP-01 需保持 80 可达 |

自备网站证书不自动续期：更新源文件后执行 `onebox frps configure --tls custom --cert 文件 --key 文件`。泛域名的自备证书需同时覆盖根域和 `*.根域`。私有 CA 临近到期时会明确报错，需要人工轮换 CA 并重新分发客户端。

## 管理命令

```bash
onebox frps                      # 管理菜单（非交互时显示状态）
onebox frps info                 # 域名、端口、配置与证书位置（status 相同）
onebox frps configure --port 7001   # 修改配置；失败自动恢复原配置和服务
onebox frps start | stop | restart
onebox frps log
onebox frps update               # 更新到官方最新稳定版
onebox frps update 0.71.0        # 指定版本（最低 0.71.0）
onebox frps renew                # 检查控制证书并续期网站证书
onebox frps rotate-token         # 更换 token，随后重新导出客户端
onebox frps uninstall            # 单独卸载 FRP
onebox frps --help
```

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
| `--tls http\|cf\|custom` | 网站证书方式；不影响控制连接的私有 CA |
| `--cert 文件 --key 文件` | 自备网站证书完整链与未加密私钥 |
| `--version 0.71.0\|latest` | frp 版本，最低 `0.71.0` |
| `--dry-run` | 只预览，不联网、不修改 |

## 说明

- 配置、更新和 token 轮换都在事务中执行：失败时恢复原文件、服务与防火墙规则。版本未变时不会重新下载 frps。
- 防火墙只清理 FRP 自己记录的规则。
- `onebox uninstall`（卸载代理节点）保留 FRP；删除 FRP 请用 `onebox frps uninstall`。节点快照 `onebox backup` 不包含 FRP。
- 文件位置：状态与证书 `/etc/onebox-frp/`，程序 `/opt/onebox-frp/frps`，网站验证目录与日志 `/var/lib/onebox-frp/`、`/var/log/onebox-frp/`；服务 `onebox-frps`、`onebox-frp-web`。
