# 远程订阅

`onebox client sub` 只输出本地 Base64 内容；`onebox subscription` 把客户端配置发布为可随时刷新的 URL，并按设备授权。节点配置每次成功变更后自动重新发布；变更失败时继续提供上一版。

## 三种入口

| 模式 | 地址形如 | 需要 | 说明 |
|---|---|---|---|
| `ip` | `http://203.0.113.10:8448/sub/令牌/格式` | 一个空闲 TCP 端口（默认 8448） | 无需域名和证书；**HTTP 明文** |
| `site` | `https://www.example.com/sub/令牌/格式` | 已启用[自有域名网站](website.md) | 复用网站的域名、证书和公网端口，不增加端口 |
| `standalone` | `https://sub.example.com:8448/sub/令牌/格式` | 解析到本机的独立域名 + 证书 | 独立 HTTPS 入口，默认端口 8448 |

首次启用时，已有自建网站默认 `site`，否则默认 `ip`。可在菜单 **4) 远程订阅** 中选择，或用命令指定。

> **安全提示**：`ip` 模式使用 HTTP 明文，链路上的第三方可以看到订阅令牌和其中的节点凭据。令牌只做访问授权，不能为 HTTP 加密。需要加密传输时请用 `site` 或 `standalone`。

## 启用

```bash
# IP 直连（IPv4）；IPv6 写法 --address 2001:db8::10，不加方括号
onebox subscription enable --mode ip --address 203.0.113.10 --port 8448

# 复用自有域名网站
onebox subscription enable --mode site

# 独立域名 HTTPS：Cloudflare DNS 证书（CF_Token 可用环境变量或隐藏输入提供）
onebox subscription enable --mode standalone --domain sub.example.com --port 8448 --tls cf

# 独立域名 HTTPS：HTTP-01 证书（TCP 80 必须空闲并持续可从公网访问）
onebox subscription enable --mode standalone --domain sub.example.com --port 8448 --tls http

# 独立域名 HTTPS：自备公有可信证书
onebox subscription enable --mode standalone --domain sub.example.com \
  --tls custom --cert /root/fullchain.pem --key /root/privkey.pem
```

- 省略 `--mode` 时：给了 `--address` 为 `ip`，给了 `--domain` 为 `standalone`，否则有网站时为 `site`，再否则为 `ip`。
- `ip` 模式的地址默认取节点的连接 IP；必须是 IP 字面量（不含端口、路径）。该端口由程序直接提供（不需要 nginx），并在本机所有地址上监听，便于 NAT 环境使用。<!-- TODO: verify ip-mode bind address -->
- `standalone` 会检查 DNS、证书与端口，不接管已有服务；端口允许时可用 `--port 443`。
- 首次启用会创建设备 `default` 并显示其链接。`ip` 和 `standalone` 需要在云安全组放行所用的 TCP 端口（HTTP-01 另需 80）。
- 订阅不经过 FRP 发布。

## 设备与链接

```bash
onebox subscription info              # 入口、设备 ID 与名称（不显示令牌）
onebox subscription add phone         # 新建设备，显示各格式 URL
onebox subscription reset 设备ID       # 换新令牌，旧链接立即失效
onebox subscription revoke 设备ID      # 撤销设备
onebox subscription publish           # 立即重新生成并发布
onebox subscription renew             # 续期 HTTPS 订阅证书（ip 模式无需）
onebox subscription disable           # 停止全部订阅访问
```

`subscription` 可简写为 `sub`。令牌只在创建或重置时显示一次，服务器只保存其哈希：遗失链接请执行 `reset`，`info` 无法找回。最多 256 个设备。

URL 末段决定返回内容：

| 末段 | 内容 | 用法 |
|---|---|---|
| `base64` | Base64 分享链接 | 支持相应协议的通用客户端订阅 |
| `mihomo` | mihomo 完整配置 | 作为远程配置导入 |
| `provider` | 只含 `proxies` 的 YAML | 在已有 mihomo 配置的 `proxy-providers` 中引用 |
| `singbox` | sing-box 完整配置（TUN） | 远程配置导入；另输出 `sing-box://import-remote-profile?url=…` 一键导入链接 |
| `singbox-notun` | sing-box 完整配置（仅代理端口） | 下载给 sing-box 使用 |
| `xray` | Xray 客户端配置 | 支持完整 Xray 配置的客户端 |

每种格式只含它支持的协议，没有可用节点的格式不发布。AnyTLS-REALITY 只出现在 `singbox` / `singbox-notun`；ShadowTLS 也应使用完整配置。

## 注意事项

- **撤销或重置只阻止后续下载，不会收回已下载的节点密码。** 需要让旧配置失效时，执行 `onebox reset` 轮换节点凭据后重新分发。
- 不要公开链接、二维码或含链接的截图。
- 切换入口模式会保留设备及令牌，`/sub/令牌/格式` 部分不变；客户端需要改 URL 的协议、地址和端口。
- 客户端要求 HTTPS 时请用域名入口；IPv6 地址的订阅在只有 IPv4 的网络中无法访问。
- 恢复节点快照会同时恢复其中的设备列表，之前撤销的设备可能重新出现，恢复后请检查 `onebox subscription info`。
- 订阅正在复用网站时，需先关闭订阅或切换到其他模式，才能关闭网站。
- HTTPS 证书由每日计划任务自动续期，续期只重载订阅入口，不重启代理内核。
