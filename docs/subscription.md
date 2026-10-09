# 远程订阅

`onebox client sub` 只输出本地 Base64 内容；`onebox subscription` 把客户端配置发布为可随时刷新的 URL，并按设备授权。节点配置每次成功变更后自动重新发布；变更失败时继续提供上一版。

## 三种入口

| 模式 | 地址形如 | 需要 | 说明 |
|---|---|---|---|
| `ip` | `http://203.0.113.10:8448/sub/令牌/格式` | 一个空闲 TCP 端口（默认 8448） | 无需域名和证书；**HTTP 明文** |
| `site` | `https://www.example.com/sub/令牌/格式` | 已启用[自有域名网站](website.md) | 复用网站的域名、证书和公网端口（443 入口关闭时为 REALITY 端口），不增加端口 |
| `standalone` | `https://sub.example.com:8448/sub/令牌/格式` | 解析到本机的独立域名 + 公有可信证书 | 独立 HTTPS 入口（专用 nginx 实例 `onebox-subscription-web`），默认端口 8448 |

可在菜单 **4) 远程订阅** 中选择（菜单每次都询问模式及该模式的全部选项，端口默认沿用当前值），或用命令指定。订阅尚未启用时，命令行按给出的选项推断模式：给了 `--address` 为 `ip`，给了 `--domain` 为 `standalone`，否则有网站时为 `site`，再否则为 `ip`。对已启用的订阅再次执行 `enable` 时只修改给出的选项：模式保持不变（更换模式必须写 `--mode`，不写 `--mode` 时给出其他模式的选项会报错），省略的 `--address`、`--domain`、`--tls`（以及自备证书的 `--cert`、`--key` 中省略的一项）和 `--port` 沿用当前值。例如 `onebox subscription enable --port 9443` 只改端口。用 `--mode` 在 `ip` 与 `standalone` 之间切换时端口同样沿用；从 `site` 切换时端口回到 8448。

> **安全提示**：`ip` 模式使用 HTTP 明文，链路上的第三方可以看到订阅令牌和其中的节点凭据。令牌只做访问授权，不能为 HTTP 加密。需要加密传输时请用 `site` 或 `standalone`。

## 启用

```bash
# IP 直连（IPv4）；IPv6 写法 --address 2001:db8::10，不加方括号
onebox subscription enable --mode ip --address 203.0.113.10 --port 8448

# 复用自有域名网站
onebox subscription enable --mode site

# 独立域名 HTTPS：Cloudflare DNS 证书（默认方式；CF_Token 可用环境变量或隐藏输入提供）
onebox subscription enable --mode standalone --domain sub.example.com --port 8448 --tls cf

# 独立域名 HTTPS：HTTP-01 证书（TCP 80 必须空闲并持续可从公网访问）
onebox subscription enable --mode standalone --domain sub.example.com --port 8448 --tls http

# 独立域名 HTTPS：自备公有可信证书
onebox subscription enable --mode standalone --domain sub.example.com \
  --tls custom --cert /root/fullchain.pem --key /root/privkey.pem
```

| 选项 | 说明 |
|---|---|
| `--mode ip\|site\|standalone` | 托管模式。省略时：已启用的订阅保持当前模式；否则给了 `--address` 为 `ip`，给了 `--domain` 为 `standalone`，有网站时为 `site`，再否则为 `ip` |
| `--address IP`（同 `--ip`） | 仅 `ip` 模式：链接中的地址 |
| `--domain 域名` | 仅 `standalone` 模式（首次启用时必填）：订阅域名 |
| `--port 端口` | `ip` / `standalone` 模式的端口，默认 8448（已启用时默认沿用当前端口） |
| `--tls cf\|http\|custom` | 仅 `standalone` 模式：证书方式，默认 `cf`（已启用时默认沿用当前方式）；`custom` 需同时给出 `--cert`、`--key` |
| `--name 名称` | 首个设备的名称，默认 `default` |

- `ip` 模式的地址默认取节点的连接地址（当它是 IP 时），否则取检测到的公网 IPv4、IPv6；必须是 IP 字面量（不含端口、路径）。该端口由 Onebox 自己的订阅服务直接提供（不需要 nginx），在本机所有地址上监听（支持 IPv6 时为双栈 `[::]`，否则 `0.0.0.0`），便于 NAT 环境使用；`--address` 只决定链接中显示的地址。v2 在 ip 模式下另起一个 nginx（`onebox-subscription-web`）转发，v3 不再需要，升级后会自动移除。
- `standalone` 会检查端口占用并申请证书，不接管已有服务；域名需事先解析到本机。端口允许时可用 `--port 443`。已启用自有域名网站时 TCP 80 由网站占用，`standalone` 请用 `cf` 或 `custom` 证书（或直接改用 `site`）。
- `--mode site` 忽略 `--domain`、`--port`、`--tls`、`--cert`、`--key`，并提示已忽略哪些选项。
- 首次启用会创建设备 `default`（或 `--name` 指定的名称）并显示其链接。`ip` 和 `standalone` 需要在云安全组放行所用的 TCP 端口（HTTP-01 另需 80）；本机防火墙由程序放行。
- 订阅不经过 FRP 发布。

## 设备与链接

```bash
onebox subscription info              # 入口、设备 ID、名称与创建时间（不显示令牌）
onebox subscription add phone         # 新建设备，显示令牌与各格式 URL
onebox subscription reset 设备ID       # 换新令牌，旧链接立即失效
onebox subscription revoke 设备ID      # 撤销设备
onebox subscription publish           # 立即重新生成并发布
onebox subscription renew             # 续期 HTTPS 订阅证书（site 模式即续期网站证书；ip 模式无需）
onebox subscription disable           # 停止全部订阅访问（设备保留）
```

- `subscription` 可简写为 `sub`（也接受 `subscribe`）；不带子命令等同 `info`。`info` 也可写作 `status` / `list`，`revoke` 也可写作 `remove`，`publish` 也可写作 `refresh`。
- 令牌只在创建或重置时显示一次，服务器只保存其哈希：遗失链接请执行 `reset`，`info` 无法找回。
- 设备名称为 1–80 字节（一个汉字占 3 字节）且不能重复；最多 256 个设备。
- 新建设备时输出设备 ID、令牌、每种格式的 URL 和 `sing-box 导入:` 一键导入链接；重置时输出新令牌和 URL。`ip` 模式另在标准错误输出明文警告。

URL 末段决定返回内容：

| 末段 | 内容 | 用法 |
|---|---|---|
| `base64` | Base64 分享链接 | 支持相应协议的通用客户端订阅 |
| `mihomo` | mihomo 完整配置 | 作为远程配置导入 |
| `provider` | 只含 `proxies` 的 YAML | 在已有 mihomo 配置的 `proxy-providers` 中引用 |
| `singbox` | sing-box 完整配置（TUN） | 远程配置导入；另输出 `sing-box://import-remote-profile?url=…` 一键导入链接 |
| `singbox-notun` | sing-box 完整配置（仅代理端口） | 下载给 sing-box 使用 |
| `xray` | Xray 客户端配置 | 支持完整 Xray 配置的客户端 |

每种格式只含它支持的协议，没有可用节点的格式不发布（访问返回 404）。AnyTLS-REALITY 只出现在 `singbox` / `singbox-notun`；ShadowTLS 不在 `base64` 中，请使用完整配置。

## 注意事项

- **撤销或重置只阻止后续下载，不会收回已下载的节点密码。** 需要让旧配置失效时，执行 `onebox reset` 轮换节点凭据后重新分发。
- 不要公开链接、二维码或含链接的截图。
- 切换入口模式会保留设备及令牌，`/sub/令牌/格式` 部分不变；客户端需要改 URL 的协议、地址和端口。
- `disable` 保留设备列表，但删除已发布的订阅内容（含凭据）并停止订阅服务；之后再次 `enable`，原有设备的令牌继续有效；入口（地址、端口、协议）与关闭前相同时提示 `订阅已启用；已有设备 URL 保持不变。`，否则提示把已有 URL 的入口改为新地址。
- 重新安装（交互重装或 `install --force`）会清除全部设备；卸载同样删除订阅数据。
- 客户端要求 HTTPS 时请用域名入口；IPv6 地址的订阅在只有 IPv4 的网络中无法访问。
- 恢复节点快照会同时恢复其中的设备列表，之前撤销的设备可能重新出现，恢复后请检查 `onebox subscription info`。
- 订阅正在复用网站时，需先关闭订阅或切换到其他模式，才能关闭网站或更换网站域名。
- HTTPS 证书由每日计划任务处理：Let's Encrypt 证书在 30 天内到期时续期，自备证书在源文件内容变化后重新部署（不会因临近到期而续期，到期前需自行替换源文件）；不执行完整配置事务、不重启代理内核：`standalone` 模式只重启独立订阅入口 `onebox-subscription-web`；`site` 模式使用网站证书，续期时只重启网站 `onebox-site`（见 [website.md](website.md#证书)）。手动执行 `onebox subscription renew` 会强制续期。v2 的订阅证书续期会重启全部代理内核。
