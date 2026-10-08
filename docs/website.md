# 自有域名网站

用自己的域名作为 REALITY 握手目标：程序建立一个可直接访问的主页，为该域名申请 Let's Encrypt 证书并自动续期。普通浏览器看到的是这个网站，合法的 REALITY 客户端则由代理内核处理。适用于 VLESS-Reality-Vision、XHTTP、gRPC-Reality 和 AnyTLS-REALITY。

## 准备

- 域名的 A / AAAA 记录**直接**解析到本机公网地址；使用 Cloudflare 等服务时关闭该记录的 CDN 代理。配置了 AAAA 时，对应 IPv6 必须可达。
- 云安全组放行 **TCP 80**（网站访问、证书申请与续期，需持续可达）和实际使用的 **REALITY TCP 端口**；开启 443 入口时还需放行 **TCP 443**。
- TCP 80 不能被其他程序占用。网站使用独立的 nginx 实例（服务名 `onebox-site`），不接管已有的 nginx 网站；端口冲突会明确报错。
- 开启 443 入口时，TCP 443 不能被其他程序或非 REALITY 协议占用（UDP 443 不受影响）。

## 启用

```bash
# 新安装：预设 + 自有域名网站
onebox install --preset 1 --reality-site www.example.com --site-title '我的手记' -y

# 已安装：把 REALITY 目标切换为自己的域名（UUID 与密钥不变）
onebox sni --reality-site www.example.com --site-title '我的手记'

# 添加 REALITY 协议时一并启用
onebox add vless-reality --reality-site www.example.com

# 已有 REALITY 协议：直接启用网站，可选证书方式 http（默认）/ cf / custom
onebox site enable www.example.com --tls cf
```

交互方式：安装向导第 2 步或 `onebox sni` 中选择“自有域名一键建站”，输入域名、标题，并选择是否开启 HTTPS 443 入口（新建时默认开启）。`--reality-site` 不能与 `--sni`、`--reality-dest` 同时使用。切换后客户端需要更新 SNI（重新导入配置或刷新订阅）。

## 流量如何处理

| 流量 | 处理 |
|---|---|
| 浏览器访问 `http://域名/` | nginx 应答证书验证请求，其余跳转到 HTTPS |
| 浏览器访问 `https://域名/`（443 入口） | REALITY 已占用 TCP 443 时复用其回落；否则 nginx 监听 443 并反代到内部网站 |
| 浏览器访问 REALITY 端口 | REALITY 把普通 TLS 请求转给本机网站 |
| 合法 REALITY 客户端 | sing-box / Xray 处理代理流量 |
| 网站内部 HTTPS 端口（默认 10443） | 只监听 `127.0.0.1`，无需对公网开放 |

开启 443 入口时网站地址为 `https://www.example.com/`；关闭后使用 REALITY 端口，例如 `https://www.example.com:8443/`。网站启用 TLS 1.3 与 HTTP/2。

```bash
onebox site                 # 等同 site info：地址、文件位置与证书状态
onebox site https on        # 开启 / 关闭（off）标准 HTTPS 443 入口
onebox site renew           # 立即强制续期网站证书
onebox site disable         # 关闭网站，REALITY 目标恢复为 www.microsoft.com
```

## 内容

默认主页是 `/var/lib/onebox-site/index.html`，可直接编辑；`onebox regen` 和配置变更不会覆盖修改过的主页。

```bash
onebox site preview profile --title '我的主页' --theme ocean   # 只生成预览文件，线上不变
onebox site template profile --title '我的主页' --description '作品与日常记录' --theme ocean
onebox site title '新的标题'
onebox site import /root/my-static-site
onebox site restore latest
```

| 项目 | 可选值 |
|---|---|
| 模板 `template` | `minimal`（默认）、`profile`、`docs` |
| 配色 `--theme` | `forest`（默认）、`ocean`、`slate` |

- **预览**：在网站管理目录生成 HTML 文件并打印路径，下载查看即可。
- **修改标题**：只适用于模板生成的页面；导入或手工修改过的页面会被拒绝，请编辑源文件后重新导入。
- **导入**：目录内必须有 `index.html`；只复制文件、不执行；拒绝符号链接、特殊文件、系统目录和递归导入；内容上限 256 MiB。
- **备份与恢复**：每次发布前完整备份原网站（保留最近 10 份），发布失败自动恢复；`site restore latest` 或 `site restore 备份ID` 手动恢复。证书验证目录始终保留。

## 证书

网站证书独立于代理证书，必须是公有可信证书（不能自签）：

| 方式 | 说明 |
|---|---|
| `http`（默认） | HTTP-01，经 TCP 80 验证；续期需要 80 持续可达 |
| `cf` | Cloudflare DNS 验证，需要 `CF_Token` |
| `custom` | 自备证书：`--cert` 完整链、`--key` 私钥；更新源文件后执行 `onebox site renew` |

其他代理协议使用 HTTP-01 证书时，会复用网站在 80 端口上的验证目录，不会争用端口。

## 关闭与卸载

- 切换回外部 REALITY 目标、执行 `site disable`，或删除最后一个 REALITY 协议时，程序停止托管网站及其续期，**网页内容保留**。
- 网站设置（标题、模板、证书方式等）不会保留：之后重新启用时从默认值开始，除非在命令中指定。<!-- TODO: verify wording against final site/plan behavior -->
- 订阅正在复用网站时，需先 `onebox subscription disable` 或切换订阅模式。
- 文件位置：网页 `/var/lib/onebox-site/`，管理目录与证书 `/etc/onebox/site/`，内容备份 `/etc/onebox/site/content-backups/`。
