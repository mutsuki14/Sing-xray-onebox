# 自有域名网站

用自己的域名作为 REALITY 握手目标：程序建立一个可直接访问的主页，为该域名申请公有可信证书（默认 Let's Encrypt）并自动续期。普通浏览器看到的是这个网站，合法的 REALITY 客户端则由代理内核处理。适用于 VLESS-Reality-Vision、XHTTP、gRPC-Reality 和 AnyTLS-REALITY，至少需要启用其中一种。

## 准备

- 域名的 A / AAAA 记录**直接**解析到本机公网地址；使用 Cloudflare 等服务时关闭该记录的 CDN 代理。配置了 AAAA 时，对应 IPv6 必须可达。
- 云安全组放行 **TCP 80**（网站的 HTTP 跳转与证书验证；使用 HTTP-01 时续期也需要它持续可达）和实际使用的 **REALITY TCP 端口**；开启 443 入口时还需放行 **TCP 443**。
- TCP 80 不能被其他程序占用。网站使用独立的 nginx 实例（服务名 `onebox-site`；缺少 nginx 时自动安装），不接管已有的 nginx 网站；端口冲突会明确报错。系统自带的 nginx 服务若只运行发行版默认欢迎页（配置未改动，网页目录中也只有该欢迎页），会被停止并禁用，以免占用 80 / 443。
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
onebox site enable www.example.com --site-https off   # 不开放 HTTPS 443 入口
```

交互方式：安装向导第 2 步或 `onebox sni` 中选择“自有域名一键建站”，输入域名和标题，选择是否开启 HTTPS 443 入口（默认开启）以及网站证书方式。`onebox sni` 的目标菜单默认“保持当前目标”（直接回车不改变 REALITY 目标，例如只更换 ShadowTLS 握手域名时）；已有网站时重新选择建站，域名、标题、443 入口与证书方式都默认沿用当前设置，修改标题会重新发布自动生成的主页（导入或手动修改过的主页会被拒绝，与 `onebox site title` 相同）。`onebox sni --reality-site` 与 `add … --reality-site` 对已有网站沿用原证书方式和 HTTPS 443 入口设置（可用 `--site-https on|off` 改变入口）；新建网站（包括 `install --reality-site`）的证书为 HTTP-01，入口默认开启，可加 `--site-https off` 保持关闭。需要其他证书方式时用 `onebox site enable 域名 --tls cf|custom`。`onebox site enable` 默认开启 HTTPS 443 入口，加 `--site-https off` 则保持关闭（443 不会被短暂开放）。`--reality-site` 不能与 `--sni`、`--reality-dest` 同时使用。切换后客户端需要更新 SNI（重新导入配置或刷新订阅）。

## 流量如何处理

| 流量 | 处理 |
|---|---|
| 浏览器访问 `http://域名/` | nginx 应答证书验证请求，其余跳转到 HTTPS |
| 浏览器访问 `https://域名/`（443 入口） | REALITY 已占用 TCP 443 时由 REALITY 转给网站；否则 nginx 监听 443 并反代到内部网站 |
| 浏览器访问 REALITY 端口 | REALITY 把普通 TLS 请求转给本机网站 |
| 合法 REALITY 客户端 | sing-box / Xray 处理代理流量 |
| 网站内部 HTTPS 端口（默认 10443） | 只监听 `127.0.0.1`，无需对公网开放 |

开启 443 入口时网站地址为 `https://www.example.com/`；关闭后使用 REALITY 端口（有多个时取最小的），例如 `https://www.example.com:8443/`。网站内部入口只接受 TLS 1.3（与 REALITY 目标要求一致），并启用 HTTP/2。

```bash
onebox site                 # 等同 site info：地址、服务状态、内容目录、模板与证书状态
onebox site https on        # 开启 / 关闭（off）标准 HTTPS 443 入口
onebox site renew           # 立即续期网站证书（手动执行时强制续期）
onebox site disable         # 关闭网站，REALITY 目标恢复为 www.microsoft.com
```

## 内容

默认主页是 `/var/lib/onebox-site/index.html`，可直接编辑；`onebox regen` 和其他配置变更不会覆盖已有的主页，只有下面的发布类命令会替换它。

```bash
onebox site preview profile --title '我的主页' --theme ocean   # 只生成预览文件，线上不变
onebox site template profile --title '我的主页' --description '作品与日常记录' --theme ocean
onebox site theme slate
onebox site title '新的标题'
onebox site description '新的描述'
onebox site import /root/my-static-site
onebox site restore latest
```

| 项目 | 可选值 |
|---|---|
| 模板 `template` | `minimal`（默认）、`profile`、`docs` |
| 配色 `--theme` / `theme` | `forest`（默认）、`ocean`、`slate` |

- **预览**：生成 `/etc/onebox/site/preview.html` 并打印路径，下载查看即可；未启用网站时也可预览。
- **更换模板**：`site template` 按模板重新生成主页并发布（未指定模板时为 `minimal`），会替换手工修改或导入的内容（原内容先备份）。
- **修改配色、标题、描述**：只适用于模板生成的页面；导入或手工修改过的页面会被拒绝（`网站已被手动修改或导入，请编辑原网页后重新导入`）。
- **导入**：目录内必须有 `index.html`；只复制文件、不执行；拒绝符号链接、特殊文件、系统目录、Onebox 配置目录和递归导入；内容上限 256 MiB、100000 个文件。
- **备份与恢复**：每次发布前完整备份原网站（保留最近 10 份），发布失败自动恢复；`site restore`（默认 latest）或 `site restore 备份ID` 手动恢复；备份 ID 是 `/etc/onebox/site/content-backups/` 下的目录名，菜单 **5) 自有域名网站 → 恢复内容** 会按时间列出可选备份（`site info` 只显示备份数量）。证书验证目录始终保留。

## 证书

网站证书独立于代理证书，必须是公有可信证书（不能自签）：

| 方式 | 说明 |
|---|---|
| `http`（默认） | Let's Encrypt HTTP-01，经 TCP 80 验证；续期需要 80 持续可达 |
| `cf` | Let's Encrypt Cloudflare DNS 验证，需要 `CF_Token` |
| `custom` | 自备证书：`--cert` 完整链、`--key` 私钥；更新源文件后由每日计划任务自动重新部署，或立即执行 `onebox site renew` |

其他代理协议使用 HTTP-01 证书时，由网站在 80 端口上的 nginx 应答验证，不会争用端口。

每日计划任务（`onebox renew --cron`，4:17）在 Let's Encrypt 证书 30 天内到期时自动续期。网站证书续期（也包括 `site` 模式订阅所用的证书）不执行完整配置事务，只重启网站服务 `onebox-site`，代理内核不受影响。v2 的续期会执行完整配置事务并重启代理内核。

## 关闭与卸载

- 切换回外部 REALITY 目标、执行 `site disable`，或删除最后一个 REALITY 协议时，程序停止托管网站及其续期，**网页内容和内容备份保留**。
- 网站设置（标题、模板、配色、描述、证书方式）不会保留：之后重新启用时从默认值开始，除非在命令中指定。v2 会保留这些设置。重新启用时继续使用保留的 `index.html`，不会按新标题或默认模板重新生成：`--site-title` 只记入网站设置，已有主页不变（只有尚无主页时才按它自动生成）。需要按当前设置重新生成主页时执行 `onebox site template [模板] --title …`（未改动过的生成页面也可用 `onebox site title …`）。
- 订阅正在复用网站时，需先 `onebox subscription disable` 或切换订阅模式，才能关闭网站或更换网站域名。
- `onebox uninstall` 同样保留网页内容和内容备份。
- 文件位置：网页 `/var/lib/onebox-site/`，管理目录与证书 `/etc/onebox/site/`，内容备份 `/etc/onebox/site/content-backups/`。
