# 客户端导入

## 导出

```bash
onebox info                  # 节点信息、凭据与导出方式
onebox client mihomo         # mihomo / Clash Meta 完整配置（YAML）
onebox client provider       # 只含节点的 mihomo proxy-provider
onebox client singbox        # sing-box 完整配置，TUN 模式
onebox client singbox-notun  # sing-box 完整配置，仅本地代理端口
onebox client xray           # Xray 客户端配置
onebox client links          # 分享链接，每行一个
onebox client sub            # Base64 订阅内容
onebox qr                    # 在终端显示每条分享链接的二维码（同 client qr）
```

- `onebox client` 不带格式时交互选择（只列出当前协议组合支持的格式）；`config` 是 `client` 的别名，格式名也接受 `link`、`base64`、`clash`、`sing-box`、`sing-box-notun`。
- 输出写到标准输出，保存文件：`onebox client mihomo > mihomo.yaml`。提示信息写到标准错误，不会混进文件。
- 每种格式只包含它支持的协议（见 [README 支持矩阵](../README.md#协议与客户端支持)）；当前组合没有可用节点时报错。
- 二维码由程序直接绘制，不需要安装 `qrencode`，每个二维码下方附带对应链接；只有能生成通用链接的协议才有二维码。在终端中二维码固定使用黑底白块的颜色（同 v2），浅色背景的终端也能正常扫描；输出到文件、管道或设置了 `NO_COLOR` 时不带颜色，只适合深色背景显示。
- `mihomo` / `provider` 输出标准 YAML（v2 输出的是 mihomo 也能读取的 JSON 文本），结构不变。
- 需要随时可更新的链接，使用[远程订阅](subscription.md)。

服务器上也保存了一份（目录 0700、文件 0600），每次配置变更后整体替换，不支持的格式不会出现（不要在该目录存放自己的文件）：

| 文件（`/etc/onebox/client/`） | 内容 |
|---|---|
| `links.txt` / `sub.txt` | 分享链接 / Base64 订阅内容 |
| `mihomo.yaml` / `provider.yaml` | mihomo 完整配置 / proxy-provider |
| `sing-box.json` / `sing-box-notun.json` | sing-box TUN 版 / 仅代理端口版 |
| `xray.json` | Xray 客户端配置 |
| `probe.json` | 链路测试用的探测配置，见 [performance.md](performance.md) |

这些文件都包含节点凭据，请私密传输。

## 各客户端的导入方式

| 客户端 | 推荐方式 |
|---|---|
| v2rayN / v2rayNG / NekoBox / Shadowrocket / Karing | 分享链接、二维码，或 Base64 订阅 |
| Clash Verge Rev / Mihomo Party / FlClash / ClashMi / Clash Meta for Android | 导入 `mihomo.yaml`，或远程订阅的 `mihomo` 链接 |
| sing-box 官方客户端（SFA / SFI / SFM）、GUI.for.SingBox | 导入 `sing-box.json`，或远程订阅的 `singbox` 链接（附 `sing-box://import-remote-profile` 一键导入） |
| sing-box 命令行 | `sing-box-notun.json` |
| Xray 命令行 | `xray.json` |
| Hiddify | 建议用 sing-box 配置（其链接解析对 Hysteria2 混淆、AnyTLS 支持不完整） |
| Stash | 部分字段名与 mihomo 不同，建议用分享链接或 Base64 订阅 |

完整配置的本地端口（均只监听 `127.0.0.1`）：

| 配置 | 本地端口 |
|---|---|
| sing-box（两种版本） | 混合代理 2080；TUN 版另有 TUN 入站 |
| sing-box / mihomo 控制面板 | 9090，需要密钥（`onebox info` 中的“控制面板密钥”） |
| mihomo | 混合代理 7890，DNS 1053 |
| Xray | SOCKS 10808，HTTP 10809 |

完整配置会让订阅地址和自有域名网站直连，代理故障时仍能刷新订阅。

## 客户端版本要求

| 客户端 | 版本 |
|---|---|
| sing-box | ≥ 1.12；使用 Hysteria2 调优（保守 BBR、接收窗口）时 ≥ 1.14 |
| mihomo | ≥ 1.19.3；含 VLESS-XHTTP 时 ≥ 1.19.22；Hysteria2 保守 BBR 需 ≥ 1.19.32 |
| Xray | 26.x（与服务端默认 26.3.27 测试） |

## 自签证书

使用自签证书时，完整配置固定证书指纹，不会关闭证书校验：

| 格式 | 信任方式 |
|---|---|
| sing-box | 内嵌服务端证书 |
| mihomo | `fingerprint` |
| Xray | `pinnedPeerCertSha256` |
| 分享链接 | `insecure=1` / `allowInsecure=1`，同时附带 `pcs`、`pinSHA256`、`hpkp` 等指纹参数，兼顾新旧客户端 |

注意：

- 只认 `allowInsecure` 而忽略指纹参数的旧客户端实际上不校验证书；TUIC 链接没有指纹字段。安全性要求高时请用完整配置或正式证书。
- mihomo 通过链接导入 **TUIC + 自签证书** 时无法跳过校验，请改用 `mihomo.yaml`。
- mihomo 链接导入会忽略 Hysteria2 端口跳跃参数 `mport`；完整配置不受影响。

## AnyTLS-REALITY

`anytls` 使用普通 TLS 证书；`anytls-reality` 使用 REALITY 密钥与握手目标，无需域名和证书。两者可同时安装，使用不同端口。

```bash
onebox add anytls-reality           # 已安装：添加协议
onebox client singbox               # 导出 sing-box 配置（或 singbox-notun）

# 新安装，指定外部握手目标
onebox install --protocols anytls-reality --core singbox --sni www.microsoft.com -y

# 添加时使用自有域名网站作为 REALITY 目标
onebox add anytls-reality --reality-site www.example.com --site-https on
```

- 服务端与客户端都需要 sing-box ≥ 1.12，且为带 `with_utls` 的构建（官方发行包已包含）。
- **只包含在 sing-box 完整配置中**（`singbox`、`singbox-notun`，含远程订阅的这两种格式）。mihomo、provider、Xray、分享链接、Base64 和二维码都不包含它：导出 mihomo、provider、Xray、分享链接或 Base64 时会在标准错误提示；`qr` 只显示其他协议的二维码，不另行提示（只有 AnyTLS-REALITY 等不能生成链接的协议时报错 `没有可生成二维码的通用链接，请使用 sing-box 配置`）。
- 不要把普通 `anytls://` 链接用于此协议。其他应用能否使用，取决于其内置 sing-box 版本以及是否支持导入完整配置。

## 常见导入问题

| 现象 | 处理 |
|---|---|
| 导入后部分节点缺失 | 该格式不支持这些协议，换用支持的格式（如 ShadowTLS、AnyTLS-REALITY 用 sing-box 配置） |
| 换了 REALITY 目标、端口或证书后无法连接 | 重新导入配置，或刷新远程订阅 |
| SS-2022 / VMess 握手失败 | 校准时间：SS-2022 误差需在 30 秒内，VMess 在 120 秒内 |
| mihomo 报未知字段 | 升级 mihomo 内核（见版本要求） |
