# 性能调优与链路测试

菜单 **7) 性能与诊断** 汇集了下面的功能。调优在服务器上执行；链路测试应在实际使用代理的 Linux 客户端上执行，才能反映客户端到 VPS 的真实路径。

## Hysteria2 与资源调优

```bash
onebox tune status                              # 当前设置（等同不带参数的 onebox tune）
onebox tune hy2 auto                            # 预览：BBR 自动估计带宽
onebox tune hy2 conservative --apply            # 保守 BBR
onebox tune hy2 measured --up 20 --down 100 --apply
onebox tune resource low-memory --apply
onebox tune resource throughput --apply
onebox tune resource balanced --apply           # 撤销接收窗口覆盖，保留拥塞选择
onebox tune reset --apply                       # 恢复默认：不调优 Hysteria2，资源档位 balanced
```

不加 `--apply` 只打印 `调优预览: …`，不修改任何配置；加 `--apply` 后需要 root，按普通配置变更执行（内核校验，失败自动回滚）。应用后需重新导入客户端配置或刷新订阅。

| 选项 | 实际改变 | 适用范围 |
|---|---|---|
| `hy2 auto` | 服务端忽略客户端声明的带宽，由 BBR 自动估计 | sing-box 承载的 Hysteria2 |
| `hy2 conservative` | 同上，并使用保守 BBR 档位 | sing-box 服务端/客户端 ≥ 1.14；mihomo ≥ 1.19.32 |
| `hy2 measured` | 指定上传 / 下载带宽，使用 Hysteria 带宽控制 | sing-box 服务端；sing-box / mihomo 客户端 |
| `resource balanced` | 不覆盖 sing-box 的 QUIC 接收窗口与并发流默认值 | 默认 |
| `resource low-memory` | 流 / 连接接收窗口 2 / 5 MiB，服务端并发流上限 64 | sing-box Hysteria2 ≥ 1.14 |
| `resource throughput` | 流 / 连接接收窗口 16 / 40 MiB，服务端并发流上限 1024 | 同上；高延迟高带宽链路需实测 |

- `--up` / `--down` 以**客户端视角**填写，单位 Mbps，必须是 1–10000 的整数，只能用于 `measured`；按实际可用带宽并留余量。切换到其他档位时会清除之前的带宽值。
- 这些调优不作用于 TUIC；Xray 承载的 Hysteria2 不支持调优，会直接报错并提示改用 sing-box 承载。
- 分享链接和 Xray 客户端不携带调优字段，需要 sing-box / mihomo 完整配置。
- 系统 TCP BBR、UDP 缓冲区和 QUIC 拥塞控制是不同层面的设置；这里不修改 sysctl（TCP BBR 见 [bbr.md](bbr.md)）。
- 需要保留调优前的状态时，先执行 `onebox backup before-tuning`。

## 链路测试工具

`probe list|merge`、`bench`、`failover` 以及带配置文件的 `reality-check` 在客户端运行时不需要 root，也不安装服务；`probe export` 和服务器上不带配置文件的 `reality-check` 需要 root。客户端需要适配其架构的 `onebox` 程序、`curl`（`reality-check` 还需要 `openssl`），以及所测协议对应的 `sing-box` / `xray`：依次查找 `--singbox` / `--xray` 指定的路径、`/opt/onebox/bin`、PATH。

### 导出探测配置

```bash
# 服务器：导出到一个新文件（不可已存在，权限 0600；含客户端凭据，不含服务端私钥）
onebox probe export /root/probe.json
```

服务器的 `/etc/onebox/client/probe.json` 也是同样的内容。私密复制到客户端后：

```bash
./onebox probe list probe.json                                   # 查看入口 ID（入口 ID、传输层、内核）
./onebox probe merge combined.json server-a.json server-b.json   # 合并多台服务器（至少两份，入口 ID 加前缀 n1-、n2-）
```

入口 ID 即协议 ID，如 `vless-reality`、`hysteria2`。

### 测速

```bash
./onebox bench probe.json --output bench-before.json
./onebox bench probe.json --entries vless-reality,hysteria2 \
  --download-url https://your-test.example/4MiB.bin \
  --upload-url https://your-test.example/upload --bytes 4194304 \
  --samples 5 --output bench-after.json
```

- 每个入口启动一个临时客户端内核，所有请求都经过该入口，没有直连兜底。默认测试全部入口，`--entries` 按给出的顺序选择。
- 默认只请求 `https://www.gstatic.com/generate_204`（`--samples` 次，默认 5，范围 1–20）；`--url` 可换成返回 2xx 的稳定端点（不跟随跳转）。下载 / 上传只在显式给出 `--download-url` / `--upload-url` 时执行，传输 `--bytes` 字节（默认 4194304）；上传端点应由你管理或获得授权。`--timeout` 设置连接与请求超时（默认 8 秒）。
- 报告为 JSON，打印到标准输出；`--output` 同时保存到新文件（不覆盖已有文件，权限 0600）。内容包括建连耗时、TTFB 中位数与 P95、请求失败率、吞吐及传输期间的延迟，以及本机客户端内核的 CPU 与内存。**请求失败率不等于丢包率**；吞吐包含建连开销。报告不含凭据。

### 多入口回退

```bash
./onebox failover probe.json          # 默认：首个 TCP 入口为主，首个仅 UDP 的入口为备
./onebox failover combined.json --entries n1-vless-reality,n2-hysteria2 \
  --port 2080 --interval 15 --failures 3 --recoveries 3 --cooldown 60
```

应用程序连接 `socks5h://127.0.0.1:2080`（只监听本机）。`--entries` 从左到右为优先级（2–8 个）；每 `--interval` 秒检测一次各入口，连续失败 `--failures` 次才切换，优先入口连续恢复 `--recoveries` 次且冷却期 `--cooldown` 秒已过才切回；全部失败时拒绝新连接，不直连。只支持 SOCKS5 CONNECT（TCP），不提供 UDP ASSOCIATE、HTTP 代理或 TUN；只切换新连接，既有连接不迁移。运行事件以 JSON 行输出到标准输出，退出的临时内核会自动重启。Ctrl+C 结束并清理临时内核。同一 IP 的多协议无法应对整个 IP 不可达，IP 冗余需要合并不同服务器的配置。

### REALITY 一致性检查

```bash
sudo onebox reality-check                     # 服务器：本机回环检查（读取本机配置，需要 root）
./onebox reality-check probe.json             # 客户端：真实路径检查
./onebox reality-check probe.json --entries vless-reality --output reality-report.json
```

对每个 REALITY 入口：用普通 TLS 访问节点，检查证书与信任链、TLS 1.3、HTTP/2，并与参考站点比较证书、ALPN、HTTP 状态、跳转和首页前 64 KiB；再分别用正确凭据和错误 short ID 启动真实客户端，确认前者能代理、后者被拒绝。未协商 HTTP/2 和页面内容不同只算警告——动态页面或负载均衡证书可能产生差异，需人工核对。检查结果不能证明不可识别，也不证明公网可达。`--ca` 可指定自有测试 CA。

### 退出码

| 退出码 | 含义 |
|---|---|
| 0 | 全部通过；`failover` 被 Ctrl+C（或 TERM）结束也是 0 |
| 1 | `bench` / `reality-check` 有失败项（详见 JSON 报告），`reality-check` 没有 REALITY 入口，`failover` 监听失败，或参数等其他错误 |
| 2 | `reality-check` 只有警告（输出 `[警告] REALITY 检查完成，请核对报告中的警告。`） |
| 130 | `bench` / `reality-check` 被 Ctrl+C 取消 |

在菜单中运行时，这些结果都会回到原菜单，不会结束会话。
