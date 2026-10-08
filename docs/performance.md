# 性能调优与链路测试

菜单 **7) 性能与诊断** 汇集了下面的功能。调优在服务器上执行；链路测试应在实际使用代理的 Linux 客户端上执行，才能反映客户端到 VPS 的真实路径。

## Hysteria2 与资源调优

```bash
onebox tune status                              # 当前设置
onebox tune hy2 auto                            # 预览：BBR 自动估计带宽
onebox tune hy2 conservative --apply            # 保守 BBR
onebox tune hy2 measured --up 20 --down 100 --apply
onebox tune resource low-memory --apply
onebox tune resource throughput --apply
onebox tune resource balanced --apply           # 撤销接收窗口覆盖，保留拥塞选择
onebox tune reset --apply                       # 恢复全部默认
```

不加 `--apply` 只预览，不需要 root；加 `--apply` 后按普通配置变更执行（内核校验，失败自动回滚）。应用后需重新导入客户端配置或刷新订阅。

| 选项 | 实际改变 | 适用范围 |
|---|---|---|
| `hy2 auto` | 服务端要求客户端使用 BBR，不指定固定带宽 | sing-box 承载的 Hysteria2 |
| `hy2 conservative` | 同上，并使用保守 BBR 档位 | sing-box 服务端/客户端 ≥ 1.14；mihomo ≥ 1.19.32 |
| `hy2 measured` | 指定上传 / 下载带宽，使用 Hysteria 带宽控制 | sing-box 服务端；sing-box / mihomo 客户端 |
| `resource balanced` | 不覆盖内核的接收窗口与并发默认值 | 默认 |
| `resource low-memory` | 流 / 连接接收窗口 2 / 5 MiB，服务端并发流上限 64 | sing-box Hysteria2 ≥ 1.14 |
| `resource throughput` | 流 / 连接接收窗口 16 / 40 MiB，服务端并发流上限 1024 | 同上；高延迟高带宽链路需实测 |

- `--up` / `--down` 以**客户端视角**填写，单位 Mbps，必须是 1–10000 的整数；按实际可用带宽并留余量。切换到其他档位时会清除之前的带宽值。
- 这些调优不作用于 TUIC；Xray 承载的 Hysteria2 不支持调优，会直接报错并提示改用 sing-box 承载。
- 分享链接和 Xray 客户端不携带调优字段，需要 sing-box / mihomo 完整配置。
- 系统 TCP BBR、UDP 缓冲区和 QUIC 拥塞控制是不同层面的设置；这里不修改 sysctl（TCP BBR 见 [bbr.md](bbr.md)）。
- 需要保留调优前的状态时，先执行 `onebox backup before-tuning`。

## 链路测试工具

`probe`、`bench`、`failover`、`reality-check` 在客户端运行时不需要 root，也不安装服务。客户端需要适配其架构的 `onebox` 程序、`curl`、`openssl`，以及所测协议对应的 `sing-box` / `xray`（`--singbox`、`--xray` 指定路径，否则从 PATH 查找）。

### 导出探测配置

```bash
# 服务器：导出到一个新文件（0600；含客户端凭据，不含服务端私钥）
onebox probe export /root/probe.json
```

服务器的 `/etc/onebox/client/probe.json` 也是同样的内容。私密复制到客户端后：

```bash
./onebox probe list probe.json                              # 查看入口 ID
./onebox probe merge combined.json server-a.json server-b.json   # 合并多台服务器（入口 ID 加前缀 n1-、n2-）
```

### 测速

```bash
./onebox bench probe.json --output bench-before.json
./onebox bench probe.json --entries vless-reality,hysteria2 \
  --download-url https://your-test.example/4MiB.bin \
  --upload-url https://your-test.example/upload --bytes 4194304 \
  --samples 5 --output bench-after.json
```

- 每个入口启动一个临时客户端内核，所有请求都经过该入口，没有直连兜底。
- 默认只请求 `https://www.gstatic.com/generate_204`；`--url` 可换成返回 2xx 的稳定端点。下载 / 上传只在显式给出 URL 时执行，上传端点应由你管理或获得授权。
- 报告包含建连耗时、TTFB 中位数与 P95、请求失败率、吞吐，以及本机客户端内核的 CPU 与内存。**请求失败率不等于丢包率**；吞吐包含建连开销。报告不含凭据或完整 URL；`--output` 不覆盖已有文件。

### 多入口回退

```bash
./onebox failover probe.json          # 默认：首个 TCP 入口为主，首个 UDP 入口为备
./onebox failover combined.json --entries n1-vless-reality,n2-hysteria2 \
  --port 2080 --interval 15 --failures 3 --recoveries 3 --cooldown 60
```

应用程序连接 `socks5h://127.0.0.1:2080`。`--entries` 从左到右为优先级（2–8 个）；连续失败达到阈值才切换，优先入口连续恢复且冷却期已过才切回；全部失败时拒绝新连接，不直连。只支持 SOCKS5 CONNECT（TCP），不提供 UDP ASSOCIATE、HTTP 代理或 TUN；只切换新连接。Ctrl+C 结束并清理临时内核。同一 IP 的多协议无法应对整个 IP 不可达，IP 冗余需要合并不同服务器的配置。

### REALITY 一致性检查

```bash
onebox reality-check                          # 服务器：本机回环检查
./onebox reality-check probe.json             # 客户端：真实路径检查
./onebox reality-check probe.json --entries vless-reality --output reality-report.json
```

检查普通 TLS 访问的证书与信任链、TLS 1.3、HTTP/2，并与参考目标比较证书、ALPN、HTTP 状态和跳转；分别用正确凭据和错误 short ID 启动真实客户端，确认前者能代理、后者被拒绝。动态页面或负载均衡证书可能产生差异，需人工核对；检查结果不能证明不可识别，也不证明公网可达。`--ca` 可指定自有测试 CA。

### 退出码

| 退出码 | 含义 |
|---|---|
| 0 | 全部通过（`failover` 被 Ctrl+C 正常结束也是 0）<!-- TODO: verify failover exit code on Ctrl+C --> |
| 1 | 有失败项，详见 JSON 报告 |
| 2 | `reality-check` 只有警告 |
| 130 | 测试被取消 |
