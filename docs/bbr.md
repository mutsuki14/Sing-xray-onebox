# BBR / BBRv3

`onebox bbr` 管理 TCP 拥塞控制：启用当前内核自带的 BBR，或安装 [byJoey/Actions-bbr-v3](https://github.com/byJoey/Actions-bbr-v3) 构建的 BBRv3 内核。交互安装节点结束时会询问是否启用系统自带 BBR（默认是，使用 `fq` 队列；`--no-bbr` 跳过，无人值守安装不询问）；升级程序、打开菜单和查看状态都不会安装内核。

> TCP BBR 只影响 TCP。Hysteria2 / TUIC 走 QUIC，由代理内核自己做拥塞控制，不受这里的设置影响：sing-box 承载的 Hysteria2 可用 `onebox tune` 调整（见 [performance.md](performance.md)）；TUIC 固定使用 QUIC 的 BBR，没有对应的调优。

## 启用当前内核的 BBR

```bash
onebox bbr status              # 拥塞算法、默认队列、实际网卡队列、模块与已装内核（无需 root）
onebox bbr enable              # BBR + fq（需要 root）
onebox bbr enable fq_codel     # 也支持 fq_pie、cake，取决于内核
```

- 适用于提供 `tcp_bbr` 模块的系统（需要时自动 `modprobe tcp_bbr`）；OpenVZ 不支持，其他容器受宿主机限制。
- 设置写入 `/etc/sysctl.d/99-onebox-bbr.conf`；任一步失败时恢复原来的运行参数和原配置文件（内容与权限）。内核不支持所选队列时会提示改用 `fq` 或 `fq_codel`。
- 其他 sysctl 配置文件（`/etc/sysctl.conf` 及各 `sysctl.d` 目录）设置了相同参数时会给出警告，并指出哪些文件在开机时晚于 Onebox 的文件加载、会覆盖它；Onebox 不修改这些文件。
- 选择队列只修改 `net.core.default_qdisc`，**不会替换正在运行的网卡队列或已有带宽整形规则**；用 `onebox bbr status` 或 `tc qdisc show` 查看实际队列。
- 算法名为 `bbr` 不代表是 v3；状态页分别显示运行内核、已加载的 `tcp_bbr` 模块版本和磁盘上的模块版本，以及已安装的 BBRv3 内核包。

## 安装 BBRv3 内核

```bash
onebox bbr releases                      # 当前 CPU 架构可用的标准版 Release，最新的在前
onebox bbr install                       # 预览最新标准版，不安装（无需 root）
onebox bbr install --dry-run             # 同上：不带 --apply 时默认即为预览
onebox bbr install latest --apply        # 安装，执行前再次确认（需要 root）
onebox bbr install x86_64-7.2.8 --apply  # 指定完整标签，以 releases 的实际输出为准
onebox bbr releases --max
onebox bbr install latest --max          # 预览 Max 实验版；安装同样需要 --apply
```

标签格式为 `架构-版本`（Max 版再加 `-max`），x86_64 以 `x86_64-` 开头，aarch64 以 `arm64-` 开头。不带 `--apply` 时 `bbr install` 只预览，`--dry-run` 与之等价（便于与其他命令保持一致），两者不能同时使用。预览需要联网查询 Release，但不安装任何软件包（缺少 curl 时直接报错）、不修改 sysctl 或引导，也不需要 root。无人值守安装必须同时给出 `--apply -y`。

GitHub API 限流时可设置 `GH_TOKEN`。

### 安装前检查

| 项目 | 要求 |
|---|---|
| 运行环境 | 独立内核：非容器、非 OpenVZ、非 WSL |
| 系统版本 | Debian 12+ 或 Ubuntu 24.04+（衍生发行版不支持；其他系统仍可启用自带 BBR） |
| 架构 | x86_64 或 aarch64，且 `dpkg --print-architecture` 一致 |
| 安装工具 | `apt-get`、`dpkg`、`dpkg-deb`、`dpkg-query`、`update-grub`、`df` |
| 引导回退 | 使用 GRUB（`/boot/grub/grub.cfg`）；当前内核的 vmlinuz、initrd 和模块目录完整（保证可回退）；不支持设备树 / U-Boot / 厂商引导链 |
| Secure Boot | EFI 系统必须能确认 Secure Boot 已关闭（状态不明也会拒绝）；传统 BIOS 引导直接通过 |
| 空间 | `/boot` 至少 512 MiB 空闲，根分区至少 2 GiB |

预览会逐项显示检查结果（`[通过]` / `[失败]` / `[跳过]`），有失败时以第一项失败的原因报错退出。执行安装时，下载目录 `/var/lib/onebox-bbr` 还需容纳安装包并另留 256 MiB；确认之后、真正安装之前会再完整检查一次。

### 安装过程

带 `--apply` 时依次：

1. 缺少 curl 时先自动安装，然后显示预览和检查结果；有检查失败时停止。
2. 下载匹配内核的 image 与 headers 两个包到 `/var/lib/onebox-bbr`，逐一校验 GitHub API 提供的大小和 SHA-256、官方下载地址，以及包内的包名、架构和版本；不执行上游的 `install.sh`。
3. 运行 `apt-get --simulate` 并显示将安装的软件包，包括来自系统软件源的额外依赖；预演需要删除任何软件包时直接取消。
4. 请求确认（默认否，`-y` 自动确认），再次检查后用 `apt-get install --no-remove --no-install-recommends` 安装，不删除任何旧内核。apt / dpkg 的输出实时显示；安装期间 Ctrl+C 只会提示等待，不会中断 dpkg。
5. 确认两个包已配置完成、新内核的引导文件齐全，执行 `update-grub` 并确认 GRUB 中有新内核的引导项。**不会自动重启，也不修改 GRUB 默认启动项。**
6. 下载校验记录保存在 `/var/lib/onebox-bbr/last-install.tsv`。

GitHub 元数据始终直接从 api.github.com 获取；`GH_PROXY` 只用于下载安装包，内容必须与直连元数据的校验值一致。缺少 SHA-256 的旧 Release 会被拒绝。

与 v2 相比：预览和菜单本身不再需要 root；预览逐项列出全部检查而不是只报第一项失败；apt 预演结果在确认之前显示；下载暂存在 `/var/lib/onebox-bbr` 而不是临时目录；apt / dpkg 输出实时显示。

### 风险与恢复

- **安装前确认有 VPS 控制台（VNC / 串口）访问和可恢复的磁盘快照。**
- 选择维护时间手动重启，必要时在 GRUB 中选择新内核，然后执行 `onebox bbr status` 和 `onebox bbr enable fq`。
- 新内核无法启动时，从控制台 GRUB 的 Advanced options 选择保留的旧内核；修复引导前不要清理旧内核包。
- 校验只保证下载完整，不能替代对上游构建者的信任。
- **Max 版**更激进地探测带宽，仅用于自有链路的吞吐实验，可能增加延迟、丢包和带宽争抢，不保证更快。Onebox 只安装内核包，上游脚本的 sysctl 调优、测速软件、模块黑名单和快捷命令都不会被应用。
- 卸载 Onebox 节点（`onebox uninstall`）不会卸载已安装的内核，也不会删除 `/etc/sysctl.d/99-onebox-bbr.conf`。

## 菜单

`onebox bbr` 在交互终端打开菜单（非交互时显示状态），标题显示当前拥塞算法和默认队列：状态与实际网卡队列、启用 BBR 并选择默认队列、查看 / 安装标准版、查看 / 安装 Max 版。需要 root 的项目在询问前先检查权限；安装项询问标签（默认 `latest`）后按上面的 `--apply` 流程执行，同样先显示预览和 apt 预演，确认后才安装。某项失败或取消后回到菜单。
