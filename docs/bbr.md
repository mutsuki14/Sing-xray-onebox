# BBR / BBRv3

`onebox bbr` 管理 TCP 拥塞控制：启用当前内核自带的 BBR，或安装 [byJoey/Actions-bbr-v3](https://github.com/byJoey/Actions-bbr-v3) 构建的 BBRv3 内核。交互安装结束时可选择启用 BBR（`--no-bbr` 跳过）；升级程序、打开菜单和查看状态都不会安装内核。

> TCP BBR 只影响 TCP 协议。Hysteria2 / TUIC 使用 QUIC 自己的拥塞控制，请用 `onebox tune`（见 [performance.md](performance.md)）。

## 启用当前内核的 BBR

```bash
onebox bbr status              # 拥塞算法、默认队列、实际网卡队列、模块与已装内核（无需 root）
onebox bbr enable              # BBR + fq（需要 root）
onebox bbr enable fq_codel     # 也支持 fq_pie、cake，取决于内核
```

- 适用于提供 `tcp_bbr` 模块的系统；OpenVZ 不支持，其他容器受宿主机限制。
- 设置写入 `/etc/sysctl.d/99-onebox-bbr.conf`；应用失败时恢复原运行参数并保留原文件。其他配置文件设置了相同参数时会提示检查覆盖关系。
- 选择队列只修改 `net.core.default_qdisc`，**不会替换正在运行的网卡队列或已有带宽整形规则**；用 `onebox bbr status` 或 `tc qdisc show` 查看实际队列。
- 算法名为 `bbr` 不代表是 v3；状态页分别显示运行内核、已加载模块版本和磁盘上的模块版本。

## 安装 BBRv3 内核

```bash
onebox bbr releases                      # 当前 CPU 架构可用的标准版 Release
onebox bbr install                       # 预览最新标准版，不安装（无需 root）
onebox bbr install --dry-run             # 同上：不带 --apply 时默认即为预览
onebox bbr install latest --apply        # 安装，执行前再次确认（需要 root）
onebox bbr install x86_64-7.2.8 --apply  # 指定标签，以 releases 的实际输出为准
onebox bbr releases --max
onebox bbr install latest --max          # 预览 Max 实验版；安装同样需要 --apply
```

无人值守安装必须同时给出 `--apply -y`。不带 `--apply` 时 `bbr install` 只预览，`--dry-run` 与之等价（便于与其他命令保持一致）<!-- TODO: verify bbr install --dry-run is accepted and equals the default preview -->。预览需要联网查询 Release，但不安装依赖、不修改 sysctl 或引导。

### 安装前检查

| 项目 | 要求 |
|---|---|
| 系统 | Debian 12+ 或 Ubuntu 24.04+（衍生发行版不支持） |
| 架构 | x86_64 或 aarch64，且 `dpkg` 架构一致 |
| 环境 | 非容器、非 WSL；不支持设备树 / U-Boot / 厂商引导链 |
| 引导 | 使用 GRUB；当前内核的 vmlinuz、initrd 和模块完整（保证可回退） |
| 安全启动 | EFI 系统必须确认 Secure Boot 已关闭 |
| 空间 | `/boot` 至少 512 MiB 空闲，根分区 2 GiB，临时目录容纳下载包并留 256 MiB |
| 工具 | `apt-get`、`dpkg`、`dpkg-deb`、`dpkg-query`、`update-grub`、`df` |

预览时也会执行这些检查，任一项不满足即停止；安装确认后会在加锁状态下再检查一次。<!-- TODO: verify whether checks are reported individually -->

### 安装过程

- 只安装匹配内核的 image 与 headers 两个包；逐一校验 GitHub API 提供的 SHA-256、大小、下载地址、包名、架构和版本，不执行上游的 `install.sh`。
- GitHub 元数据直接从 api.github.com 获取；`GH_PROXY` 只用于包下载，内容必须与直连元数据的校验值一致。缺少校验值的旧 Release 会被拒绝。
- apt 使用 `--no-remove`，不删除任何旧内核；apt / dpkg 的输出实时显示，安装过程中不要中断。<!-- TODO: verify apt simulation summary is shown before confirmation -->
- 完成后更新 GRUB 并确认新内核的引导项存在；**不会自动重启，也不修改 GRUB 默认启动项**。
- 下载校验记录保存在 `/var/lib/onebox-bbr/last-install.tsv`。

### 风险与恢复

- **安装前确认有 VPS 控制台（VNC / 串口）访问和可恢复的磁盘快照。**
- 选择维护时间手动重启，必要时在 GRUB 中选择新内核，然后执行 `onebox bbr status` 和 `onebox bbr enable fq`。
- 新内核无法启动时，从控制台 GRUB 的 Advanced options 选择保留的旧内核；修复引导前不要清理旧内核包。
- 校验只保证下载完整，不能替代对上游构建者的信任。
- **Max 版**更激进地探测带宽，仅用于自有链路的吞吐实验，可能增加延迟、丢包和带宽争抢，不保证更快。上游的极限 sysctl 参数、测速软件、模块黑名单和快捷命令不会被应用。
- 卸载 Onebox 不会卸载已安装的 Linux 系统内核。

## 菜单

`onebox bbr` 在交互终端打开菜单（非交互时显示状态）：状态与实际网卡队列、启用 BBR 并选择默认队列、查看 / 安装标准版、查看 / 安装 Max 版。菜单中的安装项也会先显示预览，确认后才执行。
