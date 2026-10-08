# 开发与测试

## 设计原则

- 单个静态 musl 程序 `onebox`（Rust 2021，MSRV 1.97，CI 使用 1.99.0）加一个很薄的 POSIX `sh` 引导脚本 `onebox.sh`。
- 依赖固定在 `Cargo.toml`（serde、serde_json、sha2、base64、libc、tar、flate2、x25519-dalek、qrcode、httparse），不引入网络或 TLS 库；下载经 `curl`，证书经 openssl / acme.sh。
- 面向用户的文字全部为简体中文；代码、注释和标识符为英文。数据结果写标准输出，提示、进度、警告和错误写标准错误。
- 数据路径上不使用 `unwrap()` / `expect()` / `panic!`；`unsafe` 只出现在 `sys/` 并注明不变式。
- 所有外部程序都通过 `sys::exec::Exec` 执行，测试中用 `FakeExec` 替代；所有文件路径来自 `Paths`，测试中用 `Paths::isolated(tmp)`。
- 每个模块的文档注释列出 “Changes from v2”：与 v2 的差异必须是有意的修复。

## 模块结构

| 模块 | 职责 |
|---|---|
| `error.rs`、`paths.rs`、`ctx.rs` | 错误类型与退出码、路径（环境变量覆盖与校验）、上下文 `Ctx { paths, exec, ui }` |
| `sys/` | 与业务无关的系统原语：原子写文件、执行命令、随机数、信号、文件锁、时间、`/proc/net` 探测、文本校验 |
| `ui/` | 交互层：`Prompter`（终端 / 脚本化测试 / `-y`）、输出约定、隐藏输入、终端二维码 |
| `domain/` | 纯数据模型，无 I/O：协议与能力表、`NodeConfig`（schema 3）、默认值、预设、凭据生成、端口规划 `PortPlan`、校验、各种修改的规划函数 |
| `state/` | `state.json` 读写（CAS 哈希）、v2 状态迁移、1.x 检测 |
| `render/` | 纯渲染：sing-box / Xray 服务端与客户端、mihomo、分享链接、Base64、探测配置 |
| `host/` | 主机集成：系统识别、init、包管理、下载、服务单元、无 init 进程管理、crontab、防火墙、端口跳跃、sysctl、内核下载、nginx |
| `apply/` | 节点变更的事务引擎：日志、快照、按阶段执行与回滚、`recover`、开机恢复 |
| `cert/`、`site/`、`subscription/` | 证书、自有域名网站、远程订阅 |
| `backup.rs`、`update/` | 快照备份；程序自更新与内核更新 |
| `frp/`、`bbr/`、`linktools/`、`diag.rs` | FRP 服务端、BBR、客户端链路工具、体检与诊断包 |
| `cli/` | 声明式参数解析、命令注册表（含 root 策略）、中文帮助、菜单与向导 |

依赖方向（无环）：`sys` → `domain` → `state` / `render` → `host` → `cert` / `site` / `subscription` → `apply` → `backup` / `update` → `cli`。`frp`、`bbr`、`linktools`、`diag` 只依赖更低层。功能模块从不调用 `apply`，由 CLI 调用。

## 事务引擎

每次节点变更构造一个 `ApplyRequest { config, expected, intents, reason }`：`config` 是规划函数产出的完整新配置，`expected` 是读取时的状态哈希（加锁后比对，防止并发覆盖），`intents` 是不持久化的一次性意图（续期证书、恢复快照、发布网站内容、替换内核等）。

执行顺序：加锁（或继承 fd 198 上的锁）→ 恢复遗留事务 → CAS 校验 → 安装信号处理 → 默认值与全量校验 → 记录运行时快照 → 写事务日志并快照所有受管路径 → 按阶段执行：

| 阶段 | 进度标签 | 工作 |
|---|---|---|
| `prepare-state` | 准备 | 安装自身、恢复快照文件、迁移订阅设备、清理临时文件 |
| `replace-cores` | 替换内核 | 仅内核更新时 |
| `prepare-cores` | 准备内核 | 下载缺失内核（遵守固定版本），刷新本机 IP |
| `prepare-certificates` | 准备证书 | 代理 / 网站 / 订阅证书 |
| `check-configurations` | 校验配置 | 渲染服务端配置并用 `sing-box check`、`xray run -test`、`nginx -t` 校验 |
| `stop-old-services` | 停止旧服务 | |
| `commit-configurations` | 写入配置 | |
| `configure-services` | 配置服务 | 写入 / 启用 / 移除服务单元 |
| `apply-website` | 应用网站 | |
| `apply-network` | 应用防火墙 | 防火墙台账、端口跳跃、`onebox-network` |
| `start-cores` | 启动内核 | 启动并等待运行 |
| `publish-clients` | 发布客户端配置 | 原子替换 `client/` 目录 |
| `publish-subscription` | 发布订阅 | |
| `finalize` | 完成 | 写入 `state.json` 与计划任务，提交并删除日志 |

失败时按快照回滚文件、服务启用状态、计划任务和防火墙规则，再按固定顺序重启原来运行的服务。阶段名与 v2 相同，v2 留下的日志可被恢复。

## 构建与检查

```bash
cargo build --release --locked
cargo fmt --check
cargo clippy --all-targets --locked -- -D warnings
cargo test --all-targets --locked
shellcheck -s sh onebox.sh                 # 引导脚本
```

<!-- TODO: verify shellcheck invocation in CI -->

开发时可用环境变量把所有路径指向临时目录，避免改动本机：`ONEBOX_DIR`、`ONEBOX_BIN_DIR`、`ONEBOX_LOG_DIR`、`ONEBOX_RUN_DIR`、`ONEBOX_SITE_ROOT`、`ONEBOX_SYSTEMD_DIR`、`ONEBOX_INITD_DIR`、`ONEBOX_EXE`、`ONEBOX_FRPS_DIR`、`ONEBOX_FRPS_BIN_DIR`、`ONEBOX_FRPS_WEB_VAR`、`ONEBOX_FRPS_LOG_DIR`、`ONEBOX_FRPS_RUN_DIR`、`ONEBOX_BBR_DIR`、`ONEBOX_BBR_CONF`、`ONEBOX_SYSTEM_ROOT`（读取 `/etc/os-release`、`/proc`、`/sys` 的前缀）。值必须是绝对路径；配合 `ONEBOX_INIT=none` 可以在容器中完整运行生命周期。

## 测试

| 层次 | 内容 | 运行方式 |
|---|---|---|
| 单元测试 | 每个模块的纯逻辑；命令执行用 `FakeExec`，文件用 `Paths::isolated` | `cargo test` |
| 黄金对比测试 | `tests/golden/` 中的 v2 状态样例与 v2.0.1 程序的输出（`render server/inbound/outbound/probe`、`client <格式>`）；v3 渲染迁移后的配置必须逐字节一致，例外逐条记录在 `tests/golden/ALLOWED_DIFFS.md` 并注明原因 | `cargo test` |
| 真实内核校验 | 生成的每份服务端与客户端配置通过 `sing-box check`、`xray run -test`、`mihomo -t`（`#[ignore]`） | 见下 |
| 黑盒测试（Python） | 协议 × 客户端真实流量矩阵、私有地址策略、生命周期（回滚、恢复、v2 迁移；root + `ONEBOX_INIT=none` + 隔离目录）、FRP、订阅 | 见下 |

真实工具的固定版本：sing-box 1.14.2、Xray 26.3.27、mihomo 1.19.32、frp 0.71.0，nginx 从发行版包中解出（不启动系统服务）。

```bash
# 真实内核校验：只运行名称含 real_core 的 #[ignore] 测试
ONEBOX_TEST_SINGBOX=/path/sing-box ONEBOX_TEST_XRAY=/path/xray ONEBOX_TEST_MIHOMO=/path/mihomo \
  cargo test --locked real_core -- --include-ignored

# 黑盒测试
cargo build --locked
ONEBOX_TEST_BINARY="$PWD/target/debug/onebox" \
  ONEBOX_TEST_SINGBOX=/path/sing-box ONEBOX_TEST_XRAY=/path/xray \
  python3 tests/native_e2e.py
sudo env ONEBOX_TEST_BINARY="$PWD/target/debug/onebox" ONEBOX_TEST_SINGBOX=/path/sing-box \
  python3 tests/native_lifecycle.py --require-full
```

<!-- TODO: verify script names and flags of the ported Python suites, and the exact test-name filter (`real_core`) of the real-core checks -->

不要不加过滤地运行 `cargo test -- --include-ignored`：其他 `#[ignore]` 测试（订阅、FRP 的端到端测试）会启动真实的 nginx、frps / frpc 并在本机监听端口（订阅测试使用 TCP 80 / 443，需要 root），还需要 `ONEBOX_NGINX_BIN`、`ONEBOX_FRPS_BIN`、`ONEBOX_FRPC_BIN` 等变量，只适合在容器或 CI 中运行。<!-- TODO: verify the ignored end-to-end tests and their env vars once ported -->

生命周期测试会运行服务、修改测试目录和网络状态，适合在容器或 CI 中运行。生成配置成功不能代替真实连通性测试。

更新黄金文件时，用 v2.0.1 程序对同一组样例状态重新生成输出；任何新增差异都必须写入 `ALLOWED_DIFFS.md`。<!-- TODO: verify golden regeneration command -->

## CI 与发布

**CI**（每次 push / pull request）：

1. 格式、clippy（`-D warnings`）、全部单元测试与黄金测试；引导脚本语法检查与 shellcheck。
2. 集成任务：下载并校验固定版本的真实内核与 frp、解出 nginx，运行真实内核校验和全部黑盒测试。
3. 交叉编译四个 musl 目标（`x86_64`、`aarch64`、`i586`、`armv7` hard-float），静态链接（`-C target-feature=+crt-static`），确认 `--version` 输出与 `Cargo.toml` 一致且没有 `INTERP` 程序头。

**发布**（只针对默认分支 `main` 上 CI 已通过的提交）：

1. 闸门：确认构建的是 `main` 的最新提交、该提交的 CI 成功；已公开的同版本 Release 永不覆盖。
2. 构建：用固定摘要的 cross 镜像构建四个资产 `onebox-linux-{amd64,arm64,386,armv7}-musl`。
3. 发布：生成 `SHA256SUMS` 与 `BUILD-INFO.json`（源码提交、CI 运行、构建工具），先上传草稿，下载回来复核校验和，再次确认 `main` 未变化，最后公开为最新 Release。

版本号以 `Cargo.toml` 为准（当前 3.0.0）；引导脚本的 `SCRIPT_VERSION`、发布标签 `v3.0.0` 与程序的 `onebox version` 输出必须一致。v2 的 `update-script` 依赖资产名 `onebox-linux-{架构}-musl` 和 `version` 的精确输出来完成原地升级，二者都不能改动。<!-- TODO: verify workflow file names and job layout once CI is written -->
