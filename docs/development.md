# 开发与测试

## 设计原则

- 单个静态 musl 程序 `onebox`（Rust 2021，`rust-version = 1.97`，CI 与发布使用 1.99.0）加一个很薄的 POSIX `sh` 引导脚本 `onebox.sh`。
- 依赖列在 `Cargo.toml`（serde、serde_json、sha2、base64、libc、tar、flate2、x25519-dalek、qrcode、httparse），具体版本由 `Cargo.lock` 锁定（构建与 CI 一律 `--locked`），不引入网络或 TLS 库；下载经 `curl`，证书经 openssl / acme.sh（固定 3.1.6）。
- 面向用户的文字全部为简体中文；代码、注释和标识符为英文。数据结果写标准输出，提示、进度、警告和错误写标准错误。
- 数据路径上不使用 `unwrap()` / `expect()` / `panic!`（测试除外）；生产代码中的 `unsafe` 只出现在 `sys/` 并注明不变式。
- 所有外部程序都通过 `sys::exec::Exec` 执行，测试中用 `FakeExec` 替代；所有文件路径来自 `Paths`，测试中用 `Paths::isolated(tmp)`；交互通过 `Prompter`，测试中用 `ScriptedPrompter`。
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
| `host/` | 主机集成：系统识别、init、包管理、下载、内核下载与校验、服务单元、无 init 进程管理、crontab、防火墙、端口跳跃、sysctl、nginx |
| `apply/` | 节点变更的事务引擎：日志、快照、按阶段执行与回滚、`recover`、开机恢复 |
| `cert/`、`site/`、`subscription/` | 证书、自有域名网站、远程订阅 |
| `backup/`、`update/` | 快照备份与恢复；程序自更新与内核更新 |
| `frp/`、`bbr/`、`linktools/`、`diag/` | FRP 服务端、BBR、客户端链路工具、体检与诊断包 |
| `cli/` | 声明式参数解析、命令注册表（含 root 策略）、中文帮助、菜单与向导 |

依赖方向（无环）：`sys` → `domain` → `state` / `render` → `host` → `cert` / `site` / `subscription` → `apply` → `backup` / `update` → `cli`。`frp`、`bbr`、`linktools`、`diag` 不调用节点事务引擎，也不依赖 `backup` / `update`：FRP 只复用叶子模块 `apply::snapshot`（仅依赖 `sys` / `paths` / `error`）；诊断读取 `frp::model`（仅依赖 `domain` / `sys` / `paths` / `error` 的叶子模块）中的 FRP 状态，并读取节点事务日志 `apply::journal`（它依赖 `domain`、`state`、`host` 的服务与计划任务模块，以及 `apply::snapshot`、`apply::program_journal`，但不依赖事务引擎）。FRP 的体检项由 `frp` 以 `diag::Check` 返回，由命令层传给 `diag`，所以 `diag` 不导入 FRP 的其他部分。各功能模块用 `cli::args`（只依赖 `ctx` / `error` 的参数解析器）声明自己的命令树。`cert`、`site`、`subscription` 的功能代码不调用 `apply`：节点变更由命令层（以及位于其上的 `backup`、`update`）构造 `ApplyRequest` 交给 `apply`。

## 事务引擎

每次节点变更构造一个 `ApplyRequest { config, expected, intents, reason }`：`config` 是规划函数产出的完整新配置，`expected` 是读取时的状态哈希（加锁后比对，防止并发覆盖），`intents` 是不持久化的一次性意图（强制续期证书、恢复快照、发布网站内容、替换内核、迁移订阅设备、Cloudflare 凭据等）。引擎从不向用户提问，凭据由命令层事先解析。

执行顺序：加锁（或继承 fd 198 上的锁）→ 恢复遗留事务（节点事务、自更新）→ CAS 校验 → 安装信号处理 → 默认值与全量校验（含 FRP 预留端口）→ 记录运行时快照 → 清理崩溃遗留的临时文件 → 写事务日志并快照所有受管路径 → 按阶段执行：

| 阶段 | 进度标签 | 工作 |
|---|---|---|
| `prepare-state` | 准备 | 安装自身、放置要恢复的备份文件、迁移订阅设备 |
| `replace-cores` | 替换内核 | 仅内核更新时：换入已校验的内核 |
| `prepare-cores` | 准备内核 | 下载缺失内核（遵守固定版本）、记录版本、刷新本机 IP、复查端口 |
| `prepare-certificates` | 准备证书 | HTTP-01 需要时停止旧的 80 端口占用者并放行 80；订阅、网站与代理证书 |
| `check-configurations` | 校验配置 | 渲染服务端配置并用 `sing-box check`、`xray run -test` 校验；网站与订阅的 nginx 配置先暂存再 `nginx -t` |
| `stop-old-services` | 停止旧服务 | 内核、订阅 nginx、网站 |
| `commit-configurations` | 写入配置 | 内核配置就位，删除不再使用的配置 |
| `configure-services` | 配置服务 | 写入 / 启用 / 移除服务单元 |
| `apply-website` | 应用网站 | 启动网站 nginx（已测试的配置）或移除网站 |
| `apply-network` | 应用防火墙 | 防火墙台账、端口跳跃、`onebox-network` |
| `start-cores` | 启动内核 | 启动并等待运行 |
| `publish-clients` | 发布客户端配置 | 原子替换 `client/` 目录 |
| `publish-subscription` | 发布订阅 | |
| `finalize` | 完成 | 写入计划任务与 `state.json`，提交并删除日志 |

失败时按日志回滚：先停止服务并清除防火墙规则，再恢复快照文件，最后恢复防火墙规则、服务启用状态、计划任务并按固定顺序启动原来运行的服务。阶段名与 v2 相同，v2 留下的事务日志（version 1）也能被恢复。FRP 有自己的事务和日志（`/etc/.onebox-frp-journal`），由 `onebox recover` 在节点事务之后一并恢复。

## 构建与检查

本地构建，以及与 CI lint 任务相同的检查：

```bash
cargo build --release --locked
scripts/check-version.sh                   # Cargo.toml、Cargo.lock 与 onebox.sh 的版本一致
cargo fmt --check
cargo clippy --all-targets --locked -- -D warnings
cargo test --all-targets --locked
cargo test --doc --locked
sh -n onebox.sh && bash -n tests/bootstrap.sh
LC_ALL=C.UTF-8 shellcheck -S warning onebox.sh scripts/check-version.sh tests/bootstrap.sh
bash tests/bootstrap.sh                    # 引导脚本的离线测试（假 uname / curl / onebox）
python3 tests/fetch_tools.py --check       # 校验 tests/tools.json，不联网
```

`tests/bootstrap.sh` 默认用本机已有的 `sh`、`bash`、`dash`、`busybox` 分别运行引导脚本，可用 `ONEBOX_BOOTSTRAP_TEST_SHELLS="dash bash"` 指定（列出的 shell 必须存在），`ONEBOX_BOOTSTRAP_QUICK=1` 跳过 30 秒的看门狗用例。

开发时可用环境变量把所有路径指向临时目录，避免改动本机：`ONEBOX_DIR`、`ONEBOX_BIN_DIR`、`ONEBOX_LOG_DIR`、`ONEBOX_RUN_DIR`、`ONEBOX_SITE_ROOT`、`ONEBOX_SYSTEMD_DIR`、`ONEBOX_INITD_DIR`、`ONEBOX_EXE`、`ONEBOX_FRPS_DIR`、`ONEBOX_FRPS_BIN_DIR`、`ONEBOX_FRPS_WEB_VAR`、`ONEBOX_FRPS_LOG_DIR`、`ONEBOX_FRPS_RUN_DIR`、`ONEBOX_BBR_DIR`、`ONEBOX_BBR_CONF`、`ONEBOX_SYSTEM_ROOT`（读取 `/etc/os-release`、`/proc`、`/sys`、`/boot` 的前缀）。值必须是不含 `..` 的绝对 UTF-8 路径，否则命令开始时即报错；前 13 个（另加 `ONEBOX_INIT`）会写入服务单元和计划任务。其他常用变量：

| 变量 | 作用 |
|---|---|
| `ONEBOX_INIT=systemd\|openrc\|none` | 指定 init 系统；`none` 时由 Onebox 自己管理进程，可在容器中完整运行生命周期 |
| `ONEBOX_SINGBOX_BIN`、`ONEBOX_XRAY_BIN` | 用本地内核文件代替下载（离线安装、测试） |
| `ONEBOX_NGINX_BIN` | 使用指定的 nginx 程序（不安装软件包，也不停用系统 nginx 服务）。不写入服务环境：服务单元记录程序路径，订阅服务的 socket 用户组取自配置事务写入 `subscription/listener.json` 的 nginx 工作账号 |

## 测试

| 层次 | 内容 | 运行方式 |
|---|---|---|
| 单元测试 | 每个模块的纯逻辑；命令执行用 `FakeExec`，文件用 `Paths::isolated`，交互用 `ScriptedPrompter` | `cargo test` |
| 黄金对比测试 | `tests/golden/cases/` 的 10 个 v2 状态样例与 v2.0.1 程序的输出（`render server/inbound/outbound/probe`、`client <格式>`）。v3 用真实的 v2 迁移读取样例后渲染：JSON 按值和文本比较，链接与 Base64 逐字节一致，mihomo 按结构比较（v3 输出 YAML，v2 输出 JSON），v2 拒绝的命令 v3 必须以相同消息拒绝。例外逐条记录在 `tests/golden/ALLOWED_DIFFS.md`，某个例外不再出现或出现在别处都会让测试失败。网站首页模板另与 v2 `site preview` 的输出逐字节比较（`src/site/golden/`） | `cargo test` |
| 真实内核校验（`#[ignore]`） | 每个黄金样例的服务端与客户端配置通过 `sing-box check`、`xray run -test`、`mihomo -t`；`doctor` 的内核检查对真实内核运行 | 见下 |
| Rust 端到端测试（`#[ignore]`） | FRP（官方 frps / frpc + nginx，全部在本机回环）、订阅（真实 nginx、openssl、curl）、链路工具（真实内核）、nginx / 网站配置、真实下载等 | 见下 |
| 黑盒测试（Python） | `tests/e2e/*.py`：在隔离目录中运行真实的 v3（和 v2.0.1）程序；生命周期与升级套件需要 root | 见下 |

### 真实工具

CI 用 `tests/fetch_tools.py` 按 `tests/tools.json` 下载并校验（GitHub API 的 SHA-256 摘要与大小）固定版本：sing-box 1.14.2、Xray 26.3.27、mihomo 1.19.32、frp 0.71.0（frps 与 frpc）；nginx 从发行版的 deb 包中解出（`apt-get download nginx` + `dpkg-deb -x`），不启动系统服务。本地同样可以（清单中是 x86_64 的资产）：

```bash
python3 tests/fetch_tools.py "$HOME/onebox-tools"    # 需要联网；GH_TOKEN 可选
```

CI 还用 `--archives 目录` 保留校验过的发布包（`Xray-linux-64.zip`、`sing-box-…-linux-amd64.tar.gz`，供安装包解压测试 `ONEBOX_TEST_XRAY_ZIP` / `ONEBOX_TEST_SINGBOX_TGZ` 使用），并从 Xray 发布包中解出 `geoip.dat` / `geosite.dat` 放在 xray 旁边。

### 黄金文件

样例、目录布局和例外说明见 `tests/golden/README.md`。用 v2.0.1 程序重新生成 `expected/`（需要 `jq`；样例部署到 `/tmp/onebox-golden/<名称>`，保证服务端配置中的证书路径在任何机器上相同）：

```bash
tests/golden/generate.sh /path/to/onebox-v2                  # 全部样例
tests/golden/generate.sh /path/to/onebox-v2 c04-site-https   # 单个样例
```

提交前检查 `expected/` 的差异：这些文件是与 v2 一致性的约定。任何新增的 v2 / v3 差异都必须作为命名规则加入 `src/render/golden.rs` 并写入 `ALLOWED_DIFFS.md`。

### 被忽略的测试（`#[ignore]`）

```bash
# 真实内核校验：render::realcore 与 diag::realcore
ONEBOX_TEST_SINGBOX=/path/sing-box ONEBOX_TEST_XRAY=/path/xray ONEBOX_TEST_MIHOMO=/path/mihomo \
  cargo test --locked realcore -- --ignored

# FRP 端到端（TCP、UDP、网站模式的 HTTPS 与 WebSocket）
ONEBOX_FRPS_BIN=/path/frps ONEBOX_FRPC_BIN=/path/frpc ONEBOX_NGINX_BIN=/path/nginx \
  cargo test --locked frp::e2e -- --ignored

# 订阅端到端（使用随机空闲端口）
ONEBOX_NGINX_BIN=/path/nginx cargo test --locked --lib subscription::e2e -- --ignored --test-threads=1

# 链路工具端到端（还需要 PATH 中的 curl 与 openssl）
ONEBOX_TEST_SINGBOX=/path/sing-box ONEBOX_TEST_XRAY=/path/xray \
  cargo test --locked --lib linktools::e2e -- --ignored
```

Xray 客户端配置的校验需要 `geosite.dat` / `geoip.dat`，放在 `ONEBOX_TEST_XRAY_ASSETS` 指定的目录（默认与 xray 程序同目录）；mihomo 首次运行会联网下载 geodata 到系统临时目录下的缓存。缺少变量或文件时多数测试打印跳过提示后通过（`ONEBOX_TEST_REQUIRE_FULL=1` 时失败），但 FRP 端到端测试会直接失败。

不要不加过滤地在开发机上运行 `cargo test -- --include-ignored`：其余被忽略的测试会访问 github.com（真实下载）、读取本机真实状态（`bbr` 状态）、向测试进程发送信号，或者需要额外条件——可用的 nginx（`ONEBOX_NGINX_BIN`、PATH 或 `/usr/sbin/nginx`，nginx 与网站配置测试找不到时会失败）（无 init 进程管理识别 nginx 也用 `ONEBOX_NGINX_BIN`）、`ONEBOX_TEST_XRAY_ZIP` / `ONEBOX_TEST_SINGBOX_TGZ`（真实安装包解压）、`nft` 与 CAP_NET_ADMIN（端口跳跃脚本），以及在独立网络命名空间中设置 `ONEBOX_TEST_NETNS=1`（防火墙，例如 `unshare -n <测试程序> real_firewall --ignored`）。这些测试适合在容器或 CI 中运行。

`ONEBOX_TEST_REQUIRE_FULL=1` 是 CI 的约定：查找真实工具的测试都使用共享的 `sys::testenv`（`tool`、`have`、`skip`），在缺少变量、工具、文件或权限时直接失败而不是跳过。

### 黑盒测试（Python）

`tests/e2e/` 下每个不以 `_` 开头的 `*.py` 是一个独立套件，`_*.py` 是共用的辅助模块，不直接运行：

| 套件 | 内容 |
|---|---|
| `protocols.py` | 协议 × 服务端内核 × 客户端（sing-box、Xray、mihomo）真实流量矩阵，全部在本机回环 |
| `policy.py` | 私有地址与本机地址拦截等出站策略、Xray 上 REALITY 与 XHTTP 共用端口 |
| `lifecycle.py` | 安装、修改、导出、备份恢复、注入启动失败后的回滚与 `recover`、v2 状态迁移、1.x 拒绝、卸载（root，`ONEBOX_INIT=none`） |
| `upgrade.py` | 用 v2.0.1 程序安装后由 v3 原地升级：继承 fd 198 上的锁、保留凭据与订阅设备、v2 备份的恢复、子进程失败时回滚到与 v2 逐字节一致（包括经过真实的 v2 `update-script` 由 v2 恢复原程序）、恢复 v2 留下的事务和自更新日志（root） |

套件通过环境变量取得被测程序和真实工具：`ONEBOX_TEST_BINARY`（v3 程序，默认 `target/debug/onebox`）、`ONEBOX_TEST_SINGBOX`、`ONEBOX_TEST_XRAY`、`ONEBOX_TEST_MIHOMO`、`ONEBOX_TEST_V2_BINARY`（v2.0.1 程序，`upgrade.py` 必需）。各套件只读取自己需要的变量（`lifecycle.py` 只用 `ONEBOX_TEST_SINGBOX` 做真实内核的一轮）；`ONEBOX_TEST_REQUIRE_FULL=1` 时任何跳过（非 root、缺少工具或变量）都算失败。`lifecycle.py` 与 `upgrade.py` 用 `RUSTC`（默认 PATH 中的 `rustc`）编译假内核，在同一次运行中先跑假内核用例（注入启动失败只在假内核下进行），真实内核只是额外的一轮。失败时以非零状态退出。

```bash
cargo build --locked
T=/path/to/tools   # tests/fetch_tools.py 下载的 sing-box、xray、mihomo

ONEBOX_TEST_BINARY="$PWD/target/debug/onebox" ONEBOX_TEST_SINGBOX=$T/sing-box \
  ONEBOX_TEST_XRAY=$T/xray ONEBOX_TEST_MIHOMO=$T/mihomo python3 tests/e2e/protocols.py
ONEBOX_TEST_BINARY="$PWD/target/debug/onebox" ONEBOX_TEST_SINGBOX=$T/sing-box \
  ONEBOX_TEST_XRAY=$T/xray python3 tests/e2e/policy.py

for suite in lifecycle upgrade; do
  sudo env ONEBOX_TEST_BINARY="$PWD/target/debug/onebox" ONEBOX_TEST_SINGBOX=$T/sing-box \
    ONEBOX_TEST_V2_BINARY=/path/to/onebox-linux-amd64-musl RUSTC="$(rustup which rustc)" \
    ONEBOX_TEST_REQUIRE_FULL=1 python3 "tests/e2e/$suite.py"
done

python3 tests/e2e/_lifecycle_sandbox_test.py   # 沙箱辅助模块的单元测试（无需 root）
python3 tests/e2e/_selftest.py                 # 其余辅助模块的自测（protocols.py 与 policy.py 运行前也会执行）
```

v2.0.1 程序使用已发布的静态资产，而不是从源码构建：CI 从 `https://github.com/mutsuki14/Sing-xray-onebox/releases/download/v2.0.1/` 下载 `onebox-linux-amd64-musl` 与 `SHA256SUMS`，要求 `SHA256SUMS` 中列出的摘要等于工作流里固定的 SHA-256、文件本身也与之相符，并且 `version` 输出 `2.0.1`。本地运行时用同样的方式取得并校验该文件。

生命周期与升级套件把每个节点装在独立的临时目录中：全部路径变量指向该目录，`PATH` 只含记录调用的辅助程序（模拟 `iptables`、`nft`、`crontab` 等，拒绝包管理器、init 工具、shell 等，拒绝的调用一律算失败）。Onebox 启动的守护进程和一次性服务使用固定的 `SAFE_PATH`，不经过这个 `PATH`，所以套件还会：在每个沙箱创建和清理时比较本机的 `iptables-save`、`ip6tables-save`、`nft list ruleset` 与 root 的 crontab（不同即失败；运行期间自行改动防火墙的主机，例如 Docker 启动容器，也会触发）；以 root 运行时进入私有挂载命名空间，把会改动主机的程序名以记录并拒绝的替身挂载到 `/usr/local/sbin`（`SAFE_PATH` 的第一项），本机看不到这个挂载。无法挂载（没有 CAP_SYS_ADMIN、Python 低于 3.12）时只打印跳过提示，`ONEBOX_TEST_REQUIRE_FULL=1` 下则失败。套件会启动服务并监听本机回环端口，适合在容器或 CI 中运行。生成配置成功不能代替真实连通性测试。

## CI 与发布

**CI**（`.github/workflows/ci.yml`；任意分支的 push、pull request 和手动触发；工具链 1.99.0）：

1. `lint`（Lint and unit tests）：`scripts/check-version.sh`、`cargo fmt --check`、clippy（`-D warnings`）、`cargo test --all-targets` 与 `cargo test --doc`；随后（即使 Rust 步骤失败也会运行）引导脚本语法检查、shellcheck、`tests/bootstrap.sh`（含 busybox ash）、`tests/fetch_tools.py --check` 和全部 Python 文件的语法检查。
2. `integration`（Integration with real cores, FRP and nginx）：下载并校验固定版本的真实内核与 frp、解出 nginx，以 root 单线程运行全部 Rust 测试（`--include-ignored --test-threads=1`，设置所有真实工具变量和 `ONEBOX_TEST_REQUIRE_FULL=1`），再以 root 逐个运行 `tests/e2e/` 下的黑盒套件（`_*.py` 辅助模块除外；目录中没有套件时该步骤直接通过）。
3. `cross`（Static build，矩阵四个目标）：用固定提交的 cross 和解析为摘要的官方构建镜像编译 `x86_64-unknown-linux-musl`、`aarch64-unknown-linux-musl`、`i586-unknown-linux-musl`、`armv7-unknown-linux-musleabihf`，静态链接（`-C target-feature=+crt-static`），确认 `--version` 输出与版本一致且没有 `INTERP` 程序头，并把所用镜像摘要作为构件留给发布流程。

**发布**（`.github/workflows/release.yml`；在 `main` 的 CI 成功后自动触发，也可手动触发或推送 `v*` 标签）：

1. `gate`：确认构建的是 `main` 的最新提交、该提交最近一次 CI 成功、版本来源一致（推送的标签必须是 `v<版本>` 且指向该提交）；已公开的同版本 Release 永不覆盖。
2. `build`：在 CI `cross` 任务测试过的同一镜像（按摘要）中构建四个资产 `onebox-linux-{amd64,arm64,386,armv7}-musl`，并记录构建信息。
3. `publish`：生成 `SHA256SUMS` 与 `BUILD-INFO.json`（版本、源码提交、CI 运行、工具链、cross 版本、构建镜像），先上传到草稿，下载回来复核校验和，确认 GitHub API 报告的大小与 SHA-256 摘要正确，再次确认 `main` 未变化，最后公开为最新 Release。

版本号以 `Cargo.toml` 为准（当前 3.0.0）：`Cargo.lock`、引导脚本的 `SCRIPT_VERSION`、发布标签 `v3.0.0` 和程序的 `onebox version` / `--version` 输出必须一致（`scripts/check-version.sh` 检查前三者）。v2 的 `update-script` 依赖资产名 `onebox-linux-{架构}-musl`、GitHub API 提供的资产大小与 SHA-256 摘要，以及 `onebox version` 的 `x.y.z` 输出来完成原地升级，这些都不能改动。
