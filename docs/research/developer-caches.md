# 开发者 SDK、包管理器、构建系统与容器缓存：跨平台盘点与安全回收研究

> 研究日期：2026-08-26。本文只做研究与只读发现设计；文中的清理、卸载、`prune`、`clean`、`remove` 等命令仅说明官方能力，**本次研究未执行其中任何一个**，也未删除文件、提权或修改开发环境。

## 1. 结论与判定框架

### 1.1 先分类，再谈“可清理”

**[推导]** 同一个名为 `cache` 的父目录里可能同时存在缓存、环境和工具链；反过来，名为 `repository` 或 `store` 的目录也可能主要是可再下载对象。**[建议]** 因此必须以管理工具的语义而不是目录名分类：

| 类别 | 例子 | 默认处置 | 风险 |
|---|---|---|---|
| A. 可再生缓存/构建输出 | pip HTTP/wheel cache、Go build cache、Cargo `target`、Derived Data | 在证据充分且无活动进程时，可通过官方工具按对象或范围回收 | R1–R2 |
| B. 共享下载/内容寻址存储 | pnpm store、NuGet global-packages、Cargo registry、容器镜像层 | 需要引用、离线恢复能力、共享关系和官方 GC 状态共同判断 | R2–R3 |
| C. 已安装依赖/环境 | `node_modules`、Python venv、Conda env、Ruby `GEM_HOME`、Composer `vendor` | 不是“缓存”；只按明确项目/环境执行可重建或卸载流程 | R3 |
| D. SDK/工具链/全局工具 | Node/Python/JDK/.NET/Go/Rust toolchain、Android SDK、Xcode、全局 CLI | v1 只报告所有者的卸载能力；不执行卸载 | 对象 R3；未来不可逆卸载动作 R4 |
| E. 用户或运行状态 | 容器 volume、Xcode archive、签名材料、配置/凭据、源码 | v1 report-only 或 BLOCKED；人工确认也不能绕过缺失能力 | 对象 R3/BLOCKED；未来不可逆动作 R4 |

**[建议]** 风险等级：**R1** 为满足全部证据门槛的普通项目文件；**R2** 为目录、批次、可再下载但昂贵或影响离线工作的共享缓存；**R3** 为已安装依赖、环境、SDK、多项目共享对象、用户状态、凭据或发布产物；**R4** 专指拟议的 Permanent filesystem action、不可逆 manager/browser mutation 或 destructive reset。根目录、受保护状态、凭据/发布产物等在 v1 可直接为 **BLOCKED**；对象敏感度本身不创造可审批的 R4 路径。运行时必须输出一个精确 tier，表中的范围只是证据尚未解析前的摘要。

### 1.2 证据门槛

下列标签贯穿全文：

- **[事实]**：官方文档或官方仓库直接说明，后附来源编号。所有网络来源均在第 16 节列出 URL 和访问日期。
- **[推导]**：由若干事实组合得到，但官方没有直接保证该结论。
- **[建议]**：面向盘点/清理器的安全策略。
- **[边界]**：目前无法可靠判断或跨版本、安装方式不稳定的部分。

为避免在表格每个单元格重复标签：紧邻表格前的标签说明其作用域；“位置/发现/官方能力”列为 **[事实]**，“风险/判定/建议”列为 **[建议]**，其中写明未知、heuristic 或不能证明的内容为 **[边界]**。同一句包含不同性质内容时仍逐段标注。

**[建议]** 任何自动建议都应输出下面九类证据；缺失项必须显示为 `unknown`，不能默认为安全：

1. **工具所有权**：哪个管理器/安装器拥有对象。
2. **规范路径**：由工具、环境变量和配置解析出的真实路径，并解析符号链接/junction 与文件系统身份。
3. **对象类别和粒度**：单项目输出、单包、单 SDK 版本、共享 store、volume 等。
4. **项目引用**：manifest、lockfile、workspace、toolchain pin、容器/AVD/运行时引用。
5. **近期活跃**：工具自己的 last-used/usage/GC 元数据优先；文件 `atime`/`mtime` 只能作为弱信号。
6. **激活/选择状态**：当前 shell、默认版本、目录 override、IDE 选择、booted/running 状态。
7. **官方状态**：工具 inventory、依赖图、`reclaimable`、lock/lease、健康/完整性信息。
8. **恢复条件**：能否从锁文件重建；网络、私有仓库、凭据、制品保留期、离线要求是否满足。
9. **共享与并发**：其他用户、项目、分支、容器、CI、远端 backend 及运行中进程是否共享。

### 1.3 “查询命令”不等于严格零写入

**[边界]** 本文的“官方查询/发现”表示命令的业务目的为 inventory、status 或 dependency inspection，**不保证进程对磁盘和网络零副作用**。**[推导]** 基于各工具文档中的 daemon、wrapper/plugin、dependency resolution、metadata 与 cache 行为，部分 CLI 即使没有显式变更动词，也可能启动 daemon、初始化 home、写日志/usage 数据、刷新 repository metadata、解析并下载依赖、生成 lock/state，或触发 plugin/wrapper 下载 [R3][G1][J3][J4][J5][M1][F1][A4]。**[建议]** 若任务要求像本次研究一样严格不修改环境，应分层执行：

| 层级 | 允许方式 | 典型例子 | 结论能力 |
|---|---|---|---|
| Z0 strict read-only | 读取已存在的 manifest、lock、config、metadata 与目录属性；不执行生态 CLI | `Cargo.toml`/`Cargo.lock`、`go.mod`/`go.sum`、Gradle/Maven config、Android `package.xml`、Xcode plist | 可识别静态引用/候选路径，不能声称 manager 当前状态 |
| Z1 guarded semantic query | 仅在可丢弃 sandbox/profile、网络禁用、写调用审计下执行；使用 tool 支持的 locked/offline/no-update/no-daemon 选项 | `cargo metadata --no-deps --locked --offline`；特定环境下的离线 manager inventory | 能提高语义准确度；仍不能假定零写入，失败即降级为 unknown |
| Z2 potentially stateful query | 默认不得在 strict read-only 扫描中运行；只描述能力或另行授权 | Gradle wrapper task、Maven help plugin、`go list`/dependency graph、`flutter doctor`、`sdkmanager --list` | 可能启动 daemon、下载 wrapper/plugin/artifact、刷新 metadata 或写 cache |
| M mutation | 只作官方能力说明，本研究绝不执行 | 所有 clean/prune/remove/uninstall/wipe/stop/switch/repair/verify-GC | 会改变文件、进程或环境 |

**[建议]** 产品应将 `semanticReadOnly` 与 `zeroWriteVerified` 分开记录，并审计系统调用/写路径，而不是从命令名称推断。若工具没有可证明的 no-write 模式，Z0 静态证据优先，官方状态标为 `unknown`。

**[事实]** Windows 的 `DeleteFile` 是否能删除打开文件取决于现有 handle 的 delete-sharing，且通常在最后一个 handle 关闭后才完成；POSIX `unlink` 在仍有打开引用时会延后释放内容 [S1][S2]。**[推导]** 因而“删除成功/失败”都不是“无人使用”的可靠证明。**[建议]** 运行进程检测只能作为阻断证据，不能证明没有短生命周期任务；在活动安装、构建、IDE 索引或守护进程存在时拒绝回收。

**[建议] 安全决策规则：**

- 只有 A 类且满足“工具确认路径 + 无活动进程 + 非共享或共享 GC 明确 + 可恢复”时，才能给出低风险建议。
- B 类必须展示实际独占可回收字节；硬链接、内容寻址层和共享镜像的逻辑大小不能相加。
- C/D 类必须找到所有者和版本引用；v1 只报告管理器能力，不执行卸载。未来不可逆 manager action 必须进入独立 R4 计划与精确审批；不能因为“最近未访问”自动卸载。
- E 类不进入通用自动清理。
- 单一访问时间永远不构成安全删除依据：即便一个系统记录了 `atime`/`mtime`，归档/复制/扫描策略与管理器自身 usage 数据也可能让它不等价于真实使用。

## 2. Node.js、npm、pnpm、Yarn 与 nvm

### 2.1 三平台位置与发现

**[事实]** 下表来自各工具的官方文档或官方仓库；明确写“常见”的位置不是保证值，权威发现列优先。shell executable lookup 是 **[建议]** 的交叉核对方式。

| 对象 | Windows | macOS | Linux | 权威发现（只读优先） |
|---|---|---|---|---|
| Node.js runtime | 安装器、系统包或版本管理器决定；没有通用默认 | 安装器/Homebrew/nvm 等决定 | 发行版包、归档、nvm 等决定 | `node -p "process.execPath"`、`node -p "process.version"` [N1]；**[建议]** Windows 再用 `Get-Command node -All`，POSIX 用 `command -v node` 交叉核对 |
| Node compile cache | 仅在 `NODE_COMPILE_CACHE`/API 启用时；否则 API 可选择 OS 临时目录 | 同左 | 同左 | `module.getCompileCacheDir()`（启用后）及 `NODE_COMPILE_CACHE` [N1] |
| npm cache | `%LocalAppData%\npm-cache` | `~/.npm` | `~/.npm` | `npm config get cache`；配置可覆盖 [N2][N3] |
| npm 本地/全局安装 | 项目 `node_modules`；全局 `{prefix}\node_modules` | 项目 `node_modules`；全局 `{prefix}/lib/node_modules` | 同 macOS | `npm root [ -g ]`、`npm prefix [ -g ]`、`npm ls [ -g ] --depth=0` [N3][N4] |
| pnpm store | 当前文档默认 `~/AppData/Local/pnpm/store` | `~/Library/pnpm/store` | `~/.local/share/pnpm/store` | `pnpm store path`；再查 `store-dir`、`PNPM_HOME`、XDG；pnpm 可能按磁盘选 store [N5][N6] |
| pnpm 项目安装 | `node_modules\.pnpm`（默认 virtual store） | `node_modules/.pnpm` | 同 macOS | `pnpm root`、`pnpm list --depth 0`、`.modules.yaml`、`pnpm why` [N6] |
| Yarn Modern | 通常项目 `.yarn/cache`；Yarn 4 默认全局缓存时转到 `globalFolder`，实现常落在 `%LOCALAPPDATA%\Yarn\Berry` | 有效路径常在 `~/.yarn/berry`，但可配置 | 同 macOS/XDG 可覆盖 | `yarn config get cacheFolder --why`、`globalFolder --why`、`enableGlobalCache --why` [N7] |
| Yarn Classic | 平台/配置相关，不应硬编码 | 同 | 同 | `yarn cache dir`、`yarn cache list`、`yarn global dir` [N8] |
| nvm-sh | **不支持原生 Windows shell** | 默认 `$NVM_DIR`（常为 `~/.nvm`）；版本在 `versions/node`，下载缓存 `.cache` | 同 macOS | `nvm ls/current/which/alias`、`nvm cache dir`、`NVM_DIR` [N9] |
| nvm-windows | `%NVM_HOME%`（常见 `%AppData%\nvm`），激活入口 `%NVM_SYMLINK%` | 不适用 | 不适用 | `nvm root/list/current/debug`、`where.exe node`、`settings.txt` [N10] |

### 2.2 官方能力、可回收粒度与证据

**标签作用域：**下表“官方查询/清理能力”为 **[事实]**，“可回收对象与粒度”及“多证据判定”是本文的 **[建议]**，写明缺失能力之处是 **[边界]**。

| 项目 | 官方查询/清理能力（仅说明） | 可回收对象与粒度 | 多证据判定、风险与边界 |
|---|---|---|---|
| Node | **[事实]** runtime 由其安装器管理；compile cache 目录可删除并重新预热 [N1] | compile cache：整目录，R1–R2；runtime：单版本安装，R3 | 查 `package.json#engines`/`devEngines`、`.nvmrc`、当前/默认版本、进程实际 executable、IDE/CI。**[边界]** Node 没有全机项目到 runtime 的使用数据库；REPL history 是用户状态，不是缓存。 |
| npm package cache | **[事实]** `npm cache ls` 查询；`npm cache verify` 会验证并执行垃圾回收，故不是严格只读；`npm cache clean --force` 清 package cache 且官方通常不建议例行执行 [N2] | registry response/tarball/content-addressed data，R2；`node_modules` 和全局包是安装，R3 | manifest、lockfile、workspace、`npm explain/query` 是引用证据；`npm ls` 的 missing/invalid/extraneous 是官方状态；无可靠 last-run。私有 registry/离线场景提高风险；活动 npm 进程时禁止。 |
| pnpm | **[事实]** `pnpm store status` 检查被改动包；`pnpm store prune` 做 store 范围的不可达回收，官方称不伤当前项目但切换分支可能重下 [N5] | store 范围 mark/sweep，R2；项目 `node_modules`、全局包和 pnpm 管理的 Node 是安装，R3 | 结合 `pnpm-lock.yaml`、workspace、`.modules.yaml`、注册项目、分支、全局目录和版本。硬链接导致删除项目安装不等于释放 store 块。pnpm 10/11 runtime 管理能力有变化，先查版本。 |
| Yarn | **[事实]** Modern `yarn cache clean` 可区分项目缓存/全局 mirror；Classic 可全清或按模块 [N7][N8] | cache scope，R1–R2；unplugged/linker 输出可重建；global package 是安装 | 先判 v1 或 Modern。检查 `packageManager`、`yarnPath`、`yarn.lock`、workspaces、`nodeLinker`、Git 跟踪。Zero-Installs 的 `.yarn/cache`、`.pnp.cjs` 可是仓库交付物，不能按缓存名删除。活动 PnP 进程可能打开 ZIP。 |
| nvm | **[事实]** nvm-sh 可清下载缓存并按版本卸载；nvm-windows 有按版本卸载，但不应假定存在同等稳定的 cache-clean 接口 [N9][N10] | 下载缓存 R1–R2；Node 版本及其全局 npm 工具 R3 | `.nvmrc`、shell 配置、alias/default、CI/IDE、当前进程路径共同判断。nvm-sh 激活按 shell；nvm-windows 切换共享 symlink。**[边界]** 没有 last-used registry，不能凭版本目录时间判“未用”。 |

**[事实]** npm 11 将 npx cache 单独暴露为 `npm cache npx ls/info/rm`；npm logs 也有独立配置/保留语义，`npm cache clean` 不应被描述为清理这两者 [N12]。**[建议]** 将 package cache、npx cache 和 logs 分成三个对象与动作。

**[事实]** standalone Corepack 提供 `COREPACK_HOME` 与 `corepack cache clean/clear` [N11]。**[建议]** 先检测 `corepack --version`，因为不能假定每个 Node 发行版都捆绑它；将其下载的包管理器版本作为独立 R2 层，不能记入 npm/pnpm/Yarn 自身 cache。

## 3. Python、pip、uv、Poetry 与 Conda

### 3.1 三平台位置与发现

**[事实]** 下表为官方默认值、覆盖规则与查询接口；明确写“常见”的 data/install 路径仅作候选，工具输出优先。

| 对象 | Windows | macOS | Linux | 权威发现（只读优先） |
|---|---|---|---|---|
| CPython | python.org per-user 常为 `%LocalAppData%\Programs\Python\PythonXY`，全局常为 `%ProgramFiles%\Python X.Y`，均可改 | python.org framework 在 `/Library/Frameworks/Python.framework`，另有 `/Applications/Python 3.x` | 无统一根；发行版常在 `/usr`，本地源码安装常在 `/usr/local` | Windows `py list --format=prefix`；任意平台用 `sys.executable`、`sys.prefix`、`sys.base_prefix`、`sysconfig.get_paths()` [P1][P2][P3] |
| stdlib venv | 任意创建路径，内部 `Scripts\` 和 `pyvenv.cfg` | 任意创建路径，内部 `bin/` 和 `pyvenv.cfg` | 同 macOS | 环境内 `sys.prefix != sys.base_prefix`；无全机官方 registry [P4] |
| pip cache | `%LocalAppData%\pip\Cache` | `~/Library/Caches/pip`（也尊重 XDG） | `$XDG_CACHE_HOME/pip` 或 `~/.cache/pip` | `python -m pip cache dir/info/list` [P5][P6] |
| uv cache | `%LOCALAPPDATA%\uv\cache` | `$XDG_CACHE_HOME/uv` 或 `~/.cache/uv` | 同 macOS | `uv cache dir`、`UV_CACHE_DIR` [P7][P8] |
| uv Python/tools/env | 由 uv data dir 决定；不能硬编码 | 常见 `~/.local/share/uv/python`；项目 env 默认 `.venv` | 同 macOS/XDG | `uv python dir/list/find`、`uv tool dir/list`；确认 `--managed-python` 所有权 [P8][P9] |
| Poetry cache | `%LOCALAPPDATA%\pypoetry\Cache` | `~/Library/Caches/pypoetry` | `$XDG_CACHE_HOME/pypoetry` 或 `~/.cache/pypoetry` | `poetry config cache-dir`、`POETRY_CACHE_DIR` [P10] |
| Poetry env | 默认 `{cache-dir}\virtualenvs` 或项目 `.venv` | 默认 `{cache-dir}/virtualenvs` 或 `.venv` | 同 macOS | `poetry env list --full-path`、`env info --path/--executable` [P11] |
| Conda base/env/pkg cache | 安装位置可选；常见示例不是规则 | 安装位置可选 | 安装位置可选 | `conda info --json/--envs`、`conda config --show envs_dirs pkgs_dirs`、`CONDA_PREFIX` [P12][P13] |

### 3.2 官方能力、可回收粒度与证据

**标签作用域：**第二列为 **[事实]**；第三、四列为 **[建议]** 与显式 **[边界]**。

| 项目 | 官方查询/清理能力（仅说明） | 可回收对象与粒度 | 多证据判定、风险与边界 |
|---|---|---|---|
| CPython/venv | **[事实]** Windows Install Manager 可列出并卸载其拥有的 runtime；其他平台由安装器/系统包管理器卸载。stdlib 无全机 venv 清理 registry [P1][P4] | runtime 对象 R3/report-only，未来卸载动作 R4；精确 venv 目录 R3；`__pycache__` 可重建但只能在明确项目边界内视为 R1 | 查解释器所有者、`pyvenv.cfg`、base interpreter、requirements/lock、editable/local 包、kernel/IDE/进程。系统 `/usr` Python 可能被 OS 依赖或 BLOCKED。没有可重建规格时 venv 不是安全缓存。 |
| pip | **[事实]** `pip cache remove <pattern>` 按 wheel/package，`pip cache purge` 清 HTTP 与 wheel cache；`pip inspect/list/show` 查安装状态 [P5][P6] | cache R1–R2；`site-packages` 是安装 R3 | 必须使用目标 `python -m pip`。锁文件/requirements 是重建证据但不证明环境无手工包。pip 没有“跨项目未使用依赖 GC”；私有/下线索引与本机构建 wheel 提高恢复风险。 |
| uv | **[事实]** `uv cache clean [PACKAGE]`、`uv cache prune [--ci]`；`uv python uninstall` 仅管理 uv-owned Python；`uv tool uninstall` 管理工具环境 [P7][P8] | cache 可全局/包级/不可达项，R1–R2；managed Python/tool/project env 为安装 R3 | uv 使用 cache lock；`--force` 绕过锁不应自动用。macOS/Linux 默认 clone、Windows hardlink 通常不与 cache 生命周期耦合；symlink 模式清 cache 可破坏环境。`UV_PROJECT_ENVIRONMENT` 可指共享绝对路径。 |
| Poetry | **[事实]** `poetry cache list/clear` 管 repository cache；`poetry env remove [--all]` 只针对当前项目关联环境 [P10][P11] | repository cache 可按 cache 或包版本，R2；`{cache-dir}/virtualenvs` **仍是已安装环境**，R3 | 查 `pyproject.toml`、`poetry.lock`、`env info`、in-project 设置、手工/editable 包与进程。`env list` 不是全机 venv inventory。Poetry 安装自身也须由 pipx/安装器/包管理器所有者移除。 |
| Conda | **[事实]** `conda clean --index-cache/--tarballs/--packages/--all`，支持 `--dry-run --json`；`--force-pkgs-dirs` 不属于 `--all` 且官方警告会破坏 symlink 环境 [P12] | 索引/压缩包 R1–R2；extracted package cache R2–R3；env/base 对象 R3/report-only，未来 remove/clean 动作可为 R4 | 结合 env registry、active `CONDA_PREFIX`、`conda list/export`、pkg/env roots、硬链接/符号链接、writable/shared 状态和其他 shell/Notebook/IDE。`--packages` 不能发现回指 cache 的 symlink。base prefix 不是缓存；多用户可写不等于独占。 |

## 4. Rust：Cargo 与 rustup

### 4.1 三平台位置与发现

**[事实]** 下表为 Cargo/rustup 官方默认和解析接口 [R1][R2][R3][R4]。

| 对象 | Windows | macOS | Linux | 权威发现 |
|---|---|---|---|---|
| Cargo home | `%USERPROFILE%\.cargo` | `$HOME/.cargo` | `$HOME/.cargo` | 先看 `CARGO_HOME`；Cargo home 文档布局 [R1][R2] |
| Cargo build output | workspace `target\`，可由 `CARGO_TARGET_DIR`/配置改变 | workspace `target/`，可改 | 同 macOS | manager 语义查询为 `cargo metadata --format-version 1` 的 `target_directory`/`workspace_root` [R3]；strict no-write 先解析 manifest/config，工具命令按 Z1 管理 |
| rustup home/toolchains | `%USERPROFILE%\.rustup`，可由 `RUSTUP_HOME` 改 | `$HOME/.rustup`，可改 | 同 macOS | `rustup show home`、`toolchain list`、`show active-toolchain`、component/target list [R4] |

**[事实]** Cargo home 混合 registry index/archive/source、Git DB/checkout、已安装 binary 和 rustup proxy；内部结构不承诺稳定。`cargo clean` 仅清所选 workspace/target 的生成物，不清全局 registry/Git cache [R1][R5]。Rust/Cargo 1.88 起有使用跟踪的自动 GC：默认网络可恢复对象未用 3 个月、本地可重建对象未用 1 个月；offline/frozen 等模式跳过，且不涵盖项目 build output [R6][R7]。

**标签作用域：**“官方能力”为 **[事实]**；风险和组合判定为 **[建议]**；无全机引用证明处为 **[边界]**。

| 对象 | 粒度/官方能力 | 引用、活跃、激活、状态与风险 |
|---|---|---|
| `target` | `cargo clean` 可按 package/profile/target 或整个 target，R1–R2 | Z0 读 `Cargo.toml`/lock/config；需要语义图时才在 sandbox 用 `cargo metadata --no-deps --locked --offline`，仍按 Z1 记录潜在写入；再查共享 `CARGO_TARGET_DIR`、IDE/rust-analyzer/构建进程。目录时间不是 workspace 活跃证明。 |
| registry/Git cache | 官方稳定文档支持使用跟踪的自动 GC 及其配置；本文不把未在所引稳定命令页证明的手动全局 GC 语法列为能力，R2 [R6][R7] | Cargo usage tracker 强于文件时间。没有全机项目 registry；扫描会漏掉其他用户、离线盘、容器与 CI。私有 Git/registry 和离线需求提高风险。 |
| `CARGO_HOME/bin` | 已安装 CLI/proxy，R3 | `.crates2.json`、`cargo install --list`、PATH 和运行进程；绝不能随 cache 一起删除。 |
| rustup toolchain/component/target | 官方按 toolchain、component、target 卸载，R3 | 查 default、directory override、`rust-toolchain.toml`、`RUSTUP_TOOLCHAIN`、显式 `+toolchain`、custom linked toolchain 与进程。无全局“未使用”证明。 |

## 5. Go

**[事实]** 下表默认值和查询接口来自 Go 官方文档 [G1][G2][G3]；写“常见”的 GOPATH 位置不是固定保证。**[建议]** 表中的 R 级是本文风险分类。

| 对象 | Windows | macOS | Linux | 权威发现与分类 |
|---|---|---|---|---|
| Go SDK (`GOROOT`) | 官方安装器常为 `C:\Program Files\Go` | 官方包常为 `/usr/local/go` | 官方归档常为 `/usr/local/go`；发行版包可不同 | `go env GOROOT GOVERSION GOTOOLCHAIN`、`go version`；SDK 是安装 R3 [G1][G2] |
| build cache | `%LocalAppData%\go-build` | `~/Library/Caches/go-build` | `$XDG_CACHE_HOME/go-build` 或 `~/.cache/go-build` | `go env GOCACHE`，R1 [G1][G3] |
| module cache | 首个 GOPATH 的 `pkg\mod`，常见 `%USERPROFILE%\go\pkg\mod` | 常见 `~/go/pkg/mod` | 同 macOS | `go env GOMODCACHE GOPATH`，共享下载/源码 R2 [G1] |
| installed binaries/source | `GOBIN` 或首个 GOPATH 的 `bin`；`GOPATH/src` | 同语义 | 同语义 | 已安装工具为 R3/report-only；用户源码为 R3/report-only 或 BLOCKED；未来不可逆移除动作才是 R4；它们都不是 cache |

**[事实]** `go clean -cache` 清 build cache，`-testcache` 使测试结果失效，`-modcache` 清整个 module cache，`-fuzzcache` 清覆盖引导语料；官方说明通常不必手工清 build cache [G1][G4]。Go 1.21+ 自动工具链选择还受 `GOTOOLCHAIN`、`go.mod`/`go.work` 的 `go` 与 `toolchain` 行、PATH 及下载策略影响；下载工具链作为特殊 `golang.org/toolchain` 模块进入 module cache，因此 `-modcache` 也会移除它 [G5]。

**[建议] 多证据：**Z0 先读 `go.mod`/`go.sum`/`go.work`/GOENV；`go env -json GOROOT GOPATH GOBIN GOCACHE GOMODCACHE GOENV GOMOD GOWORK GOTOOLCHAIN GOVERSION` 用于当前上下文。`go list -m all`、`go mod graph/why`、`go work edit -json` 能解释语义引用，但可能解析模块、访问网络或写 cache，属于 Z2；严格 no-write 时不运行，或仅在隔离副本中配合 readonly/offline 策略并审计。**[事实]** `go.sum` 是校验历史而非当前引用清单；Go 官方保证 Go 命令可并发使用 build cache [G1]。**[边界]** Go 无全机项目 registry，module source 时间也不代表实际使用，外部删除不在并发保证内。**[建议]** 活动 `go`/`gopls`/IDE/测试、共享路径、私有模块和离线构建均应阻断；SDK/`GOBIN` 只由其安装器移除。

## 6. Java、Gradle 与 Maven

### 6.1 JDK：安装而不是缓存

**[事实]** 下表为官方安装示例和原生发现入口 [J1]；**[建议]** 发现结果优先于默认路径。

| 平台 | 官方安装示例位置 | 只读发现 | 所有权与移除边界 |
|---|---|---|---|
| Windows | Oracle JDK 常见 `C:\Program Files\Java\jdk-<FEATURE>` | `JAVA_HOME`、`where.exe java`、`java -XshowSettings:properties -version` | 安装器、Installed Apps 或企业软件分发拥有；对象 R3/report-only，未来卸载动作 R4 |
| macOS | Oracle JDK bundle 常见 `/Library/Java/JavaVirtualMachines/jdk-<FEATURE>.jdk/Contents/Home` | `/usr/libexec/java_home -V`、`JAVA_HOME`、实际 `java` 路径 | vendor 安装器/bundle 或包管理器拥有；对象 R3/report-only，未来卸载动作 R4 |
| Linux | Oracle 包示例 `/usr/lib/jvm/jdk-<FEATURE>-oracle-<arch>`；发行版/vendor/归档各异 | `JAVA_HOME`、`readlink -f "$(command -v java)"`、alternatives 与包数据库 | 包管理器或归档所有者负责；对象 R3/report-only，未来卸载动作 R4 |

**[事实]** Java 没有与 npm/pip 类似的统一全局 JDK cache；JDK 是安装工具链，位置依 vendor、架构和安装方式而变 [J1]。**[建议]** 查 Gradle/Maven toolchain、IDE、CI、`JAVA_HOME`、OS alternatives、运行 Java 进程和项目语言级别后，才能讨论按版本卸载。**[边界]** 目录年龄无法覆盖脚本、服务、离线项目或另一个用户的引用。

### 6.2 Gradle

**[事实]** 下表位置和覆盖规则来自 Gradle 的 managed-directories、dependency-cache 与 toolchain 文档 [J2][J3][J4]。

| 对象 | Windows | macOS | Linux | 权威发现/状态 |
|---|---|---|---|---|
| Gradle User Home | `%USERPROFILE%\.gradle` | `~/.gradle` | `~/.gradle` | `GRADLE_USER_HOME`、`--gradle-user-home`；目录布局 [J2] |
| dependency cache | `%GRADLE_USER_HOME%\caches\modules-2` | `$GRADLE_USER_HOME/caches/modules-2` | 同 macOS | Gradle dependency resolution 与 cache locking/cleanup 状态 [J3] |
| version/build cache | `%GRADLE_USER_HOME%\caches\<version>`；本地 build cache 可另配 | 同语义 | 同语义 | build-cache 配置、Gradle version、构建输出 [J2][J5] |
| wrapper/JDK/daemon | `wrapper\dists`、`jdks`、`daemon` | `wrapper/dists`、`jdks`、`daemon` | 同 macOS | wrapper properties、toolchain report/config、daemon status/log [J2][J4][J5] |
| project state/output | `<project>\.gradle`、通常 `<project>\build` | `<project>/.gradle`、通常 `<project>/build` | 同 macOS | project root、settings/build files；输出路径可由构建改变 [J2] |

**[事实]** Gradle User Home 还包含 `gradle.properties`、init scripts、可能的凭据、daemon 状态、wrapper distributions 和自动下载 JDK；不能整目录视为缓存。Gradle 有按类别/版本的周期清理和 configurable retention；依赖缓存用锁协调 Gradle 进程 [J2][J3]。**[推导]** 容器/主机不能可靠共享锁通信时，不应把“Gradle 支持并发”扩展为跨隔离边界安全。

**[建议]** 按以下粒度决策：

- 项目 `build/`：单项目/子项目生成物，R1；先解析自定义 buildDir、任务运行和未归档制品。
- 项目 `.gradle/`：增量历史与配置状态，R1–R2；会造成冷启动，不应在 build/import 中处理。
- dependency/build caches：跨项目共享，R2；要看 Gradle 自身访问/retention、offline/private repository 和锁。
- wrapper distribution：按 Gradle distribution/version，R2；wrapper properties 是直接引用，删除后需按 URL/校验和重下。
- `$GRADLE_USER_HOME/jdks`：Gradle 自动 provision 的 JDK 安装，R3。**[事实]** `./gradlew -q javaToolchains` 可查询 project 检测的 toolchain [J4]；**[边界]** wrapper 可下载 distribution，task 会配置 build、可能启动 daemon/plugin/toolchain resolution，属于 Z2，strict no-write 时只读配置/metadata 并报 state unknown。另查 vendor/arch/languageVersion 约束与 daemon 缓存，只按单 JDK 管理。
- daemon 日志/旧版本状态：R2。**[事实]** `gradle --status` 只列同一 Gradle 版本的 daemon [J5]；**[建议]** 它仍属于 tool invocation，须在允许进程交互的模式使用并结合 OS 进程。活动 daemon 是阻断项；`gradle --stop` 会改变进程状态，属于 M，本研究不执行。

### 6.3 Maven

**[事实]** 下表位置和覆盖规则来自 Maven settings、local repository、toolchains 与 wrapper 文档 [M1][M3]。

| 对象 | Windows | macOS | Linux | 权威发现/覆盖 |
|---|---|---|---|---|
| Maven user dir | `%USERPROFILE%\.m2` | `~/.m2` | `~/.m2` | effective settings、Java `user.home`；wrapper 的 `MAVEN_USER_HOME` 是另一层 [M1][M3] |
| local repository | 默认 `%USERPROFILE%\.m2\repository` | 默认 `~/.m2/repository` | 同 macOS | `<localRepository>` 或 session `maven.repo.local` 可改；用 effective settings 确认 [M1] |
| settings/toolchains | `.m2\settings.xml`、`.m2\toolchains.xml` | `.m2/settings.xml`、`.m2/toolchains.xml` | 同 macOS | 配置、凭据、mirror、proxy、JDK 选择；不是 cache [M1][M3] |
| wrapper distributions | 默认 `.m2\wrapper\dists` | 默认 `.m2/wrapper/dists` | 同 macOS | `.mvn/wrapper/*` 与 `MAVEN_USER_HOME` [M3] |

**[事实]** Maven local repository 同时容纳远端解析制品和 `mvn install` 产生、可能从未发布到远端的本地制品；它不是纯下载缓存。Resolver 管理其内部布局、锁和同步 [M1]。官方 Dependency Plugin 的 `dependency:purge-local-repository` 可按当前项目依赖、include/exclude 与 resolution fuzziness 收窄，并可重新解析 [M2]。

**[建议]** 优先项目范围 purge，而不是删除整个 `.m2/repository`。Z0 读取 `pom.xml`、settings、toolchains、wrapper properties；`help:effective-settings`/dependency tree 依赖 plugin，离线时也可能因 plugin 未缓存而失败，属于 Z2 而非 strict no-write。结合项目活跃、IDE import/`mvn` 进程、私有仓库可用性和本地-only artifact 标记。wrapper distribution 是 R2；local repository 为 R2–R3；Maven/JDK 安装是 R3。**[边界]** Maven 没有全机“所有活跃项目”registry，也无法仅凭坐标目录时间判断制品是否可从远端恢复。

## 7. .NET SDK、runtime 与 NuGet

### 7.1 .NET 安装

**[事实]** 下表是 Microsoft 文档所述的典型安装 root；自包含、包管理器与自定义安装仍必须以实际 host/包数据库为准 [D1][D3]。

| 平台/方式 | 常见 root | 权威只读发现 |
|---|---|---|
| Windows x64/x86 installer | `%ProgramFiles%\dotnet` / `%ProgramFiles(x86)%\dotnet` | `dotnet --info`、`dotnet --list-sdks`、`dotnet --list-runtimes` |
| macOS system installer | `/usr/local/share/dotnet` | 同上；检查架构与实际 host |
| Linux distro package | 常见 `/usr/share/dotnet`，部分发行版用 `/usr/lib/dotnet` | 同上 + 包数据库 |
| `dotnet-install` user install | Windows 默认 `%LocalAppData%\Microsoft\dotnet`；Unix 默认 `$HOME/.dotnet` | `DOTNET_ROOT*`、实际 `dotnet` 路径、安装脚本参数 |

**[事实]** SDK 位于 `<root>/sdk/<version>`、runtime 位于 `<root>/shared/<name>/<version>`；它们是并行安装的工具链而非缓存 [D1][D3]。`dotnet workload list` 只读列出已安装 workloads [D5]。官方卸载应走 Windows/Visual Studio Installer、macOS 支持范围内的 .NET Uninstall Tool、Linux 对应包管理器或原安装方式；Uninstall Tool 仅支持特定 installer-owned 安装，不支持 Linux [D2]。workload orphan packs 可由 `dotnet workload clean` 管理，`--all` 是更宽操作 [D4]。所有卸载能力在本文仅作说明：SDK/runtime 对象为 R3/report-only，未来卸载/clean 动作为 R4。**[建议]** 结合 `global.json`、project target frameworks/runtime identifiers、workload manifests、Visual Studio/CI 与当前/运行进程判断引用。

**[事实]** .NET/MSBuild 项目通常把最终输出写入 `bin/<configuration>/<framework>/`，中间输出写入 `obj/`，但 MSBuild properties 或 centralized artifacts output 可改位置 [D6]。**[建议]** 以 evaluated project/binlog 或实际 build properties 确认后，将项目 `bin`/`obj` 视为 R1–R2；保留未发布的 package、publish output、symbols、signing 产物，活动 build/test/IDE 时拒绝。`dotnet clean` 是项目/configuration 范围的官方 build-output 清理能力，仍只作说明。**[边界]** 没有跨 solution 的全局 output registry。

### 7.2 NuGet 四类本地存储

**[事实]** 下表默认值、覆盖项和 `locals` 粒度来自 NuGet/.NET CLI 官方文档 [U1][U2]。

| Store | Windows 默认 | macOS/Linux 默认 | 官方发现与清理粒度 |
|---|---|---|---|
| global packages | `%USERPROFILE%\.nuget\packages` | `~/.nuget/packages` | `dotnet nuget locals global-packages --list/--clear`；`NUGET_PACKAGES`/config/MSBuild 可改 [U1][U2] |
| HTTP cache | `%LOCALAPPDATA%\NuGet\v3-cache` | `~/.local/share/NuGet/v3-cache` | `locals http-cache --list/--clear`；`NUGET_HTTP_CACHE_PATH` 可改 [U1] |
| temp scratch | `%TEMP%\NuGetScratch` | 通常 `/tmp/NuGetScratch<user>` | `locals temp --list/--clear`；以命令返回为准 [U1][U2] |
| plugins cache | `%LOCALAPPDATA%\NuGet\plugins-cache` | `~/.local/share/NuGet/plugins-cache` | `locals plugins-cache --list/--clear` [U1][U2] |

**[事实]** `dotnet nuget locals all --list` 是解析有效路径的首选；HTTP/temp/plugins 通常可重建，global-packages 则是所有 PackageReference 项目共享的展开包 [U1][U2]。**[建议]** HTTP/temp/plugins 为 R1–R2；global-packages 为 R2–R3，先查 solution/project/lock/assets、配置的 source、private/offline 包、active restore/build/IDE。`packages.config` 项目还可能有 solution/project `packages`，不能与 global-packages 混同。NuGet 配置中的源、凭据、trusted signers 和 source mapping 是配置，不是 cache [U3]。**[边界]** 没有官方全机包到所有项目的 last-use/引用 GC；清 global-packages 后未必能从已下线私有源恢复。

## 8. Ruby、RubyGems 与 Bundler

**[事实]** Ruby runtime、gem home 与 version-manager tree 都依安装方式，而不是 OS 固定路径；RubyGems 官方提供 `gem environment` 查询有效 repository [RB1]。**[建议]** 三平台均以运行时查询为准：

| 平台 | 可靠发现 | 不能硬编码的原因 |
|---|---|---|
| Windows | `where.exe ruby`、`ruby -v`、`gem environment home/path/user_gemhome`、`bundle config list` | RubyInstaller、MSYS2、版本管理器和自定义目录不同 |
| macOS | `command -v ruby`、同一组 `gem environment`/Bundler 查询 | system Ruby、Homebrew、rbenv/RVM/asdf 可并存 |
| Linux | 同 macOS，并结合发行版包数据库 | system package、源码、容器、rbenv/RVM/asdf 可并存 |

**[事实]** 上述查询和 RubyGems repository 布局由官方命令参考定义 [RB1]。`GEM_HOME`/`GEM_PATH` repository 内的 `gems/`、`specifications/`、`extensions/` 是已安装内容；仅 `cache/` 中 `.gem` archive 更接近下载缓存。Bundler 还可能使用项目 `vendor/cache`、用户 `~/.bundle/cache`（可由 `BUNDLE_USER_CACHE` 改）和由 `BUNDLE_PATH` 决定的安装路径 [RB2]。

**标签作用域：**能力与 manager 行为为 **[事实]**；风险和组合判定为 **[建议]**。

| 能力/对象 | 粒度 | 风险与判定 |
|---|---|---|
| `gem cleanup [GEM]` | 当前 `GEM_HOME` 内不再满足依赖所需的旧版本 | R2–R3；先查 installed/default/bundled gems 与 dependency；不会处理所有 `GEM_PATH` [RB1][RB3] |
| `gem uninstall` | package/version | R3；依赖检查仍不能覆盖外部脚本的动态使用 |
| `bundle clean --dry-run` / `bundle clean` | 当前 lockfile 与 configured bundle path | R2–R3；`--force` 对共享/system gems 高危，官方警告可能移除当前 app 以外的 system gems [RB2] |
| `vendor/cache` | 当前项目 archive/Git/path cache | R1–R3；以 `Gemfile.lock` 和 Git 跟踪为证据，可能是 offline/release 资产 |
| Ruby/version-manager tree | 单 runtime/version | 对象 R3/report-only；未来卸载动作 R4；由所有者管理，查 `.ruby-version`、Gemfile Ruby constraint、CI/IDE/default/active/进程 |

**[边界]** RubyGems/Bundler 没有跨项目 liveness registry；lockfile 表示依赖意图而非项目近期活跃。native extension 重建可能依赖已消失的编译器/库。不要在 Ruby/Bundler 安装或从目标树运行时清理。

## 9. PHP 与 Composer

**[事实]** 下表 cache 默认值、子目录和配置查询来自 Composer 官方配置/CLI 文档 [PH1][PH2]；PHP runtime 路径仍依安装方式。

| 对象 | Windows | macOS | Linux | 权威发现 |
|---|---|---|---|---|
| PHP runtime/Composer executable | 安装器、包管理器、开发套件或自定义路径 | Homebrew/installer/custom | distro package/custom/container | `php --ini`、实际 executable、`composer --version`；安装而非 cache |
| Composer cache root | `C:\Users\<user>\AppData\Local\Composer` | `~/Library/Caches/composer` | `$XDG_CACHE_HOME/composer`，否则 `$COMPOSER_HOME/cache` | `composer config --global cache-dir`、`COMPOSER_CACHE_DIR` [PH1] |
| 子缓存 | root 下 `files/`、`repo/`、`vcs/` | 同语义 | 同语义 | `cache-files-dir`、`cache-repo-dir`、`cache-vcs-dir` 配置 [PH1] |
| project install | 项目 `vendor\` | 项目 `vendor/` | 同 macOS | `composer show --installed`、`composer status`、`composer.lock` [PH2] |

**[事实]** `composer clear-cache`/`clearcache` 清全部 Composer cache；Composer 也按 TTL/size 对 dist files 自动 GC。官方显式清理并非跨项目 package-aware 的保留算法 [PH1][PH2]。**[建议]** `files` 为 R2；repo/VCS cache 因 clone 成本、私有源与离线性为 R2–R3。`vendor/` 是已安装依赖 R3，`composer.json/lock`、`auth.json`、配置和 Composer/PHP 本体绝非缓存。清共享 `COMPOSER_CACHE_DIR` 前检查运行进程、其他用户/CI、私有制品可恢复性。**[边界]** 官方没有扫描所有 lockfile 并只留“活跃项目所需 archive”的 GC；文件时间不能替代此缺失信息。

## 10. Dart 与 Flutter

### 10.1 Dart SDK、pub cache 与项目状态

**[事实]** 下表 pub cache 默认值和 `PUB_CACHE` 覆盖来自 Dart 官方文档 [DA1]；SDK 路径取决于 standalone/Flutter/包管理器安装。

| 对象 | Windows | macOS | Linux | 权威发现/分类 |
|---|---|---|---|---|
| Dart SDK | standalone installer、Flutter bundled SDK 或包管理器位置 | 同语义 | 同语义 | `dart --version`、实际 executable、Flutter root；SDK 是 R3 |
| pub cache | `%LOCALAPPDATA%\Pub\Cache`（精确位置可能随 Windows 版本） | `~/.pub-cache` | `~/.pub-cache` | `PUB_CACHE` 覆盖；官方环境变量规则 [DA1] |
| project state | 项目 `.dart_tool\` | 项目 `.dart_tool/` | 同 macOS | `pubspec.yaml`/lock、package config、`dart pub deps` |

**[事实]** `dart pub cache clean` 清整个共享 cache。自 Dart 3.11 起，`repair` 默认只修复当前项目 lockfile 引用的 package，`repair --all` 覆盖整个 cache；同版增加 `cache gc`，根据 pub 记录的“living projects”标记包版本并清不可达版本 [DA2][DA3][DA4]。**[建议]** 先检查 `dart --version` 与本机 `dart pub cache --help`，旧版语义不同。**[推导]** GC 的项目记录明显强于 cache 文件时间，但并不等于用户近期打开：迁移项目、被删除的 `.dart_tool`、旧 SDK、不同 `PUB_CACHE`、容器和从未由兼容 pub 处理的项目都可能漏掉。

**[建议]** 粒度从低到高：project `.dart_tool`（R1–R2）、`cache gc` 不可达版本（R2）、整个 pub cache（R2–R3）、globally activated tools/SDK（安装，R3）。先查 `dart --version`、GC 报告的项目、lockfile、global activations、运行 analyzer/pub/Flutter 和共享 cache。清全 cache 会影响 Dart 与 Flutter、全局工具和离线工作。

### 10.2 Flutter 三层边界

**[事实]** 下表的 SDK、precache、pub cache 与 project clean 边界来自 Flutter CLI、安装及卸载文档 [F1][F2][F3]。**[边界]** Flutter 没有 manager-maintained 的 per-artifact last-used/reclaimable 状态；这些字段应返回 `unknown`，而不是由文件时间推定。

| 层 | 三平台位置/发现 | 官方能力 | 风险 |
|---|---|---|---|
| Flutter SDK | 用户解压/clone 位置，无统一 Windows/macOS/Linux root；Z0 用实际 executable/`FLUTTER_ROOT`；`flutter doctor -v` 为 Z2，可能初始化/填充 SDK cache | release/channel/update/uninstall 由 SDK 管理方式负责 [F1][F2][F3] | 对象 R3/report-only，未来卸载动作 R4；多版本可能被项目/CI pin |
| `$FLUTTER_ROOT/bin/cache` | SDK 内部，含工具/engine artifacts 和 bundled Dart 的关键状态 | `flutter precache` 填充；官方没有稳定的选择性 SDK-cache GC | R3；不要把内部子目录当普通 cache 手删 |
| shared pub cache | 与 Dart 相同 | 见 pub cache | R2–R3，Dart/Flutter 跨项目共享 |
| project output | 项目 `build/`、`.dart_tool/` | `flutter clean` 删除这两类当前项目生成物 [F1] | R1–R2；会触发依赖解析/重建 |

**[建议]** Z0 查 `pubspec.yaml/lock`、Flutter/Dart constraints、FVM/其他版本管理配置、Android/iOS/native 子项目、进程和 Git 状态；只有允许 Z2 时才用 `flutter doctor` 补充 health。Android SDK、Xcode、CocoaPods、签名/keystore 不属于 Flutter cache。**[边界]** 官方公开接口未承诺 `$FLUTTER_ROOT/bin/cache` 各内部目录的独立删除语义；网络/制品不可用时其“可再下载”也不等于可安全恢复。

## 11. Android SDK、Gradle 与 Emulator

**[事实]** Android 开发工具支持 Windows、macOS 和 64-bit Linux；当前安装文档说明 ARM Linux 不受支持 [A1]。Gradle 的跨平台缓存见第 6 节，本节只补 Android 所有权。

| 对象 | Windows | macOS | Linux | 权威发现 |
|---|---|---|---|---|
| Android SDK | 官方 Studio 配置页列出 `%USERPROFILE%\AppData\Local\Android\SDK` | 常见 `~/Library/Android/sdk` 仅作 heuristic | 常见 `~/Android/Sdk` 仅作 heuristic | `ANDROID_HOME`、Studio SDK 设置、项目 `local.properties#sdk.dir`；deprecated `ANDROID_SDK_ROOT` 仅兼容并须一致 [A2][A3] |
| Android user/AVD state | `$ANDROID_USER_HOME` 默认 `$HOME/.android` 语义；AVD 路径可改 | 同语义 | 同语义 | `ANDROID_USER_HOME`、`ANDROID_EMULATOR_HOME`、`ANDROID_AVD_HOME`；`avdmanager list avd` [A2][A5] |
| SDK packages | SDK root 下 platforms/build-tools/system-images/NDK/CMake 等，不能按路径猜所有权 | 同 | 同 | `sdkmanager --list` [A4] |
| Gradle | `%USERPROFILE%\.gradle` 默认 | `~/.gradle` | `~/.gradle` | 见第 6 节；Android project `.gradle`/`build` 另计 |

**[事实] 官方粒度：**`sdkmanager --list`、`avdmanager list avd` 或 `emulator -list-avds` 提供 inventory；实际运行设备可由 `adb devices -l`/IDE device state 辅助确认 [A4][A5][A6][A7]。**[边界]** `sdkmanager --list` 可能访问 repository/刷新 metadata，属于 Z2；strict no-write 时只读 SDK `package.xml`/AVD config 并将 freshness 标 unknown。`sdkmanager --uninstall <package paths>` 按 platform、system image、NDK、CMake、build-tools 或 emulator package；`avdmanager delete avd -n <name>` 按 AVD；Device Manager Wipe Data/`emulator -wipe-data` 只重置一个 AVD 用户数据，保留 definition 和共享 system image [A4][A5][A6]。这些变更命令属于 M，仅作能力说明。

**[建议] 判定：**

- SDK package/NDK/toolchain 为 R3。扫描 `compileSdk`、`buildToolsVersion`、`ndkVersion`、CMake、version catalog、plugin/included build 和 CI/IDE 后仍只能给出“已发现引用”；动态 Gradle 配置使“无引用”不可证明。
- AVD 用户数据、snapshot、app、credential、media 是可能不可恢复状态，对象为 R3/report-only 或 BLOCKED；未来 wipe 动作才是 R4，且 wipe 不是普通 cache clear。查 boot/running 状态，运行中拒绝。
- AVD definition 对象为 R3/report-only；未来 Delete AVD 动作为 R4。system image 为共享 R2–R3，须解析所有 AVD 引用后才可考虑。
- `ANDROID_HOME` 可是多用户共享安装。Studio、`sdkmanager`、`adb`、emulator 或 Gradle 正在写入时拒绝；不要把 Android Studio system/preferences 目录混成 SDK cache。

**[边界]** Android SDK package 没有通用、可靠的 last-used 字段；若无项目引用或运行状态也只能报 `activity=unknown`。Android Studio 的 system/index/log 路径随产品、版本和用户配置变化，属于 IDE 自身状态；本研究不把它纳入 SDK/AVD 清理，必须由 Studio 的诊断/缓存机制单独发现。

## 12. Xcode、Apple SDK 与 Simulator

**[事实]** Xcode 本地平台支持、developer-dir 选择和 component 管理由 Apple 官方资料给出 [X1][X2][X3]；下表对不支持平台显式返回边界。

| 平台 | 支持与位置 | 只读发现 |
|---|---|---|
| Windows | **不支持本地 Xcode/Apple SDK**；远程 Mac 不在本机路径清理范围 | 返回 `unsupported`，不要伪造路径/能力 |
| macOS | 常见 full Xcode `/Applications/Xcode.app/Contents/Developer`；可并存多份；Command Line Tools 是独立安装 | `xcode-select --print-path`、`xcodebuild -version`/`-showsdks`、枚举 `.app`；Xcode Settings → Components/Locations；安装 Xcode 后可由本机 `xcrun simctl help` 确认并用 `simctl list --json` 辅助查询 [X1][X2] |
| Linux | **不支持本地 Xcode/Apple SDK**；远程 Mac 同样超出本机范围 | 返回 `unsupported` |

**[建议]** 三平台同样返回 `supported/reason/remote-boundary`，而不是在 Windows/Linux 悄悄略过。**[事实]** Apple 官方系统需求确认 Xcode 的本地平台边界；部分组件还有硬件限制，例如 visionOS 开发需要 Apple silicon [X3]。

**[事实]** 下表的 component/runtime/device 管理能力来自 Apple 文档；Derived Data 与 archive 的保留判断包含明确建议而非官方“安全删除”保证 [X2][X4][X5]。**[边界]** Apple 当前网页未提供本文可引用的完整 `simctl --json` 命令契约，具体 flags 以所选 Xcode 内置 `simctl help` 为准；因此不把它当作跨版本网络事实。

| 对象 | 官方/受支持粒度 | 风险与证据 |
|---|---|---|
| Optional platform/component/runtime | Xcode Settings → Components 显示安装/启用状态与 recoverable storage，可按组件 Delete/Turn Off [X2] | R2–R3；runtime 被多个 simulator/project 共用；查部署目标、SDK、所有 device 与 boot 状态 |
| Simulator device/data | 按 device 删除；runtime 独立 | 对象 R3/report-only；未来删除 device 动作为 R4。booted device 阻断；删除 device 不释放共享 runtime |
| Derived Data | 配置于 Xcode Settings → Locations；常见 `~/Library/Developer/Xcode/DerivedData` 只是 fallback | R1–R2；project-keyed build/index/log 可重建，但活动 build/index 与共享 custom path 阻断 |
| Archive (`.xcarchive`) | Organizer 管理的用户发布产物，不是 cache | R3/report-only 或 BLOCKED；未来不可逆删除动作才是 R4。它可能是唯一 distributable build、dSYM/符号化材料。项目消失或 archive 旧都不代表可删 |
| Xcode app / Command Line Tools | 完整安装级别 | 对象 R3/report-only，未来卸载动作 R4；查 selected developer dir、其他 IDE/build/CI/CLI consumer；不得作为 cache 回收 |

**[边界]** 当前官方网页对 Components/runtime 删除的支持最强，对 raw Derived Data/archives 和部分 `simctl` 清理的当前文档较弱；因此后者需更高确认等级。Xcode 也不提供通用 per-Derived-Data last-used/reclaimable 保证，缺少 build/index/process 证据时返回 `unknown`。多份 Xcode 可共享用户级 Simulator/Developer 状态，不能把整个 `~/Library/Developer` 归给当前选择版本。

## 13. 容器：Docker、containerd 与 Podman

### 13.1 三平台存储边界

**[事实]** 下表默认值和 VM/backend 边界来自各引擎官方文档；路径配置或产品查询始终优先 [C1][C2][C6][C8][C9]。

| 引擎 | Windows | macOS | Linux | 权威发现 |
|---|---|---|---|---|
| Docker Engine/Desktop | native daemon 常见 `C:\ProgramData\docker`；Desktop WSL disk 文档路径 `%LOCALAPPDATA%\Docker\wsl\data\docker_data.vhdx` | Desktop VM disk 文档路径 `~/Library/Containers/com.docker.docker/Data/vms/0/data/Docker.raw` | Engine 通常 `/var/lib/docker`；Desktop `~/.docker/desktop/vms/0/data/Docker.raw` | daemon `data-root`、Desktop Settings 的 disk image location、`docker info`；Engine 29+ containerd image store 还可能在 `/var/lib/containerd` [C1][C2] |
| containerd | embedding 产品/服务决定；无可靠统一 native 默认 | 常由 VM/embedding 产品决定 | persistent `/var/lib/containerd`，runtime `/run/containerd`，均可配置 | `/etc/containerd/config.toml`、namespace/plugin/snapshotter API [C6][C7] |
| Podman | engine 在 Podman machine Linux VM 内 | 同 Windows | rootful `/var/lib/containers/storage`；rootless `$HOME/.local/share/containers/storage`，均可改 | `podman machine list/inspect`、`podman info --format json` 的 graphRoot/runRoot/volumePath [C8][C9] |

**[推导]** Desktop/Podman machine 的虚拟磁盘是整体后端，不是可逐目录清理的宿主 cache。**[建议]** 只通过引擎对象模型盘点；不得进入 VM disk 或 data root 手工删除。

### 13.2 对象、官方状态与回收边界

**[事实]** 下表 inventory 和 prune/GC 能力来自各引擎官方 CLI/operations 文档 [C3][C4][C5][C6][C7][C8][C10]。

| 引擎 | 只读 inventory | 官方清理能力（仅说明） | 风险/共享与不可判断边界 |
|---|---|---|---|
| Docker | `docker system df -v`；`ps -a --size`；image/container/volume/network inspect/list | image/container/network/volume prune；`system prune`；BuildKit 另见第 14 节 [C3][C4][C5] | layer shared size 不可相加；stopped container 仍引用 image；zero-link volume 也可能是故意保留的 R3/report-only 数据，未来 volume prune 动作为 R4；negative label filter 无法完整 preview。活动 container/build/pull 与 daemon 阻断。 |
| containerd | 先列 namespace，再按 namespace 查 images/containers/tasks/content active/leases/snapshots 与 snapshotter | GC 由 metadata reference、lease 和 scheduler 驱动；Kubernetes/CRI 管理的对象优先由上层所有者处理 [C6][C7] | `ctr` 自称 unsupported debug/admin client；lease、task、image、snapshot parent、GC ref label 强于文件时间。不得删 blob/snapshot/meta.db；外部遍历/监控 root 也曾导致 `EBUSY`/stale handle。 |
| Podman | `podman system df -v`、object list/inspect、`podman info` | `system prune` 可清 unused pod/container/network/dangling image/build cache；`--all`、`--volumes`、`--external`、`--build` 扩围 [C8][C10] | shared layer 使 reclaimable 可能高估；volume 对象为 R3/report-only，未来 prune 动作为 R4；`--build` 官方称 active build 时不安全；additional image store 可是只读共享。 |

**[事实]** Docker 要求每个 daemon 使用独立 data root，不支持以共享目录/NFS 共用 [C1]。**[建议]** 记录 image digest/tag、container state/reference、volume mount/link/label、network attachment、created 与真实运行证据、独占/共享字节、builder/namespace/context。创建时间不是 last-used；引擎报告 `reclaimable` 也必须解释其对象语义。

## 14. 常见构建缓存

### 14.1 BuildKit / Docker buildx

**[事实]** 下表和后续 record/GC 语义来自 BuildKit/buildx 官方文档 [B1][B2][B3]。

| Windows | macOS | Linux | 发现 |
|---|---|---|---|
| Desktop/remote/`docker-container` builder 后端内，宿主路径不稳定 | 同 | standalone rootful 默认 `/var/lib/buildkit`，可由 `buildkitd.toml` 改；其他 driver 仍在后端 | `docker buildx ls` 后对**每个 builder**运行 `docker buildx du --builder NAME`（能力说明） [B1][B2] |

**[事实]** `du` 可报告 record ID/parent/type/description、mutable、shared、usage count、last-used、size、reclaimable；`reclaimable=false` 表示 builder 正持有，即使广泛 prune 也保留。带 shared 标志的 size 可能仍由 image 持有，删 metadata 不一定释放块。官方 `buildx prune` filter **例如** `until/type/description/id/parents` 及 mutable/immutable、in-use/shared/private 状态，并可用 reserved/max-used/min-free-space 做 LRU 容量控制；具体集合应按已装 buildx 帮助核对 [B2][B3]。**[建议]** 风险定为 R2–R3；活动/可变 record、远端 builder、cache mount、external exporter 和并行 build 是阻断或独立所有权。

### 14.2 Bazel

**[事实]** 下表和 output/cache 层次来自 Bazel 官方 output-layout 与 remote-cache 文档 [B4][B5]。

| Windows | macOS | Linux | 权威发现 |
|---|---|---|---|
| output root 从 `%HOME%`/`%USERPROFILE%`/known-folder 推导，XDG 可覆盖 | Bazel 9+ `~/Library/Caches/bazel`；8 及以前曾用 `/private/var/tmp` | `$XDG_CACHE_HOME/bazel` 或 `~/.cache/bazel` | `bazel info output_user_root output_base execution_root output_path`；disk cache 读实际 `--disk_cache` [B4] |

**[事实]** 每个 workspace 的 outputBase 由 workspace 路径 hash，包含 action cache、execroot、输出和 server state；repository/disk cache 与 remote cache 又是不同层。`bazel clean` 清当前 instance/workspace 输出，`--expunge` 清整个 output base；disk cache 的 GC 可按 size/entry age，remote cache 删除由 server 策略负责 [B4][B5]。官方指出 cache entry 由 hash 标识，通常不能可靠归因于某一次 build。**[建议]** 项目 output 为 R1–R2，shared/remote CAS 为 R2–R3；用 Build Event/Profile/cache-hit、workspace 路径、server 活跃与 toolchain/repository 引用补充目录年龄。远端共享清理影响所有用户，且非 hermetic 结果有 cache poisoning 风险。

### 14.3 CMake

**[事实]** CMake 三平台都没有统一全局 artifact cache：每个 binary/build tree 中的 `CMakeCache.txt`、`CMakeFiles/` 和 generator outputs 是配置/构建状态。由 `cmake -S SOURCE -B BUILD` 或 preset `binaryDir` 定位；`cmake -N -L[A][H] BUILD` 可只读查看 cache variables [B6]。`cmake --fresh` 会移除既有 cache/files 后重新配置，`cmake -U` 可移除变量但官方警告可能使 cache 不工作。**[边界]** CMake 没有官方 per-object reclaimable/last-used 状态。**[建议]** 只有确认是独立 out-of-source build tree、source/config 可重建且无活动 native build 时，整 tree 才是 R2；in-source build 混入 authored files，默认 BLOCKED，不能以 R4 审批绕过。

### 14.4 ccache

**[事实]** 下表默认值、覆盖、统计与维护能力来自 ccache 官方手册 [B7]。

| Windows | macOS | Linux | 发现/状态 |
|---|---|---|---|
| legacy `%USERPROFILE%\.ccache`，否则 `%LOCALAPPDATA%\ccache`；旧版也可能 `%APPDATA%` | legacy `~/.ccache`，否则 XDG 或 `~/Library/Caches/ccache` | legacy `~/.ccache`，否则 XDG 或 `~/.cache/ccache` | `ccache -p` 解析 `cache_dir`/`CCACHE_DIR`；`ccache -s -v`，指定路径可 `-d PATH` [B7] |

**[事实]** 官方能力包括按容量/文件数 `--cleanup`、按年龄 `--evict-older-than`、按 namespace、全清，以及相应 dry-run 支持 [B7]。它的近似 LRU 使用 cache-file mtime 且为性能只检查子集，所以即使这里时间有官方语义，也不能泛化为其他工具，更不保证精确 oldest-first。**[建议]** local cache R1–R2；remote/shared backend R2–R3。查 compiler/config/namespace/stats、active compiler/ccache 进程、remote owner 和 filesystem sharing；优先工具能力而非内部文件删除。

### 14.5 sccache

**[事实]** 下表默认值、覆盖与 stats 接口来自 sccache 官方资料 [B8]。

| Windows | macOS | Linux | 发现/状态 |
|---|---|---|---|
| `%LOCALAPPDATA%\Mozilla\sccache` | `~/Library/Caches/Mozilla.sccache` | `~/.cache/sccache` | `SCCACHE_DIR` 覆盖；`sccache --show-stats` 报 hit/miss/write/error [B8] |

**[事实]** local storage 默认有容量管理，但没有稳定的官方 per-project/per-entry 引用/last-use 清单；remote backend 清理由 backend 所有者负责。官方说明 local storage 同时只支持一个 sccache server，并发 server 会竞态/导致构建失败 [B8]。**[建议]** local cache 为 R1–R2，但任何整目录处理都须与 server 协调；活动 server/compiler、共享 `SCCACHE_DIR`、remote backend 阻断。`--stop-server` 会改变运行状态，本文不执行。

### 14.6 Ninja 与 MSBuild/dotnet build 输出

**[事实]** Ninja 没有跨项目全局 cache；它按当前 build graph 管理 outputs，`ninja -t clean` 可按全部或指定 targets 清除生成文件，默认保留被标为 generator 的输出 [B9]。三平台位置均由 `build.ninja` 所在 build directory 决定，没有通用 OS 路径。**[建议]** 用 `ninja -t targets`/graph、生成器元数据、source/build tree 边界和 active Ninja/compiler 进程判定；明确 out-of-source 普通文件可为 R1，闭合目录至少 R2，手写/被生成器错误声明的文件与 in-source tree 为 BLOCKED。**[边界]** Ninja 没有跨项目 last-used/reclaimable registry。

**[事实]** .NET SDK/MSBuild 的 `bin`/`obj`、centralized `artifacts` 路径及 `dotnet clean` 见第 7.1 节 [D6]。Windows、macOS、Linux 的语义相同但 project properties 可完全改写位置。**[建议]** 这类输出是常见构建缓存/产物候选，但 publish/package/symbol/signing output 要从普通中间文件中分离；活动 build/test/IDE 阻断。

## 15. 实现建议：统一输出与操作闸门

### 15.1 候选记录 schema

**[建议]** 三个平台都返回相同字段，unsupported/unknown 也显式返回：

```text
ecosystem, managerVersion, platform, supported, reason
owner, canonicalPath, pathSource, filesystemIdentity, scope
artifactClass, objectId, version, logicalBytes, exclusiveReclaimableBytes
references[], activitySignals[], activationState, officialState
runningBlockers[], sharing[], recoverability, credentials/networkRequirements
confidence(confirmed|inferred|unknown), risk(R1|R2|R3|R4|BLOCKED), supportedAction, actionGranularity
facts[], inferences[], recommendations[], uncertainties[]
```

### 15.2 只读发现顺序

**[建议]** 下列顺序用于产品设计；应同时遵守第 1.3 节 Z0/Z1/Z2 分层：

1. 找 executable/版本与 manager owner；不加载会改变环境的 shell hook，能用原生命令/API 就不用目录猜测。
2. 读取有效配置和环境覆盖，canonicalize 路径，识别 symlink/junction、mount、VM/remote backend、owner/ACL。
3. 用官方 inventory/graph/status 枚举对象和真实 reclaimable 字节；不要把 shared logical size 求和。
4. 在明确的 scan roots 内读 manifest/lock/workspace/toolchain pin/Git tracking；记录覆盖范围，绝不声称“全机无引用”。
5. 只读检查进程、daemon/task/lease/lock/boot 状态；当前 shell 的 inactive 不代表其他 shell/用户 inactive。
6. 验证恢复：锁文件、源、凭据、网络、制品保留、native toolchain、导出/备份。
7. 应用风险闸门并生成建议；默认不执行。每条事实携带 source URL/date，每条推导列依赖事实。

### 15.3 建议级别

**[建议]** 下表是本文的决策策略，不是各工具官方的安全保证：

| 结果 | 条件 | 示例 |
|---|---|---|
| `report-only` | unsupported、unknown owner/path、运行/共享、R3 user/toolchain state、缺恢复证据 | volume、archive、system Python、in-source CMake |
| `eligible-with-confirmation` | 精确、完整、非共享的 filesystem Trash 候选，引用与恢复检查通过 | 已验证的项目输出目录（目录至少 R2）；不是 SDK 卸载或共享 store mutation |
| `low-risk-candidate` | R1 普通文件，精确项目边界、无活动进程、可重建、非共享 | 规则验证的单个生成文件；目录须提升到至少 R2 |
| `manager-gc-candidate` | 管理器有自身 reachability/lease/usage GC，用户接受后果 | pnpm store prune、Cargo auto-GC、Dart pub GC、BuildKit GC |

**[建议]** 即使是 `low-risk-candidate` 也展示 preview、范围、独占字节、冷启动/下载成本和 rollback/rebuild 路径；默认先 dry-run（若工具支持）。没有 dry-run 不得以自制目录删除冒充官方 dry-run。v1 对提权、卸载、强制参数、绕锁、volume/data reset、全局/共享 store mutation 一律不执行，只生成 report 或 `managerPermanentRecommendation`；未来若实现 manager mutation，必须由 first-party adapter 绑定 exact structured scope，进入独立 R4 plan、显式 execution authorization、durable intent、one-shot permit 与 reconciliation。提权即使显式授权也仍被禁止。

## 16. 官方网络来源

以下网络来源均访问于 **2026-08-26**。文中“常见/通常”且未被官方承诺为固定默认的路径已明确标为 heuristic 或要求以工具查询为准。

### Node.js / npm / pnpm / Yarn / nvm

- [N1] Node.js, “Modules: Module compile cache” 与 `process.execPath`: https://nodejs.org/api/module.html#module-compile-cache ; https://nodejs.org/api/process.html#processexecpath
- [N2] npm, “npm-cache”: https://docs.npmjs.com/cli/v11/commands/npm-cache/
- [N3] npm, “Folders”: https://docs.npmjs.com/cli/v12/configuring-npm/folders/
- [N4] npm, `npm ls` / `npm prune` / `npm explain`: https://docs.npmjs.com/cli/v11/commands/npm-ls/ ; https://docs.npmjs.com/cli/v11/commands/npm-prune/ ; https://docs.npmjs.com/cli/v11/commands/npm-explain/
- [N5] pnpm, “pnpm store”: https://pnpm.io/cli/store
- [N6] pnpm, “Settings”: https://pnpm.io/11.x/settings
- [N7] Yarn, Settings / cache clean / caching: https://yarnpkg.com/configuration/yarnrc ; https://yarnpkg.com/cli/cache/clean/ ; https://yarnpkg.com/features/caching
- [N8] Yarn Classic, “yarn cache”: https://classic.yarnpkg.com/en/docs/cli/cache
- [N9] nvm-sh README: https://github.com/nvm-sh/nvm/blob/master/README.md
- [N10] nvm-windows README (commands and installation model): https://github.com/coreybutler/nvm-windows/blob/master/README.md
- [N11] nodejs/corepack official repository, README: https://github.com/nodejs/corepack/blob/main/README.md
- [N12] npm, “npm-cache” (`npm cache npx`) / logging: https://docs.npmjs.com/cli/v11/commands/npm-cache/ ; https://docs.npmjs.com/cli/v11/using-npm/logging/

### Python

- [P1] Python, “Using Python on Windows”: https://docs.python.org/3/using/windows.html
- [P2] Python, “Using Python on macOS”: https://docs.python.org/3/using/mac.html
- [P3] Python, “Using Python on Unix platforms” / `sysconfig`: https://docs.python.org/3/using/unix.html ; https://docs.python.org/3/library/sysconfig.html
- [P4] Python, `venv`: https://docs.python.org/3/library/venv.html
- [P5] pip, “Caching”: https://pip.pypa.io/en/stable/topics/caching/
- [P6] pip, `pip cache` / `pip inspect`: https://pip.pypa.io/en/stable/cli/pip_cache/ ; https://pip.pypa.io/en/stable/cli/pip_inspect/
- [P7] uv, “Caching”: https://docs.astral.sh/uv/concepts/cache/
- [P8] uv, “Storage”: https://docs.astral.sh/uv/reference/storage/
- [P9] uv, “Python versions” / CLI: https://docs.astral.sh/uv/concepts/python-versions/ ; https://docs.astral.sh/uv/reference/cli/
- [P10] Poetry, “Configuration”: https://python-poetry.org/docs/configuration/
- [P11] Poetry, “Managing environments” / CLI: https://python-poetry.org/docs/managing-environments/ ; https://python-poetry.org/docs/cli/
- [P12] Conda, `conda clean`: https://docs.conda.io/projects/conda/en/latest/commands/clean.html
- [P13] Conda, custom env/package locations / multi-user installation: https://docs.conda.io/projects/conda/en/latest/user-guide/configuration/custom-env-and-pkg-locations.html ; https://docs.conda.io/projects/conda/en/latest/user-guide/configuration/admin-multi-user-install.html

### Rust / Go

- [R1] Cargo, “Cargo Home”: https://doc.rust-lang.org/cargo/guide/cargo-home.html
- [R2] Cargo environment variables: https://doc.rust-lang.org/cargo/reference/environment-variables.html
- [R3] `cargo metadata` / `cargo locate-project`: https://doc.rust-lang.org/cargo/commands/cargo-metadata.html ; https://doc.rust-lang.org/cargo/commands/cargo-locate-project.html
- [R4] rustup book, basics/toolchains/overrides: https://rust-lang.github.io/rustup/ ; https://rust-lang.github.io/rustup/basics.html ; https://rust-lang.github.io/rustup/overrides.html
- [R5] `cargo clean`: https://doc.rust-lang.org/cargo/commands/cargo-clean.html
- [R6] Cargo configuration, cache: https://doc.rust-lang.org/cargo/reference/config.html#cache
- [R7] Rust 1.88 announcement: https://blog.rust-lang.org/2025/06/26/Rust-1.88.0/
- [G1] Go command/environment/cache: https://go.dev/cmd/go/
- [G2] Go, “Download and install”: https://go.dev/doc/install
- [G3] Go `os.UserCacheDir`: https://pkg.go.dev/os#UserCacheDir
- [G4] Go `clean`: https://go.dev/cmd/go/#hdr-Remove_object_files_and_cached_files
- [G5] Go toolchains: https://go.dev/doc/toolchain

### Java / Gradle / Maven / .NET / NuGet

- [J1] Oracle, JDK 25 Installation Guide: https://docs.oracle.com/en/java/javase/25/install/installation-guide.pdf
- [J2] Gradle, “Gradle-managed Directories”: https://docs.gradle.org/current/userguide/directory_layout.html
- [J3] Gradle, “Dependency Caching”: https://docs.gradle.org/current/userguide/dependency_caching.html
- [J4] Gradle, “Toolchains for JVM projects”: https://docs.gradle.org/current/userguide/toolchains.html
- [J5] Gradle, daemon/build cache: https://docs.gradle.org/current/userguide/gradle_daemon.html ; https://docs.gradle.org/current/userguide/build_cache.html
- [M1] Maven local repository / Resolver: https://maven.apache.org/repositories/local.html ; https://maven.apache.org/resolver/local-repository.html
- [M2] Maven Dependency Plugin purge: https://maven.apache.org/plugins/maven-dependency-plugin/purge-local-repository-mojo.html
- [M3] Maven settings/toolchains/wrapper: https://maven.apache.org/settings.html ; https://maven.apache.org/guides/mini/guide-using-toolchains.html ; https://maven.apache.org/tools/wrapper/
- [D1] Microsoft, detect installed .NET: https://learn.microsoft.com/en-us/dotnet/core/install/how-to-detect-installed-versions
- [D2] Microsoft, remove .NET / Uninstall Tool: https://learn.microsoft.com/en-us/dotnet/core/install/remove-runtime-sdk-versions ; https://learn.microsoft.com/en-us/dotnet/core/additional-tools/uninstall-tool-overview
- [D3] Microsoft, dotnet-install scripts: https://learn.microsoft.com/en-us/dotnet/core/tools/dotnet-install-script
- [D4] Microsoft, .NET 8 workload clean: https://learn.microsoft.com/en-us/dotnet/core/whats-new/dotnet-8/sdk
- [U1] NuGet, global packages and caches: https://learn.microsoft.com/en-us/nuget/consume-packages/managing-the-global-packages-and-cache-folders
- [U2] `dotnet nuget locals`: https://learn.microsoft.com/en-us/dotnet/core/tools/dotnet-nuget-locals
- [U3] `nuget.config` reference: https://learn.microsoft.com/en-us/nuget/reference/nuget-config-file

### Ruby / PHP / Dart / Flutter / mobile

- [RB1] RubyGems command reference: https://guides.rubygems.org/command-reference/
- [RB2] Bundler `bundle clean` / `bundle cache` / config: https://guides.rubygems.org/command-reference/bundle-clean/ ; https://guides.rubygems.org/command-reference/bundle-cache/ ; https://bundler.io/v4.0/man/bundle-config.1.html
- [RB3] RubyGems default/bundled gems: https://guides.rubygems.org/default-gems-and-bundled-gems/
- [PH1] Composer configuration: https://getcomposer.org/doc/06-config.md
- [PH2] Composer CLI: https://getcomposer.org/doc/03-cli.md
- [DA1] Dart, pub environment variables: https://dart.dev/tools/pub/environment-variables
- [DA2] Dart, `dart pub cache`: https://dart.dev/tools/pub/cmd/pub-cache
- [DA3] Dart 3.11 announcement: https://dart.dev/blog/announcing-dart-3-11
- [DA4] Dart changelog (3.11 pub cache behavior): https://dart.dev/changelog
- [F1] Flutter CLI: https://docs.flutter.dev/reference/flutter-cli
- [F2] Flutter install/archive: https://docs.flutter.dev/install ; https://docs.flutter.dev/install/archive
- [F3] Flutter uninstall: https://docs.flutter.dev/install/uninstall
- [A1] Android Studio install/system requirements: https://developer.android.com/studio/install/
- [A2] Android environment variables: https://developer.android.com/tools/variables
- [A3] Android Studio configuration: https://developer.android.com/studio/intro/studio-config
- [A4] Android `sdkmanager`: https://developer.android.com/tools/sdkmanager
- [A5] Android `avdmanager` / Device Manager: https://developer.android.com/tools/avdmanager ; https://developer.android.com/studio/run/managing-avds
- [A6] Android emulator CLI: https://developer.android.com/studio/run/emulator-commandline
- [A7] Android Debug Bridge (`adb devices`): https://developer.android.com/tools/adb
- [X1] Apple, command-line tools selection: https://developer.apple.com/documentation/xcode/configuring-command-line-tools-settings
- [X2] Apple, additional Xcode components: https://developer.apple.com/documentation/xcode/downloading-and-installing-additional-xcode-components
- [X3] Apple, Xcode SDK/system requirements: https://developer.apple.com/xcode/system-requirements
- [X4] Apple, “Adding additional simulators”: https://developer.apple.com/documentation/safari-developer-tools/adding-additional-simulators
- [X5] Apple, archived “Using the Organizer”: https://developer.apple.com/library/archive/documentation/DeveloperTools/Conceptual/XcodeProjectManagement/140-Using_the_Organizer/using_the_organizer.html

### Containers / build systems

- [C1] Docker daemon configuration: https://docs.docker.com/engine/daemon/
- [C2] Docker Desktop settings / backup paths: https://docs.docker.com/desktop/settings-and-maintenance/settings/ ; https://docs.docker.com/desktop/settings-and-maintenance/backup-and-restore/
- [C3] Docker `system df`: https://docs.docker.com/reference/cli/docker/system/df/
- [C4] Docker prune overview: https://docs.docker.com/engine/manage-resources/pruning/
- [C5] Docker inspect: https://docs.docker.com/reference/cli/docker/inspect/
- [C6] containerd operations: https://containerd.io/docs/main/ops/
- [C7] containerd garbage collection: https://containerd.io/docs/2.2/garbage-collection/
- [C8] Podman `system df` / `info`: https://github.com/containers/podman/blob/main/docs/source/markdown/podman-system-df.1.md ; https://github.com/containers/podman/blob/main/docs/source/markdown/podman-info.1.md
- [C9] Podman installation/machine boundary: https://podman.io/docs/installation
- [C10] Podman `system prune`: https://github.com/containers/podman/blob/main/docs/source/markdown/podman-system-prune.1.md
- [B1] BuildKit configuration: https://docs.docker.com/build/buildkit/toml-configuration
- [B2] Docker buildx `du`: https://docs.docker.com/reference/cli/docker/buildx/du/
- [B3] Docker buildx `prune` / GC: https://docs.docker.com/reference/cli/docker/buildx/prune/ ; https://docs.docker.com/build/cache/garbage-collection/
- [B4] Bazel output directory layout (current page explicitly notes the Bazel 9+ macOS change): https://bazel.build/remote/output-directories
- [B5] Bazel remote caching: https://bazel.build/remote/caching
- [B6] CMake command manual: https://cmake.org/cmake/help/latest/manual/cmake.1.html
- [B7] ccache manual: https://ccache.dev/manual/latest.html
- [B8] sccache local storage / README: https://github.com/mozilla/sccache/blob/main/docs/Local.md ; https://github.com/mozilla/sccache/blob/main/README.md
- [B9] Ninja manual, `clean` tool: https://ninja-build.org/manual

### OS filesystem semantics and .NET build outputs

- [S1] Microsoft Win32, `DeleteFileW`: https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-deletefilew
- [S2] The Open Group POSIX, `unlink`: https://pubs.opengroup.org/onlinepubs/9699919799/functions/unlink.html
- [D5] Microsoft, `dotnet workload list`: https://learn.microsoft.com/en-us/dotnet/core/tools/dotnet-workload-list
- [D6] Microsoft, `dotnet build` / `dotnet clean` / artifacts output layout: https://learn.microsoft.com/en-us/dotnet/core/tools/dotnet-build ; https://learn.microsoft.com/en-us/dotnet/core/tools/dotnet-clean ; https://learn.microsoft.com/en-us/dotnet/core/sdk/artifacts-output

## 17. 研究边界与最终安全声明

**[边界]** 本研究未找到任何一个跨生态通用接口，能证明所有用户、容器、VM、远程 worker、CI、离线卷与已移动项目都不再引用某对象；各工具查询通常只覆盖当前 user/shell/project/backend。

**[推导]** 因此可安全自动化的是“有管理器语义的、范围明确的候选生成”，而不是“按目录名和最后访问时间自动删除”。即便官方称对象 `unused` 或 `reclaimable`，也必须按该工具的精确定义解释：容器 volume 可能仍有业务数据，Conda package cache 可能被 symlink 环境引用，Dart living-project registry 可能覆盖不全，Maven local repository 可能有本地-only artifact。

**[建议]** 产品默认只做只读盘点；v1 将官方清理能力呈现为不可执行的后续建议，并在预览中标明对象、所有者、影响范围、恢复成本、共享者、阻断项、证据覆盖和未知项。只有 first-party、版本化规则证明为非共享、完整、可再生的 project-local output 时，Core 才可用平台 Trash 增加可恢复性，且目录至少 R2；这不是对 manager store 的替代。不得提权、停止进程、切换环境、改配置、清 volume、卸载 SDK，或以文件系统删除替代管理器拥有的同一语义对象。
