# SweepX

**SweepX 是一个安全优先的 Rust 磁盘分析项目。** 当前仓库包含可运行的开发版 CLI/TUI、显式确认的系统回收站预览、Linux 陈旧临时对象的可恢复隔离预览、Linux 有界文件/目录 Permanent preview，以及 P3 的计划、simulation-only 授权、审计恢复与确定性模拟执行库；v0.0.1 开发版本已经发布，但它还不是稳定产品。

> [!CAUTION]
> 当前真实文件变更能力只有三条窄路径：`trash` 单项回收、Linux `/tmp` 陈旧对象异盘隔离，以及 Linux `delete` 有界文件/目录永久删除。`delete` 要求解析后的绝对路径、普通用户、前台终端和完整摘要挑战，先持久化封闭 manifest，再对最多 256 个普通文件/真实目录逐项写 intent、重验并按后序执行 parent-relative `unlinkat`/`rmdir`。链接、特殊文件、跨挂载、超限树、其他平台和 Trash→Permanent fallback 均不支持；Permanent 不是 secure erase。

## 当前实现状态

状态截点：2026-09-12。以下描述来自当前代码与测试，不是稳定性或跨平台资格声明。

| 能力 | 当前状态 | 边界 |
|---|---|---|
| Rust workspace | 源码工作区已收敛为 17 个 crate（2026-10-01） | v0.0.1 与五目标二进制已发布，但尚未作稳定性承诺 |
| `sweepx scan` | **Linux、macOS、Windows：development-grade/degraded** 的同步、只读目录扫描 | 不传路径时扫描当前平台的文件系统根；也可显式给一个或多个绝对根。macOS 使用 handle-bound traversal，Windows 使用 handle-relative traversal |
| `sweepx status` | Linux journal-first 读取 terminal snapshot，并支持对已完成且已持久化的 journal stream 做 degraded 的 `--watch` completed replay；macOS 读取 legacy operation snapshot | Linux `--watch` 只支持 `sweepx --format ndjson status --operation-id ID --watch [--after SXCUR1]` 的 completed-stream replay：先做一次同 snapshot 全量校验，随后按每页最多 1024 条事件续读；unknown 但语法有效的 cursor 返回单独的 `stream.reset_required`；malformed cursor/usage 返回 usage error；它不等待新事件、不创建后台 operation，也不支持 cancel。macOS 仍无 journal replay/watch；Windows 已支持 durable state（默认 `%LOCALAPPDATA%\sweepx\state`，强制 current-user-private DACL 与 owner 校验，并拒绝 reparse point），但尚无 journal replay/watch |
| `sweepx cancel` | 命令存在并诚实返回 disposition | 当前没有 live in-process operation registry，能力为 disabled，不能取消同步扫描 |
| `sweepx explain` | 从有界的绝对路径 `scan.result` JSON 生成解释 | 导入数据会被降级为 stale/incomplete，候选强制 non-executable/report-only |
| `sweepx cache status` | Linux、macOS、Windows：preview cache 只读诊断 | 只支持 `human`/`json`；`--format ndjson` 是 usage error。缺失 state/cache 返回 `absent` + exit 0，且不创建默认或显式 state/cache 目录。检查范围只限 `preview-cache/current.json`、current generation、`generations/` 与 `quarantine/` 的浅层结构、大小与校验健康；不 scan、不 repair、不 quarantine，也不暴露 cache 条目或 path 内容。`available` 只表示缓存结构/校验可读，不代表 live/current 文件事实；warning/error 或 quarantine presence 返回 `degraded` + exit 4 |
| `sweepx cleaner list/show` | 读取内置 Cleaner manifest、规则与兼容性元数据 | 只报告元数据；不执行 Cleaner。版本不兼容时 list 为 partial，show 失败关闭 |
| `sweepx cleaner cargo-detect` | **实验性** live-only Cargo target 只读检测入口 | Scanner 现有有界 locator batch reader，并在三平台 backend 上提供 handle-relative/handle-bound 的有界文件读取路径；workspace 固定输入收集器只读取已 admission 的 `Cargo.toml` 与 `.cargo/config*`。两份 workspace config 现在通过同一个 retained `.cargo` handle、单个有界枚举 cursor 观察，并拒绝 ASCII 大小写 alias/重复项；由于尚无抗 ABA 的目录 generation 证明，该观察仍明确为 non-atomic。`data.hints[].evidence.cargo.configScope` 只记录 workspace pair/config 状态、外部来源状态、环境变量存在性和 redacted declaration metadata，不记录环境变量值，也不公开 workspace config `target-dir` 原文。只有显式设置且为绝对路径的 `CARGO_HOME` 会在 Cleaner compatibility gate 通过后被私下捕获，并在 scan 后重验；随后只观察该 home 根下直属 `config` / `config.toml` 的存在性。命中只投影 `cargoHomeConfig.state=present_redacted`，且该观察仍是 non-atomic；未命中以及未显式设置、使用默认 home 的情况都保持 `not_checked`，不会提升为 `verified_absent`。为验证 presence integrity，scanner 只做有界、no-follow、handle-bound 的 metadata inspection；配置内容不会被读取、解析、使用或序列化，`target-dir` 值也不会被提取，wire evidence 不包含 `CARGO_HOME` 值或 home/config 路径。SweepX 的 `cargo-detect` surface 没有 Cargo passthrough `--target-dir` 或 `--config`，所以该 CLI 入口把 `cli.targetDir` 与 `cli.configOverrides` 记为 `verified_absent`；普通 Core 调用默认保持 `not_checked`，只有显式使用 no-overrides invocation contract 才可作同样声明。process cwd 也仅在 compatibility gate 通过后私下捕获，并记录 capture-time identity；随后只在精确 native path 与重验后的 workspace root identity 都匹配时投影 `path_matches_revalidated_workspace_root`。由于未跨阶段持有 cwd handle，该状态仍保留 `invocation_cwd_identity_not_bound` blocker；cwd path 本身不序列化到 wire contract。Cargo-home ledger 不读取、解析、使用或序列化配置内容来闭合 precedence，ancestor configs 与 workspace pair 也仍未解决；因此 `precedenceComplete=false`，`targetDir` 继续保持 `NotChecked(config_scope_not_checked)`，`targetShape` 继续保持 `Unknown(config_scope_not_checked)`，且 `candidateAllowed`、`planAllowed`、`approvalAllowed`、`executionAllowed` 全部为 `false`。Core 的 `cleaner_cargo_detect_with_cancel(..., &CancellationToken)` 只让调用方协作取消 scan 之后的 fixed-input/evidence collection；同步 scan 使用另一个内部 token。当前 CLI 没有 Ctrl-C、`sweepx cancel` 或 live registry 接线来触发该 token |
| `sweepx scan --tui` | 打开根目录后进入同一进程内的目录浏览，按需扫描详情 | macOS 可查看普通文件和链接详情；权限拒绝、对象变化或身份依据缺失时刷新失败。可导航和查看；`d`/`Delete` 选择移到回收站，退出全屏后再次确认并重验 live identity；不支持 symlink/reparse/root，且没有永久删除降级 |
| `sweepx trash` | **development preview** 的系统回收站入口 | `sweepx trash /absolute/path` 强制交互终端确认，不提供跳过。仅文件/真实目录，保护系统/home/state/Trash 根，提交前重验，失败绝不转永久删除 |
| `sweepx delete` | **Linux-only development preview** 的有界文件/目录永久删除 | `sweepx delete /resolved/absolute/path` 展示 R4 封闭计划并要求精确回输 `PERMANENT 1 <ACTION_COUNT> <FULL_DIGEST>`；每项先写 intent、再重验并以非递归 `unlinkat`/`rmdir` 后序删除。最多 256 actions、深度 64、manifest path bytes 1 MiB；拒绝链接、特殊文件、提权进程、机器输出和非前台终端；不是 secure erase |
| `sweepx junk --system --clean-temp` | **Linux-only development preview** 的陈旧临时对象隔离 | 支持任意名称的目录、普通文件、符号链接、FIFO 和无绑定 Unix socket；名称不是授权依据。先展示完整候选计划，要求精确回输 canonical digest，再逐项重验、复制校验并移动到异盘私有恢复区；不永久删除 |
| `sweepx capabilities` | 报告命令和平台能力状态 | `qualified` 只表示该只读合同在当前测试范围内，不是产品发布资格 |
| P4a.2 qualification records | capability、精确平台 tuple、evidence class 与有效性现在有 typed/validated 记录合同 | 当前主机的 Trash file/directory cell 与 Linux file/directory Permanent 为 `degraded` preview；link 与其他平台 Permanent 仍为 `disabled`，不代表发布资格 |
| P3 libraries | 已实现 immutable plan、simulation-only authorization、Unix audit/recovery 与 deterministic simulation | 仅 library API；Linux 已接入 bounded SQLite event journal，在单个事务中写入完整流与 terminal snapshot，并以 degraded 形式公开 completed-stream `status --watch` replay；events 仍在 scan 完成后批量构造，因此它不是 live sink，也尚未 runtime-qualified。`scan --format ndjson` 继续 disabled；macOS 与 Windows 仍使用 legacy snapshot，均无 replay/watch；P3 计划执行链没有 native target mutation |
| 真实清理 | **Trash + Linux 隔离 + Linux 有界文件/目录 Permanent preview** | `delete` 永久移除一个被完整摘要确认的普通文件或封闭目录树；目录每项独立审计和重验，新出现的项目保留并停止后续动作。link、超限/跨挂载树、通用计划执行和 destructive Agent workflow 仍未实现 |

CLI 和 TUI 支持 `zh-CN` 与 `en-US`。它们会从 locale 环境自动选择语言，也可以用 `--locale zh-CN` 或 `--locale en-US` 显式覆盖；机器输出字段和值保持稳定，不随翻译改变。

库调用扫描与分类只需 `sweepx-core`，不依赖终端浏览器。CLI 在 `tui_adapter` 模块连接 `sweepx-scanner` 和 `sweepx-tui`；身份重验、取消和扫描资源限制继续由 scanner 负责。

## 安装

发布页已提供 v0.0.1 的统一 `sweepx` 二进制。安装器下载与当前平台匹配的归档，校验 `SHA256SUMS`，并拒绝包含额外文件的归档。

Linux / macOS：

```bash
curl --proto '=https' --tlsv1.2 -fsSL \
  https://raw.githubusercontent.com/lejunyang/sweepx/main/install.sh | sh
```

Windows PowerShell：

```powershell
irm https://raw.githubusercontent.com/lejunyang/sweepx/main/install.ps1 | iex
```

也可以从 GitHub Release 下载对应的 `.tar.gz` / `.zip` 与 `SHA256SUMS` 后手工校验。当前构建矩阵包含 Linux x86_64/aarch64、macOS Intel/Apple Silicon 和 Windows x86_64；**二进制存在不等于对应平台的扫描能力已合格**，具体以 `sweepx capabilities` 为准。

### 发布门禁

普通 push/PR 会运行 Rust、schema、站点、安装器和 native CLI CI；`main` 上的文档会独立部署 GitHub Pages。只有 HEAD commit message 包含字面量 `[publish]` 时，才会发布二进制和 crates.io 包。GitHub Release 与 Pages 使用仓库自带的 `GITHUB_TOKEN`；crates.io 需要在受保护的 `crates-io` environment 中配置 `CARGO_REGISTRY_TOKEN`。完整步骤见 [RELEASING.md](RELEASING.md)。

## 运行只读能力

需要仓库声明的 Rust toolchain。下列命令只展示当前存在的接口；请始终使用你明确选择的绝对路径。

```bash
# 查看当前能力矩阵
cargo run -p sweepx-cli -- --locale zh-CN capabilities

# 执行 development-grade/degraded 的只读扫描；默认直接显示有界终端表格
# Linux 可选择 SQLite journal 目录，macOS 可选择 legacy snapshot 目录；Windows 不要传 --state-dir
cargo run -p sweepx-cli -- scan /absolute/path/to/root

# 不传路径时扫描当前平台文件系统根（可能较慢，并受资源上限约束）
cargo run -p sweepx-cli -- scan

# 不需要后续 status/operation state 时关闭状态写入；也适用于 journal 不支持的文件系统
cargo run -p sweepx-cli -- scan --no-state /absolute/path/to/root

# 扫描后进入文件管理器式 TUI（Enter/Right 进入，d/Delete 移到回收站）
cargo run -p sweepx-cli -- scan --tui /absolute/path/to/root

# 显式将一个绝对路径移到系统回收站；默认询问确认
cargo run -p sweepx-cli -- trash /absolute/path/to/item

# Linux：永久删除一个解析后的绝对路径文件或有界目录树；必须在前台终端精确回输挑战
cargo run -p sweepx-cli -- delete "$(realpath -- /path/to/file-or-directory)"

# 仅在脚本或集成需要时显式请求 JSON
cargo run -p sweepx-cli -- \
  --format json scan /absolute/path/to/root > /absolute/path/to/scan.json

# Linux 从 journal、macOS 从 legacy state 读取扫描结束时保存的 snapshot
cargo run -p sweepx-cli -- \
  --format json \
  --state-dir /absolute/path/to/sweepx-state \
  status --operation-id <OPERATION_ID>

# 只读 preview cache 诊断；缺失缓存返回 absent 且不创建目录
cargo run -p sweepx-cli -- \
  --format json \
  --state-dir /absolute/path/to/sweepx-state \
  cache status

# 从有界的导入 JSON 生成 report-only 解释
cargo run -p sweepx-cli -- \
  --format json \
  explain --scan-json /absolute/path/to/scan.json

# 读取内置 Cleaner 元数据
cargo run -p sweepx-cli -- --format json cleaner list
cargo run -p sweepx-cli -- --format json cleaner show <CLEANER_REF>

# 实验性 live-only Cargo target 检测；默认 human 输出列出 target、大小与 report-only 原因
cargo run -p sweepx-cli -- cleaner cargo-detect /absolute/path/to/workspace

# 统一垃圾识别入口：首批覆盖常见项目构建产物，结果只报告不删除
cargo run -p sweepx-cli -- junk ~/Projects
# 实时垃圾视图：Space 选择，r 刷新，c 取消扫描，d/Delete 移到回收站
cargo run -p sweepx-cli -- junk --tui ~/Projects
# 扫描当前平台经过核验的用户缓存根（只报告）
cargo run -p sweepx-cli -- junk --system
# 系统垃圾实时视图：发现与扫描都在后台进行
cargo run -p sweepx-cli -- junk --system --tui
# 分阶段诊断：stderr 输出计时 JSON，stdout 报告格式保持不变
cargo run -p sweepx-cli -- --format json junk --timings ~/Projects
# Linux：生成陈旧临时对象计划，精确确认后复制到异盘恢复区
cargo run -p sweepx-cli -- junk --system --clean-temp

```

规则加载、类型校验与纯评估已合并到 `sweepx-catalog`，分别保留 `schema` / `vm` 模块，减少内部包依赖。 平台契约和三个实现统一到 `sweepx-platform::{linux,macos,windows}`；仅需契约的调用方可不启用后端。

分类扫描的目录行、marker、覆盖信息与可选文件索引共用字节预算。预算紧张时先丢弃可重建索引；若分类证据仍无法保留，报告标记 partial，并在 human 输出说明可能遗漏。内置规则只保留实际需要的项目 marker。

进度日志也有保留上限；仅截断进度不会把完整扫描变成 partial。错误计数、取消和真实资源不足独立保留，现场会话继续收到可靠错误与终态。

Linux 临时对象分析的目录名称、递归身份指纹及进程表读取也有共享预算；超限报告 partial，不能把截断表当作没有引用。core 提供贯穿观察的合作式取消接口，清理仍独立重验，不从报告取得删除权限。

Linux 临时对象的隔离预览与执行已独立为 core 服务，CLI 负责打印和精确确认。预览保留私有原生身份并绑定实际规则字节摘要；交互调用可额外绑定所选行的原测量。每批最多 256 项，默认清理路径累计准入 64 MiB、访问上限 1,000,000、深度 128、复制/核验 I/O 预算 1 TiB、合作期限 15 分钟。取消或超限停止后续工作；源移除开始后可能留下部分源树和完整恢复副本，不承诺原子回滚。这不是 RSS 上限或内核调用的硬超时，TUI 已接入隔离预览与精确确认；Linux 宿主上的完整运行仍待验证。

macOS 垃圾缓存的根记录和文件索引共用一次事件历史验证，收到完整历史后立即结束等待。可用 `junk --timings` 查看实际阶段耗时和命中数；可复现测量与剩余任务见 [设计审视](docs/architecture/design-review-2026-10-01.md)。

`scan --large-files --min-file-bytes 104857600 --top-files 100 ROOT...` 在同一次元数据遍历中输出独立大文件榜单。默认阈值 100 MiB、最多 100 行保留结果；阈值包含等于，排序按逻辑大小降序，分配大小单独显示，未知不当作零。human 大文件表最多显示 40 行，JSON 的 `data.largeFiles` 保留全部 top-K、计数和覆盖缺口；普通扫描列表截断不会漏掉后半段的大文件。只观察普通文件，不读内容、不沿链接越界，也不把大小变成垃圾或删除授权。该选项目前不能与 `scan --tui` 同用；已有垃圾 TUI 保持独立。

`scan --duplicates --min-duplicate-bytes 1024 ROOT...` 显式读取本地普通文件，先按大小及头尾采样筛选，再计算完整 SHA-256 并复验原生身份、大小和变化指纹。硬链接别名排除；采样相同不作为重复证明。默认最多保留 20,000 个对象、扣除 8 GiB 内容范围预算，内容阶段合作期限 30 秒；可用 `--duplicate-max-files`、`--duplicate-read-bytes`、`--duplicate-deadline-ms` 调整。失败读取仍扣预算，云占位/不支持的 provider、变化和资源不足保持明确缺口并返回 partial。JSON 的 `data.duplicates` 保留完整组、计数及不完整原因，human 最多显示 40 个文件路径；未启用时普通 scan 不增加此字段。结果不选择保留者、不证明可丢弃或可回收空间；当前与 `--tui`、`--large-files` 互斥，没有清理操作。

`junk --tui ROOT...` 使用 core 的后台垃圾扫描会话，实时显示阶段、进度和已完整观察子树的基础候选，支持选择、取消和选中刷新。也可使用 `junk --system --tui`，由后台发现保守的系统垃圾根；全量刷新重新发现本次范围，不能同时传显式根。`d/Delete` 将所选当前且覆盖完整的目录候选交给后台回收站操作，逐项原生身份重验；重要/保护目录拒绝，失败保留历史行，不永久删除。该模式要求终端，不能结合 `--timings`、机器输出或其他清理选项。macOS 会先显示历史缓存（系统模式先发现范围），再由本次完整扫描逐项替换；历史行不能回收，刷新历史行会扫描全部根；`R` 可随时在工作线程空闲时刷新全部范围，空视图的 `r` 也会重扫。Linux 临时对象保留独立事实并展示，不能用普通 Trash；Linux 可按 `x` 在后台核验所选临时对象、查看完整隔离计划并精确输入 `clean <完整摘要>` 确认；也保留独立的 `junk --system --clean-temp` 入口。系统 TUI 可用 `--quarantine-dir` 指定异文件系统私有恢复区。计划支持方向键及 PageUp/PageDown 滚动，左右键查看长行；Esc 取消/关闭，执行中的取消等待结果并可能保留部分源与完整恢复副本。确认移动后清除子候选，父目录旧统计标为历史，需刷新后才能再次操作。刷新临时行仍刷新整个系统范围。其他平台继续现场扫描。单个大根中完整子树可在其自身和父目录 marker 枚举完毕后提前展示；Git 解释、完整终态及回收准入仍由后续阶段确认。选中目录刷新只递归所选子树，沿原始身份链浅层枚举祖先所需的规则与 Git 标记，不进入无关兄弟子树；祖先旧统计标为历史，刷新后才能再次操作。局部扫描不覆盖完整根缓存，后续全量扫描仍验证原游标。

项目产物规则由 catalog 统一加载，core 的 `JunkService` 使用现有 cleaner VM 评估扫描事实；CLI 与后续交互界面可共享同一入口。匹配只产生报告候选，不能替代删除前的原生身份重验。

新增 Dart `.dart_tool` 与 SvelteKit 1/2 `.svelte-kit` 的 R3 候选。前者要求父目录普通文件 `pubspec.yaml` 和自身普通文件 `package_config.json`；后者要求父目录 `svelte.config.js` 和自身 `tsconfig.json`、`ambient.d.ts` 两个普通文件。缺失、错位或链接标记不匹配。Dart 会有界读取当前 `package_config.json`；SvelteKit 会读取 JSON 配置和生成声明签名，并复验两个文件的身份、变化指纹和内容。`projectFormat` 显式报告 `recognized` / `invalid` / `unknown` / `not_checked`。SvelteKit 的联合观察非原子，也不证明任意 TypeScript 语法正确。配置内容不持久化，缓存命中与 TUI 刷新都会重新观察。格式或 Git 忽略仍不能证明目录归属和无活动，因此带内容 profile 的两类候选只供展示，`--trash`、TUI 与后台回收均拒绝。源文件、锁文件、自定义输出路径及 SvelteKit 3 新布局不据此纳入。

当显式根中能完整识别 Git 工作区时，`junk` 会通过有界、非交互的 Git 查询给现有
`target`、`node_modules`、Python cache 与常见 build-output 候选补充 ignore/tracked 证据。
只有既命中独立项目规则、又未跟踪且被 ignore、同时没有嵌套仓库或不完整扫描证据的
目录才标记为 `known_generated_ignored` / `high`；ignore 本身不会发现任意候选、降低风险
或授予 Trash 权限，`.env.local` 等本地状态也不会仅因被 ignore 而出现。

`scan` 接受相对路径、`~`、一个或多个绝对根；不传路径时扫描当前平台文件系统根。`scan --no-state` 跳过 operation snapshot/event journal，适合不需要后续 `status`/operation state 或 state filesystem 不支持 journal 的显式只读扫描；它不能与 `--state-dir` 同时使用。默认 `human` 输出最多显示 40 行，按可回收大小降序，并用自动人类单位；`--unit auto|b|kib|mib|gib|tib` 与 `--sort size|path` 可覆盖。`>=` 表示受边界影响的下限，不是精确值；“可回收”是预计可释放的独占分配空间，不等同逻辑大小，也不作释放保证。`json` 始终保留精确字节。`scan --format ndjson` 会在扫描前以 unsupported 拒绝。Linux 已接入 bounded SQLite journal，在单个事务中写入完整事件流与 terminal snapshot；Core 的 `status` 优先读取 journal。Linux 现支持 `sweepx --format ndjson status --operation-id <OPERATION_ID> --watch [--after SXCUR1...]` 的 completed-stream replay。TUI 只做 root admission 就进入界面，单根自动进入；当前层先展示，直接子目录大小随后由后台递归聚合回填，后代不作为 TUI 行长期保留。目录 detail rescan 使用 single-flight 后台任务，deadline 为 30 s，导航或退出不会等待非协作 worker。`explain` 默认最多读取 8 MiB 的导入 JSON。

`cache status` 是独立的只读 preview cache 诊断表面，输出 kind 为 `cache.status.result`。Linux、macOS 与 Windows 都支持 `human`/`json`；`--format ndjson` 在创建或读取任何 state 目录之前就以 usage error 拒绝。若默认或显式 state/cache 缺失，命令返回 `disposition=absent`、exit 0，且不创建 `state_dir`、`preview-cache/`、`current.json` 或其他缓存目录。检查范围只限 `preview-cache/current.json`、当前 generation 文件、`generations/` 与 `quarantine/` 的浅层结构、近似字节数、当前指针健康和 stored-generation schema/checksum/provenance 健康；它不会触发 scan、repair、quarantine 或 cache rebuild，也不会暴露 cache entries、display path 或预览内容。`available` 只表示缓存结构和校验在当前读取范围内可用，不代表 live/current 文件事实。只要存在 warning、error 或 quarantine presence，结果就降为 `degraded` 并以 exit 4 返回。

库集成方可以调用 `sweepx_core::cleaner_cargo_detect_with_cancel` 并持有传入的 `sweepx_core::CancellationToken`。这个 token 的作用域刻意很窄：它只由同步 scan 完成后的 Cargo fixed-input/evidence collection 检查，不拥有也不会中断此前的同步 scan。若收集阶段观察到取消，相关 typed evidence 失败关闭为 `unknown(cancelled)`，terminal envelope 使用 `status=cancelled`、exit 10 和 `reasonCode=cancelled`；已有输出仍只用于 hint/report-only，取消不会授予 candidate、plan、approval、execution 或 mutation authority。

### `status` 与 `cancel` 的诚实语义

当前扫描是同步命令。Linux 上 `status` journal-first 读取扫描结束时写入的 terminal snapshot，并支持 `sweepx --format ndjson status --operation-id <OPERATION_ID> --watch [--after SXCUR1...]` 的 degraded completed-stream replay：它只覆盖已完成且已持久化的 journal stream，先做一次同 snapshot 全量校验，随后按每页最多 1024 条事件续读；unknown 但语法有效的 cursor 返回 `stream.reset_required`，malformed cursor/usage 返回 usage error。它不等待新事件，不创建后台 operation，也不支持 cancel，因此不是 live progress。macOS 与 Windows 都能持久化并读取 legacy operation snapshot，但仍无 replay/watch；Windows state directory 由 current-user-private DACL、owner 校验和逐级 reparse-point 拒绝保护。`cancel` 不伪装成可用能力：对于缺失或已经结束的 operation，它返回明确 disposition，而 capability matrix 将 cancellation 标记为 disabled。Cargo 检测的 caller-owned post-scan token 是独立的 library cooperative-cancellation seam，并未与该命令或 live operation registry 连接；当前 CLI 也没有 Ctrl-C handler 来触发它。

### 导入 JSON 永远不是执行依据

`explain --scan-json` 会接受符合 `scan.result` 合同的有界 JSON。导入时，路径证据会被标记为 stale preview，coverage 被降级为 incomplete/not revalidated，因此解释只能用于报告。它不会创建可执行候选、计划、授权或 permit。`scan --tui` 不走导入路径，而是只读浏览本次 live scan 的 typed 结果。

## Cleaner 概念

Cleaner 不是任意脚本或“目录名匹配后删除”的别名。一个 Cleaner package 描述版本化 manifest、证据、规则和 Core 兼容范围。当前 CLI 只允许：

- `cleaner list`：列出内置 package 及兼容性；
- `cleaner show`：仅在兼容性检查通过后展示 manifest 与规则元数据；
- `cleaner cargo-detect`：实验性、只读；Cleaner 兼容性先于扫描和规则求值检查。当前实现经由 Scanner 的有界 locator batch reader 收集固定输入；workspace 收集器只读取已 admission 的 `Cargo.toml` 与 `.cargo/config*`。两份 workspace config 通过同一个 retained `.cargo` handle 和单个有界枚举 cursor 观察，ASCII 大小写 alias 与重复项失败关闭；由于目录枚举不能排除 ABA，该观察仍是 non-atomic。workspace 证据在 manifest 合法且绑定成立时可为 `known`，同时 `data.hints[].evidence.cargo.configScope` 会输出 `cargo.config-scope.v1`：顶层字段为 `schema`、`decoderId`、`workspace`、`ancestorConfigs`、`cargoHomeConfig`、`environment`、`cli`、`invocationCwd`、`precedenceComplete`、`blockers[]`。其中 `workspace.pairSnapshot` 的状态是 `stable_snapshot|not_checked|failed`，`workspace.config/configToml` 的合同枚举是 `present|verified_absent|not_checked|failed`，但当前生产路径在 pair 非稳定时会把时间点式 absence 降为 `not_checked`；`workspace.selected` 是 `config|config_toml|none|not_checked`，`workspace.targetDirDeclaration` 是 `known|verified_absent|not_checked|unknown`。`environment` 只记录 `CARGO_TARGET_DIR`、`CARGO_BUILD_TARGET_DIR`、`CARGO_HOME` 是否 `present_redacted|verified_absent`；`valueRedacted` 字段始终存在，前者为 `true`、后者为 `false`，从不序列化变量值。workspace config 的 `target-dir` 也只在 `known` 时暴露 `source` 与 `valueRedacted=true`，不输出原始相对路径值。只有显式绝对 `CARGO_HOME` 会在 compatibility gate 通过后被私下捕获并在 scan 后重验；collector 随后只观察 home 根下直属 `config` / `config.toml` 的存在性，命中投影为 `cargoHomeConfig.state=present_redacted`，并且只能对应 `cargo_home_config_present_redacted` blocker。该观察不提供原子 pair/absence 证明：未命中以及未显式设置、使用默认 home 的情况保持 `not_checked`，并且只能对应 `cargo_home_config_not_checked` blocker；失败只对应 `cargo_home_config_failed`。为验证 presence integrity，scanner 只做有界、no-follow、handle-bound 的 metadata inspection；配置内容不会被读取、解析、使用或序列化，`target-dir` 值也不会被提取，ledger 不包含环境值或 home/config 路径。SweepX 的 `cargo-detect` CLI 没有 Cargo passthrough `--target-dir` 或 `--config`，因此 `cli.targetDir` 与 `cli.configOverrides` 当前是结构性 `verified_absent`，而不是 `not_checked`。process cwd 也只在 compatibility gate 通过后私下捕获并记录 capture-time identity；随后只与重验后的 workspace root 比较精确 native path 和 identity。匹配时仅投影 `path_matches_revalidated_workspace_root`，且因未跨阶段持有 cwd handle 而保留 `invocation_cwd_identity_not_bound` blocker；cwd path 本身不进入序列化结果。未观察到的 workspace config 成员仍保持 `not_checked`；没有平台密封的抗 ABA 目录 generation 证明时，不能把联合 presence/absence 提升为稳定选择。Cargo-home presence ledger 不读取、解析、使用或序列化配置内容来闭合 precedence，ancestor configs 与 workspace pair 也仍未解决；因此 `precedenceComplete` 继续为 `false`，`targetDir` 继续是 `not_checked(config_scope_not_checked)`，而依赖它的 `targetShape` 继续是 `unknown(config_scope_not_checked)`。因此 `Cargo.toml` + `target/` 名称目前仍只形成 `hint`，`candidateAllowed`、`planAllowed`、`approvalAllowed`、`executionAllowed` 全部为 `false`；
- Core 另提供 `cleaner_cargo_detect_with_cancel`，由库调用方持有 cancellation token。该 token 只覆盖 scan 之后的 fixed-input/evidence collection；同步 scan 仍独立拥有自己的 token。收集阶段一旦观察到取消便返回 fail-closed 的 cancelled/report-only 结果，而不是继续补全证据或扩大权限；
- 对不兼容、未知版本或证据不足的内容保持 partial、report-only 或失败关闭。

Cargo Cleaner 现在声明 `>=0.1.0, <0.2.0` 并与当前 Core 兼容；Chromium Cleaner 仍要求 `>=1.0.0, <2.0.0`，因此 catalog 仍会诚实报告 partial。Cargo detector 只扫描并输出 report-only 观察，不会调用 `cargo clean` 或获得删除权限。

## 安全模型

已经落地的只读边界与未来 mutation 设计共享以下原则，但只有经过实现和相应测试的部分才是当前能力：

1. **普通用户、只读优先。** 默认扫描不请求 UAC、`sudo`、polkit 或其他提权，并保持 no-follow、边界可见和错误可见。唯一例外是用户显式传入 `--elevate`：它在 Windows 上请求一次 UAC 同意并以提权身份重启进程，用于启用 NTFS 加速扫描路径；不传该参数时永远不会出现提权弹窗。提权只放宽只读加速能力，破坏性操作在提权会话下仍按设计硬拒绝。
2. **观察不等于授权。** Candidate、Explanation、DeletionPlan、ExecutionAuthorization、PreflightPermit、平台结果与审计记录是不同对象。
3. **不确定性不等于零。** `unknown`、`lower_bound`、`unsupported`、`not_checked` 和 `incomplete` 不能渲染成已知 `0` 或“安全”。
4. **导入结果不可执行。** 缓存、历史报告、导入 JSON、文件名或年龄都不能成为 mutation authority。
5. **精确计划绑定。** P3 library model 将授权绑定到 canonical plan digest、模式、对象与动作集合、风险、用户、主机、时效和单次使用状态。
6. **审计先于 mutation。** Linux 文件/目录 Permanent preview 在每个 `unlinkat`/`rmdir` 前持久化 authorization、claim 与独立 intent，并逐项记录 outcome；通用 P3 executor 仍是 deterministic simulation。
7. **没有降级删除。** 未来即使实现 Trash，失败、拒绝、取消或结果不明也不得自动转为 Permanent。
8. **硬保护不可绕过。** 根目录、系统区域、home/profile 根、SweepX state、受保护 anchor 及其包含关系在未来 mutation model 中必须失败关闭。

P3 executor 是 sealed、serial、deterministic 且 simulation-only：请求只携带 ID，identity/revalidation digest 由 canonical plan 派生，不携带 native path；唯一 adapter 是 fake adapter；所谓 simulated Trash/Permanent 只生成可验证 receipt 和审计状态，不调用操作系统删除接口，也不改变扫描目标。当前 audit/recovery 仍仅支持 Unix；Linux durable event journal 已在单个事务中持久化完整流与 terminal snapshot，并提供 journal-first status 与 degraded completed-stream `status --watch` replay。该 replay 只重放已完成且已持久化的 stream，先做一次同 snapshot 全量校验，单次请求按每页最多 1024 条事件续读；unknown 但语法有效的 cursor 返回 `stream.reset_required`，malformed cursor/usage 返回 usage error。由于事件仍在 scan 后批量构造，它不是 live sink，也不等待新事件、不会创建后台 operation，且尚未 runtime-qualified；`scan --format ndjson` 因此继续 disabled。macOS 仍使用 legacy snapshot；Windows 已可持久化 preview cache 与 operation snapshot（explicit private DACL + owner 校验 + reparse-point 拒绝），但仍无 event journal。因此它既不是 future native mutation 的发布级存储，也不能被写成跨平台或真实执行资格。

P4a.2 又把 mutation 资格拆成五个独立 cell：`trash.local.file`、`trash.local.directory`、`permanent.local.file`、`permanent.local.directory` 和 `permanent.local.link`。当前运行平台的两个 Trash cell 以 `degraded` preview 报告，Linux 上 file/directory Permanent 也报告 `degraded`；link 与其他平台 Permanent 仍为 `disabled`。preview 不等于发布资格。`fixture_conformance_only`、`fake`、`stale`、`incomplete`、`placeholder` 或 `mismatched` evidence 永远不能把 mutation 标成 `qualified`；未来也只有 `real_os_qualification`、`validity.status=current` 且完整匹配精确 `QualificationKey` tuple 的 evidence 才可能使对应单元合格。

## Agent 权限边界

当前 Agent 可安全协助的范围仅限：

- 查询 `capabilities`；
- 在用户明确选择的绝对根上发起只读扫描；
- 读取结构化输出并解释边界、错误与不确定性；
- 查看 Cleaner 元数据；
- 打开有界、只读的 TUI 视图。

Agent 不能把聊天中的“可以”变成 HumanApproval，不能构造或消费执行 permit，不能驱动终端挑战，也不得调用 `delete`。当前 CLI 没有通用 `plan`、`approve` 或 `execute` 子命令。

## 未来破坏性接口：仅为提案

下面的命令名只记录路线图方向，**当前二进制不接受这些命令**：

```text
PROPOSED ONLY — NOT IMPLEMENTED — DO NOT RUN
sweepx plan create ...
sweepx plan show ...
sweepx approve ...
sweepx execute ...
sweepx execute ... --dangerously-delete
```

若未来实现，它们仍必须遵守 immutable plan、精确授权、live revalidation、durable intent、reconciliation、硬保护和逐平台资格门槛。Permanent 是独立的 R4 能力，不是 Trash 失败后的 fallback，也不是 secure erase。设计状态流是：

```text
scan -> explain -> immutable plan -> explicit authorization -> live revalidation
     -> platform action -> reconcile -> audit
```

当前已走通只读扫描、TUI 浏览、单对象 `path -> Trash` preview，以及 Linux 文件/目录 `path -> closed immutable plan -> terminal challenge -> per-action durable intent -> postorder unlinkat/rmdir -> outcome`；通用 `scan -> plan -> execute` 与 link Permanent 仍不存在。

## 平台与发布边界

- Linux scanner 已实现为 development-grade/degraded，只能依据当前测试理解，不能据此宣称生产资格或完整文件系统覆盖。
- macOS scanner 现为 handle-bound degraded live scanner，并通过统一 `sweepx scan` / `scan --tui` 接入；这不等于三平台扫描资格完成。
- Windows scanner 现为 development-grade/degraded 的只读 handle-relative live scanner，并通过统一的 `scan` / `scan --tui` 接入；这不等于 Windows 或三平台扫描已取得发布资格。
- Windows NTFS 加速扫描路径已接入为**预览数据源**：资格判定通过时，一次批量元数据读取即产出扫描根的条目数与容量预览（实测 14.5 GB / 36,531 个对象耗时 1.06 s，而完整权威扫描 133 s），但预览标记 `authoritative: false` 且不携带 reopen recipe，不能据以删除任何对象；可移植的 handle-relative 遍历始终权威，加速资格失败只作为观察事件出现，不影响总计精确性。预览输出与独立目录遍历交叉验证，要求路径集合与字节总和完全一致。实测显示 `FSCTL_QUERY_USN_JOURNAL` 需要提权下的 `GENERIC_READ` 卷句柄，低权限句柄即使提权也报告功能不存在，因此未提权时不启用加速是平台属性而非实现缺陷；详见 [原生扫描加速验收矩阵](docs/research/native-scan-qualification.md)。
- P4 的资格化 native Trash beta、P5 的稳定产品，以及 link/跨平台/unbounded Permanent 都仍是未来路线图；当前 Trash 与 Linux 有界文件/目录 Permanent 都只是未取得发布资格的 development preview。
- 已有五目标二进制、校验和、安装器、GitHub Pages 与 crates.io 的发布工作流，v0.0.1 已发布；仍没有签名、SBOM、provenance 或稳定支持承诺。

## 文档导航

- [文档站点](site/index.md)：中文默认入口与英文镜像内容。
- [总体设计](DESIGN.md)：端到端架构、信任边界与关键决策。
- [Cleaner Catalog](docs/CLEANER-CATALOG.md)：生态证据、风险与 report-only 边界。
- [MangoDisk 采用决策](docs/research/mangodisk-adoption.md)：规则来源审计、许可证边界与 Linux 策略。
- [MangoDisk 未纳入规则](docs/research/mangodisk-unadopted-rules.md)：205 条规则的覆盖差距与后续核验批次。
- [Lemon Cleaner 调研结论](docs/research/lemon-cleaner-research.md)：macOS 垃圾扫描类别、GPL 许可证边界与适配要求。
- [垃圾扫描策略收集](docs/research/cleaner-strategy-collection.md)：MangoDisk 与 Lemon Cleaner 的规则结构、分类、防护项和分批落地路线。
- [原生扫描加速验收矩阵](docs/research/native-scan-qualification.md)：可先实现项与 Windows/macOS 真机门槛。
- [路线图](docs/ROADMAP.md)：当前实现快照、阶段目标、测试矩阵与发布门槛。
- [发布指南](RELEASING.md)：版本、提交消息门禁、token、产物与失败恢复。
- [扫描/缓存架构](docs/architecture/scanner-and-cache.md)、[安全删除架构](docs/architecture/safety-and-deletion.md)与[CLI/TUI/Cleaner 架构](docs/architecture/cli-tui-and-plugins.md)。

## 已知缺口

- Linux scan 的性能预算、复杂文件系统语义和故障注入仍需更完整、可复现的验证。
- macOS handle-bound 与 Windows handle-relative 的 degraded live scanner 均已存在，但其资格、覆盖与跨平台一致性仍未完成；Trash preview 的逐平台发布资格、可信本地审批 broker 与完整 preflight/reconciliation 尚未实现。
- Cleaner 签名、更新、撤销、沙箱和外部 query/mutation adapter 尚未达到发布状态。
- P3 plan/simulation authorization、audit/recovery 和 executor 已在 library 层实现；仍没有公共通用执行 CLI、可信 HumanApproval broker 或可扩展 native adapter 接口。
- 对 sparse、compressed、hard link、clone/reflink、snapshot、dedup、overlay、quota 和共享存储的空间归因不能被概括成“将释放多少空间”。

最重要的当前结论是：**SweepX 已有可运行的扫描/TUI、单对象 Trash、Linux 陈旧临时对象隔离和 Linux 有界文件/目录 Permanent preview，但还没有通用计划执行、link Permanent 或跨平台 Permanent。**

macOS 的 `junk` 缓存按批次校验根目录，避免逐根等待 FSEvents；游标在扫描前记录，扫描中发生的修改会触发后续刷新。不完整扫描不保存为可复用的根记录。旧版缓存会自动冷扫重建。

整根候选缓存还绑定本次启用规则与发现范围：切换项目/系统扫描、工具缓存位置变化或浏览器/已知根身份变化时，旧记录失效，现场重新分类。未知发现范围不能接受整根命中。文件长度索引独立校验，分类上下文变化不会单独使它失效。

整根缓存只保存文件系统与规则匹配事实：命中后使用本次工具快照重新计算活动状态，并重新查询当前 Git 仓库、tracked 与 ignore 证据；不会沿用上次 Git 置信度。Gitfile、嵌套仓库、身份/挂载边界、证据不足或查询失败时保留基础置信度及 `blockers[]`。选定根之外的父仓库和排除配置也会本次观察。

`junk --system` 的根发现、分类和工具安装清单共用本次调用的探测快照，扫描结束后不会重新启动一轮探测。整批工具调用预算为 10 秒，单次最多 2 秒、stdout 最多 64 KiB，最多尝试启动 64 个进程；超时、取消、输出过量或工具不可用时保留 unknown，安装信息的缺失字段为 null。显式项目根扫描不探测无关的 npm 安装。

npm 安装发现还共享 4,096 次文件系统观察、64 个安装、4 MiB 累计数据准入估算及单路径/环境值 64 KiB 的上限，文件系统检查也服从本次探测的期限和取消。相同缓存路径的直接子项活动观察只做一次；截断、失败或取消时不把部分最大时间当作完整活动答案。JSON 的 `npmDiscovery.complete` / `incompleteReason` 明确区分发现缺口，报告为 partial（退出码 4），拒绝整根候选缓存复用；已观察的安装和候选仍保留，缺失字段保持 null；显式项目根未请求该发现时，`npmDiscovery` 为 null。

工具缓存根、浏览器和已知缓存位置使用同一本次有界布局发现快照，版本目录展开和分片指纹检查也计入共享预算；分类不再逐候选枚举或解析路径。默认最多 4,096 个目录探测、16,384 条枚举记录、1,024 个规则根引用及 8 MiB 保留估算；5 秒期限和取消在原生调用之间检查，不保证操作系统文件访问具有硬实时期限。权限/观察失败、取消或预算不足时，机器输出的 `layoutDiscovery.complete` 为 false，保留 `incompleteReason`，报告为 partial（退出码 4）；已确认的候选仍可显示，空列表不证明没有垃圾，不持久化本次不完整分类。非交互清理/Trash 请求在发现前拒绝。 工具根的身份及变化指纹绑定本次扫描事实；精确分片数需要完整枚举和 no-follow 目录检查，链接或截断不能建立匹配。活动关系和旧格式提示由本次原生快照解释，不提供删除权；单路径超过 64 KiB 时拒绝布局准入。

根缓存未命中时，目录会重新枚举以重建本次扫描身份和分类标记；文件缓存只复用逻辑长度，缺失的物理分配、硬链接去重及可释放空间保持 unknown。不会通过复用旧候选来跳过整棵子树。

macOS 垃圾缓存的根记录和逐文件索引现在按根独立保存，不再按设备互相覆盖，也不因本次只请求其他根就删除旧缓存。受限缓存按最近读取的根整体淘汰：单文件最多 4 MiB、单根最多 8 MiB、受管文件合计最多 64 MiB、最多 256 个根；每次调用读取的编码数据最多 16 MiB，保留数据采用 128 MiB 估算预算，均不代表进程 RSS 上限。可选文件长度索引会截断，缺失条目现场检查；完整候选记录超限则不写入。缓存超限、旧 schema、身份/请求范围不匹配、链接或非私有存储均回到现场观察；写锁竞争仅放弃本次持久化，不阻塞报告。

macOS 变更历史查询最多接受 256 个绝对 UTF-8 根和 1 MiB 路径字节；应用保留的历史最多 65,536 条事件、16 MiB 估算字节（包括路径及 Vec 容量）。缺口、ID 回绕、挂载变化、无法无损解释的路径或预算耗尽会清空历史并拒绝两层复用。各根现在共享一份按路径去重的变更索引，保留最大事件游标；该索引占用磁盘缓存读取后剩余的 128 MiB 估算额度，自身最多 16 MiB，不再按根复制完整变更集合。这些额度均不是进程 RSS 上限。


项目规则的 JSON `executionPolicy` 只接受 `report_only` 或 `require_ownership_and_activity`；省略时采用后者，不继承旧的删除准入。通用 `dist/build/out/.next/.turbo` 及 Dart/SvelteKit 明确仅报告，Rust/Node/Python/Maven 则仍缺独占所有权和无活动的独立证明，因此当前所有项目候选均不能通过 `junk --trash`、TUI 或后台 worker 回收。名称、风险等级、完整覆盖、格式识别或 Git `ignored/high` 均不能替代这些证明。报告新增稳定 `executionPolicy` 字段，项目值为 `report_only` 或 `require_project_ownership_and_activity`；缓存恢复先为 `not_checked`，按本次规则重建，不保存旧准入。平台候选的 `native_revalidation_required` 仍须通过既有原生身份、覆盖与平台边界检查，并不自行提供执行权限。独立 `trash PATH` 的明确路径操作仍遵守其原有检查。

SvelteKit 1.0.0/2.0.0 的格式回归现包含实际 SDK `sync` 生成的原始文件、依赖锁及字节校验记录，普通测试离线消费；目录混入用户文件时依旧只报告。采集方式和证据边界见[项目规则执行样本](docs/development/project-rule-corpus.md)。

Dart 2.18.0/3.6.0 已加入真实 SDK 单项目与共享 workspace 的生成样本。格式识别支持其中中文/空格文件名的百分号 UTF-8 路径签名，继续拒绝无效编码、控制字符及编码后的路径分隔符等不支持形式；不求解完整 URI 语义或打开 URI。共享根配置和混入个人文件的目录仍只报告，缺少 package map 的成员笔记目录不据此识别为垃圾。

Rust target 候选现通过捕获的原生身份链读取父目录 `Cargo.toml`，在 CLI/TUI 中展示当前 package/workspace、成员模式数量、显式 workspace 路径及路径依赖声明。JSON 新增 `projectContext`，状态为 `observed` / `invalid` / `unknown` / `not_checked`；`memberPatterns` 是声明字符串数量，不能当作实际成员数量。还会观察该父目录下 `.cargo/config` 和 `.cargo/config.toml`，在 `cargoConfig` 中分别展示受支持的 `target-dir` 声明；路径值不保留，不打开声明路径。枚举中未见配置保持 unknown，联合观察为 `non_atomic`、`precedenceComplete=false`，不能据此选择实际生效文件或输出目录。不会执行 Cargo、展开 glob 或解析完整配置优先级。上下文与格式共用有界观察预算，缓存不保存声明答案，每次调用或刷新重新读取；这些声明不能证明独占所有权或无活动，项目回收限制继续保留。
