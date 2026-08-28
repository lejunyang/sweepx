# SweepX

**SweepX 是一个安全优先的 Rust 磁盘分析项目。** 当前仓库已经包含可运行的开发版只读 CLI/TUI，以及 P3 的计划、simulation-only 授权、审计恢复与确定性模拟执行库；它还不是已发布产品，也没有任何真实清理、回收站或永久删除能力。

> [!CAUTION]
> 当前可运行能力全部是只读或模拟能力。仓库没有 `plan`、`approve`、`execute` CLI，没有 native Trash/Permanent adapter，也没有会移动或删除目标文件的路径。P3 模拟执行器不接收 native path，并且只允许 sealed deterministic fake adapter。请勿把设计文档中的未来命令当成现有接口。

## 当前实现状态

状态截点：2026-08-28。以下描述来自当前代码与测试，不是发布或跨平台资格声明。

| 能力 | 当前状态 | 边界 |
|---|---|---|
| Rust workspace | 可构建、可打包的 21 crate 工作区 | 已有发布自动化，但尚未发布稳定版本或作稳定性承诺 |
| `sweepx scan` | **Linux、macOS、Windows：development-grade/degraded** 的同步、只读目录扫描 | macOS 使用 handle-bound traversal，Windows 使用 handle-relative traversal；三者均通过 `sweepx scan` / `sweepx scan --tui` 暴露，但都不代表发布资格 |
| `sweepx status` | Linux journal-first 读取 terminal snapshot，并支持对已完成且已持久化的 journal stream 做 degraded 的 `--watch` completed replay；macOS 读取 legacy operation snapshot | Linux `--watch` 只支持 `sweepx --format ndjson status --operation-id ID --watch [--after SXCUR1]` 的 completed-stream replay：先做一次同 snapshot 全量校验，随后按每页最多 1024 条事件续读；unknown 但语法有效的 cursor 返回单独的 `stream.reset_required`；malformed cursor/usage 返回 usage error；它不等待新事件、不创建后台 operation，也不支持 cancel。macOS 仍无 journal replay/watch；Windows durable state 禁用、默认 `state_dir=None`，且显式 `--state-dir` fail-closed |
| `sweepx cancel` | 命令存在并诚实返回 disposition | 当前没有 live in-process operation registry，能力为 disabled，不能取消同步扫描 |
| `sweepx explain` | 从有界的绝对路径 `scan.result` JSON 生成解释 | 导入数据会被降级为 stale/incomplete，候选强制 non-executable/report-only |
| `sweepx cleaner list/show` | 读取内置 Cleaner manifest、规则与兼容性元数据 | 只报告元数据；不执行 Cleaner。版本不兼容时 list 为 partial，show 失败关闭 |
| `sweepx cleaner cargo-detect` | **实验性** live-only Cargo target 只读检测入口 | Scanner 现有有界 locator batch reader，并在三平台 backend 上提供 handle-relative/handle-bound 的有界文件读取路径；Cargo 固定输入收集器只读取已 admission 的 `Cargo.toml` 与 `.cargo/config*`。当 workspace 证据成立时可投影为 `Known`，但 `targetDir` 仍因全局 override scope 未解而保持 `NotChecked`，`targetShape` 因依赖该前提而保持 `Unknown`；结果继续只产生 hint/report-only，不会产生 candidate、计划、授权或执行 |
| `sweepx scan --tui` | 扫描后进入同一进程内的文件管理器式目录浏览 | 仅查看与导航，不产生计划、授权或文件变更；detail rescan 为 single-flight 后台任务，2 s deadline，导航与退出不等待非协作 worker，late result 会丢弃，且有 process-wide 32 stuck-worker cap |
| `sweepx capabilities` | 报告命令和平台能力状态 | `qualified` 只表示该只读合同在当前测试范围内，不是产品发布资格 |
| P4a.2 qualification records | capability、精确平台 tuple、evidence class 与有效性现在有 typed/validated 记录合同 | 这是失败关闭的 registry substrate，不是运行时 registry 服务；所有 mutation cell 在 Linux、macOS、Windows 上仍为 `disabled` |
| P3 libraries | 已实现 immutable plan、simulation-only authorization、Unix audit/recovery 与 deterministic simulation | 仅 library API；Linux 已接入 bounded SQLite event journal，在单个事务中写入完整流与 terminal snapshot，并以 degraded 形式公开 completed-stream `status --watch` replay；events 仍在 scan 完成后批量构造，因此它不是 live sink，也尚未 runtime-qualified。`scan --format ndjson` 继续 disabled；macOS 仍是 legacy snapshot；Windows durable state 仍 disabled；没有 native target mutation |
| 真实清理 | **不可用** | Trash、Permanent、管理器 mutation 与 destructive Agent workflow 均未实现 |

CLI 和 TUI 支持 `zh-CN` 与 `en-US`。它们会从 locale 环境自动选择语言，也可以用 `--locale zh-CN` 或 `--locale en-US` 显式覆盖；机器输出字段和值保持稳定，不随翻译改变。

## 安装

发布页会提供一个统一的 `sweepx` 二进制。安装器下载与当前平台匹配的归档，校验 `SHA256SUMS`，并拒绝包含额外文件的归档。

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

# 不需要后续 status/operation state 时关闭状态写入；也适用于 journal 不支持的文件系统
cargo run -p sweepx-cli -- scan --no-state /absolute/path/to/root

# 扫描后进入文件管理器式 TUI（Enter/Right 进入，Esc/Backspace/Left 返回）
cargo run -p sweepx-cli -- scan --tui /absolute/path/to/root

# 仅在脚本或集成需要时显式请求 JSON
cargo run -p sweepx-cli -- \
  --format json scan /absolute/path/to/root > /absolute/path/to/scan.json

# Linux 从 journal、macOS 从 legacy state 读取扫描结束时保存的 snapshot
cargo run -p sweepx-cli -- \
  --format json \
  --state-dir /absolute/path/to/sweepx-state \
  status --operation-id <OPERATION_ID>

# 从有界的导入 JSON 生成 report-only 解释
cargo run -p sweepx-cli -- \
  --format json \
  explain --scan-json /absolute/path/to/scan.json

# 读取内置 Cleaner 元数据
cargo run -p sweepx-cli -- --format json cleaner list
cargo run -p sweepx-cli -- --format json cleaner show <CLEANER_REF>

# 实验性 live-only Cargo target 检测；当前内置 manifest 与 Core 不兼容，会在扫描前以 exit 12 失败关闭
cargo run -p sweepx-cli -- --format json cleaner cargo-detect /absolute/path/to/workspace

```

`scan` 接受一个或多个绝对根路径。`scan --no-state` 跳过 operation snapshot/event journal，适合不需要后续 `status`/operation state 或 state filesystem 不支持 journal 的显式只读扫描；它不能与 `--state-dir` 同时使用。默认 `human` 输出最多显示 40 行，并对文件名中的终端控制字符做安全替换；`json` 是当前 scan 的机器格式。`scan --format ndjson` 会在扫描前以 unsupported 拒绝。Linux 已接入 bounded SQLite journal，在单个事务中写入完整事件流与 terminal snapshot；Core 的 `status` 优先读取 journal。Linux 现支持 `sweepx --format ndjson status --operation-id <OPERATION_ID> --watch [--after SXCUR1...]` 的 completed-stream replay：它只重放已完成且已持久化的 journal stream，先做一次同 snapshot 全量校验，再在单次请求中按每页最多 1024 条事件续读；unknown 但语法有效的 cursor 返回单独的 `stream.reset_required` control event，malformed cursor/usage 返回 usage error。该 replay 不等待新事件，不创建后台 operation，也不支持 cancel。事件仍在 scan 完成后批量构造，因此这不是 live streaming，且尚未 runtime-qualified，所以 `scan --format ndjson` 继续 disabled。macOS 保留 legacy operation snapshot，没有 SQLite journal/replay；Windows durable state 继续 disabled。`--tui` 不能与机器格式组合，也不会要求或生成中间 JSON。当前 TUI 展示扫描结果中的虚拟根和直接子项，支持进入/返回目录、移动选择与退出；symlink/reparse 项不会被进入；目录 detail rescan 使用 single-flight 后台任务，deadline 为 2 s，导航或退出不会等待非协作 worker，超时后的 late result 会被丢弃，并由 process-wide 32 stuck-worker cap 防止无限泄漏。`explain` 默认最多读取 8 MiB 的导入 JSON，这个上限用于拒绝过大的报告，而不是放宽执行权限。

### `status` 与 `cancel` 的诚实语义

当前扫描是同步命令。Linux 上 `status` journal-first 读取扫描结束时写入的 terminal snapshot，并支持 `sweepx --format ndjson status --operation-id <OPERATION_ID> --watch [--after SXCUR1...]` 的 degraded completed-stream replay：它只覆盖已完成且已持久化的 journal stream，先做一次同 snapshot 全量校验，随后按每页最多 1024 条事件续读；unknown 但语法有效的 cursor 返回 `stream.reset_required`，malformed cursor/usage 返回 usage error。它不等待新事件，不创建后台 operation，也不支持 cancel，因此不是 live progress。macOS 读取 legacy operation snapshot，仍无 replay/watch；Windows durable snapshot state 完全禁用：默认 `state_dir=None`，不写 terminal snapshot，显式 `--state-dir` 失败关闭。`cancel` 不伪装成可用能力：对于缺失或已经结束的 operation，它返回明确 disposition，而 capability matrix 将 cancellation 标记为 disabled。

### 导入 JSON 永远不是执行依据

`explain --scan-json` 会接受符合 `scan.result` 合同的有界 JSON。导入时，路径证据会被标记为 stale preview，coverage 被降级为 incomplete/not revalidated，因此解释只能用于报告。它不会创建可执行候选、计划、授权或 permit。`scan --tui` 不走导入路径，而是只读浏览本次 live scan 的 typed 结果。

## Cleaner 概念

Cleaner 不是任意脚本或“目录名匹配后删除”的别名。一个 Cleaner package 描述版本化 manifest、证据、规则和 Core 兼容范围。当前 CLI 只允许：

- `cleaner list`：列出内置 package 及兼容性；
- `cleaner show`：仅在兼容性检查通过后展示 manifest 与规则元数据；
- `cleaner cargo-detect`：实验性、只读；Cleaner 兼容性先于扫描和规则求值检查。当前实现经由 Scanner 的有界 locator batch reader 收集固定输入，只读取已 admission 的 `Cargo.toml` 与 `.cargo/config*`。workspace 证据在 manifest 合法且绑定成立时可为 `known`，但由于 home/env/ancestor/CLI 等全局 override scope 仍未解决，`targetDir` 继续是 `not_checked(config_scope_not_checked)`，而依赖它的 `targetShape` 继续是 `unknown(config_scope_not_checked)`；因此 `Cargo.toml` + `target/` 名称目前仍只形成 `hint`，不会产生 candidate、计划、授权或执行；
- 对不兼容、未知版本或证据不足的内容保持 partial、report-only 或失败关闭。

当前 `0.1.0` Core 与仓库内要求 `>=1.0.0, <2.0.0` 的内置 Cleaner 不兼容，这是刻意可见的兼容性门，而不是可绕过的错误。没有 Cleaner 执行接口，也不会调用包管理器、浏览器或其他外部清理命令。

## 安全模型

已经落地的只读边界与未来 mutation 设计共享以下原则，但只有经过实现和相应测试的部分才是当前能力：

1. **普通用户、只读优先。** 当前扫描不请求 UAC、`sudo`、polkit 或其他提权，并保持 no-follow、边界可见和错误可见。
2. **观察不等于授权。** Candidate、Explanation、DeletionPlan、ExecutionAuthorization、PreflightPermit、平台结果与审计记录是不同对象。
3. **不确定性不等于零。** `unknown`、`lower_bound`、`unsupported`、`not_checked` 和 `incomplete` 不能渲染成已知 `0` 或“安全”。
4. **导入结果不可执行。** 缓存、历史报告、导入 JSON、文件名或年龄都不能成为 mutation authority。
5. **精确计划绑定。** P3 library model 将授权绑定到 canonical plan digest、模式、对象与动作集合、风险、用户、主机、时效和单次使用状态。
6. **审计先于模拟结果。** durable audit model 记录 intent、fence、outcome 与 reconciliation；它目前服务 deterministic simulation，不证明 native adapter 已安全。
7. **没有降级删除。** 未来即使实现 Trash，失败、拒绝、取消或结果不明也不得自动转为 Permanent。
8. **硬保护不可绕过。** 根目录、系统区域、home/profile 根、SweepX state、受保护 anchor 及其包含关系在未来 mutation model 中必须失败关闭。

P3 executor 是 sealed、serial、deterministic 且 simulation-only：请求只携带 ID，identity/revalidation digest 由 canonical plan 派生，不携带 native path；唯一 adapter 是 fake adapter；所谓 simulated Trash/Permanent 只生成可验证 receipt 和审计状态，不调用操作系统删除接口，也不改变扫描目标。当前 audit/recovery 仍仅支持 Unix；Linux durable event journal 已在单个事务中持久化完整流与 terminal snapshot，并提供 journal-first status 与 degraded completed-stream `status --watch` replay。该 replay 只重放已完成且已持久化的 stream，先做一次同 snapshot 全量校验，单次请求按每页最多 1024 条事件续读；unknown 但语法有效的 cursor 返回 `stream.reset_required`，malformed cursor/usage 返回 usage error。由于事件仍在 scan 后批量构造，它不是 live sink，也不等待新事件、不会创建后台 operation，且尚未 runtime-qualified；`scan --format ndjson` 因此继续 disabled。macOS 仍使用 legacy snapshot，Windows durable state 仍禁用。因此它既不是 future native mutation 的发布级存储，也不能被写成跨平台或真实执行资格。

P4a.2 又把 mutation 资格拆成五个独立 cell：`trash.local.file`、`trash.local.directory`、`permanent.local.file`、`permanent.local.directory` 和 `permanent.local.link`。当前它们在 Linux、macOS、Windows 上全部为 `disabled`。`fixture_conformance_only`、`fake`、`stale`、`incomplete`、`placeholder` 或 `mismatched` evidence 永远不能把 mutation 标成 `qualified`；未来也只有 `real_os_qualification`、`validity.status=current` 且完整匹配精确 `QualificationKey` tuple 的 evidence 才可能使对应单元合格。当前没有这样的合格记录，也没有 native adapter、mutation command 或 approval UI。

## Agent 权限边界

当前 Agent 可安全协助的范围仅限：

- 查询 `capabilities`；
- 在用户明确选择的绝对根上发起只读扫描；
- 读取结构化输出并解释边界、错误与不确定性；
- 查看 Cleaner 元数据；
- 打开有界、只读的 TUI 视图。

Agent 不能把聊天中的“可以”变成 HumanApproval，不能构造或消费执行 permit，不能调用未来的 approval UI，也不能调用任何危险删除开关。当前 CLI 根本没有 `plan`、`approve` 或 `execute` 子命令。

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

当前只走到只读 CLI/TUI，以及 library-only 的模拟状态；不存在 `scan -> execute` 或 `path -> delete` 路径。

## 平台与发布边界

- Linux scanner 已实现为 development-grade/degraded，只能依据当前测试理解，不能据此宣称生产资格或完整文件系统覆盖。
- macOS scanner 现为 handle-bound degraded live scanner，并通过统一 `sweepx scan` / `scan --tui` 接入；这不等于三平台扫描资格完成。
- Windows scanner 现为 development-grade/degraded 的只读 handle-relative live scanner，并通过统一的 `scan` / `scan --tui` 接入；这不等于 Windows 或三平台扫描已取得发布资格。
- P4 的 native Trash beta、P5 的稳定产品和任何 Permanent 能力都仍是未来路线图。
- 已有五目标二进制、校验和、安装器、GitHub Pages 与 crates.io 的发布工作流；尚未实际发布稳定版本，也没有签名、SBOM、provenance 或稳定支持承诺。

## 文档导航

- [文档站点](site/index.md)：中文默认入口与英文镜像内容。
- [总体设计](DESIGN.md)：端到端架构、信任边界与关键决策。
- [Cleaner Catalog](docs/CLEANER-CATALOG.md)：生态证据、风险与 report-only 边界。
- [路线图](docs/ROADMAP.md)：当前实现快照、阶段目标、测试矩阵与发布门槛。
- [发布指南](RELEASING.md)：版本、提交消息门禁、token、产物与失败恢复。
- [扫描/缓存架构](docs/architecture/scanner-and-cache.md)、[安全删除架构](docs/architecture/safety-and-deletion.md)与[CLI/TUI/Cleaner 架构](docs/architecture/cli-tui-and-plugins.md)。

## 已知缺口

- Linux scan 的性能预算、复杂文件系统语义和故障注入仍需更完整、可复现的验证。
- macOS handle-bound 与 Windows handle-relative 的 degraded live scanner 均已存在，但其资格、覆盖与跨平台一致性仍未完成；三平台 native Trash、可信本地审批 broker 与真实 preflight revalidation 尚未实现。
- Cleaner 签名、更新、撤销、沙箱和外部 query/mutation adapter 尚未达到发布状态。
- P3 plan/simulation authorization、audit/recovery 和 executor 已在 library 层实现；仍没有公共 CLI 合同、可信 HumanApproval broker 或 native adapter。
- 对 sparse、compressed、hard link、clone/reflink、snapshot、dedup、overlay、quota 和共享存储的空间归因不能被概括成“将释放多少空间”。

最重要的当前结论是：**SweepX 已有可运行的只读开发能力，但没有可运行的清理能力。**
