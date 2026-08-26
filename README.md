# SweepX

**SweepX 是一个安全优先的 Rust 磁盘分析项目。** 当前仓库已经包含可运行的开发版只读 CLI/TUI，以及 P3 的计划、simulation-only 授权、审计恢复与确定性模拟执行库；它还不是已发布产品，也没有任何真实清理、回收站或永久删除能力。

> [!CAUTION]
> 当前可运行能力全部是只读或模拟能力。仓库没有 `plan`、`approve`、`execute` CLI，没有 native Trash/Permanent adapter，也没有会移动或删除目标文件的路径。P3 模拟执行器不接收 native path，并且只允许 sealed deterministic fake adapter。请勿把设计文档中的未来命令当成现有接口。

## 当前实现状态

状态截点：2026-08-26。以下描述来自当前代码与测试，不是发布或跨平台资格声明。

| 能力 | 当前状态 | 边界 |
|---|---|---|
| Rust workspace | 可构建的多 crate 工作区 | 开发版，未提供安装包或稳定性承诺 |
| `sweepx scan` | **Linux：degraded** 的同步、只读目录扫描 | macOS/Windows 目前只编译 stub，扫描返回 unsupported；未完成三平台发布资格 |
| `sweepx status` | 读取已持久化的 operation snapshot | 不是后台任务监控，也不表示扫描仍在运行 |
| `sweepx cancel` | 命令存在并诚实返回 disposition | 当前没有 live in-process operation registry，能力为 disabled，不能取消同步扫描 |
| `sweepx explain` | 从有界的绝对路径 `scan.result` JSON 生成解释 | 导入数据会被降级为 stale/incomplete，候选强制 non-executable/report-only |
| `sweepx cleaner list/show` | 读取内置 Cleaner manifest、规则与兼容性元数据 | 只报告元数据；不执行 Cleaner。版本不兼容时 list 为 partial，show 失败关闭 |
| `sweepx tui` / `sweepx-tui` | 校验或浏览有界的 `scan.result` JSON | 仅查看与导航，不产生计划、授权或文件变更 |
| `sweepx capabilities` | 报告命令和平台能力状态 | `qualified` 只表示该只读合同在当前测试范围内，不是产品发布资格 |
| P3 libraries | 已实现 immutable plan、simulation-only authorization、Unix audit/recovery 与 deterministic simulation | 仅 library API；不是阶段资格声明，没有 CLI 接线或 native target mutation |
| 真实清理 | **不可用** | Trash、Permanent、管理器 mutation 与 destructive Agent workflow 均未实现 |

CLI 和 TUI 支持 `zh-CN` 与 `en-US`。它们会从 locale 环境自动选择语言，也可以用 `--locale zh-CN` 或 `--locale en-US` 显式覆盖；机器输出字段和值保持稳定，不随翻译改变。

## 从仓库运行只读能力

需要仓库声明的 Rust toolchain。下列命令只展示当前存在的接口；请始终使用你明确选择的绝对路径。

```bash
# 查看当前能力矩阵
cargo run -p sweepx-cli -- --locale zh-CN capabilities

# Linux 上执行开发版只读扫描，并保存机器可读结果
cargo run -p sweepx-cli -- \
  --format json \
  --state-dir /absolute/path/to/sweepx-state \
  scan /absolute/path/to/root > /absolute/path/to/scan.json

# 读取扫描结束时保存的 snapshot
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

# 校验 TUI 的只读输入，或启动独立的只读终端界面
cargo run -p sweepx-cli -- \
  --format json \
  tui --scan-json /absolute/path/to/scan.json
cargo run -p sweepx-tui -- /absolute/path/to/scan.json --locale zh-CN
```

`scan` 接受一个或多个绝对根路径。全局输出格式为 `human`、`json` 或 `ndjson`。`explain` 和 `tui` 默认最多读取 8 MiB 输入，分别可用 `--max-input-bytes` 调整；CLI 的 TUI 校验路径还支持 `--page-index` 和 `--max-total-rows`。这些上限用于拒绝过大的导入数据，而不是放宽执行权限。

### `status` 与 `cancel` 的诚实语义

当前扫描是同步命令。`status` 读取扫描结束时写入 durable state 的快照；它不是 live progress API。`cancel` 不伪装成可用能力：对于缺失或已经结束的 operation，它返回明确 disposition，而 capability matrix 将 cancellation 标记为 disabled。

### 导入 JSON 永远不是执行依据

`explain --scan-json` 和 TUI 会接受符合 `scan.result` 合同的有界 JSON。导入时，路径证据会被标记为 stale preview，coverage 被降级为 incomplete/not revalidated，因此解释只能用于报告。它不会创建可执行候选、计划、授权或 permit。

## Cleaner 概念

Cleaner 不是任意脚本或“目录名匹配后删除”的别名。一个 Cleaner package 描述版本化 manifest、证据、规则和 Core 兼容范围。当前 CLI 只允许：

- `cleaner list`：列出内置 package 及兼容性；
- `cleaner show`：仅在兼容性检查通过后展示 manifest 与规则元数据；
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

P3 executor 是 sealed、serial、deterministic 且 simulation-only：请求只携带 ID，identity/revalidation digest 由 canonical plan 派生，不携带 native path；唯一 adapter 是 fake adapter；所谓 simulated Trash/Permanent 只生成可验证 receipt 和审计状态，不调用操作系统删除接口，也不改变扫描目标。当前 audit persistence 仅支持 Unix，使用私有 snapshot + anchor 检测意外回滚/损坏；它不能抵抗同一用户同时回滚并重算两者，也不是未来 native mutation 的发布级存储。

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
- macOS 与 Windows scanner 目前是 compilation-only stub；跨平台的 explain、Cleaner metadata 和 TUI 输入处理不等于这些平台已有 live scanner。
- P4 的 native Trash beta、P5 的稳定产品和任何 Permanent 能力都仍是未来路线图。
- 没有安装包、签名发行物、SBOM 发布链或稳定支持承诺。

## 文档导航

- [文档站点](site/index.md)：中文默认入口与英文镜像内容。
- [总体设计](DESIGN.md)：端到端架构、信任边界与关键决策。
- [Cleaner Catalog](docs/CLEANER-CATALOG.md)：生态证据、风险与 report-only 边界。
- [路线图](docs/ROADMAP.md)：当前实现快照、阶段目标、测试矩阵与发布门槛。
- [扫描/缓存架构](docs/architecture/scanner-and-cache.md)、[安全删除架构](docs/architecture/safety-and-deletion.md)与[CLI/TUI/Cleaner 架构](docs/architecture/cli-tui-and-plugins.md)。

## 已知缺口

- Linux scan 的性能预算、复杂文件系统语义和故障注入仍需更完整、可复现的验证。
- macOS/Windows live scanner、三平台 native Trash、可信本地审批 broker 与真实 preflight revalidation 尚未实现。
- Cleaner 签名、更新、撤销、沙箱和外部 query/mutation adapter 尚未达到发布状态。
- P3 plan/simulation authorization、audit/recovery 和 executor 已在 library 层实现；仍没有公共 CLI 合同、可信 HumanApproval broker 或 native adapter。
- 对 sparse、compressed、hard link、clone/reflink、snapshot、dedup、overlay、quota 和共享存储的空间归因不能被概括成“将释放多少空间”。

最重要的当前结论是：**SweepX 已有可运行的只读开发能力，但没有可运行的清理能力。**
