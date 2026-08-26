# SweepX

**SweepX 是一个尚未实现的、面向 Windows、macOS 与 Linux 的跨平台 Rust CLI/TUI/Agent-safe 磁盘分析与安全清理产品设计。** 它拟议以同一套安全核心服务非交互 CLI、动态 TUI 和受限的 AI Agent 工作流，把“发现了什么”“为何可能可回收”“准备做什么”“通过哪种方式显式授权”和“实际发生了什么”明确分开。

> [!CAUTION]
> **这里没有可运行的 SweepX，也没有已发布的清理能力。不要复制执行本文中的接口草图，不要据此删除或移动任何文件。**
>
> 本次交付仅包含研究与设计文档；没有实现、构建或发布二进制，也没有执行扫描、清理、删除、提权、浏览器策略变更或外部命令。未来实现即使使用回收站，也不能保证一定可恢复或立即释放预估空间。永久删除是不可逆的 R4 操作，不是 secure erase，并且任何参数都不得绕过系统关键路径、文件系统根、用户目录根和其他硬保护。

## 当前状态

| 项目 | 状态 |
|---|---|
| 交付类型 | **设计与研究快照**，不是产品实现 |
| 研究/设计截点 | 2026-08-26 |
| Rust crate、可执行文件或安装包 | 未提供 |
| 可运行的 CLI 或 TUI | 未提供 |
| Agent Skill | 已提供可落地的 `skills/sweepx/SKILL.md` 协议草案；因产品未实现而不可执行 |
| 扫描、回收站或永久删除能力 | 未实现、未验证、未发布 |
| 平台支持声明 | Windows、macOS、Linux 是拟议的一等平台；尚无平台达到发布门槛 |
| v1 权限模型 | 拟议仅以当前普通用户身份运行；不请求或使用提权 |

本文中的“必须”“保证”和命令名均描述**未来实现的验收约束或拟议接口**，不是对现有软件能力的声明。

## 产品定位

SweepX 拟议位于普通磁盘空间分析器与应用专用清理器之间：

- 通用扫描核心只读地回答“空间在哪里”，保留权限错误、文件系统边界、链接、共享块和大小口径的不确定性。
- 类型化 Cleaner 用包管理器、构建系统、浏览器和应用自身的语义回答“为什么它可能可回收”，而不是仅凭目录名或最后访问时间。
- CLI、TUI 与 Agent 共用同一状态机和安全核心，不允许某个前端获得更宽松的删除路径。
- Agent 可以协助只读扫描、解释、生成和展示精确计划；常规审批只由人在可信本地交互界面完成。`--dangerously-delete` 是有意保留的非交互 Permanent 逃生阀，CLI 无法可靠证明调用者是人，因此 Agent Skill 明令不调用它。Agent 不能把聊天中的“可以”转成常规审批，也不能代输确认。
- 当官方管理器提供可靠的查询或清理接口时，设计倾向于使用其对象语义；外部命令仍需固定版本、参数、能力和副作用边界，绝不因名称含 `clean`、`prune` 或 `dry-run` 就自动信任。

目标不是做一个更大胆的删除器，而是让每一条建议都能说明证据、风险、覆盖缺口、预计收益口径和恢复预期。

## 拟议的关键安全约束

以下是后续实现必须通过测试和平台发布门槛证明的约束，不是当前已实现的保证：

1. **普通用户边界。** v1 不调用 UAC、`sudo`、polkit，不申请 Full Disk Access、backup privilege 或 Linux capability，不接管所有权，也不修改 ACL、TCC、immutable/read-only 属性或系统设置。若进程已处于 root/admin/elevated 或带扩大访问范围的 capability，破坏性模式应失败关闭。
2. **只读优先。** 默认从 metadata-only、no-follow、same-mount/volume 的 live scan 开始。权限不足、未知 reparse point、provider、网络卷、挂载点和未扫描子树必须显示为边界或不完整，不能被当作空目录。
3. **回收站优先。** 拟议默认动作是平台 Trash/Recycle Bin。回收站不支持、权限不足、空间不足、取消或结果不明时保持失败/待核对，绝不静默降级为永久删除。
4. **计划与授权分离。** Candidate、Explanation、不可变 DeletionPlan、Execution Authorization 和一次性 Preflight Permit 是不同对象。Trash 审批不能授权 Permanent；编辑目标、模式、风险、策略或计划内容必须重新授权。
5. **两种显式授权。** 常规路径由可信本地前台产生绑定精确计划的 Human Approval；Permanent 另允许显式 `--dangerously-delete` 跳过确认，Core 将该 flag 记录为独立的 `ExplicitDangerousDelete` 授权，而不是伪称人工审批。它可被脚本调用，所以安全不能依赖“识别人类”；`--yes`、`--force`、配置或隐式默认仍无效。两条路径都不能绕过硬保护和执行前复验。
6. **执行前现场复验。** 缓存、历史报告和导入结果只用于预览或加速。每个动作都必须在平台调用前以 no-follow 方式复验父目录、对象身份、类型、卷/挂载、链接状态、保护策略和目录后代集合；变化即 stale，并回到重新扫描。
7. **不可绕过的硬保护。** 文件系统根、卷/挂载根、系统关键区域、home/profile 根、回收站、SweepX 自身状态、保护标记及包含它们的祖先不能进入执行计划；Permanent、插件或直接核心 API 也不能放宽此规则。
8. **结果诚实且可审计。** 批次不承诺事务性或自动回滚。每个动作应先持久化 intent，再记录成功、失败、跳过、过期、取消或结果不明；平台调用已提交但结果不明时必须 reconcile，不能重试猜测。
9. **不确定性不等于零。** `unknown`、`lower_bound`、`unsupported`、`not_checked` 和 `incomplete` 与已知 `0` 不同。logical、filesystem-reported allocated、potentially reclaimable 和动作后可用空间变化也不能混为一个数字。
10. **Agent 权限不扩张。** Agent 只能经公开的结构化 Core API 工作，不能调用删除 adapter、裸删路径、执行生态清理命令、审批计划或绕过人工界面；它获得审批 ID 后仍必须由核心验证并现场复验。
11. **扫描状态是稀疏的。** Scanner 以流式目录聚合和内存队列为主，只有内存达到高水位后才创建有界临时 spill；持久 cache 只保留目录摘要、每层重项、候选及错误/边界，不保存海量普通小文件明细。TUI 默认显示 top-K + `Others`，进入目录时再优先 live 展开。默认整个状态目录上限 512 MiB，而不是预留数 GiB。

拟议风险模型为 R1（低风险、可回收候选）、R2（中风险或释放量不确定）、R3（高风险/能力不确定，默认跳过或 Trash-only）、R4（所有 Permanent 及其他不可逆动作）和不可审批的 `BLOCKED`。风险等级表达审批强度，不是“安全删除证明”。

## 普通用户权限边界

v1 的作用域是**当前用户、当前主机、当前可见文件系统视图**。它不承诺查看或清理其他用户、受系统保护的数据或需要管理员/root 权限的目标。

- 当前身份能读取的系统或受保护区域最多只做只读扫描、解释和建议；任何需要提权的清理均超出 v1。
- 读取被拒绝时应记录原生错误和不完整覆盖，不提示自动提权，也不从已知部分推断整个子树安全。
- 不自动停止进程、关闭句柄、卸载卷、改变浏览器/企业策略或修复权限。
- 进程占用检查只是权限受限、瞬时的观察；“未观察到占用”不等于无人使用。
- Windows、macOS 与 Linux 都必须独立通过扫描、回收站、复验、崩溃恢复和安全测试后，才可为该平台启用破坏性模式。一个平台通过不自动授权另一个平台。

## 拟议使用流程（不可运行）

> [!WARNING]
> 以下代码块只是未来接口的可读草图。当前没有可供运行的 `sweepx` 命令；占位符也不是 shell 输入。**请勿复制、粘贴或执行。**

### 1. 只读扫描与解释

```text
PROPOSED INTERFACE ONLY — NON-RUNNABLE
sweepx scan <ABSOLUTE_USER_SELECTED_ROOT> --format ndjson
sweepx explain --scan-id <SCAN_ID> --candidate-id <CANDIDATE_ID> --format json
```

拟议语义：扫描只产生当前 live generation 的事实、边界和候选；`explain` 绑定一个候选，分别展示事实、规则推导、启发式、未知项、风险和恢复条件。它们都不产生删除授权。

### 2. 创建、展示、人工批准并执行 Trash 计划

```text
PROPOSED INTERFACE ONLY — NON-RUNNABLE
sweepx plan create --scan-id <SCAN_ID> --candidate-id <CANDIDATE_ID> --mode trash --format json
sweepx plan show --plan-id <PLAN_ID> --format json

[HUMAN-ONLY: review the exact immutable plan in a trusted local interactive surface]
sweepx approve --plan-id <PLAN_ID>

[ONLY AFTER THE CORE RETURNS AND VALIDATES AN OPAQUE APPROVAL ID]
sweepx execute --plan-id <PLAN_ID> --approval-id <APPROVAL_ID> --format ndjson
```

拟议语义：人必须先核对精确模式、路径/对象、动作数量、逐项风险、大小不确定性、计划指纹、过期时间和恢复预期。聊天确认、管道输入、配置预批准或 Agent 代操作均无效。`execute` 不是“信任旧计划直接删除”，仍须逐动作复验、写前审计，并保留部分成功或待核对状态。

桌面环境中，`approve` 优先使用 SweepX 自己的本地原生计划审阅窗口；Windows 可选 Windows Hello/UserConsentVerifier，macOS 可选 LocalAuthentication 做一次不提权的用户复核。它们不等于 UAC/管理员授权，也不会天然对某个文件计划做密码学签名，所以完整计划绑定仍由 Core 的 256-bit digest 与一次性 ApprovalRecord 完成。Linux 没有统一同等接口；没有合格 GUI 时使用可信 foreground TTY 的短 fingerprint 挑战作为注意力检查。挑战串由 immutable plan 自动生成，不是密码，也不是安全边界。

### 3. Permanent 模式

```text
PROPOSED DANGEROUS INTERFACE ONLY — NON-RUNNABLE
sweepx plan create --scan-id <SCAN_ID> --candidate-id <CANDIDATE_ID> --mode permanent --format json
sweepx plan show --plan-id <PERMANENT_PLAN_ID> --format json
[HUMAN-ONLY: approve in the native local review window or trusted terminal fallback]
sweepx approve --plan-id <PERMANENT_PLAN_ID>
sweepx execute --plan-id <PERMANENT_PLAN_ID> --approval-id <APPROVAL_ID>
```

高级非交互逃生阀（不会走上述人类确认）为：

```text
sweepx execute --plan-id <PERMANENT_PLAN_ID> --dangerously-delete
```

> [!CAUTION]
> **Permanent 计划与 Trash 计划完全分离，所有动作至少为 R4。** `--dangerously-delete` 是唯一跳过确认并直接执行已有 Permanent 计划的显式危险开关。它本身就是可审计的操作者授权，不是人类身份证明，也不是 approval；脚本技术上可以传入，因此 AI Skill 必须自我约束为永不调用。Core 只允许它绑定当前未过期的精确 Permanent plan，不能把 Trash 计划转成 Permanent、增加对象、跳过 live revalidation，或绕过根目录/系统文件/保护 marker。`--yes`、`--force` 和旧 Trash 审批仍无效。Permanent 不是 secure erase，也不能保证数据无法恢复。

规范状态流为：

```text
scan -> explain -> immutable plan -> explicit execution authorization -> live revalidation
     -> platform action -> reconcile -> audit
```

不存在 `scan -> execute`、`path -> delete` 或 `Trash failed -> Permanent` 的捷径。

## 明确非目标

- 本轮不实现、构建、打包或发布 Rust 产品，也不执行任何真实清理。
- v1 不请求管理员/root 权限，不处理其他用户数据，也不承诺删除系统保护对象。
- 不提供“忽略安全”“任意路径删除”“回收站失败后裸删”或可绕过硬保护的接口。
- 不清空回收站，不自动 kill 进程，不自动修改浏览器、企业或操作系统策略。
- 不承诺 secure erase、跨卷原子性、批次回滚、精确释放空间、必然可恢复或必然不可恢复。
- 不把文件名、目录名、年龄、`atime`/`mtime`、负面的占用检查或所谓 dry-run 单独当成可删除证明。
- 不承诺准确判断任意文件由哪个已卸载应用创建，也不承诺证明一个 SDK、包、模型、浏览器存储或容器对象在所有项目、用户、分支、VM、容器、CI 与离线介质中均未被引用。
- 不绕过操作系统保护、浏览器安全机制、文件锁、企业策略或管理器所有权模型。
- 不允许 Cleaner、TUI、CLI 或 Agent 扩大扫描根、降低风险、生成审批、创建 permit 或直接调用平台删除 adapter。

## 文档导航

- [总体设计](DESIGN.md)：端到端架构、信任边界、数据模型、Rust crate/模块规划、跨平台抽象与关键决策。
- [Cleaner Catalog](docs/CLEANER-CATALOG.md)：系统、应用、开发工具、容器与浏览器候选的证据、风险、活跃性/引用性和平台差异。
- [路线图](docs/ROADMAP.md)：阶段性 MVP、三平台测试矩阵、故障与安全测试、可复现基准、发布门槛和待验证风险。

完整专题证据与协议也随本交付保留，便于复核综合结论：

- [工具版图](docs/research/landscape.md)、[平台文件系统语义](docs/research/platform-filesystems.md)与[系统关键文件识别](docs/research/system-protected-files.md)；
- [系统级用户确认能力](docs/research/os-user-confirmation.md)；
- [开发者缓存](docs/research/developer-caches.md)、[常见应用缓存/日志/残留](docs/research/common-application-caches.md)与[浏览器存储](docs/research/browser-storage.md)；
- [扫描/缓存架构](docs/architecture/scanner-and-cache.md)、[安全删除架构](docs/architecture/safety-and-deletion.md)与[CLI/TUI/Cleaner 架构](docs/architecture/cli-tui-and-plugins.md)；
- 可直接落地的 [Agent Skill 草案](skills/sweepx/SKILL.md)。

## 证据表达约定

研究和设计文档采用以下标签，读者不应把低一级证据升级为高一级结论：

- **事实 / 已证事实**：官方文档、标准或固定版本上游源码直接支持的陈述；网络来源必须同时给出 URL 与访问日期。
- **推导**：从一项或多项事实得出的限制或工程结论，不代表平台或上游产品承诺。
- **建议 / 产品设计**：SweepX 的保守取舍、拟议默认值或实现方向，必须经过实现和测试才可能成为产品保证。
- **未知 / 缺口 / 待实测**：当前证据不足、版本会漂移或必须在真实平台验证；它们应提高风险、转为 report-only 或阻断，不得被补写成“安全”。

本 README 只概述本地设计，不新增未经引用的网络事实。需要平台、工具或浏览器的外部事实时，应以正式文档中带 URL 和访问日期的来源为准。

## 已知未知与发布前问题

当前设计有意保留以下未决项：

- 三个平台在本地盘、网络盘、可移动盘、provider/cloud placeholder、空间不足、取消与崩溃条件下的 Trash 行为和可恢复性，需要逐平台实测。
- 当前设计尚未证明能在三平台统一地把“对象身份仍为 X”与“移入回收站”合成一个原子动作；发布前必须测量并记录最后一次复验与平台调用之间的 TOCTOU 残余风险。
- 对稀疏、压缩、hard link、clone/reflink、snapshot、dedup、overlay、quota 与共享存储的释放量归因尚未完成跨平台验证；在证明前只能返回未知或带置信度的估计。
- 普通用户看到的进程、句柄、mount namespace、ACL/TCC/LSM 和其他用户活动并不完整；无法证明“全机无人使用”。
- 浏览器 Profile、分区存储、数据库布局和本地 AI 模型组件的版本适配范围尚未实测；未知版本必须 report-only，尤其是尚未验证稳定磁盘映射的场景。
- 包管理器和 SDK 查询命令的零写入性质尚未逐版本审计；严格只读发现不能从命令名称推断，未验证命令不得进入该模式。
- Cleaner 签名、沙箱、外部命令适配器、可信本地审批 Broker、跨平台回收站 adapter 和崩溃 reconciliation 都尚未实现或通过对抗测试。
- 扫描吞吐、内存上限、缓存收益、TUI 大树响应和各平台依赖选择仍需可复现基准与故障注入验证；设计目标不是实测结果。
- 每个平台的破坏性模式必须独立通过路线图中的发布门槛。在此之前，最安全且唯一诚实的状态是“设计中、不可运行”。
