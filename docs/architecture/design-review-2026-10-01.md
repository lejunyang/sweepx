# SweepX 设计审视与扫描改进（2026-10-01）

范围：当前仓库的扫描、junk 分类、缓存和 CLI/TUI 接缝；本机为 arm64 macOS。本文区分已修复问题与尚未实现的能力，不把设计文档当成已交付功能。

## 判断

初次审视时的 22 个 crate 并不是扫描慢的直接原因（后续已收敛到 17 个）。平台适配、文件身份与删除安全、协议及扫描器的边界有价值；真正的问题是业务边界没有落实：CLI 同时负责规则加载、工具探测、分类、Git 证据、缓存、结果拼装和删除入口。审视时 `main.rs` 约 6,100 行、core 的 `lib.rs` 约 8,000 行，二者都包括测试。增加 crate 没有阻止这些职责重新堆到入口。

初次审视暂不进行机械式合并或重命名；后续基于实际依赖，将规则和平台各自收敛到既有 crate。它不会减少一次文件系统调用，还会同时改变包依赖、发布顺序和公共 API。优先在既有 crate 内拆出可独立调用的业务模块，再决定哪些小库只有一个调用者、没有独立契约，值得合并。

## 已落实的修改

| 问题 | 修改 | 边界 |
| --- | --- | --- |
| 每个 junk 根串行创建 FSEvents 流 | 所有已有根记录从最早游标批量校验，各根按自己的游标判断 | 任意历史缺失或查询失败仍退回扫描 |
| 每个目录重复构建变更集合、甚至执行事件间两两比较 | 每设备建立一次有序路径集合，按路径分量检查祖先与后代 | 父事件不能因同时存在子事件而被丢弃 |
| 游标在扫描后捕获，隐藏扫描期间变化 | 在缓存校验及遍历之前捕获 | 不声称扫描获得文件系统原子快照 |
| 不完整扫描也保存成整根命中 | 仅保存完整覆盖的根 | 拒绝访问等情况会重试 |
| 规则改变而文件系统没变时继续接受旧分类 | 根记录绑定内嵌规则内容摘要 | 运行时工具环境仍需本次探测 |
| 根发现和分类重复调用相同工具 | 两者共用本次调用的探测快照 | 不持久缓存工具配置或活动状态 |
| npm 缓存发现执行无关版本查询 | 缓存与安装清单共享有界探测快照，不再扫描后重复查询 | 多安装副本的发现范围不缩减，预算不足的答案为 unknown |
| 旧候选回放跳过整棵子树 | 移除 `ReusedDirectory` 及其重复序列化；目录保持现场遍历 | 旧扫描 ID、缺失父标记、未累计祖先字节都不能用于跳过 |
| 文件缓存将逻辑字节当作可释放字节，分配字节反而保持零 | 仅复用逻辑长度，unique/allocated/reclaimable 缺失信息为 unknown | sparse、hard link 和共享分配不能由长度推断 |
| 已复用文件没有进入下一代缓存 | 保存其标记和已验证长度 | 避免无变动文件隔代重新查询元数据 |

缓存 schema 已升级，旧结果会冷扫重建。机器输出的既有字段名和风险值不变。删除仍须使用原生身份重验，失败不能改为永久删除。

## 尚存的设计不足

1. **规则系统统一（部分落地）。** `sweepx-catalog` 的 `schema` / `vm` 模块与 CLI 的 `project-junk-rules.json` / `platform-junk-rules.json` 各自承担发现、匹配或解释。项目规则已迁入 `sweepx-catalog::junk`，由 `sweepx-core::junk::JunkService` 统一校验并调用已有 cleaner VM；CLI 不再维护另一套项目匹配逻辑。规则字节、机器 ID、风险和匹配行为保持一致，输入规模有界；规则加载时建立有序名称索引并预先规范化父标记，普通目录不再逐规则分配规范化字符串。平台规则发现与候选解释暂时仍在 CLI，需要继续扩展这个服务：输入扫描事实与本次探测证据，输出候选、依据、风险和 blockers。先统一内部类型与评估入口，不急于新增插件框架。
2. **缓存不止一种。** preview cache、整根 junk 缓存和逐文件 listing 的目标不同，原设计文档中的“只存稀疏预览”已经不能描述现状。逐文件 listing 的名称、路径与多个 marker map 随文件量增长，尚缺统一字节预算及逐根淘汰。不能因为结果行少就认为内存也少。
3. **工具调用边界（后续已落地）。** `sweepx-core::tools` 提供共享 `ProbeRunner`，工具答案有整批预算、单次时限、输出上限和取消；安装探测与报告共享快照。由工作线程调用，无后台管道读取线程。限制覆盖子进程执行与管道读取，不承诺文件系统操作或操作系统进程创建调用具有相同的硬实时上限。Windows Job 在启动后附加，不能保证捕获附加前主动逃逸的后代；读取期限不依赖这些后代关闭 stdout。
4. **缓存的活动状态解释（已分层）。** 整根 schema v4 不再持久保存 activity、staleFormats、Git、classification、confidence 和 blockers。命中后按本次工具快照重新解释，证据不足为 unknown；项目规则恢复基础 known_generated/medium，并显式标记 git_evidence_not_revalidated，不回放历史 ignored/high。当前没有缓存重建 Git 仓库上下文，需冷扫才能重新取得 Git 增强解释。工具所谓 live/stale 仅指当前报告的缓存位置，不证明没有进程持有文件。
5. **分类扫描与交互扫描分开。** `scan --tui` 已有根准入后进入浏览、按需详情扫描的基础；junk 当前仍是收集完再拼报告。`ScanSink` 已有事件入口，但这不是可直接订阅的、带背压的 junk 会话接口。

## 支撑后续 TUI 的目标接口

在 `sweepx-core` 内提供一个扫描会话，CLI 和 TUI 都只消费它，不把 UI 状态放进 scanner：

- 命令：开始、取消、提高可见目录优先级、刷新选中范围。
- 事件：阶段、进度、候选新增/修订、目录统计修订、错误、完成。
- 候选使用稳定键，单次扫描身份和 revision 单独保留；刷新必须显式替换旧证据。
- 队列必须有界；可合并进度及同一候选的旧 revision，不能丢最终结果、错误和终态。
- TUI 可立即展示旧缓存，但明确标记历史状态；最新结果逐项替换。用户选择与扫描线程解耦，删除时重新校验对象身份。

不要给普通缓存预览引入 durable event journal 写入依赖。可恢复执行/审计所需的持久日志与可丢弃的 UI 进度不是同一种可靠性要求。

## 大文件、重复文件与垃圾识别

这轮没有实现大文件榜单或内容重复文件检测，也没有扩展规则覆盖范围。

- **大文件**：作为同一次元数据遍历的独立分析器，按阈值与有界 top-K 收集普通文件；保留逻辑大小、分配大小及覆盖状态。不能仅过滤现有截断后的 `ScanSummary.entries`，否则可能漏掉遍历后半段的大文件。大不等于垃圾。
- **重复文件**：单独显式启动内容读取阶段，先按大小分组、排除同一原生文件身份的硬链接别名，再分阶段读取和完整 hash，最后核验大小、身份与修改指纹。必须限制打开文件数、读取字节和并行度，并避开会主动下载的云占位文件。候选组不自动选择保留者，不自动删除。
- **垃圾规则**：优先覆盖可验证格式的工具缓存及明确可重建输出；泛化 `cache/tmp/build` 名称不能替代所有权、格式、上下文和活动证据。Git ignore 仅增强解释。规则正例、容易误报的用户数据反例以及不同工具版本都应共用测试集。

这三种分析应共享遍历事实，但分别产生“垃圾候选 / 大文件 / 内容相同组”，避免把业务含义压成一个可删除布尔值。

## 验证说明

工作区使用固定 Rust 1.98.0。执行格式检查、workspace clippy 和本机 workspace 测试；原有 macOS 移入废纸篓集成测试 `trash_moves_ordinary_paths_without_confirmation_in_machine_invocations` 卡在系统调用，已单独排除，不能将其记为通过。后续交付已补齐 Linux/Windows 的工作区交叉 lint；对应宿主运行时仍未复验。

原生缓存微基准可运行：

```sh
cargo test -p sweepx-cli benchmark_batched_root_validation -- --ignored --nocapture
```

它在临时目录创建 24 个不变化的根，对同一组记录比较逐根和批量校验，并断言命中集合完全一致。它只测事件校验阶段，不代表整个磁盘扫描的加速比；3 次计时也不能用于宣称 p95/p99。

本机实测（2026-10-01，arm64 macOS，debug 构建，24 个未变化临时根）：

| 轮次 | 逐根校验 | 批量校验 |
| --- | ---: | ---: |
| 1 | 10.633 s | 0.426 s |
| 2 | 11.890 s | 0.404 s |
| 3 | 11.071 s | 0.427 s |

三个样本的中位数约从 11.07 s 降到 0.426 s（约 26 倍），两条路径的 24 个命中完全一致。这不覆盖全盘遍历、工具发现、冷启动、规则评估或真实用户目录变化。

首轮审视时本机 workspace 测试汇总为 694 项通过、0 失败、1 项原有 ignored；另显式排除了卡住的系统 Trash 契约测试。上面的手动微基准单独运行并通过。

## 后续交付与下一步

本次后续修改以四个功能单元提交，未增加 crate：

- 共享有界工具探测和安装快照，避免扫描后重复询问 npm；显式项目扫描不触发无关安装探测。
- 项目规则迁入 catalog，core 的 `JunkService` 调用现有 cleaner VM；平台规则和候选解释仍待继续迁移。
- 名称索引及预规范化父标记减少每目录的重复分配，重叠名称保持 catalog 顺序；未进行端到端扫描计时，不宣称整机加速倍数。
- 根缓存 schema v4 保存扫描与规则匹配事实，活动状态按本次工具证据重建；缺少 Git 仓库上下文时明确降回基础解释。

最终本机交付检查（2026-10-01，arm64 macOS）：格式检查和工作区 `--all-targets --all-features` clippy 通过；工作区 `--all-features` 测试 707 项通过、0 失败，2 项原有基准 ignored，另排除上述 1 项系统 Trash 契约测试。53 份 Markdown 的文档检查和 23 项文档检查器测试通过；catalog 打包清单包含迁移后的规则资源。

交叉验证（2026-10-01，arm64 macOS，Rust 1.98.0、Zig 0.16.0）：工作区 `--all-targets --all-features` clippy 对 `x86_64-unknown-linux-gnu` 和 `x86_64-pc-windows-gnu` 均通过。包含目标平台测试代码的编译，但未运行 Linux/Windows 测试二进制，也不代表 Windows MSVC 配置验收。检查发现的既有 Unix Trash 路径测试已按实际适用平台门控。

下一步顺序：先补逐文件 listing、marker 索引与多根缓存的统一字节预算和淘汰；随后提供可取消、带有界事件队列的 junk 会话并继续下沉平台候选解释；大文件分析再接同一次遍历，重复文件检测作为独立、显式内容读取阶段。当前这些能力尚未实现。

## Crate 收敛进展

规则三包已合入现有 `sweepx-catalog`（`schema` / `vm` / `junk` 模块），workspace 从 22 减为 20。原有 package 准入 API 保留，schema/VM 的 Rust 导入路径迁移到 catalog 模块；机器 schema ID、规则资源字节与风险值不变。平台四包已合入 `sweepx-platform::{linux,macos,windows}`，workspace 进一步收敛到 17 个。平台默认仅编译共享契约；三个后端 feature 由 scanner 原有平台 feature 转发，原生依赖仍按目标选择，Windows 纯解析器仍可在其他宿主测试。原 crate-private native helper 的可见性收紧到其平台模块，Linux 测试子进程的 exact filter 同步迁移。已经发布的旧包不属于本地 workspace，也不在新的发布顺序中；此次修改不发布或撤回 registry 包。

合并交付验证（2026-10-01，arm64 macOS）：工作区格式、`--all-targets --all-features` clippy 和测试通过，仍为 707 项通过、0 失败、2 项基准 ignored，显式排除上述系统 Trash 契约测试。独立对照合并前后的测试名称，共享契约、macOS 后端和 Windows 纯解析器的 75 项测试全部保留，仅增加平台模块前缀。仅契约、单后端以及无后端 scanner 的编译检查通过；仅契约的普通依赖树不含原生后端依赖。

Linux GNU、Windows GNU 的全工作区交叉 clippy，以及各自单独启用后端 feature 的平台 crate clippy 均通过；这不覆盖目标宿主运行时或 Windows MSVC。53 份 Markdown 检查和 23 项文档检查器测试通过。17 个本地 package archive 已生成并独立核对：迁移源码、catalog 规则资源、后端 feature 均存在，规范化依赖清单没有已移除的五个 crate。打包使用 `--no-verify`，不代表从 registry 依赖构建已验收；发布脚本顺序覆盖全部 17 包并满足本地依赖顺序。

## 第二轮精简评估：依赖方向优先于数量

2026-10-01 根据本地 Cargo metadata、源码调用点和公开契约复查剩余 17 个 crate。表中的调用者只计当前 workspace 的直接普通依赖，按包去重、不计 dev dependency，不能据此推断 registry 用户不存在。此次不再减少包数量：没有发现与上一轮 schema/VM、平台后端同等明确的合并收益。

| Crate | 保留依据与后续边界 |
| --- | --- |
| model、protocol | model 被 10 个其他包直接引用，protocol 被 5 个引用；类型/证据与输出 envelope 各自有独立契约，合并会把协议投影带入底层扫描 |
| canonical、i18n | canonical 只有约 170 行但被 5 个包共用，i18n 被 3 个表面共用；分别保持摘要语义和语言选择，不能按文件长度判断冗余 |
| platform、scanner、fixtures | 平台原生操作、遍历与聚合、共享测试夹具各有所有权；fixtures 仅是平台/scanner 的 dev dependency，合入生产层收益有限 |
| cache、event-journal | 可丢弃预览与 Linux 已完成事件的持久 replay/校验不是同一种契约；journal 虽仅 core 使用，仍应避免把 SQLite/Linux 生命周期并入通用缓存 |
| catalog、analysis | catalog 负责加载/校验/评估规则，analysis 负责候选和解释；analysis 也被 safety 使用，不能为了合并让安全层依赖 core 编排 |
| core、cli、tui | 保留业务、入口和终端呈现的边界；修正 core 反向依赖 tui，而非合并成更大的入口包 |
| audit、safety、executor | audit 有 core/CLI/safety/executor 多个消费者；safety 与 executor 保留不可伪造授权/permit 和 sealed simulation 执行之间的边界。executor 尚无 CLI 消费者，并不代表可以把其状态机或崩溃语义删除 |

已落实：将原 core 内的 `TuiDetailRescanProvider`、转换逻辑和相关测试整体迁到 CLI 的 `tui_adapter` 模块。只组合已有 scanner 与 browser API，不复制遍历算法；身份 namespace、no-follow/mount 复验、单次取消状态和有界进度发送保持原有实现。`sweepx-core` 的正常依赖图中不再包含 tui、ratatui、crossterm。core 的 typed scan summary、根准入与已有 `into_tui_parts`/`scan_for_tui_with_store` 辅助方法保留，不依赖终端类型。

同时删除没有命令或调用者的 `TuiReadRequest`、`TuiReadSuccess`、`tui_read_from_scan_json` 和错误映射封装；TUI 库的有界 JSON 视图仍保留。导入解释的错误类型由误命名的 `CoreError::TuiInput` 改为 `ScanInput`，仍返回 usage error。以上是 Rust API 调整，既有 CLI 选项、机器字段名与枚举值不变。

此次没有统计“重复代码百分比”：同样使用 SHA-256、SQLite 或 filesystem helper，可能承担不同的 domain、事务或授权契约，文本相似度不能证明可以共用。后续精简优先下沉 CLI 的平台候选解释和拆分入口模块，再处理已经验证为同一契约的重复逻辑；不新增通用 util、插件或服务框架。

验证中发现的两类问题分开处理：缓存测试以 PID/时间戳加 `create_dir_all` 命名，可能让并发测试共用目录，已单独改为原子创建的 `TempDir` 并保留其生命周期。macOS 文件详情则是产品层缺口：将原 Linux 完整详情用例临时扩展到本机后，普通文件返回 `IdentityUnavailable`；源码确认 macOS `inspect_child` 给文件/链接的 mount identity 为 `None`，而 detail scanner 要求它为已知。未通过复制父 mount 或放宽复验来掩盖它；原 Linux 成功详情用例保留平台范围，取消后空目录刷新用例扩展到三平台，并在本机通过。这是第二轮依赖迁移交付时的缺口；后续原生观测修复见下一节，不能从依赖迁移的通过结果推断详情契约已成立。

第二轮交付验证（2026-10-01，arm64 macOS，Rust 1.98.0）：格式、受影响 core/CLI 的 all-targets/all-features clippy、工作区 clippy 通过；工作区测试 708 项通过、0 失败、2 项原有基准 ignored。仍用 `cargo test --workspace --all-features --locked -- --skip trash_moves_ordinary_paths_without_confirmation_in_machine_invocations` 排除已诊断的系统 Trash 挂起，该行为未验证。Linux GNU 与 Windows GNU 的工作区交叉 clippy 通过，包括迁移后的目标测试代码；未运行目标宿主测试，未验收 MSVC。53 份 Markdown 检查和 23 项检查器测试通过。

独立复核包含：对照迁移前源码，适配器生产逻辑在可见性、注释与 rustfmt 规范化后完全一致；通过 core 的普通依赖树和 Cargo metadata 确认终端依赖已断开；core/CLI 的 package list 保留预期源码并包含 `tui_adapter.rs`；现有发布顺序仍覆盖 17 包并满足普通及开发依赖的先后关系。以上检查不包括 registry 依赖构建或发布，也不验证当时的 macOS 文件详情缺口；该缺口随后单独修复。


## macOS 详情 mount 身份修复

问题已经修复（2026-10-01）：详情 scanner 需要文件/链接的 mount 身份，普通 macOS 批量观察则没有提供。直接复制父目录身份会把缺失证据升级为结论；为每个普通扫描文件增加打开操作又会放弃批量快路径。因此在现有 platform 契约内新增详情专用的 `inspect_child_with_mount_identity` 和带同一组绑定检查的 `inspect_bound_child_with_mount_identity`。普通遍历不变，详情和递归详情使用这个入口；已有 Linux/Windows backend 默认复用它们本来就有 mount 证据的检查。

macOS 仅为详情中的文件/链接保留一个短暂元数据句柄：相对 retained parent 的 native basename 做 `openat`，`fstat` 校验设备、inode 和类型，`fstatfs` 观察对象自身的 fsid；再次核对 fsid、大小/修改指纹、父目录状态和 no-follow basename 当前绑定。所有返回/错误/取消路径关闭该句柄，不读取 payload。权限/TCC 拒绝、无法观测或替换/变化均拒绝详情刷新，不产生猜测的 identity。`f_fsid` 沿用原后端的文件系统身份定义，不宣称由此取得文件系统原子快照或新的跨平台发布资格。

打开使用 `O_EVTONLY | O_SYMLINK | O_CLOEXEC | O_NONBLOCK`。`O_SYMLINK` 请求链接自身而不是目标；[Apple XNU 的打开实现](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/vfs/vfs_vnops.c) 会清除跟随行为。本机实测，把 `O_NOFOLLOW` 同时加入会使合法的链接观察返回 ELOOP，因此不能靠把两个名字都带有 no-follow 意义的选项叠加来保证契约。`O_EVTONLY` 不阻止卷卸载，故观测前后仍要核对 fsid。它仍受宿主权限检查；元数据访问不代表可以绕过权限，也不承诺文件系统/provider 调用具有硬实时期限。

独立证据包含：`symlink_metadata` 核对 device/inode、类型与逻辑字节，另用 `getattrlist(ATTR_CMN_FSID, FSOPT_NOFOLLOW)` 对照 fsid；悬空链接证明未打开目标，真实权限拒绝仍返回拒绝。同名等长文件替换与替换成链接在观测前发生时均被拒绝，保留旧 inode 使反例不依赖分配顺序或时间竞态。TUI provider 从根准入结果分别进行直接列表、渐进递归统计和完整刷新，普通目录遍历对照名称集合、直接子项总数及递归逻辑字节；渐进列表仍为 lower bound，完整统计才是 exact，分配与可释放量仍为 unknown。

交付验证（2026-10-01，arm64 macOS，Rust 1.98.0）：受影响 platform/scanner/CLI 的测试与 all-targets/all-features clippy、格式检查、工作区 clippy 均通过；工作区测试 712 项通过、0 失败、2 项原有基准 ignored。依旧显式排除 `trash_moves_ordinary_paths_without_confirmation_in_machine_invocations` 的已诊断系统 Trash 挂起，未验证该系统操作。首次在沙箱内执行的平台全量测试遭遇 FSEvents 服务启动拒绝，宿主环境完成了该套原生测试，未因此删除或跳过 FSEvents 用例。Linux GNU、Windows GNU 工作区交叉 clippy 通过，目标测试代码已编译但未在对应宿主执行；MSVC 未验收。53 份 Markdown 检查和 23 项文档检查器测试通过。未测端到端性能，不宣称额外身份观测会提高扫描速度。


## 端到端计时基线（2026-10-01）

已提供 `junk --timings`：独立 stderr JSON 记录阶段耗时及实际根缓存命中数，不改变结果 schema。可复现脚本为 [benchmark-junk.py](../../scripts/benchmark-junk.py)，原始基线记录见 [受控目录基线](junk-benchmark-2026-10-01.json)。本次为 arm64 macOS、Rust 1.98.0 release 构建，8 个 Cargo 项目根、每根 1,024 个普通文件，共 8,192 个产物文件；各状态运行 3 次。每个候选的逻辑总量都由普通 walk/stat 独立核对，冷/热候选的路径、规则、风险、数量、大小及证据状态一致；Git/tool 等动态解释不在这一等价比较内。

| 状态 | 完整进程中位数 | 主要阶段中位数 |
| --- | ---: | --- |
| 空 SweepX 缓存 | 620.0 ms | 遍历 523.9 ms、缓存写入 47.0 ms |
| 整根缓存命中（每次 8/8） | 275.5 ms | 根缓存读取/验证/回放 256.8 ms |
| 单文件追加 8 字节 | 540.1 ms | 根验证 255.8 ms、逐文件索引验证 257.3 ms、遍历 9.5 ms |

OS 缓存没有清空，“冷”只表示空 SweepX 缓存。该结果不能推断全盘或真实用户缓存目录的加速倍数，也不提供 p95/p99。沙箱初测未能启动 FSEvents，三次热扫全部未命中；正式基线在宿主环境取得，不能把这两组不同环境的耗时混用。

测量明确指出下一步优化：单文件变化后，根缓存与逐文件索引分别等待原生事件历史；应共享覆盖充分的本次历史查询，保留各自游标、身份及覆盖检查。预算与逐根淘汰、共享分类/会话、大文件、重复文件和规则扩展仍按前述顺序推进。


## 单次历史查询复用（2026-10-01）

根记录与逐文件索引现在在查询前统一加载；从最早游标、覆盖全部请求根的一次完整历史中，各自按原游标解释变化。查询失败或历史不完整同时禁用两层复用；查询期间根目录被替换时，根记录拒绝命中，该根的旧文件索引也失效。未通过提前推进游标隐藏并发变化。独立回归覆盖查询次数、不同游标、错误/缺口、路径边界与根身份替换。

相同 release 负载各 3 次、OS 缓存仍未受控：[修改后原始结果](junk-benchmark-shared-history-2026-10-01.json)中，单文件变化完整进程中位数 285.0 ms，合并后的缓存阶段 256.2 ms，遍历 11.9 ms；第二次约 257 ms 的历史等待已移除。整根命中中位数 271.8 ms，仍保留一次约 257 ms 的验证。冷扫中位数 174.6 ms，与初测 620.0 ms 的差异不能都归因于本改动，OS 缓存/宿主状态不同，不能混称整体倍数。

[真实目录原始结果](junk-benchmark-repository-2026-10-01.json)覆盖本仓库 `crates/` 与 `site/`，只读、隔离 SweepX 状态、各 3 次：冷扫 164.5 ms、整根命中 272.3 ms。候选文件事实一致，但对这一较小负载，等待事件历史比现场扫描更慢。还需处理原生 run loop 的固定等待，再继续统一缓存预算。


## 收到完整历史后立即结束等待（2026-10-01）

原生 `events_since` 的回调设置 `HistoryDone`，但原来 `CFRunLoopRunInMode` 的 `returnAfterSourceHandled` 为 false，且回调没有停止 run loop。完整历史已收到后仍等待 250 ms 时间片耗尽，造成热扫下限。现在每处理一次事件源就返回外层检查；只收到 `HistoryDone` 才成功，其他事件源、超时、缺口不证明完成。Apple 的 [CFRunLoopRunInMode 文档](https://developer.apple.com/documentation/corefoundation/cfrunloopruninmode(_:_:_:))说明这个参数的返回语义；原生现有变更/空历史回归、新增零期限拒绝和包含完成标记及缺口的完整回调批次回归均保留契约。

同一宿主、Rust 1.98.0 release、受控 8 根/8,192 文件及真实仓库目录、每状态 3 次、OS 缓存不受控。原始结果为 [受控负载](junk-benchmark-runloop-2026-10-01.json)和 [真实目录](junk-benchmark-repository-runloop-2026-10-01.json)。

| 状态 | 修改后的完整进程中位数 | 修改后的主要阶段 |
| --- | ---: | --- |
| 受控负载冷扫 | 173.7 ms | 遍历 92.5 ms |
| 受控负载整根命中（每次 8/8） | 23.3 ms | 两层缓存读取/验证/回放 12.2 ms |
| 受控负载单文件追加 8 字节 | 42.6 ms | 缓存读取/验证 12.0 ms、遍历 9.7 ms |
| 真实 `crates/`、`site/` 冷扫 | 166.0 ms | 遍历 146.4 ms |
| 真实 `crates/`、`site/` 整根命中 | 21.5 ms | 缓存读取/验证/回放 10.6 ms |

候选文件事实冷/热一致，受控负载每轮含变化后的逻辑大小经独立 walk/stat 核验。这里只记录三次样本中位数；不推断全盘性能或尾延迟，不把不同轮次冷扫差异都归于代码改动。

## 后续任务验收清单

- [x] 端到端阶段计时、受控及真实目录冷/热测量、结果等价核验。
- [x] 合并根/文件索引历史查询，移除完整历史后的固定等待。
- [ ] listing、marker 与多根缓存的统一字节预算、逐根淘汰及有界持久化读取；预算耗尽不能把缺失证据当作否定结论。
- [ ] 平台垃圾规则与候选解释迁到可独立调用的共享服务。
- [ ] 缓存命中后重建当前 Git 上下文及增强证据。
- [ ] 核心垃圾扫描会话：开始、取消、可见目录优先级、选中范围刷新；有界阶段/进度/候选/统计/错误/终态事件，稳定候选键及 revision。
- [ ] 垃圾交互 TUI：历史结果标记与逐项替换、自由选择和删除前原生身份重验。
- [ ] 同一次遍历中的独立大文件分析：阈值、有界 top-K、逻辑/分配大小和覆盖状态。
- [ ] 显式内容阶段的重复文件检测：硬链接别名排除、分阶段读取和完整 hash、身份/变化复验、资源预算及云占位保护。
- [ ] 扩展有格式、所有权、上下文依据的垃圾规则，覆盖正例、用户数据误报反例及不同工具版本。

Linux/Windows 宿主运行时、MSVC 与系统 Trash 挂起用例仍是独立验证缺口，不因性能测量通过而视为完成。

本阶段交付验证（2026-10-01）：原生 platform 测试、受影响 crate lint、格式和工作区 clippy 通过；工作区 719 项通过、0 失败、2 项基准 ignored，1 项已诊断系统 Trash 挂起显式排除。共享历史查询阶段的 Linux GNU/Windows GNU 工作区交叉 lint 已通过；后续 run loop 改动仅在 macOS cfg 内，不改变这两个目标编译的源码分支，复用对应通过结果。53 份 Markdown 检查、23 项文档检查器测试和 5 项基准验证器测试通过。未执行 Linux/Windows 宿主运行时或 MSVC 验收。


## 分类元数据预算（2026-10-01）

分类目录行、file/directory marker、coverage/path 与可选 listing 已接入同一内存估算预算，默认整批 256 MiB、单根 128 MiB，通过 `ScanResourceLimits` 配置。模型行计入 native lineage、字符串与 Vec 的容量，不通过 JSON 大小或文件逻辑长度猜测内存；索引采用固定容器估算额度。这不是 allocator RSS 或文件分配大小的精确上限。

必需证据入场前可清除可重建 listing/covered-path 索引以腾出预算。若必需证据依旧无法保留，本根后续分类停止，避免缺失 marker 让否定谓词错误匹配；资源边界使结果为 partial，human 明确提示可能遗漏，仍继续现场遍历和原有字节累计。缺失 covered-path 不保存成整根命中。可选 listing 不要求保存每个文件；未知条目下次重新观察，既有已验证长度在预算内进入下一代。

内置分类器只保留本次规则实际需要的项目文件 marker，名称集合从规则字节加载结果派生；自定义分类器默认仍保留全部 marker，以保持其契约。目录名称只保留一次 identity-keyed lineage；不再在 listing 的旧 dirs 字段中重复存储。回归覆盖零预算下的否定谓词、可选索引压力下保住必需 marker、自定义规则 marker 变更，以及 native lineage/预留容量计入模型内存估算。

本条完成扫描中的共享预算；持久化文件的有界读取、跨根预算与逐根淘汰还未完成，上一节对应验收项暂不勾选。
