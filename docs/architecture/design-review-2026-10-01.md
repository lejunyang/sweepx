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

1. **规则系统统一（继续下沉）。** 项目与平台规则 JSON 现在都在 `sweepx-catalog::junk`，平台类型与准入放在其 `platform` 模块。`sweepx-core::junk::JunkService` 继续调用已有 cleaner VM，现通过 `with_platform` 组合平台分类，并通过 `interpret` 输出候选、依据、风险及 blockers；发现、通用候选和缓存动态解释已经移出 CLI。规则字节、机器 ID、风险保持一致，输入规模有界；名称索引及预规范化父标记保留。Linux `/tmp` 的专用原生发现及报告解释随后也已迁入 core，报告和清理预览共用测量；浏览器/known-root 发现快照和路径绑定已落地，整根候选缓存现也绑定本次启用规则与发现范围；Git 增强证据随后也已迁入 core，并在缓存命中后重新查询当前上下文。先完成具体业务边界，不新增插件框架。
2. **缓存不止一种（预算后续已落地）。** preview cache、整根 junk 缓存和逐文件 listing 的目标不同，原设计文档中的“只存稀疏预览”已经不能描述现状。逐文件 listing 的名称、路径与多个 marker map 随文件量增长，现已补齐共享估算预算、逐根淘汰、有界持久化和原生历史/批次保留；具体范围见后续交付章节。不能因为结果行少就认为内存也少，也不能将估算预算说成 allocator RSS 的精确上限。
3. **工具调用边界（后续已落地）。** `sweepx-core::tools` 提供共享 `ProbeRunner`，工具答案有整批预算、单次时限、输出上限和取消；安装探测与报告共享快照。由工作线程调用，无后台管道读取线程。限制覆盖子进程执行与管道读取，不承诺文件系统操作或操作系统进程创建调用具有相同的硬实时上限。Windows Job 在启动后附加，不能保证捕获附加前主动逃逸的后代；读取期限不依赖这些后代关闭 stdout。
4. **缓存的活动状态解释（已分层）。** 整根缓存不持久保存 activity、staleFormats、Git 查询结果、classification、confidence 和 blockers。命中后按本次工具快照重新解释，证据不足为 unknown；项目规则先恢复基础 known_generated/medium，再用共享 Git 会话重新观察当前仓库、tracked 与 ignore 证据，不回放历史 ignored/high。遍历覆盖及候选内仓库边界作为文件系统事实独立保存，不能代替当前 Git 查询。工具所谓 live/stale 仅指当前报告的缓存位置，不证明没有进程持有文件。
5. **分类扫描与交互扫描分开。** `scan --tui` 已有根准入后进入浏览、按需详情扫描的基础；普通 junk CLI 仍是收集完再拼报告。后续已加入共享 classified observer、显式目录根的工作线程会话与 `junk --tui`，见文末；垃圾 TUI 实时消费有界事件，提供取消、稳定键选择、刷新及后台回收，macOS 历史缓存与文件索引复用随后已接入；系统自动发现与 Linux 临时对象展示也已接入，临时对象的 TUI 隔离预览、完整摘要确认和结果展示随后已接入；单大根的完整子树基础候选随后已支持提前输出，目标宿主运行验证仍待完成。

## 支撑后续 TUI 的目标接口

在 `sweepx-core` 内提供一个扫描会话，CLI 和 TUI 都只消费它，不把 UI 状态放进 scanner：

- 命令：开始、取消、提高可见目录优先级、刷新选中范围。
- 事件：阶段、进度、候选新增/修订、目录统计修订、错误、完成。
- 候选使用稳定键，单次扫描身份和 revision 单独保留；刷新必须显式替换旧证据。
- 队列必须有界；可合并进度及同一候选的旧 revision，不能丢最终结果、错误和终态。
- TUI 可立即展示旧缓存，但明确标记历史状态；最新结果逐项替换。用户选择与扫描线程解耦，删除时重新校验对象身份。

不要给普通缓存预览引入 durable event journal 写入依赖。可恢复执行/审计所需的持久日志与可丢弃的 UI 进度不是同一种可靠性要求。

## 大文件、重复文件与垃圾识别

初次审视没有实现大文件榜单、内容重复检测或规则覆盖扩展；大文件榜单和显式重复检测随后已交付，见 2026-10-02 章节。规则扩展已开始补结构标记与版本/误报测试，内容格式验证仍未完成。

- **大文件**：作为同一次元数据遍历的独立分析器，按阈值与有界 top-K 收集普通文件；保留逻辑大小、分配大小及覆盖状态。不能仅过滤现有截断后的 `ScanSummary.entries`，否则可能漏掉遍历后半段的大文件。大不等于垃圾。
- **重复文件**：单独显式启动内容读取阶段，先按大小分组、排除同一原生文件身份的硬链接别名，再分阶段读取和完整 hash，最后核验大小、身份与修改指纹。必须限制打开文件数、读取字节和并行度，并避开会主动下载的云占位文件。候选组不自动选择保留者，不自动删除。
- **垃圾规则**：优先覆盖可验证格式的工具缓存及明确可重建输出；泛化 `cache/tmp/build` 名称不能替代所有权、格式、上下文和活动证据。Git ignore 仅增强解释。规则正例、容易误报的用户数据反例以及不同工具版本都应共用测试集。

这三种分析应共享遍历事实，但分别产生“垃圾候选 / 大文件 / 内容相同组”，避免把业务含义压成一个可删除布尔值。

## 验证说明

工作区使用固定 Rust 1.98.0。执行格式检查、workspace clippy 和本机 workspace 测试；原有 macOS 移入废纸篓集成测试 `trash_moves_ordinary_paths_without_confirmation_in_machine_invocations` 卡在系统调用，已单独排除，不能将其记为通过。后续交付已补齐 Linux/Windows 的工作区交叉 lint；对应宿主运行时仍未复验。

原生缓存微基准可运行：

```sh
cargo test -p sweepx-core benchmark_batched_root_validation -- --ignored --nocapture
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

后续顺序：统一缓存预算（现已补齐，见文末验收记录）；随后下沉平台候选解释、重建当前 Git 证据并提供可取消、带有界事件队列的 junk 会话；大文件分析再接同一次遍历，重复文件检测作为独立、显式内容读取阶段。完成状态以验收清单及后续章节为准。

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
- [x] listing、marker 与多根缓存的统一字节预算、逐根淘汰及有界持久化读取；预算耗尽不能把缺失证据当作否定结论。
- [x] 平台垃圾规则与候选解释迁到可独立调用的共享服务；通用及 Linux `/tmp` 发现/分类/解释、有界浏览器/known-root 快照及路径绑定已下沉，整根候选缓存绑定当前分类上下文，避免遗漏新引入的候选。
- [x] 缓存命中后重建当前 Git 上下文及增强证据。
- [ ] 核心垃圾扫描会话：显式目录根已支持开始、取消、可见目录优先级、选中范围刷新，有界事件、稳定候选键及 revision；macOS 历史缓存与文件索引复用、系统自动根发现及 Linux 临时对象事实事件已接入；单个大根的完整子树基础候选已支持提前展示，目标宿主验证仍待完成。
- [ ] 垃圾交互 TUI：显式根已支持实时阶段/进度/候选、稳定选择、刷新历史标记及原生身份重验后的后台 Trash；macOS 历史缓存首屏和系统模式已接入；Linux 临时对象的交互隔离预览/精确确认/结果已接入；单大根的完整子树基础候选已支持提前展示，目标宿主运行验证仍待完成。
- [x] 同一次遍历中的独立大文件分析：阈值、有界 top-K、逻辑/分配大小和覆盖状态；core/CLI 已接入，见 2026-10-02 交付章节。
- [x] 显式内容阶段的重复文件检测：硬链接别名排除、分阶段读取和完整 hash、身份/变化复验、资源预算及原生云占位保护；analysis/core/CLI 已接入，目标宿主与真实 provider 运行缺口见文末。
- [ ] 扩展有格式、所有权、上下文依据的垃圾规则，覆盖正例、用户数据误报反例及不同工具版本。

Linux/Windows 宿主运行时、MSVC 与系统 Trash 挂起用例仍是独立验证缺口，不因性能测量通过而视为完成。

本阶段交付验证（2026-10-01）：原生 platform 测试、受影响 crate lint、格式和工作区 clippy 通过；工作区 719 项通过、0 失败、2 项基准 ignored，1 项已诊断系统 Trash 挂起显式排除。共享历史查询阶段的 Linux GNU/Windows GNU 工作区交叉 lint 已通过；后续 run loop 改动仅在 macOS cfg 内，不改变这两个目标编译的源码分支，复用对应通过结果。53 份 Markdown 检查、23 项文档检查器测试和 5 项基准验证器测试通过。未执行 Linux/Windows 宿主运行时或 MSVC 验收。


## 分类元数据预算（2026-10-01）

分类目录行、file/directory marker、coverage/path 与可选 listing 已接入同一内存估算预算，默认整批 256 MiB、单根 128 MiB，通过 `ScanResourceLimits` 配置。模型行计入 native lineage、字符串与 Vec 的容量，不通过 JSON 大小或文件逻辑长度猜测内存；索引采用固定容器估算额度。这不是 allocator RSS 或文件分配大小的精确上限。

必需证据入场前可清除可重建 listing/covered-path 索引以腾出预算。若必需证据依旧无法保留，本根后续分类停止，避免缺失 marker 让否定谓词错误匹配；资源边界使结果为 partial，human 明确提示可能遗漏，仍继续现场遍历和原有字节累计。缺失 covered-path 不保存成整根命中。可选 listing 不要求保存每个文件；未知条目下次重新观察，既有已验证长度在预算内进入下一代。

内置分类器只保留本次规则实际需要的项目文件 marker，名称集合从规则字节加载结果派生；自定义分类器默认仍保留全部 marker，以保持其契约。目录名称只保留一次 identity-keyed lineage；不再在 listing 的旧 dirs 字段中重复存储。回归覆盖零预算下的否定谓词、可选索引压力下保住必需 marker、自定义规则 marker 变更，以及 native lineage/预留容量计入模型内存估算。

本条完成扫描中的共享预算；持久化文件的有界读取、跨根预算与逐根淘汰还未完成，上一节对应验收项暂不勾选。

缓存预算核对还发现了路径歧义：不同非 UTF-8 Unix 原生目录名可能得到相同 display string。逐文件索引不再把 lossy display path 当作键；无法无损表达的目录不保存 covered-path/listing，而原生身份和规则 marker 仍保留，后续现场观察。独立回归使用两个不同原生路径产生同一个 display string，证明不会串用文件长度。

本阶段验证：工作区 724 项通过、0 失败、2 项基准 ignored，系统 Trash 挂起用例仍单独排除；格式、工作区 clippy、Linux GNU/Windows GNU 工作区交叉 lint 和 53 份 Markdown 检查通过。受影响 crate 提交前检查为 359 项通过、2 项 ignored、1 项 Trash 排除。

相同 release、8 根/8,192 文件、每状态 3 次的 [预算后原始复测](junk-benchmark-metadata-2026-10-01.json)通过独立候选与逻辑字节核验：冷扫中位数 116.3 ms、整根命中 29.0 ms、单文件变化 48.8 ms。OS 缓存不受控；热扫与上一轮 23.3 ms 存在宿主/事件服务波动，不能宣称预算本身提高了整机速度。这次验证的是资源受限时的诚实降级和正常负载的结果等价性。

## 有界磁盘缓存与逐根索引（2026-10-01）

根记录 schema v5、逐文件索引 schema v4 现在同属每根独立的文件组；各自保留扫描前游标、原生 device/inode 和覆盖证据。之前按设备写索引会让同一卷上的根互相覆盖，尤其只刷新部分根后丢失其他根的逐文件复用。现在逐根捕获，只复制预算内的可选长度；目录仍重新枚举，未记录的孩子现场检查。回归在同卷上交替刷新两个根，并用普通 metadata 核对复用长度。

持久化预算区分编码字节和保留数据估算：单文件 4 MiB、单根文件组合计 8 MiB、受管文件合计 64 MiB、最多 256 根；每次调用两层缓存共用 16 MiB 输入和 128 MiB 保留估算额度。解析前还有编码大小的扩张准入额度，解析后计入字符串、集合和 native lineage 容量；不宣称 allocator RSS 的硬上限。完整候选记录不能截断为完整结果，写入超限即失败；可选长度索引缺项则现场观察。序列化流直接写入有界临时文件，不先分配完整 JSON 副本。

存储逐组件 no-follow 打开目录，要求最终目录和常规缓存文件属于当前用户且私有；文件额外拒绝硬链接别名及特殊类型。独占临时文件、同目录原子 rename 和非阻塞 advisory lock 保护发布及淘汰。持有的父目录句柄保留 native authority，不由 display path 重建。原子发布不承诺缓存是可恢复操作日志；正常发布后执行磁盘预算，故临时写入可能短暂多占一个受限文件，崩溃和 I/O 失败时不能承诺磁盘上限立即成立。下次淘汰清理受管孤立临时文件及已退休的旧索引，未知文件保持原样。

淘汰按根组合的最近读取时间进行，不再删除所有本次未请求的根；atime 只决定缓存保留顺序，不是扫描事实的有效性证据。枚举淘汰清单只保留至多根数上限加一项，先观察同组两个成员，避免 enumeration 顺序改变计数或分组。独立 walk/metadata 回归核对根数、组合和磁盘字节。

另修复请求范围变化：多个重叠根扫描时，候选归属最深根，父记录不含归给子根的候选。父记录因此绑定本次嵌套根集合；随后仅请求父根时拒绝旧记录，防止把漏候选的报告说成整根命中。逐文件索引本身允许缺项，范围变化后仍会现场补查。

本阶段补齐持久化读取/写入预算和逐根淘汰；原生事件历史收集和跨根变更索引的保留量还需核对，统一预算验收项暂不勾选。共享分类、当前 Git 证据、扫描会话、垃圾 TUI、大文件、重复文件和规则扩展仍待继续。

淘汰排序回归曾发现：即使显式设置旧 atime，宿主后续访问仍可改变时间戳，不能把设值后的顺序当作固定事实。排序测试改用受控的元数据响应；文件存在、成组删除和编码字节仍经真实目录枚举/metadata 独立核对。fixture 显式设为私有缓存目录，保留生产对非私有目录的拒绝。

性能复测（2026-10-01，arm64 macOS、Rust 1.98.0 release，8 根/8,192 文件、每状态 3 次，OS 缓存未清空）：[未缓冲临时实现](junk-benchmark-storage-unbuffered-2026-10-01.json)暴露序列化逐 token 写入的额外成本，冷扫缓存写入阶段中位数 268.4 ms；固定 64 KiB 缓冲后的[原始结果](junk-benchmark-storage-2026-10-01.json)为 29.5 ms。缓冲版完整进程中位数冷扫 133.3 ms、整根命中 39.6 ms（每次 8/8）、单文件变化 47.9 ms（每次 7/8）；事实及受控逻辑总量独立核验通过。未缓冲轮次同时有交叉构建和显著启动延迟，不能用其进程总耗时推断整机加速；相比上一轮热扫 29.0 ms 也没有新的提速结论。

本阶段交付验证：格式、CLI 及工作区 all-targets/all-features clippy 通过；工作区 734 项通过、0 失败，2 项原有基准 ignored，命令仍显式排除 `trash_moves_ordinary_paths_without_confirmation_in_machine_invocations` 的系统 Trash 挂起，该原生操作未验证。Linux GNU/Windows GNU 工作区交叉 lint 通过；随后修改仅在 macOS cfg 内及相应文档/测试，复用其未变目标分支的结果。未运行目标宿主测试或 MSVC。53 份 Markdown、23 项文档检查器和 5 项基准验证器测试通过。CLI 提交前检查为 124 项通过、1 项原有基准 ignored、1 项 Trash 排除。

## 有界变更历史与共享失效索引（2026-10-01）

FSEvents 查询输入现在最多 256 个绝对、可无损表达的 UTF-8 根及 1 MiB 路径字节，在原生分配前检查；超大 deadline 也拒绝溢出。只查询实际有缓存消费者的根，未缓存的额外请求根继续现场扫描，不扩大原生历史输入。超出绑定预算的嵌套根不能借用祖先索引。

回调保留量限制为 65,536 个事件及 16 MiB 估算字节，计入路径与 Vec 预留容量；超限、缺失数组或无法无损解释的路径会释放已有 payload 并永久标记本次历史不可用。缺口后可立即结束查询，不再为不可用的历史等完成标记；有效历史仍须 HistoryDone。整个已交付回调批次的 flags 都会处理，完成标记之后的同批缺口或超限也不能变成成功。

核对当前 SDK 的 `FSEvents.h` 后补齐 EventIdsWrapped：计数器回绕意味着旧 sinceWhen 无效，不能以新事件 ID 较小为由认为没有变化。挂载/卸载事件同样拒绝复用。回归使用 SDK 中的字面 flag 值作为输入，覆盖回绕、挂载及完成标记后的缺口。

各根的完整历史不再复制成独立 changed set。共享 BTreeMap 按路径保留最大事件游标，各消费者继续用自己的原游标比较；原生根重绑定是独立的无条件失效值，不能伪装为 MAX 事件，否则 MAX 游标会漏掉它。该 map 最多 65,536 个不同路径、16 MiB 估算字节，并占用两层缓存读取后剩余的 128 MiB 保留额度；根键/节点辅助存储先占用估算额度。缺项不能被解释成没有变化：建立索引失败会清除两层命中，回到现场观察。路径和 basename 查询改用借用值，避免为每个文件分配查询键。

独立验证包括：对每个路径及多种游标，用原始事件逐项遍历作 oracle，核对祖先、后代、相邻名字、重复路径最大游标及旧后代之后的新事件；以真实 Vec/字符串容量核对历史字节预算，验证超限后释放且不会恢复；验证原生重绑定对最大游标仍无条件失效。缓存根范围键 Vec 的预留容量也纳入已有保留估算，避免只统计已填充元素。

本阶段验证：工作区 745 项通过、0 失败，2 项原有基准 ignored，1 项已诊断系统 Trash 挂起仍由 `--skip trash_moves_ordinary_paths_without_confirmation_in_machine_invocations` 显式排除，该系统操作未验证。格式、受影响 platform/CLI 及工作区 all-targets/all-features clippy 通过。修改均在 macOS cfg 内；复用前一阶段未变的 Linux GNU/Windows GNU 工作区交叉 lint 结果，不代表目标宿主运行时或 MSVC 已验收。

相同 arm64 macOS、Rust 1.98.0 release，8 根/8,192 文件，每状态 3 次、OS 缓存未清空的[有界历史复测](junk-benchmark-history-bounded-2026-10-01.json)通过候选及逻辑字节独立核验：完整进程中位数冷扫 153.9 ms、整根命中 46.4 ms、单文件变化 46.7 ms。未得到新的热扫提速结论；本次收益是失效历史不再按根复制、明确内存准入与完整回退。

本阶段发现的原生层收尾是 `OpenDirectory::bulk_attributes` 跨批次累计，以及缓存普通文件覆盖当前枚举类型的风险；后续修复与验收见下一节。

## 有界原生批次与当前文件证据（2026-10-01）

macOS 属性提示现在只保留当前返回批次及至多一个 lookahead；下一次枚举释放旧提示，较早记录的延迟检查退回 retained parent 下的 no-follow `fstatat`。原生 cursor 另保留至多一页有界数据。扫描器先处理当前批次的 deferred children，再请求新批次，因此不会为了提前枚举而丢失仍待消费的提示。该辅助状态的上限由目录批次条数、字节限制和固定原生页共同约束，不再随整目录增长，也不冒充分类预算或 RSS 精确计量。

文件缓存计划现在只是复用提议：路径和原生 basename 必须与当前记录一致，backend 还须从当前 handle-relative 枚举事实确认普通文件、同一设备和相同逻辑长度。没有证据的 backend 默认退回普通检查。macOS 复用已有批量属性，不给每个命中文件额外打开句柄；目录、链接、变化长度与错位计划均现场检查。历史有效性检查仍保留，普通长度复用不建立执行身份，也不证明分配、硬链接唯一性或可释放量。

回归通过普通 `read_dir` 和 `symlink_metadata` 独立核对名称集合、类型及逻辑总量，覆盖条数/字节两种批次边界、lookahead 的连续消费、旧记录在新批次之后的变化与回退、缺少当前 backend 证据，以及旧文件计划不能隐藏目录子树或链接。资源预算验收项至此完成；共享分类、Git、扫描会话、垃圾 TUI、大文件、重复文件和规则扩展仍未完成。

相同 arm64 macOS、Rust 1.98.0 release，8 根/8,192 文件，每状态 3 次、OS 缓存未清空的[原生批次复测](junk-benchmark-bulk-bounded-2026-10-01.json)通过候选及逻辑字节独立核验：完整进程中位数冷扫 245.6 ms、整根命中 31.2 ms（每次 8/8）、单文件变化 67.8 ms（每次 7/8）。冷扫遍历阶段中位数 85.9 ms，变化后遍历 10.4 ms；本轮没有新的整机提速结论，交付的是有界保留和复用前的当前类型证据。

交付验证：受影响 platform/scanner 测试 134 项通过、1 项原有基准 ignored；格式和受影响 crate/工作区 all-targets/all-features clippy 通过。初次工作区运行在旧预览缓存夹具的 `NotFound` 处中断，后续步骤未运行；独立时钟采样证明时间戳不唯一，夹具改为原子独占创建，详见[宿主记录](../development/historical-host-notes.md#cache-test-directory-isolation-2026-10-01)。修复后的工作区完整运行 749 项通过、0 失败、2 项原有基准 ignored，1 项系统 Trash 挂起用例仍显式排除，未验证该系统操作。Linux GNU/Windows GNU 工作区交叉 clippy 通过，包括目标测试代码，未运行目标宿主测试或 MSVC。53 份 Markdown 检查、23 项文档检查器及 5 项基准验证器测试通过。

## 共享平台 catalog 与候选解释（2026-10-01）

平台规则资源逐字节迁入 catalog，声明式 browser/known-root 类型与原有严格语义校验一起迁移。新增调用者提供的 JSON 准入：解析前限制 128 KiB，最多 64 条规则及各嵌套列表 64 项；未知字段、路径逃逸、错误 root-kind/depth/match-kind 组合、重复 ID 或缺少依据均拒绝。CLI 的缓存摘要仍绑定实际内嵌加载字节，不增加手维护 hash，也不改变现有风险及机器字段。

core 的 `junk::platform` 接管工具及平台根发现、活动/格式解释和组合分类器；`junk::candidate` 接管报告类型、大小证据选择、项目/平台候选拼装及缓存动态解释。CLI 的新扫描调用 `JunkService::with_platform` 和 `interpret`；缓存只转换存储事实，再调用 `refresh_candidate_interpretation`。缺少或不一致的原生目录事实返回 `None`，公开解释入口不会因缺失 locator 而 panic。工具探测继续共享有界 invocation 快照，现允许调用者传入取消 token。旧 Git 置信度仍显式清除，当前 Git 重建尚未实现。

直接调用 core 的受控 fixture 回归同时产生 Cargo target 和 pip cache 候选，核对规则 ID、来源扫描 ID、基础置信度、活动状态和独立 metadata 尺寸；文件、链接、缺少 locator 与未知决定不能被解释成目录候选。平台 JSON 编辑回归覆盖规模、严格字段、路径及组合契约。原有 15 项发现/规则/尺寸测试跟随模块迁移，名称与迁移前源码独立对照；其中浏览器状态正例改为注入临时目录 anchor，并与完整目标集合比较，保留用户数据反例，不再要求本机装有 Chrome/Edge/Postman。

此阶段没有增加 crate；CLI `main.rs` 从 6,318 行减少到约 3,900 行（包括测试），core 的普通依赖仍不含 TUI/ratatui/crossterm。包清单包含新模块和平台规则资源；资源与迁移前 Git 版本的 bytes 比较完全一致。没有进行 registry 构建或发布。

共享服务验收仍保留未完成：Linux `/tmp` 的专用 native 测量、引用证据与报告拼装仍在 CLI，下一步迁移时必须保持它与清理预览共用同一实现，并处理跨 crate 测试夹具。浏览器/known-root 匹配也仍沿用原来的现场发现调用；后续在共享服务内将这些结果纳入本次有界快照，避免逐候选重枚举，核对根自身与嵌套根的路径绑定。不得把缓存预算验收误读为所有发现路径已完成资源审计。Git、会话、TUI、大文件、重复文件及规则扩展的清单状态不变。

本阶段验证：受影响 catalog/core/CLI 253 项测试通过、1 项原有基准 ignored、1 项系统 Trash 挂起显式排除；工作区 752 项通过、0 失败、2 项原有基准 ignored，同一 Trash 用例仍排除。格式、受影响及工作区 all-targets/all-features clippy 通过。交叉检查最初发现 CLI 的 macOS-only 导入未正确 cfg，修正门控后 Linux GNU、Windows GNU 工作区交叉 clippy 均通过，包含目标测试代码；未运行目标宿主测试或 MSVC。本次没有端到端性能测量，不声称模块迁移带来整机提速。

## 共享 Linux 临时对象发现与报告（2026-10-01）

Linux `/tmp` 的原生测量、当前用户引用证据及报告解释已迁入 `sweepx-core::junk::linux_temp`。CLI 报告与清理预览导入同一模块，不复制原生遍历或改变删除入口。公开测量是待复验的事实，不是执行 permit；候选仍保留系统范围引用不可证明的 blocker，部分发现另外保留 incomplete 标记。原有规则 ID、风险、活动代码、大小含义和报告身份生成保持不变。

进程及未来时钟夹具放入现有 `sweepx-fixtures::linux_temp`，仅由 core/CLI 的 Linux 开发依赖使用；没有新增 crate 或生产依赖。对照迁移前 Git 源码，原生生产逻辑在文档、可见性、rustfmt 和夹具导入规范化后完全一致，15 项原有原生测试名称保留；报告拼装在类型导入规范化后也完全一致。新增直接调用 core 的 Linux 回归从受控文件经 discover 到 report，使用普通 no-follow metadata 交叉核对设备/inode、逻辑长度与 Linux stat 分配字节，核对预览测量一致性和部分覆盖 blocker。

本次只完成业务迁移；Linux 原生目录名集合、递归 measurement map 和进程表读取的资源保留仍需进一步审计，不将此前缓存预算验收扩大到它们。浏览器/known-root 有界快照及路径绑定继续作为共享服务收尾，验收项暂不勾选。

交付验证：受影响 core/CLI/fixtures 的本机测试 242 项通过、1 项基准 ignored、1 项系统 Trash 挂起显式排除；工作区 752 项通过、0 失败、2 项原有基准 ignored，仍以 `--skip trash_moves_ordinary_paths_without_confirmation_in_machine_invocations` 排除该原生行为。格式、受影响及工作区 all-targets/all-features clippy 通过；Linux GNU、Windows GNU 工作区交叉 clippy 通过，包括新增 Linux 测试代码。core/fixtures 包清单包含迁移模块；53 份 Markdown 检查与 23 项检查器测试通过。宿主为 arm64 macOS，未安装 Docker、Lima 或 QEMU Linux 运行器，Linux 原生测试尚未运行，Windows 宿主/MSVC 和系统 Trash 行为也未验证；不将交叉 lint 表述为运行时验收。本次未测端到端性能，模块迁移没有新的加速结论。

## 已知缓存根自身的路径绑定（2026-10-01）

修复原生路径重建的根行分支：根行没有 parent recipe，captured absolute path 已经是对象自身的路径，不能再次附加根 basename。旧实现把单独扫描的 `…/Homebrew` 比较为 `…/Homebrew/Homebrew`，使其漏掉 known-root 分类；嵌套目录仍按 retained native recipe 的原有顺序拼接。根为 `/` 时不重复加分隔符。路径来自已验证 locator，不使用 display string，也不授予删除权限。

回归以独立 read_dir/symlink_metadata 收集受控目录全集，分别扫描宽根和已知缓存目录本身，核对所有目录 native path。移除根行修复后，该回归在根路径匹配处失败；恢复修复后通过。最初测试误用只保留候选行的 junk scan 入口而得到空集，已改为完整 scan 入口，不放宽全集相等断言。

提交前格式、core all-targets/all-features clippy 及 core 113 项本机测试通过。改动均在 macOS cfg 分支，Linux GNU/Windows GNU 未改变编译分支，复用前一阶段的工作区交叉 lint 结果；目标宿主/MSVC、系统 Trash 仍未验证。交付边界工作区 clippy 通过，工作区测试 753 项通过、0 失败、2 项基准 ignored，仍显式排除已诊断的系统 Trash 挂起用例，该行为未验证；53 份 Markdown 检查通过。

## 有界布局发现快照（2026-10-01）

浏览器 profile/partition、Chromium render cache 和 macOS known-root 发现已进入本次共享快照。已声明的路径通过现有 HostPlatformScanner 的 no-follow 原生准入；必要 marker 相对 retained parent 检查，不读取 payload。根选择复用捕获的路径，分类比较原生 path、文件身份、filesystem/mount 身份和 scanner fingerprint，不逐候选重枚举。已知根仍支持自身和较宽扫描范围中的嵌套目录；发现后被同名新对象替换的根不能沿用旧身份。原有独立 Chromium 枚举改为共用声明式 browser layout evaluator，不复制一套发现算法。

布局发现单独限制最多 4,096 个不同目录探测（包括不存在的路径）、16,384 条返回枚举记录、1,024 个跨规则根引用、8 MiB 保留估算。路径/原生编码容量、memoization 节点、profile 列表和规则根表均计入估算；共享 Arc 不复制完整事实，列表只保留选中的 profile/partition 名称。原生每批最多 256 条/64 KiB，最多同时保留一个枚举 cursor 或 root 加一个 transient marker-directory handle。5 秒合作期限及取消检查覆盖调用间边界，不能中断阻塞的 OS 文件操作，也不代表 RSS 精确上限。工具及 Linux 临时对象发现的其他保留路径不因此视为已审计。

预算、取消、期限或原生观察失败保留全局 incomplete 原因，已验证的正向根不丢弃，缺项不解释成 absence proof。CLI human 提示可能遗漏；JSON 新增 `layoutDiscovery.complete/incompleteReason`，总体为 partial 并返回 4，既有机器字段和风险值保持不变。不完整布局不写整根候选缓存，文件长度索引仍只保存完整的文件系统事实。旧 browser/known-root 缓存行必须重新匹配本次快照，否则拒绝回放。

共享服务验收仍不勾选：旧整根缓存行无法补出当前环境/启用平台规则新引入的候选，下一步需要绑定当前分类上下文并在变化时拒绝旧整根候选命中，逐文件事实缓存可继续复用。单独更新旧候选的活动字段不足以证明分类范围相同。其后继续 Git 当前证据、会话、TUI、大文件、重复文件和规则扩展。

受控回归覆盖 profile 快照只枚举一次、下一调用发现新 profile、零/条数/根数/字节预算、取消和期限、链接祖先及 marker 拒绝、宽根与根自身的 native binding、同名对象替换，以及旧缓存行不能沿用旧根身份。原先要求宿主装有 Postman/LarkShell 的规则测试改为受控 partition、显式 profile、枚举 profile 和共享 cache 全集比较，保留用户数据反例。CLI 集成回归在隔离 HOME 的子进程中制造浏览器祖先链接，同时保留真实 known cache，独立验证既有正向候选、未跟随链接、partial 字段和退出码。

首次受影响矩阵在原有 `junk_temp_cleanup_requires_a_foreground_human_confirmation` 挂起，后续 core 步骤未运行。对本次子进程采样确认：它在 normalize/discovery 的原生 admit_root/open 阻塞，尚未到达前台确认拒绝。仅终止该已确认的测试子进程后，矩阵如实失败。修复将清理/Trash 的 human/foreground 前置条件提前到根发现之前，入口内部仍调用同一验证器；保留并加 10 秒上限的原有拒绝测试在修复后通过。此项证明无效调用不再触发发现，不证明真实系统目录的 open 不会阻塞；原生合作期限仍保持上述边界。

交付验证：修复后受影响 core/CLI 234 项测试通过、1 项基准 ignored、1 项原有系统 Trash 挂起显式排除；工作区 758 项通过、0 失败、2 项基准 ignored，同一 Trash 用例仍排除。随后仅补缺失 anchor 的不完整语义，core 118 项及 CLI 部分发现集成回归通过，其余未变测试复用上述工作区结果，不称为再次完整矩阵。格式、受影响及工作区 clippy、Linux GNU/Windows GNU 工作区交叉 clippy 通过；core 包清单包含布局模块，仍为 17 个 crate；53 份 Markdown 检查及 23 项检查器测试通过。交叉检查包含目标测试代码，未运行 Linux/Windows 宿主测试或 MSVC；系统 Trash 行为未验证。本阶段没有端到端性能计时，只证明发现枚举不再按候选重复及结果/资源契约，不宣称整机加速倍数。


## 整根缓存绑定当前分类上下文（2026-10-01）

根记录升级到 schema v6，在原有加载规则字节、原生根身份、嵌套请求范围和事件历史校验之外，绑定 core 组合分类器产生的本次上下文摘要。项目规则以实际准入字节计算摘要；平台规则将当前启用的完整规则结构及顺序流式写入 hash，CLI 同时保留对内嵌原始规则字节的校验。工具匹配位置和浏览器/known-root 的 native path、文件身份、filesystem/mount 身份及 fingerprint 进入范围绑定，不能只比较旧候选行。列表按无损路径排序，原生枚举顺序不改变摘要；规则顺序仍决定平局优先级。

项目扫描与系统扫描、工具候选位置或布局原生身份变化时，旧整根候选记录在历史查询前拒绝，包含空候选记录。未知布局覆盖、缺少所需规则证据或摘要预算不足同样拒绝读取/写入候选记录，继续现场分类；独立文件长度索引仍按自身身份、覆盖与历史校验，复用同一次历史查询。动态工具 activity 不作为持久有效性证明，仍在本次解释时重建；Git 重建留在下一项。摘要有 1 MiB 流式输入、每规则至多 1,024 个排序引用及单个工具路径 64 KiB 的独立准入，超限仅放弃此缓存优化，不把完整现场分类误报为 partial。当前摘要绑定整次调用的范围，任一发现范围变化可以使全部候选根记录失效；这是保守的缓存取舍，文件长度索引仍独立复用。没有新 crate 或依赖。

回归用实际 core 扫描得到零项目候选并写入缓存，再启用平台规则；受控完整空历史保持文件系统证据相同，旧上下文可命中，新/未知上下文必须拒绝整根命中，现场扫描产生新候选。普通 read_dir/metadata 独立核对目录全集和复用文件长度。另覆盖规则启用/内容、项目加载字节编辑、发现范围变化、顺序无关、同名对象替换，以及动态 activity 改变时摘要不变。旧 schema v5 不沿用，文件索引 schema v4 不变。

共享服务这项验收完成。后续依次为缓存命中后的当前 Git 证据、核心扫描会话、垃圾 TUI、大文件、重复文件与规则扩展。其他工具发现路径、Linux 临时对象资源保留审计及目标宿主/Trash 验证缺口仍保留，不因这项摘要预算完成而视为已关闭。

交付验证（arm64 macOS、固定 Rust 1.98.0）：受影响 catalog/core/CLI 262 项测试通过、1 项原有基准 ignored；工作区 761 项通过、0 失败、2 项原有基准 ignored。两套命令仍显式排除已诊断的 `trash_moves_ordinary_paths_without_confirmation_in_machine_invocations` 系统 Trash 挂起，该行为未验证。格式、受影响及工作区 all-targets/all-features clippy、Linux GNU/Windows GNU 工作区交叉 clippy 通过；53 份 Markdown 检查通过，core 打包清单包含新 context 模块。交叉检查包含目标测试代码，不代表目标宿主运行时或 MSVC 验收。初次编译发现新增测试将 u128 长度与 u64 metadata 长度直接比较，修复显式转换后通过；未排除该回归。本次没有端到端性能计时，不宣称新增摘要提高整机扫描速度。


## 当前 Git 证据与缓存命中（2026-10-01）

Git 解释迁入 `sweepx-core::junk::git`。冷扫与整根缓存候选共用一批 `GitEvidenceSession` 预算：先丢弃旧解释，再由当前 native locator 重建路径，no-follow 准入并检查对象/filesystem/mount 身份，逐级寻找最近父仓库，范围允许位于选定根之外；marker 相对 retained parent 检查，gitfile、链接、挂载或观察不确定性均不能增强置信度。Git 的实际 worktree/git-dir 查询必须与本次原生观察相符，环境中的 GIT_DIR/WORK_TREE/INDEX_FILE 等重定向参数被清除；tracked/ignore 查询保留现有原生路径、`./` 前缀及 literal index pathspec，避免 shell、通配或 pathspec magic。查询前后复验仓库及 `.git` 原生绑定；这不是 Git 配置/index/ignore 的原子快照，也不提供任何删除授权。

根 schema v7 每候选仅增加遍历覆盖及是否包含仓库的两个标量事实；只有原有完整根覆盖、分类上下文和事件历史成立时才可复用。当前仓库位置、ignore、tracked、置信度和 blockers 不持久保存。分类扫描保留稀疏 `.git` 文件行，并让这些文件退回当前原生检查，避免 worktree/submodule 边界被普通文件裁剪或长度复用隐藏；普通文件仍保持原有缓存快路径。独立文件索引 schema v4 不变。旧上下文先降回基础解释，当前查询成功才增强；失败仍报告已知项目候选，不把未知 Git 证据当作没有 tracked 或仓库。平台及 Linux 临时对象的分类不会被 Git 刷新重写。

默认最多 65,536 个借用 lineage 节点、8 MiB 保留估算和 1,024 次原生目录准入。Git 进程共用现有 ProbeRunner：整批 5 秒、单次 2 秒、最多 256 次启动、每次 stdout 64 KiB；取消、超量输出与超时均拒绝使用答案并回收本次进程。没有另建管道线程或子进程轮询实现。native path 重建最多 256 个 component 和 64 KiB 路径，逐个追加，不复制所有祖先路径；原生 deadline 仍是调用间合作检查，不能中断阻塞 OS 调用。超大不可表示的工具期限现拒绝启动，不能溢出 Instant。仓库发现共享本次快照；每候选的 scope/tracked/ignore 查询保留当前检查，计入同一有界预算。

受控回归包含实际磁盘根记录命中后当前 Git 重建，以及只修改根外 excludes/index 时同一遍历事实由 high 降回 medium/产生 tracked blocker。普通目录枚举、metadata 和原始文件内容独立核对选定根没有改变。另覆盖 `.git` 文件与链接、嵌套 gitfile、同名对象替换、伪造 display path、未知扫描事实、lineage/内存/原生次数/期限/取消降级，以及外来 GIT_DIR/GIT_WORK_TREE 不得改变已绑定仓库。原有 ignore/已跟踪/不可用/嵌套仓库四项 CLI 契约保留，新增 gitfile、外来仓库环境及当前 GIT_CONFIG_GLOBAL 三项；配置选择变量保留，使用 Git 自身查询作独立 oracle 验证修改根外 excludes 文件后的解释。初次复用解释回归暴露 tracked blocker 残留，已清除旧 Git blocker 后按当前结果重建，不放宽断言。

Git 项完成后，继续核心扫描会话、垃圾 TUI、大文件、重复文件和规则扩展。工具/Linux 临时对象资源审计及目标宿主/系统 Trash 验证缺口仍保留。没有新 crate，没有端到端性能计时，不将增加当前 Git 查询说成扫描提速。

交付验证（arm64 macOS，固定 Rust 1.98.0）：工作区测试 767 项通过、0 失败、2 项原有基准 ignored；随后修正 Git 环境变量隔离范围并增加当前配置选择回归，最终受影响 scanner/core/CLI 294 项测试通过、0 失败、1 项基准 ignored，其余未变测试复用上述工作区结果，不称为再次完整矩阵。两套命令仍显式排除已诊断的 `trash_moves_ordinary_paths_without_confirmation_in_machine_invocations` 系统 Trash 挂起，该行为未验证。最终格式、受影响及工作区 all-targets/all-features clippy、Linux GNU/Windows GNU 工作区交叉 clippy 通过；交叉检查包含目标测试代码，未执行对应宿主运行时或 MSVC 验收。53 份 Markdown 检查通过，core 包清单包含新 Git 模块；未发布包，也未验证 registry 依赖构建。

## 核心会话的实时遍历接缝（2026-10-01）

`ClassifiedScanObserver` 与 core 的 `scan_junk_with_observer` 复用现有分类 sink、规则 evaluator、原生批次和结果构造，不另外扫描或重写分类器。调用者传入取消 token；批次进度、目录统计、边界和已保留候选通过借用回调交给工作线程中的消费者。边界及结束观察独立于 summary 的日志截断；回调必须短且自行限制复制数据，现阶段不提供任何内置队列。扫描错误仍由返回值处理，遍历 `Finished` 不代表输出存储或后续 Git 解释已经完成。

每个提交的目录批次提供大小和计数的 lower-bound 统计，不复制 hard-link 去重集合，不将尚未访问的子树说成 complete。最终候选沿用原有的根遍历结束后分类：必须先具备本根完整 marker 观察，不能用途中缺失 marker 做否定匹配。因此这一接缝能实时报告遍历状态，并在各根完成时报告基础候选，尚不能在单个大根中提前交付完整候选解释。普通非观察扫描不生成这些临时统计。

可见目录偏好在下一调度轮读取，只选择 frontier 中已经准入的目录能力，优先推进对应目录、祖先或后代；无关路径保持原有深度优先顺序。偏好不增加根、不重开 display path、不绕过 no-follow/mount/预算检查，已在运行的批次不被强制抢占。取消结果由 caller token 决定，避免被截断的 progress log 或最终 `Finished` 覆盖为成功。

受控后端回归核对有/无 observer 的所有最终扫描事实完全一致，覆盖候选先于结束、日志零容量时仍收到边界和结束、批次中取消以及动态偏好实际改变已准入目录的调度顺序而保留覆盖。core 原生夹具用普通 `read_dir`/`symlink_metadata` 独立核验一项 8 字节文件的候选总量，并验证扫描前及扫描中取消返回 cancelled。初次编译发现测试把 typed `ExitCode` 与 u8 比较，修正类型后保留原断言。

核心会话验收项仍未勾选：下一步需要工作线程所有权、有界且可合并的队列、稳定候选键/revision、选中范围刷新及旧证据替换，并将当前解释与 Git 阶段纳入显式终态。随后才能接垃圾 TUI。没有新 CLI/TUI 功能或性能加速结论，没有新增 crate。

交付验证（arm64 macOS，Rust 1.98.0）：受影响 scanner/core 177 项测试通过，工作区 773 项通过、0 失败、2 项原有基准 ignored；工作区命令继续显式排除已诊断的 `trash_moves_ordinary_paths_without_confirmation_in_machine_invocations` 系统 Trash 挂起，该行为未验证。格式、受影响及工作区 all-targets/all-features clippy、Linux GNU/Windows GNU 工作区交叉 clippy 和 53 份 Markdown 检查通过。交叉检查包含目标测试代码，未执行 Linux/Windows 宿主运行时或 MSVC 验收。没有端到端性能计时。


## 有界目录垃圾扫描会话（2026-10-01）

`sweepx-core::junk::session::JunkSession` 在现有 core crate 内拥有后台线程；开始操作只做有界输入检查及词法根规范化，规则加载、平台上下文发现、原生遍历和 Git 解释均在工作线程。原有 classified observer、规则服务、scanner 与 Git 证据实现被复用，不经过报告 JSON、终端绘制或事后事件构造，不增加 crate。调用者通过非阻塞消费或有期限的接收取得 revision 事件。

默认最多 64 个可靠队列事件、8 MiB 队列负载估算，另有各一个可合并进度/目录统计槽及一个固定大小终态槽；进度与统计计入同一字节预算。可靠候选、边界及错误具有背压，不能被进度挤掉或在取消时静默丢弃。阶段变更清除尚未消费的临时统计，终态在全部可靠观察之后交付。取消后仍需消费至终态，或者显式 close 放弃消费；close/Drop 唤醒阻塞发送者并取消，不在 UI 线程 join。进程同时最多四个工作线程，已关闭但被原生 OS 调用阻塞的线程仍占名额，退出观察发生在释放名额之后。原生文件访问仍是协作式取消。

候选旧状态与待提交状态合计默认最多 16,384 行和 64 MiB 保留估算；估算包括 native locator、字符串/Vec 容量及索引开销，不是进程 RSS 或磁盘空间。候选键以有界解码的无损原生路径、对象/filesystem/mount 身份和规则 ID 生成，排除 scan ID、修改指纹和 revision。相同对象路径/规则跨扫描保持键，新的观察仍有新的扫描身份。键及展示路径均不授予删除权限；Base 表示规则和遍历统计已观察，Current 表示本 revision 的 Git 解释已结束，未知证据及 blocker 仍保留。

选中刷新只接受本会话键，先后复验 captured root/relative parent recipe/目标目录的 no-follow、对象、filesystem 和 mount 绑定。目录内容变化可重新观察；对象替换、链接或身份不确定失败，不移除旧候选。当前实现为了保持父 marker、规则和祖先上下文，重新遍历所选候选原始根，再过滤到选中子树；它提供范围替换语义，尚不是高效的局部遍历。范围之外的旧行保留，Git 查询重新读取当前祖先仓库和 ignore/index。完整观察后才进入 Replacement，发送消失的旧键及 replaced=true；partial/cancelled/failed 均不以未见到的行证明不存在。Replacement 开始后的取消竞态由已完成观察的提交流获胜，close 仍可放弃整个消费。

边界完整性独立于 scanner 的保留日志：observer 在截断前记录不完整观察。元数据预算耗尽、边界保留预算为零或日志截断不能导致错误移除。回归通过受控原生目录、普通 read_dir/symlink_metadata 及独立 Git 命令核验精确逻辑字节、当前 ignore 变化、稳定键及新 scan ID；覆盖单槽背压、合并槽共用字节预算、可靠错误/终态顺序、worker 上限/退出、取消和资源失败、未知键/同名对象替换拒绝、partial 保留旧行及完整重扫移除。macOS 夹具卷拒绝非法 UTF-8 名称（独立宿主诊断为 EILSEQ），无损键反例使用模型 locator；它只证明编码不会混淆 lossy display，不宣称该卷支持那些文件名。零进度预算曾主动报告详情截断，因此本阶段的边界零保留回归保留正常进度预算；后续“进度保留与扫描完整性”修复了这项旧行为，并将该回归的两层日志预算都设为零，继续保留真正元数据不足时的安全断言。

本阶段仍不勾选整个会话验收项：当前输入是显式目录根，可选择本次平台解释，不包含系统自动发现根、Linux 专用临时对象分析、历史候选缓存回放或单个大根中的提前完整候选。垃圾 TUI、大文件、重复内容与规则扩展继续推进；未进行端到端性能计时，不能据此宣称扫描加速倍数。

交付验证（arm64 macOS，Rust 1.98.0）：工作区 784 项通过、0 失败、2 项原有基准 ignored；同一系统 Trash 挂起用例通过 `--skip trash_moves_ordinary_paths_without_confirmation_in_machine_invocations` 显式排除，未验证其宿主行为。格式、scanner/core/CLI 和工作区 all-targets/all-features clippy、Linux GNU/Windows GNU 工作区交叉 clippy（含目标测试代码）通过；53 份 Markdown 和 23 项文档检查器测试通过。未运行 Linux/Windows 宿主测试或 MSVC。测试曾因零进度预算夹具错误及 macOS 文件名限制失败，分别按实际语义修正夹具和改用独立模型层编码反例，没有移除安全断言。没有新增 crate 或发布。


## 显式目录根的垃圾交互 TUI（2026-10-01）

`junk --tui ROOT...` 进入空的实时垃圾视图，后台 core 会话提供扫描阶段、进度和各根结束后的候选。CLI adapter 将共享 Arc 候选转换成 TUI 的 presentation trait，不复制分类器或 native locator；core 仍不依赖终端库。界面按稳定键维护焦点和选择，Base 显示解释中，Current 显示当前；刷新开始将选中子树的旧行标为历史，失败/partial/cancelled 不把未见旧行删除，也不开放这些历史行的回收。保留逻辑大小的 known/lower-bound/unknown 状态，缺失合并进度显示未报告而非零；默认按逻辑大小降序，--sort path 按路径，未知大小排在已知零之后。展示焦点完整路径、规则依据及 risk/classification/confidence/activity/blockers 的稳定字段值，不把逻辑大小标成可释放量。

每个 UI tick 最多消费 128 个展示事件，再处理键盘；绘制最多 500 个可见行，不逐帧格式化所有候选。展示行上限 16,384、64 MiB 保留估算，最多选 256 项。展示预算耗尽会取消并保留 partial/historical，不能以丢失行制造完整结果。路径、规则及解释使用已有终端控制字符转义。方向键/Space/a/u 分别移动/选择/全选/清空；r 刷新已选或焦点范围，c 协作取消，d/Delete 请求所选当前且完整候选的 Trash，q/Esc 退出，Ctrl-C/SIGTERM 保留对应进程退出码并恢复终端。退出、设置失败或 I/O 错误均关闭 worker，不在 UI 线程等待阻塞 OS 调用。

回收是独立的单线程有界批次，进程最多一个 Trash worker，结果通道只有一个槽。保留原生行及完整覆盖作为预检，前后复用 core 的 no-follow root/relative parent/object/filesystem/mount 检查，再使用现有 TrashCandidate 逐项检查与提交；Windows 的捕获身份额外与所选行的完整 file ID 对照，不能把捕获时的新对象当作原扫描对象。重要/保护目录拒绝，不在工作线程等待 stdin；重叠祖先/后代选择在启动前拒绝。成功逐项移除行和展示的子候选，失败保留为历史且显示错误；单项失败不取消其他明确选中的操作，关闭可取消尚未开始的操作。现有系统 Trash adapter 的最终 pathname 检查到系统调用之间仍有竞态，此模式不引入 handle-relative 原子移动，也没有永久删除兜底。

本阶段提供可用的显式目录根交互切片，仍不勾选完整 TUI 验收项。历史缓存首屏、系统自动发现及 Linux 专用临时对象、单个大根中提前完整候选仍待做；选中刷新仍遍历原始根保留上下文。TUI 与 --system/--timings/机器输出/其他清理参数互斥，且不读写 candidate cache 或 durable operation journal。普通报告 CLI 的缓存行为保持原有实现。本阶段未做端到端性能测量，不把实时绘制等同扫描加速。

独立回归用注入键盘及 TestBackend 验证稳定选择/焦点、revision 过期拒绝、partial/预算耗尽禁止回收、刷新及后台回收结果后持续浏览、逻辑 lower-bound 与双语标签。中文宽字符的终端 padding cell 曾导致朴素串接 oracle 误报，按字符显示列宽解码后保留原标签断言。原生 adapter 测试以普通 stat/read 核对刷新后的字节，同名目录替换及 Unix 链接替换均在系统 Trash 调用前拒绝，原对象及替代对象 payload 保留；该测试不宣称系统 Trash 成功移动已验证。CLI 集成验证无终端、机器格式及模式冲突在扫描/状态写入前拒绝。


交付验证（arm64 macOS，Rust 1.98.0）：最终工作区 792 项通过、0 失败、2 项原有基准 ignored；同一系统 Trash 挂起用例以 `--skip trash_moves_ordinary_paths_without_confirmation_in_machine_invocations` 显式排除，其成功移动仍未验证。随后只加强排序测试中的已知零/未知对照并通过聚焦回归，未改变生产行为。格式、core/CLI/TUI 及工作区 all-targets/all-features clippy、Linux GNU/Windows GNU 工作区交叉 clippy（含目标测试代码）通过。初次 Windows 编译发现 EntryIdentity 字段私有，改用公开 accessor；测试 lint 及宽字符 oracle 的失败均已修正，没有屏蔽 cfg 或移除断言。53 份 Markdown 与 23 项检查器测试通过，CLI help 包含 --tui 并落实已有 --sort。

本机真实 PTY 用隔离目录核验最终二进制的完成候选视图；q、Ctrl-C、定向 SIGTERM 分别返回 0/130/143，终端属性和 alternate screen 恢复，payload 不变。初始诊断使用原始 ANSI substring 无法识别增量绘制，改用独立终端单元解码；父进程等待退出时必须持续消费输出，否则 macOS TCSADRAIN 可能阻塞；controlling-session leader 退出还会撤销 PTY，属性检查须在测试 wrapper 仍存活时进行。这些是 harness 修正，没有改动生产终端恢复逻辑。真实 PTY 未发送删除键；回收成功后的动态更新通过注入结果验证，实际 OS Trash 成功路径保留独立缺口。Linux/Windows 宿主运行时与 MSVC 未验收；没有新增 crate 或发布。

## 会话共享缓存与历史首屏（2026-10-01）

macOS 根记录、私有有界存储与逐文件复用从 CLI 迁入 `sweepx-core::junk::cache`，普通报告与后台会话调用同一实现；未增加 crate 或依赖。会话在规则准入之后、工具发现与历史校验之前发送 Historical 候选，再通过同一批读取预算加载文件索引并查询完整 FSEvents 历史。缓存的源字节摘要、原生根绑定及嵌套请求范围必须匹配；历史候选不要求当前分类上下文相同，也不代表其分类仍成立。工具 activity、Git 查询、classification/confidence 均不回放，界面明确标为历史；Base/Current 继续使用本次新 scan ID。目录重新枚举及分类，候选行不会跳过子树。缺失历史或可选文件事实均退回当前观察。

每 revision 在缓存读取和遍历前捕获游标，完整扫描保存候选和有界索引，已复用长度进入下一代。只刷新选中范围时不发布不完整的整根候选记录，也不覆盖未扫描根的索引。缓存错误为可靠 CacheWarning，不改变完整现场扫描的结果；取消停止后续发布。发布时对照本次扫描原生根身份，拒绝扫描后根被替换时将旧事实绑定到新对象。规则摘要按实际加载字节计算，支持编辑后的项目规则，无需手维护 hash。

根 schema v7 兼容增加可选递归 aggregate；普通报告与会话都保存它。旧 v7 记录缺少 aggregate 时，只在原记录明确为逻辑大小时显示旧逻辑值；分配字节和目录 inode 长度不能冒充递归逻辑大小，缺失计数保持 unknown。两层磁盘读取仍共用 16 MiB 编码输入、128 MiB 保留估算；历史行通过现有有界事件队列交给有界视图，会话只额外保留至多 max_candidates 个固定大小历史键用于完整替换，不占用当前原生绑定注册表。超大或超量预览省略不制造现场扫描的覆盖缺口。这些限制是保留量估算，不是 RSS 精确上限。

`junk --tui` 在 macOS 使用与普通报告相同的状态目录。历史行无法回收；`R` 或空视图的 `r` 可刷新全部根，刷新历史行也调用新增的 refresh_all，从原始根重新观察，完整终态后移除消失的历史键，取消或不完整观察继续保留。稳定键替换保留选择与焦点。Linux/Windows 目前仍现场扫描；系统自动发现、Linux 临时对象、单大根提前完整候选及高效局部刷新尚未完成，完整会话/TUI 验收项继续保留未勾选。没有端到端计时，不把历史首屏或实时绘制当作扫描加速倍数。

迁移后的并发矩阵曾在原磁盘淘汰测试的第二次发布返回 WouldBlock。独立 native flock/fork 实验确认：即使设置 CLOEXEC，子进程在 exec 前仍可持有共享 open file description；父进程只关闭自己的 File，锁会继续存在。显式 LOCK_UN 可以在子进程仍等待管道时重新获取锁。存储改为由加锁进程拥有的 LockGuard，Drop 先显式解锁再关闭；PID 检查避免子进程中的继承 guard 解锁父进程仍活跃的临界区。受控 fork 回归仅在子进程执行 async-signal-safe 调用，并有界回收它。原非阻塞互斥及完整淘汰断言保留；没有添加等待或“重试直到通过”。该实验复现了同类锁现象，未从首次失败现场追踪到具体继承者。

大目录终端诊断另发现既有进度日志上限：32,768 文件的前置报告返回 partial，源码显示 max_progress_events=16,384 超限会标记详情丢失，影响完整缓存建立。未扩大生产预算或将该报告改称完整；后续需单独修复非权威进度截断与扫描证据的关系。8,192 文件热缓存的首次 PTY 运行在 10 秒内未结束，诊断运行中已观察历史首屏、当前完成视图及安全退出，但未取得停顿堆栈，不能把间歇延迟说成已修复。同规模原生会话已作为保留的回归，通过独立 read_dir/metadata 核对完整逻辑字节、新 scan ID、稳定键和明确完成终态；这不是端到端性能基准。

交付验证（arm64 macOS，Rust 1.98.0）：最终工作区 804 项通过、0 失败、2 项原有基准 ignored，系统 Trash 挂起用例仍以 `--skip trash_moves_ordinary_paths_without_confirmation_in_machine_invocations` 排除，其成功移动未验证。格式、受影响 scanner/core/CLI/TUI 及工作区 all-targets/all-features clippy 通过。Linux GNU/Windows GNU 工作区交叉 clippy（含目标测试代码）通过；最后锁 guard 改动仅在 macOS 分支，复用未改变的这两个目标结果，宿主运行时和 MSVC 仍未验收。53 份 Markdown 和 23 项检查器测试通过。独立对照迁移前后的 29 项缓存测试名称全部保留，core/CLI 包清单包含预期迁移源码，仍为 17 包且 core 无终端依赖。

最终二进制在隔离状态目录的真实 PTY 冷缓存检查中，q/Ctrl-C/SIGTERM 分别返回 0/130/143，终端属性与 alternate screen 恢复，payload 不变；8,192 文件热缓存检查观察到 Historical/partial 首屏，再由 Current 完成视图替换并以 q 安全退出，普通 glob/stat 核对文件数和逻辑字节未变。未发送删除键。首次大负载 partial、一次热缓存 PTY 超时与上述原生验证缺口继续分别记录，不将后续通过运行称为已修复间歇延迟。


## 进度保留与扫描完整性（2026-10-01）

可选进度日志达到 max_progress_events（默认 16,384）不再生成 ResourceLimit 边界，也不截断分类或覆盖证据。新增常量大小的 ProgressRetention，独立记录省略的观察/错误数、取消、真实资源不足及遍历结束；error_count 同时统计保留和省略的错误，core 输出状态使用这些事实。非零日志容量优先保留最新错误/终态，普通观察不会覆盖诊断；现场 observer 仍在日志保留之前收到每个事件。遍历结束不等于完整覆盖或后续 Git/缓存阶段成功。没有扩大生产预算；候选、边界、统计或规则 marker 的真实丢失仍保持 partial。

受控回归覆盖零/单槽/多槽日志、连续错误后终态替换、枚举 I/O 错误，以及截断前后候选、规则、覆盖和现场观察一致。原生会话回归在默认预算下扫描 32,768 普通文件，冷、热缓存都必须 Complete；普通 read_dir/symlink_metadata 独立核对逻辑字节及条目数，检查历史首屏、新 scan ID 和稳定键。原有零边界保留的刷新回归现在也使用零进度日志，元数据不足仍必须保留旧候选且禁止以未见为已删除。

[完整阶段测量](junk-benchmark-progress-retention-2026-10-01.json)：2026-10-01，arm64 macOS Darwin 25.5.0，Rust 1.98.0 release 构建，一个受控项目根的 32,768 文件，冷缓存、热缓存尝试和单文件变化各三次，条件等待 1 秒。SweepX 冷缓存不代表操作系统冷缓存；OS 缓存未控制。候选文件系统事实先作冷/热等价比较，再通过普通 walk/stat 核对；未比较动态 Git/工具解释，样本不足以计算尾延迟。

| 状态 | 命中次数 | 进程 wall 中位数 | 遍历阶段中位数 | 根缓存校验中位数 |
| --- | ---: | ---: | ---: | ---: |
| SweepX 空缓存 | 0/3 | 245.3 ms | 212.6 ms | 0.5 ms |
| 整根缓存命中 | 3/3 | 35.5 ms | <0.001 ms | 16.3 ms |
| 单文件变化 | 0/3 | 213.1 ms | 163.6 ms | 13.8 ms |

[真实 PTY 会话记录](junk-tui-progress-retention-2026-10-01.json)：同一最终 release 二进制另在三个独立、预置缓存的 32,768 文件项目上运行垃圾会话。历史首屏为 67.7/67.3/68.8 ms，当前 Complete 候选视图为 273.1/273.3/275.2 ms（从 wrapper 启动后的采样起点测量，含绘制轮询误差，不是 CLI 进程 wall）。每次 q 返回 0、终端属性及 alternate screen 恢复，普通 glob/stat 核对全部 payload 未变；没有发送删除键。TUI 使用文件事实复用并重新遍历目录，不能把普通报告的整根命中时间当作 TUI 完成时间。这三次未达到采样阈值，没取得停顿堆栈，之前 8,192 文件 debug PTY 的一次超时仍未定位，不能称为已修复。

交付验证：固定 Rust 1.98.0 格式检查、工作区 all-targets/all-features clippy、Linux GNU 和 Windows GNU 工作区交叉 clippy（含目标测试代码）通过；工作区 809 项通过、0 失败、2 项原有基准 ignored。系统 Trash 成功路径仍显式排除同一已诊断挂起用例；Linux/Windows 宿主运行时及 MSVC 未验收。53 份 Markdown 检查、23 项文档检查器及 5 项基准验证器测试通过。没有新增 crate 或依赖；完整会话/TUI、系统模式、提前候选、大文件、重复文件及规则扩展仍按清单继续。


## 系统会话前置：Linux 临时对象观察预算（2026-10-01）

接系统垃圾会话前审计了 Linux `/tmp` 专用路径：它包含普通文件、链接、FIFO 和 socket，不能制造目录 aggregate 或把报告路径交给普通 Trash。原递归 measurement map、目录名称及进程 mount/socket 表读取没有保留上限，期限也没有贯穿 fd/map_files 等内部枚举。现在报告、预览和执行前独立重验复用同一有界实现；新增 discover_with_cancel_and_limits 将会话 token 传入全部原生观察。默认报告 API 保持兼容，各次重验独立捕获当前证据，不持久缓存进程活动或引用答案。

一个调用共享默认 1,000,000 条观察、64 MiB 累计保留估算；每目录最多 65,536 个名称和 8 MiB 原生名称字节；单个 mount/socket 表最多 4 MiB，累计输入最多 64 MiB。模型估算包括名称列表、完整身份指纹、待访问路径、hard-link/FIFO 及命名空间索引，两个测量 pass 和所有候选共用预算；它是保守累计准入，并非精确峰值或 RSS 上限。过程表使用有界分块读取，拒绝最终链接及非普通文件，FIFO 以非阻塞方式打开后拒绝；不把超量表的前缀交给阴性引用判定。资源失败粘滞到本次调用结束；取消/期限/预算不足都保留 incomplete、已有正向候选和 blocker，不允许用缺失结果证明无垃圾或取得清理授权。原 O_NOATIME/O_NOFOLLOW 目录准入及借用 fd 的 ownership 保持；合作检查不能强制中断阻塞的内核调用。

socket 命名空间只有完整表读取成功后才进入已观察集合，进程退出导致 Gone 不再缓存成空表。网络命名空间 key 改为 stat 的目标 device/inode，避免以进程各自的链接 inode 重复读取同一网络命名空间；查重前及表读取完成后再次核对命名空间绑定，变化为错误，消失不建立空表证据。这些是现场的前后观察，不构成系统范围的原子引用快照，现有 system_wide_reference_view_unavailable blocker 保留。此处只观察固定 procfs magic link，不跟随候选路径，也不授予执行权限。依据：[Linux namespaces(7)](https://man7.org/linux/man-pages/man7/namespaces.7.html)（来源访问日期：2026-10-01）。短于三个八进制数字的 mountinfo 反斜杠尾部现在保持原字节，不越界 panic。

六项可移植测试实际通过：零/到期/取消、目录条数及名称字节边界、跨候选共享模型/条数预算、超量表拒绝、累计输入共享，以及链接/目录/FIFO 不成为阻塞表读取。Linux 专用新增回归编译覆盖原生目录截断和借用 fd 保留、测量指纹超限、取消先于根访问、Gone 后同命名空间的后续引用、超量表不得建立空引用视图、命名空间绑定替换拒绝，以及独立 kernel readlink 和继承子进程核对命名空间身份。迁移前 16 项测试名称全部保留。

验证：Rust 1.98.0 格式、工作区 all-targets/all-features clippy 和 Linux GNU/Windows GNU 工作区交叉 clippy 通过，包括目标测试代码。macOS 工作区 815 项通过、0 失败、2 项原有基准 ignored；系统 Trash 挂起用例仍显式排除。完整矩阵后只追加表读取末尾取消检查和 Linux namespace 身份/绑定回归；可移植六项及工作区 lint、最终 Linux 全工作区交叉 lint再次通过，其余未变宿主测试和 Windows 分支复用上述结果。过程中发现 fixture 把新内部 context 误传给保持兼容的 discover deadline，以及两处测试调用缺少新增 namespace_path 参数，均已修正，没有放宽 cfg 或移除断言。core 包清单包含新的观察模块，没有新增 crate 或依赖。

本机没有 Docker、Podman、Colima、Lima、nerdctl 或 QEMU Linux 运行环境。可移植测试不证明 procfs、O_NOATIME 或网络命名空间在 Linux 宿主上运行正确；新增 Linux 专用用例仍未运行，目标宿主/Windows MSVC 与实际系统 Trash 成功的验证缺口保留。当前只完成系统会话的这项前置资源与取消改造；系统模式、Linux 临时对象事件/视图、单大根提前完整候选、独立大文件、重复文件及规则扩展仍待继续，不能勾选完整会话/TUI。

## 当前未完成项汇总（2026-10-02）

此前各章节保留交付时的状态；当前以验收清单和本节为准，不将已由后续章节完成的旧待办重复列入。单个大根的完整子树基础候选已支持提前输出，Git 增强和回收准入仍由后续阶段确认；高效选中范围刷新、独立大文件分析及显式重复内容分析已交付，详见文末。

| 顺序 | 未完成项 | 当前边界 |
| --- | --- | --- |
| 1 | 系统垃圾会话与 TUI 收尾 | 系统自动根发现与 Linux 临时对象事件/视图已接入；临时对象的 TUI 后台隔离预览、精确计划确认和结果展示已接入，共用原生服务；Linux 等目标宿主的完整运行验证仍缺失。 |
| 2 | 垃圾规则扩展 | 已加入 Dart 与 SvelteKit 1/2 的自身普通文件结构标记规则及共用版本/误报夹具；Dart 与 legacy SvelteKit 已接入当前有界内容 profile、缓存/会话重观察及 report-only 回收限制；现已将执行约束贯穿所有旧/新项目规则及缓存，名称/ignore 不再提供项目回收准入；SvelteKit 1.0.0/2.0.0 与 Dart 2.18.0/3.6.0 已补实际 SDK 生成文件和字节记录（含 Dart 共享/中文空格 workspace）；Cargo 父 manifest 的当前声明观察已接入 CLI/会话/TUI，并复用独立 cleaner 的解析器，并已观察父目录下两个 Cargo 本地配置文件的声明，但尚未求解有效配置或独占关系；完整语言语义、更广版本/配置采集、独占所有权/活动观察仍缺失。 |

另外保留独立收尾项：其他工具发现路径的资源审计（npm 安装/活动枚举，以及工具缓存根、版本展开与指纹快照已补共享预算；不将这些切片视为全部系统发现路径完成审计）；8,192 文件 debug 热缓存 PTY 超时及工具探测间歇失败的根因定位（含受控共享缓存正例的 ProbeUnavailable；300 ms 超时在无交叉编译的串行本机 core 运行中也已复现，后续通过未证明修复）；Linux/Windows 宿主运行时、Windows MSVC 和实际系统 Trash 成功验证。Linux/Windows 会话目前现场扫描，未获得 macOS 同等的历史缓存首屏和文件索引复用。现有 pathname 检查到系统 Trash 调用之间的竞态也仍是执行能力边界。

选中刷新的持久缓存片段合并随后已接入：完整局部观察合并新子树与历史验证后的兄弟文件事实，候选记录只作历史预览，详见文末。独立大文件/重复内容的 TUI 结果视图、明确保留者选择和交互 Trash 随后已接入，CLI 选项不再与 TUI 互斥；复用现有分析器和列表机制，最终验证与原生执行缺口见文末。Git 的重复范围查询已合并并补等价计时；上述间歇根因项仍保持开放。

crate 已从 22 收敛到 17，core 与终端依赖已分离；第二轮未发现进一步合并的明确收益。继续合并不作为独立待办，只有具体契约、所有权或依赖收益成立时再评估。

工具探测现已补固定大小的最近一次阶段诊断，独立实验定位出本机新建脚本首次直接执行的额外等待；共享缓存的旧超时随后再次复现，最新活体取样取得了实际测试子进程的启动堆栈，但尚未捕获超时当次的原因，不能认定根因已解决。详见文末工具探测及活体取样记录。

## 系统根发现与临时对象实时视图（2026-10-01）

`junk --system --tui` 现在可进入后台会话，不接受显式根；`JunkSessionRequest::system()` 本身不执行工具或文件系统发现。每次全量 revision 复用 PlatformJunkSetup 的本次工具/布局快照，选择保守系统根，并在去重前检查 256 根、单路径 64 KiB 的上限。取消与失败保留可靠终态，不把布局发现缺口当作空范围。选中目录刷新仍复验 captured binding、遍历其原始根并过滤选中子树；全量刷新才重新发现系统范围。

macOS 游标仍在发现及任何缓存读取之前捕获。显式根维持发现前的历史首屏；系统模式先发现范围，再只读取该范围的历史记录，发布和文件索引也绑定这次完整范围。受控回归注入发现清单，但使用真实遍历、分类、FSEvents 和持久化：从根 A 改为根 B 后完整替换 A 行，重启只回放 B 的历史；逻辑大小以普通 stat 独立核对。根准入另覆盖超量原始清单、相对路径、重叠根及不折叠 linked/../candidate 的拼写。

Linux 系统 revision 在目录/Git 后调用已有有界临时对象服务，使用同一取消 token 和调用预算；测量保留额度受会话已有候选剩余额度限制。JunkSessionFacts 明确区分 Directory 与 LinuxTemporary，后者保留原生 measurement 及独立逻辑字节，没有制造目录 aggregate 或 source_entry。临时对象使用独立稳定键 domain，当前 entry ID 进入本次 revision 的独立 temporary namespace；普通报告的固定 namespace 不回放为当前会话身份。完整指纹计入 core 队列、候选注册表和 TUI 保留估算，不能因为展示只有一行就忽略它。

临时对象结果沿用现有 classification/activity/blockers，不推断系统范围的原子引用视图。刷新该类行会全量重新发现系统范围。普通 Trash 的 provider 和 worker 都拒绝它们；清理仍用独立 CLI 的 `junk --system --clean-temp` 隔离预览与精确计划确认。TUI 内的预览/确认/隔离结果流尚未接入，不能据此勾选完整 TUI 项。Linux 专用桥接回归编译覆盖逻辑大小与分配大小不同、缺少目录身份、普通 Trash 拒绝及全量刷新路由；没有目标 Linux 运行证据。

交付验证（arm64 macOS，Rust 1.98.0）：受影响 core/CLI/TUI 的 361 项测试通过，1 项原有 core 基准 ignored，系统 Trash 挂起测试显式排除。包含 CLI 无终端在发现前拒绝、系统选项准入，以及上述范围变化/缓存回归；未修改的其他 crate 测试复用前一单元的工作区通过结果。格式、工作区 all-targets/all-features clippy 和 Linux GNU/Windows GNU 工作区交叉 clippy（含测试）通过。过程中的新测试把 predicates crate 写成 predicate，已修正并重新完成受影响检查，没有移除断言或放宽 cfg。core 包清单包含 session/linux_temp.rs，没有新 crate 或依赖。

[真实 PTY 系统入口记录](junk-tui-system-entry-2026-10-01.json)使用 release 二进制和隔离状态目录，三次分别在 Discovering context 阶段用 q、Ctrl-C、定向 SIGTERM 退出，返回 4/130/143，终端属性及 alternate screen 恢复，受控 payload 未变；未发送删除键。首轮 harness 将发现中 q 错误预期为 0，源码核对确认未完成扫描的既有约定是 4，仅修正测试预期后重验；没有修改产品退出语义。它验证系统入口、发现期间退出与终端恢复，不证明全系统扫描完成、吞吐性能、Linux 临时对象运行或系统 Trash 成功。目标宿主/MSVC、Trash 成功及之前 debug 热缓存 PTY 超时的缺口继续保留。


## TUI 隔离前置：独立预览与有界执行（2026-10-01）

Linux 临时对象的原生规划、耐久复制、内容核验和 fd-relative 源移除已从 CLI 迁入 `sweepx-core::junk::quarantine`，CLI 保留前台打印与 stdin 确认。没有新增 crate 或依赖。`preview_temp_clean` 返回不能从序列化计划重建的 opaque preview；执行消费一次，精确要求 `clean <完整 canonical digest>`，重验权限、当前原生事实和实际加载的规则字节摘要。计划 v3 兼容增加 ruleBytesDigest 字段，已有机器 ID、字段名及枚举不变。调用者可提供选中行的原 measurement；相同分配字节但身份或活动改变必须拒绝，不把预览时新对象升级成用户先前所选对象。

默认每批最多 256 项，清理路径累计准入估算 64 MiB、1,000,000 次路径访问、最大深度 128、复制/核验 I/O 请求预算 1 TiB、合作期限 15 分钟。可配置限制保留在 preview 中供执行使用，原生 observation 仍有自己的每次有界事实/进程表观察，较小的调用者限制同时约束其条数及模型准入。目录枚举、复制、核验和源移除都使用同一取消令牌；这些是准入估算及合作检查，不是峰值 RSS 或阻塞内核调用的硬超时。资源拒绝保持粘滞，失败不能通过回退重新获得预算。稀疏区间截到计划长度，逻辑回退按固定长度分块读取，不能因文件增长变成无界 io::copy；源打开使用 no-follow/nonblocking，打开后确认普通文件身份与修改指纹，拒绝 FIFO 替换后阻塞。待移除的同层名称共享一个保留父目录 fd，避免宽目录逐名称复制句柄。

取消在源移除之前发生时保留源对象；移除开始后允许留下部分源树及完整、已核验并同步的恢复副本，不承诺原子回滚。失败停止后续候选并保留 reconciliation/outcomes，没有永久删除兜底。生产仍硬绑定真实 `/tmp`、当前非 root/无 capability 进程和异文件系统私有恢复区，报告 fixture override 不提供执行权限。当前用户进程观察不是系统范围原子快照，pathname 祖先竞态等已有能力边界没有因迁移消失。前台确认最多保留 256 字节，恢复路径和候选打印转义控制字符。

独立核对原 CLI 的 15 项测试名称全部保留：14 项原生测试迁到 core，精确前台确认测试留在 CLI。新增 3 项可移植测试实际运行，覆盖取消/期限/粘滞 I/O 预算、独立路径/深度/模型预算、固定长度复制以及读操作触发取消后不写目标。新增 5 项 Linux 原生回归覆盖移除前取消与权限保留、I/O 拒绝及 FIFO 替换、同分配大小的新 inode、独立 procfs 统计宽目录保留 fd、opaque preview 的精确确认与规则摘要绑定；它们仅交叉编译/lint，没有 Linux 宿主运行证据。原异盘复制测试依赖 `/dev/shm` 和实际不同 device，缺少时不能证明该运行时路径。

交付验证（arm64 macOS，Rust 1.98.0）：受影响 core/CLI 283 项测试通过，1 项原有 core 基准 ignored，系统 Trash 挂起用例仍显式排除；最后可移植预算访问器变化后单独重跑 3 项并通过，其余未变宿主用例复用上述结果。格式、工作区 all-targets/all-features clippy、Linux GNU/Windows GNU 工作区交叉 clippy（含目标测试代码）通过。过程中 Linux lint 发现多余借用，后续新增测试一度被放到 tests 模块之外且前台确认保留了未使用导入；均修正并完成最终检查，没有放宽 cfg 或移除断言。core 打包清单包含 quarantine.rs 及 operation.rs。53 份 Markdown 与 23 项文档检查器测试通过。

这是 TUI 隔离流程的共享服务前置，尚未交付 TUI 的后台预览、精确输入确认和执行结果流；当前未完成项清单保持不变。Linux/Windows 原生运行、MSVC、实际系统 Trash 成功及 debug 热缓存 PTY 停顿仍未验证或定位，整项目目标继续推进。


## Linux 临时对象的 TUI 隔离协议（2026-10-01）

`junk --system --tui` 的 `x` 接入所选当前、完整临时对象的独立隔离预览与执行；普通目录继续用 `d/Delete`，混合事实类型在启动前拒绝。`--quarantine-dir` 现在可与 Linux 系统 TUI 配合使用，仍要求异文件系统私有恢复区；不传时沿用已有默认。配置不能用于普通报告或显式根 TUI。非 Linux 宿主拒绝该配置，未选择临时对象也不能伪造其执行身份。

一个 worker 复用 core 的 opaque preview 并将其保留到确认。界面只接收完整显示计划与 lowercase canonical digest，按原样输入 `clean <完整摘要>` 后通过单槽命令通道确认，没有自动填充、短指纹授权或由显示数据重建执行计划。预览保留原选中行的 Arc measurement，避免 UI 线程复制整个指纹 map；现场不同 inode、活动或分配变化拒绝。恢复区原生字节新增为计划 v3 的 quarantineBaseBytes，避免两个 lossy 显示路径产生同一摘要；模糊源/恢复路径另显示 native hex。已有 schema ID/字段名及风险值保持，新增字段为兼容扩展。

TUI 最多保留 1 MiB 完整计划、160 字节 ASCII 确认输入，过量拒绝执行。方向键/PageUp/PageDown 滚动、左右查看完整长行；按可见逻辑行绘制，不每帧构建全量终端单元。确认等待最多 15 分钟；预览、执行和扫描/Trash 互斥，Trash 与隔离共用一个进程级 mutation worker 配额，关闭或取消不能绕过尚未退出的原生 worker。结果与命令通道各一个槽；Drop/关闭取消并断开，不在 UI join。合作期限不强制中断阻塞系统调用。

Esc 在未执行时取消预览；移除开始后的取消继续等可靠结果，可能留下部分源和完整恢复副本。只有原生确认的 source-to-recovery 转换移除行；失败/未确认项保留为历史并显示恢复位置、失败及 reconciliation。Trash 与隔离复用同一确认移动处理，删除子候选并使祖先旧统计变为历史，不将删除前的精确字节继续说成当前。结果可留在界面核对，Esc 关闭、q 退出。系统范围原子引用视图、pathname 竞态等边界没有消失，没有永久删除兜底。

5 项实际 TUI 交互/渲染回归覆盖完整输入才提交、前缀拒绝与取消不移除、过期事件及过大计划/uppercase 摘要拒绝、执行中取消保留确认/不确定结果、输入预算与隔离页面不触发扫描/Trash 快捷键。CLI 新增系统 TUI 参数准入和真实受控扫描的结果处理回归；后一项用普通 read 核对 payload 未动，仅注入确认移动来验证子候选/祖先统计状态，不能据此推断系统 Trash 或 Linux 隔离真实成功。Linux 新增 1 项摘要回归，覆盖两个恢复区路径显示相同但原生字节不同的情况，仅编译覆盖。

验证（arm64 macOS，Rust 1.98.0）：受影响 core/CLI/TUI 共 371 项通过，1 项原有 core 基准 ignored，系统 Trash 挂起仍显式排除。最终共享结果处理与诊断调整后重跑 CLI/TUI 186 项，其余未改 core 185 项复用同单元结果。格式、工作区 all-targets/all-features clippy、Linux GNU/Windows GNU 工作区交叉 clippy（含目标测试代码）通过。中间 Linux 编译发现闭包移出 PathBuf，随后泛化借用产生 lint；改为 as_path 借用并重新检查，没有复制路径来掩盖问题、放宽 cfg 或移除断言。53 份 Markdown、23 项文档检查器测试通过，core/CLI/TUI 包清单均包含预期模块。

上述是代码接线和可移植交互证据。本机没有 Linux 运行环境，未执行 Linux TUI 的真实确认/隔离，也未验证 Linux/Windows 宿主、MSVC 或实际系统 Trash 成功。完整会话/TUI 的单大根提前候选与目标宿主验收仍未完成，原验收项保留未勾选；后续继续提前候选、局部刷新、大文件、重复文件及规则扩展。


## 单根内的完整子树提前候选（2026-10-01）

内置项目/平台组合分类器声明 uses_only_local_markers：规则、优先级及否定条件只依赖当前条目、本身/父目录的文件 marker，以及本次不可变发现快照。扫描 sequencer 在子树最后一个批次提交且所有准入子树已关闭后形成完整 aggregate；自身和父目录枚举均结束才调用原有 classify/interpret，发送基础候选，不等单根其他分支结束。自定义分类器默认保持整根 marker 合同，只有显式声明局部依赖才能提前分类，没有第二个规则实现或插件框架。

子树关闭仅增加计数和标志，不复制硬链接集合；普通文件和缓存文件的字节仍由既有路径直接累计到每个祖先。已交付子树释放状态，最终不会再次发同一候选；保留候选 aggregate 与尚未关闭的 state 共用现有数量准入。父目录枚举尚未结束时保留闭合子树，父目录结束后再交付；短暂等待路径列表由已准入状态数量约束。枚举失败、取消或资源截断没有完整 marker 证明，不提前交付；根结束仍保留现有 incomplete 回退。后续的其他分支失败不把先前完整观察的子树伪装成未扫描。

会话通过原有有界可靠队列发送 Base，TUI 立即展示并保留稳定选择；扫描和当前 Git 解释完成后，同键 Current 替换。提前完整是文件系统子树观察及局部基础规则的完整性，不意味着 Git、环境活动、全范围扫描或回收准入已经完成。扫描中仍不能据此 Trash/隔离；历史缓存、revision、原生身份及最终重验合同不变。普通报告仍等终态输出；不宣称端到端耗时或吞吐加速倍数。

6 项受控 scanner 回归覆盖：其他 payload 尚未观察时先交付完整子树并取消，完整子树与取消后不完整回退区分；与整根分类的最终决定、索引、覆盖及 aggregate 集合等价且无重复事件；父 marker 位于后续批次的正例/否定反例；真实缺失的 marker 等父目录结束才判断；自定义分类器默认等整根；零 metadata 预算不能制造否定候选。1 项原生 core 回归使用真实目录、内置组合规则和生产 Observer，普通 read_dir/symlink_metadata 核对完整逻辑总量，确认目标 Base 进入会话 mailbox 时无关目录 payload 尚未观察；全扫描随后完成，不靠时间窗口推断先后。

新增 1 项 TUI 渲染/状态回归，确认扫描中完整 Base 行可见但不可回收，同键 Current 替换保留选择，只有完整终态才解除准入限制。取消测试最初把“只提前完成一个子树”误写成“取消后只能有一个候选事件”；现按既有 incomplete 回退合同，独立断言提前完整子树恰好一个、其余未观察范围不完整，没有屏蔽或移除失败用例。

交付验证（arm64 macOS，Rust 1.98.0）：工作区 837 项通过、0 失败、2 项原有基准 ignored；命令仍显式排除已诊断的 trash_moves_ordinary_paths_without_confirmation_in_machine_invocations 系统 Trash 挂起，该真实成功操作未验证。随后只增加 TUI 回归，最终 TUI 87 项通过，其余未改代码复用上述工作区结果，合计已覆盖 838 项，不称为再次完整矩阵。格式、scanner/core 及最终工作区 all-targets/all-features clippy、Linux GNU/Windows GNU 工作区交叉 clippy（包括新增目标测试代码）通过；53 份 Markdown 检查通过，scanner 包清单包含新增测试模块。未运行 Linux/Windows 原生宿主或 MSVC，不以交叉 lint 代替运行时验收；没有新性能计时或新增 crate。下一步为保留父规则/Git 上下文的高效局部刷新。

## 高效选中范围刷新（2026-10-02）

选中目录刷新不再递归整个原始根。scanner 复用同一遍历、规则 VM 和分类器，只进入所选子树；沿原始根和原生身份链完整枚举浅层祖先的名称，只检查通向所选目录的路径、加载规则实际需要的文件 marker 和 `.git`。无关兄弟子树不打开、不递归；祖先 `.git` 目录仅观察原生目录 marker，不扫描其内容。过滤前仍验证每条枚举记录属于 retained parent，保留 no-follow、mount、权限与资源边界。选择最多 256 项，单原生路径最多 64 KiB；自定义全根分类器拒绝局部接口，不给它不完整的 marker 集合。

浅层祖先统计/递归覆盖明确不完整，名称枚举完成是单独的证据，且计入共享必需元数据预算。只有自身及父目录枚举完整才执行局部分类，截断的父 marker 不能支持否定谓词。所选覆盖不依赖稀疏候选或可选缓存索引：每个请求目录都须被观察并完成，目录不再匹配规则也不能绕过覆盖判断。失败、取消或预算不足仍不移除旧候选。

core 在遍历前及后续解释/替换边界重验所选原生绑定；当前 Git 证据继续用原始 lineage 重建。稳定键与本次 scan ID 分离。可靠的 Invalidated 事件将严格祖先旧行标为历史，TUI 保留其选择与原生刷新绑定，但拒绝回收，刷新祖先后才能恢复当前状态。无关兄弟行保持。局部刷新不把祖先重新准入为新根，也不从显示路径制造执行身份。

macOS 局部扫描不发布完整根候选报告或部分文件索引，以免完整缓存代际中未观察范围的事实消失。保留原代际及其原游标；随后全量扫描照常验证历史，缺口/不确定证据退回现场观察。此处没有声称局部结果已合并持久化，Linux/Windows 会话缓存差异仍保留。

受控 scanner 回归核对只检查目标目录、payload 和父 Cargo marker 三个对象；无关子树及浅层 `.git` 的内容均不观察。另覆盖父 marker 截断、所选目录未访问、全根分类器拒绝和被省略的异常 backend 路径。原生 core 回归在含 128 个无关文件的兄弟目录旁连续刷新所选子树，独立 read_dir/symlink_metadata 核对逻辑总量、原始 native root 和稳定键；已有真实 Git 忽略变化及 marker 移除回归保留。CLI/TUI 回归确认祖先历史拒绝 Trash、仍可按原生绑定刷新及旧 revision 不覆盖当前行。新增缓存回归比较局部刷新前后的实际发布字节和游标，再经全量刷新独立核对所选及兄弟 payload 的当前大小与索引。

原元数据压力用例把压力夹具放在无关兄弟目录，新局部遍历正确跳过它们，不再触发资源不足。已将夹具移入所选子树，保留不完整扫描不能移除旧候选、空保留日志也不能隐藏可靠失败及再次完整刷新才移除的原断言，没有排除该测试。

交付验证（2026-10-02，arm64 macOS，Rust 1.98.0）：工作区 847 项通过、0 失败、2 项原有基准 ignored；随后增加缓存回归并整理发布守卫，最终 core 全量 188 项通过、1 项原有基准 ignored，其余未改代码复用上述结果，合计覆盖 848 项，不称为再次完整矩阵。工作区测试命令仍显式排除已诊断挂起的 trash_moves_ordinary_paths_without_confirmation_in_machine_invocations，系统 Trash 成功操作未验证。格式、最终工作区 all-targets/all-features clippy、Linux GNU/Windows GNU 工作区交叉 clippy（含目标测试代码）、53 份 Markdown 和 23 项文档检查器测试通过。没有新增 crate、依赖或机器输出字段；公开 scanner 结果与会话事件增加上述局部覆盖/失效契约。没有本轮性能计时，不从少量受控检查次数推断全盘或尾延迟；目标宿主、Windows MSVC、实际系统 Trash 成功路径及 debug 热缓存 PTY 超时的独立缺口仍保留。下一步为同次遍历中的独立大文件分析，随后推进重复内容检测与规则覆盖。


## macOS 批量文件身份修正（2026-10-02）

独立大文件分析的硬链接回归暴露旧批量后端的身份错误：getattrlistbulk 请求 ATTR_CMN_OBJID，却把返回的 fsobj_id_t 直接解释为 stat inode。在本机两个真实硬链接路径返回不同的该属性，而普通 symlink_metadata/stat 返回相同 device/inode。Apple 的 [getattrlist 契约](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/man/man2/getattrlist.2) 区分 link/object ID 与 64 位 FILEID；本机 SDK 的 sys/attr.h 也说明 64 位对象 ID 卷应使用 ATTR_CMN_FILEID。不能把这些不同 domain 的值混用。

批量请求改为 ATTR_CMN_FILEID，并按 common-bit 顺序在 FLAGS 后解析完整 64 位值；缺少 FILEID 或 DEVID 拒绝该页，不能生成零身份。仍使用同一有界页和 native no-follow 路径，没有逐文件新 syscall。真实目录、普通文件、硬链接与链接逐项用普通 symlink_metadata 独立核对 device/inode；硬链接相同、链接自身不同。另有固定 wire 布局回归验证高于 32 位的 FILEID 与后续逻辑大小，缺失字段回归验证失败关闭。

macOS 整根垃圾缓存升级为 sweepx.junk-cache/v8，拒绝此前 v7 的 native lineage 与 aggregate，包括历史预览，避免继续回放错误的硬链接去重事实。独立的逐文件逻辑长度索引保持 v4；它不持久化原生文件身份或分配事实，也不能证明硬链接唯一性。旧 schema 拒绝回归保留并补入 v7。

本机 macOS 分配大小仍是明确的 UnknownIdentity，并不因 stat.st_blocks 为零或已知就自动升级成物理/独占可回收证据。新增大文件测试最初错误假定它为 Known，已依据现有后端契约修正，保留逻辑大小与未知分配大小的独立断言；硬链接身份对照暴露的产品缺陷则实际修复，没有修改预期来掩盖它。受影响 platform 全量 87 项通过、1 项原有基准 ignored；三个新增原生/解析回归均通过。格式、最终 host 工作区 clippy 和 Linux GNU/Windows GNU 工作区交叉 clippy 通过。缓存升级后的 core/CLI 回归及工作区范围结果在后续大文件单元统一记录；Linux/Windows 原生运行、MSVC 和真实系统 Trash 成功路径缺口仍保留。


## 同次遍历中的独立大文件分析（2026-10-02）

新增 scan --large-files，可用 --min-file-bytes 指定包含等于的整数逻辑字节阈值，用 --top-files 指定 1..=10000 个保留路径，默认分别为 100 MiB 与 100。它与普通 scan 共用一次现有元数据遍历，human 增加独立逻辑/分配大小表（最多显示 40 行），JSON 在原 envelope 的 data.largeFiles 中给出完整 top-K、计数、选项和覆盖缺口；plain scan 没有新字段，机器字段和枚举跨 locale 保持。当前不与 scan --tui 同用，不宣称已接入大文件交互或删除；普通垃圾 TUI 保持独立。

既有 analysis crate 内提供 LargeFileCollector 与报告，core 提供独立可取消、可在工作线程运行的 scan_large_files_with_store，没有新 crate 或依赖。scanner observer 在可选行保留前传递当前 ScannedEntry，并在可选 aggregate/index 保留前传递所有目录覆盖；不从截断后的 ScanSummary.entries 筛选。请求逐文件事实时，长度缓存退回当前 backend 文件观察；既有 junk-only 路径仍保持原文件复用。无第二套遍历、规则 VM 或删除实现。

有序 top-K 只复制准入榜单的原生事实，跨全部根共享条数与最多 64 MiB owned-data 估算，计入 lineage、字符串、容器辅助容量和结果转移；不是精确 RSS。榜单按已知逻辑大小排序，等大小按本次观察顺序取舍，不承诺跨扫描顺序。未知、lower-bound、unsupported 和 not-checked 的逻辑值不能排序为零，计入 unknownLogicalFiles 并使榜单不完整。正常 top-K 截断是用户选择的结果边界；真实遍历截断、权限/挂载、取消、缺少所选根覆盖或榜单保留预算不足分别保留不完整证据。普通列表截断可使原 scan 状态 partial，同时榜单仍有完整逻辑排序覆盖。

只纳入普通文件的路径观察，不读取内容，不沿链接越界。硬链接别名分别保留并携带真实原生身份；分配大小按后端证据原样保留，macOS unknown 不升级为零或逻辑长度。没有总分配/独占可回收求和，没有垃圾分类或清理授权。这是独立元数据分析；重复内容分析仍需显式读取和变化复验。

五项 analysis 回归用独立全量排序核对流式 top-K，覆盖后到的大于 u64 的最大值、阈值包含等于、分配大小不决定排序、非普通文件排除、零与四类不确定值分离、预算失败与已有行保留及无效限制拒绝。五项原生 core 回归用普通 walk/stat 核对全部文件，在一条普通保留行、零进度/边界日志下仍取得完整 top-K；还覆盖跨根共享榜单、稀疏文件/硬链接/链接、取消、真实目录截断、榜单预算不足和准入前拒绝。scanner 回归验证当前文件 observer 不调用逻辑长度复用计划，且无候选的 classified sink 不隐藏文件或覆盖。CLI 两项集成回归验证中英文机器字段、实际排序、human 大小列、参数约束/冲突和关闭分析时 plain scan 不变；fixture payload 未修改。

首轮检查中的 lifetime 借用、测试字段名及测试排序 lint 均已修正并完成检查。原生大小回归的 macOS Known 假设与真实硬链接身份缺陷按上一节分别处理；plain scan 的 macOS fixture 根改用 Unix-only canonicalization，保留生产拒绝链接祖先规则，Windows 未套用该变换。没有排除新测试、放宽 cfg 或重试到偶然通过。

交付验证（arm64 macOS，Rust 1.98.0）：工作区 864 项通过、0 失败、2 项原有基准 ignored，显式排除已诊断的 trash_moves_ordinary_paths_without_confirmation_in_machine_invocations 系统 Trash 挂起；随后只升级 macOS 整根缓存 schema 并整理 scanner rustdoc，最终 core/CLI 全量 296 项通过、1 项原有基准 ignored，其余未变测试复用工作区结果，不称为再次完整矩阵。最终格式、host 工作区 all-targets/all-features clippy 和 Linux GNU/Windows GNU 工作区交叉 clippy（含测试）通过。53 份 Markdown、23 项文档检查器测试通过，analysis/core 包清单包含新增 large_files.rs。没有新性能计时或加速倍数，目标宿主运行、MSVC 与系统 Trash 成功路径仍未验收。下一步推进显式重复内容分析、垃圾规则覆盖及其他收尾项。


## 重复检测前置：有界原生内容流（2026-10-02）

现有 BoundedRegularFileReadRequest 为小配置文件一次保留整个内容，不适合大文件完整 hash。platform 新增 RegularFileStreamRequest / RegularFileStreamResult 与 stream_bound_regular_file，三个原生后端提供保留父目录下的普通文件分块读取，复用既有 no-follow 打开、身份、文件系统及 mount 检查，不从 display path 恢复权限。既有小配置文件读取的语义保留；没有新增 crate、依赖、CLI 参数或重复文件输出。

请求携带原生 basename、身份/文件系统/mount expectation、offset、最大范围和可选上一阶段的 RegularFileObservation。范围拒绝超过 signed 64-bit 位置；Linux 使用明确的 pread64，不能在 32 位 off_t 配置下截断位置。共享循环保留固定 64 KiB 缓冲，先检查普通文件、绑定及跨阶段 size/change stamp，再发送各 chunk；只读实际逻辑范围，不额外读取一个 EOF 探测字节。读后身份、mount、size 与 change stamp 必须相同。短读继续，提前 EOF、异常长度、变化、取消或消费方拒绝均失败，已收到的 chunk 必须丢弃。外层再次核对精确长度，并保留消费方拒绝，不能被错误 backend 忽略后覆盖为成功。

每次调用只保留一个内容句柄及有界传输缓冲；Linux 打开期间另有短暂 O_PATH pin。上层仍需限制总文件数、metadata、调用次数、累计 IO 和并发；本接口没有全局预算或目录队列。同步原生调用无法在中途强制打断，取消在打开、chunk 与复验边界检查，消费者应在工作线程调用，不宣称具有硬实时 IO deadline。结果是稳定观察区间，不是原子快照、跨文件同一时刻证明或删除授权。

macOS 在元数据和内容打开前设置线程级禁止 dataless materialization，随后拒绝 SF_DATALESS。SDK sys/resource.h 与 sys/stat.h 确认 ABI，使用 [Apple XNU 的线程策略契约](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_resource.c)；仅靠读前 flag 检查不能保护观察与 read 之间的变化。guard 不可跨线程，成功显式恢复并报告恢复错误，错误或 unwind 也由 RAII 恢复。原生回归独立查询线程策略，验证作用域内 OFF、正常和提前退出后的原值；本轮未使用真实 iCloud 占位文件，云服务端到端行为仍未验收。

Windows 保持 FILE_OPEN_NO_RECALL / FILE_OPEN_REPARSE_POINT 打开，并在每个 chunk 前拒绝 offline、recall 或 reparse 属性；依据 [Microsoft 占位文件指导](https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/placeholders_guidance)。这些是原生标记和 no-recall 打开边界，不是对任意第三方 provider 的保证。Linux 没有覆盖任意 provider 的通用占位标志，流式读取仅准入 ext4、Btrfs、tmpfs；FUSE、overlay、远程及未知类型返回 ProviderOrOffline，不采用更弱的读取回退。Linux 新原生夹具明确使用 /dev/shm 的 tmpfs；该宿主能力不足时应报告环境缺口，不能改用未知文件系统并称为等价验证。上述收紧仅适用于新内容流，普通元数据扫描和既有小配置读取不改变。

十项新增回归覆盖独立 byte slice / 普通 fs::read 与 stat 对照、非零范围和完整流、hard-link 相同身份、分阶段及读取中修改、链接替换、错误 identity、短读/提前 EOF/异常 chunk count、零/EOF 范围、取消、消费方拒绝与错误 backend 的返回值，以及原生线程策略恢复。首轮测试错误把 RootAdmission 结构体当作 enum，已按现有 API 修正；libc 未提供 SF_DATALESS，改用已核对 SDK 的公开 ABI 值，没有放宽生产检查。

交付验证（arm64 macOS，Rust 1.98.0）：平台全量 97 项通过、1 项原有基准 ignored；工作区 874 项通过、0 失败、2 项原有基准 ignored，仍显式排除已诊断挂起的 trash_moves_ordinary_paths_without_confirmation_in_machine_invocations。沙盒首次平台检查中三个 FSEvents 服务用例失败（current event ID 为零、stream 无法启动）；在普通宿主环境保留原测试重验通过，没有修改预期或排除它们。格式、affected platform 与工作区 all-targets/all-features clippy、Linux GNU/Windows GNU 工作区交叉 clippy（含新原生目标测试代码）、无 backend 的契约 build 和 53 份 Markdown 检查通过；platform 包清单包含新 stream、测试和 guard 模块。最后的 Linux pread64 修正只影响 Linux cfg，Linux 工作区交叉 lint 已重验，其余未变代码复用通过结果。没有性能计时或提速结论。

重复检测验收项继续不勾选。下一步在 analysis 中接入大小筛选、硬链接排除、采样和完整 SHA-256，再接 core/CLI 并限制累计资源。Linux/Windows 原生运行、MSVC、真实云占位文件和实际系统 Trash 成功的独立缺口仍保留。


## 显式重复内容分析（2026-10-02）

scan --duplicates 现提供独立只读内容分析，默认阈值包含等于 1 KiB；--min-duplicate-bytes 0 可比较空文件。analysis 的 DuplicateCollector 接受同次元数据遍历中的当前普通文件事实，在可选列表保留之前建立有界索引；core 的 scan_duplicates_with_store 与 CLI 共用现有 scanner、根准入、输出 envelope 和状态存储。没有第二套遍历或分类器、新 crate 或外部依赖；analysis 直接引用现有 platform 的读取契约。普通 scan 没有 data.duplicates 字段；本模式与 --tui/--large-files 互斥，不宣称已接入交互删除。

完整原生对象 ID（包括 Windows 128 位 ID）排除硬链接别名和重叠根的重复观察。大小相同的至少两个对象才进入最多各 4 KiB 的头尾采样；只有采样匹配的组才读取完整 SHA-256。采样不是内容证明；摘要不带 sample-domain，输出标准完整 SHA-256 十六进制。各阶段绑定原生身份、filesystem/mount、逻辑大小与 change stamp；计算其他文件后再零字节复验先前的 hash，失败对象不进入最终组。组保留原始 allocation/coverage 证据，不选择保留者、不合计物理/独占可回收空间，也不产生垃圾分类或执行授权。跨文件结果不是原子快照，不持久缓存内容 hash。

scanner 的 FileContentRequest 与 DetailRescanner::stream_file 复用既有原生根和父目录 lineage 验证。文件自身的 mount 在现场观察，不复制父 mount，不使用显示路径；同名父目录替换拒绝。首次 range 前建立零 payload 的原生 stamp 并与源条目大小比较，防止 inspect 到 open 之间增长后将旧长度的前缀误写成完整 hash。每个后续阶段绑定上一观察。内容访问继续调用已交付的 native stream，保留三平台 no-follow、provider 和取消边界。

默认最多 20,000 个对象、64 MiB owned-data 准入估算、每文件 8 GiB、累计 8 GiB 请求范围、80,000 次内容阶段范围请求、30 秒内容阶段合作期限。CLI 可调整 max-files（1..=100000）、read-bytes（正 signed-64-bit 范围）及 deadline-ms（1..=300000）；范围请求上限随 max-files 为四倍。估算包含条目/native lineage、索引、stage stamps/摘要与结果转移，不是精确 RSS。内容串行读取，一个内容句柄和固定 64 KiB 缓冲；后端还可有有界元数据打开/探测。范围在调用前扣除预算，失败/短读不退还，交付字节单独计数；零字节最终复验同样占请求次数。取消/期限停止后续阶段，已完成复验的组可保留，未完成 hash 丢弃。同步原生调用的期限是合作检查，不能中断阻塞内核调用。

JSON data.duplicates 保留选项、完整组、原生事实、别名/对象数、已扣范围字节、实际交付字节、请求次数及 distinct incompleteReasons。缺少原生元数据、真实遍历缺口、保留/读取预算、期限、取消、变化/provider/读取失败不能被解释成唯一或无重复。human 显示完整摘要与最多 40 个组内路径，未知分配不变；中英文机器字段和枚举一致。普通列表截断仍可令原 scan partial，同时独立内容分析完整。

组合回归暴露边界日志截断将保留缺口传播为遍历缺口的旧行为。ScanSink 现分别报告 native traversal coverage 和原有 retained coverage：实时分析先收到所有边界/错误，再取得保留截断前的原生覆盖；缓存索引、所选范围准入、分类 aggregate 与摘要仍使用原有保守覆盖，没有升级删除/缓存证据。正常路径共用最终 aggregate，只有 retention overflow 时额外计算标量覆盖，不重复遍历或复制硬链接集合。受控回归同时核对完整现场覆盖、不完整保留/cache evidence 和真实目录截断不被隐藏。

八项 analysis 回归以独立全字节相等及已知 SHA-256 核对分组，覆盖头尾相同中间不同、大小唯一不读取、硬链接/空文件、完整 128 位 ID、错误身份/长度/mount、完整读取失败、最终 stamp 变化、忽略消费者拒绝的异常 source、读取/操作/保留预算、未知元数据、期限和取消。两项原生 scanner 回归覆盖显示路径伪造、同名父目录替换及 inspect/open 间增长拒绝；三项原生 core 回归覆盖截断日志/列表下完整分组、跨原始根比较、真实遍历缺口、取消、预算及准入前选项拒绝。三项 CLI 回归覆盖中英文 JSON、human、完整摘要与 distinct 原生对象、资源 partial/退出码 4、参数要求/冲突、plain scan 不变及 fixture payload 未修改。

交付验证（arm64 macOS，Rust 1.98.0）：工作区 890 项通过、0 失败、2 项原有基准 ignored，仍以 cargo test --workspace --all-features --locked -- --skip trash_moves_ordinary_paths_without_confirmation_in_machine_invocations 显式排除已诊断挂起的系统 Trash 成功用例。随后仅增加上述保留/原生覆盖回归，最终 scanner 全量 74 项通过；其余未变代码复用工作区结果，合计覆盖 891 项，不称为再次完整矩阵。受控覆盖夹具最初没有产生保留缺口（classified scan 不保留普通文件行），改为真实链接边界；FakePlatform 初始未按请求上限分批，改用已有单条批次夹具，生产检查与完整断言不变，没有排除新测试。格式、最终 host 工作区 all-targets/all-features clippy 和 Linux GNU/Windows GNU 工作区交叉 clippy（含新目标测试代码）通过。53 份 Markdown 和 23 项文档检查器测试通过；受影响四包 package list 含新增分析/内容流适配及测试模块，没有进行 registry 依赖构建或发布。Linux/Windows 原生运行、Windows MSVC、真实云占位文件及实际系统 Trash 成功的独立缺口仍保留。下一步为有格式/所有权/上下文依据的垃圾规则扩展及其他收尾项；没有本轮性能计时，不宣称端到端提速。


## 项目候选自身结构标记与规则扩展（2026-10-02）

项目规则新增可选 requiredOwnMarkers，默认空以兼容现有 JSON；最多 64 个安全的单组件文件名，与原有 32 KiB catalog 输入限制共用准入。自身全部标记与父目录至少一个标记共同匹配，规则优先级保持 catalog 顺序。JunkService 从同一次遍历的 ordinary-file marker map 按当前 ScanEntryId 消费事实，并使用已有 cleaner VM；不新增遍历、分类时文件读取、工具查询或 crate。标记名称从加载后的父/自身列表派生，缓存及分类上下文摘要自动绑定实际规则字节。旧的仅父上下文匹配 API 对需要自身标记的规则返回无匹配，不从显示路径猜目录 ID。

新增 dart.tool-state 和 node.sveltekit-output 两个 R3 结构候选。Dart 要求父 pubspec.yaml、自身 package_config.json，依据 [Dart 项目工具状态](https://dart.dev/tools/pub/package-layout) 与 [workspace 布局](https://dart.dev/tools/pub/workspaces)。SvelteKit 1/2 要求父 svelte.config.js、自身 tsconfig.json 与 ambient.d.ts，依据 [项目结构](https://svelte.dev/docs/kit/project-structure) 及 1.0.0/2.0.0 的 tagged sync 源码。当前 SvelteKit 3 配置/生成文件已变，旧布局规则不推断新版或自定义 outDir。规则 evidence 明确说明结构、内容及活动的区别；名称集合不证明内容格式、实际工具所有权或执行权限，不把新规则提升为 R1/R2。源文件和锁文件不作为候选。垃圾规则扩展验收仍未勾选，后续继续有界原生内容格式验证、所有权及活动依据。

既有 fixtures 新增共享的九组受控布局，core 原生扫描和中英文 CLI 使用同一输入与独立预期集合，覆盖 Dart 2.18 单项目、3.6 workspace、SvelteKit 1.0/2.0、同名用户数据、父/自身/兄弟标记错位、目录冒充文件、缺少多个必需标记之一及新版布局拒绝。夹具表达源码/文档中的布局，不声称实际执行这些工具版本；最小 payload 不作为格式验证证据。核心/CLI 仅扩展已有 fixtures 开发依赖的宿主范围，不增加生产依赖。原生会话回归覆盖普通标记变目录、消失后选中刷新撤下旧键、后续全量刷新拒绝旧缓存事实、恢复标记后稳定键恢复，以及 Unix 链接标记不成立；普通 payload 经独立 fs::read 核对不变。加载准入回归覆盖自身列表默认值、类型、规模及逃逸名称；规则编辑同时改变 marker 选择和摘要。

交付验证（arm64 macOS，Rust 1.98.0）：工作区 896 项通过、0 失败、2 项原有基准 ignored，命令仍为 cargo test --workspace --all-features --locked -- --skip trash_moves_ordinary_paths_without_confirmation_in_machine_invocations，已诊断系统 Trash 成功用例仍显式排除。首轮新增 core 测试误用不存在的状态字段，按实际 ScanSuccess.output.status 修正；Windows 交叉检查发现 CLI 夹具调用 Unix-only canonicalization helper，改为 Unix 原逻辑、Windows 原生 fixture path，保留目标测试范围。最终 host 工作区 all-targets/all-features clippy、Linux GNU/Windows GNU 工作区交叉 lint（含测试）通过；工作区矩阵后修正这项夹具的 cfg 路径，并避免无关名称或旧规则额外查自身 marker；最终 core 六项分类回归及该 CLI 回归单独复验，其他未变测试复用结果，不称为再次完整矩阵。格式、53 份 Markdown 与 23 项文档检查器测试通过，受影响 catalog/fixtures/core/CLI package list 核对资源与源码保留。没有性能计时或提速结论，没有发布。Linux/Windows 原生运行、MSVC、真实云占位及实际系统 Trash 成功的独立验证缺口保留。


## 格式验证前置：捕获目录下的有界整文件读取（2026-10-02）

扫描器的 LocatorReader 新增 read_captured_regular_file，接受当前捕获的目录行及一个原生 basename，复用现有 root/lineage no-follow 重验及有界祖先枚举，直接在 retained parent 下读取文件。旧小配置读取接口保持不变；新入口调用已有 provider-safe 原生内容流，无第二套目录遍历/内容读取或新 crate。首次零 payload 观察建立当前普通文件身份、filesystem/mount、逻辑长度和变化指纹；与捕获目录 scope 比较后才允许内容，不能复制父 mount 代替文件证据。文件超过配置的单文件/总字节额度立即拒绝，只有 probe 已执行，无截断 payload。完整读取绑定 probe，文件增长、替换或改变不会把旧长度前缀说成完整内容；错误时丢弃暂存字节。

每次调用需至少两个内容阶段额度；路径分量计入 root/目录链与最终文件名，只重新打开一次 parent，probe/full 共用句柄。名称字节也占已有目录限额，所有原生枚举批次继续使用原限制。保留 Vec 只按已核验长度有界预留，不通过不断增长文件扩大缓冲。缺失、链接、类型错误、provider/offline、挂载/身份不一致或取消是失败，不声明原子缺失或完整工具所有权；范围只是稳定观察区间。API 没有跨调用全局 IO/metadata 预算或强制中断内核 IO 的期限，上层必须累计资源并在工作线程调用。

两个原生回归用普通 fs::read/stat 独立对照完整内容和长度，覆盖伪造显示路径、精确边界/空文件、超限仅 probe、无效及逃逸名称、不足阶段/路径/名称预算、取消、链接与目录类型、缺失、同名父目录替换，以及 probe 后受控增长。计数来自 backend 的实际调用，不制造预期长度；保留旧目录使身份反例不依赖 inode 重用。Linux 新夹具显式使用 /dev/shm 的 tmpfs，缺少宿主能力应报告环境缺口；Windows 没有套用 Unix canonicalization，原生链接分支只在 Unix 运行。

验证（arm64 macOS，Rust 1.98.0）：scanner 全量 76 项通过，最后增加最终文件名的分量计费后两个新增原生回归再次通过；此前 896 项工作区结果中未变测试复用，合计覆盖 898 项，不称为再次完整矩阵。最终 host 与 Linux GNU/Windows GNU 工作区 all-targets/all-features clippy（含目标测试）通过；无 backend 的 scanner 合约检查、格式/diff、53 份 Markdown 与 scanner package list 通过。新目标测试只进行了交叉编译，Linux/Windows 原生运行、MSVC、真实云占位及实际系统 Trash 成功仍未验收；工作区仍保留原两项基准 ignored 和已诊断系统 Trash 成功用例的显式排除。没有新计时或提速结论，没有发布。

垃圾规则扩展验收继续未勾选。本单元闭合有界、provider-safe 整文件读取接缝，尚未解析 Dart/SvelteKit 的内容，也未连接 CLI/会话/缓存动态解释或新的格式回收准入。后续应将内容格式、未知/无效/未检查状态与所有权/活动分开，缓存命中重新观察；格式缺口不能仅靠旧 classification、Git ignore/high 或 native identity 回收资格消失。


## Dart 当前格式证据与回收边界（2026-10-02）

- 已接入可独立调用的 `junk::format::ProjectFormatSession`：使用前一阶段捕获目录完整读取，不以显示路径重开，不读取 URI 指向的包内容，也不调用 SDK。识别 pub v2 包映射、自声明 generator/version 和父根 `../` + `lib/` 引用；这是有限 profile，不是 Dart URI、YAML、workspace 所有权的完整实现。未知扩展字段允许；已知字段重复/缺失或不一致为 invalid；未来版本、非支持 URI、缺失 pub/父根签名保持 unknown。用户可以仿造所有这些字段，所以 recognized 不等于生成者身份或可丢弃证明。
- 规则增加严格可选 `contentFormat`，profile 必须声明其固定输入；实际加载字节仍决定缓存/会话摘要。新/历史/Base 候选是 not_checked，每个调用/revision 有界观察当前内容，JSON/Human/TUI 均展示结果。配置字节与格式答案不写入文件系统缓存，正常目录结构事实仍可缓存，unknown 候选不被作为“没有垃圾”永久丢弃。
- 默认每项最多 256 KiB、每次调用最多 128 项、累计最坏内容预留 32 MiB；失败不返还请求预算。每项祖先最多 32 个组件、目录枚举沿用单次有界 reader，累计工作受尝试数约束；scan ID 去重键最多 1024 字节。解析前还限制整个 JSON 的嵌套深度，包括被 serde 跳过的扩展字段；字符串内括号不计深度。序列处理只保留小型状态，不保存包 URI 或配置原文。默认 5 秒合作期限与取消覆盖读取/解析阶段，不能中断阻塞内核调用。没有扫描加速或真实云 provider 性能声明。
- Git 忽略仍可作为独立报告事实，但不能将内容 unknown/invalid/not_checked 提升到 high。recognized 行也保留 `project_ownership_not_verified`：CLI 批量回收、TUI 展示准入及后台 worker 均拒绝此 profile，不从内容签名获得删除权。不声称解决既有 pathname 到系统 Trash 的竞态。
- 独立夹具加强 Dart 2.18/3.6 的 package-map 内容；它们是按文档/源码编写的例子，不是运行对应 SDK 的录制。回归覆盖格式状态、重复字段/包名、深度和内容预算、provider 拒绝、取消、链接、同名同长度内容变化、缓存不保存格式答案、Base/Current/选中及完整刷新、Git 不提升及两层回收拒绝。SvelteKit 仍使用结构夹具；更完整版本采集、内容解析、所有权/活动、目标宿主运行验证继续未完成，规则扩展验收不打勾。

主要依据：[pub package-config 源码](https://github.com/dart-lang/pub/blob/master/lib/src/package_config.dart)、[Dart workspace 文档](https://dart.dev/tools/pub/workspaces)。

本阶段验证：初始工作区矩阵 907 项通过、2 项基准 ignored，继续显式排除已诊断的 `trash_moves_ordinary_paths_without_confirmation_in_machine_invocations` 宿主 Trash 挂起用例。后续修改复验中，深层扩展字段回归暴露 serde 跳过未知字段时没有递归限额，已加入完整 payload 的词法深度资源准入；最终格式 9 项、catalog 27 项、CLI 单元 48 项与契约 60 项/relay 1 项、TUI 89 项通过，Core 最终整体运行 209 项通过、1 项失败、1 项基准 ignored。失败为未修改的工具成功探测用例在 300 ms 内返回 `TimedOut`，发生在并行交叉编译期间；同一二进制受控子进程的三次单独观察为 34.87/11.03/11.46 ms，7 项工具契约隔离串行运行通过。这只定位到成功用例的时间预算，未证明并行失败根因或稳定性，因此保留验证缺口，不能将此最终矩阵写成全绿。由于 Core 失败，随后 TUI 步骤未执行，已单独补跑并通过。

最终 host 工作区 all-targets/all-features clippy、Linux GNU 与 Windows GNU 工作区交叉 clippy（含测试代码）、后续 TUI 文案的两个目标复验、fmt/diff 与 53 份 Markdown 检查通过；core 包清单包含新模块和测试。未执行 Linux/Windows 原生运行、MSVC、实际云 provider 或系统 Trash 成功验证。旧性能/平台/执行竞态与规则所有权、活动收尾继续未完成，不据此关闭整体路线图。


## Legacy SvelteKit 当前内容签名（2026-10-02）

- `svelte_kit_legacy_sync` 作为严格可选 catalog profile 接入原有 `ProjectFormatSession`，要求已捕获的 `tsconfig.json`、`ambient.d.ts` 普通文件。支持从 1.0.0/2.0.0 tagged sync 源码核对的 node/bundler 生成签名：原生完整读取、已知 JSON 字段类型/重复检查、默认父根/type/include/exclude 及编译选项；ambient 只识别生成头、kit 引用和四种 env module 声明签名，不声称实现 TypeScript 语法验证。自定义 config hook、未来输出、缺失签名、链接/权限/provider/身份变化保留 unknown；没有求值 JS、执行 SDK、打开 alias/glob 或序列化环境声明内容。识别签名不推断实际安装的工具版本。
- 两个文件读取后各完整重读一次，对比先前结束观察与当前开始观察的原生身份/变化指纹及字节。文件间变化撤回 recognized，原因 `content_changed_between_reads`；签名结果的 reason 明确包含 `non_atomic`，不承诺封闭目录代际或原子跨文件快照。
- 首次 I/O 前预留四个单文件上限，即默认每项最坏 1 MiB，失败不返还；与 Dart 共用 32 MiB 内容请求预算，所以纯 SvelteKit 调用最多观察 32 项。最多 128 项候选及每项最多四次有界原生读取共同限制累计元数据/祖先枚举；单个读取的零字节 probe 与 full read 都计入其自身限额。5 秒期限保持合作式，不打断阻塞内核调用；不作扫描性能改善声明。
- CLI/TUI、缓存命中和选中/完整 revision 沿用当前格式观察，不保存格式答案。所有权和活动仍未确认，两个 profile 都保留 `project_ownership_not_verified`；Git 不提升缺失内容证据，已识别签名同样被批量/交互/后台 Trash 拒绝。源文件、锁文件、自定义路径及 SvelteKit 3 新布局仍不匹配；旧 pathname 到系统 Trash 的竞态未解决。
- 独立夹具已加强为两代内容签名；仍是按源码编写的例子，尚不是对应 SDK 的运行录制。新增回归覆盖两代正例、用户源/更改的声明、无效 JSON/UTF-8、预算边界与零读取、provider/取消、两文件之间变化、显示路径伪造、会话同名同长度内容变更和刷新、locale 稳定报告与独立回收拒绝。完整所有权/活动、更多工具版本、实际 provider/目标宿主的路线图缺口仍保留，规则扩展验收不打勾。

主要依据：[1.0.0 配置生成](https://github.com/sveltejs/kit/blob/%40sveltejs/kit%401.0.0/packages/kit/src/core/sync/write_tsconfig.js)、[2.0.0 配置生成](https://github.com/sveltejs/kit/blob/%40sveltejs/kit%402.0.0/packages/kit/src/core/sync/write_tsconfig.js)、[2.0.0 声明生成](https://github.com/sveltejs/kit/blob/%40sveltejs/kit%402.0.0/packages/kit/src/core/sync/write_ambient.js)。

本阶段验证：完整工作区 `cargo test --workspace --all-features --locked -- --skip trash_moves_ordinary_paths_without_confirmation_in_machine_invocations --test-threads=1` 串行运行 918 项通过、0 失败、2 项原有基准 ignored。已诊断的宿主系统 Trash 挂起用例仍显式排除，未验证实际 Trash 成功。为与交叉编译资源分开，本轮先完成测试再执行 lint；上一阶段 300 ms 工具成功探测的并行超时根因仍未解决，串行通过不等于其并行稳定性已证明。

最终 host 工作区 all-targets/all-features clippy、Linux GNU/Windows GNU 工作区交叉 lint（包含测试代码）、fmt/diff、53 份 Markdown 检查通过；core 包清单包含新增 SvelteKit 模块。未运行 Linux/Windows 原生、MSVC、实际云 provider 或对应 SDK 版本录制，不据此关闭规则扩展和整体路线图。


## npm 安装发现资源边界与热缓存诊断（2026-10-02）

此前 npm 安装发现无上限枚举各管理器版本及 PATH，反复 canonicalize 比较，并逐安装重枚举同一缓存的直接子项；子进程预算耗尽、取消或期限到达后仍可能继续文件系统工作。本轮在原 tools 模块内加入 `ToolDiscoveryLimits` / `ToolDiscoveryReport`，原 Vec API 保留为有界正向清单兼容入口，不能据其空结果证明没有安装。

- 默认整个 npm 调用最多 4,096 次文件系统操作、64 个不同 executable 身份、4 MiB 累计路径/字符串/集合节点准入估算，以及单路径/环境值 64 KiB。失败的探测和目录迭代结束检查也扣额度；不因去重、失败或丢弃临时索引返还。环境复制、路径展开及集合都有固定输入或准入边界；估算不是精确 RSS。文件系统调用共享 ProbeRunner 的 10 秒总预算、启动额度和取消，前后检查；同步内核调用仍不可强制中断。
- executable 拼写解析和同一缓存路径的活动观察在本次调用内去重，不持久保存。工具 launcher 解析保留管理器符号链接支持，这是安装清单而非 scanner/删除权限；缓存根与直接子项用 no-follow metadata，链接目标不成为活动时间。Windows 额外拒绝声明 reparse/offline/recall 属性的活动根；这不是原生身份绑定或 provider 运行验收，路径与时间观察都不提供删除授权。活动只说明非原子的 root/direct-child mtime，截断/读取失败不返回部分最大值，也不能证明精确最后使用时间或无活动。
- JSON 新增 `npmDiscovery` 的 complete/incompleteReason，显式项目根未请求该发现时为 null；human 两种语言提示缺口，CLI 为 partial/退出 4。核心会话发送可靠 discovery_incomplete 及 Partial 终态，并保留正向安装和已完成候选；完整根候选缓存的 classification context 在发现不完整时拒绝复用。文件事实索引仍独立验证，不缓存工具发现或活动答案。
- 受控回归覆盖零/到期/取消/启动耗尽、晚到取消、文件操作/路径/数据/安装上限、正向清单保留、可执行路径去重、目录截断未知、每调用活动重观察、链接自身与目标区分、共享缓存、上下文缓存拒绝、核心 Partial 事件和两种语言的 CLI 报告。共享缓存夹具有两个真实测试 launcher、128 个文件；320 次操作额度能完成一次缓存遍历及安装探测，不能容纳两次遍历。普通 read_dir/stat 及完整 payload 是独立核验路径，不从实现计数制造活动时间。

[debug 热缓存 PTY 原始诊断](junk-tui-debug-warm-diagnostic-2026-10-02.json)记录重构前 clean 632a6e7 的本机 arm64 macOS、Rust 1.98.0 debug 二进制，三个独立、预置缓存的目录，每次 8,192 个 8 字节文件及一个 sentinel。历史首屏为 76.2/121.0/73.5 ms，当前完成视图为 182.7/280.0/180.2 ms，q 返回 0、终端属性/alternate screen 恢复，独立数量/长度及 sentinel 核验通过，未发送删除键。起点是 PTY wrapper 启动后的采样，不是纯扫描或进程 wall；OS 缓存不受控，没有记录验证命中数或二进制 hash。三次未复现旧 10 秒超时，未取得慢堆栈，因此根因项继续未完成；这些记录不能证明修复或推断尾延迟。旧 300 ms 工具测试在并行构建下的超时也未定位，本轮未修改其期限。

工具缓存根的候选展开/指纹路径等资源审计、规则所有权/活动依据、Linux/Windows 原生与 MSVC、真实云 provider、实际 Trash 成功及最终 pathname 竞态仍未完成，不勾选整体规则/会话/TUI 验收。

本阶段验证（arm64 macOS、Rust 1.98.0）：完整工作区串行 928 项通过、0 失败、2 项原有基准 ignored，仍显式排除已诊断挂起的 `trash_moves_ordinary_paths_without_confirmation_in_machine_invocations`，实际系统 Trash 成功未验证。随后追加 PATH 临时清单上限，最终 core 全量 225 项通过、1 项原有基准 ignored；最终 CLI 单元 48 项、契约 62 项与 relay 1 项通过。其余未变代码复用工作区结果，合计覆盖 930 项，不称为又一次完整矩阵。Windows 交叉 lint 指出枚举循环可用 while-let，已等价改写并复验 tools；最终活动根及缺失路径/迭代失败区分后，core 全量复验包含新增缺失观察回归。初次共享缓存测试误放到函数内，未实际运行，移到模块级后真实通过，没有将零项测试视为验证。格式、host/Linux GNU/Windows GNU 工作区 all-targets/all-features clippy（含测试分支）、53 份 Markdown 检查通过；core 包清单包含安装测试模块。源码与编译检查不证明 Windows reparse/provider 或 Linux 原生行为，MSVC、目标宿主、云 provider 与上述 Trash 缺口保留。

另外记录一项未定位验证缺口：上述最后 core 复验最初为 224 项通过、1 项失败、1 项基准 ignored，失败是共享缓存正例的 `ProbeUnavailable`，当时尚未记录子进程具体失败类型。加入只记录状态/耗时/字节数、不打印答案的测试诊断及失败夹具保留后，完整相同顺序运行 225 项通过；随后预先固定十次独立同二进制运行也全部通过，未提前遇到通过即停止。没有放宽 2 秒 probe/10 秒总期限、移除断言或排除测试，仍未证明原失败根因，不能把后续通过表述为修复该间歇问题。此处的已通过检查与未定位稳定性缺口分别保留，不称为整体全绿。

Windows 属性依据：[Rust MetadataExt::file_attributes](https://doc.rust-lang.org/std/os/windows/fs/trait.MetadataExt.html#tymethod.file_attributes)、[Microsoft 文件属性常量](https://learn.microsoft.com/en-us/windows/win32/fileio/file-attribute-constants)（2026-10-02）；使用已有 windows-sys 常量，不自行复制 ABI 值。


## 工具缓存根的有界原生布局快照（2026-10-02）

工具缓存根原来在布局预算之外展开版本目录，并用无上限 `read_dir` 检查分片；`flatten` 忽略迭代错误，分片的 `entry.metadata()` 还会跟随最终链接。此次复用 core 内已有 `LayoutDiscovery`，没有新增 crate、规则引擎或后台线程。

- 工具根、浏览器和 known-root 共享 4,096 个不同目录探测、16,384 条原生枚举记录、1,024 个根引用及 8 MiB 数据准入估算；工具答复、路径副本、解释快照和筛选列表也扣数据额度，单路径超过 64 KiB 在复制/原生访问之前拒绝。5 秒和取消在原生调用之间检查，不能中断阻塞内核调用。npm 安装/活动发现的独立预算保持不变。
- 版本容器按路径及筛选类型每调用只枚举一次；完整性与正向路径分开保留。精确分片数需要完整 EOF、合法名称，以及 retained-parent 下 no-follow 的普通目录、filesystem/mount 检查。每次只保留一个枚举父句柄和一个临时子目录句柄，不为各分片重复打开祖先链或保留目录根索引。枚举前后检查父身份及变化指纹，但不宣称跨文件原子快照。
- 工具根与其他布局根一样保留原生身份、filesystem/mount 及根变化指纹；分类须与当前扫描的完整事实一致，同路径替换不能沿用旧匹配。整根缓存上下文加入工具根原生事实。根选择按已捕获身份去重，live/stale/unknown 关系及旧格式提示在发现时计算，候选解释不再 canonicalize/stat；这些答案每调用重建，不写文件系统缓存，也不证明无活动或可删除。
- 后续预算耗尽仍保留已准入的正向根和解释，缺口沿已有 `layoutDiscovery`、核心可靠错误及 Partial 终态传播，并拒绝整根候选缓存复用。未知答复/未能原生观察的报告根保留 unknown，不推断 stale。取消、期限或零字节预算不能进入后续 resolver。
- 回归通过普通目录枚举/no-follow metadata 独立核对版本集合和 256 个分片；覆盖链接/普通文件冒充分片、枚举前缀恰好等于期望值仍不能作精确匹配、替换父目录、超长输入、筛选缓存隔离、单父句柄观察、后续上限保留正向根、当前 native 身份绑定、显示路径变化及相同路径替换导致上下文失效。

没有本轮端到端计时或新的加速倍数。规则所有权/活动、其他系统发现路径审计、Linux/Windows 缓存体验、原生宿主/MSVC、真实 provider、系统 Trash 成功及最终 pathname 竞态仍保留。旧 300 ms 正例超时在本轮无交叉编译的串行 core 运行也复现，不能仅归因于并行构建。

交付验证（arm64 macOS，Rust 1.98.0）：最终完整工作区 `cargo test --workspace --all-features --locked -- --skip trash_moves_ordinary_paths_without_confirmation_in_machine_invocations --test-threads=1` 为 937 项通过、0 失败、2 项原有基准 ignored；core 232 项通过，CLI 单元/契约/relay 为 48/62/1 项通过。受影响 core 及最终 host/Linux GNU/Windows GNU 工作区 all-targets/all-features clippy（含目标测试代码）、fmt/diff、53 份 Markdown 检查及 core 包清单通过。真实系统 Trash 成功用例仍因已诊断挂起显式排除；Linux/Windows 原生、MSVC 和真实 provider 仍未验收。

保留本轮失败记录：最初 sandbox 中 junk 专项为 118 项通过、1 项失败、1 项 ignored，未改动的 `an_untouched_root_round_trips_as_current` 在 10 秒 fixture 历史 settle 限额内失败；采样请求到达时进程已自然结束，未取得阻塞堆栈。随后可访问宿主事件服务的 core 全量运行中，该缓存测试通过，但旧 `captures_complete_answer_and_exit_status` 在 300 ms 内 `TimedOut`，结果为 231 项通过、1 项失败、1 项 ignored，当时没有交叉编译运行。最后工作区全量通过，不证明前述间歇原因已修复；没有放宽期限、移除断言或排除这两个测试，不将整体路线图描述为全绿。下一步继续规则所有权/活动及尚未定位的性能、平台收尾。


## 项目规则的执行约束与未核验所有权（2026-10-02）

审计发现，原有 `project_execution_blocker` 只拦截带内容 profile 的 Dart/SvelteKit；通用 `project.build-output` 在证据文案中声明 report-only，却能与旧 Rust/Node/Python/Maven 规则一样仅凭名称/父 marker/完整覆盖进入批量或 TUI Trash。Git ignore/high 不是所有权或可丢弃性证明，独立 Cargo cleaner 的 typed evidence 也明确将 sharing/activity 保持 not_checked，不能借作授权。

- catalog 新增严格 `ProjectExecutionPolicy`：`report_only` 与 `require_ownership_and_activity`，省略时采用后者。JSON 不能配置为 allow/native 权限。内置泛化输出及 Dart/SvelteKit 显式仅报告；旧工具项目规则要求独立独占所有权和活动证据。目前这些观察尚未实现，因此所有项目行继续展示但不能回收，不将此安全修复作为规则扩展完成。
- core 的 `JunkExecutionPolicy` 随当前候选解释传递，cache restore 初始为 not_checked；只在当前已加载规则解释时重建。缓存不保存授权或拥有者/活动结论，原尺寸/native lineage/覆盖事实独立保留。bulk、TUI 显示准入、provider 启动与后台 worker 均复用同一检查，不通过 confidence、risk 或可编辑 blockers 字符串授权。已有平台原生准入及独立临时对象隔离协议保留。
- JSON 新增 locale-independent `executionPolicy`；project_report_only、project_ownership_not_verified、project_activity_not_verified 与 rule_evidence_not_revalidated 明确标记不同缺口。Git 仍按原有语义解释 ignore/tracked 证据，但 high 不消除执行要求。human 两种语言明确展示回收受限；CLI help、README 和两个 site 语言版本同步。没有新增 crate、探测线程、SDK 执行或扫描开销阶段。
- 回归用普通 Git check-ignore 及完整文件字节独立核对实际命中的用户数据；覆盖通用输出与 R1/R2 旧规则、content profile、风险/高置信度/展示 blocker 清空不能绕过、bulk 与 worker 均在 Trash 前拒绝、TUI 刷新后依旧拒绝、缓存 not_checked 与本次不同规则重解释、严格 policy admission 及双语机器/人类报告。原 native worker 替换/链接回归改用受控平台式下层行，继续验证身份变化必须在真实 Trash 调用之前拒绝；没有放宽断言或把项目 layout 作为有效删除证明。

本单元只修复执行约束缺口，没有实现所有权/活动证明、扩大生成格式语义或采集真实 SDK 版本，也没有端到端性能结论。规则扩展、系统会话/TUI 目标宿主、跨平台缓存体验、旧间歇超时、真实 provider、MSVC、Trash 成功和最终 pathname 竞态继续保留。

交付验证（arm64 macOS，Rust 1.98.0）：完整工作区 `cargo test --workspace --all-features --locked -- --skip trash_moves_ordinary_paths_without_confirmation_in_machine_invocations --test-threads=1` 为 941 项通过、0 失败、2 项原有基准 ignored，其中 catalog/core/CLI unit/contracts 为 28/233/49/63 项通过。受影响 catalog/core/CLI 及 host/Linux GNU/Windows GNU 工作区 all-targets/all-features clippy、fmt/diff、53 份 Markdown 检查和三个受影响包清单通过。Windows 初次检查发现新增测试误用 Unix-only 路径助手，改为正确平台夹具后 Windows 全工作区复验通过；宿主新增契约实际运行 1 项通过，其余未变代码复用完整矩阵，不称为再跑一次全矩阵。一次 exact 过滤拼写只选中零项，未计作验证，随后完整测试名真实执行。

早期失败均记录并核对：core 的 2 项 Git 测试、CLI 的 2 项缓存单元及 2 项 Git 契约原来精确断言没有项目执行阻碍，已更新为完整的所有权/活动加原 Git blocker 列表，保留独立的 confidence/tracked/ignore/原生字节断言。新增 CLI 正例的最初无仓库夹具观察到实际祖先 Git 边界，改为隔离夹具内创建真实仓库，保持生产边界拒绝和精确断言不变。没有放宽期限、反复重试偶发失败直到通过、删除测试或隐藏后续未运行步骤。既有系统 Trash 成功挂起仍显式排除；Linux/Windows 原生宿主、MSVC、真实 provider 未验证，旧 300 ms、共享缓存 ProbeUnavailable 与 debug PTY 停顿根因仍未解决。下一步继续独立项目上下文/所有权/活动观察和版本采集，验收清单不因这次阻止错误准入而勾选完成。


## 实际 SvelteKit SDK 生成样本（2026-10-02）

此前 SvelteKit 正例仅按 tagged source 独立编写，不能证明识别器兼容实际 SDK 输出。本轮在隔离项目/home/store 与受控环境运行固定的 @sveltejs/kit 1.0.0、2.0.0 sync，保存未经改写的生成配置和 ambient 声明、原始项目输入、冻结依赖锁、上游 MIT license 与逐文件 SHA-256/长度 receipt。实际宿主为 arm64 macOS、Node v24.19.0、pnpm 11.25.0；没有更改 SweepX 依赖、运行用户配置或生成删除授权。采集入口和复验命令见[项目规则执行样本](../development/project-rule-corpus.md)。

普通 Rust 回归离线使用真实记录，独立校验所有保留文件的 bytes/hash；生产 profile 直接接受两份原始输出，不清理注释/换行来迎合 parser。原生 core 回归通过内置垃圾扫描取得候选，目录混入个人笔记仍 recognized 且拒绝回收，普通 fs::read 核对输入/生成文件未改动；macOS 缓存不保留格式答案，之后修改配置重新观察为 unknown。自定义 rootDirs 的受控反例仍 unknown，未冒充实际 SDK 自定义配置采集。

采集工具拒绝覆盖已有或部分输出，每文件最多 256 KiB，每子进程最多 1 MiB 输出及 180 秒，退出/失败/取消停止自己启动的 POSIX 进程组并等待直接子进程。六项采集回归覆盖失败、无限输出、已退出 leader 留下子进程、保留已有采集、256 KiB 精确字节边界与链接/FIFO 拒绝；不把这些工作限额宣称为全局磁盘/网络配额。normal scan 不运行 SDK，未新增 crate、生产观察阶段或性能结论。

本单元补上两个真实 SvelteKit 版本的正例证据，没有完成 Dart SDK 采集、更广 SvelteKit 版本/配置、完整语言语义、项目独占归属或活动观察；规则扩展仍未勾选。当前 Cargo substrate 与 junk 普通 marker 的 native-row 接缝仍需处理，不能从省略的 manifest 行伪造完整扫描身份。平台运行、云 provider、MSVC、Trash 成功及旧间歇失败/竞态继续保留。

交付验证：完整工作区 `cargo test --workspace --all-features --locked -- --skip trash_moves_ordinary_paths_without_confirmation_in_machine_invocations --test-threads=1` 为 944 项通过、0 失败、2 项原有基准 ignored，既有系统 Trash 成功挂起继续显式排除。之后仅加强 cache JSON 无格式字段断言，实际目标回归再执行 1 项通过，其余未改行为复用完整结果。受影响 core/fixtures、host/Linux GNU/Windows GNU 工作区 all-targets/all-features clippy、fmt/diff、54 份 Markdown 检查通过；fixtures/core 包清单通过，fixtures 包含全部 18 份原始录制文件。采集工具六项测试通过；超时子进程测试用实际 child-ready 标记确认已启动后再检查迟到写入不存在，避免启动失败冒充取消成功。本轮没有重现或宣称修复旧 300 ms probe、共享缓存 ProbeUnavailable 或 debug 热缓存 PTY 问题；跨编译不作为 Linux/Windows 运行证据，MSVC、实际 cloud provider 与 Trash 成功未验收。

最后按仓库冻结依赖重新运行两版真实 SDK，逐文件与原记录比较，两版各八份输入/输出/许可文件全部字节相同；新 receipt 仅采集时刻不同，不用后来的时间覆盖原始记录。采集读取使用限长读和前后元数据核对，拒绝 final link、特殊文件及超出生成项目的路径，不靠 stat 后的无界 read_bytes 声称字节有界。


## 实际 Dart SDK、共享 workspace 与编码路径修正（2026-10-02）

官方 macos-arm64 Dart 2.18.0/3.6.0 ZIP 经其 SHA-256 核对后在任务临时目录展开，未全局安装或纳入仓库。独立隔离的 HOME/PUB_CACHE、显式关闭/抑制 analytics 与无第三方依赖的 offline pub get 产生四份原始记录：两版单项目、3.6.0 共享 workspace 和带中文/空格成员路径的 workspace。workspace 命令从成员调用，实际 SDK 删除过时成员 map 且保留旁边个人笔记；source/lock/map/notes、SDK license、版本/revision、调用目录与逐文件 SHA-256/长度 receipt 均保留。SDK 样本与手写正反例分开，普通 Rust 回归离线消费，不在产品扫描时执行 SDK。复验入口与证据边界见[项目规则执行样本](../development/project-rule-corpus.md#recorded-dart-runs-and-uri-compatibility)。

新增实际 map 回归首次失败，明确为 3.6.0 Unicode workspace 的 unsupported_package_uri：旧识别器只接受 ASCII 字符，拒绝 SDK 自己生成的百分号 UTF-8 名称。本次只扩展有界 URI 文件名签名：普通 ASCII 路径保留无分配路径，转义分支最多暂存已准入的 4096 URI 字节，只解码一次、不留存位置、不打开 URI；坏 UTF-8、控制字符、无效转义、编码的分隔符/dot、递归编码、query/fragment/scheme 等不支持形状保持 unknown。没有新的依赖、crate、探测线程或读取阶段，也没有将识别升级为文件系统/执行授权。

独立 receipt 回归核对全部源输入和生成字节；真实 SDK 格式正例保持原输出，另以明确 URI 正反例覆盖 Win drive 签名、大小写 hex、无效 UTF-8 与结构/控制转义。原生 core 与双语 CLI 物化四份样本，只取得根 dart.tool-state 候选，不把已删除 map 的成员个人笔记目录当垃圾。普通 fs::read 核对所有输入/生成/personal bytes 不变，recognized 根仍保留所有权/活动阻碍和 report_only 执行策略。既有 cache/revision 格式重观察、provider/链接/取消/预算和 SvelteKit 实际样本回归保留。

再次采集四种实际场景后，所有非 map 输入/输出字节一致，map 除 generated 时间和受控 pubCache 临时路径外的全部字段一致；不改写原录制的动态字段或宣称原始字节完全一样。采集工具复用既有有界子进程/文件读，仅增加 SDK 版本拒绝与已有采集保护的独立失败回归。更广 SDK/配置/依赖、完整 YAML/URI/语言语义、独占归属、活动观察与目标宿主/真实 provider/Trash 成功仍未完成；规则扩展不勾选，旧性能/间歇失败/最终路径竞态也不由这些样本关闭。

交付验证（arm64 macOS、Rust 1.98.0）：完整工作区 `cargo test --workspace --all-features --locked -- --skip trash_moves_ordinary_paths_without_confirmation_in_machine_invocations --test-threads=1` 为 949 项通过、0 失败、2 项原有基准 ignored；既有系统 Trash 成功挂起仍显式排除。受影响 core/CLI/fixtures、host/Linux GNU/Windows GNU 工作区 all-targets/all-features clippy、fmt/diff、54 份 Markdown 检查通过；三个受影响包清单通过，fixtures 包含全部 52 份原始 SDK 录制文件（本轮新增 Dart 34 份）。两种采集工具共八项实际进程/文件边界/失败回归通过。初次实际 Unicode map 专项为 0 通过、1 失败，修正生产识别器后全部内容专项 17 项通过，未改写 SDK 正例来迎合旧实现；Linux/Windows 首轮交叉 lint 因抽取后的测试局部变量只在 macOS 缓存分支使用而失败，窄化该绑定后两个完整目标复验通过。该测试绑定修正后宿主内容专项 17 项与受影响 clippy 再通过，其余未变实现复用完整结果，不称为又跑一次全工作区。没有放宽生产 cfg、忽略断言或重试偶发失败直到通过；实际 Linux/Windows/MSVC、云 provider、系统 Trash 成功仍未验收，旧 probe/cache/PTY 间歇原因和最终 pathname 竞态继续开放。

## 工具探测阶段证据（2026-10-02）

旧 `TimedOut` 与 `ProbeUnavailable` 只保留总耗时，不能区分启动、输出或退出等待。`ProbeRunner::last_diagnostics` 现保留最近一次尝试的固定大小记录：admission/launch/setup/drain/complete 阶段、启动返回/管道就绪/首次输出的累计时间、读取字节数、独立的 EOF 和已观察退出状态，以及包含清理的返回耗时。启动失败和预算拒绝也替换旧记录，不回放上次成功；不保留命令、环境、路径或输出内容，不累积历史。完整阶段也不代表成功退出或有效答案，更不能建立所有权、无活动或删除权限。生产默认不打印诊断；测试只打印这些有界事实，期限、取消和原答案准入不变。

[原始阶段记录与独立执行实验](probe-phase-diagnostic-2026-10-02.json)来自本机 arm64 macOS 25.5.0、Rust 1.98.0 debug。先对修改前同一个测试二进制固定运行 60 次答案/退出用例，全部通过，wrapper wall 为 21.0–61.8 ms，没有获得原失败。新增诊断后，同二进制再固定运行 60 次答案用例和 10 次独立共享缓存夹具，也全部通过；artifact 记录二进制/source hash、逐次耗时和阶段事实。host clippy 在 wrapper 被确认完成之前启动，未记录是否重叠，故这些重复只用于诊断，不作为受控性能比较或尾延迟估计。

独立路径用普通 Python 子进程执行 10 对新建、字节相同的 shell 脚本，每次核对 `ready` 的完整字节和成功退出：首次直接执行为 268.1–1029.8 ms，紧接的重复执行为 7.1–10.6 ms；显式 `/bin/sh script` 为 7.6–11.1 ms，但随后首次直接执行该文件仍为 257.2–1038.1 ms。内联 shell 对照为 6.4–170.0 ms。未重置 OS cache，没有 SweepX cache；这些是特定脚本微实验，不能推断真实工具或全盘扫描加速。实际共享缓存探测阶段记录同样表明慢等待主要在 launch 返回之后、首次输出之前，不是 `Command::spawn` 调用本身占用了全部等待。

这定位出一个可重复的宿主首次直接执行效应，尚未取得慢子进程堆栈，不能在进程加载、宿主策略和调度之间归因，也不能将其认定为旧 300 ms 答案测试或 2 秒共享缓存失败的唯一原因。没有改用显式解释器启动生产工具、延长期限或忽略失败；debug 热缓存 TUI 停顿与事件历史 settle 问题也未由本轮实验关闭。两个独立回归用 shell 控制“直接子进程已退出但后代仍持有 stdout”和“stdout 已关闭但直接子进程仍运行”，核对两种失败均拒绝答案且诊断区分 EOF/退出；另外验证成功、启动失败、预算拒绝之间不会残留旧事实。

交付验证：工具专项 24 项通过；完整工作区 `cargo test --workspace --all-features --locked -- --skip trash_moves_ordinary_paths_without_confirmation_in_machine_invocations --test-threads=1` 为 951 项通过、0 失败、2 项原有基准 ignored，仍显式排除已诊断挂起的真实系统 Trash 成功用例。受影响 core 与 host/Linux GNU/Windows GNU 工作区 all-targets/all-features clippy、fmt/diff、54 份 Markdown 检查及 core 包清单通过；诊断 artifact 的 50 个独立执行记录、70 个探测重复记录和成功状态已核验。Linux/Windows 原生运行、MSVC、真实云 provider 与系统 Trash 成功未验收；交叉 lint 不是运行时证据，没有端到端提速结论，原间歇失败仍保留。

## Cargo 当前父配置声明与原生祖先读取（2026-10-02）

此前项目行只有布局/Git/生成格式，Cargo typed cleaner 的输入则要求真正捕获的 manifest 行与完整根身份，不能从 classified scan 省略的普通文件行伪造。scanner 现提供 `read_captured_ancestor_regular_file`：祖先只能来自原始 locator，先验证完整原生链直到候选自身，再在保留的祖先句柄下做同一零字节 probe/整文件读取。超过原扫描根、同名候选替换、链接、mount/provider 不确定、取消或预算不足均拒绝；完整链及文件名仍计入预算，即使目标文件位于根目录也不跳过候选验证。步进最多额外保留一个所选祖先句柄，不从显示路径生成 parent、扫描行或执行身份。已有直接子文件和 Cargo collector 复用这一重开接缝。

catalog 为 rust.target 声明严格可选 `contextProfile: cargo_manifest`，必须包含固定父 marker Cargo.toml；未知 profile 拒绝。core 与 Cargo cleaner 共用一个 TOML/manifest 声明解析器，新增纯声明投影支持 package/virtual_workspace/workspace_package、members/exclude/default-members 的声明模式数、显式 package.workspace 和字符串 path dependency 声明。cleaner 的既有窄 workspace/成员/路径依赖准入保持原限制，不把新声明投影传成身份绑定 typed evidence。

来源访问日期：2026-10-02。Cargo 的[workspace 契约](https://doc.rust-lang.org/cargo/reference/workspaces.html)说明 members 可含 glob、路径依赖可能成为成员、祖先与 package.workspace 都会影响归属，成员默认共用输出目录。因此此处只展示当前 manifest 自己声明了什么：不运行 Cargo、不展开模式、不打开声明路径、不求解祖先/config/env/CLI 优先级，缺失成员字段也不表示没有其他成员或共享。观测区间非原子，不能建立独占归属、无活动或回收权限。

CLI 的既有 projectFormats 阶段与 core 的 Formats worker 阶段同时观察内容和 context，共享最多 128 次尝试、256 KiB/文件、32 MiB 最坏读取预留与 5 秒合作期限；失败也先扣预算，两类 dedup map 总保留受同一尝试数限制。当前规则初始化 context 为 not_checked；历史缓存不持久化配置/声明答案，新调用、缓存重新解释和每个 revision 都重新观察。JSON 增加 locale-stable projectContext，human/TUI 展示声明与失败；渲染留在 CLI，核心数据无需终端即可调用。项目执行约束仍独立，observed 不解除所有权/活动 blocker，布局候选混入用户文件也继续可见但不能回收。

回归覆盖严格 profile/固定 marker、声明模式与实际成员概念分离、中文声明不泄漏到报告、缺失与空列表、显式 workspace/path dependency、无效/重复 TOML、字节/次数共享预算、取消、同名候选替换、完整 ancestor 成本、probe 到内容读取之间变化、缓存不保存 context、同长度 manifest 变化、Base/Current/选中及完整 revision，以及双语 JSON/human 和用户 payload 不变。原生读取用普通文件读取作为独立内容对照，不制造完整 manifest 扫描身份。

独立对照还使用隔离 Cargo home/env 的固定 Rust 1.98.0 `cargo metadata --offline --no-deps`，一个 `crates/*` 声明实际解析出 a/b 两个成员；SweepX 报告 `memberPatterns: 1`，继续保留所有权/活动 blocker，普通读取核对 manifest 和个人 payload 未变化。[Cargo 声明对照记录](cargo-context-oracle-2026-10-02.json)保存声明字节摘要、实际成员数量、SweepX 投影、宿主和二进制摘要；生产扫描和普通 Rust 回归不执行 Cargo，这一额外实验不证明完整配置、归属或活动语义。

交付验证：原生整文件/祖先专项实际执行 4 项，新增核心上下文、会话和双语 CLI 契约通过；完整工作区矩阵 961 项通过、0 失败、2 项原有基准 ignored。随后更新规则来源日期/引用及执行约束原因后，最终 core/CLI 全量 361 项通过、1 项原有基准 ignored；catalog 当前来源字节下的全量结果与未改 scanner/其他 crate 复用此前检查，不称为又跑完整工作区。最终 host、Linux GNU 与 Windows GNU 工作区 all-targets/all-features clippy、fmt/diff、54 份 Markdown 及三个受影响包清单通过。仍显式排除已诊断挂起的真实系统 Trash 成功测试；Linux/Windows 原生、MSVC 与真实云 provider 未验收，没有本轮扫描加速倍数。

保留失败经过：首次祖先专项过滤名未匹配，零项不计作验证，已改用真实 content_tests 模块执行；新增测试最初误用含中文的 Rust byte literal，另一次误移动 format 字段，均修正夹具写法/借用后真实执行。首轮工作区在旧自定义 marker 夹具失败：该夹具替换 Cargo.toml 却保留固定 context profile，现明确关闭该 profile，保留原 marker/digest 断言和生产严格准入。补强 context 对伪造 native policy 的阻断时，最初覆盖了 ReportOnly 的既有原因；生产修复仅在 native-policy 分支阻断 context，独立 report-only 原因继续保留，原断言未放宽；原生替换 worker 的下层平台式夹具明确清除项目 context，继续验证真实 Trash 前的身份拒绝。

该次受影响矩阵还复现旧共享缓存探测失败：[首次输出前的失败阶段记录](cargo-context-probe-failure-2026-10-02.json)显示 launch/setup 约 6.6 ms 返回，2 秒期限内未观察到输出、EOF 或直接子进程退出；tool-b 随后 1.09 秒返回，后续版本查询约 7–13 ms。fixture 已保留，但进程清理后才取得失败记录，没有慢堆栈，不能归因或认定解决。修复上述独立原因优先级后只进行一次预定的最终 core/CLI 矩阵并通过，不把原探测故障解释为该修复解决，没有延长期限、忽略 probe 测试或反复重试直到通过。性能/间歇失败及规则有效配置、所有权/活动仍未完成；声明 observed 不能关闭规则扩展验收。

## 慢工具子进程的活体启动取样（2026-10-02）

[完整取样记录](probe-live-sampling-2026-10-02.json)来自 clean 5dbd7f7、本机 arm64 macOS 26.5.2（Darwin 25.5.0）、固定 Rust 1.98.0 debug 测试二进制。独立实验预定十组新建的相同 shell 脚本及紧接重复执行，固定输出 ready 和成功状态逐次核对；首次输出约 232–855 ms，重复约 7–11 ms。交替五组在 50 ms 后尚无输出时仅对自己创建的 PID 取样，一份未获得报告、一份没有调用栈，三份取得启动栈；取样本身会干扰时序，不能将两组作无干扰性能比较。没有 SweepX cache，未控制 OS cache，也不是端到端扫描计时。

另用同一当前二进制预定十次 exact 共享缓存测试，交替五次对仍存活超过 50 ms 的直接子进程取样。只通过该自建测试进程的 libproc 子进程接口取得 PID，不扫描用户进程表。十次实际各运行一项且通过；五份报告中四份有调用栈、一份空栈，不把 sample 的退出 0 等同于取得可用证据。四份反复显示主要采样位置为 _dyld_start + 0，取样前线程均为 runState=3、userTime=0；少量后续帧进入 dyld 初始化/调试通知。依据 Apple 的[dyld 启动源码](https://github.com/apple-oss-distributions/dyld/blob/main/dyld/dyldMain.cpp)，这些捕获的等待发生在工具脚本逻辑之前；仅有入口 PC 和用户态栈仍不能区分内核授权、调度或其他宿主原因，调试通知帧也可能由取样引入。

初次原生取样工具误将 proc_listchildpids 返回的 PID 个数解释成字节数，十次虽通过却没有取样，原始记录单独保留，不充作栈证据。独立单子进程夹具核对返回 1 与唯一实际 PID 后修正工具，再执行上述预定十次；没有修改生产程序或测试来迎合实验。首次沙箱实验无法调用 ps，完成其自建子进程清理后在可访问原生取样接口的环境进行；没有读取其他进程、修改宿主安全设置、延长期限或改用解释器启动生产工具。

此次捕获的是成功但慢的启动，未重现旧 300 ms/2 秒失败当次、debug 热缓存 PTY 超时或 FSEvents settle 失败；这些项继续开放。原生实验期间没有交叉编译，不据此声称扫描提速或问题修复。源码未变，只重新构建当前 core 测试二进制并运行上述 exact 测试；文档和原始记录检查不替代工作区或目标宿主验证。

## Cargo 当前本地输出配置声明（2026-10-02）

rust.target 的当前上下文现同时观察父目录 Cargo.toml 和该目录下 .cargo/config、.cargo/config.toml。core 复用独立 Cargo cleaner 的有界 TOML/target-dir 解码器，不新增解析器、工具进程或 crate；JSON projectContext 增加固定大小的 cargoConfig，逐文件报告 status/reason/declared，CLI human 与 TUI 复用同一显示函数。仅受支持的相对目录声明为 observed，绝对/父级路径、include、错误类型等保持 unknown，坏 TOML 为 invalid；不将窄 decoder 的拒绝解释成完整 Cargo 语法无效。路径值不保留、求解或打开；两个文件各自的声明都展示，枚举未见成员为 config_not_observed_non_atomic，不能升级为全局配置不存在。

来源访问日期为 2026-10-02。Cargo 的[配置文档](https://doc.rust-lang.org/cargo/reference/config.html)规定两个名字共存时使用无扩展名的文件，并列出 target-dir 的环境/CLI 覆盖。此处的联合观察没有封闭快照，cwd、祖先、Cargo home、环境与 CLI 作用域也未求解，因此 consistency=non_atomic、precedenceComplete=false；不以某个已见文件或缺失字段选择实际输出目录，不解除项目所有权/活动回收阻碍。纯解析 API 的结果本身不建立原生来源。

scanner 的新祖先配置观察先复验原始完整链直到候选自身，再从同一个捕获根重新走到所需祖先，取得未消费的枚举游标；第二次观察的类型、身份、filesystem 和 mount 必须与第一次一致。不能把第一次已消费的游标交给 .cargo 搜索，不能从 display path 构造 parent 或伪造 manifest/root 行。两次遍历共用目录条数/字节预算，部件预算保守计入完整链。配置对沿既有单 .cargo 句柄/完整有界枚举路径读取，两成员共用载荷预算。既有整根配置观察同时迁入共享 provider-safe 零字节 probe/完整 stream，文件由原生 mount 详情绑定，完整读取匹配 probe 指纹；未知 provider、链接、身份/挂载变化、取消或超限拒绝且没有普通读取 fallback。原有 Cargo home presence-only 路径继续不读内容。

一次 Cargo context 尝试在任何 I/O 前预留 manifest 加两个配置文件的最坏载荷，失败不返还；默认最多 128 次尝试、每文件 256 KiB、累计 32 MiB，因此最多准入 42 项完整 Cargo context 尝试（与其他格式共享），两配置文件单次合计最多 512 KiB，调用方更小限制保留。配置对要求五个请求额度以覆盖目录与两文件的 probe/full 阶段；内容/上下文仍共享 5 秒合作期限，不承诺内核调用硬实时。固定大小投影计入候选/队列模型预算，观察仅在本次 invocation/revision 去重，缓存不保存答案。

原生回归用普通 fs::read 独立核对两个成员内容；覆盖伪造显示路径、扫描根以上拒绝、候选替换、全链部件与请求限额、provider 拒绝、probe 后变化、超大文件、链接和非原子未见成员。核心/会话/双语 CLI 回归覆盖两名共存、当前调用去重、新调用/选中/完整刷新重观察、缺失字段与未见文件区分、路径不泄漏、预算不足以及回收阻碍保留。最初两项 scanner 正例失败，随后诊断分别补上未消费游标和原生文件 mount 观察；CLI 最初也捕获 null 而不是声明 true。没有改弱正例、复制父 mount 或把失败当 absence。

[独立 Cargo 配置对照](cargo-local-config-oracle-2026-10-02.json)在固定 Cargo 1.98.0、隔离 home/覆盖环境的三个 offline metadata 场景中核对：两个文件均声明、无扩展名文件未声明 target-dir、只有现代文件。实际 Cargo 分别使用 legacy 路径、默认 target、modern 路径；SweepX 分别报告各文件自己的声明而保持 precedenceComplete=false 和项目回收阻碍。普通读取确认配置/manifest/个人载荷未变。生产和普通 Rust 回归不执行 Cargo；这个对照不证明全部有效配置、所有权、活动或删除安全。

交付验证：完整工作区串行 965 项通过、0 失败、2 项原有基准 ignored，仍显式排除已诊断挂起的 trash_moves_ordinary_paths_without_confirmation_in_machine_invocations，实际系统 Trash 成功未验证。之后仅去除重复测试断言、补内部 rustdoc，并将 Linux 配置内容夹具放到已知本地 /dev/shm；最终原生内容/祖先专项 6 项通过，其余未变宿主行为复用工作区结果，不称为第二次完整矩阵。最终受影响 crate 及 host/Linux GNU/Windows GNU 工作区 all-targets/all-features clippy、fmt/diff、54 份 Markdown 和三包清单通过；三个独立 Cargo 对照的投影、状态及保留字节核验通过。Linux 专用测试代码只交叉 lint，原生 Linux/Windows、MSVC、真实云 provider 和系统 Trash 成功仍未验收。没有端到端计时或提速结论；旧 probe/PTY/FSEvents 间歇失败及有效配置、所有权、活动和最终 pathname 竞态继续开放。

## 合并 Git 范围查询与扫描计时（2026-10-02）

每个项目候选原先分别启动 Git，查询工作区顶层与绝对 .git 位置，然后查询 tracked/ignore。共享 GitEvidenceSession 现在用一次有界 rev-parse 同时取得两个位置，普通候选完整判断由四次启动减到三次；tracked 候选仍在 tracked 命中时提前拒绝。两个位置继续各自进行原生 no-follow、identity、filesystem/mount 和 fingerprint 核对，候选与仓库的前后复验保持原路径，不跨候选或调用缓存范围答案。Git 环境重定向仍移除，外部配置改变工作区时仍拒绝，名称/ignore 不提供项目回收权限。CLI 与 TUI 的 Git 阶段共用这次修改。

来源访问日期为 2026-10-02，Git 的 [rev-parse 文档](https://git-scm.com/docs/git-rev-parse)定义工作区与绝对 Git 目录输出。联合结果仅接受两个完整绝对路径记录，截断、额外记录、空/相对路径或失败均不提供范围依据；保留原 Unix 无损字节及 Windows UTF-8/CRLF 解码契约。Unix 原生名字含换行时不采用联合拆行，继续两个独立有界查询；该分支不宣称减少启动。新增回归实际创建中文/换行工作区，用独立 Git ignore 与普通文件读取对照；三次启动额度仍能完成普通候选解释，复用扫描事实时新 index 的 tracked 优先，外部 core.worktree 变化在同一会话内重查，项目回收阻碍保持。

[完整扫描对照](git-scope-benchmark-2026-10-02.json)使用本机 arm64 macOS Darwin 25.5.0、Rust 1.98.0、Apple Git 2.50.1 的默认 CLI feature/debug 构建；修改前来自 d1fc89e，artifact 保存两个二进制及源文件摘要。受控仓库有 32 个显式项目根，每个 target 内 64 个文件、18,400 逻辑字节，共 2,048 文件；30 个未跟踪忽略目标、一个带跟踪文件的目标、一个未忽略目标。独立 Git 命令核对每个目标的 index/ignore 关系及联合/两次 scope 字节一致，普通目录枚举、长度和全部原始文件字节核对数量/总量/无改动。修改前后全部候选、当前 Git/配置解释与执行约束一致，只排除单次扫描 ID 等观察标识；不执行 Trash。

最终测量固定每个二进制六轮空 SweepX 缓存与六轮热尝试，交替修改前/后顺序；没有同时运行本任务的编译或测试。OS cache 未清空或受控，不将空 SweepX 缓存称为冷磁盘。两个二进制各自首轮热尝试为 32 根 miss，另五轮均为 32 根 hit，按实际命中单独归组，不能把六轮全叫缓存命中。

| 实际状态 | 修改前扫描 wall 中位数 | 修改后扫描 wall 中位数 | 修改前 Git 阶段中位数 | 修改后 Git 阶段中位数 | 每二进制样本数 |
| --- | ---: | ---: | ---: | ---: | ---: |
| 空 SweepX 缓存，32 根 miss | 2.290 s | 1.794 s | 1.973 s | 1.472 s | 6 |
| 热尝试，32 根 hit | 2.026 s | 1.602 s | 1.906 s | 1.468 s | 5 |

该受控负载下，扫描 wall 中位数分别减少约 22%/21%，Git 阶段分别减少约 25%/23%；这是完整只读 CLI 调用及其明确阶段，不代表真实全盘吞吐、TUI 首屏或 p95/p99。最初独立 oracle 错误预期带跟踪文件的目标仍被 check-ignore 命中，实际 Git 返回 1，尚未执行扫描；仅修正 harness 的这项预期。随后一轮完整等价测量与短时 core lint 有部分重叠，其全部原始样本另存 artifact 的 diagnosticAttempts、排除于上表；最终固定次数串行测量单独记录，没有遇到快样本就结束或混用两轮数据。

这减少一次确定的重复启动，没有定位旧 300 ms/2 秒工具失败、8,192 文件热缓存 PTY 超时或 FSEvents settle 偶发失败，也不关闭有效配置、归属/活动、缓存片段合并、大文件/重复 TUI、跨平台缓存及目标宿主/执行验收缺口。路线图保持进行中。

交付验证：Git 专项实际运行七项通过，完整工作区串行 969 项通过、0 失败、两个原有基准 ignored；仍显式排除已诊断挂起的 trash_moves_ordinary_paths_without_confirmation_in_machine_invocations，实际系统 Trash 成功未验证。受影响 core、host/Linux GNU/Windows GNU 工作区 all-targets/all-features clippy、fmt/diff、54 份 Markdown 与 core 包清单通过；24 个最终计时样本的等价摘要、实际命中状态、中位数及被测源文件摘要独立复核。Linux/Windows 新测试代码只交叉 lint，原生宿主、Windows MSVC、真实 provider 和系统 Trash 成功继续未验收；已通过检查不关闭上述间歇根因项，没有放宽期限或排除额外测试。


## 大文件与重复内容的实时 TUI（2026-10-02）

`scan --tui --large-files` 和 `scan --tui --duplicates` 现可直接组合，根/状态/终端准入后先打开已有列表，分析在工作线程完成；普通 JSON/human 分析输出及字段保持不变。core 提供 `scan_file_analysis_with_observer`/`FileAnalysisSink`，analysis 的大文件 preview 和重复 observer 都调用已有收集器，没有第二套扫描/hash 算法或新 crate。大文件中途榜单至少相隔 100 ms 发布一次，只保留最新快照，最终榜单（含不完整榜单）可靠交付。重复大小组不可能再加入其他大小文件，因此完成本组采样、完整 hash 和成员原生复验后即可发布，再处理后续大小组；取消/超限保留已经闭合的组，整体仍 partial/cancelled，结果不是跨文件原子快照。

CLI 的可靠通道一个槽，加生产者一份有界载荷，中途榜单和进度各有一个替换槽；视图 registry 最多 16384 行/64 MiB 准入估算，collector 和已有 TUI model 预算独立，并不宣称总 RSS 为 64 MiB。进度路径按 UTF-8 边界限制为 2048 字节，预算拒绝只保留一个错误，不积累重复诊断；刷新/保留者更新需等待上一有界批次消费。原生扫描 worker 被阻塞时关闭仍保留进程配额，取消是合作式；UI 不做 native IO 或 join。复用稳定键选择、取消、历史标记、刷新和终端恢复；`r/R` 全量刷新分析范围，保留选择但清除保留者选择。列表按组相邻展示，长文件路径保留尾部和省略号，详情仍显示完整路径；逻辑大小不改称可释放量，分配未知不变成零。

重复模式 `p` 明确选择/取消保留者，每组最多一个，不默认选择；保留者不能进入回收批次。完整成功的整体扫描终态是 file view 提供 Trash 的前提，提前组或最终榜单回调不能掩盖之后的状态持久化失败。每批最多 256 个所选文件，最多另含 256 个保留者；worker 先以原 live stamp 做 provider-safe 零字节检查，再复用 DuplicateCollector 在共享原内容/文件/请求预算内重读并计算完整 SHA-256，合作期限覆盖预检及内容阶段。新的摘要、完整原生键和 stamp 都必须匹配，任何预检缺口拒绝整个批次；每项真正提交前再次检查保留者、所选文件和 native root/parent/object/filesystem/mount 绑定。大文件来自用户明确文件选择，仅做 provider-safe 原生/长度复验，不读取载荷。两模式共享 junk/隔离 mutation worker 配额、原 Trash adapter 和重要路径拒绝，不改变项目 junk 规则的所有权/活动限制，没有永久删除兜底。live stamp 不序列化，JSON 恢复的 hash 不提供本次内容证明；最终 pathname 检查到系统 Trash 调用之间的竞态仍保留。

独立回归用普通目录读取/metadata 核对榜单、普通读取/SHA-256 核对内容，并覆盖硬链接排除、同名文件/父目录替换、等长修改保留者、明确保留者/禁止选中保留者、取消、资源缺口、刷新清除保留者、JSON 丢弃 live stamp、合并中途榜单不占可靠终槽、关闭释放背压发送者和状态写入失败。初次新回归发现全尺寸内容读完才关闭重复组，生产改为逐大小组闭合；路径 oracle 的受控 `/fixture` 前缀、格式拒绝的实际 stderr 以及部分结果必须经过新 revision 重观察才能变 current 的测试预期分别纠正，没有放宽原生检查。最初新测试依赖/导入和 lint 问题也已修正。

[真实终端验收记录](file-analysis-tui-pty-2026-10-02.json)来自 arm64 macOS、Rust 1.98.0 debug、三个初始普通文件（两份 1 MiB 相同内容、一份 5 MiB 不同内容），刷新前再加入一份相同内容；关闭 SweepX 状态缓存，不控制 OS cache，不作速度或尾延迟比较。最终固定八个场景覆盖两种分析的英文 q/Ctrl-C/SIGTERM 和中文 q；都核对完整结果、选择/刷新、重复模式明确保留者及刷新清除、退出码 0/130/143、终端属性/alternate screen 恢复、全部文件名称及独立 SHA-256 未变，没有发送删除键。首次 PTY 暴露长路径表格只显示共同前缀，已修复显示尾部并增加终端单元回归；中文脚本初次用错完成文字且未清除覆盖写入的宽字符尾格，修正独立中文覆盖样例和解析器后再固定验收，不把这两项脚本错误归为产品停顿。

交付验证：完整工作区 `cargo test --workspace --all-features --locked -- --skip trash_moves_ordinary_paths_without_confirmation_in_machine_invocations --test-threads=1` 为 986 项通过、0 失败、2 项原有基准 ignored；随后仅修复路径展示/保留者提示并增加宽字符尾部回归，最终宿主 CLI/TUI 全量 217 项通过，其余未变行为复用工作区结果，合计覆盖 987 项，不称为再次完整工作区。该最终专项首次在沙箱内的旧 cancel JSON 用例收到空 stdout；独立执行确认默认状态目录访问返回 `Operation not permitted`，没有改测试或放宽生产行为，宿主专项通过。真实系统 Trash 成功仍因既有挂起用例显式排除，不能记为通过。host/Linux GNU/Windows GNU 工作区 all-targets/all-features clippy、fmt/diff、54 份 Markdown 及四个受影响包清单通过；Windows 首次交叉编译发现新复验分支使用仅 Unix 导入的 IdentityEvidence，改为完整类型路径后最终工作区交叉 lint 通过，没有扩大 cfg 或 suppress。最后的 Rustdoc/文档补充不改变已测宿主行为。

本条完成大文件/重复内容的动态视图、明确保留者和安全拒绝路径；原生 Linux/Windows、MSVC、真实云 provider、系统 Trash 成功与最终 pathname 竞态仍未验收/关闭，交叉编译和未发送删除键的 PTY 不证明这些行为。此前 probe/热缓存 PTY/FSEvents 间歇问题未由本单元解决。下一步继续选中刷新片段的持久缓存合并、项目有效配置/独占归属/活动证据，以及跨平台缓存与其他原生收尾；完整路线图仍进行中。

## 选中刷新后的持久缓存片段合并（2026-10-02）

此前局部扫描只更新会话行，不写持久缓存；关闭后历史首屏仍显示旧尺寸，也不能将新观察的文件长度保留给下一次扫描。此次在既有 core 缓存模块中接入片段合并，没有新增 crate、扫描算法或 CLI 选项。

- 文件索引在本次完整局部观察后更新所选子树，移除所选范围旧后代及浅层祖先。兄弟目录只有在旧根原生绑定一致、历史完整且从其原游标起没有重叠变更时才能携入新代际；变化或未知范围退回现场观察。嵌套根按原始请求范围归属，不能借选中范围改变拥有者。目录仍原生重枚举，长度复用仍经过现有 backend 检查并重建当前扫描身份、marker 与祖先统计。
- 新索引游标在预览读取、历史查询与遍历前捕获，后续 racing changes 留给下一次校验。旧索引按目录消费，不复制整个旧索引；新片段优先占用既有 4 MiB 可选编码额度，兄弟索引在剩余额度内保留。候选预览与文件索引读共享同一 invocation 读取/保留预算和一次历史查询，缺口不会重置额度。
- 候选记录将所选原生路径的旧行替换为本次事实，保留其他历史行及旧祖先统计；显示路径不能决定替换范围，无原生来源的旧行不携入。此记录具有不同扫描 namespace，只作历史首屏，不补造全根覆盖。缓存 schema 升为 `sweepx.junk-cache/v9`，`preview_only` 同时在 reader 和历史有效性入口阻止整根命中；旧 reader 必须拒绝新 schema，当前 reader 拒绝 v8。独立长度索引继续 v4。之后完整扫描恢复正常整根候选记录。
- 取消、partial、未覆盖选中目录、根变化或缺少完整变更历史不推进局部代际。两缓存文件分别有界原子发布，没有跨文件事务；写入失败沿已有 CacheWarning 提示，不改变新鲜扫描结果或提供删除权限。历史首屏仍显式标为 Historical/StalePreview，活动、配置、Git 与执行策略须本次重建。

受控历史回归用实际原生扫描来源、普通 metadata 和文件字节作独立对照，验证新子树、未变化兄弟、范围外修改、旧后代消失、浅层祖先不获递归覆盖、连续两次片段发布、后续竞态失效、嵌套根归属、输入预算共享、缺失/损坏历史和替换根拒绝。原生会话回归核对关闭/重启后的新尺寸历史首屏、当前整根重观察及恢复完整候选记录。取消回归通过单槽可靠队列在 Traversal 阶段同步取消，资源缺口回归实际压满选中子树的元数据预算，两者核对已发布文件逐字节不变。没有计时或新的加速倍数，索引计划复用不冒充端到端吞吐测量。

首次沙箱原生检查没有更新索引，独立历史查询明确返回 `FSEventStreamStart failed`，保留旧缓存正是生产 fallback；宿主原生回归通过，未屏蔽 FSEvents 或放宽覆盖要求。初次新增字段落入函数实参及测试错误假定 request 可 Clone，均已修正。后来加强的历史断言错误要求旧覆盖变 incomplete；实际契约保留当时的覆盖事实并标记 StalePreview，已改为同时核对历史 provenance、not_checked 执行策略和 historical_cache blocker，没有改变生产事实语义。既有工具探测在 core 全量中又出现 ProbeUnavailable：launch/setup 约 0.58 ms 返回，2 秒内无 stdout、EOF 或退出；tool-a 也曾到 1.77 秒才首次输出。该故障的根因仍未解决，不将片段合并作为其修复。

验证记录及未通过尝试见[缓存片段验收记录](cache-fragment-validation-2026-10-02.json)。规则有效配置、独占所有权/活动、其他发现路径审计、旧 probe/debug PTY/FSEvents 间歇问题、跨平台缓存、原生宿主/MSVC、真实云 provider、系统 Trash 成功与最终 pathname 竞态继续开放。

最终工作区串行原生测试为 994 项通过、0 失败、2 项原有基准 ignored，已诊断挂起的 `trash_moves_ordinary_paths_without_confirmation_in_machine_invocations` 仍显式排除，不能记为成功移动。最终 host/Linux GNU/Windows GNU 工作区 all-targets/all-features clippy、fmt/diff、54 份 Markdown 检查与 core 包清单通过；交叉编译包括正确 cfg 的测试代码，但不证明目标运行时。前一次 core 全量为 260 项通过、1 项旧 probe 失败、1 项 ignored；前一次 workspace 因历史断言错误在 core 阶段停止，后续未运行，修正后才执行上述最终完整矩阵。最终检查有并行构建，不作性能比较，也不以之后通过关闭旧间歇根因。没有发布或实际 Trash 成功验收。
