---
title: 架构
---

# 架构

SweepX 以共享的协议与安全类型为中心，把可运行的扫描/预览路径、Linux 有界文件/目录 Permanent 窄路径和仍在 library 层的通用模拟 mutation model 分开。

## 当前数据流

```text
absolute roots
  -> platform backend
  -> scanner + model aggregates/boundaries
  -> Core output envelope
  -> bounded human table | explicit JSON
  -> optional in-process file-manager TUI
  -> Linux bounded SQLite journal + terminal snapshot (unless scan --no-state)
  -> macOS legacy terminal snapshot (unless scan --no-state)
  -> Windows durable state under %LOCALAPPDATA%\sweepx\state (private DACL enforced)

bounded scan.result JSON
  -> imported provenance downgrade
  -> report-only explanation

preview-cache/current.json + current generation + flat generations/quarantine dirs
  -> bounded read-only cache inspection
  -> cache.status.result
```

Linux、macOS 与 Windows 均连接实际的 development-grade/degraded 只读 scanner backend；macOS traversal 为 handle-bound，Windows 为 handle-relative，三者都通过 `sweepx scan` / `scan --tui` 暴露。

Scanner 还新增了一个有界 locator batch reader，供只读上层在已 admission 的 locator 上执行固定文件读取。当前最直接的使用者是 Cargo detector：它读取 `Cargo.toml` 和 `.cargo/config*` 来产生 typed evidence，但这些读取不会把结果升级为 candidate 或执行权限。

`sweepx-cache` 现在还提供 preview cache 的只读 inspection API，供 `cache status` 读取现有 `preview-cache` 结构。它只检查 `current.json`、pointer 指向的 current generation 文件，以及平铺的 `generations/` / `quarantine/` 目录，报告存在性、数量、近似字节数和健康状态；它不会创建、修复、quarantine、重建或暴露 preview entries/path 内容。

## Crate 职责

当前 workspace 共 17 个 crate。平台实现位于 `sweepx-platform::{linux,macos,windows}`，通过 `backend-linux` / `backend-macos` / `backend-windows` 选择；默认只提供契约。scanner 继续保留原有 `platform-*` feature，并转发到对应后端；原生依赖仍按目标平台编译。Windows 纯解析器仍可在其他平台启用并测试。

规则类型与校验位于 `sweepx-catalog::schema`，纯规则评估位于 `sweepx-catalog::vm`，内置资源与 package 准入由同一个 crate 管理。原独立 schema/VM 包已退出 workspace；机器 schema ID、规则内容和风险值保持不变。

项目规则 JSON 可声明 `requiredOwnMarkers`（默认空、最多 64 个安全文件名），要求捕获目录自身直接包含全部指定普通文件；`requiredParentMarkers` 仍要求父目录至少一个标记。`JunkService` 按本次目录 ID 消费同一次遍历的文件标记，使用现有 VM，分类时无额外 I/O。加载字节摘要自动绑定缓存；结构标记不证明内容格式、活动或删除权限。共享版本/误报夹具放在既有 fixtures 的 `project_junk` 模块，仅供开发测试使用。

`LocatorReader::read_captured_regular_file` 为上层格式验证提供有界整文件读取。它复用捕获目录的 root/lineage 重验与 provider-safe 原生内容流，先用零 payload 观察当前文件身份、挂载、长度及变化指纹；超限不交付内容，完整读取须匹配该观察。不会从显示路径重建权限、接受截断前缀或证明原子缺失；每次调用限制文件字节、名称、路径分量和阶段数，上层仍需累计预算、取消及工作线程。该接缝已可独立调用，垃圾格式解释和回收准入尚未接入它。

| 层 | 代表 crate | 当前职责 |
|---|---|---|
| 模型与协议 | `sweepx-model`, `sweepx-protocol`, `sweepx-canonical`, `sweepx-i18n` | tagged evidence、稳定 envelope/canonical digest、双语渲染 |
| 平台与扫描 | `sweepx-platform`, `sweepx-scanner`, `sweepx-cache`, `sweepx-event-journal` | platform boundary、三平台只读遍历与聚合；Linux bounded SQLite journal；macOS legacy snapshot |
| 分析与 Cleaner | `sweepx-analysis`, `sweepx-catalog` | candidate/explanation、声明式规则、内置 package |
| 用户表面 | `sweepx-core`, `sweepx-cli`, `sweepx-tui` | 命令编排、机器/人类输出、有界只读视图 |
| P3 模拟安全 | `sweepx-safety`, `sweepx-audit`, `sweepx-executor` | immutable binding、durable audit/recovery、sealed fake execution |

`sweepx-core` 不依赖 `sweepx-tui`、ratatui 或 crossterm。CLI 的 `tui_adapter` 模块连接 browser 的详情请求和 scanner 的原生身份复验；scanner 继续负责 no-follow、mount、取消与资源限制。旧的 core JSON 浏览封装没有命令或调用者，已移除；只读 JSON 视图仍由 TUI 库提供，`scan --tui` 使用本次 typed summary。

macOS 详情扫描通过 `inspect_bound_child_with_mount_identity` 补充文件/链接自身的文件系统身份：相对已保留父句柄打开临时元数据句柄，核对对象与当前 basename 绑定，再由 `fstatfs` 观察 fsid。链接只观察自身；没有内容读取，也不复制父目录 mount。普通批量扫描保持原路径，只有需要身份复验的详情扫描承担额外系统调用。拒绝、变化和缺失证据仍使刷新失败；分配/可释放字节不因此变为已知，删除前的身份重验仍独立执行。

Linux `delete` 复用 `sweepx-audit` 的 exact authorization、claim、intent、outcome 与 fence，但不宣称通用 P3 executor 已 native 化。CLI 自己构造并持久化一个最多 256 action 的封闭 R4 plan；普通文件执行一次 exact-basename `unlinkat`，目录按 manifest 后序逐项执行 `unlinkat`/nonrecursive `rmdir`。该 adapter 在非 Linux 构建中不存在。

Git 增强由 core 的 `GitEvidenceSession` 共用于普通报告和垃圾会话。每个候选通过一次有界 `rev-parse` 同时观察工作区和 `.git` 位置，再分别进行原生身份、filesystem/mount 和变化指纹核对；范围不跨候选缓存，环境重定向仍移除，外部配置变化不能沿用旧范围。Unix 路径含换行时保留两个独立查询，避免输出分隔符歧义；其他联合输出必须有且仅有两个完整绝对路径，截断、额外记录或查询失败不提供范围依据。当前 tracked/ignore 查询、资源期限与项目回收约束继续独立生效。

## 状态与取消

`sweepx-core::tools::ProbeRunner` 在调用方工作线程上有界读取完整工具答复，不创建后台管道读取线程。macOS 同时使用输出就绪与本次未回收子进程的退出通知，避免答复已到达或 EOF 后仍等固定轮询；通知只唤醒检查，不能替代 `Child` 退出状态或证明活动/所有权。每次最多增加一个独占退出观察描述符，失败回退有界轮询；单次/整批期限、输出上限、取消和进程组清理保持原契约，原生启动/回收仍服从宿主调度。Linux/Windows 保持既有轮询。 完整 stdout 和退出状态在最终接受前再次检查取消与期限；已经超期的完整输出仍被拒绝，只保留诊断事实。

大文件分析在既有 `sweepx-analysis` 模块中使用有界 top-K；core 的 `scan_large_files_with_store` 与普通 scan 共享一次 scanner 遍历及输出 envelope。observer 的 `on_entry` 在可选行保留/分类之前传递每个原生观察，`on_directory_coverage` 在可选 aggregate/index 保留之前传递覆盖。所需文件事实使逻辑长度缓存退回当前文件观察，不制造缺失的分配或 mount 证据；普通 junk 路径仍保留原缓存快路径。收集器只复制入榜的原生条目，分类器、垃圾候选和执行授权不参与大小排序。

显式内容分析可通过 platform 的 `stream_bound_regular_file` 在保留父目录下分块读取指定范围，固定 64 KiB 缓冲，并检查跨阶段及读后原生身份、mount、大小和 change stamp；失败时 chunk 仅是临时数据，不能形成完整 hash 证明。macOS 在线程上禁止 dataless 下载，Windows 检查 no-recall/provider/reparse 边界，Linux 仅准入 ext4、Btrfs、tmpfs。调用者仍需工作线程、累计 IO/metadata/并发预算；原生同步读取的取消是协作式。重复分析现由 analysis 的 DuplicateCollector 与 core 的 scan_duplicates_with_store 接入显式 scan --duplicates。它共用本次遍历事实，在有界大小索引内排除硬链接别名，采样筛选后才完整 hash；每阶段及最终复验原生身份、大小与变化指纹。共享累计读取、范围请求、文件数量和保留估算预算，取消/期限停止后续内容阶段。失败 chunk 不形成摘要，未知/provider/资源缺口保持 partial；内容 hash 不持久缓存，结果不授予删除权限。

共享实时列表每批最多处理 128 个事件，随后绘制并检查键盘。收到任意事件的批次使用零超时输入检查，下一空批恢复 50 ms 空闲等待；有界队列暂时取空也不会在每个活动批次强加固定等待。完整结果、错误、选择与取消契约保持，大文件/重复内容视图共用这套循环。

`sweepx-core::junk::session` 提供显式目录根或系统自动发现的后台垃圾扫描会话，由 CLI adapter 接入 `junk --tui`。阶段、候选、边界、错误和终态使用有界背压队列，进度与目录统计合并；稳定候选键与 revision 分离。选中刷新复验原生绑定，只有完整观察才能移除旧行；取消或不完整扫描保留未确认的旧证据。TUI 只绘制可见行，选择独立于扫描，后台回收复用原生绑定检查和现有 Trash adapter。macOS 缓存存储和文件复用已迁到 core 共用；会话先发送明确标记的历史候选，再重建当前目录身份、分类及 Git 证据，完整观察后才能移除旧键。缓存失败退回现场扫描。系统全量刷新重新发现根，macOS 缓存绑定本次范围；系统模式先发现范围再读取历史预览，游标仍在发现之前捕获。Linux 临时对象保留独立的测量事实和会话身份，不制造目录 aggregate 或普通 Trash 身份；临时对象刷新整个系统范围，TUI 的 `x` 已接入独立隔离预览、精确摘要确认与结果状态；完整原生运行仍缺 Linux 宿主验证。选中目录刷新保留原始根与原生身份链，只递归所选子树，浅层枚举祖先所需的规则及 Git 标记；祖先旧统计成为历史，原生绑定仍可供再次选中刷新。祖先枚举完整与递归覆盖分开记录，父标记截断不能产生否定分类，所有所选目录都获得完整覆盖后才替换旧行。macOS 完整局部扫描合并所选子树文件索引与历史验证后未变化的兄弟目录，丢弃选中范围的旧后代、浅层祖先及已变化范围外索引；嵌套根仍按原范围独立归属。全局新游标在历史查询和遍历前捕获，竞态变更留给下次验证。候选片段只合并为 v9 历史预览，混合扫描身份和旧祖先统计不能成为整根命中；后续完整扫描恢复完整记录。缺少完整历史、取消或 partial 不推进局部代际。两缓存文件分别有界原子发布，不构成跨文件事务；预算遗漏的索引仍现场检查。自定义全根分类器不能使用该局部接口。会话取消独立于下述持久化 `cancel` 命令。

Linux 临时对象服务提供共享预算与合作式取消；目录名、递归身份指纹、进程枚举和 mount/socket 表输入都有界。资源失败不可恢复为本次完整阴性结论；报告与清理重验复用同一实现，各次调用独立建立预算和当前引用证据。

内置局部规则在子树完整、自身及父目录 marker 枚举结束后调用同一个分类器，提前发送基础候选；Git 增强仍在后续阶段完成。自定义分类器默认等待整根，可通过 uses_only_local_markers 明确声明只依赖自身/父目录 marker；否定谓词及规则优先级也必须在这些事实下完整。关闭状态只用标志和子树计数，字节已经累计到祖先，不复制硬链接集合；交付后释放子树状态。

`junk::quarantine` 将 Linux 临时对象的原生预览/执行与 CLI 打印、stdin 确认分离。不可由序列化显示计划重建的预览保留捕获身份与执行预算，执行消费一次并重验当前原生事实；摘要绑定实际规则字节。清理路径、目录枚举和内容 I/O 合作式取消且有界；待移除的同层对象共享父目录 fd，避免宽目录逐名称复制句柄。移除开始后的失败可能留下部分源和完整恢复副本，没有原子回滚或永久删除兜底。TUI 通过单槽通道接收显示计划和最终结果，原生预览保留在 worker 等待完整摘要确认；Trash 与隔离共享一个 mutation worker 配额。关闭不 join，取消在原生阶段合作检查。确认移动后移除子候选并将祖先统计标为历史，两个操作复用同一结果处理实现。临时对象 measurement 用 Arc 共享，避免 UI 选择深拷贝；计划绑定恢复区原生字节，非 UTF-8 路径用额外 hex 展示，显示拼写相同不能产生相同计划摘要。

进度日志也有保留上限；仅截断进度不会把完整扫描变成 partial。错误计数、取消和真实资源不足独立保留，现场会话继续收到可靠错误与终态。

CLI scan 当前同步完成。Linux 在 scan 完成后批量构造事件，并在单个事务中把完整流与 terminal snapshot 写入 bounded SQLite journal；Core `status` journal-first，并支持 degraded 的 `sweepx --format ndjson status --operation-id ID --watch [--after SXCUR1]` completed replay：先做一次同 snapshot 全量校验，再对已完成且已持久化的 stream 按每页最多 1024 条事件续读；unknown 但语法有效的 cursor 返回 `stream.reset_required`，malformed cursor/usage 返回 usage error。由于事件仍在 scan 后批量构造，该 surface 不是 live sink，不等待新事件，不创建后台 operation，也不支持 cancel。macOS 与 Windows 仍写 legacy operation snapshot；Windows state directory 由 current-user-private DACL、owner 校验和逐级 reparse-point 拒绝保护。`scan --no-state` 会跳过对应的 operation-state 写入，适合不需要后续 status/operation state 或 state filesystem 不支持 journal 的只读扫描，并与 `--state-dir` 冲突。`cancel` 只返回诚实 disposition；这就是 capability 被标记 disabled 的原因。

与 scan/status 分离，`cache status` 只读取 preview cache 的现存状态。Linux、macOS 与 Windows 支持 human/JSON；NDJSON 是 usage error。缺失 state/cache 返回 `absent` 且不创建目录。`available` 只表示缓存结构和受限校验可读，不代表任何 live/current 文件事实；warning、error 或 quarantine presence 会把结果降为 `degraded`。

项目内容观察由 `junk::format::ProjectFormatSession` 串行执行，独立于纯规则 VM。Dart profile 使用捕获目录的有界原生完整文件读取，按当前内容识别 pub v2 自声明格式及父项目根引用，不打开配置中的 URI、不解析 pubspec YAML、不运行 SDK。每个命令调用/会话 revision 重建观察器，缓存不保存格式答案；历史和 Base 行是 `not_checked`。默认每个文件最多 256 KiB、最多 128 个不同候选、累计预留 32 MiB 内容，每次尝试包括失败均扣除最坏请求预算；祖先与目录枚举受单次限额约束，因此累计元数据工作也受尝试数限制。5 秒是合作期限，不能打断阻塞内核调用。配置无效、provider/权限/身份变化、超限与取消都显式保留；格式识别成功仍有 `project_ownership_not_verified`，Git 不覆盖它，CLI/TUI/后台回收均拒绝此 profile。SvelteKit legacy profile 复用此流程：观察 `tsconfig.json` 与 `ambient.d.ts` 后完整重读各一次，比较身份、变化指纹和内容；发现文件间变化即 unknown，仍不承诺原子快照或完整 TypeScript 语法有效。每项在首次 I/O 前预留四次读取，因此共享 32 MiB 请求预算最多允许 32 项纯 SvelteKit 观察；累计读取/元数据工作也由最大尝试数乘四约束。声明内容不持久化，不求值 JS 配置或访问其中的 alias/glob。独占所有权、活动及更多真实工具版本证据仍待实现。

## 导入是明确的信任边界

Core 不会因为 scan JSON 带有本项目 schema 就保留它的 live 权威。解析之后，entry/aggregate provenance 被改为 stale preview，coverage 变为 incomplete/not revalidated。Analyzer 可以据此解释，但不能把它升级为 executable candidate。当前 TUI 不导入这类 JSON，而是直接浏览本次 live scan 的 typed summary。

同样地，当前 Cargo detector 虽然已经具备 handle-bound 的固定输入收集器，并能在 manifest 绑定成立时给出 `known` workspace evidence，但 `targetDir` 仍因全局 override scope 未解而保持 `not_checked`，`targetShape` 仍保持 `unknown`。因此 CLI 结果继续是 hint/report-only，而不是 plan/approval/execution authority。

## P3 为什么仍不算通用真实 executor

P3 的库分层有意让 native mutation 无处接入：

- plan 通过 canonical digest 固定内容；
- authorization 精确绑定 plan 与 action set；
- audit store 负责 durable claim、intent、outcome 和 reconciliation；
- permit 与 revalidation observer 是 simulation-specific；
- executor 的 request 没有 native path；
- adapter trait sealed，唯一实现是 deterministic fake adapter。
- audit persistence 当前仅支持 Unix；独立的 Linux scan event-state 路径已有 bounded SQLite journal、单事务完整流/terminal persistence，以及 degraded completed-stream replay。由于该 replay 只覆盖已完成且已持久化的 stream，且事件仍在 scan 后批量构造，它仍不是 live、跨平台或 runtime-qualified 的 native mutation 存储。

这套 P3 executor 本身只测试状态机与崩溃语义，不会删除目标。真实 Linux 文件/目录 `delete` 是独立的受限 CLI 路径；它没有开放 native adapter trait 或无界/跨目标批量执行。

## 未来架构方向

路线图的完整状态流仍是：

```text
scan -> explain -> immutable plan -> explicit authorization -> live revalidation
     -> platform action -> reconcile -> audit
```

当前公共表面除前两步和只读视图外，只增加了 Linux 有界文件/目录的本地 closed-plan/challenge/per-action-intent/unlink/outcome 窄路径；通用 native platform action、approval broker 与 plan/execute CLI wiring 仍未实现。


项目规则的 JSON `executionPolicy` 只接受 `report_only` 或 `require_ownership_and_activity`；省略时采用后者，不继承旧的删除准入。通用 `dist/build/out/.next/.turbo` 及 Dart/SvelteKit 明确仅报告，Rust/Node/Python/Maven 则仍缺独占所有权和无活动的独立证明，因此当前所有项目候选均不能通过 `junk --trash`、TUI 或后台 worker 回收。名称、风险等级、完整覆盖、格式识别或 Git `ignored/high` 均不能替代这些证明。报告新增稳定 `executionPolicy` 字段，项目值为 `report_only` 或 `require_project_ownership_and_activity`；缓存恢复先为 `not_checked`，按本次规则重建，不保存旧准入。平台候选的 `native_revalidation_required` 仍须通过既有原生身份、覆盖与平台边界检查，并不自行提供执行权限。独立 `trash PATH` 的明确路径操作仍遵守其原有检查。

SvelteKit 1.0.0/2.0.0 的格式回归包含实际 SDK sync 生成的原始文件、冻结依赖锁与逐文件字节校验记录，独立于手写结构夹具；普通测试离线消费。真实生成目录混入用户文件时仍拒绝回收，macOS 缓存后重新观察当前格式。更广版本/配置仍待采集；Dart 指定版本的实际 SDK 样本已补齐，见下段。这些记录不证明归属、无活动或被扫描机器的工具版本。

Dart 2.18.0/3.6.0 的实际离线 pub 记录覆盖单项目、从成员调用的共享 workspace 与中文/空格成员路径。格式 profile 支持这些 SDK 产生的百分号 UTF-8 文件名签名，普通 ASCII 路径保持无分配检查；无效编码、控制字符、编码的分隔符/dot 与 URI 结构语法仍 unknown，不解析 YAML、不求解完整 URI 语义，也不打开 URI。源码、锁文件及成员笔记通过普通读取核对不变，根 map 的 recognized 不能证明独占归属或无活动。

Rust target 候选现通过捕获的原生身份链读取父目录 `Cargo.toml`，在 CLI/TUI 中展示当前 package/workspace、成员模式数量、显式 workspace 路径及路径依赖声明。JSON 新增 `projectContext`，状态为 `observed` / `invalid` / `unknown` / `not_checked`；`memberPatterns` 是声明字符串数量，不能当作实际成员数量。还会观察该父目录下 `.cargo/config` 和 `.cargo/config.toml`，在 `cargoConfig` 中分别展示受支持的 `target-dir` 声明；`pathKind` 描述宿主上的 absolute / parent_relative / relative（Windows 另有 drive_relative / root_relative）拼写。绝对和父级路径可被报告，但不打开、不规范化，也不展开 `~` 或环境变量；路径值不写入报告或持久缓存。枚举中未见配置保持 unknown，联合观察为 `non_atomic`、`precedenceComplete=false`，不能据此选择实际生效文件或输出目录。不会执行 Cargo，也不声明完整配置或构建语义。上下文与格式共用有界观察预算，缓存不保存声明答案，每次调用或刷新重新读取；这些声明不能证明独占所有权或无活动，项目回收限制继续保留。 另有 `cargoOutput`，明确模拟“候选父目录启动、当前环境、无 Cargo CLI 覆盖”的配置范围：有界读取各原生祖先及 Cargo home，选择近端标量并应用环境覆盖。它只报告来源、路径类型与经过复验的精确拼写比较，不打开输出路径、不证明路径别名等价或未来构建参数。共享来源索引仅本调用内保留有界私有路径值，刷新重建；非原子观察不解除回收限制。Cargo home 支持候选父目录为 cwd 的相对路径、空值退回用户 home，以及原生确认不存在或非目录时回到默认输出；链接、拒绝、缺少可用 home 环境和不确定读取仍为 unknown。home 的相对输出基点保留 Cargo 的原始 parent 拼写，含点/父级的基点不做精确拼写匹配。include、自定义 cwd/CLI、系统用户目录回退、原生别名及输出对象等价仍需后续补齐；所有权与活动限制继续保留。

core 另提供 `scan_file_analysis_with_observer` 与工作线程局部的 `FileAnalysisSink`。中途榜单可合并，最终榜单和已核验重复大小组在整体终态返回前交付；只有扫描返回才能证明含状态持久化在内的完整成功。重复组的 live stamp 不写入 JSON。CLI 管理有界队列、原生稳定键、保留者选择、重算预检及共享 Trash worker 准入；TUI 复用已有列表/事件/终端机制，不从显示路径恢复文件系统权限。


`cargoOutput.workspace` 现补充本次调用的工作区成员与默认选择：`isWorkspace`、`memberCount`、`defaultMemberCount`、`projectIsRoot`。有界原生读取支持 literal/glob 成员、raw exclude 前缀、显式 workspace 指针及传递路径依赖；共享既有 TOML 解析器，不执行 Cargo。全部输入在输出前再次检查身份、内容摘要与已枚举名称，失败保持 unknown/invalid，不返回截断成员集；非原子观察不证明构建有效。没有配置覆盖时，默认 `target` 属于解析后的工作区根或独立 package，来源分别为 `workspace_default` / `package_default`。声明路径只作为独立准入的配置输入，不扩展扫描范围，不获得回收权限；原始路径与成员名称不写入报告或缓存。include、自定义 cwd/CLI、系统用户目录回退、原生别名及输出对象等价仍需后续补齐；所有权与活动限制继续保留。
