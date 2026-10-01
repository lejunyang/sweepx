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

## 状态与取消

`sweepx-core::junk::session` 提供显式目录根或系统自动发现的后台垃圾扫描会话，由 CLI adapter 接入 `junk --tui`。阶段、候选、边界、错误和终态使用有界背压队列，进度与目录统计合并；稳定候选键与 revision 分离。选中刷新复验原生绑定，只有完整观察才能移除旧行；取消或不完整扫描保留未确认的旧证据。TUI 只绘制可见行，选择独立于扫描，后台回收复用原生绑定检查和现有 Trash adapter。macOS 缓存存储和文件复用已迁到 core 共用；会话先发送明确标记的历史候选，再重建当前目录身份、分类及 Git 证据，完整观察后才能移除旧键。缓存失败退回现场扫描。系统全量刷新重新发现根，macOS 缓存绑定本次范围；系统模式先发现范围再读取历史预览，游标仍在发现之前捕获。Linux 临时对象保留独立的测量事实和会话身份，不制造目录 aggregate 或普通 Trash 身份；临时对象刷新整个系统范围，TUI 内的隔离计划确认尚未接入。选中目录刷新仍遍历原始根以保留分类上下文。会话取消独立于下述持久化 `cancel` 命令。

Linux 临时对象服务提供共享预算与合作式取消；目录名、递归身份指纹、进程枚举和 mount/socket 表输入都有界。资源失败不可恢复为本次完整阴性结论；报告与清理重验复用同一实现，各次调用独立建立预算和当前引用证据。

`junk::quarantine` 将 Linux 临时对象的原生预览/执行与 CLI 打印、stdin 确认分离。不可由序列化显示计划重建的预览保留捕获身份与执行预算，执行消费一次并重验当前原生事实；摘要绑定实际规则字节。清理路径、目录枚举和内容 I/O 合作式取消且有界；待移除的同层对象共享父目录 fd，避免宽目录逐名称复制句柄。移除开始后的失败可能留下部分源和完整恢复副本，没有原子回滚或永久删除兜底。TUI 的计划确认接入尚未完成。

进度日志也有保留上限；仅截断进度不会把完整扫描变成 partial。错误计数、取消和真实资源不足独立保留，现场会话继续收到可靠错误与终态。

CLI scan 当前同步完成。Linux 在 scan 完成后批量构造事件，并在单个事务中把完整流与 terminal snapshot 写入 bounded SQLite journal；Core `status` journal-first，并支持 degraded 的 `sweepx --format ndjson status --operation-id ID --watch [--after SXCUR1]` completed replay：先做一次同 snapshot 全量校验，再对已完成且已持久化的 stream 按每页最多 1024 条事件续读；unknown 但语法有效的 cursor 返回 `stream.reset_required`，malformed cursor/usage 返回 usage error。由于事件仍在 scan 后批量构造，该 surface 不是 live sink，不等待新事件，不创建后台 operation，也不支持 cancel。macOS 与 Windows 仍写 legacy operation snapshot；Windows state directory 由 current-user-private DACL、owner 校验和逐级 reparse-point 拒绝保护。`scan --no-state` 会跳过对应的 operation-state 写入，适合不需要后续 status/operation state 或 state filesystem 不支持 journal 的只读扫描，并与 `--state-dir` 冲突。`cancel` 只返回诚实 disposition；这就是 capability 被标记 disabled 的原因。

与 scan/status 分离，`cache status` 只读取 preview cache 的现存状态。Linux、macOS 与 Windows 支持 human/JSON；NDJSON 是 usage error。缺失 state/cache 返回 `absent` 且不创建目录。`available` 只表示缓存结构和受限校验可读，不代表任何 live/current 文件事实；warning、error 或 quarantine presence 会把结果降为 `degraded`。

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
