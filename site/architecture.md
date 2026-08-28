---
title: 架构
---

# 架构

SweepX 以共享的协议与安全类型为中心，把已经可运行的只读路径和仍在 library 层的模拟 mutation model 分开。

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
  -> Windows no durable state (state_dir defaults to None)

bounded scan.result JSON
  -> imported provenance downgrade
  -> report-only explanation
```

Linux、macOS 与 Windows 均连接实际的 development-grade/degraded 只读 scanner backend；macOS traversal 为 handle-bound，Windows 为 handle-relative，三者都通过 `sweepx scan` / `scan --tui` 暴露。

## Crate 职责

| 层 | 代表 crate | 当前职责 |
|---|---|---|
| 模型与协议 | `sweepx-model`, `sweepx-protocol`, `sweepx-canonical`, `sweepx-i18n` | tagged evidence、稳定 envelope/canonical digest、双语渲染 |
| 平台与扫描 | `sweepx-platform*`, `sweepx-scanner`, `sweepx-cache`, `sweepx-event-journal` | platform boundary、三平台只读遍历与聚合；Linux bounded SQLite journal；macOS legacy snapshot |
| 分析与 Cleaner | `sweepx-analysis`, `sweepx-cleaner-*`, `sweepx-catalog` | candidate/explanation、声明式规则、内置 package |
| 用户表面 | `sweepx-core`, `sweepx-cli`, `sweepx-tui` | 命令编排、机器/人类输出、有界只读视图 |
| P3 模拟安全 | `sweepx-safety`, `sweepx-audit`, `sweepx-executor` | immutable binding、durable audit/recovery、sealed fake execution |

## 状态与取消

CLI scan 当前同步完成。Linux 在 scan 完成后批量构造事件，并在单个事务中把完整流与 terminal snapshot 写入 bounded SQLite journal；Core `status` journal-first。event-journal crate 保留 Linux 测试专用 bounded cursor replay/reset substrate，但尚未接入 Core/CLI。macOS 仍写 legacy operation snapshot。`scan --no-state` 会跳过对应的 operation-state 写入，适合不需要后续 status/operation state 或 state filesystem 不支持 journal 的只读扫描，并与 `--state-dir` 冲突。Windows durable state 禁用：默认 `state_dir=None`，显式 `--state-dir` 失败关闭。当前没有 live sink、runtime qualification 或公开 `status --watch`/NDJSON；live cancel 也仍禁用。`cancel` 只返回诚实 disposition；这就是 capability 被标记 disabled 的原因。

## 导入是明确的信任边界

Core 不会因为 scan JSON 带有本项目 schema 就保留它的 live 权威。解析之后，entry/aggregate provenance 被改为 stale preview，coverage 变为 incomplete/not revalidated。Analyzer 可以据此解释，但不能把它升级为 executable candidate。当前 TUI 不导入这类 JSON，而是直接浏览本次 live scan 的 typed summary。

## P3 为什么不算真实 executor

P3 的库分层有意让 native mutation 无处接入：

- plan 通过 canonical digest 固定内容；
- authorization 精确绑定 plan 与 action set；
- audit store 负责 durable claim、intent、outcome 和 reconciliation；
- permit 与 revalidation observer 是 simulation-specific；
- executor 的 request 没有 native path；
- adapter trait sealed，唯一实现是 deterministic fake adapter。
- audit persistence 当前仅支持 Unix；独立的 Linux scan event-state 路径已有 bounded SQLite journal 和单事务完整流/terminal persistence。event-journal crate 的 replay/reset substrate 仅供 Linux 测试，尚未接 Core/CLI；这不是 live、公开、跨平台或 runtime-qualified 的 native mutation 存储。

这能测试状态机与崩溃语义，却不会删除目标。审计库对自己的 state 文件使用文件系统 I/O，不等于对扫描目标做 mutation。

## 未来架构方向

路线图的完整状态流仍是：

```text
scan -> explain -> immutable plan -> explicit authorization -> live revalidation
     -> platform action -> reconcile -> audit
```

当前公共表面只覆盖前两步和只读视图；P3 在库内模拟后续状态。native platform action、approval broker 和 CLI wiring 都尚未实现。
