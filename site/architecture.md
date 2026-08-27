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
  -> durable terminal snapshot on Unix (optional state directory)
  -> no durable terminal snapshot on Windows (state_dir defaults to None)

bounded scan.result JSON
  -> imported provenance downgrade
  -> report-only explanation
```

Linux、macOS 与 Windows 均连接实际的 development-grade/degraded 只读 scanner backend；macOS traversal 为 handle-bound，Windows 为 handle-relative，三者都通过 `sweepx scan` / `scan --tui` 暴露。

## Crate 职责

| 层 | 代表 crate | 当前职责 |
|---|---|---|
| 模型与协议 | `sweepx-model`, `sweepx-protocol`, `sweepx-canonical`, `sweepx-i18n` | tagged evidence、稳定 envelope/canonical digest、双语渲染 |
| 平台与扫描 | `sweepx-platform*`, `sweepx-scanner`, `sweepx-cache` | platform boundary、Linux 只读遍历、macOS handle-bound 只读遍历、Windows handle-relative 只读遍历、聚合，以及 Unix-only durable state |
| 分析与 Cleaner | `sweepx-analysis`, `sweepx-cleaner-*`, `sweepx-catalog` | candidate/explanation、声明式规则、内置 package |
| 用户表面 | `sweepx-core`, `sweepx-cli`, `sweepx-tui` | 命令编排、机器/人类输出、有界只读视图 |
| P3 模拟安全 | `sweepx-safety`, `sweepx-audit`, `sweepx-executor` | immutable binding、durable audit/recovery、sealed fake execution |

## 状态与取消

CLI scan 当前同步完成，并在 Unix 上启用 state directory 时保存 terminal snapshot。Windows durable state 禁用：默认 `state_dir=None`，不持久化 terminal snapshot，显式 `--state-dir` 失败关闭。`status` 不是后台 worker 查询；scan NDJSON 与 live cancel 也仍禁用。`cancel` 只返回诚实 disposition；这就是 capability 被标记 disabled 的原因。

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
- audit persistence 当前仅支持 Unix；它现在使用 bundled SQLite WAL 原子事务与 event replay 管理 durable claim、intent、outcome 与 reconciliation 状态；它仍不是 native mutation 的发布级存储。

这能测试状态机与崩溃语义，却不会删除目标。审计库对自己的 state 文件使用文件系统 I/O，不等于对扫描目标做 mutation。

## 未来架构方向

路线图的完整状态流仍是：

```text
scan -> explain -> immutable plan -> explicit authorization -> live revalidation
     -> platform action -> reconcile -> audit
```

当前公共表面只覆盖前两步和只读视图；P3 在库内模拟后续状态。native platform action、approval broker 和 CLI wiring 都尚未实现。
