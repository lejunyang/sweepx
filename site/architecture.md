---
title: 架构
---

# 架构

SweepX 的架构信息在 README 中已经有一条主线：同一套安全核心同时服务 CLI、TUI 和 Agent，而不是给某个前端保留更宽松的 mutation path。

## 一条受约束的状态流

README 用一条状态流概括未来实现：

```text
scan -> explain -> immutable plan -> explicit execution authorization -> live revalidation
     -> platform action -> reconcile -> audit
```

这条流的价值在于把每一步都变成可验证的状态，而不是一段模糊的“开始清理”。它要求：

- 观察不等于授权。
- 旧缓存不等于当前现场。
- 平台调用结果不等于一定成功或一定可恢复。

## 核心模块分层

从现有设计文本可提炼出四层职责：

| 层 | 责任 |
|---|---|
| Scanner | 只读、流式、no-follow 地收集目录事实与边界，并保持稀疏状态。 |
| Analyzer | 生成 Candidate 和 Explanation，区分事实、推导、启发式与未知项。 |
| Planner / Authorization | 产出 immutable plan，并把 HumanApproval 或 ExplicitDangerousDelete 绑定到该计划。 |
| Execution / Audit | 在 live revalidation 通过后调用平台动作，并持久化 intent、结果、reconcile 与 audit。 |

## 为什么 Agent 必须受限

SweepX 的 Agent-safe 不是让 Agent 自动删除，而是明确 Agent 只能工作在受限边界内：

- Agent 只能经公开、结构化的 Core API 工作。
- Agent 可以帮助做只读扫描、解释、计划展示。
- Agent 不能审批计划，不能代输确认，也不能调用危险删除开关。

这决定了产品结构必须以 Core 为中心，而不是让某个前端单独实现一套近路。

## 稀疏状态而不是全量清单

README 还强调扫描状态默认是稀疏的：

- 目录聚合和内存队列优先。
- 只有达到高水位后才允许有界临时 spill。
- 持久 cache 不保存海量普通小文件明细。
- TUI 默认显示 top-K 与 `Others`，深入时再优先 live 展开。

这意味着未来架构既要考虑大规模文件树，也要防止“为了列全量明细而让状态无限膨胀”。

## 当前能确认的结论

站点只对已经明确写出的设计边界负责，因此当前能诚实表达的结论是：

- 架构目标是安全核心统一，而不是多前端各自实现删除。
- destructive features are still under development。
- 真实平台适配、审批 Broker、回收站 adapter 和崩溃恢复都还没有成为已交付实现。
