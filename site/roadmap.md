---
title: 路线图
---

# 路线图

路线图第 4 节给出的不是发布日期，而是阶段式能力边界。它最重要的信息不是“何时上线”，而是“在什么证据条件下，哪些能力仍然不能上线”。

> [!CAUTION]
> 当前 SweepX 仍处于设计阶段。P0 到 P3 都不包含真实平台变更路径，因此任何 destructive capability 现在都不可用。

## 分阶段演进

| 阶段 | 可见增量 | 仍然不包含什么 |
|---|---|---|
| P0 | 契约、schema、安全策略、fixture 与 oracle 基线 | 任何 runnable cleaner 或平台变更 |
| P1 | 0.1 只读 scanner CLI | Cleaner 推荐、计划、审批、Trash、Permanent |
| P2 | 0.2 explainable analysis、TUI、只读 Agent 工作流 | 计划批准、真实执行、浏览器状态删除、策略变更 |
| P3 | 0.3 immutable planning 与 simulated execution | 任何 native Trash / Permanent call |
| P4 | 0.9 native Trash beta，且仅限合格 tuple | Permanent、跨文件系统 Trash、远程/provider/system 路径 |
| P5 | 1.0 普通用户稳定产品 | 任何未取得资格的能力、提权清理、广义 manager mutation |
| P6 | post-v1 能力轨道 | 没有新 threat model 和独立证据的扩展 |

## 关键判断

这条路线图直接决定了当前站点必须怎么写：

- 现在还没有进入 P4 的资格化 native Trash beta。
- 因此 destructive features 不能被描述为 beta-ready，更不能被表述为可执行。
- Permanent 更晚，且只有在独立 capability cell 被证明后才可能出现。

## 第 2 节与第 4 节如何共同约束产品

第 2 节定义安全底线，第 4 节定义阶段边界。两者叠加后的结果是：

1. 每个阶段都要继承普通用户边界、计划绑定和失败关闭语义。
2. 阶段推进不能用“先支持功能，之后补安全”来解释。
3. 即便某个原型能跑，只要证据和资格没完成，站点也必须把它当作 unavailable / unqualified。

## Stop-ship 规则

路线图还列出了不能发布的条件，尤其包括：

- 任一硬保护、审批、intent、permit 或 reconcile 约束可以被绕过。
- CLI、TUI、Cleaner API、Skill 之间出现语义分叉。
- 错误、未知项、不完整子树被渲染成“当前为 0”或“已完成”。
- 任何 adapter 无法证明 Trash failure 不会走到 Permanent。

这些规则让路线图更接近发布门槛说明，而不是普通的 feature backlog。

## 当前最诚实的产品状态

如果只基于现有文档，当前最准确的结论是：

- SweepX 是一份安全约束清晰的设计快照。
- read-only 和 simulated 阶段描述得较完整，但仍不是交付实现。
- destructive features remain under development and are not available for use today.
