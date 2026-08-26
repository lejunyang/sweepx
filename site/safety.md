---
title: 安全边界
---

# 安全边界

路线图第 2 节把 SweepX 的安全底线定义为所有阶段都必须继承的约束，而不是可以为了上线时间临时放宽的策略。

> [!CAUTION]
> 当前实现仍在开发中。以下内容描述的是未来版本必须满足的安全约束，不代表仓库里已经存在可用的 destructive feature。

## 不可谈判的底线

| 约束 | 站点解读 |
|---|---|
| 普通用户边界 | SweepX 以当前普通用户身份运行，不请求提权，也不会把 elevated runtime 视作合法 destructive mode。 |
| 只读扫描 | 扫描是 metadata-only、no-follow、same-mount/volume、错误可见、流式聚合。 |
| 类型分离 | Candidate、Explanation、DeletionPlan、ExecutionAuthorization、PreflightPermit、平台结果和审计记录必须是不同状态。 |
| 计划绑定 | 授权绑定某一个精确计划，不能把旧结果、缓存、目录年龄或“没发现进程占用”当成删除许可。 |
| 回收站优先 | Trash 失败、权限不足、取消或结果不明时，绝不能静默回退到 Permanent。 |
| 硬保护不可绕过 | 根目录、系统关键区域、home/profile 根、SweepX 状态和保护锚点都不能进入执行计划。 |

## 为什么 destructive features 现在必须标记为 unavailable

因为路线图同时要求两件事：

- 在任何阶段都不能削弱计划绑定、复验和失败关闭语义。
- P0 到 P3 明确不包含真实平台变更路径，P4 才可能在有限资格单元里开始 native Trash beta。

这意味着当前任何“删除”“清理”“自动释放空间”的说法都不成立。更准确的表述是：

- 功能仍 under development。
- destructive workflow is unavailable。
- Permanent 只可能在独立资格完成后出现，而且不会早于更晚阶段。

## 审批与执行必须分离

路线图把一次可执行动作拆成若干独立对象：

1. 只读观察产生 Candidate 和 Explanation。
2. 规划阶段生成 immutable plan。
3. 人类审批或显式危险授权只绑定这一个计划。
4. 执行前仍需做 live revalidation。
5. 平台结果与审计记录必须独立持久化。

这套拆分的含义很直接：没有 `scan -> execute` 的捷径，也没有 “Trash 失败后直接 Permanent” 的降级通道。

## 审批记录的语义

即使未来有 HumanApproval 或 `--dangerously-delete`，它们也必须共享“精确计划绑定”这一核心约束：

- HumanApproval 绑定完整 canonical plan digest、模式、对象集合、风险和时效。
- `--dangerously-delete` 只授权既有 Permanent plan，本身不是人类身份凭证。
- Agent 可以准备计划，但不能驱动任何本地审批界面，也不能使用危险开关。

## 对外表达原则

站点、CLI 和未来 TUI 都应保持同一口径：

- 事实、推导、建议、未知项要明确区分。
- `unknown` 和 `0` 不能被混写。
- “potentially reclaimable” 不是“guaranteed freed space”。
- 只要资格和实测证据不完整，就必须保持 fail closed。
