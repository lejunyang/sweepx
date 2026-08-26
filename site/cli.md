---
title: CLI 草案
---

# CLI 草案

README 把 SweepX 的命令展示明确标记为“未来接口草图”。这意味着文档可以解释语义，但不能把这些命令当作当前可执行接口。

> [!WARNING]
> 下面的命令面是 proposed interface only。当前仓库没有可运行的 `sweepx` 命令，也没有任何已发布的 destructive action。

## 只读扫描与解释

```text
sweepx scan <ABSOLUTE_USER_SELECTED_ROOT> --format ndjson
sweepx explain --scan-id <SCAN_ID> --candidate-id <CANDIDATE_ID> --format json
```

这里的重点不是命令名字，而是语义拆分：

- `scan` 只产生当前 live generation 的事实、边界和候选。
- `explain` 绑定单个候选，展示事实、推导、未知项、风险和恢复预期。
- 两者都不构成删除授权。

## 计划、审批与执行

```text
sweepx plan create --scan-id <SCAN_ID> --candidate-id <CANDIDATE_ID> --mode trash --format json
sweepx plan show --plan-id <PLAN_ID> --format json
sweepx approve --plan-id <PLAN_ID>
sweepx execute --plan-id <PLAN_ID> --approval-id <APPROVAL_ID> --format ndjson
```

设计上，这组接口只允许用户沿着固定状态机前进：

1. 先根据 live data 创建 immutable plan。
2. 人类在可信本地界面核对精确计划。
3. 核心返回并验证 opaque approval id。
4. `execute` 在真正动作前继续逐项复验。

因此，CLI 草案有两个核心立场：

- 它不允许把聊天确认、管道输入或配置默认值视作审批。
- 它不允许旧计划绕过现场复验。

## Permanent 是独立模式，不是开关补丁

README 还给出了单独的 Permanent 草案：

```text
sweepx plan create --scan-id <SCAN_ID> --candidate-id <CANDIDATE_ID> --mode permanent --format json
sweepx execute --plan-id <PERMANENT_PLAN_ID> --dangerously-delete
```

这部分必须谨慎理解：

- Permanent plan 与 Trash plan 完全分离。
- `--dangerously-delete` 只能作用于现有 Permanent plan。
- 它记录的是显式危险授权，不是人类身份认证。
- AI Agent 被明确禁止调用这个危险开关。

## 当前用户应该如何解读这些命令

最重要的不是记住参数，而是记住现状：

- 这些命令 today are not runnable.
- destructive features are unavailable or unqualified.
- 文档里的命令只是把未来实现需要满足的安全协议写清楚。

如果未来真的落地，CLI 也必须先服从安全模型，而不是为了简化体验省略 plan binding、审批对象或执行前复验。
