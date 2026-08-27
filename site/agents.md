---
title: Agent 权限边界
---

# Agent 权限边界

Agent-safe 的含义不是“Agent 可以自动清理”，而是自动化只能使用比本地用户更窄、可审计的能力。

## 当前允许范围

Agent 可以在用户提供明确范围后：

- 运行 `capabilities` 并报告 degraded/report-only/unsupported/disabled 状态；
- 在用户选择的绝对根上运行 Linux 只读扫描；
- 读取现有 JSON，解释 error、boundary、coverage 和 tagged size；scan NDJSON 当前禁用；
- 对有界 scan JSON 运行 report-only `explain`；
- 列出或展示 Cleaner 元数据；
- 打开或摘要只读 TUI 输入。

Agent 必须保留机器输出中的不确定性，不能把 partial 改写为完整、把 unknown 改写为 zero，或把 potentially reclaimable 改写为 guaranteed freed。

## 当前禁止范围

当前 CLI 本身没有 mutation 命令；Agent 也不得绕过这一事实：

- 不得把聊天确认当作 HumanApproval；
- 不得直接调用 safety/audit/executor library 拼出伪工作流；
- 不得生成、伪造或消费 plan、authorization、permit 或 audit token；
- 不得执行包管理器、浏览器或 shell cleanup 命令；
- 不得调用未实现的 `plan`、`approve`、`execute` 或 `--dangerously-delete`；
- 不得将 fake executor receipt 描述为真实清理结果。

## 结构化输出与语言

当前 scan 自动化应使用 JSON；NDJSON 要等 durable journal/replay 完成后才会开放。`--locale` 只影响人类文案，不改变 schema key、status、reason code 或 capability state。Agent 不应通过翻译或摘要丢失这些稳定字段。

## 未来边界仍然更窄

路线图允许未来 Agent 协助 scan、explain 和计划展示，但不允许它驱动 native dialog、OS verifier、trusted terminal challenge 或危险开关。即使用户在聊天中说“批准”，也必须由未来 Core 验证来自可信本地表面的 opaque approval，并重新做 live revalidation。当前尚无这条 CLI workflow。
