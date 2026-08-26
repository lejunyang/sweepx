---
title: Cleaner 概念
---

# Cleaner 概念

Cleaner 是带版本、证据和兼容约束的领域规则包，不是任意 shell script，也不是当前可执行的清理插件。

## 当前内置内容

仓库包含两个示例 package：

| Cleaner ID | 描述 | 当前命令面 |
|---|---|---|
| `org.sweepx.cargo-target` | Cargo workspace 的 target build output | metadata/report-only |
| `org.sweepx.chromium-rebuildable-cache` | Chromium HTTP 与 Code Cache，并与应用状态分离 | metadata/report-only |

package 包含 manifest、规则和 evidence 文档。规则由受限、声明式 VM 表达；当前 CLI 不让它执行 I/O、外部命令或 native mutation。

## `list` 与 `show` 的差异

```bash
cargo run -p sweepx-cli -- --format json cleaner list
cargo run -p sweepx-cli -- --format json cleaner show <CLEANER_REF>
```

- `list` 总结所有内置 package，并逐项报告 `compatible` / `incompatible` 和 `reportOnly`。
- `show` 可接受 `id` 或 `id@version`，但在当前 Core 不满足 `requires.core` 时以兼容性错误失败。
- 兼容性门不能通过 flag 绕过，也不会因为 list 能看到 package 就让它变成 executable。

当前 Core 是 `0.1.0`，两个内置 manifest 要求 `>=1.0.0, <2.0.0`，所以 list 会诚实返回 partial，而 show 失败关闭。这是期望状态。

## 规则输出不等于清理动作

规则评估可以表达 known/unknown、证据、风险和 report-only，但不能：

- 生成未由扫描证据支持的裸路径；
- 降低未知项的风险；
- 执行 Cargo、浏览器或操作系统命令；
- 删除、移动或回收文件；
- 创建 plan、authorization 或 permit。

即使未来 Cleaner 能生成候选，导入 scan JSON 的 stale/incomplete provenance 仍强制候选 non-executable。

## 未来资格门

Cleaner 从“能描述”走到“能参与执行”至少需要 package canonicalization、签名与撤销、Core/version compatibility、规则确定性、平台与应用版本证据、reference/activity/recovery fixtures、完整 live identity 与通用 Safety Core 的计划/授权流程。当前这些门没有全部完成，因此文档只承诺 metadata/report-only。
