---
title: 安全模型
---

# 安全模型

SweepX 当前的安全性首先来自能力缺失与类型边界：可运行表面只读，模拟执行表面 sealed，真实 mutation 表面不存在。未来安全目标不能被写成今天已有的删除保证。

> [!CAUTION]
> 当前没有 native Trash、Permanent、平台 mutation adapter 或 destructive CLI。P3 测试只覆盖确定性模拟，不能证明真实文件操作安全。

## 已实现的只读边界

| 边界 | 当前行为 |
|---|---|
| 用户选择根 | `scan` 只接受显式绝对路径 |
| 遍历 | Linux scanner 使用 metadata/no-follow 语义并记录边界 |
| 错误与不完整性 | 权限、挂载、链接和资源限制不会伪装成空或已完成 |
| 导入输入 | `scan.result` JSON 必须是绝对路径并受 byte/row 上限约束 |
| 导入可信度 | provenance 降级为 stale preview，coverage 强制 incomplete/not revalidated |
| TUI | 动作只包含导航；没有选择后执行或隐式 mutation |
| Cleaner | 只读 metadata，兼容性失败关闭 |
| 能力表达 | unsupported、degraded、report_only、disabled 分开报告 |

当前 CLI 不请求提权，不调用清理管理器，也不因 read error 自动扩大范围。这里的“只读”针对扫描目标；Unix 上的 `scan` 可以在指定 state directory 写自己的终态 snapshot，P3 audit library 也可以用 Unix bundled SQLite WAL 原子事务与 event replay 写 SweepX 自己的审计状态。Windows durable snapshot state 在私有 DACL 与 reparse-point 检查实现前保持禁用。它们都不修改被扫描的目标。

## 导入报告为什么只能 report-only

一个 JSON 文件记录的是过去的观察，不能证明路径现在仍指向同一个对象。`explain` 与 TUI 在导入时主动丢弃 live 权威：

```text
scan.result JSON
  -> bounded parse
  -> stale preview provenance
  -> incomplete + not revalidated coverage
  -> explanation / view only
  -> no executable candidate
```

这阻止了 `old report -> current delete`。即使 JSON 来自刚完成的本机扫描，导入边界仍按不可信执行输入处理。

## P3 library-only 安全模型

P3 libraries 把以下 simulation-only 对象保持为不同类型：

1. immutable `DeletionPlan` 与 canonical digest；
2. 精确绑定计划、模式、动作集合、用户、主机和 TTL 的 `ExecutionAuthorization`；
3. durable intent、fence、outcome 与 reconciliation 状态；
4. 一次性的 simulated preflight permit；
5. deterministic simulated receipt。

关键限制是：

- executor 请求只有 identifier 与 digest，不携带 native path；
- revalidation observer 与 fake adapter 都由 crate sealed；
- 唯一 adapter 不调用操作系统文件 mutation；
- simulated Trash/Permanent 只是不同的模型分支与审计标签；
- 没有 CLI 把用户输入接到这些 library APIs。

因此 P3 能验证 replay、binding、fencing、audit 与 fault-handling 逻辑，但不能验证真实 Trash、恢复性、释放空间或 TOCTOU 收口。

## P4a.2 失败关闭资格记录

P4a.2 增加的是 typed/validated capability qualification record 合同，不是 mutation 实现。它把 mutation 拆成五个独立单元：

| Capability cell | Linux | macOS | Windows |
|---|---|---|---|
| `trash.local.file` | disabled | disabled | disabled |
| `trash.local.directory` | disabled | disabled | disabled |
| `permanent.local.file` | disabled | disabled | disabled |
| `permanent.local.directory` | disabled | disabled | disabled |
| `permanent.local.link` | disabled | disabled | disabled |

验证器拒绝把 `fixture_conformance_only`、`fake`、`stale`、`incomplete`、`placeholder` 或 `mismatched` evidence 用作 mutation 资格。未来只有 evidence class 为 `real_os_qualification`、有效性为 `current`，且完整匹配 Core/version、policy 与 adapter digest、OS build、arch、filesystem/version、volume、provider/backend、ordinary-user profile 和精确 capability 的 tuple，才可能使单个单元合格。

这只是失败关闭的 registry substrate，不是运行时 registry 服务。当前没有合格 mutation 记录、native adapter、mutation command 或 approval UI。

## 未来 mutation 的不可谈判约束

下列内容是未来发布门槛，不是当前能力声明：

- 普通用户边界；不以 UAC、`sudo`、polkit 或权限改写扩大作用域。
- Candidate、Explanation、Plan、Authorization、Permit、Outcome 与 Audit 保持类型分离。
- 授权绑定完整 immutable plan；修改目标、模式、风险或动作集合必须重新授权。
- 每个动作在平台调用前做 live no-follow revalidation。
- 根、系统区域、home/profile 根、SweepX state 与 protected anchors 不可批准。
- Trash failure、拒绝、取消或 ambiguity 绝不回退为 Permanent。
- intent 必须先持久化；不确定提交进入 reconciliation，不自动重试猜测。
- `unknown` 不显示为 `0`，potentially reclaimable 不显示为 guaranteed freed space。

## 关于未来 Permanent 提案

设计材料讨论过独立的 Permanent R4 授权和显式危险来源。这仍然只是模型与路线图：当前 CLI 没有 `--dangerously-delete`，也没有 Permanent adapter。若未来引入，它必须绑定既有精确计划，不能选择额外目标、绕过保护或成为 Trash fallback；它也不等于 secure erase。
