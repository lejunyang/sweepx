---
title: 安全模型
---

# 安全模型

SweepX 当前的安全性首先来自能力缺失与类型边界：可运行表面只读，模拟执行表面 sealed，真实 mutation 表面不存在。未来安全目标不能被写成今天已有的删除保证。

> [!CAUTION]
> 当前仅有单对象 Trash development preview：必须交互确认并在提交前重验；没有 Permanent、plan/approve/execute 或 Trash-to-Permanent fallback。P3 测试仍只覆盖确定性模拟。

## 已实现的只读边界

| 边界 | 当前行为 |
|---|---|
| 用户选择根 | `scan` 只接受显式绝对路径 |
| 遍历 | Linux 使用 metadata/no-follow 语义；macOS 使用 handle-bound traversal；Windows 使用 handle-relative traversal；三者都记录边界 |
| 错误与不完整性 | 权限、挂载、链接和资源限制不会伪装成空或已完成 |
| 导入输入 | `scan.result` JSON 必须是绝对路径并受 byte/row 上限约束 |
| 导入可信度 | provenance 降级为 stale preview，coverage 强制 incomplete/not revalidated |
| `cache status` | 只读检查现有 preview cache 结构与健康；缺失时返回 `absent`，且不创建目录 |
| TUI | 导航之外仅允许 `d`/`Delete` 选择单项 Trash；退出全屏后确认并重验，symlink/reparse/root 禁止操作 |
| Cleaner | 只读 metadata，兼容性失败关闭 |
| 能力表达 | unsupported、degraded、report_only、disabled 分开报告 |

当前 CLI 不请求提权，不调用清理管理器，也不因 read error 自动扩大范围。这里的“只读”针对扫描目标。Linux 可在 SweepX state directory 写 bounded SQLite event journal，并以单事务保存完整流与 terminal snapshot；macOS 只写 legacy terminal snapshot；Windows durable operation state 禁用，默认 `state_dir=None`，显式 `--state-dir` 失败关闭。`scan --no-state` 可显式跳过 Linux/macOS 的 operation-state 写入，并与 `--state-dir` 冲突。Linux 的 Core status journal-first，并支持 degraded 的 `sweepx --format ndjson status --operation-id ID --watch [--after SXCUR1]` completed replay：它只重放已完成且已持久化的 stream，先做一次同 snapshot 全量校验，再按每页最多 1024 条事件续读；unknown 但语法有效的 cursor 返回 `stream.reset_required`，malformed cursor/usage 返回 usage error。`cache status` 则只读取现有 preview cache：检查范围限于 `preview-cache/current.json`、current generation、`generations/` 与 `quarantine/` 的浅层结构、近似字节数和健康状态；缺失 state/cache 返回 `absent` 且不创建目录，NDJSON 是 usage error。它不会触发 scan、repair、quarantine 或 rebuild，也不会暴露 cache 条目或 path 内容。由于事件仍在 scan 后批量构造，completed replay 不是 live，不等待新事件，不创建后台 operation，也不支持 cancel。这不代表 live sink、runtime qualification 或 mutation qualification；这些状态写入都不修改扫描目标。

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
| `trash.local.file` | 当前主机为 degraded preview | 当前主机为 degraded preview | 当前主机为 degraded preview |
| `trash.local.directory` | 当前主机为 degraded preview | 当前主机为 degraded preview | 当前主机为 degraded preview |
| `permanent.local.file` | disabled | disabled | disabled |
| `permanent.local.directory` | disabled | disabled | disabled |
| `permanent.local.link` | disabled | disabled | disabled |

验证器拒绝把 `fixture_conformance_only`、`fake`、`stale`、`incomplete`、`placeholder` 或 `mismatched` evidence 用作 mutation 资格。未来只有 evidence class 为 `real_os_qualification`、有效性为 `current`，且完整匹配 Core/version、policy 与 adapter digest、OS build、arch、filesystem/version、volume、provider/backend、ordinary-user profile 和精确 capability 的 tuple，才可能使单个单元合格。

这仍是失败关闭的 registry substrate，不是运行时 registry 服务。当前 Trash 只是 `degraded` preview，没有 `qualified` mutation 记录、Permanent adapter 或 approval UI。

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
