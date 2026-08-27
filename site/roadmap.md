---
title: 路线图
---

# 路线图

路线图是能力与证据门槛，不是发布日期。代码可以先落地，阶段仍可能因为跨平台、基准、故障注入或安全证据不完整而未完成。

> [!CAUTION]
> 当前实现横跨 P1/P2 的部分只读能力和 P3 的 library-only 模拟，但没有任何 native mutation。不能把“有 crate/测试”写成“阶段已资格化”。

## 当前落点

| 轨道 | 当前证据 | 未完成边界 |
|---|---|---|
| P0 契约/模型 | workspace、schema、fixture、安全类型和大量测试存在 | 完整 evidence bundle 与所有验收门尚未声明完成 |
| P1 scanner CLI | Linux read-only scan degraded；macOS handle-bound scan degraded；Windows handle-relative scan degraded；三者均通过 `scan` / `scan --tui` 暴露；Unix status snapshot 可用 | Windows durable state disabled，默认 `state_dir=None`，显式 `--state-dir` fail-closed；scan NDJSON 与 live cancel disabled；三平台/资源 gate 未闭合 |
| P2 analysis/TUI/Cleaner | bounded explain、`scan --tui` live 目录浏览、metadata-only Cleaner 可运行 | imported explain input report-only；签名/沙箱/完整跨表面资格未闭合 |
| P3 plan/audit/simulation | immutable plan、simulation-only authorization、Unix audit/recovery、sealed fake executor 已实现；Unix audit 现使用 bundled SQLite WAL 原子事务 + event replay | 没有 CLI wiring、可信 HumanApproval broker、native path、真实 revalidation 或 platform adapter；阶段尚未资格化 |
| P4a 资格底座 | Linux `cfg(test)` disposable fixture；P4a.2 typed/validated qualification records 与五个独立 mutation cell | 所有 cell 在 Linux/macOS/Windows 上均 disabled；没有 native adapter、mutation command、approval UI 或产品 mutation capability |
| P4+ mutation | 无公开能力 | Trash、Permanent 与发布资格全部是未来工作 |
| 发布工程 | CI、Pages、五目标归档/checksum、Unix/Windows 安装器、crates.io 顺序发布已实现 | 尚无稳定 release；签名、SBOM 与 provenance gate 未完成 |

## 阶段目标

| 阶段 | 目标增量 | 明确不包含 |
|---|---|---|
| P0 | 契约、schema、安全策略、fixture/oracle 基线 | mutation 与性能宣传 |
| P1 | 三平台合格的只读 scanner CLI | Cleaner 执行、计划、Trash/Permanent |
| P2 | 可解释分析、有界 TUI、只读 Agent 与 catalog reporting | 审批或真实执行 |
| P3 | immutable plan/authorization、durable audit、deterministic simulation | native Trash/Permanent、用户文件执行、public execution CLI |
| P4 | 仅对精确合格 tuple 开放 native Trash beta | Permanent、跨文件系统/remote/provider/system mutation |
| P5 | 三平台普通用户稳定产品 | 未资格能力、提权清理与广义 manager mutation |
| P6 | 单独 threat model 下的 post-v1 轨道 | 无独立证据的扩张 |

## P3 完成标准

当前最接近的工作是 P3 libraries。它只有在模型和 fault-injection tests 持续证明以下内容时才能收敛：

- plan digest 与 authorization exact binding 不能错配；
- nonce、TTL、claim、fence 和 permit 不能 replay；
- durable intent 在 simulated submit 前写入；
- ambiguous outcome 进入 reconciliation；
- cancel 不会被记成 success；
- Trash 分支不会转成 Permanent；
- sealed fake adapter 仍是唯一 executor adapter；
- 对用户文件的 native mutation 始终不可能。

即便完成这些，也不会自动产生 `sweepx plan/approve/execute` CLI。公共接口设计、可信本地审批、真实 live revalidation 和 native adapter 是后续独立工作。

## P4 之前的硬停止线

在第一个 native Trash test 之前，至少需要：

1. 精确 OS/arch/filesystem/provider capability tuple；
2. disposable fixture 与独立 oracle；
3. target、parent、ancestor、mount 与 descendant swap 对抗测试；
4. native result ambiguity 与 crash reconciliation；
5. 证明所有 Trash failure path 不会进入 Permanent；
6. CLI/TUI/Agent/Cleaner 对相同身份、风险与结果保持一致。

当前没有进入这一步。

P4a.2 只完成了失败关闭的 qualification registry 合同。`trash.local.file`、`trash.local.directory`、`permanent.local.file`、`permanent.local.directory` 和 `permanent.local.link` 在三个 OS family 上仍全部 disabled。`fixture_conformance_only`、`fake`、`stale`、`incomplete`、`placeholder` 和 `mismatched` evidence 永远不能资格化 mutation；未来也只有 current `real_os_qualification` evidence 完整匹配精确 tuple 时，单个 cell 才可能合格。

## 未来命令仍然只是提案

`plan create/show`、trusted approval、`execute` 和任何 Permanent flag 都不在当前命令树。文档只有在真实 CLI wiring 与对应 capability qualification 落地后，才能把它们从“提案”改为“可运行”。
