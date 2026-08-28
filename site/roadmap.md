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
| P1 scanner CLI | Linux read-only scan degraded，且已有 bounded SQLite journal、单事务完整流/terminal persistence、journal-first status，以及 degraded 的 `status --watch --format ndjson` completed replay；macOS 保留 legacy snapshot；Windows scan handle-relative degraded | Linux replay 只覆盖已完成且已持久化的 stream：先做一次同 snapshot 全量校验，再按每页最多 1024 条事件续读；unknown-valid cursor 返回 `stream.reset_required`，malformed cursor/usage 是 usage error。它仍 non-live，不等待新事件，不创建后台 operation，也不支持 cancel；`scan --no-state` 可显式跳过 operation state 写入且与 `--state-dir` 冲突；Windows durable state disabled；live sink、runtime qualification、`scan --format ndjson` 与三平台/资源 gate 未闭合 |
| P2 analysis/TUI/Cleaner | bounded explain、`scan --tui` live 目录浏览、metadata-only Cleaner 可运行 | imported explain input report-only；TUI detail expansion 已是 single-flight 后台 rescan、2 s deadline、late result discard、32 stuck-worker cap；Cargo detector 现有有界 locator batch reader 和固定输入收集器，但 `targetDir` 仍是 `NotChecked`、`targetShape` 仍是 `Unknown`，结果继续 hint/report-only；签名/沙箱/完整跨表面资格未闭合 |
| P3 plan/audit/simulation | immutable plan、simulation-only authorization、Unix audit/recovery、sealed fake executor 已实现；Linux bounded journal、单事务 complete-stream/terminal persistence，以及 degraded completed-stream replay 已实现 | replay 仍 non-live、非 runtime-qualified，且只适用于 Linux completed stream；没有可信 HumanApproval broker、native path、真实 revalidation、live event sink、`scan --format ndjson`、非 Linux journal parity 或 platform adapter；阶段尚未资格化 |
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

## 新近里程碑记录

| Commit | 里程碑 | 当前准确表述 |
|---|---|---|
| `1483246` | Linux completed-stream replay/watch for `status` | Linux 现以 degraded 形式公开 `operation.event.completed_replay`：`sweepx --format ndjson status --operation-id ID --watch [--after SXCUR1]` 只重放已完成且已持久化的 journal stream，先做一次同 snapshot 全量校验，再按每页最多 1024 条事件续读；unknown-valid cursor 返回 `stream.reset_required`，malformed cursor/usage 是 usage error。该 replay 不等待新事件、不创建后台 operation、不支持 cancel，且仍 non-live、非 runtime-qualified。`scan --format ndjson` 保持 disabled；macOS 仍是 legacy snapshot；Windows durable state 仍 disabled。 |

## 新近里程碑记录

以下记录对应 2026-08-28 新落地、且已反映到当前文档的实现里程碑；它们是代码完成记录，不是资格声明：

| Commit | 里程碑 | 当前准确表述 |
|---|---|---|
| `297f006` | Scanner bounded locator file reader | 新增有界 locator reader 与 batch API；沿已 admission locator 读取固定文件，拒绝 display-path authority，并对请求、组件、字节和目录枚举施加上限。Linux 有原生测试；Windows/macOS 仍以现有 backend contract 和 native CI 作为资格门。 |
| `48d5f60` | Optional locator reads stay bound | optional relative reads 现继续绑定同一 filesystem/mount scope，并受剩余 batch byte budget 约束。 |
| `c0343da` | Cargo fixed-input collector | Cargo 固定输入收集器通过 handle-bound 读取 `Cargo.toml` 与 `.cargo/config*`，对替换、symlink/reparse、mount 变化、资源上限和取消 fail closed。 |
| `f042e39` | Typed Cargo evidence surfaced | `cargo-detect` 现输出 typed Cargo evidence 和独立 capability 条目；workspace evidence 可在绑定成立时变为 `Known`，但由于全局 override scope 未解，`targetDir` 仍为 `NotChecked`、`targetShape` 仍为 `Unknown`，结果继续只做 hint/report-only，`candidate/plan/approval/execution` 全为 false。 |
