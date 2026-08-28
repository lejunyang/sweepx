# SweepX CLI、TUI 与 Cleaner 插件架构

状态：v1 设计稿。设计截点：2026-08-26。

> **安全声明：本文只定义接口、数据契约和发布门槛，不是实现或操作手册；本文编写过程没有扫描、清理、删除、移动、提权、启动生态工具、修改浏览器/开发环境，也没有调用任何外部副作用。** 文中的命令仅表示未来产品接口。

## 1. 范围、原则与共同下限

本设计为本地人类 CLI、全屏 TUI 和 Cleaner 插件定义同一个产品边界。三者不是三套清理器：它们都只能调用同一个 Scanner、Candidate Builder、Planner、Human Approval Broker、Preflight、Executor、Audit/Reconciler。CLI/TUI 只是呈现层；Cleaner 只能提供受约束的发现规则和证据；任何一层都不能直接取得删除 adapter。

v1 的共同下限如下：

1. 以当前普通用户运行；破坏性模式拒绝 root、elevated token 和会扩大文件访问边界的 Linux capability。不得请求 UAC、`sudo`、polkit、Full Disk Access、backup privilege，不接管 ownership，不改 ACL、TCC、immutable/read-only 属性或系统设置。
2. 只允许本机、本用户、本次 live admission 和 live no-follow 枚举产生 Candidate。缓存、导入 JSON、远端结果、历史报告、插件声明和 stale preview 都不能产生 Candidate 或执行许可。
3. 默认不跟随 symlink/Windows reparse point，不跨 mount/volume；额外 root 必须单独 admission。unknown reparse、mount/bind、provider、网络、权限或身份边界显式报告并失败关闭。
4. 默认动作是平台 Trash/Recycle Bin。Trash 不可用、失败或结果不明时，绝不降级成永久删除。`Permanent` 是独立计划、独立授权且所有动作均为 R4；它不是 secure erase。
5. root、系统目录、home/profile 根、Trash、SweepX 自身状态、保护路径/身份及任一祖先中的 `.sweepx-protect` 是 core 硬保护，CLI flag、配置、插件、`--yes`、`--force` 或直接 API 均不可绕过。
6. 路径不是身份。不可变计划绑定 parent recipe、native basename、parent/object/domain/type/mount/link identity、policy/adapter 版本和摘要。每个实际动作紧邻调用前必须重新 no-follow 定位、完整复验并取得最长 2 秒的一次性 `PreflightPermit`。
7. 批次不具备事务性。审批和执行按 action 绑定；每个 action 写前持久化 intent，记录平台结果，并在崩溃、取消或矛盾时 reconcile。已成功项不自动回滚，未知结果不自动重试。
8. `unknown`、`unsupported`、`not_checked`、`lower_bound`、`incomplete` 与数值 `0` 永远不同。缺证据只会提高风险或 report/skip，不会变成 `unused`、`safe` 或删除许可。
9. 扫描器维持 `B_scan=128 MiB` tree-dependent memory budget、parent + all helpers `384 MiB` private-RSS 发布 envelope、count+bytes 双重队列上限、有界 spill、公平调度和 backpressure。慢 TUI、慢插件或断开的事件消费者不能迫使 Scanner 无界缓存。
10. 所有前端使用同一结构化契约。显示文本、翻译后的路径、排序、过滤和解释不参与 digest、身份比较或执行参数。

风险语义固定为：R1 为边界明确、可重建的低风险候选；R2 为目录、多项、共享或释放量不确定；R3 为数据库、工具链、浏览器应用状态、provider/remote、活动对象或能力不确定，默认跳过或 Trash-only；R4 为任何 Permanent 或不可逆 manager mutation；`BLOCKED` 不可审批。

## 2. 组件、信任与唯一安全状态机

### 2.1 组件图

```text
不可信输入/呈现层
  CLI human renderer    TUI virtual views    Agent/JSON client
          |                    |                    |
          +--------- versioned Core API -----------+
                               |
Cleaner package -> Rule VM -> Detect/Analyze -> Candidate Builder
 (signed data)     (sandbox)    (evidence only)      |
Native probe helper -------------------------------> |
 (少量、审计、隔离；不能产 Candidate/permit)          |
                                                     v
                 Explanation -> Immutable Planner -> Human Approval Broker
                                                        | sealed approval ref
                                                        v
          Audit fence -> live Revalidation -> one-shot PreflightPermit
                                                        |
                                  Core Executor -> platform adapter
                                                        |
                                      Outcome -> Audit/Reconciler
```

信任从低到高分为五层：

- **展示与输入层（不可信）**：CLI 参数、TUI selection、JSON/NDJSON 客户端、Agent、导入文件只提交查询或候选 ID，不能提交原始删除路径、审批正文或 permit。
- **Cleaner 层（受限）**：签名只证明来源和完整性，不证明规则正确。声明式规则在无副作用 VM 中运行；少量 native probe 在隔离 helper 中运行，只能发出 typed evidence/proposed root。
- **Scanner/分析层（事实边界）**：Scanner 以当前普通用户 live、metadata-only、no-follow、same-mount 观察，Candidate Builder 再把当前记录与规则证据连接。缓存仅用于 `StalePreview` 和纯派生加速。
- **计划/审批层（授权边界）**：Planner 生成 canonical immutable plan；Human Approval Broker 独占审批构造权。审批表达人的精确意图，但不证明对象仍未变化。
- **执行/审计层（最高权限但仍为普通用户）**：Preflight 独占 permit 构造权，adapter 只收 sealed permit 和绑定的 native basename/官方动作描述，不收任意 path、argv 或 force bit。Audit store 不可 durable append+sync 时不得开始动作。

插件进程、CLI/TUI 渲染器、Agent 和 JSON 调用者均不能链接或访问 adapter 的构造接口；`PreflightPermit` 是 core-private、不可序列化类型。即使绕开 UI 直接调用公开 Core API，也必须经过相同硬保护、审批绑定、live 复验、intent 和 reconcile。

### 2.2 唯一安全状态机

Cleaner 的 `detect -> analyze` 是进入核心前的只读管线 phase，不另造授权状态：成功的 live detection 产生 `CANDIDATE`/批次 `DISCOVERED`，analysis 产生 `EXPLAINED`；`report_only` 是分析处置结果而非可继续向下的状态。所有 CLI、TUI、Cleaner 和 Agent 必须投影下面两套由安全核心持久化的规范状态；不得重命名后改变含义，也不得创造捷径。

批次状态：

```text
DISCOVERED -> EXPLAINED -> PLANNED -> AUTHORIZATION_PENDING -> AUTHORIZED
  -> REVALIDATING -> READY -> EXECUTING
  -> { COMPLETED | PARTIAL | CANCELLED | NEEDS_RECONCILIATION }
any applicable nonterminal state -> { REJECTED | HARD_BLOCKED }
each terminal outcome T -> AUDITED(terminalOutcome=T)
```

单项状态：

```text
CANDIDATE -> EXPLAINED -> IN_PLAN -> AUTHORIZED -> REVALIDATING
  -> PREFLIGHT_READY -> TRASHING | PERMANENT_DELETING
  -> { SUCCEEDED | FAILED | SKIPPED | STALE | CANCELLED | INDETERMINATE }
any applicable nonterminal state -> { REJECTED | HARD_BLOCKED }
each terminal outcome T -> AUDITED(terminalOutcome=T)
```

任一适用阶段都可进入 `REJECTED` 或 `HARD_BLOCKED` 并写审计。合法分支只有：解释绑定 evidence 后才可计划；计划必须 canonical digest；batch `AUTHORIZED -> REVALIDATING -> READY` 和 item `AUTHORIZED -> REVALIDATING -> PREFLIGHT_READY` 都必须经过 live no-follow 全量复验；`READY/PREFLIGHT_READY -> EXECUTING/TRASHING|PERMANENT_DELETING` 必须已有 durable `ACTION_INTENT` 且 permit 未过期。`READY` 是 batch 聚合态，`PREFLIGHT_READY` 是 item 态，并非别名或重命名。preflight 可直接产生 `SKIPPED`、`STALE`、`HARD_BLOCKED` 或 `CANCELLED` 而不调用 adapter；平台已提交后只能由 action outcome/reconciliation 产生终态。`STALE` 必须重新 scan/explain/plan/authorize。`NEEDS_RECONCILIATION` 的 recovery 可把事实收敛为 `COMPLETED`、`PARTIAL` 或仍为 `INDETERMINATE`，绝不靠重放猜测。

每个 terminal batch/item 只有在相应 summary/outcome durable 后才转为 `AUDITED(terminalOutcome=T)`；`AUDITED` 是审计包装状态，永远保留而不替换 substantive terminal outcome。若 audit append+sync 失败，则保持未审计的 `NEEDS_RECONCILIATION`/明确失败并返回 exit 11；不得为了得到 `AUDITED` 而伪造结果。全部 action 明确成功才是 batch `COMPLETED`；只要至少一项明确失败/skip 且无 ambiguous/indeterminate（无论是否也有成功项，包括全失败/全 skip）就是 batch `PARTIAL`/JSON `partial`/exit 4；JSON `failed`/exit 8 只表示尚未形成可汇总 destructive batch 的一般命令失败。任一已提交动作结果无法证明则优先成为 `NEEDS_RECONCILIATION`，item 为 `INDETERMINATE`。

| 核心状态 | JSON status / exit | 关键事件 | TUI 标签 |
|---|---|---|---|
| `DISCOVERED` / `EXPLAINED` | `ok / 0`（只读结果） | `candidate.detected`, `analysis.completed` | 已发现 / 已解释 |
| `PLANNED` / `AUTHORIZATION_PENDING` | `ok / 0`；未授权执行请求为 `authorization_required / 6` | `plan.created`, `approval.requested` 或 dangerous flag admission | 计划待授权 |
| `AUTHORIZED` / `REVALIDATING` / `READY` | 流中状态；无单独成功结论 | `approval.granted` 或 `authorization.explicit_dangerous_delete`, `revalidation.*`, `preflight.ready` | 已授权 / 复验中 / 就绪 |
| `EXECUTING` | 流中状态 | `action.intent.durable`, `action.*` | 执行中 |
| `COMPLETED` | `ok / 0` | `batch.completed` | 已完成 |
| `PARTIAL` | `partial / 4` | `batch.partial` | 部分完成 |
| `CANCELLED` | `cancelled / 10`；有歧义则用 exit 9 | `batch.cancelled` | 已取消 |
| `NEEDS_RECONCILIATION` / item `INDETERMINATE` | `needs_reconciliation / 9` | `batch.needs_reconciliation`, `action.indeterminate` | 待核对 / 结果不确定 |
| `STALE` | `stale / 7` | `revalidation.stale`, `action.skipped` | 已过期，需重建 |
| `HARD_BLOCKED` | `blocked / 5` | `hard_protection.blocked`, `action.skipped` | 安全阻断 |
| `REJECTED` | `authorization_required / 6` 或只读 `failed / 8`（按阶段） | `plan.rejected` / `approval.rejected` | 已拒绝 |
| `AUDITED` | 沿用其已审计终态 | `audit.batch.committed`, `operation.terminal` | 已审计 |

## 3. 核心数据模型

所有整数时间使用 RFC 3339 UTC 字符串和独立 monotonic offset；所有可能超过 JSON 安全整数的 byte/count/sequence 用十进制字符串。Unix native basename 用 base64 原始 bytes，Windows 用 base64 UTF-16LE；`displayPath` 永不作为执行输入。

### 3.1 值、来源与覆盖

```json
{ "state": "known", "value": "0" }
{ "state": "lower_bound", "value": "4096", "reason": "incomplete_ads_coverage" }
{ "state": "unknown", "reason": "shared_extents_not_attributable" }
{ "state": "not_checked", "reason": "strict_z0_mode" }
{ "state": "unsupported", "reason": "platform_has_no_api" }
```

禁止用 JSON `null`、字段缺失、`-1` 或 `0` 代替这些状态。排序时 unknown 是独立桶；求和只对相同口径的 `known` 做 checked-u128 运算。任何 child 为无界 unknown 时，聚合不能声称 exact；权限失败使祖先成为 lower bound 且 `coverage.complete=false`。

`logical`、apparent logical、按 object identity 去重的 unique logical、filesystem-reported allocated、potentially reclaimable 与事后 caller-visible capacity delta 是六种不同口径。hard link、clone/reflink、snapshot、dedup、overlay 或 shared extent 未能证明独占时，exclusive reclaimable 必须是 `unknown`，不能把 logical/allocated 总和宣传为必然释放量。

```text
Coverage {
  complete, discovered, processed, skipped_entries, skipped_subtrees,
  error_count, boundary_count, unknown_size_entries, details_lost,
  incomplete_reasons[], durable_detail_sequence_range?
}

Provenance = LiveObservation | ValidatedCache | DerivedFromCurrent
           | StalePreview | Unknown
```

只有前三类且输入全部属于本代 current 才能进入 current aggregate；`StalePreview` 只能灰色展示。

### 3.2 Candidate、Explanation 与计划

`Candidate` 至少保存：schema/scanner/adapter/cleaner 版本和 digest、candidate/scan/root ID、`source=local_current_live_scan`、parent reopen recipe、native basename、parent/object/object-domain/type/mount/link identity、metadata fingerprint、logical/allocated/reclaimable tagged values、完整 coverage、boundaries/errors、rule IDs、facts/inferences/uncertainties、risk floor、支持动作和恢复条件。目录 Candidate 必须连接同一 scan generation 的 final `DirectoryAggregate` revision；不完整目录只能解释，不能进入目录 PlanItem。

`Explanation` 绑定 candidate digest，并逐项区分 `fact`、`manager_fact`、`rule_inference`、`heuristic`、`unknown`，说明为何命中、为何被排除、共享/引用/活动/恢复/凭据网络条件、大小口径、风险提升及所需人工动作。解释不可改 identity、scope、mode 或 risk floor。

不可变计划使用 `schema=sweepx.plan/v1`：

```text
DeletionPlan {
  planId, nonce, createdAt, expiresAt, hostInstanceId, userIdentity,
  scanId, scanRootIdentity, mode: Trash | Permanent,
  candidateSchemaVersion, scannerSemanticsVersion,
  safetyPolicyVersion, safetyPolicyDigest, protectedAnchorSnapshotDigest,
  adapterCapabilitiesDigest, cleanerSetDigest, items[], aggregateRisk,
  canonicalDigest
}

PlanItem {
  itemId, candidateId, explanationDigest, actionKind, topLevelActionId,
  parentReopenRecipe, nativeBasename, expected identities/type/mount/link,
  expectedMetadataFingerprint, subtreeComplete, descendantManifest?,
  cleanerEvidenceDigest?, officialActionDigest?, riskTier, riskFactors[],
  recoveryExpectation
}
```

任何 target、顺序、mode、risk、规则/adapter/policy/anchor digest 或 descendant manifest 改变都会得到新 plan ID/digest，并失效旧 authorization。`canonicalDigest` 是 immutable plan 的完整 256-bit digest；显示 fingerprint 只是该摘要的短 `SX1-...` 诊断/注意力 token，不是密码、授权或完整性边界。Trash 和 Permanent 不混批。Trash 目录是一个 top-level platform action，但执行前重验封闭 descendant manifest；Permanent 目录把每个 descendant 按后序变成独立 action，最后才是 root action，绝不把递归 glob 当成一个动作。

### 3.3 ExecutionAuthorization 与 permit

常规审批逻辑 schema 为 `sweepx.approval/v1`，但它**不是可导入 JSON 文件**。Broker 内部 HumanApproval 记录绑定：`approvalId`、plan ID 与完整 256-bit digest、mode、精确 item/action 集、selected-item/action counts、`approvedRiskByAction`、descendant manifest digests、policy/anchor/cleaner digests、user/host、`approvalSurface`、confirmation evidence、批准时间、最长 5 分钟 TTL、single-use nonce 和 consumed state。不能用短 fingerprint 或批次 `maxRisk` 替代完整 digest/逐 action risk。

为满足 human-only、exact-plan 和不可由 Agent/插件伪造：

1. 只有随 core 发布的 Human Approval Broker 可构造 ApprovalRecord；公共 SDK 没有 constructor/import endpoint。`approve` 不接受 JSON body、stdin、管道、环境变量、配置预批准、RPC token、`--yes` 或 `--force`。Agent、Cleaner、插件和远程客户端不得点击、键入或代答。
2. Broker 的 `ApprovalSurface` 优先是随 core 发布、身份经过校验的 `NativeFirstPartyLocalModal`。只有无合格图形会话且 Broker 能证明本地 controlling terminal、foreground process group 和当前用户会话时，才回退为 `TrustedForegroundTerminal`；没有第三种 stdin/RPC/webview surface。CLI/TUI 只得到 opaque `approvalId`，原始 record、认证密钥和 nonce 不出 broker。
3. 两种 surface 都从同一 pending request 展示 exact immutable plan：mode、可展开的精确 item/action 清单、`N` 个选中 item、`M` 个底层 action、逐项 risk、unknown/coverage、恢复预期、expiry 和只读 fingerprint。R3 逐项显式选择；selection 变化会创建/绑定新 plan，而不是在批准时偷偷修改旧 plan。
4. 原生 modal 要求用户先勾选明确 acknowledgement，再点击默认不聚焦、危险样式且标明动作模式的 approval button；Permanent 页面醒目标注绕过回收站且不是 secure erase。该点击只生成 ApprovalRecord，不复用为 execute。`approve` 成功后，用户仍须在独立步骤调用 `execute --approval-id ...`。
5. 只有 trusted foreground terminal fallback 使用 typed challenge。Broker 从已持久化 immutable full plan digest 和锁定的 selection 重算 `N`、`M`，生成 `APPROVE <mode> <N> <M> <SX1-plan-fingerprint>`；Permanent 使用 `PERMANENT <N> <M> <SX1-plan-fingerprint>`。短 fingerprint 只作对照和注意力提示，ApprovalRecord 始终绑定并验证完整 256-bit digest、精确 item/action IDs 和 counts。粘贴与无障碍输入可以允许，但 Agent/插件不能预填。
6. 常驻 core broker 用进程内 session key sealing record，并写入 core 私有 approval store；executor 按 `approvalId` 回查并同时验证 sealed record、store state、OS peer/workflow session、full plan digest 和一次性 CAS。broker 重启、workflow session 退出或 TTL 到期即失效，不能离线复制审批文件。`approvalId` 泄露本身不足以执行，审批也不改变硬保护或复验要求。

原生 modal 可选增加不提权的用户重新验证：Windows 使用 [UserConsentVerifier.RequestVerificationAsync](https://learn.microsoft.com/en-us/uwp/api/windows.security.credentials.ui.userconsentverifier.requestverificationasync)，desktop window 通过 [IUserConsentVerifierInterop::RequestVerificationForWindowAsync](https://learn.microsoft.com/en-us/windows/win32/api/userconsentverifierinterop/nf-userconsentverifierinterop-iuserconsentverifierinterop-requestverificationforwindowasync) 关联 owner，并可使用已配置的 [Windows Hello](https://learn.microsoft.com/en-us/windows/apps/develop/security/windows-hello)；macOS 使用 [LocalAuthentication](https://developer.apple.com/documentation/localauthentication) 的 [`LAContext.evaluatePolicy`](https://developer.apple.com/documentation/localauthentication/lacontext/evaluatepolicy(_:localizedreason:reply:))。普通成功只表示 OS 当时接受验证，不会提权，也不会天然签名或绑定任意 plan digest；回调后 Broker 必须回到同一 pending request，重新核对完整 digest、selection、`N`/`M`、mode、TTL 和 surface session。

确认本身不得调用 Windows [UAC](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/user-account-control/how-it-works) 或 macOS [Authorization Services](https://developer.apple.com/documentation/security/authorization-services)。Linux 没有统一等价 reauthentication API；有图形会话时仍用 first-party native dialog，否则用 trusted foreground TTY，不为了确认调用 `sudo` 或 [polkit](https://polkit.pages.freedesktop.org/polkit/polkit.8.html)。未来只有受用户在场策略保护的应用密钥对 canonical challenge 签名，且密钥生命周期、恢复和跨版本 gate 合格时，才可声称密码学绑定；可评估 Windows Hello protected-key signing 与 macOS [Face ID/Touch ID 保护的 Keychain item](https://developer.apple.com/documentation/localauthentication/accessing-keychain-items-with-face-id-or-touch-id)。

这防止产品接口内的 JSON、Agent 和插件伪造 HumanApproval；它不声称能抵抗已完全控制同一桌面会话/内核的恶意程序。

第二个封闭 variant 是 `ExplicitDangerousDelete(DangerousDeleteRecord)`。它由 CLI 的字面量 `--dangerously-delete` 请求 Core admission 创建，只接受已有 Permanent R4 plan，并绑定与 HumanApproval 相同的 exact plan/action/risk/digest/user/host/session/TTL/nonce，但 `source=ExplicitDangerousDelete`，不含 approval surface 或 confirmation evidence。其既有语义不变：跳过 native modal、可选 OS reauthentication 和 terminal challenge。CLI 无法可靠证明调用者是人，因此该 variant 不是 human approval，并明确支持非交互；Agent Skill 必须拒绝调用。两种 variant 汇入同一 `ExecutionAuthorization` 类型，并在任何 ACTION_INTENT 前原子 single-use claim。

`PreflightPermit` 是最长 2 秒、内存内、one-shot 的 sealed capability，绑定 plan/item/action、authorization variant+ID、mode/risk、policy/anchor digest、最终 parent/object/domain/mount identity、held parent/object handle、revalidation digest 和 nonce。adapter 调用一次后无论结果如何均消费；不能持久化、打印、传给插件或跨 action 复用。

因此类型边界恒为 `Candidate != DeletionPlan != ExecutionAuthorization != PreflightPermit`；任何 UI boolean、插件字段或 `deletable=true` 都不能折叠这些阶段。

## 4. CLI 契约

### 4.1 命令树

```text
sweepx [global-options] <command>

  scan <ROOT>...                  live、只读扫描并检测候选
  explain --scan-id ID --candidate-id ID...
  plan create --scan-id ID --candidate-id ID... [--mode trash|permanent]
  plan show --plan-id ID
  approve --plan-id ID              仅可信本地交互；不可自动化
  execute --plan-id ID (--approval-id ID | --dangerously-delete)
  cancel --operation-id ID
  recover --batch-id ID [--reconcile-only | --resume-pending]
  status [--operation-id ID | --scan-id ID | --plan-id ID | --batch-id ID] [--watch]
  capabilities [--cleaner ID] [--platform]
  tui [--scan-id ID | --plan-id ID | --batch-id ID]
  cleaner list
  cleaner show ID[@VERSION]
  cleaner verify <PACKAGE>
  cleaner install <PACKAGE>      仅安装，不授予能力或执行清理
  cleaner remove ID[@VERSION]
  trust list
  trust import <SIGNED-KEY-BUNDLE>
  trust revoke <KEY-ID>
  audit show --batch-id ID
  audit verify [--batch-id ID]
  audit export --batch-id ID --output FILE
```

主协议命令名固定为 `scan`、`explain`、`plan create/show`、`approve`、`execute`、`cancel`、`recover`、`status`、`cache status`、`capabilities`。脚本不得依赖本地化 human 文本；机器调用只依赖 schema、枚举和退出码。

### 4.2 全局和关键 flags

| Flag | 语义与约束 |
|---|---|
| `--format human\|json\|ndjson` | 默认 `human`；JSON 只输出一个终态 envelope；NDJSON 只输出 durable event envelope。Linux 已有 bounded SQLite journal、单事务完整流/terminal snapshot 与 journal-first status，并以 degraded 形式公开 `sweepx --format ndjson status --operation-id ID --watch [--after SXCUR1]` 的 completed-stream replay：先做一次同 snapshot 全量校验，随后按每页最多 1024 条事件续读；unknown 但语法有效的 cursor 返回单独的 `stream.reset_required`，malformed cursor/usage 返回 usage error。由于事件仍在 scan 后批量构造，该 surface 是 non-live 的 completed replay，不等待新事件、不创建后台 operation，也不支持 cancel，且尚未 runtime-qualified；因此 `scan --format ndjson` 仍在 admission 前返回 unsupported。机器格式 stdout 不混入日志，诊断走 stderr。 |
| `--output FILE` | 非交互命令可把选定格式写入新文件；默认 stdout。以当前用户私有权限写同目录临时文件并 no-replace 原子发布，拒绝 symlink、已存在路径和 `approve`；输出失败不重放已执行 action，结果从 audit/status 恢复。 |
| `--locale zh-CN\|en-US` | 只影响 human 文案，不影响 enum/digest。 |
| `--no-color`、`--quiet` | 只影响显示；不得隐藏终态 error/unknown/partial。 |
| `--request-id UUID` | 客户端关联 ID，不参与授权；重复 ID 不使动作幂等。 |
| `--state-dir PATH` | 只能选择当前用户私有、非 symlink/reparse 的 SweepX 状态目录；不能指向 scan target、root、Trash 或共享目录。Linux 在此写 SQLite journal，macOS 保留 legacy operation snapshot。Windows 当前因尚未实现 current-user-private DACL 与逐组件 reparse 检查而完全拒绝 durable state。执行时改变 state-dir 会使 plan/authorization 不可用。 |
| `scan --no-state` | 显式关闭只读扫描的 operation snapshot/event journal 写入，适合不需要后续 status/operation state 或 state filesystem 不支持 journal 的扫描；不能与 `--state-dir` 组合，且命令结束后不能用 `status` 恢复该 operation。 |
| `--after CURSOR` | 仅用于 Linux 的 `status --watch --format ndjson` completed-stream replay，从 durable event cursor 续读，不重跑扫描或动作。cursor 必须是语法正确的 opaque `SXCUR1...` token；unknown 但语法有效的 cursor 不报 usage，而是返回单独的 `stream.reset_required`。malformed cursor/usage 仍是 usage error。macOS 和 Windows 当前不支持该 surface。 |

flags 使用严格 typed parser：UUID、duration、byte-size 和 enum 解析失败即 exit 2，不做宽松转换。以上 flags 默认适用于所有非 `approve` 命令，例外已在表内列明；`--after` 只允许 Linux 的 `status --watch --format ndjson` completed replay。`--output` 与 interactive `approve` 冲突，`--quiet` 不得与 HumanApproval 合并以隐藏 exact plan 或 ApprovalSurface，`--detach` 只用于产生持久 operation ID 的 scan（未来若 execute 支持也必须复用同一 cancel/status 契约）。任何不适用或冲突组合在 admission 前返回结构化 `USAGE`，不会部分执行。

`scan` 的关键 flags：

- `--cleaner ID[@VERSION]` 可重复；省略表示启用所有兼容、已信任且能力获准的规则。
- `--strict-z0` 禁止启动任何生态/浏览器 CLI，是默认值；`--allow-guarded-query <official-command-id>` 只能逐 descriptor opt-in Z1，不能写 `all`。
- `--memory-budget 64MiB..128MiB` 只能收紧默认 `B_scan=128 MiB`；不得通过 CLI 超过已发布 profile。
- `--max-depth N`、`--deadline DURATION`、`--exclude-native-file FILE` 只缩小覆盖；结果必须显示 incomplete/边界，不能假装未命中为 0。排除文件是无损 native path list，不支持 shell glob。
- `--cache off\|preview` 控制 stale preview/派生加速；无“trust cache”模式。
- `--detach` 在持久化 operation/stream ID 后返回；用 `status --operation-id ID --watch --after CURSOR` 继续消费。

`explain` 只接受 scan/candidate ID，不接受任意 path。`plan create` 只接受同一本机、未过期、本次 live scan 的 candidate ID；`--mode` 默认 `trash`。选择 `permanent` 只创建 R4 计划，不是批准。`plan show` 必须显示 canonical digest、完整 action count、mode、风险、unknown、coverage、恢复预期和 expiry。

`cache status` 是独立的只读 preview-cache 诊断命令。它输出 `cache.status.result`，只支持 `human`/`json`；`--format ndjson` 在创建或读取任何 state/cache 路径之前即以 `USAGE` 失败。Linux 与 macOS 支持该命令，Windows 返回 `UNSUPPORTED`。若默认或显式 `state_dir` 下的 preview cache 缺失，命令返回 `disposition=absent`、exit 0，且不得创建 `state_dir`、`preview-cache/`、`current.json` 或任何 generation/quarantine 目录。检查范围严格限制为 `preview-cache/current.json`、pointer 指向的 current generation 文件、以及平铺的 `generations/` 与 `quarantine/` 目录：它只报告存在性、数量、近似字节数、current/schema 健康和 typed warning/error，不执行 scan、repair、quarantine、rebuild，也不暴露缓存条目、display path、预览内容或 live filesystem 事实。`available` 只表示受限缓存结构与校验在当前读取范围内可读；任意 warning、error 或 quarantine presence 都使 disposition 变为 `degraded` 且 exit 4。

`execute` 不能接受 mode、path、candidate、额外 item、retry 或 policy override；这些全部已绑定在 plan。`--approval-id` 产生 `HumanApproval` authorization。唯一例外 `--dangerously-delete` 产生独立的 `ExplicitDangerousDelete` authorization：它只接受已有、未过期的 Permanent R4 plan，允许非交互 CLI 使用，并由 Core 生成绑定精确 plan/mode/items/actions/risk/digests/user/host/session 的 sealed single-use `DangerousDeleteRecord`，在同一 admission 原子 claim，随后仍执行全部复验/intent/permit/audit。CLI 不声称能识别调用者是不是人或 Agent。它与 `--approval-id` 互斥，不能改 mode 或目标。`recover --resume-pending` 只可继续从未 reserve nonce 的 PENDING action，仍须 authorization 有效并重新完整 preflight；RESERVED、STALE、INDETERMINATE 一律先 reconcile，不能自动重发。

`cancel --operation-id ID` 是幂等控制请求，只允许同一 OS user/workflow session 或 core 授权的本地操作者调用。结果为 `accepted`、`already_requested`、`already_terminal` 或 `too_late_platform_submitted`：每次请求写 `operation.cancel.requested`；首次接纳写 `operation.cancel.accepted`，重复请求写 `operation.cancel.already_requested`，已有终态写 `operation.cancel.already_terminal` 并引用原 terminal sequence，已有平台提交写 `operation.cancel.too_late`。重复请求不重启、不重试动作。扫描在目标 250 ms 内停止新 root/目录 admission，协作 worker 在检查点退出，无法取消的调用留在原有有界 quarantine slot。执行只阻止下一 action。仅有 durable `ACTION_INTENT` 但能由 nonce/adapter fence 证明尚未提交时，写 durable `CANCELLED_BEFORE_ACTION`/source-unchanged outcome；平台 submission 不能被排除或观察矛盾时才必须 reconcile。`accepted` 不等于已经到达 terminal `CANCELLED`，调用者必须继续读取 `status`/event stream。

### 4.3 确认与危险参数

- `approve` 是常规 HumanApproval 入口。Broker 优先打开 first-party native local modal；只有无合格图形会话时才回退到 trusted foreground terminal typed challenge。没有 `--yes`、`-y`、`--force`、`--assume-yes`、`--non-interactive-approve`、stdin/pipe confirmation、RPC approval body、environment/config approval 或持久“总是允许”；`--format json|ndjson`、`--output` 和 stdout 重定向也被拒绝。成功后只向调用者返回 opaque `approvalId`，不执行计划。在没有合格 local modal 或 trusted foreground TTY 的脚本/Agent 中调用返回 exit 6 和 `APPROVAL_INTERACTIVE_HUMAN_REQUIRED`。
- `--dangerously-delete` 是 HumanApproval 之外的显式危险授权，而不是 safety bypass：它只在 `execute` 接受一个已存在的 Permanent R4 plan，保持既有语义并跳过 native modal、可选 OS reauthentication 和 terminal challenge，随后生成独立 `DangerousDeleteRecord`。允许 stdin 关闭、输出重定向和 machine format，以满足非交互用途；这些条件不证明或否定人类身份。Trash plan、过期/stale plan、缺失精确风险/manifest/digest 或与 `--approval-id` 并用均 exit 6/2，且不得产生 action intent。Agent Skill 必须拒绝调用此 flag，但 Core 不依赖该策略识别 Agent。
- shell 展开的 glob 只可能成为多个显式 scan root；planner/executor 拒绝 `*`、`?`、空/相对/malformed basename、`..`、device namespace 和未扫描 path。没有 `--follow-links`、`--cross-mount`、`--delete-any-path`、`--ignore-protection` 或 `--trash-fallback-permanent`。
- `--mode permanent` 只存在于 `plan create`，不能在 approve/execute 时切换；`--dangerously-delete` 只授权执行已有 Permanent plan。Trash 失败后必须重新 live scan、创建新的 Permanent plan，再选择独立 ApprovalSurface 或显式危险 flag。
- `--resume-pending` 不代表 retry uncertain action。`--reconcile-only` 不执行新的 destructive action。
- `cleaner install/trust import/revoke` 是产品配置变更，不是清理授权；安装或信任插件会使引用旧 cleaner-set digest 的计划 stale。
- root、保护 marker、mount、unknown identity/type/reparse、提权 runtime 和 audit 不可写是 sealed hard block，任何危险参数都无效。

### 4.4 稳定退出码

| Code | 名称 | 精确含义 |
|---:|---|---|
| 0 | `OK` | 请求完成；字段仍可合法为 `unknown`，但请求的 coverage/动作终态完整。 |
| 2 | `USAGE` | CLI 参数、schema 或组合非法；未开始目标操作。 |
| 3 | `UNSUPPORTED` | 请求的平台、layout、adapter 或能力不支持；未执行 destructive action。 |
| 4 | `PARTIAL` | 有可用结果但 scope incomplete/存在明确 skipped、error 或 detail loss；对于已形成的 destructive batch，只要至少一个 action 明确 fail/skip 且无 ambiguous/indeterminate 即为 PARTIAL，包括全失败、全 skip 或成功与失败混合。字段级 unknown 本身不自动触发 4。 |
| 5 | `SAFETY_BLOCKED` | core hard protection、普通用户检查、风险或 preflight 阻断。 |
| 6 | `AUTHORIZATION_REQUIRED` | 缺少、拒绝、过期、已消费或不匹配的授权；或 danger flag 用于非 Permanent plan。 |
| 7 | `STALE_REPLAN_REQUIRED` | identity/type/mount/link/descendant/evidence/policy/cleaner 改变，必须重扫或重建计划。 |
| 8 | `OPERATION_FAILED` | 明确失败且无需 reconcile 的一般操作错误。 |
| 9 | `NEEDS_RECONCILIATION` | 已提交动作结果不确定、崩溃留下 RESERVED intent，或 source/destination 矛盾。 |
| 10 | `CANCELLED` | 请求被取消；若有已提交动作不确定则改用 9。 |
| 11 | `STATE_INTEGRITY_UNAVAILABLE` | audit/approval/plan store 不可 durable、损坏或 fence 无法建立；破坏性动作不得开始。 |
| 12 | `PLUGIN_TRUST_OR_COMPAT` | Cleaner 签名、撤销、schema、core/platform/probe ABI 或 capability 不兼容。 |
| 13 | `OFFICIAL_COMMAND_FAILED` | 经允许的官方查询/动作 adapter 明确失败或违反 no-write/output/timeout 契约；若仍有部分结果则可由命令返回 4，并在 item error 中保留此分类。 |

单命令出现多类终态时按以下优先级选唯一 process code：`11 > 9 > 10 > 7 > 5 > 6 > 12 > 13 > 8 > 3 > 4 > 0`。详细逐项状态永远在结构化结果中，不能从单一退出码反推每项成功。`capabilities` 正常报告某项 unsupported 返回 0；只有用户请求执行该 unsupported 能力才返回 3。

## 5. JSON、NDJSON 与恢复契约

### 5.1 单结果 JSON

所有 `--format json` 响应使用 `sweepx.output/v1`：

```json
{
  "schema": "sweepx.output/v1",
  "kind": "scan.result",
  "requestId": "...",
  "operationId": "...",
  "generatedAt": "2026-08-26T00:00:00Z",
  "status": "ok",
  "exitCode": 0,
  "compat": {
    "coreVersion": "1.0.0",
    "scannerSemanticsVersion": 1,
    "safetyPolicyVersion": 1,
    "platformAdapter": { "id": "linux", "version": "1.0.0" },
    "cleanerSetDigest": "sha256:...",
    "requiredFeatures": [],
    "extensions": []
  },
  "summary": { "coverage": {}, "counts": {}, "riskCounts": {} },
  "data": {},
  "errors": [],
  "warnings": []
}
```

`kind` 的 v1 值为 `scan.result`、`explanation.result`、`plan.result`、`execution.result`、`recovery.result`、`cancel.result`、`status.result`、`capabilities.result`、`cleaner.result`、`audit.result`、`cache.status.result`。`approval.result` 仅是 Broker 在可信前台已取得人类输入后返回 opaque `approvalId` 的内部 typed response，不属于 `approve` 的 JSON/NDJSON CLI 模式；CLI `approve` 始终只接受和输出 human mode。`status` 为 `ok|partial|blocked|authorization_required|stale|failed|needs_reconciliation|cancelled|unsupported`。

`cache.status.result` 也是当前已发布的单结果 kind。其 `data` 固定包含：`command=cache.status`、`disposition=absent|available|degraded|unsupported`、`exists`、`currentGeneration`、`generationCount`、`quarantineCount`、`approxBytes`、`approxBytesComplete`、`storedSchema`、`currentHealth=available|missing|unknown|error`、`schemaHealth=available|missing|unknown|error`、以及 typed `warnings[]` / `errors[]`。`unsupported` 同时承载平台不支持、格式/路径 usage error 或 inspection integrity error 的失败关闭预检；此时顶层 `errors[]` 给出稳定错误码。`disposition=absent` 与 exit 0 只表示 preview cache 缺失且未被创建；`available` 只表示受限缓存结构与校验可读，不代表任何 live/current 文件事实；只要存在 warning、error 或 quarantine presence，就必须返回 `partial` / exit 4。

当前发布 schema 还固定 `status.result.data` 与 `cancel.result.data` 的完整字段集。status data 是公开 operation snapshot view；cancel data 包含 `operationId`、disposition、恒为 false 的 `canCancel` 和 nullable operation。`not_found` / `unsupported` 要求 operation 为 null，`already_terminal` 要求完整 operation view；未知 data 字段拒绝。

错误合同：

```text
Error {
  code, class, messageKey, params, phase, retryable,
  itemId?, actionId?, candidateId?, displayPath?,
  nativeDomain?, nativeCode?, observedAt,
  recovery: { disposition, nextCommand?, requiresHuman? }
}
```

`messageKey`/enum 是稳定机器字段；本地化 `message` 可附加但不稳定。未知新增字段必须忽略；未知 major schema 必须拒绝。未知 enum 不能映射为成功，应作为 unsupported/unknown 保留。JSON 输出不可直接回灌 `execute`；execute 只解析内部 plan ID，以及互斥的两种 authorization admission：broker `approvalId` -> `HumanApproval`，或字面量 `--dangerously-delete` -> Permanent-only `ExplicitDangerousDelete`。两者都不能从 JSON artifact 导入或携带任意 target。

`/v1` 表示固定 major、additive-only 的 v1 family，不声称有未编码的 minor number。每个 envelope 的 `compat` 还携带 `requiredFeatures[]` 和 `extensions[]`（reverse-DNS 名称）：消费者必须拒绝不认识的 required feature；可保留并忽略不认识的 optional extension 字段。既有字段不得在 v1 中改类型/语义/requiredness，enum 不删不复用；新增 enum 必须同时携带 `{rawValue, classification=unknown|unsupported}`，身份、scope、risk、protection、action 或 outcome enum 未知时该记录不能参与 plan/成功判定。破坏性变化发布 `/v2`；状态库 migration 不能证明保留 `unknown/lower_bound` 时重建或拒绝，不做隐式降级。

机器输出默认含本机敏感路径，仅写当前用户私有 stdout/file；`audit export` 默认把 `displayPath` 和自由文本 evidence 替换为稳定的 per-export pseudonym，并保留非可逆 identity digest、risk、错误 class/native code 和 coverage。显式 `--include-sensitive-paths` 只可用于 human foreground export，需单独确认且不改变执行记录。trusted local core store 保留无损 native basename/parent recipe供复验；任何脱敏后的 JSON 都标 `redacted=true`，不可导入、不可计划、不可执行。

### 5.2 可恢复 NDJSON

这是当前 Linux-only 的 degraded completed-stream replay 合同，不是 live stream 合同。当前 `scan --format ndjson` 在扫描、root validation 和 state 创建之前返回 unsupported；不得把 scan 完成后批量构造的 event vector 冒充 live stream。Linux 已有 bounded SQLite journal，在单个事务中写入完整 stream 与 terminal snapshot，Core `status` journal-first，并公开 `sweepx --format ndjson status --operation-id ID --watch [--after SXCUR1]`：先做一次同 snapshot 全量校验，再从已完成且已持久化的 stream 中按每页最多 1024 条事件续读。unknown 但语法有效的 cursor 必须先发单独的 `stream.reset_required`；malformed cursor/usage 仍是 usage error。该 replay 不等待新事件、不创建后台 operation，也不支持 cancel，因此仍非 live、非 runtime-qualified。macOS 仍为 legacy snapshot，Windows durable state 仍禁用。

每一行是完整 JSON 对象，使用 `sweepx.event/v1`：

```json
{
  "schema": "sweepx.event/v1",
  "streamId": "...",
  "operationId": "...",
  "sequence": "42",
  "cursor": "opaque-signed-cursor",
  "emittedAt": "2026-08-26T00:00:00Z",
  "monotonicOffsetNs": "123456",
  "type": "scan.progress",
  "phase": "detect",
  "terminal": false,
  "payload": {},
  "checkpoint": { "durable": true, "lastDurableSequence": "42" }
}
```

每条 event 的 `payload.compat` 或 `operation.started.payload.compat` 必须携带与单结果相同的 `requiredFeatures[]`、`extensions[]` 和版本摘要；后续 event 以该 operation compatibility snapshot 为准。

同一 stream 的 `sequence` 严格递增；交付是 at-least-once，消费者用 `(streamId, sequence)` 去重。`cursor` 绑定 stream、sequence 和 checkpoint digest，客户端不得自行构造。Linux 当前的 `status --operation-id ID --watch --after CURSOR --format ndjson` 从 durable journal 续读已完成且已持久化的 stream，不重启 operation；它先做一次同 snapshot 全量校验，并在单次请求中按每页最多 1024 条事件续读。unknown 但语法有效的 cursor 返回单独的 `stream.reset_required` control event，malformed cursor/usage 仍是 usage error。该 replay 不等待新事件，也不创建后台 operation。terminal event 必须 durable；中间 progress 可合并，但错误、boundary、incomplete reason、intent、outcome 和 terminal 不可丢。

事件保留受配额限制。请求的 cursor 不属于当前 journal generation 时，服务发出独立 delivery-control stream 的 `stream.reset_required`；payload 包含 `requestedCursor`、`availableFromSequence`、`snapshotRef` 和 journal high-water `resumeAfter`。该 control event 不写入 canonical operation stream，也不破坏 `operation.terminal` 必须最后的约束。客户端读取 `status` snapshot 后使用 `resumeAfter` 继续，不能把缺口当作无事件。断线不会取消已 detach operation；前台命令收到 SIGINT 时只请求 cancel，并继续到 terminal/reconciliation 摘要。

### 5.3 v1 精确事件集合

| Event type | 必需 payload / 语义 | 是否可合并 |
|---|---|---|
| `operation.started` | command、request digest、compat、root/item counts | 否 |
| `phase.changed` | `from?`、`to=detect|analyze|plan|authorize|revalidate|execute|reconcile|audit`；`approve` 是 HumanApproval 命令名，不是 phase enum | 否 |
| `scan.root.admitted` | root ID、display path、live root/mount identity、policy digest | 否 |
| `scan.progress` | 下述完整 `ScanProgress` | 是，最多 10 Hz/key |
| `scan.aggregate.revised` | directory ID、revision、四种 size、coverage、provenance | 是；终版否 |
| `scan.boundary.observed` | boundary class、root/directory、native code、coverage effect | 否，详情可 journal 引用 |
| `scan.error.observed` | stable class、operation、retryable、native domain/code、coverage effect | 否，详情可 journal 引用 |
| `scan.root.completed` | root final aggregate、complete、quarantined operations | 否 |
| `candidate.detected` | candidate ID/digest、rule IDs、risk floor；必须 live source | 可按分页引用合并 |
| `analysis.completed` | candidate ID、explanation digest、eligibility/report-only reason | 否 |
| `plan.created` / `plan.rejected` | plan ID/digest/mode/action count/risk 或拒绝原因 | 否 |
| `approval.requested` | full plan digest + diagnostic fingerprint、mode、selected-item/action counts、ApprovalSurface | 否 |
| `approval.granted` / `approval.rejected` / `approval.expired` | opaque `approvalId`（仅 granted）、full plan digest、ApprovalSurface、可选 OS reauthentication 结果分类 | 否 |
| `authorization.explicit_dangerous_delete` | authorization ID、plan digest、Permanent mode、item/action counts、risk/policy/anchor/cleaner digests；不含 nonce | 否 |
| `revalidation.started` | item/action ID、attempt ID | 否 |
| `revalidation.passed` / `revalidation.stale` | revalidation digest 或 stable stale reason | 否 |
| `preflight.ready` | action ID、permit expiry；不含不可序列化 permit、nonce 或 handle | 否 |
| `hard_protection.blocked` | item/action、protection class、policy/anchor digest | 否 |
| `operation.cancel.requested` / `operation.cancel.accepted` / `operation.cancel.already_requested` / `operation.cancel.already_terminal` / `operation.cancel.too_late` | requester、operation state、原 terminal sequence、已提交/quarantine 计数（按 disposition 适用） | 否 |
| `action.intent.durable` | action/attempt/fence epoch、mode、prepared digest；明确 platform call 尚未确认 | 否 |
| `action.platform.completed` | actual operation、platform result/error、aborted/cancelled | 否 |
| `action.skipped` / `action.failed_before_submit` | action、stable reason、source unchanged evidence；没有 platform call | 否 |
| `action.permit.consumed` | action/attempt、adapter acceptance；不泄露 permit | 否 |
| `action.reconciled` / `action.indeterminate` | source/destination postcheck、recovery state | 否 |
| `item.completed` | item ordered action summary、status | 否 |
| `batch.completed` / `batch.partial` / `batch.cancelled` / `batch.needs_reconciliation` | totals、durable audit sequence range | 否 |
| `recovery.started` / `recovery.completed` | batch/fence、reconciled/pending/indeterminate totals | 否 |
| `audit.started` / `audit.batch.committed` / `audit.failed` | batch、durable sequence/digest 或 integrity error | 否 |
| `detail.persistence.failed` | lost counts/classes、affected roots、emergency-record state | 否 |
| `stream.reset_required` | cursor gap 与 snapshot ref | 否 |
| `operation.terminal` | output status、exit code、final snapshot digest | 否，恰好一次 durable |

`ScanProgress` 精确保留 Scanner 合同：`scanId, rootId, volumeOrMountId, aggregateRevision, phase, discovered, queued, inFlight, processed, skippedEntries, skippedSubtrees, errors, boundaries, logicalKnown, allocatedKnown, reclaimableKnown, unknownEntries, queueDepthsAndBytes, activeWorkers, entriesPerSecond, metadataOpsPerSecond, elapsed, completeState`。总 entry 未知时不得提供伪百分比；仅对已封闭且已知总数的局部集合提供 percentage。`operation.terminal` 只在 required audit/terminal snapshot durable 后发出；audit 失败时携带 `STATE_INTEGRITY_UNAVAILABLE`/exit 11，而不是把先前 batch 状态提升为已审计成功。

执行结果 `status` 至少保留：`TRASH_SUCCEEDED_PLATFORM_REPORTED`、`TRASH_SUCCEEDED_LOCATION_REPORTED`、`PERMANENT_DELETE_SUCCEEDED`、`SKIPPED_PROTECTED`、`SKIPPED_RISK_NOT_APPROVED`、`SKIPPED_INCOMPLETE_SUBTREE`、`STALE_PARENT`、`STALE_IDENTITY`、`STALE_TYPE`、`STALE_MOUNT`、`STALE_LINK`、`STALE_DESCENDANTS`、`BLOCKED_UNKNOWN_REPARSE`、`BLOCKED_OUTSIDE_SCAN_ROOT`、`BLOCKED_RUNTIME_PRIVILEGE`、`FAILED_PERMISSION`、`FAILED_READ_ONLY`、`FAILED_SHARING_VIOLATION`、`FAILED_TRASH_UNSUPPORTED`、`FAILED_TRASH_NO_SPACE`、`FAILED_NOT_EMPTY_AFTER_APPROVED_CHILDREN`、`FAILED_PLATFORM_ERROR`、`FAILED_CANCELLED_BY_PLATFORM`、`VANISHED_BEFORE_ACTION`、`CANCELLED_BEFORE_ACTION`、`INDETERMINATE_AFTER_CRASH`、`INDETERMINATE_PLATFORM_RESULT`。Missing/not found 不是 success。

## 6. TUI 信息架构与超大树行为

### 6.1 视图和流程

TUI 是 Core API 的可恢复客户端，不持有 Candidate 真相或 permit。主视图如下：

1. **Overview/Status**：volume/root、live/stale 标识、coverage、known/lower-bound/unknown 大小、错误/边界、Scanner queue/backpressure 和插件状态。
2. **Tree/List**：按 root 懒加载虚拟树，也可切换扁平 candidate list。每行同时显示 object class、risk、logical/allocated/reclaimable 口径、confidence、coverage 和 activity/shared 标记。
3. **Filter/Sort**：按 cleaner、artifact class、risk、eligibility、complete、confidence、size state、age-signal（明确为弱信号）、owner、platform、boundary/error、live/stale 过滤；unknown 独立选项，不被 `size=0` 或“最小”吞并。
4. **Explain**：Facts、manager facts、inferences、unknowns、references/activity/activation/official state、recoverability、sharing、阻断项、rule/source 版本和“为何不可计划”。
5. **Plan Review**：只从选中 candidate IDs 请求 core 创建 plan；显示 exact items/actions、目录 manifest 摘要、mode、每 action risk、policy/cleaner digest、expiry、计划前后 diff。任何编辑都创建新 plan。
6. **Approval**：进入独立 ApprovalSurface 并锁定筛选和 selection；优先打开 first-party native modal，展示 exact plan、`N` selected items/`M` underlying actions、风险/unknown/expiry，要求 acknowledgement + destructive approval button。只有可信 foreground TTY fallback 才显示 digest-derived typed challenge。返回后只显示 opaque `approvalId`/TTL。
7. **Execute**：再次展示 plan fingerprint 和审批状态；“开始执行”是独立按钮，不复用 approval keystroke。逐 action 显示 revalidate、intent、platform result、reconcile；取消只在 action 边界生效。
8. **Reconcile/Recovery**：突出 RESERVED intent、source/destination 观察和 `INDETERMINATE`；允许 `reconcile-only`，只对确定从未提交且仍有有效审批的 PENDING action提供“完整复验后继续”。
9. **Audit**：按 monotonic sequence 展示 intent/outcome/hash-chain、native error、requested/actual operation、recovery state；清楚区分平台报告 Trash 与实际释放量。
10. **Cleaners/Capabilities**：manifest、签名发布者、digest、能力授权、兼容/撤销状态、probe/官方命令边界；安装插件不自动启用执行。

导航默认：`Tab/Shift-Tab` 切 pane，方向键或 `j/k` 移动，`Enter` 展开，`/` 搜索，`f` facets，`s` sort，`Space` 仅选择候选，`e` explain，`p` 打开 plan review，`a` 打开 trusted approval，`x` 仅打开 execute review（不直接执行），`r` refresh/reconcile，`Esc` 返回，`q` 离开。任何单键都不能完成审批或 destructive action；selection、approval、execute 是三个独立步骤。

### 6.2 有界内存与 backpressure

TUI 不下载整棵树，也不要求 Core 维护可分页的 full-tree index。默认对每个已展开 parent 只保留 exact top-64 heavy children 和一个不可选择、不可计划的 `Others` 聚合行；`Others` 只携带 count、大小口径、coverage/unknown 和当前 revision，绝不伪装成对象、Candidate 或递归总量。面包屑、virtual scroll、server-side filter/sort/top-K 和每页最多 500 行的 cursor 只作用于当前已物化的稀疏视图。

展开目录或请求被 `Others`/LRU 淘汰的细节会触发优先级更高的 targeted live detail enumeration，而不是查询预建全树索引。结果属于新 live revision，并按新 top-K + `Others` 替换当前 parent；浅层枚举只能给 direct-child count 和已观察 lower bound。若用户要选择未物化对象，先完成该 live detail enumeration并取得真实 Candidate ID；若要把目录加入计划，Planner 还必须 targeted live rescan 并生成完整封闭 descendant manifest。collapsed 子树仅保留 ID/revision/summary，TUI 不缓存百万条 action。

TUI 的 tree-dependent budget `B_tui=48 MiB`：

| 结构 | 硬上限 | 满载行为 |
|---|---:|---|
| visible/expanded row arena | 20,000 rows 或 20 MiB | 每 parent 只留 top-64 + `Others`；LRU 驱逐 collapsed、off-screen、未 pinned 行 |
| explanation/detail LRU | 2,000 records 或 10 MiB | 仅保留 ID/digest，重新 live/分页读取 |
| event/error ring | 10,000 events 或 6 MiB | 中间 progress 合并；durable detail 只留 sequence ref |
| filter/top-K/selection refs | 6 MiB | filter 移到 server；selection 只留 content-addressed token/digest |
| reserve/render buffers | 6 MiB | 超限降刷新率，绝不向 Scanner 借无界内存 |

订阅 mailbox 同时按 count/bytes 有界；`scan.progress` 按 root/directory key 合并且最多 10 Hz，terminal/错误/boundary/intent/outcome 不丢。消费者持续不读时 core 保存每 root terminal snapshot并使 TUI 断线；重连用 cursor。TUI 卡住不会阻断 correctness lane，也不会让 Scanner 超过默认 `B_scan=128 MiB`、parent + all helpers private RSS `384 MiB`、progress map 4096 key/16 MiB、ephemeral spill `192 MiB/operation` 与 `256 MiB global`，或 queue count+byte 上限。spill 只在 charged memory 达到高水位且 compact/evict 后仍取不到 permit 时延迟创建，operation 完成后删除。

深度 4096 和单目录百万 entries 时，视图使用面包屑、虚拟滚动和 server-side counts，不递归构建 widget；native path 延迟渲染。过滤结果的“共 N 项”只有 N 已知才显示，其他显示“已发现 N+”。Stale preview 始终带水印，live revision 到达后原位替换；不能让旧行保持选中并静默进入 plan。

server-side query 也不是无限资源的逃生口。每个 cursor 绑定 `(scanId, final-or-visible revision, sparse parent/view digest, filter digest, sort specification)`，排序稳定 tie-break 为 `(value-state bucket, requested key, object identity, candidateId)`；generation/revision 改变、10 分钟 TTL 到期或 filter/sort 改变即返回 `CURSOR_STALE`/`stream.reset_required`，不得跨 snapshot 拼页。每 operation 最多 8 个、进程全局最多 32 个活跃 cursor；每页最多 500 行，每查询 CPU deadline 2 秒。query hot state 从同一 `B_scan` byte permits 取得，绝不增加 `384 MiB` aggregate private-RSS envelope；排序只覆盖当前 sparse rows 或 targeted live enumeration 的有界批次，不建立全树 secondary index。需要外排时计入上述 `192 MiB/operation`、`256 MiB global` ephemeral spill；满时返回 visible `ResourceLimit`/partial，不退化为内存全排序。

大 selection 由 core 存成 content-addressed `selectionSetRef + digest`，TUI 内存只保留 token；全局 selection store 硬上限 `16 MiB`。descendant-manifest store 全局硬上限 `64 MiB`；被 UI/cache 淘汰的细节只有经 targeted live rescan 生成封闭 manifest 后才可进入计划。只可回收未被 live plan/authorization/batch 引用且 TTL 已过的对象；任一 store 达限时返回明确 `ResourceLimit`/拒绝，不静默驱逐 active record、不截断 selection/manifest，也不把 `Others` 当作批量选择。Planner 读取 selection 后仍逐 ID 验证 live Candidate 和 final aggregate，selection digest 进入 plan；audit emergency reserve 独立，不能被 selection、manifest 或 spill 挤占。

query hot state 只能从 `B_scan=128 MiB` 的非保留 permits 借用，预算器永久保护 scanner correctness lane；若 permit 不足，分页/排序或 targeted detail enumeration 立即 backpressure 或返回 `ResourceLimit`，不得拖延 terminal/error journal 或 root close。任何 query profile 都不能突破 `B_scan`/`384 MiB` envelope 或以构建 full-tree index 换取速度。

## 7. Cleaner 包、manifest 与规则 schema

### 7.1 包模型

Cleaner 是内容寻址、签名、不可变包：

```text
cleaner-package/
  cleaner.json                 # sweepx.cleaner-manifest/v1
  rules/*.json                 # sweepx.cleaner-rule/v1
  probes/<platform>/*          # 可选，少量审计过的 native helper
  evidence/*.md                # 说明/来源，不进入授权
  SIGNATURE                    # 覆盖 domain-separated package digest
```

默认第三方包只能含声明式规则；native probe 只允许 SweepX first-party native-probe signing key、仓库 allowlist digest 和发布期沙箱测试三者同时满足。任何 Cleaner 都不能带 install script、shell fragment、动态下载、解释器依赖、post-install hook 或 deletion adapter。

### 7.2 `sweepx.cleaner-manifest/v1`

```json
{
  "schema": "sweepx.cleaner-manifest/v1",
  "id": "org.sweepx.cargo-target",
  "version": "1.2.0",
  "description": "Cargo workspace target build outputs",
  "publisher": { "id": "org.sweepx", "keyId": "..." },
  "packageDigest": "sha256:...",
  "requires": {
    "core": ">=1.0.0 <2.0.0",
    "scannerSemantics": [1],
    "candidateSchema": [1],
    "ruleSchema": [1],
    "nativeProbeAbi": [1]
  },
  "platforms": [{ "os": "linux", "arch": ["x86_64", "aarch64"] }],
  "targetVersions": { "cargo": ">=1.70 <2.0", "unknown": "report_only" },
  "capabilities": {
    "discover": {"required": ["filesystem.metadata.read.scoped", "config.read.scoped"], "optional": ["process.observe"]},
    "semanticQuery": [],
    "analyze": ["rule.evaluate.pure"],
    "planProposal": ["candidate.propose.filesystemTrash"],
    "officialMutation": [],
    "postActionVerification": ["filesystem.identity.read.scoped"]
  },
  "roots": [],
  "configDecoders": [{
    "id": "cargo-workspace-config-v1",
    "schema": "sweepx.config-decoder/v1",
    "formats": ["cargo-toml", "cargo-lock"],
    "allowlistedRelativeNames": ["Cargo.toml", "Cargo.lock", ".cargo/config", ".cargo/config.toml"],
    "singleFileBytes": 4194304,
    "totalBytes": 16777216,
    "network": "deny",
    "includes": "deny",
    "credentials": "deny",
    "outputSchema": "cargo.workspace-evidence/v1"
  }],
  "rules": [{ "id": "cargo-target-v1", "path": "rules/cargo-target.json", "sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" }],
  "probes": [],
  "officialCommands": [],
  "riskFloor": "R1",
  "supportedActions": ["report", "filesystemTrash"],
  "references": [],
  "expiresAt": "2027-08-26T00:00:00Z"
}
```

root resolver 只能使用 core 提供的 typed source：known-folder、显式 scan root、已扫描配置字段、固定相对组件或经过 live 验证的 manager output。不能展开任意 env、home shortcut、shell substitution、glob 或未经 admission 的绝对路径。环境覆盖只能作为候选证据，最终仍由 Scanner 独立 admission。

manifest 还必须声明每个 config decoder 的 allowlisted filename/format、单文件与总 byte cap、是否可能读取凭据；例如 Cargo decoder 只允许 `Cargo.toml`、`Cargo.lock`、`.cargo/config`、`.cargo/config.toml`，单文件 4 MiB、总计 16 MiB，禁止 include/network/credential expansion。`description`、完整 tool/browser `targetVersions`、unknown-version disposition 以及下面的 probe/command descriptor 都是必填或显式空值；省略 capability 一律视为 deny。

能力按 `discover`、`semanticQuery`、纯 `analyze`、`planProposal`、`officialMutation`、`postActionVerification` 六个阶段分别取 manifest、平台、host policy 与用户授权交集；阶段之间不可继承，空数组就是拒绝。`planProposal` 只允许提出 shared Candidate/action kind，不是 Planner、Approval 或 permit 能力；普通第三方 manifest 的 `officialMutation` 必须为空。

上例为 Linux 变体的完整 manifest envelope；Windows/macOS 要么在同一 manifest 的 `platforms` 中给出各自已测试 root/capability 条目，要么发布同 ID 不同 platform payload，不能从 Linux 路径推断。实际 rule object 见第 10 节，且其 ID/path/digest 必须与 `rules[]` 完全对应；这里的示例 digest 仅是格式占位。rule `sha256` 对解析时已拒绝 duplicate key 的原始 file bytes 计算，包发布器不得在验签后重写 JSON。

### 7.3 `sweepx.cleaner-rule/v1`

```text
CleanerRule {
  schema, id, artifactClass, platforms, rootRef,
  discovery: { effectClass, capabilities[], nativeProbeId?, semanticReadOnly,
               zeroWriteVerified, unknownVersionBehavior },
  selectors: [exact basename / anchored relative components / typed metadata],
  requiredEvidence[], optionalEvidence[], exclusionEvidence[],
  grouping: object | directory | manager-scope | storage-key,
  analysis: { fact predicates, inference predicates, unknownPolicy },
  risk: { floor, monotonicRaises[] },
  proposal: { disposition, supportedAction, targetGranularity },
  recoveryRequirements[], activityBlockers[], sharingRules[],
  explanationKeys[], references[]
}
```

规则 VM 支持布尔/集合/版本比较和 tagged-value predicate，不支持脚本、循环、I/O、正则回溯、动态路径拼接或任意命令。规则只能维持/提高 core risk，不能把 unknown 变 known、降低内置 risk、覆盖 protection 或声明 `safeToDelete=true`。`unknownPolicy` 只能是 `raise_risk`、`report_only`、`block`。规则建议与 core policy 冲突时 core 胜出。

predicate 不是自由表达式字符串。v1 使用有界 typed AST：`{"op":"and|or|not|eq|in|exists|state_is|version_in|is_descendant_of|set_intersects","args":[...]}`；leaf 只能是 `{"field":<schema-known field>}` 或 typed literal，禁止脚本、函数调用、正则、算术、路径拼接和隐式类型转换。`monotonicRaises[].when` 使用同一 AST，`to` 只能比 floor 更高或 `BLOCKED`。加载器拒绝 unknown op/field/type、深度超过 32、节点超过 1024；求值缺字段得到 `unknown` 并交给 `unknownPolicy`，不得按 false 处理。包内与第 10 节示例都必须保存 typed AST；manifest `rules[].sha256` 按规则文件原始 bytes 计算。

`disposition` 的稳定枚举为 `report_only | eligible_with_confirmation | low_risk_candidate | manager_gc_candidate`；它只是建议，core 可升风险或拒绝。每次规则求值输出 `sweepx.cleaner-evidence/v1`，至少含：`owner`、`canonicalPath`/`pathSource`、filesystem identity、coverage scope、`artifactClass`/`objectId`/object version/manager version、`actionGranularity`、logical 与 exclusive-reclaimable tagged bytes、references、activity signals、activation/official state、running blockers、sharing、recoverability、credential/network requirements、compatibility、confidence、risk、supported action、facts（source URL/version/access date）、inferences（引用 fact IDs）、recommendations 和 uncertainties。不存在的证据必须输出 tagged `unknown/not_checked/unsupported`；不得省略后当 false。任何规则结果仍映射回共享 `Candidate`/`Explanation`，没有 plugin-only deletable model。

动作 enum 只使用 `report | filesystemTrash | managerPermanentRecommendation`，manifest `supportedActions`、capability 名、rule proposal 和 Candidate 中必须逐字一致；不存在 kebab/camel alias。`managerPermanentRecommendation` 只显示外部建议，不是执行能力。

### 7.4 少量 native probe

manifest 中的 descriptor 是可 canonicalize 的 typed object，不是自由文本：

```text
NativeProbeDescriptor {
  schema=sweepx.native-probe/v1, id, abiVersion,
  artifacts[{os, arch, minOs?, maxTestedOs?, packageRelativePath, sha256}],
  inputSchema, outputSchema,
  capabilities[], sandboxProfile, network=deny, filesystemReadScopes[],
  cpuMillis, rssBytes, handleCount, timeoutMillis, stdoutBytes, stderrBytes
}

OfficialCommandDescriptor {
  schema=sweepx.official-command/v1, id, effectClass: Z1 | Z2 | M, vendor,
  semanticReadOnly, zeroWriteVerified,
  executable{absolutePathSource, ownerPolicy, identityPolicy, versionRange},
  argvTemplate[{literal}|{typedPlaceholder, validation}], cwdSource,
  environmentAllowlist, strippedEnvironment, stdin=closed, tty=false,
  networkPolicy, noUpdateFlags[], noDaemonFlags[], lockOrOfflineFlags[],
  writeMonitor{allowedDisposableScopes[], failOnOtherWrite=true},
  timeoutMillis, processTreeGraceMillis, stdoutBytes, stderrBytes,
  output{schema, parserId, parserVersion}, exitMap, transientRetryPolicy
}
```

第三方包不得声明 `effectClass=M`，也不得把 Z2 变成自动 discovery；first-party M action adapter 与普通 Cleaner package 分发、签名和 capability 域分离。下面是完整 Z1 descriptor 示例，仅定义接口，本节点不执行：

```json
{
  "schema": "sweepx.official-command/v1",
  "id": "cargo-metadata-locked",
  "effectClass": "Z1",
  "vendor": "The Rust Project",
  "semanticReadOnly": true,
  "zeroWriteVerified": false,
  "executable": {"absolutePathSource": {"kind": "trustedToolchainInventory", "toolId": "cargo"}, "ownerPolicy": {"allowed": ["currentUser", "rootOwnedNotGroupOrWorldWritable"], "rejectUnknown": true}, "identityPolicy": {"kind": "platformSigner", "publisherIds": ["rust-project-release-key"], "fallback": {"kind": "packageManagerReceiptDigest", "algorithm": "sha256"}}, "versionRange": ">=1.70 <2.0"},
  "argvTemplate": [{"literal": "metadata"}, {"literal": "--format-version"}, {"literal": "1"}, {"literal": "--no-deps"}, {"literal": "--locked"}, {"literal": "--offline"}, {"literal": "--manifest-path"}, {"typedPlaceholder": "admittedCargoManifest", "validation": "existing regular Cargo.toml under admitted root"}],
  "cwdSource": "admitted-workspace-root",
  "environmentAllowlist": ["PATH_FIXED_BY_EXECUTABLE_RESOLUTION", "LANG=C", "CARGO_HOME=disposable", "CARGO_TARGET_DIR=disposable"],
  "strippedEnvironment": ["proxy", "credentials", "dynamic-loader", "shell-init"],
  "stdin": "closed",
  "tty": false,
  "networkPolicy": "deny",
  "noUpdateFlags": ["--locked"],
  "noDaemonFlags": [],
  "lockOrOfflineFlags": ["--offline"],
  "writeMonitor": {"allowedDisposableScopes": ["CARGO_HOME", "CARGO_TARGET_DIR"], "failOnOtherWrite": true},
  "timeoutMillis": 10000,
  "processTreeGraceMillis": 500,
  "stdoutBytes": 8388608,
  "stderrBytes": 1048576,
  "output": {"schema": "cargo.metadata-output/v1", "parserId": "cargo-metadata", "parserVersion": 1},
  "exitMap": {"0": "evidence", "other": "official_command_failed"},
  "transientRetryPolicy": {"maxRetries": 0}
}
```

检测到 daemon/network/范围外写或版本不匹配即 evidence unknown/report-only。因为此命令仍可能初始化 disposable 状态，它绝不冒充 Z0。

只有无法由稳定数据规则表达的版本化数据库/OS API（例如浏览器完整 StorageKey 解码、manager 的结构化 inventory）才考虑 native probe。每个 probe：

- 在独立、无网络、无写权限、当前普通用户的 helper 中运行；有 CPU、RSS、handle、stdout 体积和 wall-clock 硬上限。
- 输入是 core 已 admission 的 read-only handle/typed snapshot，不是任意 path；输出是版本化 `Evidence`，不能输出 Candidate、Plan、Approval、permit 或 action argv。
- capability 必须逐项声明，core 与 host policy 取交集；未获能力时输出 `not_checked`，不得降级猜测。
- crash、timeout、malformed output、schema mismatch、unexpected write/network 都隔离为 probe error；Scanner 继续，相关证据 unknown/report-only。helper 失败不能使其他 lane 增 worker 或无界重试。
- probe digest/ABI/decoder version 进入 evidence、candidate 和 plan；升级或撤销使未执行计划 stale。

## 8. 能力、兼容、签名和撤销

能力最小集合为：`filesystem.metadata.read.scoped`、`config.read.scoped`、`process.observe`、`browser-layout.decode:<family>@<range>`、`manager-metadata.decode:<format>@<range>`、`official_command.query:<id>`。`config.read.scoped` 只授权 manifest 声明的 typed config decoder 按 filename/format/byte cap 读取；它不授权读取或分类候选 artifact 内容。默认拒绝 network、任意 artifact 内容读取、写文件、启动 daemon、停止进程、改策略、提权、任意 subprocess 和 deletion。更广内容读取即使未来开放也需单独 capability/隐私审查，且不能触发 cloud hydration。

兼容判定同时满足：

1. schema major 精确支持；同一 v1 family 只允许 manifest 明确的 additive extension 字段并按 unknown-field/`requiredFeatures` 规则处理；
2. core semver range、scanner semantics、Candidate/Plan schema、安全 policy minimum 与 probe ABI 均匹配；Cleaner 不得 pin/降级 core safety policy；
3. OS、arch、filesystem、生态工具/浏览器完整版本落在已测试矩阵；未知未来 browser layout 只能 `unsupported_layout`/report-only；
4. runtime capability 是 manifest 请求、平台能力、管理员 policy 和用户授权的交集；缺 required capability 禁用规则，缺 optional capability产生 unknown；
5. package/probe digest、active cleaner-set digest 和 revocation epoch 纳入 plan。

包摘要/签名算法必须无自引用且逐字节可复现：archive entry name 必须是 NFC UTF-8、只用 `/` 分隔、保留大小写且逐 byte 比较；拒绝 `\`、空组件、`.`/`..`、绝对路径、NFC 后 collision、Windows case-fold collision、directory entry、symlink、hardlink、device、FIFO/socket、archive duplicate entry 和 sparse alias，只接受唯一 normalized relative path 的 regular files。解析 JSON 时先拒绝 duplicate key、非 UTF-8、非有限数和未知 required feature。按 RFC 8785 canonicalize `cleaner.json`，但计算时省略 `packageDigest` 字段。文件表精确定义为 RFC 8785 JSON array，每项固定键 `[{"path":<normalized UTF-8 relative path>,"bytes":<decimal string>,"sha256":<64-char lowercase hex>}, ...]`，按 `path` 的 UTF-8 bytes 升序；排除 `SIGNATURE` 本身。`cleaner.json` 项的 `bytes` 和 `sha256` 均针对上述省略字段后的 RFC 8785 canonical bytes；其他 regular file 则针对原始 bytes。`packageDigest` 编码为 `sha256:<64-char lowercase hex>`，其值是 `SHA-256(UTF-8("SweepX cleaner package v1\0") || RFC8785(fileTable))`，随后回填 manifest。`SIGNATURE` 是 versioned envelope `{schema, algorithm, keyId, publisherId, packageId, packageVersion, packageDigest, manifestSchema, signedAt, expiresAt?, transparencyProof?, signature}`，签名输入为 `UTF-8("SweepX cleaner signature v1\0") || RFC8785(signature envelope without signature)`；Ed25519 `signature` 使用 unpadded base64url。验证时间、key ID、publisher、package ID/version、有效期和 transparency/reference metadata，重新计算 digest 后才验签。签名与摘要都不包含 `SIGNATURE`，因此不存在循环。信任边界：

- 官方 root 只能由 SweepX release 更新；用户导入 publisher key只允许声明式规则，不能自行获得 native-probe 或 action-adapter trust。
- 签名不等于安全，package 仍经 schema、capability、静态路径、资源和行为测试。安装先在私有 staging 验证 size/count/path traversal/symlink/hardlink，再原子发布 content-addressed 目录。
- signed revocation metadata 可按 publisher key、package digest、probe digest、版本范围撤销。命中撤销立即禁用；其 Candidate 仅供解释，plan/authorization 失效。
- revocation metadata 超过 7 天未刷新时，已安装声明式规则最多 report-only；native probe、official command adapter 和新计划禁用。离线不能把 stale trust 当 current。
- trust store 损坏、签名不匹配、同 ID/version 不同 digest、rollback 或 revocation epoch 回退返回 exit 12，并且不能用 `--force` 加载。

## 9. 官方外部命令的严格规则

命令名里有 `list`、`status` 或 `dry-run` 不证明零写入。SweepX 使用四级副作用模型：Z0 只读既有文件/metadata、不启动生态 CLI；Z1 guarded semantic query；Z2 potentially stateful query；M mutation。默认 scan 是 Z0。

Z1 只有同时满足以下条件才可由用户按 `official-command-id` 显式开启（CLI 为 `--allow-guarded-query <official-command-id>`；native probe 由已选 Cleaner 的签名 manifest 与 capability 自动确定，不共用 ID namespace）：

1. manifest 列出官方 vendor、可接受签名/package owner、绝对 executable identity/hash/version range、固定 argv template、允许的 typed placeholder、cwd、环境 allowlist、offline/no-update/no-daemon/locked flags、timeout、stdout/stderr byte limit 和 output schema。
2. core 直接 spawn executable，不经过 shell、`PATH` 重新解析、wrapper、alias、profile 或 plugin；无 stdin/TTY，不继承代理/凭据/动态 loader 环境，locale 固定，cwd 为已 admission scope。argv 不允许通配、命令替换、响应文件或用户自由字符串。
3. 在可丢弃 profile/sandbox 中运行，网络默认拒绝，并监控允许写路径。任何超出声明的写、daemon、下载、prompt、schema 噪声、超时或截断即失败，证据为 unknown；最多按 manifest 的 transient policy 有界重试。
4. 输出只作为 manager evidence，不能绕过 live Scanner、生成 permit或把 manager 的 `unused/reclaimable` 扩大到其定义之外。工具版本、argv digest、exit/native code、输出 digest、观察到的写和覆盖范围全部审计。

Z2 在 automatic scan 中永不运行；只能 report“可另行查询”，不能用于计划资格。M 命令不会被普通 Cleaner 执行。若某官方 manager mutation 未来被 first-party action adapter 支持，必须具备确定的结构化 dry-run、完整对象集和 scope digest；执行前重跑 dry-run并要求逐对象/总 digest 完全匹配，否则 STALE。它进入 `mode=Permanent`、每个 semantic action 为 R4，经同一 human exact-plan approval、ACTION_INTENT、one-shot manager permit、无 shell spawn、outcome/reconcile；无 dry-run或无法确认 exact scope 的命令永远 report-only。它绝不作为 Trash failure fallback。

禁止清单包括：从互联网上下载 executable、执行 project wrapper/plugin（可能下载组件）、用 shell 拼命令、调用 `sudo`、`--force`/绕锁、停止 daemon/browser、改 config/policy、清 volume/reset data、把官方命令失败后改成 raw directory deletion，或把自制目录删除称为 manager dry-run。

## 10. 具体 Cleaner 规则示例

### 10.1 开发者缓存：Cargo workspace `target`

规则 `org.sweepx.cargo-target/cargo-target-v1` 是声明式 `filesystemTrash` 示例：

```json
{
  "schema": "sweepx.cleaner-rule/v1",
  "id": "cargo-target-v1",
  "artifactClass": "regenerable-project-output",
  "platforms": [{"os": "windows", "arch": ["x86_64", "aarch64"]}, {"os": "macos", "arch": ["x86_64", "aarch64"]}, {"os": "linux", "arch": ["x86_64", "aarch64"]}],
  "rootRef": {"kind": "admitted-workspace", "evidence": "cargo.workspace.v1"},
  "discovery": {"effectClass": "Z0", "capabilities": ["filesystem.metadata.read.scoped", "config.read.scoped"], "nativeProbeId": null, "semanticReadOnly": true, "zeroWriteVerified": true, "unknownVersionBehavior": "report_only"},
  "selectors": [{"kind": "typed-relative-path", "field": "cargo.targetDir", "mustBeWithinAdmittedRoot": true}],
  "requiredEvidence": ["cargo.workspace.v1", "cargo.config.target-dir.v1", "scan.final-complete-aggregate.v1", "object.no-boundary.v1", "object.not-shared.v1"],
  "optionalEvidence": ["process.cargo-family.observed.v1", "project.last-build-signal.v1"],
  "exclusionEvidence": ["workspace.shared-target.v1", "artifact.source-or-signing.v1", "object.mount-or-provider.v1", "process.cargo-family.open.v1"],
  "grouping": "directory",
  "analysis": {"factPredicates": [{"op": "eq", "args": [{"field": "cargo.targetDir"}, {"field": "candidate.relativePath"}]}, {"op": "eq", "args": [{"field": "coverage.complete"}, true]}, {"op": "eq", "args": [{"field": "cargo.targetShape"}, "recognized_generated_structure"]}], "inferencePredicates": [{"op": "and", "args": [{"op": "exists", "args": [{"field": "cargo.workspaceId"}]}, {"op": "state_is", "args": [{"field": "exclusiveReclaimableBytes"}, "known"]}]}], "unknownPolicy": "report_only"},
  "risk": {"floor": "R1", "monotonicRaises": [{"when": {"op": "or", "args": [{"op": "eq", "args": [{"field": "objectType"}, "Directory"]}, {"op": "exists", "args": [{"field": "activity.recentSignal"}]}]}, "to": "R2"}, {"when": {"op": "or", "args": [{"op": "eq", "args": [{"field": "sharing.state"}, "shared"]}, {"op": "eq", "args": [{"field": "activity.state"}, "observed_open"]}, {"op": "state_is", "args": [{"field": "cargo.targetShape"}, "unknown"]}]}, "to": "R3"}]},
  "proposal": {"disposition": "eligible_with_confirmation", "supportedAction": "filesystemTrash", "targetGranularity": "closed-directory-manifest"},
  "recoveryRequirements": ["workspace source and lock/config retained", "toolchain available or reacquirable"],
  "activityBlockers": ["observed cargo/rustc/build-script/IDE holder"],
  "sharingRules": ["shared CARGO_TARGET_DIR => report_only"],
  "explanationKeys": ["cargo.rebuild-cost", "cargo.shared-target-warning"],
  "references": ["cargo-clean-official-docs@accessed-2026-08-26"]
}
```

1. Detect 在显式 scan root 中 live 发现 `Cargo.toml`。Scanner 本身仍只读 filesystem metadata；当前实现已新增有界 locator batch reader，可在 Linux/macOS/Windows backend 上沿已 admission locator 进行 handle-relative/handle-bound 的固定文件读取。core 内置、版本化、无副作用的 Cargo config decoder 通过这一路径在 `config.read.scoped` 能力下 Z0 读取已存在的 `Cargo.toml` 与 `.cargo/config*`，并只返回 typed workspace/相对 `target-dir` evidence。该 decoder 不 hash 或分类目标文件、不读取凭据、不扩展任意 include；能力未获准、语法/版本未知或路径不是已 admission scope 时输出 unknown/report-only。不自动运行 `cargo metadata`。默认 `target/` 名称只是线索，不是资格。
2. 当前固定输入收集器已能稳定读取 `Cargo.toml`、`.cargo/config` 与 `.cargo/config.toml`，并对替换、symlink/reparse、mount 变化、资源上限和取消 fail closed。workspace 证据在 manifest 合法且绑定成立时可投影为 `Known`。但 home/env/ancestor/CLI 等全局 override scope 尚未解决，因此 detector 中的 `cargo.targetDir` 仍保持 `NotChecked(config_scope_not_checked)`；依赖它的 `cargo.targetShape` 继续保持 `Unknown(config_scope_not_checked)`，即使同一 workspace 下的 target 目录聚合与名称线索已存在。
3. Analyze 仍要求 target 目录位于已 admission workspace 或明确配置路径、out-of-source/生成物边界可证明、目录扫描完整、无 symlink/reparse/mount/provider 边界。检查活动 `cargo`/`rustc`/build-script/IDE/rust-analyzer 只产生时间点 blocker；“未观察到”不证明无人使用。因为 `targetDir` scope 与 sharing/activity 仍未闭合，当前 `cargo-detect` 输出继续是 hint/report-only：`candidateAllowed=false`、`planAllowed=false`、`approvalAllowed=false`、`executionAllowed=false`。
4. `cargo.targetShape` 只由 metadata-only shape classifier 产生：它检查已扫描相对名称、对象类型与 Cargo 约定的顶层生成结构，绝不打开或识别文件内容；只要出现不在 allowlist 的顶层组件、special/link、不可读项或分类不确定，就是 `unknown` 并 report-only。它不能证明任意文件“不是源码/签名资产”，因此低风险只适用于结构完全落入发布期 allowlist 的封闭目录；多个 workspace/环境共享 `CARGO_TARGET_DIR`、release/package/signing evidence、config 缺失或目标跨 mount 时提升 R2/R3 或 report-only。mtime 只能是弱 activity signal，不能单独证明未使用。
5. Plan 默认是整个已封闭 target directory 的平台 Trash，展示冷启动/重编译成本和 potentially reclaimable；不调用 `cargo clean`，因为 strict Z0 不启动工具。审批后仍完整重验 descendant manifest；新增文件使 STALE。Trash 失败不 `rm -rf`。

另一个 manager-scope 反例是 pnpm store：它是跨项目内容寻址/硬链接共享存储。仅凭 `~/.local/share/pnpm/store` 或年龄不能计划 raw Trash；必须解析有效 store、workspace/lock/`.modules.yaml`、分支和离线/私有源。`pnpm store prune` 没有满足 exact、无副作用 dry-run 合同的版本时只显示 `managerPermanentRecommendation`，不由 v1 Cleaner 执行，reclaimable 保持 unknown。

### 10.2 浏览器：Chromium HTTP/Code Cache 与应用状态分离

规则 `org.sweepx.chromium-rebuildable-cache/chromium-cache-v1`：

其 package manifest 同样使用 `sweepx.cleaner-manifest/v1` 的全部字段：`id=org.sweepx.chromium-rebuildable-cache`、独立 package version/publisher/digest、core/scanner/candidate/rule/probe ABI ranges、Windows/macOS/Linux 的 arch 与 browser full-version/layout tested ranges、required capabilities、`rules=[chromium-cache-v1]`、`probes=[chromium-profile-state-v1 descriptor]`、空 `officialCommands`、`riskFloor=R2`、`supportedActions=[report,filesystemTrash]`、references/expiry；任一缺失或 unknown future layout 都 report-only。下面是其完整 rule object：

```json
{
  "schema": "sweepx.cleaner-rule/v1",
  "id": "chromium-cache-v1",
  "artifactClass": "rebuildable-browser-cache",
  "platforms": [{"os": "windows", "arch": ["x86_64", "aarch64"]}, {"os": "macos", "arch": ["x86_64", "aarch64"]}, {"os": "linux", "arch": ["x86_64", "aarch64"]}],
  "rootRef": {"kind": "probe-verified-profile-cache-root", "evidence": "chromium.profile-state.v1"},
  "discovery": {"effectClass": "Z0", "capabilities": ["filesystem.metadata.read.scoped", "process.observe", "browser-layout.decode:chromium@tested-range"], "nativeProbeId": "chromium-profile-state-v1", "semanticReadOnly": true, "zeroWriteVerified": true, "unknownVersionBehavior": "report_only"},
  "selectors": [{"kind": "exact-relative-components", "values": [["Cache"], ["Code Cache"]]}],
  "requiredEvidence": ["browser.product-version-channel.v1", "browser.profile-and-cache-root.v1", "browser.quiescent.v1", "browser.layout-supported.v1", "scan.final-complete-aggregate.v1"],
  "optionalEvidence": ["browser.cache-backend.v1"],
  "exclusionEvidence": ["browser.running-or-unknown.v1", "browser.application-state.v1", "storage-key.hostname-only.v1", "browser.unsupported-layout.v1"],
  "grouping": "directory",
  "analysis": {"factPredicates": [{"op": "in", "args": [{"field": "candidate.relativeComponents"}, [["Cache"], ["Code Cache"]]]}, {"op": "eq", "args": [{"field": "browser.profileStillness"}, "verified"]}], "inferencePredicates": [{"op": "eq", "args": [{"field": "browser.storageClass"}, "rebuildable_http_or_code_cache"]}], "unknownPolicy": "report_only"},
  "risk": {"floor": "R2", "monotonicRaises": [{"when": {"op": "or", "args": [{"op": "eq", "args": [{"field": "browser.runningState"}, "running"]}, {"op": "state_is", "args": [{"field": "browser.layout"}, "unknown"]}, {"op": "state_is", "args": [{"field": "browser.attribution"}, "unknown"]}]}, "to": "BLOCKED"}]},
  "proposal": {"disposition": "eligible_with_confirmation", "supportedAction": "filesystemTrash", "targetGranularity": "whole-verified-cache-root"},
  "recoveryRequirements": ["browser can regenerate cache", "profile application-state roots excluded"],
  "activityBlockers": ["browser owner process or lock/open-handle uncertainty"],
  "sharingRules": ["bind to exact product/channel/profile; never hostname-only"],
  "explanationKeys": ["browser.cache-rebuild", "browser.may-redownload", "browser.partition-warning"],
  "references": ["chromium-layout-adapter@tested-milestone"]
}
```

其 manifest 中的 probe descriptor 为：

```json
{
  "schema": "sweepx.native-probe/v1",
  "id": "chromium-profile-state-v1",
  "abiVersion": 1,
  "artifacts": [
    {"os": "windows", "arch": "x86_64", "packageRelativePath": "probes/windows-x86_64/chromium-profile-state.exe", "sha256": "1111111111111111111111111111111111111111111111111111111111111111"},
    {"os": "windows", "arch": "aarch64", "packageRelativePath": "probes/windows-aarch64/chromium-profile-state.exe", "sha256": "2222222222222222222222222222222222222222222222222222222222222222"},
    {"os": "macos", "arch": "x86_64", "packageRelativePath": "probes/macos-x86_64/chromium-profile-state", "sha256": "3333333333333333333333333333333333333333333333333333333333333333"},
    {"os": "macos", "arch": "aarch64", "packageRelativePath": "probes/macos-aarch64/chromium-profile-state", "sha256": "4444444444444444444444444444444444444444444444444444444444444444"},
    {"os": "linux", "arch": "x86_64", "packageRelativePath": "probes/linux-x86_64/chromium-profile-state", "sha256": "5555555555555555555555555555555555555555555555555555555555555555"},
    {"os": "linux", "arch": "aarch64", "packageRelativePath": "probes/linux-aarch64/chromium-profile-state", "sha256": "6666666666666666666666666666666666666666666666666666666666666666"}
  ],
  "inputSchema": "chromium.admitted-handles/v1",
  "outputSchema": "chromium.profile-state/v1",
  "capabilities": ["process.observe", "browser-layout.decode:chromium@tested-range"],
  "sandboxProfile": "readonly-handles-no-network-no-child-process",
  "network": "deny",
  "filesystemReadScopes": ["admitted-user-data-handle", "admitted-profile-handle", "admitted-cache-handle"],
  "cpuMillis": 1000,
  "rssBytes": 16777216,
  "handleCount": 64,
  "timeoutMillis": 5000,
  "stdoutBytes": 1048576,
  "stderrBytes": 262144
}
```

其中各示例 digest 只是格式占位，真实发布必须逐 artifact 替换且匹配 package file table。该 first-party、签名且 allowlisted 的窄 probe 输入仅为已 admission 的 User Data/Profile/cache handles 与目标 browser identity；只调用 OS 进程/打开句柄只读观察和版本资源读取，禁止调用浏览器 singleton 协议、创建/删除 lock、打开 LevelDB、迁移 schema、spawn child 或发网络请求；输出 `browser.product-version-channel.v1`、roots、holder coverage 和 `verified|skipped_running_profile|unsupported_layout`。版本、layout 或静止状态无法证明即 report-only。

1. Detect 先绑定 browser brand/channel/full version、真实 User Data/Profile Path 和外置 cache root；默认路径只生成 proposed root，须 live 验证。运行中的 User Data/Profile、锁/holder 不确定、unknown milestone/layout 一律 `skipped_running_profile` 或 `unsupported_layout`。不删锁、不通知/强杀浏览器、不 repair DB。
2. 规则只把该 Profile 的 HTTP `Cache` 和 JS/Wasm `Code Cache` 分类为可重建候选；明确排除 `Service Worker/CacheStorage`、IndexedDB、Local Storage、cookie、history、extension storage、Firefox `storage/` 与 Safari logical profile。这些是应用/用户状态，不因名字含 cache 就进入规则。
3. 不提供“按域名删 HTTP cache”：现代 Chromium cache key 含 Network Isolation Key，站点状态必须保留匹配版本 parser 得到的完整 serialized `StorageKey`（包括 origin、top-level schemeful site、ancestor-chain state、存在时的 nonce/opaque precursor）以及 bucket/实际 StoragePartition identity。`(origin, top-level site, bucket/partition)` 仅用于展示。无法由版本化 adapter 无损解码完整身份时只报告，hostname 命中不能计划。
4. Profile 已静止、版本适配、边界完整且 Trash 可用时，整个明确 cache root 可形成 R2 Trash plan；应用一致性组永不混入。执行前浏览器重新启动、目录 backend 改变或 descendant manifest 变化即 STALE。
5. 若用户选择的是站点应用状态而不是上述可重建 cache，则 Candidate 必须绑定 browser product/full version/channel、Profile/store identity、actual User Data/Profile/cache roots、adapter/source version、observedAt、running state、snapshot method 及完整 StorageKey（origin、top-level/client site、container/private attributes、partition、bucket）。一致性组必须包含相关 SQLite DB/WAL/SHM/journal、LevelDB CURRENT/MANIFEST/log、blob/body、Service Worker registrar/script、salt 和 origin metadata；HTTP/code/startup cache 单列。只在静止 profile 的同时间点、可恢复 snapshot 副本上由版本 adapter 解析；snapshot 只能按其证据称 crash/time-point 或 single-DB consistency，不能夸为应用事务一致。legacy/new bucket/unified layout 按 magic/schema 探测，unknown 返回 `unsupported_layout`。Safari Profile 映射未被版本 adapter 证明时保持 logical/unresolved，拒绝 raw per-profile deletion。

### 10.3 浏览器本地模型：支持路径优先且默认 report-only

Chrome/Edge 基础模型不能靠固定 `OptGuideOnDeviceModel` 名称裸删。规则 live 记录产品/版本/channel、内部页暴露的 path/version/size（若存在）和策略状态；Chrome 与 Edge component ID 不互相假定。持久禁用/删除的受支持路径是目标产品明确支持的 `GenAILocalFoundationalModelSettings=1`；`ComponentUpdatesEnabled=false` 影响大量安全组件，不能作为等价快捷方式。

由于写企业策略会改变系统/组织状态且内部页 Uninstall 非稳定外部 API，v1 Cleaner 只生成 report-only 建议和副作用说明，不改 registry/managed preference、不开内部页、不手删组件目录。若浏览器仍允许模型，结果必须写“可能重新下载”，不能承诺永久释放。

## 11. 完整生命周期

1. **Detect**：解析兼容且已信任的 Cleaner；Scanner 对每个显式 root 做 ordinary-user live admission，metadata-only/no-follow/same-mount 流式枚举。规则/native probe 只补证据。
2. **Analyze**：按工具所有权、规范路径、对象类别、引用、活动、激活状态、官方状态、恢复条件、共享/并发九类证据分类。开发者对象严格区分 A 可重建项目产物、B 共享/内容寻址 store、C 已安装依赖/环境、D SDK/toolchain/global tool、E volume/archive/credential/source/user runtime state；目录名含 cache 不得改变类别。低风险必须有 manager-confirmed scope、无 observed blocker、非共享或 manager-defined GC 语义及明确 rebuild/recovery；文件 age/atime 只是弱信号，negative holder 只表示当时未观察到。没有跨生态查询能证明所有用户、项目、container、VM、CI、remote worker 或 offline media 都无引用。缺项显式 unknown，风险单调不降。
3. **Plan**：只接收 local current live Candidate。Planner 应用硬保护，绑定 identity、封闭目录 manifest、cleaner/policy/adapter digest，生成 immutable Trash（默认）或独立 Permanent R4 plan。
4. **Authorize**：常规 CLI/TUI 在 trusted local surface 展示 exact plan，由 Broker 生成 sealed、短期、single-use、逐 action risk-bound HumanApproval；Agent、插件必须在此暂停，不能代替人输入。独立的 `--dangerously-delete` 分支只适用于已有 Permanent R4 plan，跳过 prompt 并生成 ExplicitDangerousDelete，Agent 不得调用。
5. **Revalidate**：每 action 重新定位 root/祖先/parent/entry，比较 identity/type/mount/link、保护 marker、目录 manifest和 cleaner/官方 dry-run evidence，观察 holder，重算风险。任何变化 stale/block。
6. **Execute**：先 durable `ACTION_INTENT`，再做 final no-follow check并立即签发一次性 permit；adapter 只执行已授权 Trash/Permanent/已审计官方 action。取消阻止下一个尚未提交的平台 action；即使当前 action 已写 intent，只要 fence/nonce 证明 adapter 尚未提交，也可写 `CANCELLED_BEFORE_ACTION`；已提交或是否提交不明则进入 outcome/reconcile。
7. **Audit/Reconcile**：持久化 actual platform operation、native result、source/destination postcheck和 capacity observation。INTENT 无 OUTCOME、平台 aborted/unknown 或 crash 先 reconcile；missing 不猜 success，不自动重发。

Scanner cache、Cleaner evidence cache 和 UI cache从不跨越第 3/5 步的 live gates。审计 hash chain只能检测部分损坏，不宣称对同一用户不可篡改。

## 12. 错误、恢复与可观测语义

- 扫描 AccessDenied/Timeout/ProviderOffline/Unsupported 继续 siblings，祖先 `complete=false`；cache corrupt 被隔离后冷扫，不能用旧 aggregate 填空。correctness journal 失败时停止新 admission、发 `detail.persistence.failed` 并保留计数/类别；详情丢失永远不是 complete。
- Scanner 取消后迟到平台调用进入固定 quarantine slot，结果与已终止 generation 隔离；UI 显示“逻辑已取消，仍有 N 个调用待回收”，不声称线程/资源全部停止。
- Cleaner/probe crash、timeout、签名/compat/capability 失败只禁用该规则或使相关 evidence unknown；不会加载未签名 fallback，不会执行同名系统命令。
- authorization rejected/expired/consumed 不改变 plan；HumanApproval 重新授权必须再次展示 exact plan，ExplicitDangerousDelete 则要求重新显式传入 flag 并产生新 record。plan、policy、anchor、cleaner set、adapter 或 runtime user 变化使任一 authorization 无效。
- ACTION_INTENT 后崩溃的 action 是 RESERVED/ambiguous。`recover` 取得 non-expiring OS batch lock 和更高 fence epoch后先 reconcile；旧 executor 仍持锁时不得接管。只有证明平台调用从未提交的 pending action才可新 attempt，且完整 preflight。
- Trash 的 recovery state 精确区分 `PLATFORM_TRASH_REPORTED`、`TRASH_LOCATION_REPORTED`、`TRASH_SUCCESS_LOCATION_UNKNOWN`、`NOT_SUPPORTED_SOURCE_UNCHANGED`、`FAILED_SOURCE_UNCHANGED`、`INDETERMINATE`。Trash success 不等于空间释放或保证可恢复。
- caller-visible capacity before/after 仅为同平台事后 observation，与 logical/allocated/reclaimable 分列；不作为成败唯一证据。

`status` 和 TUI 必须首先展示处置建议：`retry_read_only`、`rescan`、`replan_and_reapprove`、`reconcile_only`、`manual_external_action` 或 `no_safe_recovery`。不得用模糊“失败，请重试”诱导重复 destructive action。

## 13. 测试与发布门槛

### 13.1 契约与跨界一致性

- 对同一 fixture，CLI human/JSON、TUI 和 Cleaner API 产生完全相同的 Candidate/Explanation/Plan digest、risk、coverage 和 action outcome；任何前端不得重算安全结论。
- `sweepx.output/v1` JSON Schema、`sweepx.event/v1` replay/golden、unknown-field/unknown-enum、u128 string、native-name round-trip、cursor duplicate/gap/reset、终态恰好一次全部通过。
- 状态机 property test 拒绝所有未列转移，尤其 Candidate->Execute、Plan->Execute、authorization 改 mode、permit 复用、Trash->Permanent fallback 和 stale->retry。
- 所有公开 Core API、CLI flag、config/env、TUI shortcut、插件/probe 和 direct adapter fuzz 均不能绕过 ordinary-user、hard protection、no-follow、same-mount、approval、intent 或 permit。

### 13.2 Scanner/TUI 性能与内存

- 使用深度 4096、单目录 1M entries、10M entries、1M hard-link identities、symlink/reparse/mount/provider/permission/race fixture；正确性 oracle 必须 100% 匹配。
- Scanner tree-dependent charged memory不超过 `128 MiB`，parent + all helpers private RSS 不超过已验证 `384 MiB` profile；所有 queue、terminal、pending-directory、quarantine、spill high-water 不越界，spill 同时满足 `192 MiB/operation` 与 `256 MiB global`。slow consumer/cache writer/probe不能饿死本地 root。
- TUI tree-dependent memory不超过 `48 MiB`；百万行 filter/sort/expand、快速滚动、断线重连和 event flood 仍以 top-K + `Others`、targeted live detail 和虚拟化工作，terminal/error/boundary 不丢，不建立/预载 full-tree index。selection store 不超过 `16 MiB`，descendant-manifest store 不超过 `64 MiB`。
- 总数未知不显示百分比；unknown、lower bound、incomplete、stale preview 视觉/JSON snapshot tests 不得渲染为 0、空或 current。

### 13.3 Cleaner 供应链与沙箱

- 测试签名错配、同版本不同 digest、过期/revoked/rollback metadata、离线撤销超期、zip-slip、绝对路径、symlink/hardlink、压缩炸弹、超量文件、重复 key 和 canonicalization 差异。
- 规则 VM fuzz 不得发生 I/O、非确定性或资源无界；unknown policy只能升风险。恶意 rule 生成 root/protected path/force bit 必须被 core拒绝。
- native probe 覆盖 escape、网络/写入、fork bomb、stdout bomb、hang/crash、malformed schema、TOCTOU 和 capability confusion；失败后只降级 unknown/report-only。
- 官方命令测试固定 executable identity、无 shell、argv 注入、环境净化、daemon/download/write/network 检测、timeout/output cap、版本漂移和 dry-run digest变化。任何违规都不得形成 Candidate 或 permit。

### 13.4 授权、执行与平台 gate

- 自动化测试证明 pipe/stdin、后台/非 controlling TTY、RPC/SDK body、插件/Agent 输入、`--yes`、env/config、伪造 JSON、复制 `approvalId`、broker restart、跨 user/host/session、过期/重放 nonce 均不能伪造 HumanApproval。native modal 必须展示 exact plan、`N` items/`M` actions、risk/unknown/expiry，且 acknowledgement + approval button 只批准不执行；TTY challenge 必须从当前 immutable full digest 与 counts 重算，短 fingerprint 永不替代完整 256-bit digest。另测可选 OS reauthentication 的 success/failure/cancel 和异步 plan/TTL change，确保它不提权、不被当作 digest 签名；`--dangerously-delete` 仍只产生 ExplicitDangerousDelete、只接受已有 Permanent R4 plan，跳过确认但不能通过配置/env/别名隐式启用、不能和 approval-id 并用，并且仍受所有硬保护/复验。
- target/parent/ancestor/type/link/mount/descendant/marker 在 scan、approval、final check各窗口替换均失败关闭；目录注入新 child 不被递归带走。
- fault injection 覆盖 intent 前、intent sync 后、platform submit 后、outcome sync 前和 reconcile 中崩溃；missing 不算 success、RESERVED 不自动重发、旧 fence executor不能再调用 adapter。
- Windows 必须验证 IFileOperation 的逐项 sink、aborted、undo/destruction flags；macOS 验证 `trashItem` 不 fallback remove；Linux 验证 GIO unsupported/EXDEV 不 unlink。平台任一 Trash 路径不能证明不会永久销毁，就只发布 scan/plan。
- root/system/home/SweepX/Trash/protected marker、unknown reparse、mount/bind、provider、审计不可写和 elevated runtime 全部 hard-block 测试通过，才可在该平台启用 destructive mode。
- 文案 lint 禁止无条件使用 `exact disk usage`、`will free`、`unused`、`safe to delete`、`guaranteed recoverable`；只能说 observed、potentially reclaimable、platform reported、unknown/incomplete。

发布采用 capability-by-capability allowlist：某 Cleaner、probe、browser/tool 版本或平台组合未通过，就只减少能力并明确 `unsupported/report-only`，不能用推测补齐。任何 safety schema major、policy、approval或 adapter 行为改变都要求重新 threat-model、fixture、golden、fault-injection 和真实 OS gate。

## 14. 最终不变量

```text
live scan fact != cleaner inference != candidate != immutable plan
              != execution authorization != preflight permit != platform outcome

missing evidence -> risk never decreases -> report, skip, or re-plan
missing evidence != 0 != unused != permission to delete
```

CLI、TUI、Cleaner 与 Agent 即使呈现方式不同，也必须共享上述状态机、schema、风险、硬保护和执行器；谁都没有更短的删除路径。本文到此仍只是 v1 设计，**没有授权或执行任何扫描、外部命令、清理、删除、策略修改或本机状态变更**。
