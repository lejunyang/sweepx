# SweepX 安全删除架构

状态：v1 架构设计。研究与设计截点：2026-08-26。除非另有注明，本文引用的所有网络来源均于 **2026-08-26** 访问。

本文定义候选、解释、计划、审批、执行前复验、平台动作和审计之间的安全边界。本文不是实现；本节点和 v1 设计阶段不调用、模拟或执行任何删除。只有某平台通过本文发布门槛后，后续实现才可以在当前普通用户权限下启用 destructive mode。

本文沿用上游研究的证据标签：已证事实表示一手资料直接支持；推导表示由事实得到的限制；产品设计表示 SweepX 的保守选择；待实测表示必须在真实平台验证的假设。启发式、缓存、大小估计和占用观察都不是安全保证。

## 1. 安全合同与非目标

未来执行能力必须满足：

1. 仅以当前普通用户身份运行。不请求 UAC/sudo/polkit，不启用 backup/DAC capability，不接管 ownership，不修改 ACL、TCC、immutable flag、只读属性或系统设置。
2. 默认动作是平台 Trash/Recycle Bin。若在调用前确认不支持、权限不足或空间不足，则不提交且源对象保持不变。平台调用一旦提交，cancelled、aborted 或结果不明必须以事后 reconcile 判定 source/destination；无法证明源未变化时记 INDETERMINATE。任何情形都不得静默降级为永久删除。
3. Permanent 是独立模式、独立不可变计划和独立不可逆授权；Trash 的 HumanApproval 永远不能授权 Permanent，ExplicitDangerousDelete 也只能绑定已有 Permanent plan。
4. 文件路径不是对象身份。审批后、每项动作紧邻平台调用前，必须 no-follow 复验 parent + basename、父身份、对象身份/类型、volume/mount、link/reparse、扫描根 containment 和全部硬保护。
5. 默认不跟随 symlink 或 Windows reparse point，不跨 mount/volume，不递归未知边界。
6. 根、系统/用户保护路径、保护文件、保护 marker、mount point、Trash 内部、SweepX 自身状态不可审批；任何 --force、--yes、--recursive、--permanent、配置、环境变量、glob、插件或直接 core API 调用都不得绕过。
7. 一批动作不具备事务性。必须逐项写前记录、逐项结果、部分成功、取消、失败、stale 和 indeterminate。
8. Trash 只表示平台接受回收请求，不表示空间已释放或必然可恢复；Permanent 只表示绕过用户回收站移除获批目录项，不是 secure erase，也不保证不可恢复。

非目标：

- 不清空回收站，不提供 secure erase/覆写承诺，不自动 kill 进程或关闭句柄。
- 不承诺跨卷批次原子提交、自动回滚、精确释放空间或系统级完整 in-use 视图。
- 不从 imported/remote/stale/cache-only 报告直接产生计划或许可。
- 不提供 ignore-safety、delete-any-path 或 Trash-failed-then-unlink 接口。
- 不把命名、年龄、目录位置、“常见缓存”、negative holder result 或 native cleaner dry-run 描述为 safe to delete。

## 2. 威胁模型与剩余限制

需要失败关闭的场景包括：

- 扫描后目标、basename、父目录或任一祖先被替换/重命名；普通文件与 link/reparse 互换；
- Linux bind/mount namespace、Windows mounted folder、macOS volume/provider 边界变化；
- 审批后向目录注入新后代、隐藏未扫描后代或改变 hard-link topology；
- 缓存、导入报告、UI、插件、环境变量或脚本构造任意路径或篡改操作模式；
- 大小写、Unicode normalization、原始 Unix 字节、Windows long path/device namespace/ADS、别名或尾分隔符使展示路径与实际对象不同；
- 平台 API 顶层成功但单项失败/aborted，或批次中途取消、崩溃、断电；
- Trash 不支持或跨文件系统失败后误走永久删除；
- 普通用户看不到 holder，被错误解释为 unused；
- 计划、审批、策略版本或 nonce 被篡改、替换、过期或重放；
- SweepX 意外在 root/admin/capability/elevated 环境运行，扩大破坏面。

同一 UID 的主动恶意进程可能在最后一次检查与 pathname-based Trash API 之间持续竞态。三个平台没有统一的“仅当 identity 仍为 X 时原子移入 Trash”公开接口。设计通过稳定父 locator、no-follow、短 TTL、紧邻调用的复验、目录封闭 manifest 和事后 reconcile 缩小窗口；无法完全消除时必须明确残余风险，绝不声称完美 TOCTOU 防护。

## 3. 数据边界

所有跨边界记录版本化并 canonical serialize。display_path 和本地化说明只供展示，不是执行参数。

### 3.1 Candidate

Candidate 由扫描器 ScannedEntry 经显式、版本化映射构造，只是建议。映射不能丢失安全字段；新增的 locator/candidate/rule 字段来自同次 live admission 或候选层，不伪装成 scanner 原字段：

    Candidate {
      schema_version, scanner_semantics_version, adapter_version,
      candidate_id, scan_id, source,
      display_path, parent_reopen_recipe, native_basename,
      parent_identity, object_identity?, object_type,
      filesystem_object_domain_identity?,
      volume_or_mount_identity?, scan_root_identity,
      link_or_reparse_kind?, link_payload_digest?, hard_link_count?,
      logical_bytes: Known(u128) | Unknown(reason),
      allocated_bytes: Known(u128) | LowerBound(u128, reason) | Unknown(reason),
      reclaimable_estimate: Known(u128) | Unknown(reason), confidence,
      cloud_or_offline_state?, metadata_fingerprint,
      scan_timestamp, aggregate_revision?, subtree_complete,
      boundaries[], errors[],
      rule_ids[], evidence[], uncertainties[], provenance
    }

字段映射为：ScannedEntry.platform_file_identity -> Candidate.object_identity；parent_identity/native_basename/type/object-domain/mount/link/sizes/provider state/metadata fingerprint/errors/field-level provenance 以相同 tagged union 原样保留。parent_reopen_recipe 是同次 live root admission 产生的可序列化、无损 native 相对组件链，只是“如何从已验证 root 重新定位 parent”的 recipe，不是 handle、身份或授权；它不能来自 cache，使用后仍必须逐层 no-follow 核对 identity。scanner 明确规定 cache 不产生 candidate qualification，因此只有 source=local_current_live_scan 可新建 Candidate；本代按字段验证的 cache value 可以附着于同一 live 枚举 entry 的解释，但不能单独触发 candidate、进入 plan 或提供 recipe。imported、remote、stale、cache_only 只能展示并要求本机重扫。Unknown、LowerBound 与 Known(0) 不同。Candidate 不含 durable deletable 或 authorization 位。

CandidateBuilder 的 join 是显式的：普通文件候选来自本代 live ScannedEntry；目录候选必须以 (scan_id, scan_root_identity, object_identity) 连接同一 generation 的 final DirectoryAggregate revision。DirectoryAggregate.complete 原样映射为 subtree_complete，boundaries、skipped/errors、unknown/coverage 和 aggregate revision 一并进入 Candidate evidence。缺失 final aggregate、revision 不匹配、aggregate complete=false 或任何 join 字段冲突时，可以解释候选但不能生成 directory PlanItem；不得用旧缓存 aggregate 补齐。

### 3.2 Explanation

Explanation 绑定 candidate digest，回答：为何成为候选；哪些是本次事实、领域规则、启发式或未知；哪些子树未扫描；link/reparse/hard-link/provider/mount 状态；每种大小口径；默认动作、可恢复性预期、风险等级、占用观察与覆盖局限。

解释不能改变身份、目标集合、operation mode 或证据。文案使用 potentially reclaimable、observed open at <time>、scan incomplete、unknown；不使用 safe to delete、unused、will free exactly、guaranteed recoverable/unrecoverable。

### 3.3 不可变 DeletionPlan

    DeletionPlan {
      plan_schema_version, plan_id, nonce, created_at, expires_at,
      host_instance_id, user_identity,
      candidate_schema_version, scanner_semantics_version,
      safety_policy_version, safety_policy_digest,
      protected_anchor_snapshot_digest, adapter_capabilities_digest,
      scan_id, scan_root_identity,
      mode: Trash | Permanent,
      items: [PlanItem], aggregate_risk,
      canonical_digest
    }

    PlanItem {
      item_id, top_level_action_id, candidate_id, explanation_digest,
      parent_reopen_recipe, native_basename, display_path,
      expected_parent_identity, expected_object_identity,
      expected_filesystem_object_domain_identity,
      expected_object_type, expected_volume_or_mount_identity,
      expected_link_or_reparse_kind, expected_link_payload_digest?,
      expected_metadata_fingerprint,
      planned_descendant_manifest?: [DescendantAction], subtree_complete,
      risk_tier, risk_factors[], recovery_expectation
    }

    DescendantAction {
      action_id, relative_parent_recipe, native_basename,
      expected_parent_identity, expected_object_identity,
      expected_filesystem_object_domain_identity,
      expected_object_type, expected_volume_or_mount_identity,
      expected_link_or_reparse_kind, expected_metadata_fingerprint,
      planned_risk_tier, postorder_index
    }

计划绑定精确 item 集合、身份、模式、风险、scanner/schema/policy 版本、完整 canonical safety-policy 内容摘要、当时解析出的内置/用户/marker 保护锚点摘要、adapter capability、主机、用户和短有效期。确定性序列化后计算 256-bit `canonical_digest`；人类可见 fingerprint 是从该完整摘要截取的短 `SX1-...` 注意力/诊断 token，不是密码、授权或完整性边界。任何字段变化都生成新计划并重新授权。执行时不能通过 glob、相对路径、shell expansion 或环境变量增加对象。Trash 与 Permanent 不混批。

top_level_action_id = H(plan_nonce, item_id, "top-level")，是 canonical plan 的一部分。普通文件/link、Trash 目录和 Permanent 非目录均以它作为 action/risk/nonce/audit key。Permanent 目录的 root directory action 也使用 top_level_action_id，并排在全部 descendants 之后。

目录只有在扫描完整并包含封闭 descendant manifest 时才能进入计划。manifest 的每个 descendant 是一个有稳定 action_id、完整预期身份、逐项风险与后序位置的 DescendantAction；不通过读取文件内容做 hash，以免触发 provider hydration。Trash 目录仍是一个 top-level platform action，但复验整个 manifest；Permanent 目录的 action sequence 是所有 descendant action 按 postorder_index 排序，最后追加 top-level root action，绝不把“目录 item”当成一次递归通配动作。任一 ExecutionAuthorization 的 risk-by-action map 必须同时包含 top_level_action_id 与所有 descendant action_id。

### 3.4 ExecutionAuthorization

    ApprovalRecord {
      approval_id, plan_id, plan_digest,
      approved_mode, approved_item_ids, approved_item_count,
      approved_risk_by_item, approved_risk_by_action,
      approved_descendant_manifest_digests,
      approved_action_count, approved_max_risk,
      policy_version, policy_digest, protected_anchor_snapshot_digest,
      plan_schema_version,
      approving_user_identity, host_instance_id,
      approved_at, expires_at,
      approval_surface, confirmation_evidence, os_reauthentication?,
      nonce, consumed_state
    }

    DangerousDeleteRecord {
      authorization_id, source: ExplicitDangerousDelete,
      plan_id, plan_digest, exact_mode: Permanent,
      authorized_item_ids, authorized_item_count,
      authorized_risk_by_item, authorized_risk_by_action,
      authorized_descendant_manifest_digests, authorized_action_count,
      policy_version, policy_digest, protected_anchor_snapshot_digest,
      plan_schema_version, invoking_user_identity, host_instance_id,
      workflow_session, invoked_at, expires_at, nonce, consumed_state
    }

    ExecutionAuthorization = HumanApproval(ApprovalRecord)
                           | ExplicitDangerousDelete(DangerousDeleteRecord)

ExecutionAuthorization 只证明调用者对精确计划提供了对应类型的执行意图，不证明文件安全、调用者是人或状态未变。两种 variant 都绑定完整 256-bit plan digest、精确 mode/item/action 集合、每个 item/action 的风险、每个 descendant manifest digest、实际 action count、policy version + content digest + protection snapshot、用户/主机、短 TTL 与 single-use nonce。`HumanApproval` 另绑定下述本地 `ApprovalSurface`；`ExplicitDangerousDelete` 只允许 Permanent 并记录显式 flag 来源。runtime_risk 必须不高于该 action 自己的 authorized risk；不能借同批其他 R2/R3 item 的更高风险额度放行。编辑目标、提升逐项风险、策略/锚点变化或过期都会使 authorization 失效。

`ApprovalSurface` 不是通用输入接口，而是 Broker 独占的两种本地人机界面：

    ApprovalSurface = NativeFirstPartyLocalModal
                    | TrustedForegroundTerminal

1. **首选原生窗口**：Broker 启动随 SweepX/core 发布并校验身份的 first-party local modal；远端页面、插件 webview、RPC 调用者和 Agent 不能充当该 surface。窗口从 Broker 的 pending request 读取并展示 exact plan：精确 mode 和可展开 item/action 清单、`N` 个选中 item、其展开后的 `M` 个底层 action、逐项风险、unknown/coverage、恢复预期、expiry 和只读 fingerprint。用户必须先勾选明确 acknowledgement，再点默认不聚焦、危险样式且标明动作模式的批准按钮。该按钮只生成 ApprovalRecord；关闭窗口后仍须独立发起 `execute`，批准动作绝不同时执行删除。
2. **可信终端 fallback**：只有本机原生窗口不可用且 Broker 能证明 controlling terminal、foreground process group 与本地用户会话时，才在该 TTY 显示同一 exact plan并要求键入 challenge。Broker 从已持久化的 immutable full plan digest 和已锁定 selection 重新计算 `N`、`M`，再生成 `APPROVE <mode> <N> <M> <SX1-plan-fingerprint>`；Permanent 使用醒目的 `PERMANENT <N> <M> <SX1-plan-fingerprint>`。短 fingerprint 只帮助人对照/注意，安全校验与 ApprovalRecord 始终比较完整 256-bit digest 和精确 item/action IDs。
3. **拒绝自动化确认**：stdin/pipe、重定向输入、公共 RPC/SDK approval body、配置、环境变量、插件、远程会话和 Agent 点击/键入均不能完成 HumanApproval。CLI/TUI 只得到 opaque `approval_id`；approval record、nonce 和 Broker sealing key 不出 core。

原生 surface 可以选择增加**不提权**的本机用户重新验证。Windows 使用 [UserConsentVerifier.RequestVerificationAsync](https://learn.microsoft.com/en-us/uwp/api/windows.security.credentials.ui.userconsentverifier.requestverificationasync)；桌面窗口使用官方 [IUserConsentVerifierInterop::RequestVerificationForWindowAsync](https://learn.microsoft.com/en-us/windows/win32/api/userconsentverifierinterop/nf-userconsentverifierinterop-iuserconsentverifierinterop-requestverificationforwindowasync)，可由已配置的 [Windows Hello](https://learn.microsoft.com/en-us/windows/apps/develop/security/windows-hello) 完成。macOS 使用 [LocalAuthentication](https://developer.apple.com/documentation/localauthentication) 的 [`LAContext.evaluatePolicy`](https://developer.apple.com/documentation/localauthentication/lacontext/evaluatepolicy(_:localizedreason:reply:))。这些 API 的普通成功结果只说明 OS 在当时接受了验证，不会提权，也不会天然签名或绑定任意 SweepX digest；异步回调后 Broker 必须仍指向同一个 pending request，并重新核对完整 digest、item/action counts、selection、mode、TTL 和 surface session 后才写 ApprovalRecord。

确认本身不得触发 Windows [UAC](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/user-account-control/how-it-works) 或 macOS [Authorization Services](https://developer.apple.com/documentation/security/authorization-services)，也不获取管理员能力。Linux 没有统一等价的用户在场验证 API；使用 first-party native app dialog，无法提供合格图形会话时才用 trusted foreground TTY，不为了“确认”调用 `sudo` 或 [polkit](https://polkit.pages.freedesktop.org/polkit/polkit.8.html)。未来只有在密钥生命周期、用户在场策略、失败/恢复语义和跨版本行为均通过平台 gate 后，才可让受保护应用密钥对 canonical approval challenge 签名并声称密码学绑定；Windows 可评估 Windows Hello protected-key signing，macOS 可评估 [Face ID/Touch ID 保护的 Keychain item](https://developer.apple.com/documentation/localauthentication/accessing-keychain-items-with-face-id-or-touch-id)。

`--yes`、`--force`、配置、环境变量和插件不能生成 authorization。唯一非交互入口是字面量 `--dangerously-delete`，且只能为已有 Permanent R4 plan 生成 `DangerousDeleteRecord`；它保持现有语义，跳过 modal、OS reauthentication 和 terminal challenge。不能有“以后全部同意”令牌，不能接受 path/mode/新增 item，也不能绕过保护或复验。

### 3.5 RevalidationRecord 与 PreflightPermit

    RevalidationRecord {
      plan_id, item_id, action_id, checked_at,
      runtime_user_state,
      root_identity, ancestor_chain_digest,
      parent_identity, native_basename,
      object_identity, filesystem_object_domain_identity, object_type,
      volume_or_mount_identity,
      link_or_reparse_kind, metadata_fingerprint,
      live_policy_digest, live_protected_anchor_snapshot_digest,
      protection_policy_result,
      descendant_manifest_result?, cleaner_evidence_result?,
      observed_open_state,
      result: Match | Stale(reason) | Blocked(reason)
    }

    PreflightPermit {
      plan_id, item_id, action_id, plan_digest, authorization_id,
      mode, risk_tier, policy_version, policy_digest,
      protected_anchor_snapshot_digest,
      validated_at, expires_at,
      final_parent_identity, final_object_identity,
      final_filesystem_object_domain_identity,
      final_volume_or_mount_identity,
      held_parent_handle, held_object_handle?,
      revalidation_digest, one_shot_nonce
    }

只有完整 Match 且 live policy/anchor digest 与 plan/authorization 一致时，才在内存生成最长 2 秒、一次性的 permit。permit 持有 preflight 当项临时打开的 parent/object handle；不持久化、不跨 item、不改变 mode。DeletionAdapter 只接受 permit 和已经绑定的 native basename，不接受任意 path/list/string。adapter 在调用前验证当前 core policy digest/anchor digest 仍等于 permit；policy store 不可读或摘要改变即拒绝。

### 3.6 ItemOutcome 与 AuditEvent

    ActionOutcome {
      plan_id, authorization_id, authorization_source, item_id, action_id, attempt_id,
      requested_mode, actual_platform_operation,
      risk_tier, policy_version, policy_digest, adapter_version,
      started_at, finished_at,
      before_revalidation_digest,
      platform_operation_id?, platform_result?,
      platform_error_domain?, platform_error_code?,
      aborted?, cancelled?,
      resulting_trash_locator?, recovery_state,
      source_postcheck, destination_postcheck?,
      caller_visible_capacity_before?, caller_visible_capacity_after?,
      status, notes[]
    }

    ItemOutcome = ordered summary of all ActionOutcome for one PlanItem

审计保存 intent 和实际 adapter 结果，不把请求意图冒充成功。路径可能敏感，日志位于当前用户私有目录，设保留期，不含文件内容。本地 hash chain 只能发现部分意外损坏；同一用户可删除或篡改自己的状态，不能称为不可篡改审计。

## 4. 组件信任边界

    scanner/cache -> Candidate
        -> explanation/risk classifier
        -> immutable plan builder -> canonical digest
        -> authorization gate -> HumanApproval | ExplicitDangerousDelete
        -> core hard-protection + live preflight
        -> one-shot PreflightPermit
        -> platform adapter
        -> per-item outcome -> durable audit/reconciliation

- ScanPlatformAdapter 只产生扫描记录，不能调用 DeletionAdapter；cache 和 imported data 是不可信输入。本文后续无修饰的 adapter 均指 DeletionAdapter。
- UI、CLI、插件、规则包不能创建 permit 或绕过 core protection。
- risk classifier 只能维持/提高风险或阻断，不能把 unknown 降级。
- core executor 与每个 DeletionAdapter 都独立拒绝缺 permit、模式不符、过期 nonce 和 hard-protected target，形成纵深防御。
- adapter 不提供 Trash-or-Permanent 组合函数。
- audit store 无法可靠 append+sync 时不得开始新动作。

## 5. 状态机

### 5.1 批次与单项状态

    DISCOVERED -> EXPLAINED -> PLANNED -> AUTHORIZATION_PENDING -> AUTHORIZED
      -> REVALIDATING -> READY -> EXECUTING
      -> COMPLETED | PARTIAL | CANCELLED | NEEDS_RECONCILIATION
      -> AUDITED

单项：

    CANDIDATE -> EXPLAINED -> IN_PLAN -> AUTHORIZED -> REVALIDATING
      -> PREFLIGHT_READY -> TRASHING | PERMANENT_DELETING
      -> SUCCEEDED | FAILED | SKIPPED | STALE | CANCELLED | INDETERMINATE
      -> AUDITED

任何阶段还可进入 REJECTED 或 HARD_BLOCKED。STALE 必须重新扫描、解释、计划、授权；不能复用旧 permit。

### 5.2 转移规则

| 当前 | 条件 | 下一状态 | 明确禁止 |
|---|---|---|---|
| Candidate | 解释绑定 evidence | Explained/Rejected | Candidate -> Execute |
| Explained | hard protection 通过，构建并 digest | Planned/HardBlocked | UI path 直接进 plan |
| Planned | 获得匹配 digest/mode/items/risk/policy 的 HumanApproval，或 Permanent 获得 ExplicitDangerousDelete | Authorized/Rejected | Plan -> Execute |
| Authorized | live no-follow 全量复验 | Ready/Stale/HardBlocked | Authorized -> Execute 而无复验 |
| Ready | INTENT 已 durable，permit 未过期 | Executing | 修改 mode/target |
| Executing | adapter + reconcile 有逐项事实 | terminal/NeedsReconciliation | Trash failure -> Permanent |
| terminal | outcome durable | Audited | missing 当 success |

复验终态至少包括 SKIPPED_PROTECTED、SKIPPED_RISK_NOT_APPROVED、SKIPPED_INCOMPLETE_SUBTREE、BLOCKED_RUNTIME_PRIVILEGE、BLOCKED_POLICY_INTEGRITY、STALE_PARENT、STALE_IDENTITY、STALE_TYPE、STALE_MOUNT、STALE_LINK、STALE_DESCENDANTS。

每个实际平台 action（Trash 的每个 top-level item；Permanent 的每个文件、link 和后序目录）前都先 append+sync 独立 ACTION_INTENT，并使用独立 action_id/attempt_id/permit/outcome。计划 digest 不符、策略损坏、意外提权、广泛 identity 异常是 batch-fatal；普通权限/Trash 单项错误可记录后继续独立 item。取消只阻止下一 action；已提交平台 API 的 action 必须 reconcile，不能未经事实标 cancelled。

## 6. 风险分级

风险是授权政策，不是安全证明。unknown 只能维持或提高风险。

| 等级 | 判定示例 | 允许动作 | 审批 |
|---|---|---|---|
| R1 低风险可回收 | 本地普通文件、扫描完整、identity/volume 可用、无 link/boundary/holder signal | Trash | 展示原因、路径、口径、恢复说明，确认计划 |
| R2 中风险可回收 | 普通目录、多项批次、用户内容、近期修改、hard-link reclaim 不确定 | Trash | ApprovalSurface 展示 exact plan、逐项风险与诊断 fingerprint |
| R3 高风险/能力不确定 | executable/app bundle、数据库、VM/container/package state、active log、observed-open、cloud/provider、network/removable、跨卷语义、部分 evidence unknown | 默认 skip；策略允许时 Trash-only | 单独选择并加强确认；部分因素直接阻断 |
| R4 不可逆 | 任一 Permanent；非空目录永久动作 | Permanent | 独立批次；原生 modal 确认 `N` items/`M` actions，可信 TTY 才键入 digest-derived challenge；或显式传 `--dangerously-delete`；authorization 均绑定完整计划 |
| BLOCKED | root、protected、mount point、unknown reparse、身份不足、计划篡改、提权上下文、新后代 | 无 | 不可审批，不可 force 降级 |

Permanent 必定 R4。目录、hard link、unknown reclaim、近期修改至少维持或提升一级；observed-open/provider/remote/incomplete 提升至 R3 或 BLOCKED。native cleaner dry-run 与计划不一致是 STALE，不是降低风险的证据。

## 7. 不可绕过的硬保护

### 7.1 内置保护集合

用户可以增加保护，不能删除或放宽内置项：

- 任意 filesystem、volume、mount、bind、mounted-folder、automount、UNC share root；
- OS 启动、恢复、系统、设备、虚拟 filesystem、package manager/state 树；
- 当前 home/profile 根本身、所有 profile 集合的父根；
- Trash/Recycle Bin 及 freedesktop Trash 内部；
- SweepX executable、安装目录、活动 cwd、配置、cache/spill、计划库、锁和审计；
- 上述 protected anchor 的祖先目录（整体动作会包含保护项时）；
- 当前进程 executable/cwd 及整体动作会包含它们的祖先；
- device、socket、FIFO、Windows device namespace、未建模 ADS、unknown reparse/special object；
- 身份、parent、type、mount 或 containment 无法现场复验的对象；
- scan root 外对象；目录中的未审批、新出现、未扫描后代。

Windows 锚点通过 known-folder/volume API 取得，而非假设 C:；包括 Windows、System、Program Files、ProgramData、Profiles、系统管理文件和 Recycle Bin。macOS 包括 /、所有 volume roots、signed/read-only system volume，以及 /System、/Library、/Applications、/usr、/bin、/sbin、/private、/dev、/Volumes 等。Linux 包括 /、/boot、/dev、/etc、/proc、/run、/sys、/usr、/bin、/sbin、/lib*、/var、/root 及本次 /proc/self/mountinfo 的每个 mount root。列表是保守下限；平台锚点解析失败则 destructive mode 失败关闭。

### 7.2 根目录拒绝与等价别名

root refusal 在解析计划、审批、preflight 和 adapter 四层重复。拒绝：

- POSIX /、macOS /Volumes/<name> 对应的 volume root、Linux 任一 mount/bind root；
- Windows drive root（C:\ 及大小写/尾分隔符等价形式）、volume-GUID root（\\?\Volume{GUID}\）、UNC share root（\\server\share\），以及 mounted-folder 所指 volume root；
- 根的 .、..、重复分隔符、大小写等价、短/长名、symlink/reparse alias、trailing separator 等所有 native-normalized 等价形式；
- 空、相对、malformed、含 wildcard/glob、device namespace 或无法无损规范化的输入。

匹配不使用字符串 starts_with。使用 native component comparison、no-follow identity、parent identity chain、volume/mount identity 和 known-folder/mount API。Windows case semantics 按实际 volume，Unix 保留原始字节；display normalization 不参与执行。

### 7.3 保护路径、保护文件和 marker

保护规则有三种：

- PROTECTED_SUBTREE：对象等于锚点或位于其下即拒绝；
- PROTECTED_ANCHOR：对象等于锚点或是其祖先、整体动作会包含锚点即拒绝；
- PROTECTED_IDENTITY：即使经 hard link、不同盘符、mount alias、大小写或 symlink 拼写到达，只要 identity 命中即拒绝。

显式 protected-file policy 保存原生 identity + parent identity + volume/mount，而不是只存 path。policy_version 纳入 plan/authorization，preflight 重新读取。

v1 定义保留 marker 名 .sweepx-protect。对候选及其从 scan root 到 parent 的每个真实祖先，执行器以 no-follow、parent-relative 方式检查该 basename：

1. 任意类型的同名目录项存在（regular、symlink、reparse 或无法识别）即保护 marker 所在目录及全部后代；marker 自身也受保护。
2. 不打开 marker 内容，不跟随它，不要求特定内容。这样 symlink marker 也只能增加保护，不能转向外部。
3. 某层因权限/竞态无法确定 marker 是否存在时，目标 BLOCKED；不能把“没看见”当不存在。
4. marker 作用从所在目录继承到 descendants，但不向 sibling 或祖先扩展；然而删除它的祖先会包含 marker，因此由 PROTECTED_ANCHOR 规则拒绝。
5. 计划后 marker 新增/删除/identity 改变都会令 plan STALE；执行前再次逐层检查。
6. --force、Permanent、配置、env、plugin 和直接 adapter 调用不能忽略 marker。用户要取消保护必须在 SweepX 外显式移除 marker，再重新扫描、计划和审批；本动作不能顺带删除 marker。

### 7.4 危险参数能力边界

唯一的永久删除危险参数命名为 `--dangerously-delete`。它允许调用者在 `execute` 阶段对一个已经存在、未过期的 Permanent R4 plan 跳过确认，并支持非交互 CLI；Core 不声称能识别调用者是人还是分配了 PTY 的 Agent。该 flag 形成独立 `ExplicitDangerousDelete` authorization：Core 生成与精确 plan/mode/items/actions/risk/digests/user/host/session 绑定的 sealed single-use `DangerousDeleteRecord`，在同一 admission 原子 claim并完整审计。它与 `--approval-id` 互斥，也不能把 Trash plan 改成 Permanent。Agent Skill 明令不调用，但真正不可绕过的边界是：任何危险参数都不能关闭 root/protection/marker 检查，不能 follow link、跨未批准 mount、忽略 identity/type/parent/plan digest，不能把 cache/imported data 变成 permit，不能提权，不能把 unknown 记 success。

core executor 和 DeletionAdapter 的公共接口不接受 force bit。hard protection 结果是 sealed permit 的前置条件；DeletionAdapter 还验证 permit 的 policy version、policy/anchor digest 和 target class。直接 API、配置或 UI 绕过因此也会 hard refuse。

## 8. 路径、链接、目录与 TOCTOU

### 8.1 权威定位

持久计划中的定位是 parent_reopen_recipe + exact native basename + expected parent/object/domain/type/mount identities。recipe 是从 scan root 到 parent 的原生相对组件链，不是打开的 handle，也不因序列化而成为可信路径；preflight 从 live no-follow root handle 逐层重开并核对后，才得到短期 held_parent_handle。Unix 保存原始 basename bytes；Windows 保存 UTF-16。不得通过 lossy UTF-8、Unicode normalization、大小写折叠或 shell 字符串重建。

DeletionExecutor 默认串行、同时最多一个 active permit，因此最多保留一组 preflight parent/object handles；单项终态或 permit 过期立即关闭。计划和 Candidate 不持有 native handle，也不受 scanner 的 open-enumerator 配额混淆。未来提高并发必须给 handle 数独立硬上限并重新做 TOCTOU/平台 adapter 测试。

计划拒绝 .、..、空 basename、未扫描绝对路径、歧义 device name、未建模 ADS、离开 scan root 的组件和身份不一致对象。

### 8.2 紧邻动作的复验顺序

每个 item 必须。步骤 2–9 可以执行较慢查询，但它们只建立“准备复验”；真正授权 identity check 是步骤 10，在其后不再执行任何可能让窗口拉长的查询：

1. 确认 runtime 仍是普通用户；验证 plan/authorization digest、variant、mode、items、risk、policy、nonce、TTL。
2. no-follow 重新定位 scan root、所有祖先和 parent；比较 root/ancestor/parent identity 与 containment。
3. 用 exact native basename no-follow 读取当前 directory entry。
4. 比较 object identity、type、volume/mount、link/reparse kind/payload、hard-link/关键 metadata fingerprint。
5. 重新读取 mount/volume snapshot；任何 remap、bind/mounted-folder 变化为 STALE_MOUNT。
6. 重新运行 root/path/file/marker/self/Trash 全部 hard protection。
7. 目录重新枚举并比较封闭 descendant manifest；新增、消失、权限或 identity 变化为 STALE_DESCENDANTS。
8. 适用时重跑 native cleaner query/dry-run；变化令计划 stale。它不能授权。
9. best-effort 观察 holder，但 negative result 不授权；风险提升超过审批即停止。
10. 为当前 action append+sync ACTION_INTENT，明确其状态为“平台调用尚未发生，等待 final recheck”，记录 item/action/attempt、prepared identity、plan/mode、holder、fence epoch 和预留 nonce。若此后失败，补记 SKIPPED/STALE；INTENT 本身不表示调用已发生。
11. durable INTENT 完成后，使用 preflight 打开的 held_parent_handle，再次以 exact basename no-follow 读取 entry，并重新比较 parent、object identity/object-domain/type、mount、link/reparse、containment、live policy/anchor digest；目录还复核平台可用的 closure token，若无此能力则明确保留同 UID 后代注入残余风险。任一变化停止。只在内存生成短期 one-shot permit。
12. final recheck 后不做 UI、网络、cache、cleaner、holder 或额外日志等待；立即调用 adapter。adapter 入口再次验证 permit TTL/nonce/mode/policy digest 和 held parent binding。
13. 调用后比较 source、平台逐项结果和可得 destination；持久化 outcome 后才推进下一项。

任何 inability to compare 都失败关闭。仅检查 target identity 不足：父/祖先或 mount 被替换同样停止。

### 8.3 平台最强 containment

- Linux 优先保持 scan-root/parent FD，使用 openat2 的 RESOLVE_NO_SYMLINKS | RESOLVE_BENEATH | RESOLVE_NO_XDEV 与 statx mount ID；永久动作只可 parent-relative unlinkat。
- Windows 以 FILE_FLAG_OPEN_REPARSE_POINT 打开 entry 本身，保持 parent/object handle，比较 FileIdInfo 与 volume；不得启用 SeBackupPrivilege。Shell Trash 仍可能接收 item/path，残余 race 必须承认。
- macOS 结合 lstat、fileResourceIdentifier、volumeIdentifier 与已保持的 parent 信息；Foundation Trash URL 最终是 path/URL-based，残余 race 必须承认。

最终 parent + basename identity/object-domain/type/mount/link/policy check 与平台调用之间不做 UI、网络、cache、cleaner、holder 或额外 audit sync，缩短窗口。操作后矛盾或替换标 INDETERMINATE，不猜成功。

### 8.4 link 与 hard link

- symlink/目录 reparse 永不递归。若计划明确选择 link 本身，只处理该目录项，不处理 target。
- unknown reparse tag BLOCKED；junction、mounted folder、bind、automount 都是边界。
- 普通对象与 link 互换或 tag/payload 改变为 STALE_LINK/TYPE。
- hard link 按 scanner 的 filesystem_object_domain_identity + platform_file_identity 识别；volume/mount identity 另用于 traversal boundary。Linux bind alias 不能因 mount ID 不同被当作不同底层对象。只移除获批名称；已知有 surviving link 时不承诺释放数据，覆盖不足为 unknown。

### 8.5 目录封闭世界

“授权目录”不等于授权未来出现的内容。Trash 顶层目录前必须完整重枚举并匹配 manifest；发现新对象、不可读、边界或变化则整个目录 item stale，不调用顶层 Trash API。

Permanent 递归只按授权 plan 中的 manifest DescendantAction 后序逐项处理。每个 descendant 都完整执行“重新打开 -> prepared checks -> ACTION_INTENT -> final recheck -> 新 one-shot permit -> 单次 platform primitive -> ActionOutcome”，不能复用 parent/前一 descendant 的 permit。未授权的新项目必须保留，父目录返回 FAILED_NOT_EMPTY_AFTER_APPROVED_CHILDREN。部分已处理 descendants 逐项审计，顶层 item/batch 为 PARTIAL。

## 9. Trash、Permanent 与可恢复性

### 9.1 Trash 默认模式

- 只调用平台支持的回收 API，不直接拼写或修改 $Recycle.Bin、.Trash 或 .Trashes。
- 调用前 capability/preflight 返回 unsupported/denied/no-space 时不提交，记录 SOURCE_CONFIRMED_UNCHANGED；不调用 permanent API。
- 调用提交后返回 cancelled/aborted/unknown 或回调矛盾时，不能承诺源不变：立即 reconcile。只有 no-submit 证据或 source postcheck 证实相同 identity 仍在原处，才使用 SOURCE_CONFIRMED_UNCHANGED；否则为 PARTIAL/INDETERMINATE。任何结果都不调用 permanent API。
- 不自动 empty Trash。移入 Trash 通常仍占空间，不能从“已回收”推导 reclaimed capacity。
- v1 不自实现 cross-filesystem copy-to-trash。未来若加入，它是 R3 慢操作，必须预检临时双倍空间、进度/取消、info ordering 和 crash residue；仍不能 fallback Permanent。

recovery_state 至少有 PLATFORM_TRASH_REPORTED、TRASH_LOCATION_REPORTED、TRASH_SUCCESS_LOCATION_UNKNOWN、NOT_SUPPORTED_SOURCE_UNCHANGED、FAILED_SOURCE_UNCHANGED、INDETERMINATE。即使成功，也只说“平台报告已移入 Trash”；平台可能重命名碰撞项、隐藏 destination、受策略/容量/provider 限制或之后被清空，因此不保证恢复。

### 9.2 Permanent 独立模式

Permanent 必须在计划创建时声明；所有 item 至少 R4；与 Trash 分批。HumanApproval 优先在 first-party native modal 展示 exact plan、`N` 个选中 item、`M` 个底层 action、path/type/risk/unknown/expiry 和“绕过回收站”，以 acknowledgement + destructive approval button 确认；只有可信 foreground TTY fallback 才键入 digest-derived challenge。ExplicitDangerousDelete 路径跳过全部确认和可选 OS reauthentication，但把相同精确字段写入 authorization/audit。审批与 execute 始终是两个动作，两种 authorization 在执行前都做同样完整复验和 hard protection。

Trash 失败后若调用者另行要求 Permanent，必须从新的 live scan 重新开始，重新生成 Candidate 与 Explanation，创建新 Permanent plan 并重新授权；旧 scan、Candidate、plan、authorization 或 permit 均不得携带 authority。Permanent 成功不等于 secure erase：snapshot、backup、clone/reflink、cloud copy、journal、open handle 和介质都可能保留内容或空间。

### 9.3 事后容量

可选记录动作前后同一 volume 的 caller-visible capacity：Windows GetDiskFreeSpaceExW caller-available、Linux statvfs f_bavail、macOS volumeAvailableCapacityForImportantUsageKey。三者语义不同，macOS 还包含 purgeable 判断；只能作为单平台事后 observation，与 logical/allocated/reclaimable 分列。Trash 后无变化是正常结果，不能把容量 delta 当动作成败唯一证据。

## 10. 三平台 adapter

### 10.1 Windows

身份/边界：CreateFileW 等以 FILE_FLAG_OPEN_REPARSE_POINT 和目录所需 backup-semantics 打开 entry，但不启用 SeBackupPrivilege。身份使用 volume identity + FileIdInfo/file index，并结合 parent/type/短 TTL；ID 不是跨时间永久 ID。所有 directory reparse 默认边界，unknown tag、junction、mounted folder、UNC/provider 根据策略 R3 或 BLOCKED。

Trash：Windows 8+ 在 STA 线程使用 IFileOperation::DeleteItem + PerformOperations，真实 owner window、progress sink，并设置 `FOFX_RECYCLEONDELETE` 作为 recycle-only 强制语义；destruction warning 只能是附加防线，undo “if possible” 也不是保证。必须同时检查 HRESULT、逐项 `PostDeleteItem` sink 与 GetAnyOperationsAborted；顶层成功不能覆盖单项 aborted。若不能证明已送入 Recycle Bin，则 TRASH_UNAVAILABLE，绝不改用普通 permanent delete 重试。无法证明 recycle-only 的旧 OS/API 组合关闭 destructive mode。禁止直接操作 $Recycle.Bin。

Permanent：每个 DescendantAction 仅用自己的 Permanent permit 调用不跟随 link target 的 API；目录按 manifest 后序。sharing violation、read-only、DACL/属性失败原样返回，不清属性、不改 ACL、不提权。

占用：Restart Manager 只对具体文件做时间点 observation/失败诊断；目录不能注册。不得调用需要管理员权限的 Handle，不关闭句柄、不终止进程。

证据：[IFileOperation::DeleteItem](https://learn.microsoft.com/en-us/windows/win32/api/shobjidl_core/nf-shobjidl_core-ifileoperation-deleteitem)、[operation flags](https://learn.microsoft.com/en-us/windows/win32/api/shobjidl_core/nf-shobjidl_core-ifileoperation-setoperationflags)、[GetAnyOperationsAborted](https://learn.microsoft.com/en-us/windows/win32/api/shobjidl_core/nf-shobjidl_core-ifileoperation-getanyoperationsaborted)、[FILE_ID_INFO](https://learn.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-file_id_info)、[Reparse points](https://learn.microsoft.com/en-us/windows/win32/fileio/reparse-points)、[DeleteFile](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-deletefile)、[Restart Manager](https://learn.microsoft.com/en-gb/windows/win32/api/restartmanager/nf-restartmanager-rmregisterresources)。

### 10.2 macOS

身份/边界：lstat/no-follow 与 fileResourceIdentifier + volumeIdentifier（或 st_dev/st_ino）组合；不把 ID 当永久身份。same-volume；network、automount、File Provider、read-only/signed system volume 是边界。不请求 FDA；已有 FDA 也不改变 hard protection。sandbox 只用用户明确授予的 scope，扫描用只读 bookmark 不会隐式成为删除许可。

Trash：逐个 top-level item 调用 FileManager.trashItem(at:resultingItemURL:)，记录 resulting URL 或位置未知和结构化 error。不得依赖私有 Trash 布局，失败后不得调用 removeItem fallback。

Permanent：每个 action 仅用自己的 Permanent permit。FileManager.removeItem 只允许用于复验为非目录且其 API 不跟随 link target 的文件/link action；目录 action 必须使用 parent-relative、no-follow 的 POSIX rmdir（或经实测等价的严格 nonrecursive primitive），目录非空即 FAILED_NOT_EMPTY_AFTER_APPROVED_CHILDREN，绝不调用会递归移除 contents 的 Foundation API。目录只执行 manifest actions；不称为 secure erase。

占用：lsof/内核信息只生成 observed-open；受权限、TCC、安全策略与 race 限制。file coordination 是协作，不是无人使用证明。不 kill 进程。

证据：[FileManager.trashItem](https://developer.apple.com/documentation/foundation/filemanager/trashitem(at:resultingitemurl:))、[FileManager.removeItem](https://developer.apple.com/documentation/foundation/filemanager/removeitem(at:))、[Apple Trash semantics](https://support.apple.com/guide/mac-help/delete-files-and-folders-on-mac-mchlp1093/mac)、[Darwin stat](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man2/stat.2.html)、[fileResourceIdentifier](https://developer.apple.com/documentation/foundation/urlresourcevalues/fileresourceidentifier)、[volumeIdentifier](https://developer.apple.com/documentation/foundation/urlresourcekey/volumeidentifierkey)、[App Sandbox file access](https://developer.apple.com/documentation/security/accessing-files-from-the-macos-app-sandbox)、[File coordination](https://developer.apple.com/library/archive/documentation/FileManagement/Conceptual/FileSystemProgrammingGuide/FileCoordinators/FileCoordinators.html)。

### 10.3 Linux

身份/边界：优先 parent FD + openat2 RESOLVE_NO_SYMLINKS/BENEATH/NO_XDEV，statx mount ID + device/inode，保存并复验 /proc/self/mountinfo。仅 st_dev 不足以识别 bind mount。旧 kernel/filesystem 缺 containment/identity 能力时，高风险目录动作失败关闭。symlink 只处理 link；mount/bind/network/FUSE/automount/pseudo/container 默认不进入。

Trash：优先 GIO g_file_trash。调用前 capability check 的 G_IO_ERROR_NOT_SUPPORTED/EXDEV/permission/space 不提交并确认 source 未变；调用已经提交后的 cancel、remote error 或不明返回必须按全局规则 reconcile，不能承诺 source 未变。不手写 fallback，不永久 unlink。未来若实现 freedesktop Trash，必须验证共享 .Trash sticky 且非 symlink、files/info、.trashinfo 先行、O_EXCL collision、percent encoding、权限、容量、取消和 crash residue。

Permanent：每个 DescendantAction 只在自己的 permit 下用 parent FD + exact basename 的 unlinkat 类操作；目录按 manifest 后序；新文件保留，父返回 non-empty。immutable、read-only、ACL、LSM 失败不经 root/capability 重试。

占用：可观察当前 namespace 可见的 /proc/PID/fd、maps、cwd、root、exe，并按 device/inode/open identity 而非 path string 匹配。ptrace、hidepid、namespace、capability、LSM 会限制 coverage。advisory lock 缺失不代表 unused。

证据：[Trash specification](https://specifications.freedesktop.org/trash/latest/)、[GIO File.trash](https://docs.gtk.org/gio/method.File.trash.html)、[openat2](https://man7.org/linux/man-pages/man2/openat2.2.html)、[statx](https://man7.org/linux/man-pages/man2/statx.2.html)、[mountinfo](https://man7.org/linux/man-pages/man5/proc_pid_mountinfo.5.html)、[symlink](https://man7.org/linux/man-pages/man7/symlink.7.html)、[unlink](https://man7.org/linux/man-pages/man2/unlink.2.html)、[/proc/PID/fd](https://man7.org/linux/man-pages/man5/proc_pid_fd.5.html)、[/proc/PID/maps](https://man7.org/linux/man-pages/man5/proc_pid_maps.5.html)。

## 11. 普通用户与 in-use 边界

每项 preflight 检查 runtime：Windows elevated/full token 时 destructive mode 拒绝，不启用 backup/restore/take-ownership privilege；macOS euid=0 拒绝且不调用 privileged helper；Linux euid=0，或 effective/permitted/ambient capability sets 中存在任一会改变文件访问、ownership、属性、mount/namespace 或进程观察边界的 capability（至少 CAP_DAC_OVERRIDE、CAP_DAC_READ_SEARCH、CAP_FOWNER、CAP_CHOWN、CAP_LINUX_IMMUTABLE、CAP_SYS_ADMIN）时拒绝。v1 最简单且强制的实现是要求所有三组 capability set 均为空；不调用 sudo/polkit/setuid，不切 user/mount namespace。

统一占用状态：

    OBSERVED_OPEN { checked_at, visible_holders[], visibility_limits[] }
    NOT_OBSERVED { checked_at, coverage }
    UNKNOWN { reason }
    NOT_SUPPORTED

OBSERVED_OPEN 只表示当时观察到，不证明 Trash/unlink 必失败。NOT_OBSERVED 不表示 unused；UNKNOWN 不降低风险。Unix pathname 被 unlink 后，open FD/mapping 仍可保留对象和空间；Windows share mode/mapping 可导致失败或延迟。进程可在检查后打开对象，所以占用观察不能替代身份复验。SweepX 不 kill、close handle 或申请更高权限来扩大视图。

## 12. 执行协议、结果与崩溃恢复

### 12.1 参考伪代码

    execute(plan, authorization):
      require audit_store.durable()
      require ordinary_user()
      require verify_plan_and_authorization_binding(plan, authorization)
      require authorization.variant == HumanApproval
           or (authorization.variant == ExplicitDangerousDelete
               and plan.mode == Permanent)
      require live_policy_and_anchor_digests_match(plan, authorization)
      executor_fence = acquire_nonexpiring_os_batch_lock(plan.id)
      executor_epoch = audit.atomic_claim_unused_authorization_and_sync_batch_start(
        authorization.id, authorization.nonce, plan.digest, executor_fence.process_identity
      )

      for item in stable_order(plan.items):
        actions = exact_authorized_action_sequence(item, plan.mode)
        # Trash: exactly one top-level action.
        # Permanent directory: descendant manifest postorder, then top_level_action_id.
        for action in actions:
          if cancelled: audit.sync(ACTION_CANCELLED_BEFORE_START); continue
          bound = reopen_parent_and_entry_no_follow(action)
          prepared = inspect_root_ancestors_parent_entry_mount(bound)
          require identities_types_mount_link_containment_match(prepared, action)
          require all_hard_protections_allow(prepared, plan.policy_digest)
          require directory_manifest_matches_if_needed(prepared, action)
          require cleaner_evidence_matches_if_needed(prepared, action)
          holders = observe_open_best_effort(prepared)
          runtime_risk = recompute_risk(prepared, holders)
          require runtime_risk <= authorization.risk_by_action[action.id]
          action_nonce = audit.atomic_reserve_action_nonce_and_sync_intent(
            executor_epoch, action.id, prepared, holders
          )
          final = final_parent_basename_no_follow_recheck(bound, action)
          require final_matches_prepared_action_mount_policy_and_manifest(final)
          permit = issue_in_memory_one_shot_permit(
            executor_epoch, action_nonce, bound, final, plan.mode,
            plan.policy_digest
          )
          result = plan.mode == Trash
            ? adapter.trash(permit)
            : adapter.permanent_delete_one_nonrecursive_action(permit)
          outcome = reconcile_source_destination_and_platform_result(result)
          audit.sync(ACTION_OUTCOME, outcome)

      audit.sync(BATCH_END, derive_from_durable_item_outcomes())
      audit.release_batch_lock_keep_authorization_consumed(executor_fence)

ExecutionAuthorization（无论 HumanApproval 或 ExplicitDangerousDelete）的 UNUSED -> CLAIMED(executor_instance, fence_epoch) -> CONSUMED 转移由 audit store 以 compare-and-swap 事务完成，并在任何 ACTION_INTENT 前 durable。executor 同时持有本机 non-expiring exclusive OS lock；它不靠超时续租，suspend 的旧进程仍持锁，recovery 不得接管。只有 OS 已确认旧进程退出、锁被内核释放后，恢复器才可取得锁并 CAS 到更高 fence_epoch；DeletionAdapter 在每次调用入口验证调用者仍持锁且 epoch 与 durable batch 相同。旧 epoch 永远被拒绝，因此不会出现恢复器与旧 executor 并发执行。

每个 action_nonce 在 final recheck 之前随 ACTION_INTENT 原子从 UNALLOCATED -> RESERVED(epoch)；final recheck 后只在本进程内以原子状态 RESERVED -> CONSUMED_BY_ADAPTER，一次 adapter call 后即不可复用。这里无需在 final recheck 后等待 durable I/O。若进程在 INTENT 后任意时点崩溃，nonce 保持 RESERVED/ambiguous，恢复器先 reconcile 该 action，绝不直接重发；只有确认平台调用从未提交且重新完成全套 preflight 后，才以新的 attempt/action_nonce 执行。require 失败不被 force 捕获后继续。not found/VANISHED 不是成功。free-space delta 只是分列观测。

### 12.2 稳定结果枚举

至少包括：TRASH_SUCCEEDED_PLATFORM_REPORTED、TRASH_SUCCEEDED_LOCATION_REPORTED、PERMANENT_DELETE_SUCCEEDED、SKIPPED_PROTECTED、SKIPPED_RISK_NOT_APPROVED、SKIPPED_INCOMPLETE_SUBTREE、STALE_PARENT、STALE_IDENTITY、STALE_TYPE、STALE_MOUNT、STALE_LINK、STALE_DESCENDANTS、BLOCKED_UNKNOWN_REPARSE、BLOCKED_OUTSIDE_SCAN_ROOT、BLOCKED_RUNTIME_PRIVILEGE、FAILED_PERMISSION、FAILED_READ_ONLY、FAILED_SHARING_VIOLATION、FAILED_TRASH_UNSUPPORTED、FAILED_TRASH_NO_SPACE、FAILED_NOT_EMPTY_AFTER_APPROVED_CHILDREN、FAILED_PLATFORM_ERROR、FAILED_CANCELLED_BY_PLATFORM、VANISHED_BEFORE_ACTION、CANCELLED_BEFORE_ACTION、INDETERMINATE_AFTER_CRASH、INDETERMINATE_PLATFORM_RESULT。

只有每项确认成功才显示 batch success；混合结果为 PARTIAL。Windows 必须综合逐项 sink 和 aborted，而非只看 PerformOperations 顶层值。原生 error domain/code 原样保留并附稳定跨平台分类。

### 12.3 写前日志与 reconciliation

每个实际 action 的平台调用前持久化 plan/item/action/attempt、mode、prepared identity、adapter/version、timestamp、fence epoch、reserved nonce 和 ACTION_INTENT；返回后持久化 ACTION_OUTCOME，再由 action outcomes 汇总 ItemOutcome。两者之间崩溃则 NEEDS_RECONCILIATION：

- source 仍为相同 identity：完整重新 preflight；authorization 仍有效且仅 transient failure 时可用新 attempt 重试；
- 已确认相同 identity 位于 Trash：补记成功；
- source missing 且 destination 无法确认：INDETERMINATE，不猜成功、不自动重试；
- source 位置出现不同 identity：STALE_IDENTITY，绝不删除新对象；
- source/destination 都有对象或跨卷残留：PARTIAL/INDETERMINATE，供审阅。

删除不是天然幂等。“路径不存在”不能证明上次成功。每次重试有新 attempt ID/nonce 并重新 preflight。取消在 action 边界生效；已经提交的 API 等待可用回调或进入 reconciliation。resume 只继续确定 PENDING 且从未 reserve nonce 的 action；RESERVED、STALE、INDETERMINATE 不自动继续。批次不回滚已成功 action。

## 13. 攻击与故障验收

| 场景 | 必须观察到的防御 | 剩余限制 |
|---|---|---|
| cache/imported 增加 path | 无法构建 permit；要求 live scan | 同 UID 可修改本地状态，仍需 preflight |
| Trash plan 改 Permanent | digest/mode/authorization 不符 | 本地 digest 不是远程信任证明 |
| force/config/plugin/direct API | core + adapter hard refusal | 测试覆盖每条入口 |
| root alternate spelling/alias | native identity/mount refusal | 平台 API 能力不足则全禁用 |
| protected marker symlink/权限拒绝 | no-follow presence 或 unknown 均 BLOCKED | marker 可造成保护性 DoS |
| target/parent/ancestor swap | identity/type/containment stale | 最后 check 后仍有极小 race |
| bind/mount/reparse swap | mount/tag snapshot stale | namespace 可继续变化 |
| 审批后注入 child | manifest mismatch，不调用 top-level Trash | pathname API 前有残余窗口 |
| hidden holder | negative 不授权，unknown 不降风险 | 普通用户视图不完整 |
| platform partial/aborted | per-item mixed audit | 无跨平台事务 |
| crash source missing | indeterminate，不算 success | destination 可能无稳定 locator |
| audit/SweepX self deletion | protected identity/anchor | 用户可在 SweepX 外操作自己的文件 |
| root/admin launch | destructive mode disabled | 只读扫描由产品另行决定 |

## 14. 平台实测与发布门槛

以下是待实测假设，不是保证。

### 14.1 通用矩阵

必须覆盖普通/空/非空/深目录，symlink、hard link、junction/reparse、mount/bind，sparse/compressed/clone/reflink，permission/read-only/vanish/long/raw filename，Trash unsupported/no-space/cancel/partial，target/parent/type/mount/link/descendant replacement，root aliases、marker inheritance，以及 force/yes/permanent/recursive/glob/config/env/plugin/direct-core 绕过。

在平台调用前、提交后、outcome sync 前做 fault injection；验证 mixed result、reconciliation、audit durability。占用测试覆盖 holder found、none observed、visibility denied、process vanished、open-unlinked。provider fixture 监控内容 hydration。审计/计划库不可写时不得动作。

ApprovalSurface 测试必须证明：native modal 是有图形会话时的首选，展示 exact plan、`N` items/`M` actions、risk/unknown/expiry，并要求 acknowledgement 后单独点击 destructive approval button；批准不会自动 execute。无合格图形会话才允许 trusted foreground TTY fallback，challenge 必须由当前 immutable full digest 与 selection/action counts 重算。stdin/pipe、后台或非 controlling TTY、RPC/SDK、插件、远程会话和 Agent 均不能批准；短 fingerprint 碰撞或篡改不能替代完整 256-bit digest 校验。

### 14.2 Windows 待实测

- IFileOperation flags、destruction warning、progress sink 和 GetAnyOperationsAborted 能否区分回收、直接销毁、取消和部分失败；不能区分即拒绝 Trash。
- held handle 的 share mode 不阻塞 Shell，又保持足够复验；否则缩短 handle lifetime并提高 race 告警。
- NTFS/ReFS/FAT/exFAT、UNC、OneDrive/offline、ADS、hard link、long path；symlink/junction/mounted folder/unknown tag 只作用于目录项。
- known-folder/volume root 识别非默认系统盘、volume-GUID、UNC share 和 mounted-folder alias。
- filtered admin 与 elevated token 判定符合 ordinary-user policy。
- 可选 UserConsentVerifier/Windows Hello 成功、失败、取消和异步返回后 plan/selection/TTL 变化均按同一 pending request 重新校验；普通成功不被当作 digest 签名，且确认路径不出现 UAC。

### 14.3 macOS 待实测

- trashItem 对 symlink 移动 link 本身；不能证明则禁用 symlink Trash。
- resultingItemURL 在 APFS、外接 exFAT、network、File Provider 的可用性；未知 destination 如实记录。
- Trash 不支持时不会静默永久销毁；无法确认则阻断。
- TCC、sandbox bookmark、已有 FDA、ACL 组合不绕过保护；signed/system volume 与 /Volumes root alias 拒绝。
- APFS clone/snapshot/provider 不出现精确释放承诺；lsof denial 为 unknown。
- 可选 LocalAuthentication 成功、失败、取消和异步返回后 plan/selection/TTL 变化均按同一 pending request 重新校验；普通成功不被当作 digest 签名，且确认路径不调用 Authorization Services。

### 14.4 Linux 待实测

- 最低 kernel 的 openat2/statx mount ID；缺少时明确禁用哪些目录/Permanent 能力。
- GIO unsupported/EXDEV/error 从不永久 unlink source。
- ext4/XFS/Btrfs、独立/bind/overlay/FUSE/NFS/removable/headless；mount namespace swap 失败关闭。
- freedesktop Trash 的恶意 symlink/非-sticky .Trash 即使未来实现也拒绝；v1 无手写 fallback。
- hidepid/namespace/LSM denial 为 unknown；manifest recursion 保留新 child 并返回 non-empty。
- 在 GUI 可用时使用 first-party native dialog；headless/无合格图形会话时使用 trusted foreground TTY。确认不调用 sudo/polkit，且无可信 surface 时 HumanApproval 不可用。

### 14.5 发布判定

某平台只有全部满足才启用 destructive mode：

1. root/system/home/SweepX/Trash/protected-file/marker 测试全部通过；
2. Trash 失败的所有路径均证明未调用 Permanent；
3. target/parent/ancestor/link/mount/descendant 替换均失败关闭；
4. force/config/plugin/direct adapter 绕过均 hard refuse；
5. crash recovery 不把 missing 当 success，逐项结果覆盖 partial/aborted；
6. 文案不把 heuristic、negative holder、allocated estimate、Trash success 写成安全保证；
7. 普通用户 runtime 检测和 audit durability 通过真实 OS 测试。

否则该平台只提供扫描、解释和计划导出，不提供执行。

## 15. 审计事件与关键不变量

事件至少有 SCAN_REFERENCED、CANDIDATE_EXPLAINED、PLAN_CREATED/REJECTED、AUTHORIZATION_HUMAN_GRANTED/REJECTED、AUTHORIZATION_EXPLICIT_DANGEROUS_DELETE、PREFLIGHT_STARTED/PASSED/STALE、HARD_PROTECTION_BLOCKED、ACTION_INTENT、ACTION_PLATFORM_RESULT、ACTION_RECONCILED/INDETERMINATE、ITEM_SUMMARIZED、BATCH_CANCELLED/COMPLETED、RECOVERY_STARTED/COMPLETED。

每条含 monotonic sequence、wall/monotonic time、previous digest、plan/authorization source+ID/item/attempt、policy/adapter version、user/host、requested/actual mode、identity/revalidation digest、risk、native error、destination/recovery/final state；不含文件内容。

最终不变量：

1. Candidate != Plan != ExecutionAuthorization != PreflightPermit。
2. destructive action 前必须有匹配 plan、HumanApproval 或 Permanent-only ExplicitDangerousDelete authorization、fresh revalidation、hard-protection Match 和 durable INTENT。
3. adapter 不接收任意路径；permit 一次、短期、模式不可变。
4. Trash 是默认；Trash failure 永不自动 Permanent。
5. Permanent 独立授权且不能绕过任何保护；危险 flag 只跳过确认。
6. root、protected path/file/marker、mount、unknown reparse、SweepX/Trash internal 永不可授权。
7. no-follow、same-mount 是共同下限；identity/parent/type/mount/manifest 变化即停止。
8. cache/imported/stale data 不授权；holder negative 不授权。
9. batch 非原子且逐项审计；missing/unknown/denied/unsupported 不等于 success。
10. Trash success 不等于容量释放或保证恢复；Permanent success 不等于 secure erase。

## 16. 证据边界

上游一手证据支持：Windows IFileOperation 的 undo 仅在可能时成立、操作可 aborted，Windows 8+ 的 `FOFX_RECYCLEONDELETE` 才提供明确 recycle-only 请求语义；macOS Trash API 与立即 removal API 语义不同；Linux Trash 是桌面规范而非统一 syscall，GIO 可返回 unsupported，跨 mount rename 为 EXDEV；三平台都有不同 identity/link/mount 语义；Unix open FD/mapping 可在 pathname unlink 后保留对象；Restart Manager、lsof、/proc 都是受权限和时序限制的观察。Windows UserConsentVerifier/Windows Hello 与 macOS LocalAuthentication 提供的是本机用户验证能力，不等于提升文件访问权限；它们的普通成功回调也没有接收并签名任意 SweepX plan digest 的合同。UAC、Authorization Services 和 polkit 属于权限/授权机制，不应被挪作单纯的删除确认 UI。

没有跨平台普通用户接口能够保证任意共享 extent 的精确释放量、所有 volume/provider 上永久可恢复的 Trash、完整 holder 视图、未来持续无人使用或无竞态 pathname Trash。因此最终失败关闭原则是：

    missing evidence -> risk never decreases -> report, skip, or re-plan
    missing evidence != zero bytes != unused != permission to delete
