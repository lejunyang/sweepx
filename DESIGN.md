# SweepX 总体设计

状态：设计基线与部分开发实现。设计与外部证据截点：2026-08-26；实现快照：2026-08-27。

本文把扫描、专项 Cleaner、CLI/TUI、人工审批和跨平台删除收束为一个安全核心。当前仓库已有开发级只读 CLI/TUI：Linux 与 macOS live scan 均为 `degraded`，Windows 只读 live scan 仍为 `unsupported`；另有只读解释与 Cleaner 元数据，以及 library-only 的不可变计划、simulation-only 授权、Unix 审计/恢复和确定性 fake execution。这些实现不代表阶段、发布或 mutation qualification；当前没有 native Trash/Permanent adapter、mutation CLI 或审批 UI，所有 native mutation capability 仍为 `disabled`。v1 只以当前普通用户身份工作，未通过真实平台发布门槛的能力必须保持 `report-only` 或只提供扫描、解释和计划导出。

## 0. 文档约定、范围与导航

### 0.1 证据标签

本文每个结论使用下列标签；不能把后一类伪装成前一类：

- **[事实]**：标准、厂商文档或固定上游源码直接支持。每个保留的网络事实都附直接 URL 和访问日期 `2026-08-26`。
- **[推导]**：从一个或多个事实得到的工程判断，不是平台或厂商保证。
- **[建议]**：SweepX 的规范性产品/架构选择；实现必须遵守，除非用新 ADR 显式替代。
- **[待实测]**：只有真实 OS/文件系统/版本测试通过后才能开放的能力。
- **[缺口]**：当前没有足够证据；默认 `unknown`、降级、跳过或阻断。

文案中的 `logical size`、`filesystem-reported allocated size`、`potentially reclaimable` 和动作后的 `caller-visible capacity delta` 是四种不同口径。`unknown`、`unsupported`、`not_checked`、`incomplete`、`lower_bound` 与数值 `0` 永远不同。

### 0.2 关联文档

- 产品入口与使用边界：[README.md](README.md)
- Cleaner 覆盖、位置、官方能力和风险：[docs/CLEANER-CATALOG.md](docs/CLEANER-CATALOG.md)
- 分阶段交付、测试和发布门槛：[docs/ROADMAP.md](docs/ROADMAP.md)
- 竞品与设计启示：[docs/research/landscape.md](docs/research/landscape.md)
- 三平台文件系统与 Trash：[docs/research/platform-filesystems.md](docs/research/platform-filesystems.md)
- 系统关键文件、swap/休眠/内核接口：[docs/research/system-protected-files.md](docs/research/system-protected-files.md)
- 系统级用户确认与身份复核：[docs/research/os-user-confirmation.md](docs/research/os-user-confirmation.md)
- 开发生态证据：[docs/research/developer-caches.md](docs/research/developer-caches.md)
- 常见应用缓存、日志与卸载残留：[docs/research/common-application-caches.md](docs/research/common-application-caches.md)
- 浏览器、站点存储和本地模型：[docs/research/browser-storage.md](docs/research/browser-storage.md)
- 扫描与缓存细化设计：[docs/architecture/scanner-and-cache.md](docs/architecture/scanner-and-cache.md)
- 安全删除细化设计：[docs/architecture/safety-and-deletion.md](docs/architecture/safety-and-deletion.md)
- CLI/TUI/插件协议：[docs/architecture/cli-tui-and-plugins.md](docs/architecture/cli-tui-and-plugins.md)
- Agent 操作协议：[skills/sweepx/SKILL.md](skills/sweepx/SKILL.md)

如专题文档和本文冲突，以本文的安全不变量和“冲突决议”章节为当前总设计；任何降低安全下限的变更必须同时更新本文、协议 golden tests 和威胁模型。

### 0.3 目标与非目标

**目标 [建议]**：Windows、macOS、Linux 同等作为一等平台；提供有界、可取消的元数据扫描，可解释 Cleaner，默认 Trash 的受控动作，CLI/TUI/Agent 共用的状态机，以及可重放审计和崩溃核对。

**非目标 [建议]**：

- v1 不请求管理员/root、UAC、`sudo`、polkit、Full Disk Access、backup privilege 或 Linux capability；不接管 ownership，不修改 ACL/TCC/immutable/read-only 属性。
- 不清空回收站，不提供 secure erase，不承诺 SSD、COW、snapshot、备份或云端副本不可恢复。
- 不把 imported/remote/stale/cache-only 报告变成动作依据。
- 不自动 kill 进程、关闭句柄、停止 daemon、改浏览器/企业策略、重置容器 volume 或卸载 SDK。
- 不用单个 atime/mtime、目录名、锁文件缺失或“未观察到 holder”证明 unused。

## 1. 产品结论与验收映射

### 1.1 一句话架构

**[建议]** SweepX 是“普通用户、内存优先的流式只读扫描器 + 稀疏摘要缓存 + 版本化证据规则 + 不可变计划 + 显式 ExecutionAuthorization + 紧邻动作复验 + 平台 Trash/Permanent adapter + 可核对审计”的单一核心；常规路径使用 HumanApproval，Permanent 另允许受约束的 ExplicitDangerousDelete，CLI、TUI 和 Agent 只是不同客户端。

### 1.2 验收覆盖

| 验收项 | 本文位置 | 深入材料 |
|---|---|---|
| 1. 文档结构与互链 | 0.2、17 | README、Catalog、Roadmap |
| 2. 竞品矩阵 | 2 | landscape |
| 3. 扫描/缓存/FS 语义 | 7、10 | scanner-and-cache、platform-filesystems |
| 4. 开发生态目录 | 8.1 | Cleaner Catalog、developer-caches |
| 5. 浏览器与本地模型 | 8.2 | browser-storage |
| 6. 四级风险与删除安全 | 6、9 | safety-and-deletion |
| 7. CLI/TUI/JSON/NDJSON | 11 | cli-tui-and-plugins |
| 8. Cleaner schema/生命周期 | 12 | cli-tui-and-plugins、Catalog |
| 9. AI Skill | 13 | skills/sweepx/SKILL.md |
| 10. Rust 工程/依赖/测试/路线 | 14、15、17 | Roadmap |
| 11. 来源和结论分类 | 0.1、18 | research 文档集 |

## 2. 竞品结论：借能力，不复制信任模型

下表仅保留影响架构的代表性事实；所有链接访问日期均为 **2026-08-26**。

| 类别/代表 | 已证能力与局限 [事实] | SweepX 推导与建议 |
|---|---|---|
| `dust` / `gdu` / `dua-cli` | 可做跨平台层级扫描；gdu/dua 使用并行路径，后两者提供 TUI。来源：[dust](https://github.com/bootandy/dust)、[gdu](https://github.com/dundee/gdu)、[dua-cli](https://github.com/Byron/dua-cli)（访问：2026-08-26） | 通用 walker 适合回答“空间在哪里”，不够回答“对象是否仍被引用”；并发必须有背压而不是每项一个 task。 |
| `ncdu` | 支持保存/导入扫描；导入结果禁用删除、刷新和 shell。来源：[ncdu 2.x manual](https://dev.yorhel.nl/ncdu/man/2_0)（访问：2026-08-26） | imported snapshot 永远 browse-only，是 SweepX 的硬边界。 |
| Czkawka | 一个 core 服务 CLI/GUI，并采用分阶段检测和缓存。来源：[upstream](https://github.com/qarmin/czkawka/blob/master/README.md)（访问：2026-08-26） | 多前端共享事实和安全决策，不能各自重算风险。 |
| BleachBit | preview/clean 使用同类 selector；CleanerML 是声明式规则系统，但也含高风险动作。来源：[CLI](https://docs.bleachbit.org/doc/command-line-interface.html)、[CleanerML](https://docs.bleachbit.org/cml/cleanerml.html)（访问：2026-08-26） | 采用受限 typed rule；不复制任意删除、shred 或自由 shell 能力。 |
| BleachBit / CCleaner / CleanMyMac 的浏览器数据能力 | 这些产品按产品与平台区分 cache、history、cookie、session/site data 等类别；BleachBit 与 CCleaner 还提供 cookie 保留能力。来源：[BleachBit documentation](https://docs.bleachbit.org/)、[CCleaner cookie retention](https://support.ccleaner.com/articles/en_US/Master_Article/select-cookies-to-clean-with-ccleaner-for-windows)、[CleanMyMac Privacy](https://macpaw.com/support/cleanmymac/knowledgebase/privacy)（访问：2026-08-26） | 不提供一个笼统的“浏览器垃圾”开关；按 browser/profile/storage type 展开并保留 keep list。IndexedDB、Cache Storage、Service Worker 和登录态属于应用状态，不能按普通 HTTP cache 风险处理。 |
| QDirStat / rmlint | 前者允许用户定义外部 cleanup action；后者生成可审阅动作脚本。来源：[QDirStat](https://github.com/shundhammer/qdirstat/blob/master/README.md)、[rmlint cautions](https://rmlint.readthedocs.io/en/latest/cautions.html)（访问：2026-08-26） | 可审阅中间产物值得保留；任意命令必须在独立、更高信任域，v1 Cleaner 不提供。 |
| Kondo / cargo-cache | 能按项目或 Rust 语义识别构建产物/缓存。来源：[Kondo](https://github.com/tbillington/kondo)、[cargo-cache](https://github.com/matthiaskrgr/cargo-cache/blob/master/README.md)（访问：2026-08-26） | 类型化 Cleaner 要保存 owner、引用、恢复成本和活动证据，不按目录名直接删。 |
| Docker / pnpm / uv | 原生命令使用 daemon/包管理器自己的对象或引用语义。来源：[Docker df](https://docs.docker.com/reference/cli/docker/system/df/)、[pnpm store](https://pnpm.io/cli/store)、[uv cache](https://docs.astral.sh/uv/concepts/cache/)（访问：2026-08-26） | 原生 inventory/GC 语义通常优于裸路径；但命令是否零写入必须单独证明。 |
| WizTree | Windows NTFS 的快速路径依赖平台特化条件。来源：[WizTree guide](https://diskanalyzer.com/guide)（访问：2026-08-26） | 可增加平台 fast path，但 portable walker 和共同安全语义始终是基线；v1 普通用户不启用需提权的 MFT 路径。 |
| DaisyDisk | 提供可视化收集/审阅并阻止若干根目录动作；其 size 与删除行为是 macOS 特化。来源：[delete guide](https://daisydiskapp.com/guide/deleting-files)、[APFS guide](https://daisydiskapp.com/guide/apfs)（访问：2026-08-26） | 候选篮和风险 review 可借鉴，物理占用结论不能跨平台外推。 |
| 商业系统清理器 | CCleaner、CleanMyMac、PC Manager 能按应用类别清理，但能力随平台、版本和渠道变化。来源：[CCleaner policy](https://www.ccleaner.com/legal/products-policy)、[CleanMyMac System Junk](https://macpaw.com/support/cleanmymac-x/knowledgebase/system-junk)、[PC Manager](https://pcmanager.microsoft.com/en-us)（访问：2026-08-26） | 商业能力只作为带日期快照；不以营销性能、安全或“彻底删除”措辞做保证。 |

**[推导]** 没有一个现成工具同时提供跨平台扫描、领域引用判断、可信物理释放量、默认可恢复动作、不可绕过保护、TUI 和可审计插件。**[建议]** SweepX 不追求“一键万能清理”，而是把事实、推导、建议、授权和实际结果逐层隔离。

## 3. 组件与信任边界

```text
                         不可信 / 低信任
  CLI renderer       TUI virtual client       Agent / JSON client
       \                    |                       /
        +------------ versioned Core API ----------+
                               |
  signed Cleaner pkg -> typed Rule VM -> Detect / Analyze
        (来源证明)       (无 I/O)       (只产生 Evidence)
  first-party probe --------------------^  (隔离、只读、能力受限)
                               |
                               v
  live Scanner -> Candidate Builder -> Explanation / Risk
       |                 |                    |
       | cache: preview  |                    v
       | only            +----------> Immutable Planner
       |                                      |
       |                          canonical plan + digest
       |                                      v
       +------------------------ Authorization Gate
                          human approval | explicit dangerous flag
                                              |
                                sealed execution authorization
                                              v
  private Audit Fence -> live Preflight -> one-shot Permit
                                              |
                                   serial Core Executor
                                              |
                    Windows / macOS / Linux DeletionAdapter
                                              |
                     platform result -> Reconciler -> Audit
                         最高信任，但仍仅普通用户权限
```

### 3.1 五层信任模型

1. **输入/呈现层不可信**：路径文本、排序、筛选、翻译、Agent、导出 JSON 只能请求查询或引用 ID，不能提交任意删除 path、approval body、permit 或 mode override。
2. **Cleaner 层受限**：签名只证明来源/完整性；规则只能产生 evidence/proposal、维持或提高风险。第三方不得带 native mutation adapter。
3. **Scanner 是事实边界**：只有本机、本用户、本次 live admission、no-follow 观察能建立 Candidate。缓存、历史和 imported report 没有授权含义。
4. **Planner/Authorization 是意图边界**：Planner 独占 canonical plan 构造。Broker 构造可信交互产生的 Human Approval；Core admission 可为显式 `--dangerously-delete` 构造独立 DangerousDeleteRecord。后者证明调用者显式传参，不证明调用者是人。两者都只表达对精确计划的执行意图，不证明对象未变。
5. **Preflight/Executor 是动作边界**：permit 只能由安全核心在现场复验后创建；adapter 只接收 sealed permit 和绑定 native basename，不接受任意路径、argv、recursive 或 force bit。

### 3.2 Rust 类型必须表达的边界

**[建议]** `Candidate`、`DeletionPlan`、`ExecutionAuthorization`、`PreflightPermit` 和 `ActionOutcome` 使用不同的非可互转类型；`ExecutionAuthorization` 是 `HumanApproval(ApprovalRecord)` 或 `ExplicitDangerousDelete(DangerousDeleteRecord)` 的封闭枚举。`PreflightPermit` 字段私有、不可 `Serialize`/`Clone`，构造函数和 `DeletionAdapter` 均为 safety crate 内部可见。公开 API 不暴露 `delete(path)`。

## 4. 核心数据模型与序列化

### 4.1 Tagged value 与无损路径

```rust
enum EvidenceValue<T> {
    Known(T),
    LowerBound { value: T, reason: Reason },
    Unknown { reason: Reason },
    Unsupported { reason: Reason },
    NotChecked { reason: Reason },
}

enum FieldProvenance {
    LiveObservation { observed_at: Timestamp, method: MethodId },
    ValidatedCache { observed_at: Timestamp, validation: MethodId, token: Digest },
    DerivedFromCurrent { inputs: Vec<FieldId>, algorithm: Version },
    StalePreview { observed_at: Timestamp },
    Unknown { reason: Reason },
}
```

Unix basename 以原始 bytes 保存，Windows 以 UTF-16 code units 保存；wire format 分别使用带类型标签的 unpadded base64url。`display_path` 只显示，不参与定位、digest 或动作。byte/count/sequence 统一用十进制字符串承载 `u128`，checked arithmetic 溢出变 `Unknown(overflow)`。

### 4.2 扫描和分析对象

```text
ScannedEntry {
  schema/scanner/adapter versions, scan_id, root_identity, timestamp,
  provenance{admission=Live, fields{}}, display_path,
  parent_identity, native_basename, object_type,
  object_identity?, filesystem_object_domain_identity?, mount_identity?,
  link_or_reparse_kind?, link_payload_digest?, hard_link_count?,
  logical_bytes, allocated_bytes, reclaimable_estimate, confidence,
  cloud_or_offline_state?, metadata_fingerprint, boundary?, errors[]
}

DirectoryAggregate {
  scan_id, directory_identity, revision,
  apparent_logical, unique_logical, filesystem_reported_allocated,
  potentially_reclaimable, counts, skipped, errors, boundaries,
  complete, incomplete_reasons[], provenance, arithmetic_state
}

Candidate {
  candidate_id, candidate_digest, source=local_current_live_scan,
  lossless locator recipe + all scan identities,
  tagged sizes, coverage, final aggregate revision?, rule/evidence IDs,
  facts[], inferences[], heuristics[], uncertainties[], risk_floor
}

Explanation {
  candidate_digest, facts[], manager_facts[], inferences[], heuristics[],
  unknowns[], size_meanings, blockers, default_action,
  recovery_expectation, redownload_or_rebuild_cost, risk
}
```

目录 Candidate 必须连接同一 `scan_id/root identity/object identity` 的最终 `DirectoryAggregate`；revision 缺失/不符或 `complete=false` 时只可解释，不可进入目录 PlanItem。

### 4.3 不可变计划、审批和现场许可

```text
DeletionPlan {
  schema=sweepx.plan/v1, plan_id, nonce, created_at, expires_at,
  host_instance_id, user_identity, scan_id, scan_root_identity,
  mode=Trash|Permanent, candidate/scanner versions,
  safety_policy_version+digest, protected_anchor_snapshot_digest,
  adapter_capabilities_digest, cleaner_set_digest,
  items[], aggregate_risk, canonical_digest
}

PlanItem {
  item_id, candidate_id, explanation_digest, action_kind,
  top_level_action_id, parent_reopen_recipe, native_basename,
  expected parent/object/object-domain/type/mount/link identities,
  expected_metadata_fingerprint, subtree_complete,
  descendant_manifest?, cleaner_evidence_digest?, official_action_digest?,
  risk_tier, risk_factors[], recovery_expectation
}

ApprovalRecord {
  approval_id, plan_id+digest, exact mode/item/action sets and counts,
  approved_risk_by_action, descendant_manifest digests,
  policy/anchor/cleaner digests, user/host/workflow session,
  human channel, approved_at, expires_at, confirmation evidence,
  single-use nonce, UNUSED|CLAIMED(epoch)|CONSUMED
}

DangerousDeleteRecord {
  authorization_id, source=ExplicitDangerousDelete, plan_id+digest,
  exact mode=Permanent, item/action sets and counts, risk_by_action,
  descendant/policy/anchor/cleaner digests, user/host/workflow session,
  invoked_at, expires_at, single-use nonce, UNUSED|CLAIMED(epoch)|CONSUMED
}

ExecutionAuthorization = HumanApproval(ApprovalRecord)
                       | ExplicitDangerousDelete(DangerousDeleteRecord)

RevalidationRecord {
  plan/item/action, runtime user state, root+ancestor+parent+object identities,
  type/mount/link/fingerprint, live policy/anchors, protection result,
  manifest/cleaner result, observed-open state, Match|Stale|Blocked
}

PreflightPermit {
  private: plan/item/action/authorization/mode/risk/digests,
  final identities, held parent/object handles, validated_at/expires_at,
  fence epoch, revalidation digest, one-shot nonce
}
```

**[建议，补足上游实现缺口]**：

- canonical form 为 RFC 8785 JSON；网络标准来源：[RFC 8785](https://www.rfc-editor.org/rfc/rfc8785)（访问：2026-08-26）。所有大整数和 native names 已先编码为字符串，避免 JSON number 歧义。
- `canonical_digest = SHA-256("SweepX plan v1\0" || JCS(plan without canonical_digest))`。其中 `\0` 表示一个 NUL byte；排序在模型层固定，UI 顺序不参与。
- plan 默认 TTL 10 分钟且 v1 无延长 flag；Approval TTL 最大 5 分钟；Permit TTL 最大 2 秒。任何一个过期都失败关闭。
- 人类可见 fingerprint 为 `SX1-` 加 full digest 前 12 个大写十六进制字符，仅用于对照、诊断和终端 fallback 的注意力检查；它不是授权或密码。安全校验始终比较完整 256-bit digest。
- Trash 与 Permanent 不混批；target、顺序、mode、risk、policy、anchor、adapter、Cleaner set 或 descendant manifest 任一变化都创建新 plan。

### 4.4 Outcome 与审计

```text
ActionOutcome {
  plan/authorization/item/action/attempt IDs,
  requested_mode, actual_platform_operation, risk and versions,
  start/end, preflight digest, platform operation/result/error,
  aborted/cancelled, resulting_trash_locator?, recovery_state,
  source/destination postchecks, optional capacity before/after,
  stable status, notes[]
}

AuditEvent {
  monotonic sequence, wall+monotonic time, previous_digest,
  all relevant IDs/digests, requested/actual operation,
  native result, reconciliation state
}
```

Audit 保存 intent 与事实结果，不把请求写成成功。日志不存文件内容；路径属于敏感数据，默认导出使用每次导出的稳定 pseudonym。hash chain 只能检测部分本地损坏，不能宣称抵抗同一用户主动篡改。

## 5. Core API 草图

```rust
trait SweepxService {
    fn start_scan(&self, req: ScanRequest) -> Result<OperationId>;
    fn explain(&self, scan: ScanId, ids: &[CandidateId]) -> Result<Vec<Explanation>>;
    fn create_plan(&self, req: CreatePlanRequest) -> Result<PlanRef>;
    fn show_plan(&self, id: PlanId) -> Result<PlanView>;
    fn request_human_approval(
        &self,
        id: PlanId,
        channel: TrustedForegroundConsole,
    ) -> Result<OpaqueApprovalId>;
    fn authorize_dangerous_delete(
        &self,
        plan: PlanId,
        intent: ExplicitDangerousDelete,
    ) -> Result<ExecutionAuthorization>;
    fn execute(&self, plan: PlanId, authorization: ExecutionAuthorization)
        -> Result<OperationId>;
    fn cancel(&self, operation: OperationId) -> Result<CancelDisposition>;
    fn recover(&self, batch: BatchId, mode: RecoverMode) -> Result<OperationId>;
    fn status(&self, query: StatusQuery) -> Result<Snapshot>;
    fn events(&self, operation: OperationId, after: Option<Cursor>) -> EventStream;
}

trait ScanPlatformAdapter {
    fn admit_root(&self, root: NativeRoot) -> Result<AdmittedRoot>;
    fn enumerate(&self, dir: &DirHandle, sink: &mut dyn EntrySink) -> Result<CloseMarker>;
    fn metadata_no_follow(&self, parent: &DirHandle, name: &NativeName)
        -> Result<ScannedEntry>;
    fn mount_snapshot(&self) -> Result<MountSnapshot>;
}

// crate-private + sealed；没有公开任意 path API。
trait DeletionAdapter: sealed::Sealed {
    fn trash(&mut self, permit: TrashPermit) -> PlatformAttempt;
    fn permanent_delete_one_nonrecursive(
        &mut self,
        permit: PermanentPermit,
    ) -> PlatformAttempt;
    fn reconcile(&mut self, intent: &DurableIntent) -> Reconciliation;
}
```

`CreatePlanRequest` 只接受同一 live scan 的 candidate IDs 或 content-addressed selection set。CLI 的 `--approval-id` 解析为 `HumanApproval`；`--dangerously-delete` 解析为 `ExplicitDangerousDelete` 并只允许已有、未过期的 Permanent R4 plan。Core 不把后者伪装成 Human Approval，而是生成/封存独立、同样绑定 exact plan 和 single-use nonce 的 `DangerousDeleteRecord`。CLI 无法可靠识别“调用者是人还是拥有 PTY 的 Agent”，因此安全边界不依赖调用者身份；Agent 禁用该 flag 是 Skill policy。两种授权都不接受 path、mode、额外 item、retry、policy override 或 arbitrary argv。

## 6. 端到端生命周期、状态与不变量

### 6.1 唯一生命周期

```text
live scan
  -> Candidate
  -> Explanation
  -> immutable DeletionPlan + canonical digest
  -> exact execution authorization
       |-- HumanApproval (trusted interactive Broker)
       `-- ExplicitDangerousDelete (explicit flag, Permanent only)
  -> live no-follow revalidation
  -> durable ACTION_INTENT
  -> final parent+basename check
  -> one-shot PreflightPermit
  -> Trash OR Permanent adapter
  -> source/destination reconciliation
  -> ActionOutcome / ItemOutcome
  -> durable audit
```

Cleaner 只参与 `detect -> analyze -> proposal`；`plan -> approve -> execute` 永远由 core 拥有。这是对“Cleaner detect/analyze/plan/execute 生命周期”的安全解释：插件可在每阶段收到只读通知，但没有 plan constructor、approval、permit 或 execute hook。

### 6.2 规范状态机

批次：

```text
DISCOVERED -> EXPLAINED -> PLANNED -> AUTHORIZATION_PENDING -> AUTHORIZED
  -> REVALIDATING -> READY -> EXECUTING
  -> COMPLETED | PARTIAL | CANCELLED | NEEDS_RECONCILIATION
any applicable nonterminal -> REJECTED | HARD_BLOCKED
each terminal T -> AUDITED(terminalOutcome=T)
```

单项：

```text
CANDIDATE -> EXPLAINED -> IN_PLAN -> AUTHORIZED -> REVALIDATING
  -> PREFLIGHT_READY -> TRASHING | PERMANENT_DELETING
  -> SUCCEEDED | FAILED | SKIPPED | STALE | CANCELLED | INDETERMINATE
any applicable nonterminal -> REJECTED | HARD_BLOCKED
each terminal T -> AUDITED(terminalOutcome=T)
```

`AUDITED` 是包装状态，必须保留原 terminal outcome；它不能把 `PARTIAL` 或 `INDETERMINATE` 改写成成功。`STALE` 必须回到 live scan，不能复用旧 plan/authorization/permit。

### 6.3 精确执行顺序

1. 检查 audit store 可 append+sync、当前 runtime 为普通用户、plan/authorization/policy/anchor/cleaner/capability digest 完全匹配。
2. 获取 non-expiring OS batch lock；事务性 CAS authorization `UNUSED -> CLAIMED(epoch) -> CONSUMED`。只有内核确认旧进程释放锁，recovery 才能取得更高 fence epoch。
3. 按 canonical 稳定顺序串行处理 action：重新打开 root、祖先、parent 和 exact native basename；全程 no-follow。
4. 比较 root/ancestor/parent/object/object-domain/type/mount/link/fingerprint/containment；检查所有保护 anchor 和 marker；目录重新匹配封闭 manifest；必要时重跑 Cleaner evidence。
5. best-effort 观察 holder，重算该 action 风险；`runtime_risk <= authorization.risk_by_action[action_id]`，不能借同批更高风险额度。
6. 原子 reserve 新 action nonce，持久化并 sync `ACTION_INTENT`。
7. 紧邻动作做最终 parent+basename no-follow 复验；此后到 adapter call 之间不得插入 UI、网络、缓存、Cleaner、holder query 或新的 durable I/O。
8. 在内存签发最长 2 秒、一次性的 mode-specific permit；adapter 入口再次验证 batch lock、fence、policy/anchor digest 和 nonce。
9. 调用恰好一个平台动作；permit 无论成功失败都消费。记录 platform/native result，并核对 source/destination。
10. sync `ACTION_OUTCOME` 后才能进入下一 action；最后由 durable outcomes 汇总 ItemOutcome 和 batch 状态。

Trash 目录是一个 top-level platform action，但动作前必须完整重验 descendant manifest。Permanent 目录则把每个 descendant 变成独立 action，按 postorder 执行，root 最后；新出现的 child 不删除，最终返回 `FAILED_NOT_EMPTY_AFTER_APPROVED_CHILDREN`。

取消只阻止下一次尚未提交的平台动作。`ACTION_INTENT` 后崩溃、取消或返回不明时先 reconcile；reserved nonce 不重放。source missing 且 destination 未确认是 `INDETERMINATE`，不是成功。批次非事务性，已经成功的 item 不自动回滚。

### 6.4 不可破坏的全局不变量

1. `live fact != inference != Candidate != Plan != ExecutionAuthorization != Permit != Outcome`。
2. 缓存、imported、remote、stale preview 永远不能授权删除。
3. 路径不是身份；display path 不是执行参数。
4. 默认 Trash；Trash unsupported/denied/full/cancelled/ambiguous 永不转 Permanent。
5. Permanent 永远 R4、独立计划、独立批次和显式执行授权；常规人类审批与 `--dangerously-delete` 都不能绕过硬保护；它不是 secure erase。
6. no-follow、same-mount/volume、errors-visible、ordinary-user 是三平台共同下限。
7. 硬保护在 plan、authorization、preflight、core executor 和 adapter 重复执行，任何 flag/config/env/plugin/direct API 均不可绕过。
8. negative holder observation 不授权；unknown 只维持/提高风险。
9. destructive action 前必须有匹配 plan、有效 ExecutionAuthorization、fresh revalidation、durable intent 和 fresh permit；ExplicitDangerousDelete 仅对 Permanent 有效。
10. 每项结果独立审计；missing/unknown/unsupported/denied 不等于 success。

## 7. 扫描、实时聚合与增量缓存

### 7.1 有界管线

```text
RootSpec
 -> live root/mount admission
 -> bounded DirTicket queue
 -> fixed platform enumerators
 -> bounded EntryStub queue
 -> fixed no-follow metadata workers
 -> bounded ScannedEntry queue
 -> boundary/identity/size accounting
 -> bounded AccountedDelta queue
 -> single logical aggregate sequencer
 -> bounded CacheMutation queue -> transactional cache writer
 -> coalesced ProgressSnapshot -> CLI/TUI
```

每个 message 有唯一 owner；每个可增长对象必须先取得 byte permit。正常路径以内存流式聚合为主；只有 charged memory 达到 75% 高水位、compact/evict 后仍不能取得 permit 才延迟创建有界 spill，否则显式 `ResourceLimit/incomplete`。阻塞本地调用在固定 blocking pool；network/FUSE/provider 在独立 slow lane/helper。禁止每 entry 创建线程/future，也禁止超时后补建 worker。

### 7.2 默认界限

| 资源 | 默认硬界限 |
|---|---:|
| metadata workers | `min(32, 4 × logical CPUs)` |
| 同一本地 volume 活跃调用 | `min(8, logical CPUs)` |
| network/FUSE/provider | 每 volume 1；全局 helper/quarantine 4；deadline 30 s |
| 打开的目录枚举器 | 64 |
| root quantum | 256 entries 或 10 ms |
| metadata batch | 128 entries 或 256 KiB |
| local call soft deadline | 5 s |
| local quarantine | 每 volume 8、全局 32，不补 worker |
| retries | 仅明确 transient I/O，最多 2 次，50/200 ms + 0–25% jitter，仍受原 deadline |
| depth/native path representation | 4096 / 64 KiB |
| 队列 count | DirTicket 4096；EntryStub 16384；ScannedEntry/Delta 8192；CacheMutation 4096 |
| backpressure low-water | 70% |
| progress | 每 key 最多 10 Hz；4096 keys / 16 MiB |
| terminal lane | 1024 messages / 2 MiB；terminal 不丢 |
| correctness detail/event journal | 32 MiB / 50,000 details；1 s transaction；256 KiB emergency segment |
| tree-dependent scanner memory | `B_scan=128 MiB` |
| parent + all helpers private RSS | 经平台验证后 `<=384 MiB` |
| PendingDirectoryState | 32,768 records 或 16 MiB |
| scanner spill | 内存高水位后才创建；192 MiB/operation、256 MiB global |
| sparse preview cache | 64 MiB 或 100,000 summary records；不持久化普通小文件明细 |

按 volume 分组的 deficit round-robin 保证多个 root 公平；深目录用显式 frame，宽目录流式枚举。取消请求目标在 250 ms 内停止新 root/目录 admission；无法取消的调用留在原 quarantine slot，迟到结果与已终止 generation 隔离。终态必须报告仍待 OS 回收的调用数，不能谎称全部线程已经停止。

### 7.3 文件系统语义

- symlink 只记录 link 本身；所有 Windows directory reparse point 默认边界。v1 没有 follow-links opt-in。
- root admission 固定 root identity、object-domain identity、mount/volume identity 和 mount snapshot。nested/bind/mounted-folder/network/FUSE/automount/pseudo/container/provider/read-only system volume 只列 boundary；额外位置必须作为显式新 root。
- hard link 只在 object identity 可比较的 aggregate scope 去重；存在范围外 link 时 reclaimable 为 0 或 unknown，而非重复相加。
- sparse/compression/ADS/APFS clone/reflink/dedup/snapshot/overlay/thin provisioning 会让 allocated 不等于独占释放量；没有 extent 独占证据就保持 reclaimable unknown。
- 权限、TCC/ACL/LSM、provider offline、vanished race、timeout 均成为结构化错误和 coverage；祖先为 lower bound、`complete=false`，siblings 可继续。
- metadata-only 默认不打开内容、不 hash、不主动 hydrate cloud placeholder。

### 7.4 实时聚合

每个 entry 获得 scan-local sequence 和幂等 `delta_id`。single logical sequencer 保证 completion order 不影响最终结果。apparent size 按名称累计；unique size 按当前目录 subtree 的 identity union 计算，不能用全局 first-seen 代替每个目录的集合。

扫描以目录 accumulator 向祖先传播 delta；UI 对每个已展开 parent 只保留 exact top-64 heavy children 和一个不可选择、不可计划的 `Others` 聚合。普通小文件不因此生成持久明细。浅层预枚举只能得出 direct-child count 和已完成观察的递增 lower bound，不能知道递归总量；进入目录会优先 live 展开并发布新 revision。

hard-link 去重为每个可比较 identity 保留最小、仅本 operation 存活的 accounting state；它不是文件明细 cache。实际 `nlink>1`、重复 identity 或扫描中 link-count 转换再升级为 exception evidence，并在相应 sibling/ancestor/root scope 修正。必要的 identity/frontier/pending state 只有在 `M_variable_charged` 经 compact/evict 后仍达到 96 MiB high-water 时才 spill，降到 64 MiB low-water 前保持 spill 模式；无法保留精确状态或观察矛盾时相关 unique/allocated/reclaimable 变 unknown，不能近似为精确。Bloom filter 最多省查询，不能决定硬链接计数。

`complete=true` 仅在目录正常关闭、所有已枚举 child 有终态、无未进入 boundary/权限/超时/取消/资源降级，且参与的缓存字段已在本 generation 验证时成立。

### 7.5 缓存信任边界

v1 sparse preview cache 只做：

- 启动时显示有水印的 `StalePreview`；
- 用 change hints 和旧索引安排 dirty-first 顺序；
- 保存 roots/必要祖先、目录摘要、每 parent top-64、默认 `>=32 MiB` heavy leaf、Candidate 和 error/boundary；普通小文件只贡献 aggregate，不单独持久化；
- 当前 live 输入完全一致后，复用纯派生排序/聚合摘要；
- 减少数据库重建/排序，不承诺减少文件系统 metadata query。

每次进入的目录仍 live 枚举；每个 entry 仍 live no-follow 查询 identity/type/mount。allocation/provider/link-count v1 一律现场查；USN/FSEvents/inotify/fanotify 仅是 dirty hint。旧 DirectoryAggregate 永不整体升级为本次 complete。cache corrupt/lock/quota/write timeout 打开 circuit breaker、隔离 building generation并继续 cold/live scan；缓存失败绝不能放宽扫描或删除语义。

cache key 分为 `GenerationKey(host,user,root,mount snapshot,versions,policy)`、`ObjectKey(platform,object-domain,file identity)` 和 `PathIndexKey(root,parent,native basename)`，不得用 normalized path、mtime/ctime/size 冒充身份。`Others` 不是对象或 Candidate；若用户要查看或选择已淘汰明细，必须 targeted live rescan，目录删除计划仍须生成完整封闭 descendant manifest。

## 8. Cleaner 领域模型

### 8.1 开发者缓存与工具链

**[推导]** “目录名是 cache”不等于对象可回收；跨生态也不存在能证明所有用户、分支、容器、VM、CI、远程 worker 和离线介质都不再引用某对象的统一查询。**[建议]** 每项 Cleaner evidence 必须保存 owner、规范路径来源、对象类别/粒度、项目引用、活动信号、激活状态、管理器状态、恢复条件、共享/并发、confidence、risk、supported action 和 uncertainties。

| 类别 | 示例 | v1 默认处置 |
|---|---|---|
| A 可再生项目输出/缓存 | Cargo `target`、Go build cache、pip wheel/HTTP cache、Derived Data | 完整、静止、可重建且非共享时 R1–R2，可提出 filesystem Trash |
| B 共享/内容寻址 store | pnpm store、NuGet global packages、Cargo registry、镜像层、BuildKit/Bazel cache | R2–R3；需要管理器 reachability/GC 证据，v1 通常只建议 manager 操作 |
| C 已安装依赖/环境 | `node_modules`、venv、Conda env、Ruby gems、Composer `vendor` | R3；不是通用缓存，只报告或按明确项目重建流程处理 |
| D SDK/toolchain/global tool | JDK、.NET SDK、rustup、Node/Python、Android SDK、Xcode component | R3；只建议所有者卸载，系统/共享项可 BLOCKED |
| E 用户/运行/发布状态 | container volume、AVD user data、Xcode archive、签名材料、源码、凭据 | R3/BLOCKED；若未来不可逆动作则 R4，v1 report-only |

Catalog 必须逐项覆盖：Node/npm/pnpm/Yarn/Corepack/nvm；Python/pip/uv/Poetry/Conda；Rust/Cargo/rustup；Go；Java/JDK/Gradle/Maven；.NET/NuGet/MSBuild；Ruby/RubyGems/Bundler；PHP/Composer；Dart/Flutter；Android SDK/AVD；Xcode/Simulator/Derived Data；Docker/containerd/Podman；BuildKit、Bazel、CMake、ccache、sccache、Ninja。具体位置、官方命令、平台差异和版本依据集中在 [Cleaner Catalog](docs/CLEANER-CATALOG.md) 与 [开发缓存研究](docs/research/developer-caches.md)。

**查询副作用分级 [建议]**：

| 等级 | 允许行为 | v1 策略 |
|---|---|---|
| Z0 | 读取已存在的 manifest/lock/config/metadata 和文件属性，不启动生态工具 | 默认且自动允许 |
| Z1 | 业务上只读，但可能初始化状态；固定 binary/argv，在无网络、可丢写区、写监控和 timeout 下查询 | 仅逐 descriptor `--allow-guarded-query` opt-in |
| Z2 | 可能启动 daemon、下载 wrapper/plugin、刷新 metadata 或写真实 cache | 自动扫描禁止，只报告 |
| M | clean/prune/remove/uninstall/reset/策略变更 | v1 Cleaner 不执行；只生成 `managerPermanentRecommendation` |

`semanticReadOnly` 与 `zeroWriteVerified` 必须分列。npm cache、pnpm store、uv cache、Cargo GC、Conda clean、Docker/BuildKit 等官方能力的具体事实和来源见 Catalog；例如 npm 官方说明 cache 一般无需清空且 `verify` 会做验证/GC，来源：[npm-cache](https://docs.npmjs.com/cli/v11/commands/npm-cache/)（访问：2026-08-26）；pnpm 提供 store prune，来源：[pnpm store](https://pnpm.io/cli/store)（访问：2026-08-26）；Docker 的 `system df`/prune 使用 daemon 对象语义，来源：[system df](https://docs.docker.com/reference/cli/docker/system/df/)、[pruning](https://docs.docker.com/engine/manage-resources/pruning/)（访问：2026-08-26）。这些能力仍不是 SweepX 的自动授权。

### 8.2 常见应用缓存、日志与残留

常见应用没有可安全复用的“扫几个固定目录”规则。产品 channel、沙箱、portable/custom data root、应用配置和版本都会改变位置；同一个 vendor root 往往混有 cache、设置、凭据、会话、本地历史、插件、离线内容或用户产物。**[建议]** SweepX 只从版本化 vendor 文档、应用配置/manifest、known-folder API、官方 UI 或卸载 receipt 建立 owner evidence，永不凭目录名反推“已卸载残留”。完整一手资料矩阵见 [常见应用缓存、日志与残留研究](docs/research/common-application-caches.md)。

| 应用族 | 已证的优先控制 | v1 默认处置 | 关键排除项 |
|---|---|---|---|
| JetBrains、Steam、Spotify | 应用自己的 invalidate/clear cache | manager recommendation；不模拟为裸删 | Local History、游戏/Workshop、离线下载 |
| Teams、Slack、Zoom | reset/reinstall/cache UI 可能同时修改设置或会话 | R3/R4 report-only 或 manager recommendation | personalization、cookies/session、recordings、support bundle |
| Adobe Premiere/After Effects | Media/Disk Cache UI | R2 manager recommendation | project/source/proxy/autosave、共享 media DB |
| VS Code | `--user-data-dir` 与 Open Logs Folder 只提供 scope/evidence | closed log 可 R2；整个 user-data root R3 report-only | settings、workspace state、backup、extensions |
| Adobe install state | Creative Cloud uninstaller/Cleaner Tool | R4 manager-only recommendation | credentials、plugins、profiles、shared components |

日志只在能证明 exact owner、closed rotation/session group、无 writer、无 support/compliance retention 时才可能成为 R2 Trash 候选；current log、诊断 bundle、cloud-sync evidence 或 holder coverage unknown 均 R3/report-only。官方 `clear/reset/prune` 属 M mutation：v1 只展示精确 vendor 路径与副作用，不代替用户执行。

### 8.3 浏览器、按站点存储和本地模型

#### Profile 发现

- **[事实] Chromium**：Profile 是 User Data 根下的子目录，真实路径优先由版本页/运行实例确认；channel、命令行、环境或策略可改写。来源：[Chromium User Data Directory（固定 commit）](https://github.com/chromium/chromium/blob/c551499a894d32bd04a882a0beae53d854e28ba2/docs/user_data_dir.md)（访问：2026-08-26）。
- **[事实] Firefox**：一个逻辑 Profile 可有持久 `ProfD` 和本地缓存 `ProfLD`，应优先从 `about:profiles`/Profile Service 与配置解析。来源：[Firefox Profiles Service](https://firefox-source-docs.mozilla.org/toolkit/profile/index.html)（访问：2026-08-26）。
- **[事实] Safari**：Safari 17+ 的 Profile 是产品管理的逻辑边界；公开资料没有提供稳定的“Profile 显示名到磁盘目录”契约。来源：[Apple Safari Profiles](https://support.apple.com/en-us/105100)、[WebKit Profiles API](https://webkit.org/blog/14423/building-profiles-with-new-webkit-api/)（访问：2026-08-26）。**[建议]** 未有版本 adapter 证明映射时为 `logical/unresolved`，只引导 Safari UI，不做 raw per-profile plan。

#### 数据类别和完整存储键

| 类别 | 例子 | 清理含义 |
|---|---|---|
| 可重建缓存 | Chromium HTTP/Code Cache、Firefox HTTP/startup cache、WebKit NetworkCache | Profile 静止、layout 已验证、完整目录 manifest 时可成为 R2 Trash 候选；可能重下载/重编译 |
| 应用状态 | Cache Storage、IndexedDB、Local Storage、Service Worker 注册/脚本 | R3/report-only；必须按一致性组和版本 adapter 处理，不能因名称含 cache 降风险 |
| 登录/隐私状态 | cookies、session restore、password、autofill、history/download history | 默认不进入通用 Cleaner；浏览器支持 UI/API 与同步副作用需单独确认 |
| 浏览器共享组件 | Chrome/Edge 本地基础模型与清单/资产 | 按产品/版本/内部页识别；v1 report-only，不按固定目录裸删 |

**[事实]** 现代浏览器会分区站点状态：Chromium StorageKey 包含 top-level site 等，Chrome 的 storage partitioning 已产品化；Firefox 使用含 container/partition 信息的 OriginAttributes；WebKit 对第三方状态使用 top/client origin 分区。来源：[Chrome Storage Partitioning](https://developer.chrome.com/docs/privacy-sandbox/storage-partitioning/)、[Chromium StorageKey 固定源码](https://chromium.googlesource.com/chromium/src/+/c551499a894d32bd04a882a0beae53d854e28ba2/third_party/blink/common/storage_key/storage_key.cc#85)、[Firefox OriginAttributes 固定源码](https://github.com/mozilla-firefox/firefox/blob/dddd3ebf8c01bcbf38c5ba24812e9df1ea6fff8a/caps/OriginAttributes.cpp)、[WebKit Tracking Prevention](https://webkit.org/tracking-prevention/)（访问：2026-08-26）。

**[推导]** hostname 不是完整归因键。**[建议]** browser Candidate 至少绑定产品、完整版本、channel、Profile/store identity、adapter/source version、采集时刻、运行态、snapshot 方法和 storage type。Chromium 必须保留匹配版本 parser 得到的完整 serialized `StorageKey`，包括 origin、top-level schemeful site、ancestor-chain state、存在时的 nonce/opaque precursor，再结合 bucket 与实际 `StoragePartition` identity；Firefox/WebKit 同样保留完整 container/privacy/partition identity。`(origin, top-level/client site, container/privacy attributes, partition, bucket)` 只能作为显示投影，不能当唯一 destructive key。无法无损解码就报告，不能按 hostname 生成计划。

SQLite 主库与 WAL/SHM/journal、LevelDB `CURRENT`/`MANIFEST`/log、IndexedDB blob、Cache Storage body、Service Worker registrar/script、salt/origin metadata 构成版本相关一致性组。**[事实]** SQLite WAL 是数据库持久状态的一部分，LevelDB 对数据库有单进程锁语义。来源：[SQLite WAL](https://www.sqlite.org/wal.html)、[SQLite corruption guidance](https://www.sqlite.org/howtocorrupt.html)、[LevelDB documentation](https://github.com/google/leveldb/blob/main/doc/index.md)（访问：2026-08-26）。**[建议]** 浏览器运行或锁/holder 状态不明时跳过；不删锁、不 repair、不强杀。文件系统快照也只能按证据称 time-point/crash consistent，不能夸为跨 store 事务一致。

#### Chrome/Edge 本地基础模型

- **[事实]** Chrome 模型会按资格和使用自动管理、下载或清除，不是安装包中固定不变的一个文件。来源：[Chrome built-in model management](https://developer.chrome.com/docs/ai/understand-built-in-model-management)（访问：2026-08-26）。
- **[事实，固定源码快照]** Chromium M154 主干同时存在旧 Optimization Guide 组件和 Manifest Broker 资产；组件 ID、目录和 payload 是版本实现细节。来源：[installer](https://chromium.googlesource.com/chromium/src/+/c551499a894d32bd04a882a0beae53d854e28ba2/chrome/browser/component_updater/optimization_guide_on_device_model_installer.cc#53)、[manifest asset manager](https://github.com/chromium/chromium/blob/c551499a894d32bd04a882a0beae53d854e28ba2/components/optimization_guide/core/model_execution/manifest_broker/manifest_asset_manager.cc)（访问：2026-08-26）。
- **[事实]** Chrome 与 Edge 的专用 `GenAILocalFoundationalModelSettings=1` 在受支持平台/版本表示阻止下载并删除已有基础模型；Edge 文档未列 Linux 支持。来源：[Chrome live policy data](https://chromeenterprise.google/static/json/policy_templates_en-US.json)、[Edge policy](https://learn.microsoft.com/en-us/deployedge/microsoft-edge-policies/genailocalfoundationalmodelsettings)（访问：2026-08-26）。
- **[建议]** 不假设 Chrome/Edge component ID 相同，不承诺固定 4 GB 或固定 `weights.bin`；从目标产品版本和可用的 on-device internals 记录 live path/version/size。`ComponentUpdatesEnabled=false` 影响大量组件，不作为 AI 清理捷径；来源：[Edge ComponentUpdatesEnabled](https://learn.microsoft.com/en-us/deployedge/microsoft-edge-policies/componentupdatesenabled)（访问：2026-08-26）。v1 不写 registry/managed preferences，不开启内部页、不手删模型目录，只输出支持路径、副作用和“可能重新下载”。

## 9. 风险、安全保护与删除语义

### 9.1 规范风险词汇

| 等级 | 典型条件 | v1 行为与确认 |
|---|---|---|
| R1 | 完整、local、普通、可重建、无 link/boundary/holder signal | Trash；展示解释、大小口径和恢复说明后确认 exact plan |
| R2 | 目录/多项批次、用户内容、近期修改、共享或 hard-link/reclaim 不确定 | Trash；展开逐项 action、风险、fingerprint |
| R3 | executable/app、DB、VM/container/package state、observed-open、provider/network/removable、重要 evidence unknown | 默认 skip；策略明确允许时 Trash-only，逐项加强确认 |
| R4 | 任一 Permanent；未来 manager/browser 不可逆 mutation | 独立批次与不可逆 execution authorization，不能由 Trash approval 授权 |
| BLOCKED | root、保护对象、mount point、unknown reparse、身份/策略/audit 不可验证、意外提权、新/未读 descendant | 无动作、无 force、不可审批 |

这里解决研究材料的术语差异：个人/发布/凭据数据本身是 R3 或 BLOCKED；只要动作不可逆就升为 R4。risk 是审批政策，不是“安全证明”。

### 9.2 不可绕过的保护集合

以下对象按 native identity、known-folder/mount API 和真实祖先链识别，不能只做字符串前缀匹配：

- 任意 filesystem/volume/mount/bind/mounted-folder/automount/UNC share root 及等价别名；
- OS boot、recovery、system、device/virtual filesystem anchors，以及 package-manager 的权威数据库、配置、锁、receipt、transaction/rollback state；这不阻止通过固定 core adapter 对单独建模的 cache artifact 调用 owner-supported GC；
- 当前 home/profile 根本身及包含所有 profiles 的父根；
- Trash/Recycle Bin 内部；
- SweepX executable、安装目录、活动 cwd、配置、cache/spill、plan、approval、lock、audit 和 daemon socket；
- 用户/组织新增 protected path/file/identity，以及整体动作会包含它们的祖先；
- device/socket/FIFO、Windows device namespace、未建模 ADS、unknown reparse/special object；
- scan root 外、identity/parent/type/mount/containment 无法现场复验的对象；
- 目录中未审批、新出现或不可读的 descendant；
- 真实 no-follow 祖先链上任何名为 `.sweepx-protect` 的 entry。其类型任意、不可打开或跟随；无法证明不存在也 BLOCKED。

系统对象的动态识别和用户解释见 [系统关键文件研究](docs/research/system-protected-files.md)。规范例子包括：Windows 运行时 page file、`swapfile.sys`、`hiberfil.sys` 和 dedicated crash-dump backing；macOS APFS VM-role volume/swap、SSV/SIP 与经当前配置确认的 sleep image；Linux `/proc/swaps` 中的 active swap、当前 mount namespace 的根/mountpoints 以及 proc/sysfs/dev/cgroup/efivarfs 等内核接口。它们通过 OS 配置、volume role、mount/swap identity 识别，而不是只匹配 basename。已完成的 Windows crash dump 是诊断数据，默认 R3/report-only，与 active backing file 的 BLOCKED 语义分开。

用户和组织只能增加保护，不能删除内置保护。若用户在 SweepX 外移除 marker，也必须重新 scan/explain/plan/approve。

### 9.3 执行授权

常规路径中，只有随 core 发布的 Human Approval Broker 可构造 ApprovalRecord；公共 SDK 没有 constructor/import endpoint。Broker 优先打开随 core 发布、经过身份校验的本地原生审批窗口；没有合格图形会话时才回退到本地 foreground console/TUI。两者都拒绝 stdin/pipe、重定向、远程插件、配置或环境预批准。人先看到 exact mode、selected item/action count、每 action risk、unknown/coverage、恢复预期、expiry 和 plan fingerprint；R3 逐项选择。

Permanent 原生窗口显示“永久删除 N 个选中项（底层 M 个动作）”、完整可展开路径/风险、绕过回收站且并非 secure erase、只读 fingerprint/expiry，要求勾选理解后再点默认不聚焦的 destructive 按钮；该点击只产生 approval，不同时开始 execute。Windows 可选用 `UserConsentVerifier`/Windows Hello、macOS 可选用 LocalAuthentication 做不提权的当前用户重新验证；普通返回值只证明 OS 当时接受了验证，并不签名或绑定任意 plan digest，因此 Broker 仍须把结果关联到同一个 pending request，并重新比对完整 digest。不能为此调用 UAC、Authorization Services、sudo 或 polkit。Linux 没有统一同等接口，使用本地窗口或可信终端 fallback。未来只有受用户在场策略保护的应用密钥对 canonical challenge 签名，才可称为密码学绑定。

可信终端 fallback 才要求人工键入：

```text
PERMANENT <selected-item-count> <underlying-action-count> <SX1-plan-fingerprint>
```

允许粘贴和无障碍输入，但输入仍来自可信前台，Agent/插件不得预填。approval 最长 5 分钟、single-use，绑定 exact plan/mode/items/actions/risk/policy/anchor/cleaner/user/host/workflow session；opaque `approvalId` 本身不足以执行。

这里的 challenge 由 Broker 从持久化 immutable plan 的 selected-item count、underlying-action count 和短 fingerprint 生成，只是让操作者重新注意“永久删除哪个计划”；真正的防篡改、TTL、session 和 single-use 绑定来自 sealed ApprovalRecord 中的完整 256-bit digest。它不证明阅读理解、人类身份或对象安全。

显式危险路径不经过原生窗口、OS reauthentication 或 terminal challenge：调用者给已有 Permanent R4 plan 传 `--dangerously-delete` 后，CLI/Core admission 创建 `DangerousDeleteRecord`，记录 `source=ExplicitDangerousDelete`、完整 argv/环境过滤结果、user/host/session/time 及与 ApprovalRecord 相同的 plan/action/risk/digest/nonce 绑定，并原子 claim。它可用于非交互 CLI；Core 不声称也无法证明调用者是人。Agent Skill 必须拒绝调用，但该限制属于 Agent policy，不是 OS 身份认证。无论来源，Authorization 都不能跳过 hard protection、live preflight、intent/permit/outcome/audit。

### 9.4 Trash 与 Permanent

**默认行为的精确定义 [建议]**：scan/explain/plan 永远无 mutation；用户显式执行一个已批准计划时，filesystem action 默认 `Trash`。这同时满足“默认 dry-run/预览”和“默认回收站”，二者不冲突。

- Trash 成功只表示平台报告已接受/移动；不保证未来恢复、不保证立即释放空间。Trash 失败、unsupported、no-space、cancelled 或 ambiguous 时保持原 mode 并停止/核对，绝不调用 Permanent。
- Permanent 只通过 `plan create --mode permanent` 建立新 R4 plan；没有 execute-time `--permanent`。调用者可走独立 Broker challenge，或显式执行 `execute --plan-id ID --dangerously-delete` 跳过确认；后一入口由 Core 为精确 Permanent plan 生成并立即消费一次性 DangerousDeleteRecord。它可以非交互使用，但不能改变 mode/targets、绕过复验或硬保护；Agent Skill 明令不调用。Permanent 表示绕过用户回收站移除已授权目录项，不是 secure erase 或保证不可恢复。
- v1 不执行 manager/browser 的 M 类 mutation。未来若引入，必须是第三种显式 action family、R4、独立 adapter/approval/recovery，不得假装继承 filesystem Trash 可恢复性。

### 9.5 TOCTOU 与 holder 边界

路径替换、父目录替换、link/reparse 互换、mount namespace 变化、目录注入和 policy/anchor 改变都在 final action 前失败关闭。平台允许时保留 parent/object handle 并使用 relative non-follow primitive；但三个平台没有统一“仅当 identity 仍为 X 时原子移入 Trash”的公开接口。**[缺口]** 同一 UID 恶意进程仍可能在最后一次检查与 pathname-based Trash API 间竞态；设计只能以稳定 parent locator、短 permit TTL、紧邻复验、封闭 manifest 和事后 reconcile 缩小窗口，不能声称完全消除。

holder 统一为 `OBSERVED_OPEN | NOT_OBSERVED{coverage} | UNKNOWN | NOT_SUPPORTED`。positive signal 可升风险/阻断；negative 只是时间点观察，不授权、不替代 identity revalidation。SweepX 不 kill、close handle 或提权扩大可见性。

## 10. 三平台 adapter 与普通用户边界

### 10.1 共同接口

```text
PlatformAdapter
├── admit/enumerate/metadata_no_follow
├── object_domain_identity + traversal_mount_identity
├── logical/allocated/provider metadata
├── boundary snapshot + ordinary-user runtime check
├── observe_use(identity) -> observed | not_observed | unknown
├── trash(TrashPermit) -> PlatformAttempt
├── permanent_one_nonrecursive(PermanentPermit) -> PlatformAttempt
├── reconcile(DurableIntent) -> source/destination facts
└── caller_available_space(volume) -> optional observation
```

| 平台 | 扫描身份/边界 | Trash | Permanent 与 holder | 普通用户运行门槛 |
|---|---|---|---|---|
| Windows | `FindFirstFileW`；`FILE_FLAG_OPEN_REPARSE_POINT`；volume + `FILE_ID_INFO`；所有目录 reparse、mounted folder、UNC、offline/provider 为边界。[FindFirstFileW](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-findfirstfilew)、[FILE_ID_INFO](https://learn.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-file_id_info)、[reparse](https://learn.microsoft.com/en-us/windows/win32/fileio/reparse-points)（访问：2026-08-26） | Windows 8+ 在 STA 使用 `IFileOperation::DeleteItem/PerformOperations`，以 `FOFX_RECYCLEONDELETE` 强制 recycle-only；destruction warning 仅为附加防线。综合 HRESULT、逐项 `PostDeleteItem` progress sink、`GetAnyOperationsAborted`；任何不能证明回收的情况均 `TRASH_UNAVAILABLE`，绝不永久删除 fallback。[DeleteItem](https://learn.microsoft.com/en-us/windows/win32/api/shobjidl_core/nf-shobjidl_core-ifileoperation-deleteitem)、[flags](https://learn.microsoft.com/en-us/windows/win32/api/shobjidl_core/nf-shobjidl_core-ifileoperation-setoperationflags)、[aborted](https://learn.microsoft.com/en-us/windows/win32/api/shobjidl_core/nf-shobjidl_core-ifileoperation-getanyoperationsaborted)（访问：2026-08-26） | 每 permit 一个 no-follow primitive；不清属性、不改 DACL。Restart Manager 仅作文件 holder 观察。[DeleteFileW](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-deletefile)、[Restart Manager](https://learn.microsoft.com/en-gb/windows/win32/api/restartmanager/nf-restartmanager-rmregisterresources)（访问：2026-08-26） | destructive mode 拒绝 elevated/full token；不启用 backup/restore/take-ownership privilege；无法证明 recycle-only 的 OS/API 组合仅 scan/plan |
| macOS | `lstat` + volume/file resource identity 或 `st_dev/st_ino`；volume/network/automount/File Provider/signed-read-only system volume 为边界。[stat(2)](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man2/stat.2.html)、[resource ID](https://developer.apple.com/documentation/foundation/urlresourcevalues/fileresourceidentifier)、[volume ID](https://developer.apple.com/documentation/foundation/urlresourcekey/volumeidentifierkey)（访问：2026-08-26） | 每 top-level item 调 `FileManager.trashItem`，记录 resulting URL 或 location unknown；失败不调用 `removeItem`。[trashItem](https://developer.apple.com/documentation/foundation/filemanager/trashitem(at:resultingitemurl:))（访问：2026-08-26） | 非目录/link 仅用实测 no-follow primitive；目录用 parent-relative nonrecursive `rmdir`，禁止 Foundation 递归目录删除。`lsof`/内核观察仅提示 | `euid=0` 拒绝；不请求 FDA/privileged helper；已有 FDA 或 sandbox grant 不能削弱保护 |
| Linux | `readdir/getdents + fstatat/statx`；object-domain 通常 `st_dev+inode`，边界另用 mount ID 和 `/proc/self/mountinfo`；优先 <code>openat2(NO_SYMLINKS&#124;BENEATH&#124;NO_XDEV)</code>。[statx](https://man7.org/linux/man-pages/man2/statx.2.html)、[mountinfo](https://man7.org/linux/man-pages/man5/proc_pid_mountinfo.5.html)、[openat2](https://man7.org/linux/man-pages/man2/openat2.2.html)（访问：2026-08-26） | 优先 GIO `g_file_trash`；v1 不手写 freedesktop fallback，不支持/EXDEV/空间/权限错误不 `unlink`。[GIO trash](https://docs.gtk.org/gio/method.File.trash.html)、[Trash spec](https://specifications.freedesktop.org/trash/latest/)（访问：2026-08-26） | parent FD + exact basename 的 `unlinkat` 类 nonrecursive action；manifest postorder。`/proc/PID/{fd,maps,cwd,root,exe}` 只在当前 namespace/权限可见范围观察。[unlink](https://man7.org/linux/man-pages/man2/unlink.2.html)、[proc fd](https://man7.org/linux/man-pages/man5/proc_pid_fd.5.html)、[proc maps](https://man7.org/linux/man-pages/man5/proc_pid_maps.5.html)（访问：2026-08-26） | `euid=0` 或 effective/permitted/ambient capability 任一非空均拒绝；不切 user/mount namespace、不用 sudo/polkit/setuid |

allocation 只作归属量：Windows 非 reparse 后查询 compressed size 并完整覆盖 ADS，否则 lower-bound/unknown；macOS APFS clone/snapshot/shared container 下 reclaimable unknown；Linux `st_blocks*512` 可报告，但 FIEMAP shared/unknown/delalloc/encoded 只降低置信度。来源：[Windows streams](https://learn.microsoft.com/en-us/windows/win32/fileio/file-streams)、[Apple APFS](https://developer.apple.com/documentation/foundation/about-apple-file-system)、[Linux FIEMAP](https://docs.kernel.org/filesystems/fiemap.html)（访问：2026-08-26）。

某个平台只有 root/home/SweepX/Trash/marker、TOCTOU、Trash no-fallback、partial/aborted、crash recovery、runtime privilege 和 audit durability 的真实 OS gate 全通过，才启用 destructive mode；否则 `capabilities` 明示 scan/explain/plan-only。

## 11. CLI、结构化协议与 TUI

### 11.1 命令树

```text
sweepx [global-options] <command>
  scan <ROOT>...
  explain --scan-id ID --candidate-id ID...
  plan create --scan-id ID --candidate-id ID... [--mode trash|permanent]
  plan show --plan-id ID
  approve --plan-id ID                       # 仅可信本地人工
  execute --plan-id ID (--approval-id ID | --dangerously-delete)
  cancel --operation-id ID
  recover --batch-id ID [--reconcile-only | --resume-pending]
  status [--operation-id ID | --scan-id ID | --plan-id ID | --batch-id ID] [--watch]
  capabilities [--cleaner ID] [--platform]
  tui [--scan-id ID | --plan-id ID | --batch-id ID]
  cleaner list | show ID[@VERSION] | verify PACKAGE | install PACKAGE | remove ID[@VERSION]
  trust list | import SIGNED-KEY-BUNDLE | revoke KEY-ID
  audit show --batch-id ID | verify [--batch-id ID] | export --batch-id ID --output FILE
```

全局 `--format human|json|ndjson`、`--output`、`--locale zh-CN|en-US`、`--no-color`、`--quiet`、`--request-id`、`--state-dir`；`--after` 只用于 `status --watch --format ndjson`。scan 的 `--strict-z0` 默认开启，Z1 只能逐 command ID opt-in；`--memory-budget 64MiB..128MiB` 只能收紧；`--max-depth`/`--deadline`/native exclude 只缩小 coverage；cache 只有 `off|preview`。

不存在 `--yes/-y`、`--force`、`--recursive`、`--follow-links`、`--cross-mount`、`--ignore-protection`、`--delete-any-path`、non-interactive HumanApproval 或 Trash-to-Permanent fallback。唯一非交互 destructive authorization 是字面量 `--dangerously-delete`，且只绑定已有 Permanent R4 plan。shell glob 只能在 shell 展开后成为多个显式 scan roots，planner/executor 不接收 glob。

### 11.2 JSON、NDJSON 与退出码

bounded 命令返回一个 `sweepx.output/v1` terminal envelope；stream 返回每行一个 `sweepx.event/v1`。sequence 为十进制字符串、严格递增；交付 at-least-once，以 `(streamId, sequence)` 去重；cursor 绑定 stream/sequence/checkpoint。cursor 过期先发 `stream.reset_required`，客户端取 status snapshot 后续读。每个 operation 恰好一个 durable `operation.terminal`。

当前实现尚无满足该契约的 durable event journal 和 replay path，因此 `scan --format ndjson` 必须在 admission 前返回 unsupported，不能输出仅驻内存、checkpoint 非 durable 的伪事件流。当前 scan 机器输出只开放 bounded JSON；NDJSON 在 journal、cursor replay 与 durable terminal event 同时落地后再启用。Windows durable snapshot store 同样失败关闭，直到实现 current-user-private DACL、逐组件 reparse-point 拒绝和私有文件 ACL；默认路径不创建，显式 `--state-dir` 也拒绝。

事件集合包括：operation/phase；scan root/progress/aggregate/boundary/error/completed；candidate/analysis；plan/authorization（含 human approval 与 explicit dangerous delete）；revalidation/preflight/protection；cancel；action intent/platform/skipped/permit/reconcile；item/batch/recovery/audit；detail persistence、stream reset 和 terminal。只有中间 progress、非终版 aggregate 可合并；错误、边界、incomplete reason、intent、outcome 和 terminal 不丢。`approval.*` 事件只来自 core/TUI 内部 broker stream；`authorization.explicit_dangerous_delete` 只记录 flag admission 与精确 plan digest，不泄露 record/nonce。

| code | 名称 | 含义 |
|---:|---|---|
| 0 | OK | 请求按结构化结果完成 |
| 2 | USAGE | 参数/schema/组合非法，未 admission |
| 3 | UNSUPPORTED | 能力/platform/layout 不支持 |
| 4 | PARTIAL | scope incomplete，或 destructive batch 至少一个明确 fail/skip 且无 ambiguous；包括全失败/全 skip |
| 5 | SAFETY_BLOCKED | core 安全阻断 |
| 6 | AUTHORIZATION_REQUIRED | 缺少/拒绝/过期/消费/不匹配；或 ExplicitDangerousDelete 用于非 Permanent plan |
| 7 | STALE_REPLAN_REQUIRED | 必须重扫/重建计划 |
| 8 | OPERATION_FAILED | 尚未形成可汇总 destructive batch 的明确一般失败 |
| 9 | NEEDS_RECONCILIATION | 提交结果不明或 crash intent |
| 10 | CANCELLED | 无 ambiguous 的取消 |
| 11 | STATE_INTEGRITY_UNAVAILABLE | audit/plan/authorization/fence 不可靠 |
| 12 | PLUGIN_TRUST_OR_COMPAT | Cleaner trust/schema/ABI/capability 失败 |
| 13 | OFFICIAL_COMMAND_FAILED | 受控官方查询/动作 adapter 失败 |

混合优先级：`11 > 9 > 10 > 7 > 5 > 6 > 12 > 13 > 8 > 3 > 4 > 0`。进程码不能替代逐项 outcome；envelope 与 exit 冲突时取更保守状态。

### 11.3 TUI

视图为 Overview/Status、virtual Tree/List、Filter/Sort、Explain、Plan Review、trusted Approval、Execute Review、Recovery/Audit、Cleaners/Capabilities。选择、审批、执行是三个步骤；没有单键 destructive shortcut。

TUI 不载入全树：默认只保留每个已展开 parent 的 exact top-64 heavy children 和不可选/不可计划的 `Others` 聚合行，cursor page 最多 500 rows，配合面包屑和 virtual scroll。展开被折叠/驱逐的目录会触发优先级更高的 live detail enumeration，并产生新 revision；浅层预枚举只给 direct-child count，不能谎报 recursive total。tree-dependent `B_tui=48 MiB`；server query 不依赖持久化全树索引。

selection 以 content-addressed ref 保存，全局最多 16 MiB；descendant manifest store 最多 64 MiB。被 UI/cache 丢弃的细节若要进入计划，Planner 必须做 targeted live rescan 生成封闭 manifest。超限返回 `ResourceLimit`，不截断、不静默驱逐 active plan/batch。

## 12. Cleaner 扩展、签名与示例

### 12.1 包与 schema

```text
cleaner-package/
  cleaner.json          # sweepx.cleaner-manifest/v1
  rules/*.json          # sweepx.cleaner-rule/v1
  probes/<platform>/*   # 可选；仅 first-party、allowlisted
  evidence/*.md         # 解释/来源，不授权
  SIGNATURE
```

manifest 声明 package/publisher/digest、core/scanner/candidate/rule/probe ABI ranges、OS/arch/tool/browser tested ranges、分阶段 capabilities、typed root/config decoder、rules/probes/official commands、risk floor、supported actions、references、expiry 和 unknown-version behavior。规则含 artifact class、exact selector、required/optional/exclusion evidence、grouping、typed AST predicate、monotonic risk raise、proposal、recovery/activity/sharing/explanation。

typed AST 只支持有界布尔/集合/版本/tagged-value 操作；无脚本、循环、I/O、回溯正则、算术、动态 path 或隐式类型转换。深度最多 32、节点最多 1024；缺字段得到 unknown。动作枚举仅 `report | filesystemTrash | managerPermanentRecommendation`，最后一项不是执行权限。

### 12.2 信任与能力

- 包不可变、内容寻址并由 Ed25519 签名；签名证明来源/完整性，不证明安全。manifest/file table 按 RFC 8785 canonicalize；拒绝 duplicate JSON keys、path traversal、绝对路径、symlink/hardlink/device、NFC/case-fold collision、archive duplicate 和压缩炸弹。
- 第三方只能声明式规则。native probe 必须同时满足 first-party probe key、artifact digest allowlist 和发布期沙箱测试；导入 publisher key 不能获得 probe/action authority。
- capability 按 discover/query/analyze/proposal/mutation/postcheck 分段，与平台和 host policy 取交集；省略即 deny。probe 输入是 admitted read-only handle/typed snapshot，不是 arbitrary path；无网络/写入/child process，CPU/RSS/handle/stdout/stderr/timeout 有硬限。
- revocation 可按 publisher/package/probe/version；命中立即 report-only 并使计划 stale。trust metadata 超过 7 天未刷新：声明式规则仅 report-only，probe/official command/new plan 禁用。没有 force bypass。
- `cleaner install/remove` 与 `trust import/revoke` 会修改配置/信任，只允许人类 foreground 管理，不属于 Agent allowlist，也不是 cleanup approval。

### 12.3 两个规范示例

**Cargo workspace `target`**：

```json
{
  "schema": "sweepx.cleaner-rule/v1",
  "id": "cargo-target-v1",
  "artifactClass": "rebuildable-project-output",
  "grouping": "directory",
  "requiredEvidence": [
    "cargo.workspace-boundary.v1",
    "cargo.target-shape.v1",
    "scan.final-complete-aggregate.v1"
  ],
  "risk": {
    "floor": "R1",
    "monotonicRaises": [{
      "when": {"op": "eq", "args": [{"field": "objectType"}, "Directory"]},
      "to": "R2"
    }],
    "unknownPolicy": "report_only"
  },
  "proposal": {
    "disposition": "low_risk_candidate",
    "supportedAction": "filesystemTrash",
    "targetGranularity": "whole-verified-target-root"
  }
}
```

Z0 解析已扫描的 `Cargo.toml`/lock/`.cargo/config*`，只把已 admission、out-of-source、完整且结构落入 allowlist 的 target root 提为候选；目录条件必把基础 R1 单文件风险提升为至少 R2。共享 `CARGO_TARGET_DIR`、活动 cargo/rustc/IDE、发布/签名证据或 unknown component 再升 R3/report-only。mtime 仅弱信号。Z1 `cargo metadata --no-deps --locked --offline` 只能显式 opt-in、固定 executable/argv、可丢 home/target、无网络和写监控；不调用 `cargo clean`。来源：[Cargo metadata](https://doc.rust-lang.org/cargo/commands/cargo-metadata.html)、[Cargo clean](https://doc.rust-lang.org/cargo/commands/cargo-clean.html)（访问：2026-08-26）。

**Chromium HTTP/Code Cache**：

```json
{
  "schema": "sweepx.cleaner-rule/v1",
  "id": "chromium-cache-v1",
  "artifactClass": "rebuildable-browser-cache",
  "selectors": [{"kind": "exact-relative-components", "values": [["Cache"], ["Code Cache"]]}],
  "requiredEvidence": [
    "browser.product-version-channel.v1",
    "browser.profile-and-cache-root.v1",
    "browser.quiescent.v1",
    "browser.layout-supported.v1",
    "scan.final-complete-aggregate.v1"
  ],
  "risk": {"floor": "R2", "unknownPolicy": "report_only"},
  "proposal": {
    "disposition": "eligible_with_confirmation",
    "supportedAction": "filesystemTrash",
    "targetGranularity": "whole-verified-cache-root"
  }
}
```

规则绑定 product/channel/full version/profile 和真实 cache root；browser running/unknown、layout unknown、manifest change 全部 skip/stale。只纳入 HTTP/Code Cache，明确排除 Cache Storage、IndexedDB、Local Storage、cookies、history、extensions 和 Service Worker application state。不提供 hostname-level HTTP cache 删除。

发布示例中的 digest 必须由构建工具生成并验签；任何全 `0/1/2...` placeholder digest 都由 release lint 拒绝。

## 13. AI Skill 与自动化边界

Agent 协议固定为：

```text
capabilities/status -> scan -> explain -> plan/show
  -> PAUSE FOR HUMAN APPROVAL
  -> execute -> reconcile if needed -> audit/report
```

Agent 可以调用 status/capabilities、scan、explain、plan、execute（已有有效 opaque approval 后）、cancel、recover，以及只读 Cleaner/audit 查询。Agent 不得：

- 代人运行 `sweepx approve`、输入/管道 confirmation、自动化 TUI、把对话中的“可以”当 approval；
- 传递、建议自动化或代理 `--dangerously-delete`；该 flag 支持非交互，CLI 无法可靠区分人和 Agent，因此必须由 Skill policy 明令禁用；
- 请求/读取/复制/编辑 ApprovalRecord，只能接收 Broker 返回的 opaque ID；
- 调用 `rm`/`unlink`/PowerShell deletion、平台 Trash API、生态 cleanup 或浏览器内部接口绕过 core；
- 使用提权、force、follow-link、cross-mount、persistent approval，或把 Trash failure 转 Permanent；
- 从 display path、导入 JSON 或 cache 构造动作目标。

Agent 必须解析 `sweepx.output/v1`/`sweepx.event/v1`、校验 schema/compat、去重 sequence、要求唯一 durable terminal，保留 tagged unknown 和 native error。遇到 exit 6 时只向人展示 exact plan fingerprint/mode/count/risk/unknown/recovery/expiry，并请人亲自在可信本地 native/terminal surface 完成；Agent 不得点击原生窗口、响应 OS reauthentication 或输入 terminal challenge。exit 7 回到 scan；9 先 recover；11 停止全部 mutation；12/13 不加载 fallback 或裸删。

完整可落地 Skill 草案见 [skills/sweepx/SKILL.md](skills/sweepx/SKILL.md)。

## 14. Rust workspace、模块与依赖

### 14.1 Workspace 布局

```text
Cargo.toml
crates/
  sweepx-model/             # tagged values、IDs、wire DTO、状态/outcome enum
  sweepx-canonical/         # JCS、domain-separated digest、fingerprint
  sweepx-platform/          # native names/identities、adapter traits、capabilities
  sweepx-platform-windows/  # Windows scan/trash/permanent/holder
  sweepx-platform-macos/    # macOS scan/trash/permanent/holder
  sweepx-platform-linux/    # Linux scan/trash/permanent/holder
  sweepx-scanner/           # scheduler、queues、budget、aggregate、cancel
  sweepx-cache/             # generations、field provenance、spill/index
  sweepx-cleaner-schema/    # manifest/rule/evidence JSON Schema + validation
  sweepx-cleaner-vm/        # pure typed AST evaluator
  sweepx-probe-host/        # first-party helper protocol/sandbox
  sweepx-catalog/           # built-in data rules、version adapters
  sweepx-safety/            # risk、protections、plan、approval、preflight；sealed permit
  sweepx-executor/          # fence、serial action loop、adapter dispatch
  sweepx-audit/             # intent/outcome journal、CAS、reconciliation
  sweepx-core/              # use cases / SweepxService facade
  sweepx-protocol/          # output/event v1、cursor、exit mapping
  sweepx-cli/               # clap front end + human/JSON/NDJSON renderers
  sweepx-tui/               # ratatui virtual client
  sweepx-agent-contract/    # machine protocol examples/golden fixtures；无审批能力
  sweepx-fixtures/          # test-only generator/fault controller/oracle schema
xtask/                      # schema generation、source/date lint、fixtures、release gate
```

依赖方向：`model/canonical/platform traits` 在底层；scanner/cache/cleaner 不依赖 executor；safety 可读 Candidate/Explanation 但不依赖 CLI/TUI；platform-specific deletion 实现只能由 executor 构造；frontends 只依赖 `core + protocol`。Cargo feature 只选择平台和可选 adapter，不能关闭保护或审批。

### 14.2 关键依赖与替代方案

| 用途 | 首选 | 选择理由 | 替代/拒绝条件 |
|---|---|---|---|
| CLI | `clap` derive | typed parser、稳定 help/completion | `bpaf` 可行；不得自行宽松解析危险参数 |
| async control | `tokio`（仅控制面）+ 固定 blocking pools | cancellation/event/IPC 成熟；阻塞 FS 不放 async executor | `async-std` 无关键收益；扫描 hot path 可用 scoped threads + channels |
| 有界 channel | `crossbeam-channel` 或 Tokio bounded `mpsc`，外包 byte semaphore | count + bytes 双门、固定 worker | `flume` 可替代；拒绝 unbounded channel |
| errors | `thiserror` 库 + `anyhow` 仅 binary 边界 | 保留稳定 enum/native code | 不向 wire 暴露 debug string 作为唯一错误 |
| serialization/schema | `serde`、`serde_json`、`schemars`，自有严格 duplicate-key loader/JCS wrapper | wire/schema 生态成熟 | `simd-json` 需证明无语义差异后再引入 |
| digest/signature | `sha2`、`ed25519-dalek`、`subtle`/`zeroize` | 成熟、可审计、constant-time primitives | OS crypto 可作 FIPS profile；算法变更升 schema/domain |
| durable state | SQLite bundled + WAL，`rusqlite` 单 writer，`mmap` disabled | transaction/CAS/index/integrity check 适合 cache/audit | `redb`/`sled` 只有在 crash/fdatasync 跨平台证据更强时替换；audit 与 disposable cache 分离 DB |
| TUI | `ratatui` + `crossterm` | 跨平台、虚拟视图可控 | `termwiz` 可替代；不得把全树建成 widget |
| time/IDs | `time`、`uuid` | RFC3339 UTC 和随机 IDs | monotonic 时间仍来自 `std::time::Instant`，不可持久化为 wall time 替代 |
| secrets/OS private store | `keyring` 或平台 credential API wrapper | broker sealing key 不进入导出状态 | 无可靠 secure store 时仅进程内 key，重启使 approval 失效 |
| Windows | `windows` crate | Win32/COM/Restart Manager 强类型绑定 | `windows-sys` 用于更窄底层调用 |
| macOS/Linux syscalls | `rustix`，macOS Objective-C/Foundation 以小型 FFI crate 封装 | fd-relative/no-follow API 边界清晰 | `nix` 可替代；避免全局 libc scattered unsafe |
| Linux Trash | `gio`/`glib` crate 或私有 helper | 对接 desktop GIO 而非自行实现规范 | headless/不可用则 Trash unsupported；v1 不手写 fallback |
| testing | `proptest`、`insta`/golden、`loom`（小型状态模型）、`criterion` | property/protocol/concurrency/benchmark | 真实 OS fault suites 仍不可被 mock 取代 |

所有依赖锁定到 `Cargo.lock`；release 构建启用 `deny(warnings)`、`cargo-deny` license/advisory/source policy、SBOM 和可复现 artifact metadata。`unsafe` 仅允许在 platform FFI 小模块，要求 safety comment、Miri/ASan/TSan 可运行部分和 code owner review。

### 14.3 Durable store 划分

**[建议]** 用三个当前用户私有、非 symlink、权限验证后的 SQLite 文件：

1. `cache.db`：可丢的稀疏 preview cache，quota 64 MiB/100k summary records；只存 roots/必要祖先、每 parent top-64、默认至少 32 MiB 的 heavy leaf、候选/error/boundary 与聚合摘要，不存普通小文件明细；corrupt 时 quarantine+cold scan；
2. `core-state.db`：plan、approval sealed record、operation/fence/selection/manifest metadata；不可用则 exit 11；
3. `audit.db`：append-only logical journal、intent/outcome/hash chain；单 writer，`FULL` synchronous，action 前显式 checkpoint/fsync 验证。

scanner 正常只使用有界内存；仅当实际 charged memory 达到 75% 高水位且经 compact/evict 后仍不能取得 permit 时，才延迟创建独立 ephemeral spill DB，默认上限 192 MiB/operation、256 MiB global，operation 完成后删除。selection store 16 MiB，manifest store 64 MiB，detail/event journal 32 MiB，core state + audit 64 MiB（其中 8 MiB emergency reserve），WAL/temp headroom 16 MiB；整个 SweepX state/cache 目录默认 512 MiB 硬上限。达到上限失败关闭/降级，绝不挤占 audit reserve；active audit/batch records 不参与 LRU。

## 15. 测试、基准与发布门槛

### 15.1 测试矩阵

| 层 | 必测内容 |
|---|---|
| Model/schema | tagged zero/unknown/lower-bound roundtrip，native bytes/UTF-16，u128 strings，JCS/digest golden，unknown enum/required feature，migration 不丢 unknown |
| Scanner unit/property | checked overflow、hard-link scope、complete propagation、随机 completion order deterministic aggregate、backpressure、late quarantine isolation、cache invalidation/corruption |
| Filesystem integration | depth 4096、1M children、10M entries、1M identities；symlink/reparse/cycle、hard link、mount/bind/overlay、sparse/compressed/ADS/clone/reflink、permission sibling、vanish/replace/provider hydration |
| Safety state model | 拒绝 Candidate->Execute、Plan->Execute、mode/risk/digest mismatch、permit replay、Trash fallback、stale retry、directory injection、root alias、marker race、direct adapter bypass |
| Authorization | HumanApproval 的 pipe/stdin/env/config/JSON/TUI automation、cross-user/host/session、broker restart、expiry、nonce replay、copied ID 全部失败；ExplicitDangerousDelete 仅绑定已有 Permanent plan，不能隐式启用/扩 scope/绕保护，Agent evaluation 必须拒绝该 flag |
| Crash/recovery | fault injection 于 intent 前、intent sync 后、submit 后、outcome sync 前、reconcile 中；missing 不成功、reserved 不重发、old fence 不执行 |
| Platform Trash | Windows per-item sink/aborted/undo flags；macOS trashItem no remove fallback；Linux GIO unsupported/EXDEV no unlink；权限/空间/取消/partial/unknown |
| Cleaner supply chain | signature/digest/revocation/rollback、zip-slip/collision/link/device/bomb、typed AST fuzz、probe escape/network/write/fork/output bomb、official argv/env drift |
| Protocol/TUI/Agent | CLI/TUI/Agent 同 fixture 得相同 Candidate/Plan digest；event replay/gap/reset/terminal once；48 MiB TUI budget；Agent 必须停在 HumanApproval 且拒绝 `--dangerously-delete` |
| Copy/language lint | 禁止无条件 `exact disk usage`、`will free`、`unused`、`safe to delete`、`guaranteed recoverable/unrecoverable` |

真实测试矩阵至少覆盖 Windows 10/11 上 NTFS/ReFS/FAT/exFAT/OneDrive/UNC；macOS 支持版本上的 APFS/exFAT/File Provider/TCC/sandbox；Linux 的 ext4/XFS/Btrfs/OverlayFS/FUSE/NFS/GIO desktop/headless、不同 kernel/openat2/statx capability。每项保存 OS/build、kernel、hardware、filesystem/options、普通用户 token/capability、fixture receipt、event trace 和 adapter digest。

### 15.2 可复现基准

没有可信的跨产品同条件 2026 benchmark；因此不宣称“最快”。fixture generator 使用固定 seed/JSON manifest，独立 oracle 不链接 scanner code。每环境记录 git/lock digest、release flags、CPU/RAM/storage/controller、filesystem/options、encryption/compression/provider、worker/queue/memory、cache state、fixture SHA-256。

场景包括 cold full scan、warm OS cache、warm SweepX preview、1% mutation、notification gap、schema/policy invalidation、cancel、permission/provider/FUSE timeout、slow cache writer、journal failure、cache corrupt、spill full。warm OS 和 SweepX cache 不混称。性能 run 必须先通过 100% correctness oracle；每场景 1 次不计分 warm-up + 至少 15 个独立 reset runs，报告 median/min/max/MAD。p95/p99 latency 至少 200/1000 个独立 observation，用 nearest-rank 并保存原始数据和 bootstrap 95% CI。

初始 gate（目标，不是已验证事实）：

- oracle 100%；任一 error/boundary/unknown/complete/hard-link 差异失败；
- scanner charged tree memory `<=128 MiB`，parent+helpers private RSS `<=384 MiB`，TUI tree memory `<=48 MiB`；
- 本地响应 workload time-to-first-result median `<=500 ms`，event p95 `<=250 ms`；
- cancel admission-stop p95 `<=250 ms`，cooperative logical terminal `<= longest deadline + 1 s`；资源实际回收另报，不伪造上限；
- 相同环境相对批准基线 median throughput 回退 >10%，或 p95 首结果/取消回退 >20%，必须解释和审批；
- cache 优化不能减少 v1 必需的 live validation。

### 15.3 Destructive capability release gate

每个平台/文件系统/capability 独立 allowlist。只有以下全部通过才启用动作：

1. root/system/home/SweepX/Trash/protected file/marker 与 alias 测试；
2. Trash 所有失败路径证明从未调用 Permanent；
3. target/parent/ancestor/type/link/mount/descendant 替换失败关闭；
4. flag/config/env/plugin/direct core/adapter 绕过均 hard refuse；
5. crash/partial/aborted/reconciliation 不把 missing 当 success；
6. ordinary-user runtime 和 audit durability 在真实 OS 验证；
7. platform-specific [待实测] 条目关闭或明确降级。

失败的平台仍发布 read-only scan/explain/plan export，不降低共同安全下限。

## 16. ADR

### ADR-001：单核心、多 surface

**决定 [建议]**：CLI、TUI、Agent、Cleaner 共用 core 状态机和模型，front end 不复制安全逻辑。理由是消除 digest/risk/行为分叉。替代方案“各界面独立实现”被拒绝。

### ADR-002：portable walker + 可选平台增强

**决定 [建议]**：普通用户、metadata-only、no-follow、same-volume walker 是基线；平台增强只能增加字段/性能，不能改变安全下限。拒绝以 Windows admin MFT、内容 hash 或全盘提权作为 v1 默认。

### ADR-003：有界并发而非 task-per-entry

**决定 [建议]**：固定 worker、count+byte queue、DRR、公平 slow lane、spill 和 circuit breaker。理由是 hostile tree/provider 下仍有可证明的内存和线程上限。代价是小树峰值吞吐可能不及无界 fan-out。

### ADR-004：缓存非权威

**决定 [建议]**：缓存只提供 stale preview/排序/纯派生加速；Candidate 和 preflight 都要求 live facts。替代方案“目录 mtime/change feed 命中即跳过枚举”在 v1 被拒绝，因为覆盖和权限变化证据不足。

### ADR-005：Trash-first、Permanent 独立 R4

**决定 [建议]**：filesystem execution 默认平台 Trash；任何 Trash 失败不 fallback。Permanent 是新计划、新审批、新批次、manifest-driven nonrecursive actions。拒绝 `--force`/execute-time `--permanent` 和 secure-erase 承诺。

### ADR-006：人类 exact approval，Agent 不能代理

**决定 [建议]**：常规路径只接受可信本地 Broker 经第一方 native modal 或 foreground terminal fallback 产生的 sealed、短期、single-use ApprovalRecord；拒绝 stdin、JSON token、对话同意和 standing approval。短 challenge 只是终端注意力检查，完整 plan digest 才是绑定。Windows/macOS 的非提权系统重新验证可作为附加证据，Linux 无统一基线；均不能替代 plan binding。为满足显式跳过确认的产品需求，Permanent 另有 `ExplicitDangerousDelete` authorization；它支持非交互，但只能绑定已有 R4 plan，并保留全部硬保护/复验/审计。CLI 不伪称能识别人类，Agent Skill 单独禁止调用该 flag。

### ADR-007：声明式 Cleaner，native probe 极小化

**决定 [建议]**：第三方只用 signed typed rules；first-party probe 接受 admitted handles、无网络/写入且有资源上限。拒绝同信任级别任意 shell/plugin deletion。manager mutation v1 仅建议。

### ADR-008：SQLite 分库、串行动作与 write-ahead audit

**决定 [建议]**：cache、core state、audit 分库；单 writer，动作串行，每 action 先 durable intent，再 final check/permit/adapter/outcome。理由是易于 fence、CAS 和核对。替代的并行 batch 删除暂缓，直到能证明 ordering、audit 和竞态不弱化。

### ADR-009：能力按平台实测开放

**决定 [建议]**：不以“支持某 OS”隐含 Trash/Permanent 已可用；`capabilities` 精确报告 scan/trash/permanent/browser/version/filesystem combinations。任一 gate 不通过则 report-only。

## 17. 实施阶段与交付边界

详细里程碑、owner、退出条件和发布矩阵见 [docs/ROADMAP.md](docs/ROADMAP.md)。总体顺序：

1. **M0 契约与只读骨架**：workspace、models/JCS/digest、protocol/schema golden、普通用户 capability probe、三平台 CI。
2. **M1 有界 Scanner**：portable adapters、aggregate/cache/spill、TUI、bounded JSON、fixtures/oracle；durable journal/replay 完成后再开放 NDJSON；无 deletion code path。
3. **M2 Cleaner 与 Catalog**：Z0 typed rules、Cargo/Chromium cache 示例、开发生态 report-only、签名/撤销/probe host。
4. **M3 Plan/Approval/Audit dry-run**：canonical plan、Broker、hard protection、preflight simulation、crash journal；adapter 仍编译为 deny-all。
5. **M4 Trash capability**：逐平台真实 gate 通过后按 capability 开放，默认 Trash；未通过平台保持 read-only。
6. **M5 Permanent R4**：仅在 nonrecursive primitive、directory manifest、fault injection 与人工 challenge 全通过后逐平台开放。
7. **M6 浏览器/manager 专项**：版本 adapter、完整 StorageKey、更多 Cleaner；任何 M mutation 需新 ADR，不自动纳入。

每个 milestone 同步更新 [README.md](README.md)、[Cleaner Catalog](docs/CLEANER-CATALOG.md) 与 [Roadmap](docs/ROADMAP.md)，不把关键决定只留在 issue/chat。

## 18. 风险、冲突与证据缺口登记

| ID | 类别 | 当前结论/冲突决议 | 实施动作或降级 |
|---|---|---|---|
| R-01 | TOCTOU | 三平台没有统一 identity-conditional atomic Trash；最后一次检查后仍有残余 race | held parent/object、<=2 s permit、无中间 I/O、manifest、reconcile；不能宣称消除 |
| R-02 | Trash 语义 | Trash 不是统一 syscall，也不保证所有 volume 恢复 | adapter capability allowlist；unsupported 保持 source，不 fallback Permanent |
| R-03 | 物理释放 | clone/reflink/snapshot/dedup/provider 使 per-file reclaim 不可精确 | 分列 logical/allocated/reclaimable/capacity delta；unknown 不相加 |
| R-04 | Holder | 普通用户无法完整看到所有 FD/mapping/kernel/provider 引用 | negative 永不授权；positive 升风险；不 kill/提权 |
| R-05 | Provider hydration | metadata API 是否触发下载依实现而异 | 平台实测监控网络/allocated delta；有疑问禁用增强 query |
| R-06 | Windows Trash | `IFileOperation` 对 partial/aborted/undo/destruction 的组合需真实验证 | 无法区分直接销毁则禁用 Trash；逐项 sink + aborted + postcheck |
| R-07 | Windows Permanent | exact no-follow primitive 与 link behavior 尚未固定 | adapter deny-all，待测试后 capability allowlist |
| R-08 | macOS link/Trash | `trashItem` symlink 行为和 pathname race 待实测 | 不能证明则禁用 link Trash；目录 Permanent 只用 nonrecursive primitive |
| R-09 | Linux capability | 最低 kernel、`openat2`/unique mount ID 缺失下的矩阵未定 | 缺 containment 时禁高风险目录/Permanent；明确 capabilities |
| R-10 | 浏览器漂移 | Chromium/Firefox/WebKit schema、锁、模型架构持续变化 | 固定 commit/milestone adapter、expiry、unknown version report-only |
| R-11 | Safari | 可见 Profile 到私有磁盘 store 的稳定映射未证实 | logical/unresolved；Safari UI only |
| R-12 | Edge model | Edge component ID/path 与 Linux 专用 policy 支持未证实 | 不套 Chrome ID；live inspect；Linux policy unknown/report-only |
| R-13 | Query 副作用 | “list/status/dry-run”可能启动 daemon、写 cache 或联网 | Z0 default；Z1 sandbox+write monitor；Z2/M 不在自动发现运行 |
| R-14 | Manager mutation vs Trash | manager GC 往往永久且无 filesystem Trash | v1 `managerPermanentRecommendation` only；未来独立 R4 action family |
| R-15 | Browser-supported delete vs Trash | 浏览器 API/UI 可能同步、登出且不可从 Trash 恢复 | 独立 semantic recovery/approval；v1 filesystem Cleaner 不冒充 |
| R-16 | Approval TTL/fingerprint | 上游只固定 approval <=5 min、permit <=2 s，plan/fingerprint 未定 | 本文定 plan 10 min、`SX1-`+12 hex；实现/UX 测试可用新 ADR 调整，不降低绑定 |
| R-17 | `PARTIAL` 定义 | 状态段与简表可能被读成仅“混合成功失败” | 本文定：只要 destructive batch 有明确 fail/skip 且无 ambiguity，包括全失败/全 skip，均 PARTIAL/exit 4；一般未成批失败才 exit 8 |
| R-18 | Approval events | public `approve` 禁 JSON，但 event vocab 含 approval event | 事件仅 core/TUI broker 内部/受权 watch；不泄露 record/challenge input |
| R-19 | Trust commands | Agent allowlist不含 install/remove/import/revoke | 明确为 human foreground 配置 mutation，不属于 cleanup approval |
| R-20 | Canonical/store | 上游未选 JCS/digest/DB | 本文选择 RFC 8785 + domain-separated SHA-256 + SQLite 分库；必须 golden/fault test |
| R-21 | State disk bound | scanner spill、cache、selection、manifest 原先分别给 quota | 改为内存优先和稀疏摘要：preview 64 MiB、spill 192 MiB/op 与 256 MiB global、selection 16 MiB、manifest 64 MiB，默认总 quota 512 MiB；满则降级/阻断 |
| R-22 | 性能事实 | 无可信跨产品同条件 benchmark | 只发布自有可复现数据，不宣称行业最快 |
| R-23 | 提权边界 | 用户可能在 admin/root 会话启动程序 | read-only capability 可报告；destructive mode 硬拒绝，不自动降权后继续 |
| R-24 | 插件 digest 示例 | 上游规则示例使用占位 digest | release lint 拒绝占位；构建生成真实 file table/digest/signature |

### 18.1 尚需平台证据的发布问题

- Windows：COM apartment/owner window、held handle sharing flags、NTFS/ReFS/FAT/exFAT/UNC/OneDrive、ADS 与 long/device paths。
- macOS：APFS/exFAT/network/File Provider resulting Trash locator、TCC/sandbox/FDA 组合、symlink Trash 和 Foundation link semantics。
- Linux：支持的最低 kernel/glib/GIO，ext4/XFS/Btrfs/Overlay/FUSE/NFS/headless、mount namespace swap、hidepid/LSM。
- 全平台：audit fsync/power-loss、non-expiring lock/fence、provider no-hydration、directory manifest scale、exact approval accessibility。

这些问题不是实现者自由猜测点：对应 capability 在 evidence 完成前必须关闭。

## 19. 规范性完成定义

首个可发布 MVP 只有在以下条件同时成立时才称完成：

- 三平台均能以普通用户做有界 live scan，错误/边界/unknown 可见，cache 关闭也保持正确；
- CLI/TUI/Agent 对同一事实产生相同 Candidate、Explanation、Plan digest 和风险；
- Cleaner Catalog 覆盖要求的开发生态、浏览器类别和本地模型，并逐项给出事实、推导、建议和 uncertainty；
- explicit execution authorization、live revalidation、硬保护、write-ahead audit 和 reconciliation 无旁路；Agent 路径必须使用 HumanApproval，不能调用 `--dangerously-delete`；
- Trash 是已开放 filesystem action 的默认，Permanent 仅在单独 R4 gate 通过的平台开放；
- 性能/内存/安全/故障 oracle 达标，未通过的能力在 `capabilities` 中明确为 unsupported/report-only；
- README、Catalog、Roadmap、Skill 与本设计没有相互冲突的安全语义，所有网络事实有直接 URL 与访问日期。

最终失败关闭原则：

```text
missing evidence -> risk never decreases -> report, skip, or re-plan
missing evidence != zero bytes != unused != permission to delete
Trash reported success != guaranteed recovery != guaranteed freed capacity
Permanent success != secure erase
```
