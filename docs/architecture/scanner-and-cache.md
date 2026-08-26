# SweepX 扫描、实时聚合与增量缓存架构

状态：v1 架构设计。研究与设计截点：2026-08-26。除非另有注明，本文引用的所有网络来源均于 **2026-08-26** 访问。

本文定义 Windows、macOS、Linux 上的只读扫描核心、实时聚合、增量缓存和可复现性能验证方法。本文不是实现，也不调用或执行删除。v1 始终以当前普通用户运行，只读取完成扫描所需的元数据；不提权，不取得 backup privilege/capability，不接管 ownership，不修改 ACL、TCC、文件属性或系统设置。

本文沿用上游研究的证据标签：已证事实表示上游一手资料直接支持；推导表示由事实导出的限制；产品设计表示 SweepX 选择；待实测表示发布前必须在真实平台验证、失败时保守降级的假设。平台 adapter 可以增加能力，不能降低共同下限：ordinary-user、metadata-only、no-follow、same-mount/volume、errors-visible。

## 1. 目标、非目标与不变量

目标：

1. 在本地快盘、慢盘、多个 root 以及 provider/网络边界并存时，提供有界、公平、可取消的并发扫描。
2. 扫描过程中持续输出可重建的进度、目录聚合、错误和 coverage，而不是等待全树结束。
3. 明确 logical size、filesystem-reported allocated size、potentially reclaimable 和 unknown 的不同口径。
4. 在不改变扫描正确性和安全边界的前提下，用有界的稀疏 preview cache 即时恢复 stale preview、安排 dirty/visible-first 扫描；缓存不保留普通小文件的逐项记录，v1 也不承诺减少文件系统 metadata query 数。
5. 以数据集 manifest、正确性 oracle 和完整环境记录建立可复现基准。

非目标：

- 不读取文件内容做 hash、分类或查毒；不主动 materialize/hydrate cloud placeholder。
- 不承诺任意文件的独占物理 extent，或删除后必定释放的精确字节。
- 不把缓存、mtime、变更通知、命名规则、年龄或进程观察当成持续有效的事实证明。
- 不跟随符号链接或未知 Windows reparse point；v1 不实现跨 mount/volume 的透明递归。
- 不生成 deletable=true 一类持久授权字段，不向删除执行器发送路径命令。

全局不变量：

1. unknown、unsupported、not_checked、incomplete 与数值 0 是五种不同状态。
2. 权限失败或消失竞态不会被表示为空目录或零字节；祖先结果是已观测 lower bound 且 complete=false。
3. 同一对象的 hard-link 数据在同一聚合口径内最多计一次；`nlink > 1` 使用精确 exception state，无法继续保存精确状态或覆盖范围不足时相应 unique/reclaimable 为 unknown。
4. 任一可增长内存结构都必须从预算器取得 byte permit；只有实测 charged memory 达到 high-water pressure 后才允许惰性创建有界、ephemeral spill。RAM 与 spill 都不可用时显式降级，不无界增长。
5. 缓存命中必须保留 freshness、coverage 和 provenance；缓存只加速，绝不授权删除。
6. 缺少证据意味着降低置信度并 report/skip，不意味着零字节、unused 或 permission to delete。

## 2. 统一类型与数据合同

### 2.1 扫描记录

平台 adapter 输出统一的 ScannedEntry。native_basename 保留平台原生无损表示：Unix 原始字节，Windows UTF-16；display_path 仅供展示。

    ScannedEntry {
      schema_version, scanner_semantics_version, adapter_version,
      scan_id, scan_root_identity, scan_timestamp,
      provenance: {
        admission: Live,
        fields: map<Field, FieldProvenance>
      },
      display_path,
      parent_identity,
      native_basename,
      object_type: Regular | Directory | Symlink | Reparse | Special | Unknown,
      platform_file_identity?,
      filesystem_object_domain_identity?,
      volume_or_mount_identity?,
      link_or_reparse_kind?, link_payload_digest?, hard_link_count?,
      logical_bytes: Known(u128) | Unknown(reason),
      allocated_bytes: Known(u128) | LowerBound(u128, reason) | Unknown(reason),
      reclaimable_estimate: Known(u128) | Unknown(reason),
      confidence: High | Medium | Low | Unknown,
      cloud_or_offline_state?,
      metadata_fingerprint,
      boundary?,
      errors: [ScanError]
    }

    FieldProvenance =
        LiveObservation { observed_at, method }
      | ValidatedCache { observed_at, validation_method,
                         covered_change_token }
      | DerivedFromCurrent { input_fields[], algorithm_version }
      | StalePreview { observed_at }
      | Unknown { reason }

filesystem_object_domain_identity 是 hard-link 身份所属的底层 filesystem/volume 域；volume_or_mount_identity 是本次遍历边界。Windows/macOS 上两者常相关，Linux bind mount 可有不同 mount ID 却暴露相同 st_dev/inode，因此二者不得合并。current ScannedEntry 的 admission、parent/basename、identity、type、mount 与 link kind 必须来自本代 live no-follow observation；不存在整条记录笼统的 cache provenance。每个可缓存字段单独记录来源和 validation method，StalePreview/Unknown 不参与 current aggregate 或候选。身份字段不是跨时间永久 ID；它们只在本次 root、mount snapshot、父目录和短期元数据指纹共同约束下使用。字段不可取得时写 Unknown(reason)，不得制造占位值。

### 2.2 目录聚合

    DirectoryAggregate {
      scan_id, directory_identity, revision,
      apparent_logical_bytes: Exact(u128) | LowerBound(u128, reason) | Unknown(reason),
      unique_logical_bytes: Exact(u128) | LowerBound(u128, reason) | Unknown(reason),
      filesystem_reported_allocated_bytes:
          Exact(u128) | LowerBound(u128, reason) | Unknown(reason),
      potentially_reclaimable_bytes:
          Exact(u128) | LowerBound(u128, reason) | Unknown(reason),
      unknown_size_entries,
      direct_child_count: Exact(u128) | LowerBound(u128),
      recursive_entry_count: Exact(u128) | LowerBound(u128),
      entries_seen, entries_accounted, directories_closed,
      skipped_entries, skipped_subtrees, error_count,
      boundaries: [BoundarySummary],
      complete: true | false,
      incomplete_reasons: [Reason],
      provenance_summary,
      arithmetic_state: Exact | Overflowed
    }

apparent_logical_bytes 按可见目录项相加；unique_logical_bytes 与 allocated 聚合按对象身份去重。存在任一 LowerBound 时，allocated 聚合最多也是 LowerBound；存在无法界定的 Unknown 时为 Unknown。跨 root 的 unique 合计只有在底层 object-domain 身份可比较且 adapter 宣告稳定时才生成，否则只提供 per-root unique 与 cross-root apparent，跨 root unique/allocated 为 Unknown。UI 必须标注口径。checked u128 加法失败时设置 Overflowed 并令对应值 unknown，不能饱和后继续显示为精确值。

一次正常关闭的浅层枚举最多把 `direct_child_count` 提升为 Exact；它不会证明任何 child directory 的后代数量或递归大小。只要后代尚未关闭，`recursive_entry_count` 和递归 byte aggregate 都是本代已观测值的 LowerBound。complete=true 只有在目录枚举正常关闭、所有已枚举 child 及其进入的 descendants 到达终态、无未进入边界、无权限/超时/取消/预算降级、且所用字段已在本代验证时成立。stale preview 的旧总量必须另行标注，不能混入该 lower bound。

### 2.3 错误与边界

    ScanError {
      class,
      operation: AdmitRoot | Enumerate | StatNoFollow | ReadLink | QueryAllocation |
                 QueryIdentity | QueryMount | CacheRead | CacheWrite,
      native_domain, native_code, retryable,
      observed_at, display_path?, object_identity?, detail
    }

稳定分类至少包括 AccessDenied、TccAclLsmDenied、SharingViolation、VanishedRace、SymlinkLoop、CrossDevice、ReadOnly、UnsupportedReparse、UnsupportedFilesystem、ProviderOffline、RecallAvoided、Timeout、TransientIo、PermanentIo、Interrupted 和 CacheCorrupt。保留原生错误码。

BoundarySummary 区分 symlink、directory reparse、mount/bind、network、FUSE、automount、pseudo/container mount、provider、read-only/system volume、depth/path limit 和 unknown type。边界是可见结果，不是静默丢弃。

## 3. 跨平台有界并发管线

### 3.1 数据流和所有权

    RootSpec
      -> [root admission / live root and mount snapshot]
      -> bounded DirTicket queue
      -> [platform enumerators]
      -> bounded EntryStub queue
      -> [no-follow metadata workers]
      -> bounded ScannedEntry queue
      -> [boundary + identity + size accounting]
      -> bounded AccountedDelta queue
      -> [single logical aggregate sequencer]
           |-> bounded ProgressSnapshot map -> UI / CLI consumer
           `-> eligible sparse records only
               -> bounded PreviewMutation queue -> [transactional sparse-preview writer]

每个消息拥有唯一 owner；移动到下一队列后上游释放其 byte permit。每阶段接收 EndOfRoot、Cancelled 和 FatalSession 标记。正常完成时，aggregate sequencer 收到该 root 的所有目录 close marker 且所有在途序号已结算后才发布 complete 终态。取消时，超过 deadline 的只读调用可被移入有界 quarantine、从当前 generation 断开并丢弃其迟到结果；此后可以发布 terminal incomplete/cancelled，但必须同时报告 quarantined operation 数，不能称资源已全部回收。禁止每 entry 创建独立线程、独立 future 或永久 task。

阻塞的本地文件系统 API 位于固定大小 blocking worker pool；潜在 hostile network/FUSE/provider 调用位于受监督 helper process 或独立 slow worker lane。异步控制面只负责调度、预算、取消和事件。固定 worker 不因卡住而补建；一个卡住的 slow worker 不得占用本地卷的全部 worker。

### 3.2 默认调度参数

以下是产品设计初值，不是平台保证，必须由基准校准：

| 资源 | 默认上限 | 规则 |
|---|---:|---|
| 全局 metadata workers | min(32, 4 × logical CPUs) | 只运行已取得队列和 byte permit 的任务 |
| 同一本地 volume 活跃调用 | min(8, logical CPUs) | SSD/HDD 可按实测 profile 下调 |
| network/FUSE/provider volume | 1 | 独立 lane，单调用 deadline 30 s |
| 同时打开的目录枚举器 | 64 | 关闭或暂停后才放行新 handle |
| 单 root 连续调度 quantum | 256 entries 或 10 ms | 先到者结束，避免大 root 饥饿其他 root |
| metadata batch | 最多 128 entries / 256 KiB | 不跨 volume，不延迟取消检查 |
| 本地单调用软 deadline | 5 s | 超时标记；不可取消调用隔离，不无限加 worker |
| 本地 blocking/quarantine slots | 最多 32；每本地 volume 最多 8 | 调用入场先占固定 worker slot；超时只把原 slot 改为 quarantine，不补建 |
| slow helper/quarantine slots | 全局 4；每 slow volume 1 | 每调用独占 helper；超时后仍占原 slot，直到 OS 确认退出 |

root scheduler 使用按 volume 分组的 deficit round-robin。每个 root 有独立 frontier 和配额；深目录每处理一个 batch 就把 continuation 放回队尾，宽目录流式发 EntryStub，不保存全部 child。小目录可批处理以减少切换。慢 lane 只能消费自己的并发令牌。

深度遍历使用显式 DirFrame，不依赖调用栈。默认最大深度 4096、单个 native path 表示 64 KiB；平台更严格限制仍优先。达到限制写 DepthOrPathLimit boundary，沿祖先传播 incomplete。

### 3.3 背压

每条队列同时受 message count 和 charged bytes 两个门限制；任一达到高水位即暂停 producer，降到低水位 70% 才恢复。默认 count 上限：DirTicket 4096、EntryStub 16384、ScannedEntry 8192、AccountedDelta 8192、PreviewMutation 4096。PreviewMutation 只接受第 8 节规则选中的稀疏 summary/reference；普通小文件不产生此消息。实际 byte 上限由第 6 节预算器决定，count 不是内存保证的替代品。

- 枚举器不能取得 EntryStub permit 时保留一个有界 continuation，然后暂停或关闭目录 handle。
- metadata worker 不能取得下游 permit 时不继续读取更多 entry。
- preview writer 变慢时最多反压 2 s；单次事务也有 2 s deadline。超时、I/O error、quota/full、lock loss 或 corruption 立即打开 circuit breaker：回滚 building generation，把尚未消费的 PreviewMutation 批量丢弃并写一个 CacheWrite/incomplete-cache 错误，此后本 session 不再投递 preview mutation。普通小文件只更新流式 aggregate/top-K heap，本来就不产生逐项 mutation。aggregate/terminal correctness lane 与 preview lane 分离并继续；缓存永远不能无限阻止 final aggregate 或 cancellation。
- UI 慢时，以 root/directory key 合并中间 ProgressSnapshot，默认最多 10 Hz。内存 progress map 最多 4096 key/16 MiB；超出时只保留每 root 汇总和当前可见目录。error/boundary 细节可由持久 journal 按 sequence 拉取；被淘汰的普通 entry/detail 没有持久逐项表，进入或展开时必须定向 live rescan。
- correctness detail/event journal 与 cache DB 分离，配 32 MiB/50,000 detail 硬上限、1 s 事务 deadline 和 256 KiB 预分配 emergency segment。错误/boundary 详情先写有界 journal batch，terminal event 只携带计数、首个分类和 durable sequence range。
- journal full/locked/corrupt/timeout 时立即停止新 admission，将未写详情合并为计数和类别 bitmap，使用只允许一次写入的 emergency segment 或预留内存 terminal slot 发布 DETAIL_PERSISTENCE_FAILED；所有受影响 root complete=false、details_lost=true。若连 emergency 写也失败，仍在内存 terminal snapshot 标记该事实并向 stderr 输出固定小记录，然后逻辑终止；不等待磁盘恢复，也不把丢失详情称为 complete。
- 不可丢 terminal lane 同时受 1024 message 与 2 MiB 限制。lane 满时反压 aggregate sequencer；若消费者持续不读超过 2 s，则合并为每 root 一个 terminal snapshot并丢弃被覆盖的中间进度，但不丢终态、计数或 details_lost。每 root 终态从预留 slot 取得，消费者可由 final snapshot 加仍可用的 durable ranges 恢复状态。
- preview cache 被禁用、损坏或空间不足时，扫描仍可继续；preview mutation 转为明确 CacheWrite 性能降级事件，但不能把本来正确的 aggregate 改成 incomplete，也不能改变 no-follow、coverage 或 size 语义。

### 3.4 取消、超时与重试

取消 token 为 session -> root -> volume lane -> operation 的层级结构：

1. 请求取消后 250 ms 控制面目标内停止接收新 root、停止新目录 admission，并发出 cancelling 快照。
2. worker 在取任务前、每个枚举 batch 后、增强查询前和队列写入前检查 token。
3. 每个 blocking 调用在 dispatch 前已经占有一个固定 local 或 slow slot。已进入内核或 provider 的不可取消调用不假装已取消；关闭可关闭的 handle，等待其 deadline，超时后把原 slot 原地改为 quarantine、与当前 generation 断开并记 Timeout/Interrupted。迟到结果必须丢弃，不能修改已终止 generation。
4. 有限 drain 只结算已取得结果的消息。未开始项目记 interrupted；所有未闭合目录及祖先 complete=false。
5. 取消 generation 永远不能提交为 complete cache generation。

仅 TransientIo、provider/network 的明确 transient 错误允许最多 2 次重试，指数退避 50 ms、200 ms 并加 0–25% jitter，且受原 operation deadline 约束。permission、unsupported、read-only、boundary、稳定 VanishedRace 不重试。任何重试都产生同一 logical operation 下的新 attempt 记录。

普通文件系统调用可能无法满足严格 wall-clock 资源回收，尤其 hostile FUSE/网络 provider；这是证据缺口。被隔离调用持续占用原 fixed worker/helper slot，绝不补建；因此本地最多 32（每 volume 8）、slow helper 最多 4（每 volume 1）个 quarantine。相应 slot 无容量时，dispatch 前即 fail-fast 为 ResourceUnavailable；不会出现无法归属的第 33/第 5 个 orphan。helper 可 best-effort terminate，但不把 kill 请求当已退出。发布测试必须分别验证“逻辑终止”（generation 已封闭且迟到结果无效）和“资源回收”；UI 文案只能说“扫描已取消，仍有 N 个平台调用待回收”，不能声称所有工作已停止。

## 4. 平台 adapter

| 维度 | Windows | macOS | Linux |
|---|---|---|---|
| 枚举/普通权限 | FindFirstFileW 等，当前 access token；不启用 backup privilege | Foundation enumerator 或 FTS/POSIX，当前用户；TCC/sandbox 错误可见 | getdents/readdir + statx/fstatat，当前 fsuid；不取 capability |
| no-follow 身份 | FILE_FLAG_OPEN_REPARSE_POINT；volume serial + FileIdInfo/file index | lstat；volumeIdentifier + fileResourceIdentifier 或 st_dev/st_ino | fstatat AT_SYMLINK_NOFOLLOW；对象域/身份为 st_dev + inode，遍历边界另用 statx mount ID |
| 边界 | 所有 directory reparse point 默认边界；mounted folder、UNC、unknown tag 单独列出 | symlink、volume、network、automount、File Provider、read-only system volume | mount ID；保存 /proc/self/mountinfo；bind/network/FUSE/overlay/pseudo 单独列出 |
| logical | 主数据流文件长度 | st_size / totalFileSize | st_size |
| allocated | 经验证为非 reparse 后查询 GetCompressedFileSize；ADS 另行枚举，缺失则 unknown | st_blocks 或 Foundation allocated keys | st_blocks × 512；可选 FIEMAP 只增加不确定性信息 |
| offline/provider | 不打开 OFFLINE/RECALL 内容 | dataless/File Provider 不 materialize | provider/FUSE/remote 不读内容，严格 timeout |

Windows 的 GetCompressedFileSize 会跟随 symlink。adapter 必须先 no-follow 确认普通文件、身份与 reparse 状态；对任一 reparse entry 不调用它，allocated 写 Unknown，除非未来有经平台测试的 handle-based 等价能力。ADS 每个 stream 独立占用：只有 stream 枚举完整且每个 allocation query 成功时才写 Known(total)；部分枚举/查询只能写 LowerBound(observed_total, incomplete_stream_coverage)，完全无法枚举则写 Unknown，不能只降低 confidence 后保留 Known。

macOS 的 Full Disk Access 不是 root，也不是完整 coverage 证明；sandbox root 只来自用户明确选择的只读 scope。Linux 仅凭 st_dev 不能识别 bind mount，必须优先 mount ID 和本次 mountinfo snapshot。OverlayFS 身份稳定性不足时降级为 unknown 或边界。

## 5. 大小、链接和卷的统一语义

### 5.1 四种不可混用的量

1. logical_bytes 是文件主数据流长度；目录聚合同时给 apparent 与 identity-deduplicated 视图。它不是物理占用。
2. allocated_bytes 是文件系统报告的归属量估计。Windows ADS、cluster rounding，APFS metadata，Linux 512-byte st_blocks 单位及平台能力差异都必须记录。
3. reclaimable_estimate 是带 confidence 的候选估计，可以 unknown。它不能由前两者简单复制。
4. 动作后的 caller-visible free-space delta 属于删除/审计层的事后观测，不是扫描值；Windows caller available、Linux f_bavail 与 macOS important-usage capacity 也不能横向当成同一口径。

null/Unknown 与 Known(0) 不同。对外使用 logical size、filesystem-reported allocated size、potentially reclaimable、scan incomplete、unknown；不得使用 exact disk usage、will free、unused 或 safe to delete。

### 5.2 sparse、compression 与共享 extent

- sparse/compressed 文件可能 logical 远大于 allocated，二者都保留。
- Windows ReFS clone/dedup、macOS APFS clone/snapshot/shared container、Linux reflink/dedup/snapshot/overlay/thin provisioning 使 per-file allocated 不等于独占空间。
- Linux FIEMAP 的 SHARED、UNKNOWN、DELALLOC、ENCODED 只能降低置信度；SHARED 不能量化独占 reclaim。
- quota、purgeable、provider、延迟分配和远端服务器统计进一步使 reclaimable unknown。

只要扫描器无法证明 extent 独占，不能把多个 allocated 值相加后称为将释放的空间。

### 5.3 symlink、reparse 和 hard link

symlink 默认只记录 link entry 自身，不进入 target。Windows 任何 directory reparse point 默认都是边界，不限于已知 symlink。v1 不启用 follow opt-in；未来若启用，必须理解 tag/type，并有 cycle、root containment、UNC/network、depth、mount、deadline 和取消限制。

hard-link 对象键：

- Windows：volume identity + FileIdInfo，fallback file index 必须标能力等级；
- macOS：volume/device identity + file resource identity/inode；
- Linux：filesystem object domain（通常 st_dev）+ inode；STATX_MNT_ID[_UNIQUE] 只用于遍历/mount 边界。bind-mounted alias 的 mount ID 可不同但底层对象键相同。OverlayFS 或不同 namespace 中若 adapter 不能证明 object-domain 可比较，则禁止跨 root unique 合并并置 Unknown。

流式观察每个可见名称用于 apparent 聚合；仅按第 7、8 节的稀疏预览规则保留名称记录。为避免扫描期间 `nlink=1 -> nlink>1` 或相反的竞态造成伪精确，所有可比较 ObjectKey 都进入仅本 operation 存活的最小 identity-accounting state；它只保留第一次出现的 directory-node reference、计数所需 size 和 link-count observation，不保留 display path 或完整 ScannedEntry，也不写 preview cache。再次出现时由 first/current node 计算各 directory scope 的 correction；`nlink>1`、重复 identity 或 link-count 转换再升级为 exact exception state。identity/link count 无法取得、同一 ObjectKey 的观察矛盾，或 state 在内存与有界 spill 都耗尽时，受影响 scope 的 unique logical/allocated/reclaimable 必须为 Unknown(IdentityUnstableOrResourceLimit)，不能退回按名称求和；apparent 聚合仍可继续。

若 nlink 大于本次范围内观察名称数，说明覆盖范围外可能仍有链接：针对删除候选的文件数据 reclaimable 为 unknown；若已知必有 surviving link，则为 Known(0)。目录项自身 metadata 与文件数据分开。

### 5.4 mount/volume 策略

root admission 固定 scan_root_identity、filesystem_object_domain_identity、volume_or_mount_identity、边界 policy 和 snapshot 时间。默认 same-mount/volume：nested mount、bind、mounted folder、network、FUSE、automount、pseudo/container、removable、provider 和 read-only/system volume只列 boundary，不递归。每个额外 root 必须单独 admission，不能因它位于某选中目录下而隐式进入；多个显式 root 聚合仍遵守上节 object-domain 可比较性规则。

Linux 保存 /proc/self/mountinfo 和可用的 STATX_MNT_ID_UNIQUE；mount namespace 或映射改变使对应 root cache 全失效。Windows mounted-folder reparse target 不属于父树。macOS APFS 同 container 的不同 volume 仍是不同遍历边界，尽管共享容量池。

### 5.5 权限和 cloud/provider

权限失败继续 siblings，并给失败子树、祖先写 incomplete 与 lower-bound。默认 metadata-only，不打开内容、不 hash。Windows recall/offline 属性、macOS dataless File Provider、Linux remote/provider 无证据时 local allocated/reclaimable 为 unknown。即使 metadata API 理论上不读取内容，provider 是否触发 hydration 仍需平台实测；失败时 adapter 停用相关查询。

## 6. 可证明的内存上限

### 6.1 预算模型

默认 tree-dependent memory budget B_scan = 128 MiB。所有 queue item、native path buffer、DirFrame、hard-link exception、aggregate delta、event/terminal snapshot 和 preview batch 按实际分配 capacity 加 25% allocator/容器余量收费。预算器发 byte permit 后才能创建；释放对象即归还。

    M_variable <=
        bytes(DirTicket queue)
      + bytes(EntryStub queue)
      + bytes(ScannedEntry queue)
      + bytes(AccountedDelta queue)
      + bytes(PreviewMutation queue)
      + bytes(active DirFrames, PendingDirectoryStates, native path arena)
      + bytes(identity accounting and exact hard-link exception state)
      + bytes(progress/event map and terminal lane)
      + bytes(correctness-journal transaction batches and emergency segment)
      + bytes(worker scratch)
      <= B_scan

默认受支持 build 设 aggregate private-memory envelope B_private_total=384 MiB，统计主进程与全部 helper 的 private RSS 之和：主进程 baseline/code/allocator headroom 96 MiB，B_scan 128 MiB，最多 48 个显式 1 MiB worker stack，数据库 page cache 且禁用 mmap 32 MiB，reserve 16 MiB；四个 helper 各由 OS job/cgroup/rlimit 或等价机制强制 private RSS <=16 MiB，总计 64 MiB，合计 384 MiB。不能提供可执行 per-helper 限额的平台不启用 helper，slow lane 只允许固定 worker并接受资源回收未知。启动实测主进程 baseline 超过 96 MiB 时先等额缩小 B_scan，低于最小 64 MiB 则拒绝该 profile；线程数、stack、DB cache、helper 数均不能动态突破。全局限额 allocator 拒绝超预算应用 heap allocation并转 ResourceLimit。平台库的隐藏 allocation/stack 和内核 page cache不能仅靠 Rust allocator绝对约束，因此 B_private_total 是必须由真实平台 parent+children RSS fault test 验证的发布 envelope；不通过则减少 worker/B_scan 或禁用相关 adapter。无论平台基线如何，随树规模增长的应用常驻量硬上限始终是 B_scan，不能随 entry 数线性增长。

默认 B_scan 子预算软配额：queues 32 MiB、path/frame 16 MiB、identity accounting/exception state 16 MiB、aggregate/event/terminal 12 MiB、preview batches 8 MiB、worker scratch 24 MiB、reserve 20 MiB。软配额可借 reserve，但总预算不可突破 128 MiB。

spill high-water 以预算器的 `M_variable_charged` 计量，不以进程 RSS 或 OS page cache 猜测：默认是 `0.75 * B_scan = 96 MiB`。达到后先 compact queue/arena、淘汰可重建 UI/preview detail；只有 compact 后 charge 仍 `>=96 MiB` 且下一项 correctness allocation 无法在 high-water 内取得 permit，才创建本 operation 的 spill。进入 spill 模式后以 `64 MiB` 为 low-water 形成 hysteresis；降到 `<=64 MiB` 前，可 spill 的新状态继续优先落盘。

### 6.2 极深、极宽与身份表

- Active DirFrame 只存 parent identity、enumeration cursor、pending child count 和 aggregate accumulator，不保存全部 child。枚举 handle 关闭但仍等 descendants 的 PendingDirectoryState 同样从 path/frame 子预算收费；child terminal delta 直接更新该 state，pending count 到零后才提交 aggregate 并释放。达到 6.1 的 `96 MiB` post-compaction high-water 前，不得仅因记录数或目录宽度而创建 spill。
- native path 使用分段 arena 和 parent-relative表示；display path 延迟渲染。单 entry 的异常长路径仍计费。
- RAM 是主存储。只有上述 high-water 条件成立，frontier/PendingDirectoryState、最小 identity-accounting state 和升级后的 hard-link exception state 才可事务性 spill；普通 entry 的 path/name/detail 与完整 ScannedEntry 永不因此落盘。spill 使用当前用户私有权限、generation tag、checksum、唯一索引和 checked counters，按 FIFO/DRR 取回；Bloom filter 等近似结构最多避免一次精确查询，不能决定计数正确性。
- scanner spill 是临时资源，包含 WAL/temp overhead 在内默认每个 scan operation 最多 192 MiB、进程全局最多 256 MiB。它与 preview cache 配额和生命周期完全分离；operation close/cancel 后删除，崩溃遗留物只在下次启动回收，永不作为结果或 preview 读取。整个 SweepX state directory 的 512 MiB 上下文上限包含其他 durable 状态，其具体 breakdown 由持久状态设计定义，不在本节重新分配。
- spill 不可写、任一配额达到或校验损坏时，不无界增长：停止受影响范围的新 admission，记录 visible ResourceLimit，complete=false，并结算已在途项目。若 `nlink` 不可得，或无法保持精确 exception state，受影响 unique logical/allocated/reclaimable 为 Unknown(IdentityUnavailableOrResourceLimit)；apparent aggregate 与仍可证明的 coverage 尽可能继续。

### 6.3 内存验收

测试必须逐项记录所有队列/terminal lane、PendingDirectoryState 的 count/byte high-water、budget charged、compact 前后 charge、spill-created/time/bytes（含 WAL/temp）、thread/helper/quarantine 数、主进程和 children private/mapped RSS。在 10 million entries、深度 4096、单目录 1 million child 和 `nlink=1`/`nlink>1`/扫描中 link-count 转换 fixture 上，charged bytes 不得超过 B_scan，aggregate parent+helper private RSS 不得超过经该平台验证的 B_private_total，所有 count/bytes 不得超配置。post-compaction charge 低于 96 MiB 的 run 必须没有 spill artifact；普通 entry 的 path/name/detail 在任何 run 都不得产生 spill row，最小 identity-accounting row 只为 exactness 临时存在；每 operation/global spill（含 WAL/temp）分别不得超过 192/256 MiB，complete/cancel/crash recovery 后必须清理。fault injection 还要覆盖 baseline 过大、native allocation spike、四个永久阻塞 helper 和 identity/exception-state exhaustion；必须 fail-fast/降并发且不补建第五个，资源耗尽时产生 visible incomplete/Unknown，而非 OOM、死锁、遗漏错误、double count 或伪精确 reclaimable。

## 7. 实时聚合与进度

### 7.1 确定性聚合

每个 EntryStub 获得 scan-local sequence。metadata 完成顺序可以任意，但 aggregate sequencer 按 identity accounting 规则应用幂等 delta_id。apparent 值对每个可见名称贡献；unique 值必须按“当前 aggregate 的 subtree scope + ObjectKey”去重，不能用全局 first-seen 决定所有目录。因而同一 hard-link 在两个 sibling subtree 中各自对两个 sibling 的 unique total 贡献一次，而在共同祖先/root 只贡献一次。没有可比较身份时 unique/allocated confidence 降级，不能靠路径猜同一对象。

聚合完全流式进行：每个可比较 identity 使用第 5.3/6 节的最小临时 accounting row，它不是 preview/detail row。首个 occurrence 贡献 apparent 与 unique，后续 occurrence 根据 first/current directory-node ancestry 对 sibling/ancestor/root scope 传播 correction delta；`nlink>1` 或 link-count 转换补充 exact exception evidence。不存在全 entry path spool、全树 cache、external sort 或离线 distinct pass。未闭合 descendants 的 recursive bytes/count 始终发布本代 LowerBound；全部 admitted descendant 闭合后才能转为 Exact。identity state 耗尽或观察不稳定时，受影响 unique logical/allocated/reclaimable 为 Unknown，绝不近似或写零。性质测试必须覆盖 sibling、ancestor、root、跨 root/bind alias，以及扫描中 hard-link add/remove。

每个目录枚举结束发送 EnumerateClosed(expected_child_count)。只有 expected child 全部进入终态，目录才 close；child error/boundary/cancel 传播 incomplete。cache record 中的某字段只有按 8.3 的 field-by-field 规则在本代完成 live query，或未来由经证据和实测批准的 field-covering token 验证后，才能产生 current delta；该字段标 ValidatedCache，并同时记录本代 validation method。StalePreview 不进入 current aggregate。迟到的字段失效先发送负 delta 撤销旧 revision，再发送 live delta；revision 单调递增。

最终结果不依赖 task 完成顺序。性质测试随机重排 metadata、cache 和错误完成顺序，要求最后 aggregate、errors、boundaries、complete 完全相同且无 double count。

每个 parent 在线维护 eligible preview children 的精确 top-K heap，默认 K=64；child directory 总是 eligible，leaf/detail 只有达到默认 32 MiB threshold 才 eligible。展示排序键 `preview_rank_bytes` 只服务 UI：优先取 `filesystem_reported_allocated_bytes` 的数值部分，allocated 为 Unknown 时回退 logical 的数值部分，两者均 Unknown 时置后；随后按 native basename 无损字节序和稳定 sequence 打破平局。每个 retained child 只有一条以 generation/parent/native-name/object identity 为键的 canonical row，并用 roles bitset 表示 top-K、large-leaf、candidate、error、boundary 或 ancestor-closure；多角色不重复成行或计数。top-K 最多标记 64 个 eligible direct children，mandatory/ancestor extra rows 不占排名槽。`Others` 精确等于 parent aggregate 减去 retained-child canonical contribution union，而不是减 role 数；普通小文件与其他未展示 settled contribution 汇入其中。其 Exact/LowerBound/Unknown 必须与当前 coverage 一致并严格对账。`preview_rank_bytes` 不能用于 reclaimable/candidate 判定。`Others` 没有 object identity 或 path，只是 aggregate：不可选择、不可作为 candidate、不可加入 plan。展开 `Others` 只会提高该 parent 的 live detail enumeration/rescan 优先级，不能选择整个 bucket。

### 7.2 ProgressEvent

    ProgressEvent {
      scan_id, root_id, volume_or_mount_id,
      sequence, aggregate_revision, phase,
      discovered, queued, in_flight, processed,
      skipped_entries, skipped_subtrees, errors, boundaries,
      logical_known, allocated_known, reclaimable_known, unknown_entries,
      queue_depths_and_bytes, active_workers,
      entries_per_second, metadata_ops_per_second,
      elapsed, complete_state,
      terminal: false | true
    }

树的最终 entry 数未知时不显示百分比。UI 显示已发现/已处理、pending、速率、活跃 worker、unknown 和 coverage。只有封闭且 complete 的预先枚举集合可以显示局部百分比。事件合并不得吞掉新错误、boundary、incomplete 原因或 terminal snapshot。

progressive presentation 先发布 roots 与已 live 枚举的 direct children；一次 shallow close 只使 direct_child_count 精确，recursive count/bytes 在 descendants 闭合前仍是 LowerBound。用户 enter/expand 某目录或 `Others` 时，scheduler 在同一按 volume DRR 内提升该目录/subtree 的 quantum 优先级，并执行 live detail enumeration/revalidation。缓存 detail 已淘汰或缺失时产生新的 live revision，绝不从 sparse cache 恢复为 current truth；因此 enter/expand 读取的不是一棵完整保留树。

## 8. 增量缓存

### 8.1 用途与信任边界

v1 增量缓存的加速边界是：扫描启动时立即恢复明确标为 StalePreview 的稀疏 UI；根据上代 sparse preview summaries/references 与 dirty hints 调整本次 live enumeration/metadata query 的优先级；在本代 live 输入字段完全相同后，复用不访问文件系统的纯派生展示/分类值。它没有完整 path/object index、entry catalogue 或 aggregate merge run，不跳过目录枚举、基础 no-follow identity/type/mount 查询或昂贵 allocation/provider/link-count 查询，因此不声称减少 v1 filesystem metadata ops。只有未来存在经一手证据和实测批准的 field-covering token 时，才可据此减少该字段查询。缓存不是事实权威，不能产生候选资格、deletability、审批或执行许可。imported、remote、stale 或 cache-only 数据只能展示为陈旧信息。

只有本次 live enumeration/admission 能触发候选；本代按字段验证的缓存值最多附着为解释数据。删除层即使接收这种 live candidate，也必须在执行前以 no-follow 的 parent + basename 重新解析并核对 parent identity、object identity、type、volume/mount、link/reparse 和 root containment。旧缓存永远不能替代该 gate。

### 8.2 generation、键和 schema

    GenerationKey = {
      host_instance_id, user_identity,
      root_identity, root_volume_or_mount_identity,
      mount_snapshot_digest,
      schema_version, scanner_semantics_version,
      adapter_capabilities_digest, scan_policy_fingerprint
    }

    ObjectKey = {
      platform, filesystem_object_domain_identity, platform_file_identity
    }

    PathIndexKey = {
      root_identity, parent_identity, native_basename
    }

对象键、遍历 mount identity 与路径索引必须分开。normalized path、mtime、ctime、size 单独或组合都不是身份。一个 ObjectKey 可对应不同 mount alias 下的多个 PathIndexKey，以保留 hard-link 名称并避免 bind alias 双计。file ID 可能复用，所以复用 retained reference 还必须比较父绑定、类型、generation 和 fingerprint；object-domain 不可比较时不做跨 root unique 聚合。ObjectKey/PathIndexKey 只属于下列被稀疏保留的 reference，不构成全树索引，也不要求每个 live ScannedEntry 有缓存 row。

    PreviewRecord =
        RootSummary
      | DirectorySummary
      | HeavyChildSummary
      | LargeLeafDetail
      | CandidateReference
      | HardLinkExceptionSummary
      | ErrorReference
      | BoundaryReference

每条 PreviewRecord 按适用性保存 generation_id、freshness、coverage、provenance、capability bitmap、validation_token、error TTL 和 scan policy。它不是 ScannedEntry 的超集，preview cache 也不是 entry catalogue。默认稀疏保留规则为：

1. 保留每个 root；任一被保留 record 的目录 ancestor chain 必须闭包到 root。
2. 每个 parent 按 7.1 的确定性顺序给最多 K=64 个 eligible child 标记 `top_k` role。top-K turnover 在一个事务中更新 canonical row 的 role 并修正 `Others`，不插入同 child 的第二行。
3. child directory 总是 eligible；非目录 leaf/detail 仅当 `preview_rank_bytes >= 32 MiB` 时 eligible。普通小文件即使被 live 扫描也不写逐项 preview row，top-K 不是绕过该阈值的入口。
4. candidate、error、boundary 不受 top-K 或 32 MiB threshold 淘汰，作为 mandatory role；ancestor closure 也只是同一 canonical row 的 structural role。mandatory row 仍受整个 cache 硬 quota 约束：先淘汰仅含普通 summary/top-K role 的 row；若连 mandatory row 及 ancestor closure 都无法提交，则回滚 preview batch并打开 circuit breaker，而不是静默丢记录或扩容。错误/boundary 的 correctness detail 仍由独立 journal 保证。

DirectorySummary 保存 stale aggregate、direct/recursive count 状态、`Others`、coverage、可选 change-hint cursor 和 closed_at，只用于 UI 预览和增量比较；v1 不用它跳过本次目录枚举。缓存不保存文件内容或持久 deletable 标志。cache miss/eviction 后的 detail 必须 targeted live rescan，不能从 ancestor summary 反推出一棵完整 child tree。

### 8.3 验证指纹和读取算法

MetadataFingerprint 至少覆盖当前平台可取得的：object type、object identity、parent identity、volume/mount、link/reparse kind 与 payload、logical/allocation metadata、mtime/ctime/change token、hard-link count、provider/offline state、filesystem capability bitmap、scan/no-follow/boundary policy 和 error state。不可用字段以 Unsupported/NotChecked 编码，不能省略后与零混同。

读取流程：

1. live no-follow admission root，比较 root identity、mount snapshot、当前用户和 policy。
2. v1 每次扫描都以当前普通用户 live 枚举每个进入的目录；枚举失败立即使 subtree incomplete，绝不复用旧 directory aggregate 来填补 coverage。对本次枚举出的每个 directory entry 做 parent + basename 的轻量 no-follow metadata 查询；这不表示持久化完整 path index。
3. 比较 identity、type、mount、link/reparse 和 validation fingerprint；不等即失效 entry 与祖先 aggregate。
4. v1 不存在可笼统称为“fresh enough”的昂贵字段。所有来源都使用 2.1 的唯一 FieldProvenance tagged union。allocation、provider/offline、link count 等字段只有两种方式能成为本代 current：本代执行相应 live query，记 LiveObservation；或 adapter 有上游一手证据且平台实测证明某 authoritative token 覆盖该精确字段，并在本代 live 读取 token 相等，记 ValidatedCache 且保存 observed_at/method/token。当前没有为三平台批准这种 field-covering token，因此 v1 对这些字段一律 live query；跳过查询时只以 StalePreview 展示并在本代 ScannedEntry 写 Unknown(NotRevalidated)，不能参与 current aggregate/candidate。纯派生字段只有其全部输入是本代 current 且 algorithm_version 相同时才可记 DerivedFromCurrent。
5. directory aggregate 永不整体作为本次 complete 结果复用；仅“目录 mtime 没变”或 change hint 无事件都不足。上代稀疏保留的 DirectorySummary 可先显示为 StalePreview，首次 live 结果到达即以新 revision 替换。
6. 混合 cached/live 聚合持续携带每部分 provenance；live 结果可修正旧 revision。

### 8.4 失效矩阵

| 事件 | 最小失效范围 | 后续动作 |
|---|---|---|
| schema/scanner semantics 不兼容 | 全库或对应表 | migration 经校验；否则冷扫 |
| adapter capability / size policy / boundary policy 改变 | 受影响平台字段、root aggregate | 现场刷新；不能沿用 complete |
| user/host/root identity 改变 | generation | 新 generation |
| volume/mount identity、namespace、mountinfo digest 改变 | root 或 volume | 全失效并重新 admission |
| parent rename / path index 改变 | entry path、旧/新 ancestor chain | no-follow 重索引 |
| child create/delete/rename 或收到 change hint | parent subtree 与 ancestors | 本次仍 live 枚举；hint 只调整优先级 |
| identity/type/link/reparse/payload/nlink 改变 | entry、object aliases、ancestors | 现场刷新；旧候选 stale |
| logical/allocation/provider/offline metadata 改变 | entry、ancestors | 现场刷新相应口径 |
| permission/read-only/capability 改变或无法证明未变 | entry/subtree | 本次 live 枚举/metadata 决定 coverage；旧 success/error 都不证明当前状态 |
| 上代 cancelled/crashed/incomplete | 未闭合 subtree、ancestors | 不得 complete hit |
| 可选 change feed 报告 gap/overflow/watch loss/rename pairing failure | 受影响 subtree；无法定界则 volume | 标 dirty；本次 live 枚举仍是事实来源 |
| 离线期间变化、通知不支持或通知语义未验证 | root/subtree | 不影响正确性；每次都 live 枚举 |
| TTL 到期 / 用户 refresh | 选中范围 | live revalidation |
| cache checksum/transaction 损坏 | generation 或全库 | quarantine 后冷扫 |

Windows USN/通知、macOS FSEvents、Linux inotify/fanotify 在 v1 只是可选、尚未由本上游研究验证的调度 dirty hint，不进入 correctness 或 complete 判定。收到事件可提前扫描相应范围；遗漏、gap、overflow、watch loss、权限变化、offline mutation 或不支持通知不会让错误结果被接受，因为每次扫描仍 live 枚举全部进入目录。未来若要凭 change feed 跳过枚举，必须先补充一手证据、定义 ACL/TCC/LSM 与离线变化 coverage、通过 gap/overflow 测试并升级 scanner_semantics_version；不满足则禁止该优化。

### 8.5 负缓存和一致性

AccessDenied、VanishedRace、Timeout、Unsupported、ProviderOffline 可以记录以解释上次结果，但默认只活到下次 scan admission，不能把 unreadable subtree 变成 empty/zero。重复稳定 permission error 可用不超过 30 s 的 UI 去抖 TTL；每次显式 refresh 都重验。incomplete aggregate 永远不能升级为 complete hit。

preview cache 单 writer，多进程通过 OS lock 选主；reader 只看 committed generation。每代状态为 building、complete 或 incomplete。eligible sparse preview batch 与 retained directory close 在事务中提交；崩溃前未提交的 close 不可见。校验和、外键/唯一索引和启动 integrity check 失败时 quarantine 数据库并冷扫。migration 必须保留 Unknown 语义；无法证明等价就重建。

默认 preview cache quota 为 64 MiB 或 100,000 个 sparse summary/reference records，先到者为准，包含 DB/WAL/index overhead；按 record priority、generation/last-validated LRU 清理。building generation 不能保留无限空间或豁免 quota：quota/full/lock failure 时回滚本 batch、打开 preview circuit breaker 并继续 correctness lane，不再写 cache。preview cache 与 6.2 的 ephemeral scanner spill 使用独立 quota/lifecycle，均采用当前用户私有权限；不存内容。整个 state directory 的 512 MiB 上限只是本组件必须参与的全局约束，durable breakdown 见持久状态设计。quota/锁/损坏只影响 preview convenience，不能放宽边界、改变 aggregate 或错误传播。

## 9. 可复现性能与正确性基准

### 9.1 环境清单

每次 run 生成只读 result bundle，记录：git revision、dirty state、编译器与依赖 lock digest、release build flags、OS edition/version、kernel/build、CPU 型号/核数、RAM、存储介质/控制器、filesystem/version、volume/mount options、加密/压缩/dedup/provider 状态、普通用户身份类别、并发/队列/内存配置、cache DB 状态、fixture seed 与 manifest SHA-256。

不得把 OS page cache 和 SweepX cache 混称 warm cache。cold OS-cache run 在 disposable VM snapshot 或 reboot 后进行；产品本身不提权 drop caches。若平台无法可靠清 page cache，记录为 reboot-cold 或 uncontrolled，而不是声称 cold。

### 9.2 可重建 fixture

fixture generator 接收固定 seed 和 JSON manifest，只负责构造；独立 oracle verifier 不链接 scanner crate，也不读取 scanner 输出生成期望值，而使用原生 fixture creation receipts、平台查询工具和预先定义的规范模型验证：

- 深树：深度 4096；宽树：单目录 1 million entries；规模：1M/10M 小文件；
- 少量大文件与混合 log-normal size；显式包含 32 MiB - 1 byte、32 MiB、32 MiB + 1 byte 的 leaf/detail；
- 同一 parent 下超过 64 个 child directories，并构造相同 `preview_rank_bytes` 以验证稳定 tie-break、top-K turnover 与 `Others` 对账；candidate/error/boundary 放在排名 64 之外；
- hard-link fan-out 同时覆盖 `nlink=1`、`nlink>1`，以及链接全部在 root、部分在 root 外两种；
- symlink cycle、Windows known/unknown reparse、nested/bind/mounted folder boundary；
- sparse、compressed、ADS；支持时 APFS clone、ReFS clone、Btrfs/XFS reflink；
- permission-denied child 与 readable sibling、enumerate 后 vanish、read-only、slow/error injection；
- provider placeholder，测试期间监控网络/下载/allocated delta，验证不主动 hydrate。

oracle manifest 保存每个预期 identity class、边界、错误、logical/allocated 已知值或 unknown、hard-link equivalence 和 complete 预期。竞态场景由独立 fault controller 与 scanner 通过 named barrier 同步，例如 ENUMERATED -> 删除/替换 -> CONTINUE；timeout、notification loss、cache-writer crash、provider hydration 也使用预先生成的 event script，保存实际 barrier/event trace。oracle 根据 manifest + creation receipt + trace 推导唯一预期，不按 scanner 结果自适应。性能 run 只有 oracle 全通过才有效；通过漏报错误或跳过边界获得的速度判为失败。

### 9.3 场景和步骤

场景：cold full scan、warm OS page cache 但空 SweepX cache、warm sparse-preview cache、1% localized create/delete/rename/resize、notification gap 后失效、schema/policy 全失效、取消、permission error、slow network/FUSE/provider lane、preview writer 限速、correctness-journal failure、preview corruption、preview-quota exhaustion 和 spill-limit。另设 shallow-first、expand/enter priority、evicted-detail live rescan、top-K turnover，以及刚低于/刚高于 B_scan high-water 的成对 run。v1 warm cache 的预期收益只计 time-to-first-preview、dirty/visible-first latency 和 sparse DB write reduction；filesystem metadata ops 必须与正确 cold semantics 等价，不能把少查 metadata 当 v1 成功。全普通小文件 fixture 必须产生零个逐项 preview row；低于 high-water 的 run 必须不创建 spill；quota/cache failure 不得改变最终 aggregate 语义。缓存 mutation 还必须覆盖：Windows ADS-only create/remove/resize，sparse hole punch/fill，compression flag/state 改变，provider offline/dataless/materialized 状态改变，hard-link 在 root 内外 add/remove/rename，symlink/reparse type/payload 变化，mount/bind remap，以及 ACL/TCC/LSM permission 变化。每例验证旧字段只成为 StalePreview/Unknown，除非本代 live query 得到新值。

每个 scenario 从 immutable VM/disk snapshot 或 fixture generator receipt 重新恢复；删除并重建 SweepX cache/spill、恢复指定 notification cursor、重置 fault-controller script，并记录 pre-run tree receipt/cache DB hash/state ID。warm-OS 与 warm-SweepX 场景按 manifest 明确执行预热步骤；mutation/corruption 只应用于该 run 的可丢 clone，结束后丢弃。cold 场景按 9.1 的 reboot/snapshot 规则恢复。

吞吐/wall time 每个环境先 1 次不计分 warm-up，再至少 15 个独立 reset run，报告 median/min/max/MAD。p95/p99 不从 7 次 run 估算：time-to-first-result、event 和 cancel latency 每种至少收集 200/1000 个独立、分层覆盖 root/volume 的 observation；使用 nearest-rank quantile（p95=ceil(0.95N)、p99=ceil(0.99N) 的有序样本），同时保存 bootstrap 95% CI、原始 observation 与所属 run。样本不足则不报告/不执行对应 percentile gate。跨硬件不比较绝对排行榜，只对同 fixture/environment 的基线 revision 做回归。

### 9.4 指标与初始 gate

记录 wall time、entries/s、metadata ops/s、CPU user/system、I/O bytes/ops、time-to-first-result、progress event latency、peak private/mapped RSS、budget charged、每队列 count/byte high-water、open handles、preview validation/hit/miss、各 PreviewRecord tag 的 count/bytes、ordinary-entry row count、DB/write amplification、spill-created/time 及每 operation/global bytes（含 WAL/temp）、state-directory bytes、top-K/`Others` reconciliation、targeted live-detail rescan count、error latency、取消控制面与最终 settle latency。

初始 release gate（均为产品目标，平台实测后可收紧，不可无证据宣称已达成）：

- 正确性 oracle 100% 匹配；任何错误、boundary、unknown、complete 或 hard-link double-count 差异即失败。
- charged tree-dependent memory <=128 MiB；aggregate parent+helper private RSS <=384 MiB；所有 queue/terminal/pending-directory high-water <= 配置。
- scanner spill 每 operation <=192 MiB、进程全局 <=256 MiB（均含 WAL/temp）；post-compaction `M_variable_charged <96 MiB` 的 run 不得创建任何 spill artifact，进入 spill 模式后使用 64 MiB low-water hysteresis，结束/取消/崩溃恢复后不得残留可读 generation。
- preview cache <=64 MiB 且 <=100,000 sparse records；ordinary small-file preview rows 恒为 0。每 parent directory top-K=64，强制 candidate/error/boundary 独立保留，显示行 + `Others` 必须与 parent aggregate 对账；`Others` 始终不可选择、不可成为 candidate、不可规划。
- correctness detail/event journal <=32 MiB 且 <=50,000 details，emergency segment 预分配 256 KiB；scanner 参与的整个 state directory 仍须服从 512 MiB 全局上限，durable 分项预算由对应设计统一校验。
- shallow close 之前和之后都不得在 descendant 未闭合时把 recursive count/bytes 标 Exact；enter/expand 必须提高 live enumeration/rescan 优先级并发布新 live revision，不能把 cached detail 直接升级为 current。
- 本地可响应工作负载 time-to-first-result median <= 500 ms；事件 p95 <= 250 ms。
- cancel admission stop p95 <= 250 ms；cooperative work 的逻辑终止不超过最长 deadline + 1 s。不可取消调用到 deadline 后可进入 quarantine，terminal 状态必须分别报告 local/slow 数量；resource-reap latency 单独观测且不设伪造上限。local quarantine 不超过每本地 volume 8/全局 32，slow helper quarantine 不超过每 slow volume 1/全局 4；任一槽满后对应 lane 在 dispatch 前 fail-fast，hostile provider 不阻塞其他 lane。
- 同环境 median throughput 相对批准基线下降超过 10%，或 p95 首结果/取消回退超过 20%，需要解释和审批。
- sparse preview 快不能以减少 live root/mount/fingerprint 验证为代价。

## 10. 测试与发布门槛

### 10.1 自动测试清单

- 单元：三种 size 与 unknown、checked overflow、identity key、最小 identity-accounting row、`nlink>1` exact exception dedup、扫描中 link-count 转换、complete/LowerBound 传播、top-K 稳定 tie-break、canonical row 多角色去重、`Others` 对账/不可选择/不可规划、32 MiB threshold、mandatory candidate/error/boundary retention、cache fingerprint、失效矩阵、migration、损坏冷扫。
- 性质/并发：随机 completion order 最终聚合一致；hard-link 在 sibling/ancestor/root scope 各自正确且无 double count；exception state 耗尽转 Unknown；慢 consumer/writer 与 journal failure 走有界降级；queue 与 terminal lane 不越界；取消无死锁；迟到 quarantine 结果不能修改终态；crash 不产生 complete generation；丢失全部 change hints 仍因 live enumeration 得到相同结果。
- 集成：symlink/reparse no-follow、cycle、same-mount、bind/mounted-folder、权限失败 sibling continuation、enumerate/stat race、timeout/retry、placeholder 无主动 hydration、partial/cancelled generation；shallow direct count 与 recursive LowerBound；enter/expand priority 和 evicted-detail live revision；high-water 以下零 spill、192/256 MiB spill caps/cleanup；64 MiB/100,000 sparse preview caps 与普通小文件零 row。
- 安全边界：伪造 cache 的 path/identity/type/mount/link/deletable 字段，只能导致失效/冷扫，不能产出删除许可。
- 文案 lint：拒绝 unqualified exact disk usage、will free、unused、safe to delete、guaranteed recoverable/unrecoverable。

### 10.2 待平台实测假设

| 平台/owner | 假设与环境 | 方法与期望 | 失败时降级 |
|---|---|---|---|
| Windows adapter owner | NTFS/ReFS/FAT/exFAT；FileIdInfo、long path、DACL | replacement/race fixture；ID 与 parent binding 可检测变化 | identity 不足的目录 complete=false，禁用复用 |
| Windows adapter owner | sparse/compressed/ADS、ReFS clone/dedup | 与系统工具/fixture oracle 比 logical、allocated；共享数据 reclaim unknown | allocated 或 ADS coverage 置 unknown |
| Windows adapter owner | symlink/junction/mounted folder/unknown reparse/UNC/OneDrive placeholder | 证明 no-follow 且 GetCompressedFileSize 不作用于 reparse；监控 recall | 列 boundary，不做增强查询 |
| macOS adapter owner | APFS sparse/compression/clone/snapshot/shared container | st_blocks/Foundation keys 与 fixture 对照 | 仅报告支持字段，reclaim unknown |
| macOS adapter owner | TCC、sandbox scope、File Provider dataless、network/automount、signed volume | denied 可见、metadata scan 不主动下载 | provider 字段 unknown 或 root boundary |
| Linux adapter owner | ext4/XFS/Btrfs/OverlayFS；statx/FIEMAP | 验证 mount ID、flags、reflink/delalloc 传播不确定性 | 缺能力时不用 st_dev 猜 bind，列 boundary |
| Linux adapter owner | bind/nested/FUSE/NFS、mount namespace、LSM、change-hint 丢失 | 验证 bind alias object key 去重；丢 hint 仍由 live enumeration 正确；其他 lane 有响应 | 跨 root unique 置 unknown；慢 lane 隔离 |
| Performance owner | 10M entries、深/宽树、1M `nlink=1`/`nlink>1` identities、四个阻塞 helper | 验证 128 MiB B_scan、384 MiB aggregate RSS、192 MiB/operation 与 256 MiB/global lazy spill、64 MiB/100k sparse preview、普通小文件零 row、shallow/top-K/`Others` gate 及 oracle | 缩小默认并发/B_scan；无法保持 exact exception 时置 Unknown 或失败关闭受影响 root |

表中期望不是已证保证。每个支持 OS/filesystem 组合必须保存原始测试 bundle；未通过时只提供能力较小的扫描 profile，不能用推测补齐字段。

## 11. 上游证据与明确缺口

本设计直接采用上游平台研究中的事实和一手链接：

- Windows 枚举、身份、reparse、大小与云属性：[FindFirstFileW](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-findfirstfilew)、[FILE_ID_INFO](https://learn.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-file_id_info)、[Reparse points](https://learn.microsoft.com/en-us/windows/win32/fileio/reparse-points)、[GetCompressedFileSize](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getcompressedfilesizew)、[File streams](https://learn.microsoft.com/en-us/windows/win32/fileio/file-streams)、[Cloud Files API](https://learn.microsoft.com/en-us/windows/win32/cfapi/build-a-cloud-file-sync-engine)。
- macOS 身份、allocated、APFS 与边界：[Darwin stat(2)](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man2/stat.2.html)、[fileAllocatedSize](https://developer.apple.com/documentation/foundation/urlresourcekey/fileallocatedsizekey)、[totalFileAllocatedSize](https://developer.apple.com/documentation/foundation/urlresourcevalues/totalfileallocatedsize)、[fileResourceIdentifier](https://developer.apple.com/documentation/foundation/urlresourcevalues/fileresourceidentifier)、[volumeIdentifier](https://developer.apple.com/documentation/foundation/urlresourcekey/volumeidentifierkey)、[About Apple File System](https://developer.apple.com/documentation/foundation/about-apple-file-system)、[FileManager enumerator](https://developer.apple.com/documentation/foundation/filemanager/enumerator(at:includingpropertiesforkeys:options:errorhandler:))。
- Linux 大小、身份、mount 与 extent：[statx(2)](https://man7.org/linux/man-pages/man2/statx.2.html)、[stat type](https://man7.org/linux/man-pages/man3/stat.3type.html)、[proc mountinfo](https://man7.org/linux/man-pages/man5/proc_pid_mountinfo.5.html)、[openat2(2)](https://man7.org/linux/man-pages/man2/openat2.2.html)、[FIEMAP](https://docs.kernel.org/filesystems/fiemap.html)、[OverlayFS](https://docs.kernel.org/filesystems/overlayfs.html)。
- POSIX 对 hard link、symlink 和权限的基础语义：[POSIX stat](https://pubs.opengroup.org/onlinepubs/9799919799/functions/stat.html)、[POSIX unlinkat](https://pubs.opengroup.org/onlinepubs/9799919799/functions/unlinkat.html)、[path_resolution(7)](https://man7.org/linux/man-pages/man7/path_resolution.7.html)。

证据仍不能保证：任意对象的独占 extent；shared clone/reflink/snapshot 集合的精确释放量；每个 provider 的 metadata 访问永不 hydration；跨平台统一大小；普通用户完整 coverage；cache snapshot 在下一瞬间仍有效。SweepX 因此把这些结果保留为 unknown/低置信度，并把最新 live 复验留给后续安全执行边界。

最终原则：

    missing evidence -> lower confidence -> report or skip
    missing evidence != zero bytes != unused != permission to delete
