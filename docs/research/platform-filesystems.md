# Windows、macOS、Linux 文件系统语义与保守清理边界

研究截点：2026-08-26。除非单独注明，本文所有网络来源均于 **2026-08-26** 访问。本文只研究只读扫描和安全产品设计；没有删除文件、请求提权或更改系统设置。优先引用 Microsoft、Apple、freedesktop.org、Linux kernel/man-pages、POSIX 与上游项目资料。

## 结论摘要

跨平台扫描器可以统一“展示层”，不能假设三平台具有统一的文件身份、回收站、物理占用或“正在使用”语义。最小安全合同应是：

1. 以当前普通用户、只读元数据方式扫描；不自动提权。
2. 默认不跟随符号链接或 Windows reparse point，不跨 mount/volume。
3. 分列 `logical bytes`、`filesystem-reported allocated bytes`、`estimated reclaimable bytes` 和 `unknown/unscanned`；后两者允许未知。
4. 权限失败、离线占位、超时、竞态和不支持的文件系统能力都是一等结果，绝不能当作空目录或零字节。
5. 清理前重新核验父目录、名称、对象类型、volume/mount 与 file identity；旧扫描只是一张快照。
6. 使用 Windows `IFileOperation`、macOS `FileManager.trashItem`、Linux GIO/freedesktop Trash 等平台接口；Trash/Recycle Bin 不等于已经释放空间。
7. “进程正在使用”只能 best-effort 观测。没观测到不是安全证明；观测到也不总意味着不能 rename/unlink。

## 术语与证据标签

- **已证事实**：引用的一手资料直接支持。
- **推导**：从已证事实得到，但不是平台厂商保证。
- **产品建议**：拟议产品的保守行为。
- **证据缺口**：公开稳定接口没有给出可靠答案，或能力依赖具体文件系统/provider。

本文中的“物理占用/allocated”通常仍是文件系统报告的归属量，不是独占物理扇区计数，也不是删除后必然增加的可用空间。

## 平台差异速览

| 维度 | Windows | macOS | Linux | 统一保守行为 |
|---|---|---|---|---|
| 普通用户边界 | access token + DACL；UAC 管理员通常也先以过滤 token 运行 | POSIX/ACL + TCC/Full Disk Access + 可选 App Sandbox；FDA 不等于 root | mode bits/ACL + capabilities + LSM + namespace | 当前身份扫描；记录 coverage；不把提权作为默认修复 |
| 推荐回收接口 | Shell `IFileOperation`，undo “where possible” | `FileManager.trashItem(at:resultingItemURL:)` | GIO `g_file_trash()` / freedesktop Trash | 回收失败即停止；不静默 permanent delete |
| 回收站实现 | Shell virtual known folder；不得直接操作 `$Recycle.Bin` | 使用 Foundation API；私有 `.Trash/.Trashes` 布局不是稳定合同 | 规范定义 `$XDG_DATA_HOME/Trash` 与挂载点 trash 结构 | 回收后仍占空间；empty trash 是独立破坏性动作 |
| logical | 文件主流长度 | `st_size` / Foundation total size | `st_size` | 明确标为 logical，不称“可释放” |
| allocated | `GetCompressedFileSize` 等；需考虑 ADS/cluster | `st_blocks`、Foundation allocated-size keys | `st_blocks * 512` | 叫“文件系统报告的 allocated estimate” |
| shared data | hard links、ReFS block clone、Windows Server Data Deduplication 等 | hard links、APFS clone、snapshot | hard links、reflink、snapshot、overlay/thin provisioning | 共享 extent 时不相加为 reclaimable |
| 链接/边界 | symlink/junction/mount/cloud placeholder 都可能是 reparse point | symlink + volume/mount；APFS container 内多 volume 共享空间 | symlink + mount namespace/bind/overlay/automount | 默认 no-follow、same-mount；未知类型跳过 |
| in-use 观测 | Restart Manager（文件级）；系统级 Handle 需管理员 | `lsof`/内核信息，受权限、平台安全策略与 race 限制 | `/proc`/`lsof`，受 ptrace/hidepid/namespace/LSM 限制 | 显示“在检查时观测到”，不称 lock oracle |

## Windows

### 1. 普通用户权限边界

**已证事实**

- Windows 将请求的 access mask、调用者 access token 与对象 security descriptor/DACL 比较；看到路径不代表能遍历、读取或删除。[File security and access rights](https://learn.microsoft.com/en-us/windows/win32/fileio/file-security-and-access-rights)、[How DACLs control access](https://learn.microsoft.com/en-us/windows/win32/secauthz/how-dacls-control-access-to-an-object)
- `FindFirstFileW` 要求调用者能访问给定路径中的目录，因此枚举父目录成功后仍可能在后代处失败。[FindFirstFileW](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-findfirstfilew)
- UAC 下，即使账户属于 Administrators，应用通常先拿 filtered standard-user token；完整权限需要显式 elevation。[How UAC works](https://learn.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works)
- `SeBackupPrivilege` 与 backup semantics 可以绕过部分普通检查，但这是备份程序特权，不属于普通用户扫描。[File security and access rights](https://learn.microsoft.com/en-us/windows/win32/fileio/file-security-and-access-rights)
- 删除要求对象本身的 `DELETE` 或父目录的 delete-child 权限；read-only 属性又是单独障碍。[DeleteFile](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-deletefile)、[File access rights](https://learn.microsoft.com/en-us/windows/win32/fileio/file-access-rights-constants)

**推导**：扫描时算出的 `deletable=true` 只能是提示。ACL、属性、父目录、句柄和路径绑定都可能在执行前改变。

**产品建议**：默认 unelevated；不启用 backup privilege、不接管 ownership、不改 ACL。逐项记录 `access_denied` 等错误，继续扫描 siblings；目录总计标记为 lower bound/incomplete。

### 2. Recycle Bin 机制与接口

**已证事实**

- Microsoft 在 Vista 及以后推荐 `IFileOperation` 取代旧 `SHFileOperation`；`DeleteItem` 排队，`PerformOperations` 执行。[IFileOperation::DeleteItem](https://learn.microsoft.com/en-us/windows/win32/api/shobjidl_core/nf-shobjidl_core-ifileoperation-deleteitem)、[SHFILEOPSTRUCT](https://learn.microsoft.com/en-us/windows/win32/api/shellapi/ns-shellapi-shfileopstructw)
- operation flags 可请求保留 undo、建立 undo record，并在无法回收而会直接销毁时警告；文档明确说 undo 只在 “if possible” 时成立。Windows 8 及以后另有 `FOFX_RECYCLEONDELETE`，其语义才是明确请求送入 Recycle Bin。[SetOperationFlags](https://learn.microsoft.com/en-us/windows/win32/api/shobjidl_core/nf-shobjidl_core-ifileoperation-setoperationflags)
- 操作可能由用户或系统中止；调用者还应检查 `GetAnyOperationsAborted`，不能只看顶层返回值。[GetAnyOperationsAborted](https://learn.microsoft.com/en-us/windows/win32/api/shobjidl_core/nf-shobjidl_core-ifileoperation-getanyoperationsaborted)
- Recycle Bin 是 Shell virtual known folder，不是应由应用直接拼出的普通目录；`SHQueryRecycleBin` 可查指定盘回收站统计，`SHEmptyRecycleBin` 执行清空。[Known folders](https://learn.microsoft.com/en-us/windows/win32/shell/knownfolderid)、[Shell namespace](https://learn.microsoft.com/en-us/windows/win32/shell/namespace-intro)、[SHQueryRecycleBin](https://learn.microsoft.com/en-us/windows/win32/api/shellapi/nf-shellapi-shqueryrecyclebinw)、[SHEmptyRecycleBin](https://learn.microsoft.com/en-us/windows/win32/api/shellapi/nf-shellapi-shemptyrecyclebinw)

**推导**：在典型受支持的本地卷上，移入 Recycle Bin 会保留数据供恢复，因而不代表空间已经释放；path/provider、卷类型、策略、容量等会改变行为或使回收不可用。

**产品建议**：在 Windows 8 及以后，于 STA 线程使用 `IFileOperation`、真实 owner window、progress sink，并设置 `FOFX_RECYCLEONDELETE` 作为 recycle-only 强制语义；`FOF_WANTNUKEWARNING` 只能是附加防线，不能充当 recycle-only 保证。逐项检查 `PostDeleteItem` 结果和 `GetAnyOperationsAborted`；不能回收时保持原文件并令本次 Trash 动作失败，绝不改用普通永久删除重试。若调用者随后另行要求永久删除，必须从新的 live scan 开始，创建新的 Permanent R4 计划并取得新的显式授权（HumanApproval 或 `--dangerously-delete`）后进入独立批次；禁止沿用 Trash 计划或审批。禁止直接操作 `$Recycle.Bin`。旧于 Windows 8 或无法证明 recycle-only 能力的平台组合保持 destructive capability 关闭，进入待实测/不支持状态。

### 3. 逻辑大小、allocated 与稀疏/压缩/共享数据

**已证事实**

- `WIN32_FIND_DATA.nFileSizeHigh/Low` 是文件长度，即 logical size。[WIN32_FIND_DATA](https://learn.microsoft.com/en-us/windows/win32/api/minwinbase/ns-minwinbase-win32_find_dataw)
- `GetCompressedFileSize` 返回命名文件的磁盘存储量，并对支持它的卷反映 sparse/compressed 大小；若输入是 symlink，它会跟随并报告 target。[GetCompressedFileSize](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getcompressedfilesizew)
- 一个文件的每个 stream 分别有 allocation size、actual size 与 valid data length，也可分别 sparse/compressed/encrypted。[File streams](https://learn.microsoft.com/en-us/windows/win32/fileio/file-streams) Alternate Data Streams 可额外占空间，需用 `FindFirstStreamW`/`WIN32_FIND_STREAM_DATA` 枚举。[FindFirstStreamW](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-findfirststreamw)
- sparse 文件的未写零区间不分配 cluster，logical 可远大于 allocated。[Sparse files](https://learn.microsoft.com/en-us/windows/win32/fileio/sparse-files)
- ReFS block cloning 让多个文件通过引用计数共享物理 cluster，写入时再分配。[Block cloning](https://learn.microsoft.com/en-us/windows/win32/fileio/block-cloning)
- Windows Server Data Deduplication 会在受支持卷上识别重复数据并以共享存储表示；其可用性受 Windows Server 版本、卷/文件系统和工作负载限制，不能与 ReFS block cloning 混为同一机制。[Data Deduplication overview](https://learn.microsoft.com/en-us/windows-server/storage/data-deduplication/overview)、[interoperability](https://learn.microsoft.com/en-us/windows-server/storage/data-deduplication/interop)
- quota 可使调用者可用空间不同于总空闲空间；`GetDiskFreeSpaceExW` 分别返回 caller-available 与 total free。[GetDiskFreeSpaceExW](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getdiskfreespaceexw)

**推导**：logical、每文件 allocated 之和、删除候选集合后 free-space 增量三者都可能不同。ADS、allocation rounding、hard link、ReFS clone/dedup、quota 与回收站保留都会破坏简单等式。

**产品建议**：同时展示 logical 与 allocated estimate；支持时计入/标出 ADS。ReFS、dedup、cloud-tiered、网络盘上降低置信度。动作后按受影响 volume 比较 caller-visible free space，作为 observed delta 单列，不能反过来宣称预估精确。

### 4. 符号链接、硬链接、挂载卷与 reparse point

**已证事实**

- NTFS 多个目录项可引用同一文件；handle 信息含 link count、volume serial 与 file index，`FileIdInfo` 可给 volume serial + 128-bit ID。ID 支持依文件系统而变，也不是跨时间永不复用的全局 ID。[BY_HANDLE_FILE_INFORMATION](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/ns-fileapi-by_handle_file_information)、[FILE_ID_INFO](https://learn.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-file_id_info)、[Hard-link backup guidance](https://learn.microsoft.com/en-us/windows/win32/backup/backing-up-and-restoring-hard-links)
- 删除一个 hard-link 名称不会释放仍被其他链接引用的数据。[Hard links and junctions](https://learn.microsoft.com/en-us/windows/win32/fileio/hard-links-and-junctions)
- symlink、junction、mounted folder、cloud placeholder、dedup/filter 都可能表现为 reparse point；`FILE_ATTRIBUTE_REPARSE_POINT` 与 reparse tag 用于识别。[Reparse points](https://learn.microsoft.com/en-us/windows/win32/fileio/reparse-points)、[Reparse point operations](https://learn.microsoft.com/en-us/windows/win32/fileio/reparse-point-operations)
- `FILE_FLAG_OPEN_REPARSE_POINT` 可打开 reparse entry 本身；对 symlink 路径执行 `DeleteFile` 删除 link 而不是 target。[CreateFile flags](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/ns-fileapi-createfile3_extended_parameters)、[Symbolic-link effects](https://learn.microsoft.com/en-us/windows/win32/fileio/symbolic-link-effects-on-file-systems-functions)
- mounted folder 是与另一 volume 关联的目录；volume 可由 drive letter、volume GUID 或 mounted-folder path 访问。[Naming a volume](https://learn.microsoft.com/en-us/windows/win32/fileio/naming-a-volume)、[Volume mount-point functions](https://learn.microsoft.com/en-us/windows/win32/fileio/volume-mount-point-functions)

**产品建议**：总计按 `(volume identity, file ID)` 去重 hard link，同时保留所有可见名称。任何 directory reparse point 默认都是边界，而不只是已知 symlink；v1 不提供 follow-links opt-in，即使 tag 已理解也只报告该边界。未来版本若研究跟随能力，仍须另行设计 cycle/UNC/volume/depth 限制且不得改变 v1 合同。执行前以 no-follow 方式核验 entry 的 identity/tag；绝不因 mount-point 目录处于选中树中而递归删除 target volume。

### 5. 权限/枚举错误与云占位

**已证事实**

- `CreateFile` 在现有 handle 的 share mode 与请求冲突时返回 `ERROR_SHARING_VIOLATION`；扫描还会遇到 `ERROR_ACCESS_DENIED`、消失路径与 I/O 错误。[CreateFileW](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew)
- `FILE_ATTRIBUTE_OFFLINE`、`RECALL_ON_OPEN`、`RECALL_ON_DATA_ACCESS` 表明访问可能触发远端取回。[File attribute constants](https://learn.microsoft.com/en-us/windows/win32/fileio/file-attribute-constants)、[Cloud Files API](https://learn.microsoft.com/en-us/windows/win32/cfapi/build-a-cloud-file-sync-engine)
- long path 仍依赖合适 Win32 API 与应用 `longPathAware` opt-in。[Maximum path limitation](https://learn.microsoft.com/en-us/windows/win32/fileio/maximum-file-path-limitation)

**产品建议**：metadata-only 且避免内容读取/云 hydration；错误至少区分 permission、sharing violation、recall avoided、vanished、unsupported reparse、timeout/transient I/O。用 Unicode/long-path-aware API；远端与 offline 项有限重试。

### 6. 进程占用识别及局限

**已证事实**

- 若已有 handle 没给 `FILE_SHARE_DELETE` 或文件被 memory-map，删除会失败；若删除被接受，也要到最后相关 handle 关闭后才完成。[DeleteFile](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-deletefile)
- Restart Manager 可注册具体 filename，并由 `RmGetList` 返回正在使用它的应用/服务；目录不是可注册资源，文档对目录列出 `ERROR_ACCESS_DENIED`。[RmRegisterResources](https://learn.microsoft.com/en-gb/windows/win32/api/restartmanager/nf-restartmanager-rmregisterresources)、[RmGetList](https://learn.microsoft.com/en-us/windows/win32/api/restartmanager/nf-restartmanager-rmgetlist)
- Sysinternals Handle 可做系统级 open-handle 枚举，但 Microsoft 明确说需要管理员权限。[Handle](https://learn.microsoft.com/en-us/sysinternals/downloads/handle)

**推导**：Restart Manager 是文件级、时间点式、会竞态的 best-effort attribution，不是完整 lock oracle。

**产品建议**：正常 Shell 操作失败为 sharing violation 后，再对具体失败文件按需查询 Restart Manager；结果显示为“检查时观测到”。不自动终止进程或关闭 handle；目录失败时定位具体 descendant，不把目录直接交给 Restart Manager。

### 7. Windows 保守降级

| 条件 | 行为 |
|---|---|
| DACL/UAC/属性阻止访问 | 标记 incomplete；不提权、不接管权限 |
| 未知 reparse tag / UNC / mounted folder | 默认不进入，列为单独边界 |
| hard link 数大于扫描范围内名称数 | 已知有 surviving link 时文件数据 reclaim 为 0；无法证明链接覆盖时为 unknown；目录项 metadata 分开 |
| sparse/compressed/ADS/ReFS clone | 分列 logical/allocated；不承诺释放值 |
| offline/recall 属性 | 不打开内容；标记 local allocation/reclaim 不确定 |
| Recycle Bin 不可用 | 保持源文件；不得自动永久删除 |
| holder 无法识别 | 报告 `in_use_holder_unknown`；建议关闭应用后重试 |

## macOS

### 1. 普通用户、TCC 与 sandbox 边界

**已证事实**

- POSIX permissions/ACL 仍适用；macOS privacy controls 还保护 Desktop、Documents、Downloads、iCloud Drive、network volumes 等。Full Disk Access 必须由使用者在 System Settings 授予，应用不能自行授予。[Apple Platform Security: file access](https://support.apple.com/en-gb/guide/security-pdf/secddd1d86a6/web)、[Privacy & Security settings](https://support.apple.com/guide/mac-help/mchl211c911f/mac)
- sandboxed app 通常只完全访问自己的 container；容器外访问常来自用户显式选择，并可用 security-scoped bookmark 持久化。只需读时存在 read-only bookmark 选项。[Accessing files from the macOS App Sandbox](https://developer.apple.com/documentation/security/accessing-files-from-the-macos-app-sandbox)
- 即使 sandbox 允许，POSIX mode/ACL 仍可拒绝。[Accessing files from the macOS App Sandbox](https://developer.apple.com/documentation/security/accessing-files-from-the-macos-app-sandbox)、[Change permissions](https://support.apple.com/guide/mac-help/change-permissions-for-files-folders-or-disks-mchlp1203/mac)
- Apple 不建议先用 `isReadableFile`/存在性检查预测之后的操作；状态会在 check/use 之间变化，应尝试实际操作并处理错误。[isReadableFile](https://developer.apple.com/documentation/foundation/filemanager/isreadablefile(atpath:))、[fileExists](https://developer.apple.com/documentation/foundation/filemanager/fileexists(atpath:))
- Foundation 深度 enumerator 支持 error handler 来决定遇错后是否继续。[FileManager enumerator](https://developer.apple.com/documentation/foundation/filemanager/enumerator(at:includingpropertiesforkeys:options:errorhandler:))

**产品建议**：以当前用户启动；若 sandboxed，让用户选择 root 并保存 read-only security-scoped bookmark。仅在确需更广覆盖时解释 FDA，不能声称它能保证完整扫描。逐项错误继续 siblings，显示 unscanned/unknown。

**推导**：FDA 是隐私控制中的额外授权，不等同于 root，也不能据此推断 ownership、mode、ACL、只读 volume 或其他保护全部放行。

### 2. Trash 机制与接口

**已证事实**

- Foundation 提供 `FileManager.trashItem(at:resultingItemURL:)`；Apple 用户文档说明放入 Trash 的项目要到清空 Trash 才删除。[trashItem](https://developer.apple.com/documentation/foundation/filemanager/trashitem(at:resultingitemurl:))、[Delete files and folders on Mac](https://support.apple.com/guide/mac-help/delete-files-and-folders-on-mac-mchlp1093/mac)
- `FileManager.removeItem(at:)` 删除指定 URL 的文件或目录；Apple 的 removal delegate 文档进一步明确，这类 removed item 立即删除且不进入 Trash。[removeItem(at:)](https://developer.apple.com/documentation/foundation/filemanager/removeitem(at:))、[removal delegate](https://developer.apple.com/documentation/foundation/filemanagerdelegate/filemanager(_:shouldremoveitematpath:))

**证据缺口**：Apple 没有把每种 local/removable/network/provider volume 内部 `.Trash`/`.Trashes/<uid>` 布局作为稳定公共合同。

**产品建议**：逐个 top-level item 调用 `trashItem`，保存返回的 resulting URL（若提供）和结构化错误；不拼私有目录，不在失败时降级为 `removeItem`，不自动 empty Trash。跨多个卷的一批操作不宣称具备事务性。

### 3. 逻辑大小、allocated 与 APFS 稀疏/压缩/clone

**已证事实**

- Darwin/POSIX `stat` 区分 `st_size`（logical length）、`st_blocks`（allocated blocks）、`st_nlink`、`st_dev` 与 `st_ino`。[Darwin stat(2)](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man2/stat.2.html)、[POSIX stat](https://pubs.opengroup.org/onlinepubs/9799919799/functions/stat.html)
- Foundation 分别提供 `fileAllocatedSize`、含 metadata 的 `totalFileAllocatedSize`、`totalFileSize`、`fileResourceIdentifier` 与 `volumeIdentifier`。[fileAllocatedSizeKey](https://developer.apple.com/documentation/foundation/urlresourcekey/fileallocatedsizekey)、[totalFileAllocatedSize](https://developer.apple.com/documentation/foundation/urlresourcevalues/totalfileallocatedsize)、[totalFileSize](https://developer.apple.com/documentation/foundation/urlresourcevalues/totalfilesize)、[fileResourceIdentifier](https://developer.apple.com/documentation/foundation/urlresourcevalues/fileresourceidentifier)、[volumeIdentifier](https://developer.apple.com/documentation/foundation/urlresourcekey/volumeidentifierkey)
- APFS sparse 文件只为写入区域分配 block；clone 初始共享未变化 block，之后 copy-on-write；`FileManager.copyItem` 在支持处可自动创建 clone。[About Apple File System](https://developer.apple.com/documentation/foundation/about-apple-file-system)、[Reducing app disk usage](https://developer.apple.com/documentation/xcode/reducing-your-app-s-disk-usage)、[APFS cloning sample](https://developer.apple.com/library/archive/samplecode/APFSCloning/Listings/README_md.html)
- Foundation 可查询 volume 是否支持以 `decmpfs` 透明解压压缩文件。多个 APFS volume 共享一个 container 的空闲池。[volumeSupportsCompressionKey](https://developer.apple.com/documentation/foundation/urlresourcekey/volumesupportscompressionkey)、[APFS volumes](https://support.apple.com/guide/disk-utility/add-delete-or-erase-apfs-volumes-dskua9e6a110/mac)
- Time Machine local snapshots 在同一磁盘上，并可在需要空间时自动删除；Apple 将其占用计入 available space。[About local snapshots](https://support.apple.com/en-us/102154)

**推导**：`decmpfs` 压缩文件的 logical content 与 allocated storage 可能不同。两个 clone 可以有不同 file identity 却共享 extent；普通 `st_blocks`/Foundation keys 无法给出删除任意 clone 集合的独占 reclaim。path tree、Finder/System Settings、`du`、`df`、APFS container 与删除后的 free-space 可能都不相等。

**产品建议**：分列 logical、filesystem-reported allocated、unique hard-link view、estimated reclaimable/confidence、unscanned 和 cloud-only。APFS clone/snapshot 情形默认把 reclaimable 设为 unknown，而不是相加。

### 4. 符号链接、硬链接、mount/volume

**已证事实**

- `lstat()` 描述 symlink 自身，`stat()` 跟随 target；`st_nlink` 是 hard-link count，`(st_dev, st_ino)` 在传统模型中标识对象。[Darwin stat(2)](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man2/stat.2.html)
- POSIX `unlink` 移除一个名称；只有 link count 到零且没有 open descriptor 或 memory mapping 保留对象时数据才最终释放。[POSIX unlink](https://pubs.opengroup.org/onlinepubs/9799919799/functions/unlinkat.html)、[POSIX close](https://pubs.opengroup.org/onlinepubs/9799919799/functions/close.html)、[Darwin mmap(2)](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man2/mmap.2.html)
- Darwin FTS 的 `FTS_PHYSICAL` 避免逻辑跟随 symlink，`FTS_XDEV` 阻止进入 device number 不同的目录。[Darwin fts_open(3)](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man3/fts_open.3.html)
- `statfs()` 提供包含某路径的 mounted filesystem 信息；Foundation 也暴露 containing volume/identifier。[Darwin statfs(2)](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man2/statfs.2.html)
- Catalina 以后系统内容位于 read-only system volume；Big Sur 以后还使用 signed system volume。[Read-only system volume](https://support.apple.com/101400)、[Protecting data at multiple layers](https://developer.apple.com/news/?id=3xpv8r2m)

**产品建议**：no-follow 遍历；hard link 按 `(volume/device identity, file identity/inode)` 去重，同时显示多路径。默认 same-volume；network、automount、File Provider、read-only/signed system volume 作为边界。删除前再次 no-follow resolve 并比对 identity/type/volume。

### 5. 权限错误与 cloud/File Provider

**已证事实**

- POSIX `opendir/readdir` 可因 path component 缺 search permission 或目录缺 read permission而得到 `EACCES`。[opendir](https://pubs.opengroup.org/onlinepubs/9799919799/functions/opendir.html)、[readdir](https://pubs.opengroup.org/onlinepubs/9799919799/functions/readdir.html)
- File Provider 可表示内容尚未本地存在的 dataless item；读取内容可能触发下载。[WWDC21 FileProvider](https://developer.apple.com/videos/play/wwdc2021/10182/)、[File Provider metrics](https://developer.apple.com/documentation/fileprovider/exporting-file-provider-metrics-data)

**推导**：即使产品意图“只读”，打开内容做 hash/classification 仍可能产生网络流量、hydration 与本地空间增长。

**产品建议**：默认只取 metadata；不为算大小或分类打开内容。把 dataless/provider item 标为 local-size/reclaim unknown；错误区分 TCC、POSIX/ACL、provider、read-only volume、vanished、timeout。

### 6. 进程占用识别及局限

**已证事实**

- 上游 `lsof` 支持 Darwin/macOS 并显示进程与 file descriptor；可见性受调用者权限和平台安全策略限制。[lsof man page](https://github.com/lsof-org/lsof/blob/master/docs/manpage.md)、[lsof FAQ](https://github.com/lsof-org/lsof/blob/master/docs/faq.md)
- POSIX/Darwin 允许最后一个 pathname 被 unlink 后，对象因 open descriptor 或 file-backed mapping 继续存在并占空间。[POSIX unlink](https://pubs.opengroup.org/onlinepubs/9799919799/functions/unlinkat.html)、[Darwin mmap(2)](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man2/mmap.2.html)
- Apple file coordination 是 document/iCloud 等参与者的协作机制，不是对任意文件“无人使用”的系统证明。[File coordinators and presenters](https://developer.apple.com/library/archive/documentation/FileManagement/Conceptual/FileSystemProgrammingGuide/FileCoordinators/FileCoordinators.html)

**推导**：`lsof` 是 point-in-time、权限受限、可能受 NFS 卡顿影响的观测；路径可能已经 rename/unlink，进程也可在检查后立刻打开。没结果不等于 safe；有结果也不一定意味着 Trash rename 必然失败。

**产品建议**：只对最终候选按需查询；显示 PID、进程名、UID、descriptor/type 与时间戳，标签为 observed-open。若不完整则明确标注；不自动 kill。process attribution 不能替代执行前 identity revalidation。动作后如需记录用户可见容量，可读取 `volumeAvailableCapacityForImportantUsageKey`；这是系统对“重要资源可用容量”的只读估计，受 purgeable content 与 APFS container 共享影响，不应解释为纯粹未分配 block。[Apple capacity key](https://developer.apple.com/documentation/foundation/urlresourcekey/volumeavailablecapacityforimportantusagekey)

### 7. macOS 保守降级

| 条件 | 行为 |
|---|---|
| TCC/POSIX/ACL denial | 标记 incomplete；可解释用户选择目录或可选 FDA，但不自动请求 |
| symlink | 只计 link 自身，不跟随 |
| hard link > 1 | 已知仍有其他链接时，文件数据 reclaim 记 0；链接覆盖不完整时记 unknown；目录项 metadata 分开 |
| APFS clone/snapshot/shared container | allocated 仅作 attribution，reclaimable unknown |
| File Provider placeholder | 不读内容/不 materialize；本地占用标不确定 |
| 不同 volume、network、automount | 停止并作为单独 root，需要 opt-in |
| signed/read-only system volume | 可读则分析，不提供 cleanup |
| Trash API 失败或 identity 改变 | 跳过并报告，不永久删除 |

## Linux

### 1. 普通用户权限边界

**已证事实**

- 路径每个目录 component 都需要 search/execute；目录 read 控制枚举。用户可能知道名称却不能 list，或能 list 名称却因缺 search 无法 `stat`。[path_resolution(7)](https://man7.org/linux/man-pages/man7/path_resolution.7.html)、[stat(2)](https://man7.org/linux/man-pages/man2/stat.2.html)
- 普通检查使用 filesystem UID/GID、supplementary groups 与 mode bits；`CAP_DAC_READ_SEARCH` 可绕过部分 read/search，但普通进程没有此能力。[capabilities(7)](https://man7.org/linux/man-pages/man7/capabilities.7.html)
- unlink 需要 containing directory 的 write + search；sticky directory 又要求合适 owner/`CAP_FOWNER`。immutable/append-only、read-only filesystem 等仍可阻止。[unlink(2)](https://man7.org/linux/man-pages/man2/unlink.2.html)
- POSIX ACL 可在 mode bits 之外表达更细访问权限；SELinux 等 LSM 可施加强制策略，Landlock 则由进程叠加限制自身。远端文件系统还可能受服务端策略影响，具体语义不是通用 Linux 保证。[acl(5)](https://man7.org/linux/man-pages/man5/acl.5.html)、[Linux Security Modules](https://docs.kernel.org/admin-guide/LSM/index.html)、[Landlock](https://docs.kernel.org/security/landlock.html)

**推导**：普通用户结果只是当前进程在当前 mount/user namespace 可见的快照。`access()` 等预检无法证明之后的 cleanup 会成功。

**产品建议**：默认 unprivileged；每个 enumerate/stat/readlink/filesystem query 错误保存 `errno`；显示 skipped subtree 与已知 lower-bound totals。action time 尽可能以已打开 parent directory FD 做相对操作并重验 identity；提权扫描必须是明确的独立模式。

### 2. freedesktop Trash 与接口

**已证事实**

- freedesktop Trash 规范定义存储布局，不是统一 syscall。home trash 为 `$XDG_DATA_HOME/Trash`；其他 mounted filesystem 可用 `$topdir/.Trash/$uid` 或 `$topdir/.Trash-$uid`。共享 `.Trash` 必须 sticky 且不能是 symlink。[Trash specification](https://specifications.freedesktop.org/trash/latest/)
- 每个 trash 包含 `files/` 与 `info/`；对应 `.trashinfo` 记录 percent-encoded 原 `Path` 与 `DeletionDate`。规范要求先创建 info，并用如 `O_EXCL` 的方式原子分配名称，避免并发碰撞。[Trash specification 1.0](https://specifications.freedesktop.org/trash/1.0/)
- 规范允许其他文件系统 copy 到 home trash 作为 fallback，但明确指出成本/延迟；实现可拒绝 network/removable resource。`rename()` 不能跨 mount，会返回 `EXDEV`。[rename(2)](https://man7.org/linux/man-pages/man2/rename.2.html)
- GLib `g_file_trash()` 是常用 desktop abstraction，可返回 `G_IO_ERROR_NOT_SUPPORTED`；system mounts 默认禁用，mount option 可改变支持。[GIO File.trash](https://docs.gtk.org/gio/method.File.trash.html)

**推导**：跨文件系统 copy-to-trash 可能暂时同时占 source 和 copy 的空间，也可能半途失败。正确手写 Trash 涉及 collision、metadata ordering、mount detection、encoding、permissions 与 crash recovery。

**产品建议**：优先 GIO/native desktop trash。`NOT_SUPPORTED`、权限不足、空间不足、取消或远端错误时保持 source；不静默 `unlink`。cross-filesystem copy-to-trash 作为明确的慢操作，做容量预检、进度、取消和残留恢复。不要接受未经检查的 `.Trash` symlink/非 sticky 共享目录。

### 3. 逻辑大小、allocated 与 sparse/compression/reflink

**已证事实**

- `st_size` 是 logical bytes；`st_blocks` 是已分配的 512-byte units，因此通用 allocated estimate 是 `st_blocks * 512`。[stat type](https://man7.org/linux/man-pages/man3/stat.3type.html)、[GNU du](https://www.gnu.org/software/coreutils/manual/html_node/du-invocation.html)
- sparse holes 通常不贡献 allocated blocks；透明 compression 可令 allocated 小于 logical。支持时 `statx` 可给 `STATX_ATTR_COMPRESSED`。[statx(2)](https://man7.org/linux/man-pages/man2/statx.2.html)、[Btrfs compression](https://btrfs.readthedocs.io/en/stable/ch-compression.html)
- reflink 通过 copy-on-write 共享 extent；删除一个 pathname/file 不释放仍被其他引用的 extent。[FICLONE](https://man7.org/linux/man-pages/man2/ioctl_ficlone.2.html)、[Btrfs reflink](https://btrfs.readthedocs.io/en/latest/Reflink.html)
- FIEMAP 可报告 extent 及 `SHARED`、`UNKNOWN`、`DELALLOC`、`ENCODED` 等 flag；extent 之间的缺口可表示 hole。各文件系统支持不同，`SHARED` 本身不能量化独占 reclaim。[Kernel FIEMAP](https://docs.kernel.org/filesystems/fiemap.html)
- `statx` 允许字段不支持，且并发变化时不同字段可能来自不同瞬间。`statvfs().f_bavail` 是普通用户可用空间，比 total free 更符合用户体验。[statx(2)](https://man7.org/linux/man-pages/man2/statx.2.html)、[statvfs(3)](https://man7.org/linux/man-pages/man3/statvfs.3.html)
- Btrfs qgroup 有 referenced/exclusive 等文件系统特定口径，但不能当成通用 per-path 规则。[Btrfs qgroups](https://btrfs.readthedocs.io/en/latest/btrfs-quota.html)

**推导**：`st_blocks` 之和在普通 sparse case 很有用，但 compression、dedup、reflink、snapshot、thin provisioning、remote/overlay、metadata、delayed allocation 与 quota 都让它不等于删除后释放量。

**产品建议**：分列 logical、按 hard-link identity 去重的 allocated estimate、置信度修饰的 reclaimable。FIEMAP unavailable/UNKNOWN/DELALLOC/ENCODED/shared 必须成为 uncertainty，而非 0。必要时动作前后比较 `f_bavail`，并说明 delayed accounting 可能使观测滞后。

### 4. symlink、hard link、mount 与 namespace

**已证事实**

- `lstat()`/`fstatat(..., AT_SYMLINK_NOFOLLOW)` 描述 symlink；`stat()` 跟随。`nftw(..., FTW_PHYS)` 不跟随，`FTW_MOUNT` 限制同 filesystem。[symlink(7)](https://man7.org/linux/man-pages/man7/symlink.7.html)、[nftw(3)](https://man7.org/linux/man-pages/man3/nftw.3.html)
- hard links 是同 inode 的不同名称；传统身份为 `(st_dev, st_ino)`，`st_nlink` 给链接数；unlink 一个名称不会释放仍有链接的文件。[link(2)](https://man7.org/linux/man-pages/man2/link.2.html)、[unlink(2)](https://man7.org/linux/man-pages/man2/unlink.2.html)
- `/proc/self/mountinfo` 描述调用进程 mount namespace，含 mount/parent ID、major:minor、filesystem root、mount point、type/source/options。[proc_pid_mountinfo(5)](https://man7.org/linux/man-pages/man5/proc_pid_mountinfo.5.html)
- `statx(STATX_MNT_ID[_UNIQUE])` 可标识 mount；`st_dev` 单独不能区分 bind mounts。`openat2(RESOLVE_NO_XDEV)` 阻止包括 bind mount 在内的 mount crossing，`NO_SYMLINKS/BENEATH/IN_ROOT` 可加强路径 containment。[statx(2)](https://man7.org/linux/man-pages/man2/statx.2.html)、[openat2(2)](https://man7.org/linux/man-pages/man2/openat2.2.html)
- 不同 mount namespace 可见不同树；OverlayFS 的 `st_dev/st_ino` 稳定性有条件，写入可触发 lower object copy-up。[OverlayFS](https://docs.kernel.org/filesystems/overlayfs.html)

**产品建议**：扫描开始保存 `/proc/self/mountinfo` 与时间，以 mount ID 而非路径前缀/仅 `st_dev` 定边界。nested、bind、network、FUSE、automount、pseudo、container mounts 默认只列不入；需逐个 opt-in、timeout/cancel。

### 5. 权限与枚举错误

**已证事实**：路径解析、`stat` 和目录读取都可能独立失败；对象也可在枚举与读取 metadata 之间消失。[path_resolution(7)](https://man7.org/linux/man-pages/man7/path_resolution.7.html)、[stat(2)](https://man7.org/linux/man-pages/man2/stat.2.html)

**推导**：mount query、FUSE/provider 或远端服务端策略还会产生各自错误；这些结果不能仅由 mode bits 预测。

**产品建议**：至少分类 `EACCES/EPERM`、`ENOENT` race、`ELOOP`、`EXDEV`、read-only、I/O、timeout、unsupported 与 interrupted。未知 subtree 不参与“完整百分比”；总计明确为已观测 lower bound。重试必须有界，network/FUSE 不可阻塞整个扫描。

### 6. 进程占用识别及局限

**已证事实**

- `/proc/PID/fd/` 暴露进程 open FD 的 symlink；`maps` 暴露 file-backed mappings；`cwd`、`root`、`exe` 也是相关引用。[proc_pid_fd(5)](https://man7.org/linux/man-pages/man5/proc_pid_fd.5.html)、[proc_pid_maps(5)](https://man7.org/linux/man-pages/man5/proc_pid_maps.5.html)、[procfs](https://docs.kernel.org/filesystems/proc.html)
- 读取其他进程信息受 ptrace checks、procfs `hidepid`、capability、LSM 与 namespace 视图限制；进程/FD 也随时变化。[proc_pid_fd(5)](https://man7.org/linux/man-pages/man5/proc_pid_fd.5.html)、[proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html)、[kernel procfs docs](https://docs.kernel.org/filesystems/proc.html)
- 最后一个 hard link 被 unlink 后，open FD 或 file-backed mapping 仍可保留对象与空间。[unlink(2)](https://man7.org/linux/man-pages/man2/unlink.2.html)、[mmap(2)](https://man7.org/linux/man-pages/man2/mmap.2.html)
- advisory lock 只覆盖合作进程；没有 lock 不等于 unused。[flock(2)](https://man7.org/linux/man-pages/man2/flock.2.html) `lsof` 只是方便的时间点视图。[lsof(8)](https://man7.org/linux/man-pages/man8/lsof.8.html)

**推导**：普通用户没有一个原子、完整、系统级的 “path not in use” 查询。Unix 允许 unlink open regular file，因此 observed-open 与“必然不能删”也不等价。

**产品建议**：按 device/inode/open identity 匹配 FD、mapping、cwd/root/exe，而不是只比 path string；报告可见 PID 数、不可见 PID 数、vanished process 与 procfs restriction。结果永远保留 `unknown` 状态；数据库、VM/container image、package manager state、active log、executable、mount point 和 process cwd 默认跳过。

### 7. Linux 保守降级

| 条件 | 行为 |
|---|---|
| mode/ACL/LSM/namespace denial | 记录 errno 与 incomplete；不自动 capability/root 重扫 |
| Trash `NOT_SUPPORTED` / cross-filesystem | 保持 source 并结束本次动作；只说明 copy 成本。任何后续 Permanent 意图须重新 live scan、创建新 R4 计划并独立授权 |
| symlink | 只看 link，不跟随 |
| mount/bind/network/FUSE/automount | 默认边界；显式 opt-in + timeout |
| hard link 范围不完整 | 已知有 surviving link 时文件数据 reclaim 为 0；无法证明覆盖全部链接时为 unknown；目录项 metadata 分开 |
| reflink/compression/FIEMAP 不完整 | allocated 是 estimate；shared extent 不相加 |
| `/proc` 可见性不足 | 标记 in-use unknown，不推断无人使用 |
| identity/mount 在执行前改变 | 跳过，要求重新扫描 |

## 跨平台统一数据模型与执行门槛

### 建议的扫描记录

每个 entry 至少保存：

```text
display_path, parent_identity, basename, object_type
platform_file_identity, volume_or_mount_identity
logical_bytes, allocated_bytes?, reclaimable_estimate?, confidence
hard_link_count?, reparse_or_symlink_kind?, cloud_or_offline_state?
scan_timestamp, scan_root, scanner_version, errors[]
```

目录聚合额外保存 `complete: true|false`、skipped count、跨边界列表和 size 口径。`allocated_bytes = null` 与 `0` 必须不同。

### 执行前 gate

1. 动作计划必须来自本机当前扫描，不能来自 imported/remote/stale report。
2. 重新以 no-follow 语义解析父目录与 basename。
3. 核对 object type、file identity、volume/mount identity、link/reparse 状态与选中 root containment。
4. 核对 Cleaner 语义仍成立。只可重跑计划中已绑定、版本/可执行文件/argv/输出 schema 固定并已通过 sandbox、禁网和写监控验证的 Z1 descriptor；普通名称为 dry-run/query 的命令不自动获得只读资格，Z2 不能用于计划资格，M 类命令在 v1 不执行。
5. best-effort 查询 observed-open，但不把 negative result 当许可。
6. 使用平台 Trash API；若不支持则保持 source 并结束本次动作。Permanent 只能由后续独立请求从新的 live scan、新计划、新 R4 授权和新批次开始，不能在本流程中确认或降级。
7. 记录逐项结果、平台 error、实际目标/Trash URL、是否 aborted；批量不宣称原子。
8. 以平台 caller-visible free-space API 记录事后 delta，和预估分列：Windows 用 `GetDiskFreeSpaceExW` 的 caller-available 值，Linux 用 `statvfs().f_bavail`，macOS 可用 Foundation 的 `volumeAvailableCapacityForImportantUsageKey`，但后者包含系统对 purgeable space 的判断，三者不应直接横向等同。

## 证据缺口

截至研究日，没有跨三个平台的稳定公共接口能够给出以下保证：

- 任意文件/目录的独占物理 extent 数量；
- 删除任意 hard-link、clone/reflink、snapshot 关联集合后必定释放的精确字节；
- 所有 local/removable/network/cloud/provider volume 上统一且始终可恢复的 Trash 行为；
- 普通用户完整看到所有持有 FD、mapping、kernel/provider reference 的进程；
- 一个无竞态的“文件现在且接下来都未被使用/可安全删除”判断；
- metadata/content 访问在每个 cloud provider 上都不会触发 hydration；
- 一个与 Explorer/Finder、`du`、`df`、quota、purgeable 与删除后 free-space 同时一致的单一大小。

因此对外文案应使用：`logical size`、`filesystem-reported allocated size`、`potentially reclaimable`、`observed open at <time>`、`scan incomplete`、`unknown`。除非有更强的领域规则与执行后测量，不应写 `exact disk usage`、`will free`、`unused`、`safe to delete` 或 `guaranteed unrecoverable`。

## 最终保守策略

```text
missing evidence -> lower confidence -> report/skip
missing evidence != zero bytes != unused != permission to delete
```

平台 adapter 可以提升能力，但不能降低共同安全下限：普通用户、metadata-only、no-follow、same-mount、错误可见、动作可审阅、执行前重验、Trash-first、永久删除不降级、占用检查仅作提示、结果按实际发生记录。
