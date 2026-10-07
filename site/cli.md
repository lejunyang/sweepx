---
title: CLI 与安全清理预览
---

# CLI 与安全清理预览

当前 `sweepx` 是唯一的可执行入口。它提供 `scan`、`junk`、`explain`、`status`、`cancel`、`cache`、`cleaner`、`trash`、Linux `delete` 和 `capabilities`；`scan --tui` 在根目录准入后立即进入交互浏览，并在后台渐进扫描。

> [!CAUTION]
> `trash` 仍是默认的可恢复动作，失败不会 fallback。Linux `delete` 是独立的有界文件/目录 R4 Permanent preview：要求解析后的绝对路径、前台终端完整摘要挑战、封闭 manifest、逐项 durable intent/outcome 与提交前身份重验。link、超限/跨平台 Permanent，以及通用 `plan`、`approve`、`execute` 仍未实现。

## 构建与查看能力

在仓库根目录运行：

```bash
cargo build -p sweepx-cli
cargo run -p sweepx-cli -- --locale zh-CN capabilities
```

全局参数：

| 参数 | 含义 |
|---|---|
| `--format human|json|ndjson` | 选择展示或机器输出；默认 `human`；当前 scan 拒绝 `ndjson` |
| `--locale zh-CN|en-US` | 覆盖自动检测的语言 |
| `--unit auto|b|kib|mib|gib|tib` | human/TUI 大小单位；`kb/mb/gb/tb` 可作别名 |
| `--sort size|path` | human/TUI 排序；默认大小降序 |
| `--state-dir ABSOLUTE_DIR` | Linux 上指定 SQLite journal 目录，macOS 上指定 legacy snapshot 目录；Windows 使用 `%LOCALAPPDATA%\sweepx\state` 作为默认目录；状态目录必须仅当前用户可访问，否则失败关闭 |
| `--elevate` | 仅 Windows 有实际效果，默认关闭。若当前进程未提权，则在做任何其他事情之前请求一次 UAC 同意并以提权身份重新启动自身；父进程随后原样返回子进程的 exit code，**并把子进程的标准输出原样转发到自己的标准输出**，因此管道与重定向的行为与不提权时一致。提权进程无法继承父进程的控制台（`runas` 会新建一个、随子进程退出而关闭），所以子进程会先把输出写入父进程在自己私有临时目录中生成的文件，再由父进程回读转发；该文件路径只由父进程生成，任何从外部传入的同名参数都会被剥离。已提权时不会重复启动；用户取消或平台不支持时继续以当前权限运行，不改变扫描结果。该参数不会转发给被重新启动的子进程，因此不可能二次提权 |
| `scan --no-state` | 跳过 Linux journal 或 macOS legacy snapshot 写入；适合不需要后续 status/operation state 或 state filesystem 不支持 journal 的只读扫描；不能与 `--state-dir` 同时使用 |

语言解析会依次考虑显式 override、locale 环境与系统 locale，无法识别时回退到 `en-US`。机器字段和值不翻译。

普通 `scan` 的 human 摘要直接从扫描事实筛选前 40 行；JSON 为紧凑单文档，逐行写出全部已保留事实，字段、原生路径编码和证据状态保持稳定。这仍是扫描结束后的导出，不是实时事件流，也不限制总导出字节。stdout 写入或 flush 失败返回 8；中断的 JSON 不能作为完整结果使用，已完成扫描的持久状态不因此回滚。

普通扫描详情共享 128 MiB 保留估算，包括原生祖先身份链、容器容量和额外开销；这不是全进程 RSS 上限。超过预算会标记 `resource_limit` 并截断详情，已经累计的递归统计和独立大文件观察仍保留。目录句柄 frontier 默认 128，为共享原生 I/O 额度留出余量；宽目录通过延后同级目录并优先深入已打开子树完成遍历。

### P4a.2 资格记录不是新命令

协议现在能用 typed/validated 记录表达一个精确 capability/平台 tuple 及其 evidence。mutation 不使用宽泛的 delete 标记，而是分成 `trash.local.file`、`trash.local.directory`、`permanent.local.file`、`permanent.local.directory` 和 `permanent.local.link`。当前主机的两个 Trash cell 与 Linux file/directory Permanent 为 `degraded` preview；link 和其他平台 Permanent 仍为 `disabled`。

这些记录仍是失败关闭的 qualification registry substrate；`degraded` preview 不等于 `qualified`。`fixture_conformance_only`、`fake`、`stale`、`incomplete`、`placeholder` 或 `mismatched` evidence 永远不能使 mutation 合格。未来只有 current `real_os_qualification` evidence 完整匹配精确 tuple 时，对应单元才可能被标为 `qualified`。当前没有通用 `plan`/approval UI；Permanent adapter 仅覆盖 Linux 有界普通文件/真实目录树。


## 独立大文件榜单

```bash
sweepx scan --no-state --large-files --min-file-bytes 104857600 --top-files 100 /absolute/root
sweepx --format json scan --no-state --large-files --min-file-bytes 0 --top-files 20 /absolute/root
```

`--large-files` 在现有元数据遍历中独立收集普通文件，默认包含逻辑大小至少 100 MiB 的文件，保留整个调用所有根中最大的 100 个路径。`--min-file-bytes` 接收包含等于的非负整数逻辑字节阈值，`--top-files` 范围为 1..=10000，两者都要求 `--large-files`；加上 `--tui` 可动态查看榜单。榜单始终按逻辑大小降序，等大文件按本次原生观察顺序取舍，不保证不同卷或扫描之间的 tie 顺序。

human 显示独立的逻辑大小/分配大小表，最多 40 行；JSON 新增 `data.largeFiles`，包含 `options`、`files`、`observedFiles`、`qualifyingFiles`、`unknownLogicalFiles`、`topKLimited`、`complete` 和 `incompleteReasons`。机器字段、状态和十进制字节字符串不随 locale 改变。没有启用时，普通 scan 输出不增加此字段。文件观察在普通列表保留之前到达收集器，后半段的大文件仍可替换 top-K 中较小的行；普通列表截断可能使 scan 总状态为 partial，但独立榜单可保持完整覆盖。

收集器最多保留 64 MiB 的 owned-data 准入估算，包括 native lineage；这不是精确 RSS。正常 top-K 截断不表示遍历失败；未知逻辑大小、保留预算不足、取消、权限/挂载或真实遍历截断则留下明确的不完整原因，不能把空列表说成没有大文件。只做 no-follow 元数据观察，不读取内容。硬链接路径仍分别展示，分配证据未知时原样保留（macOS 当前为 unknown），也不求和冒充可回收空间。大文件不是垃圾候选；普通 human/JSON 输出仅报告，`--tui` 中的回收来自用户明确的文件选择。

## 显式重复内容分析

```bash
sweepx scan --no-state --duplicates --min-duplicate-bytes 1024 /absolute/root
sweepx --format json scan --no-state --duplicates --duplicate-read-bytes 1073741824 /absolute/root
```

`--duplicates` 在普通元数据遍历之后显式读取内容，默认包含逻辑大小至少 1 KiB 的普通文件。`--min-duplicate-bytes` 是包含等于的非负整数阈值；设为 0 才比较空文件。先按大小分组，排除同一原生对象的硬链接别名及重叠根观察，再比较最多各 4 KiB 的头尾采样。只有完整 SHA-256 相同、最终原生身份/大小/变化指纹复验成功的至少两个不同对象才进入组；采样相同不是重复证明。

`--duplicate-max-files` 默认 20000、范围 1..=100000；`--duplicate-read-bytes` 默认 8 GiB、范围 1..=9223372036854775807；`--duplicate-deadline-ms` 默认 30000、范围 1..=300000。四个参数都要求 `--duplicates`，该模式与 `--large-files` 互斥，可与 `--tui` 同用。整个调用共享最多 64 MiB 的 owned-data 准入估算（不是精确 RSS）、每个文件最大 8 GiB 和最多 max-files × 4 次内容阶段范围请求，包括最终零字节复验。后端还有有界元数据打开/探测，不计为内容阶段请求。单次只读取一个文件、使用固定 64 KiB 缓冲，没有并行内容读取。总读取预算在每次请求前扣除，包括采样和完整 hash；失败/短读不退还，实际交付字节单独计数。期限及取消在原生调用/chunk 边界合作检查，不能中断阻塞的内核调用。

JSON 在 `data.duplicates` 输出 `options`、`groups`、`observedFiles`、`retainedFiles`、`hardLinkAliasesExcluded`、`readBudgetChargedBytes`、`deliveredBytes`、`readOperations`、`complete` 和 `incompleteReasons`。每组包含 `sha256`、`logicalBytes` 和携带原生证据的 `files`；字段、十进制字节字符串及枚举不随 locale 变化。human 显示完整摘要和最多 40 个组内路径。普通扫描未启用分析时不增加此字段；分析不依赖被截断的普通结果列表。覆盖/元数据/保留量/读取预算/期限/取消/变化/provider/读取失败各自保留缺口，空的不完整报告不证明没有重复文件；整体为 partial 时返回 4。

内容读取沿保留的原生根/父目录身份链执行，不从显示路径恢复权限，不跟随链接或跨挂载。macOS 禁止线程内 dataless materialization；Windows 保留 no-recall 并拒绝 offline/recall/reparse 属性；Linux 仅准入 ext4、Btrfs、tmpfs，FUSE、overlay、远程及未知文件系统保持 `provider_or_offline`。未知分配大小不升级为零；结果不选择保留者、不合计可回收空间、不形成垃圾分类或删除授权。当前不持久缓存内容 hash，跨文件结果不是原子快照，实际云服务行为仍需宿主验证。

## 大文件与重复内容的实时界面

```bash
sweepx scan --no-state --tui --large-files --min-file-bytes 104857600 /absolute/root
sweepx scan --no-state --tui --duplicates --min-duplicate-bytes 1024 /absolute/root
```

两种视图都要求 human 输出及终端 stdin/stdout，元数据和内容工作在可取消的后台线程执行。大文件中途榜单只保留最新快照，最终榜单和重复组可靠交付。重复分析按大小分组，完成本组完整哈希和原生复验后再读取后续大小组，因此内容读取期间即可出现已核验组；不复用旧内容 hash，也不自动将文件判成垃圾。

结果交付后，后台直接返回最终状态及缺口，省去结束时重复生成整份扫描/分析 JSON 的开销。取消、状态保存失败和不完整扫描仍阻止回收；文件观察、内容核验及各自的保留预算继续适用。

方向键/j/k 移动，Space 选择，a 全选（最多 256 项），u 清空，c 取消，r/R 全量重新扫描分析范围，q/Esc 退出。重复模式按 p 将焦点文件设为该组保留者或取消保留；每组只能有一个保留者，不自动选择。组内文件相邻展示，保留者有明显标记且不能回收。刷新保留原生稳定键对应的选择，但清除全部保留者选择；取消/不完整刷新保留旧行并标明历史状态。

整个范围完整成功结束后，d/Delete 提交所选文件（未选择时为焦点文件）。每个所选重复组必须有未被选中的保留者。有界后台线程先核验原生变化指纹，再按原共享内容字节/文件数/请求预算重新计算所选副本和保留者；合作期限覆盖预检及内容阶段，最多 512 个不同副本/保留者另做零字节元数据预检。内容/指纹变化、硬链接别名、证据缺失、provider/mount/link 边界或不完整验证均在 Trash 前拒绝整个批次。每次移动前再次复验保留者和所选原生绑定；大文件回收只复验原生文件身份/长度，不读载荷。重要/保护路径拒绝，不在后台等待 stdin，也没有永久删除兜底。

分析视图最多保留 16384 行及 64 MiB 准入估算，与收集器/界面模型预算分别计算。可靠通道一个槽加生产者一份有界载荷，中途榜单和进度各一个可替换槽；内容串行读取。回收与 junk/隔离共用进程级 mutation worker 配额，关闭取消待执行工作，不在界面 join 阻塞内核调用。系统 Trash 成功、真实云 provider 和目标宿主仍需运行验证，已有最终 pathname 检查到 Trash 调用之间的竞态仍在。

普通 `scan` 的稀疏预览压缩保留原 top-K、必留边界及 Others 汇总规则，省去额度不足时反复复制和序列化全部行的开销。保存时直接写紧凑 JSON，沿用原校验摘要；实际 generation 编码最多 65 MiB，超额拒绝更新当前指针并报告缓存资源缺口，扫描事实仍保留。旧格式仍可解析，这一改造不提供删除权限。

普通预览与垃圾历史缓存现在共用原生目录句柄，读取、发布、损坏数据隔离和只读诊断不再逐次从显示路径打开文件。加载前限制 current 指针为 64 KiB、generation 为 65 MiB，超大输入不读取内容、不复制到隔离区，并报告缓存资源缺口；当前扫描结果仍保留。Unix 检查 owner、私有权限、普通文件与单硬链接，Windows 使用相对句柄、显式私有 DACL 和 reparse/offline/recall 拒绝。旧 JSON/checksum 兼容，原生缓存 backend 对权限不合格的对象直接拒绝；core state 入口的旧权限整备仍需独立审计。此改造没有删除权限，也未闭合完整预览 freshness、provider 宿主行为或整体内存预算。

普通预览首次投影另有 192 MiB 的辅助存储预留及一百万行/聚合上限，在复制行和建立索引前检查；超额报告 `cache.preview.resource_limit`，跳过缓存更新，保留当前扫描和上一代缓存。目录缺少聚合时保留未知计数，Windows 边界名称保留原生 UTF-16。该预留不是进程内存上限；写入前现按同一解码准入逐片核算整代 256 MiB 的预留，避免发布下次加载会被预算拒绝的缓存；单片编码最多 1 MiB、单片解码预留最多 8 MiB，超额保留旧代次和当前扫描。该检查复用一个缓冲并及时释放临时行，没有整代副本；状态目录/provider 审计仍需继续。

## 安装

正式 release 会为 Linux x86_64/aarch64、macOS Intel/Apple Silicon 和 Windows x86_64 生成归档和统一 `SHA256SUMS`。安装器会校验 checksum，并要求归档内只有根级 `sweepx` 或 `sweepx.exe`。

```bash
curl --proto '=https' --tlsv1.2 -fsSL \
  https://raw.githubusercontent.com/lejunyang/sweepx/main/install.sh | sh
```

```powershell
irm https://raw.githubusercontent.com/lejunyang/sweepx/main/install.ps1 | iex
```

目前有发布基础设施不代表已经发布稳定版本；安装前应核对 GitHub Release 和 `sweepx capabilities`。

普通 push/PR 会运行 Rust、schema、站点、安装器和 native CLI CI；GitHub Pages 在 `main` 更新时独立部署。只有 HEAD commit message 含字面量 `[publish]` 时，二进制与 crates.io 发布任务才运行。GitHub Release 和 Pages 不需要额外 token；crates.io 需要在受保护的 `crates-io` environment 中配置 `CARGO_REGISTRY_TOKEN`。

## 三平台开发版只读扫描

```bash
cargo run -p sweepx-cli -- scan /absolute/path/to/root
# 不需要后续 operation state 时显式跳过写入
cargo run -p sweepx-cli -- scan --no-state /absolute/path/to/root
```

- 不传根路径时扫描当前平台文件系统根；也可以传入相对路径、`~` 或一个或多个绝对根。
- 默认直接向终端输出有界的 40 行文件表；不要求 JSON 文件。
- 扫描同步运行，metadata-only、no-follow，并把挂载/链接/资源边界与错误写进结果。
- 当前 Linux capability 是 `degraded`，不是发布资格。
- macOS backend 现为 handle-bound degraded scanner，并通过统一的 `scan` / `scan --tui` 路径接入；这不等于发布资格。
- Windows backend 现提供 handle-relative 的 degraded 只读扫描，并通过 `scan` / `scan --tui` 接入；这不等于发布资格。
- Linux 可显式选择 SQLite journal 目录；macOS 可选择 legacy snapshot 目录；Windows 可选择 durable state 目录，该目录必须仅当前用户可访问。
- `scan --format ndjson` 当前在扫描前返回 unsupported；Linux 已有 bounded SQLite journal、单事务完整流/terminal persistence 与 journal-first status，并支持 degraded 的 `sweepx --format ndjson status --operation-id ID --watch [--after SXCUR1]` completed replay：先做一次同 snapshot 全量校验，再对已完成且已持久化的 stream 按每页最多 1024 条事件续读；unknown 但语法有效的 cursor 返回 `stream.reset_required`，malformed cursor/usage 返回 usage error。由于事件仍在 scan 后批量构造，该 replay 不是 live stream，不等待新事件，不创建后台 operation，也不支持 cancel，因此 `scan --format ndjson` 继续 disabled。

只有脚本和系统集成才需要显式机器输出：

```bash
sweepx --format json scan /absolute/path/to/root > scan.json
# 当前返回 unsupported；不会开始扫描
sweepx --format ndjson scan /absolute/path/to/root
```

Dart 与 SvelteKit 候选使用有界原生内容观察，JSON 的 `projectFormat` 包含 `profile`、`status`、`reason`；状态为 `not_checked`、`recognized`、`invalid` 或 `unknown`，跨语言稳定。无内容 profile 的行该字段为 `null`。缓存命中也重新观察，TUI 显示格式阶段和结果。Dart 识别 pub v2 自声明格式及父根引用；SvelteKit 检查 legacy JSON 配置和生成声明签名，读取后再复验两个文件，仍明确非原子。它不解析完整 TypeScript、不求值 JS 配置或证明工具版本、独占归属与无活动。两类 profile 均仅报告，`junk --trash`、TUI 与后台回收拒绝。默认单文件 256 KiB、累计最坏请求 32 MiB、最多 128 项、合作期限 5 秒；SvelteKit 每项预留四次完整读取（最多 1 MiB），因此纯 SvelteKit 批次最多 32 项。`junk --timings` 的 `projectFormats` 单独计时；无新命令选项。

系统扫描中的 npm 安装发现共享 4,096 次文件系统观察、64 个安装、4 MiB 累计准入估算、单路径/环境值 64 KiB，以及工具调用的 10 秒期限和取消。相同缓存路径只观察一次直接子项修改时间；这不是精确最后使用时间，截断不返回部分最大值。JSON 的 `npmDiscovery.complete` 与 `incompleteReason` 跨语言稳定；发现缺口使报告为 partial、退出码 4，并拒绝整根候选缓存复用，保留已确认的安装/候选及未知字段；显式项目根未请求发现时，该对象为 `null`。边界在同步原生调用之间检查，不能强制中断阻塞内核操作。

## 状态快照与取消

Linux、macOS 或 Windows 上从 scan 输出取得 `operationId` 后，可以查询对应的 terminal snapshot：

```bash
cargo run -p sweepx-cli -- \
  --format json \
  --state-dir /absolute/path/to/sweepx-state \
  status --operation-id <OPERATION_ID>

cargo run -p sweepx-cli -- \
  --format ndjson \
  --state-dir /absolute/path/to/sweepx-state \
  status --operation-id <OPERATION_ID> --watch [--after SXCUR1_CURSOR]

cargo run -p sweepx-cli -- \
  --format json \
  --state-dir /absolute/path/to/sweepx-state \
  cancel --operation-id <OPERATION_ID>
```

`status` 在 Linux 上 journal-first 读取已持久化 terminal state，并支持 degraded 的 `sweepx --format ndjson status --operation-id <OPERATION_ID> --watch [--after SXCUR1]` completed replay：它只覆盖已完成且已持久化的 stream，先做一次同 snapshot 全量校验，然后按每页最多 1024 条事件续读；unknown 但语法有效的 cursor 返回 `stream.reset_required`，malformed cursor/usage 返回 usage error。它不等待新事件，不创建后台 operation，也不支持 cancel，因此不是 live progress。macOS 使用 legacy snapshot，仍无 replay/watch。Windows 默认 `state_dir=%LOCALAPPDATA%\sweepx\state` 并在该目录写入 durable snapshot；若状态目录可被其他用户访问则失败关闭。当前没有 live in-process registry，结果会显示 `canCancel: false`，`cancel` capability 为 `disabled`。cancel 命令存在是为了明确区分 `not_found`、`already_terminal` 或 `unsupported`，而不是伪装已经能中断同步扫描。

`status` 和 `cancel` 只打开现有状态：缺少根或 `operations/` 时返回未找到，不创建目录，也不修补现有权限。legacy snapshot 的原生读写保留目录句柄，拒绝链接、多硬链接、非普通或非私有文件；macOS 读取与写入准备共用禁止物化策略，Linux 相对操作保留 mount 身份，Windows 保留 DACL/卷边界检查。每份快照限 8 MiB 编码，解码前另限 65,536 次 JSON 值/键访问尝试；超过上限返回错误，写入拒绝保留旧快照。该额度不是进程 RSS 或全部状态文件的磁盘配额。Linux journal 的目录、锁与数据库共用保留句柄和 mount 证据；缺失查询不创建文件，不修补已有公共权限。私有 SQLite VFS 直接读写准入的数据库句柄，WAL/rollback 文件沿保留父目录获取并重验，连接绑定检查实际 C 文件对象；默认 VFS 不变。Linux OFD 锁避免关闭其他数据库 FD 释放本连接锁；大小与身份重查只读相对元数据。每 journal 的 32 MiB 编码长度额度包含 DB、WAL、rollback 和遗留 SHM；最多 64 个活动 VFS 上下文，包括日志关闭后仍被残留文件对象保留的上下文。它不是全部状态磁盘或进程 RSS 上限。原生 Linux/OFD 验收、最终相对 unlink 竞态、未显式绑定状态根的 audit/其他写入的共同额度、真实 provider 与目标宿主验收仍待完成。写入请求原生文件刷新（Unix 另刷新保留父目录），不据此承诺断电恢复；提交后刷新失败返回错误，但不会删除已发布的新文件。

CLI/Core 的普通预览、垃圾历史及显式 state-root 的兼容 macOS 文件索引写入与 operation snapshot、Linux journal 共用状态根非阻塞锁；默认垃圾入口不写文件索引：合作写入的文件长度合计限 512 MiB，目录与文件名合计限 4,090 项，计入未知普通文件及新旧文件/临时文件共存。缓存写入保留其中 32 MiB 和 8 个条目供终态记录使用；这些是准入余量，不是预分配或物理空间保证。只遍历已知存储形状；未知目录、链接、非私有文件或不确定原生证据拒绝新写入，不改权限、不删除 operation/audit/recovery 记录。缓存拒绝仍返回当前扫描事实；终态持久化拒绝明确报错并保留旧记录。独立 library cache API 仍沿用组件额度，需显式 state-root API 才参与共同计费；旧 component-only audit API、未来 spill/其他写入及非合作式写入尚未全部接入，因此全局资源审计仍未完成。它不是 RSS 上限、硬 I/O 期限或断电恢复保证。

原生扫描主路径与存储 I/O 现在共用 256 个句柄名额，其中存储 Directory/LockGuard 对象还受 128 个 owner 名额限制。打开、复制或创建前申请，实际句柄关闭后才返还；共享对象的引用不重复计费。扫描根/子目录、Linux 独立枚举 stream、文件身份检查及有界内容读取，与存储目录、控制锁、相对数据/临时文件、目录枚举和保留 SQLite 数据/WAL/索引文件均参与；SQLite 外部连接在存储对象退休后仍持有文件时，额度保持至实际关闭。Unix 存储导出的文件是携带额度的 `NativeFile`，其 `try_clone` 也先申请名额。额度耗尽时，扫描保持明确资源不足，不能将拒绝视为对象不存在或发布完整结果；普通预览跳过缓存，快照和审计在原生入口报告 `native_io_handles` 或 `native_authority_handles` 并保留旧记录，SQLite 回调中的打开失败仍按数据库 I/O 错误返回。祖先临时捕获也占名额，低余量可能拒绝打开，终态持久化没有句柄预留保证。借用 File/原生句柄后自行复制、尚未准入的外部文件、其他发现/NTFS/Trash 原生 helper 及 Windows 安全 token 查询仍不在此额度内；它不是全进程句柄/RSS 上限。原生 Linux/Windows 验收仍待完成。

显式 `AuditStore::open_in_state_dir` 现把固定 `audit/` 或 `permanent-delete-audit/` 接入上述共享额度，Linux `delete` 已采用该入口。创建前预留剩余 81 MiB SQL 增长及缺失名称；额度不足不创建审计子目录，但可能已创建零长度控制锁。短 SQL 和整个执行/恢复声明持有状态锁，直至数据库关闭和策略恢复；后续 SQL 复查控制锁身份及进程归属，竞争缓存写入直接拒绝。计划以借用的数据结构流式编码，最多 8 MiB，通过原生独占 rename 发布，已有或竞争创建的计划不被覆盖；提交前编码/恢复拒绝清理本次临时文件，提交后刷新失败则保留新记录。旧 `AuditStore::open` 仍只有组件额度，不能推断父状态根。全局句柄准入、其他写入/保留政策、RSS 和原生目标宿主验收继续开放。

Linux/macOS AuditStore 现使用共同的保留 SQLite VFS。实际打开的数据库 FD 在 SQL 开始前核对身份，连接另检查真实 C 文件对象；DB/WAL/rollback/SHM 沿保留目录操作，写入、truncate 和索引扩展在回调中受额度限制。DB 限 64 MiB、WAL 限 16 MiB、索引限 1 MiB，四类文件总长限 81 MiB；保留 NORMAL WAL、旧 wire/schema 和并发读者视图。macOS 禁止物化策略覆盖完整同步 SQL、映射访问和关闭区间，成功恢复后才返回结果或发布 live claim；消费执行也在关闭完成后释放排他锁。拒绝不整备权限或淘汰审计记录，Windows audit 仍不支持。

保留 SQLite VFS 统一在现有 audit crate 内，Linux journal 复用其 EXCLUSIVE 模式，原有数据库布局及 32 MiB 额度不变。AuditStore 使用 NORMAL WAL；64 个活动上下文由组件共同准入，每个共享索引映射最多 1 MiB，数据库页面不映射。macOS 已验证实际审计写入拒绝、目录/数据库替换拒绝、完整禁止物化区间、锁保持及崩溃恢复；并发读写和默认 SQLite 兼容由共同驱动测试覆盖，后者仅限独立进程。同进程默认 POSIX 客户端混用、Linux 原生运行、真实 provider、最终非合作式 unlink 替换、旧 component-only audit API 的共同额度及全局 owner 句柄/资源验收仍开放。

## Preview cache 只读诊断

```bash
cargo run -p sweepx-cli -- \
  --format json \
  --state-dir /absolute/path/to/sweepx-state \
  cache status
```

- Linux、macOS 与 Windows 均支持 `cache status`。
- 只支持 `human` 与 `json`；`--format ndjson` 在创建或读取任何 state/cache 目录之前以 usage error 失败。
- 若默认或显式 state/cache 缺失，结果返回 `disposition=absent`、exit 0，且不会创建 `state_dir`、`preview-cache/`、`current.json` 或其他缓存目录。
- 检查范围严格限制为 `preview-cache/current.json`、pointer 指向的 current generation 文件，以及平铺的 `generations/` 与 `quarantine/` 目录。
- 输出 kind 是 `cache.status.result`，并报告 `exists`、`currentGeneration`、`generationCount`、`quarantineCount`、`approxBytes`、`approxBytesComplete`、`storedSchema`、`currentHealth`、`schemaHealth` 以及 typed `warnings[]` / `errors[]`。
- 该命令不会触发 scan、repair、quarantine、rebuild，也不会暴露缓存条目、display path、预览内容或 live filesystem 事实。
- `available` 只表示受限缓存结构与校验可读；任意 warning、error 或 quarantine presence 都会把结果降为 `degraded`，并返回 exit 4。
- generation 解析另有 256 MiB 的存储预留预算，限制复制字符串、集合容量与内部枚举缓冲；它不是整个进程的内存上限。超额报告 `current_generation_parse_limit` 和十进制字符串 `reservationCapBytes`，不修改或隔离缓存文件。普通扫描报告缓存资源缺口并继续当前观察。

## 从 scan JSON 解释

```bash
cargo run -p sweepx-cli -- \
  --format json \
  explain \
  --scan-json /absolute/path/to/scan.json \
  --candidate-id <OPTIONAL_CANDIDATE_ID> \
  --max-input-bytes 8388608
```

输入必须是绝对路径、符合 `scan.result` 合同，并受 byte limit 限制。导入时 Core 会：

1. 将 provenance 改为 stale preview；
2. 将 coverage 标记为 incomplete/not revalidated；
3. 生成 explanation，但把 candidate 强制为 non-executable/report-only。

因此输出可用于理解，不可用于计划或执行。

## Cleaner 元数据

```bash
cargo run -p sweepx-cli -- --format json cleaner list
cargo run -p sweepx-cli -- --format json cleaner show org.sweepx.cargo-target
```

`list` 展示 package 与兼容性。`show` 只有在 Core 版本范围匹配时才展示完整 manifest/rules；不兼容时使用专门的兼容性错误退出。两者都不执行规则指向的文件动作。详见 [Cleaner 概念](/cleaners)。

统一垃圾识别入口已经可用：

```bash
sweepx junk ~/Projects
sweepx junk --tui ~/Projects
sweepx junk --tui --system
sweepx --format json junk .
sweepx --format json junk --system
```

项目产物规则统一由 catalog 加载、core 的 `JunkService` 使用现有 cleaner VM 评估，CLI 与后续交互界面可共享该入口。规则匹配只形成报告候选。

Dart `.dart_tool` 要求父目录普通文件 `pubspec.yaml` 和自身普通文件 `package_config.json`；SvelteKit 1/2 `.svelte-kit` 要求父目录 `svelte.config.js` 和自身 `tsconfig.json`、`ambient.d.ts` 两个普通文件。缺失、错位、目录或链接标记不能满足结构要求；当前内容观察另由上述 profile 给出。这些 R3 候选未证明独占所有权与工具活动，因此仅报告，不能据此回收。源文件、锁文件、自定义输出路径和 SvelteKit 3 新布局不据此匹配。机器规则 ID 分别是 `dart.tool-state`、`node.sveltekit-output`，跨语言保持一致。

`junk --tui ROOT...` 实时显示扫描阶段、进度及已完整观察子树的基础垃圾候选；`junk --tui --system` 在后台自动发现保守的系统垃圾根，不能同时传显式根。默认按逻辑大小降序，`--sort path` 改为路径顺序；未知大小排在已知零字节之后，不当作零。方向键移动，Space 选择，`a` 全选（最多 256 项），`u` 清空，`r` 刷新所选或当前行（空视图重扫全部），`R` 刷新全部范围，`c` 取消，`d/Delete` 将目录候选移到系统回收站，`q/Esc` 退出。选择按稳定键保留；旧、不完整或回收失败的行标为历史证据，需要完整刷新后才能再次回收。回收在独立工作线程执行，逐项重验 no-follow、对象/filesystem/mount 身份；重要/保护目录拒绝，失败不永久删除。该模式要求终端，不能结合 `--timings`、`--trash`、`--clean-temp`或机器输出。`--quarantine-dir` 可与 Linux `--system --tui` 配合指定异文件系统私有恢复区。Linux/macOS/Windows 会先显示历史候选缓存（系统模式先发现范围），并在后台重新观察本次范围、解释当前 Git 证据；三平台使用当前原生长度观测，不保留可选文件索引。历史行不能回收，刷新缓存预览行会扫描全部范围，系统全量刷新会重新发现根。三平台继续遍历目录并观察当前文件长度；该视图不写 operation journal。Linux 临时对象使用独立测量结果展示，逻辑字节与分配字节分开；普通 Trash 拒绝这些行，刷新会重扫系统范围，Linux 可按 `x` 对所选临时对象在后台生成完整隔离计划，输入 `clean <完整摘要>` 再按 Enter 确认；确认框不自动填充摘要。方向键/PageUp/PageDown 滚动计划，左右键查看长行，Esc 取消或关闭；移除中的取消等待结果，可留下部分源和完整恢复副本。界面保留恢复目录和失败原因，确认移动才移除行；父目录旧统计失效为历史，需刷新后才能再次操作。预览、执行与扫描/Trash 互斥，仍可使用独立的 `junk --system --clean-temp` 入口。选中目录刷新只递归所选子树，浅层枚举原生祖先所需的规则与 Git 标记，不进入无关兄弟子树；祖先旧统计标为历史，完整刷新后才能再次操作。macOS 局部刷新完整结束后，只将新候选片段合入历史候选记录，保留未刷新兄弟的历史展示，不查询 FSEvents 或合并文件索引。合并记录不能整根命中；取消、不完整观察或缓存准入失败保留旧记录；单个大根中，完整子树在自身和父目录 marker 枚举完毕后即可展示基础候选；Git 解释和完整终态仍继续，扫描中不能据此回收。

扫描因取消或资源缺口未完成范围观察时保留已显示的候选；后续完整刷新会移除该范围内不再匹配的行，包括先前取消时留下的基础候选。缓存预览和未完成解释的基础行没有局部刷新绑定，按 `r` 会重扫全部根；已解释的目录行仍可局部刷新。会话的呈现索引和 CLI 私有结果表各自限制为最多 16,384 行及 64 MiB 保留估算，跨失败/取消刷新累计，不随新一轮扫描重置；拒收新行或更新时保留相应旧证据并停止本轮，视图不完整且不能回收；已由完整观察确认失效的行仍会撤下。这些额度与扫描候选、事件队列及界面预算独立，不是进程 RSS 上限。

当前候选按本次遍历及工具快照解释 activity/staleFormats，并由 core 的 `GitEvidenceSession` 重建当前仓库、tracked 与 ignore 证据。缓存只保存遍历覆盖及候选内仓库边界事实，不保存 Git 查询结果；历史 `ignored` / `high` 不作为本次证据。当前确认未跟踪、被 ignore、完整覆盖且不含仓库的项目候选才增强置信度，失败保留基础 `known_generated` / `medium` 和明确 blocker。选定根之外的父仓库与排除配置也在本次观察。

显式根继续识别明确可重建的项目产物：Rust `target`、Node `node_modules`、Python `__pycache__/.pytest_cache/.mypy_cache/.ruff_cache`，以及常见 `dist/build/out/.next/.turbo`。若原生路径及遍历证据能完整确认 Git 工作区，`junk` 还会以有界、非交互的 Git 查询检查这些**已有规则候选**：未跟踪、被 ignore 且不含嵌套仓库时，JSON 将其标为 `classification=known_generated_ignored`、`confidence=high`；存在 tracked descendant、gitfile/嵌套仓库、扫描证据不完整或 Git 查询失败时保守保留原分类并给出 `blockers[]`。Git ignore 只增强解释，不单独发现或授权删除任意路径；`.env.local` 等本地状态不会仅因被 ignore 而成为候选。

不传显式根并加 `--system` 时，Linux 除报告 `XDG_CACHE_HOME` 外，还会枚举 `/tmp` 的任意直接子对象，名称不参与判断。候选必须是当前用户拥有、与 `/tmp` 同设备、可从 sticky 父目录删除且递归 atime/mtime/ctime 至少 7 天未更新的目录、普通文件、符号链接、FIFO 或无绑定 Unix socket；目录会 no-follow 递归统计分配大小和最新活动时间。SweepX 拒绝其他用户对象、跨设备/挂载边界、外部硬链接、设备 inode、已绑定 socket，以及在当前用户可读的 `cwd`/`root`/`exe`/`fd`（含 FIFO 的 `pipe:[inode]` 引用）/`map_files`/`mountinfo` 或可观测网络命名空间 Unix socket 表中出现的对象。其他用户私有进程或挂载/网络命名空间仍可能不可见；只要当前用户视图读取不完整，报告标记 partial 且清理拒绝执行。macOS 在 `~/Library/Caches` 下逐个报告应用缓存，Windows 只在 `%LOCALAPPDATA%/Packages` 下识别深度为 2 的 `LocalCache` / `TempState`。Linux `/var/tmp`、Windows 系统清理以及包管理器/容器共享存储尚未纳入。

Linux 临时对象分析与清理重验都有独立的资源预算：默认最多 1,000,000 条观察、64 MiB 累计保留估算；每目录最多 65,536 个名称及 8 MiB 名称字节，单个 mount/socket 表最多 4 MiB，整次表读取最多 64 MiB。它们不是 RSS 上限。取消、期限或预算不足均保留不完整状态，表的截断前缀不能证明没有进程引用；缺失候选也不能当作没有垃圾。

隔离预览和执行复用 `sweepx-core::junk::quarantine`，CLI 只打印和确认。原生预览不能由显示路径或摘要重建，计划绑定实际加载的规则字节；会话调用可要求所选行原测量与现场完全一致。每批最多 256 项；默认路径累计准入估算 64 MiB、访问上限 1,000,000、深度 128、复制/核验 I/O 预算 1 TiB、合作期限 15 分钟。目录枚举与复制、核验、源移除使用同一取消令牌；读取长度固定为计划长度，增长的文件不会导致无界复制。确认输入最多保留 256 字节。取消或超限停止后续动作，但移除开始后可留下部分源树和完整恢复副本，不提供原子回滚；这些预算不代表 RSS 或阻塞内核调用的硬超时。TUI 隔离流程已接入；Linux 宿主上的端到端执行仍未验收。

Linux 系统 TUI 可指定恢复区：

```bash
sweepx junk --system --tui --quarantine-dir /mnt/recovery/sweepx
```

仅接受临时对象选择，目录候选仍使用 `d/Delete`；不混合两种执行计划。计划展示最多 1 MiB，确认输入最多 160 字节，过大计划拒绝执行而非截断授权。后台保留原生预览，只有一个 mutation worker 和单槽结果/确认通道，等待确认最多 15 分钟。关闭界面取消且不 join 阻塞系统调用。

Linux 可显式隔离这一组陈旧临时对象：

```bash
sweepx junk --system --clean-temp
# 可选：--quarantine-dir /absolute/private/directory
```

该模式只接受 human 输出和前台交互终端。SweepX 先打印全部目标、大小、隔离位置、剩余进程观察边界和完整 canonical digest；用户必须原样输入 `clean <完整摘要>`，短指纹不授权。确认后它再次重验每个对象的设备/inode、所有者、类型、atime/mtime/ctime、年龄、当前用户进程引用和挂载边界，检查异盘剩余空间，再把对象复制到与 `/tmp` 不同文件系统上的 `0700` 私有隔离区。普通文件会保留稀疏区间、同步数据并逐字节校验，目录项、FIFO/socket 类型和元数据完成 fsync 后才移除源对象。`plan.json` 和逐项 `outcomes.jsonl` 在移动前持久化；中途失败会停止后续项并报告 partial/reconciliation，不会永久删除。默认隔离根是 `$XDG_DATA_HOME/sweepx/quarantine` 或 `$HOME/.local/share/sweepx/quarantine`。

这不是桌面 Trash 的替代实现。Linux Freedesktop Trash 通常要求跨文件系统项目进入**源挂载点自己的** `.Trash-$UID`。本机 `/tmp` 位于根盘而 HOME Trash 位于另一块盘，GIO 实测返回 `Trashing on system internal mounts is not supported`，普通用户也无权在 `/` 创建 `/.Trash-$UID`；因此桌面回收站存在，不代表根盘 `/tmp` 支持 Trash。SweepX 会解释这一类失败，且绝不从 Trash 自动降级为永久删除。

### 候选的体积是怎么报的

`reclaimable` 优先使用文件系统的已分配大小。当平台拒绝给出分配量时，改报表观逻辑大小，并把
`sizeIsLogical` 置为 `true`。

这一点在 Windows 上很关键：适配器**有意**不声称分配量 —— `FILE_STANDARD_INFO` 只描述未命名 `$DATA`
流，因此在存在备用流、稀疏区间或压缩时，给出精确值就是猜测。这个拒绝是对的，但照字面执行会让所有候选
都没有体积：2026-09-05 实测 30 条候选全部如此，其中包含 1.8 GB 的浏览器缓存。一个说不出任何东西有多大
的清理工具，并没有回答用户的问题。

两个量不可互换，所以这种替换始终显式可见、不静默。仅为下限的分配量不会因为"字段名义正确"而胜出 ——
精确已知的逻辑大小信息量更大。当两者都不精确时，保留由分配量派生的证据，因为它的 reason code 说明了
体积为何缺失。

### 浏览器渲染缓存

`--system` 会报告所发现的每一个 Chromium 系安装中可重建的缓存：HTTP 缓存、已编译的 JavaScript 与
WebAssembly 缓存，以及 GPU 和着色器缓存。发现阶段从磁盘枚举 profile，而不是假定只有 `Default`；同时也
覆盖位于 profile **之外**、与其并列的着色器缓存。

三种后端布局各不相同，因此每条规则由各自的标记守卫 —— 分别是 `Cache_Data`、`js` 和 `data_1`。索引文件
不能作为通用标记：2026-09-05 实测，三者中有两者的根目录下根本没有索引文件。

**刻意不纳入**的部分：Service Worker `CacheStorage`、`IndexedDB`、`Local Storage`、cookies 以及扩展
状态。`CacheStorage` 名字里有 cache，但它保存的是 PWA 离线状态，而不是网络可以再次取回的响应。

2026-09-05 在 Windows 上跨 Edge、Edge Dev、Chrome 实测：合计 1.8 GB，其中最大的单个目录是 Edge Dev 的
611.7 MB 代码缓存。若假定只有一个浏览器安装，就会漏掉它。

blockfile 后端的着色器缓存体积包含固定骨架 —— 即使缓存为空，`data_0` 到 `data_3` 和 `index` 也会被写入，
因此空缓存仍占约 0.5 MB。
### 工具缓存：识别每一份副本，而不只是在用的那份

`junk --system --rule RULE_ID` 只扫描一个类别，可重复指定并结合 `--tui`。未知或其他平台的 ID 在发现前拒绝；未选类别不在本次扫描范围内。不传 `--rule` 仍执行完整系统发现，受保护目录的原生调用仍可能等待系统响应。Unix npm 默认目录为 `~/.npm`，Windows 为 `%LOCALAPPDATA%/npm-cache`；只报告有 `content-v2` 和 `index-v5` 目录的 `_cacache`，保留 `_npx` 工具及自定义同级文件。工具回答缺失时保持 `activity: unknown`。pnpm 的 256 分片目录允许额外的普通 `.DS_Store` 文件，但仍拒绝未知额外条目及该名称的目录或链接。

npm、pnpm、pip 的规则不依赖单一位置。发现阶段会枚举工具报告的路径、工具自身的环境变量覆盖，以及
文档记载的平台默认位置；随后只有目录**自身内容**符合该缓存的结构特征时才纳入 —— 对 pnpm store 来说，
是 `files/` 下恰好 256 个两位十六进制分片目录。

询问工具回答的是**哪一份在用**，而在用的那份恰恰是**不该**回收的。废弃的副本才是垃圾，而它永远不会是
resolver 报告的那个。2026-09-05 实测：位于文档默认位置的 pnpm store 有 146.8 MB、最后写入
2024-10-26，而真正在用的那份是另一个卷上的 127.5 MB —— 只信 resolver 的规则会完整漏掉那份更大且已
停止使用的副本。

报告两个标记。两者都不会删除、预选或改变排序；分类仍然只读。

| 字段 | 取值 | 含义 |
|---|---|---|
| `activity` | `live` | 工具报告的就是此路径，不应回收。 |
| | `stale` | 已验证属于该工具的缓存，但工具并未在使用。 |
| | `unknown` | 无法询问工具，因此不做任何断言。拿不到答案不等于已废弃。 |
| `staleFormats` | 例如 `["http"]` | 根目录内已被取代的格式目录，且当前格式同时存在。 |

`unknown` 来自一次实测到的失败：Windows 上 npm 以 `.cmd`/`.ps1` 包装脚本分发，而直接创建进程不会应用
`PATHEXT`，导致 resolver 返回空，一度把**在用**的缓存标成了废弃。目录身份同样通过文件系统解析而非比较
路径字符串，因为大小写敏感性是宿主与卷的属性；按字符串比较曾把同一个 pip 缓存报告了三次。

`staleFormats` 只在旧格式与当前格式**同时存在**时报告。否则该工具只是版本较旧、磁盘上只有那一种格式，
称其“已被取代”就是错的。2026-09-05 实测：pip 缓存中旧格式 `http` 有 73.1 MB、最后写入 2023-12-09，
而当前格式 `http-v2` 为 0 MB —— 99.9% 的字节位于一个不再被写入的格式中，而所在根目录本身是在用的。
## 文件管理器式 TUI 与回收站预览

`trash /absolute/path` 直接回收普通文件/真实目录；重要目录要求交互终端确认，保护根拒绝。macOS 使用 Foundation 的原生系统回收接口，不再等待 Finder AppleScript。其路径转换需要无损 UTF-8，其他编码拒绝；部分系统没有“放回原处”菜单，可从回收站拖出恢复。提交前继续重验身份，失败或结果不明不会降级为永久删除。原生系统调用仍是同步调用，取消不能证明文件尚未移动。

```bash
cargo run -p sweepx-cli -- --locale zh-CN \
  scan --tui /absolute/path/to/root [/another/absolute/root]
cargo run -p sweepx-cli -- trash /absolute/path/to/item
```

TUI 直接消费本次 live scan 的 typed 结果，不要求中间 JSON。单根会自动进入；多根先展示虚拟根。`Enter` / `Right` / `l` 进入目录，`Esc` / `Backspace` / `Left` / `h` 返回，方向键或 `j`/`k` 移动，`d` / `Delete` 选择移到系统回收站，`q` 或 `Ctrl-C` 退出。回收站动作会先退出全屏，再要求确认并重验扫描身份；symlink 和 reparse point 不可操作。

`--tui` 要求 stdin/stdout 都是终端，并且不能与 `--format json|ndjson` 组合。TUI 只做 root admission 就进入界面，单根自动进入；当前层先展示，直接子目录的递归大小在后台扫描时约每 120 ms 以明确的下限值（`>=`）增量回填并重排，最终结果再收敛为 exact 或 incomplete，后代不作为列表行长期保存。递归详情逐个完成子树，避免宽目录同时持有所有兄弟句柄；进度在各子树之间统一合并，最后一次增量可提前，完整结果仍保留全部行。进度通道容量为 1，慢终端只会丢弃已过时的中间快照，不会反压扫描。目录 detail rescan 以 single-flight 后台任务运行：30 秒是无进展 deadline，有有效增量时续期；导航或退出不会等待非协作 worker，最后一次进度回调中的取消也会阻止完整结果发布。

## Linux 有界文件/目录永久删除预览

```bash
cargo run -p sweepx-cli -- delete "$(realpath -- /path/to/file-or-directory)"
```

`delete` 是 Linux-only、R4、不可恢复的 development preview。它接受当前用户拥有的普通文件，或最多 256 个动作、深度 64、累计路径数据 1 MiB 的真实目录树；普通文件 hard-link count 必须为 1。路径必须是 `realpath -- PATH` 得到的解析后绝对路径，不能包含 `.` / `..` 或经过 symlink。link、special file、跨 mount、root/capability-bearing 进程、系统/home/state/Trash/cwd/executable 保护范围及任一祖先/后代中的 `.sweepx-protect` 都会失败关闭。命令只接受 human 输出且 stdin/stdout 必须处于前台终端。

执行前会展示完整 canonical digest，并要求逐字输入 `PERMANENT 1 <ACTION_COUNT> <FULL_DIGEST>`。计划先写入当前用户私有的 `state/permanent-delete-audit/`；目录会将每个后代绑定为独立 action，按后序逐项执行。每项都先写 durable intent，再重验保护链、parent/object identity、类型、local filesystem、mount、owner、hard-link count 与 metadata fingerprint，最后只调用一次 parent-relative `unlinkat` 或 nonrecursive `rmdir`，并写入独立 outcome。新增/替换对象不会被顺手删除；若已有动作成功，结果明确报告 partial。Linux 没有“仅当 basename 仍指向已打开 inode 时才 unlink”的通用原子接口，因此最终 identity check 与 `unlinkat` 之间仍有明确的同 UID pathname race；本功能保持 preview 状态。该命令没有无界递归、`--yes`、`--force`、`--permanently` 或 `--dangerously-delete` 旁路；它也永远不会被 `trash` 失败触发。Permanent 表示绕过回收站，不是 secure erase。

扫描加速和跨平台垃圾规则的来源、可借鉴点、GPL 边界以及 Linux 策略见 [MangoDisk 采用决策](https://github.com/lejunyang/sweepx/blob/main/docs/research/mangodisk-adoption.md)。

## Windows 扫描加速与权限

Windows 上存在一条基于 NTFS 原生元数据的加速扫描路径。每个扫描根在遍历前会先做一次只读资格判定，**判定失败不影响结果正确性**：可移植的 handle-relative 遍历始终是权威实现，产出的总计仍然精确。

加速需要一个 `GENERIC_READ` 级别的卷句柄。在本机实测（未提权列 2026-09-02 对 `C:` 与 `E:` 验证；已提权列 2026-09-04 对 `C:` 验证）得到的边界是：

| 请求的访问级别 | 未提权 | 已提权 |
|---|---|---|
| `0` / `FILE_READ_ATTRIBUTES` / `SYNCHRONIZE` / 两者组合 | 句柄可以打开，但 FSCTL 返回 `ERROR_INVALID_FUNCTION (1)` | **完全相同，仍是 `1`** |
| `GENERIC_READ` | 打开即被拒绝，`ERROR_ACCESS_DENIED (5)` | 打开成功，`FSCTL_QUERY_USN_JOURNAL` 可用 |

关键结论是：低权限句柄在提权后**依然**报告控制码不存在。这不是"权限不够"，而是该句柄级别上功能本身不存在，因此没有"降低权限换取可用性"的空间——未提权时加速无法启用是平台属性，不是实现缺陷。这一整张表由探针 `volume_access_masks_behave_the_same_at_both_privilege_levels` 在两种权限级别下分别实测得出，而不是从未提权结果推断而来。

资格判定失败会作为一条 `scan.progress` 事件出现，带 `accelerationRefusalReason`（稳定机器码，不翻译）与 `elevationMightHelp`。它的 `coverageEffect` 是 `observed` 而不是 `incomplete`：放弃一项优化不会丢失任何覆盖，普通未提权扫描不应因此显示为 partial。`elevationMightHelp` 仅在原因确实是权限时为 `true`，避免把用户引向一个无法解决问题的 UAC 弹窗（例如卷不是 NTFS 时提权毫无帮助）。

需要加速时可以显式 `--elevate`，它会请求一次 UAC 同意并以提权身份重启进程。注意提权会话下的破坏性操作仍按设计被硬拒绝，不会因为权限更高而放宽。

资格判定通过时，会对卷的 NTFS 元数据做一次批量读取，为每个扫描根产出一份**预览（preview）**，结果出现在扫描摘要的 `acceleration` 字段中：

```json
"acceleration": {
  "used": true,
  "preview": {
    "entryCount": "37371",
    "logicalBytes": "14812812602",
    "elapsedMicros": "1058065",
    "exact": true,
    "authoritative": false
  }
}
```

判定失败则在同一位置报告为 `{"used": false, "reason": "not_elevated", "elevationMightHelp": true}`。

预览有两条必须注意的性质：

- `authoritative` 恒为 `false`。预览数据来自元数据快照，**不携带 reopen recipe**，而删除操作正是要对它做重新校验。它的作用是让大目录能快速给出一个总量；不能凭预览删除任何东西，遍历产出的权威结果会覆盖它。
- 当扫描根下有记录无法解析时 `exact` 为 `false`，此时容量是下界，不得按精确值展示。

本机 2026-09-02 实测，对象为 `E:\Projects\sweepx`（14.5 GB、36,531 个对象）：预览耗时 **1.06 s**，而完整权威扫描耗时 **133 s**，即拿到首个答案约快 **126 倍**。权威扫描本身并没有变快——预览是附加的，其整卷读取是约一秒的固定成本，只有在大目录上才划算。

预览输出会与普通目录遍历做交叉验证（两者访问文件系统的代码路径完全不同），要求路径集合与字节总和逐一相等。

### 跨运行的历史预览

普通 `scan` 加载的 generation 始终报告 `loadStatus: "stale_preview"`。它提供历史记录计数，当前文件事实仍来自本次原生遍历；历史预览不提供删除权限。此前的 `verified_preview` 升级已撤回。

macOS 普通预览与垃圾历史缓存现在复用平台的线程级禁止 dataless 物化策略，覆盖目录打开、枚举、计费、读取与发布准备。未知/拒绝的策略调用不回退无保护读取，已知 dataless 文件直接拒绝；读取成功还需恢复原策略，恢复失败丢弃结果。发布先完成受保护编码和策略恢复，再提交相对名称替换，恢复失败保留旧指针。整文件限额读取也接入同一保护。原生线程策略已有本机验证，真实云 provider、Linux journal VFS/OFD 运行资格、全局状态保留额度及原生 Linux bind mount 验收仍待审计。

Linux 缓存目录现在保留本次打开句柄的挂载身份；子目录、锁、读取文件、计费和发布临时文件必须与该目录同挂载、同设备。设备号与 inode 相同的 bind mount 也不能代替这一证据。缺少所需原生字段、身份不匹配或拒绝时跳过缓存，当前扫描继续；不跟随链接，不把未知证据算零。显式缓存根可以位于独立挂载盘，根内对象不能跨挂载。发布前再次核对临时文件的名称绑定；检查到 rename/unlink 的最终竞态仍开放。Linux 原生及私有命名空间 bind mount 测试仍待目标宿主运行。

普通预览保存会保留最多四个 generation，并保护当前代次。计费只查看缓存根、`generations/` 与 `quarantine/` 三个平坦目录，总计最多 4,090 个非点条目；512 MiB 编码长度额度包含未知普通文件、隔离记录及本次发布临时文件。未知文件和隔离记录不参与淘汰，未知目录或计费失败会跳过缓存更新，当前扫描继续。计费、发布和非当前代次淘汰使用同一保留句柄及非阻塞锁；已有权限不被修补，已有 generation ID 不被覆盖。准备时可能先淘汰非当前缓存，后续投影失败也保持当前指针。该额度不是物理分配或整个进程/状态目录上限；原生 provider、目标宿主与不遵守锁的替换竞态仍需独立验证。

[NTFS 日志会合并未关闭文件的重复同类变化](https://learn.microsoft.com/en-us/windows/win32/fileio/change-journal-records)。因此日志位置未变不能证明文件事实未变，即使游标在遍历前捕获并覆盖全部卷，也不足以建立这个证明。普通预览不再额外探测卷日志，也不要求为加载历史缓存提权。

| Warning | 含义 |
|---|---|
| `cache.preview.unverified.no_evidence` | generation 没有有效性 token，保持历史状态；新写入的 generation 使用空列表。 |
| `cache.preview.unverified.legacy_unbound` | 旧 generation 带有日志提示，但没有完整扫描范围、原生卷身份和捕获顺序证明；保持历史状态，不解析 token 或探测卷。 |

旧 `validity` 字段和校验摘要仍兼容，旧 token 可以保留和读取。校验摘要证明存储内容一致，不能证明它仍对应当前文件系统。此变化不影响独立的 NTFS 批量预览及其 `authoritative: false` 合同。

## 当前不存在的命令

```text
PROPOSED ONLY — NOT IMPLEMENTED
sweepx plan create ...
sweepx plan show ...
sweepx approve ...
sweepx execute ...
sweepx execute ... --dangerously-delete
```

P3 中有对应概念的 library model 与 fake execution tests，但仍没有通用 plan/approve/execute CLI。Linux 有界文件/目录 `delete` 是独立 preview，不使用这组通用命令。

## `npx-cache`

一次原生遍历列出 npx 缓存槽中的直接工具、实际安装版本和整套依赖的逻辑大小。

```sh
sweepx npx-cache
sweepx npx-cache --package PACKAGE --older-versions
sweepx npx-cache --package PACKAGE --older-versions --trash
sweepx npx-cache --entry 0123456789abcdef --trash
sweepx --format json npx-cache --root /absolute/npm-cache/_npx
```

默认位置为 `~/.npm/_npx`；重定向缓存请指定 `--root`。没有 `--trash` 时只预览。`--older-versions` 保留每个包的最高已安装语义版本（不访问注册表），同版本及仅 build metadata 不同的版本都保留；未知版本、多包槽、覆盖不完整不进入自动计划；有未知或多包成员的版本组整体排除，已识别的其他工具组可独立计划。包过滤只选择直接依赖；回收单位是整个槽，不拆除共享依赖。执行前重新读取绑定原生身份的 manifest，macOS/Linux 检查当前用户的进程参数与打开文件；Windows 活动适配尚不支持回收。拒绝、部分失败和未完成分别返回结果；始终使用 OS 回收站。活动观察不是排他锁，新的启动与最终路径替换窗口仍存在。JSON `inventory` 保留完整根报告，`selection` 是本次计划，字段不随语言变化。

## `browser-model`

```sh
sweepx browser-model
sweepx browser-model --version 2025.8.8.1141 --trash
sweepx browser-model --disable-download-config /absolute/chrome-no-model.mobileconfig
```

本轮支持 Chrome legacy `OptGuideOnDeviceModel/<version>` 的原生大小、manifest/config 识别与元数据重验；macOS 明确选择后回收整个版本目录，拒绝正在运行的 Chrome、不可用活动观察、原生变化或不完整数据。其他平台回收、Edge 与 Manifest Broker 资产尚未支持；预测模型和整个 User Data 不是替代目标。模型回收不保证持久禁用重下。

这个入口只导出配置文件，不自动写入或安装系统策略。macOS 配置导出只包含 `GenAILocalFoundationalModelSettings=1`，不关闭其他组件更新。请手动安装并在 `chrome://policy` 确认该值与正常状态。此策略禁止基础模型下载，Chrome 自身可能删除已有模型，依赖该模型的能力将不可用；策略自动清除不经过 SweepX 回收站，建议先退出 Chrome 并回收载荷。移除该配置描述文件恢复默认策略。导出不等于安装或验证。

## `browser-extension`

```sh
sweepx browser-extension bundle --output /absolute/SweepX-Browser-Extension
sweepx browser-extension register --browser chrome --bundle /absolute/SweepX-Browser-Extension
sweepx browser-extension request --browser chrome --profile Default --domain example.com
sweepx browser-extension status
```

程序内置扩展源文件，`bundle` 创建新的私有目录，包含扩展、独立通信组件及 `INSTALL.txt`，默认拒绝覆盖已有目录；`--update` 只更新已识别的私有 SweepX bundle 中的生成文件，保留其他文件。`register` 在 macOS/Linux 为当前用户的稳定版 Chrome/Edge 注册通信组件；Edge 使用 `--browser edge`。Windows 注册需依导出的说明手动设置 HKCU；Beta/Dev 注册未自动化。最后一级注册目录权限不安全或祖先含链接时拒绝，且不修复现有权限。

首次需在对应浏览器的扩展页启用开发者模式并加载导出的 `extension` 目录。扩展工作台支持占用概览、搜索排序的网站列表、存储分区明细和独立的清理确认。点击「扫描占用」可自动连接；在「连接与设置」核对当前浏览器和 profile 目录。也可在「指定网站清理」输入精确域名或 HTTP(S) origin，完全不连接 SweepX，由当前浏览器确认清理；此模式的大小为未知。裸域名明确包含 HTTP/HTTPS 默认端口，显式 origin 保留端口，不包含子域名。浏览器启动本地组件，不需要一直运行 SweepX 或网络服务。扩展只能展示 SweepX 已识别的存储；共享及未归属数据单独显示，不声称覆盖所有网站数据。

`request` 仅排队一个精确域名的待确认计划，15 分钟有效；打开匹配的扩展确认页处理或拒绝，`status` 查看待处理和最后回传结果。连接后立即检查请求，空闲且可见的页面每五秒检查一次；自动检查不覆盖正在核对的域名，手动“检查待确认请求”可在选中域名时使用。新请求重置清理范围和确认信息；重新连接后可再次查看尚未处理的同一请求，无请求、请求过期、浏览器/profile 不匹配或读取错误均有提示；实际调用清理接口前再次检查请求有效期。完成报告表示浏览器 API 已完成，不证明空间释放。网站存储可能有未同步内容，清除无回收站；Cookie、历史、密码和扩展数据不清除，个人资料身份需用户确认。

更新时保持目录不变，用新版 SweepX 执行 `browser-extension bundle --output /absolute/SweepX-Browser-Extension --update`，然后在浏览器重新加载扩展并重新打开工作台；原通信注册路径不变，无需重复注册。此前若加载了版本目录，先切换到固定 `extension` 目录一次，并用 `register --replace` 调整原 SweepX 注册。更新逐个原子替换文件，整个 bundle 不是原子事务；中断后重新执行更新，成功后再重新加载。Windows 更新前需断开使用本地组件的浏览器连接。目前无商店发布、静默安装或商店自动更新；企业策略拒绝时不绕过。用户已在 Edge 展示实际域名明细，实际删除仍待本机验收。详见[扩展指南](../integrations/chromium-cleanup/README.md)。

## `site-storage`

按域名汇总 Chromium 网站数据，并保留浏览器、profile、完整存储键、分区和 bucket 明细。默认报告只读；网站应用状态与 `junk` 分开。

```bash
sweepx site-storage
sweepx site-storage --browser edge --profile Default --domain example.com
sweepx --format json site-storage --browser chrome
```

macOS、Linux 和 Windows 均探测默认安装位置的 `Default` / `Profile *`。`--browser` 使用稳定标签，如 `edge`、`chrome`、`edge-dev`；`--profile` 精确匹配目录名；`--domain` 只匹配一个 hostname，不包含子域名。自定义 profile 路径、沙箱发行版和非默认 StoragePartition 不自动推断。

支持三种归因布局：

- `service_worker_cache_storage`：读取有界的 `index.txt`，按 protobuf 的 origin/storage_key 字段解析，避免把缓存名称中的 URL 误认成来源。
- `indexed_db`：识别旧 `.indexeddb.leveldb` / `.indexeddb.blob` 配对，保留非默认端口。
- `web_storage`：从原生绑定的 `QuotaManager` 文件观察 bucket ID、完整 storage key 和 bucket 名称，关联 `WebStorage/<id>`。这是主数据库文件的非原子观察，不重放 WAL/journal，不能作为删除依据。

Local Storage、Session Storage、Service Worker 注册/脚本、扩展和 HTTP/code cache 以共享类别报告整体大小，不编造按域名的占用。macOS/Linux 分离的 profile cache 根也会统计。 安装级 AI 模型、优化模型和组件下载以 `@installation` 独立列出，不归属域名；显式 `--profile` 排除此范围。新 IndexedDB SQLite 独立布局及未知 bucket 保持未归因；不因解析不支持而丢掉整体大小。

机器格式保留 `sweepx.site_storage.result/v1`、`profiles`、`subsystemBytes`、`fullyAttributed`、`origins[].storageKey/bytes/directoryCount`。新增 `domains` 汇总，以及 `sizeComplete`、`unattributedBytes`、`snapshotConsistency`、目录和 bucket 明细。大小是逻辑长度，不代表物理分配或可释放空间；无法取得的大小为 null，已知下界与完整值通过覆盖状态区分。`fullyAttributed=false` 可以表示有共享/未知字节，不能据此把总量显示为精确归因。

域名筛选只过滤来源行，子系统整体总量保持不变；`totalsScope` 明确这一点。来源目录的大小和父总量由同一次原生遍历得到，不反复遍历同一数据。最多 32 个 profile、64 MiB 元数据观察和 16 MiB 来源报告保留估算；两分钟合作式期限在原生观察间检查，不能保证中断阻塞的 OS 调用。发现/扫描/元数据失败输出 partial、退出码 4；完整报告退出 0。

旧 `--trash-origin` 和 `--browse` 目前在扫描前以退出码 3 拒绝：原 LOCK 探测不能证明所有浏览器写入已停止，通用目录 TUI 也不具备站点选择约束。后续删除需要先预览具体浏览器/profile/分区/bucket，并验证关闭状态、当前映射和原生身份；显示路径与域名汇总都不是执行授权。未删除网站数据。

### 名称列溢出、完整路径与滚动

名称列的实际宽度远小于直觉：五个固定列先占去 67 格，剩下的才按百分比分配。在 80 列终端上，名称列
只有 6 格，而不是 80 的 42%。因此长路径必然溢出，界面对此有三种处理：

- 未选中且溢出的行以省略号结尾，表示后面还有内容被省掉了；
- 选中行改为循环滚动，每 300 毫秒推进一格，跑完一遍后空四格再从头开始；
- 按 `p` 在页脚固定显示选中行的完整路径，页脚会换行，不再截断。

只有选中行滚动。若所有溢出行同时滚动，用户正要读的那一行会被整屏的动画干扰。

滚动窗口的宽度恒等于列宽。宽字符（如中文）占两格，若某个宽字符放不进最后一格，会以空格补足而不是
直接丢弃——否则右侧各列会随文字滚动左右跳动。同理，滚动到宽字符中间时也补空格，不然相邻两帧会渲染
成同一内容，中文路径每隔一格就会卡顿一次。

`p` 显示的路径只用于阅读。它不构成任何执行凭据；移入回收站前仍会重新校验原生身份。

Linux/macOS/Windows 的普通 `junk` 报告与垃圾 TUI 使用当前原生文件长度观测：Linux 用相对保留父目录的 no-follow `statx` 核对类型、长度、设备和 mount ID；macOS 使用本次 `getattrlistbulk`；Windows 使用当前目录枚举批次的在线普通文件长度，排除 reparse、offline/recall、设备项与无效身份。垃圾入口省去完整文件条目和可选文件索引，macOS 默认不查询 FSEvents。目录、规则 marker 与候选仍现场遍历，缺失或不合格事实回到普通检查；分配大小、硬链接唯一性与可释放空间保持 unknown。普通 `scan`、大文件、重复内容及要求完整文件事实的调用方沿用完整原生观察。根记录仅作历史展示，不完整扫描保留旧记录。

历史候选记录绑定规则字节、平台、根身份和嵌套根范围，不接受为当前整根命中。每次报告重新发现所需上下文并现场分类；兼容 library 文件索引仍独立验证，默认垃圾入口不使用该索引。

`junk --system` 的根发现、分类和工具安装清单共用本次调用的探测快照，扫描结束后不会重新启动一轮探测。整批工具调用预算为 10 秒，单次最多 2 秒、stdout 最多 64 KiB，最多尝试启动 64 个进程；超时、取消、输出过量或工具不可用时保留 unknown，安装信息的缺失字段为 null。显式项目根扫描不探测无关的 npm 安装。

工具缓存根、浏览器和已知缓存位置共用本次有界布局发现快照，版本目录展开和分片指纹检查也计入共享预算；分类不再逐候选枚举或解析路径。默认限制为 4,096 个目录探测、16,384 条返回枚举记录、1,024 个规则根引用和 8 MiB 保留估算；5 秒期限及取消在原生调用之间检查，不能中断阻塞的 OS 访问。缺少 anchor、权限/观察失败或资源不足时，`layoutDiscovery.complete` 为 false，`incompleteReason` 给出稳定原因代码；总体报告 partial、退出码 4。已确认候选仍可显示，空列表不证明没有垃圾；本次不完整分类不写整根候选缓存。非交互清理/Trash 请求在发现前拒绝。 工具根的身份及变化指纹绑定本次扫描事实；精确分片数需要完整枚举和 no-follow 目录检查，链接或截断不能建立匹配。活动关系和旧格式提示由本次原生快照解释，不提供删除权；单路径超过 64 KiB 时拒绝布局准入。

每个根的目录都会重新枚举，重建本次扫描身份和分类标记。默认三平台垃圾入口直接使用当前原生普通文件长度；兼容 library 文件索引仍需现场类型与相同长度确认。缺失的物理分配、硬链接去重及可释放空间保持 unknown，旧候选不能用来跳过整棵子树。

`junk --timings` 在 stderr 输出一条 `sweepx.junk.timings/v1` JSON，包含发现、准备、根缓存验证、逐文件缓存验证、遍历、候选拼装、Git 证据、缓存写入和报告阶段的纳秒耗时，以及实际根命中/未命中数；当前 `rootCacheHits` 始终为 0；默认垃圾入口不再准备逐文件索引，`rootCacheValidation` 与 `subtreeCacheValidation` 保留为接近零的阶段边界。stdout 的既有报告格式不变。计时仅用于只读报告，不能与 `--trash` 或 `--clean-temp` 同用。`complete` 表示报告流程走到结尾，覆盖是否完整仍以报告 `status` 为准。阶段计时从 junk 命令分发开始，不包含前面的 CLI 启动；完整进程耗时由基准脚本单独测量。

先构建 `cargo build -p sweepx-cli --release`，再运行 `python3 scripts/benchmark-junk.py --build-label release --output /tmp/junk-benchmark.json`。脚本使用隔离状态目录，对比空 SweepX 缓存、热扫尝试和受控单文件变化，并核对候选及文件大小；`--root /absolute/project` 可测只读真实目录。它保留每次实际命中数，不把 OS 缓存等同 SweepX 缓存；小样本只汇报中位数。

兼容 library 的 macOS `SubtreeCacheProvider` 仍可共享一次 FSEvents 查询，各根按扫描前捕获的原游标判断变化，再以本批原生类型和长度确认文件。缺失历史或查询失败回到现场检查。普通报告不读取整根候选记录；TUI 独立读取历史预览。默认两个入口都不查询 FSEvents 或读写文件索引，稳定计时字段不会改名。

兼容历史查询收到完整历史标记后立即结束 run loop 等待。该标记只说明已投递历史，不能证明最近写入已进入日志；超时或历史缺口拒绝索引复用。这是一次性查询，尚无持续监听或事件触发局部重扫。

默认三平台垃圾入口关闭可选文件索引保留；逐文件逻辑聚合不再复制祖先路径列表。分类扫描保留的目录行、marker、覆盖和可选复用索引共享估算字节预算（默认整批 256 MiB、每根 128 MiB），不等同进程 RSS 上限。优先淘汰可重建索引，再为所需规则证据留空间；仍放不下时输出 `status=partial`，human 提示候选可能遗漏，不能把空列表当成没有垃圾。内置规则根据本次加载的 requiredParentMarkers 选择文件 marker；任意自定义评估器默认仍保留全部文件名。

进度日志也有保留上限；仅截断进度不会把完整扫描变成 partial。错误计数、取消和真实资源不足独立保留，现场会话继续收到可靠错误与终态。

逐文件缓存键必须能无损表示目录路径；无法转换成 UTF-8 的原生路径不存 covered-path/listing，后续现场观察，仍保留原生身份与规则 marker。display path 不作为执行或缓存键的替代凭据。

历史候选根记录与兼容 library 的 macOS 文件索引按根独立保存；默认垃圾入口只发布候选历史，不再按设备互相覆盖，也不因本次只请求其他根就删除旧缓存。受限缓存按最近读取的根整体淘汰：单文件最多 4 MiB、单根最多 8 MiB、受管文件合计最多 64 MiB、最多 256 个根；每次调用读取的编码数据最多 16 MiB，保留数据采用 128 MiB 估算预算，均不代表进程 RSS 上限。可选文件长度索引会截断，缺失条目现场检查；完整候选记录超限则不写入。缓存超限、旧 schema、身份/请求范围不匹配、链接或非私有存储均回到现场观察；写锁竞争仅放弃本次持久化，不阻塞报告。

兼容 macOS library 文件索引的变更历史查询最多接受 256 个绝对 UTF-8 根和 1 MiB 路径字节；应用保留的历史最多 65,536 条事件、16 MiB 估算字节（包括路径及 Vec 容量）。缺口、ID 回绕、挂载变化、无法无损解释的路径或预算耗尽会清空历史并拒绝文件索引复用。各根现在共享一份按路径去重的变更索引，保留最大事件游标；该索引占用磁盘缓存读取后剩余的 128 MiB 估算额度，自身最多 16 MiB，不再按根复制完整变更集合。这些额度均不是进程 RSS 上限。


项目规则的 JSON `executionPolicy` 只接受 `report_only` 或 `require_ownership_and_activity`；省略时采用后者，不继承旧的删除准入。通用 `dist/build/out/.next/.turbo` 及 Dart/SvelteKit 明确仅报告，Rust/Node/Python/Maven 则仍缺独占所有权和无活动的独立证明，因此当前所有项目候选均不能通过 `junk --trash`、TUI 或后台 worker 回收。名称、风险等级、完整覆盖、格式识别或 Git `ignored/high` 均不能替代这些证明。报告新增稳定 `executionPolicy` 字段，项目值为 `report_only` 或 `require_project_ownership_and_activity`；缓存恢复先为 `not_checked`，按本次规则重建，不保存旧准入。浏览器离线/应用状态使用 `require_user_data_selection`，并以 `user_data_requires_explicit_selection` 阻止普通垃圾批量回收及垃圾 TUI 删除；目录自身和递归汇总的覆盖也必须同时完整。需独立明确选择来源或路径。其他平台候选的 `native_revalidation_required` 仍须通过既有原生身份、覆盖与平台边界检查，并不自行提供执行权限。独立 `trash PATH` 的明确路径操作仍遵守其原有检查。

Dart 2.18.0/3.6.0 的真实生成样本覆盖单项目和共享 workspace；中文/空格成员路径的百分号 UTF-8 签名现可识别。无效或不支持的 URI 形式仍报告 unknown，配置中的 URI 不会被打开；recognized 也不能让共享根或混入个人文件的项目候选获得回收资格。


`cargoOutput.workspace` 现补充本次调用的工作区成员与默认选择：`isWorkspace`、`memberCount`、`defaultMemberCount`、`projectIsRoot`。有界原生读取支持 literal/glob 成员、raw exclude 前缀、显式 workspace 指针及传递路径依赖；共享既有 TOML 解析器，不执行 Cargo。全部输入在输出前再次检查身份、内容摘要与已枚举名称，失败保持 unknown/invalid，不返回截断成员集；非原子观察不证明构建有效。没有配置覆盖时，默认 `target` 属于解析后的工作区根或独立 package，来源分别为 `workspace_default` / `package_default`。声明路径只作为独立准入的配置输入，不扩展扫描范围，不获得回收权限；原始路径与成员名称不写入报告或缓存。Cargo home 支持候选父目录为 cwd 的相对路径、空值退回用户 home，以及原生确认不存在或非目录时回到默认输出；链接、拒绝、缺少可用 home 环境和不确定读取仍为 unknown。home 的相对输出基点保留 Cargo 的原始 parent 拼写，含点/父级的基点不做精确拼写匹配。include、自定义 cwd/CLI、系统用户目录回退、原生别名及输出对象等价仍需后续补齐；所有权与活动限制继续保留。

Linux/macOS/Windows 的垃圾 TUI 历史记录共享私有、无链接跟随的有界存储。根记录绑定实际规则字节、平台、设备/文件/mount 身份及嵌套根范围，链接祖先或缺失身份拒绝读取。历史首屏只用于展示，上次完整覆盖不证明当前完整；活动、Git 和删除许可必须重建。三平台仍重新遍历目录并观察当前文件长度，选中刷新可保存新子树并保留未选兄弟的旧展示，回放行全部标为历史；macOS 默认入口同样只合并候选历史，兼容 library 文件索引仍独立验证变化历史。缺失游标保持 `null`，不能视作 0；v9 根记录失效重建，macOS 文件索引 schema 不变。每根候选复制前受独立 4 MiB 保留数据估算限制，取消、不完整扫描和超额不覆盖旧记录；该限制不是 RSS 上限。

Windows 状态目录的 owner/DACL 检查来自同一个已打开目录句柄，最终 reparse/offline/recall 对象拒绝。私有权限只接受能完整解释的普通 allow/deny 条目；陌生授权类型、损坏边界或读取失败不算私有。受控 owner 仍为 token user/owner，或本用户令牌确有 Administrators 组时的该组；SYSTEM/Administrators 的允许访问政策不变。每次令牌信息最多 256 KiB，SID 有界并按原生要求对齐，SDK 文本最多 32,767 个原生 UTF-16 单元，内嵌 NUL 拒绝。这些不是进程 RSS 或阻塞系统调用的硬期限；目录检查也不绑定后续路径操作。垃圾历史缓存与 legacy operation snapshot 已使用保留句柄接入；其他状态路径及完整执行路径竞态审计仍开放。

Windows 垃圾 TUI 现可读取历史首屏；读写、发布和缓存淘汰沿保留目录/文件句柄进行，复用受保护 DACL 与权限解释器，拒绝 reparse、offline/recall、远程设备、跨卷及多硬链接文件。仅支持普通绝对 drive 路径（含 verbatim drive），UNC/device 与未知文件系统回退现场扫描；这些记录仍是历史展示，没有 Linux/Windows 当前文件索引命中。各平台每缓存目录最多观察 4,096 条枚举项（含未知名称）；Windows 单页固定 64 KiB，零进度、截断和超额报缓存不可用，当前扫描继续。成功发布后沿用原磁盘淘汰额度；淘汰失败可能留下已发布代次，不保证崩溃耐久或进程 RSS。Windows 原生运行/MSVC/provider 验收仍待完成。

按域名清除：

```sh
sweepx site-storage --browser edge --profile Default --domain example.com --export-delete-plan /absolute/new-plan.json
```

SweepX 已内置扩展和本地通信组件，安装入口见 [`browser-extension`](#browser-extension)。仅安装 SweepX 时可扫描和导出计划；完成按域清除仍需在匹配的浏览器个人资料加载扩展。可以连接 SweepX 直接查看域名、存储键/bucket 和共享分类占用，也可不连接，直接指定精确网站；扩展不再提供计划文件导入。扩展只申请 `browsingData`、`nativeMessaging` 权限，无网络请求，不直接移走共享数据库。清理时选择数据范围、确认当前个人资料后点击「确认清理」，无需重复输入域名。清理范围、确认要求和验收边界见[扩展指南](../integrations/chromium-cleanup/README.md)。旧文件级回收参数保持拒绝。
