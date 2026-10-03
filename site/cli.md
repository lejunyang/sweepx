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

Linux 或 macOS 上从 scan 输出取得 `operationId` 后，可以查询对应的 terminal snapshot：

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

`junk --tui ROOT...` 实时显示扫描阶段、进度及已完整观察子树的基础垃圾候选；`junk --tui --system` 在后台自动发现保守的系统垃圾根，不能同时传显式根。默认按逻辑大小降序，`--sort path` 改为路径顺序；未知大小排在已知零字节之后，不当作零。方向键移动，Space 选择，`a` 全选（最多 256 项），`u` 清空，`r` 刷新所选或当前行（空视图重扫全部），`R` 刷新全部范围，`c` 取消，`d/Delete` 将目录候选移到系统回收站，`q/Esc` 退出。选择按稳定键保留；旧、不完整或回收失败的行标为历史证据，需要完整刷新后才能再次回收。回收在独立工作线程执行，逐项重验 no-follow、对象/filesystem/mount 身份；重要/保护目录拒绝，失败不永久删除。该模式要求终端，不能结合 `--timings`、`--trash`、`--clean-temp`或机器输出。`--quarantine-dir` 可与 Linux `--system --tui` 配合指定异文件系统私有恢复区。Linux/macOS/Windows 会先显示历史候选缓存（系统模式先发现范围），并在后台重新观察本次范围、解释当前 Git 证据；macOS 另有经现场类型和长度确认的文件索引复用。历史行不能回收，刷新缓存预览行会扫描全部范围，系统全量刷新会重新发现根。Linux/Windows 重新观察每个文件；该视图不写 operation journal。Linux 临时对象使用独立测量结果展示，逻辑字节与分配字节分开；普通 Trash 拒绝这些行，刷新会重扫系统范围，Linux 可按 `x` 对所选临时对象在后台生成完整隔离计划，输入 `clean <完整摘要>` 再按 Enter 确认；确认框不自动填充摘要。方向键/PageUp/PageDown 滚动计划，左右键查看长行，Esc 取消或关闭；移除中的取消等待结果，可留下部分源和完整恢复副本。界面保留恢复目录和失败原因，确认移动才移除行；父目录旧统计失效为历史，需刷新后才能再次操作。预览、执行与扫描/Trash 互斥，仍可使用独立的 `junk --system --clean-temp` 入口。选中目录刷新只递归所选子树，浅层枚举原生祖先所需的规则与 Git 标记，不进入无关兄弟子树；祖先旧统计标为历史，完整刷新后才能再次操作。macOS 局部刷新会写回新子树并保留经完整变更历史验证的兄弟文件索引；候选记录仅供历史预览，不能作整根命中。取消、不完整观察或历史缺口保留旧局部缓存代际；单个大根中，完整子树在自身和父目录 marker 枚举完毕后即可展示基础候选；Git 解释和完整终态仍继续，扫描中不能据此回收。

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

`--tui` 要求 stdin/stdout 都是终端，并且不能与 `--format json|ndjson` 组合。TUI 只做 root admission 就进入界面，单根自动进入；当前层先展示，直接子目录的递归大小在后台扫描时约每 120 ms 以明确的下限值（`>=`）增量回填并重排，最终结果再收敛为 exact 或 incomplete，后代不作为列表行长期保存。进度通道容量为 1，慢终端只会丢弃已过时的中间快照，不会反压扫描。目录 detail rescan 以 single-flight 后台任务运行：30 秒是无进展 deadline，有有效增量时续期；导航或退出不会等待非协作 worker。

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

## `site-storage`

按来源报告浏览器站点存储，让用户可以逐站点决定。只读：不删除任何内容，也不预选任何条目。

**刻意与 `junk` 分开**。junk 表示"可重建"；而这里是 R3 浏览器应用状态，风险分级将其归入*默认跳过/仅报告，
策略可允许逐项选中*。正是这份按来源的拆分让"逐项选中"成为可能 —— 没有它，用户唯一的选择就是全部清空、
丢掉所有登录态。

归因两个子系统，因为它们都是一个来源一个目录：

- `service_worker_cache_storage` —— 目录名是单向哈希，因此来源取自每个桶的 `index.txt`。它以纯 UTF-8
  存储，且前面紧跟自身长度；这正是把它与相邻字段中内嵌的 URL 区分开的依据：某个使用 Workbox 的站点会存入
  缓存名 `workbox-precache-v2-https://gamemap.app/`，其前置长度计的是整个名字，而不是其中那段 URL。
- `indexed_db` —— 来源就在目录名里。`.leveldb` 与 `.blob` 属于同一个来源，需要相加而不是分别计为两个。

报告的单位是**完整存储键**，不是主机名。Chromium 会按顶层站点对第三方存储分区，因此同一个主机可以持有多份
互不可见的数据；按主机名合并会把互不相关的各方呈现为同一行。

`fullyAttributed` 表示子系统之下的每一个字节是否都归属到了某个具名来源，采用精确比较。曾有 367 字节的差额
被解释为"浏览器运行中在两次遍历之间写入"并用容差掩盖过去 —— 而它实际上是解析器漏掉了一整个来源，因此这项
检查保持严格。

**Local Storage 被刻意排除在外。** 2026-09-05 实测，它的 303 个来源以多对多的方式共享 12 个 LevelDB 文件：
单个 2.3 MB 文件里有 61 个来源，`cn.bing.com` 跨 4 个文件，47 个来源跨越文件边界。没有任何文件边界与来源
边界对齐；把某个来源的记录字节相加也无法解决，因为 LevelDB 在 compaction 之前会保留被覆盖的旧版本与
tombstone。在那里给出任何按来源的体积都是编造，因此一律不报。

2026-09-05 在本机实测：Edge `Default` 的 CacheStorage 为 458.6 MB、12 个来源（仅 `onedrive.live.com`
就占 200.4 MB）；IndexedDB 为 276.6 MB、43 个来源（`www.bilibili.com` 236.1 MB，占该子系统 85%）。
### 删除单个来源的存储

`site-storage --trash-origin <STORAGE_KEY>` 会把该来源的存储移入回收站。每次调用只处理一个来源：R3
允许的是逐项选中，而不是批量。

存储键精确匹配，且不接受用主机名作简写，因为同一个主机可以拥有多份被分区、互相隔离的存储。若允许用
`example.com` 匹配 `https://example.com/^0https://other.test`，就会清掉用户并未指名的数据。

有三种拒绝发生在触碰任何东西之前，且都不改动文件系统：

- **未知存储键** —— exit 2，并说明匹配规则。
- **数据库正被占用** —— exit 3。LevelDB 用 `LOCK` 文件上的独占锁保护数据库；拿不到该锁就说明浏览器正打开
  着它。这不是理论上的顾虑：2026-09-05 实测，在 35 个 Edge 进程运行时，IndexedDB 目录**可以被成功重命名**，
  也就是说文件系统不会阻止这次移动，而浏览器会继续向一个目录已消失的句柄写入。探测必须以"不共享写"方式打开
  —— Rust 的默认共享模式在 43 个 Edge 目录中报出 0 个被占用，而独占打开报出 2 个。
- **人类可读格式下没有交互式终端** —— exit 2。

探测是逐目录而非逐浏览器的，因为 Chromium 只在站点需要时才打开数据库。无法判定锁状态的目录按"被占用"处理：
错误地拒绝一个本可删除的目录没有代价，而移走一个正在使用的数据库无法挽回。

一个来源可能拥有多个目录（IndexedDB 的 `.leveldb` 与 `.blob` 是分开的），而回收站不提供事务，因此会在移动
任何目录之前先检查全部；若中途失败，则以 `status: partial` 报告，并列出确实已移动的路径。partial 绝不会被
四舍五入成成功。

为此加强了 Windows 上的身份复校。原先 `same_file` 比较的是类型、长度和修改时间；而目录长度为 0、时间戳可写，
因此在同一路径上删除并重建的目录能同时满足这三项，却是另一个对象。现在身份取自 `FILE_ID_INFO`（与扫描器记录
身份的来源相同），并在每次移动前立即重新读取。

### 在 TUI 中按域浏览

`--browse` 把发现到的存储子系统目录交给已有的交互式浏览器，用户可以逐个域查看体积、并用 `d` / `Delete` 键把单个域移入回收站。

```
sweepx site-storage --browse
```

行走的是普通扫描，而不是把报告里的条目重新拼成表格：交互式回收站的执行凭据来自扫描器提供的 native identity 与 locator，而数据模型明确禁止从展示路径反推这两个字段。

首屏列出的是各浏览器的子系统根目录（如 `IndexedDB`、`Service Worker\CacheStorage`），进入后才按需列出其下的各域目录。根目录行只保留足以互相区分的尾部路径段——四个子系统的深度并不相同，固定截取会让 Edge 与 Edge Dev 的 `CacheStorage` 渲染成同一行文本。

`--browse` 需要终端 stdin 与 stdout，且不能与 `--format json` / `--format ndjson` 或 `--trash-origin` 同时使用。

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

macOS 的 `junk` 文件索引集中查询 FSEvents；游标在扫描前记录，扫描中的变化保留给后续校验。事件通知可能延迟，空历史不证明整棵树未变，所以当前候选始终来自现场遍历。根记录仅作历史展示，不完整扫描不覆盖原完整记录；旧 schema 冷扫重建。

历史候选记录绑定规则字节、平台、根身份和嵌套根范围，不接受为当前整根命中。每次报告重新发现所需上下文并现场分类；文件长度索引独立校验，分类上下文变化不会单独使它失效。

`junk --system` 的根发现、分类和工具安装清单共用本次调用的探测快照，扫描结束后不会重新启动一轮探测。整批工具调用预算为 10 秒，单次最多 2 秒、stdout 最多 64 KiB，最多尝试启动 64 个进程；超时、取消、输出过量或工具不可用时保留 unknown，安装信息的缺失字段为 null。显式项目根扫描不探测无关的 npm 安装。

工具缓存根、浏览器和已知缓存位置共用本次有界布局发现快照，版本目录展开和分片指纹检查也计入共享预算；分类不再逐候选枚举或解析路径。默认限制为 4,096 个目录探测、16,384 条返回枚举记录、1,024 个规则根引用和 8 MiB 保留估算；5 秒期限及取消在原生调用之间检查，不能中断阻塞的 OS 访问。缺少 anchor、权限/观察失败或资源不足时，`layoutDiscovery.complete` 为 false，`incompleteReason` 给出稳定原因代码；总体报告 partial、退出码 4。已确认候选仍可显示，空列表不证明没有垃圾；本次不完整分类不写整根候选缓存。非交互清理/Trash 请求在发现前拒绝。 工具根的身份及变化指纹绑定本次扫描事实；精确分片数需要完整枚举和 no-follow 目录检查，链接或截断不能建立匹配。活动关系和旧格式提示由本次原生快照解释，不提供删除权；单路径超过 64 KiB 时拒绝布局准入。

每个根的目录都会重新枚举，重建本次扫描身份和分类标记；文件缓存仅在原生枚举确认普通文件类型与相同长度后复用逻辑长度，缺失的物理分配、硬链接去重及可释放空间保持 unknown。不会通过复用旧候选来跳过整棵子树。

`junk --timings` 在 stderr 输出一条 `sweepx.junk.timings/v1` JSON，包含发现、准备、根缓存验证、逐文件缓存验证、遍历、候选拼装、Git 证据、缓存写入和报告阶段的纳秒耗时，以及实际根命中/未命中数；当前 `rootCacheHits` 始终为 0，根未命中不表示没有使用逐文件索引。stdout 的既有报告格式不变。计时仅用于只读报告，不能与 `--trash` 或 `--clean-temp` 同用。`complete` 表示报告流程走到结尾，覆盖是否完整仍以报告 `status` 为准。阶段计时从 junk 命令分发开始，不包含前面的 CLI 启动；完整进程耗时由基准脚本单独测量。

先构建 `cargo build -p sweepx-cli --release`，再运行 `python3 scripts/benchmark-junk.py --build-label release --output /tmp/junk-benchmark.json`。脚本使用隔离状态目录，对比空 SweepX 缓存、热扫尝试和受控单文件变化，并核对候选及文件大小；`--root /absolute/project` 可测只读真实目录。它保留每次实际命中数，不把 OS 缓存等同 SweepX 缓存；小样本只汇报中位数。

macOS 的逐文件索引共享一次覆盖已读索引根的 FSEvents 历史查询，各根按原游标判断变化；缺失历史或查询失败仍回到现场观察。普通报告不读取整根候选记录，TUI 独立读取历史预览。`rootCacheValidation` 保留原机器字段名，现计量文件索引准备；`subtreeCacheValidation` 保留为零附近的阶段边界。

历史查询收到完整历史标记后立即结束 run loop 等待。该标记只说明已投递的历史，不能证明最近写入已进入日志；文件索引仍须现场类型和长度确认，超时或历史缺口拒绝索引复用。

分类扫描保留的目录行、marker、覆盖和可选复用索引共享估算字节预算（默认整批 256 MiB、每根 128 MiB），不等同进程 RSS 上限。优先淘汰可重建索引，再为所需规则证据留空间；仍放不下时输出 `status=partial`，human 提示候选可能遗漏，不能把空列表当成没有垃圾。内置规则根据本次加载的 requiredParentMarkers 选择文件 marker；任意自定义评估器默认仍保留全部文件名。

进度日志也有保留上限；仅截断进度不会把完整扫描变成 partial。错误计数、取消和真实资源不足独立保留，现场会话继续收到可靠错误与终态。

逐文件缓存键必须能无损表示目录路径；无法转换成 UTF-8 的原生路径不存 covered-path/listing，后续现场观察，仍保留原生身份与规则 marker。display path 不作为执行或缓存键的替代凭据。

macOS 垃圾缓存的根记录和逐文件索引现在按根独立保存，不再按设备互相覆盖，也不因本次只请求其他根就删除旧缓存。受限缓存按最近读取的根整体淘汰：单文件最多 4 MiB、单根最多 8 MiB、受管文件合计最多 64 MiB、最多 256 个根；每次调用读取的编码数据最多 16 MiB，保留数据采用 128 MiB 估算预算，均不代表进程 RSS 上限。可选文件长度索引会截断，缺失条目现场检查；完整候选记录超限则不写入。缓存超限、旧 schema、身份/请求范围不匹配、链接或非私有存储均回到现场观察；写锁竞争仅放弃本次持久化，不阻塞报告。

macOS 变更历史查询最多接受 256 个绝对 UTF-8 根和 1 MiB 路径字节；应用保留的历史最多 65,536 条事件、16 MiB 估算字节（包括路径及 Vec 容量）。缺口、ID 回绕、挂载变化、无法无损解释的路径或预算耗尽会清空历史并拒绝文件索引复用。各根现在共享一份按路径去重的变更索引，保留最大事件游标；该索引占用磁盘缓存读取后剩余的 128 MiB 估算额度，自身最多 16 MiB，不再按根复制完整变更集合。这些额度均不是进程 RSS 上限。


项目规则的 JSON `executionPolicy` 只接受 `report_only` 或 `require_ownership_and_activity`；省略时采用后者，不继承旧的删除准入。通用 `dist/build/out/.next/.turbo` 及 Dart/SvelteKit 明确仅报告，Rust/Node/Python/Maven 则仍缺独占所有权和无活动的独立证明，因此当前所有项目候选均不能通过 `junk --trash`、TUI 或后台 worker 回收。名称、风险等级、完整覆盖、格式识别或 Git `ignored/high` 均不能替代这些证明。报告新增稳定 `executionPolicy` 字段，项目值为 `report_only` 或 `require_project_ownership_and_activity`；缓存恢复先为 `not_checked`，按本次规则重建，不保存旧准入。平台候选的 `native_revalidation_required` 仍须通过既有原生身份、覆盖与平台边界检查，并不自行提供执行权限。独立 `trash PATH` 的明确路径操作仍遵守其原有检查。

Dart 2.18.0/3.6.0 的真实生成样本覆盖单项目和共享 workspace；中文/空格成员路径的百分号 UTF-8 签名现可识别。无效或不支持的 URI 形式仍报告 unknown，配置中的 URI 不会被打开；recognized 也不能让共享根或混入个人文件的项目候选获得回收资格。


`cargoOutput.workspace` 现补充本次调用的工作区成员与默认选择：`isWorkspace`、`memberCount`、`defaultMemberCount`、`projectIsRoot`。有界原生读取支持 literal/glob 成员、raw exclude 前缀、显式 workspace 指针及传递路径依赖；共享既有 TOML 解析器，不执行 Cargo。全部输入在输出前再次检查身份、内容摘要与已枚举名称，失败保持 unknown/invalid，不返回截断成员集；非原子观察不证明构建有效。没有配置覆盖时，默认 `target` 属于解析后的工作区根或独立 package，来源分别为 `workspace_default` / `package_default`。声明路径只作为独立准入的配置输入，不扩展扫描范围，不获得回收权限；原始路径与成员名称不写入报告或缓存。Cargo home 支持候选父目录为 cwd 的相对路径、空值退回用户 home，以及原生确认不存在或非目录时回到默认输出；链接、拒绝、缺少可用 home 环境和不确定读取仍为 unknown。home 的相对输出基点保留 Cargo 的原始 parent 拼写，含点/父级的基点不做精确拼写匹配。include、自定义 cwd/CLI、系统用户目录回退、原生别名及输出对象等价仍需后续补齐；所有权与活动限制继续保留。

Linux/macOS/Windows 的垃圾 TUI 历史记录共享私有、无链接跟随的有界存储。根记录绑定实际规则字节、平台、设备/文件/mount 身份及嵌套根范围，链接祖先或缺失身份拒绝读取。历史首屏只用于展示，上次完整覆盖不证明当前完整；活动、Git 和删除许可必须重建。Linux/Windows 仍重新扫描全部文件，选中刷新可保存新子树并保留未选兄弟的旧展示，回放行全部标为历史；macOS 文件索引仍独立验证变化历史。缺失游标保持 `null`，不能视作 0；v9 根记录失效重建，macOS 文件索引 schema 不变。每根候选复制前受独立 4 MiB 保留数据估算限制，取消、不完整扫描和超额不覆盖旧记录；该限制不是 RSS 上限。

Windows 状态目录的 owner/DACL 检查来自同一个已打开目录句柄，最终 reparse/offline/recall 对象拒绝。私有权限只接受能完整解释的普通 allow/deny 条目；陌生授权类型、损坏边界或读取失败不算私有。受控 owner 仍为 token user/owner，或本用户令牌确有 Administrators 组时的该组；SYSTEM/Administrators 的允许访问政策不变。每次令牌信息最多 256 KiB，SID 有界并按原生要求对齐，SDK 文本最多 32,767 个原生 UTF-16 单元，内嵌 NUL 拒绝。这些不是进程 RSS 或阻塞系统调用的硬期限；目录检查也不绑定后续路径操作。垃圾历史缓存已使用保留句柄接入；其他状态路径及完整执行路径竞态审计仍开放。

Windows 垃圾 TUI 现可读取历史首屏；读写、发布和缓存淘汰沿保留目录/文件句柄进行，复用受保护 DACL 与权限解释器，拒绝 reparse、offline/recall、远程设备、跨卷及多硬链接文件。仅支持普通绝对 drive 路径（含 verbatim drive），UNC/device 与未知文件系统回退现场扫描；这些记录仍是历史展示，没有 Linux/Windows 当前文件索引命中。各平台每缓存目录最多观察 4,096 条枚举项（含未知名称）；Windows 单页固定 64 KiB，零进度、截断和超额报缓存不可用，当前扫描继续。成功发布后沿用原磁盘淘汰额度；淘汰失败可能留下已发布代次，不保证崩溃耐久或进程 RSS。Windows 原生运行/MSVC/provider 验收仍待完成。
