---
title: CLI 与只读扫描
---

# CLI 与只读扫描

当前 `sweepx` 是唯一的可执行入口。它提供 `scan`、`junk`、`explain`、`status`、`cancel`、`cache`、`cleaner`、`trash` 和 `capabilities`；`scan --tui` 在根目录准入后立即进入交互浏览，并在后台渐进扫描。

> [!CAUTION]
> `trash` 是 development preview：只移到系统回收站，默认确认并在提交前重验；没有 Permanent fallback。`plan`、`approve`、`execute`、Permanent 和 `--dangerously-delete` 仍只是路线图提案。

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

### P4a.2 资格记录不是新命令

协议现在能用 typed/validated 记录表达一个精确 capability/平台 tuple 及其 evidence。mutation 不使用宽泛的 delete 标记，而是分成 `trash.local.file`、`trash.local.directory`、`permanent.local.file`、`permanent.local.directory` 和 `permanent.local.link`。当前主机的两个 Trash cell 为 `degraded` preview；其余平台和全部 Permanent cell 仍为 `disabled`。

这些记录仍是失败关闭的 qualification registry substrate；`degraded` preview 不等于 `qualified`。`fixture_conformance_only`、`fake`、`stale`、`incomplete`、`placeholder` 或 `mismatched` evidence 永远不能使 mutation 合格。未来只有 current `real_os_qualification` evidence 完整匹配精确 tuple 时，对应单元才可能被标为 `qualified`。当前没有 `plan`/approval UI，也没有 Permanent adapter。

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
sweepx --format json junk .
sweepx --format json junk --system
```

显式根继续识别明确可重建的项目产物：Rust `target`、Node `node_modules`、Python `__pycache__/.pytest_cache/.mypy_cache/.ruff_cache`，以及常见 `dist/build/out/.next/.turbo`。不传显式根并加 `--system` 时，Linux 在绝对 `XDG_CACHE_HOME`（否则 `~/.cache`）下逐个报告应用缓存，macOS 在 `~/Library/Caches` 下逐个报告应用缓存，Windows 只在 `%LOCALAPPDATA%/Packages` 下识别深度为 2 的 `LocalCache` / `TempState`。`--system` 与显式根互斥。所有结果都只报告候选、规则 ID、风险、来源审阅日期、第一方依据和可回收估算，不自动删除；Linux 的 `/tmp`/`/var/tmp`、Windows 系统清理以及包管理器/容器共享存储尚未按目录名纳入。

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

```bash
cargo run -p sweepx-cli -- --locale zh-CN \
  scan --tui /absolute/path/to/root [/another/absolute/root]
cargo run -p sweepx-cli -- trash /absolute/path/to/item
```

TUI 直接消费本次 live scan 的 typed 结果，不要求中间 JSON。单根会自动进入；多根先展示虚拟根。`Enter` / `Right` / `l` 进入目录，`Esc` / `Backspace` / `Left` / `h` 返回，方向键或 `j`/`k` 移动，`d` / `Delete` 选择移到系统回收站，`q` 或 `Ctrl-C` 退出。回收站动作会先退出全屏，再要求确认并重验扫描身份；symlink 和 reparse point 不可操作。

`--tui` 要求 stdin/stdout 都是终端，并且不能与 `--format json|ndjson` 组合。TUI 只做 root admission 就进入界面，单根自动进入；当前层先展示，直接子目录的递归大小在后台扫描时约每 120 ms 以明确的下限值（`>=`）增量回填并重排，最终结果再收敛为 exact 或 incomplete，后代不作为列表行长期保存。进度通道容量为 1，慢终端只会丢弃已过时的中间快照，不会反压扫描。目录 detail rescan 以 single-flight 后台任务运行：30 秒是无进展 deadline，有有效增量时续期；导航或退出不会等待非协作 worker。

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

### 跨运行复用预览

只有在能够证明预览仍然成立时，它才有价值。扫描写入预览时，会在同一个 generation 内记录所覆盖各卷的
NTFS 变更日志位置。下次运行会重新读取该位置：若卷未发生变化，则预览描述的就是当前文件系统状态，扫描会
报告 `loadStatus: "verified_preview"` 而不是 `stale_preview`。

校验只会提升加载结果。没有记录证据、日志不可读，或卷确实发生了变化，都会保持原有行为并附带说明原因的
warning：

| Warning | 含义 |
|---|---|
| `cache.preview.unverified.no_evidence` | 存下的 generation 里没有任何证据，无从校验。未提权运行不会记录证据。 |
| `cache.preview.unverified.read_failed (N)` | 重读变更日志失败，`N` 是操作系统错误码。`5` 表示需要提权；`87` 表示 SweepX 传入了非法参数，属于需要上报的缺陷。 |
| `cache.preview.unverified.journal_must_rescan` | 日志明确表示所存区间已不再被覆盖。没有发生错误，只是证据过期了。 |
| `cache.preview.unverified.malformed_evidence` | 存下的证据结构上不可用。 |
| `cache.preview.unverified.unknown_kind (K)` | 证据声明的机制 `K` 是本次构建不认识的，通常是更新版本的 SweepX 写入的。 |
| `cache.preview.unverified.no_mechanism` | 本次构建在该平台上没有变更检测机制。 |
| `cache.preview.unverified.changed` | 卷自证据捕获以来确实发生了变化。 |

前缀之后的 code 是稳定的、可用于程序匹配；括号中的细节是附加信息，不属于 code 本身。复用还要求所覆盖的**每一个**卷都未变化，因为
半有效的预览会让一部分目录显示正确大小、另一部分显示过期大小，而整体看起来却是正确的。

预览要通过校验需同时满足两个条件。其一，读取日志需要与加速相同的提权卷句柄，因此未提权运行不会记录任何
证据，行为与该功能引入之前完全一致。其二，状态目录必须与被扫描的目录树位于**不同的卷**：写入缓存本身会
被记录到它所记录的那个卷的日志中，从而推进该卷的变更位置，使刚存下的证据当即过期。由于默认状态目录位于
`C:`，因此目前扫描 `C:` 无法通过校验，仍按 `stale_preview` 上报。证据
存储在带校验和的 generation payload 内，因此在磁盘上篡改 token 会使整个 generation 失效，而不会换来
一次虚假的 "unchanged"。

## 当前不存在的命令

```text
PROPOSED ONLY — NOT IMPLEMENTED
sweepx plan create ...
sweepx plan show ...
sweepx approve ...
sweepx execute ...
sweepx execute ... --dangerously-delete
```

P3 中有对应概念的 library model 与 fake execution tests，但仍没有 plan/approve/execute CLI 或 Permanent mutation。

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
