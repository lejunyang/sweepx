# 浏览器 Profile、站点存储与本地 AI 模型清理研究

> 调研快照：2026-08-26（PRC）。本文只描述只读发现、归因、快照与受控清理设计；本次调研未启动浏览器数据清理，也未修改任何 Profile、浏览器设置或企业策略。

## 1. 结论与安全边界

1. **先发现真实 Profile，再谈目录。** Chromium/Edge 优先读取 `chrome://version` / `edge://version` 的 `Profile Path`；Firefox 优先用 `about:profiles`；Safari 17+ 的 Profile 是由 Safari 管理的逻辑数据存储，不应只靠猜目录名。默认路径只是候选，channel、命令行、环境变量、企业策略和沙箱发行版都可能改写它。
2. **“按域名”必须升级为“按完整存储键”。** 现代浏览器会按顶层站点、嵌入 origin、容器/隐私属性或 bucket 再分区。同一 `example.com` 可以有多份互不可见的数据；反过来，一个应用也可能横跨 Service Worker、Cache Storage、IndexedDB 和 Local Storage。仅匹配目录名中的 hostname 会漏删、误删或破坏隐私隔离。
3. **HTTP/脚本编译缓存与站点应用状态分开处理。** HTTP cache、JS/Wasm code cache 通常可重建；Cache Storage（Cache API）则常是 PWA 离线状态的一部分，不能因为也叫 cache 就与 HTTP cache 等同。
4. **没有跨存储全局事务。** 即使单个 SQLite/LevelDB 副本可读，也不代表 Service Worker 注册、脚本、Cache Storage、IndexedDB、Local Storage 与 cookie 来自同一时点。备份/迁移时应把同一 Profile、完整分区键下的应用存储作为一致性组。
5. **运行中的 Profile 默认跳过。** 首选正常退出浏览器、用非侵入方式确认持锁进程/打开句柄消失，再复制完整的一致性组文件集合；其次是同一时间点的文件系统/卷快照。后者仍不等于跨 store 应用事务一致。不能满足时标记 `skipped_running_profile` 或 `potentially_inconsistent`，不得删除锁、repair、自动升级 schema 或把 best-effort 副本称为一致快照。
6. **Chrome/Edge 本地基础模型的受支持控制是专用策略，但 SweepX v1 只报告。** `GenAILocalFoundationalModelSettings = 1` 是厂商文档中的“阻止下载并删除现有模型”路径；SweepX v1 不设置它，只展示适用性与副作用。`ComponentUpdatesEnabled=false` 影响面过大，不作为 SweepX 建议或兜底。手删目录不是持久禁用方式，也不属于 SweepX action。

## 2. 证据口径与版本固定

本文采用以下等级：

- **A（公开契约）**：浏览器厂商支持文档、开发者文档、企业策略文档。可作为产品行为依据，但仍注明适用版本。
- **A-（当前源码）**：厂商官方源码或其官方 GitHub 镜像的固定 commit。可证明该快照的实现，不构成未来兼容承诺。
- **B（保守推导）**：由 A/A- 组合出的路径或产品推断，必须运行时验证。
- **未知**：没有足够官方证据；本文不会补成事实。

源码快照：

| 项目 | 固定版本 | 时间/用途 |
|---|---|---|
| Chromium | [`c551499a…`](https://chromium.googlesource.com/chromium/src/+/c551499a894d32bd04a882a0beae53d854e28ba2/) (`main@{#1685685}`) | 2026-08-25 17:10 UTC；存储路径与本地模型实现 |
| Firefox | [`dddd3ebf…`](https://github.com/mozilla-firefox/firefox/tree/dddd3ebf8c01bcbf38c5ba24812e9df1ea6fff8a) | 2026-08-25 12:59 UTC；QuotaManager/DOM 存储实现 |
| WebKit | [`0fdbfc2c…`](https://github.com/WebKit/WebKit/tree/0fdbfc2c77ce3e85884bef7b1a48fcfb7630c28f) | 2026-08-25 17:34 UTC；Safari/WebKit 数据存储实现 |

除链接内另有日期外，所有来源访问日期均为 **2026-08-26**。

## 3. Profile 发现与平台差异

### 3.1 Chromium 系（Chrome、Edge 及其他派生浏览器）

Chromium 官方文档说明：每个 Profile 是 User Data 根下的子目录（常见 `Default`、`Profile 1`，但名称不是契约）；运行实例的真实路径应从版本页读取。[C1]

| 平台 | Chrome Stable User Data 候选 | Chromium 候选 | Edge 候选 | Profile cache 根 |
|---|---|---|---|---|
| Windows | `%LOCALAPPDATA%\Google\Chrome\User Data` | `%LOCALAPPDATA%\Chromium\User Data` | `%LOCALAPPDATA%\Microsoft\Edge\User Data` | 与 Profile 目录相同 |
| macOS | `~/Library/Application Support/Google/Chrome` | `~/Library/Application Support/Chromium` | `~/Library/Application Support/Microsoft Edge` | `~/Library/Caches/<vendor>/<product>/<profile>` |
| Linux | `~/.config/google-chrome` | `~/.config/chromium` | 常见 `~/.config/microsoft-edge` | `~/.cache/<product>/<profile>` |

Edge 的 Windows 示例和 `edge://version` 来自 Microsoft 文档；表中 macOS/Linux Edge 根是 B 级候选，必须用目标实例验证。`UserDataDir` 策略可改写根目录。[E1]

发现顺序：

1. 版本页的 `Profile Path`；
2. 实际进程参数 `--user-data-dir`、`--profile-directory`；
3. 按 OS、品牌与 Stable/Beta/Dev/Canary/Testing channel 枚举；
4. 可将候选目录存在 `Preferences`、目录结构以及 `Local State` 中可识别条目作为启发式佐证；内部 schema 未识别时不解析、也不据此排除 Profile；
5. 派生浏览器只复用数据模型假设，产品根路径、加密绑定与迁移节奏另行验证。

Linux 还要处理 `CHROME_USER_DATA_DIR`、`CHROME_CONFIG_HOME`、`XDG_CONFIG_HOME` 和 `XDG_CACHE_HOME`。macOS/Linux 的 cache 根可能不在 User Data 下，因此只复制 Profile 会漏掉 HTTP/code cache。[C1]

**证据：A（默认根、版本页）；B（派生浏览器候选）。保守降级：** 无法验证 `Local State`/`Preferences` 或版本页时，仅报告候选，不进入清理集合。

### 3.2 Firefox

Firefox 桌面一个逻辑 Profile 可对应两个 leaf name 相同的目录：[F1]

| 平台 | Profile Root (`ProfD`，持久数据) | Profile Local (`ProfLD`，可重建缓存) |
|---|---|---|
| Windows | `%APPDATA%\Mozilla\Firefox\Profiles\<name>` | `%LOCALAPPDATA%\Mozilla\Firefox\Profiles\<name>` |
| macOS | `~/Library/Application Support/Firefox/Profiles/<name>` | `~/Library/Caches/Firefox/Profiles/<name>` |
| Linux | `~/.mozilla/firefox/<name>` | `~/.cache/mozilla/firefox/<name>` |

`profiles.ini` / `installs.ini` 位于 Profile 的配置根而不是具体 `<name>` 内：Windows `%APPDATA%\Mozilla\Firefox\`、macOS `~/Library/Application Support/Firefox/`、Linux `~/.mozilla/firefox/`。若 `ProfD` 不在默认 root，`ProfD` 与 `ProfLD` 可以是同一目录，不能机械构造一份镜像 cache 路径。[F1]

发现优先级为 `about:profiles` / `about:support` → `profiles.ini` 当前 `[Install<hash>] Default=...` → 保守枚举。`installs.ini` 自 Gecko 67 起是 install sections 的恢复备份，不是比 `profiles.ini` 更权威的实时来源；`-profile`、环境变量、MSIX、Snap、Flatpak、企业重定向还可产生未登记或非默认路径，其中 Flatpak 这里只是待按打包文档验证的候选，并非 [F1]/[F2] 已证明的固定路径。[F1][F2]

`profiles.ini` 在启动时读一次，写回前主要以 mtime/size 避免覆盖，仍有并发窗口。[F2] 运行中读取只能算带时间戳的一次观察，必须与活动实例报告交叉验证。

**证据：A。保守降级：** `IsRelative=0` 按绝对路径处理；无法关联 `ProfD`/`ProfLD` 时分别报告，不按最近修改时间猜活动 Profile。

### 3.3 Safari

桌面 Safari 的当前适用平台是 macOS。Apple 已停止 Windows 版 Safari（最终版 5.1.7，已过时），Linux 没有 Apple Safari；WebKitGTK/WPE 是不同 port，不能套用 Safari 路径。[S1][S2]

Safari Profiles 从 Safari 17 开始（随 macOS Sonoma，并通过当时更新提供给 Ventura/Monterey）。Apple 明确：历史、cookie、其他网站数据、Tab Groups 和收藏夹按 Profile 隔离；扩展安装共享但启用状态按 Profile；AutoFill、密码及部分安全/网站/隐私设置仍共享。删除非默认 Profile 会删除其历史、cookie 与网站数据但保留收藏夹；默认 Profile 不能删除。[S1][S3]

Profile 及其关联的书签、历史、Tab Groups 会在启用 Safari iCloud、登录同一 Apple Account 的 Safari 17+ 设备间同步；同一 Profile 的 iCloud Tabs 也可跨设备显示。[S1] Apple 的这项产品说明不证明 cookie 或底层网站存储目录逐文件同步，也不意味着“在一台设备删目录即可全设备持久清理”。跨设备目标必须另行核对 iCloud/各设备状态。

Safari 没有公开、稳定的“显示名 → 磁盘目录”契约。macOS 14/iOS 17 的公开 `WKWebsiteDataStore` API 支持 UUID 标识的多个持久 store，但它枚举/管理的是调用方应用自己的 store，并不是任意外部进程操作 Safari Profile 的 API；历史、书签和每站设置仍属于 Safari/client 自身数据。[S4] 当前 Cocoa WebKit 源码为 identifier-backed store 构造相对结构 `WebKit[/<bundle-or-process-id>]/WebsiteDataStore/<UUID>`；`NSLibraryDirectory` 由当前进程/container 上下文解析。外部工具必须运行时解析真实 container/home，不能简单拼接 `$HOME`。默认 store 没有 identifier，且没有公开证据把 Safari 可见名称映射到这些 UUID，故不能断言默认或其他 Safari Profile 就是某个 UUID 目录。[S5]

**证据：A（产品/Profile 语义、平台）；A-/B（identifier-backed WebKit store 实现）。保守降级：** 将 Safari Profiles 报告为 logical/unresolved；只允许 Safari UI 的 whole-profile/website-data 操作。除非目标 Safari/WebKit 版本适配器独立验证完整映射，否则拒绝 per-profile 文件级清理。

## 4. 站点存储布局

### 4.1 Chromium M154 开发主干快照布局

下表中 `<P>` 是 Profile 或非默认 StoragePartition 根，`<C>` 是对应 profile cache 根。它不是对当日 Chrome/Edge Stable 的直接断言；所有目录名均为 M154 主干实现而非外部稳定 API，目标稳定版必须按其完整版本对应源码再验证。[C2][C3][C4][C6][C7][C10]

| 类型 | 当前候选路径 | 归因与清理含义 |
|---|---|---|
| HTTP disk cache | `<C>/Cache`（部分 backend/版本可再有 `Cache_Data`） | Chrome 86 起由资源 URL 与 Network Isolation Key（top-level site + current-frame site）共同索引；不能只按 URL/hostname 精准删项；可重建且与 Cache API 不同 [C10][C13] |
| JS/Wasm code cache | `<C>/Code Cache` | 生成代码缓存、可重建；按实际目录探测，不依赖内部 backend 文件名 |
| Local Storage（LevelDB） | `<P>/Local Storage/leveldb` | 多个 `StorageKey` 共用 DB，不能按子目录删域名 |
| Local Storage（新后端） | `<P>/LocalStorage` | 2026 主干已有 LevelDB→SQLite rollout；两种布局都要探测 |
| IndexedDB（LevelDB） | first-party default bucket: `<P>/IndexedDB/<origin-id>.indexeddb.leveldb` + `.indexeddb.blob`; 分区 bucket: `<P>/WebStorage/<bucket-id>/IndexedDB/indexeddb.{leveldb,blob}` | `.indexeddb.blob` 是 LevelDB 布局；目录名/ID 是内部映射 |
| IndexedDB（SQLite rollout） | first-party default bucket: `<P>/IndexedDB/<origin-id>/<SHA256+Base32(db-name)>`; 分区 bucket: `<P>/WebStorage/<bucket-id>/IndexedDB/<hashed-db-name>` | M154 含 LevelDB/SQLite rollout；必须探测实际 backend，不能因无 `.leveldb` 判定为空 [C3][C11] |
| Service Worker 注册（legacy/default） | `<P>/Service Worker/Database` | LevelDB 元数据；不保证与 bucket 布局同时存在 |
| Service Worker 脚本（legacy/default） | `<P>/Service Worker/ScriptCache` | disk-cache backend |
| Cache Storage（legacy/default） | `<P>/Service Worker/CacheStorage` | PWA 应用数据，不能按 HTTP cache 清理 |
| M154 bucket 布局 | `<P>/WebStorage/<bucket-id>/{ScriptCache,CacheStorage,...}` | 当前常量/quota client 映射；`bucket-id` 不是域名，须读 metadata |

非默认 StoragePartition（扩展、app、`webview`、Isolated Web App 等）可位于 `<profile>/Storage/ext/<partition-domain>/def` 或 `.../<12-hex partition-name hash>`，并有自己的存储/cache 子树；hash 是当前 6-byte SHA-256 截断，不能反推原 partition name。只扫描 Profile 顶层会漏项。[C7]

旧 IndexedDB origin id 近似 `<scheme>_<host>_<port>`（默认端口常编码为 `0`），但 IPv6、`file:`、opaque origin 等有特殊规则，且该规则不能推广到现代 bucket。M154 `StorageKey` 序列化还可编码 top-level schemeful site、ancestor-chain bit、nonce、opaque top-level-site precursor 等；Chrome 的广义 Storage Partitioning 自 Chrome 115 面向所有用户启用。[C5][C8][C12] 因而可靠的机器身份必须是由匹配版本 parser 完整解析并保留的 serialized `StorageKey`，包括 origin、top-level schemeful site、ancestor-chain state，以及存在时的 nonce/opaque precursor，再结合 bucket 与实际 `StoragePartition` identity。`(origin, top-level site, bucket/partition)` 只能作为面向人的展示投影，不能当作唯一删除键。

### 4.2 Firefox 当前布局

普通网站持久状态主要在 `<ProfD>/storage/default/<origin-dir>/`；源码还定义 `permanent`、`temporary`、`private`、`archives`、`to-be-removed` 等 repository，不能把 Web `persist()` 简单理解成“移动到 permanent”。[F3]

| 类型 | 当前候选路径 | 归因与清理含义 |
|---|---|---|
| HTTP disk cache | `<ProfLD>/cache2/entries`; index 为 `index`, `index.log`, `index.tmp` | entry 文件名是 cache key 的 SHA-1 大写 hex；可重建 [F4] |
| DOM ScriptLoader 外部网页 JS bytecode/stencil cache | HTTP cache entry 的 alternate data | 当前此路径复用 HTTP cache，没有独立稳定目录；不代表 Service Worker 脚本、privileged JS 或所有 Wasm 派生缓存 [F5] |
| Firefox UI/startup cache | `<ProfLD>/startupCache/startupCache.<word-size>.<endian>` | 与网页 origin 无直接对应、构建相关、可重建；不要误当站点 JS cache [F6] |
| IndexedDB | `<ProfD>/storage/<persistence>/<origin>/idb/<encoded>.sqlite` + WAL/SHM/journal + `.files/` | DB 与外部 Blob/clone 文件是一个单元 [F7] |
| Local Storage | `.../<origin>/ls/data.sqlite` + journal/`usage`/`usage-journal` | 当前 LSNG 不用 WAL，但 journal/usage 状态仍须整体保留 [F8] |
| Service Worker 注册 | `<ProfD>/serviceworker.txt` | 当前格式版本 12；registrar 记录含 cache name/API id，但不自带完整脚本/Cache API body [F9] |
| Cache Storage | `.../<origin>/cache/` | DB、body/morgue、padding 等为一个逻辑单元 [F10] |

QuotaManager origin 目录用 `+` 编码 scheme/host/port，末尾还可有 `^key=value&...` 的 `OriginAttributes`。当前属性包括 `userContextId`、`privateBrowsingId`、`firstPartyDomain`、`geckoViewUserContextId`、`partitionKey`；同域的 Container Tabs 和不同 top site 分区不能合并。[F11][F12] Firefox 自 85 默认启用 Network Partitioning，自 103 默认启用 Dynamic State Partitioning；覆盖 Local Storage、DOM Cache、IndexedDB、Shared/Service Workers 等。[F13]

归因应优先读取 `.metadata-v2` 并用匹配版本的 parser 解析完整 origin + suffix。`<ProfD>/storage.sqlite` 是 QuotaManager 全局状态的一部分，完整快照应与整个 `storage/` 同时采集，但不能把它当唯一 origin 真相。未知 scheme、无效 suffix、migration 临时文件一律当 opaque，不强行归域。`private` repository 是版本相关的隐私态内部实现，默认只报告/跳过，不按普通持久站点数据导出。

Firefox 的 Service Worker 注册、脚本与 DOM Cache 有显式关联：保留 `serviceworker.txt` 时，不能把相应 origin 的 `cache/` 当普通可丢 cache；反之，仅复制 registrar 也不能恢复工作的 Service Worker。

### 4.3 identifier-backed Cocoa `WKWebsiteDataStore` 当前实现（不是 Safari Profile 的公开布局）

对当前 UUID-backed Cocoa store，源码可见 `Cookies/Cookies.binarycookies`、`NetworkCache`、`Origins` 以及用于旧布局/迁移的 `LocalStorage`、`IndexedDB`、`CacheStorage`、`ServiceWorkers` 等子路径。[S5] 下图仅表示 embedding app 的 identifier-backed 实现边界，不能直接等同于 Safari 的可见 Profile。现代 unified origin storage 的核心结构为：[S6][S7][S8][S9][S10]

```text
<website-data-store>/
├── Cookies/Cookies.binarycookies        # 私有、版本相关格式
├── NetworkCache/                       # HTTP/资源缓存，可重建
└── Origins/
    ├── salt                            # 必须与散列目录一起保存
    └── <hash(top-origin)>/
        └── <hash(client-origin)>/
            ├── origin                  # ClientOrigin 元数据（若存在）
            ├── LocalStorage/localstorage.sqlite3
            ├── IndexedDB/              # SQLite DB 及相关文件
            ├── CacheStorage/            # index/records/blobs/salt
            └── ServiceWorkers/          # 注册 DB + Scripts/V1
```

目录散列由“`Origins/salt` + serialized top origin/client origin”生成；缺少 salt 或 origin metadata 时，不能可靠从 hash 反推域名。第一方常为相同 top/client origin，嵌入第三方则双键分区。[S6]

WebKit 官方隐私说明确认：第三方 Service Worker、其 Cache Storage/IndexedDB，以及第三方 HTTP cache 都按第一方站点分区。[S11] 其 ITP 保留规则至少要区分两类：无 qualifying user interaction 时，脚本可写存储可能受 7 天上限；被分类为 tracking domain 的所有网站数据，在达到 30 天浏览器使用期间无 first-party interaction 且未获 storage access 的阈值后，由周期性清理执行删除。二者都不是通用于所有站点的单一“7 天规则”。Safari 17 又把 cookies、cache、service workers、Web Push 等按 Safari Profile 隔离。[S3]

顶层 `ServiceWorkers` 等 legacy/custom migration 输入与统一 `Origins/.../ServiceWorkers` 不能合并或独立删除；必须先确定实际 Safari/WebKit 版本与 active layout。

Safari/WebKit 没有可依赖的独立、公开“站点脚本编译缓存”文件系统契约。JavaScript 源响应属于 `NetworkCache`；若版本内部持久化派生代码，也应连同 HTTP cache 视作可重建、不按域迁移的内部数据，而不能虚构固定 `Code Cache` 路径。

## 5. 共享、分区与一致性限制

### 5.1 不同的“共享”层级

| 范围 | Chromium | Firefox | Safari |
|---|---|---|---|
| Profile 间站点状态 | 通常隔离；User Data 级组件另算 | `ProfD` 隔离；登记/选择信息在 config root | Safari 17 明确按 Profile 隔离网站数据；Profile 及关联书签、历史、Tab Groups 可经 iCloud 同步，但这不证明 cookie/本地 website-data 文件逐项同步 |
| 同 origin 的第三方嵌入 | 按 top-level site 等 `StorageKey` 分区 | 按 `partitionKey` 等 OriginAttributes 分区 | 按 `(top origin, client origin)` 分区 |
| HTTP cache | 已分区，且与 Cache API 分离 | Network Partitioning，自 Firefox 85 默认 | 第三方 HTTP cache 按第一方站点分区 |
| Service Worker / Cache API | 按 StorageKey/bucket；二者相关但不是同一 DB | 注册表与 per-origin Cache API 分离 | 同 origin 树下分开存放，第三方双键分区 |
| 浏览器级本地 AI 模型 | User Data/组件级，可跨多个 Profile 消费 | 本文不主张有同等组件 | Edge/Chrome 范畴；Safari 未纳入该模型结论 |

### 5.2 最小应用一致性组

针对一个完整存储键，迁移或精准清理至少联合考虑：

```text
Profile/store identity + partition key
├── cookies / authentication state（若任务包含会话）
├── Local Storage
├── IndexedDB（含 blob/外部文件/journal）
├── Service Worker registration + script body
└── Cache Storage metadata + response body/blob
```

HTTP cache、网页 JS/Wasm 编译缓存通常可排除并重建。不能把两个 top-site partition 扁平合并；也不能仅保留 `serviceworker.txt`/registration DB 而丢脚本与 Cache Storage。任何“仅按域清理”都应先让用户选择：仅第一方、某个明确分区，还是该 origin 的所有完整属性变体。

## 6. 运行中锁、只读快照与跳过策略

### 6.1 锁不是一致性快照

- Chromium 在 **User Data 根级**实施进程单例，而不是每个 `Default`/`Profile N` 各自的数据库一致性锁：Windows 使用 mutex/隐藏窗口及 `lockfile`；POSIX 根下使用 Unix socket、cookie 与常见 symlink 形态的 `SingletonLock`/`SingletonSocket`/`SingletonCookie`。[C9]
- Firefox 使用平台相关 OS file locking；Windows 常见 `parent.lock`，Linux 常见 `lock`/`.parentlock`，macOS 常见 `.parentlock`。这些名称只是诊断线索，stale 文件不等于活进程；外部工具必须有匹配目标平台/版本的锁适配器，不能对三个文件统一试锁。[F1][F14][F16]
- WebKit 内部在有活动页面或 network process 持有 store 时拒绝删除，并跟踪活动路径；这不是外部清理器可获得的 Safari lock API，也没有公开稳定的 Safari Profile 锁文件名。[S12]
- LevelDB 官方要求同一 DB 同时只由一个进程打开；SQLite 的 WAL/journal 是持久状态的一部分，单拷主 DB 可能丢已提交事务或损坏副本。[X1][X2][X3]

### 6.2 推荐算法（fail closed）

1. 只读记录浏览器品牌、完整版本、channel、实际 User Data/Profile/Local/cache 路径。
2. 请求正常退出；用进程/打开句柄及不创建、不删除、不替换锁文件的只读检查判断静止状态。不要调用会创建/清理 `Singleton*` 或向现有进程发通知的单例逻辑。Safari 只采用 Safari/`com.apple.WebKit.*` 进程与 open-file 证据；无法证明静止就返回 `skipped_running_profile`。
3. 静止后复制完整目标：Profile/store、外置 cache root（如需）、所有 SQLite `-wal`/`-shm`/journal、LevelDB `CURRENT`/`MANIFEST`/日志、Blob/body/script/salt/origin metadata。Firefox 的持久站点状态以 `ProfD` 为主；若声称包含 HTTP/startup cache，还须复制匹配的 `ProfLD`，完整 discovery 还须包含上级 config root 的 INI。三者可能跨卷。
4. 跨目录最好使用同一时间点的 APFS/VSS/LVM/btrfs/ZFS 等文件系统/卷快照。这比逐文件复制可恢复性更高，但若浏览器未静止，它通常只提供 crash/time-point consistency；没有浏览器 application writer 或跨 store 全局事务时，不得称应用级/逻辑原子一致。跨卷也不能宣称同一时点。只在快照副本上解析。
5. 在线采集只有两种可接受降级：同一时间点文件系统快照；或逐 DB 的 SQLite Online Backup。后者只能称“单 DB 逻辑副本”，不覆盖 Firefox IndexedDB `.files/`、DOM Cache body、Quota metadata 或 Service Worker registrar；带外部 Blob/body 的完整 store 仍应使用卷快照或跳过。
6. 检测到浏览器运行、锁冲突、缺失 WAL/MANIFEST、删除 marker、usage journal、无法解析的 schema/partition 时：跳过该 store，输出原因和覆盖范围；不删锁、不强杀、不 repair、不触发解析库迁移。
7. 逻辑清理优先把浏览器支持入口作为人类可审阅的建议。Safari 用自身的 Manage Website Data / Clear History / Manage Profiles UI；受控 WKWebView 应用只能用其自己的 `WKWebsiteDataStore` API，外部清理器不能假定该 API 可操作 Safari 私有 store。SweepX v1 对 IndexedDB、Local Storage、Cache Storage、Service Worker、cookie/session 等应用状态始终 report-only，不执行文件级清理；唯一 filesystem 例外是 first-party、版本适配、浏览器静止、manifest 完整的 whole HTTP/code/startup cache root，经 Core 计划与平台 Trash 处理。Safari 默认仍应跳过。

Mozilla 的官方手动备份说明明确要求完全关闭 Firefox。[F15] Apple 的 Safari UI 允许按网站移除网站数据，并提醒可能退出登录、改变网站行为，且删除 cookie/网站数据可能影响其他 app。[S13] 原始 Safari/WebKit 快照只允许恢复到已验证兼容的 schema 世代；CacheStorage、Service Worker 和 IndexedDB 都有版本/迁移状态，首次用新版本打开可能迁移数据并破坏回滚假设。

## 7. Chrome 与 Edge 本地模型

### 7.1 Chrome：识别、组件边界与迁移

Chrome 官方把 Prompt、Summarizer、Writer、Rewriter、Proofreader 等基础模型 API 与 Translator/Language Detector 的 expert models 区分；基础语言模型称 Gemini Nano。模型不是随安装包静态固定：未就绪时，API 使用流程（通常是满足条件的 `create()`）可能触发下载；新 Profile 启动后不久且 Gemini Nano scam detection 活跃时，`availability()` 有时也会触发下载，当前 Chromium 还存在受实验配置控制的后台下载路径。具体预取/触发时机受版本、rollout 和组件服务控制。更新为整模型下载并热切换，版本可在 `chrome://on-device-internals` 查看。[M1][M2]

这里必须区分两层：上段是 Chrome 公开产品/开发者契约；下述 Manifest Broker、默认 feature 与可调阈值是 **M154 主干实现快照**，不等于 2026-08-26 所有 Stable 客户端均已采用。

截至 Chromium M154 主干，旧/兼容组件与新 Manifest Broker 并存：[M3][M4][M5][M6]

| 对象 | 当前识别信息 | 相对 `DIR_COMPONENT_USER` 的边界 | 证据 |
|---|---|---|---|
| 旧/兼容基础模型 | `Optimization Guide On Device Model`; ID `fklghjjljmnfjoepjmlobpekiapffcja` | `OptGuideOnDeviceModel/<version>/` | A- |
| 模型清单（`manifest.binarypb`，不是权重载荷 ID） | `Optimization Guide On DeviceModels Manifest`; ID `ceofaddefefcbblgcgnibnonglccbfja` | `OptimizationGuideModelsManifest/<version>/` | A- |
| 新架构资产 | ID 由清单中的公钥计算；名称/组合动态 | 通常 `OptGuideManifestModel/<public-key-hex>/<version>/` | A- |
| 普通 Optimization Guide 预测模型 | 与基础 LLM 不同 | `OptimizationGuidePredictionModels` | A- |

旧载荷至少校验 `weights.bin` 与 `on_device_model_execution_config.pb`；可再有运行 cache。当前源码把 `DIR_COMPONENT_USER` 注册到 User Data 根，这是 A- 级源码事实；由此组合默认 OS 根得到以下 B 级候选：

- Windows：`%LOCALAPPDATA%\Google\Chrome\User Data\{OptGuideOnDeviceModel,OptimizationGuideModelsManifest,OptGuideManifestModel}`
- macOS：`~/Library/Application Support/Google/Chrome/{OptGuideOnDeviceModel,OptimizationGuideModelsManifest,OptGuideManifestModel}`
- Linux：`~/.config/google-chrome/{OptGuideOnDeviceModel,OptimizationGuideModelsManifest,OptGuideManifestModel}`

这些是 **B 级组合推导**，会被 branding/channel/`--user-data-dir` 改写；实际位置、模型名、版本和体积以 `chrome://on-device-internals` 为准。“固定约 4 GB”不是契约。新架构已在 2026-08-04 的主干提交中默认启用，旧 `optimization-guide-on-device-model` flag 于 2026-08-19 因 M150 到期移除；因此不能依赖旧 flag 或固定单一 ID 做长期发现。[M6]

Chrome 官方在 2025-10-21 的自动模型生命周期文档说明：模型可因磁盘压力、企业策略禁用或连续 30 天不再满足资格而被 purge；可能在运行 session 中消失；该自动 purge 场景中，基础模型 purge 后相关 LoRA 有 30 天 grace period。[M2] 这不能无条件推广到策略禁用或新 Manifest Broker 的手动 `Uninstall Models`，其辅助资产清理范围要按目标版本验证。官方当前开发要求页面列出：Windows 10/11、macOS 13+、Linux 或满足版本要求的 Chromebook Plus；Profile 所在卷至少 22 GB 空闲；GPU 严格大于 4 GB VRAM，或 CPU 至少 16 GB RAM/4 核；首次下载需非计量连接；低于 10 GB 可用空间时模型会被移除。[M1] 这些阈值与主干 Finch 可调常量可能不同，应按目标 Chrome 版本和内部页实测。

### 7.2 Edge：产品边界

Microsoft 官方 Prompt API（开发预览）说明：[E2]

- Edge Canary/Dev 138.0.3309.2 起使用 Phi-4-mini；150.0.4070 起可选择预发布 Aion-1.0-Instruct。
- 模型首次调用时下载、跨网站共享、下载后可离线；Phi 预览要求 Windows 10/11 或 macOS 13.3+、至少 20 GB 空闲、5.5 GB VRAM、非计量网络，低于 10 GB 空闲会删除。
- “built into Edge” 不代表权重随安装包静态内置，因为同页明确有初次下载。

Microsoft **没有公开承诺** Edge 的公钥、component ID、payload 或根路径与 Chrome 完全相同。下列只是由 Chromium 上游组件架构与 Edge 默认 User Data 根组合出的 B 级检查候选，不是保证存在、采用相同 ID，或由 Edge 策略全部删除的目录：

```text
<Edge User Data>/OptGuideOnDeviceModel/
<Edge User Data>/OptimizationGuideModelsManifest/
<Edge User Data>/OptGuideManifestModel/
```

Windows 候选根为 `%LOCALAPPDATA%\Microsoft\Edge\User Data`；macOS 为 `~/Library/Application Support/Microsoft Edge`；Linux 常见 `~/.config/microsoft-edge`，但专用模型策略未列 Linux 支持。若目标 build 存在 `edge://on-device-internals`，可用它查看当前暴露的 path/version/size；这是内部诊断面，可能不存在或不展示所有 manifest-broker assets，不能当 Microsoft 支持的稳定接口，也不能把 Chrome ID 套给 Edge。

### 7.3 厂商支持的清理与禁用路径（SweepX v1 仅报告）

Chrome 官方策略数据与 Edge 官方策略页对同名策略都给出清晰语义：[M7][E3]

```text
GenAILocalFoundationalModelSettings = 1  # Disabled / Disallowed
```

- 值 `0` 或未设置：允许浏览器自动管理、下载并本地推理；这不保证启动即下载。Chrome 当前实现还受使用、硬件、磁盘、网络、电源与 rollout 影响；Edge 官方材料直接确认使用、硬件、磁盘和网络条件，不能把上游的电源/field-trial 细节当 Edge 契约。
- 值 `1`：不下载，且删除已经下载的“基础 GenAI 模型”。官方措辞不承诺清除每个 manifest、adaptation、expert、cache 或 prediction asset，须分别枚举验证。
- 动态刷新；非 per-profile。
- Chrome 支持 `chrome.*` M124+、Android M142+、ChromeOS M149+。
- Edge 支持 Windows/macOS 132+、Android 147+；iOS 不支持；官方列表没有 Linux。

以下是对厂商管理文档的**事实性操作顺序说明**，供组织管理员在 SweepX 之外评估；SweepX v1 不执行、自动化或请求这些策略变更：

1. 按产品/平台使用官方管理面：Chrome 使用官方 ADMX、macOS managed preference 或 Linux managed policy JSON；Edge 使用其文档支持的 Windows ADMX、macOS managed preference、Android managed app configuration。Edge 的该专用策略未列 Linux 支持。不要写内部 `Local State` pref。
2. 在 `chrome://policy` / `edge://policy` reload 并确认值、scope 与无错误状态。
3. 等动态卸载；Chrome 用 `chrome://on-device-internals` 验证状态、路径和体积；Edge 仅在目标 build 存在对应内部页时把它作为附加验证，并另查磁盘候选。
4. 若文件仍被模型服务占用，再完全退出浏览器并复查。

Windows 的管理根分别是 `SOFTWARE\Policies\Google\Chrome` 与 `SOFTWARE\Policies\Microsoft\Edge`，值类型 `REG_DWORD=1`；macOS 用同名 managed preference integer。本文不给出执行命令，以避免把研究误当成授权变更。

当前 Chromium 内部页有两条版本相关路径：legacy `Uninstall` 调用 `ForceUninstall()`；新 Manifest Broker 的 `Uninstall Models` 会清 usage 并让 asset manager 卸载 ledger 中跟踪的模型资产。两者都走 component uninstaller，而不是裸删目录，并有短暂延迟供消费者释放。[M4][M8] 仅在目标 build 确实提供且操作成功时才优先于人工删文件；它仍是一次性诊断清理，策略允许且功能再次需要时会重下，且不是 Microsoft 承诺的 Edge 管理接口。

手工删除不是官方支持的正常清理路径，且不是 SweepX v1 的恢复或清理动作。产品只报告 live path、版本、大小、厂商策略/内部页能力与副作用，不生成模型目录删除计划。裸删可能重新下载、误删非基础模型资产，或让组件注册状态与磁盘不一致；整个 User Data、`OptimizationGuidePredictionModels` 和 manifest 均不得作为替代目标。

### 7.4 企业策略副作用

| 控制 | 作用 | 副作用/限制 |
|---|---|---|
| `GenAILocalFoundationalModelSettings=1` | 阻止并删除本地基础模型 | 依赖该共享模型的能力不可用或降级；当前 Chromium 源码消费者候选还包括 Compose、History Search/Query Intent、Scam Detection、Permissions AI、部分设备端语音识别等，但产品启用与 cloud fallback 依版本/rollout；不代表所有云端 AI 都关闭；策略不承诺清除所有其他 expert/prediction assets [M9] |
| `ComponentUpdatesEnabled=false` | 桌面也会阻止模型组件后续下载/更新 | 不承诺立即删除现有模型；同时停止大量非豁免浏览器组件更新并可能延误修复；Chrome/Edge 保留部分安全关键、非可执行组件例外；策略非动态刷新，通常需重启受管实例后验证，非 AI 专用 [M7][E4] |
| 内部页 Uninstall | 释放现有模型空间 | 非持久禁用，可重下；UI 随版本变化 |
| flags / 手删 / ACL / 防火墙 | 非支持或仅开发调试 | 会漂移、可重下、可能破坏组件更新或误删；不得作为默认方案 |

Chrome 的 `GeminiSettings` 和 `GenAiDefaultSettings` 控制其他产品/默认能力，不等价于专用策略“阻止并删除本地基础模型”；不要互相替代。Edge/Chrome 的完整消费者清单与云端 fallback 均会 rollout，未知项应标记未知。

## 8. 清理器实现建议

一个保守实现应把流程固化为：

```text
discover
  -> record exact browser/version/channel/profile roots
  -> verify profile/store identity
  -> detect owning processes + inspect lock ownership without mutation
  -> take a same-time, recoverable file-set snapshot
  -> decode full storage key with versioned adapter
  -> plan and preview affected stores/partitions/bytes
  -> require explicit scope for mutation
  -> prefer browser-supported deletion API/UI/policy
  -> verify absence and report skipped/unknown items
```

最低保障：

- 每次运行记录浏览器完整版本、源码适配版本、Profile 路径、采集时间、浏览器运行态和快照方法。
- 同时识别 legacy 与新 bucket/unified 布局；用文件 magic/schema 和 metadata 验证，不能只看目录名。
- 未知版本只做原始归档/报告，返回 `unsupported_layout`，不把解析失败当作“0 字节/无数据”。
- 预览中展示完整 origin、top-level site、container/partition/bucket 和每种存储类型；默认不把不同分区合并。
- HTTP/code/startup cache 可单列为“可重建”；Cache Storage、IndexedDB、Local Storage、Service Worker 列为“应用状态”。
- 删除后若浏览器仍允许组件或站点重新生成，应明确标注“可重建/可能重下”，不能承诺永久释放空间。

## 8.5 Windows 真机实测：按域归因的可行性与边界（2026-09-05）

本节是本机 Edge / Edge Dev / Chrome 的直接测量，用于回答“能否把站点存储按域呈现给用户、由用户自行选择清理”。
测量对象是本人日常使用的 Profile，不是新建的干净 Profile。

### 8.5.1 体量分布：不可清理的部分才是大头

Edge `Default`（Edge 运行中，33 个进程）：

| 子系统 | 体积 | 官方定位 |
| --- | --- | --- |
| Service Worker / CacheStorage | **458.0 MB** | PWA 离线状态，**不是** HTTP cache |
| Cache（HTTP） | 345.7 MB | 可重建 |
| Code Cache | 305.3 MB | 可重建 |
| IndexedDB | 277.7 MB | 站点应用数据 |
| Local Extension Settings | 52.3 MB | 扩展状态 |
| Local Storage | 20.7 MB | 站点应用数据 |

`CacheStorage + IndexedDB = 735.7 MB`，**超过** `Cache + Code Cache = 651.0 MB`。这证实了只清可重建缓存
会放过一多半占用；而这部分恰恰是第 1 节要求整体保留、不能按 HTTP cache 处理的内容。结论不是“可以清”，
而是“必须能按域告知用户，由用户自己决定”。

### 8.5.2 归因可行性：三类子系统的结论完全不同

| 子系统 | origin 从何而来 | 能否得到**每域体积** | 是否需读被锁文件 |
| --- | --- | --- | --- |
| CacheStorage | 每个哈希目录下的 `index.txt` | **能**，一目录一 origin，体积=目录体积 | 否 |
| IndexedDB | **目录名本身**（`https_www.bilibili.com_0.indexeddb.*`） | **能**，同上 | 否 |
| Local Storage | 共享 LevelDB 的记录键 | **不能**，仅能得到域清单 | 是（`.log` 被独占） |

CacheStorage 的哈希目录名不可逆（上游 README 明确为 origin 的哈希），因此 `index.txt` 是唯一途径；
origin 在其中以 **UTF-8** 明文存储（首次记录为 UTF-16LE 是错的：文件里确实有 UTF-16 片段，但那是哈希的
十六进制字符串，不是 origin）。每个 `index.txt` 中 origin 恰好出现 2 次、且只有 1 个唯一值，无分区后缀。
匹配模式必须 scheme 无关：本机有一个 `chrome-extension://` 的键，只匹配 `https?` 会漏掉它。
实测 Edge 12/12、Edge Dev 6/6 全部解析成功，**0 未解析**。

交叉验证（归因求和 vs 独立目录遍历）：Edge `458.2 MB = 458.2 MB`，Edge Dev `36.8 MB = 36.8 MB`，两者一致。
这条对照是必要的：只统计已解析目录会在解析失败时静默少报，而少报看起来和精确值一样。

按域归因后的实际分布（Edge CacheStorage）：`onedrive.live.com` 200.35 MB、`www.yuque.com` 105.69 MB、
`www.msn.cn` 79.74 MB（新标签页内容）。IndexedDB 侧 `www.bilibili.com` 单域 236.08 MB，占该子系统 85%。
这正是按域呈现的价值：用户可以清掉 `msn.cn` 而保留 OneDrive 和飞书，而“清空站点数据”会一起毁掉登录态。

Local Storage 是反例：319 个域共处一个 LevelDB，键里有域但**体积不可切分**。对它只能报告“存在哪些域”，
不能报告每域占用；把总量按域均摊或按键数比例估算都是编造，不做。

### 8.5.3 两套布局并存，且 bucket-id 不是域名

本机同时存在 legacy 路径与 `WebStorage/<bucket-id>/` bucket 布局（第 4.1 节 M154 行所述）。Edge 有 2 个
bucket、合计 0.2 MB，主体仍在 legacy；Chrome 只有 `WebStorage/QuotaManager` 而无 legacy 子目录。
枚举必须同时覆盖两套，否则要么漏算要么重复计算。

`WebStorage/QuotaManager`（SQLite，160 KB）是 bucket-id → 存储键的唯一映射。它在浏览器运行时**可读**：
以 `FileShare.ReadWrite | Delete` 共享打开即可，独占打开则失败。第 6.1 节“锁不是一致性快照”仍然成立 ——
可读不等于可信，读到的是运行中状态，只应作为**报告**依据，不作为删除授权。

### 8.5.4 归因单位必须是完整存储键，不能是 hostname

`QuotaManager` 中的键形如：

```text
https://www.googletagmanager.com/^0https://codacy.com_default
    └─ 嵌入 origin ─┘        └分区┘└─ 顶层站点 ─┘└bucket┘
```

实测到 3 组分区键：`googletagmanager.com` under `codacy.com`、`doubao.com` under `larkoffice.com`、
`doubleclick.net` under `nexusmods.com`。这印证第 1 节第 2 条：同一 host 既可作为第一方 origin 存在，
也可作为第三方在多个顶层站点下各存一份互不可见的数据。**按 hostname 合并会删掉用户并未选择清理的隔离数据。**

首次用正则抓取时漏掉了 `^0` 分隔符，把上述键读成了一个名为 `codacy.comwww.googletagmanager.com` 的域。
这不是显示瑕疵：若以此为单位归因，两个不同主体的数据会被并成一条呈现给用户。分区分隔符必须显式解析。

### 8.5.5 由此得出的实现边界

1. 归因单位是**完整存储键**（origin + 顶层站点分区 + bucket），呈现时可按顶层站点分组，但内部不得合并。
2. 只报告**能独立求和**的子系统的每域体积（CacheStorage、IndexedDB）；Local Storage 只报告域清单，
   并显式标注体积不可分。
3. 每次归因都必须与独立目录遍历对账；不一致时先查原因，不得调整对照口径。
4. 浏览器运行中只做报告。任何删除都需要第 6.2 节的进程停止证据，与本节的可读性无关。
5. CacheStorage 与 IndexedDB 属站点应用状态，即使按域呈现，也应与可重建的 HTTP/Code Cache 分开标注，
   不能因为目录名含 cache 就归为可弃。
## 9. 来源索引

### Chromium / Chrome

- **[C1]** [Chromium User Data Directory](https://github.com/chromium/chromium/blob/c551499a894d32bd04a882a0beae53d854e28ba2/docs/user_data_dir.md#current-location) — A/A-；默认路径、版本页、cache 根及覆盖项。
- **[C2]** [DOM storage database paths](https://chromium.googlesource.com/chromium/src/+/c551499a894d32bd04a882a0beae53d854e28ba2/components/services/storage/dom_storage/dom_storage_database.cc#279) — A-；LevelDB/SQLite paths 与 rollout。
- **[C3]** [IndexedDB file path utility](https://chromium.googlesource.com/chromium/src/+/c551499a894d32bd04a882a0beae53d854e28ba2/content/browser/indexed_db/file_path_util.cc#115) — A-；legacy/bucket paths 与 SQLite DB-name hash。
- **[C4]** [Storage directory utility](https://chromium.googlesource.com/chromium/src/+/c551499a894d32bd04a882a0beae53d854e28ba2/storage/browser/quota/storage_directory_util.cc#12) — A-；`WebStorage/<bucket-id>/<client>`。
- **[C5]** [Database identifier](https://chromium.googlesource.com/chromium/src/+/c551499a894d32bd04a882a0beae53d854e28ba2/storage/common/database/database_identifier.cc#183) — A-；legacy origin 编码。
- **[C6]** [Service Worker architecture/storage](https://github.com/chromium/chromium/blob/c551499a894d32bd04a882a0beae53d854e28ba2/content/browser/service_worker/README.md#storage) — A-；registration/script/cache layout。
- **[C7]** [StoragePartition Code Cache](https://chromium.googlesource.com/chromium/src/+/c551499a894d32bd04a882a0beae53d854e28ba2/content/browser/storage_partition_impl.cc#1562) 与 [partition path map](https://chromium.googlesource.com/chromium/src/+/c551499a894d32bd04a882a0beae53d854e28ba2/content/browser/storage_partition_impl_map.cc#56) — A-。
- **[C8]** [Chrome Storage Partitioning](https://developer.chrome.com/docs/privacy-sandbox/storage-partitioning/) — A；Chrome 115+ 行为，页面 2023-05-16 更新。
- **[C9]** [ProcessSingleton design](https://chromium.googlesource.com/chromium/src/+/c551499a894d32bd04a882a0beae53d854e28ba2/chrome/browser/process_singleton.h#32)、[POSIX](https://chromium.googlesource.com/chromium/src/+/c551499a894d32bd04a882a0beae53d854e28ba2/chrome/browser/process_singleton_posix.cc#115)、[Windows](https://chromium.googlesource.com/chromium/src/+/c551499a894d32bd04a882a0beae53d854e28ba2/chrome/browser/process_singleton_win.cc#93) — A-。
- **[C10]** [Profile network context cache path](https://chromium.googlesource.com/chromium/src/+/c551499a894d32bd04a882a0beae53d854e28ba2/chrome/browser/net/profile_network_context_service.cc#1387) — A-；`<C>/Cache`。
- **[C11]** [IndexedDB bucket backend rollout](https://chromium.googlesource.com/chromium/src/+/c551499a894d32bd04a882a0beae53d854e28ba2/content/browser/indexed_db/instance/bucket_context.cc#87) — A-；LevelDB/SQLite selection。
- **[C12]** [StorageKey serialization](https://chromium.googlesource.com/chromium/src/+/c551499a894d32bd04a882a0beae53d854e28ba2/third_party/blink/common/storage_key/storage_key.cc#85) — A-；top-level site、ancestor bit、nonce/opaque precursor。
- **[C13]** [Chrome HTTP cache partitioning](https://developer.chrome.com/blog/http-cache-partitioning) — A；Chrome 86 起以 URL + Network Isolation Key 分区。

### Firefox / Mozilla

- **[F1]** [Firefox Profiles Service](https://firefox-source-docs.mozilla.org/toolkit/profile/index.html) — A；ProfD/ProfLD、Profile Service 与锁。
- **[F2]** [Profile-per-install changes](https://firefox-source-docs.mozilla.org/toolkit/profile/changes.html#profile-per-install) — A；`profiles.ini`/`installs.ini`。
- **[F3]** [QuotaManager implementation](https://github.com/mozilla-firefox/firefox/blob/dddd3ebf8c01bcbf38c5ba24812e9df1ea6fff8a/dom/quota/ActorsParent.cpp) 与 [client names](https://github.com/mozilla-firefox/firefox/blob/dddd3ebf8c01bcbf38c5ba24812e9df1ea6fff8a/dom/quota/Client.h) — A-。
- **[F4]** [Firefox HTTP Cache](https://firefox-source-docs.mozilla.org/networking/cache2/doc.html) — A-；Mozilla 实现文档，不是外部格式契约。
- **[F5]** [ScriptLoader bytecode-cache implementation](https://github.com/mozilla-firefox/firefox/blob/dddd3ebf8c01bcbf38c5ba24812e9df1ea6fff8a/dom/script/ScriptLoader.cpp) — A-；当前外部网页脚本 bytecode/stencil 使用 HTTP cache alternate data。[2017 Mozilla JSBC 文章](https://blog.mozilla.org/javascript/2017/12/12/javascript-startup-bytecode-cache/) 仅作历史设计背景（B），不证明 2026 实现。
- **[F6]** [StartupCache source](https://github.com/mozilla-firefox/firefox/blob/dddd3ebf8c01bcbf38c5ba24812e9df1ea6fff8a/startupcache/StartupCache.cpp) — A-。
- **[F7]** [IndexedDB implementation](https://github.com/mozilla-firefox/firefox/blob/dddd3ebf8c01bcbf38c5ba24812e9df1ea6fff8a/dom/indexedDB/ActorsParent.cpp) — A-。
- **[F8]** [LocalStorage implementation](https://github.com/mozilla-firefox/firefox/blob/dddd3ebf8c01bcbf38c5ba24812e9df1ea6fff8a/dom/localstorage/ActorsParent.cpp) — A-。
- **[F9]** [ServiceWorker registrar implementation](https://github.com/mozilla-firefox/firefox/blob/dddd3ebf8c01bcbf38c5ba24812e9df1ea6fff8a/dom/serviceworkers/ServiceWorkerRegistrar.cpp) 与 [filename/version constants](https://github.com/mozilla-firefox/firefox/blob/dddd3ebf8c01bcbf38c5ba24812e9df1ea6fff8a/dom/serviceworkers/ServiceWorkerRegistrar.h#L17) — A-。
- **[F10]** DOM Cache [DB path/open](https://github.com/mozilla-firefox/firefox/blob/dddd3ebf8c01bcbf38c5ba24812e9df1ea6fff8a/dom/cache/DBAction.cpp)、[quota/padding](https://github.com/mozilla-firefox/firefox/blob/dddd3ebf8c01bcbf38c5ba24812e9df1ea6fff8a/dom/cache/QuotaClient.cpp) 与 [body/morgue file helpers](https://github.com/mozilla-firefox/firefox/blob/dddd3ebf8c01bcbf38c5ba24812e9df1ea6fff8a/dom/cache/FileUtils.cpp) — A-。
- **[F11]** [OriginParser](https://github.com/mozilla-firefox/firefox/blob/dddd3ebf8c01bcbf38c5ba24812e9df1ea6fff8a/dom/quota/OriginParser.cpp) — A-。
- **[F12]** [OriginAttributes](https://github.com/mozilla-firefox/firefox/blob/dddd3ebf8c01bcbf38c5ba24812e9df1ea6fff8a/caps/OriginAttributes.cpp) — A-。
- **[F13]** [MDN State Partitioning](https://developer.mozilla.org/en-US/docs/Web/Privacy/Guides/State_Partitioning) — A/B；Firefox 85/103 版本线。
- **[F14]** [Firefox already running / lock troubleshooting](https://support.mozilla.org/en-US/kb/firefox-already-running-not-responding) — B。
- **[F15]** [Mozilla manual Profile backup](https://support.mozilla.org/en-US/kb/back-and-restore-information-firefox-profiles) — A；先退出再复制。
- **[F16]** [Firefox Profile lock implementation](https://github.com/mozilla-firefox/firefox/blob/dddd3ebf8c01bcbf38c5ba24812e9df1ea6fff8a/toolkit/profile/nsProfileLock.cpp) — A-；平台锁协议。

### Safari / WebKit

- **[S1]** [Use profiles in Safari on Mac](https://support.apple.com/en-us/105100) — A；更新于 2025-12-05。
- **[S2]** [Update Safari / obsolete Windows Safari](https://support.apple.com/102665) 与 [WebKit ports](https://docs.webkit.org/Ports/Introduction.html) — A。
- **[S3]** [WebKit Features in Safari 17](https://webkit.org/blog/14445/webkit-features-in-safari-17-0/) 与 [Safari 17 release notes](https://developer.apple.com/documentation/safari-release-notes/safari-17-release-notes) — A；Safari 17 于 2023-09-18 发布。
- **[S4]** [Building Profiles with new WebKit API](https://webkit.org/blog/14423/building-profiles-with-new-webkit-api/) — A；2023-08-30。
- **[S5]** [Cocoa WebsiteDataStore paths](https://github.com/WebKit/WebKit/blob/0fdbfc2c77ce3e85884bef7b1a48fcfb7630c28f/Source/WebKit/UIProcess/WebsiteData/Cocoa/WebsiteDataStoreCocoa.mm#L273) 与 [configuration](https://github.com/WebKit/WebKit/blob/0fdbfc2c77ce3e85884bef7b1a48fcfb7630c28f/Source/WebKit/UIProcess/WebsiteData/WebsiteDataStoreConfiguration.cpp#L69) — A-。
- **[S6]** [NetworkStorageManager origin hashing](https://github.com/WebKit/WebKit/blob/0fdbfc2c77ce3e85884bef7b1a48fcfb7630c28f/Source/WebKit/NetworkProcess/storage/NetworkStorageManager.cpp#L114) 与 [`m_path/salt` loading](https://github.com/WebKit/WebKit/blob/0fdbfc2c77ce3e85884bef7b1a48fcfb7630c28f/Source/WebKit/NetworkProcess/storage/NetworkStorageManager.cpp#L243) — A-。
- **[S7]** [OriginStorageManager](https://github.com/WebKit/WebKit/blob/0fdbfc2c77ce3e85884bef7b1a48fcfb7630c28f/Source/WebKit/NetworkProcess/storage/OriginStorageManager.cpp#L517) — A-。
- **[S8]** [LocalStorageManager](https://github.com/WebKit/WebKit/blob/0fdbfc2c77ce3e85884bef7b1a48fcfb7630c28f/Source/WebKit/NetworkProcess/storage/LocalStorageManager.cpp#L39) 与 [IDBStorageManager](https://github.com/WebKit/WebKit/blob/0fdbfc2c77ce3e85884bef7b1a48fcfb7630c28f/Source/WebKit/NetworkProcess/storage/IDBStorageManager.cpp) — A-。
- **[S9]** [CacheStorageDiskStore](https://github.com/WebKit/WebKit/blob/0fdbfc2c77ce3e85884bef7b1a48fcfb7630c28f/Source/WebKit/NetworkProcess/storage/CacheStorageDiskStore.cpp) — A-。
- **[S10]** [Service Worker registration DB](https://github.com/WebKit/WebKit/blob/0fdbfc2c77ce3e85884bef7b1a48fcfb7630c28f/Source/WebCore/workers/service/server/SWRegistrationDatabase.cpp) 与 [NetworkCache](https://github.com/WebKit/WebKit/blob/0fdbfc2c77ce3e85884bef7b1a48fcfb7630c28f/Source/WebKit/NetworkProcess/cache/NetworkCacheStorage.cpp) — A-。
- **[S11]** [Tracking Prevention in WebKit](https://webkit.org/tracking-prevention/) — A。
- **[S12]** [Store removal/active-use guards](https://github.com/WebKit/WebKit/blob/0fdbfc2c77ce3e85884bef7b1a48fcfb7630c28f/Source/WebKit/UIProcess/WebsiteData/Cocoa/WebsiteDataStoreCocoa.mm#L322) — A-。
- **[S13]** [Clear Safari website data](https://support.apple.com/guide/safari/manage-cookies-sfri11471/mac) — A。

### Chrome / Edge 本地模型与通用存储安全

- **[M1]** [Get started with Chrome built-in AI](https://developer.chrome.com/docs/ai/get-started) — A；正文显示 Published 2024-12-12 / Last updated 2025-05-20（页面结构化日期曾与正文不一致，以可见正文记录），当前页面含 Chrome 149 语言范围。
- **[M2]** [Chrome built-in model management](https://developer.chrome.com/docs/ai/understand-built-in-model-management) — A；发布/更新于 2025-10-21。
- **[M3]** [Model/manifest names, IDs and legacy directories](https://chromium.googlesource.com/chromium/src/+/c551499a894d32bd04a882a0beae53d854e28ba2/chrome/browser/component_updater/optimization_guide_on_device_model_installer.cc#53)、[manifest-asset directory](https://chromium.googlesource.com/chromium/src/+/c551499a894d32bd04a882a0beae53d854e28ba2/chrome/browser/component_updater/optimization_guide_on_device_model_installer.cc#351)、[required legacy payload files](https://chromium.googlesource.com/chromium/src/+/c551499a894d32bd04a882a0beae53d854e28ba2/components/optimization_guide/core/model_execution/on_device_model_component.h#49) 与 [component root registration](https://chromium.googlesource.com/chromium/src/+/c551499a894d32bd04a882a0beae53d854e28ba2/chrome/app/chrome_main_delegate.cc#1445) — A-。
- **[M4]** [On-device component state](https://chromium.googlesource.com/chromium/src/+/c551499a894d32bd04a882a0beae53d854e28ba2/components/optimization_guide/core/model_execution/on_device_model_component.cc#627) 与 [internals handler](https://chromium.googlesource.com/chromium/src/+/c551499a894d32bd04a882a0beae53d854e28ba2/chrome/browser/ui/webui/on_device_internals/on_device_internals_page_handler.cc#310) — A-；legacy 资格、卸载与 live path。
- **[M5]** [On-device architecture](https://chromium.googlesource.com/chromium/src/+/c551499a894d32bd04a882a0beae53d854e28ba2/components/optimization_guide/core/model_execution/on_device.md) — A-。
- **[M6]** [Manifest Broker default-on commit](https://github.com/chromium/chromium/commit/4942ffcc60827c9ad4fa2666b0dc9e00f170cc47)、[architecture doc update](https://github.com/chromium/chromium/commit/58c2d52e4e2567276b661fd38ef1b28abfd1fb9e)、[old flag removal](https://github.com/chromium/chromium/commit/c4b9fa1b4a074fd651e53ff2066f3dfc3fe120db) — A-；2026 主干迁移。
- **[M7]** [Chrome live policy data](https://chromeenterprise.google/static/json/policy_templates_en-US.json)（搜索 `GenAILocalFoundationalModelSettings` / `ComponentUpdatesEnabled`）— A；2026-08-26 获取。
- **[M8]** Manifest Broker [UI](https://github.com/chromium/chromium/blob/c551499a894d32bd04a882a0beae53d854e28ba2/chrome/browser/resources/on_device_internals/broker_state.ts)、[broker state](https://github.com/chromium/chromium/blob/c551499a894d32bd04a882a0beae53d854e28ba2/components/optimization_guide/core/model_execution/manifest_broker/manifest_broker_state.cc) 与 [asset uninstall](https://github.com/chromium/chromium/blob/c551499a894d32bd04a882a0beae53d854e28ba2/components/optimization_guide/core/model_execution/manifest_broker/manifest_asset_manager.cc) — A-；新架构 `Uninstall Models`。
- **[M9]** [Current on-device feature keys](https://github.com/chromium/chromium/blob/c551499a894d32bd04a882a0beae53d854e28ba2/components/optimization_guide/core/model_execution/on_device_features.cc) — A-；消费者候选，不代表全部已发布产品能力。
- **[E1]** [Edge user-data variables/Profile path](https://learn.microsoft.com/en-us/deployedge/edge-learnmore-create-user-directory-vars) — A。
- **[E2]** [Edge Prompt API](https://learn.microsoft.com/en-us/microsoft-edge/web-platform/prompt-api)、[Writing Assistance APIs](https://learn.microsoft.com/en-us/microsoft-edge/web-platform/writing-assistance-apis) 与 [Proofreader API](https://learn.microsoft.com/en-us/microsoft-edge/web-platform/proofreader-api) — A；Prompt 页面更新于 2026-06-02。
- **[E3]** [Edge GenAI local model policy](https://learn.microsoft.com/en-us/deployedge/microsoft-edge-policies/genailocalfoundationalmodelsettings) — A；`ms.date` 2026-05-20、抓取时页面显示 Last updated 2026-05-22，站点 `updated_at` 曾见 2026-06-15；访问 2026-08-26。
- **[E4]** [Edge component updates policy](https://learn.microsoft.com/en-us/deployedge/microsoft-edge-policies/componentupdatesenabled) — A；同站点日期元数据存在上述口径差异；访问 2026-08-26。
- **[X1]** [LevelDB documentation](https://github.com/google/leveldb/blob/main/doc/index.md) — primary project docs；single-process database locking。
- **[X2]** [SQLite WAL](https://www.sqlite.org/wal.html) 与 [How To Corrupt](https://www.sqlite.org/howtocorrupt.html) — primary project docs；DB/journal pairing。
- **[X3]** [SQLite Online Backup API](https://www.sqlite.org/backup.html) — primary project docs；单 DB 在线一致副本，不是浏览器跨 store 事务。

## 10. 已知未知项与保守降级总表

| 未知/易漂移项 | 不应声称 | 保守处理 |
|---|---|---|
| 未来 Chromium DOM/IDB/bucket schema | 固定目录永远有效 | 按 milestone/commit adapter；未知即 `unsupported_layout` |
| Safari 默认 Profile 的真实私有目录/名称映射 | 所有 Profile 都是 `WebsiteDataStore/<UUID>` | Safari/API/可验证 metadata 优先；否则 unresolved |
| Edge 的模型公钥与 component ID | 等于上游 Chrome 的 `fkl...` | 用 `edge://on-device-internals`；ID 标未知 |
| Chrome/Edge 精确模型体积、文件名、功能消费者 | 永远 4 GB、永远 `weights.bin`、完整功能清单固定 | 记录 live path/version/size；按版本重新枚举 |
| 活 Profile 的普通目录副本 | 是原子、一致备份 | 快照或跳过；明确 `potentially_inconsistent` |
| hostname 命中 | 覆盖该站全部数据且不会误删 | 解码完整 StorageKey/OriginAttributes/top-client origin，并预览所有分区 |

这套降级原则的核心是：**能验证才归因，能一致才迁移，能由浏览器支持接口完成就不直接改内部文件；其余一律报告并跳过。**

## 9. 实现落地（2026-09-05）

`sweepx site-storage` 已实现 §8.5 的归因结论，作为独立只读命令，不并入 `junk`：`docs/CLEANER-CATALOG.md`
的风险分级把"browser application state"逐字归为 **R3 —— 默认跳过/仅报告，策略可允许逐项选中**，而 R4 专指
不可逆动作。因此本命令只报告、不预选、不删除。

实现过程中修正了两处调研阶段的错误认识：

1. **origin 是 UTF-8，不是 UTF-16LE**（§8.5.2 已就地更正）。文件里确有 UTF-16 片段，但那是哈希的十六进制
   字符串。
2. **不能取"第一个 URL"，也不能靠字符类边界**。最终判据是 protobuf 的**长度前缀自校验**：真实 origin 前一
   个字节恰好等于其自身长度（含尾部 `/`）。18 个桶全部符合。
   - 反例一：Workbox 站点把缓存名存为 `workbox-precache-v2-https://gamemap.app/`，其前置长度计的是整个名
     字（40），不等于其中 URL 的长度，因此被正确排除。
   - 反例二：先尝试的"scheme 前不得紧跟字母数字"规则**漏掉了一整个来源** —— 扩展 origin 的长度前缀是
     `0x34`（数字 `4`），被误判为"更长 token 的延续"。

第 2 条错误一度表现为 480 MB 中 367 字节的差额，我最初解释为"Edge 运行中边扫边写"并加了容差 —— 这是错的：
那 367 字节**正是**被漏掉的扩展 origin。修正解析后差额归零，容差随即收回为精确比较。**容差掩盖了缺陷，而不
是吸收了噪声。**

验证方式：与独立目录遍历交叉核对，Edge 12/12 桶、Edge Dev 6/6 桶全部解析，四个子系统的归因之和与遍历总量
差额均为 0；IndexedDB 的 `.leveldb`/`.blob` 正确合并（43 个来源对应 52 个目录）。

## 11. Edge 遥测数据库（2026-09-05 实测）

用户提问「浏览器历史记录或其他缓存现在能否识别」后，对本机 Edge / Edge Dev / Chrome 的 profile
做了一次「未覆盖项」普查，发现体量最大的单文件并不是历史记录，而是一组 Edge 独有的遥测数据库。

### 11.1 未覆盖清单（Edge Default，>= 1 MB，排除已覆盖目录）

| 体量 | 对象 | 性质 |
| --- | --- | --- |
| 572.0 MB | `Extensions/` | 扩展本体，不是垃圾（删除等于卸载） |
| 108.6 MB | `ExtensionActivityEdge` | 扩展 API 调用遥测，SQLite |
| 55.2 MB | `Local Extension Settings/` | 扩展自身数据 |
| 50.5 MB | `load_statistics.db` | 25,798 行加载统计 |
| 28.4 MB | `WebAssistDatabase` | 30,459 行导航记录 |
| 20.7 MB | `Local Storage/` | 已能按域报告（§8.5.2），不可切分 |
| 19.6 MB | `History` | 浏览历史 + 下载 + 标注，非纯缓存 |
| 11.2 MB | `Favicons` | 169 图标 / 472 映射，可重新抓取 |

三个大项是 **Edge 独有**：`ExtensionActivityEdge`、`load_statistics.db`、`WebAssistDatabase`
在 Chrome 的 `Default` 下完全不存在。因此不能写成通用 `chromium.*` 规则，与 R2 那三条渲染缓存规则
的适用面不同。

同一份代码在两个安装间差两个数量级（`ExtensionActivityEdge`：Edge 108.6 MB vs Edge Dev 0.0 MB），
说明规则不能依据「典型体积」预判，必须逐机实测。

### 11.2 关键发现：89% 是 SQLite freelist，不是日志内容

`ExtensionActivityEdge` 的实测构成：

```
page_size=4096  page_count=27789  freelist=24730
file       : 108.6 MB
live pages :  11.9 MB
free pages :  96.6 MB   (89.0%)
```

**Edge 自己在删旧行，但从不 VACUUM。** 因此文件里 89% 是已释放但未归还操作系统的空页。这修正了
公开资料的因果描述——它们普遍称此文件「不清理旧条目所以无限增长」，而实测是「清理了但不回收空间」。

保留窗口同样是实测值，与「无限增长」不符：

```
oldest row : 2026-09-02 16:00:00 UTC
newest row : 2026-09-05 11:08:15 UTC
span       : 2 天 19 小时
rows       : 445,178  ->  约 6,631 行/小时
```

即存在约 3 天的滚动保留。真正的膨胀来源是**写入速率 x 页面不回收**，而非无限累积。这一点决定了
清理口径：删除文件回收的是 108.6 MB，而其中仅 11.9 MB 对应「真实数据」。

### 11.3 内容是用户可识别的

`string_ids` / `url_ids` 两张映射表把整数外键还原为明文：

```
string_ids[1]  = 'kagpabjoboikccfdghpdlaaopmgpgfdc'   扩展 ID
string_ids[2]  = 'windows.getAll'                     被调用的 API
string_ids[50] = 'storage.set'
url_ids (557)  = edge://newtab/ , https://cn.bing.com/search , ...
```

所以它同时记录「哪个扩展、调了什么 API、在哪个页面上」。归类为纯技术遥测是不准确的：其中含浏览过的
URL，属于用户可识别数据。这影响风险分级——它不是 R2「可重建」，删除不会被任何机制补回。

### 11.4 外部资料与本机实测的差异

公开资料一致认为删除安全、Edge 会自动重建、微软未提供关闭开关（微软论坛 Moderator 明确答复
「by design，目前无法阻止」），并有用户报告涨到 196 GB。但这些均为三方博客与论坛，微软**未正式
文档化**该文件。可采信的是「删除安全 + 会重建 + 无开关」；不可照搬的是「不清理旧条目」这一因果解释，
本机实测与之矛盾（见 §11.2）。

来源：
- https://www.thewindowsclub.com/what-is-extensionactivityedge-file
- https://learn.microsoft.com/en-sg/answers/questions/2282536/how-extensionactivityedge-cant-be-create-after-del

### 11.5 尚未决定的口径问题

1. **体积怎么报**：删除整个文件回收 108.6 MB，但 live 数据仅 11.9 MB。是否需要类似
   `sizeIsLogical` 的标注，说明「其中 X MB 为数据库空洞」？
2. **风险等级**：含浏览过的 URL 与扩展 ID，删除不可逆且无法重建，按 §CLEANER-CATALOG 分级应为 R3
   （默认仅报告，允许逐项选中 Trash），而非 R2。
3. **是否需要关进程**：文件被运行中的 Edge 独占，与 §8.5 逐域 Trash 遇到的 LevelDB `LOCK` 情形同类，
   需要同样的 holder 证据而不是直接移动。
4. `load_statistics.db` / `WebAssistDatabase` 的内部构成尚未做同等深度的探查，不应假定与
   `ExtensionActivityEdge` 相同。
