# Windows、macOS、Linux 磁盘分析与清理工具版图

研究截点：2026-08-26。本文是只读桌面研究，不代表对任何产品执行过清理操作。除非单独注明，本文列出的所有网络来源均于 **2026-08-26** 访问。优先采用厂商文档、项目上游仓库和标准文档；产品营销中的性能或安全措辞只按“厂商声称”记录。

## 结论摘要

市场上没有一个工具同时可靠覆盖“跨平台任意目录分析、系统/浏览器/开发缓存语义、可恢复清理、可信物理占用、TUI 与可审计扩展”。已有产品大致分成四类：

1. `dust`、`gdu`、`ncdu`、`dua-cli` 等通用分析器擅长快速回答“空间在哪里”，但不知道某个缓存是否仍被应用引用。
2. BleachBit、CCleaner、CleanMyMac 等系统清理器理解应用数据类别，但平台覆盖、透明度和扩展模型差异很大。
3. Kondo、`cargo-cache`、Docker/pnpm/uv 等开发者清理器掌握项目或包管理器语义，但覆盖面窄。
4. WizTree、TreeSize、DaisyDisk 等商业可视化工具在交互与平台特化上突出，却不能直接迁移成统一的跨平台后端。

**产品建议：**采用“通用只读扫描核心 + 类型化 cleaner + 生态原生命令适配器 + CLI/TUI 双界面”。扫描、建议、动作计划和执行必须是四个明确阶段；默认 dry-run 和系统回收站；导入/历史报告绝不能直接成为删除依据；“安全删除”不得承诺对 SSD、快照、写时复制或云副本有效。

## 阅读方法与证据等级

- **事实**：被本表引用的官方文档或上游仓库直接说明。
- **推导**：由若干已证事实得出的设计判断，不是原产品承诺。
- **建议**：面向拟议产品的取舍。
- **缺口**：查阅的一手资料没有建立该能力；“未证实”不等于证明不存在。
- `✓` 表示一手资料明确支持；`△` 表示仅部分平台/版本/模式支持，或能力有关键限制；`—` 表示查阅的一手资料未证实。

“平台”按原生发行和官方支持口径填写；能从 Windows 客户端远程扫描 Linux 不等于 Linux 原生支持。性能列只记录实现路径或可复核机制，不把“fastest”“很快”之类营销词当成横向基准。

## 可追溯能力矩阵

### A. 通用磁盘分析器与 TUI

| 工具 | 平台与类别 | 扫描 | 专项清理 | 浏览器数据 | 安全删除 | 交互 | 性能 | 扩展能力 | 主要证据 |
|---|---|---|---|---|---|---|---|---|---|
| **dust (`bootandy/dust`)** | Windows / macOS / Linux；开源 CLI | ✓ 层级大小、深度、文件数、apparent size、类型/正则过滤、文件系统边界 | — | — | — | 非交互文本输出 | Rust 实现；未找到可复核的跨工具基准 | △ CLI 组合与配置，无稳定 cleaner/plugin API 证据 | [上游仓库](https://github.com/bootandy/dust)、[Releases](https://github.com/bootandy/dust/releases) |
| **dua-cli** | Windows / macOS / Linux 等；开源 CLI+TUI；Windows 有 release binary、Scoop 与 WinGet，源码安装需 nightly Rust | ✓ aggregate 与交互扫描、apparent size | △ TUI 中分阶段删除 | — | — | ✓ 键盘浏览、标记、删除 | ✓ 默认并行遍历；未找到标准化横评 | △ 可配置，但无公开 cleaner DSL/plugin API | [上游 README（含 Windows 安装）](https://github.com/Byron/dua-cli)、[Releases](https://github.com/Byron/dua-cli/releases) |
| **gdu** | Windows amd64 / macOS / Linux / BSD 等；开源 TUI；具体 OS/架构按 release 验证 | ✓ 目录树、搜索、重扫、ignore、JSON 导入/导出、硬链接去重 | △ 标记后删除、shell/open action | — | — | ✓ TUI，另有 Web UI | ✓ 面向 SSD 的并行处理；上游明确说 HDD 收益较小；无受控横评 | △ 配置和 JSON 互操作，无 cleaner plugin API | [仓库](https://github.com/dundee/gdu)、[安装（含 WinGet/Scoop）](https://github.com/dundee/gdu/blob/master/INSTALL.md)、[v5.37.0 Releases](https://github.com/dundee/gdu/releases/tag/v5.37.0)、[man page](https://github.com/dundee/gdu/blob/master/gdu.1.md?plain=1)、[配置](https://github.com/dundee/gdu/blob/master/configuration.md) |
| **ncdu 2.x** | Linux / macOS / BSD 等 Unix-like；开源 TUI | ✓ 排序、刷新、排除、单文件系统、JSON/二进制导入导出 | △ 活扫描可删除；导入扫描禁用删除/刷新/shell | — | — | ✓ curses 浏览器 | △ 支持线程控制；无可信跨工具基准 | △ 导出格式与 shell 集成，无 cleaner DSL | [官方主页](https://dev.yorhel.nl/ncdu)、[2.x 手册](https://dev.yorhel.nl/ncdu/man/2_0) |
| **diskonaut** | Windows / macOS / Linux（版本需固定）；开源 TUI | ✓ 内存索引与终端 treemap | △ 文件/目录删除并跟踪本次释放量 | — | — | ✓ 可钻取空间图 | △ 索引后交互快，但超大树有内存成本；无公开基准 | — | [上游 README](https://github.com/imsnif/diskonaut/blob/main/README.md)、[Windows release](https://github.com/imsnif/diskonaut/releases/tag/0.11.0) |
| **QDirStat** | Linux / BSD / Unix-like；开源 GUI | ✓ 树+treemap、搜索、分类、exclude、缓存/远端扫描文件 | ✓ 无限个用户定义 cleanup action，可捕获输出/错误 | — | — | ✓ Qt GUI、多选 | △ 缓存报告避免重复扫描；无横评 | ✓ 可配置外部动作，但属于高信任命令，不是受限 DSL | [README](https://github.com/shundhammer/qdirstat/blob/master/README.md)、[server/cached scan 指南](https://github.com/shundhammer/qdirstat/blob/master/doc/QDirStat-for-Servers.md) |
| **Czkawka / Krokiet** | Windows / macOS / Linux / FreeBSD 等；开源 core+CLI+GUI | ✓ 重复、大文件、空项、临时项、坏链接/文件、相似媒体；缓存重复扫描结果 | ✓ 多种重复项处置策略；CLI dry-run | — | — | ✓ CLI、Slint/GTK GUI | △ 分阶段哈希与缓存；无统一横评 | ✓ 可复用 core，多前端；cleaner 仍为源码级扩展 | [README](https://github.com/qarmin/czkawka/blob/master/README.md)、[CLI 指南](https://github.com/qarmin/czkawka/blob/master/instructions/Instruction_CLI.md) |
| **rmlint** | Linux 为主，也支持若干 Unix/macOS；开源 CLI | ✓ 重复文件/目录、空项、坏链接、未 strip 二进制，多种哈希模式 | ✓ 生成可审阅 cleanup script，可删或改成 hardlink/symlink/reflink | — | — | CLI + 结构化输出/脚本 | △ xattr checksum cache 与多阶段检测；部分优化仅 Linux | ✓ 多种输出和生成脚本，但不是通用 cleaner 插件 | [文档](https://rmlint.readthedocs.io/)、[上游 README](https://github.com/sahib/rmlint/blob/master/README.rst)、[风险说明](https://rmlint.readthedocs.io/en/latest/cautions.html) |

### B. 系统与浏览器清理器

| 工具 | 平台与类别 | 扫描 | 专项清理 | 浏览器数据 | 安全删除 | 交互 | 性能 | 扩展能力 | 主要证据 |
|---|---|---|---|---|---|---|---|---|---|
| **BleachBit** | Windows / Linux；macOS 官方标为实验/受限；开源 GUI+CLI | ✓ cleaner 级 preview/list | ✓ OS/应用缓存、日志、临时项、Windows MRU、数据库 vacuum，并可精细编辑 INI/JSON/SQLite | ✓ 缓存、历史、cookie、站点/会话数据；Cookie Manager 可保留条目 | △ 覆写 cleaner 结果、shred 文件/目录、擦空闲空间；官方资料不能证明 SSD/COW/快照上的不可恢复性 | ✓ GUI 和可脚本化 CLI，preview 与 clean 使用相同 selector | — 未找到可重复横评 | ✓ CleanerML：OS guard、变量、glob/tree/deep scan、regex、delete/truncate/shred、校验与翻译 | [文档首页](https://docs.bleachbit.org/)、[CLI](https://docs.bleachbit.org/doc/command-line-interface.html)、[CleanerML](https://docs.bleachbit.org/cml/cleanerml.html)、[擦除说明](https://docs.bleachbit.org/doc/shred-files-and-wipe-disks.html) |
| **CCleaner** | Windows 与 macOS 为不同产品；商业 GUI | ✓ Custom Clean、重复/大文件等因版本而异 | ✓ Windows/应用数据、include/exclude、重复项；功能按版本/平台分化 | ✓ 历史、缓存、cookie 等；Windows 可保留指定 cookie | △ 厂商对 Windows Drive Wiper/空闲空间覆写的说明；不能外推到 Mac，也不能证明 SSD 上可靠 | ✓ GUI、选择与 review | — 厂商宣传不构成可比基准 | △ Windows 规则/配置可定制；未证实类似 CleanerML 的公共稳定 SDK | [产品政策与能力](https://www.ccleaner.com/legal/products-policy)、[Cookie 保留](https://support.ccleaner.com/articles/en_US/Master_Article/select-cookies-to-clean-with-ccleaner-for-windows)、[Duplicate Finder](https://support.ccleaner.com/articles/en_US/Master_Article/what-is-ccleaner-s-duplicate-file-finder)、[厂商 Drive Wiper 说明](https://www.ccleaner.com/knowledge/the-ultimate-guide-how-to-wipe-your-drive-and-destroy-your-data)、[Mac 概览](https://support.ccleaner.com/articles/en_US/Master_Article/what-is-the-new-ccleaner-for-mac) |
| **CleanMyMac 桌面版** | macOS；商业 GUI | ✓ System Junk、Large & Old Files 等分类扫描 | ✓ 缓存、日志、语言包、文档版本、Xcode junk、应用数据 | ✓ Safari/Chrome/Firefox 的历史、cookie、下载历史、autofill 等，具体能力与发行渠道有关 | △ Shredder 宣称普通/secure removal；SSD、APFS clone/snapshot 与备份限制未被其说明充分覆盖 | ✓ scan → review details → select → remove | — 未找到独立可复核基准 | — 未证实公共 plugin API 或机器可读报告 | [System Junk](https://macpaw.com/support/cleanmymac-x/knowledgebase/system-junk)、[Large & Old](https://macpaw.com/support/cleanmymac-x/knowledgebase/large-and-old)、[Privacy](https://macpaw.com/support/cleanmymac/knowledgebase/privacy)、[Shredder](https://macpaw.com/support/cleanmymac-x/knowledgebase/shredder) |
| **Microsoft PC Manager** | Windows 10/11；免费商业 GUI | ✓ storage/large-file 管理 | ✓ 系统 cleanup、Storage Sense 集成、启动项等 | △ 官方服务协议明确 Deep Cleanup 涵盖浏览器与应用 cache，但没有细粒度类别矩阵 | — 未证实 | ✓ GUI | — 只有高层产品描述 | — 未找到 CLI/API/cleaner 扩展机制 | [官方产品页](https://pcmanager.microsoft.com/en-us)、[官方服务协议](https://pcmanager-en.microsoft.com/en-us/termsofservice)、[Storage Sense](https://support.microsoft.com/en-us/windows/experience/storage-filemanagement/manage-drive-space-with-storage-sense) |
| **Stacer（原项目）** | Linux；历史开源 GUI，原上游已停止维护 | △ 历史版本含系统监控/资源视图 | △ 历史版本含系统清理、启动项/服务/包管理 | — | — | GUI | 不再适合作为当前性能基准 | 源码可改，但无当前稳定扩展承诺 | [原上游仓库](https://github.com/oguzhaninan/Stacer) |

### C. 开发者缓存与构建产物清理器

| 工具 | 平台与类别 | 扫描 | 专项清理 | 浏览器数据 | 安全删除 | 交互 | 性能 | 扩展能力 | 主要证据 |
|---|---|---|---|---|---|---|---|---|---|
| **dust (`ariefsn/dust`)** | macOS / Linux；开源 CLI+TUI；与 `bootandy/dust` 同名但不同项目 | ✓ developer/browser/project/app/system/package-manager 分类扫描；CLI 支持显式 `--dry-run` | ✓ Docker、JS、Deno、Gradle/Maven、pip/Conda、Go、Rust、Xcode 等 cleaner | △ 清 HTTP/GPU/code cache、Service Workers、IndexedDB；上游明确不碰 cookie/history/password/bookmark，但 IndexedDB 仍可能影响站点离线/登录状态 | — | ✓ 两栏 TUI；首次交互默认为 dry-run；另有 scriptable scan/clean | △ 单静态二进制；无可复核跨工具基准 | △ YAML 配置；新增 cleaner 需实现 Go interface 并编译注册，不是第三方运行时插件 | [README 的 Browsers 与 Safety 段](https://github.com/ariefsn/dust/blob/main/README.md#browsers-http-cache-gpu-cache-code-cache-service-workers-indexeddb) |
| **CleanMyMac CLI（public beta）** | macOS 11+；商业产品团队公开的 CLI/TUI，仓库未声明开源许可证 | ✓ `analyze [path]` 交互空间浏览 | ✓ `clean dev/junk/ai/trash`；`purge` 按项目与年龄列出构建/依赖产物 | — README 未列浏览器隐私清理 | —；`--force` 是跳过确认，不是 secure erase | ✓ TUI/CLI，review、ignore list、protected paths、明确确认 | — 未发布可复核基准 | △ cleaner 逻辑与桌面产品共享；未证实公共扩展 API | [官方仓库与 beta 声明](https://github.com/MacPaw/cleanmymac-cli)、[Commands](https://github.com/MacPaw/cleanmymac-cli/wiki/Commands)、[Safety & Privacy](https://github.com/MacPaw/cleanmymac-cli/wiki/Safety-and-Privacy) |
| **Kondo** | Windows / macOS / Linux（按 release）；开源 CLI+GUI | ✓ 识别 Cargo、Node、Unity、SBT、Maven/Gradle、Python、CMake、Swift、.NET 等项目并估算产物 | ✓ 按项目类型删除依赖/构建目录，支持 dry-run/选择 | — | — | CLI 与 GUI | — 无公开标准横评 | △ 新项目类型集中在源码定义，未证实外部稳定 schema | [上游仓库](https://github.com/tbillington/kondo)、[Changelog](https://github.com/tbillington/kondo/blob/master/CHANGELOG.md) |
| **npkill** | Windows / macOS / Linux；开源 Node TUI | ✓ 递归找 `node_modules` 或指定目录名，计算大小并按大小/路径/年龄排序 | ✓ 键盘选择、范围/全选并删除目录；对疑似应用目录发警告 | — | — | ✓ TUI | △ 目录名级扫描，未找到标准横评 | △ 可换目标目录名，但无包管理器引用图或通用 cleaner SDK | [上游仓库](https://github.com/voidcosmos/npkill)、[官网](https://npkill.js.org/) |
| **cargo-cache / cargo-sweep** | Cargo/Rust 专用 CLI | ✓ cache 分类、大小；或按项目/工具链/年龄识别构建产物 | ✓ dry-run、选择 cache 类别、autoclean；sweep 可按天数/已安装工具链清理 | — | — | CLI | △ checksum/search/GC 等专用优化 | — 生态专用，不是通用插件 | [cargo-cache](https://github.com/matthiaskrgr/cargo-cache/blob/master/README.md)、[cargo-sweep](https://github.com/holmgr/cargo-sweep)、[Cargo clean](https://doc.rust-lang.org/cargo/commands/cargo-clean.html) |
| **Docker 原生命令** | Linux Docker Engine；Windows/macOS 常经 Docker Desktop；命令作用于所连 daemon | ✓ `docker system df -v` 按 daemon 对象报告 usage/reclaimable | ✓ `system prune` 清 unused container/network/image/build cache；volume 需显式 opt-in | — | — | CLI、confirmation/filters | ✓ 利用 daemon 对象图，而非扫描宿主路径 | 适合作为外部 adapter | [安装平台](https://docs.docker.com/engine/install/)、[`system df`](https://docs.docker.com/engine/reference/commandline/system_df/)、[prune](https://docs.docker.com/engine/manage-resources/pruning/) |
| **pnpm / uv 原生命令** | 各自支持 Windows / macOS / Linux；官方 CLI | ✓ 根据 store/cache 元数据识别内容 | ✓ `pnpm store prune` 清 unreferenced package；`uv cache clean` 可全量/按包，`uv cache prune` 清 unused | — | — | CLI | ✓ 使用生态引用语义，仍需分别 benchmark | 适合作为外部 adapter | [pnpm 安装](https://pnpm.io/installation)、[pnpm store](https://pnpm.io/cli/store)、[uv 安装](https://docs.astral.sh/uv/getting-started/installation/)、[uv cache](https://docs.astral.sh/uv/concepts/cache/) |
| **Homebrew cleanup** | macOS / Linux；官方 CLI | ✓ `cleanup --dry-run` 可列出将移除项 | ✓ 移除 stale lock、过时下载与旧安装版本，支持 prune/age 控制 | — | — | CLI | ✓ 使用 Homebrew 自身安装元数据 | 适合作为外部 adapter | [Homebrew 首页](https://brew.sh/)、[Homebrew man page](https://docs.brew.sh/Manpage) |

### D. 商业可视化磁盘分析器

| 工具 | 平台与类别 | 扫描 | 专项清理 | 浏览器数据 | 安全删除 | 交互 | 性能 | 扩展能力 | 主要证据 |
|---|---|---|---|---|---|---|---|---|---|
| **WizTree** | Windows；商业（个人免费）GUI/CLI | ✓ 目录、treemap、largest/duplicate、CSV、MFT dump 导入/导出 | △ 可删文件，非语义化系统 cleaner | — | — | ✓ 树+treemap+筛选，CLI export | ✓ 本地 NTFS 可直接读 MFT，但快速路径需管理员；非 NTFS/非管理员走普通扫描 | △ 报告/命令行，无公开 cleaner SDK | [官网](https://www.diskanalyzer.com/)、[About](https://diskanalyzer.com/about)、[Guide](https://diskanalyzer.com/guide) |
| **TreeSize Free / Personal / Professional** | Windows 客户端；商业分级 | ✓ 层级、treemap、filter、报告；高版本含 old/large/temp/duplicate、远端/云 | △ 高版本可批量删/移/归档与 link 去重；必须按 edition 标注 | — | — 未证实 | ✓ GUI；Professional 有 CLI/schedule/report | △ 平台特化扫描；未找到独立横评 | △ filter/report/automation；无公共 cleaner plugin API | [功能页](https://www.jam-software.com/treesize/features.shtml)、[版本比较](https://www.jam-software.com/treesize/editions.shtml)、[重复项工作流](https://www.jam-software.com/treesize/find-remove-duplicate-files.shtml) |
| **DaisyDisk** | macOS；商业 GUI | ✓ radial map、drill-down、Quick Look；主张按物理占用，hard link/APFS clone 只计首次，网络盘例外；另展示 hidden/purgeable/snapshot | △ Collector 收集后永久删除；阻止若干系统/root 目录 | — | — 未证实 secure erase | ✓ “收集篮 + 倒计时”式慎重交互 | △ 平台专用；没有公开可复核基准 | — 无 CLI/API/plugin 证据 | [官网](https://daisydiskapp.com/)、[规格](https://daisydiskapp.com/specs)、[删除指南](https://daisydiskapp.com/guide/deleting-files)、[hard links](https://daisydiskapp.com/manual/4/en/Topics/HardLinks.php)、[APFS clones](https://daisydiskapp.com/guide/apfs)、[snapshots](https://daisydiskapp.com/guide/time-machine) |

## 逐维度观察

### 1. 扫描

**事实：**通用分析器主要依赖目录遍历；`dua-cli`/gdu 明确采用并行策略，WizTree 在 Windows/NTFS/管理员条件下可走 MFT 快速路径。Czkawka 将廉价元数据过滤与昂贵内容哈希分阶段；ncdu、gdu、QDirStat 支持保存或导入扫描。

**推导：**不应只有一个“最快扫描器”。可移植 walker 是基线；SSD 可选有界并行；Windows/NTFS 可选 MFT 后端；内容哈希应按需进入第二阶段。冷/热缓存、HDD/SSD、网络盘、权限错误和文件数量都会改变结果。

**建议：**默认只读元数据扫描；记录扫描根、时间、平台、文件系统、边界策略、错误与版本。保存的报告必须标为 snapshot。

### 2. 专项清理

**事实：**BleachBit 的规则知道应用数据结构；Kondo 知道项目签名；Docker、pnpm、uv 等原生命令知道引用关系；普通磁盘分析器通常只知道路径和大小。

**推导：**“路径位于 cache 目录”不等于“当前未被引用”。原生生态命令的 unused/refcount 语义通常优于泛化的路径删除。

**建议：**cleaner 输出 `id、候选路径/对象、理由、规则版本、logical/allocated estimate、置信度、可恢复性、所需权限`；优先调用或复刻稳定的生态语义，并将要执行的原生命令完整展示。

### 3. 浏览器数据

**事实：**BleachBit、CCleaner、CleanMyMac 都区分若干浏览器数据类别；BleachBit/CCleaner 还能保留选定 cookie。不同浏览器、profile、发行渠道和运行状态会改变可用能力。

**推导：**一个“清理浏览器”开关过于粗糙。cookie、活跃登录会话、密码、autofill、history、downloads、site storage、cache、打开标签恢复数据的风险完全不同。同步开启时，本地操作还可能传播到云端。

**建议（由最终安全设计收紧）：**按浏览器与 profile 展开；默认只建议 cache；登录态、密码、autofill、session restore 和站点数据分别确认。运行中或运行状态无法确认的 profile 一律不做文件级修改；浏览器支持的官方 UI/API 是首选。SQLite online backup 最多只能为单个数据库提供只读分析快照，不能形成跨存储一致性、不能授权清理，也不能成为绕过运行中检查的“事务策略”。

### 4. 安全删除

**事实：**BleachBit 与若干商业工具提供覆写或“shred”功能，但查阅资料没有证明单文件覆写能覆盖 SSD wear levelling/TRIM、APFS/Btrfs/ReFS COW/reflink、快照、日志、备份、云同步或坏块重映射中的其他副本。

**推导：**“多次覆写”不是现代跨平台的通用不可恢复保证。它还可能制造额外 SSD 写入。

**建议：**普通清理优先 Trash/Recycle Bin；永久删除单独确认。SweepX 不提供文件覆写/shred 选项，因为它无法形成跨现代介质的可靠保证。设备退役只应提供指向平台/设备级 cryptographic erase 或 sanitize 流程的说明，不由 SweepX 执行，也不能把文件 shred 包装成等价方案。

### 5. 交互

**事实：**TUI 产品证明键盘浏览、排序、多选和逐项删除可行；DaisyDisk 的 Collector、BleachBit preview、rmlint 生成脚本、Czkawka dry-run 都提供了不同程度的“先审后做”。ncdu 导入报告禁用 live action，QDirStat 也警告不要对远端 cache report 运行本地 cleanup action。

**建议：**CLI 与 TUI 共享同一动作计划格式。TUI 只编辑选择，不直接绕过计划层。确认页按风险/cleaner/volume 分组，显示不可恢复项、跨卷项、权限项、未知大小和正在使用项。导入报告只能浏览；恢复 live action 必须重新扫描并逐项核验身份。

### 6. 性能

**证据缺口：**截至研究日，没有找到覆盖这些产品、同时控制文件系统、介质、冷热 cache、文件数、权限、symlink/hardlink 策略、线程数和峰值 RSS 的可信 apples-to-apples benchmark。

**建议：**自己的 benchmark 至少公开 corpus、平台/文件系统、介质、冷/热 cache、逻辑与 allocated 口径、错误数量、链接策略、并发度、wall/CPU time 与 peak RSS。界面在扫描期间持续展示已扫描项、错误数、当前根和取消状态；网络/automount 路径设置超时和并发上限。

### 7. 扩展能力

**事实：**BleachBit CleanerML 是调查中最完整的 declarative cleaner precedent；QDirStat 的任意 cleanup command 最灵活但信任面最大；Czkawka 的 core/多前端是架构复用范例；Kondo 与 `ariefsn/dust` 主要靠编译期源码扩展。

**建议（由最终架构裁决）：**优先受限声明式 schema（平台条件、路径变量、glob、年龄、大小、owner、应用运行检测、preview 描述、风险、引用验证），schema 验证后才运行。QDirStat 式任意 cleanup command 只作为竞品风险案例，**不进入 SweepX v1**；规则不得携带任意脚本或 shell 片段。确需领域语义时，只允许核心内置或受审计、能力受限的固定 executable + argv template adapter，并受普通用户权限、超时、输出上限、签名、版本、审计和统一安全状态机约束。签名/来源与规则版本必须进入动作计划。

## 值得借鉴的设计

1. **ncdu 的 snapshot 安全边界**：导入结果只可浏览，防止对陈旧路径动作。
2. **BleachBit 的同构 preview/clean selector 与 CleanerML**：预览和执行解析同一规则，降低“预览一套、执行另一套”的漂移。
3. **DaisyDisk Collector / rmlint action script**：让候选集合成为可检查的中间产物。
4. **Czkawka 的 core + 多前端**：扫描、判定和身份校验在一个核心实现，CLI/TUI 只是 surface。
5. **gdu/ncdu 的导出与过滤**：支持可重复分析和大规模环境的离线审阅。
6. **生态原生 prune**：把 Docker volume、pnpm store 引用、uv unreachable cache 等领域知识留给最了解状态的工具。
7. **WizTree 的可选特化后端**：平台快速路径可以存在，但不能成为跨平台语义的唯一实现。
8. **保留清单**：cookie/session、工作区、固定 cache 等应能单独 keep；排除规则要在 preview 中说明命中原因。

## 应避免的设计

1. 扫描完成后提供未经逐项身份复核的“一键删”。
2. 把 inaccessible、offline、timeout、provider failure 计作 0 字节。
3. 用 logical size 承诺“将释放 X GB”。
4. 导入旧报告后直接删除对应路径。
5. 默认跨 symlink、junction/reparse point、mount、network 或 automount。
6. 把无法放入回收站静默降级成永久删除。
7. 用最后访问时间单独判断“未使用”；平台可能禁用/延迟该时间。
8. 将整个“浏览器数据”合成一个 checkbox，或在浏览器运行时盲删数据库。
9. 宣称文件覆写能保证 SSD/COW/快照环境不可恢复。
10. 默认以 root/Administrator 扫描，或为提高覆盖率自动提权、接管 ownership、修改 ACL。
11. 把可执行任意 shell 的扩展与声明式 cleaner 赋予相同信任等级。
12. 用厂商“最快”口号代替可复现实验，或把远程扫描能力写成本机平台支持。

## 建议的最小产品边界

```text
read-only scanner -> immutable scan report -> cleaner evaluation
                  -> reviewable action plan -> revalidation
                  -> platform trash adapter -> observed outcome
```

- **Scanner**：跨平台 metadata walker；默认不跟随链接、不跨卷；logical 与 allocated 分列；错误是一等数据。
- **Cleaner registry**：版本化 declarative rules + 小规模受审计 native adapters。
- **Plan**：JSON/文本均可导出；列出每个动作的来源、证据、风险与回滚方式。
- **Executor**：按平台调用回收站接口；每项执行前重验 identity/root/mount/type；没有静默永久删除。
- **UI**：CLI 适于 CI/report；TUI 适于浏览与选择；两者不得复制清理判定逻辑。
- **Telemetry/benchmark**：本地可见、默认最小化；性能结论附环境，不上传路径或浏览器敏感数据。

## 证据缺口与保守表述

- 未找到可信的 2026 跨产品统一性能基准；只可说某工具“采用并行/MFT/cache”，不可据此断言整体最快。
- 商业产品能力常随 edition、商店渠道和平台变化；发布比较前需按具体版本复核。
- diskonaut 的维护谱系、Stacer 后继项目状态及处于 public beta 的 CleanMyMac CLI 接口均可能变化，应显式 pin 版本/仓库；`dua-cli` 虽提供 Windows binary/Scoop/WinGet，但源码安装仍依赖 nightly Rust。
- cleaner 数量与受支持应用列表变化快；只可作为带日期快照，不能当长期兼容承诺。
- “未找到 plugin API”只是本次一手资料审阅的缺口，不是不存在的证明。
- 安全删除缺少跨 SSD、快照、reflink、加密、云同步、备份与固件重映射的通用保证；默认降级为“不保证其他副本不可恢复”。
- 浏览器内部 schema 与锁策略会更新；没有浏览器/版本级验证时，只做 dry-run 并跳过。
- 扫描工具展示的“size on disk”不必等于删除后的 free-space 增量；平台细节见 [platform-filesystems.md](platform-filesystems.md)。

## 开源证据快照

为避免上游默认分支在研究后移动，下表记录了 2026-08-26 实际解析到的 HEAD。正文中的 README/源码能力描述应与这些快照一起阅读；这不是对未来版本的承诺。商业产品采用当日可访问的厂商页面，并在矩阵中保留 edition/channel 限定。

| 项目 | 研究时默认分支 HEAD | 固定快照 |
|---|---|---|
| `bootandy/dust` | `8a846f6689f2` | [commit](https://github.com/bootandy/dust/tree/8a846f6689f2db6be6ef595239a21ec784d62b57) |
| `Byron/dua-cli` | `7baa9266a593` | [commit](https://github.com/Byron/dua-cli/tree/7baa9266a593fd6b7f7568c741798d76660eb3ab) |
| `dundee/gdu` | `c01721a9afa0` | [commit](https://github.com/dundee/gdu/tree/c01721a9afa01a1280772dccd778796d8394d807)；矩阵另固定 release `v5.37.0` |
| `imsnif/diskonaut` | `65cd829069e2` | [commit](https://github.com/imsnif/diskonaut/tree/65cd829069e275dc8a3e4493d0da7f8f08055d82) |
| `shundhammer/qdirstat` | `f4a37d961da7` | [commit](https://github.com/shundhammer/qdirstat/tree/f4a37d961da75acb1dc3f8ec9c935b34c35c8757) |
| `qarmin/czkawka` | `105a520bab59` | [commit](https://github.com/qarmin/czkawka/tree/105a520bab59d8a0064770b3dbcba0ab47abe59e) |
| `sahib/rmlint` | `b311f38dab01` | [commit](https://github.com/sahib/rmlint/tree/b311f38dab01585a138ed0f3ac14d2b426d12523) |
| `oguzhaninan/Stacer` | `a44d0565a05c` | [commit](https://github.com/oguzhaninan/Stacer/tree/a44d0565a05c996b1058f950f1d308e1964c8320) |
| `ariefsn/dust` | `df2d67c8ac90` | [commit](https://github.com/ariefsn/dust/tree/df2d67c8ac90dabea8788f1cb4e58d192c826639) |
| `tbillington/kondo` | `1d351ca80b3d` | [commit](https://github.com/tbillington/kondo/tree/1d351ca80b3d3adfad9bbe7db872c27359190210) |
| `voidcosmos/npkill` | `2dad63647fdd` | [commit](https://github.com/voidcosmos/npkill/tree/2dad63647fdd6887e9022c8d22887fe5606eb92f) |
| `matthiaskrgr/cargo-cache` | `2f4497beeab9` | [commit](https://github.com/matthiaskrgr/cargo-cache/tree/2f4497beeab989becd2ecdae8a42601956e822b0) |
| `holmgr/cargo-sweep` | `94a7cf012d40` | [commit](https://github.com/holmgr/cargo-sweep/tree/94a7cf012d40d314896c0fa6986132b0a1e931ba) |
| `MacPaw/cleanmymac-cli` | `6f5f64c6a606` | [commit](https://github.com/MacPaw/cleanmymac-cli/tree/6f5f64c6a60655024456ff61cd49f0bc72916e89)；public beta |

## 额外一手资料索引

以下 URL 同样于 2026-08-26 访问：

- Microsoft，Windows 释放磁盘空间与 Storage Sense：<https://support.microsoft.com/en-US/Windows/experience/storage-filemanagement/free-up-drive-space-in-windows>
- Apple，在 Mac 上查找和删除文件：<https://support.apple.com/guide/mac-help/find-and-delete-files-on-your-mac-syspf5a64aa6/mac>
- npm cache（官方文档强调 cache 通常无需清空，`verify` 会校验并 GC）：<https://docs.npmjs.com/cli/v11/commands/npm-cache/>
- Cargo clean：<https://doc.rust-lang.org/cargo/commands/cargo-clean.html>
- Go command/cache 文档：<https://go.dev/src/cmd/go/alldocs.go>
