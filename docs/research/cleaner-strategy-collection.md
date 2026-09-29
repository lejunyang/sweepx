# 垃圾扫描策略收集

收集对象：

- [harry0703/MangoDisk](https://github.com/harry0703/MangoDisk)
- [Tencent/lemon-cleaner](https://github.com/Tencent/lemon-cleaner)

收集日期：2026-09-29。

## 许可证兼容性

SweepX 已改为 **GPL-3.0-only**。因此可以在遵守 GPL-3.0 条款的前提下，收集、研究并在同类 copyleft 项目中改编 MangoDisk 的 GPL-3.0 策略。

Lemon Cleaner 是多许可证仓库：

- Lemon Cleaner / Lemon Monitor：GPL-3.0-only；
- LemonDaemon：GPL-2.0-only；
- 第三方组件按其各自许可证。

SweepX 可以采纳 GPL-3.0 模块中的策略；不应把 LemonDaemon 的 GPL-2.0-only 代码或文本混入 GPL-3.0-only 项目后再按 GPL-3.0 分发。若未来需要 LemonDaemon 能力，应独立实现，或单独处理 GPL-2.0 的兼容性和分发义务。

## MangoDisk 策略概览

MangoDisk 的规则位于 `src-tauri/crates/mangodisk-core/rules/filesystem`，以 TOML 表达。当前快照共 244 条规则：

| 平台 | system | browser | application | development | ai | container | 合计 |
|---|---:|---:|---:|---:|---:|---:|---:|
| Linux | 6 | 0 | 21 | 0 | 0 | 0 | 27 |
| macOS | 10 | 12 | 61 | 39 | 2 | 1 | 125 |
| Windows | 6 | 17 | 38 | 28 | 2 | 1 | 92 |

### 规则结构

MangoDisk 的每条规则包含以下关键部分：

- `id`、`schema_version`、`rule_version`：规则身份与版本。
- `platform`、`category`：平台和分类。
- `risk`：风险级别，例如 `safe`、`recoverable`。
- `default_selected` / `recommended_selected`：默认和推荐选择状态。
- `required_stopped_processes`：要求关闭的进程。
- `applicability`：应用是否安装、root 是否存在、可执行文件是否可用等适用条件。
- `roots`：受控根路径模板、动态子目录和路径类型。
- `matcher`：root 内对象的匹配逻辑。
- `execution`：删除整个 root、仅删除匹配内容等执行策略。
- `verification`：生命周期、证据、验证日期、平台和参考链接。

### macOS 策略分类

MangoDisk macOS 规则覆盖：

1. **system（10 条）**：用户临时目录、旧诊断日志、Apple 媒体缓存、地理服务缓存、帮助缓存、Darwin 用户缓存、断点下载、Apple Intelligence、parsecd、QuickLook。
2. **browser（12 条）**：Opera、Edge、Firefox、Arc、Brave、Chromium、Chrome、Vivaldi、360、UC、Chrome offline 等浏览器缓存。
3. **application（61 条）**：微信、QQ、钉钉、Slack、Telegram、Discord、Notion、Figma、Postman、Zoom、Office、WPS、腾讯会议、网易系/爱奇艺/优酷等渲染或更新缓存。
4. **development（39 条）**：Cargo、npm、pnpm、yarn、Bun、Deno、Go、Gradle、Maven、NuGet、uv、pip、Homebrew、CocoaPods、Xcode、Android、JetBrains、VS Code、sccache、ccache 等开发缓存。
5. **ai（2 条）**：Hugging Face Xet、Claude Code。
6. **container（1 条）**：Docker Desktop 诊断缓存。

### 可直接借鉴的策略原则

- 所有清理对象必须落在受控 `roots` 内，不接受用户传入路径的上级泛化。
- 动态浏览器/应用 profile 只选择固定缓存后缀，如 `Cache`、`Code Cache`、`GPUCache`、`DawnCache`、`GrShaderCache`、`GraphiteDawnCache`。
- 浏览器 profile 中的 cookie、history、password、bookmark、extension、Local Storage、IndexedDB 不进入缓存规则。
- 临时目录需要年龄门槛，并排除数据库、plist、密钥、文档、图片等可能有持久价值的对象。
- 开发工具缓存必须证明可通过包管理器、编译器或工具链重新下载/重建。
- 每条规则必须保留验证证据、日期、平台和参考链接。

## Lemon Cleaner 策略概览

Lemon Cleaner 的垃圾策略主要位于：

- `LemonClener/LemonClener/libcleaner/garbage1_zh.xml`
- `LemonClener/LemonClener/libcleaner/garbage1_en.xml`
- `LemonClener/LemonClener/libcleaner/garbage_appstore_zh.xml`
- `LemonClener/LemonClener/libcleaner/garbage_appstore_zh.xml`
- `LemonClener/LemonClener/libcleaner/garbage_appstore_en.xml`

其规则模型由三部分组成：

1. `<filters>`：可复用过滤器。
2. `<category>`：面向用户的分类。
3. `<item>` / `<action>` / `<path>` / `<atom>`：具体应用、动作、路径和过滤器组合。

### 用户可见分类

Lemon Cleaner 将垃圾分成三类：

1. **系统垃圾**
   - 系统缓存；
   - 系统日志；
   - 无用语言文件；
   - iOS 照片缓存；
   - iOS 软件升级数据；
   - iOS 设备备份；
   - 废纸篓；
   - 下载。

2. **应用垃圾**
   - Xcode：app 缓存、DerivedData、iOS/macOS Device Support、Archives、Device Logs、DocumentationCache、Simulator、Simulator Runtimes；
   - Sketch：应用缓存、日志、修订缓存相关排除；
   - 其他上百款应用的定制方案。

3. **上网垃圾**
   - Mail 附件缓存；
   - Safari；
   - Chrome；
   - QQ 浏览器；
   - Opera；
   - Firefox；
   - Microsoft Edge；
   - LaunchServices 下载检疫日志。

### 高价值防护项

Lemon 的 filter 列表记录了大量误删案例，后续规则实现应优先保留这些 blocker：

- 不清理 `com.apple.dock`、`com.apple.appstore`、`com.apple.LaunchServices-*`、`com.apple.Safari`、`com.apple.Spotlight` 等系统活动目录。
- 不把 `~/Library/Caches/Metadata/` 整体作为垃圾。
- 不处理 `DiagnosticReports`。
- 不跨浏览器品牌做名称泛化。
- `1Password`、`IINA`、`Aerial`、`com.apple.appstoreagent`、`codes.rambo.AirCore` 等路径加白。
- 不清理 `.app` 包内部内容。
- `~/Library/Containers/com.tencent.qq`、`~/Library/Containers/com.tencent.xinWeChat` 等容器不能按根目录整体处理。
- 桌面图片、ColorSync 等系统缓存排除。

## 合并后的 SweepX 策略路线

建议按风险和可验证性分批移植/重写，而不是一次性导入全部 244 条 MangoDisk 规则和 Lemon XML：

1. **第一批：低风险、可重建缓存**
   - Cargo registry cache / git db；
   - npm/pnpm/yarn/Bun cache；
   - Go cache/module cache；
   - pip/uv cache；
   - Xcode DerivedData；
   - JetBrains/VS Code caches。

2. **第二批：浏览器渲染和网络缓存**
   - Chrome/Chromium/Edge/Brave/Arc/Vivaldi/Opera/Firefox；
   - 仅选择 profile 下固定 cache/GPU cache 后缀；
   - 要求浏览器关闭或明确处于只读扫描阶段。

3. **第三批：系统临时和日志**
   - 用户 temp；
   - 可再生系统日志；
   - 断点下载；
   - 缩略图和 QuickLook 缓存。
   - 每一类需要年龄、所有者、进程、symlink、mount 和 exclusion 检查。

4. **第四批：应用专属缓存**
   - 微信、QQ、钉钉、Slack、Telegram、Discord、Figma、Postman、Zoom 等；
   - 每个应用单独验证，不按品牌或目录名批量推断。

5. **暂缓项**
   - GPL-2.0-only 的 LemonDaemon 策略；
   - iOS 设备备份、下载、废纸篓；
   - 浏览器隐私数据；
   - 应用容器整体；
   - Docker/虚拟机/模拟器镜像；
   - 系统目录中的受保护数据库和状态文件。

## 已集成的第一批 macOS 策略

2026-09-29 已将以下 report-only 策略接入 `crates/sweepx-cli/resources/platform-junk-rules.json`，并由统一 `junk --system` 扫描路径发现。具体位置通过每条规则的 `knownRoots`（`base: home` + 相对 `components`）声明，发现代码只读这份数据，不再按 rule id 硬编码根路径；新增策略只需在 JSON 增加 `knownRoots`：

- `macos.xcode-derived-data`：`~/Library/Developer/Xcode/DerivedData`。
- `macos.cargo-registry-cache`：`~/.cargo/registry/cache` 与 `~/.cargo/git/db`。
- `macos.firefox-cache`：`~/Library/Caches/Firefox/Profiles`。
- `macos.chromium-cache`：`~/Library/Caches/Chromium`。
- `macos.safari-cache`：Safari cache、Safari metadata、CacheDeleteExtension、SafeBrowsing、safaridavclient。
- `macos.tencent-meeting-cache`：腾讯会议 WebKit `NetworkCache`。

这些规则仍然只产生报告，不会自动删除；删除能力必须另走不可变计划、实时重验和用户确认。

## 已集成的第二批 macOS 开发缓存

2026-09-29 继续从 MangoDisk 开发类规则改编 8 条，同样以 `knownRoots` 声明、report-only 运行：

- `macos.homebrew-cache`：`~/Library/Caches/Homebrew`。
- `macos.go-cache`：`~/Library/Caches/go-build` 与 `~/go/pkg/mod/cache/download`（不含 `pkg/mod` 中已解出的源码）。
- `macos.uv-cache`：`~/.cache/uv` 与 `~/Library/Caches/uv`。
- `macos.bun-cache`：`~/.bun/install/cache`。
- `macos.yarn-cache`：`~/Library/Caches/Yarn` 与 `~/.yarn/berry/cache`。
- `macos.gradle-cache`：`~/.gradle` 下 `caches`、`daemon`、`workers`、`notifications`、`wrapper/dists`、`.tmp`。
- `macos.jetbrains-cache`：`~/Library/Caches/JetBrains`。
- `macos.deno-cache`：`~/Library/Caches/deno`。

仍未纳入：npm 走已有跨平台 `tool.npm-cache`（按 `npm config get cache` 实测），MangoDisk 中硬编码 `~/.npm/_cacache` 的等价规则不重复收录；Maven `~/.m2/repository`、NuGet `~/.nuget/packages`、pnpm store 等被项目硬链接或属于依赖存储而非纯下载缓存的条目，按更高风险留待单独评估。

## 多份工具安装盘点（npm）

仅问 `PATH` 上第一份 npm 的 cache，无法回答系统里装了几份 npm、各自被谁管控、是否还在用。新增 `crates/sweepx-cli/src/tool_installations.rs`，按管理器的固定/版本目录布局枚举每一份 npm，并对每份可执行文件单独执行：

- 管控方 `manager`：`homebrew`、`nvm`、`fnm`、`volta`、`asdf`、`mise`、`n`，以及不在已知布局内的 `path`；
- 版本标签 `managerLabel`（如 nvm 的 `v20.19.0`）、npm 版本、同目录 Node 版本；
- 这份 npm 自己上报的 cache 目录及其最近修改时间 `cacheLastActiveAt`（取目录与一级子项的最新 mtime，RFC-3339）；
- 是否为裸命令解析到的默认项 `isPathDefault`（至多一个）。

这些字段在 `junk --system` JSON 顶层 `toolInstallations` 中输出，report-only；发现 npm cache 候选时也会汇总每份安装各自上报的 cache，而不是只信第一份。

实测（本机，2026-09-29）：共 14 份 npm —— 1 份 Homebrew（npm 11.17.0 / Node v26.5.0，`isPathDefault=true`）+ 13 份 nvm 版本（v12 到 v24）。关键现象：14 份 npm 上报的 cache **全部是同一个目录** `~/Desktop/osdk-home/cache/pkg/npm`，因为本 shell 注入了全局 `NPM_CONFIG_CACHE`；其 `cacheLastActiveAt` 都是扫描当下。这说明“多份 npm”在本机并不等于“多份 cache”——是否真有多份 cache 取决于配置，盘点的价值正是把“安装多份”和“cache 多份”分开呈现，而不是按安装数臆造垃圾。若未注入该变量，各 nvm 版本默认共享 `~/.npm`，自定义 per-install cache 才会产生多份。

## 已集成的第三批：Application Support 侧浏览器派生缓存

实测发现 macOS 的 Chromium 派生缓存主要不在 `~/Library/Caches`，而在 `~/Library/Application Support/<browser>` 下，分两类：

- 与 profile 并列、整个安装共享：`ShaderCache`、`GrShaderCache`、`GraphiteDawnCache`、`GPUPersistentCache`、`component_crx_cache`、`extensions_crx_cache`；
- 每个 profile 内部：`GPUCache`、`DawnGraphiteCache`、`DawnWebGPUCache`。

为避免“一个浏览器一个代码分支”，规则新增数据结构 `browserCaches`（`BrowserCacheSpec`：anchor + userData 路径 + sharedCaches + profileCaches），由统一发现逻辑展开；profile 名（`Default` / `Profile N`）从磁盘枚举而非写死。新增 matchKind `verified_browser_cache`、rootKind `macos_browser_derived_cache`。

新增 report-only 规则 `macos.browser-derived-cache`，一条规则内用 7 个 spec 覆盖 Chrome、Edge、Brave、Arc、Vivaldi、Opera、Chromium。仅当目录真实存在时报告；`Cookies`、`History`、`Login Data`、`Bookmarks`、`Local Storage`、`IndexedDB`、Service Worker `CacheStorage` 等持久数据一律不进入任何 spec，并有测试强制。

实测（本机，2026-09-29）：Chrome 与 Edge 都齐了 6 个共享缓存 + Default 下 3 个 profile 缓存；目录内部为 blockfile（`data_0..3` + `index`）或内容寻址（`f_*` / 哈希目录），符合“可由 GPU 进程与组件更新器重建”的判定。Arc/Brave/Vivaldi/Opera/Chromium 在本机未安装，对应 spec 只是数据、不产生结果——这正是数据驱动的目的，装上即自动覆盖，无需改代码。

随后实测本机已装的两款内嵌 Chromium 的应用，发现 profile 约定不止 `Default`/`Profile N`，于是把 `BrowserCacheSpec` 扩展为支持三种 profile 发现方式（仍是纯数据）：

- `profileNames`：显式 profile 名，如 LarkShell 的 `IronDefault`（外加枚举到的 `Default`）；
- `enumerateNamedProfiles`：是否枚举 `Default`/`Profile N`（默认 true）；
- `partitionContainers`：容器目录，其每个实目录子项都算一个 partition，适配 Postman 用 UUID 命名的 `Partitions`。

据此在同一条 `macos.browser-derived-cache` 规则里追加了 LarkShell 与 Postman 两个 spec：LarkShell 取安装共享的 `ShaderCache/GrShaderCache/GraphiteDawnCache/CodeCache` 及各 profile 内派生缓存；Postman 取顶层与每个 UUID partition 下的 `Cache/Code Cache/GPUCache/Dawn*`。两者的 `Cookies`、`Local Storage`、`IndexedDB`、`Service Worker` 等仍被排除。

实测（本机，2026-09-29）：展开结果覆盖 Postman 多个 UUID partition 各自的 `Cache`（数量与磁盘一致），并命中 LarkShell 的 `GrShaderCache`；展开结果去重、且不含任何 `/Cookies` 路径，有测试逐项核对。

## 落地要求

每条进入 SweepX 的策略必须同时满足：

1. 许可证来源清晰，优先使用 MangoDisk GPL-3.0 规则与 Lemon GPL-3.0 模块。
2. 路径所有权和可重建性有第一方/官方资料证明。
3. 明确保留数据边界。
4. 先以 report-only 规则运行，不直接进入删除计划。
5. 删除前另经不可变计划、实时身份重验、用户确认和平台能力 gate。
6. 保留来源、验证日期、参考链接和适配说明。
