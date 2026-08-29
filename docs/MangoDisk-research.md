# MangoDisk 深度调研报告

> **调研对象**：[harry0703/MangoDisk](https://github.com/harry0703/MangoDisk)
> **调研版本**：commit `7c8ffc3`（2026-08-27）
> **技术栈**：Tauri 2 + Rust（后端 3 crate）+ Vue 3 / TypeScript（前端）
> **许可证**：GPL-3.0
> **调研范围**：垃圾/缓存识别规则体系、规则来源与验证机制、全量规则清单、扫描加速方案、重复文件识别算法
> **代码引用格式**：所有引用均为 `路径:行号` 格式，基于上述 commit 可直接定位

---

## 目录

- [一、项目架构总览](#一、项目架构总览)
- [二、规则体系设计：三层清理模型](#二、规则体系设计-三层清理模型)
- [三、规则从何而来：来源与验证机制](#三、规则从何而来-来源与验证机制)
- [四、Schema 规范：规则的表达能力边界](#四、schema-规范-规则的表达能力边界)
- [五、安全护栏：不可绕过的硬约束](#五、安全护栏-不可绕过的硬约束)
- [六、全量规则清单（205 声明式 + 31 项目 + 24 专用）](#六、全量规则清单)
- [七、扫描加速：七层优化体系](#七、扫描加速-七层优化体系)
- [八、重复文件识别：四级漏斗算法](#八、重复文件识别-四级漏斗算法)
- [九、总结与可借鉴设计](#九、总结与可借鉴设计)

---

## 一、项目架构总览

### 1.1 Crate 分层

| Crate | 路径 | 职责 |
|-------|------|------|
| `mangodisk-core` | `src-tauri/crates/mangodisk-core/` | 业务核心：清理引擎、规则解析、去重、大文件、磁盘分析、卸载、启动项 |
| `mangodisk-platform` | `src-tauri/crates/mangodisk-platform/` | 平台抽象：Windows/macOS 原生 API 封装（NTFS、USN、getattrlistbulk 等） |
| `mangodisk-cli` | `src-tauri/crates/mangodisk-cli/` | 命令行入口（`mangodisk clean` 等） |
| 主 Tauri 壳 | `src-tauri/src/` | Tauri command 注册、服务编排 |

### 1.2 核心模块规模

```
src/cleanup/service.rs                      11061 行   清理服务主编排
src/applications/uninstall/service.rs        3153 行   应用卸载
src/system_settings/catalog.rs               2514 行   系统优化项目录
src/cleanup/cleaners/project_artifacts.rs    2235 行   项目产物清理
src/filesystem/permanent_delete.rs           2101 行   受保护删除事务
src/storage/duplicates/service.rs            1991 行   重复文件识别
src/cleanup/rules/declarative_schema.rs      1755 行   声明式规则 schema 校验
src/cleanup/scan.rs                          1518 行   清理扫描调度
src/storage/traversal.rs                     1207 行   文件系统遍历引擎
```

规则资源本身：`rules/` 目录共 **237 个文件、10249 行 TOML**。

---

## 二、规则体系设计：三层清理模型

MangoDisk 的核心设计思想是：**把"普通清理行为"下沉为可校验的声明式数据，只把"必须写代码"的场景留给 Rust**。这一分层在贡献指南中被明确定义。

> 引用 `src-tauri/crates/mangodisk-core/rules/README.md:1-8`：
> "MangoDisk keeps ordinary cleanup behavior in validated TOML resources... If cleanup requires a system command, an application API, shared-resource coordination, or special high-impact confirmation, implement a dedicated cleaner instead of **weakening the declarative safety model**."

### 2.1 三层模型对比

| 层级 | 载体 | 数量 | 适用场景 | 判定标准（`rules/README.md:9-12`） |
|------|------|------|---------|-------------------------------|
| **第 1 层：声明式文件系统规则** | TOML（schema v3） | **205 条** | 已知的缓存、日志、崩溃报告、临时目录 | 由 OS / 已安装应用 / 开发工具拥有的可丢弃位置 |
| **第 2 层：项目产物规则** | TOML（schema v1） | **31 条**（69 个产物目录） | 源码项目内可重建的输出 | 如 `target`、`node_modules`、框架构建缓存 |
| **第 3 层：专用 Cleaner** | Rust 代码 | **24 个** | 需要应用特定逻辑的场景 | 需系统命令、提权、共享 blob 感知、执行前即时校验 |

### 2.2 目录布局强制约定

路径结构被构建期强制校验为 `filesystem/<platform>/<category>/<rule-id>.toml`（`rules/README.md:31`）：

```
rules/
├── filesystem/
│   ├── macos/          {system, browser, application, development, ai, container}
│   └── windows/        {system, browser, application, development, ai, container}
└── project-artifacts/  {rust.toml, node.toml, python.toml, ...}
```

### 2.3 构建期嵌入 + 运行期二次校验（双重校验）

这是一个值得注意的设计：规则在**构建期校验并嵌入二进制**，运行期**再次解析同一 schema**。

> 引用 `src-tauri/crates/mangodisk-core/build.rs:20-53`：
> ```rust
> let rules_directory = manifest_directory.join("rules");
> println!("cargo:rerun-if-changed={}", rules_directory.display());
> let owned_sources = load_rule_sources(&filesystem_rules_directory, "filesystem cleanup")
>     .unwrap_or_else(|error| panic!("failed to load filesystem cleanup rules: {error}"));
> write_embedded_sources("embedded-cleanup-rules.rs", ...)
> ```
> 注意 `build.rs:6` 通过 `#[path = "src/cleanup/rules/declarative_schema.rs"]` 直接复用运行期的 schema 代码，保证构建期与运行期校验逻辑**完全同源**。

运行期再解析一次：

> 引用 `src-tauri/crates/mangodisk-core/src/cleanup/rules/declarative_catalog.rs:20,49-51`：
> ```rust
> include!(concat!(env!("OUT_DIR"), "/embedded-cleanup-rules.rs"));
> // Re-parse embedded sources at runtime to preserve the validation boundary
> let parsed = parse_catalog(EMBEDDED_DECLARATIVE_RULE_SOURCES)?;
> ```

**设计意图**：任何绕过 schema 的规则都无法通过编译；同时运行期不信任构建产物，再次校验安全边界。

---

## 三、规则从何而来：来源与验证机制

这是本次调研的核心问题之一。结论是：**规则由项目独立维护，第三方项目仅作为"线索"，每条规则必须有权威依据 + 真实系统验证**。

### 3.1 官方立场声明（明确排除"抄清单"）

> 引用 `README.zh-CN.md:95`：
> "清理规则由 MangoDisk **独立维护**。第三方项目**只用于提供线索**，候选规则必须核对可靠来源、明确安全边界，并通过**真实系统验证**后才会收录。无法确认安全的内容不会加入规则库。"

> 引用 `README.md:95`（英文原文）：
> "MangoDisk maintains its own cleanup rules. Third-party projects may provide **research leads**, but a candidate rule is only accepted after **reliable sources, safe boundaries, and real-system behavior** have been verified. Anything without a clear safety boundary is excluded."

即：**没有从 CCleaner / BleachBit / CleanMyMac 等项目直接移植规则清单**，第三方只用于发现"哪里可能有缓存"，具体边界必须自行核实。

### 3.2 每条规则强制携带 `[verification]` 区块

> 引用 `rules/README.md` 中的规则模板（`rules/README.md:60-66`）：
> ```toml
> [verification]
> lifecycle = "verified"
> evidence = "Example stores reproducible cache data in this directory; settings, credentials, projects, and user-created content remain outside the selected root"
> verified_at = "2026-08-05"
> verified_platform = "macos"
> references = ["https://example.com/official-cache-documentation"]
> ```

字段语义（`rules/README.md` "Verification" 节）：

| 字段 | 约束 | 作用 |
|------|------|------|
| `lifecycle` | 生产库只接受 `verified` / `stable` / `deprecated`；**`candidate` 和 `disabled` 被拒绝** | 阻止未验证规则进入正式版 |
| `evidence` | 必须解释**为什么数据可丢弃** + **边界外保留了什么重要数据** | 强制作者论证安全性 |
| `verified_at` | `YYYY-MM-DD` | 可追溯验证时间 |
| `verified_platform` | 必须与规则 `platform` 一致 | 防止跨平台假验证 |
| `references` | 有权威 HTTPS 来源时必须添加 | 提供第一方依据 |

**实测统计（全部 205 条 filesystem 规则）**：

- `lifecycle`：**205 条全部为 `verified`**，无一例外
- `verified_at`：2026-07 共 115 条，2026-08 共 90 条（规则库为近期集中验证建立）
- 携带 `references` 的规则：**190 / 205（92.7%）**，共 **318 条外部引用链接**
- 未带 references 的 15 条（如 `system.directx-shader-cache`、`system.stale-partial-downloads`、`app.wechat-diagnostic-cache`）改为在 `evidence` 中做文本论证

### 3.3 引用来源的权威性分布（含项目产物规则，共 369 条引用）

| 来源域名 | 引用次数 | 性质 |
|---------|---------|------|
| `chromium.googlesource.com` | 52 | Chromium 官方源码文档（`user_data_dir.md` 等） |
| `github.com` | 38 | 上游项目官方仓库/文档 |
| `developer.apple.com` | 37 | Apple 官方开发者文档 |
| `learn.microsoft.com` | 23 | 微软官方文档 |
| `www.electronjs.org` | 19 | Electron 官方文档 |
| `docs.astral.sh` | 7 | uv / ruff 官方文档 |
| `support.mozilla.org` | 4 | Mozilla 官方支持 |
| `developer.android.com` / `doc.rust-lang.org` / `go.dev` / `docs.gradle.org` / `docs.npmjs.com` | 各 4 | 各语言官方文档 |
| 其余 | — | `docs.docker.com`、`maven.apache.org`、`www.jetbrains.com`、`mypy.readthedocs.io`、`im.qq.com`、`browser.360.cn`、`www.wps.cn` 等**第一方官网** |

**关键观察**：引用几乎全部指向**第一方官方文档**，而非第三方清理软件的规则库或博客。国内应用（QQ、WPS、360）也引用其官方站点。

### 3.4 典型实例：pnpm 缓存规则的完整依据链

> 引用 `rules/filesystem/macos/development/dev.pnpm-cache.toml`（全文）：
> ```toml
> id = "dev.pnpm-cache"
> schema_version = 3
> rule_version = 3
> platform = "macos"
> category = "development"
> risk = "recoverable"
> default_selected = false
> recommended_selected = true
> required_stopped_processes = []
>
> [[applicability]]
> kind = "anyOf"
> items = [
>   { kind = "executableAvailable", names = ["pnpm"] },
>   { kind = "anyRootExists" },
> ]
>
> [[roots]]
> template = "${user_library}/pnpm/store"
> verified_rebuildable = true
>
> [[roots]]
> template = "${user_library}/Caches/pnpm"
> verified_rebuildable = true
>
> [matcher]
> kind = "all"
>
> [execution]
> kind = "deleteWholeRoot"
> requires_app_close = false
>
> [verification]
> lifecycle = "verified"
> evidence = "pnpm documents its store as content-addressable package data and provides store path, status, and prune operations; project manifests and configuration remain outside the selected roots"
> verified_at = "2026-07-20"
> verified_platform = "macos"
> references = ["https://pnpm.io/cli/store"]
> ```

可以看到完整的论证链：**官方文档证明 store 是内容寻址的包数据 → 官方提供 prune 操作 → 项目清单与配置在边界外 → 标注可重建 → 允许整根删除**。

### 3.5 规则版本演进机制

> 引用 `rules/README.md`（"Identity, selection, and risk" 节）：
> "`rule_version` must be positive. **Increment it when a change alters roots, matching, execution, risk, applicability, or verification semantics.**"

上例 `dev.pnpm-cache` 已是 `rule_version = 3`，说明规则边界经过多次迭代修正。

### 3.6 自动化校验闸门

> 引用 `rules/README.md`（"Validation" 节）：
> ```sh
> pnpm check:rule-sources
> cargo test --manifest-path src-tauri/Cargo.toml -p mangodisk-core declarative_schema
> cargo test --manifest-path src-tauri/Cargo.toml -p mangodisk-core project_artifact_schema
> ```
> "The build recursively validates all TOML resources, including schema fields, platform variables, risk, lifecycle, matchers, root boundaries, applicability, process policy, and **catalog overlap**. **Do not bypass a failure with a broader root, weaker matcher, or dedicated Rust branch for one rule ID.**"

注意最后一句：明确禁止"为单个规则 ID 开 Rust 特例分支"来绕过校验——这是防止安全模型被腐蚀的制度性约束。

另外规则注释与 evidence 被强制要求用英文，以便自动化源码检查（`rules/README.md`，"Rule comments and verification evidence are developer-facing text and must use English so the automated source check can validate a consistent public rule catalog"）。

---

## 四、Schema 规范：规则的表达能力边界

### 4.1 受控路径变量（禁止任意绝对路径）

规则**不能写死绝对路径**，必须以受控变量开头（`rules/README.md`，"Roots" 节）：

| 变量 | 平台 | 实测使用次数 |
|------|------|------------|
| `${local_app_data}` | Windows | 242 |
| `${application_support}` | macOS | 194 |
| `${user_library}` | macOS | 147 |
| `${roaming_app_data}` | Windows | 141 |
| `${home}` | 全平台 | 81 |
| `${program_data}` | Windows | 4 |
| `${temp}` | 全平台 | 2 |
| `${darwin_user_cache}` | macOS | 1 |
| `${program_files}` / `${system_root}` | Windows / 全平台 | 0（schema 支持但未使用） |

> `rules/README.md`：模板"must begin with one controlled, lowercase variable and use `/` separators"，且校验器"rejects **parent traversal**, uncontrolled variables, duplicate roots, protected locations, unsafe expansion, and broad matching outside recognized cache or verified rebuildable boundaries."

### 4.2 适用性探针（Applicability）——先判断"装没装"再决定扫不扫

每条规则**必须**至少有一个 `[[applicability]]` 探针。支持的探针类型（`rules/README.md`，"Applicability" 节）：

`anyRootExists`、`pathExists`、`applicationInstalled`、`applicationVersion`、`executableAvailable`、`systemVersion`、`fileSystemIn`、`capabilityAvailable`、`processRunning`，以及组合器 `anyOf` / `allOf` / `not`。

**关键安全语义（fail-open vs fail-closed 的精确处理）**：

> `rules/README.md`："Applicability avoids unnecessary traversal; **it never relaxes root or matcher safety**. A known-inapplicable rule is skipped, while **missing or incomplete inventory data keeps the rule eligible for scanning**."

即：探针只用于**性能剪枝**，不承担安全职责；清单数据不完整时**保持规则可扫描**（不因探测失败而漏扫）。

代码侧对应实现：

> 引用 `src/cleanup/cleaners/mod.rs:95-104`：
> ```rust
> // A missing executable is definitive only when inventory capture
> // completed. Partial inventory must fail closed as Limited.
> status: if inventory.executable_inventory_complete() {
>     CleanerPreviewStatus::NotApplicable
> } else {
>     CleanerPreviewStatus::Limited
> },
> ```

禁止的探针输入：`rules/README.md` 明确 "Arbitrary absolute paths, environment variables, and **command execution** are not valid applicability inputs."

### 4.3 匹配器（Matcher）种类与实测分布

支持的匹配器（`rules/README.md`，"Matchers and execution" 节）：
`all`、`nameEquals`、`nameGlob`、`extensionIn`、`pathSegmentIn`、`olderThan`、`largerThan`、`smallerThan`、`maxDepth`、`allOf`、`anyOf`、`not`

限制：名称匹配器只接受**名称而非路径**；`nameGlob` **不支持 `**`**；年龄/大小/深度数值必须 > 0。

**实测分布（205 条）**：

| 匹配器 | 数量 | 说明 |
|--------|------|------|
| `all` | 176 | 仅当根本身是狭义缓存或已验证可重建位置时才允许 |
| `allOf` | 10 | 组合约束（如 Downloads 残留下载） |
| `olderThan` | 7 | 时间闸门（如临时目录 3 天） |
| `pathSegmentIn` | 5 | 路径片段限定 |
| `extensionIn` | 3 | 扩展名限定 |
| `not` | 3 | 排除特定内容 |
| `nameGlob` | 1 | 通配名（缩略图缓存 `thumbcache_*.db`） |

### 4.4 两种执行策略

| 策略 | 数量 | 语义与准入条件 |
|------|------|-------------|
| `deleteMatchingContents` | 177 | 默认策略：逐个匹配项删除，每文件一个受保护删除事务 |
| `deleteWholeRoot` | 28 | 性能优化：**原子移动**整根到同卷私有暂存区再删除 |

`deleteWholeRoot` 的准入条件极严（`rules/README.md`）：

> "It is accepted only for **static roots** with `verified_rebuildable = true`, an **exact `all` matcher**, and `default_selected = false`. Runtime execution also requires the rule to **own the complete root** and a native aggregate to read every entry **without links or permission skips**. Source-scoped cleanup, nested rule ownership, unsupported native traversal, and **any skipped entry automatically fall back to `deleteMatchingContents` before mutation**."

即：五重前置条件 + 运行期任何异常都**自动降级**，绝不冒险整根删。

### 4.5 风险分级与选择策略

| `risk` | 数量 | 语义 |
|--------|------|------|
| `safe` | 122 | 可默认勾选 |
| `recoverable` | 83 | 可重建但需时间成本，默认不勾选 |
| `highImpact` | 0 | schema 支持，声明式规则中未使用 |

选择策略约束（`rules/README.md`）：
- `default_selected = true` **只允许** `safe` 规则 → 实测 63 条默认勾选，全部为 safe
- `recommended_selected` 控制桌面端与 CLI `recommended` 共享的推荐集 → 实测 82 条推荐
- `recoverable` 规则**只有在所有 root 都 `verified_rebuildable = true`** 时才能被推荐

### 4.6 进程关闭策略

> `rules/README.md`："When `requires_app_close = true`, `required_stopped_processes` must contain the **individual executable names** that preflight must stop or reject. When application closure is not required, the list must be empty."

实测：**152 / 205 条规则需要关闭应用**（主要是浏览器与 Electron 应用，因为运行中的进程会持有缓存文件句柄）。

---

## 五、安全护栏：不可绕过的硬约束

### 5.1 受保护的个人与高价值数据

> `rules/README.md`（"Protected personal and high-value data" 节）：
> "The **home root, Downloads, Documents, Desktop, project directories, repositories, credentials, and cloud-synchronized folders** are not ordinary cache roots. Do not combine them with `all`, broad name patterns, or composite matchers that can degrade into whole-root selection."

### 5.2 唯一的 Downloads 例外——七重条件白名单

`system.stale-partial-downloads` 是**唯一**允许触碰 Downloads 的规则，条件被硬编码为七条（`rules/README.md`）：

1. 规则 ID **必须精确**为 `system.stale-partial-downloads`
2. 归一化后的 root **必须精确**是当前用户 Downloads 目录
3. `risk` 为 `recoverable` 且 `default_selected = false`
4. matcher 必须是 `allOf`
5. `olderThan` **至少 7 天**
6. `extensionIn` **只能包含** `crdownload`、`download`、`partial`、`part`
7. `maxDepth` **不超过 3**

实际规则与之完全对应：

> 引用 `rules/filesystem/macos/system/system.stale-partial-downloads.toml:1-3,17-24`：
> ```toml
> # Browsers and download managers leave incomplete files in Downloads. This rule
> # only matches explicit temporary extensions older than seven days, preserves
> # recent resumable downloads, and is not selected by default.
> ...
> [[roots]]
> template = "${home}/Downloads"
>
> [matcher]
> kind = "allOf"
> items = [
>   { kind = "olderThan", days = 7 },
>   { kind = "extensionIn", values = ["crdownload", "download", "partial", "part"] },
>   { kind = "maxDepth", depth = 3 },
> ]
> ```

### 5.3 AI 模型数据必须走专用 Cleaner

> `rules/README.md`："AI models are **high-value downloadable data**. Ordinary filesystem rules must **not** target project directories, Ollama model stores, LM Studio data, or user-managed model directories. The dedicated AI model cleaner validates official store layouts, **shared blobs, links, and each model immediately before execution**."

对应实现在 `src/cleanup/cleaners/ai_model_storage.rs`（1334 行），管理 13 个模型存储 ID（见 §6.4）。

### 5.4 规则所有权与嵌套冲突校验

扫描计划编译期会校验规则间的所有权冲突，防止两条规则争夺同一路径：

> 引用 `src/cleanup/rules/scan_plan.rs:77`：
> ```rust
> validate_ownership_conflicts(&rules, &activations)?;
> ```

> 引用 `src/cleanup/rules/scan_plan.rs:145-148`：
> ```rust
> /// Proves that deleting `root` cannot consume a nested boundary owned by
> /// ... the exact, deeper activation retains ownership of this complete root.
> pub(crate) fn rule_exclusively_owns_root(&self, rule_index: usize, root: &Path) -> bool {
> ```

同时，扫描计划刻意不向平台层暴露规则 ID：

> 引用 `src/cleanup/rules/scan_plan.rs:303-306`：
> ```rust
> /// in the scan plan prevents platform implementations from learning rule
> /// IDs or cleanup policy, while nested ownership and filtered matchers
> ```

### 5.5 UI 文案与执行数据分离

> `rules/README.md`："Rule execution data and UI presentation remain separate... **Do not add UI names, descriptions, impact text, localization keys, or locale fields to TOML.**"

用户可见文案放在 `src/locales` 的 `cleanupRules.entries.<rule-id>` 下。这保证规则文件是纯粹的**安全边界声明**，不掺杂展示逻辑。

---

## 六、全量规则清单

> **统计总览**
> - 声明式文件系统规则：**205 条**（Windows 87 + macOS 118）
> - 项目产物规则：**31 条**，覆盖 **69 个产物目录**
> - 专用 Rust Cleaner：**24 个**
> - **合计约 260 条清理规则**

**分类分布矩阵**：

| 分类 | Windows | macOS | 小计 |
|------|---------|-------|------|
| application（应用） | 34 | 55 | 89 |
| development（开发工具） | 28 | 39 | 67 |
| browser（浏览器） | 17 | 12 | 29 |
| system（系统） | 6 | 10 | 16 |
| ai | 1 | 1 | 2 |
| container（容器） | 1 | 1 | 2 |
| **合计** | **87** | **118** | **205** |

### 6.1 表格字段说明

- **风险**：`safe` / `recoverable`
- **默认勾选**：`default_selected`，仅 safe 可为 true
- **智能推荐**：`recommended_selected`（`—` 表示字段未设置）
- **清理根路径**：`[[roots]].template`；`✅可重建` = `verified_rebuildable = true`；`→展开(...)` = `kind = "childDirectories"` 的子目录展开策略
- **匹配器**：`[matcher]` 原始声明
- **执行策略**：`deleteMatchingContents` / `deleteWholeRoot` + 是否需关闭应用
- **适用性探针**：`[[applicability]]` 原始声明（过长截断）
- **需停止进程**：`required_stopped_processes`
- **权威依据**：`[verification].references` 链接

---

### 6.2 声明式文件系统规则全量清单（205 条）

#### windows / system（6 条）

| # | 规则 ID | 风险 | 默认勾选 | 智能推荐 | 清理根路径（模板变量） | 匹配器 | 执行策略 | 适用性探针 | 需停止进程 | 权威依据 |
|---|---------|------|---------|---------|----------------------|--------|---------|-----------|-----------|---------|
| 1 | `system.crash-dumps` | safe | true | — | `${local_app_data}/CrashDumps` | `"all"` | deleteMatchingContents<br>需关进程:否 | `"anyRootExists"` | — | [1](https://learn.microsoft.com/en-us/windows/win32/wer/collecting-user-mode-dumps) |
| 2 | `system.directx-shader-cache` | safe | true | — | `${local_app_data}/D3DSCache`<br>`${local_app_data}/NVIDIA/DXCache`<br>`${local_app_data}/NVIDIA/GLCache`<br>`${local_app_data}/NVIDIA Corporation/NV_Cache`<br>`${local_app_data}/AMD/DxCache`<br>`${local_app_data}/AMD/DxcCache`<br>`${local_app_data}/AMD/GLCache`<br>`${local_app_data}/AMD/VkCache`<br>`${local_app_data}/Intel/ShaderCache`<br>`${local_app_data}/Intel/D3DSCache` | `"all"` | deleteMatchingContents<br>需关进程:否 | `"anyRootExists"` | — | （evidence 文本论证） |
| 3 | `system.error-reports` | safe | true | — | `${local_app_data}/Microsoft/Windows/WER/ReportArchive`<br>`${local_app_data}/Microsoft/Windows/WER/ReportQueue`<br>`${local_app_data}/Microsoft/Windows/WER/Temp`<br>`${program_data}/Microsoft/Windows/WER/ReportArchive`<br>`${program_data}/Microsoft/Windows/WER/ReportQueue`<br>`${program_data}/Microsoft/Windows/WER/Temp` | `"all"` | deleteMatchingContents<br>需关进程:否 | `"anyRootExists"` | — | [1](https://learn.microsoft.com/en-us/windows/win32/api/werapi/ne-werapi-report_store_types) |
| 4 | `system.stale-partial-downloads` | recoverable | false | — | `${home}/Downloads` | `"allOf" [ { "olderThan", days = 7 }, { "extensionIn", values = ["crdownload", "download", "partial", "part"] }, { "maxDepth", depth = 3 }, ]` | deleteMatchingContents<br>需关进程:否 | `"anyRootExists"` | — | （evidence 文本论证） |
| 5 | `system.thumbnail-cache` | safe | true | — | `${local_app_data}/Microsoft/Windows/Explorer` | `"nameGlob" values = ["thumbcache_*.db", "iconcache_*.db"]` | deleteMatchingContents<br>需关进程:否 | `"anyRootExists"` | — | [1](https://learn.microsoft.com/en-us/windows/win32/api/thumbcache/nn-thumbcache-ithumbnailcache) |
| 6 | `system.user-temp` | safe | true | — | `${temp}` | `"olderThan" days = 3` | deleteMatchingContents<br>需关进程:否 | `"anyRootExists"` | — | [1](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-gettemppathw) |

#### windows / browser（17 条）

| # | 规则 ID | 风险 | 默认勾选 | 智能推荐 | 清理根路径（模板变量） | 匹配器 | 执行策略 | 适用性探针 | 需停止进程 | 权威依据 |
|---|---------|------|---------|---------|----------------------|--------|---------|-----------|-----------|---------|
| 1 | `browser.2345-cache` | safe | true | — | `${local_app_data}/2345Explorer/User Data/ShaderCache`<br>`${local_app_data}/2345Explorer/User Data/GrShaderCache`<br>`${local_app_data}/2345Explorer/User Data` →展开(子目录名=Default, Guest Profile, System Profile; 子目录前缀=Profile; 固定后缀=Cache, Code Cache, GPUCache, DawnCache, DawnGraphiteCache, DawnWebGPUCache, Shared Dictionary/cache) | `"all"` | deleteMatchingContents<br>需关进程:是 | `"anyOf" [ { "applicationInstalled", identifiers = ["2345浏览器", "2345加速浏览器", "2345Explorer"] }, { "executableAvailable", names = ["2345Explorer.exe"] }, { "anyRootExists" }, ]` | 2345Explorer.exe | [1](https://www.2345.com/) [2](https://chromium.googlesource.com/chromium/src/+/main/docs/user_data_dir.md) |
| 2 | `browser.360-safe-cache` | safe | true | — | `${roaming_app_data}/360se6/User Data/GraphiteDawnCache`<br>`${roaming_app_data}/360se6/User Data` →展开(子目录名=Default, Guest Profile, System Profile; 子目录前缀=Profile; 固定后缀=Cache, Code Cache, GPUCache, DawnCache, DawnGraphiteCache, DawnWebGPUCache, Shared Dictionary/cache) | `"all"` | deleteMatchingContents<br>需关进程:是 | `"anyOf" [ { "applicationInstalled", identifiers = ["360安全浏览器", "360 Safe Browser", "360se"] }, { "executableAvailable", names = ["360se.exe"] }, { "anyRootExists" }, ]` | 360se.exe | [1](https://browser.360.cn/) [2](https://chromium.googlesource.com/chromium/src/+/main/docs/user_data_dir.md) |
| 3 | `browser.360-speed-cache` | safe | true | — | `${local_app_data}/360ChromeX/Chrome/User Data/ShaderCache64`<br>`${local_app_data}/360ChromeX/Chrome/User Data/GrShaderCache64`<br>`${local_app_data}/360ChromeX/Chrome/User Data/GraphiteDawnCache`<br>`${local_app_data}/360ChromeX/Chrome/User Data` →展开(子目录名=Default, Guest Profile, System Profile; 子目录前缀=Profile; 固定后缀=Cache, Code Cache, GPUCache64, DawnGraphiteCache, DawnWebGPUCache) | `"all"` | deleteMatchingContents<br>需关进程:是 | `"anyOf" [ { "applicationInstalled", identifiers = ["360 Extreme Browser X", "360极速浏览器X", "360ChromeX"] }, { "executableAvailable", names = ["360ChromeX.exe"] }, { "anyRootExists" }, ]` | 360ChromeX.exe | [1](https://browser.360.cn/) [2](https://chromium.googlesource.com/chromium/src/+/main/docs/user_data_dir.md) |
| 4 | `browser.arc-cache` | safe | true | — | `${local_app_data}/Packages/TheBrowserCompany.Arc_ttt1ap7aakyb4/LocalCache/Local/Arc/User Data/ShaderCache`<br>`${local_app_data}/Packages/TheBrowserCompany.Arc_ttt1ap7aakyb4/LocalCache/Local/Arc/User Data/GrShaderCache`<br>`${local_app_data}/Packages/TheBrowserCompany.Arc_ttt1ap7aakyb4/LocalCache/Local/Arc/User Data/GraphiteDawnCache`<br>`${local_app_data}/Packages/TheBrowserCompany.Arc_ttt1ap7aakyb4/LocalCache/Local/Arc/User Data` →展开(子目录名=Default, Guest Profile, System Profile; 子目录前缀=Profile; 固定后缀=Cache, Code Cache, GPUCache, DawnCache, DawnGraphiteCache, DawnWebGPUCache, GrShaderCache, GraphiteDawnCache, Media Cache, Shared Dictionary/cache) | `"all"` | deleteMatchingContents<br>需关进程:是 | `"anyOf" [ { "applicationInstalled", identifiers = ["The Browser Company Arc", "Arc"] }, { "anyRootExists" }, ]` | Arc.exe | [1](https://chromium.googlesource.com/chromium/src/+/main/docs/user_data_dir.md) |
| 5 | `browser.brave-cache` | safe | true | — | `${local_app_data}/BraveSoftware/Brave-Browser/User Data/ShaderCache`<br>`${local_app_data}/BraveSoftware/Brave-Browser/User Data/GrShaderCache`<br>`${local_app_data}/BraveSoftware/Brave-Browser/User Data/GraphiteDawnCache`<br>`${local_app_data}/BraveSoftware/Brave-Browser/User Data/DawnGraphiteCache`<br>`${local_app_data}/BraveSoftware/Brave-Browser/User Data/DawnWebGPUCache`<br>`${local_app_data}/BraveSoftware/Brave-Browser/User Data/component_crx_cache`<br>`${local_app_data}/BraveSoftware/Brave-Browser/User Data/extensions_crx_cache`<br>`${local_app_data}/BraveSoftware/Brave-Browser/User Data` →展开(子目录名=Default, Guest Profile, System Profile; 子目录前缀=Profile; 固定后缀=Cache, Code Cache, GPUCache, DawnCache, DawnGraphiteCache, DawnWebGPUCache, GrShaderCache, GraphiteDawnCache, Media Cache) | `"all"` | deleteMatchingContents<br>需关进程:是 | `"anyOf" [ { "applicationInstalled", identifiers = ["com.brave.Browser", "Brave"] }, { "anyRootExists" }, ]` | Brave Browser, brave.exe | [1](https://support.brave.com/hc/en-us/articles/360017903152-How-Do-I-Clear-Cookies-And-Site-Data-In-Brave) |
| 6 | `browser.chrome-cache` | safe | true | — | `${local_app_data}/Google/Chrome/User Data/ShaderCache`<br>`${local_app_data}/Google/Chrome/User Data/GrShaderCache`<br>`${local_app_data}/Google/Chrome/User Data/GraphiteDawnCache`<br>`${local_app_data}/Google/Chrome/User Data/DawnGraphiteCache`<br>`${local_app_data}/Google/Chrome/User Data/DawnWebGPUCache`<br>`${local_app_data}/Google/Chrome/User Data/component_crx_cache`<br>`${local_app_data}/Google/Chrome/User Data/extensions_crx_cache`<br>`${local_app_data}/Google/Chrome/User Data` →展开(子目录名=Default, Guest Profile, System Profile; 子目录前缀=Profile; 固定后缀=Cache, Code Cache, GPUCache, DawnCache, DawnGraphiteCache, DawnWebGPUCache, GrShaderCache, GraphiteDawnCache, Media Cache) | `"all"` | deleteMatchingContents<br>需关进程:是 | `"anyOf" [ { "applicationInstalled", identifiers = ["com.google.Chrome", "Google Chrome"] }, { "anyRootExists" }, ]` | Google Chrome, chrome.exe | [1](https://chromium.googlesource.com/chromium/src/+/main/docs/user_data_dir.md) [2](https://support.google.com/accounts/answer/32050) |
| 7 | `browser.chrome-offline-cache` | recoverable | false | true | `${local_app_data}/Google/Chrome/User Data` →展开(子目录名=Default, Guest Profile, System Profile; 子目录前缀=Profile; 固定后缀=Service Worker/CacheStorage, Service Worker/ScriptCache) ✅可重建 | `"all"` | deleteMatchingContents<br>需关进程:是 | `"anyOf" [ { "applicationInstalled", identifiers = ["com.google.Chrome", "Google Chrome"] }, { "anyRootExists" }, ]` | Google Chrome, chrome.exe | [1](https://chromium.googlesource.com/chromium/src/+/main/docs/user_data_dir.md) |
| 8 | `browser.chromium-cache` | safe | true | — | `${local_app_data}/Chromium/User Data/ShaderCache`<br>`${local_app_data}/Chromium/User Data/GrShaderCache`<br>`${local_app_data}/Chromium/User Data/GraphiteDawnCache`<br>`${local_app_data}/Chromium/User Data/DawnGraphiteCache`<br>`${local_app_data}/Chromium/User Data/DawnWebGPUCache`<br>`${local_app_data}/Chromium/User Data/component_crx_cache`<br>`${local_app_data}/Chromium/User Data/extensions_crx_cache`<br>`${local_app_data}/Chromium/User Data` →展开(子目录名=Default, Guest Profile, System Profile; 子目录前缀=Profile; 固定后缀=Cache, Code Cache, GPUCache, DawnCache, DawnGraphiteCache, DawnWebGPUCache, GrShaderCache, GraphiteDawnCache, Media Cache) | `"all"` | deleteMatchingContents<br>需关进程:是 | `"anyOf" [ { "applicationInstalled", identifiers = ["org.chromium.Chromium", "Chromium"] }, { "anyRootExists" }, ]` | Chromium, chromium.exe | [1](https://chromium.googlesource.com/chromium/src/+/main/docs/user_data_dir.md) |
| 9 | `browser.duckduckgo-cache` | safe | true | — | `${local_app_data}/Packages` →展开(子目录前缀=DuckDuckGo.DesktopBrowser_; 固定后缀=LocalState/EBWebView, LocalState/internalEnvironment/EBWebView) | `"pathSegmentIn" values = ["Cache", "Code Cache", "GPUCache", "DawnCache", "DawnGraphiteCache", "DawnWebGPUCache", "GrShaderCache", "GraphiteDawnCache", "Media Cache"]` | deleteMatchingContents<br>需关进程:是 | `"anyOf" [ { "applicationInstalled", identifiers = ["DuckDuckGo", "DuckDuckGo Browser"] }, { "anyRootExists" }, ]` | DuckDuckGo.exe | （evidence 文本论证） |
| 10 | `browser.edge-cache` | safe | true | — | `${local_app_data}/Microsoft/Edge/User Data/ShaderCache`<br>`${local_app_data}/Microsoft/Edge/User Data/GrShaderCache`<br>`${local_app_data}/Microsoft/Edge/User Data/GraphiteDawnCache`<br>`${local_app_data}/Microsoft/Edge/User Data/DawnGraphiteCache`<br>`${local_app_data}/Microsoft/Edge/User Data/DawnWebGPUCache`<br>`${local_app_data}/Microsoft/Edge/User Data/component_crx_cache`<br>`${local_app_data}/Microsoft/Edge/User Data/extensions_crx_cache`<br>`${local_app_data}/Microsoft/Edge/User Data` →展开(子目录名=Default, Guest Profile, System Profile; 子目录前缀=Profile; 固定后缀=Cache, Code Cache, GPUCache, DawnCache, DawnGraphiteCache, DawnWebGPUCache, GrShaderCache, GraphiteDawnCache, Media Cache) | `"all"` | deleteMatchingContents<br>需关进程:是 | `"anyOf" [ { "applicationInstalled", identifiers = ["Microsoft Edge", "Microsoft Edge Update"] }, { "anyRootExists" }, ]` | Microsoft Edge, msedge.exe | [1](https://learn.microsoft.com/en-us/deployedge/edge-learnmore-create-user-directory-vars) [2](https://learn.microsoft.com/en-us/deployedge/microsoft-edge-policies/userdatadir) |
| 11 | `browser.edge-offline-cache` | recoverable | false | true | `${local_app_data}/Microsoft/Edge/User Data` →展开(子目录名=Default, Guest Profile, System Profile; 子目录前缀=Profile; 固定后缀=Service Worker/CacheStorage, Service Worker/ScriptCache) ✅可重建 | `"all"` | deleteMatchingContents<br>需关进程:是 | `"anyOf" [ { "applicationInstalled", identifiers = ["Microsoft Edge", "Microsoft Edge Update"] }, { "anyRootExists" }, ]` | Microsoft Edge, msedge.exe | [1](https://learn.microsoft.com/en-us/deployedge/edge-learnmore-create-user-directory-vars) |
| 12 | `browser.firefox-cache` | safe | true | — | `${local_app_data}/Mozilla/Firefox/Profiles` →展开(全部子目录; 固定后缀=cache2, startupCache, shader-cache) | `"all"` | deleteMatchingContents<br>需关进程:是 | `"anyOf" [ { "applicationInstalled", identifiers = ["org.mozilla.firefox", "Mozilla Firefox", "Firefox"] }, { "anyRootExists" }, ]` | firefox.exe | [1](https://support.mozilla.org/en-US/kb/how-clear-firefox-cache) [2](https://support.mozilla.org/en-US/kb/profiles-where-firefox-stores-user-data) |
| 13 | `browser.gecko-family-cache` | safe | true | — | `${local_app_data}/Floorp/Profiles` →展开(全部子目录; 固定后缀=cache2, startupCache, shader-cache)<br>`${local_app_data}/librewolf/Profiles` →展开(全部子目录; 固定后缀=cache2, startupCache, shader-cache)<br>`${local_app_data}/Waterfox/Profiles` →展开(全部子目录; 固定后缀=cache2, startupCache, shader-cache)<br>`${local_app_data}/Thunderbird/Profiles` →展开(全部子目录; 固定后缀=cache2, startupCache, shader-cache) | `"all"` | deleteMatchingContents<br>需关进程:是 | `"anyOf" [ { "applicationInstalled", identifiers = ["Floorp", "LibreWolf", "Waterfox", "Mozilla Thunderbird", "Thunderbird"] }, { "anyRootExists" }, ]` | floorp.exe, librewolf.exe, waterfox.exe, thunderbird.exe | （evidence 文本论证） |
| 14 | `browser.opera-cache` | safe | true | — | `${roaming_app_data}/Opera Software/Opera Stable/Cache`<br>`${roaming_app_data}/Opera Software/Opera Stable/Code Cache`<br>`${roaming_app_data}/Opera Software/Opera Stable/GPUCache`<br>`${roaming_app_data}/Opera Software/Opera Stable/DawnCache`<br>`${roaming_app_data}/Opera Software/Opera Stable/DawnGraphiteCache`<br>`${roaming_app_data}/Opera Software/Opera Stable/DawnWebGPUCache`<br>`${roaming_app_data}/Opera Software/Opera Stable/GrShaderCache`<br>`${roaming_app_data}/Opera Software/Opera Stable/GraphiteDawnCache`<br>`${roaming_app_data}/Opera Software/Opera Stable/Media Cache`<br>`${roaming_app_data}/Opera Software/Opera GX Stable/Cache`<br>`${roaming_app_data}/Opera Software/Opera GX Stable/Code Cache`<br>`${roaming_app_data}/Opera Software/Opera GX Stable/GPUCache`<br>`${roaming_app_data}/Opera Software/Opera GX Stable/DawnCache`<br>`${roaming_app_data}/Opera Software/Opera GX Stable/DawnGraphiteCache`<br>`${roaming_app_data}/Opera Software/Opera GX Stable/DawnWebGPUCache`<br>`${roaming_app_data}/Opera Software/Opera GX Stable/GrShaderCache`<br>`${roaming_app_data}/Opera Software/Opera GX Stable/GraphiteDawnCache`<br>`${roaming_app_data}/Opera Software/Opera GX Stable/Media Cache` | `"all"` | deleteMatchingContents<br>需关进程:是 | `"anyOf" [ { "applicationInstalled", identifiers = ["com.operasoftware.Opera", "Opera"] }, { "anyRootExists" }, ]` | opera.exe | [1](https://help.opera.com/en/latest/web-preferences/#clearBrowsingData) |
| 15 | `browser.sogou-cache` | safe | true | — | `${local_app_data}/Sogou/SogouExplorer/User Data/ShaderCache`<br>`${local_app_data}/Sogou/SogouExplorer/User Data/GrShaderCache`<br>`${local_app_data}/Sogou/SogouExplorer/User Data/GraphiteDawnCache`<br>`${local_app_data}/Sogou/SogouExplorer/User Data` →展开(子目录名=Default, Guest Profile, System Profile; 子目录前缀=Profile; 固定后缀=Cache, Code Cache, GPUCache, DawnCache) | `"all"` | deleteMatchingContents<br>需关进程:是 | `"anyOf" [ { "applicationInstalled", identifiers = ["Sogou Explorer", "搜狗高速浏览器", "SogouExplorer"] }, { "executableAvailable", names = ["SogouExplorer.exe"] }, { "anyRootExists" }, ]` | SogouExplorer.exe | [1](https://ie.sogou.com/) [2](https://chromium.googlesource.com/chromium/src/+/main/docs/user_data_dir.md) |
| 16 | `browser.uc-cache` | safe | true | — | `${local_app_data}/UC/User Data/ShaderCache`<br>`${local_app_data}/UC/User Data/GrShaderCache`<br>`${local_app_data}/UC/User Data/GraphiteDawnCache`<br>`${local_app_data}/UC/User Data/component_crx_cache`<br>`${local_app_data}/UC/User Data` →展开(子目录名=Default, Guest Profile, System Profile; 子目录前缀=Profile; 固定后缀=Cache, Code Cache, GPUCache, DawnCache, DawnGraphiteCache, DawnWebGPUCache, GrShaderCache, GraphiteDawnCache, Media Cache) | `"all"` | deleteMatchingContents<br>需关进程:是 | `"anyOf" [ { "applicationInstalled", identifiers = ["UC Browser", "UC浏览器", "UC"] }, { "executableAvailable", names = ["uc.exe"] }, { "anyRootExists" }, ]` | uc.exe, uc_proxy.exe | [1](https://www.uc.cn/zh-cn/browser/pc.html) [2](https://chromium.googlesource.com/chromium/src/+/main/docs/user_data_dir.md) |
| 17 | `browser.vivaldi-cache` | safe | true | — | `${local_app_data}/Vivaldi/User Data/ShaderCache`<br>`${local_app_data}/Vivaldi/User Data/GrShaderCache`<br>`${local_app_data}/Vivaldi/User Data/GraphiteDawnCache`<br>`${local_app_data}/Vivaldi/User Data/DawnGraphiteCache`<br>`${local_app_data}/Vivaldi/User Data/DawnWebGPUCache`<br>`${local_app_data}/Vivaldi/User Data/component_crx_cache`<br>`${local_app_data}/Vivaldi/User Data/extensions_crx_cache`<br>`${local_app_data}/Vivaldi/User Data` →展开(子目录名=Default, Guest Profile, System Profile; 子目录前缀=Profile; 固定后缀=Cache, Code Cache, GPUCache, DawnCache, DawnGraphiteCache, DawnWebGPUCache, GrShaderCache, GraphiteDawnCache, Media Cache) | `"all"` | deleteMatchingContents<br>需关进程:是 | `"anyOf" [ { "applicationInstalled", identifiers = ["com.vivaldi.Vivaldi", "Vivaldi"] }, { "anyRootExists" }, ]` | Vivaldi, vivaldi.exe | [1](https://help.vivaldi.com/desktop/tools/delete-browsing-data/) |

#### windows / application（34 条）

| # | 规则 ID | 风险 | 默认勾选 | 智能推荐 | 清理根路径（模板变量） | 匹配器 | 执行策略 | 适用性探针 | 需停止进程 | 权威依据 |
|---|---------|------|---------|---------|----------------------|--------|---------|-----------|-----------|---------|
| 1 | `app.adobe-media-cache` | recoverable | false | true | `${local_app_data}/Adobe/Common/Media Cache Files` ✅可重建<br>`${roaming_app_data}/Adobe/Common/Media Cache Files` ✅可重建 | `"all"` | deleteMatchingContents<br>需关进程:是 | `"anyOf" [ { "applicationInstalled", identifiers = ["Adobe Premiere Pro", "Adobe After Effects", "Adobe Media Encoder"] }, { "anyRootExists" }, ]` | Adobe Premiere Pro.exe, AfterFX.exe, Adobe Media Encoder.exe | [1](https://helpx.adobe.com/premiere/desktop/troubleshooting/media-issues/manage-media-cache.html) |
| 2 | `app.battlenet-cache` | safe | false | true | `${local_app_data}/Battle.net/Cache`<br>`${local_app_data}/Battle.net/BrowserCaches` →展开(全部子目录; 固定后缀=Cache, Code Cache, GPUCache, DawnCache, DawnGraphiteCache, DawnWebGPUCache, GrShaderCache, GraphiteDawnCache, Shared Dictionary/cache,)<br>`${local_app_data}/Blizzard Entertainment/Battle.net/Cache` | `"all"` | deleteMatchingContents<br>需关进程:是 | `"anyOf" [ { "applicationInstalled", identifiers = ["Battle.net", "Blizzard.BattleNet"] }, { "anyRootExists" }, ]` | Battle.net.exe, Agent.exe | [1](https://us.support.blizzard.com/en/article/34721) [2](https://eu.support.blizzard.com/en/article/24123) [3](https://chromium.googlesource.com/chromium/src/+/main/docs/user_data_dir.md) |
| 3 | `app.chatgpt-cache` | safe | false | true | `${local_app_data}/Packages/OpenAI.Codex_2p2nqsd0c76g0/LocalCache/Local/Codex/Logs`<br>`${local_app_data}/Packages/OpenAI.Codex_2p2nqsd0c76g0/LocalCache/Roaming/Codex/web/Codex/component_crx_cache`<br>`${local_app_data}/Packages/OpenAI.Codex_2p2nqsd0c76g0/LocalCache/Roaming/Codex/web/Codex/extensions_crx_cache`<br>`${local_app_data}/Packages/OpenAI.Codex_2p2nqsd0c76g0/LocalCache/Roaming/Codex/web/Codex/GPUPersistentCache`<br>`${local_app_data}/Packages/OpenAI.Codex_2p2nqsd0c76g0/LocalCache/Roaming/Codex/web/Codex/GraphiteDawnCache`<br>`${local_app_data}/Packages/OpenAI.Codex_2p2nqsd0c76g0/LocalCache/Roaming/Codex/web/Codex/GrShaderCache`<br>`${local_app_data}/Packages/OpenAI.Codex_2p2nqsd0c76g0/LocalCache/Roaming/Codex/web/Codex/ShaderCache`<br>`${local_app_data}/Packages/OpenAI.Codex_2p2nqsd0c76g0/LocalCache/Roaming/Codex/web/Codex/Crashpad/reports`<br>`${local_app_data}/Packages/OpenAI.Codex_2p2nqsd0c76g0/LocalCache/Roaming/Codex/web/Codex/Default/Cache`<br>`${local_app_data}/Packages/OpenAI.Codex_2p2nqsd0c76g0/LocalCache/Roaming/Codex/web/Codex/Default/Code Cache`<br>`${local_app_data}/Packages/OpenAI.Codex_2p2nqsd0c76g0/LocalCache/Roaming/Codex/web/Codex/Default/GPUCache`<br>`${local_app_data}/Packages/OpenAI.Codex_2p2nqsd0c76g0/LocalCache/Roaming/Codex/web/Codex/Default/DawnCache`<br>`${local_app_data}/Packages/OpenAI.Codex_2p2nqsd0c76g0/LocalCache/Roaming/Codex/web/Codex/Default/DawnGraphiteCache`<br>`${local_app_data}/Packages/OpenAI.Codex_2p2nqsd0c76g0/LocalCache/Roaming/Codex/web/Codex/Default/DawnWebGPUCache`<br>`${local_app_data}/Packages/OpenAI.Codex_2p2nqsd0c76g0/LocalCache/Roaming/Codex/web/Codex/Default/GrShaderCache`<br>`${local_app_data}/Packages/OpenAI.Codex_2p2nqsd0c76g0/LocalCache/Roaming/Codex/web/Codex/Default/GraphiteDawnCache`<br>`${local_app_data}/Packages/OpenAI.Codex_2p2nqsd0c76g0/LocalCache/Roaming/Codex/web/Codex/Default/Shared Dictionary/cache`<br>`${local_app_data}/Packages/OpenAI.Codex_2p2nqsd0c76g0/LocalCache/Roaming/Codex/web/Codex/Default/Service Worker/CacheStorage`<br>`${local_app_data}/Packages/OpenAI.Codex_2p2nqsd0c76g0/LocalCache/Roaming/Codex/web/Codex/Default/Partitions` →展开(全部子目录; 固定后缀=Cache, Code Cache, GPUCache, DawnCache, DawnGraphiteCache, DawnWebGPUCache, GrShaderCache, GraphiteDawnCache, Shared Dictionary/cache, Service Worker/CacheStorage) | `"all"` | deleteMatchingContents<br>需关进程:是 | `"anyOf" [ { "applicationInstalled", identifiers = ["OpenAI.Codex", "ChatGPT", "Codex"] }, { "anyRootExists" }, ]` | ChatGPT.exe | [1](https://openai.com/index/introducing-the-codex-app/) [2](https://help.openai.com/en/articles/20001276-moving-to-the-new-chatgpt-desktop-app) [3](https://help.openai.com/en/articles/20001277-using-the-built-in-browser-in-the-chatgpt-desktop-app) [4](https://learn.microsoft.com/en-us/microsoft-edge/webview2/concepts/user-data-folder) [5](https://chromium.googlesource.com/chromium/src/+/main/docs/user_data_dir.md) |
| 4 | `app.discord-cache` | safe | false | true | `${roaming_app_data}/discord/Cache`<br>`${roaming_app_data}/discord/Code Cache`<br>`${roaming_app_data}/discord/GPUCache`<br>`${roaming_app_data}/discord/DawnCache`<br>`${roaming_app_data}/discord/DawnGraphiteCache`<br>`${roaming_app_data}/discord/DawnWebGPUCache`<br>`${roaming_app_data}/discord/GrShaderCache`<br>`${roaming_app_data}/discord/GraphiteDawnCache`<br>`${roaming_app_data}/discord/Shared Dictionary/cache`<br>`${roaming_app_data}/discord/logs`<br>`${roaming_app_data}/discord/Crashpad/reports` | `"all"` | deleteMatchingContents<br>需关进程:是 | `"anyOf" [ { "applicationInstalled", identifiers = ["Discord", "Discord Inc."] }, { "anyRootExists" }, ]` | Discord.exe | [1](https://support.discord.com/hc/en-us/articles/115004307527--Windows-Corrupt-Installation) [2](https://www.electronjs.org/docs/latest/api/app#appgetpathname) [3](https://chromium.googlesource.com/chromium/src/+/main/docs/user_data_dir.md) |
| 5 | `app.douyin-live-updater-cache` | recoverable | false | true | `${local_app_data}/webcast_mate-updater` ✅可重建 | `"all"` | deleteWholeRoot<br>需关进程:是 | `"anyRootExists"` | webcast_mate.exe, webcast_mate_updater.exe | （evidence 文本论证） |
| 6 | `app.dropbox-rendering-cache` | safe | false | true | `${roaming_app_data}/Dropbox/Cache`<br>`${roaming_app_data}/Dropbox/Code Cache`<br>`${roaming_app_data}/Dropbox/GPUCache`<br>`${roaming_app_data}/Dropbox/DawnGraphiteCache`<br>`${roaming_app_data}/Dropbox/DawnWebGPUCache`<br>`${roaming_app_data}/Dropbox/GrShaderCache`<br>`${roaming_app_data}/Dropbox/GraphiteDawnCache`<br>`${roaming_app_data}/Dropbox/Shared Dictionary/cache`<br>`${roaming_app_data}/Dropbox/Partitions` →展开(全部子目录; 固定后缀=Cache, Code Cache, GPUCache, DawnCache, DawnGraphiteCache, DawnWebGPUCache, GrShaderCache, GraphiteDawnCache, Shared Dictionary/cache) | `"all"` | deleteMatchingContents<br>需关进程:是 | `"anyOf" [ { "applicationInstalled", identifiers = ["Dropbox", "Dropbox.Dropbox"] }, { "anyRootExists" }, ]` | Dropbox.exe | [1](https://help.dropbox.com/installs/desktop-application-overview) [2](https://chromium.googlesource.com/chromium/src/+/main/docs/user_data_dir.md) |
| 7 | `app.ea-rendering-cache` | safe | false | true | `${local_app_data}/Electronic Arts/EA Desktop/CEF` →展开(全部子目录; 固定后缀=EADesktop/BrowserCache/Cache, EADesktop/BrowserCache/Code Cache, EADesktop/BrowserCache/GPUCache, EADesktop/BrowserCache/DawnCache, EADesktop/BrowserCache/DawnGraphiteCache, EADesktop/BrowserCache/DawnWebGPUCache, EADesktop/BrowserCache/GrShaderCache, EADesktop/BrowserCache/GraphiteDawnCache, EADesktop/BrowserCache/Shared Dictionary/cache,)<br>`${local_app_data}/EADesktop/cache/qmlcache` | `"all"` | deleteMatchingContents<br>需关进程:是 | `"anyOf" [ { "applicationInstalled", identifiers = ["EA app", "ElectronicArts.EADesktop"] }, { "anyRootExists" }, ]` | EADesktop.exe, EACefSubProcess.exe, EALocalHostSvc.exe | [1](https://help.ea.com/en/articles/technical-issues/clear-cache/) [2](https://chromium.googlesource.com/chromium/src/+/main/docs/user_data_dir.md) |
| 8 | `app.electron-cache` | safe | false | true | `${roaming_app_data}` →展开(子目录名=Slack, Microsoft Teams, Figma, obsidian, Insomnia, Claude, GitHub Desktop; 固定后缀=Cache, Code Cache, GPUCache, DawnCache, DawnGraphiteCache, DawnWebGPUCache, GrShaderCache, GraphiteDawnCache, Shared Dictionary/cache, logs, Crashpad/reports)<br>`${local_app_data}` →展开(子目录名=Slack, Microsoft Teams, Figma, obsidian, Insomnia, Claude, GitHub Desktop; 固定后缀=Cache, Code Cache, GPUCache, DawnCache, DawnGraphiteCache, DawnWebGPUCache, GrShaderCache, GraphiteDawnCache, Shared Dictionary/cache, logs, Crashpad/reports) | `"all"` | deleteMatchingContents<br>需关进程:是 | `"anyRootExists"` | Slack.exe, Teams.exe, Figma.exe, Obsidian.exe, Insomnia.exe, Claude.exe, GitHubDesktop.exe | [1](https://www.electronjs.org/docs/latest/api/app#appgetpathname) [2](https://chromium.googlesource.com/chromium/src/+/main/docs/user_data_dir.md) |
| 9 | `app.electron-updater-cache` | recoverable | false | true | `${local_app_data}/gowhisper-updater` ✅可重建<br>`${local_app_data}/weflow-updater` ✅可重建<br>`${local_app_data}/gitmind-updater` ✅可重建 | `"all"` | deleteWholeRoot<br>需关进程:是 | `"anyRootExists"` | GoWhisper.exe, WeFlow.exe, GitMind.exe | [1](https://www.electron.build/auto-update.html) [2](https://gowhisper.io/) [3](https://gitmind.com/download) |
| 10 | `app.flashvoice-cache` | safe | false | true | `${local_app_data}/com.flashvoices/EBWebView/component_crx_cache`<br>`${local_app_data}/com.flashvoices/EBWebView/extensions_crx_cache`<br>`${local_app_data}/com.flashvoices/EBWebView/GPUPersistentCache`<br>`${local_app_data}/com.flashvoices/EBWebView/GraphiteDawnCache`<br>`${local_app_data}/com.flashvoices/EBWebView/GrShaderCache`<br>`${local_app_data}/com.flashvoices/EBWebView/ShaderCache`<br>`${local_app_data}/com.flashvoices/EBWebView/Crashpad/reports`<br>`${local_app_data}/com.flashvoices/EBWebView/Default/Cache`<br>`${local_app_data}/com.flashvoices/EBWebView/Default/Code Cache`<br>`${local_app_data}/com.flashvoices/EBWebView/Default/GPUCache`<br>`${local_app_data}/com.flashvoices/EBWebView/Default/DawnCache`<br>`${local_app_data}/com.flashvoices/EBWebView/Default/DawnGraphiteCache`<br>`${local_app_data}/com.flashvoices/EBWebView/Default/DawnWebGPUCache`<br>`${local_app_data}/com.flashvoices/EBWebView/Default/GrShaderCache`<br>`${local_app_data}/com.flashvoices/EBWebView/Default/GraphiteDawnCache`<br>`${local_app_data}/com.flashvoices/EBWebView/Default/Shared Dictionary/cache`<br>`${local_app_data}/com.flashvoices/EBWebView/Default/Service Worker/CacheStorage`<br>`${roaming_app_data}/com.flashvoices/logs` | `"all"` | deleteMatchingContents<br>需关进程:是 | `"anyOf" [ { "applicationInstalled", identifiers = ["FlashVoice", "com.flashvoices"] }, { "anyRootExists" }, ]` | FlashVoice.exe | [1](https://learn.microsoft.com/en-us/microsoft-edge/webview2/concepts/user-data-folder) [2](https://chromium.googlesource.com/chromium/src/+/main/docs/user_data_dir.md) |
| 11 | `app.game-launcher-cache` | safe | false | true | `${local_app_data}/EpicGamesLauncher/Saved/webcache`<br>`${local_app_data}/EpicGamesLauncher/Saved/webcache_4147`<br>`${local_app_data}/EpicGamesLauncher/Saved/webcache_4430`<br>`${local_app_data}/EpicGamesLauncher/Saved/Logs`<br>`${local_app_data}/EpicGamesLauncher/Saved/Crashes` ✅可重建<br>`${local_app_data}/Ubisoft Game Launcher/cache` | `"all"` | deleteMatchingContents<br>需关进程:是 | `"anyOf" [ { "applicationInstalled", identifiers = ["Epic Games Launcher", "EpicGames.EpicGamesLauncher", "Ubisoft Connect"] }, { "anyRootExists" }, ]` | EpicGamesLauncher.exe, EpicWebHelper.exe, UbisoftConnect.exe, upc.exe | [1](https://www.epicgames.com/help/c-1/a202300000013316) |
| 12 | `app.gitmind-rendering-cache` | safe | false | true | `${roaming_app_data}/GitMind/Code Cache`<br>`${roaming_app_data}/GitMind/GPUCache`<br>`${roaming_app_data}/GitMind/Shared Dictionary/cache`<br>`${roaming_app_data}/GitMind/Service Worker/CacheStorage`<br>`${roaming_app_data}/GitMind/logs`<br>`${roaming_app_data}/GitMind/Crashpad/reports`<br>`${roaming_app_data}/GitMind/webview/EBWebView/component_crx_cache`<br>`${roaming_app_data}/GitMind/webview/EBWebView/extensions_crx_cache`<br>`${roaming_app_data}/GitMind/webview/EBWebView/GPUPersistentCache`<br>`${roaming_app_data}/GitMind/webview/EBWebView/GraphiteDawnCache`<br>`${roaming_app_data}/GitMind/webview/EBWebView/GrShaderCache`<br>`${roaming_app_data}/GitMind/webview/EBWebView/ShaderCache`<br>`${roaming_app_data}/GitMind/webview/EBWebView/Crashpad/reports`<br>`${roaming_app_data}/GitMind/webview/EBWebView/Default/Cache`<br>`${roaming_app_data}/GitMind/webview/EBWebView/Default/Code Cache`<br>`${roaming_app_data}/GitMind/webview/EBWebView/Default/GPUCache`<br>`${roaming_app_data}/GitMind/webview/EBWebView/Default/DawnCache`<br>`${roaming_app_data}/GitMind/webview/EBWebView/Default/DawnGraphiteCache`<br>`${roaming_app_data}/GitMind/webview/EBWebView/Default/DawnWebGPUCache`<br>`${roaming_app_data}/GitMind/webview/EBWebView/Default/GrShaderCache`<br>`${roaming_app_data}/GitMind/webview/EBWebView/Default/GraphiteDawnCache`<br>`${roaming_app_data}/GitMind/webview/EBWebView/Default/Shared Dictionary/cache`<br>`${roaming_app_data}/GitMind/webview/EBWebView/Default/Service Worker/CacheStorage` | `"all"` | deleteMatchingContents<br>需关进程:是 | `"anyOf" [ { "applicationInstalled", identifiers = ["GitMind", "com.wangxutech.gitmind.desktop"] }, { "anyRootExists" }, ]` | GitMind.exe | [1](https://gitmind.com/download) [2](https://learn.microsoft.com/en-us/microsoft-edge/webview2/concepts/user-data-folder) [3](https://chromium.googlesource.com/chromium/src/+/main/docs/user_data_dir.md) |
| 13 | `app.netease-cloud-music-cache` | safe | false | true | `${local_app_data}/NetEase/CloudMusic/webapp91x64/Cache`<br>`${local_app_data}/NetEase/CloudMusic/webapp91x64/Code Cache`<br>`${local_app_data}/NetEase/CloudMusic/webapp91x64/GPUCache`<br>`${local_app_data}/NetEase/CloudMusic/webapp91x64/DawnCache`<br>`${local_app_data}/NetEase/CloudMusic/webapp91x64/DawnGraphiteCache`<br>`${local_app_data}/NetEase/CloudMusic/webapp91x64/DawnWebGPUCache`<br>`${local_app_data}/NetEase/CloudMusic/webapp91x64/GrShaderCache`<br>`${local_app_data}/NetEase/CloudMusic/webapp91x64/GraphiteDawnCache`<br>`${local_app_data}/NetEase/CloudMusic/webapp91x64/Shared Dictionary/cache`<br>`${local_app_data}/NetEase/CloudMusic/webapp91x64/Crashpad/reports`<br>`${local_app_data}/NetEase/CloudMusic/Log` | `"all"` | deleteMatchingContents<br>需关进程:是 | `"anyOf" [ { "applicationInstalled", identifiers = ["NetEase Cloud Music", "CloudMusic", "NetEase (Hangzhou) Network Co., Ltd"] }, { "anyRootExists" }, ]` | cloudmusic.exe | [1](https://music.163.com/#/download) [2](https://github.com/microsoft/winget-pkgs/tree/master/manifests/n/NetEase/CloudMusic/3.1.37.205354) [3](https://chromium.googlesource.com/chromium/src/+/main/docs/user_data_dir.md) |
| 14 | `app.notion-cache` | safe | false | true | `${roaming_app_data}/Notion/Cache`<br>`${roaming_app_data}/Notion/Code Cache`<br>`${roaming_app_data}/Notion/GPUCache`<br>`${roaming_app_data}/Notion/DawnCache`<br>`${roaming_app_data}/Notion/DawnGraphiteCache`<br>`${roaming_app_data}/Notion/DawnWebGPUCache`<br>`${roaming_app_data}/Notion/GrShaderCache`<br>`${roaming_app_data}/Notion/GraphiteDawnCache`<br>`${roaming_app_data}/Notion/Shared Dictionary/cache`<br>`${roaming_app_data}/Notion/logs`<br>`${roaming_app_data}/Notion/Crashpad/reports`<br>`${roaming_app_data}/Notion/Partitions` →展开(全部子目录; 固定后缀=Cache, Code Cache, GPUCache, DawnCache, DawnGraphiteCache, DawnWebGPUCache, GrShaderCache, GraphiteDawnCache, Shared Dictionary/cache) | `"all"` | deleteMatchingContents<br>需关进程:是 | `"anyOf" [ { "applicationInstalled", identifiers = ["Notion", "Notion Labs, Inc."] }, { "anyRootExists" }, ]` | Notion.exe | [1](https://www.notion.com/help/reset-notion) [2](https://www.notion.com/help/use-pages-offline) [3](https://www.electronjs.org/docs/latest/api/app#appgetpathname) [4](https://chromium.googlesource.com/chromium/src/+/main/docs/user_data_dir.md) |
| 15 | `app.obs-diagnostic-cache` | safe | true | — | `${roaming_app_data}` →展开(子目录名=obs-studio, wxobs-studio; 固定后缀=logs, profiler_data, crashes) | `"olderThan" days = 14` | deleteMatchingContents<br>需关进程:是 | `"anyRootExists"` | obs64.exe, obs32.exe | （evidence 文本论证） |
| 16 | `app.postman-cache` | safe | false | true | `${roaming_app_data}/Postman/Cache`<br>`${roaming_app_data}/Postman/Code Cache`<br>`${roaming_app_data}/Postman/GPUCache`<br>`${roaming_app_data}/Postman/DawnCache`<br>`${roaming_app_data}/Postman/DawnGraphiteCache`<br>`${roaming_app_data}/Postman/DawnWebGPUCache`<br>`${roaming_app_data}/Postman/GrShaderCache`<br>`${roaming_app_data}/Postman/GraphiteDawnCache`<br>`${roaming_app_data}/Postman/logs`<br>`${roaming_app_data}/Postman/Shared Dictionary/cache`<br>`${roaming_app_data}/Postman/Partitions` →展开(全部子目录; 固定后缀=Cache, Code Cache, GPUCache, DawnCache, DawnGraphiteCache, DawnWebGPUCache, GrShaderCache, GraphiteDawnCache, Shared Dictionary/cache) | `"all"` | deleteMatchingContents<br>需关进程:是 | `"anyOf" [ { "applicationInstalled", identifiers = ["Postman", "Postman, Inc."] }, { "anyRootExists" }, ]` | Postman.exe | [1](https://learning.postman.com/latest-v-12/docs/getting-started/troubleshooting-inapp) [2](https://www.electronjs.org/docs/latest/api/app#appgetpathname) [3](https://chromium.googlesource.com/chromium/src/+/main/docs/user_data_dir.md) |
| 17 | `app.qq-rendering-cache` | safe | false | true | `${roaming_app_data}/QQ/Cache`<br>`${roaming_app_data}/QQ/Code Cache`<br>`${roaming_app_data}/QQ/GPUCache`<br>`${roaming_app_data}/QQ/DawnCache`<br>`${roaming_app_data}/QQ/DawnGraphiteCache`<br>`${roaming_app_data}/QQ/DawnWebGPUCache`<br>`${roaming_app_data}/QQ/GrShaderCache`<br>`${roaming_app_data}/QQ/GraphiteDawnCache`<br>`${roaming_app_data}/QQ/Shared Dictionary/cache`<br>`${roaming_app_data}/QQ/log`<br>`${roaming_app_data}/QQ/Crashpad/reports`<br>`${roaming_app_data}/QQ/Partitions` →展开(全部子目录; 固定后缀=Cache, Code Cache, GPUCache, DawnCache, DawnGraphiteCache, DawnWebGPUCache, GrShaderCache, GraphiteDawnCache, Shared Dictionary/cache) | `"all"` | deleteMatchingContents<br>需关进程:是 | `"anyOf" [ { "applicationInstalled", identifiers = ["QQ", "Tencent QQ", "腾讯QQ"] }, { "anyRootExists" }, ]` | QQ.exe | [1](https://im.qq.com/index/) [2](https://chromium.googlesource.com/chromium/src/+/main/docs/user_data_dir.md) |
| 18 | `app.signal-cache` | safe | false | true | `${roaming_app_data}/Signal/Cache`<br>`${roaming_app_data}/Signal/Code Cache`<br>`${roaming_app_data}/Signal/GPUCache`<br>`${roaming_app_data}/Signal/DawnCache`<br>`${roaming_app_data}/Signal/DawnGraphiteCache`<br>`${roaming_app_data}/Signal/DawnWebGPUCache`<br>`${roaming_app_data}/Signal/GrShaderCache`<br>`${roaming_app_data}/Signal/GraphiteDawnCache`<br>`${roaming_app_data}/Signal/Shared Dictionary/cache`<br>`${roaming_app_data}/Signal/logs`<br>`${roaming_app_data}/Signal/Crashpad/reports` | `"all"` | deleteMatchingContents<br>需关进程:是 | `"anyOf" [ { "applicationInstalled", identifiers = ["Signal", "Signal Messenger, LLC"] }, { "anyRootExists" }, ]` | Signal.exe | [1](https://github.com/signalapp/Signal-Desktop/tree/v8.22.0) [2](https://www.electronjs.org/docs/latest/api/app#appgetpathname) [3](https://chromium.googlesource.com/chromium/src/+/main/docs/user_data_dir.md) |
| 19 | `app.sogou-input-cache` | safe | false | true | `${program_data}/SogouInput/SGCefCache/SGMyInput/CefLocalStorage` | `"pathSegmentIn" values = ["Cache", "Code Cache"]` | deleteMatchingContents<br>需关进程:是 | `"anyOf" [ { "applicationInstalled", identifiers = ["Sogou.SogouInput", "Sogou Input", "搜狗输入法"] }, { "anyRootExists" }, ]` | SGMyInput.exe,
  SGTool.exe,
  SGWebRender.exe,
  SogouCloud.exe,
  SogouImeBroker.exe,
  SOGOUSmartAssistant.exe, | [1](https://shurufa.sogou.com/) [2](https://chromium.googlesource.com/chromium/src/+/main/docs/user_data_dir.md) |
| 20 | `app.spotify-rendering-cache` | safe | false | true | `${local_app_data}/Spotify/Browser/Cache`<br>`${local_app_data}/Spotify/Browser/Code Cache`<br>`${local_app_data}/Spotify/Browser/GPUCache`<br>`${local_app_data}/Spotify/Browser/DawnGraphiteCache`<br>`${local_app_data}/Spotify/Browser/DawnWebGPUCache`<br>`${local_app_data}/Spotify/Browser/Shared Dictionary/cache`<br>`${local_app_data}/Spotify/Default/Cache`<br>`${local_app_data}/Spotify/Default/Code Cache`<br>`${local_app_data}/Spotify/Default/GPUCache`<br>`${local_app_data}/Spotify/Default/DawnGraphiteCache`<br>`${local_app_data}/Spotify/Default/DawnWebGPUCache`<br>`${local_app_data}/Spotify/Default/Shared Dictionary/cache`<br>`${local_app_data}/Spotify/GraphiteDawnCache`<br>`${local_app_data}/Spotify/GrShaderCache`<br>`${local_app_data}/Spotify/ShaderCache` | `"all"` | deleteMatchingContents<br>需关进程:是 | `"anyOf" [ { "applicationInstalled", identifiers = ["Spotify", "Spotify.Spotify"] }, { "anyRootExists" }, ]` | Spotify.exe | [1](https://support.spotify.com/us/article/storage-information/) [2](https://chromium.googlesource.com/chromium/src/+/main/docs/user_data_dir.md) |
| 21 | `app.steam-rendering-cache` | safe | false | true | `${local_app_data}/Steam/htmlcache/Default/Cache`<br>`${local_app_data}/Steam/htmlcache/Default/Code Cache`<br>`${local_app_data}/Steam/htmlcache/Default/GPUCache`<br>`${local_app_data}/Steam/htmlcache/Default/DawnGraphiteCache`<br>`${local_app_data}/Steam/htmlcache/Default/DawnWebGPUCache`<br>`${local_app_data}/Steam/htmlcache/Default/Shared Dictionary/cache`<br>`${local_app_data}/Steam/htmlcache/GraphiteDawnCache`<br>`${local_app_data}/Steam/htmlcache/GrShaderCache`<br>`${local_app_data}/Steam/htmlcache/ShaderCache` | `"all"` | deleteMatchingContents<br>需关进程:是 | `"anyOf" [ { "applicationInstalled", identifiers = ["Steam", "Valve.Steam"] }, { "anyRootExists" }, ]` | steam.exe, steamwebhelper.exe | [1](https://store.steampowered.com/news/101607/) [2](https://store.steampowered.com/news/4186/) [3](https://chromium.googlesource.com/chromium/src/+/main/docs/user_data_dir.md) |
| 22 | `app.teams-msix-cache` | safe | false | true | `${local_app_data}/Packages/MSTeams_8wekyb3d8bbwe/LocalCache/Microsoft/MSTeams/EBWebView` →展开(子目录名=Default; 子目录前缀=Profile; 固定后缀=Cache, Code Cache, GPUCache, DawnCache, DawnGraphiteCache, DawnWebGPUCache, GrShaderCache, GraphiteDawnCache, Shared Dictionary/cache)<br>`${local_app_data}/Packages/MSTeams_8wekyb3d8bbwe/LocalCache/Microsoft/MSTeams/EBWebView/ShaderCache`<br>`${local_app_data}/Packages/MSTeams_8wekyb3d8bbwe/LocalCache/Microsoft/MSTeams/EBWebView/GrShaderCache`<br>`${local_app_data}/Packages/MSTeams_8wekyb3d8bbwe/LocalCache/Microsoft/MSTeams/EBWebView/GraphiteDawnCache` | `"all"` | deleteMatchingContents<br>需关进程:是 | `"anyOf" [ { "applicationInstalled", identifiers = ["MSTeams", "Microsoft Teams"] }, { "anyRootExists" }, ]` | ms-teams.exe | [1](https://learn.microsoft.com/en-us/troubleshoot/microsoftteams/teams-administration/clear-teams-cache) |
| 23 | `app.telegram-temporary-cache` | safe | false | true | `${roaming_app_data}/Telegram Desktop/tdata/temp`<br>`${roaming_app_data}/Telegram Desktop/tdata/dumps` | `"extensionIn" values = ["dmp", "tmp", "png", "ico", "ics"]` | deleteMatchingContents<br>需关进程:是 | `"anyOf" [ { "applicationInstalled", identifiers = ["Telegram Desktop", "Telegram.TelegramDesktop"] }, { "anyRootExists" }, ]` | Telegram.exe | [1](https://github.com/telegramdesktop/tdesktop/tree/v7.0.9) |
| 24 | `app.tencent-meeting-cache` | safe | false | true | `${roaming_app_data}/Tencent/WeMeet/Global/Data/WebkitCacheData` →展开(全部子目录; 固定后缀=BrowserMetrics, Default/Cache, Default/Code Cache, Default/GPUCache, Default/DawnCache, Default/DawnGraphiteCache, Default/DawnWebGPUCache, Default/GrShaderCache, Default/GraphiteDawnCache, Default/Shared Dictionary/cache, GraphiteDawnCache, GrShaderCache, ShaderCache)<br>`${roaming_app_data}/Tencent/WeMeet/Global/Logs`<br>`${local_app_data}/Tencent/WeMeet/Logs` | `"all"` | deleteMatchingContents<br>需关进程:是 | `"anyOf" [ { "applicationInstalled", identifiers = ["Tencent Meeting", "TencentMeeting", "WeMeet", "腾讯会议"] }, { "anyRootExists" }, ]` | WeMeetApp.exe, WeMeetCrashHandler.exe | [1](https://meeting.tencent.com/download/) [2](https://github.com/microsoft/winget-pkgs/tree/master/manifests/t/Tencent/TencentMeeting/3.44.10.457) [3](https://chromium.googlesource.com/chromium/src/+/main/docs/user_data_dir.md) |
| 25 | `app.vlc-cache` | safe | false | true | `${roaming_app_data}/vlc/art`<br>`${roaming_app_data}/vlc/crashdump` | `"extensionIn" values = ["jpg", "jpeg", "png", "webp", "bmp", "gif", "tif", "tiff", "dmp"]` | deleteMatchingContents<br>需关进程:是 | `"anyOf" [ { "applicationInstalled", identifiers = ["VLC media player", "VideoLAN.VLC"] }, { "anyRootExists" }, ]` | vlc.exe | [1](https://github.com/videolan/vlc/tree/3.0.23) |
| 26 | `app.wechat-diagnostic-cache` | safe | true | — | `${roaming_app_data}/Tencent` →展开(子目录名=xwechat, WeChat; 固定后缀=log, radium/cache, crashinfo/reports, crash/Reports) | `"all"` | deleteMatchingContents<br>需关进程:是 | `"anyOf" [ { "applicationInstalled", identifiers = ["Weixin", "WeChat", "微信"] }, { "anyRootExists" }, ]` | Weixin.exe, WeChat.exe | （evidence 文本论证） |
| 27 | `app.wechat-rendering-cache` | safe | false | true | `${roaming_app_data}/Tencent/xwechat/radium/web/profiles` →展开(全部子目录; 固定后缀=Cache, Code Cache, GPUCache, DawnCache, DawnGraphiteCache, DawnWebGPUCache, GrShaderCache, GraphiteDawnCache, Shared Dictionary/cache)<br>`${roaming_app_data}/Tencent/WeChat/radium/web/profiles` →展开(全部子目录; 固定后缀=Cache, Code Cache, GPUCache, DawnCache, DawnGraphiteCache, DawnWebGPUCache, GrShaderCache, GraphiteDawnCache, Shared Dictionary/cache)<br>`${roaming_app_data}/Tencent/xwechat/radium/users` →展开(全部子目录; 固定后缀=applet/codecache)<br>`${roaming_app_data}/Tencent/WeChat/radium/WmpfCache` | `"all"` | deleteMatchingContents<br>需关进程:是 | `"anyOf" [ { "applicationInstalled", identifiers = ["Weixin", "WeChat", "微信"] }, { "anyRootExists" }, ]` | Weixin.exe, WeChat.exe | [1](https://weixin.qq.com/cgi-bin/readtemplate?lang=zh_CN&t=download/windows) [2](https://chromium.googlesource.com/chromium/src/+/main/docs/user_data_dir.md) |
| 28 | `app.wecom-diagnostic-cache` | safe | false | true | `${roaming_app_data}/Tencent/WXWork/Log` | `"all"` | deleteMatchingContents<br>需关进程:是 | `"anyOf" [ { "applicationInstalled", identifiers = ["WeCom", "WXWork", "企业微信"] }, { "anyRootExists" }, ]` | WXWork.exe | [1](https://work.weixin.qq.com/) |
| 29 | `app.whatsapp-rendering-cache` | safe | false | true | `${local_app_data}/Packages/5319275A.WhatsAppDesktop_cv1g1gvanyjgm/LocalCache/EBWebView/component_crx_cache`<br>`${local_app_data}/Packages/5319275A.WhatsAppDesktop_cv1g1gvanyjgm/LocalCache/EBWebView/extensions_crx_cache`<br>`${local_app_data}/Packages/5319275A.WhatsAppDesktop_cv1g1gvanyjgm/LocalCache/EBWebView/GPUPersistentCache`<br>`${local_app_data}/Packages/5319275A.WhatsAppDesktop_cv1g1gvanyjgm/LocalCache/EBWebView/GraphiteDawnCache`<br>`${local_app_data}/Packages/5319275A.WhatsAppDesktop_cv1g1gvanyjgm/LocalCache/EBWebView/GrShaderCache`<br>`${local_app_data}/Packages/5319275A.WhatsAppDesktop_cv1g1gvanyjgm/LocalCache/EBWebView/ShaderCache`<br>`${local_app_data}/Packages/5319275A.WhatsAppDesktop_cv1g1gvanyjgm/LocalCache/EBWebView/Crashpad/reports`<br>`${local_app_data}/Packages/5319275A.WhatsAppDesktop_cv1g1gvanyjgm/LocalCache/EBWebView/Default/Cache`<br>`${local_app_data}/Packages/5319275A.WhatsAppDesktop_cv1g1gvanyjgm/LocalCache/EBWebView/Default/Code Cache`<br>`${local_app_data}/Packages/5319275A.WhatsAppDesktop_cv1g1gvanyjgm/LocalCache/EBWebView/Default/GPUCache`<br>`${local_app_data}/Packages/5319275A.WhatsAppDesktop_cv1g1gvanyjgm/LocalCache/EBWebView/Default/DawnCache`<br>`${local_app_data}/Packages/5319275A.WhatsAppDesktop_cv1g1gvanyjgm/LocalCache/EBWebView/Default/DawnGraphiteCache`<br>`${local_app_data}/Packages/5319275A.WhatsAppDesktop_cv1g1gvanyjgm/LocalCache/EBWebView/Default/DawnWebGPUCache`<br>`${local_app_data}/Packages/5319275A.WhatsAppDesktop_cv1g1gvanyjgm/LocalCache/EBWebView/Default/GrShaderCache`<br>`${local_app_data}/Packages/5319275A.WhatsAppDesktop_cv1g1gvanyjgm/LocalCache/EBWebView/Default/GraphiteDawnCache`<br>`${local_app_data}/Packages/5319275A.WhatsAppDesktop_cv1g1gvanyjgm/LocalCache/EBWebView/Default/Shared Dictionary/cache`<br>`${local_app_data}/Packages/5319275A.WhatsAppDesktop_cv1g1gvanyjgm/LocalCache/EBWebView/Default/Service Worker/CacheStorage` | `"all"` | deleteMatchingContents<br>需关进程:是 | `"anyOf" [ { "applicationInstalled", identifiers = ["5319275A.WhatsAppDesktop", "WhatsApp"] }, { "anyRootExists" }, ]` | WhatsApp.Root.exe, WhatsApp.exe | [1](https://apps.microsoft.com/detail/9nksqgp7f2nh) [2](https://www.whatsapp.com/download) [3](https://learn.microsoft.com/en-us/microsoft-edge/webview2/concepts/user-data-folder) [4](https://chromium.googlesource.com/chromium/src/+/main/docs/user_data_dir.md) |
| 30 | `app.wps-cache` | safe | true | — | `${roaming_app_data}/Kingsoft/office6/cache` | `"all"` | deleteMatchingContents<br>需关进程:是 | `"anyOf" [ { "applicationInstalled", identifiers = ["Kingsoft.WPSOffice.CN", "WPS Office", "WPS Office CN"] }, { "anyRootExists" }, ]` | wpsoffice.exe,
  wps.exe,
  et.exe,
  wpp.exe,
  wpspdf.exe,
  wpscloudsvr.exe,
  wpscenter.exe,
  promecefpluginhost.exe,
  ksomisc.exe,
  wpsupdate.exe, | [1](https://www.wps.cn/product/wpswin) |
| 31 | `app.wps-diagnostic-cache` | safe | false | true | `${roaming_app_data}/Kingsoft/office6` | `"pathSegmentIn" values = ["log", "dump"]` | deleteMatchingContents<br>需关进程:是 | `"anyOf" [ { "applicationInstalled", identifiers = ["Kingsoft.WPSOffice.CN", "WPS Office", "WPS Office CN"] }, { "anyRootExists" }, ]` | wpsoffice.exe,
  wps.exe,
  et.exe,
  wpp.exe,
  wpspdf.exe,
  wpscloudsvr.exe,
  wpscenter.exe,
  promecefpluginhost.exe,
  ksomisc.exe,
  wpsupdate.exe, | [1](https://www.wps.cn/product/wpswin) |
| 32 | `app.wps-rendering-cache` | safe | true | — | `${roaming_app_data}/Kingsoft/wps/addons/data/win-i386/cef/2` | `"pathSegmentIn" values = ["Cache", "Code Cache"]` | deleteMatchingContents<br>需关进程:是 | `"anyOf" [ { "applicationInstalled", identifiers = ["Kingsoft.WPSOffice.CN", "WPS Office", "WPS Office CN"] }, { "anyRootExists" }, ]` | wpsoffice.exe,
  wps.exe,
  et.exe,
  wpp.exe,
  wpspdf.exe,
  wpscloudsvr.exe,
  wpscenter.exe,
  promecefpluginhost.exe,
  ksomisc.exe,
  wpsupdate.exe, | [1](https://www.wps.cn/product/wpswin) [2](https://chromium.googlesource.com/chromium/src/+/main/docs/user_data_dir.md) |
| 33 | `app.zenaion-cache` | safe | false | true | `${local_app_data}/bot.zenai/EBWebView/Default/Cache`<br>`${local_app_data}/bot.zenai/EBWebView/Default/Code Cache`<br>`${local_app_data}/bot.zenai/EBWebView/Default/GPUCache`<br>`${local_app_data}/bot.zenai/EBWebView/Default/DawnGraphiteCache`<br>`${local_app_data}/bot.zenai/EBWebView/Default/DawnWebGPUCache`<br>`${local_app_data}/bot.zenai/EBWebView/Default/GrShaderCache`<br>`${local_app_data}/bot.zenai/EBWebView/Default/GraphiteDawnCache`<br>`${local_app_data}/bot.zenai/EBWebView/Default/Shared Dictionary/cache`<br>`${local_app_data}/bot.zenai/EBWebView/ShaderCache`<br>`${local_app_data}/bot.zenai/EBWebView/GrShaderCache`<br>`${local_app_data}/bot.zenai/EBWebView/GraphiteDawnCache`<br>`${local_app_data}/bot.zenai/EBWebView/GPUPersistentCache/DawnGraphiteCache`<br>`${local_app_data}/bot.zenai/EBWebView/component_crx_cache`<br>`${local_app_data}/bot.zenai/EBWebView/extensions_crx_cache`<br>`${local_app_data}/bot.zenai/EBWebView/Crashpad/reports` | `"all"` | deleteMatchingContents<br>需关进程:是 | `"anyOf" [ { "applicationInstalled", identifiers = ["ZenAion", "ZenAI"] }, { "anyRootExists" }, ]` | ZenAI.exe, zenai-host.exe | [1](https://zenai.bot/guide/core-features/view-all) [2](https://learn.microsoft.com/en-us/microsoft-edge/webview2/concepts/user-data-folder) |
| 34 | `app.zoom-diagnostic-cache` | safe | true | — | `${roaming_app_data}/Zoom/logs` | `"olderThan" days = 14` | deleteMatchingContents<br>需关进程:是 | `"anyOf" [ { "applicationInstalled", identifiers = ["Zoom", "Zoom Workplace"] }, { "anyRootExists" }, ]` | Zoom.exe | [1](https://support.zoom.com/hc/en/article?id=zm_kb&sysparm_article=KB0066286) |

#### windows / development（28 条）

| # | 规则 ID | 风险 | 默认勾选 | 智能推荐 | 清理根路径（模板变量） | 匹配器 | 执行策略 | 适用性探针 | 需停止进程 | 权威依据 |
|---|---------|------|---------|---------|----------------------|--------|---------|-----------|-----------|---------|
| 1 | `dev.android-cache` | recoverable | false | — | `${local_app_data}/Android/Sdk/.temp`<br>`${local_app_data}/Android/Sdk/temp`<br>`${local_app_data}/Android/Sdk/cache` | `"all"` | deleteMatchingContents<br>需关进程:是 | `"anyRootExists"` | studio64.exe | [1](https://developer.android.com/tools/sdkmanager) |
| 2 | `dev.android-user-cache` | recoverable | false | — | `${home}/.android/cache`<br>`${home}/.android/build-cache` | `"all"` | deleteMatchingContents<br>需关进程:是 | `"anyRootExists"` | studio64.exe | [1](https://developer.android.com/studio/command-line/variables) |
| 3 | `dev.browser-automation-cache` | recoverable | false | — | `${local_app_data}/ms-playwright` ✅可重建<br>`${local_app_data}/ms-playwright-go` ✅可重建<br>`${local_app_data}/ms-playwright-mcp` ✅可重建<br>`${local_app_data}/Cypress/Cache`<br>`${local_app_data}/selenium` ✅可重建 | `"all"` | deleteMatchingContents<br>需关进程:是 | `"anyRootExists"` | cypress.exe, playwright.exe | [1](https://playwright.dev/docs/browsers#managing-browser-binaries) [2](https://docs.cypress.io/app/references/advanced-installation#Binary-cache) [3](https://www.selenium.dev/documentation/selenium_manager/#caching) |
| 4 | `dev.build-accelerator-cache` | recoverable | false | — | `${home}/.cache/sccache`<br>`${home}/.terraform.d/plugin-cache` | `"all"` | deleteMatchingContents<br>需关进程:是 | `"anyRootExists"` | sccache.exe, terraform.exe | [1](https://github.com/mozilla/sccache/blob/main/docs/Configuration.md) [2](https://developer.hashicorp.com/terraform/cli/config/config-file#provider-plugin-cache) |
| 5 | `dev.cargo-cache` | recoverable | false | — | `${home}/.cargo/registry/cache`<br>`${home}/.cargo/registry/src` ✅可重建<br>`${home}/.cargo/git` ✅可重建<br>`${home}/.rustup/downloads` ✅可重建 | `"all"` | deleteMatchingContents<br>需关进程:否 | `"anyOf" [ { "executableAvailable", names = ["cargo.exe"] }, { "anyRootExists" }, ]` | — | [1](https://doc.rust-lang.org/cargo/guide/cargo-home.html) [2](https://rust-lang.github.io/rustup/installation/) |
| 6 | `dev.ccache-cache` | recoverable | false | — | `${roaming_app_data}/ccache` | `"not" item = { "nameEquals", values = ["ccache.conf"] }` | deleteMatchingContents<br>需关进程:是 | `"anyOf" [ { "executableAvailable", names = ["ccache.exe", "ccache"] }, { "anyRootExists" }, ]` | ccache.exe | [1](https://ccache.dev/manual/latest.html#_location_of_the_configuration_file) |
| 7 | `dev.copilot-cli-cache` | recoverable | false | — | `${local_app_data}/copilot` ✅可重建 | `"all"` | deleteWholeRoot<br>需关进程:是 | `"anyOf" [ { "executableAvailable", names = ["copilot.exe", "copilot"] }, { "anyRootExists" }, ]` | copilot.exe | [1](https://docs.github.com/en/copilot/reference/copilot-cli-reference/cli-config-dir-reference#changing-the-location-of-the-configuration-directory) |
| 8 | `dev.dart-analysis-cache` | recoverable | false | true | `${local_app_data}/.dartServer` ✅可重建 | `"all"` | deleteWholeRoot<br>需关进程:是 | `"anyOf" [ { "executableAvailable", names = ["dart.exe", "flutter.bat"] }, { "anyRootExists" }, ]` | dart, flutter | [1](https://github.com/flutter/flutter/blob/master/dev/devicelab/lib/tasks/analysis.dart) [2](https://github.com/flutter/flutter/blob/master/dev/snippets/test/filesystem_resource_provider.dart) |
| 9 | `dev.editor-cache` | recoverable | false | — | `${roaming_app_data}` →展开(子目录名=Code, Cursor, Windsurf, VSCodium; 固定后缀=Cache, Code Cache, GPUCache, CachedData, CachedExtensions, CachedExtensionVSIXs, DawnCache, DawnGraphiteCache, DawnWebGPUCache, GrShaderCache, GraphiteDawnCache, Shared Dictionary/cache, Crashpad/reports, logs,) | `"all"` | deleteMatchingContents<br>需关进程:是 | `"anyRootExists"` | Code.exe, Cursor.exe, Windsurf.exe, VSCodium.exe | [1](https://github.com/microsoft/vscode/tree/1.132.0) [2](https://code.visualstudio.com/docs/configure/command-line#_advanced-cli-options) [3](https://chromium.googlesource.com/chromium/src/+/main/docs/user_data_dir.md) |
| 10 | `dev.go-cache` | recoverable | false | — | `${local_app_data}/go-build` ✅可重建 | `"all"` | deleteWholeRoot<br>需关进程:否 | `"anyOf" [ { "executableAvailable", names = ["go.exe"] }, { "anyRootExists" }, ]` | — | [1](https://go.dev/cmd/go/#hdr-Build_and_test_caching) |
| 11 | `dev.go-module-cache` | recoverable | false | — | `${home}/go/pkg/mod/cache/download` | `"all"` | deleteMatchingContents<br>需关进程:否 | `"anyRootExists"` | — | [1](https://go.dev/ref/mod#module-cache) |
| 12 | `dev.gradle-cache` | recoverable | false | — | `${home}/.gradle/caches`<br>`${home}/.gradle/daemon` ✅可重建<br>`${home}/.gradle/workers` ✅可重建<br>`${home}/.gradle/notifications` ✅可重建 | `"all"` | deleteMatchingContents<br>需关进程:是 | `"anyOf" [ { "executableAvailable", names = ["java.exe", "gradle.exe"] }, { "anyRootExists" }, ]` | gradle.exe, java.exe | [1](https://docs.gradle.org/current/userguide/directory_layout.html) |
| 13 | `dev.hex-cache` | recoverable | false | — | `${home}/.hex/cache` | `"all"` | deleteMatchingContents<br>需关进程:是 | `"anyOf" [ { "executableAvailable", names = ["mix.bat", "mix"] }, { "anyRootExists" }, ]` | beam.smp.exe | [1](https://hex.hexdocs.pm/Mix.Tasks.Hex.Config.html) |
| 14 | `dev.jetbrains-cache` | recoverable | false | — | `${local_app_data}/JetBrains` →展开(全部子目录; 固定后缀=caches, index, tmp, log, compile-server) ✅可重建<br>`${local_app_data}/Google` →展开(子目录前缀=AndroidStudio; 固定后缀=caches, index, tmp, log, compile-server) ✅可重建 | `"all"` | deleteMatchingContents<br>需关进程:是 | `"anyRootExists"` | idea64.exe, studio64.exe, pycharm64.exe, webstorm64.exe | [1](https://www.jetbrains.com/help/idea/tuning-the-ide.html#system-directory) [2](https://www.jetbrains.com/help/idea/invalidate-caches.html) |
| 15 | `dev.jvm-tooling-cache` | recoverable | false | — | `${home}/.sbt/boot` ✅可重建<br>`${home}/.sbt/preloaded` ✅可重建<br>`${home}/.ivy2/cache` | `"all"` | deleteMatchingContents<br>需关进程:是 | `"anyRootExists"` | java.exe | [1](https://www.scala-sbt.org/1.x/docs/Launcher-Getting-Started.html) [2](https://ant.apache.org/ivy/history/latest-milestone/settings/caches.html) |
| 16 | `dev.maven-cache` | recoverable | false | — | `${home}/.m2/repository` ✅可重建 | `"all"` | deleteWholeRoot<br>需关进程:否 | `"anyRootExists"` | — | [1](https://maven.apache.org/guides/mini/guide-configuring-maven.html) |
| 17 | `dev.node-tooling-cache` | recoverable | false | — | `${local_app_data}/node/corepack` ✅可重建<br>`${local_app_data}/node-gyp/Cache`<br>`${local_app_data}/electron/Cache` | `"all"` | deleteMatchingContents<br>需关进程:否 | `"anyOf" [ { "executableAvailable", names = ["node.exe", "npm.cmd"] }, { "anyRootExists" }, ]` | — | [1](https://github.com/nodejs/corepack#environment-variables) [2](https://github.com/nodejs/node-gyp#command-options) [3](https://github.com/electron/get#how-it-works) |
| 18 | `dev.npm-cache` | recoverable | false | — | `${local_app_data}/npm-cache`<br>`${local_app_data}/npm/cache` | `"all"` | deleteMatchingContents<br>需关进程:否 | `"anyOf" [ { "executableAvailable", names = ["node.exe", "npm.cmd"] }, { "anyRootExists" }, ]` | — | [1](https://docs.npmjs.com/cli/cache/) |
| 19 | `dev.nuget-cache` | recoverable | false | — | `${home}/.nuget/packages` ✅可重建<br>`${local_app_data}/NuGet/v3-cache` ✅可重建<br>`${local_app_data}/NuGet/plugins-cache` ✅可重建<br>`${local_app_data}/NuGet/Scratch` ✅可重建 | `"all"` | deleteWholeRoot<br>需关进程:是 | `"anyRootExists"` | dotnet, nuget, msbuild | [1](https://learn.microsoft.com/en-us/nuget/consume-packages/managing-the-global-packages-and-cache-folders) [2](https://learn.microsoft.com/en-us/nuget/reference/cli-reference/cli-ref-locals) |
| 20 | `dev.package-manager-cache` | recoverable | false | — | `${local_app_data}/Composer` ✅可重建<br>`${local_app_data}/deno` ✅可重建<br>`${local_app_data}/vcpkg/archives` ✅可重建 | `"all"` | deleteWholeRoot<br>需关进程:否 | `"anyRootExists"` | — | [1](https://getcomposer.org/doc/06-config.md#cache-dir) [2](https://docs.deno.com/runtime/getting_started/installation/#cache-location) [3](https://learn.microsoft.com/en-us/vcpkg/users/binarycaching#default-binary-cache) |
| 21 | `dev.pip-cache` | recoverable | false | — | `${local_app_data}/pip/Cache` | `"all"` | deleteMatchingContents<br>需关进程:否 | `"anyOf" [ { "executableAvailable", names = ["python.exe", "pip.exe"] }, { "anyRootExists" }, ]` | — | [1](https://pip.pypa.io/en/stable/topics/caching/) |
| 22 | `dev.pnpm-cache` | recoverable | false | — | `${local_app_data}/pnpm/store` ✅可重建 | `"all"` | deleteWholeRoot<br>需关进程:否 | `"anyOf" [ { "executableAvailable", names = ["pnpm.exe", "pnpm.cmd"] }, { "anyRootExists" }, ]` | — | [1](https://pnpm.io/cli/store) |
| 23 | `dev.python-tooling-cache` | recoverable | false | — | `${local_app_data}/pypoetry/Cache/artifacts`<br>`${local_app_data}/pypoetry/Cache/cache`<br>`${local_app_data}/pyenv/pyenv-win/install_cache` | `"all"` | deleteMatchingContents<br>需关进程:否 | `"anyOf" [ { "executableAvailable", names = ["python.exe", "python3.exe"] }, { "anyRootExists" }, ]` | — | [1](https://python-poetry.org/docs/configuration/#cache-dir) [2](https://github.com/pyenv-win/pyenv-win) |
| 24 | `dev.sccache-cache` | recoverable | false | — | `${local_app_data}/Mozilla/sccache/cache` | `"all"` | deleteMatchingContents<br>需关进程:是 | `"anyOf" [ { "executableAvailable", names = ["sccache.exe", "sccache"] }, { "anyRootExists" }, ]` | sccache.exe | [1](https://github.com/mozilla/sccache/blob/main/docs/Configuration.md) |
| 25 | `dev.user-tool-cache` | recoverable | false | — | `${home}/.bun/install/cache`<br>`${home}/.cache/node/corepack`<br>`${home}/.node-gyp` ✅可重建<br>`${home}/.pyenv/pyenv-win/install_cache`<br>`${home}/.cache/ruff`<br>`${home}/.cache/mypy`<br>`${home}/.cache/pre-commit`<br>`${home}/.cache/puppeteer`<br>`${home}/.cache/selenium` | `"all"` | deleteMatchingContents<br>需关进程:否 | `"anyRootExists"` | — | [1](https://bun.sh/docs/pm/global-cache) [2](https://github.com/nodejs/corepack#environment-variables) [3](https://github.com/nodejs/node-gyp#command-options) [4](https://docs.astral.sh/ruff/configuration/#cache-dir) [5](https://mypy.readthedocs.io/en/stable/command_line.html#cmdoption-mypy-cache-dir) [6](https://pre-commit.com/#managing-ci-caches) [7](https://pptr.dev/guides/configuration#changing-the-default-cache-directory) [8](https://www.selenium.dev/documentation/selenium_manager/#caching) |
| 26 | `dev.uv-cache` | recoverable | false | true | `${local_app_data}/uv/cache` ✅可重建 | `"all"` | deleteWholeRoot<br>需关进程:是 | `"anyOf" [ { "executableAvailable", names = ["uv.exe"] }, { "anyRootExists" }, ]` | uv | [1](https://docs.astral.sh/uv/reference/storage/#cache-directory) [2](https://docs.astral.sh/uv/concepts/cache/#clearing-the-cache) |
| 27 | `dev.visual-studio-cache` | recoverable | false | — | `${local_app_data}/Microsoft/VisualStudio/VSCommon/MEFCache`<br>`${local_app_data}/Microsoft/VisualStudio` →展开(全部子目录; 固定后缀=ComponentModelCache, Cache, ImageLibrary, MEFCacheBackup) ✅可重建 | `"all"` | deleteMatchingContents<br>需关进程:是 | `"anyRootExists"` | devenv.exe | [1](https://learn.microsoft.com/en-us/visualstudio/extensibility/managed-extensibility-framework-in-the-editor) |
| 28 | `dev.yarn-cache` | recoverable | false | — | `${roaming_app_data}/Yarn/Cache`<br>`${local_app_data}/Yarn/Cache` | `"all"` | deleteMatchingContents<br>需关进程:否 | `"anyRootExists"` | — | [1](https://classic.yarnpkg.com/lang/en/docs/cli/cache/) |

#### windows / ai（1 条）

| # | 规则 ID | 风险 | 默认勾选 | 智能推荐 | 清理根路径（模板变量） | 匹配器 | 执行策略 | 适用性探针 | 需停止进程 | 权威依据 |
|---|---------|------|---------|---------|----------------------|--------|---------|-----------|-----------|---------|
| 1 | `ai.huggingface-xet-cache` | recoverable | false | — | `${home}/.cache/huggingface/xet` | `"allOf" [ { "pathSegmentIn", values = ["chunk_cache", "shard_cache", "logs"] }, { "not", item = { "pathSegmentIn", values = ["staging"] } }, ]` | deleteMatchingContents<br>需关进程:否 | `"anyRootExists"` | — | （evidence 文本论证） |

#### windows / container（1 条）

| # | 规则 ID | 风险 | 默认勾选 | 智能推荐 | 清理根路径（模板变量） | 匹配器 | 执行策略 | 适用性探针 | 需停止进程 | 权威依据 |
|---|---------|------|---------|---------|----------------------|--------|---------|-----------|-----------|---------|
| 1 | `container.docker-desktop-rendering-cache` | safe | false | — | `${roaming_app_data}/Docker Desktop/Cache`<br>`${roaming_app_data}/Docker Desktop/Code Cache`<br>`${roaming_app_data}/Docker Desktop/GPUCache`<br>`${roaming_app_data}/Docker Desktop/DawnCache`<br>`${roaming_app_data}/Docker Desktop/DawnGraphiteCache`<br>`${roaming_app_data}/Docker Desktop/DawnWebGPUCache`<br>`${roaming_app_data}/Docker Desktop/GrShaderCache`<br>`${roaming_app_data}/Docker Desktop/GraphiteDawnCache`<br>`${roaming_app_data}/Docker Desktop/Shared Dictionary/cache` | `"all"` | deleteMatchingContents<br>需关进程:是 | `"anyOf" [ { "applicationInstalled", identifiers = ["Docker Desktop", "Docker.DockerDesktop"] }, { "anyRootExists" }, ]` | Docker Desktop.exe | [1](https://docs.docker.com/desktop/settings-and-maintenance/settings/) [2](https://docs.docker.com/desktop/settings-and-maintenance/backup-and-restore/) [3](https://chromium.googlesource.com/chromium/src/+/main/docs/user_data_dir.md) |

#### macos / system（10 条）

| # | 规则 ID | 风险 | 默认勾选 | 智能推荐 | 清理根路径（模板变量） | 匹配器 | 执行策略 | 适用性探针 | 需停止进程 | 权威依据 |
|---|---------|------|---------|---------|----------------------|--------|---------|-----------|-----------|---------|
| 1 | `system.apple-intelligence-cache` | recoverable | false | — | `${user_library}/Caches/com.apple.e5rt.e5bundlecache` | `"all"` | deleteMatchingContents<br>需关进程:否 | `"anyRootExists"` | — | [1](https://developer.apple.com/documentation/foundation/url/cachesdirectory) |
| 2 | `system.apple-media-cache` | safe | true | — | `${user_library}/Caches/com.apple.AppleMediaServices` | `"all"` | deleteMatchingContents<br>需关进程:否 | `"anyRootExists"` | — | [1](https://developer.apple.com/documentation/foundation/url/cachesdirectory) |
| 3 | `system.darwin-user-cache` | safe | true | — | `${darwin_user_cache}` | `"allOf" [ { "olderThan", days = 7 }, { "not", item = { "extensionIn", values = ["db", "sqlite", "sqlite3", "plist"] } }, ]` | deleteMatchingContents<br>需关进程:否 | `"anyRootExists"` | — | [1](https://developer.apple.com/documentation/foundation/using-the-file-system-effectively) |
| 4 | `system.geo-services-cache` | recoverable | false | — | `${user_library}/Caches/GeoServices` | `"all"` | deleteMatchingContents<br>需关进程:否 | `"anyRootExists"` | — | [1](https://developer.apple.com/documentation/foundation/url/cachesdirectory) |
| 5 | `system.help-cache` | safe | true | — | `${user_library}/Caches/com.apple.helpd` | `"all"` | deleteMatchingContents<br>需关进程:否 | `"anyRootExists"` | — | [1](https://developer.apple.com/documentation/foundation/url/cachesdirectory) |
| 6 | `system.old-diagnostic-logs` | safe | true | — | `${user_library}/Logs` | `"olderThan" days = 7` | deleteMatchingContents<br>需关进程:否 | `"anyRootExists"` | — | [1](https://developer.apple.com/documentation/xcode/acquiring-crash-reports-and-diagnostic-logs) |
| 7 | `system.parsecd-cache` | recoverable | false | — | `${user_library}/Caches/com.apple.parsecd` | `"all"` | deleteMatchingContents<br>需关进程:否 | `"anyRootExists"` | — | [1](https://developer.apple.com/documentation/foundation/url/cachesdirectory) |
| 8 | `system.quicklook-cache` | safe | true | — | `${user_library}/Caches/com.apple.QuickLook.thumbnailcache`<br>`${user_library}/Caches/Quick Look` | `"all"` | deleteMatchingContents<br>需关进程:否 | `"anyRootExists"` | — | [1](https://developer.apple.com/documentation/foundation/url/cachesdirectory) |
| 9 | `system.stale-partial-downloads` | recoverable | false | — | `${home}/Downloads` | `"allOf" [ { "olderThan", days = 7 }, { "extensionIn", values = ["crdownload", "download", "partial", "part"] }, { "maxDepth", depth = 3 }, ]` | deleteMatchingContents<br>需关进程:否 | `"anyRootExists"` | — | （evidence 文本论证） |
| 10 | `system.user-temp` | safe | true | — | `${temp}` | `"allOf" [ { "olderThan", days = 7 }, { "not", item = { "extensionIn", values = ["db", "sqlite", "sqlite3", "plist"] } }, ]` | deleteMatchingContents<br>需关进程:否 | `"anyRootExists"` | — | [1](https://developer.apple.com/documentation/foundation/using-the-file-system-effectively) |

#### macos / browser（12 条）

| # | 规则 ID | 风险 | 默认勾选 | 智能推荐 | 清理根路径（模板变量） | 匹配器 | 执行策略 | 适用性探针 | 需停止进程 | 权威依据 |
|---|---------|------|---------|---------|----------------------|--------|---------|-----------|-----------|---------|
| 1 | `browser.360-speed-cache` | safe | true | — | `${user_library}/Caches/360Chrome`<br>`${application_support}/360Chrome/ShaderCache64`<br>`${application_support}/360Chrome/GrShaderCache64`<br>`${application_support}/360Chrome/GraphiteDawnCache`<br>`${application_support}/360Chrome/component_crx_cache`<br>`${application_support}/360Chrome` →展开(子目录名=Default, Guest Profile, System Profile; 子目录前缀=Profile; 固定后缀=GPUCache64, DawnGraphiteCache, DawnWebGPUCache) | `"all"` | deleteMatchingContents<br>需关进程:是 | `"anyOf" [ { "applicationInstalled", identifiers = ["net.qihoo.360browser", "360Chrome"] }, { "anyRootExists" }, ] # The macOS build stores HTTP and code cache data under Library/Caches.` | 360Chrome, 360Chrome Helper, 360Chrome Helper (GPU), 360Chrome Helper (Renderer) | [1](https://browser.360.cn/ee/mac/index.html) [2](https://chromium.googlesource.com/chromium/src/+/main/docs/user_data_dir.md) |
| 2 | `browser.arc-cache` | safe | true | — | `${user_library}/Caches/company.thebrowser.Browser`<br>`${application_support}/Arc/User Data/ShaderCache`<br>`${application_support}/Arc/User Data/GrShaderCache`<br>`${application_support}/Arc/User Data/GraphiteDawnCache`<br>`${application_support}/Arc/User Data/component_crx_cache`<br>`${application_support}/Arc/User Data/extensions_crx_cache`<br>`${application_support}/Arc/User Data` →展开(子目录名=Default, Guest Profile, System Profile; 子目录前缀=Profile; 固定后缀=Cache, Code Cache, GPUCache, DawnCache, GrShaderCache, GraphiteDawnCache, Media Cache) | `"all"` | deleteMatchingContents<br>需关进程:是 | `"anyOf" [ { "applicationInstalled", identifiers = ["company.thebrowser.Browser", "Arc"] }, { "anyRootExists" }, ]` | Arc | （evidence 文本论证） |
| 3 | `browser.brave-cache` | safe | true | — | `${user_library}/Caches/BraveSoftware/Brave-Browser`<br>`${application_support}/BraveSoftware/Brave-Browser` →展开(子目录名=Default, Guest Profile, System Profile; 子目录前缀=Profile; 固定后缀=Cache, Code Cache, GPUCache, DawnCache, GrShaderCache) | `"all"` | deleteMatchingContents<br>需关进程:是 | `"anyOf" [ { "applicationInstalled", identifiers = ["com.brave.Browser", "Brave"] }, { "anyRootExists" }, ]` | Brave Browser | [1](https://support.brave.com/hc/en-us/articles/360017903152-How-Do-I-Clear-Cookies-And-Site-Data-In-Brave) |
| 4 | `browser.chrome-cache` | safe | true | — | `${user_library}/Caches/Google/Chrome`<br>`${application_support}/Google/Chrome/ShaderCache`<br>`${application_support}/Google/Chrome/GrShaderCache`<br>`${application_support}/Google/Chrome/GraphiteDawnCache`<br>`${application_support}/Google/Chrome/GPUPersistentCache`<br>`${application_support}/Google/Chrome` →展开(子目录名=Default, Guest Profile, System Profile; 子目录前缀=Profile; 固定后缀=Cache, Code Cache, GPUCache, DawnCache, GrShaderCache) | `"all"` | deleteMatchingContents<br>需关进程:是 | `"anyOf" [ { "applicationInstalled", identifiers = ["com.google.Chrome", "Google Chrome"] }, { "anyRootExists" }, ]` | Google Chrome | [1](https://chromium.googlesource.com/chromium/src/+/main/docs/user_data_dir.md) [2](https://support.google.com/accounts/answer/32050) |
| 5 | `browser.chrome-offline-cache` | recoverable | false | true | `${application_support}/Google/Chrome` →展开(子目录名=Default, Guest Profile, System Profile; 子目录前缀=Profile; 固定后缀=Service Worker/CacheStorage, Service Worker/ScriptCache) ✅可重建 | `"all"` | deleteMatchingContents<br>需关进程:是 | `"anyOf" [ { "applicationInstalled", identifiers = ["com.google.Chrome", "Google Chrome"] }, { "anyRootExists" }, ]` | Google Chrome | [1](https://chromium.googlesource.com/chromium/src/+/main/docs/user_data_dir.md) |
| 6 | `browser.chromium-cache` | safe | true | — | `${user_library}/Caches/Chromium`<br>`${application_support}/Chromium` →展开(子目录名=Default, Guest Profile, System Profile; 子目录前缀=Profile; 固定后缀=Cache, Code Cache, GPUCache, DawnCache, GrShaderCache) | `"all"` | deleteMatchingContents<br>需关进程:是 | `"anyOf" [ { "applicationInstalled", identifiers = ["org.chromium.Chromium", "Chromium"] }, { "anyRootExists" }, ]` | Chromium | [1](https://chromium.googlesource.com/chromium/src/+/main/docs/user_data_dir.md) |
| 7 | `browser.edge-cache` | safe | true | — | `${user_library}/Caches/Microsoft Edge`<br>`${application_support}/Microsoft Edge` →展开(子目录名=Default, Guest Profile, System Profile; 子目录前缀=Profile; 固定后缀=Cache, Code Cache, GPUCache, DawnCache, GrShaderCache) | `"all"` | deleteMatchingContents<br>需关进程:是 | `"anyOf" [ { "applicationInstalled", identifiers = ["Microsoft Edge", "Microsoft Edge Update"] }, { "anyRootExists" }, ]` | Microsoft Edge | [1](https://learn.microsoft.com/en-us/deployedge/microsoft-edge-policies/userdatadir) |
| 8 | `browser.edge-offline-cache` | recoverable | false | true | `${application_support}/Microsoft Edge` →展开(子目录名=Default, Guest Profile, System Profile; 子目录前缀=Profile; 固定后缀=Service Worker/CacheStorage, Service Worker/ScriptCache) ✅可重建 | `"all"` | deleteMatchingContents<br>需关进程:是 | `"anyOf" [ { "applicationInstalled", identifiers = ["Microsoft Edge", "Microsoft Edge Update"] }, { "anyRootExists" }, ]` | Microsoft Edge | [1](https://learn.microsoft.com/en-us/deployedge/microsoft-edge-policies/userdatadir) |
| 9 | `browser.firefox-cache` | safe | true | — | `${user_library}/Caches/Firefox/Profiles` | `"all"` | deleteMatchingContents<br>需关进程:是 | `"anyOf" [ { "applicationInstalled", identifiers = ["org.mozilla.firefox", "Mozilla Firefox", "Firefox"] }, { "anyRootExists" }, ]` | firefox | [1](https://support.mozilla.org/en-US/kb/how-clear-firefox-cache) [2](https://support.mozilla.org/en-US/kb/profiles-where-firefox-stores-user-data) |
| 10 | `browser.opera-cache` | safe | true | — | `${user_library}/Caches/com.operasoftware.Opera`<br>`${application_support}/com.operasoftware.Opera/ShaderCache`<br>`${application_support}/com.operasoftware.Opera/GrShaderCache`<br>`${application_support}/com.operasoftware.Opera/GraphiteDawnCache` | `"all"` | deleteMatchingContents<br>需关进程:是 | `"anyOf" [ { "applicationInstalled", identifiers = ["com.operasoftware.Opera", "Opera"] }, { "anyRootExists" }, ]` | Opera | （evidence 文本论证） |
| 11 | `browser.uc-cache` | safe | true | — | `${user_library}/Caches/UC`<br>`${user_library}/Caches/org.uc.UC`<br>`${application_support}/UC/ShaderCache`<br>`${application_support}/UC/GrShaderCache`<br>`${application_support}/UC/GraphiteDawnCache`<br>`${application_support}/UC/component_crx_cache`<br>`${application_support}/UC` →展开(子目录名=Default, Guest Profile, System Profile; 子目录前缀=Profile; 固定后缀=Cache, Code Cache, GPUCache, DawnCache, DawnGraphiteCache, DawnWebGPUCache, GrShaderCache, GraphiteDawnCache, Media Cache) | `"all"` | deleteMatchingContents<br>需关进程:是 | `"anyOf" [ { "applicationInstalled", identifiers = ["org.uc.UC", "UC"] }, { "anyRootExists" }, ] # The signed Apple-silicon build stores its network and code cache under the # platform cache root rather than inside Application Supp` | UC, UC Helper, UC Helper (GPU), UC Helper (Renderer) | [1](https://www.uc.cn/zh-cn/browser/pc.html) [2](https://chromium.googlesource.com/chromium/src/+/main/docs/user_data_dir.md) |
| 12 | `browser.vivaldi-cache` | safe | true | — | `${user_library}/Caches/com.vivaldi.Vivaldi`<br>`${application_support}/Vivaldi/ShaderCache`<br>`${application_support}/Vivaldi/GrShaderCache`<br>`${application_support}/Vivaldi/GraphiteDawnCache`<br>`${application_support}/Vivaldi/component_crx_cache`<br>`${application_support}/Vivaldi/extensions_crx_cache`<br>`${application_support}/Vivaldi` →展开(子目录名=Default, Guest Profile, System Profile; 子目录前缀=Profile; 固定后缀=Cache, Code Cache, GPUCache, DawnCache, GrShaderCache, GraphiteDawnCache, Media Cache) | `"all"` | deleteMatchingContents<br>需关进程:是 | `"anyOf" [ { "applicationInstalled", identifiers = ["com.vivaldi.Vivaldi", "Vivaldi"] }, { "anyRootExists" }, ]` | Vivaldi | （evidence 文本论证） |

#### macos / application（55 条）

| # | 规则 ID | 风险 | 默认勾选 | 智能推荐 | 清理根路径（模板变量） | 匹配器 | 执行策略 | 适用性探针 | 需停止进程 | 权威依据 |
|---|---------|------|---------|---------|----------------------|--------|---------|-----------|-----------|---------|
| 1 | `app.adobe-media-cache` | recoverable | false | true | `${user_library}/Caches/Adobe` ✅可重建<br>`${application_support}/Adobe/Common/Media Cache Files` ✅可重建 | `"all"` | deleteMatchingContents<br>需关进程:是 | `"anyOf" [ { "applicationInstalled", identifiers = ["Adobe Premiere Pro", "Adobe After Effects", "Adobe Media Encoder"] }, { "anyRootExists" }, ]` | Adobe Premiere Pro, Adobe After Effects, Adobe Media Encoder | [1](https://helpx.adobe.com/premiere/desktop/troubleshooting/media-issues/manage-media-cache.html) |
| 2 | `app.apple-mail-cache` | safe | true | — | `${user_library}/Caches/com.apple.mail` | `"all"` | deleteMatchingContents<br>需关进程:是 | `"anyOf" [ { "applicationInstalled", identifiers = ["com.apple.mail", "Mail"] }, { "anyRootExists" }, ]` | Mail | [1](https://developer.apple.com/documentation/foundation/url/cachesdirectory) |
| 3 | `app.baidu-netdisk-rendering-cache` | safe | false | true | `${user_library}/Containers/com.baidu.netdisk/Data/Library/Application Support/baidunetdisk/Cache`<br>`${user_library}/Containers/com.baidu.netdisk/Data/Library/Application Support/baidunetdisk/Code Cache`<br>`${user_library}/Containers/com.baidu.netdisk/Data/Library/Application Support/baidunetdisk/GPUCache`<br>`${user_library}/Containers/com.baidu.netdisk/Data/Library/Application Support/baidunetdisk/DawnCache`<br>`${user_library}/Containers/com.baidu.netdisk/Data/Library/Application Support/baidunetdisk/DawnGraphiteCache`<br>`${user_library}/Containers/com.baidu.netdisk/Data/Library/Application Support/baidunetdisk/DawnWebGPUCache`<br>`${user_library}/Containers/com.baidu.netdisk/Data/Library/Application Support/baidunetdisk/GrShaderCache`<br>`${user_library}/Containers/com.baidu.netdisk/Data/Library/Application Support/baidunetdisk/GraphiteDawnCache`<br>`${user_library}/Containers/com.baidu.netdisk/Data/Library/Application Support/baidunetdisk/Shared Dictionary/cache`<br>`${user_library}/Containers/com.baidu.netdisk/Data/Library/Application Support/baidunetdisk/Service Worker/CacheStorage` | `"all"` | deleteMatchingContents<br>需关进程:是 | `"anyOf" [ { "applicationInstalled", identifiers = ["com.baidu.netdisk", "BaiduNetdisk"] }, { "anyRootExists" }, ]` | BaiduNetdisk | [1](https://pan.baidu.com/download) [2](https://www.electronjs.org/docs/latest/api/app#appgetpathname) [3](https://chromium.googlesource.com/chromium/src/+/main/docs/user_data_dir.md) |
| 4 | `app.chatgpt-cache` | safe | true | — | `${user_library}/Caches/com.openai.chat`<br>`${user_library}/Caches/Codex` | `"all"` | deleteMatchingContents<br>需关进程:是 | `"anyOf" [ { "applicationInstalled", identifiers = ["com.openai.chat", "com.openai.codex", "ChatGPT"] }, { "anyRootExists" }, ]` | ChatGPT | [1](https://developer.apple.com/documentation/foundation/url/cachesdirectory) |
| 5 | `app.clash-verge-diagnostic-cache` | safe | false | true | `${application_support}/io.github.clash-verge-rev.clash-verge-rev/logs` | `"all"` | deleteMatchingContents<br>需关进程:是 | `"anyOf" [ { "applicationInstalled", identifiers = ["io.github.clash-verge-rev.clash-verge-rev", "Clash Verge"] }, { "anyRootExists" }, ]` | clash-verge | [1](https://github.com/clash-verge-rev/clash-verge-rev) |
| 6 | `app.claude-cache` | safe | true | — | `${user_library}/Caches/com.anthropic.claudefordesktop`<br>`${application_support}/Claude/Cache`<br>`${application_support}/Claude/Code Cache`<br>`${application_support}/Claude/GPUCache`<br>`${application_support}/Claude/DawnCache`<br>`${application_support}/Claude/DawnGraphiteCache`<br>`${application_support}/Claude/DawnWebGPUCache`<br>`${application_support}/Claude/GrShaderCache`<br>`${application_support}/Claude/GraphiteDawnCache`<br>`${application_support}/Claude/Shared Dictionary/cache`<br>`${application_support}/Claude/Service Worker/CacheStorage`<br>`${application_support}/Claude/Crashpad/reports`<br>`${application_support}/Claude/Partitions` →展开(全部子目录; 固定后缀=Cache, Code Cache, GPUCache, DawnCache, DawnGraphiteCache, DawnWebGPUCache, GrShaderCache, GraphiteDawnCache, Shared Dictionary/cache, Service Worker/CacheStorage) | `"all"` | deleteMatchingContents<br>需关进程:是 | `"anyOf" [ { "applicationInstalled", identifiers = ["com.anthropic.claudefordesktop", "Claude"] }, { "anyRootExists" }, ]` | Claude | [1](https://support.claude.com/en/articles/10065433-install-claude-desktop) [2](https://www.electronjs.org/docs/latest/api/app#appgetpathname) [3](https://chromium.googlesource.com/chromium/src/+/main/docs/user_data_dir.md) |
| 7 | `app.core-device-cache` | recoverable | false | true | `${user_library}/Containers/com.apple.CoreDevice.CoreDeviceService/Data/Library/Caches` ✅可重建 | `"all"` | deleteMatchingContents<br>需关进程:否 | `"anyRootExists"` | — | [1](https://developer.apple.com/documentation/foundation/using-the-file-system-effectively) |
| 8 | `app.dingtalk-content-cache` | safe | false | true | `${application_support}/DingTalkMac` →展开(全部子目录; 固定后缀=EAppFiles, ImageFiles, GifEmotionFiles, wave_cards, theme_cache, Sync_v2/cache) ✅可重建<br>`${user_library}/Caches/com.alibaba.DingTalkMac/WebKit/NetworkCache`<br>`${user_library}/Caches/com.alibaba.DingTalkMac/WebKit/CacheStorage`<br>`${user_library}/Caches/com.alibaba.DingTalkMac/thumbnails`<br>`${user_library}/Caches/com.alibaba.DingTalkMac/fsCachedData` | `"all"` | deleteMatchingContents<br>需关进程:是 | `"anyOf" [ { "applicationInstalled", identifiers = ["com.alibaba.DingTalkMac", "DingTalk"] }, { "anyRootExists" }, ]` | DingTalk, DingTalkMac | [1](https://page.dingtalk.com/wow/z/dingtalk/default/585885) |
| 9 | `app.dingtalk-diagnostic-cache` | safe | false | true | `${application_support}/DingTalkMac/log`<br>`${application_support}/DingTalkMac/activitylog` ✅可重建<br>`${application_support}/DingTalkMac/holmeslogs` ✅可重建<br>`${application_support}/DingTalkMac/image_translate_cache`<br>`${application_support}/DingTalkMac/image_res_cache` | `"all"` | deleteMatchingContents<br>需关进程:是 | `"anyOf" [ { "applicationInstalled", identifiers = ["com.alibaba.DingTalkMac", "DingTalk"] }, { "anyRootExists" }, ]` | DingTalk, DingTalkMac | （evidence 文本论证） |
| 10 | `app.discord-cache` | safe | true | — | `${user_library}/Caches/com.hnc.Discord`<br>`${application_support}/discord/Cache`<br>`${application_support}/discord/Code Cache`<br>`${application_support}/discord/GPUCache`<br>`${application_support}/discord/DawnCache`<br>`${application_support}/discord/DawnGraphiteCache`<br>`${application_support}/discord/DawnWebGPUCache`<br>`${application_support}/discord/GrShaderCache`<br>`${application_support}/discord/GraphiteDawnCache`<br>`${application_support}/discord/Shared Dictionary/cache`<br>`${application_support}/discord/logs`<br>`${application_support}/discord/Crashpad/reports` | `"all"` | deleteMatchingContents<br>需关进程:是 | `"anyOf" [ { "applicationInstalled", identifiers = ["com.hnc.Discord", "Discord"] }, { "anyRootExists" }, ]` | Discord | [1](https://www.electronjs.org/docs/latest/api/app#appgetpathname) [2](https://chromium.googlesource.com/chromium/src/+/main/docs/user_data_dir.md) |
| 11 | `app.electron-productivity-cache` | safe | false | true | `${application_support}` →展开(子目录名=Insomnia, Notion, obsidian, GitHub Desktop; 固定后缀=Cache, Code Cache, GPUCache, DawnCache, DawnGraphiteCache, DawnWebGPUCache, GrShaderCache, GraphiteDawnCache, Shared Dictionary/cache, logs, Crashpad/reports) | `"all"` | deleteMatchingContents<br>需关进程:是 | `"anyRootExists"` | Insomnia, Notion, Obsidian, GitHub Desktop | [1](https://www.electronjs.org/docs/latest/api/app#appgetpathname) [2](https://chromium.googlesource.com/chromium/src/+/main/docs/user_data_dir.md) |
| 12 | `app.figma-cache` | safe | true | — | `${user_library}/Caches/com.figma.Desktop`<br>`${application_support}/Figma/Cache`<br>`${application_support}/Figma/Code Cache`<br>`${application_support}/Figma/GPUCache` | `"all"` | deleteMatchingContents<br>需关进程:是 | `"anyOf" [ { "applicationInstalled", identifiers = ["com.figma.Desktop", "Figma"] }, { "anyRootExists" }, ]` | Figma | [1](https://www.electronjs.org/docs/latest/api/app#appgetpathname) |
| 13 | `app.flashvoice-cache` | safe | false | true | `${user_library}/Caches/FlashVoice`<br>`${application_support}/com.flashvoices/logs` | `"all"` | deleteMatchingContents<br>需关进程:是 | `"anyOf" [ { "applicationInstalled", identifiers = ["com.flashvoices", "FlashVoice"] }, { "anyRootExists" }, ]` | FlashVoice | [1](https://developer.apple.com/documentation/foundation/filemanager/searchpathdirectory/cachesdirectory) |
| 14 | `app.game-launcher-cache` | safe | false | true | `${user_library}/Caches/com.epicgames.EpicGamesLauncher/webcache` | `"all"` | deleteMatchingContents<br>需关进程:是 | `"anyOf" [ { "applicationInstalled", identifiers = ["com.epicgames.EpicGamesLauncher", "Epic Games Launcher"] }, { "anyRootExists" }, ]` | EpicGamesLauncher, EpicWebHelper | [1](https://www.epicgames.com/help/c-1/a202300000013316) |
| 15 | `app.google-updater-cache` | safe | true | — | `${application_support}/Google/GoogleUpdater/crx_cache` | `"all"` | deleteMatchingContents<br>需关进程:否 | `"anyRootExists"` | — | [1](https://support.google.com/chrome/answer/14697318?hl=en) |
| 16 | `app.iwork-cache` | safe | true | — | `${user_library}/Caches/com.apple.iWork.Pages`<br>`${user_library}/Caches/com.apple.iWork.Numbers`<br>`${user_library}/Caches/com.apple.iWork.Keynote` | `"all"` | deleteMatchingContents<br>需关进程:是 | `"anyOf" [ { "applicationInstalled", identifiers = ["com.apple.iWork.Pages", "com.apple.iWork.Numbers", "com.apple.iWork.Keynote"] }, { "anyRootExists" }, ]` | Pages, Numbers, Keynote | [1](https://developer.apple.com/documentation/foundation/url/cachesdirectory) |
| 17 | `app.lark-renderer-cache` | safe | false | true | `${user_library}/Caches/LarkShell/aha/users` →展开(全部子目录; 固定后缀=profile_explorer/Cache, profile_explorer/Code Cache, profile_main/Cache, profile_main/Code Cache, profile_global/Cache, profile_global/Code Cache)<br>`${application_support}/LarkShell/aha/users` →展开(全部子目录; 固定后缀=profile_explorer/Cache, profile_explorer/Code Cache, profile_explorer/GPUCache, profile_explorer/DawnCache, profile_explorer/DawnGraphiteCache, profile_explorer/DawnWebGPUCache, profile_explorer/GrShaderCache, profile_explorer/GraphiteDawnCache, profile_explorer/Shared Dictionary/cache, profile_explorer/Service Worker/CacheStorage, profile_main/Cache, profile_main/Code Cache, profile_main/GPUCache, profile_main/DawnCache, profile_main/DawnGraphiteCache, profile_main/DawnWebGPUCache, profile_main/GrShaderCache, profile_main/GraphiteDawnCache, profile_main/Shared Dictionary/cache, profile_main/Service Worker/CacheStorage, profile_global/Cache, profile_global/Code Cache, profile_global/GPUCache, profile_global/DawnCache, profile_global/DawnGraphiteCache, profile_global/DawnWebGPUCache, profile_global/GrShaderCache, profile_global/GraphiteDawnCache, profile_global/Shared Dictionary/cache, profile_global/Service Worker/CacheStorage)<br>`${application_support}/LarkShell/iron/users` →展开(全部子目录; 固定后缀=profile_explorer/Cache, profile_explorer/Code Cache, profile_explorer/GPUCache, profile_explorer/DawnCache, profile_explorer/DawnGraphiteCache, profile_explorer/DawnWebGPUCache, profile_explorer/GrShaderCache, profile_explorer/GraphiteDawnCache, profile_explorer/Shared Dictionary/cache, profile_explorer/Service Worker/CacheStorage, profile_main/Cache, profile_main/Code Cache, profile_main/GPUCache, profile_main/DawnCache, profile_main/DawnGraphiteCache, profile_main/DawnWebGPUCache, profile_main/GrShaderCache, profile_main/GraphiteDawnCache, profile_main/Shared Dictionary/cache, profile_main/Service Worker/CacheStorage, profile_global/Cache, profile_global/Code Cache, profile_global/GPUCache, profile_global/DawnCache, profile_global/DawnGraphiteCache, profile_global/DawnWebGPUCache, profile_global/GrShaderCache, profile_global/GraphiteDawnCache, profile_global/Shared Dictionary/cache, profile_global/Service Worker/CacheStorage)<br>`${application_support}/LarkShell/ShaderCache`<br>`${application_support}/LarkShell/GrShaderCache`<br>`${application_support}/LarkShell/GraphiteDawnCache`<br>`${application_support}/LarkShell/CodeCache`<br>`${application_support}/LarkShell/component_crx_cache`<br>`${application_support}/LarkShell/iron/Cache`<br>`${application_support}/LarkShell/iron/GPUCache`<br>`${application_support}/LarkShell/iron/Shared Dictionary/cache`<br>`${application_support}/LarkShell/iron/Code Cache`<br>`${application_support}/LarkShell/iron/DawnCache`<br>`${application_support}/LarkShell/iron/DawnGraphiteCache`<br>`${application_support}/LarkShell/iron/DawnWebGPUCache`<br>`${application_support}/LarkShell/iron/GrShaderCache`<br>`${application_support}/LarkShell/iron/GraphiteDawnCache`<br>`${application_support}/LarkShell/iron/Service Worker/CacheStorage` | `"all"` | deleteMatchingContents<br>需关进程:是 | `"anyOf" [ { "applicationInstalled", identifiers = ["com.electron.lark", "com.bytedance.lark", "Lark", "Feishu"] }, { "anyRootExists" }, ]` | Lark, Feishu, LarkShell, Lark Helper, Lark Helper (GPU), Lark Helper (Renderer) | [1](https://www.larksuite.com/hc/en-US/articles/360048488246-clear-cache-and-system-reset-faqs) [2](https://chromium.googlesource.com/chromium/src/+/main/docs/user_data_dir.md) |
| 18 | `app.lm-studio-cache` | safe | true | — | `${user_library}/Caches/com.lmstudio.lmstudio` | `"all"` | deleteMatchingContents<br>需关进程:是 | `"anyOf" [ { "applicationInstalled", identifiers = ["com.lmstudio.lmstudio", "LM Studio"] }, { "anyRootExists" }, ]` | LM Studio | [1](https://developer.apple.com/documentation/foundation/url/cachesdirectory) |
| 19 | `app.lobsterai-update-cache` | safe | false | true | `${application_support}/LobsterAI/updates` | `"allOf" [ { "nameGlob", values = ["lobsterai-update-auto-*.dmg"] }, { "maxDepth", depth = 1 }, ]` | deleteMatchingContents<br>需关进程:是 | `"anyOf" [ { "applicationInstalled", identifiers = ["com.lobsterai.app", "LobsterAI"] }, { "anyRootExists" }, ]` | LobsterAI | [1](https://github.com/netease-youdao/LobsterAI) |
| 20 | `app.manus-rendering-cache` | safe | false | true | `${application_support}/Manus/Cache`<br>`${application_support}/Manus/Code Cache`<br>`${application_support}/Manus/GPUCache`<br>`${application_support}/Manus/DawnCache`<br>`${application_support}/Manus/DawnGraphiteCache`<br>`${application_support}/Manus/DawnWebGPUCache`<br>`${application_support}/Manus/GrShaderCache`<br>`${application_support}/Manus/GraphiteDawnCache`<br>`${application_support}/Manus/Shared Dictionary/cache`<br>`${application_support}/Manus/Service Worker/CacheStorage`<br>`${application_support}/Manus/Crashpad/reports` | `"all"` | deleteMatchingContents<br>需关进程:是 | `"anyOf" [ { "applicationInstalled", identifiers = ["im.manus.desktop", "Manus"] }, { "anyRootExists" }, ]` | Manus | [1](https://manus.im/desktop) [2](https://www.electronjs.org/docs/latest/api/app#appgetpathname) [3](https://chromium.googlesource.com/chromium/src/+/main/docs/user_data_dir.md) |
| 21 | `app.manus-update-cache` | recoverable | false | true | `${user_library}/Caches/manus-updater` ✅可重建<br>`${user_library}/Caches/im.manus.desktop` ✅可重建 | `"all"` | deleteMatchingContents<br>需关进程:是 | `"anyOf" [ { "applicationInstalled", identifiers = ["im.manus.desktop", "Manus"] }, { "anyRootExists" }, ]` | Manus | [1](https://help.manus.im/en/articles/14089011-how-to-download-the-manus-desktop-app) [2](https://developer.apple.com/documentation/foundation/url/cachesdirectory) |
| 22 | `app.media-analysis-cache` | safe | true | — | `${user_library}/Containers/com.apple.mediaanalysisd/Data/Library/Caches`<br>`${user_library}/Containers/com.apple.mediaanalysisd/Data/tmp` | `"all"` | deleteMatchingContents<br>需关进程:否 | `"anyRootExists"` | — | [1](https://developer.apple.com/documentation/foundation/using-the-file-system-effectively) |
| 23 | `app.media-cache` | safe | true | — | `${user_library}/Caches/com.spotify.client`<br>`${user_library}/Caches/com.apple.Music`<br>`${user_library}/Caches/com.apple.podcasts`<br>`${user_library}/Caches/com.apple.TV`<br>`${user_library}/Caches/com.colliderli.iina` | `"all"` | deleteMatchingContents<br>需关进程:是 | `"anyRootExists"` | Spotify, Music, Podcasts, TV, IINA | [1](https://developer.apple.com/documentation/foundation/url/cachesdirectory) |
| 24 | `app.obs-diagnostic-cache` | safe | true | — | `${application_support}/obs-studio/logs`<br>`${application_support}/obs-studio/profiler_data` | `"olderThan" days = 14` | deleteMatchingContents<br>需关进程:是 | `"anyOf" [ { "applicationInstalled", identifiers = ["com.obsproject.obs-studio", "OBS"] }, { "anyRootExists" }, ]` | OBS | （evidence 文本论证） |
| 25 | `app.office-cache` | recoverable | false | true | `${user_library}/Caches/com.microsoft.Word` ✅可重建<br>`${user_library}/Caches/com.microsoft.Excel` ✅可重建<br>`${user_library}/Caches/com.microsoft.Powerpoint` ✅可重建 | `"all"` | deleteMatchingContents<br>需关进程:是 | `"anyOf" [ { "applicationInstalled", identifiers = ["com.microsoft.Word", "com.microsoft.Excel", "com.microsoft.Powerpoint"] }, { "anyRootExists" }, ]` | Microsoft Word, Microsoft Excel, Microsoft PowerPoint | [1](https://developer.apple.com/documentation/foundation/url/cachesdirectory) |
| 26 | `app.ollama-update-cache` | safe | false | true | `${user_library}/Caches/ollama/updates` | `"allOf" [ { "nameEquals", values = ["Ollama-darwin.zip"] }, { "olderThan", days = 7 }, { "maxDepth", depth = 2 }, ]` | deleteMatchingContents<br>需关进程:否 | `"anyOf" [ { "applicationInstalled", identifiers = ["com.electron.ollama", "Ollama"] }, { "anyRootExists" }, ]` | — | [1](https://github.com/ollama/ollama/issues/11972) |
| 27 | `app.outlook-cache` | safe | true | — | `${user_library}/Caches/com.microsoft.Outlook` | `"all"` | deleteMatchingContents<br>需关进程:是 | `"anyOf" [ { "applicationInstalled", identifiers = ["com.microsoft.Outlook", "Microsoft Outlook"] }, { "anyRootExists" }, ]` | Microsoft Outlook | [1](https://developer.apple.com/documentation/foundation/url/cachesdirectory) |
| 28 | `app.parallels-windows-image-cache` | recoverable | false | true | `${user_library}/Parallels/Downloads` ✅可重建 | `"allOf" [ { "extensionIn", values = ["esd"] }, { "olderThan", days = 7 }, { "maxDepth", depth = 1 }, ]` | deleteMatchingContents<br>需关进程:否 | `"anyOf" [ { "applicationInstalled", identifiers = ["com.parallels.desktop.console", "Parallels Desktop"] }, { "anyRootExists" }, ]` | — | [1](https://kb.parallels.com/en/129607) [2](https://kb.parallels.com/en/130126) |
| 29 | `app.postman-cache` | safe | false | true | `${application_support}/Postman/Cache`<br>`${application_support}/Postman/Code Cache`<br>`${application_support}/Postman/GPUCache`<br>`${application_support}/Postman/DawnCache`<br>`${application_support}/Postman/DawnGraphiteCache`<br>`${application_support}/Postman/DawnWebGPUCache`<br>`${application_support}/Postman/GrShaderCache`<br>`${application_support}/Postman/GraphiteDawnCache`<br>`${application_support}/Postman/logs`<br>`${application_support}/Postman/Shared Dictionary/cache`<br>`${application_support}/Postman/Partitions` →展开(全部子目录; 固定后缀=Cache, Code Cache, GPUCache, DawnCache, DawnGraphiteCache, DawnWebGPUCache, GrShaderCache, GraphiteDawnCache, Shared Dictionary/cache) | `"all"` | deleteMatchingContents<br>需关进程:是 | `"anyOf" [ { "applicationInstalled", identifiers = ["com.postmanlabs.mac", "Postman"] }, { "anyRootExists" }, ]` | Postman | [1](https://learning.postman.com/latest-v-12/docs/getting-started/troubleshooting-inapp) [2](https://www.electronjs.org/docs/latest/api/app#appgetpathname) [3](https://chromium.googlesource.com/chromium/src/+/main/docs/user_data_dir.md) |
| 30 | `app.qq-cache` | safe | false | true | `${user_library}/Caches/com.tencent.qq`<br>`${user_library}/Containers/com.tencent.qq/Data/Library/Application Support/QQ/Cache`<br>`${user_library}/Containers/com.tencent.qq/Data/Library/Application Support/QQ/Code Cache`<br>`${user_library}/Containers/com.tencent.qq/Data/Library/Application Support/QQ/GPUCache`<br>`${user_library}/Containers/com.tencent.qq/Data/Library/Application Support/QQ/DawnCache`<br>`${user_library}/Containers/com.tencent.qq/Data/Library/Application Support/QQ/DawnGraphiteCache`<br>`${user_library}/Containers/com.tencent.qq/Data/Library/Application Support/QQ/DawnWebGPUCache`<br>`${user_library}/Containers/com.tencent.qq/Data/Library/Application Support/QQ/GrShaderCache`<br>`${user_library}/Containers/com.tencent.qq/Data/Library/Application Support/QQ/GraphiteDawnCache`<br>`${user_library}/Containers/com.tencent.qq/Data/Library/Application Support/QQ/Shared Dictionary/cache`<br>`${user_library}/Containers/com.tencent.qq/Data/Library/Application Support/QQ/Partitions` →展开(全部子目录; 固定后缀=Cache, Code Cache, GPUCache, DawnCache, DawnGraphiteCache, DawnWebGPUCache, GrShaderCache, GraphiteDawnCache, Shared Dictionary/cache, Service Worker/CacheStorage) | `"all"` | deleteMatchingContents<br>需关进程:是 | `"anyOf" [ { "applicationInstalled", identifiers = ["com.tencent.qq", "QQ"] }, { "anyRootExists" }, ]` | QQ | [1](https://im.qq.com/macqq/index.shtml) [2](https://chromium.googlesource.com/chromium/src/+/main/docs/user_data_dir.md) |
| 31 | `app.qq-update-cache` | safe | false | true | `${user_library}/Containers/com.tencent.qq/Data/Library/Application Support/QQ/versions` | `"allOf" [ { "nameGlob", values = ["*.zip"] }, { "olderThan", days = 7 }, { "maxDepth", depth = 1 }, ]` | deleteMatchingContents<br>需关进程:否 | `"anyOf" [ { "applicationInstalled", identifiers = ["com.tencent.qq", "QQ"] }, { "anyRootExists" }, ]` | — | [1](https://im.qq.com/macqq/index.shtml) |
| 32 | `app.qqlive-rendering-cache` | safe | false | true | `${user_library}/Caches/com.tencent.tenvideo`<br>`${application_support}/Caches/com.tencent.tenvideo`<br>`${application_support}/com.tencent.mac.marvis/icon_cache`<br>`${application_support}/com.tencent.mac.marvis/Cache`<br>`${application_support}/com.tencent.mac.marvis/Code Cache`<br>`${application_support}/com.tencent.mac.marvis/GPUCache`<br>`${application_support}/com.tencent.mac.marvis/DawnCache`<br>`${application_support}/com.tencent.mac.marvis/DawnGraphiteCache`<br>`${application_support}/com.tencent.mac.marvis/DawnWebGPUCache`<br>`${application_support}/com.tencent.mac.marvis/GrShaderCache`<br>`${application_support}/com.tencent.mac.marvis/GraphiteDawnCache`<br>`${application_support}/com.tencent.mac.marvis/Shared Dictionary/cache`<br>`${application_support}/com.tencent.mac.marvis/Crashpad/reports`<br>`${application_support}/com.tencent.mac.marvis/Partitions` →展开(全部子目录; 固定后缀=Cache, Code Cache, GPUCache, DawnCache, DawnGraphiteCache, DawnWebGPUCache, GrShaderCache, GraphiteDawnCache, Shared Dictionary/cache) | `"all"` | deleteMatchingContents<br>需关进程:是 | `"anyOf" [ { "applicationInstalled", identifiers = ["com.tencent.tenvideo", "QQLive", "腾讯视频"] }, { "anyRootExists" }, ]` | QQLive | [1](https://v.qq.com/download.html) [2](https://chromium.googlesource.com/chromium/src/+/main/docs/user_data_dir.md) |
| 33 | `app.qwenwork-cache` | safe | false | true | `${application_support}/QwenWorkCN/Cache`<br>`${application_support}/QwenWorkCN/Code Cache`<br>`${application_support}/QwenWorkCN/GPUCache`<br>`${application_support}/QwenWorkCN/DawnCache`<br>`${application_support}/QwenWorkCN/DawnGraphiteCache`<br>`${application_support}/QwenWorkCN/DawnWebGPUCache`<br>`${application_support}/QwenWorkCN/GrShaderCache`<br>`${application_support}/QwenWorkCN/GraphiteDawnCache`<br>`${application_support}/QwenWorkCN/Shared Dictionary/cache`<br>`${application_support}/QwenWorkCN/logs`<br>`${application_support}/QwenWorkCN/Crashpad/reports`<br>`${application_support}/QwenWorkCN/Partitions` →展开(全部子目录; 固定后缀=Cache, Code Cache, GPUCache, DawnCache, DawnGraphiteCache, DawnWebGPUCache, GrShaderCache, GraphiteDawnCache, Shared Dictionary/cache) | `"all"` | deleteMatchingContents<br>需关进程:是 | `"anyOf" [ { "applicationInstalled", identifiers = ["cn.qwenwork.desktop.mac", "QwenWorkCN"] }, { "anyRootExists" }, ]` | QwenWorkCN | [1](https://www.electronjs.org/docs/latest/api/app#appgetpathname) [2](https://chromium.googlesource.com/chromium/src/+/main/docs/user_data_dir.md) |
| 34 | `app.slack-cache` | safe | true | — | `${user_library}/Caches/com.tinyspeck.slackmacgap`<br>`${application_support}/Slack/Cache`<br>`${application_support}/Slack/Code Cache`<br>`${application_support}/Slack/GPUCache`<br>`${application_support}/Slack/Service Worker/CacheStorage` | `"all"` | deleteMatchingContents<br>需关进程:是 | `"anyOf" [ { "applicationInstalled", identifiers = ["com.tinyspeck.slackmacgap", "Slack"] }, { "anyRootExists" }, ]` | Slack | [1](https://slack.com/help/articles/205138367-Troubleshoot-connection-issues) [2](https://www.electronjs.org/docs/latest/api/app#appgetpathname) |
| 35 | `app.teams-cache` | safe | true | — | `${user_library}/Caches/com.microsoft.teams2`<br>`${application_support}/Microsoft/Teams/Cache`<br>`${application_support}/Microsoft/Teams/Code Cache`<br>`${application_support}/Microsoft/Teams/GPUCache` | `"all"` | deleteMatchingContents<br>需关进程:是 | `"anyOf" [ { "applicationInstalled", identifiers = ["com.microsoft.teams2", "Microsoft Teams"] }, { "anyRootExists" }, ]` | MSTeams, Microsoft Teams | [1](https://learn.microsoft.com/en-us/troubleshoot/microsoftteams/teams-administration/clear-teams-cache) |
| 36 | `app.telegram-cache` | safe | true | — | `${user_library}/Caches/com.tdesktop.Telegram`<br>`${user_library}/Caches/ru.keepcoder.Telegram` | `"all"` | deleteMatchingContents<br>需关进程:是 | `"anyOf" [ { "applicationInstalled", identifiers = ["com.tdesktop.Telegram", "ru.keepcoder.Telegram", "Telegram"] }, { "anyRootExists" }, ]` | Telegram | [1](https://developer.apple.com/documentation/foundation/url/cachesdirectory) |
| 37 | `app.telegram-temporary-cache` | safe | false | true | `${application_support}/Telegram Desktop/tdata/temp`<br>`${application_support}/Telegram Desktop/tdata/dumps` | `"extensionIn" values = ["dmp", "dat", "tmp", "png", "ico", "ics"]` | deleteMatchingContents<br>需关进程:是 | `"anyOf" [ { "applicationInstalled", identifiers = ["com.tdesktop.Telegram", "ru.keepcoder.Telegram", "Telegram"] }, { "anyRootExists" }, ]` | Telegram | [1](https://github.com/telegramdesktop/tdesktop/tree/v7.0.1) |
| 38 | `app.tencent-lemon-cache` | safe | true | — | `${user_library}/Caches/com.tencent.Lemon`<br>`${user_library}/Caches/com.tencent.LemonMonitor`<br>`${user_library}/Caches/com.tencent.LemonUpdate` | `"all"` | deleteMatchingContents<br>需关进程:是 | `"anyOf" [ { "applicationInstalled", identifiers = ["com.tencent.Lemon", "Tencent Lemon"] }, { "anyRootExists" }, ]` | Tencent Lemon, LemonMonitor, LemonUpdate | [1](https://lemon.qq.com/) [2](https://developer.apple.com/documentation/foundation/url/cachesdirectory) |
| 39 | `app.tencent-meeting-cache` | safe | true | — | `${user_library}/Caches/com.tencent.meeting/WebKit/NetworkCache` | `"all"` | deleteMatchingContents<br>需关进程:是 | `"anyOf" [ { "applicationInstalled", identifiers = ["com.tencent.meeting", "TencentMeeting", "Tencent Meeting"] }, { "anyRootExists" }, ]` | TencentMeeting | [1](https://meeting.tencent.com/download/) [2](https://developer.apple.com/documentation/foundation/url/cachesdirectory) |
| 40 | `app.thunder-cache` | safe | false | true | `${user_library}/Caches/com.xunlei.Thunder` | `"all"` | deleteMatchingContents<br>需关进程:是 | `"anyOf" [ { "applicationInstalled", identifiers = ["com.xunlei.Thunder", "Thunder", "迅雷"] }, { "anyRootExists" }, ]` | Thunder, DownloadService | [1](https://mac.xunlei.com/) [2](https://developer.apple.com/documentation/foundation/url/cachesdirectory) |
| 41 | `app.thunderbird-cache` | safe | true | — | `${user_library}/Caches/org.mozilla.thunderbird` | `"all"` | deleteMatchingContents<br>需关进程:是 | `"anyOf" [ { "applicationInstalled", identifiers = ["org.mozilla.thunderbird", "Mozilla Thunderbird", "Thunderbird"] }, { "anyRootExists" }, ]` | Thunderbird | [1](https://developer.apple.com/documentation/foundation/url/cachesdirectory) |
| 42 | `app.utools-rendering-cache` | safe | false | true | `${application_support}/uTools/Cache`<br>`${application_support}/uTools/Code Cache`<br>`${application_support}/uTools/GPUCache`<br>`${application_support}/uTools/DawnCache`<br>`${application_support}/uTools/DawnGraphiteCache`<br>`${application_support}/uTools/DawnWebGPUCache`<br>`${application_support}/uTools/GrShaderCache`<br>`${application_support}/uTools/GraphiteDawnCache`<br>`${application_support}/uTools/Shared Dictionary/cache`<br>`${application_support}/uTools/Service Worker/CacheStorage`<br>`${application_support}/uTools/logs`<br>`${application_support}/uTools/Crashpad/reports`<br>`${application_support}/uTools/Partitions` →展开(全部子目录; 固定后缀=Cache, Code Cache, GPUCache, DawnCache, DawnGraphiteCache, DawnWebGPUCache, GrShaderCache, GraphiteDawnCache, Shared Dictionary/cache, Service Worker/CacheStorage) | `"all"` | deleteMatchingContents<br>需关进程:是 | `"anyOf" [ { "applicationInstalled", identifiers = ["org.yuanli.utools", "uTools"] }, { "anyRootExists" }, ]` | uTools | [1](https://www.u-tools.cn/) [2](https://www.electronjs.org/docs/latest/api/app#appgetpathname) [3](https://chromium.googlesource.com/chromium/src/+/main/docs/user_data_dir.md) |
| 43 | `app.vlc-cache` | safe | false | true | `${user_library}/Caches/org.videolan.vlc` | `"all"` | deleteMatchingContents<br>需关进程:是 | `"anyOf" [ { "applicationInstalled", identifiers = ["org.videolan.vlc", "VLC"] }, { "anyRootExists" }, ]` | VLC | [1](https://developer.apple.com/documentation/foundation/url/cachesdirectory) [2](https://github.com/videolan/vlc/tree/3.0.23) |
| 44 | `app.wallpaper-agent-cache` | safe | true | — | `${user_library}/Containers/com.apple.wallpaper.agent/Data/Library/Caches` | `"all"` | deleteMatchingContents<br>需关进程:否 | `"anyRootExists"` | — | [1](https://developer.apple.com/documentation/foundation/using-the-file-system-effectively) |
| 45 | `app.wechat-cache` | safe | false | true | `${user_library}/Caches/com.tencent.xinWeChat`<br>`${user_library}/Containers/com.tencent.xinWeChat/Data/Documents/app_data/radium/web/profiles` →展开(全部子目录; 固定后缀=Cache, Code Cache, GPUCache, DawnCache, DawnGraphiteCache, DawnWebGPUCache, GrShaderCache, GraphiteDawnCache, Shared Dictionary/cache, Service Worker/CacheStorage)<br>`${user_library}/Containers/com.tencent.xinWeChat/Data/Library/Caches/profiles` →展开(全部子目录; 固定后缀=Cache, Code Cache, GPUCache, DawnCache, DawnGraphiteCache, DawnWebGPUCache, GrShaderCache, GraphiteDawnCache, Shared Dictionary/cache, Service Worker/CacheStorage) | `"all"` | deleteMatchingContents<br>需关进程:是 | `"anyOf" [ { "applicationInstalled", identifiers = ["com.tencent.xinWeChat", "WeChat"] }, { "anyRootExists" }, ]` | WeChat | [1](https://weixin.qq.com/) [2](https://chromium.googlesource.com/chromium/src/+/main/docs/user_data_dir.md) |
| 46 | `app.wecom-cache` | safe | false | true | `${user_library}/Caches/com.tencent.WeWorkMac`<br>`${user_library}/Containers/com.tencent.WeWorkMac/Data/Documents/cefcache/Cache`<br>`${user_library}/Containers/com.tencent.WeWorkMac/Data/Documents/cefcache/Code Cache`<br>`${user_library}/Containers/com.tencent.WeWorkMac/Data/Documents/cefcache/GPUCache`<br>`${user_library}/Containers/com.tencent.WeWorkMac/Data/Documents/cefcache/DawnCache`<br>`${user_library}/Containers/com.tencent.WeWorkMac/Data/Documents/cefcache/DawnGraphiteCache`<br>`${user_library}/Containers/com.tencent.WeWorkMac/Data/Documents/cefcache/DawnWebGPUCache`<br>`${user_library}/Containers/com.tencent.WeWorkMac/Data/Documents/cefcache/GrShaderCache`<br>`${user_library}/Containers/com.tencent.WeWorkMac/Data/Documents/cefcache/GraphiteDawnCache`<br>`${user_library}/Containers/com.tencent.WeWorkMac/Data/Documents/cefcache/ShaderCache`<br>`${user_library}/Containers/com.tencent.WeWorkMac/Data/Documents/cefcache/Shared Dictionary/cache`<br>`${user_library}/Containers/com.tencent.WeWorkMac/Data/Documents/cefcache/Service Worker/CacheStorage`<br>`${user_library}/Containers/com.tencent.WeWorkMac/Data/Documents/cefcache/component_crx_cache`<br>`${user_library}/Containers/com.tencent.WeWorkMac/Data/Documents/cefcache` →展开(子目录前缀=wew_; 固定后缀=Cache, Code Cache, GPUCache, DawnCache, DawnGraphiteCache, DawnWebGPUCache, GrShaderCache, GraphiteDawnCache, Shared Dictionary/cache, Service Worker/CacheStorage) | `"all"` | deleteMatchingContents<br>需关进程:是 | `"anyOf" [ { "applicationInstalled", identifiers = ["com.tencent.WeWorkMac", "WeCom"] }, { "anyRootExists" }, ]` | WeCom, WXWork, 企业微信 | [1](https://apps.apple.com/app/id1189898970?mt=12) [2](https://chromium.googlesource.com/chromium/src/+/main/docs/user_data_dir.md) |
| 47 | `app.whatsapp-cache` | safe | true | — | `${user_library}/Caches/net.whatsapp.WhatsApp` | `"all"` | deleteMatchingContents<br>需关进程:是 | `"anyOf" [ { "applicationInstalled", identifiers = ["net.whatsapp.WhatsApp", "WhatsApp"] }, { "anyRootExists" }, ]` | WhatsApp | [1](https://developer.apple.com/documentation/foundation/url/cachesdirectory) |
| 48 | `app.workbuddy-rendering-cache` | safe | false | true | `${home}/.workbuddy/app/session/Cache`<br>`${home}/.workbuddy/app/session/Code Cache`<br>`${home}/.workbuddy/app/session/GPUCache`<br>`${home}/.workbuddy/app/session/DawnCache`<br>`${home}/.workbuddy/app/session/DawnGraphiteCache`<br>`${home}/.workbuddy/app/session/DawnWebGPUCache`<br>`${home}/.workbuddy/app/session/GrShaderCache`<br>`${home}/.workbuddy/app/session/GraphiteDawnCache`<br>`${home}/.workbuddy/app/session/Shared Dictionary/cache`<br>`${home}/.workbuddy/app/session/Service Worker/CacheStorage`<br>`${home}/.workbuddy/app/session/Partitions` →展开(全部子目录; 固定后缀=Cache, Code Cache, GPUCache, DawnCache, DawnGraphiteCache, DawnWebGPUCache, GrShaderCache, GraphiteDawnCache, Shared Dictionary/cache, Service Worker/CacheStorage) | `"all"` | deleteMatchingContents<br>需关进程:是 | `"anyOf" [ { "applicationInstalled", identifiers = ["com.workbuddy.workbuddy", "WorkBuddy"] }, { "anyRootExists" }, ]` | WorkBuddy Helper, WorkBuddy Helper (GPU), WorkBuddy Helper (Renderer), WorkBuddyRepair | [1](https://copilot.tencent.com/work/) [2](https://www.codebuddy.cn/docs/workbuddy/Overview) [3](https://www.electronjs.org/docs/latest/api/app#appgetpathname) [4](https://chromium.googlesource.com/chromium/src/+/main/docs/user_data_dir.md) |
| 49 | `app.wps-cache` | safe | true | — | `${user_library}/Caches/com.kingsoft.wpsoffice.mac`<br>`${user_library}/Containers/com.kingsoft.wpsoffice.mac.global/Data/Library/Caches/com.kingsoft.wpsoffice.mac.global` | `"all"` | deleteMatchingContents<br>需关进程:是 | `"anyOf" [ { "applicationInstalled", identifiers = ["com.kingsoft.wpsoffice.mac", "com.kingsoft.wpsoffice.mac.global", "wpsoffice", "WPS Office"] }, { "anyRootExists" }, ]` | wpsoffice,
  WPS Office,
  wpscloudsvr,
  promecefpluginhost,
  promecefpluginhost (GPU),
  promecefpluginhost (Renderer), | [1](https://www.wps.com/office/mac/) [2](https://developer.apple.com/documentation/foundation/url/cachesdirectory) |
| 50 | `app.wps-diagnostic-cache` | safe | false | true | `${user_library}/Containers/com.kingsoft.wpsoffice.mac.global/Data/Library/Application Support/Kingsoft/office6` | `"pathSegmentIn" values = ["log", "dump"]` | deleteMatchingContents<br>需关进程:是 | `"anyOf" [ { "applicationInstalled", identifiers = ["com.kingsoft.wpsoffice.mac.global", "wpsoffice", "WPS Office"] }, { "anyRootExists" }, ]` | wpsoffice,
  WPS Office,
  wpscloudsvr,
  promecefpluginhost,
  promecefpluginhost (GPU),
  promecefpluginhost (Renderer), | [1](https://www.wps.com/office/mac/) |
| 51 | `app.xmind-rendering-cache` | safe | false | true | `${application_support}/Xmind/Electron v3/Cache`<br>`${application_support}/Xmind/Electron v3/Code Cache`<br>`${application_support}/Xmind/Electron v3/GPUCache`<br>`${application_support}/Xmind/Electron v3/DawnCache`<br>`${application_support}/Xmind/Electron v3/DawnGraphiteCache`<br>`${application_support}/Xmind/Electron v3/DawnWebGPUCache`<br>`${application_support}/Xmind/Electron v3/GrShaderCache`<br>`${application_support}/Xmind/Electron v3/GraphiteDawnCache`<br>`${application_support}/Xmind/Electron v3/Shared Dictionary/cache`<br>`${application_support}/Xmind/Electron v3/Crashpad/reports` | `"all"` | deleteMatchingContents<br>需关进程:是 | `"anyOf" [ { "applicationInstalled", identifiers = ["net.xmind.vana.app", "Xmind"] }, { "anyRootExists" }, ]` | Xmind, Xmind Helper | [1](https://xmind.cn/user-guide/file-cache-new) [2](https://www.electronjs.org/docs/latest/api/app#appgetpathname) |
| 52 | `app.ynote-cache` | safe | false | true | `${application_support}/ynote-desktop/Cache`<br>`${application_support}/ynote-desktop/Code Cache`<br>`${application_support}/ynote-desktop/GPUCache`<br>`${application_support}/ynote-desktop/DawnCache`<br>`${application_support}/ynote-desktop/DawnGraphiteCache`<br>`${application_support}/ynote-desktop/DawnWebGPUCache`<br>`${application_support}/ynote-desktop/GrShaderCache`<br>`${application_support}/ynote-desktop/GraphiteDawnCache`<br>`${application_support}/ynote-desktop/Shared Dictionary/cache`<br>`${application_support}/ynote-desktop/Crashpad/reports`<br>`${application_support}/ynote-desktop/myLogs` ✅可重建<br>`${application_support}/ynote-desktop/Partitions` →展开(全部子目录; 固定后缀=Cache, Code Cache, GPUCache, DawnCache, DawnGraphiteCache, DawnWebGPUCache, GrShaderCache, GraphiteDawnCache, Shared Dictionary/cache)<br>`${application_support}/Caches/ynote-desktop-updater` | `"all"` | deleteMatchingContents<br>需关进程:是 | `"anyOf" [ { "applicationInstalled", identifiers = ["ynote-desktop", "有道云笔记"] }, { "anyRootExists" }, ]` | 有道云笔记 | [1](https://note.youdao.com/) [2](https://www.electronjs.org/docs/latest/api/app#appgetpathname) [3](https://chromium.googlesource.com/chromium/src/+/main/docs/user_data_dir.md) |
| 53 | `app.youdao-translation-cache` | safe | false | true | `${user_library}/Containers/com.youdao.YoudaoDict/Data/Library/Caches` | `"all"` | deleteMatchingContents<br>需关进程:是 | `"anyOf" [ { "applicationInstalled", identifiers = ["com.youdao.YoudaoDict", "YoudaoDict", "网易有道翻译"] }, { "anyRootExists" }, ]` | 网易有道翻译 | [1](https://developer.apple.com/documentation/foundation/using-the-file-system-effectively) |
| 54 | `app.zenaion-cache` | safe | false | true | `${application_support}/bot.zenai/.caches`<br>`${application_support}/bot.zenai/logs` | `"all"` | deleteMatchingContents<br>需关进程:是 | `"anyOf" [ { "applicationInstalled", identifiers = ["bot.zenai", "ZenAion"] }, { "anyRootExists" }, ]` | ZenAI, zenai-host | [1](https://zenai.bot/guide/core-features/view-all) [2](https://developer.apple.com/documentation/webkit/wkwebsitedatastore) |
| 55 | `app.zoom-cache` | safe | true | — | `${user_library}/Caches/us.zoom.xos` | `"all"` | deleteMatchingContents<br>需关进程:是 | `"anyOf" [ { "applicationInstalled", identifiers = ["us.zoom.xos", "zoom.us"] }, { "anyRootExists" }, ]` | zoom.us | [1](https://developer.apple.com/documentation/foundation/url/cachesdirectory) |

#### macos / development（39 条）

| # | 规则 ID | 风险 | 默认勾选 | 智能推荐 | 清理根路径（模板变量） | 匹配器 | 执行策略 | 适用性探针 | 需停止进程 | 权威依据 |
|---|---------|------|---------|---------|----------------------|--------|---------|-----------|-----------|---------|
| 1 | `dev.android-cache` | recoverable | false | — | `${user_library}/Android/sdk/.temp` ✅可重建<br>`${user_library}/Android/sdk/temp` ✅可重建<br>`${user_library}/Android/sdk/cache` ✅可重建 | `"all"` | deleteWholeRoot<br>需关进程:是 | `"anyRootExists" # Keep installed platforms, build tools, emulator images, and licenses. Only # SDK Manager staging and download caches are selected.` | Android Studio | [1](https://developer.android.com/tools/sdkmanager) |
| 2 | `dev.android-user-cache` | recoverable | false | — | `${home}/.android/cache` ✅可重建<br>`${home}/.android/build-cache` ✅可重建<br>`${home}/.android/breakpad` ✅可重建 | `"all"` | deleteWholeRoot<br>需关进程:是 | `"anyRootExists" # The .android root also contains signing keys, device-pairing keys, AVDs, and # emulator data. The rule deliberately owns only named rebuildable caches.` | Android Studio, adb | [1](https://developer.android.com/studio/command-line/variables) |
| 3 | `dev.browser-automation-cache` | recoverable | false | — | `${user_library}/Caches/ms-playwright`<br>`${user_library}/Caches/ms-playwright-go`<br>`${user_library}/Caches/ms-playwright-mcp`<br>`${user_library}/Caches/Cypress`<br>`${home}/.cache/selenium` | `"not" item = { "nameEquals", values = ["se-config.toml"] }` | deleteMatchingContents<br>需关进程:是 | `"anyOf" [ { "executableAvailable", names = ["playwright", "npx", "cypress", "selenium-manager"] }, { "anyRootExists" }, ]` | node,
  playwright,
  Cypress,
  selenium-manager,
  Google Chrome for Testing, | [1](https://playwright.dev/docs/browsers#managing-browser-binaries) [2](https://docs.cypress.io/app/references/advanced-installation#Binary-cache) [3](https://www.selenium.dev/documentation/selenium_manager/#caching) |
| 4 | `dev.bun-cache` | recoverable | false | — | `${home}/.bun/install/cache` ✅可重建 | `"all"` | deleteWholeRoot<br>需关进程:否 | `"anyOf" [ { "executableAvailable", names = ["bun"] }, { "anyRootExists" }, ]` | — | [1](https://bun.sh/docs/pm/global-cache) |
| 5 | `dev.cargo-cache` | recoverable | false | true | `${home}/.cargo/registry/cache` ✅可重建<br>`${home}/.cargo/git/db` ✅可重建 | `"all"` | deleteWholeRoot<br>需关进程:否 | `"anyOf" [ { "executableAvailable", names = ["cargo"] }, { "anyRootExists" }, ]` | — | [1](https://doc.rust-lang.org/cargo/guide/cargo-home.html) |
| 6 | `dev.cargo-extracted-sources` | recoverable | false | false | `${home}/.cargo/registry/src` ✅可重建 | `"all"` | deleteWholeRoot<br>需关进程:是 | `"anyOf" [ { "executableAvailable", names = ["cargo"] }, { "anyRootExists" }, ]` | cargo, rustc, rust-analyzer | [1](https://doc.rust-lang.org/cargo/guide/cargo-home.html) |
| 7 | `dev.ccache-cache` | recoverable | false | — | `${user_library}/Caches/ccache` | `"all"` | deleteMatchingContents<br>需关进程:是 | `"anyOf" [ { "executableAvailable", names = ["ccache"] }, { "anyRootExists" }, ]` | ccache | [1](https://ccache.dev/manual/latest.html#_location_of_the_configuration_file) |
| 8 | `dev.cocoapods-cache` | recoverable | false | — | `${user_library}/Caches/CocoaPods` | `"all"` | deleteMatchingContents<br>需关进程:否 | `"anyRootExists"` | — | [1](https://guides.cocoapods.org/terminal/commands.html#pod_cache) |
| 9 | `dev.composer-cache` | recoverable | false | — | `${user_library}/Caches/composer`<br>`${home}/.composer/cache` ✅可重建 | `"all"` | deleteMatchingContents<br>需关进程:否 | `"anyOf" [ { "executableAvailable", names = ["composer"] }, { "anyRootExists" }, ]` | — | [1](https://getcomposer.org/doc/06-config.md#cache-dir) |
| 10 | `dev.copilot-cli-cache` | recoverable | false | — | `${user_library}/Caches/copilot` | `"all"` | deleteMatchingContents<br>需关进程:是 | `"anyOf" [ { "executableAvailable", names = ["copilot"] }, { "anyRootExists" }, ]` | copilot | [1](https://docs.github.com/en/copilot/reference/copilot-cli-reference/cli-config-dir-reference#changing-the-location-of-the-configuration-directory) |
| 11 | `dev.dart-analysis-cache` | recoverable | false | true | `${home}/.dartServer` ✅可重建 | `"all"` | deleteWholeRoot<br>需关进程:是 | `"anyOf" [ { "executableAvailable", names = ["dart", "flutter"] }, { "anyRootExists" }, ]` | dart, flutter | [1](https://github.com/flutter/flutter/blob/master/dev/devicelab/lib/tasks/analysis.dart) |
| 12 | `dev.deno-cache` | recoverable | false | — | `${user_library}/Caches/deno` | `"all"` | deleteMatchingContents<br>需关进程:否 | `"anyOf" [ { "executableAvailable", names = ["deno"] }, { "anyRootExists" }, ]` | — | [1](https://docs.deno.com/runtime/getting_started/installation/#cache-location) [2](https://docs.deno.com/runtime/reference/cli/clean/) |
| 13 | `dev.go-cache` | recoverable | false | — | `${user_library}/Caches/go-build`<br>`${home}/go/pkg/mod/cache/download` | `"all"` | deleteMatchingContents<br>需关进程:否 | `"anyOf" [ { "executableAvailable", names = ["go"] }, { "anyRootExists" }, ]` | — | [1](https://go.dev/cmd/go/#hdr-Build_and_test_caching) [2](https://go.dev/ref/mod#module-cache) |
| 14 | `dev.gradle-cache` | recoverable | false | true | `${home}/.gradle/caches` ✅可重建<br>`${home}/.gradle/daemon` ✅可重建<br>`${home}/.gradle/workers` ✅可重建<br>`${home}/.gradle/notifications` ✅可重建<br>`${home}/.gradle/wrapper/dists` ✅可重建<br>`${home}/.gradle/.tmp` ✅可重建 | `"all"` | deleteWholeRoot<br>需关进程:是 | `"anyOf" [ { "executableAvailable", names = ["gradle", "java"] }, { "anyRootExists" }, ]` | gradle, java | [1](https://docs.gradle.org/current/userguide/directory_layout.html) |
| 15 | `dev.hex-cache` | recoverable | false | — | `${home}/.hex/cache` | `"all"` | deleteMatchingContents<br>需关进程:是 | `"anyOf" [ { "executableAvailable", names = ["mix"] }, { "anyRootExists" }, ]` | beam.smp, mix | [1](https://hex.hexdocs.pm/Mix.Tasks.Hex.Config.html) |
| 16 | `dev.homebrew-cache` | recoverable | false | true | `${user_library}/Caches/Homebrew` ✅可重建 | `"all"` | deleteWholeRoot<br>需关进程:否 | `"anyRootExists"` | — | [1](https://docs.brew.sh/Manpage#cleanup-options-formulacask-) |
| 17 | `dev.jetbrains-cache` | recoverable | false | true | `${user_library}/Caches/JetBrains` →展开(全部子目录; 固定后缀=caches, index, tmp, jcef_cache, semantic-search, full-line, intellij-rust, vcs-log, python_stubs, cpython-cache, python_packages, icon-cache, composer_packages, web-types) ✅可重建<br>`${user_library}/Caches/Google` →展开(子目录前缀=AndroidStudio; 固定后缀=caches, index, tmp, jcef_cache, semantic-search, full-line, vcs-log, icon-cache) ✅可重建 | `"all"` | deleteMatchingContents<br>需关进程:是 | `"anyOf" [ { "applicationInstalled", identifiers = ["com.jetbrains.intellij", "com.google.android.studio", "IntelliJ IDEA", "Android Studio", "PyCharm", "WebStorm", "GoLand", "RustRover", "PhpStorm"] }, { "anyRootExists" }, ]` | IntelliJ IDEA, Android Studio, PyCharm, WebStorm, GoLand, RustRover, PhpStorm | [1](https://www.jetbrains.com/help/idea/tuning-the-ide.html#system-directory) |
| 18 | `dev.jvm-tooling-cache` | recoverable | false | — | `${home}/.sbt/boot` ✅可重建<br>`${home}/.sbt/preloaded` ✅可重建<br>`${home}/.ivy2/cache` | `"all"` | deleteMatchingContents<br>需关进程:是 | `"anyRootExists"` | java | [1](https://www.scala-sbt.org/1.x/docs/Launcher-Getting-Started.html) [2](https://ant.apache.org/ivy/history/latest-milestone/settings/caches.html) |
| 19 | `dev.maven-cache` | recoverable | false | — | `${home}/.m2/repository` ✅可重建 | `"all"` | deleteWholeRoot<br>需关进程:是 | `"anyOf" [ { "executableAvailable", names = ["mvn"] }, { "anyRootExists" }, ]` | mvn, java | [1](https://maven.apache.org/guides/mini/guide-configuring-maven.html) |
| 20 | `dev.mise-cache` | recoverable | false | — | `${user_library}/Caches/mise` | `"not" item = { "pathSegmentIn", values = ["http-tarballs"] }` | deleteMatchingContents<br>需关进程:是 | `"anyOf" [ { "executableAvailable", names = ["mise"] }, { "anyRootExists" }, ]` | mise | [1](https://mise.jdx.dev/directories.html) [2](https://mise.jdx.dev/cache-behavior.html) [3](https://mise.jdx.dev/dev-tools/backends/http.html) |
| 21 | `dev.node-gyp-cache` | recoverable | false | true | `${user_library}/Caches/node-gyp` ✅可重建 | `"all"` | deleteWholeRoot<br>需关进程:否 | `"anyOf" [ { "executableAvailable", names = ["node", "npm"] }, { "anyRootExists" }, ]` | — | [1](https://github.com/nodejs/node-gyp#command-options) |
| 22 | `dev.node-tooling-cache` | recoverable | false | — | `${home}/.cache/node/corepack` ✅可重建<br>`${user_library}/Caches/electron` ✅可重建<br>`${home}/.cache/electron` ✅可重建<br>`${home}/.nvm/.cache` ✅可重建 | `"all"` | deleteWholeRoot<br>需关进程:否 | `"anyOf" [ { "executableAvailable", names = ["node", "corepack"] }, { "anyRootExists" }, ]` | — | [1](https://github.com/nodejs/corepack#environment-variables) [2](https://github.com/electron/get#how-it-works) [3](https://github.com/nvm-sh/nvm#problems) |
| 23 | `dev.npm-cache` | recoverable | false | true | `${home}/.npm/_cacache` ✅可重建 | `"all"` | deleteWholeRoot<br>需关进程:否 | `"anyOf" [ { "executableAvailable", names = ["node", "npm"] }, { "anyRootExists" }, ]` | — | [1](https://docs.npmjs.com/cli/cache/) |
| 24 | `dev.npx-cache` | safe | false | true | `${home}/.npm/_npx` ✅可重建 | `"all"` | deleteWholeRoot<br>需关进程:否 | `"anyOf" [ { "executableAvailable", names = ["node", "npx"] }, { "anyRootExists" }, ]` | — | [1](https://docs.npmjs.com/cli/cache/) |
| 25 | `dev.nuget-cache` | recoverable | false | true | `${home}/.nuget/packages` ✅可重建<br>`${home}/.local/share/NuGet/http-cache` ✅可重建<br>`${home}/.local/share/NuGet/v3-cache` ✅可重建 | `"all"` | deleteWholeRoot<br>需关进程:是 | `"anyOf" [ { "executableAvailable", names = ["dotnet", "nuget"] }, { "anyRootExists" }, ]` | dotnet, nuget, msbuild | [1](https://learn.microsoft.com/en-us/nuget/consume-packages/managing-the-global-packages-and-cache-folders) [2](https://learn.microsoft.com/en-us/nuget/reference/cli-reference/cli-ref-locals) |
| 26 | `dev.pnpm-cache` | recoverable | false | true | `${user_library}/pnpm/store` ✅可重建<br>`${user_library}/Caches/pnpm` ✅可重建 | `"all"` | deleteWholeRoot<br>需关进程:否 | `"anyOf" [ { "executableAvailable", names = ["pnpm"] }, { "anyRootExists" }, ]` | — | [1](https://pnpm.io/cli/store) |
| 27 | `dev.pyinstaller-cache` | recoverable | false | — | `${application_support}/pyinstaller` →展开(子目录前缀=bincache; 固定后缀=arm64, x86_64, universal2) ✅可重建 | `"all"` | deleteMatchingContents<br>需关进程:否 | `"anyRootExists"` | — | [1](https://github.com/pyinstaller/pyinstaller/blob/develop/PyInstaller/building/utils.py) |
| 28 | `dev.python-cache` | recoverable | false | — | `${user_library}/Caches/pip`<br>`${user_library}/Caches/pypoetry/artifacts`<br>`${user_library}/Caches/pypoetry/cache`<br>`${home}/.pyenv/cache`<br>`${home}/.cache/ruff`<br>`${home}/.cache/mypy` | `"all"` | deleteMatchingContents<br>需关进程:否 | `"anyRootExists"` | — | [1](https://pip.pypa.io/en/stable/topics/caching/) [2](https://python-poetry.org/docs/configuration/#cache-dir) [3](https://docs.astral.sh/ruff/configuration/#cache-dir) [4](https://mypy.readthedocs.io/en/stable/command_line.html#cmdoption-mypy-cache-dir) |
| 29 | `dev.qclaw-compile-cache` | recoverable | false | false | `${home}/.qclaw/compile-cache` ✅可重建 | `"all"` | deleteWholeRoot<br>需关进程:是 | `"anyOf" [ { "executableAvailable", names = ["qclaw"] }, { "anyRootExists" }, ]` | qclaw | [1](https://nodejs.org/api/module.html#module-compile-cache) |
| 30 | `dev.qoder-rendering-cache` | safe | false | true | `${application_support}` →展开(子目录名=Qoder, QoderCN; 固定后缀=Cache, Code Cache, GPUCache, DawnCache, DawnGraphiteCache, DawnWebGPUCache, GrShaderCache, GraphiteDawnCache, Shared Dictionary/cache, logs, Crashpad/reports, CachedData, CachedExtensionVSIXs)<br>`${application_support}/QoderCN/Partitions` →展开(全部子目录; 固定后缀=Cache, Code Cache, GPUCache, DawnCache, DawnGraphiteCache, DawnWebGPUCache, GrShaderCache, GraphiteDawnCache, Shared Dictionary/cache) | `"all"` | deleteMatchingContents<br>需关进程:是 | `"anyOf" [ { "applicationInstalled", identifiers = ["com.qoder.ide", "com.aliyun.lingma.ide", "Qoder", "Qoder CN"] }, { "anyRootExists" }, ]` | Qoder, Qoder Helper, QoderCN, Qoder CN Helper | [1](https://docs.qoder.com/troubleshooting/common-issue) [2](https://www.electronjs.org/docs/latest/api/app#appgetpathname) [3](https://chromium.googlesource.com/chromium/src/+/main/docs/user_data_dir.md) |
| 31 | `dev.rubygems-cache` | recoverable | false | — | `${home}/.gem/ruby` →展开(全部子目录; 固定后缀=cache)<br>`${home}/.gem/cache` | `"all"` | deleteMatchingContents<br>需关进程:是 | `"anyOf" [ { "executableAvailable", names = ["gem", "bundle"] }, { "anyRootExists" }, ]` | bundle, gem, ruby | [1](https://guides.rubygems.org/command-reference/#gem-environment) [2](https://github.com/rubygems/rubygems/blob/master/lib/rubygems/defaults.rb) |
| 32 | `dev.sccache-cache` | recoverable | false | — | `${user_library}/Caches/Mozilla.sccache` | `"all"` | deleteMatchingContents<br>需关进程:是 | `"anyOf" [ { "executableAvailable", names = ["sccache"] }, { "anyRootExists" }, ]` | sccache | [1](https://github.com/mozilla/sccache/blob/main/docs/Configuration.md) |
| 33 | `dev.swiftpm-cache` | recoverable | false | — | `${user_library}/Caches/org.swift.swiftpm` | `"all"` | deleteMatchingContents<br>需关进程:否 | `"anyRootExists"` | — | [1](https://developer.apple.com/documentation/foundation/url/cachesdirectory) [2](https://github.com/swiftlang/swift-package-manager) |
| 34 | `dev.uv-cache` | recoverable | false | true | `${home}/.cache/uv` ✅可重建<br>`${user_library}/Caches/uv` ✅可重建 | `"all"` | deleteWholeRoot<br>需关进程:是 | `"anyOf" [ { "executableAvailable", names = ["uv"] }, { "anyRootExists" }, ]` | uv | [1](https://docs.astral.sh/uv/reference/storage/#cache-directory) [2](https://docs.astral.sh/uv/concepts/cache/#clearing-the-cache) |
| 35 | `dev.vscode-cache` | safe | false | true | `${application_support}/Code/Cache`<br>`${application_support}/Code/CachedExtensionVSIXs`<br>`${application_support}/Code/CachedData`<br>`${application_support}/Code/GPUCache`<br>`${application_support}/Code/Code Cache` | `"all"` | deleteMatchingContents<br>需关进程:是 | `"anyRootExists"` | Visual Studio Code, Code | [1](https://github.com/microsoft/vscode/issues/99873) [2](https://code.visualstudio.com/docs/configure/command-line#_advanced-cli-options) |
| 36 | `dev.xcode-auxiliary-cache` | recoverable | false | — | `${user_library}/Developer/Xcode/DocumentationCache`<br>`${user_library}/Developer/Xcode/DocumentationIndex`<br>`${user_library}/Developer/Xcode/iOS Device Logs`<br>`${user_library}/Developer/Xcode/watchOS Device Logs` | `"olderThan" days = 14` | deleteMatchingContents<br>需关进程:是 | `"anyOf" [ { "applicationInstalled", identifiers = ["com.apple.dt.Xcode", "Xcode"] }, { "executableAvailable", names = ["xcodebuild"] }, { "anyRootExists" }, ]` | Xcode | [1](https://developer.apple.com/documentation/xcode/acquiring-crash-reports-and-diagnostic-logs) |
| 37 | `dev.xcode-derived-data` | recoverable | false | — | `${user_library}/Developer/Xcode/DerivedData` ✅可重建 | `"all"` | deleteWholeRoot<br>需关进程:是 | `"anyOf" [ { "executableAvailable", names = ["xcodebuild"] }, { "anyRootExists" }, ]` | Xcode | [1](https://developer.apple.com/documentation/Xcode-Release-Notes/xcode-26-release-notes) |
| 38 | `dev.xcode-simulator-cache` | recoverable | false | — | `${user_library}/Developer/CoreSimulator/Caches`<br>`${user_library}/Developer/CoreSimulator/Temp` | `"all"` | deleteMatchingContents<br>需关进程:是 | `"anyOf" [ { "applicationInstalled", identifiers = ["com.apple.dt.Xcode", "Xcode"] }, { "executableAvailable", names = ["xcodebuild", "simctl"] }, { "anyRootExists" }, ]` | Xcode, Simulator, CoreSimulatorService, xcodebuild, xctest | [1](https://developer.apple.com/documentation/foundation/using-the-file-system-effectively) |
| 39 | `dev.yarn-cache` | recoverable | false | — | `${user_library}/Caches/Yarn`<br>`${home}/.yarn/berry/cache` | `"all"` | deleteMatchingContents<br>需关进程:否 | `"anyRootExists"` | — | [1](https://classic.yarnpkg.com/lang/en/docs/cli/cache/) [2](https://yarnpkg.com/configuration/yarnrc/#cacheFolder) |

#### macos / ai（1 条）

| # | 规则 ID | 风险 | 默认勾选 | 智能推荐 | 清理根路径（模板变量） | 匹配器 | 执行策略 | 适用性探针 | 需停止进程 | 权威依据 |
|---|---------|------|---------|---------|----------------------|--------|---------|-----------|-----------|---------|
| 1 | `ai.huggingface-xet-cache` | recoverable | false | — | `${home}/.cache/huggingface/xet` | `"allOf" [ { "pathSegmentIn", values = ["chunk_cache", "shard_cache", "logs"] }, { "not", item = { "pathSegmentIn", values = ["staging"] } }, ]` | deleteMatchingContents<br>需关进程:否 | `"anyRootExists"` | — | （evidence 文本论证） |

#### macos / container（1 条）

| # | 规则 ID | 风险 | 默认勾选 | 智能推荐 | 清理根路径（模板变量） | 匹配器 | 执行策略 | 适用性探针 | 需停止进程 | 权威依据 |
|---|---------|------|---------|---------|----------------------|--------|---------|-----------|-----------|---------|
| 1 | `container.docker-desktop-diagnostic-cache` | safe | false | true | `${user_library}/Containers/com.docker.docker/Data/log` | `"olderThan" days = 7` | deleteMatchingContents<br>需关进程:是 | `"anyOf" [ { "applicationInstalled", identifiers = ["com.docker.docker", "Docker"] }, { "anyRootExists" }, ]` | Docker, Docker Desktop, com.docker.backend, com.docker.virtualization | [1](https://docs.docker.com/engine/daemon/logs/) |


### 6.3 项目产物规则全量清单（31 条 / 69 个产物目录）

识别方式：先用 `[match]` 中的标志文件确认这是某生态的源码项目，再清理其中可重建的产物目录。全部 31 条规则均为 `platforms = ["macos", "windows"]`、`risk = recoverable`、`default_selected = false`（schema 强制，见 `rules/README.md` "Project artifact rules" 节）。

| # | 规则 ID | 平台 | 项目识别标志（[match]） | 清理的产物目录 | 权威依据 | 验证日期 |
|---|---------|------|----------------------|--------------|---------|---------|
| 1 | `project.autoconf-cache` |  | `file_names_any = "configure.ac", "configure.in"]` | `autom4te.cache` | [1](https://www.gnu.org/software/autoconf/manual/autoconf-2.61/html_node/autom4te_002ecache.html) | 2026-07-18 |
| 2 | `project.clojure-cli-cache` |  | `file_names_any = "deps.edn"]` | `.cpcache` | [1](https://clojure.org/reference/clojure_cli) | 2026-07-18 |
| 3 | `project.cmake-build-artifacts` |  | `file_names_any = "CMakeLists.txt"]` | `build`<br>`cmake-build-debug`<br>`cmake-build-release` | [1](https://cmake.org/cmake/help/latest/guide/tutorial/Before%20You%20Begin.html) | 2026-07-31 |
| 4 | `project.cocoapods-build-artifacts` |  | `file_names_any = "Podfile"]` | `Pods` | [1](https://guides.cocoapods.org/using/pod-install-vs-update.html) | 2026-07-31 |
| 5 | `project.composer-build-artifacts` |  | `file_names_any = "composer.json"]` | `vendor` | [1](https://getcomposer.org/doc/03-cli.md#install-i) | 2026-07-31 |
| 6 | `project.dotnet-build-artifacts` |  | `file_suffixes_any = ".csproj", ".fsproj"]` | `bin`<br>`obj` | [1](https://learn.microsoft.com/en-us/dotnet/core/project-sdk/overview#default-includes-and-excludes) | 2026-07-31 |
| 7 | `project.dune-build-artifacts` |  | `file_names_any = "dune-project", "dune-workspace"]` | `_build` | [1](https://dune.readthedocs.io/en/latest/usage.html) | 2026-07-18 |
| 8 | `project.elixir-build-artifacts` |  | `file_names_any = "mix.exs"]` | `_build`<br>`.elixir_ls`<br>`.elixir-tools`<br>`.lexical` | [1](https://hexdocs.pm/mix/Mix.Tasks.Clean.html) [2](https://github.com/elixir-lsp/elixir-ls) [3](https://github.com/elixir-tools/next-ls) [4](https://github.com/lexical-lsp/lexical) | 2026-07-31 |
| 9 | `project.flutter-build-artifacts` |  | `file_names_any = "pubspec.yaml"]` | `build`<br>`.dart_tool`<br>`linux/flutter/ephemeral`<br>`windows/flutter/ephemeral` | [1](https://docs.flutter.dev/reference/flutter-cli#commands) | 2026-07-31 |
| 10 | `project.godot-build-artifacts` |  | `file_names_any = "project.godot"]` | `.godot` | [1](https://docs.godotengine.org/en/stable/tutorials/assets_pipeline/import_process.html) | 2026-07-31 |
| 11 | `project.gradle-build-artifacts` |  | `file_names_any = "build.gradle", "build.gradle.kts"]` | `build`<br>`.gradle` | [1](https://docs.gradle.org/current/userguide/directory_layout.html#dir:project_root) | 2026-07-31 |
| 12 | `project.haskell-build-artifacts` |  | `file_names_any = "stack.yaml", "cabal.project"]` | `.stack-work`<br>`dist-newstyle` | [1](https://docs.haskellstack.org/en/stable/topics/stack_work/) [2](https://cabal.readthedocs.io/en/stable/cabal-project-description-file.html#cmdoption-builddir) | 2026-07-31 |
| 13 | `project.jupyter-build-artifacts` |  | `file_suffixes_any = ".ipynb"]` | `.ipynb_checkpoints` (descendant, 深度≤32) | [1](https://github.com/jupyter-server/jupyter_server/blob/main/jupyter_server/services/contents/filecheckpoints.py) | 2026-07-31 |
| 14 | `project.leiningen-build-artifacts` |  | `file_names_any = "project.clj"]` | `target` | [1](https://leiningen.org/tutorial.html) | 2026-07-18 |
| 15 | `project.maven-build-artifacts` |  | `file_names_any = "pom.xml"]` | `target` | [1](https://maven.apache.org/plugins/maven-clean-plugin/usage.html) | 2026-07-31 |
| 16 | `project.meson-build-artifacts` |  | `file_names_any = "meson.build"]` | `builddir` | [1](https://mesonbuild.com/Using-multiple-build-directories.html) | 2026-07-18 |
| 17 | `project.mill-build-artifacts` |  | `file_names_any = "build.mill", "build.mill.yaml", "build.sc"]` | `out` | [1](https://mill-build.org/mill/fundamentals/out-dir.html) | 2026-07-18 |
| 18 | `project.node-build-artifacts` |  | `file_names_any = "package.json"]` | `node_modules`<br>`.angular/cache`<br>`.next/cache`<br>`.nuxt`<br>`.turbo` | [1](https://docs.npmjs.com/cli/v11/configuring-npm/folders#node-modules) [2](https://angular.dev/cli/cache) [3](https://nextjs.org/docs/app/guides/ci-build-caching) [4](https://nuxt.com/docs/3.x/directory-structure/nuxt) [5](https://turborepo.com/docs/crafting-your-repository/caching) | 2026-07-31 |
| 19 | `project.pants-workdir` |  | `file_names_any = "pants.toml"]` | `.pants.d` | [1](https://www.pantsbuild.org/stable/docs/using-pants/troubleshooting-common-issues) | 2026-07-18 |
| 20 | `project.pixi-build-artifacts` |  | `file_names_any = "pixi.toml"]` | `.pixi` | [1](https://pixi.sh/latest/workspace/multi_environment/) | 2026-07-31 |
| 21 | `project.python-build-artifacts` |  | `file_names_any = "pyproject.toml", "setup.py", "setup.cfg", "requirements.txt", "Pipfile", "poetry.lock"]` | `.pytest_cache`<br>`.mypy_cache`<br>`.ruff_cache`<br>`.tox`<br>`.nox`<br>`__pypackages__`<br>`__pycache__` (descendant, 深度≤32)<br>`.ipynb_checkpoints` (descendant, 深度≤32) | [1](https://docs.pytest.org/en/stable/how-to/cache.html) [2](https://mypy.readthedocs.io/en/stable/command_line.html#cmdoption-mypy-cache-dir) [3](https://docs.astral.sh/ruff/settings/#cache-dir) [4](https://tox.wiki/en/stable/config.html#tox-root) [5](https://nox.thea.codes/en/stable/config.html#nox.options.envdir) [6](https://peps.python.org/pep-0582/) [7](https://peps.python.org/pep-3147/) [8](https://github.com/jupyter-server/jupyter_server/blob/main/jupyter_server/services/contents/filecheckpoints.py) | 2026-07-31 |
| 22 | `project.rails-cache` |  | `file_names_any = "Gemfile"] relative_paths_all = "config/application.rb"] relative_paths_any = "bin/rails", "config/environment.rb"]` | `tmp/cache` | [1](https://guides.rubyonrails.org/v6.0/command_line.html) | 2026-07-18 |
| 23 | `project.react-native-build-artifacts` |  | `file_names_any = "package.json"] relative_paths_any = "android", "ios"]` | `android/build`<br>`android/.gradle`<br>`ios/build`<br>`ios/DerivedData`<br>`.expo`<br>`.metro` | [1](https://docs.gradle.org/current/userguide/directory_layout.html#dir:project_root) [2](https://developer.apple.com/documentation/xcode/customizing-the-build-schemes-for-a-project) [3](https://docs.expo.dev/troubleshooting/clear-cache-macos-linux/) | 2026-07-31 |
| 24 | `project.rebar-build-artifacts` |  | `file_names_any = "rebar.config"]` | `_build` | [1](https://rebar3.org/docs/workflow/) | 2026-07-18 |
| 25 | `project.rust-build-artifacts` |  | `file_names_any = "Cargo.toml"]` | `target`<br>`.xwin-cache` | [1](https://doc.rust-lang.org/cargo/reference/build-cache.html) [2](https://github.com/Jake-Shadle/xwin#environment-variables) | 2026-07-31 |
| 26 | `project.sbt-build-artifacts` |  | `file_names_any = "build.sbt"]` | `target`<br>`project/target` | [1](https://www.scala-sbt.org/1.x/docs/Running.html#Common+commands) | 2026-07-31 |
| 27 | `project.swift-build-artifacts` |  | `file_names_any = "Package.swift"]` | `.build`<br>`.swiftpm` | [1](https://docs.swift.org/swiftpm/documentation/packagemanagerdocs/gettingstarted/) [2](https://github.com/swiftlang/swift-package-manager) | 2026-07-31 |
| 28 | `project.terraform-build-artifacts` |  | `file_names_any = ".terraform.lock.hcl"]` | `.terraform` | [1](https://developer.hashicorp.com/terraform/cli/init#working-directory-contents) | 2026-07-31 |
| 29 | `project.unity-build-artifacts` |  | `file_names_any = "Assembly-CSharp.csproj"] relative_paths_all = "Assets", "ProjectSettings"]` | `Library`<br>`Temp`<br>`Obj`<br>`Logs`<br>`MemoryCaptures` | [1](https://docs.unity3d.com/Manual/AssetWorkflow.html) | 2026-07-31 |
| 30 | `project.unreal-build-artifacts` |  | `file_suffixes_any = ".uproject"]` | `Binaries`<br>`Intermediate`<br>`DerivedDataCache` | [1](https://dev.epicgames.com/documentation/unreal-engine/unreal-engine-directory-structure) [2](https://dev.epicgames.com/documentation/en-us/unreal-engine/derived-data-cache) | 2026-07-31 |
| 31 | `project.zig-build-artifacts` |  | `file_names_any = "build.zig"]` | `.zig-cache`<br>`zig-cache`<br>`zig-out` | [1](https://ziglang.org/learn/build-system/#installing-build-artifacts) | 2026-07-31 |


---

### 6.4 专用 Rust Cleaner 全量清单（24 个）

这些场景无法用声明式规则安全表达，必须用代码实现（需要执行系统命令、感知共享 blob、调用 COM 接口或执行前即时校验）。

#### A. AI 模型存储（13 个）

实现：`src/cleanup/cleaners/ai_model_storage.rs`（1334 行）

| # | Cleaner ID | 代码引用 |
|---|-----------|---------|
| 1 | `special.ai-model-hugging-face` | `ai_model_storage.rs:27` |
| 2 | `special.ai-model-whisper` | `ai_model_storage.rs:28` |
| 3 | `special.ai-model-pytorch` | `ai_model_storage.rs:29` |
| 4 | `special.ai-cache-pytorch-hub-repositories` | `ai_model_storage.rs:30` |
| 5 | `special.ai-model-modelscope` | `ai_model_storage.rs:31` |
| 6 | `special.ai-model-keras` | `ai_model_storage.rs:32` |
| 7 | `special.ai-model-openai-clip` | `ai_model_storage.rs:33` |
| 8 | `special.ai-model-tensorflow-hub` | `ai_model_storage.rs:34` |
| 9 | `special.ai-model-lm-studio` | `ai_model_storage.rs:35` |
| 10 | `special.ai-model-ollama` | `ai_model_storage.rs:36` |
| 11 | `special.ai-model-coqui-tts` | `ai_model_storage.rs:37` |
| 12 | `special.ai-model-gpt4all` | `ai_model_storage.rs:38` |
| 13 | `special.ai-model-jan` | `ai_model_storage.rs:39` |

**为何必须用代码**：模型仓库使用**共享 blob + 符号链接**结构（如 HuggingFace 的 `blobs/` + `snapshots/`），删除某个模型时必须校验 blob 是否被其他模型引用，声明式路径匹配无法表达这种引用计数关系。

#### B. Windows 系统清理（6 个，走原生 COM 接口）

实现：`src/cleanup/cleaners/windows_system_cleanup.rs` + 平台层 `mangodisk-platform/src/windows/disk_cleanup.rs`

> 引用 `src/cleanup/cleaners/windows_system_cleanup.rs:20-42`：
> ```rust
> const CLEANERS: [(&str, WindowsDiskCleanupKind); 6] = [
>     (RECYCLE_BIN_ID, WindowsDiskCleanupKind::RecycleBin),
>     ("special.windows-system-logs", WindowsDiskCleanupKind::SystemLogs),
>     ("special.windows-internet-cache", WindowsDiskCleanupKind::InternetCache),
>     ("special.windows-delivery-optimization", WindowsDiskCleanupKind::DeliveryOptimization),
>     ("special.windows-defender-cache", WindowsDiskCleanupKind::DefenderCache),
>     ("special.windows-update-cleanup", WindowsDiskCleanupKind::UpdateCleanup),
> ];
> ```

| # | Cleaner ID | 底层机制 |
|---|-----------|---------|
| 1 | `special.windows-recycle-bin` | 回收站清空 |
| 2 | `special.windows-system-logs` | 系统日志（≥3 天，深度≤16，`disk_cleanup.rs:42-48`） |
| 3 | `special.windows-internet-cache` | `IEmptyVolumeCache` handler "Internet Cache Files"（`disk_cleanup.rs:49`） |
| 4 | `special.windows-delivery-optimization` | handler "Delivery Optimization Files"（`disk_cleanup.rs:50`） |
| 5 | `special.windows-defender-cache` | handler "Windows Defender"（`disk_cleanup.rs:51`） |
| 6 | `special.windows-update-cleanup` | handler "Update Cleanup"（`disk_cleanup.rs:52`） |

**实现机制**：通过注册表 `SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches`（`disk_cleanup.rs:40`）枚举系统 VolumeCache handler，用 `CoCreateInstance` 创建 `IEmptyVolumeCache` COM 对象（`disk_cleanup.rs:176`），调用其 `measure()` / `purge()`（`disk_cleanup.rs:220-247`），并通过 `IEmptyVolumeCacheCallBack` 回调上报进度（`disk_cleanup.rs:121-149`）。估算结果有 30 秒 TTL 缓存（`disk_cleanup.rs:41`）。

**安全设计**：回收站与 Update Cleanup **刻意排除在智能推荐之外**：

> 引用 `src/cleanup/cleaners/windows_system_cleanup.rs:220-227`：
> ```rust
> fn is_recommended(kind: WindowsDiskCleanupKind) -> bool {
>     // Emptying the Recycle Bin permanently removes user-deleted content, and
>     ...
>     WindowsDiskCleanupKind::RecycleBin | WindowsDiskCleanupKind::UpdateCleanup
> ```

#### C. macOS 专用（4 个）

| # | Cleaner ID | 实现文件 | 说明 |
|---|-----------|---------|------|
| 1 | `special.macos-universal-binaries` | `src/applications/binary_optimization/macos_universal_binaries.rs`（1482 行） | 剥离 Universal Binary 中当前架构不需要的 slice |
| 2 | `special.xcode-device-support` | `src/cleanup/cleaners/xcode_storage.rs`（1374 行） | Xcode 设备支持文件 |
| 3 | `special.xcode-archives` | 同上 | Xcode 归档 |
| 4 | `special.xcode-simulator-runtime` | 同上 | 模拟器运行时 |
| — | `special.additional-user-caches` | `src/cleanup/cleaners/user_cache_inventory.rs`（898 行） | 动态发现未被声明式规则覆盖的用户缓存（需减去声明式规则的所有权范围） |

#### D. 跨平台工具链（5 个，需执行外部命令）

| # | Cleaner ID | 实现文件 | 执行的命令 |
|---|-----------|---------|-----------|
| 1 | `special.docker-build-cache` | `docker_build_cache.rs:20`（514 行） | `docker system df` 预览 → `docker builder prune`（`docker_build_cache.rs:43-44`） |
| 2 | `special.conda-cache` | `conda_cache.rs:21`（487 行） | `conda clean` 预览 → `conda clean`（`conda_cache.rs:40-41`） |
| 3 | `special.rust-toolchains` | `rust_toolchains.rs:28`（845 行） | rustup 工具链管理 |
| 4 | `special.codex-archived-sessions` | `codex_archived_sessions.rs:22`（459 行） | Codex 归档会话 |
| 5 | `special.dropbox-cache` | `dropbox_cache.rs:45`（1480 行） | Dropbox 缓存（需感知同步状态） |

**为何必须用代码**：这类清理必须通过工具自身的 CLI 完成（直接删目录会破坏工具内部的元数据一致性）。Cleaner 会先探测可执行文件是否存在：

> 引用 `src/cleanup/cleaners/mod.rs:71,89-92`：
> ```rust
> fn executable_aliases(&self) -> &'static [&'static str];
> ...
> let Some(executable) = inventory.executable(self.executable_aliases()) else {
> ```

---

## 七、扫描加速：七层优化体系

MangoDisk 的扫描加速不是单点优化，而是**七个层次叠加**。

### 7.1 第 1 层：绕过文件系统 API，直读 NTFS 元数据（Windows）

这是 Windows 侧最大的性能杠杆。传统 `FindFirstFile` / `readdir` 递归需要为每个目录发起独立系统调用；MangoDisk 改用 `FSCTL_QUERY_FILE_LAYOUT` **一次性批量读取整卷的 NTFS 文件记录**。

> 引用 `mangodisk-platform/src/windows/file_layout/parser.rs:50-77`：
> ```rust
> pub(super) fn enumerate_layout(
>     volume: HANDLE,
>     minimum_bytes: u64,
>     mode: LayoutCollectionMode,
>     is_cancelled: &(dyn Fn() -> bool + Sync),
> ) -> Result<LayoutCollection, LayoutScanError> {
>     let mut input = QUERY_FILE_LAYOUT_INPUT::default();
>     input.Anonymous.FilterEntryCount = 0;
>     input.Flags = QUERY_FILE_LAYOUT_RESTART
>         | QUERY_FILE_LAYOUT_INCLUDE_NAMES
>         | QUERY_FILE_LAYOUT_INCLUDE_STREAMS
>         | QUERY_FILE_LAYOUT_INCLUDE_STREAMS_WITH_NO_CLUSTERS_ALLOCATED;
>     input.FilterType = QUERY_FILE_LAYOUT_FILTER_TYPE_NONE;
>
>     let mut output_buffer = AlignedBuffer::new(OUTPUT_BUFFER_BYTES);
>     ...
>         let returned = match device_io_control(
>             volume,
>             FSCTL_QUERY_FILE_LAYOUT,
> ```

**关键参数**（`parser.rs:31-48`）：

```rust
const OUTPUT_BUFFER_BYTES: usize = 8 * 1024 * 1024;   // 8MB 对齐缓冲，减少 IOCTL 往返
const NTFS_DATA_ATTRIBUTE: u32 = 0x80;                 // 只取 $DATA 流
const RESERVED_NTFS_RECORD_COUNT: u64 = 24;            // 跳过 NTFS 保留记录（$MFT 等）
const MAX_NAME_CHAIN_LENGTH: usize = 4_096;            // 防御损坏偏移链
const MAX_STREAM_CHAIN_LENGTH: usize = 4_096;
const MAX_DIRECTORY_RECORDS: usize = 2_000_000;
const MAX_DEFERRED_CANDIDATES: usize = 100_000;
const MAX_LAYOUT_ENTRIES: u64 = 10_000_000;            // 超限则回退 Win32 遍历
```

**健壮性设计**：
- 分页游标由内核维护，用累计上限防御病态重复页（`parser.rs:45-48` 注释："A cumulative limit rejects pathological repeated pages and bounds worst-case CPU and memory; **very large volumes fall back to Win32 traversal**"）
- 跳过 OneDrive 等云占位文件：`collection.remote_file_count`（`parser.rs:99-108`）
- 硬链接处理：保留长名、丢弃 DOS-only 别名（`parser.rs:577` 测试 `hard_links_keep_long_names_and_drop_dos_only_aliases`）
- 未知版本 fail-closed（`parser.rs:795` 测试 `unknown_stream_versions_fail_closed`）
- 目录父链有固定上限并检测环（`file_layout/mod.rs:1056` `directory_parent_cycles_fail_closed`、`mod.rs:1107` `directory_parent_chain_has_a_fixed_limit`）

### 7.2 第 2 层：批量目录属性读取（macOS）

macOS 无法直读 APFS 元数据，改用 `getattrlistbulk`——**单次系统调用返回一页多个条目的全部属性**，避免"readdir + 每项 stat"的双倍调用。

> 引用 `mangodisk-platform/src/macos/bulk_directory.rs:74-90`：
> ```rust
> pub(super) fn read_page(
>     ...
>         libc::getattrlistbulk(
> ```

> 引用 `mangodisk-platform/src/macos/bulk_directory.rs:177-192`：
> ```rust
> fn bulk_attributes() -> libc::attrlist {
>     ...
>         commonattr: libc::ATTR_CMN_RETURNED_ATTRS
>             | ATTR_CMN_ERROR
>             | libc::ATTR_CMN_NAME
>             | libc::ATTR_CMN_DEVID
>             | libc::ATTR_CMN_OBJTYPE
>             | libc::ATTR_CMN_MODTIME
>             | libc::ATTR_CMN_FLAGS,
>         dirattr: libc::ATTR_DIR_MOUNTSTATUS,
>         fileattr: libc::ATTR_FILE_DATALENGTH,
> ```

一次调用即取回：名称、设备 ID、对象类型、修改时间、标志位、挂载状态、数据长度——**遍历所需的全部信息一次拿齐**。

配置（`bulk_directory.rs:13-19`）：
```rust
const DIRECTORY_BUFFER_BYTES: usize = 64 * 1024;   // 64KB 分页缓冲
pub(super) const VNODE_TYPE_REGULAR_FILE: FileSystemObjectType = 1;
pub(super) const VNODE_TYPE_DIRECTORY: FileSystemObjectType = 2;
pub(super) const VNODE_TYPE_SYMBOLIC_LINK: FileSystemObjectType = 5;
```

安全打开目录（`bulk_directory.rs:63`）使用 `O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW`——`O_NOFOLLOW` 防止符号链接逃逸。

另有轻量版 `read_name_page()` + `bulk_name_attributes()`（`bulk_directory.rs:108-115,195-202`）：只取名称与类型，用于只需目录结构的场景，进一步降低开销。

### 7.3 第 3 层：USN Journal 增量变更追踪（Windows）——缓存有效性判定

要复用上次扫描结果，必须能判断"磁盘变没变"。MangoDisk 读取 NTFS 的 **USN 变更日志**来做增量判定。

> 引用 `mangodisk-platform/src/windows/change_tracking.rs:17-26`（导入的 USN API）：
> ```rust
> FSCTL_QUERY_USN_JOURNAL, FSCTL_READ_USN_JOURNAL, READ_USN_JOURNAL_DATA_V1,
> USN_JOURNAL_DATA_V0, USN_JOURNAL_DATA_V2, USN_REASON_BASIC_INFO_CHANGE, USN_REASON_CLOSE,
> ...
> ```

变更原因被精细分类（`change_tracking.rs:59-79`）：

```rust
const DATA_CHANGE_REASONS: u32 = USN_REASON_DATA_OVERWRITE
    | USN_REASON_DATA_EXTEND | USN_REASON_DATA_TRUNCATION
    | USN_REASON_NAMED_DATA_OVERWRITE | ... | USN_REASON_STREAM_CHANGE;
const CREATE_DELETE_REASONS: u32 = USN_REASON_FILE_CREATE | USN_REASON_FILE_DELETE;
const RENAME_REASONS: u32 = USN_REASON_RENAME_OLD_NAME | USN_REASON_RENAME_NEW_NAME;
const METADATA_CHANGE_REASONS: u32 = USN_REASON_BASIC_INFO_CHANGE | ... ;
```

优化细节（`change_tracking.rs:556`）：只解码根的直接子项名称，避免为每条 USN 记录都做路径解析——"Decode only direct root children whose names can themselves introduce..."

### 7.4 第 4 层：内存索引缓存 + 变更令牌校验

> 引用 `src/storage/index/cache.rs:22-28`：
> ```rust
> const ANALYSIS_CACHE_ROOT_LIMIT: usize = 2;              // LRU 只保留 2 个扫描根
> const LARGE_FILE_RESULT_LIMIT: usize = 2_000;
> pub(crate) const LARGE_FILE_INDEX_FLOOR_BYTES: u64 = 50 * 1024 * 1024;  // 大文件索引下限 50MB
> ```

复用决策三态（`src/storage/index/cache.rs:72-78`）：

```rust
pub(crate) enum CacheReuseDecision {
    Reusable,
    Miss,
    ...
}
```

复用流程（`cache.rs:88-169`）：取出缓存的 `FilesystemChangeToken` → `validate_change_token()` 比对 → 一致则 `Reusable`，否则 `Miss`。缺失令牌**判定为过期**（`cache.rs:590` 测试 `missing_change_token_is_stale`）——fail-safe。

LRU 淘汰有测试保证（`cache.rs:687` `storing_a_third_root_evicts_only_the_least_recent_root`、`cache.rs:714` `reusing_a_root_updates_its_eviction_recency`）。

**跨功能复用**：一次分析扫描的索引可直接派生大文件视图，无需重新遍历（`cache.rs:172` `large_files_result()`、`cache.rs:634` 测试 `large_file_view_reuses_active_analysis_without_change_history`）。

### 7.5 第 5 层：设备感知的自适应并发

盲目提高并发在机械硬盘上会因随机寻道而**降低**吞吐。MangoDisk 按卷的物理介质类型分配 worker 上限。

> 引用 `mangodisk-platform/src/contracts/volumes.rs:21-51`：
> ```rust
> /// volumes. The class is diagnostic only; `worker_limit` drives scheduling.
> pub struct ScanConcurrency {
>     pub class: ScanDeviceClass,
>     pub worker_limit: usize,
> }
> impl ScanConcurrency {
>     ... class: ScanDeviceClass::SolidState, worker_limit: 4,     // SSD: 4
>     ... class: ScanDeviceClass::Rotational, worker_limit: 2,     // HDD: 2
>     pub const fn conservative(class: ScanDeviceClass) -> Self {
>         ... worker_limit: 1,                                     // 其他: 1
> ```

设备类型（`contracts/volumes.rs:53-60`）：`SolidState` / `Rotational` / `Removable` / `Network` / `Unknown`

**探测方式**：
- Windows：`measure_scan_concurrency()`（`windows/volumes.rs:131-147`），可移动介质、网络盘直接降为保守 1 worker
- macOS：读取 IOKit 的 `SolidState` 属性（`macos/volumes.rs:128`），失败则 `Unknown`

**清理扫描调度**（`src/cleanup/scan.rs:40,235-242`）：
```rust
const CLEANUP_SCAN_WORKER_LIMIT: usize = 4;
...
let available_workers = thread::available_parallelism()
    ...
    .min(CLEANUP_SCAN_WORKER_LIMIT);
let (worker_count, scheduling_classes) = scan_worker_count(&plan, &volumes, available_workers);
```

即 `min(CPU 并行度, 设备上限, 硬上限 4, 任务数)`。

**背压控制**（`src/cleanup/scan.rs:627-633`）：
```rust
let worker_count = worker_count.max(1).min(plan.root_tasks.len());
...
// its capacity to worker count bounds memory while providing backpressure.
let (result_sender, result_receiver) = sync_channel(worker_count);
```

### 7.6 第 6 层：适用性剪枝——不扫描不存在的应用

清理扫描在遍历前先跑适用性探针，把"没装的应用"整条规则跳过。

> 引用 `src/cleanup/scan.rs:188-217`：
> ```rust
> let applicability_started = Instant::now();
> let requires_process_for_applicability = definitions.iter().any(rule_requires_process);
> // Only applicability probes need process data before traversal. Close-
> let mut process_snapshot = if requires_process_for_applicability {
>     ...
>             != Applicability::NotApplicable
> ...
> let applicability_elapsed_ms = applicability_started.elapsed().as_millis() as u64;
> ```

优化点：进程快照是**按需**采集的——只有存在 `processRunning` 探针时才在遍历前取快照，否则延后。进程快照采集本身也并行（`scan.rs:176`：`thread::spawn`）。

`ScanItemStatus::NotApplicable` 的规则被统计并从遍历中剔除（`scan.rs:384-399`）。

### 7.7 第 7 层：路径 Trie 剪枝与提前止步

遍历过程中用 `should_descend` 判断是否需要进入子目录——没有任何规则边界的分支直接不进。

> 引用 `src/cleanup/rules/scan_plan.rs:209`：
> ```rust
> pub(crate) fn should_descend(&self, path: &Path, rules: &[CompiledRule]) -> bool {
> ```

> 引用 `src/cleanup/rules/scan_plan.rs:11-16,247-249`：
> ```rust
> /// A scan plan stores rule activation boundaries rather than a complete file
> ...
> /// an active-rule set and evaluates matching and ownership directly. Only
> /// merged nested roots use multi-rule PathTrie dispatch.
> ```

即：单规则路径走**快路径**直接判定，只有嵌套根重叠时才走多规则 PathTrie 分发——避免为常见情况付出 Trie 查询成本。

另有 `completed_without_io`（`scan_plan.rs:100`）：某些规则在编译期即可确定结果，**完全不产生 IO**。

### 7.8 第 8 层：`deleteWholeRoot` 原子移动（删除阶段加速）

> `rules/README.md`："`deleteWholeRoot` **avoids one protected deletion transaction per file** by atomically moving the verified root into a private same-volume staging directory and removing that tree."

对 `node_modules`、pnpm store 这类含数十万小文件的目录，省掉每文件事务开销，是数量级差异。28 条规则使用此策略。

### 7.9 进度节流（避免 UI 反压拖慢扫描）

> 引用 `src/storage/duplicates/service.rs:64`：
> ```rust
> const PROGRESS_INTERVAL_MS: u64 = 120;
> ```

多线程并发上报时用 CAS 竞争"时间窗口"，保证同一窗口只有一个 worker 发事件：

> 引用 `src/storage/duplicates/service.rs`（`DuplicateProgress::emit`）：
> ```rust
> } else if self.last_emit_ms
>     .fetch_update(Ordering::AcqRel, Ordering::Acquire, |previous_ms| {
>         (current_ms.saturating_sub(previous_ms) >= PROGRESS_INTERVAL_MS).then_some(current_ms)
>     })
>     .is_err()
> {
>     // Multiple hash workers can reach the throttle concurrently. A load followed by a
>     // store lets all of them pass and emit duplicate progress events; the CAS grants the
>     // current time window to exactly one worker.
>     return;
> }
> ```

### 7.10 分页结果返回（避免序列化整个结果集到 WebView）

> 引用 `src/storage/duplicates/service.rs`（`find_paged_with_progress` 文档注释）：
> ```rust
> /// Product entry point used by Tauri. Starting a scan invalidates the old paginated session.
> /// On success, only the first page is copied into the WebView; the complete bounded result
> /// remains in Rust and later pages are loaded on demand.
> ```

---

## 八、重复文件识别：四级漏斗算法

核心实现：`src/storage/duplicates/service.rs`（1991 行）+ `candidates.rs`（817 行）+ `directory_aggregation.rs`（628 行）+ `hash_cache.rs`（217 行）

**算法总览**：

```
全部文件
  │  ① 大小分组（0 次读取）           ← HashMap<u64, Vec<FileCandidate>>
  ▼  只保留同大小且组内 >1 的候选
  │  ② 物理身份去重（0 次内容读取）    ← (volume, index) 过滤硬链接/别名
  ▼  排除指向同一物理文件的路径
  │  ③ 采样哈希（读 ≤48KB/文件）       ← BLAKE3 head+middle+tail 16KiB
  ▼  只保留采样哈希相同且组内 >1 的候选
  │  ④ 完整哈希（全量读取）            ← BLAKE3 流式 1MB 缓冲
  ▼  字节级精确重复组
  │  ⑤ 目录级聚合                     ← 整目录内容相同则合并为目录组
  ▼  最终结果
```

### 8.1 第 ① 级：大小分组 —— 零读取预筛

候选被按字节大小分桶，只有同桶且桶内多于一个的文件才继续。

> 引用 `src/storage/duplicates/candidates.rs:136-140`：
> ```rust
> pub(super) struct CandidateEnumeration<'a> {
>     root_ordinal: usize,
>     minimum_bytes: u64,
>     visit: &'a dyn Fn(TraversalStage, &Path, u64),
>     size_groups: &'a mut HashMap<u64, Vec<FileCandidate>>,
> ```

同时应用**候选策略剪枝**：

> 引用 `src/storage/duplicates/candidates.rs:105-133`：
> ```rust
> pub(super) fn should_prune_directory(path: &Path) -> bool {
>     ...
>     // Hidden implementation trees are noisy during broad discovery and often contain VCS or
>     // tool metadata rather than independent user copies. Visible build and dependency folders
>     // deliberately remain eligible: their names are not reliable safety boundaries, and both
>     // developers and ordinary applications can store user-managed files inside them.
>     name.starts_with('.')
> }
>
> pub(super) fn should_exclude_file(self, path: &Path) -> bool {
>     if path.file_name()... .is_some_and(|name| name.eq_ignore_ascii_case(".DS_Store")) {
>         return true;
>     }
>     self.broad_discovery && path.extension()... PROTECTED_FILE_EXTENSIONS
> ```

其中（`candidates.rs:22`）：
```rust
const PROTECTED_FILE_EXTENSIONS: [&str; 3] = ["bin", "dll", "jar"];
```

**设计权衡说明**：注释明确指出隐藏目录（`.git` 等）被剪枝是因为"噪音大且多为工具元数据"，而 `node_modules` 这类**可见**构建目录**刻意保留**——因为"目录名不是可靠的安全边界，开发者和普通应用都可能在里面放用户文件"。这体现了保守取向。

宽范围扫描时（用户主目录级），额外排除 `.bin`/`.dll`/`.jar`——避免把库文件误报为可删重复项。该判定**每根只算一次**：

> 引用 `src/storage/duplicates/candidates.rs:87-103`：
> ```rust
> /// Defines which files and subtrees are meaningful during one duplicate discovery scan.
> ///
> /// The broad-scope decision is intentionally computed once per root. Resolving platform user
> /// directories for every candidate previously added repeated filesystem work to the hottest
> /// classification path and made native and generic enumeration harder to keep semantically
> /// identical.
> pub(super) struct DuplicateCandidatePolicy {
>     broad_discovery: bool,
> }
> impl DuplicateCandidatePolicy {
>     pub(super) fn for_scan_root(scan_root: &Path) -> Self {
>         Self { broad_discovery: is_broad_user_scope(scan_root) }
>     }
> ```

### 8.2 第 ② 级：物理身份过滤 —— 排除硬链接与别名

**这是很多去重工具会漏掉的一步**：硬链接、APFS 克隆、同一文件的多个路径，内容当然相同，但删除它们并不释放空间。

> 引用 `src/storage/duplicates/candidates.rs:26-37`：
> ```rust
> pub(super) struct FileIdentity {
>     pub(super) volume: u64,
>     pub(super) index: u64,
> }
>
> pub(super) enum FileIdentitySource {
>     Metadata,
>     DirectoryHint,
>     FileHandle,
> }
> ```

身份获取有**三级降级**：`Metadata`（最快）→ `DirectoryHint`（目录批量提示）→ `FileHandle`（打开句柄，最慢但最可靠）。

过滤统计（`candidates.rs:75-85`）：
```rust
pub(super) struct PhysicalIdentityFilter {
    pub(super) candidates: Vec<FileCandidate>,
    pub(super) alias_count: usize,          // 被过滤的别名数
    pub(super) unavailable_count: usize,    // 身份不可用数
    pub(super) worker_count: usize,
    pub(super) peak_in_flight: usize,
    pub(super) hint_count: usize,
    pub(super) verified_hint_count: usize,
    pub(super) hint_fallback_directory_count: usize,
    pub(super) hint_failure_samples: Vec<IdentityHintFailureSample>,
}
```

### 8.3 第 ③ 级：采样哈希 —— BLAKE3 三段采样

只读文件的**头、中、尾各 16KiB**（合计 ≤48KB）做 BLAKE3，快速淘汰"大小相同但内容不同"的文件。

**采样方案定义**（`src/storage/duplicates/service.rs:80-119`）：

```rust
impl SamplePlan {
    Self::Head4KiB => "head-4k",
    Self::HeadTail8KiB => "head-tail-8k",
    Self::HeadMiddleTail16KiB => "head-middle-tail-16k",
    Self::HeadMiddleTail256KiB => "head-middle-tail-256k",
}

fn offsets(self, file_bytes: u64, sample_bytes: u64) -> [Option<u64>; 3] {
    let tail = file_bytes.saturating_sub(sample_bytes);
    ...
    Self::Head4KiB => [Some(0), None, None],
    Self::HeadTail8KiB => [Some(0), Some(tail), None],
    Self::HeadMiddleTail16KiB => [Some(0), Some(tail / 2), Some(tail)],
    Self::HeadMiddleTail256KiB => [Some(0), Some(tail / 2), Some(tail)],
}

const PRODUCTION_SAMPLE_PLAN: SamplePlan = SamplePlan::HeadMiddleTail16KiB;
```

注意 `SamplePlan` 是多方案枚举，生产用 `HeadMiddleTail16KiB`，其他方案标注 `#[cfg(test)]` 供基准测试对比——说明这个参数是**基准实测选定**的，而非拍脑袋。

**采样哈希实现**（`service.rs:1886-1929`）：

```rust
fn sample_hash(
    candidate: &FileCandidate, plan: SamplePlan, operation: &OperationGuard,
    buffer: &mut Vec<u8>, bytes_read: &mut u64,
) -> Result<blake3::Hash, String> {
    let mut file = File::open(&candidate.path).map_err(|error| error.to_string())?;
    validate_open_file(candidate, &file, true)?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(&candidate.bytes.to_le_bytes());          // ← 文件大小混入摘要
    let sample_size = u64::try_from(plan.segment_bytes()).unwrap_or(u64::MAX).min(candidate.bytes);
    ...
    for offset in plan.offsets(candidate.bytes, sample_size).into_iter().flatten() {
        operation.ensure_not_cancelled()...;
        if previous == Some(offset) { continue; }           // ← 小文件三段重叠时跳过重复段
        previous = Some(offset);
        file.seek(SeekFrom::Start(offset))...;
        let read = read_up_to(&mut file, buffer, bytes_read)...;
        hasher.update(&offset.to_le_bytes());               // ← 偏移量混入，防止段序混淆
        hasher.update(&buffer[..read]);
    }
    // Sampling filters candidates; it does not establish duplicates. At the end, verify that the
    // same open object retained its length and modification time. If the path was replaced during
    // sampling, full hashing reopens it and strictly verifies physical identity. Avoid reopening
    // every path here because low-threshold Windows scans can otherwise create thousands of handles.
    validate_open_file(candidate, &file, false)?;
    Ok(hasher.finalize())
}
```

三处细节值得注意：
1. **文件大小与偏移量都混入哈希**——防止不同大小/不同段顺序产生碰撞
2. **小文件三段重叠时跳过**（`if previous == Some(offset)`）
3. **采样前后各校验一次文件未被替换**，但刻意不重开句柄（注释说明：低阈值 Windows 扫描会创建数千句柄）

### 8.4 第 ④ 级：完整哈希 —— 字节级确认

只有采样哈希相同**且组内多于一个**的候选才进入完整哈希：

> 引用 `src/storage/duplicates/service.rs:1456-1459`：
> ```rust
> let mut full_task_groups = sample_groups
>     .into_values()
>     .filter(|items| items.len() > 1)
>     .collect::<Vec<_>>();
> ```

**完整哈希实现**（`service.rs:1931-1959`）：

```rust
fn full_hash(candidate: &FileCandidate, operation: &OperationGuard, ...) -> Result<blake3::Hash, String> {
    // Full hashing uses the current file opened by this scan. Across scans, path, size,
    // modification time, and file identity alone cannot prove that content stayed unchanged.
    // Reusing an old hash on removable media with coarse timestamps could classify an equal-size
    // rewrite as a duplicate and create unacceptable cleanup risk.
    let mut file = File::open(&candidate.path)...;
    validate_open_file(candidate, &file, true)?;
    let mut hasher = blake3::Hasher::new();
    buffer.resize(FULL_HASH_BUFFER_BYTES, 0);
    loop {
        operation.ensure_not_cancelled()...;
        let read = file.read(buffer)...;
        if read == 0 { break; }
        *bytes_read = bytes_read.saturating_add(...);
        hasher.update(&buffer[..read]);
    }
    validate_open_file(candidate, &file, false)?;
    validate_current_path(candidate)?;      // ← 完整哈希后额外校验路径身份
    Ok(hasher.finalize())
}
```

缓冲区大小（`service.rs:60`）：`const FULL_HASH_BUFFER_BYTES: usize = 1024 * 1024;`（1MB）

**关键安全推理**（上面的注释）：跨扫描复用完整哈希是危险的——在时间戳精度粗糙的可移动介质上，**等大小重写**会被误判为重复，造成数据丢失。所以完整哈希必须基于本次扫描打开的句柄。

**分组键设计**（`service.rs:1486`）：
```rust
let mut full_groups = HashMap::<(u64, blake3::Hash), Vec<usize>>::new();
```
键是 `(文件大小, 完整哈希)` 二元组，双重保险。

### 8.5 优先级调度：大收益组优先出结果

> 引用 `src/storage/duplicates/service.rs:1463-1476`：
> ```rust
> // Prioritize sample groups with more potential reclaimable space so large real duplicate
> // groups reach the UI sooner. All tasks still share one bounded worker pool; ordering changes
> // scheduling priority only, not the stable final result.
> full_task_groups.sort_by(|left, right| {
>     let left_bytes = candidates[left[0]].bytes
>         .saturating_mul(left.len().saturating_sub(1) as u64);
>     let right_bytes = candidates[right[0]].bytes
>         .saturating_mul(right.len().saturating_sub(1) as u64);
>     right_bytes.cmp(&left_bytes).then_with(|| left[0].cmp(&right[0]))
> });
> ```

按 `文件大小 × (组内文件数 - 1)`（即**可回收空间**）降序排，让"删了最省空间"的组先出现在 UI。注释强调这只改调度顺序，不改最终结果稳定性。

### 8.6 增量流式输出：组完成即推送

不等全部哈希完成，**每个采样组的完整哈希一做完就立即推送该组结果**：

> 引用 `src/storage/duplicates/service.rs:1482-1484`：
> ```rust
> // Retain a lightweight candidate-to-sample-group mapping. Full-hash workers remain globally
> // parallel, but a group can finalize its local full-hash buckets and stream them as soon as its
> // remaining count reaches zero, without waiting for unrelated large files.
> ```

> 引用 `src/storage/duplicates/service.rs:1545-1548`：
> ```rust
> state.remaining_tasks = state.remaining_tasks.saturating_sub(1);
> if state.remaining_tasks == 0 {
>     complete_full_task_group(state, &mut full_groups, on_group_complete);
> }
> ```

**结果稳定性保证**（`service.rs:1570-1591`）：
```rust
fn complete_full_task_group(...) {
    // Identical full content necessarily has the same size and sample hash, so groups never need
    // merging across sample buckets. Local results still enter the global map so final ordering
    // and the digest use one authoritative collection.
    for (key, mut indices) in std::mem::take(&mut state.hash_groups) {
        // Worker completion order is nondeterministic. Sorting by candidate ordinal stabilizes
        // local order so cached and fresh paths produce the same internal result and streaming
        // batches remain reproducible.
        indices.sort_unstable();
        ...
```

按候选序号排序，保证**缓存路径与新鲜路径产生完全一致的结果**。

### 8.7 哈希 Worker 池：设备感知 + 有界背压

> 引用 `src/storage/duplicates/service.rs:61-62`：
> ```rust
> const DUPLICATE_HASH_WORKER_LIMIT: usize = 4;
> const HASH_RESULT_QUEUE_PER_WORKER: usize = 2;
> ```

**Worker 池实现**（`service.rs:1686-1788`）：

```rust
let worker_count = configured_worker_count.max(1).min(task_indices.len());
let queue_capacity = worker_count.saturating_mul(HASH_RESULT_QUEUE_PER_WORKER);
...
thread::scope(|scope| -> Result<(), String> {
    let next_task = Arc::new(AtomicUsize::new(0));
    // The channel carries only fixed-size indexes, digests, and counters; it copies neither
    // paths nor file content. The receiver aggregates immediately instead of retaining a
    // second outcome per candidate. Capacity scales with worker count and applies backpressure
    // directly to hash threads when the consumer slows down.
    let (sender, receiver) = sync_channel(queue_capacity);
    ...
            scope.spawn(move || {
                let mut buffer = Vec::<u8>::new();        // ← 每 worker 复用缓冲区
                loop {
                    if operation.cancelled().load(Ordering::Relaxed) { break; }
                    let task_position = next_task.fetch_add(1, Ordering::Relaxed);   // ← 无锁任务窃取
```

设计要点：
- **原子计数器实现无锁任务分发**（`next_task.fetch_add`）
- **有界 channel 提供背压**：消费端慢下来会直接卡住哈希线程，防止内存膨胀
- **channel 只传固定大小的索引/摘要/计数**，不复制路径与文件内容
- **每 worker 复用 buffer**，避免反复分配
- **完成数校验**（`service.rs:1773-1779`）：`completed_count != task_indices.len()` 则报错，防止静默漏算

**设备感知的 worker 分配**（`service.rs:1820-1884`）：

```rust
ScanDeviceClass::SolidState => (
    scheduling.class,
    scheduling.worker_limit.min(DUPLICATE_HASH_WORKER_LIMIT),
    scheduling.worker_limit.min(DUPLICATE_HASH_WORKER_LIMIT),
),
// Duplicate hashing interleaves reads from multiple large files. Even when cleanup
// allows two independent roots on rotational media, this stage must use one worker
// so random seeks do not erase all throughput.
ScanDeviceClass::Rotational => (scheduling.class, 1, scheduling.worker_limit.min(...)),
ScanDeviceClass::Removable | ScanDeviceClass::Network | ScanDeviceClass::Unknown =>
    (scheduling.class, 1, 1),
```

**机械硬盘上哈希阶段强制单 worker**——注释解释得很清楚：去重哈希会交错读取多个大文件，多 worker 的随机寻道会**抹掉全部吞吐**。这与清理扫描允许 HDD 用 2 worker 形成对比，是针对不同 IO 模式的差异化调优。

### 8.8 跨扫描哈希缓存（严格身份校验）

缓存命中需要**五重条件全部匹配**：

> 引用 `src/storage/duplicates/service.rs:1593-1604`：
> ```rust
> fn duplicate_cache_file_matches(candidate: &FileCandidate, cached: &DuplicateHashCacheFile) -> bool {
>     candidate.root_ordinal == cached.root_ordinal
>         && candidate.path == cached.path
>         && candidate.bytes == cached.bytes
>         && candidate.modified_at == cached.modified_at
>         && candidate.identity
>             .is_some_and(|identity| encode_file_identity(identity) == cached.identity)
> }
> ```

即：根序号 + 路径 + 大小 + 修改时间 + **物理身份 (volume, index)** 全部一致。

身份编码（`service.rs:1606-1611`）：
```rust
fn encode_file_identity(identity: FileIdentity) -> [u8; 16] {
    let mut encoded = [0_u8; 16];
    encoded[..8].copy_from_slice(&identity.volume.to_be_bytes());
    encoded[8..].copy_from_slice(&identity.index.to_be_bytes());
    encoded
}
```

缓存快照还绑定了扫描参数（`service.rs:1640`）：
```rust
hash_cache::store_snapshot(roots, minimum_bytes, sample_plan.name(), files, ...)
```
`minimum_bytes` 与 `sample_plan.name()` 都参与快照标识——**采样方案变了缓存自动失效**。

注意 §8.4 的注释：完整哈希**不跨扫描复用**（只在同次扫描内用于流式输出），而采样哈希可复用——这是安全性与性能的精确权衡。

### 8.9 第 ⑤ 级：目录级重复聚合

若两个目录内**每个文件**都一一对应重复，则合并展示为"重复目录"而非几百条重复文件。

> 引用 `src/storage/duplicates/directory_aggregation.rs:70`：
> ```rust
> /// Replaces overlapping file groups with exact directory groups when every regular file in each
> ```

**目录指纹算法**（`directory_aggregation.rs:38-61`）：

```rust
struct DirectorySeed {
    bytes: u64,
    file_count: u64,
    hash_sum_low: u64,
    hash_sum_high: u64,
    hash_xor_low: u64,
    hash_xor_high: u64,
}

impl DirectorySeed {
    fn add(&mut self, file: &KnownFile) {
        let digest = blake3::hash(file.hash.as_bytes());
        let bytes = digest.as_bytes();
        let low = u64::from_le_bytes(bytes[0..8]...);
        let high = u64::from_le_bytes(bytes[8..16]...);
        self.bytes = self.bytes.saturating_add(file.bytes);
        self.file_count = self.file_count.saturating_add(1);
        self.hash_sum_low = self.hash_sum_low.wrapping_add(low);      // ← 加法：顺序无关
        self.hash_sum_high = self.hash_sum_high.wrapping_add(high);
        self.hash_xor_low ^= low;                                     // ← 异或：顺序无关
        self.hash_xor_high ^= high;
    }
}
```

设计巧妙之处：用**加法 + 异或**双重交换律累积器构造顺序无关的目录种子。单用加法或单用异或都容易碰撞，两者组合大幅降低碰撞概率；且遍历顺序不影响结果。

种子只用于**快速分桶**，最终仍生成正式指纹（`directory_aggregation.rs:63-68`）：
```rust
struct DirectoryFingerprint {
    digest: [u8; 32],
    bytes: u64,
    file_count: u64,
}
```

限制（`directory_aggregation.rs:16-17`）：
```rust
const MAX_DIRECTORY_AGGREGATION_DEPTH: usize = 20;
const HASH_BUFFER_BYTES: usize = 1024 * 1024;
```

### 8.10 删除阶段的失败诊断（避免日志风暴）

> 引用 `src/storage/duplicates/service.rs:196-215`：
> ```rust
> impl HashFailureDiagnostics {
>     fn record(&mut self, path: &Path, error: &str) {
>         self.count = self.count.saturating_add(1);
>         if self.samples.len() >= HASH_FAILURE_SAMPLE_LIMIT { return; }
>         let error_digest = blake3::hash(error.as_bytes()).to_hex().to_string();
>         self.samples.push(format!("{}#{}", diagnostic_path(path), &error_digest[..12]));
>     }
>     fn write_log(&self, operation_id: u64, stage: HashStage) {
>         if self.count == 0 { return; }
>         // Permission and sharing failures can affect thousands of files. Per-file warnings would
>         // create a log storm and slow the scan. Stage summaries keep totals and a few correlatable
>         // samples without recording full paths or raw errors.
> ```

权限/共享冲突可能影响数千文件，逐条打日志会造成**日志风暴并拖慢扫描**。方案：只记总数 + 最多 3 个样本（`service.rs:63`：`HASH_FAILURE_SAMPLE_LIMIT: usize = 3`），且错误信息**哈希后**记录（隐私保护，不落原始路径与原始错误）。

### 8.11 完整诊断指标（44 项）

`DuplicateScanDiagnostics`（`service.rs:234-275`）暴露 44 个指标，覆盖每一级漏斗：

| 类别 | 指标 |
|------|------|
| 阶段耗时 | `enumeration_and_size_group_ms`、`group_and_identity_ms`、`sample_hash_ms`、`full_hash_ms`、`result_sort_ms`、`directory_aggregation_ms` |
| 候选量 | `size_group_candidate_count`、`sample_hash_candidate_count`、`full_hash_candidate_count` |
| 读取量 | `sample_hash_bytes`、`full_hash_bytes` |
| 身份过滤 | `physical_alias_filtered_count`、`identity_unavailable_count`、`identity_hint_count`、`identity_hint_verified_count`、`identity_hint_fallback_directory_count` |
| 并发 | `sample_hash_worker_count`、`sample_hash_peak_in_flight`、`full_hash_worker_count`、`full_hash_peak_in_flight`、`hash_result_queue_capacity` |
| 缓存 | `cache_snapshot_found`、`cache_candidate_match_count`、`sample_hash_cache_hit_count`、`full_hash_cache_hit_count`、`cache_load_ms`、`cache_validation_ms`、`cache_fallback_count`、`cache_write_entry_count`、`cache_write_ms` |
| 流式 | `streamed_group_batch_count`、`streamed_group_count`、`first_streamed_group_ms` |
| 策略 | `candidate_strategy`、`sample_plan` |

配合 `src/reporting/benchmark/`（runner 1311 行 + dataset 1024 行 + comparison 923 行）构成完整的性能回归体系。

---

## 九、总结与可借鉴设计

### 9.1 规则体系的核心结论

**关于"规则从何而来"**：
1. **明确否认移植第三方规则库**——第三方（CCleaner / BleachBit 类）仅作 research leads
2. **92.7% 的规则携带官方文档引用**，318 条链接绝大多数指向第一方（Chromium 源码文档 52、Apple 37、Microsoft 23、Electron 19）
3. **205 条规则 100% 处于 `verified` 生命周期**，无一条 candidate 进入生产
4. 每条规则强制 `evidence` 文本论证"为什么可删 + 边界外保留了什么"
5. 规则有 `rule_version` 演进机制（pnpm 规则已迭代到 v3）

**关于"识别规则是什么"**：
- 205 条声明式规则（Windows 87 / macOS 118），6 大分类
- 31 条项目产物规则，覆盖 69 个可重建目录、31 个技术生态
- 24 个专用 Rust Cleaner（13 AI 模型 + 6 Windows 系统 + 5 工具链）
- 路径必须用 8 个受控变量之一开头，禁止绝对路径与 `..`
- 12 种匹配器，实测 176 条用 `all`（因根本身即狭义缓存）
- 152/205 条需关闭应用进程

### 9.2 加速方案总结

| 层次 | 技术手段 | 关键代码 |
|------|---------|---------|
| 1 | Windows：`FSCTL_QUERY_FILE_LAYOUT` 直读 NTFS，8MB 缓冲 | `windows/file_layout/parser.rs:50-96` |
| 2 | macOS：`getattrlistbulk` 批量属性，64KB 分页 | `macos/bulk_directory.rs:74-90,177-192` |
| 3 | Windows：USN Journal 增量变更判定 | `windows/change_tracking.rs:17-79` |
| 4 | 内存索引 LRU 缓存 + 变更令牌校验 | `storage/index/cache.rs:22-28,88-169` |
| 5 | 设备感知并发（SSD 4 / HDD 2 / 其他 1） | `contracts/volumes.rs:21-51`、`cleanup/scan.rs:235-242` |
| 6 | 适用性探针剪枝（未安装应用整条跳过） | `cleanup/scan.rs:188-217` |
| 7 | 路径 Trie 剪枝 + `should_descend` 提前止步 | `cleanup/rules/scan_plan.rs:209,247-249` |
| 8 | `deleteWholeRoot` 原子移动（省每文件事务） | 28 条规则 + `rules/README.md` |
| — | 进度 CAS 节流 120ms + 结果分页返回 | `duplicates/service.rs:64` |

### 9.3 去重算法总结

| 级别 | 手段 | IO 成本 | 关键代码 |
|------|------|--------|---------|
| ① | 大小分组 | 0 读取 | `duplicates/candidates.rs:136-140` |
| ② | 物理身份 (volume, index) 过滤硬链接 | 0 内容读取 | `candidates.rs:26-37,75-85` |
| ③ | BLAKE3 采样：head+middle+tail 16KiB | ≤48KB/文件 | `service.rs:80-119,1886-1929` |
| ④ | BLAKE3 完整哈希，1MB 流式 | 全量 | `service.rs:1931-1959` |
| ⑤ | 目录级聚合（加法+异或双累积器） | 复用已有哈希 | `directory_aggregation.rs:38-61` |

**算法安全性的三个亮点**：
1. 采样哈希把**文件大小与段偏移量都混入摘要**，抗碰撞
2. 完整哈希**拒绝跨扫描复用**——注释明确论证了"可移动介质等大小重写会被误判"的风险
3. 采样前后 + 完整哈希后**多次校验文件未被替换**（`validate_open_file` / `validate_current_path`）

### 9.4 最值得借鉴的设计模式

1. **声明式优先 + 代码兜底的分层**：把可声明的部分做成 schema 校验的数据，明确禁止"为单规则开 Rust 特例"来绕过校验
2. **构建期 + 运行期同源双重校验**：`build.rs` 通过 `#[path]` 复用运行期 schema 代码，杜绝两套逻辑漂移
3. **探针只做性能、不做安全**：适用性探测失败时 fail-open 保持可扫描，安全性完全由 root + matcher 保证，职责边界清晰
4. **危险操作的多重条件白名单**：Downloads 例外用七条硬编码条件锁死，而非依赖 review
5. **降级优于冒险**：`deleteWholeRoot` 遇到任何异常（嵌套所有权、跳过条目、不支持的原生遍历）都在**修改前**自动退回逐文件删除
6. **诊断即产品**：44 项去重指标 + 完整 benchmark 体系，让性能优化可度量、可回归
7. **注释记录权衡而非描述代码**：大量注释解释"为什么不这么做"（如为何 HDD 哈希只用 1 worker、为何不重开句柄、为何 `node_modules` 不剪枝），这是高质量工程文档的典范

---

## 附录：关键文件索引

| 文件 | 行数 | 职责 |
|------|------|------|
| `rules/README.md` | — | 规则贡献规范与全部安全约束（**理解规则体系的第一入口**） |
| `src/cleanup/rules/declarative_schema.rs` | 1755 | 声明式规则 schema 定义与校验 |
| `src/cleanup/rules/declarative_catalog.rs` | 587 | 嵌入规则加载与运行期二次校验 |
| `src/cleanup/rules/scan_plan.rs` | 935 | 扫描计划编译、所有权校验、Trie 剪枝 |
| `src/cleanup/rules/matcher.rs` | 253 | 匹配器求值 |
| `src/cleanup/applicability.rs` | 267 | 适用性探针求值 |
| `src/cleanup/scan.rs` | 1518 | 清理扫描调度与并发 |
| `src/cleanup/service.rs` | 11061 | 清理服务主编排 |
| `src/storage/duplicates/service.rs` | 1991 | 重复文件识别主流程 |
| `src/storage/duplicates/candidates.rs` | 817 | 候选枚举、物理身份过滤 |
| `src/storage/duplicates/directory_aggregation.rs` | 628 | 目录级重复聚合 |
| `src/storage/duplicates/hash_cache.rs` | 217 | 跨扫描哈希缓存 |
| `src/storage/traversal.rs` | 1207 | 遍历引擎与快速路径 |
| `src/storage/index/cache.rs` | 739 | 索引缓存与变更令牌 |
| `mangodisk-platform/src/windows/file_layout/parser.rs` | 1034 | NTFS FILE_LAYOUT 解析 |
| `mangodisk-platform/src/windows/change_tracking.rs` | 1580 | USN Journal 增量追踪 |
| `mangodisk-platform/src/windows/disk_cleanup.rs` | — | IEmptyVolumeCache COM 封装 |
| `mangodisk-platform/src/macos/bulk_directory.rs` | 394 | getattrlistbulk 封装 |
| `mangodisk-platform/src/contracts/volumes.rs` | — | 设备类型与并发策略 |
| `build.rs`（core） | — | 构建期规则校验与嵌入 |

---

*报告基于 MangoDisk commit `7c8ffc3`（2026-08-27）源码分析编写。所有代码引用格式为 `路径:行号`，可在该 commit 下直接定位验证。*
