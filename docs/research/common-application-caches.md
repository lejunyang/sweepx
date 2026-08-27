# 常见应用缓存、日志与卸载残留研究

研究日期与网络来源访问日期：**2026-08-26**。

本文给 SweepX 提供一组有边界的代表性应用证据，覆盖 VS Code、JetBrains IDE、Microsoft Teams、Slack、Zoom、Steam、Adobe Premiere Pro / After Effects / Creative Cloud 与 Spotify。它不是“所有应用垃圾路径大全”，也不授权按固定字符串删除目录。

## 目录

- [1. 证据口径与结论](#_1-证据口径与结论)
- [2. 统一安全规则](#_2-统一安全规则)
- [3. 应用矩阵](#_3-应用矩阵)
- [4. 逐应用证据](#_4-逐应用证据)
- [5. 日志、诊断包与卸载残留](#_5-日志、诊断包与卸载残留)
- [6. Cleaner 建模建议](#_6-cleaner-建模建议)
- [7. 官方来源索引](#_7-官方来源索引)

## 1. 证据口径与结论

- **F（事实）**：由厂商官方文档或上游厂商材料直接支持，并受文档所述版本、平台和 channel 限制。
- **I（推导）**：从一项或多项事实得出的工程限制，不是厂商承诺。
- **R（建议）**：SweepX 的保守产品策略。
- **U（未知）**：来源没有证明、版本易漂移或必须实机验证的部分。

核心结论：

1. **不存在通用的“应用 cache 目录即安全垃圾”规则。** 同一个 app-data 根经常混有 cache、设置、凭据、会话、插件、本地历史、离线内容与用户产物。
2. **优先展示厂商自己的 Clear / Reset / Invalidate / Purge 控制。** 这些操作仍属于 mutation（M）；SweepX v1 只给出 `managerPermanentRecommendation`，不代用户执行，也不以裸删目录模拟。
3. **路径必须由运行实例、配置、厂商 UI、manifest、known-folder API 或卸载 receipt 解析。** 默认路径只是候选证据，portable、sandbox、channel 和用户配置都可能改写它。
4. **“退出应用”是最低前置条件，不是无占用证明。** 还要观察 updater、helper、renderer/WebView、sync、indexer、build 与 media-render 进程；普通用户无法完整观察时保持 unknown/report-only。
5. **日志只按 exact closed file 或厂商定义的 closed rotation/session group 处理。** 当前日志、诊断包、云同步冲突证据、支持工单附件与 writer 不明的文件一律 R3/report-only。
6. **卸载后目录不是天然垃圾。** 必须证明产品/channel/版本所有权，并排除其他版本、共享组件、配置、凭据、插件、用户文档与离线内容。

## 2. 统一安全规则

每条应用规则都必须记录：

```text
product + full version + channel + platform
typed root source + effective configured path + observedAt
artifact class + exact consistency unit + owner evidence
cache/state/user-content exclusions
official control + side effects + restart/sign-in/redownload cost
process/holder coverage + confidence + unknowns
risk + disposition + supported action + source IDs
```

统一处置：

| 场景 | v1 处置 |
|---|---|
| 厂商提供明确的 clear/invalidate/purge UI | R2–R4 `manager_gc_candidate` / `managerPermanentRecommendation`，只展示步骤与副作用 |
| exact closed log，所有权、rotation 与 retention 已证 | 至少 R2；完成 live revalidation 后才可提出平台 Trash |
| mixed app-data/container/user-data root | R3 `report_only` |
| 安装数据库、凭据、共享组件或产品修复状态 | R4 manager-only recommendation，裸删 BLOCKED |
| 运行中、holder coverage unknown、版本或布局不受支持 | `report_only` / `unsupported_layout` |
| 用户 Downloads、录制、项目、素材、存档、游戏、save、offline media | 用户数据或应用状态，默认 R3/BLOCKED |

所有 filesystem Trash 候选仍要通过普通用户运行、no-follow、same-mount、完整目录 manifest、硬保护、不可变计划、可信人工审批和紧邻动作复验。Trash 失败不转 Permanent。

## 3. 应用矩阵

| 产品与证据版本 | 平台 | 权威发现/控制 | 必须排除 | 卸载残留置信度 | SweepX v1 |
|---|---|---|---|---|---|
| VS Code 1.109/current | Windows/macOS/Linux | `--user-data-dir`、Portable Mode、Open Logs Folder | settings、workspace state、backup、extensions | 仅显式 complete uninstall 为高 | closed logs 可 R2；整个 user-data R3 report-only |
| IntelliJ IDEA 2026.1 family | Windows/macOS/Linux | configured system/log path、Invalidate Caches、Leftover Storage UI | Local History、config、plugins | 高，且按产品/版本 | cache manager recommendation；closed logs R2 |
| New Teams current | Windows/macOS | Windows Reset、官方 cache procedure | personalization、cookies/session、support bundle | 低/未知 | reset scope R4 manager recommendation |
| Slack current | Windows/macOS/Linux | Troubleshooting → Clear Cache and Restart | mixed app data、Net Logs | Windows/Linux reinstall 较高；macOS 未证 | R2 manager recommendation；raw root R3 |
| Zoom Workplace current | Windows/macOS/Linux | 官方 cache/data reset、Open Log Folder、CleanZoom | recordings、chat/media、support evidence、session state | Windows full cleanup 高；其他未知 | UI control R2；mixed/full reset R3–R4 |
| Steam current | Windows/macOS/Linux | Settings → Downloads → Clear Download Cache | `steamapps`、`userdata`、Workshop、saves、Cloud | Windows manual uninstall 中等/高 | download cache manager recommendation |
| Premiere Pro / After Effects current | Windows/macOS | Media/Disk Cache preferences 与 purge UI | project、source、proxy、autosave、render、plugin、shared DB | 未证 | R2 manager recommendation；shared root R3 |
| Creative Cloud install state | Windows/macOS | Creative Cloud uninstaller / Cleaner Tool | credential、preference、plugin、profile、shared component | 可存在残留为高；裸路径归因为低 | R4 manager-only；raw file BLOCKED |
| Spotify current | Windows/macOS/Linux（供应平台） | Settings → Storage → Clear cache | offline downloads、local files | 低/未知 | R2 manager recommendation；无 raw path rule |

## 4. 逐应用证据

### 4.1 VS Code

**F：发现与位置。** `--user-data-dir` 指向实际 user-data root；Portable Mode 可同时重定位 user data 与 extensions。官方 portable/uninstall 文档给出的默认 user-data 候选为 Windows `%APPDATA%\Code`、macOS `~/Library/Application Support/Code`、Linux `~/.config/Code`。日志应优先通过 **Developer: Open Logs Folder** 定位。

**F：边界。** 整个 user-data root 包含设置、状态、backup 和 extension data，不是 cache。`~/.vscode` 含 extension/state，也不能当作 cache。官方 complete-uninstall 文档列出的保留目录，只能证明“在用户明确要求完整卸载时这些位置属于卸载范围”，不能证明其中每项平时可清。

**U：** 没找到当前官方稳定的 raw cache subdirectory 契约。

**R：** exact closed timestamped log/session 可在证明无 Code/extension-host writer 后成为 R2 Trash 候选；当前日志、整个 user-data root、extension root 和所谓“卸载残留”保持 R3/report-only。

### 4.2 JetBrains IDE

**F：发现。** IntelliJ IDEA 2026.1 文档给出 system dir：Windows `%LOCALAPPDATA%\JetBrains\<product><version>`、macOS `~/Library/Caches/JetBrains/<product><version>`、Linux `~/.cache/JetBrains/<product><version>`。Windows/Linux 日志通常位于 system dir 的 `log`，macOS 位于 `~/Library/Logs/JetBrains/<product><version>`。`idea.system.path` 与 `idea.log.path` 可覆盖默认值，IDE Help 菜单可揭示实际目录。

**F：关键排除。** system dir 同时包含 caches 和 **Local History**；config/plugins 位于其他根并属于用户状态。不能将整个 system dir 标成低风险 cache。

**F：官方控制。** **File → Invalidate Caches → Invalidate and Restart** 针对当前 IDE 版本使用过的所有项目，并在 restart 时执行。Local History 只有用户显式勾选对应选项才纳入。**Help → Delete Leftover IDE Storage Directories** 用于旧版本；文档说明旧 cache/log 可在约 180 天后自动移除，而 config/plugins 保留。

**R：** 优先 R2 manager recommendation。旧版本也优先用厂商 leftover UI。closed logs 可 R2 Trash；Local History/config/plugins 为 R3/report-only。需确保 IDE、indexer、build tool 与 Toolbox helper 静止。

### 4.3 Microsoft Teams

**F：Windows。** New Teams 文档给出 `%USERPROFILE%\AppData\Local\Packages\MSTeams_8wekyb3d8bbwe\LocalCache\Microsoft\MSTeams`，并优先建议 Windows Settings → Apps → Teams → Advanced options → Reset。

**F：macOS。** 官方流程涉及 `~/Library/Group Containers/UBF8T346G9.com.microsoft.teams` 与 `~/Library/Containers/com.microsoft.teams2`。这些 container 范围不是纯 cache。

**F：副作用。** Reset 会删除 app data，包括 personalization settings。诊断 bundle 通过快捷键生成到 Downloads，属于用户创建的支持材料。

**U：** 当前 cache 文档未给出 Linux 支持，也没有证明普通 uninstall 后的完整残留契约。

**R：** Windows Reset/macOS container cleanup 为 R4 manager recommendation；不按内部 Chromium 子目录裸删。要求 Teams、WebView 与 helper 静止。support bundle 默认为 R3/report-only；用户明确选择一个 closed file 时才另行评估。

### 4.4 Slack

**F：官方控制。** **Help → Troubleshooting → Clear Cache and Restart** 是支持的 cache 控制；Net Logs 通过 Troubleshooting 的 Download Logs / Report Issue 生成。

**F：reinstall 范围。** Windows 官方 troubleshooting 涉及 `%AppData%\Slack` 和 `%LocalAppData%\Slack`，并要求确认 `Slack.exe` 与 `Update.exe` 不在运行。Linux direct-download reinstall 文档涉及 `~/.config/Slack` 和 package repository files。

**U：** 未找到官方稳定的 raw cache/log 子目录；macOS 卸载残留也没有被本轮来源证明。

**R：** Clear Cache and Restart 为 R2 manager recommendation。上述 app-data/config 根为 mixed state，仅在用户明确的 complete-reinstall 工作流中报告，平时 R3/report-only。Net Logs 是用户支持材料，不作为 cache。

### 4.5 Zoom Workplace

**F：位置/控制。** Windows 文档给出 `%APPDATA%\Zoom\data` 与 `%APPDATA%\Zoom\logs`。macOS 日志可从 Open Log Folder 或 `~/Library/Logs/zoom.us` 定位；cache 文档显示 `Library/Application Support/zoom.us` 下的 `data`，但页面对 home-relative 表达存在歧义，不能静态拼接。Linux vendor reset scope 同时覆盖 `~/.cache/zoom` 与 `~/.zoom`，日志在 `~/.zoom/logs`。

**F：副作用。** Settings → General 的 **Clear local Zoom App data and cookies** 会涉及 cookies/state。Windows `CleanZoom` 是完整移除 config 与本地设置的工具，不是低风险 cache purge。录制和 chat/media 目录另有配置位置，必须排除。

**R：** vendor UI cache control 为 R2 manager recommendation；Windows/macOS `data` 通常 R2–R3/report-only，Linux 双根为 R3/R4 manager recommendation。仅 exact closed logs 且没有 support case 时可评估 R2。

### 4.6 Steam

**F：官方控制。** **Steam → Settings → Downloads → Clear Download Cache** 是 manager-defined scope；官方说明不会影响已安装游戏，但会使用户重新登录。

**F：日志。** Steam Cloud log 的官方位置为 Windows `C:\Program Files (x86)\Steam\logs\cloud_log.txt`、macOS `~/Library/Application Support/Steam/logs/cloud_log.txt`、Linux `~/.local/share/Steam/logs/cloud_log.txt`。

**F：关键排除。** `steamapps`、`userdata`、Workshop/game content、save 与 Cloud data 不是 download cache。官方 Windows manual uninstall 指南要求需要保留游戏时先保护 `steamapps`；这不代表每次普通卸载都必然留下相同内容。

**R：** download cache 为 R2 manager recommendation。Steam/client service 或 active download 存在时不提清理。Cloud/current log 是同步/冲突证据，R3/report-only；closed rotation 最多 R2。含 `steamapps`/`userdata` 的 uninstall root 在用户做保留选择前 R3/BLOCKED。

### 4.7 Adobe Premiere Pro 与 After Effects

**F：Premiere。** 默认 media-cache 根候选为 Windows `C:\Users\<user>\AppData\Roaming\Adobe\Common`、macOS `~/Library/Application Support/Adobe/Common`；实际位置以 Preferences/Settings → Media Cache 为准。`.pek` peak 与 `.cfa` conformed media 可再生成，但 `Adobe/Common` 可能跨应用共享。官方提供 **Remove Media Cache Files → Delete unused**；删除全部 cache 要先 **File → Close All Projects**。Media Cache Files 与对应 Database records 是一致性组。

**F：After Effects。** actual disk/media cache 位置由 Preferences/Settings → Disk 或 Media & Disk Cache 揭示。官方提供 **Empty Disk Cache**、**Edit → Purge → All Memory & Disk Cache** 与 **Clean Database & Cache**。disk cache 是再生 frame/audio；media cache/database 可能跨 Adobe 应用共享。

**R：** 两者优先 R2 manager recommendation。排除 project、source footage、export、proxy、autosave、render、preset、plugin 与 shared DB state。相关 Adobe app/render process 未完全静止时 report-only；raw whole `Adobe/Common` 为 R3。

### 4.8 Adobe Creative Cloud 安装状态

**F：** Creative Cloud desktop app 是 Adobe app 的受支持 uninstaller；Creative Cloud Cleaner Tool 可移除所选 files/folders、registry entries、旧软件和损坏的 installation records。它服务于安装/更新修复，不是通用 cache cleaner。enterprise uninstaller 对删除用户 preference 有显式选择。

**I：** 工具的存在证明安装状态残留可能存在，但不证明这些状态能被安全拆成独立 raw path。

**R：** 仅 R4 manager-only recommendation。先备份 product directories、custom plugins 与 profiles，并按厂商流程停止 Adobe apps/services。credentials、preferences、install records 和 shared components 不能成为 filesystem candidate。

### 4.9 Spotify

**F：** Settings 的 Storage 管理提供 **Clear cache**；官方区分 streaming cache 与 downloaded music/podcasts。reinstall 会导致 downloads 重新下载。

**U：** 本轮 vendor 来源没有给出稳定的 desktop raw cache/log path 或完整 uninstall residue inventory。

**R：** R2 manager recommendation。offline downloads 与 local files 明确排除；不提供 raw path rule，未知版本或 app 未静止时 report-only。

## 5. 日志、诊断包与卸载残留

### 5.1 日志与诊断包

应用目录中出现 `log`、`.log` 或日期名字不构成 owner、closed 或 retention 证据。一个 R2 log proposal 至少要求：

- 路径来自应用配置、官方 UI 或 vendor 文档；
- exact current log 与 closed rotation/session group 可区分；
- 未观察到 app/updater/helper writer，且观察 coverage 被记录；
- 没有活跃 support case、crash upload、Cloud conflict、compliance 或 audit retention；
- grouping 包含厂商要求的 metadata/attachments，但不扩大到父 app-data root；
- Trash 后的诊断损失、隐私与恢复预期被展示。

Teams diagnostic bundle、Slack Net Logs、Zoom support logs 与 Steam Cloud log 都可能是用户正在使用的诊断证据，默认 R3。

### 5.2 卸载残留

只有下列证据组合才能把“可能残留”提升为 app-owned residual：

1. 卸载 receipt/package database、signed app identity 或 vendor complete-uninstall manifest；
2. 产品、版本、channel 与 configured root 一致；
3. 没有其他已安装版本、共享插件/helper/service 使用该对象；
4. 用户文档、license、credential、preference、offline media、game/save 和 exports 已明确排除；
5. owner manager 没有更合适的 supported removal/repair 流程。

即使证据齐全，mixed root 通常仍为 R3/report-only；厂商 uninstall/Cleaner Tool 属 R4 manager recommendation。通用“扫描 Program Files/AppData 后猜测软件已卸载”的功能不进入 v1。

## 6. Cleaner 建模建议

建议把每个应用拆成不同 artifact class，而不是一个 `app.clean` 总开关：

```text
app.<product>.rebuildable-cache
app.<product>.closed-log-session
app.<product>.diagnostic-bundle
app.<product>.mixed-user-data
app.<product>.install-state
app.<product>.offline-user-content
```

规则 unknown-version behavior 固定为 `report_only` 或 `unsupported_layout`。官方 UI/manager command 只能作为 recommendation 或 future first-party adapter；第三方 declarative rule 不能启动应用、模拟点击、停止进程、写 policy、执行 shell 或裸删 mixed root。

进入实现前，每条规则还需要在 Windows、macOS、Linux 中明确 supported/unsupported，并用真实版本 fixture 验证 configured path、sandbox/portable channel、holder、网络/写副作用、完整 consistency unit、恢复条件和厂商版本漂移。

## 7. 官方来源索引

以下来源均访问于 **2026-08-26**。

### VS Code

- [CLI 与 `--user-data-dir`](https://code.visualstudio.com/docs/configure/command-line)
- [Portable Mode 与默认 user-data roots](https://code.visualstudio.com/docs/setup/portable)
- [Complete uninstall](https://code.visualstudio.com/docs/setup/uninstall)
- [Developer: Open Logs Folder](https://code.visualstudio.com/updates/v1_20)

### JetBrains

- [IntelliJ IDEA 2026.1 directories](https://www.jetbrains.com/help/idea/2026.1/directories-used-by-the-ide-to-store-settings-caches-plugins-and-logs.html)
- [Invalidate caches](https://www.jetbrains.com/help/idea/invalidate-caches.html)
- [Uninstall IntelliJ IDEA / leftover directories](https://www.jetbrains.com/help/idea/uninstall.html)

### Microsoft Teams

- [Clear Teams client cache](https://learn.microsoft.com/troubleshoot/microsoftteams/teams-administration/clear-teams-cache)
- [Collect and identify Teams logs](https://learn.microsoft.com/training/modules/troubleshoot-audio-video-client-issues/03-collect-identify-logs)
- [Teams diagnostic keyboard shortcuts](https://support.microsoft.com/accessibility/teams/keyboard-shortcuts-for-microsoft-teams)

### Slack

- [Troubleshoot connection issues / Clear Cache and Restart / Net Logs](https://slack.com/help/articles/205138367-Troubleshoot-connection-issues)
- [Update or reinstall the desktop app](https://slack.com/help/articles/360048367814-Update-the-Slack-desktop-app)
- [Troubleshoot notifications / report logs](https://slack.com/help/articles/360001559367-Troubleshoot-Slack-notifications)

### Zoom

- [Clear Zoom cache and cookies](https://support.zoom.com/hc/en/article?id=zm_kb&sysparm_article=KB0079926)
- [Clear local Zoom App data and cookies](https://support.zoom.com/hc/en/article?id=zm_kb&sysparm_article=KB0058833)
- [Client logs](https://support.zoom.com/hc/en/article?id=zm_kb&sysparm_article=KB0060047)
- [Complete uninstall / CleanZoom](https://support.zoom.com/hc/en/article?id=zm_kb&sysparm_article=KB0065146)
- [Client directory categories](https://support.zoom.com/hc/en/article?id=zm_kb&sysparm_article=KB0084064)

### Steam

- [Clear Download Cache](https://help.steampowered.com/en/faqs/view/6AD7-820D-8BE5-E51F)
- [Steam Cloud paths and log](https://help.steampowered.com/en/faqs/view/68D2-35AB-09A9-7678)
- [Uninstall Steam](https://help.steampowered.com/en/faqs/view/3C73-90F9-F600-0266)

### Adobe

- [Premiere media-cache control](https://helpx.adobe.com/premiere/desktop/troubleshooting/media-issues/clear-media-cache-using-preferences.html)
- [Premiere manual cache removal and default roots](https://helpx.adobe.com/premiere/desktop/troubleshooting/media-issues/delete-media-cache-files-manually.html)
- [After Effects memory, storage and cache controls](https://helpx.adobe.com/after-effects/using/memory-storage1.html)
- [Creative Cloud Cleaner Tool](https://helpx.adobe.com/download-install/apps/troubleshoot/download-failure/cc-cleaner-tool-installation-problems.html)
- [Creative Cloud app uninstall](https://helpx.adobe.com/creative-cloud/help/uninstall-remove-app.html)

### Spotify

- [Storage, cache and downloads](https://support.spotify.com/article/storage-information/)
- [Reinstall and re-download effects](https://support.spotify.com/article/spotify-not-playing/)
