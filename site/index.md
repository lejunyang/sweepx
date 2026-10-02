---
layout: home

hero:
  name: "SweepX"
  text: "先看清，再决定"
  tagline: "可运行的开发版磁盘分析 CLI/TUI，并提供受保护的 Trash、Linux 隔离与有界目录 Permanent 预览。"
  image:
    src: /mark.svg
    alt: SweepX
  actions:
    - theme: brand
      text: 开始了解
      link: /guide/introduction
    - theme: alt
      text: 运行只读扫描
      link: /cli
    - theme: alt
      text: English
      link: /en/

features:
  - title: 可运行，但只读
    details: Linux、macOS 与 Windows 均已有 degraded 的开发版只读 scanner，并统一通过 `sweepx scan` / `scan --tui` 接入；macOS 使用 handle-bound traversal，Windows 使用 handle-relative traversal。
  - title: 证据不会变成授权
    details: 导入 scan JSON 会被强制降级为 stale、incomplete 和 report-only。`cache status` 也只是 preview cache 的只读诊断；`available` 只表示缓存结构/校验可读，不代表 live/current 文件事实。
  - title: 可恢复清理预览
    details: CLI/TUI 支持显式确认、实时重验的单对象 Trash；Linux 另有完整摘要确认、逐项重验的陈旧临时对象异盘隔离，名称不作为授权依据。没有 Permanent fallback，通用 plan/approve/execute 仍未开放。
  - title: Linux 文件/目录 Permanent 预览
    details: 只接受解析后的绝对路径普通文件或有界真实目录；完整摘要挑战、封闭 manifest、逐项 durable intent 与 parent-relative unlinkat/rmdir 形成独立 R4 路径。链接、超限树和跨平台 Permanent 仍禁用。
---

> [!CAUTION]
> **SweepX 另有 Linux 有界文件/目录 Permanent development preview。** 它要求普通用户在前台终端输入完整摘要，先持久化封闭计划，再对每项写 intent、重验并按后序执行 `unlinkat`/`rmdir`。它不是 secure erase，也不覆盖链接、超限树或跨平台执行；Trash 失败绝不进入该路径。P3 的通用计划/执行仍是 library-only 模拟。

## 现在能做什么

| 能力 | 当前状态 |
|---|---|
| Linux 目录扫描 | development-grade、read-only、degraded |
| macOS 目录扫描 | development-grade、read-only、handle-bound degraded |
| Windows 目录扫描 | development-grade、read-only、handle-relative degraded |
| `status` | Linux journal-first 读取 terminal snapshot，并支持 degraded 的 `sweepx --format ndjson status --operation-id ID --watch [--after SXCUR1]` completed replay；macOS 与 Windows 读取 legacy snapshot，Windows state directory 强制 current-user-private |
| `cancel` | 命令存在，但 live cancellation disabled |
| `explain` | 从有界 scan JSON 生成 report-only 解释 |
| `cache status` | Linux/macOS/Windows：preview cache 只读诊断 |
| Cleaner | 只读 list/show 元数据，带版本兼容门；`cargo-detect` 有固定输入读取和 typed evidence，但仍是 hint/report-only |
| CLI/TUI | 单一 `sweepx` 入口；默认终端表格，`scan --tui` 先进入界面再渐进扫描；当前层行有界保留，递归大小由 30 s deadline 的 single-flight 后台任务聚合 |
| Trash / Permanent | 单对象 Trash preview；Linux 另有 `/tmp` 隔离 preview 与有界文件/目录 Permanent preview；link/超限/跨平台 Permanent 不存在 |

CLI 与 TUI 自动检测 `zh-CN` / `en-US`，也接受显式 `--locale` 覆盖。当前 `scan` 机器输出使用 JSON，`scan --format ndjson` 仍 disabled。`cache status` 只支持 human/JSON；NDJSON 是 usage error。缺失 state/cache 返回 `absent` 且不创建目录；检查范围只限 `preview-cache/current.json`、current generation、`generations/` 与 `quarantine/` 的浅层结构和健康，不 scan、不 repair、不 quarantine，也不暴露 cache 条目或 path 内容。Linux 的 `status --watch --format ndjson` 只重放已完成且已持久化的 stream：先做一次同 snapshot 全量校验，再按每页最多 1024 条事件续读；unknown 但语法有效的 cursor 返回 `stream.reset_required`，malformed cursor/usage 返回 usage error。由于事件仍在 scan 后批量构造，它不是 live stream，不等待新事件，不创建后台 operation，也不支持 cancel。
发布基础设施会构建五个目标归档、checksum 与安装器，并发布本站到 GitHub Pages；v0.0.1 开发版本已发布，稳定版本尚未发布。


`junk --system` 的工具缓存根、浏览器/已知缓存位置发现与分类共享本次有界布局快照，版本展开和分片检查也计入共享预算，分类不再逐候选枚举或解析路径。权限、观察或资源不足时，`layoutDiscovery.complete` 为 false 并给出 `incompleteReason`，报告 partial、退出码 4；已确认的结果仍可显示，空列表不能证明没有垃圾。原生期限是调用间的合作检查，不能中断阻塞的操作系统访问。非交互清理/Trash 请求在发现前拒绝。

整根候选缓存绑定当前启用规则及发现范围，变化时重新分类；文件长度缓存独立校验，避免旧的空候选结果挡住新启用规则应发现的内容。

macOS 多根垃圾扫描的缓存发布共用一次归属分组，普通报告和垃圾 TUI 都已接入。辅助预算不足会提示并省略相应缓存更新，当前观察结果仍保留；缺少缓存事实的范围下次重新观察。嵌套根保持独立，历史预览不授权回收。

垃圾候选缓存命中后也重建当前 Git 解释；根外 ignore 配置、index 或仓库边界变化不沿用旧置信度。Git 查询只增强已有项目规则候选，不单独发现垃圾或授权删除。

## 按你的问题阅读

| 你想了解 | 页面 |
|---|---|
| 项目现在到底实现了什么 | [介绍](/guide/introduction) |
| 如何运行当前命令 | [CLI 与安全清理预览](/cli) |
| 为什么导入报告不能执行 | [安全模型](/safety) |
| Cleaner 是规则还是脚本 | [Cleaner 概念](/cleaners) |
| Agent 被允许做什么 | [Agent 边界](/agents) |
| crates 如何分层 | [架构](/architecture) |
| P3 与未来 mutation 在哪里分界 | [路线图](/roadmap) |

## 一句话结论

SweepX 已经从纯设计进入**可运行的开发预览阶段**：扫描/TUI、单对象 Trash、Linux 陈旧临时对象隔离与有界文件/目录 Permanent preview 可体验；通用 `plan`、`approve`、`execute` 和更广的 Permanent 仍是未来工作。


项目垃圾候选仍可展示、选择和刷新，但当前尚无独占所有权和活动证明，不能由 `junk --trash` 或 TUI 回收。名称、风险等级、格式和 Git ignore 都不能替代这些证明；通用 build-output 规则明确仅报告。
