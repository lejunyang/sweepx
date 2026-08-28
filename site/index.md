---
layout: home

hero:
  name: "SweepX"
  text: "先看清，再决定"
  tagline: "可运行的开发版只读磁盘分析 CLI/TUI；真实清理能力仍然不存在。"
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
    details: 导入 scan JSON 会被强制降级为 stale、incomplete 和 report-only。Cargo detector 现在能读取固定输入并投影 workspace evidence，但仍只输出 hint/report-only；查看报告或解释候选不会产生删除权限。
  - title: 破坏性路径仍封闭
    details: 当前没有 plan、approve、execute CLI，没有 native Trash/Permanent adapter，也没有任何删除目标文件的实现。
---

> [!CAUTION]
> **SweepX 目前没有清理能力。** P3 中的计划、授权、durable audit 和 executor 是 library-only 的确定性模拟；模拟器不接收 native path，只使用 sealed fake adapter。Linux 已有 bounded SQLite journal 与单事务完整流/terminal snapshot；event-journal crate 仅保留 Linux 测试专用 bounded cursor replay/reset substrate，尚未接入 Core/CLI。这些都不等于 runtime 或真实执行资格。

## 现在能做什么

| 能力 | 当前状态 |
|---|---|
| Linux 目录扫描 | development-grade、read-only、degraded |
| macOS 目录扫描 | development-grade、read-only、handle-bound degraded |
| Windows 目录扫描 | development-grade、read-only、handle-relative degraded |
| `status` | Linux journal-first 读取 terminal snapshot；macOS 读取 legacy snapshot；Windows durable state disabled、默认 `state_dir=None`，且显式 `--state-dir` fail-closed |
| `cancel` | 命令存在，但 live cancellation disabled |
| `explain` | 从有界 scan JSON 生成 report-only 解释 |
| Cleaner | 只读 list/show 元数据，带版本兼容门；`cargo-detect` 有固定输入读取和 typed evidence，但仍是 hint/report-only |
| CLI/TUI | 单一 `sweepx` 入口；默认终端表格，`scan --tui` 进入目录浏览；detail rescan 为 single-flight 后台任务，2 s deadline，导航/退出不中断 |
| Trash / Permanent | 不存在 |

CLI 与 TUI 自动检测 `zh-CN` / `en-US`，也接受显式 `--locale` 覆盖。当前 scan 机器输出使用 JSON。Linux 虽已有 durable journal substrate，但事件仍在 scan 后批量构造；live sink、runtime qualification 与公开 `status --watch`/NDJSON 尚未完成，因此 NDJSON 保持禁用。
发布基础设施会构建五个目标归档、checksum 与安装器，并发布本站到 GitHub Pages；稳定 release 尚未发布。

## 按你的问题阅读

| 你想了解 | 页面 |
|---|---|
| 项目现在到底实现了什么 | [介绍](/guide/introduction) |
| 如何运行当前只读命令 | [CLI 与只读扫描](/cli) |
| 为什么导入报告不能执行 | [安全模型](/safety) |
| Cleaner 是规则还是脚本 | [Cleaner 概念](/cleaners) |
| Agent 被允许做什么 | [Agent 边界](/agents) |
| crates 如何分层 | [架构](/architecture) |
| P3 与未来 mutation 在哪里分界 | [路线图](/roadmap) |

## 一句话结论

SweepX 已经从纯设计进入**可运行的只读开发阶段**，但还没有进入真实清理阶段。任何 `plan`、`approve`、`execute`、Trash 或 Permanent 说明都只能是未来提案，不能当成当前命令。
