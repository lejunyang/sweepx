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
    details: 导入 scan JSON 会被强制降级为 stale、incomplete 和 report-only。`cache status` 也只是 preview cache 的只读诊断；`available` 只表示缓存结构/校验可读，不代表 live/current 文件事实。
  - title: 破坏性路径仍封闭
    details: 当前没有 plan、approve、execute CLI，没有 native Trash/Permanent adapter，也没有任何删除目标文件的实现。
---

> [!CAUTION]
> **SweepX 目前没有清理能力。** P3 中的计划、授权、durable audit 和 executor 是 library-only 的确定性模拟；模拟器不接收 native path，只使用 sealed fake adapter。Linux 已有 bounded SQLite journal、单事务完整流/terminal snapshot，以及对已完成且已持久化 journal stream 的 degraded `status --watch` completed replay；但它仍是 non-live、非 runtime-qualified，也不代表真实执行资格。

## 现在能做什么

| 能力 | 当前状态 |
|---|---|
| Linux 目录扫描 | development-grade、read-only、degraded |
| macOS 目录扫描 | development-grade、read-only、handle-bound degraded |
| Windows 目录扫描 | development-grade、read-only、handle-relative degraded |
| `status` | Linux journal-first 读取 terminal snapshot，并支持 degraded 的 `sweepx --format ndjson status --operation-id ID --watch [--after SXCUR1]` completed replay；macOS 读取 legacy snapshot；Windows durable state disabled、默认 `state_dir=None`，且显式 `--state-dir` fail-closed |
| `cancel` | 命令存在，但 live cancellation disabled |
| `explain` | 从有界 scan JSON 生成 report-only 解释 |
| `cache status` | Linux/macOS：preview cache 只读诊断；Windows：disabled |
| Cleaner | 只读 list/show 元数据，带版本兼容门；`cargo-detect` 有固定输入读取和 typed evidence，但仍是 hint/report-only |
| CLI/TUI | 单一 `sweepx` 入口；默认终端表格，`scan --tui` 进入目录浏览；detail rescan 为 single-flight 后台任务，2 s deadline，导航/退出不中断 |
| Trash / Permanent | 不存在 |

CLI 与 TUI 自动检测 `zh-CN` / `en-US`，也接受显式 `--locale` 覆盖。当前 `scan` 机器输出使用 JSON，`scan --format ndjson` 仍 disabled。`cache status` 只支持 human/JSON；NDJSON 是 usage error。缺失 state/cache 返回 `absent` 且不创建目录；检查范围只限 `preview-cache/current.json`、current generation、`generations/` 与 `quarantine/` 的浅层结构和健康，不 scan、不 repair、不 quarantine，也不暴露 cache 条目或 path 内容。Linux 的 `status --watch --format ndjson` 只重放已完成且已持久化的 stream：先做一次同 snapshot 全量校验，再按每页最多 1024 条事件续读；unknown 但语法有效的 cursor 返回 `stream.reset_required`，malformed cursor/usage 返回 usage error。由于事件仍在 scan 后批量构造，它不是 live stream，不等待新事件，不创建后台 operation，也不支持 cancel。
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
