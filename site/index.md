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
    details: Linux 上已有 degraded 的开发版扫描器；默认终端表格和 `scan --tui` 文件管理器可运行。macOS/Windows 扫描仍是 unsupported stub。
  - title: 证据不会变成授权
    details: 导入 scan JSON 会被强制降级为 stale、incomplete 和 report-only。查看报告或解释候选不会产生删除权限；live TUI 同样只有导航能力。
  - title: 破坏性路径仍封闭
    details: 当前没有 plan、approve、execute CLI，没有 native Trash/Permanent adapter，也没有任何删除目标文件的实现。
---

> [!CAUTION]
> **SweepX 目前没有清理能力。** P3 中的计划、授权、durable audit 和 executor 是 library-only 的确定性模拟；模拟器不接收 native path，只使用 sealed fake adapter。

## 现在能做什么

| 能力 | 当前状态 |
|---|---|
| Linux 目录扫描 | development-grade、read-only、degraded |
| macOS / Windows 扫描 | unsupported compilation stub |
| `status` | 读取持久化的终态 snapshot |
| `cancel` | 命令存在，但 live cancellation disabled |
| `explain` | 从有界 scan JSON 生成 report-only 解释 |
| Cleaner | 只读 list/show 元数据，带版本兼容门 |
| CLI/TUI | 单一 `sweepx` 入口；默认终端表格，`scan --tui` 进入目录浏览 |
| Trash / Permanent | 不存在 |

CLI 与 TUI 自动检测 `zh-CN` / `en-US`，也接受显式 `--locale` 覆盖。JSON/NDJSON 的机器字段不会因语言变化。
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
