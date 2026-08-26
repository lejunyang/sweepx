---
title: 介绍
---

# 介绍

SweepX 是一个安全优先的 Rust 磁盘分析项目。当前仓库已经有可运行的开发版只读 CLI/TUI，而不是只有设计文档；与此同时，它没有任何真实清理能力。

> [!WARNING]
> “可运行”只适用于只读或模拟表面。没有 native Trash、Permanent、`plan`、`approve` 或 `execute` CLI，也没有删除或移动目标文件的 adapter。

## 当前状态

- Linux scanner 能在用户明确选择的绝对路径上做同步、只读扫描，能力状态为 `degraded`。
- macOS 和 Windows scanner 仍是 compilation-only stub，live scan 返回 `unsupported`。
- `status` 读取已持久化的终态 snapshot；`cancel` 因没有 live operation registry 而标记为 `disabled`。
- `explain` 从有界 `scan.result` JSON 生成解释，但导入数据被降级为 stale/incomplete，候选只能 report-only。
- 内置 Cleaner 支持 metadata-only 的 list/show，并在 core 版本不兼容时失败关闭。
- CLI 的 `tui` 子命令校验并摘要有界输入；`sweepx-tui` 提供只读的分页、pane 和行导航。
- P3 已实现 immutable plan、simulation-only authorization、Unix audit/recovery 和 sealed deterministic simulated executor，但只有 library API；没有可信 HumanApproval broker。

这些是代码和测试覆盖到的开发能力，不是安装包、生产支持或三平台资格声明。

## 产品定位

SweepX 位于通用磁盘分析器与应用专用 Cleaner 之间：

- Scanner 回答“当前能看见的空间在哪里”，同时保留权限错误、链接、挂载边界和大小不确定性。
- Analyzer 将事实、推导、启发式与未知项分开，而不是把目录年龄或名字当作“可安全删除”的证明。
- Cleaner 用版本化 manifest 和声明式规则描述领域知识；当前只展示元数据，不执行脚本。
- CLI、TUI 与未来 Agent workflow 共用同一 Core 合同，不给某个表面额外 mutation 权限。

## 为什么强调 development-grade

`degraded`、`qualified`、`report_only`、`unsupported` 与 `disabled` 是能力单元的状态，不是营销等级。比如：

- Linux scan 已实现，但还没有满足路线图中的全部基准、故障注入和跨平台发布门槛；
- explain/TUI 在合同测试覆盖内可用，不代表导入 JSON 可成为 live execution evidence；
- Cleaner metadata 可读取，不代表 Cleaner 可运行；
- P3 fake executor 的测试不证明任何真实文件系统 adapter。

## 推荐阅读顺序

1. [CLI 与只读扫描](/cli)：运行当前存在的命令。
2. [安全模型](/safety)：理解 imported/report-only 和 mutation 边界。
3. [Cleaner 概念](/cleaners) 与 [Agent 边界](/agents)：理解两个容易被误读的扩展面。
4. [架构](/architecture) 与 [路线图](/roadmap)：查看 crate 分层和下一阶段门槛。
