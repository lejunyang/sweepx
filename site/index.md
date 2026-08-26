---
layout: home

hero:
  name: "SweepX"
  text: "安全优先的磁盘分析与清理设计快照"
  tagline: "当前仅提供研究与接口设计，不提供可运行的扫描、回收站或永久删除能力。破坏性功能仍在开发和资格验证中。"
  image:
    src: /mark.svg
    alt: SweepX
  actions:
    - theme: brand
      text: 阅读介绍
      link: /guide/introduction
    - theme: alt
      text: 查看安全边界
      link: /safety
    - theme: alt
      text: English
      link: /en/

features:
  - title: 当前状态必须诚实
    details: SweepX 现在是设计与研究快照，不是已发布产品。站点只描述未来实现应满足的约束，不暗示已有删除能力。
  - title: 破坏性路径默认不可用
    details: 回收站与永久删除都属于受约束能力。当前实现未发布、未验证、未取得资格，任何 destructive workflow 都不应被视作可执行。
  - title: 双语文档同步表达
    details: 中文为默认入口，英文位于 /en/。两套页面都保持相同的安全立场、CLI 草案和阶段路线图，避免信息漂移。
---

> [!WARNING]
> **SweepX 仍在开发中。** 当前仓库没有可运行的 SweepX CLI/TUI，也没有已发布的清理执行路径。任何可能改变文件状态的能力都属于未实现、未验证或尚未取得资格的功能。

## 设计目标

SweepX 试图把“发现了什么”“为什么可能可回收”“谁在本地显式授权”“系统实际做了什么”拆成独立阶段，而不是把扫描结果直接变成删除动作。

这份站点聚焦三个承诺：

- 所有文案都以“设计约束”而不是“现有能力”来表达。
- 安全边界优先于功能覆盖或速度叙事。
- 双语页面都明确说明 destructive features 目前 unavailable / unqualified。

## 你会在这里看到什么

| 页面 | 内容 |
|---|---|
| 介绍 | 产品定位、当前状态、为何它仍然只是设计快照 |
| 安全边界 | 不可谈判的普通用户边界、计划绑定和失败关闭原则 |
| CLI 草案 | 未来命令面如何表达 scan、plan、approve、execute |
| 架构 | 只读扫描、解释、不可变计划和授权分离的系统结构 |
| 路线图 | P0 到 P6 的阶段演进，以及哪些能力尚未进入发布范围 |

## 核心结论

SweepX 的方向不是“更激进地删”，而是“更保守地证明为什么现在还不能删”。在发布前：

- 当前实现仍处于 under development。
- destructive features are unavailable。
- Permanent 模式没有资格声明，不可视作已设计完成即可上线的能力。
