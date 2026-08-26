---
title: CLI 与只读扫描
---

# CLI 与只读扫描

当前 `sweepx` 是可运行的开发版只读 CLI。它提供 `scan`、`explain`、`status`、`cancel`、`cleaner`、`tui` 和 `capabilities`；没有任何 mutation 子命令。

> [!CAUTION]
> `plan`、`approve`、`execute`、Trash、Permanent 和 `--dangerously-delete` 都不是当前 CLI。看到这些名称时，应将它们理解为路线图提案。

## 构建与查看能力

在仓库根目录运行：

```bash
cargo build -p sweepx-cli -p sweepx-tui
cargo run -p sweepx-cli -- --locale zh-CN capabilities
```

全局参数：

| 参数 | 含义 |
|---|---|
| `--format human|json|ndjson` | 选择展示或机器输出；默认 `human` |
| `--locale zh-CN|en-US` | 覆盖自动检测的语言 |
| `--state-dir ABSOLUTE_DIR` | 为 scan/status/cancel 指定 durable snapshot 目录 |

语言解析会依次考虑显式 override、locale 环境与系统 locale，无法识别时回退到 `en-US`。机器字段和值不翻译。

## Linux 只读扫描

```bash
cargo run -p sweepx-cli -- \
  --format json \
  --state-dir /absolute/path/to/sweepx-state \
  scan /absolute/path/to/root > /absolute/path/to/scan.json
```

- 可以传入多个根，但每个根都必须是绝对路径。
- 扫描同步运行，metadata-only、no-follow，并把挂载/链接/资源边界与错误写进结果。
- 当前 Linux capability 是 `degraded`，不是发布资格。
- macOS/Windows backend 目前是 unsupported stub；能编译不等于能扫描。
- `ndjson` 用于事件流，并以 terminal event 结束；这不意味着存在后台 daemon。

## 状态快照与取消

从 scan 输出取得 `operationId` 后：

```bash
cargo run -p sweepx-cli -- \
  --format json \
  --state-dir /absolute/path/to/sweepx-state \
  status --operation-id <OPERATION_ID>

cargo run -p sweepx-cli -- \
  --format json \
  --state-dir /absolute/path/to/sweepx-state \
  cancel --operation-id <OPERATION_ID>
```

`status` 只读取已持久化 snapshot。当前没有 live in-process registry，因此结果会显示 `canCancel: false`，`cancel` capability 为 `disabled`。cancel 命令存在是为了明确区分 `not_found`、`already_terminal` 或 `unsupported`，而不是伪装已经能中断同步扫描。

## 从 scan JSON 解释

```bash
cargo run -p sweepx-cli -- \
  --format json \
  explain \
  --scan-json /absolute/path/to/scan.json \
  --candidate-id <OPTIONAL_CANDIDATE_ID> \
  --max-input-bytes 8388608
```

输入必须是绝对路径、符合 `scan.result` 合同，并受 byte limit 限制。导入时 Core 会：

1. 将 provenance 改为 stale preview；
2. 将 coverage 标记为 incomplete/not revalidated；
3. 生成 explanation，但把 candidate 强制为 non-executable/report-only。

因此输出可用于理解，不可用于计划或执行。

## Cleaner 元数据

```bash
cargo run -p sweepx-cli -- --format json cleaner list
cargo run -p sweepx-cli -- --format json cleaner show org.sweepx.cargo-target
```

`list` 展示 package 与兼容性。`show` 只有在 Core 版本范围匹配时才展示完整 manifest/rules；不兼容时使用专门的兼容性错误退出。两者都不执行规则指向的文件动作。详见 [Cleaner 概念](/cleaners)。

## 有界只读 TUI

CLI 可先验证输入和分页：

```bash
cargo run -p sweepx-cli -- \
  --format json \
  tui \
  --scan-json /absolute/path/to/scan.json \
  --page-index 0 \
  --max-input-bytes 8388608 \
  --max-total-rows 100000
```

交互式界面由独立二进制提供：

```bash
cargo run -p sweepx-tui -- /absolute/path/to/scan.json --locale zh-CN
```

键位包括 `Tab` / `Shift-Tab` 切 pane，方向键或 `j`/`k` 切行，`PageUp`/`PageDown` 翻页，`q` 退出。动作类型只有 navigation，代码将其标记为 non-destructive。

## 当前不存在的命令

```text
PROPOSED ONLY — NOT IMPLEMENTED
sweepx plan create ...
sweepx plan show ...
sweepx approve ...
sweepx execute ...
sweepx execute ... --dangerously-delete
```

P3 中有对应概念的 library model 与 fake execution tests，但没有 CLI wiring，也没有 native filesystem mutation。
