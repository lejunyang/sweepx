---
title: CLI 与只读扫描
---

# CLI 与只读扫描

当前 `sweepx` 是唯一的可执行入口。它提供 `scan`、`explain`、`status`、`cancel`、`cleaner` 和 `capabilities`；`scan --tui` 在扫描完成后进入交互浏览，没有独立的 TUI 命令或二进制，也没有任何 mutation 子命令。

> [!CAUTION]
> `plan`、`approve`、`execute`、Trash、Permanent 和 `--dangerously-delete` 都不是当前 CLI。看到这些名称时，应将它们理解为路线图提案。

## 构建与查看能力

在仓库根目录运行：

```bash
cargo build -p sweepx-cli
cargo run -p sweepx-cli -- --locale zh-CN capabilities
```

全局参数：

| 参数 | 含义 |
|---|---|
| `--format human|json|ndjson` | 选择展示或机器输出；默认 `human` |
| `--locale zh-CN|en-US` | 覆盖自动检测的语言 |
| `--state-dir ABSOLUTE_DIR` | 为 scan/status/cancel 指定 durable snapshot 目录 |

语言解析会依次考虑显式 override、locale 环境与系统 locale，无法识别时回退到 `en-US`。机器字段和值不翻译。

## 安装

正式 release 会为 Linux x86_64/aarch64、macOS Intel/Apple Silicon 和 Windows x86_64 生成归档和统一 `SHA256SUMS`。安装器会校验 checksum，并要求归档内只有根级 `sweepx` 或 `sweepx.exe`。

```bash
curl --proto '=https' --tlsv1.2 -fsSL \
  https://raw.githubusercontent.com/lejunyang/sweepx/main/install.sh | sh
```

```powershell
irm https://raw.githubusercontent.com/lejunyang/sweepx/main/install.ps1 | iex
```

目前有发布基础设施不代表已经发布稳定版本；安装前应核对 GitHub Release 和 `sweepx capabilities`。

普通 push/PR 会运行 Rust、schema、站点、安装器和 native CLI CI；GitHub Pages 在 `main` 更新时独立部署。只有 HEAD commit message 含字面量 `[publish]` 时，二进制与 crates.io 发布任务才运行。GitHub Release 和 Pages 不需要额外 token；crates.io 需要在受保护的 `crates-io` environment 中配置 `CARGO_REGISTRY_TOKEN`。

## Linux 只读扫描

```bash
cargo run -p sweepx-cli -- \
  --state-dir /absolute/path/to/sweepx-state \
  scan /absolute/path/to/root
```

- 可以传入多个根，但每个根都必须是绝对路径。
- 默认直接向终端输出有界的 40 行文件表；不要求 JSON 文件。
- 扫描同步运行，metadata-only、no-follow，并把挂载/链接/资源边界与错误写进结果。
- 当前 Linux capability 是 `degraded`，不是发布资格。
- macOS/Windows backend 目前是 unsupported stub；能编译不等于能扫描。
- `ndjson` 用于事件流，并以 terminal event 结束；这不意味着存在后台 daemon。

只有脚本和系统集成才需要显式机器输出：

```bash
sweepx --format json scan /absolute/path/to/root > scan.json
sweepx --format ndjson scan /absolute/path/to/root > events.ndjson
```

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

## 文件管理器式只读 TUI

```bash
cargo run -p sweepx-cli -- --locale zh-CN \
  scan --tui /absolute/path/to/root [/another/absolute/root]
```

TUI 直接消费本次 live scan 的 typed 结果，不要求中间 JSON。初始层展示一个或多个虚拟根；`Enter` / `Right` / `l` 进入目录，`Esc` / `Backspace` / `Left` / `h` 返回，方向键或 `j`/`k` 移动，`q` 或 `Ctrl-C` 退出。symlink 和 reparse point 只显示而不可进入。

`--tui` 要求 stdin/stdout 都是终端，并且不能与 `--format json|ndjson` 组合。这些条件会在创建 state 或开始扫描之前校验。终端输出中的不可信控制字符会被替换，不会原样解释为 ANSI 序列。

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
