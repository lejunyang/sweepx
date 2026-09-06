---
title: Cleaner 概念
---

# Cleaner 概念

Cleaner 是带版本、证据和兼容约束的领域规则包，不是任意 shell script，也不是当前可执行的清理插件。

## 当前内置内容

仓库包含两个示例 package：

| Cleaner ID | 描述 | 当前命令面 |
|---|---|---|
| `org.sweepx.cargo-target` | Cargo workspace 的 target build output | metadata/report-only |
| `org.sweepx.chromium-rebuildable-cache` | Chromium HTTP 与 Code Cache，并与应用状态分离 | metadata/report-only |

package 包含 manifest、规则和 evidence 文档。规则由受限、声明式 VM 表达；当前 CLI 不让它执行 I/O、外部命令或 native mutation。

## `list` 与 `show` 的差异

```bash
cargo run -p sweepx-cli -- --format json cleaner list
cargo run -p sweepx-cli -- --format json cleaner show <CLEANER_REF>
```

- `list` 总结所有内置 package，并逐项报告 `compatible` / `incompatible` 和 `reportOnly`。
- `show` 可接受 `id` 或 `id@version`，但在当前 Core 不满足 `requires.core` 时以兼容性错误失败。
- 兼容性门不能通过 flag 绕过，也不会因为 list 能看到 package 就让它变成 executable。

两个内置 manifest 要求 `>=0.1.0, <0.2.0`，当前 Core `0.1.0` 满足该范围，因此 list 返回 `ok` 且没有不兼容包，show 也能成功。若某个 manifest 的范围排除了正在运行的 Core，它仍会被诚实标记为 `incompatible` 并被 show 拒绝——兼容性闸门依然生效，只是随包发布的清单不会触发它。

## `cargo-detect` 的当前边界

`org.sweepx.cargo-target` 现在除了 metadata 之外，还接入了实验性的 `cleaner cargo-detect` 只读检测面：

- Scanner 新增了有界 locator batch reader，可沿已 admission 的 locator 做固定文件读取；三平台 backend 都走同一有界 contract。
- workspace 固定输入收集器只读取 `Cargo.toml`、`.cargo/config` 和 `.cargo/config.toml`，并对替换、symlink/reparse、mount 变化、资源上限和取消 fail closed。
- manifest 绑定成立时，workspace typed evidence 可以是 `known`。
- `data.hints[].evidence.cargo.configScope` 现在公开 `cargo.config-scope.v1` wire contract：顶层字段为 `schema`、`decoderId`、`workspace`、`ancestorConfigs`、`cargoHomeConfig`、`environment`、`cli`、`invocationCwd`、`precedenceComplete`、`blockers[]`。
- `workspace.pairSnapshot` 的状态是 `stable_snapshot|not_checked|failed`；`workspace.config` / `workspace.configToml` 的合同枚举是 `present|verified_absent|not_checked|failed`，但当前生产路径在 pair 非稳定时会把时间点式 absence 降为 `not_checked`；`workspace.selected` 是 `config|config_toml|none|not_checked`；`workspace.targetDirDeclaration` 是 `known|verified_absent|not_checked|unknown`。
- `environment` 只记录 `CARGO_TARGET_DIR`、`CARGO_BUILD_TARGET_DIR`、`CARGO_HOME` 的存在性：状态只有 `present_redacted|verified_absent`。`valueRedacted` 字段始终存在，前者为 `true`、后者为 `false`；不保留也不序列化任何值。
- workspace config 中的 `build.target-dir` 同样只暴露脱敏声明：`targetDirDeclaration.state=known` 时只返回 `source=config|config_toml` 和 `valueRedacted=true`，不返回原始相对路径值。
- 只有显式设置且为绝对路径的 `CARGO_HOME` 会在 Cleaner compatibility gate 通过后被私下捕获，并在 scan 后重验。collector 只观察该 home 根下直属 `config` / `config.toml` 是否存在：命中仅投影 `cargoHomeConfig.state=present_redacted`，观察仍是 non-atomic；未命中以及未显式设置、使用默认 home 的情况保持 `not_checked`，不能提升为 `verified_absent`。scanner 对命中的直属文件只做有界、no-follow、handle-bound metadata inspection；配置内容不会被读取、解析、使用或序列化，`target-dir` 值也不会被提取，环境值与 home/config 路径同样不会进入输出。
- SweepX 的 `cargo-detect` CLI surface 没有 Cargo passthrough `--target-dir` 或 `--config`，因此该入口把 `cli.targetDir` 与 `cli.configOverrides` 记为结构性 `verified_absent`；普通 Core 调用默认保持 `not_checked`，只有显式采用 no-overrides invocation contract 才能作同样声明。
- process cwd 只会在 Cleaner compatibility gate 通过后私下捕获并记录 capture-time identity；随后只与重验后的 workspace root 比较精确 native path 和 identity。匹配时仅投影 `path_matches_revalidated_workspace_root`，且因未跨阶段持有 cwd handle 而保留 `invocation_cwd_identity_not_bound` blocker；cwd path 本身不会被序列化到结果里。
- `blockers[]` 是排序去重后的稳定字符串词表；显式 Cargo-home config 命中使用 `cargo_home_config_present_redacted`，而未检查/读取失败分别使用 `cargo_home_config_not_checked|cargo_home_config_failed`。其他 blocker 继续覆盖 ancestor configs、环境 override、CLI、invocation cwd 和 workspace config 的未闭合状态。
- `.cargo/config` 与 `.cargo/config.toml` 现在通过同一个 retained `.cargo` handle 和单个有界枚举 cursor 观察；ASCII 大小写 alias 与重复项会失败关闭。但目录枚举不能排除并发 ABA，因此该结果仍是 non-atomic：未观察到的成员保持 `not_checked`，不能提升为 `verified_absent` 或稳定选择。
- Cargo-home presence ledger 仅使用有界、no-follow、handle-bound 的 metadata inspection；配置内容不会被读取、解析、使用或序列化。ancestor configs 与 workspace pair 也仍未解决，因此当前 `precedenceComplete=false`，`targetDir` 继续是 `not_checked(config_scope_not_checked)`，`targetShape` 继续是 `unknown(config_scope_not_checked)`。
- Core 库调用方可以使用 `cleaner_cargo_detect_with_cancel(..., &CancellationToken)` 协作取消 scan 之后的 fixed-input/evidence collection。该 token 不归属同步 filesystem scan；同步 scan 使用独立的内部 token，因此在 scan 期间触发 caller-owned token 只会在 post-scan collection 开始时被观察。
- 若 collection 观察到取消，相关 typed evidence 失败关闭为 `unknown(cancelled)`，terminal envelope 使用 `status=cancelled`、exit 10 和 `reasonCode=cancelled`。取消不会把已有 observation 提升为 candidate，也不授予 plan、approval、execution 或 mutation authority。
- 当前 CLI 只创建未连接到信号的本地 token；没有 Ctrl-C handler，`sweepx cancel` 也没有与它或 live in-process operation registry 接线。因此 caller-owned token 是 library integration seam，不是当前用户可触发的 CLI 取消能力。
- 结果仍然只有 `hint` / `report-only`：不会生成 candidate，也不会开放 plan、approval 或 execution；顶层 `candidateAllowed`、`planAllowed`、`approvalAllowed`、`executionAllowed` 继续全为 `false`。

## 规则输出不等于清理动作

规则评估可以表达 known/unknown、证据、风险和 report-only，但不能：

- 生成未由扫描证据支持的裸路径；
- 降低未知项的风险；
- 执行 Cargo、浏览器或操作系统命令；
- 删除、移动或回收文件；
- 创建 plan、authorization 或 permit。

即使未来 Cleaner 能生成候选，导入 scan JSON 的 stale/incomplete provenance 仍强制候选 non-executable。

## 未来资格门

Cleaner 从“能描述”走到“能参与执行”至少需要 package canonicalization、签名与撤销、Core/version compatibility、规则确定性、平台与应用版本证据、reference/activity/recovery fixtures、完整 live identity 与通用 Safety Core 的计划/授权流程。当前这些门没有全部完成，因此文档只承诺 metadata/report-only。
