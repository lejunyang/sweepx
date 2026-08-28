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

当前 Core 是 `0.1.0`，两个内置 manifest 要求 `>=1.0.0, <2.0.0`，所以 list 会诚实返回 partial，而 show 失败关闭。这是期望状态。

## `cargo-detect` 的当前边界

`org.sweepx.cargo-target` 现在除了 metadata 之外，还接入了实验性的 `cleaner cargo-detect` 只读检测面：

- Scanner 新增了有界 locator batch reader，可沿已 admission 的 locator 做固定文件读取；三平台 backend 都走同一有界 contract。
- Cargo 固定输入收集器只读取 `Cargo.toml`、`.cargo/config` 和 `.cargo/config.toml`，并对替换、symlink/reparse、mount 变化、资源上限和取消 fail closed。
- manifest 绑定成立时，workspace typed evidence 可以是 `known`。
- `data.hints[].evidence.cargo.configScope` 现在公开 `cargo.config-scope.v1` wire contract：顶层字段为 `schema`、`decoderId`、`workspace`、`ancestorConfigs`、`cargoHomeConfig`、`environment`、`cli`、`invocationCwd`、`precedenceComplete`、`blockers[]`。
- `workspace.pairSnapshot` 的状态是 `stable_snapshot|not_checked|failed`；`workspace.config` / `workspace.configToml` 的合同枚举是 `present|verified_absent|not_checked|failed`，但当前生产路径在 pair 非稳定时会把时间点式 absence 降为 `not_checked`；`workspace.selected` 是 `config|config_toml|none|not_checked`；`workspace.targetDirDeclaration` 是 `known|verified_absent|not_checked|unknown`。
- `environment` 只记录 `CARGO_TARGET_DIR`、`CARGO_BUILD_TARGET_DIR`、`CARGO_HOME` 的存在性：状态只有 `present_redacted|verified_absent`。`valueRedacted` 字段始终存在，前者为 `true`、后者为 `false`；不保留也不序列化任何值。
- workspace config 中的 `build.target-dir` 同样只暴露脱敏声明：`targetDirDeclaration.state=known` 时只返回 `source=config|config_toml` 和 `valueRedacted=true`，不返回原始相对路径值。
- `blockers[]` 是排序去重后的稳定字符串词表。当前实现会公开 `ancestor_configs_failed|ancestor_configs_not_checked|cargo_build_target_dir_present_redacted|cargo_home_config_failed|cargo_home_config_not_checked|cargo_home_present_redacted|cargo_target_dir_present_redacted|cli_config_overrides_failed|cli_config_overrides_not_checked|cli_target_dir_failed|cli_target_dir_not_checked|invocation_cwd_binding_failed|invocation_cwd_not_bound|workspace_config_duplicate_key|workspace_config_include_unsupported|workspace_config_malformed|workspace_config_not_checked|workspace_config_pair_failed|workspace_config_pair_not_stable|workspace_config_read_failed|workspace_config_resource_limit|workspace_config_shape_unsupported|workspace_target_dir_invalid`。
- `.cargo/config` 与 `.cargo/config.toml` 现在通过同一个 retained `.cargo` handle 和单个有界枚举 cursor 观察；ASCII 大小写 alias 与重复项会失败关闭。但目录枚举不能排除并发 ABA，因此该结果仍是 non-atomic：未观察到的成员保持 `not_checked`，不能提升为 `verified_absent` 或稳定选择。
- 因此当前 `precedenceComplete=false`。home/env/ancestor/CLI/cwd 的 precedence source 仍未闭合，`targetDir` 继续是 `not_checked(config_scope_not_checked)`，`targetShape` 继续是 `unknown(config_scope_not_checked)`。
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
