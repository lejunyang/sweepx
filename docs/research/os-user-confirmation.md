# SweepX 系统级用户确认能力研究

状态：设计输入，截点 2026-08-26。本文讨论普通用户进程在永久删除前如何请求本机用户确认；它不授予文件访问权限，也不改变 SweepX v1 的“不提权”边界。

## 1. 结论

三平台没有一个完全一致、同时满足“原生 UI、重新验证当前用户、对任意 SweepX 计划摘要做密码学签名”的通用 API。因此设计必须拆开三件事：

1. **计划审阅**：SweepX 第一方原生窗口或可信 foreground TTY 展示 exact immutable plan。
2. **用户重新验证**：Windows/macOS 可选调用系统 UI；Linux 没有可作为共同基线的统一对应物。
3. **计划绑定**：始终由 Broker/Core 对完整 256-bit plan digest、pending request、user/host/session、TTL 和 single-use nonce 做封存与复核。

原生按钮、手输短串或一次 Windows Hello/Touch ID 成功都不能单独证明用户读懂了某个计划。它们是确认证据；完整 plan binding 仍在 Core。

## 2. 平台矩阵

| 平台能力 | 能证明什么 | 是否提权 | 是否天然绑定任意 plan digest | SweepX 用法 |
|---|---|---:|---:|---|
| Windows `UserConsentVerifier` / desktop `IUserConsentVerifierInterop` | 配置的 Windows Hello、PIN、生物识别等验证器当时返回 `Verified` | 否 | 否；message 只是展示文本 | 可选的 fresh user reauthentication；要求本地图形会话和 owner HWND |
| Windows Hello app-specific `KeyCredential.RequestSignAsync` | 受 Windows Hello 保护、应用专属且私钥不可导出的 key 对 challenge 签名 | 否 | 可以，前提是 canonical challenge 含完整 digest/nonce/purpose/expiry 且正确管理 key lifecycle | 后续可选高保证 profile；不是 v1 基线 |
| Windows UAC / `runas` | 同意创建 elevated token 或输入管理员凭据 | **是** | 否；提示针对 executable/elevation | 不得仅为确认普通用户删除而调用 |
| Windows `TaskDialogIndirect` | 本桌面上有人或自动化点击了按钮 | 否 | 否 | 可作为第一方原生 review UI，但不是身份认证 |
| macOS `LAContext.evaluatePolicy(.deviceOwnerAuthentication)` | 设备所有者通过 Touch ID、Apple Watch 或账号密码等允许的机制完成验证 | 否 | 否；`localizedReason` 只是说明 | 可选 fresh user reauthentication；要求登录的 GUI session |
| macOS user-presence protected Keychain/Secure Enclave key | 受访问控制的 app key 在满足 user-presence 后完成私钥操作 | 否 | 可以，把完整 canonical challenge 作为签名输入 | 后续可选高保证 profile；需单独设计 key enrollment/recovery |
| macOS Authorization Services | 根据 policy 授予 named right，凭据可能缓存 | 常用于受限/privileged 工作流 | 不天然绑定任意 plan bytes | 不得仅为普通文件确认而引入 |
| macOS `NSAlert` | 本桌面上有人或自动化点击了按钮 | 否 | 否 | 可作为第一方原生 review UI，但不是身份认证 |
| Linux polkit | 某 subject/process 被 policy 授权某个已注册 action；可能通过 agent 验证用户或管理员 | 面向 privileged mechanism/系统 policy | 没有可移植的任意 digest 签名保证 | v1 不为确认而安装 policy、请求 polkit 或提权 |
| Linux 本地 GUI / foreground TTY | 本地交互 surface 收到按钮选择或 challenge | 否 | 否 | 共同基线；没有 GUI/可信 TTY 则 HumanApproval 不可用 |

## 3. 推荐审批流程

`sweepx approve --plan-id ID` 依次选择：

1. 已验证 executable/IPC peer 的第一方 native `ApprovalSurface`；
2. 无合格 GUI 时，可信本地 foreground TTY；
3. 两者都不可用时返回 `APPROVAL_INTERACTIVE_HUMAN_REQUIRED`，不提供 stdin/RPC/环境变量 fallback。

原生 Permanent modal 应显示：

- “永久删除 N 个选中项”，另列 M 个底层 filesystem actions；
- 精确路径/类型/逐项风险、unknown/coverage、恢复与重建影响；
- “绕过回收站，但不是 secure erase”；
- 只读 `SX1-...` fingerprint 和过期时间；
- 未勾选“我理解这些项目将绕过回收站”前禁用 destructive button，Cancel 为默认焦点。

审批点击与真正执行保持两个步骤。窗口打开期间 plan、policy、session 或 digest 发生变化必须拒绝；Broker 只接受该 pending request 的 decision，重新读取 plan 并比较完整 digest 后才封存一次性 `ApprovalRecord`。

Windows/macOS 可在 destructive decision 后请求系统重新验证。取消、不可用、session 切换或返回异常都必须按声明的 policy 显式失败或降级，不能悄悄记为 verified。系统 API 的普通布尔成功不对 prompt text 做签名，所以不能取代上述完整 digest 检查。

## 4. 终端 challenge 的含义

无原生窗口时，Broker 从 immutable plan 自动生成：

```text
PERMANENT <selected-item-count> <underlying-action-count> <SX1-plan-fingerprint>
```

fingerprint 是 `SX1-` 加 domain-separated canonical plan SHA-256 的前 12 个大写 hex；它只用于人工对照和降低误操作。授权校验从不依赖 48-bit 前缀，而是依赖 sealed record 内完整 256-bit digest。challenge 不证明输入者一定是人、已理解后果或对象安全；它也不提供 TTL、anti-replay 或 single-use，这些都由 Broker/Core 提供。

## 5. 与危险参数和 Agent 的关系

`execute --plan-id ID --dangerously-delete` 明确跳过 native dialog、OS reauthentication 和 terminal challenge，只为已有 Permanent R4 plan 生成另一类可审计授权。它仍不能改 target/mode、绕过实时复验或硬保护。

AI Skill 不得运行 `approve`、打开/操控原生 helper、点击按钮、响应系统认证、输入 terminal challenge，或使用 `--dangerously-delete`。

## 6. 官方资料

访问日期均为 2026-08-26：

- Microsoft: [`UserConsentVerifier.RequestVerificationAsync`](https://learn.microsoft.com/en-us/uwp/api/windows.security.credentials.ui.userconsentverifier.requestverificationasync)、[`IUserConsentVerifierInterop::RequestVerificationForWindowAsync`](https://learn.microsoft.com/en-us/windows/win32/api/userconsentverifierinterop/nf-userconsentverifierinterop-iuserconsentverifierinterop-requestverificationforwindowasync)、[Windows Hello / `KeyCredential.RequestSignAsync`](https://learn.microsoft.com/en-us/windows/apps/develop/security/windows-hello)、[UAC 工作方式](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/user-account-control/how-it-works)、[`TaskDialogIndirect`](https://learn.microsoft.com/en-us/windows/win32/api/commctrl/nf-commctrl-taskdialogindirect)。
- Apple: [Local Authentication](https://developer.apple.com/documentation/localauthentication)、[`LAContext.evaluatePolicy`](https://developer.apple.com/documentation/localauthentication/lacontext/evaluatepolicy(_:localizedreason:reply:))、[受 Face ID/Touch ID 保护的 Keychain item](https://developer.apple.com/documentation/localauthentication/accessing-keychain-items-with-face-id-or-touch-id)、[Authorization Services](https://developer.apple.com/documentation/security/authorization-services)、[`NSAlert`](https://developer.apple.com/documentation/appkit/nsalert)。
- freedesktop/polkit: [polkit 架构](https://polkit.pages.freedesktop.org/polkit/polkit.8.html)、[`Authority.CheckAuthorization`](https://polkit.pages.freedesktop.org/polkit/eggdbus-interface-org.freedesktop.PolicyKit1.Authority.html)、[`pkttyagent`](https://polkit.pages.freedesktop.org/polkit/pkttyagent.1.html)。
