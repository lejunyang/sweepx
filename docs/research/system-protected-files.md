# 系统关键文件与不可删除对象研究

研究日期与网络来源访问日期：**2026-08-26**。本文回答“扫描到一个很大的系统文件时，SweepX 应怎样识别、解释并硬阻断删除”。它不授权修改分页、休眠、转储、挂载或内核配置。

## 目录

- [1. 结论](#_1-结论)
- [2. 统一识别原则](#_2-统一识别原则)
- [3. Windows](#_3-windows)
- [4. macOS](#_4-macos)
- [5. Linux](#_5-linux)
- [6. 用户提示与规则模型](#_6-用户提示与规则模型)
- [7. 官方来源](#_7-官方来源)

## 1. 结论

1. **系统关键对象不能靠 basename 单独判定。** `pagefile.sys` 等名称只有结合当前系统卷、OS 配置、文件属性和运行时枚举才构成强证据；同名普通文件不能冒充系统对象，系统对象也可能被配置到非默认位置。
2. **活跃内存后备、休眠后备、专用崩溃转储后备、内核/设备/固件接口和系统卷是 BLOCKED。** `--dangerously-delete`、Permanent plan、提权环境或插件都不得改变这一结论。
3. **完成后的 crash dump 与活跃 dump backing file 不同。** `Memory.dmp`/minidump 是高价值诊断数据，默认 R3/report-only，可由未来专项规则在明确 retention/support 条件后处理；它不是因为名称而成为“运行必需文件”。
4. **配置改变必须交给操作系统。** 例如关闭 Windows hibernation 应使用 Windows 支持的 `powercfg /HIBERNATE` 流程；SweepX 不通过删除 `hiberfil.sys` 模拟配置变更。
5. **Linux 必须按当前 mount namespace 解析。** `/proc/self/mountinfo` 与 `/proc/swaps` 比写死 `/proc`、`/sys` 或某个 swap 路径更接近真实语义。

## 2. 统一识别原则

系统保护器产生 `ProtectedIdentity`，而不是 Cleaner Candidate：

```text
ProtectedIdentity {
  platform, class, source_api, observed_at,
  object_or_mount_identity, configured_native_path?,
  evidence[], explanation_key, protection=BLOCKED
}
```

识别顺序：

1. 从 OS 支持的运行时接口/配置读取对象或 mount；
2. 展开 OS 变量并取得 no-follow parent/object/mount identity；
3. 用系统卷、APFS role、mount fs type、active swap 列表等语义交叉确认；
4. 将 identity 与真实祖先加入不可变 protected-anchor snapshot；
5. 计划和每次 preflight 都按 identity/mount 复查。无法读取来源或发生竞态时，相关范围 BLOCKED，而不是“未发现”。

## 3. Windows

| 对象 | 动态识别 | 给用户的解释 | SweepX 行为 |
|---|---|---|---|
| 活跃 page file | 用 `Win32_PageFileUsage` 枚举运行时 page file；`Win32_PageFileSetting` 只表示启动配置。必要时读取 `Memory Management\PagingFiles` / `ExistingPageFiles`，不假设只有 `C:\pagefile.sys` | Windows 正用它承载 committed virtual memory，也可能依赖它生成 crash dump | `system.windows.active-pagefile`，BLOCKED；不能 unlink/truncate/Trash，也不代改 page-file 配置 |
| `swapfile.sys` | 由 `Win32_OperatingSystem.SystemDrive` 定位当前系统卷，结合根级 exact basename 与 hidden/system 属性；basename 本身不是充分证据 | Windows Memory Manager 管理的 suspended-app swap store，不是普通 cache | `system.windows.swapfile`，强证据命中即 BLOCKED；公开资料没有稳定的独立管理 API，不猜测清理方式 |
| `hiberfil.sys` | 动态解析 OS/System drive，再匹配根级 hidden/system 对象；`powercfg /AVAILABLESLEEPSTATES` 只用于说明当前能力 | Windows 用它保存 hibernation/hybrid-sleep 所需的系统内存状态 | `system.windows.hibernation-file`，BLOCKED；如用户要释放空间，仅报告受支持的 `powercfg /HIBERNATE` 配置路径及副作用，不执行删文件 |
| Dedicated dump backing file | 从 `HKLM\SYSTEM\CurrentControlSet\Control\CrashControl\DedicatedDumpFile` 读取并展开路径，不假设文件名或盘符 | Windows 为未来系统崩溃转储保留的中间后备空间 | `system.windows.dedicated-dump-backing`，BLOCKED |
| 已完成 kernel/full/small dump | 根据 `CrashControl\DumpFile`、`MinidumpDir`、`CrashDumpEnabled` 定位 | 系统崩溃后的诊断证据，可能用于定位故障 | `diagnostic.windows.crash-dump`，默认 R3/report-only；不是无条件 OS 安全硬阻断，但只进入独立诊断 retention 规则 |

**证据边界：** Microsoft 对 `swapfile.sys` 的具体说明来自官方归档支持博客，而不是当前稳定枚举 API。因此必须使用 system drive + exact name + system/hidden metadata 的组合证据；证据不完整时按系统卷保护覆盖，不输出可执行候选。

## 4. macOS

| 对象 | 动态识别 | 给用户的解释 | SweepX 行为 |
|---|---|---|---|
| APFS VM role volume 与 swap | 从 APFS volume metadata/API 识别 **VM volume role**；`diskutil apfs list` 是可观察表示。不只依赖 `/private/var/vm` 或 `swapfile0` 名称 | macOS 使用隐藏 APFS VM volume 存放加密 swap | `system.macos.vm-volume`，整个已挂载 VM-role volume 及后代 BLOCKED |
| Signed System Volume | 从 startup APFS System role、mount/read-only 状态识别 SSV | Apple 签名的系统内容由 macOS 验证完整性 | `system.macos.signed-system-volume`，BLOCKED；即使某环境可写也不尝试修改 |
| SIP-protected location | 以 OS 保护元数据、返回错误和受保护区域为权威 | System Integrity Protection 限制包括 root 在内的进程修改系统关键部分 | `system.macos.sip-protected`，BLOCKED；不把 root/FDA 当授权 |
| 当前 sleep image | 仅在当前 power-management 配置明确给出 hibernation-file path 时识别，并尽量与 VM-role volume 交叉确认 | macOS 可能用它保存 hibernation 的内存状态 | `system.macos.sleep-image`，确认后 BLOCKED；不全局写死 `/private/var/vm/sleepimage` |

**证据边界：** Apple 当前安全文档明确描述 APFS VM role、加密 swap、SSV 与 SIP；公开 sleep-image 路径材料具有历史性，不能据此承诺所有当前 Mac 都存在同名路径。因此未知时保护 VM volume，不按 filename 猜。

## 5. Linux

| 对象 | 动态识别 | 给用户的解释 | SweepX 行为 |
|---|---|---|---|
| 活跃 swap file/partition | 在 SweepX 当前 mount namespace 解析 `/proc/swaps`；对每个 pathname `stat` 区分 regular file 与 block device。`swapon --show` 只作为用户态展示 | Linux kernel 正在把该文件或设备用作 swap | `system.linux.active-swap`，BLOCKED；不 unlink/truncate/format，不自动运行 `swapoff` |
| `/` 与所有 active mount roots | 解析 `/proc/self/mountinfo` 的 mount ID、parent、root、mountpoint、device 和 fs type | 它是运行系统的根或另一个 filesystem 的接入点，不是普通目录 | `/` 永久 BLOCKED；其他 mountpoint 是默认 traversal boundary，只有作为新显式 scan root 才可只读进入，其 mount root 本身仍不可删除 |
| kernel/pseudo filesystem | 按 mountinfo 的 fs type 识别 `proc`、`sysfs`、`devtmpfs`/`dev`、`devpts`、`cgroup`/`cgroup2`、`securityfs`、`debugfs`、`efivarfs` 等，不依赖惯用 path | 这是活跃内核、设备、进程、控制组、安全、调试或固件接口，不是磁盘垃圾 | mount root 与后代 BLOCKED；尤其 `efivarfs`，kernel 文档警告某些 UEFI variable 删除可导致 firmware 无法 POST |
| `tmpfs` / `ramfs` | 按 mountinfo fs type 识别，并区分 OS-managed runtime/device/shared-memory mount | 内存后备的活跃运行时状态，不等于“可随意删除的临时文件” | mount root 为边界；OS-managed instance 与后代 BLOCKED，其他显式 scope 仍只读/保守分析 |

容器中看到的是当前进程 namespace。不得用 host 路径假设替代当前 `/proc/self/mountinfo`/`/proc/swaps`；namespace 信息不可读时 destructive mode 失败关闭。

## 6. 用户提示与规则模型

扫描结果对系统对象显示真实类别、用途和来源，例如：

```text
pagefile.sys — Windows active page file
  作用：虚拟内存后备；也可能支撑 crash dump
  风险：BLOCKED / system-managed
  操作：SweepX 永不删除；如需调整，使用 Windows 支持的系统配置

/dev/nvme0n1p3 — Linux active swap partition
  作用：内核当前 swap area
  风险：BLOCKED / active kernel state
  操作：SweepX 永不删除、格式化或自动 swapoff
```

禁止把 BLOCKED 对象包装为 `R4 + --dangerously-delete`：R4 表示“产品允许的不可逆动作”，BLOCKED 表示“没有 action、没有 authorization path”。系统配置建议也不属于 SweepX 删除计划。

## 7. 官方来源

所有来源访问于 **2026-08-26**。

### Microsoft

- [Win32_PageFileUsage](https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-pagefileusage)
- [Win32_PageFileSetting](https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-pagefilesetting)
- [Introduction to the page file](https://learn.microsoft.com/en-us/troubleshoot/windows-client/performance/introduction-to-the-page-file)
- [Page-file sizing and crash dumps](https://learn.microsoft.com/en-us/troubleshoot/windows-client/performance/how-to-determine-the-appropriate-page-file-size-for-64-bit-versions-of-windows)
- [`swapfile.sys` official archived support post](https://learn.microsoft.com/en-us/archive/blogs/supportingwindows/windows-8-windows-server-2012-the-new-swap-file)
- [Disable and re-enable hibernation](https://learn.microsoft.com/en-us/troubleshoot/windows-client/setup-upgrade-and-drivers/disable-and-re-enable-hibernation)
- [`powercfg` command-line options](https://learn.microsoft.com/en-us/windows-hardware/design/device-experiences/powercfg-command-line-options)
- [Server Core memory dump / DedicatedDumpFile](https://learn.microsoft.com/en-us/windows-server/administration/server-core/server-core-memory-dump)
- [Configure USB crash dump](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/validation-os-configure-usb-crash-dump?view=windows-11)
- [Memory dump file options](https://learn.microsoft.com/en-us/troubleshoot/windows-server/performance/memory-dump-file-options)
- [Read small memory dump files](https://learn.microsoft.com/en-us/troubleshoot/windows-client/performance/read-small-memory-dump-file)

### Apple

- [Secure virtual memory / APFS VM volume](https://support.apple.com/guide/security/seca6147599e/web)
- [Signed System Volume](https://support.apple.com/guide/security/secd698747c9/web)
- [macOS read-only system volume](https://support.apple.com/guide/mac-help/mchl0f9af76f/mac)
- [System Integrity Protection](https://support.apple.com/102149)
- [Historical sleep image behavior](https://support.apple.com/en-ph/HT202473)

### Linux

- [`/proc/swaps`](https://www.man7.org/linux/man-pages/man5/proc_swaps.5.html)
- [`swapon(2)` / `swapoff(2)`](https://www.man7.org/linux/man-pages/man2/swapon.2.html)
- [Kernel procfs documentation](https://docs.kernel.org/filesystems/proc.html)
- [`/proc/PID/mountinfo`](https://www.man7.org/linux/man-pages/man5/proc_pid_mountinfo.5.html)
- [`mount(2)`](https://www.man7.org/linux/man-pages/man2/mount.2.html)
- [sysfs](https://docs.kernel.org/filesystems/sysfs.html)
- [debugfs](https://docs.kernel.org/filesystems/debugfs.html)
- [efivarfs](https://docs.kernel.org/filesystems/efivarfs.html)
- [tmpfs](https://docs.kernel.org/filesystems/tmpfs.html)
- [ramfs/rootfs/initramfs](https://docs.kernel.org/filesystems/ramfs-rootfs-initramfs.html)
