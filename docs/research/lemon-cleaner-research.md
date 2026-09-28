# Lemon Cleaner 调研结论

调研对象：[Tencent/lemon-cleaner](https://github.com/Tencent/lemon-cleaner)。

调研快照：2026-09-28，上游 `HEAD` 为 `7ff8676f1dbe624b039f6b5d50ca81b50963629e`。

## 许可证结论

Lemon Cleaner 是 GPL 系列许可证项目：

- 根目录 `LICENSE.txt` 声明：Lemon Cleaner 与 Lemon Monitor 模块使用 **GPL-3.0-only**。
- `LICENSE_LemonCleaner_LemonDaemon.txt` 声明：LemonDaemon 模块使用 **GPL-2.0-only**。
- 仓库 README 同样说明 LemonDaemon 为 GPL v2，Lemon Monitor 与 Lemon Cleaner 为 GPL v3；另有单独授权的第三方组件。

SweepX 已改为 **GPL-3.0-only**，因此可以收集和改编 Lemon Cleaner / Lemon Monitor 的 GPL-3.0 策略；LemonDaemon 的 GPL-2.0-only 内容不能直接按 GPL-3.0 混编，若需要其能力应独立实现或单独处理兼容性。

## 可参考的产品行为

Lemon Cleaner 的公开源码显示，其垃圾扫描围绕三类用户可理解的对象展开：

1. **系统垃圾**：系统缓存、日志、iOS 照片缓存、iOS 升级数据、废纸篓等。
2. **应用垃圾**：Xcode、微信、Sketch 等应用的应用专属缓存、日志和可再生数据。
3. **浏览器/上网痕迹**：浏览器缓存及隐私相关数据。

其规则资源位于：

- `LemonClener/LemonClener/libcleaner/garbage1_zh.xml`
- `LemonClener/LemonClener/libcleaner/garbage1_en.xml`
- `LemonClener/LemonClener/libcleaner/garbage_appstore_zh.xml`
- `LemonClener/LemonClener/libcleaner/garbage_appstore_en.xml`

这些 XML 表达了路径、层级、过滤器、推荐状态和清理动作；SweepX 可在 GPL-3.0 边界内收集和改编非 LemonDaemon 部分，但需保留来源和许可声明。

## 对 SweepX 的策略影响

Lemon Cleaner 验证了 macOS 清理器需要区分以下对象：

- `~/Library/Caches` 中应用可重建的缓存；
- `~/Library/Developer/Xcode/DerivedData` 等开发工具可再生产物；
- 用户明确确认后才可处理的 `~/.Trash`、`~/Downloads`、iOS 设备备份；
- 不能按目录名一概处理的浏览器隐私、应用容器、`Application Support`、偏好设置和用户文档。

SweepX 的采纳原则：

1. 只收集 GPL-3.0 模块中的策略，不混入 GPL-2.0-only 的 LemonDaemon 内容。
2. 每一条规则必须有一方或官方文档证明路径所有权、可重建边界和需保留的数据。
3. 自动扫描先以 report-only 方式落地，不直接获得删除授权。
4. 删除动作必须另经不可变计划、实时重验、用户确认和平台能力门槛。

## 与 MangoDisk 的关系

MangoDisk 与 Lemon Cleaner 都提供 GPL-3.0 策略来源。合并后的策略清单、分类和分批落地路线见 [垃圾扫描策略收集](cleaner-strategy-collection.md)。
