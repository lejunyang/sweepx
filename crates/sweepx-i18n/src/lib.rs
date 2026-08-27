use std::env;
use std::error::Error;
use std::fmt;
use std::str::FromStr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum Locale {
    ZhCn,
    #[default]
    EnUs,
}

impl Locale {
    pub const fn as_bcp47(self) -> &'static str {
        match self {
            Self::ZhCn => "zh-CN",
            Self::EnUs => "en-US",
        }
    }

    pub const fn all() -> [Self; 2] {
        [Self::ZhCn, Self::EnUs]
    }
}

impl fmt::Display for Locale {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_bcp47())
    }
}

impl FromStr for Locale {
    type Err = LocaleParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        parse_locale(value).ok_or_else(|| LocaleParseError {
            input: value.to_string(),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocaleParseError {
    input: String,
}

impl LocaleParseError {
    pub fn input(&self) -> &str {
        &self.input
    }
}

impl fmt::Display for LocaleParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "unsupported locale {:?}; expected zh-CN or en-US",
            self.input
        )
    }
}

impl Error for LocaleParseError {}

fn parse_locale(value: &str) -> Option<Locale> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return None;
    }

    let normalized = trimmed.replace('_', "-").to_ascii_lowercase();
    let language = normalized.split('.').next().unwrap_or(&normalized);
    let language = language.split('@').next().unwrap_or(language);

    match language {
        "zh" | "zh-cn" | "zh-hans" | "zh-hans-cn" | "zh-chs" | "zh-chs-cn" | "cn" => {
            Some(Locale::ZhCn)
        }
        "en" | "en-us" | "en-posix" => Some(Locale::EnUs),
        "c" | "posix" => None,
        _ => None,
    }
}

pub fn parse_locale_alias(value: &str) -> Option<Locale> {
    parse_locale(value)
}

pub trait EnvProvider {
    fn var(&self, key: &str) -> Option<String>;
}

#[derive(Debug, Default, Clone, Copy)]
pub struct ProcessEnv;

impl EnvProvider for ProcessEnv {
    fn var(&self, key: &str) -> Option<String> {
        env::var(key).ok()
    }
}

pub trait SystemLocaleProvider {
    fn system_locale(&self) -> Option<String>;
}

#[derive(Debug, Default, Clone, Copy)]
pub struct SysLocaleProvider;

impl SystemLocaleProvider for SysLocaleProvider {
    fn system_locale(&self) -> Option<String> {
        sys_locale::get_locale()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocaleResolution {
    locale: Locale,
    source: LocaleSource,
}

impl LocaleResolution {
    pub const fn new(locale: Locale, source: LocaleSource) -> Self {
        Self { locale, source }
    }

    pub const fn locale(&self) -> Locale {
        self.locale
    }

    pub const fn source(&self) -> LocaleSource {
        self.source
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocaleSource {
    Explicit,
    LcAll,
    LcMessages,
    Lang,
    System,
    Default,
}

pub struct LocaleResolver<E = ProcessEnv, S = SysLocaleProvider> {
    env: E,
    system: S,
}

impl Default for LocaleResolver<ProcessEnv, SysLocaleProvider> {
    fn default() -> Self {
        Self::new(ProcessEnv, SysLocaleProvider)
    }
}

impl<E, S> LocaleResolver<E, S> {
    pub const fn new(env: E, system: S) -> Self {
        Self { env, system }
    }
}

impl<E, S> LocaleResolver<E, S>
where
    E: EnvProvider,
    S: SystemLocaleProvider,
{
    pub fn resolve(&self, explicit: Option<Locale>) -> LocaleResolution {
        if let Some(locale) = explicit {
            return LocaleResolution::new(locale, LocaleSource::Explicit);
        }

        for (key, source) in [
            ("LC_ALL", LocaleSource::LcAll),
            ("LC_MESSAGES", LocaleSource::LcMessages),
            ("LANG", LocaleSource::Lang),
        ] {
            if let Some(locale) = self.env.var(key).as_deref().and_then(parse_locale) {
                return LocaleResolution::new(locale, source);
            }
        }

        if let Some(locale) = self
            .system
            .system_locale()
            .as_deref()
            .and_then(parse_locale)
        {
            return LocaleResolution::new(locale, LocaleSource::System);
        }

        LocaleResolution::new(Locale::EnUs, LocaleSource::Default)
    }
}

pub fn detect_locale(explicit: Option<Locale>) -> LocaleResolution {
    LocaleResolver::default().resolve(explicit)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MessageKey {
    AboutSummary,
    ScanStart,
    ScanCompleted,
    ScanPartial,
    ErrorGeneric,
    StatusSummary,
    CancelAccepted,
    CapabilitiesSummary,
    SafetyReadOnlyNotice,
    LabelCommand,
    LabelLocale,
    LabelStatus,
    LabelCapabilities,
    LabelRoot,
    LabelItems,
    LabelErrors,
}

impl MessageKey {
    pub const fn all() -> [Self; 16] {
        [
            Self::AboutSummary,
            Self::ScanStart,
            Self::ScanCompleted,
            Self::ScanPartial,
            Self::ErrorGeneric,
            Self::StatusSummary,
            Self::CancelAccepted,
            Self::CapabilitiesSummary,
            Self::SafetyReadOnlyNotice,
            Self::LabelCommand,
            Self::LabelLocale,
            Self::LabelStatus,
            Self::LabelCapabilities,
            Self::LabelRoot,
            Self::LabelItems,
            Self::LabelErrors,
        ]
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MessageArgs<'a> {
    pub command: &'a str,
    pub root: &'a str,
    pub items: usize,
    pub errors: usize,
    pub status: &'a str,
    pub capabilities: &'a str,
    pub detail: &'a str,
}

#[derive(Debug, Clone)]
pub struct Catalog {
    locale: Locale,
}

impl Catalog {
    pub const fn new(locale: Locale) -> Self {
        Self { locale }
    }

    pub const fn locale(&self) -> Locale {
        self.locale
    }

    pub fn render(&self, key: MessageKey, args: &MessageArgs<'_>) -> String {
        match self.locale {
            Locale::ZhCn => render_zh_cn(key, args),
            Locale::EnUs => render_en_us(key, args),
        }
    }

    pub fn render_plan_review(
        &self,
        key: PlanReviewMessageKey,
        args: &PlanReviewMessageArgs<'_>,
    ) -> String {
        render_plan_review(self.locale, key, args)
    }
}

pub fn render(locale: Locale, key: MessageKey, args: &MessageArgs<'_>) -> String {
    Catalog::new(locale).render(key, args)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PlanReviewMessageKey {
    Summary,
    AuthorityNotice,
    FingerprintNotice,
    RecoveryNotice,
}

impl PlanReviewMessageKey {
    pub const fn all() -> [Self; 4] {
        [
            Self::Summary,
            Self::AuthorityNotice,
            Self::FingerprintNotice,
            Self::RecoveryNotice,
        ]
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Summary => "plan.review.summary",
            Self::AuthorityNotice => "plan.review.authority_notice",
            Self::FingerprintNotice => "plan.review.fingerprint_notice",
            Self::RecoveryNotice => "plan.review.recovery_notice",
        }
    }
}

impl fmt::Display for PlanReviewMessageKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Display values for the read-only plan review surface.
///
/// `mode`, `risk`, and `recovery_kind` are stable protocol enum values and are intentionally
/// interpolated verbatim instead of translated. Counts stay decimal strings end to end.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PlanReviewMessageArgs<'a> {
    pub plan_id: &'a str,
    pub mode: &'a str,
    pub item_count: &'a str,
    pub action_count: &'a str,
    pub risk: &'a str,
    pub fingerprint: &'a str,
    pub recovery_kind: &'a str,
}

pub fn render_plan_review(
    locale: Locale,
    key: PlanReviewMessageKey,
    args: &PlanReviewMessageArgs<'_>,
) -> String {
    match locale {
        Locale::EnUs => render_plan_review_en_us(key, args),
        Locale::ZhCn => render_plan_review_zh_cn(key, args),
    }
}

fn render_plan_review_en_us(key: PlanReviewMessageKey, args: &PlanReviewMessageArgs<'_>) -> String {
    match key {
        PlanReviewMessageKey::Summary => format!(
            "Plan {plan_id}: mode {mode}, {item_count} items, {action_count} actions, risk {risk}.",
            plan_id = args.plan_id,
            mode = args.mode,
            item_count = args.item_count,
            action_count = args.action_count,
            risk = args.risk
        ),
        PlanReviewMessageKey::AuthorityNotice => {
            "Review only: this output grants no approval and authorizes no execution. JSON is not plan authority.".to_string()
        }
        PlanReviewMessageKey::FingerprintNotice => format!(
            "Attention fingerprint {fingerprint} is for comparison only; it is not authorization.",
            fingerprint = args.fingerprint
        ),
        PlanReviewMessageKey::RecoveryNotice => format!(
            "Recovery expectation: {recovery_kind}. Capacity release is not guaranteed.",
            recovery_kind = args.recovery_kind
        ),
    }
}

fn render_plan_review_zh_cn(key: PlanReviewMessageKey, args: &PlanReviewMessageArgs<'_>) -> String {
    match key {
        PlanReviewMessageKey::Summary => format!(
            "计划 {plan_id}：模式 {mode}，{item_count} 个条目，{action_count} 个动作，风险 {risk}。",
            plan_id = args.plan_id,
            mode = args.mode,
            item_count = args.item_count,
            action_count = args.action_count,
            risk = args.risk
        ),
        PlanReviewMessageKey::AuthorityNotice => {
            "仅供审阅：此输出不授予审批，也不授权执行；JSON 不是计划权威来源。".to_string()
        }
        PlanReviewMessageKey::FingerprintNotice => format!(
            "注意力指纹 {fingerprint} 仅用于对照，不是授权凭据。",
            fingerprint = args.fingerprint
        ),
        PlanReviewMessageKey::RecoveryNotice => format!(
            "恢复预期：{recovery_kind}；不保证释放容量。",
            recovery_kind = args.recovery_kind
        ),
    }
}

fn render_en_us(key: MessageKey, args: &MessageArgs<'_>) -> String {
    match key {
        MessageKey::AboutSummary => {
            "SweepX is a safety-first CLI for scanning storage and planning cleanup.".to_string()
        }
        MessageKey::ScanStart => {
            format!(
                "Starting scan for {command} at {root}.",
                command = args.command,
                root = args.root
            )
        }
        MessageKey::ScanCompleted => format!(
            "Scan completed for {root}: {items} items, {errors} errors.",
            root = args.root,
            items = args.items,
            errors = args.errors
        ),
        MessageKey::ScanPartial => format!(
            "Scan completed with partial results for {root}: {items} items, {errors} errors.",
            root = args.root,
            items = args.items,
            errors = args.errors
        ),
        MessageKey::ErrorGeneric => format!("Operation failed: {detail}.", detail = args.detail),
        MessageKey::StatusSummary => format!("Current status: {status}.", status = args.status),
        MessageKey::CancelAccepted => format!(
            "Cancellation accepted for operation {detail}.",
            detail = args.detail
        ),
        MessageKey::CapabilitiesSummary => format!(
            "Available capabilities: {capabilities}.",
            capabilities = args.capabilities
        ),
        MessageKey::SafetyReadOnlyNotice => {
            "Read-only mode does not modify files, permissions, or system settings.".to_string()
        }
        MessageKey::LabelCommand => "Command".to_string(),
        MessageKey::LabelLocale => "Locale".to_string(),
        MessageKey::LabelStatus => "Status".to_string(),
        MessageKey::LabelCapabilities => "Capabilities".to_string(),
        MessageKey::LabelRoot => "Root".to_string(),
        MessageKey::LabelItems => "Items".to_string(),
        MessageKey::LabelErrors => "Errors".to_string(),
    }
}

fn render_zh_cn(key: MessageKey, args: &MessageArgs<'_>) -> String {
    match key {
        MessageKey::AboutSummary => {
            "SweepX 是一个以安全为先的 CLI，用于扫描存储并规划清理。".to_string()
        }
        MessageKey::ScanStart => format!(
            "开始为 {command} 扫描 {root}。",
            command = args.command,
            root = args.root
        ),
        MessageKey::ScanCompleted => format!(
            "{root} 扫描完成：{items} 个条目，{errors} 个错误。",
            root = args.root,
            items = args.items,
            errors = args.errors
        ),
        MessageKey::ScanPartial => format!(
            "{root} 扫描完成，但结果不完整：{items} 个条目，{errors} 个错误。",
            root = args.root,
            items = args.items,
            errors = args.errors
        ),
        MessageKey::ErrorGeneric => format!("操作失败：{detail}。", detail = args.detail),
        MessageKey::StatusSummary => format!("当前状态：{status}。", status = args.status),
        MessageKey::CancelAccepted => {
            format!("已接受操作 {detail} 的取消请求。", detail = args.detail)
        }
        MessageKey::CapabilitiesSummary => format!(
            "可用能力：{capabilities}。",
            capabilities = args.capabilities
        ),
        MessageKey::SafetyReadOnlyNotice => "只读模式不会修改文件、权限或系统设置。".to_string(),
        MessageKey::LabelCommand => "命令".to_string(),
        MessageKey::LabelLocale => "语言".to_string(),
        MessageKey::LabelStatus => "状态".to_string(),
        MessageKey::LabelCapabilities => "能力".to_string(),
        MessageKey::LabelRoot => "根目录".to_string(),
        MessageKey::LabelItems => "条目".to_string(),
        MessageKey::LabelErrors => "错误".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;

    #[derive(Debug, Default)]
    struct TestEnv {
        vars: BTreeMap<String, String>,
    }

    impl TestEnv {
        fn with(key: &str, value: &str) -> Self {
            let mut vars = BTreeMap::new();
            vars.insert(key.to_string(), value.to_string());
            Self { vars }
        }

        fn with_many(pairs: &[(&str, &str)]) -> Self {
            let mut vars = BTreeMap::new();
            for (key, value) in pairs {
                vars.insert((*key).to_string(), (*value).to_string());
            }
            Self { vars }
        }
    }

    impl EnvProvider for TestEnv {
        fn var(&self, key: &str) -> Option<String> {
            self.vars.get(key).cloned()
        }
    }

    #[derive(Debug, Default, Clone)]
    struct TestSystemLocale(Option<String>);

    impl TestSystemLocale {
        fn new(value: Option<&str>) -> Self {
            Self(value.map(str::to_string))
        }
    }

    impl SystemLocaleProvider for TestSystemLocale {
        fn system_locale(&self) -> Option<String> {
            self.0.clone()
        }
    }

    fn sample_args<'a>() -> MessageArgs<'a> {
        MessageArgs {
            command: "scan",
            root: "/tmp/demo",
            items: 12,
            errors: 2,
            status: "partial",
            capabilities: "filesystem.metadata.read.scoped, process.observe",
            detail: "permission denied",
        }
    }

    fn sample_plan_review_args<'a>() -> PlanReviewMessageArgs<'a> {
        PlanReviewMessageArgs {
            plan_id: "plan-example",
            mode: "trash",
            item_count: "2",
            action_count: "5",
            risk: "R2",
            fingerprint: "SX1-0123456789AB",
            recovery_kind: "platform_trash",
        }
    }

    #[test]
    fn locale_display_is_bcp47() {
        assert_eq!(Locale::ZhCn.to_string(), "zh-CN");
        assert_eq!(Locale::EnUs.to_string(), "en-US");
    }

    #[test]
    fn locale_parser_accepts_expected_aliases() {
        for raw in ["zh-CN", "zh_cn", "zh", "ZH_hans.CN", "zh-Hans-CN", "cn"] {
            assert_eq!(raw.parse::<Locale>().unwrap(), Locale::ZhCn, "{raw}");
        }

        for raw in [
            "en-US",
            "en_us",
            "en",
            "EN.UTF-8",
            "en-US.UTF-8",
            "en_POSIX",
        ] {
            assert_eq!(raw.parse::<Locale>().unwrap(), Locale::EnUs, "{raw}");
        }
    }

    #[test]
    fn locale_parser_rejects_unsupported_values() {
        for raw in ["", "fr-FR", "de_DE", "C", "POSIX", "ja_JP.UTF-8"] {
            assert!(raw.parse::<Locale>().is_err(), "{raw}");
            assert_eq!(parse_locale_alias(raw), None, "{raw}");
        }
    }

    #[test]
    fn explicit_locale_wins_over_environment_and_system() {
        let resolver = LocaleResolver::new(
            TestEnv::with_many(&[
                ("LC_ALL", "zh_CN.UTF-8"),
                ("LC_MESSAGES", "en_US.UTF-8"),
                ("LANG", "zh_CN.UTF-8"),
            ]),
            TestSystemLocale::new(Some("zh_CN")),
        );

        let resolved = resolver.resolve(Some(Locale::EnUs));
        assert_eq!(resolved.locale(), Locale::EnUs);
        assert_eq!(resolved.source(), LocaleSource::Explicit);
    }

    #[test]
    fn lc_all_has_priority_over_other_environment_variables() {
        let resolver = LocaleResolver::new(
            TestEnv::with_many(&[
                ("LC_ALL", "zh_CN.UTF-8"),
                ("LC_MESSAGES", "en_US.UTF-8"),
                ("LANG", "en_US.UTF-8"),
            ]),
            TestSystemLocale::new(Some("en_US")),
        );

        let resolved = resolver.resolve(None);
        assert_eq!(resolved.locale(), Locale::ZhCn);
        assert_eq!(resolved.source(), LocaleSource::LcAll);
    }

    #[test]
    fn lc_messages_is_used_when_lc_all_is_missing() {
        let resolver = LocaleResolver::new(
            TestEnv::with_many(&[("LC_MESSAGES", "zh_CN.UTF-8"), ("LANG", "en_US.UTF-8")]),
            TestSystemLocale::new(Some("en_US")),
        );

        let resolved = resolver.resolve(None);
        assert_eq!(resolved.locale(), Locale::ZhCn);
        assert_eq!(resolved.source(), LocaleSource::LcMessages);
    }

    #[test]
    fn lang_is_used_when_higher_priority_envs_are_absent() {
        let resolver = LocaleResolver::new(
            TestEnv::with("LANG", "zh_CN.UTF-8"),
            TestSystemLocale::new(Some("en_US")),
        );

        let resolved = resolver.resolve(None);
        assert_eq!(resolved.locale(), Locale::ZhCn);
        assert_eq!(resolved.source(), LocaleSource::Lang);
    }

    #[test]
    fn invalid_or_posix_env_values_fall_through_to_system_locale() {
        let resolver = LocaleResolver::new(
            TestEnv::with_many(&[
                ("LC_ALL", "C"),
                ("LC_MESSAGES", "POSIX"),
                ("LANG", "fr_FR.UTF-8"),
            ]),
            TestSystemLocale::new(Some("zh_CN.UTF-8")),
        );

        let resolved = resolver.resolve(None);
        assert_eq!(resolved.locale(), Locale::ZhCn);
        assert_eq!(resolved.source(), LocaleSource::System);
    }

    #[test]
    fn invalid_system_locale_falls_back_to_default_english() {
        let resolver = LocaleResolver::new(
            TestEnv::with_many(&[
                ("LC_ALL", "C"),
                ("LC_MESSAGES", "POSIX"),
                ("LANG", "de_DE.UTF-8"),
            ]),
            TestSystemLocale::new(Some("fr_FR.UTF-8")),
        );

        let resolved = resolver.resolve(None);
        assert_eq!(resolved.locale(), Locale::EnUs);
        assert_eq!(resolved.source(), LocaleSource::Default);
    }

    #[test]
    fn missing_all_locale_sources_falls_back_to_default_english() {
        let resolver = LocaleResolver::new(TestEnv::default(), TestSystemLocale::default());

        let resolved = resolver.resolve(None);
        assert_eq!(resolved.locale(), Locale::EnUs);
        assert_eq!(resolved.source(), LocaleSource::Default);
    }

    #[test]
    fn each_message_key_renders_for_every_locale() {
        let args = sample_args();

        for locale in Locale::all() {
            for key in MessageKey::all() {
                let rendered = render(locale, key, &args);
                assert!(
                    !rendered.trim().is_empty(),
                    "missing rendering for {locale:?} {key:?}"
                );
            }
        }
    }

    #[test]
    fn status_message_keeps_machine_protocol_value_untranslated() {
        let args = MessageArgs {
            status: "needs_reconciliation",
            ..sample_args()
        };

        let en = render(Locale::EnUs, MessageKey::StatusSummary, &args);
        let zh = render(Locale::ZhCn, MessageKey::StatusSummary, &args);

        assert!(en.contains("needs_reconciliation"));
        assert!(zh.contains("needs_reconciliation"));
    }

    #[test]
    fn capabilities_message_keeps_machine_protocol_values_untranslated() {
        let args = MessageArgs {
            capabilities: "filesystem.metadata.read.scoped, browser-layout.decode:chromium@tested-range",
            ..sample_args()
        };

        let en = render(Locale::EnUs, MessageKey::CapabilitiesSummary, &args);
        let zh = render(Locale::ZhCn, MessageKey::CapabilitiesSummary, &args);

        assert!(en.contains("filesystem.metadata.read.scoped"));
        assert!(zh.contains("filesystem.metadata.read.scoped"));
        assert!(en.contains("browser-layout.decode:chromium@tested-range"));
        assert!(zh.contains("browser-layout.decode:chromium@tested-range"));
    }

    #[test]
    fn plan_review_messages_keep_machine_enums_and_decimal_strings_untranslated() {
        let args = sample_plan_review_args();

        for locale in Locale::all() {
            let summary = render_plan_review(locale, PlanReviewMessageKey::Summary, &args);
            let fingerprint =
                render_plan_review(locale, PlanReviewMessageKey::FingerprintNotice, &args);
            let recovery = render_plan_review(locale, PlanReviewMessageKey::RecoveryNotice, &args);

            for value in ["plan-example", "trash", "2", "5", "R2"] {
                assert!(summary.contains(value), "{locale:?}: {value}");
            }
            assert!(fingerprint.contains("SX1-0123456789AB"));
            assert!(recovery.contains("platform_trash"));
        }
    }

    #[test]
    fn plan_review_authority_message_is_explicitly_non_authorizing() {
        let args = sample_plan_review_args();
        let en = render_plan_review(Locale::EnUs, PlanReviewMessageKey::AuthorityNotice, &args);
        let zh = render_plan_review(Locale::ZhCn, PlanReviewMessageKey::AuthorityNotice, &args);

        assert!(en.contains("no approval"));
        assert!(en.contains("no execution"));
        assert!(en.contains("JSON is not plan authority"));
        assert!(zh.contains("不授予审批"));
        assert!(zh.contains("不授权执行"));
        assert!(zh.contains("JSON 不是计划权威来源"));
    }

    #[test]
    fn translated_messages_are_distinct_between_locales() {
        let args = sample_args();

        for key in [
            MessageKey::AboutSummary,
            MessageKey::ScanStart,
            MessageKey::ScanCompleted,
            MessageKey::ScanPartial,
            MessageKey::ErrorGeneric,
            MessageKey::StatusSummary,
            MessageKey::CancelAccepted,
            MessageKey::CapabilitiesSummary,
            MessageKey::SafetyReadOnlyNotice,
        ] {
            let en = render(Locale::EnUs, key, &args);
            let zh = render(Locale::ZhCn, key, &args);
            assert_ne!(en, zh, "{key:?}");
        }
    }

    #[test]
    fn each_plan_review_message_key_renders_for_every_locale() {
        let args = sample_plan_review_args();
        for locale in Locale::all() {
            for key in PlanReviewMessageKey::all() {
                let rendered = render_plan_review(locale, key, &args);
                assert!(
                    !rendered.trim().is_empty(),
                    "missing plan review rendering for {locale:?} {key:?}"
                );
            }
        }
    }

    #[test]
    fn plan_review_message_keys_have_stable_machine_names() {
        assert_eq!(
            PlanReviewMessageKey::AuthorityNotice.as_str(),
            "plan.review.authority_notice"
        );
        assert_eq!(
            PlanReviewMessageKey::RecoveryNotice.to_string(),
            "plan.review.recovery_notice"
        );
    }

    #[test]
    fn label_parity_count_matches_locale_count() {
        let args = sample_args();
        let mut count = 0usize;
        for locale in Locale::all() {
            for key in MessageKey::all() {
                let _ = render(locale, key, &args);
                count += 1;
            }
        }

        assert_eq!(count, Locale::all().len() * MessageKey::all().len());
    }
}
