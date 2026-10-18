//! Bounded explanations of incomplete scan coverage, separate from user action feedback.
use super::*;

/// User-facing reason why part of a scan could not be checked.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum JunkIssueKind {
    /// A directory could not be read with current permissions.
    Permission,
    /// A directory belongs to an excluded filesystem or volume.
    OtherVolume,
    /// A special file (for example an application IPC socket) is outside cleanup traversal.
    SkippedEntry,
    /// A directory or result exceeded the bounded scan capacity.
    Capacity,
    /// npm installation discovery could not observe all locations.
    NpmDiscovery,
    /// Application cache discovery could not observe all locations.
    AppDiscovery,
    /// A location changed or could not be read for another reason.
    Unavailable,
    /// Automatic change notification is unavailable.
    Watch,
}

impl JunkIssueKind {
    fn label(self, locale: Locale) -> &'static str {
        let (zh, en) = match self {
            Self::Permission => (
                "没有权限读取部分目录",
                "Some folders could not be read: permission denied",
            ),
            Self::OtherVolume => (
                "已跳过其他磁盘或不支持的文件系统",
                "Other volumes or unsupported filesystems were skipped",
            ),
            Self::SkippedEntry => (
                "已跳过特殊文件（例如应用通信文件）",
                "Special files such as application sockets were skipped",
            ),
            Self::Capacity => (
                "部分目录或扫描结果过大，未全部检查",
                "Some folders or results were too large to check fully",
            ),
            Self::NpmDiscovery => (
                "部分 npm 安装或缓存配置未能检查",
                "Some npm installations or cache settings could not be checked",
            ),
            Self::AppDiscovery => (
                "未能找到或读取全部应用缓存位置",
                "Some application cache locations could not be checked",
            ),
            Self::Unavailable => (
                "部分位置读取失败或已发生变化",
                "Some locations could not be read or have changed",
            ),
            Self::Watch => (
                "无法自动检测文件变化",
                "Automatic change detection is unavailable",
            ),
        };
        if locale == Locale::ZhCn { zh } else { en }
    }
}

#[derive(Default)]
pub(super) struct IssueSummary {
    count: u64,
    examples: Vec<String>,
}

fn bounded(mut text: String) -> String {
    if text.len() > 2048 {
        let mut end = 2048;
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        text.truncate(end);
        text.push('…');
    }
    text
}

fn discovery_detail(kind: JunkIssueKind, detail: String, locale: Locale) -> String {
    if !matches!(
        kind,
        JunkIssueKind::NpmDiscovery | JunkIssueKind::AppDiscovery
    ) {
        return detail;
    }
    let (code, rest) = detail.split_once(": ").unwrap_or((&detail, ""));
    let labels = match code {
        "probe_budget" | "deadline" => (
            "查询用时过长，部分位置未能检查",
            "Location lookup timed out before all locations were checked",
        ),
        "resource_limit" => (
            "位置或安装数量较多，本轮未全部检查",
            "Too many locations or installations to check in this scan",
        ),
        "probe_unavailable" => ("缓存位置查询失败", "Cache location query failed"),
        "observation_unavailable" => (
            "读取安装或目录信息失败",
            "Could not read installation or folder information",
        ),
        "cancelled" => ("位置检查已停止", "Location lookup was stopped"),
        _ => return detail,
    };
    let label = if locale == Locale::ZhCn {
        labels.0
    } else {
        labels.1
    };
    if rest.is_empty() || rest == "npm installation discovery could not complete" {
        label.into()
    } else {
        format!("{label}\n{rest}")
    }
}

impl JunkModel {
    pub(super) fn has_unchecked_locations(&self) -> bool {
        self.issues.is_empty()
            || self.issues.keys().any(|kind| {
                !matches!(
                    kind,
                    JunkIssueKind::OtherVolume | JunkIssueKind::SkippedEntry | JunkIssueKind::Watch
                )
            })
    }
    pub(super) fn record_issue(&mut self, kind: JunkIssueKind, detail: String) {
        self.issue_count = self.issue_count.saturating_add(1);
        let summary = self.issues.entry(kind).or_default();
        summary.count = summary.count.saturating_add(1);
        if summary.examples.len() < 3 {
            let detail = bounded(discovery_detail(kind, detail, self.locale));
            if !summary.examples.contains(&detail) {
                summary.examples.push(detail);
            }
        }
    }

    pub(super) fn coverage_summary(&self) -> String {
        if self.issues.is_empty() {
            return match self.outcome {
                Some(JunkOutcome::Partial) => self
                    .text(
                        "有位置未完成检查，按 e 查看原因",
                        "Some locations were not checked; press e for details",
                    )
                    .into(),
                _ => String::new(),
            };
        }
        self.issues
            .keys()
            .map(|kind| kind.label(self.locale))
            .collect::<Vec<_>>()
            .join("；")
    }

    pub(super) fn coverage_details(&self) -> String {
        if self.issues.is_empty() {
            return if self.outcome == Some(JunkOutcome::Partial) {
                self.text("本轮有位置未完成检查，暂无详细错误；R 重新检查全部", "Some locations were not checked; no detailed error was retained. R checks the full scope again").into()
            } else {
                self.text("没有未完成的检查", "No incomplete checks").into()
            };
        }
        let mut text = String::new();
        for (kind, summary) in &self.issues {
            text.push_str(&format!(
                "{} ({})\n",
                kind.label(self.locale),
                summary.count
            ));
            for example in &summary.examples {
                text.push_str(example);
                text.push('\n');
            }
            text.push('\n');
        }
        text
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn missing_diagnostics_do_not_turn_partial_coverage_into_a_success_message() {
        let mut model = JunkModel::new(Locale::EnUs, HumanSizeUnit::Bytes);
        model.outcome = Some(JunkOutcome::Partial);
        assert_ne!(model.coverage_details(), "No incomplete checks");
        assert!(model.coverage_details().contains("no detailed error"));
    }

    #[test]
    fn coverage_reasons_survive_exclusions_without_overwriting_action_feedback() {
        let mut model = JunkModel::new(Locale::ZhCn, HumanSizeUnit::Bytes);
        model.grouped = Some(grouped::GroupedView::default());
        model.apply(JunkEvent::Started {
            revision: 1,
            keys: None,
        });
        model.diagnostic("已选择 1 项".into());
        model.apply(JunkEvent::Issue {
            revision: 1,
            kind: JunkIssueKind::NpmDiscovery,
            detail: "/tools/npm: permission denied".into(),
        });
        for n in 0..100 {
            model.apply(JunkEvent::Issue {
                revision: 1,
                kind: JunkIssueKind::Permission,
                detail: format!("/private/{n}"),
            });
            model.apply(JunkEvent::Notice {
                revision: 1,
                message: "symlink skipped".into(),
            });
        }
        assert_eq!(model.issue_count, 101);
        assert_eq!(model.issues.len(), 2);
        assert_eq!(model.issues[&JunkIssueKind::Permission].examples.len(), 3);
        assert_eq!(model.diagnostic, "已选择 1 项");
        assert!(model.coverage_summary().contains("npm"));
        let details = model.coverage_details();
        assert!(
            details.contains("/tools/npm: permission denied") && details.contains("没有权限读取")
        );
        assert!(!details.contains("symlink"));
    }
}
