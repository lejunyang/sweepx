//! Category summaries reuse the core organization and captured overlap identities.
use std::collections::{BTreeMap, BTreeSet};
use sweepx_core::junk::{
    candidate::JunkCandidate,
    organization::{JunkCategory, organize_candidates},
};
use sweepx_i18n::Locale;
use sweepx_model::{EvidenceValue, HumanSizeUnit};

pub(crate) fn print_groups(
    candidates: &[JunkCandidate],
    locale: Locale,
    unit: HumanSizeUnit,
    mode: &str,
) {
    let zh = locale == Locale::ZhCn;
    let title = match (mode, zh) {
        ("regular", true) => "常规清理扫描：已知应用、系统与开发工具缓存位置",
        ("regular", false) => {
            "Regular cleanup: known application, system and developer cache locations"
        }
        ("deep", true) => "全盘深度扫描：系统磁盘与已支持的项目、平台规则；其他卷及权限缺口仍排除",
        ("deep", false) => {
            "Deep cleanup: system disk with project/platform rules; other volumes and permission gaps remain excluded"
        }
        (_, true) => "指定目录扫描：项目规则",
        (_, false) => "Selected directories: project rules",
    };
    println!("{title}");
    let ids: BTreeSet<_> = candidates.iter().map(|row| &row.entry_id).collect();
    let organizations = organize_candidates(candidates);
    let mut groups: BTreeMap<(JunkCategory, &str, &str, bool), Vec<&JunkCandidate>> =
        BTreeMap::new();
    for (row, group) in candidates.iter().zip(&organizations) {
        groups
            .entry((
                group.category,
                &group.owner_key,
                &group.owner_label,
                group.named_application,
            ))
            .or_default()
            .push(row);
    }
    let mut category = None;
    for ((kind, location, label, named), rows) in groups {
        if category != Some(kind) {
            println!("\n{}", kind.label(locale));
            category = Some(kind);
        }
        let outer: Vec<_> = rows
            .iter()
            .filter(|row| !row.ancestor_ids.iter().any(|id| ids.contains(id)))
            .collect();
        let size = group_size(
            outer
                .iter()
                .map(|row| (&row.reclaimable, row.size_is_logical)),
            zh,
            unit,
        );
        let label = sanitize(label);
        let location = sanitize(location);
        let source = if named {
            String::new()
        } else if zh {
            format!(" · 来源目录 {location}")
        } else {
            format!(" · source location {location}")
        };
        let restricted = rows
            .iter()
            .filter(|row| row.project_execution_blocker().is_some())
            .count();
        if zh {
            println!(
                "  {label}  {size} · {} 项 · {restricted} 项仅供查看{source}",
                rows.len()
            );
        } else {
            println!(
                "  {label}  {size} · {} items · {restricted} report-only{source}",
                rows.len()
            );
        }
    }
    println!(
        "\n{}",
        if zh {
            "使用 --tui 逐层展开和选择，或 --details 查看路径、规则和依据。"
        } else {
            "Use --tui to drill down and select, or --details for paths, rules and evidence."
        }
    );
}

/// Keep actionable omissions visible even when expected symlink boundaries fill the log.
pub(crate) fn boundary_examples(
    summary: &sweepx_scanner::ScanSummary,
) -> impl Iterator<Item = &sweepx_platform::BoundaryRecord> {
    let actionable = |boundary: &&sweepx_platform::BoundaryRecord| {
        !matches!(
            boundary.kind,
            sweepx_platform::BoundaryKind::Symlink | sweepx_platform::BoundaryKind::RootSymlink
        )
    };
    summary.boundaries.iter().filter(actionable).chain(
        summary
            .boundaries
            .iter()
            .filter(move |boundary| !actionable(boundary)),
    )
}

pub(crate) fn print_coverage(summary: &sweepx_scanner::ScanSummary, locale: Locale) {
    let zh = locale == Locale::ZhCn;
    if zh {
        println!(
            "遍历{} · 保留 {} 条检查限制 · {} 个错误 · 资源限制{}",
            if summary.progress_retention.finished {
                "已结束"
            } else {
                "未结束"
            },
            summary.boundaries.len(),
            summary.error_count(),
            if summary.progress_retention.resource_limited {
                "已触发"
            } else {
                "未触发"
            }
        );
    } else {
        println!(
            "Traversal {} · {} retained issues · {} errors · resource limit {}",
            if summary.progress_retention.finished {
                "finished"
            } else {
                "unfinished"
            },
            summary.boundaries.len(),
            summary.error_count(),
            if summary.progress_retention.resource_limited {
                "reached"
            } else {
                "not reached"
            }
        );
    }
    for boundary in boundary_examples(summary).take(8) {
        let text = format!("{}: {}", boundary.path.display(), boundary.detail);
        println!("  {}", sanitize(&text));
    }
    if summary.boundaries.len() > 8 {
        println!(
            "{}",
            if zh {
                "更多限制请使用 --tui 的 e 或 JSON scanCoverage 查看；保留记录数量不代表完整边界数量。"
            } else {
                "More issues: press e in --tui or inspect JSON scanCoverage; retained counts are not a complete boundary inventory."
            }
        );
    }
}

fn sanitize(text: &str) -> String {
    text.chars()
        .flat_map(|c| {
            if c.is_control() {
                c.escape_default().collect::<Vec<_>>()
            } else {
                vec![c]
            }
        })
        .collect()
}

fn group_size<'a>(
    values: impl Iterator<Item = (&'a sweepx_model::ByteValue, bool)>,
    zh: bool,
    unit: HumanSizeUnit,
) -> String {
    let mut sum = Some(0u128);
    let mut incomplete = false;
    let mut quantities = BTreeSet::new();
    let mut observed = false;
    for (value, logical) in values {
        quantities.insert(logical);
        let value = match value {
            EvidenceValue::Known { value } => Some(value.0),
            EvidenceValue::LowerBound { value, .. } => {
                incomplete = true;
                Some(value.0)
            }
            _ => {
                incomplete = true;
                None
            }
        };
        if let Some(value) = value {
            observed = true;
            sum = sum.and_then(|sum| sum.checked_add(value));
        }
    }
    if quantities.len() > 1 {
        if zh {
            "混合大小证据，见 --details".into()
        } else {
            "Mixed size evidence; see --details".into()
        }
    } else if !observed {
        if zh {
            "未知".into()
        } else {
            "unknown".into()
        }
    } else {
        format!(
            "{}{} {}",
            if incomplete { ">= " } else { "" },
            sum.map(|n| unit.format(n))
                .unwrap_or_else(|| "unknown".into()),
            match (quantities.contains(&true), zh) {
                (true, true) => "逻辑大小",
                (false, true) => "文件系统占用",
                (true, false) => "logical",
                (false, false) => "on disk",
            }
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sweepx_model::{ByteValue, DecimalU128, ReasonCode};
    #[test]
    fn group_size_keeps_unknown_partial_mixed_and_overflow_distinct() {
        let unknown = ByteValue::Unknown {
            reason: ReasonCode::Unknown,
        };
        let ten = ByteValue::Known {
            value: DecimalU128::new(10),
        };
        let max = ByteValue::Known {
            value: DecimalU128::new(u128::MAX),
        };
        let label = |values: Vec<(&ByteValue, bool)>| {
            group_size(values.into_iter(), false, HumanSizeUnit::Bytes)
        };
        assert_eq!(label(vec![(&unknown, true)]), "unknown");
        assert_eq!(
            label(vec![(&ten, true), (&unknown, true)]),
            ">= 10 B logical"
        );
        assert_eq!(
            label(vec![(&ten, true), (&ten, false)]),
            "Mixed size evidence; see --details"
        );
        assert_eq!(label(vec![(&max, true), (&ten, true)]), "unknown logical");
        assert_eq!(sanitize("app\x1b[2J\n"), "app\\u{1b}[2J\\n");
    }
}
