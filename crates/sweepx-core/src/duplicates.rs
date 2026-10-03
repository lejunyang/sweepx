//! Explicit duplicate-content workflow shares ordinary scan observations and state/output paths.

use super::*;
use crate::large_files::{FileAnalysisObservation, FileAnalysisOptions};
use sweepx_analysis::DuplicateCollector;

/// Runs the ordinary metadata walk followed by bounded, cancellable content analysis.
/// Size/sample screening precedes full SHA-256 and final native revalidation. Results are
/// read-only observations, not junk classification, keeper choices or deletion authority.
pub fn scan_duplicates_with_store<S: SnapshotStore>(
    context: &CoreContext,
    request: &ScanRequest,
    store: Option<&S>,
    options: &DuplicateOptions,
    cancel: &CancellationToken,
) -> Result<ScanSuccess, CoreError> {
    DuplicateCollector::new(options.clone())?;
    scan_with_store_options(
        context,
        request,
        store,
        ScannerOptions::default(),
        None,
        None,
        None,
        Some(FileAnalysisObservation {
            options: FileAnalysisOptions::Duplicates(options),
            cancel,
            sink: None,
        }),
        ScanProjection::Materialized,
    )
    .map(|result| result.scan)
}

pub(super) fn append_human_groups(
    locale: Locale,
    data: &Value,
    lines: &mut Vec<String>,
    max_rows: usize,
    size_unit: HumanSizeUnit,
) {
    let Some(report) = data.get("duplicates") else {
        return;
    };
    let complete = report["complete"].as_bool().unwrap_or(false);
    let groups = report["groups"]
        .as_array()
        .map(Vec::as_slice)
        .unwrap_or(&[]);
    lines.push(match locale {
        Locale::ZhCn => format!(
            "重复内容组（完整 SHA-256，仅报告）；覆盖{}，{} 组。",
            if complete { "完整" } else { "不完整" },
            groups.len()
        ),
        Locale::EnUs => format!(
            "Duplicate-content groups (full SHA-256, report-only); coverage {}, {} groups.",
            if complete { "complete" } else { "incomplete" },
            groups.len()
        ),
    });
    let mut displayed = 0;
    for (index, group) in groups.iter().enumerate() {
        if displayed >= max_rows {
            break;
        }
        let size = group["logicalBytes"]
            .as_str()
            .and_then(|value| value.parse::<u128>().ok())
            .map(|value| size_unit.format(value))
            .unwrap_or_else(|| "?".into());
        lines.push(format!(
            "#{}  {}  SHA-256 {}",
            index + 1,
            size,
            group["sha256"].as_str().unwrap_or("?")
        ));
        for file in group["files"].as_array().map(Vec::as_slice).unwrap_or(&[]) {
            if displayed >= max_rows {
                break;
            }
            displayed += 1;
            lines.push(format!(
                "  {}",
                truncate_display(
                    &sanitize_terminal_text(file["displayPath"].as_str().unwrap_or("?")),
                    96
                )
            ));
        }
    }
    lines.push(match locale {
        Locale::ZhCn => format!("排除 {} 个同对象别名；读取范围预算已扣除 {} 字节，{} 次范围请求。重复内容不证明文件可丢弃，不选择保留者，也不合计可回收空间。", report["hardLinkAliasesExcluded"].as_str().unwrap_or("?"), report["readBudgetChargedBytes"].as_str().unwrap_or("?"), report["readOperations"].as_str().unwrap_or("?")),
        Locale::EnUs => format!("Excluded {} same-object aliases; charged {} payload-range bytes across {} range requests. Duplicate content does not establish disposability, choose a keeper, or prove reclaimable space.", report["hardLinkAliasesExcluded"].as_str().unwrap_or("?"), report["readBudgetChargedBytes"].as_str().unwrap_or("?"), report["readOperations"].as_str().unwrap_or("?")),
    });
}

#[cfg(all(test, any(target_os = "linux", target_os = "macos", windows)))]
mod tests;
