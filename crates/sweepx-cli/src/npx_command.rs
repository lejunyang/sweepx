use crate::trash_command::TrashCandidate;
use serde_json::json;
use std::path::Path;
use std::process::ExitCode;
use sweepx_core::{CancellationToken, OutputFormat};
use sweepx_i18n::Locale;
use sweepx_model::HumanSizeUnit;

#[allow(clippy::too_many_arguments)]
pub(crate) fn run(
    root: &Path,
    package: Option<&str>,
    selected: &[String],
    older: bool,
    apply: bool,
    format: OutputFormat,
    unit: HumanSizeUnit,
    locale: Locale,
) -> ExitCode {
    let zh = locale == Locale::ZhCn;
    let cancel = CancellationToken::new();
    let inventory = sweepx_core::npx::inventory(root, &cancel);
    let visible: Vec<_> = inventory
        .entries
        .iter()
        .filter(|r| package.is_none_or(|p| r.packages.iter().any(|v| v.name == p)))
        .collect();
    let plan: Vec<_> = visible
        .iter()
        .copied()
        .filter(|r| (older && r.older_version) || selected.contains(&r.id))
        .collect();
    if selected.iter().any(|id| !plan.iter().any(|r| &r.id == id)) || (apply && plan.is_empty()) {
        eprintln!(
            "{}",
            if zh {
                "使用 --entry 选择当前安装编号，或用 --older-versions 预览旧版本；加 --trash 执行回收。"
            } else {
                "Select current slot IDs with --entry, or use --older-versions; --trash applies that plan."
            }
        );
        return ExitCode::from(2);
    }
    if format == OutputFormat::Human {
        for row in &visible {
            let size = row
                .bytes
                .as_deref()
                .and_then(|b| b.parse::<u128>().ok())
                .map(|b| unit.format(b))
                .unwrap_or_else(|| "?".into());
            let packages = row
                .packages
                .iter()
                .map(|p| format!("{}@{}", p.name, p.version.as_deref().unwrap_or("?")))
                .collect::<Vec<_>>()
                .join(", ");
            println!(
                "{:>12}  {}  {}{}{}",
                size,
                row.id,
                packages,
                if row.older_version {
                    if zh { " [旧版本]" } else { " [older]" }
                } else {
                    ""
                },
                if plan.iter().any(|r| r.id == row.id) {
                    if zh { " [已选择]" } else { " [selected]" }
                } else {
                    ""
                }
            );
            for issue in &row.issues {
                eprintln!("{}: {issue}", row.id);
            }
        }
        println!(
            "{}",
            if zh {
                "大小包含整套安装及依赖；回收单位为完整安装目录。--older-versions 保留最高已安装版本。"
            } else {
                "Sizes include the complete installation and dependencies; selecting a package moves its whole slot. Highest installed versions are retained by --older-versions."
            }
        );
    }
    let mut results = Vec::new();
    let mut blocked = None;
    if apply {
        let scopes: Result<Vec<_>, _> = plan
            .iter()
            .map(|r| crate::trash_command::path_from_live_locator(r.source_entry()))
            .collect();
        match &scopes {
            Ok(paths) => {
                if let Err(e) = sweepx_core::tools::scoped_activity::check_scopes(
                    &paths.iter().map(|p| p.as_path()).collect::<Vec<_>>(),
                    &cancel,
                ) {
                    blocked = Some(e);
                }
            }
            Err(e) => blocked = Some(e.to_string()),
        }
        if blocked.is_none() {
            for row in &plan {
                // Process observations are time-local; validate selected native manifests and
                // lineage again. Trash performs the final identity check; no permanent fallback.
                let result = (|| {
                    let scope = crate::trash_command::path_from_live_locator(row.source_entry())
                        .map_err(|e| e.to_string())?;
                    sweepx_core::tools::scoped_activity::check_scopes(&[scope.as_path()], &cancel)?;
                    row.revalidate(&cancel)?;
                    let candidate = TrashCandidate::from_scanned_entry(row.source_entry())
                        .map_err(|e| e.to_string())?;
                    if candidate.requires_confirmation() {
                        return Err("important_path_refused".into());
                    }
                    candidate.submit().map_err(|e| e.to_string())
                })();
                results.push(json!({"id":row.id,"moved":result.is_ok(),"error":result.err()}));
            }
        }
    }
    let failed = blocked.is_some() || results.iter().any(|r| r["moved"] != true);
    if format != OutputFormat::Human {
        println!(
            "{}",
            json!({"schema":"sweepx.npx_cache.result/v1","readOnly":!apply,"sizeKind":"logical","inventory":inventory,"selection":plan.iter().map(|r|r.id.as_str()).collect::<Vec<_>>(),"results":results,"blocked":blocked,"recoverable":true,"permanentDeletion":false,"activityScope":"current_user_processes_time_local","status":if failed {"blocked_or_partial"} else if inventory.complete {"ok"} else {"partial"}})
        );
    } else {
        if let Some(e) = &blocked {
            eprintln!("Not moved: {e}");
        }
        for result in &results {
            println!(
                "{}: {}",
                result["id"],
                if result["moved"] == true {
                    if zh {
                        "已放入回收站".into()
                    } else {
                        "moved to Trash".into()
                    }
                } else {
                    result["error"].to_string()
                }
            );
        }
    }
    ExitCode::from(if failed {
        8
    } else if !inventory.complete {
        4
    } else {
        0
    })
}
