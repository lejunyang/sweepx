//! Project retirement is a preview-bound vertical slice over the existing inventory and Trash seam.
use crate::managed_cache::Config;
use serde_json::{Value, json};
use std::path::Path;
use std::process::ExitCode;
use sweepx_core::managed_cache::{PnpmProjectMode, PnpmProjectPlan};
use sweepx_core::{CancellationToken, OutputFormat};
use sweepx_i18n::Locale;
use sweepx_model::HumanSizeUnit;

pub(crate) struct Request<'a> {
    pub project: &'a Path,
    pub mode: PnpmProjectMode,
    pub expected: Option<&'a str>,
    pub trash: bool,
}
pub(crate) fn run(
    config: &Config,
    request: Request<'_>,
    format: OutputFormat,
    unit: HumanSizeUnit,
    locale: Locale,
) -> ExitCode {
    let Request {
        project,
        mode,
        expected,
        trash,
    } = request;
    let cancel = CancellationToken::new();
    let inventory =
        sweepx_core::managed_cache::pnpm_project_inventory(&config.root, &config.projects, &cancel);
    let plan = sweepx_core::managed_cache::pnpm_project_plan(&inventory, project, mode, &cancel);
    let mut results = Vec::new();
    let mut error = plan.as_ref().err().cloned();
    if trash && error.is_none() {
        match expected {
            None => error = Some("project_preview_digest_required_use_plan".into()),
            Some(id) if plan.as_ref().is_ok_and(|p| p.id != id) => {
                error = Some("project_plan_changed_refresh_preview".into())
            }
            Some(_) => {
                if let Err(e) = execute(
                    config,
                    plan.as_ref().expect("plan checked"),
                    &cancel,
                    &mut results,
                ) {
                    error = Some(e);
                }
            }
        }
    }
    if format == OutputFormat::Human {
        println!(
            "{}",
            if locale == Locale::ZhCn {
                "项目清理预览：引用仅覆盖指定搜索范围；所有移动进入回收站，大小不代表可释放空间。"
            } else {
                "Project cleanup preview: references cover the stated search scope; all moves use recoverable Trash, sizes are not reclaimable space."
            }
        );
        if let Ok(p) = &plan {
            println!(
                "project={} mode={:?}\nplan={}\ndependencies={}",
                p.project,
                p.mode,
                p.id,
                crate::managed_cache::size(&p.dependency_logical_bytes, unit)
            );
            for path in &p.directory_paths {
                println!("directory: {path}");
            }
            println!(
                "store files: {}; retained files: {}; shared package versions: {}",
                p.content_paths.len(),
                p.retained_content_files,
                p.shared_packages.len()
            );
            for path in p.content_paths.iter().take(20) {
                println!("store: {path}");
            }
            if p.content_paths.len() > 20 {
                println!("... use --format json for all admitted paths");
            }
            if !trash {
                println!(
                    "{}",
                    if locale == Locale::ZhCn {
                        "核对预览后，使用相同参数加 --plan 上述摘要 --trash 执行。"
                    } else {
                        "After review, repeat these arguments with --plan DIGEST --trash."
                    }
                );
            }
        }
        for result in &results {
            println!("{result}");
        }
        if let Some(e) = &error {
            eprintln!("{e}");
        }
    } else {
        println!(
            "{}",
            json!({"schema":"sweepx.pnpm_project.result/v1","readOnly":!trash,
            "plan":plan.as_ref().ok(),"inventoryComplete":inventory.complete,"inventoryIssues":inventory.issues,
            "results":results,"blocked":error,"recoverable":true,"permanentFallback":false,"reclaimableBytes":null,
            "status":if error.is_some() {"blocked_or_partial"} else {"ok"}})
        );
    }
    ExitCode::from(if error.is_some() {
        if trash { 8 } else { 4 }
    } else {
        0
    })
}
fn activity(
    config: &Config,
    plan: &PnpmProjectPlan,
    cancel: &CancellationToken,
) -> Result<(), String> {
    // A copied/clone-imported project can use dependencies without holding store handles.
    let mut paths = vec![config.root.as_path(), Path::new(&plan.project)];
    paths.extend(plan.directory_paths.iter().map(Path::new));
    sweepx_core::tools::scoped_activity::check_scopes(&paths, cancel)
}
fn execute(
    config: &Config,
    plan: &PnpmProjectPlan,
    cancel: &CancellationToken,
    results: &mut Vec<Value>,
) -> Result<(), String> {
    activity(config, plan, cancel)?;
    // Preflight every directory before any mutation. A guarded target cannot strand the caller
    // with an already-retired store when the project-side scope was never eligible.
    for entry in plan.directories() {
        sweepx_core::managed_cache::revalidate_project_directory(entry, cancel)?;
        let candidate = crate::trash_command::TrashCandidate::from_scanned_entry(entry)
            .map_err(|e| e.to_string())?;
        if candidate.requires_confirmation() {
            return Err("important_project_path_refused".into());
        }
    }
    for entry in plan.directories() {
        activity(config, plan, cancel)?;
        let outcome = (|| {
            sweepx_core::managed_cache::revalidate_project_directory(entry, cancel)?;
            crate::trash_command::TrashCandidate::from_scanned_entry(entry)
                .map_err(|e| e.to_string())?
                .submit()
                .map_err(|e| e.to_string())
        })();
        record(results, &entry.display_path, "directory", &outcome);
        outcome?;
    }
    let mut checked_at = std::time::Instant::now();
    for (i, file) in plan.content().iter().enumerate() {
        let outcome = (|| {
            if i % 64 == 0 || checked_at.elapsed().as_secs() >= 1 {
                // Project-side paths are now absent; store activity remains relevant to CAS moves.
                sweepx_core::tools::scoped_activity::check_scopes(
                    &[config.root.as_path()],
                    cancel,
                )?;
                checked_at = std::time::Instant::now();
            }
            let current = sweepx_core::managed_cache::revalidate_project_content(file, cancel)?;
            crate::trash_command::trash_observed_file(&current, None, None, cancel)
        })();
        record(results, &file.display_path, "store_content", &outcome);
        outcome?;
    }
    Ok(())
}
fn record(results: &mut Vec<Value>, path: &str, action: &str, outcome: &Result<(), String>) {
    results.push(json!({"path":path,"action":action,"completed":outcome.is_ok(),"error":outcome.as_ref().err()}));
}
