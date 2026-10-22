//! One explicit selection flow for package content, download caches and managed models.
use clap::Args;
use serde_json::json;
use std::io::IsTerminal;
use std::path::PathBuf;
use std::process::{Command, ExitCode};
use std::time::Duration;
use sweepx_core::managed_cache::{Action, Inventory, Item};
use sweepx_core::{CancellationToken, OutputFormat};
use sweepx_i18n::Locale;
use sweepx_model::{EvidenceValue, HumanSizeUnit, ScanSort};
/// Arguments shared by the tool-specific entry points; exact IDs are selected after inventory.
#[derive(Debug, Args)]
pub(crate) struct Arguments {
    /// Absolute versioned pnpm store or osdk data directory; required for pnpm.
    #[arg(long)]
    pub root: Option<PathBuf>,
    /// Absolute osdk cache directory; defaults to OSDK_CACHE_DIR or osdk's reported configuration.
    #[arg(long)]
    pub cache_root: Option<PathBuf>,
    /// Search installed-project references below this absolute directory (repeatable).
    /// Defaults to the current directory. Build trees and node_modules are not project search roots.
    #[arg(long)]
    pub project_root: Vec<PathBuf>,
    /// Select one pnpm project for a reviewable project/dependency cleanup plan.
    #[arg(long, conflicts_with_all = ["entry", "package", "max_links", "unobserved", "tui", "remove_models"])]
    pub project: Option<PathBuf>,
    /// Keep source and retire dependencies, or retire the entire project. Requires --project.
    #[arg(long, requires = "project", value_parser = ["dependencies", "project"])]
    pub project_mode: Option<String>,
    /// Execute only the matching current project preview digest; requires --project --trash.
    #[arg(long, requires_all = ["project", "trash"])]
    pub plan: Option<String>,
    /// Show one exact package/model name.
    #[arg(long)]
    pub package: Option<String>,
    /// Show packages whose every observed content file has at most this native link count.
    /// Counts are clues, not proof of unused dependencies; clone/copy imports can have one link.
    #[arg(long)]
    pub max_links: Option<u128>,
    /// Show items with no references observed in the stated project search roots.
    #[arg(long)]
    pub unobserved: bool,
    /// Select exact current inventory IDs (repeatable); omitted means read-only inventory.
    #[arg(long, conflicts_with = "tui")]
    pub entry: Vec<String>,
    /// Move selected pnpm content/project targets or osdk download directories to OS Trash.
    /// Package selections keep shared/multi-link files; project mode accounts for its links.
    /// Package indexes remain for tool repair/refetch.
    #[arg(long,conflicts_with_all=["remove_models","tui"])]
    pub trash: bool,
    /// Explicitly remove selected osdk local models through osdk; this is not recoverable Trash.
    /// Declarations/locks stay; sync can download again. The manager can reclaim unreferenced
    /// model content; SweepX does not invoke global prune.
    #[arg(long, conflicts_with = "tui")]
    pub remove_models: bool,
    /// Browse package/model details and select Trash-eligible cache items on a worker.
    /// Model rows show their tool-managed removal command; d never deletes model snapshots.
    #[arg(long)]
    pub tui: bool,
}
/// pnpm-specific commands discover stores and select safe candidates automatically.
#[derive(Debug, Args)]
pub(crate) struct PnpmArguments {
    /// Versioned store or store container; omitted discovers installed/configured/default stores.
    #[arg(long)]
    root: Option<PathBuf>,
    /// Project directory: show installed package bytes, or retire dependencies with --trash.
    #[arg(long, conflicts_with_all = ["entry", "package", "max_links", "unobserved", "tui"])]
    project: Option<PathBuf>,
    /// Extra installed-project reference search scopes (repeatable); defaults are discovered.
    #[arg(long)]
    project_root: Vec<PathBuf>,
    /// Keep source (default dependencies), or explicitly retire the whole project.
    #[arg(long, requires = "project", value_parser = ["dependencies", "project"])]
    project_mode: Option<String>,
    /// Restrict packages by exact name.
    #[arg(long)]
    package: Option<String>,
    /// Restrict observed native links; this alone never proves disuse.
    #[arg(long)]
    max_links: Option<u128>,
    /// Restrict rows to packages unobserved in reference search scopes.
    #[arg(long)]
    unobserved: bool,
    /// Optional advanced selection; ordinary cleanup selects all admitted unused content.
    #[arg(long, conflicts_with = "tui", hide = true)]
    entry: Vec<String>,
    /// Optional legacy preview guard; ordinary cleanup creates its plan internally.
    #[arg(long, requires_all = ["project", "trash"], hide = true)]
    plan: Option<String>,
    /// Move admitted unused store files or project dependencies to recoverable OS Trash.
    #[arg(long, conflicts_with = "tui")]
    trash: bool,
    /// Browse a store and its project package footprints.
    #[arg(long)]
    tui: bool,
}
/// Defaults protect nearby/common project locations; output always declares the observed scope.
fn pnpm_scopes(args: &PnpmArguments) -> Result<Vec<PathBuf>, String> {
    let mut scopes = args.project_root.clone();
    if scopes.is_empty() {
        if let Some(project) = &args.project {
            scopes.push(project.parent().unwrap_or(project).to_path_buf());
        } else {
            scopes.extend(default_pnpm_scopes()?);
        }
    }
    if let Some(project) = &args.project {
        scopes.push(project.clone());
    }
    scopes.sort();
    scopes.dedup();
    let all = scopes.clone();
    scopes.retain(|p| !all.iter().any(|other| other != p && p.starts_with(other)));
    if scopes.len() > 32 || scopes.iter().any(|p| !p.is_absolute()) {
        return Err("absolute_bounded_project_scopes_required".into());
    }
    Ok(scopes)
}
/// Shared default reference scopes. Filesystem discovery belongs on a worker in interactive use.
pub(crate) fn default_pnpm_scopes() -> Result<Vec<PathBuf>, String> {
    let mut scopes = vec![std::env::current_dir().map_err(|e| e.to_string())?];
    if let Some(home) = sweepx_core::junk::platform::user_home_dir() {
        for name in [
            "Desktop/Projects",
            "Projects",
            "projects",
            "workspace",
            "workspaces",
            "dev",
        ] {
            let path = home.join(name);
            if path.is_dir() {
                scopes.push(path);
            }
        }
    }
    scopes.sort();
    scopes.dedup();
    let all = scopes.clone();
    scopes.retain(|p| !all.iter().any(|other| other != p && p.starts_with(other)));
    Ok(scopes)
}
pub(crate) fn run_pnpm(
    args: PnpmArguments,
    format: OutputFormat,
    unit: HumanSizeUnit,
    locale: Locale,
    sort: ScanSort,
) -> ExitCode {
    let cancel = CancellationToken::new();
    let scopes = match pnpm_scopes(&args) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(2);
        }
    };
    if args.root.as_ref().is_some_and(|p| !p.is_absolute())
        || args.max_links == Some(0)
        || args.entry.len() > 256
    {
        eprintln!("Invalid store root or link limit");
        return ExitCode::from(2);
    }
    if let Some(project) = &args.project {
        if !project.is_absolute() {
            eprintln!("absolute_project_required");
            return ExitCode::from(2);
        }
        if !args.trash && args.project_mode.is_none() {
            let (mut projects, complete, issues) =
                sweepx_core::managed_cache::pnpm_projects(std::slice::from_ref(project), &cancel);
            projects.retain(|p| std::path::Path::new(&p.directory).starts_with(project));
            if format == OutputFormat::Human {
                for p in &projects {
                    println!(
                        "{}  {}  complete={} store={} status={}",
                        size(&p.logical_bytes, unit),
                        p.directory,
                        p.size_complete,
                        p.store_dir.as_deref().unwrap_or("?"),
                        p.store_status
                    );
                }
                for e in &issues {
                    eprintln!("{e}");
                }
            } else {
                println!(
                    "{}",
                    json!({"schema":"sweepx.pnpm_projects.result/v1","readOnly":true,"projects":projects,"complete":complete,"issues":issues,"sizeScope":"installed_pnpm_virtual_stores","reclaimableBytes":null})
                );
            }
            return ExitCode::from(if complete { 0 } else { 4 });
        }
    }
    let locations =
        sweepx_core::managed_cache::pnpm_locations(args.root.as_deref(), &scopes, &cancel);
    if locations.stores.is_empty() {
        eprintln!("No pnpm stores discovered: {:?}", locations.issues);
        return ExitCode::from(4);
    }
    let config_for = |root: PathBuf| Config {
        tool: "pnpm",
        cache: root.clone(),
        root,
        projects: scopes.clone(),
        package: args.package.clone(),
        max_links: args.max_links,
        unobserved: args.unobserved,
    };
    if let Some(project) = &args.project {
        let (projects, _, _) =
            sweepx_core::managed_cache::pnpm_projects(std::slice::from_ref(project), &cancel);
        let root = projects
            .iter()
            .find(|p| std::path::Path::new(&p.directory) == project)
            .and_then(|p| p.store_dir.as_ref())
            .map(PathBuf::from);
        let Some(root) = root.filter(|p| locations.stores.contains(p)) else {
            eprintln!("Project store unavailable or does not match --root");
            return ExitCode::from(4);
        };
        return crate::pnpm_project::run(
            &config_for(root),
            crate::pnpm_project::Request {
                project,
                mode: if args.project_mode.as_deref() == Some("project") {
                    sweepx_core::managed_cache::PnpmProjectMode::Project
                } else {
                    sweepx_core::managed_cache::PnpmProjectMode::Dependencies
                },
                expected: args.plan.as_deref(),
                trash: args.trash,
            },
            format,
            unit,
            locale,
        );
    }
    if args.tui {
        if format != OutputFormat::Human
            || !std::io::stdin().is_terminal()
            || !std::io::stdout().is_terminal()
            || locations.stores.len() != 1
        {
            eprintln!("--tui requires an interactive terminal and one store; select --root");
            return ExitCode::from(2);
        }
        return crate::managed_cache_tui::run(
            config_for(locations.stores[0].clone()),
            locale,
            unit,
            sort,
        );
    }
    let observation = sweepx_core::managed_cache::pnpm_observe_projects(&scopes, &cancel);
    let mut stores = Vec::new();
    let mut failed = false;
    let mut partial = !locations.issues.is_empty();
    if format == OutputFormat::Human {
        for issue in &locations.issues {
            eprintln!("{issue}");
        }
    }
    for root in &locations.stores {
        let config = config_for(root.clone());
        let report = sweepx_core::managed_cache::pnpm_inventory_observed(
            &config.root,
            &observation,
            &cancel,
        );
        let selected: Vec<_> = report
            .entries
            .iter()
            .filter(|e| config.visible(e))
            .filter(|e| {
                if args.entry.is_empty() {
                    e.eligible
                } else {
                    args.entry.contains(&e.id)
                }
            })
            .map(|e| e.id.clone())
            .collect();
        let missing = args.entry.iter().any(|id| !selected.contains(id));
        let results = if missing {
            Err("selected_item_missing_or_ineligible".into())
        } else if args.trash && !report.complete {
            Err("complete_inventory_required".into())
        } else if args.trash && !selected.is_empty() {
            execute(&config, &report, &selected, false, &cancel)
        } else {
            Ok(Vec::new())
        };
        failed |= results.is_err()
            || results
                .as_ref()
                .is_ok_and(|r| r.iter().any(|r| r["completed"] != true));
        partial |= !report.complete;
        if format == OutputFormat::Human {
            println!("Store: {}", report.root);
            println!(
                "Admitted unused packages: {}; unique cleanup content: {} (logical)",
                selected.len(),
                size(&report.selected_pnpm_bytes(&selected), unit)
            );
            for e in report.entries.iter().filter(|e| config.visible(e)) {
                println!(
                    "{}  {}@{}  projects={} eligible={}",
                    size(&e.logical_bytes, unit),
                    e.name,
                    e.version.as_deref().unwrap_or("?"),
                    e.projects.len(),
                    e.eligible
                );
            }
            let mut projects: Vec<_> = report.projects.iter().collect();
            projects.sort_by_key(|a| std::cmp::Reverse(value_bytes(&a.logical_bytes)));
            for p in projects {
                println!(
                    "pnpm packages: {}  {}  complete={}",
                    size(&p.logical_bytes, unit),
                    p.directory,
                    p.size_complete
                );
            }
            for issue in &report.issues {
                eprintln!("{issue}");
            }
            match &results {
                Ok(rows) => println!(
                    "Trash moves: {}",
                    rows.iter()
                        .find(|r| r["kind"] == "summary")
                        .and_then(|r| r["completedMoves"].as_u64())
                        .unwrap_or_else(
                            || rows.iter().filter(|r| r["completed"] == true).count() as u64
                        )
                ),
                Err(e) => eprintln!("{e}"),
            }
        }
        stores.push(json!({"inventory":report,"cleanupLogicalBytes":report.selected_pnpm_bytes(&selected),"selection":selected,"results":results.as_ref().ok(),"blocked":results.as_ref().err()}));
    }
    if format != OutputFormat::Human {
        let mut output = json!({"schema":"sweepx.managed_cache.result/v1","readOnly":!args.trash,"stores":stores,"discoveryIssues":locations.issues,"recoverable":true,"reclaimableBytes":null,"status":if failed {"blocked_or_partial"} else if partial {"partial"} else {"ok"}});
        if stores.len() == 1 {
            for key in [
                "inventory",
                "selection",
                "results",
                "blocked",
                "cleanupLogicalBytes",
            ] {
                output[key] = stores[0][key].clone();
            }
        }
        println!("{output}");
    }
    ExitCode::from(if failed {
        8
    } else if partial {
        4
    } else {
        0
    })
}
fn value_bytes(value: &sweepx_model::ByteValue) -> Option<u128> {
    match value {
        EvidenceValue::Known { value } | EvidenceValue::LowerBound { value, .. } => Some(value.0),
        _ => None,
    }
}
#[derive(Clone)]
pub(crate) struct Config {
    pub tool: &'static str,
    pub root: PathBuf,
    pub cache: PathBuf,
    pub projects: Vec<PathBuf>,
    pub package: Option<String>,
    pub max_links: Option<u128>,
    pub unobserved: bool,
}
impl Config {
    pub fn inventory(&self, cancel: &CancellationToken) -> Inventory {
        if self.tool == "pnpm" {
            sweepx_core::managed_cache::pnpm_inventory(&self.root, &self.projects, cancel)
        } else {
            sweepx_core::managed_cache::osdk_inventory(
                &self.root,
                &self.cache,
                &self.projects,
                cancel,
            )
        }
    }
    pub fn visible(&self, item: &Item) -> bool {
        self.package.as_ref().is_none_or(|n| item.name == *n)
            && self
                .max_links
                .is_none_or(|n| item.max_links.is_some_and(|m| m <= n))
            && (!self.unobserved || item.projects.is_empty())
    }
}
pub(crate) fn run(
    tool: &'static str,
    args: Arguments,
    format: OutputFormat,
    unit: HumanSizeUnit,
    locale: Locale,
    sort: ScanSort,
) -> ExitCode {
    if args.tui
        && (format != OutputFormat::Human
            || !std::io::stdin().is_terminal()
            || !std::io::stdout().is_terminal())
    {
        eprintln!("--tui requires human output and an interactive terminal");
        return ExitCode::from(2);
    }
    let Some(root) = args.root.or_else(|| {
        if tool == "osdk" {
            default_osdk(false)
        } else {
            None
        }
    }) else {
        eprintln!(
            "{}",
            if tool == "pnpm" {
                "pnpm requires --root pointing at the exact versioned store directory"
            } else {
                "OSDK locations unavailable; provide absolute --root and --cache-root"
            }
        );
        return ExitCode::from(2);
    };
    let cache = args
        .cache_root
        .or_else(|| {
            if tool == "osdk" {
                default_osdk(true)
            } else {
                None
            }
        })
        .or_else(|| (tool == "pnpm").then(|| root.clone()));
    let Some(cache) = cache else {
        eprintln!("OSDK cache location unavailable; provide absolute --cache-root");
        return ExitCode::from(2);
    };
    if args.project.is_some() && (tool != "pnpm" || args.project_root.is_empty()) {
        eprintln!("Project cleanup requires pnpm-store and explicit --project-root search scopes");
        return ExitCode::from(2);
    }
    let projects = if args.project_root.is_empty() {
        match std::env::current_dir() {
            Ok(p) => vec![p],
            Err(e) => {
                eprintln!("{e}");
                return ExitCode::from(2);
            }
        }
    } else {
        args.project_root
    };
    if !root.is_absolute()
        || !cache.is_absolute()
        || projects.iter().any(|p| !p.is_absolute())
        || projects.len() > 32
        || args.entry.len() > 256
        || args.max_links == Some(0)
        || (tool == "pnpm" && args.remove_models)
    {
        eprintln!("Invalid roots, limits or action for this tool");
        return ExitCode::from(2);
    }
    let config = Config {
        tool,
        root,
        cache,
        projects,
        package: args.package,
        max_links: args.max_links,
        unobserved: args.unobserved,
    };
    if let Some(project) = args.project {
        let mode = if args.project_mode.as_deref() == Some("project") {
            sweepx_core::managed_cache::PnpmProjectMode::Project
        } else {
            sweepx_core::managed_cache::PnpmProjectMode::Dependencies
        };
        return crate::pnpm_project::run(
            &config,
            crate::pnpm_project::Request {
                project: &project,
                mode,
                expected: args.plan.as_deref(),
                trash: args.trash,
            },
            format,
            unit,
            locale,
        );
    }
    if args.tui {
        return crate::managed_cache_tui::run(config, locale, unit, sort);
    }
    let cancel = CancellationToken::new();
    let report = config.inventory(&cancel);
    let visible: Vec<_> = report
        .entries
        .iter()
        .filter(|e| config.visible(e))
        .collect();
    let chosen: Vec<_> = visible
        .iter()
        .copied()
        .filter(|e| args.entry.contains(&e.id))
        .collect();
    if args
        .entry
        .iter()
        .any(|id| !chosen.iter().any(|e| &e.id == id))
        || ((args.trash || args.remove_models) && chosen.is_empty())
        || chosen.iter().any(|e| {
            (args.trash && e.action == Action::OsdkModelRemove)
                || (args.remove_models && e.action != Action::OsdkModelRemove)
        })
    {
        eprintln!(
            "Select visible current IDs with --entry; use --trash for caches or --remove-models for model rows"
        );
        return ExitCode::from(2);
    }
    let results = if args.trash || args.remove_models {
        execute(&config, &report, &args.entry, args.remove_models, &cancel)
    } else {
        Ok(Vec::new())
    };
    let failed = results.is_err()
        || results
            .as_ref()
            .is_ok_and(|rows| rows.iter().any(|r| r["completed"] != true));
    if format == OutputFormat::Human {
        println!(
            "{}",
            if locale == Locale::ZhCn {
                "项目引用仅覆盖下列搜索范围；文件大小和链接数不代表实际可释放空间："
            } else {
                "Project references cover these search roots only; file size and link counts do not prove freed space:"
            }
        );
        for p in &report.project_roots {
            println!("  {p}")
        }
        for item in visible {
            println!(
                "{}  {}  {}@{}  links={} single={} projects={} eligible={}",
                size(&item.logical_bytes, unit),
                item.id,
                item.name,
                item.version.as_deref().unwrap_or("?"),
                link_range(item.min_links, item.max_links),
                item.single_link_files,
                item.projects.len(),
                item.eligible
            );
            println!("{}", details(item, &report, unit, locale));
        }
        for issue in &report.issues {
            eprintln!("{issue}")
        }
        match &results {
            Ok(r) => {
                for row in r {
                    println!("{row}")
                }
            }
            Err(e) => eprintln!("{e}"),
        };
    } else {
        println!(
            "{}",
            json!({"schema":"sweepx.managed_cache.result/v1","readOnly":!args.trash&&!args.remove_models,"inventory":report,"selection":args.entry,"results":results.as_ref().ok(),"blocked":results.as_ref().err(),"recoverable":!args.remove_models,"reclaimableBytes":null,"status":if failed{"blocked_or_partial"}else if report.complete{"ok"}else{"partial"}})
        );
    }
    ExitCode::from(if failed {
        8
    } else if !report.complete {
        4
    } else {
        0
    })
}
pub(crate) fn execute(
    config: &Config,
    previous: &Inventory,
    ids: &[String],
    models: bool,
    cancel: &CancellationToken,
) -> Result<Vec<serde_json::Value>, String> {
    if ids.is_empty() || (config.tool != "pnpm" && ids.len() > 256) {
        return Err("explicit_bounded_selection_required".into());
    }
    let activity = if config.tool == "pnpm" {
        config.root.as_path()
    } else {
        config.cache.as_path()
    };
    if config.tool == "pnpm" {
        sweepx_core::tools::scoped_activity::check_scopes(&[activity], cancel)?;
    }
    if config.tool == "pnpm" {
        if models {
            return Err("not_osdk_models".into());
        }
        let mut results = Vec::new();
        let mut completed = 0u64;
        let mut ordinal = 0usize;
        let mut last_check = std::time::Instant::now();
        let outcome = sweepx_core::managed_cache::pnpm_cleanup_batches(
            previous,
            ids,
            cancel,
            &mut |batch| {
                for file in batch {
                    let result = (|| -> Result<(), String> {
                        if cancel.is_cancelled() {
                            return Err("cancelled".into());
                        }
                        if ordinal.is_multiple_of(64)
                            || last_check.elapsed() >= Duration::from_secs(1)
                        {
                            sweepx_core::tools::scoped_activity::check_scopes(&[activity], cancel)?;
                            last_check = std::time::Instant::now();
                        }
                        let current =
                            sweepx_core::managed_cache::revalidate_pnpm_file(file, cancel)?;
                        crate::trash_command::trash_observed_file(&current, None, None, cancel)
                    })();
                    ordinal += 1;
                    if result.is_ok() {
                        completed += 1;
                    }
                    if results.len() < 256 || result.is_err() {
                        results.push(json!({"path":file.display_path,"completed":result.is_ok(),"error":result.as_ref().err()}));
                    }
                    result?;
                }
                Ok(())
            },
        );
        // Keep successful work visible even if a later plan batch fails. Large runs retain a
        // sample plus exact operation counts, avoiding an unbounded per-file machine report.
        if let Err(e) = &outcome {
            results.push(json!({"completed":false,"error":e}));
        }
        results.push(json!({"kind":"summary","completed":outcome.is_ok(),"completedMoves":completed,"attemptedMoves":ordinal,"pathsTruncated":ordinal > 256}));
        return Ok(results);
    }
    let current = config.inventory(cancel);
    if !current.complete {
        return Err("complete_current_inventory_required".into());
    }
    let chosen: Vec<_> = current
        .entries
        .iter()
        .filter(|e| ids.contains(&e.id))
        .collect();
    if chosen.len() != ids.len()
        || chosen.iter().any(|e| {
            !e.eligible || !config.visible(e) || !previous.entries.iter().any(|p| p.id == e.id)
        })
    {
        return Err("selection_changed_or_ineligible".into());
    }
    let mut results = Vec::new();
    {
        let mut runner = sweepx_core::tools::ProbeRunner::new(
            sweepx_core::tools::ProbeLimits {
                total_timeout: Duration::from_secs(120),
                probe_timeout: Duration::from_secs(30),
                max_processes: 256,
                max_stdout_bytes: 1024 * 1024,
            },
            cancel.clone(),
        );
        for item in chosen {
            let result = (|| -> Result<(), String> {
                let source = item.source_entry().ok_or("missing_native_unit")?;
                let unit_scope = crate::trash_command::path_from_live_locator(source)
                    .map_err(|e| e.to_string())?;
                sweepx_core::tools::scoped_activity::check_scopes(&[unit_scope.as_path()], cancel)?;
                if models {
                    if item.action != Action::OsdkModelRemove {
                        return Err("not_model_item".into());
                    }
                    item.revalidate_model(cancel)?;
                    let data = current.revalidated_root_path(cancel)?;
                    let out = runner
                        .run_authorized_operation(
                            Command::new("osdk")
                                .args(["--offline", "--yes", "model", "remove", "--", &item.name])
                                .env("OSDK_DATA_DIR", data),
                        )
                        .map_err(|e| format!("operation_state_uncertain: {e}"))?;
                    if !out.status.success() {
                        return Err(format!(
                            "model_remove_failed_state_uncertain: {}",
                            out.status
                        ));
                    }
                    Ok(())
                } else {
                    if item.action != Action::TrashDirectory {
                        return Err("model_requires_remove_models".into());
                    }
                    let entry = item.source_entry().ok_or("missing_native_unit")?;
                    let candidate = crate::trash_command::TrashCandidate::from_scanned_entry(entry)
                        .map_err(|e| e.to_string())?;
                    if candidate.requires_confirmation() {
                        return Err("important_path_refused".into());
                    }
                    candidate.submit().map_err(|e| e.to_string())
                }
            })();
            let failed = result.is_err();
            results.push(
                json!({"id":item.id,"completed":!failed,"error":result.err(),"action":item.action}),
            );
            if failed {
                break;
            }
        }
    }
    Ok(results)
}
pub(crate) fn size(value: &sweepx_model::ByteValue, unit: HumanSizeUnit) -> String {
    match value {
        EvidenceValue::Known { value } => unit.format(value.0),
        EvidenceValue::LowerBound { value, .. } => format!("≥ {}", unit.format(value.0)),
        _ => "?".into(),
    }
}
pub(crate) fn link_range(min: Option<u128>, max: Option<u128>) -> String {
    let label = |value: Option<u128>| value.map_or_else(|| "?".into(), |n| n.to_string());
    format!("{}–{}", label(min), label(max))
}
pub(crate) fn details(
    item: &Item,
    report: &Inventory,
    unit: HumanSizeUnit,
    locale: Locale,
) -> String {
    let mut text = format!(
        "{}\n{}\nallocated={} missing={}\n",
        item.rule_id,
        item.path,
        size(&item.allocated_bytes, unit),
        item.missing_files
    );
    for &i in &item.projects {
        if let Some(p) = report.projects.get(i) {
            text.push_str(&format!(
                "{}  {}={} complete={} store={}\n",
                p.directory,
                if report.tool == "pnpm" {
                    "pnpm packages"
                } else {
                    "total"
                },
                size(&p.logical_bytes, unit),
                p.size_complete,
                p.store_dir.as_deref().unwrap_or("?")
            ));
            if report.tool == "pnpm" && p.store_dir.as_deref() == Some(report.root.as_str()) {
                text.push_str(if locale == Locale::ZhCn {
                    "项目清理预览（保留源码 / 整个项目）：\n"
                } else {
                    "Project cleanup previews (keep source / whole project):\n"
                });
                for mode in ["dependencies", "project"] {
                    text.push_str(&format!(
                        "sweepx pnpm-store --project {} --project-mode {}\n",
                        quote_cli_arg(&p.directory),
                        mode
                    ));
                }
            }
        }
    }
    if item.action == Action::OsdkModelRemove {
        // Keep the displayed command scoped to this root and stable selection token. A bare
        // manager name could otherwise target a same-named alias in the user's default store.
        text.push_str(&format!(
            "sweepx osdk-cache --root {} --entry {} --remove-models\n",
            quote_cli_arg(&report.root),
            item.id
        ));
        text.push_str(if locale==Locale::ZhCn{"移除本地模型；声明和锁文件保留，后续同步可能重新下载。管理器可能回收无引用模型内容；SweepX 不执行全局 prune。\n"}else{"Remove local models; declarations/locks stay and sync may download again. The manager may reclaim unreferenced model content; SweepX does not run global prune.\n"})
    }
    text.push_str(&item.issues.join("\n"));
    text
}
fn quote_cli_arg(value: &str) -> String {
    #[cfg(windows)]
    {
        format!("'{}'", value.replace('\'', "''"))
    }
    #[cfg(not(windows))]
    {
        format!("'{}'", value.replace('\'', "'\\''"))
    }
}
fn default_osdk(cache: bool) -> Option<PathBuf> {
    if let Some(p) = std::env::var_os(if cache {
        "OSDK_CACHE_DIR"
    } else {
        "OSDK_DATA_DIR"
    }) {
        return Some(p.into());
    }
    let mut runner = sweepx_core::tools::ProbeRunner::new(
        sweepx_core::tools::ProbeLimits::default(),
        CancellationToken::new(),
    );
    let output = runner
        .run(Command::new("osdk").args(["--offline", "config", "list"]))
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8(output.stdout).ok()?;
    text.lines()
        .find_map(|l| {
            l.split_once('=')
                .filter(|(k, _)| k.trim() == if cache { "cache_dir" } else { "data_dir" })
                .map(|(_, v)| PathBuf::from(v.trim()))
        })
        .filter(|p| p.is_absolute())
}
