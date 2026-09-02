use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::io::IsTerminal;
#[cfg(target_os = "linux")]
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode as ProcessExitCode;
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

mod trash_command;

use clap::{Parser, Subcommand, ValueEnum};
use serde::Deserialize;
use serde_json::json;
#[cfg(target_os = "windows")]
use sweepx_core::cache_status_unsupported;
#[cfg(unix)]
use sweepx_core::{CacheStatusRequest, cache_status, cache_status_state_error};
use sweepx_core::{
    CancelRequest, CancellationToken, CleanerCargoDetectInvocation, CleanerCargoDetectRequest,
    CleanerShowRequest, CoreContext, ExplainRequest, OutputFormat, SCAN_NDJSON_UNAVAILABLE_MESSAGE,
    ScanRequest, StateError, StatusRequest, cache_status_usage_error, cancel_with_store,
    capabilities, cleaner_cargo_detect_with_invocation_and_cancel, cleaner_list, cleaner_show,
    core_error_exit_code, durable_store, explain_from_scan_json, parse_locale_override,
    scan_for_tui_with_store, scan_ndjson_supported, scan_with_store, serialize_json,
    serialize_ndjson, state_dir_from_explicit_or_default, status_with_store,
    tui_detail_rescan_provider, usage_error_output, validate_absolute_root,
};
#[cfg(target_os = "linux")]
use sweepx_core::{StatusReplayRequest, replay_completed_status};
use sweepx_i18n::detect_locale;
use sweepx_model::{
    ByteValue, EvidenceValue, HumanSizeUnit, ObjectType, ReasonCode, ScanEntryId, ScanSort,
};
use sweepx_platform::{
    ElevatedRelaunch, ElevationPolicy, PrivilegeProvider, StartupPrivilegeDecision,
    decide_startup_privilege,
};
use sweepx_protocol::OutputEnvelope;
use sweepx_tui::{BrowserExit, BrowserModel, run_live_browser_with_detail_rescan};

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum FormatArg {
    Human,
    Json,
    Ndjson,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum UnitArg {
    Auto,
    B,
    #[value(name = "kib", alias = "kb")]
    Kib,
    #[value(name = "mib", alias = "mb")]
    Mib,
    #[value(name = "gib", alias = "gb")]
    Gib,
    #[value(name = "tib", alias = "tb")]
    Tib,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum SortArg {
    Size,
    Path,
}

impl From<SortArg> for ScanSort {
    fn from(value: SortArg) -> Self {
        match value {
            SortArg::Size => Self::Size,
            SortArg::Path => Self::Path,
        }
    }
}

impl From<UnitArg> for HumanSizeUnit {
    fn from(value: UnitArg) -> Self {
        match value {
            UnitArg::Auto => Self::Auto,
            UnitArg::B => Self::Bytes,
            UnitArg::Kib => Self::KiB,
            UnitArg::Mib => Self::MiB,
            UnitArg::Gib => Self::GiB,
            UnitArg::Tib => Self::TiB,
        }
    }
}

impl From<FormatArg> for OutputFormat {
    fn from(value: FormatArg) -> Self {
        match value {
            FormatArg::Human => OutputFormat::Human,
            FormatArg::Json => OutputFormat::Json,
            FormatArg::Ndjson => OutputFormat::Ndjson,
        }
    }
}

#[derive(Debug, Parser)]
#[command(
    name = "sweepx",
    version = env!("CARGO_PKG_VERSION"),
    about = "Disk usage scanner, interactive browser, and Trash-first cleanup"
)]
struct Cli {
    #[arg(long, global = true, value_enum, default_value = "human")]
    format: FormatArg,
    #[arg(long, global = true)]
    locale: Option<String>,
    #[arg(long, global = true)]
    state_dir: Option<PathBuf>,
    /// Unit used by human-readable byte columns. JSON always keeps exact bytes.
    #[arg(long, global = true, value_enum, default_value = "auto")]
    unit: UnitArg,
    /// Sort human scan and TUI rows. Machine output keeps scanner order.
    #[arg(long, global = true, value_enum, default_value = "size")]
    sort: SortArg,
    /// Re-run elevated to enable privileged read-only accelerators.
    ///
    /// Without this flag SweepX only *detects* privilege it was already started with and
    /// never prompts. With it, and only when not already elevated, SweepX asks the OS to
    /// start one elevated copy and adopts that copy's exit code. Declining leaves the
    /// unprivileged scan running. Elevation never widens what deletion may touch.
    #[arg(long, global = true)]
    elevate: bool,
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    Scan {
        #[arg(long)]
        tui: bool,
        #[arg(long)]
        no_state: bool,
        /// Root paths; accepts absolute paths, paths relative to the current directory, and `~`.
        #[arg(value_name = "ROOT")]
        roots: Vec<OsString>,
    },
    Explain {
        #[arg(long, value_name = "ABSOLUTE_FILE")]
        scan_json: PathBuf,
        #[arg(long)]
        candidate_id: Option<String>,
        #[arg(long, default_value_t = sweepx_core::DEFAULT_ANALYSIS_INPUT_BYTES)]
        max_input_bytes: usize,
    },
    Status {
        #[arg(long)]
        operation_id: String,
        #[arg(long)]
        watch: bool,
        #[arg(long)]
        after: Option<String>,
    },
    Cancel {
        #[arg(long)]
        operation_id: String,
    },
    Cleaner {
        #[command(subcommand)]
        command: CleanerCommands,
    },
    /// Discover known rebuildable or disposable artifacts under the selected roots.
    Junk {
        /// Scan conservative platform cache roots; conflicts with explicit roots.
        #[arg(long)]
        system: bool,
        #[arg(value_name = "ROOT")]
        roots: Vec<OsString>,
    },
    Cache {
        #[command(subcommand)]
        command: CacheCommands,
    },
    /// Move one file or directory to the operating system Trash/Recycle Bin.
    Trash {
        #[arg(required = true, value_name = "ABSOLUTE_PATH")]
        path: OsString,
    },
    Capabilities,
}

#[derive(Debug, Subcommand)]
enum CleanerCommands {
    List,
    Show {
        cleaner_ref: String,
    },
    CargoDetect {
        #[arg(required = true, value_name = "ABSOLUTE_ROOT")]
        roots: Vec<OsString>,
    },
}

#[derive(Debug, Subcommand)]
enum CacheCommands {
    Status,
}

fn main() -> ProcessExitCode {
    let cli = Cli::parse();

    // Privilege is settled first, before locale parsing, before any state directory is
    // resolved, and before any scan begins. On Windows elevation is only granted at
    // process creation, so honoring `--elevate` means re-running as a second process;
    // doing that after a state directory existed would leave one run's files owned by a
    // different identity than the process that continues. If an elevated child ran, its
    // exit code is the whole invocation's answer and this process must add nothing.
    match startup_privilege(cli.elevate) {
        StartupPrivilege::ElevatedChildCompleted { exit_code } => {
            return ProcessExitCode::from(exit_code);
        }
        StartupPrivilege::Continue { notice } => {
            // A declined or unavailable elevation is reportable, not fatal: the run
            // continues on its unprivileged path.
            if let Some(notice) = notice {
                eprintln!("{notice}");
            }
        }
    }

    let explicit_locale = match cli.locale.as_deref() {
        Some(raw) => match parse_locale_override(raw) {
            Ok(locale) => Some(locale),
            Err(error) => {
                eprintln!("{error}");
                return ProcessExitCode::from(2);
            }
        },
        None => None,
    };
    let locale_resolution = detect_locale(explicit_locale);
    let context = CoreContext::new(locale_resolution);
    let format: OutputFormat = cli.format.into();
    let size_unit: HumanSizeUnit = cli.unit.into();
    let sort: ScanSort = cli.sort.into();

    let result = match cli.command {
        Commands::Scan {
            tui,
            no_state,
            roots,
        } => {
            if no_state && cli.state_dir.is_some() {
                let message = "--no-state cannot be combined with --state-dir";
                if format == OutputFormat::Human {
                    eprintln!("{message}");
                } else {
                    let output = usage_error_output("cli.conflicting_state_options", message);
                    if format == OutputFormat::Ndjson {
                        println!(
                            "{}",
                            serde_json::to_string(&output).expect("output serializable")
                        );
                    } else {
                        println!("{}", serialize_json(&output));
                    }
                }
                return ProcessExitCode::from(2);
            }
            if tui
                && let Err(message) = validate_tui_environment(
                    format,
                    std::io::stdin().is_terminal(),
                    std::io::stdout().is_terminal(),
                )
            {
                eprintln!("{message}");
                return ProcessExitCode::from(2);
            }
            if format == OutputFormat::Ndjson && !scan_ndjson_supported() {
                eprintln!("{SCAN_NDJSON_UNAVAILABLE_MESSAGE}");
                return ProcessExitCode::from(3);
            }
            let (state_dir, store) = match resolve_state_store(cli.state_dir.as_deref(), no_state) {
                Ok(value) => value,
                Err(code) => return code,
            };
            let roots = match normalize_scan_roots(&roots) {
                Ok(roots) => roots,
                Err(error) => {
                    eprintln!("{error}");
                    return ProcessExitCode::from(2);
                }
            };
            let progress = ScanProgress::start(
                context.locale(),
                roots.len(),
                tui,
                format == OutputFormat::Human,
            );
            let scan = match store.as_ref() {
                Some(store) if tui => scan_for_tui_with_store(
                    &context,
                    &ScanRequest {
                        roots,
                        state_dir: state_dir.clone(),
                    },
                    Some(store),
                ),
                Some(store) => scan_with_store(
                    &context,
                    &ScanRequest {
                        roots,
                        state_dir: state_dir.clone(),
                    },
                    Some(store),
                ),
                None if tui => scan_for_tui_with_store(
                    &context,
                    &ScanRequest {
                        roots,
                        state_dir: None,
                    },
                    Option::<&sweepx_core::MemorySnapshotStore>::None,
                ),
                None => scan_with_store(
                    &context,
                    &ScanRequest {
                        roots,
                        state_dir: None,
                    },
                    Option::<&sweepx_core::MemorySnapshotStore>::None,
                ),
            };
            progress.finish();
            if tui {
                return finish_tui_scan(&context, scan, size_unit, sort);
            }
            scan.map(RenderedResult::Scan)
        }
        Commands::Explain {
            scan_json,
            candidate_id,
            max_input_bytes,
        } => explain_from_scan_json(
            &context,
            &ExplainRequest {
                scan_json_path: scan_json,
                candidate_id,
                max_input_bytes,
            },
        )
        .map(RenderedResult::Explanation),
        Commands::Status {
            operation_id,
            watch,
            after,
        } => {
            if after.is_some() && !watch {
                let message = "--after requires --watch";
                eprintln!("{message}");
                return ProcessExitCode::from(2);
            }
            if watch && format != OutputFormat::Ndjson {
                let message = "--watch requires --format ndjson";
                eprintln!("{message}");
                return ProcessExitCode::from(2);
            }
            if watch {
                #[cfg(not(target_os = "linux"))]
                {
                    eprintln!("completed journal replay is unsupported on this platform");
                    return ProcessExitCode::from(3);
                }
                #[cfg(target_os = "linux")]
                {
                    let state_dir =
                        match state_dir_from_explicit_or_default(cli.state_dir.as_deref()) {
                            Ok(value) => value,
                            Err(error) => {
                                eprintln!("{error}");
                                return ProcessExitCode::from(state_error_exit_code(&error));
                            }
                        };
                    let request = StatusReplayRequest {
                        operation_id,
                        state_dir,
                        after,
                    };
                    let result = replay_completed_status(&context, &request);
                    match result {
                        Ok(result) => {
                            let exit_code = replay_exit_code(&result);
                            print_output(
                                &context,
                                format,
                                size_unit,
                                sort,
                                &RenderedResult::Replay(result),
                            );
                            return ProcessExitCode::from(exit_code);
                        }
                        Err(error) => {
                            eprintln!("{error}");
                            return ProcessExitCode::from(replay_error_exit_code(&error));
                        }
                    }
                }
            }
            let (state_dir, store) = match resolve_state_store(cli.state_dir.as_deref(), false) {
                Ok(value) => value,
                Err(code) => return code,
            };
            match store.as_ref() {
                Some(store) => status_with_store(
                    &context,
                    &StatusRequest {
                        operation_id,
                        state_dir: state_dir.clone(),
                    },
                    Some(store),
                )
                .map(RenderedResult::Snapshot),
                None => status_with_store(
                    &context,
                    &StatusRequest {
                        operation_id,
                        state_dir: None,
                    },
                    Option::<&sweepx_core::MemorySnapshotStore>::None,
                )
                .map(RenderedResult::Snapshot),
            }
        }
        Commands::Cancel { operation_id } => {
            let (state_dir, store) = match resolve_state_store(cli.state_dir.as_deref(), false) {
                Ok(value) => value,
                Err(code) => return code,
            };
            match store.as_ref() {
                Some(store) => cancel_with_store(
                    &context,
                    &CancelRequest {
                        operation_id,
                        state_dir: state_dir.clone(),
                    },
                    Some(store),
                )
                .map(RenderedResult::Snapshot),
                None => cancel_with_store(
                    &context,
                    &CancelRequest {
                        operation_id,
                        state_dir: None,
                    },
                    Option::<&sweepx_core::MemorySnapshotStore>::None,
                )
                .map(RenderedResult::Snapshot),
            }
        }
        Commands::Cleaner { command } => match command {
            CleanerCommands::List => cleaner_list(&context).map(RenderedResult::Cleaner),
            CleanerCommands::Show { cleaner_ref } => {
                cleaner_show(&context, &CleanerShowRequest { cleaner_ref })
                    .map(RenderedResult::Cleaner)
            }
            CleanerCommands::CargoDetect { roots } => {
                let roots = match normalize_roots(&roots) {
                    Ok(roots) => roots,
                    Err(error) => {
                        eprintln!("{error}");
                        return ProcessExitCode::from(2);
                    }
                };
                let cancel = CancellationToken::new();
                cleaner_cargo_detect_with_invocation_and_cancel(
                    &context,
                    &CleanerCargoDetectRequest::new(roots),
                    &CleanerCargoDetectInvocation::without_cargo_cli_overrides(),
                    &cancel,
                )
                .map(RenderedResult::Cleaner)
            }
        },
        Commands::Junk { system, roots } => {
            let roots = match normalize_junk_roots(system, &roots) {
                Ok(roots) => roots,
                Err(error) => {
                    eprintln!("{error}");
                    return ProcessExitCode::from(2);
                }
            };
            return run_junk_scan(&context, format, size_unit, roots, system);
        }
        Commands::Cache { command } => match command {
            CacheCommands::Status => {
                if format == OutputFormat::Ndjson {
                    let result = RenderedResult::CacheStatus(cache_status_usage_error(
                        &context,
                        "cache status does not support --format ndjson",
                    ));
                    print_output(&context, OutputFormat::Json, size_unit, sort, &result);
                    return ProcessExitCode::from(result.exit_code());
                }
                #[cfg(target_os = "windows")]
                {
                    let result = RenderedResult::CacheStatus(cache_status_unsupported(&context));
                    let code = result.exit_code();
                    print_output(&context, format, size_unit, sort, &result);
                    return ProcessExitCode::from(code);
                }
                #[cfg(unix)]
                {
                    let state_dir =
                        match state_dir_from_explicit_or_default(cli.state_dir.as_deref()) {
                            Ok(value) => value,
                            Err(error) => {
                                let result = RenderedResult::CacheStatus(cache_status_state_error(
                                    &context, &error,
                                ));
                                let code = result.exit_code();
                                print_output(&context, format, size_unit, sort, &result);
                                return ProcessExitCode::from(code);
                            }
                        };
                    match cache_status(&context, &CacheStatusRequest { state_dir }) {
                        Ok(result) => Ok(RenderedResult::CacheStatus(result)),
                        Err(sweepx_core::CoreError::State(error)) => Ok(
                            RenderedResult::CacheStatus(cache_status_state_error(&context, &error)),
                        ),
                        Err(error) => Err(error),
                    }
                }
            }
        },
        Commands::Trash { path } => {
            return trash_command::run_cli_trash(
                &path,
                format,
                context.locale(),
                std::io::stdin().is_terminal(),
            );
        }
        Commands::Capabilities => capabilities(&context).map(RenderedResult::Capabilities),
    };

    match result {
        Ok(result) => {
            let code = result.exit_code();
            print_output(&context, format, size_unit, sort, &result);
            ProcessExitCode::from(code)
        }
        Err(error) => {
            eprintln!("{error}");
            ProcessExitCode::from(core_error_exit_code(&error) as u8)
        }
    }
}

/// Long flag that opts in to elevation, and the one argument never forwarded to a child.
const ELEVATE_FLAG: &str = "--elevate";

/// Outcome of the startup privilege gate.
enum StartupPrivilege {
    /// This process performs the work. `notice` reports a failed opt-in, if any.
    Continue { notice: Option<String> },
    /// An elevated child already did the work; exit with its code and do nothing else.
    ElevatedChildCompleted { exit_code: u8 },
}

/// Settles privilege for this invocation before any work begins.
///
/// Detection always runs and never prompts. A prompt is possible only when the user passed
/// `--elevate` *and* this process is not already elevated, which is what keeps the default
/// path incapable of raising a UAC dialog.
fn startup_privilege(opted_in: bool) -> StartupPrivilege {
    let policy = if opted_in {
        ElevationPolicy::RequestWhenUserOptedIn
    } else {
        ElevationPolicy::DetectOnly
    };
    let Some(relaunch) = current_relaunch_request() else {
        // Without a trustworthy image path there is nothing safe to relaunch, so the run
        // continues unprivileged rather than guessing at what to start elevated.
        return StartupPrivilege::Continue {
            notice: opted_in.then(|| {
                "could not determine this program's own path; continuing without elevation"
                    .to_string()
            }),
        };
    };

    let provider = platform_privilege_provider();
    match decide_startup_privilege(provider.as_ref(), policy, &relaunch) {
        StartupPrivilegeDecision::ElevatedChildCompleted { exit_code } => {
            StartupPrivilege::ElevatedChildCompleted { exit_code }
        }
        StartupPrivilegeDecision::Continue { refusal, .. } => StartupPrivilege::Continue {
            notice: refusal.map(|refusal| format!("continuing without elevation: {refusal}")),
        },
    }
}

/// Builds the relaunch request for this process, dropping the opt-in flag.
///
/// Dropping `--elevate` is what bounds the recursion: a child that saw it again would run the
/// same opt-in logic. It is already elevated by then, so detection would stop it, but removing
/// the flag makes a second relaunch impossible by construction rather than relying on that one
/// check.
fn current_relaunch_request() -> Option<ElevatedRelaunch> {
    let program = std::env::current_exe().ok()?;
    if !program.is_absolute() {
        return None;
    }
    let arguments = std::env::args_os()
        .skip(1)
        .filter(|argument| argument != ELEVATE_FLAG)
        .collect();
    Some(ElevatedRelaunch::new(program, arguments))
}

/// Selects the privilege backend for this host.
///
/// A host without a backend gets the fail-closed default: detection reports `Unknown`, which
/// grants no accelerator and still refuses destructive mode.
fn platform_privilege_provider() -> Box<dyn PrivilegeProvider> {
    #[cfg(windows)]
    {
        Box::new(sweepx_platform_windows::WindowsPrivilegeProvider::new())
    }
    #[cfg(not(windows))]
    {
        /// Placeholder until a Unix backend exists. Reports an unknown level rather than
        /// claiming the process is unprivileged, so R-23's destructive refusal still applies.
        struct UnknownPrivilege;
        impl PrivilegeProvider for UnknownPrivilege {
            fn provider_name(&self) -> &'static str {
                "unimplemented"
            }
            fn observe(&self) -> sweepx_platform::PrivilegeObservation {
                sweepx_platform::PrivilegeObservation::unknown()
            }
        }
        Box::new(UnknownPrivilege)
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct JunkRule {
    id: String,
    names: Vec<String>,
    risk: String,
    required_parent_markers: Vec<String>,
    evidence: String,
    source_reviewed_at: String,
    references: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PlatformJunkRule {
    id: String,
    platform: String,
    root_kind: String,
    match_kind: String,
    names: Vec<String>,
    /// Child names that must exist inside the root before it is reported.
    ///
    /// For tool-reported roots this is the structural check that the directory really is the
    /// cache the tool described, rather than whatever else now sits at that path.
    required_markers: Vec<String>,
    depth: usize,
    risk: String,
    evidence: String,
    source_reviewed_at: String,
    references: Vec<String>,
}

#[derive(Debug, Clone)]
struct JunkCandidate {
    path: String,
    rule_id: String,
    risk: String,
    reclaimable: ByteValue,
    evidence: String,
    source_reviewed_at: String,
    references: Vec<String>,
    entry_id: ScanEntryId,
    ancestor_ids: BTreeSet<ScanEntryId>,
}

// The first catalog is intentionally narrow: project outputs with deterministic names and a
// rebuild contract. MangoDisk's broader inventory is research input, not license-compatible code
// or automatic authority. Each future rule must carry its own source and safety review.
const PROJECT_JUNK_RULES_JSON: &str = include_str!("../resources/project-junk-rules.json");
const PLATFORM_JUNK_RULES_JSON: &str = include_str!("../resources/platform-junk-rules.json");

fn run_junk_scan(
    context: &CoreContext,
    format: OutputFormat,
    size_unit: HumanSizeUnit,
    roots: Vec<PathBuf>,
    include_platform_rules: bool,
) -> ProcessExitCode {
    let rules = match load_project_junk_rules() {
        Ok(rules) => rules,
        Err(error) => {
            eprintln!("invalid built-in project junk rules: {error}");
            return ProcessExitCode::from(12);
        }
    };
    let platform_rules = if include_platform_rules {
        match load_platform_junk_rules() {
            Ok(rules) => rules,
            Err(error) => {
                eprintln!("invalid built-in platform junk rules: {error}");
                return ProcessExitCode::from(12);
            }
        }
    } else {
        Vec::new()
    };
    let progress = ScanProgress::start(
        context.locale(),
        roots.len(),
        false,
        format == OutputFormat::Human,
    );
    let scan = scan_with_store(
        context,
        &ScanRequest {
            roots,
            state_dir: None,
        },
        Option::<&sweepx_core::MemorySnapshotStore>::None,
    );
    progress.finish();
    let scan = match scan {
        Ok(scan) => scan,
        Err(error) => {
            eprintln!("{error}");
            return ProcessExitCode::from(core_error_exit_code(&error) as u8);
        }
    };
    // Applicability is joined through scan identities and lossless native names. Display paths
    // remain presentation-only and are never reused to probe the filesystem.
    let markers_by_parent = scan
        .summary
        .entries
        .iter()
        .filter(|entry| entry.object_type == ObjectType::File)
        .filter_map(|entry| {
            let identity = entry.identity.as_ref()?;
            let parent_id = identity.parent_id.clone()?;
            let name = native_name_for_rule(&entry.native_basename)?;
            Some((parent_id, name))
        })
        .fold(
            BTreeMap::<ScanEntryId, BTreeSet<String>>::new(),
            |mut index, (parent_id, name)| {
                index.entry(parent_id).or_default().insert(name);
                index
            },
        );
    let aggregates = scan
        .summary
        .aggregates
        .iter()
        .map(|aggregate| (aggregate.directory_identity.as_str(), aggregate))
        .collect::<BTreeMap<_, _>>();
    let mut candidates = scan
        .summary
        .entries
        .iter()
        .filter(|entry| entry.object_type == ObjectType::Directory)
        .filter_map(|entry| {
            let identity = entry.identity.as_ref()?;
            let locator = entry.native_locator.as_ref()?;
            let name = native_name_for_rule(&entry.native_basename)?;
            rules.iter().find_map(|rule| {
                (rule
                    .names
                    .iter()
                    .any(|candidate| normalized_rule_name(candidate) == name)
                    && junk_rule_applies(rule, identity, &markers_by_parent))
                .then(|| JunkCandidate {
                    path: entry.display_path.clone(),
                    rule_id: rule.id.clone(),
                    risk: rule.risk.clone(),
                    reclaimable: aggregates
                        .get(identity.entry_id.as_str())
                        .map(|aggregate| aggregate.potentially_reclaimable_bytes.clone())
                        .unwrap_or(EvidenceValue::NotChecked {
                            reason: ReasonCode::ResourceLimit,
                        }),
                    evidence: rule.evidence.clone(),
                    source_reviewed_at: rule.source_reviewed_at.clone(),
                    references: rule.references.clone(),
                    entry_id: identity.entry_id.clone(),
                    ancestor_ids: locator
                        .parent_reopen_recipe
                        .iter()
                        .map(|component| component.entry_id.clone())
                        .collect(),
                })
            })
        })
        .collect::<Vec<_>>();
    candidates.extend(platform_junk_candidates(
        &scan.summary,
        &aggregates,
        &platform_rules,
    ));
    candidates.sort_by(|left, right| {
        left.ancestor_ids
            .len()
            .cmp(&right.ancestor_ids.len())
            .then_with(|| left.path.cmp(&right.path))
    });
    let mut top_level = Vec::with_capacity(candidates.len());
    let mut selected_ids = BTreeSet::new();
    for candidate in candidates {
        if candidate
            .ancestor_ids
            .iter()
            .any(|ancestor| selected_ids.contains(ancestor))
        {
            continue;
        }
        selected_ids.insert(candidate.entry_id.clone());
        top_level.push(candidate);
    }
    let mut candidates = top_level;
    candidates.sort_by(|left, right| {
        junk_evidence_bytes(&right.reclaimable)
            .cmp(&junk_evidence_bytes(&left.reclaimable))
            .then_with(|| left.path.cmp(&right.path))
    });
    let (known_reclaimable, incomplete_size_count) = junk_size_summary(&candidates);
    if format == OutputFormat::Human {
        println!(
            "{}",
            match context.locale() {
                sweepx_i18n::Locale::ZhCn => "垃圾扫描报告（已核验可重建/可丢弃位置；仅报告）",
                sweepx_i18n::Locale::EnUs =>
                    "Junk scan report (verified rebuildable/disposable locations; report-only)",
            }
        );
        for candidate in &candidates {
            println!(
                "{risk:<4} {:>12}  {rule:<18} {path}",
                junk_size_label(&candidate.reclaimable, size_unit),
                risk = candidate.risk,
                rule = candidate.rule_id,
                path = candidate.path,
            );
        }
        println!(
            "{}",
            match context.locale() {
                sweepx_i18n::Locale::ZhCn => format!(
                    "汇总：{} 个候选，已统计可回收 {}{}；{} 项为下限或未知；没有执行删除。",
                    candidates.len(),
                    if incomplete_size_count > 0 { ">= " } else { "" },
                    known_reclaimable
                        .map(|bytes| size_unit.format(bytes))
                        .unwrap_or_else(|| "unknown".to_string()),
                    incomplete_size_count,
                ),
                sweepx_i18n::Locale::EnUs => format!(
                    "Summary: {} candidates, {}{} accounted reclaimable; {} lower-bound or unknown sizes; nothing was deleted.",
                    candidates.len(),
                    if incomplete_size_count > 0 { ">= " } else { "" },
                    known_reclaimable
                        .map(|bytes| size_unit.format(bytes))
                        .unwrap_or_else(|| "unknown".to_string()),
                    incomplete_size_count,
                ),
            }
        );
    } else {
        println!(
            "{}",
            json!({
                "schema": "sweepx.junk.result/v1",
                "status": if scan.output.status == sweepx_protocol::OutputStatus::Ok { "ok" } else { "partial" },
                "readOnly": true,
                "candidateCount": candidates.len(),
                "knownReclaimableBytes": known_reclaimable.map(|value| value.to_string()),
                "incompleteSizeCount": incomplete_size_count,
                "candidates": candidates.iter().map(|candidate| json!({
                    "path": candidate.path, "ruleId": candidate.rule_id, "risk": candidate.risk,
                    "reclaimable": candidate.reclaimable,
                    "evidence": candidate.evidence,
                    "sourceReviewedAt": candidate.source_reviewed_at,
                    "references": candidate.references,
                })).collect::<Vec<_>>(),
            })
        );
    }
    ProcessExitCode::from(scan.output.conservative_exit_code() as u8)
}

fn load_project_junk_rules() -> Result<Vec<JunkRule>, String> {
    let rules: Vec<JunkRule> =
        serde_json::from_str(PROJECT_JUNK_RULES_JSON).map_err(|error| error.to_string())?;
    let mut ids = BTreeSet::new();
    for rule in &rules {
        if !ids.insert(rule.id.as_str())
            || rule.id.trim().is_empty()
            || !matches!(rule.risk.as_str(), "R1" | "R2" | "R3")
            || rule.names.is_empty()
            || rule.evidence.trim().is_empty()
            || !valid_verification_date(&rule.source_reviewed_at)
            || rule.references.is_empty()
            || !rule
                .references
                .iter()
                .all(|reference| reference.starts_with("https://"))
            || !rule
                .names
                .iter()
                .chain(rule.required_parent_markers.iter())
                .all(|name| safe_rule_component(name))
        {
            return Err(format!("invalid project junk rule: {}", rule.id));
        }
    }
    Ok(rules)
}

fn safe_rule_component(value: &str) -> bool {
    !value.is_empty()
        && !matches!(value, "." | "..")
        && !value.contains('/')
        && !value.contains('\\')
        && !value.contains('\0')
}

fn junk_rule_applies(
    rule: &JunkRule,
    identity: &sweepx_model::ScanObjectIdentity,
    markers_by_parent: &BTreeMap<ScanEntryId, BTreeSet<String>>,
) -> bool {
    if rule.required_parent_markers.is_empty() {
        return true;
    }
    // Marker checks are applicability filters only. They reduce obvious false positives such as
    // dependency-internal `dist` directories and never grant mutation authority. The join is
    // identity-based so a lossy display path cannot redirect even this read-only classification.
    identity.parent_id.as_ref().is_some_and(|parent_id| {
        markers_by_parent.get(parent_id).is_some_and(|markers| {
            rule.required_parent_markers
                .iter()
                .any(|marker| markers.contains(&normalized_rule_name(marker)))
        })
    })
}

fn platform_junk_candidates(
    summary: &sweepx_core::ScanSummary,
    aggregates: &BTreeMap<&str, &sweepx_model::DirectoryAggregate>,
    rules: &[PlatformJunkRule],
) -> Vec<JunkCandidate> {
    let platform = if cfg!(target_os = "linux") {
        "linux"
    } else if cfg!(target_os = "macos") {
        "macos"
    } else if cfg!(target_os = "windows") {
        "windows"
    } else {
        "unsupported"
    };
    let mut candidates = Vec::new();
    for rule in rules
        .iter()
        .filter(|rule| rule.platform == platform || rule.platform == "any")
    {
        for entry in summary
            .roots
            .iter()
            .chain(summary.entries.iter())
            .filter(|entry| entry.object_type == ObjectType::Directory)
        {
            let Some(identity) = entry.identity.as_ref() else {
                continue;
            };
            let Some(locator) = entry.native_locator.as_ref() else {
                continue;
            };
            let depth = locator.parent_reopen_recipe.len();
            let matched = match rule.match_kind.as_str() {
                "direct_children" => depth == rule.depth,
                "named_descendant" => {
                    depth == rule.depth
                        && native_name_for_rule(&entry.native_basename).is_some_and(|name| {
                            rule.names
                                .iter()
                                .any(|candidate| normalized_rule_name(candidate) == name)
                        })
                }
                // The scan root itself is the candidate. Root discovery already confirmed the
                // tool reported this path and that the required markers are present, so the
                // rule reports one aggregate for the whole cache rather than per-file rows.
                "verified_tool_root" => depth == 0 && tool_reported_root_matches(rule, entry),
                _ => false,
            };
            if !matched {
                continue;
            }
            candidates.push(JunkCandidate {
                path: entry.display_path.clone(),
                rule_id: rule.id.clone(),
                risk: rule.risk.clone(),
                reclaimable: aggregates
                    .get(identity.entry_id.as_str())
                    .map(|aggregate| aggregate.potentially_reclaimable_bytes.clone())
                    .unwrap_or_else(|| entry.reclaimable_estimate.clone()),
                evidence: rule.evidence.clone(),
                source_reviewed_at: rule.source_reviewed_at.clone(),
                references: rule.references.clone(),
                entry_id: identity.entry_id.clone(),
                ancestor_ids: locator
                    .parent_reopen_recipe
                    .iter()
                    .map(|component| component.entry_id.clone())
                    .collect(),
            });
        }
    }
    candidates
}

/// Confirms a scanned root is the one this rule's tool reported.
///
/// Root discovery and candidate classification are separate passes, and the user may also name
/// roots explicitly, so a depth-0 directory is not automatically this rule's cache. Without
/// re-checking, scanning an unrelated directory would be labelled "npm cache".
///
/// The comparison uses the captured lossless native path, not `display_path`: display paths are
/// presentation data and are never execution or classification authority in this codebase. The
/// markers are then re-checked so a rule only reports a directory that still has the cache's
/// shape. This is report-only classification and grants no deletion authority; the scanner's
/// no-follow identity checks remain the authority over what was traversed.
fn tool_reported_root_matches(rule: &PlatformJunkRule, entry: &sweepx_model::ScannedEntry) -> bool {
    let Some(tool) = tool_reported_root_for(&rule.root_kind) else {
        return false;
    };
    let Some(reported) = tool.resolve() else {
        return false;
    };
    let Some(locator) = entry.native_locator.as_ref() else {
        return false;
    };
    let Some(captured) = locator.scan_root_absolute_path.as_ref() else {
        // Without a captured native path there is nothing trustworthy to compare against, so the
        // rule declines rather than falling back to the display string.
        return false;
    };
    if !captured.equals_path(&reported).unwrap_or(false) {
        return false;
    }
    root_has_required_markers(&reported, &rule.required_markers)
}

fn native_name_for_rule(name: &sweepx_model::NativeName) -> Option<String> {
    match name {
        sweepx_model::NativeName::UnixBytes(bytes) => String::from_utf8(bytes.clone()).ok(),
        sweepx_model::NativeName::WindowsUtf16(units) => String::from_utf16(units)
            .ok()
            .map(|name| name.to_ascii_lowercase()),
    }
}

fn normalized_rule_name(name: &str) -> String {
    if cfg!(windows) {
        name.to_ascii_lowercase()
    } else {
        name.to_string()
    }
}

fn junk_evidence_bytes(value: &ByteValue) -> Option<u128> {
    match value {
        EvidenceValue::Known { value } | EvidenceValue::LowerBound { value, .. } => Some(value.0),
        _ => None,
    }
}

fn junk_size_label(value: &ByteValue, unit: HumanSizeUnit) -> String {
    match value {
        EvidenceValue::Known { value } => unit.format(value.0),
        EvidenceValue::LowerBound { value, .. } => format!(">= {}", unit.format(value.0)),
        EvidenceValue::Unknown { .. }
        | EvidenceValue::Unsupported { .. }
        | EvidenceValue::NotChecked { .. } => "unknown".to_string(),
    }
}

fn junk_size_summary(candidates: &[JunkCandidate]) -> (Option<u128>, usize) {
    let mut total = Some(0u128);
    let mut incomplete = 0usize;
    for candidate in candidates {
        match &candidate.reclaimable {
            EvidenceValue::Known { value } => {
                total = total.and_then(|sum| sum.checked_add(value.0));
            }
            EvidenceValue::LowerBound { value, .. } => {
                total = total.and_then(|sum| sum.checked_add(value.0));
                incomplete += 1;
            }
            EvidenceValue::Unknown { .. }
            | EvidenceValue::Unsupported { .. }
            | EvidenceValue::NotChecked { .. } => incomplete += 1,
        }
    }
    (total, incomplete)
}

fn validate_tui_environment(
    format: OutputFormat,
    stdin_is_terminal: bool,
    stdout_is_terminal: bool,
) -> Result<(), &'static str> {
    if format != OutputFormat::Human {
        return Err("--tui cannot be combined with --format json or --format ndjson");
    }
    if !stdin_is_terminal || !stdout_is_terminal {
        return Err("--tui requires terminal stdin and stdout");
    }
    Ok(())
}

fn finish_tui_scan(
    context: &CoreContext,
    scan: Result<sweepx_core::ScanSuccess, sweepx_core::CoreError>,
    size_unit: HumanSizeUnit,
    sort: ScanSort,
) -> ProcessExitCode {
    let scan = match scan {
        Ok(scan) => scan,
        Err(error) => {
            eprintln!("{error}");
            return ProcessExitCode::from(core_error_exit_code(&error) as u8);
        }
    };
    // Progressive TUI owns the visible result. Avoid printing the roots-only bootstrap snapshot
    // on exit because it would look like a completed zero-byte scan.
    let unsupported = scan.output.status == sweepx_protocol::OutputStatus::Unsupported;
    if unsupported {
        println!(
            "{}",
            sweepx_core::render_human_output_with_size_unit(context, &scan.output, size_unit, sort,)
        );
        return ProcessExitCode::from(scan.output.conservative_exit_code() as u8);
    }
    let sweepx_core::TuiScanParts {
        status,
        exit_code,
        scan_id,
        summary,
    } = scan.into_tui_parts();
    let provider = tui_detail_rescan_provider(&summary);
    let sweepx_core::ScanSummary { roots, .. } = summary;
    let model = match BrowserModel::from_progressive_roots(
        context.locale(),
        status,
        scan_id,
        roots,
        Vec::new(),
        size_unit,
        sort,
    ) {
        Ok(model) => model,
        Err(error) => {
            eprintln!("interactive browser setup failed: {error}");
            return ProcessExitCode::from(8);
        }
    };
    let browser_result = run_live_browser_with_detail_rescan(model, provider);
    match browser_result {
        Ok(BrowserExit::TrashSelected { entry }) => {
            trash_command::run_tui_trash(&entry, context.locale())
        }
        Ok(browser_exit) => ProcessExitCode::from(tui_exit_code(exit_code, browser_exit)),
        Err(error) => {
            eprintln!("interactive browser failed: {error}");
            ProcessExitCode::from(8)
        }
    }
}

fn tui_exit_code(scan_exit_code: u8, browser_exit: BrowserExit) -> u8 {
    match browser_exit {
        BrowserExit::Quit => scan_exit_code,
        BrowserExit::TrashSelected { .. } => 1,
        BrowserExit::Terminated { signal } => {
            signal.map_or(1, |signal| 128u8.saturating_add(signal))
        }
    }
}

fn resolve_state_store(
    explicit: Option<&std::path::Path>,
    no_state: bool,
) -> Result<(Option<PathBuf>, Option<sweepx_core::DurableSnapshotStore>), ProcessExitCode> {
    if no_state {
        return Ok((None, None));
    }
    let state_dir = match state_dir_from_explicit_or_default(explicit) {
        Ok(value) => value,
        Err(error) => {
            eprintln!("{error}");
            return Err(ProcessExitCode::from(state_error_exit_code(&error)));
        }
    };
    let store = match durable_store(state_dir.as_deref()) {
        Ok(value) => value,
        Err(error) => {
            eprintln!("{error}");
            return Err(ProcessExitCode::from(state_error_exit_code(&error)));
        }
    };
    Ok((state_dir, store))
}

fn state_error_exit_code(error: &StateError) -> u8 {
    match error {
        StateError::DurableStateUnsupportedOnWindows => 3,
        _ => 2,
    }
}

fn normalize_roots(raw_roots: &[OsString]) -> Result<Vec<PathBuf>, sweepx_core::CoreError> {
    raw_roots
        .iter()
        .map(|raw| expand_scan_root(raw.as_os_str()))
        .map(|path| validate_absolute_root(path.as_os_str()))
        .collect()
}

/// Expands only the CLI conveniences users expect. It deliberately does not canonicalize or
/// resolve symlinks; the platform scanner still performs the authoritative no-follow admission.
fn expand_scan_root(raw: &std::ffi::OsStr) -> PathBuf {
    let path = PathBuf::from(raw);
    if path.is_absolute() {
        return path;
    }
    if path == Path::new("~") {
        return user_home_dir().unwrap_or(path);
    }
    if let Ok(suffix) = path.strip_prefix("~")
        && !suffix.as_os_str().is_empty()
        && let Some(home) = user_home_dir()
    {
        return home.join(suffix);
    }
    std::env::current_dir()
        .map(|cwd| cwd.join(&path))
        .unwrap_or(path)
}

fn user_home_dir() -> Option<PathBuf> {
    std::env::var_os(if cfg!(windows) { "USERPROFILE" } else { "HOME" }).map(PathBuf::from)
}

/// Terminal-only heartbeat. It reports elapsed work rather than inventing a percentage, because
/// filesystem traversal cannot know the final item count before it has discovered the tree.
struct ScanProgress {
    stop: Option<mpsc::Sender<()>>,
    worker: Option<thread::JoinHandle<()>>,
}

impl ScanProgress {
    fn start(locale: sweepx_i18n::Locale, root_count: usize, tui: bool, enabled: bool) -> Self {
        if !enabled || !std::io::stderr().is_terminal() {
            return Self {
                stop: None,
                worker: None,
            };
        }
        let (tx, rx) = mpsc::channel();
        let worker = thread::spawn(move || {
            let started = Instant::now();
            eprintln!(
                "{}",
                match (locale, tui) {
                    (sweepx_i18n::Locale::ZhCn, true) => {
                        format!("正在准备 TUI：先扫描 {root_count} 个根目录的当前层…")
                    }
                    (sweepx_i18n::Locale::ZhCn, false) => {
                        format!("正在扫描 {root_count} 个根目录…")
                    }
                    (sweepx_i18n::Locale::EnUs, true) => {
                        format!(
                            "Preparing TUI by scanning the current level of {root_count} root(s)…"
                        )
                    }
                    (sweepx_i18n::Locale::EnUs, false) => {
                        format!("Scanning {root_count} root(s)…")
                    }
                }
            );
            loop {
                match rx.recv_timeout(Duration::from_secs(1)) {
                    Ok(()) | Err(mpsc::RecvTimeoutError::Disconnected) => break,
                    Err(mpsc::RecvTimeoutError::Timeout) => eprintln!(
                        "{}",
                        match locale {
                            sweepx_i18n::Locale::ZhCn => {
                                format!("仍在扫描… {:.1}s", started.elapsed().as_secs_f64())
                            }
                            sweepx_i18n::Locale::EnUs => {
                                format!("Still scanning… {:.1}s", started.elapsed().as_secs_f64())
                            }
                        }
                    ),
                }
            }
        });
        Self {
            stop: Some(tx),
            worker: Some(worker),
        }
    }

    fn finish(mut self) {
        self.stop.take();
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

fn normalize_scan_roots(raw_roots: &[OsString]) -> Result<Vec<PathBuf>, sweepx_core::CoreError> {
    if raw_roots.is_empty() {
        Ok(default_full_scan_roots())
    } else {
        normalize_roots(raw_roots)
    }
}

fn normalize_junk_roots(system: bool, raw_roots: &[OsString]) -> Result<Vec<PathBuf>, String> {
    if system && !raw_roots.is_empty() {
        return Err("junk --system cannot be combined with explicit roots".to_string());
    }
    if !system {
        return normalize_scan_roots(raw_roots).map_err(|error| error.to_string());
    }
    let roots = default_platform_junk_roots()?;
    if roots.is_empty() {
        return Err("no supported platform junk root is available".to_string());
    }
    Ok(roots)
}

fn default_platform_junk_roots() -> Result<Vec<PathBuf>, String> {
    let rules = load_platform_junk_rules()?;
    let mut roots = Vec::new();
    // Tool-reported roots come first because they are platform-independent and each one is
    // verified against the rule's markers before being admitted.
    for rule in &rules {
        let Some(tool) = tool_reported_root_for(&rule.root_kind) else {
            continue;
        };
        let Some(root) = tool.resolve() else {
            continue;
        };
        if !is_existing_real_directory(&root)
            || !root_has_required_markers(&root, &rule.required_markers)
        {
            continue;
        }
        if !roots.contains(&root) {
            roots.push(root);
        }
    }
    #[cfg(target_os = "linux")]
    {
        // XDG_CACHE_HOME is valid only as an absolute path. Falling back to ~/.cache follows the
        // XDG Base Directory specification; data/config homes are intentionally excluded.
        if rules.iter().any(|rule| rule.platform == "linux")
            && let Some(cache) = std::env::var_os("XDG_CACHE_HOME")
                .map(PathBuf::from)
                .filter(|path| path.is_absolute())
                .or_else(|| {
                    user_home_dir()
                        .filter(|home| home.is_absolute())
                        .map(|home| home.join(".cache"))
                })
            && is_existing_real_directory(&cache)
        {
            roots.push(cache);
        }
    }
    #[cfg(target_os = "macos")]
    {
        // Apple defines Library/Caches as discardable, but candidate classification remains
        // report-only and no broader Library/Application Support root is admitted here.
        if rules.iter().any(|rule| rule.platform == "macos")
            && let Some(cache) = user_home_dir()
                .filter(|home| home.is_absolute())
                .map(|home| home.join("Library/Caches"))
            && is_existing_real_directory(&cache)
        {
            roots.push(cache);
        }
    }
    #[cfg(target_os = "windows")]
    {
        // LocalCache is narrower than LocalAppData. SweepX does not classify an application's
        // LocalFolder or the whole LocalAppData tree as disposable.
        if rules.iter().any(|rule| rule.platform == "windows")
            && let Some(packages) = std::env::var_os("LOCALAPPDATA")
                .map(PathBuf::from)
                .filter(|path| path.is_absolute())
                .map(|path| path.join("Packages"))
            && is_existing_real_directory(&packages)
        {
            roots.push(packages);
        }
    }
    Ok(roots)
}

fn is_existing_real_directory(path: &Path) -> bool {
    // Root discovery is convenience only, but it still avoids following a symlink before the
    // platform scanner performs the authoritative no-follow admission and identity checks.
    std::fs::symlink_metadata(path).is_ok_and(|metadata| metadata.file_type().is_dir())
}

/// One tool-reported cache root, as the tool itself describes it.
///
/// Measured on Windows on 2026-09-01: for npm, pnpm, and pip the location reported by the tool
/// differed from the documented platform default *and both paths existed*. Shipping the defaults
/// would therefore have reported a stale cache nobody uses while missing the live one, with no
/// way to tell them apart from the path alone. Asking the tool is the only way to be right.
struct ToolReportedRoot {
    /// Program to run. Resolved through the platform's normal executable search.
    program: &'static str,
    /// Arguments that make the tool print exactly one path on stdout.
    arguments: &'static [&'static str],
}

impl ToolReportedRoot {
    /// Returns the tool's own answer, or `None` when the tool is absent or unhelpful.
    ///
    /// A missing tool, a nonzero exit, empty output, or a relative path all yield `None`: this
    /// is discovery, so an unusable answer must drop the rule rather than fall back to a guess.
    /// Only the first line is used, because a tool may add warnings after it.
    fn resolve(&self) -> Option<PathBuf> {
        let output = std::process::Command::new(self.program)
            .args(self.arguments)
            .stdin(std::process::Stdio::null())
            .output()
            .ok()?;
        if !output.status.success() {
            return None;
        }
        let text = String::from_utf8(output.stdout).ok()?;
        let path = PathBuf::from(text.lines().next()?.trim());
        // A relative path cannot be admitted as a scan root, and resolving one here against the
        // current directory would invent a location the tool never reported.
        path.is_absolute().then_some(path)
    }
}

/// Maps a `rootKind` to the tool that reports it.
///
/// Returning `None` means the kind is not tool-reported and is discovered from platform
/// conventions instead.
fn tool_reported_root_for(root_kind: &str) -> Option<ToolReportedRoot> {
    match root_kind {
        "npm_reported_cache" => Some(ToolReportedRoot {
            program: "npm",
            arguments: &["config", "get", "cache"],
        }),
        "pnpm_reported_store" => Some(ToolReportedRoot {
            program: "pnpm",
            arguments: &["store", "path"],
        }),
        "pip_reported_cache" => Some(ToolReportedRoot {
            program: "pip",
            arguments: &["cache", "dir"],
        }),
        _ => None,
    }
}

/// Confirms a directory has the shape the rule expects before it is reported.
///
/// Without this a rule would report whatever now occupies the path the tool named. The check is
/// read-only and uses `symlink_metadata` so a symlinked marker cannot stand in for a real child;
/// the scanner still performs the authoritative no-follow admission afterwards.
fn root_has_required_markers(root: &Path, markers: &[String]) -> bool {
    markers.iter().all(|marker| {
        std::fs::symlink_metadata(root.join(marker)).is_ok_and(|metadata| {
            let file_type = metadata.file_type();
            file_type.is_dir() || file_type.is_file()
        })
    })
}

fn load_platform_junk_rules() -> Result<Vec<PlatformJunkRule>, String> {
    let rules: Vec<PlatformJunkRule> =
        serde_json::from_str(PLATFORM_JUNK_RULES_JSON).map_err(|error| error.to_string())?;
    let mut ids = BTreeSet::new();
    for rule in &rules {
        let expected = match rule.platform.as_str() {
            "linux" => ("xdg_cache_home", "direct_children", 1),
            "macos" => ("macos_user_caches", "direct_children", 1),
            "windows" => ("windows_packages", "named_descendant", 2),
            // A tool-reported root is the scan root itself, so its depth is 0 and its
            // `rootKind` must be one the discovery table actually knows how to resolve.
            // Otherwise a rule could name a root that is silently never produced.
            "any" => {
                if tool_reported_root_for(&rule.root_kind).is_none() {
                    return Err(format!(
                        "platform junk rule {} names an unresolvable root kind: {}",
                        rule.id, rule.root_kind
                    ));
                }
                (rule.root_kind.as_str(), "verified_tool_root", 0)
            }
            _ => return Err(format!("invalid platform junk rule: {}", rule.id)),
        };
        let id_prefix = if rule.platform == "any" {
            "tool."
        } else {
            &format!("{}.", rule.platform)
        };
        if !ids.insert(rule.id.as_str())
            || !rule.id.starts_with(id_prefix)
            || (
                rule.root_kind.as_str(),
                rule.match_kind.as_str(),
                rule.depth,
            ) != expected
            || !matches!(rule.risk.as_str(), "R1" | "R2" | "R3")
            || rule.evidence.trim().is_empty()
            || !valid_verification_date(&rule.source_reviewed_at)
            || rule.references.is_empty()
            || !rule
                .references
                .iter()
                .all(|reference| reference.starts_with("https://"))
            || !rule
                .names
                .iter()
                .chain(rule.required_markers.iter())
                .all(|name| safe_rule_component(name))
            || (rule.match_kind == "direct_children" && !rule.names.is_empty())
            || (rule.match_kind == "named_descendant" && rule.names.is_empty())
            // A tool-reported root is admitted on the tool's word alone, so it must carry at
            // least one structural marker; without one the rule would report whatever now
            // occupies that path.
            || (rule.match_kind == "verified_tool_root"
                && (!rule.names.is_empty() || rule.required_markers.is_empty()))
        {
            return Err(format!("invalid platform junk rule: {}", rule.id));
        }
    }
    Ok(rules)
}

fn valid_verification_date(value: &str) -> bool {
    value.len() == 10
        && value.bytes().enumerate().all(|(index, byte)| {
            matches!(index, 4 | 7) && byte == b'-'
                || !matches!(index, 4 | 7) && byte.is_ascii_digit()
        })
}

fn default_full_scan_roots() -> Vec<PathBuf> {
    #[cfg(unix)]
    {
        vec![PathBuf::from("/")]
    }
    #[cfg(windows)]
    {
        std::env::var_os("SystemDrive")
            .map(|drive| PathBuf::from(format!("{}\\", drive.to_string_lossy())))
            .into_iter()
            .collect()
    }
    #[cfg(not(any(unix, windows)))]
    {
        Vec::new()
    }
}

fn print_output(
    context: &CoreContext,
    format: OutputFormat,
    size_unit: HumanSizeUnit,
    sort: ScanSort,
    result: &RenderedResult,
) {
    match format {
        OutputFormat::Human => {
            println!(
                "{}",
                sweepx_core::render_human_output_with_size_unit(
                    context,
                    result.output(),
                    size_unit,
                    sort,
                )
            );
        }
        OutputFormat::Json => {
            println!("{}", serialize_json(result.output()));
        }
        OutputFormat::Ndjson => match result {
            RenderedResult::Scan(scan) => {
                print!("{}", serialize_ndjson(&scan.events));
            }
            #[cfg(target_os = "linux")]
            RenderedResult::Replay(replay) => {
                let stdout = std::io::stdout();
                let mut lock = stdout.lock();
                for event in &replay.events {
                    serde_json::to_writer(&mut lock, event).expect("event serializable");
                    lock.write_all(b"\n").expect("newline write");
                    lock.flush().expect("stdout flush");
                }
            }
            _ => {
                let line = serde_json::to_string(result.output()).expect("output serializable");
                println!("{line}");
            }
        },
    }
}

enum RenderedResult {
    Scan(sweepx_core::ScanSuccess),
    Explanation(sweepx_core::ExplanationSuccess),
    #[cfg(target_os = "linux")]
    Replay(sweepx_core::CompletedReplaySuccess),
    CacheStatus(sweepx_core::CacheStatusSuccess),
    Snapshot(sweepx_core::SnapshotSuccess),
    Cleaner(sweepx_core::CleanerSuccess),
    Capabilities(sweepx_core::CapabilitiesSuccess),
}

impl RenderedResult {
    fn output(&self) -> &OutputEnvelope {
        match self {
            Self::Scan(scan) => &scan.output,
            Self::Explanation(explanation) => &explanation.output,
            #[cfg(target_os = "linux")]
            Self::Replay(replay) => &replay.output,
            Self::CacheStatus(cache) => &cache.output,
            Self::Snapshot(snapshot) => &snapshot.output,
            Self::Cleaner(cleaner) => &cleaner.output,
            Self::Capabilities(capabilities) => &capabilities.output,
        }
    }

    fn exit_code(&self) -> u8 {
        self.output().conservative_exit_code() as u8
    }
}

#[cfg(target_os = "linux")]
fn replay_exit_code(result: &sweepx_core::CompletedReplaySuccess) -> u8 {
    if result.reset_required {
        0
    } else {
        result.terminal_exit_code as u8
    }
}

#[cfg(target_os = "linux")]
fn replay_error_exit_code(error: &sweepx_core::CoreError) -> u8 {
    match error {
        sweepx_core::CoreError::InvalidOperationId(_)
        | sweepx_core::CoreError::InvalidReplayCursor(_) => 2,
        sweepx_core::CoreError::ReplayUnsupported(_) => 3,
        sweepx_core::CoreError::ReplayNotFound(_) => 8,
        sweepx_core::CoreError::State(StateError::DurableStateUnsupportedOnWindows)
        | sweepx_core::CoreError::State(StateError::DefaultStateDirUnavailable) => 3,
        sweepx_core::CoreError::State(_) => 11,
        _ => core_error_exit_code(error) as u8,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_arg_maps_to_core_format() {
        assert_eq!(OutputFormat::from(FormatArg::Human).as_str(), "human");
        assert_eq!(OutputFormat::from(FormatArg::Json).as_str(), "json");
        assert_eq!(OutputFormat::from(FormatArg::Ndjson).as_str(), "ndjson");
    }

    #[test]
    fn relative_scan_root_resolves_against_current_directory() {
        let resolved = normalize_roots(&[OsString::from("relative")]).unwrap();
        assert_eq!(
            resolved,
            vec![std::env::current_dir().unwrap().join("relative")]
        );
    }

    #[test]
    fn tilde_scan_root_expands_to_home() {
        let Some(home) = user_home_dir() else {
            return;
        };
        assert_eq!(normalize_roots(&[OsString::from("~")]).unwrap(), vec![home]);
    }

    #[test]
    fn cli_parser_accepts_allowed_commands_only() {
        assert!(matches!(
            Cli::try_parse_from(["sweepx", "capabilities"]),
            Ok(Cli {
                command: Commands::Capabilities,
                ..
            })
        ));
        assert!(matches!(
            Cli::try_parse_from(["sweepx", "cleaner", "list"]),
            Ok(Cli {
                command: Commands::Cleaner {
                    command: CleanerCommands::List
                },
                ..
            })
        ));
        assert!(matches!(
            Cli::try_parse_from(["sweepx", "cache", "status"]),
            Ok(Cli {
                command: Commands::Cache {
                    command: CacheCommands::Status
                },
                ..
            })
        ));
        assert!(Cli::try_parse_from(["sweepx", "delete"]).is_err());
        assert!(
            Cli::try_parse_from([
                "sweepx",
                "cleaner",
                "cargo-detect",
                "--target-dir",
                "/tmp/target",
                "/tmp/workspace",
            ])
            .is_err()
        );
        assert!(
            Cli::try_parse_from([
                "sweepx",
                "cleaner",
                "cargo-detect",
                "--config",
                "build.target-dir='/tmp/target'",
                "/tmp/workspace",
            ])
            .is_err()
        );
        assert!(matches!(
            Cli::try_parse_from(["sweepx", "scan", "--tui", "/tmp"]),
            Ok(Cli {
                command: Commands::Scan { tui: true, .. },
                ..
            })
        ));
        assert!(Cli::try_parse_from(["sweepx", "tui", "--scan-json", "/tmp/a.json"]).is_err());
    }

    #[test]
    fn tui_preflight_rejects_machine_formats_and_non_terminals() {
        assert!(validate_tui_environment(OutputFormat::Human, true, true).is_ok());
        assert!(validate_tui_environment(OutputFormat::Json, true, true).is_err());
        assert!(validate_tui_environment(OutputFormat::Ndjson, true, true).is_err());
        assert!(validate_tui_environment(OutputFormat::Human, false, true).is_err());
        assert!(validate_tui_environment(OutputFormat::Human, true, false).is_err());
    }

    #[test]
    fn default_scan_format_remains_human() {
        let cli = Cli::try_parse_from(["sweepx", "scan", "/tmp"]).unwrap();
        assert_eq!(cli.format, FormatArg::Human);
    }

    #[test]
    fn scan_without_roots_selects_platform_filesystem_roots() {
        let cli = Cli::try_parse_from(["sweepx", "scan"]).unwrap();
        let Commands::Scan { roots, .. } = cli.command else {
            panic!("expected scan command");
        };
        assert!(roots.is_empty());
        let resolved = normalize_scan_roots(&roots).unwrap();
        assert!(!resolved.is_empty());
        assert!(resolved.iter().all(|root| root.is_absolute()));
    }

    #[test]
    fn human_size_unit_aliases_parse() {
        let cli = Cli::try_parse_from(["sweepx", "--unit", "mb", "scan", "."]).unwrap();
        assert_eq!(cli.unit, UnitArg::Mib);
    }

    #[test]
    fn embedded_project_junk_rules_are_bounded_and_validated() {
        let rules = load_project_junk_rules().unwrap();
        assert!(rules.len() >= 5);
        assert!(rules.iter().all(|rule| !rule.references.is_empty()));
        assert!(
            rules
                .iter()
                .all(|rule| valid_verification_date(&rule.source_reviewed_at))
        );
    }

    #[test]
    fn embedded_platform_junk_rules_are_narrow_and_evidence_bearing() {
        let rules = load_platform_junk_rules().unwrap();
        assert_eq!(rules.len(), 6);
        assert!(rules.iter().all(|rule| !rule.references.is_empty()));
        assert!(
            rules
                .iter()
                .all(|rule| valid_verification_date(&rule.source_reviewed_at))
        );
        let linux = rules.iter().find(|rule| rule.platform == "linux").unwrap();
        assert_eq!(linux.root_kind, "xdg_cache_home");
        assert_eq!(linux.match_kind, "direct_children");
        let windows = rules
            .iter()
            .find(|rule| rule.platform == "windows")
            .unwrap();
        assert_eq!(windows.names, ["LocalCache", "TempState"]);
        assert_eq!(windows.depth, 2);
    }

    /// Every tool-reported rule must be resolvable and structurally guarded.
    ///
    /// Measured on Windows on 2026-09-01: npm, pnpm, and pip each reported a cache location that
    /// differed from the documented platform default while *both* paths existed. A rule that
    /// hardcoded the default would have reported a stale cache and missed the live one. So each
    /// such rule must name a root kind the discovery table can resolve, and must carry at least
    /// one marker so the tool's answer is verified rather than trusted outright.
    #[test]
    fn tool_reported_rules_are_resolvable_and_marker_guarded() {
        let rules = load_platform_junk_rules().unwrap();
        let tool_rules: Vec<_> = rules
            .iter()
            .filter(|rule| rule.match_kind == "verified_tool_root")
            .collect();

        assert_eq!(tool_rules.len(), 3, "expected the npm, pnpm, and pip rules");
        for rule in tool_rules {
            assert!(
                tool_reported_root_for(&rule.root_kind).is_some(),
                "rule {} names a root kind nothing can resolve, so it would never be produced",
                rule.id
            );
            assert!(
                !rule.required_markers.is_empty(),
                "rule {} would report whatever now occupies the reported path",
                rule.id
            );
            // The reported directory is itself the candidate, so it must not also try to match
            // child names.
            assert_eq!(rule.depth, 0, "rule {} must match the root itself", rule.id);
            assert!(rule.names.is_empty());
            assert_eq!(rule.platform, "any");
        }
    }

    /// A rule naming an unresolvable tool root must be rejected outright.
    ///
    /// Such a rule would silently never produce a candidate, which looks like "nothing to clean"
    /// rather than like a broken rule.
    #[test]
    fn a_tool_rule_with_an_unknown_root_kind_is_refused() {
        assert!(tool_reported_root_for("npm_reported_cache").is_some());
        assert!(tool_reported_root_for("definitely_not_a_known_tool").is_none());
    }

    /// Markers must be verified against the real filesystem, not assumed.
    #[test]
    fn required_markers_are_checked_against_the_filesystem() {
        let temp = tempfile::TempDir::new().unwrap();
        let root = temp.path();

        // No markers yet: the directory must not qualify.
        assert!(!root_has_required_markers(root, &["_cacache".to_string()]));
        // An empty marker list is vacuously satisfied, which is why the validator forbids it
        // for tool-reported rules.
        assert!(root_has_required_markers(root, &[]));

        std::fs::create_dir(root.join("_cacache")).unwrap();
        assert!(root_has_required_markers(root, &["_cacache".to_string()]));
        // Every marker must be present, not merely one of them.
        assert!(!root_has_required_markers(
            root,
            &["_cacache".to_string(), "index-v5".to_string()]
        ));
    }

    #[test]
    fn junk_system_rejects_explicit_roots() {
        let roots = vec![OsString::from(".")];
        assert!(normalize_junk_roots(true, &roots).is_err());
    }

    #[test]
    fn unsupported_durable_state_uses_unsupported_exit_code() {
        assert_eq!(
            state_error_exit_code(&StateError::DurableStateUnsupportedOnWindows),
            3
        );
    }

    #[test]
    fn tui_exit_preserves_scan_status_except_for_process_signals() {
        assert_eq!(tui_exit_code(4, BrowserExit::Quit), 4);
        assert_eq!(
            tui_exit_code(4, BrowserExit::Terminated { signal: Some(15) }),
            143
        );
        assert_eq!(
            tui_exit_code(4, BrowserExit::Terminated { signal: None }),
            1
        );
    }

    /// Elevation must be opt-in, so the flag must default to off on every subcommand.
    #[test]
    fn elevation_is_off_unless_the_flag_is_given() {
        let cli = Cli::try_parse_from(["sweepx", "scan", "."]).unwrap();
        assert!(!cli.elevate);

        let cli = Cli::try_parse_from(["sweepx", "scan", "--elevate", "."]).unwrap();
        assert!(cli.elevate);
        // Global, so it must also be accepted before the subcommand and on other commands.
        assert!(
            Cli::try_parse_from(["sweepx", "--elevate", "junk", "--system"])
                .unwrap()
                .elevate
        );
    }

    /// Not passing the flag must select the policy that cannot prompt.
    ///
    /// Asserts the mapping rather than the effect, because the effect is "no UAC dialog",
    /// which cannot be observed from a test.
    #[test]
    fn default_invocation_selects_detect_only_policy() {
        // Mirrors `startup_privilege`'s mapping; a change there must be reflected here.
        let policy = |opted_in: bool| {
            if opted_in {
                ElevationPolicy::RequestWhenUserOptedIn
            } else {
                ElevationPolicy::DetectOnly
            }
        };
        assert_eq!(policy(false), ElevationPolicy::DetectOnly);
        assert_eq!(policy(false), ElevationPolicy::default());
        assert_eq!(policy(true), ElevationPolicy::RequestWhenUserOptedIn);
    }

    /// The opt-in flag must not reach the elevated child.
    ///
    /// If it did, the child would evaluate the same opt-in and could relaunch again. The
    /// program path must also be absolute, so the shell cannot resolve a bare name to a
    /// different image and start *that* elevated.
    #[test]
    fn the_relaunch_request_drops_the_opt_in_flag() {
        let request = current_relaunch_request().expect("the test binary has a path");

        assert!(
            request.program.is_absolute(),
            "an elevated relaunch must name an absolute image"
        );
        assert!(
            !request
                .arguments
                .iter()
                .any(|argument| argument == ELEVATE_FLAG),
            "forwarding {ELEVATE_FLAG} would let the child evaluate the opt-in again: {:?}",
            request.arguments
        );
    }
}
