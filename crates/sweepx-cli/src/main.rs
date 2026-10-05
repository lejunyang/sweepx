use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::io::{IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode as ProcessExitCode;
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

#[cfg(target_os = "macos")]
use sweepx_core::junk::cache as junk_cache;
#[cfg(target_os = "linux")]
use sweepx_core::junk::linux_temp;
#[cfg(target_os = "linux")]
mod permanent_delete_command;
#[cfg(target_os = "macos")]
use sweepx_core::junk::cache::provider as subtree_provider;
#[cfg(target_os = "macos")]
mod tcc_access;
#[cfg(target_os = "linux")]
mod temp_clean_command;
use sweepx_core::junk::JunkService;
#[cfg(all(test, target_os = "macos"))]
use sweepx_core::junk::ProjectJunkRule as JunkRule;
#[cfg(test)]
use sweepx_core::junk::load_project_rules as load_project_junk_rules;
mod file_tui;
mod junk_timings;
mod junk_tui;
mod npx_command;
mod site_storage_command;
mod trash_command;
mod tui_adapter;
use tui_adapter::tui_detail_rescan_provider;

use clap::{Parser, Subcommand, ValueEnum};
use serde_json::json;
use sweepx_core::{CacheStatusRequest, cache_status, cache_status_state_error};
use sweepx_core::{
    CancelRequest, CancellationToken, CleanerCargoDetectInvocation, CleanerCargoDetectRequest,
    CleanerShowRequest, CoreContext, ExplainRequest, OutputFormat, SCAN_NDJSON_UNAVAILABLE_MESSAGE,
    ScanRequest, StateError, StatusRequest, cache_status_usage_error, cancel_with_store,
    capabilities, cleaner_cargo_detect_with_invocation_and_cancel, cleaner_list, cleaner_show,
    core_error_exit_code, durable_store, explain_from_scan_json, parse_locale_override,
    scan_for_output_with_store, scan_for_tui_with_store, scan_junk_with_store,
    scan_ndjson_supported, serialize_json, state_dir_from_explicit_or_default, status_with_store,
    usage_error_output, validate_absolute_root,
};
#[cfg(target_os = "linux")]
use sweepx_core::{StatusReplayRequest, replay_completed_status};
use sweepx_i18n::detect_locale;
use sweepx_model::{ByteValue, EvidenceValue, HumanSizeUnit, ScanSort};
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
    /// Absolute private state directory. Status/cancel never create missing state or repair permissions.
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
    /// Internal: file the elevated child writes its stdout to, for the parent to relay.
    ///
    /// An elevated process cannot inherit the parent's console — `ShellExecuteExW` with `runas`
    /// creates a new one, which closes when the child exits. Measured on Windows: without this,
    /// `--elevate scan` completed successfully and the user received **zero bytes**, because every
    /// line went to a console that vanished. A scan tool that reports success and shows no result
    /// is worse than one that refuses.
    ///
    /// Hidden because it is a private protocol between the two processes, not a user-facing
    /// feature. The parent always generates the path inside its own per-run temporary directory;
    /// accepting an arbitrary destination would turn an elevated SweepX into a general "write this
    /// file as administrator" primitive.
    #[arg(long, global = true, hide = true, value_name = "ABSOLUTE_FILE")]
    relay_stdout_to: Option<PathBuf>,
    /// On macOS, open System Settings and wait for Full Disk Access before scanning.
    ///
    /// Without this flag SweepX only *detects* whether access is already held and never opens
    /// settings. macOS has no API to grant access programmatically, so with this flag SweepX opens
    /// the Full Disk Access pane, prints guidance, and proceeds automatically once the user
    /// enables it (or continues without it if they do not). On non-macOS hosts the flag is
    /// accepted for portable scripts but has no effect.
    #[arg(long, global = true)]
    full_disk_access: bool,
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    Scan {
        /// Browse directories or show live --large-files/--duplicates results with explicit Trash selection.
        #[arg(long)]
        tui: bool,
        /// Rank ordinary files by logical size; report-only unless explicitly selected in --tui.
        #[arg(long)]
        large_files: bool,
        /// Read local content for SHA-256 groups; --tui requires choosing a keeper before Trash.
        #[arg(long, conflicts_with = "large_files")]
        duplicates: bool,
        /// Inclusive logical-byte threshold for --duplicates (default 1 KiB).
        #[arg(long, requires = "duplicates", default_value_t = 1024)]
        min_duplicate_bytes: u128,
        /// Total attempted content-range bytes; failed reads remain charged (default 8 GiB).
        #[arg(long, requires = "duplicates", default_value_t = 8 * 1024 * 1024 * 1024u64, value_parser = clap::value_parser!(u64).range(1..=i64::MAX as u64))]
        duplicate_read_bytes: u64,
        /// Distinct retained native file objects (default 20000, maximum 100000).
        #[arg(long, requires = "duplicates", default_value_t = 20000, value_parser = clap::value_parser!(u32).range(1..=100000))]
        duplicate_max_files: u32,
        /// Cooperative content-phase deadline in milliseconds (default 30000, maximum 300000).
        #[arg(long, requires = "duplicates", default_value_t = 30000, value_parser = clap::value_parser!(u64).range(1..=300000))]
        duplicate_deadline_ms: u64,
        /// Inclusive exact logical-byte threshold for --large-files (default 100 MiB).
        #[arg(long, requires = "large_files", default_value_t = 100 * 1024 * 1024)]
        min_file_bytes: u128,
        /// Retain the largest K file paths; ties follow native observation order.
        #[arg(long, requires = "large_files", default_value_t = 100, value_parser = clap::value_parser!(u32).range(1..=10000))]
        top_files: u32,
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
    /// Read existing operation state; missing state stays missing.
    Status {
        #[arg(long)]
        operation_id: String,
        #[arg(long)]
        watch: bool,
        #[arg(long)]
        after: Option<String>,
    },
    /// Report cancellation disposition; live cancellation remains disabled.
    Cancel {
        #[arg(long)]
        operation_id: String,
    },
    Cleaner {
        #[command(subcommand)]
        command: CleanerCommands,
    },
    /// Discover known rebuildable or disposable artifacts under the selected roots.
    /// Reports partial results when discovery or scan evidence is incomplete.
    /// Cargo target candidates report current manifests and bounded workspace/default output for a parent-cwd/no-CLI model; ownership and activity remain unverified.
    Junk {
        /// Open the live junk view for explicit directory roots or --system. Space selects; d moves selected
        /// current, complete directory candidates to Trash after native identity revalidation.
        /// Linux/macOS/Windows show historical caches first; current results always traverse live.
        /// macOS additionally validates file indexes. Only freshly verified rows can be moved.
        /// Dart and SvelteKit content-profile candidates remain report-only while ownership is unverified.
        /// On Linux, x previews selected temporary objects for quarantine with typed full-digest confirmation.
        #[arg(long, conflicts_with_all = ["timings", "trash", "clean_temp"])]
        tui: bool,
        /// Emit phase timings and root-cache hit counts as one JSON diagnostic on stderr.
        /// Measures report-only work; stdout keeps its existing format.
        #[arg(long, conflicts_with_all = ["trash", "clean_temp"])]
        timings: bool,
        /// Scan conservative platform cache roots; conflicts with explicit roots.
        /// Tool discovery has a 10s batch budget, a 2s probe timeout and a 64 KiB answer limit.
        /// npm inventory also bounds filesystem observations and reports incomplete discovery.
        #[arg(long)]
        system: bool,
        /// Limit --system discovery and classification to a platform rule ID. Repeat to select
        /// multiple categories, e.g. --rule tool.npm-cache. Other categories are outside this scan.
        #[arg(long = "rule", requires = "system", value_name = "RULE_ID")]
        rules: Vec<String>,
        /// Move approved stale Linux temporary objects to a recoverable quarantine.
        ///
        /// Requires `--system`, human output, and a foreground terminal. The full plan digest
        /// must be typed back exactly. This never falls back to permanent deletion.
        #[arg(long, requires = "system", conflicts_with = "roots")]
        clean_temp: bool,
        /// Move eligible junk candidates to the operating-system Trash.
        ///
        /// Each target is revalidated by native identity immediately before it is moved.
        /// This never falls back to permanent deletion. Current project rules remain report-only
        /// because exclusive ownership and inactivity are unverified; generic outputs are always report-only.
        #[arg(long, conflicts_with = "clean_temp")]
        trash: bool,
        /// Absolute quarantine base on a filesystem different from `/tmp`.
        ///
        /// Defaults to `$XDG_DATA_HOME/sweepx/quarantine` or
        /// `$HOME/.local/share/sweepx/quarantine`.
        /// Requires `--system` with `--clean-temp` or `--tui`.
        #[arg(long, value_name = "ABSOLUTE_DIRECTORY", requires = "system")]
        quarantine_dir: Option<PathBuf>,
        #[arg(value_name = "ROOT")]
        roots: Vec<OsString>,
    },
    Cache {
        #[command(subcommand)]
        command: CacheCommands,
    },
    /// List npx tool versions and whole-installation sizes; preview or Trash selected slots.
    NpxCache {
        /// Explicit npm cache/_npx root. Defaults to ~/.npm/_npx; redirected caches require this.
        #[arg(long, value_name = "ABSOLUTE_DIRECTORY")]
        root: Option<PathBuf>,
        /// Show slots that directly request this exact package name.
        #[arg(long)]
        package: Option<String>,
        /// Select complete installation slots by their current ID (repeatable).
        #[arg(long, conflicts_with = "older_versions")]
        entry: Vec<String>,
        /// Select strictly lower installed semantic versions; retain each package's highest.
        /// Multi-package, unknown and duplicate-highest versions are excluded.
        #[arg(long)]
        older_versions: bool,
        /// Apply the selection through recoverable OS Trash after current native/activity checks.
        /// Without this flag the command only reports the plan.
        #[arg(long)]
        trash: bool,
    },
    /// Report Chromium site data by domain, preserving each full storage key and bucket.
    /// Native scans cover default macOS/Linux/Windows profile locations. Shared databases remain
    /// unattributed; byte totals are logical and do not establish disposable or reclaimable space.
    SiteStorage {
        /// Restrict discovery to a browser/channel label, e.g. edge or chrome on macOS/Linux.
        #[arg(long)]
        browser: Option<String>,
        /// Restrict scanning to an exact profile directory name, e.g. Default.
        #[arg(long)]
        profile: Option<String>,
        /// Show one exact hostname with all its storage keys, partitions and buckets.
        /// This is a read-only filter, not deletion authority.
        #[arg(long)]
        domain: Option<String>,
        /// Export a browser-managed deletion plan. Requires an exact browser, profile and domain.
        /// Apply it with the optional Chromium extension after reviewing its irreversible scope.
        #[arg(long, value_name = "NEW_JSON_FILE", requires_all = ["browser", "profile", "domain"], conflicts_with_all = ["trash_origin", "browse"])]
        export_delete_plan: Option<PathBuf>,
        /// Legacy removal request. Refused until browser activity and metadata mappings can be
        /// revalidated; use --domain to review concrete storage items first.
        #[arg(long, value_name = "STORAGE_KEY")]
        trash_origin: Option<String>,
        /// Legacy generic browser view. Refused because it cannot enforce site-data selection.
        #[arg(long, conflicts_with = "trash_origin")]
        browse: bool,
    },
    /// Move one file or directory to the operating system Trash/Recycle Bin.
    ///
    /// Ordinary paths move directly; important directories require terminal confirmation.
    /// macOS uses native Foundation Trash and requires lossless UTF-8 paths. Some systems
    /// restore by dragging items out of Trash instead of Put Back. Never permanently deletes.
    Trash {
        #[arg(required = true, value_name = "ABSOLUTE_PATH")]
        path: OsString,
    },
    /// Permanently delete one bounded local file or directory tree on Linux.
    ///
    /// This irreversible development preview requires human output, a foreground terminal, an
    /// exact digest-derived challenge, durable per-action audit, and immediate identity
    /// revalidation. Directories use a bounded closed manifest and nonrecursive postorder actions.
    /// It is never used as a fallback from `trash`.
    #[cfg(target_os = "linux")]
    Delete {
        #[arg(required = true, value_name = "ABSOLUTE_FILE_OR_DIRECTORY")]
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

    // An elevated child redirects its own stdout before producing anything, so every existing
    // `println!` lands in the relay file without each call site having to know about it. Doing
    // this first is what makes it complete: a later redirect would lose whatever was already
    // buffered toward the console that is about to disappear.
    if let Some(destination) = cli.relay_stdout_to.as_deref()
        && let Err(error) = redirect_stdout_to_file(destination)
    {
        // Failing loudly here is deliberate. Continuing would run the whole scan and discard the
        // result exactly as the unfixed elevation path did, and the parent would report success.
        eprintln!("could not redirect output for the elevated run: {error}");
        return ProcessExitCode::from(8);
    }

    // Privilege is settled first, before locale parsing, before any state directory is
    // resolved, and before any scan begins. On Windows elevation is only granted at
    // process creation, so honoring `--elevate` means re-running as a second process;
    // doing that after a state directory existed would leave one run's files owned by a
    // different identity than the process that continues. If an elevated child ran, its
    // exit code is the whole invocation's answer and this process adds nothing of its own --
    // but it must still relay what the child wrote, or the user sees nothing at all.
    match startup_privilege(cli.elevate) {
        StartupPrivilege::ElevatedChildCompleted { exit_code, relayed } => {
            if let Some(relayed) = relayed {
                relay_child_output(&relayed);
            }
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

    // Full Disk Access is settled after privilege elevation (both must precede any scan), but
    // only on macOS and only when requested: detection alone never opens settings. Access is a
    // guard for reading protected areas, never authority to widen deletion.
    #[cfg(target_os = "macos")]
    {
        tcc_access::ensure(cli.full_disk_access);
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
            large_files,
            duplicates,
            min_duplicate_bytes,
            duplicate_read_bytes,
            duplicate_max_files,
            duplicate_deadline_ms,
            min_file_bytes,
            top_files,
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
            let (state_dir, store) =
                match resolve_state_store(cli.state_dir.as_deref(), no_state, true) {
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
            if tui && (large_files || duplicates) {
                let options = if duplicates {
                    file_tui::Options::Duplicates(sweepx_core::DuplicateOptions {
                        minimum_logical_bytes: min_duplicate_bytes.into(),
                        max_read_bytes: duplicate_read_bytes,
                        max_files: duplicate_max_files as usize,
                        max_duration_ms: duplicate_deadline_ms,
                        max_read_operations: duplicate_max_files as usize * 4,
                        ..Default::default()
                    })
                } else {
                    file_tui::Options::Large(sweepx_core::LargeFileOptions {
                        minimum_logical_bytes: min_file_bytes.into(),
                        max_files: top_files as usize,
                        ..Default::default()
                    })
                };
                return file_tui::run(context, roots, state_dir, store, options, size_unit, sort);
            }
            let progress = ScanProgress::start(
                context.locale(),
                roots.len(),
                tui,
                format == OutputFormat::Human,
            );
            if tui {
                let scan = scan_for_tui_with_store(
                    &context,
                    &ScanRequest {
                        roots,
                        state_dir: state_dir.clone(),
                    },
                    store.as_ref(),
                );
                progress.finish();
                return finish_tui_scan(&context, scan, size_unit, sort);
            }
            let duplicate_options = sweepx_core::DuplicateOptions {
                minimum_logical_bytes: min_duplicate_bytes.into(),
                max_read_bytes: duplicate_read_bytes,
                max_files: duplicate_max_files as usize,
                max_duration_ms: duplicate_deadline_ms,
                max_read_operations: duplicate_max_files as usize * 4,
                ..Default::default()
            };
            let large_options = sweepx_core::LargeFileOptions {
                minimum_logical_bytes: min_file_bytes.into(),
                max_files: top_files as usize,
                ..Default::default()
            };
            let analysis = if duplicates {
                Some(sweepx_core::FileAnalysisOptions::Duplicates(
                    &duplicate_options,
                ))
            } else if large_files {
                Some(sweepx_core::FileAnalysisOptions::Large(&large_options))
            } else {
                None
            };
            let scan = scan_for_output_with_store(
                &context,
                &ScanRequest { roots, state_dir },
                store.as_ref(),
                analysis,
                &CancellationToken::new(),
            );
            progress.finish();
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
                            if let Err(error) = print_output(
                                &context,
                                format,
                                size_unit,
                                sort,
                                &RenderedResult::Replay(result),
                            ) {
                                eprintln!("{error}");
                                return ProcessExitCode::from(8);
                            }
                            return ProcessExitCode::from(exit_code);
                        }
                        Err(error) => {
                            eprintln!("{error}");
                            return ProcessExitCode::from(replay_error_exit_code(&error));
                        }
                    }
                }
            }
            let (state_dir, store) =
                match resolve_state_store(cli.state_dir.as_deref(), false, false) {
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
            let (state_dir, store) =
                match resolve_state_store(cli.state_dir.as_deref(), false, false) {
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
        Commands::Junk {
            tui,
            timings,
            system,
            rules,
            clean_temp,
            trash,
            quarantine_dir,
            roots,
        } => {
            if quarantine_dir.is_some() && !clean_temp && !tui {
                eprintln!("--quarantine-dir requires --system with --clean-temp or --tui");
                return ProcessExitCode::from(2);
            }
            let stdin_is_terminal = std::io::stdin().is_terminal();
            if tui {
                if let Err(message) = validate_tui_environment(
                    format,
                    stdin_is_terminal,
                    std::io::stdout().is_terminal(),
                ) {
                    eprintln!("{message}");
                    return ProcessExitCode::from(2);
                }
                let roots = match normalize_roots(&roots) {
                    Ok(roots) if system && !roots.is_empty() => {
                        eprintln!("junk --tui --system cannot be combined with explicit roots");
                        return ProcessExitCode::from(2);
                    }
                    Ok(roots) if system || !roots.is_empty() => roots,
                    Ok(_) => {
                        eprintln!("junk --tui requires explicit directory roots");
                        return ProcessExitCode::from(2);
                    }
                    Err(error) => {
                        eprintln!("{error}");
                        return ProcessExitCode::from(2);
                    }
                };
                let cache_state_root = state_dir_from_explicit_or_default(cli.state_dir.as_deref())
                    .ok()
                    .flatten()
                    .filter(|root| root.join("junk-cache").as_os_str().len() <= 64 * 1024);
                return junk_tui::run(
                    roots,
                    system.then_some(rules),
                    context.locale(),
                    size_unit,
                    sort,
                    cache_state_root,
                    quarantine_dir,
                );
            }
            if let Err(message) =
                validate_junk_mutation_environment(clean_temp, trash, format, stdin_is_terminal)
            {
                eprintln!("{message}");
                return ProcessExitCode::from(2);
            }
            let mut timings = junk_timings::JunkTimings::new(timings);
            let discovery_progress = ScanProgress::start(
                context.locale(),
                roots.len(),
                false,
                format == OutputFormat::Human,
            );
            let normalized_roots = match normalize_junk_roots(system, &roots, &rules) {
                Ok(roots) => roots,
                Err(error) => {
                    eprintln!("{error}");
                    return ProcessExitCode::from(2);
                }
            };
            discovery_progress.finish();
            timings.phase("discovery");
            // Resolve the state directory for the per-root junk cache. A cache is best-effort: if
            // no state directory is available the scan simply runs uncached rather than failing.
            let cache_state_root = state_dir_from_explicit_or_default(cli.state_dir.as_deref())
                .ok()
                .flatten()
                .filter(|root| root.join("junk-cache").as_os_str().len() <= 64 * 1024);
            return run_junk_scan(
                &context,
                format,
                size_unit,
                normalized_roots.scan_roots,
                normalized_roots.temp_roots,
                normalized_roots.platform,
                JunkCleanOptions {
                    enabled: clean_temp,
                    quarantine_dir: quarantine_dir.as_deref(),
                    stdin_is_terminal,
                },
                trash,
                cache_state_root,
                timings,
            );
        }
        Commands::NpxCache {
            root,
            package,
            entry,
            older_versions,
            trash,
        } => {
            let Some(root) = root.or_else(sweepx_core::npx::default_root) else {
                eprintln!("npx cache root unavailable; supply --root");
                return ProcessExitCode::from(2);
            };
            if !root.is_absolute() {
                eprintln!("--root must be absolute");
                return ProcessExitCode::from(2);
            }
            return npx_command::run(
                &root,
                package.as_deref(),
                &entry,
                older_versions,
                trash,
                format,
                size_unit,
                context.locale(),
            );
        }
        Commands::SiteStorage {
            browser,
            profile,
            domain,
            export_delete_plan,
            trash_origin,
            browse,
        } => {
            return site_storage_command::run(
                &context,
                format,
                size_unit,
                browser.as_deref(),
                profile.as_deref(),
                domain.as_deref(),
                trash_origin.is_some() || browse,
                export_delete_plan.as_deref(),
            );
        }
        Commands::Cache { command } => match command {
            CacheCommands::Status => {
                if format == OutputFormat::Ndjson {
                    let result = RenderedResult::CacheStatus(cache_status_usage_error(
                        &context,
                        "cache status does not support --format ndjson",
                    ));
                    if let Err(error) =
                        print_output(&context, OutputFormat::Json, size_unit, sort, &result)
                    {
                        eprintln!("{error}");
                        return ProcessExitCode::from(8);
                    }
                    return ProcessExitCode::from(result.exit_code());
                }
                let state_dir = match state_dir_from_explicit_or_default(cli.state_dir.as_deref()) {
                    Ok(value) => value,
                    Err(error) => {
                        let result =
                            RenderedResult::CacheStatus(cache_status_state_error(&context, &error));
                        let code = result.exit_code();
                        if let Err(error) = print_output(&context, format, size_unit, sort, &result)
                        {
                            eprintln!("{error}");
                            return ProcessExitCode::from(8);
                        }
                        return ProcessExitCode::from(code);
                    }
                };
                match cache_status(&context, &CacheStatusRequest { state_dir }) {
                    Ok(result) => Ok(RenderedResult::CacheStatus(result)),
                    Err(sweepx_core::CoreError::State(error)) => Ok(RenderedResult::CacheStatus(
                        cache_status_state_error(&context, &error),
                    )),
                    Err(error) => Err(error),
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
        #[cfg(target_os = "linux")]
        Commands::Delete { path } => {
            let state_dir = match state_dir_from_explicit_or_default(cli.state_dir.as_deref()) {
                Ok(Some(path)) => path,
                Ok(None) => {
                    eprintln!("no state directory is available for the permanent-delete audit");
                    return ProcessExitCode::from(8);
                }
                Err(error) => {
                    eprintln!("{error}");
                    return ProcessExitCode::from(8);
                }
            };
            return permanent_delete_command::run_cli_permanent_delete(
                &path,
                format,
                context.locale(),
                &state_dir,
                std::io::stdin().is_terminal(),
                std::io::stdout().is_terminal(),
            );
        }
        Commands::Capabilities => capabilities(&context).map(RenderedResult::Capabilities),
    };

    match result {
        Ok(result) => {
            let code = result.exit_code();
            if let Err(error) = print_output(&context, format, size_unit, sort, &result) {
                eprintln!("{error}");
                return ProcessExitCode::from(8);
            }
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

/// Internal flag naming the file an elevated child writes its stdout to.
const RELAY_FLAG: &str = "--relay-stdout-to";

/// Points this process's standard output at `destination`, for the whole process.
///
/// Redirecting at the OS handle level rather than at each print site is what makes the fix
/// complete: `println!`, any library that writes to stdout, and anything already queued all follow
/// a single `SetStdHandle`. Rewriting 34 call sites would leave every future one to remember.
#[cfg(windows)]
fn redirect_stdout_to_file(destination: &Path) -> std::io::Result<()> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::System::Console::{STD_OUTPUT_HANDLE, SetStdHandle};

    // `create_new` is the guard that makes an attacker-supplied path useless: the parent creates a
    // fresh private directory per run, so an existing file here means something is wrong and the
    // run refuses rather than truncating whatever it names.
    let file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(destination)?;
    // SAFETY: the handle comes from a live `File`; `SetStdHandle` only stores it. The file is
    // deliberately leaked below so the handle stays valid for the rest of the process.
    let ok = unsafe { SetStdHandle(STD_OUTPUT_HANDLE, file.as_raw_handle() as _) };
    if ok == 0 {
        return Err(std::io::Error::last_os_error());
    }
    // Rust's `std::io::stdout` caches its handle on first use, so the `File` must outlive every
    // later write. Leaking it is the intended lifetime: it is released when the process exits.
    std::mem::forget(file);
    Ok(())
}

/// Non-Windows hosts never relaunch, so a relay request cannot be honored.
#[cfg(not(windows))]
fn redirect_stdout_to_file(_destination: &Path) -> std::io::Result<()> {
    Err(std::io::Error::other(
        "output relay is only used by the Windows elevation path",
    ))
}

/// Copies an elevated child's captured output to this process's stdout, then removes it.
///
/// Written through as bytes rather than as text: machine output must reach the caller's pipe
/// byte-for-byte, and re-encoding could corrupt a path that is not valid Unicode.
///
/// A missing or unreadable file is reported on stderr and does not change the exit code. The
/// child's own code already described the outcome, and overriding it here would report a failure
/// for a run that succeeded.
fn relay_child_output(captured: &Path) {
    use std::io::Write;

    match std::fs::read(captured) {
        Ok(bytes) => {
            let mut stdout = std::io::stdout();
            if let Err(error) = stdout.write_all(&bytes).and_then(|()| stdout.flush()) {
                eprintln!("could not relay the elevated run's output: {error}");
            }
        }
        Err(error) => {
            eprintln!("the elevated run produced no readable output ({error})");
        }
    }
    // Best-effort cleanup of a temporary file; the directory goes with it below.
    let _ = std::fs::remove_file(captured);
    if let Some(directory) = captured.parent() {
        let _ = std::fs::remove_dir(directory);
    }
}

/// Outcome of the startup privilege gate.
enum StartupPrivilege {
    /// This process performs the work. `notice` reports a failed opt-in, if any.
    Continue { notice: Option<String> },
    /// An elevated child already did the work; exit with its code after relaying its output.
    ElevatedChildCompleted {
        exit_code: u8,
        /// File the child wrote its stdout to, when a relay was arranged.
        relayed: Option<PathBuf>,
    },
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
    // Arranged before the request is built so the child can be told where to write. A failure to
    // prepare it is not fatal: the run still elevates, and the relay is simply absent, which is no
    // worse than the behavior this replaces.
    let relay = opted_in.then(prepare_relay_destination).flatten();
    let Some(relaunch) = current_relaunch_request(relay.as_deref()) else {
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
            StartupPrivilege::ElevatedChildCompleted {
                exit_code,
                relayed: relay,
            }
        }
        StartupPrivilegeDecision::Continue { refusal, .. } => {
            // No child ran, so nothing will ever write the relay file. Removing the directory here
            // keeps a declined prompt from leaving debris behind on every attempt.
            if let Some(relay) = relay.as_deref().and_then(Path::parent) {
                let _ = std::fs::remove_dir(relay);
            }
            StartupPrivilege::Continue {
                notice: refusal.map(|refusal| format!("continuing without elevation: {refusal}")),
            }
        }
    }
}

/// Creates a private directory for this run and names the file the child should write.
///
/// The directory is created with a unique name and the file itself is *not* created, so the child's
/// `create_new` open is the single point that decides the file is new. The path is generated here
/// rather than accepted from the command line because an elevated process writing to a
/// caller-chosen path is a privilege-escalation primitive, not a feature.
fn prepare_relay_destination() -> Option<PathBuf> {
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_nanos();
    let directory =
        std::env::temp_dir().join(format!("sweepx-relay-{}-{unique}", std::process::id()));
    std::fs::create_dir(&directory).ok()?;
    Some(directory.join("stdout"))
}

/// Builds the relaunch request for this process, dropping the opt-in flag.
///
/// Dropping `--elevate` is what bounds the recursion: a child that saw it again would run the
/// same opt-in logic. It is already elevated by then, so detection would stop it, but removing
/// the flag makes a second relaunch impossible by construction rather than relying on that one
/// check.
///
/// Any inherited `--relay-stdout-to` is dropped for the same reason: the destination must be the
/// one this process just created, never one an outer caller chose.
fn current_relaunch_request(relay: Option<&Path>) -> Option<ElevatedRelaunch> {
    let program = std::env::current_exe().ok()?;
    if !program.is_absolute() {
        return None;
    }
    let arguments = forwardable_arguments(std::env::args_os().skip(1), relay);
    Some(ElevatedRelaunch::new(program, arguments))
}

/// Filters this run's arguments into the set the elevated child should receive.
///
/// Separated from process state so the stripping rules are testable directly: both are security
/// properties, and a test that can only observe the current process's real arguments cannot exercise
/// either of them.
fn forwardable_arguments(
    inherited: impl Iterator<Item = OsString>,
    relay: Option<&Path>,
) -> Vec<OsString> {
    let mut arguments: Vec<OsString> = Vec::new();
    let mut inherited = inherited;
    while let Some(argument) = inherited.next() {
        if argument == ELEVATE_FLAG {
            continue;
        }
        if argument == RELAY_FLAG {
            // Consume its value too, or the path would survive as a stray positional root.
            inherited.next();
            continue;
        }
        if let Some(text) = argument.to_str()
            && text.starts_with(&format!("{RELAY_FLAG}="))
        {
            continue;
        }
        arguments.push(argument);
    }
    if let Some(relay) = relay {
        arguments.push(OsString::from(RELAY_FLAG));
        arguments.push(relay.as_os_str().to_os_string());
    }
    arguments
}

/// Selects the privilege backend for this host.
///
/// A host without a backend gets the fail-closed default: detection reports `Unknown`, which
/// grants no accelerator and still refuses destructive mode.
fn platform_privilege_provider() -> Box<dyn PrivilegeProvider> {
    #[cfg(windows)]
    {
        Box::new(sweepx_platform::windows::WindowsPrivilegeProvider::new())
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

struct JunkCleanOptions<'a> {
    enabled: bool,
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    quarantine_dir: Option<&'a Path>,
    stdin_is_terminal: bool,
}

// The first catalog is intentionally narrow: project outputs with deterministic names and a
// rebuild contract. MangoDisk's broader inventory is research input, not license-compatible code
// or automatic authority. Each future rule must carry its own source and safety review.

#[cfg(all(test, target_os = "macos"))]
use sweepx_core::junk::candidate::GitIgnoreEvidence;
use sweepx_core::junk::candidate::JunkCandidate;
#[cfg(all(test, target_os = "macos"))]
use sweepx_core::junk::candidate::refresh_candidate_interpretation;
#[cfg(all(test, target_os = "macos"))]
use sweepx_core::junk::candidate::{assemble_platform_candidate, assemble_project_candidate};
use sweepx_core::junk::git::{GitEvidenceLimits, GitEvidenceSession};

#[cfg(all(test, target_os = "macos"))]
use sweepx_core::junk::platform::PlatformJunkEvidence;
#[cfg(all(test, target_os = "macos"))]
use sweepx_core::junk::platform::PlatformJunkRule;
#[cfg(all(test, target_os = "macos"))]
use sweepx_core::junk::platform::load_platform_junk_rules;
use sweepx_core::junk::platform::{PlatformJunkSetup, default_platform_junk_roots, user_home_dir};

/// Converts an in-memory candidate into the cache record's owned form.
#[cfg(all(test, target_os = "macos"))]
fn junk_candidate_to_stored(candidate: &JunkCandidate) -> junk_cache::StoredJunkCandidate {
    junk_cache::StoredJunkCandidate::from_candidate(candidate)
}

/// Converts a cache record back into an in-memory candidate.
///
/// Tool interpretation is rebuilt from this invocation. Git metadata is not retained in the
/// root facts, so project candidates first revert to base confidence with an explicit blocker;
/// the current Git session then independently refreshes them using validated traversal facts.
#[cfg(all(test, target_os = "macos"))]
fn stored_candidate_to_junk(
    stored: junk_cache::StoredJunkCandidate,
    project_rules: &[JunkRule],
    platform_rules: &[PlatformJunkRule],
    evidence: &PlatformJunkEvidence,
) -> Option<JunkCandidate> {
    refresh_candidate_interpretation(
        stored.into_candidate(),
        project_rules,
        platform_rules,
        evidence,
    )
}

fn validate_junk_mutation_environment(
    clean_temp: bool,
    trash: bool,
    format: OutputFormat,
    stdin_is_terminal: bool,
) -> Result<(), &'static str> {
    if format != OutputFormat::Human || !stdin_is_terminal {
        if clean_temp {
            return Err(
                "junk --system --clean-temp requires human output and a foreground interactive terminal",
            );
        }
        if trash {
            return Err("junk --trash requires human output and a foreground interactive terminal");
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn run_junk_scan(
    context: &CoreContext,
    format: OutputFormat,
    size_unit: HumanSizeUnit,
    roots: Vec<PathBuf>,
    #[cfg_attr(not(target_os = "linux"), allow(unused_variables))] temp_requested_roots: Vec<
        PathBuf,
    >,
    platform: Option<PlatformJunkSetup>,
    clean: JunkCleanOptions<'_>,
    move_to_trash: bool,
    // Explicit common state root; history and indexes use its shared quota before local locks.
    #[cfg_attr(not(target_os = "macos"), allow(unused_variables))] cache_state_root: Option<
        PathBuf,
    >,
    mut timings: junk_timings::JunkTimings,
) -> ProcessExitCode {
    #[cfg(target_os = "macos")]
    let cache_dir = cache_state_root
        .as_ref()
        .map(|root| root.join("junk-cache"));
    if let Err(message) = validate_junk_mutation_environment(
        clean.enabled,
        move_to_trash,
        format,
        clean.stdin_is_terminal,
    ) {
        eprintln!("{message}");
        return ProcessExitCode::from(2);
    }
    let project_service = match JunkService::built_in() {
        Ok(rules) => rules,
        Err(error) => {
            eprintln!("invalid built-in project junk rules: {error}");
            return ProcessExitCode::from(12);
        }
    };
    let PlatformJunkSetup {
        rules: platform_rules,
        evidence,
    } = platform.unwrap_or_default();
    let layout_failure = evidence.layout_failure();
    let tool_failure = evidence.tool_discovery_failure();
    if let Some(failure) = tool_failure
        && format == OutputFormat::Human
    {
        eprintln!(
            "{} ({})",
            match context.locale() {
                sweepx_i18n::Locale::ZhCn =>
                    "npm 安装发现不完整：可能遗漏安装或缓存，缺失活动信息不代表未使用",
                sweepx_i18n::Locale::EnUs =>
                    "npm installation discovery is incomplete: installations or caches may be missing; unknown activity does not mean unused",
            },
            failure.code()
        );
    }
    if let Some(failure) = layout_failure
        && format == OutputFormat::Human
    {
        eprintln!(
            "{} ({})",
            match context.locale() {
                sweepx_i18n::Locale::ZhCn =>
                    "平台位置发现不完整：可能遗漏候选，空列表不能证明没有垃圾",
                sweepx_i18n::Locale::EnUs =>
                    "Platform layout discovery is incomplete: candidates may be missing; an empty list does not prove the scope contains no junk",
            },
            failure.code()
        );
    }
    let scan_roots = roots;
    #[cfg(target_os = "linux")]
    let temp_root = linux_temp::report_temp_root();
    #[cfg(target_os = "linux")]
    let temp_discovery = platform_rules
        .iter()
        .find(|rule| rule.root_kind == "linux_tmp")
        .and_then(|rule| {
            let temp_root = temp_root.as_ref()?;
            let requested = if temp_requested_roots.is_empty() {
                None
            } else {
                Some(temp_requested_roots.as_slice())
            };
            Some((
                rule,
                linux_temp::discover(
                    temp_root,
                    requested,
                    Instant::now() + linux_temp::MEASURE_DEADLINE,
                ),
            ))
        });
    let progress = ScanProgress::start(
        context.locale(),
        scan_roots.len(),
        false,
        format == OutputFormat::Human,
    );
    // Resolve every rule's tool caches and live root once, up front, so the walk-time classifier
    // and the later assembly both read from this snapshot instead of each spawning the tools.
    let classifier = project_service.with_platform(&platform_rules, &evidence);
    #[cfg(target_os = "macos")]
    let classification_context = classifier.classification_context_digest();

    // Resolve every root to its canonical (symlink-free) path; FSEvents reports canonical paths
    // and the per-root cache is keyed on them. A root that cannot be canonicalized is passed
    // through unchanged so the scanner reports the real error for it.
    let canonical_roots: Vec<PathBuf> = scan_roots
        .iter()
        .map(|root| std::fs::canonicalize(root).unwrap_or_else(|_| root.clone()))
        .collect();

    // Capture before cache validation and traversal: writes during the scan must invalidate the next reuse.
    #[cfg(target_os = "macos")]
    let scan_event_id = sweepx_core::current_event_id();

    timings.phase("setup");

    // Only file indexes participate in acceleration. Their lengths must match live native
    // enumeration; an advisory event history cannot authorize skipping a whole root.
    #[cfg(target_os = "macos")]
    let subtree_provider = subtree_provider::SubtreeCacheProvider::prepare_files(
        cache_dir.as_deref().unwrap_or(Path::new("/nonexistent")),
        &canonical_roots,
        junk_cache::CacheReader::new(cache_dir.as_deref().unwrap_or(Path::new("/nonexistent"))),
    );
    #[cfg(target_os = "macos")]
    let subtree_provider = if let Some(root) = &cache_state_root {
        subtree_provider
            .with_state_directory(root)
            .expect("explicit absolute state scope")
    } else {
        subtree_provider
    };
    let miss_indexes: Vec<usize> = (0..canonical_roots.len()).collect();

    let miss_roots: Vec<PathBuf> = miss_indexes
        .iter()
        .map(|index| canonical_roots[*index].clone())
        .collect();

    timings.cache_roots(
        canonical_roots.len(),
        canonical_roots.len() - miss_roots.len(),
    );
    timings.phase("rootCacheValidation");

    // File-index validation was included in the shared root-cache phase above.
    timings.phase("subtreeCacheValidation");
    let classified = if miss_roots.is_empty() {
        None
    } else {
        Some(scan_junk_with_store(
            context,
            &ScanRequest {
                roots: miss_roots.clone(),
                state_dir: None,
            },
            Option::<&sweepx_core::MemorySnapshotStore>::None,
            &classifier,
            #[cfg(target_os = "macos")]
            Some(&subtree_provider),
            #[cfg(not(target_os = "macos"))]
            None,
        ))
    };
    progress.finish();
    timings.phase("traversal");
    let scan = match classified {
        Some(Ok(scan)) => Some(scan),
        Some(Err(error)) => {
            eprintln!("{error}");
            return ProcessExitCode::from(core_error_exit_code(&error) as u8);
        }
        None => None,
    };
    if format == OutputFormat::Human
        && scan
            .as_ref()
            .is_some_and(|scan| scan.scan.output.status != sweepx_protocol::OutputStatus::Ok)
    {
        eprintln!(
            "{}",
            match context.locale() {
                sweepx_i18n::Locale::ZhCn =>
                    "扫描证据不完整：候选列表可能有遗漏；没有候选不表示该范围没有垃圾。",
                sweepx_i18n::Locale::EnUs =>
                    "Scan evidence is incomplete: candidates may be missing; an empty list does not establish that the scope contains no junk.",
            }
        );
    }

    // Assemble freshly scanned candidates. Applicability was joined during the walk through scan
    // identities and lossless native names; aggregates carry each directory's size.
    let mut fresh_candidates = Vec::new();
    let mut git_session =
        GitEvidenceSession::new(GitEvidenceLimits::default(), CancellationToken::new());
    if let Some(scan) = &scan {
        let aggregates = scan
            .scan
            .summary
            .aggregates
            .iter()
            .map(|aggregate| (aggregate.directory_identity.as_str(), aggregate))
            .collect::<BTreeMap<_, _>>();
        for entry in scan
            .scan
            .summary
            .roots
            .iter()
            .chain(scan.scan.summary.entries.iter())
        {
            let Some(identity) = entry.identity.as_ref() else {
                continue;
            };
            let Some(decision) = scan.decisions.get(&identity.entry_id) else {
                continue;
            };
            if let Some(candidate) =
                project_service.interpret(decision, entry, &aggregates, &platform_rules, &evidence)
            {
                fresh_candidates.push(candidate);
            }
        }
        timings.phase("classification");
        git_session.capture_scan_facts(
            &scan.scan.summary,
            &scan.coverages,
            &scan.directory_markers,
            &mut fresh_candidates,
        );
    }
    #[cfg(target_os = "linux")]
    if let Some((rule, discovery)) = &temp_discovery {
        fresh_candidates.extend(linux_temp::report_candidates(rule, discovery));
    }

    let mut formats = sweepx_core::junk::format::ProjectFormatSession::new(
        sweepx_core::junk::format::ProjectFormatLimits::default(),
        CancellationToken::new(),
    );
    for candidate in &mut fresh_candidates {
        formats.refresh(candidate);
    }
    timings.phase("projectFormats");
    git_session.refresh(&mut fresh_candidates);
    timings.phase("gitEvidence");

    // Persist original observations for historical TUI presentation. Every root is freshly
    // traversed on the next report; these rows never qualify a whole-root scan shortcut.
    #[cfg(target_os = "macos")]
    if cache_dir.is_some()
        && let Some(scan) = &scan
    {
        let cancel = CancellationToken::new();
        let grouped_candidates = classification_context.and_then(|_| {
            match junk_cache::publication::CandidateCacheGroups::prepare(
                &canonical_roots,
                &fresh_candidates,
                &scan.scan.summary.aggregates,
                &cancel,
            ) {
                Ok(groups) => Some(groups),
                Err(error) => {
                    eprintln!("could not prepare junk cache: {error}");
                    None
                }
            }
        });
        for index in &miss_indexes {
            let root = &canonical_roots[*index];
            // Unknown discovery scope or a context digest that exceeds its bound cannot justify
            // candidate reuse, even with complete filesystem traversal. File facts are independent.
            let Some(classification_context) = classification_context else {
                continue;
            };
            // Incomplete scans (including denied roots) must be retried, never frozen as hits.
            if !root
                .to_str()
                .is_some_and(|path| scan.covered_paths.get(path) == Some(&true))
            {
                continue;
            }
            let Some(groups) = &grouped_candidates else {
                continue;
            };
            match groups
                .project_root(*index, &cancel)
                .and_then(|stored| {
                    junk_cache::StoredJunkRoot::capture(
                        root,
                        stored,
                        scan_event_id,
                        classification_context,
                    )
                })
                .and_then(|mut record| {
                    if !scan
                        .observed_roots
                        .iter()
                        .any(|source| record.matches_observed_root(source))
                    {
                        return Err(std::io::Error::other("cache root changed after traversal"));
                    }
                    record.bind_scope(&canonical_roots);
                    junk_cache::write_in_state(
                        cache_state_root.as_deref().expect("cache state scope"),
                        &record,
                    )
                }) {
                Ok(()) => {}
                // A cache write failure never fails the report; the root simply rescans next run.
                Err(error) => eprintln!(
                    "could not update junk cache for {}: {error}",
                    root.display()
                ),
            }
        }

        // Persist file lengths only. Candidate rows cannot reconstruct subtree accounting or
        // current scan identities; directories are always traversed on a root-cache miss.
        drop(grouped_candidates);
        subtree_provider.store_observed_indexes(
            &scan.observed_roots,
            &canonical_roots,
            scan_event_id,
            &scan.covered_paths,
            &scan.dir_listings,
            &cancel,
            |root, error| {
                eprintln!(
                    "could not update subtree index for {}: {error}",
                    root.display()
                );
            },
        );
    }

    #[cfg(target_os = "macos")]
    if let Some(root) = &cache_state_root
        && let Err(error) = junk_cache::prune_in_state(root)
    {
        eprintln!("could not prune junk cache: {error}");
    }

    timings.phase("cacheWrite");
    let mut candidates = fresh_candidates;
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
    if move_to_trash {
        let mut items = Vec::new();
        for candidate in &candidates {
            // The source row comes from a fresh scan or from the cache; the bulk trash path
            // revalidates each one by its own captured native locator rather than trusting the
            // candidate display path. Linux temp candidates carry none and use another flow.
            let Some(entry) = candidate.source_entry.as_ref() else {
                continue;
            };
            // Observing the directory inode alone does not cover its descendants. Match its
            // current aggregate too; a missing/partial subtree cannot enter bulk junk Trash.
            let eligible = entry.coverage.complete
                && !entry.coverage.details_lost
                && scan.as_ref().is_some_and(|scan| {
                    scan.scan
                        .summary
                        .aggregates
                        .iter()
                        .find(|aggregate| {
                            aggregate.directory_identity == candidate.entry_id.as_str()
                        })
                        .is_some_and(|aggregate| {
                            aggregate.coverage.complete && !aggregate.coverage.details_lost
                        })
                });
            items.push(trash_command::BulkTrashItem {
                path: candidate.path.clone(),
                size: junk_evidence_bytes(&candidate.reclaimable).unwrap_or(0),
                rule_id: candidate.rule_id.clone(),
                entry,
                eligible,
                project_blocker: candidate.project_execution_blocker(),
            });
        }
        return trash_command::run_bulk_trash(context.locale(), items);
    }
    #[cfg(target_os = "linux")]
    let temp_discovery_complete = temp_discovery
        .as_ref()
        .is_none_or(|(_, discovery)| discovery.complete);
    #[cfg(not(target_os = "linux"))]
    let temp_discovery_complete = true;
    #[cfg(target_os = "linux")]
    let temp_discovery_json: Option<serde_json::Value> =
        temp_discovery.as_ref().map(|(_, discovery)| {
            json!({
                "complete": discovery.complete,
                "incompleteReason": discovery.incomplete_reason,
            })
        });
    #[cfg(not(target_os = "linux"))]
    let temp_discovery_json: Option<serde_json::Value> = None;
    #[cfg(target_os = "linux")]
    let temp_clean_inputs = candidates
        .iter()
        .filter(|candidate| candidate.rule_id == linux_temp::RULE_ID)
        .filter_map(|candidate| {
            let EvidenceValue::Known { value } = &candidate.reclaimable else {
                return None;
            };
            Some(temp_clean_command::TempCleanInput {
                path: candidate.native_path.clone()?,
                allocated_bytes: value.0,
                expected: None,
            })
        })
        .collect::<Vec<_>>();
    if format == OutputFormat::Human {
        println!(
            "{}",
            match (context.locale(), clean.enabled) {
                (sweepx_i18n::Locale::ZhCn, true) => {
                    "垃圾扫描报告与可恢复临时对象清理预览"
                }
                (sweepx_i18n::Locale::EnUs, true) => {
                    "Junk scan report and recoverable temporary-object cleanup preview"
                }
                (sweepx_i18n::Locale::ZhCn, false) => {
                    "垃圾扫描报告（候选依据与缺口见各行；仅报告）"
                }
                (sweepx_i18n::Locale::EnUs, false) =>
                    "Junk scan report (candidate evidence and gaps shown per row; report-only)",
            }
        );
        for candidate in &candidates {
            let git_note = match (
                context.locale(),
                candidate.git.is_some(),
                candidate.blockers.is_empty(),
            ) {
                (sweepx_i18n::Locale::ZhCn, true, _) => format!(
                    " [Git 已忽略；置信度 {}]",
                    candidate.confidence.as_deref().unwrap_or("not_checked")
                ),
                (sweepx_i18n::Locale::EnUs, true, _) => {
                    format!(
                        " [Git ignored; confidence {}]",
                        candidate.confidence.as_deref().unwrap_or("not_checked")
                    )
                }
                (sweepx_i18n::Locale::ZhCn, false, false) => {
                    format!(" [Git 未提升：{}]", candidate.blockers.join(","))
                }
                (sweepx_i18n::Locale::EnUs, false, false) => {
                    format!(" [Git not promoted: {}]", candidate.blockers.join(","))
                }
                (_, false, true) => String::new(),
            };
            println!(
                "{risk:<4} {:>12}  {rule:<18} {path}{git_note}{format_note}{context_note}{execution_note}",
                junk_size_label(&candidate.reclaimable, size_unit),
                risk = candidate.risk,
                rule = candidate.rule_id,
                path = candidate.path,
                context_note = candidate
                    .project_context
                    .as_ref()
                    .map(|e| match context.locale() {
                        sweepx_i18n::Locale::ZhCn => format!(
                            " [项目上下文：{}；声明未解析为所有权]",
                            junk_project_context_label(e)
                        ),
                        sweepx_i18n::Locale::EnUs => format!(
                            " [project context: {}; declarations do not establish ownership]",
                            junk_project_context_label(e)
                        ),
                    })
                    .unwrap_or_default(),
                execution_note = match (context.locale(), candidate.project_execution_blocker()) {
                    (sweepx_i18n::Locale::ZhCn, Some("user_data_requires_explicit_selection")) =>
                        " [用户数据待确认：请独立明确选择来源或路径；垃圾列表不能回收]",
                    (sweepx_i18n::Locale::EnUs, Some("user_data_requires_explicit_selection")) =>
                        " [User data needs review: select an origin/path separately; junk Trash is blocked]",
                    (sweepx_i18n::Locale::ZhCn, Some(_)) =>
                        " [回收受限：规则仅报告或所有权/活动未核验]",
                    (sweepx_i18n::Locale::EnUs, Some(_)) =>
                        " [Trash blocked: report-only rule or unverified ownership/activity]",
                    (_, None) => "",
                },
                format_note = candidate
                    .project_format
                    .as_ref()
                    .map(|evidence| match context.locale() {
                        sweepx_i18n::Locale::ZhCn => format!(
                            " [格式：{}/{}；所有权未核验，仅报告]",
                            evidence.status.code(),
                            evidence.reason
                        ),
                        sweepx_i18n::Locale::EnUs => format!(
                            " [format: {}/{}; ownership unverified, report-only]",
                            evidence.status.code(),
                            evidence.reason
                        ),
                    })
                    .unwrap_or_default(),
            );
        }
        println!(
            "{}",
            match (context.locale(), clean.enabled) {
                (sweepx_i18n::Locale::ZhCn, true) => format!(
                    "汇总：{} 个候选，已统计可回收 {}{}；{} 项为下限或未知；尚未移动，下一步将展示精确确认计划。",
                    candidates.len(),
                    if incomplete_size_count > 0 { ">= " } else { "" },
                    known_reclaimable
                        .map(|bytes| size_unit.format(bytes))
                        .unwrap_or_else(|| "unknown".to_string()),
                    incomplete_size_count,
                ),
                (sweepx_i18n::Locale::EnUs, true) => format!(
                    "Summary: {} candidates, {}{} accounted reclaimable; {} lower-bound or unknown sizes; nothing has moved yet, and an exact confirmation plan follows.",
                    candidates.len(),
                    if incomplete_size_count > 0 { ">= " } else { "" },
                    known_reclaimable
                        .map(|bytes| size_unit.format(bytes))
                        .unwrap_or_else(|| "unknown".to_string()),
                    incomplete_size_count,
                ),
                (sweepx_i18n::Locale::ZhCn, false) => format!(
                    "汇总：{} 个候选，已统计可回收 {}{}；{} 项为下限或未知；没有执行删除。",
                    candidates.len(),
                    if incomplete_size_count > 0 { ">= " } else { "" },
                    known_reclaimable
                        .map(|bytes| size_unit.format(bytes))
                        .unwrap_or_else(|| "unknown".to_string()),
                    incomplete_size_count,
                ),
                (sweepx_i18n::Locale::EnUs, false) => format!(
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
    }
    #[cfg(target_os = "linux")]
    if let Some((_, discovery)) = &temp_discovery
        && !discovery.complete
    {
        eprintln!(
            "Linux /tmp discovery was incomplete: {}; --clean-temp will refuse the truncated report.",
            discovery
                .incomplete_reason
                .as_deref()
                .unwrap_or("unknown reason")
        );
    }
    // When npm is in scope, report every installation discovered: the manager controlling each,
    // its version, which copy PATH defaults to, and the measured last activity of its cache. This
    // is what lets a reader see multiple npm copies instead of only the resolver's answer.
    // Inventory is the same invocation snapshot used by classification, never a second
    // round of subprocesses after scanning. Explicit project-only scans have no tool probes.
    let npm_installations = &evidence.npm_installations;
    if format != OutputFormat::Human {
        // All-cache runs (no fresh scan) are treated as ok; otherwise use the fresh scan's status.
        let scan_status_ok = scan
            .as_ref()
            .is_none_or(|result| result.scan.output.status == sweepx_protocol::OutputStatus::Ok);
        println!(
            "{}",
            json!({
                "schema": "sweepx.junk.result/v1",
                "status": if scan_status_ok && temp_discovery_complete && !evidence.discovery_incomplete() { "ok" } else { "partial" },
                "readOnly": true,
                "tempDiscovery": temp_discovery_json,
                "layoutDiscovery": {
                    "complete": layout_failure.is_none(),
                    "incompleteReason": layout_failure.map(|failure| failure.code()),
                },
                "npmDiscovery": platform_rules.iter().any(|rule| rule.root_kind == "npm_reported_cache").then(|| json!({
                    "complete": tool_failure.is_none(),
                    "incompleteReason": tool_failure.map(|failure| failure.code()),
                })),
                "candidateCount": candidates.len(),
                "knownReclaimableBytes": known_reclaimable.map(|value| value.to_string()),
                "incompleteSizeCount": incomplete_size_count,
                "toolInstallations": npm_installations.iter().map(|installation| json!({
                    "tool": installation.tool,
                    "manager": installation.manager,
                    "managerLabel": installation.manager_label,
                    "executable": installation.executable.to_string_lossy(),
                    "toolVersion": installation.tool_version,
                    "runtimeVersion": installation.runtime_version,
                    "cache": installation.cache.as_ref().map(|cache| cache.to_string_lossy()),
                    "cacheLastActiveAt": installation.cache_last_active_at,
                    "isPathDefault": installation.is_path_default,
                })).collect::<Vec<_>>(),
                "candidates": candidates.iter().map(|candidate| json!({
                    "path": candidate.path, "ruleId": candidate.rule_id, "risk": candidate.risk,
                    "reclaimable": candidate.reclaimable,
                    "evidence": candidate.evidence,
                    "sourceReviewedAt": candidate.source_reviewed_at,
                    "references": candidate.references,
                    // Markers, not instructions. `activity` says whether the tool is using this
                    // copy; `staleFormats` names obsolete format directories inside it. Both are
                    // omitted when they do not apply so a reader never sees an empty claim.
                    "activity": candidate.activity,
                    "staleFormats": candidate.stale_formats,
                    "git": candidate.git.as_ref().map(|evidence| json!({
                        "status": evidence.status,
                        "repositoryEntryId": evidence.repository_entry_id,
                        "check": evidence.check,
                    })),
                    "classification": candidate.classification,
                    "confidence": candidate.confidence,
                    "blockers": candidate.blockers,
                    "projectFormat": candidate.project_format,
                    "projectContext": candidate.project_context,
                    "executionPolicy": candidate.execution_policy,
                    // Names the quantity in `reclaimable`. True means apparent logical size,
                    // because this platform declined to claim filesystem allocation; the two
                    // differ on compressed, sparse and multi-stream files, so a consumer that
                    // needs allocation must be able to see that it did not get it.
                    "sizeIsLogical": candidate.size_is_logical,
                })).collect::<Vec<_>>(),
            })
        );
    }
    timings.phase("report");
    timings.finish(candidates.len());
    if clean.enabled {
        #[cfg(target_os = "linux")]
        {
            return temp_clean_command::run_temp_clean(
                temp_clean_inputs,
                clean.quarantine_dir,
                temp_discovery_complete,
                format,
                context.locale(),
                clean.stdin_is_terminal,
            );
        }
        #[cfg(not(target_os = "linux"))]
        {
            eprintln!("junk --system --clean-temp is currently available only on Linux");
            return ProcessExitCode::from(3);
        }
    }
    // An all-cache run (no fresh scan) reports success; a run that scanned uses the fresh output's
    // conservative exit code so any partial coverage still degrades the code.
    let scan_exit = scan.as_ref().map_or(0, |result| {
        result.scan.output.conservative_exit_code() as u8
    });
    ProcessExitCode::from(
        if scan_exit == 0 && (!temp_discovery_complete || evidence.discovery_incomplete()) {
            4
        } else {
            scan_exit
        },
    )
}

fn junk_evidence_bytes(value: &ByteValue) -> Option<u128> {
    match value {
        EvidenceValue::Known { value } | EvidenceValue::LowerBound { value, .. } => Some(value.0),
        _ => None,
    }
}

fn junk_project_context_label(
    evidence: &sweepx_core::junk::manifest::ProjectContextEvidence,
) -> String {
    let mut label = format!("{}/{}", evidence.status.code(), evidence.reason);
    if let Some(manifest) = evidence.cargo_manifest {
        use std::fmt::Write;
        let members = manifest
            .member_patterns
            .map(|n| n.to_string())
            .unwrap_or_else(|| "not_declared".into());
        let _ = write!(
            label,
            "; kind={}; memberPatterns={members}; explicitWorkspace={}; pathDependenciesDeclared={}",
            manifest.kind.code(),
            manifest.explicit_workspace,
            manifest.path_dependencies_declared
        );
    }
    if let Some(config) = evidence.cargo_config {
        use std::fmt::Write;
        let _ = write!(
            label,
            "; config={}/{}; configPathKind={}; configToml={}/{}; configTomlPathKind={}; precedenceComplete={}",
            config.config.status.code(),
            config.config.reason,
            config
                .config
                .path_kind
                .map(|kind| kind.code())
                .unwrap_or("unknown"),
            config.config_toml.status.code(),
            config.config_toml.reason,
            config
                .config_toml
                .path_kind
                .map(|kind| kind.code())
                .unwrap_or("unknown"),
            config.precedence_complete
        );
    }
    if let Some(output) = evidence.cargo_output {
        use std::fmt::Write;
        let _ = write!(
            label,
            "; output={}/{}; outputScope={}; configModel={}; outputSource={}; candidatePath={}",
            output.status.code(),
            output.reason,
            output.scope,
            output.config_model,
            output
                .source
                .map(|source| source.code())
                .unwrap_or("unknown"),
            output.candidate_path.code()
        );
        if let Some(workspace) = output.workspace {
            let _ = write!(
                label,
                "; workspace={}; members={}; defaultMembers={}; projectIsRoot={}",
                workspace.is_workspace,
                workspace.member_count,
                workspace.default_member_count,
                workspace.project_is_root
            );
        }
    }
    label
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
    create: bool,
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
    let resolved = if create {
        durable_store(state_dir.as_deref())
    } else {
        sweepx_core::existing_durable_store(state_dir.as_deref())
    };
    let store = match resolved {
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

impl Drop for ScanProgress {
    fn drop(&mut self) {
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

struct NormalizedJunkRoots {
    platform: Option<PlatformJunkSetup>,
    scan_roots: Vec<PathBuf>,
    temp_roots: Vec<PathBuf>,
}

fn normalize_junk_roots(
    system: bool,
    raw_roots: &[OsString],
    rule_ids: &[String],
) -> Result<NormalizedJunkRoots, String> {
    if !system {
        return Ok(NormalizedJunkRoots {
            platform: None,
            scan_roots: normalize_scan_roots(raw_roots).map_err(|error| error.to_string())?,
            temp_roots: Vec::new(),
        });
    }

    let explicit = if raw_roots.is_empty() {
        Vec::new()
    } else {
        normalize_roots(raw_roots).map_err(|error| error.to_string())?
    };
    #[cfg(target_os = "linux")]
    if !explicit.is_empty() {
        if let Some(temp_root) = linux_temp::report_temp_root()
            && explicit.iter().all(|root| {
                root == temp_root.as_path() || root.parent() == Some(temp_root.as_path())
            })
        {
            let temp_roots = explicit
                .iter()
                .filter(|root| root.as_path() != temp_root.as_path())
                .cloned()
                .collect::<Vec<_>>();
            let platform = PlatformJunkSetup::discover_selected_with_cancel(
                rule_ids,
                CancellationToken::new(),
            )?;
            return Ok(NormalizedJunkRoots {
                scan_roots: default_platform_junk_roots(&platform),
                temp_roots,
                platform: Some(platform),
            });
        }
        return Err(
            "junk --system cannot be combined with explicit non-temporary roots".to_string(),
        );
    }
    #[cfg(not(target_os = "linux"))]
    if !explicit.is_empty() {
        return Err("junk --system cannot be combined with explicit roots".to_string());
    }

    let platform =
        PlatformJunkSetup::discover_selected_with_cancel(rule_ids, CancellationToken::new())?;
    let scan_roots = default_platform_junk_roots(&platform);
    if scan_roots.is_empty() {
        return Err("no supported platform junk root is available".to_string());
    }
    Ok(NormalizedJunkRoots {
        platform: Some(platform),
        scan_roots,
        temp_roots: Vec::new(),
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
) -> Result<(), Box<dyn std::error::Error>> {
    let stdout = std::io::stdout();
    let mut writer = std::io::BufWriter::with_capacity(16 * 1024, stdout.lock());
    match format {
        OutputFormat::Human => {
            let text = match result {
                RenderedResult::Scan(scan) => scan.render_human(context, size_unit, sort),
                _ => sweepx_core::render_human_output_with_size_unit(
                    context,
                    result.output(),
                    size_unit,
                    sort,
                ),
            };
            writeln!(writer, "{text}")?;
        }
        OutputFormat::Json => {
            match result {
                RenderedResult::Scan(scan) => scan.write_json(&mut writer)?,
                _ => writer.write_all(serialize_json(result.output()).as_bytes())?,
            }
            writer.write_all(b"\n")?;
        }
        OutputFormat::Ndjson => match result {
            RenderedResult::Scan(scan) => {
                for event in scan.events() {
                    serde_json::to_writer(&mut writer, event)?;
                    writer.write_all(b"\n")?;
                }
            }
            #[cfg(target_os = "linux")]
            RenderedResult::Replay(replay) => {
                for event in &replay.events {
                    serde_json::to_writer(&mut writer, event)?;
                    writer.write_all(b"\n")?;
                    writer.flush()?;
                }
            }
            _ => {
                serde_json::to_writer(&mut writer, result.output())?;
                writer.write_all(b"\n")?;
            }
        },
    }
    writer.flush()?;
    Ok(())
}

enum RenderedResult {
    Scan(sweepx_core::ScanOutput),
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
            Self::Scan(scan) => scan.metadata(),
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
    fn valid_verification_date(value: &str) -> bool {
        value.len() == 10
            && value.bytes().enumerate().all(|(index, byte)| {
                matches!(index, 4 | 7) && byte == b'-'
                    || !matches!(index, 4 | 7) && byte.is_ascii_digit()
            })
    }

    #[cfg(target_os = "macos")]
    fn observed_cache_root(root: &Path) -> sweepx_model::ScannedEntry {
        let context = CoreContext::new(sweepx_i18n::LocaleResolution::new(
            sweepx_i18n::Locale::EnUs,
            sweepx_i18n::LocaleSource::Explicit,
        ));
        sweepx_core::scan_for_tui_with_store::<sweepx_core::MemorySnapshotStore>(
            &context,
            &ScanRequest {
                roots: vec![root.to_path_buf()],
                state_dir: None,
            },
            None,
        )
        .unwrap()
        .summary
        .roots
        .remove(0)
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn cached_tool_activity_uses_current_evidence_without_replaying_old_claims() {
        let fixture = tempfile::tempdir().unwrap();
        let root = fixture.path().canonicalize().unwrap();
        std::fs::create_dir(root.join("wheels")).unwrap();
        let rule = load_platform_junk_rules()
            .unwrap()
            .into_iter()
            .find(|rule| rule.root_kind == "pip_reported_cache")
            .unwrap();
        let entry = observed_cache_root(&root);
        let current = PlatformJunkEvidence::precompute_with(
            std::slice::from_ref(&rule),
            |_| Some(root.clone()),
            Vec::new(),
        );
        let mut prior =
            assemble_platform_candidate(&rule, &entry, &BTreeMap::new(), &current).unwrap();
        prior.activity = Some("stale".into());
        prior.stale_formats = vec!["invented-old-format".into()];
        prior.classification = Some("known_generated_ignored".into());
        prior.confidence = Some("high".into());
        let stored = junk_candidate_to_stored(&prior);
        let json = serde_json::to_value(&stored).unwrap();
        for field in [
            "activity",
            "stale_formats",
            "git",
            "classification",
            "confidence",
            "blockers",
        ] {
            assert!(
                json.get(field).is_none(),
                "transient claim persisted: {field}"
            );
        }
        let rules = [rule];
        let live = stored_candidate_to_junk(stored.clone(), &[], &rules, &current).unwrap();
        assert_eq!(live.activity.as_deref(), Some("live"));
        assert!(live.stale_formats.is_empty());
        assert!(live.confidence.is_none());
        let failed = PlatformJunkEvidence::default();
        let unknown = stored_candidate_to_junk(stored, &[], &rules, &failed).unwrap();
        assert_eq!(unknown.activity.as_deref(), Some("unknown"));
        assert!(
            unknown
                .blockers
                .iter()
                .any(|value| value == "tool_evidence_not_revalidated")
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn cached_project_facts_do_not_preserve_git_confidence() {
        let fixture = tempfile::tempdir().unwrap();
        let root = fixture.path().canonicalize().unwrap();
        let entry = observed_cache_root(&root);
        let rules = load_project_junk_rules().unwrap();
        let mut prior = assemble_project_candidate(&rules[0], &entry, &BTreeMap::new()).unwrap();
        prior.git = Some(GitIgnoreEvidence {
            status: "ignored".into(),
            repository_entry_id: prior.entry_id.to_string(),
            check: "git.check-ignore.v1".into(),
        });
        prior.classification = Some("known_generated_ignored".into());
        prior.confidence = Some("high".into());
        let restored = stored_candidate_to_junk(
            junk_candidate_to_stored(&prior),
            &rules,
            &[],
            &PlatformJunkEvidence::default(),
        )
        .unwrap();
        assert!(restored.git.is_none());
        assert_eq!(restored.classification.as_deref(), Some("known_generated"));
        assert_eq!(restored.confidence.as_deref(), Some("medium"));
        assert_eq!(
            restored.blockers,
            [
                "project_ownership_not_verified",
                "project_activity_not_verified",
                "git_evidence_not_revalidated"
            ]
        );
        assert_eq!(restored.reclaimable, prior.reclaimable);
        assert_eq!(restored.source_entry, prior.source_entry);
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn validated_disk_candidate_hit_rebuilds_git_from_current_external_configuration() {
        let owner = tempfile::tempdir().unwrap();
        let base = owner.path().canonicalize().unwrap();
        let root = base.join("project");
        std::fs::create_dir_all(root.join("target")).unwrap();
        std::fs::write(root.join("Cargo.toml"), b"[workspace]\nmembers=[]\n").unwrap();
        std::fs::write(root.join("target/file"), b"payload").unwrap();
        let run_git = |args: &[&std::ffi::OsStr]| {
            let mut command = std::process::Command::new("git");
            command.arg("-C").arg(&base).args(args);
            let output =
                sweepx_core::tools::ProbeRunner::new(Default::default(), CancellationToken::new())
                    .run(&mut command)
                    .unwrap();
            assert!(output.status.success());
        };
        run_git(&[
            std::ffi::OsStr::new("init"),
            std::ffi::OsStr::new("--quiet"),
        ]);
        let excludes = base.join("external-excludes");
        std::fs::write(&excludes, b"project/target/\n").unwrap();
        run_git(&[
            std::ffi::OsStr::new("config"),
            std::ffi::OsStr::new("core.excludesFile"),
            excludes.as_os_str(),
        ]);
        let service = JunkService::built_in().unwrap();
        let evidence = PlatformJunkEvidence::default();
        let classifier = service.with_platform(&[], &evidence);
        let digest = classifier.classification_context_digest().unwrap();
        let context = CoreContext::new(sweepx_i18n::LocaleResolution::new(
            sweepx_i18n::Locale::EnUs,
            sweepx_i18n::LocaleSource::Explicit,
        ));
        let scan = scan_junk_with_store::<sweepx_core::MemorySnapshotStore>(
            &context,
            &ScanRequest {
                roots: vec![root.clone()],
                state_dir: None,
            },
            None,
            &classifier,
            None,
        )
        .unwrap();
        let aggregates = scan
            .scan
            .summary
            .aggregates
            .iter()
            .map(|aggregate| (aggregate.directory_identity.as_str(), aggregate))
            .collect();
        let mut fresh = scan
            .scan
            .summary
            .entries
            .iter()
            .filter_map(|entry| {
                let decision = scan.decisions.get(&entry.identity.as_ref()?.entry_id)?;
                service.interpret(decision, entry, &aggregates, &[], &evidence)
            })
            .collect::<Vec<_>>();
        assert_eq!(fresh.len(), 1);
        let mut git = GitEvidenceSession::new(Default::default(), CancellationToken::new());
        git.capture_scan_facts(
            &scan.scan.summary,
            &scan.coverages,
            &scan.directory_markers,
            &mut fresh,
        );
        git.refresh(&mut fresh);
        assert_eq!(fresh[0].confidence.as_deref(), Some("high"));
        let record = junk_cache::StoredJunkRoot::capture(
            &root,
            fresh.iter().map(junk_candidate_to_stored).collect(),
            42,
            digest,
        )
        .unwrap();
        let cache = base.join("private-cache");
        junk_cache::write(&cache, &record).unwrap();
        let restore = || {
            let roots = vec![root.clone()];
            // Test persistent facts independently of the retired whole-root current replay.
            // This checks fresh Git interpretation, not freshness of the historical tree.
            junk_cache::CacheReader::new(&cache)
                .historical_roots(&roots)
                .remove(0)
                .expect("historical filesystem facts round trip")
                .into_candidates()
                .into_iter()
                .map(|stored| {
                    stored_candidate_to_junk(stored, service.project_rules(), &[], &evidence)
                        .unwrap()
                })
                .collect::<Vec<_>>()
        };
        let mut warm = restore();
        assert!(warm[0].git.is_none(), "Git answers were not persisted");
        GitEvidenceSession::new(Default::default(), CancellationToken::new()).refresh(&mut warm);
        assert_eq!(warm[0].confidence.as_deref(), Some("high"));
        assert_eq!(
            warm[0].blockers,
            [
                "project_ownership_not_verified",
                "project_activity_not_verified"
            ]
        );
        std::fs::write(&excludes, b"").unwrap();
        let mut changed = restore();
        GitEvidenceSession::new(Default::default(), CancellationToken::new()).refresh(&mut changed);
        assert_eq!(changed[0].confidence.as_deref(), Some("medium"));
        assert!(changed[0].git.is_none());
        assert_eq!(
            changed[0].blockers,
            [
                "project_ownership_not_verified",
                "project_activity_not_verified"
            ]
        );
        assert_eq!(std::fs::read(root.join("target/file")).unwrap(), b"payload");
        let names = std::fs::read_dir(&root)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect::<BTreeSet<_>>();
        assert_eq!(
            names,
            ["Cargo.toml", "target"]
                .into_iter()
                .map(std::ffi::OsString::from)
                .collect()
        );
    }

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
        #[cfg(target_os = "linux")]
        {
            let parsed = Cli::try_parse_from(["sweepx", "delete", "/tmp/file"]).unwrap();
            assert!(matches!(parsed.command, Commands::Delete { .. }));
            assert!(
                Cli::try_parse_from(["sweepx", "delete", "--permanently", "/tmp/file",]).is_err()
            );
        }
        #[cfg(not(target_os = "linux"))]
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
    fn system_junk_tui_parses_without_explicit_roots() {
        let cli = Cli::try_parse_from(["sweepx", "junk", "--system", "--tui"]).unwrap();
        assert!(
            matches!(cli.command, Commands::Junk { system: true, tui: true, roots, .. } if roots.is_empty())
        );
    }

    #[test]
    fn junk_rule_selection_requires_system_and_is_preserved_for_tui() {
        assert!(Cli::try_parse_from(["sweepx", "junk", "--rule", "tool.pip-cache", "."]).is_err());
        let cli = Cli::try_parse_from([
            "sweepx",
            "junk",
            "--system",
            "--tui",
            "--rule",
            "tool.pip-cache",
            "--rule",
            "tool.npm-cache",
        ])
        .unwrap();
        assert!(
            matches!(cli.command, Commands::Junk { system: true, tui: true, rules, .. } if rules == ["tool.pip-cache", "tool.npm-cache"])
        );
    }

    #[test]
    fn quarantine_location_accepts_system_tui_and_requires_system_scope() {
        let cli = Cli::try_parse_from([
            "sweepx",
            "junk",
            "--system",
            "--tui",
            "--quarantine-dir",
            "/volume/private",
        ])
        .unwrap();
        assert!(matches!(
            cli.command,
            Commands::Junk {
                tui: true,
                system: true,
                quarantine_dir: Some(_),
                ..
            }
        ));
        assert!(
            Cli::try_parse_from([
                "sweepx",
                "junk",
                "--tui",
                "--quarantine-dir",
                "/volume/private",
                "/project"
            ])
            .is_err()
        );
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
    fn junk_system_rejects_explicit_roots() {
        let roots = vec![OsString::from(".")];
        assert!(normalize_junk_roots(true, &roots, &[]).is_err());
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
        let request = current_relaunch_request(None).expect("the test binary has a path");

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

    /// A relay destination requested by an outer caller must never be forwarded.
    ///
    /// The destination has to be the one this process just created inside its own private
    /// directory. Forwarding an inherited value would let a caller choose where an *elevated*
    /// SweepX writes, which is a privilege-escalation primitive rather than a feature. Both spellings
    /// are stripped, and the separated form must not leave its value behind as a stray positional
    /// argument — that would silently turn a path into an extra scan root.
    #[test]
    fn an_inherited_relay_destination_is_never_forwarded() {
        let chosen = Path::new("C:\\sweepx-chosen\\stdout");

        for inherited in [
            vec![
                OsString::from("scan"),
                OsString::from(RELAY_FLAG),
                OsString::from("C:\\attacker\\target"),
                OsString::from("C:\\real\\root"),
            ],
            vec![
                OsString::from("scan"),
                OsString::from(format!("{RELAY_FLAG}=C:\\attacker\\target")),
                OsString::from("C:\\real\\root"),
            ],
        ] {
            let forwarded = forwardable_arguments(inherited.into_iter(), Some(chosen));

            assert!(
                !forwarded
                    .iter()
                    .any(|argument| argument.to_string_lossy().contains("attacker")),
                "an inherited relay destination survived: {forwarded:?}"
            );
            assert!(
                forwarded
                    .iter()
                    .any(|argument| argument == "C:\\real\\root"),
                "stripping the flag must not consume a real argument: {forwarded:?}"
            );
            let relay_positions = forwarded
                .iter()
                .filter(|argument| *argument == RELAY_FLAG)
                .count();
            assert_eq!(
                relay_positions, 1,
                "exactly one relay flag, the one we chose: {forwarded:?}"
            );
            assert!(
                forwarded
                    .iter()
                    .any(|argument| argument == chosen.as_os_str()),
                "our own destination must be passed: {forwarded:?}"
            );
        }
    }

    /// Without a relay the child is told nothing about one, so it writes to its own console.
    #[test]
    fn no_relay_means_no_relay_flag() {
        let forwarded = forwardable_arguments(
            vec![OsString::from("scan"), OsString::from("C:\\root")].into_iter(),
            None,
        );
        assert_eq!(
            forwarded,
            vec![OsString::from("scan"), OsString::from("C:\\root")]
        );
    }
}
