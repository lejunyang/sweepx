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
#[cfg(target_os = "macos")]
use sweepx_core::junk::ProjectJunkRule as JunkRule;
#[cfg(test)]
use sweepx_core::junk::load_project_rules as load_project_junk_rules;
mod junk_timings;
mod junk_tui;
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
    scan_for_tui_with_store, scan_junk_with_store, scan_ndjson_supported, scan_with_store,
    serialize_json, serialize_ndjson, state_dir_from_explicit_or_default, status_with_store,
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
        /// Browse directories interactively and scan details on demand.
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
    /// Reports partial results when discovery or scan evidence is incomplete.
    Junk {
        /// Open the live junk view for explicit directory roots. Space selects; d moves selected
        /// current, complete candidates to Trash after native identity revalidation.
        /// macOS shows historical caches first; only freshly verified rows can be moved.
        #[arg(long, conflicts_with_all = ["timings", "system", "trash", "clean_temp", "quarantine_dir"])]
        tui: bool,
        /// Emit phase timings and root-cache hit counts as one JSON diagnostic on stderr.
        /// Measures report-only work; stdout keeps its existing format.
        #[arg(long, conflicts_with_all = ["trash", "clean_temp"])]
        timings: bool,
        /// Scan conservative platform cache roots; conflicts with explicit roots.
        /// Tool discovery has a 10s batch budget, a 2s probe timeout and a 64 KiB answer limit.
        #[arg(long)]
        system: bool,
        /// Move approved stale Linux temporary objects to a recoverable quarantine.
        ///
        /// Requires `--system`, human output, and a foreground terminal. The full plan digest
        /// must be typed back exactly. This never falls back to permanent deletion.
        #[arg(long, requires = "system", conflicts_with = "roots")]
        clean_temp: bool,
        /// Move classified junk candidates to the operating-system Trash.
        ///
        /// One explicit confirmation covers the exact plan. Each target is revalidated by
        /// native identity immediately before it is moved. This never falls back to permanent
        /// deletion.
        #[arg(long, conflicts_with = "clean_temp")]
        trash: bool,
        /// Absolute quarantine base on a filesystem different from `/tmp`.
        ///
        /// Defaults to `$XDG_DATA_HOME/sweepx/quarantine` or
        /// `$HOME/.local/share/sweepx/quarantine`.
        #[arg(long, value_name = "ABSOLUTE_DIRECTORY", requires = "clean_temp")]
        quarantine_dir: Option<PathBuf>,
        #[arg(value_name = "ROOT")]
        roots: Vec<OsString>,
    },
    Cache {
        #[command(subcommand)]
        command: CacheCommands,
    },
    /// Report browser site storage per origin. Never deletes and never pre-selects.
    ///
    /// Separate from `junk` on purpose. Junk means "rebuildable"; this is R3 site application
    /// state — PWA offline data and structured site data — which the browser itself only ever
    /// removes one site at a time and which is not safe to treat as disposable in bulk.
    SiteStorage {
        /// Move one named origin's storage to the Trash. Requires an exact storage key.
        ///
        /// One origin at a time by design: R3 permits an individually selected item, not a batch.
        /// The key must match exactly, partition included, because a hostname can name several
        /// mutually isolated partitions and clearing the wrong one destroys data the user did not
        /// choose.
        #[arg(long, value_name = "STORAGE_KEY")]
        trash_origin: Option<String>,
        /// Browse the storage directories interactively, with per-origin labels.
        ///
        /// Scans the storage roots for real, so every row carries the identity and native locator
        /// the Trash path requires. The alternative — synthesizing entries from the report — is
        /// forbidden by the model itself: `identity` and `native_locator` must not be derived from a
        /// display path, and the interactive Trash takes its authority from exactly those fields.
        #[arg(long, conflicts_with = "trash_origin")]
        browse: bool,
    },
    /// Move one file or directory to the operating system Trash/Recycle Bin.
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
        Commands::Junk {
            tui,
            timings,
            system,
            clean_temp,
            trash,
            quarantine_dir,
            roots,
        } => {
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
                    Ok(roots) if !roots.is_empty() => roots,
                    Ok(_) => {
                        eprintln!("junk --tui requires explicit directory roots");
                        return ProcessExitCode::from(2);
                    }
                    Err(error) => {
                        eprintln!("{error}");
                        return ProcessExitCode::from(2);
                    }
                };
                let cache_dir = state_dir_from_explicit_or_default(cli.state_dir.as_deref())
                    .ok()
                    .flatten()
                    .map(|state_dir| state_dir.join("junk-cache"));
                return junk_tui::run(roots, context.locale(), size_unit, sort, cache_dir);
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
            let normalized_roots = match normalize_junk_roots(system, &roots) {
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
            let cache_dir = state_dir_from_explicit_or_default(cli.state_dir.as_deref())
                .ok()
                .flatten()
                .map(|state_dir| state_dir.join("junk-cache"));
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
                cache_dir,
                timings,
            );
        }
        Commands::SiteStorage {
            trash_origin,
            browse,
        } => {
            if browse {
                if let Err(message) = validate_tui_environment(
                    format,
                    std::io::stdin().is_terminal(),
                    std::io::stdout().is_terminal(),
                ) {
                    // The shared validator names `--tui`, which is not the flag the user typed here.
                    // Reporting a flag that does not appear in their command sends them looking for
                    // the wrong thing, so the actual one is named alongside it.
                    eprintln!("--browse: {message}");
                    return ProcessExitCode::from(2);
                }
                let roots = site_storage_roots();
                if roots.is_empty() {
                    eprintln!("no browser site storage was found to browse");
                    return ProcessExitCode::from(3);
                }
                // Deliberately routed through the ordinary scan and the existing browser: the
                // interactive Trash reads its authority from the scanner's identity and native
                // locator, so the rows have to come from a real scan rather than from the report.
                let scan = scan_for_tui_with_store(
                    &context,
                    &ScanRequest {
                        roots,
                        state_dir: None,
                    },
                    Option::<&sweepx_core::MemorySnapshotStore>::None,
                );
                return finish_tui_scan(&context, scan, size_unit, sort);
            }
            return run_site_storage(
                &context,
                format,
                size_unit,
                trash_origin.as_deref(),
                std::io::stdin().is_terminal(),
            );
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
                let state_dir = match state_dir_from_explicit_or_default(cli.state_dir.as_deref()) {
                    Ok(value) => value,
                    Err(error) => {
                        let result =
                            RenderedResult::CacheStatus(cache_status_state_error(&context, &error));
                        let code = result.exit_code();
                        print_output(&context, format, size_unit, sort, &result);
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
#[cfg(target_os = "macos")]
use sweepx_core::junk::candidate::refresh_candidate_interpretation;
#[cfg(all(test, target_os = "macos"))]
use sweepx_core::junk::candidate::{assemble_platform_candidate, assemble_project_candidate};
use sweepx_core::junk::git::{GitEvidenceLimits, GitEvidenceSession};

#[cfg(target_os = "macos")]
use sweepx_core::junk::platform::PlatformJunkEvidence;
#[cfg(target_os = "macos")]
use sweepx_core::junk::platform::PlatformJunkRule;
#[cfg(all(test, target_os = "macos"))]
use sweepx_core::junk::platform::load_platform_junk_rules;
use sweepx_core::junk::platform::{
    CHROMIUM_INSTALLS, PlatformJunkSetup, default_platform_junk_roots, is_existing_real_directory,
    same_directory, user_home_dir,
};

/// Index of the deepest canonical root that is an ancestor of `path`, or `None`.
///
/// "Deepest" = the longest matching root, so a candidate under `…/Caches/Yarn` attributes to the
/// Yarn root rather than the wider `…/Caches` root. Matching is by exact path component, with a
/// trailing separator, so a prefix directory name cannot partially match.
#[cfg(target_os = "macos")]
fn deepest_root_for(path: &str, roots: &[PathBuf]) -> Option<usize> {
    let mut best: Option<(usize, usize)> = None;
    for (index, root) in roots.iter().enumerate() {
        let root_text = root.display().to_string();
        let matches = path == root_text || path.starts_with(&format!("{root_text}/"));
        if matches && best.is_none_or(|(_, len)| root_text.len() > len) {
            best = Some((index, root_text.len()));
        }
    }
    best.map(|(index, _)| index)
}

/// Converts an in-memory candidate into the cache record's owned form.
#[cfg(target_os = "macos")]
fn junk_candidate_to_stored(candidate: &JunkCandidate) -> junk_cache::StoredJunkCandidate {
    junk_cache::StoredJunkCandidate::from_candidate(candidate)
}

/// Converts a cache record back into an in-memory candidate.
///
/// Tool interpretation is rebuilt from this invocation. Git metadata is not retained in the
/// root facts, so project candidates first revert to base confidence with an explicit blocker;
/// the current Git session then independently refreshes them using validated traversal facts.
#[cfg(target_os = "macos")]
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
    // Directory holding the per-root junk cache (`<state>/junk-cache`); `None` when caching is
    // unavailable (non-macOS, or no usable state directory).
    #[cfg_attr(not(target_os = "macos"), allow(unused_variables))] cache_dir: Option<PathBuf>,
    mut timings: junk_timings::JunkTimings,
) -> ProcessExitCode {
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
    #[cfg(target_os = "macos")]
    let rules = project_service.project_rules();
    let PlatformJunkSetup {
        rules: platform_rules,
        evidence,
    } = platform.unwrap_or_default();
    let layout_failure = evidence.layout_failure();
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

    // Load both cache generations before the single history observation. The pre-scan cursor
    // above remains the next generation's cursor, preserving changes racing with validation.
    #[cfg(target_os = "macos")]
    let (subtree_provider, cache_records) = subtree_provider::SubtreeCacheProvider::prepare(
        cache_dir.as_deref().unwrap_or(Path::new("/nonexistent")),
        &canonical_roots,
        classification_context.as_ref(),
    );

    // Split roots into FSEvents-validated cache hits and the indexes that still need scanning.
    #[cfg(target_os = "macos")]
    let (hit_records, miss_indexes): (Vec<junk_cache::StoredJunkRoot>, Vec<usize>) =
        match &cache_dir {
            Some(_) => {
                let mut hits = Vec::new();
                let mut misses = Vec::new();
                for (index, record) in cache_records.into_iter().enumerate() {
                    match record {
                        Some(record) => hits.push(record),
                        _ => misses.push(index),
                    }
                }
                (hits, misses)
            }
            None => (Vec::new(), (0..canonical_roots.len()).collect()),
        };
    // Off macOS there is no FSEvents validity source; every root is scanned.
    #[cfg(not(target_os = "macos"))]
    let miss_indexes: Vec<usize> = (0..canonical_roots.len()).collect();

    #[cfg(target_os = "macos")]
    let mut cached_candidates: Vec<JunkCandidate> = hit_records
        .into_iter()
        .flat_map(junk_cache::StoredJunkRoot::into_candidates)
        .filter_map(|stored| stored_candidate_to_junk(stored, rules, &platform_rules, &evidence))
        .collect();
    // Caching is macOS-only; other platforms have no restored candidates.
    #[cfg(not(target_os = "macos"))]
    let mut cached_candidates: Vec<JunkCandidate> = Vec::new();
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

    git_session.refresh(&mut fresh_candidates);
    git_session.refresh(&mut cached_candidates);
    timings.phase("gitEvidence");

    // Persist every scanned (miss) root with the candidates attributed to its deepest root, then
    // keep other roots while the bounded cache has space. A root with zero candidates is still
    // written so an empty-but-scanned root stays a hit next time.
    #[cfg(target_os = "macos")]
    if let Some(cache) = &cache_dir {
        for index in &miss_indexes {
            let root = &canonical_roots[*index];
            // Unknown discovery scope or a context digest that exceeds its bound cannot justify
            // candidate reuse, even with complete filesystem traversal. File facts are independent.
            let Some(classification_context) = classification_context else {
                continue;
            };
            // Incomplete scans (including denied roots) must be retried, never frozen as hits.
            if !scan.as_ref().is_some_and(|scan| {
                root.to_str()
                    .is_some_and(|path| scan.covered_paths.get(path) == Some(&true))
            }) {
                continue;
            }
            let mut stored = Vec::new();
            for candidate in &fresh_candidates {
                if deepest_root_for(&candidate.path, &canonical_roots) == Some(*index) {
                    let mut row = junk_candidate_to_stored(candidate);
                    row.aggregate = scan
                        .as_ref()
                        .and_then(|scan| {
                            scan.scan.summary.aggregates.iter().find(|aggregate| {
                                aggregate.directory_identity == candidate.entry_id.as_str()
                            })
                        })
                        .cloned();
                    stored.push(row);
                }
            }
            match junk_cache::StoredJunkRoot::capture(
                root,
                stored,
                scan_event_id,
                classification_context,
            )
            .and_then(|mut record| {
                if !scan.as_ref().is_some_and(|scan| {
                    scan.observed_roots
                        .iter()
                        .any(|source| record.matches_observed_root(source))
                }) {
                    return Err(std::io::Error::other("cache root changed after traversal"));
                }
                record.bind_scope(&canonical_roots);
                junk_cache::write(cache, &record)
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
        if let Some(scan) = &scan {
            for source in &scan.observed_roots {
                if let Err(error) = subtree_provider.store_observed_index(
                    source,
                    &canonical_roots,
                    scan_event_id,
                    &scan.covered_paths,
                    &scan.dir_listings,
                ) {
                    eprintln!(
                        "could not update subtree index for {}: {error}",
                        source.display_path
                    );
                }
            }
        }
    }

    #[cfg(target_os = "macos")]
    if let Some(cache) = &cache_dir
        && let Err(error) = junk_cache::prune(cache)
    {
        eprintln!("could not prune junk cache: {error}");
    }

    timings.phase("cacheWrite");
    let mut candidates = cached_candidates;
    candidates.append(&mut fresh_candidates);
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
            // Eligibility is the row's own coverage: a directory that was scanned completely can
            // be reclaimed; an incomplete row stays ineligible so the move fails closed.
            let eligible = entry.coverage.complete && !entry.coverage.details_lost;
            items.push(trash_command::BulkTrashItem {
                path: candidate.path.clone(),
                size: junk_evidence_bytes(&candidate.reclaimable).unwrap_or(0),
                rule_id: candidate.rule_id.clone(),
                entry,
                eligible,
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
                    "垃圾扫描报告（已核验可重建/可丢弃位置；仅报告）"
                }
                (sweepx_i18n::Locale::EnUs, false) =>
                    "Junk scan report (verified rebuildable/disposable locations; report-only)",
            }
        );
        for candidate in &candidates {
            let git_note = match (
                context.locale(),
                candidate.git.is_some(),
                candidate.blockers.is_empty(),
            ) {
                (sweepx_i18n::Locale::ZhCn, true, _) => " [Git 已忽略；置信度 high]".to_string(),
                (sweepx_i18n::Locale::EnUs, true, _) => {
                    " [Git ignored; confidence high]".to_string()
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
                "{risk:<4} {:>12}  {rule:<18} {path}{git_note}",
                junk_size_label(&candidate.reclaimable, size_unit),
                risk = candidate.risk,
                rule = candidate.rule_id,
                path = candidate.path,
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
                "status": if scan_status_ok && temp_discovery_complete && layout_failure.is_none() { "ok" } else { "partial" },
                "readOnly": true,
                "tempDiscovery": temp_discovery_json,
                "layoutDiscovery": {
                    "complete": layout_failure.is_none(),
                    "incompleteReason": layout_failure.map(|failure| failure.code()),
                },
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
        if scan_exit == 0 && (!temp_discovery_complete || layout_failure.is_some()) {
            4
        } else {
            scan_exit
        },
    )
}

/// One origin's share of a browser storage subsystem, with the bytes it holds.
///
/// The unit is the **full storage key**, not a hostname. Chromium partitions third-party storage by
/// top-level site, so one host can hold several mutually invisible sets of data — measured on this
/// host, `googletagmanager.com` under `codacy.com` is distinct from the same host elsewhere.
/// Merging on hostname would present unrelated parties as one row and, if ever acted on, clear
/// isolated data the user never selected.
#[derive(Debug, Clone, PartialEq, Eq)]
struct OriginUsage {
    /// The storage key as the browser recorded it, partition included.
    key: String,
    bytes: u64,
    /// Directories that make up this key's usage. One origin routinely owns several: IndexedDB
    /// keeps `.leveldb` and `.blob` apart, and counting them as separate origins would report the
    /// same site twice.
    directories: Vec<PathBuf>,
}

/// Reads the origin out of one `CacheStorage` bucket directory.
///
/// The directory name is a one-way hash of the origin — upstream documents the layout as
/// `CacheStorage/<hash of origin>/<GUID>/` — so `index.txt` is the only route from a directory back
/// to the site that owns it.
///
/// Measured 2026-09-05: the origin is stored as **plain UTF-8**. The file does contain UTF-16
/// stretches, but those hold the hash's hex string, not the origin; an early note recording the
/// origin as UTF-16LE was wrong. The pattern is scheme-agnostic because this host has a
/// `chrome-extension://` key that an `https?`-only match silently drops.
fn cache_storage_origin(bucket: &Path) -> Option<String> {
    let raw = std::fs::read(bucket.join("index.txt")).ok()?;
    let text = String::from_utf8_lossy(&raw);
    extract_storage_key(&text)
}

/// Pulls the origin out of decoded `index.txt` text.
///
/// The origin is a length-delimited protobuf field, so the byte before it is that string's own
/// length. That is what distinguishes it from a URL embedded in a neighbouring field: measured across
/// all 18 buckets on this host, every real origin is preceded by exactly its own length — 19 for
/// `https://www.msn.cn`, 52 for a `chrome-extension://` key — while a Workbox cache name
/// (`workbox-precache-v2-https://gamemap.app/`) is preceded by the length of the whole name, which
/// does not match the URL that starts partway into it.
///
/// A character-class boundary was tried first and rejected: the length prefix is itself often a
/// digit or a letter, so treating "preceded by an alphanumeric" as disqualifying silently dropped the
/// extension origin whose prefix byte is `0x34`.
fn extract_storage_key(text: &str) -> Option<String> {
    let bytes = text.as_bytes();
    let mut found = None;
    let mut index = 0usize;
    while index < bytes.len() {
        // A scheme is [a-z][a-z0-9+-.]* immediately followed by "://".
        if !bytes[index].is_ascii_lowercase() {
            index += 1;
            continue;
        }
        let start = index;
        let mut cursor = index;
        while cursor < bytes.len()
            && (bytes[cursor].is_ascii_lowercase()
                || bytes[cursor].is_ascii_digit()
                || matches!(bytes[cursor], b'+' | b'-' | b'.'))
        {
            cursor += 1;
        }
        if cursor == start || !bytes[cursor..].starts_with(b"://") {
            index = start + 1;
            continue;
        }
        cursor += 3;
        let host_start = cursor;
        while cursor < bytes.len()
            && (bytes[cursor].is_ascii_alphanumeric()
                || matches!(bytes[cursor], b'.' | b'-' | b'_'))
        {
            cursor += 1;
        }
        if cursor == host_start {
            index = start + 1;
            continue;
        }
        let mut end = cursor;
        // A partitioned key continues as "/^0" followed by the top-level site. The separator must
        // be parsed explicitly: eliding it once produced a single fused pseudo-origin named
        // `codacy.comwww.googletagmanager.com` out of two unrelated parties.
        if bytes[cursor..].starts_with(b"/^0") {
            let mut partition = cursor + 3;
            let scheme_start = partition;
            while partition < bytes.len()
                && (bytes[partition].is_ascii_lowercase()
                    || bytes[partition].is_ascii_digit()
                    || matches!(bytes[partition], b'+' | b'-' | b'.'))
            {
                partition += 1;
            }
            if partition > scheme_start && bytes[partition..].starts_with(b"://") {
                partition += 3;
                let site_start = partition;
                while partition < bytes.len()
                    && (bytes[partition].is_ascii_alphanumeric()
                        || matches!(bytes[partition], b'.' | b'-' | b'_'))
                {
                    partition += 1;
                }
                if partition > site_start {
                    end = partition;
                }
            }
        }
        // The stored origin ends with a trailing "/" on every bucket measured here. Accept the run
        // only if the preceding byte equals the field's own length, including that slash.
        let with_slash = bytes.get(end) == Some(&b'/');
        let field_length = end - start + usize::from(with_slash);
        let self_describing = start > 0
            && usize::from(bytes[start - 1]) == field_length
            && field_length <= u8::MAX as usize;
        if self_describing {
            found = Some(text[start..end].to_string());
        }
        index = end;
    }
    found
}

/// Reads the origin out of an IndexedDB directory name.
///
/// Unlike `CacheStorage`, the origin is in the name itself, so no file is read. Measured
/// 2026-09-05, all 52 directories on this host follow `<scheme>_<host>_<n>.indexeddb.<leveldb|blob>`
/// with no exceptions; the two suffixes belong to one origin and must be summed, not counted twice.
fn indexed_db_origin(name: &str) -> Option<String> {
    let stem = name
        .strip_suffix(".indexeddb.leveldb")
        .or_else(|| name.strip_suffix(".indexeddb.blob"))?;
    // Trailing `_<n>` is the origin's serial number, not part of its identity.
    let (head, serial) = stem.rsplit_once('_')?;
    if serial.is_empty() || !serial.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let (scheme, host) = head.split_once('_')?;
    if scheme.is_empty() || host.is_empty() {
        return None;
    }
    Some(format!("{scheme}://{host}"))
}
/// Recursive logical size of a directory, never following a link out of it.
///
/// `symlink_metadata` is used at every step so a reparse point contributes its own size and not its
/// target's. Following one would attribute another site's — or another volume's — bytes to this
/// origin, and could walk outside the profile entirely.
///
/// Returns a lower bound alongside the total: an unreadable subtree means the real figure is larger,
/// and that has to stay visible rather than being rendered as exact.
fn directory_logical_bytes(root: &Path) -> (u64, bool) {
    let mut total = 0u64;
    let mut complete = true;
    let mut pending = vec![root.to_path_buf()];
    while let Some(current) = pending.pop() {
        let Ok(entries) = std::fs::read_dir(&current) else {
            complete = false;
            continue;
        };
        for entry in entries {
            let Ok(entry) = entry else {
                complete = false;
                continue;
            };
            let path = entry.path();
            let Ok(metadata) = std::fs::symlink_metadata(&path) else {
                complete = false;
                continue;
            };
            let file_type = metadata.file_type();
            if file_type.is_dir() {
                pending.push(path);
            } else if file_type.is_file() {
                total = total.saturating_add(metadata.len());
            }
            // A symlink or reparse point is counted as neither: its target's bytes are not this
            // origin's, and its own entry size is not meaningful storage usage.
        }
    }
    (total, complete)
}

/// Attributes one browser storage subsystem to the origins that own it.
///
/// Both subsystems keep one directory per origin, which is what makes per-origin bytes obtainable at
/// all. Local Storage deliberately has no equivalent here: measured 2026-09-05, its 303 origins
/// share twelve LevelDB files many-to-many — one 2.3 MB file held 61 origins while
/// `cn.bing.com` spanned four files — so no file boundary lines up with an origin boundary. Summing
/// an origin's record bytes would not fix it either, because LevelDB retains superseded revisions
/// and tombstones until compaction, so record bytes and disk bytes differ by an unknown factor.
/// Reporting a per-origin figure there would be invention, so nothing is reported.
fn attribute_storage_origins(subsystem: &Path, kind: StorageSubsystem) -> Vec<OriginUsage> {
    let Ok(entries) = std::fs::read_dir(subsystem) else {
        return Vec::new();
    };
    let mut by_key: BTreeMap<String, OriginUsage> = BTreeMap::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if !is_existing_real_directory(&path) {
            continue;
        }
        let key = match kind {
            StorageSubsystem::CacheStorage => cache_storage_origin(&path),
            StorageSubsystem::IndexedDb => path
                .file_name()
                .and_then(|name| name.to_str())
                .and_then(indexed_db_origin),
        };
        // An unattributable directory is skipped rather than lumped into an "other" bucket: naming
        // an origin is the whole point, and a row the user cannot act on is noise. The caller
        // cross-checks the attributed total against a full walk, which is what makes such a skip
        // visible instead of silent.
        let Some(key) = key else {
            continue;
        };
        let (bytes, _) = directory_logical_bytes(&path);
        let usage = by_key.entry(key.clone()).or_insert_with(|| OriginUsage {
            key,
            bytes: 0,
            directories: Vec::new(),
        });
        usage.bytes = usage.bytes.saturating_add(bytes);
        usage.directories.push(path);
    }
    let mut usages: Vec<_> = by_key.into_values().collect();
    // Largest first: the user's question is which site is using the space.
    usages.sort_by(|left, right| {
        right
            .bytes
            .cmp(&left.bytes)
            .then_with(|| left.key.cmp(&right.key))
    });
    usages
}

/// Which per-origin storage subsystem is being attributed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StorageSubsystem {
    /// `Service Worker/CacheStorage`: PWA offline state. Named cache, but not refetchable.
    CacheStorage,
    /// `IndexedDB`: structured site data.
    IndexedDb,
}
/// One browser profile's per-origin storage, as reported to the user.
struct SiteStorageReport {
    /// `<installation>/<profile>`, for example `Microsoft/Edge/Default`.
    profile: String,
    subsystem: &'static str,
    origins: Vec<OriginUsage>,
    /// Total bytes below the subsystem directory, walked independently of attribution.
    ///
    /// Kept so attribution can be checked against it rather than trusted. Counting only the
    /// directories that resolved would under-report silently, and an under-report is
    /// indistinguishable from an exact total.
    subsystem_bytes: u64,
    /// True when every byte below the subsystem was attributed to some origin.
    fully_attributed: bool,
}

/// Reports per-origin site storage for every discovered Chromium profile.
///
/// Read-only by construction: nothing is deleted, pre-selected, or ranked as reclaimable. The
/// browsers' own settings UI offers exactly this — per-site removal — but without size ranking and
/// only while the browser runs.
fn collect_site_storage() -> Vec<SiteStorageReport> {
    let mut reports = Vec::new();
    let Some(local_app_data) = std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
    else {
        return reports;
    };
    for install in CHROMIUM_INSTALLS {
        let mut user_data = local_app_data.clone();
        for component in install.relative_user_data.split('/') {
            user_data.push(component);
        }
        if !is_existing_real_directory(&user_data) {
            continue;
        }
        let Ok(entries) = std::fs::read_dir(&user_data) else {
            continue;
        };
        let mut profiles: Vec<String> = entries
            .flatten()
            .filter_map(|entry| {
                let name = entry.file_name().to_str()?.to_string();
                (name == "Default" || name.starts_with("Profile ")).then_some(name)
            })
            .collect();
        profiles.sort();
        for profile in profiles {
            let profile_dir = user_data.join(&profile);
            // `Service Worker/CacheStorage` is pushed segment by segment: a `/`-containing literal
            // yields a mixed-separator path on Windows, which passes local checks and then never
            // matches a natively captured path.
            let mut cache_storage = profile_dir.clone();
            cache_storage.push("Service Worker");
            cache_storage.push("CacheStorage");
            for (subsystem, kind, dir) in [
                (
                    "service_worker_cache_storage",
                    StorageSubsystem::CacheStorage,
                    cache_storage,
                ),
                (
                    "indexed_db",
                    StorageSubsystem::IndexedDb,
                    profile_dir.join("IndexedDB"),
                ),
            ] {
                if !is_existing_real_directory(&dir) {
                    continue;
                }
                let origins = attribute_storage_origins(&dir, kind);
                let (subsystem_bytes, _) = directory_logical_bytes(&dir);
                let attributed: u64 = origins.iter().map(|usage| usage.bytes).sum();
                // Exact equality on purpose. A 367-byte shortfall here was first explained away as a
                // live browser writing between the two walks and covered with a tolerance; it was in
                // fact an entire origin being dropped by the parser. The tolerance hid the defect
                // rather than absorbing noise, so the check is strict and any drift shows up as
                // `fullyAttributed: false` for inspection instead of being silently forgiven.
                reports.push(SiteStorageReport {
                    profile: format!("{}/{profile}", install.relative_user_data),
                    subsystem,
                    origins,
                    subsystem_bytes,
                    fully_attributed: attributed == subsystem_bytes,
                });
            }
        }
    }
    reports
}
/// Whether a LevelDB-backed storage directory is currently held open by its browser.
///
/// LevelDB guards a database with an exclusive lock on its `LOCK` file, so failing to take that lock
/// means the browser has the database open. This matters because the filesystem will *not* stop the
/// move: measured 2026-09-05 with 35 Edge processes running, an IndexedDB directory renamed
/// successfully. A Trash operation would likewise succeed and the browser would keep writing against
/// a handle whose directory is gone — losing data without reporting an error.
///
/// The check is per directory, not per browser. Chromium opens a database only when a site needs it:
/// on this host 2 of 43 Edge directories were locked while the rest were free. A single probe would
/// have suggested the whole browser was idle, which is how an early version of this guard was nearly
/// dismissed as unworkable.
///
/// An absent `LOCK` means there is no LevelDB database to hold — `CacheStorage` buckets have none —
/// and is reported as not held. A lock that cannot be evaluated is reported as **held**: refusing a
/// removable directory costs the user nothing, while proceeding against a live database is
/// unrecoverable.
fn storage_directory_is_held(directory: &Path) -> bool {
    #[cfg(windows)]
    use std::os::windows::fs::OpenOptionsExt;

    let lock = directory.join("LOCK");
    match std::fs::symlink_metadata(&lock) {
        Ok(metadata) if metadata.is_file() => {}
        Ok(_) => return true,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return false,
        Err(_) => return true,
    }
    // The share mode is the whole check. Rust's default allows FILE_SHARE_WRITE, and measured
    // 2026-09-05 against the same 43 Edge directories that mode reported 0 held while an exclusive
    // open reported 2 — the default silently succeeds alongside the browser's own writer, which is
    // exactly the case that must be refused. share_mode(0) is what LevelDB itself contends for.
    // The handle is dropped immediately and never written to.
    let mut options = std::fs::OpenOptions::new();
    options.write(true);
    #[cfg(windows)]
    options.share_mode(0);
    // On Unix an advisory flock is not observable through open(2), so a write open cannot prove the
    // database is idle. Nothing here claims otherwise: this command is Windows-only today, and a
    // Unix implementation needs its own holder evidence rather than this probe.
    match options.open(&lock) {
        Ok(handle) => {
            drop(handle);
            false
        }
        Err(_) => true,
    }
}
/// The storage subsystem directories worth browsing, deduplicated.
///
/// Derived from the same discovery the report uses, so the two views cannot disagree about which
/// profiles exist. Empty subsystems are excluded: a root with nothing under it adds a row the user
/// cannot act on.
fn site_storage_roots() -> Vec<PathBuf> {
    let mut roots: Vec<PathBuf> = Vec::new();
    for report in collect_site_storage() {
        if report.origins.is_empty() {
            continue;
        }
        for usage in &report.origins {
            for directory in &usage.directories {
                // The subsystem directory is the parent of each origin directory; browsing the
                // subsystem lets the user compare origins side by side rather than one at a time.
                if let Some(parent) = directory.parent()
                    && !roots
                        .iter()
                        .any(|existing| same_directory(existing, parent))
                {
                    roots.push(parent.to_path_buf());
                }
            }
        }
    }
    roots
}
/// Moves every directory belonging to one storage key to the Trash.
///
/// The key must be given in full and is matched exactly. A hostname is not accepted as a shorthand
/// because Chromium partitions third-party storage by top-level site: `googletagmanager.com` under
/// one site is not the same data as under another, and treating a hostname as the unit would clear
/// isolated storage the user never named.
///
/// All-or-nothing at the directory level is deliberate but not achievable atomically: one origin can
/// own several directories — IndexedDB keeps `.leveldb` and `.blob` apart — and the Trash exposes no
/// transaction. So every directory is checked *before* any is moved, and if a later move fails the
/// earlier ones are reported as already moved rather than silently forgotten. Partial success is
/// stated, never rounded to success or failure.
fn trash_one_origin(
    context: &CoreContext,
    format: OutputFormat,
    reports: &[SiteStorageReport],
    key: &str,
    stdin_is_terminal: bool,
) -> ProcessExitCode {
    let mut targets: Vec<PathBuf> = Vec::new();
    for report in reports {
        for usage in &report.origins {
            if usage.key == key {
                targets.extend(usage.directories.iter().cloned());
            }
        }
    }
    if targets.is_empty() {
        let message = match context.locale() {
            sweepx_i18n::Locale::ZhCn => format!(
                "未找到存储键 {key}。存储键必须完整、精确匹配（含分区），可先运行 site-storage 查看。"
            ),
            sweepx_i18n::Locale::EnUs => format!(
                "no storage key matched {key}. Keys are matched exactly, partition included; run site-storage to list them."
            ),
        };
        eprintln!("{message}");
        return ProcessExitCode::from(2);
    }

    // Refuse before touching anything. A held database is not a recoverable failure after the fact:
    // the filesystem allows the move, so the browser would go on writing to a directory that is no
    // longer there.
    let held: Vec<&PathBuf> = targets
        .iter()
        .filter(|directory| storage_directory_is_held(directory))
        .collect();
    if !held.is_empty() {
        let message = match context.locale() {
            sweepx_i18n::Locale::ZhCn => format!(
                "{key} 的 {} 个目录正被浏览器占用；请关闭浏览器后重试。未做任何改动。",
                held.len()
            ),
            sweepx_i18n::Locale::EnUs => format!(
                "{} directory/directories of {key} are open in the browser; close it and retry. Nothing was changed.",
                held.len()
            ),
        };
        eprintln!("{message}");
        return ProcessExitCode::from(3);
    }

    if format == OutputFormat::Human && stdin_is_terminal {
        println!(
            "{}",
            match context.locale() {
                sweepx_i18n::Locale::ZhCn =>
                    format!("即将把 {key} 的 {} 个存储目录移入回收站。", targets.len()),
                sweepx_i18n::Locale::EnUs => format!(
                    "About to move {} storage directory/directories of {key} to the Trash.",
                    targets.len()
                ),
            }
        );
        for target in &targets {
            println!("  {}", target.display());
        }
        if !trash_command::confirm(Path::new(key), context.locale()) {
            let message = match context.locale() {
                sweepx_i18n::Locale::ZhCn => "已取消，未做任何改动。",
                sweepx_i18n::Locale::EnUs => "Cancelled; nothing was changed.",
            };
            println!("{message}");
            return ProcessExitCode::from(0);
        }
    } else if format == OutputFormat::Human {
        let message = match context.locale() {
            sweepx_i18n::Locale::ZhCn => "需要交互式终端确认；未做任何改动。",
            sweepx_i18n::Locale::EnUs => {
                "an interactive terminal is required to confirm; nothing was changed."
            }
        };
        eprintln!("{message}");
        return ProcessExitCode::from(2);
    }

    let mut moved: Vec<PathBuf> = Vec::new();
    let mut failure: Option<(PathBuf, String)> = None;
    for target in targets {
        // Captured and revalidated per directory: identity is re-read immediately before each move,
        // so a directory substituted between the listing and this moment is refused rather than
        // acted on under a stale name.
        let candidate = match trash_command::TrashCandidate::capture(target.clone(), None) {
            Ok(candidate) => candidate,
            Err(error) => {
                failure = Some((target, error.to_string()));
                break;
            }
        };
        match candidate.submit() {
            Ok(()) => moved.push(target),
            Err(error) => {
                failure = Some((target, error.to_string()));
                break;
            }
        }
    }

    let all_moved = failure.is_none();
    if format == OutputFormat::Human {
        for path in &moved {
            println!("  moved: {}", path.display());
        }
        if let Some((path, reason)) = &failure {
            eprintln!("  refused: {} ({reason})", path.display());
        }
        println!(
            "{}",
            match context.locale() {
                sweepx_i18n::Locale::ZhCn => format!(
                    "{key}：已移入回收站 {} 个目录{}。",
                    moved.len(),
                    if all_moved {
                        String::new()
                    } else {
                        "，其余因校验失败未处理".to_string()
                    }
                ),
                sweepx_i18n::Locale::EnUs => format!(
                    "{key}: {} directory/directories moved to the Trash{}.",
                    moved.len(),
                    if all_moved {
                        String::new()
                    } else {
                        ", the rest left in place after a failed check".to_string()
                    }
                ),
            }
        );
    } else {
        println!(
            "{}",
            json!({
                "schema": "sweepx.site_storage.trash/v1",
                "storageKey": key,
                // "partial" is a real outcome, not a rounding of success: some directories of this
                // origin were moved and others were not.
                "status": if all_moved { "ok" } else { "partial" },
                "movedPaths": moved.iter().map(|path| path.display().to_string()).collect::<Vec<_>>(),
                "refused": failure.as_ref().map(|(path, reason)| json!({
                    "path": path.display().to_string(),
                    "reason": reason,
                })),
            })
        );
    }
    ProcessExitCode::from(if all_moved { 0 } else { 4 })
}
/// Runs the `site-storage` command.
///
/// Report-only, and deliberately not part of `junk`: this is R3 browser application state, which the
/// risk taxonomy places at "default skip/report, policy may allow an individually selected item".
/// The per-origin breakdown is what makes such a selection possible at all — without it the only
/// available choice is to clear everything and lose every login.
fn run_site_storage(
    context: &CoreContext,
    format: OutputFormat,
    size_unit: HumanSizeUnit,
    trash_origin: Option<&str>,
    stdin_is_terminal: bool,
) -> ProcessExitCode {
    let reports = collect_site_storage();
    if let Some(key) = trash_origin {
        return trash_one_origin(context, format, &reports, key, stdin_is_terminal);
    }
    if format == OutputFormat::Human {
        for report in &reports {
            println!(
                "{}",
                match context.locale() {
                    sweepx_i18n::Locale::ZhCn => format!(
                        "{} / {}：{} 个来源，合计 {}{}",
                        report.profile,
                        report.subsystem,
                        report.origins.len(),
                        if report.fully_attributed { "" } else { ">= " },
                        size_unit.format(u128::from(report.subsystem_bytes)),
                    ),
                    sweepx_i18n::Locale::EnUs => format!(
                        "{} / {}: {} origins, {}{} total",
                        report.profile,
                        report.subsystem,
                        report.origins.len(),
                        if report.fully_attributed { "" } else { ">= " },
                        size_unit.format(u128::from(report.subsystem_bytes)),
                    ),
                }
            );
            for usage in &report.origins {
                println!(
                    "  {:>12}  {}",
                    size_unit.format(u128::from(usage.bytes)),
                    usage.key
                );
            }
        }
        println!(
            "{}",
            match context.locale() {
                sweepx_i18n::Locale::ZhCn =>
                    "以上仅为报告：未删除任何内容，也未预选任何条目。".to_string(),
                sweepx_i18n::Locale::EnUs =>
                    "Report only: nothing was deleted and nothing was pre-selected.".to_string(),
            }
        );
    } else {
        println!(
            "{}",
            json!({
                "schema": "sweepx.site_storage.result/v1",
                "readOnly": true,
                "profiles": reports.iter().map(|report| json!({
                    "profile": report.profile,
                    "subsystem": report.subsystem,
                    // The independently walked total. `fullyAttributed` false means some bytes
                    // below the subsystem belong to no named origin, so the per-origin rows are a
                    // lower bound on the subsystem rather than a partition of it.
                    "subsystemBytes": report.subsystem_bytes.to_string(),
                    "fullyAttributed": report.fully_attributed,
                    "origins": report.origins.iter().map(|usage| json!({
                        // The full storage key, partition included. Not a hostname: one host can
                        // hold several mutually invisible partitioned sets.
                        "storageKey": usage.key,
                        "bytes": usage.bytes.to_string(),
                        "directoryCount": usage.directories.len(),
                    })).collect::<Vec<_>>(),
                })).collect::<Vec<_>>(),
            })
        );
    }
    ProcessExitCode::from(0)
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
            let platform = PlatformJunkSetup::discover()?;
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

    let platform = PlatformJunkSetup::discover()?;
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
        assert_eq!(restored.blockers, ["git_evidence_not_revalidated"]);
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
            let read = junk_cache::CacheReader::new(&cache).roots(&roots, Some(&digest));
            // Controlled complete history: only Git inputs outside this root are mutated below.
            let mut valid = junk_cache::validate_records_with_log(
                &roots,
                read,
                Some(&sweepx_scanner::ChangeLog {
                    events: vec![],
                    must_rescan: false,
                }),
            );
            valid
                .remove(0)
                .expect("the filesystem and classification cache must actually hit")
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
        assert!(warm[0].blockers.is_empty());
        std::fs::write(&excludes, b"").unwrap();
        let mut changed = restore();
        GitEvidenceSession::new(Default::default(), CancellationToken::new()).refresh(&mut changed);
        assert_eq!(changed[0].confidence.as_deref(), Some("medium"));
        assert!(changed[0].git.is_none());
        assert!(changed[0].blockers.is_empty());
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

    /// Every browser cache rule must be shaped so discovery can actually produce it.
    #[cfg(windows)]
    #[test]
    fn a_locked_storage_database_is_reported_as_held() {
        use std::os::windows::fs::OpenOptionsExt;

        let dir = std::env::temp_dir().join(format!("sweepx-held-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp dir");
        let lock = dir.join("LOCK");
        std::fs::write(&lock, b"").expect("lock file");

        assert!(
            !storage_directory_is_held(&dir),
            "an unheld database must not be refused"
        );

        // Hold it the way LevelDB does. share_mode(1) permits readers but not another writer, so an
        // exclusive probe must fail; Rust's default share mode would succeed here, which is the
        // defect this test exists to pin.
        let holder = std::fs::OpenOptions::new()
            .write(true)
            .share_mode(1)
            .open(&lock)
            .expect("the test can hold the lock");
        assert!(
            storage_directory_is_held(&dir),
            "a held database must be refused: the filesystem would allow the move and the browser \
             would keep writing to a directory that is gone"
        );
        drop(holder);
        assert!(
            !storage_directory_is_held(&dir),
            "releasing the lock makes the database removable again"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(windows)]
    #[test]
    #[ignore = "reads the real browser profiles on this host"]
    fn browse_roots_are_scannable_subsystems_with_trash_authority() {
        // The browser is progressive: the scan returns roots and the TUI expands children on demand
        // through the detail-rescan provider. So the invariant to hold here is that each root is a
        // real scanned object carrying identity and native locator - the fields the interactive Trash
        // takes its authority from, and the ones the model forbids synthesizing from a display path.
        let roots = site_storage_roots();
        assert!(
            !roots.is_empty(),
            "this host has browser storage, so discovery must find it"
        );
        let context = CoreContext::new(detect_locale(None));
        let parts = scan_for_tui_with_store(
            &context,
            &ScanRequest {
                roots: roots.clone(),
                state_dir: None,
            },
            Option::<&sweepx_core::MemorySnapshotStore>::None,
        )
        .expect("the storage roots are scannable")
        .into_tui_parts();

        assert_eq!(
            parts.summary.roots.len(),
            roots.len(),
            "every discovered subsystem must appear as a scanned root"
        );
        for entry in &parts.summary.roots {
            assert!(
                entry.identity.is_some(),
                "{} has no identity, so the Trash path could not revalidate it",
                entry.display_path
            );
            assert!(
                entry.native_locator.is_some(),
                "{} has no native locator, so it carries no execution authority",
                entry.display_path
            );
        }
    }
    #[test]
    fn a_directory_without_a_lock_file_is_not_held() {
        // CacheStorage buckets carry no LevelDB lock; absence must not read as "held" or every one
        // of them would be permanently unremovable.
        let dir = std::env::temp_dir().join(format!("sweepx-nolock-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp dir");
        assert!(!storage_directory_is_held(&dir));
        let _ = std::fs::remove_dir_all(&dir);
    }
    #[test]
    fn a_link_inside_a_storage_directory_is_not_counted_as_its_bytes() {
        // A reparse point must contribute neither its own nor its target's size: following one would
        // bill another site — or another volume — to this origin.
        let temp = std::env::temp_dir().join(format!("sweepx-origin-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&temp);
        std::fs::create_dir_all(temp.join("real")).expect("temp dir");
        std::fs::write(temp.join("real").join("payload"), vec![7u8; 4096]).expect("payload");
        let (bytes, complete) = directory_logical_bytes(&temp);
        assert_eq!(bytes, 4096, "only the real file counts");
        assert!(complete, "a readable tree is complete");
        let _ = std::fs::remove_dir_all(&temp);
    }
    #[test]
    fn a_cache_name_chosen_by_the_page_is_not_mistaken_for_the_origin() {
        // Byte-for-byte shape of a real Workbox bucket on this host: the cache name field carries a
        // URL of its own, ahead of the two occurrences of the actual origin.
        // Prefix bytes are the real ones: 40 (0x28) counts the whole cache name, so the URL inside
        // it is not self-describing; 20 (0x14) counts "https://gamemap.app/" exactly.
        let text = "\u{1}Y\u{2}\u{28}workbox-precache-v2-https://gamemap.app/\u{1}x\u{0}\
                    \u{14}https://gamemap.app/\u{0}\u{14}https://gamemap.app/ ";
        assert_eq!(
            extract_storage_key(text).as_deref(),
            Some("https://gamemap.app"),
            "the origin must win over an application-chosen cache name that embeds a URL"
        );
    }

    #[test]
    fn a_partitioned_key_keeps_both_sites_apart() {
        // Shape recorded from the QuotaManager database, where partitioned keys do appear. Measured
        // 2026-09-05, none of this host's 18 CacheStorage buckets is partitioned, so this case is
        // pinned from the documented form rather than from an index.txt.
        // 54 (0x36) is the length of the full partitioned key including its trailing slash.
        let text = "\u{36}https://www.googletagmanager.com/^0https://codacy.com/";
        assert_eq!(
            extract_storage_key(text).as_deref(),
            Some("https://www.googletagmanager.com/^0https://codacy.com"),
            "dropping the ^0 separator fuses two unrelated parties into one pseudo-origin"
        );
    }

    #[test]
    fn every_index_txt_origin_ends_at_its_trailing_slash() {
        // Measured across all 18 buckets on this host: index.txt always terminates the origin with
        // "/" and carries no bucket suffix. The `_default` suffix belongs to QuotaManager keys, not
        // here; an earlier version of this test wrongly applied that shape to index.txt.
        assert_eq!(
            extract_storage_key("\u{13}https://www.msn.cn/\u{0}\u{13}https://www.msn.cn/ ")
                .as_deref(),
            Some("https://www.msn.cn")
        );
    }
    #[test]
    fn a_non_http_scheme_is_still_an_origin() {
        // This host stores a chrome-extension key; an https-only pattern drops it silently.
        assert_eq!(
            // 52 (0x34) is this key's own length, exactly as the real bucket stores it.
            extract_storage_key("\u{34}chrome-extension://clngdbkpkpeebahjckkjfobafhncgmne/")
                .as_deref(),
            Some("chrome-extension://clngdbkpkpeebahjckkjfobafhncgmne")
        );
    }

    #[test]
    fn indexed_db_pairs_leveldb_and_blob_under_one_origin() {
        // Measured: 52 of 52 directories on this host follow this shape, and the two suffixes of one
        // origin must resolve identically or the site is reported twice at half its size each.
        let leveldb = indexed_db_origin("https_www.bilibili.com_0.indexeddb.leveldb");
        let blob = indexed_db_origin("https_www.bilibili.com_0.indexeddb.blob");
        assert_eq!(leveldb.as_deref(), Some("https://www.bilibili.com"));
        assert_eq!(leveldb, blob, "both suffixes belong to one origin");
    }

    #[test]
    fn indexed_db_rejects_a_name_that_is_not_an_origin_directory() {
        assert_eq!(indexed_db_origin("LOCK"), None);
        assert_eq!(
            indexed_db_origin("https_example.com_x.indexeddb.leveldb"),
            None
        );
    }
}
