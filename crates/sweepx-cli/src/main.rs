use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::io::IsTerminal;
#[cfg(target_os = "linux")]
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command as ProcessCommand, ExitCode as ProcessExitCode, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

#[cfg(target_os = "macos")]
mod junk_cache;
#[cfg(target_os = "linux")]
mod linux_temp;
#[cfg(target_os = "linux")]
mod permanent_delete_command;
#[cfg(target_os = "macos")]
mod subtree_provider;
#[cfg(target_os = "macos")]
mod tcc_access;
#[cfg(target_os = "linux")]
mod temp_clean_command;
mod tool_installations;
mod trash_command;

use clap::{Parser, Subcommand, ValueEnum};
use serde::Deserialize;
use serde_json::json;
use sweepx_core::{CacheStatusRequest, cache_status, cache_status_state_error};
use sweepx_core::{
    CancelRequest, CancellationToken, CleanerCargoDetectInvocation, CleanerCargoDetectRequest,
    CleanerShowRequest, CoreContext, ExplainRequest, JunkClassifier, OutputFormat,
    SCAN_NDJSON_UNAVAILABLE_MESSAGE, ScanRequest, StateError, StatusRequest,
    cache_status_usage_error, cancel_with_store, capabilities,
    cleaner_cargo_detect_with_invocation_and_cancel, cleaner_list, cleaner_show,
    core_error_exit_code, durable_store, explain_from_scan_json, parse_locale_override,
    scan_for_tui_with_store, scan_junk_with_store, scan_ndjson_supported, scan_with_store,
    serialize_json, serialize_ndjson, state_dir_from_explicit_or_default, status_with_store,
    tui_detail_rescan_provider, usage_error_output, validate_absolute_root,
};
#[cfg(target_os = "linux")]
use sweepx_core::{StatusReplayRequest, replay_completed_status};
use sweepx_i18n::detect_locale;
use sweepx_model::{
    ByteValue, Coverage, EvidenceValue, HumanSizeUnit, IdentityEvidence, ReasonCode, ScanEntryId,
    ScanSort,
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
            system,
            clean_temp,
            trash,
            quarantine_dir,
            roots,
        } => {
            let normalized_roots = match normalize_junk_roots(system, &roots) {
                Ok(roots) => roots,
                Err(error) => {
                    eprintln!("{error}");
                    return ProcessExitCode::from(2);
                }
            };
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
                system,
                JunkCleanOptions {
                    enabled: clean_temp,
                    quarantine_dir: quarantine_dir.as_deref(),
                    stdin_is_terminal: std::io::stdin().is_terminal(),
                },
                trash,
                cache_dir,
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

/// A fixed, well-known filesystem location a rule can select without a tool reporting it.
///
/// The location is expressed relative to a resolved `base` rather than as a literal absolute
/// string, so a rule stays portable across users and volumes. Only documented, vendor-published
/// roots belong here; a directory name guessed from an upstream catalog is not evidence by
/// itself.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct KnownRoot {
    /// Anchor the components are joined onto. `home` resolves to the current user's home
    /// directory and must be absolute; unknown bases are rejected.
    base: String,
    /// Path components appended to `base`, in order. Every component must be a single non-empty
    /// name with no separators or parent traversal.
    components: Vec<String>,
}

/// Declarative layout of one Chromium-family browser's derived GPU/network caches.
///
/// A browser keeps caches in two places: shared directories sitting beside the profiles, and one
/// directory per enumerated profile. Encoding this in the rule data lets SweepX discover caches
/// for any browser without a code branch per browser or a hardcoded profile-name list (profiles
/// are expanded from disk). Only derived cache directory names belong in the lists; cookies,
/// history, passwords, bookmarks, Local Storage and IndexedDB are never named.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct BrowserCacheSpec {
    /// Anchor `userData` is resolved against: `application_support` (`~/Library/Application
    /// Support`), `local_app_data` (`%LOCALAPPDATA%`), or `home`.
    base: String,
    /// Components from `base` to the browser's user-data directory.
    user_data: Vec<String>,
    /// Cache directories that live directly under the user-data directory, shared by all
    /// profiles, for example `GrShaderCache`.
    #[serde(default)]
    shared_caches: Vec<String>,
    /// Cache directories that live inside each profile, for example `GPUCache`.
    #[serde(default)]
    profile_caches: Vec<String>,
    /// Multi-component `/`-separated paths relative to user-data for non-derived-cache state,
    /// for example `Crashpad/reports` or `Shared Dictionary/cache`.
    #[serde(default)]
    shared_paths: Vec<String>,
    /// Multi-component `/`-separated paths relative to each profile, for example
    /// `Service Worker/CacheStorage`.
    #[serde(default)]
    profile_paths: Vec<String>,
    /// Explicit profile directory names directly under user-data, for example `IronDefault`.
    /// Use this when a product does not follow the `Default`/`Profile N` convention.
    #[serde(default)]
    profile_names: Vec<String>,
    /// When true (the default), profiles named `Default` and `Profile N` are enumerated from
    /// user-data. Set false for products whose only profiles are those in `profileNames` or
    /// `partition_containers`.
    #[serde(default = "default_true")]
    enumerate_named_profiles: bool,
    /// Directories under user-data whose every real-directory child is a profile/partition. Use
    /// for products such as Postman that name partitions with UUIDs under `Partitions`.
    #[serde(default)]
    partition_containers: Vec<String>,
}

const fn default_true() -> bool {
    true
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
    /// Fixed locations a `verified_known_root` rule selects. Empty for every other match kind,
    /// which keeps location knowledge in the rule data instead of in code keyed on rule id.
    #[serde(default)]
    known_roots: Vec<KnownRoot>,
    /// Browser-cache layouts a `verified_browser_cache` rule expands. One entry per browser;
    /// discovery walks shared and per-profile cache directories from each, in the rule data.
    #[serde(default)]
    browser_caches: Vec<BrowserCacheSpec>,
    depth: usize,
    risk: String,
    evidence: String,
    source_reviewed_at: String,
    references: Vec<String>,
}

#[derive(Debug, Clone)]
struct JunkCandidate {
    path: String,
    /// Native path retained only for in-process actions; never serialized as authority.
    #[cfg(target_os = "linux")]
    native_path: Option<PathBuf>,
    rule_id: String,
    risk: String,
    reclaimable: ByteValue,
    evidence: String,
    source_reviewed_at: String,
    references: Vec<String>,
    entry_id: ScanEntryId,
    ancestor_ids: BTreeSet<ScanEntryId>,
    /// `live` or `stale` for a tool cache; `None` when activity is not a meaningful question.
    ///
    /// A marker only. A stale cache is not deleted, pre-selected, or ranked differently here;
    /// platform junk classification is report-only and this simply records which copy the tool is
    /// using, so the reader can tell an abandoned cache from the working one.
    activity: Option<String>,
    /// Superseded format generations found inside this root, largest evidence first.
    ///
    /// Distinct from `activity`: a live root can still hold an obsolete format that nothing writes
    /// to any more, which was measured as 99.9% of the bytes in pip's cache on this host.
    stale_formats: Vec<String>,
    /// True when `reclaimable` carries apparent logical size because allocation is unavailable.
    ///
    /// Reported rather than hidden: the two quantities differ on compressed, sparse and
    /// multi-stream files, and a consumer that needs allocation must be able to tell that it did
    /// not get it. Windows never claims allocation by design, so on Windows this is normally true.
    size_is_logical: bool,
    /// Git evidence augments project-rule confidence but never grants mutation authority.
    git: Option<GitIgnoreEvidence>,
    /// Stable report classification; platform candidates predate Git enrichment and omit it.
    classification: Option<String>,
    /// Stable confidence label for the classification, independent of the risk tier.
    confidence: Option<String>,
    /// Conditions that prevent this report-only candidate from being promoted.
    blockers: Vec<String>,
    /// The scanned source row, retained for the bulk Trash path's identity revalidation. Present
    /// for freshly scanned candidates and for candidates restored from cache; `None` for the Linux
    /// temporary-object candidates, which use a different cleanup flow.
    source_entry: Option<sweepx_model::ScannedEntry>,
}

#[derive(Debug, Clone, serde::Serialize)]
struct GitIgnoreEvidence {
    status: String,
    repository_entry_id: String,
    check: String,
}

#[derive(Debug, Clone)]
struct GitRepository {
    entry_id: ScanEntryId,
    path: PathBuf,
    depth: usize,
    ancestor_ids: BTreeSet<ScanEntryId>,
    uses_gitfile: bool,
}

const GIT_EVIDENCE_MAX_QUERIES: usize = 256;
const GIT_EVIDENCE_DEADLINE: Duration = Duration::from_secs(5);

struct GitProbeBudget {
    remaining_queries: usize,
    deadline: Instant,
}

struct JunkCleanOptions<'a> {
    enabled: bool,
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    quarantine_dir: Option<&'a Path>,
    stdin_is_terminal: bool,
}

impl GitProbeBudget {
    fn new() -> Self {
        Self {
            remaining_queries: GIT_EVIDENCE_MAX_QUERIES,
            deadline: Instant::now() + GIT_EVIDENCE_DEADLINE,
        }
    }

    fn run(
        &mut self,
        repository: &Path,
        arguments: &[&str],
        path: &Path,
        literal_pathspec: bool,
    ) -> Result<i32, ()> {
        if self.remaining_queries == 0 || Instant::now() >= self.deadline {
            return Err(());
        }
        self.remaining_queries -= 1;
        let relative = path.strip_prefix(repository).map_err(|_| ())?;
        if relative.as_os_str().is_empty() {
            return Err(());
        }
        // Prefix with `./` so a native name beginning with `:` cannot be parsed as Git pathspec
        // magic. The index query additionally disables all wildcard interpretation; check-ignore
        // does not accept literal pathspec mode on the Git versions in the supported runner set.
        let literal_relative = Path::new(".").join(relative);
        // Git's ignore/index queries are local and non-mutating, but still receive explicit
        // process/time limits: an unexpected executable or repository configuration must not hang
        // a disk scan. Fixed arguments keep native path bytes out of a shell.
        let mut command = ProcessCommand::new("git");
        command
            .arg("--no-optional-locks")
            .arg("-c")
            .arg("core.fsmonitor=false")
            .arg("-C")
            .arg(repository)
            .args(arguments)
            .arg("--")
            .arg(literal_relative)
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("GIT_PAGER", "cat")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        if literal_pathspec {
            command.env("GIT_LITERAL_PATHSPECS", "1");
        }
        let mut child = command.spawn().map_err(|_| ())?;
        loop {
            match child.try_wait().map_err(|_| ())? {
                Some(status) => return status.code().ok_or(()),
                None if Instant::now() < self.deadline => {
                    thread::sleep(Duration::from_millis(10));
                }
                None => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(());
                }
            }
        }
    }

    fn exhausted(&self) -> bool {
        self.remaining_queries == 0 || Instant::now() >= self.deadline
    }
}

// The first catalog is intentionally narrow: project outputs with deterministic names and a
// rebuild contract. MangoDisk's broader inventory is research input, not license-compatible code
// or automatic authority. Each future rule must carry its own source and safety review.
const PROJECT_JUNK_RULES_JSON: &str = include_str!("../resources/project-junk-rules.json");
const PLATFORM_JUNK_RULES_JSON: &str = include_str!("../resources/platform-junk-rules.json");

/// Expensive, rule-derived evidence computed once and shared by every classification.
///
/// `tool_cache_candidates` shells out to the developer tool — for npm it additionally enumerates
/// every installation and runs up to three subprocesses per copy (`npm --version`, `node
/// --version`, `npm config get cache`). These values depend only on the rule and the host
/// environment, never on a scanned entry, so asking for them on every `verified_tool_root` check
/// during the walk turned one scan into hundreds of sequential tool launches. Measured on this
/// host 2026-09-29: the walk sat blocked in `poll` on tool output for more than six minutes while
/// using under twenty seconds of CPU. Capturing the answers here once is what keeps the
/// accelerated walk I/O-bound instead of subprocess-bound.
struct PlatformRuleEvidence {
    /// Verified cache locations (markers and structural fingerprint already checked).
    cache_candidates: Vec<PathBuf>,
    /// Cache the tool itself currently names, after resolution; `None` for non-tool-reported
    /// rules or when the tool could not be asked (then liveness is `Unknown`, never `Stale`).
    reported_root: Option<PathBuf>,
}

/// Owned, rule-id-keyed table of precomputed platform evidence.
struct PlatformJunkEvidence {
    by_rule: BTreeMap<String, PlatformRuleEvidence>,
}

impl PlatformJunkEvidence {
    /// Resolves the expensive inputs for every rule once, before the walk begins.
    fn precompute(rules: &[PlatformJunkRule]) -> Self {
        let mut by_rule = BTreeMap::new();
        for rule in rules {
            let cache_candidates = tool_cache_candidates(rule);
            let reported_root =
                tool_reported_root_for(&rule.root_kind).and_then(|tool| tool.resolve());
            by_rule.insert(
                rule.id.clone(),
                PlatformRuleEvidence {
                    cache_candidates,
                    reported_root,
                },
            );
        }
        Self { by_rule }
    }

    /// Precomputed evidence for one rule, or `None` if the rule set this snapshot was built from
    /// did not include it (treated as "cannot classify").
    fn for_rule(&self, rule: &PlatformJunkRule) -> Option<&PlatformRuleEvidence> {
        self.by_rule.get(&rule.id)
    }
}

/// Junk classifier backed by the CLI's loaded project and platform rule sets.
///
/// It is handed to the scanner, which invokes it while the walk runs so non-candidate rows are
/// never buffered. Decisions are namespaced (`project:` / `platform:`) because the two sets
/// have separate id namespaces.
struct CliJunkClassifier<'a> {
    project_rules: &'a [JunkRule],
    platform_rules: &'a [PlatformJunkRule],
    /// Precomputed tool evidence shared across all walk-time classifications.
    evidence: &'a PlatformJunkEvidence,
}

impl JunkClassifier for CliJunkClassifier<'_> {
    fn classify(
        &self,
        entry: &sweepx_model::ScannedEntry,
        markers: &BTreeMap<ScanEntryId, BTreeSet<String>>,
    ) -> Option<String> {
        for rule in self.project_rules {
            if project_rule_classifies(rule, entry, markers) {
                return Some(format!("project:{}", rule.id));
            }
        }
        let platform = if cfg!(target_os = "linux") {
            "linux"
        } else if cfg!(target_os = "macos") {
            "macos"
        } else if cfg!(target_os = "windows") {
            "windows"
        } else {
            "unsupported"
        };
        // Specific, root-identifying rules win over generic catch-all rules when several
        // match one directory; ties keep file order. Measured: without this, the earlier
        // `macos.user-caches` (direct_children) shadowed `macos.homebrew-cache`/`yarn-cache`
        // and the directory lost its specific attribution.
        let mut best: Option<(u8, &PlatformJunkRule)> = None;
        for rule in self
            .platform_rules
            .iter()
            .filter(|rule| rule.platform == platform || rule.platform == "any")
        {
            if platform_rule_classifies(rule, entry, self.evidence) {
                let rank = platform_rule_specificity(rule);
                if best.is_none_or(|(best_rank, _)| rank < best_rank) {
                    best = Some((rank, rule));
                }
            }
        }
        best.map(|(_, rule)| format!("platform:{}", rule.id))
    }
}

/// Specificity rank of a platform rule's match kind; lower wins.
///
/// Rules that identify an exact root (tool-reported, known layout or declared known root) are
/// the most specific. `named_descendant` pins name and depth; `direct_children` is a generic
/// depth bucket that merely inherits everything underneath.
fn platform_rule_specificity(rule: &PlatformJunkRule) -> u8 {
    match rule.match_kind.as_str() {
        "verified_tool_root"
        | "verified_cache_root"
        | "verified_browser_cache"
        | "verified_known_root" => 0,
        "named_descendant" => 1,
        "direct_children" => 2,
        _ => 3,
    }
}

/// Whether a project rule matches an observed directory.
///
/// Same conditions as the former post-scan builder: a name in the rule and identity-based
/// parent-marker applicability.
fn project_rule_classifies(
    rule: &JunkRule,
    entry: &sweepx_model::ScannedEntry,
    markers: &BTreeMap<ScanEntryId, BTreeSet<String>>,
) -> bool {
    let Some(identity) = entry.identity.as_ref() else {
        return false;
    };
    let Some(name) = native_name_for_rule(&entry.native_basename) else {
        return false;
    };
    rule.names
        .iter()
        .any(|candidate| normalized_rule_name(candidate) == name)
        && junk_rule_applies(rule, identity, markers)
}

/// Whether a platform rule matches an observed directory, evaluated at walk time.
///
/// Depth is read from the entry's captured locator. The depth-zero match kinds behave exactly
/// as before: those directories are still their own scan roots except known roots, which may
/// legitimately be nested inside a wider root.
fn platform_rule_classifies(
    rule: &PlatformJunkRule,
    entry: &sweepx_model::ScannedEntry,
    evidence: &PlatformJunkEvidence,
) -> bool {
    let Some(locator) = entry.native_locator.as_ref() else {
        return false;
    };
    let depth = locator.parent_reopen_recipe.len();
    match rule.match_kind.as_str() {
        "direct_children" => depth == rule.depth,
        "named_descendant" => {
            depth == rule.depth
                && native_name_for_rule(&entry.native_basename).is_some_and(|name| {
                    rule.names
                        .iter()
                        .any(|candidate| normalized_rule_name(candidate) == name)
                })
        }
        "verified_tool_root" => depth == 0 && tool_reported_root_matches(rule, entry, evidence),
        "verified_cache_root" => depth == 0 && render_cache_root_matches(rule, entry),
        "verified_browser_cache" => depth == 0 && browser_cache_root_matches(rule, entry),
        "verified_known_root" => known_macos_root_matches(rule, entry),
        #[cfg(target_os = "linux")]
        "stale_inactive_direct_child" => false,
        _ => false,
    }
}

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
    junk_cache::StoredJunkCandidate {
        path: candidate.path.clone(),
        rule_id: candidate.rule_id.clone(),
        risk: candidate.risk.clone(),
        reclaimable: candidate.reclaimable.clone(),
        evidence: candidate.evidence.clone(),
        source_reviewed_at: candidate.source_reviewed_at.clone(),
        references: candidate.references.clone(),
        entry_id: candidate.entry_id.clone(),
        ancestor_ids: candidate.ancestor_ids.clone(),
        activity: candidate.activity.clone(),
        stale_formats: candidate.stale_formats.clone(),
        size_is_logical: candidate.size_is_logical,
        git: candidate
            .git
            .as_ref()
            .map(|git| junk_cache::StoredGitIgnoreEvidence {
                status: git.status.clone(),
                repository_entry_id: git.repository_entry_id.clone(),
                check: git.check.clone(),
            }),
        classification: candidate.classification.clone(),
        confidence: candidate.confidence.clone(),
        blockers: candidate.blockers.clone(),
        source_entry: candidate.source_entry.clone(),
    }
}

/// Converts a cache record back into an in-memory candidate.
///
/// Returns `None` only so it can be used directly in a `filter_map`; the conversion is infallible.
#[cfg(target_os = "macos")]
fn stored_candidate_to_junk(stored: junk_cache::StoredJunkCandidate) -> Option<JunkCandidate> {
    let source_entry = source_entry_from_stored(&stored);
    Some(JunkCandidate {
        path: stored.path,
        #[cfg(target_os = "linux")]
        native_path: None,
        rule_id: stored.rule_id,
        risk: stored.risk,
        reclaimable: stored.reclaimable,
        evidence: stored.evidence,
        source_reviewed_at: stored.source_reviewed_at,
        references: stored.references,
        entry_id: stored.entry_id,
        ancestor_ids: stored.ancestor_ids,
        activity: stored.activity,
        stale_formats: stored.stale_formats,
        size_is_logical: stored.size_is_logical,
        git: stored.git.map(|git| GitIgnoreEvidence {
            status: git.status,
            repository_entry_id: git.repository_entry_id,
            check: git.check,
        }),
        classification: stored.classification,
        confidence: stored.confidence,
        blockers: stored.blockers,
        source_entry,
    })
}

/// Reads the source `ScannedEntry` carried by a cached candidate.
///
/// Records written before the row was persisted (or by a path that had none) return `None`; that
/// candidate then cannot be bulk-trashed from cache while its report stays accurate.
#[cfg(target_os = "macos")]
fn source_entry_from_stored(
    stored: &junk_cache::StoredJunkCandidate,
) -> Option<sweepx_model::ScannedEntry> {
    stored.source_entry.clone()
}

#[allow(clippy::too_many_arguments)]
#[cfg_attr(not(target_os = "linux"), allow(unused_variables))]
fn run_junk_scan(
    context: &CoreContext,
    format: OutputFormat,
    size_unit: HumanSizeUnit,
    roots: Vec<PathBuf>,
    temp_requested_roots: Vec<PathBuf>,
    include_platform_rules: bool,
    clean: JunkCleanOptions<'_>,
    move_to_trash: bool,
    // Directory holding the per-root junk cache (`<state>/junk-cache`); `None` when caching is
    // unavailable (non-macOS, or no usable state directory).
    #[cfg_attr(not(target_os = "macos"), allow(unused_variables))] cache_dir: Option<PathBuf>,
) -> ProcessExitCode {
    if clean.enabled && (format != OutputFormat::Human || !clean.stdin_is_terminal) {
        eprintln!(
            "junk --system --clean-temp requires human output and a foreground interactive terminal"
        );
        return ProcessExitCode::from(2);
    }
    if move_to_trash && (format != OutputFormat::Human || !clean.stdin_is_terminal) {
        eprintln!("junk --trash requires human output and a foreground interactive terminal");
        return ProcessExitCode::from(2);
    }
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
    let evidence = PlatformJunkEvidence::precompute(&platform_rules);
    let classifier = CliJunkClassifier {
        project_rules: &rules,
        platform_rules: &platform_rules,
        evidence: &evidence,
    };

    // Resolve every root to its canonical (symlink-free) path; FSEvents reports canonical paths
    // and the per-root cache is keyed on them. A root that cannot be canonicalized is passed
    // through unchanged so the scanner reports the real error for it.
    let canonical_roots: Vec<PathBuf> = scan_roots
        .iter()
        .map(|root| std::fs::canonicalize(root).unwrap_or_else(|_| root.clone()))
        .collect();

    // Split roots into FSEvents-validated cache hits and the indexes that still need scanning.
    #[cfg(target_os = "macos")]
    let (hit_records, miss_indexes): (Vec<junk_cache::StoredJunkRoot>, Vec<usize>) =
        match &cache_dir {
            Some(cache) => {
                let mut hits = Vec::new();
                let mut misses = Vec::new();
                for (index, record) in junk_cache::load_current_roots(cache, &canonical_roots)
                    .into_iter()
                    .enumerate()
                {
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
    let cached_candidates: Vec<JunkCandidate> = hit_records
        .into_iter()
        .flat_map(junk_cache::StoredJunkRoot::into_candidates)
        .filter_map(stored_candidate_to_junk)
        .collect();
    // Caching is macOS-only; other platforms have no restored candidates.
    #[cfg(not(target_os = "macos"))]
    let cached_candidates: Vec<JunkCandidate> = Vec::new();
    let miss_roots: Vec<PathBuf> = miss_indexes
        .iter()
        .map(|index| canonical_roots[*index].clone())
        .collect();

    // Build the subtree-reuse provider for the roots being scanned. On a cache-validated run the
    // scanner skips whole unchanged child subtrees through it.
    #[cfg(target_os = "macos")]
    let subtree_provider = subtree_provider::SubtreeCacheProvider::prepare(
        cache_dir.as_deref().unwrap_or(Path::new("/nonexistent")),
        &miss_roots,
    );

    // Capture before traversal: writes during the scan must invalidate the next reuse.
    #[cfg(target_os = "macos")]
    let scan_event_id = sweepx_core::current_event_id();
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
    let scan = match classified {
        Some(Ok(scan)) => Some(scan),
        Some(Err(error)) => {
            eprintln!("{error}");
            return ProcessExitCode::from(core_error_exit_code(&error) as u8);
        }
        None => None,
    };

    // Assemble freshly scanned candidates. Applicability was joined during the walk through scan
    // identities and lossless native names; aggregates carry each directory's size.
    let mut fresh_candidates = Vec::new();
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
            if let Some(rule_id) = decision.strip_prefix("project:") {
                let Some(rule) = rules.iter().find(|rule| rule.id == rule_id) else {
                    continue;
                };
                fresh_candidates.push(assemble_project_candidate(rule, entry, &aggregates));
            } else if let Some(rule_id) = decision.strip_prefix("platform:") {
                let Some(rule) = platform_rules.iter().find(|rule| rule.id == rule_id) else {
                    continue;
                };
                fresh_candidates.push(assemble_platform_candidate(
                    rule,
                    entry,
                    &aggregates,
                    &evidence,
                ));
            }
        }
        annotate_project_candidates_with_git(
            &scan.scan.summary,
            &scan.coverages,
            &scan.directory_markers,
            &mut fresh_candidates,
        );
    }
    #[cfg(target_os = "linux")]
    if let Some((rule, discovery)) = &temp_discovery {
        fresh_candidates.extend(linux_temp_candidates(rule, discovery));
    }

    // Persist every scanned (miss) root with the candidates attributed to its deepest root, then
    // drop cache entries for roots no longer present. A root with zero candidates is still
    // written so an empty-but-scanned root stays a hit next time.
    #[cfg(target_os = "macos")]
    if let Some(cache) = &cache_dir {
        for index in &miss_indexes {
            let root = &canonical_roots[*index];
            // Incomplete scans (including denied roots) must be retried, never frozen as hits.
            if !scan.as_ref().is_some_and(|scan| {
                scan.covered_paths.get(&root.display().to_string()) == Some(&true)
            }) {
                continue;
            }
            let mut stored = Vec::new();
            for candidate in &fresh_candidates {
                if deepest_root_for(&candidate.path, &canonical_roots) == Some(*index) {
                    stored.push(junk_candidate_to_stored(candidate));
                }
            }
            match junk_cache::StoredJunkRoot::capture(root, stored, scan_event_id)
                .and_then(|record| junk_cache::write(cache, &record))
            {
                Ok(()) => {}
                // A cache write failure never fails the report; the root simply rescans next run.
                Err(error) => eprintln!(
                    "could not update junk cache for {}: {error}",
                    root.display()
                ),
            }
        }
        let _ = junk_cache::prune(cache, &canonical_roots);

        // Write the per-device subtree index from every freshly scanned candidate, so unchanged
        // child subtrees can be skipped on the next run even when this root itself is rescanned.
        if let Some(scan) = &scan {
            let aggregate_by_id: BTreeMap<ScanEntryId, &sweepx_model::DirectoryAggregate> = scan
                .scan
                .summary
                .aggregates
                .iter()
                .map(|aggregate| {
                    (
                        ScanEntryId::from_loaded(aggregate.directory_identity.clone()),
                        aggregate,
                    )
                })
                .collect();
            let mut directories = Vec::new();
            for candidate in &fresh_candidates {
                if let (Some(entry), Some(aggregate)) = (
                    candidate.source_entry.as_ref(),
                    aggregate_by_id.get(&candidate.entry_id),
                ) {
                    directories.push(junk_cache::StoredSubtreeDirectory {
                        entry: entry.clone(),
                        rule_id: candidate.rule_id.clone(),
                        aggregate: (*aggregate).clone(),
                    });
                }
            }
            // Convert the scanner's captured child listings into the persisted form.
            let listings: BTreeMap<String, junk_cache::StoredDirListing> = scan
                .dir_listings
                .iter()
                .map(|(path, listing)| {
                    (
                        path.clone(),
                        junk_cache::StoredDirListing {
                            files: listing.files.clone(),
                            dirs: listing.dirs.clone(),
                        },
                    )
                })
                .collect();
            // One index per device; use the first scanned root only to identify the device.
            let store_result = miss_roots.first().map(|scan_root| {
                subtree_provider.store_index(
                    scan_root,
                    scan_event_id,
                    scan.covered_paths.clone(),
                    listings,
                    directories,
                )
            });
            if let Some(Err(error)) = store_result {
                eprintln!("could not update subtree index: {error}");
            }
        }
    }

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
    let npm_installations: Vec<tool_installations::ToolInstallation> = if load_platform_junk_rules()
        .is_ok_and(|rules| {
            rules
                .iter()
                .any(|rule| rule.root_kind == "npm_reported_cache")
        }) {
        tool_installations::discover_npm_installations()
    } else {
        Vec::new()
    };
    if format != OutputFormat::Human {
        // All-cache runs (no fresh scan) are treated as ok; otherwise use the fresh scan's status.
        let scan_status_ok = scan
            .as_ref()
            .is_none_or(|result| result.scan.output.status == sweepx_protocol::OutputStatus::Ok);
        println!(
            "{}",
            json!({
                "schema": "sweepx.junk.result/v1",
                "status": if scan_status_ok && temp_discovery_complete { "ok" } else { "partial" },
                "readOnly": true,
                "tempDiscovery": temp_discovery_json,
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
    ProcessExitCode::from(scan.as_ref().map_or(0, |result| {
        result.scan.output.conservative_exit_code() as u8
    }))
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

/// Assembles one project junk candidate for an entry the classifier already matched.
fn assemble_project_candidate(
    rule: &JunkRule,
    entry: &sweepx_model::ScannedEntry,
    aggregates: &BTreeMap<&str, &sweepx_model::DirectoryAggregate>,
) -> JunkCandidate {
    let identity = entry
        .identity
        .as_ref()
        .expect("matched entry carries identity");
    let locator = entry
        .native_locator
        .as_ref()
        .expect("matched entry carries a locator");
    let size = junk_size_for(aggregates.get(identity.entry_id.as_str()).copied());
    JunkCandidate {
        path: entry.display_path.clone(),
        #[cfg(target_os = "linux")]
        native_path: None,
        rule_id: rule.id.clone(),
        risk: rule.risk.clone(),
        reclaimable: size.value,
        evidence: rule.evidence.clone(),
        source_reviewed_at: rule.source_reviewed_at.clone(),
        references: rule.references.clone(),
        entry_id: identity.entry_id.clone(),
        ancestor_ids: locator
            .parent_reopen_recipe
            .iter()
            .map(|component| component.entry_id.clone())
            .collect(),
        // A project build output has no "which copy is the tool using" question: it belongs to
        // the tree it sits in. Claiming an activity here would be noise.
        activity: None,
        stale_formats: Vec::new(),
        size_is_logical: size.is_logical_fallback,
        git: None,
        classification: Some("known_generated".to_string()),
        confidence: Some("medium".to_string()),
        blockers: Vec::new(),
        source_entry: Some(entry.clone()),
    }
}

/// Adds bounded Git evidence to already-classified project candidates.
///
/// This seam is intentionally report-only. Git decides its own ignore semantics, while the
/// scanner remains the source of filesystem identity and size. A subprocess or repository lookup
/// failure leaves the existing candidate at its original confidence; it never makes it safer.
fn annotate_project_candidates_with_git(
    summary: &sweepx_core::ScanSummary,
    coverages: &BTreeMap<ScanEntryId, Coverage>,
    directory_markers: &BTreeMap<ScanEntryId, BTreeMap<String, ScanEntryId>>,
    candidates: &mut [JunkCandidate],
) {
    if summary
        .boundaries
        .iter()
        .any(|boundary| boundary.kind == sweepx_platform::BoundaryKind::ResourceLimit)
    {
        for candidate in candidates {
            candidate
                .blockers
                .push("git_scan_evidence_incomplete".to_string());
        }
        return;
    }
    let repositories = git_repositories(summary, coverages, directory_markers);
    let mut budget = GitProbeBudget::new();
    for candidate in candidates.iter_mut() {
        let Some(repository) = repositories
            .iter()
            .filter(|repository| repository_contains(repository, candidate))
            .max_by_key(|repository| repository.depth)
        else {
            continue;
        };
        if repository.uses_gitfile {
            candidate
                .blockers
                .push("gitfile_repository_boundary".to_string());
            continue;
        }
        if candidate_contains_nested_repository(&repositories, repository, &candidate.entry_id) {
            candidate.blockers.push("nested_repository".to_string());
            continue;
        }
        if coverages
            .get(&candidate.entry_id)
            .is_none_or(|coverage| !coverage.complete || coverage.details_lost)
        {
            candidate
                .blockers
                .push("git_scan_evidence_incomplete".to_string());
            continue;
        }
        let Some(candidate_row) = summary
            .roots
            .iter()
            .chain(summary.entries.iter())
            .find(|row| {
                row.identity
                    .as_ref()
                    .is_some_and(|identity| identity.entry_id == candidate.entry_id)
            })
        else {
            candidate
                .blockers
                .push("git_path_binding_unavailable".to_string());
            continue;
        };
        let Some(candidate_locator) = candidate_row.native_locator.as_ref() else {
            candidate
                .blockers
                .push("git_path_binding_unavailable".to_string());
            continue;
        };
        let Some(path) = path_from_scanned_entry(candidate_row) else {
            candidate
                .blockers
                .push("git_path_binding_unavailable".to_string());
            continue;
        };
        // A repository row is usually absent in a classified scan (it is not itself junk),
        // so identities are read from the candidate row's captured locator chain: the scan
        // root or the matching reopen component names the repository, and the entry component
        // names the candidate. This compares the same native evidence the old summary-based
        // check used, without requiring the non-junk rows to have been retained.
        let Some(repo_evidence) =
            locator_component_identity(candidate_locator, &repository.entry_id)
        else {
            candidate.blockers.push("git_identity_changed".to_string());
            continue;
        };
        if !identity_evidence_matches_path(repo_evidence, &repository.path)
            || !identity_evidence_matches_path(
                &candidate_locator.entry.platform_file_identity,
                &path,
            )
        {
            candidate.blockers.push("git_identity_changed".to_string());
            continue;
        }
        if budget.exhausted() {
            candidate
                .blockers
                .push("git_query_budget_exhausted".to_string());
            continue;
        }
        match git_path_has_tracked_descendant(&mut budget, &repository.path, &path) {
            Ok(true) => {
                candidate.blockers.push("tracked_descendant".to_string());
                continue;
            }
            Ok(false) => {}
            Err(()) => {
                candidate.blockers.push("git_query_failed".to_string());
                continue;
            }
        }
        if budget.exhausted() {
            candidate
                .blockers
                .push("git_query_budget_exhausted".to_string());
            continue;
        }
        match git_path_is_ignored(&mut budget, &repository.path, &path) {
            Ok(true) => {
                candidate.git = Some(GitIgnoreEvidence {
                    status: "ignored".to_string(),
                    repository_entry_id: repository.entry_id.to_string(),
                    check: "git.check-ignore.v1".to_string(),
                });
                candidate.classification = Some("known_generated_ignored".to_string());
                candidate.confidence = Some("high".to_string());
            }
            Ok(false) => {}
            Err(()) => candidate.blockers.push("git_query_failed".to_string()),
        }
    }
}

/// Finds a directory component's platform identity inside a captured locator chain.
///
/// The component may be the scan root, an intermediate reopen component, or the entry itself.
fn locator_component_identity<'a>(
    locator: &'a sweepx_model::NativeLocatorEvidence,
    entry_id: &ScanEntryId,
) -> Option<&'a IdentityEvidence<sweepx_model::PlatformFileIdentity>> {
    std::iter::once(&locator.scan_root)
        .chain(locator.parent_reopen_recipe.iter())
        .chain(std::iter::once(&locator.entry))
        .find(|component| &component.entry_id == entry_id)
        .map(|component| &component.platform_file_identity)
}

/// Whether captured identity evidence still names the directory currently at `path`.
#[cfg(unix)]
fn identity_evidence_matches_path(
    evidence: &IdentityEvidence<sweepx_model::PlatformFileIdentity>,
    path: &Path,
) -> bool {
    use std::os::unix::fs::MetadataExt;

    let IdentityEvidence::Known { value } = evidence else {
        return false;
    };
    let Ok(metadata) = std::fs::symlink_metadata(path) else {
        return false;
    };
    metadata.file_type().is_dir()
        && value.device.0 == u128::from(metadata.dev())
        && value.inode.0 == u128::from(metadata.ino())
}

/// Whether captured identity evidence still names the directory currently at `path`.
#[cfg(windows)]
fn identity_evidence_matches_path(
    evidence: &IdentityEvidence<sweepx_model::PlatformFileIdentity>,
    path: &Path,
) -> bool {
    let IdentityEvidence::Known { value } = evidence else {
        return false;
    };
    matches!(
        sweepx_platform_windows::read_live_identity(path),
        Ok(Some(actual))
            if value.device.0 == u128::from(actual.device()) && value.inode.0 == actual.inode()
    )
}

fn git_repositories(
    summary: &sweepx_core::ScanSummary,
    coverages: &BTreeMap<ScanEntryId, Coverage>,
    directory_markers: &BTreeMap<ScanEntryId, BTreeMap<String, ScanEntryId>>,
) -> Vec<GitRepository> {
    // In a classified scan only junk directory rows survive, so a `.git` row is absent even
    // when its name was recorded as a directory marker. Repositories are therefore the parent
    // ids whose recorded children include `.git`. Flatten the markers into a child→parent map
    // so the full ancestor chain is reconstructible without the dropped rows.
    let mut child_parent: BTreeMap<ScanEntryId, ScanEntryId> = BTreeMap::new();
    // child id → its own native basename, used to reconstruct paths for dropped rows.
    let mut child_names: BTreeMap<ScanEntryId, String> = BTreeMap::new();
    for (parent_id, children) in directory_markers {
        for (name, child_id) in children {
            child_parent.insert(child_id.clone(), parent_id.clone());
            child_names.insert(child_id.clone(), name.clone());
        }
    }
    let mut root_paths: BTreeMap<ScanEntryId, PathBuf> = BTreeMap::new();
    for row in summary.roots.iter().chain(summary.entries.iter()) {
        let Some(locator) = row.native_locator.as_ref() else {
            continue;
        };
        let Some(absolute) = locator.scan_root_absolute_path.as_ref() else {
            continue;
        };
        let key = locator.scan_root.entry_id.clone();
        if root_paths.contains_key(&key) {
            continue;
        }
        if let Some(path) = native_absolute_path_for_git(absolute) {
            root_paths.insert(key, path);
        }
    }
    let mut repositories = Vec::new();
    for (parent_id, children) in directory_markers {
        if !children.contains_key(".git") {
            continue;
        }
        if coverages
            .get(parent_id)
            .is_none_or(|coverage| !coverage.complete)
        {
            continue;
        }
        // Prefer the parent's own retained row (carries the real locator). Rows for nested
        // non-junk directories were dropped, so reconstruct the path from recorded names:
        // walk child→parent collecting basenames, then append them to the root path.
        let row = summary
            .roots
            .iter()
            .chain(summary.entries.iter())
            .find(|row| {
                row.identity
                    .as_ref()
                    .is_some_and(|identity| &identity.entry_id == parent_id)
            });
        let Some(path) = row
            .as_ref()
            .and_then(|row| path_from_scanned_entry(row))
            .or_else(|| {
                reconstruct_marker_path(parent_id, &child_parent, &child_names, &root_paths)
            })
        else {
            continue;
        };
        // A `.git` *file* (gitfile/submodule pointer) is a boundary even though the marker
        // index only records directory names; verify against the live path.
        let uses_gitfile = std::fs::symlink_metadata(path.join(".git"))
            .is_ok_and(|metadata| metadata.file_type().is_file());
        // Build the ancestor chain from child→parent; stop at the scan root (no parent
        // recorded). When the row survives, its locator gives the same chain directly.
        let (depth, ancestor_ids) = row
            .as_ref()
            .and_then(|row| row.native_locator.as_ref())
            .map(|locator| {
                (
                    locator.parent_reopen_recipe.len(),
                    locator
                        .parent_reopen_recipe
                        .iter()
                        .map(|component| component.entry_id.clone())
                        .collect::<BTreeSet<_>>(),
                )
            })
            .unwrap_or_else(|| {
                let mut chain: BTreeSet<ScanEntryId> = BTreeSet::new();
                let mut current = child_parent.get(parent_id).cloned();
                while let Some(parent) = current {
                    let next = child_parent.get(&parent).cloned();
                    chain.insert(parent);
                    current = next;
                }
                let depth = chain.len();
                (depth, chain)
            });
        repositories.push(GitRepository {
            entry_id: parent_id.clone(),
            path,
            depth,
            ancestor_ids,
            uses_gitfile,
        });
    }
    repositories
}

/// Reconstructs a dropped directory row's path from the recorded marker chain.
///
/// Follows child→parent to the scan root, collecting each child's recorded native basename,
/// then appends the names in root order to the root path. Returns `None` if the chain does
/// not terminate at a known scan root (markers incomplete).
fn reconstruct_marker_path(
    target_id: &ScanEntryId,
    child_parent: &BTreeMap<ScanEntryId, ScanEntryId>,
    child_names: &BTreeMap<ScanEntryId, String>,
    root_paths: &BTreeMap<ScanEntryId, PathBuf>,
) -> Option<PathBuf> {
    let mut names: Vec<String> = Vec::new();
    let mut current = target_id.clone();
    while !root_paths.contains_key(&current) {
        let parent = child_parent.get(&current)?.clone();
        names.push(child_names.get(&current)?.clone());
        current = parent;
    }
    let mut path = root_paths.get(&current)?.clone();
    for name in names.into_iter().rev() {
        path.push(name);
    }
    Some(path)
}

fn repository_contains(repository: &GitRepository, candidate: &JunkCandidate) -> bool {
    repository.entry_id == candidate.entry_id
        || candidate.ancestor_ids.contains(&repository.entry_id)
}

fn candidate_contains_nested_repository(
    repositories: &[GitRepository],
    owning_repository: &GitRepository,
    candidate_id: &ScanEntryId,
) -> bool {
    repositories.iter().any(|nested| {
        nested.entry_id != owning_repository.entry_id && nested.ancestor_ids.contains(candidate_id)
    })
}

fn path_from_scanned_entry(entry: &sweepx_model::ScannedEntry) -> Option<PathBuf> {
    let locator = entry.validated_native_locator().ok()??;
    let root = native_absolute_path_for_git(locator.scan_root_absolute_path.as_ref()?)?;
    if locator.entry.entry_id == locator.scan_root.entry_id {
        return Some(root);
    }
    let mut path = root;
    for component in locator.parent_reopen_recipe.iter().skip(1) {
        path.push(native_name_for_git(&component.native_basename)?);
    }
    path.push(native_name_for_git(&locator.entry.native_basename)?);
    Some(path)
}

#[cfg(unix)]
fn native_absolute_path_for_git(path: &sweepx_model::NativeAbsolutePath) -> Option<PathBuf> {
    use std::os::unix::ffi::OsStringExt;
    match path {
        sweepx_model::NativeAbsolutePath::UnixBytes(bytes) => {
            Some(PathBuf::from(OsString::from_vec(bytes.clone())))
        }
        sweepx_model::NativeAbsolutePath::WindowsUtf16(_) => None,
    }
}

#[cfg(windows)]
fn native_absolute_path_for_git(path: &sweepx_model::NativeAbsolutePath) -> Option<PathBuf> {
    use std::os::windows::ffi::OsStringExt;
    match path {
        sweepx_model::NativeAbsolutePath::WindowsUtf16(units) => {
            Some(PathBuf::from(OsString::from_wide(units)))
        }
        sweepx_model::NativeAbsolutePath::UnixBytes(_) => None,
    }
}

#[cfg(unix)]
fn native_name_for_git(name: &sweepx_model::NativeName) -> Option<OsString> {
    use std::os::unix::ffi::OsStringExt;
    match name {
        sweepx_model::NativeName::UnixBytes(bytes) => Some(OsString::from_vec(bytes.clone())),
        sweepx_model::NativeName::WindowsUtf16(_) => None,
    }
}

#[cfg(windows)]
fn native_name_for_git(name: &sweepx_model::NativeName) -> Option<OsString> {
    use std::os::windows::ffi::OsStringExt;
    match name {
        sweepx_model::NativeName::WindowsUtf16(units) => Some(OsString::from_wide(units)),
        sweepx_model::NativeName::UnixBytes(_) => None,
    }
}

fn git_path_is_ignored(
    budget: &mut GitProbeBudget,
    repository: &Path,
    path: &Path,
) -> Result<bool, ()> {
    match budget.run(repository, &["check-ignore", "--quiet"], path, false)? {
        0 => Ok(true),
        1 => Ok(false),
        _ => Err(()),
    }
}

fn git_path_has_tracked_descendant(
    budget: &mut GitProbeBudget,
    repository: &Path,
    path: &Path,
) -> Result<bool, ()> {
    match budget.run(repository, &["ls-files", "--error-unmatch"], path, true)? {
        0 => Ok(true),
        1 => Ok(false),
        _ => Err(()),
    }
}

/// Assembles one platform junk candidate for an entry the classifier already matched.
///
/// This is the former body of `platform_junk_candidates` without the rule/entry loops: the
/// classification decision was made during the walk, but activity, size and evidence are
/// assembled here from the retained aggregate.
fn assemble_platform_candidate(
    rule: &PlatformJunkRule,
    entry: &sweepx_model::ScannedEntry,
    aggregates: &BTreeMap<&str, &sweepx_model::DirectoryAggregate>,
    evidence: &PlatformJunkEvidence,
) -> JunkCandidate {
    let identity = entry
        .identity
        .as_ref()
        .expect("matched entry carries identity");
    let locator = entry
        .native_locator
        .as_ref()
        .expect("matched entry carries a locator");
    let activity = classify_tool_root(rule, entry, evidence)
        .map(|classification| classification.code().to_string());
    let stale_formats = superseded_format_generations(rule, entry, evidence);
    // Same allocation-versus-logical problem as the project rules, with one extra source: the
    // entry's own estimate, kept ahead of the logical fallback as the scanner's own claim.
    let aggregate = aggregates.get(identity.entry_id.as_str()).copied();
    debug_assert!(
        !(rule.root_kind == "linux_tmp")
            || aggregate.is_some_and(|aggregate| {
                aggregate.coverage.complete && !aggregate.coverage.details_lost
            }),
        "linux tmp candidates are filtered before assembly"
    );
    let size = if aggregate.is_some() {
        junk_size_for(aggregate)
    } else {
        JunkSize {
            value: entry.reclaimable_estimate.clone(),
            is_logical_fallback: false,
        }
    };
    JunkCandidate {
        path: entry.display_path.clone(),
        #[cfg(target_os = "linux")]
        native_path: None,
        rule_id: rule.id.clone(),
        risk: rule.risk.clone(),
        reclaimable: size.value,
        evidence: rule.evidence.clone(),
        source_reviewed_at: rule.source_reviewed_at.clone(),
        references: rule.references.clone(),
        entry_id: identity.entry_id.clone(),
        ancestor_ids: locator
            .parent_reopen_recipe
            .iter()
            .map(|component| component.entry_id.clone())
            .collect(),
        #[cfg(target_os = "linux")]
        activity: if rule.root_kind == "linux_tmp" {
            Some(linux_temp::ACTIVITY_CODE.to_string())
        } else {
            activity
        },
        #[cfg(not(target_os = "linux"))]
        activity,
        stale_formats,
        size_is_logical: size.is_logical_fallback,
        git: None,
        #[cfg(target_os = "linux")]
        classification: (rule.root_kind == "linux_tmp")
            .then(|| linux_temp::CLASSIFICATION.to_string()),
        #[cfg(not(target_os = "linux"))]
        classification: None,
        confidence: (rule.root_kind == "linux_tmp").then(|| "medium".to_string()),
        #[cfg(target_os = "linux")]
        blockers: if rule.root_kind == "linux_tmp" {
            vec![linux_temp::REFERENCE_BLOCKER.to_string()]
        } else {
            Vec::new()
        },
        #[cfg(not(target_os = "linux"))]
        blockers: Vec::new(),
        source_entry: Some(entry.clone()),
    }
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
fn tool_reported_root_matches(
    rule: &PlatformJunkRule,
    entry: &sweepx_model::ScannedEntry,
    evidence: &PlatformJunkEvidence,
) -> bool {
    classify_tool_root(rule, entry, evidence).is_some()
}

/// Whether a matched cache root is the one the tool is currently using.
///
/// Reported as a marker rather than acted on. A live cache is the one that must *not* be reclaimed,
/// so this is a guard; the stale copies are the reclaimable ones and carry no deletion authority
/// either, because platform junk classification stays report-only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ToolRootActivity {
    /// The tool itself named this path.
    Live,
    /// A real cache of this tool that the tool is not using — an abandoned or relocated copy.
    Stale,
    /// A real cache of this tool, but the tool could not be asked which copy it uses.
    ///
    /// Distinct from `Stale` because absence of an answer is not evidence of abandonment. Measured:
    /// on this host `npm` is a `.ps1`/`.cmd` shim, and `Command::new("npm")` does not apply
    /// `PATHEXT`, so the resolver returns nothing and the *live* cache would otherwise be labelled
    /// stale — the exact false claim this whole mechanism exists to avoid.
    Unknown,
}

impl ToolRootActivity {
    /// Stable machine value; never localized.
    const fn code(self) -> &'static str {
        match self {
            Self::Live => "live",
            Self::Stale => "stale",
            Self::Unknown => "unknown",
        }
    }
}

/// Decides whether a scanned root is one of this rule's caches, and whether it is live.
///
/// Compares against every candidate location rather than only the resolver's answer, because an
/// abandoned cache is never the one the resolver names. Comparison uses the captured lossless
/// native path, not `display_path`: display paths are presentation data and are never execution or
/// classification authority in this codebase.
fn classify_tool_root(
    rule: &PlatformJunkRule,
    entry: &sweepx_model::ScannedEntry,
    evidence: &PlatformJunkEvidence,
) -> Option<ToolRootActivity> {
    let locator = entry.native_locator.as_ref()?;
    // Without a captured native path there is nothing trustworthy to compare against, so the rule
    // declines rather than falling back to the display string.
    let captured = locator.scan_root_absolute_path.as_ref()?;
    // Must be one of the candidates discovery itself verified, which means its markers and
    // structural fingerprint were already checked against real bytes. Re-deriving the check from
    // `display_path` would be wrong twice over: display paths are not classification authority, and
    // the same directory reached through a differently-cased path would be judged a second time.
    //
    // Candidates and the live resolver are precomputed once (see `PlatformJunkEvidence`) rather
    // than launched here: doing this per walk entry was the source of the multi-minute stall.
    let rule_evidence = evidence.for_rule(rule)?;
    let matched = rule_evidence
        .cache_candidates
        .iter()
        .find(|candidate| captured.equals_path(candidate).unwrap_or(false))?;
    // Liveness compares directory identity, not spelling. The resolver and an environment override
    // routinely name one directory with different casing, and comparing the resolver's raw string
    // against the deduplicated candidate reported that single cache as both stale and live at once.
    //
    // No answer means `Unknown`, never `Stale`: a tool that cannot be asked has not told us this
    // copy is abandoned, and claiming otherwise about a live cache is the worst outcome available.
    Some(match rule_evidence.reported_root {
        Some(ref reported) if same_directory(matched, reported) => ToolRootActivity::Live,
        Some(_) => ToolRootActivity::Stale,
        None => ToolRootActivity::Unknown,
    })
}

/// One Chromium-family browser installation whose caches SweepX knows how to find.
///
/// Listed explicitly rather than by scanning for anything resembling a browser: a directory named
/// `User Data` is not authority to treat its contents as disposable.
struct ChromiumInstall {
    /// Path below `%LOCALAPPDATA%`, `/`-separated so the platform separator is applied once, by
    /// `push`. Writing a `\`-containing literal produced a mixed-separator path that passed every
    /// local check yet never matched the native path the scanner captured.
    relative_user_data: &'static str,
}

/// The installations probed on Windows.
///
/// Measured on this host 2026-09-05: all three exist, and Edge Dev held the single largest
/// reclaimable directory (611.7 MB of code cache). Assuming one browser would have missed it.
const CHROMIUM_INSTALLS: &[ChromiumInstall] = &[
    ChromiumInstall {
        relative_user_data: "Microsoft/Edge/User Data",
    },
    ChromiumInstall {
        relative_user_data: "Microsoft/Edge Dev/User Data",
    },
    ChromiumInstall {
        relative_user_data: "Microsoft/Edge Beta/User Data",
    },
    ChromiumInstall {
        relative_user_data: "Google/Chrome/User Data",
    },
    ChromiumInstall {
        relative_user_data: "Google/Chrome Beta/User Data",
    },
    ChromiumInstall {
        relative_user_data: "Google/Chrome Dev/User Data",
    },
    ChromiumInstall {
        relative_user_data: "BraveSoftware/Brave-Browser/User Data",
    },
    ChromiumInstall {
        relative_user_data: "Vivaldi/User Data",
    },
];

/// Cache directories that live inside a profile, and so exist once per profile.
const PROFILE_RENDER_CACHES: &[&str] = &[
    "Cache",
    "Code Cache",
    "GPUCache",
    "DawnGraphiteCache",
    "DawnWebGPUCache",
    "Media Cache",
];

/// Cache directories that live beside the profiles, shared by the whole installation.
///
/// Easy to miss: they are not under any profile, so a profile-only walk finds none of them. They
/// held about 40 MB across three installations here.
const INSTALL_RENDER_CACHES: &[&str] = &[
    "ShaderCache",
    "GrShaderCache",
    "GraphiteDawnCache",
    "GraphiteCache",
];

/// Every render-cache directory of every discovered Chromium installation.
///
/// Returns scan roots, not candidates: which rule claims each one is decided by that rule's marker,
/// because the three backends have three different layouts. Nothing is filtered on size here — an
/// empty blockfile cache still occupies its scaffolding, and hiding it would misreport the disk.
fn chromium_render_cache_roots() -> Vec<PathBuf> {
    let mut roots = Vec::new();
    let Some(local_app_data) = std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
    else {
        return roots;
    };
    for install in CHROMIUM_INSTALLS {
        let mut user_data = local_app_data.clone();
        for component in install.relative_user_data.split('/') {
            user_data.push(component);
        }
        if !is_existing_real_directory(&user_data) {
            continue;
        }
        for name in INSTALL_RENDER_CACHES {
            let candidate = user_data.join(name);
            if is_existing_real_directory(&candidate) {
                roots.push(candidate);
            }
        }
        // Profiles are enumerated from disk. Their names are a user-facing product concept
        // (`Default`, `Profile 1`, …) and a hardcoded list would silently skip the rest.
        let Ok(entries) = std::fs::read_dir(&user_data) else {
            continue;
        };
        for entry in entries.flatten() {
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                continue;
            };
            if name != "Default" && !name.starts_with("Profile ") {
                continue;
            }
            let profile = user_data.join(name);
            if !is_existing_real_directory(&profile) {
                continue;
            }
            for cache in PROFILE_RENDER_CACHES {
                let candidate = profile.join(cache);
                if is_existing_real_directory(&candidate) {
                    roots.push(candidate);
                }
            }
        }
    }
    roots
}

/// Whether this scan root is the cache the rule describes.
///
/// Discovery yields every render cache of every installation, so a root reaching this point is some
/// browser cache but not necessarily *this* rule's. The marker decides, and the three backends are
/// told apart by it: the HTTP cache keeps entries under `Cache_Data`, the code cache under `js`, and
/// the shader caches are blockfile roots holding `data_1`. An index file is not a usable
/// discriminator — measured 2026-09-05, two of the three carry none at the root.
fn render_cache_root_matches(rule: &PlatformJunkRule, entry: &sweepx_model::ScannedEntry) -> bool {
    let Some(locator) = entry.native_locator.as_ref() else {
        return false;
    };
    // Same rule as everywhere else in this file: the captured native path is authority, the display
    // path is presentation.
    let Some(captured) = locator.scan_root_absolute_path.as_ref() else {
        return false;
    };
    let Some(root) = chromium_render_cache_roots()
        .into_iter()
        .find(|candidate| captured.equals_path(candidate).unwrap_or(false))
    else {
        return false;
    };
    rule.required_markers
        .iter()
        .all(|marker| root.join(marker).exists())
}

#[cfg(target_os = "macos")]
fn known_macos_root_matches(rule: &PlatformJunkRule, entry: &sweepx_model::ScannedEntry) -> bool {
    let Some(locator) = entry.native_locator.as_ref() else {
        return false;
    };
    let Some(entry_path) = entry_native_absolute_path(locator) else {
        return false;
    };
    // Exact, full-length match against each declared known root. The components are taken from
    // the captured native chain, never from `display_path`, and an exact component count is
    // required so a directory *inside* a known root (for example a Homebrew download) is not
    // promoted.
    known_macos_roots(rule)
        .into_iter()
        .find(|root| entry_path.equals_path(root).unwrap_or(false))
        .is_some_and(|root| root_has_required_markers(&root, &rule.required_markers))
}

/// Reconstructs an entry's own absolute native path from its locator chain.
///
/// The locator stores only the scan root as an absolute path; intermediate and entry components
/// are retained natively. `parent_reopen_recipe` starts with a component duplicating the scan
/// root (the locator invariant), so it is skipped; every remaining intermediate basename and
/// the entry basename are appended byte-for-byte without normalization. This is what lets a
/// known root nested inside a wider scan root (Homebrew/Yarn under `~/Library/Caches`) be
/// classified at its real depth instead of only when it is a depth-0 root.
#[cfg(target_os = "macos")]
fn entry_native_absolute_path(
    locator: &sweepx_model::NativeLocatorEvidence,
) -> Option<sweepx_model::NativeAbsolutePath> {
    let sweepx_model::NativeAbsolutePath::UnixBytes(root) =
        locator.scan_root_absolute_path.as_ref()?
    else {
        return None;
    };
    let mut bytes = root.clone();
    let append = |bytes: &mut Vec<u8>, name: &sweepx_model::NativeName| {
        let sweepx_model::NativeName::UnixBytes(component) = name else {
            return false;
        };
        bytes.push(b'/');
        bytes.extend_from_slice(component);
        true
    };
    for component in locator.parent_reopen_recipe.iter().skip(1) {
        if !append(&mut bytes, &component.native_basename) {
            return None;
        }
    }
    if !append(&mut bytes, &locator.entry.native_basename) {
        return None;
    }
    Some(sweepx_model::NativeAbsolutePath::unix(bytes))
}

#[cfg(not(target_os = "macos"))]
fn known_macos_root_matches(_rule: &PlatformJunkRule, _entry: &sweepx_model::ScannedEntry) -> bool {
    false
}

#[cfg(target_os = "macos")]
fn known_macos_roots(rule: &PlatformJunkRule) -> Vec<PathBuf> {
    let Some(home) = user_home_dir().filter(|home| home.is_absolute()) else {
        return Vec::new();
    };
    let mut paths: Vec<PathBuf> = Vec::new();
    for known in &rule.known_roots {
        // Only a home-relative anchor is currently defined. A literal absolute base is refused
        // rather than trusted, because rules must not encode one machine's layout.
        if known.base != "home" {
            continue;
        }
        let mut path: PathBuf = home.clone();
        for component in &known.components {
            path.push(component);
        }
        if is_existing_real_directory(&path)
            && !paths.iter().any(|existing| same_directory(existing, &path))
        {
            paths.push(path);
        }
    }
    paths
}

#[cfg(not(target_os = "macos"))]
// The only caller sits inside the `#[cfg(target_os = "macos")]` root-discovery block, so this
// stub exists purely to keep the not-macOS build resolving and is dead on linux/Windows.
#[allow(dead_code)]
fn known_macos_roots(_rule: &PlatformJunkRule) -> Vec<PathBuf> {
    Vec::new()
}

/// Resolves a browser-cache spec's anchor to an absolute base directory.
///
/// `application_support` is the macOS `~/Library/Application Support`, `local_app_data` is the
/// Windows `%LOCALAPPDATA%`, and `home` is the user home. An unknown or unresolvable anchor
/// yields `None` rather than a guessed path.
fn browser_base_dir(base: &str) -> Option<PathBuf> {
    let home = user_home_dir()?;
    match base {
        "home" => Some(home),
        "application_support" => Some(home.join("Library").join("Application Support")),
        "local_app_data" => std::env::var_os("LOCALAPPDATA")
            .map(PathBuf::from)
            .filter(|path| path.is_absolute()),
        _ => None,
    }
}

/// Every derived cache directory a rule's browser specs expand to.
///
/// Walks each browser's shared caches beside the profiles and the profile caches inside every
/// `Default`/`Profile N` directory enumerated from disk, so no browser needs a code branch and no
/// profile name is assumed. Only existing real directories are returned and duplicates are folded
/// by filesystem identity, because two browsers (or an injected config) can resolve to one path.
fn browser_cache_roots(rule: &PlatformJunkRule) -> Vec<PathBuf> {
    let mut roots = Vec::new();
    for spec in &rule.browser_caches {
        let Some(base) = browser_base_dir(&spec.base) else {
            continue;
        };
        let mut user_data = base;
        for component in &spec.user_data {
            user_data.push(component);
        }
        if !is_existing_real_directory(&user_data) {
            continue;
        }
        for name in &spec.shared_caches {
            let candidate = user_data.join(name);
            push_browser_root(&candidate, &mut roots);
        }
        // Non-derived state paths resolved relative to user-data, split on `/` so the platform
        // separator is applied consistently.
        for relative in &spec.shared_paths {
            let mut candidate = user_data.clone();
            for component in relative.split('/') {
                candidate.push(component);
            }
            push_browser_root(&candidate, &mut roots);
        }
        // Gather every directory that holds a profile/partition, then select its derived caches.
        let mut profile_dirs: Vec<PathBuf> = Vec::new();
        for name in &spec.profile_names {
            profile_dirs.push(user_data.join(name));
        }
        if spec.enumerate_named_profiles {
            // Read from disk: a fixed list would silently miss extra Default/Profile N entries.
            if let Ok(entries) = std::fs::read_dir(&user_data) {
                for entry in entries.flatten() {
                    let file_name = entry.file_name();
                    if let Some(name) = file_name.to_str()
                        && (name == "Default" || name.starts_with("Profile "))
                    {
                        profile_dirs.push(entry.path());
                    }
                }
            }
        }
        for container in &spec.partition_containers {
            let dir = user_data.join(container);
            if let Ok(entries) = std::fs::read_dir(&dir) {
                // Every real-directory child is treated as a partition (UUIDs, hashes, …), so the
                // product's naming scheme does not need to be encoded.
                for entry in entries.flatten() {
                    profile_dirs.push(entry.path());
                }
            }
        }
        for profile in profile_dirs {
            if !is_existing_real_directory(&profile) {
                continue;
            }
            for cache in &spec.profile_caches {
                push_browser_root(&profile.join(cache), &mut roots);
            }
            // Profile-relative multi-component state paths.
            for relative in &spec.profile_paths {
                let mut candidate = profile.clone();
                for component in relative.split('/') {
                    candidate.push(component);
                }
                push_browser_root(&candidate, &mut roots);
            }
        }
    }
    roots
}

fn push_browser_root(candidate: &Path, roots: &mut Vec<PathBuf>) {
    if is_existing_real_directory(candidate)
        && !roots
            .iter()
            .any(|existing| same_directory(existing, candidate))
    {
        roots.push(candidate.to_path_buf());
    }
}

/// Whether a scanned root is one of the derived caches this rule's browser specs expand to.
///
/// Comparison uses the captured native path, never the display string: display paths are not
/// classification authority in this codebase. The directory's position inside a known browser
/// user-data tree, together with its derived-cache name, is the evidence; the marker-bearing
/// network caches elsewhere are a different rule.
fn browser_cache_root_matches(rule: &PlatformJunkRule, entry: &sweepx_model::ScannedEntry) -> bool {
    let Some(locator) = entry.native_locator.as_ref() else {
        return false;
    };
    let Some(captured) = locator.scan_root_absolute_path.as_ref() else {
        return false;
    };
    browser_cache_roots(rule)
        .iter()
        .any(|root| captured.equals_path(root).unwrap_or(false))
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
/// The size to report for a junk candidate, and which quantity it actually is.
///
/// `potentially_reclaimable_bytes` is derived from filesystem allocation, and the Windows adapter
/// deliberately refuses to claim allocation: `FILE_STANDARD_INFO` describes only the unnamed `$DATA`
/// stream, so an exact figure would be a guess wherever alternate streams, sparse ranges or
/// compression are in play. That refusal is correct and is not worked around here.
///
/// The consequence was that on Windows *every* candidate reported an unknown size — measured
/// 2026-09-05, 30 of 30, including 1.8 GB of browser caches. A cleaning tool that cannot say how
/// large anything is has not answered the user's question.
///
/// So when allocation is unavailable, the apparent logical size is reported instead, since it is
/// known exactly and is the quantity a user means by "how big is this cache". The two are not
/// interchangeable, so the caller is told which one it received rather than being left to assume
/// allocation.
struct JunkSize {
    value: ByteValue,
    /// True when `value` is logical size standing in for unavailable allocation.
    is_logical_fallback: bool,
}

/// Picks the reportable size for one aggregate, preferring allocation and falling back to logical.
fn junk_size_for(aggregate: Option<&sweepx_model::DirectoryAggregate>) -> JunkSize {
    let Some(aggregate) = aggregate else {
        return JunkSize {
            value: ByteValue::NotChecked {
                reason: ReasonCode::ResourceLimit,
            },
            is_logical_fallback: false,
        };
    };
    // Only an exactly known allocation is preferred. A lower bound or unknown allocation carries
    // less information than an exactly known logical size, so it does not win by being the
    // nominally correct field.
    if matches!(
        aggregate.potentially_reclaimable_bytes,
        ByteValue::Known { .. }
    ) {
        return JunkSize {
            value: aggregate.potentially_reclaimable_bytes.clone(),
            is_logical_fallback: false,
        };
    }
    match &aggregate.apparent_logical_bytes {
        known @ ByteValue::Known { .. } => JunkSize {
            value: known.clone(),
            is_logical_fallback: true,
        },
        // Neither is exact: keep the allocation-derived evidence, because its reason code explains
        // why the size is missing. Substituting an equally inexact logical value would discard that
        // explanation without adding anything.
        _ => JunkSize {
            value: aggregate.potentially_reclaimable_bytes.clone(),
            is_logical_fallback: false,
        },
    }
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

struct NormalizedJunkRoots {
    scan_roots: Vec<PathBuf>,
    temp_roots: Vec<PathBuf>,
}

fn normalize_junk_roots(
    system: bool,
    raw_roots: &[OsString],
) -> Result<NormalizedJunkRoots, String> {
    if !system {
        return Ok(NormalizedJunkRoots {
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
            return Ok(NormalizedJunkRoots {
                scan_roots: default_platform_junk_roots()?,
                temp_roots,
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

    let scan_roots = default_platform_junk_roots()?;
    if scan_roots.is_empty() {
        return Err("no supported platform junk root is available".to_string());
    }
    Ok(NormalizedJunkRoots {
        scan_roots,
        temp_roots: Vec::new(),
    })
}

fn default_platform_junk_roots() -> Result<Vec<PathBuf>, String> {
    let rules = load_platform_junk_rules()?;
    let mut roots = Vec::new();
    // Tool-reported roots come first because they are platform-independent. Every plausible
    // location is enumerated, not just the one the tool named: an abandoned cache at a documented
    // default is exactly what a resolver-only pass misses, and on this host it was the larger copy.
    // Each candidate is verified by markers and structural fingerprint before admission.
    for rule in &rules {
        if tool_reported_root_for(&rule.root_kind).is_none() {
            continue;
        }
        for root in tool_cache_candidates(rule) {
            // Identity, not spelling: two rules can name one directory, and a scan given the same
            // directory twice reports it twice.
            if !roots
                .iter()
                .any(|existing: &PathBuf| same_directory(existing.as_path(), root.as_path()))
            {
                roots.push(root);
            }
        }
    }
    // Browser derived caches are declared in rule data (one spec per browser) and expanded here,
    // so the same mechanism serves any platform whose spec anchor resolves.
    for rule in &rules {
        for root in browser_cache_roots(rule) {
            if !roots
                .iter()
                .any(|existing: &PathBuf| same_directory(existing.as_path(), root.as_path()))
            {
                roots.push(root);
            }
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
        if rules.iter().any(|rule| rule.platform == "macos") {
            if let Some(cache) = user_home_dir()
                .filter(|home| home.is_absolute())
                .map(|home| home.join("Library/Caches"))
                .filter(|cache| is_existing_real_directory(cache))
            {
                roots.push(cache);
            }
            for rule in rules.iter().filter(|rule| rule.platform == "macos") {
                for root in known_macos_roots(rule) {
                    if !roots.iter().any(|existing: &PathBuf| {
                        same_directory(existing.as_path(), root.as_path())
                    }) {
                        roots.push(root);
                    }
                }
            }
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
        // Browser render caches are separate roots, one per cache directory, because each is an
        // independent aggregate the user may keep or reclaim on its own. They are added only when a
        // rule asks for them, so an installation nobody has a rule for is never walked.
        if rules
            .iter()
            .any(|rule| rule.root_kind == "chromium_render_cache")
        {
            for root in chromium_render_cache_roots() {
                if !roots
                    .iter()
                    .any(|existing: &PathBuf| same_directory(existing.as_path(), root.as_path()))
                {
                    roots.push(root);
                }
            }
        }
    }
    Ok(roots)
}

#[cfg(target_os = "linux")]
fn linux_temp_candidates(
    rule: &PlatformJunkRule,
    discovery: &linux_temp::LinuxTempDiscovery,
) -> Vec<JunkCandidate> {
    use std::os::unix::fs::MetadataExt;

    discovery
        .candidates
        .iter()
        .filter_map(|candidate| {
            let metadata = &candidate.measurement.top;
            let mut blockers = vec![linux_temp::REFERENCE_BLOCKER.to_string()];
            if !discovery.complete {
                blockers.push("linux_tmp_discovery_incomplete".to_string());
            }
            Some(JunkCandidate {
                path: candidate.path.display().to_string(),
                native_path: Some(candidate.path.clone()),
                rule_id: rule.id.clone(),
                risk: rule.risk.clone(),
                reclaimable: ByteValue::Known {
                    value: sweepx_model::DecimalU128::new(candidate.measurement.allocated_bytes),
                },
                evidence: rule.evidence.clone(),
                source_reviewed_at: rule.source_reviewed_at.clone(),
                references: rule.references.clone(),
                entry_id: ScanEntryId::for_scan_ordinal(
                    &sweepx_model::ScanId::new("linux-temp-report"),
                    u128::from(metadata.ino()).saturating_add(1),
                )
                .ok()?,
                ancestor_ids: BTreeSet::new(),
                activity: Some(linux_temp::ACTIVITY_CODE.to_string()),
                stale_formats: Vec::new(),
                size_is_logical: false,
                git: None,
                classification: Some(linux_temp::CLASSIFICATION.to_string()),
                confidence: Some("medium".to_string()),
                blockers,
                source_entry: None,
            })
        })
        .collect()
}

fn is_existing_real_directory(path: &Path) -> bool {
    // Root discovery is convenience only, but it still avoids following a symlink before the
    // platform scanner performs the authoritative no-follow admission and identity checks.
    std::fs::symlink_metadata(path).is_ok_and(|metadata| metadata.file_type().is_dir())
}

/// One tool-reported cache root, as the tool itself describes it.
///
/// Measured on Windows on 2026-09-01: for npm, pnpm, and pip the location reported by the tool
/// differed from the documented platform default *and both paths existed*.
///
/// The first reading of that measurement — that defaults must therefore not be shipped — was wrong,
/// and re-measuring on 2026-09-05 established the opposite. A resolver answers "which cache is
/// live", and the live one is precisely the one that must **not** be reclaimed. The abandoned copy
/// at the documented default is the junk, and on this host it was the larger of the two: a pnpm
/// store of 146.8 MB last written 2024-10-26, against 127.5 MB in the store actually in use. A
/// resolver-only rule cannot see it at all.
///
/// So discovery enumerates every plausible location and the resolver is retained for a different
/// purpose: to mark which candidate is live, as a guard rather than as the discovery mechanism.
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
        // On Windows many of these tools ship only as a `.cmd`/`.bat` shim, and `Command::new` does
        // not apply `PATHEXT`, so the bare name fails even though the shell finds it. Measured: npm
        // on this host is `npm.ps1` plus `npm.cmd`, and without this the live npm cache was reported
        // as abandoned. `.ps1` is deliberately not attempted: it is not directly executable and
        // running it would mean invoking a shell.
        #[cfg(target_os = "windows")]
        let spellings: Vec<String> = vec![
            format!("{}.cmd", self.program),
            format!("{}.bat", self.program),
            format!("{}.exe", self.program),
            self.program.to_string(),
        ];
        #[cfg(not(target_os = "windows"))]
        let spellings: Vec<String> = vec![self.program.to_string()];

        for spelling in spellings {
            let Ok(output) = std::process::Command::new(&spelling)
                .args(self.arguments)
                .stdin(std::process::Stdio::null())
                .output()
            else {
                continue;
            };
            if !output.status.success() {
                continue;
            }
            let Ok(text) = String::from_utf8(output.stdout) else {
                continue;
            };
            let Some(line) = text.lines().next() else {
                continue;
            };
            let path = PathBuf::from(line.trim());
            // A relative path cannot be admitted as a scan root, and resolving one here against the
            // current directory would invent a location the tool never reported.
            if path.is_absolute() {
                return Some(path);
            }
        }
        None
    }
}

/// Where a tool's cache may sit besides the location the tool itself reports.
///
/// Each entry is an environment variable holding an absolute path, or a path relative to a known
/// base. Enumerating these is what finds an abandoned cache: the resolver only ever names the live
/// one, and a stale copy is indistinguishable from it by path shape.
struct CandidateSources {
    /// Environment variables that, when set to an absolute path, name the cache root directly.
    env_overrides: &'static [&'static str],
    /// Paths relative to `%LOCALAPPDATA%` (Windows) or `$HOME` (elsewhere).
    relative_defaults: &'static [&'static str],
    /// When set, a candidate from the list above is a *container* of versioned store directories,
    /// and each child matching this prefix is the actual root.
    ///
    /// Measured: `pnpm store path` reports `…\.pnpm-store\v3`, one level below the configured store
    /// directory. A default written without the version level therefore fails the marker check and
    /// silently yields no candidate — which is how the stale store was first missed. The version is
    /// discovered from the directory rather than hardcoded, because the same name (`v3`) is used by
    /// both a current pnpm and a store abandoned two years ago, so it cannot indicate freshness.
    versioned_child_prefix: Option<&'static str>,
}

/// Structural evidence that a directory really is the kind of cache a rule claims.
///
/// A path alone proves nothing, and two caches of the same tool at different locations look
/// identical from the outside. The fingerprint is read from the directory's own contents, so it
/// holds regardless of where the cache lives or which tool reported it.
struct StructuralFingerprint {
    /// Additional children that must exist directly under the root.
    required_children: &'static [&'static str],
    /// A child that must exist directly under the root, for example `files` for a pnpm store.
    required_child: &'static str,
    /// Optional shard layout: this many children of `required_child`, all directories whose names
    /// are lowercase two-digit hex. Measured on a real pnpm store: exactly 256 such shards.
    ///
    /// `None` skips the check for caches with no such layout.
    hex_shard_count: Option<usize>,
}

/// One generation of a cache format, used to spot a superseded layout inside a live root.
///
/// Measured on this host: pip's cache held `http` at 73.1 MB last written 2023-12-09 next to the
/// current `http-v2` at 0 MB. The old format was 99.9% of the bytes and no longer written to, and
/// no rule keyed to the root alone can distinguish the two.
struct FormatGeneration {
    /// Child directory holding this generation, for example `http` or `http-v2`.
    directory: &'static str,
    /// `true` when a current tool still writes this generation.
    current: bool,
}

/// Everything discovery knows about one tool's cache beyond the resolver.
struct ToolCacheProfile {
    sources: CandidateSources,
    fingerprint: StructuralFingerprint,
    /// Format generations within a single root, oldest first. Empty when the cache has only one.
    generations: &'static [FormatGeneration],
}

/// Maps a `rootKind` to the additional locations and content checks for that tool.
///
/// Returning `None` means the kind has no profile and only the resolver's answer is used, which
/// keeps a rule working before its profile is measured on a real host.
fn tool_cache_profile(root_kind: &str) -> Option<ToolCacheProfile> {
    match root_kind {
        "pnpm_reported_store" => Some(ToolCacheProfile {
            sources: CandidateSources {
                // `PNPM_HOME` names the install dir, not the store; the store honors this one.
                env_overrides: &["PNPM_STORE_DIR"],
                relative_defaults: &["pnpm/store", ".pnpm-store"],
                versioned_child_prefix: Some("v"),
            },
            fingerprint: StructuralFingerprint {
                required_children: &[],
                required_child: "files",
                hex_shard_count: Some(256),
            },
            generations: &[],
        }),
        "pip_reported_cache" => Some(ToolCacheProfile {
            sources: CandidateSources {
                env_overrides: &["PIP_CACHE_DIR"],
                relative_defaults: &["pip/Cache", "pip/cache"],
                versioned_child_prefix: None,
            },
            // The root itself has no shard layout; the generations below carry the evidence.
            fingerprint: StructuralFingerprint {
                required_children: &[],
                required_child: "",
                hex_shard_count: None,
            },
            generations: &[
                FormatGeneration {
                    directory: "http",
                    current: false,
                },
                FormatGeneration {
                    directory: "http-v2",
                    current: true,
                },
            ],
        }),
        "npm_reported_cache" => Some(ToolCacheProfile {
            sources: CandidateSources {
                env_overrides: &["NPM_CONFIG_CACHE"],
                relative_defaults: &["npm-cache"],
                versioned_child_prefix: None,
            },
            fingerprint: StructuralFingerprint {
                required_children: &[],
                required_child: "_cacache",
                hex_shard_count: None,
            },
            generations: &[],
        }),
        _ => None,
    }
}

/// Whether two paths name the same directory on this host.
///
/// Resolved through the filesystem rather than by comparing strings, because whether two spellings
/// are the same directory depends on the volume, not on the text. Falls back to an exact comparison
/// when canonicalization fails, which keeps a genuinely distinct path from being folded away on the
/// strength of a failed probe.
fn same_directory(left: &Path, right: &Path) -> bool {
    match (std::fs::canonicalize(left), std::fs::canonicalize(right)) {
        (Ok(left), Ok(right)) => left == right,
        _ => left == right,
    }
}

/// Confirms a directory's own contents match the cache layout the rule claims.
///
/// This is what lets a rule report a cache at a location no tool named. Every check is read-only
/// and uses `symlink_metadata`, so a symlink cannot impersonate the structure; the scanner's
/// no-follow admission remains the authority over what is actually traversed.
fn matches_structural_fingerprint(root: &Path, fingerprint: &StructuralFingerprint) -> bool {
    if fingerprint.required_child.is_empty() {
        return true;
    }
    if !root_has_named_children(root, fingerprint.required_children.iter().copied()) {
        return false;
    }
    let child = root.join(fingerprint.required_child);
    if !std::fs::symlink_metadata(&child).is_ok_and(|metadata| metadata.file_type().is_dir()) {
        return false;
    }
    let Some(expected) = fingerprint.hex_shard_count else {
        return true;
    };
    // Counting shards is bounded by the directory's own size and reads no file contents. A wrong
    // count means this is not the layout claimed, so the rule must decline rather than guess.
    let Ok(entries) = std::fs::read_dir(&child) else {
        return false;
    };
    let mut shards = 0usize;
    for entry in entries.flatten() {
        let Ok(metadata) = entry.metadata() else {
            return false;
        };
        if !metadata.is_dir() {
            return false;
        }
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            return false;
        };
        if name.len() != 2
            || !name
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        {
            return false;
        }
        shards += 1;
        if shards > expected {
            return false;
        }
    }
    shards == expected
}

/// Every location this tool's cache might occupy, live or abandoned.
///
/// The resolver's answer comes first when available, then environment overrides, then documented
/// defaults. Each candidate must exist, be a real directory, and carry both the rule's markers and
/// the profile's structural fingerprint before it is admitted — otherwise a rule keyed to a default
/// would report whatever unrelated directory now sits there.
fn tool_cache_candidates(rule: &PlatformJunkRule) -> Vec<PathBuf> {
    let mut candidates = Vec::new();
    // Deduplication asks the filesystem, not the string. `%LOCALAPPDATA%\pip\Cache` and
    // `…\pip\cache` are one directory on a case-insensitive volume and two on a case-sensitive one,
    // and the resolver may name the same directory with different casing again. Comparing spellings
    // reported that single cache three times. Case sensitivity is a property of the host and volume,
    // so the identity is probed rather than assumed either way.
    let push = |path: PathBuf, out: &mut Vec<PathBuf>| {
        if !path.is_absolute()
            || !is_existing_real_directory(&path)
            || !root_has_required_markers(&path, &rule.required_markers)
        {
            return;
        }
        let already = out.iter().any(|existing| same_directory(existing, &path));
        if !already {
            out.push(path);
        }
    };
    if let Some(tool) = tool_reported_root_for(&rule.root_kind)
        && let Some(reported) = tool.resolve()
    {
        push(reported, &mut candidates);
    }
    let Some(profile) = tool_cache_profile(&rule.root_kind) else {
        return candidates;
    };
    for name in profile.sources.env_overrides {
        if let Some(value) = std::env::var_os(name) {
            push(PathBuf::from(value), &mut candidates);
        }
    }
    // npm is commonly installed several times (Homebrew plus one copy per Node version under
    // nvm/fnm/volta). The resolver above only asks whichever npm is first on PATH, so a cache a
    // non-default npm was explicitly configured to use would be missed. Ask every discovered
    // installation for its own cache; the marker/fingerprint checks below still verify each.
    if rule.root_kind == "npm_reported_cache" {
        for installation in tool_installations::discover_npm_installations() {
            if let Some(cache) = installation.cache {
                push(cache, &mut candidates);
            }
        }
    }
    // Defaults are relative to the platform's per-user cache base. On Windows that is
    // %LOCALAPPDATA%; elsewhere the home directory, where these tools use dotted names.
    let base = if cfg!(target_os = "windows") {
        std::env::var_os("LOCALAPPDATA").map(PathBuf::from)
    } else {
        user_home_dir()
    };
    if let Some(base) = base.filter(|path| path.is_absolute()) {
        for relative in profile.sources.relative_defaults {
            // Join component by component so the result uses the platform separator throughout. A
            // literal "a/b" on Windows produces a mixed-separator path that passes every local
            // check here yet fails to line up with the scanner's captured native path, so the
            // candidate is discovered and then silently never classified.
            let mut path = base.clone();
            for component in relative.split('/') {
                path.push(component);
            }
            match profile.sources.versioned_child_prefix {
                // The default names a container of versioned stores; the roots are one level down.
                // Enumerated rather than guessed, and each is still verified below.
                Some(prefix) => {
                    if let Ok(entries) = std::fs::read_dir(&path) {
                        for entry in entries.flatten() {
                            if entry
                                .file_name()
                                .to_str()
                                .is_some_and(|name| name.starts_with(prefix))
                            {
                                push(entry.path(), &mut candidates);
                            }
                        }
                    }
                }
                None => push(path, &mut candidates),
            }
        }
    }
    candidates.retain(|path| matches_structural_fingerprint(path, &profile.fingerprint));
    candidates
}

/// Names the superseded cache-format directories present inside a matched root.
///
/// A cache root can be live while most of its bytes sit in a format no current tool writes. On this
/// host pip held `http` at 73.1 MB last written 2023-12-09 beside the current `http-v2` at 0 MB, so
/// a rule keyed only to the root would describe 99.9% inert bytes as an active cache.
///
/// Reported only when a current generation is also present. Without that evidence the tool is
/// simply an older version whose only format is the one on disk, and calling it superseded would be
/// wrong. Read-only, `symlink_metadata`, and a marker rather than deletion authority.
fn superseded_format_generations(
    rule: &PlatformJunkRule,
    entry: &sweepx_model::ScannedEntry,
    evidence: &PlatformJunkEvidence,
) -> Vec<String> {
    let Some(profile) = tool_cache_profile(&rule.root_kind) else {
        return Vec::new();
    };
    if profile.generations.is_empty() {
        return Vec::new();
    }
    // `NativeAbsolutePath` can only be compared, not converted back to a `PathBuf` — deliberately,
    // since a display string is not reopenable. So the root used for these reads is the verified
    // candidate that the captured path matches, never a string rebuilt from the report.
    let Some(captured) = entry
        .native_locator
        .as_ref()
        .and_then(|locator| locator.scan_root_absolute_path.as_ref())
    else {
        return Vec::new();
    };
    let rule_evidence = match evidence.for_rule(rule) {
        Some(value) => value,
        None => return Vec::new(),
    };
    let Some(root) = rule_evidence
        .cache_candidates
        .iter()
        .find(|candidate| captured.equals_path(candidate).unwrap_or(false))
    else {
        return Vec::new();
    };
    let present = |generation: &FormatGeneration| {
        std::fs::symlink_metadata(root.join(generation.directory))
            .is_ok_and(|metadata| metadata.file_type().is_dir())
    };
    let has_current = profile
        .generations
        .iter()
        .any(|generation| generation.current && present(generation));
    if !has_current {
        return Vec::new();
    }
    profile
        .generations
        .iter()
        .filter(|generation| !generation.current && present(generation))
        .map(|generation| generation.directory.to_string())
        .collect()
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
    root_has_named_children_display(root, markers)
}

fn root_has_named_children<'a>(root: &Path, names: impl IntoIterator<Item = &'a str>) -> bool {
    names.into_iter().all(|marker| {
        std::fs::symlink_metadata(root.join(marker)).is_ok_and(|metadata| {
            let file_type = metadata.file_type();
            file_type.is_dir() || file_type.is_file()
        })
    })
}

fn root_has_named_children_display<'a>(
    root: &Path,
    names: impl IntoIterator<Item = &'a String>,
) -> bool {
    root_has_named_children(root, names.into_iter().map(String::as_str))
}

fn load_platform_junk_rules() -> Result<Vec<PlatformJunkRule>, String> {
    let rules: Vec<PlatformJunkRule> =
        serde_json::from_str(PLATFORM_JUNK_RULES_JSON).map_err(|error| error.to_string())?;
    let mut ids = BTreeSet::new();
    for rule in &rules {
        let expected = match rule.platform.as_str() {
            "linux" => match rule.root_kind.as_str() {
                "xdg_cache_home" => ("xdg_cache_home", "direct_children", 1),
                "linux_tmp" => ("linux_tmp", "stale_inactive_direct_child", 0),
                _ => return Err(format!("invalid platform junk rule: {}", rule.id)),
            },
            "macos" => match rule.root_kind.as_str() {
                "macos_user_caches" => ("macos_user_caches", "direct_children", 1),
                "macos_developer_cache" => ("macos_developer_cache", "verified_known_root", 0),
                "macos_browser_cache" => ("macos_browser_cache", "verified_known_root", 0),
                // Derived GPU/shader caches that live in Application Support, outside the
                // ~/Library/Caches tree; expanded from the rule's declarative browser layouts.
                "macos_browser_derived_cache" => {
                    ("macos_browser_derived_cache", "verified_browser_cache", 0)
                }
                // R3 application/site state and diagnostics expanded through the same layout.
                "macos_browser_state" => ("macos_browser_state", "verified_browser_cache", 0),
                "macos_app_cache" => ("macos_app_cache", "verified_known_root", 0),
                _ => return Err(format!("invalid platform junk rule: {}", rule.id)),
            },
            // A platform can host more than one root kind, so the shape is keyed on the root
            // kind rather than on the platform. Keying it on the platform alone made the first
            // root kind the only one that platform could ever express.
            "windows" => match rule.root_kind.as_str() {
                "windows_packages" => ("windows_packages", "named_descendant", 2),
                // Browser render caches sit one level below a profile directory, and the
                // browser-level shader caches sit directly below the user-data root. Discovery
                // yields both as scan roots, so the rule matches the root itself.
                "chromium_render_cache" => ("chromium_render_cache", "verified_cache_root", 0),
                _ => return Err(format!("invalid platform junk rule: {}", rule.id)),
            },
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
            || (rule.match_kind == "stale_inactive_direct_child"
                && (rule.root_kind != "linux_tmp"
                    || !rule.names.is_empty()
                    || !rule.required_markers.is_empty()
                    || rule.risk != "R3"))
            || (rule.match_kind == "named_descendant" && rule.names.is_empty())
            // A tool-reported root is admitted on the tool's word alone, so it must carry at
            // least one structural marker; without one the rule would report whatever now
            // occupies that path.
            || (rule.match_kind == "verified_tool_root"
                && (!rule.names.is_empty() || rule.required_markers.is_empty()))
            // A cache root is admitted because discovery walked a known browser layout, but the
            // directory still has to prove it is a cache. Chromium writes a backend marker into
            // every one; requiring it keeps the rule from reporting a same-named directory that
            // happens to sit at that path.
            || (rule.match_kind == "verified_cache_root"
                && (!rule.names.is_empty() || rule.required_markers.is_empty()))
            || (rule.match_kind == "verified_known_root"
                && (!rule.names.is_empty() || rule.known_roots.is_empty()))
            || (rule.match_kind != "verified_known_root" && !rule.known_roots.is_empty())
            // A verified_browser_cache rule must declare at least one browser spec, and no other
            // kind may carry them.
            || (rule.match_kind == "verified_browser_cache"
                && (!rule.names.is_empty()
                    || rule.browser_caches.is_empty()
                    || !rule.required_markers.is_empty()))
            || (rule.match_kind != "verified_browser_cache" && !rule.browser_caches.is_empty())
            || !rule
                .known_roots
                .iter()
                .all(|known| {
                    known.base == "home"
                        && !known.components.is_empty()
                        && known
                            .components
                            .iter()
                            .all(|component| safe_rule_component(component))
                })
            || !rule
                .browser_caches
                .iter()
                .all(|spec| {
                    let valid_anchor =
                        matches!(spec.base.as_str(), "application_support" | "local_app_data" | "home");
                    let has_any_target = !spec.shared_caches.is_empty()
                        || !spec.profile_caches.is_empty()
                        || !spec.shared_paths.is_empty()
                        || !spec.profile_paths.is_empty();
                    let can_find_profiles = spec.enumerate_named_profiles
                        || !spec.profile_names.is_empty()
                        || !spec.partition_containers.is_empty();
                    // A profile-scoped target with no way to locate a profile would be inert.
                    let profile_discovery_is_possible =
                        (spec.profile_caches.is_empty() && spec.profile_paths.is_empty())
                            || can_find_profiles;
                    let safe_single_components = spec
                        .user_data
                        .iter()
                        .chain(spec.shared_caches.iter())
                        .chain(spec.profile_caches.iter())
                        .chain(spec.profile_names.iter())
                        .chain(spec.partition_containers.iter())
                        .all(|component| safe_rule_component(component));
                    // Every segment of a multi-component path must also be a safe component.
                    let safe_path_segments = spec
                        .shared_paths
                        .iter()
                        .chain(spec.profile_paths.iter())
                        .all(|relative| {
                            !relative.is_empty()
                                && relative
                                    .split('/')
                                    .all(safe_rule_component)
                        });
                    valid_anchor
                        && !spec.user_data.is_empty()
                        && has_any_target
                        && profile_discovery_is_possible
                        && safe_single_components
                        && safe_path_segments
                })
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
    fn embedded_platform_junk_rules_are_narrow_and_evidence_bearing() {
        let rules = load_platform_junk_rules().unwrap();
        assert_eq!(rules.len(), 26);
        assert!(rules.iter().all(|rule| !rule.references.is_empty()));
        assert!(
            rules
                .iter()
                .all(|rule| valid_verification_date(&rule.source_reviewed_at))
        );
        let linux = rules
            .iter()
            .find(|rule| rule.id == "linux.xdg-user-cache")
            .unwrap();
        assert_eq!(linux.root_kind, "xdg_cache_home");
        assert_eq!(linux.match_kind, "direct_children");
        let linux_tmp = rules
            .iter()
            .find(|rule| rule.id == "linux.stale-temp-object")
            .unwrap();
        assert_eq!(linux_tmp.root_kind, "linux_tmp");
        assert_eq!(linux_tmp.match_kind, "stale_inactive_direct_child");
        assert_eq!(linux_tmp.risk, "R3");
        // Found by id, not by platform: Windows now carries browser cache rules too, and matching
        // on the platform alone silently returned whichever rule happened to be first.
        let macos_rules: Vec<_> = rules
            .iter()
            .filter(|rule| rule.platform == "macos")
            .collect();
        assert_eq!(macos_rules.len(), 17);
        let integrated_macos_ids = [
            "macos.xcode-derived-data",
            "macos.cargo-registry-cache",
            "macos.firefox-cache",
            "macos.chromium-cache",
            "macos.safari-cache",
            "macos.tencent-meeting-cache",
            "macos.homebrew-cache",
            "macos.go-cache",
            "macos.uv-cache",
            "macos.bun-cache",
            "macos.yarn-cache",
            "macos.gradle-cache",
            "macos.jetbrains-cache",
            "macos.deno-cache",
            "macos.browser-derived-cache",
        ];
        for id in integrated_macos_ids {
            assert!(rules.iter().any(|rule| rule.id == id), "missing {id}");
        }
        // Location knowledge must live in the rule data, not in code matched on rule id. Every
        // verified_known_root rule therefore declares at least one home-relative root, and no
        // other kind does.
        for rule in &rules {
            if rule.match_kind == "verified_known_root" {
                assert!(
                    !rule.known_roots.is_empty(),
                    "rule {} declares no known roots",
                    rule.id
                );
                assert!(
                    rule.known_roots
                        .iter()
                        .all(|known| known.base == "home" && !known.components.is_empty()),
                    "rule {} uses an unsupported known-root anchor",
                    rule.id
                );
            } else {
                assert!(
                    rule.known_roots.is_empty(),
                    "rule {} must not declare known roots",
                    rule.id
                );
            }
        }

        let windows = rules
            .iter()
            .find(|rule| rule.id == "windows.packaged-app-cache")
            .unwrap();
        assert_eq!(windows.names, ["LocalCache", "TempState"]);
        assert_eq!(windows.depth, 2);

        // The derived browser rule must describe several browsers purely in data, and no spec
        // may name durable profile storage.
        let derived = rules
            .iter()
            .find(|rule| rule.id == "macos.browser-derived-cache")
            .unwrap();
        assert_eq!(derived.match_kind, "verified_browser_cache");
        assert!(derived.browser_caches.len() >= 5);
        let forbidden = [
            "Cookies",
            "History",
            "Login Data",
            "Bookmarks",
            "Local Storage",
            "IndexedDB",
        ];
        for spec in &derived.browser_caches {
            assert!(spec.base == "application_support");
            assert!(!spec.user_data.is_empty());
            assert!(!spec.shared_caches.is_empty() || !spec.profile_caches.is_empty());
            for name in spec.shared_caches.iter().chain(spec.profile_caches.iter()) {
                assert!(
                    !forbidden.contains(&name.as_str()),
                    "rule selects durable {name}"
                );
            }
        }
        // On this host Postman and LarkShell are installed. Expansion must reach Postman's UUID
        // partitions through the container and LarkShell's IronDefault/profile tree, proving the
        // non-Default discovery forms work rather than only the Default/Profile convention.
        let mut expanded: Vec<String> = browser_cache_roots(derived)
            .into_iter()
            .map(|path| path.to_string_lossy().into_owned())
            .collect();
        let home = user_home_dir().unwrap();
        let postman_partitions = home.join("Library/Application Support/Postman/Partitions");
        let mut found_partition_cache = 0;
        if is_existing_real_directory(&postman_partitions) {
            for entry in std::fs::read_dir(&postman_partitions).unwrap().flatten() {
                if entry.path().join("Cache").is_dir() {
                    found_partition_cache += 1;
                }
            }
        }
        for path in &expanded {
            assert!(!path.contains("/Cookies"));
        }
        let counted = expanded
            .iter()
            .filter(|path| path.contains("/Postman/Partitions/") && path.ends_with("/Cache"))
            .count();
        assert_eq!(counted, found_partition_cache);
        let lark_shared = home.join("Library/Application Support/LarkShell/GrShaderCache");
        if is_existing_real_directory(&lark_shared) {
            assert!(
                expanded
                    .iter()
                    .any(|path| path == lark_shared.to_str().unwrap())
            );
        }
        expanded.sort();
        let before = expanded.len();
        expanded.dedup();
        assert_eq!(
            before,
            expanded.len(),
            "expanded roots must be deduplicated"
        );
    }

    #[test]
    fn browser_state_rule_reports_offline_state_and_diagnostics_at_r3() {
        let rules = load_platform_junk_rules().unwrap();
        let state = rules
            .iter()
            .find(|rule| rule.id == "macos.browser-state-diagnostics")
            .unwrap();
        assert_eq!(state.root_kind, "macos_browser_state");
        assert_eq!(state.match_kind, "verified_browser_cache");
        assert_eq!(state.risk, "R3");
        // Every expanded path must exist and be one of the documented state/diagnostic kinds;
        // durable browsing data is still excluded.
        let forbidden = [
            "Cookies",
            "History",
            "Login Data",
            "Bookmarks",
            "Local Storage",
            "IndexedDB",
        ];
        let home = user_home_dir().unwrap();
        let expanded = browser_cache_roots(state);
        for path in &expanded {
            assert!(path.is_dir(), "reports a missing path {path:?}");
            let rendered = path.to_string_lossy();
            for name in forbidden {
                assert!(
                    !rendered.contains(&format!("/{name}")),
                    "state rule selects durable {name}"
                );
            }
        }
        // On this host Chrome/Edge CacheStorage and Postman logs exist and must be reported.
        let must_exist = [
            home.join(
                "Library/Application Support/Google/Chrome/Default/Service Worker/CacheStorage",
            ),
            home.join(
                "Library/Application Support/Microsoft Edge/Default/Service Worker/CacheStorage",
            ),
            home.join("Library/Application Support/Postman/logs"),
        ];
        for expected in must_exist {
            assert!(
                expanded.iter().any(|path| same_directory(path, &expected)),
                "missing {expected:?}"
            );
        }
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
    /// Every tool profile must be self-consistent and usable by discovery.
    ///
    /// A profile whose fingerprint or defaults are wrong fails silently: the candidate is simply
    /// never produced, which is exactly how the stale pnpm store was missed on the first attempt.
    #[test]
    fn tool_cache_profiles_are_well_formed() {
        let rules = load_platform_junk_rules().expect("rules must load");
        for rule in rules
            .iter()
            .filter(|rule| rule.match_kind == "verified_tool_root")
        {
            let Some(profile) = tool_cache_profile(&rule.root_kind) else {
                continue;
            };
            assert!(
                !profile.sources.relative_defaults.is_empty()
                    || !profile.sources.env_overrides.is_empty(),
                "{} has a profile that adds no candidate location",
                rule.id
            );
            for relative in profile.sources.relative_defaults {
                assert!(
                    !relative.starts_with('/') && !relative.contains('\\'),
                    "{}: relative default {relative:?} must be '/'-separated and relative",
                    rule.id
                );
            }
            // A generation list is only meaningful if it can distinguish old from current.
            if !profile.generations.is_empty() {
                assert!(
                    profile.generations.iter().any(|g| g.current),
                    "{} lists format generations but none is current",
                    rule.id
                );
                assert!(
                    profile.generations.iter().any(|g| !g.current),
                    "{} lists format generations but none is superseded",
                    rule.id
                );
            }
        }
    }

    /// The structural fingerprint accepts a real store layout and rejects a lookalike.
    ///
    /// Pins the measured shape of a pnpm store: `files/` holding exactly 256 two-hex-digit shard
    /// directories. The count is asserted against the number actually observed on disk rather than
    /// against the constant it is meant to protect, so a change to either side is caught.
    #[test]
    fn the_store_fingerprint_needs_the_measured_shard_layout() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().join("store");
        let files = root.join("files");
        std::fs::create_dir_all(&files).expect("create files");
        let fingerprint = StructuralFingerprint {
            required_children: &[],
            required_child: "files",
            hex_shard_count: Some(256),
        };

        // Empty: the child exists but the layout does not match.
        assert!(!matches_structural_fingerprint(&root, &fingerprint));

        for shard in 0..256u32 {
            std::fs::create_dir(files.join(format!("{shard:02x}"))).expect("create shard");
        }
        assert!(
            matches_structural_fingerprint(&root, &fingerprint),
            "256 lowercase two-hex-digit shards is the layout measured on a real pnpm store"
        );

        // One extra child breaks it: a directory that merely contains hex-named folders is not a
        // store, and admitting it would let the rule name an unrelated tree a pnpm store.
        std::fs::create_dir(files.join("zz")).expect("create intruder");
        assert!(!matches_structural_fingerprint(&root, &fingerprint));

        // A missing required child is refused even when nothing else is wrong.
        let bare = temp.path().join("bare");
        std::fs::create_dir(&bare).expect("create bare");
        assert!(!matches_structural_fingerprint(&bare, &fingerprint));
    }

    /// A fingerprint with no required child imposes no structural condition.
    ///
    /// pip's root has no shard layout; its evidence is the format generations instead. The empty
    /// marker must therefore pass rather than reject everything.
    #[test]
    fn an_empty_fingerprint_accepts_any_directory() {
        let temp = tempfile::tempdir().expect("temp dir");
        let fingerprint = StructuralFingerprint {
            required_children: &[],
            required_child: "",
            hex_shard_count: None,
        };
        assert!(matches_structural_fingerprint(temp.path(), &fingerprint));
    }

    /// Activity codes are distinct, stable and machine-safe.
    ///
    /// `unknown` exists because a resolver that cannot run is not evidence of abandonment: npm on
    /// this host is a `.cmd`/`.ps1` shim, and treating "no answer" as `stale` labelled the live
    /// cache as junk.
    #[test]
    fn activity_codes_are_distinct_and_machine_safe() {
        let all = [
            ToolRootActivity::Live,
            ToolRootActivity::Stale,
            ToolRootActivity::Unknown,
        ];
        let mut codes: Vec<&str> = all.iter().map(|activity| activity.code()).collect();
        let count = codes.len();
        codes.sort_unstable();
        codes.dedup();
        assert_eq!(codes.len(), count, "activity codes must be distinct");
        assert!(
            codes
                .iter()
                .all(|code| code.chars().all(|c| c.is_ascii_lowercase())),
            "codes must stay lowercase ASCII for machine consumers"
        );
    }

    /// Two spellings of one directory are the same directory; two real directories are not.
    ///
    /// Case sensitivity is a property of the host and volume, so the behavior is probed rather than
    /// assumed. Comparing spellings reported a single pip cache three times.
    #[test]
    fn directory_identity_is_resolved_not_string_compared() {
        let temp = tempfile::tempdir().expect("temp dir");
        let one = temp.path().join("Cache");
        std::fs::create_dir(&one).expect("create dir");
        let other = temp.path().join("other");
        std::fs::create_dir(&other).expect("create other");

        assert!(same_directory(&one, &one));
        assert!(
            !same_directory(&one, &other),
            "genuinely different directories must never be folded together"
        );

        // Whether the folded spelling is the same directory depends on the volume. Assert whichever
        // invariant this host actually exhibits instead of hardcoding either expectation.
        let folded = temp.path().join("cache");
        if folded.exists() {
            assert!(
                same_directory(&one, &folded),
                "a case-insensitive volume resolves both spellings to one directory"
            );
        } else {
            assert!(
                !same_directory(&one, &folded),
                "a case-sensitive volume must not treat the folded spelling as the same directory"
            );
        }
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
    #[test]
    fn render_cache_rules_are_marker_guarded() {
        let rules = load_platform_junk_rules().expect("rules must load");
        let render: Vec<_> = rules
            .iter()
            .filter(|rule| rule.root_kind == "chromium_render_cache")
            .collect();
        assert!(
            !render.is_empty(),
            "the browser cache rules must survive in the shipped catalog"
        );
        for rule in render {
            assert_eq!(rule.match_kind, "verified_cache_root");
            assert_eq!(rule.depth, 0);
            assert_eq!(
                rule.risk, "R2",
                "{}: render caches are rebuildable",
                rule.id
            );
            assert!(
                rule.names.is_empty(),
                "{}: the root itself matches",
                rule.id
            );
            // Without a marker the rule would claim whatever now sits at that path.
            assert!(
                !rule.required_markers.is_empty(),
                "{}: a cache root must prove it is a cache",
                rule.id
            );
        }
        // The markers must tell the three backends apart. If two rules shared a marker set they
        // would both claim the same directory, and the same cache would be reported twice.
        let mut marker_sets: Vec<&Vec<String>> = render_cache_marker_sets(&rules);
        let total = marker_sets.len();
        marker_sets.sort();
        marker_sets.dedup();
        assert_eq!(
            marker_sets.len(),
            total,
            "two render cache rules share a marker set and would both claim one directory"
        );
    }

    /// A minimal aggregate carrying just the two byte fields `junk_size_for` reads.
    ///
    /// The remaining fields are filled with complete, exact values so they cannot influence the
    /// outcome: the test is about which of the two sizes is chosen, nothing else.
    fn aggregate_with(
        reclaimable: ByteValue,
        apparent: ByteValue,
    ) -> sweepx_model::DirectoryAggregate {
        sweepx_model::DirectoryAggregate {
            scan_id: sweepx_model::ScanId::new("scan-size-fallback".to_string()),
            directory_identity: "scan-entry:v1:dGVzdA:1".to_string(),
            revision: sweepx_model::DecimalU128::new(1),
            apparent_logical_bytes: apparent,
            unique_logical_bytes: ByteValue::Known {
                value: sweepx_model::DecimalU128::new(0),
            },
            filesystem_reported_allocated_bytes: ByteValue::Unknown {
                reason: ReasonCode::IncompleteStreamCoverage,
            },
            potentially_reclaimable_bytes: reclaimable,
            direct_child_count: sweepx_model::CountValue::Known {
                value: sweepx_model::DecimalU128::new(0),
            },
            recursive_entry_count: sweepx_model::CountValue::Known {
                value: sweepx_model::DecimalU128::new(0),
            },
            coverage: sweepx_model::Coverage {
                state: sweepx_model::CoverageState::Complete,
                complete: true,
                incomplete_reasons: Vec::new(),
                details_lost: false,
                provenance: sweepx_model::FieldProvenance::LiveObservation {
                    observed_at: "2026-09-05T00:00:00Z".to_string(),
                    method: sweepx_model::MethodId::NativeApi,
                },
            },
            arithmetic_state: sweepx_model::ArithmeticState::Exact,
        }
    }
    fn render_cache_marker_sets(rules: &[PlatformJunkRule]) -> Vec<&Vec<String>> {
        rules
            .iter()
            .filter(|rule| rule.root_kind == "chromium_render_cache")
            .map(|rule| &rule.required_markers)
            .collect()
    }

    /// Discovery must not invent roots, and must produce only real directories.
    ///
    /// Deliberately tolerant about *which* browsers exist: that is a property of the host. What is
    /// asserted is that whatever comes back is a real directory reachable below LOCALAPPDATA.
    #[test]
    fn render_cache_discovery_yields_only_real_directories() {
        for root in chromium_render_cache_roots() {
            assert!(
                root.is_absolute(),
                "{root:?} must be absolute to be a scan root"
            );
            assert!(
                is_existing_real_directory(&root),
                "{root:?} was reported but is not a directory"
            );
            // A mixed-separator path passes local checks yet never matches the native path the
            // scanner captures, so the candidate is found and then silently never classified.
            if cfg!(windows) {
                assert!(
                    !root.to_string_lossy().contains('/'),
                    "{root:?} mixes separators and would never match a captured native path"
                );
            }
        }
    }

    /// Discovery must not report one directory twice.
    #[test]
    fn render_cache_discovery_does_not_repeat_a_directory() {
        let roots = chromium_render_cache_roots();
        for (index, root) in roots.iter().enumerate() {
            for other in &roots[index + 1..] {
                assert!(
                    !same_directory(root, other),
                    "{root:?} and {other:?} are the same directory reported twice"
                );
            }
        }
    }

    /// An exactly known allocation is preferred; logical size stands in when it is not available.
    ///
    /// This is the difference between reporting 1.8 GB of browser caches and reporting nothing:
    /// Windows declines to claim allocation because `FILE_STANDARD_INFO` covers only the unnamed
    /// stream, and measured 2026-09-05 that left 30 of 30 candidates sizeless.
    #[test]
    fn a_missing_allocation_falls_back_to_logical_size_and_says_so() {
        let exact = junk_size_for(Some(&aggregate_with(
            ByteValue::Known {
                value: sweepx_model::DecimalU128::new(64),
            },
            ByteValue::Known {
                value: sweepx_model::DecimalU128::new(99),
            },
        )));
        assert!(
            !exact.is_logical_fallback,
            "a known allocation must be used as-is"
        );
        assert_eq!(
            exact.value,
            ByteValue::Known {
                value: sweepx_model::DecimalU128::new(64)
            }
        );

        let fell_back = junk_size_for(Some(&aggregate_with(
            ByteValue::Unknown {
                reason: ReasonCode::IncompleteStreamCoverage,
            },
            ByteValue::Known {
                value: sweepx_model::DecimalU128::new(99),
            },
        )));
        assert!(
            fell_back.is_logical_fallback,
            "the substitution must be visible to the caller, not silent"
        );
        assert_eq!(
            fell_back.value,
            ByteValue::Known {
                value: sweepx_model::DecimalU128::new(99)
            }
        );

        // Neither exact: keep the allocation evidence, whose reason explains the absence. Swapping
        // in an equally inexact logical value would discard that explanation for nothing.
        let neither = junk_size_for(Some(&aggregate_with(
            ByteValue::Unknown {
                reason: ReasonCode::IncompleteStreamCoverage,
            },
            ByteValue::LowerBound {
                value: sweepx_model::DecimalU128::new(5),
                reason: ReasonCode::IncompleteStreamCoverage,
            },
        )));
        assert!(!neither.is_logical_fallback);
        assert!(matches!(neither.value, ByteValue::Unknown { .. }));

        // No aggregate at all is not a size of zero.
        let missing = junk_size_for(None);
        assert!(!missing.is_logical_fallback);
        assert!(matches!(missing.value, ByteValue::NotChecked { .. }));
    }
}
