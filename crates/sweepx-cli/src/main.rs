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
    /// Report browser site storage per origin. Never deletes and never pre-selects.
    ///
    /// Separate from `junk` on purpose. Junk means "rebuildable"; this is R3 site application
    /// state — PWA offline data and structured site data — which the browser itself only ever
    /// removes one site at a time and which is not safe to treat as disposable in bulk.
    SiteStorage,
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
        Commands::SiteStorage => {
            return run_site_storage(&context, format, size_unit);
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
    /// `live` or `stale` for a tool cache; `None` when activity is not a meaningful question.
    ///
    /// A marker only. A stale cache is not deleted, pre-selected, or ranked differently here;
    /// platform junk classification is report-only and this simply records which copy the tool is
    /// using, so the reader can tell an abandoned cache from the working one.
    activity: Option<&'static str>,
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
                .then(|| {
                    let size = junk_size_for(aggregates.get(identity.entry_id.as_str()).copied());
                    JunkCandidate {
                        path: entry.display_path.clone(),
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
                        // A project build output has no "which copy is the tool using" question: it
                        // belongs to the tree it sits in. Claiming an activity here would be noise.
                        activity: None,
                        stale_formats: Vec::new(),
                        size_is_logical: size.is_logical_fallback,
                    }
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
                    // Markers, not instructions. `activity` says whether the tool is using this
                    // copy; `staleFormats` names obsolete format directories inside it. Both are
                    // omitted when they do not apply so a reader never sees an empty claim.
                    "activity": candidate.activity,
                    "staleFormats": candidate.stale_formats,
                    // Names the quantity in `reclaimable`. True means apparent logical size,
                    // because this platform declined to claim filesystem allocation; the two
                    // differ on compressed, sparse and multi-stream files, so a consumer that
                    // needs allocation must be able to see that it did not get it.
                    "sizeIsLogical": candidate.size_is_logical,
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
                // markers and structural fingerprint, so the rule reports one aggregate for the
                // whole cache rather than per-file rows.
                "verified_tool_root" => depth == 0 && tool_reported_root_matches(rule, entry),
                // Also the scan root itself, but discovered by walking a known browser layout
                // instead of by asking a tool. The marker is rechecked here because discovery
                // and classification see the path through different readers.
                "verified_cache_root" => depth == 0 && render_cache_root_matches(rule, entry),
                _ => false,
            };
            if !matched {
                continue;
            }
            let activity =
                classify_tool_root(rule, entry).map(|classification| classification.code());
            let stale_formats = superseded_format_generations(rule, entry);
            // Same allocation-versus-logical problem as the project rules, with one extra source:
            // the entry's own estimate, which is kept ahead of the logical fallback because it is
            // the scanner's own claim about this specific entry.
            let aggregate = aggregates.get(identity.entry_id.as_str()).copied();
            let size = if aggregate.is_some() {
                junk_size_for(aggregate)
            } else {
                JunkSize {
                    value: entry.reclaimable_estimate.clone(),
                    is_logical_fallback: false,
                }
            };
            candidates.push(JunkCandidate {
                path: entry.display_path.clone(),
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
                activity,
                stale_formats,
                size_is_logical: size.is_logical_fallback,
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
    classify_tool_root(rule, entry).is_some()
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
) -> Option<ToolRootActivity> {
    let locator = entry.native_locator.as_ref()?;
    // Without a captured native path there is nothing trustworthy to compare against, so the rule
    // declines rather than falling back to the display string.
    let captured = locator.scan_root_absolute_path.as_ref()?;
    // Must be one of the candidates discovery itself verified, which means its markers and
    // structural fingerprint were already checked against real bytes. Re-deriving the check from
    // `display_path` would be wrong twice over: display paths are not classification authority, and
    // the same directory reached through a differently-cased path would be judged a second time.
    let matched = tool_cache_candidates(rule)
        .into_iter()
        .find(|candidate| captured.equals_path(candidate).unwrap_or(false))?;
    // Liveness compares directory identity, not spelling. The resolver and an environment override
    // routinely name one directory with different casing, and comparing the resolver's raw string
    // against the deduplicated candidate reported that single cache as both stale and live at once.
    //
    // No answer means `Unknown`, never `Stale`: a tool that cannot be asked has not told us this
    // copy is abandoned, and claiming otherwise about a live cache is the worst outcome available.
    Some(
        match tool_reported_root_for(&rule.root_kind).and_then(|tool| tool.resolve()) {
            Some(reported) if same_directory(&matched, &reported) => ToolRootActivity::Live,
            Some(_) => ToolRootActivity::Stale,
            None => ToolRootActivity::Unknown,
        },
    )
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
) -> ProcessExitCode {
    let reports = collect_site_storage();
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
    let Some(root) = tool_cache_candidates(rule)
        .into_iter()
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
        assert_eq!(rules.len(), 9);
        assert!(rules.iter().all(|rule| !rule.references.is_empty()));
        assert!(
            rules
                .iter()
                .all(|rule| valid_verification_date(&rule.source_reviewed_at))
        );
        let linux = rules.iter().find(|rule| rule.platform == "linux").unwrap();
        assert_eq!(linux.root_kind, "xdg_cache_home");
        assert_eq!(linux.match_kind, "direct_children");
        // Found by id, not by platform: Windows now carries browser cache rules too, and matching
        // on the platform alone silently returned whichever rule happened to be first.
        let windows = rules
            .iter()
            .find(|rule| rule.id == "windows.packaged-app-cache")
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
