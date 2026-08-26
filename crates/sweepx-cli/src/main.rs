use std::ffi::OsString;
use std::path::PathBuf;
use std::process::ExitCode as ProcessExitCode;

use clap::{Parser, Subcommand, ValueEnum};
use sweepx_core::{
    CancelRequest, CleanerShowRequest, CoreContext, ExplainRequest, OutputFormat, ScanRequest,
    StatusRequest, TuiReadRequest, cancel_with_store, capabilities, cleaner_list, cleaner_show,
    durable_store, explain_from_scan_json, parse_locale_override, render_human_output,
    scan_with_store, serialize_json, serialize_ndjson, state_dir_from_explicit_or_default,
    status_with_store, tui_read_from_scan_json, validate_absolute_root,
};
use sweepx_i18n::detect_locale;
use sweepx_protocol::OutputEnvelope;

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum FormatArg {
    Human,
    Json,
    Ndjson,
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
    version = "0.1.0",
    about = "Read-only SweepX CLI facade"
)]
struct Cli {
    #[arg(long, global = true, value_enum, default_value = "human")]
    format: FormatArg,
    #[arg(long, global = true)]
    locale: Option<String>,
    #[arg(long, global = true)]
    state_dir: Option<PathBuf>,
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    Scan {
        #[arg(required = true, value_name = "ABSOLUTE_ROOT")]
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
    },
    Cancel {
        #[arg(long)]
        operation_id: String,
    },
    Cleaner {
        #[command(subcommand)]
        command: CleanerCommands,
    },
    Tui {
        #[arg(long, value_name = "ABSOLUTE_FILE")]
        scan_json: PathBuf,
        #[arg(long, default_value_t = 0)]
        page_index: usize,
        #[arg(long, default_value_t = sweepx_core::DEFAULT_ANALYSIS_INPUT_BYTES)]
        max_input_bytes: usize,
        #[arg(long, default_value_t = 100_000)]
        max_total_rows: usize,
    },
    Capabilities,
}

#[derive(Debug, Subcommand)]
enum CleanerCommands {
    List,
    Show { cleaner_ref: String },
}

fn main() -> ProcessExitCode {
    let cli = Cli::parse();
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
    let state_dir = match state_dir_from_explicit_or_default(cli.state_dir.as_deref()) {
        Ok(value) => value,
        Err(error) => {
            eprintln!("{error}");
            return ProcessExitCode::from(2);
        }
    };
    let store = match durable_store(state_dir.as_deref()) {
        Ok(value) => value,
        Err(error) => {
            eprintln!("{error}");
            return ProcessExitCode::from(2);
        }
    };

    let result = match cli.command {
        Commands::Scan { roots } => {
            let roots = match normalize_roots(&roots) {
                Ok(roots) => roots,
                Err(error) => {
                    eprintln!("{error}");
                    return ProcessExitCode::from(2);
                }
            };
            match store.as_ref() {
                Some(store) => scan_with_store(
                    &context,
                    &ScanRequest {
                        roots,
                        state_dir: state_dir.clone(),
                    },
                    Some(store),
                )
                .map(RenderedResult::Scan),
                None => scan_with_store(
                    &context,
                    &ScanRequest {
                        roots,
                        state_dir: None,
                    },
                    Option::<&sweepx_core::MemorySnapshotStore>::None,
                )
                .map(RenderedResult::Scan),
            }
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
        Commands::Status { operation_id } => match store.as_ref() {
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
        },
        Commands::Cancel { operation_id } => match store.as_ref() {
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
        },
        Commands::Cleaner { command } => match command {
            CleanerCommands::List => cleaner_list(&context).map(RenderedResult::Cleaner),
            CleanerCommands::Show { cleaner_ref } => {
                cleaner_show(&context, &CleanerShowRequest { cleaner_ref })
                    .map(RenderedResult::Cleaner)
            }
        },
        Commands::Tui {
            scan_json,
            page_index,
            max_input_bytes,
            max_total_rows,
        } => tui_read_from_scan_json(
            &context,
            &TuiReadRequest {
                scan_json_path: scan_json,
                page_index,
                max_input_bytes,
                max_total_rows,
            },
        )
        .map(RenderedResult::TuiRead),
        Commands::Capabilities => Ok(RenderedResult::Capabilities(capabilities(&context))),
    };

    match result {
        Ok(result) => {
            let format: OutputFormat = cli.format.into();
            let code = result.exit_code();
            print_output(&context, format, &result);
            ProcessExitCode::from(code)
        }
        Err(error) => {
            eprintln!("{error}");
            ProcessExitCode::from(8)
        }
    }
}

fn normalize_roots(raw_roots: &[OsString]) -> Result<Vec<PathBuf>, sweepx_core::CoreError> {
    raw_roots
        .iter()
        .map(|raw| validate_absolute_root(raw.as_os_str()))
        .collect()
}

fn print_output(context: &CoreContext, format: OutputFormat, result: &RenderedResult) {
    match format {
        OutputFormat::Human => {
            println!("{}", render_human_output(context, result.output()));
        }
        OutputFormat::Json => {
            println!("{}", serialize_json(result.output()));
        }
        OutputFormat::Ndjson => match result {
            RenderedResult::Scan(scan) => {
                print!("{}", serialize_ndjson(&scan.events));
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
    Snapshot(sweepx_core::SnapshotSuccess),
    Cleaner(sweepx_core::CleanerSuccess),
    TuiRead(sweepx_core::TuiReadSuccess),
    Capabilities(sweepx_core::CapabilitiesSuccess),
}

impl RenderedResult {
    fn output(&self) -> &OutputEnvelope {
        match self {
            Self::Scan(scan) => &scan.output,
            Self::Explanation(explanation) => &explanation.output,
            Self::Snapshot(snapshot) => &snapshot.output,
            Self::Cleaner(cleaner) => &cleaner.output,
            Self::TuiRead(tui) => &tui.output,
            Self::Capabilities(capabilities) => &capabilities.output,
        }
    }

    fn exit_code(&self) -> u8 {
        self.output().conservative_exit_code() as u8
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
    fn absolute_root_validation_is_enforced() {
        let relative = OsString::from("relative");
        assert!(normalize_roots(&[relative]).is_err());
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
        assert!(Cli::try_parse_from(["sweepx", "delete"]).is_err());
    }
}
