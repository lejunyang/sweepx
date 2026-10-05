use crate::trash_command::TrashCandidate;
use serde_json::json;
use std::path::Path;
use std::process::ExitCode;
use sweepx_core::{CancellationToken, OutputFormat};
use sweepx_i18n::Locale;
use sweepx_model::HumanSizeUnit;

pub(crate) fn run(
    version: Option<&str>,
    trash: bool,
    config: Option<&Path>,
    format: OutputFormat,
    unit: HumanSizeUnit,
    locale: Locale,
) -> ExitCode {
    if let Some(path) = config {
        let result = (|| {
            if !path.is_absolute() {
                return Err("config_path_must_be_absolute".to_string());
            }
            use std::io::Write;
            let mut file = std::fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(path)
                .map_err(|e| e.to_string())?;
            file.write_all(sweepx_core::browser_storage::models::macos_disable_profile().as_bytes())
                .map_err(|e| e.to_string())
        })();
        match result {
            Ok(()) => {
                println!(
                    "{}",
                    json!({"schema":"sweepx.browser_model.policy_export/v1","path":path,"installed":false,"verified":false,"policy":"GenAILocalFoundationalModelSettings","value":1,"requires":"install_profile_and_verify_chrome_policy"})
                );
                return ExitCode::SUCCESS;
            }
            Err(e) => {
                eprintln!("{e}");
                return ExitCode::from(3);
            }
        }
    }
    let cancel = CancellationToken::new();
    let Some(install) = sweepx_core::browser_storage::default_installations()
        .into_iter()
        .find(|i| i.browser == "chrome")
    else {
        eprintln!("Chrome installation root unavailable");
        return ExitCode::from(3);
    };
    let inventory = sweepx_core::browser_storage::models::inventory(&install, &cancel);
    let plan: Vec<_> = inventory
        .versions
        .iter()
        .filter(|r| version.is_none_or(|v| r.version == v))
        .collect();
    if plan.is_empty() {
        eprintln!("No matching model version observed");
        return ExitCode::from(3);
    }
    let mut results = Vec::new();
    let mut blocked = None;
    if trash {
        if let Err(e) = sweepx_core::tools::scoped_activity::check_chrome_inactive(&cancel) {
            blocked = Some(e);
        }
        if blocked.is_none() {
            for row in &plan {
                let result = (|| {
                    sweepx_core::tools::scoped_activity::check_chrome_inactive(&cancel)?;
                    let scope = crate::trash_command::path_from_live_locator(row.source_entry())
                        .map_err(|e| e.to_string())?;
                    // The browser-wide check above still refuses active Chrome. Other processes
                    // may read unrelated profile metadata (e.g. Spotlight and .DS_Store); that
                    // does not establish use of this model version. Check its native scope only.
                    sweepx_core::tools::scoped_activity::check_scopes(&[scope.as_path()], &cancel)?;
                    row.revalidate(&cancel)?;
                    let candidate = TrashCandidate::from_scanned_entry(row.source_entry())
                        .map_err(|e| e.to_string())?;
                    if candidate.requires_confirmation() {
                        return Err("important_path_refused".into());
                    }
                    candidate.submit().map_err(|e| e.to_string())
                })();
                results.push(
                    json!({"version":row.version,"moved":result.is_ok(),"error":result.err()}),
                );
            }
        }
    }
    if format == OutputFormat::Human {
        for row in &plan {
            println!(
                "{:>12}  {}{}",
                row.bytes
                    .as_deref()
                    .and_then(|b| b.parse::<u128>().ok())
                    .map(|b| unit.format(b))
                    .unwrap_or_else(|| "?".into()),
                row.version,
                if row.complete { "" } else { " [partial]" }
            );
            for issue in &row.issues {
                eprintln!("{issue}");
            }
        }
        println!(
            "{}",
            if locale == Locale::ZhCn {
                "模型回收不等于禁止重下。安装专用策略并在 chrome://policy 确认值为 1；依赖基础模型的功能将不可用。"
            } else {
                "Trash alone does not prevent redownload. Install the dedicated policy and verify value 1 in chrome://policy; foundation-model features will become unavailable."
            }
        );
        if let Some(e) = &blocked {
            eprintln!("{e}");
        }
        for r in &results {
            println!("{r}");
        }
    } else {
        println!(
            "{}",
            json!({"schema":"sweepx.browser_model.result/v1","readOnly":!trash,"inventory":inventory,"results":results,"blocked":blocked,"recoverable":true,"permanentDeletion":false,"redownloadDisabled":null,"policy":"GenAILocalFoundationalModelSettings=1"})
        );
    }
    ExitCode::from(
        if blocked.is_some() || results.iter().any(|r| r["moved"] != true) {
            8
        } else if !inventory.complete {
            4
        } else {
            0
        },
    )
}
