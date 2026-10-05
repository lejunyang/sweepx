//! Rendering and read-only filters for the reusable browser analysis.
use std::collections::BTreeMap;
use std::process::ExitCode;

use serde_json::json;
use sweepx_core::browser_storage::{
    BrowserStorageAnalysis, analyze_site_storage, default_installations,
};
use sweepx_core::{CancellationToken, CoreContext, OutputFormat};
use sweepx_i18n::Locale;
use sweepx_model::HumanSizeUnit;

#[allow(clippy::too_many_arguments)]
pub(crate) fn run(
    context: &CoreContext,
    format: OutputFormat,
    unit: HumanSizeUnit,
    browser: Option<&str>,
    profile: Option<&str>,
    domain: Option<&str>,
    legacy_mutation: bool,
    export_delete_plan: Option<&std::path::Path>,
) -> ExitCode {
    if legacy_mutation {
        // An exclusive Windows LOCK open never proved all browser clients were stopped, and
        // opening LOCK on Unix did not test advisory locks at all. Modern buckets additionally
        // depend on a shared, live QuotaManager mapping. Refuse before discovery or mutation.
        eprintln!(
            "{}",
            match context.locale() {
                Locale::ZhCn =>
                    "站点数据删除与通用目录浏览暂不可用：尚不能验证浏览器已停止，以及存储键和 bucket 的当前映射。请用 --domain 查看具体条目；未做任何改动。",
                Locale::EnUs =>
                    "Site deletion and generic directory browsing are unavailable until browser inactivity and current key/bucket mappings can be verified. Use --domain to review items; nothing was changed.",
            }
        );
        return ExitCode::from(3);
    }
    let mut installations = default_installations();
    if let Some(browser) = browser {
        installations.retain(|i| i.browser.eq_ignore_ascii_case(browser));
        if installations.is_empty() {
            eprintln!("unknown browser label: {browser}");
            return ExitCode::from(2);
        }
    }
    let analysis = analyze_site_storage(&installations, profile, &CancellationToken::new());
    if let Some(path) = export_delete_plan {
        let result = (|| {
            let plan = sweepx_core::browser_storage::cleanup_plan(
                &analysis,
                browser.ok_or("browser_required")?,
                profile.ok_or("profile_required")?,
                domain.ok_or("domain_required")?,
            )?;
            if !path.is_absolute() {
                return Err("plan_path_must_be_absolute".to_string());
            }
            let bytes = serde_json::to_vec_pretty(&plan).map_err(|e| e.to_string())?;
            // Only a fresh user-selected file is created; no overwrite or followed final symlink.
            // Export is never deletion authority: the browser adapter revalidates the selection.
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(path)
                .map_err(|e| e.to_string())?;
            use std::io::Write;
            file.write_all(&bytes).map_err(|e| e.to_string())?;
            Ok::<_, String>(plan)
        })();
        match result {
            Ok(plan) => {
                println!(
                    "{}",
                    json!({"schema":"sweepx.browser_cleanup.export/v1","readOnly":true,"plan":plan,"path":path,"applied":false})
                );
                return ExitCode::SUCCESS;
            }
            Err(e) => {
                eprintln!("{e}");
                return ExitCode::from(3);
            }
        }
    }
    let output = render_json(&analysis, domain);
    if format != OutputFormat::Human {
        println!("{output}");
    } else {
        let zh = context.locale() == Locale::ZhCn;
        println!(
            "{}",
            if zh {
                "域名汇总（逻辑大小；网站数据不自动视为垃圾）："
            } else {
                "Domains (logical size; site data is not automatically junk):"
            }
        );
        for row in output["domains"].as_array().into_iter().flatten() {
            println!(
                "  {:>12}  {}  ({} {})",
                size_label(
                    row["bytes"].as_str(),
                    row["sizeComplete"].as_bool() == Some(true),
                    unit
                ),
                row["domain"].as_str().unwrap_or("?"),
                row["storageItemCount"],
                if zh {
                    "个存储条目"
                } else {
                    "storage items"
                }
            );
        }
        for report in &analysis.profiles {
            if domain.is_some()
                && !report
                    .origins
                    .iter()
                    .any(|r| matches_domain(&r.domain, domain))
            {
                continue;
            }
            println!(
                "{} / {}: {}; {} {}",
                report.profile,
                report.subsystem,
                size_label(
                    report.subsystem_bytes.as_deref(),
                    report.size_complete,
                    unit
                ),
                if zh { "未归因" } else { "unattributed" },
                size_label(
                    report.unattributed_bytes.as_deref(),
                    report.size_complete,
                    unit
                )
            );
            for usage in report
                .origins
                .iter()
                .filter(|r| matches_domain(&r.domain, domain))
            {
                println!(
                    "  {:>12} {}{}",
                    size_label(usage.bytes.as_deref(), usage.complete, unit),
                    usage.storage_key,
                    usage
                        .bucket_id
                        .map(|id| format!(
                            " [bucket {id}, {}]",
                            usage.bucket_name.as_deref().unwrap_or("?")
                        ))
                        .unwrap_or_default()
                );
                if domain.is_some() {
                    for path in &usage.directories {
                        println!("    {}", path.display());
                    }
                }
            }
            for issue in &report.issues {
                eprintln!("{}: {issue}", report.profile);
            }
        }
        for issue in &analysis.issues {
            eprintln!("{issue}");
        }
        println!(
            "{}",
            if zh {
                "仅为报告。共享数据库和 HTTP 缓存不能在此按域名精确归因；文件观察不是跨数据库的一致快照。"
            } else {
                "Report only. Shared databases and HTTP cache cannot be attributed precisely by domain here; observations are not an atomic cross-database snapshot."
            }
        );
    }
    ExitCode::from(if analysis.complete { 0 } else { 4 })
}

fn matches_domain(actual: &str, filter: Option<&str>) -> bool {
    filter.is_none_or(|domain| actual.eq_ignore_ascii_case(domain))
}

fn size_label(value: Option<&str>, complete: bool, unit: HumanSizeUnit) -> String {
    match value.and_then(|b| b.parse::<u128>().ok()) {
        Some(bytes) if complete => unit.format(bytes),
        Some(bytes) => format!(">= {}", unit.format(bytes)),
        None => "?".into(),
    }
}

fn render_json(analysis: &BrowserStorageAnalysis, domain: Option<&str>) -> serde_json::Value {
    let mut domains = BTreeMap::<String, (Option<u128>, usize, bool)>::new();
    for report in &analysis.profiles {
        for row in report
            .origins
            .iter()
            .filter(|r| matches_domain(&r.domain, domain))
        {
            let group = domains
                .entry(row.domain.clone())
                .or_insert((Some(0), 0, true));
            group.0 = group
                .0
                .zip(row.bytes.as_ref().and_then(|b| b.parse::<u128>().ok()))
                .and_then(|(a, b)| a.checked_add(b));
            group.1 += 1;
            group.2 &= row.complete;
        }
    }
    let mut domains: Vec<_> = domains.into_iter().map(|(domain, (bytes, count, complete))|
        json!({"domain": domain, "bytes": bytes.map(|b| b.to_string()), "storageItemCount": count, "sizeComplete": complete,
            "selectionIsExecutionAuthority": false})).collect();
    domains.sort_by_key(|r| {
        std::cmp::Reverse(
            r["bytes"]
                .as_str()
                .and_then(|b| b.parse::<u128>().ok())
                .unwrap_or(0),
        )
    });
    let profiles: Vec<_> = analysis
        .profiles
        .iter()
        .map(|r| {
            let mut value =
                serde_json::to_value(r).expect("site reports contain serializable values");
            value["origins"]
                .as_array_mut()
                .expect("origin array")
                .retain(|r| {
                    r["domain"]
                        .as_str()
                        .is_some_and(|name| matches_domain(name, domain))
                });
            value
        })
        .collect();
    json!({"schema": "sweepx.site_storage.result/v1", "readOnly": true,
        "status": if analysis.complete { "ok" } else { "partial" }, "profiles": profiles,
        "domains": domains, "issues": analysis.issues, "domainFilter": domain,
        "totalsScope": "entire_reported_subsystem_before_domain_filter",
        "discoveryScope": "default_installations_default_storage_partition",
        "sizeKind": "logical", "removalSupported": false})
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn domain_filter_is_exact_and_case_insensitive() {
        assert!(matches_domain("example.com", Some("EXAMPLE.COM")));
        assert!(!matches_domain("sub.example.com", Some("example.com")));
        assert!(!matches_domain(
            "example.com.evil.test",
            Some("example.com")
        ));
    }
}
