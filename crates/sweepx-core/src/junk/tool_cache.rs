//! Typed tool-cache layouts use this traversal's native observations, independently of a tool
//! executable. npm log cleanup additionally verifies every direct file; npx/pnpm retain their
//! separate installation/link/reference inventories and cannot become blanket-root Trash.

use super::candidate::{JunkCandidate, JunkExecutionPolicy};
use super::platform::PlatformJunkRule;
use crate::CancellationToken;
use crate::managed_cache::native::Native;
use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet};
use sweepx_model::{NativeName, ObjectType, ScanEntryId, ScannedEntry};

type Files = BTreeMap<ScanEntryId, BTreeSet<String>>;
type Directories = BTreeMap<ScanEntryId, BTreeMap<String, ScanEntryId>>;

fn includes(rules: &[PlatformJunkRule], kinds: &[&str]) -> bool {
    rules
        .iter()
        .any(|rule| kinds.contains(&rule.root_kind.as_str()))
}
fn marker_name(name: &NativeName) -> Option<Cow<'_, str>> {
    match name {
        NativeName::UnixBytes(bytes) => std::str::from_utf8(bytes).ok().map(Cow::Borrowed),
        NativeName::WindowsUtf16(units) => String::from_utf16(units)
            .ok()
            .map(|s| Cow::Owned(s.to_ascii_lowercase())),
    }
}
fn parent_name(entry: &ScannedEntry) -> Option<Cow<'_, str>> {
    let locator = entry.native_locator.as_ref()?;
    if let Some(parent) = locator.parent_reopen_recipe.last() {
        return marker_name(&parent.native_basename);
    }
    // Only a selected scan root needs decoding beyond its stored relative lineage.
    super::git::native_path(entry)?
        .parent()?
        .file_name()?
        .to_str()
        .map(|s| Cow::Owned(super::normalize_rule_name(s)))
}
pub(super) fn needs_file_marker(rules: &[PlatformJunkRule], name: &NativeName) -> bool {
    let Some(name) = marker_name(name) else {
        return false;
    };
    if matches!(name.as_ref(), "package.json" | "package-lock.json") {
        return includes(rules, &["npm_npx"]);
    }
    // Most payload filenames do not allocate or walk the rule list on the hot file-length path.
    name.len() <= 64
        && name.ends_with(".log")
        && log_name(&name).is_some()
        && includes(rules, &["npm_logs"])
        || name.len() <= 64
            && name.ends_with("-timing.json")
            && log_name(&name).is_some()
            && includes(rules, &["npm_logs"])
        || name.len() <= 64
            && name.ends_with("-eresolve-report.txt")
            && log_name(&name).is_some()
            && includes(rules, &["npm_logs"])
}
pub(super) fn needs_directory_marker(rules: &[PlatformJunkRule], name: &NativeName) -> bool {
    let Some(name) = marker_name(name) else {
        return false;
    };
    (matches!(
        name.as_ref(),
        "_cacache" | "_npx" | "content-v2" | "index-v5" | "node_modules"
    ) && includes(
        rules,
        &["npm_reported_cache", "npm_logs", "npm_npx", "npm_other"],
    )) || (matches!(name.as_ref(), "wheels" | "http" | "http-v2")
        && includes(rules, &["pip_reported_cache"]))
        || (shard(&name) && includes(rules, &["pnpm_reported_store"]))
}
fn shard(name: &str) -> bool {
    name.len() == 2
        && name
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

pub(super) fn classifies(
    rule: &PlatformJunkRule,
    entry: &ScannedEntry,
    files: &Files,
    directories: &Directories,
) -> bool {
    if !matches!(
        rule.root_kind.as_str(),
        "npm_reported_cache"
            | "npm_logs"
            | "npm_npx"
            | "npm_other"
            | "pip_reported_cache"
            | "pnpm_reported_store"
    ) || entry.object_type != ObjectType::Directory
    {
        return false;
    }
    let Some(identity) = &entry.identity else {
        return false;
    };
    let Some(name) = marker_name(&entry.native_basename) else {
        return false;
    };
    let own = directories.get(&identity.entry_id);
    let has = |name: &str| own.is_some_and(|set| set.contains_key(name));
    match rule.root_kind.as_str() {
        "npm_reported_cache" => name == "_cacache" && has("content-v2") && has("index-v5"),
        "pip_reported_cache" => has("wheels") && (has("http-v2") || has("http")),
        "pnpm_reported_store" => {
            // A deep-discovered CAS payload is review-only. Its owning store still needs the
            // existing pnpm index/project/hard-link inventory before any selected retirement.
            name == "files"
                && parent_name(entry).is_some_and(|parent| {
                    parent
                        .strip_prefix('v')
                        .is_some_and(|v| !v.is_empty() && v.bytes().all(|b| b.is_ascii_digit()))
                })
                && own.is_some_and(|set| set.len() == 256 && set.keys().all(|key| shard(key)))
        }
        "npm_logs" => {
            let context = identity
                .parent_id
                .as_ref()
                .and_then(|id| directories.get(id))
                .is_some_and(|set| set.contains_key("_cacache") || set.contains_key("_npx"))
                || parent_name(entry).is_some_and(|parent| parent == ".npm");
            name == "_logs"
                && context
                && files
                    .get(&identity.entry_id)
                    .is_some_and(|set| set.iter().any(|name| log_name(name).is_some()))
        }
        "npm_other" => {
            !matches!(name.as_ref(), "_cacache" | "_logs" | "_npx")
                && (parent_name(entry).is_some_and(|parent| parent == ".npm")
                    || identity
                        .parent_id
                        .as_ref()
                        .and_then(|id| directories.get(id))
                        .is_some_and(|set| set.contains_key("_cacache")))
        }
        "npm_npx" => {
            name.len() == 16
                && name.bytes().all(|b| b.is_ascii_hexdigit())
                && parent_name(entry).is_some_and(|parent| parent == "_npx")
                && has("node_modules")
                && files.get(&identity.entry_id).is_some_and(|set| {
                    set.contains("package.json") && set.contains("package-lock.json")
                })
        }
        _ => false,
    }
}

// npm uses ISO timestamps with ':' and '.' replaced by '_'. Filename evidence only discovers
// a report row; log content and all sibling types/names still need independent native checks.
#[derive(Clone, Copy, PartialEq, Eq)]
enum LogKind {
    Initial,
    Rotation,
    Timing,
    Resolution,
}
fn log_name(name: &str) -> Option<(&str, LogKind)> {
    let (stamp, suffix) = name.split_at_checked(24)?;
    if !stamp.bytes().enumerate().all(|(i, b)| match i {
        4 | 7 => b == b'-',
        10 => matches!(b, b'T' | b't'),
        13 | 16 | 19 => b == b'_',
        23 => matches!(b, b'Z' | b'z'),
        _ => b.is_ascii_digit(),
    }) {
        return None;
    }
    let kind = if matches!(suffix, "-debug.log" | "-debug-0.log") {
        LogKind::Initial
    } else if suffix == "-timing.json" {
        LogKind::Timing
    } else if suffix == "-eresolve-report.txt" {
        LogKind::Resolution
    } else if suffix
        .strip_prefix("-debug-")
        .and_then(|s| s.strip_suffix(".log"))
        .is_some_and(|n| !n.is_empty() && n.len() <= 6 && n.bytes().all(|b| b.is_ascii_digit()))
    {
        LogKind::Rotation
    } else {
        return None;
    };
    Some((stamp, kind))
}
fn npm_header(bytes: &[u8]) -> bool {
    let line = |kind: &str, prefix: &str| {
        bytes
            .split(|b| *b == b'\n')
            .filter_map(|s| std::str::from_utf8(s).ok())
            .any(|line| {
                let mut parts = line.splitn(3, ' ');
                parts
                    .next()
                    .is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
                    && parts.next() == Some(kind)
                    && parts.next().is_some_and(|s| s.starts_with(prefix))
            })
    };
    line("info", "using npm@") && (line("verbose", "cli ") || line("info", "using node@"))
}

/// Per-invocation log verification budget. Native reads stay on the worker; they never retain
/// log contents or expose them in diagnostics. Limits apply cumulatively, including failures.
pub struct ToolLayoutSession {
    cancel: CancellationToken,
    remaining_files: usize,
    remaining_bytes: usize,
}
impl ToolLayoutSession {
    /// Starts independent content checks; no npm/pnpm executable or historical activity is used.
    pub fn new(cancel: CancellationToken) -> Self {
        Self {
            cancel,
            remaining_files: 2048,
            remaining_bytes: 8 * 1024 * 1024,
        }
    }
    /// Verifies npm log candidates from the loaded catalog. A failure preserves a report row and
    /// blocks automatic directory cleanup; an unrelated tool-query failure never enters this path.
    pub fn refresh(&mut self, candidate: &mut JunkCandidate, rules: &[PlatformJunkRule]) {
        if !rules
            .iter()
            .any(|rule| rule.id == candidate.rule_id && rule.root_kind == "npm_logs")
        {
            return;
        }
        candidate.execution_policy = JunkExecutionPolicy::ReportOnly;
        candidate
            .blockers
            .retain(|code| !code.starts_with("npm_logs_"));
        match candidate
            .source_entry
            .as_ref()
            .ok_or_else(|| "npm_logs_native_source_missing".to_owned())
            .and_then(|source| self.verify_logs(source))
        {
            Ok(()) => candidate.execution_policy = JunkExecutionPolicy::NativeRevalidationRequired,
            Err(reason) => candidate.blockers.push(reason),
        }
    }
    fn verify_logs(&mut self, source: &ScannedEntry) -> Result<(), String> {
        let fail = |reason: &str| format!("npm_logs_{reason}");
        if self.cancel.is_cancelled() {
            return Err(fail("cancelled"));
        }
        let mut native = Native::new(&self.cancel);
        let rows = native
            .children_bounded(source, 1024, 16 * 1024 * 1024)
            .map_err(|_| fail("enumeration_unavailable"))?;
        let mut initial = BTreeSet::new();
        let mut rotations = Vec::new();
        for row in &rows {
            let Some(name) = super::native_rule_name(&row.native_basename) else {
                return Err(fail("unknown_entry"));
            };
            // Finder creates this ordinary metadata file; a linked/non-file object is still refused.
            if name == super::normalize_rule_name(".DS_Store")
                && row.object_type == ObjectType::File
            {
                continue;
            }
            if row.object_type != ObjectType::File {
                return Err(fail("non_log_entry"));
            }
            let Some((stamp, kind)) = log_name(&name) else {
                return Err(fail("unrecognized_name"));
            };
            let requested = if kind == LogKind::Timing {
                64 * 1024
            } else {
                4096
            };
            if self.remaining_files == 0 || self.remaining_bytes < requested {
                return Err(fail("verification_limit"));
            }
            self.remaining_files -= 1;
            self.remaining_bytes -= requested;
            if kind == LogKind::Timing {
                let length = match &row.logical_bytes {
                    sweepx_model::EvidenceValue::Known { value } => usize::try_from(value.0)
                        .ok()
                        .filter(|length| *length <= requested)
                        .ok_or_else(|| fail("timing_too_large"))?,
                    _ => return Err(fail("timing_length_unknown")),
                };
                let bytes = native
                    .read_prefix(row, requested)
                    .map_err(|_| fail("timing_unavailable"))?;
                if bytes.len() != length {
                    return Err(fail("timing_changed"));
                }
                let value: serde_json::Value =
                    serde_json::from_slice(&bytes).map_err(|_| fail("invalid_timing"))?;
                if !value["metadata"].is_object()
                    || !value["metadata"]["version"].is_string()
                    || !value["timers"].is_object()
                    || !value["timers"]["npm"].is_u64()
                    || !value["unfinishedTimers"].is_object()
                {
                    return Err(fail("unrecognized_timing"));
                }
                continue;
            }
            let bytes = native
                .read_prefix(row, 4096)
                .map_err(|_| fail("file_unavailable"))?;
            if kind == LogKind::Resolution {
                let contains = |value: &[u8]| bytes.windows(value.len()).any(|part| part == value);
                // npm wraps the generated report with its debug-log paths. Paths are just
                // diagnostic text here; none are reopened or used as execution authority.
                let header = bytes.starts_with(b"# npm resolution error report\n")
                    || bytes.starts_with(b"'Log files:\n")
                        && contains(b"\n\n# npm resolution error report\n");
                let explanation = contains(b"\nWhile resolving:")
                    || contains(b"\nFound:")
                    || contains(b"\nCould not resolve dependency:");
                if !header || !explanation {
                    return Err(fail("unrecognized_resolution_report"));
                }
            } else if kind == LogKind::Initial {
                if !npm_header(&bytes) {
                    return Err(fail("unrecognized_header"));
                }
                initial.insert(stamp.to_owned());
            } else {
                let framed =
                    bytes
                        .split(|b| *b == b'\n')
                        .filter_map(|s| std::str::from_utf8(s).ok())
                        .any(|line| {
                            let mut parts = line.splitn(3, ' ');
                            parts.next().is_some_and(|n| {
                                !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit())
                            }) && parts.next().is_some_and(|level| {
                                matches!(
                                    level,
                                    "silly"
                                        | "verbose"
                                        | "info"
                                        | "warn"
                                        | "error"
                                        | "http"
                                        | "timing"
                                )
                            }) && parts.next().is_some_and(|content| !content.is_empty())
                        });
                if !framed {
                    return Err(fail("unrecognized_rotation"));
                }
                rotations.push(stamp.to_owned());
            }
        }
        if rotations.iter().any(|stamp| !initial.contains(stamp)) {
            return Err(fail("rotation_without_header"));
        }
        // Empty directories are allowed only when native discovery/classification already bound
        // their npm cache context; arbitrary directories cannot manufacture a rule match here.
        unchanged_directory(&mut native, source, &rows)
    }
}

fn unchanged_directory(
    native: &mut Native<'_>,
    source: &ScannedEntry,
    before: &[ScannedEntry],
) -> Result<(), String> {
    // Scanner fingerprints bind native identity/type/length, not directory change times.
    // Compare another bounded native listing; an identity-only reopen cannot detect new notes.
    let expected = before
        .iter()
        .map(|row| (&row.native_basename, row))
        .collect::<std::collections::HashMap<_, _>>();
    let after = native
        .children_bounded(source, 1024, 16 * 1024 * 1024)
        .map_err(|_| "npm_logs_directory_changed")?;
    if expected.len() != before.len()
        || after.len() != before.len()
        || after.iter().any(|row| {
            !expected.get(&row.native_basename).is_some_and(|before| {
                before.object_type == row.object_type
                    && before.metadata_fingerprint == row.metadata_fingerprint
            })
        })
    {
        return Err("npm_logs_directory_changed".into());
    }
    Ok(())
}

/// Independent guard immediately before Trash, shared by bulk and interactive cleanup.
/// Other tool families retain their existing execution policy and dedicated inventory guards.
pub fn revalidate_for_trash(
    rule_id: &str,
    source: &ScannedEntry,
    cancel: &CancellationToken,
) -> Result<(), String> {
    let rules =
        super::platform::load_platform_junk_rules().map_err(|_| "tool_rules_unavailable")?;
    if rules
        .iter()
        .any(|rule| rule.id == rule_id && rule.root_kind == "npm_logs")
    {
        ToolLayoutSession::new(cancel.clone()).verify_logs(source)?;
        let path = super::git::native_path(source)
            .ok_or_else(|| "npm_logs_native_path_unavailable".to_owned())?;
        crate::tools::scoped_activity::check_scopes(&[&path], cancel)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::{JunkService, platform::PlatformJunkEvidence};
    use super::*;
    use std::fs;
    use std::path::{Path, PathBuf};
    use sweepx_scanner::{HostPlatformScanner, Scanner, ScannerOptions};

    fn fixture() -> (tempfile::TempDir, PathBuf) {
        #[cfg(target_os = "linux")]
        let temp = tempfile::tempdir_in("/dev/shm").unwrap();
        #[cfg(not(target_os = "linux"))]
        let temp = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        let root = temp.path().canonicalize().unwrap();
        #[cfg(windows)]
        let root = temp.path().to_path_buf();
        (temp, root)
    }
    fn log(root: &Path) -> PathBuf {
        let logs = root.join("archive/.npm/_logs");
        fs::create_dir_all(&logs).unwrap();
        fs::write(
            logs.join("2026-10-21T01_02_03_004Z-debug-0.log"),
            b"0 verbose cli /node /npm\n1 info using npm@11.0.0\n2 info using node@v24.0.0\n",
        )
        .unwrap();
        logs
    }
    fn scan(
        root: &Path,
    ) -> (
        Vec<JunkCandidate>,
        Vec<PlatformJunkRule>,
        sweepx_scanner::ClassifiedScan,
    ) {
        let rules = super::super::platform::select_platform_rules(&[
            "tool.npm-cache".into(),
            "tool.npm-logs".into(),
            "tool.npm-npx".into(),
            "tool.npm-other-data".into(),
            "tool.pip-cache".into(),
            "tool.pnpm-store".into(),
        ])
        .unwrap();
        let service = JunkService::built_in().unwrap();
        let evidence = PlatformJunkEvidence::default();
        let scanned = Scanner::new(
            HostPlatformScanner::new(),
            ScannerOptions {
                // Tool-cache fixtures interpret native markers and totals, not previews.
                accelerated_preview: false,
                retain_directory_index: false,
                ..ScannerOptions::default()
            },
        )
        .scan_classified(
            &[sweepx_platform::ScanRoot::new(root.to_path_buf()).unwrap()],
            &CancellationToken::new(),
            &service.with_platform(&rules, &evidence),
            None,
        )
        .unwrap();
        let aggregates = scanned
            .summary
            .aggregates
            .iter()
            .map(|a| (a.directory_identity.as_str(), a))
            .collect();
        let rows = scanned
            .summary
            .entries
            .iter()
            .chain(&scanned.summary.roots)
            .filter_map(|entry| {
                let decision = scanned.decisions.get(&entry.identity.as_ref()?.entry_id)?;
                service.interpret(decision, entry, &aggregates, &rules, &evidence)
            })
            .collect();
        (rows, rules, scanned)
    }
    fn total(path: &Path) -> u128 {
        fs::read_dir(path)
            .unwrap()
            .map(|entry| {
                let path = entry.unwrap().path();
                let meta = fs::symlink_metadata(&path).unwrap();
                if meta.is_dir() {
                    total(&path)
                } else if meta.is_file() {
                    u128::from(meta.len())
                } else {
                    0
                }
            })
            .sum()
    }
    #[test]
    fn offline_old_locations_split_downloads_logs_npx_and_unknown_data_with_native_totals() {
        let (_temp, root) = fixture();
        let logs = log(&root);
        let cache = root.join("archive/.npm/_cacache");
        fs::create_dir_all(cache.join("content-v2")).unwrap();
        fs::create_dir(cache.join("index-v5")).unwrap();
        fs::write(
            cache.join("content-v2/payload"),
            b"independent cached bytes",
        )
        .unwrap();
        let slot = root.join("archive/.npm/_npx/0123456789abcdef");
        fs::create_dir_all(slot.join("node_modules/tool")).unwrap();
        fs::write(
            slot.join("package.json"),
            br#"{"dependencies":{"tool":"1.0.0"}}"#,
        )
        .unwrap();
        fs::write(slot.join("package-lock.json"), b"{}").unwrap();
        fs::write(
            slot.join("node_modules/tool/package.json"),
            br#"{"name":"tool","version":"1.0.0"}"#,
        )
        .unwrap();
        let unknown = root.join("archive/.npm/old-binary-downloads");
        fs::create_dir(&unknown).unwrap();
        fs::write(
            unknown.join("personal-notes"),
            b"retain until explicit review",
        )
        .unwrap();
        // A same-named ordinary file cannot satisfy a directory-format marker.
        let lookalike = root.join("lookalike/_cacache");
        fs::create_dir_all(lookalike.join("content-v2")).unwrap();
        fs::write(lookalike.join("index-v5"), b"file, not a directory").unwrap();
        let (mut rows, rules, scanned) = scan(&root);
        assert!(
            scanned.directory_markers.is_empty(),
            "completed local markers must be released"
        );
        let mut verification = ToolLayoutSession::new(CancellationToken::new());
        for row in &mut rows {
            verification.refresh(row, &rules);
        }
        for (path, rule) in [
            (&cache, "tool.npm-cache"),
            (&logs, "tool.npm-logs"),
            (&slot, "tool.npm-npx"),
            (&unknown, "tool.npm-other-data"),
        ] {
            let row = rows
                .iter()
                .find(|row| row.rule_id == rule && row.path == path.to_string_lossy())
                .unwrap_or_else(|| {
                    panic!(
                        "missing {} at {:?}; rows={:?}",
                        rule,
                        path,
                        rows.iter()
                            .map(|r| (&r.rule_id, &r.path))
                            .collect::<Vec<_>>()
                    )
                });
            let aggregate = scanned
                .summary
                .aggregates
                .iter()
                .find(|a| a.directory_identity == row.entry_id.as_str())
                .unwrap();
            assert_eq!(
                aggregate.apparent_logical_bytes,
                sweepx_platform::known_u128(total(path))
            );
            if rule == "tool.npm-logs" {
                assert_eq!(
                    row.execution_policy,
                    JunkExecutionPolicy::NativeRevalidationRequired,
                    "{:?}",
                    row.blockers
                );
            }
            if rule == "tool.npm-npx" {
                assert_eq!(
                    row.execution_policy,
                    JunkExecutionPolicy::RequireUserDataSelection
                );
            }
            if rule == "tool.npm-other-data" {
                assert_eq!(row.execution_policy, JunkExecutionPolicy::ReportOnly);
            }
        }
        assert!(!rows.iter().any(|r| r.path == lookalike.to_string_lossy()));
        // Reuse the existing version parser, independently of npm availability.
        let inventory = crate::npx::inventory(slot.parent().unwrap(), &CancellationToken::new());
        assert!(inventory.complete, "{:?}", inventory.issues);
        assert_eq!(
            inventory.entries[0].packages[0].version.as_deref(),
            Some("1.0.0")
        );
    }
    #[test]
    fn log_verification_preserves_mixed_contents_and_checks_again_before_trash() {
        let (_temp, root) = fixture();
        let logs = log(&root);
        let cancel = CancellationToken::new();
        let mut native = Native::new(&cancel);
        let directory = native.root(&logs).unwrap();
        let before = native
            .children_bounded(&directory, 1024, 16 * 1024 * 1024)
            .unwrap();
        fs::write(logs.join("notes.txt"), b"personal data").unwrap();
        assert!(
            unchanged_directory(&mut native, &directory, &before).is_err(),
            "identity alone cannot certify an unchanged directory listing"
        );
        let (mut rows, rules, _) = scan(&root);
        let row = rows
            .iter_mut()
            .find(|r| r.rule_id == "tool.npm-logs")
            .unwrap();
        ToolLayoutSession::new(CancellationToken::new()).refresh(row, &rules);
        assert_eq!(row.execution_policy, JunkExecutionPolicy::ReportOnly);
        assert!(
            revalidate_for_trash(
                &row.rule_id,
                row.source_entry.as_ref().unwrap(),
                &CancellationToken::new()
            )
            .is_err()
        );
        assert_eq!(fs::read(logs.join("notes.txt")).unwrap(), b"personal data");
        fs::remove_file(logs.join("notes.txt")).unwrap();
        let (mut rows, rules, _) = scan(&root);
        let row = rows
            .iter_mut()
            .find(|r| r.rule_id == "tool.npm-logs")
            .unwrap();
        ToolLayoutSession::new(CancellationToken::new()).refresh(row, &rules);
        assert_eq!(
            row.execution_policy,
            JunkExecutionPolicy::NativeRevalidationRequired
        );
        fs::write(
            logs.join("2026-10-21T01_02_03_004Z-debug-0.log"),
            b"unexplained changed content",
        )
        .unwrap();
        assert!(
            revalidate_for_trash(
                &row.rule_id,
                row.source_entry.as_ref().unwrap(),
                &CancellationToken::new()
            )
            .is_err()
        );
        let cancelled = CancellationToken::new();
        cancelled.cancel();
        assert!(
            revalidate_for_trash(&row.rule_id, row.source_entry.as_ref().unwrap(), &cancelled)
                .is_err()
        );
    }
    #[test]
    fn log_verification_accepts_large_debug_prefixes_rotations_and_complete_timing_metadata() {
        let (_temp, root) = fixture();
        let logs = log(&root);
        let initial = logs.join("2026-10-21T01_02_03_004Z-debug-0.log");
        let mut debug = fs::read(&initial).unwrap();
        debug.extend_from_slice(&vec![b'x'; 100_000]);
        fs::write(&initial, debug).unwrap();
        fs::write(
            logs.join("2026-10-21T01_02_03_004Z-debug-1.log"),
            b"103 verbose continuing npm output\n",
        )
        .unwrap();
        fs::write(
            logs.join("2026-10-21T01_02_03_004Z-eresolve-report.txt"),
            b"'Log files:\n/diagnostic-only/debug-0.log\n\n# npm resolution error report\n\nWhile resolving: example@1.0.0\n",
        )
        .unwrap();
        let timing = logs.join("2026-10-21T01_02_03_004Z-timing.json");
        fs::write(
            &timing,
            br#"{"metadata":{"version":"11.0.0"},"timers":{"npm":42},"unfinishedTimers":{}}"#,
        )
        .unwrap();
        let (rows, _, _) = scan(&root);
        let source = rows
            .iter()
            .find(|row| row.rule_id == "tool.npm-logs")
            .unwrap()
            .source_entry
            .as_ref()
            .unwrap();
        ToolLayoutSession::new(CancellationToken::new())
            .verify_logs(source)
            .unwrap();
        let resolution = logs.join("2026-10-21T01_02_03_004Z-eresolve-report.txt");
        let original = fs::read(&resolution).unwrap();
        fs::write(&resolution, b"personal notes using a log-looking filename").unwrap();
        let (rows, _, _) = scan(&root);
        let source = rows
            .iter()
            .find(|row| row.rule_id == "tool.npm-logs")
            .unwrap()
            .source_entry
            .as_ref()
            .unwrap();
        assert!(
            ToolLayoutSession::new(CancellationToken::new())
                .verify_logs(source)
                .unwrap_err()
                .contains("unrecognized_resolution_report")
        );
        fs::write(resolution, original).unwrap();
        fs::write(&timing, br#"{"personal":"not npm timing metadata"}"#).unwrap();
        let (rows, _, _) = scan(&root);
        let source = rows
            .iter()
            .find(|row| row.rule_id == "tool.npm-logs")
            .unwrap()
            .source_entry
            .as_ref()
            .unwrap();
        assert!(
            ToolLayoutSession::new(CancellationToken::new())
                .verify_logs(source)
                .is_err()
        );
        fs::remove_file(&timing).unwrap();
        fs::remove_file(&initial).unwrap();
        let (rows, _, _) = scan(&root);
        let source = rows
            .iter()
            .find(|row| row.rule_id == "tool.npm-logs")
            .unwrap()
            .source_entry
            .as_ref()
            .unwrap();
        assert!(
            ToolLayoutSession::new(CancellationToken::new())
                .verify_logs(source)
                .unwrap_err()
                .contains("rotation_without_header")
        );
    }

    #[cfg(unix)]
    #[test]
    fn linked_layout_markers_never_identify_a_download_cache_or_npx_slot() {
        use std::os::unix::fs::symlink;
        let (_temp, root) = fixture();
        fs::create_dir(root.join("real")).unwrap();
        let cache = root.join("custom/_cacache");
        fs::create_dir_all(cache.join("index-v5")).unwrap();
        symlink(root.join("real"), cache.join("content-v2")).unwrap();
        let slot = root.join("custom/_npx/0123456789abcdef");
        fs::create_dir_all(&slot).unwrap();
        fs::write(slot.join("package.json"), b"{}").unwrap();
        fs::write(slot.join("package-lock.json"), b"{}").unwrap();
        symlink(root.join("real"), slot.join("node_modules")).unwrap();
        let (rows, _, _) = scan(&root);
        assert!(
            !rows
                .iter()
                .any(|r| r.rule_id == "tool.npm-cache" || r.rule_id == "tool.npm-npx")
        );
    }
}
