//! Bounded, invocation-time process references for explicitly selected cache installations.
//! These are observations, not an exclusive lock: another process can start after a check.
#[cfg(any(target_os = "macos", target_os = "linux"))]
use super::{ProbeLimits, ProbeRunner};
use crate::CancellationToken;
use std::path::Path;
#[cfg(any(target_os = "macos", target_os = "linux"))]
use std::time::Duration;

/// Refuses known process references or unavailable host observations. Supported on macOS/Linux
/// for the current user's processes; callers must revalidate files and perform recoverable actions.
/// Checks are not a cross-user audit or a guarantee against a concurrent process launch.
pub fn check_scopes(scopes: &[&Path], cancel: &CancellationToken) -> Result<(), String> {
    if scopes.is_empty() || scopes.len() > 1024 {
        return Err("activity_scope_limit".into());
    }
    let strings: Vec<_> = scopes
        .iter()
        .map(|p| {
            p.to_str()
                .filter(|p| p.starts_with('/') && !p.contains(['\n', '\r', '\0', '\\']))
                .ok_or("activity_path_unavailable")
        })
        .collect::<Result<_, _>>()?;
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    {
        use std::process::Command;
        // SAFETY: getuid reads the calling process's identity and has no preconditions.
        let uid = unsafe { libc::getuid() }.to_string();
        let mut runner = ProbeRunner::new(
            ProbeLimits {
                total_timeout: Duration::from_secs(15),
                probe_timeout: Duration::from_secs(7),
                max_processes: 2,
                max_stdout_bytes: 8 * 1024 * 1024,
            },
            cancel.clone(),
        );
        let output = runner
            .run(Command::new("/bin/ps").args(["-u", &uid, "-o", "pid=,command="]))
            .map_err(|e| format!("activity_unavailable: {e}"))?;
        if !output.status.success() {
            return Err("activity_process_list_failed".into());
        }
        let text =
            std::str::from_utf8(&output.stdout).map_err(|_| "activity_encoding_unavailable")?;
        check_commands(text, &strings, std::process::id())?;
        #[cfg(target_os = "macos")]
        let lsof = "/usr/sbin/lsof";
        #[cfg(target_os = "linux")]
        let lsof = "/usr/bin/lsof";
        let output = runner
            .run(Command::new(lsof).args(["-nP", "-a", "-u", &uid, "-F", "pn"]))
            .map_err(|e| format!("activity_unavailable: {e}"))?;
        if !output.status.success() {
            return Err("activity_open_file_list_failed".into());
        }
        let text =
            std::str::from_utf8(&output.stdout).map_err(|_| "activity_encoding_unavailable")?;
        check_open_files(text, &strings, std::process::id())
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = (strings, cancel);
        Err("activity_host_unsupported".into())
    }
}
#[cfg(any(target_os = "macos", target_os = "linux", test))]
fn reference(text: &str, scope: &str) -> bool {
    text.match_indices(scope).any(|(i, _)| {
        let before = &text[..i];
        let after = &text[i + scope.len()..];
        (before.is_empty() || before.ends_with([' ', '\t', '"', '\'']))
            && (after.is_empty() || after.starts_with(['/', ' ', '\t', '"', '\'']))
    })
}
#[cfg(any(target_os = "macos", target_os = "linux", test))]
fn check_commands(text: &str, scopes: &[&str], own: u32) -> Result<(), String> {
    let mut count = 0;
    for line in text.lines().filter(|s| !s.trim().is_empty()) {
        count += 1;
        if count > 16384 {
            return Err("activity_process_limit".into());
        }
        let line = line.trim_start();
        let (pid, args) = line
            .split_once(char::is_whitespace)
            .ok_or("activity_invalid_process_record")?;
        let pid = pid.parse::<u32>().map_err(|_| "activity_invalid_pid")?;
        if pid != own && scopes.iter().any(|scope| reference(args, scope)) {
            return Err("running_installation".into());
        }
    }
    if count == 0 {
        return Err("activity_empty_process_list".into());
    }
    Ok(())
}
#[cfg(any(target_os = "macos", target_os = "linux", test))]
fn check_open_files(text: &str, scopes: &[&str], own: u32) -> Result<(), String> {
    let mut pid = None;
    let mut count = 0;
    for line in text.lines() {
        if let Some(value) = line.strip_prefix('p') {
            pid = Some(value.parse::<u32>().map_err(|_| "activity_invalid_pid")?);
            count += 1;
        }
        if let Some(path) = line.strip_prefix('n') {
            if pid.is_none() {
                return Err("activity_missing_pid".into());
            }
            if pid != Some(own) && scopes.iter().any(|scope| reference(path, scope)) {
                return Err("open_installation".into());
            }
        }
    }
    if count == 0 {
        return Err("activity_empty_open_file_list".into());
    }
    Ok(())
}
/// Conservative browser-wide refusal for the model Trash preview on macOS. A process under any
/// matching branded application path blocks the move even when another profile is active.
/// This is a current-user observation, not a process singleton lock or cross-user guarantee.
pub fn check_chrome_inactive(cancel: &CancellationToken) -> Result<(), String> {
    #[cfg(target_os = "macos")]
    {
        use std::process::Command;
        // SAFETY: getuid only reads the current process identity.
        let uid = unsafe { libc::getuid() }.to_string();
        let mut runner = ProbeRunner::new(
            ProbeLimits {
                total_timeout: Duration::from_secs(5),
                probe_timeout: Duration::from_secs(4),
                max_processes: 1,
                max_stdout_bytes: 8 * 1024 * 1024,
            },
            cancel.clone(),
        );
        let out = runner
            .run(Command::new("/bin/ps").args(["-u", &uid, "-o", "pid=,command="]))
            .map_err(|e| format!("browser_activity_unavailable: {e}"))?;
        if !out.status.success() {
            return Err("browser_process_list_failed".into());
        }
        let text = std::str::from_utf8(&out.stdout).map_err(|_| "browser_activity_encoding")?;
        if text.is_empty() {
            return Err("browser_process_list_empty".into());
        }
        if text.contains("Google Chrome.app/Contents/") || text.contains("Google Chrome Helper") {
            return Err("running_browser: fully quit Chrome before moving models".into());
        }
        Ok(())
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = cancel;
        Err("model_activity_host_unsupported".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn known_arguments_handles_and_boundary_matches_are_distinct() {
        let scopes = ["/cache/_npx/123"];
        assert!(
            check_commands(
                "2 node /cache/_npx/123/node_modules/tool/main.js",
                &scopes,
                1
            )
            .is_err()
        );
        assert!(
            check_commands(
                "1 sweepx /cache/_npx/123\n2 node /cache/_npx/1234/main.js",
                &scopes,
                1
            )
            .is_ok()
        );
        assert!(check_open_files("p2\nn/cache/_npx/123/tool", &scopes, 1).is_err());
        assert!(
            check_open_files(
                "p1\nn/cache/_npx/123/tool\np2\nn/cache/_npx/1234/tool",
                &scopes,
                1
            )
            .is_ok()
        );
        assert!(check_open_files("n/cache/_npx/123", &scopes, 1).is_err());
        assert!(check_commands("garbled", &scopes, 1).is_err());
    }
}
