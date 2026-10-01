//! Foreground rendering and exact confirmation for the shared Linux quarantine service.

use std::io::{self, BufRead, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode as ProcessExitCode;
pub(crate) use sweepx_core::junk::quarantine::TempCleanInput;
use sweepx_core::junk::quarantine::{self, TempCleanPlanBody};
use sweepx_core::{CancellationToken, OutputFormat};
use sweepx_i18n::Locale;

/// Foreground CLI adapter; planning and native execution are shared with interactive clients.
pub(crate) fn run_temp_clean(
    inputs: Vec<TempCleanInput>,
    explicit_quarantine: Option<&Path>,
    discovery_complete: bool,
    format: OutputFormat,
    locale: Locale,
    stdin_is_terminal: bool,
) -> ProcessExitCode {
    if let Err(error) = quarantine::ensure_unprivileged() {
        eprintln!("{error}");
        return ProcessExitCode::from(8);
    }
    if format != OutputFormat::Human || !stdin_is_terminal {
        eprintln!(
            "junk --system --clean-temp requires human output and a foreground interactive terminal"
        );
        return ProcessExitCode::from(2);
    }
    if inputs.is_empty() {
        println!(
            "{}",
            match locale {
                Locale::ZhCn => "没有符合安全边界的陈旧 Linux 临时对象。",
                Locale::EnUs => "No stale Linux temporary object met the safety boundary.",
            }
        );
        return ProcessExitCode::SUCCESS;
    }
    let cancel = CancellationToken::new();
    let preview = match quarantine::preview_temp_clean(
        &inputs,
        explicit_quarantine,
        discovery_complete,
        &cancel,
    ) {
        Ok(preview) => preview,
        Err(error) => {
            eprintln!("cleanup plan refused: {error}");
            return ProcessExitCode::from(8);
        }
    };
    print_plan(
        locale,
        preview.plan(),
        preview.digest(),
        preview.allocated_bytes(),
    );
    if !confirm_digest(preview.digest(), io::stdin().lock(), io::stdout()) {
        println!(
            "{}",
            match locale {
                Locale::ZhCn => "已取消；没有移动任何临时对象。",
                Locale::EnUs => "Cancelled; no temporary object was moved.",
            }
        );
        return ProcessExitCode::SUCCESS;
    }
    let confirmation = format!("clean {}", preview.digest());
    match quarantine::execute_temp_clean(preview, &confirmation, &cancel) {
        Ok(result) => {
            print_execution_result(
                locale,
                &result.digest,
                &result.recovery_directory,
                &result.moved,
                result.failure.as_ref(),
            );
            ProcessExitCode::from(if result.failure.is_some() { 4 } else { 0 })
        }
        Err(error) => {
            eprintln!("cleanup plan became stale before execution: {error}");
            ProcessExitCode::from(8)
        }
    }
}

fn print_plan(locale: Locale, plan: &TempCleanPlanBody, digest: &str, total: u128) {
    let fingerprint = sweepx_canonical::attention_fingerprint_from_digest_hex(digest);
    match locale {
        Locale::ZhCn => {
            println!("可恢复临时对象清理计划");
            println!("  候选：{} 个", plan.candidates.len());
            println!("  已统计分配大小：{total} 字节");
            println!(
                "  隔离区：{}",
                sanitize_terminal_text(&plan.quarantine_base)
            );
            println!("  模式：跨文件系统可恢复隔离；不永久删除");
            println!("  剩余边界：无法读取其他用户私有进程/挂载命名空间");
            for candidate in &plan.candidates {
                println!(
                    "    {} [{}]  {} 字节",
                    sanitize_terminal_text(&candidate.path),
                    candidate.inode_type,
                    candidate.allocated_bytes
                );
            }
            println!("  注意指纹：{fingerprint}");
            println!("  完整计划摘要：{digest}");
        }
        Locale::EnUs => {
            println!("Recoverable temporary-object cleanup plan");
            println!("  candidates: {}", plan.candidates.len());
            println!("  accounted allocated size: {total} bytes");
            println!(
                "  quarantine: {}",
                sanitize_terminal_text(&plan.quarantine_base)
            );
            println!("  mode: cross-filesystem recoverable quarantine; never permanent");
            println!(
                "  residual boundary: other users' private process/mount namespaces are unreadable"
            );
            for candidate in &plan.candidates {
                println!(
                    "    {} [{}]  {} bytes",
                    sanitize_terminal_text(&candidate.path),
                    candidate.inode_type,
                    candidate.allocated_bytes
                );
            }
            println!("  attention fingerprint: {fingerprint}");
            println!("  full plan digest: {digest}");
        }
    }
}

fn sanitize_terminal_text(value: &str) -> String {
    value
        .chars()
        .map(|character| {
            if character.is_control() {
                '\u{fffd}'
            } else {
                character
            }
        })
        .collect()
}

fn confirm_digest<R: BufRead, W: Write>(digest: &str, reader: R, mut writer: W) -> bool {
    let _ = write!(writer, "Type `clean {digest}` to execute this exact plan: ");
    let _ = writer.flush();
    let mut answer = String::new();
    // Bound paste/input retention even on a foreground terminal. A truncated line is refusal.
    reader.take(257).read_line(&mut answer).is_ok()
        && answer.len() <= 256
        && answer.trim() == format!("clean {digest}")
}

fn print_execution_result(
    locale: Locale,
    digest: &str,
    run_dir: &Path,
    moved: &[(PathBuf, PathBuf, u128)],
    failure: Option<&(PathBuf, String)>,
) {
    let bytes = moved
        .iter()
        .fold(0u128, |sum, (_, _, bytes)| sum.saturating_add(*bytes));
    match locale {
        Locale::ZhCn => {
            println!("已隔离 {} 个临时对象，共 {bytes} 字节。", moved.len());
            println!(
                "恢复目录：{}",
                sanitize_terminal_text(&run_dir.to_string_lossy())
            );
            println!("计划摘要：{digest}");
            if let Some((path, error)) = failure {
                eprintln!(
                    "后续动作已停止：{}（{}）",
                    sanitize_terminal_text(&path.to_string_lossy()),
                    sanitize_terminal_text(error)
                );
            }
        }
        Locale::EnUs => {
            println!(
                "Quarantined {} temporary objects ({bytes} bytes).",
                moved.len()
            );
            println!(
                "Recovery directory: {}",
                sanitize_terminal_text(&run_dir.to_string_lossy())
            );
            println!("Plan digest: {digest}");
            if let Some((path, error)) = failure {
                eprintln!(
                    "Stopped before later actions: {} ({})",
                    sanitize_terminal_text(&path.to_string_lossy()),
                    sanitize_terminal_text(error)
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn full_digest_confirmation_is_exact() {
        let digest = "abc123";
        let mut output = Vec::new();
        assert!(confirm_digest(
            digest,
            io::Cursor::new(b"clean abc123\n"),
            &mut output
        ));
        assert!(!confirm_digest(
            digest,
            io::Cursor::new(b"abc123\n"),
            Vec::new()
        ));
        assert!(!confirm_digest(
            digest,
            io::Cursor::new(format!("clean {digest}{}\n", " ".repeat(300))),
            Vec::new()
        ));
        assert!(!confirm_digest(
            digest,
            io::Cursor::new(b"clean ABC123\n"),
            Vec::new()
        ));
    }
}
