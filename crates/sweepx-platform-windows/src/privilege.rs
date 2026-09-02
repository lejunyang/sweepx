//! Windows privilege detection and opt-in elevation.
//!
//! Detection reads the process token; it never prompts and never launches a
//! process. Elevation is implemented as a *relaunch* rather than an in-process
//! privilege change, because Windows grants elevation only at process creation —
//! see [`WindowsPrivilegeProvider::request_elevation`] for why, and
//! [`WindowsPrivilegeProvider::relaunch_elevated`] for the mechanism.

use std::mem;
use std::ptr;

use sweepx_platform::{
    ElevatedRelaunch, ElevationPolicy, ElevationRefusal, PrivilegeObservation, PrivilegeProvider,
};

#[cfg(windows)]
use std::ffi::{OsStr, OsString};
#[cfg(windows)]
use std::os::windows::ffi::{OsStrExt, OsStringExt};

#[cfg(windows)]
use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_CANCELLED, HANDLE, WAIT_FAILED, WAIT_OBJECT_0,
};
#[cfg(windows)]
use windows_sys::Win32::Security::{
    GetTokenInformation, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation,
};
#[cfg(windows)]
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, GetExitCodeProcess, INFINITE, OpenProcessToken, WaitForSingleObject,
};
#[cfg(windows)]
use windows_sys::Win32::UI::Shell::{
    SEE_MASK_NOASYNC, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW, ShellExecuteExW,
};
#[cfg(windows)]
use windows_sys::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;

/// Windows implementation of [`PrivilegeProvider`].
#[derive(Debug, Clone, Copy, Default)]
pub struct WindowsPrivilegeProvider;

impl WindowsPrivilegeProvider {
    /// Creates the provider.
    pub const fn new() -> Self {
        Self
    }
}

impl PrivilegeProvider for WindowsPrivilegeProvider {
    fn provider_name(&self) -> &'static str {
        "windows-process-token"
    }

    #[cfg(windows)]
    fn observe(&self) -> PrivilegeObservation {
        // SAFETY: `GetCurrentProcess` returns a pseudo-handle that needs no close, and
        // `OpenProcessToken` writes at most one handle into `token`, which is closed on
        // every path below. `TOKEN_QUERY` alone is requested: this must stay a read.
        unsafe {
            let mut token: HANDLE = ptr::null_mut();
            if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
                // The token is unreadable, so the answer is genuinely unknown. Reporting
                // `NotElevated` here would look like a safe default while actually
                // disabling the R-23 destructive-mode refusal on a host that may well be
                // elevated.
                return PrivilegeObservation::unknown();
            }

            let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
            let mut returned = 0_u32;
            let queried = GetTokenInformation(
                token,
                TokenElevation,
                ptr::from_mut(&mut elevation).cast(),
                u32::try_from(mem::size_of::<TOKEN_ELEVATION>()).unwrap_or(u32::MAX),
                &mut returned,
            );
            CloseHandle(token);

            // A short write means the field was not populated, so the value in it is not
            // an answer even though the call reported success.
            if queried == 0 || returned as usize != mem::size_of::<TOKEN_ELEVATION>() {
                return PrivilegeObservation::unknown();
            }
            if elevation.TokenIsElevated == 0 {
                PrivilegeObservation::not_elevated()
            } else {
                PrivilegeObservation::inherited()
            }
        }
    }

    #[cfg(not(windows))]
    fn observe(&self) -> PrivilegeObservation {
        // Fail closed rather than claim knowledge of a token this host does not have.
        PrivilegeObservation::unknown()
    }

    fn request_elevation(
        &self,
        policy: ElevationPolicy,
    ) -> Result<PrivilegeObservation, ElevationRefusal> {
        if policy == ElevationPolicy::DetectOnly {
            return Err(ElevationRefusal::PolicyForbidsRequest);
        }
        // Windows grants elevation to a *process*, at creation time; there is no call
        // that raises the privilege of a process already running. Honoring an opt-in
        // therefore means re-launching SweepX elevated and handing the work to the new
        // process — which changes process identity, audit lineage, and the ownership of
        // any state directory already opened. Doing that from inside a scan would
        // silently fork the run in two, so it must be decided at the entry point,
        // before any scan state exists, and never here.
        Err(ElevationRefusal::Unavailable(
            "elevation on Windows requires re-launching the process; it cannot be \
             acquired by a process that is already running"
                .to_string(),
        ))
    }

    #[cfg(windows)]
    fn relaunch_elevated(&self, request: &ElevatedRelaunch) -> Result<u8, ElevationRefusal> {
        // An absolute path is required because the shell resolves a bare name against
        // its own search order, which could start a different image than the one now
        // running -- and it would start that one elevated.
        if !request.program.is_absolute() {
            return Err(ElevationRefusal::Failed(
                "refusing to relaunch elevated without an absolute program path".to_string(),
            ));
        }
        let verb = wide("runas");
        let program = wide_os(request.program.as_os_str());
        let arguments = wide_os(&join_arguments(&request.arguments));

        let mut info = SHELLEXECUTEINFOW {
            cbSize: match u32::try_from(mem::size_of::<SHELLEXECUTEINFOW>()) {
                Ok(size) => size,
                Err(_) => {
                    return Err(ElevationRefusal::Failed(
                        "SHELLEXECUTEINFOW size does not fit the ABI field".to_string(),
                    ));
                }
            },
            // NOCLOSEPROCESS yields the child handle so its exit code can be adopted;
            // without it the parent could not tell success from failure. NOASYNC keeps
            // the shell call valid for a process that exits right after it returns.
            fMask: SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC,
            hwnd: ptr::null_mut(),
            lpVerb: verb.as_ptr(),
            lpFile: program.as_ptr(),
            lpParameters: arguments.as_ptr(),
            lpDirectory: ptr::null(),
            nShow: SW_SHOWNORMAL,
            hInstApp: ptr::null_mut(),
            lpIDList: ptr::null_mut(),
            lpClass: ptr::null(),
            hkeyClass: ptr::null_mut(),
            dwHotKey: 0,
            // SAFETY: the union is an optional icon/monitor handle; all-zero means
            // "not supplied", which is what the null `fMask` bits above declare.
            Anonymous: unsafe { mem::zeroed() },
            hProcess: ptr::null_mut(),
        };

        // SAFETY: every pointer field either is null or points at a NUL-terminated wide
        // buffer that outlives this call, and `cbSize` matches the struct actually
        // passed. The returned process handle is closed on all paths below.
        unsafe {
            if ShellExecuteExW(&mut info) == 0 {
                let error = std::io::Error::last_os_error();
                // Declining the UAC dialog is reported as ERROR_CANCELLED. It is the
                // user's answer, not a malfunction, and must not read as one.
                return Err(if error.raw_os_error() == Some(ERROR_CANCELLED as i32) {
                    ElevationRefusal::Declined
                } else {
                    ElevationRefusal::Failed(format!("ShellExecuteExW failed: {error}"))
                });
            }
            if info.hProcess.is_null() {
                // Without a handle the child's outcome is unknowable. Reporting success
                // here would let the parent exit 0 while the elevated run failed.
                return Err(ElevationRefusal::Failed(
                    "the elevated process started without returning a handle".to_string(),
                ));
            }
            let child = info.hProcess as HANDLE;
            let waited = WaitForSingleObject(child, INFINITE);
            if waited != WAIT_OBJECT_0 {
                CloseHandle(child);
                return Err(ElevationRefusal::Failed(format!(
                    "waiting for the elevated process failed (result {waited}, WAIT_FAILED={WAIT_FAILED})"
                )));
            }
            let mut code: u32 = 0;
            let queried = GetExitCodeProcess(child, &mut code);
            CloseHandle(child);
            if queried == 0 {
                return Err(ElevationRefusal::Failed(format!(
                    "could not read the elevated process exit code: {}",
                    std::io::Error::last_os_error()
                )));
            }
            // Exit codes are a byte at the process boundary. A wider value cannot be
            // forwarded faithfully, so it is reported as a failure rather than
            // truncated into a possibly-successful-looking code.
            u8::try_from(code).map_err(|_| {
                ElevationRefusal::Failed(format!(
                    "the elevated process returned exit code {code}, which does not fit a process exit byte"
                ))
            })
        }
    }
}

/// Encodes a NUL-terminated wide string for the Win32 ABI.
#[cfg(windows)]
fn wide(value: &str) -> Vec<u16> {
    OsStr::new(value)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

/// Encodes an `OsStr` as a NUL-terminated wide string, preserving it losslessly.
///
/// Windows paths are UTF-16 and need not be valid Unicode; going through `to_string_lossy`
/// would replace unpaired surrogates and could name a different file than intended.
#[cfg(windows)]
fn wide_os(value: &OsStr) -> Vec<u16> {
    value.encode_wide().chain(std::iter::once(0)).collect()
}

/// Builds a `lpParameters` string that the child will parse back into the same arguments.
///
/// `ShellExecuteExW` takes one flat command line, so each argument is quoted per the
/// standard Windows convention: embedded quotes and the backslashes preceding them are
/// escaped, and every argument is wrapped so spaces cannot split it. Passing arguments
/// unquoted would silently turn one path containing a space into two roots.
///
/// Works in UTF-16 throughout so a non-Unicode path survives the round trip.
#[cfg(windows)]
fn join_arguments(arguments: &[OsString]) -> OsString {
    const QUOTE: u16 = b'"' as u16;
    const BACKSLASH: u16 = b'\\' as u16;
    const SPACE: u16 = b' ' as u16;

    let mut line: Vec<u16> = Vec::new();
    for (index, argument) in arguments.iter().enumerate() {
        if index > 0 {
            line.push(SPACE);
        }
        line.push(QUOTE);
        let mut backslashes = 0usize;
        for unit in argument.encode_wide() {
            match unit {
                BACKSLASH => {
                    backslashes += 1;
                    line.push(unit);
                }
                QUOTE => {
                    // Double the run of backslashes so they stay literal, then escape
                    // the quote itself. `resize` rather than a push loop: clippy reads
                    // the loop as a mistake, but the repetition is the intent.
                    let doubled = line.len() + backslashes + 1;
                    line.resize(doubled, BACKSLASH);
                    backslashes = 0;
                    line.push(QUOTE);
                }
                _ => {
                    backslashes = 0;
                    line.push(unit);
                }
            }
        }
        // A trailing backslash would otherwise escape the closing quote.
        line.resize(line.len() + backslashes, BACKSLASH);
        line.push(QUOTE);
    }
    OsString::from_wide(&line)
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;
    use sweepx_platform::{PrivilegeLevel, PrivilegeOrigin, resolve_privilege};

    /// Detection must return a definite answer on a real Windows host.
    ///
    /// `Unknown` is a legitimate value of the type, so a test that accepted anything
    /// would pass even if the token query were broken. This asserts the query
    /// actually worked, and separately that consistency holds with the origin field.
    #[test]
    fn detection_answers_definitely_on_this_host() {
        let observed = WindowsPrivilegeProvider::new().observe();

        assert_ne!(
            observed.level,
            PrivilegeLevel::Unknown,
            "the process token must be readable on a Windows host"
        );
        match observed.level {
            PrivilegeLevel::NotElevated => {
                assert_eq!(observed.origin, PrivilegeOrigin::None);
            }
            PrivilegeLevel::Elevated => {
                // Nothing in SweepX requested it, so it can only have been inherited.
                assert_eq!(observed.origin, PrivilegeOrigin::InheritedFromSession);
            }
            PrivilegeLevel::Unknown => unreachable!("asserted above"),
        }
    }

    /// Repeated detection is stable and free of side effects.
    ///
    /// Guards against a leaked token handle or a query that mutates state: the
    /// answer must not drift across calls within one process.
    #[test]
    fn detection_is_stable_and_side_effect_free() {
        let provider = WindowsPrivilegeProvider::new();
        let first = provider.observe();
        for _ in 0..64 {
            assert_eq!(provider.observe(), first);
        }
    }

    #[test]
    fn detect_only_policy_refuses_before_touching_the_host() {
        assert_eq!(
            WindowsPrivilegeProvider::new().request_elevation(ElevationPolicy::DetectOnly),
            Err(ElevationRefusal::PolicyForbidsRequest)
        );
    }

    /// An opted-in request reports that in-process elevation is impossible.
    ///
    /// This documents a platform fact rather than a missing feature, so the refusal
    /// must be `Unavailable` and not `Declined`: the user never declined anything.
    #[test]
    fn opted_in_request_reports_relaunch_requirement_without_prompting() {
        let refusal = WindowsPrivilegeProvider::new()
            .request_elevation(ElevationPolicy::RequestWhenUserOptedIn)
            .expect_err("in-process elevation is impossible on Windows");

        assert!(matches!(refusal, ElevationRefusal::Unavailable(_)));
    }

    /// A declined or impossible elevation must leave the run on its detected path.
    #[test]
    fn resolution_falls_back_to_the_detected_level() {
        let provider = WindowsPrivilegeProvider::new();
        let detected = provider.observe();
        let (resolved, refusal) =
            resolve_privilege(&provider, ElevationPolicy::RequestWhenUserOptedIn);

        assert_eq!(resolved, detected);
        if detected.level == PrivilegeLevel::NotElevated {
            assert!(matches!(refusal, Some(ElevationRefusal::Unavailable(_))));
        }
    }

    /// A relative program path must be refused before any prompt is raised.
    ///
    /// The shell would resolve a bare name against its own search order, so honoring
    /// one could start a *different* image elevated. Refusing is the whole point.
    #[test]
    fn relaunch_refuses_a_relative_program_path() {
        let request = ElevatedRelaunch::new(
            std::path::PathBuf::from("sweepx.exe"),
            vec![OsString::from("scan")],
        );

        let refusal = WindowsPrivilegeProvider::new()
            .relaunch_elevated(&request)
            .expect_err("a relative program path must not be relaunched");

        assert!(matches!(refusal, ElevationRefusal::Failed(_)));
    }

    /// Arguments must survive the flattening into a single command line.
    ///
    /// `ShellExecuteExW` takes one string, so a path containing a space would become
    /// two roots if it were not quoted -- scanning something the user never named.
    #[test]
    fn arguments_with_spaces_are_quoted_as_single_arguments() {
        let line = join_arguments(&[
            OsString::from("scan"),
            OsString::from(r"C:\Program Files\App"),
        ]);

        assert_eq!(line, OsString::from(r#""scan" "C:\Program Files\App""#));
    }

    /// A trailing backslash must not escape the closing quote.
    ///
    /// `"E:\dir\"` would swallow the quote and merge this argument with the next; the
    /// backslash run has to be doubled before the terminator.
    #[test]
    fn a_trailing_backslash_does_not_escape_the_closing_quote() {
        let line = join_arguments(&[OsString::from(r"E:\dir\")]);

        assert_eq!(line, OsString::from(r#""E:\dir\\""#));
    }

    /// Embedded quotes and their preceding backslashes must both be escaped.
    #[test]
    fn embedded_quotes_are_escaped_with_their_backslash_run() {
        let line = join_arguments(&[OsString::from(r#"a\"b"#)]);

        // One literal backslash then a literal quote: the run doubles to two, and the
        // quote gains its own escape.
        assert_eq!(line, OsString::from(r#""a\\\"b""#));
    }

    /// Non-Unicode arguments must round-trip, since Windows paths are UTF-16.
    #[test]
    fn a_lone_surrogate_argument_is_preserved() {
        // 0xD800 is an unpaired high surrogate: valid in a Windows path, not valid UTF-8.
        let argument = OsString::from_wide(&[u16::from(b'x'), 0xD800, u16::from(b'y')]);
        let line = join_arguments(std::slice::from_ref(&argument));

        let units: Vec<u16> = line.encode_wide().collect();
        assert_eq!(
            units,
            vec![
                u16::from(b'"'),
                u16::from(b'x'),
                0xD800,
                u16::from(b'y'),
                u16::from(b'"')
            ],
            "a lossy conversion would have replaced the surrogate"
        );
    }

    /// No arguments produces an empty command line rather than a stray quote pair.
    #[test]
    fn no_arguments_produces_an_empty_command_line() {
        assert_eq!(join_arguments(&[]), OsString::new());
    }
}
