//! Invocation-scoped, bounded read-only tool probes shared by CLI and future scan sessions.
//!
//! Stdout is drained on the caller's worker with nonblocking reads. There are no pipe-reader
//! threads to outlive cancellation when a descendant inherits the write end. Stderr is discarded
//! because these probes consume a single machine-readable answer, not diagnostic transcripts.

/// Current process and open-file references to explicit cache scopes.
pub mod scoped_activity;

mod installations;
pub use installations::{
    ToolDiscoveryFailure, ToolDiscoveryLimits, ToolDiscoveryReport, ToolInstallation,
    discover_npm_installations, discover_npm_installations_with_limits,
};

use std::io::{self, Read};
use std::process::{Child, ChildStdout, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

use crate::CancellationToken;

/// Resource limits for one complete batch of tool discovery.
#[derive(Debug, Clone, Copy)]
pub struct ProbeLimits {
    /// Wall-clock admission and execution budget shared by all probes in this batch.
    pub total_timeout: Duration,
    /// Maximum execution/drain time for any individual probe.
    pub probe_timeout: Duration,
    /// Maximum attempted launches, including absent executables.
    pub max_processes: usize,
    /// Maximum stdout bytes accepted from one probe; excess output is never used as an answer.
    pub max_stdout_bytes: usize,
}

impl Default for ProbeLimits {
    fn default() -> Self {
        Self {
            total_timeout: Duration::from_secs(10),
            probe_timeout: Duration::from_secs(2),
            max_processes: 64,
            max_stdout_bytes: 64 * 1024,
        }
    }
}

/// Why a tool answer cannot be used; none of these establishes abandonment or disposability.
#[derive(Debug, thiserror::Error)]
pub enum ProbeError {
    /// The caller cancelled this invocation.
    #[error("tool discovery cancelled")]
    Cancelled,
    /// The shared launch or wall-clock budget was exhausted before admission.
    #[error("tool discovery budget exhausted")]
    BudgetExhausted,
    /// The child or an inherited stdout writer did not finish by the deadline.
    #[error("tool probe timed out")]
    TimedOut,
    /// Stdout exceeded its byte budget. Partial output is discarded.
    #[error("tool probe stdout exceeded its limit")]
    OutputLimit,
    /// Launch, process containment, polling or pipe setup failed.
    #[error("tool probe failed: {0}")]
    Io(#[from] io::Error),
}

/// Complete bounded stdout and exit status. A non-success status is a probe failure for discovery.
#[derive(Debug)]
pub struct ProbeOutput {
    /// Exit status, retained so callers can distinguish valid negative answers (e.g. Git).
    pub status: ExitStatus,
    /// Complete stdout, never a truncated prefix.
    pub stdout: Vec<u8>,
}

/// Last stage reached by a probe. This describes timing, never answer validity or cleanup safety.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeStage {
    /// Checking shared cancellation, launch count and deadline before launching a child.
    Admission,
    /// Launching the child through the host process API.
    Launch,
    /// Establishing process containment and preparing the output pipe.
    Setup,
    /// Draining output and polling the direct child's exit status.
    Drain,
    /// Observed both complete stdout and the direct child's exit status.
    Complete,
}

/// Bounded diagnostic facts from the most recent attempt, including failed attempts.
///
/// No command, environment, path or output bytes are retained. Timings are cumulative from
/// admission, include host scheduling, and do not prove the cause of a slow call. In particular,
/// launch/reaping can block in the host API despite the cooperative deadline. These facts are
/// independent of whether the answer is usable and must never establish inactivity or ownership.
#[derive(Debug, Clone, Copy)]
pub struct ProbeDiagnostics {
    /// Last stage reached before returning a result.
    pub stage: ProbeStage,
    /// Time to return, including process cleanup on success or failure.
    pub elapsed: Duration,
    /// Time when the host returned a child; absent when admission or launch failed.
    pub launched_after: Option<Duration>,
    /// Time when containment and pipe setup completed.
    pub ready_after: Option<Duration>,
    /// Time when the first stdout bytes arrived; absent for empty output or no observed output.
    pub first_stdout_after: Option<Duration>,
    /// Bytes read, including a chunk refused by the output limit; no bytes themselves are retained.
    pub stdout_bytes: usize,
    /// Whether EOF was observed, independently of the direct child's exit.
    pub stdout_eof: bool,
    /// Direct child's status observed before cleanup, independently of inherited pipe writers.
    pub exit_status: Option<ExitStatus>,
}

/// Shared probe budget and cancellation state for an invocation; use on a worker, not a UI thread.
pub struct ProbeRunner {
    limits: ProbeLimits,
    deadline: Instant,
    remaining: usize,
    cancel: CancellationToken,
    last_diagnostics: Option<ProbeDiagnostics>,
}

impl ProbeRunner {
    /// Starts a batch using the provided limits and cancellation token.
    pub fn new(limits: ProbeLimits, cancel: CancellationToken) -> Self {
        Self {
            deadline: Instant::now()
                .checked_add(limits.total_timeout)
                .unwrap_or_else(Instant::now),
            remaining: limits.max_processes,
            limits,
            cancel,
            last_diagnostics: None,
        }
    }

    /// Returns fixed-size facts from the last attempt, or `None` before any attempt.
    /// Each attempt replaces the previous facts, including refusal before launch.
    pub fn last_diagnostics(&self) -> Option<ProbeDiagnostics> {
        self.last_diagnostics
    }

    /// Whether the next probe can still be admitted. No child is launched after cancellation.
    pub fn is_exhausted(&self) -> bool {
        self.check_budget().is_err()
    }

    // Filesystem discovery uses the same invocation deadline and cancellation as subprocesses.
    // It must not keep enumerating installations or caches after probe admission is exhausted.
    pub(super) fn check_budget(&self) -> Result<(), ProbeError> {
        if self.cancel.is_cancelled() {
            Err(ProbeError::Cancelled)
        } else if self.remaining == 0 || Instant::now() >= self.deadline {
            Err(ProbeError::BudgetExhausted)
        } else {
            Ok(())
        }
    }

    /// Runs fixed-argument discovery with null stdin/stderr and bounded stdout.
    ///
    /// The caller supplies executable, arguments, environment and optional cwd. This method owns
    /// stdio and process containment; do not use it for interactive tools or filesystem mutation.
    /// Ordinary process launch and OS process reaping remain subject to the host scheduler.
    /// On Unix, the hosting process must not externally reap these children or change SIGCHLD wait
    /// behavior while they are owned; existing auto-reaping modes are rejected before launch.
    pub fn run(&mut self, command: &mut Command) -> Result<ProbeOutput, ProbeError> {
        let started = Instant::now();
        let mut diagnostics = ProbeDiagnostics {
            stage: ProbeStage::Admission,
            elapsed: Duration::ZERO,
            launched_after: None,
            ready_after: None,
            first_stdout_after: None,
            stdout_bytes: 0,
            stdout_eof: false,
            exit_status: None,
        };
        let result = self.run_observed(command, started, &mut diagnostics);
        // run_observed has released its process guard before this measurement. Keeping only the
        // most recent fixed-size record avoids an unbounded transcript or retained failed output.
        diagnostics.elapsed = started.elapsed();
        self.last_diagnostics = Some(diagnostics);
        #[cfg(test)]
        eprintln!(
            "probe result={:?}, diagnostics={diagnostics:?}",
            result.as_ref().err()
        );
        result
    }

    fn run_observed(
        &mut self,
        command: &mut Command,
        started: Instant,
        diagnostics: &mut ProbeDiagnostics,
    ) -> Result<ProbeOutput, ProbeError> {
        self.check_budget()?;
        self.remaining -= 1;
        let deadline = self.deadline.min(
            Instant::now()
                .checked_add(self.limits.probe_timeout)
                .ok_or(ProbeError::BudgetExhausted)?,
        );
        #[cfg(unix)]
        require_waitable_children()?;
        command
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .stdout(Stdio::piped());
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            // A private process group lets timeout cleanup include ordinary tool descendants.
            command.process_group(0);
        }
        diagnostics.stage = ProbeStage::Launch;
        let child = self.launch_active(command, deadline)?;
        diagnostics.launched_after = Some(started.elapsed());
        diagnostics.stage = ProbeStage::Setup;
        let mut process = ProbeProcess::new(child)?;
        let mut pipe = process.child.stdout.take().expect("piped stdout");
        prepare_pipe(&pipe)?;
        diagnostics.ready_after = Some(started.elapsed());
        diagnostics.stage = ProbeStage::Drain;
        let mut stdout = Vec::new();
        let mut status = None;
        let mut eof = false;
        let mut buffer = [0; 4096];
        loop {
            self.check_active_at(deadline, Instant::now())?;
            // Drain one bounded chunk per turn so a continuously noisy child cannot starve
            // cancellation or deadline checks. Capacity cannot grow from an unbounded answer.
            if !eof {
                match read_available(&mut pipe, &mut buffer)? {
                    PipeRead::Bytes(count) => {
                        if diagnostics.first_stdout_after.is_none() {
                            diagnostics.first_stdout_after = Some(started.elapsed());
                        }
                        diagnostics.stdout_bytes = diagnostics.stdout_bytes.saturating_add(count);
                        if count > self.limits.max_stdout_bytes.saturating_sub(stdout.len()) {
                            return Err(ProbeError::OutputLimit);
                        }
                        stdout.extend_from_slice(&buffer[..count]);
                        continue;
                    }
                    PipeRead::Eof => {
                        eof = true;
                        diagnostics.stdout_eof = true;
                    }
                    PipeRead::Pending => {}
                }
            }
            if status.is_none() {
                status = process.observe_exit()?;
                diagnostics.exit_status = status;
            }
            if eof && let Some(status) = status {
                // Keep Unix PID ownership until original-group cleanup has been attempted.
                #[cfg(unix)]
                let status = process.cleanup_and_reap(status)?;
                // A nonblocking host call or scheduling pause can still cross the deadline
                // after the loop's admission check. Complete bytes/status do not authorize
                // accepting an answer once this invocation is cancelled or expired.
                return self.complete_observed(
                    deadline,
                    Instant::now(),
                    diagnostics,
                    status,
                    stdout,
                );
            }
            let pause = deadline
                .saturating_duration_since(Instant::now())
                .min(Duration::from_millis(5));
            #[cfg(target_os = "macos")]
            if !eof && process.exit_waiter.is_some() {
                use std::os::fd::AsFd;
                // Wake on output/EOF instead of delaying a ready answer until the next tick.
                // Keep the same bounded slice so cancellation and child-exit polling remain
                // cooperative. After EOF, polling HUP would spin while a live child runs.
                wait_for_pipe(pipe.as_fd(), pause)?;
            } else {
                process.wait_for_exit(pause);
            }
            #[cfg(not(target_os = "macos"))]
            std::thread::sleep(pause);
        }
    }

    /// Checks the execution budget at one observation point, separately from launch admission.
    /// An explicit observation time also allows deterministic final-stage boundary regressions
    /// without relying on host scheduling or changing the production execution deadline.
    fn check_active_at(&self, deadline: Instant, observed_at: Instant) -> Result<(), ProbeError> {
        if self.cancel.is_cancelled() {
            Err(ProbeError::Cancelled)
        } else if observed_at >= deadline {
            Err(ProbeError::TimedOut)
        } else {
            Ok(())
        }
    }

    /// Native signal-policy queries and host scheduling can cross the initial admission check.
    /// Recheck directly before spawn without consuming a second launch-count allowance.
    fn launch_active(&self, command: &mut Command, deadline: Instant) -> Result<Child, ProbeError> {
        self.check_active_at(deadline, Instant::now())?;
        Ok(command.spawn()?)
    }

    /// Accepts the already complete pipe and child observations only while execution is active.
    /// Rejection retains Drain diagnostics: cleanup still owns the child, and the observed
    /// status/bytes are diagnostic facts rather than a usable answer.
    fn complete_observed(
        &self,
        deadline: Instant,
        observed_at: Instant,
        diagnostics: &mut ProbeDiagnostics,
        status: ExitStatus,
        stdout: Vec<u8>,
    ) -> Result<ProbeOutput, ProbeError> {
        self.check_active_at(deadline, observed_at)?;
        diagnostics.stage = ProbeStage::Complete;
        Ok(ProbeOutput { status, stdout })
    }
}

struct ProbeProcess {
    child: Child,
    #[cfg(unix)]
    /// Set only after group cleanup was attempted while the child was unreaped.
    /// A later drop must never signal this numeric group after the PID has been released.
    group_cleanup_attempted: bool,
    #[cfg(unix)]
    /// Failed wait-ownership validation forbids both raw group and direct-child PID signalling.
    child_wait_ownership_lost: bool,
    #[cfg(target_os = "macos")]
    /// Optional, invocation-local notification with exactly one extra owned descriptor.
    exit_waiter: Option<macos::ExitWaiter>,
    #[cfg(windows)]
    _job: windows::Job,
}

impl ProbeProcess {
    fn new(mut child: Child) -> io::Result<Self> {
        #[cfg(windows)]
        let job = match windows::Job::attach(&child) {
            Ok(job) => job,
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(error);
            }
        };
        // Keep mutable on Windows for failed-attachment cleanup only.
        #[cfg(not(windows))]
        let _ = &mut child;
        // Exit notification is optional acceleration. Registration failure retains bounded
        // polling; it cannot invalidate an otherwise complete tool answer or reap the child.
        #[cfg(target_os = "macos")]
        let exit_waiter = macos::ExitWaiter::new(&child).ok();
        Ok(Self {
            child,
            #[cfg(unix)]
            group_cleanup_attempted: false,
            #[cfg(unix)]
            child_wait_ownership_lost: false,
            #[cfg(target_os = "macos")]
            exit_waiter,
            #[cfg(windows)]
            _job: job,
        })
    }

    /// Observes direct-child exit without releasing Unix PID ownership. Stdout completion
    /// remains independent: a descendant may still own the pipe after the child has exited.
    fn observe_exit(&mut self) -> io::Result<Option<ExitStatus>> {
        #[cfg(unix)]
        {
            match observe_unreaped_exit(&self.child) {
                Err(error) if error.kind() == io::ErrorKind::Interrupted => Ok(None),
                result => result,
            }
        }
        #[cfg(not(unix))]
        {
            // Windows containment uses an owned job handle, independent of PID reuse.
            self.child.try_wait()
        }
    }

    #[cfg(unix)]
    fn signal_owned_group(&mut self) -> io::Result<()> {
        if self.group_cleanup_attempted {
            return Ok(());
        }
        if self.child_wait_ownership_lost {
            return Err(io::Error::other("child wait ownership was lost"));
        }
        // Recheck the owned wait identity immediately before signalling. An external reaper
        // violates the API contract; uncertainty must not become a signal to a recycled PID.
        if let Err(error) =
            require_waitable_children().and_then(|()| observe_unreaped_exit(&self.child))
        {
            self.child_wait_ownership_lost = true;
            return Err(error);
        }
        self.group_cleanup_attempted = true;
        // SAFETY: process_group(0) created this group. All status observations use WNOWAIT;
        // no wait/reap occurs before this signal, so the child PID/group cannot be reassigned.
        // Preserve best-effort group cleanup: macOS can return EPERM for a zombie-only group
        // even though the caller owns its wait status. This does not invalidate natural pipe
        // EOF or a complete answer; errors must not lead to post-reap numeric retries.
        unsafe {
            libc::kill(-(self.child.id() as libc::pid_t), libc::SIGKILL);
        }
        Ok(())
    }

    /// Reaps only after attempting group cleanup, and cross-checks the observation with Child's
    /// ordinary wait status. Called only after natural EOF and a terminal exit observation;
    /// killing a live pipe writer must never manufacture an accepted complete answer.
    #[cfg(unix)]
    fn cleanup_and_reap(&mut self, observed: ExitStatus) -> io::Result<ExitStatus> {
        self.signal_owned_group()?;
        let reaped = self.child.wait()?;
        if reaped != observed {
            return Err(io::Error::other(
                "non-consuming child status changed at reap",
            ));
        }
        Ok(reaped)
    }

    #[cfg(target_os = "macos")]
    fn wait_for_exit(&mut self, interval: Duration) {
        match self
            .exit_waiter
            .as_ref()
            .map(|waiter| waiter.wait(interval))
        {
            Some(Ok(())) => return,
            Some(Err(_)) => self.exit_waiter = None,
            None => {}
        }
        std::thread::sleep(interval);
    }
}

impl Drop for ProbeProcess {
    fn drop(&mut self) {
        #[cfg(unix)]
        {
            // On incomplete/error paths the child is still unreaped, including when only its
            // exit (not pipe EOF) was observed. Attempted cleanup suppresses post-reap signals.
            let _ = self.signal_owned_group();
            if self.child_wait_ownership_lost {
                return;
            }
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
        // The Windows job handle closes afterwards, terminating its remaining descendants.
    }
}

/// WNOWAIT keeps the owned child waitable and its numeric identity reserved until group cleanup.
/// Initialize the whole record because older WNOHANG implementations may not clear no-event
/// fields. Interrupted observations return to the bounded outer loop, but cannot validate
/// cleanup ownership. The caller must retain exclusive wait rights until group signalling.
#[cfg(unix)]
fn observe_unreaped_exit(child: &Child) -> io::Result<Option<ExitStatus>> {
    use std::os::unix::process::ExitStatusExt;
    // SAFETY: zero is valid for all scalar/pointer fields; waitid initializes its tagged result.
    let mut information: libc::siginfo_t = unsafe { std::mem::zeroed() };
    // SAFETY: only this exclusively owned, unreaped child is selected; WNOWAIT never consumes
    // its status. The initialized siginfo storage is live and correctly sized for this ABI.
    if unsafe {
        libc::waitid(
            libc::P_PID,
            child.id() as libc::id_t,
            &mut information,
            libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
        )
    } < 0
    {
        let error = io::Error::last_os_error();
        return Err(error);
    }
    // SAFETY: waitid's successful result is SIGCHLD data; a zero record is the no-event case.
    let pid = unsafe { information.si_pid() };
    if pid == 0 {
        return Ok(None);
    }
    if pid != child.id() as libc::pid_t || information.si_signo != libc::SIGCHLD {
        return Err(io::Error::other("unexpected child exit identity"));
    }
    // SAFETY: the owned-child SIGCHLD tag selects the status union used by waitid.
    let value = unsafe { information.si_status() };
    let raw = match information.si_code {
        libc::CLD_EXITED => (value & 0xff) << 8,
        libc::CLD_KILLED | libc::CLD_DUMPED if (1..=127).contains(&value) => {
            value
                | if information.si_code == libc::CLD_DUMPED {
                    0x80
                } else {
                    0
                }
        }
        _ => return Err(io::Error::other("unexpected nonterminal child exit event")),
    };
    Ok(Some(ExitStatus::from_raw(raw)))
}

/// Query only: never change process-global signal policy. Auto-reaping would release child
/// identities behind the owned guard, so refuse it before creating any process or pipe.
#[cfg(unix)]
fn require_waitable_children() -> io::Result<()> {
    // SAFETY: all-zero scalar/pointer fields form initialized output storage; null action
    // queries the current disposition and cannot replace the hosting process's handler.
    let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
    if unsafe { libc::sigaction(libc::SIGCHLD, std::ptr::null(), &mut action) } < 0 {
        return Err(io::Error::last_os_error());
    }
    if action.sa_sigaction == libc::SIG_IGN || action.sa_flags & libc::SA_NOCLDWAIT != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "SIGCHLD auto-reaping is incompatible with owned tool probes",
        ));
    }
    Ok(())
}

enum PipeRead {
    Bytes(usize),
    Pending,
    Eof,
}

/// Waits without consuming output. Readiness remains provisional: the next nonblocking read
/// handles EOF/errors, and the caller rechecks cancellation/deadlines before accepting bytes.
#[cfg(target_os = "macos")]
fn wait_for_pipe(pipe: std::os::fd::BorrowedFd<'_>, interval: Duration) -> io::Result<()> {
    use std::os::fd::AsRawFd;
    let mut descriptor = libc::pollfd {
        fd: pipe.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    // Round up sub-millisecond intervals to avoid busy waiting at the deadline. The host can
    // overschedule this cooperative wait; no answer is accepted after the deadline check.
    let millis = interval
        .as_nanos()
        .div_ceil(1_000_000)
        .min(i32::MAX as u128) as i32;
    // SAFETY: a live borrowed descriptor and one initialized pollfd remain valid for the call.
    // No other reader can consume the pipe or close the worker's exclusively owned handle.
    if unsafe { libc::poll(&mut descriptor, 1, millis) } < 0 {
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
        // A signal is just a wakeup; the outer loop checks cancellation, budget and child state.
    }
    Ok(())
}

#[cfg(unix)]
fn prepare_pipe(pipe: &ChildStdout) -> io::Result<()> {
    use std::os::fd::AsRawFd;
    // SAFETY: live owned pipe descriptor, scalar fcntl commands; no pointer arguments.
    let flags = unsafe { libc::fcntl(pipe.as_raw_fd(), libc::F_GETFL) };
    if flags == -1
        || unsafe { libc::fcntl(pipe.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) } == -1
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(windows)]
fn prepare_pipe(_: &ChildStdout) -> io::Result<()> {
    Ok(())
}

fn read_available(pipe: &mut ChildStdout, buffer: &mut [u8]) -> io::Result<PipeRead> {
    #[cfg(windows)]
    let buffer = {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::Foundation::ERROR_BROKEN_PIPE;
        use windows_sys::Win32::System::Pipes::PeekNamedPipe;
        let mut available = 0;
        // SAFETY: this worker exclusively owns the pipe's read end. No concurrent read can
        // consume the reported bytes; PeekNamedPipe accepts anonymous pipes too.
        if unsafe {
            PeekNamedPipe(
                pipe.as_raw_handle(),
                std::ptr::null_mut(),
                0,
                std::ptr::null_mut(),
                &mut available,
                std::ptr::null_mut(),
            )
        } == 0
        {
            let error = io::Error::last_os_error();
            return if error.raw_os_error() == Some(ERROR_BROKEN_PIPE as i32) {
                Ok(PipeRead::Eof)
            } else {
                Err(error)
            };
        }
        if available == 0 {
            return Ok(PipeRead::Pending);
        }
        let count = buffer.len().min(available as usize);
        &mut buffer[..count]
    };
    match pipe.read(buffer) {
        Ok(0) => Ok(PipeRead::Eof),
        Ok(count) => Ok(PipeRead::Bytes(count)),
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
            ) =>
        {
            Ok(PipeRead::Pending)
        }
        Err(error) => Err(error),
    }
}

#[cfg(target_os = "macos")]
mod macos {
    use super::*;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

    /// One private kernel queue watching only the owned, unreaped child's exit. Events wake
    /// polling, never supply an answer/status; waitid/Child::wait remain the status authority.
    pub(super) struct ExitWaiter(OwnedFd);

    impl ExitWaiter {
        /// Registers one unreaped owned child; registration errors leave the caller free to
        /// retain its original bounded polling rather than rejecting a valid tool answer.
        pub(super) fn new(child: &Child) -> io::Result<Self> {
            // SAFETY: no arguments; success returns one descriptor exclusively owned below.
            let raw = unsafe { libc::kqueue() };
            if raw < 0 {
                return Err(io::Error::last_os_error());
            }
            let queue = Self(unsafe { OwnedFd::from_raw_fd(raw) });
            // A kqueue is not inherited across fork; also close it across exec. No other
            // invocation borrows this descriptor or retains event/PID histories.
            if unsafe { libc::fcntl(raw, libc::F_SETFD, libc::FD_CLOEXEC) } < 0 {
                return Err(io::Error::last_os_error());
            }
            let change = libc::kevent {
                ident: child.id() as libc::uintptr_t,
                filter: libc::EVFILT_PROC,
                flags: libc::EV_ADD | libc::EV_ONESHOT,
                fflags: libc::NOTE_EXIT,
                data: 0,
                udata: std::ptr::null_mut(),
            };
            // SAFETY: initialized change and owned queue; this child has not been reaped,
            // so its PID cannot identify a replacement. Zero events only registers the watch.
            if unsafe { libc::kevent(raw, &change, 1, std::ptr::null_mut(), 0, std::ptr::null()) }
                < 0
            {
                return Err(io::Error::last_os_error());
            }
            Ok(queue)
        }

        /// Waits for a notification or interval expiry without consuming stdout or reaping.
        /// The caller must recheck its deadline, cancellation and typed child status.
        pub(super) fn wait(&self, interval: Duration) -> io::Result<()> {
            let timeout = libc::timespec {
                tv_sec: interval.as_secs().min(libc::time_t::MAX as u64) as libc::time_t,
                tv_nsec: interval.subsec_nanos().into(),
            };
            // SAFETY: all-zero integer/pointer fields are a valid empty output kevent.
            let mut event: libc::kevent = unsafe { std::mem::zeroed() };
            // SAFETY: live queue, no changes, one initialized event and a finite timeout.
            let result = unsafe {
                libc::kevent(
                    self.0.as_raw_fd(),
                    std::ptr::null(),
                    0,
                    &mut event,
                    1,
                    &timeout,
                )
            };
            if result < 0 {
                let error = io::Error::last_os_error();
                if error.kind() != io::ErrorKind::Interrupted {
                    return Err(error);
                }
            } else if result > 0 && event.flags & libc::EV_ERROR != 0 {
                return Err(io::Error::from_raw_os_error(event.data as i32));
            }
            Ok(())
        }
    }
}

#[cfg(windows)]
mod windows {
    use super::*;
    use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
    use windows_sys::Win32::System::JobObjects::{
        AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
        SetInformationJobObject,
    };

    pub(super) struct Job(OwnedHandle);
    impl Job {
        pub(super) fn attach(child: &Child) -> io::Result<Self> {
            // SAFETY: anonymous job, default security; handle ownership transferred once.
            let handle = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
            if handle.is_null() {
                return Err(io::Error::last_os_error());
            }
            let job = Self(unsafe { OwnedHandle::from_raw_handle(handle) });
            let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
            limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            // SAFETY: initialized struct and correct byte length; both handles are live.
            if unsafe {
                SetInformationJobObject(
                    job.0.as_raw_handle(),
                    JobObjectExtendedLimitInformation,
                    &limits as *const _ as *const _,
                    std::mem::size_of_val(&limits) as u32,
                )
            } == 0
                || unsafe { AssignProcessToJobObject(job.0.as_raw_handle(), child.as_raw_handle()) }
                    == 0
            {
                return Err(io::Error::last_os_error());
            }
            // std::Command exposes the child after launch. Assignment therefore cannot promise
            // containment of descendants that deliberately escape before this point; the pipe
            // deadline still bounds the caller without depending on descendant EOF.
            Ok(job)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "macos")]
    #[test]
    fn pipe_wait_wakes_on_output_and_eof_without_consuming_the_answer() {
        use std::io::Write;
        use std::os::fd::{AsFd, FromRawFd, OwnedFd};
        use std::sync::{Barrier, mpsc};
        for close_writer in [false, true] {
            let mut descriptors = [-1; 2];
            // SAFETY: storage holds both returned descriptors; success transfers each to one
            // OwnedFd below, and no raw handle is retained or closed behind its owner.
            assert_eq!(unsafe { libc::pipe(descriptors.as_mut_ptr()) }, 0);
            let reader = unsafe { OwnedFd::from_raw_fd(descriptors[0]) };
            let writer = unsafe { OwnedFd::from_raw_fd(descriptors[1]) };
            let admitted = Barrier::new(2);
            let (completed, result) = mpsc::sync_channel(1);
            std::thread::scope(|scope| {
                let waiter = scope.spawn(|| {
                    admitted.wait();
                    wait_for_pipe(reader.as_fd(), Duration::from_secs(5)).unwrap();
                    let mut file = std::fs::File::from(reader);
                    let mut answer = [0; 5];
                    let count = file.read(&mut answer).unwrap();
                    completed.send((count, answer)).unwrap();
                });
                admitted.wait();
                if close_writer {
                    drop(writer);
                } else {
                    std::fs::File::from(writer).write_all(b"ready").unwrap();
                }
                // A separate, generous synchronization ceiling proves wakeup without relying
                // on a millisecond scheduling assertion or the production polling constant.
                let observed = result.recv_timeout(Duration::from_secs(2));
                waiter.join().unwrap();
                assert_eq!(
                    observed.unwrap(),
                    if close_writer {
                        (0, [0; 5])
                    } else {
                        (5, *b"ready")
                    }
                );
            });
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn child_exit_notification_wakes_without_reaping_its_status() {
        use std::os::fd::AsFd;
        use std::os::unix::process::CommandExt;
        use std::sync::{Barrier, mpsc};
        let mut command = Command::new("/bin/sh");
        command
            .args(["-c", "printf ready; read ignored; exit 0"])
            .env_clear()
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .process_group(0);
        let mut process = ProbeProcess::new(command.spawn().unwrap()).unwrap();
        let mut pipe = process.child.stdout.take().unwrap();
        prepare_pipe(&pipe).unwrap();
        // Readiness confirms that the shell has started and is blocked on our stdin, keeping
        // kernel launch latency out of the independent exit-notification contract.
        let deadline = Instant::now() + Duration::from_secs(2);
        let mut ready = Vec::new();
        while ready.len() < 5 {
            assert!(
                Instant::now() < deadline,
                "controlled child never became ready"
            );
            wait_for_pipe(
                pipe.as_fd(),
                deadline.saturating_duration_since(Instant::now()),
            )
            .unwrap();
            let mut bytes = [0; 5];
            match read_available(&mut pipe, &mut bytes).unwrap() {
                PipeRead::Bytes(count) => ready.extend_from_slice(&bytes[..count]),
                PipeRead::Pending => {}
                PipeRead::Eof => panic!("child exited before stdin release"),
            }
        }
        assert_eq!(ready, b"ready");
        let watcher = process
            .exit_waiter
            .as_ref()
            .expect("owned-child watch unavailable");
        let admitted = Barrier::new(2);
        let (completed, result) = mpsc::sync_channel(1);
        std::thread::scope(|scope| {
            let waiter = scope.spawn(|| {
                admitted.wait();
                completed
                    .send(watcher.wait(Duration::from_secs(5)))
                    .unwrap();
            });
            admitted.wait();
            drop(process.child.stdin.take());
            let observed = result.recv_timeout(Duration::from_secs(2));
            waiter.join().unwrap();
            observed.unwrap().unwrap();
        });
        // A kernel notification cannot replace a typed exit observation or cleanup before reap.
        let observed = process.observe_exit().unwrap().unwrap();
        assert!(process.cleanup_and_reap(observed).unwrap().success());
    }

    fn child(case: &str) -> Command {
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args(["--exact", "tools::tests::probe_child", "--nocapture"])
            .env("SWEEPX_PROBE_TEST_CASE", case);
        command
    }

    fn runner() -> ProbeRunner {
        ProbeRunner::new(
            ProbeLimits {
                probe_timeout: Duration::from_millis(300),
                max_stdout_bytes: 512,
                ..ProbeLimits::default()
            },
            CancellationToken::new(),
        )
    }

    fn completion_fixture(code: u32, stdout: &[u8]) -> (ExitStatus, ProbeDiagnostics) {
        #[cfg(unix)]
        let status = {
            use std::os::unix::process::ExitStatusExt;
            ExitStatus::from_raw((code as i32) << 8)
        };
        #[cfg(windows)]
        let status = {
            use std::os::windows::process::ExitStatusExt;
            ExitStatus::from_raw(code)
        };
        (
            status,
            ProbeDiagnostics {
                stage: ProbeStage::Drain,
                elapsed: Duration::ZERO,
                launched_after: Some(Duration::ZERO),
                ready_after: Some(Duration::ZERO),
                first_stdout_after: Some(Duration::ZERO),
                stdout_bytes: stdout.len(),
                stdout_eof: true,
                exit_status: Some(status),
            },
        )
    }

    #[test]
    fn final_completion_rejects_a_deadline_crossed_after_the_loop_check() {
        let runner = runner();
        let before = Instant::now();
        // These controlled observation points represent a pause between the loop check and
        // the final host observation. They do not depend on the production timeout or sleeps.
        let deadline = before + Duration::from_secs(1);
        runner.check_active_at(deadline, before).unwrap();
        for completed_at in [deadline, deadline + Duration::from_nanos(1)] {
            let stdout = b"complete answer\n";
            let (status, mut diagnostics) = completion_fixture(0, stdout);
            assert!(matches!(
                runner.complete_observed(
                    deadline,
                    completed_at,
                    &mut diagnostics,
                    status,
                    stdout.to_vec(),
                ),
                Err(ProbeError::TimedOut)
            ));
            assert_eq!(diagnostics.stage, ProbeStage::Drain);
            assert!(diagnostics.stdout_eof);
            assert_eq!(diagnostics.stdout_bytes, stdout.len());
            assert_eq!(diagnostics.exit_status, Some(status));
        }
    }

    #[test]
    fn final_completion_preserves_fresh_answers_and_prioritizes_cancellation() {
        let cancel = CancellationToken::new();
        let runner = ProbeRunner::new(ProbeLimits::default(), cancel.clone());
        let before = Instant::now();
        let deadline = before + Duration::from_secs(1);
        let stdout = b"complete answer\n";
        for code in [0, 7] {
            let (status, mut diagnostics) = completion_fixture(code, stdout);
            let answer = runner
                .complete_observed(
                    deadline,
                    deadline - Duration::from_nanos(1),
                    &mut diagnostics,
                    status,
                    stdout.to_vec(),
                )
                .unwrap();
            assert_eq!(answer.stdout.as_slice(), stdout);
            assert_eq!(answer.status.code(), Some(code as i32));
            assert_eq!(diagnostics.stage, ProbeStage::Complete);
        }
        // Cancellation occurs after the original loop check, and must outrank timeout when
        // both are true at acceptance. Complete native observations remain diagnostic only.
        runner.check_active_at(deadline, before).unwrap();
        cancel.cancel();
        for completed_at in [before, deadline] {
            let (status, mut diagnostics) = completion_fixture(0, stdout);
            assert!(matches!(
                runner.complete_observed(
                    deadline,
                    completed_at,
                    &mut diagnostics,
                    status,
                    stdout.to_vec(),
                ),
                Err(ProbeError::Cancelled)
            ));
            assert_eq!(diagnostics.stage, ProbeStage::Drain);
            assert!(diagnostics.stdout_eof);
            assert_eq!(diagnostics.exit_status, Some(status));
        }
    }

    #[test]
    fn overflowing_deadlines_decline_before_process_launch() {
        for limits in [
            ProbeLimits {
                total_timeout: Duration::MAX,
                ..ProbeLimits::default()
            },
            ProbeLimits {
                probe_timeout: Duration::MAX,
                ..ProbeLimits::default()
            },
        ] {
            let mut runner = ProbeRunner::new(limits, CancellationToken::new());
            let mut absent = Command::new("sweepx-deliberately-absent-deadline-fixture");
            // A launch would produce Io(NotFound); an unrepresentable bound must instead decline
            // admission without panicking or consulting the executable search path.
            assert!(matches!(
                runner.run(&mut absent),
                Err(ProbeError::BudgetExhausted)
            ));
        }
    }

    #[test]
    fn probe_child() {
        let Ok(case) = std::env::var("SWEEPX_PROBE_TEST_CASE") else {
            return;
        };
        if let Some(sentinel) = std::env::var_os("SWEEPX_PROBE_LAUNCH_SENTINEL") {
            std::fs::write(sentinel, b"child launched").unwrap();
        }
        match case.as_str() {
            #[cfg(unix)]
            "auto_reap" => {
                // Process-global policy changes are isolated in this test child, never made
                // in the parent harness or by the production runner.
                let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
                if std::env::var("SWEEPX_AUTOREAP_MODE").unwrap() == "ignore" {
                    action.sa_sigaction = libc::SIG_IGN;
                } else {
                    action.sa_sigaction = libc::SIG_DFL;
                    action.sa_flags = libc::SA_NOCLDWAIT;
                }
                // SAFETY: this private test process installs only constant dispositions using
                // initialized mask/action storage; the parent harness's policy is untouched.
                unsafe {
                    libc::sigemptyset(&mut action.sa_mask);
                    assert_eq!(
                        libc::sigaction(libc::SIGCHLD, &action, std::ptr::null_mut()),
                        0
                    );
                }
                let mut command = Command::new("/bin/sh");
                command
                    .args(["-c", "printf forbidden > \"$1\"", "sh"])
                    .arg(std::env::var_os("SWEEPX_AUTOREAP_SENTINEL").unwrap());
                let mut runner = runner();
                assert!(
                    matches!(runner.run(&mut command), Err(ProbeError::Io(error))
                    if error.kind() == io::ErrorKind::InvalidInput)
                );
                assert_eq!(
                    runner.last_diagnostics().unwrap().stage,
                    ProbeStage::Admission
                );
                println!("auto-reap refused before launch");
                std::process::exit(0);
            }
            "answer" => {
                print!("answer");
                std::process::exit(0);
            }
            "failure" => {
                std::process::exit(7);
            }
            "noise" => {
                use std::io::Write;
                loop {
                    let _ = std::io::stdout().write_all(&[b'x'; 4096]);
                }
            }
            "wait" => std::thread::sleep(Duration::from_secs(30)),
            _ => panic!("unknown test case"),
        }
    }

    #[test]
    fn captures_complete_answer_and_exit_status() {
        let output = runner().run(&mut child("answer")).unwrap();
        assert!(output.status.success());
        assert!(String::from_utf8(output.stdout).unwrap().contains("answer"));
        assert_eq!(
            runner().run(&mut child("failure")).unwrap().status.code(),
            Some(7)
        );
    }

    #[test]
    fn late_launch_refusal_prevents_a_command_from_creating_its_sentinel() {
        let fixture = tempfile::tempdir().unwrap();
        let sentinel = fixture.path().join("never-created");
        for cancelled in [false, true] {
            let cancel = CancellationToken::new();
            let runner = ProbeRunner::new(Default::default(), cancel.clone());
            if cancelled {
                cancel.cancel();
            }
            let mut command = child("answer");
            // A marker written at the first test-child action is an independent launch oracle.
            command.env("SWEEPX_PROBE_LAUNCH_SENTINEL", &sentinel);
            let result = runner.launch_active(&mut command, Instant::now());
            assert!(
                matches!(result, Err(ProbeError::Cancelled) if cancelled)
                    || matches!(result, Err(ProbeError::TimedOut) if !cancelled)
            );
            assert!(!sentinel.exists());
        }
    }

    #[test]
    fn diagnostics_replace_success_with_admission_and_launch_failures() {
        let mut runner = ProbeRunner::new(
            ProbeLimits {
                max_processes: 2,
                ..ProbeLimits::default()
            },
            CancellationToken::new(),
        );
        assert!(runner.last_diagnostics().is_none());
        let output = runner.run(&mut child("answer")).unwrap();
        let complete = runner.last_diagnostics().unwrap();
        assert_eq!(complete.stage, ProbeStage::Complete);
        assert!(complete.stdout_eof);
        assert_eq!(complete.stdout_bytes, output.stdout.len());
        assert_eq!(complete.exit_status, Some(output.status));
        assert!(complete.launched_after.unwrap() <= complete.ready_after.unwrap());
        assert!(complete.ready_after.unwrap() <= complete.first_stdout_after.unwrap());
        assert!(complete.first_stdout_after.unwrap() <= complete.elapsed);

        assert!(matches!(
            runner.run(&mut Command::new("sweepx-absent-probe-diagnostic-fixture")),
            Err(ProbeError::Io(_))
        ));
        let launch = runner.last_diagnostics().unwrap();
        assert_eq!(launch.stage, ProbeStage::Launch);
        assert!(launch.launched_after.is_none());
        assert!(launch.ready_after.is_none());
        assert!(launch.first_stdout_after.is_none());
        assert!(launch.exit_status.is_none());
        assert_eq!(launch.stdout_bytes, 0);
        assert!(!launch.stdout_eof);

        assert!(matches!(
            runner.run(&mut child("answer")),
            Err(ProbeError::BudgetExhausted)
        ));
        let admission = runner.last_diagnostics().unwrap();
        assert_eq!(admission.stage, ProbeStage::Admission);
        assert!(admission.launched_after.is_none());
        assert!(admission.exit_status.is_none());
        assert_eq!(admission.stdout_bytes, 0);
    }

    #[cfg(unix)]
    #[test]
    fn diagnostics_distinguish_child_exit_from_stdout_completion() {
        // The shells independently control exit and pipe ownership. A direct child exiting is
        // insufficient to accept an answer when a descendant still holds stdout open; EOF alone
        // is insufficient while the direct child continues running. No answer is accepted here.
        for (script, expected_eof, expected_exit) in [
            ("printf ready; sleep 30 & exit 0", false, true),
            ("printf ready; exec 1>&-; sleep 30", true, false),
        ] {
            let mut runner = ProbeRunner::new(ProbeLimits::default(), CancellationToken::new());
            let mut command = Command::new("/bin/sh");
            command.args(["-c", script]);
            assert!(matches!(
                runner.run(&mut command),
                Err(ProbeError::TimedOut)
            ));
            let diagnostics = runner.last_diagnostics().unwrap();
            assert_eq!(diagnostics.stage, ProbeStage::Drain);
            assert_eq!(diagnostics.stdout_bytes, b"ready".len());
            assert_eq!(diagnostics.stdout_eof, expected_eof);
            assert_eq!(diagnostics.exit_status.is_some(), expected_exit);
            assert!(diagnostics.first_stdout_after.is_some());
            assert!(diagnostics.ready_after.unwrap() <= diagnostics.elapsed);
        }
    }

    #[test]
    fn noisy_output_is_refused_instead_of_truncated() {
        assert!(matches!(
            runner().run(&mut child("noise")),
            Err(ProbeError::OutputLimit)
        ));
    }

    #[test]
    fn timeout_and_shared_admission_budget_are_enforced() {
        let started = Instant::now();
        assert!(matches!(
            runner().run(&mut child("wait")),
            Err(ProbeError::TimedOut)
        ));
        assert!(started.elapsed() < Duration::from_secs(5));
        let mut limited = ProbeRunner::new(
            ProbeLimits {
                max_processes: 1,
                ..ProbeLimits::default()
            },
            CancellationToken::new(),
        );
        limited.run(&mut child("answer")).unwrap();
        assert!(matches!(
            limited.run(&mut child("answer")),
            Err(ProbeError::BudgetExhausted)
        ));
    }

    #[test]
    fn cancellation_stops_active_and_future_probes() {
        let cancel = CancellationToken::new();
        let mut runner = ProbeRunner::new(ProbeLimits::default(), cancel.clone());
        std::thread::scope(|scope| {
            scope.spawn(|| {
                std::thread::sleep(Duration::from_millis(100));
                cancel.cancel();
            });
            assert!(matches!(
                runner.run(&mut child("wait")),
                Err(ProbeError::Cancelled)
            ));
        });
        assert!(matches!(
            runner.run(&mut child("answer")),
            Err(ProbeError::Cancelled)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn inherited_stdout_does_not_leave_a_reader_waiting_for_eof() {
        let mut command = Command::new("sh");
        command.args(["-c", "sleep 30 & exit 0"]);
        let started = Instant::now();
        assert!(matches!(
            runner().run(&mut command),
            Err(ProbeError::TimedOut)
        ));
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    #[cfg(unix)]
    fn ready_guard(script: &str) -> (ProbeProcess, std::process::ChildStdin, ChildStdout) {
        use std::os::unix::process::CommandExt;
        let mut command = Command::new("/bin/sh");
        command
            .args(["-c", script])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .process_group(0);
        let mut process = ProbeProcess::new(command.spawn().unwrap()).unwrap();
        let gate = process.child.stdin.take().unwrap();
        let mut pipe = process.child.stdout.take().unwrap();
        prepare_pipe(&pipe).unwrap();
        let deadline = Instant::now() + Duration::from_secs(3);
        let mut ready = Vec::new();
        while ready.len() < 5 {
            assert!(
                Instant::now() < deadline,
                "controlled shell did not become ready"
            );
            let mut buffer = [0; 5];
            match read_available(&mut pipe, &mut buffer[..5 - ready.len()]).unwrap() {
                PipeRead::Bytes(count) => ready.extend_from_slice(&buffer[..count]),
                PipeRead::Pending => std::thread::sleep(Duration::from_millis(1)),
                PipeRead::Eof => panic!("controlled shell exited before its ready marker"),
            }
        }
        assert_eq!(ready, b"ready");
        (process, gate, pipe)
    }

    #[cfg(unix)]
    fn await_owned_exit(process: &mut ProbeProcess) -> ExitStatus {
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            assert!(Instant::now() < deadline, "controlled shell did not exit");
            if let Some(status) = process.observe_exit().unwrap() {
                return status;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    #[cfg(unix)]
    fn pipe_tail(pipe: &mut ChildStdout) -> Vec<u8> {
        let deadline = Instant::now() + Duration::from_secs(3);
        let mut bytes = Vec::new();
        loop {
            assert!(Instant::now() < deadline, "controlled pipe did not close");
            let mut buffer = [0; 32];
            match read_available(pipe, &mut buffer).unwrap() {
                PipeRead::Bytes(count) => bytes.extend_from_slice(&buffer[..count]),
                PipeRead::Pending => std::thread::sleep(Duration::from_millis(1)),
                PipeRead::Eof => return bytes,
            }
            assert!(bytes.len() <= 64);
        }
    }

    #[cfg(unix)]
    #[test]
    fn non_consuming_exit_observations_match_ordinary_wait_for_codes_and_signals() {
        use std::io::Write;
        use std::os::unix::process::ExitStatusExt;
        for (action, code, signal) in [
            ("exit 0", Some(0), None),
            ("exit 7", Some(7), None),
            ("exit 255", Some(255), None),
            ("kill -TERM $$", None, Some(libc::SIGTERM)),
            ("kill -KILL $$", None, Some(libc::SIGKILL)),
        ] {
            let (mut process, mut gate, _) =
                ready_guard(&format!("printf ready; read ignored; {action}"));
            assert!(process.observe_exit().unwrap().is_none());
            gate.write_all(b"release\n").unwrap();
            let observed = await_owned_exit(&mut process);
            assert_eq!(process.observe_exit().unwrap(), Some(observed));
            // This independent ordinary wait proves WNOWAIT really retained the status. It
            // deliberately violates the guard's exclusive-wait precondition to check that a
            // subsequent drop refuses raw signals once that authority has been released.
            let oracle = process.child.wait().unwrap();
            assert_eq!(observed, oracle, "{action}");
            assert_eq!(oracle.code(), code);
            assert_eq!(oracle.signal(), signal);
            drop(process);
        }
    }

    #[cfg(unix)]
    #[test]
    fn exited_parent_keeps_wait_identity_until_inherited_stdout_finishes_naturally() {
        use std::io::Write;
        let (mut process, mut gate, mut pipe) =
            ready_guard("exec 3<&0; (read ignored <&3; printf delayed) & printf ready; exit 7");
        let observed = await_owned_exit(&mut process);
        assert_eq!(observed.code(), Some(7));
        let mut byte = [0];
        assert!(matches!(
            read_available(&mut pipe, &mut byte).unwrap(),
            PipeRead::Pending
        ));
        assert_eq!(process.observe_exit().unwrap(), Some(observed));
        gate.write_all(b"release\n").unwrap();
        assert_eq!(pipe_tail(&mut pipe), b"delayed");
        assert_eq!(process.cleanup_and_reap(observed).unwrap().code(), Some(7));
    }

    #[cfg(unix)]
    #[test]
    fn released_wait_ownership_cannot_signal_the_former_group_on_drop() {
        use std::io::Write;
        let (mut process, mut gate, mut pipe) =
            ready_guard("exec 3<&0; (read ignored <&3; printf survived) & printf ready; exit 7");
        await_owned_exit(&mut process);
        assert_eq!(process.child.wait().unwrap().code(), Some(7));
        drop(process);
        // The live inherited writer is an independent oracle: a post-reap group signal would
        // kill it before it can answer. Release it through an owned pipe, never a numeric PID.
        gate.write_all(b"release\n").unwrap();
        assert_eq!(pipe_tail(&mut pipe), b"survived");
    }

    #[cfg(unix)]
    #[test]
    fn auto_reaping_policies_are_refused_in_isolated_children_before_any_tool_launch() {
        let fixture = tempfile::tempdir().unwrap();
        for mode in ["ignore", "no_wait"] {
            let sentinel = fixture.path().join(mode);
            let mut command = child("auto_reap");
            command
                .env("SWEEPX_AUTOREAP_MODE", mode)
                .env("SWEEPX_AUTOREAP_SENTINEL", &sentinel);
            let output = ProbeRunner::new(Default::default(), CancellationToken::new())
                .run(&mut command)
                .unwrap();
            assert!(output.status.success());
            assert!(
                String::from_utf8(output.stdout)
                    .unwrap()
                    .contains("auto-reap refused before launch")
            );
            assert!(!sentinel.exists());
        }
    }
}
