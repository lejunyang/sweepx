//! Invocation-scoped, bounded read-only tool probes shared by CLI and future scan sessions.
//!
//! Stdout is drained on the caller's worker with nonblocking reads. There are no pipe-reader
//! threads to outlive cancellation when a descendant inherits the write end. Stderr is discarded
//! because these probes consume a single machine-readable answer, not diagnostic transcripts.

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
        let child = command.spawn()?;
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
            if self.cancel.is_cancelled() {
                return Err(ProbeError::Cancelled);
            }
            if Instant::now() >= deadline {
                return Err(ProbeError::TimedOut);
            }
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
                status = process.child.try_wait()?;
                diagnostics.exit_status = status;
            }
            if eof && let Some(status) = status {
                diagnostics.stage = ProbeStage::Complete;
                return Ok(ProbeOutput { status, stdout });
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
}

struct ProbeProcess {
    child: Child,
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
            #[cfg(target_os = "macos")]
            exit_waiter,
            #[cfg(windows)]
            _job: job,
        })
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
            // SAFETY: this group was created for this child, never the caller's process group.
            // On error, descendants holding stdout must be stopped as well as the direct child.
            unsafe {
                libc::kill(-(self.child.id() as libc::pid_t), libc::SIGKILL);
            }
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
        // The Windows job handle closes afterwards, terminating its remaining descendants.
    }
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
    /// polling, never supply an answer/status; Child::try_wait remains the status authority.
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
        // Only Child::wait reaps the status, independently proving that a kernel notification
        // cannot be substituted for a complete, successfully interpreted tool result.
        assert!(process.child.wait().unwrap().success());
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
        match case.as_str() {
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
}
