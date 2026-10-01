use super::*;
use std::collections::VecDeque;
use std::sync::{Condvar, Mutex, MutexGuard};
use std::time::Instant;

pub(super) struct Mailbox {
    pub closed: bool,
    pub preferred: Option<PathBuf>,
    queue: VecDeque<JunkSessionEvent>,
    bytes: usize,
    progress: Option<JunkSessionEvent>,
    statistics: Option<JunkSessionEvent>,
    terminal: Option<JunkSessionEvent>,
    job: Option<Job>,
    revision: JunkSessionRevision,
    cancel: CancellationToken,
    idle: bool,
    exited: bool,
}

pub(super) struct Shared {
    state: Mutex<Mailbox>,
    available: Condvar,
    space: Condvar,
    limits: JunkSessionLimits,
}

impl Shared {
    pub fn new(limits: JunkSessionLimits) -> Self {
        Self {
            state: Mutex::new(Mailbox {
                closed: false,
                preferred: None,
                queue: VecDeque::new(),
                bytes: 0,
                progress: None,
                statistics: None,
                terminal: None,
                job: None,
                revision: JunkSessionRevision(1),
                cancel: CancellationToken::new(),
                idle: false,
                exited: false,
            }),
            available: Condvar::new(),
            space: Condvar::new(),
            limits,
        }
    }
    pub fn lock(&self) -> MutexGuard<'_, Mailbox> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
    pub fn cancel_token(&self) -> CancellationToken {
        self.lock().cancel.clone()
    }

    fn pop_locked(&self, state: &mut Mailbox) -> Option<JunkSessionEvent> {
        if let Some(event) = state.queue.pop_front() {
            state.bytes = state.bytes.saturating_sub(event_cost(&event.kind));
            self.space.notify_all();
            return Some(event);
        }
        if let Some(event) = state.progress.take().or_else(|| state.statistics.take()) {
            state.bytes = state.bytes.saturating_sub(event_cost(&event.kind));
            self.space.notify_all();
            return Some(event);
        }
        state.terminal.take()
    }
    pub fn pop(&self) -> Option<JunkSessionEvent> {
        self.pop_locked(&mut self.lock())
    }
    pub fn receive(
        &self,
        timeout: Duration,
    ) -> Result<Option<JunkSessionEvent>, JunkSessionControlError> {
        let deadline = Instant::now()
            .checked_add(timeout)
            .ok_or(JunkSessionControlError::ResourceLimit)?;
        let mut state = self.lock();
        loop {
            if let Some(event) = self.pop_locked(&mut state) {
                return Ok(Some(event));
            }
            if state.closed {
                return Err(JunkSessionControlError::Closed);
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Ok(None);
            }
            (state, _) = self
                .available
                .wait_timeout(state, remaining)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
        }
    }
    pub fn refresh(
        &self,
        keys: Vec<JunkCandidateKey>,
    ) -> Result<JunkSessionRevision, JunkSessionControlError> {
        if keys
            .len()
            .saturating_mul(std::mem::size_of::<JunkCandidateKey>())
            .saturating_add(256)
            > self.limits.max_event_bytes
        {
            return Err(JunkSessionControlError::ResourceLimit);
        }
        let mut state = self.lock();
        if state.closed {
            return Err(JunkSessionControlError::Closed);
        }
        if !state.idle
            || state.job.is_some()
            || !state.queue.is_empty()
            || state.progress.is_some()
            || state.statistics.is_some()
            || state.terminal.is_some()
        {
            return Err(JunkSessionControlError::Busy);
        }
        let revision = JunkSessionRevision(
            state
                .revision
                .0
                .checked_add(1)
                .ok_or(JunkSessionControlError::ResourceLimit)?,
        );
        state.revision = revision;
        state.cancel = CancellationToken::new();
        state.job = Some(Job {
            revision,
            selected: (!keys.is_empty()).then_some(keys),
            cancel: state.cancel.clone(),
        });
        state.idle = false;
        self.available.notify_all();
        Ok(revision)
    }
    pub fn next_job(&self) -> Option<Job> {
        let mut state = self.lock();
        loop {
            if state.closed {
                return None;
            }
            if let Some(job) = state.job.take() {
                return Some(job);
            }
            state = self
                .available
                .wait(state)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
        }
    }
    pub fn close(&self) {
        let mut state = self.lock();
        state.closed = true;
        state.cancel.cancel();
        state.queue.clear();
        state.bytes = 0;
        state.progress = None;
        state.statistics = None;
        state.terminal = None;
        state.job = None;
        self.space.notify_all();
        self.available.notify_all();
    }
    pub fn wait_exit(&self, timeout: Duration) -> Result<bool, JunkSessionControlError> {
        let deadline = Instant::now()
            .checked_add(timeout)
            .ok_or(JunkSessionControlError::ResourceLimit)?;
        let mut state = self.lock();
        while !state.exited {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Ok(false);
            }
            (state, _) = self
                .available
                .wait_timeout(state, remaining)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
        }
        Ok(true)
    }
}

pub(super) struct WorkerExit(pub Arc<Shared>, pub WorkerPermit);
impl Drop for WorkerExit {
    fn drop(&mut self) {
        // Observing exit must also prove the process-wide worker permit is available again.
        self.1.release();
        self.0.lock().exited = true;
        self.0.available.notify_all();
    }
}

pub(super) struct Writer {
    pub shared: Arc<Shared>,
    pub fault: Option<JunkSessionFailure>,
    pub error_count: usize,
    pub coverage_incomplete: bool,
    revision: JunkSessionRevision,
    cancel: CancellationToken,
}
impl Writer {
    pub fn new(
        shared: Arc<Shared>,
        revision: JunkSessionRevision,
        cancel: CancellationToken,
    ) -> Self {
        Self {
            shared,
            revision,
            cancel,
            fault: None,
            error_count: 0,
            coverage_incomplete: false,
        }
    }
    pub fn send(&mut self, kind: JunkSessionEventKind) -> Result<(), JunkSessionFailure> {
        let cost = event_cost(&kind);
        if cost > self.shared.limits.max_event_bytes {
            return Err(JunkSessionFailure::new(
                "resource_limit",
                "one reliable event exceeds mailbox byte budget",
            ));
        }
        let event = JunkSessionEvent {
            revision: self.revision,
            kind,
        };
        let mut state = self.shared.lock();
        // A pending base revision may be replaced by its current interpretation, but never
        // discard a current result, an error or a terminal. Reappend to preserve phase ordering.
        if let JunkSessionEventKind::Candidate { key, .. } = &event.kind
            && let Some(index) = state.queue.iter().position(|old| old.revision == self.revision && matches!(&old.kind, JunkSessionEventKind::Candidate { key: old_key, state: JunkSessionCandidateState::Base, .. } if old_key == key))
        {
            let old = state.queue.remove(index).expect("queued index exists");
            state.bytes = state.bytes.saturating_sub(event_cost(&old.kind));
        }
        // Cancellation ends native work but cannot discard already produced final/error data.
        // Consumers drain through the terminal; closing the receiver releases this wait.
        while !state.closed
            && (state.queue.len() >= self.shared.limits.max_events
                || state.bytes.saturating_add(cost) > self.shared.limits.max_event_bytes)
        {
            clear_coalesced(&mut state);
            if state.queue.len() < self.shared.limits.max_events
                && state.bytes.saturating_add(cost) <= self.shared.limits.max_event_bytes
            {
                break;
            }
            state = self
                .shared
                .space
                .wait(state)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
        }
        if state.closed {
            return Err(JunkSessionFailure::new(
                "session_closed",
                "event consumer closed",
            ));
        }
        state.bytes = state.bytes.saturating_add(cost);
        state.queue.push_back(event);
        self.shared.available.notify_all();
        Ok(())
    }
    pub fn coalesce(&self, kind: JunkSessionEventKind) {
        if event_cost(&kind) > self.shared.limits.max_event_bytes {
            return;
        }
        let mut state = self.shared.lock();
        if state.closed {
            return;
        }
        let statistics = matches!(kind, JunkSessionEventKind::DirectoryStatistics { .. });
        let old = if statistics {
            state.statistics.take()
        } else {
            state.progress.take()
        };
        if let Some(old) = old {
            state.bytes = state.bytes.saturating_sub(event_cost(&old.kind));
        }
        let cost = event_cost(&kind);
        if state.bytes.saturating_add(cost) > self.shared.limits.max_event_bytes {
            return;
        }
        state.bytes = state.bytes.saturating_add(cost);
        let slot = if statistics {
            &mut state.statistics
        } else {
            &mut state.progress
        };
        *slot = Some(JunkSessionEvent {
            revision: self.revision,
            kind,
        });
        self.shared.available.notify_all();
    }
    pub fn phase(&mut self, phase: JunkSessionPhase) -> Result<(), JunkSessionFailure> {
        // Do not deliver traversal lower bounds after the Git/replacement phase has begun.
        {
            let mut state = self.shared.lock();
            clear_coalesced(&mut state);
        }
        self.send(JunkSessionEventKind::Phase(phase))
    }
    pub fn failure(&mut self, failure: JunkSessionFailure) {
        self.error_count = self.error_count.saturating_add(1);
        if let Err(error) = self.send(JunkSessionEventKind::Error(failure)) {
            self.abort(error);
        }
    }
    pub fn abort(&mut self, failure: JunkSessionFailure) {
        if self.fault.is_none() {
            self.fault = Some(failure);
        }
        self.cancel.cancel();
    }
    pub fn finish(&self, outcome: JunkSessionOutcome, replaced: bool, candidate_count: usize) {
        let mut state = self.shared.lock();
        if state.closed {
            return;
        }
        // Fixed-size reserved terminal storage cannot be crowded out by candidates. A new
        // revision is refused until the preceding queue, coalescing slots and terminal are drained.
        state.terminal = Some(JunkSessionEvent {
            revision: self.revision,
            kind: JunkSessionEventKind::Completed {
                outcome,
                replaced,
                candidate_count,
                error_count: self.error_count,
            },
        });
        state.idle = true;
        self.shared.available.notify_all();
    }
}

fn event_cost(kind: &JunkSessionEventKind) -> usize {
    let base = std::mem::size_of::<JunkSessionEvent>().saturating_add(256);
    base.saturating_add(match kind {
        JunkSessionEventKind::Started {
            scope: JunkSessionScope::Selected(keys),
        } => keys
            .len()
            .saturating_mul(std::mem::size_of::<JunkCandidateKey>()),
        JunkSessionEventKind::Candidate { row, .. } => row.cost(),
        JunkSessionEventKind::Progress { path, .. } => path.capacity(),
        JunkSessionEventKind::DirectoryStatistics { path, aggregate } => path
            .capacity()
            .saturating_add(1024)
            .saturating_add(aggregate.directory_identity.capacity())
            .saturating_add(aggregate.scan_id.len()),
        JunkSessionEventKind::Boundary(boundary) => boundary
            .path
            .capacity()
            .saturating_add(boundary.detail.capacity())
            .saturating_add(std::mem::size_of::<sweepx_platform::BoundaryRecord>()),
        JunkSessionEventKind::Error(failure) | JunkSessionEventKind::CacheWarning(failure) => {
            failure.detail.capacity()
        }
        _ => 0,
    })
}

fn clear_coalesced(state: &mut Mailbox) {
    for event in [state.progress.take(), state.statistics.take()]
        .into_iter()
        .flatten()
    {
        state.bytes = state.bytes.saturating_sub(event_cost(&event.kind));
    }
}

#[cfg(test)]
mod tests;
