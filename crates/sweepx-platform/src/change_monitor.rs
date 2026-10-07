//! Session-owned, advisory filesystem notifications. No event certifies unchanged facts or
//! supplies traversal/deletion authority. A drain takes only the changes already delivered;
//! subsequent callbacks, including writes racing with a scan, remain in the next batch.

use std::collections::BTreeSet;
use std::io;
use std::path::PathBuf;
#[cfg(any(
    any(
        all(target_os = "macos", feature = "backend-macos"),
        all(target_os = "linux", feature = "backend-linux"),
        all(windows, feature = "backend-windows")
    ),
    test
))]
use std::path::{Component, Path};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use crate::CancellationToken;

#[cfg(all(target_os = "linux", feature = "backend-linux"))]
mod linux;
#[cfg(all(windows, feature = "backend-windows"))]
mod windows;

/// Application-owned notification and native watch bounds, separate from scanner retention.
#[derive(Debug, Clone, Copy)]
pub struct ChangeMonitorLimits {
    /// Maximum distinct pending directories; exhaustion requests a complete fresh scan.
    pub max_directories: usize,
    /// Estimated pending path/tree storage bytes, not RSS or framework-owned memory.
    pub max_bytes: usize,
    /// Maximum Linux directory watches or Windows root watches. macOS uses one stream.
    pub max_watches: usize,
    /// Estimated Linux watch-path registry bytes, independent of the pending queue.
    pub max_watch_bytes: usize,
}
impl Default for ChangeMonitorLimits {
    fn default() -> Self {
        Self {
            max_directories: 256,
            max_bytes: 1024 * 1024,
            max_watches: if cfg!(windows) { 32 } else { 65_536 },
            max_watch_bytes: 16 * 1024 * 1024,
        }
    }
}

/// Delivered changes since the previous drain. Paths select fresh work only.
#[derive(Debug, Default)]
pub struct DirectoryChanges {
    /// Coalesced containing directories; ancestor paths subsume descendants.
    pub directories: Vec<PathBuf>,
    /// A native gap, lost mapping or queue overflow requires a complete scan.
    pub full_scan: bool,
    /// A permanent listener failure disables automatic refresh after one fresh fallback.
    pub unavailable: Option<String>,
}

#[derive(Default)]
struct Pending {
    paths: BTreeSet<PathBuf>,
    bytes: usize,
    full: bool,
    failure: Option<String>,
    first: Option<Instant>,
    last: Option<Instant>,
}

pub(crate) struct ChangeQueue {
    #[cfg(any(
        any(
            all(target_os = "macos", feature = "backend-macos"),
            all(target_os = "linux", feature = "backend-linux"),
            all(windows, feature = "backend-windows")
        ),
        test
    ))]
    roots: Vec<PathBuf>,
    #[cfg(any(
        any(
            all(target_os = "macos", feature = "backend-macos"),
            all(target_os = "linux", feature = "backend-linux"),
            all(windows, feature = "backend-windows")
        ),
        test
    ))]
    limits: ChangeMonitorLimits,
    pending: Mutex<Pending>,
    failed: std::sync::atomic::AtomicBool,
}

#[cfg(any(
    all(target_os = "linux", feature = "backend-linux"),
    all(target_os = "macos", feature = "backend-macos"),
    all(windows, feature = "backend-windows")
))]
pub(crate) struct ListenerExit(pub Arc<ChangeQueue>, pub CancellationToken);
#[cfg(any(
    all(target_os = "linux", feature = "backend-linux"),
    all(target_os = "macos", feature = "backend-macos"),
    all(windows, feature = "backend-windows")
))]
impl Drop for ListenerExit {
    fn drop(&mut self) {
        if !self.1.is_cancelled() {
            self.0
                .fail("native filesystem listener exited unexpectedly");
        }
    }
}
impl ChangeQueue {
    fn lock(&self) -> std::sync::MutexGuard<'_, Pending> {
        self.pending
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    #[cfg(any(
        any(
            all(target_os = "macos", feature = "backend-macos"),
            all(target_os = "linux", feature = "backend-linux"),
            all(windows, feature = "backend-windows")
        ),
        test
    ))]
    pub(crate) fn directory(&self, path: &Path) {
        if !path.is_absolute()
            || path.as_os_str().len() > 64 * 1024
            || path.components().any(|c| matches!(c, Component::ParentDir))
        {
            self.gap();
            return;
        }
        let Some(root) = self.roots.iter().find(|root| path.starts_with(root)) else {
            // Ancestor changes can replace a root; unrelated events never broaden the scope.
            if self.roots.iter().any(|root| root.starts_with(path)) {
                self.gap();
            }
            return;
        };
        // Git interpretation depends on repository state, including siblings of .git. A change
        // inside .git must refresh that repository rather than just the administrative directory.
        let mut directory = path;
        for parent in path.ancestors().take_while(|p| p.starts_with(root)) {
            if parent.file_name().is_some_and(|name| name == ".git") {
                directory = parent.parent().unwrap_or(root);
            }
        }
        let mut state = self.lock();
        Self::touch(&mut state);
        if state.full || state.paths.iter().any(|p| directory.starts_with(p)) {
            return;
        }
        // Bound temporary removals too: retain avoids a second all-path collection.
        state.paths.retain(|p| !p.starts_with(directory));
        state.bytes = state
            .paths
            .iter()
            .map(|p| p.capacity().saturating_add(160))
            .sum();
        let cost = directory.as_os_str().len().saturating_add(160);
        if state.paths.len() >= self.limits.max_directories
            || state.bytes.saturating_add(cost) > self.limits.max_bytes
        {
            Self::mark_full(&mut state);
            return;
        }
        let path = directory.to_path_buf();
        let cost = path.capacity().saturating_add(160);
        if state.bytes.saturating_add(cost) > self.limits.max_bytes {
            Self::mark_full(&mut state);
        } else {
            state.bytes += cost;
            state.paths.insert(path);
        }
    }

    #[cfg(any(
        all(target_os = "macos", feature = "backend-macos"),
        all(windows, feature = "backend-windows"),
        test
    ))]
    pub(crate) fn changed_path(&self, path: &Path) {
        self.directory(path.parent().unwrap_or(path));
    }

    fn touch(state: &mut Pending) {
        let now = Instant::now();
        state.first.get_or_insert(now);
        state.last = Some(now);
    }
    fn mark_full(state: &mut Pending) {
        state.paths.clear();
        state.bytes = 0;
        state.full = true;
    }
    pub(crate) fn gap(&self) {
        let mut state = self.lock();
        Self::touch(&mut state);
        Self::mark_full(&mut state);
    }
    pub(crate) fn fail(&self, detail: impl ToString) {
        self.failed
            .store(true, std::sync::atomic::Ordering::Release);
        let mut state = self.lock();
        Self::touch(&mut state);
        Self::mark_full(&mut state);
        if state.failure.is_none() {
            let mut text = detail.to_string();
            if text.len() > 2000 {
                let mut end = 2000;
                while !text.is_char_boundary(end) {
                    end -= 1;
                }
                text.truncate(end);
                text.push_str(" [truncated]");
            }
            state.failure = Some(text);
        }
    }
    fn drain_ready(&self) -> Option<DirectoryChanges> {
        let mut state = self.lock();
        let first = state.first?;
        if !state.full
            && state.last?.elapsed() < std::time::Duration::from_millis(200)
            && first.elapsed() < std::time::Duration::from_secs(1)
        {
            return None;
        }
        let pending = std::mem::take(&mut *state);
        Some(DirectoryChanges {
            directories: pending.paths.into_iter().collect(),
            full_scan: pending.full,
            unavailable: pending.failure,
        })
    }
}

/// Persistent native listener for one live session. Start before traversal, and register every
/// admitted Linux directory before enumerating it. Notifications never qualify cached replay.
/// Closing cancels native listeners; their bounded waits and OS resources stay on worker threads.
pub struct ChangeMonitor {
    queue: Arc<ChangeQueue>,
    stop: CancellationToken,
    #[cfg(all(target_os = "linux", feature = "backend-linux"))]
    backend: linux::Backend,
    #[cfg(all(windows, feature = "backend-windows"))]
    backend: windows::Backend,
    threads: Mutex<Vec<std::thread::JoinHandle<()>>>,
}
impl ChangeMonitor {
    /// Starts native delivery without walking any directory. Unsupported inputs/hosts fail
    /// explicitly; callers can still run ordinary fresh scans without a listener.
    #[cfg(not(any(
        all(target_os = "macos", feature = "backend-macos"),
        all(target_os = "linux", feature = "backend-linux"),
        all(windows, feature = "backend-windows")
    )))]
    pub fn start(_roots: &[PathBuf], _limits: ChangeMonitorLimits) -> io::Result<Self> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "native change monitor unavailable",
        ))
    }

    /// Starts the selected host backend before traversal, without walking directory trees.
    #[cfg(any(
        all(target_os = "macos", feature = "backend-macos"),
        all(target_os = "linux", feature = "backend-linux"),
        all(windows, feature = "backend-windows")
    ))]
    pub fn start(roots: &[PathBuf], limits: ChangeMonitorLimits) -> io::Result<Self> {
        if roots.is_empty()
            || roots.len() > 256
            || limits.max_directories == 0
            || limits.max_bytes == 0
            || limits.max_watches == 0
            || limits.max_watch_bytes == 0
            || roots
                .iter()
                .any(|p| !p.is_absolute() || p.as_os_str().len() > 64 * 1024)
            || roots.iter().map(|p| p.as_os_str().len()).sum::<usize>() > 1024 * 1024
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid change monitor scope or bounds",
            ));
        }
        let queue = Arc::new(ChangeQueue {
            roots: roots.to_vec(),
            limits,
            pending: Mutex::new(Pending::default()),
            failed: std::sync::atomic::AtomicBool::new(false),
        });
        let stop = CancellationToken::new();
        #[cfg(all(target_os = "macos", feature = "backend-macos"))]
        let thread = crate::macos::fsevents::start_live(roots, Arc::clone(&queue), stop.clone())?;
        #[cfg(all(target_os = "linux", feature = "backend-linux"))]
        let (backend, thread) = linux::Backend::start(Arc::clone(&queue), stop.clone())?;
        #[cfg(all(windows, feature = "backend-windows"))]
        let backend = windows::Backend::new();
        Ok(Self {
            queue,
            stop,
            #[cfg(any(
                all(target_os = "linux", feature = "backend-linux"),
                all(windows, feature = "backend-windows")
            ))]
            backend,
            threads: Mutex::new({
                #[cfg(not(windows))]
                {
                    vec![thread]
                }
                #[cfg(windows)]
                {
                    Vec::new()
                }
            }),
        })
    }

    /// Drains a coalesced batch after 200 ms of quiet, or after one second of continuous changes.
    /// A drain never clears callbacks arriving during the subsequent fresh scan.
    pub fn drain_ready(&self) -> Option<DirectoryChanges> {
        self.queue.drain_ready()
    }

    /// Whether native watch installation can still contribute advisory invalidations.
    pub fn is_available(&self) -> bool {
        !self.stop.is_cancelled() && !self.queue.failed.load(std::sync::atomic::Ordering::Acquire)
    }

    /// Reports an inability to install a native watch. This is independent of fresh scan validity.
    pub fn report_unavailable(&self, detail: impl ToString) {
        self.queue.fail(detail);
    }

    /// Requests a full fresh revision when a separately observed root binding changed.
    /// This records an invalidation only; it supplies no cache freshness or execution evidence.
    pub fn report_gap(&self) {
        self.queue.gap();
    }

    /// Stops delivery. Call off the UI thread to also release native owners with `wait_for_exit`.
    pub fn close(&self) {
        self.stop.cancel();
    }

    /// Joins native listener threads after close. Native cancellation completion may block;
    /// session shutdown invokes this only on its worker, never the rendering thread.
    pub fn wait_for_exit(&self) {
        self.close();
        for thread in self
            .threads
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .drain(..)
        {
            let _ = thread.join();
        }
    }

    #[cfg(all(target_os = "linux", feature = "backend-linux"))]
    pub(crate) fn register_fd(&self, fd: std::os::fd::RawFd, path: &Path) -> io::Result<()> {
        self.backend.register(fd, path, &self.queue)
    }

    #[cfg(all(windows, feature = "backend-windows"))]
    pub(crate) fn register_windows(
        &self,
        handle: crate::native_handles::Admitted<std::os::windows::io::OwnedHandle>,
        path: &Path,
    ) -> io::Result<()> {
        self.backend.register(
            handle,
            path,
            Arc::clone(&self.queue),
            self.stop.clone(),
            &self.threads,
        )
    }
}
impl Drop for ChangeMonitor {
    fn drop(&mut self) {
        self.close();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn root() -> PathBuf {
        #[cfg(windows)]
        {
            PathBuf::from(r"C:\fixture")
        }
        #[cfg(not(windows))]
        {
            PathBuf::from("/fixture")
        }
    }
    fn queue(limits: ChangeMonitorLimits) -> ChangeQueue {
        ChangeQueue {
            roots: vec![root()],
            limits,
            pending: Mutex::new(Pending::default()),
            failed: std::sync::atomic::AtomicBool::new(false),
        }
    }
    fn ready(queue: &ChangeQueue) -> DirectoryChanges {
        let earlier = Instant::now() - std::time::Duration::from_secs(2);
        {
            let mut state = queue.lock();
            state.first = Some(earlier);
            state.last = Some(earlier);
        }
        queue.drain_ready().unwrap()
    }

    #[test]
    fn component_scopes_coalesce_and_git_changes_cover_repository_context() {
        let queue = queue(ChangeMonitorLimits::default());
        queue.directory(&root().join("project/target/deep"));
        queue.directory(&root().join("project/target"));
        queue.directory(&root().join("project/target-other"));
        assert_eq!(
            ready(&queue).directories,
            vec![
                root().join("project/target"),
                root().join("project/target-other")
            ]
        );
        queue.changed_path(&root().join("project/.git/refs/heads/main"));
        assert_eq!(ready(&queue).directories, vec![root().join("project")]);
        queue.directory(&root().with_file_name("unrelated"));
        assert!(queue.drain_ready().is_none());
        queue.directory(root().parent().unwrap());
        assert!(queue.drain_ready().unwrap().full_scan);
    }

    #[test]
    fn overflow_and_malformed_paths_fail_closed_and_later_batches_survive_drains() {
        let queue = queue(ChangeMonitorLimits {
            max_directories: 1,
            ..ChangeMonitorLimits::default()
        });
        queue.directory(&root().join("a"));
        assert!(
            queue.drain_ready().is_none(),
            "burst is coalesced before scheduling"
        );
        let first = ready(&queue);
        assert_eq!(first.directories, [root().join("a")]);
        // This models delivery while the consumer is scanning the first batch. No scan-end clear
        // is allowed to erase the second batch; it belongs to the next revision.
        queue.directory(&root().join("b"));
        assert_eq!(ready(&queue).directories, [root().join("b")]);
        queue.directory(&root().join("a"));
        queue.directory(&root().join("b"));
        let overflow = queue.drain_ready().unwrap();
        assert!(overflow.full_scan && overflow.directories.is_empty());
        queue.directory(&root().join("../escape"));
        assert!(queue.drain_ready().unwrap().full_scan);
        queue.fail("native delivery failed");
        assert_eq!(
            queue.drain_ready().unwrap().unavailable.as_deref(),
            Some("native delivery failed")
        );
        assert!(queue.failed.load(std::sync::atomic::Ordering::Acquire));
        assert!(
            queue.drain_ready().is_none(),
            "a permanent failure is delivered once"
        );
    }
}
