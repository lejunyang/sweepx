//! One inotify instance, registered against pinned directory descriptors before enumeration.
//! procfs resolves our live descriptor intentionally; user pathname symlinks are never reopened.
//! Kernel watches consume a separate bounded registry, not one retained fd per directory.

use super::*;
use crate::native_handles::{Admitted, HandleLease};
use std::collections::BTreeMap;
use std::ffi::CString;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

#[derive(Default)]
struct Registry {
    paths: BTreeMap<i32, WatchPath>,
    objects: BTreeMap<(u64, u64), i32>,
    bytes: usize,
}

struct WatchPath {
    path: PathBuf,
    object: (u64, u64),
}
impl WatchPath {
    fn cost(&self) -> usize {
        self.path.capacity().saturating_add(256)
    }
}
impl Registry {
    fn remove(&mut self, wd: i32) {
        if let Some(entry) = self.paths.remove(&wd) {
            self.bytes = self.bytes.saturating_sub(entry.cost());
            self.objects.remove(&entry.object);
        }
    }
}

pub(super) struct Backend {
    fd: Arc<Admitted<OwnedFd>>,
    paths: Arc<Mutex<Registry>>,
}
impl Backend {
    pub(super) fn start(
        queue: Arc<ChangeQueue>,
        stop: CancellationToken,
    ) -> io::Result<(Self, std::thread::JoinHandle<()>)> {
        let lease = HandleLease::acquire_io()?;
        // SAFETY: scalar flags; ownership of the nonnegative descriptor transfers once below.
        let fd = unsafe { libc::inotify_init1(libc::IN_CLOEXEC | libc::IN_NONBLOCK) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let fd = Arc::new(Admitted::new(unsafe { OwnedFd::from_raw_fd(fd) }, lease));
        let paths = Arc::new(Mutex::new(Registry::default()));
        let read_fd = Arc::clone(&fd);
        let read_paths = Arc::clone(&paths);
        let thread = std::thread::Builder::new()
            .name("sweepx-inotify".into())
            .spawn(move || {
                let _exit = super::ListenerExit(Arc::clone(&queue), stop.clone());
                let mut buffer = [0u8; 64 * 1024];
                while !stop.is_cancelled() {
                    let mut poll = libc::pollfd {
                        fd: read_fd.as_raw_fd(),
                        events: libc::POLLIN,
                        revents: 0,
                    };
                    // SAFETY: exactly one initialized pollfd, bounded wait for cancellation.
                    let result = unsafe { libc::poll(&mut poll, 1, 100) };
                    if result < 0 {
                        if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                            continue;
                        }
                        queue.fail(io::Error::last_os_error());
                        break;
                    }
                    if result == 0 {
                        continue;
                    }
                    if poll.revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0 {
                        queue.fail("inotify stream ended");
                        break;
                    }
                    // Hold the registry lock across the read and lookup. A concurrent registration
                    // cannot publish an event before its wd mapping, or remap a reused wd mid-batch.
                    let mut registry = read_paths
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    let count = unsafe {
                        libc::read(
                            read_fd.as_raw_fd(),
                            buffer.as_mut_ptr().cast(),
                            buffer.len(),
                        )
                    };
                    if count < 0 {
                        if matches!(
                            io::Error::last_os_error().kind(),
                            io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                        ) {
                            continue;
                        }
                        queue.fail(io::Error::last_os_error());
                        break;
                    }
                    if count == 0 {
                        queue.fail("inotify returned EOF");
                        break;
                    }
                    consume(&buffer[..count as usize], &mut registry, &queue);
                }
            })?;
        Ok((Self { fd, paths }, thread))
    }

    pub(super) fn register(
        &self,
        directory_fd: RawFd,
        path: &Path,
        queue: &ChangeQueue,
    ) -> io::Result<()> {
        let mut registry = self
            .paths
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
        // SAFETY: the borrowed scan descriptor stays live throughout registration.
        if unsafe { libc::fstat(directory_fd, stat.as_mut_ptr()) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let stat = unsafe { stat.assume_init() };
        let object = (stat.st_dev, stat.st_ino);
        if let Some(wd) = registry.objects.get(&object).copied() {
            let previous = &registry.paths[&wd];
            if previous.path != path {
                // Retained watches follow inodes across rename; old display mappings cannot be
                // promoted to the new namespace. A full revision rebuilds the watch instance.
                queue.gap();
            }
            return Ok(());
        }
        let retained = WatchPath {
            path: path.to_path_buf(),
            object,
        };
        if registry.paths.len() >= queue.limits.max_watches
            || registry.bytes.saturating_add(retained.cost()) > queue.limits.max_watch_bytes
        {
            return Err(io::Error::other("inotify watch registry budget exceeded"));
        }
        // No access/open/close-read notifications: our own scans must not cause refresh loops.
        let mask = libc::IN_MODIFY
            | libc::IN_ATTRIB
            | libc::IN_CLOSE_WRITE
            | libc::IN_CREATE
            | libc::IN_DELETE
            | libc::IN_MOVED_FROM
            | libc::IN_MOVED_TO
            | libc::IN_DELETE_SELF
            | libc::IN_MOVE_SELF
            | libc::IN_UNMOUNT
            | libc::IN_ONLYDIR;
        let proc_path =
            CString::new(format!("/proc/self/fd/{directory_fd}")).expect("numeric fd has no NUL");
        // SAFETY: both descriptors are live for this call; procfs follows only our pinned fd.
        let wd = unsafe { libc::inotify_add_watch(self.fd.as_raw_fd(), proc_path.as_ptr(), mask) };
        if wd < 0 {
            return Err(io::Error::last_os_error());
        }
        if registry.paths.contains_key(&wd) {
            // Descriptor reuse/wrap is a gap, including any still queued old IGNORED records.
            queue.gap();
            registry.remove(wd);
        }
        registry.bytes = registry.bytes.saturating_add(retained.cost());
        registry.objects.insert(object, wd);
        registry.paths.insert(wd, retained);
        Ok(())
    }
}

fn consume(buffer: &[u8], registry: &mut Registry, queue: &ChangeQueue) {
    let mut offset = 0usize;
    while offset < buffer.len() {
        let header = std::mem::size_of::<libc::inotify_event>();
        if buffer.len() - offset < header {
            queue.gap();
            return;
        }
        // SAFETY: checked fixed header; kernel byte buffers need not meet struct alignment.
        let event = unsafe {
            std::ptr::read_unaligned(buffer.as_ptr().add(offset).cast::<libc::inotify_event>())
        };
        let Some(end) = offset
            .checked_add(header)
            .and_then(|v| v.checked_add(event.len as usize))
            .filter(|end| *end <= buffer.len())
        else {
            queue.gap();
            return;
        };
        if event.mask & (libc::IN_Q_OVERFLOW | libc::IN_UNMOUNT | libc::IN_MOVE_SELF) != 0 {
            queue.gap();
        } else if event.mask & (libc::IN_DELETE_SELF | libc::IN_IGNORED) != 0 {
            if let Some(path) = registry.paths.get(&event.wd) {
                if queue.roots.contains(&path.path) {
                    queue.gap();
                } else {
                    queue.directory(path.path.parent().unwrap_or(&path.path));
                }
            } else {
                queue.gap();
            }
            if event.mask & libc::IN_IGNORED != 0 {
                registry.remove(event.wd);
            }
        } else if let Some(path) = registry.paths.get(&event.wd) {
            // Watching each admitted directory makes names unnecessary: changes to children
            // select their containing directory, including new/deleted/replaced directories.
            queue.directory(&path.path);
        } else {
            queue.gap();
        }
        offset = end;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn malformed_unknown_and_overflow_records_request_full_scan() {
        let root = PathBuf::from("/fixture");
        for (wd, mask, len) in [
            (5i32, libc::IN_MODIFY, 0u32),
            (-1, libc::IN_Q_OVERFLOW, 0),
            (3, libc::IN_MODIFY, 100),
        ] {
            let queue = ChangeQueue {
                roots: vec![root.clone()],
                limits: ChangeMonitorLimits::default(),
                pending: Mutex::new(Pending::default()),
                failed: std::sync::atomic::AtomicBool::new(false),
            };
            let mut buffer = Vec::new();
            buffer.extend(wd.to_ne_bytes());
            buffer.extend(mask.to_ne_bytes());
            buffer.extend(0u32.to_ne_bytes());
            buffer.extend(len.to_ne_bytes());
            let mut registry = Registry {
                paths: BTreeMap::from([(
                    3,
                    WatchPath {
                        path: root.clone(),
                        object: (1, 2),
                    },
                )]),
                objects: BTreeMap::from([((1, 2), 3)]),
                bytes: root.capacity() + 256,
            };
            consume(&buffer, &mut registry, &queue);
            assert!(queue.lock().full);
        }
    }
}
