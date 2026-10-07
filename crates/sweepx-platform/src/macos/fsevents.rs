//! Minimal, read-only bindings to the macOS FSEvents change log.
//!
//! FSEvents records persistent change notifications, including content modifications. Capture
//! a cursor before observations so subsequently delivered changes remain relevant to the next
//! validation. Notifications are advisory: a recently completed write can be delivered after
//! HistoryDone, so an empty historical drain cannot prove current tree facts. Consumers need
//! independent current evidence before reusing filesystem values.
//!
//! FSEvents is a notification daemon delivered on a `CFRunLoop`, so a one-shot historical query
//! means creating a stream, briefly spinning a run loop to drain it, and tearing everything down.
//! That query releases its pointers before returning. The separate live listener owns a stream
//! on its run-loop thread across revisions and tears it down before that thread exits. Failures
//! request fresh scanning in the caller. Completeness here describes the delivered historical
//! batch, not an atomic observation barrier or a guarantee that the tree is unchanged now.

#![cfg(target_os = "macos")]

use std::ffi::{CStr, c_char, c_void};
use std::path::Path;
use std::time::{Duration, Instant};

/// Starts one live stream on its owning run-loop thread. The cursor is captured before startup
/// and traversal. A successful handshake proves installation, not an unchanged-tree barrier.
pub(crate) fn start_live(
    roots: &[std::path::PathBuf],
    queue: std::sync::Arc<crate::change_monitor::ChangeQueue>,
    stop: crate::CancellationToken,
) -> std::io::Result<std::thread::JoinHandle<()>> {
    validate_query_roots(&roots.iter().map(|p| p.as_path()).collect::<Vec<_>>())?;
    let roots = roots.to_vec();
    let since = current_event_id();
    let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel(1);
    let startup_stop = stop.clone();
    let thread = std::thread::Builder::new()
        .name("sweepx-fsevents-live".into())
        .spawn(move || {
            let _exit =
                crate::change_monitor::ListenerExit(std::sync::Arc::clone(&queue), stop.clone());
            let result = run_live(&roots, since, &queue, &stop, ready_tx);
            if let Err(error) = result {
                queue.fail(error);
            }
        })?;
    match ready_rx.recv_timeout(Duration::from_secs(5)) {
        Ok(Ok(())) => Ok(thread),
        Ok(Err(detail)) => {
            startup_stop.cancel();
            let _ = thread.join();
            Err(std::io::Error::other(detail))
        }
        Err(error) => {
            startup_stop.cancel();
            Err(std::io::Error::other(format!(
                "FSEvents startup handshake: {error}"
            )))
        }
    }
}

fn run_live(
    roots: &[std::path::PathBuf],
    since: EventId,
    queue: &crate::change_monitor::ChangeQueue,
    stop: &crate::CancellationToken,
    ready: std::sync::mpsc::SyncSender<Result<(), String>>,
) -> std::io::Result<()> {
    let _lease = match crate::native_handles::HandleLease::acquire_io() {
        Ok(lease) => lease,
        Err(error) => {
            let _ = ready.send(Err(error.to_string()));
            return Err(error);
        }
    };
    let mut strings = Vec::with_capacity(roots.len());
    for root in roots {
        let bytes = root.as_os_str().as_encoded_bytes();
        // SAFETY: validated UTF-8 roots and initialized slices; CF owns its copied strings.
        let string = unsafe {
            CFStringCreateWithBytes(
                kCFAllocatorDefault,
                bytes.as_ptr(),
                bytes.len() as CFIndex,
                CF_STRING_ENCODING_UTF8,
                0,
            )
        };
        if string.is_null() {
            release_strings(&strings);
            let _ = ready.send(Err("FSEvents path allocation failed".into()));
            return Err(std::io::Error::other("FSEvents path allocation failed"));
        }
        strings.push(string);
    }
    let array = unsafe {
        CFArrayCreate(
            kCFAllocatorDefault,
            strings.as_ptr(),
            strings.len() as CFIndex,
            &kCFTypeArrayCallBacks,
        )
    };
    if array.is_null() {
        release_strings(&strings);
        let _ = ready.send(Err("FSEvents root array allocation failed".into()));
        return Err(std::io::Error::other(
            "FSEvents root array allocation failed",
        ));
    }
    let mut context = FSEventStreamContext {
        version: 0,
        info: (queue as *const crate::change_monitor::ChangeQueue)
            .cast_mut()
            .cast(),
        retain: None,
        release: None,
        copy_description: None,
    };
    // WatchRoot reports ancestor/root renames as gaps. No IgnoreSelf: our own modifications and
    // delayed setup events must be retained. The stream survives all scan revisions in the session.
    let stream = unsafe {
        FSEventStreamCreate(
            kCFAllocatorDefault,
            live_callback,
            &mut context,
            array,
            since,
            0.1,
            CREATE_FLAG_NO_DEFER | CREATE_FLAG_FILE_EVENTS | 0x4,
        )
    };
    unsafe {
        CFRelease(array);
    }
    release_strings(&strings);
    if stream.is_null() {
        let _ = ready.send(Err("FSEventStreamCreate returned null".into()));
        return Err(std::io::Error::other("FSEventStreamCreate returned null"));
    }
    // SAFETY: native pointers stay on this thread; queue outlives invalidation and release.
    unsafe {
        FSEventStreamScheduleWithRunLoop(stream, CFRunLoopGetCurrent(), kCFRunLoopDefaultMode);
    }
    if unsafe { FSEventStreamStart(stream) } == 0 {
        unsafe {
            FSEventStreamInvalidate(stream);
            FSEventStreamRelease(stream);
        }
        let _ = ready.send(Err("FSEventStreamStart failed".into()));
        return Err(std::io::Error::other("FSEventStreamStart failed"));
    }
    let _ = ready.send(Ok(()));
    while !stop.is_cancelled() {
        unsafe {
            CFRunLoopRunInMode(kCFRunLoopDefaultMode, 0.1, 1);
        }
    }
    // Native callback ownership ends before returning and dropping its shared queue.
    unsafe {
        FSEventStreamStop(stream);
        FSEventStreamInvalidate(stream);
        FSEventStreamRelease(stream);
    }
    Ok(())
}

extern "C" fn live_callback(
    _stream: ConstFSEventStreamRef,
    info: *mut c_void,
    count: usize,
    event_paths: *mut c_void,
    flags: *const u32,
    ids: *const u64,
) {
    if info.is_null() {
        return;
    }
    // SAFETY: run_live's borrowed queue stays alive until stream teardown on this same thread.
    let queue = unsafe { &*info.cast::<crate::change_monitor::ChangeQueue>() };
    if event_paths.is_null() || flags.is_null() || ids.is_null() {
        queue.gap();
        return;
    }
    let paths = event_paths as *const *const c_char;
    for index in 0..count {
        let (path, flags) = unsafe { (*paths.add(index), *flags.add(index)) };
        if flags
            & (FLAG_MUST_SCAN_SUBDIRS
                | FLAG_USER_DROPPED
                | FLAG_KERNEL_DROPPED
                | FLAG_IDS_WRAPPED
                | FLAG_ROOT_CHANGED
                | FLAG_MOUNT
                | FLAG_UNMOUNT)
            != 0
        {
            queue.gap();
        } else if flags & FLAG_HISTORY_DONE != 0 {
            // HistoryDone is not a freshness barrier; keep the stream running for live delivery.
        } else if path.is_null() {
            queue.gap();
        } else {
            // SAFETY: FSEvents owns this terminated string during the callback. Non-UTF-8 paths
            // cannot be represented by this framework contract and therefore force a full scan.
            match unsafe { CStr::from_ptr(path) }.to_str() {
                Ok(path) => queue.changed_path(Path::new(path)),
                Err(_) => queue.gap(),
            }
        }
    }
}

/// FSEvents event identifier; per volume, monotonic, `u64`.
pub type EventId = u64;

/// One historical change under a queried root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChangeEvent {
    /// Absolute path FSEvents reported.
    pub path: String,
    /// Event id assigned to this change.
    pub id: EventId,
    /// Raw FSEvents flags; callers test the relevant bits.
    pub flags: u32,
}

/// Outcome of draining the change log since one id for a set of roots.
#[derive(Debug, Clone)]
pub struct ChangeLog {
    /// Concrete events in the completed drain; unusable history may discard its payload.
    pub events: Vec<ChangeEvent>,
    /// Set for dropped/lost/wrapped history, mount changes, malformed paths or exhausted budgets.
    ///
    /// This is the fail-closed channel: a `true` here invalidates every cached result regardless
    /// of which path the event names.
    pub must_rescan: bool,
}

// FSEvents event flag bits (verified in FSEvents.h of the active SDK).
const FLAG_MUST_SCAN_SUBDIRS: u32 = 0x0000_0001;
const FLAG_USER_DROPPED: u32 = 0x0000_0002;
const FLAG_KERNEL_DROPPED: u32 = 0x0000_0004;
const FLAG_IDS_WRAPPED: u32 = 0x0000_0008;
const FLAG_MOUNT: u32 = 0x0000_0040;
const FLAG_UNMOUNT: u32 = 0x0000_0080;
const FLAG_HISTORY_DONE: u32 = 0x0000_0010;
const FLAG_ROOT_CHANGED: u32 = 0x0000_0020;

/// `kFSEventStreamCreateFlagNoDefer`: deliver the historical batch promptly rather than waiting
/// out the latency to coalesce. We want a one-shot drain, not a live stream.
const CREATE_FLAG_NO_DEFER: u32 = 0x0000_0002;
/// `kFSEventStreamCreateFlagFileEvents`: report the exact file for every change instead of only
/// the containing directory. This is the input for file-level cache reuse: a change to one file
/// then invalidates just that file, not its whole parent directory.
const CREATE_FLAG_FILE_EVENTS: u32 = 0x0000_0010;

// Application-owned retention limits, independent of the framework's internal allocations.
const MAX_QUERY_ROOTS: usize = 256;
const MAX_QUERY_PATH_BYTES: usize = 1024 * 1024;
const MAX_HISTORY_EVENTS: usize = 65_536;
const MAX_HISTORY_BYTES: usize = 16 * 1024 * 1024;

/// UTF-8 text encoding id for `CFStringCreateWithBytes`.
const CF_STRING_ENCODING_UTF8: u32 = 0x0800_0100;

/// Most recent event id the system has produced.
///
/// Capture *before* a scan so the next validation includes writes racing with the walk.
/// A cursor taken after traversal would silently hide those writes.
pub fn current_event_id() -> EventId {
    // SAFETY: FSEventsGetCurrentEventId takes no arguments and returns a scalar.
    unsafe { FSEventsGetCurrentEventId() }
}

/// Drains every event under `roots` with an id strictly greater than `since`, bounded by
/// `timeout`.
///
/// The drain is honest about coverage. Any must-scan/dropped/root-changed event sets
/// [`ChangeLog::must_rescan`]; a clean drain yields the delivered historical event list.
/// Recently completed writes can arrive later; this is not a current-tree freshness oracle. A
/// timeout leaves the result unusable (treated by callers as a rescan) rather than partially read.
/// Query inputs are limited to 256 absolute UTF-8 roots and 1 MiB of path bytes. Owned history
/// is limited to 65,536 events and a 16 MiB estimate including path and Vec capacities. Exhaustion
/// clears retained history and requests a fresh scan; these bounds are not a process RSS limit.
pub fn events_since(
    roots: &[&Path],
    since: EventId,
    timeout: Duration,
) -> std::io::Result<ChangeLog> {
    if roots.is_empty() {
        return Ok(ChangeLog {
            events: Vec::new(),
            must_rescan: false,
        });
    }

    validate_query_roots(roots)?;
    let deadline = Instant::now()
        .checked_add(timeout)
        .ok_or_else(|| std::io::Error::other("FSEvents deadline overflow"))?;

    // Build the CFArray of path strings. Kept as owned CF values and released at the end.
    let mut cf_paths: Vec<CFStringRef> = Vec::with_capacity(roots.len());
    for root in roots {
        let bytes = root.as_os_str().as_encoded_bytes();
        // SAFETY: bytes/length describe the same initialized slice; null return handled.
        let cf = unsafe {
            CFStringCreateWithBytes(
                kCFAllocatorDefault,
                bytes.as_ptr(),
                bytes.len() as CFIndex,
                CF_STRING_ENCODING_UTF8,
                0,
            )
        };
        if cf.is_null() {
            release_strings(&cf_paths);
            return Err(std::io::Error::other(
                "could not allocate CFString for FSEvents path",
            ));
        }
        cf_paths.push(cf);
    }
    let values: Vec<*const c_void> = cf_paths.clone();
    // SAFETY: values/length describe the same initialized array; null return handled.
    let paths_array = unsafe {
        CFArrayCreate(
            kCFAllocatorDefault,
            values.as_ptr(),
            values.len() as CFIndex,
            // SAFETY: address of the extern static callback table.
            &kCFTypeArrayCallBacks,
        )
    };
    if paths_array.is_null() {
        release_strings(&cf_paths);
        return Err(std::io::Error::other(
            "could not allocate CFArray for FSEvents paths",
        ));
    }

    // State shared with the C callback; the run loop runs on this thread, and the stream is fully
    // invalidated before `collector` is dropped, so the raw pointer never outlives the data.
    let mut collector = Collector::new(MAX_HISTORY_EVENTS, MAX_HISTORY_BYTES);

    let mut context = FSEventStreamContext {
        version: 0,
        info: &mut collector as *mut Collector as *mut c_void,
        retain: None,
        release: None,
        copy_description: None,
    };

    // SAFETY: all arguments initialized; null return handled below before any use.
    let stream = unsafe {
        FSEventStreamCreate(
            kCFAllocatorDefault,
            stream_callback,
            &mut context,
            paths_array,
            since,
            // Latency 0 plus NoDefer and FileEvents: drain exact-file historical events at once.
            0.0,
            CREATE_FLAG_NO_DEFER | CREATE_FLAG_FILE_EVENTS,
        )
    };
    if stream.is_null() {
        unsafe { CFRelease(paths_array as CFTypeRef) };
        release_strings(&cf_paths);
        return Err(std::io::Error::other("FSEventStreamCreate returned null"));
    }

    // SAFETY: CFRunLoopGetCurrent on a thread lazily creates a run loop for this thread.
    let run_loop = unsafe { CFRunLoopGetCurrent() };
    // SAFETY: stream and run loop are live and the mode is a retained constant.
    unsafe {
        FSEventStreamScheduleWithRunLoop(stream, run_loop, kCFRunLoopDefaultMode);
        if FSEventStreamStart(stream) == 0 {
            // Start can fail; unwind the schedule and release below.
            FSEventStreamInvalidate(stream);
            FSEventStreamRelease(stream);
            CFRelease(paths_array as CFTypeRef);
            release_strings(&cf_paths);
            return Err(std::io::Error::other("FSEventStreamStart failed"));
        }
    }

    // Return after each handled source so HistoryDone can end the drain immediately. The
    // callback does not stop the run loop: waiting for the whole slice after it completed
    // imposed a 250 ms floor on every valid cache hit. A handled source alone does not prove
    // completeness; only the callback's HistoryDone flag ends the outer loop successfully.
    let mut timed_out = false;
    while !collector.history_done && !collector.must_rescan && !timed_out {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            timed_out = true;
            break;
        }
        let slice = remaining.min(Duration::from_millis(250)).as_secs_f64();
        // SAFETY: run loop live; returns a scalar result code.
        let _result = unsafe { CFRunLoopRunInMode(kCFRunLoopDefaultMode, slice, 1) };
    }

    // Full teardown in declared order; stopping after a timeout simply ends the live stream.
    // SAFETY: stream was started/scheduled and is live.
    unsafe {
        FSEventStreamStop(stream);
        FSEventStreamInvalidate(stream);
        FSEventStreamRelease(stream);
        CFRelease(paths_array as CFTypeRef);
    }
    release_strings(&cf_paths);

    if timed_out {
        return Err(std::io::Error::other("FSEvents drain timed out"));
    }

    Ok(ChangeLog {
        events: collector.events,
        must_rescan: collector.must_rescan,
    })
}

fn release_strings(values: &[CFStringRef]) {
    for value in values {
        // SAFETY: each is an owned CF object not otherwise released.
        unsafe { CFRelease(*value as CFTypeRef) };
    }
}

fn validate_query_roots(roots: &[&Path]) -> std::io::Result<()> {
    if roots.len() > MAX_QUERY_ROOTS {
        return Err(std::io::Error::other("FSEvents root count budget exceeded"));
    }
    let mut bytes = 0usize;
    for root in roots {
        if !root.is_absolute()
            || root.as_os_str().as_encoded_bytes().contains(&0)
            || root.to_str().is_none()
            || root
                .components()
                .any(|part| matches!(part, std::path::Component::ParentDir))
        {
            return Err(std::io::Error::other(
                "FSEvents root must be an absolute lossless path",
            ));
        }
        bytes = bytes
            .checked_add(root.as_os_str().len())
            .filter(|bytes| *bytes <= MAX_QUERY_PATH_BYTES)
            .ok_or_else(|| std::io::Error::other("FSEvents query path budget exceeded"))?;
    }
    Ok(())
}

/// Per-drain state. Reserve bounded Vec slots before allocating payload strings; once any
/// coverage or resource boundary is uncertain, release the payload and never resume collection.
struct Collector {
    events: Vec<ChangeEvent>,
    path_bytes: usize,
    event_limit: usize,
    byte_limit: usize,
    must_rescan: bool,
    history_done: bool,
}

impl Collector {
    fn new(event_limit: usize, byte_limit: usize) -> Self {
        Self {
            events: Vec::new(),
            path_bytes: 0,
            event_limit,
            byte_limit,
            must_rescan: false,
            history_done: false,
        }
    }

    fn invalidate(&mut self) {
        self.must_rescan = true;
        self.events = Vec::new();
        self.path_bytes = 0;
    }

    fn retain(&mut self, bytes: &[u8], id: EventId, flags: u32) {
        if self.must_rescan {
            return;
        }
        let Ok(text) = std::str::from_utf8(bytes) else {
            self.invalidate();
            return;
        };
        let path = Path::new(text);
        if !path.is_absolute()
            || path
                .components()
                .any(|part| matches!(part, std::path::Component::ParentDir))
            || self.events.len() >= self.event_limit
        {
            self.invalidate();
            return;
        }
        let capacity = if self.events.len() == self.events.capacity() {
            self.events
                .capacity()
                .saturating_mul(2)
                .max(1)
                .min(self.event_limit)
        } else {
            self.events.capacity()
        };
        let fits = self
            .path_bytes
            .checked_add(bytes.len())
            .and_then(|payload| {
                capacity
                    .checked_mul(std::mem::size_of::<ChangeEvent>())
                    .and_then(|slots| payload.checked_add(slots))
            })
            .is_some_and(|total| total <= self.byte_limit);
        if !fits {
            self.invalidate();
            return;
        }
        if capacity > self.events.capacity()
            && self
                .events
                .try_reserve_exact(capacity - self.events.len())
                .is_err()
        {
            self.invalidate();
            return;
        }
        // Vec may grant more capacity than requested. Refuse it before retaining any new path;
        // allocator overhead/framework storage are outside this owned-data admission estimate.
        let path = text.to_owned();
        let path_bytes = self.path_bytes.saturating_add(path.capacity());
        if path_bytes.saturating_add(
            self.events
                .capacity()
                .saturating_mul(std::mem::size_of::<ChangeEvent>()),
        ) > self.byte_limit
        {
            self.invalidate();
            return;
        }
        self.path_bytes = path_bytes;
        self.events.push(ChangeEvent { path, id, flags });
    }
}

/// FSEvents `FSEventStreamCallback`. Paths are `char **` (UseCFTypes is not enabled).
/// Flags are always processed for the whole batch, including records following HistoryDone;
/// after invalidation payload is skipped, so later flags cannot restore incomplete history.
extern "C" fn stream_callback(
    _stream: ConstFSEventStreamRef,
    info: *mut c_void,
    count: usize,
    event_paths: *mut c_void,
    flags: *const u32,
    ids: *const u64,
) {
    if info.is_null() {
        return;
    }
    // SAFETY: registered Collector is live until the stream is fully torn down on this thread.
    let collector = unsafe { &mut *(info.cast::<Collector>()) };
    if event_paths.is_null() || flags.is_null() || ids.is_null() {
        collector.invalidate();
        return;
    }
    let paths = event_paths as *const *const c_char;
    for index in 0..count {
        // SAFETY: the native callback supplies count initialized parallel array elements.
        let (raw_path, flags, id) =
            unsafe { (*paths.add(index), *flags.add(index), *ids.add(index)) };
        if flags
            & (FLAG_MUST_SCAN_SUBDIRS
                | FLAG_USER_DROPPED
                | FLAG_KERNEL_DROPPED
                | FLAG_IDS_WRAPPED
                | FLAG_ROOT_CHANGED
                | FLAG_MOUNT
                | FLAG_UNMOUNT)
            != 0
        {
            collector.invalidate();
        }
        if flags & FLAG_HISTORY_DONE != 0 {
            collector.history_done = true;
            continue;
        }
        if collector.must_rescan {
            continue;
        }
        if raw_path.is_null() {
            collector.invalidate();
            continue;
        }
        // SAFETY: FSEvents supplies a live NUL-terminated byte string for each concrete path.
        collector.retain(unsafe { CStr::from_ptr(raw_path) }.to_bytes(), id, flags);
    }
}

// ---- CoreFoundation / CoreServices extern declarations ----

type CFIndex = isize;
type Boolean = u8;
type CFTypeRef = *const c_void;
type CFAllocatorRef = *const c_void;
type CFStringRef = *const c_void;
type CFArrayRef = *const c_void;
type CFRunLoopRef = *const c_void;
type CFRunLoopMode = CFStringRef;
type FSEventStreamRef = *mut c_void;
type ConstFSEventStreamRef = *const c_void;

#[repr(C)]
struct FSEventStreamContext {
    version: CFIndex,
    info: *mut c_void,
    retain: Option<extern "C" fn(*const c_void) -> *const c_void>,
    release: Option<extern "C" fn(*const c_void)>,
    copy_description: Option<extern "C" fn() -> CFStringRef>,
}

#[repr(C)]
struct CFArrayCallBacks {
    version: CFIndex,
    retain: Option<extern "C" fn(CFAllocatorRef, CFTypeRef) -> CFTypeRef>,
    release: Option<extern "C" fn(CFAllocatorRef, CFTypeRef)>,
    copy_description: Option<extern "C" fn(CFTypeRef) -> CFStringRef>,
    equal: Option<extern "C" fn(CFTypeRef, CFTypeRef) -> Boolean>,
}

#[link(name = "CoreFoundation", kind = "framework")]
unsafe extern "C" {
    static kCFAllocatorDefault: CFAllocatorRef;
    static kCFRunLoopDefaultMode: CFRunLoopMode;
    static kCFTypeArrayCallBacks: CFArrayCallBacks;

    fn CFRelease(cf: CFTypeRef);
    fn CFArrayCreate(
        allocator: CFAllocatorRef,
        values: *const CFTypeRef,
        num_values: CFIndex,
        callbacks: *const CFArrayCallBacks,
    ) -> CFArrayRef;
    fn CFStringCreateWithBytes(
        allocator: CFAllocatorRef,
        bytes: *const u8,
        num_bytes: CFIndex,
        encoding: u32,
        is_external: Boolean,
    ) -> CFStringRef;
    fn CFRunLoopGetCurrent() -> CFRunLoopRef;
    fn CFRunLoopRunInMode(mode: CFRunLoopMode, duration: f64, return_after_source: Boolean) -> i32;
}

#[link(name = "CoreServices", kind = "framework")]
unsafe extern "C" {
    fn FSEventsGetCurrentEventId() -> EventId;
    fn FSEventStreamCreate(
        allocator: CFAllocatorRef,
        callback: extern "C" fn(
            ConstFSEventStreamRef,
            *mut c_void,
            usize,
            *mut c_void,
            *const u32,
            *const u64,
        ),
        context: *mut FSEventStreamContext,
        paths: CFArrayRef,
        since_when: EventId,
        latency: f64,
        flags: u32,
    ) -> FSEventStreamRef;
    fn FSEventStreamScheduleWithRunLoop(
        stream: FSEventStreamRef,
        run_loop: CFRunLoopRef,
        mode: CFRunLoopMode,
    );
    fn FSEventStreamStart(stream: FSEventStreamRef) -> Boolean;
    fn FSEventStreamStop(stream: FSEventStreamRef);
    fn FSEventStreamInvalidate(stream: FSEventStreamRef);
    fn FSEventStreamRelease(stream: FSEventStreamRef);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn current_event_id_is_nonzero_on_a_live_system() {
        assert!(current_event_id() > 0, "a booted system has FSEvents");
    }

    #[test]
    fn zero_deadline_refuses_history_even_when_the_stream_started() {
        let root = fs::canonicalize(std::env::temp_dir()).unwrap();
        let error = events_since(&[root.as_path()], current_event_id(), Duration::ZERO)
            .expect_err("no time to establish HistoryDone; never accept partial history");
        assert!(error.to_string().contains("timed out"), "{error}");
    }

    #[test]
    fn handled_sources_preserve_the_whole_complete_callback_batch() {
        let mut collector = Collector::new(8, 4096);
        let names =
            ["/root/a", "/root/b", "", "/root/c"].map(|name| std::ffi::CString::new(name).unwrap());
        let paths: Vec<_> = names.iter().map(|name| name.as_ptr()).collect();
        // Even a sentinel inside a delivered batch cannot discard following concrete records.
        let flags = [0, 0, FLAG_HISTORY_DONE, 0];
        let ids = [101, 102, 103, 104];
        stream_callback(
            std::ptr::null(),
            (&mut collector as *mut Collector).cast(),
            paths.len(),
            paths.as_ptr().cast_mut().cast(),
            flags.as_ptr(),
            ids.as_ptr(),
        );
        assert!(collector.history_done);
        assert!(!collector.must_rescan);
        assert_eq!(
            collector
                .events
                .iter()
                .map(|event| event.path.as_str())
                .collect::<Vec<_>>(),
            ["/root/a", "/root/b", "/root/c"]
        );
        assert_eq!(
            collector
                .events
                .iter()
                .map(|event| event.id)
                .collect::<Vec<_>>(),
            [101, 102, 104]
        );
    }

    #[test]
    fn fixture_change_is_observed_after_bounded_delivery_wait() {
        let fixture = tempfile::tempdir().expect("isolated fixture");
        // Unix temporary ancestors may be symlinked; FSEvents reports the resolved spelling.
        let root = fs::canonicalize(fixture.path()).expect("canonical fixture root");
        let file = root.join("new.txt");
        let expected_path = file.to_str().expect("controlled UTF-8 fixture");
        let baseline = current_event_id();
        fs::write(&file, b"fixture mutation").expect("write fixture");
        assert_eq!(fs::read(&file).unwrap(), b"fixture mutation");

        // HistoryDone only closes the currently delivered historical batch. Wait explicitly
        // for this known fixture's FileEvents record, retaining the pre-mutation cursor on
        // every query. A delayed setup event cannot stand in for the exact created filename.
        // This synchronization lives only in the test, never in cache hit decisions.
        let deadline = Instant::now() + Duration::from_secs(5);
        let observed = loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            assert!(
                !remaining.is_zero(),
                "fixture write was not delivered within 5 seconds"
            );
            let batch =
                events_since(&[root.as_path()], baseline, remaining).expect("drain history");
            assert!(
                !batch.must_rescan,
                "ordinary fixture write has no history gap"
            );
            if let Some(event) = batch
                .events
                .iter()
                .find(|event| event.path == expected_path)
            {
                assert!(
                    event.id > baseline,
                    "the fixture mutation follows its captured cursor"
                );
                break event.id;
            }
            std::thread::sleep(
                Duration::from_millis(25).min(deadline.saturating_duration_since(Instant::now())),
            );
        };

        // Subsequent batches must be beyond the observed mutation. They may legitimately
        // contain delayed notifications; an empty answer would not prove current quiescence.
        let later = events_since(&[root.as_path()], observed, Duration::from_secs(5))
            .expect("history beyond observed mutation");
        assert!(!later.must_rescan);
        assert!(later.events.iter().all(|event| event.id > observed));
    }
    fn deliver(collector: &mut Collector, paths: &[&[u8]], flags: &[u32]) {
        assert_eq!(paths.len(), flags.len());
        let paths: Vec<_> = paths
            .iter()
            .map(|path| std::ffi::CString::new(*path).unwrap())
            .collect();
        let pointers: Vec<_> = paths.iter().map(|path| path.as_ptr()).collect();
        let ids: Vec<_> = (1..=paths.len() as u64).collect();
        stream_callback(
            std::ptr::null(),
            (collector as *mut Collector).cast(),
            pointers.len(),
            pointers.as_ptr().cast_mut().cast(),
            flags.as_ptr(),
            ids.as_ptr(),
        );
    }

    #[test]
    fn overflow_or_gap_after_history_done_still_refuses_the_entire_batch() {
        // Literal flag values independently match the SDK declarations, rather than building
        // the test input from the implementation's gap mask. Wrapped ids invalidate old cursors.
        for flag in [0x0000_0004, 0x0000_0008, 0x0000_0040, 0x0000_0080] {
            let mut collector = Collector::new(8, 4096);
            deliver(
                &mut collector,
                &[b"/root/file", b"", b"/root/later"],
                &[0, 0x10, flag],
            );
            assert!(collector.history_done);
            assert!(collector.must_rescan, "flag {flag:#x}");
            assert!(collector.events.is_empty());
        }
        let mut collector = Collector::new(1, 4096);
        deliver(
            &mut collector,
            &[b"/root/first", b"", b"/root/second"],
            &[0, 0x10, 0],
        );
        assert!(collector.history_done);
        assert!(collector.must_rescan);
        assert!(collector.events.is_empty());
    }

    #[test]
    fn count_and_byte_exhaustion_release_payload_and_never_resume_collection() {
        let mut count = Collector::new(2, 4096);
        deliver(&mut count, &[b"/r/a", b"/r/b"], &[0, 0]);
        assert_eq!(count.events.len(), 2);
        deliver(&mut count, &[b"/r/c", b"/r/d", b""], &[0, 0, 0x10]);
        assert!(count.must_rescan && count.history_done);
        assert_eq!(count.events.capacity(), 0);
        assert_eq!(count.path_bytes, 0);

        let mut bytes = Collector::new(1000, 256);
        let path = format!("/r/{}", "x".repeat(128));
        deliver(&mut bytes, &[path.as_bytes()], &[0]);
        assert_eq!(bytes.events.len(), 1);
        deliver(&mut bytes, &[path.as_bytes(), b"/r/small"], &[0, 0]);
        assert!(bytes.must_rescan);
        assert_eq!(bytes.events.capacity(), 0);

        // Independently account actual Vec slots and string capacities, including reservation
        // growth; a lot of short paths must not evade the byte budget by only charging text.
        let mut slots = Collector::new(1000, 2048);
        for _ in 0..100 {
            deliver(&mut slots, &[b"/x"], &[0]);
            let actual = slots.events.capacity() * std::mem::size_of::<ChangeEvent>()
                + slots
                    .events
                    .iter()
                    .map(|event| event.path.capacity())
                    .sum::<usize>();
            assert!(actual <= 2048);
            if slots.must_rescan {
                break;
            }
        }
        assert!(slots.must_rescan);
        assert!(slots.events.is_empty());
    }

    #[test]
    fn malformed_native_paths_and_missing_arrays_cannot_establish_clean_history() {
        for path in [b"/r/\xff".as_slice(), b"relative", b"/r/../other"] {
            let mut collector = Collector::new(8, 4096);
            deliver(&mut collector, &[b"/r/valid", path, b""], &[0, 0, 0x10]);
            assert!(collector.must_rescan && collector.history_done);
            assert!(collector.events.is_empty());
        }
        let mut collector = Collector::new(8, 4096);
        stream_callback(
            std::ptr::null(),
            (&mut collector as *mut Collector).cast(),
            1,
            std::ptr::null_mut(),
            std::ptr::null(),
            std::ptr::null(),
        );
        assert!(collector.must_rescan);
    }

    #[test]
    fn query_count_paths_and_deadlines_are_checked_before_native_allocation() {
        use std::os::unix::ffi::OsStrExt;
        let too_many = vec![Path::new("/root"); 257];
        assert!(
            events_since(&too_many, 1, Duration::from_secs(1))
                .unwrap_err()
                .to_string()
                .contains("root count")
        );
        let long = format!("/{}", "x".repeat(600_000));
        assert!(
            events_since(
                &[Path::new(&long), Path::new(&long)],
                1,
                Duration::from_secs(1)
            )
            .unwrap_err()
            .to_string()
            .contains("path budget")
        );
        for path in [
            Path::new("relative"),
            Path::new("/r/../other"),
            Path::new(std::ffi::OsStr::from_bytes(b"/r/\xff")),
            Path::new(std::ffi::OsStr::from_bytes(b"/r/\0x")),
        ] {
            assert!(validate_query_roots(&[path]).is_err());
        }
        assert!(
            events_since(&[Path::new("/root")], 1, Duration::MAX)
                .unwrap_err()
                .to_string()
                .contains("overflow")
        );
    }
}
