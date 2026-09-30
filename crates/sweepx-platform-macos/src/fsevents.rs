//! Minimal, read-only bindings to the macOS FSEvents change log.
//!
//! FSEvents records a persistent, per-volume, monotonically increasing event for every change
//! the filesystem notices, including file content modifications. That is the missing input for a
//! reusable scan cache: at scan time we capture the current event id, and on the next scan we ask
//! FSEvents for every event *since* that id under a root. No event under the root means its stored
//! result is still true; any event (or a dropped/history-lost flag) invalidates it.
//!
//! FSEvents is a notification daemon delivered on a `CFRunLoop`, so a one-shot historical query
//! means creating a stream, briefly spinning a run loop to drain it, and tearing everything down.
//! All pointers are released and nothing outlives the function that created them. Failures always
//! degrade to "rescan" in the caller; this module never claims a root is unchanged unless the
//! change log itself says the history is complete and empty for it.

#![cfg(target_os = "macos")]

use std::ffi::{CStr, c_char, c_void};
use std::path::Path;
use std::time::{Duration, Instant};

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
    /// Every event delivered before the `HistoryDone` sentinel.
    pub events: Vec<ChangeEvent>,
    /// Set when FSEvents asked us to rescan (dropped events, lost history, or a changed root).
    ///
    /// This is the fail-closed channel: a `true` here invalidates every cached result regardless
    /// of which path the event names.
    pub must_rescan: bool,
}

// FSEvents event flag bits (verified in FSEvents.h of the active SDK).
const FLAG_MUST_SCAN_SUBDIRS: u32 = 0x0000_0001;
const FLAG_USER_DROPPED: u32 = 0x0000_0002;
const FLAG_KERNEL_DROPPED: u32 = 0x0000_0004;
const FLAG_HISTORY_DONE: u32 = 0x0000_0010;
const FLAG_ROOT_CHANGED: u32 = 0x0000_0020;

/// `kFSEventStreamCreateFlagNoDefer`: deliver the historical batch promptly rather than waiting
/// out the latency to coalesce. We want a one-shot drain, not a live stream.
const CREATE_FLAG_NO_DEFER: u32 = 0x0000_0002;

/// UTF-8 text encoding id for `CFStringCreateWithBytes`.
const CF_STRING_ENCODING_UTF8: u32 = 0x0800_0100;

/// Most recent event id the system has produced.
///
/// Captured *after* a scan so it can only over-invalidate: an id taken before the walk would miss
/// writes racing with the scan.
pub fn current_event_id() -> EventId {
    // SAFETY: FSEventsGetCurrentEventId takes no arguments and returns a scalar.
    unsafe { FSEventsGetCurrentEventId() }
}

/// Drains every event under `roots` with an id strictly greater than `since`, bounded by
/// `timeout`.
///
/// The drain is honest about coverage. Any must-scan/dropped/root-changed event sets
/// [`ChangeLog::must_rescan`]; a clean, fully drained history yields the exact event list. A
/// timeout leaves the result unusable (treated by callers as a rescan) rather than partially read.
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
    let mut collector = Collector {
        events: Vec::new(),
        must_rescan: false,
        history_done: false,
    };

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
            // Latency 0 plus NoDefer: drain historical events immediately.
            0.0,
            CREATE_FLAG_NO_DEFER,
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

    let deadline = Instant::now() + timeout;
    // Drain until the callback observes HistoryDone. Each RunInMode returns when a source is
    // handled (the callback stops the loop on HistoryDone) or when its slice times out.
    let mut timed_out = false;
    while !collector.history_done && !timed_out {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            timed_out = true;
            break;
        }
        let slice = remaining.min(Duration::from_millis(250)).as_secs_f64();
        // SAFETY: run loop live; returns a scalar result code.
        let _result = unsafe { CFRunLoopRunInMode(kCFRunLoopDefaultMode, slice, 0) };
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

/// Per-drain state populated by the FSEvents callback.
struct Collector {
    events: Vec<ChangeEvent>,
    must_rescan: bool,
    history_done: bool,
}

/// FSEvents `FSEventStreamCallback`.
///
/// `event_paths` is a `char **` because we did not set `kFSEventStreamCreateFlagUseCFTypes`;
/// `flags` and `ids` are parallel arrays.
extern "C" fn stream_callback(
    _stream: ConstFSEventStreamRef,
    info: *mut c_void,
    count: usize,
    event_paths: *mut c_void,
    flags: *const u32,
    ids: *const u64,
) {
    if info.is_null() || event_paths.is_null() || flags.is_null() || ids.is_null() {
        return;
    }
    // SAFETY: `info` is the `Collector` pointer registered in the context, live for the whole run.
    let collector = unsafe { &mut *(info.cast::<Collector>()) };
    let paths = event_paths as *const *const c_char;

    for index in 0..count {
        // SAFETY: the arrays carry `count` initialized elements for this callback.
        let (raw_path, flags, id) =
            unsafe { (*paths.add(index), *flags.add(index), *ids.add(index)) };
        // SAFETY: FSEvents provides a NUL-terminated UTF-8 C string.
        let path = unsafe { CStr::from_ptr(raw_path) }
            .to_string_lossy()
            .into_owned();

        if flags
            & (FLAG_MUST_SCAN_SUBDIRS | FLAG_USER_DROPPED | FLAG_KERNEL_DROPPED | FLAG_ROOT_CHANGED)
            != 0
        {
            collector.must_rescan = true;
        }
        if flags & FLAG_HISTORY_DONE != 0 {
            collector.history_done = true;
        }
        // The HistoryDone sentinel names no real path; keep only concrete events.
        if flags & FLAG_HISTORY_DONE == 0 {
            collector.events.push(ChangeEvent { path, id, flags });
        }
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
    fn detects_a_change_under_a_root_and_then_a_clean_history() {
        let dir = std::env::temp_dir().join(format!("sweepx-fsevents-{}", std::process::id()));
        // macOS TMPDIR is under a symlinked ancestor (/var -> /private/var); canonicalize so the
        // queried path matches what FSEvents reports.
        fs::create_dir_all(&dir).expect("temp dir");
        let dir = fs::canonicalize(&dir).expect("canonical temp dir");

        // Establish a baseline id after the directory creation.
        let baseline = current_event_id();
        // A creation strictly after the baseline must show up under the root.
        fs::write(dir.join("new.txt"), b"x").expect("write");
        let changed =
            events_since(&[dir.as_path()], baseline, Duration::from_secs(5)).expect("drain");
        // Without the FileEvents flag FSEvents reports at directory granularity: creating
        // new.txt surfaces an event naming its parent directory (the fixture root), not the
        // file. That is exactly the "something changed under this path" signal a cache needs.
        let root_prefix = format!("{}/", dir.display());
        assert!(
            changed
                .events
                .iter()
                .any(|event| event.path == root_prefix || event.path.starts_with(&root_prefix)),
            "the parent directory of the new file must be reported; got {:?}",
            changed.events
        );
        assert!(
            !changed.must_rescan,
            "an ordinary write is not a dropped history"
        );

        // A fresh query past the last event id reports a clean, empty history.
        let latest = current_event_id();
        let clean = events_since(&[dir.as_path()], latest, Duration::from_secs(5)).expect("drain");
        assert!(clean.events.is_empty(), "no writes since the latest id");
        assert!(!clean.must_rescan);

        let _ = fs::remove_dir_all(&dir);
    }
}
