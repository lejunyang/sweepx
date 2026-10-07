//! Bounded root subscriptions on asynchronous handles opened by admitted object/volume identity.
//! Each root owns one thread, one directory handle, one event and two 32 KiB buffers. Reissue
//! before parsing the completed buffer so callbacks are not lost during consumer processing.

use super::*;
use crate::native_handles::{Admitted, HandleLease};
use std::os::windows::ffi::OsStringExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle, RawHandle};
use windows_sys::Win32::Foundation::{
    ERROR_IO_PENDING, ERROR_NOTIFY_ENUM_DIR, HANDLE, WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows_sys::Win32::Storage::FileSystem::{
    FILE_NOTIFY_CHANGE_ATTRIBUTES, FILE_NOTIFY_CHANGE_DIR_NAME, FILE_NOTIFY_CHANGE_FILE_NAME,
    FILE_NOTIFY_CHANGE_LAST_WRITE, FILE_NOTIFY_CHANGE_SECURITY, FILE_NOTIFY_CHANGE_SIZE,
    ReadDirectoryChangesW,
};
use windows_sys::Win32::System::IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED};
use windows_sys::Win32::System::Threading::{CreateEventW, ResetEvent, WaitForSingleObject};

pub(super) struct Backend {
    roots: Mutex<BTreeSet<PathBuf>>,
}
impl Backend {
    pub(super) fn new() -> Self {
        Self {
            roots: Mutex::new(BTreeSet::new()),
        }
    }

    pub(super) fn register(
        &self,
        handle: Admitted<OwnedHandle>,
        path: &Path,
        queue: Arc<ChangeQueue>,
        stop: CancellationToken,
        threads: &Mutex<Vec<std::thread::JoinHandle<()>>>,
    ) -> io::Result<()> {
        let mut roots = self
            .roots
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if roots.contains(path) {
            return Ok(());
        }
        if roots.len() >= queue.limits.max_watches.min(32) {
            return Err(io::Error::other("Windows root watch budget exceeded"));
        }
        let path = path.to_path_buf();
        let worker_path = path.clone();
        let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel(1);
        let thread = std::thread::Builder::new()
            .name("sweepx-directory-changes".into())
            .spawn(move || {
                let _exit = super::ListenerExit(Arc::clone(&queue), stop.clone());
                let result = run(handle, &worker_path, &queue, &stop, ready_tx);
                if let Err(error) = result {
                    queue.fail(error);
                }
            })?;
        threads
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(thread);
        match ready_rx.recv_timeout(std::time::Duration::from_secs(5)) {
            Ok(Ok(())) => {
                roots.insert(path);
                Ok(())
            }
            Ok(Err(detail)) => Err(io::Error::other(detail)),
            Err(error) => Err(io::Error::other(format!(
                "Windows notification startup handshake: {error}"
            ))),
        }
    }
}

struct Request {
    handle: Admitted<OwnedHandle>,
    event: Admitted<OwnedHandle>,
    // Box keeps the kernel's OVERLAPPED pointer stable for the entire pending operation.
    overlapped: Box<OVERLAPPED>,
    buffer: Box<[u32; 8192]>,
    pending: bool,
}
impl Request {
    fn new(handle: Admitted<OwnedHandle>) -> io::Result<Self> {
        let lease = HandleLease::acquire_io()?;
        let event = unsafe { CreateEventW(std::ptr::null(), 1, 0, std::ptr::null()) };
        if event.is_null() {
            return Err(io::Error::last_os_error());
        }
        let event = Admitted::new(
            unsafe { OwnedHandle::from_raw_handle(event as RawHandle) },
            lease,
        );
        let mut overlapped = Box::new(OVERLAPPED::default());
        overlapped.hEvent = event.as_raw_handle() as HANDLE;
        Ok(Self {
            handle,
            event,
            overlapped,
            buffer: Box::new([0; 8192]),
            pending: false,
        })
    }
    fn issue(&mut self) -> io::Result<()> {
        unsafe {
            ResetEvent(self.event.as_raw_handle() as HANDLE);
        }
        let filter = FILE_NOTIFY_CHANGE_FILE_NAME
            | FILE_NOTIFY_CHANGE_DIR_NAME
            | FILE_NOTIFY_CHANGE_ATTRIBUTES
            | FILE_NOTIFY_CHANGE_SIZE
            | FILE_NOTIFY_CHANGE_LAST_WRITE
            | FILE_NOTIFY_CHANGE_SECURITY;
        // SAFETY: handle is asynchronous; aligned buffer and boxed OVERLAPPED remain live until
        // GetOverlappedResult completes or Drop waits for native cancellation completion.
        let result = unsafe {
            ReadDirectoryChangesW(
                self.handle.as_raw_handle() as HANDLE,
                self.buffer.as_mut_ptr().cast(),
                std::mem::size_of_val(self.buffer.as_ref()) as u32,
                1,
                filter,
                std::ptr::null_mut(),
                self.overlapped.as_mut(),
                None,
            )
        };
        if result == 0 && io::Error::last_os_error().raw_os_error() != Some(ERROR_IO_PENDING as i32)
        {
            return Err(io::Error::last_os_error());
        }
        self.pending = true;
        Ok(())
    }
}
impl Drop for Request {
    fn drop(&mut self) {
        if self.pending {
            // Do not free writable kernel buffers after merely requesting cancellation. Waiting
            // for completion is required even on errors; this runs only on the listener worker.
            unsafe {
                CancelIoEx(
                    self.handle.as_raw_handle() as HANDLE,
                    self.overlapped.as_ref(),
                );
                let mut transferred = 0;
                GetOverlappedResult(
                    self.handle.as_raw_handle() as HANDLE,
                    self.overlapped.as_ref(),
                    &mut transferred,
                    1,
                );
            }
        }
    }
}

fn run(
    handle: Admitted<OwnedHandle>,
    root: &Path,
    queue: &ChangeQueue,
    stop: &CancellationToken,
    ready: std::sync::mpsc::SyncSender<Result<(), String>>,
) -> io::Result<()> {
    let mut request = match Request::new(handle).and_then(|mut request| {
        request.issue()?;
        Ok(request)
    }) {
        Ok(request) => {
            let _ = ready.send(Ok(()));
            request
        }
        Err(error) => {
            let _ = ready.send(Err(error.to_string()));
            return Err(error);
        }
    };
    let mut completed = Box::new([0u32; 8192]);
    while !stop.is_cancelled() {
        let wait = unsafe { WaitForSingleObject(request.event.as_raw_handle() as HANDLE, 100) };
        if wait == WAIT_TIMEOUT {
            continue;
        }
        if wait != WAIT_OBJECT_0 {
            return Err(io::Error::last_os_error());
        }
        let mut bytes = 0u32;
        let result = unsafe {
            GetOverlappedResult(
                request.handle.as_raw_handle() as HANDLE,
                request.overlapped.as_ref(),
                &mut bytes,
                0,
            )
        };
        request.pending = false;
        if result == 0 {
            if io::Error::last_os_error().raw_os_error() == Some(ERROR_NOTIFY_ENUM_DIR as i32) {
                queue.gap();
                request.issue()?;
                continue;
            }
            return Err(io::Error::last_os_error());
        }
        if bytes as usize > std::mem::size_of_val(request.buffer.as_ref()) {
            queue.gap();
            return Err(io::Error::other("invalid native notification length"));
        }
        std::mem::swap(&mut completed, &mut request.buffer);
        request.issue()?;
        if bytes == 0 {
            queue.gap();
            continue;
        }
        // SAFETY: exactly the initialized completed bytes; the reissued request uses the other
        // buffer, so native writes cannot race this read-only parsing pass.
        let buffer =
            unsafe { std::slice::from_raw_parts(completed.as_ptr().cast::<u8>(), bytes as usize) };
        consume(buffer, root, queue);
    }
    Ok(())
}

fn consume(buffer: &[u8], root: &Path, queue: &ChangeQueue) {
    let mut offset = 0usize;
    loop {
        let record = &buffer[offset..];
        if record.len() < 12 {
            queue.gap();
            return;
        }
        let next = u32::from_le_bytes(record[..4].try_into().expect("checked field")) as usize;
        let action = u32::from_le_bytes(record[4..8].try_into().expect("checked field"));
        let bytes = u32::from_le_bytes(record[8..12].try_into().expect("checked field")) as usize;
        if bytes == 0
            || !bytes.is_multiple_of(2)
            || bytes > record.len() - 12
            || !(1..=5).contains(&action)
            || (next != 0 && (next < 12 + bytes || !next.is_multiple_of(4) || next >= record.len()))
        {
            queue.gap();
            return;
        }
        let units: Vec<u16> = record[12..12 + bytes]
            .as_chunks::<2>()
            .0
            .iter()
            .map(|p| u16::from_le_bytes([p[0], p[1]]))
            .collect();
        let relative = PathBuf::from(std::ffi::OsString::from_wide(&units));
        // Reject malformed/escaping names without interpreting them as filesystem authority.
        if relative
            .components()
            .any(|c| !matches!(c, Component::Normal(_)))
            || units.contains(&0)
        {
            queue.gap();
            return;
        }
        queue.changed_path(&root.join(relative));
        if next == 0 {
            break;
        }
        offset += next;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn native_records_preserve_both_rename_sides_and_reject_escape_and_truncation() {
        let root = PathBuf::from(r"C:\fixture");
        let queue = ChangeQueue {
            roots: vec![root.clone()],
            limits: ChangeMonitorLimits::default(),
            pending: Mutex::new(Pending::default()),
            failed: std::sync::atomic::AtomicBool::new(false),
        };
        let record = |name: &str, action: u32| {
            let units: Vec<_> = name.encode_utf16().collect();
            let mut data = 0u32.to_le_bytes().to_vec();
            data.extend(action.to_le_bytes());
            data.extend((units.len() as u32 * 2).to_le_bytes());
            for unit in units {
                data.extend(unit.to_le_bytes());
            }
            data
        };
        consume(&record(r"old\file", 4), &root, &queue);
        consume(&record(r"new\file", 5), &root, &queue);
        assert_eq!(
            queue.lock().paths,
            BTreeSet::from([root.join("old"), root.join("new")])
        );
        for data in [record(r"..\escape", 1), vec![0; 8], record("file", 99)] {
            consume(&data, &root, &queue);
            assert!(queue.lock().full);
        }
    }
}
