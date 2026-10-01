//! Test-only GIO Trash qualification adapter.
//!
//! This module is nested under `trash_qualification`, which is compiled only
//! for Linux unit tests. It intentionally exposes no crate or product API.
//! GIO accepts only a pathname for `g_file_trash`; the parent-descriptor and
//! exact-basename binding is therefore rechecked immediately before that
//! unavoidable pathname handoff. No unlink or Permanent fallback exists here.

use std::ffi::{CStr, c_char, c_int, c_uint, c_void};
use std::ptr;

use libloading::Library;

use super::{
    BackendError, BackendErrorClass, BackendSubmission, BoundTrashBackend, DurableIntentToken,
    PrivateNativeTarget, TrashBackend,
};

const G_FILE_QUERY_INFO_NOFOLLOW_SYMLINKS: c_int = 1;
const G_IO_ERROR_NOT_SUPPORTED: c_int = 15;
const CAN_TRASH_ATTRIBUTE: &CStr = c"access::can-trash";
const GIO_LIBRARY: &str = "libgio-2.0.so.0";
const GOBJECT_LIBRARY: &str = "libgobject-2.0.so.0";
const GLIB_LIBRARY: &str = "libglib-2.0.so.0";

#[repr(C)]
struct GError {
    domain: c_uint,
    code: c_int,
    message: *mut c_char,
}

type GFileNewForPath = unsafe extern "C" fn(*const c_char) -> *mut c_void;
type GFileQueryInfo = unsafe extern "C" fn(
    *mut c_void,
    *const c_char,
    c_int,
    *mut c_void,
    *mut *mut GError,
) -> *mut c_void;
type GFileInfoGetAttributeBoolean = unsafe extern "C" fn(*mut c_void, *const c_char) -> c_int;
type GFileTrash = unsafe extern "C" fn(*mut c_void, *mut c_void, *mut *mut GError) -> c_int;
type GIoErrorQuark = unsafe extern "C" fn() -> c_uint;
type GObjectUnref = unsafe extern "C" fn(*mut c_void);
type GErrorFree = unsafe extern "C" fn(*mut GError);

pub(super) trait GioCalls {
    fn can_trash(&self, path: &CStr) -> Result<bool, BackendError>;
    fn trash(&self, path: &CStr) -> BackendSubmission;
}

pub(super) struct LoadedGio {
    // The libraries must outlive every function pointer resolved from them.
    _gio: Library,
    _gobject: Library,
    _glib: Library,
    file_new_for_path: GFileNewForPath,
    file_query_info: GFileQueryInfo,
    file_info_get_attribute_boolean: GFileInfoGetAttributeBoolean,
    file_trash: GFileTrash,
    io_error_quark: GIoErrorQuark,
    object_unref: GObjectUnref,
    error_free: GErrorFree,
}

impl LoadedGio {
    fn load() -> Result<Self, BackendError> {
        Self::load_named(GIO_LIBRARY, GOBJECT_LIBRARY, GLIB_LIBRARY)
    }

    fn load_named(
        gio_name: &str,
        gobject_name: &str,
        glib_name: &str,
    ) -> Result<Self, BackendError> {
        // SAFETY: each fixed SONAME is loaded only into this test-only adapter,
        // and the Library handles are retained for every copied symbol's life.
        let gio = unsafe { Library::new(gio_name) }
            .map_err(|error| BackendError::unavailable(format!("load {gio_name}: {error}")))?;
        // SAFETY: same lifetime rule as above.
        let gobject = unsafe { Library::new(gobject_name) }
            .map_err(|error| BackendError::unavailable(format!("load {gobject_name}: {error}")))?;
        // SAFETY: same lifetime rule as above.
        let glib = unsafe { Library::new(glib_name) }
            .map_err(|error| BackendError::unavailable(format!("load {glib_name}: {error}")))?;

        // SAFETY: every symbol name and function signature is copied verbatim
        // from the stable GLib/GIO C ABI; retained libraries keep them valid.
        let file_new_for_path = unsafe { load_symbol(&gio, b"g_file_new_for_path\0")? };
        // SAFETY: see the ABI/lifetime justification above.
        let file_query_info = unsafe { load_symbol(&gio, b"g_file_query_info\0")? };
        // SAFETY: see the ABI/lifetime justification above.
        let file_info_get_attribute_boolean =
            unsafe { load_symbol(&gio, b"g_file_info_get_attribute_boolean\0")? };
        // SAFETY: see the ABI/lifetime justification above.
        let file_trash = unsafe { load_symbol(&gio, b"g_file_trash\0")? };
        // SAFETY: see the ABI/lifetime justification above.
        let io_error_quark = unsafe { load_symbol(&gio, b"g_io_error_quark\0")? };
        // SAFETY: see the ABI/lifetime justification above.
        let object_unref = unsafe { load_symbol(&gobject, b"g_object_unref\0")? };
        // SAFETY: see the ABI/lifetime justification above.
        let error_free = unsafe { load_symbol(&glib, b"g_error_free\0")? };

        Ok(Self {
            _gio: gio,
            _gobject: gobject,
            _glib: glib,
            file_new_for_path,
            file_query_info,
            file_info_get_attribute_boolean,
            file_trash,
            io_error_quark,
            object_unref,
            error_free,
        })
    }

    fn file_for_path(&self, path: &CStr) -> Result<GObjectGuard<'_>, BackendError> {
        // SAFETY: path is NUL-terminated and the function pointer was resolved
        // from the retained GIO library with the documented ABI.
        let file = unsafe { (self.file_new_for_path)(path.as_ptr()) };
        GObjectGuard::new(file, self.object_unref).ok_or_else(|| {
            BackendError::ambiguous("g_file_new_for_path returned null without GError")
        })
    }

    fn take_error(&self, error: *mut GError, context: &str) -> BackendError {
        if error.is_null() {
            return BackendError::ambiguous(format!(
                "{context} failed without a GError; submission state is unknown"
            ));
        }
        // SAFETY: GIO returned a live GError pointer owned by the caller. Its
        // scalar fields and NUL-terminated message are valid until g_error_free.
        let (domain, code, detail) = unsafe {
            let error_ref = &*error;
            let detail = if error_ref.message.is_null() {
                format!("{context} failed without an error message")
            } else {
                CStr::from_ptr(error_ref.message)
                    .to_string_lossy()
                    .into_owned()
            };
            (error_ref.domain, error_ref.code, detail)
        };
        // SAFETY: error was returned by GIO and has not previously been freed.
        unsafe { (self.error_free)(error) };
        // SAFETY: the quark function takes no arguments and was resolved with
        // the documented GIO ABI.
        let io_domain = unsafe { (self.io_error_quark)() };
        let class = if domain == io_domain && code == G_IO_ERROR_NOT_SUPPORTED {
            BackendErrorClass::NotSupported
        } else {
            BackendErrorClass::Other
        };
        BackendError {
            domain,
            code,
            class,
            detail,
        }
    }
}

impl GioCalls for LoadedGio {
    fn can_trash(&self, path: &CStr) -> Result<bool, BackendError> {
        let file = self.file_for_path(path)?;
        let mut error = ptr::null_mut();
        // SAFETY: file is a live GFile, all pointers remain valid for the call,
        // and the result is guarded and unreferenced exactly once below.
        let info = unsafe {
            (self.file_query_info)(
                file.as_ptr(),
                CAN_TRASH_ATTRIBUTE.as_ptr(),
                G_FILE_QUERY_INFO_NOFOLLOW_SYMLINKS,
                ptr::null_mut(),
                &mut error,
            )
        };
        let info = match GObjectGuard::new(info, self.object_unref) {
            Some(info) => info,
            None => return Err(self.take_error(error, "GIO can-trash probe")),
        };
        if !error.is_null() {
            return Err(self.take_error(error, "GIO can-trash probe contradicted success"));
        }
        // SAFETY: info is a live GFileInfo and the static attribute name is
        // NUL-terminated for the duration of this call.
        Ok(unsafe {
            (self.file_info_get_attribute_boolean)(info.as_ptr(), CAN_TRASH_ATTRIBUTE.as_ptr()) != 0
        })
    }

    fn trash(&self, path: &CStr) -> BackendSubmission {
        let file = match self.file_for_path(path) {
            Ok(file) => file,
            Err(error) => return BackendSubmission::NotSubmitted(error),
        };
        let mut error = ptr::null_mut();
        // SAFETY: file is a live GFile and error is a writable out pointer. A
        // null cancellable deliberately prevents this seam adding cancellation.
        let result = unsafe { (self.file_trash)(file.as_ptr(), ptr::null_mut(), &mut error) };
        match (result != 0, error.is_null()) {
            (true, true) => BackendSubmission::ReportedSuccess,
            (false, false) => {
                BackendSubmission::ReportedFailure(self.take_error(error, "g_file_trash"))
            }
            (true, false) => BackendSubmission::Ambiguous(
                self.take_error(error, "g_file_trash returned success with GError"),
            ),
            (false, true) => BackendSubmission::Ambiguous(BackendError::ambiguous(
                "g_file_trash returned failure without GError",
            )),
        }
    }
}

unsafe fn load_symbol<T: Copy>(library: &Library, symbol: &[u8]) -> Result<T, BackendError> {
    // SAFETY: the caller supplies the documented function-pointer type for the
    // exact C ABI symbol and retains the library for the copied pointer's life.
    let resolved = unsafe { library.get::<T>(symbol) }.map_err(|error| {
        let name = CStr::from_bytes_with_nul(symbol)
            .map(CStr::to_string_lossy)
            .unwrap_or_else(|_| "<invalid-symbol>".into());
        BackendError::unavailable(format!("resolve {name}: {error}"))
    })?;
    Ok(*resolved)
}

struct GObjectGuard<'a> {
    pointer: *mut c_void,
    unref: GObjectUnref,
    _owner: std::marker::PhantomData<&'a LoadedGio>,
}

impl<'a> GObjectGuard<'a> {
    fn new(pointer: *mut c_void, unref: GObjectUnref) -> Option<Self> {
        (!pointer.is_null()).then_some(Self {
            pointer,
            unref,
            _owner: std::marker::PhantomData,
        })
    }

    fn as_ptr(&self) -> *mut c_void {
        self.pointer
    }
}

impl Drop for GObjectGuard<'_> {
    fn drop(&mut self) {
        // SAFETY: pointer is non-null, owned by this guard, and unref is the
        // matching GObject release function from the retained library.
        unsafe { (self.unref)(self.pointer) };
    }
}

pub(super) struct GioTrashBackend<L = fn() -> Result<LoadedGio, BackendError>> {
    load: L,
}

impl GioTrashBackend {
    pub(super) fn dynamically_loaded() -> Self {
        Self {
            load: LoadedGio::load,
        }
    }
}

impl<L> GioTrashBackend<L> {
    pub(super) fn with_loader(load: L) -> Self {
        Self { load }
    }
}

impl<L, G> TrashBackend for GioTrashBackend<L>
where
    L: FnOnce() -> Result<G, BackendError>,
    G: GioCalls,
{
    type Bound = BoundGioTrash<G>;

    fn probe_and_bind(self, target: PrivateNativeTarget) -> Result<Self::Bound, BackendError> {
        let gio = (self.load)()?;
        target
            .verify_exact_binding()
            .map_err(|error| BackendError::synthetic(error.to_string()))?;
        if !gio.can_trash(target.gio_path())? {
            return Err(BackendError {
                domain: 0,
                code: G_IO_ERROR_NOT_SUPPORTED,
                class: BackendErrorClass::NotSupported,
                detail: "GIO access::can-trash is false".to_string(),
            });
        }
        target
            .verify_exact_binding()
            .map_err(|error| BackendError::synthetic(error.to_string()))?;
        Ok(BoundGioTrash { gio, target })
    }
}

pub(super) struct BoundGioTrash<G> {
    gio: G,
    target: PrivateNativeTarget,
}

impl<G: GioCalls> BoundTrashBackend for BoundGioTrash<G> {
    fn submit_trash(self, intent: &DurableIntentToken) -> BackendSubmission {
        if let Err(error) = intent.verify() {
            return BackendSubmission::NotSubmitted(BackendError::synthetic(format!(
                "durable intent verification failed at GIO boundary: {error}"
            )));
        }
        if let Err(error) = self.target.verify_exact_binding() {
            return BackendSubmission::NotSubmitted(BackendError::synthetic(format!(
                "exact target binding failed at GIO boundary: {error}"
            )));
        }
        self.gio.trash(self.target.gio_path())
    }

    fn adapter_label(&self) -> &'static str {
        "gio-g_file_trash-test-only"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unavailable_backend_is_reported_without_a_fallback() {
        let error = LoadedGio::load_named(
            "libgio-sweepx-deliberately-missing.so",
            GOBJECT_LIBRARY,
            GLIB_LIBRARY,
        )
        .err()
        .expect("missing backend must fail");
        assert_eq!(error.class, BackendErrorClass::Unavailable);
        assert!(
            error
                .detail
                .contains("libgio-sweepx-deliberately-missing.so")
        );
    }

    #[test]
    fn adapter_surface_contains_no_permanent_or_unlink_symbol() {
        let source = include_str!("gio_trash.rs");
        let forbidden = [
            concat!("submit_", "permanent"),
            concat!("delete_", "permanently"),
            concat!("g_file_", "delete"),
            concat!("libc::", "unlink"),
            concat!("Command::", "new"),
        ];
        for symbol in forbidden {
            assert!(
                !source.contains(symbol),
                "test-only GIO adapter must not contain forbidden path: {symbol}"
            );
        }
        assert!(source.contains("g_file_trash"));
    }
}
