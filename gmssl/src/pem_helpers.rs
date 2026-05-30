// PEM and DER helper functions using fmemopen/open_memstream.
//
// These provide in-memory I/O for C functions that use FILE* pointers,
// avoiding the need to write temporary files to disk.

use crate::error::GmsslError;
use libc::{c_char, c_int, c_void, size_t, FILE};
use std::ffi::CString;
use std::io;
use std::ptr;

/// Open a FILE* from a byte buffer for reading (uses POSIX fmemopen).
///
/// # Safety
/// The caller must ensure the returned FILE* is closed via `libc::fclose`.
pub(crate) unsafe fn file_from_bytes(data: &[u8]) -> Result<*mut FILE, GmsslError> {
    let mode = CString::new("rb").unwrap();
    let fp = libc::fmemopen(data.as_ptr() as *mut c_void, data.len(), mode.as_ptr());
    if fp.is_null() {
        Err(GmsslError::IoError(io::Error::last_os_error()))
    } else {
        Ok(fp)
    }
}

/// Execute a C function that writes PEM output to a FILE*, capturing the output.
///
/// Uses POSIX `open_memstream` to capture the written data into a `Vec<u8>`.
///
/// # Safety
/// The `writer` closure is given a FILE* and must return 1 on success.
pub(crate) unsafe fn collect_to_bytes<F>(writer: F) -> Result<Vec<u8>, GmsslError>
where
    F: FnOnce(*mut FILE) -> c_int,
{
    let mut buf: *mut c_char = ptr::null_mut();
    let mut size: size_t = 0;
    let _mode = CString::new("wb").unwrap();
    let fp = libc::open_memstream(&mut buf, &mut size);
    if fp.is_null() {
        return Err(GmsslError::IoError(io::Error::last_os_error()));
    }
    let ret = writer(fp);
    libc::fclose(fp);
    if ret != 1 {
        if !buf.is_null() {
            libc::free(buf as *mut c_void);
        }
        return Err(GmsslError::LibraryError("PEM write failed"));
    }
    // fflush is needed before reading buf
    // open_memstream data is available after fflush or fclose
    let result = if size > 0 && !buf.is_null() {
        std::slice::from_raw_parts(buf as *const u8, size).to_vec()
    } else {
        Vec::new()
    };
    libc::free(buf as *mut c_void);
    Ok(result)
}

/// Open a FILE* from a file path.
///
/// # Safety
/// The caller must ensure the returned FILE* is closed via `libc::fclose`.
pub(crate) unsafe fn file_open_read(path: &str) -> Result<*mut FILE, GmsslError> {
    let c_path = CString::new(path).map_err(|_| {
        GmsslError::InvalidInput("path contains NUL byte")
    })?;
    let c_mode = CString::new("rb").unwrap();
    let fp = libc::fopen(c_path.as_ptr(), c_mode.as_ptr());
    if fp.is_null() {
        Err(GmsslError::IoError(io::Error::last_os_error()))
    } else {
        Ok(fp)
    }
}

/// Open a FILE* for writing to a file path.
///
/// # Safety
/// The caller must ensure the returned FILE* is closed via `libc::fclose`.
pub(crate) unsafe fn file_open_write(path: &str) -> Result<*mut FILE, GmsslError> {
    let c_path = CString::new(path).map_err(|_| {
        GmsslError::InvalidInput("path contains NUL byte")
    })?;
    let c_mode = CString::new("wb").unwrap();
    let fp = libc::fopen(c_path.as_ptr(), c_mode.as_ptr());
    if fp.is_null() {
        Err(GmsslError::IoError(io::Error::last_os_error()))
    } else {
        Ok(fp)
    }
}

/// Helper: execute a PEM-reading C function from an in-memory byte buffer.
///
/// The C function receives a FILE* opened with fmemopen from the provided data.
/// Returns the function's return value.
pub(crate) fn read_pem_data<F>(pem_data: &[u8], f: F) -> Result<c_int, GmsslError>
where
    F: FnOnce(*mut FILE) -> c_int,
{
    unsafe {
        let fp = file_from_bytes(pem_data)?;
        let ret = f(fp);
        libc::fclose(fp);
        Ok(ret)
    }
}

/// Helper: collect DER output from a C function that uses the `uint8_t **out, size_t *outlen` pattern.
///
/// # Safety
/// The closure must call a C function that writes DER data using the pointer-pointer pattern.
pub(crate) unsafe fn collect_der<F>(max_size: usize, f: F) -> Result<Vec<u8>, GmsslError>
where
    F: FnOnce(*mut *mut u8, *mut size_t) -> c_int,
{
    let mut buf = vec![0u8; max_size];
    let start = buf.as_mut_ptr();
    let mut ptr: *mut u8 = start;
    let mut len: size_t = max_size;
    let ret = f(&mut ptr, &mut len);
    if ret != 1 {
        return Err(GmsslError::LibraryError("DER encoding failed"));
    }
    // Use pointer arithmetic (how far `ptr` advanced) rather than `len`
    // because some GmSSL functions write total bytes to len instead of remaining.
    let written = (ptr as usize).saturating_sub(start as usize);
    buf.truncate(written);
    Ok(buf)
}

/// Helper: parse DER data with a C function that uses the `const uint8_t **in, size_t *inlen` pattern.
///
/// # Safety
/// The closure must call a C function that reads DER data using the pointer-pointer pattern.
pub(crate) unsafe fn parse_der<T, F>(data: &[u8], f: F) -> Result<T, GmsslError>
where
    F: FnOnce(*mut T, *mut *const u8, *mut size_t) -> c_int,
{
    let mut result = std::mem::MaybeUninit::<T>::uninit();
    let mut ptr: *const u8 = data.as_ptr();
    let mut len: size_t = data.len();
    let ret = f(result.as_mut_ptr(), &mut ptr, &mut len);
    if ret != 1 {
        return Err(GmsslError::LibraryError("DER decoding failed"));
    }
    Ok(result.assume_init())
}
