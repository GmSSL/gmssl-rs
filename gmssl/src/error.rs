// GmSSL error types and helper functions.

use std::fmt;

/// Errors that can occur when using the GmSSL library.
#[derive(Debug)]
pub enum GmsslError {
    /// The underlying C library returned a failure.
    LibraryError(&'static str),
    /// An invalid key was provided (wrong size, bad format).
    InvalidKey(&'static str),
    /// Invalid input parameters.
    InvalidInput(&'static str),
    /// An I/O error occurred (file not found, permission denied, etc.).
    IoError(std::io::Error),
    /// Signature verification failed (the signature does not match).
    VerificationFailed,
    /// Decryption failed (bad padding, wrong key, tag mismatch).
    DecryptionFailed,
}

impl fmt::Display for GmsslError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GmsslError::LibraryError(ctx) => write!(f, "GmSSL library error: {}", ctx),
            GmsslError::InvalidKey(msg) => write!(f, "Invalid key: {}", msg),
            GmsslError::InvalidInput(msg) => write!(f, "Invalid input: {}", msg),
            GmsslError::IoError(e) => write!(f, "I/O error: {}", e),
            GmsslError::VerificationFailed => write!(f, "Verification failed"),
            GmsslError::DecryptionFailed => write!(f, "Decryption failed"),
        }
    }
}

impl std::error::Error for GmsslError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            GmsslError::IoError(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for GmsslError {
    fn from(e: std::io::Error) -> Self {
        GmsslError::IoError(e)
    }
}

/// Check that a C function returned 1 (success). Returns `Ok(())` or an error.
#[inline]
pub(crate) fn ok_or_library_error(ret: i32, context: &'static str) -> Result<(), GmsslError> {
    if ret == 1 {
        Ok(())
    } else {
        Err(GmsslError::LibraryError(context))
    }
}

/// Check a C verify function result: 1=valid, anything else=invalid.
///
/// Note: GmSSL verifiers sometimes return -1 (not 0) for invalid
/// signatures, notably sm2_verify_finish and sm9_verify_finish.
/// We treat all non-1 results as "verification failed" rather than
/// "library error" to match this behavior.
#[inline]
pub(crate) fn verify_result(ret: i32, _context: &'static str) -> Result<bool, GmsslError> {
    Ok(ret == 1)
}
