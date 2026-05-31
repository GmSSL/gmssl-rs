// Cryptographically secure random number generation.

use crate::error::{ok_or_library_error, GmsslError};
use gmssl_rs_sys::rand_bytes as ffi_rand_bytes;

/// Fill `buf` with cryptographically secure random bytes.
///
/// Returns an error if the underlying GmSSL random number generator fails.
///
/// # Examples
///
/// ```no_run
/// use gmssl_rs::rand_bytes;
/// let mut buf = [0u8; 32];
/// rand_bytes(&mut buf).unwrap();
/// ```
pub fn rand_bytes(buf: &mut [u8]) -> Result<(), GmsslError> {
    if buf.is_empty() {
        return Ok(());
    }
    let ret = unsafe { ffi_rand_bytes(buf.as_mut_ptr(), buf.len()) };
    ok_or_library_error(ret, "rand_bytes")
}
