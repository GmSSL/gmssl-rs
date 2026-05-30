// SM3 cryptographic hash and HMAC.
//
// SM3 is a cryptographic hash function defined by GM/T 0004-2012.
// It produces a 256-bit (32-byte) digest.
//
// # Examples
//
// ```
// use gmssl::Sm3;
//
// // One-shot hashing
// let hash = Sm3::digest(b"hello world");
// assert_eq!(hash.len(), 32);
//
// // Streaming hashing
// let mut sm3 = Sm3::new();
// sm3.update(b"hello ");
// sm3.update(b"world");
// let hash = sm3.finish();
// ```

use std::mem::MaybeUninit;
use std::os::raw::c_char;

use gmssl_sys;

/// SM3 streaming hash context.
///
/// Implements the standard init/update/finish pattern.
#[derive(Debug)]
pub struct Sm3 {
    ctx: MaybeUninit<gmssl_sys::SM3_CTX>,
}

impl Sm3 {
    /// Create a new SM3 hash context.
    pub fn new() -> Self {
        let mut ctx = MaybeUninit::uninit();
        unsafe {
            gmssl_sys::sm3_init(ctx.as_mut_ptr());
        }
        Sm3 { ctx }
    }

    /// Feed data into the hash.
    pub fn update(&mut self, data: &[u8]) {
        unsafe {
            gmssl_sys::sm3_update(self.ctx.as_mut_ptr(), data.as_ptr(), data.len());
        }
    }

    /// Finalize and produce the 32-byte digest.
    pub fn finish(&mut self) -> [u8; gmssl_sys::SM3_DIGEST_SIZE] {
        let mut dgst = [0u8; gmssl_sys::SM3_DIGEST_SIZE];
        unsafe {
            gmssl_sys::sm3_finish(self.ctx.as_mut_ptr(), dgst.as_mut_ptr());
        }
        dgst
    }

    /// One-shot hash: compute SM3 digest of `data`.
    pub fn digest(data: &[u8]) -> [u8; gmssl_sys::SM3_DIGEST_SIZE] {
        let mut sm3 = Sm3::new();
        sm3.update(data);
        sm3.finish()
    }

    /// Reset the context to compute a new hash.
    pub fn reset(&mut self) {
        unsafe {
            gmssl_sys::sm3_init(self.ctx.as_mut_ptr());
        }
    }
}

impl Default for Sm3 {
    fn default() -> Self {
        Self::new()
    }
}

/// SM3 HMAC context.
#[derive(Debug)]
pub struct Sm3Hmac {
    ctx: MaybeUninit<gmssl_sys::SM3_HMAC_CTX>,
}

impl Sm3Hmac {
    /// Create a new SM3 HMAC context with the given key.
    pub fn new(key: &[u8]) -> Self {
        let mut ctx = MaybeUninit::uninit();
        unsafe {
            gmssl_sys::sm3_hmac_init(ctx.as_mut_ptr(), key.as_ptr(), key.len());
        }
        Sm3Hmac { ctx }
    }

    /// Feed data into the HMAC computation.
    pub fn update(&mut self, data: &[u8]) {
        unsafe {
            gmssl_sys::sm3_hmac_update(self.ctx.as_mut_ptr(), data.as_ptr(), data.len());
        }
    }

    /// Finalize and produce the 32-byte MAC.
    pub fn finish(&mut self) -> [u8; gmssl_sys::SM3_HMAC_SIZE] {
        let mut mac = [0u8; gmssl_sys::SM3_HMAC_SIZE];
        unsafe {
            gmssl_sys::sm3_hmac_finish(self.ctx.as_mut_ptr(), mac.as_mut_ptr());
        }
        mac
    }

    /// One-shot HMAC-SM3.
    pub fn mac(key: &[u8], data: &[u8]) -> [u8; gmssl_sys::SM3_HMAC_SIZE] {
        let mut hmac = Sm3Hmac::new(key);
        hmac.update(data);
        hmac.finish()
    }

    /// Reset with a new key.
    pub fn reset(&mut self, key: &[u8]) {
        unsafe {
            gmssl_sys::sm3_hmac_init(self.ctx.as_mut_ptr(), key.as_ptr(), key.len());
        }
    }
}

/// SM3 PBKDF2 key derivation.
///
/// Derives a key from a password and salt using PBKDF2-HMAC-SM3.
///
/// # Arguments
/// * `password` - The password bytes.
/// * `salt` - The salt bytes (max 64 bytes).
/// * `iterations` - Number of iterations (min 10000).
/// * `out` - Output buffer to fill with derived key material.
pub fn sm3_pbkdf2(
    password: &[u8],
    salt: &[u8],
    iterations: usize,
    out: &mut [u8],
) -> Result<(), crate::error::GmsslError> {
    use crate::error::ok_or_library_error;
    let ret = unsafe {
        gmssl_sys::sm3_pbkdf2(
            password.as_ptr() as *const c_char,
            password.len(),
            salt.as_ptr(),
            salt.len(),
            iterations,
            out.len(),
            out.as_mut_ptr(),
        )
    };
    ok_or_library_error(ret, "sm3_pbkdf2")
}

#[cfg(test)]
mod tests;
