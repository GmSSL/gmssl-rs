// ZUC stream cipher.
//
// ZUC is a stream cipher defined by GM/T 0001-2016, used in 4G/5G telecom
// security and Chinese national standards. ZUC-256 is the 256-bit key variant.

use std::mem::MaybeUninit;

use gmssl_rs_sys;

use crate::error::{ok_or_library_error, GmsslError};

/// ZUC stream cipher.
///
/// ZUC uses a 128-bit key and 128-bit IV. The same keystream is used
/// for both encryption and decryption (XOR operation).
#[derive(Debug)]
pub struct Zuc {
    state: MaybeUninit<gmssl_rs_sys::ZUC_STATE>,
}

impl Zuc {
    /// Create a new ZUC cipher with the given key and IV.
    pub fn new(key: &[u8; 16], iv: &[u8; 16]) -> Self {
        let mut state = MaybeUninit::uninit();
        unsafe {
            gmssl_rs_sys::zuc_init(state.as_mut_ptr(), key.as_ptr(), iv.as_ptr());
        }
        Zuc { state }
    }

    /// Generate keystream words.
    ///
    /// Produces `nwords` 32-bit keystream words.
    pub fn generate_keystream(&mut self, nwords: usize) -> Vec<u32> {
        let mut words = vec![0u32; nwords];
        unsafe {
            gmssl_rs_sys::zuc_generate_keystream(self.state.as_mut_ptr(), nwords, words.as_mut_ptr());
        }
        words
    }

    /// Encrypt or decrypt data (same operation for ZUC).
    ///
    /// Returns the encrypted/decrypted data of the same length as the input.
    pub fn encrypt(&mut self, data: &[u8]) -> Vec<u8> {
        let mut out = vec![0u8; data.len()];
        unsafe {
            gmssl_rs_sys::zuc_encrypt(self.state.as_mut_ptr(), data.as_ptr(), data.len(), out.as_mut_ptr());
        }
        out
    }

    /// One-shot ZUC encryption/decryption.
    pub fn process(key: &[u8; 16], iv: &[u8; 16], data: &[u8]) -> Vec<u8> {
        let mut zuc = Zuc::new(key, iv);
        zuc.encrypt(data)
    }
}

/// ZUC integrity (MAC) context.
///
/// Produces a 32-bit (4-byte) MAC tag.
#[derive(Debug)]
pub struct ZucMac {
    ctx: MaybeUninit<gmssl_rs_sys::ZUC_MAC_CTX>,
}

impl ZucMac {
    /// Create a new ZUC MAC context.
    pub fn new(key: &[u8; 16], iv: &[u8; 16]) -> Self {
        let mut ctx = MaybeUninit::uninit();
        unsafe {
            gmssl_rs_sys::zuc_mac_init(ctx.as_mut_ptr(), key.as_ptr(), iv.as_ptr());
        }
        ZucMac { ctx }
    }

    /// Feed data into the MAC computation.
    pub fn update(&mut self, data: &[u8]) {
        unsafe {
            gmssl_rs_sys::zuc_mac_update(self.ctx.as_mut_ptr(), data.as_ptr(), data.len());
        }
    }

    /// Finalize and produce the 4-byte MAC tag.
    ///
    /// `remainder` is the final partial data (less than a word), and `nbits` is
    /// its length in bits.
    pub fn finish(&mut self, remainder: &[u8], nbits: usize) -> [u8; 4] {
        let mut mac = [0u8; 4];
        unsafe {
            gmssl_rs_sys::zuc_mac_finish(
                self.ctx.as_mut_ptr(),
                remainder.as_ptr(),
                nbits,
                mac.as_mut_ptr(),
            );
        }
        mac
    }
}

/// ZUC-256 stream cipher (256-bit key variant).
#[derive(Debug)]
pub struct Zuc256 {
    state: MaybeUninit<gmssl_rs_sys::ZUC_STATE>,
}

impl Zuc256 {
    /// Create a new ZUC-256 cipher with 256-bit key and 184-bit (23-byte) IV.
    pub fn new(key: &[u8; 32], iv: &[u8; 23]) -> Self {
        let mut state = MaybeUninit::uninit();
        unsafe {
            gmssl_rs_sys::zuc256_init(state.as_mut_ptr(), key.as_ptr(), iv.as_ptr());
        }
        Zuc256 { state }
    }

    /// Generate keystream words.
    pub fn generate_keystream(&mut self, nwords: usize) -> Vec<u32> {
        let mut words = vec![0u32; nwords];
        unsafe {
            gmssl_rs_sys::zuc256_generate_keystream(
                self.state.as_mut_ptr(),
                nwords,
                words.as_mut_ptr(),
            );
        }
        words
    }

    /// Encrypt or decrypt data.
    pub fn encrypt(&mut self, data: &[u8]) -> Vec<u8> {
        let mut out = vec![0u8; data.len()];
        unsafe {
            gmssl_rs_sys::zuc_encrypt(self.state.as_mut_ptr(), data.as_ptr(), data.len(), out.as_mut_ptr());
        }
        out
    }
}

/// ZUC streaming encryptor using init/update/finish pattern.
#[derive(Debug)]
pub struct ZucEncryptor {
    ctx: MaybeUninit<gmssl_rs_sys::ZUC_CTX>,
    inited: bool,
}

impl ZucEncryptor {
    /// Create a new ZUC streaming encryptor.
    pub fn new(key: &[u8; 16], iv: &[u8; 16]) -> Result<Self, GmsslError> {
        let mut ctx = MaybeUninit::uninit();
        ok_or_library_error(
            unsafe { gmssl_rs_sys::zuc_encrypt_init(ctx.as_mut_ptr(), key.as_ptr(), iv.as_ptr()) },
            "zuc_encrypt_init",
        )?;
        Ok(ZucEncryptor { ctx, inited: true })
    }

    /// Feed data for encryption/decryption.
    pub fn update(&mut self, input: &[u8]) -> Result<Vec<u8>, GmsslError> {
        if !self.inited {
            return Err(GmsslError::InvalidInput("ZUC context not initialized"));
        }
        let mut out = vec![0u8; input.len() + 16];
        let mut outlen: usize = 0;
        ok_or_library_error(
            unsafe {
                gmssl_rs_sys::zuc_encrypt_update(
                    self.ctx.as_mut_ptr(),
                    input.as_ptr(),
                    input.len(),
                    out.as_mut_ptr(),
                    &mut outlen,
                )
            },
            "zuc_encrypt_update",
        )?;
        out.truncate(outlen);
        Ok(out)
    }

    /// Finalize.
    pub fn finish(&mut self) -> Result<Vec<u8>, GmsslError> {
        if !self.inited {
            return Err(GmsslError::InvalidInput("ZUC context not initialized"));
        }
        self.inited = false;
        let mut out = vec![0u8; 16];
        let mut outlen: usize = 0;
        ok_or_library_error(
            unsafe {
                gmssl_rs_sys::zuc_encrypt_finish(
                    self.ctx.as_mut_ptr(),
                    out.as_mut_ptr(),
                    &mut outlen,
                )
            },
            "zuc_encrypt_finish",
        )?;
        out.truncate(outlen);
        Ok(out)
    }
}

#[cfg(test)]
mod tests;
