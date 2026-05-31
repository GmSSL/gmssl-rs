// SM4 block cipher.
//
// SM4 is a 128-bit block cipher with 128-bit keys, defined by GM/T 0002-2012.
//
// Supported modes: CBC (with PKCS#7 padding), CTR, and GCM.

use std::mem::MaybeUninit;

use gmssl_rs_sys;

use crate::error::{ok_or_library_error, GmsslError};

/// SM4 raw block cipher key.
///
/// Used for single-block encrypt/decrypt or as a building block for cipher modes.
#[derive(Debug)]
pub struct Sm4Key {
    enc_key: MaybeUninit<gmssl_rs_sys::SM4_KEY>,
    dec_key: MaybeUninit<gmssl_rs_sys::SM4_KEY>,
}

impl Sm4Key {
    /// Create a new SM4 key for encryption and decryption.
    pub fn new(key: &[u8; 16]) -> Self {
        let mut enc_key = MaybeUninit::uninit();
        let mut dec_key = MaybeUninit::uninit();
        unsafe {
            gmssl_rs_sys::sm4_set_encrypt_key(enc_key.as_mut_ptr(), key.as_ptr());
            gmssl_rs_sys::sm4_set_decrypt_key(dec_key.as_mut_ptr(), key.as_ptr());
        }
        Sm4Key { enc_key, dec_key }
    }

    /// Encrypt a single 16-byte block.
    pub fn encrypt_block(&self, block: &[u8; 16]) -> [u8; 16] {
        let mut out = [0u8; 16];
        unsafe {
            gmssl_rs_sys::sm4_encrypt(self.enc_key.as_ptr(), block.as_ptr(), out.as_mut_ptr());
        }
        out
    }

    /// Decrypt a single 16-byte block.
    pub fn decrypt_block(&self, block: &[u8; 16]) -> [u8; 16] {
        let mut out = [0u8; 16];
        unsafe {
            gmssl_rs_sys::sm4_encrypt(self.dec_key.as_ptr(), block.as_ptr(), out.as_mut_ptr());
        }
        out
    }
}

/// SM4-CBC streaming encryptor.
#[derive(Debug)]
pub struct Sm4CbcEncryptor {
    ctx: MaybeUninit<gmssl_rs_sys::SM4_CBC_CTX>,
    inited: bool,
}

impl Sm4CbcEncryptor {
    /// Create a new SM4-CBC encryption context.
    pub fn new(key: &[u8; 16], iv: &[u8; 16]) -> Result<Self, GmsslError> {
        let mut ctx = MaybeUninit::uninit();
        let ret = unsafe {
            gmssl_rs_sys::sm4_cbc_encrypt_init(ctx.as_mut_ptr(), key.as_ptr(), iv.as_ptr())
        };
        ok_or_library_error(ret, "sm4_cbc_encrypt_init")?;
        Ok(Sm4CbcEncryptor { ctx, inited: true })
    }

    /// Feed plaintext data. Returns the corresponding ciphertext (may be
    /// buffered internally, so output length may differ from input length).
    pub fn update(&mut self, input: &[u8]) -> Result<Vec<u8>, GmsslError> {
        if !self.inited {
            return Err(GmsslError::InvalidInput("encryptor not initialized"));
        }
        let out_len = input.len() + gmssl_rs_sys::SM4_BLOCK_SIZE;
        let mut out = vec![0u8; out_len];
        let mut outlen: usize = 0;
        let ret = unsafe {
            gmssl_rs_sys::sm4_cbc_encrypt_update(
                self.ctx.as_mut_ptr(),
                input.as_ptr(),
                input.len(),
                out.as_mut_ptr(),
                &mut outlen,
            )
        };
        ok_or_library_error(ret, "sm4_cbc_encrypt_update")?;
        out.truncate(outlen);
        Ok(out)
    }

    /// Finalize encryption (adds PKCS#7 padding). Returns the final ciphertext block.
    pub fn finish(&mut self) -> Result<Vec<u8>, GmsslError> {
        if !self.inited {
            return Err(GmsslError::InvalidInput("encryptor not initialized"));
        }
        self.inited = false;
        let mut out = vec![0u8; gmssl_rs_sys::SM4_BLOCK_SIZE * 2];
        let mut outlen: usize = 0;
        let ret = unsafe {
            gmssl_rs_sys::sm4_cbc_encrypt_finish(
                self.ctx.as_mut_ptr(),
                out.as_mut_ptr(),
                &mut outlen,
            )
        };
        ok_or_library_error(ret, "sm4_cbc_encrypt_finish")?;
        out.truncate(outlen);
        Ok(out)
    }
}

/// One-shot SM4-CBC-Padding encryption.
pub fn sm4_cbc_padding_encrypt(
    key: &[u8; 16],
    iv: &[u8; 16],
    data: &[u8],
) -> Result<Vec<u8>, GmsslError> {
    let sm4_key = Sm4Key::new(key);
    let out_len = data.len() + gmssl_rs_sys::SM4_BLOCK_SIZE * 2;
    let mut out = vec![0u8; out_len];
    let mut outlen: usize = out_len;
    let ret = unsafe {
        gmssl_rs_sys::sm4_cbc_padding_encrypt(
            sm4_key.enc_key.as_ptr(),
            iv.as_ptr(),
            data.as_ptr(),
            data.len(),
            out.as_mut_ptr(),
            &mut outlen,
        )
    };
    ok_or_library_error(ret, "sm4_cbc_padding_encrypt")?;
    out.truncate(outlen);
    Ok(out)
}

/// SM4-CBC streaming decryptor.
#[derive(Debug)]
pub struct Sm4CbcDecryptor {
    ctx: MaybeUninit<gmssl_rs_sys::SM4_CBC_CTX>,
    inited: bool,
}

impl Sm4CbcDecryptor {
    /// Create a new SM4-CBC decryption context.
    pub fn new(key: &[u8; 16], iv: &[u8; 16]) -> Result<Self, GmsslError> {
        let mut ctx = MaybeUninit::uninit();
        let ret = unsafe {
            gmssl_rs_sys::sm4_cbc_decrypt_init(ctx.as_mut_ptr(), key.as_ptr(), iv.as_ptr())
        };
        ok_or_library_error(ret, "sm4_cbc_decrypt_init")?;
        Ok(Sm4CbcDecryptor { ctx, inited: true })
    }

    /// Feed ciphertext data.
    pub fn update(&mut self, input: &[u8]) -> Result<Vec<u8>, GmsslError> {
        if !self.inited {
            return Err(GmsslError::InvalidInput("decryptor not initialized"));
        }
        let out_len = input.len() + gmssl_rs_sys::SM4_BLOCK_SIZE;
        let mut out = vec![0u8; out_len];
        let mut outlen: usize = 0;
        let ret = unsafe {
            gmssl_rs_sys::sm4_cbc_decrypt_update(
                self.ctx.as_mut_ptr(),
                input.as_ptr(),
                input.len(),
                out.as_mut_ptr(),
                &mut outlen,
            )
        };
        ok_or_library_error(ret, "sm4_cbc_decrypt_update")?;
        out.truncate(outlen);
        Ok(out)
    }

    /// Finalize decryption (removes PKCS#7 padding).
    pub fn finish(&mut self) -> Result<Vec<u8>, GmsslError> {
        if !self.inited {
            return Err(GmsslError::InvalidInput("decryptor not initialized"));
        }
        self.inited = false;
        let mut out = vec![0u8; gmssl_rs_sys::SM4_BLOCK_SIZE * 2];
        let mut outlen: usize = 0;
        let ret = unsafe {
            gmssl_rs_sys::sm4_cbc_decrypt_finish(
                self.ctx.as_mut_ptr(),
                out.as_mut_ptr(),
                &mut outlen,
            )
        };
        ok_or_library_error(ret, "sm4_cbc_decrypt_finish")?;
        out.truncate(outlen);
        Ok(out)
    }
}

/// One-shot SM4-CBC-Padding decryption.
pub fn sm4_cbc_padding_decrypt(
    key: &[u8; 16],
    iv: &[u8; 16],
    data: &[u8],
) -> Result<Vec<u8>, GmsslError> {
    let sm4_key = Sm4Key::new(key);
    let out_len = data.len() + gmssl_rs_sys::SM4_BLOCK_SIZE;
    let mut out = vec![0u8; out_len];
    let mut outlen: usize = out_len;
    let ret = unsafe {
        gmssl_rs_sys::sm4_cbc_padding_decrypt(
            sm4_key.dec_key.as_ptr(),
            iv.as_ptr(),
            data.as_ptr(),
            data.len(),
            out.as_mut_ptr(),
            &mut outlen,
        )
    };
    ok_or_library_error(ret, "sm4_cbc_padding_decrypt")?;
    out.truncate(outlen);
    Ok(out)
}

/// SM4-CBC convenience: encrypt with streaming API.
pub struct Sm4Cbc;

impl Sm4Cbc {
    /// Encrypt data using SM4-CBC with PKCS#7 padding.
    pub fn encrypt(key: &[u8; 16], iv: &[u8; 16], plaintext: &[u8]) -> Result<Vec<u8>, GmsslError> {
        sm4_cbc_padding_encrypt(key, iv, plaintext)
    }

    /// Decrypt data using SM4-CBC with PKCS#7 padding.
    pub fn decrypt(key: &[u8; 16], iv: &[u8; 16], ciphertext: &[u8]) -> Result<Vec<u8>, GmsslError> {
        sm4_cbc_padding_decrypt(key, iv, ciphertext)
    }
}

/// SM4-CTR streaming encryptor/decryptor.
///
/// CTR mode uses the same operation for both encryption and decryption.
#[derive(Debug)]
pub struct Sm4Ctr {
    ctx: MaybeUninit<gmssl_rs_sys::SM4_CTR_CTX>,
    inited: bool,
}

impl Sm4Ctr {
    /// Create a new SM4-CTR context.
    pub fn new(key: &[u8; 16], ctr: &[u8; 16]) -> Result<Self, GmsslError> {
        let mut ctx = MaybeUninit::uninit();
        let ret = unsafe {
            gmssl_rs_sys::sm4_ctr_encrypt_init(ctx.as_mut_ptr(), key.as_ptr(), ctr.as_ptr())
        };
        ok_or_library_error(ret, "sm4_ctr_encrypt_init")?;
        Ok(Sm4Ctr { ctx, inited: true })
    }

    /// Process data (same for encryption and decryption).
    pub fn update(&mut self, input: &[u8]) -> Result<Vec<u8>, GmsslError> {
        if !self.inited {
            return Err(GmsslError::InvalidInput("CTR context not initialized"));
        }
        let out_len = input.len() + gmssl_rs_sys::SM4_BLOCK_SIZE;
        let mut out = vec![0u8; out_len];
        let mut outlen: usize = 0;
        let ret = unsafe {
            gmssl_rs_sys::sm4_ctr_encrypt_update(
                self.ctx.as_mut_ptr(),
                input.as_ptr(),
                input.len(),
                out.as_mut_ptr(),
                &mut outlen,
            )
        };
        ok_or_library_error(ret, "sm4_ctr_encrypt_update")?;
        out.truncate(outlen);
        Ok(out)
    }

    /// Finalize.
    pub fn finish(&mut self) -> Result<Vec<u8>, GmsslError> {
        if !self.inited {
            return Err(GmsslError::InvalidInput("CTR context not initialized"));
        }
        self.inited = false;
        let mut out = vec![0u8; gmssl_rs_sys::SM4_BLOCK_SIZE];
        let mut outlen: usize = 0;
        let ret = unsafe {
            gmssl_rs_sys::sm4_ctr_encrypt_finish(
                self.ctx.as_mut_ptr(),
                out.as_mut_ptr(),
                &mut outlen,
            )
        };
        ok_or_library_error(ret, "sm4_ctr_encrypt_finish")?;
        out.truncate(outlen);
        Ok(out)
    }

    /// One-shot SM4-CTR encryption (same function for decryption).
    pub fn encrypt(key: &[u8; 16], ctr: &[u8; 16], data: &[u8]) -> Result<Vec<u8>, GmsslError> {
        let sm4_key = Sm4Key::new(key);
        let mut out = vec![0u8; data.len()];
        let mut iv = *ctr;
        unsafe {
            gmssl_rs_sys::sm4_ctr_encrypt(
                sm4_key.enc_key.as_ptr(),
                iv.as_mut_ptr(),
                data.as_ptr(),
                data.len(),
                out.as_mut_ptr(),
            );
        }
        Ok(out)
    }
}

/// Result of SM4-GCM encryption.
#[derive(Debug)]
pub struct Sm4GcmEncryptResult {
    pub ciphertext: Vec<u8>,
    pub tag: Vec<u8>,
}

/// SM4-GCM authenticated encryption.
///
/// GCM provides both confidentiality and authenticity.
#[derive(Debug)]
pub struct Sm4Gcm;

impl Sm4Gcm {
    /// One-shot SM4-GCM encryption.
    pub fn encrypt(
        key: &[u8],
        iv: &[u8],
        aad: &[u8],
        plaintext: &[u8],
        tag_len: usize,
    ) -> Result<Sm4GcmEncryptResult, GmsslError> {
        if key.len() != gmssl_rs_sys::SM4_KEY_SIZE {
            return Err(GmsslError::InvalidKey("SM4 key must be 16 bytes"));
        }

        let sm4_key = Sm4Key::new(key.try_into().unwrap());
        let mut ciphertext = vec![0u8; plaintext.len() + gmssl_rs_sys::SM4_BLOCK_SIZE];
        let mut tag = vec![0u8; tag_len];

        let ret = unsafe {
            gmssl_rs_sys::sm4_gcm_encrypt(
                sm4_key.enc_key.as_ptr(),
                iv.as_ptr(),
                iv.len(),
                aad.as_ptr(),
                aad.len(),
                plaintext.as_ptr(),
                plaintext.len(),
                ciphertext.as_mut_ptr(),
                tag_len,
                tag.as_mut_ptr(),
            )
        };
        ok_or_library_error(ret, "sm4_gcm_encrypt")?;

        ciphertext.truncate(plaintext.len());
        Ok(Sm4GcmEncryptResult { ciphertext, tag })
    }

    /// One-shot SM4-GCM decryption.
    pub fn decrypt(
        key: &[u8],
        iv: &[u8],
        aad: &[u8],
        tag: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, GmsslError> {
        if key.len() != gmssl_rs_sys::SM4_KEY_SIZE {
            return Err(GmsslError::InvalidKey("SM4 key must be 16 bytes"));
        }

        let sm4_key = Sm4Key::new(key.try_into().unwrap());
        let mut plaintext = vec![0u8; ciphertext.len()];

        let ret = unsafe {
            gmssl_rs_sys::sm4_gcm_decrypt(
                sm4_key.enc_key.as_ptr(),
                iv.as_ptr(),
                iv.len(),
                aad.as_ptr(),
                aad.len(),
                ciphertext.as_ptr(),
                ciphertext.len(),
                tag.as_ptr(),
                tag.len(),
                plaintext.as_mut_ptr(),
            )
        };
        ok_or_library_error(ret, "sm4_gcm_decrypt")?;

        Ok(plaintext)
    }
}

#[cfg(test)]
mod tests;
