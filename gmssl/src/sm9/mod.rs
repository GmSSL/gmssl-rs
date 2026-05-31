// SM9 identity-based cryptography.
//
// SM9 (GM/T 0044-2016) supports identity-based signatures (IBS) and
// identity-based encryption (IBE) using bilinear pairings on BN curves.

use std::mem::MaybeUninit;
use gmssl_rs_sys;

use crate::error::{ok_or_library_error, verify_result, GmsslError};
use crate::pem_helpers;

// ============================================================================
// SM9 Sign Master Key (held by KGC)
// ============================================================================

pub struct Sm9SignMasterKey {
    key: gmssl_rs_sys::SM9_SIGN_MASTER_KEY,
}

impl std::fmt::Debug for Sm9SignMasterKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Sm9SignMasterKey").finish()
    }
}

impl Sm9SignMasterKey {
    /// Generate a new SM9 signature master key.
    pub fn generate() -> Result<Self, GmsslError> {
        let mut key = MaybeUninit::uninit();
        ok_or_library_error(
            unsafe { gmssl_rs_sys::sm9_sign_master_key_generate(key.as_mut_ptr()) },
            "sm9_sign_master_key_generate",
        )?;
        Ok(Sm9SignMasterKey {
            key: unsafe { key.assume_init() },
        })
    }

    /// Extract a user's signing private key from the master key.
    pub fn extract_key(&self, id: &str) -> Result<Sm9SignKey, GmsslError> {
        let id_c = std::ffi::CString::new(id)
            .map_err(|_| GmsslError::InvalidInput("ID contains NUL byte"))?;
        let mut key = MaybeUninit::uninit();
        ok_or_library_error(
            unsafe {
                gmssl_rs_sys::sm9_sign_master_key_extract_key(
                    &self.key,
                    id_c.as_ptr(),
                    id.len(),
                    key.as_mut_ptr(),
                )
            },
            "sm9_sign_master_key_extract_key",
        )?;
        Ok(Sm9SignKey {
            key: unsafe { key.assume_init() },
            id: id.to_string(),
        })
    }

    /// Import from encrypted PEM (in-memory).
    pub fn from_encrypted_pem(pem_data: &[u8], password: &str) -> Result<Self, GmsslError> {
        let pass_c = std::ffi::CString::new(password)
            .map_err(|_| GmsslError::InvalidInput("password contains NUL byte"))?;
        let mut key = MaybeUninit::uninit();
        let fp = unsafe { pem_helpers::file_from_bytes(pem_data)? };
        let ret = unsafe {
            gmssl_rs_sys::sm9_sign_master_key_info_decrypt_from_pem(
                key.as_mut_ptr(),
                pass_c.as_ptr(),
                fp,
            )
        };
        unsafe { libc::fclose(fp) };
        ok_or_library_error(ret, "sm9_sign_master_key_info_decrypt_from_pem")?;
        Ok(Sm9SignMasterKey {
            key: unsafe { key.assume_init() },
        })
    }

    /// Export to encrypted PEM (in-memory).
    pub fn to_encrypted_pem(&self, password: &str) -> Result<Vec<u8>, GmsslError> {
        let pass_c = std::ffi::CString::new(password)
            .map_err(|_| GmsslError::InvalidInput("password contains NUL byte"))?;
        unsafe {
            pem_helpers::collect_to_bytes(|fp| {
                gmssl_rs_sys::sm9_sign_master_key_info_encrypt_to_pem(
                    &self.key,
                    pass_c.as_ptr(),
                    fp,
                )
            })
        }
    }
}

// ============================================================================
// SM9 Sign User Key
// ============================================================================

pub struct Sm9SignKey {
    key: gmssl_rs_sys::SM9_SIGN_KEY,
    id: String,
}

impl std::fmt::Debug for Sm9SignKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Sm9SignKey").field("id", &self.id).finish()
    }
}

impl Sm9SignKey {
    /// Get the user identity associated with this key.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Import from encrypted PEM (in-memory).
    pub fn from_encrypted_pem(pem_data: &[u8], password: &str) -> Result<Self, GmsslError> {
        let pass_c = std::ffi::CString::new(password)
            .map_err(|_| GmsslError::InvalidInput("password contains NUL byte"))?;
        let mut key = MaybeUninit::uninit();
        let fp = unsafe { pem_helpers::file_from_bytes(pem_data)? };
        let ret = unsafe {
            gmssl_rs_sys::sm9_sign_key_info_decrypt_from_pem(
                key.as_mut_ptr(),
                pass_c.as_ptr(),
                fp,
            )
        };
        unsafe { libc::fclose(fp) };
        ok_or_library_error(ret, "sm9_sign_key_info_decrypt_from_pem")?;
        Ok(Sm9SignKey {
            key: unsafe { key.assume_init() },
            id: String::new(), // PEM doesn't encode the ID
        })
    }

    /// Export to encrypted PEM (in-memory).
    pub fn to_encrypted_pem(&self, password: &str) -> Result<Vec<u8>, GmsslError> {
        let pass_c = std::ffi::CString::new(password)
            .map_err(|_| GmsslError::InvalidInput("password contains NUL byte"))?;
        unsafe {
            pem_helpers::collect_to_bytes(|fp| {
                gmssl_rs_sys::sm9_sign_key_info_encrypt_to_pem(
                    &self.key,
                    pass_c.as_ptr(),
                    fp,
                )
            })
        }
    }
}

// ============================================================================
// SM9 Sign/Verify
// ============================================================================

/// Sign a message using an SM9 signing key.
pub fn sm9_sign(key: &Sm9SignKey, data: &[u8]) -> Result<Vec<u8>, GmsslError> {
    let mut ctx = MaybeUninit::uninit();
    ok_or_library_error(
        unsafe { gmssl_rs_sys::sm9_sign_init(ctx.as_mut_ptr()) },
        "sm9_sign_init",
    )?;
    ok_or_library_error(
        unsafe { gmssl_rs_sys::sm9_sign_update(ctx.as_mut_ptr(), data.as_ptr(), data.len()) },
        "sm9_sign_update",
    )?;

    let mut sig = vec![0u8; 256];
    let mut siglen: usize = sig.len();
    ok_or_library_error(
        unsafe {
            gmssl_rs_sys::sm9_sign_finish(
                ctx.as_mut_ptr(),
                &key.key,
                sig.as_mut_ptr(),
                &mut siglen,
            )
        },
        "sm9_sign_finish",
    )?;
    // GmSSL sets *siglen = 0 before DER encoding, causing size_t wrap.
    // Recover actual size from ASN.1 SEQUENCE header.
    truncate_der_sequence(&mut sig);
    Ok(sig)
}

/// Verify an SM9 signature.
pub fn sm9_verify(
    mpk: &Sm9SignMasterKey,
    id: &str,
    data: &[u8],
    sig: &[u8],
) -> Result<bool, GmsslError> {
    let id_c = std::ffi::CString::new(id)
        .map_err(|_| GmsslError::InvalidInput("ID contains NUL byte"))?;

    let mut ctx = MaybeUninit::uninit();
    ok_or_library_error(
        unsafe { gmssl_rs_sys::sm9_verify_init(ctx.as_mut_ptr()) },
        "sm9_verify_init",
    )?;
    ok_or_library_error(
        unsafe { gmssl_rs_sys::sm9_verify_update(ctx.as_mut_ptr(), data.as_ptr(), data.len()) },
        "sm9_verify_update",
    )?;

    verify_result(
        unsafe {
            gmssl_rs_sys::sm9_verify_finish(
                ctx.as_mut_ptr(),
                sig.as_ptr(),
                sig.len(),
                &mpk.key,
                id_c.as_ptr(),
                id.len(),
            )
        },
        "sm9_verify_finish",
    )
}

// ============================================================================
// SM9 Enc Master Key (held by KGC)
// ============================================================================

pub struct Sm9EncMasterKey {
    key: gmssl_rs_sys::SM9_ENC_MASTER_KEY,
}

impl std::fmt::Debug for Sm9EncMasterKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Sm9EncMasterKey").finish()
    }
}

impl Sm9EncMasterKey {
    /// Generate a new SM9 encryption master key.
    pub fn generate() -> Result<Self, GmsslError> {
        let mut key = MaybeUninit::uninit();
        ok_or_library_error(
            unsafe { gmssl_rs_sys::sm9_enc_master_key_generate(key.as_mut_ptr()) },
            "sm9_enc_master_key_generate",
        )?;
        Ok(Sm9EncMasterKey {
            key: unsafe { key.assume_init() },
        })
    }

    /// Extract a user's decryption private key from the master key.
    pub fn extract_key(&self, id: &str) -> Result<Sm9EncKey, GmsslError> {
        let id_c = std::ffi::CString::new(id)
            .map_err(|_| GmsslError::InvalidInput("ID contains NUL byte"))?;
        let mut key = MaybeUninit::uninit();
        ok_or_library_error(
            unsafe {
                gmssl_rs_sys::sm9_enc_master_key_extract_key(
                    &self.key,
                    id_c.as_ptr(),
                    id.len(),
                    key.as_mut_ptr(),
                )
            },
            "sm9_enc_master_key_extract_key",
        )?;
        Ok(Sm9EncKey {
            key: unsafe { key.assume_init() },
            id: id.to_string(),
        })
    }

    /// Import from encrypted PEM (in-memory).
    pub fn from_encrypted_pem(pem_data: &[u8], password: &str) -> Result<Self, GmsslError> {
        let pass_c = std::ffi::CString::new(password)
            .map_err(|_| GmsslError::InvalidInput("password contains NUL byte"))?;
        let mut key = MaybeUninit::uninit();
        let fp = unsafe { pem_helpers::file_from_bytes(pem_data)? };
        let ret = unsafe {
            gmssl_rs_sys::sm9_enc_master_key_info_decrypt_from_pem(
                key.as_mut_ptr(),
                pass_c.as_ptr(),
                fp,
            )
        };
        unsafe { libc::fclose(fp) };
        ok_or_library_error(ret, "sm9_enc_master_key_info_decrypt_from_pem")?;
        Ok(Sm9EncMasterKey {
            key: unsafe { key.assume_init() },
        })
    }

    /// Export to encrypted PEM (in-memory).
    pub fn to_encrypted_pem(&self, password: &str) -> Result<Vec<u8>, GmsslError> {
        let pass_c = std::ffi::CString::new(password)
            .map_err(|_| GmsslError::InvalidInput("password contains NUL byte"))?;
        unsafe {
            pem_helpers::collect_to_bytes(|fp| {
                gmssl_rs_sys::sm9_enc_master_key_info_encrypt_to_pem(
                    &self.key,
                    pass_c.as_ptr(),
                    fp,
                )
            })
        }
    }
}

// ============================================================================
// SM9 Enc User Key
// ============================================================================

pub struct Sm9EncKey {
    key: gmssl_rs_sys::SM9_ENC_KEY,
    id: String,
}

impl std::fmt::Debug for Sm9EncKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Sm9EncKey").field("id", &self.id).finish()
    }
}

impl Sm9EncKey {
    /// Get the user identity associated with this key.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Import from encrypted PEM (in-memory).
    pub fn from_encrypted_pem(pem_data: &[u8], password: &str) -> Result<Self, GmsslError> {
        let pass_c = std::ffi::CString::new(password)
            .map_err(|_| GmsslError::InvalidInput("password contains NUL byte"))?;
        let mut key = MaybeUninit::uninit();
        let fp = unsafe { pem_helpers::file_from_bytes(pem_data)? };
        let ret = unsafe {
            gmssl_rs_sys::sm9_enc_key_info_decrypt_from_pem(
                key.as_mut_ptr(),
                pass_c.as_ptr(),
                fp,
            )
        };
        unsafe { libc::fclose(fp) };
        ok_or_library_error(ret, "sm9_enc_key_info_decrypt_from_pem")?;
        Ok(Sm9EncKey {
            key: unsafe { key.assume_init() },
            id: String::new(),
        })
    }

    /// Export to encrypted PEM (in-memory).
    pub fn to_encrypted_pem(&self, password: &str) -> Result<Vec<u8>, GmsslError> {
        let pass_c = std::ffi::CString::new(password)
            .map_err(|_| GmsslError::InvalidInput("password contains NUL byte"))?;
        unsafe {
            pem_helpers::collect_to_bytes(|fp| {
                gmssl_rs_sys::sm9_enc_key_info_encrypt_to_pem(
                    &self.key,
                    pass_c.as_ptr(),
                    fp,
                )
            })
        }
    }
}

// ============================================================================
// SM9 Encrypt/Decrypt
// ============================================================================

/// Encrypt data for a recipient identified by `id` using the master public key.
pub fn sm9_encrypt(
    mpk: &Sm9EncMasterKey,
    id: &str,
    data: &[u8],
) -> Result<Vec<u8>, GmsslError> {
    if data.len() > gmssl_rs_sys::SM9_MAX_PLAINTEXT_SIZE {
        return Err(GmsslError::InvalidInput(
            "SM9 plaintext exceeds 255 bytes maximum",
        ));
    }
    let id_c = std::ffi::CString::new(id)
        .map_err(|_| GmsslError::InvalidInput("ID contains NUL byte"))?;

    let mut out = vec![0u8; gmssl_rs_sys::SM9_MAX_CIPHERTEXT_SIZE];
    let mut outlen: usize = out.len();
    ok_or_library_error(
        unsafe {
            gmssl_rs_sys::sm9_encrypt(
                &mpk.key,
                id_c.as_ptr(),
                id.len(),
                data.as_ptr(),
                data.len(),
                out.as_mut_ptr(),
                &mut outlen,
            )
        },
        "sm9_encrypt",
    )?;
    // GmSSL sets *outlen = 0 before DER encoding, causing size_t wrap.
    // Recover actual size from ASN.1 SEQUENCE header.
    truncate_der_sequence(&mut out);
    Ok(out)
}

/// Decrypt data using the user's private key.
pub fn sm9_decrypt(key: &Sm9EncKey, id: &str, ciphertext: &[u8]) -> Result<Vec<u8>, GmsslError> {
    let id_c = std::ffi::CString::new(id)
        .map_err(|_| GmsslError::InvalidInput("ID contains NUL byte"))?;

    let mut out = vec![0u8; ciphertext.len()];
    let mut outlen: usize = out.len();
    ok_or_library_error(
        unsafe {
            gmssl_rs_sys::sm9_decrypt(
                &key.key,
                id_c.as_ptr(),
                id.len(),
                ciphertext.as_ptr(),
                ciphertext.len(),
                out.as_mut_ptr(),
                &mut outlen,
            )
        },
        "sm9_decrypt",
    )?;
    out.truncate(outlen);
    Ok(out)
}

/// Truncate a Vec containing a DER SEQUENCE to its actual encoded size.
fn truncate_der_sequence(data: &mut Vec<u8>) {
    if data.len() >= 2 && data[0] == 0x30 {
        let content_len = data[1] as usize;
        let total = if content_len < 0x80 {
            2 + content_len
        } else if content_len == 0x81 && data.len() >= 3 {
            2 + 1 + data[2] as usize
        } else if content_len == 0x82 && data.len() >= 4 {
            let l = u16::from_be_bytes([data[2], data[3]]) as usize;
            2 + 2 + l
        } else {
            return;
        };
        if total <= data.len() {
            data.truncate(total);
        }
    }
}

#[cfg(test)]
mod tests;
