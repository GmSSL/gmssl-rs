// SM2 public key cryptography.
//
// SM2 is the Chinese national elliptic curve public key algorithm standard
// (GM/T 0003-2012), covering digital signatures, public key encryption,
// and key exchange on the sm2p256v1 curve.

use std::mem::MaybeUninit;
use gmssl_rs_sys;

use crate::error::{ok_or_library_error, verify_result, GmsslError};
use crate::pem_helpers;

/// SM2 key pair (public + optional private key).
#[derive(Debug)]
pub struct Sm2Key {
    key: gmssl_rs_sys::SM2_KEY,
    has_private_key: bool,
}

impl Sm2Key {
    /// Generate a new SM2 key pair.
    pub fn generate() -> Result<Self, GmsslError> {
        let mut key = MaybeUninit::uninit();
        ok_or_library_error(
            unsafe { gmssl_rs_sys::sm2_key_generate(key.as_mut_ptr()) },
            "sm2_key_generate",
        )?;
        Ok(Sm2Key {
            key: unsafe { key.assume_init() },
            has_private_key: true,
        })
    }

    /// Import from PKCS#8 encrypted private key PEM (in-memory).
    pub fn from_encrypted_private_key_pem(
        pem_data: &[u8],
        password: &str,
    ) -> Result<Self, GmsslError> {
        let pass_c = std::ffi::CString::new(password)
            .map_err(|_| GmsslError::InvalidInput("password contains NUL byte"))?;

        let mut key = MaybeUninit::uninit();
        pem_helpers::read_pem_data(pem_data, |fp| unsafe {
            gmssl_rs_sys::sm2_private_key_info_decrypt_from_pem(
                key.as_mut_ptr(),
                pass_c.as_ptr(),
                fp,
            )
        })?;
        // Re-read because read_pem_data closes the fp first; we need the return code
        let fp = unsafe { pem_helpers::file_from_bytes(pem_data)? };
        let ret = unsafe {
            gmssl_rs_sys::sm2_private_key_info_decrypt_from_pem(
                key.as_mut_ptr(),
                pass_c.as_ptr(),
                fp,
            )
        };
        unsafe { libc::fclose(fp) };
        ok_or_library_error(ret, "sm2_private_key_info_decrypt_from_pem")?;
        Ok(Sm2Key {
            key: unsafe { key.assume_init() },
            has_private_key: true,
        })
    }

    /// Export to PKCS#8 encrypted private key PEM (in-memory).
    pub fn to_encrypted_private_key_pem(
        &self,
        password: &str,
    ) -> Result<Vec<u8>, GmsslError> {
        if !self.has_private_key {
            return Err(GmsslError::InvalidKey("no private key to export"));
        }
        let pass_c = std::ffi::CString::new(password)
            .map_err(|_| GmsslError::InvalidInput("password contains NUL byte"))?;

        unsafe {
            pem_helpers::collect_to_bytes(|fp| {
                gmssl_rs_sys::sm2_private_key_info_encrypt_to_pem(
                    &self.key,
                    pass_c.as_ptr(),
                    fp,
                )
            })
        }
    }

    /// Import from public key PEM (in-memory).
    pub fn from_public_key_pem(pem_data: &[u8]) -> Result<Self, GmsslError> {
        let mut key = MaybeUninit::uninit();
        let fp = unsafe { pem_helpers::file_from_bytes(pem_data)? };
        let ret = unsafe {
            gmssl_rs_sys::sm2_public_key_info_from_pem(key.as_mut_ptr(), fp)
        };
        unsafe { libc::fclose(fp) };
        ok_or_library_error(ret, "sm2_public_key_info_from_pem")?;
        Ok(Sm2Key {
            key: unsafe { key.assume_init() },
            has_private_key: false,
        })
    }

    /// Export to public key PEM (in-memory).
    pub fn to_public_key_pem(&self) -> Result<Vec<u8>, GmsslError> {
        unsafe {
            pem_helpers::collect_to_bytes(|fp| {
                gmssl_rs_sys::sm2_public_key_info_to_pem(&self.key, fp)
            })
        }
    }

    /// Import from private key PEM (PKCS#8 PrivateKeyInfo, in-memory).
    pub fn from_private_key_pem(pem_data: &[u8]) -> Result<Self, GmsslError> {
        let mut key = MaybeUninit::uninit();
        let fp = unsafe { pem_helpers::file_from_bytes(pem_data)? };
        let ret = unsafe {
            gmssl_rs_sys::sm2_private_key_info_from_pem(key.as_mut_ptr(), fp)
        };
        unsafe { libc::fclose(fp) };
        ok_or_library_error(ret, "sm2_private_key_info_from_pem")?;
        Ok(Sm2Key {
            key: unsafe { key.assume_init() },
            has_private_key: true,
        })
    }

    /// Export to private key PEM (PKCS#8 PrivateKeyInfo, in-memory).
    pub fn to_private_key_pem(&self) -> Result<Vec<u8>, GmsslError> {
        if !self.has_private_key {
            return Err(GmsslError::InvalidKey("no private key to export"));
        }
        unsafe {
            pem_helpers::collect_to_bytes(|fp| {
                gmssl_rs_sys::sm2_private_key_info_to_pem(&self.key, fp)
            })
        }
    }

    /// Import from public key DER (SubjectPublicKeyInfo).
    pub fn from_public_key_der(der: &[u8]) -> Result<Self, GmsslError> {
        unsafe {
            pem_helpers::parse_der(der, |key, pin, pinlen| {
                gmssl_rs_sys::sm2_public_key_info_from_der(key, pin, pinlen)
            })
        }
        .map(|key| Sm2Key {
            key,
            has_private_key: false,
        })
    }

    /// Export to public key DER (SubjectPublicKeyInfo).
    pub fn to_public_key_der(&self) -> Result<Vec<u8>, GmsslError> {
        unsafe {
            pem_helpers::collect_der(512, |out, outlen| {
                gmssl_rs_sys::sm2_public_key_info_to_der(&self.key, out, outlen)
            })
        }
    }

    /// Import from private key DER (PKCS#8 PrivateKeyInfo).
    pub fn from_private_key_der(der: &[u8]) -> Result<Self, GmsslError> {
        unsafe {
            let mut attrs: *const u8 = std::ptr::null();
            let mut attrslen: usize = 0;
            pem_helpers::parse_der(der, |key, pin, pinlen| {
                gmssl_rs_sys::sm2_private_key_info_from_der(
                    key,
                    &mut attrs,
                    &mut attrslen,
                    pin,
                    pinlen,
                )
            })
        }
        .map(|key| Sm2Key {
            key,
            has_private_key: true,
        })
    }

    /// Export to private key DER (PKCS#8 PrivateKeyInfo).
    pub fn to_private_key_der(&self) -> Result<Vec<u8>, GmsslError> {
        if !self.has_private_key {
            return Err(GmsslError::InvalidKey("no private key to export"));
        }
        unsafe {
            pem_helpers::collect_der(512, |out, outlen| {
                gmssl_rs_sys::sm2_private_key_info_to_der(&self.key, out, outlen)
            })
        }
    }

    /// Import from public key PEM file.
    pub fn from_public_key_pem_file(path: &str) -> Result<Self, GmsslError> {
        let mut key = MaybeUninit::uninit();
        let fp = unsafe { pem_helpers::file_open_read(path)? };
        let ret = unsafe {
            gmssl_rs_sys::sm2_public_key_info_from_pem(key.as_mut_ptr(), fp)
        };
        unsafe { libc::fclose(fp) };
        ok_or_library_error(ret, "sm2_public_key_info_from_pem")?;
        Ok(Sm2Key {
            key: unsafe { key.assume_init() },
            has_private_key: false,
        })
    }

    /// Export to public key PEM file.
    pub fn to_public_key_pem_file(&self, path: &str) -> Result<(), GmsslError> {
        let fp = unsafe { pem_helpers::file_open_write(path)? };
        let ret = unsafe {
            gmssl_rs_sys::sm2_public_key_info_to_pem(&self.key, fp)
        };
        unsafe { libc::fclose(fp) };
        ok_or_library_error(ret, "sm2_public_key_info_to_pem")
    }

    /// Import from encrypted private key PEM file.
    pub fn from_encrypted_private_key_pem_file(
        path: &str,
        password: &str,
    ) -> Result<Self, GmsslError> {
        let pass_c = std::ffi::CString::new(password)
            .map_err(|_| GmsslError::InvalidInput("password contains NUL byte"))?;
        let mut key = MaybeUninit::uninit();
        let fp = unsafe { pem_helpers::file_open_read(path)? };
        let ret = unsafe {
            gmssl_rs_sys::sm2_private_key_info_decrypt_from_pem(
                key.as_mut_ptr(),
                pass_c.as_ptr(),
                fp,
            )
        };
        unsafe { libc::fclose(fp) };
        ok_or_library_error(ret, "sm2_private_key_info_decrypt_from_pem")?;
        Ok(Sm2Key {
            key: unsafe { key.assume_init() },
            has_private_key: true,
        })
    }

    /// Export to encrypted private key PEM file.
    pub fn to_encrypted_private_key_pem_file(
        &self,
        path: &str,
        password: &str,
    ) -> Result<(), GmsslError> {
        if !self.has_private_key {
            return Err(GmsslError::InvalidKey("no private key to export"));
        }
        let pass_c = std::ffi::CString::new(password)
            .map_err(|_| GmsslError::InvalidInput("password contains NUL byte"))?;
        let fp = unsafe { pem_helpers::file_open_write(path)? };
        let ret = unsafe {
            gmssl_rs_sys::sm2_private_key_info_encrypt_to_pem(
                &self.key,
                pass_c.as_ptr(),
                fp,
            )
        };
        unsafe { libc::fclose(fp) };
        ok_or_library_error(ret, "sm2_private_key_info_encrypt_to_pem")
    }

    /// Compute the Z value (hash of signer identity + curve parameters + public key).
    pub fn compute_z(&self, id: &str) -> Result<[u8; 32], GmsslError> {
        let id_c = std::ffi::CString::new(id)
            .map_err(|_| GmsslError::InvalidInput("ID contains NUL byte"))?;
        let mut z = [0u8; 32];
        ok_or_library_error(
            unsafe {
                gmssl_rs_sys::sm2_compute_z(
                    z.as_mut_ptr(),
                    &self.key.public_key,
                    id_c.as_ptr(),
                    id.len(),
                )
            },
            "sm2_compute_z",
        )?;
        Ok(z)
    }

    /// Returns true if this key has a private key.
    pub fn has_private_key(&self) -> bool {
        self.has_private_key
    }

    // Internal: get raw key pointer
    pub(crate) fn as_ptr(&self) -> *const gmssl_rs_sys::SM2_KEY {
        &self.key
    }
}

/// SM2 streaming signer.
///
/// Follows the init/update/finish pattern for signing arbitrary-length messages.
/// The signer computes SM3(Z || message) internally, where Z is derived from
/// the signer's identity and public key per GM/T 0003.5.
pub struct Sm2Signer {
    ctx: Box<MaybeUninit<gmssl_rs_sys::SM2_SIGN_CTX>>,
}

impl Sm2Signer {
    /// Create a new SM2 signer.
    ///
    /// `id` is the signer's identity string. If `None`, the default ID
    /// "1234567812345678" is used per the GM/T standard.
    pub fn new(key: &Sm2Key, id: Option<&str>) -> Result<Self, GmsslError> {
        if !key.has_private_key {
            return Err(GmsslError::InvalidKey("private key required for signing"));
        }
        let id = id.unwrap_or("1234567812345678");
        let id_c = std::ffi::CString::new(id)
            .map_err(|_| GmsslError::InvalidInput("ID contains NUL byte"))?;

        let mut ctx = Box::new(MaybeUninit::uninit());
        ok_or_library_error(
            unsafe {
                gmssl_rs_sys::sm2_sign_init(
                    ctx.as_mut_ptr(),
                    key.as_ptr(),
                    id_c.as_ptr(),
                    id.len(),
                )
            },
            "sm2_sign_init",
        )?;
        Ok(Sm2Signer { ctx })
    }

    /// Feed message data into the signature computation.
    pub fn update(&mut self, data: &[u8]) -> Result<(), GmsslError> {
        ok_or_library_error(
            unsafe {
                gmssl_rs_sys::sm2_sign_update(self.ctx.as_mut_ptr(), data.as_ptr(), data.len())
            },
            "sm2_sign_update",
        )
    }

    /// Finalize and produce the DER-encoded signature.
    pub fn finish(&mut self) -> Result<Vec<u8>, GmsslError> {
        let mut sig = vec![0u8; gmssl_rs_sys::SM2_MAX_SIGNATURE_SIZE];
        let mut siglen: usize = sig.len();
        ok_or_library_error(
            unsafe {
                gmssl_rs_sys::sm2_sign_finish(
                    self.ctx.as_mut_ptr(),
                    sig.as_mut_ptr(),
                    &mut siglen,
                )
            },
            "sm2_sign_finish",
        )?;
        // GmSSL sets *siglen = 0 before DER encoding, causing size_t wrap.
        // Compute actual DER size from ASN.1 SEQUENCE header: 0x30 || len || content
        truncate_der_sequence(&mut sig);
        Ok(sig)
    }

    /// One-shot sign: sign a complete message.
    pub fn sign(key: &Sm2Key, id: Option<&str>, data: &[u8]) -> Result<Vec<u8>, GmsslError> {
        let mut signer = Sm2Signer::new(key, id)?;
        signer.update(data)?;
        signer.finish()
    }
}

impl std::fmt::Debug for Sm2Signer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Sm2Signer").finish()
    }
}

/// SM2 streaming verifier.
pub struct Sm2Verifier {
    ctx: Box<MaybeUninit<gmssl_rs_sys::SM2_VERIFY_CTX>>,
}

impl Sm2Verifier {
    /// Create a new SM2 verifier.
    pub fn new(key: &Sm2Key, id: Option<&str>) -> Result<Self, GmsslError> {
        let id = id.unwrap_or("1234567812345678");
        let id_c = std::ffi::CString::new(id)
            .map_err(|_| GmsslError::InvalidInput("ID contains NUL byte"))?;

        let mut ctx = Box::new(MaybeUninit::uninit());
        ok_or_library_error(
            unsafe {
                gmssl_rs_sys::sm2_verify_init(
                    ctx.as_mut_ptr(),
                    key.as_ptr(),
                    id_c.as_ptr(),
                    id.len(),
                )
            },
            "sm2_verify_init",
        )?;
        Ok(Sm2Verifier { ctx })
    }

    /// Feed message data into the verification computation.
    pub fn update(&mut self, data: &[u8]) -> Result<(), GmsslError> {
        ok_or_library_error(
            unsafe {
                gmssl_rs_sys::sm2_verify_update(self.ctx.as_mut_ptr(), data.as_ptr(), data.len())
            },
            "sm2_verify_update",
        )
    }

    /// Finalize and verify the signature against the accumulated message.
    ///
    /// Returns `Ok(true)` if valid, `Ok(false)` if invalid, `Err` on library error.
    pub fn finish(&mut self, sig: &[u8]) -> Result<bool, GmsslError> {
        verify_result(
            unsafe {
                gmssl_rs_sys::sm2_verify_finish(
                    self.ctx.as_mut_ptr(),
                    sig.as_ptr(),
                    sig.len(),
                )
            },
            "sm2_verify_finish",
        )
    }

    /// One-shot verify: verify a signature over a complete message.
    pub fn verify(
        key: &Sm2Key,
        id: Option<&str>,
        data: &[u8],
        sig: &[u8],
    ) -> Result<bool, GmsslError> {
        let mut verifier = Sm2Verifier::new(key, id)?;
        verifier.update(data)?;
        verifier.finish(sig)
    }
}

impl std::fmt::Debug for Sm2Verifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Sm2Verifier").finish()
    }
}

/// SM2 encryption (one-shot).
///
/// Encrypts data for the given public key. Maximum plaintext size is 255 bytes
/// (SM2 ciphertext format limitation).
pub fn sm2_encrypt(key: &Sm2Key, data: &[u8]) -> Result<Vec<u8>, GmsslError> {
    if data.len() > gmssl_rs_sys::SM2_MAX_PLAINTEXT_SIZE {
        return Err(GmsslError::InvalidInput(
            "SM2 plaintext exceeds 255 bytes maximum",
        ));
    }
    let mut out = vec![0u8; gmssl_rs_sys::SM2_MAX_CIPHERTEXT_SIZE];
    let mut outlen: usize = out.len();
    ok_or_library_error(
        unsafe {
            gmssl_rs_sys::sm2_encrypt(
                key.as_ptr(),
                data.as_ptr(),
                data.len(),
                out.as_mut_ptr(),
                &mut outlen,
            )
        },
        "sm2_encrypt",
    )?;
    // GmSSL sets *outlen = 0 before DER encoding, causing size_t wrap.
    truncate_der_sequence(&mut out);
    Ok(out)
}

/// SM2 decryption (one-shot).
///
/// Decrypts data using the given private key.
pub fn sm2_decrypt(key: &Sm2Key, ciphertext: &[u8]) -> Result<Vec<u8>, GmsslError> {
    if !key.has_private_key {
        return Err(GmsslError::InvalidKey("private key required for decryption"));
    }
    let mut out = vec![0u8; ciphertext.len()];
    let mut outlen: usize = out.len();
    ok_or_library_error(
        unsafe {
            gmssl_rs_sys::sm2_decrypt(
                key.as_ptr(),
                ciphertext.as_ptr(),
                ciphertext.len(),
                out.as_mut_ptr(),
                &mut outlen,
            )
        },
        "sm2_decrypt",
    )?;
    out.truncate(outlen);
    Ok(out)
}

/// SM2 ECDH key exchange.
///
/// Computes the shared secret from the local private key and the peer's public key.
pub fn sm2_ecdh(key: &Sm2Key, peer_key: &Sm2Key) -> Result<[u8; 32], GmsslError> {
    if !key.has_private_key {
        return Err(GmsslError::InvalidKey("private key required for ECDH"));
    }
    let mut out = [0u8; 32];
    ok_or_library_error(
        unsafe { gmssl_rs_sys::sm2_do_ecdh(key.as_ptr(), peer_key.as_ptr(), out.as_mut_ptr()) },
        "sm2_do_ecdh",
    )?;
    Ok(out)
}

/// Truncate a Vec containing a DER SEQUENCE to its actual encoded size.
///
/// GmSSL DER encoding functions set `*outlen = 0` before starting, causing
/// unsigned size_t wrap when they decrement. We recover the actual size from
/// the ASN.1 SEQUENCE header: tag (0x30) + length byte + content.
fn truncate_der_sequence(data: &mut Vec<u8>) {
    if data.len() >= 2 && data[0] == 0x30 {
        let content_len = data[1] as usize;
        let total = if content_len < 0x80 {
            // Short form: length byte IS the content length
            2 + content_len
        } else if content_len == 0x81 && data.len() >= 3 {
            // Long form: 1 byte of length follows
            2 + 1 + data[2] as usize
        } else if content_len == 0x82 && data.len() >= 4 {
            // Long form: 2 bytes of length follow
            let l = u16::from_be_bytes([data[2], data[3]]) as usize;
            2 + 2 + l
        } else {
            return; // unknown encoding, don't truncate
        };
        if total <= data.len() {
            data.truncate(total);
        }
    }
}

#[cfg(test)]
mod tests;
