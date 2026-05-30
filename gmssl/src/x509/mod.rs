// X.509 certificate handling.
//
// Supports parsing and verification of SM2 X.509v3 certificates,
// certificate chains, CSR (certificate signing requests), and CRLs.

use std::ptr;

use gmssl_sys;

use crate::error::{ok_or_library_error, verify_result, GmsslError};
use crate::pem_helpers;

/// Maximum size for a single PEM/DER certificate.
const X509_CERT_MAX_SIZE: usize = 8192;
/// Maximum size for a certificate chain.
const X509_CERTS_MAX_SIZE: usize = 65536;

/// X.509 certificate (stored as DER bytes internally).
#[derive(Debug, Clone)]
pub struct X509Cert {
    der: Vec<u8>,
}

impl X509Cert {
    /// Parse a certificate from DER bytes.
    pub fn from_der(der: &[u8]) -> Result<Self, GmsslError> {
        // Validate by extracting details
        unsafe {
            let mut cert_ptr: *const u8 = ptr::null();
            let mut cert_len: usize = 0;
            let mut in_ptr: *const u8 = der.as_ptr();
            let mut in_len: usize = der.len();
            let ret = gmssl_sys::x509_cert_from_der(
                &mut cert_ptr,
                &mut cert_len,
                &mut in_ptr,
                &mut in_len,
            );
            ok_or_library_error(ret, "x509_cert_from_der")?;

            // The C function sets cert_ptr to point into the input, but we want our own copy.
            Ok(X509Cert {
                der: der.to_vec(),
            })
        }
    }

    /// Parse a certificate from PEM data.
    pub fn from_pem(pem_data: &[u8]) -> Result<Self, GmsslError> {
        let mut buf = vec![0u8; X509_CERT_MAX_SIZE];
        let mut len: usize = buf.len();

        let fp = unsafe { pem_helpers::file_from_bytes(pem_data)? };
        let ret = unsafe {
            gmssl_sys::x509_cert_from_pem(buf.as_mut_ptr(), &mut len, buf.len(), fp)
        };
        unsafe { libc::fclose(fp) };
        ok_or_library_error(ret, "x509_cert_from_pem")?;

        buf.truncate(len);
        Ok(X509Cert { der: buf })
    }

    /// Export certificate as PEM.
    pub fn to_pem(&self) -> Result<Vec<u8>, GmsslError> {
        unsafe {
            pem_helpers::collect_to_bytes(|fp| {
                gmssl_sys::x509_cert_to_pem(self.der.as_ptr(), self.der.len(), fp)
            })
        }
    }

    /// Get the raw DER-encoded certificate.
    pub fn as_der(&self) -> &[u8] {
        &self.der
    }

    /// Get the certificate subject.
    pub fn subject(&self) -> Result<Vec<u8>, GmsslError> {
        let mut subj: *const u8 = ptr::null();
        let mut subj_len: usize = 0;
        unsafe {
            ok_or_library_error(
                gmssl_sys::x509_cert_get_subject(
                    self.der.as_ptr(),
                    self.der.len(),
                    &mut subj,
                    &mut subj_len,
                ),
                "x509_cert_get_subject",
            )?;
            Ok(std::slice::from_raw_parts(subj, subj_len).to_vec())
        }
    }

    /// Get the certificate issuer.
    pub fn issuer(&self) -> Result<Vec<u8>, GmsslError> {
        let mut issuer: *const u8 = ptr::null();
        let mut issuer_len: usize = 0;
        unsafe {
            ok_or_library_error(
                gmssl_sys::x509_cert_get_issuer(
                    self.der.as_ptr(),
                    self.der.len(),
                    &mut issuer,
                    &mut issuer_len,
                ),
                "x509_cert_get_issuer",
            )?;
            Ok(std::slice::from_raw_parts(issuer, issuer_len).to_vec())
        }
    }

    /// Get the certificate serial number.
    pub fn serial_number(&self) -> Result<Vec<u8>, GmsslError> {
        let mut version: i32 = 0;
        let mut serial: *const u8 = ptr::null();
        let mut serial_len: usize = 0;
        let mut issuer: *const u8 = ptr::null();
        let mut issuer_len: usize = 0;
        let mut not_before: i64 = 0;
        let mut not_after: i64 = 0;
        let mut subject: *const u8 = ptr::null();
        let mut subject_len: usize = 0;
        let mut pub_key: gmssl_sys::X509_KEY = unsafe { std::mem::zeroed() };
        let mut sig_algor: i32 = 0;
        let mut signature: *const u8 = ptr::null();
        let mut signature_len: usize = 0;

        unsafe {
            ok_or_library_error(
                gmssl_sys::x509_cert_get_details(
                    self.der.as_ptr(),
                    self.der.len(),
                    &mut version,
                    &mut serial,
                    &mut serial_len,
                    &mut issuer,
                    &mut issuer_len,
                    &mut not_before,
                    &mut not_after,
                    &mut subject,
                    &mut subject_len,
                    &mut pub_key,
                    &mut sig_algor,
                    &mut signature,
                    &mut signature_len,
                ),
                "x509_cert_get_details",
            )?;
            // Clean up the X509_KEY (may contain heap-allocated data)
            gmssl_sys::x509_key_cleanup(&mut pub_key);
            Ok(std::slice::from_raw_parts(serial, serial_len).to_vec())
        }
    }

    /// Get the validity period as (not_before, not_after) timestamps.
    pub fn validity(&self) -> Result<(i64, i64), GmsslError> {
        let mut version: i32 = 0;
        let mut serial: *const u8 = ptr::null();
        let mut serial_len: usize = 0;
        let mut issuer: *const u8 = ptr::null();
        let mut issuer_len: usize = 0;
        let mut not_before: i64 = 0;
        let mut not_after: i64 = 0;
        let mut subject: *const u8 = ptr::null();
        let mut subject_len: usize = 0;
        let mut pub_key: gmssl_sys::X509_KEY = unsafe { std::mem::zeroed() };
        let mut sig_algor: i32 = 0;
        let mut signature: *const u8 = ptr::null();
        let mut signature_len: usize = 0;

        unsafe {
            ok_or_library_error(
                gmssl_sys::x509_cert_get_details(
                    self.der.as_ptr(),
                    self.der.len(),
                    &mut version,
                    &mut serial,
                    &mut serial_len,
                    &mut issuer,
                    &mut issuer_len,
                    &mut not_before,
                    &mut not_after,
                    &mut subject,
                    &mut subject_len,
                    &mut pub_key,
                    &mut sig_algor,
                    &mut signature,
                    &mut signature_len,
                ),
                "x509_cert_get_details",
            )?;
            gmssl_sys::x509_key_cleanup(&mut pub_key);
        }
        Ok((not_before, not_after))
    }

    /// Verify this certificate against a CA certificate.
    pub fn verify_by_ca(
        &self,
        ca_cert: &X509Cert,
        signer_id: Option<&str>,
    ) -> Result<bool, GmsslError> {
        let id = signer_id.unwrap_or("1234567812345678");
        let id_c = std::ffi::CString::new(id)
            .map_err(|_| GmsslError::InvalidInput("signer ID contains NUL byte"))?;

        verify_result(
            unsafe {
                gmssl_sys::x509_cert_verify_by_ca_cert(
                    self.der.as_ptr(),
                    self.der.len(),
                    ca_cert.der.as_ptr(),
                    ca_cert.der.len(),
                    id_c.as_ptr(),
                    id.len(),
                )
            },
            "x509_cert_verify_by_ca_cert",
        )
    }
}

/// A chain of X.509 certificates.
#[derive(Debug, Clone)]
pub struct X509CertChain {
    der: Vec<u8>,
}

impl X509CertChain {
    /// Parse a certificate chain from PEM data.
    pub fn from_pem(pem_data: &[u8]) -> Result<Self, GmsslError> {
        let mut buf = vec![0u8; X509_CERTS_MAX_SIZE];
        let mut len: usize = buf.len();

        let fp = unsafe { pem_helpers::file_from_bytes(pem_data)? };
        let ret = unsafe {
            gmssl_sys::x509_certs_from_pem(buf.as_mut_ptr(), &mut len, buf.len(), fp)
        };
        unsafe { libc::fclose(fp) };
        ok_or_library_error(ret, "x509_certs_from_pem")?;

        buf.truncate(len);
        Ok(X509CertChain { der: buf })
    }

    /// Get the number of certificates in the chain.
    pub fn count(&self) -> Result<usize, GmsslError> {
        let mut cnt: usize = 0;
        unsafe {
            ok_or_library_error(
                gmssl_sys::x509_certs_get_count(self.der.as_ptr(), self.der.len(), &mut cnt),
                "x509_certs_get_count",
            )?;
        }
        Ok(cnt)
    }

    /// Get a certificate by index.
    pub fn get(&self, index: usize) -> Result<X509Cert, GmsslError> {
        let mut cert: *const u8 = ptr::null();
        let mut cert_len: usize = 0;
        unsafe {
            ok_or_library_error(
                gmssl_sys::x509_certs_get_cert_by_index(
                    self.der.as_ptr(),
                    self.der.len(),
                    index as i32,
                    &mut cert,
                    &mut cert_len,
                ),
                "x509_certs_get_cert_by_index",
            )?;
            Ok(X509Cert {
                der: std::slice::from_raw_parts(cert, cert_len).to_vec(),
            })
        }
    }

    /// Verify the entire certificate chain against a set of root CAs.
    pub fn verify(&self, root_certs: &X509CertChain) -> Result<(), GmsslError> {
        ok_or_library_error(
            unsafe {
                gmssl_sys::x509_certs_verify(
                    self.der.as_ptr(),
                    self.der.len(),
                    0, // certs_type
                    root_certs.der.as_ptr(),
                    root_certs.der.len(),
                    10, // depth
                )
            },
            "x509_certs_verify",
        )
    }
}

#[cfg(test)]
mod tests;
