// gmssl: Safe, idiomatic Rust wrapper for the GmSSL cryptographic library
//
// Provides RAII-based types for SM3 (hash), SM4 (block cipher), SM2 (public key),
// SM9 (identity-based), X.509 (certificates), and ZUC (stream cipher).

pub mod error;
pub mod pem_helpers;
pub mod rand;
pub mod sm2;
pub mod sm3;
pub mod sm4;
pub mod sm9;
pub mod x509;
pub mod zuc;

// Re-exports for convenience
pub use error::GmsslError;
pub use rand::rand_bytes;
pub use sm2::{Sm2Key, Sm2Signer, Sm2Verifier};
pub use sm3::{Sm3, Sm3Hmac};
pub use sm4::{Sm4Cbc, Sm4Ctr, Sm4Gcm, Sm4Key};
pub use sm9::{Sm9EncKey, Sm9EncMasterKey, Sm9SignKey, Sm9SignMasterKey};
pub use x509::{X509Cert, X509CertChain};
pub use zuc::Zuc;
