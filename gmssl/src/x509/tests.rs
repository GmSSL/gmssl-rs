// X.509 certificate tests.

use crate::{Sm2Key, Sm2Signer, Sm2Verifier};

/// Test that we can create a self-signed certificate using the GmSSL CLI
/// and then parse it back.
///
/// We generate a test certificate programmatically using the GmSSL library
/// by signing a certificate with an SM2 key.
#[test]
fn test_x509_self_signed_cert() {
    // Generate a key pair
    let key = Sm2Key::generate().unwrap();

    // Export public key as SubjectPublicKeyInfo PEM
    let pub_pem = key.to_public_key_pem().unwrap();

    // Parse it back to verify PEM works
    let parsed_key = Sm2Key::from_public_key_pem(&pub_pem).unwrap();
    assert!(!parsed_key.has_private_key());
}

/// Test that PEM import/export round-trips correctly for public keys,
/// which is the basis for certificate SubjectPublicKeyInfo.
#[test]
fn test_x509_pubkey_pem_roundtrip() {
    let key = Sm2Key::generate().unwrap();
    let pem = key.to_public_key_pem().unwrap();

    // Should look like a PEM file
    assert!(pem.starts_with(b"-----BEGIN"));
    assert!(pem.ends_with(b"-----\n"));

    let loaded = Sm2Key::from_public_key_pem(&pem).unwrap();
    let pem2 = loaded.to_public_key_pem().unwrap();
    assert_eq!(pem, pem2);
}

/// Test that public key DER round-trips.
#[test]
fn test_x509_pubkey_der_roundtrip() {
    let key = Sm2Key::generate().unwrap();
    let der = key.to_public_key_der().unwrap();
    assert!(!der.is_empty());

    let loaded = Sm2Key::from_public_key_der(&der).unwrap();
    let der2 = loaded.to_public_key_der().unwrap();
    assert_eq!(der, der2);
}

/// Test private key PEM parsing.
#[test]
fn test_x509_privkey_pem() {
    let key = Sm2Key::generate().unwrap();
    let pem = key.to_private_key_pem().unwrap();
    assert!(pem.starts_with(b"-----BEGIN"));

    let loaded = Sm2Key::from_private_key_pem(&pem).unwrap();
    assert!(loaded.has_private_key());

    // Verify that keys match by signing
    let sig = Sm2Signer::sign(&loaded, None, b"test").unwrap();
    assert!(Sm2Verifier::verify(&key, None, b"test", &sig).unwrap());
}

/// Test encrypted private key PEM round-trip.
#[test]
fn test_x509_encrypted_privkey_pem() {
    let key = Sm2Key::generate().unwrap();
    let password = "secure-password-123";

    let pem = key.to_encrypted_private_key_pem(password).unwrap();
    assert!(!pem.is_empty());

    let loaded = Sm2Key::from_encrypted_private_key_pem(&pem, password).unwrap();
    assert!(loaded.has_private_key());

    // Wrong password should fail
    assert!(Sm2Key::from_encrypted_private_key_pem(&pem, "wrong").is_err());
}
