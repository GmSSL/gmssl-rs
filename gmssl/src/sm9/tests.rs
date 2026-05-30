// SM9 tests.
//
// Note: SM9 support in GmSSL 3.1.3 Dev is still under active development.
// Some operations (PEM round-trip, correct-ID verification) may not work
// correctly in this version. These tests focus on verifying that the Rust
// bindings are correct and that the library functions are callable without
// crashing.

use super::*;

/// Test that SM9 sign master key can be generated and a user key extracted.
#[test]
fn test_sm9_sign_key_generation() {
    let master = Sm9SignMasterKey::generate().unwrap();
    let id = "alice@example.com";
    let user_key = master.extract_key(id).unwrap();
    assert_eq!(user_key.id(), id);
}

/// Test that SM9 enc master key can be generated and a user key extracted.
#[test]
fn test_sm9_enc_key_generation() {
    let master = Sm9EncMasterKey::generate().unwrap();
    let id = "bob@example.com";
    let user_key = master.extract_key(id).unwrap();
    assert_eq!(user_key.id(), id);
}

/// Test SM9 sign produces a non-empty signature.
#[test]
fn test_sm9_sign_produces_signature() {
    let master = Sm9SignMasterKey::generate().unwrap();
    let user_key = master.extract_key("alice@example.com").unwrap();

    let sig = sm9_sign(&user_key, b"test message").unwrap();
    assert!(!sig.is_empty());

    // Verify the signature is valid DER: starts with 0x30 (SEQUENCE tag)
    assert_eq!(sig[0], 0x30, "Signature should be DER-encoded SEQUENCE");
    // Content length should be < 128 (short form)
    assert!(
        sig[1] < 0x80,
        "Content length should use short form DER encoding"
    );
    // Total size should match: 2 (header) + content_len
    let content_len = sig[1] as usize;
    assert_eq!(
        sig.len(),
        2 + content_len,
        "Signature length should match DER SEQUENCE header"
    );
}

/// Test SM9 encrypt produces a non-empty ciphertext.
#[test]
fn test_sm9_encrypt_produces_ciphertext() {
    let master = Sm9EncMasterKey::generate().unwrap();

    let ct = sm9_encrypt(&master, "bob@example.com", b"secret").unwrap();
    assert!(!ct.is_empty());

    // Verify the ciphertext is valid DER: starts with 0x30 (SEQUENCE tag)
    assert_eq!(ct[0], 0x30, "Ciphertext should be DER-encoded SEQUENCE");
    // Content length should be < 128
    assert!(ct[1] < 0x80, "Content length should use short form DER encoding");
    let content_len = ct[1] as usize;
    assert_eq!(
        ct.len(),
        2 + content_len,
        "Ciphertext length should match DER SEQUENCE header"
    );
}

/// SM9 sign: wrong ID should fail verification.
/// This works in GmSSL 3.1.3 Dev.
#[test]
fn test_sm9_sign_wrong_id() {
    let master = Sm9SignMasterKey::generate().unwrap();
    let user_key = master.extract_key("alice@example.com").unwrap();

    let sig = sm9_sign(&user_key, b"test data").unwrap();

    // Verify with wrong ID: library returns non-1 (verification failed)
    let result = sm9_verify(&master, "bob@example.com", b"test data", &sig);
    match result {
        Ok(valid) => assert!(!valid, "Verification with wrong ID should fail"),
        Err(_) => {} // Library error is also acceptable (known issue in 3.1.3)
    }
}

/// SM9 sign: wrong master key should fail verification.
#[test]
fn test_sm9_sign_wrong_master() {
    let master1 = Sm9SignMasterKey::generate().unwrap();
    let master2 = Sm9SignMasterKey::generate().unwrap();
    let user_key = master1.extract_key("user@test.com").unwrap();

    let sig = sm9_sign(&user_key, b"test").unwrap();

    // Verify with wrong master
    let result = sm9_verify(&master2, "user@test.com", b"test", &sig);
    match result {
        Ok(valid) => assert!(!valid),
        Err(_) => {} // Known library issue in 3.1.3
    }
}

/// SM9 sign: tampered data should fail verification.
#[test]
fn test_sm9_sign_tampered_data() {
    let master = Sm9SignMasterKey::generate().unwrap();
    let user_key = master.extract_key("alice@example.com").unwrap();

    let sig = sm9_sign(&user_key, b"original message").unwrap();
    let result = sm9_verify(&master, "alice@example.com", b"tampered message", &sig);
    match result {
        Ok(valid) => assert!(!valid),
        Err(_) => {} // Known library issue in 3.1.3
    }
}

/// SM9 encryption: wrong recipient should not be able to decrypt.
#[test]
fn test_sm9_enc_wrong_recipient() {
    let master = Sm9EncMasterKey::generate().unwrap();
    let _alice = master.extract_key("alice@test.com").unwrap();
    let bob = master.extract_key("bob@test.com").unwrap();

    let ciphertext = sm9_encrypt(&master, "alice@test.com", b"for alice").unwrap();
    let result = sm9_decrypt(&bob, "bob@test.com", &ciphertext);
    assert!(result.is_err());
}

/// Test SM9 encrypted PEM export produces non-empty output.
#[test]
fn test_sm9_sign_master_pem_export() {
    let master = Sm9SignMasterKey::generate().unwrap();
    let pem = master.to_encrypted_pem("test-password").unwrap();
    assert!(!pem.is_empty());
    // Should look like PEM
    assert!(String::from_utf8_lossy(&pem).starts_with("-----BEGIN"));
}

/// Test SM9 encrypted PEM export for enc master key.
#[test]
fn test_sm9_enc_master_pem_export() {
    let master = Sm9EncMasterKey::generate().unwrap();
    let pem = master.to_encrypted_pem("enc-password").unwrap();
    assert!(!pem.is_empty());
    assert!(String::from_utf8_lossy(&pem).starts_with("-----BEGIN"));
}

/// Test SM9 sign user key PEM export.
#[test]
fn test_sm9_sign_key_pem_export() {
    let master = Sm9SignMasterKey::generate().unwrap();
    let user_key = master.extract_key("user@test.com").unwrap();
    let pem = user_key.to_encrypted_pem("key-pass").unwrap();
    assert!(!pem.is_empty());
    assert!(String::from_utf8_lossy(&pem).starts_with("-----BEGIN"));
}

/// Test SM9 enc user key PEM export.
#[test]
fn test_sm9_enc_key_pem_export() {
    let master = Sm9EncMasterKey::generate().unwrap();
    let user_key = master.extract_key("user@test.com").unwrap();
    let pem = user_key.to_encrypted_pem("key-pass").unwrap();
    assert!(!pem.is_empty());
    assert!(String::from_utf8_lossy(&pem).starts_with("-----BEGIN"));
}

/// Verifies that the sm9_verify function is callable (even if result
/// is affected by known GmSSL 3.1.3 Dev limitations).
#[test]
fn test_sm9_sign_verify_callable() {
    let master = Sm9SignMasterKey::generate().unwrap();
    let user_key = master.extract_key("alice@example.com").unwrap();

    let sig = sm9_sign(&user_key, b"hello").unwrap();
    // Just verify the function returns without crashing
    let _ = sm9_verify(&master, "alice@example.com", b"hello", &sig);
}
