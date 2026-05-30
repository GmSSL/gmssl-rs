// SM2 tests.

use super::*;

/// Generate key and do sign/verify round-trip.
#[test]
fn test_sm2_sign_verify_roundtrip() {
    let key = Sm2Key::generate().unwrap();
    assert!(key.has_private_key());

    let data = b"message to sign and verify";
    let sig = Sm2Signer::sign(&key, None, data).unwrap();
    assert!(!sig.is_empty());

    let valid = Sm2Verifier::verify(&key, None, data, &sig).unwrap();
    assert!(valid);
}

/// Sign with one key, verify with another should fail (not error).
#[test]
fn test_sm2_wrong_key_fails() {
    let key1 = Sm2Key::generate().unwrap();
    let key2 = Sm2Key::generate().unwrap();

    let data = b"test message";
    let sig = Sm2Signer::sign(&key1, None, data).unwrap();

    // Verify with wrong key should return Ok(false), not Err
    let valid = Sm2Verifier::verify(&key2, None, data, &sig).unwrap();
    assert!(!valid);
}

/// Tampered signature should not verify.
#[test]
fn test_sm2_tampered_signature() {
    let key = Sm2Key::generate().unwrap();
    let data = b"message";

    let mut sig = Sm2Signer::sign(&key, None, data).unwrap();
    // Tamper with the signature
    if let Some(b) = sig.last_mut() {
        *b ^= 1;
    }

    let valid = Sm2Verifier::verify(&key, None, data, &sig).unwrap();
    assert!(!valid);
}

/// Encrypt/decrypt round-trip.
#[test]
fn test_sm2_encrypt_decrypt_roundtrip() {
    let key = Sm2Key::generate().unwrap();

    let plaintext = b"short message";
    let ciphertext = sm2_encrypt(&key, plaintext).unwrap();
    let decrypted = sm2_decrypt(&key, &ciphertext).unwrap();
    assert_eq!(&decrypted, plaintext);
}

/// Encrypt/decrypt with maximum plaintext size (255 bytes).
#[test]
fn test_sm2_encrypt_max_plaintext() {
    let key = Sm2Key::generate().unwrap();
    let plaintext = vec![0x42u8; 255];

    let ciphertext = sm2_encrypt(&key, &plaintext).unwrap();
    let decrypted = sm2_decrypt(&key, &ciphertext).unwrap();
    assert_eq!(&decrypted, &plaintext);
}

/// Encrypt with public key only, decrypt should fail.
#[test]
fn test_sm2_encrypt_public_only() {
    let key = Sm2Key::generate().unwrap();
    let pub_pem = key.to_public_key_pem().unwrap();
    let pub_only_key = Sm2Key::from_public_key_pem(&pub_pem).unwrap();
    assert!(!pub_only_key.has_private_key());

    // Encryption with public key should work
    let ciphertext = sm2_encrypt(&pub_only_key, b"data").unwrap();
    // Decryption should fail (no private key)
    let result = sm2_decrypt(&pub_only_key, &ciphertext);
    assert!(result.is_err());
}

/// PEM round-trip: private key.
#[test]
fn test_sm2_pem_roundtrip_private() {
    let key = Sm2Key::generate().unwrap();
    let pem = key.to_private_key_pem().unwrap();
    assert!(pem.starts_with(b"-----BEGIN"));

    let loaded = Sm2Key::from_private_key_pem(&pem).unwrap();
    assert!(loaded.has_private_key());

    // Sign with loaded, verify with original
    let sig = Sm2Signer::sign(&loaded, None, b"test").unwrap();
    assert!(Sm2Verifier::verify(&key, None, b"test", &sig).unwrap());
}

/// PEM round-trip: public key.
#[test]
fn test_sm2_pem_roundtrip_public() {
    let key = Sm2Key::generate().unwrap();
    let pem = key.to_public_key_pem().unwrap();
    assert!(pem.starts_with(b"-----BEGIN"));

    let pub_key = Sm2Key::from_public_key_pem(&pem).unwrap();
    assert!(!pub_key.has_private_key());

    // Verify a signature using the re-imported public key
    let sig = Sm2Signer::sign(&key, None, b"test").unwrap();
    assert!(Sm2Verifier::verify(&pub_key, None, b"test", &sig).unwrap());
}

/// Encrypted PEM round-trip.
#[test]
fn test_sm2_encrypted_pem_roundtrip() {
    let key = Sm2Key::generate().unwrap();
    let password = "my-secret-password";

    let encrypted_pem = key.to_encrypted_private_key_pem(password).unwrap();
    assert!(!encrypted_pem.is_empty());

    let loaded = Sm2Key::from_encrypted_private_key_pem(&encrypted_pem, password).unwrap();
    assert!(loaded.has_private_key());

    // Wrong password should fail
    let result = Sm2Key::from_encrypted_private_key_pem(&encrypted_pem, "wrong-password");
    assert!(result.is_err());
}

/// DER round-trip.
#[test]
fn test_sm2_der_roundtrip() {
    let key = Sm2Key::generate().unwrap();

    // Public key DER
    let pub_der = key.to_public_key_der().unwrap();
    let pub_key = Sm2Key::from_public_key_der(&pub_der).unwrap();
    assert!(!pub_key.has_private_key());

    // Verify with re-imported public key
    let sig = Sm2Signer::sign(&key, None, b"test").unwrap();
    assert!(Sm2Verifier::verify(&pub_key, None, b"test", &sig).unwrap());

    // Private key DER
    let priv_der = key.to_private_key_der().unwrap();
    let priv_key = Sm2Key::from_private_key_der(&priv_der).unwrap();
    assert!(priv_key.has_private_key());

    let sig2 = Sm2Signer::sign(&priv_key, None, b"test2").unwrap();
    assert!(Sm2Verifier::verify(&key, None, b"test2", &sig2).unwrap());
}

/// Streaming sign and verify.
#[test]
fn test_sm2_streaming_sign_verify() {
    let key = Sm2Key::generate().unwrap();
    let id = "alice@test.com";

    let mut signer = Sm2Signer::new(&key, Some(id)).unwrap();
    signer.update(b"part1 ").unwrap();
    signer.update(b"part2 ").unwrap();
    signer.update(b"part3").unwrap();
    let sig = signer.finish().unwrap();

    let mut verifier = Sm2Verifier::new(&key, Some(id)).unwrap();
    verifier.update(b"part1 part2 part3").unwrap();
    let valid = verifier.finish(&sig).unwrap();
    assert!(valid);
}

/// ECDH key exchange.
#[test]
fn test_sm2_ecdh() {
    let alice = Sm2Key::generate().unwrap();
    let bob = Sm2Key::generate().unwrap();

    let shared_alice = sm2_ecdh(&alice, &bob).unwrap();
    let shared_bob = sm2_ecdh(&bob, &alice).unwrap();

    // Both sides should compute the same shared secret
    assert_eq!(shared_alice, shared_bob);

    // Should not be all zeros
    assert!(!shared_alice.iter().all(|&b| b == 0));
}

/// Compute Z value.
#[test]
fn test_sm2_compute_z() {
    let key = Sm2Key::generate().unwrap();
    let z = key.compute_z("1234567812345678").unwrap();
    assert_eq!(z.len(), 32);
    assert!(!z.iter().all(|&b| b == 0));
}

/// Default ID signing.
#[test]
fn test_sm2_with_custom_id() {
    let key = Sm2Key::generate().unwrap();
    let custom_id = "user@example.com";

    let sig = Sm2Signer::sign(&key, Some(custom_id), b"hello").unwrap();
    let valid = Sm2Verifier::verify(&key, Some(custom_id), b"hello", &sig).unwrap();
    assert!(valid);

    // Wrong ID should fail verification
    let wrong_id = Sm2Verifier::verify(&key, Some("other@test.com"), b"hello", &sig).unwrap();
    assert!(!wrong_id);
}
