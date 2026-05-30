// SM4 block cipher tests.

use super::*;

/// SM4-CBC with PKCS#7 padding: round-trip encrypt/decrypt.
#[test]
fn test_sm4_cbc_roundtrip() {
    let key = [0x01u8; 16];
    let iv = [0x02u8; 16];

    // Short plaintext
    let plaintext = b"Hello, GmSSL SM4!";
    let ciphertext = sm4_cbc_padding_encrypt(&key, &iv, plaintext).unwrap();
    let decrypted = sm4_cbc_padding_decrypt(&key, &iv, &ciphertext).unwrap();
    assert_eq!(&decrypted, plaintext);

    // Exact block boundary
    let plaintext = b"0123456789ABCDEF";
    let ciphertext = sm4_cbc_padding_encrypt(&key, &iv, plaintext).unwrap();
    let decrypted = sm4_cbc_padding_decrypt(&key, &iv, &ciphertext).unwrap();
    assert_eq!(&decrypted, plaintext);

    // Empty payload
    let plaintext = b"";
    let ciphertext = sm4_cbc_padding_encrypt(&key, &iv, plaintext).unwrap();
    let decrypted = sm4_cbc_padding_decrypt(&key, &iv, &ciphertext).unwrap();
    assert_eq!(&decrypted, plaintext);
}

/// SM4-CBC streaming round-trip.
#[test]
fn test_sm4_cbc_streaming_roundtrip() {
    let key = [0x01u8; 16];
    let iv = [0x02u8; 16];
    let plaintext = b"streaming CBC test with multiple update calls";

    // Encrypt
    let mut enc = Sm4CbcEncryptor::new(&key, &iv).unwrap();
    let mut ct = Vec::new();
    ct.extend_from_slice(&enc.update(&plaintext[..10]).unwrap());
    ct.extend_from_slice(&enc.update(&plaintext[10..20]).unwrap());
    ct.extend_from_slice(&enc.update(&plaintext[20..]).unwrap());
    ct.extend_from_slice(&enc.finish().unwrap());

    // Decrypt
    let mut dec = Sm4CbcDecryptor::new(&key, &iv).unwrap();
    let mut pt = Vec::new();
    pt.extend_from_slice(&dec.update(&ct[..16]).unwrap());
    pt.extend_from_slice(&dec.update(&ct[16..]).unwrap());
    pt.extend_from_slice(&dec.finish().unwrap());

    assert_eq!(&pt, plaintext);
}

/// SM4-CBC with wrong key should produce different output.
#[test]
fn test_sm4_cbc_wrong_key() {
    let key1 = [0x01u8; 16];
    let key2 = [0xFFu8; 16];
    let iv = [0x02u8; 16];
    let plaintext = b"test message";

    let ct = sm4_cbc_padding_encrypt(&key1, &iv, plaintext).unwrap();
    // Decrypting with wrong key should fail or produce garbage
    let result = sm4_cbc_padding_decrypt(&key2, &iv, &ct);
    // May fail due to padding error, or succeed with wrong plaintext
    match result {
        Ok(pt) => assert_ne!(&pt, plaintext),
        Err(_) => {} // Padding error is also acceptable
    }
}

/// SM4-CTR round-trip.
#[test]
fn test_sm4_ctr_roundtrip() {
    let key = [0x01u8; 16];
    let ctr = [0x03u8; 16];
    let plaintext = b"SM4 CTR mode test message!";

    // CTR encrypt = decrypt
    let ct = Sm4Ctr::encrypt(&key, &ctr, plaintext).unwrap();
    let pt = Sm4Ctr::encrypt(&key, &ctr, &ct).unwrap();
    assert_eq!(&pt, plaintext);
}

/// SM4-CTR streaming round-trip.
#[test]
fn test_sm4_ctr_streaming() {
    let key = [0x01u8; 16];
    let ctr = [0x03u8; 16];
    let plaintext = b"streaming CTR test data";

    // Encrypt
    let mut enc = Sm4Ctr::new(&key, &ctr).unwrap();
    let mut ct = Vec::new();
    ct.extend_from_slice(&enc.update(&plaintext[..8]).unwrap());
    ct.extend_from_slice(&enc.update(&plaintext[8..]).unwrap());
    ct.extend_from_slice(&enc.finish().unwrap());

    // Decrypt with CTR (same operation)
    let mut dec = Sm4Ctr::new(&key, &ctr).unwrap();
    let mut pt = Vec::new();
    pt.extend_from_slice(&dec.update(&ct).unwrap());
    pt.extend_from_slice(&dec.finish().unwrap());

    assert_eq!(&pt, plaintext);
}

/// SM4-GCM round-trip.
#[test]
fn test_sm4_gcm_roundtrip() {
    let key = hex::decode("0123456789abcdeffedcba9876543210").unwrap();
    let iv = hex::decode("00001234567800000000abcd").unwrap();
    let aad = b"authenticated data";
    let plaintext = b"GCM test plaintext";

    let result = Sm4Gcm::encrypt(&key, &iv, aad, plaintext, 16).unwrap();
    assert_eq!(result.ciphertext.len(), plaintext.len());
    assert_eq!(result.tag.len(), 16);

    let decrypted = Sm4Gcm::decrypt(&key, &iv, aad, &result.tag, &result.ciphertext).unwrap();
    assert_eq!(&decrypted, plaintext);
}

/// SM4-GCM with wrong tag should fail.
#[test]
fn test_sm4_gcm_wrong_tag() {
    let key = hex::decode("0123456789abcdeffedcba9876543210").unwrap();
    let iv = hex::decode("00001234567800000000abcd").unwrap();
    let aad = b"";
    let plaintext = b"test";

    let result = Sm4Gcm::encrypt(&key, &iv, aad, plaintext, 16).unwrap();

    // Tamper with tag
    let mut bad_tag = result.tag.clone();
    bad_tag[0] ^= 1;

    let dec_result = Sm4Gcm::decrypt(&key, &iv, aad, &bad_tag, &result.ciphertext);
    assert!(dec_result.is_err());
}

/// SM4-GCM with wrong AAD should fail.
#[test]
fn test_sm4_gcm_wrong_aad() {
    let key = hex::decode("0123456789abcdeffedcba9876543210").unwrap();
    let iv = hex::decode("00001234567800000000abcd").unwrap();
    let aad = b"correct aad";
    let plaintext = b"test data for GCM";

    let result = Sm4Gcm::encrypt(&key, &iv, aad, plaintext, 16).unwrap();

    // Try to decrypt with wrong AAD
    let dec_result = Sm4Gcm::decrypt(&key, &iv, b"wrong aad", &result.tag, &result.ciphertext);
    assert!(dec_result.is_err());
}

/// SM4-GCM with different tag sizes.
#[test]
fn test_sm4_gcm_tag_sizes() {
    let key = hex::decode("0123456789abcdeffedcba9876543210").unwrap();
    let iv = hex::decode("00001234567800000000abcd").unwrap();
    let aad = b"";
    let plaintext = b"testing tag sizes";

    for &tag_len in &[12, 16] {
        let result = Sm4Gcm::encrypt(&key, &iv, aad, plaintext, tag_len).unwrap();
        assert_eq!(result.tag.len(), tag_len);
        let decrypted = Sm4Gcm::decrypt(&key, &iv, aad, &result.tag, &result.ciphertext).unwrap();
        assert_eq!(&decrypted, plaintext);
    }
}

/// SM4 raw block cipher.
#[test]
fn test_sm4_block_cipher() {
    let key = [0x01u8; 16];
    let sm4 = Sm4Key::new(&key);

    let plaintext = [0x42u8; 16];
    let ciphertext = sm4.encrypt_block(&plaintext);
    let decrypted = sm4.decrypt_block(&ciphertext);

    assert_eq!(decrypted, plaintext);
    assert_ne!(ciphertext, plaintext); // Should be different from plaintext
}
