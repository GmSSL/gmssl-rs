// ZUC stream cipher tests.

use super::*;

/// ZUC round-trip encrypt/decrypt.
#[test]
fn test_zuc_roundtrip() {
    let key = [0x01u8; 16];
    let iv = [0x02u8; 16];
    let plaintext = b"ZUC stream cipher test message for encryption and decryption!";

    // Encrypt (same as decrypt for stream cipher)
    let ct = Zuc::process(&key, &iv, plaintext);
    let pt = Zuc::process(&key, &iv, &ct);

    assert_eq!(&pt[..], &plaintext[..]);
}

/// ZUC with random data round-trip.
#[test]
fn test_zuc_long_data() {
    let key = [0x42u8; 16];
    let iv = [0x24u8; 16];

    // 1KB of data
    let plaintext = vec![0xAAu8; 1024];
    let ct = Zuc::process(&key, &iv, &plaintext);
    let pt = Zuc::process(&key, &iv, &ct);

    assert_eq!(pt, plaintext);
    // Ciphertext should differ from plaintext
    assert_ne!(ct, plaintext);
}

/// ZUC with different keys produces different output.
#[test]
fn test_zuc_different_keys() {
    let iv = [0x02u8; 16];
    let plaintext = b"same plaintext";

    let ct1 = Zuc::process(&[0x01u8; 16], &iv, plaintext);
    let ct2 = Zuc::process(&[0xFFu8; 16], &iv, plaintext);

    assert_ne!(ct1, ct2);
}

/// ZUC keystream generation.
#[test]
fn test_zuc_keystream() {
    let mut zuc = Zuc::new(&[0x01u8; 16], &[0x02u8; 16]);
    let words1 = zuc.generate_keystream(4);
    let words2 = zuc.generate_keystream(4);

    // Successive keystream blocks should differ
    assert_ne!(words1, words2);
    assert_eq!(words1.len(), 4);
    assert_eq!(words2.len(), 4);
}

/// ZUC MAC computation.
#[test]
fn test_zuc_mac() {
    let key = [0x01u8; 16];
    let iv = [0x02u8; 16];

    let mut mac_ctx = ZucMac::new(&key, &iv);
    mac_ctx.update(b"message for MAC");
    let mac1 = mac_ctx.finish(b"", 0);

    // Same key/iv/data = same MAC
    let mut mac_ctx = ZucMac::new(&key, &iv);
    mac_ctx.update(b"message for MAC");
    let mac2 = mac_ctx.finish(b"", 0);

    assert_eq!(mac1, mac2);

    // Different data = different MAC
    let mut mac_ctx = ZucMac::new(&key, &iv);
    mac_ctx.update(b"different message");
    let mac3 = mac_ctx.finish(b"", 0);

    assert_ne!(mac1, mac3);
}

/// ZUC-256 round-trip.
#[test]
fn test_zuc256_roundtrip() {
    let key = [0x01u8; 32];
    let iv = [0x02u8; 23];
    let plaintext = b"ZUC-256 test";

    let mut zuc = Zuc256::new(&key, &iv);
    let ct = zuc.encrypt(plaintext);

    let mut zuc = Zuc256::new(&key, &iv);
    let pt = zuc.encrypt(&ct);

    assert_eq!(&pt[..], &plaintext[..]);
}

/// ZUC streaming encryptor round-trip.
#[test]
fn test_zuc_streaming() {
    let key = [0x01u8; 16];
    let iv = [0x02u8; 16];
    let plaintext = b"streaming ZUC test data for encryption";

    // Encrypt
    let mut enc = ZucEncryptor::new(&key, &iv).unwrap();
    let mut ct = Vec::new();
    ct.extend_from_slice(&enc.update(&plaintext[..10]).unwrap());
    ct.extend_from_slice(&enc.update(&plaintext[10..]).unwrap());
    ct.extend_from_slice(&enc.finish().unwrap());

    // Decrypt
    let mut dec = ZucEncryptor::new(&key, &iv).unwrap();
    let mut pt = Vec::new();
    pt.extend_from_slice(&dec.update(&ct).unwrap());
    pt.extend_from_slice(&dec.finish().unwrap());

    assert_eq!(&pt, plaintext);
}
