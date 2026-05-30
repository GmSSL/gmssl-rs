// SM3 hash tests using known-answer test vectors from GM/T 0004-2012.

use super::*;

/// SM3("abc") test vector from the standard.
#[test]
fn test_sm3_abc() {
    let dgst = Sm3::digest(b"abc");
    let expected =
        hex::decode("66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0")
            .unwrap();
    assert_eq!(&dgst[..], &expected[..]);
}

/// SM3("") empty string test vector.
#[test]
fn test_sm3_empty() {
    let dgst = Sm3::digest(b"");
    let expected =
        hex::decode("1ab21d8355cfa17f8e61194831e81a8f22bec8c728fefb747ed035eb5082aa2b")
            .unwrap();
    assert_eq!(&dgst[..], &expected[..]);
}

/// SM3 of the standard 64-byte block.
#[test]
fn test_sm3_512bit() {
    // "abcd" repeated 16 times = 64 bytes = 512 bits
    let msg = b"abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd";
    let dgst = Sm3::digest(msg);
    let expected =
        hex::decode("debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732")
            .unwrap();
    assert_eq!(&dgst[..], &expected[..]);
}

/// Streaming hash should equal one-shot hash.
#[test]
fn test_sm3_streaming_equiv() {
    let msg = b"Hello, GmSSL SM3 streaming test message!";
    let one_shot = Sm3::digest(msg);

    let mut hasher = Sm3::new();
    // Feed byte by byte
    for &b in msg.iter() {
        hasher.update(&[b]);
    }
    let streaming = hasher.finish();
    assert_eq!(one_shot, streaming);
}

/// Reset and reuse.
#[test]
fn test_sm3_reset() {
    let mut hasher = Sm3::new();
    hasher.update(b"first message");
    let first = hasher.finish();

    hasher.reset();
    hasher.update(b"second message");
    let second = hasher.finish();

    // Should not be equal
    assert_ne!(first, second);
    // second should equal one-shot
    assert_eq!(second, Sm3::digest(b"second message"));
}

/// HMAC-SM3 basic test
#[test]
fn test_sm3_hmac_basic() {
    let key = b"my secret key";
    let data = b"message to authenticate";
    let mac1 = Sm3Hmac::mac(key, data);

    // Same key, same data = same MAC
    let mac2 = Sm3Hmac::mac(key, data);
    assert_eq!(mac1, mac2);

    // Different data = different MAC
    let mac3 = Sm3Hmac::mac(key, b"different message");
    assert_ne!(mac1, mac3);

    // Different key = different MAC
    let mac4 = Sm3Hmac::mac(b"different secret key", data);
    assert_ne!(mac1, mac4);
}

/// HMAC-SM3 streaming test
#[test]
fn test_sm3_hmac_streaming() {
    let key = b"hmac key";
    let msg = b"streaming hmac test";

    let one_shot = Sm3Hmac::mac(key, msg);

    let mut hmac = Sm3Hmac::new(key);
    hmac.update(b"streaming ");
    hmac.update(b"hmac test");
    let streaming = hmac.finish();

    assert_eq!(one_shot, streaming);
}

/// HMAC-SM3 reset
#[test]
fn test_sm3_hmac_reset() {
    let mut hmac = Sm3Hmac::new(b"key1");
    hmac.update(b"data");
    let mac1 = hmac.finish();

    hmac.reset(b"key1");
    hmac.update(b"data");
    let mac2 = hmac.finish();
    assert_eq!(mac1, mac2);

    hmac.reset(b"key2");
    hmac.update(b"data");
    let mac3 = hmac.finish();
    assert_ne!(mac1, mac3);
}

/// SM3 PBKDF2 basic test
#[test]
fn test_sm3_pbkdf2_basic() {
    let password = b"password";
    let salt = b"salt";
    let mut key = [0u8; 32];
    sm3_pbkdf2(password, salt, 10000, &mut key).unwrap();

    // Second call with same params should produce same key
    let mut key2 = [0u8; 32];
    sm3_pbkdf2(password, salt, 10000, &mut key2).unwrap();
    assert_eq!(key, key2);

    // Different salt = different key
    let mut key3 = [0u8; 32];
    sm3_pbkdf2(password, b"different salt", 10000, &mut key3).unwrap();
    assert_ne!(key, key3);
}

/// SM3 PBKDF2 with different output lengths
#[test]
fn test_sm3_pbkdf2_lengths() {
    let password = b"test password";
    let salt = b"test salt";

    for &len in &[16, 32, 48, 64] {
        let mut key = vec![0u8; len];
        sm3_pbkdf2(password, salt, 10000, &mut key).unwrap();
        assert_eq!(key.len(), len);
        // Should not be all zeros
        assert!(!key.iter().all(|&b| b == 0));
    }
}
