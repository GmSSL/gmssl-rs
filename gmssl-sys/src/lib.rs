// gmssl-sys: Low-level FFI bindings to libgmssl
//
// All extern "C" function declarations and #[repr(C)] type definitions
// are organized by algorithm, matching the GmSSL 3.1 header structure.
// See https://github.com/guanzhi/GmSSL

#![allow(non_camel_case_types, non_snake_case, dead_code, clippy::missing_safety_doc)]

use libc::{c_char, c_int, c_uint, c_void, FILE, size_t, time_t};

// ============================================================================
// Version
// ============================================================================

pub const GMSSL_VERSION_NUM: c_int = 30103;

extern "C" {
    pub fn gmssl_version_num() -> c_int;
    pub fn gmssl_version_str() -> *const c_char;
}

// ============================================================================
// Random
// ============================================================================

pub const RAND_BYTES_MAX_SIZE: usize = 256;

extern "C" {
    pub fn rand_bytes(buf: *mut u8, buflen: size_t) -> c_int;
}

// ============================================================================
// SM3 Hash
// ============================================================================

pub const SM3_DIGEST_SIZE: usize = 32;
pub const SM3_BLOCK_SIZE: usize = 64;
pub const SM3_STATE_WORDS: usize = 8;
pub const SM3_HMAC_SIZE: usize = SM3_DIGEST_SIZE;

pub const SM3_PBKDF2_MIN_ITER: usize = 10000;
pub const SM3_PBKDF2_MAX_ITER: usize = 16777216 - 1;
pub const SM3_PBKDF2_MAX_SALT_SIZE: usize = 64;
pub const SM3_PBKDF2_DEFAULT_SALT_SIZE: usize = 8;

#[repr(C)]
#[derive(Debug)]
pub struct SM3_CTX {
    pub digest: [u32; SM3_STATE_WORDS],
    pub nblocks: u64,
    pub block: [u8; SM3_BLOCK_SIZE],
    pub num: size_t,
}

#[repr(C)]
#[derive(Debug)]
pub struct SM3_HMAC_CTX {
    pub sm3_ctx: SM3_CTX,
    pub key: [u8; SM3_BLOCK_SIZE],
}

#[repr(C)]
#[derive(Debug)]
pub struct SM3_KDF_CTX {
    pub sm3_ctx: SM3_CTX,
    pub outlen: size_t,
}

extern "C" {
    pub fn sm3_init(ctx: *mut SM3_CTX);
    pub fn sm3_update(ctx: *mut SM3_CTX, data: *const u8, datalen: size_t);
    pub fn sm3_finish(ctx: *mut SM3_CTX, dgst: *mut u8);

    pub fn sm3_hmac_init(ctx: *mut SM3_HMAC_CTX, key: *const u8, keylen: size_t);
    pub fn sm3_hmac_update(ctx: *mut SM3_HMAC_CTX, data: *const u8, datalen: size_t);
    pub fn sm3_hmac_finish(ctx: *mut SM3_HMAC_CTX, mac: *mut u8);

    pub fn pbkdf2_hmac_sm3_genkey(
        pass: *const c_char,
        passlen: size_t,
        salt: *const u8,
        saltlen: size_t,
        iter: size_t,
        outlen: size_t,
        out: *mut u8,
    ) -> c_int;

    pub fn sm3_kdf_init(ctx: *mut SM3_KDF_CTX, outlen: size_t);
    pub fn sm3_kdf_update(ctx: *mut SM3_KDF_CTX, in_: *const u8, inlen: size_t);
    pub fn sm3_kdf_finish(ctx: *mut SM3_KDF_CTX, out: *mut u8);
}

// ============================================================================
// SM4 Block Cipher
// ============================================================================

pub const SM4_KEY_SIZE: usize = 16;
pub const SM4_BLOCK_SIZE: usize = 16;
pub const SM4_NUM_ROUNDS: usize = 32;

pub const SM4_GCM_MAX_IV_SIZE: usize = 64;
pub const SM4_GCM_MIN_IV_SIZE: usize = 1;
pub const SM4_GCM_DEFAULT_IV_SIZE: usize = 12;
pub const SM4_GCM_MIN_AAD_SIZE: usize = 0;
pub const SM4_GCM_MAX_AAD_SIZE: usize = 1 << 24;
pub const SM4_GCM_MIN_PLAINTEXT_SIZE: usize = 0;
pub const SM4_GCM_MAX_TAG_SIZE: usize = 16;
pub const SM4_GCM_MIN_TAG_SIZE: usize = 12;
pub const SM4_GCM_DEFAULT_TAG_SIZE: usize = 16;

#[repr(C)]
#[derive(Debug)]
pub struct SM4_KEY {
    pub rk: [u32; SM4_NUM_ROUNDS],
}

#[repr(C)]
#[derive(Debug)]
pub struct SM4_CBC_CTX {
    pub sm4_key: SM4_KEY,
    pub iv: [u8; SM4_BLOCK_SIZE],
    pub block: [u8; SM4_BLOCK_SIZE],
    pub block_nbytes: size_t,
}

#[repr(C)]
#[derive(Debug)]
pub struct SM4_CTR_CTX {
    pub sm4_key: SM4_KEY,
    pub ctr: [u8; SM4_BLOCK_SIZE],
    pub block: [u8; SM4_BLOCK_SIZE],
    pub block_nbytes: size_t,
}

// Forward declaration for GHASH_CTX (used by SM4_GCM_CTX)
#[repr(C)]
pub struct GHASH_CTX {
    _private: [u8; 272],
}

#[repr(C)]
pub struct SM4_GCM_CTX {
    pub enc_ctx: SM4_CTR_CTX,
    pub mac_ctx: GHASH_CTX,
    pub Y: [u8; 16],
    pub taglen: size_t,
    pub mac: [u8; 16],
    pub maclen: size_t,
    pub encedlen: u64,
}

extern "C" {
    pub fn sm4_set_encrypt_key(key: *mut SM4_KEY, raw_key: *const u8);
    pub fn sm4_set_decrypt_key(key: *mut SM4_KEY, raw_key: *const u8);
    pub fn sm4_encrypt(key: *const SM4_KEY, in_: *const u8, out: *mut u8);

    // One-shot padded CBC
    pub fn sm4_cbc_padding_encrypt(
        key: *const SM4_KEY,
        iv: *const u8,
        in_: *const u8,
        inlen: size_t,
        out: *mut u8,
        outlen: *mut size_t,
    ) -> c_int;
    pub fn sm4_cbc_padding_decrypt(
        key: *const SM4_KEY,
        iv: *const u8,
        in_: *const u8,
        inlen: size_t,
        out: *mut u8,
        outlen: *mut size_t,
    ) -> c_int;

    // Streaming CBC
    pub fn sm4_cbc_encrypt_init(
        ctx: *mut SM4_CBC_CTX,
        key: *const u8,
        iv: *const u8,
    ) -> c_int;
    pub fn sm4_cbc_encrypt_update(
        ctx: *mut SM4_CBC_CTX,
        in_: *const u8,
        inlen: size_t,
        out: *mut u8,
        outlen: *mut size_t,
    ) -> c_int;
    pub fn sm4_cbc_encrypt_finish(
        ctx: *mut SM4_CBC_CTX,
        out: *mut u8,
        outlen: *mut size_t,
    ) -> c_int;
    pub fn sm4_cbc_decrypt_init(
        ctx: *mut SM4_CBC_CTX,
        key: *const u8,
        iv: *const u8,
    ) -> c_int;
    pub fn sm4_cbc_decrypt_update(
        ctx: *mut SM4_CBC_CTX,
        in_: *const u8,
        inlen: size_t,
        out: *mut u8,
        outlen: *mut size_t,
    ) -> c_int;
    pub fn sm4_cbc_decrypt_finish(
        ctx: *mut SM4_CBC_CTX,
        out: *mut u8,
        outlen: *mut size_t,
    ) -> c_int;

    // One-shot CTR
    pub fn sm4_ctr_encrypt(
        key: *const SM4_KEY,
        ctr: *mut u8,
        in_: *const u8,
        inlen: size_t,
        out: *mut u8,
    );

    // Streaming CTR
    pub fn sm4_ctr_encrypt_init(
        ctx: *mut SM4_CTR_CTX,
        key: *const u8,
        ctr: *const u8,
    ) -> c_int;
    pub fn sm4_ctr_encrypt_update(
        ctx: *mut SM4_CTR_CTX,
        in_: *const u8,
        inlen: size_t,
        out: *mut u8,
        outlen: *mut size_t,
    ) -> c_int;
    pub fn sm4_ctr_encrypt_finish(
        ctx: *mut SM4_CTR_CTX,
        out: *mut u8,
        outlen: *mut size_t,
    ) -> c_int;

    // One-shot GCM
    pub fn sm4_gcm_encrypt(
        key: *const SM4_KEY,
        iv: *const u8,
        ivlen: size_t,
        aad: *const u8,
        aadlen: size_t,
        in_: *const u8,
        inlen: size_t,
        out: *mut u8,
        taglen: size_t,
        tag: *mut u8,
    ) -> c_int;
    pub fn sm4_gcm_decrypt(
        key: *const SM4_KEY,
        iv: *const u8,
        ivlen: size_t,
        aad: *const u8,
        aadlen: size_t,
        in_: *const u8,
        inlen: size_t,
        tag: *const u8,
        taglen: size_t,
        out: *mut u8,
    ) -> c_int;

    // Streaming GCM
    pub fn sm4_gcm_encrypt_init(
        ctx: *mut SM4_GCM_CTX,
        key: *const u8,
        keylen: size_t,
        iv: *const u8,
        ivlen: size_t,
        aad: *const u8,
        aadlen: size_t,
        taglen: size_t,
    ) -> c_int;
    pub fn sm4_gcm_encrypt_update(
        ctx: *mut SM4_GCM_CTX,
        in_: *const u8,
        inlen: size_t,
        out: *mut u8,
        outlen: *mut size_t,
    ) -> c_int;
    pub fn sm4_gcm_encrypt_finish(
        ctx: *mut SM4_GCM_CTX,
        out: *mut u8,
        outlen: *mut size_t,
    ) -> c_int;
    pub fn sm4_gcm_decrypt_init(
        ctx: *mut SM4_GCM_CTX,
        key: *const u8,
        keylen: size_t,
        iv: *const u8,
        ivlen: size_t,
        aad: *const u8,
        aadlen: size_t,
        taglen: size_t,
    ) -> c_int;
    pub fn sm4_gcm_decrypt_update(
        ctx: *mut SM4_GCM_CTX,
        in_: *const u8,
        inlen: size_t,
        out: *mut u8,
        outlen: *mut size_t,
    ) -> c_int;
    pub fn sm4_gcm_decrypt_finish(
        ctx: *mut SM4_GCM_CTX,
        out: *mut u8,
        outlen: *mut size_t,
    ) -> c_int;
}

// ============================================================================
// SM2 Public Key Cryptography
// ============================================================================

pub const SM2_DEFAULT_ID: &[u8; 16] = b"1234567812345678";
pub const SM2_DEFAULT_ID_LENGTH: usize = 16;
pub const SM2_MAX_ID_BITS: usize = 65535;
pub const SM2_MAX_ID_LENGTH: usize = SM2_MAX_ID_BITS / 8;

pub const SM2_MIN_SIGNATURE_SIZE: usize = 8;
pub const SM2_MAX_SIGNATURE_SIZE: usize = 72;
pub const SM2_MIN_PLAINTEXT_SIZE: usize = 1;
pub const SM2_MAX_PLAINTEXT_SIZE: usize = 255;
pub const SM2_MIN_CIPHERTEXT_SIZE: usize = 45;
pub const SM2_MAX_CIPHERTEXT_SIZE: usize = 366;

pub const SM2_SIGN_PRE_COMP_COUNT: usize = 32;

pub type sm2_z256_t = [u64; 4];

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct SM2_Z256_POINT {
    pub X: sm2_z256_t,
    pub Y: sm2_z256_t,
    pub Z: sm2_z256_t,
}

#[repr(C)]
#[derive(Debug)]
pub struct SM2_KEY {
    pub public_key: SM2_Z256_POINT,
    pub private_key: sm2_z256_t,
}

#[repr(C)]
#[derive(Debug)]
pub struct SM2_SIGNATURE {
    pub r: [u8; 32],
    pub s: [u8; 32],
}

#[repr(C)]
pub struct SM2_POINT {
    pub x: [u8; 32],
    pub y: [u8; 32],
}

#[repr(C)]
pub struct SM2_CIPHERTEXT {
    pub point: SM2_POINT,
    pub hash: [u8; 32],
    pub ciphertext_size: u8,
    pub ciphertext: [u8; SM2_MAX_PLAINTEXT_SIZE],
}

#[repr(C)]
pub struct SM2_SIGN_PRE_COMP {
    pub k: sm2_z256_t,
    pub x1_modn: sm2_z256_t,
}

#[repr(C)]
pub struct SM2_SIGN_CTX {
    pub sm3_ctx: SM3_CTX,
    pub saved_sm3_ctx: SM3_CTX,
    pub key: SM2_KEY,
    pub fast_sign_private: sm2_z256_t,
    pub pre_comp: [SM2_SIGN_PRE_COMP; SM2_SIGN_PRE_COMP_COUNT],
    pub num_pre_comp: c_uint,
    pub public_point_table: [SM2_Z256_POINT; 16],
}

#[repr(C)]
pub struct SM2_VERIFY_CTX {
    pub sm3_ctx: SM3_CTX,
    pub saved_sm3_ctx: SM3_CTX,
    pub key: SM2_KEY,
    pub public_point_table: [SM2_Z256_POINT; 16],
}

#[repr(C)]
pub struct SM2_ENC_PRE_COMP {
    pub k: sm2_z256_t,
    pub C1: SM2_POINT,
}

pub const SM2_ENC_PRE_COMP_NUM: usize = 8;

#[repr(C)]
pub struct SM2_ENC_CTX {
    pub pre_comp: [SM2_ENC_PRE_COMP; SM2_ENC_PRE_COMP_NUM],
    pub pre_comp_num: size_t,
    pub buf: [u8; SM2_MAX_PLAINTEXT_SIZE],
    pub buf_size: size_t,
}

#[repr(C)]
pub struct SM2_DEC_CTX {
    pub buf: [u8; SM2_MAX_CIPHERTEXT_SIZE],
    pub buf_size: size_t,
}

extern "C" {
    // Key generation
    pub fn sm2_key_generate(key: *mut SM2_KEY) -> c_int;

    // Key import/export (raw)
    pub fn sm2_public_key_to_der(key: *const SM2_KEY, out: *mut *mut u8, outlen: *mut size_t) -> c_int;
    pub fn sm2_public_key_from_der(key: *mut SM2_KEY, in_: *mut *const u8, inlen: *mut size_t) -> c_int;
    pub fn sm2_private_key_to_der(key: *const SM2_KEY, out: *mut *mut u8, outlen: *mut size_t) -> c_int;
    pub fn sm2_private_key_from_der(key: *mut SM2_KEY, in_: *mut *const u8, inlen: *mut size_t) -> c_int;

    // SubjectPublicKeyInfo DER
    pub fn sm2_public_key_info_to_der(key: *const SM2_KEY, out: *mut *mut u8, outlen: *mut size_t) -> c_int;
    pub fn sm2_public_key_info_from_der(key: *mut SM2_KEY, in_: *mut *const u8, inlen: *mut size_t) -> c_int;

    // SubjectPublicKeyInfo PEM
    pub fn sm2_public_key_info_to_pem(key: *const SM2_KEY, fp: *mut FILE) -> c_int;
    pub fn sm2_public_key_info_from_pem(key: *mut SM2_KEY, fp: *mut FILE) -> c_int;

    // PKCS#8 PrivateKeyInfo DER
    pub fn sm2_private_key_info_to_der(key: *const SM2_KEY, out: *mut *mut u8, outlen: *mut size_t) -> c_int;
    pub fn sm2_private_key_info_from_der(
        key: *mut SM2_KEY,
        attrs: *mut *const u8,
        attrslen: *mut size_t,
        in_: *mut *const u8,
        inlen: *mut size_t,
    ) -> c_int;

    // PKCS#8 PrivateKeyInfo PEM
    pub fn sm2_private_key_info_to_pem(key: *const SM2_KEY, fp: *mut FILE) -> c_int;
    pub fn sm2_private_key_info_from_pem(key: *mut SM2_KEY, fp: *mut FILE) -> c_int;

    // Encrypted PKCS#8 DER
    pub fn sm2_private_key_info_encrypt_to_der(
        key: *const SM2_KEY,
        pass: *const c_char,
        out: *mut *mut u8,
        outlen: *mut size_t,
    ) -> c_int;
    pub fn sm2_private_key_info_decrypt_from_der(
        key: *mut SM2_KEY,
        attrs: *mut *const u8,
        attrs_len: *mut size_t,
        pass: *const c_char,
        in_: *mut *const u8,
        inlen: *mut size_t,
    ) -> c_int;

    // Encrypted PKCS#8 PEM
    pub fn sm2_private_key_info_encrypt_to_pem(
        key: *const SM2_KEY,
        pass: *const c_char,
        fp: *mut FILE,
    ) -> c_int;
    pub fn sm2_private_key_info_decrypt_from_pem(
        key: *mut SM2_KEY,
        pass: *const c_char,
        fp: *mut FILE,
    ) -> c_int;

    // Compute Z value
    pub fn sm2_compute_z(
        z: *mut u8,
        pub_: *const SM2_Z256_POINT,
        id: *const c_char,
        idlen: size_t,
    ) -> c_int;

    // Sign/verify (one-shot with pre-computed digest)
    pub fn sm2_sign(key: *const SM2_KEY, dgst: *const u8, sig: *mut u8, siglen: *mut size_t) -> c_int;
    pub fn sm2_verify(key: *const SM2_KEY, dgst: *const u8, sig: *const u8, siglen: size_t) -> c_int;

    // Streaming sign/verify
    pub fn sm2_sign_init(
        ctx: *mut SM2_SIGN_CTX,
        key: *const SM2_KEY,
        id: *const c_char,
        idlen: size_t,
    ) -> c_int;
    pub fn sm2_sign_update(ctx: *mut SM2_SIGN_CTX, data: *const u8, datalen: size_t) -> c_int;
    pub fn sm2_sign_finish(ctx: *mut SM2_SIGN_CTX, sig: *mut u8, siglen: *mut size_t) -> c_int;

    pub fn sm2_verify_init(
        ctx: *mut SM2_VERIFY_CTX,
        key: *const SM2_KEY,
        id: *const c_char,
        idlen: size_t,
    ) -> c_int;
    pub fn sm2_verify_update(ctx: *mut SM2_VERIFY_CTX, data: *const u8, datalen: size_t) -> c_int;
    pub fn sm2_verify_finish(ctx: *mut SM2_VERIFY_CTX, sig: *const u8, siglen: size_t) -> c_int;

    // Encrypt/decrypt (one-shot)
    pub fn sm2_encrypt(
        key: *const SM2_KEY,
        in_: *const u8,
        inlen: size_t,
        out: *mut u8,
        outlen: *mut size_t,
    ) -> c_int;
    pub fn sm2_decrypt(
        key: *const SM2_KEY,
        in_: *const u8,
        inlen: size_t,
        out: *mut u8,
        outlen: *mut size_t,
    ) -> c_int;

    // KDF
    pub fn sm2_kdf(in_: *const u8, inlen: size_t, outlen: size_t, out: *mut u8) -> c_int;

    // ECDH
    pub fn sm2_do_ecdh(
        key: *const SM2_KEY,
        peer_key: *const SM2_KEY,
        out: *mut u8,
    ) -> c_int;
    pub fn sm2_ecdh(
        key: *const SM2_KEY,
        uncompressed_point: *const u8,
        out: *mut u8,
    ) -> c_int;
}

// ============================================================================
// SM9 Identity-Based Cryptography
// ============================================================================

pub const SM9_HID_SIGN: u8 = 0x01;
pub const SM9_HID_ENC: u8 = 0x03;
pub const SM9_MAX_ID_SIZE: usize = SM2_MAX_ID_LENGTH;
pub const SM9_MAX_SIGNATURE_SIZE: usize = 104;
pub const SM9_MAX_PLAINTEXT_SIZE: usize = 255;
pub const SM9_MAX_CIPHERTEXT_SIZE: usize = 367;
pub const SM9_SIGNATURE_SIZE: usize = 104;

// sm9_z256_t is different from sm2_z256_t
pub type sm9_z256_t = [u64; 4];

#[repr(C)]
pub struct SM9_Z256_TWIST_POINT {
    pub X: sm9_z256_t,
    pub Y: sm9_z256_t,
    pub Z: sm9_z256_t,
}

// SM9_Z256_POINT is same as SM2_Z256_POINT for SM9
pub type SM9_Z256_POINT = SM2_Z256_POINT;

#[repr(C)]
pub struct SM9_SIGN_MASTER_KEY {
    pub Ppubs: SM9_Z256_TWIST_POINT,
    pub ks: sm9_z256_t,
}

#[repr(C)]
pub struct SM9_SIGN_KEY {
    pub Ppubs: SM9_Z256_TWIST_POINT,
    pub ds: SM9_Z256_POINT,
}

#[repr(C)]
pub struct SM9_SIGNATURE {
    pub h: sm9_z256_t,
    pub S: SM9_Z256_POINT,
}

#[repr(C)]
pub struct SM9_ENC_MASTER_KEY {
    pub Ppube: SM9_Z256_POINT,
    pub ke: sm9_z256_t,
}

#[repr(C)]
pub struct SM9_ENC_KEY {
    pub Ppube: SM9_Z256_POINT,
    pub de: SM9_Z256_TWIST_POINT,
}

#[repr(C)]
pub struct SM9_SIGN_CTX {
    pub sm3_ctx: SM3_CTX,
}

extern "C" {
    // SM9 Sign master key
    pub fn sm9_sign_master_key_generate(master: *mut SM9_SIGN_MASTER_KEY) -> c_int;
    pub fn sm9_sign_master_key_extract_key(
        master: *const SM9_SIGN_MASTER_KEY,
        id: *const c_char,
        idlen: size_t,
        key: *mut SM9_SIGN_KEY,
    ) -> c_int;
    pub fn sm9_sign_master_key_info_encrypt_to_der(
        msk: *const SM9_SIGN_MASTER_KEY,
        pass: *const c_char,
        out: *mut *mut u8,
        outlen: *mut size_t,
    ) -> c_int;
    pub fn sm9_sign_master_key_info_decrypt_from_der(
        msk: *mut SM9_SIGN_MASTER_KEY,
        pass: *const c_char,
        in_: *mut *const u8,
        inlen: *mut size_t,
    ) -> c_int;
    pub fn sm9_sign_master_key_info_encrypt_to_pem(
        msk: *const SM9_SIGN_MASTER_KEY,
        pass: *const c_char,
        fp: *mut FILE,
    ) -> c_int;
    pub fn sm9_sign_master_key_info_decrypt_from_pem(
        msk: *mut SM9_SIGN_MASTER_KEY,
        pass: *const c_char,
        fp: *mut FILE,
    ) -> c_int;
    pub fn sm9_sign_master_public_key_to_pem(
        mpk: *const SM9_SIGN_MASTER_KEY,
        fp: *mut FILE,
    ) -> c_int;
    pub fn sm9_sign_master_public_key_from_pem(
        mpk: *mut SM9_SIGN_MASTER_KEY,
        fp: *mut FILE,
    ) -> c_int;

    // SM9 Sign user key
    pub fn sm9_sign_key_info_encrypt_to_der(
        key: *const SM9_SIGN_KEY,
        pass: *const c_char,
        out: *mut *mut u8,
        outlen: *mut size_t,
    ) -> c_int;
    pub fn sm9_sign_key_info_decrypt_from_der(
        key: *mut SM9_SIGN_KEY,
        pass: *const c_char,
        in_: *mut *const u8,
        inlen: *mut size_t,
    ) -> c_int;
    pub fn sm9_sign_key_info_encrypt_to_pem(
        key: *const SM9_SIGN_KEY,
        pass: *const c_char,
        fp: *mut FILE,
    ) -> c_int;
    pub fn sm9_sign_key_info_decrypt_from_pem(
        key: *mut SM9_SIGN_KEY,
        pass: *const c_char,
        fp: *mut FILE,
    ) -> c_int;

    // SM9 Sign/Verify
    pub fn sm9_sign_init(ctx: *mut SM9_SIGN_CTX) -> c_int;
    pub fn sm9_sign_update(ctx: *mut SM9_SIGN_CTX, data: *const u8, datalen: size_t) -> c_int;
    pub fn sm9_sign_finish(
        ctx: *mut SM9_SIGN_CTX,
        key: *const SM9_SIGN_KEY,
        sig: *mut u8,
        siglen: *mut size_t,
    ) -> c_int;
    pub fn sm9_verify_init(ctx: *mut SM9_SIGN_CTX) -> c_int;
    pub fn sm9_verify_update(ctx: *mut SM9_SIGN_CTX, data: *const u8, datalen: size_t) -> c_int;
    pub fn sm9_verify_finish(
        ctx: *mut SM9_SIGN_CTX,
        sig: *const u8,
        siglen: size_t,
        mpk: *const SM9_SIGN_MASTER_KEY,
        id: *const c_char,
        idlen: size_t,
    ) -> c_int;

    // SM9 Enc master key
    pub fn sm9_enc_master_key_generate(master: *mut SM9_ENC_MASTER_KEY) -> c_int;
    pub fn sm9_enc_master_key_extract_key(
        master: *const SM9_ENC_MASTER_KEY,
        id: *const c_char,
        idlen: size_t,
        key: *mut SM9_ENC_KEY,
    ) -> c_int;
    pub fn sm9_enc_master_key_info_encrypt_to_der(
        msk: *const SM9_ENC_MASTER_KEY,
        pass: *const c_char,
        out: *mut *mut u8,
        outlen: *mut size_t,
    ) -> c_int;
    pub fn sm9_enc_master_key_info_decrypt_from_der(
        msk: *mut SM9_ENC_MASTER_KEY,
        pass: *const c_char,
        in_: *mut *const u8,
        inlen: *mut size_t,
    ) -> c_int;
    pub fn sm9_enc_master_key_info_encrypt_to_pem(
        msk: *const SM9_ENC_MASTER_KEY,
        pass: *const c_char,
        fp: *mut FILE,
    ) -> c_int;
    pub fn sm9_enc_master_key_info_decrypt_from_pem(
        msk: *mut SM9_ENC_MASTER_KEY,
        pass: *const c_char,
        fp: *mut FILE,
    ) -> c_int;
    pub fn sm9_enc_master_public_key_to_pem(
        mpk: *const SM9_ENC_MASTER_KEY,
        fp: *mut FILE,
    ) -> c_int;
    pub fn sm9_enc_master_public_key_from_pem(
        mpk: *mut SM9_ENC_MASTER_KEY,
        fp: *mut FILE,
    ) -> c_int;

    // SM9 Enc user key
    pub fn sm9_enc_key_info_encrypt_to_der(
        key: *const SM9_ENC_KEY,
        pass: *const c_char,
        out: *mut *mut u8,
        outlen: *mut size_t,
    ) -> c_int;
    pub fn sm9_enc_key_info_decrypt_from_der(
        key: *mut SM9_ENC_KEY,
        pass: *const c_char,
        in_: *mut *const u8,
        inlen: *mut size_t,
    ) -> c_int;
    pub fn sm9_enc_key_info_encrypt_to_pem(
        key: *const SM9_ENC_KEY,
        pass: *const c_char,
        fp: *mut FILE,
    ) -> c_int;
    pub fn sm9_enc_key_info_decrypt_from_pem(
        key: *mut SM9_ENC_KEY,
        pass: *const c_char,
        fp: *mut FILE,
    ) -> c_int;

    // SM9 Encrypt/Decrypt
    pub fn sm9_encrypt(
        mpk: *const SM9_ENC_MASTER_KEY,
        id: *const c_char,
        idlen: size_t,
        in_: *const u8,
        inlen: size_t,
        out: *mut u8,
        outlen: *mut size_t,
    ) -> c_int;
    pub fn sm9_decrypt(
        key: *const SM9_ENC_KEY,
        id: *const c_char,
        idlen: size_t,
        in_: *const u8,
        inlen: size_t,
        out: *mut u8,
        outlen: *mut size_t,
    ) -> c_int;
}

// ============================================================================
// X.509 Certificates
// ============================================================================

// X509_KEY is a union type with cleanup needed
#[repr(C)]
pub struct X509_KEY {
    data: [u8; 8192], // oversize opaque; exact size from header is large due to unions
}

extern "C" {
    pub fn x509_key_set_sm2_key(x509_key: *mut X509_KEY, sm2_key: *const SM2_KEY) -> c_int;
    pub fn x509_key_generate(key: *mut X509_KEY, algor: c_int, param: *const c_void, paramlen: size_t) -> c_int;
    pub fn x509_key_cleanup(key: *mut X509_KEY);
    pub fn x509_public_key_info_to_der(key: *const X509_KEY, out: *mut *mut u8, outlen: *mut size_t) -> c_int;
    pub fn x509_public_key_info_from_der(key: *mut X509_KEY, in_: *mut *const u8, inlen: *mut size_t) -> c_int;
    pub fn x509_public_key_info_to_pem(key: *const X509_KEY, fp: *mut FILE) -> c_int;
    pub fn x509_public_key_info_from_pem(key: *mut X509_KEY, fp: *mut FILE) -> c_int;
}

// X.509 Certificate operations (cert is raw DER bytes)
extern "C" {
    // Certificate to/from DER
    pub fn x509_cert_to_der(a: *const u8, alen: size_t, out: *mut *mut u8, outlen: *mut size_t) -> c_int;
    pub fn x509_cert_from_der(
        a: *mut *const u8,
        alen: *mut size_t,
        in_: *mut *const u8,
        inlen: *mut size_t,
    ) -> c_int;

    // Certificate to/from PEM
    pub fn x509_cert_to_pem(a: *const u8, alen: size_t, fp: *mut FILE) -> c_int;
    pub fn x509_cert_from_pem(
        a: *mut u8,
        alen: *mut size_t,
        maxlen: size_t,
        fp: *mut FILE,
    ) -> c_int;

    // Certificate details
    pub fn x509_cert_get_details(
        a: *const u8,
        alen: size_t,
        version: *mut c_int,
        serial: *mut *const u8,
        serial_len: *mut size_t,
        issuer: *mut *const u8,
        issuer_len: *mut size_t,
        not_before: *mut time_t,
        not_after: *mut time_t,
        subject: *mut *const u8,
        subject_len: *mut size_t,
        public_key: *mut X509_KEY,
        signature_algor: *mut c_int,
        signature: *mut *const u8,
        signature_len: *mut size_t,
    ) -> c_int;

    // Get individual certificate fields
    pub fn x509_cert_get_subject(
        a: *const u8,
        alen: size_t,
        subj: *mut *const u8,
        subj_len: *mut size_t,
    ) -> c_int;
    pub fn x509_cert_get_issuer(
        a: *const u8,
        alen: size_t,
        name: *mut *const u8,
        namelen: *mut size_t,
    ) -> c_int;
    pub fn x509_cert_get_subject_public_key(
        a: *const u8,
        alen: size_t,
        public_key: *mut X509_KEY,
    ) -> c_int;
    pub fn x509_cert_get_signature_algor(
        a: *const u8,
        alen: size_t,
        oid: *mut c_int,
    ) -> c_int;

    // Verify cert by CA cert
    pub fn x509_cert_verify_by_ca_cert(
        a: *const u8,
        alen: size_t,
        cacert: *const u8,
        cacertlen: size_t,
        signer_id: *const c_char,
        signer_id_len: size_t,
    ) -> c_int;

    // Certificate chain operations
    pub fn x509_certs_to_pem(d: *const u8, dlen: size_t, fp: *mut FILE) -> c_int;
    pub fn x509_certs_from_pem(
        d: *mut u8,
        dlen: *mut size_t,
        maxlen: size_t,
        fp: *mut FILE,
    ) -> c_int;
    pub fn x509_certs_get_count(d: *const u8, dlen: size_t, cnt: *mut size_t) -> c_int;
    pub fn x509_certs_get_cert_by_index(
        d: *const u8,
        dlen: size_t,
        index: c_int,
        cert: *mut *const u8,
        certlen: *mut size_t,
    ) -> c_int;
    pub fn x509_certs_get_last(
        d: *const u8,
        dlen: size_t,
        cert: *mut *const u8,
        certlen: *mut size_t,
    ) -> c_int;
    pub fn x509_certs_verify(
        certs: *const u8,
        certslen: size_t,
        certs_type: c_int,
        cacerts: *const u8,
        cacertslen: size_t,
        depth: size_t,
    ) -> c_int;

    // CSR (Certificate Signing Request)
    pub fn x509_req_sign_to_der(
        version: c_int,
        subject: *const u8,
        subject_len: size_t,
        subject_public_key: *const X509_KEY,
        attrs: *const u8,
        attrs_len: size_t,
        signature_algor: c_int,
        sign_key: *mut X509_KEY,
        signer_id: *const c_char,
        signer_id_len: size_t,
        out: *mut *mut u8,
        outlen: *mut size_t,
    ) -> c_int;
    pub fn x509_req_verify(
        req: *const u8,
        reqlen: size_t,
        signer_id: *const c_char,
        signer_id_len: size_t,
    ) -> c_int;
    pub fn x509_req_get_details(
        req: *const u8,
        reqlen: size_t,
        version: *mut c_int,
        subject: *mut *const u8,
        subject_len: *mut size_t,
        subject_public_key: *mut X509_KEY,
        attributes: *mut *const u8,
        attributes_len: *mut size_t,
        signature_algor: *mut c_int,
        signature: *mut *const u8,
        signature_len: *mut size_t,
    ) -> c_int;
    pub fn x509_req_to_pem(req: *const u8, reqlen: size_t, fp: *mut FILE) -> c_int;
    pub fn x509_req_from_pem(
        req: *mut u8,
        reqlen: *mut size_t,
        maxlen: size_t,
        fp: *mut FILE,
    ) -> c_int;
    pub fn x509_req_to_der(a: *const u8, alen: size_t, out: *mut *mut u8, outlen: *mut size_t) -> c_int;
    pub fn x509_req_from_der(
        a: *mut *const u8,
        alen: *mut size_t,
        in_: *mut *const u8,
        inlen: *mut size_t,
    ) -> c_int;
}

// ============================================================================
// ZUC Stream Cipher
// ============================================================================

pub const ZUC_KEY_SIZE: usize = 16;
pub const ZUC_IV_SIZE: usize = 16;
pub const ZUC_MAC_SIZE: usize = 4;

pub const ZUC256_KEY_SIZE: usize = 32;
pub const ZUC256_IV_SIZE: usize = 23;
pub const ZUC256_MAC32_SIZE: usize = 4;
pub const ZUC256_MAC64_SIZE: usize = 8;
pub const ZUC256_MAC128_SIZE: usize = 16;

#[repr(C)]
#[derive(Debug)]
pub struct ZUC_STATE {
    pub LFSR: [u32; 16],
    pub R1: u32,
    pub R2: u32,
}

#[repr(C)]
#[derive(Debug)]
pub struct ZUC_MAC_CTX {
    pub LFSR: [u32; 16],
    pub R1: u32,
    pub R2: u32,
    pub T: u32,
    pub K0: u32,
    pub buf: [u8; 4],
    pub buflen: size_t,
}

#[repr(C)]
#[derive(Debug)]
pub struct ZUC256_MAC_CTX {
    pub LFSR: [u32; 16],
    pub R1: u32,
    pub R2: u32,
    pub T: [u32; 4],
    pub K0: [u32; 4],
    pub buf: [u8; 4],
    pub buflen: size_t,
    pub macbits: c_int,
}

#[repr(C)]
#[derive(Debug)]
pub struct ZUC_CTX {
    pub zuc_state: ZUC_STATE,
    pub block: [u8; 4],
    pub block_nbytes: size_t,
}

extern "C" {
    // ZUC stream cipher
    pub fn zuc_init(state: *mut ZUC_STATE, key: *const u8, iv: *const u8);
    pub fn zuc_generate_keystream(state: *mut ZUC_STATE, nwords: size_t, words: *mut u32);
    pub fn zuc_encrypt(state: *mut ZUC_STATE, in_: *const u8, inlen: size_t, out: *mut u8);

    // ZUC MAC
    pub fn zuc_mac_init(ctx: *mut ZUC_MAC_CTX, key: *const u8, iv: *const u8);
    pub fn zuc_mac_update(ctx: *mut ZUC_MAC_CTX, data: *const u8, len: size_t);
    pub fn zuc_mac_finish(
        ctx: *mut ZUC_MAC_CTX,
        data: *const u8,
        nbits: size_t,
        mac: *mut u8,
    );

    // ZUC-256
    pub fn zuc256_init(state: *mut ZUC_STATE, key: *const u8, iv: *const u8);
    pub fn zuc256_generate_keystream(state: *mut ZUC_STATE, nwords: size_t, words: *mut u32);
    pub fn zuc256_mac_init(
        ctx: *mut ZUC256_MAC_CTX,
        key: *const u8,
        iv: *const u8,
        macbits: c_int,
    );
    pub fn zuc256_mac_update(ctx: *mut ZUC256_MAC_CTX, data: *const u8, len: size_t);
    pub fn zuc256_mac_finish(
        ctx: *mut ZUC256_MAC_CTX,
        data: *const u8,
        nbits: size_t,
        mac: *mut u8,
    );

    // ZUC streaming
    pub fn zuc_encrypt_init(ctx: *mut ZUC_CTX, key: *const u8, iv: *const u8) -> c_int;
    pub fn zuc_encrypt_update(
        ctx: *mut ZUC_CTX,
        in_: *const u8,
        inlen: size_t,
        out: *mut u8,
        outlen: *mut size_t,
    ) -> c_int;
    pub fn zuc_encrypt_finish(ctx: *mut ZUC_CTX, out: *mut u8, outlen: *mut size_t) -> c_int;
}
