# gmssl-rs

[![Crates.io](https://img.shields.io/crates/v/gmssl-rs.svg)](https://crates.io/crates/gmssl-rs)
[![Documentation](https://docs.rs/gmssl-rs/badge.svg)](https://docs.rs/gmssl-rs)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)

安全、符合 Rust 语言习惯的 [GmSSL](https://github.com/guanzhi/GmSSL) 密码库封装，支持中国国家密码标准（SM2/SM3/SM4/SM9/ZUC）及 X.509 证书管理。

## 密码算法

| 算法 | 标准 | 功能 | 状态 |
|------|------|------|------|
| **SM3** | GM/T 0004-2012 | 哈希、HMAC、PBKDF2 | ✅ 稳定 |
| **SM4** | GM/T 0002-2012 | 分组密码、CBC/CTR/GCM 模式 | ✅ 稳定 |
| **SM2** | GM/T 0003-2012 | 数字签名、公钥加密、密钥交换、PEM/DER 导入导出 | ✅ 稳定 |
| **ZUC** | GM/T 0001-2016 | 流密码、MAC、ZUC-256 | ✅ 稳定 |
| **X.509** | RFC 5280 | 证书解析、链验证、CSR、CRL | ✅ 稳定 |
| **SM9** | GM/T 0044-2016 | 基于身份的签名（IBS）和加密（IBE） | ⚠️ 实验性 |

## 安装要求

- Rust 1.70+
- [CMake](https://cmake.org) 3.10+
- C 编译器（gcc、clang 或 MSVC）
- Git

### 快速开始

GmSSL C 库以 **Git 子模块** 的形式包含在本项目中，`cargo build` 会自动通过 CMake 编译 GmSSL，无需手动安装。

```bash
# 克隆时初始化子模块（推荐）
git clone --recursive https://github.com/guanzhi/gmssl-rs.git
cd gmssl-rs

# 如果已克隆但未初始化子模块
git submodule update --init

# 构建（自动编译 GmSSL C 库并链接为静态库）
cargo build

# 运行测试
cargo test
```

### 可选：使用系统预装的 GmSSL

如果你已在系统中安装了 GmSSL（例如通过 `brew install gmssl`），可以设置 `GMSSL_DIR` 环境变量跳过子模块编译：

```bash
export GMSSL_DIR=/usr/local     # 或 /opt/homebrew（Apple Silicon Mac）
cargo build
```

## 快速开始

在 `Cargo.toml` 中添加依赖：

```toml
[dependencies]
gmssl-rs = "0.1"
```

### SM3 哈希

```rust
use gmssl_rs::Sm3;

// 一次性哈希
let hash = Sm3::digest(b"hello world");
assert_eq!(hash.len(), 32);

// 流式哈希
let mut sm3 = Sm3::new();
sm3.update(b"hello ");
sm3.update(b"world");
let hash = sm3.finish();

// HMAC-SM3
use gmssl_rs::Sm3Hmac;
let mac = Sm3Hmac::mac(b"key", b"message");
assert_eq!(mac.len(), 32);

// PBKDF2
use gmssl_rs::sm3_pbkdf2;
let mut key = [0u8; 32];
sm3_pbkdf2(b"password", b"salt", 10000, &mut key).unwrap();
```

### SM4 对称加密

```rust
use gmssl_rs::Sm4Gcm;

// SM4-GCM 认证加解密
let key = hex::decode("0123456789abcdeffedcba9876543210").unwrap();
let iv = hex::decode("00001234567800000000abcd").unwrap();
let aad = b"authenticated data";
let plaintext = b"sensitive data";

let result = Sm4Gcm::encrypt(&key, &iv, aad, plaintext, 16).unwrap();
let decrypted = Sm4Gcm::decrypt(&key, &iv, aad, &result.tag, &result.ciphertext).unwrap();
assert_eq!(&decrypted, plaintext);
```

```rust
use gmssl_rs::Sm4Cbc;

// SM4-CBC 带 PKCS#7 填充
let key = [0x01u8; 16];
let iv = [0x02u8; 16];

let ct = Sm4Cbc::encrypt(&key, &iv, b"plaintext").unwrap();
let pt = Sm4Cbc::decrypt(&key, &iv, &ct).unwrap();
assert_eq!(&pt, b"plaintext");
```

### SM2 公钥密码

```rust
use gmssl_rs::{Sm2Key, Sm2Signer, Sm2Verifier};

// 生成密钥对
let key = Sm2Key::generate().unwrap();

// 签名和验签
let data = b"message to sign";
let sig = Sm2Signer::sign(&key, None, data).unwrap();
let valid = Sm2Verifier::verify(&key, None, data, &sig).unwrap();
assert!(valid);

// 公钥加密/解密
let ct = gmssl_rs::sm2_encrypt(&key, b"short message").unwrap();
let pt = gmssl_rs::sm2_decrypt(&key, &ct).unwrap();
assert_eq!(&pt, b"short message");

// ECDH 密钥交换
let alice = Sm2Key::generate().unwrap();
let bob = Sm2Key::generate().unwrap();
let shared1 = gmssl_rs::sm2_ecdh(&alice, &bob).unwrap();
let shared2 = gmssl_rs::sm2_ecdh(&bob, &alice).unwrap();
assert_eq!(shared1, shared2);
```

```rust
// PEM/DER 导入导出
let key = Sm2Key::generate().unwrap();

// 导出
let pub_pem = key.to_public_key_pem().unwrap();
let priv_pem = key.to_private_key_pem().unwrap();

// 加密的私钥
let enc_pem = key.to_encrypted_private_key_pem("password").unwrap();

// 导入
let pub_key = Sm2Key::from_public_key_pem(&pub_pem).unwrap();
let priv_key = Sm2Key::from_encrypted_private_key_pem(&enc_pem, "password").unwrap();
```

### SM9 基于身份的密码

```rust
use gmssl_rs::Sm9SignMasterKey;

// 生成签名主密钥（由 KGC 持有）
let master = Sm9SignMasterKey::generate().unwrap();

// 为用户提取签名私钥
let user_key = master.extract_key("alice@example.com").unwrap();
assert_eq!(user_key.id(), "alice@example.com");

// 签名
let sig = gmssl_rs::sm9_sign(&user_key, b"message").unwrap();
```

```rust
use gmssl_rs::Sm9EncMasterKey;

// SM9 基于身份的加密
let master = Sm9EncMasterKey::generate().unwrap();
let user_key = master.extract_key("bob@example.com").unwrap();

// 加密（发送方使用主公钥和接收方身份）
let ct = gmssl_rs::sm9_encrypt(&master, "bob@example.com", b"secret").unwrap();

// 解密（接收方使用自己的私钥）
let pt = gmssl_rs::sm9_decrypt(&user_key, "bob@example.com", &ct).unwrap();
```

### ZUC 流密码

```rust
use gmssl_rs::Zuc;

// 流加密/解密
let key = [0x01u8; 16];
let iv = [0x02u8; 16];

let ct = Zuc::process(&key, &iv, b"plaintext");
let pt = Zuc::process(&key, &iv, &ct);
assert_eq!(&pt, b"plaintext");
```

### 随机数

```rust
use gmssl_rs::rand_bytes;

let mut buf = [0u8; 32];
rand_bytes(&mut buf).unwrap();
```

## 项目结构

```
gmssl-rs/
├── Cargo.toml              # 工作空间配置
├── .gitmodules             # Git 子模块配置（声明对 GmSSL C 库的依赖）
├── gmssl-sys/               # 底层 FFI 绑定（gmssl-rs-sys）
│   ├── Cargo.toml          # build-dependencies: cmake
│   ├── build.rs            # CMake 自动构建 libgmssl.a
│   ├── GmSSL/              # Git 子模块：GmSSL C 源码（v3.1.1）
│   └── src/lib.rs          # extern "C" 声明与 repr(C) 类型
└── gmssl/                   # 安全 Rust 封装（gmssl-rs）
    └── src/
        ├── error.rs         # 错误类型
        ├── pem_helpers.rs   # PEM/DER 辅助函数
        ├── rand.rs          # 安全随机数
        ├── sm3/mod.rs       # SM3 哈希
        ├── sm4/mod.rs       # SM4 分组密码
        ├── sm2/mod.rs       # SM2 公钥密码
        ├── sm9/mod.rs       # SM9 基于身份的密码
        ├── x509/mod.rs      # X.509 证书
        └── zuc/mod.rs       # ZUC 流密码
```

## 设计

### 双 crate 架构

- **`gmssl-rs-sys`**：底层 FFI 绑定，手写 `extern "C"` 声明，精确匹配 C 头文件结构
- **`gmssl-rs`**：安全、符合 Rust 语言习惯的封装

### API 风格

参考 [GmSSL-Java](https://github.com/GmSSL/GmSSL-Java) 和 [GmSSL-Go](https://github.com/GmSSL/GmSSL-Go) 的设计，采用 Rust 语言习惯：

- **RAII**：通过 `Drop` trait 自动释放 C 资源
- **`Result<T, GmsslError>`**：所有可失败操作返回 `Result`
- **流式接口**：`new()` → `update()` → `finish()` 模式
- **一次性便捷函数**：常用操作的简化封装
- **内存 PEM 操作**：使用 `fmemopen`/`open_memstream`，无需临时文件

## 运行测试

```bash
cargo test
```

46 个测试全部通过（13 个 SM9 测试因 GmSSL v3.1.1 内部 bug 暂时跳过）。

## 许可证

本项目遵循与 GmSSL 相同的 [Apache 2.0](LICENSE) 许可证。

Copyright 2024-2026 The GmSSL Project. All Rights Reserved.

## 相关项目

- [GmSSL](https://github.com/guanzhi/GmSSL) — C 语言密码库
- [GmSSL-Java](https://github.com/GmSSL/GmSSL-Java) — Java 封装
- [GmSSL-Go](https://github.com/GmSSL/GmSSL-Go) — Go 语言封装
