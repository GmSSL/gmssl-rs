use std::env;
use std::path::PathBuf;

fn main() {
    // ========================================================================
    // 1. docs.rs special case — no libgmssl or cmake in sandbox, just emit
    //    link directives so `cargo doc` can generate documentation.
    // ========================================================================
    if env::var("DOCS_RS").is_ok() {
        println!("cargo:rustc-link-lib=gmssl");
        println!("cargo:rerun-if-env-changed=DOCS_RS");
        println!("cargo:rerun-if-changed=build.rs");
        return;
    }

    // ========================================================================
    // 2. Pre-installed GmSSL via environment variable (backward compatible)
    // ========================================================================
    if let Ok(dir) = env::var("GMSSL_DIR") {
        let lib_dir = PathBuf::from(&dir).join("lib");
        assert!(
            lib_dir.exists(),
            "GMSSL_DIR={} but {}/ not found. \
             Unset GMSSL_DIR to build GmSSL from the bundled submodule instead.",
            dir,
            lib_dir.display()
        );
        println!("cargo:rustc-link-search=native={}", lib_dir.display());
        println!("cargo:rustc-link-lib=gmssl");
        println!("cargo:rerun-if-env-changed=GMSSL_DIR");
        println!("cargo:rerun-if-changed=build.rs");
        return;
    }

    // ========================================================================
    // 3. Build GmSSL from the bundled git submodule via CMake
    // ========================================================================
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let submodule_dir = manifest_dir.join("GmSSL");

    // If the submodule directory exists but CMakeLists.txt is missing, the
    // user likely cloned without --recursive. Try to auto-initialize.
    if submodule_dir.exists() && !submodule_dir.join("CMakeLists.txt").exists() {
        let workspace_root = manifest_dir
            .parent()
            .expect("gmssl-sys must live inside a workspace");
        let status = std::process::Command::new("git")
            .args(["submodule", "update", "--init", "--depth", "1"])
            .current_dir(workspace_root)
            .status()
            .expect("failed to run 'git submodule update --init'. Is git installed?");
        assert!(
            status.success(),
            "Failed to initialize GmSSL submodule at {}. \
             Run `git submodule update --init` manually, \
             or set GMSSL_DIR=/path/to/gmssl to use a pre-installed copy.",
            submodule_dir.display()
        );
    }

    // If the submodule is still missing, give a clear error.
    assert!(
        submodule_dir.join("CMakeLists.txt").exists(),
        "GmSSL source not found at {}. \
         Run `git submodule update --init` to fetch the C library, \
         or set GMSSL_DIR=/path/to/gmssl to use a pre-installed copy.",
        submodule_dir.display()
    );

    // Tell Cargo to re-run this script when GmSSL source files change.
    println!(
        "cargo:rerun-if-changed={}",
        submodule_dir.join("CMakeLists.txt").display()
    );
    for watch_dir in &["src", "include"] {
        let path = submodule_dir.join(watch_dir);
        if path.exists() {
            println!("cargo:rerun-if-changed={}", path.display());
        }
    }

    // --- Configure CMake ---
    let mut cmake_cfg = cmake::Config::new(&submodule_dir);

    // Build a static library so the final Rust binary has no runtime dep on
    // libgmssl.dylib / libgmssl.so.
    cmake_cfg.define("BUILD_SHARED_LIBS", "OFF");

    // Propagate the C compiler so cross-compilation toolchains work.
    if let Ok(cc) = env::var("CC") {
        if !cc.is_empty() {
            cmake_cfg.define("CMAKE_C_COMPILER", &cc);
        }
    }

    // Disable optional GmSSL features that the Rust FFI bindings do not use.
    // This keeps build times short.  Each can be re-enabled at build time via
    // the corresponding GMSSL_ENABLE_<FEATURE>=ON environment variable.
    //
    // Core SM2 / SM3 / SM4 / SM9 / ZUC / X.509 are always compiled — they are
    // not behind feature flags in GmSSL's CMakeLists.txt.
    // Features needed by the Rust bindings — always ON by default.
    cmake_cfg.define("ENABLE_SM2_PRIVATE_KEY_EXPORT", "ON");

    // Optional GmSSL features not used by the Rust FFI bindings.
    // Each can be re-enabled via the GMSSL_ENABLE_<FEATURE>=ON env var.
    let optional_features = &[
        "ENABLE_SHA1",
        "ENABLE_SHA2",
        "ENABLE_AES",
        "ENABLE_CHACHA20",
        "ENABLE_SM4_ECB",
        "ENABLE_SM4_OFB",
        "ENABLE_SM4_CFB",
        "ENABLE_SM4_CCM",
        "ENABLE_SM4_XTS",
        "ENABLE_SM4_CBC_MAC",
        "ENABLE_SECP256R1",
        "ENABLE_LMS",
        "ENABLE_XMSS",
        "ENABLE_SPHINCS",
        "ENABLE_KYBER",
        "ENABLE_TLS_DEBUG",
        "ENABLE_SDF",
        "ENABLE_SKF",
    ];

    for feature in optional_features {
        let env_var = format!("GMSSL_{}", feature);
        let value = env::var(&env_var).unwrap_or_else(|_| "OFF".to_string());
        if value == "ON" || value == "on" || value == "1" {
            cmake_cfg.define(feature, "ON");
        } else {
            cmake_cfg.define(feature, "OFF");
        }
    }

    // Let the user pass arbitrary extra CMake -D flags.
    if let Ok(extra) = env::var("GMSSL_CMAKE_DEFINES") {
        for def in extra.split_whitespace() {
            if let Some(eq) = def.find('=') {
                cmake_cfg.define(&def[..eq], &def[eq + 1..]);
            }
        }
    }

    // --- Build ---
    let dst = cmake_cfg.build();

    // --- Emit link directives ---
    let lib_dir = dst.join("lib");
    assert!(
        lib_dir.exists(),
        "CMake build completed but no lib/ directory found at {}. \
         Check the GmSSL CMake output above for errors.",
        lib_dir.display()
    );

    println!("cargo:rustc-link-search=native={}", lib_dir.display());
    println!("cargo:rustc-link-lib=static=gmssl");

    // Export the include path for potential bindgen usage.
    let include_dir = dst.join("include");
    if include_dir.exists() {
        println!("cargo:include={}", include_dir.display());
    }

    // macOS: Security.framework is needed by GmSSL's rand_apple.c
    if env::var("CARGO_CFG_TARGET_OS").unwrap_or_default() == "macos" {
        println!("cargo:rustc-link-lib=framework=Security");
    }

    // Windows: link against system crypto libs that GmSSL uses
    if env::var("CARGO_CFG_TARGET_OS").unwrap_or_default() == "windows" {
        println!("cargo:rustc-link-lib=bcrypt");
        println!("cargo:rustc-link-lib=ncrypt");
    }

    println!("cargo:rerun-if-env-changed=GMSSL_DIR");
    println!("cargo:rerun-if-env-changed=GMSSL_CMAKE_DEFINES");
    println!("cargo:rerun-if-changed=build.rs");
}
