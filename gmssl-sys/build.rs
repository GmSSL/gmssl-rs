use std::env;
use std::path::{Path, PathBuf};

/// GmSSL release tag that this version of the bindings was written against.
const GMSSL_RELEASE_TAG: &str = "v3.2.0";
const GMSSL_RELEASE_URL: &str = "https://github.com/guanzhi/GmSSL/archive/refs/tags/v3.2.0.tar.gz";

/// Cargo features and their corresponding GmSSL CMake options.
const OPTIONAL_FEATURES: &[(&str, &str)] = &[
    ("sha1", "ENABLE_SHA1"),
    ("sha2", "ENABLE_SHA2"),
    ("aes", "ENABLE_AES"),
    ("aes-ccm", "ENABLE_AES_CCM"),
    ("chacha20", "ENABLE_CHACHA20"),
    ("sm4-ecb", "ENABLE_SM4_ECB"),
    ("sm4-ofb", "ENABLE_SM4_OFB"),
    ("sm4-cfb", "ENABLE_SM4_CFB"),
    ("sm4-ccm", "ENABLE_SM4_CCM"),
    ("sm4-xts", "ENABLE_SM4_XTS"),
    ("sm4-cbc-mac", "ENABLE_SM4_CBC_MAC"),
    ("secp256r1", "ENABLE_SECP256R1"),
    ("lms", "ENABLE_LMS"),
    ("xmss", "ENABLE_XMSS"),
    ("sphincs", "ENABLE_SPHINCS"),
    ("kyber", "ENABLE_KYBER"),
    ("tls", "ENABLE_TLS"),
    ("tls-debug", "ENABLE_TLS_DEBUG"),
];

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
             Unset GMSSL_DIR to build GmSSL from source instead.",
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
    // 3. Locate or acquire GmSSL source
    // ========================================================================
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let source_dir = locate_gmssl_source(&manifest_dir);

    // Tell Cargo to re-run this script when GmSSL source files change.
    println!(
        "cargo:rerun-if-changed={}",
        source_dir.join("CMakeLists.txt").display()
    );
    for watch_dir in &["src", "include"] {
        let path = source_dir.join(watch_dir);
        if path.exists() {
            println!("cargo:rerun-if-changed={}", path.display());
        }
    }

    // ========================================================================
    // 4. Build GmSSL via CMake
    // ========================================================================
    let mut cmake_cfg = cmake::Config::new(&source_dir);

    // Build a static library so the final Rust binary has no runtime dep on
    // libgmssl.dylib / libgmssl.so.
    cmake_cfg.define("BUILD_SHARED_LIBS", "OFF");

    // Propagate the C compiler so cross-compilation toolchains work.
    if let Ok(cc) = env::var("CC") {
        if !cc.is_empty() {
            cmake_cfg.define("CMAKE_C_COMPILER", &cc);
        }
    }

    // Needed by the Rust FFI bindings — always ON.
    cmake_cfg.define("ENABLE_SM2_PRIVATE_KEY_EXPORT", "ON");

    // Disable optional GmSSL features not used by the Rust bindings to keep
    // build times short. Each option can be enabled with either its Cargo
    // feature or the existing GMSSL_ENABLE_<F>=ON environment variable.
    for &(cargo_feature, cmake_option) in OPTIONAL_FEATURES {
        let legacy_env_var = format!("GMSSL_{cmake_option}");
        println!("cargo:rerun-if-env-changed={legacy_env_var}");

        let enabled_by_env = matches!(env::var(&legacy_env_var).as_deref(), Ok("ON" | "on" | "1"));
        let cargo_env_var = format!(
            "CARGO_FEATURE_{}",
            cargo_feature.replace('-', "_").to_ascii_uppercase()
        );
        let enabled_by_cargo = env::var_os(cargo_env_var).is_some();

        cmake_cfg.define(
            cmake_option,
            if enabled_by_env || enabled_by_cargo {
                "ON"
            } else {
                "OFF"
            },
        );
    }

    // Windows MSVC: GmSSL's dylib.h uses #ifdef WIN32 but MSVC only
    // defines _WIN32. Without this define, SDF/SKF source files fail
    // to compile because they try to #include <dlfcn.h> (POSIX-only).
    if env::var("CARGO_CFG_TARGET_OS").unwrap_or_default() == "windows" {
        cmake_cfg.cflag("-DWIN32");
    }

    // Arbitrary extra CMake -D flags.
    if let Ok(extra) = env::var("GMSSL_CMAKE_DEFINES") {
        for def in extra.split_whitespace() {
            if let Some(eq) = def.find('=') {
                cmake_cfg.define(&def[..eq], &def[eq + 1..]);
            }
        }
    }

    // Windows MSVC: GmSSL hardcodes CMAKE_INSTALL_PREFIX to
    // "C:/Program Files/GmSSL" in its CMakeLists.txt, overriding
    // the value that the cmake crate passes on the command line.
    // Patch it out so the library lands in OUT_DIR.
    if env::var("CARGO_CFG_TARGET_OS").unwrap_or_default() == "windows" {
        patch_cmake_install_prefix(&source_dir);
    }

    let dst = cmake_cfg.build();

    // Restore the original CMakeLists.txt that was patched above.
    if env::var("CARGO_CFG_TARGET_OS").unwrap_or_default() == "windows" {
        restore_cmake_lists(&source_dir);
    }

    // ========================================================================
    // 5. Emit link directives
    // ========================================================================
    // MSVC multi-config generators (Visual Studio) place libraries in
    // lib/<Config>/ (e.g. lib/Debug/gmssl.lib). Single-config generators
    // (Makefiles, Ninja) place them directly in lib/.
    let lib_dir = find_lib_dir(&dst);

    println!("cargo:rustc-link-search=native={}", lib_dir.display());
    println!("cargo:rustc-link-lib=static=gmssl");

    let include_dir = dst.join("include");
    if include_dir.exists() {
        println!("cargo:include={}", include_dir.display());
    }

    // macOS: Security.framework needed by rand_apple.c
    if env::var("CARGO_CFG_TARGET_OS").unwrap_or_default() == "macos" {
        println!("cargo:rustc-link-lib=framework=Security");
    }
    // Windows: system crypto libs used by GmSSL
    if env::var("CARGO_CFG_TARGET_OS").unwrap_or_default() == "windows" {
        println!("cargo:rustc-link-lib=advapi32");
        println!("cargo:rustc-link-lib=bcrypt");
        println!("cargo:rustc-link-lib=ncrypt");
    }

    println!("cargo:rerun-if-env-changed=GMSSL_DIR");
    println!("cargo:rerun-if-env-changed=GMSSL_CMAKE_DEFINES");
    println!("cargo:rerun-if-changed=build.rs");
}

/// On Windows MSVC, GmSSL's CMakeLists.txt hardcodes
/// `set(CMAKE_INSTALL_PREFIX "C:/Program Files/GmSSL")` which
/// overrides the value we pass via `-D`.  Patch it temporarily
/// during the build and restore the original after.
fn patch_cmake_install_prefix(source_dir: &Path) {
    let cmake_lists = source_dir.join("CMakeLists.txt");
    let original = std::fs::read_to_string(&cmake_lists).unwrap_or_else(|e| {
        panic!("Failed to read {}: {}", cmake_lists.display(), e);
    });

    let patched = original.replace(
        "set(CMAKE_INSTALL_PREFIX \"C:/Program Files/GmSSL\")",
        "# PATCHED by gmssl-rs build.rs — removed hardcoded install prefix\n# set(CMAKE_INSTALL_PREFIX \"C:/Program Files/GmSSL\")",
    );

    if patched != original {
        eprintln!("Patched GmSSL CMakeLists.txt: removed hardcoded CMAKE_INSTALL_PREFIX");
        // Save original and write patched version
        let backup = source_dir.join("CMakeLists.txt.bak");
        std::fs::write(&backup, &original).unwrap_or_else(|e| {
            panic!("Failed to backup {}: {}", cmake_lists.display(), e);
        });
        std::fs::write(&cmake_lists, &patched).unwrap_or_else(|e| {
            // Try to restore backup on failure
            let _ = std::fs::copy(&backup, &cmake_lists);
            panic!("Failed to write {}: {}", cmake_lists.display(), e);
        });
    }
}

/// Restore the original CMakeLists.txt after a successful build.
fn restore_cmake_lists(source_dir: &Path) {
    let backup = source_dir.join("CMakeLists.txt.bak");
    if backup.exists() {
        let _ = std::fs::copy(&backup, source_dir.join("CMakeLists.txt"));
        let _ = std::fs::remove_file(&backup);
    }
}

/// Find the directory containing the compiled `gmssl` library.
///
/// MSVC multi-config generators place libraries in `lib/<Config>/`
/// (e.g. `lib/Debug/gmssl.lib`), while single-config generators
/// (Makefiles, Ninja) use `lib/` directly.
fn find_lib_dir(prefix: &Path) -> PathBuf {
    // Try the simple layout first (Makefiles, Ninja).
    let lib = prefix.join("lib");
    if lib.join("libgmssl.a").exists()
        || lib.join("libgmssl.so").exists()
        || lib.join("libgmssl.dylib").exists()
        || lib.join("gmssl.lib").exists()
    {
        return lib;
    }
    // MSVC multi-config: check lib/Debug/ and lib/Release/.
    for config in &["Debug", "Release", "MinSizeRel", "RelWithDebInfo"] {
        let cfg_lib = prefix.join("lib").join(config);
        if cfg_lib.join("gmssl.lib").exists() {
            return cfg_lib;
        }
    }
    panic!(
        "GmSSL library not found under {}/lib/. \
         Check the CMake build output above for errors.",
        prefix.display()
    );
}

/// Locate the GmSSL source tree, downloading the pinned release if necessary.
///
/// Priority:
/// 1. `GMSSL_SOURCE_DIR`, for local development with an explicit source tree.
/// 2. Downloaded release tarball in `OUT_DIR`.
fn locate_gmssl_source(_manifest_dir: &Path) -> PathBuf {
    if let Ok(source_dir) = env::var("GMSSL_SOURCE_DIR") {
        let path = PathBuf::from(&source_dir);
        assert!(
            path.join("CMakeLists.txt").exists(),
            "GMSSL_SOURCE_DIR={} is not a GmSSL source tree",
            source_dir
        );
        println!("cargo:rerun-if-env-changed=GMSSL_SOURCE_DIR");
        return path;
    }

    // Always use the release tarball by default. The repository still contains
    // a historical submodule, but it can drift from the release tag that these
    // bindings are generated for.
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let tarball_dir = out_dir.join("gmssl-src");
    let tarball_path = out_dir.join(format!("GmSSL-{}.tar.gz", GMSSL_RELEASE_TAG));
    let extract_dir = out_dir.join(format!("GmSSL-{}", GMSSL_RELEASE_TAG));

    // Download if not already cached.
    if !tarball_path.exists() {
        eprintln!(
            "Downloading GmSSL {} source from GitHub...",
            GMSSL_RELEASE_TAG
        );
        let status = std::process::Command::new("curl")
            .args([
                "-L",
                "-o",
                tarball_path.to_str().unwrap(),
                GMSSL_RELEASE_URL,
            ])
            .status()
            .expect("failed to run curl. Is curl installed?");
        assert!(status.success(), "Failed to download GmSSL source");
    }

    // Extract if not already done.
    if !extract_dir.join("CMakeLists.txt").exists() {
        eprintln!("Extracting GmSSL {} source...", GMSSL_RELEASE_TAG);
        let _ = std::fs::create_dir_all(&tarball_dir);

        // Use `tar xzf` (available on macOS, Linux, and Windows via Git Bash).
        let status = std::process::Command::new("tar")
            .args([
                "xzf",
                tarball_path.to_str().unwrap(),
                "-C",
                tarball_dir.to_str().unwrap(),
            ])
            .status()
            .expect("failed to run tar. Is tar installed?");
        assert!(status.success(), "Failed to extract GmSSL source");
    }

    let extracted = tarball_dir.join(format!("GmSSL-{}", GMSSL_RELEASE_TAG));
    if !extracted.join("CMakeLists.txt").exists() {
        // GitHub tarballs sometimes nest inside `GmSSL-<tag>/`
        // or `GmSSL-<tag>/GmSSL-<tag>/`. Find the real root.
        let found = std::fs::read_dir(&tarball_dir)
            .ok()
            .and_then(|mut entries| {
                entries.find_map(|e| {
                    let p = e.ok()?.path();
                    p.join("CMakeLists.txt").exists().then_some(p)
                })
            });
        if let Some(path) = found {
            return path;
        }
        panic!(
            "GmSSL source not found after extracting {}. \
             Please install GmSSL manually and set GMSSL_DIR.",
            GMSSL_RELEASE_URL
        );
    }

    extracted
}
