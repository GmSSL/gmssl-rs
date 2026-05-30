use std::env;
use std::path::PathBuf;

fn find_library_dir() -> Option<PathBuf> {
    // Check GMSSL_DIR environment variable
    if let Ok(dir) = env::var("GMSSL_DIR") {
        let lib_dir = PathBuf::from(&dir).join("lib");
        if lib_dir.exists() {
            return Some(lib_dir);
        }
    }

    // Common installation paths
    let candidates = &[
        "/usr/local/lib",
        "/opt/homebrew/lib",
        "/usr/lib",
        "/usr/lib64",
        "/usr/lib/x86_64-linux-gnu",
    ];

    for path in candidates {
        let p = PathBuf::from(path);
        if p.join("libgmssl.dylib").exists()
            || p.join("libgmssl.so").exists()
            || p.join("libgmssl.a").exists()
        {
            return Some(p);
        }
    }
    None
}

fn main() {
    let lib_dir = find_library_dir().expect(
        "libgmssl not found. Set GMSSL_DIR=/path/to/gmssl or install GmSSL to /usr/local",
    );

    println!("cargo:rustc-link-search=native={}", lib_dir.display());
    println!("cargo:rustc-link-lib=gmssl");
    println!("cargo:rerun-if-env-changed=GMSSL_DIR");
    println!("cargo:rerun-if-changed=build.rs");
}
