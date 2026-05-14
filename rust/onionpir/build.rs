// Build script for the `onionpir` Rust crate.
//
// Runs the repo-root CMake project with `-DONIONPIR_BUILD_FFI=ON` to produce
// `libonionpir.a`, then links it (plus the C++ runtime) into the crate. The
// FFI surface itself is declared in `src/lib.rs`.
//
// Re-runs when the C ABI header or any C++ source changes.

use std::env;
use std::path::PathBuf;

fn main() {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    // rust/onionpir/ → repo root
    let repo_root = manifest_dir.parent().unwrap().parent().unwrap();

    // Upstream gates the debug/benchmark print macros (DEBUG_PRINT,
    // PRINT_INT_ARRAY) on _BENCHMARK or _DEBUG. Plain Release leaves them
    // undefined → compile errors. Build type "Benchmark" defines _BENCHMARK
    // and uses the same -O3 -march=native flags.
    let dst = cmake::Config::new(repo_root)
        .define("ONIONPIR_BUILD_FFI", "ON")
        .define("CMAKE_BUILD_TYPE", "Benchmark")
        .profile("Benchmark")  // tell cmake-rs not to override CMAKE_BUILD_TYPE
        .build_target("onionpir")
        .build();

    // cmake-rs puts artifacts under <dst>/build by default.
    let lib_dir = dst.join("build");
    println!("cargo:rustc-link-search=native={}", lib_dir.display());
    println!("cargo:rustc-link-lib=static=onionpir");

    // C++ runtime: libc++ on Apple (clang default), libstdc++ on Linux GCC.
    let target = env::var("TARGET").unwrap_or_default();
    if target.contains("apple") {
        println!("cargo:rustc-link-lib=dylib=c++");
    } else {
        println!("cargo:rustc-link-lib=dylib=stdc++");
    }

    // Re-run triggers.
    let watch = [
        repo_root.join("src/includes/onion_ffi.h"),
        repo_root.join("src/onion_ffi.cpp"),
        repo_root.join("CMakeLists.txt"),
    ];
    for p in &watch {
        println!("cargo:rerun-if-changed={}", p.display());
    }
    // Also rerun if anything under src/ changes — broader than ideal but
    // catches edits to the engine that affect the FFI's behavior.
    println!("cargo:rerun-if-changed={}", repo_root.join("src").display());
}
