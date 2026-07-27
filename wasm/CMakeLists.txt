cmake_minimum_required(VERSION 3.13)

# Phase-3 WASM build. Configure with:
#   emcmake cmake -S . -B build (from the repo's wasm/ directory)
# and build with: cmake --build build
#
# Toolchain notes:
# - HEXL is x86-only, so the WASM build always uses the scalar shim at
#   rust/onionpir/cpp/hexl_compat/. There's no way to flip this off here.
# - We compile a client-only WASM module: upstream's client-side sources +
#   bv_keyswitch + supporting infrastructure, plus our C ABI (onion_ffi.cpp)
#   so the embind layer in bindings.cpp can reuse the same wire format the
#   Rust crate uses.

set(CMAKE_POLICY_VERSION_MINIMUM 3.5)
project(onionpir-wasm CXX)

if (NOT EMSCRIPTEN)
    message(FATAL_ERROR
        "wasm/CMakeLists.txt must be configured under emcmake — "
        "run `emcmake cmake -S . -B build` from the wasm/ directory.")
endif()

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# -O3 for runtime speed; -msimd128 enables WebAssembly SIMD128 — baseline in
# every modern browser (Chrome 91+, Firefox 89+, Safari 16.4+) and Node 16+ —
# so the compiler autovectorizes and the wasm_simd128 eltwise path in
# cpp/hexl_shim.cpp is emitted; -fexceptions for the throw/catch in
# onion_ffi.cpp's error paths (Emscripten disables them by default and aborts
# on throw).
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O3 -msimd128 -fexceptions")

# Define _BENCHMARK so the macros in includes/logging.h and includes/utils.h
# (DEBUG_PRINT, PRINT_INT_ARRAY) resolve to no-ops. Without this they're
# undeclared and the build fails.
add_compile_definitions(_BENCHMARK)

set(REPO_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/..")
# The C++ engine now lives inside the onionpir crate (rust/onionpir/cpp/) so
# `cargo vendor` can ship it as a self-contained crate.
set(CPP_ROOT "${REPO_ROOT}/rust/onionpir/cpp")

# Upstream client-side sources. server.cpp / matrix.cpp are intentionally
# excluded — the WASM module is client-only.
set(ONIONPIR_CLIENT_SRC
    "${CPP_ROOT}/bv_keyswitch.cpp"
    "${CPP_ROOT}/client.cpp"
    "${CPP_ROOT}/gsw.cpp"
    "${CPP_ROOT}/logging.cpp"
    "${CPP_ROOT}/pir.cpp"
    "${CPP_ROOT}/rlwe.cpp"
    "${CPP_ROOT}/utils.cpp"
    "${CPP_ROOT}/hexl_shim.cpp"      # scalar fallback (HEXL is x86-only)
    "${CPP_ROOT}/shared_key_store.cpp"  # pulled in by server.h transitively
    "${CPP_ROOT}/onion_ffi.cpp"      # C ABI — bindings.cpp calls into it
)

# Module target.
add_executable(onionpir_client
    bindings.cpp
    hash_utils.cpp
    ${ONIONPIR_CLIENT_SRC}
)

target_include_directories(onionpir_client PRIVATE
    "${CPP_ROOT}/includes"
    "${CPP_ROOT}/hexl_compat"             # scalar hexl/hexl.hpp shim header
    "${CMAKE_CURRENT_SOURCE_DIR}"         # for hash_utils.h
)

# Emscripten link flags:
#   --bind                       — enable embind
#   ENVIRONMENT=web,worker       — usable from browser main thread and workers
#   ALLOW_MEMORY_GROWTH=1        — heap grows on demand
#   INITIAL_MEMORY=64MB          — start big enough for keygen + one query
#   MAXIMUM_MEMORY=1GB           — cap at 1GB to bound runaway growth
#   EXPORT_NAME=createOnionPir   — JS factory function name
#   MODULARIZE=1                 — emit an ES-module-style factory
#   EXPORT_ES6=1                 — produce ES module syntax
#   DISABLE_EXCEPTION_CATCHING=0 — let the throws from onion_ffi.cpp escape
#   DYNAMIC_EXECUTION=0          — forbid eval/new Function for strict CSP
#   EMBIND_AOT=1                 — pre-generate embind invokers needed above
target_link_options(onionpir_client PRIVATE
    "--bind"
    "-sENVIRONMENT=web,worker,node"
    "-sALLOW_MEMORY_GROWTH=1"
    "-sINITIAL_MEMORY=67108864"
    "-sMAXIMUM_MEMORY=1073741824"
    "-sMODULARIZE=1"
    "-sEXPORT_ES6=1"
    "-sEXPORT_NAME=createOnionPir"
    "-sDISABLE_EXCEPTION_CATCHING=0"
    "-sDYNAMIC_EXECUTION=0"
    "-sEMBIND_AOT=1"
    "-fexceptions"
)

# Emit ES-module .js + .wasm side files.
set_target_properties(onionpir_client PROPERTIES
    OUTPUT_NAME "onionpir_client"
    SUFFIX ".mjs"
)
