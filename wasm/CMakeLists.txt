cmake_minimum_required(VERSION 3.13)
project(onionpir-wasm CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# ==================== SEAL configuration for Emscripten ====================
# Force-set intrinsic detection results BEFORE add_subdirectory(SEAL).
# Emscripten cannot run check_cxx_source_runs() during cross-compilation,
# so we tell SEAL what's available at compile time.

# Emscripten's clang supports __int128 (via i64 pair emulation) and __builtin_clzll
set(SEAL___INT128_FOUND ON CACHE INTERNAL "Emscripten supports __int128")
set(SEAL___BUILTIN_CLZLL_FOUND ON CACHE INTERNAL "Emscripten clang supports __builtin_clzll")

# x86-only intrinsics — not available in WASM
set(SEAL__ADDCARRY_U64_FOUND OFF CACHE INTERNAL "x86-only intrinsic")
set(SEAL__SUBBORROW_U64_FOUND OFF CACHE INTERNAL "x86-only intrinsic")

# Memory functions — may not be available in WASM/Emscripten
set(SEAL_MEMSET_S_FOUND OFF CACHE INTERNAL "Not available in WASM")
set(SEAL_EXPLICIT_BZERO_FOUND OFF CACHE INTERNAL "Not available in WASM")
set(SEAL_EXPLICIT_MEMSET_FOUND OFF CACHE INTERNAL "Not available in WASM")

# SEAL build options
set(SEAL_USE_INTEL_HEXL OFF CACHE BOOL "" FORCE)
set(SEAL_USE_MSGSL      OFF CACHE BOOL "" FORCE)
set(SEAL_USE_ZLIB       OFF CACHE BOOL "" FORCE)
set(SEAL_USE_ZSTD       OFF CACHE BOOL "" FORCE)
set(SEAL_BUILD_DEPS     ON  CACHE BOOL "" FORCE)
set(SEAL_THROW_ON_TRANSPARENT_CIPHERTEXT OFF CACHE BOOL "" FORCE)
set(SEAL_USE_ALIGNED_ALLOC OFF CACHE BOOL "" FORCE)

# SEAL must also be compiled with exception support for Emscripten
if(EMSCRIPTEN)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fexceptions")
endif()

add_subdirectory(../rust/onionpir/extern/SEAL seal_build)

# ==================== Client-only WASM module ====================
# Define _BENCHMARK to enable the no-op debug macros in logging.h / utils.h
add_compile_definitions(_BENCHMARK)
# Only compile client-side source files (no server.cpp, no matrix.cpp)

set(REPO_SRC ../src)

add_executable(onionpir_client
    bindings.cpp
    hash_utils.cpp
    ${REPO_SRC}/client.cpp
    ${REPO_SRC}/pir.cpp
    ${REPO_SRC}/gsw_eval.cpp
    ${REPO_SRC}/utils.cpp
    ${REPO_SRC}/logging.cpp
)

target_include_directories(onionpir_client PRIVATE
    ${REPO_SRC}/includes
    ${CMAKE_CURRENT_SOURCE_DIR}
)

target_link_libraries(onionpir_client PRIVATE SEAL::seal)

# ==================== Emscripten link flags ====================
if(EMSCRIPTEN)
    # Enable C++ exceptions (SEAL uses them internally)
    target_compile_options(onionpir_client PRIVATE -fexceptions)

    target_link_options(onionpir_client PRIVATE
        -lembind
        -fexceptions
        -sWASM=1
        -sMODULARIZE=1
        -sEXPORT_NAME=createOnionPirModule
        -sALLOW_MEMORY_GROWTH=1
        -sINITIAL_MEMORY=67108864      # 64 MB
        -sMAXIMUM_MEMORY=268435456     # 256 MB
        -sNO_FILESYSTEM=0
        -sENVIRONMENT=web,worker,node
        -sSINGLE_FILE=0
    )
endif()
