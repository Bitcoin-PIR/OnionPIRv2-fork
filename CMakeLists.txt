cmake_minimum_required(VERSION 3.13)

# Set build type to Benchmark if not specified
if (NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Benchmark)
endif()

# ==================== Compiler Selection ====================
# On macOS ARM64, use GCC from Homebrew for OpenMP support.
# On Linux, use system GCC.
if (APPLE)
    # Look for Homebrew GCC (g++-15, g++-14, etc.)
    find_program(GCC_CXX NAMES g++-15 g++-14 g++-13 PATHS /opt/homebrew/bin NO_DEFAULT_PATH)
    find_program(GCC_CC  NAMES gcc-15 gcc-14 gcc-13 PATHS /opt/homebrew/bin NO_DEFAULT_PATH)
    if (GCC_CXX AND GCC_CC)
        set(CMAKE_C_COMPILER  ${GCC_CC})
        set(CMAKE_CXX_COMPILER ${GCC_CXX})
        message(STATUS "Using Homebrew GCC: ${GCC_CXX}")
    else()
        message(WARNING "Homebrew GCC not found, falling back to default compiler. OpenMP may not work.")
    endif()
else()
    set(CMAKE_C_COMPILER  /usr/bin/gcc)
    set(CMAKE_CXX_COMPILER /usr/bin/g++)
endif()

# Ask every target in this project to compile as C++20
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)   # fail if the compiler can't do C++20
set(CMAKE_CXX_EXTENSIONS  OFF)        # use -std=c++20, not gnu++20

# Automatically enables all available optimizations for your local machine
if (APPLE)
    # On ARM macOS with GCC, -march=native can fail. Use -mcpu=native instead.
    set(CMAKE_CXX_FLAGS "-O3 -MD -mcpu=native")
    set(CMAKE_OSX_ARCHITECTURES "")  # Prevent CMake from adding -arch flag
else()
    set(CMAKE_CXX_FLAGS "-O3 -MD -march=native -mtune=native")
endif()

# Add perf when building in Debug mode
if (CMAKE_BUILD_TYPE MATCHES Debug)
    if (APPLE)
        set(CMAKE_CXX_FLAGS "-O2 -MD -pg -mcpu=native")
    else()
        set(CMAKE_CXX_FLAGS "-O2 -MD -pg -march=native -mtune=native")
    endif()
endif()


set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -D_DEBUG")
set(IS_BENCHMARK_BUILD CMAKE_BUILD_TYPE STREQUAL "Benchmark")
if (${IS_BENCHMARK_BUILD})
    add_compile_definitions(_BENCHMARK)
endif ()
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
project(Onion-PIR)

# AVX-512 / AVX-2 disable switches. -mno-avx512f / -mno-avx2 are x86-only
# flags; gcc/clang on aarch64 hard-error on them. Both must be gated on
# CMAKE_SYSTEM_PROCESSOR, which is only populated by project() — that's
# why this block lives below project() rather than above.
#
# NOAVX512 defaults ON: SEAL's check_cxx_compiler_flag(-mavx512ifma) only
# tests compiler acceptance, not CPU support. gcc 13+ always accepts the
# flag, so SEAL's blake2b auto-vectorizes into vmovdqu64 / zmm registers
# and SIGILLs on AVX2-only CPUs (e.g. Coffee Lake i7-8700) the moment
# any keygen runs. Operators on known AVX-512-IFMA hosts can opt back in
# with -DNOAVX512=OFF. HEXL's runtime CPU dispatch still provides the
# AVX-512-IFMA acceleration on capable hardware via its own paths.
option(NOAVX512 "Disable AVX-512" ON)
option(NOAVX2 "Disable AVX2" OFF)
if (CMAKE_SYSTEM_PROCESSOR MATCHES "^(x86_64|AMD64|amd64|i[3-6]86)$")
    if (NOAVX512)
        message(STATUS "Disabling AVX-512 (-mno-avx512f)")
        add_compile_options(-mno-avx512f)
    endif()
    if (NOAVX2)
        message(STATUS "Disabling AVX2 (-mno-avx2)")
        add_compile_options(-mno-avx2)
    endif()
else()
    if (NOAVX512 OR NOAVX2)
        message(STATUS "NOAVX512/NOAVX2 ignored on non-x86 target "
                       "(${CMAKE_SYSTEM_PROCESSOR}); these flags are x86-only.")
    endif()
endif()

# Option to enable Intel HEXL acceleration. HEXL is x86_64-only (AVX2 +
# AVX-512-IFMA paths with runtime CPU dispatch). Defaults to ON on x86_64
# Linux/Windows; OFF on Apple Silicon and other non-x86 targets.
# When enabled, HEXL is fetched and built by SEAL's own FetchContent
# (extern/SEAL/cmake/ExternalIntelHEXL.cmake pins v1.2.5 = f95acf1),
# exposing the HEXL::hexl target we link against below.
#
# NOTE: this block MUST come after project(). CMAKE_SYSTEM_PROCESSOR is
# only populated by project(); reading it earlier yields an empty string,
# which makes the arch regex fail and silently disables HEXL even when
# the caller passed -DUSE_HEXL=ON.
if (CMAKE_SYSTEM_PROCESSOR MATCHES "^(x86_64|AMD64|amd64)$" AND NOT APPLE)
    option(USE_HEXL "Enable Intel HEXL acceleration (x86_64 only)" ON)
else()
    option(USE_HEXL "Enable Intel HEXL acceleration (x86_64 only)" OFF)
endif()

if (USE_HEXL AND NOT (CMAKE_SYSTEM_PROCESSOR MATCHES "^(x86_64|AMD64|amd64)$"))
    message(WARNING "USE_HEXL=ON requested on ${CMAKE_SYSTEM_PROCESSOR}; "
                    "HEXL is x86_64-only. Disabling.")
    set(USE_HEXL OFF)
endif()

if (USE_HEXL)
    message(STATUS "HEXL support enabled (fetched + built via SEAL).")
    add_compile_definitions(ONIONPIR_USE_HEXL)
else()
    message(STATUS "HEXL support disabled.")
endif()

# ==================== OpenMP ====================
find_package(OpenMP REQUIRED)

# ==================== SEAL (submodule) ====================
# Build SEAL from extern/SEAL submodule instead of requiring a system install.
# Couple SEAL's HEXL integration to our USE_HEXL option. When ON, SEAL
# fetches HEXL via FetchContent and exposes HEXL::hexl. When OFF, SEAL's
# scalar fallback path is used (required on Apple Silicon / aarch64).
if (USE_HEXL)
    set(SEAL_USE_INTEL_HEXL ON  CACHE BOOL "" FORCE)
else()
    set(SEAL_USE_INTEL_HEXL OFF CACHE BOOL "" FORCE)
endif()

# Extend NOAVX512 policy to HEXL itself. HEXL's probe
# (hexl's own cmake/hexl/hexl-util.cmake::hexl_check_compile_flag, fetched
# at configure time by SEAL's extern/SEAL/cmake/ExternalIntelHEXL.cmake)
# uses try_run() with COMPILE_DEFINITIONS=-march=native, which bypasses the
# -mno-avx512f we injected via add_compile_options above (add_compile_options
# does not propagate into try_compile/try_run). On AVX-512-capable build
# hosts (e.g. GitHub Actions ubuntu-22.04 on Azure westcentralus) the probes
# therefore succeed and HEXL's root CMakeLists.txt then:
#   1. calls add_definitions(-DHEXL_HAS_AVX512{DQ,IFMA,VBMI2}), enabling the
#      #ifdef HEXL_HAS_AVX512* guards inside HEXL sources, and
#   2. appends eltwise-*-avx512*.cpp / fwd-ntt-avx512.cpp / inv-ntt-avx512.cpp
#      to its build sources.
# Those TUs then fail to compile under the parent project's inherited
# -mno-avx512f with "inlining failed in call to always_inline '_mm512_*':
# target specific option mismatch", as seen in
#   https://github.com/Bitcoin-PIR/Bitcoin-PIR/actions/runs/24554690767
#
# Cache-variable overrides (set(HEXL_HAS_AVX512DQ OFF CACHE BOOL "" FORCE))
# do not help: hexl_check_compile_flag runs unconditionally and writes via
# add_definitions(), which is independent of the CMake variable's value.
#
# Fix: supersede SEAL's internal FetchContent_Declare(hexl ...) by declaring
# hexl FIRST ourselves, with a PATCH_COMMAND that drops the three AVX-512
# probe call sites from HEXL's root CMakeLists.txt. FetchContent_Declare
# uses first-declared-wins semantics, so SEAL's subsequent declaration of
# the same content name is a no-op. HEXL's AVX2 probe (test-avx256.cpp,
# HEXL_HAS_AVX256) is preserved — HEXL-without-AVX-512 is still faster than
# SEAL's scalar fallback.
#
# Linux-only (sed + POSIX tools). USE_HEXL is x86_64 Linux/Windows, but
# we gate this patch step on UNIX so Windows consumers remain unaffected;
# on Windows this block is skipped, HEXL's probes still fire, and the
# MSVC build path is untouched. The primary regression this fixes is
# Linux CI, which is the only currently-exercised HEXL target.
if (USE_HEXL AND NOAVX512 AND UNIX)
    include(FetchContent)
    FetchContent_Declare(
        hexl
        PREFIX hexl
        GIT_REPOSITORY https://github.com/intel/hexl
        GIT_TAG        f95acf1  # 1.2.5 — must match extern/SEAL/cmake/ExternalIntelHEXL.cmake
        PATCH_COMMAND  sed -i.bak
                       "/hexl_check_compile_flag.*test-avx512/d"
                       CMakeLists.txt
    )
endif()

# SEAL has its own NOAVX512 / NOAVX2 options that, when ON, add
# -mno-avx512f / -mno-avx2 to its compile options. Those flags are
# x86-only — gcc/clang on aarch64 hard-error on them. Force both OFF
# in the cache before add_subdirectory(extern/SEAL) on non-x86 hosts so
# SEAL's own block skips the flag injection. (On x86 the user-level
# defaults from the block above stay in effect.)
if (NOT (CMAKE_SYSTEM_PROCESSOR MATCHES "^(x86_64|AMD64|amd64|i[3-6]86)$"))
    set(NOAVX512 OFF CACHE BOOL "" FORCE)
    set(NOAVX2   OFF CACHE BOOL "" FORCE)
endif()
set(SEAL_USE_MSGSL      OFF CACHE BOOL "" FORCE)
set(SEAL_USE_ZLIB       OFF CACHE BOOL "" FORCE)
set(SEAL_USE_ZSTD       OFF CACHE BOOL "" FORCE)
set(SEAL_BUILD_DEPS     ON  CACHE BOOL "" FORCE)
set(SEAL_THROW_ON_TRANSPARENT_CIPHERTEXT OFF CACHE BOOL "" FORCE)
add_subdirectory(extern/SEAL)

# ==================== Core library (for FFI / Rust integration) ====================
# All source files except main.cpp and tests.cpp go into the static library.
file(GLOB LIB_SRC_FILES
    src/server.cpp
    src/client.cpp
    src/pir.cpp
    src/gsw_eval.cpp
    src/matrix.cpp
    src/utils.cpp
    src/logging.cpp
    src/shared_key_store.cpp
    src/ffi.cpp
    src/ffi_c.cpp
)
add_library(onionpir ${LIB_SRC_FILES})
target_include_directories(onionpir PUBLIC src/includes)
target_link_libraries(onionpir PUBLIC SEAL::seal OpenMP::OpenMP_CXX)
if (USE_HEXL)
    # HEXL::hexl was fetched + built by SEAL above (SEAL_USE_INTEL_HEXL=ON).
    target_link_libraries(onionpir PUBLIC HEXL::hexl)
endif()

# Install the library and FFI headers for external consumers (e.g. Rust -sys crate)
install(TARGETS onionpir seal
    ARCHIVE DESTINATION lib
    LIBRARY DESTINATION lib)
install(FILES src/includes/ffi.h src/includes/ffi_c.h DESTINATION include/onionpir)

# ==================== Test executable ====================
add_executable(Onion-PIR src/main.cpp src/tests.cpp)
target_link_libraries(Onion-PIR PRIVATE onionpir)
target_include_directories(Onion-PIR PRIVATE src/includes)
