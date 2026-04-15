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


# Option to enable Intel HEXL acceleration. HEXL is x86_64-only (AVX2 +
# AVX-512-IFMA paths with runtime CPU dispatch). Defaults to ON on x86_64
# Linux/Windows; OFF on Apple Silicon and other non-x86 targets.
# When enabled, HEXL is fetched and built by SEAL's own FetchContent
# (extern/SEAL/cmake/ExternalIntelHEXL.cmake pins v1.2.5 = f95acf1),
# exposing the HEXL::hexl target we link against below.
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


option(NOAVX512 "Disable AVX-512" OFF)
option(NOAVX2 "Disable AVX2" OFF)
if (NOAVX512)
    message("Disabling AVX-512")
    add_compile_options(-mno-avx512f)
endif()
if (NOAVX2)
    message("Disabling AVX2")
    add_compile_options(-mno-avx2)
endif()

set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -D_DEBUG")
set(IS_BENCHMARK_BUILD CMAKE_BUILD_TYPE STREQUAL "Benchmark")
if (${IS_BENCHMARK_BUILD})
    add_compile_definitions(_BENCHMARK)
endif ()
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
project(Onion-PIR)

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
