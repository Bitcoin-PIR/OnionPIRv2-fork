# Top-level wrapper. The real OnionPIR CMake build is self-contained inside
# rust/onionpir/ — that lets `cargo vendor` of the onionpir crate carry the
# CMake project + cpp/ engine sources along, so Rust consumers (e.g.
# BitcoinPIR's Nix flake) build without needing the surrounding fork repo
# layout. cargo flattens a vendored git dep down to just the consumed
# subcrate; anything outside rust/onionpir/ is dropped.
#
# This file exists for backward compatibility: `cmake -B build` from the
# repo root still works (run.py, java/build.sh) and produces the same
# `onionpir` library + `Onion-PIR` test executable, by delegating into
# rust/onionpir/. All build options (ONIONPIR_BUILD_FFI, ONIONPIR_BUILD_SHARED,
# USE_HEXL, ACTIVE_CONFIG, …) stay settable through this wrapper.
cmake_minimum_required(VERSION 3.13)
project(Onion-PIR-fork)
add_subdirectory(rust/onionpir)
