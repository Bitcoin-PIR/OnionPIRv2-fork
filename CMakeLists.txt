# Top-level wrapper. The real OnionPIR CMake build now lives self-contained
# inside rust/onionpir/ — that lets `cargo vendor` of the onionpir crate
# bring along the CMake setup + extern/SEAL submodule + cpp/ source, so
# Rust consumers (e.g. BitcoinPIR's nix build derivation) build without
# needing the surrounding fork repo layout.
#
# This file exists for backward compatibility: `cmake -B build` from the
# fork's root still works and produces the same `onionpir` static lib +
# `Onion-PIR` test executable, just by delegating into rust/onionpir/.
cmake_minimum_required(VERSION 3.13)
project(Onion-PIR-Fork-Wrapper)
add_subdirectory(rust/onionpir)
