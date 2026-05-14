#!/usr/bin/env bash
#
# Build the OnionPIRv2 WASM client. Requires emscripten on $PATH:
#   - brew install emscripten   (macOS)
#   - or: https://emscripten.org/docs/getting_started/downloads.html
#
# Output:
#   build/onionpir_client.mjs   (ES module factory)
#   build/onionpir_client.wasm  (compiled module)
#
# Usage:
#   cd wasm && ./build.sh
#
# Pass --clean to wipe build/ first; pass --debug for -O0 + debug symbols.

set -euo pipefail

cd "$(dirname "$0")"

CMAKE_BUILD_TYPE=Release
EXTRA_CXX_FLAGS=""
CLEAN=0

for arg in "$@"; do
    case "$arg" in
        --clean) CLEAN=1 ;;
        --debug) CMAKE_BUILD_TYPE=Debug; EXTRA_CXX_FLAGS="-g -O0" ;;
        *) echo "unknown flag: $arg" >&2; exit 1 ;;
    esac
done

if ! command -v emcmake >/dev/null 2>&1; then
    echo "error: emcmake not found on PATH." >&2
    echo "Install emscripten (e.g. \`brew install emscripten\`) or activate emsdk first." >&2
    exit 1
fi

if [[ "$CLEAN" -eq 1 ]]; then
    rm -rf build
fi
mkdir -p build

emcmake cmake \
    -S . \
    -B build \
    -DCMAKE_BUILD_TYPE="$CMAKE_BUILD_TYPE" \
    ${EXTRA_CXX_FLAGS:+-DCMAKE_CXX_FLAGS="$EXTRA_CXX_FLAGS"}

cmake --build build --parallel

echo
echo "Built: $(pwd)/build/onionpir_client.mjs (+ .wasm)"
