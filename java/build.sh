#!/usr/bin/env bash
#
# Build + run the Java JNA bindings test.
#
# Requirements:
#   - A JDK on $PATH (javac/java).
#   - The native shared library built once via:
#       cd <repo-root> && mkdir build-shared && cd build-shared && \
#         cmake -DONIONPIR_BUILD_FFI=ON -DONIONPIR_BUILD_SHARED=ON .. && \
#         make onionpir -j
#
# On first run, downloads jna-5.16.0.jar into java/lib/.
# Then compiles com/onionpir/jna/*.java into java/build/ and runs
# test/PirRoundTrip.java.

set -euo pipefail

cd "$(dirname "$0")"
REPO_ROOT="$(cd .. && pwd)"
LIB_DIR="${REPO_ROOT}/build-shared"

if [[ ! -f "${LIB_DIR}/libonionpir.dylib" && ! -f "${LIB_DIR}/libonionpir.so" ]]; then
    echo "error: ${LIB_DIR}/libonionpir.{dylib,so} not found." >&2
    echo "Build it first:" >&2
    echo "  cd ${REPO_ROOT} && mkdir -p build-shared && cd build-shared && \\" >&2
    echo "    cmake -DONIONPIR_BUILD_FFI=ON -DONIONPIR_BUILD_SHARED=ON .. && \\" >&2
    echo "    make onionpir -j" >&2
    exit 1
fi

mkdir -p lib build

# Fetch JNA on first run.
JNA_VERSION="5.16.0"
JNA_JAR="lib/jna-${JNA_VERSION}.jar"
if [[ ! -f "${JNA_JAR}" ]]; then
    echo "Fetching JNA ${JNA_VERSION}..."
    curl -L --fail --output "${JNA_JAR}" \
        "https://repo1.maven.org/maven2/net/java/dev/jna/jna/${JNA_VERSION}/jna-${JNA_VERSION}.jar"
fi

echo "Compiling Java sources..."
javac -d build -cp "${JNA_JAR}" \
    com/onionpir/jna/OnionBuf.java \
    com/onionpir/jna/PirParamsInfo.java \
    com/onionpir/jna/OnionPirLibrary.java \
    com/onionpir/jna/OnionPir.java \
    com/onionpir/jna/OnionPirClient.java \
    com/onionpir/jna/OnionPirServer.java \
    com/onionpir/jna/OnionKeyStore.java \
    test/PirRoundTrip.java \
    test/DbSaveLoad.java \
    test/ClientSkRoundTrip.java \
    test/PushPlaintexts.java \
    test/SharedKeyStoreTest.java

echo
echo "Running PirRoundTrip..."
java -cp "build:${JNA_JAR}" \
    -Djna.library.path="${LIB_DIR}" \
    PirRoundTrip

echo
echo "Running DbSaveLoad..."
java -cp "build:${JNA_JAR}" \
    -Djna.library.path="${LIB_DIR}" \
    DbSaveLoad

echo
echo "Running ClientSkRoundTrip..."
java -cp "build:${JNA_JAR}" \
    -Djna.library.path="${LIB_DIR}" \
    ClientSkRoundTrip

echo
echo "Running PushPlaintexts..."
java -cp "build:${JNA_JAR}" \
    -Djna.library.path="${LIB_DIR}" \
    PushPlaintexts

echo
echo "Running SharedKeyStoreTest..."
java -cp "build:${JNA_JAR}" \
    -Djna.library.path="${LIB_DIR}" \
    SharedKeyStoreTest
