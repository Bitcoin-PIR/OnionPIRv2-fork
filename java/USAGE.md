# OnionPIR Java JNA Binding — Usage Guide

Java JNA wrapper for the OnionPIRv2 C FFI. Provides safe, `AutoCloseable` classes for FHE-based Private Information Retrieval.

## Building the Native Library

The Java binding loads `libonionpir.so` (Linux) or `libonionpir.dylib` (macOS) at runtime. Build it as a shared library:

```bash
cd OnionPIRv2
git submodule update --init --recursive   # fetch SEAL
mkdir -p build-shared && cd build-shared
cmake .. -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=ON
make -j$(nproc)
# produces: libonionpir.so (Linux) or libonionpir.dylib (macOS)
```

### macOS prerequisites

Homebrew GCC is required for OpenMP support:

```bash
brew install gcc
```

The CMakeLists.txt auto-detects `g++-15`, `g++-14`, or `g++-13` from `/opt/homebrew/bin`.

### Build options

| CMake flag | Default | Description |
|---|---|---|
| `-DBUILD_SHARED_LIBS=ON` | OFF | **Required** — builds `.so`/`.dylib` instead of `.a` |
| `-DUSE_HEXL=ON` | ON (Linux), OFF (macOS) | Intel HEXL acceleration (x86 only) |
| `-DNOAVX512=OFF` | ON | Disable AVX-512 (default ON; pre–Ice Lake CPUs SIGILL on AVX-512. Pass `=OFF` on Xeon Scalable / Ice Lake+ to opt in) |
| `-DNOAVX2=ON` | OFF | Disable AVX2 instructions |

## Java Dependency

Add JNA to your project. Gradle example:

```groovy
dependencies {
    implementation 'net.java.dev.jna:jna:5.16.0'
}
```

Maven:

```xml
<dependency>
    <groupId>net.java.dev.jna</groupId>
    <artifactId>jna</artifactId>
    <version>5.16.0</version>
</dependency>
```

## Loading the Native Library

JNA resolves `"onionpir"` to `libonionpir.so`/`.dylib` via `java.library.path`. Set it when running:

```bash
java -Djna.library.path=/path/to/OnionPIRv2/build-shared ...
```

Or set `LD_LIBRARY_PATH` (Linux) / `DYLD_LIBRARY_PATH` (macOS).

## Package Structure

All classes are in `com.onionpir.jna`:

| Class | Description |
|---|---|
| `OnionPirLibrary` | Raw JNA interface — all C functions. Use directly only if the safe wrappers don't cover your case. |
| `OnionPir` | Static utilities: `paramsInfo(numEntries)` |
| `OnionPirClient` | FHE client — key generation, query encryption, response decryption |
| `OnionPirServer` | PIR server — database loading, key registration, query answering |
| `OnionKeyStore` | Shared key store — deserialize keys once, share across servers |
| `OnionPirQueue` | Async query queue — non-blocking submit with pollable results |
| `OnionBuf` | JNA struct mapping (internal, not normally used directly) |
| `PirParamsInfo` | JNA struct for database parameter info |
| `QueryStatus` | Enum: `QUEUED`, `PROCESSING`, `DONE`, `ERROR`, `NOT_FOUND` |

## Client-Side API (Primary Use Case)

### Create a client, generate keys, query, and decrypt

```java
import com.onionpir.jna.*;

// 1. Create a keygen client (num_entries=0 uses compiled-in default)
try (OnionPirClient keygenClient = new OnionPirClient(0)) {

    // 2. Generate FHE keys to send to the server
    long clientId       = keygenClient.getId();
    byte[] galoisKeys   = keygenClient.generateGaloisKeys();  // ~2-5 MB
    byte[] gswKeys      = keygenClient.generateGswKeys();     // ~1-2 MB
    byte[] secretKey    = keygenClient.exportSecretKey();

    // 3. Send galoisKeys + gswKeys to the server for key registration
    //    (wire format: [4B len LE][0x30][4B gk_len LE][gk][4B gsw_len LE][gsw])

    // 4. Create per-database clients from the same secret key
    try (OnionPirClient indexClient = OnionPirClient.fromSecretKey(
            indexBinCount, clientId, secretKey);
         OnionPirClient chunkClient = OnionPirClient.fromSecretKey(
            chunkBinCount, clientId, secretKey)) {

        // 5. Generate and send a query
        byte[] query = indexClient.generateQuery(entryIndex);
        // ... send query to server, receive encrypted response ...

        // 6. Decrypt the response
        byte[] entry = indexClient.decryptResponse(entryIndex, serverResponse);
    }
}
```

### Key reuse pattern

The secret key is independent of database size. Export it once, then create clients for different `num_entries` values:

```java
// Keygen (num_entries doesn't matter, pass 0)
try (OnionPirClient keygen = new OnionPirClient(0)) {
    byte[] sk = keygen.exportSecretKey();
    long id   = keygen.getId();
    byte[] gk = keygen.generateGaloisKeys();
    byte[] gsw = keygen.generateGswKeys();
    // ... register gk + gsw with server ...

    // Create clients for specific database sizes
    try (OnionPirClient c1 = OnionPirClient.fromSecretKey(1 << 16, id, sk);
         OnionPirClient c2 = OnionPirClient.fromSecretKey(1 << 18, id, sk)) {
        // c1 and c2 share the same FHE keys but target different DB sizes
    }
}
```

## Server-Side API

```java
try (OnionPirServer server = new OnionPirServer(numEntries)) {

    // Load a preprocessed database
    server.loadDb("/path/to/db.bin");
    // or build from chunks:
    // server.pushChunk(chunkData, chunkIndex);
    // server.preprocess();

    // Register client keys
    server.setGaloisKey(clientId, galoisKeys);
    server.setGswKey(clientId, gswKeys);

    // Answer a query
    byte[] response = server.answerQuery(clientId, queryBytes);
    // ... send response back to client ...

    // Cleanup
    server.removeClient(clientId);
}
```

### Shared key store (multi-server optimization)

When running multiple server instances (e.g., one per database partition), use a shared key store to avoid deserializing keys N times:

```java
try (OnionKeyStore keyStore = new OnionKeyStore(numEntries)) {
    // Deserialize once
    keyStore.setGaloisKey(clientId, galoisKeys);
    keyStore.setGswKey(clientId, gswKeys);

    // Attach to multiple servers (keyStore must outlive all servers)
    try (OnionPirServer server1 = new OnionPirServer(numEntries);
         OnionPirServer server2 = new OnionPirServer(numEntries)) {
        server1.setKeyStore(keyStore);
        server2.setKeyStore(keyStore);
        // Both servers share the same deserialized keys
    }
}
```

## Async Query Queue

For concurrent query handling without manually synchronizing server access:

```java
try (OnionPirServer server = new OnionPirServer(numEntries);
     OnionPirQueue queue = new OnionPirQueue(server)) {

    // Submit queries (non-blocking)
    long ticket = queue.submit(clientId, queryBytes);

    // Poll for completion
    while (queue.status(ticket) != QueryStatus.DONE) {
        Thread.sleep(1);
    }

    // Retrieve result
    byte[] response = queue.result(ticket);
}
```

## Database Parameters

Query compile-time PIR parameters for a given database size:

```java
PirParamsInfo.ByValue info = OnionPir.paramsInfo(1 << 16);
// info.num_entries     — number of DB rows
// info.entry_size      — bytes per entry
// info.num_plaintexts  — plaintext count
// info.fst_dim_sz      — first dimension size
// info.other_dim_sz    — other dimension size
// info.poly_degree     — SEAL polynomial degree
// info.coeff_val_cnt   — coefficients per entry (poly_degree * rns_mod_cnt)
// info.db_size_mb      — logical DB size in MB
// info.physical_size_mb — physical (expanded) size in MB
```

## Thread Safety

- A single `OnionPirClient`, `OnionPirServer`, or `OnionKeyStore` instance must **not** be shared across threads.
- Multiple instances can exist concurrently on different threads.
- Use `OnionPirQueue` to safely handle concurrent queries against a single server.

## Memory Management

All wrapper classes implement `AutoCloseable`. Use try-with-resources to ensure native handles are freed:

```java
try (OnionPirClient client = new OnionPirClient(numEntries)) {
    // ... use client ...
}  // onion_client_free() called automatically
```

Methods that return `byte[]` (keys, queries, responses) copy the data from the native buffer and free it immediately. The returned `byte[]` is a normal Java array with no native lifecycle concerns.

## Type Mapping Reference

| C type | Java/JNA type | Notes |
|---|---|---|
| `void*` (handles) | `com.sun.jna.Pointer` | Opaque, managed by wrapper classes |
| `uint64_t` | `long` | Unsigned semantics; use `Long.toUnsignedString()` for display |
| `size_t` | `com.sun.jna.NativeLong` | Handled internally by wrappers |
| `const uint8_t*` + `size_t` | `byte[]` | JNA marshals automatically |
| `OnionBuf` (return) | `byte[]` | Wrappers copy + free; raw API uses `OnionBuf.ByValue` |
| `CPirParamsInfo` | `PirParamsInfo.ByValue` | Struct returned by value |
| `const char*` | `String` | JNA marshals automatically |
