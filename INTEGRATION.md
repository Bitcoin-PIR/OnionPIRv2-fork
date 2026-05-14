# OnionPIRv2 — integration guide for downstream consumers

This document is the migration + integration reference for code that depends on
this fork's Rust crate, WASM client, Java JNA bindings, or the C ABI directly.
It captures the breaking changes from the SEAL-based fork (`pre-port` tag) to
the current upstream-tracking codebase, plus the new capabilities that came
with the port.

The motivating context: the upstream OnionPIRv2 paper (ePrint 2025/1142) was
revised to fix a misuse of SEAL's GHS/hybrid key-switching where the "special
prime" silently inflated the effective ciphertext modulus, leaving real-world
security below the claimed 128 bits. Upstream's fix was to remove SEAL entirely
and re-implement BV key-switching (no special prime). This fork tracks that
upstream and re-applies the Rust / WASM / Java / multi-tenant layers on top.

The previous SEAL-based main HEAD is preserved at tag `pre-port` if you ever
need to compare.

---

## 1. Breaking changes — checklist

Skim this whole section first. The drift from `pre-port` is substantial and
some of the failures are silent (wrong-but-decodable answers).

### 1.1 C ABI renames

| Old | New |
|---|---|
| `onion_get_params_info` | `onion_params_info` |
| `onion_client_generate_galois_keys` | `onion_client_galois_keys` |
| `onion_client_generate_gsw_keys` | `onion_client_gsw_key` |
| `onion_server_set_galois_key` | `onion_server_set_galois_keys` |

`CPirParamsInfo` → `OnionPirParamsInfo`, with a new `rns_mod_count` field
between `poly_degree` and `coeff_val_cnt`.

### 1.2 Wire formats — all hand-rolled little-endian now

SEAL's `Serializable` bytes are gone. Everything is plain LE:

```
RlweCt (query)   : [u32 ntt_form][u32 poly_size][u64 c0[…]][u64 c1[…]]
BvGaloisKeys     : [u32 num_keys]
                   per key:  [u32 galois_k][u32 num_cts][u32 poly_size]
                   per ct:   [u64 a[…]][u64 b[…]]
GSWCt            : [u32 num_rows][u32 row_size]
                   per row:  [u64 row[…]]
Plaintext        : [u32 N][u64 coeff_0]…[u64 coeff_{N-1}]
Secret key       : [u32 word_count][u64 sk_words[…]]
Server response  : bit-packed via PirServer::save_resp_to_stream
                   (unchanged interface; format is internal)
```

Anything previously persisted under SEAL serialization (galois keys, GSW
keys, secret keys, recorded queries / responses) is no longer parseable.
Re-key every client.

### 1.3 Preprocessed DB format changed

Header grew from 4×u64 to 6×u64:
```
[u64 magic][u64 version][u64 layout_id]
[u64 num_pt][u64 coeff_val_cnt][u64 data_bytes]
[<data_bytes> raw payload]
```

`load_db` will return `false` for any file written by the pre-port build.

**Regenerate every cached `preprocessed_db.bin`.**

### 1.4 `push_database_chunk` is gone

Replaced by `push_plaintexts`, which operates at the **plaintext** level:
each plaintext is `N` `uint64` coefficients in `[0, t)`. The "pack raw bytes
into plaintext coefficients" step that used to live in
`push_database_chunk` now belongs in **app code**.

Packing recipe (use `bits_per_coeff = PlainMod - 1`, read it as
`PolyDegree`-related fields from `params_info`):

```
for each plaintext slot p:
  buffer = 0; offset = 0; coeff_idx = 0
  for each entry byte b in this plaintext's data:
    buffer |= (uint128)b << offset
    offset += 8
    while offset >= bits_per_coeff:
      pt[p][coeff_idx++] = buffer & ((1 << bits_per_coeff) - 1)
      buffer >>= bits_per_coeff
      offset  -= bits_per_coeff
  if offset > 0:
    pt[p][coeff_idx] = buffer & ((1 << bits_per_coeff) - 1)
```

Then `server.push_plaintexts(pt_flat, num_plaintexts, offset, &[])`.

### 1.5 `decrypt_response` output changed

* Old: took an entry index, returned the unpacked entry bytes.
* New: returns the raw plaintext as `[u32 N][u64 coeff_0]…[u64 coeff_{N-1}]`.

App code does the inverse bit-unpacking with the same `bits_per_coeff` it
used at push time.

### 1.6 Wire-format helpers

The serializers / deserializers live in `src/onion_ffi.cpp`. If you need to
interop without going through the FFI (e.g., decoding bytes in TypeScript),
reproduce the formats above byte-for-byte.

---

## 2. New capabilities

All exposed through the C ABI, Rust, and Java. WASM gets the client-side ones.

### 2.1 `SharedKeyStore`

Many `PirServer` instances back onto one cache of deserialized client keys.
Memory scales with the client count, not (clients × servers). Internal LRU
caps the cache at 100 clients today.

```
Rust:  let store = KeyStore::new();
       store.set_galois_keys(client_id, &galois_blob);
       store.set_gsw_key(client_id, &gsw_blob);
       unsafe { server.set_key_store(Some(&store)); }
```

End-to-end example: [tests/integration.rs `shared_key_store_two_servers`](rust/onionpir/tests/integration.rs).

### 2.2 Async `QueryQueue`

Worker-thread-backed async wrapper. Submit → poll status → consume result.
Thread-safe on the producer side.

```
Rust:  let queue = QueryQueue::new(&mut server);
       let ticket = queue.submit(client_id, &query_bytes).unwrap();
       loop {
           match queue.status(ticket) {
               QueryStatus::Done => break queue.result(ticket).unwrap(),
               QueryStatus::Error => panic!("..."),
               _ => std::thread::sleep(Duration::from_millis(10)),
           }
       }
```

Note: WASM doesn't expose the queue (no threads). End-to-end example:
[tests/integration.rs `query_queue_roundtrip`](rust/onionpir/tests/integration.rs).

### 2.3 Indirect DB mode

Many servers share one NTT-expanded backing store; each server keeps its own
`index_table` mapping `pt_id` → physical entry in the store. Memory scales
with one shared DB + N small `u32` index tables instead of N full DBs.

Constraints today:
* `CONFIG_N2048_K1` only (composite-first-dim configs refuse the attach).
* `index_table.len()` must equal `params_info().num_plaintexts`.
* Caller-owned buffers must outlive every server attached.

End-to-end example: [tests/integration.rs `shared_database_identity_index_table`](rust/onionpir/tests/integration.rs).

### 2.4 Client secret-key export / import

Persist a client across process restarts (esp. browser page reloads).

```
Rust:  let sk = client.export_secret_key();
       // …persist sk somewhere…
       let restored = Client::from_secret_key(0, original_id, &sk).unwrap();
```

End-to-end example: [tests/integration.rs `client_secret_key_roundtrip`](rust/onionpir/tests/integration.rs).

### 2.5 DB persistence

```
server.save_db(path)             → bool
server.load_db(path)             → bool
unsafe { server.load_db_from_borrowed(&bytes) } → bool   // zero-copy alias
```

End-to-end example: [tests/integration.rs `db_save_load_roundtrip`](rust/onionpir/tests/integration.rs).

### 2.6 `push_plaintexts` (production-mode chunked build)

```
server.push_plaintexts(plaintexts_u64, count, offset, record_indices) → bool
```

End-to-end example: [tests/integration.rs `push_plaintexts_roundtrip`](rust/onionpir/tests/integration.rs).

---

## 3. Build configuration

Pick a config at build time via `-DACTIVE_CONFIG=...` on the CMake line or by
threading it through `rust/onionpir/build.rs`. Default is `CONFIG_N2048_K1`.

| Config | N | Plain mod | log Q | Bytes / plaintext | Notes |
|---|---|---|---|---|---|
| `CONFIG_N2048_K1` (default) | 2048 | 14 | 60 | **3328** | Production-tested. Security ~110-bit classical per LWE estimator. |
| `CONFIG_N2048_K1_COMP` | 2048 | 13 | 58 (= 29+29) | 3072 | Composite-first-dim 32×32→64 fast path. Closest to 128-bit at N=2048. |
| `CONFIG_N2048_K2_MP` | 2048 | 10 | 58 (CRT) | 2304 | Multi-precision K=2. |
| `CONFIG_N4096_K2_MP` | 4096 | 40 | 120 | **19968** (~19.5 KB) | Biggest bins, ~2× server cost, proper ≥128-bit security. |

The default DB target size is `DB_SIZE_MB = 128` (override at build time).
Actual `num_pt` falls out of `DB_SIZE_MB * 1024 * 1024 / pt_size`, then
gets rounded by `utils::calculate_db_shape`.

### What changed from the pre-port fork

The pre-port fork's active config was effectively `N=2048, PlainMod=16,
DB_SIZE_MB=256, num_entries=65536` (a power of two). The current default
landed at `N=2048, PlainMod=14, DB_SIZE_MB=128, num_pt≈40448` (not a power
of two).

To approximate the old capacity with the new code: build with
`-DDB_SIZE_MB=256` and the default `CONFIG_N2048_K1`. That gives
`num_pt ≈ 80693`, bytes/plaintext = 3328, total bytes ≈ 256 MB.

---

## 4. Capacity math (read at runtime, don't hardcode)

**`params_info(num_entries)` previews the shape for a given target.** Pass
`0` for the compile-time default; pass a non-zero value to preview the shape
a `Server::new(num_entries)` / `Client::new(num_entries)` of the same size
would produce. See §10 below for when to use the runtime override.

All consumers should pull these from `params_info(0)`:

| Field | Meaning | Old default | New default |
|---|---|---|---|
| `poly_degree` (N) | Lattice / plaintext coeff count | 2048 | 2048 |
| `rns_mod_count` (K) | RNS limbs | 1 | 1 |
| `entry_size` | Bytes per plaintext | 3840 | 3328 |
| `num_plaintexts` | Total bins (defaults to `DB_SIZE_MB / pt_size`; **runtime-overridable** since 2026-05-15) | 65536 (2¹⁶) | shape-dependent |
| `fst_dim_sz` | First-dimension size | 256 | 512 |
| `other_dim_sz` | Other-dim product | 256 | shape-dependent |
| `db_size_mb` | Pre-NTT byte budget (`num_pt × entry_size`) | ~245 MB | shape-dependent |
| `physical_size_mb` | **On-disk size** (`num_pt × coeff_val_cnt × sizeof(db_coeff_t)`, the actual `save_db` output size) | — | shape-dependent |

The total *useful* capacity is `entry_size × num_plaintexts` bytes (the
`db_size_mb` field). The **on-disk** size is what `save_db` writes and what
`load_db` / `load_db_from_borrowed` need to read — that's `physical_size_mb`,
which is *larger* than `db_size_mb` because the saved DB is in post-NTT
level-major form. At the default config (N=2048, PlainMod=14, K=1) the
expansion factor is `(coeff_val_cnt × 8) / pt_size = 16384 / 3328 ≈ 4.92×`.
Previously `physical_size_mb` aliased `db_size_mb`; that was a documentation
footgun (BitcoinPIR hit it) and is fixed now.

---

## 5. Guidance for cuckoo-hashing consumers (e.g., BitcoinPIR)

Three things in particular matter when the cuckoo planner sits on top of
this library:

### 5.1 Never hardcode bin size or bin count

Always read `entry_size` and `num_plaintexts` from `params_info(0)` at app
init. The values move whenever someone picks a different `ACTIVE_CONFIG` or
`DB_SIZE_MB`.

### 5.2 `num_pt` is no longer a power of two

`40448 & (40448 - 1) ≠ 0`. Any code using bitmask-style modular reduction
(`entry_id & (num_bins - 1)`) is wrong here — switch to true `%`. The
in-tree helper `hash_cuckoo_int` (in `wasm/hash_utils.cpp`) already uses
`%`; mirror that on the Rust server side if you have parallel logic.

### 5.3 Cuckoo load factor / hash count

The smaller bin count at the same load factor pushes insertion failure
rates up. Phase-1 numbers from the previous build (6 hashes, 65536 bins,
load ~0.65) likely need 1–2 more hash functions against the new ~40 K
bins to hold the >99% success threshold. Re-fit empirically.

### 5.4 Three knobs to recover capacity

| Goal | Knob |
|---|---|
| Restore ~256 MB total at same bin size | `-DDB_SIZE_MB=256` → num_pt ≈ 80 693, bytes/bin = 3328 |
| Bigger bins → fewer cuckoo collisions | `-DACTIVE_CONFIG=CONFIG_N4096_K2_MP` → 19.5 KB/bin, ~2× server cost |
| Drop cuckoo entirely (if data fits in bigger bins) | same as above + redesign |

---

## 6. API quick reference

### 6.1 C ABI ([src/includes/onion_ffi.h](src/includes/onion_ffi.h))

```c
// Lifecycle
OnionClientHandle  onion_client_new(uint64_t num_entries);
OnionServerHandle  onion_server_new(uint64_t num_entries);

// Params
OnionPirParamsInfo onion_params_info(uint64_t num_entries);

// Client: key generation + query + decrypt
OnionBuf  onion_client_galois_keys(OnionClientHandle);
OnionBuf  onion_client_gsw_key(OnionClientHandle);
OnionBuf  onion_client_generate_query(OnionClientHandle, uint64_t pt_idx);
OnionBuf  onion_client_decrypt_response(OnionClientHandle, const uint8_t*, size_t);

// Client persistence
OnionBuf          onion_client_export_secret_key(OnionClientHandle);
OnionClientHandle onion_client_new_from_sk(uint64_t, uint64_t, const uint8_t*, size_t);

// Server data
void onion_server_gen_data(OnionServerHandle, const uint64_t*, size_t);
int  onion_server_push_plaintexts(OnionServerHandle, const uint64_t*, uint64_t, uint64_t, const uint64_t*, size_t);
int  onion_server_save_db(OnionServerHandle, const char*);
int  onion_server_load_db(OnionServerHandle, const char*);
int  onion_server_load_db_from_borrowed(OnionServerHandle, const uint8_t*, size_t);

// Server: client keys + query
void     onion_server_set_galois_keys(OnionServerHandle, uint64_t, const uint8_t*, size_t);
void     onion_server_set_gsw_key   (OnionServerHandle, uint64_t, const uint8_t*, size_t);
OnionBuf onion_server_answer_query  (OnionServerHandle, uint64_t, const uint8_t*, size_t);

// Multi-tenant
OnionKeyStoreHandle onion_key_store_new(void);
void onion_server_set_key_store(OnionServerHandle, OnionKeyStoreHandle);
int  onion_server_set_shared_database(OnionServerHandle, const uint64_t*, uint64_t, const uint32_t*, uint64_t);

// Async
OnionQueueHandle onion_queue_new(OnionServerHandle);
uint64_t         onion_queue_submit(OnionQueueHandle, uint64_t, const uint8_t*, size_t);
int              onion_queue_status(OnionQueueHandle, uint64_t);
OnionBuf         onion_queue_result(OnionQueueHandle, uint64_t);
```

### 6.2 Rust ([rust/onionpir/src/lib.rs](rust/onionpir/src/lib.rs))

Safe wrappers: `Client`, `Server`, `KeyStore`, `QueryQueue`, `params_info()`.
Cross-call pointer aliases (`set_key_store`, `load_db_from_borrowed`,
`set_shared_database`) are marked `unsafe` so the borrow contract is visible.

### 6.3 Java JNA ([java/com/onionpir/jna/](java/com/onionpir/jna/))

`OnionPir`, `OnionPirClient`, `OnionPirServer`, `OnionKeyStore`,
`OnionPirQueue`, `QueryStatus`. All wrappers are `AutoCloseable`.
Cross-call pointer aliases must be backed by JNA `Memory` (not `long[]`),
since Java arrays are only pinned for the duration of one call — see
`OnionPirServer.setSharedDatabase` for the pattern.

### 6.4 WASM ([wasm/onionpir_client.d.ts](wasm/onionpir_client.d.ts))

ES-module factory `createOnionPir()` returns:
* `paramsInfo()` — runtime config
* `OnionPirClient` — `id`, `galoisKeys`, `gswKey`, `generateQuery`,
  `decryptResponse`, `exportSecretKey`
* `createClientFromSecretKey(id, sk)` — restore persisted clients
* `splitmix64`, `cuckooHashInt`, `buildCuckooBs1` — app-level hash helpers
  (unchanged from pre-port)

The WASM module is **client-only** — no server, no queue, no DB save/load.

---

## 7. Where to find end-to-end examples

For every API path, look at the integration tests — they exercise the same
wire format BitcoinPIR would use, and are the canonical reference for "how
do I call this correctly":

* C ABI: [tests/ffi_smoke.cpp](tests/ffi_smoke.cpp)
* Rust:  [rust/onionpir/tests/integration.rs](rust/onionpir/tests/integration.rs)
* Java:  [java/test/](java/test/)
* WASM:  [wasm/test_node.mjs](wasm/test_node.mjs)

Each integration test is `Server::new` → `gen_data` → `Client::new` →
register keys → `generate_query` → `answer_query` → `decrypt_response`.
The multi-tenant tests (`shared_key_store_two_servers`,
`query_queue_roundtrip`, `shared_database_identity_index_table`) layer
the extra features on top of that base.

---

## 8. Build matrix

```
# Native executable (the upstream test harness)
mkdir build && cd build && cmake .. && make Onion-PIR -j

# Static library for native consumers (Rust crate uses this internally)
mkdir build-ffi && cd build-ffi
cmake -DONIONPIR_BUILD_FFI=ON ..
make onionpir -j

# Shared library for Java JNA
mkdir build-shared && cd build-shared
cmake -DONIONPIR_BUILD_FFI=ON -DONIONPIR_BUILD_SHARED=ON ..
make onionpir -j

# Rust crate
cargo build -p onionpir
cargo test -p onionpir -- --test-threads=1   # must run serially

# WASM client (requires emscripten on PATH)
cd wasm && ./build.sh

# Java integration suite
cd java && ./build.sh
```

`-DUSE_HEXL=ON` (default on x86_64) links Intel HEXL for fast NTT.
`-DUSE_HEXL=OFF` (default on AArch64 / WASM) falls back to the scalar shim
at [src/hexl_compat/](src/hexl_compat/) (Shoup mul + NEON eltwise on ARM —
about 3× slower than HEXL-on-x86 in the default config).

---

## 10. Right-sizing per-server: `Server::new(num_entries)` (since 2026-05-15)

The `num_entries` argument to `Server::new`, `Client::new`,
`Client::from_secret_key`, and `params_info` shapes that single PirParams
instance for the requested plaintext count. Pass `0` to use the compile-
time `DBConsts::DB_SIZE_MB`-derived default; pass a non-zero value to
override.

The lattice config (`PolyDegree`, `PlainMod`, `L_EP`, `L_KEY`, `L_KS`,
`TREE_HEIGHT`, `FST_DIM_POW2`, `NoiseStdDev`) stays compile-time
constexpr — only `target_num_pt` moves runtime.

### When this matters

If your deployment has a single PirServer per process, you can ignore
this — the compile-time default works fine.

If you instantiate **many servers in one process at different scales**
(multi-tenant setups, multi-group cuckoo-PIR architectures, etc.), pass
each server its own `num_entries` matching the actual data it holds.
Otherwise every server gets the largest-server shape, which costs:

- **Storage**: each server's `save_db` writes the full
  `num_pt × coeff_val_cnt × 8` bytes regardless of how much real data
  is in there. At `DB_SIZE_MB=3072` (CONFIG_N2048_K1) that's **15 GB
  per server file**. 75 servers → 1.1 TB total.
- **Per-query compute**: the first-dim matmul runs over the full
  `num_pt`-shaped matrix, not the per-server data size. For BitcoinPIR's
  shape (per-group ~10 K plaintexts vs. global 968 K) that's ~95× more
  ops per query than the per-instance shape would do.

### Example: per-group server sizing

```rust
// Each group has ~10 K bins of actual data; size the per-group server
// to fit that, not the global DB_SIZE_MB.
for group_id in 0..75 {
    let mut s = Server::new(group_bins[group_id] as u64);
    // s.params_info() now reports per-group num_pt ~10240, fst_dim
    // ~128, save_db output ~160 MB — instead of 968k / 512 / 15 GB
    // that DB_SIZE_MB=3072 would have produced.
    populate(&mut s, &group_data[group_id]);
    s.save_db(&format!("group_{}.bin", group_id));
}
```

### Client must match server

Query bytes encode the PirParams-derived `fst_dim_sz` and `num_dims`,
so a client built with `num_entries=N` cannot talk to a server built
with a different `num_entries`. Either:

- Both sides agree at construction (the typical case — the client knows
  its target group's bin count), or
- Use `Indirect DB mode` (§2.3) which keeps every server at the same
  `num_pt` while sharing a single backing store. Storage scales like
  the per-instance fix, but per-query compute does **not** — the matmul
  still runs at the full shape. Pick this only when you can't agree on
  shape at the client (rare).

### `calculate_db_shape` rounds up

The shape calculator picks a matmul-friendly `(fst_dim_sz, num_dims)`,
so `params_info(N).num_plaintexts` may exceed `N`. Treat `N` as a
floor on the bin count; read `params_info()` after construction to see
the actual shape you got.
