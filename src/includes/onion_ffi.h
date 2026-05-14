// OnionPIRv2 C-ABI for Rust / Java / native consumers.
//
// Minimum-viable surface tied to the upstream BV-keyswitch flow (see
// src/tests/test_pir.cpp for the reference end-to-end transcript). The fork's
// previous extra features (load_db_from_borrowed, SharedKeyStore, async
// QueryQueue, indirect-database mode) are not included here — they will be
// re-introduced in a later phase.
//
// All variable-length return values are passed back via OnionBuf and must be
// freed by the caller with onion_free_buf().
//
// Threading: server / client handles are NOT thread-safe; callers must
// serialize access to a given handle.

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stddef.h>

// ============================================================================
//   Owned byte buffer returned from variable-length producers
// ============================================================================

typedef struct {
    uint8_t *data;
    size_t   len;
} OnionBuf;

// Frees the buffer; pass-by-value matches how it was returned. No-op on NULL.
void onion_free_buf(OnionBuf buf);

// ============================================================================
//   Database / parameter shape
// ============================================================================

typedef struct {
    uint64_t num_entries;        // padded entry count (>= requested)
    uint64_t entry_size;         // bytes per entry
    uint64_t num_plaintexts;     // total plaintexts (== fst_dim_sz * other_dim_sz)
    uint64_t fst_dim_sz;
    uint64_t other_dim_sz;
    uint64_t poly_degree;        // N (e.g. 4096 in the secure config)
    uint64_t rns_mod_count;      // K (1 for single-mod, 2 for K2_MP)
    uint64_t coeff_val_cnt;      // poly_degree * rns_mod_count
    double   db_size_mb;
    double   physical_size_mb;
} OnionPirParamsInfo;

// num_entries=0 → use the compiled-in default from DBConsts.
OnionPirParamsInfo onion_params_info(uint64_t num_entries);

// ============================================================================
//   Opaque handles
// ============================================================================

typedef void *OnionServerHandle;
typedef void *OnionClientHandle;

// ============================================================================
//   Client
// ============================================================================
//
// Lifecycle: each client owns its own secret key, GSW key, and BV galois keys
// (generated lazily on first call). To pair a client with a server, ship the
// galois-keys and gsw-key blobs to the server side via onion_server_set_*.

OnionClientHandle onion_client_new(uint64_t num_entries);
void              onion_client_free(OnionClientHandle h);
uint64_t          onion_client_id(OnionClientHandle h);

// Serialized BV galois keys for this client. Caller frees.
OnionBuf onion_client_galois_keys(OnionClientHandle h);

// Serialized GSW(s) key for this client. Caller frees.
OnionBuf onion_client_gsw_key(OnionClientHandle h);

// Serialized query for plaintext index pt_idx. Caller frees.
// pt_idx must be in [0, params.num_plaintexts).
OnionBuf onion_client_generate_query(OnionClientHandle h, uint64_t pt_idx);

// Decrypts a server response (bit-packed bytes as produced by
// onion_server_answer_query). Returns the N-coefficient plaintext as a flat
// uint64 array (each coefficient < t), serialized as
// `[u32 N][u64 coeff_0]…[u64 coeff_{N-1}]`. Caller frees.
OnionBuf onion_client_decrypt_response(OnionClientHandle h,
                                       const uint8_t *response,
                                       size_t response_len);

// ============================================================================
//   Server
// ============================================================================

OnionServerHandle onion_server_new(uint64_t num_entries);
void              onion_server_free(OnionServerHandle h);

// Populate the database with random data. If record_indices is non-null and
// num_indices > 0, only those plaintext indices are retained for
// onion_server_get_original_plaintext (test convenience to avoid keeping the
// full pre-NTT DB in memory).
void onion_server_gen_data(OnionServerHandle h,
                           const uint64_t *record_indices,
                           size_t num_indices);

// Returns the pre-NTT plaintext at pt_idx as `[u32 N][u64 coeff_0]…`.
// Only valid for indices that were passed to onion_server_gen_data.
// Caller frees.
OnionBuf onion_server_get_original_plaintext(OnionServerHandle h,
                                             uint64_t pt_idx);

// Register a client's keys. The keys are deserialized once and held until the
// client is removed.
void onion_server_set_galois_keys(OnionServerHandle h, uint64_t client_id,
                                  const uint8_t *data, size_t len);
void onion_server_set_gsw_key(OnionServerHandle h, uint64_t client_id,
                              const uint8_t *data, size_t len);

// Run the full PIR query and return the bit-packed response. Caller frees.
OnionBuf onion_server_answer_query(OnionServerHandle h, uint64_t client_id,
                                   const uint8_t *query, size_t query_len);

#ifdef __cplusplus
}  // extern "C"
#endif
