#pragma once
// OnionPIRv2 C-compatible FFI layer for Rust integration.
// Wraps the C++ ffi.h API with extern "C" functions using raw pointers.

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stddef.h>

// ======================== Params info ========================

typedef struct {
  uint64_t num_entries;
  uint64_t entry_size;
  uint64_t num_plaintexts;
  uint64_t fst_dim_sz;
  uint64_t other_dim_sz;
  uint64_t poly_degree;
  uint64_t coeff_val_cnt;
  double   db_size_mb;
  double   physical_size_mb;
} CPirParamsInfo;

// ======================== Opaque handles ========================

typedef void* OnionPirServerHandle;
typedef void* OnionPirClientHandle;
typedef void* OnionPirQueueHandle;

// ======================== Return buffer ========================
// Caller-owned byte buffer returned by functions that produce variable-length output.
// The caller must free it with onion_free_buf().

typedef struct {
  uint8_t *data;
  size_t   len;
} OnionBuf;

void onion_free_buf(OnionBuf buf);

// ======================== Params ========================

// Pass num_entries = 0 to use the compiled-in default.
CPirParamsInfo onion_get_params_info(uint64_t num_entries);

// ======================== Server ========================

// Pass num_entries = 0 to use the compiled-in default.
OnionPirServerHandle onion_server_new(uint64_t num_entries);
void onion_server_free(OnionPirServerHandle h);

// Returns 1 on success, 0 on failure.
int onion_server_load_db(OnionPirServerHandle h, const char *path);

// Zero-copy load of a preprocessed DB from a caller-owned byte buffer. The
// buffer must start with the standard preprocessed header and remain valid
// for the lifetime of the server. The server aliases the buffer and will NOT
// unmap or free it on destruction. Returns 1 on success, 0 on failure.
int onion_server_load_db_from_borrowed(OnionPirServerHandle h,
                                       const uint8_t *data, size_t len);

void onion_server_save_db(OnionPirServerHandle h, const char *path);

void onion_server_push_chunk(OnionPirServerHandle h,
                             const uint8_t *data, size_t data_len,
                             size_t chunk_idx);
void onion_server_preprocess(OnionPirServerHandle h);

// Attach a shared NTT-expanded database with per-instance indirection.
// shared_ntt_store: level-major layout [level * num_entries + entry_id], caller-owned.
// index_table: per-instance mapping of length index_table_len (must == num_pt), caller-owned.
void onion_server_set_shared_database(
    OnionPirServerHandle h,
    const uint64_t *shared_ntt_store,
    size_t shared_store_num_entries,
    const uint32_t *index_table,
    size_t index_table_len
);

// NTT-expand a single raw entry into dst (coeff_val_cnt uint64_t values).
// Use onion_get_params_info to determine coeff_val_cnt (= poly_degree * rns_mod_cnt).
void onion_server_ntt_expand_entry(
    OnionPirServerHandle h,
    const uint8_t *raw_entry,
    size_t raw_len,
    uint64_t *dst
);

void onion_server_set_galois_key(OnionPirServerHandle h,
                                 uint64_t client_id,
                                 const uint8_t *key, size_t key_len);
void onion_server_set_gsw_key(OnionPirServerHandle h,
                              uint64_t client_id,
                              const uint8_t *key, size_t key_len);
void onion_server_remove_client(OnionPirServerHandle h, uint64_t client_id);

OnionBuf onion_server_answer_query(OnionPirServerHandle h,
                                   uint64_t client_id,
                                   const uint8_t *query, size_t query_len);

// ======================== Shared key store ========================

typedef void* OnionKeyStoreHandle;

// Pass num_entries = 0 to use the compiled-in default.
OnionKeyStoreHandle onion_key_store_new(uint64_t num_entries);
void onion_key_store_free(OnionKeyStoreHandle h);

// Key registration (deserialize once, share across all servers)
void onion_key_store_set_galois_key(OnionKeyStoreHandle h,
                                     uint64_t client_id,
                                     const uint8_t *key, size_t key_len);
void onion_key_store_set_gsw_key(OnionKeyStoreHandle h,
                                  uint64_t client_id,
                                  const uint8_t *key, size_t key_len);

// Export expanded GSW key as flat uint64 array for caching.
// Returned buffer contains uint64_t values (cast to uint8_t*); len is in bytes.
// Caller must free with onion_free_buf().
OnionBuf onion_key_store_export_gsw(OnionKeyStoreHandle h, uint64_t client_id);

// Import pre-expanded GSW key (skip deserialization + NTT).
// data points to num_values uint64_t values.
void onion_key_store_import_gsw(OnionKeyStoreHandle h,
                                 uint64_t client_id,
                                 const uint64_t *data, size_t num_values);

// Returns 1 if both key types are loaded for the client, 0 otherwise.
int onion_key_store_has_client(OnionKeyStoreHandle h, uint64_t client_id);

void onion_key_store_remove_client(OnionKeyStoreHandle h, uint64_t client_id);

// Attach a shared key store to a server.
// The store must outlive the server. Non-owning pointer.
void onion_server_set_key_store(OnionPirServerHandle server, OnionKeyStoreHandle store);

// ======================== Query queue ========================

// Status codes matching QueryStatus enum
#define ONION_QUERY_QUEUED     0
#define ONION_QUERY_PROCESSING 1
#define ONION_QUERY_DONE       2
#define ONION_QUERY_ERROR      3
#define ONION_QUERY_NOT_FOUND  4

OnionPirQueueHandle onion_queue_new(OnionPirServerHandle server);
void onion_queue_stop(OnionPirQueueHandle h);
void onion_queue_free(OnionPirQueueHandle h);

uint64_t onion_queue_submit(OnionPirQueueHandle h,
                            uint64_t client_id,
                            const uint8_t *query, size_t query_len);
uint8_t  onion_queue_status(OnionPirQueueHandle h, uint64_t ticket);
uint64_t onion_queue_position(OnionPirQueueHandle h, uint64_t ticket);

// Returns the result. Caller must free with onion_free_buf().
// Returns {NULL, 0} if ticket is not Done.
OnionBuf onion_queue_result(OnionPirQueueHandle h, uint64_t ticket);

// ======================== Client ========================

// Pass num_entries = 0 to use the compiled-in default. Must match the server.
OnionPirClientHandle onion_client_new(uint64_t num_entries);
void onion_client_free(OnionPirClientHandle h);

// Create a client from an existing secret key (from onion_client_export_secret_key).
// Use this to create per-database clients that share the same encryption keys.
OnionPirClientHandle onion_client_new_from_sk(uint64_t num_entries,
                                               uint64_t client_id,
                                               const uint8_t *sk, size_t sk_len);

// Export the client's secret key. Caller must free with onion_free_buf().
OnionBuf onion_client_export_secret_key(OnionPirClientHandle h);

uint64_t onion_client_get_id(OnionPirClientHandle h);
OnionBuf onion_client_generate_galois_keys(OnionPirClientHandle h);
OnionBuf onion_client_generate_gsw_keys(OnionPirClientHandle h);
OnionBuf onion_client_generate_query(OnionPirClientHandle h, uint64_t entry_index);
OnionBuf onion_client_decrypt_response(OnionPirClientHandle h,
                                       uint64_t entry_index,
                                       const uint8_t *resp, size_t resp_len);

#ifdef __cplusplus
}
#endif
