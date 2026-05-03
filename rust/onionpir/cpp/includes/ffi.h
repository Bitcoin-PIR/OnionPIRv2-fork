#pragma once
// OnionPIRv2 FFI — C++ side of the cxx bridge.
//
// All data crossing the boundary is byte-serialized (Vec<u8> / &[u8]).
// SEAL objects never cross the FFI boundary.
//
// The Rust side will define a #[cxx::bridge] that references this header.

#include <cstdint>
#include <cstddef>
#include <memory>
#include <string>
#include <vector>

// ======================== Params info ========================
// A plain struct (shared with Rust via cxx) describing the compiled-in
// database configuration. Rust reads this to know entry sizes, counts, etc.
struct PirParamsInfo {
  uint64_t num_entries;
  uint64_t entry_size;        // bytes per entry
  uint64_t num_plaintexts;
  uint64_t fst_dim_sz;
  uint64_t other_dim_sz;
  uint64_t poly_degree;
  uint64_t coeff_val_cnt;     // poly_degree * rns_mod_cnt (uint64s per NTT plaintext)
  double   db_size_mb;        // logical DB size
  double   physical_size_mb;  // NTT-expanded storage
};

// ======================== Opaque wrapper types ========================
// These are the C++ objects that Rust holds via UniquePtr<T>.

class OnionPirServer;
class OnionPirClient;

// ======================== Free functions ========================

/// Return PIR parameters for a given entry count.
/// If num_entries == 0, uses the compiled-in default.
PirParamsInfo get_pir_params_info(uint64_t num_entries = 0);

// -------- Server --------

/// Create a new PIR server with the given number of database entries.
/// If num_entries == 0, uses the compiled-in default.
std::unique_ptr<OnionPirServer> new_server(uint64_t num_entries = 0);

/// Try to load a preprocessed (NTT + realigned) database via mmap.
/// Returns true on success. On false, caller should populate + preprocess.
bool server_load_db(OnionPirServer &server, const std::string &path);

/// Try to load a preprocessed database from a caller-owned byte buffer.
/// The buffer must start with the standard preprocessed header and remain
/// valid for the lifetime of the server. Zero-copy: the server aliases the
/// buffer and will NOT unmap or free it on destruction. Useful for loading
/// multiple groups from slices of one mmap'd file.
bool server_load_db_from_borrowed(OnionPirServer &server,
                                  const uint8_t *data, size_t len);

/// Save the current preprocessed database to disk.
void server_save_db(const OnionPirServer &server, const std::string &path);

/// Push one chunk of raw entries into the database.
/// `chunk_data` is a flat byte buffer: fst_dim_sz entries concatenated,
/// each exactly entry_size bytes (pad with zeros if shorter).
/// `chunk_idx` is the row index (0 .. other_dim_sz-1).
void server_push_chunk(OnionPirServer &server,
                       const std::vector<uint8_t> &chunk_data,
                       size_t chunk_idx);

/// Run NTT preprocessing + realignment after all chunks are pushed.
/// This is the expensive one-time step.
void server_preprocess(OnionPirServer &server);

/// Attach a shared NTT-expanded database with per-instance indirection.
/// Replaces push_chunk + preprocess for this instance.
/// shared_ntt_store: level-major layout [level * num_entries + entry_id].
/// index_table: per-instance mapping, length = padded num_entries (num_pt).
/// Both pointers must outlive the server.
void server_set_shared_database(
    OnionPirServer &server,
    const uint64_t *shared_ntt_store,
    size_t shared_store_num_entries,
    const uint32_t *index_table,
    size_t index_table_len
);

/// NTT-expand a single raw entry into coeff_val_cnt uint64_t values.
/// Used for offline preparation of the shared NTT store.
/// dst must have space for coeff_val_cnt uint64_t values.
void server_ntt_expand_entry(
    const OnionPirServer &server,
    const uint8_t *raw_entry,
    size_t raw_len,
    uint64_t *dst
);

/// Register a client's Galois keys (serialized bytes from client_generate_galois_keys).
void server_set_galois_key(OnionPirServer &server,
                           uint64_t client_id,
                           const std::vector<uint8_t> &key_bytes);

/// Register a client's GSW keys (serialized bytes from client_generate_gsw_keys).
void server_set_gsw_key(OnionPirServer &server,
                        uint64_t client_id,
                        const std::vector<uint8_t> &key_bytes);

/// Manually remove a client's cached keys.
void server_remove_client(OnionPirServer &server, uint64_t client_id);

/// Answer a PIR query synchronously. Returns the serialized response bytes.
std::vector<uint8_t> server_answer_query(OnionPirServer &server,
                                         uint64_t client_id,
                                         const std::vector<uint8_t> &query_bytes);

// -------- Async query queue --------
// Queries are serialized through a single worker thread.
// Submit returns a ticket; poll with query_status / collect with query_result.

class OnionPirQueryQueue;

/// Create a query queue backed by a worker thread.  Holds a reference to the server.
std::unique_ptr<OnionPirQueryQueue> new_query_queue(OnionPirServer &server);

/// Stop the queue and join its worker thread.
void query_queue_stop(OnionPirQueryQueue &queue);

/// Submit a query. Returns a ticket ID immediately.
uint64_t query_queue_submit(OnionPirQueryQueue &queue,
                            uint64_t client_id,
                            const std::vector<uint8_t> &query_bytes);

/// Status of a queued query.
enum class QueryStatus : uint8_t {
  Queued     = 0,   // waiting in line
  Processing = 1,   // currently being answered
  Done       = 2,   // result ready
  Error      = 3,   // query failed
  NotFound   = 4,   // unknown ticket
};

/// Check the status of a ticket.
QueryStatus query_queue_status(const OnionPirQueryQueue &queue, uint64_t ticket);

/// How many queries are ahead of this ticket (0 when Processing/Done/Error).
uint64_t query_queue_position(const OnionPirQueryQueue &queue, uint64_t ticket);

/// Retrieve the result for a completed ticket. Removes it from the queue.
/// Throws if the ticket is not Done.
std::vector<uint8_t> query_queue_result(OnionPirQueryQueue &queue, uint64_t ticket);

// -------- Shared key store --------

/// Create a shared key store. All PirServers that share the same SEAL
/// parameters can reference one store, avoiding per-server deserialization.
/// If num_entries == 0, uses the compiled-in default.
std::unique_ptr<SharedKeyStore> new_key_store(uint64_t num_entries = 0);

/// Deserialize and store a client's Galois key.
void key_store_set_galois_key(SharedKeyStore &store,
                               uint64_t client_id,
                               const std::vector<uint8_t> &key_bytes);

/// Deserialize, convert, and NTT-transform a client's GSW key.
void key_store_set_gsw_key(SharedKeyStore &store,
                            uint64_t client_id,
                            const std::vector<uint8_t> &key_bytes);

/// Export the expanded (NTT-transformed) GSW key as a flat uint64 array.
std::vector<uint64_t> key_store_export_gsw(const SharedKeyStore &store,
                                            uint64_t client_id);

/// Import a pre-expanded GSW key from a flat uint64 array (skip processing).
void key_store_import_gsw(SharedKeyStore &store,
                           uint64_t client_id,
                           const uint64_t *data,
                           size_t num_values);

/// Check if both key types are loaded for a client.
bool key_store_has_client(const SharedKeyStore &store, uint64_t client_id);

/// Remove a client's keys.
void key_store_remove_client(SharedKeyStore &store, uint64_t client_id);

/// Attach a shared key store to a server (non-owning — store must outlive server).
void server_set_key_store(OnionPirServer &server, SharedKeyStore &store);

// -------- Client --------

/// Create a new PIR client. num_entries must match the server's value.
/// If num_entries == 0, uses the compiled-in default.
std::unique_ptr<OnionPirClient> new_client(uint64_t num_entries = 0);

/// Create a PIR client from an existing secret key.
/// The secret key bytes come from client_export_secret_key.
/// Key generation (galois/GSW) is independent of num_entries, so generate
/// keys with any client, export the secret key, then create per-database
/// clients with the correct num_entries for query/decrypt.
std::unique_ptr<OnionPirClient> new_client_from_secret_key(
    uint64_t num_entries,
    uint64_t client_id,
    const std::vector<uint8_t> &secret_key_bytes);

/// Export the client's secret key as serialized bytes.
std::vector<uint8_t> client_export_secret_key(const OnionPirClient &client);

/// Get the client's unique ID (used as client_id for server key registration).
uint64_t client_get_id(const OnionPirClient &client);

/// Generate the Galois keys to send to the server.
std::vector<uint8_t> client_generate_galois_keys(OnionPirClient &client);

/// Generate the GSW keys to send to the server.
std::vector<uint8_t> client_generate_gsw_keys(OnionPirClient &client);

/// Generate a PIR query for the given entry index.
std::vector<uint8_t> client_generate_query(OnionPirClient &client, uint64_t entry_index);

/// Decrypt the server's response and extract the requested entry bytes.
std::vector<uint8_t> client_decrypt_response(OnionPirClient &client,
                                             uint64_t entry_index,
                                             const std::vector<uint8_t> &response_bytes);
