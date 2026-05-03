#pragma once

#include "gsw_eval.h"
#include "pir.h"
#include <list>
#include <map>
#include <sstream>

/// Centralized key store shared across all PirServer instances.
///
/// Deserializes client keys once and makes them available to every server
/// via a non-owning pointer. This avoids the N× deserialization overhead
/// when N servers share the same SEAL parameters (which is always the case
/// since parameters are compile-time constants in database_constants.h).
///
/// Thread safety: the store itself is NOT thread-safe. Callers must ensure
/// that key registration / removal does not race with query processing.
/// Read-only access from multiple threads (e.g. via fast_expand_qry) is safe
/// as long as no concurrent mutation occurs.
class SharedKeyStore {
public:
  /// Create a key store. `num_entries` only affects PirParams dimensioning
  /// (not SEAL parameters), so any valid value works. Pass 0 for the default.
  explicit SharedKeyStore(size_t num_entries = 0);

  // ======================== Key registration ========================

  /// Deserialize a Galois key from a SEAL binary stream.
  void set_galois_key(size_t client_id, std::stringstream &stream);

  /// Deserialize a GSW key: load 2×l_key ciphertexts, convert format, NTT.
  void set_gsw_key(size_t client_id, std::stringstream &stream);

  /// Import a pre-expanded GSW key from a flat uint64 array.
  /// Skips deserialization + NTT — use for restoring from Rust-side cache.
  /// `num_values` must equal gsw_row_count() * gsw_row_size().
  void import_expanded_gsw(size_t client_id, const uint64_t *data, size_t num_values);

  // ======================== Key export ========================

  /// Export the expanded GSW key as a flat uint64 array for Rust-side caching.
  /// Returns an empty vector if the client has no GSW key loaded.
  std::vector<uint64_t> export_expanded_gsw(size_t client_id) const;

  // ======================== Key access ========================

  /// Get the Galois key for a client. Throws if not found.
  const seal::GaloisKeys &get_galois_key(size_t client_id) const;

  /// Get the GSW key for a client. Throws if not found.
  const GSWCiphertext &get_gsw_key(size_t client_id) const;

  /// Check whether both key types are loaded for a client.
  bool has_client(size_t client_id) const;

  // ======================== Lifecycle ========================

  /// Promote a client to most-recently-used.
  void touch(size_t client_id);

  /// Remove a client's keys and LRU entry.
  void remove(size_t client_id);

  // ======================== Dimensions (for export/import) ========================

  /// Number of rows in a GSW key: 2 * l_key.
  size_t gsw_row_count() const;

  /// Number of uint64 values per row: 2 * PolyDegree * rns_mod_cnt.
  size_t gsw_row_size() const;

private:
  PirParams params_;
  seal::SEALContext context_;
  GSWEval key_gsw_;

  static constexpr size_t MAX_CLIENTS = 100;
  std::map<size_t, seal::GaloisKeys> galois_keys_;
  std::map<size_t, GSWCiphertext> gsw_keys_;
  std::list<size_t> lru_order_;
  std::map<size_t, std::list<size_t>::iterator> lru_pos_;

  void evict_if_full();
};
