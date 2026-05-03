#pragma once

#include "gsw_eval.h"
#include "pir.h"
#include "shared_key_store.h"
#include <optional>
#include <string>
#include <list>

// RAW_DB_FILE is only used in debug builds for direct_get_entry verification
#ifdef _DEBUG
#define RAW_DB_FILE "./rawDB.bin"
#endif

// typedef std::vector<std::optional<seal::Plaintext>> DatabaseChunk;  // 256 plaintexts
typedef std::unique_ptr<std::optional<seal::Plaintext>[]> DatabaseChunk;  // Heap allocation for N_1 plaintexts
typedef std::unique_ptr<std::optional<seal::Plaintext>[]> Database;       // One consecutive huge vector for the entire database on heap

class PirServer {
public:
  PirServer(const PirParams &pir_params);
  ~PirServer();

  /**
   * Generate random data for the server database and directly set the database.
   * It pushes the data to the database in chunks.
   */
  void gen_data();

  /**
   * Save the preprocessed (NTT + realigned) database to a binary file.
   * The file contains a header for config validation followed by the raw db_aligned_ data.
   * This allows skipping the expensive gen_data/NTT/realign pipeline on subsequent launches.
   */
  void save_db_to_file(const std::string &path) const;

  /**
   * Attach a shared NTT-expanded database with per-instance indirection.
   * Replaces push_chunk + preprocess for this instance.
   *
   * @param shared_ntt_store  Level-major shared NTT data (all entries, contiguous).
   *                          Layout: shared_ntt_store[level * shared_store_num_entries + entry_id]
   *                          Caller must ensure this memory outlives the server.
   * @param shared_store_num_entries  Number of entries in the shared store.
   * @param index_table       Per-instance mapping: index_table[logical_pos] = entry_id in shared store.
   *                          Length must equal num_pt (fst_dim_sz * other_dim_sz).
   *                          Caller must ensure this memory outlives the server.
   * @param index_table_len   Length of the index table (must == num_pt_).
   */
  void set_shared_database(
      const uint64_t* shared_ntt_store,
      size_t shared_store_num_entries,
      const uint32_t* index_table,
      size_t index_table_len
  );

  /**
   * NTT-expand a single raw entry into level-major coefficient form.
   * Used for offline preparation of the shared NTT store.
   *
   * @param raw_entry  Raw entry bytes (exactly entry_size bytes, zero-padded if shorter).
   * @param raw_len    Length of raw_entry in bytes.
   * @param dst        Output buffer for coeff_val_cnt uint64_t values.
   *                   dst[level] = NTT coefficient at level for this entry.
   */
  void ntt_expand_entry(const uint8_t* raw_entry, size_t raw_len, uint64_t* dst) const;

  /**
   * Load a preprocessed database from file via mmap (zero-copy).
   * Returns true if the file exists and config matches. Returns false otherwise
   * (caller should fall back to gen_data).
   * After a successful load, the server is ready to answer queries — no gen_data needed.
   */
  bool load_db_from_file(const std::string &path);

  /**
   * Load a preprocessed database from a caller-owned byte buffer (zero-copy).
   *
   * The buffer must start with the same header format produced by
   * save_db_to_file (4 x uint64_t: PREPROC_MAGIC, num_pt, coeff_val_cnt,
   * data_bytes) followed by data_bytes of NTT-form data. The caller retains
   * ownership of the buffer and MUST keep it valid for the lifetime of this
   * PirServer instance (typically by backing it with an mmap region owned by
   * the caller). The destructor will NOT unmap or free the buffer.
   *
   * Intended use: consolidate multiple per-group preprocessed databases into
   * one file, mmap it once in the caller, and hand a sub-slice to each
   * PirServer. This is the borrowed analogue of load_db_from_file.
   *
   * Returns true on success. Returns false if the buffer is too small or the
   * header fails validation against the current PirParams.
   */
  bool load_db_from_borrowed(const uint8_t *data, size_t len);

  // push one chunk of entry to the given database
  void push_database_chunk(std::vector<Entry> &chunk_entry, const size_t chunk_idx);

  /**
   * Run NTT preprocessing and memory realignment on the populated database.
   * Call this after all chunks have been pushed via push_database_chunk().
   * This is the expensive one-time step that prepares the DB for queries.
   */
  void preprocess_db();

  // Given the client id and a packed client query, this function first unpacks the query, then returns the retrieved encrypted result.
  seal::Ciphertext make_query(const size_t client_id, std::stringstream &query_stream);

  // return the number of bits needed to represent the server reponse
  size_t save_resp_to_stream(const seal::Ciphertext &response, std::stringstream &resp_stream);

  /**
   * @brief A clever way to evaluate the external product for second to last dimensions. 
   * 
   * @param result The BFV ciphertexts
   * @param selection_cipher A single RGSW(b) ciphertext, where b \in {0, 1}. 0 to get the first half of the result, 1 to get the second half.
   */
  void other_dim_mux(std::vector<seal::Ciphertext> &result, GSWCiphertext &selection_cipher);
  
  void set_client_galois_key(const size_t client_id, std::stringstream &gsw_stream);
  void set_client_gsw_key(const size_t client_id, std::stringstream &gsw_stream);
  void remove_client_keys(const size_t client_id);

  /// Attach a shared key store. When set, key lookups use the shared store
  /// instead of per-server maps. The store must outlive this server.
  void set_shared_key_store(SharedKeyStore *store);

#ifdef _DEBUG
  /**
  Asking the server to return the entry at the given (abstract) index.
  This is not doing PIR. So this reveals the index to the server. This is
  only for testing purposes.
  */
  Entry direct_get_entry(const size_t index) const;
#endif

  friend class PirTest;

private:
  size_t num_pt_;
  seal::SEALContext context_;
  seal::Evaluator evaluator_;
  std::vector<size_t> dims_;
  // Client key storage with LRU eviction.
  // lru_order_ stores client_ids from least-recently-used (front) to most-recently-used (back).
  // lru_pos_ maps client_id → iterator into lru_order_ for O(1) promotion.
  static constexpr size_t MAX_CLIENTS = 100;
  std::map<size_t, seal::GaloisKeys> client_galois_keys_;
  std::map<size_t, GSWCiphertext> client_gsw_keys_;
  std::list<size_t> lru_order_;
  std::map<size_t, std::list<size_t>::iterator> lru_pos_;

  void touch_client(size_t client_id);
  void evict_if_full();
  SharedKeyStore *shared_key_store_ = nullptr;  // optional shared key store
  Database db_; // pointer to the entire database vector
  std::unique_ptr<uint64_t[]> db_aligned_; // aligned database for fast first dim (owned memory)
  uint64_t *db_aligned_mmap_ = nullptr;    // mmap'd database (non-owned, munmap in destructor)
  size_t db_aligned_mmap_len_ = 0;         // total mmap length including header
  int db_aligned_mmap_fd_ = -1;            // file descriptor for mmap

  // Shared database mode (indirect access via index table)
  const uint64_t* shared_ntt_store_ = nullptr;   // non-owned: level-major shared NTT data
  size_t shared_store_num_entries_ = 0;
  const uint32_t* index_table_ = nullptr;        // non-owned: logical_pos → entry_id
  size_t index_table_len_ = 0;
  bool use_shared_db_ = false;
  std::vector<uint128_t> inter_res_; // pointer to the intermediate result vector for fst dim
  PirParams pir_params_;
  GSWEval key_gsw_;
  GSWEval data_gsw_;

  // Expands the query BFV ciphertext into a vector of BFV ciphertexts,
  // where the first DatabaseConstants::MaxFstDim many ciphertexts is the first dimension query,
  // and the rest will be used to reconstruct the RGSW ciphertexts for the other dimensions.
  std::vector<seal::Ciphertext> expand_query(size_t client_id, seal::Ciphertext &ciphertext) const;

  // we apply new techniques to avoid trivial splits on zero ciphertexts.
  // Notice that a large portion of the query is zero, and they are generated by
  // splitting some zero ciphertexts. Trivial split are the ones that split the
  // zero ciphertexts into two zero ciphertexts. However, to do this, we must
  // make sure that all the first dimension is in the same expansion sub-tree.
  // The expand query used in Cheetah is not suitable for this, though we don't
  // need special permutation for packing when using it.
  std::vector<seal::Ciphertext> fast_expand_qry(size_t client_id, seal::Ciphertext &ciphertext) const;
  
  // high level: homomorphic matrix vector multiplication between plaintext database and query ciphertext
  // input selection_vector should stay in coefficient form.
  // output will be in coefficient form.
  std::vector<seal::Ciphertext> evaluate_first_dim(std::vector<seal::Ciphertext> &selection_vector);

  // This is a helper for evaluate the first dimension. 
  // Instead of doing a mod operation after every addition and multiplication during the matrix multiplication,
  // we delay the mod operation until the end. We also use barret reduction for the mod operation.
  void delay_modulus(std::vector<seal::Ciphertext> &result, const uint128_t *__restrict inter_res);
  
  // This is a helper for evaluate the first dimension when other_dim_sz < 16.
  // It processes ciphertexts individually without unrolling.
  void delay_modulus_small(std::vector<seal::Ciphertext> &result, const uint128_t *__restrict inter_res);
  
  // Transforms the plaintexts in the database into their NTT representation.
  // This speeds up computation but takes up more memory.  
  void preprocess_ntt();
  // Realign the database so that the first dimension calculation is in a contiguous memory.
  void realign_db();

  // Fill the intermediate_db_ with some ciphertext. We just need to allocate the memory.
  void fill_inter_res();

  // Returns the active db_aligned pointer (mmap'd or heap-allocated).
  inline uint64_t *get_db_ptr() const {
    return db_aligned_mmap_ ? db_aligned_mmap_ : db_aligned_.get();
  }

#ifdef _DEBUG
  // write one chunk of the database to a binary file for direct_get_entry verification
  void write_one_chunk(std::vector<Entry> &chunk);
#endif

  void prep_query(const std::vector<seal::Ciphertext> &fst_dim_query, std::vector<uint64_t>& query_data);

  // customized modulus switch for single mod seal::Ciphertext. (Not RNS modulus)
  // The goal is to halve the size of the ciphertext.
  void mod_switch_inplace(seal::Ciphertext &ciphertext, const uint64_t small_q);

};
