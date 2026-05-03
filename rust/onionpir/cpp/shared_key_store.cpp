#include "shared_key_store.h"
#include "database_constants.h"

// ======================== Construction ========================

static size_t resolve_num_entries_ks(size_t num_entries) {
  return num_entries == 0 ? DatabaseConstants::NumEntries : num_entries;
}

SharedKeyStore::SharedKeyStore(size_t num_entries)
    : params_(resolve_num_entries_ks(num_entries)),
      context_(params_.get_seal_params()),
      key_gsw_(params_, params_.get_l_key(), params_.get_base_log2_key()) {}

// ======================== Key registration ========================

void SharedKeyStore::set_galois_key(size_t client_id, std::stringstream &stream) {
  seal::GaloisKeys key;
  key.load(context_, stream);
  auto pid = key.parms_id();
  fprintf(stderr, "[SharedKeyStore %p] set_galois_key: client=%zu, parms_id[0]=%llu, "
          "store context parms_id[0]=%llu\n",
          (void*)this, client_id,
          (unsigned long long)pid[0],
          (unsigned long long)context_.key_parms_id()[0]);
  galois_keys_[client_id] = std::move(key);
  touch(client_id);
  evict_if_full();
}

void SharedKeyStore::set_gsw_key(size_t client_id, std::stringstream &stream) {
  // Step 1: load 2×l_key SEAL ciphertexts
  std::vector<seal::Ciphertext> temp_gsw;
  const size_t count = 2 * params_.get_l_key();
  temp_gsw.reserve(count);
  for (size_t i = 0; i < count; i++) {
    seal::Ciphertext row;
    row.load(context_, stream);
    temp_gsw.push_back(std::move(row));
  }

  // Step 2: convert from SEAL ciphertext format to flat GSWCiphertext
  GSWCiphertext gsw_key;
  key_gsw_.seal_GSW_vec_to_GSW(gsw_key, temp_gsw);

  // Step 3: NTT transform
  key_gsw_.gsw_ntt_negacyclic_harvey(gsw_key);

  fprintf(stderr, "[SharedKeyStore %p] set_gsw_key: client=%zu, rows=%zu, row_size=%zu\n",
          (void*)this, client_id, gsw_key.size(),
          gsw_key.empty() ? 0 : gsw_key[0].size());
  gsw_keys_[client_id] = std::move(gsw_key);
  touch(client_id);
  evict_if_full();
}

void SharedKeyStore::import_expanded_gsw(size_t client_id, const uint64_t *data, size_t num_values) {
  const size_t rows = gsw_row_count();
  const size_t row_sz = gsw_row_size();
  if (num_values != rows * row_sz) {
    throw std::invalid_argument(
        "import_expanded_gsw: expected " + std::to_string(rows * row_sz) +
        " values, got " + std::to_string(num_values));
  }

  GSWCiphertext gsw_key(rows);
  for (size_t r = 0; r < rows; r++) {
    gsw_key[r].assign(data + r * row_sz, data + (r + 1) * row_sz);
  }

  gsw_keys_[client_id] = std::move(gsw_key);
  touch(client_id);
  evict_if_full();
}

// ======================== Key export ========================

std::vector<uint64_t> SharedKeyStore::export_expanded_gsw(size_t client_id) const {
  auto it = gsw_keys_.find(client_id);
  if (it == gsw_keys_.end()) {
    return {};
  }

  const auto &gsw = it->second;
  const size_t row_sz = gsw_row_size();
  std::vector<uint64_t> flat;
  flat.reserve(gsw.size() * row_sz);
  for (const auto &row : gsw) {
    flat.insert(flat.end(), row.begin(), row.end());
  }
  return flat;
}

// ======================== Key access ========================

const seal::GaloisKeys &SharedKeyStore::get_galois_key(size_t client_id) const {
  return galois_keys_.at(client_id);
}

const GSWCiphertext &SharedKeyStore::get_gsw_key(size_t client_id) const {
  return gsw_keys_.at(client_id);
}

bool SharedKeyStore::has_client(size_t client_id) const {
  return galois_keys_.count(client_id) > 0 && gsw_keys_.count(client_id) > 0;
}

// ======================== Lifecycle ========================

void SharedKeyStore::touch(size_t client_id) {
  auto it = lru_pos_.find(client_id);
  if (it != lru_pos_.end()) {
    lru_order_.erase(it->second);
  }
  lru_order_.push_back(client_id);
  lru_pos_[client_id] = std::prev(lru_order_.end());
}

void SharedKeyStore::evict_if_full() {
  while (lru_order_.size() > MAX_CLIENTS) {
    size_t victim = lru_order_.front();
    lru_order_.pop_front();
    lru_pos_.erase(victim);
    galois_keys_.erase(victim);
    gsw_keys_.erase(victim);
  }
}

void SharedKeyStore::remove(size_t client_id) {
  galois_keys_.erase(client_id);
  gsw_keys_.erase(client_id);
  auto it = lru_pos_.find(client_id);
  if (it != lru_pos_.end()) {
    lru_order_.erase(it->second);
    lru_pos_.erase(it);
  }
}

// ======================== Dimensions ========================

size_t SharedKeyStore::gsw_row_count() const {
  return 2 * params_.get_l_key();
}

size_t SharedKeyStore::gsw_row_size() const {
  return 2 * DatabaseConstants::PolyDegree * params_.get_rns_mod_cnt();
}
