// OnionPIRv2 C-compatible FFI — wraps ffi.h for Rust / C consumers.

#include "ffi_c.h"
#include "ffi_internal.h"

#include <new>

// ======================== Helpers ========================

static OnionBuf vec_to_buf(std::vector<uint8_t> &&v) {
  OnionBuf buf;
  buf.len = v.size();
  if (buf.len == 0) {
    buf.data = nullptr;
    return buf;
  }
  buf.data = static_cast<uint8_t *>(std::malloc(buf.len));
  std::memcpy(buf.data, v.data(), buf.len);
  return buf;
}

static std::vector<uint8_t> ptr_to_vec(const uint8_t *data, size_t len) {
  return std::vector<uint8_t>(data, data + len);
}

// ======================== Buffer management ========================

extern "C" void onion_free_buf(OnionBuf buf) {
  std::free(buf.data);
}

// ======================== Params ========================

extern "C" CPirParamsInfo onion_get_params_info(uint64_t num_entries) {
  PirParamsInfo info = get_pir_params_info(num_entries);
  CPirParamsInfo c;
  c.num_entries    = info.num_entries;
  c.entry_size     = info.entry_size;
  c.num_plaintexts = info.num_plaintexts;
  c.fst_dim_sz     = info.fst_dim_sz;
  c.other_dim_sz   = info.other_dim_sz;
  c.poly_degree    = info.poly_degree;
  c.coeff_val_cnt  = info.coeff_val_cnt;
  c.db_size_mb     = info.db_size_mb;
  c.physical_size_mb = info.physical_size_mb;
  return c;
}

// ======================== Server ========================

extern "C" OnionPirServerHandle onion_server_new(uint64_t num_entries) {
  auto ptr = new_server(num_entries);
  return ptr.release();  // caller owns
}

extern "C" void onion_server_free(OnionPirServerHandle h) {
  delete static_cast<OnionPirServer *>(h);
}

extern "C" int onion_server_load_db(OnionPirServerHandle h, const char *path) {
  auto &srv = *static_cast<OnionPirServer *>(h);
  return server_load_db(srv, std::string(path)) ? 1 : 0;
}

extern "C" int onion_server_load_db_from_borrowed(OnionPirServerHandle h,
                                                  const uint8_t *data,
                                                  size_t len) {
  auto &srv = *static_cast<OnionPirServer *>(h);
  return server_load_db_from_borrowed(srv, data, len) ? 1 : 0;
}

extern "C" void onion_server_save_db(OnionPirServerHandle h, const char *path) {
  auto &srv = *static_cast<OnionPirServer *>(h);
  server_save_db(srv, std::string(path));
}

extern "C" void onion_server_push_chunk(OnionPirServerHandle h,
                                        const uint8_t *data, size_t data_len,
                                        size_t chunk_idx) {
  auto &srv = *static_cast<OnionPirServer *>(h);
  auto v = ptr_to_vec(data, data_len);
  server_push_chunk(srv, v, chunk_idx);
}

extern "C" void onion_server_preprocess(OnionPirServerHandle h) {
  auto &srv = *static_cast<OnionPirServer *>(h);
  server_preprocess(srv);
}

extern "C" void onion_server_set_shared_database(
    OnionPirServerHandle h,
    const uint64_t *shared_ntt_store,
    size_t shared_store_num_entries,
    const uint32_t *index_table,
    size_t index_table_len) {
  auto &srv = *static_cast<OnionPirServer *>(h);
  server_set_shared_database(srv, shared_ntt_store, shared_store_num_entries,
                             index_table, index_table_len);
}

extern "C" void onion_server_ntt_expand_entry(
    OnionPirServerHandle h,
    const uint8_t *raw_entry,
    size_t raw_len,
    uint64_t *dst) {
  auto &srv = *static_cast<OnionPirServer *>(h);
  server_ntt_expand_entry(srv, raw_entry, raw_len, dst);
}

extern "C" void onion_server_set_galois_key(OnionPirServerHandle h,
                                            uint64_t client_id,
                                            const uint8_t *key, size_t key_len) {
  auto &srv = *static_cast<OnionPirServer *>(h);
  auto v = ptr_to_vec(key, key_len);
  server_set_galois_key(srv, client_id, v);
}

extern "C" void onion_server_set_gsw_key(OnionPirServerHandle h,
                                         uint64_t client_id,
                                         const uint8_t *key, size_t key_len) {
  auto &srv = *static_cast<OnionPirServer *>(h);
  auto v = ptr_to_vec(key, key_len);
  server_set_gsw_key(srv, client_id, v);
}

extern "C" void onion_server_remove_client(OnionPirServerHandle h, uint64_t client_id) {
  auto &srv = *static_cast<OnionPirServer *>(h);
  server_remove_client(srv, client_id);
}

extern "C" OnionBuf onion_server_answer_query(OnionPirServerHandle h,
                                              uint64_t client_id,
                                              const uint8_t *query, size_t query_len) {
  auto &srv = *static_cast<OnionPirServer *>(h);
  auto v = ptr_to_vec(query, query_len);
  auto result = server_answer_query(srv, client_id, v);
  return vec_to_buf(std::move(result));
}

// ======================== Shared key store ========================

extern "C" OnionKeyStoreHandle onion_key_store_new(uint64_t num_entries) {
  auto ptr = new_key_store(num_entries);
  return ptr.release();
}

extern "C" void onion_key_store_free(OnionKeyStoreHandle h) {
  delete static_cast<SharedKeyStore *>(h);
}

extern "C" void onion_key_store_set_galois_key(OnionKeyStoreHandle h,
                                                uint64_t client_id,
                                                const uint8_t *key, size_t key_len) {
  auto &store = *static_cast<SharedKeyStore *>(h);
  auto v = ptr_to_vec(key, key_len);
  key_store_set_galois_key(store, client_id, v);
}

extern "C" void onion_key_store_set_gsw_key(OnionKeyStoreHandle h,
                                             uint64_t client_id,
                                             const uint8_t *key, size_t key_len) {
  auto &store = *static_cast<SharedKeyStore *>(h);
  auto v = ptr_to_vec(key, key_len);
  key_store_set_gsw_key(store, client_id, v);
}

extern "C" OnionBuf onion_key_store_export_gsw(OnionKeyStoreHandle h, uint64_t client_id) {
  auto &store = *static_cast<SharedKeyStore *>(h);
  auto flat = key_store_export_gsw(store, client_id);
  OnionBuf buf;
  buf.len = flat.size() * sizeof(uint64_t);
  if (buf.len == 0) {
    buf.data = nullptr;
    return buf;
  }
  buf.data = static_cast<uint8_t *>(std::malloc(buf.len));
  std::memcpy(buf.data, flat.data(), buf.len);
  return buf;
}

extern "C" void onion_key_store_import_gsw(OnionKeyStoreHandle h,
                                            uint64_t client_id,
                                            const uint64_t *data, size_t num_values) {
  auto &store = *static_cast<SharedKeyStore *>(h);
  key_store_import_gsw(store, client_id, data, num_values);
}

extern "C" int onion_key_store_has_client(OnionKeyStoreHandle h, uint64_t client_id) {
  auto &store = *static_cast<SharedKeyStore *>(h);
  return key_store_has_client(store, client_id) ? 1 : 0;
}

extern "C" void onion_key_store_remove_client(OnionKeyStoreHandle h, uint64_t client_id) {
  auto &store = *static_cast<SharedKeyStore *>(h);
  key_store_remove_client(store, client_id);
}

extern "C" void onion_server_set_key_store(OnionPirServerHandle server, OnionKeyStoreHandle store) {
  auto &srv = *static_cast<OnionPirServer *>(server);
  auto &ks = *static_cast<SharedKeyStore *>(store);
  server_set_key_store(srv, ks);
}

// ======================== Query queue ========================

extern "C" OnionPirQueueHandle onion_queue_new(OnionPirServerHandle server) {
  auto &srv = *static_cast<OnionPirServer *>(server);
  auto ptr = new_query_queue(srv);
  return ptr.release();
}

extern "C" void onion_queue_stop(OnionPirQueueHandle h) {
  auto &q = *static_cast<OnionPirQueryQueue *>(h);
  query_queue_stop(q);
}

extern "C" void onion_queue_free(OnionPirQueueHandle h) {
  delete static_cast<OnionPirQueryQueue *>(h);
}

extern "C" uint64_t onion_queue_submit(OnionPirQueueHandle h,
                                       uint64_t client_id,
                                       const uint8_t *query, size_t query_len) {
  auto &q = *static_cast<OnionPirQueryQueue *>(h);
  auto v = ptr_to_vec(query, query_len);
  return query_queue_submit(q, client_id, v);
}

extern "C" uint8_t onion_queue_status(OnionPirQueueHandle h, uint64_t ticket) {
  auto &q = *static_cast<OnionPirQueryQueue *>(h);
  return static_cast<uint8_t>(query_queue_status(q, ticket));
}

extern "C" uint64_t onion_queue_position(OnionPirQueueHandle h, uint64_t ticket) {
  auto &q = *static_cast<OnionPirQueryQueue *>(h);
  return query_queue_position(q, ticket);
}

extern "C" OnionBuf onion_queue_result(OnionPirQueueHandle h, uint64_t ticket) {
  auto &q = *static_cast<OnionPirQueryQueue *>(h);
  try {
    auto result = query_queue_result(q, ticket);
    return vec_to_buf(std::move(result));
  } catch (...) {
    return {nullptr, 0};
  }
}

// ======================== Client ========================

extern "C" OnionPirClientHandle onion_client_new(uint64_t num_entries) {
  auto ptr = new_client(num_entries);
  return ptr.release();
}

extern "C" void onion_client_free(OnionPirClientHandle h) {
  delete static_cast<OnionPirClient *>(h);
}

extern "C" OnionPirClientHandle onion_client_new_from_sk(uint64_t num_entries,
                                                          uint64_t client_id,
                                                          const uint8_t *sk, size_t sk_len) {
  auto v = ptr_to_vec(sk, sk_len);
  auto ptr = new_client_from_secret_key(num_entries, client_id, v);
  return ptr.release();
}

extern "C" OnionBuf onion_client_export_secret_key(OnionPirClientHandle h) {
  auto &c = *static_cast<OnionPirClient *>(h);
  auto result = client_export_secret_key(c);
  return vec_to_buf(std::move(result));
}

extern "C" uint64_t onion_client_get_id(OnionPirClientHandle h) {
  auto &c = *static_cast<OnionPirClient *>(h);
  return client_get_id(c);
}

extern "C" OnionBuf onion_client_generate_galois_keys(OnionPirClientHandle h) {
  auto &c = *static_cast<OnionPirClient *>(h);
  auto result = client_generate_galois_keys(c);
  return vec_to_buf(std::move(result));
}

extern "C" OnionBuf onion_client_generate_gsw_keys(OnionPirClientHandle h) {
  auto &c = *static_cast<OnionPirClient *>(h);
  auto result = client_generate_gsw_keys(c);
  return vec_to_buf(std::move(result));
}

extern "C" OnionBuf onion_client_generate_query(OnionPirClientHandle h, uint64_t entry_index) {
  auto &c = *static_cast<OnionPirClient *>(h);
  auto result = client_generate_query(c, entry_index);
  return vec_to_buf(std::move(result));
}

extern "C" OnionBuf onion_client_decrypt_response(OnionPirClientHandle h,
                                                  uint64_t entry_index,
                                                  const uint8_t *resp, size_t resp_len) {
  auto &c = *static_cast<OnionPirClient *>(h);
  auto v = ptr_to_vec(resp, resp_len);
  auto result = client_decrypt_response(c, entry_index, v);
  return vec_to_buf(std::move(result));
}
