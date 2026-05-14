// OnionPIRv2 C-ABI implementation. See src/includes/onion_ffi.h for contracts.
//
// Wire format
// -----------
// All multi-byte integers are little-endian (matches every target arch we
// build for: x86_64, AArch64, WASM). Serialization formats:
//
//   RlweCt (query):
//     [u32 ntt_form_flag][u32 poly_size_words]
//     [u64 c0[poly_size_words]][u64 c1[poly_size_words]]
//     where poly_size_words == N * K.
//
//   BvGaloisKeys (galois keys blob):
//     [u32 num_keys]
//     for each key:
//       [u32 galois_k][u32 num_cts][u32 poly_size_words]
//       for each ct: [u64 a[…]][u64 b[…]]
//
//   GSWCt (gsw_key blob):
//     [u32 num_rows][u32 row_size_words]
//     for each row: [u64 row[row_size_words]]
//
//   Plaintext (RlwePt blob returned to client):
//     [u32 N][u64 coeff_i for i in 0..N]
//
//   Server response: upstream's existing bit-packed stream
//     (PirServer::save_resp_to_stream / PirClient::load_resp_from_stream).

#include "onion_ffi.h"

#include "pir.h"
#include "client.h"
#include "server.h"
#include "bv_keyswitch.h"
#include "gsw.h"
#include "rlwe.h"
#include "database_constants.h"

#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

// ============================================================================
//   Buffer helpers
// ============================================================================

namespace {

OnionBuf make_buf(size_t len) {
    OnionBuf b{nullptr, 0};
    if (len == 0) return b;
    b.data = static_cast<uint8_t *>(std::malloc(len));
    if (!b.data) return OnionBuf{nullptr, 0};
    b.len = len;
    return b;
}

OnionBuf vec_to_buf(const std::vector<uint8_t> &v) {
    OnionBuf b = make_buf(v.size());
    if (b.data && b.len) std::memcpy(b.data, v.data(), b.len);
    return b;
}

// Tiny LE serializer
struct Writer {
    std::vector<uint8_t> &out;
    explicit Writer(std::vector<uint8_t> &dst) : out(dst) {}
    void u32(uint32_t v) {
        out.push_back(static_cast<uint8_t>(v & 0xff));
        out.push_back(static_cast<uint8_t>((v >> 8) & 0xff));
        out.push_back(static_cast<uint8_t>((v >> 16) & 0xff));
        out.push_back(static_cast<uint8_t>((v >> 24) & 0xff));
    }
    void u64_array(const uint64_t *data, size_t n) {
        const size_t bytes = n * sizeof(uint64_t);
        const size_t base = out.size();
        out.resize(base + bytes);
        std::memcpy(out.data() + base, data, bytes);
    }
};

struct Reader {
    const uint8_t *p;
    const uint8_t *end;
    Reader(const uint8_t *data, size_t len) : p(data), end(data + len) {}
    bool has(size_t n) const { return static_cast<size_t>(end - p) >= n; }
    uint32_t u32() {
        if (!has(4)) throw std::runtime_error("ffi: short read (u32)");
        uint32_t v = static_cast<uint32_t>(p[0]) |
                     (static_cast<uint32_t>(p[1]) << 8) |
                     (static_cast<uint32_t>(p[2]) << 16) |
                     (static_cast<uint32_t>(p[3]) << 24);
        p += 4;
        return v;
    }
    void u64_array(uint64_t *dst, size_t n) {
        const size_t bytes = n * sizeof(uint64_t);
        if (!has(bytes)) throw std::runtime_error("ffi: short read (u64 array)");
        std::memcpy(dst, p, bytes);
        p += bytes;
    }
};

// ============================================================================
//   (De)serialization
// ============================================================================

void serialize_rlwe_ct(const RlweCt &ct, std::vector<uint8_t> &out) {
    Writer w(out);
    w.u32(ct.ntt_form ? 1u : 0u);
    const uint32_t poly = static_cast<uint32_t>(ct.c0.size());
    w.u32(poly);
    w.u64_array(ct.c0.data(), poly);
    w.u64_array(ct.c1.data(), poly);
}

RlweCt deserialize_rlwe_ct(const uint8_t *data, size_t len) {
    Reader r(data, len);
    const uint32_t ntt = r.u32();
    const uint32_t poly = r.u32();
    RlweCt ct;
    ct.ntt_form = (ntt != 0);
    ct.c0.assign(poly, 0);
    ct.c1.assign(poly, 0);
    r.u64_array(ct.c0.data(), poly);
    r.u64_array(ct.c1.data(), poly);
    return ct;
}

void serialize_bv_galois_keys(const bvks::BvGaloisKeys &keys,
                              std::vector<uint8_t> &out) {
    Writer w(out);
    w.u32(static_cast<uint32_t>(keys.keys.size()));
    for (const auto &k : keys.keys) {
        w.u32(k.galois_k);
        w.u32(static_cast<uint32_t>(k.cts.size()));
        const uint32_t poly = k.cts.empty() ? 0u
                              : static_cast<uint32_t>(k.cts.front().a.size());
        w.u32(poly);
        for (const auto &ct : k.cts) {
            w.u64_array(ct.a.data(), poly);
            w.u64_array(ct.b.data(), poly);
        }
    }
}

bvks::BvGaloisKeys deserialize_bv_galois_keys(const uint8_t *data, size_t len) {
    Reader r(data, len);
    const uint32_t num_keys = r.u32();
    bvks::BvGaloisKeys keys;
    keys.keys.reserve(num_keys);
    for (uint32_t i = 0; i < num_keys; i++) {
        bvks::BvKeySwitchKey ksk;
        ksk.galois_k = r.u32();
        const uint32_t num_cts = r.u32();
        const uint32_t poly = r.u32();
        ksk.cts.resize(num_cts);
        for (uint32_t j = 0; j < num_cts; j++) {
            ksk.cts[j].a.assign(poly, 0);
            ksk.cts[j].b.assign(poly, 0);
            r.u64_array(ksk.cts[j].a.data(), poly);
            r.u64_array(ksk.cts[j].b.data(), poly);
        }
        keys.keys.push_back(std::move(ksk));
    }
    return keys;
}

void serialize_gsw_ct(const GSWCt &gsw, std::vector<uint8_t> &out) {
    Writer w(out);
    w.u32(static_cast<uint32_t>(gsw.size()));
    const uint32_t row_size = gsw.empty()
                              ? 0u
                              : static_cast<uint32_t>(gsw.front().size());
    w.u32(row_size);
    for (const auto &row : gsw) {
        w.u64_array(row.data(), row_size);
    }
}

GSWCt deserialize_gsw_ct(const uint8_t *data, size_t len) {
    Reader r(data, len);
    const uint32_t num_rows = r.u32();
    const uint32_t row_size = r.u32();
    GSWCt gsw(num_rows);
    for (uint32_t i = 0; i < num_rows; i++) {
        gsw[i].assign(row_size, 0);
        r.u64_array(gsw[i].data(), row_size);
    }
    return gsw;
}

void serialize_plaintext(const RlwePt &pt, std::vector<uint8_t> &out) {
    Writer w(out);
    w.u32(static_cast<uint32_t>(pt.data.size()));
    w.u64_array(pt.data.data(), pt.data.size());
}

void serialize_secret_key(const RlweSk &sk, std::vector<uint8_t> &out) {
    Writer w(out);
    w.u32(static_cast<uint32_t>(sk.data.size()));
    w.u64_array(sk.data.data(), sk.data.size());
}

RlweSk deserialize_secret_key(const uint8_t *data, size_t len) {
    Reader r(data, len);
    const uint32_t n = r.u32();
    RlweSk sk;
    sk.data.assign(n, 0);
    r.u64_array(sk.data.data(), n);
    return sk;
}

// ============================================================================
//   Opaque handle types
// ============================================================================

size_t resolve_num_entries(uint64_t num_entries) {
    return num_entries == 0
           ? static_cast<size_t>(DBConsts::DB_SIZE_MB) // placeholder; PirParams ignores
           : static_cast<size_t>(num_entries);
}

}  // namespace

// PirParams's default ctor reads num_pt_ from DBConsts::DB_SIZE_MB / pt_size,
// so we keep the "0 = compiled-in default" semantics by simply using the
// default ctor when num_entries == 0. (The current upstream PirParams takes
// no num_entries argument — the database size is set at compile time.)
struct OnionPirClient_t {
    PirParams params;
    PirClient inner;
    bool keys_built = false;
    bvks::BvGaloisKeys galois_cache;
    GSWCt gsw_cache;
    OnionPirClient_t() : params(), inner(params) {}
    OnionPirClient_t(size_t client_id, RlweSk sk)
        : params(), inner(params, client_id, std::move(sk)) {}
};

struct OnionPirServer_t {
    PirParams params;
    PirServer inner;
    OnionPirServer_t() : params(), inner(params) {}
};

// ============================================================================
//   C ABI
// ============================================================================

extern "C" void onion_free_buf(OnionBuf buf) {
    std::free(buf.data);
}

extern "C" OnionPirParamsInfo onion_params_info(uint64_t /*num_entries*/) {
    // Upstream's PirParams is constructed from compile-time DBConsts, so
    // num_entries is currently ignored. Kept in the signature for forward
    // compatibility with a future runtime-sized constructor.
    PirParams p;
    OnionPirParamsInfo info{};
    info.num_entries      = static_cast<uint64_t>(p.get_num_pt()); // one entry per plaintext for now
    info.entry_size       = static_cast<uint64_t>(p.get_pt_size());
    info.num_plaintexts   = static_cast<uint64_t>(p.get_num_pt());
    info.fst_dim_sz       = static_cast<uint64_t>(p.get_fst_dim_sz());
    info.other_dim_sz     = static_cast<uint64_t>(p.get_num_pt() / p.get_fst_dim_sz());
    info.poly_degree      = static_cast<uint64_t>(DBConsts::PolyDegree);
    info.rns_mod_count    = static_cast<uint64_t>(p.K());
    info.coeff_val_cnt    = static_cast<uint64_t>(DBConsts::PolyDegree) * p.K();
    info.db_size_mb       = p.get_DBSize_MB();
    info.physical_size_mb = p.get_DBSize_MB(); // physical == logical until composite mod adds split layout
    return info;
}

// ----------------------------------------------------------------------------
// Client
// ----------------------------------------------------------------------------

extern "C" OnionClientHandle onion_client_new(uint64_t /*num_entries*/) {
    try {
        return new OnionPirClient_t();
    } catch (...) {
        return nullptr;
    }
}

extern "C" void onion_client_free(OnionClientHandle h) {
    delete static_cast<OnionPirClient_t *>(h);
}

extern "C" uint64_t onion_client_id(OnionClientHandle h) {
    auto *c = static_cast<OnionPirClient_t *>(h);
    return c ? static_cast<uint64_t>(c->inner.get_client_id()) : 0;
}

extern "C" OnionClientHandle onion_client_new_from_sk(uint64_t /*num_entries*/,
                                                      uint64_t client_id,
                                                      const uint8_t *sk_data,
                                                      size_t sk_len) {
    if (!sk_data) return nullptr;
    try {
        RlweSk sk = deserialize_secret_key(sk_data, sk_len);
        return new OnionPirClient_t(static_cast<size_t>(client_id), std::move(sk));
    } catch (...) {
        return nullptr;
    }
}

extern "C" OnionBuf onion_client_export_secret_key(OnionClientHandle h) {
    auto *c = static_cast<OnionPirClient_t *>(h);
    if (!c) return OnionBuf{nullptr, 0};
    try {
        std::vector<uint8_t> bytes;
        serialize_secret_key(c->inner.get_secret_key(), bytes);
        return vec_to_buf(bytes);
    } catch (...) {
        return OnionBuf{nullptr, 0};
    }
}

static void build_client_keys_once(OnionPirClient_t *c) {
    if (c->keys_built) return;
    c->galois_cache = c->inner.create_bv_galois_keys();
    c->gsw_cache    = c->inner.generate_gsw_from_key();
    c->keys_built = true;
}

extern "C" OnionBuf onion_client_galois_keys(OnionClientHandle h) {
    auto *c = static_cast<OnionPirClient_t *>(h);
    if (!c) return OnionBuf{nullptr, 0};
    try {
        build_client_keys_once(c);
        std::vector<uint8_t> bytes;
        serialize_bv_galois_keys(c->galois_cache, bytes);
        return vec_to_buf(bytes);
    } catch (...) {
        return OnionBuf{nullptr, 0};
    }
}

extern "C" OnionBuf onion_client_gsw_key(OnionClientHandle h) {
    auto *c = static_cast<OnionPirClient_t *>(h);
    if (!c) return OnionBuf{nullptr, 0};
    try {
        build_client_keys_once(c);
        std::vector<uint8_t> bytes;
        serialize_gsw_ct(c->gsw_cache, bytes);
        return vec_to_buf(bytes);
    } catch (...) {
        return OnionBuf{nullptr, 0};
    }
}

extern "C" OnionBuf onion_client_generate_query(OnionClientHandle h, uint64_t pt_idx) {
    auto *c = static_cast<OnionPirClient_t *>(h);
    if (!c) return OnionBuf{nullptr, 0};
    try {
        RlweCt q = c->inner.fast_generate_query(static_cast<size_t>(pt_idx));
        std::vector<uint8_t> bytes;
        serialize_rlwe_ct(q, bytes);
        return vec_to_buf(bytes);
    } catch (...) {
        return OnionBuf{nullptr, 0};
    }
}

extern "C" OnionBuf onion_client_decrypt_response(OnionClientHandle h,
                                                  const uint8_t *response,
                                                  size_t response_len) {
    auto *c = static_cast<OnionPirClient_t *>(h);
    if (!c) return OnionBuf{nullptr, 0};
    try {
        // The response wire format is the bit-packed stream produced by
        // PirServer::save_resp_to_stream — feed it back through the matching
        // load_resp_from_stream.
        std::stringstream ss;
        ss.write(reinterpret_cast<const char *>(response), response_len);
        ss.seekg(0);
        RlweCt reconstructed = c->inner.load_resp_from_stream(ss);
        RlwePt pt = c->inner.decrypt_mod_q(reconstructed);
        std::vector<uint8_t> bytes;
        serialize_plaintext(pt, bytes);
        return vec_to_buf(bytes);
    } catch (...) {
        return OnionBuf{nullptr, 0};
    }
}

// ----------------------------------------------------------------------------
// Server
// ----------------------------------------------------------------------------

extern "C" OnionServerHandle onion_server_new(uint64_t /*num_entries*/) {
    try {
        return new OnionPirServer_t();
    } catch (...) {
        return nullptr;
    }
}

extern "C" void onion_server_free(OnionServerHandle h) {
    delete static_cast<OnionPirServer_t *>(h);
}

extern "C" void onion_server_gen_data(OnionServerHandle h,
                                      const uint64_t *record_indices,
                                      size_t num_indices) {
    auto *s = static_cast<OnionPirServer_t *>(h);
    if (!s) return;
    try {
        std::vector<size_t> idx;
        if (record_indices && num_indices > 0) {
            idx.reserve(num_indices);
            for (size_t i = 0; i < num_indices; i++) {
                idx.push_back(static_cast<size_t>(record_indices[i]));
            }
        }
        s->inner.gen_data(idx);
    } catch (...) {
        // swallow — gen_data is fire-and-forget; caller can still inspect state
    }
}

extern "C" OnionBuf onion_server_get_original_plaintext(OnionServerHandle h,
                                                       uint64_t pt_idx) {
    auto *s = static_cast<OnionPirServer_t *>(h);
    if (!s) return OnionBuf{nullptr, 0};
    try {
        RlwePt pt = s->inner.direct_get_original_plaintext(static_cast<size_t>(pt_idx));
        std::vector<uint8_t> bytes;
        serialize_plaintext(pt, bytes);
        return vec_to_buf(bytes);
    } catch (...) {
        return OnionBuf{nullptr, 0};
    }
}

extern "C" void onion_server_set_galois_keys(OnionServerHandle h, uint64_t client_id,
                                              const uint8_t *data, size_t len) {
    auto *s = static_cast<OnionPirServer_t *>(h);
    if (!s) return;
    try {
        bvks::BvGaloisKeys keys = deserialize_bv_galois_keys(data, len);
        s->inner.set_client_bv_galois_key(static_cast<size_t>(client_id),
                                          std::move(keys));
    } catch (...) {}
}

extern "C" void onion_server_set_gsw_key(OnionServerHandle h, uint64_t client_id,
                                          const uint8_t *data, size_t len) {
    auto *s = static_cast<OnionPirServer_t *>(h);
    if (!s) return;
    try {
        GSWCt gsw = deserialize_gsw_ct(data, len);
        s->inner.set_client_gsw_key(static_cast<size_t>(client_id), std::move(gsw));
    } catch (...) {}
}

extern "C" int onion_server_save_db(OnionServerHandle h, const char *path) {
    auto *s = static_cast<OnionPirServer_t *>(h);
    if (!s || !path) return 0;
    try {
        s->inner.save_db_to_file(std::string(path));
        return 1;
    } catch (...) {
        return 0;
    }
}

extern "C" int onion_server_load_db(OnionServerHandle h, const char *path) {
    auto *s = static_cast<OnionPirServer_t *>(h);
    if (!s || !path) return 0;
    try {
        return s->inner.load_db_from_file(std::string(path)) ? 1 : 0;
    } catch (...) {
        return 0;
    }
}

extern "C" int onion_server_load_db_from_borrowed(OnionServerHandle h,
                                                   const uint8_t *data,
                                                   size_t len) {
    auto *s = static_cast<OnionPirServer_t *>(h);
    if (!s || !data) return 0;
    try {
        return s->inner.load_db_from_borrowed(data, len) ? 1 : 0;
    } catch (...) {
        return 0;
    }
}

extern "C" OnionBuf onion_server_answer_query(OnionServerHandle h, uint64_t client_id,
                                              const uint8_t *query, size_t query_len) {
    auto *s = static_cast<OnionPirServer_t *>(h);
    if (!s) return OnionBuf{nullptr, 0};
    try {
        RlweCt q = deserialize_rlwe_ct(query, query_len);
        RlweCt response = s->inner.make_query(static_cast<size_t>(client_id), q);
        std::stringstream ss;
        s->inner.save_resp_to_stream(response, ss);
        const std::string str = ss.str();
        std::vector<uint8_t> bytes(str.begin(), str.end());
        return vec_to_buf(bytes);
    } catch (...) {
        return OnionBuf{nullptr, 0};
    }
}
