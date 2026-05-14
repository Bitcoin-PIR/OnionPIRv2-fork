// OnionPIRv2 WASM client — Emscripten embind bindings.
//
// Thin wrapper over the C ABI in src/includes/onion_ffi.h. By going through
// the same FFI surface as the Rust crate, the on-the-wire format is identical
// — a query produced in-browser can be answered by any onionpir server
// (native, Rust, Java), and vice versa.

#include "onion_ffi.h"

#include <emscripten/bind.h>
#include <emscripten/val.h>

#include <cstdint>
#include <vector>

using namespace emscripten;

namespace {

// Copy an OnionBuf into a JS Uint8Array, freeing the C-side buffer.
val buf_to_uint8array(OnionBuf buf) {
    if (buf.data == nullptr || buf.len == 0) {
        onion_free_buf(buf);
        return val::global("Uint8Array").new_(0);
    }
    // typed_memory_view aliases WASM heap; .slice() copies into a JS-owned
    // Uint8Array so we can safely free buf afterward.
    val view = val(typed_memory_view(buf.len, buf.data));
    val copy = view.call<val>("slice");
    onion_free_buf(buf);
    return copy;
}

// JS Uint8Array → std::vector<uint8_t> (owned).
std::vector<uint8_t> uint8array_to_vec(const val &arr) {
    return convertJSArrayToNumberVector<uint8_t>(arr);
}

}  // namespace

// ============================================================================
// Client (mirrors the C ABI surface in onion_ffi.h)
// ============================================================================

class OnionPirWasmClient {
public:
    OnionPirWasmClient() : h_(onion_client_new(0)) {}
    ~OnionPirWasmClient() { if (h_) onion_client_free(h_); }

    OnionPirWasmClient(const OnionPirWasmClient &) = delete;
    OnionPirWasmClient &operator=(const OnionPirWasmClient &) = delete;

    // Tagged factory ctor — runs onion_client_new_from_sk and stashes the
    // resulting handle. emscripten doesn't dispatch static factories cleanly,
    // so we expose this as a free function below.
    OnionPirWasmClient(OnionClientHandle h) : h_(h) {}

    // Client id (auto-assigned). Returned as double because JS numbers go up
    // to 2^53 and client ids are small.
    double id() const {
        return static_cast<double>(onion_client_id(h_));
    }

    val galois_keys() {
        return buf_to_uint8array(onion_client_galois_keys(h_));
    }

    val gsw_key() {
        return buf_to_uint8array(onion_client_gsw_key(h_));
    }

    val generate_query(uint32_t pt_idx) {
        return buf_to_uint8array(
            onion_client_generate_query(h_, static_cast<uint64_t>(pt_idx)));
    }

    // Decrypt a server response. Input is the bit-packed response bytes
    // produced by server.answer_query (Rust / native FFI side).
    // Output is the N-coefficient plaintext as [u32 N (LE)][u64 coeff_0]…
    val decrypt_response(val response_arr) {
        auto bytes = uint8array_to_vec(response_arr);
        return buf_to_uint8array(
            onion_client_decrypt_response(h_, bytes.data(), bytes.size()));
    }

    val export_secret_key() {
        return buf_to_uint8array(onion_client_export_secret_key(h_));
    }

private:
    OnionClientHandle h_;
};

// Factory: reconstruct a client from a previously-exported secret key.
// Returns nullptr if the SK bytes are malformed.
OnionPirWasmClient *create_client_from_sk(double client_id, val sk_arr) {
    auto bytes = uint8array_to_vec(sk_arr);
    OnionClientHandle h = onion_client_new_from_sk(
        0, static_cast<uint64_t>(client_id), bytes.data(), bytes.size());
    if (h == nullptr) return nullptr;
    return new OnionPirWasmClient(h);
}

// ============================================================================
// Params info
// ============================================================================

val params_info() {
    OnionPirParamsInfo p = onion_params_info(0);
    val obj = val::object();
    obj.set("numEntries", static_cast<double>(p.num_entries));
    obj.set("entrySize", static_cast<double>(p.entry_size));
    obj.set("numPlaintexts", static_cast<double>(p.num_plaintexts));
    obj.set("fstDimSz", static_cast<double>(p.fst_dim_sz));
    obj.set("otherDimSz", static_cast<double>(p.other_dim_sz));
    obj.set("polyDegree", static_cast<double>(p.poly_degree));
    obj.set("rnsModCount", static_cast<double>(p.rns_mod_count));
    obj.set("coeffValCnt", static_cast<double>(p.coeff_val_cnt));
    obj.set("dbSizeMB", p.db_size_mb);
    obj.set("physicalSizeMB", p.physical_size_mb);
    return obj;
}

// ============================================================================
// Hash utilities (application-level helpers — pure math, no PIR state)
// ============================================================================

#include "hash_utils.h"

double splitmix64_wrapper(double x) {
    return static_cast<double>(hash_splitmix64(static_cast<uint64_t>(x)));
}

double cuckoo_hash_int_wrapper(uint32_t entry_id, double key, uint32_t num_bins) {
    return static_cast<double>(
        hash_cuckoo_int(entry_id, static_cast<uint64_t>(key), num_bins));
}

// ============================================================================
// Embind registrations
// ============================================================================

EMSCRIPTEN_BINDINGS(onionpir_client) {
    class_<OnionPirWasmClient>("OnionPirClient")
        .constructor<>()
        .function("id", &OnionPirWasmClient::id)
        .function("galoisKeys", &OnionPirWasmClient::galois_keys)
        .function("gswKey", &OnionPirWasmClient::gsw_key)
        .function("generateQuery", &OnionPirWasmClient::generate_query)
        .function("decryptResponse", &OnionPirWasmClient::decrypt_response)
        .function("exportSecretKey", &OnionPirWasmClient::export_secret_key);

    function("paramsInfo", &params_info);
    function("createClientFromSecretKey", &create_client_from_sk,
             allow_raw_pointers());
    function("splitmix64", &splitmix64_wrapper);
    function("cuckooHashInt", &cuckoo_hash_int_wrapper);
    function("buildCuckooBs1", &hash_build_cuckoo_bs1_embind);
}
