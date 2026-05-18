// FFI smoke test for libonionpir.a — exercises the full PIR round-trip
// through the C ABI (mirrors rust/onionpir/cpp/tests/test_pir.cpp but via
// onion_ffi.h).
//
// Build (from repo root, after `make onionpir` under build-ffi):
//   c++ -std=c++17 -O2 -I rust/onionpir/cpp/includes tests/ffi_smoke.cpp \
//       build-ffi/libonionpir.a -o build-ffi/ffi_smoke
// Run:
//   ./build-ffi/ffi_smoke

#include "onion_ffi.h"

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>

namespace {

bool plaintext_equal(const OnionBuf &a, const OnionBuf &b) {
    if (a.len != b.len) return false;
    return std::memcmp(a.data, b.data, a.len) == 0;
}

int run_one_experiment(uint64_t pt_idx,
                       OnionServerHandle s,
                       OnionClientHandle c) {
    OnionBuf galois = onion_client_galois_keys(c);
    OnionBuf gsw    = onion_client_gsw_key(c);
    if (!galois.data || !gsw.data) {
        std::fprintf(stderr, "key generation failed\n");
        return 1;
    }
    const uint64_t client_id = onion_client_id(c);
    onion_server_set_galois_keys(s, client_id, galois.data, galois.len);
    onion_server_set_gsw_key(s, client_id, gsw.data, gsw.len);
    onion_free_buf(galois);
    onion_free_buf(gsw);

    OnionBuf query = onion_client_generate_query(c, pt_idx);
    if (!query.data) { std::fprintf(stderr, "query gen failed\n"); return 1; }

    OnionBuf response = onion_server_answer_query(
        s, client_id, query.data, query.len);
    onion_free_buf(query);
    if (!response.data) {
        std::fprintf(stderr, "server answer failed\n");
        return 1;
    }

    OnionBuf decrypted = onion_client_decrypt_response(
        c, response.data, response.len);
    onion_free_buf(response);
    if (!decrypted.data) {
        std::fprintf(stderr, "client decrypt failed\n");
        return 1;
    }

    OnionBuf actual = onion_server_get_original_plaintext(s, pt_idx);
    if (!actual.data) {
        std::fprintf(stderr, "server get_original_plaintext failed\n");
        onion_free_buf(decrypted);
        return 1;
    }

    const bool ok = plaintext_equal(decrypted, actual);
    std::printf("  pt_idx=%llu: %s (decrypted=%zu bytes, actual=%zu bytes)\n",
                static_cast<unsigned long long>(pt_idx),
                ok ? "OK" : "MISMATCH",
                decrypted.len, actual.len);

    onion_free_buf(decrypted);
    onion_free_buf(actual);
    return ok ? 0 : 2;
}

}  // namespace

int main() {
    OnionPirParamsInfo p = onion_params_info(0);
    std::printf("Params: N=%llu  K=%llu  num_pt=%llu  fst_dim=%llu  other_dim=%llu\n",
                static_cast<unsigned long long>(p.poly_degree),
                static_cast<unsigned long long>(p.rns_mod_count),
                static_cast<unsigned long long>(p.num_plaintexts),
                static_cast<unsigned long long>(p.fst_dim_sz),
                static_cast<unsigned long long>(p.other_dim_sz));

    OnionServerHandle s = onion_server_new(0);
    if (!s) { std::fprintf(stderr, "server_new failed\n"); return 1; }

    // Pre-declare which plaintext indices we'll need so gen_data only keeps
    // those (the FFI mirrors test_pir.cpp's pattern).
    const std::vector<uint64_t> targets = {0, 1, 7, 42, p.num_plaintexts - 1};
    onion_server_gen_data(s, targets.data(), targets.size());
    std::printf("Server initialized; running %zu queries\n", targets.size());

    int failures = 0;
    for (uint64_t pt_idx : targets) {
        OnionClientHandle c = onion_client_new(0);
        if (!c) { std::fprintf(stderr, "client_new failed\n"); failures++; continue; }
        failures += (run_one_experiment(pt_idx, s, c) != 0) ? 1 : 0;
        onion_client_free(c);
    }
    onion_server_free(s);

    std::printf("\n%d failures out of %zu\n", failures, targets.size());
    return failures == 0 ? 0 : 1;
}
