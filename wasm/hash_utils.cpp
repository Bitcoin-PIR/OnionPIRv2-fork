#include "hash_utils.h"
#include <algorithm>

// ======================== splitmix64 ========================

uint64_t hash_splitmix64(uint64_t x) {
    x = (x ^ (x >> 30)) * 0xbf58476d1ce4e5b9ULL;
    x = (x ^ (x >> 27)) * 0x94d049bb133111ebULL;
    return x ^ (x >> 31);
}

// ======================== Cuckoo hashing ========================

uint32_t hash_cuckoo_int(uint32_t entry_id, uint64_t key, uint32_t num_bins) {
    uint64_t h = hash_splitmix64(key ^ static_cast<uint64_t>(entry_id));
    return static_cast<uint32_t>(h % num_bins);
}

// Build a cuckoo hash table with deterministic eviction.
// Matches the Rust server's build_chunk_cuckoo_for_group exactly:
//   - All num_keys hash functions (typically 6)
//   - Deterministic eviction chain (no RNG)
//   - 10000 max kicks
std::vector<uint32_t> build_cuckoo_bs1(
    const uint32_t* entries, size_t num_entries,
    const uint64_t* keys, size_t num_keys,
    uint32_t num_bins) {

    constexpr uint32_t EMPTY_VAL = 0xFFFFFFFF;
    constexpr size_t MAX_KICKS = 10000;

    std::vector<uint32_t> table(num_bins, EMPTY_VAL);

    for (size_t i = 0; i < num_entries; i++) {
        uint32_t entry_id = entries[i];

        // Phase 1: try direct placement with each hash function
        bool placed = false;
        for (size_t h = 0; h < num_keys; h++) {
            uint32_t bin = hash_cuckoo_int(entry_id, keys[h], num_bins);
            if (table[bin] == EMPTY_VAL) {
                table[bin] = entry_id;
                placed = true;
                break;
            }
        }
        if (placed) continue;

        // Phase 2: deterministic eviction chain
        uint32_t current_id = entry_id;
        size_t current_hash_fn = 0;
        uint32_t current_bin = hash_cuckoo_int(entry_id, keys[0], num_bins);
        bool success = false;

        for (size_t kick = 0; kick < MAX_KICKS; kick++) {
            // Evict the occupant at current_bin
            uint32_t evicted = table[current_bin];
            table[current_bin] = current_id;

            // Try to place evicted item in any empty alternate bin
            for (size_t h = 0; h < num_keys; h++) {
                size_t try_h = (current_hash_fn + 1 + h) % num_keys;
                uint32_t bin = hash_cuckoo_int(evicted, keys[try_h], num_bins);
                if (bin == current_bin) continue;
                if (table[bin] == EMPTY_VAL) {
                    table[bin] = evicted;
                    success = true;
                    break;
                }
            }
            if (success) break;

            // Continue chain: deterministic next bucket
            size_t alt_h = (current_hash_fn + 1 + kick % (num_keys - 1)) % num_keys;
            uint32_t alt_bin = hash_cuckoo_int(evicted, keys[alt_h], num_bins);
            uint32_t final_bin;
            if (alt_bin == current_bin) {
                size_t h2 = (alt_h + 1) % num_keys;
                final_bin = hash_cuckoo_int(evicted, keys[h2], num_bins);
            } else {
                final_bin = alt_bin;
            }

            current_id = evicted;
            current_hash_fn = alt_h;
            current_bin = final_bin;
        }

        // If !success after MAX_KICKS, insertion failed (caller should handle)
    }

    return table;
}

// ======================== Embind wrappers ========================

#ifdef __EMSCRIPTEN__
#include <emscripten/val.h>

using namespace emscripten;

val hash_build_cuckoo_bs1_embind(val entries_val, val keys_val, uint32_t num_bins) {
    // Convert JS Uint32Array → C++ vector
    size_t num_entries = entries_val["length"].as<size_t>();
    std::vector<uint32_t> entries(num_entries);
    for (size_t i = 0; i < num_entries; i++) {
        entries[i] = entries_val[i].as<uint32_t>();
    }

    // Convert JS keys array → C++ uint64 vector.
    // Keys are passed as Uint32Array of length num_keys*2 (lo32, hi32 pairs)
    // to avoid precision loss with double (which can't represent >2^53).
    size_t keys_len = keys_val["length"].as<size_t>();
    size_t num_keys = keys_len / 2;
    std::vector<uint64_t> keys(num_keys);
    for (size_t i = 0; i < num_keys; i++) {
        uint32_t lo = keys_val[i * 2].as<uint32_t>();
        uint32_t hi = keys_val[i * 2 + 1].as<uint32_t>();
        keys[i] = static_cast<uint64_t>(lo) | (static_cast<uint64_t>(hi) << 32);
    }

    auto result = build_cuckoo_bs1(entries.data(), entries.size(),
                                    keys.data(), keys.size(), num_bins);

    // Return as Uint32Array
    return val(typed_memory_view(result.size(), result.data())).call<val>("slice");
}
#endif
