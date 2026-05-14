#pragma once

#include <cstdint>
#include <cstddef>
#include <vector>

#ifdef __EMSCRIPTEN__
#include <emscripten/val.h>
#endif

// splitmix64 hash function
uint64_t hash_splitmix64(uint64_t x);

// Compute a single cuckoo bucket index for an entry
uint32_t hash_cuckoo_int(uint32_t entry_id, uint64_t key, uint32_t num_bins);

// Build a complete cuckoo hash table for a group.
// entries: sorted array of entry_ids assigned to this group
// keys: array of 6 hash function keys
// num_bins: table size
// Returns: table[bin] = entry_id (or 0xFFFFFFFF for empty)
std::vector<uint32_t> build_cuckoo_bs1(
    const uint32_t* entries, size_t num_entries,
    const uint64_t* keys, size_t num_keys,
    uint32_t num_bins
);

#ifdef __EMSCRIPTEN__
// Embind-friendly wrappers that work with JS typed arrays
emscripten::val hash_build_cuckoo_bs1_embind(
    emscripten::val entries_val,
    emscripten::val keys_val,
    uint32_t num_bins
);
#endif
