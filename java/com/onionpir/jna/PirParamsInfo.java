package com.onionpir.jna;

import com.sun.jna.Structure;

import java.util.Arrays;
import java.util.List;

/**
 * JNA mapping of {@code OnionPirParamsInfo} declared in
 * {@code src/includes/onion_ffi.h}.
 *
 * <pre>
 * typedef struct {
 *     uint64_t num_entries;
 *     uint64_t entry_size;
 *     uint64_t num_plaintexts;
 *     uint64_t fst_dim_sz;
 *     uint64_t other_dim_sz;
 *     uint64_t poly_degree;
 *     uint64_t rns_mod_count;
 *     uint64_t coeff_val_cnt;
 *     double   db_size_mb;
 *     double   physical_size_mb;
 * } OnionPirParamsInfo;
 * </pre>
 */
public class PirParamsInfo extends Structure {
    public long numEntries;
    public long entrySize;
    public long numPlaintexts;
    public long fstDimSz;
    public long otherDimSz;
    public long polyDegree;
    public long rnsModCount;
    public long coeffValCnt;
    public double dbSizeMb;
    public double physicalSizeMb;

    public PirParamsInfo() {}

    @Override
    protected List<String> getFieldOrder() {
        return Arrays.asList(
                "numEntries", "entrySize", "numPlaintexts",
                "fstDimSz", "otherDimSz",
                "polyDegree", "rnsModCount", "coeffValCnt",
                "dbSizeMb", "physicalSizeMb"
        );
    }

    @Override
    public String toString() {
        return "PirParamsInfo{" +
                "numEntries=" + numEntries +
                ", entrySize=" + entrySize +
                ", numPlaintexts=" + numPlaintexts +
                ", fstDimSz=" + fstDimSz +
                ", otherDimSz=" + otherDimSz +
                ", polyDegree=" + polyDegree +
                ", rnsModCount=" + rnsModCount +
                ", coeffValCnt=" + coeffValCnt +
                ", dbSizeMb=" + dbSizeMb +
                ", physicalSizeMb=" + physicalSizeMb +
                '}';
    }

    /** Pass-by-value variant — required by JNA for direct struct return types. */
    public static class ByValue extends PirParamsInfo implements Structure.ByValue {}
}
