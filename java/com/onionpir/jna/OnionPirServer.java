package com.onionpir.jna;

import com.sun.jna.Pointer;

/**
 * Safe wrapper around an OnionPIR server handle.
 *
 * <p>Workflow:
 * <ol>
 *   <li>{@link #genData(long[])} — populate with random data (test path);
 *       pass the plaintext indices you'll query so
 *       {@link #getOriginalPlaintext(long)} stays valid for those rows.</li>
 *   <li>{@link #setGaloisKeys(long, byte[])} / {@link #setGswKey(long, byte[])}
 *       — register a client's key blobs.</li>
 *   <li>{@link #answerQuery(long, byte[])} — run the PIR query.</li>
 * </ol>
 *
 * <p>Thread safety: a single instance must not be shared across threads.
 *
 * <p>Production-mode database building (push_chunk / preprocess / load /
 * save / load_from_borrowed) is not yet exposed by the upstream-tracking
 * FFI — it lands in Phase 6.
 */
public final class OnionPirServer implements AutoCloseable {

    private static final OnionPirLibrary LIB = OnionPirLibrary.INSTANCE;
    private Pointer handle;

    /**
     * @param numEntries currently ignored — upstream params are compile-time.
     */
    public OnionPirServer(long numEntries) {
        handle = LIB.onion_server_new(numEntries);
        if (handle == null) {
            throw new RuntimeException("onion_server_new returned null");
        }
    }

    /**
     * Populate the DB with random data. If {@code queryIndices} is non-empty,
     * only those plaintexts are retained for {@link #getOriginalPlaintext}.
     */
    public void genData(long[] queryIndices) {
        if (queryIndices == null) queryIndices = new long[0];
        LIB.onion_server_gen_data(handle, queryIndices, queryIndices.length);
    }

    /**
     * Recover the pre-NTT plaintext for {@code ptIdx} (must have been passed
     * to a prior {@link #genData(long[])} call). Format matches
     * {@link OnionPirClient#decryptResponse(byte[])} for direct equality
     * checks in tests.
     */
    public byte[] getOriginalPlaintext(long ptIdx) {
        return OnionPir.bufToBytes(LIB.onion_server_get_original_plaintext(handle, ptIdx));
    }

    /** Register a client's serialized BV galois keys. */
    public void setGaloisKeys(long clientId, byte[] data) {
        LIB.onion_server_set_galois_keys(handle, clientId, data, data.length);
    }

    /** Register a client's serialized GSW(s) key. */
    public void setGswKey(long clientId, byte[] data) {
        LIB.onion_server_set_gsw_key(handle, clientId, data, data.length);
    }

    /** Run a PIR query and return the bit-packed response. */
    public byte[] answerQuery(long clientId, byte[] query) {
        OnionBuf.ByValue buf = LIB.onion_server_answer_query(
                handle, clientId, query, query.length);
        return OnionPir.bufToBytes(buf);
    }

    /**
     * Save the post-NTT, realigned database to {@code path}.
     * @return {@code true} on success; {@code false} on I/O failure or empty DB.
     */
    public boolean saveDb(String path) {
        return LIB.onion_server_save_db(handle, path) != 0;
    }

    /**
     * Load a previously-saved DB. Returns {@code false} if the file is
     * missing or the on-disk layout doesn't match the server's compile-time
     * config.
     */
    public boolean loadDb(String path) {
        return LIB.onion_server_load_db(handle, path) != 0;
    }

    /**
     * Zero-copy: alias an already-formatted DB buffer. The buffer must
     * outlive the server (the server keeps a reference, doesn't copy).
     * Returns {@code false} on header / size mismatch.
     */
    public boolean loadDbFromBorrowed(byte[] data) {
        return LIB.onion_server_load_db_from_borrowed(handle, data, data.length) != 0;
    }

    @Override
    public void close() {
        if (handle != null) {
            LIB.onion_server_free(handle);
            handle = null;
        }
    }
}
