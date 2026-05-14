package com.onionpir.jna;

import com.sun.jna.Pointer;

/**
 * Safe wrapper around an OnionPIR client handle.
 *
 * <p>Each client owns a fresh secret key. Pair its keys ({@link #galoisKeys()},
 * {@link #gswKey()}) and id ({@link #id()}) with a server via
 * {@link OnionPirServer#setGaloisKeys(long, byte[])} and
 * {@link OnionPirServer#setGswKey(long, byte[])}.
 *
 * <p>Thread safety: a single instance must not be shared across threads.
 *
 * <pre>{@code
 * try (OnionPirClient c = new OnionPirClient(0)) {
 *     byte[] galois = c.galoisKeys();
 *     byte[] gsw    = c.gswKey();
 *     byte[] query  = c.generateQuery(42);
 *     // ... server.answerQuery(...) → response ...
 *     byte[] plaintext = c.decryptResponse(response);
 * }
 * }</pre>
 */
public final class OnionPirClient implements AutoCloseable {

    private static final OnionPirLibrary LIB = OnionPirLibrary.INSTANCE;
    private Pointer handle;

    /**
     * @param numEntries currently ignored — upstream params are compile-time;
     *                   kept for forward compatibility.
     */
    public OnionPirClient(long numEntries) {
        handle = LIB.onion_client_new(numEntries);
        if (handle == null) {
            throw new RuntimeException("onion_client_new returned null");
        }
    }

    /** Auto-assigned client id. */
    public long id() {
        return LIB.onion_client_id(handle);
    }

    /** Serialized BV galois keys. Hand to {@link OnionPirServer#setGaloisKeys}. */
    public byte[] galoisKeys() {
        return OnionPir.bufToBytes(LIB.onion_client_galois_keys(handle));
    }

    /** Serialized GSW(s) key. Hand to {@link OnionPirServer#setGswKey}. */
    public byte[] gswKey() {
        return OnionPir.bufToBytes(LIB.onion_client_gsw_key(handle));
    }

    /**
     * Serialized PIR query for plaintext index {@code ptIdx}.
     * {@code ptIdx} must be in [0, numPlaintexts).
     */
    public byte[] generateQuery(long ptIdx) {
        return OnionPir.bufToBytes(LIB.onion_client_generate_query(handle, ptIdx));
    }

    /**
     * Decrypt a server response. Returns the plaintext in the same
     * {@code [u32 N (LE)][u64 coeff_i]…} layout that
     * {@link OnionPirServer#getOriginalPlaintext(long)} produces.
     */
    public byte[] decryptResponse(byte[] response) {
        OnionBuf.ByValue buf = LIB.onion_client_decrypt_response(
                handle, response, response.length);
        return OnionPir.bufToBytes(buf);
    }

    @Override
    public void close() {
        if (handle != null) {
            LIB.onion_client_free(handle);
            handle = null;
        }
    }
}
