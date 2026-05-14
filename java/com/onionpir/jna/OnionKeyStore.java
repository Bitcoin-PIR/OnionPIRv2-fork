package com.onionpir.jna;

import com.sun.jna.Pointer;

/**
 * A shared cache of deserialized client keys, backable by many
 * {@link OnionPirServer} instances. Attach via
 * {@link OnionPirServer#setKeyStore(OnionKeyStore)}; once attached, the
 * server's set/get key paths route through the store.
 *
 * <p>Lifecycle: the store must outlive every attached server. Internal LRU
 * eviction caps the cache at 100 clients (drops the least-recently-touched
 * one when full).
 *
 * <p>Thread safety: the underlying C++ store is not internally synchronized.
 * Callers must serialize key registration against query processing.
 */
public final class OnionKeyStore implements AutoCloseable {

    private static final OnionPirLibrary LIB = OnionPirLibrary.INSTANCE;
    private Pointer handle;

    public OnionKeyStore() {
        handle = LIB.onion_key_store_new();
        if (handle == null) {
            throw new RuntimeException("onion_key_store_new returned null");
        }
    }

    /** Package-private — used by {@link OnionPirServer#setKeyStore}. */
    Pointer raw() { return handle; }

    public void setGaloisKeys(long clientId, byte[] data) {
        LIB.onion_key_store_set_galois_keys(handle, clientId, data, data.length);
    }

    public void setGswKey(long clientId, byte[] data) {
        LIB.onion_key_store_set_gsw_key(handle, clientId, data, data.length);
    }

    public boolean hasClient(long clientId) {
        return LIB.onion_key_store_has_client(handle, clientId) != 0;
    }

    public void remove(long clientId) {
        LIB.onion_key_store_remove(handle, clientId);
    }

    public long size() {
        return LIB.onion_key_store_size(handle);
    }

    @Override
    public void close() {
        if (handle != null) {
            LIB.onion_key_store_free(handle);
            handle = null;
        }
    }
}
