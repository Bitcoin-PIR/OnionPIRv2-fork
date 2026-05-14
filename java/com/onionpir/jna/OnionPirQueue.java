package com.onionpir.jna;

import com.sun.jna.Pointer;

/**
 * Worker-thread-backed async wrapper around {@link OnionPirServer#answerQuery}.
 *
 * <p>Lifetime: the wrapped {@link OnionPirServer} must outlive this queue.
 * While the queue has pending or in-flight work, callers must NOT mutate the
 * server (set keys, gen_data, push_plaintexts, etc.) — drain tickets first
 * or call {@link #stop()}.
 *
 * <p>{@link #submit}, {@link #status}, {@link #result}, {@link #stop} are
 * thread-safe and can be called concurrently from multiple producer threads.
 */
public final class OnionPirQueue implements AutoCloseable {

    private static final OnionPirLibrary LIB = OnionPirLibrary.INSTANCE;
    private Pointer handle;

    /** Spawn the worker thread for {@code server}. */
    public OnionPirQueue(OnionPirServer server) {
        handle = LIB.onion_queue_new(server.rawHandle());
        if (handle == null) {
            throw new RuntimeException("onion_queue_new returned null");
        }
    }

    /**
     * Enqueue a query. Returns the assigned ticket (always > 0), or
     * {@code 0} if the queue has been stopped.
     */
    public long submit(long clientId, byte[] query) {
        return LIB.onion_queue_submit(handle, clientId, query, query.length);
    }

    /** Non-blocking status poll. */
    public QueryStatus status(long ticket) {
        return QueryStatus.fromCode(LIB.onion_queue_status(handle, ticket));
    }

    /**
     * Fetch and consume the result for {@code ticket}. Returns the response
     * bytes (on DONE), the UTF-8 error message (on ERROR), or {@code null}
     * for QUEUED / PROCESSING / NOT_FOUND.
     */
    public byte[] result(long ticket) {
        OnionBuf.ByValue buf = LIB.onion_queue_result(handle, ticket);
        if (buf.data == null || buf.len == 0) {
            OnionPir.bufToBytes(buf);  // safe to call: frees nothing
            return null;
        }
        return OnionPir.bufToBytes(buf);
    }

    /** Cooperative shutdown. Idempotent. */
    public void stop() {
        LIB.onion_queue_stop(handle);
    }

    @Override
    public void close() {
        if (handle != null) {
            LIB.onion_queue_free(handle);
            handle = null;
        }
    }
}
