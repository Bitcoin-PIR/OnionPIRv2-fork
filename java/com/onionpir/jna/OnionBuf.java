package com.onionpir.jna;

import com.sun.jna.Pointer;
import com.sun.jna.Structure;

import java.util.Arrays;
import java.util.List;

/**
 * JNA mapping of the C struct {@code OnionBuf} declared in
 * {@code src/includes/onion_ffi.h}:
 *
 * <pre>
 * typedef struct {
 *     uint8_t *data;
 *     size_t   len;
 * } OnionBuf;
 * </pre>
 *
 * Callers must free the underlying buffer with
 * {@link OnionPirLibrary#onion_free_buf(OnionBuf.ByValue)}. The
 * {@link OnionPir#bufToBytes(ByValue)} helper does the copy-and-free in one step.
 */
public class OnionBuf extends Structure {
    public Pointer data;
    public long len;

    public OnionBuf() {}

    @Override
    protected List<String> getFieldOrder() {
        return Arrays.asList("data", "len");
    }

    /** Pass-by-value variant — required by JNA for direct struct return types. */
    public static class ByValue extends OnionBuf implements Structure.ByValue {}
}
