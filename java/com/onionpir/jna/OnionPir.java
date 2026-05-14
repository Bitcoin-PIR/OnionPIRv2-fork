package com.onionpir.jna;

/**
 * Static utilities and the entry point to the {@link OnionPirLibrary} singleton.
 */
public final class OnionPir {
    private OnionPir() {}

    /** Inspect the compiled-in PIR shape. {@code numEntries==0} → defaults. */
    public static PirParamsInfo.ByValue paramsInfo(long numEntries) {
        return OnionPirLibrary.INSTANCE.onion_params_info(numEntries);
    }

    /**
     * Copy the buffer payload into a Java {@code byte[]} and free the native
     * allocation. Always do this for {@code OnionBuf.ByValue} returned from
     * the FFI to avoid leaks.
     */
    public static byte[] bufToBytes(OnionBuf.ByValue buf) {
        try {
            if (buf.data == null || buf.len == 0) {
                return new byte[0];
            }
            return buf.data.getByteArray(0, (int) buf.len);
        } finally {
            OnionPirLibrary.INSTANCE.onion_free_buf(buf);
        }
    }
}
