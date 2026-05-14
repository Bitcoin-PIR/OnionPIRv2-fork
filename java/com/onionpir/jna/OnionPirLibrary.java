package com.onionpir.jna;

import com.sun.jna.Library;
import com.sun.jna.Native;
import com.sun.jna.Pointer;

/**
 * Raw JNA declarations for every {@code extern "C"} function in
 * {@code src/includes/onion_ffi.h}.
 *
 * <p>The native library name is {@code "onionpir"}, which JNA resolves to
 * {@code libonionpir.so} (Linux) or {@code libonionpir.dylib} (macOS). Build with:
 * <pre>
 * mkdir build-shared && cd build-shared
 * cmake .. -DONIONPIR_BUILD_FFI=ON -DONIONPIR_BUILD_SHARED=ON
 * make -j$(nproc)
 * </pre>
 * and either:
 * <ul>
 *   <li>set {@code -Djna.library.path=/abs/path/to/build-shared} at JVM launch, or</li>
 *   <li>set {@code DYLD_LIBRARY_PATH} (macOS) / {@code LD_LIBRARY_PATH} (Linux).</li>
 * </ul>
 */
public interface OnionPirLibrary extends Library {

    OnionPirLibrary INSTANCE = Native.load("onionpir", OnionPirLibrary.class);

    // ── Buffer management ────────────────────────────────────────────────

    void onion_free_buf(OnionBuf.ByValue buf);

    // ── Params ───────────────────────────────────────────────────────────

    PirParamsInfo.ByValue onion_params_info(long num_entries);

    // ── Client ───────────────────────────────────────────────────────────

    Pointer onion_client_new(long num_entries);
    void    onion_client_free(Pointer h);
    long    onion_client_id(Pointer h);

    OnionBuf.ByValue onion_client_galois_keys(Pointer h);
    OnionBuf.ByValue onion_client_gsw_key(Pointer h);
    OnionBuf.ByValue onion_client_generate_query(Pointer h, long pt_idx);
    OnionBuf.ByValue onion_client_decrypt_response(Pointer h, byte[] response, long response_len);

    // ── Server ───────────────────────────────────────────────────────────

    Pointer onion_server_new(long num_entries);
    void    onion_server_free(Pointer h);

    void onion_server_gen_data(Pointer h, long[] record_indices, long num_indices);
    OnionBuf.ByValue onion_server_get_original_plaintext(Pointer h, long pt_idx);

    void onion_server_set_galois_keys(Pointer h, long client_id, byte[] data, long len);
    void onion_server_set_gsw_key   (Pointer h, long client_id, byte[] data, long len);

    OnionBuf.ByValue onion_server_answer_query(Pointer h, long client_id,
                                               byte[] query, long query_len);
}
