//! Rust bindings for OnionPIRv2 — a high-performance PIR library based on
//! BV key-switching (no SEAL special prime).
//!
//! See [`Server`] and [`Client`] for the entry points. Most users should use
//! the high-level wrappers; the raw FFI is in the private [`ffi`] module.
//!
//! ## Example
//!
//! ```no_run
//! use onionpir::{Server, Client};
//!
//! let info = onionpir::params_info(0);
//! let pt_idx = 42;
//!
//! let mut server = Server::new(0);
//! server.gen_data(&[pt_idx]); // pre-record this plaintext for the test path
//!
//! let mut client = Client::new(0);
//! let client_id = client.id();
//! server.set_galois_keys(client_id, &client.galois_keys());
//! server.set_gsw_key(client_id, &client.gsw_key());
//!
//! let query = client.generate_query(pt_idx);
//! let response = server.answer_query(client_id, &query);
//! let decrypted = client.decrypt_response(&response);
//! let actual = server.get_original_plaintext(pt_idx);
//! assert_eq!(decrypted, actual);
//! ```

use std::os::raw::c_void;

// ============================================================================
// Raw FFI declarations (mirror src/includes/onion_ffi.h)
// ============================================================================

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct COnionBuf {
    data: *mut u8,
    len: usize,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct ParamsInfo {
    pub num_entries: u64,
    pub entry_size: u64,
    pub num_plaintexts: u64,
    pub fst_dim_sz: u64,
    pub other_dim_sz: u64,
    pub poly_degree: u64,
    pub rns_mod_count: u64,
    pub coeff_val_cnt: u64,
    pub db_size_mb: f64,
    pub physical_size_mb: f64,
}

type ClientHandle = *mut c_void;
type ServerHandle = *mut c_void;

#[link(name = "onionpir", kind = "static")]
extern "C" {
    fn onion_free_buf(buf: COnionBuf);

    fn onion_params_info(num_entries: u64) -> ParamsInfo;

    fn onion_client_new(num_entries: u64) -> ClientHandle;
    fn onion_client_free(h: ClientHandle);
    fn onion_client_id(h: ClientHandle) -> u64;
    fn onion_client_new_from_sk(num_entries: u64, client_id: u64,
                                sk_data: *const u8, sk_len: usize) -> ClientHandle;
    fn onion_client_export_secret_key(h: ClientHandle) -> COnionBuf;
    fn onion_client_galois_keys(h: ClientHandle) -> COnionBuf;
    fn onion_client_gsw_key(h: ClientHandle) -> COnionBuf;
    fn onion_client_generate_query(h: ClientHandle, pt_idx: u64) -> COnionBuf;
    fn onion_client_decrypt_response(h: ClientHandle, response: *const u8, len: usize) -> COnionBuf;

    fn onion_server_new(num_entries: u64) -> ServerHandle;
    fn onion_server_free(h: ServerHandle);
    fn onion_server_gen_data(h: ServerHandle, indices: *const u64, num_indices: usize);
    fn onion_server_get_original_plaintext(h: ServerHandle, pt_idx: u64) -> COnionBuf;
    fn onion_server_set_galois_keys(h: ServerHandle, client_id: u64, data: *const u8, len: usize);
    fn onion_server_set_gsw_key(h: ServerHandle, client_id: u64, data: *const u8, len: usize);
    fn onion_server_answer_query(
        h: ServerHandle,
        client_id: u64,
        query: *const u8,
        query_len: usize,
    ) -> COnionBuf;

    fn onion_server_save_db(h: ServerHandle, path: *const i8) -> i32;
    fn onion_server_load_db(h: ServerHandle, path: *const i8) -> i32;
    fn onion_server_load_db_from_borrowed(h: ServerHandle, data: *const u8, len: usize) -> i32;
}

// ============================================================================
// Buffer marshalling
// ============================================================================

fn buf_to_vec(buf: COnionBuf) -> Vec<u8> {
    if buf.data.is_null() || buf.len == 0 {
        // SAFETY: even if data is non-null with len 0, freeing is still safe.
        unsafe { onion_free_buf(buf) };
        return Vec::new();
    }
    // Copy out (FFI buffer is malloc'd; we don't want Rust's allocator to free it).
    // SAFETY: data was allocated by malloc on the C side; buf.len bytes are valid.
    let slice = unsafe { std::slice::from_raw_parts(buf.data, buf.len) };
    let vec = slice.to_vec();
    // SAFETY: we own buf; free it on the C side.
    unsafe { onion_free_buf(buf) };
    vec
}

// ============================================================================
// Free functions
// ============================================================================

/// Inspect the compiled-in database parameters.
///
/// `num_entries` is currently ignored (the upstream PirParams reads its shape
/// from build-time constants); kept in the signature for forward compatibility.
pub fn params_info(num_entries: u64) -> ParamsInfo {
    unsafe { onion_params_info(num_entries) }
}

// ============================================================================
// Client
// ============================================================================

/// A PIR client. Owns its secret key, BV galois keys, and GSW(s) key.
pub struct Client {
    h: ClientHandle,
}

// Handle is private and access is serialized through &mut self / methods.
unsafe impl Send for Client {}

impl Client {
    /// Construct a fresh client with the compiled-in default parameters.
    /// `num_entries` is currently ignored (see `params_info`).
    pub fn new(num_entries: u64) -> Self {
        let h = unsafe { onion_client_new(num_entries) };
        assert!(!h.is_null(), "onion_client_new returned null");
        Self { h }
    }

    /// Reconstruct a client from a previously-exported secret key plus the
    /// id the server already knows. Returns `None` on size / format mismatch.
    pub fn from_secret_key(num_entries: u64, client_id: u64, sk: &[u8]) -> Option<Self> {
        let h = unsafe { onion_client_new_from_sk(num_entries, client_id, sk.as_ptr(), sk.len()) };
        if h.is_null() { None } else { Some(Self { h }) }
    }

    /// Serialized secret key. Pair with `Client::from_secret_key` to restore
    /// this client in another process. The bytes are sensitive — they fully
    /// recover the client's identity.
    pub fn export_secret_key(&self) -> Vec<u8> {
        buf_to_vec(unsafe { onion_client_export_secret_key(self.h) })
    }

    /// The client's auto-assigned id. Pair with `Server::set_*` calls on the
    /// receiving side to bind the keys to this client.
    pub fn id(&self) -> u64 {
        unsafe { onion_client_id(self.h) }
    }

    /// Serialized BV galois keys. Hand to `Server::set_galois_keys`.
    pub fn galois_keys(&self) -> Vec<u8> {
        buf_to_vec(unsafe { onion_client_galois_keys(self.h) })
    }

    /// Serialized GSW(s) key. Hand to `Server::set_gsw_key`.
    pub fn gsw_key(&self) -> Vec<u8> {
        buf_to_vec(unsafe { onion_client_gsw_key(self.h) })
    }

    /// Serialized PIR query for plaintext index `pt_idx`.
    /// `pt_idx` must be in `[0, params.num_plaintexts)`.
    pub fn generate_query(&self, pt_idx: u64) -> Vec<u8> {
        buf_to_vec(unsafe { onion_client_generate_query(self.h, pt_idx) })
    }

    /// Decrypt a server response. Returns the recovered plaintext as
    /// `[u32 N (LE)][u64 coeff_i for i in 0..N]`. Compare against
    /// `Server::get_original_plaintext` to verify correctness.
    pub fn decrypt_response(&self, response: &[u8]) -> Vec<u8> {
        buf_to_vec(unsafe {
            onion_client_decrypt_response(self.h, response.as_ptr(), response.len())
        })
    }
}

impl Drop for Client {
    fn drop(&mut self) {
        unsafe { onion_client_free(self.h) };
    }
}

// ============================================================================
// Server
// ============================================================================

/// A PIR server. Holds the (preprocessed) database and per-client keys.
pub struct Server {
    h: ServerHandle,
}

unsafe impl Send for Server {}

impl Server {
    /// Construct a fresh server with the compiled-in default parameters.
    pub fn new(num_entries: u64) -> Self {
        let h = unsafe { onion_server_new(num_entries) };
        assert!(!h.is_null(), "onion_server_new returned null");
        Self { h }
    }

    /// Populate the database with random data. Optionally pass the plaintext
    /// indices you'll query so `get_original_plaintext` returns the correct
    /// pre-NTT plaintexts for those rows (the server doesn't keep a copy of
    /// the full DB in memory).
    pub fn gen_data(&mut self, query_indices: &[u64]) {
        unsafe {
            onion_server_gen_data(self.h, query_indices.as_ptr(), query_indices.len());
        }
    }

    /// Returns the recorded pre-NTT plaintext for `pt_idx`.
    /// Only valid for indices passed to a prior `gen_data` call.
    pub fn get_original_plaintext(&self, pt_idx: u64) -> Vec<u8> {
        buf_to_vec(unsafe { onion_server_get_original_plaintext(self.h, pt_idx) })
    }

    /// Register a client's serialized BV galois keys.
    pub fn set_galois_keys(&mut self, client_id: u64, data: &[u8]) {
        unsafe { onion_server_set_galois_keys(self.h, client_id, data.as_ptr(), data.len()) };
    }

    /// Register a client's serialized GSW(s) key.
    pub fn set_gsw_key(&mut self, client_id: u64, data: &[u8]) {
        unsafe { onion_server_set_gsw_key(self.h, client_id, data.as_ptr(), data.len()) };
    }

    /// Run the full PIR query and return the bit-packed response.
    pub fn answer_query(&mut self, client_id: u64, query: &[u8]) -> Vec<u8> {
        buf_to_vec(unsafe {
            onion_server_answer_query(self.h, client_id, query.as_ptr(), query.len())
        })
    }

    /// Save the post-NTT, realigned database to `path`. Returns `false` on I/O
    /// failure or if no DB has been populated yet.
    pub fn save_db(&self, path: &str) -> bool {
        let c = std::ffi::CString::new(path).expect("path contains NUL byte");
        unsafe { onion_server_save_db(self.h, c.as_ptr()) != 0 }
    }

    /// Load a previously-saved DB. Returns `false` if the file is missing or
    /// the on-disk layout doesn't match the server's compile-time config.
    pub fn load_db(&mut self, path: &str) -> bool {
        let c = std::ffi::CString::new(path).expect("path contains NUL byte");
        unsafe { onion_server_load_db(self.h, c.as_ptr()) != 0 }
    }

    /// Zero-copy alias an already-formatted DB buffer. The buffer must outlive
    /// the server. Returns `false` on header mismatch / size mismatch.
    ///
    /// # Safety
    /// `data` must remain valid for the lifetime of the server. The server
    /// reads (but does not write) it during every query.
    pub unsafe fn load_db_from_borrowed(&mut self, data: &[u8]) -> bool {
        onion_server_load_db_from_borrowed(self.h, data.as_ptr(), data.len()) != 0
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        unsafe { onion_server_free(self.h) };
    }
}
