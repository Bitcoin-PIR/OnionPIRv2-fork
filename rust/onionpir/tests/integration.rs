//! End-to-end PIR round-trip via the Rust crate.
//!
//! Run with `--test-threads=1` (or via `cargo test -- --test-threads=1`). The
//! native engine keeps unsynchronized static state (NTT object cache, timer
//! logger), so two tests running in parallel can hit a SIGTRAP. Serial
//! execution is the only correct way to run this suite.

use onionpir::{params_info, Client, Server};

#[test]
fn pir_roundtrip() {
    let info = params_info(0);
    println!(
        "Params: N={} K={} num_pt={} fst_dim={} other_dim={}",
        info.poly_degree, info.rns_mod_count, info.num_plaintexts,
        info.fst_dim_sz, info.other_dim_sz,
    );

    let targets: Vec<u64> = vec![0, 1, 7, 42, info.num_plaintexts - 1];

    let mut server = Server::new(0);
    server.gen_data(&targets);

    let mut failures = 0;
    for &pt_idx in &targets {
        let client = Client::new(0);
        let client_id = client.id();

        let galois = client.galois_keys();
        let gsw = client.gsw_key();
        server.set_galois_keys(client_id, &galois);
        server.set_gsw_key(client_id, &gsw);

        let query = client.generate_query(pt_idx);
        let response = server.answer_query(client_id, &query);
        let decrypted = client.decrypt_response(&response);
        let actual = server.get_original_plaintext(pt_idx);

        if decrypted != actual {
            eprintln!("MISMATCH at pt_idx={}: dec={}B actual={}B", pt_idx, decrypted.len(), actual.len());
            failures += 1;
        } else {
            println!("  pt_idx={}: OK ({} bytes)", pt_idx, decrypted.len());
        }
    }
    assert_eq!(failures, 0, "{} of {} queries failed", failures, targets.len());
}

/// Build a server, query for the golden plaintext, persist its DB, then
/// reconstruct fresh servers from the file (and from a borrowed buffer) and
/// verify the PIR response matches the golden plaintext on both paths.
#[test]
fn db_save_load_roundtrip() {
    let pt_idx: u64 = 99;
    let tmp_path = std::env::temp_dir().join(format!("onionpir-test-db-{}.bin", std::process::id()));
    let tmp = tmp_path.to_str().unwrap();
    let _ = std::fs::remove_file(&tmp_path);

    // Step 1: generate a DB, query for pt_idx, save the DB. The result is the
    // golden plaintext: every other load path must reproduce it.
    let golden = {
        let mut s = Server::new(0);
        s.gen_data(&[pt_idx]);
        let c = Client::new(0);
        s.set_galois_keys(c.id(), &c.galois_keys());
        s.set_gsw_key(c.id(), &c.gsw_key());
        let q = c.generate_query(pt_idx);
        let resp = s.answer_query(c.id(), &q);
        let pt = c.decrypt_response(&resp);
        assert_eq!(pt, s.get_original_plaintext(pt_idx),
                   "stage1: PIR result didn't match recorded plaintext");
        assert!(s.save_db(tmp), "save_db failed");
        pt
    };

    // Step 2: file-load path. NO gen_data — load_db is the only data source.
    {
        let mut s = Server::new(0);
        assert!(s.load_db(tmp), "load_db failed");
        let c = Client::new(0);
        s.set_galois_keys(c.id(), &c.galois_keys());
        s.set_gsw_key(c.id(), &c.gsw_key());
        let q = c.generate_query(pt_idx);
        let resp = s.answer_query(c.id(), &q);
        assert_eq!(c.decrypt_response(&resp), golden, "file-load PIR != golden");
    }

    // Step 3: borrowed-buffer path. Read the file into a Rust Vec and alias
    // it. `bytes` must outlive the server.
    let bytes = std::fs::read(&tmp_path).expect("read saved DB");
    {
        let mut s = Server::new(0);
        // SAFETY: `bytes` outlives `s` (both end at the closing brace).
        assert!(unsafe { s.load_db_from_borrowed(&bytes) },
                "load_db_from_borrowed failed");
        let c = Client::new(0);
        s.set_galois_keys(c.id(), &c.galois_keys());
        s.set_gsw_key(c.id(), &c.gsw_key());
        let q = c.generate_query(pt_idx);
        let resp = s.answer_query(c.id(), &q);
        assert_eq!(c.decrypt_response(&resp), golden, "borrowed-load PIR != golden");
    }

    let _ = std::fs::remove_file(&tmp_path);
}

/// Export a client's secret key, drop the client, reconstruct from the
/// exported bytes (with the same id), and verify the reconstructed client
/// answers queries identically. The server keeps the original key
/// registration; the restored client must match the same identity.
#[test]
fn client_secret_key_roundtrip() {
    let pt_idx: u64 = 33;
    let mut server = Server::new(0);
    server.gen_data(&[pt_idx]);

    // Step 1: register the original client's keys on the server, query, drop.
    let (original_id, sk_bytes, golden) = {
        let c = Client::new(0);
        let id = c.id();
        let sk = c.export_secret_key();
        assert!(!sk.is_empty(), "exported sk should be non-empty");
        server.set_galois_keys(id, &c.galois_keys());
        server.set_gsw_key(id, &c.gsw_key());
        let q = c.generate_query(pt_idx);
        let resp = server.answer_query(id, &q);
        let pt = c.decrypt_response(&resp);
        (id, sk, pt)
    }; // original client dropped here

    // Step 2: rebuild a client from the exported sk and the same id. The
    // server's registered galois/gsw keys still resolve under `original_id`.
    let restored = Client::from_secret_key(0, original_id, &sk_bytes)
        .expect("from_secret_key must accept its own exported bytes");
    assert_eq!(restored.id(), original_id, "id must round-trip");

    let q = restored.generate_query(pt_idx);
    let resp = server.answer_query(restored.id(), &q);
    let pt = restored.decrypt_response(&resp);
    assert_eq!(pt, golden,
               "restored client did not reproduce the original plaintext");
}
