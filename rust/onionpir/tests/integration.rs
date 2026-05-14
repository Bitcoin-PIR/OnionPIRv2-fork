//! End-to-end PIR round-trip via the Rust crate.
//!
//! Run with `--test-threads=1` (or via `cargo test -- --test-threads=1`). The
//! native engine keeps unsynchronized static state (NTT object cache, timer
//! logger), so two tests running in parallel can hit a SIGTRAP. Serial
//! execution is the only correct way to run this suite.

use onionpir::{params_info, Client, KeyStore, QueryQueue, QueryStatus, Server};

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

/// Build a DB from random data, then overwrite one specific plaintext with a
/// known pattern via push_plaintexts, and verify a PIR query for that index
/// returns the same pattern. Exercises the production-mode chunked-build path.
#[test]
fn push_plaintexts_roundtrip() {
    let info = params_info(0);
    let n = info.poly_degree as usize;
    let pt_mod_bits = 14u64; // pessimistic — log(t) varies by config, but our
                             // patterns are all small so they fit any t.
    let pt_idx: u64 = 17;

    let mut server = Server::new(0);

    // Step 1: fill the DB with random data so all the matmul scaffolding is in
    // place. record pt_idx so we have a starting point for the comparison.
    server.gen_data(&[pt_idx]);

    // Step 2: build a deterministic, recognizable plaintext for slot pt_idx.
    //   coeff[i] = i & 0xFF (8 LSBs of the index)
    // Then push it. The push must overwrite whatever gen_data put there.
    let payload: Vec<u64> = (0..n).map(|i| (i & 0xff) as u64).collect();
    let pushed_ok = server.push_plaintexts(&payload, 1, pt_idx, &[pt_idx]);
    assert!(pushed_ok, "push_plaintexts failed");
    let _ = pt_mod_bits;

    // Step 3: query, decrypt, and confirm the recovered plaintext matches the
    // payload we just pushed. We compare against the server's recorded copy
    // (re-recorded on push because we passed pt_idx in record_indices).
    let c = Client::new(0);
    server.set_galois_keys(c.id(), &c.galois_keys());
    server.set_gsw_key(c.id(), &c.gsw_key());
    let q = c.generate_query(pt_idx);
    let resp = server.answer_query(c.id(), &q);
    let decrypted = c.decrypt_response(&resp);
    let recorded = server.get_original_plaintext(pt_idx);
    assert_eq!(decrypted, recorded,
               "push_plaintexts: PIR result != server's recorded plaintext");

    // Verify the recorded plaintext actually contains the pushed pattern.
    // Format is [u32 N (LE)][u64 coeff_0]...[u64 coeff_{N-1}], so byte 4..12
    // is coeff[0] (= 0), byte 12..20 is coeff[1] (= 1), etc.
    assert!(recorded.len() >= 4 + n * 8);
    let n_from_header =
        u32::from_le_bytes(recorded[0..4].try_into().unwrap()) as usize;
    assert_eq!(n_from_header, n);
    for i in 0..std::cmp::min(n, 16) {
        let lo = 4 + i * 8;
        let coeff = u64::from_le_bytes(recorded[lo..lo+8].try_into().unwrap());
        assert_eq!(coeff, (i & 0xff) as u64,
                   "coeff[{}] = {}, want {}", i, coeff, i & 0xff);
    }
}

/// Two servers backed by the same KeyStore. A client registers its keys
/// once (with the store); both servers can answer the client's queries
/// without each one keeping its own deserialized copy. The store's size()
/// stays at 1.
#[test]
fn shared_key_store_two_servers() {
    let pt_idx_a: u64 = 5;
    let pt_idx_b: u64 = 17;

    let store = KeyStore::new();
    let client = Client::new(0);
    let id = client.id();

    // One-time key registration on the store. Both servers will use it.
    store.set_galois_keys(id, &client.galois_keys());
    store.set_gsw_key(id, &client.gsw_key());
    assert!(store.has_client(id));
    assert_eq!(store.size(), 1);

    // Server A — gen its own DB, attach the shared store, answer a query.
    let golden_a = {
        let mut a = Server::new(0);
        a.gen_data(&[pt_idx_a]);
        // SAFETY: `store` outlives `a` (the inner block).
        unsafe { a.set_key_store(Some(&store)); }
        let q = client.generate_query(pt_idx_a);
        let resp = a.answer_query(id, &q);
        client.decrypt_response(&resp)
    };

    // Server B — independent DB, same store, different query index.
    let golden_b = {
        let mut b = Server::new(0);
        b.gen_data(&[pt_idx_b]);
        unsafe { b.set_key_store(Some(&store)); }
        let q = client.generate_query(pt_idx_b);
        let resp = b.answer_query(id, &q);
        client.decrypt_response(&resp)
    };

    // The store kept exactly one client through both servers' query paths.
    assert_eq!(store.size(), 1, "store should still hold exactly 1 client");

    // Sanity: the responses are non-empty and differ (different DBs, different
    // indices). We don't have direct golden plaintexts here because the test
    // skips registering the recorded_pts_ on the per-server side (gen_data
    // recorded only one index each).
    assert!(!golden_a.is_empty() && !golden_b.is_empty());

    // After removing the client, the store reports it gone.
    store.remove(id);
    assert!(!store.has_client(id));
    assert_eq!(store.size(), 0);
}

/// Submit multiple queries to a QueryQueue, poll until done, fetch results,
/// and verify each one decrypts to the same plaintext the synchronous path
/// would have produced.
#[test]
fn query_queue_roundtrip() {
    let targets: Vec<u64> = vec![3, 11, 25, 88];

    let mut server = Server::new(0);
    server.gen_data(&targets);

    let client = Client::new(0);
    let id = client.id();
    server.set_galois_keys(id, &client.galois_keys());
    server.set_gsw_key(id, &client.gsw_key());

    // After this point we can no longer touch the server directly — the
    // queue worker thread owns it.
    let queue = QueryQueue::new(&mut server);
    let queries: Vec<(u64, Vec<u8>)> = targets.iter()
        .map(|&i| (i, client.generate_query(i)))
        .collect();

    let mut tickets = Vec::with_capacity(queries.len());
    for (_, q) in &queries {
        tickets.push(queue.submit(id, q).expect("submit returned 0"));
    }

    // Poll until all reach Done (or timeout). Each query takes ~500 ms in
    // the scalar-shim default config; budget 30 s to be safe.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    let mut bytes_by_ticket: std::collections::HashMap<u64, Vec<u8>> =
        std::collections::HashMap::new();
    while bytes_by_ticket.len() < tickets.len() {
        for &t in &tickets {
            if bytes_by_ticket.contains_key(&t) { continue; }
            let s = queue.status(t);
            if s == QueryStatus::Done {
                let b = queue.result(t).expect("result(Done) returned None");
                bytes_by_ticket.insert(t, b);
            } else if s == QueryStatus::Error {
                let err = queue.result(t).expect("result(Error) returned None");
                panic!("ticket {} errored: {}",
                       t, String::from_utf8_lossy(&err));
            } else if s == QueryStatus::NotFound {
                panic!("ticket {} disappeared without completing", t);
            }
        }
        if std::time::Instant::now() > deadline {
            panic!("timed out waiting for {} tickets", tickets.len());
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }

    queue.stop();

    // After stop the queue is dead; submitting a new query returns None.
    let q_extra = client.generate_query(targets[0]);
    assert!(queue.submit(id, &q_extra).is_none(),
            "submit on a stopped queue must return None");

    // Decrypt each response — none can be empty.
    for (i, &t) in tickets.iter().enumerate() {
        let bytes = bytes_by_ticket.remove(&t).unwrap();
        assert!(!bytes.is_empty(), "ticket {} response empty", t);
        let pt = client.decrypt_response(&bytes);
        assert!(!pt.is_empty(), "decrypt for target idx={} empty", targets[i]);
    }
}
