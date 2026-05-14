//! End-to-end PIR round-trip via the Rust crate.

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
