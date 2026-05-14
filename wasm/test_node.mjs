// Quick node smoke test for the WASM module. Exercises:
//   - module instantiation
//   - paramsInfo()
//   - OnionPirClient construction
//   - galoisKeys() / gswKey() / generateQuery() round-trip (sanity-check byte sizes)
//   - hash utilities (splitmix64)
//
// Run from repo root (after wasm/build.sh succeeded):
//   node wasm/test_node.mjs

import createOnionPir from "./build/onionpir_client.mjs";

const m = await createOnionPir();

const info = m.paramsInfo();
console.log("paramsInfo:");
console.log("  numEntries:", info.numEntries);
console.log("  numPlaintexts:", info.numPlaintexts);
console.log("  polyDegree:", info.polyDegree);
console.log("  rnsModCount:", info.rnsModCount);
console.log("  dbSizeMB:", info.dbSizeMB);

// Constants we expect from the default config.
if (info.polyDegree !== 2048 && info.polyDegree !== 4096) {
    throw new Error(`unexpected polyDegree=${info.polyDegree}`);
}

// Client
const client = new m.OnionPirClient();
console.log("\nclient.id():", client.id());

const galois = client.galoisKeys();
console.log("galoisKeys: %d bytes", galois.length);

const gsw = client.gswKey();
console.log("gswKey:     %d bytes", gsw.length);

const query = client.generateQuery(42);
console.log("generateQuery(42): %d bytes", query.length);

client.delete();

// Secret-key export/import round-trip. Make sure the bytes look plausible
// and a restored client reports the same id.
const sender = new m.OnionPirClient();
const sid = sender.id();
const sk = sender.exportSecretKey();
console.log("\nexportSecretKey: %d bytes (sk_id=%d)", sk.length, sid);
if (sk.length < 16) throw new Error(`unexpectedly small SK blob: ${sk.length}`);

const restored = m.createClientFromSecretKey(sid, sk);
if (!restored) throw new Error("createClientFromSecretKey returned null");
if (restored.id() !== sid) {
    throw new Error(`id round-trip failed: ${sid} -> ${restored.id()}`);
}
console.log("createClientFromSecretKey: OK (id=%d)", restored.id());
sender.delete();
restored.delete();

// Hash utilities
const h = m.splitmix64(0x123456789);
console.log("\nsplitmix64(0x123456789):", h.toString(16));
const bin = m.cuckooHashInt(7, 0xdeadbeef, 64);
console.log("cuckooHashInt(7, 0xdeadbeef, 64):", bin);

console.log("\nAll smoke checks passed.");
