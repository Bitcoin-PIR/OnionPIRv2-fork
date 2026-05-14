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

// Hash utilities
const h = m.splitmix64(0x123456789);
console.log("\nsplitmix64(0x123456789):", h.toString(16));
const bin = m.cuckooHashInt(7, 0xdeadbeef, 64);
console.log("cuckooHashInt(7, 0xdeadbeef, 64):", bin);

console.log("\nAll smoke checks passed.");
