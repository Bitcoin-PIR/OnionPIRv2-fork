// End-to-end secret-key export/import via Java JNA. Mirrors the Rust
// client_secret_key_roundtrip integration test.

import com.onionpir.jna.OnionPirClient;
import com.onionpir.jna.OnionPirServer;

import java.util.Arrays;

public class ClientSkRoundTrip {
    public static void main(String[] args) {
        long ptIdx = 33L;

        try (OnionPirServer server = new OnionPirServer(0)) {
            server.genData(new long[]{ ptIdx });

            // Step 1: register original client's keys, query, capture golden.
            long originalId;
            byte[] sk;
            byte[] golden;
            try (OnionPirClient c = new OnionPirClient(0)) {
                originalId = c.id();
                sk = c.exportSecretKey();
                if (sk.length < 16) {
                    System.err.println("exported sk suspiciously small: " + sk.length);
                    System.exit(1);
                }
                server.setGaloisKeys(originalId, c.galoisKeys());
                server.setGswKey(originalId, c.gswKey());
                byte[] q = c.generateQuery(ptIdx);
                byte[] resp = server.answerQuery(originalId, q);
                golden = c.decryptResponse(resp);
            }

            // Step 2: rebuild a client from the exported sk with the same id.
            // The server still has the original galois/gsw key registered.
            OnionPirClient restored = OnionPirClient.fromSecretKey(0, originalId, sk);
            if (restored == null) {
                System.err.println("fromSecretKey returned null"); System.exit(1);
            }
            try (OnionPirClient r = restored) {
                if (r.id() != originalId) {
                    System.err.printf("id round-trip failed: %d -> %d%n",
                                       originalId, r.id());
                    System.exit(1);
                }
                byte[] q = r.generateQuery(ptIdx);
                byte[] resp = server.answerQuery(r.id(), q);
                byte[] dec = r.decryptResponse(resp);
                if (!Arrays.equals(dec, golden)) {
                    System.err.println("restored client PIR != golden");
                    System.exit(1);
                }
            }
            System.out.println("Client SK round-trip OK (sk=" + sk.length + " bytes)");
        }
    }
}
