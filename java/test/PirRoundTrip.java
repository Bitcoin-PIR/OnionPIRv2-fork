// End-to-end PIR round-trip via the Java JNA bindings. Mirrors
// rust/onionpir/tests/integration.rs.
//
// Build + run via java/build.sh (handles JNA jar + library path).

import com.onionpir.jna.OnionPir;
import com.onionpir.jna.OnionPirClient;
import com.onionpir.jna.OnionPirServer;
import com.onionpir.jna.PirParamsInfo;

import java.util.Arrays;

public class PirRoundTrip {
    public static void main(String[] args) {
        PirParamsInfo info = OnionPir.paramsInfo(0);
        System.out.printf(
                "Params: N=%d K=%d num_pt=%d fst_dim=%d other_dim=%d%n",
                info.polyDegree, info.rnsModCount, info.numPlaintexts,
                info.fstDimSz, info.otherDimSz);

        long[] targets = { 0L, 1L, 7L, 42L, info.numPlaintexts - 1 };

        try (OnionPirServer server = new OnionPirServer(0)) {
            server.genData(targets);

            int failures = 0;
            for (long ptIdx : targets) {
                try (OnionPirClient client = new OnionPirClient(0)) {
                    long clientId = client.id();
                    server.setGaloisKeys(clientId, client.galoisKeys());
                    server.setGswKey(clientId, client.gswKey());

                    byte[] query = client.generateQuery(ptIdx);
                    byte[] response = server.answerQuery(clientId, query);
                    byte[] decrypted = client.decryptResponse(response);
                    byte[] actual = server.getOriginalPlaintext(ptIdx);

                    if (!Arrays.equals(decrypted, actual)) {
                        System.out.printf(
                                "  pt_idx=%d: MISMATCH (decrypted=%d B actual=%d B)%n",
                                ptIdx, decrypted.length, actual.length);
                        failures++;
                    } else {
                        System.out.printf(
                                "  pt_idx=%d: OK (%d bytes)%n",
                                ptIdx, decrypted.length);
                    }
                }
            }
            if (failures > 0) {
                System.out.printf("%d failures of %d%n", failures, targets.length);
                System.exit(1);
            }
            System.out.printf("All %d queries OK%n", targets.length);
        }
    }
}
