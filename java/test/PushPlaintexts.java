// End-to-end push_plaintexts via Java JNA. Mirrors the Rust
// push_plaintexts_roundtrip test.

import com.onionpir.jna.OnionPir;
import com.onionpir.jna.OnionPirClient;
import com.onionpir.jna.OnionPirServer;
import com.onionpir.jna.PirParamsInfo;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

public class PushPlaintexts {
    public static void main(String[] args) {
        PirParamsInfo info = OnionPir.paramsInfo(0);
        int n = (int) info.polyDegree;
        long ptIdx = 17L;

        try (OnionPirServer server = new OnionPirServer(0)) {
            server.genData(new long[]{ ptIdx });

            // Build a deterministic plaintext: coeff[i] = i & 0xff.
            long[] payload = new long[n];
            for (int i = 0; i < n; i++) payload[i] = i & 0xff;
            if (!server.pushPlaintexts(payload, 1L, ptIdx, new long[]{ ptIdx })) {
                System.err.println("pushPlaintexts failed"); System.exit(1);
            }

            try (OnionPirClient c = new OnionPirClient(0)) {
                long id = c.id();
                server.setGaloisKeys(id, c.galoisKeys());
                server.setGswKey(id, c.gswKey());
                byte[] q = c.generateQuery(ptIdx);
                byte[] resp = server.answerQuery(id, q);
                byte[] decrypted = c.decryptResponse(resp);
                byte[] recorded = server.getOriginalPlaintext(ptIdx);
                if (!java.util.Arrays.equals(decrypted, recorded)) {
                    System.err.println("PIR != recorded"); System.exit(1);
                }
                // Verify the recorded plaintext matches the pushed pattern.
                ByteBuffer bb = ByteBuffer.wrap(recorded).order(ByteOrder.LITTLE_ENDIAN);
                int nFromHeader = bb.getInt();
                if (nFromHeader != n) {
                    System.err.println("N mismatch: " + nFromHeader + " vs " + n);
                    System.exit(1);
                }
                for (int i = 0; i < Math.min(n, 16); i++) {
                    long coeff = bb.getLong();
                    if (coeff != (long)(i & 0xff)) {
                        System.err.printf("coeff[%d] = %d, want %d%n",
                                          i, coeff, i & 0xff);
                        System.exit(1);
                    }
                }
                System.out.println("push_plaintexts round-trip OK");
            }
        }
    }
}
