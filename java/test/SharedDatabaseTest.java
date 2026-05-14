// Indirect DB mode via Java JNA. Java mirror of the Rust
// shared_database_identity_index_table test.

import com.onionpir.jna.OnionPir;
import com.onionpir.jna.OnionPirClient;
import com.onionpir.jna.OnionPirServer;
import com.onionpir.jna.PirParamsInfo;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;

public class SharedDatabaseTest {
    public static void main(String[] args) throws IOException {
        // Right-size both servers so the shared store fits in Java's
        // Files.readAllBytes 2GB cap, and the test is fast.
        final long SMALL_DB = 1024L;
        PirParamsInfo info = OnionPir.paramsInfo(SMALL_DB);
        if (info.rnsModCount != 1) {
            System.out.println("skipping: shared_database needs K=1");
            return;
        }
        long ptIdx = 12L;
        int numPt = (int) info.numPlaintexts;

        Path tmp = Path.of(System.getProperty("java.io.tmpdir"),
                "onionpir-java-shared-" + ProcessHandle.current().pid() + ".bin");
        Files.deleteIfExists(tmp);

        // Step 1: build + golden + save.
        byte[] golden;
        try (OnionPirServer s = new OnionPirServer(SMALL_DB);
             OnionPirClient c = new OnionPirClient(SMALL_DB)) {
            s.genData(new long[]{ ptIdx });
            long id = c.id();
            s.setGaloisKeys(id, c.galoisKeys());
            s.setGswKey(id, c.gswKey());
            byte[] q = c.generateQuery(ptIdx);
            byte[] resp = s.answerQuery(id, q);
            golden = c.decryptResponse(resp);
            if (!s.saveDb(tmp.toString())) {
                System.err.println("saveDb failed"); System.exit(1);
            }
        }

        // Step 2: read file, skip 48-byte header, reinterpret as long[].
        byte[] raw = Files.readAllBytes(tmp);
        if (raw.length <= 48) { System.err.println("file too small"); System.exit(1); }
        int n = (raw.length - 48) / 8;
        long[] store = new long[n];
        ByteBuffer bb = ByteBuffer.wrap(raw, 48, raw.length - 48)
                .order(ByteOrder.LITTLE_ENDIAN);
        for (int i = 0; i < n; i++) store[i] = bb.getLong();

        // Identity index table.
        int[] indexTable = new int[numPt];
        for (int i = 0; i < numPt; i++) indexTable[i] = i;

        // Step 3: serving server via shared store.
        try (OnionPirServer s = new OnionPirServer(SMALL_DB);
             OnionPirClient c = new OnionPirClient(SMALL_DB)) {
            if (!s.setSharedDatabase(store, numPt, indexTable)) {
                System.err.println("setSharedDatabase failed"); System.exit(1);
            }
            long id = c.id();
            s.setGaloisKeys(id, c.galoisKeys());
            s.setGswKey(id, c.gswKey());
            byte[] q = c.generateQuery(ptIdx);
            byte[] resp = s.answerQuery(id, q);
            byte[] dec = c.decryptResponse(resp);
            if (!Arrays.equals(dec, golden)) {
                System.err.println("shared-DB PIR != golden"); System.exit(1);
            }
        }

        Files.deleteIfExists(tmp);
        System.out.println("Shared database (identity index table): OK");
    }
}
