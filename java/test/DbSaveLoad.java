// End-to-end save/load round-trip via Java JNA. Mirrors the Rust
// db_save_load_roundtrip integration test.

import com.onionpir.jna.OnionPir;
import com.onionpir.jna.OnionPirClient;
import com.onionpir.jna.OnionPirServer;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;

public class DbSaveLoad {
    public static void main(String[] args) throws IOException {
        long ptIdx = 99L;
        // Right-size each server for a small DB so the saved file fits
        // in Java's Files.readAllBytes 2GB cap and the test is fast.
        // Exercises the per-instance num_pt feature (PirParams ctor with
        // a runtime target).
        final long SMALL_DB = 1024L;
        Path tmp = Path.of(System.getProperty("java.io.tmpdir"),
                "onionpir-java-test-" + ProcessHandle.current().pid() + ".bin");
        Files.deleteIfExists(tmp);

        // Step 1: gen, query (golden), save.
        byte[] golden;
        try (OnionPirServer server = new OnionPirServer(SMALL_DB)) {
            server.genData(new long[]{ ptIdx });
            try (OnionPirClient client = new OnionPirClient(SMALL_DB)) {
                long id = client.id();
                server.setGaloisKeys(id, client.galoisKeys());
                server.setGswKey(id, client.gswKey());
                byte[] q = client.generateQuery(ptIdx);
                byte[] resp = server.answerQuery(id, q);
                golden = client.decryptResponse(resp);
                byte[] actual = server.getOriginalPlaintext(ptIdx);
                if (!Arrays.equals(golden, actual)) {
                    System.err.println("step1: PIR != recorded plaintext");
                    System.exit(1);
                }
                if (!server.saveDb(tmp.toString())) {
                    System.err.println("saveDb failed");
                    System.exit(1);
                }
            }
        }

        // Step 2: file-load path. No genData.
        try (OnionPirServer server = new OnionPirServer(SMALL_DB)) {
            if (!server.loadDb(tmp.toString())) {
                System.err.println("loadDb failed"); System.exit(1);
            }
            try (OnionPirClient client = new OnionPirClient(SMALL_DB)) {
                long id = client.id();
                server.setGaloisKeys(id, client.galoisKeys());
                server.setGswKey(id, client.gswKey());
                byte[] q = client.generateQuery(ptIdx);
                byte[] resp = server.answerQuery(id, q);
                byte[] dec = client.decryptResponse(resp);
                if (!Arrays.equals(dec, golden)) {
                    System.err.println("file-load PIR != golden"); System.exit(1);
                }
                System.out.println("file-load: OK");
            }
        }

        // Step 3: borrowed-buffer path.
        byte[] bytes = Files.readAllBytes(tmp);
        try (OnionPirServer server = new OnionPirServer(SMALL_DB)) {
            if (!server.loadDbFromBorrowed(bytes)) {
                System.err.println("loadDbFromBorrowed failed"); System.exit(1);
            }
            try (OnionPirClient client = new OnionPirClient(SMALL_DB)) {
                long id = client.id();
                server.setGaloisKeys(id, client.galoisKeys());
                server.setGswKey(id, client.gswKey());
                byte[] q = client.generateQuery(ptIdx);
                byte[] resp = server.answerQuery(id, q);
                byte[] dec = client.decryptResponse(resp);
                if (!Arrays.equals(dec, golden)) {
                    System.err.println("borrowed-load PIR != golden"); System.exit(1);
                }
                System.out.println("borrowed-load: OK");
            }
        }

        Files.deleteIfExists(tmp);
        System.out.println("All save/load paths OK");
    }
}
