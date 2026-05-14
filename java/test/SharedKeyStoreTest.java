// Two servers backed by one SharedKeyStore — Java mirror of the Rust
// shared_key_store_two_servers test.

import com.onionpir.jna.OnionKeyStore;
import com.onionpir.jna.OnionPirClient;
import com.onionpir.jna.OnionPirServer;

public class SharedKeyStoreTest {
    public static void main(String[] args) {
        long ptIdxA = 5L;
        long ptIdxB = 17L;

        try (OnionKeyStore store = new OnionKeyStore();
             OnionPirClient client = new OnionPirClient(0)) {
            long id = client.id();
            store.setGaloisKeys(id, client.galoisKeys());
            store.setGswKey(id, client.gswKey());
            if (!store.hasClient(id) || store.size() != 1) {
                System.err.println("registration: hasClient=" + store.hasClient(id)
                        + " size=" + store.size()); System.exit(1);
            }

            byte[] respA;
            try (OnionPirServer a = new OnionPirServer(0)) {
                a.genData(new long[]{ ptIdxA });
                a.setKeyStore(store);
                byte[] q = client.generateQuery(ptIdxA);
                respA = a.answerQuery(id, q);
                if (respA.length == 0) {
                    System.err.println("serverA answer empty"); System.exit(1);
                }
            }

            byte[] respB;
            try (OnionPirServer b = new OnionPirServer(0)) {
                b.genData(new long[]{ ptIdxB });
                b.setKeyStore(store);
                byte[] q = client.generateQuery(ptIdxB);
                respB = b.answerQuery(id, q);
                if (respB.length == 0) {
                    System.err.println("serverB answer empty"); System.exit(1);
                }
            }

            if (store.size() != 1) {
                System.err.println("size after queries: " + store.size()); System.exit(1);
            }

            // decrypt sanity check — just confirm the client can decrypt
            // both responses without errors.
            byte[] decA = client.decryptResponse(respA);
            byte[] decB = client.decryptResponse(respB);
            if (decA.length == 0 || decB.length == 0) {
                System.err.println("decrypt empty"); System.exit(1);
            }

            store.remove(id);
            if (store.hasClient(id) || store.size() != 0) {
                System.err.println("post-remove: hasClient=" + store.hasClient(id)
                        + " size=" + store.size()); System.exit(1);
            }
            System.out.println("Shared key store: two-server round-trip OK");
        }
    }
}
