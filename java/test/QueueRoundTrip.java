// Submit multiple queries to OnionPirQueue, poll until done, fetch + decrypt.
// Java mirror of the Rust query_queue_roundtrip test.

import com.onionpir.jna.OnionPirClient;
import com.onionpir.jna.OnionPirQueue;
import com.onionpir.jna.OnionPirServer;
import com.onionpir.jna.QueryStatus;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class QueueRoundTrip {
    public static void main(String[] args) throws InterruptedException {
        long[] targets = { 3L, 11L, 25L, 88L };

        try (OnionPirServer server = new OnionPirServer(0)) {
            server.genData(targets);

            try (OnionPirClient client = new OnionPirClient(0)) {
                long id = client.id();
                server.setGaloisKeys(id, client.galoisKeys());
                server.setGswKey(id, client.gswKey());

                // After this point we no longer touch the server directly.
                try (OnionPirQueue queue = new OnionPirQueue(server)) {
                    List<Long> tickets = new ArrayList<>();
                    List<byte[]> queries = new ArrayList<>();
                    for (long t : targets) queries.add(client.generateQuery(t));
                    for (byte[] q : queries) {
                        long ticket = queue.submit(id, q);
                        if (ticket == 0) { System.err.println("submit=0"); System.exit(1); }
                        tickets.add(ticket);
                    }

                    long deadlineNs = System.nanoTime() + 30L * 1_000_000_000L;
                    Map<Long, byte[]> done = new HashMap<>();
                    while (done.size() < tickets.size()) {
                        for (long t : tickets) {
                            if (done.containsKey(t)) continue;
                            QueryStatus s = queue.status(t);
                            if (s == QueryStatus.DONE) {
                                byte[] b = queue.result(t);
                                if (b == null) { System.err.println("result(DONE)=null"); System.exit(1); }
                                done.put(t, b);
                            } else if (s == QueryStatus.ERROR) {
                                byte[] err = queue.result(t);
                                System.err.println("ticket " + t + " ERROR: "
                                        + new String(err == null ? new byte[]{} : err));
                                System.exit(1);
                            } else if (s == QueryStatus.NOT_FOUND) {
                                System.err.println("ticket " + t + " not found");
                                System.exit(1);
                            }
                        }
                        if (System.nanoTime() > deadlineNs) {
                            System.err.println("timeout"); System.exit(1);
                        }
                        Thread.sleep(10);
                    }

                    queue.stop();

                    // submit after stop must return 0.
                    long postStop = queue.submit(id, queries.get(0));
                    if (postStop != 0) {
                        System.err.println("submit-after-stop=" + postStop);
                        System.exit(1);
                    }

                    for (int i = 0; i < tickets.size(); i++) {
                        byte[] resp = done.get(tickets.get(i));
                        if (resp.length == 0) {
                            System.err.println("empty response for ticket " + tickets.get(i));
                            System.exit(1);
                        }
                        byte[] pt = client.decryptResponse(resp);
                        if (pt.length == 0) {
                            System.err.println("empty decrypt for pt_idx " + targets[i]);
                            System.exit(1);
                        }
                    }
                    System.out.println("queue round-trip OK ("
                            + tickets.size() + " tickets)");
                }
            }
        }
    }
}
