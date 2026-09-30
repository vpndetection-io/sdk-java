package io.vpndetection;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;
import java.util.concurrent.FutureTask;

/**
 * Concurrent misses for one address share one request, a lookup's or the batch chunk carrying it,
 * every other caller awaiting it. The stub holds each request until the test releases it, and a
 * call is only released once every thread is parked, so the calls under test are known to overlap.
 */
class SharedLookupTest {
    private static final String IP = "8.8.8.8";

    private static StubHttpClient.Route answer(String ip) {
        return StubHttpClient.Route.ok("{\"ip\": \"" + ip + "\", \"is_vpn\": false}");
    }

    @Test
    void concurrentLookupsOfOneAddressSendOneRequest() throws Exception {
        StubHttpClient http = StubHttpClient.gated(SharedLookupTest::answer);
        try (VPNDetection client = VPNDetection.builder().httpClient(http).build()) {
            List<Call<Result>> lookups = new ArrayList<>();
            for (int i = 0; i < 20; i++) {
                lookups.add(Call.start(() -> client.lookup(IP)));
            }
            http.awaitArrivals(1);
            Call.parked(lookups);
            http.release();
            for (Call<Result> lookup : lookups) {
                assertEquals(IP, lookup.get().ip());
            }
            assertEquals(1, http.calls.size());
        }
    }

    @Test
    void aFailureReachesEveryWaiterAndIsNotCached() throws Exception {
        StubHttpClient http = StubHttpClient.gated(
                ip -> new StubHttpClient.Route(500, "{\"error\": \"the stub failed\"}", Map.of()));
        try (VPNDetection client = VPNDetection.builder().httpClient(http).retries(0).build()) {
            List<Call<Result>> lookups = new ArrayList<>();
            for (int i = 0; i < 5; i++) {
                lookups.add(Call.start(() -> client.lookup(IP)));
            }
            http.awaitArrivals(1);
            Call.parked(lookups);
            http.release();
            for (Call<Result> lookup : lookups) {
                ExecutionException e = assertThrows(ExecutionException.class, lookup::get);
                assertEquals(ErrorKind.SERVER_ERROR, ((VPNDetectionException) e.getCause()).kind());
            }
            assertEquals(1, http.calls.size());
            assertThrows(VPNDetectionException.class, () -> client.lookup(IP));
            assertEquals(2, http.calls.size(), "a failure is never cached");
        }
    }

    @Test
    void aBatchAwaitsALookupAlreadyInFlight() throws Exception {
        StubHttpClient http = StubHttpClient.gated(SharedLookupTest::answer);
        try (VPNDetection client = VPNDetection.builder().httpClient(http).build()) {
            Call<Result> lookup = Call.start(() -> client.lookup(IP));
            http.awaitArrivals(1);
            Call<LinkedHashMap<String, BatchResult>> batch =
                    Call.start(() -> client.lookupBatch(List.of(IP, "1.1.1.1")));
            http.awaitArrivals(2);
            http.release();
            assertEquals(IP, lookup.get().ip());
            assertEquals(IP, batch.get().get(IP).orElseThrow().ip());
            assertEquals(List.of("1.1.1.1"), http.batchIps);
            assertEquals(2, http.calls.size());
        }
    }

    @Test
    void aLookupAwaitsABatchAlreadyCarryingItsAddress() throws Exception {
        StubHttpClient http = StubHttpClient.gated(SharedLookupTest::answer);
        try (VPNDetection client = VPNDetection.builder().httpClient(http).build()) {
            Call<LinkedHashMap<String, BatchResult>> batch =
                    Call.start(() -> client.lookupBatch(List.of(IP, "1.1.1.1")));
            http.awaitArrivals(1);
            Call<Result> lookup = Call.start(() -> client.lookup(IP));
            Call.parked(List.of(batch, lookup));
            http.release();
            assertEquals(IP, lookup.get().ip());
            assertTrue(batch.get().get(IP).isSuccess());
            assertEquals(1, http.calls.size());
        }
    }

    @Test
    void aWaiterWhoseLeaderIsInterruptedAsksAgain() throws Exception {
        StubHttpClient http = StubHttpClient.gated(SharedLookupTest::answer);
        try (VPNDetection client = VPNDetection.builder().httpClient(http).build()) {
            Call<Result> leader = Call.start(() -> client.lookup(IP));
            http.awaitArrivals(1);
            Call<Result> waiter = Call.start(() -> client.lookup(IP));
            Call.parked(List.of(leader, waiter));
            leader.thread.interrupt();
            assertThrows(ExecutionException.class, leader::get);
            http.awaitArrivals(2);
            http.release();
            assertEquals(IP, waiter.get().ip());
            assertEquals(2, http.calls.size());
        }
    }

    @Test
    void withTheCacheOffNothingIsShared() throws Exception {
        StubHttpClient http = StubHttpClient.gated(SharedLookupTest::answer);
        try (VPNDetection client = VPNDetection.builder().httpClient(http).cacheEnabled(false).build()) {
            List<Call<Result>> lookups = new ArrayList<>();
            for (int i = 0; i < 5; i++) {
                lookups.add(Call.start(() -> client.lookup(IP)));
            }
            http.awaitArrivals(5);
            http.release();
            for (Call<Result> lookup : lookups) {
                lookup.get();
            }
            assertEquals(5, http.calls.size());
        }
    }

    // A call on a thread of its own, so a test can interrupt it and see when it is parked.
    private static final class Call<T> {
        final Thread thread;
        final Future<T> result;

        private Call(Thread thread, Future<T> result) {
            this.thread = thread;
            this.result = result;
        }

        static <T> Call<T> start(java.util.concurrent.Callable<T> body) {
            FutureTask<T> task = new FutureTask<>(body);
            Thread thread = new Thread(task, "shared-lookup-test");
            thread.setDaemon(true);
            thread.start();
            return new Call<>(thread, task);
        }

        T get() throws Exception {
            return result.get(10, java.util.concurrent.TimeUnit.SECONDS);
        }

        // Waits until every call's thread is parked: waiting on a request, its own or another's.
        static void parked(List<? extends Call<?>> calls) throws InterruptedException {
            long until = System.nanoTime() + 10_000_000_000L;
            for (Call<?> call : calls) {
                while (call.thread.getState() != Thread.State.WAITING
                        && call.thread.getState() != Thread.State.TIMED_WAITING) {
                    if (System.nanoTime() > until) {
                        throw new AssertionError(call.thread.getState() + " is not parked");
                    }
                    Thread.sleep(1);
                }
            }
        }
    }
}
