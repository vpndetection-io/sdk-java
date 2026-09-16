package io.vpndetection;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import io.vpndetection.middleware.Core;
import io.vpndetection.middleware.Lookup;
import io.vpndetection.middleware.Options;
import io.vpndetection.model.Entitlement;
import io.vpndetection.model.EntitlementPlan;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;

import java.io.IOException;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.stream.Collectors;

/** The Java-specific API surface, as distinct from the shared corpus in {@link ConformanceTest}. */
class ClientTest {
    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static JsonNode data;

    private static final List<String> ADDRESSES = addresses(6001);

    @BeforeAll
    static void loadCorpus() throws IOException {
        data = MAPPER.readTree(Path.of("testdata", "testdata.json").toFile());
    }

    @Test
    void isBogonIsOnTheClientAndAgreesWithTheStandaloneForm() {
        try (VPNDetection client = VPNDetection.create()) {
            for (JsonNode c : data.get("isBogon")) {
                String ip = c.get("ip").asText();
                assertEquals(c.get("expect").asBoolean(), client.isBogon(ip),
                        ip + " (" + c.get("why").asText() + ")");
                assertEquals(Bogon.isBogon(ip), client.isBogon(ip),
                        ip + ": client and standalone form disagree");
            }
        }
    }

    @Test
    void batchConcurrencyIsConfigurablePerCall() {
        StubHttpClient http = StubHttpClient.echoing(Duration.ofMillis(20));
        try (VPNDetection client = VPNDetection.builder()
                .httpClient(http).cacheEnabled(false).build()) {
            client.lookupBatch(ADDRESSES, new BatchOptions().concurrency(3));

            assertEquals(7, http.calls.size(), "one request per chunk of 1000");
            assertTrue(http.peak.get() <= 3,
                    "peak in flight was " + http.peak.get() + ", expected at most 3");
            assertTrue(http.peak.get() > 1, "requests should still overlap");
        }
    }

    @Test
    void aPerCallConcurrencyOverridesTheClientDefault() {
        StubHttpClient http = StubHttpClient.echoing(Duration.ofMillis(20));
        // Instance default of 2, raised to 6 for this one batch.
        try (VPNDetection client = VPNDetection.builder()
                .httpClient(http).cacheEnabled(false).concurrency(2).build()) {
            client.lookupBatch(ADDRESSES, new BatchOptions().concurrency(6));

            assertTrue(http.peak.get() > 2,
                    "override ignored: peak was " + http.peak.get() + ", expected above 2");
            assertTrue(http.peak.get() <= 6,
                    "peak in flight was " + http.peak.get() + ", expected at most 6");
        }
    }

    @Test
    void withoutAnOverrideTheClientConcurrencyStillApplies() {
        StubHttpClient http = StubHttpClient.echoing(Duration.ofMillis(20));
        try (VPNDetection client = VPNDetection.builder()
                .httpClient(http).cacheEnabled(false).concurrency(2).build()) {
            client.lookupBatch(ADDRESSES);

            assertTrue(http.peak.get() <= 2,
                    "peak in flight was " + http.peak.get() + ", expected at most 2");
        }
    }

    @Test
    void retriesAreConfigurablePerCall() {
        StubHttpClient http = StubHttpClient.of(Map.of("9.9.9.9",
                new StubHttpClient.Route(500, "{\"error\": \"lookup failed\"}", Map.of())));
        try (VPNDetection client = VPNDetection.builder()
                .httpClient(http).cacheEnabled(false).retries(0).build()) {
            assertThrows(VPNDetectionException.class,
                    () -> client.lookup("9.9.9.9", new LookupOptions().retries(2)));

            // 1 initial attempt plus 2 retries, rather than the instance's 0.
            assertEquals(3, http.calls.size());
        }
    }

    // The transport here ignores the request's own timeout and outlasts every bound, so only a race
    // the client owns ends the call in time, and only the per-call bound names 200ms.
    @Test
    void aPerCallTimeoutBelowTheClientsFiresAsARetryableNetworkError() {
        StubHttpClient http = StubHttpClient.hanging();
        LookupOptions quick = new LookupOptions().requestTimeout(Duration.ofMillis(200));
        try (VPNDetection client = VPNDetection.builder().httpClient(http).cacheEnabled(false)
                .retries(0).requestTimeout(Duration.ofSeconds(10)).build()) {
            Map<String, Executable> calls = new LinkedHashMap<>();
            calls.put("lookup", () -> client.lookup("9.9.9.9", quick));
            calls.put("myIp", () -> client.myIp(quick));
            calls.put("myEntitlement", () -> client.myEntitlement(quick));

            for (Map.Entry<String, Executable> call : calls.entrySet()) {
                long started = System.nanoTime();
                VPNDetectionException e = assertThrows(VPNDetectionException.class, call.getValue());
                long took = Duration.ofNanos(System.nanoTime() - started).toMillis();

                assertEquals(ErrorKind.NETWORK, e.kind(), call.getKey());
                assertTrue(e.retryable(), call.getKey());
                assertTrue(e.getMessage().contains("after 200ms"), call.getKey() + ": " + e.getMessage());
                assertTrue(took < 5000, call.getKey() + " took " + took + "ms, past its own bound");
            }
        }
    }

    @Test
    void aPerCallTimeoutBoundsEveryChunkOfABatch() {
        StubHttpClient http = StubHttpClient.hanging();
        try (VPNDetection client = VPNDetection.builder().httpClient(http).cacheEnabled(false)
                .retries(0).requestTimeout(Duration.ofSeconds(10)).build()) {
            long started = System.nanoTime();
            LinkedHashMap<String, BatchResult> got = client.lookupBatch(addresses(1500),
                    new BatchOptions().requestTimeout(Duration.ofMillis(200)));
            long took = Duration.ofNanos(System.nanoTime() - started).toMillis();

            assertEquals(2, http.calls.size(), "one request per chunk");
            assertEquals(1500, got.size());
            for (BatchResult answer : got.values()) {
                VPNDetectionException e = answer.error().orElseThrow();
                assertEquals(ErrorKind.NETWORK, e.kind());
                assertTrue(e.getMessage().contains("after 200ms"), e.getMessage());
            }
            assertTrue(took < 5000, "the batch took " + took + "ms, past its own bound");
        }
    }

    // Per ATTEMPT: a timeout is retryable, and each retry starts a fresh budget rather than
    // inheriting whatever the first attempt left.
    @Test
    void aTimedOutAttemptIsRetriedWithAFreshBudget() {
        StubHttpClient http = StubHttpClient.hanging();
        try (VPNDetection client = VPNDetection.builder().httpClient(http).cacheEnabled(false)
                .retries(0).build()) {
            long started = System.nanoTime();
            assertThrows(VPNDetectionException.class, () -> client.lookup("9.9.9.9",
                    new LookupOptions().retries(2).requestTimeout(Duration.ofMillis(150))));
            long took = Duration.ofNanos(System.nanoTime() - started).toMillis();

            assertEquals(3, http.calls.size());
            assertTrue(took >= 450, "took " + took + "ms, less than three attempts of 150ms each");
        }
    }

    // An injected client keeps its own, looser bound; the request path's still applies per lookup.
    @Test
    void theMiddlewareTimeoutHoldsForAnInjectedClient() {
        try (VPNDetection client = VPNDetection.builder().httpClient(StubHttpClient.hanging())
                .cacheEnabled(false).requestTimeout(Duration.ofSeconds(10)).build()) {
            Core<String> core = new Core<>(new Options<String>().client(client)
                    .timeout(Duration.ofMillis(200)), request -> request);

            Lookup answer = core.evaluate("9.9.9.9");
            VPNDetectionException e = answer.error().orElseThrow();
            assertEquals(ErrorKind.NETWORK, e.kind());
            assertTrue(e.getMessage().contains("after 200ms"), e.getMessage());
            assertFalse(answer.isBlocked(), "a failed lookup fails open");
        }
    }

    @Test
    void aTimeoutMustBePositive() {
        assertThrows(IllegalArgumentException.class,
                () -> new LookupOptions().requestTimeout(Duration.ZERO));
        assertThrows(IllegalArgumentException.class,
                () -> VPNDetection.builder().requestTimeout(Duration.ofMillis(-1)));
    }

    // No cap on what one call takes: chunking to the endpoint's 1000 is the client's job.
    @Test
    void aBatchOfAnyLengthIsSentAsChunksOfAThousand() {
        List<String> ips = addresses(2500);
        StubHttpClient http = StubHttpClient.echoing(Duration.ZERO);
        try (VPNDetection client = VPNDetection.builder().httpClient(http).cacheEnabled(false).build()) {
            LinkedHashMap<String, BatchResult> got = client.lookupBatch(ips);

            assertEquals(3, http.calls.size(), "three requests in all");
            assertEquals(List.of(500, 1000, 1000),
                    http.batchSizes.stream().sorted().collect(Collectors.toList()),
                    "every request is a POST /batch of at most 1000");
            assertEquals(ips, new ArrayList<>(got.keySet()));
            for (String ip : ips) {
                assertEquals(ip, got.get(ip).orElseThrow().ip(), ip + " should be answered for itself");
            }
        }
    }

    @Test
    void aTierGatedFlagIsEmptyRatherThanFalse() {
        StubHttpClient http = StubHttpClient.of(Map.of(
                "1.1.1.1", StubHttpClient.Route.ok("{\"ip\": \"1.1.1.1\", \"is_vpn\": false}"),
                "8.8.8.8", StubHttpClient.Route.ok(
                        "{\"ip\": \"8.8.8.8\", \"is_vpn\": false, \"is_hosting\": false}")));

        try (VPNDetection client = VPNDetection.builder().httpClient(http).build()) {
            Result free = client.lookup("1.1.1.1");
            assertTrue(free.isHosting().isEmpty(), "a plan that omits the field answers nothing");
            assertFalse(free.isHosting().orElse(false), "orElse(false) still reads false");

            Result paid = client.lookup("8.8.8.8");
            assertEquals(Optional.of(false), paid.isHosting(),
                    "a plan that includes the field and answers false keeps the false");
        }
    }

    @Test
    void asyncLookupsResolveToTheSameAnswers() {
        StubHttpClient http = StubHttpClient.echoing(Duration.ofMillis(5));
        try (VPNDetection client = VPNDetection.builder().httpClient(http).build()) {
            assertEquals("1.1.1.1", client.lookupAsync("1.1.1.1").join().ip());

            LinkedHashMap<String, BatchResult> got = client.lookupBatchAsync(ADDRESSES).join();
            assertEquals(ADDRESSES, new ArrayList<>(got.keySet()));
            assertTrue(got.values().stream().allMatch(BatchResult::isSuccess));
        }
    }

    @Test
    void aSuppliedExecutorIsNotShutDownWithTheClient() {
        ExecutorService executor = Executors.newCachedThreadPool();
        try (VPNDetection client = VPNDetection.builder()
                .httpClient(StubHttpClient.echoing(Duration.ZERO)).executor(executor).build()) {
            client.lookup("1.1.1.1");
        }
        assertFalse(executor.isShutdown(), "the client must not close an executor it was handed");
        executor.shutdown();
    }

    // Enough addresses for seven chunks of the batch endpoint's 1000, so a concurrency bound has
    // something to bound: one request per chunk, and only the chunks overlap.
    private static List<String> addresses(int count) {
        List<String> out = new ArrayList<>(count);
        for (int i = 0; i < count; i++) {
            out.add("9." + (1 + i / 65536) + "." + (i / 256 % 256) + "." + (i % 256));
        }
        return List.copyOf(out);
    }
    private static final String ENTITLEMENT_BODY = """
            {
              "org_id": "85bb51e4-2eb6-4a31-8e4d-02ba8b98fe61",
              "apikey": {
                "id": "0ab424cc-7619-4dad-b027-afacdc2cedb0",
                "expires": null,
                "allowed_cidrs": []
              },
              "plan": {"key": "max", "tier": "max"},
              "usage": {
                "requests": 580,
                "quota": 5000000,
                "hard_limit": null,
                "window_start": "2026-09-04T07:00:00Z",
                "window_end": "2026-10-04T07:00:00Z"
              }
            }
            """;

    @Test
    void myIpClassifiesTheCallingAddress() {
        StubHttpClient http = StubHttpClient.of(Map.of(
                "myip", StubHttpClient.Route.ok("{\"ip\": \"45.83.91.1\", \"is_vpn\": true}")));

        try (VPNDetection client = VPNDetection.builder().httpClient(http).build()) {
            Result result = client.myIp();
            assertEquals("45.83.91.1", result.ip());
            assertTrue(result.isVpn());
        }
    }

    @Test
    void myIpIsNotCached() {
        // The cache is keyed by address, and which address this is IS the question.
        StubHttpClient http = StubHttpClient.of(Map.of(
                "myip", StubHttpClient.Route.ok("{\"ip\": \"45.83.91.1\", \"is_vpn\": true}")));

        try (VPNDetection client = VPNDetection.builder().httpClient(http).build()) {
            client.myIp();
            client.myIp();
            assertEquals(2, http.calls.size());
        }
    }

    @Test
    void myEntitlementReportsThePlanAndTheUsage() {
        StubHttpClient http = StubHttpClient.of(Map.of(
                "api/v1/entitlement", StubHttpClient.Route.ok(ENTITLEMENT_BODY)));

        try (VPNDetection client = VPNDetection.builder().httpClient(http).build()) {
            Entitlement ent = client.myEntitlement();
            assertEquals("max", ent.getPlan().getKey());
            assertEquals(EntitlementPlan.TierEnum.MAX, ent.getPlan().getTier());
            assertEquals(580L, ent.getUsage().getRequests());
            assertEquals(5000000L, ent.getUsage().getQuota());
            // Null means NEVER stop, which is not the same as a limit of zero.
            assertNull(ent.getUsage().getHardLimit());
            assertTrue(ent.getApikey().getAllowedCidrs().isEmpty());
        }
    }

    @Test
    void myEntitlementIsNotCached() {
        // The whole point is what has been spent.
        StubHttpClient http = StubHttpClient.of(Map.of(
                "api/v1/entitlement", StubHttpClient.Route.ok(ENTITLEMENT_BODY)));

        try (VPNDetection client = VPNDetection.builder().httpClient(http).build()) {
            client.myEntitlement();
            client.myEntitlement();
            assertEquals(2, http.calls.size());
        }
    }

    @Test
    void myEntitlementSurfacesAnUnauthorizedKey() {
        StubHttpClient http = StubHttpClient.of(Map.of(
                "api/v1/entitlement",
                new StubHttpClient.Route(401, "{\"error\": \"invalid API key\"}", Map.of())));

        try (VPNDetection client = VPNDetection.builder().httpClient(http).retries(0).build()) {
            assertThrows(VPNDetectionException.class, client::myEntitlement);
        }
    }

}
