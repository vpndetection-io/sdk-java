package io.vpndetection;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import io.vpndetection.model.AccountMe;
import io.vpndetection.model.AccountPlan;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

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

/** The Java-specific API surface, as distinct from the shared corpus in {@link ConformanceTest}. */
class ClientTest {
    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static JsonNode data;

    private static final List<String> ADDRESSES = addresses(12);

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

            assertEquals(ADDRESSES.size(), http.calls.size());
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

    private static List<String> addresses(int count) {
        List<String> out = new ArrayList<>(count);
        for (int i = 1; i <= count; i++) {
            out.add("9.9.9." + i);
        }
        return List.copyOf(out);
    }
    private static final String ACCOUNT_BODY = """
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
    void myAccountReportsThePlanAndTheUsage() {
        StubHttpClient http = StubHttpClient.of(Map.of(
                "api/v1/account/me", StubHttpClient.Route.ok(ACCOUNT_BODY)));

        try (VPNDetection client = VPNDetection.builder().httpClient(http).build()) {
            AccountMe account = client.myAccount();
            assertEquals("max", account.getPlan().getKey());
            assertEquals(AccountPlan.TierEnum.MAX, account.getPlan().getTier());
            assertEquals(580L, account.getUsage().getRequests());
            assertEquals(5000000L, account.getUsage().getQuota());
            // Null means NEVER stop, which is not the same as a limit of zero.
            assertNull(account.getUsage().getHardLimit());
            assertTrue(account.getApikey().getAllowedCidrs().isEmpty());
        }
    }

    @Test
    void myAccountIsNotCached() {
        // The whole point is what has been spent.
        StubHttpClient http = StubHttpClient.of(Map.of(
                "api/v1/account/me", StubHttpClient.Route.ok(ACCOUNT_BODY)));

        try (VPNDetection client = VPNDetection.builder().httpClient(http).build()) {
            client.myAccount();
            client.myAccount();
            assertEquals(2, http.calls.size());
        }
    }

    @Test
    void myAccountSurfacesAnUnauthorizedKey() {
        StubHttpClient http = StubHttpClient.of(Map.of(
                "api/v1/account/me",
                new StubHttpClient.Route(401, "{\"error\": \"invalid API key\"}", Map.of())));

        try (VPNDetection client = VPNDetection.builder().httpClient(http).retries(0).build()) {
            assertThrows(VPNDetectionException.class, client::myAccount);
        }
    }

}
