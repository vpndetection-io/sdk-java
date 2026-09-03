package io.vpndetection;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import io.vpndetection.internal.ApiClient;
import io.vpndetection.model.ClassDetail;
import io.vpndetection.model.ProxyDetail;
import io.vpndetection.model.VpnDetail;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Asserts the shared conformance corpus that every VPNDetection SDK asserts.
 *
 * <p>The corpus is generated into testdata/ and is identical across languages, so a behaviour that
 * drifts here fails here rather than surfacing as two client libraries quietly disagreeing about
 * the same address.
 */
class ConformanceTest {
    // The generated models carry java.time.LocalDate, so a bare ObjectMapper cannot read one
    // back. This is the same mapper the client itself deserializes responses with.
    private static final ObjectMapper MAPPER = ApiClient.createDefaultObjectMapper();
    private static JsonNode data;

    @BeforeAll
    static void loadCorpus() throws IOException {
        data = MAPPER.readTree(Path.of("testdata", "testdata.json").toFile());
    }

    @Test
    void isBogonMatchesTheCanonicalRanges() {
        for (JsonNode c : data.get("isBogon")) {
            String ip = c.get("ip").asText();
            assertEquals(c.get("expect").asBoolean(), Bogon.isBogon(ip),
                    ip + " (" + c.get("why").asText() + ")");
        }
    }

    @Test
    void aBogonIsAnsweredLocallyInTheFullMaxShape() {
        StubHttpClient http = StubHttpClient.of(Map.of());
        try (VPNDetection client = clientOn(http).build()) {
            Result r = client.lookup("10.0.0.1");

            assertTrue(r.isBogon());
            assertEquals("10.0.0.1", r.ip());
            for (JsonNode flag : data.get("bogonResponse").get("flagsFalse")) {
                String name = flag.asText();
                Optional<?> value = member(r, name);
                assertTrue(value.isPresent(), name + " must be present");
                assertEquals(Boolean.FALSE, value.get(), name + " must be present and false");
            }
            for (JsonNode object : data.get("bogonResponse").get("emptyObjects")) {
                String name = object.asText();
                Optional<?> value = member(r, name);
                assertTrue(value.isPresent(), name + " must be present");
                assertEquals(emptyDetail(name), value.get(), name + " must be present and empty");
            }
            assertEquals(0, http.calls.size(), "a bogon must not reach the network");
        }
    }

    @Test
    void lookupPreservesAbsentVersusFalseAcrossEveryPlanShape() throws IOException {
        for (JsonNode c : data.get("lookup")) {
            String name = c.get("name").asText();
            JsonNode body = c.get("body");
            String ip = body.get("ip").asText();
            StubHttpClient http = StubHttpClient.of(Map.of(ip, new StubHttpClient.Route(
                    c.get("status").asInt(), MAPPER.writeValueAsString(body), Map.of())));

            try (VPNDetection client = clientOn(http).build()) {
                Result r = client.lookup(ip);
                JsonNode expect = c.get("expect");

                assertEquals(expect.get("ip").asText(), r.ip(), name);
                assertEquals(expect.get("isBogon").asBoolean(), r.isBogon(), name);

                JsonNode present = expect.get("present");
                if (present != null) {
                    present.fieldNames().forEachRemaining(field -> {
                        Optional<?> value = member(r, field);
                        assertTrue(value.isPresent(), name + ": " + field + " should be present");
                        assertEquals(present.get(field).asBoolean(), value.get(),
                                name + ": " + field);
                    });
                }
                for (JsonNode absent : orEmpty(expect.get("absent"))) {
                    assertTrue(member(r, absent.asText()).isEmpty(),
                            name + ": " + absent.asText() + " must be ABSENT, not false");
                }
                for (JsonNode empty : orEmpty(expect.get("emptyPresent"))) {
                    String field = empty.asText();
                    assertEquals(emptyDetail(field), member(r, field).orElse(null),
                            name + ": " + field + " must be present and empty");
                }
                for (String detail : List.of("vpn", "hosting", "dcproxy")) {
                    if (expect.get(detail) != null) {
                        assertEquals(MAPPER.treeToValue(expect.get(detail), detailType(detail)),
                                member(r, detail).orElse(null), name + ": " + detail);
                    }
                }
            }
        }
    }

    @Test
    void a429IsClassifiedByRetryAfterNotByItsStatus() throws IOException {
        for (JsonNode c : data.get("errors")) {
            String name = c.get("name").asText();
            Map<String, String> headers = new HashMap<>();
            c.get("headers").fieldNames().forEachRemaining(
                    h -> headers.put(h, c.get("headers").get(h).asText()));
            StubHttpClient http = StubHttpClient.of(Map.of("1.1.1.1", new StubHttpClient.Route(
                    c.get("status").asInt(), MAPPER.writeValueAsString(c.get("body")), headers)));

            // No retries, so a retryable error still surfaces rather than looping.
            try (VPNDetection client = clientOn(http).retries(0).build()) {
                JsonNode expect = c.get("expect");
                VPNDetectionException err = assertThrows(VPNDetectionException.class,
                        () -> client.lookup("1.1.1.1"), name);

                assertEquals(ErrorKind.valueOf(expect.get("kind").asText().toUpperCase()),
                        err.kind(), name);
                assertEquals(expect.get("retryable").asBoolean(), err.retryable(),
                        name + ": retryable");
                if (expect.get("message") != null) {
                    assertEquals(expect.get("message").asText(), err.getMessage(),
                            name + ": message");
                }
                if (expect.get("retryAfterSeconds") != null) {
                    assertEquals(expect.get("retryAfterSeconds").asLong(),
                            err.retryAfter().orElseThrow().toSeconds(), name);
                }
            }
        }
    }

    @Test
    void batchDedupesShortCircuitsBogonsAndKeysByAddress() {
        JsonNode c = batchCase("dedup-bogon-and-order-free-keying");
        StubHttpClient http = StubHttpClient.of(Map.of(
                "1.1.1.1", StubHttpClient.Route.ok("{\"ip\": \"1.1.1.1\", \"is_vpn\": false}"),
                "8.8.8.8", StubHttpClient.Route.ok("{\"ip\": \"8.8.8.8\", \"is_vpn\": false}")));

        try (VPNDetection client = clientOn(http).build()) {
            LinkedHashMap<String, BatchResult> got = client.lookupBatch(strings(c.get("input")));
            JsonNode expect = c.get("expect");

            assertEquals(strings(expect.get("keys")), new ArrayList<>(got.keySet()));
            assertEquals(expect.get("httpRequests").asInt(), http.calls.size());
            for (JsonNode bogon : expect.get("bogonKeys")) {
                assertTrue(got.get(bogon.asText()).orElseThrow().isBogon(),
                        bogon.asText() + " should be a local answer");
            }
        }
    }

    @Test
    void oneBadAddressDoesNotLoseTheRestOfTheBatch() {
        JsonNode c = batchCase("partial-failure-does-not-fail-the-batch");
        StubHttpClient http = StubHttpClient.of(Map.of(
                "1.1.1.1", StubHttpClient.Route.ok("{\"ip\": \"1.1.1.1\", \"is_vpn\": false}")));

        try (VPNDetection client = clientOn(http).retries(0).build()) {
            LinkedHashMap<String, BatchResult> got = client.lookupBatch(strings(c.get("input")));
            JsonNode expect = c.get("expect");

            assertEquals(strings(expect.get("keys")), new ArrayList<>(got.keySet()));
            for (JsonNode bad : expect.get("errorKeys")) {
                BatchResult entry = got.get(bad.asText());
                assertFalse(entry.isSuccess(), bad.asText() + " should carry its error");
                assertNotNull(entry.error().orElseThrow().kind());
            }
            assertFalse(got.get("1.1.1.1").orElseThrow().isVpn(), "the good address still answered");
        }
    }

    @Test
    void aCacheHitIssuesNoSecondRequest() {
        JsonNode c = batchCase("cache-hit-issues-no-second-request");
        StubHttpClient http = StubHttpClient.of(Map.of(
                "1.1.1.1", StubHttpClient.Route.ok("{\"ip\": \"1.1.1.1\", \"is_vpn\": false}")));

        try (VPNDetection client = clientOn(http).build()) {
            for (int i = 0; i < c.get("repeat").asInt(); i++) {
                client.lookupBatch(strings(c.get("input")));
            }
            assertEquals(c.get("expect").get("httpRequests").asInt(), http.calls.size());
        }
    }

    @Test
    void twoClientsNeverShareACachedAnswer() {
        StubHttpClient http = StubHttpClient.of(Map.of(
                "1.1.1.1", StubHttpClient.Route.ok("{\"ip\": \"1.1.1.1\", \"is_vpn\": false}")));

        try (VPNDetection a = clientOn(http).apiKey("key-a").build();
                VPNDetection b = clientOn(http).apiKey("key-b").build()) {
            a.lookup("1.1.1.1");
            b.lookup("1.1.1.1");
            // Two keys can be on different plans and so entitled to different fields; a shared
            // cache would serve one of them the other's shape.
            assertEquals(2, http.calls.size());
        }
    }

    @Test
    void cachingCanBeTurnedOff() {
        StubHttpClient http = StubHttpClient.of(Map.of(
                "1.1.1.1", StubHttpClient.Route.ok("{\"ip\": \"1.1.1.1\", \"is_vpn\": false}")));

        try (VPNDetection client = clientOn(http).cacheEnabled(false).build()) {
            client.lookup("1.1.1.1");
            client.lookup("1.1.1.1");
            assertEquals(2, http.calls.size());
        }
    }

    private static VPNDetection.Builder clientOn(StubHttpClient http) {
        return VPNDetection.builder().httpClient(http);
    }

    private static JsonNode batchCase(String name) {
        for (JsonNode c : data.get("batch")) {
            if (c.get("name").asText().equals(name)) {
                return c;
            }
        }
        throw new IllegalArgumentException("no batch case named " + name);
    }

    private static List<String> strings(JsonNode array) {
        List<String> out = new ArrayList<>();
        array.forEach(n -> out.add(n.asText()));
        return out;
    }

    private static Iterable<JsonNode> orEmpty(JsonNode array) {
        return array == null ? List.of() : array;
    }

    // The corpus names members the way the wire does, so every claim it makes has to reach the
    // matching accessor. An unknown name is a corpus that grew a member this binding has not.
    private static Optional<?> member(Result r, String wire) {
        switch (wire) {
            case "is_vpn":
                return Optional.of(r.isVpn());
            case "is_hosting":
                return r.isHosting();
            case "is_relay":
                return r.isRelay();
            case "is_tor":
                return r.isTor();
            case "is_cdn":
                return r.isCdn();
            case "is_resproxy":
                return r.isResproxy();
            case "is_dcproxy":
                return r.isDcproxy();
            case "is_mobproxy":
                return r.isMobproxy();
            case "vpn":
                return r.vpn();
            case "hosting":
                return r.hosting();
            case "relay":
                return r.relay();
            case "tor":
                return r.tor();
            case "cdn":
                return r.cdn();
            case "resproxy":
                return r.resproxy();
            case "dcproxy":
                return r.dcproxy();
            case "mobproxy":
                return r.mobproxy();
            default:
                throw new IllegalArgumentException("the corpus names a member this SDK lacks: " + wire);
        }
    }

    private static Object emptyDetail(String wire) {
        Class<?> type = detailType(wire);
        if (type == VpnDetail.class) {
            return new VpnDetail();
        }
        return type == ClassDetail.class ? new ClassDetail() : new ProxyDetail();
    }

    private static Class<?> detailType(String wire) {
        switch (wire) {
            case "vpn":
                return VpnDetail.class;
            case "hosting":
            case "relay":
            case "tor":
            case "cdn":
                return ClassDetail.class;
            case "resproxy":
            case "dcproxy":
            case "mobproxy":
                return ProxyDetail.class;
            default:
                throw new IllegalArgumentException("not a detail object: " + wire);
        }
    }
}
