package io.vpndetection;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.vpndetection.middleware.Condition;
import io.vpndetection.middleware.Core;
import io.vpndetection.middleware.Lookup;
import io.vpndetection.middleware.Options;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * What a lookup without a key reads. Unlimited's answer carries the AS's country and RPKI status
 * and no {@code type}, which is a paid plan's, and no {@code is_bot}: 6.13.0 refused the answer
 * without the type as a retried server error, so every keyless lookup failed once the API stopped
 * sending it. The answers are the corpus's own, from a public address, since a bogon is answered
 * locally and would pass every case vacuously.
 */
final class KeylessAnswerTest {
    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final String IP = "146.70.116.130";

    /** The corpus's keyless answer, a deep copy each call. */
    private static ObjectNode unlimited() throws IOException {
        for (JsonNode c : MAPPER.readTree(Path.of("testdata", "testdata.json").toFile()).get("lookup")) {
            if (c.get("name").asText().equals("unlimited-location-asn")) {
                return c.get("body").deepCopy();
            }
        }
        throw new AssertionError("the corpus has no unlimited-location-asn case");
    }

    private static StubHttpClient serving(JsonNode body) {
        return StubHttpClient.of(Map.of(IP, StubHttpClient.Route.ok(body.toString())));
    }

    @Test
    void aLookupReadsAnAnswerWithoutTheAsnsType() throws IOException {
        ObjectNode body = unlimited();
        assertFalse(body.get("asn").has("type"), "the corpus's keyless answer has no AS type");
        StubHttpClient http = serving(body);
        try (VPNDetection client = VPNDetection.builder().httpClient(http).build()) {
            Result result = client.lookup(IP);

            assertEquals(IP, result.ip());
            assertTrue(result.isVpn());
            assertEquals("M247 Europe SRL", result.asn().orElseThrow().getName());
            assertEquals("US", result.asn().orElseThrow().getCountry());
            assertEquals("valid", result.asn().orElseThrow().getRpkiStatus());
            assertNull(result.asn().orElseThrow().getType(), "the wire left the type out");
            assertEquals(1, http.calls.size(), "an answer that reads is not retried");
            assertTrue(result.isBot().isEmpty(), "Unlimited's is_bot is absent, never false");
        }
    }

    @Test
    void aTypeTheAnswerServesStillReadsAsServed() throws IOException {
        ObjectNode body = unlimited();
        ((ObjectNode) body.get("asn")).put("type", "hosting");
        try (VPNDetection client = VPNDetection.builder().httpClient(serving(body)).build()) {
            assertEquals("hosting", client.lookup(IP).asn().orElseThrow().getType());
        }
    }

    @Test
    void aTypeThatIsNullOrNotAStringIsStillARetriedServerError() throws IOException {
        for (String type : List.of("null", "5", "1.5", "true", "{}", "[]", "[\"hosting\"]")) {
            ObjectNode body = unlimited();
            ((ObjectNode) body.get("asn")).set("type", MAPPER.readTree(type));
            StubHttpClient http = serving(body);
            try (VPNDetection client = VPNDetection.builder().httpClient(http).retries(1).build()) {
                VPNDetectionException err = assertThrows(VPNDetectionException.class, () -> client.lookup(IP), type);
                assertEquals(ErrorKind.SERVER_ERROR, err.kind(), type);
                assertEquals(200, err.statusCode().orElseThrow(), type);
                assertEquals(2, http.calls.size(), type + ": retried");
            }
        }
    }

    @Test
    void aBatchEntryWithoutTheTypeReadsAndOneWithANullTypeIsThatAddressesFailure() throws IOException {
        ObjectNode lean = unlimited();
        ObjectNode broken = unlimited();
        broken.put("ip", "8.8.8.8");
        ((ObjectNode) broken.get("asn")).putNull("type");
        StubHttpClient http = StubHttpClient.of(Map.of(
                IP, StubHttpClient.Route.ok(lean.toString()),
                "8.8.8.8", StubHttpClient.Route.ok(broken.toString())));
        try (VPNDetection client = VPNDetection.builder().httpClient(http).apiKey("k").retries(0).build()) {
            Map<String, BatchResult> out = client.lookupBatch(List.of(IP, "8.8.8.8"));

            assertNull(out.get(IP).orElseThrow().asn().orElseThrow().getType());
            assertEquals("M247 Europe SRL", out.get(IP).orElseThrow().asn().orElseThrow().getName());
            assertFalse(out.get("8.8.8.8").isSuccess(), "an entry holding a null type is not an answer");
            assertEquals(ErrorKind.SERVER_ERROR, out.get("8.8.8.8").error().orElseThrow().kind());
        }
    }

    // A bogon is answered locally in the widest shape, every member present and empty, so its type
    // is a value (an empty string) and nothing about it is missing.
    @Test
    void aBogonsEmptyTypeIsAValueAndNothingInItIsMissing() {
        try (VPNDetection client = VPNDetection.builder().httpClient(StubHttpClient.of(Map.of())).build()) {
            Result bogon = client.lookup("10.0.0.1");
            List<Map<String, Object>> condition = List.of(Map.of("asn", Map.of("type", "hosting")));

            assertEquals("", bogon.asn().orElseThrow().getType());
            assertEquals(List.of(), Condition.missingMembers(condition, bogon));
            assertFalse(Condition.matches(condition, bogon));
        }
    }

    /** A middleware core on a keyless client, which reports what it is told to into {@code warnings}. */
    private static Core<String> core(StubHttpClient http, Map<String, Object> condition,
            Options.OnMissingField onMissing, List<String> warnings) {
        VPNDetection client = VPNDetection.builder().httpClient(http).build();
        return new Core<>(new Options<String>().client(client).blockCondition(condition)
                .onMissingField(onMissing).onWarn(warnings::add), request -> request);
    }

    @Test
    void aConditionOnTheAsnsTypeNeverMatchesAKeylessAnswerAndIsReportedByItsPath() throws IOException {
        List<String> warnings = new ArrayList<>();
        StubHttpClient http = serving(unlimited());
        Core<String> core = core(http, Map.of("asn", Map.of("type", "hosting")), Options.OnMissingField.WARN,
                warnings);

        Lookup looked = core.evaluate(IP);

        assertFalse(looked.isBlocked(), "a member the answer lacks never matches");
        assertEquals(1, warnings.size());
        assertTrue(warnings.get(0).contains("blockCondition names asn.type,"), warnings.get(0));
    }

    // The client's cache hands the second request the first's answer, and it still lacks the type.
    @Test
    void aCachedKeylessAnswerStillLacksTheTypeForTheNextRequest() throws IOException {
        StubHttpClient http = serving(unlimited());
        Core<String> core = core(http, Map.of("asn", Map.of("type", "hosting", "country", "US")),
                Options.OnMissingField.THROW, new ArrayList<>());

        for (int request = 1; request <= 2; request++) {
            IllegalStateException e = assertThrows(IllegalStateException.class, () -> core.evaluate(IP));
            assertTrue(e.getMessage().contains("blockCondition names asn.type,"), e.getMessage());
        }
        assertEquals(1, http.calls.size(), "the second request was answered from the cache");
    }

    @Test
    void aConditionOnIsBotNeverMatchesAKeylessAnswerAndIsReportedMissing() throws IOException {
        List<String> warnings = new ArrayList<>();
        Core<String> core = core(serving(unlimited()), Map.of("is_bot", true), Options.OnMissingField.WARN,
                warnings);

        assertFalse(core.evaluate(IP).isBlocked());
        assertEquals(1, warnings.size());
        assertTrue(warnings.get(0).contains("blockCondition names is_bot,"), warnings.get(0));
    }

    // The same condition against a paid answer, which serves the type: it is evaluated and blocks,
    // so the cases above are about the missing member and not about a condition that never fires.
    @Test
    void theSameConditionBlocksAnAnswerThatServesTheType() throws IOException {
        List<String> warnings = new ArrayList<>();
        ObjectNode body = unlimited();
        ((ObjectNode) body.get("asn")).put("type", "hosting");
        Core<String> core = core(serving(body), Map.of("asn", Map.of("type", "hosting")),
                Options.OnMissingField.THROW, warnings);

        Lookup looked = core.evaluate(IP);

        assertTrue(looked.isBlocked());
        assertEquals(List.of(), warnings);
    }
}
