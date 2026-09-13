package io.vpndetection;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.vpndetection.internal.ApiClient;
import io.vpndetection.middleware.Bound;
import io.vpndetection.middleware.Condition;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The middleware half of the shared conformance corpus, which every framework middleware in every
 * language asserts.
 *
 * <p>The corpus is language-neutral JSON, so a bound arrives as an object with gte/gt/lte/lt keys
 * and an any-of as an array. Rebuilding them into the Java types here is what keeps the corpus
 * readable by twelve languages instead of carrying one language's spelling.
 */
class MiddlewareConformanceTest {
    private static final ObjectMapper MAPPER = ApiClient.createDefaultObjectMapper();
    private static final Set<String> BOUND_KEYS = Set.of("gte", "gt", "lte", "lt");
    private static JsonNode middleware;

    @BeforeAll
    static void loadCorpus() throws IOException {
        middleware = MAPPER.readTree(Path.of("testdata", "testdata.json").toFile()).get("middleware");
    }

    @Test
    void corpusConditions() throws IOException {
        for (JsonNode c : middleware.get("conditions")) {
            String why = c.get("name").asText() + ": " + c.get("why").asText();
            Result result = resultFor(c);
            List<Map<String, Object>> conditions = toConditions(c.get("condition"));

            assertEquals(c.get("expect").get("blocked").asBoolean(),
                    Condition.matches(conditions, result), why);

            List<String> missing = new ArrayList<>(Condition.missingMembers(conditions, result));
            List<String> want = new ArrayList<>();
            c.get("expect").get("missing").forEach(n -> want.add(n.asText()));
            Collections.sort(missing);
            Collections.sort(want);
            assertEquals(want, missing, why);
        }
    }

    @Test
    void corpusRefusesAConditionThatConstrainsNothing() {
        for (JsonNode c : middleware.get("invalidConditions")) {
            String why = c.get("name").asText() + ": " + c.get("why").asText();
            IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                    () -> Condition.validate(toConditions(c.get("condition"))), why);
            assertTrue(e.getMessage().contains("constrains nothing"), why);
        }
    }

    private static Result resultFor(JsonNode c) throws IOException {
        if (c.has("bogon")) {
            // Answered locally, so this needs no transport and pins the synthesized shape rather
            // than a fixture's idea of it.
            try (VPNDetection client =
                    VPNDetection.builder().httpClient(StubHttpClient.of(Map.of())).build()) {
                return client.lookup(c.get("bogon").asText());
            }
        }
        String ip = c.get("body").get("ip").asText();
        StubHttpClient http = StubHttpClient.of(
                Map.of(ip, StubHttpClient.Route.ok(MAPPER.writeValueAsString(c.get("body")))));
        try (VPNDetection client =
                VPNDetection.builder().httpClient(http).cacheEnabled(false).retries(0).build()) {
            return client.lookup(ip);
        }
    }

    private static List<Map<String, Object>> toConditions(JsonNode raw) {
        List<Map<String, Object>> out = new ArrayList<>();
        if (raw.isArray()) {
            raw.forEach(entry -> out.add(toCondition(entry)));
        } else {
            out.add(toCondition(raw));
        }
        return out;
    }

    private static Map<String, Object> toCondition(JsonNode raw) {
        Map<String, Object> out = new LinkedHashMap<>();
        raw.fields().forEachRemaining(e -> out.put(e.getKey(), toValue(e.getValue())));
        return out;
    }

    private static Object toValue(JsonNode raw) {
        if (raw.isArray()) {
            List<Object> any = new ArrayList<>();
            raw.forEach(entry -> any.add(toValue(entry)));
            return any;
        }
        if (raw.isObject()) {
            if (isBound(raw)) {
                Bound bound = null;
                var names = raw.fieldNames();
                while (names.hasNext()) {
                    String key = names.next();
                    double value = raw.get(key).asDouble();
                    bound = switch (key) {
                        case "gte" -> bound == null ? Bound.gte(value) : bound.andGte(value);
                        case "gt" -> bound == null ? Bound.gt(value) : bound.andGt(value);
                        case "lte" -> bound == null ? Bound.lte(value) : bound.andLte(value);
                        default -> bound == null ? Bound.lt(value) : bound.andLt(value);
                    };
                }
                return bound;
            }
            return toCondition(raw);
        }
        if (raw.isBoolean()) {
            return raw.asBoolean();
        }
        if (raw.isNumber()) {
            return raw.numberValue();
        }
        if (raw.isNull()) {
            return null;
        }
        return raw.asText();
    }

    private static boolean isBound(JsonNode raw) {
        if (raw.isEmpty()) {
            return false;
        }
        var names = raw.fieldNames();
        while (names.hasNext()) {
            if (!BOUND_KEYS.contains(names.next())) {
                return false;
            }
        }
        return true;
    }
}
